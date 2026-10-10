import boto3
import os
import logging
from datetime import datetime, timezone
import json
from botocore.config import Config
from botocore.exceptions import ClientError


def get_current_utc_date():
    return datetime.now(timezone.utc).strftime("%Y/%m/%d")


# Configure boto3 with retries
boto3_config = Config(
    retries=dict(
        max_attempts=10,  # Maximum number of retries
        mode="adaptive",  # Exponential backoff with adaptive mode
    )
)

# Version 2 adds principal_errors, a per-principal permissions_boundary and
# fully paginated policy lists.
CACHE_SCHEMA_VERSION = 2

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.ERROR)


def write_permissions_to_s3(permission_cache, execution_id):
    """
    Write the IAM permissions cache to S3 as a JSON file

    Args:
        permission_cache (IAMPermissionCache): The permission cache object
        s3_bucket (str): The name of the S3 bucket to write to
    """
    try:
        # Create S3 client with the same retry configuration
        s3_client = boto3.client("s3", config=boto3_config)

        # Prepare the data to be written
        cache_data = {
            "role_permissions": permission_cache.role_permissions,
            "user_permissions": permission_cache.user_permissions,
            "principal_errors": permission_cache.principal_errors,
            "cache_schema_version": CACHE_SCHEMA_VERSION,
            "generated_at": datetime.now().isoformat(),
        }

        # Convert to JSON string
        json_data = json.dumps(cache_data, default=str, indent=2)

        # Define the S3 key (filename) - write to bucket root
        s3_key = f"permissions_cache_{execution_id}.json"
        s3_bucket = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")

        # Upload to S3
        s3_client.put_object(
            Bucket=s3_bucket, Key=s3_key, Body=json_data, ContentType="application/json"
        )

        logger.info(
            f"Successfully wrote permissions cache to s3://{s3_bucket}/{s3_key}"
        )
        return s3_key

    except Exception as e:
        logger.error(f"Error writing permissions cache to S3: {str(e)}", exc_info=True)
        raise


def _is_no_such_entity(error):
    return (
        isinstance(error, ClientError)
        and error.response.get("Error", {}).get("Code") == "NoSuchEntity"
    )


class IAMPermissionCache:
    def __init__(self, iam_client):
        self.iam_client = iam_client
        self.role_permissions = {}
        self.user_permissions = {}
        self.principal_errors = []
        self.policy_cache = {}
        self.default_version_cache = {}
        self.group_policy_cache = {}

    def initialize(self):
        """
        Get all IAM permissions and cache them
        """
        logger.info("Initializing IAM permission cache")
        self._cache_role_permissions()
        self._cache_user_permissions()

    def _get_policy_document(self, policy_arn, version_id):
        """
        Get policy document with caching. A failed read raises so the caller can
        record it against the principal it was read for.
        """
        cache_key = f"{policy_arn}:{version_id}"
        if cache_key not in self.policy_cache:
            response = self.iam_client.get_policy_version(
                PolicyArn=policy_arn, VersionId=version_id
            )
            self.policy_cache[cache_key] = response["PolicyVersion"]["Document"]
        return self.policy_cache[cache_key]

    def _managed_policy_document(self, policy_arn):
        """
        Read a managed policy's default version document, calling GetPolicy once
        per ARN
        """
        if policy_arn not in self.default_version_cache:
            policy_info = self.iam_client.get_policy(PolicyArn=policy_arn)["Policy"]
            self.default_version_cache[policy_arn] = policy_info["DefaultVersionId"]
        return self._get_policy_document(
            policy_arn, self.default_version_cache[policy_arn]
        )

    def _record_error(self, principal_type, name, stage, error):
        logger.error(f"Error reading {stage} for {principal_type} {name}: {error}")
        self.principal_errors.append(
            {"type": principal_type, "name": name, "stage": stage, "error": str(error)}
        )

    def _drop_principal(self, principal_type, name):
        """
        Forget a principal deleted during the run, with any errors recorded for it
        """
        logger.warning(f"{principal_type} {name} no longer exists; skipping it")
        self.principal_errors = [
            e
            for e in self.principal_errors
            if (e["type"], e["name"]) != (principal_type, name)
        ]

    def _group_policies(self, group_name):
        """
        Return a group's attached and inline policies and the (stage, error)
        pairs of the reads that failed, read once per group. A failed read keeps
        the policies that were read.
        """
        if group_name in self.group_policy_cache:
            return self.group_policy_cache[group_name]

        policies = []
        errors = []
        try:
            paginator = self.iam_client.get_paginator("list_attached_group_policies")
            for page in paginator.paginate(GroupName=group_name):
                for policy in page["AttachedPolicies"]:
                    policy_arn = policy["PolicyArn"]
                    try:
                        policies.append(
                            {
                                "name": policy["PolicyName"],
                                "arn": policy_arn,
                                "group": group_name,
                                "document": self._managed_policy_document(policy_arn),
                            }
                        )
                    except Exception as e:
                        errors.append(
                            (
                                "group_policy",
                                f"group {group_name}, policy {policy_arn}: {e}",
                            )
                        )
        except Exception as e:
            errors.append(("group_policies", f"group {group_name}: {e}"))

        try:
            paginator = self.iam_client.get_paginator("list_group_policies")
            for page in paginator.paginate(GroupName=group_name):
                for policy_name in page["PolicyNames"]:
                    try:
                        policy_doc = self.iam_client.get_group_policy(
                            GroupName=group_name, PolicyName=policy_name
                        )["PolicyDocument"]
                        policies.append(
                            {
                                "name": policy_name,
                                "group": group_name,
                                "document": policy_doc,
                            }
                        )
                    except Exception as e:
                        errors.append(
                            (
                                "group_policy",
                                f"group {group_name}, policy {policy_name}: {e}",
                            )
                        )
        except Exception as e:
            errors.append(("group_policies", f"group {group_name}: {e}"))

        self.group_policy_cache[group_name] = (policies, errors)
        return policies, errors

    def _cache_principal(self, principal_type, name):
        """
        Read one role's or user's attached, inline and boundary policies.

        Every list is paginated. A failed read is appended to principal_errors
        and the rest of the principal is still read, so a consumer sees both what
        was collected and what was not. Returns None for a principal deleted
        during the run (NoSuchEntity), which is then left out of the cache.
        """
        kind = "Role" if principal_type == "role" else "User"
        name_param = {f"{kind}Name": name}
        entry = {
            "attached_policies": [],
            "inline_policies": [],
            "permissions_boundary": None,
        }

        try:
            paginator = self.iam_client.get_paginator(
                f"list_attached_{principal_type}_policies"
            )
            for page in paginator.paginate(**name_param):
                for policy in page["AttachedPolicies"]:
                    policy_arn = policy["PolicyArn"]
                    try:
                        entry["attached_policies"].append(
                            {
                                "name": policy["PolicyName"],
                                "arn": policy_arn,
                                "document": self._managed_policy_document(policy_arn),
                            }
                        )
                    except Exception as e:
                        self._record_error(
                            principal_type,
                            name,
                            "attached_policy",
                            f"{policy_arn}: {e}",
                        )
        except Exception as e:
            if _is_no_such_entity(e):
                return self._drop_principal(principal_type, name)
            self._record_error(principal_type, name, "list_attached_policies", e)

        try:
            paginator = self.iam_client.get_paginator(f"list_{principal_type}_policies")
            get_inline = getattr(self.iam_client, f"get_{principal_type}_policy")
            for page in paginator.paginate(**name_param):
                for policy_name in page["PolicyNames"]:
                    try:
                        policy_doc = get_inline(**name_param, PolicyName=policy_name)[
                            "PolicyDocument"
                        ]
                        entry["inline_policies"].append(
                            {"name": policy_name, "document": policy_doc}
                        )
                    except Exception as e:
                        self._record_error(
                            principal_type,
                            name,
                            "inline_policy",
                            f"{policy_name}: {e}",
                        )
        except Exception as e:
            if _is_no_such_entity(e):
                return self._drop_principal(principal_type, name)
            self._record_error(principal_type, name, "list_inline_policies", e)

        # ListRoles and ListUsers do not return PermissionsBoundary; only GetRole
        # and GetUser do.
        detail = None
        try:
            detail = getattr(self.iam_client, f"get_{principal_type}")(**name_param)
            boundary = detail[kind].get("PermissionsBoundary") or {}
            boundary_arn = boundary.get("PermissionsBoundaryArn")
            if boundary_arn:
                entry["permissions_boundary"] = self._managed_policy_document(
                    boundary_arn
                )
        except Exception as e:
            # Only a NoSuchEntity from GetRole/GetUser itself means the principal
            # is gone; one from the boundary policy read is a boundary error.
            if detail is None and _is_no_such_entity(e):
                return self._drop_principal(principal_type, name)
            self._record_error(principal_type, name, "permissions_boundary", e)

        return entry

    def _cache_role_permissions(self):
        """
        Cache all role permissions
        """
        logger.info("Caching role permissions")
        paginator = self.iam_client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                role_name = role["RoleName"]
                entry = self._cache_principal("role", role_name)
                if entry is not None:
                    self.role_permissions[role_name] = entry

    def _cache_user_permissions(self):
        """
        Cache all user permissions
        """
        logger.info("Caching user permissions")
        paginator = self.iam_client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                user_name = user["UserName"]
                entry = self._cache_principal("user", user_name)
                if entry is None:
                    continue
                self.user_permissions[user_name] = entry

                # Group policies apply to the member as if attached to the user,
                # so they are cached per user; a failed read is recorded rather
                # than left looking like a user with no groups.
                try:
                    group_policies = []
                    group_paginator = self.iam_client.get_paginator(
                        "list_groups_for_user"
                    )
                    for group_page in group_paginator.paginate(UserName=user_name):
                        for group in group_page["Groups"]:
                            policies, errors = self._group_policies(group["GroupName"])
                            group_policies.extend(policies)
                            for stage, error in errors:
                                self._record_error("user", user_name, stage, error)
                    self.user_permissions[user_name]["group_policies"] = group_policies
                except Exception as e:
                    if _is_no_such_entity(e):
                        del self.user_permissions[user_name]
                        self._drop_principal("user", user_name)
                        continue
                    self._record_error("user", user_name, "group_policies", e)
                    self.user_permissions[user_name]["group_policies_error"] = str(e)


def lambda_handler(event, context):
    """
    Main Lambda handler
    """
    logger.info("Starting Bedrock security assessment")
    iam_client = boto3.client("iam", config=boto3_config)
    logger.info(event, context)
    try:
        # Initialize permission cache
        logger.info("Initializing IAM permission cache")
        permission_cache = IAMPermissionCache(iam_client)
        permission_cache.initialize()
        execution_id = event["Execution"]["Name"]
        s3_key = write_permissions_to_s3(permission_cache, execution_id)

        return {
            "statusCode": 200,
            "body": f"Successfully cached IAM permissions to {s3_key}",
        }

    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}", exc_info=True)
        raise
