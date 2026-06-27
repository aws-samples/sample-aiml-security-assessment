import boto3
import csv
import os
import logging
from datetime import datetime, timedelta, timezone
import time
from typing import Dict, List, Any, Optional
from io import StringIO
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError
import random
import json
from schema import create_finding

# Configure boto3 with retries
boto3_config = Config(
    retries=dict(
        max_attempts=10,  # Maximum number of retries
        mode="adaptive",  # Exponential backoff with adaptive mode
    )
)


# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.ERROR)

# IAM is a global service. Findings derived purely from the IAM permission cache
# (e.g. BR-01, BR-03) are identical across regions, so they are produced only on
# the primary region (Map index 0) and tagged with this region label to avoid
# duplicate findings when scanning multiple regions.
GLOBAL_REGION_LABEL = "Global"

# Error codes returned when a region exists but is not enabled/usable for the
# account (opt-in regions, disabled regions). The availability probe treats
# these the same as an endpoint connection failure.
REGION_UNAVAILABLE_ERROR_CODES = {
    "UnrecognizedClientException",
    "InvalidClientTokenId",
    "AuthFailure",
    "OptInRequired",
}

ACCESS_DENIED_ERROR_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
}


def is_account_not_authorized(error: Exception) -> bool:
    """
    Distinguish an account/feature-gate denial from an IAM-policy denial.

    Both surface as AccessDeniedException, but the cause differs:
      - IAM gap:        "... is not authorized to perform: <action> because no
                         identity-based policy allows ..."  -> grant the action.
      - Account gate:   "Your account is not authorized to invoke this API
                         operation."  -> the Bedrock feature (e.g. Custom Model
                         Import, Batch Inference, Model Evaluation) is not enabled
                         or allow-listed for this account/region. No IAM change
                         fixes it, so the check is Not Applicable rather than a
                         finding.
    """
    text = str(error)
    return (
        "not authorized to invoke this API operation" in text
        or "account is not authorized" in text
    )


def is_region_unsupported(error: Exception) -> bool:
    """
    Detect a "this API/feature is not available in this region" error.

    Several Bedrock features (Knowledge Bases, Agents, Flows, Model/RAG
    evaluation, ...) are not in every region. boto3 surfaces an unsupported
    operation as an UnknownOperation/"Unknown operation" error. When a check
    calls such an API in a region that lacks it, that is Not Applicable rather
    than a security finding or a hard error.
    """
    text = str(error)
    return "UnknownOperation" in text or "Unknown operation" in text


def describe_api_error(error: Exception, api_label: str, region: str = "") -> str:
    """
    Build a report-friendly description for an API error raised by a regional
    check.

    Some regions don't support a given Bedrock API. boto3 surfaces this as
    "Unknown operation ..." (ValidationException) or UnknownOperationException.
    For those, return a clean "<api_label> not available in <region>" message
    instead of leaking the raw boto3 exception text into the report. Any other
    error keeps its raw text so genuine problems (e.g. permissions) stay
    diagnosable.
    """
    error_text = str(error)
    if "UnknownOperation" in error_text or "Unknown operation" in error_text:
        location = region if region else "this region"
        return f"{api_label} not available in {location}"
    return f"Unable to check {api_label}: {error_text}"


def _probe_bedrock_resource_list(probe_label: str, probe_func) -> Optional[bool]:
    """
    Probe a Bedrock list API and report whether it found any regional resources.

    Returns:
        True if the API found at least one resource
        False if the API was successfully queried and returned no resources
        None if the result is inconclusive (for example, AccessDenied)
    """
    try:
        return bool(probe_func())
    except EndpointConnectionError:
        raise
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        error_text = str(e)

        if code in REGION_UNAVAILABLE_ERROR_CODES:
            raise

        if code in ACCESS_DENIED_ERROR_CODES:
            logger.warning(
                f"Unable to determine regional Bedrock footprint from {probe_label}: {code}"
            )
            return None

        if (
            code == "ValidationException"
            or "UnknownOperation" in error_text
            or "Unknown operation" in error_text
        ):
            logger.info(f"{probe_label} API not available in this region")
            return False

        logger.warning(
            f"Unexpected error probing {probe_label} for regional Bedrock footprint: {error_text}"
        )
        return None
    except Exception as e:
        error_text = str(e)
        if "UnknownOperation" in error_text or "Unknown operation" in error_text:
            logger.info(f"{probe_label} API not available in this region")
            return False

        logger.warning(
            f"Unexpected error probing {probe_label} for regional Bedrock footprint: {error_text}"
        )
        return None


def _first_page_items(paginator, result_key: str) -> List[Dict[str, Any]]:
    """Return at most the first page of items from a paginator-based Bedrock list API."""
    for page in paginator.paginate(PaginationConfig={"MaxItems": 1, "PageSize": 1}):
        return page.get(result_key, [])
    return []


def detect_bedrock_regional_footprint(region: str = "") -> Optional[bool]:
    """
    Detect whether a region has Bedrock-managed resources that justify regional findings.

    Returns:
        True if Bedrock-managed resources exist in the region
        False if supported APIs were probed and no resources were found
        None if the footprint could not be determined confidently
    """
    bedrock_client = boto3.client("bedrock", config=boto3_config, region_name=region)
    bedrock_agent_client = boto3.client(
        "bedrock-agent", config=boto3_config, region_name=region
    )

    probes = [
        (
            "Bedrock Guardrails",
            lambda: bedrock_client.list_guardrails().get("guardrails", []),
        ),
        (
            "Bedrock Prompts",
            lambda: bedrock_agent_client.list_prompts().get("promptSummaries", []),
        ),
        (
            "Bedrock Agents",
            lambda: bedrock_agent_client.list_agents().get("agents", []),
        ),
        (
            "Bedrock Knowledge Bases",
            lambda: _first_page_items(
                bedrock_agent_client.get_paginator("list_knowledge_bases"),
                "knowledgeBaseSummaries",
            ),
        ),
        (
            "Bedrock Flows",
            lambda: _first_page_items(
                bedrock_agent_client.get_paginator("list_flows"),
                "flowSummaries",
            ),
        ),
        (
            "Bedrock Custom Models",
            lambda: _first_page_items(
                bedrock_client.get_paginator("list_custom_models"),
                "modelSummaries",
            ),
        ),
    ]

    indeterminate = False
    successful_empty_probe = False
    for probe_label, probe_func in probes:
        probe_result = _probe_bedrock_resource_list(probe_label, probe_func)
        if probe_result is True:
            return True
        if probe_result is False:
            successful_empty_probe = True
        if probe_result is None:
            indeterminate = True

    if successful_empty_probe:
        return False

    return None if indeterminate else False


def _extract_s3_bucket_name(s3_config: Optional[Dict[str, Any]]) -> Optional[str]:
    """Support both the documented field name and the legacy test fixture key."""
    if not s3_config:
        return None

    return s3_config.get("bucketName") or s3_config.get("s3BucketName")


def _is_access_denied_client_error(error: Exception) -> bool:
    """Normalize AccessDenied checks across Bedrock and S3 client errors."""
    if not isinstance(error, ClientError):
        return False

    error_code = error.response.get("Error", {}).get("Code")
    return error_code in {"AccessDenied", "AccessDeniedException"}


def get_permissions_cache(execution_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve and parse the permissions cache JSON file from S3

    Args:
        execution_id (str): Step Functions execution ID

    Returns:
        Optional[Dict[str, Any]]: Parsed permissions cache as dictionary, None if not found or error
    """
    try:
        s3_client = boto3.client("s3", config=boto3_config)
        s3_key = f"permissions_cache_{execution_id}.json"
        s3_bucket = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")

        logger.info(f"Retrieving permissions cache from s3://{s3_bucket}/{s3_key}")

        try:
            # Get the JSON file from S3
            response = s3_client.get_object(Bucket=s3_bucket, Key=s3_key)

            # Read and parse the JSON content
            json_content = response["Body"].read().decode("utf-8")
            permissions_cache = json.loads(json_content)

            logger.info(
                f"Successfully retrieved permissions cache for execution {execution_id}"
            )
            return permissions_cache

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                logger.warning(
                    f"Permissions cache not found: s3://{s3_bucket}/{s3_key}"
                )
            elif e.response["Error"]["Code"] == "NoSuchBucket":
                logger.error(f"Bucket not found: {s3_bucket}")
            else:
                logger.error(
                    f"AWS error retrieving permissions cache: {str(e)}", exc_info=True
                )
            return None

    except json.JSONDecodeError as e:
        logger.error(f"Error parsing permissions cache JSON: {str(e)}", exc_info=True)
        return None
    except Exception as e:
        logger.error(
            f"Unexpected error retrieving permissions cache: {str(e)}", exc_info=True
        )
        return None


def check_marketplace_subscription_access(
    permission_cache, region: str = ""
) -> Dict[str, Any]:
    logger.debug("Starting check for overly permissive Marketplace subscription access")
    try:
        findings = {
            "check_name": "Marketplace Subscription Access Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        overly_permissive_identities = []

        def check_policy_for_subscription_access(policy_doc: Any) -> bool:
            try:
                if isinstance(policy_doc, str):
                    policy_doc = json.loads(policy_doc)

                if not policy_doc:
                    return False

                statements = policy_doc.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]

                for statement in statements:
                    effect = statement.get("Effect", "")
                    if effect.upper() != "ALLOW":
                        continue

                    actions = statement.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]

                    resources = statement.get("Resource", [])
                    if isinstance(resources, str):
                        resources = [resources]

                    if "aws-marketplace:Subscribe" in actions:
                        if "*" in resources:
                            return True

                return False
            except Exception as e:
                logger.error(
                    f"Error parsing policy document for subscription access: {str(e)}"
                )
                return False

        # Check roles
        for role_name, permissions in permission_cache["role_permissions"].items():
            for policy in (
                permissions["attached_policies"] + permissions["inline_policies"]
            ):
                if check_policy_for_subscription_access(policy["document"]):
                    overly_permissive_identities.append(
                        {"name": role_name, "type": "role", "policy": policy["name"]}
                    )
                    break

        # Check users
        for user_name, permissions in permission_cache["user_permissions"].items():
            for policy in (
                permissions["attached_policies"] + permissions["inline_policies"]
            ):
                if check_policy_for_subscription_access(policy["document"]):
                    overly_permissive_identities.append(
                        {"name": user_name, "type": "user", "policy": policy["name"]}
                    )
                    break

        if overly_permissive_identities:
            findings["status"] = "WARN"
            findings["details"] = (
                f"Found {len(overly_permissive_identities)} identities with overly permissive marketplace subscription access"
            )

            for identity in overly_permissive_identities:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-03",
                        finding_name="Marketplace Subscription Access Check",
                        finding_details=f"{identity['type'].capitalize()} '{identity['name']}' has overly permissive marketplace subscription access through policy '{identity['policy']}'",
                        resolution="Ensure that users have access to only the models that you want user to be able to subscribe to based on your organizational policies. For example, you may want users to have access to only text based models and not image and video generation model. This can also help to keep cost in check.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam-awsmanpol.html#security-iam-awsmanpol-bedrock-marketplace",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            findings["details"] = (
                "No identities found with overly permissive marketplace subscription access"
            )
            findings["csv_data"].append(
                create_finding(
                    check_id="BR-03",
                    finding_name="Marketplace Subscription Access Check",
                    finding_details="No identities found with overly permissive marketplace subscription access",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam-awsmanpol.html#security-iam-awsmanpol-bedrock-marketplace",
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_marketplace_subscription_access: {str(e)}", exc_info=True
        )
        return {
            "check_name": "Marketplace Subscription Access Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-03",
                    finding_name="Marketplace Subscription Access Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ],
        }


def has_bedrock_access(iam_client, principal_name: str, principal_type: str) -> bool:
    """
    Check if a user or role has Bedrock access through policies
    """
    logger.debug(f"Checking Bedrock access for {principal_type}: {principal_name}")
    try:
        if principal_type == "role":
            policies = iam_client.list_attached_role_policies(RoleName=principal_name)
        else:
            policies = iam_client.list_attached_user_policies(UserName=principal_name)

        # Check attached policies
        for policy in policies["AttachedPolicies"]:
            policy_arn = policy["PolicyArn"]
            logger.debug(f"Checking policy: {policy_arn}")
            policy_version = iam_client.get_policy(PolicyArn=policy_arn)["Policy"][
                "DefaultVersionId"
            ]
            policy_doc = iam_client.get_policy_version(
                PolicyArn=policy_arn, VersionId=policy_version
            )["PolicyVersion"]["Document"]

            if has_bedrock_permissions(policy_doc):
                logger.info(f"Found Bedrock permissions in policy: {policy_arn}")
                return True

        # Check inline policies
        if principal_type == "role":
            inline_policies = iam_client.list_role_policies(RoleName=principal_name)
        else:
            inline_policies = iam_client.list_user_policies(UserName=principal_name)

        for policy_name in inline_policies["PolicyNames"]:
            logger.debug(f"Checking inline policy: {policy_name}")
            if principal_type == "role":
                policy_doc = iam_client.get_role_policy(
                    RoleName=principal_name, PolicyName=policy_name
                )["PolicyDocument"]
            else:
                policy_doc = iam_client.get_user_policy(
                    UserName=principal_name, PolicyName=policy_name
                )["PolicyDocument"]

            if has_bedrock_permissions(policy_doc):
                logger.info(
                    f"Found Bedrock permissions in inline policy: {policy_name}"
                )
                return True

        return False

    except Exception as e:
        logger.error(
            f"Error checking permissions for {principal_type} {principal_name}: {str(e)}"
        )
        return False


def check_stale_bedrock_access(permission_cache, region: str = "") -> Dict[str, Any]:
    """
    Check for stale Bedrock access using IAM service-last-accessed data.

    This check is derived purely from IAM (a global service) and the cached
    permissions, so it produces identical results in every region. The handler
    runs it once, on the primary region, tagged with GLOBAL_REGION_LABEL.
    """
    logger.debug("Starting check for stale Bedrock access")
    try:
        findings = {
            "check_name": "Stale Bedrock Access Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        stale_identities = []
        active_identities = []
        two_months_ago = datetime.now(timezone.utc) - timedelta(days=60)

        sts_client = boto3.client("sts", config=boto3_config)
        account_id = sts_client.get_caller_identity()["Account"]

        identities_to_check = []

        # Check roles
        for role_name, permissions in permission_cache["role_permissions"].items():
            if has_bedrock_permissions_in_cache(permissions):
                identities_to_check.append(("role", role_name))

        # Check users
        for user_name, permissions in permission_cache["user_permissions"].items():
            if has_bedrock_permissions_in_cache(permissions):
                identities_to_check.append(("user", user_name))

        if not identities_to_check:
            logger.info("No identities found with Bedrock access")
            findings["csv_data"].append(
                create_finding(
                    check_id="BR-14",
                    finding_name="Stale Bedrock Access Check",
                    finding_details="No identities found with Bedrock access",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )
            return findings

        # Check last accessed info for each identity
        iam_client = boto3.client("iam", config=boto3_config)
        for identity_type, identity_name in identities_to_check:
            try:
                arn = f"arn:aws:iam::{account_id}:{identity_type}/{identity_name}"
                response = iam_client.generate_service_last_accessed_details(Arn=arn)
                job_id = response["JobId"]

                wait_time = 0
                max_wait_time = 30
                while wait_time < max_wait_time:
                    response = iam_client.get_service_last_accessed_details(
                        JobId=job_id
                    )
                    if response["JobStatus"] == "COMPLETED":
                        for service in response["ServicesLastAccessed"]:
                            if service["ServiceName"] == "Amazon Bedrock":
                                last_accessed = service.get("LastAuthenticated")
                                if last_accessed:
                                    if (
                                        last_accessed.replace(tzinfo=timezone.utc)
                                        < two_months_ago
                                    ):
                                        stale_identities.append(
                                            {
                                                "name": identity_name,
                                                "type": identity_type,
                                                "last_accessed": last_accessed,
                                            }
                                        )
                                    else:
                                        active_identities.append(
                                            {
                                                "name": identity_name,
                                                "type": identity_type,
                                                "last_accessed": last_accessed,
                                            }
                                        )
                                else:
                                    stale_identities.append(
                                        {
                                            "name": identity_name,
                                            "type": identity_type,
                                            "last_accessed": None,
                                        }
                                    )
                        break
                    time.sleep(1)  # nosemgrep: arbitrary-sleep
                    wait_time += 1

                # Log warning if job timed out
                if wait_time >= max_wait_time:
                    logger.warning(
                        f"Timeout waiting for IAM job to complete for {identity_type} {identity_name} - skipping"
                    )
            except Exception as e:
                logger.error(
                    f"Error checking last access for {identity_type} {identity_name}: {str(e)}"
                )
                continue

        if stale_identities:
            findings["status"] = "WARN"
            findings["details"] = (
                f"Found {len(stale_identities)} identities with stale Bedrock access"
            )

            for identity in stale_identities:
                last_accessed_str = (
                    identity["last_accessed"].strftime("%Y-%m-%d")
                    if identity["last_accessed"]
                    else "never"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-14",
                        finding_name="Stale Bedrock Access Check",
                        finding_details=f"{identity['type'].capitalize()} '{identity['name']}' last accessed Bedrock on {last_accessed_str}",
                        resolution="You can use last accessed information to refine your policies and allow access to only the services and actions that your IAM identities and policies use. This helps you to better adhere to the best practice of least privilege.",
                        reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

        else:
            active_details = []
            for identity in active_identities:
                last_accessed_str = identity["last_accessed"].strftime("%Y-%m-%d")
                active_details.append(
                    f"{identity['type'].capitalize()} '{identity['name']}' last accessed on {last_accessed_str}"
                )

            finding_details = (
                "All identities with Bedrock access are actively using the service"
            )
            if active_details:
                finding_details += ": " + "; ".join(active_details)

            findings["details"] = finding_details
            findings["csv_data"].append(
                create_finding(
                    check_id="BR-14",
                    finding_name="Stale Bedrock Access Check",
                    finding_details=finding_details,
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(f"Error in check_stale_bedrock_access: {str(e)}", exc_info=True)
        return {
            "check_name": "Stale Bedrock Access Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-14",
                    finding_name="Stale Bedrock Access Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_full_access_roles(
    permission_cache, region: str = ""
) -> Dict[str, Any]:
    """
    Check for roles with AmazonBedrockFullAccess policy using cached permissions
    """
    logger.debug("Starting check for AmazonBedrockFullAccess roles")
    findings = {
        "check_name": "Bedrock Full Access Check",
        "status": "PASS",
        "details": "",
        "csv_data": [],
    }

    bedrock_roles = []
    for role_name, permissions in permission_cache["role_permissions"].items():
        for policy in permissions["attached_policies"]:
            if policy["name"] == "AmazonBedrockFullAccess":
                bedrock_roles.append({"name": role_name, "policy": policy["name"]})
                break

    if bedrock_roles:
        findings["status"] = "WARN"
        findings["details"] = (
            f"Found {len(bedrock_roles)} roles with AmazonBedrockFullAccess policy"
        )

        for role in bedrock_roles:
            findings["csv_data"].append(
                create_finding(
                    check_id="BR-01",
                    finding_name="AmazonBedrockFullAccess role check",
                    finding_details=f"Role '{role['name']}' has AmazonBedrockFullAccess policy attached",
                    resolution="Limit the AmazonBedrockFullAccess policy only to required access",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples-agent.html#iam-agents-ex-all\nhttps://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples-br-studio.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            )
    else:
        findings["details"] = "No roles found with AmazonBedrockFullAccess policy"
        findings["csv_data"].append(
            create_finding(
                check_id="BR-01",
                finding_name="AmazonBedrockFullAccess role check",
                finding_details="No roles found with AmazonBedrockFullAccess policy",
                resolution="No action required",
                reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples-agent.html#iam-agents-ex-all\nhttps://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples-br-studio.html",
                severity="High",
                status="Passed",
                region=region,
            )
        )

    return findings


def get_role_usage(role_name: str) -> str:
    """
    Check where a specific IAM role is being used
    """
    logger.debug(f"Checking usage for role: {role_name}")
    usage_list = []

    try:
        # Check Lambda functions
        lambda_client = boto3.client("lambda", config=boto3_config)
        lambda_functions = lambda_client.list_functions()
        for function in lambda_functions["Functions"]:
            if role_name in function["Role"]:
                usage_list.append(f"Lambda: {function['FunctionName']}")
                logger.debug(f"Found role usage in Lambda: {function['FunctionName']}")
    except Exception as e:
        logger.error(f"Error checking Lambda usage: {str(e)}")

    try:
        # Check ECS tasks
        ecs_client = boto3.client("ecs", config=boto3_config)
        clusters = ecs_client.list_clusters()["clusterArns"]
        for cluster in clusters:
            tasks = ecs_client.list_tasks(cluster=cluster)["taskArns"]
            if tasks:
                task_details = ecs_client.describe_tasks(cluster=cluster, tasks=tasks)
                for task in task_details["tasks"]:
                    if role_name in task.get("taskRoleArn", ""):
                        usage_list.append(f"ECS Task: {task['taskArn']}")
                        logger.debug(f"Found role usage in ECS task: {task['taskArn']}")
    except Exception as e:
        logger.error(f"Error checking ECS usage: {str(e)}")

    result = "; ".join(usage_list) if usage_list else "No active usage found"
    logger.debug(f"Role usage result: {result}")
    return result


def check_bedrock_vpc_endpoints(region: str = "") -> Dict[str, bool]:
    """
    Check if any VPC has Bedrock VPC endpoints
    """
    logger.debug("Checking for Bedrock VPC endpoints")
    try:
        ec2_client = boto3.client("ec2", config=boto3_config, region_name=region)

        bedrock_endpoints = [
            "com.amazonaws.region.bedrock",
            "com.amazonaws.region.bedrock-runtime",
            "com.amazonaws.region.bedrock-agent",
            "com.amazonaws.region.bedrock-agent-runtime",
        ]

        # Get current region
        current_region = region
        logger.debug(f"Current region: {current_region}")

        # Get list of all VPCs
        vpcs = ec2_client.describe_vpcs()
        vpc_ids = [vpc["VpcId"] for vpc in vpcs["Vpcs"]]
        logger.debug(f"Found VPCs: {vpc_ids}")

        # Replace 'region' with actual region in endpoint names
        bedrock_endpoints = [
            endpoint.replace("region", current_region) for endpoint in bedrock_endpoints
        ]
        found_endpoints = []

        # Get all VPC endpoints
        paginator = ec2_client.get_paginator("describe_vpc_endpoints")

        for page in paginator.paginate():
            for endpoint in page["VpcEndpoints"]:
                service_name = endpoint["ServiceName"]
                vpc_id = endpoint["VpcId"]
                logger.debug(f"Found VPC endpoint: {service_name} in VPC: {vpc_id}")

                # Check if this endpoint matches any of our Bedrock endpoints
                for bedrock_endpoint in bedrock_endpoints:
                    if service_name == bedrock_endpoint:
                        logger.info(
                            f"Found matching Bedrock endpoint: {service_name} in VPC: {vpc_id}"
                        )
                        found_endpoints.append(
                            {"vpc_id": vpc_id, "service": service_name}
                        )

        return {
            "has_endpoints": len(found_endpoints) > 0,
            "found_endpoints": found_endpoints,
            "all_vpcs": vpc_ids,
        }

    except Exception as e:
        logger.error(f"Error checking VPC endpoints: {str(e)}", exc_info=True)
        return {"has_endpoints": False, "found_endpoints": [], "all_vpcs": []}


def has_bedrock_permissions_in_cache(permissions: Dict) -> bool:
    """
    Check if the cached permissions contain Bedrock access
    """
    for policy in permissions["attached_policies"] + permissions["inline_policies"]:
        if has_bedrock_permissions(policy["document"]):
            return True
    return False


def has_bedrock_permissions(policy_doc: Any) -> bool:
    """
    Check if a policy document contains Bedrock permissions
    """
    try:
        if isinstance(policy_doc, str):
            policy_doc = json.loads(policy_doc)

        if not policy_doc:
            return False

        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            effect = statement.get("Effect", "")
            if effect.upper() != "ALLOW":
                continue

            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            for action in actions:
                if "bedrock" in action.lower():
                    return True

        return False
    except Exception as e:
        logger.error(f"Error parsing policy document: {str(e)}")
        return False


def _policy_grants_wildcard(policy_doc: Any) -> bool:
    """
    Return True if the policy document has an Allow statement granting both
    Action "*" and Resource "*" (full wildcard access).
    """
    try:
        if isinstance(policy_doc, str):
            policy_doc = json.loads(policy_doc)

        if not policy_doc:
            return False

        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if statement.get("Effect", "").upper() != "ALLOW":
                continue

            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = statement.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            if "*" in actions and "*" in resources:
                return True

        return False
    except Exception as e:
        logger.warning(f"Error parsing policy document for wildcard access: {str(e)}")
        return False


def handle_aws_throttling(func, *args, **kwargs):
    """
    Handle AWS API throttling with exponential backoff
    """
    max_retries = 5
    base_delay = 1  # Start with 1 second delay

    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] == "Throttling":
                if attempt == max_retries - 1:
                    raise  # Re-raise if we're out of retries
                delay = (2**attempt) * base_delay + (random.random() * 0.1)
                logger.warning(f"Request throttled. Retrying in {delay:.2f} seconds...")
                time.sleep(delay)
            else:
                raise


def check_bedrock_access_and_vpc_endpoints(
    permission_cache, region: str = ""
) -> Dict[str, Any]:
    logger.debug("Starting check for Bedrock access and VPC endpoints")
    try:
        findings = {
            "check_name": "Bedrock Access and VPC Endpoint Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_access_found = False

        # Check roles and users for Bedrock access
        for role_name, permissions in permission_cache["role_permissions"].items():
            if has_bedrock_permissions_in_cache(permissions):
                bedrock_access_found = True
                break

        if not bedrock_access_found:
            for user_name, permissions in permission_cache["user_permissions"].items():
                if has_bedrock_permissions_in_cache(permissions):
                    bedrock_access_found = True
                    break

        if bedrock_access_found:
            bedrock_footprint_found = detect_bedrock_regional_footprint(region=region)

            if bedrock_footprint_found is False:
                findings["details"] = "No regional Bedrock resources found"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-02",
                        finding_name="Amazon Bedrock private connectivity check",
                        finding_details="No regional Bedrock resources found to assess private connectivity",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/vpc-interface-endpoints.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

            vpc_endpoint_check = check_bedrock_vpc_endpoints(region=region)

            if not vpc_endpoint_check["has_endpoints"]:
                findings["status"] = "WARN"

                if vpc_endpoint_check["all_vpcs"]:
                    vpc_list = ", ".join(vpc_endpoint_check["all_vpcs"])
                    finding_detail = (
                        f"No Bedrock service VPC endpoints found in VPCs: {vpc_list}"
                    )
                else:
                    finding_detail = "No VPCs found in the account"

                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-02",
                        finding_name="Amazon Bedrock private connectivity not used",
                        finding_details=finding_detail,
                        resolution="Create a VPC endpoint in your VPC with any of the following Bedrock service endpoints that your application may be using:\n- com.amazonaws.region.bedrock\n- com.amazonaws.region.bedrock-runtime\n- com.amazonaws.region.bedrock-agent\n- com.amazonaws.region.bedrock-agent-runtime",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/vpc-interface-endpoints.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
            else:
                endpoint_details = []
                for endpoint in vpc_endpoint_check["found_endpoints"]:
                    endpoint_details.append(
                        f"VPC {endpoint['vpc_id']} has endpoint {endpoint['service']}"
                    )
                findings["details"] = "Bedrock VPC endpoints found: " + "; ".join(
                    endpoint_details
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-02",
                        finding_name="Amazon Bedrock private connectivity",
                        finding_details=f"Bedrock VPC endpoints found: {'; '.join(endpoint_details)}",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/vpc-interface-endpoints.html",
                        severity="High",
                        status="Passed",
                        region=region,
                    )
                )
        else:
            findings["details"] = "No Bedrock access found in roles or users"

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_access_and_vpc_endpoints: {str(e)}", exc_info=True
        )
        return {
            "check_name": "Bedrock Access and VPC Endpoint Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-02",
                    finding_name="Bedrock VPC Endpoint Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_guardrails(region: str = "") -> Dict[str, Any]:
    """
    Check if Amazon Bedrock Guardrails are configured and being used
    """
    logger.debug("Starting check for Bedrock Guardrails configuration")
    try:
        findings = {
            "check_name": "Bedrock Guardrails Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_client = boto3.client(
            "bedrock", config=boto3_config, region_name=region
        )

        try:
            # List all guardrails
            response = bedrock_client.list_guardrails()

            if response.get("guardrails", []):
                guardrail_names = [
                    guardrail["name"] for guardrail in response["guardrails"]
                ]
                findings["details"] = (
                    f"Found {len(guardrail_names)} Bedrock guardrails configured"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-05",
                        finding_name="Bedrock Guardrails Check",
                        finding_details=f"Amazon Bedrock Guardrails are properly configured with {len(guardrail_names)} guardrails",
                        resolution="No action required. Continue monitoring and updating guardrails as needed.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html",
                        severity="High",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                bedrock_footprint_found = detect_bedrock_regional_footprint(
                    region=region
                )

                if bedrock_footprint_found is False:
                    findings["details"] = "No regional Bedrock resources found"
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-05",
                            finding_name="Bedrock Guardrails Check",
                            finding_details="No regional Bedrock resources found to protect with guardrails",
                            resolution="No action required",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html",
                            severity="Informational",
                            status="N/A",
                            region=region,
                        )
                    )
                else:
                    findings["status"] = "WARN"
                    findings["details"] = "No Bedrock guardrails configured"
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-05",
                            finding_name="Bedrock Guardrails Check",
                            finding_details="No Amazon Bedrock Guardrails are configured. This may expose your application to potential risks such as harmful content, sensitive information disclosure, or hallucinations.",
                            resolution="Configure Bedrock Guardrails to implement safeguards such as:\n- Content filters to block harmful content\n- Denied topics to prevent undesirable discussions\n- Sensitive information filters to protect PII\n- Contextual grounding checks to prevent hallucinations",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html",
                            severity="Medium",
                            status="Failed",
                            region=region,
                        )
                    )

        except bedrock_client.exceptions.ValidationException as e:
            findings["status"] = "ERROR"
            findings["details"] = f"Error validating guardrails configuration: {str(e)}"
            findings["csv_data"].append(
                create_finding(
                    check_id="BR-05",
                    finding_name="Bedrock Guardrails Check",
                    finding_details=f"Error checking Bedrock Guardrails configuration: {str(e)}",
                    resolution="Verify your AWS credentials and permissions to access Bedrock Guardrails.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(f"Error in check_bedrock_guardrails: {str(e)}", exc_info=True)
        return {
            "check_name": "Bedrock Guardrails Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-05",
                    finding_name="Bedrock Guardrails Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_logging_configuration(region: str = "") -> Dict[str, Any]:
    """
    Check if model invocation logging is enabled for Amazon Bedrock
    """
    # FinServ extension (FS-64): In addition to verifying that invocation
    # logging is enabled, the FinServ guide (PDF §1.2.1, §1.2.6, §1.2.7)
    # expects the log output to include guardrailTrace with action,
    # inputAssessments, and outputAssessments to support SR 11-7 audit trails
    # and NYDFS 500.06 retention. See docs/SECURITY_CHECKS_FINSERV.md
    # (FS-64 → BR-04 extension note) for the detection / remediation language.
    logger.debug("Starting check for Bedrock model invocation logging configuration")
    try:
        findings = {
            "check_name": "Bedrock Model Invocation Logging Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_footprint_found = detect_bedrock_regional_footprint(region=region)
        if bedrock_footprint_found is False:
            findings["details"] = "No regional Bedrock resources found"
            findings["csv_data"].append(
                create_finding(
                    check_id="BR-04",
                    finding_name="Bedrock Model Invocation Logging Check",
                    finding_details="No regional Bedrock resources found to monitor with invocation logging",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )
            return findings

        bedrock_client = boto3.client(
            "bedrock", config=boto3_config, region_name=region
        )

        try:
            # Get current logging configuration
            response = bedrock_client.get_model_invocation_logging_configuration()

            logging_enabled = False
            enabled_destinations = []

            # Check S3 logging configuration
            s3_config = response.get("loggingConfig", {}).get("s3Config")
            if _extract_s3_bucket_name(s3_config):
                logging_enabled = True
                enabled_destinations.append("Amazon S3")

            # Check CloudWatch logging configuration
            cloudwatch_config = response.get("loggingConfig", {}).get(
                "cloudWatchConfig"
            )
            if cloudwatch_config and cloudwatch_config.get("logGroupName"):
                logging_enabled = True
                enabled_destinations.append("CloudWatch Logs")

            if logging_enabled:
                findings["details"] = (
                    f"Model invocation logging is enabled with delivery to: {', '.join(enabled_destinations)}"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-04",
                        finding_name="Bedrock Model Invocation Logging Check",
                        finding_details=f"Model invocation logging is properly configured with delivery to: {', '.join(enabled_destinations)}",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                findings["status"] = "FAIL"
                findings["details"] = "Model invocation logging is not enabled"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-04",
                        finding_name="Bedrock Model Invocation Logging Check",
                        finding_details="Model invocation logging is not enabled. This limits your ability to track and audit model usage.",
                        resolution="Enable model invocation logging to collect invocation logs, model input data, and model output data. Configure logging to deliver to Amazon S3, CloudWatch Logs, or both for comprehensive monitoring.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

        except bedrock_client.exceptions.ValidationException:
            findings["status"] = "FAIL"
            findings["details"] = "Model invocation logging is not enabled"
            findings["csv_data"].append(
                create_finding(
                    check_id="BR-04",
                    finding_name="Bedrock Model Invocation Logging Check",
                    finding_details="Model invocation logging is not enabled. This limits your ability to track and audit model usage.",
                    resolution="Enable model invocation logging to collect invocation logs, model input data, and model output data. Configure logging to deliver to Amazon S3, CloudWatch Logs, or both for comprehensive monitoring.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
                    severity="Medium",
                    status="Failed",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_logging_configuration: {str(e)}", exc_info=True
        )
        return {
            "check_name": "Bedrock Model Invocation Logging Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-04",
                    finding_name="Bedrock Logging Configuration Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_cloudtrail_logging(region: str = "") -> Dict[str, Any]:
    """
    Check if CloudTrail is configured to log Amazon Bedrock API calls
    """
    # FinServ extension (FS-23): In addition to verifying CloudTrail is logging
    # Bedrock API calls, the FinServ guide (PDF §1.2.15) expects an advanced
    # event selector for AWS::Bedrock::KnowledgeBase so Retrieve and
    # RetrieveAndGenerate data events are captured (NOT logged by default).
    # See docs/SECURITY_CHECKS_FINSERV.md (FS-23 → BR-06
    # extension note) for the detection / remediation language.
    logger.debug("Starting check for Bedrock CloudTrail logging configuration")
    try:
        findings = {
            "check_name": "Bedrock CloudTrail Logging Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_footprint_found = detect_bedrock_regional_footprint(region=region)
        if bedrock_footprint_found is False:
            findings["details"] = "No regional Bedrock resources found"
            findings["csv_data"].append(
                create_finding(
                    check_id="BR-06",
                    finding_name="Bedrock CloudTrail Logging Check",
                    finding_details="No regional Bedrock resources found to audit with Bedrock-specific CloudTrail coverage",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )
            return findings

        cloudtrail_client = boto3.client(
            "cloudtrail", config=boto3_config, region_name=region
        )

        try:
            # Get all trails
            trails_response = cloudtrail_client.list_trails()
            trails = trails_response.get("Trails", [])

            bedrock_logging_enabled = False
            logging_trails = []

            for trail in trails:
                trail_arn = trail["TrailARN"]
                trail_name = trail["Name"]

                # Get trail configuration
                trail_config = cloudtrail_client.get_trail(Name=trail_arn)

                # Get trail runtime status (IsLogging is only in get_trail_status)
                trail_status = cloudtrail_client.get_trail_status(Name=trail_arn)

                # Check if trail is enabled and multi-region
                if trail_config["Trail"].get("IsMultiRegionTrail") and trail_status.get(
                    "IsLogging", False
                ):
                    # Get event selectors
                    event_selectors = cloudtrail_client.get_event_selectors(
                        TrailName=trail_arn
                    )

                    # Check advanced event selectors if they exist
                    advanced_selectors = event_selectors.get(
                        "AdvancedEventSelectors", []
                    )
                    basic_selectors = event_selectors.get("EventSelectors", [])

                    # Check if Bedrock events are being logged
                    for selector in advanced_selectors:
                        field_selectors = selector.get("FieldSelectors", [])
                        for field in field_selectors:
                            if (
                                field.get("Field") == "eventSource"
                                and "bedrock" in str(field.get("Equals", [])).lower()
                            ):
                                bedrock_logging_enabled = True
                                logging_trails.append(trail_name)
                                break

                    # If no advanced selectors, check if logging all management events
                    if not bedrock_logging_enabled and basic_selectors:
                        for selector in basic_selectors:
                            if selector.get(
                                "IncludeManagementEvents", False
                            ) and selector.get("ReadWriteType", "") in ["All", "Write"]:
                                bedrock_logging_enabled = True
                                logging_trails.append(trail_name)
                                break

            if bedrock_logging_enabled:
                findings["details"] = (
                    f"CloudTrail logging enabled for Bedrock in trails: {', '.join(logging_trails)}"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-06",
                        finding_name="Bedrock CloudTrail Logging Check",
                        finding_details=f"CloudTrail is properly configured to log Bedrock API activity in trails: {', '.join(logging_trails)}",
                        resolution="No action required. Continue monitoring CloudTrail logs for Bedrock activity.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                findings["status"] = "FAIL"
                findings["details"] = (
                    "No CloudTrail trails configured to log Bedrock activity"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-06",
                        finding_name="Bedrock CloudTrail Logging Check",
                        finding_details="CloudTrail is not configured to log Amazon Bedrock API calls. This limits your ability to audit and monitor Bedrock usage.",
                        resolution="Enable CloudTrail logging for Bedrock by :\n"
                        + "1. Configuring an advanced event selector for Bedrock events \n"
                        + "2. Enabling management events logging in a multi-region trail",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )

        except ClientError as e:
            findings["status"] = "ERROR"
            findings["details"] = f"Error checking CloudTrail configuration: {str(e)}"
            findings["csv_data"].append(
                create_finding(
                    check_id="BR-06",
                    finding_name="Bedrock CloudTrail Logging Check",
                    finding_details=f"Error checking CloudTrail configuration for Bedrock logging: {str(e)}",
                    resolution="Verify your AWS credentials and permissions to access CloudTrail.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_cloudtrail_logging: {str(e)}", exc_info=True
        )
        return {
            "check_name": "Bedrock CloudTrail Logging Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-06",
                    finding_name="Bedrock CloudTrail Logging Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_prompt_management(region: str = "") -> Dict[str, Any]:
    """
    Check if Amazon Bedrock Prompt Management feature is being used
    """
    logger.debug("Starting check for Bedrock Prompt Management usage")
    try:
        findings = {
            "check_name": "Bedrock Prompt Management Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_client = boto3.client(
            "bedrock-agent", config=boto3_config, region_name=region
        )

        try:
            # List all prompts
            paginator = bedrock_client.get_paginator("list_prompts")
            prompts = []
            for page in paginator.paginate():
                prompts.extend(page.get("promptSummaries", []))

            if prompts:
                findings["details"] = f"Found {len(prompts)} prompts"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-07",
                        finding_name="Bedrock Prompt Management Check",
                        finding_details=f"Prompt Management is being used with {len(prompts)} prompts",
                        resolution="No action required. Continue using Prompt Management for consistent and optimized prompts.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-management.html",
                        severity="Low",
                        status="Passed",
                        region=region,
                    )
                )

                # Additional check for prompt variants
                prompts_without_variants = []
                for prompt in prompts:
                    prompt_id = prompt.get("id") or prompt.get("promptId")
                    prompt_name = prompt.get("name") or prompt_id or "unknown"
                    if not prompt_id:
                        logger.warning(
                            "Skipping prompt without identifier in Prompt Management check"
                        )
                        continue

                    try:
                        prompt_details = bedrock_client.get_prompt(
                            promptIdentifier=prompt_id
                        )
                        prompt_config = prompt_details.get("prompt", prompt_details)
                        if len(prompt_config.get("variants", [])) <= 1:
                            prompts_without_variants.append(prompt_name)
                    except Exception as e:
                        logger.warning(
                            f"Could not get details for prompt {prompt_name}: {str(e)}"
                        )

                if prompts_without_variants:
                    findings["status"] = "WARN"
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-07",
                            finding_name="Bedrock Prompt Variants Check",
                            finding_details=f"Found {len(prompts_without_variants)} prompts without multiple variants. Testing different prompt variants helps optimize responses.",
                            resolution="Create and test multiple variants for your prompts to find the most effective configurations.",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-management.html",
                            severity="Low",
                            status="Failed",
                            region=region,
                        )
                    )
            else:
                findings["status"] = "WARN"
                findings["details"] = "Prompt Management feature is not being used"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-07",
                        finding_name="Bedrock Prompt Management Check",
                        finding_details="Prompt Management feature is not being used. This may lead to inconsistent prompt handling and suboptimal model responses.",
                        resolution="Implement Prompt Management to:\n"
                        + "1. Create and version your prompts\n"
                        + "2. Test different prompt variants\n"
                        + "3. Share prompts across your organization\n"
                        + "4. Maintain consistent prompt templates",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-management.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        except Exception as e:
            # An API error (e.g. InternalServerErrorException after retries,
            # throttling, or a permissions issue) is not a security failure.
            # Surface it as N/A rather than Failed, matching the BR-11 pattern.
            logger.warning(f"Error listing prompts: {str(e)}")
            findings["csv_data"].append(
                create_finding(
                    check_id="BR-07",
                    finding_name="Bedrock Prompt Management Check",
                    finding_details=describe_api_error(
                        e, "Bedrock Prompt Management API", region
                    ),
                    resolution="Verify your AWS credentials and permissions to access Bedrock Prompt Management, then retry the assessment.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-management.html",
                    severity="Low",
                    status="N/A",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_prompt_management: {str(e)}", exc_info=True
        )
        return {
            "check_name": "Bedrock Prompt Management Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-07",
                    finding_name="Bedrock Prompt Management Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_knowledge_base_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if Amazon Bedrock Knowledge Bases have proper encryption configured
    including customer-managed KMS keys for data at rest
    """
    logger.debug("Starting check for Bedrock Knowledge Base encryption")
    try:
        findings = {
            "check_name": "Bedrock Knowledge Base Encryption Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_agent_client = boto3.client(
            "bedrock-agent", config=boto3_config, region_name=region
        )

        try:
            # List all knowledge bases
            knowledge_bases = []
            paginator = bedrock_agent_client.get_paginator("list_knowledge_bases")
            for page in paginator.paginate():
                knowledge_bases.extend(page.get("knowledgeBaseSummaries", []))

            if not knowledge_bases:
                findings["details"] = "No Knowledge Bases found"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-09",
                        finding_name="Bedrock Knowledge Base Encryption Check",
                        finding_details="No Knowledge Bases found in the account",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-kb.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

            kb_without_cmk = []
            kb_access_denied = []

            for kb in knowledge_bases:
                kb_id = kb.get("knowledgeBaseId")
                kb_name = kb.get("name", kb_id)

                try:
                    # Get detailed knowledge base info
                    kb_details = bedrock_agent_client.get_knowledge_base(
                        knowledgeBaseId=kb_id
                    )

                    kb_config = kb_details.get("knowledgeBase", {})

                    # Knowledge Base encryption is managed at the underlying storage layer
                    # (OpenSearch Serverless, RDS, S3, etc.) and cannot be determined
                    # from the KB API alone. Flag for manual review.
                    storage_config = kb_config.get("storageConfiguration", {})
                    storage_type = storage_config.get("type", "Unknown")

                    kb_without_cmk.append(
                        {"id": kb_id, "name": kb_name, "storage_type": storage_type}
                    )

                except ClientError as e:
                    if _is_access_denied_client_error(e):
                        kb_access_denied.append({"id": kb_id, "name": kb_name})
                        continue

                    logger.warning(f"Error checking knowledge base {kb_id}: {str(e)}")
                except Exception as e:
                    logger.warning(f"Error checking knowledge base {kb_id}: {str(e)}")

            if kb_without_cmk or kb_access_denied:
                detail_parts = []
                if kb_without_cmk:
                    detail_parts.append(
                        f"Found {len(kb_without_cmk)} Knowledge Bases - encryption validated at storage layer"
                    )
                if kb_access_denied:
                    detail_parts.append(
                        f"Could not assess {len(kb_access_denied)} Knowledge Bases due to access denied"
                    )
                findings["details"] = "; ".join(detail_parts)

                for kb in kb_without_cmk:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-09",
                            finding_name="Bedrock Knowledge Base Encryption Review",
                            finding_details=f"Knowledge Base '{kb['name']}' ({kb['id']}) uses '{kb['storage_type']}' storage. Encryption is managed at the storage layer and cannot be validated from the KB API. Verify encryption configuration on the underlying storage resource.",
                            resolution="1. For OpenSearch Serverless: Verify encryption with CMK at collection level\n2. For S3 data sources: Verify CMK-encrypted S3 buckets\n3. For RDS: Verify KMS encryption on the database\n4. Consider using CMK for transient data during ingestion",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-kb.html",
                            severity="Informational",
                            status="N/A",
                            region=region,
                        )
                    )

                for kb in kb_access_denied:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-09",
                            finding_name="Bedrock Knowledge Base Encryption Check",
                            finding_details=f"Unable to assess Knowledge Base '{kb['name']}' ({kb['id']}) because access to Knowledge Base metadata was denied.",
                            resolution="Ensure the assessment role can call bedrock:ListKnowledgeBases and bedrock:GetKnowledgeBase for the target account.",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-kb.html",
                            severity="Informational",
                            status="N/A",
                            region=region,
                        )
                    )
            else:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-09",
                        finding_name="Bedrock Knowledge Base Encryption Check",
                        finding_details=f"All {len(knowledge_bases)} Knowledge Bases reviewed for encryption configuration",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-kb.html",
                        severity="High",
                        status="Passed",
                        region=region,
                    )
                )

        except ClientError as e:
            if _is_access_denied_client_error(e):
                findings["status"] = "WARN"
                findings["details"] = (
                    "Unable to assess Knowledge Base encryption because access was denied"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-09",
                        finding_name="Bedrock Knowledge Base Encryption Check",
                        finding_details="Unable to assess Knowledge Base encryption because access to Knowledge Base metadata was denied.",
                        resolution="Ensure the assessment role can call bedrock:ListKnowledgeBases and bedrock:GetKnowledgeBase for the target account.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-kb.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )
            elif is_region_unsupported(e):
                findings["status"] = "N/A"
                findings["details"] = "Knowledge Bases API not available in this region"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-09",
                        finding_name="Bedrock Knowledge Base Encryption Check",
                        finding_details=describe_api_error(
                            e, "Knowledge Bases API", region
                        ),
                        resolution="Amazon Bedrock Knowledge Bases are not available in this region. No action required.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-kb.html",
                        severity="Low",
                        status="N/A",
                        region=region,
                    )
                )
            else:
                error_code = e.response.get("Error", {}).get("Code")
                if error_code == "ValidationException":
                    findings["status"] = "ERROR"
                    findings["details"] = (
                        f"Error validating Knowledge Base configuration: {str(e)}"
                    )
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-09",
                            finding_name="Bedrock Knowledge Base Encryption Check",
                            finding_details=f"Error checking Knowledge Base encryption: {str(e)}",
                            resolution="Verify your AWS credentials and permissions to access Bedrock Knowledge Bases",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-kb.html",
                            severity="High",
                            status="Failed",
                            region=region,
                        )
                    )
                else:
                    raise

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_knowledge_base_encryption: {str(e)}", exc_info=True
        )
        return {
            "check_name": "Bedrock Knowledge Base Encryption Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-09",
                    finding_name="Bedrock Knowledge Base Encryption Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_guardrail_iam_enforcement(
    permission_cache, region: str = ""
) -> Dict[str, Any]:
    """
    Check if IAM policies enforce the use of specific guardrails via
    the bedrock:GuardrailIdentifier condition key
    """
    logger.debug("Starting check for Bedrock Guardrail IAM enforcement")
    try:
        findings = {
            "check_name": "Bedrock Guardrail IAM Enforcement Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_client = boto3.client(
            "bedrock", config=boto3_config, region_name=region
        )

        # First check if any guardrails exist
        try:
            guardrails_response = bedrock_client.list_guardrails()
            guardrails = guardrails_response.get("guardrails", [])

            if not guardrails:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-10",
                        finding_name="Bedrock Guardrail IAM Enforcement Check",
                        finding_details="No guardrails configured - IAM enforcement check not applicable",
                        resolution="Configure Bedrock Guardrails first, then enforce their use via IAM policies",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-permissions-id.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

        except Exception as e:
            logger.warning(f"Error listing guardrails: {str(e)}")

        # Check IAM policies for guardrail enforcement
        roles_without_enforcement = []
        roles_with_enforcement = []

        for role_name, permissions in permission_cache.get(
            "role_permissions", {}
        ).items():
            has_bedrock_invoke = False
            has_guardrail_condition = False

            all_policies = permissions.get("attached_policies", []) + permissions.get(
                "inline_policies", []
            )

            for policy in all_policies:
                policy_doc = policy.get("document", {})

                try:
                    if isinstance(policy_doc, str):
                        policy_doc = json.loads(policy_doc)

                    if not policy_doc:
                        continue

                    statements = policy_doc.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]

                    for statement in statements:
                        if statement.get("Effect", "").upper() != "ALLOW":
                            continue

                        actions = statement.get("Action", [])
                        if isinstance(actions, str):
                            actions = [actions]

                        # Check if policy allows InvokeModel or InvokeModelWithResponseStream
                        for action in actions:
                            if any(
                                invoke_action in action.lower()
                                for invoke_action in [
                                    "bedrock:invokemodel",
                                    "bedrock:*",
                                    "bedrock:invoke*",
                                ]
                            ):
                                has_bedrock_invoke = True

                                # Check for guardrail condition
                                conditions = statement.get("Condition", {})
                                for (
                                    condition_operator,
                                    condition_keys,
                                ) in conditions.items():
                                    if isinstance(condition_keys, dict):
                                        for key in condition_keys.keys():
                                            if (
                                                "bedrock:guardrailidentifier"
                                                in key.lower()
                                            ):
                                                has_guardrail_condition = True
                                                break

                except Exception as e:
                    logger.warning(
                        f"Error parsing policy for role {role_name}: {str(e)}"
                    )

            if has_bedrock_invoke:
                if has_guardrail_condition:
                    roles_with_enforcement.append(role_name)
                else:
                    roles_without_enforcement.append(role_name)

        if roles_without_enforcement:
            findings["status"] = "WARN"
            findings["details"] = (
                f"Found {len(roles_without_enforcement)} roles with Bedrock invoke permissions but no guardrail enforcement"
            )

            findings["csv_data"].append(
                create_finding(
                    check_id="BR-10",
                    finding_name="Bedrock Guardrail IAM Enforcement Missing",
                    finding_details=f"The following roles can invoke Bedrock models without enforced guardrails: {', '.join(roles_without_enforcement[:10])}{'...' if len(roles_without_enforcement) > 10 else ''}",
                    resolution="Add IAM policy conditions to enforce guardrail usage:\n"
                    + "1. Use 'bedrock:GuardrailIdentifier' condition key\n"
                    + "2. Specify required guardrail ARN or ID\n"
                    + '3. Example: "Condition": {"StringEquals": {"bedrock:GuardrailIdentifier": "arn:aws:bedrock:region:account:guardrail/guardrail-id"}}',
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-permissions-id.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            )
        else:
            if not roles_with_enforcement:
                # No roles with Bedrock invoke permissions - N/A (nothing to check)
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-10",
                        finding_name="Bedrock Guardrail IAM Enforcement Check",
                        finding_details="No roles with Bedrock invoke permissions found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-permissions-id.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )
            else:
                # Roles exist and all have guardrail enforcement - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-10",
                        finding_name="Bedrock Guardrail IAM Enforcement Check",
                        finding_details=f"All {len(roles_with_enforcement)} roles with Bedrock invoke permissions have guardrail enforcement",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-permissions-id.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_guardrail_iam_enforcement: {str(e)}", exc_info=True
        )
        return {
            "check_name": "Bedrock Guardrail IAM Enforcement Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-10",
                    finding_name="Bedrock Guardrail IAM Enforcement Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_custom_model_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if custom/fine-tuned Bedrock models have proper encryption configured
    """
    logger.debug("Starting check for Bedrock custom model encryption")
    try:
        findings = {
            "check_name": "Bedrock Custom Model Encryption Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_client = boto3.client(
            "bedrock", config=boto3_config, region_name=region
        )

        try:
            # List custom models
            custom_models = []
            paginator = bedrock_client.get_paginator("list_custom_models")
            for page in paginator.paginate():
                custom_models.extend(page.get("modelSummaries", []))

            if not custom_models:
                findings["details"] = "No custom models found"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-11",
                        finding_name="Bedrock Custom Model Encryption Check",
                        finding_details="No custom/fine-tuned models found in the account",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-custom-job.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

            models_without_cmk = []
            models_with_cmk = []

            for model in custom_models:
                model_arn = model.get("modelArn")
                model_name = model.get("modelName", model_arn)

                try:
                    # Get detailed model info
                    model_details = bedrock_client.get_custom_model(
                        modelIdentifier=model_arn
                    )

                    # Check for customer-managed KMS key via the customization job
                    has_cmk = False
                    job_arn = model_details.get("jobArn")
                    if job_arn:
                        try:
                            job_details = bedrock_client.get_model_customization_job(
                                jobIdentifier=job_arn
                            )
                            job_output_config = job_details.get("outputDataConfig", {})
                            if job_output_config.get("kmsKeyId"):
                                has_cmk = True
                        except Exception as job_err:
                            logger.warning(
                                f"Could not retrieve customization job for {model_name}: {str(job_err)}"
                            )

                    if not has_cmk:
                        models_without_cmk.append(
                            {
                                "name": model_name,
                                "arn": model_arn,
                                "base_model": model_details.get(
                                    "baseModelArn", "Unknown"
                                ),
                            }
                        )
                    else:
                        models_with_cmk.append(model_name)

                except Exception as e:
                    logger.warning(
                        f"Error checking custom model {model_name}: {str(e)}"
                    )

            if models_without_cmk:
                findings["status"] = "WARN"
                findings["details"] = (
                    f"Found {len(models_without_cmk)} custom models to review for CMK encryption"
                )

                for model in models_without_cmk:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-11",
                            finding_name="Bedrock Custom Model Encryption Review",
                            finding_details=f"Custom model '{model['name']}' should be reviewed for customer-managed KMS encryption. Model artifacts and training data should use CMK.",
                            resolution="1. Use customer-managed KMS keys for training job output\n2. Ensure S3 buckets with training data use CMK encryption\n3. For future models, specify KMS key in customization job configuration",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-custom-job.html",
                            severity="Medium",
                            status="Failed",
                            region=region,
                        )
                    )
            else:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-11",
                        finding_name="Bedrock Custom Model Encryption Check",
                        finding_details=f"All {len(custom_models)} custom models reviewed",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-custom-job.html",
                        severity="High",
                        status="Passed",
                        region=region,
                    )
                )

        except Exception as e:
            logger.warning(f"Error listing custom models: {str(e)}")
            findings["csv_data"].append(
                create_finding(
                    check_id="BR-11",
                    finding_name="Bedrock Custom Model Encryption Check",
                    finding_details=describe_api_error(e, "Custom model API", region),
                    resolution="Verify permissions to access Bedrock custom models",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-customization-iam-role.html",
                    severity="Low",
                    status="N/A",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_custom_model_encryption: {str(e)}", exc_info=True
        )
        return {
            "check_name": "Bedrock Custom Model Encryption Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-11",
                    finding_name="Bedrock Custom Model Encryption Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_invocation_log_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if S3 buckets used for model invocation logging have proper encryption
    """
    logger.debug("Starting check for Bedrock invocation log encryption")
    try:
        findings = {
            "check_name": "Bedrock Invocation Log Encryption Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_client = boto3.client(
            "bedrock", config=boto3_config, region_name=region
        )
        s3_client = boto3.client("s3", config=boto3_config, region_name=region)

        try:
            # Get logging configuration
            response = bedrock_client.get_model_invocation_logging_configuration()
            logging_config = response.get("loggingConfig", {})

            s3_config = logging_config.get("s3Config")

            bucket_name = _extract_s3_bucket_name(s3_config)

            if not bucket_name:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-12",
                        finding_name="Bedrock Invocation Log Encryption Check",
                        finding_details="Model invocation logging to S3 is not configured",
                        resolution="If logging is enabled to CloudWatch only, ensure CloudWatch log group uses CMK encryption",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

            # Check S3 bucket encryption
            try:
                encryption_response = s3_client.get_bucket_encryption(
                    Bucket=bucket_name
                )
                rules = encryption_response.get(
                    "ServerSideEncryptionConfiguration", {}
                ).get("Rules", [])

                has_cmk = False
                encryption_type = "None"

                for rule in rules:
                    default_encryption = rule.get(
                        "ApplyServerSideEncryptionByDefault", {}
                    )
                    sse_algorithm = default_encryption.get("SSEAlgorithm", "")
                    kms_key_id = default_encryption.get("KMSMasterKeyID", "")

                    if sse_algorithm == "aws:kms":
                        encryption_type = "KMS"
                        if kms_key_id and not kms_key_id.startswith("alias/aws/"):
                            has_cmk = True
                            encryption_type = "Customer-Managed KMS"
                    elif sse_algorithm == "AES256":
                        encryption_type = "SSE-S3"

                if has_cmk:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-12",
                            finding_name="Bedrock Invocation Log Encryption Check",
                            finding_details=f"S3 bucket '{bucket_name}' for invocation logs uses customer-managed KMS encryption",
                            resolution="No action required",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
                            severity="Medium",
                            status="Passed",
                            region=region,
                        )
                    )
                else:
                    findings["status"] = "WARN"
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-12",
                            finding_name="Bedrock Invocation Log Encryption",
                            finding_details=f"S3 bucket '{bucket_name}' for invocation logs uses {encryption_type} encryption instead of customer-managed KMS. Invocation logs may contain sensitive prompts and responses.",
                            resolution="1. Enable SSE-KMS with a customer-managed key on the S3 bucket\n2. Update bucket policy to require encrypted uploads\n3. Consider enabling S3 bucket versioning and MFA delete for log integrity",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
                            severity="Medium",
                            status="Failed",
                            region=region,
                        )
                    )

            except ClientError as e:
                if (
                    e.response["Error"]["Code"]
                    == "ServerSideEncryptionConfigurationNotFoundError"
                ):
                    findings["status"] = "FAIL"
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-12",
                            finding_name="Bedrock Invocation Log Encryption Missing",
                            finding_details=f"S3 bucket '{bucket_name}' for invocation logs has NO encryption configured. Logs containing prompts and responses are stored unencrypted.",
                            resolution="Enable SSE-KMS encryption with a customer-managed key on the S3 bucket immediately",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
                            severity="High",
                            status="Failed",
                            region=region,
                        )
                    )
                elif _is_access_denied_client_error(e):
                    findings["status"] = "WARN"
                    findings["details"] = (
                        f"Unable to assess encryption for bucket '{bucket_name}' due to access denied"
                    )
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-12",
                            finding_name="Bedrock Invocation Log Encryption Check",
                            finding_details=f"Unable to assess encryption for bucket '{bucket_name}' because access to the bucket encryption configuration was denied.",
                            resolution="Ensure the assessment role and bucket policy allow s3:GetEncryptionConfiguration for the logging bucket.",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
                            severity="Informational",
                            status="N/A",
                            region=region,
                        )
                    )
                else:
                    raise

        except bedrock_client.exceptions.ValidationException:
            findings["csv_data"].append(
                create_finding(
                    check_id="BR-12",
                    finding_name="Bedrock Invocation Log Encryption Check",
                    finding_details="Model invocation logging is not configured",
                    resolution="Configure model invocation logging with an encrypted S3 bucket",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_invocation_log_encryption: {str(e)}", exc_info=True
        )
        return {
            "check_name": "Bedrock Invocation Log Encryption Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-12",
                    finding_name="Bedrock Invocation Log Encryption Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_flows_guardrails(region: str = "") -> Dict[str, Any]:
    """
    Check if Bedrock Flows have guardrails configured on prompt and knowledge base nodes
    """
    logger.debug("Starting check for Bedrock Flows guardrail configuration")
    try:
        findings = {
            "check_name": "Bedrock Flows Guardrails Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_agent_client = boto3.client(
            "bedrock-agent", config=boto3_config, region_name=region
        )

        try:
            # List all flows
            flows = []
            paginator = bedrock_agent_client.get_paginator("list_flows")
            for page in paginator.paginate():
                flows.extend(page.get("flowSummaries", []))

            if not flows:
                findings["details"] = "No Bedrock Flows found"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-13",
                        finding_name="Bedrock Flows Guardrails Check",
                        finding_details="No Bedrock Flows found in the account",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/flows-guardrails.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

            flows_without_guardrails = []
            flows_with_guardrails = []

            for flow in flows:
                flow_id = flow.get("id")
                flow_name = flow.get("name", flow_id)

                try:
                    # Get detailed flow info
                    flow_details = bedrock_agent_client.get_flow(flowIdentifier=flow_id)

                    definition = flow_details.get("definition", {})
                    nodes = definition.get("nodes", [])

                    # Check each node for guardrail configuration
                    nodes_needing_guardrails = []
                    nodes_with_guardrails = []

                    for node in nodes:
                        node_name = node.get("name", "Unknown")
                        node_type = node.get("type", "")
                        node_config = node.get("configuration", {})

                        # Prompt nodes and Knowledge Base nodes should have guardrails
                        if node_type in ["Prompt", "KnowledgeBase"]:
                            guardrail_config = None

                            if node_type == "Prompt":
                                prompt_config = node_config.get("prompt", {})
                                guardrail_config = prompt_config.get(
                                    "guardrailConfiguration"
                                )
                            elif node_type == "KnowledgeBase":
                                kb_config = node_config.get("knowledgeBase", {})
                                guardrail_config = kb_config.get(
                                    "guardrailConfiguration"
                                )

                            if guardrail_config and guardrail_config.get(
                                "guardrailIdentifier"
                            ):
                                nodes_with_guardrails.append(node_name)
                            else:
                                nodes_needing_guardrails.append(
                                    {"name": node_name, "type": node_type}
                                )

                    if nodes_needing_guardrails:
                        flows_without_guardrails.append(
                            {
                                "flow_id": flow_id,
                                "flow_name": flow_name,
                                "nodes": nodes_needing_guardrails,
                            }
                        )
                    elif nodes_with_guardrails:
                        flows_with_guardrails.append(flow_name)

                except Exception as e:
                    logger.warning(f"Error checking flow {flow_id}: {str(e)}")

            if flows_without_guardrails:
                findings["status"] = "WARN"
                findings["details"] = (
                    f"Found {len(flows_without_guardrails)} flows with nodes missing guardrails"
                )

                for flow in flows_without_guardrails:
                    node_details = ", ".join(
                        [f"{n['name']} ({n['type']})" for n in flow["nodes"]]
                    )
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-13",
                            finding_name="Bedrock Flow Missing Guardrails",
                            finding_details=f"Flow '{flow['flow_name']}' has nodes without guardrails configured: {node_details}. Without guardrails, intermediate steps can generate harmful content.",
                            resolution="1. Configure guardrails on Prompt nodes via guardrailConfiguration\n2. Configure guardrails on Knowledge Base nodes when using RetrieveAndGenerate\n3. Apply organization-wide guardrail enforcement policies",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/flows-guardrails.html",
                            severity="High",
                            status="Failed",
                            region=region,
                        )
                    )
            else:
                if flows_with_guardrails:
                    # Flows exist and all have guardrails - Passed
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-13",
                            finding_name="Bedrock Flows Guardrails Check",
                            finding_details=f"All nodes in {len(flows_with_guardrails)} flows have guardrails configured",
                            resolution="No action required",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/flows-guardrails.html",
                            severity="Medium",
                            status="Passed",
                            region=region,
                        )
                    )
                else:
                    # Flows exist but none have guardrail-applicable nodes - N/A
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-13",
                            finding_name="Bedrock Flows Guardrails Check",
                            finding_details=f"Reviewed {len(flows)} flows - no Prompt or Knowledge Base nodes requiring guardrails",
                            resolution="No action required",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/flows-guardrails.html",
                            severity="Informational",
                            status="N/A",
                            region=region,
                        )
                    )

        except Exception as e:
            logger.warning(f"Error listing flows: {str(e)}")
            findings["csv_data"].append(
                create_finding(
                    check_id="BR-13",
                    finding_name="Bedrock Flows Guardrails Check",
                    finding_details=describe_api_error(e, "Bedrock Flows API", region),
                    resolution="Verify permissions to access Bedrock Flows",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/flows-guardrails.html",
                    severity="Low",
                    status="N/A",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_flows_guardrails: {str(e)}", exc_info=True
        )
        return {
            "check_name": "Bedrock Flows Guardrails Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-13",
                    finding_name="Bedrock Flows Guardrails Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_agent_roles(permission_cache, region: str = "") -> Dict[str, Any]:
    """
    Check IAM roles associated with Bedrock agents for least privilege access
    """
    logger.debug("Starting check for Bedrock agent IAM roles")
    try:
        findings = {
            "check_name": "Bedrock Agent IAM Roles Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_client = boto3.client(
            "bedrock-agent", config=boto3_config, region_name=region
        )

        try:
            # Get all Bedrock agents
            paginator = bedrock_client.get_paginator("list_agents")
            agents = []
            for page in paginator.paginate():
                agents.extend(page.get("agentSummaries", page.get("agents", [])))

            if not agents:
                findings["details"] = "No Bedrock agents found"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-08",
                        finding_name="Bedrock Agent IAM Roles Check",
                        finding_details="No Bedrock agents found in the account",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_service-with-iam.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

            issues_found = []

            for agent in agents:
                agent_id = agent.get("agentId")
                agent_name = agent.get("agentName") or agent_id or "unknown"
                if not agent_id:
                    logger.warning(
                        "Skipping Bedrock agent without agentId in IAM role check"
                    )
                    continue

                # Get agent details including role ARN
                agent_details = bedrock_client.get_agent(agentId=agent_id)

                role_arn = agent_details.get("agent", {}).get(
                    "agentResourceRoleArn"
                ) or agent_details.get("agentResourceRoleArn")
                if not role_arn:
                    continue

                role_name = role_arn.split("/")[-1]

                # Check role in permission cache
                if role_name in permission_cache["role_permissions"]:
                    role_info = permission_cache["role_permissions"][role_name]

                    # Check for overly permissive policies
                    has_full_access = False
                    has_permission_boundary = bool(role_info.get("permission_boundary"))
                    has_vpc_condition = False
                    has_specific_resources = True

                    # Check attached policies
                    for policy in role_info["attached_policies"]:
                        if "BedrockFullAccess" in policy["name"]:
                            has_full_access = True

                        # Check policy document for resource constraints and conditions
                        doc = policy.get("document", {})
                        for statement in doc.get("Statement", []):
                            if statement.get("Effect") == "Allow":
                                # Check for resource constraints
                                resources = statement.get("Resource", [])
                                if resources == ["*"]:
                                    has_specific_resources = False

                                # Check for VPC conditions
                                conditions = statement.get("Condition", {})
                                if any(
                                    "vpc" in str(c).lower() for c in conditions.values()
                                ):
                                    has_vpc_condition = True

                    # Check inline policies
                    for policy in role_info["inline_policies"]:
                        doc = policy.get("document", {})
                        for statement in doc.get("Statement", []):
                            if statement.get("Effect") == "Allow":
                                resources = statement.get("Resource", [])
                                if resources == ["*"]:
                                    has_specific_resources = False

                                conditions = statement.get("Condition", {})
                                if any(
                                    "vpc" in str(c).lower() for c in conditions.values()
                                ):
                                    has_vpc_condition = True

                    # Collect issues
                    role_issues = []
                    if has_full_access:
                        role_issues.append("uses full access policy")
                    if not has_specific_resources:
                        role_issues.append("lacks specific resource constraints")
                    if not has_permission_boundary:
                        role_issues.append("missing permission boundary")
                    if not has_vpc_condition:
                        role_issues.append("missing VPC conditions")

                    if role_issues:
                        issues_found.append(
                            f"Agent '{agent_name}' role '{role_name}' {', '.join(role_issues)}"
                        )

            if issues_found:
                findings["status"] = "FAIL"
                findings["details"] = (
                    f"Found {len(issues_found)} roles with least privilege issues"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-08",
                        finding_name="Bedrock Agent IAM Roles Check",
                        finding_details="IAM roles associated with Bedrock agents have least privilege issues:\n"
                        + "\n".join(f"- {issue}" for issue in issues_found),
                        resolution="1. Replace full access policies with scoped policies\n"
                        + "2. Specify exact resource ARNs instead of using wildcards\n"
                        + "3. Apply permission boundaries to limit maximum permissions\n"
                        + "4. Add VPC conditions to restrict access to specific networks\n"
                        + "5. Review and update role trust policies",
                        reference="https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/gensec05-bp01.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )
            else:
                findings["details"] = (
                    f"All {len(agents)} Bedrock agent roles follow least privilege principles"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-08",
                        finding_name="Bedrock Agent IAM Roles Check",
                        finding_details=f"All {len(agents)} Bedrock agent roles properly implement least privilege access",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/gensec05-bp01.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )

        except bedrock_client.exceptions.ValidationException as e:
            findings["status"] = "ERROR"
            findings["details"] = f"Error checking Bedrock agents: {str(e)}"
            findings["csv_data"].append(
                create_finding(
                    check_id="BR-08",
                    finding_name="Bedrock Agent IAM Roles Check",
                    finding_details=f"Error checking Bedrock agent configurations: {str(e)}",
                    resolution="Verify your AWS credentials and permissions to access Bedrock agents.",
                    reference="https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/gensec05-bp01.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(f"Error in check_bedrock_agent_roles: {str(e)}", exc_info=True)
        return {
            "check_name": "Bedrock Agent IAM Roles Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-08",
                    finding_name="Bedrock Agent IAM Roles Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_cross_account_guardrails(region: str = "") -> Dict[str, Any]:
    """
    BR-15: Check if organization-level guardrails are configured using AWS Organizations Bedrock policies
    for centralized safety control enforcement (NEW - April 2026 feature)
    """
    logger.debug("Starting check for cross-account guardrails enforcement")
    try:
        findings = {
            "check_name": "Cross-Account Guardrails Enforcement Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        try:
            orgs_client = boto3.client("organizations", config=boto3_config)

            # Check if running in management account
            org_info = orgs_client.describe_organization()
            master_account_id = org_info["Organization"]["MasterAccountId"]

            # Get current account ID
            sts_client = boto3.client("sts", config=boto3_config)
            current_account = sts_client.get_caller_identity()["Account"]

            if current_account != master_account_id:
                findings["details"] = (
                    "Not running in management account, cannot check organizational policies"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-15",
                        finding_name="Cross-Account Guardrails Enforcement Check",
                        finding_details="Check must run in AWS Organizations management account to evaluate organizational policies",
                        resolution="Run assessment in management account to check cross-account guardrails enforcement",
                        reference="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_bedrock.html",
                        severity="Medium",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

            # List policy types enabled for the organization. The Amazon Bedrock
            # policy type (used to enforce guardrails across accounts) is
            # identified as BEDROCK_POLICY in AWS Organizations.
            enabled_policy_types = orgs_client.list_roots()["Roots"][0].get(
                "PolicyTypes", []
            )
            bedrock_policy_enabled = any(
                pt.get("Type") == "BEDROCK_POLICY" and pt.get("Status") == "ENABLED"
                for pt in enabled_policy_types
            )

            if not bedrock_policy_enabled:
                findings["status"] = "WARN"
                findings["details"] = (
                    "Bedrock Guardrails policy type is not enabled for the organization"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-15",
                        finding_name="Cross-Account Guardrails Enforcement Check",
                        finding_details="Bedrock Guardrails policy type is not enabled at the organization level. Cross-account guardrails cannot be enforced without enabling this policy type.",
                        resolution="Enable Bedrock Guardrails policy type in AWS Organizations to enforce consistent safety controls across all accounts. Use AWS Organizations console or CLI to enable the policy type.",
                        reference="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_bedrock.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )
                return findings

            # Check for Bedrock policies attached to organization roots/OUs/accounts
            policies_attached = False
            try:
                policies = orgs_client.list_policies(Filter="BEDROCK_POLICY")
                policies_attached = len(policies.get("Policies", [])) > 0
            except Exception as e:
                if "UnknownOperation" in str(e) or "Unknown operation" in str(e):
                    logger.info(
                        "Bedrock Guardrails policy listing not available in this region"
                    )
                    findings["details"] = (
                        "Bedrock Guardrails organizational policy feature not available in this region"
                    )
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-15",
                            finding_name="Cross-Account Guardrails Enforcement Check",
                            finding_details="Bedrock Guardrails organizational policy API not available in this region",
                            resolution="This feature may not be available in all regions. Check AWS documentation for regional availability.",
                            reference="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_bedrock.html",
                            severity="Medium",
                            status="N/A",
                            region=region,
                        )
                    )
                    return findings
                raise

            if not policies_attached:
                findings["status"] = "WARN"
                findings["details"] = (
                    "No Bedrock Guardrails policies found at organization level"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-15",
                        finding_name="Cross-Account Guardrails Enforcement Check",
                        finding_details="Bedrock Guardrails policy type is enabled but no policies are attached. Cross-account guardrails are not being enforced across the organization.",
                        resolution="Create and attach Bedrock Guardrails policies to the organization root, OUs, or specific accounts to enforce consistent safety controls across all foundation model interactions.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-enforcements.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )
            else:
                findings["details"] = (
                    "Cross-account guardrails enforcement is configured"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-15",
                        finding_name="Cross-Account Guardrails Enforcement Check",
                        finding_details="Bedrock Guardrails policies are configured at organization level, enabling centralized enforcement of safety controls",
                        resolution="No action required. Continue monitoring guardrail policy coverage and effectiveness.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-enforcements.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "AWSOrganizationsNotInUseException":
                findings["details"] = (
                    "AWS Organizations is not enabled for this account"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-15",
                        finding_name="Cross-Account Guardrails Enforcement Check",
                        finding_details="AWS Organizations is not in use. Cross-account guardrails can only be configured in Organizations-enabled accounts.",
                        resolution="Enable AWS Organizations and configure Bedrock Guardrails policies for centralized multi-account enforcement, or accept single-account guardrail management.",
                        reference="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_bedrock.html",
                        severity="Medium",
                        status="N/A",
                        region=region,
                    )
                )
            elif error_code in ACCESS_DENIED_ERROR_CODES:
                findings["details"] = (
                    "Insufficient permissions to check organizational policies"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-15",
                        finding_name="Cross-Account Guardrails Enforcement Check",
                        finding_details=describe_api_error(
                            e, "Organizations policy check", region
                        ),
                        resolution="Grant organizations:DescribeOrganization and organizations:ListPolicies permissions to the assessment role",
                        reference="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_permissions_overview.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
            else:
                raise

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_cross_account_guardrails: {str(e)}", exc_info=True
        )
        return {
            "check_name": "Cross-Account Guardrails Enforcement Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-15",
                    finding_name="Cross-Account Guardrails Enforcement Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-enforcements.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_guardrail_tier(region: str = "") -> Dict[str, Any]:
    """
    BR-16: Verify guardrails are using Standard tier (vs Express tier) for enhanced protection
    """
    logger.debug("Starting check for Bedrock guardrail tier validation")
    try:
        findings = {
            "check_name": "Guardrail Tier Validation Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_client = boto3.client(
            "bedrock", config=boto3_config, region_name=region
        )

        try:
            # List all guardrails
            guardrails_response = bedrock_client.list_guardrails(maxResults=100)
            guardrails = guardrails_response.get("guardrails", [])

            if not guardrails:
                findings["details"] = "No Bedrock guardrails found"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-16",
                        finding_name="Guardrail Tier Validation Check",
                        finding_details="No Bedrock guardrails configured in this region",
                        resolution="Create Bedrock guardrails with Standard tier for enhanced content filtering and protection",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.html",
                        severity="Medium",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

            suboptimal_guardrails = []
            standard_tier_guardrails = []

            for guardrail_summary in guardrails:
                guardrail_id = guardrail_summary.get("id")
                guardrail_name = guardrail_summary.get("name", "unknown")

                if not guardrail_id:
                    continue

                # Get detailed guardrail configuration
                guardrail_detail = bedrock_client.get_guardrail(
                    guardrailIdentifier=guardrail_id
                )
                guardrail_config = guardrail_detail.get("guardrail", guardrail_detail)

                # The content-filter tier is reported under
                # contentPolicy.tier.tierName. Valid values are CLASSIC and
                # STANDARD; STANDARD is the more robust tier. When a guardrail has
                # no content policy the field is absent, so default to CLASSIC
                # (the baseline) rather than assuming the enhanced tier.
                content_policy = guardrail_config.get("contentPolicy", {})
                tier = content_policy.get("tier", {}).get("tierName", "CLASSIC")

                if tier != "STANDARD":
                    suboptimal_guardrails.append(
                        {"name": guardrail_name, "id": guardrail_id, "tier": tier}
                    )
                else:
                    standard_tier_guardrails.append(guardrail_name)

            if suboptimal_guardrails:
                findings["status"] = "WARN"
                findings["details"] = (
                    f"Found {len(suboptimal_guardrails)} guardrails not using STANDARD tier"
                )

                for gr in suboptimal_guardrails:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-16",
                            finding_name="Guardrail Tier Validation Check",
                            finding_details=f"Guardrail '{gr['name']}' (ID: {gr['id']}) is using the '{gr['tier']}' content-filter tier instead of 'STANDARD'. The STANDARD tier provides more robust content filtering and broader language support than the CLASSIC tier.",
                            resolution="Update the guardrail to use the STANDARD content-filter tier for improved contextual understanding, better prompt attack filtering (distinguishing jailbreaks from prompt injection), and broader language support. The STANDARD tier requires cross-Region inference. Review pricing implications before upgrading.",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.html",
                            severity="Medium",
                            status="Failed",
                            region=region,
                        )
                    )

            if standard_tier_guardrails:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-16",
                        finding_name="Guardrail Tier Validation Check",
                        finding_details=f"{len(standard_tier_guardrails)} guardrails are using the STANDARD content-filter tier with enhanced protection capabilities",
                        resolution="No action required. Continue monitoring guardrail effectiveness.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html",
                        severity="Low",
                        status="Passed",
                        region=region,
                    )
                )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ACCESS_DENIED_ERROR_CODES:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-16",
                        finding_name="Guardrail Tier Validation Check",
                        finding_details=describe_api_error(
                            e, "Guardrail tier check", region
                        ),
                        resolution="Grant bedrock:ListGuardrails and bedrock:GetGuardrail permissions",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
            else:
                raise

        return findings

    except Exception as e:
        logger.error(f"Error in check_bedrock_guardrail_tier: {str(e)}", exc_info=True)
        return {
            "check_name": "Guardrail Tier Validation Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-16",
                    finding_name="Guardrail Tier Validation Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html",
                    severity="Medium",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_custom_model_kms_encryption(region: str = "") -> Dict[str, Any]:
    """
    BR-17: Verify fine-tuned/customized models use customer-managed KMS keys instead of AWS-owned keys
    Note: This extends the existing check_bedrock_custom_model_encryption (BR-11) to specifically verify KMS key type
    """
    logger.debug("Starting check for custom model KMS encryption")
    try:
        findings = {
            "check_name": "Custom Model Customer-Managed KMS Encryption Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_client = boto3.client(
            "bedrock", config=boto3_config, region_name=region
        )

        try:
            # Get custom models using paginator
            paginator = bedrock_client.get_paginator("list_custom_models")
            custom_models = []
            for page in paginator.paginate():
                custom_models.extend(page.get("modelSummaries", []))

            if not custom_models:
                findings["details"] = "No custom models found"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-17",
                        finding_name="Custom Model Customer-Managed KMS Encryption Check",
                        finding_details="No custom (fine-tuned) Bedrock models found in this region",
                        resolution="When creating custom models, specify a customer-managed KMS key for encryption to maintain control over encryption keys",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-custom-job.html",
                        severity="High",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

            models_with_aws_keys = []
            models_with_customer_keys = []
            models_unknown = []

            for model in custom_models:
                model_arn = model.get("modelArn")
                model_name = model.get("modelName", "unknown")

                # Get model details to check encryption
                try:
                    model_detail = bedrock_client.get_custom_model(
                        modelIdentifier=model_arn
                    )

                    # GetCustomModel reports the encryption key as modelKmsKeyArn.
                    # When absent, the model is encrypted with an AWS-owned key.
                    kms_key_id = model_detail.get("modelKmsKeyArn")

                    if not kms_key_id:
                        # No KMS key specified = AWS-owned key
                        models_with_aws_keys.append(
                            {"name": model_name, "arn": model_arn}
                        )
                    elif kms_key_id.startswith("arn:aws:kms"):
                        # Customer-managed KMS key
                        models_with_customer_keys.append(model_name)
                    else:
                        # Unknown key format
                        models_unknown.append(model_name)

                except ClientError as detail_error:
                    error_code = detail_error.response.get("Error", {}).get("Code", "")
                    if error_code not in ACCESS_DENIED_ERROR_CODES:
                        logger.warning(
                            f"Could not get details for model {model_name}: {error_code}"
                        )
                    models_unknown.append(model_name)

            if models_with_aws_keys:
                findings["status"] = "WARN"
                findings["details"] = (
                    f"Found {len(models_with_aws_keys)} custom models using AWS-owned keys"
                )

                for model_info in models_with_aws_keys:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-17",
                            finding_name="Custom Model Customer-Managed KMS Encryption Check",
                            finding_details=f"Custom model '{model_info['name']}' uses AWS-owned encryption keys instead of customer-managed KMS keys. This limits your control over key rotation, access policies, and audit trail.",
                            resolution="When creating new custom models, specify a customer-managed KMS key using the customizationConfig.kmsKeyArn parameter. For existing models, consider retraining with customer-managed KMS encryption. Ensure KMS key grants allow Amazon Bedrock service access.",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-custom-job.html",
                            severity="High",
                            status="Failed",
                            region=region,
                        )
                    )

            if models_with_customer_keys:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-17",
                        finding_name="Custom Model Customer-Managed KMS Encryption Check",
                        finding_details=f"{len(models_with_customer_keys)} custom models are using customer-managed KMS keys for encryption",
                        resolution="No action required. Continue using customer-managed keys for new custom models.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-custom-job.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ACCESS_DENIED_ERROR_CODES:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-17",
                        finding_name="Custom Model Customer-Managed KMS Encryption Check",
                        finding_details=describe_api_error(
                            e, "Custom model encryption check", region
                        ),
                        resolution="Grant bedrock:ListCustomModels and bedrock:GetCustomModel permissions",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )
            else:
                raise

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_custom_model_kms_encryption: {str(e)}",
            exc_info=True,
        )
        return {
            "check_name": "Custom Model Customer-Managed KMS Encryption Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-17",
                    finding_name="Custom Model Customer-Managed KMS Encryption Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-custom-job.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_model_evaluations(region: str = "") -> Dict[str, Any]:
    """
    BR-18: Check if model evaluation jobs exist for foundation models to assess safety metrics
    """
    logger.debug("Starting check for Bedrock model evaluation implementation")
    try:
        findings = {
            "check_name": "Model Evaluation Implementation Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_client = boto3.client(
            "bedrock", config=boto3_config, region_name=region
        )

        try:
            # List model evaluation jobs
            eval_jobs_response = bedrock_client.list_evaluation_jobs(maxResults=100)
            eval_jobs = eval_jobs_response.get("jobSummaries", [])

            if not eval_jobs:
                findings["status"] = "WARN"
                findings["details"] = "No model evaluation jobs found"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-18",
                        finding_name="Model Evaluation Implementation Check",
                        finding_details="No Bedrock model evaluation jobs found. Model evaluation helps assess toxicity, accuracy, semantic robustness, and other safety metrics before production deployment.",
                        resolution="Create model evaluation jobs using Amazon Bedrock Evaluations to assess foundation model performance against safety and quality metrics. Use built-in datasets or custom test sets. Enable LLM-as-a-judge evaluation for comprehensive assessment.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/evaluation.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
                return findings

            # Analyze evaluation jobs
            recent_evaluations = []
            thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)

            for job in eval_jobs:
                job_name = job.get("jobName", "unknown")
                job_status = job.get("status", "unknown")
                creation_time = job.get("creationTime")

                # Check if evaluation is recent (within 30 days)
                is_recent = False
                if creation_time:
                    if isinstance(creation_time, str):
                        try:
                            creation_time = datetime.fromisoformat(
                                creation_time.replace("Z", "+00:00")
                            )
                        except ValueError:
                            pass
                    if isinstance(creation_time, datetime):
                        is_recent = creation_time >= thirty_days_ago

                if is_recent and job_status == "Completed":
                    recent_evaluations.append(job_name)

            findings["details"] = (
                f"Found {len(eval_jobs)} model evaluation jobs, {len(recent_evaluations)} recent"
            )

            if recent_evaluations:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-18",
                        finding_name="Model Evaluation Implementation Check",
                        finding_details=f"Found {len(recent_evaluations)} model evaluation jobs completed in the last 30 days. Regular evaluation helps maintain model quality and safety standards.",
                        resolution="Continue regular model evaluations. Consider implementing automated evaluation pipelines for continuous model validation. Review evaluation results for safety metrics including toxicity and bias.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/evaluation.html",
                        severity="Low",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                findings["status"] = "WARN"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-18",
                        finding_name="Model Evaluation Implementation Check",
                        finding_details=f"Found {len(eval_jobs)} total model evaluation jobs, but none completed in the last 30 days. Regular evaluation is recommended for production models.",
                        resolution="Schedule regular model evaluation runs to assess ongoing model performance and safety. Configure evaluations to include responsible AI metrics like toxicity, accuracy, and robustness.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/evaluation.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            error_msg = str(e)

            if "UnknownOperation" in error_msg or "Unknown operation" in error_msg:
                findings["details"] = (
                    "Model evaluation API not available in this region"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-18",
                        finding_name="Model Evaluation Implementation Check",
                        finding_details=describe_api_error(
                            e, "Model evaluation API", region
                        ),
                        resolution="Model evaluation may not be available in all regions. Check AWS documentation for regional availability.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/evaluation.html",
                        severity="Low",
                        status="N/A",
                        region=region,
                    )
                )
            elif is_account_not_authorized(e):
                findings["details"] = (
                    "Model evaluation not enabled for this account/region"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-18",
                        finding_name="Model Evaluation Implementation Check",
                        finding_details=describe_api_error(
                            e, "Model evaluation check", region
                        ),
                        resolution="Amazon Bedrock model evaluation is not enabled or available for this account in this region. No IAM change is required; enable the feature to assess model evaluation practices.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/evaluation.html",
                        severity="Low",
                        status="N/A",
                        region=region,
                    )
                )
            elif error_code in ACCESS_DENIED_ERROR_CODES:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-18",
                        finding_name="Model Evaluation Implementation Check",
                        finding_details=describe_api_error(
                            e, "Model evaluation check", region
                        ),
                        resolution="Grant bedrock:ListEvaluationJobs permission to assess model evaluation practices",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
            else:
                raise

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_model_evaluations: {str(e)}", exc_info=True
        )
        return {
            "check_name": "Model Evaluation Implementation Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-18",
                    finding_name="Model Evaluation Implementation Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/evaluation.html",
                    severity="Medium",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_prompt_flow_validation(region: str = "") -> Dict[str, Any]:
    """
    BR-19: Verify Bedrock Agents prompt flows are validated before deployment
    """
    logger.debug("Starting check for Bedrock prompt flow validation")
    try:
        findings = {
            "check_name": "Prompt Flow Validation Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_agent_client = boto3.client(
            "bedrock-agent", config=boto3_config, region_name=region
        )

        try:
            # List all flows
            flows_response = bedrock_agent_client.list_flows(maxResults=100)
            flows = flows_response.get("flowSummaries", [])

            if not flows:
                findings["details"] = "No Bedrock prompt flows found"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-19",
                        finding_name="Prompt Flow Validation Check",
                        finding_details="No Bedrock prompt flows configured in this region",
                        resolution="When creating prompt flows, use the ValidateFlowDefinition API to validate flow definitions before deployment",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/flows.html",
                        severity="Medium",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

            unvalidated_flows = []
            validated_flows = []

            for flow_summary in flows:
                flow_id = flow_summary.get("id")
                flow_name = flow_summary.get("name", "unknown")
                flow_status = flow_summary.get("status", "unknown")

                if not flow_id:
                    continue

                # Get detailed flow configuration
                try:
                    flow_detail = bedrock_agent_client.get_flow(flowIdentifier=flow_id)
                    flow_info = flow_detail.get("flow", flow_detail)

                    # GetFlow returns a `validations` array describing problems
                    # found when the flow was last prepared. Treat any validation
                    # entry with ERROR severity as a failed validation. A flow that
                    # is Prepared/Published with no error-level validations is
                    # considered validated.
                    validations = flow_info.get("validations", [])
                    error_validations = [
                        v
                        for v in validations
                        if str(v.get("severity", "")).upper() == "ERROR"
                    ]

                    if error_validations:
                        messages = "; ".join(
                            v.get("message", "unknown") for v in error_validations[:5]
                        )
                        unvalidated_flows.append(
                            {
                                "name": flow_name,
                                "id": flow_id,
                                "status": flow_status,
                                "errors": messages,
                            }
                        )
                    elif flow_status in ["Prepared", "Published"]:
                        validated_flows.append(flow_name)
                    else:
                        # No error-level validations, but the flow has not been
                        # prepared/published, so it has not been validated for
                        # deployment.
                        unvalidated_flows.append(
                            {
                                "name": flow_name,
                                "id": flow_id,
                                "status": flow_status,
                                "errors": "",
                            }
                        )

                except ClientError as detail_error:
                    error_code = detail_error.response.get("Error", {}).get("Code", "")
                    if error_code not in ACCESS_DENIED_ERROR_CODES:
                        logger.warning(
                            f"Could not get details for flow {flow_name}: {error_code}"
                        )

            if unvalidated_flows:
                findings["status"] = "WARN"
                findings["details"] = (
                    f"Found {len(unvalidated_flows)} flows that may not be validated"
                )

                for flow in unvalidated_flows:
                    if flow.get("errors"):
                        detail = (
                            f"Prompt flow '{flow['name']}' (ID: {flow['id']}) has "
                            f"validation errors: {flow['errors']}. Unvalidated flows "
                            "can lead to runtime errors or unexpected behavior."
                        )
                    else:
                        detail = (
                            f"Prompt flow '{flow['name']}' (ID: {flow['id']}) has "
                            f"status '{flow['status']}' and has not been validated for "
                            "deployment. Unvalidated flows can lead to runtime errors "
                            "or unexpected behavior."
                        )
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-19",
                            finding_name="Prompt Flow Validation Check",
                            finding_details=detail,
                            resolution="Use the ValidateFlowDefinition API to validate the flow definition before preparing or publishing. Fix any validation errors before deployment. Ensure all nodes, connections, and configurations are correct.",
                            reference="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_ValidateFlowDefinition.html",
                            severity="Medium",
                            status="Failed",
                            region=region,
                        )
                    )

            if validated_flows:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-19",
                        finding_name="Prompt Flow Validation Check",
                        finding_details=f"{len(validated_flows)} prompt flows are validated and prepared for deployment",
                        resolution="No action required. Continue validating flows before deployment.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/flows.html",
                        severity="Low",
                        status="Passed",
                        region=region,
                    )
                )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            error_msg = str(e)

            if "UnknownOperation" in error_msg or "Unknown operation" in error_msg:
                findings["details"] = "Prompt flows API not available in this region"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-19",
                        finding_name="Prompt Flow Validation Check",
                        finding_details=describe_api_error(
                            e, "Prompt flows API", region
                        ),
                        resolution="Bedrock prompt flows may not be available in all regions",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/flows.html",
                        severity="Low",
                        status="N/A",
                        region=region,
                    )
                )
            elif error_code in ACCESS_DENIED_ERROR_CODES:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-19",
                        finding_name="Prompt Flow Validation Check",
                        finding_details=describe_api_error(
                            e, "Prompt flow check", region
                        ),
                        resolution="Grant bedrock-agent:ListFlows and bedrock-agent:GetFlow permissions",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
            else:
                raise

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_prompt_flow_validation: {str(e)}", exc_info=True
        )
        return {
            "check_name": "Prompt Flow Validation Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-19",
                    finding_name="Prompt Flow Validation Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/flows.html",
                    severity="Medium",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_knowledge_base_kms_encryption(region: str = "") -> Dict[str, Any]:
    """
    BR-20: Verify Knowledge Base vector stores use customer-managed KMS keys (extends BR-09)
    """
    logger.debug("Starting check for Knowledge Base customer-managed KMS encryption")
    try:
        findings = {
            "check_name": "Knowledge Base Customer-Managed KMS Encryption Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_agent_client = boto3.client(
            "bedrock-agent", config=boto3_config, region_name=region
        )

        try:
            # List all knowledge bases
            kb_response = bedrock_agent_client.list_knowledge_bases(maxResults=100)
            knowledge_bases = kb_response.get("knowledgeBaseSummaries", [])

            if not knowledge_bases:
                findings["details"] = "No Bedrock knowledge bases found"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-20",
                        finding_name="Knowledge Base Customer-Managed KMS Encryption Check",
                        finding_details="No Bedrock knowledge bases found in this region",
                        resolution="When creating knowledge bases, specify customer-managed KMS keys for both vector store and data source encryption",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-kb.html",
                        severity="High",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

            kbs_with_aws_keys = []
            kbs_with_customer_keys = []
            kbs_storage_layer_review = []
            kbs_indeterminate = []

            for kb_summary in knowledge_bases:
                kb_id = kb_summary.get("knowledgeBaseId")
                kb_name = kb_summary.get("name", "unknown")

                if not kb_id:
                    continue

                # Get detailed KB configuration
                try:
                    kb_detail = bedrock_agent_client.get_knowledge_base(
                        knowledgeBaseId=kb_id
                    )
                    kb_config = kb_detail.get("knowledgeBase", {})

                    # The KB `type` (VECTOR | KENDRA | SQL | MANAGED) is the
                    # authoritative discriminator and is present in every SDK
                    # version. Only a MANAGED knowledge base exposes the
                    # customer-managed KMS key directly on the KB, under
                    # knowledgeBaseConfiguration.managedKnowledgeBaseConfiguration.
                    # serverSideEncryptionConfiguration.kmsKeyArn. For VECTOR / SQL /
                    # KENDRA stores the encryption key lives on the underlying
                    # storage resource and cannot be read from this API, so those
                    # are flagged for manual review rather than reported as failures.
                    kb_configuration = kb_config.get("knowledgeBaseConfiguration", {})
                    kb_type = kb_configuration.get("type", "")
                    managed_config = kb_configuration.get(
                        "managedKnowledgeBaseConfiguration"
                    )
                    storage_config = kb_config.get("storageConfiguration", {})
                    storage_type = storage_config.get("type") or kb_type or "Unknown"

                    is_managed_type = kb_type == "MANAGED"

                    if is_managed_type and managed_config is None:
                        # The KB is MANAGED but the managedKnowledgeBaseConfiguration
                        # block is absent from the response. This happens when the
                        # bundled botocore model predates the field (added in
                        # botocore 1.43.32); botocore silently strips unmodeled
                        # fields. Surface as indeterminate rather than failing or
                        # passing on incomplete data.
                        kbs_indeterminate.append({"name": kb_name, "id": kb_id})
                    elif managed_config is not None:
                        sse_config = managed_config.get(
                            "serverSideEncryptionConfiguration", {}
                        )
                        kms_key_arn = sse_config.get("kmsKeyArn")

                        if kms_key_arn and kms_key_arn.startswith("arn:aws:kms"):
                            kbs_with_customer_keys.append(kb_name)
                        else:
                            kbs_with_aws_keys.append(
                                {
                                    "name": kb_name,
                                    "id": kb_id,
                                    "storage_type": "Managed (Amazon Bedrock)",
                                }
                            )
                    else:
                        # Custom vector store (VECTOR / SQL / KENDRA): encryption is
                        # managed at the storage layer and cannot be validated from
                        # the KB API.
                        kbs_storage_layer_review.append(
                            {
                                "name": kb_name,
                                "id": kb_id,
                                "storage_type": storage_type,
                            }
                        )

                except ClientError as detail_error:
                    error_code = detail_error.response.get("Error", {}).get("Code", "")
                    if error_code not in ACCESS_DENIED_ERROR_CODES:
                        logger.warning(
                            f"Could not get details for KB {kb_name}: {error_code}"
                        )

            if kbs_with_aws_keys:
                findings["status"] = "WARN"
                findings["details"] = (
                    f"Found {len(kbs_with_aws_keys)} managed knowledge bases without a customer-managed KMS key"
                )

                for kb in kbs_with_aws_keys:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-20",
                            finding_name="Knowledge Base Customer-Managed KMS Encryption Check",
                            finding_details=f"Managed knowledge base '{kb['name']}' (ID: {kb['id']}) does not have a customer-managed KMS key configured and is encrypted with an AWS-owned key. This limits control over key rotation, access policies, and audit trails.",
                            resolution="When creating or updating a managed knowledge base, specify a customer-managed KMS key ARN under knowledgeBaseConfiguration.managedKnowledgeBaseConfiguration.serverSideEncryptionConfiguration.kmsKeyArn. Ensure the KMS key policy allows Amazon Bedrock service access.",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-kb.html",
                            severity="High",
                            status="Failed",
                            region=region,
                        )
                    )

            if kbs_storage_layer_review:
                if findings["status"] == "PASS":
                    findings["status"] = "WARN"
                for kb in kbs_storage_layer_review:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-20",
                            finding_name="Knowledge Base Customer-Managed KMS Encryption Review",
                            finding_details=f"Knowledge base '{kb['name']}' (ID: {kb['id']}) uses '{kb['storage_type']}' storage. The vector-store encryption key is managed at the storage layer and cannot be validated from the Knowledge Base API. Verify customer-managed KMS encryption on the underlying store.",
                            resolution="1. For OpenSearch Serverless: verify the collection uses a customer-managed KMS key\n2. For Amazon RDS/Aurora: verify KMS encryption on the database\n3. For third-party stores (Pinecone, Redis, MongoDB): verify the provider's encryption configuration\n4. Verify the customer-managed KMS key used for transient data during ingestion",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-kb.html",
                            severity="Informational",
                            status="N/A",
                            region=region,
                        )
                    )

            if kbs_indeterminate:
                if findings["status"] == "PASS":
                    findings["status"] = "WARN"
                for kb in kbs_indeterminate:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-20",
                            finding_name="Knowledge Base Customer-Managed KMS Encryption Review",
                            finding_details=f"Knowledge base '{kb['name']}' (ID: {kb['id']}) is a MANAGED knowledge base, but its encryption configuration could not be read from the API response. This typically means the deployed AWS SDK (botocore) predates the managedKnowledgeBaseConfiguration field (added in botocore 1.43.32) and silently dropped it. Customer-managed KMS encryption could not be confirmed.",
                            resolution="Upgrade the function's bundled boto3/botocore to 1.43.32 or later so the managed knowledge base encryption configuration is returned, then re-run the assessment. Meanwhile, verify the customer-managed KMS key in the Amazon Bedrock console.",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-kb.html",
                            severity="Informational",
                            status="N/A",
                            region=region,
                        )
                    )

            if kbs_with_customer_keys:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-20",
                        finding_name="Knowledge Base Customer-Managed KMS Encryption Check",
                        finding_details=f"{len(kbs_with_customer_keys)} managed knowledge bases are using customer-managed KMS keys",
                        resolution="No action required. Continue using customer-managed keys for new knowledge bases.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-kb.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if is_region_unsupported(e):
                findings["details"] = "Knowledge Bases API not available in this region"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-20",
                        finding_name="Knowledge Base Customer-Managed KMS Encryption Check",
                        finding_details=describe_api_error(
                            e, "Knowledge Bases API", region
                        ),
                        resolution="Amazon Bedrock Knowledge Bases are not available in this region. No action required.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-kb.html",
                        severity="Low",
                        status="N/A",
                        region=region,
                    )
                )
            elif error_code in ACCESS_DENIED_ERROR_CODES:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-20",
                        finding_name="Knowledge Base Customer-Managed KMS Encryption Check",
                        finding_details=describe_api_error(
                            e, "Knowledge base encryption check", region
                        ),
                        resolution="Grant bedrock-agent:ListKnowledgeBases and bedrock-agent:GetKnowledgeBase permissions",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )
            else:
                raise

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_knowledge_base_kms_encryption: {str(e)}",
            exc_info=True,
        )
        return {
            "check_name": "Knowledge Base Customer-Managed KMS Encryption Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-20",
                    finding_name="Knowledge Base Customer-Managed KMS Encryption Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-kb.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_agent_action_group_iam(
    region: str = "", permission_cache: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    BR-21: Check if Bedrock Agent action groups use scoped Lambda execution roles (extends BR-08)
    """
    logger.debug("Starting check for Bedrock Agent action group IAM least privilege")

    if permission_cache is None:
        permission_cache = {}

    try:
        findings = {
            "check_name": "Agent Action Group IAM Least Privilege Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_agent_client = boto3.client(
            "bedrock-agent", config=boto3_config, region_name=region
        )
        lambda_client = boto3.client("lambda", config=boto3_config, region_name=region)

        try:
            # List all agents
            agents_response = bedrock_agent_client.list_agents(maxResults=100)
            agents = agents_response.get("agentSummaries", [])

            if not agents:
                findings["details"] = "No Bedrock agents found"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-21",
                        finding_name="Agent Action Group IAM Least Privilege Check",
                        finding_details="No Bedrock agents configured in this region",
                        resolution="When creating agents with action groups, ensure Lambda execution roles follow least privilege principles",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-security.html",
                        severity="High",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

            overly_permissive_lambdas = []
            compliant_lambdas = []

            for agent_summary in agents:
                agent_id = agent_summary.get("agentId")
                agent_name = agent_summary.get("agentName", "unknown")

                if not agent_id:
                    continue

                try:
                    # Get agent action groups
                    action_groups_response = (
                        bedrock_agent_client.list_agent_action_groups(
                            agentId=agent_id, agentVersion="DRAFT", maxResults=100
                        )
                    )
                    action_groups = action_groups_response.get(
                        "actionGroupSummaries", []
                    )

                    for action_group in action_groups:
                        # Get action group details
                        action_group_id = action_group.get("actionGroupId")
                        action_group_name = action_group.get(
                            "actionGroupName", "unknown"
                        )

                        if not action_group_id:
                            continue

                        try:
                            ag_detail = bedrock_agent_client.get_agent_action_group(
                                agentId=agent_id,
                                agentVersion="DRAFT",
                                actionGroupId=action_group_id,
                            )
                            ag_config = ag_detail.get("agentActionGroup", {})

                            # Get Lambda function ARN if configured
                            action_group_executor = ag_config.get(
                                "actionGroupExecutor", {}
                            )
                            lambda_arn = action_group_executor.get("lambda")

                            if lambda_arn:
                                # Extract function name from ARN
                                function_name = (
                                    lambda_arn.split(":")[-1]
                                    if ":" in lambda_arn
                                    else lambda_arn
                                )

                                try:
                                    # Get Lambda function configuration
                                    lambda_config = lambda_client.get_function(
                                        FunctionName=function_name
                                    )
                                    role_arn = lambda_config.get(
                                        "Configuration", {}
                                    ).get("Role")

                                    if role_arn:
                                        # Check if role has overly broad permissions
                                        role_name = role_arn.split("/")[-1]

                                        # Check permission cache for this role. Each
                                        # policy entry is a dict {"name", "document"},
                                        # so inspect the policy name rather than the
                                        # dict itself.
                                        role_perms = permission_cache.get(
                                            "role_permissions", {}
                                        ).get(role_name, {})
                                        attached_policies = role_perms.get(
                                            "attached_policies", []
                                        )
                                        inline_policies = role_perms.get(
                                            "inline_policies", []
                                        )

                                        # Check for overly permissive managed policies
                                        # by policy name.
                                        has_admin_access = any(
                                            p.get("name") == "AdministratorAccess"
                                            for p in attached_policies
                                        )
                                        has_full_access = any(
                                            "FullAccess" in (p.get("name") or "")
                                            for p in attached_policies
                                        )
                                        # Check inline policy documents for an Allow on
                                        # Action "*" / Resource "*" (wildcard access).
                                        has_star_resource = any(
                                            _policy_grants_wildcard(p.get("document"))
                                            for p in inline_policies
                                        )

                                        if (
                                            has_admin_access
                                            or has_full_access
                                            or has_star_resource
                                        ):
                                            if has_admin_access:
                                                issue = "AdministratorAccess"
                                            elif has_full_access:
                                                issue = "a *FullAccess managed policy"
                                            else:
                                                issue = (
                                                    "an inline policy granting wildcard "
                                                    'Action/Resource ("*")'
                                                )
                                            overly_permissive_lambdas.append(
                                                {
                                                    "agent_name": agent_name,
                                                    "action_group": action_group_name,
                                                    "function_name": function_name,
                                                    "role_name": role_name,
                                                    "issue": issue,
                                                }
                                            )
                                        else:
                                            compliant_lambdas.append(function_name)

                                except ClientError as lambda_error:
                                    error_code = lambda_error.response.get(
                                        "Error", {}
                                    ).get("Code", "")
                                    if error_code not in ACCESS_DENIED_ERROR_CODES:
                                        logger.warning(
                                            f"Could not get Lambda config for {function_name}: {error_code}"
                                        )

                        except ClientError as ag_error:
                            error_code = ag_error.response.get("Error", {}).get(
                                "Code", ""
                            )
                            if error_code not in ACCESS_DENIED_ERROR_CODES:
                                logger.warning(
                                    f"Could not get action group details: {error_code}"
                                )

                except ClientError as list_error:
                    error_code = list_error.response.get("Error", {}).get("Code", "")
                    if error_code not in ACCESS_DENIED_ERROR_CODES:
                        logger.warning(
                            f"Could not list action groups for agent {agent_name}: {error_code}"
                        )

            if overly_permissive_lambdas:
                findings["status"] = "WARN"
                findings["details"] = (
                    f"Found {len(overly_permissive_lambdas)} Lambda functions with overly permissive IAM roles"
                )

                for lambda_info in overly_permissive_lambdas:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-21",
                            finding_name="Agent Action Group IAM Least Privilege Check",
                            finding_details=f"Lambda function '{lambda_info['function_name']}' used by agent '{lambda_info['agent_name']}' action group '{lambda_info['action_group']}' has role '{lambda_info['role_name']}' with {lambda_info['issue']}. This violates least privilege principles.",
                            resolution="Update the Lambda execution role to use scoped permissions. Remove AdministratorAccess and FullAccess policies. Grant only the specific AWS service permissions needed for the action group's operations. Use Resource-based policies to scope permissions to specific resources.",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-security.html",
                            severity="High",
                            status="Failed",
                            region=region,
                        )
                    )

            if compliant_lambdas:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-21",
                        finding_name="Agent Action Group IAM Least Privilege Check",
                        finding_details=f"{len(compliant_lambdas)} Lambda functions are using scoped IAM roles",
                        resolution="No action required. Continue using least privilege IAM roles for action group Lambda functions.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-security.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if is_region_unsupported(e):
                findings["details"] = "Bedrock Agents API not available in this region"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-21",
                        finding_name="Agent Action Group IAM Least Privilege Check",
                        finding_details=describe_api_error(
                            e, "Bedrock Agents API", region
                        ),
                        resolution="Amazon Bedrock Agents are not available in this region. No action required.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/agents.html",
                        severity="Low",
                        status="N/A",
                        region=region,
                    )
                )
            elif error_code in ACCESS_DENIED_ERROR_CODES:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-21",
                        finding_name="Agent Action Group IAM Least Privilege Check",
                        finding_details=describe_api_error(
                            e, "Agent action group IAM check", region
                        ),
                        resolution="Grant bedrock-agent:ListAgents, bedrock-agent:ListAgentActionGroups, bedrock-agent:GetAgentActionGroup, and lambda:GetFunction permissions",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )
            else:
                raise

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_agent_action_group_iam: {str(e)}", exc_info=True
        )
        return {
            "check_name": "Agent Action Group IAM Least Privilege Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-21",
                    finding_name="Agent Action Group IAM Least Privilege Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_service_quotas_throttling(region: str = "") -> Dict[str, Any]:
    """
    BR-22: Verify service quotas are configured for model invocation throttling
    """
    logger.debug("Starting check for Bedrock service quotas throttling limits")
    try:
        findings = {
            "check_name": "Model Invocation Throttling Limits Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        service_quotas_client = boto3.client(
            "service-quotas", config=boto3_config, region_name=region
        )

        try:
            # List Bedrock service quotas
            quotas_response = service_quotas_client.list_service_quotas(
                ServiceCode="bedrock", MaxResults=100
            )
            quotas = quotas_response.get("Quotas", [])

            if not quotas:
                findings["details"] = "Could not retrieve Bedrock service quotas"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-22",
                        finding_name="Model Invocation Throttling Limits Check",
                        finding_details="Unable to retrieve Bedrock service quotas for this region",
                        resolution="Verify service quotas access and ensure Bedrock is available in this region",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/quotas.html",
                        severity="Medium",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

            # Check for custom quotas (non-default values indicate intentional configuration)
            custom_quotas = []
            default_quotas = []

            for quota in quotas:
                quota_name = quota.get("QuotaName", "unknown")
                quota_code = quota.get("QuotaCode", "")

                # Check if quota is related to throttling/rate limits
                is_throttling_quota = any(
                    keyword in quota_name.lower()
                    for keyword in [
                        "tokens per minute",
                        "tpm",
                        "requests per",
                        "throughput",
                        "invocations",
                    ]
                )

                if is_throttling_quota:
                    # Check if quota has been customized
                    default_value = quota.get("Value", 0)
                    adjustable = quota.get("Adjustable", False)

                    # Try to get applied quota (custom value if set)
                    try:
                        applied_quota = service_quotas_client.get_service_quota(
                            ServiceCode="bedrock", QuotaCode=quota_code
                        )
                        applied_value = applied_quota.get("Quota", {}).get(
                            "Value", default_value
                        )

                        if applied_value != default_value or not adjustable:
                            custom_quotas.append(
                                {
                                    "name": quota_name,
                                    "value": applied_value,
                                    "adjustable": adjustable,
                                }
                            )
                        else:
                            default_quotas.append(quota_name)
                    except ClientError:
                        # If we can't get applied quota, assume default
                        if adjustable:
                            default_quotas.append(quota_name)

            if not custom_quotas and default_quotas:
                findings["status"] = "WARN"
                findings["details"] = "No custom throttling quotas configured"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-22",
                        finding_name="Model Invocation Throttling Limits Check",
                        finding_details="Account is using default Bedrock service quotas for model invocation throttling. Custom quotas help prevent abuse, control costs, and ensure fair resource usage across applications.",
                        resolution="Review Bedrock service quotas and configure custom limits for model invocation rates (tokens per minute) based on your application requirements. Request quota increases through AWS Service Quotas console if needed. Set up CloudWatch alarms to monitor quota utilization.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/quotas.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
            elif custom_quotas:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-22",
                        finding_name="Model Invocation Throttling Limits Check",
                        finding_details=f"{len(custom_quotas)} custom throttling quotas are configured. Regular quota review helps maintain appropriate rate limits.",
                        resolution="Continue monitoring quota utilization. Review and adjust quotas as application requirements change.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/quotas.html",
                        severity="Low",
                        status="Passed",
                        region=region,
                    )
                )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            error_msg = str(e)

            if (
                "NoSuchResourceException" in error_msg
                or "not found" in error_msg.lower()
            ):
                findings["details"] = "Bedrock service quotas not available"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-22",
                        finding_name="Model Invocation Throttling Limits Check",
                        finding_details="Bedrock service quotas not found in Service Quotas API for this region",
                        resolution="Bedrock may not be available in this region or quotas may not be published to Service Quotas API",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/quotas.html",
                        severity="Low",
                        status="N/A",
                        region=region,
                    )
                )
            elif error_code in ACCESS_DENIED_ERROR_CODES:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-22",
                        finding_name="Model Invocation Throttling Limits Check",
                        finding_details=describe_api_error(
                            e, "Service quotas check", region
                        ),
                        resolution="Grant servicequotas:ListServiceQuotas and servicequotas:GetServiceQuota permissions",
                        reference="https://docs.aws.amazon.com/servicequotas/latest/userguide/identity-access-management.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
            else:
                raise

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_service_quotas_throttling: {str(e)}", exc_info=True
        )
        return {
            "check_name": "Model Invocation Throttling Limits Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-22",
                    finding_name="Model Invocation Throttling Limits Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/quotas.html",
                    severity="Medium",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_guardrail_content_filters(region: str = "") -> Dict[str, Any]:
    """
    BR-23: Verify guardrails have ALL content filters enabled (extends BR-05)
    """
    logger.debug("Starting check for Bedrock guardrail content filter coverage")
    try:
        findings = {
            "check_name": "Guardrail Content Filter Coverage Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_client = boto3.client(
            "bedrock", config=boto3_config, region_name=region
        )

        try:
            # List all guardrails
            guardrails_response = bedrock_client.list_guardrails(maxResults=100)
            guardrails = guardrails_response.get("guardrails", [])

            if not guardrails:
                findings["details"] = "No Bedrock guardrails found"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-23",
                        finding_name="Guardrail Content Filter Coverage Check",
                        finding_details="No Bedrock guardrails configured in this region",
                        resolution="Create guardrails with all content filters enabled (hate, insults, sexual, violence) with appropriate thresholds",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-content-filters.html",
                        severity="High",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

            incomplete_guardrails = []
            complete_guardrails = []

            for guardrail_summary in guardrails:
                guardrail_id = guardrail_summary.get("id")
                guardrail_name = guardrail_summary.get("name", "unknown")

                if not guardrail_id:
                    continue

                # Get detailed guardrail configuration
                guardrail_detail = bedrock_client.get_guardrail(
                    guardrailIdentifier=guardrail_id
                )
                guardrail_config = guardrail_detail.get("guardrail", guardrail_detail)

                # Check content filter configuration. GetGuardrail reports the
                # configured filters under contentPolicy.filters (the *Config
                # field names are part of the Create/Update request shape, not the
                # response).
                content_policy = guardrail_config.get("contentPolicy", {})
                filters_config = content_policy.get("filters", [])

                # Required filter types
                required_filters = {"HATE", "INSULTS", "SEXUAL", "VIOLENCE"}
                configured_filters = set()
                missing_filters = []

                for filter_item in filters_config:
                    filter_type = filter_item.get("type")
                    input_strength = filter_item.get("inputStrength", "NONE")
                    output_strength = filter_item.get("outputStrength", "NONE")

                    if filter_type in required_filters:
                        # Filter is considered configured if it has any strength other than NONE
                        if input_strength != "NONE" or output_strength != "NONE":
                            configured_filters.add(filter_type)

                # Find missing filters
                missing_filters = required_filters - configured_filters

                if missing_filters:
                    incomplete_guardrails.append(
                        {
                            "name": guardrail_name,
                            "id": guardrail_id,
                            "missing": list(missing_filters),
                        }
                    )
                else:
                    complete_guardrails.append(guardrail_name)

            if incomplete_guardrails:
                findings["status"] = "WARN"
                findings["details"] = (
                    f"Found {len(incomplete_guardrails)} guardrails with incomplete content filter coverage"
                )

                for gr in incomplete_guardrails:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-23",
                            finding_name="Guardrail Content Filter Coverage Check",
                            finding_details=f"Guardrail '{gr['name']}' (ID: {gr['id']}) is missing content filters: {', '.join(gr['missing'])}. Complete content filter coverage is essential for comprehensive content safety.",
                            resolution="Update guardrail to enable all content filters (HATE, INSULTS, SEXUAL, VIOLENCE). Configure appropriate threshold levels (LOW, MEDIUM, HIGH) for both input and output filtering based on your use case. Review AWS documentation for threshold guidance.",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-content-filters.html",
                            severity="High",
                            status="Failed",
                            region=region,
                        )
                    )

            if complete_guardrails:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-23",
                        finding_name="Guardrail Content Filter Coverage Check",
                        finding_details=f"{len(complete_guardrails)} guardrails have complete content filter coverage (hate, insults, sexual, violence)",
                        resolution="No action required. Continue monitoring filter effectiveness and adjust thresholds as needed.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-content-filters.html",
                        severity="Low",
                        status="Passed",
                        region=region,
                    )
                )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ACCESS_DENIED_ERROR_CODES:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-23",
                        finding_name="Guardrail Content Filter Coverage Check",
                        finding_details=describe_api_error(
                            e, "Guardrail content filter check", region
                        ),
                        resolution="Grant bedrock:ListGuardrails and bedrock:GetGuardrail permissions",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )
            else:
                raise

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_guardrail_content_filters: {str(e)}", exc_info=True
        )
        return {
            "check_name": "Guardrail Content Filter Coverage Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-23",
                    finding_name="Guardrail Content Filter Coverage Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-content-filters.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_automated_reasoning_policy(region: str = "") -> Dict[str, Any]:
    """
    BR-24: Check if Automated Reasoning policies are configured on guardrails
    """
    logger.debug("Starting check for Bedrock Automated Reasoning policy implementation")
    try:
        findings = {
            "check_name": "Automated Reasoning Policy Implementation Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_client = boto3.client(
            "bedrock", config=boto3_config, region_name=region
        )

        try:
            # List all guardrails
            guardrails_response = bedrock_client.list_guardrails(maxResults=100)
            guardrails = guardrails_response.get("guardrails", [])

            if not guardrails:
                findings["details"] = "No Bedrock guardrails found"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-24",
                        finding_name="Automated Reasoning Policy Implementation Check",
                        finding_details="No Bedrock guardrails configured in this region",
                        resolution="Create guardrails with Automated Reasoning policies for formal verification of model responses",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-automated-reasoning.html",
                        severity="Medium",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

            without_ar_policy = []
            with_ar_policy = []

            for guardrail_summary in guardrails:
                guardrail_id = guardrail_summary.get("id")
                guardrail_name = guardrail_summary.get("name", "unknown")

                if not guardrail_id:
                    continue

                # Get detailed guardrail configuration
                try:
                    guardrail_detail = bedrock_client.get_guardrail(
                        guardrailIdentifier=guardrail_id
                    )
                    guardrail_config = guardrail_detail.get(
                        "guardrail", guardrail_detail
                    )

                    # GetGuardrail reports Automated Reasoning under
                    # automatedReasoningPolicy.policies. The guardrail has a policy
                    # configured when that list is non-empty.
                    ar_policy = guardrail_config.get("automatedReasoningPolicy") or {}
                    has_ar_policy = bool(ar_policy.get("policies"))

                    if not has_ar_policy:
                        without_ar_policy.append(
                            {"name": guardrail_name, "id": guardrail_id}
                        )
                    else:
                        with_ar_policy.append(guardrail_name)

                except ClientError as detail_error:
                    error_code = detail_error.response.get("Error", {}).get("Code", "")
                    if error_code not in ACCESS_DENIED_ERROR_CODES:
                        logger.warning(
                            f"Could not get details for guardrail {guardrail_name}: {error_code}"
                        )

            if without_ar_policy:
                findings["status"] = "WARN"
                findings["details"] = (
                    f"Found {len(without_ar_policy)} guardrails without Automated Reasoning policies"
                )

                for gr in without_ar_policy:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-24",
                            finding_name="Automated Reasoning Policy Implementation Check",
                            finding_details=f"Guardrail '{gr['name']}' (ID: {gr['id']}) does not have an Automated Reasoning policy configured. Automated Reasoning provides formal verification of model responses against defined policies.",
                            resolution="Configure Automated Reasoning policies on guardrails to mathematically verify model responses. Define policies that specify allowed and disallowed behaviors. Use for high-assurance use cases where formal verification is required.",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-automated-reasoning.html",
                            severity="Medium",
                            status="Failed",
                            region=region,
                        )
                    )

            if with_ar_policy:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-24",
                        finding_name="Automated Reasoning Policy Implementation Check",
                        finding_details=f"{len(with_ar_policy)} guardrails have Automated Reasoning policies configured for formal verification",
                        resolution="No action required. Continue using Automated Reasoning for high-assurance verification.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-automated-reasoning.html",
                        severity="Low",
                        status="Passed",
                        region=region,
                    )
                )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            error_msg = str(e)

            if "UnknownOperation" in error_msg or "Unknown operation" in error_msg:
                findings["details"] = (
                    "Automated Reasoning feature not available in this region"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-24",
                        finding_name="Automated Reasoning Policy Implementation Check",
                        finding_details=describe_api_error(
                            e, "Automated Reasoning API", region
                        ),
                        resolution="Automated Reasoning may not be available in all regions. Check AWS documentation for regional availability.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-automated-reasoning.html",
                        severity="Low",
                        status="N/A",
                        region=region,
                    )
                )
            elif error_code in ACCESS_DENIED_ERROR_CODES:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-24",
                        finding_name="Automated Reasoning Policy Implementation Check",
                        finding_details=describe_api_error(
                            e, "Automated Reasoning policy check", region
                        ),
                        resolution="Grant bedrock:ListGuardrails and bedrock:GetGuardrail permissions",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
            else:
                raise

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_automated_reasoning_policy: {str(e)}",
            exc_info=True,
        )
        return {
            "check_name": "Automated Reasoning Policy Implementation Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-24",
                    finding_name="Automated Reasoning Policy Implementation Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-automated-reasoning.html",
                    severity="Medium",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_rag_evaluation_jobs(region: str = "") -> Dict[str, Any]:
    """
    BR-25: Verify RAG applications have evaluation jobs configured
    """
    logger.debug("Starting check for Bedrock RAG evaluation jobs")
    try:
        findings = {
            "check_name": "RAG Evaluation Jobs Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_agent_client = boto3.client(
            "bedrock-agent", config=boto3_config, region_name=region
        )
        bedrock_client = boto3.client(
            "bedrock", config=boto3_config, region_name=region
        )

        try:
            # List all knowledge bases
            kb_response = bedrock_agent_client.list_knowledge_bases(maxResults=100)
            knowledge_bases = kb_response.get("knowledgeBaseSummaries", [])

            if not knowledge_bases:
                findings["details"] = "No knowledge bases found"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-25",
                        finding_name="RAG Evaluation Jobs Check",
                        finding_details="No Bedrock knowledge bases found in this region",
                        resolution="When implementing RAG applications, configure evaluation jobs to assess context relevance, response correctness, and prevent hallucinations",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-evaluation-rag.html",
                        severity="Low",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

            # List evaluation jobs (filter for RAG-related evaluations)
            try:
                eval_jobs_response = bedrock_client.list_evaluation_jobs(maxResults=100)
                eval_jobs = eval_jobs_response.get("jobSummaries", [])

                # Map knowledge bases to evaluation jobs
                kbs_with_evals = set()
                recent_evaluations = []
                thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)

                for job in eval_jobs:
                    job_name = job.get("jobName", "")
                    job_status = job.get("status", "unknown")
                    creation_time = job.get("creationTime")

                    # Check if this is a RAG evaluation (simple heuristic: name contains kb id or "rag")
                    is_rag_eval = "rag" in job_name.lower() or any(
                        kb["knowledgeBaseId"] in job_name for kb in knowledge_bases
                    )

                    if is_rag_eval:
                        # Check if evaluation is recent
                        is_recent = False
                        if creation_time:
                            if isinstance(creation_time, str):
                                try:
                                    creation_time = datetime.fromisoformat(
                                        creation_time.replace("Z", "+00:00")
                                    )
                                except ValueError:
                                    pass
                            if isinstance(creation_time, datetime):
                                is_recent = creation_time >= thirty_days_ago

                        if is_recent and job_status == "Completed":
                            recent_evaluations.append(job_name)
                            # Try to identify which KB this evaluation is for
                            for kb in knowledge_bases:
                                if kb["knowledgeBaseId"] in job_name:
                                    kbs_with_evals.add(kb["knowledgeBaseId"])

                kbs_without_evals = [
                    kb
                    for kb in knowledge_bases
                    if kb["knowledgeBaseId"] not in kbs_with_evals
                ]

                if kbs_without_evals:
                    findings["status"] = "WARN"
                    findings["details"] = (
                        f"Found {len(kbs_without_evals)} knowledge bases without recent RAG evaluation jobs"
                    )

                    for kb in kbs_without_evals:
                        findings["csv_data"].append(
                            create_finding(
                                check_id="BR-25",
                                finding_name="RAG Evaluation Jobs Check",
                                finding_details=f"Knowledge base '{kb['name']}' (ID: {kb['knowledgeBaseId']}) does not have recent RAG evaluation jobs. RAG evaluations assess context relevance, response correctness, faithfulness, and harmfulness to prevent hallucinations.",
                                resolution="Create RAG evaluation jobs for knowledge bases using Amazon Bedrock Model Evaluation. Configure evaluations to test context relevance, answer correctness, and faithfulness metrics. Run evaluations regularly (monthly or after significant KB updates) to maintain quality.",
                                reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-evaluation-rag.html",
                                severity="Low",
                                status="Failed",
                                region=region,
                            )
                        )

                if recent_evaluations:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-25",
                            finding_name="RAG Evaluation Jobs Check",
                            finding_details=f"Found {len(recent_evaluations)} recent RAG evaluation jobs. Regular RAG evaluations help maintain response quality and prevent hallucinations.",
                            resolution="Continue regular RAG evaluations. Review evaluation results and adjust retrieval strategies or knowledge base content as needed.",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-evaluation-rag.html",
                            severity="Low",
                            status="Passed",
                            region=region,
                        )
                    )

            except ClientError as eval_error:
                error_code = eval_error.response.get("Error", {}).get("Code", "")
                if error_code not in ACCESS_DENIED_ERROR_CODES:
                    logger.warning(f"Could not list evaluation jobs: {error_code}")
                    # Continue check even if evaluation jobs API fails

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if is_region_unsupported(e):
                findings["details"] = (
                    "Knowledge Bases / evaluation API not available in this region"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-25",
                        finding_name="RAG Evaluation Jobs Check",
                        finding_details=describe_api_error(
                            e, "RAG evaluation API", region
                        ),
                        resolution="Amazon Bedrock Knowledge Bases or RAG evaluation are not available in this region. No action required.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-evaluation-rag.html",
                        severity="Low",
                        status="N/A",
                        region=region,
                    )
                )
            elif error_code in ACCESS_DENIED_ERROR_CODES:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-25",
                        finding_name="RAG Evaluation Jobs Check",
                        finding_details=describe_api_error(
                            e, "RAG evaluation check", region
                        ),
                        resolution="Grant bedrock-agent:ListKnowledgeBases and bedrock:ListEvaluationJobs permissions",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples.html",
                        severity="Low",
                        status="Failed",
                        region=region,
                    )
                )
            else:
                raise

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_rag_evaluation_jobs: {str(e)}", exc_info=True
        )
        return {
            "check_name": "RAG Evaluation Jobs Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-25",
                    finding_name="RAG Evaluation Jobs Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-evaluation-rag.html",
                    severity="Low",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_guardrail_pii_filters(region: str = "") -> Dict[str, Any]:
    """
    BR-26: Verify guardrails configure sensitive-information (PII) protection
    (extends BR-23, which only covers the harmful-content filters).
    """
    logger.debug("Starting check for Bedrock guardrail sensitive-information filters")
    try:
        findings = {
            "check_name": "Guardrail Sensitive Information Filter Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_client = boto3.client(
            "bedrock", config=boto3_config, region_name=region
        )

        try:
            guardrails_response = bedrock_client.list_guardrails(maxResults=100)
            guardrails = guardrails_response.get("guardrails", [])

            if not guardrails:
                findings["details"] = "No Bedrock guardrails found"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-26",
                        finding_name="Guardrail Sensitive Information Filter Check",
                        finding_details="No Bedrock guardrails configured in this region",
                        resolution="Create guardrails with sensitive-information filters (PII entities and/or regex patterns) to detect and redact sensitive data in prompts and model responses",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-sensitive-filters.html",
                        severity="High",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

            guardrails_without_pii = []
            guardrails_with_pii = []

            for guardrail_summary in guardrails:
                guardrail_id = guardrail_summary.get("id")
                guardrail_name = guardrail_summary.get("name", "unknown")

                if not guardrail_id:
                    continue

                guardrail_detail = bedrock_client.get_guardrail(
                    guardrailIdentifier=guardrail_id
                )
                guardrail_config = guardrail_detail.get("guardrail", guardrail_detail)

                # GetGuardrail reports PII protection under
                # sensitiveInformationPolicy.piiEntities and .regexes.
                sensitive_policy = guardrail_config.get(
                    "sensitiveInformationPolicy", {}
                )
                pii_entities = sensitive_policy.get("piiEntities", [])
                regexes = sensitive_policy.get("regexes", [])

                if pii_entities or regexes:
                    guardrails_with_pii.append(guardrail_name)
                else:
                    guardrails_without_pii.append(
                        {"name": guardrail_name, "id": guardrail_id}
                    )

            if guardrails_without_pii:
                findings["status"] = "WARN"
                findings["details"] = (
                    f"Found {len(guardrails_without_pii)} guardrails without sensitive-information filters"
                )

                for gr in guardrails_without_pii:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-26",
                            finding_name="Guardrail Sensitive Information Filter Check",
                            finding_details=f"Guardrail '{gr['name']}' (ID: {gr['id']}) has no sensitive-information filters configured (no PII entities or regex patterns). Prompts and model responses are not screened for sensitive data such as PII.",
                            resolution="Configure sensitive-information filters on the guardrail: add PII entity types (e.g. NAME, EMAIL, SSN, CREDIT_DEBIT_CARD_NUMBER) and/or custom regex patterns, and set the appropriate BLOCK or ANONYMIZE action for input and output.",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-sensitive-filters.html",
                            severity="High",
                            status="Failed",
                            region=region,
                        )
                    )

            if guardrails_with_pii:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-26",
                        finding_name="Guardrail Sensitive Information Filter Check",
                        finding_details=f"{len(guardrails_with_pii)} guardrails have sensitive-information (PII) filters configured",
                        resolution="No action required. Periodically review the PII entity types and regex patterns to ensure coverage matches your data.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-sensitive-filters.html",
                        severity="Low",
                        status="Passed",
                        region=region,
                    )
                )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ACCESS_DENIED_ERROR_CODES:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-26",
                        finding_name="Guardrail Sensitive Information Filter Check",
                        finding_details=describe_api_error(
                            e, "Guardrail sensitive information check", region
                        ),
                        resolution="Grant bedrock:ListGuardrails and bedrock:GetGuardrail permissions",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )
            else:
                raise

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_guardrail_pii_filters: {str(e)}", exc_info=True
        )
        return {
            "check_name": "Guardrail Sensitive Information Filter Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-26",
                    finding_name="Guardrail Sensitive Information Filter Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-sensitive-filters.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_guardrail_contextual_grounding(region: str = "") -> Dict[str, Any]:
    """
    BR-27: Verify guardrails enable contextual grounding checks to detect
    hallucinations and irrelevant responses (extends BR-05).
    """
    logger.debug("Starting check for Bedrock guardrail contextual grounding")
    try:
        findings = {
            "check_name": "Guardrail Contextual Grounding Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_client = boto3.client(
            "bedrock", config=boto3_config, region_name=region
        )

        try:
            guardrails_response = bedrock_client.list_guardrails(maxResults=100)
            guardrails = guardrails_response.get("guardrails", [])

            if not guardrails:
                findings["details"] = "No Bedrock guardrails found"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-27",
                        finding_name="Guardrail Contextual Grounding Check",
                        finding_details="No Bedrock guardrails configured in this region",
                        resolution="Create guardrails with contextual grounding checks to detect hallucinations (ungrounded responses) and irrelevant answers, especially for RAG applications",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-contextual-grounding-check.html",
                        severity="Medium",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

            guardrails_without_grounding = []
            guardrails_with_grounding = []

            for guardrail_summary in guardrails:
                guardrail_id = guardrail_summary.get("id")
                guardrail_name = guardrail_summary.get("name", "unknown")

                if not guardrail_id:
                    continue

                guardrail_detail = bedrock_client.get_guardrail(
                    guardrailIdentifier=guardrail_id
                )
                guardrail_config = guardrail_detail.get("guardrail", guardrail_detail)

                # GetGuardrail reports grounding/relevance checks under
                # contextualGroundingPolicy.filters. A filter is active when it
                # is enabled (the enabled flag defaults to True when omitted).
                grounding_policy = guardrail_config.get("contextualGroundingPolicy", {})
                grounding_filters = grounding_policy.get("filters", [])
                active_filters = [
                    f for f in grounding_filters if f.get("enabled", True)
                ]

                if active_filters:
                    guardrails_with_grounding.append(guardrail_name)
                else:
                    guardrails_without_grounding.append(
                        {"name": guardrail_name, "id": guardrail_id}
                    )

            if guardrails_without_grounding:
                findings["status"] = "WARN"
                findings["details"] = (
                    f"Found {len(guardrails_without_grounding)} guardrails without contextual grounding checks"
                )

                for gr in guardrails_without_grounding:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-27",
                            finding_name="Guardrail Contextual Grounding Check",
                            finding_details=f"Guardrail '{gr['name']}' (ID: {gr['id']}) does not have contextual grounding checks enabled. Without grounding and relevance checks, the guardrail cannot detect hallucinated (ungrounded) or off-topic model responses.",
                            resolution="Enable contextual grounding checks (GROUNDING and RELEVANCE filter types) on the guardrail with appropriate thresholds. This is especially important for RAG applications to ensure responses are grounded in the retrieved source material.",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-contextual-grounding-check.html",
                            severity="Medium",
                            status="Failed",
                            region=region,
                        )
                    )

            if guardrails_with_grounding:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-27",
                        finding_name="Guardrail Contextual Grounding Check",
                        finding_details=f"{len(guardrails_with_grounding)} guardrails have contextual grounding checks enabled",
                        resolution="No action required. Review grounding and relevance thresholds periodically to balance hallucination detection against false positives.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-contextual-grounding-check.html",
                        severity="Low",
                        status="Passed",
                        region=region,
                    )
                )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ACCESS_DENIED_ERROR_CODES:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-27",
                        finding_name="Guardrail Contextual Grounding Check",
                        finding_details=describe_api_error(
                            e, "Guardrail contextual grounding check", region
                        ),
                        resolution="Grant bedrock:ListGuardrails and bedrock:GetGuardrail permissions",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
            else:
                raise

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_guardrail_contextual_grounding: {str(e)}",
            exc_info=True,
        )
        return {
            "check_name": "Guardrail Contextual Grounding Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-27",
                    finding_name="Guardrail Contextual Grounding Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-contextual-grounding-check.html",
                    severity="Medium",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_agent_guardrail_association(region: str = "") -> Dict[str, Any]:
    """
    BR-28: Verify each Bedrock Agent has a guardrail associated so that agent
    interactions are subject to safety controls.
    """
    logger.debug("Starting check for Bedrock Agent guardrail association")
    try:
        findings = {
            "check_name": "Agent Guardrail Association Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_agent_client = boto3.client(
            "bedrock-agent", config=boto3_config, region_name=region
        )

        try:
            # list_agents summaries already include guardrailConfiguration, so no
            # per-agent get_agent call is required.
            agents = []
            paginator = bedrock_agent_client.get_paginator("list_agents")
            for page in paginator.paginate():
                agents.extend(page.get("agentSummaries", []))

            if not agents:
                findings["details"] = "No Bedrock agents found"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-28",
                        finding_name="Agent Guardrail Association Check",
                        finding_details="No Bedrock agents configured in this region",
                        resolution="When creating agents, associate a Bedrock guardrail so agent inputs and responses are filtered for harmful content, PII, and denied topics",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-guardrails.html",
                        severity="High",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

            agents_without_guardrail = []
            agents_with_guardrail = []

            for agent in agents:
                agent_id = agent.get("agentId")
                agent_name = agent.get("agentName", agent_id or "unknown")

                guardrail_config = agent.get("guardrailConfiguration") or {}
                if guardrail_config.get("guardrailIdentifier"):
                    agents_with_guardrail.append(agent_name)
                else:
                    agents_without_guardrail.append(
                        {"name": agent_name, "id": agent_id}
                    )

            if agents_without_guardrail:
                findings["status"] = "WARN"
                findings["details"] = (
                    f"Found {len(agents_without_guardrail)} agents without an associated guardrail"
                )

                for agent in agents_without_guardrail:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-28",
                            finding_name="Agent Guardrail Association Check",
                            finding_details=f"Bedrock agent '{agent['name']}' (ID: {agent['id']}) does not have a guardrail associated. Agent interactions are not subject to content filtering, PII protection, or denied-topic controls.",
                            resolution="Associate a Bedrock guardrail with the agent by setting guardrailConfiguration (guardrailIdentifier and guardrailVersion) on the agent. Prepare the agent after updating so the change takes effect.",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-guardrails.html",
                            severity="High",
                            status="Failed",
                            region=region,
                        )
                    )

            if agents_with_guardrail:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-28",
                        finding_name="Agent Guardrail Association Check",
                        finding_details=f"{len(agents_with_guardrail)} agents have an associated guardrail",
                        resolution="No action required. Continue associating guardrails with new agents.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-guardrails.html",
                        severity="Low",
                        status="Passed",
                        region=region,
                    )
                )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            error_msg = str(e)
            if "UnknownOperation" in error_msg or "Unknown operation" in error_msg:
                findings["details"] = "Bedrock Agents API not available in this region"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-28",
                        finding_name="Agent Guardrail Association Check",
                        finding_details=describe_api_error(
                            e, "Bedrock Agents API", region
                        ),
                        resolution="Bedrock Agents may not be available in all regions",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-guardrails.html",
                        severity="Low",
                        status="N/A",
                        region=region,
                    )
                )
            elif error_code in ACCESS_DENIED_ERROR_CODES:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-28",
                        finding_name="Agent Guardrail Association Check",
                        finding_details=describe_api_error(
                            e, "Agent guardrail association check", region
                        ),
                        resolution="Grant bedrock-agent:ListAgents permission",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )
            else:
                raise

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_agent_guardrail_association: {str(e)}",
            exc_info=True,
        )
        return {
            "check_name": "Agent Guardrail Association Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-28",
                    finding_name="Agent Guardrail Association Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-guardrails.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ],
        }


# Agents with an idle session TTL longer than this (in seconds) are flagged.
# Default Bedrock value is 600s (10 min); 3600s (1 hour) is a generous ceiling.
AGENT_MAX_IDLE_SESSION_TTL_SECONDS = 3600


def check_bedrock_agent_idle_session_ttl(region: str = "") -> Dict[str, Any]:
    """
    BR-29: Verify Bedrock Agents do not use an excessively long idle session TTL,
    which widens the window for session/context reuse abuse.
    """
    logger.debug("Starting check for Bedrock Agent idle session TTL")
    try:
        findings = {
            "check_name": "Agent Idle Session TTL Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_agent_client = boto3.client(
            "bedrock-agent", config=boto3_config, region_name=region
        )

        try:
            agents = []
            paginator = bedrock_agent_client.get_paginator("list_agents")
            for page in paginator.paginate():
                agents.extend(page.get("agentSummaries", []))

            if not agents:
                findings["details"] = "No Bedrock agents found"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-29",
                        finding_name="Agent Idle Session TTL Check",
                        finding_details="No Bedrock agents configured in this region",
                        resolution="When creating agents, set a conservative idleSessionTTLInSeconds to limit how long an idle session remains resumable",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-create.html",
                        severity="Low",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

            agents_long_ttl = []
            agents_ok_ttl = []

            for agent in agents:
                agent_id = agent.get("agentId")
                agent_name = agent.get("agentName", agent_id or "unknown")

                if not agent_id:
                    continue

                # idleSessionTTLInSeconds is only returned by GetAgent, not in the
                # list summary.
                try:
                    agent_detail = bedrock_agent_client.get_agent(agentId=agent_id)
                    agent_config = agent_detail.get("agent", agent_detail)
                    ttl = agent_config.get("idleSessionTTLInSeconds")

                    if ttl is None:
                        continue

                    if ttl > AGENT_MAX_IDLE_SESSION_TTL_SECONDS:
                        agents_long_ttl.append(
                            {"name": agent_name, "id": agent_id, "ttl": ttl}
                        )
                    else:
                        agents_ok_ttl.append(agent_name)

                except ClientError as detail_error:
                    error_code = detail_error.response.get("Error", {}).get("Code", "")
                    if error_code not in ACCESS_DENIED_ERROR_CODES:
                        logger.warning(
                            f"Could not get details for agent {agent_name}: {error_code}"
                        )

            if agents_long_ttl:
                findings["status"] = "WARN"
                findings["details"] = (
                    f"Found {len(agents_long_ttl)} agents with an idle session TTL above {AGENT_MAX_IDLE_SESSION_TTL_SECONDS} seconds"
                )

                for agent in agents_long_ttl:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-29",
                            finding_name="Agent Idle Session TTL Check",
                            finding_details=f"Bedrock agent '{agent['name']}' (ID: {agent['id']}) has an idle session TTL of {agent['ttl']} seconds, which exceeds the recommended maximum of {AGENT_MAX_IDLE_SESSION_TTL_SECONDS} seconds. Long-lived idle sessions widen the window for session and conversation-context reuse.",
                            resolution=f"Reduce idleSessionTTLInSeconds to {AGENT_MAX_IDLE_SESSION_TTL_SECONDS} seconds or less, based on your application's session requirements, so idle sessions expire promptly.",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-create.html",
                            severity="Low",
                            status="Failed",
                            region=region,
                        )
                    )

            if agents_ok_ttl:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-29",
                        finding_name="Agent Idle Session TTL Check",
                        finding_details=f"{len(agents_ok_ttl)} agents use an idle session TTL within the recommended bound",
                        resolution="No action required.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-create.html",
                        severity="Low",
                        status="Passed",
                        region=region,
                    )
                )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            error_msg = str(e)
            if "UnknownOperation" in error_msg or "Unknown operation" in error_msg:
                findings["details"] = "Bedrock Agents API not available in this region"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-29",
                        finding_name="Agent Idle Session TTL Check",
                        finding_details=describe_api_error(
                            e, "Bedrock Agents API", region
                        ),
                        resolution="Bedrock Agents may not be available in all regions",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-create.html",
                        severity="Low",
                        status="N/A",
                        region=region,
                    )
                )
            elif error_code in ACCESS_DENIED_ERROR_CODES:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-29",
                        finding_name="Agent Idle Session TTL Check",
                        finding_details=describe_api_error(
                            e, "Agent idle session TTL check", region
                        ),
                        resolution="Grant bedrock-agent:ListAgents and bedrock-agent:GetAgent permissions",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples.html",
                        severity="Low",
                        status="Failed",
                        region=region,
                    )
                )
            else:
                raise

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_agent_idle_session_ttl: {str(e)}", exc_info=True
        )
        return {
            "check_name": "Agent Idle Session TTL Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-29",
                    finding_name="Agent Idle Session TTL Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-create.html",
                    severity="Low",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_imported_model_kms_encryption(region: str = "") -> Dict[str, Any]:
    """
    BR-30: Verify imported custom models use customer-managed KMS keys
    (complements BR-11/BR-17, which cover fine-tuned custom models).
    """
    logger.debug("Starting check for imported model KMS encryption")
    try:
        findings = {
            "check_name": "Imported Model Customer-Managed KMS Encryption Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_client = boto3.client(
            "bedrock", config=boto3_config, region_name=region
        )

        try:
            imported_models = []
            paginator = bedrock_client.get_paginator("list_imported_models")
            for page in paginator.paginate():
                imported_models.extend(page.get("modelSummaries", []))

            if not imported_models:
                findings["details"] = "No imported models found"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-30",
                        finding_name="Imported Model Customer-Managed KMS Encryption Check",
                        finding_details="No imported custom Bedrock models found in this region",
                        resolution="When importing models, specify a customer-managed KMS key for encryption to maintain control over encryption keys",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-customization-import-model.html",
                        severity="High",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

            models_with_aws_keys = []
            models_with_customer_keys = []

            for model in imported_models:
                model_arn = model.get("modelArn")
                model_name = model.get("modelName", "unknown")

                try:
                    model_detail = bedrock_client.get_imported_model(
                        modelIdentifier=model_arn
                    )
                    # GetImportedModel reports the encryption key as modelKmsKeyArn.
                    kms_key_arn = model_detail.get("modelKmsKeyArn")

                    if kms_key_arn and kms_key_arn.startswith("arn:aws:kms"):
                        models_with_customer_keys.append(model_name)
                    else:
                        models_with_aws_keys.append(
                            {"name": model_name, "arn": model_arn}
                        )

                except ClientError as detail_error:
                    error_code = detail_error.response.get("Error", {}).get("Code", "")
                    if error_code not in ACCESS_DENIED_ERROR_CODES:
                        logger.warning(
                            f"Could not get details for imported model {model_name}: {error_code}"
                        )

            if models_with_aws_keys:
                findings["status"] = "WARN"
                findings["details"] = (
                    f"Found {len(models_with_aws_keys)} imported models without a customer-managed KMS key"
                )

                for model_info in models_with_aws_keys:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-30",
                            finding_name="Imported Model Customer-Managed KMS Encryption Check",
                            finding_details=f"Imported model '{model_info['name']}' is not encrypted with a customer-managed KMS key. This limits your control over key rotation, access policies, and audit trail.",
                            resolution="Re-import the model specifying a customer-managed KMS key (modelKmsKeyArn). Ensure the KMS key policy grants Amazon Bedrock service access.",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-customization-import-model.html",
                            severity="High",
                            status="Failed",
                            region=region,
                        )
                    )

            if models_with_customer_keys:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-30",
                        finding_name="Imported Model Customer-Managed KMS Encryption Check",
                        finding_details=f"{len(models_with_customer_keys)} imported models are using customer-managed KMS keys for encryption",
                        resolution="No action required. Continue using customer-managed keys for imported models.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-customization-import-model.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            error_msg = str(e)
            if "UnknownOperation" in error_msg or "Unknown operation" in error_msg:
                findings["details"] = "Imported models API not available in this region"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-30",
                        finding_name="Imported Model Customer-Managed KMS Encryption Check",
                        finding_details=describe_api_error(
                            e, "Imported models API", region
                        ),
                        resolution="Model import may not be available in all regions",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-customization-import-model.html",
                        severity="Low",
                        status="N/A",
                        region=region,
                    )
                )
            elif is_account_not_authorized(e):
                findings["details"] = (
                    "Custom model import not enabled for this account/region"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-30",
                        finding_name="Imported Model Customer-Managed KMS Encryption Check",
                        finding_details=describe_api_error(
                            e, "Imported model encryption check", region
                        ),
                        resolution="Amazon Bedrock Custom Model Import is not enabled or available for this account in this region. No IAM change is required; the check applies only once model import is in use.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-customization-import-model.html",
                        severity="Low",
                        status="N/A",
                        region=region,
                    )
                )
            elif error_code in ACCESS_DENIED_ERROR_CODES:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-30",
                        finding_name="Imported Model Customer-Managed KMS Encryption Check",
                        finding_details=describe_api_error(
                            e, "Imported model encryption check", region
                        ),
                        resolution="Grant bedrock:ListImportedModels and bedrock:GetImportedModel permissions",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )
            else:
                raise

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_imported_model_kms_encryption: {str(e)}",
            exc_info=True,
        )
        return {
            "check_name": "Imported Model Customer-Managed KMS Encryption Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-30",
                    finding_name="Imported Model Customer-Managed KMS Encryption Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-customization-import-model.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_batch_inference_output_encryption(
    region: str = "",
) -> Dict[str, Any]:
    """
    BR-31: Verify batch inference (model invocation) jobs encrypt their S3 output
    with a customer-managed KMS key.
    """
    logger.debug("Starting check for batch inference output encryption")
    try:
        findings = {
            "check_name": "Batch Inference Output Encryption Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_client = boto3.client(
            "bedrock", config=boto3_config, region_name=region
        )

        try:
            # list_model_invocation_jobs summaries already include
            # outputDataConfig.s3OutputDataConfig.s3EncryptionKeyId, so no
            # per-job get_model_invocation_job call is required.
            jobs = []
            paginator = bedrock_client.get_paginator("list_model_invocation_jobs")
            for page in paginator.paginate():
                jobs.extend(page.get("invocationJobSummaries", []))

            if not jobs:
                findings["details"] = "No batch inference jobs found"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-31",
                        finding_name="Batch Inference Output Encryption Check",
                        finding_details="No Bedrock batch inference (model invocation) jobs found in this region",
                        resolution="When creating batch inference jobs, set outputDataConfig.s3OutputDataConfig.s3EncryptionKeyId to a customer-managed KMS key to encrypt the job output",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/batch-inference.html",
                        severity="Medium",
                        status="N/A",
                        region=region,
                    )
                )
                return findings

            jobs_without_cmk = []
            jobs_with_cmk = []

            for job in jobs:
                job_name = job.get("jobName", "unknown")
                output_config = job.get("outputDataConfig", {})
                s3_output = output_config.get("s3OutputDataConfig", {})
                encryption_key = s3_output.get("s3EncryptionKeyId")

                if encryption_key:
                    jobs_with_cmk.append(job_name)
                else:
                    jobs_without_cmk.append(job_name)

            if jobs_without_cmk:
                findings["status"] = "WARN"
                findings["details"] = (
                    f"Found {len(jobs_without_cmk)} batch inference jobs without a customer-managed KMS output key"
                )

                for job_name in jobs_without_cmk:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-31",
                            finding_name="Batch Inference Output Encryption Check",
                            finding_details=f"Batch inference job '{job_name}' does not specify a customer-managed KMS key for its S3 output. Job output (model responses) may be encrypted only with the bucket default or an AWS-managed key.",
                            resolution="When creating batch inference jobs, set outputDataConfig.s3OutputDataConfig.s3EncryptionKeyId to a customer-managed KMS key, and ensure the destination S3 bucket enforces that key.",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/batch-inference.html",
                            severity="Medium",
                            status="Failed",
                            region=region,
                        )
                    )

            if jobs_with_cmk:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-31",
                        finding_name="Batch Inference Output Encryption Check",
                        finding_details=f"{len(jobs_with_cmk)} batch inference jobs specify a customer-managed KMS key for their S3 output",
                        resolution="No action required. Continue specifying a customer-managed KMS key for batch inference output.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/batch-inference.html",
                        severity="Low",
                        status="Passed",
                        region=region,
                    )
                )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            error_msg = str(e)
            if "UnknownOperation" in error_msg or "Unknown operation" in error_msg:
                findings["details"] = "Batch inference API not available in this region"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-31",
                        finding_name="Batch Inference Output Encryption Check",
                        finding_details=describe_api_error(
                            e, "Batch inference API", region
                        ),
                        resolution="Batch inference may not be available in all regions",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/batch-inference.html",
                        severity="Low",
                        status="N/A",
                        region=region,
                    )
                )
            elif is_account_not_authorized(e):
                findings["details"] = (
                    "Batch inference not enabled for this account/region"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-31",
                        finding_name="Batch Inference Output Encryption Check",
                        finding_details=describe_api_error(
                            e, "Batch inference output encryption check", region
                        ),
                        resolution="Amazon Bedrock batch inference is not enabled or available for this account in this region. No IAM change is required; the check applies only once batch inference is in use.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/batch-inference.html",
                        severity="Low",
                        status="N/A",
                        region=region,
                    )
                )
            elif error_code in ACCESS_DENIED_ERROR_CODES:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-31",
                        finding_name="Batch Inference Output Encryption Check",
                        finding_details=describe_api_error(
                            e, "Batch inference output encryption check", region
                        ),
                        resolution="Grant bedrock:ListModelInvocationJobs permission",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
            else:
                raise

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_batch_inference_output_encryption: {str(e)}",
            exc_info=True,
        )
        return {
            "check_name": "Batch Inference Output Encryption Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-31",
                    finding_name="Batch Inference Output Encryption Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/batch-inference.html",
                    severity="Medium",
                    status="Failed",
                    region=region,
                )
            ],
        }


def check_bedrock_cloudwatch_alarms(region: str = "") -> Dict[str, Any]:
    """
    BR-32: Verify CloudWatch alarms exist on Amazon Bedrock runtime metrics
    (AWS/Bedrock namespace) to detect abuse, throttling, and cost spikes.
    """
    logger.debug("Starting check for CloudWatch alarms on Bedrock metrics")
    try:
        findings = {
            "check_name": "Bedrock CloudWatch Alarm Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        # Only assess this when the region actually has Bedrock resources, to
        # avoid recommending alarms in regions where Bedrock is unused.
        bedrock_footprint_found = detect_bedrock_regional_footprint(region=region)
        if bedrock_footprint_found is False:
            findings["details"] = "No regional Bedrock resources found"
            findings["csv_data"].append(
                create_finding(
                    check_id="BR-32",
                    finding_name="Bedrock CloudWatch Alarm Check",
                    finding_details="No regional Bedrock resources found to monitor with CloudWatch alarms",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-runtime-metrics.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )
            return findings

        cloudwatch_client = boto3.client(
            "cloudwatch", config=boto3_config, region_name=region
        )

        try:
            bedrock_alarms = []
            paginator = cloudwatch_client.get_paginator("describe_alarms")
            for page in paginator.paginate(AlarmTypes=["MetricAlarm"]):
                for alarm in page.get("MetricAlarms", []):
                    # A metric alarm targets Bedrock either directly (Namespace)
                    # or via a metric-math expression referencing AWS/Bedrock.
                    if alarm.get("Namespace") == "AWS/Bedrock":
                        bedrock_alarms.append(alarm.get("AlarmName"))
                        continue
                    for metric in alarm.get("Metrics", []):
                        metric_stat = metric.get("MetricStat", {})
                        namespace = metric_stat.get("Metric", {}).get("Namespace", "")
                        if namespace == "AWS/Bedrock":
                            bedrock_alarms.append(alarm.get("AlarmName"))
                            break

            if bedrock_alarms:
                findings["details"] = (
                    f"Found {len(bedrock_alarms)} CloudWatch alarms on Bedrock metrics"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-32",
                        finding_name="Bedrock CloudWatch Alarm Check",
                        finding_details=f"Found {len(bedrock_alarms)} CloudWatch alarm(s) monitoring Amazon Bedrock runtime metrics (AWS/Bedrock namespace).",
                        resolution="No action required. Review alarm thresholds and notification targets periodically to ensure they still detect abuse, throttling, and cost anomalies.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-runtime-metrics.html",
                        severity="Low",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                findings["status"] = "WARN"
                findings["details"] = "No CloudWatch alarms found on Bedrock metrics"
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-32",
                        finding_name="Bedrock CloudWatch Alarm Check",
                        finding_details="No CloudWatch alarms are configured on Amazon Bedrock runtime metrics (AWS/Bedrock namespace). Without alarms, abuse, denial-of-wallet, sustained throttling, and content-filter spikes can go undetected.",
                        resolution="Create CloudWatch alarms on AWS/Bedrock runtime metrics such as Invocations, InvocationThrottles, InputTokenCount, OutputTokenCount, and ContentFilteredCount, and route them to an Amazon SNS topic for notification.",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-runtime-metrics.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ACCESS_DENIED_ERROR_CODES:
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-32",
                        finding_name="Bedrock CloudWatch Alarm Check",
                        finding_details=describe_api_error(
                            e, "CloudWatch alarm check", region
                        ),
                        resolution="Grant cloudwatch:DescribeAlarms permission to the assessment role",
                        reference="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/iam-access-control-overview-cw.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
            else:
                raise

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_bedrock_cloudwatch_alarms: {str(e)}", exc_info=True
        )
        return {
            "check_name": "Bedrock CloudWatch Alarm Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [
                create_finding(
                    check_id="BR-32",
                    finding_name="Bedrock CloudWatch Alarm Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-runtime-metrics.html",
                    severity="Medium",
                    status="Failed",
                    region=region,
                )
            ],
        }


def generate_csv_report(findings: List[Dict[str, Any]]) -> str:
    """
    Generate CSV report from all security check findings
    """
    logger.debug("Generating CSV report")
    csv_buffer = StringIO()
    fieldnames = [
        "Check_ID",
        "Finding",
        "Finding_Details",
        "Resolution",
        "Reference",
        "Severity",
        "Status",
        "Region",
    ]
    writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)

    writer.writeheader()
    for finding in findings:
        if finding["csv_data"]:
            for row in finding["csv_data"]:
                writer.writerow(row)

    return csv_buffer.getvalue()


def get_current_utc_date():
    return datetime.now(timezone.utc).strftime("%Y/%m/%d")


def write_to_s3(
    execution_id, csv_content: str, bucket_name: str, region: str = ""
) -> str:
    """
    Write CSV report to S3 bucket
    """
    logger.debug(f"Writing CSV report to S3 bucket: {bucket_name}")
    try:
        s3_client = boto3.client("s3", config=boto3_config)
        if region:
            file_name = f"bedrock_security_report_{execution_id}_{region}.csv"
        else:
            file_name = f"bedrock_security_report_{execution_id}.csv"

        s3_client.put_object(
            Bucket=bucket_name, Key=file_name, Body=csv_content, ContentType="text/csv"
        )

        s3_url = f"https://{bucket_name}.s3.amazonaws.com/{file_name}"
        logger.info(f"Successfully wrote report to S3: {s3_url}")
        return s3_url
    except Exception as e:
        logger.error(f"Error writing to S3: {str(e)}", exc_info=True)
        raise


def lambda_handler(event, context):
    """
    Main Lambda handler
    """
    logger.info("Starting Bedrock security assessment")
    all_findings = []

    try:
        # Extract target region from Step Functions Map state
        region = event.get("Region", os.environ.get("AWS_REGION", "us-east-1"))
        # IAM is global: only the primary region (Map index 0) runs IAM-only checks.
        is_primary_region = int(event.get("RegionIndex", 0)) == 0
        logger.info(f"Scanning region: {region} (primary={is_primary_region})")

        execution_id = event["Execution"]["Name"]

        # Initialize permission cache (shared/global IAM data)
        logger.info("Initializing IAM permission cache")
        permission_cache = get_permissions_cache(execution_id)

        if not permission_cache:
            logger.error(
                "Permission cache not found - IAM permission caching may have failed"
            )
            permission_cache = {"role_permissions": {}, "user_permissions": {}}

        # Run global IAM-only checks once (on the primary region) so the same role
        # violations are not reported once per scanned region. These run before the
        # regional availability gate so they are still emitted even if Bedrock is
        # not available in the primary region.
        if is_primary_region:
            logger.info("Running global AmazonBedrockFullAccess check (BR-01)")
            all_findings.append(
                check_bedrock_full_access_roles(
                    permission_cache, region=GLOBAL_REGION_LABEL
                )
            )

            logger.info("Running global marketplace subscription access check (BR-03)")
            all_findings.append(
                check_marketplace_subscription_access(
                    permission_cache, region=GLOBAL_REGION_LABEL
                )
            )

            # logger.info("Running global stale Bedrock access check (BR-14)")
            # all_findings.append(
            #     check_stale_bedrock_access(permission_cache, region=GLOBAL_REGION_LABEL)
            # )

        # Verify Bedrock is available in this region. A ValidationException here
        # (logging simply not configured) still means the service is reachable,
        # so only an endpoint connection failure or a region-not-enabled error
        # should short-circuit the assessment.
        bedrock_unavailable = False
        unavailable_detail = ""
        try:
            test_client = boto3.client(
                "bedrock", config=boto3_config, region_name=region
            )
            test_client.get_model_invocation_logging_configuration()
        except EndpointConnectionError:
            bedrock_unavailable = True
            unavailable_detail = f"Amazon Bedrock is not available in region {region}. No checks performed."
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in REGION_UNAVAILABLE_ERROR_CODES:
                bedrock_unavailable = True
                unavailable_detail = f"Amazon Bedrock is not available or not enabled in region {region} ({error_code}). No checks performed."
            else:
                # Service is reachable (e.g. ValidationException, AccessDenied) —
                # proceed; individual checks handle their own errors.
                logger.info(
                    f"Bedrock availability probe returned {error_code}; proceeding with checks"
                )

        if bedrock_unavailable:
            logger.info(f"Bedrock service not available in region {region}, skipping")
            all_findings.append(
                {
                    "check_name": "Bedrock Service Availability",
                    "status": "N/A",
                    "details": f"Bedrock is not available in region {region}",
                    "csv_data": [
                        create_finding(
                            check_id="BR-00",
                            finding_name="Bedrock Service Availability",
                            finding_details=unavailable_detail,
                            resolution="No action required. Bedrock is not deployed in this region.",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/bedrock-regions.html",
                            severity="Informational",
                            status="N/A",
                            region=region,
                        )
                    ],
                }
            )
            csv_content = generate_csv_report(all_findings)
            bucket_name = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
            s3_url = write_to_s3(execution_id, csv_content, bucket_name, region=region)
            return {
                "statusCode": 200,
                "body": {
                    "message": f"Bedrock not available in {region}",
                    "report_url": s3_url,
                },
            }

        # Run regional checks using the cached permissions
        logger.info("Running Bedrock access and VPC endpoints check")
        bedrock_access_vpc_findings = check_bedrock_access_and_vpc_endpoints(
            permission_cache, region=region
        )
        all_findings.append(bedrock_access_vpc_findings)

        logger.info("Running Bedrock logging findings check")
        bedrock_logging_findings = check_bedrock_logging_configuration(region=region)
        all_findings.append(bedrock_logging_findings)

        logger.info("Running Bedrock Guardrails check")
        bedrock_guardrails_findings = check_bedrock_guardrails(region=region)
        all_findings.append(bedrock_guardrails_findings)

        logger.info("Running Bedrock CloudTrail logging check")
        bedrock_cloudtrail_findings = check_bedrock_cloudtrail_logging(region=region)
        all_findings.append(bedrock_cloudtrail_findings)

        logger.info("Running Bedrock Prompt Management check")
        bedrock_prompt_management_findings = check_bedrock_prompt_management(
            region=region
        )
        all_findings.append(bedrock_prompt_management_findings)

        logger.info("Running Bedrock agent IAM roles check")
        bedrock_agent_roles_findings = check_bedrock_agent_roles(
            permission_cache, region=region
        )
        all_findings.append(bedrock_agent_roles_findings)

        logger.info("Running Bedrock Knowledge Base encryption check")
        kb_encryption_findings = check_bedrock_knowledge_base_encryption(region=region)
        all_findings.append(kb_encryption_findings)

        logger.info("Running Bedrock Guardrail IAM enforcement check")
        guardrail_iam_findings = check_bedrock_guardrail_iam_enforcement(
            permission_cache, region=region
        )
        all_findings.append(guardrail_iam_findings)

        logger.info("Running Bedrock custom model encryption check")
        custom_model_encryption_findings = check_bedrock_custom_model_encryption(
            region=region
        )
        all_findings.append(custom_model_encryption_findings)

        logger.info("Running Bedrock invocation log encryption check")
        invocation_log_encryption_findings = check_bedrock_invocation_log_encryption(
            region=region
        )
        all_findings.append(invocation_log_encryption_findings)

        logger.info("Running Bedrock Flows guardrails check")
        flows_guardrails_findings = check_bedrock_flows_guardrails(region=region)
        all_findings.append(flows_guardrails_findings)

        # New security checks (BR-15+)
        # BR-15 is a global check (runs once on primary region)
        if is_primary_region:
            logger.info("Running cross-account guardrails enforcement check (BR-15)")
            cross_account_guardrails_findings = check_bedrock_cross_account_guardrails(
                region=GLOBAL_REGION_LABEL
            )
            all_findings.append(cross_account_guardrails_findings)

        # Regional checks (BR-16 through BR-25)
        logger.info("Running guardrail tier validation check (BR-16)")
        guardrail_tier_findings = check_bedrock_guardrail_tier(region=region)
        all_findings.append(guardrail_tier_findings)

        logger.info(
            "Running custom model customer-managed KMS encryption check (BR-17)"
        )
        custom_model_kms_findings = check_bedrock_custom_model_kms_encryption(
            region=region
        )
        all_findings.append(custom_model_kms_findings)

        logger.info("Running model evaluation implementation check (BR-18)")
        model_eval_findings = check_bedrock_model_evaluations(region=region)
        all_findings.append(model_eval_findings)

        logger.info("Running prompt flow validation check (BR-19)")
        prompt_flow_findings = check_bedrock_prompt_flow_validation(region=region)
        all_findings.append(prompt_flow_findings)

        logger.info(
            "Running knowledge base customer-managed KMS encryption check (BR-20)"
        )
        kb_kms_findings = check_bedrock_knowledge_base_kms_encryption(region=region)
        all_findings.append(kb_kms_findings)

        logger.info("Running agent action group IAM least privilege check (BR-21)")
        agent_action_group_iam_findings = check_bedrock_agent_action_group_iam(
            region=region, permission_cache=permission_cache
        )
        all_findings.append(agent_action_group_iam_findings)

        logger.info("Running service quotas throttling limits check (BR-22)")
        service_quotas_findings = check_bedrock_service_quotas_throttling(region=region)
        all_findings.append(service_quotas_findings)

        logger.info("Running guardrail content filter coverage check (BR-23)")
        content_filter_findings = check_bedrock_guardrail_content_filters(region=region)
        all_findings.append(content_filter_findings)

        logger.info("Running automated reasoning policy implementation check (BR-24)")
        automated_reasoning_findings = check_bedrock_automated_reasoning_policy(
            region=region
        )
        all_findings.append(automated_reasoning_findings)

        logger.info("Running RAG evaluation jobs check (BR-25)")
        rag_eval_findings = check_bedrock_rag_evaluation_jobs(region=region)
        all_findings.append(rag_eval_findings)

        logger.info("Running guardrail sensitive-information filter check (BR-26)")
        guardrail_pii_findings = check_bedrock_guardrail_pii_filters(region=region)
        all_findings.append(guardrail_pii_findings)

        logger.info("Running guardrail contextual grounding check (BR-27)")
        guardrail_grounding_findings = check_bedrock_guardrail_contextual_grounding(
            region=region
        )
        all_findings.append(guardrail_grounding_findings)

        logger.info("Running agent guardrail association check (BR-28)")
        agent_guardrail_findings = check_bedrock_agent_guardrail_association(
            region=region
        )
        all_findings.append(agent_guardrail_findings)

        logger.info("Running agent idle session TTL check (BR-29)")
        agent_ttl_findings = check_bedrock_agent_idle_session_ttl(region=region)
        all_findings.append(agent_ttl_findings)

        logger.info("Running imported model KMS encryption check (BR-30)")
        imported_model_findings = check_bedrock_imported_model_kms_encryption(
            region=region
        )
        all_findings.append(imported_model_findings)

        logger.info("Running batch inference output encryption check (BR-31)")
        batch_inference_findings = check_bedrock_batch_inference_output_encryption(
            region=region
        )
        all_findings.append(batch_inference_findings)

        logger.info("Running CloudWatch alarm check (BR-32)")
        cloudwatch_alarm_findings = check_bedrock_cloudwatch_alarms(region=region)
        all_findings.append(cloudwatch_alarm_findings)

        # Generate and upload report
        logger.info("Generating CSV report")
        csv_content = generate_csv_report(all_findings)

        bucket_name = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
        if not bucket_name:
            raise ValueError(
                "AIML_ASSESSMENT_BUCKET_NAME environment variable is not set"
            )

        logger.info("Writing report to S3")
        s3_url = write_to_s3(execution_id, csv_content, bucket_name, region=region)

        return {
            "statusCode": 200,
            "body": {
                "message": "Security checks completed successfully",
                "findings": all_findings,
                "report_url": s3_url,
            },
        }

    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}", exc_info=True)
        return {"statusCode": 500, "body": f"Error during security checks: {str(e)}"}
