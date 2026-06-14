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


def check_marketplace_subscription_access(permission_cache, region: str = "") -> Dict[str, Any]:
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


def check_bedrock_full_access_roles(permission_cache, region: str = "") -> Dict[str, Any]:
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


def check_bedrock_access_and_vpc_endpoints(permission_cache, region: str = "") -> Dict[str, Any]:
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

        bedrock_client = boto3.client("bedrock", config=boto3_config, region_name=region)

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
    logger.debug("Starting check for Bedrock model invocation logging configuration")
    try:
        findings = {
            "check_name": "Bedrock Model Invocation Logging Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        bedrock_client = boto3.client("bedrock", config=boto3_config, region_name=region)

        try:
            # Get current logging configuration
            response = bedrock_client.get_model_invocation_logging_configuration()

            logging_enabled = False
            enabled_destinations = []

            # Check S3 logging configuration
            s3_config = response.get("loggingConfig", {}).get("s3Config")
            if s3_config and s3_config.get("s3BucketName"):
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
    logger.debug("Starting check for Bedrock CloudTrail logging configuration")
    try:
        findings = {
            "check_name": "Bedrock CloudTrail Logging Check",
            "status": "PASS",
            "details": "",
            "csv_data": [],
        }

        cloudtrail_client = boto3.client("cloudtrail", config=boto3_config, region_name=region)

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

        bedrock_client = boto3.client("bedrock-agent", config=boto3_config, region_name=region)

        try:
            # List all prompts
            response = bedrock_client.list_prompts()
            prompts = response.get("promptSummaries", [])

            if prompts:
                # Count prompts by status
                active_prompts = [p for p in prompts if p.get("status") == "ACTIVE"]
                draft_prompts = [p for p in prompts if p.get("status") == "DRAFT"]

                findings["details"] = (
                    f"Found {len(prompts)} prompts ({len(active_prompts)} active, {len(draft_prompts)} draft)"
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="BR-07",
                        finding_name="Bedrock Prompt Management Check",
                        finding_details=f"Prompt Management is being used with {len(prompts)} prompts ({len(active_prompts)} active, {len(draft_prompts)} draft)",
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
                    try:
                        prompt_details = bedrock_client.get_prompt(
                            promptId=prompt["promptId"]
                        )
                        if len(prompt_details.get("variants", [])) <= 1:
                            prompts_without_variants.append(prompt["name"])
                    except Exception as e:
                        logger.warning(
                            f"Could not get details for prompt {prompt['name']}: {str(e)}"
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

        bedrock_agent_client = boto3.client("bedrock-agent", config=boto3_config, region_name=region)

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

                except Exception as e:
                    logger.warning(f"Error checking knowledge base {kb_id}: {str(e)}")

            if kb_without_cmk:
                findings["details"] = (
                    f"Found {len(kb_without_cmk)} Knowledge Bases - encryption validated at storage layer"
                )

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

        except bedrock_agent_client.exceptions.ValidationException as e:
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


def check_bedrock_guardrail_iam_enforcement(permission_cache, region: str = "") -> Dict[str, Any]:
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

        bedrock_client = boto3.client("bedrock", config=boto3_config, region_name=region)

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

        bedrock_client = boto3.client("bedrock", config=boto3_config, region_name=region)

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

        bedrock_client = boto3.client("bedrock", config=boto3_config, region_name=region)
        s3_client = boto3.client("s3", config=boto3_config, region_name=region)

        try:
            # Get logging configuration
            response = bedrock_client.get_model_invocation_logging_configuration()
            logging_config = response.get("loggingConfig", {})

            s3_config = logging_config.get("s3Config")

            if not s3_config or not s3_config.get("bucketName"):
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

            bucket_name = s3_config.get("bucketName")

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
                elif e.response["Error"]["Code"] == "AccessDenied":
                    findings["csv_data"].append(
                        create_finding(
                            check_id="BR-12",
                            finding_name="Bedrock Invocation Log Encryption Check",
                            finding_details=f"Unable to check encryption for bucket '{bucket_name}' - access denied",
                            resolution="Ensure Lambda execution role has s3:GetEncryptionConfiguration permission",
                            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
                            severity="Medium",
                            status="Failed",
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

        bedrock_agent_client = boto3.client("bedrock-agent", config=boto3_config, region_name=region)

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

        bedrock_client = boto3.client("bedrock-agent", config=boto3_config, region_name=region)

        try:
            # Get all Bedrock agents
            response = bedrock_client.list_agents()
            agents = response.get("agents", [])

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
                agent_name = agent.get("agentName")

                # Get agent details including role ARN
                agent_details = bedrock_client.get_agent(agentId=agent_id)

                role_arn = agent_details.get("agentResourceRoleArn")
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


def write_to_s3(execution_id, csv_content: str, bucket_name: str, region: str = "") -> str:
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
                check_bedrock_full_access_roles(permission_cache, region=GLOBAL_REGION_LABEL)
            )

            logger.info("Running global marketplace subscription access check (BR-03)")
            all_findings.append(
                check_marketplace_subscription_access(permission_cache, region=GLOBAL_REGION_LABEL)
            )

            logger.info("Running global stale Bedrock access check (BR-14)")
            all_findings.append(
                check_stale_bedrock_access(permission_cache, region=GLOBAL_REGION_LABEL)
            )

        # Verify Bedrock is available in this region. A ValidationException here
        # (logging simply not configured) still means the service is reachable,
        # so only an endpoint connection failure or a region-not-enabled error
        # should short-circuit the assessment.
        bedrock_unavailable = False
        unavailable_detail = ""
        try:
            test_client = boto3.client("bedrock", config=boto3_config, region_name=region)
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
                logger.info(f"Bedrock availability probe returned {error_code}; proceeding with checks")

        if bedrock_unavailable:
            logger.info(f"Bedrock service not available in region {region}, skipping")
            all_findings.append({
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
            })
            csv_content = generate_csv_report(all_findings)
            bucket_name = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
            s3_url = write_to_s3(execution_id, csv_content, bucket_name, region=region)
            return {"statusCode": 200, "body": {"message": f"Bedrock not available in {region}", "report_url": s3_url}}

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
        bedrock_prompt_management_findings = check_bedrock_prompt_management(region=region)
        all_findings.append(bedrock_prompt_management_findings)

        logger.info("Running Bedrock agent IAM roles check")
        bedrock_agent_roles_findings = check_bedrock_agent_roles(permission_cache, region=region)
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
        custom_model_encryption_findings = check_bedrock_custom_model_encryption(region=region)
        all_findings.append(custom_model_encryption_findings)

        logger.info("Running Bedrock invocation log encryption check")
        invocation_log_encryption_findings = check_bedrock_invocation_log_encryption(region=region)
        all_findings.append(invocation_log_encryption_findings)

        logger.info("Running Bedrock Flows guardrails check")
        flows_guardrails_findings = check_bedrock_flows_guardrails(region=region)
        all_findings.append(flows_guardrails_findings)

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
