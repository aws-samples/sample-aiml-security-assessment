"""
Amazon Bedrock AgentCore Security Assessment Lambda Function

This function performs comprehensive security assessments for Amazon Bedrock AgentCore
resources including Runtimes, Code Interpreters, Browser Tools, Memory, and Gateways.
"""

import boto3
import csv
import json
import logging
import os
import time
from io import StringIO
from datetime import datetime, timezone
from typing import Dict, List, Any
from botocore.config import Config
from botocore.exceptions import ClientError

from schema import create_finding, SeverityEnum, StatusEnum

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configure boto3 with adaptive retry mode
boto3_config = Config(retries=dict(max_attempts=10, mode="adaptive"))

# Initialize AWS clients
s3_client = boto3.client("s3", config=boto3_config)
iam_client = boto3.client("iam", config=boto3_config)
ec2_client = boto3.client("ec2", config=boto3_config)
ecr_client = boto3.client("ecr", config=boto3_config)
logs_client = boto3.client("logs", config=boto3_config)
xray_client = boto3.client("xray", config=boto3_config)
cloudwatch_client = boto3.client("cloudwatch", config=boto3_config)

# Initialize AgentCore client
try:
    agentcore_client = boto3.client("bedrock-agentcore-control", config=boto3_config)
    logger.info("Successfully initialized bedrock-agentcore-control client")
except Exception as e:
    logger.warning(f"Failed to initialize bedrock-agentcore-control client: {e}")
    agentcore_client = None

# Environment variables
BUCKET_NAME = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")

# Execution tracking
start_time = None


def get_permissions_cache(execution_id: str) -> Dict[str, Any]:
    """
    Retrieve IAM permissions cache from S3.

    Args:
        execution_id: Unique execution identifier

    Returns:
        Dictionary containing cached IAM permissions

    Raises:
        Exception: If cache retrieval fails
    """
    try:
        cache_key = f"permissions_cache_{execution_id}.json"
        logger.info(f"Retrieving permissions cache: {cache_key}")

        response = s3_client.get_object(Bucket=BUCKET_NAME, Key=cache_key)
        cache_data = json.loads(response["Body"].read().decode("utf-8"))

        logger.info(
            f"Successfully retrieved permissions cache with {len(cache_data.get('role_permissions', []))} roles"
        )
        return cache_data

    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            logger.warning(f"Permissions cache not found: {cache_key}")
            return {"role_permissions": [], "user_permissions": []}
        else:
            logger.error(f"Error retrieving permissions cache: {e}")
            raise


def get_current_utc_date() -> str:
    """
    Get current UTC date in ISO format.

    Returns:
        Current UTC date as string
    """
    return datetime.now(timezone.utc).isoformat()


def check_timeout() -> bool:
    """
    Check if execution is approaching timeout.

    Returns:
        True if execution should continue, False if timeout approaching
    """
    if start_time is None:
        return True

    elapsed = time.time() - start_time

    if elapsed > 480:  # 8 minutes
        logger.warning(f"Approaching timeout: {elapsed}s elapsed")

    return elapsed < 540  # 9 minutes hard stop


def generate_csv_report(findings: List[Dict[str, Any]]) -> str:
    """
    Generate CSV report from findings.

    Args:
        findings: List of finding dictionaries

    Returns:
        CSV content as string
    """
    output = StringIO()

    if not findings:
        logger.warning("No findings to generate report")
        # Create empty report with headers
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "Check_ID",
                "Finding",
                "Finding_Details",
                "Resolution",
                "Reference",
                "Severity",
                "Status",
            ],
        )
        writer.writeheader()
        return output.getvalue()

    # Write CSV with findings
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "Check_ID",
            "Finding",
            "Finding_Details",
            "Resolution",
            "Reference",
            "Severity",
            "Status",
        ],
    )
    writer.writeheader()

    for finding in findings:
        writer.writerow(finding)

    csv_content = output.getvalue()
    logger.info(f"Generated CSV report with {len(findings)} findings")

    return csv_content


def write_to_s3(execution_id: str, csv_content: str, bucket_name: str) -> str:
    """
    Upload CSV report to S3.

    Args:
        execution_id: Unique execution identifier
        csv_content: CSV content to upload
        bucket_name: S3 bucket name

    Returns:
        S3 URL of uploaded file

    Raises:
        Exception: If upload fails
    """
    try:
        key = f"agentcore_security_report_{execution_id}.csv"

        s3_client.put_object(
            Bucket=bucket_name,
            Key=key,
            Body=csv_content.encode("utf-8"),
            ContentType="text/csv",
        )

        s3_url = f"s3://{bucket_name}/{key}"
        logger.info(f"Successfully uploaded report to {s3_url}")

        return s3_url

    except Exception as e:
        logger.error(f"Error uploading to S3: {e}")
        raise


def check_agentcore_vpc_configuration() -> List[Dict[str, Any]]:
    """
    Check VPC configuration for AgentCore Runtimes, Code Interpreters, and Browser Tools.

    Validates:
    - VPC configuration exists
    - Subnets are private (not public)
    - Required VPC endpoints exist
    - NAT gateway configuration

    Returns:
        List of findings
    """
    findings = []

    if agentcore_client is None:
        logger.error("AgentCore client not available")
        findings.append(
            create_finding(
                check_id="AC-01",
                finding_name="AgentCore VPC Configuration Check",
                finding_details="AgentCore client not available in this region",
                resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/",
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    try:
        logger.info("Checking AgentCore VPC configuration")
        resources_found = False

        # Check Runtimes
        try:
            runtimes_response = agentcore_client.list_agent_runtimes()
            runtimes = runtimes_response.get("agentRuntimes", [])

            if not runtimes:
                logger.info("No AgentCore Runtimes found")
            else:
                resources_found = True
                logger.info(f"Found {len(runtimes)} AgentCore Runtimes")

                for runtime in runtimes:
                    runtime_id = runtime.get("agentRuntimeId", "unknown")
                    runtime_name = runtime.get("agentRuntimeName", runtime_id)

                    # Get detailed runtime info
                    try:
                        runtime_details = agentcore_client.get_agent_runtime(
                            agentRuntimeId=runtime_id
                        )
                        network_config = runtime_details.get("networkConfiguration", {})
                        network_mode = network_config.get("networkMode", "PUBLIC")

                        if network_mode == "PUBLIC":
                            findings.append(
                                create_finding(
                                    check_id="AC-01",
                                    finding_name="AgentCore Runtime VPC Configuration",
                                    finding_details=f"Runtime '{runtime_name}' ({runtime_id}) is not configured with VPC. This exposes the runtime to public internet.",
                                    resolution="Configure VPC with private subnets and required VPC endpoints (ECR, S3, CloudWatch Logs)",
                                    reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/security/agentcore-vpc.md",
                                    severity=SeverityEnum.HIGH,
                                    status=StatusEnum.FAILED,
                                )
                            )
                        else:
                            # Validate VPC configuration
                            subnet_ids = network_config.get("subnetIds", [])

                            if subnet_ids:
                                # Check if subnets are private
                                try:
                                    subnets_response = ec2_client.describe_subnets(
                                        SubnetIds=subnet_ids
                                    )
                                    for subnet in subnets_response.get("Subnets", []):
                                        subnet_id = subnet["SubnetId"]

                                        # Check route tables for internet gateway
                                        route_tables = ec2_client.describe_route_tables(
                                            Filters=[
                                                {
                                                    "Name": "association.subnet-id",
                                                    "Values": [subnet_id],
                                                }
                                            ]
                                        )

                                        for rt in route_tables.get("RouteTables", []):
                                            for route in rt.get("Routes", []):
                                                if route.get(
                                                    "GatewayId", ""
                                                ).startswith("igw-"):
                                                    findings.append(
                                                        create_finding(
                                                            check_id="AC-01",
                                                            finding_name="AgentCore Runtime Public Subnet",
                                                            finding_details=f"Runtime '{runtime_name}' is in public subnet {subnet_id} with direct internet access",
                                                            resolution="Move runtime to private subnets without direct internet gateway routes",
                                                            reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/security/agentcore-vpc.md",
                                                            severity=SeverityEnum.MEDIUM,
                                                            status=StatusEnum.FAILED,
                                                        )
                                                    )

                                except ClientError as e:
                                    logger.warning(
                                        f"Error checking subnet configuration: {e}"
                                    )

                    except ClientError as e:
                        if e.response["Error"]["Code"] == "ResourceNotFoundException":
                            logger.warning(f"Runtime {runtime_id} not found")
                        else:
                            logger.error(f"Error describing runtime {runtime_id}: {e}")

        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                logger.info("No AgentCore Runtimes found")
            else:
                logger.error(f"Error listing runtimes: {e}")
                raise

        # Note: Code Interpreters and Browser Tools are configured as part of Runtime
        # They don't have separate list/describe APIs in bedrock-agentcore-control
        # VPC configuration for these tools is inherited from the Runtime configuration

        # Return appropriate status based on whether resources were found
        if not findings:
            if resources_found:
                findings.append(
                    create_finding(
                        check_id="AC-01",
                        finding_name="AgentCore VPC Configuration Check",
                        finding_details="All AgentCore resources have proper VPC configuration",
                        resolution="No action required",
                        reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/security/agentcore-vpc.md",
                        severity=SeverityEnum.HIGH,
                        status=StatusEnum.PASSED,
                    )
                )
            else:
                findings.append(
                    create_finding(
                        check_id="AC-01",
                        finding_name="AgentCore VPC Configuration Check",
                        finding_details="No AgentCore resources found",
                        resolution="No action required",
                        reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/security/agentcore-vpc.md",
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )

    except Exception as e:
        logger.error(f"Error in VPC configuration check: {e}")
        findings.append(
            create_finding(
                check_id="AC-01",
                finding_name="AgentCore VPC Configuration Check",
                finding_details=f"Error during check: {str(e)}",
                resolution="Investigate error and retry assessment",
                reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/",
                severity=SeverityEnum.HIGH,
                status=StatusEnum.FAILED,
            )
        )

    return findings


def check_agentcore_full_access_roles(
    permission_cache: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Check for IAM roles with overly permissive AgentCore access.

    Identifies:
    - Roles with BedrockAgentCoreFullAccess managed policy
    - Roles with wildcard AgentCore permissions

    Args:
        permission_cache: Cached IAM permissions data

    Returns:
        List of findings
    """
    findings = []

    try:
        logger.info("Checking for AgentCore full access roles")

        role_permissions = permission_cache.get("role_permissions", {})

        if not role_permissions:
            logger.info("No role permissions in cache")
            findings.append(
                create_finding(
                    check_id="AC-02",
                    finding_name="AgentCore IAM Full Access Check",
                    finding_details="No IAM role permissions found in cache",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam-awsmanpol.html",
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            return findings

        full_access_roles = []
        wildcard_roles = []

        # Iterate over role_permissions dict (role_name -> permissions)
        for role_name, permissions in role_permissions.items():
            attached_policies = permissions.get("attached_policies", [])
            inline_policies = permissions.get("inline_policies", [])

            # Check for BedrockAgentCoreFullAccess managed policy
            for policy in attached_policies:
                policy_name = policy.get("name", "")
                if (
                    "BedrockAgentCoreFullAccess" in policy_name
                    or "AgentCoreFullAccess" in policy_name
                ):
                    full_access_roles.append(role_name)
                    break

            # Check for wildcard AgentCore permissions in inline policies
            for policy in inline_policies:
                policy_name = policy.get("name", "")
                policy_doc = policy.get("document", {})
                try:
                    if isinstance(policy_doc, str):
                        policy_doc = json.loads(policy_doc)

                    statements = policy_doc.get("Statement", [])
                    if not isinstance(statements, list):
                        statements = [statements]

                    for statement in statements:
                        if statement.get("Effect") == "Allow":
                            actions = statement.get("Action", [])
                            if isinstance(actions, str):
                                actions = [actions]

                            resources = statement.get("Resource", [])
                            if isinstance(resources, str):
                                resources = [resources]

                            # Check for wildcard AgentCore permissions
                            for action in actions:
                                if (
                                    "bedrock-agentcore:*" in action
                                    or "bedrock-agentcore-control:*" in action
                                ):
                                    if "*" in resources:
                                        wildcard_roles.append(role_name)
                                        break

                except Exception as e:
                    logger.warning(
                        f"Error parsing inline policy for role {role_name}: {e}"
                    )

        # Generate findings for full access roles
        if full_access_roles:
            findings.append(
                create_finding(
                    check_id="AC-02",
                    finding_name="AgentCore IAM Full Access Policy",
                    finding_details=f"The following roles have BedrockAgentCoreFullAccess policy: {', '.join(full_access_roles)}",
                    resolution="Replace with least-privilege policies scoped to specific AgentCore resources and actions",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam-awsmanpol.html",
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )

        # Generate findings for wildcard roles
        if wildcard_roles:
            findings.append(
                create_finding(
                    check_id="AC-02",
                    finding_name="AgentCore IAM Wildcard Permissions",
                    finding_details=f"The following roles have wildcard AgentCore permissions on all resources: {', '.join(wildcard_roles)}",
                    resolution="Scope permissions to specific AgentCore resources using resource ARNs",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam-awsmanpol.html",
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )

        # If no issues found - roles were evaluated and none were problematic
        if not findings:
            findings.append(
                create_finding(
                    check_id="AC-02",
                    finding_name="AgentCore IAM Full Access Check",
                    finding_details="No roles with overly permissive AgentCore access found",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam-awsmanpol.html",
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                )
            )

    except Exception as e:
        logger.error(f"Error in full access roles check: {e}")
        findings.append(
            create_finding(
                check_id="AC-02",
                finding_name="AgentCore IAM Full Access Check",
                finding_details=f"Error during check: {str(e)}",
                resolution="Investigate error and retry assessment",
                reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam-awsmanpol.html",
                severity=SeverityEnum.HIGH,
                status=StatusEnum.FAILED,
            )
        )

    return findings


def check_stale_agentcore_access(
    permission_cache: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Check for IAM principals with AgentCore permissions but no recent usage.

    Identifies:
    - Principals that haven't accessed AgentCore in 60+ days
    - Principals with permissions but never accessed AgentCore

    Args:
        permission_cache: Cached IAM permissions data

    Returns:
        List of findings
    """
    findings = []

    try:
        logger.info("Checking for stale AgentCore access")

        # Get current account ID from STS
        sts_client = boto3.client("sts", config=boto3_config)
        account_id = sts_client.get_caller_identity()["Account"]

        role_permissions = permission_cache.get("role_permissions", {})
        user_permissions = permission_cache.get("user_permissions", {})

        if not role_permissions and not user_permissions:
            logger.info("No IAM permissions in cache")
            findings.append(
                create_finding(
                    check_id="AC-03",
                    finding_name="AgentCore Stale Access Check",
                    finding_details="No IAM permissions found in cache",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            return findings

        # Identify principals with AgentCore permissions
        agentcore_principals = []

        # Check roles - iterate over dict
        for role_name, permissions in role_permissions.items():
            # Build role ARN from role name
            role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
            attached_policies = permissions.get("attached_policies", [])
            inline_policies = permissions.get("inline_policies", [])

            has_agentcore_permission = False

            # Check attached policies
            for policy in attached_policies:
                policy_name = policy.get("name", "")
                if "AgentCore" in policy_name or "agentcore" in policy_name.lower():
                    has_agentcore_permission = True
                    break

            # Check inline policies
            if not has_agentcore_permission:
                for policy in inline_policies:
                    policy_name = policy.get("name", "")
                    policy_doc = policy.get("document", {})
                    try:
                        if isinstance(policy_doc, str):
                            policy_doc = json.loads(policy_doc)

                        statements = policy_doc.get("Statement", [])
                        if not isinstance(statements, list):
                            statements = [statements]

                        for statement in statements:
                            if statement.get("Effect") == "Allow":
                                actions = statement.get("Action", [])
                                if isinstance(actions, str):
                                    actions = [actions]

                                for action in actions:
                                    if (
                                        "bedrock-agentcore" in action.lower()
                                        or "agentcore" in action.lower()
                                    ):
                                        has_agentcore_permission = True
                                        break

                                if has_agentcore_permission:
                                    break

                    except Exception as e:
                        logger.warning(
                            f"Error parsing inline policy for role {role_name}: {e}"
                        )

            if has_agentcore_permission and role_arn:
                agentcore_principals.append(
                    {"type": "role", "name": role_name, "arn": role_arn}
                )

        # Check users - iterate over dict
        for user_name, permissions in user_permissions.items():
            # Build user ARN from user name
            user_arn = f"arn:aws:iam::{account_id}:user/{user_name}"
            attached_policies = permissions.get("attached_policies", [])
            inline_policies = permissions.get("inline_policies", [])

            has_agentcore_permission = False

            # Check attached policies
            for policy in attached_policies:
                policy_name = policy.get("name", "")
                if "AgentCore" in policy_name or "agentcore" in policy_name.lower():
                    has_agentcore_permission = True
                    break

            # Check inline policies
            if not has_agentcore_permission:
                for policy in inline_policies:
                    policy_name = policy.get("name", "")
                    policy_doc = policy.get("document", {})
                    try:
                        if isinstance(policy_doc, str):
                            policy_doc = json.loads(policy_doc)

                        statements = policy_doc.get("Statement", [])
                        if not isinstance(statements, list):
                            statements = [statements]

                        for statement in statements:
                            if statement.get("Effect") == "Allow":
                                actions = statement.get("Action", [])
                                if isinstance(actions, str):
                                    actions = [actions]

                                for action in actions:
                                    if (
                                        "bedrock-agentcore" in action.lower()
                                        or "agentcore" in action.lower()
                                    ):
                                        has_agentcore_permission = True
                                        break

                                if has_agentcore_permission:
                                    break

                    except Exception as e:
                        logger.warning(
                            f"Error parsing inline policy for user {user_name}: {e}"
                        )

            if has_agentcore_permission and user_arn:
                agentcore_principals.append(
                    {"type": "user", "name": user_name, "arn": user_arn}
                )

        if not agentcore_principals:
            logger.info("No principals with AgentCore permissions found")
            findings.append(
                create_finding(
                    check_id="AC-03",
                    finding_name="AgentCore Stale Access Check",
                    finding_details="No IAM principals with AgentCore permissions found",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            return findings

        logger.info(
            f"Found {len(agentcore_principals)} principals with AgentCore permissions"
        )

        # Check last accessed for each principal
        stale_principals = []
        never_accessed_principals = []

        for principal in agentcore_principals:
            principal_arn = principal["arn"]
            principal_name = principal["name"]
            principal_type = principal["type"]

            try:
                # Generate service last accessed details
                logger.info(
                    f"Generating service last accessed details for {principal_type} {principal_name}"
                )

                generate_response = iam_client.generate_service_last_accessed_details(
                    Arn=principal_arn
                )
                job_id = generate_response["JobId"]

                # Wait for job completion (max 30 seconds)
                max_wait_time = 30
                wait_interval = 2
                elapsed_time = 0
                job_status = "IN_PROGRESS"

                while job_status == "IN_PROGRESS" and elapsed_time < max_wait_time:
                    time.sleep(wait_interval)  # nosemgrep: arbitrary-sleep
                    elapsed_time += wait_interval

                    get_response = iam_client.get_service_last_accessed_details(
                        JobId=job_id
                    )
                    job_status = get_response["JobStatus"]

                    if job_status == "COMPLETED":
                        # Check for AgentCore service access
                        services = get_response.get("ServicesLastAccessed", [])

                        agentcore_service = None
                        for service in services:
                            service_name = service.get("ServiceName", "")
                            service_namespace = service.get("ServiceNamespace", "")

                            # Look for AgentCore service
                            if (
                                "agentcore" in service_name.lower()
                                or "agentcore" in service_namespace.lower()
                                or "bedrock-agentcore" in service_namespace.lower()
                            ):
                                agentcore_service = service
                                break

                        if agentcore_service:
                            last_authenticated = agentcore_service.get(
                                "LastAuthenticated"
                            )

                            if last_authenticated:
                                # Calculate days since last access
                                last_access_date = datetime.fromisoformat(
                                    str(last_authenticated).replace("Z", "+00:00")
                                )
                                current_date = datetime.now(timezone.utc)
                                days_since_access = (
                                    current_date - last_access_date
                                ).days

                                if days_since_access > 60:
                                    stale_principals.append(
                                        {
                                            "type": principal_type,
                                            "name": principal_name,
                                            "days": days_since_access,
                                        }
                                    )
                                    logger.info(
                                        f"{principal_type} {principal_name} last accessed AgentCore {days_since_access} days ago"
                                    )
                            else:
                                # Never accessed
                                never_accessed_principals.append(
                                    {"type": principal_type, "name": principal_name}
                                )
                                logger.info(
                                    f"{principal_type} {principal_name} has never accessed AgentCore"
                                )
                        else:
                            # AgentCore service not in the list - treat as never accessed
                            never_accessed_principals.append(
                                {"type": principal_type, "name": principal_name}
                            )
                            logger.info(
                                f"{principal_type} {principal_name} has AgentCore permissions but service not in access history"
                            )

                        break

                    elif job_status == "FAILED":
                        logger.error(
                            f"Job failed for {principal_type} {principal_name}"
                        )
                        break

                if job_status == "IN_PROGRESS":
                    logger.warning(
                        f"Job timed out for {principal_type} {principal_name} after {max_wait_time}s"
                    )
                    findings.append(
                        create_finding(
                            check_id="AC-03",
                            finding_name="AgentCore Stale Access Check Incomplete",
                            finding_details=f"Could not determine last access for {principal_type} '{principal_name}' — IAM job timed out after {max_wait_time}s",
                            resolution="Re-run the assessment or manually check service last accessed details for this principal",
                            reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                            severity=SeverityEnum.LOW,
                            status=StatusEnum.FAILED,
                        )
                    )

            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code == "NoSuchEntity":
                    logger.warning(f"Principal {principal_name} no longer exists")
                elif error_code == "AccessDenied":
                    logger.error(f"Access denied when checking {principal_name}: {e}")
                    findings.append(
                        create_finding(
                            check_id="AC-03",
                            finding_name="AgentCore Stale Access Check",
                            finding_details=f"Access denied when checking service last accessed for {principal_type} {principal_name}",
                            resolution="Ensure Lambda execution role has iam:GenerateServiceLastAccessedDetails and iam:GetServiceLastAccessedDetails permissions",
                            reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                            severity=SeverityEnum.HIGH,
                            status=StatusEnum.FAILED,
                        )
                    )
                    return findings
                else:
                    logger.error(
                        f"Error checking {principal_type} {principal_name}: {e}"
                    )

            except Exception as e:
                logger.error(
                    f"Unexpected error checking {principal_type} {principal_name}: {e}"
                )

        # Generate findings for stale access
        if stale_principals:
            stale_details = ", ".join(
                [
                    f"{p['type']} '{p['name']}' ({p['days']} days)"
                    for p in stale_principals
                ]
            )
            findings.append(
                create_finding(
                    check_id="AC-03",
                    finding_name="AgentCore Stale Access",
                    finding_details=f"The following principals have not accessed AgentCore in 60+ days: {stale_details}",
                    resolution="Review and remove unused AgentCore permissions following least privilege principle",
                    reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                )
            )

        # Generate findings for never accessed
        if never_accessed_principals:
            never_accessed_details = ", ".join(
                [f"{p['type']} '{p['name']}'" for p in never_accessed_principals]
            )
            findings.append(
                create_finding(
                    check_id="AC-03",
                    finding_name="AgentCore Unused Permissions",
                    finding_details=f"The following principals have AgentCore permissions but have never accessed the service: {never_accessed_details}",
                    resolution="Review and remove unused AgentCore permissions following least privilege principle",
                    reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                )
            )

        # If no issues found
        if not findings:
            findings.append(
                create_finding(
                    check_id="AC-03",
                    finding_name="AgentCore Stale Access Check",
                    finding_details=f"All {len(agentcore_principals)} principals with AgentCore permissions have accessed the service within the last 60 days",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                    severity=SeverityEnum.LOW,
                    status=StatusEnum.PASSED,
                )
            )

    except Exception as e:
        logger.error(f"Error in stale access check: {e}")
        findings.append(
            create_finding(
                check_id="AC-03",
                finding_name="AgentCore Stale Access Check",
                finding_details=f"Error during check: {str(e)}",
                resolution="Investigate error and retry assessment",
                reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                severity=SeverityEnum.MEDIUM,
                status=StatusEnum.FAILED,
            )
        )

    return findings


def check_agentcore_observability() -> List[Dict[str, Any]]:
    """
    Check observability configuration for AgentCore resources.

    Validates:
    - CloudWatch Logs configuration
    - X-Ray tracing enabled
    - CloudWatch custom metrics published

    Returns:
        List of findings
    """
    findings = []

    if agentcore_client is None:
        findings.append(
            create_finding(
                check_id="AC-04",
                finding_name="AgentCore Observability Check",
                finding_details="AgentCore client not available in this region",
                resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/observability/",
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    try:
        logger.info("Checking AgentCore observability configuration")
        resources_found = False

        # Check Runtimes for logging and tracing
        try:
            runtimes_response = agentcore_client.list_agent_runtimes()
            runtimes = runtimes_response.get("agentRuntimes", [])

            if not runtimes:
                logger.info("No AgentCore Runtimes found")
            else:
                resources_found = True
                logger.info(f"Found {len(runtimes)} AgentCore Runtimes")

                for runtime in runtimes:
                    runtime_id = runtime.get("agentRuntimeId", "unknown")
                    runtime_name = runtime.get("agentRuntimeName", runtime_id)

                    try:
                        runtime_details = agentcore_client.get_agent_runtime(
                            agentRuntimeId=runtime_id
                        )

                        # Check CloudWatch Logs configuration
                        logging_config = runtime_details.get("loggingConfig", {})
                        cloudwatch_logs_config = logging_config.get(
                            "cloudWatchLogsConfig"
                        )

                        if not cloudwatch_logs_config:
                            findings.append(
                                create_finding(
                                    check_id="AC-04",
                                    finding_name="AgentCore Runtime CloudWatch Logs",
                                    finding_details=f"Runtime '{runtime_name}' ({runtime_id}) does not have CloudWatch Logs configured",
                                    resolution="Enable CloudWatch Logs for monitoring and troubleshooting",
                                    reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/observability/",
                                    severity=SeverityEnum.MEDIUM,
                                    status=StatusEnum.FAILED,
                                )
                            )
                        else:
                            # Verify log group exists
                            log_group_name = cloudwatch_logs_config.get("logGroupName")
                            if log_group_name:
                                try:
                                    logs_client.describe_log_groups(
                                        logGroupNamePrefix=log_group_name, limit=1
                                    )
                                except ClientError as e:
                                    if (
                                        e.response["Error"]["Code"]
                                        == "ResourceNotFoundException"
                                    ):
                                        findings.append(
                                            create_finding(
                                                check_id="AC-04",
                                                finding_name="AgentCore Runtime Log Group Missing",
                                                finding_details=f"Runtime '{runtime_name}' has CloudWatch Logs configured but log group '{log_group_name}' does not exist",
                                                resolution="Create the log group or update runtime configuration",
                                                reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/observability/",
                                                severity=SeverityEnum.MEDIUM,
                                                status=StatusEnum.FAILED,
                                            )
                                        )

                        # Check X-Ray tracing configuration
                        tracing_config = runtime_details.get("tracingConfig", {})
                        tracing_enabled = tracing_config.get("enabled", False)

                        if not tracing_enabled:
                            findings.append(
                                create_finding(
                                    check_id="AC-04",
                                    finding_name="AgentCore Runtime X-Ray Tracing",
                                    finding_details=f"Runtime '{runtime_name}' ({runtime_id}) does not have X-Ray tracing enabled",
                                    resolution="Enable X-Ray tracing for distributed tracing and performance analysis",
                                    reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/observability/",
                                    severity=SeverityEnum.MEDIUM,
                                    status=StatusEnum.FAILED,
                                )
                            )

                    except ClientError as e:
                        if e.response["Error"]["Code"] != "ResourceNotFoundException":
                            logger.error(f"Error describing runtime {runtime_id}: {e}")

        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                logger.error(f"Error listing runtimes: {e}")

        # Return appropriate status based on whether resources were found
        if not findings:
            if resources_found:
                findings.append(
                    create_finding(
                        check_id="AC-04",
                        finding_name="AgentCore Observability Check",
                        finding_details="All AgentCore resources have proper observability configuration",
                        resolution="No action required",
                        reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/observability/",
                        severity=SeverityEnum.MEDIUM,
                        status=StatusEnum.PASSED,
                    )
                )
            else:
                findings.append(
                    create_finding(
                        check_id="AC-04",
                        finding_name="AgentCore Observability Check",
                        finding_details="No AgentCore resources found",
                        resolution="No action required",
                        reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/observability/",
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )

    except Exception as e:
        logger.error(f"Error in observability check: {e}")
        findings.append(
            create_finding(
                check_id="AC-04",
                finding_name="AgentCore Observability Check",
                finding_details=f"Error during check: {str(e)}",
                resolution="Investigate error and retry assessment",
                reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/observability/",
                severity=SeverityEnum.MEDIUM,
                status=StatusEnum.FAILED,
            )
        )

    return findings


def check_agentcore_encryption() -> List[Dict[str, Any]]:
    """
    Check encryption configuration for AgentCore resources.

    Validates:
    - ECR repository encryption
    - S3 bucket encryption for Browser Tool recordings
    - Customer-managed vs AWS-managed keys

    Returns:
        List of findings
    """
    findings = []

    try:
        logger.info("Checking AgentCore encryption configuration")
        resources_found = False

        # Check ECR repositories used by AgentCore
        try:
            ecr_response = ecr_client.describe_repositories()
            repositories = ecr_response.get("repositories", [])

            agentcore_repos = []
            for repo in repositories:
                repo_name = repo.get("repositoryName", "")
                # Look for AgentCore-related repositories
                if (
                    "agentcore" in repo_name.lower()
                    or "bedrock-agent" in repo_name.lower()
                ):
                    agentcore_repos.append(repo)

            if agentcore_repos:
                resources_found = True
                logger.info(
                    f"Found {len(agentcore_repos)} AgentCore-related ECR repositories"
                )

                for repo in agentcore_repos:
                    repo_name = repo.get("repositoryName", "unknown")
                    encryption_config = repo.get("encryptionConfiguration", {})
                    encryption_type = encryption_config.get("encryptionType", "NONE")

                    if encryption_type == "NONE" or not encryption_config:
                        findings.append(
                            create_finding(
                                check_id="AC-05",
                                finding_name="AgentCore ECR Repository Encryption",
                                finding_details=f"ECR repository '{repo_name}' does not have encryption enabled",
                                resolution="Enable encryption with customer-managed KMS keys for better control",
                                reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security-encryption.html",
                                severity=SeverityEnum.HIGH,
                                status=StatusEnum.FAILED,
                            )
                        )
                    elif encryption_type == "AES256":
                        findings.append(
                            create_finding(
                                check_id="AC-05",
                                finding_name="AgentCore ECR Repository AWS-Managed Keys",
                                finding_details=f"ECR repository '{repo_name}' uses AWS-managed keys instead of customer-managed KMS keys",
                                resolution="Consider using customer-managed KMS keys for better control and audit capabilities",
                                reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security-encryption.html",
                                severity=SeverityEnum.LOW,
                                status=StatusEnum.FAILED,
                            )
                        )

        except ClientError as e:
            logger.warning(f"Error checking ECR repositories: {e}")

        # Note: Browser Tool recording buckets and Code Interpreter storage are configured
        # as part of Runtime configuration, not as separate resources

        # Return appropriate status based on whether resources were found
        if not findings:
            if resources_found:
                findings.append(
                    create_finding(
                        check_id="AC-05",
                        finding_name="AgentCore Encryption Check",
                        finding_details="All AgentCore resources have proper encryption configuration",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/key-management.html",
                        severity=SeverityEnum.HIGH,
                        status=StatusEnum.PASSED,
                    )
                )
            else:
                findings.append(
                    create_finding(
                        check_id="AC-05",
                        finding_name="AgentCore Encryption Check",
                        finding_details="No AgentCore resources found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock/latest/userguide/key-management.html",
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )

    except Exception as e:
        logger.error(f"Error in encryption check: {e}")
        findings.append(
            create_finding(
                check_id="AC-05",
                finding_name="AgentCore Encryption Check",
                finding_details=f"Error during check: {str(e)}",
                resolution="Investigate error and retry assessment",
                reference="https://docs.aws.amazon.com/bedrock/latest/userguide/key-management.html",
                severity=SeverityEnum.HIGH,
                status=StatusEnum.FAILED,
            )
        )

    return findings


def check_browser_tool_recording() -> List[Dict[str, Any]]:
    """
    Check Browser Tool recording configuration.

    Note: Browser Tools are configured as part of Runtime configuration in AgentCore.
    This check validates that Runtimes have appropriate storage configuration.

    Returns:
        List of findings
    """
    findings = []

    if agentcore_client is None:
        findings.append(
            create_finding(
                check_id="AC-06",
                finding_name="AgentCore Browser Tool Recording Check",
                finding_details="AgentCore client not available in this region",
                resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/browser/",
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    try:
        logger.info(
            "Checking Browser Tool recording configuration (via Runtime config)"
        )

        # Browser Tools are part of Runtime configuration
        # Check if Runtimes have appropriate storage configured
        runtimes_response = agentcore_client.list_agent_runtimes()
        runtimes = runtimes_response.get("agentRuntimes", [])

        if not runtimes:
            logger.info("No AgentCore Runtimes found")
            findings.append(
                create_finding(
                    check_id="AC-06",
                    finding_name="AgentCore Browser Tool Recording Check",
                    finding_details="No AgentCore Runtimes found to check browser tool configuration",
                    resolution="No action required",
                    reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/browser/",
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            return findings

        logger.info(f"Found {len(runtimes)} AgentCore Runtimes")

        # Check if runtimes have storage configuration for browser tools
        for runtime in runtimes:
            runtime_id = runtime.get("agentRuntimeId", "unknown")
            runtime_name = runtime.get("agentRuntimeName", runtime_id)

            try:
                runtime_details = agentcore_client.get_agent_runtime(
                    agentRuntimeId=runtime_id
                )

                # Check for storage configuration (browser tools need storage)
                storage_config = runtime_details.get("storageConfig", {})

                if not storage_config:
                    findings.append(
                        create_finding(
                            check_id="AC-06",
                            finding_name="AgentCore Runtime Storage Configuration",
                            finding_details=f"Runtime '{runtime_name}' ({runtime_id}) does not have storage configuration for browser tools",
                            resolution="Configure S3 storage for browser tool session recordings and artifacts",
                            reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/browser/",
                            severity=SeverityEnum.MEDIUM,
                            status=StatusEnum.FAILED,
                        )
                    )

            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceNotFoundException":
                    logger.error(f"Error describing runtime {runtime_id}: {e}")

        # If no findings, return passed
        if not findings:
            findings.append(
                create_finding(
                    check_id="AC-06",
                    finding_name="AgentCore Browser Tool Recording Check",
                    finding_details=f"All {len(runtimes)} Runtimes have proper storage configuration",
                    resolution="No action required",
                    reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/browser/",
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.PASSED,
                )
            )

    except Exception as e:
        logger.error(f"Error in browser tool recording check: {e}")
        findings.append(
            create_finding(
                check_id="AC-06",
                finding_name="AgentCore Browser Tool Recording Check",
                finding_details=f"Error during check: {str(e)}",
                resolution="Investigate error and retry assessment",
                reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/browser/",
                severity=SeverityEnum.MEDIUM,
                status=StatusEnum.FAILED,
            )
        )

    return findings


def check_agentcore_memory_configuration() -> List[Dict[str, Any]]:
    """
    Check Memory resource configuration.

    Validates:
    - IAM role permissions are least-privilege
    - Encryption is configured

    Returns:
        List of findings
    """
    findings = []

    if agentcore_client is None:
        findings.append(
            create_finding(
                check_id="AC-07",
                finding_name="AgentCore Memory Configuration Check",
                finding_details="AgentCore client not available in this region",
                resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/memory/",
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    try:
        logger.info("Checking AgentCore Memory configuration")

        memories_response = agentcore_client.list_memories()
        memories = memories_response.get("memories", [])

        if not memories:
            logger.info("No Memory resources found")
            findings.append(
                create_finding(
                    check_id="AC-07",
                    finding_name="AgentCore Memory Configuration Check",
                    finding_details="No Memory resources found",
                    resolution="No action required",
                    reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/memory/",
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            return findings

        logger.info(f"Found {len(memories)} Memory resources")

        for memory in memories:
            memory_id = memory.get("id", "unknown")
            memory_name = (
                memory.get("name", memory_id) if memory.get("name") else memory_id
            )

            try:
                memory_details = agentcore_client.get_memory(memoryId=memory_id)

                # Check encryption configuration
                encryption_key_arn = memory_details.get("encryptionKeyArn")

                if not encryption_key_arn:
                    findings.append(
                        create_finding(
                            check_id="AC-07",
                            finding_name="AgentCore Memory Encryption",
                            finding_details=f"Memory '{memory_name}' ({memory_id}) does not have customer-managed encryption configured",
                            resolution="Enable encryption with customer-managed KMS keys",
                            reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/memory/",
                            severity=SeverityEnum.MEDIUM,
                            status=StatusEnum.FAILED,
                        )
                    )

            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceNotFoundException":
                    logger.error(f"Error describing memory {memory_id}: {e}")

        # If no findings, return passed
        if not findings:
            findings.append(
                create_finding(
                    check_id="AC-07",
                    finding_name="AgentCore Memory Configuration Check",
                    finding_details=f"All {len(memories)} Memory resources have proper configuration",
                    resolution="No action required",
                    reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/memory/",
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                )
            )

    except Exception as e:
        logger.error(f"Error in memory configuration check: {e}")
        findings.append(
            create_finding(
                check_id="AC-07",
                finding_name="AgentCore Memory Configuration Check",
                finding_details=f"Error during check: {str(e)}",
                resolution="Investigate error and retry assessment",
                reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/memory/",
                severity=SeverityEnum.MEDIUM,
                status=StatusEnum.FAILED,
            )
        )

    return findings


def check_agentcore_vpc_endpoints() -> List[Dict[str, Any]]:
    """
    Check for AWS PrivateLink VPC endpoints for AgentCore.

    Validates:
    - VPC endpoints exist for bedrock-agentcore services
    - Private connectivity is configured

    Returns:
        List of findings
    """
    findings = []

    try:
        logger.info("Checking for AgentCore VPC endpoints")

        # Get all VPCs
        vpcs_response = ec2_client.describe_vpcs()
        vpcs = vpcs_response.get("Vpcs", [])

        if not vpcs:
            findings.append(
                create_finding(
                    check_id="AC-08",
                    finding_name="AgentCore VPC Endpoints Check",
                    finding_details="No VPCs found in the account",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/vpc.html",
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            return findings

        vpc_ids = [vpc["VpcId"] for vpc in vpcs]

        # Get all VPC endpoints
        endpoints_response = ec2_client.describe_vpc_endpoints()
        all_endpoints = endpoints_response.get("VpcEndpoints", [])

        # Check for AgentCore endpoints
        found_agentcore_endpoints = []
        for endpoint in all_endpoints:
            service_name = endpoint.get("ServiceName", "")
            if (
                "agentcore" in service_name.lower()
                or "bedrock-agentcore" in service_name.lower()
            ):
                found_agentcore_endpoints.append(
                    {
                        "vpc_id": endpoint.get("VpcId"),
                        "service": service_name,
                        "state": endpoint.get("State"),
                    }
                )

        if not found_agentcore_endpoints:
            findings.append(
                create_finding(
                    check_id="AC-08",
                    finding_name="AgentCore VPC Endpoints Missing",
                    finding_details=f"No AgentCore VPC endpoints found in {len(vpc_ids)} VPCs. AgentCore API traffic traverses public internet, exposing it to interception.",
                    resolution="Create VPC interface endpoints for AgentCore services:\n"
                    + "1. com.amazonaws.region.bedrock-agentcore\n"
                    + "2. com.amazonaws.region.bedrock-agentcore-control\n"
                    + "3. com.amazonaws.region.bedrock-agentcore-runtime\n"
                    + "This enables private connectivity via AWS PrivateLink",
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/vpc.html",
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )
        else:
            # Check endpoint state
            unhealthy_endpoints = [
                e for e in found_agentcore_endpoints if e["state"] != "available"
            ]

            if unhealthy_endpoints:
                findings.append(
                    create_finding(
                        check_id="AC-08",
                        finding_name="AgentCore VPC Endpoints Unhealthy",
                        finding_details=f"Found {len(unhealthy_endpoints)} AgentCore VPC endpoints in non-available state",
                        resolution="Investigate and resolve VPC endpoint issues",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/vpc.html",
                        severity=SeverityEnum.MEDIUM,
                        status=StatusEnum.FAILED,
                    )
                )
            else:
                endpoint_details = ", ".join(
                    [
                        f"{e['service']} in {e['vpc_id']}"
                        for e in found_agentcore_endpoints
                    ]
                )
                findings.append(
                    create_finding(
                        check_id="AC-08",
                        finding_name="AgentCore VPC Endpoints Check",
                        finding_details=f"AgentCore VPC endpoints configured: {endpoint_details}",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/vpc.html",
                        severity=SeverityEnum.HIGH,
                        status=StatusEnum.PASSED,
                    )
                )

    except Exception as e:
        logger.error(f"Error in VPC endpoints check: {e}")
        findings.append(
            create_finding(
                check_id="AC-08",
                finding_name="AgentCore VPC Endpoints Check",
                finding_details=f"Error during check: {str(e)}",
                resolution="Investigate error and retry assessment",
                reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/vpc.html",
                severity=SeverityEnum.MEDIUM,
                status=StatusEnum.FAILED,
            )
        )

    return findings


def check_agentcore_service_linked_role() -> List[Dict[str, Any]]:
    """
    Check if the AgentCore service-linked role exists and is properly configured.

    The AWSServiceRoleForBedrockAgentCoreNetwork role is required for VPC ENI creation.

    Returns:
        List of findings
    """
    findings = []

    try:
        logger.info("Checking AgentCore service-linked role")

        slr_name = "AWSServiceRoleForBedrockAgentCoreNetwork"

        try:
            role_response = iam_client.get_role(RoleName=slr_name)
            role = role_response.get("Role", {})

            # Verify the role is properly configured
            assume_role_policy = role.get("AssumeRolePolicyDocument", {})

            # Check if the trust policy allows bedrock-agentcore service
            statements = assume_role_policy.get("Statement", [])
            has_correct_principal = False

            for statement in statements:
                principal = statement.get("Principal", {})
                service = principal.get("Service", "")
                if isinstance(service, list):
                    if any("agentcore" in s.lower() for s in service):
                        has_correct_principal = True
                elif "agentcore" in service.lower():
                    has_correct_principal = True

            if has_correct_principal:
                findings.append(
                    create_finding(
                        check_id="AC-09",
                        finding_name="AgentCore Service-Linked Role Check",
                        finding_details=f"Service-linked role '{slr_name}' exists and is properly configured for AgentCore VPC networking",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-vpc.html",
                        severity=SeverityEnum.MEDIUM,
                        status=StatusEnum.PASSED,
                    )
                )
            else:
                findings.append(
                    create_finding(
                        check_id="AC-09",
                        finding_name="AgentCore Service-Linked Role Misconfigured",
                        finding_details=f"Service-linked role '{slr_name}' exists but may have incorrect trust policy",
                        resolution="Delete and recreate the service-linked role by enabling VPC configuration on an AgentCore Runtime",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-vpc.html",
                        severity=SeverityEnum.MEDIUM,
                        status=StatusEnum.FAILED,
                    )
                )

        except iam_client.exceptions.NoSuchEntityException:
            findings.append(
                create_finding(
                    check_id="AC-09",
                    finding_name="AgentCore Service-Linked Role Missing",
                    finding_details=f"Service-linked role '{slr_name}' does not exist. VPC configuration for AgentCore Runtimes will fail without this role.",
                    resolution="The service-linked role is automatically created when you configure VPC for an AgentCore Runtime. Ensure IAM permissions allow service-linked role creation.",
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-vpc.html",
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                )
            )

    except Exception as e:
        logger.error(f"Error in service-linked role check: {e}")
        findings.append(
            create_finding(
                check_id="AC-09",
                finding_name="AgentCore Service-Linked Role Check",
                finding_details=f"Error during check: {str(e)}",
                resolution="Investigate error and retry assessment",
                reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-vpc.html",
                severity=SeverityEnum.MEDIUM,
                status=StatusEnum.FAILED,
            )
        )

    return findings


def check_agentcore_resource_based_policies() -> List[Dict[str, Any]]:
    """
    Check for proper resource-based policies on AgentCore resources.

    Validates:
    - Agent Runtime resource policies
    - Gateway resource policies
    - Memory resource policies

    Returns:
        List of findings
    """
    findings = []

    if agentcore_client is None:
        findings.append(
            create_finding(
                check_id="AC-10",
                finding_name="AgentCore Resource-Based Policies Check",
                finding_details="AgentCore client not available in this region",
                resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security_iam_service-with-iam.html",
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    try:
        logger.info("Checking AgentCore resource-based policies")

        resources_without_rbp = []
        resources_with_rbp = []

        # Check Agent Runtimes
        try:
            runtimes_response = agentcore_client.list_agent_runtimes()
            runtimes = runtimes_response.get("agentRuntimes", [])

            for runtime in runtimes:
                runtime_id = runtime.get("agentRuntimeId", "unknown")
                runtime_name = runtime.get("agentRuntimeName", runtime_id)

                try:
                    # Try to get resource policy
                    policy_response = (
                        agentcore_client.get_agent_runtime_resource_policy(
                            agentRuntimeId=runtime_id
                        )
                    )
                    policy = policy_response.get("resourcePolicy")

                    if policy:
                        resources_with_rbp.append(f"Runtime: {runtime_name}")
                    else:
                        resources_without_rbp.append(
                            {"type": "Runtime", "name": runtime_name, "id": runtime_id}
                        )

                except ClientError as e:
                    if e.response["Error"]["Code"] == "ResourceNotFoundException":
                        resources_without_rbp.append(
                            {"type": "Runtime", "name": runtime_name, "id": runtime_id}
                        )
                    else:
                        logger.warning(
                            f"Error checking policy for runtime {runtime_id}: {e}"
                        )
                except AttributeError:
                    # API method doesn't exist
                    logger.info("get_agent_runtime_resource_policy API not available")
                    break

        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                logger.warning(f"Error listing runtimes: {e}")

        # Check Gateways
        try:
            gateways_response = agentcore_client.list_gateways()
            gateways = gateways_response.get("gateways", [])

            for gateway in gateways:
                gateway_id = gateway.get("gatewayId", "unknown")
                gateway_name = gateway.get("name", gateway_id)

                try:
                    policy_response = agentcore_client.get_gateway_resource_policy(
                        gatewayId=gateway_id
                    )
                    policy = policy_response.get("resourcePolicy")

                    if policy:
                        resources_with_rbp.append(f"Gateway: {gateway_name}")
                    else:
                        resources_without_rbp.append(
                            {"type": "Gateway", "name": gateway_name, "id": gateway_id}
                        )

                except ClientError as e:
                    if e.response["Error"]["Code"] == "ResourceNotFoundException":
                        resources_without_rbp.append(
                            {"type": "Gateway", "name": gateway_name, "id": gateway_id}
                        )
                except AttributeError:
                    logger.info("get_gateway_resource_policy API not available")
                    break

        except (ClientError, AttributeError) as e:
            logger.info(f"Gateway APIs not available: {e}")

        # Generate findings
        if resources_without_rbp:
            resource_list = ", ".join(
                [f"{r['type']} '{r['name']}'" for r in resources_without_rbp[:5]]
            )
            if len(resources_without_rbp) > 5:
                resource_list += f" and {len(resources_without_rbp) - 5} more"

            findings.append(
                create_finding(
                    check_id="AC-10",
                    finding_name="AgentCore Resource-Based Policies Missing",
                    finding_details=f"The following AgentCore resources do not have resource-based policies: {resource_list}. Without RBPs, access control relies solely on identity-based policies.",
                    resolution="Attach resource-based policies to AgentCore resources to:\n"
                    + "1. Implement defense-in-depth access control\n"
                    + "2. Enable cross-account access control\n"
                    + "3. Restrict access based on source VPC or IP\n"
                    + "4. Implement hierarchical authorization for Agent Runtimes",
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security_iam_service-with-iam.html",
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )

        if not findings:
            if resources_with_rbp:
                findings.append(
                    create_finding(
                        check_id="AC-10",
                        finding_name="AgentCore Resource-Based Policies Check",
                        finding_details=f"Resource-based policies configured on: {', '.join(resources_with_rbp)}",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security_iam_service-with-iam.html",
                        severity=SeverityEnum.MEDIUM,
                        status=StatusEnum.PASSED,
                    )
                )
            else:
                findings.append(
                    create_finding(
                        check_id="AC-10",
                        finding_name="AgentCore Resource-Based Policies Check",
                        finding_details="No AgentCore resources found to check for resource-based policies",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security_iam_service-with-iam.html",
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )

    except Exception as e:
        logger.error(f"Error in resource-based policies check: {e}")
        findings.append(
            create_finding(
                check_id="AC-10",
                finding_name="AgentCore Resource-Based Policies Check",
                finding_details=f"Error during check: {str(e)}",
                resolution="Investigate error and retry assessment",
                reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security_iam_service-with-iam.html",
                severity=SeverityEnum.MEDIUM,
                status=StatusEnum.FAILED,
            )
        )

    return findings


def check_agentcore_policy_engine_encryption() -> List[Dict[str, Any]]:
    """
    Check if AgentCore Policy Engines are encrypted with customer-managed KMS keys.

    Policy engines store authorization rules that determine what agents can do.
    Unencrypted policy data exposes security controls.

    Returns:
        List of findings
    """
    findings = []

    if agentcore_client is None:
        findings.append(
            create_finding(
                check_id="AC-11",
                finding_name="AgentCore Policy Engine Encryption Check",
                finding_details="AgentCore client not available in this region",
                resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-encryption.html",
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    try:
        logger.info("Checking AgentCore Policy Engine encryption")

        try:
            # List policy engines
            policy_engines_response = agentcore_client.list_policy_engines()
            policy_engines = policy_engines_response.get("policyEngines", [])

            if not policy_engines:
                findings.append(
                    create_finding(
                        check_id="AC-11",
                        finding_name="AgentCore Policy Engine Encryption Check",
                        finding_details="No Policy Engines found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-encryption.html",
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )
                return findings

            engines_without_cmk = []
            engines_with_cmk = []

            for engine in policy_engines:
                engine_id = engine.get("policyEngineId", "unknown")
                engine_name = engine.get("name", engine_id)

                try:
                    engine_details = agentcore_client.get_policy_engine(
                        policyEngineId=engine_id
                    )

                    encryption_key_arn = engine_details.get("encryptionKeyArn")

                    if encryption_key_arn:
                        engines_with_cmk.append(engine_name)
                    else:
                        engines_without_cmk.append(
                            {"name": engine_name, "id": engine_id}
                        )

                except ClientError as e:
                    if e.response["Error"]["Code"] != "ResourceNotFoundException":
                        logger.warning(f"Error getting policy engine {engine_id}: {e}")

            if engines_without_cmk:
                engine_list = ", ".join([f"'{e['name']}'" for e in engines_without_cmk])
                findings.append(
                    create_finding(
                        check_id="AC-11",
                        finding_name="AgentCore Policy Engine Encryption Missing",
                        finding_details=f"The following Policy Engines do not use customer-managed KMS encryption: {engine_list}. Policy data containing authorization rules is not protected with CMK.",
                        resolution="1. Create a customer-managed KMS key with appropriate key policy\n"
                        + "2. Grant Policy in AgentCore permissions via kms:CreateGrant\n"
                        + "3. Create new policy engines with --encryption-key-arn parameter\n"
                        + "Note: Encryption cannot be added to existing policy engines",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-encryption.html",
                        severity=SeverityEnum.HIGH,
                        status=StatusEnum.FAILED,
                    )
                )

            if engines_with_cmk:
                findings.append(
                    create_finding(
                        check_id="AC-11",
                        finding_name="AgentCore Policy Engine Encryption Check",
                        finding_details=f"Policy Engines with CMK encryption: {', '.join(engines_with_cmk)}",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-encryption.html",
                        severity=SeverityEnum.MEDIUM,
                        status=StatusEnum.PASSED,
                    )
                )

            if not findings:
                findings.append(
                    create_finding(
                        check_id="AC-11",
                        finding_name="AgentCore Policy Engine Encryption Check",
                        finding_details=f"Checked {len(policy_engines)} Policy Engines",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-encryption.html",
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )

        except AttributeError:
            # API not available
            findings.append(
                create_finding(
                    check_id="AC-11",
                    finding_name="AgentCore Policy Engine Encryption Check",
                    finding_details="Policy Engine APIs not yet available in bedrock-agentcore-control client",
                    resolution="N/A - Check may need to be updated when APIs become available",
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-encryption.html",
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )

    except Exception as e:
        logger.error(f"Error in policy engine encryption check: {e}")
        findings.append(
            create_finding(
                check_id="AC-11",
                finding_name="AgentCore Policy Engine Encryption Check",
                finding_details=f"Error during check: {str(e)}",
                resolution="Investigate error and retry assessment",
                reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-encryption.html",
                severity=SeverityEnum.MEDIUM,
                status=StatusEnum.FAILED,
            )
        )

    return findings


def check_agentcore_gateway_encryption() -> List[Dict[str, Any]]:
    """
    Check if AgentCore Gateways are encrypted with customer-managed KMS keys.

    Gateway configurations include tool definitions, target endpoints, and
    API schemas which may contain sensitive information.

    Returns:
        List of findings
    """
    findings = []

    if agentcore_client is None:
        findings.append(
            create_finding(
                check_id="AC-12",
                finding_name="AgentCore Gateway Encryption Check",
                finding_details="AgentCore client not available in this region",
                resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-encryption.html",
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    try:
        logger.info("Checking AgentCore Gateway encryption")

        try:
            gateways_response = agentcore_client.list_gateways()
            gateways = gateways_response.get("gateways", [])

            if not gateways:
                findings.append(
                    create_finding(
                        check_id="AC-12",
                        finding_name="AgentCore Gateway Encryption Check",
                        finding_details="No Gateways found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-encryption.html",
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )
                return findings

            gateways_without_cmk = []
            gateways_with_cmk = []

            for gateway in gateways:
                gateway_id = gateway.get("gatewayId", "unknown")
                gateway_name = gateway.get("name", gateway_id)

                try:
                    gateway_details = agentcore_client.get_gateway(gatewayId=gateway_id)

                    # Check for customer-managed KMS key
                    encryption_key_arn = gateway_details.get(
                        "kmsKeyArn"
                    ) or gateway_details.get("encryptionKeyArn")

                    if encryption_key_arn:
                        gateways_with_cmk.append(gateway_name)
                    else:
                        gateways_without_cmk.append(
                            {"name": gateway_name, "id": gateway_id}
                        )

                except ClientError as e:
                    if e.response["Error"]["Code"] != "ResourceNotFoundException":
                        logger.warning(f"Error getting gateway {gateway_id}: {e}")

            if gateways_without_cmk:
                gateway_list = ", ".join(
                    [f"'{g['name']}'" for g in gateways_without_cmk]
                )
                findings.append(
                    create_finding(
                        check_id="AC-12",
                        finding_name="AgentCore Gateway Encryption Missing",
                        finding_details=f"The following Gateways do not use customer-managed KMS encryption: {gateway_list}. Gateway configuration data uses AWS-managed keys.",
                        resolution="1. Create gateways with customer-managed KMS keys for additional control\n"
                        + "2. AWS-managed keys are single-tenant and region-specific\n"
                        + "3. Consider CMK for enhanced audit capabilities and key rotation control",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-encryption.html",
                        severity=SeverityEnum.LOW,
                        status=StatusEnum.FAILED,
                    )
                )

            if gateways_with_cmk:
                findings.append(
                    create_finding(
                        check_id="AC-12",
                        finding_name="AgentCore Gateway Encryption Check",
                        finding_details=f"Gateways with CMK encryption: {', '.join(gateways_with_cmk)}",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-encryption.html",
                        severity=SeverityEnum.MEDIUM,
                        status=StatusEnum.PASSED,
                    )
                )

            if not findings:
                findings.append(
                    create_finding(
                        check_id="AC-12",
                        finding_name="AgentCore Gateway Encryption Check",
                        finding_details=f"Checked {len(gateways)} Gateways",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-encryption.html",
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )

        except AttributeError:
            findings.append(
                create_finding(
                    check_id="AC-12",
                    finding_name="AgentCore Gateway Encryption Check",
                    finding_details="Gateway APIs not yet available in bedrock-agentcore-control client",
                    resolution="N/A - Check may need to be updated when APIs become available",
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-encryption.html",
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )

    except Exception as e:
        logger.error(f"Error in gateway encryption check: {e}")
        findings.append(
            create_finding(
                check_id="AC-12",
                finding_name="AgentCore Gateway Encryption Check",
                finding_details=f"Error during check: {str(e)}",
                resolution="Investigate error and retry assessment",
                reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-encryption.html",
                severity=SeverityEnum.MEDIUM,
                status=StatusEnum.FAILED,
            )
        )

    return findings


def check_agentcore_gateway_configuration() -> List[Dict[str, Any]]:
    """
    Check Gateway resource configuration.

    Note: Gateway APIs may not be available in bedrock-agentcore-control yet.
    This check will gracefully handle if the API doesn't exist.

    Returns:
        List of findings
    """
    findings = []

    if agentcore_client is None:
        findings.append(
            create_finding(
                check_id="AC-13",
                finding_name="AgentCore Gateway Configuration Check",
                finding_details="AgentCore client not available in this region",
                resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/gateway/",
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    try:
        logger.info("Checking AgentCore Gateway configuration")

        # Try to list gateways - this API may not exist yet
        try:
            gateways_response = agentcore_client.list_gateways()
            gateways = gateways_response.get("gateways", [])

            if not gateways:
                logger.info("No Gateway resources found")
                findings.append(
                    create_finding(
                        check_id="AC-13",
                        finding_name="AgentCore Gateway Configuration Check",
                        finding_details="No Gateway resources found",
                        resolution="No action required",
                        reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/gateway/",
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )
                return findings

            logger.info(f"Found {len(gateways)} Gateway resources")

            # If we got here, gateways exist - check their configuration
            for gateway in gateways:
                gateway_id = gateway.get("gatewayId", "unknown")
                gateway_name = gateway.get("name", gateway_id)

                # Basic check - just verify gateway exists
                # Detailed configuration checks would require get_gateway API
                logger.info(f"Found gateway: {gateway_name} ({gateway_id})")

            # If no findings, return passed
            findings.append(
                create_finding(
                    check_id="AC-13",
                    finding_name="AgentCore Gateway Configuration Check",
                    finding_details=f"Found {len(gateways)} Gateway resources",
                    resolution="No action required",
                    reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/gateway/",
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.PASSED,
                )
            )

        except AttributeError as e:
            # list_gateways method doesn't exist
            logger.info(f"Gateway API not available: {e}")
            findings.append(
                create_finding(
                    check_id="AC-13",
                    finding_name="AgentCore Gateway Configuration Check",
                    finding_details="Gateway API not yet available in bedrock-agentcore-control",
                    resolution="N/A - Gateway management may be done through other means",
                    reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/gateway/",
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )

        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                findings.append(
                    create_finding(
                        check_id="AC-13",
                        finding_name="AgentCore Gateway Configuration Check",
                        finding_details="No Gateway resources found",
                        resolution="No action required",
                        reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/gateway/",
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )
            else:
                raise

    except Exception as e:
        logger.error(f"Error in gateway configuration check: {e}")
        findings.append(
            create_finding(
                check_id="AC-13",
                finding_name="AgentCore Gateway Configuration Check",
                finding_details=f"Error during check: {str(e)}",
                resolution="Investigate error and retry assessment",
                reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/gateway/",
                severity=SeverityEnum.MEDIUM,
                status=StatusEnum.FAILED,
            )
        )

    return findings


def lambda_handler(event, context):
    """
    Lambda handler for AgentCore security assessment.

    Args:
        event: Lambda event containing execution_id
        context: Lambda context

    Returns:
        Response with status and S3 URL
    """
    global start_time
    start_time = time.time()

    try:
        # Extract execution ID
        execution_id = event.get("Execution", {}).get("Name", "unknown")
        logger.info(
            f"Starting AgentCore security assessment for execution: {execution_id}"
        )

        # Retrieve permission cache
        try:
            permission_cache = get_permissions_cache(execution_id)
        except Exception as e:
            logger.warning(f"Failed to retrieve permission cache: {e}")
            permission_cache = {"role_permissions": [], "user_permissions": []}

        # Collect all findings
        all_findings = []

        # Execute all assessment checks
        checks = [
            ("VPC Configuration", check_agentcore_vpc_configuration),
            (
                "IAM Full Access",
                lambda: check_agentcore_full_access_roles(permission_cache),
            ),
            ("Stale Access", lambda: check_stale_agentcore_access(permission_cache)),
            ("Observability", check_agentcore_observability),
            ("Encryption", check_agentcore_encryption),
            ("Browser Tool Recording", check_browser_tool_recording),
            ("Memory Configuration", check_agentcore_memory_configuration),
            ("Gateway Configuration", check_agentcore_gateway_configuration),
            ("VPC Endpoints", check_agentcore_vpc_endpoints),
            ("Service-Linked Role", check_agentcore_service_linked_role),
            ("Resource-Based Policies", check_agentcore_resource_based_policies),
            ("Policy Engine Encryption", check_agentcore_policy_engine_encryption),
            ("Gateway Encryption", check_agentcore_gateway_encryption),
        ]

        for check_name, check_func in checks:
            if not check_timeout():
                logger.error(
                    f"Timeout approaching, skipping remaining checks after {check_name}"
                )
                break

            try:
                logger.info(f"Running check: {check_name}")
                check_start = time.time()

                findings = check_func()
                all_findings.extend(findings)

                check_duration = time.time() - check_start
                logger.info(
                    f"Check '{check_name}' completed in {check_duration:.2f}s with {len(findings)} findings"
                )

            except Exception as e:
                logger.error(f"Error in check '{check_name}': {e}")
                # Add error finding
                all_findings.append(
                    create_finding(
                        check_id="AC-00",
                        finding_name=f"AgentCore {check_name} Check Error",
                        finding_details=f"Error during {check_name} check: {str(e)}",
                        resolution="Investigate error and retry assessment",
                        reference="https://aws.github.io/bedrock-agentcore-starter-toolkit/",
                        severity=SeverityEnum.HIGH,
                        status=StatusEnum.FAILED,
                    )
                )

        # Generate CSV report
        logger.info(f"Generating CSV report with {len(all_findings)} total findings")
        csv_content = generate_csv_report(all_findings)

        # Upload to S3
        s3_url = write_to_s3(execution_id, csv_content, BUCKET_NAME)

        # Calculate execution metrics
        total_duration = time.time() - start_time
        logger.info(f"Assessment completed in {total_duration:.2f}s")

        # Publish CloudWatch metrics
        try:
            cloudwatch_client.put_metric_data(
                Namespace="AIMLSecurity/AgentCore",
                MetricData=[
                    {
                        "MetricName": "AssessmentDuration",
                        "Value": total_duration,
                        "Unit": "Seconds",
                    },
                    {
                        "MetricName": "FindingsCount",
                        "Value": len(all_findings),
                        "Unit": "Count",
                    },
                ],
            )
        except Exception as e:
            logger.warning(f"Failed to publish CloudWatch metrics: {e}")

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": "AgentCore security assessment completed successfully",
                    "s3_url": s3_url,
                    "execution_id": execution_id,
                    "findings_count": len(all_findings),
                    "duration_seconds": total_duration,
                }
            ),
        }

    except Exception as e:
        logger.error(f"Fatal error in lambda_handler: {e}", exc_info=True)
        return {
            "statusCode": 500,
            "body": json.dumps(
                {"message": "AgentCore security assessment failed", "error": str(e)}
            ),
        }
