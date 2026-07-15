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
from botocore.exceptions import ClientError, EndpointConnectionError

from schema import create_finding, SeverityEnum, StatusEnum
from severity_disposition import could_not_assess_row, COULD_NOT_ASSESS_PREFIX

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configure boto3 with adaptive retry mode
boto3_config = Config(retries=dict(max_attempts=10, mode="adaptive"))

# Initialize S3 client (always uses Lambda's region for bucket operations)
s3_client = boto3.client("s3", config=boto3_config)

# Regional clients — initialized in lambda_handler with target region
iam_client = None
ec2_client = None
ecr_client = None
logs_client = None
xray_client = None
cloudwatch_client = None
agentcore_client = None

# Environment variables
BUCKET_NAME = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")

# IAM is a global service. Findings derived purely from the IAM permission cache
# (e.g. AC-02, AC-03) are identical across regions, so they are produced only on
# the primary region (Map index 0) and tagged with this region label to avoid
# duplicate findings when scanning multiple regions.
GLOBAL_REGION_LABEL = "Global"

AGENTIC_AI_LENS_URL = (
    "https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/"
    "agentic-ai-lens.html"
)
AGENTCORE_STARTER_TOOLKIT_URL = (
    "https://aws.github.io/bedrock-agentcore-starter-toolkit/"
)
AGENTCORE_VPC_REFERENCE_URL = (
    "https://aws.github.io/bedrock-agentcore-starter-toolkit/"
    "user-guide/security/agentcore-vpc.html"
)
AGENTCORE_OBSERVABILITY_REFERENCE_URL = (
    "https://aws.github.io/bedrock-agentcore-starter-toolkit/"
    "user-guide/observability/quickstart.html"
)
AGENTCORE_BROWSER_REFERENCE_URL = (
    "https://aws.github.io/bedrock-agentcore-starter-toolkit/"
    "user-guide/builtin-tools/quickstart-browser.html"
)
AGENTCORE_MEMORY_REFERENCE_URL = (
    "https://aws.github.io/bedrock-agentcore-starter-toolkit/"
    "user-guide/memory/quickstart.html"
)
AGENTCORE_GATEWAY_REFERENCE_URL = (
    "https://aws.github.io/bedrock-agentcore-starter-toolkit/"
    "user-guide/gateway/quickstart.html"
)
AGENTCORE_DATA_ENCRYPTION_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-encryption.html"
)
ECR_ENCRYPTION_REFERENCE_URL = (
    "https://docs.aws.amazon.com/AmazonECR/latest/userguide/encryption-at-rest.html"
)
AGENTCORE_GATEWAY_API_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/"
    "API_GetGateway.html"
)
AGENTCORE_POLICY_ENGINE_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/"
    "API_GatewayPolicyEngineConfiguration.html"
)

AGENTIC_AGENTCORE_CHECK_MAPPINGS = {
    "AC-01": {
        "check_id": "AG-15",
        "finding": "Agentic AI Runtime Network Boundary",
        "lens_domain": "Bounded Autonomy",
        "agentic_context": "Agent runtimes should execute inside explicit network boundaries to reduce unintended external reachability.",
        "resolution": "Configure AgentCore runtimes with appropriate VPC settings and restrict network paths to required services.",
    },
    "AC-02": {
        "check_id": "AG-16",
        "finding": "Agentic AI AgentCore Least Privilege",
        "lens_domain": "Agent Identity & Access",
        "agentic_context": "Over-permissive AgentCore principals can let agents or operators bypass intended autonomy and tool boundaries.",
        "resolution": "Replace full-access AgentCore permissions with least-privilege IAM policies scoped to required resources and actions.",
    },
    "AC-03": {
        "check_id": "AG-17",
        "finding": "Agentic AI Stale AgentCore Access",
        "lens_domain": "Agent Identity & Access",
        "agentic_context": "Unused AgentCore permissions increase the blast radius of compromised principals.",
        "resolution": "Remove or restrict stale AgentCore permissions for principals that no longer need access.",
    },
    "AC-04": {
        "check_id": "AG-18",
        "finding": "Agentic AI AgentCore Observability",
        "lens_domain": "Auditability & Observability",
        "agentic_context": "AgentCore observability provides the telemetry needed to investigate runtime, tool, memory, and gateway behavior.",
        "resolution": "Enable CloudWatch Logs, tracing, and AgentCore observability for runtime and gateway resources where supported.",
    },
    "AC-07": {
        "check_id": "AG-19",
        "finding": "Agentic AI Memory Data Protection",
        "lens_domain": "Memory & Data Privacy",
        "agentic_context": "Agent memory can contain sensitive user or business context and should use customer-controlled encryption where required.",
        "resolution": "Configure AgentCore memory resources with customer-managed KMS keys and review memory access permissions.",
    },
    "AC-08": {
        "check_id": "AG-20",
        "finding": "Agentic AI Private AgentCore Connectivity",
        "lens_domain": "Bounded Autonomy",
        "agentic_context": "Private service connectivity reduces exposure for agents that access AgentCore control or runtime services.",
        "resolution": "Create required VPC endpoints for AgentCore services and validate endpoint availability.",
    },
    "AC-10": {
        "check_id": "AG-21",
        "finding": "Agentic AI Resource Policy Boundary",
        "lens_domain": "Agent Identity & Access",
        "agentic_context": "Resource-based policies add a second authorization boundary for AgentCore runtimes and gateways.",
        "resolution": "Attach resource-based policies to AgentCore resources to constrain principals, accounts, and network sources.",
    },
    "AC-11": {
        "check_id": "AG-22",
        "finding": "Agentic AI Policy Engine Data Protection",
        "lens_domain": "Tool Authorization",
        "agentic_context": "Policy engines contain authorization logic for tool calls and should be protected with appropriate encryption controls.",
        "resolution": "Configure policy engines with customer-managed KMS keys where enhanced key control is required.",
    },
    "AC-12": {
        "check_id": "AG-23",
        "finding": "Agentic AI Gateway Data Protection",
        "lens_domain": "Tool Authorization",
        "agentic_context": "Gateway configuration can include tool schemas, target definitions, and integration metadata.",
        "resolution": "Configure AgentCore gateways with customer-managed KMS keys where enhanced key control is required.",
    },
}

# Error codes returned when a region exists but is not enabled/usable for the
# account (opt-in regions, disabled regions). The availability probe treats
# these the same as an endpoint connection failure.
REGION_UNAVAILABLE_ERROR_CODES = {
    "UnrecognizedClientException",
    "InvalidClientTokenId",
    "AuthFailure",
    "OptInRequired",
}

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


def _agentcore_list_all(
    list_method_name: str,
    result_keys: List[str],
    extra_kwargs: Dict[str, Any] = None,
) -> List[Dict[str, Any]]:
    """Collect all items from an AgentCore list API, following nextToken.

    ``extra_kwargs`` is passed on every page call (e.g. ``{"type": "CUSTOM"}``
    to restrict ListBrowsers/ListCodeInterpreters to customer-created
    resources, matching the BrowserCustom/CodeInterpreterCustom resource types
    that Security Hub controls BedrockAgentCore.5-.7 evaluate).
    """
    if agentcore_client is None:
        return []

    items: List[Dict[str, Any]] = []
    next_token = None
    list_method = getattr(agentcore_client, list_method_name)

    while True:
        kwargs = dict(extra_kwargs) if extra_kwargs else {}
        if next_token:
            kwargs["nextToken"] = next_token

        response = list_method(**kwargs)
        if not isinstance(response, dict):
            logger.warning(
                f"{list_method_name} returned unexpected response type: "
                f"{type(response).__name__}"
            )
            break

        for result_key in result_keys:
            page_items = response.get(result_key)
            if isinstance(page_items, list):
                items.extend(page_items)
                break

        next_token = response.get("nextToken")
        if next_token is not None and not isinstance(next_token, str):
            logger.warning(
                f"{list_method_name} returned non-string nextToken: "
                f"{type(next_token).__name__}"
            )
            break
        if not next_token:
            break

    return items


def _unwrap_agentcore_detail(
    response: Dict[str, Any], wrapper_key: str
) -> Dict[str, Any]:
    """Handle detail APIs that wrap the resource under a top-level key."""
    if not isinstance(response, dict):
        return {}

    wrapped = response.get(wrapper_key)
    if isinstance(wrapped, dict):
        return wrapped

    return response


def _get_agentcore_resource_policy(resource_arn: str) -> str:
    """Retrieve the generic AgentCore resource policy for a resource ARN."""
    response = agentcore_client.get_resource_policy(resourceArn=resource_arn)
    return response.get("policy") or response.get("resourcePolicy") or ""


def _is_access_denied_client_error(error: ClientError) -> bool:
    """Normalize access-denied checks across AgentCore control plane APIs."""
    if not isinstance(error, ClientError):
        return False

    error_code = error.response.get("Error", {}).get("Code")
    return error_code in {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
    }


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
                "Region",
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
            "Region",
        ],
    )
    writer.writeheader()

    for finding in findings:
        writer.writerow(finding)

    csv_content = output.getvalue()
    logger.info(f"Generated CSV report with {len(findings)} findings")

    return csv_content


def build_agentic_agentcore_security_findings(
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Create AG-* rows from AgentCore checks that already prove agentic controls."""
    agentic_findings = []
    for row in findings:
        source_check_id = row.get("Check_ID", "")
        mapping = AGENTIC_AGENTCORE_CHECK_MAPPINGS.get(source_check_id)
        if not mapping:
            continue

        status = row.get("Status", "N/A")
        severity = row.get("Severity", "Informational")
        if status == "N/A":
            severity = "Informational"

        agentic_findings.append(
            create_finding(
                check_id=mapping["check_id"],
                finding_name=mapping["finding"],
                finding_details=(
                    f"Agentic AI security domain: {mapping['lens_domain']}. "
                    f"{mapping['agentic_context']} "
                    f"Source check {source_check_id}: {row.get('Finding_Details', '')}"
                ),
                resolution=mapping["resolution"],
                reference=AGENTIC_AI_LENS_URL,
                severity=severity,
                status=status,
                region=row.get("Region", ""),
            )
        )
    return agentic_findings


def build_agentic_agentcore_unavailable_findings(
    region: str, existing_findings: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Create N/A AG-* rows for AgentCore-derived checks that could not run."""
    existing_check_ids = {finding.get("Check_ID") for finding in existing_findings}
    unavailable_findings = []

    for mapping in AGENTIC_AGENTCORE_CHECK_MAPPINGS.values():
        if mapping["check_id"] in existing_check_ids:
            continue

        unavailable_findings.append(
            create_finding(
                check_id=mapping["check_id"],
                finding_name=mapping["finding"],
                finding_details=(
                    f"Agentic AI security domain: {mapping['lens_domain']}. "
                    f"This AgentCore-derived control could not be assessed because "
                    f"Amazon Bedrock AgentCore is not available in region {region}."
                ),
                resolution="No action required unless AgentCore workloads are expected in this region.",
                reference=AGENTIC_AI_LENS_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
                region=region,
            )
        )

    return unavailable_findings


def write_to_s3(
    execution_id: str, csv_content: str, bucket_name: str, region: str = ""
) -> str:
    """
    Upload CSV report to S3.

    Args:
        execution_id: Unique execution identifier
        csv_content: CSV content to upload
        bucket_name: S3 bucket name
        region: AWS region identifier for the report filename

    Returns:
        S3 URL of uploaded file

    Raises:
        Exception: If upload fails
    """
    try:
        if region:
            key = f"agentcore_security_report_{execution_id}_{region}.csv"
        else:
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
    Check that AgentCore Runtimes use VPC network mode.

    Aligns with AWS Security Hub control BedrockAgentCore.1 (severity High):
    the control fails if the runtime's networkConfiguration.networkMode is
    PUBLIC (an absent value defaults to PUBLIC and fails). Custom browsers and
    code interpreters are covered by their own controls (BedrockAgentCore.5-.7)
    and APIs, not by this check.

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
                reference=AGENTCORE_STARTER_TOOLKIT_URL,
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
            runtimes = _agentcore_list_all("list_agent_runtimes", ["agentRuntimes"])

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
                                    reference=AGENTCORE_VPC_REFERENCE_URL,
                                    severity=SeverityEnum.HIGH,
                                    status=StatusEnum.FAILED,
                                )
                            )
                        # VPC mode passes: Security Hub control BedrockAgentCore.1
                        # fails only when networkMode is PUBLIC. (VPC subnet
                        # details live under networkConfiguration.networkModeConfig
                        # .subnets, not a top-level subnetIds field.)

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

        # Note: custom browsers and code interpreters have their own APIs
        # (ListBrowsers/GetBrowser, ListCodeInterpreters/GetCodeInterpreter)
        # and their own Security Hub controls (BedrockAgentCore.5-.7). Browser
        # session recording is covered by AC-06; this check covers runtimes only.

        # Return appropriate status based on whether resources were found
        if not findings:
            if resources_found:
                findings.append(
                    create_finding(
                        check_id="AC-01",
                        finding_name="AgentCore VPC Configuration Check",
                        finding_details="All AgentCore resources have proper VPC configuration",
                        resolution="No action required",
                        reference=AGENTCORE_VPC_REFERENCE_URL,
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
                        reference=AGENTCORE_VPC_REFERENCE_URL,
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )

    except Exception as e:
        logger.error(f"Error in VPC configuration check: {e}")
        findings.append(
            could_not_assess_row(
                create_finding,
                "AC-01",
                "AgentCore VPC Configuration Check",
                e,
                AGENTCORE_STARTER_TOOLKIT_URL,
                SeverityEnum,
                StatusEnum,
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
            could_not_assess_row(
                create_finding,
                "AC-02",
                "AgentCore IAM Full Access Check",
                e,
                "https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam-awsmanpol.html",
                SeverityEnum,
                StatusEnum,
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
                        could_not_assess_row(
                            create_finding,
                            "AC-03",
                            "AgentCore Stale Access Check",
                            f"Could not determine last access for {principal_type} "
                            f"'{principal_name}' — IAM job timed out after "
                            f"{max_wait_time}s",
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                            SeverityEnum,
                            StatusEnum,
                        )
                    )

            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code == "NoSuchEntity":
                    logger.warning(f"Principal {principal_name} no longer exists")
                elif error_code == "AccessDenied":
                    logger.error(f"Access denied when checking {principal_name}: {e}")
                    findings.append(
                        could_not_assess_row(
                            create_finding,
                            "AC-03",
                            "AgentCore Stale Access Check",
                            f"Access denied when checking service last accessed for {principal_type} {principal_name} ({e})",
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                            SeverityEnum,
                            StatusEnum,
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
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
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
            could_not_assess_row(
                create_finding,
                "AC-03",
                "AgentCore Stale Access Check",
                e,
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html",
                SeverityEnum,
                StatusEnum,
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
                reference=AGENTCORE_OBSERVABILITY_REFERENCE_URL,
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
            runtimes = _agentcore_list_all("list_agent_runtimes", ["agentRuntimes"])

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
                                    reference=AGENTCORE_OBSERVABILITY_REFERENCE_URL,
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
                                                reference=AGENTCORE_OBSERVABILITY_REFERENCE_URL,
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
                                    reference=AGENTCORE_OBSERVABILITY_REFERENCE_URL,
                                    severity=SeverityEnum.MEDIUM,
                                    status=StatusEnum.FAILED,
                                )
                            )

                    except ClientError as e:
                        if e.response["Error"]["Code"] != "ResourceNotFoundException":
                            logger.error(f"Error describing runtime {runtime_id}: {e}")

        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                # Enumeration itself failed (e.g. AccessDenied) — re-raise so
                # the outer handler reports COULD_NOT_ASSESS rather than
                # silently falling through to a "no resources found" N/A,
                # which would understate an access gap as a clean result.
                logger.error(f"Error listing runtimes: {e}")
                raise

        # Return appropriate status based on whether resources were found
        if not findings:
            if resources_found:
                findings.append(
                    create_finding(
                        check_id="AC-04",
                        finding_name="AgentCore Observability Check",
                        finding_details="All AgentCore resources have proper observability configuration",
                        resolution="No action required",
                        reference=AGENTCORE_OBSERVABILITY_REFERENCE_URL,
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
                        reference=AGENTCORE_OBSERVABILITY_REFERENCE_URL,
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )

    except Exception as e:
        logger.error(f"Error in observability check: {e}")
        findings.append(
            could_not_assess_row(
                create_finding,
                "AC-04",
                "AgentCore Observability Check",
                e,
                AGENTCORE_OBSERVABILITY_REFERENCE_URL,
                SeverityEnum,
                StatusEnum,
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
                                reference=ECR_ENCRYPTION_REFERENCE_URL,
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
                                reference=ECR_ENCRYPTION_REFERENCE_URL,
                                severity=SeverityEnum.LOW,
                                status=StatusEnum.FAILED,
                            )
                        )

        except ClientError as e:
            # Enumeration itself failed (e.g. AccessDenied) — re-raise so the
            # outer handler reports COULD_NOT_ASSESS rather than silently
            # falling through to a "no resources found" N/A.
            logger.warning(f"Error checking ECR repositories: {e}")
            raise

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
                        reference=AGENTCORE_DATA_ENCRYPTION_REFERENCE_URL,
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
                        reference=AGENTCORE_DATA_ENCRYPTION_REFERENCE_URL,
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )

    except Exception as e:
        logger.error(f"Error in encryption check: {e}")
        findings.append(
            could_not_assess_row(
                create_finding,
                "AC-05",
                "AgentCore Encryption Check",
                e,
                AGENTCORE_DATA_ENCRYPTION_REFERENCE_URL,
                SeverityEnum,
                StatusEnum,
            )
        )

    return findings


def check_browser_tool_recording() -> List[Dict[str, Any]]:
    """
    Check that custom AgentCore browsers have session recording enabled with an
    S3 destination configured.

    Aligns with AWS Security Hub control BedrockAgentCore.6 (severity Medium):
    the control fails if a custom browser does not have recording enabled or
    does not have an S3 location configured for storing recordings. Only
    customer-created browsers are evaluated (ListBrowsers type=CUSTOM); AWS
    system browsers such as aws.browser.v1 are out of scope, matching the
    control's AWS::BedrockAgentCore::BrowserCustom resource type.
    """
    check_name = "AgentCore Browser Session Recording Check"
    findings = []

    if agentcore_client is None:
        findings.append(
            create_finding(
                check_id="AC-06",
                finding_name=check_name,
                finding_details="AgentCore client not available in this region",
                resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                reference=AGENTCORE_BROWSER_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    def _could_not_assess(detail: str, resolution: str) -> Dict[str, Any]:
        # COULD_NOT_ASSESS disposition (severity methodology section 3.4): the
        # check could not run, so report an unknown state (N/A, Low) instead of
        # a false Failed or a silent "no resources" row.
        return create_finding(
            check_id="AC-06",
            finding_name=f"COULD NOT ASSESS: {check_name}",
            finding_details=detail,
            resolution=resolution,
            reference=AGENTCORE_BROWSER_REFERENCE_URL,
            severity=SeverityEnum.LOW,
            status=StatusEnum.NA,
        )

    try:
        logger.info("Checking custom browser session recording configuration")
        try:
            browsers = _agentcore_list_all(
                "list_browsers", ["browserSummaries"], {"type": "CUSTOM"}
            )
        except ClientError as e:
            if _is_access_denied_client_error(e):
                return [
                    _could_not_assess(
                        f"Unable to list AgentCore browsers: {str(e)}. Custom "
                        "browser session recording was NOT assessed.",
                        "Grant bedrock-agentcore:ListBrowsers and "
                        "bedrock-agentcore:GetBrowser to the assessment role "
                        "and re-run the assessment.",
                    )
                ]
            raise
        except AttributeError:
            return [
                _could_not_assess(
                    "Browser APIs are not available in this bedrock-agentcore-control "
                    "client version. Custom browser session recording was NOT assessed.",
                    "Ensure botocore meets the version floor in requirements.txt "
                    "and re-run the assessment.",
                )
            ]

        if not browsers:
            findings.append(
                create_finding(
                    check_id="AC-06",
                    finding_name=check_name,
                    finding_details="No custom browsers found",
                    resolution="No action required",
                    reference=AGENTCORE_BROWSER_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            return findings

        logger.info(f"Found {len(browsers)} custom browsers")
        browsers_without_recording = []
        browsers_with_recording = []
        browsers_not_assessed = []

        for browser in browsers:
            browser_id = browser.get("browserId", "unknown")
            browser_name = browser.get("name", browser_id)
            try:
                browser_details = agentcore_client.get_browser(browserId=browser_id)
            except ClientError as e:
                if e.response["Error"]["Code"] == "ResourceNotFoundException":
                    continue
                logger.warning(f"Error describing browser {browser_id}: {e}")
                browsers_not_assessed.append(browser_name)
                continue

            recording = browser_details.get("recording") or {}
            recording_enabled = recording.get("enabled") is True
            s3_bucket = (recording.get("s3Location") or {}).get("bucket")

            if recording_enabled and s3_bucket:
                browsers_with_recording.append(browser_name)
            else:
                browsers_without_recording.append(
                    {"name": browser_name, "id": browser_id}
                )

        if browsers_without_recording:
            browser_list = ", ".join(
                f"'{b['name']}'" for b in browsers_without_recording
            )
            findings.append(
                create_finding(
                    check_id="AC-06",
                    finding_name="AgentCore Browser Session Recording Disabled",
                    finding_details=(
                        f"The following custom browsers do not have session recording "
                        f"enabled with an S3 destination: {browser_list}. Without "
                        "recording, automated browsing sessions cannot be audited for "
                        "unauthorized access, data exfiltration, or malicious activity."
                    ),
                    resolution=(
                        "Enable session recording with an S3 location when creating "
                        "custom browsers (recording.enabled=true and "
                        "recording.s3Location.bucket). Recording cannot be changed "
                        "after creation; recreate the browser with recording enabled."
                    ),
                    reference=AGENTCORE_BROWSER_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                )
            )

        if browsers_with_recording and not browsers_without_recording:
            findings.append(
                create_finding(
                    check_id="AC-06",
                    finding_name=check_name,
                    finding_details=(
                        f"All {len(browsers_with_recording)} custom browsers have "
                        "session recording enabled with an S3 destination"
                    ),
                    resolution="No action required",
                    reference=AGENTCORE_BROWSER_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.PASSED,
                )
            )

        if browsers_not_assessed:
            findings.append(
                _could_not_assess(
                    "Unable to describe the following custom browsers: "
                    f"{', '.join(browsers_not_assessed)}. Their session recording "
                    "configuration was NOT assessed.",
                    "Grant bedrock-agentcore:GetBrowser to the assessment role "
                    "and re-run the assessment.",
                )
            )

    except Exception as e:
        logger.error(f"Error in browser session recording check: {e}")
        findings.append(
            _could_not_assess(
                f"This check could not be completed (error: {str(e)}). Custom "
                "browser session recording was NOT assessed.",
                "Verify the assessment role's bedrock-agentcore permissions, "
                "confirm the region supports AgentCore, and re-run the assessment.",
            )
        )

    return findings


def check_browser_network_mode() -> List[Dict[str, Any]]:
    """
    Check that custom AgentCore browsers are not configured with PUBLIC
    network mode.

    Aligns with AWS Security Hub control BedrockAgentCore.5 (severity High):
    the control fails when a custom browser's
    networkConfiguration.networkMode is PUBLIC. Only customer-created
    browsers are evaluated (ListBrowsers type=CUSTOM, Rule 7); AWS system
    browsers such as aws.browser.v1 are out of scope, matching the control's
    AWS::BedrockAgentCore::BrowserCustom resource type.
    """
    check_name = "AgentCore Browser Network Mode Check"
    findings = []

    if agentcore_client is None:
        findings.append(
            create_finding(
                check_id="AC-14",
                finding_name=check_name,
                finding_details="AgentCore client not available in this region",
                resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                reference=AGENTCORE_BROWSER_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    def _could_not_assess(detail: str, resolution: str) -> Dict[str, Any]:
        return create_finding(
            check_id="AC-14",
            finding_name=f"COULD NOT ASSESS: {check_name}",
            finding_details=detail,
            resolution=resolution,
            reference=AGENTCORE_BROWSER_REFERENCE_URL,
            severity=SeverityEnum.LOW,
            status=StatusEnum.NA,
        )

    try:
        logger.info("Checking custom browser network mode configuration")
        try:
            browsers = _agentcore_list_all(
                "list_browsers", ["browserSummaries"], {"type": "CUSTOM"}
            )
        except ClientError as e:
            if _is_access_denied_client_error(e):
                return [
                    _could_not_assess(
                        f"Unable to list AgentCore browsers: {str(e)}. Custom "
                        "browser network mode was NOT assessed.",
                        "Grant bedrock-agentcore:ListBrowsers and "
                        "bedrock-agentcore:GetBrowser to the assessment role "
                        "and re-run the assessment.",
                    )
                ]
            raise
        except AttributeError:
            return [
                _could_not_assess(
                    "Browser APIs are not available in this bedrock-agentcore-control "
                    "client version. Custom browser network mode was NOT assessed.",
                    "Ensure botocore meets the version floor in requirements.txt "
                    "and re-run the assessment.",
                )
            ]

        if not browsers:
            findings.append(
                create_finding(
                    check_id="AC-14",
                    finding_name=check_name,
                    finding_details="No custom browsers found",
                    resolution="No action required",
                    reference=AGENTCORE_BROWSER_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            return findings

        browsers_public = []
        browsers_private = []
        browsers_not_assessed = []

        for browser in browsers:
            browser_id = browser.get("browserId", "unknown")
            browser_name = browser.get("name", browser_id)
            try:
                browser_details = agentcore_client.get_browser(browserId=browser_id)
            except ClientError as e:
                if e.response["Error"]["Code"] == "ResourceNotFoundException":
                    continue
                logger.warning(f"Error describing browser {browser_id}: {e}")
                browsers_not_assessed.append(browser_name)
                continue

            network_mode = browser_details.get("networkConfiguration", {}).get(
                "networkMode", "PUBLIC"
            )

            if network_mode == "PUBLIC":
                browsers_public.append(browser_name)
            else:
                browsers_private.append(browser_name)

        if browsers_public:
            browser_list = ", ".join(f"'{b}'" for b in browsers_public)
            findings.append(
                create_finding(
                    check_id="AC-14",
                    finding_name="AgentCore Browser Public Network Mode",
                    finding_details=(
                        f"The following custom browsers use PUBLIC network mode: "
                        f"{browser_list}. Public network mode exposes the browser "
                        "tool to the public internet."
                    ),
                    resolution=(
                        "Configure custom browsers with VPC network mode "
                        "(networkConfiguration.networkMode=VPC) and appropriate "
                        "subnets/security groups. Network mode cannot be changed "
                        "after creation; recreate the browser with VPC mode."
                    ),
                    reference=AGENTCORE_BROWSER_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )

        if browsers_private and not browsers_public:
            findings.append(
                create_finding(
                    check_id="AC-14",
                    finding_name=check_name,
                    finding_details=(
                        f"All {len(browsers_private)} custom browsers use VPC "
                        "network mode"
                    ),
                    resolution="No action required",
                    reference=AGENTCORE_BROWSER_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                )
            )

        if browsers_not_assessed:
            findings.append(
                _could_not_assess(
                    "Unable to describe the following custom browsers: "
                    f"{', '.join(browsers_not_assessed)}. Their network mode "
                    "configuration was NOT assessed.",
                    "Grant bedrock-agentcore:GetBrowser to the assessment role "
                    "and re-run the assessment.",
                )
            )

    except Exception as e:
        logger.error(f"Error in browser network mode check: {e}")
        findings.append(
            _could_not_assess(
                f"This check could not be completed (error: {str(e)}). Custom "
                "browser network mode was NOT assessed.",
                "Verify the assessment role's bedrock-agentcore permissions, "
                "confirm the region supports AgentCore, and re-run the assessment.",
            )
        )

    return findings


CODE_INTERPRETER_REFERENCE_URL = (
    "https://aws.github.io/bedrock-agentcore-starter-toolkit/"
    "user-guide/builtin-tools/quickstart-code-interpreter.html"
)


def check_code_interpreter_network_mode() -> List[Dict[str, Any]]:
    """
    Check that custom AgentCore code interpreters are not configured with
    PUBLIC or SANDBOX network mode.

    Aligns with AWS Security Hub control BedrockAgentCore.7 (severity High):
    the control fails when a custom code interpreter's
    networkConfiguration.networkMode is PUBLIC or SANDBOX (only VPC mode
    passes). Only customer-created code interpreters are evaluated
    (ListCodeInterpreters type=CUSTOM, Rule 7); AWS system code interpreters
    such as aws.codeinterpreter.v1 are out of scope, matching the control's
    AWS::BedrockAgentCore::CodeInterpreterCustom resource type.
    """
    check_name = "AgentCore Code Interpreter Network Mode Check"
    findings = []

    if agentcore_client is None:
        findings.append(
            create_finding(
                check_id="AC-15",
                finding_name=check_name,
                finding_details="AgentCore client not available in this region",
                resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                reference=CODE_INTERPRETER_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    def _could_not_assess(detail: str, resolution: str) -> Dict[str, Any]:
        return create_finding(
            check_id="AC-15",
            finding_name=f"COULD NOT ASSESS: {check_name}",
            finding_details=detail,
            resolution=resolution,
            reference=CODE_INTERPRETER_REFERENCE_URL,
            severity=SeverityEnum.LOW,
            status=StatusEnum.NA,
        )

    try:
        logger.info("Checking custom code interpreter network mode configuration")
        try:
            code_interpreters = _agentcore_list_all(
                "list_code_interpreters",
                ["codeInterpreterSummaries"],
                {"type": "CUSTOM"},
            )
        except ClientError as e:
            if _is_access_denied_client_error(e):
                return [
                    _could_not_assess(
                        f"Unable to list AgentCore code interpreters: {str(e)}. "
                        "Custom code interpreter network mode was NOT assessed.",
                        "Grant bedrock-agentcore:ListCodeInterpreters and "
                        "bedrock-agentcore:GetCodeInterpreter to the assessment "
                        "role and re-run the assessment.",
                    )
                ]
            raise
        except AttributeError:
            return [
                _could_not_assess(
                    "Code interpreter APIs are not available in this "
                    "bedrock-agentcore-control client version. Custom code "
                    "interpreter network mode was NOT assessed.",
                    "Ensure botocore meets the version floor in requirements.txt "
                    "and re-run the assessment.",
                )
            ]

        if not code_interpreters:
            findings.append(
                create_finding(
                    check_id="AC-15",
                    finding_name=check_name,
                    finding_details="No custom code interpreters found",
                    resolution="No action required",
                    reference=CODE_INTERPRETER_REFERENCE_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            return findings

        interpreters_insecure = []
        interpreters_vpc = []
        interpreters_not_assessed = []

        for interpreter in code_interpreters:
            interpreter_id = interpreter.get("codeInterpreterId", "unknown")
            interpreter_name = interpreter.get("name", interpreter_id)
            try:
                interpreter_details = agentcore_client.get_code_interpreter(
                    codeInterpreterId=interpreter_id
                )
            except ClientError as e:
                if e.response["Error"]["Code"] == "ResourceNotFoundException":
                    continue
                logger.warning(
                    f"Error describing code interpreter {interpreter_id}: {e}"
                )
                interpreters_not_assessed.append(interpreter_name)
                continue

            network_mode = interpreter_details.get("networkConfiguration", {}).get(
                "networkMode", "PUBLIC"
            )

            if network_mode in ("PUBLIC", "SANDBOX"):
                interpreters_insecure.append(
                    {"name": interpreter_name, "network_mode": network_mode}
                )
            else:
                interpreters_vpc.append(interpreter_name)

        if interpreters_insecure:
            details_list = ", ".join(
                f"'{i['name']}' ({i['network_mode']})" for i in interpreters_insecure
            )
            findings.append(
                create_finding(
                    check_id="AC-15",
                    finding_name="AgentCore Code Interpreter Insecure Network Mode",
                    finding_details=(
                        "The following custom code interpreters do not use VPC "
                        f"network mode: {details_list}. PUBLIC and SANDBOX modes "
                        "expose the code interpreter to broader network access "
                        "than VPC mode."
                    ),
                    resolution=(
                        "Configure custom code interpreters with VPC network mode "
                        "(networkConfiguration.networkMode=VPC) and appropriate "
                        "subnets/security groups. Network mode cannot be changed "
                        "after creation; recreate the code interpreter with VPC "
                        "mode."
                    ),
                    reference=CODE_INTERPRETER_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )

        if interpreters_vpc and not interpreters_insecure:
            findings.append(
                create_finding(
                    check_id="AC-15",
                    finding_name=check_name,
                    finding_details=(
                        f"All {len(interpreters_vpc)} custom code interpreters use "
                        "VPC network mode"
                    ),
                    resolution="No action required",
                    reference=CODE_INTERPRETER_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                )
            )

        if interpreters_not_assessed:
            findings.append(
                _could_not_assess(
                    "Unable to describe the following custom code interpreters: "
                    f"{', '.join(interpreters_not_assessed)}. Their network mode "
                    "configuration was NOT assessed.",
                    "Grant bedrock-agentcore:GetCodeInterpreter to the assessment "
                    "role and re-run the assessment.",
                )
            )

    except Exception as e:
        logger.error(f"Error in code interpreter network mode check: {e}")
        findings.append(
            _could_not_assess(
                f"This check could not be completed (error: {str(e)}). Custom "
                "code interpreter network mode was NOT assessed.",
                "Verify the assessment role's bedrock-agentcore permissions, "
                "confirm the region supports AgentCore, and re-run the assessment.",
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
                reference=AGENTCORE_MEMORY_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    try:
        logger.info("Checking AgentCore Memory configuration")

        memories = _agentcore_list_all("list_memories", ["memories"])

        if not memories:
            logger.info("No Memory resources found")
            findings.append(
                create_finding(
                    check_id="AC-07",
                    finding_name="AgentCore Memory Configuration Check",
                    finding_details="No Memory resources found",
                    resolution="No action required",
                    reference=AGENTCORE_MEMORY_REFERENCE_URL,
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
                memory_details = _unwrap_agentcore_detail(
                    agentcore_client.get_memory(memoryId=memory_id), "memory"
                )

                # Check encryption configuration
                encryption_key_arn = memory_details.get(
                    "encryptionKeyArn"
                ) or memory_details.get("kmsKeyArn")

                if not encryption_key_arn:
                    findings.append(
                        create_finding(
                            check_id="AC-07",
                            finding_name="AgentCore Memory Encryption",
                            finding_details=f"Memory '{memory_name}' ({memory_id}) does not have customer-managed encryption configured",
                            resolution="Enable encryption with customer-managed KMS keys",
                            reference=AGENTCORE_MEMORY_REFERENCE_URL,
                            severity=SeverityEnum.MEDIUM,
                            status=StatusEnum.FAILED,
                        )
                    )

            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceNotFoundException":
                    logger.error(f"Error describing memory {memory_id}: {e}")

        # If no findings, return passed. One severity per control (severity
        # methodology section 3.4): BedrockAgentCore.3 is Medium, so the Passed
        # row carries the same Medium as the Failed row above.
        if not findings:
            findings.append(
                create_finding(
                    check_id="AC-07",
                    finding_name="AgentCore Memory Configuration Check",
                    finding_details=f"All {len(memories)} Memory resources have proper configuration",
                    resolution="No action required",
                    reference=AGENTCORE_MEMORY_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.PASSED,
                )
            )

    except Exception as e:
        logger.error(f"Error in memory configuration check: {e}")
        findings.append(
            could_not_assess_row(
                create_finding,
                "AC-07",
                "AgentCore Memory Configuration Check",
                e,
                AGENTCORE_MEMORY_REFERENCE_URL,
                SeverityEnum,
                StatusEnum,
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

    if agentcore_client is None:
        findings.append(
            create_finding(
                check_id="AC-08",
                finding_name="AgentCore VPC Endpoints Check",
                finding_details="AgentCore client not available in this region",
                resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/vpc.html",
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    try:
        logger.info("Checking for AgentCore VPC endpoints")

        runtimes_response = agentcore_client.list_agent_runtimes()
        runtimes = runtimes_response.get("agentRuntimes", [])

        if not runtimes:
            findings.append(
                create_finding(
                    check_id="AC-08",
                    finding_name="AgentCore VPC Endpoints Check",
                    finding_details="No AgentCore resources found",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/vpc.html",
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
            return findings

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
            could_not_assess_row(
                create_finding,
                "AC-08",
                "AgentCore VPC Endpoints Check",
                e,
                "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/vpc.html",
                SeverityEnum,
                StatusEnum,
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
            could_not_assess_row(
                create_finding,
                "AC-09",
                "AgentCore Service-Linked Role Check",
                e,
                "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-vpc.html",
                SeverityEnum,
                StatusEnum,
            )
        )

    return findings


def check_agentcore_resource_based_policies() -> List[Dict[str, Any]]:
    """
    Check for proper resource-based policies on AgentCore resources.

    Validates:
    - Agent Runtime resource policies
    - Gateway resource policies

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
        policy_access_denied = []
        policy_check_errors = []

        # Check Agent Runtimes
        try:
            runtimes = _agentcore_list_all("list_agent_runtimes", ["agentRuntimes"])

            for runtime in runtimes:
                runtime_id = runtime.get("agentRuntimeId", "unknown")
                runtime_name = runtime.get("agentRuntimeName", runtime_id)
                runtime_arn = runtime.get("agentRuntimeArn")

                try:
                    if not runtime_arn:
                        resources_without_rbp.append(
                            {"type": "Runtime", "name": runtime_name, "id": runtime_id}
                        )
                        continue

                    policy = _get_agentcore_resource_policy(runtime_arn)

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
                    elif _is_access_denied_client_error(e):
                        policy_access_denied.append(
                            {"type": "Runtime", "name": runtime_name, "id": runtime_id}
                        )
                    else:
                        policy_check_errors.append(
                            {
                                "type": "Runtime",
                                "name": runtime_name,
                                "id": runtime_id,
                                "error_code": e.response.get("Error", {}).get(
                                    "Code", "Unknown"
                                ),
                            }
                        )
                        logger.warning(
                            f"Error checking policy for runtime {runtime_id}: {e}"
                        )

        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                # Enumeration itself failed (e.g. AccessDenied) — re-raise so
                # the outer handler reports COULD_NOT_ASSESS rather than
                # silently proceeding as if there were zero runtimes to check.
                logger.warning(f"Error listing runtimes: {e}")
                raise

        # Check Gateways
        try:
            gateways = _agentcore_list_all("list_gateways", ["items", "gateways"])

            for gateway in gateways:
                gateway_id = gateway.get("gatewayId", "unknown")
                gateway_name = gateway.get("name", gateway_id)

                try:
                    gateway_details = agentcore_client.get_gateway(
                        gatewayIdentifier=gateway_id
                    )
                    gateway_arn = gateway_details.get("gatewayArn")

                    if not gateway_arn:
                        resources_without_rbp.append(
                            {"type": "Gateway", "name": gateway_name, "id": gateway_id}
                        )
                        continue

                    policy = _get_agentcore_resource_policy(gateway_arn)

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
                    elif _is_access_denied_client_error(e):
                        policy_access_denied.append(
                            {"type": "Gateway", "name": gateway_name, "id": gateway_id}
                        )
                    else:
                        policy_check_errors.append(
                            {
                                "type": "Gateway",
                                "name": gateway_name,
                                "id": gateway_id,
                                "error_code": e.response.get("Error", {}).get(
                                    "Code", "Unknown"
                                ),
                            }
                        )
                        logger.warning(
                            f"Error checking policy for gateway {gateway_id}: {e}"
                        )

        except AttributeError as e:
            # Gateway APIs are not present in this bedrock-agentcore-control
            # client version — a genuine NOT_APPLICABLE, not an access gap.
            logger.info(f"Gateway APIs not available: {e}")
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                # Enumeration itself failed (e.g. AccessDenied) — re-raise so
                # the outer handler reports COULD_NOT_ASSESS instead of
                # silently treating it the same as "Gateway APIs unavailable".
                logger.warning(f"Error listing gateways: {e}")
                raise

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

        if policy_access_denied:
            resource_list = ", ".join(
                [f"{r['type']} '{r['name']}'" for r in policy_access_denied[:5]]
            )
            if len(policy_access_denied) > 5:
                resource_list += f" and {len(policy_access_denied) - 5} more"

            findings.append(
                create_finding(
                    check_id="AC-10",
                    finding_name=f"{COULD_NOT_ASSESS_PREFIX}AgentCore Resource-Based Policies Check",
                    finding_details=(
                        f"Unable to assess resource-based policies for {resource_list} "
                        "because access to AgentCore resource policy metadata was denied. "
                        "This control was NOT assessed for these resources."
                    ),
                    resolution=(
                        "Ensure the assessment role can call "
                        "bedrock-agentcore:GetResourcePolicy for AgentCore resources, "
                        "then re-run the assessment."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security_iam_service-with-iam.html",
                    severity=SeverityEnum.LOW,
                    status=StatusEnum.NA,
                )
            )

        if policy_check_errors:
            resource_list = ", ".join(
                [f"{r['type']} '{r['name']}'" for r in policy_check_errors[:5]]
            )
            if len(policy_check_errors) > 5:
                resource_list += f" and {len(policy_check_errors) - 5} more"

            error_codes = sorted({r["error_code"] for r in policy_check_errors})
            findings.append(
                create_finding(
                    check_id="AC-10",
                    finding_name=f"{COULD_NOT_ASSESS_PREFIX}AgentCore Resource-Based Policies Check",
                    finding_details=(
                        f"Unable to fully assess resource-based policies for {resource_list} "
                        f"due to AgentCore API errors: {', '.join(error_codes)}. This control "
                        "was NOT assessed for these resources."
                    ),
                    resolution=(
                        "Re-run the assessment. If the issue persists, review AgentCore "
                        "service health and the assessment role's control plane permissions."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security_iam_service-with-iam.html",
                    severity=SeverityEnum.LOW,
                    status=StatusEnum.NA,
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
            could_not_assess_row(
                create_finding,
                "AC-10",
                "AgentCore Resource-Based Policies Check",
                e,
                "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security_iam_service-with-iam.html",
                SeverityEnum,
                StatusEnum,
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
            policy_engines = _agentcore_list_all(
                "list_policy_engines", ["policyEngines"]
            )

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
            could_not_assess_row(
                create_finding,
                "AC-11",
                "AgentCore Policy Engine Encryption Check",
                e,
                "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-encryption.html",
                SeverityEnum,
                StatusEnum,
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
            gateways = _agentcore_list_all("list_gateways", ["items", "gateways"])

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
                    gateway_details = agentcore_client.get_gateway(
                        gatewayIdentifier=gateway_id
                    )

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
                        # BedrockAgentCore.4 is Medium severity in Security Hub.
                        # One severity applies to every Passed/Failed row of a
                        # control (severity methodology §3.4/Rule 2); this
                        # previously emitted LOW on the Failed path while the
                        # Passed path below used MEDIUM.
                        severity=SeverityEnum.MEDIUM,
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
            could_not_assess_row(
                create_finding,
                "AC-12",
                "AgentCore Gateway Encryption Check",
                e,
                "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-encryption.html",
                SeverityEnum,
                StatusEnum,
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
                reference=AGENTCORE_GATEWAY_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        )
        return findings

    try:
        logger.info("Checking AgentCore Gateway configuration")

        # Try to list gateways - this API may not exist yet
        try:
            gateways = _agentcore_list_all("list_gateways", ["items", "gateways"])

            if not gateways:
                logger.info("No Gateway resources found")
                findings.append(
                    create_finding(
                        check_id="AC-13",
                        finding_name="AgentCore Gateway Configuration Check",
                        finding_details="No Gateway resources found",
                        resolution="No action required",
                        reference=AGENTCORE_GATEWAY_REFERENCE_URL,
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
                    reference=AGENTCORE_GATEWAY_REFERENCE_URL,
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
                    reference=AGENTCORE_GATEWAY_REFERENCE_URL,
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
                        reference=AGENTCORE_GATEWAY_REFERENCE_URL,
                        severity=SeverityEnum.INFORMATIONAL,
                        status=StatusEnum.NA,
                    )
                )
            else:
                raise

    except Exception as e:
        logger.error(f"Error in gateway configuration check: {e}")
        findings.append(
            could_not_assess_row(
                create_finding,
                "AC-13",
                "AgentCore Gateway Configuration Check",
                e,
                AGENTCORE_GATEWAY_REFERENCE_URL,
                SeverityEnum,
                StatusEnum,
            )
        )

    return findings


def check_agentcore_gateway_agentic_security() -> List[Dict[str, Any]]:
    """
    Check API-provable AgentCore Gateway controls for agentic tool execution.

    Validates:
    - Inbound gateway authorization is enabled
    - Policy engine is attached in ENFORCE mode
    - Debug exception detail is not exposed
    - AWS WAF web ACL is associated
    """
    findings = []

    if agentcore_client is None:
        for check_id, finding_name in [
            ("AG-24", "Agentic AI Gateway Inbound Authorization"),
            ("AG-25", "Agentic AI Gateway Tool Policy Enforcement"),
            ("AG-26", "Agentic AI Gateway Error Detail Exposure"),
            ("AG-27", "Agentic AI Gateway WAF Protection"),
        ]:
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name=finding_name,
                    finding_details="AgentCore client not available in this region",
                    resolution="Deploy in a region where Amazon Bedrock AgentCore is available",
                    reference=AGENTIC_AI_LENS_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                )
            )
        return findings

    try:
        gateways = _agentcore_list_all("list_gateways", ["items", "gateways"])
    except AttributeError:
        return [
            create_finding(
                check_id="AG-24",
                finding_name="Agentic AI Gateway Security Controls",
                finding_details="Gateway APIs not yet available in bedrock-agentcore-control client",
                resolution="Upgrade the AWS SDK/runtime when AgentCore Gateway APIs are available",
                reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            )
        ]
    except ClientError as e:
        if _is_access_denied_client_error(e):
            # COULD_NOT_ASSESS disposition (severity methodology §3.4): the
            # check could not run, so report an unknown state (N/A, Low)
            # rather than the previous Informational, which understated an
            # access gap as "no issue."
            return [
                could_not_assess_row(
                    create_finding,
                    "AG-24",
                    "Agentic AI Gateway Security Controls",
                    f"Unable to list AgentCore Gateways: {str(e)}. Gateway "
                    "inbound authorization, tool policy enforcement, error "
                    "detail exposure, and WAF protection were NOT assessed.",
                    AGENTCORE_GATEWAY_API_REFERENCE_URL,
                    SeverityEnum,
                    StatusEnum,
                )
            ]
        return [
            could_not_assess_row(
                create_finding,
                "AG-24",
                "Agentic AI Gateway Security Controls",
                e,
                AGENTCORE_GATEWAY_API_REFERENCE_URL,
                SeverityEnum,
                StatusEnum,
            )
        ]

    if not gateways:
        return [
            create_finding(
                check_id="AG-24",
                finding_name="Agentic AI Gateway Inbound Authorization",
                finding_details="No AgentCore Gateways found",
                resolution="No action required",
                reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            ),
            create_finding(
                check_id="AG-25",
                finding_name="Agentic AI Gateway Tool Policy Enforcement",
                finding_details="No AgentCore Gateways found",
                resolution="No action required",
                reference=AGENTCORE_POLICY_ENGINE_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            ),
            create_finding(
                check_id="AG-26",
                finding_name="Agentic AI Gateway Error Detail Exposure",
                finding_details="No AgentCore Gateways found",
                resolution="No action required",
                reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            ),
            create_finding(
                check_id="AG-27",
                finding_name="Agentic AI Gateway WAF Protection",
                finding_details="No AgentCore Gateways found",
                resolution="No action required",
                reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
            ),
        ]

    for gateway in gateways:
        gateway_id = gateway.get("gatewayId", "unknown")
        gateway_name = gateway.get("name", gateway_id)

        try:
            gateway_details = agentcore_client.get_gateway(gatewayIdentifier=gateway_id)
        except ClientError as e:
            findings.append(
                could_not_assess_row(
                    create_finding,
                    "AG-24",
                    f"Agentic AI Gateway Security Controls for '{gateway_name}' ({gateway_id})",
                    e,
                    AGENTCORE_GATEWAY_API_REFERENCE_URL,
                    SeverityEnum,
                    StatusEnum,
                )
            )
            continue

        authorizer_type = gateway_details.get("authorizerType") or gateway.get(
            "authorizerType"
        )
        policy_engine_config = gateway_details.get("policyEngineConfiguration") or {}
        policy_engine_mode = policy_engine_config.get("mode")
        policy_engine_arn = policy_engine_config.get("arn")

        if authorizer_type in {"AWS_IAM", "CUSTOM_JWT"}:
            findings.append(
                create_finding(
                    check_id="AG-24",
                    finding_name="Agentic AI Gateway Inbound Authorization",
                    finding_details=f"Gateway '{gateway_name}' ({gateway_id}) uses authorizerType {authorizer_type}.",
                    resolution="No action required",
                    reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                )
            )
        elif (
            authorizer_type == "AUTHENTICATE_ONLY"
            and policy_engine_mode == "ENFORCE"
            and policy_engine_arn
        ):
            findings.append(
                create_finding(
                    check_id="AG-24",
                    finding_name="Agentic AI Gateway Inbound Authorization",
                    finding_details=f"Gateway '{gateway_name}' ({gateway_id}) uses authorizerType AUTHENTICATE_ONLY and delegates authorization to policy engine {policy_engine_arn} in ENFORCE mode.",
                    resolution="No action required. Continue validating policy coverage for all exposed gateway targets.",
                    reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                )
            )
        elif authorizer_type == "AUTHENTICATE_ONLY":
            findings.append(
                create_finding(
                    check_id="AG-24",
                    finding_name="Agentic AI Gateway Authenticate-Only Authorization",
                    finding_details=f"Gateway '{gateway_name}' ({gateway_id}) uses authorizerType AUTHENTICATE_ONLY without an attached policy engine in ENFORCE mode. AgentCore Gateway authenticates the SigV4 caller but does not make an authorization decision for this authorizer type.",
                    resolution="Use AWS_IAM or CUSTOM_JWT for gateway-enforced authorization, or attach an AgentCore policy engine in ENFORCE mode before using AUTHENTICATE_ONLY.",
                    reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )
        else:
            findings.append(
                create_finding(
                    check_id="AG-24",
                    finding_name="Agentic AI Gateway Inbound Authorization Disabled",
                    finding_details=f"Gateway '{gateway_name}' ({gateway_id}) uses authorizerType {authorizer_type or 'unspecified'}. Agent tool endpoints must use an explicit gateway authorizer.",
                    resolution="Configure the gateway authorizerType as AWS_IAM or CUSTOM_JWT and provide the required authorizer configuration.",
                    reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )

        if not policy_engine_config:
            findings.append(
                create_finding(
                    check_id="AG-25",
                    finding_name="Agentic AI Gateway Tool Policy Enforcement Missing",
                    finding_details=f"Gateway '{gateway_name}' ({gateway_id}) does not have a policy engine configuration. Tool calls are not evaluated by AgentCore policy enforcement.",
                    resolution="Attach an AgentCore policy engine to the gateway and use ENFORCE mode for production tool authorization.",
                    reference=AGENTCORE_POLICY_ENGINE_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )
        elif policy_engine_mode != "ENFORCE":
            findings.append(
                create_finding(
                    check_id="AG-25",
                    finding_name="Agentic AI Gateway Tool Policy Not Enforced",
                    finding_details=f"Gateway '{gateway_name}' ({gateway_id}) policy engine {policy_engine_arn or 'unknown'} is in {policy_engine_mode or 'unknown'} mode. LOG_ONLY mode records decisions but does not block denied tool calls.",
                    resolution="Change the gateway policyEngineConfiguration mode to ENFORCE after validating policies in LOG_ONLY mode.",
                    reference=AGENTCORE_POLICY_ENGINE_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                )
            )
        else:
            findings.append(
                create_finding(
                    check_id="AG-25",
                    finding_name="Agentic AI Gateway Tool Policy Enforcement",
                    finding_details=f"Gateway '{gateway_name}' ({gateway_id}) has policy engine {policy_engine_arn or 'unknown'} in ENFORCE mode.",
                    resolution="No action required",
                    reference=AGENTCORE_POLICY_ENGINE_REFERENCE_URL,
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.PASSED,
                )
            )

        if gateway_details.get("exceptionLevel") == "DEBUG":
            findings.append(
                create_finding(
                    check_id="AG-26",
                    finding_name="Agentic AI Gateway Debug Error Detail Enabled",
                    finding_details=f"Gateway '{gateway_name}' ({gateway_id}) returns DEBUG-level exception detail. Detailed errors can disclose tool, target, or policy implementation details to callers.",
                    resolution="Remove DEBUG exceptionLevel for production gateways so callers receive generic gateway errors.",
                    reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                )
            )
        else:
            findings.append(
                create_finding(
                    check_id="AG-26",
                    finding_name="Agentic AI Gateway Error Detail Exposure",
                    finding_details=f"Gateway '{gateway_name}' ({gateway_id}) does not expose DEBUG-level exception detail.",
                    resolution="No action required",
                    reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.PASSED,
                )
            )

        web_acl_arn = gateway_details.get("webAclArn")
        if web_acl_arn:
            findings.append(
                create_finding(
                    check_id="AG-27",
                    finding_name="Agentic AI Gateway WAF Protection",
                    finding_details=f"Gateway '{gateway_name}' ({gateway_id}) is associated with WAF web ACL {web_acl_arn}.",
                    resolution="No action required",
                    reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                    severity=SeverityEnum.LOW,
                    status=StatusEnum.PASSED,
                )
            )
        else:
            findings.append(
                create_finding(
                    check_id="AG-27",
                    finding_name="Agentic AI Gateway WAF Protection Missing",
                    finding_details=f"Gateway '{gateway_name}' ({gateway_id}) is not associated with an AWS WAF web ACL.",
                    resolution="Associate an AWS WAF web ACL with internet-facing AgentCore gateways to add request filtering and abuse protection.",
                    reference=AGENTCORE_GATEWAY_API_REFERENCE_URL,
                    severity=SeverityEnum.LOW,
                    status=StatusEnum.FAILED,
                )
            )

    return findings


def lambda_handler(event, context):
    """
    Lambda handler for AgentCore security assessment.

    Args:
        event: Lambda event containing execution_id and Region
        context: Lambda context

    Returns:
        Response with status and S3 URL
    """
    global start_time, iam_client, ec2_client, ecr_client, logs_client
    global xray_client, cloudwatch_client, agentcore_client
    start_time = time.time()

    try:
        # Extract target region from Step Functions Map state
        region = event.get("Region", os.environ.get("AWS_REGION", "us-east-1"))
        # IAM is global: only the primary region (Map index 0) runs IAM-only checks.
        is_primary_region = int(event.get("RegionIndex", 0)) == 0
        logger.info(f"Scanning region: {region} (primary={is_primary_region})")

        execution_id = event.get("Execution", {}).get("Name", "unknown")

        # Initialize regional clients (iam is global, the rest are region-scoped)
        iam_client = boto3.client("iam", config=boto3_config)
        ec2_client = boto3.client("ec2", config=boto3_config, region_name=region)
        ecr_client = boto3.client("ecr", config=boto3_config, region_name=region)
        logs_client = boto3.client("logs", config=boto3_config, region_name=region)
        xray_client = boto3.client("xray", config=boto3_config, region_name=region)
        cloudwatch_client = boto3.client(
            "cloudwatch", config=boto3_config, region_name=region
        )

        # Collect all findings
        all_findings = []

        # Retrieve permission cache (shared/global IAM data)
        try:
            permission_cache = get_permissions_cache(execution_id)
        except Exception as e:
            logger.warning(f"Failed to retrieve permission cache: {e}")
            permission_cache = {"role_permissions": [], "user_permissions": []}

        # Run global IAM-only checks once (on the primary region) so the same role
        # violations are not reported once per scanned region. These run before the
        # regional availability gate so they are still emitted even if AgentCore is
        # not available in the primary region.
        if is_primary_region:
            global_checks = [
                (
                    "IAM Full Access",
                    lambda: check_agentcore_full_access_roles(permission_cache),
                ),
                (
                    "Stale Access",
                    lambda: check_stale_agentcore_access(permission_cache),
                ),
                # AC-09 inspects a global IAM service-linked role, so it is also
                # run once on the primary region rather than per scanned region.
                ("Service-Linked Role", check_agentcore_service_linked_role),
            ]
            for check_name, check_func in global_checks:
                try:
                    logger.info(f"Running global check: {check_name}")
                    global_findings = check_func()
                    for finding in global_findings:
                        finding["Region"] = GLOBAL_REGION_LABEL
                    all_findings.extend(global_findings)
                except Exception as e:
                    logger.error(f"Error in global check '{check_name}': {e}")
                    error_finding = could_not_assess_row(
                        create_finding,
                        "AC-00",
                        f"AgentCore {check_name} Check",
                        e,
                        AGENTCORE_STARTER_TOOLKIT_URL,
                        SeverityEnum,
                        StatusEnum,
                    )
                    error_finding["Region"] = GLOBAL_REGION_LABEL
                    all_findings.append(error_finding)

        # Reset per-invocation so a warm container cannot leak a previous
        # region's client if creation below fails.
        agentcore_client = None
        try:
            agentcore_client = boto3.client(
                "bedrock-agentcore-control", config=boto3_config, region_name=region
            )
        except Exception as e:
            # The client could not even be constructed (e.g. the SDK in this
            # runtime does not know the service). This is the one case where the
            # region genuinely cannot be assessed.
            logger.warning(
                f"Failed to initialize bedrock-agentcore-control client: {e}"
            )
            agentcore_client = None

        if agentcore_client is not None:
            # Test service availability with a lightweight call
            try:
                agentcore_client.list_agent_runtimes(maxResults=1)
                logger.info("Successfully initialized bedrock-agentcore-control client")
            except EndpointConnectionError:
                logger.info(
                    f"AgentCore service not available in region {region}, skipping"
                )
                agentcore_client = None
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code in REGION_UNAVAILABLE_ERROR_CODES:
                    logger.info(
                        f"AgentCore not accessible in region {region} ({error_code}), skipping"
                    )
                    agentcore_client = None
                else:
                    # Service is reachable but returned another API error (e.g. access
                    # denied) — proceed; individual checks handle their own errors.
                    logger.info(
                        f"AgentCore client initialized (probe returned {error_code})"
                    )
            except Exception as e:
                # An unexpected probe failure (e.g. a boto3/botocore SDK param or
                # operation mismatch such as ParamValidationError/AttributeError)
                # says nothing about regional availability. Treating it as "not
                # available" would silently skip every AgentCore check and emit a
                # false N/A report, so keep the client and let the individual
                # checks surface their own errors instead.
                logger.warning(
                    f"AgentCore availability probe raised an unexpected error, "
                    f"proceeding with checks: {e}"
                )

        # If AgentCore not available, produce an N/A report (plus any global IAM
        # findings already collected on the primary region) and exit early
        if agentcore_client is None:
            all_findings.append(
                create_finding(
                    check_id="AC-00",
                    finding_name="AgentCore Service Availability",
                    finding_details=f"Amazon Bedrock AgentCore is not available in region {region}. No checks performed.",
                    resolution="No action required. AgentCore is not deployed in this region.",
                    reference=AGENTCORE_STARTER_TOOLKIT_URL,
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.NA,
                    region=region,
                )
            )
            for finding in all_findings:
                if not finding.get("Region"):
                    finding["Region"] = region
            all_findings.extend(check_agentcore_gateway_agentic_security())
            all_findings.extend(build_agentic_agentcore_security_findings(all_findings))
            all_findings.extend(
                build_agentic_agentcore_unavailable_findings(region, all_findings)
            )
            for finding in all_findings:
                if not finding.get("Region"):
                    finding["Region"] = region
            csv_content = generate_csv_report(all_findings)
            s3_url = write_to_s3(execution_id, csv_content, BUCKET_NAME, region=region)
            return {
                "statusCode": 200,
                "body": json.dumps(
                    {
                        "message": f"AgentCore not available in {region}",
                        "s3_url": s3_url,
                    }
                ),
            }

        logger.info(
            f"Starting AgentCore security assessment for execution: {execution_id}"
        )

        # Execute regional assessment checks (IAM-only checks AC-02/AC-03 and the
        # global service-linked role check AC-09 are run separately, once, on the
        # primary region above)
        checks = [
            ("VPC Configuration", check_agentcore_vpc_configuration),
            ("Observability", check_agentcore_observability),
            ("Encryption", check_agentcore_encryption),
            ("Browser Tool Recording", check_browser_tool_recording),
            ("Browser Network Mode", check_browser_network_mode),
            ("Code Interpreter Network Mode", check_code_interpreter_network_mode),
            ("Memory Configuration", check_agentcore_memory_configuration),
            ("Gateway Configuration", check_agentcore_gateway_configuration),
            ("VPC Endpoints", check_agentcore_vpc_endpoints),
            ("Resource-Based Policies", check_agentcore_resource_based_policies),
            ("Policy Engine Encryption", check_agentcore_policy_engine_encryption),
            ("Gateway Encryption", check_agentcore_gateway_encryption),
            ("Agentic Gateway Security", check_agentcore_gateway_agentic_security),
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
                error_finding = could_not_assess_row(
                    create_finding,
                    "AC-00",
                    f"AgentCore {check_name} Check",
                    e,
                    AGENTCORE_STARTER_TOOLKIT_URL,
                    SeverityEnum,
                    StatusEnum,
                )
                error_finding["Region"] = region
                all_findings.append(error_finding)

        # Inject region into all findings that don't have it set
        for finding in all_findings:
            if not finding.get("Region"):
                finding["Region"] = region

        logger.info("Building Agentic AI Security findings from AgentCore results")
        all_findings.extend(build_agentic_agentcore_security_findings(all_findings))
        for finding in all_findings:
            if not finding.get("Region"):
                finding["Region"] = region

        # Generate CSV report
        logger.info(f"Generating CSV report with {len(all_findings)} total findings")
        csv_content = generate_csv_report(all_findings)

        # Upload to S3
        s3_url = write_to_s3(execution_id, csv_content, BUCKET_NAME, region=region)

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
