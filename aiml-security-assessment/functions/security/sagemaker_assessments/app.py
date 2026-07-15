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

# TO DO PYDANTIC SUPPORT
from schema import create_finding
from severity_disposition import could_not_assess_row

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
# (e.g. the SM-02 full-access and stale-access checks) are identical across
# regions, so they are produced only on the primary region (Map index 0) and
# tagged with this region label to avoid duplicate findings when scanning
# multiple regions.
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


def check_sagemaker_internet_access(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker notebook instances have direct internet access.

    Aligns with AWS Security Hub control SageMaker.1 (severity High), whose
    scope is NotebookInstance only. The domain network-access-type check
    (repo-specific hardening, no SageMaker.1 mapping) is a separate check —
    check_sagemaker_domain_network_access — so domain findings are not
    surfaced under the SageMaker.1 label.
    """
    logger.debug("Starting check for SageMaker direct internet access")
    try:
        findings = {"csv_data": []}

        instances_with_direct_access = []
        total_resources_checked = 0

        # Create SageMaker client
        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        # Check Notebook Instances
        try:
            paginator = sagemaker_client.get_paginator("list_notebook_instances")
            for page in paginator.paginate():
                for instance in page.get("NotebookInstances", []):
                    instance_name = instance.get("NotebookInstanceName")
                    if instance_name:
                        # Get detailed information about the notebook instance
                        instance_details = sagemaker_client.describe_notebook_instance(
                            NotebookInstanceName=instance_name
                        )

                        # Check if direct internet access is enabled
                        if instance_details.get("DirectInternetAccess") == "Enabled":
                            instances_with_direct_access.append(
                                {
                                    "name": instance_name,
                                    "subnet_id": instance_details.get(
                                        "SubnetId", "N/A"
                                    ),
                                    "vpc_id": instance_details.get("VpcId", "N/A"),
                                }
                            )
                        total_resources_checked += 1
        except Exception as e:
            logger.error(f"Error checking notebook instances: {str(e)}")
            raise

        # Generate findings
        if instances_with_direct_access:
            for instance in instances_with_direct_access:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-01",
                        finding_name="Direct Internet Access Enabled",
                        finding_details=f"SageMaker notebook instance '{instance['name']}' has direct internet access enabled",
                        resolution="Configure the notebook instance to use VPC connectivity and disable direct internet access",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/infrastructure-security.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if total_resources_checked > 0:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-01",
                        finding_name="SageMaker Internet Access Check",
                        finding_details="All SageMaker notebook instances are properly configured to use VPC connectivity",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/infrastructure-security.html",
                        severity="High",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-01",
                        finding_name="SageMaker Internet Access Check",
                        finding_details="No SageMaker notebook instances found to check",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/infrastructure-security.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_internet_access: {str(e)}", exc_info=True
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-01",
                    "SageMaker Internet Access Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_domain_network_access(region: str = "") -> Dict[str, Any]:
    """
    Repo-specific hardening check (no direct Security Hub control mapping)
    verifying SageMaker Domains use VpcOnly network access. Split out from
    the former combined SM-01 check, which surfaced domain findings under
    the SageMaker.1 label even though that control's scope is
    NotebookInstance only.
    """
    logger.debug("Starting check for SageMaker domain network access type")
    try:
        findings = {"csv_data": []}

        domains_with_direct_access = []
        total_domains_checked = 0

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        try:
            paginator = sagemaker_client.get_paginator("list_domains")
            for page in paginator.paginate():
                for domain in page.get("Domains", []):
                    domain_id = domain.get("DomainId")
                    if domain_id:
                        domain_details = sagemaker_client.describe_domain(
                            DomainId=domain_id
                        )
                        total_domains_checked += 1

                        vpc_id = domain_details.get("DomainSettings", {}).get(
                            "SecurityGroupIds", ["N/A"]
                        )[0]
                        domain_name = domain_details.get("DomainName", "N/A")

                        if domain_details.get("AppNetworkAccessType") != "VpcOnly":
                            domains_with_direct_access.append(
                                {
                                    "domain_id": domain_id,
                                    "name": domain_name,
                                    "vpc_id": vpc_id,
                                }
                            )
        except Exception as e:
            logger.error(f"Error checking domains: {str(e)}")
            raise

        if domains_with_direct_access:
            for domain in domains_with_direct_access:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-27",
                        finding_name="Non-VPC Only Network Access",
                        finding_details=f"SageMaker domain '{domain['domain_id']}' ({domain['name']}) is not configured for VPC-only access",
                        resolution="Configure the SageMaker domain to use VPC-only network access type",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/infrastructure-security.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if total_domains_checked > 0:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-27",
                        finding_name="SageMaker Domain Network Access Check",
                        finding_details=f"All {total_domains_checked} SageMaker domains are configured for VPC-only access",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/infrastructure-security.html",
                        severity="High",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-27",
                        finding_name="SageMaker Domain Network Access Check",
                        finding_details="No SageMaker domains found to check",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/infrastructure-security.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_domain_network_access: {str(e)}", exc_info=True
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-27",
                    "SageMaker Domain Network Access Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_guardduty_enabled(region: str = "") -> Dict[str, Any]:
    """
    Check if GuardDuty is enabled in the account to monitor SageMaker security issues

    Returns:
        Dict[str, Any]: Finding details including status and recommendations
    """
    findings = {
        "check_name": "GuardDuty Enablement Check",
        "status": "PASS",
        "details": "",
        "csv_data": [],
    }

    try:
        guardduty_client = boto3.client(
            "guardduty", config=boto3_config, region_name=region
        )

        # Get list of detectors in the current region
        detectors = guardduty_client.list_detectors()

        if not detectors.get("DetectorIds"):
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-04",
                    finding_name="GuardDuty Not Enabled",
                    finding_details="Amazon GuardDuty is not enabled in this account. GuardDuty can help detect security threats in SageMaker workloads.",
                    resolution="Enable Amazon GuardDuty to monitor for potential security threats in your SageMaker environment, including anomalous model access patterns and potential data exfiltration attempts.",
                    reference="https://docs.aws.amazon.com/guardduty/latest/ug/ai-protection.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-04",
                    finding_name="GuardDuty Enabled",
                    finding_details="Amazon GuardDuty is properly enabled and monitoring for security threats in SageMaker workloads.",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/guardduty/latest/ug/ai-protection.html",
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )
    except ClientError as e:
        findings["csv_data"].append(
            could_not_assess_row(
                create_finding,
                "SM-04",
                "GuardDuty Check",
                e,
                "https://docs.aws.amazon.com/guardduty/latest/ug/security-iam.html",
                region=region,
            )
        )
    except Exception as e:
        findings["csv_data"].append(
            could_not_assess_row(
                create_finding,
                "SM-04",
                "GuardDuty Check",
                e,
                "https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html",
                region=region,
            )
        )

    return findings


def check_sagemaker_iam_permissions(
    permission_cache, region: str = ""
) -> Dict[str, Any]:
    """
    Check SageMaker IAM permissions and stale access.

    These checks are derived purely from IAM (a global service) and the cached
    permissions, so they produce identical results in every region. The handler
    runs this check once, on the primary region, tagged with GLOBAL_REGION_LABEL.
    Regional SSO/domain configuration is checked separately by
    check_sagemaker_sso_configuration.
    """
    logger.debug("Starting check for SageMaker IAM permissions")
    try:
        findings = {"csv_data": []}

        # Check for roles with SageMaker full access
        roles_with_full_access = []
        for role_name, permissions in permission_cache["role_permissions"].items():
            for policy in permissions["attached_policies"]:
                if policy["name"] == "AmazonSageMakerFullAccess":
                    roles_with_full_access.append(role_name)
                    break

        # Check for stale access. IAM is a global service, so the client is not
        # region-scoped (region is used only for finding tags).
        stale_users = []
        iam_client = boto3.client("iam", config=boto3_config)
        two_months_ago = datetime.now(timezone.utc) - timedelta(days=60)

        # Check users' last access to SageMaker
        for user_name, permissions in permission_cache["user_permissions"].items():
            has_sagemaker_access = False
            for policy in (
                permissions["attached_policies"] + permissions["inline_policies"]
            ):
                if has_sagemaker_permissions(policy["document"]):
                    has_sagemaker_access = True
                    break

            if has_sagemaker_access:
                try:
                    response = iam_client.generate_service_last_accessed_details(
                        Arn=f"arn:aws:iam::{get_account_id()}:user/{user_name}"
                    )
                    job_id = response["JobId"]

                    # Wait for job completion
                    waiter_time = 0
                    while waiter_time < 10:
                        details = iam_client.get_service_last_accessed_details(
                            JobId=job_id
                        )
                        if details["JobStatus"] == "COMPLETED":
                            for service in details["ServicesLastAccessed"]:
                                if service["ServiceName"] == "Amazon SageMaker":
                                    last_accessed = service.get("LastAuthenticated")
                                    if last_accessed and last_accessed < two_months_ago:
                                        stale_users.append(
                                            {
                                                "name": user_name,
                                                "last_accessed": last_accessed,
                                            }
                                        )
                            break
                        time.sleep(1)  # nosemgrep: arbitrary-sleep
                        waiter_time += 1
                except Exception as e:
                    logger.error(
                        f"Error checking last access for user {user_name}: {str(e)}"
                    )

        # Generate findings
        if roles_with_full_access or stale_users:
            # Findings for full access roles
            if roles_with_full_access:
                for role_name in roles_with_full_access:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="SM-02",
                            finding_name="SageMaker Full Access Policy Used",
                            finding_details=f"Role '{role_name}' has AmazonSageMakerFullAccess policy attached",
                            resolution="Replace AmazonSageMakerFullAccess with more restrictive custom policies that follow the principle of least privilege",
                            reference="https://docs.aws.amazon.com/sagemaker-unified-studio/latest/adminguide/security-iam.html",
                            severity="High",
                            status="Failed",
                            region=region,
                        )
                    )

            # Findings for stale users
            if stale_users:
                for user in stale_users:
                    findings["csv_data"].append(
                        create_finding(
                            check_id="SM-02",
                            finding_name="Stale SageMaker Access",
                            finding_details=f"User '{user['name']}' hasn't accessed SageMaker since {user['last_accessed'].strftime('%Y-%m-%d')}",
                            resolution="Review and remove SageMaker access for inactive users",
                            reference="https://docs.aws.amazon.com/sagemaker-unified-studio/latest/adminguide/security-iam.html",
                            severity="Medium",
                            status="Failed",
                            region=region,
                        )
                    )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-02",
                    finding_name="SageMaker IAM Permissions Check",
                    finding_details="No issues found with IAM permissions and no stale access detected",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker-unified-studio/latest/adminguide/security-iam.html",
                    severity="High",
                    status="Passed",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_iam_permissions: {str(e)}", exc_info=True
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-02",
                    "SageMaker IAM Permissions Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker-unified-studio/latest/adminguide/security-iam.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_sso_configuration(region: str = "") -> Dict[str, Any]:
    """
    Check SageMaker domain SSO / IAM Identity Center configuration.

    SageMaker domains are regional resources, so this check runs once per
    scanned region (unlike the IAM-global checks in
    check_sagemaker_iam_permissions).
    """
    logger.debug("Starting check for SageMaker SSO configuration")
    try:
        findings = {"csv_data": []}

        domains_without_sso = []
        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )
        paginator = sagemaker_client.get_paginator("list_domains")

        for page in paginator.paginate():
            for domain in page["Domains"]:
                domain_id = domain["DomainId"]
                try:
                    domain_details = sagemaker_client.describe_domain(
                        DomainId=domain_id
                    )

                    # Check authentication mode
                    auth_mode = domain_details.get("AuthMode", "")
                    if auth_mode != "SSO":
                        domains_without_sso.append(
                            {
                                "domain_id": domain_id,
                                "domain_name": domain_details.get("DomainName", "N/A"),
                                "auth_mode": auth_mode,
                            }
                        )

                    # Check if SSO is properly configured with Identity Center
                    if auth_mode == "SSO":
                        identity_store_id = domain_details.get("IdentityStoreId")

                        if not identity_store_id:
                            domains_without_sso.append(
                                {
                                    "domain_id": domain_id,
                                    "domain_name": domain_details.get(
                                        "DomainName", "N/A"
                                    ),
                                    "auth_mode": "SSO (Incomplete Configuration)",
                                }
                            )

                except Exception as domain_error:
                    logger.error(
                        f"Error checking domain {domain_id}: {str(domain_error)}"
                    )

        if domains_without_sso:
            for domain in domains_without_sso:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-02",
                        finding_name="SSO Not Properly Configured",
                        finding_details=(
                            f"SageMaker domain '{domain['domain_id']}' ({domain['domain_name']}) "
                            f"is using authentication mode: {domain['auth_mode']}"
                        ),
                        resolution=(
                            "Enable and properly configure AWS IAM Identity Center (successor to AWS SSO) "
                            "for centralized access management. Ensure Identity Store ID is configured."
                        ),
                        reference="https://aws.amazon.com/blogs/machine-learning/team-and-user-management-with-amazon-sagemaker-and-aws-sso/",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-02",
                    finding_name="SageMaker SSO Configuration Check",
                    finding_details="No SageMaker domains found, or all domains use SSO with IAM Identity Center configured",
                    resolution="No action required",
                    reference="https://aws.amazon.com/blogs/machine-learning/team-and-user-management-with-amazon-sagemaker-and-aws-sso/",
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_sso_configuration: {str(e)}", exc_info=True
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-02",
                    "SageMaker SSO Configuration Check",
                    e,
                    "https://aws.amazon.com/blogs/machine-learning/team-and-user-management-with-amazon-sagemaker-and-aws-sso/",
                    region=region,
                )
            ]
        }


def has_sagemaker_permissions(policy_doc: Dict) -> bool:
    """
    Check if a policy document contains SageMaker permissions
    """
    try:
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
                if "sagemaker" in action.lower():
                    return True
        return False
    except Exception as e:
        logger.error(f"Error parsing policy document: {str(e)}")
        return False


def get_account_id() -> str:
    """
    Get current AWS account ID
    """
    try:
        sts_client = boto3.client("sts")
        return sts_client.get_caller_identity()["Account"]
    except Exception as e:
        logger.error(f"Error getting account ID: {str(e)}")
        raise


def check_sagemaker_notebook_storage_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker notebook instance storage volumes are encrypted with a
    KMS key.

    Aligns with AWS Security Hub control SageMaker.21 (severity Medium):
    the control requires a customer-managed KMS key for notebook storage.
    Detection uses presence-as-proxy (Correctness Rule 1) — the KmsKeyId
    field only holds a value when the customer configured one, so absence
    is the practical "no customer-managed key" signal. This intentionally
    does NOT try to distinguish an AWS-managed key from a customer-managed
    one by string-matching the key id/ARN (e.g. checking for the substring
    "aws/sagemaker"): that substring test misses AWS-managed keys referenced
    by key id or ARN and can produce a false PASS on an encryption control.
    Domain and training-job encryption were previously bundled into this
    check under the SM-03 label; they are repo-specific hardening checks
    with no SageMaker.21 mapping and have moved to
    check_sagemaker_domain_and_training_job_encryption (SM-26).
    """
    logger.debug("Starting check for SageMaker notebook storage encryption")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        notebooks_without_kms = []
        notebooks_with_kms = []

        try:
            paginator = sagemaker_client.get_paginator("list_notebook_instances")
            for page in paginator.paginate():
                for instance in page.get("NotebookInstances", []):
                    instance_name = instance.get("NotebookInstanceName")
                    if instance_name:
                        instance_details = sagemaker_client.describe_notebook_instance(
                            NotebookInstanceName=instance_name
                        )

                        if instance_details.get("KmsKeyId"):
                            notebooks_with_kms.append(instance_name)
                        else:
                            notebooks_without_kms.append(instance_name)
        except Exception as e:
            logger.error(f"Error checking notebook instances encryption: {str(e)}")
            raise

        if notebooks_without_kms:
            for notebook_name in notebooks_without_kms:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-03",
                        finding_name="SageMaker Notebook Storage Encryption Missing",
                        finding_details=f"Notebook instance '{notebook_name}' does not have a customer-managed KMS key configured for storage volume encryption.",
                        resolution="Configure a customer-managed KMS key (KmsKeyId) when creating or updating the notebook instance to encrypt its storage volume.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/key-management.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if notebooks_with_kms:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-03",
                        finding_name="SageMaker Notebook Storage Encryption Check",
                        finding_details=f"All {len(notebooks_with_kms)} notebook instances have a KMS key configured for storage encryption",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/key-management.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-03",
                        finding_name="SageMaker Notebook Storage Encryption Check",
                        finding_details="No notebook instances found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/key-management.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_notebook_storage_encryption: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-03",
                    "SageMaker Notebook Storage Encryption Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_domain_and_training_job_encryption(
    region: str = "",
) -> Dict[str, Any]:
    """
    Repo-specific hardening check (no direct Security Hub control mapping)
    covering SageMaker Domain KMS/VPC configuration and Training Job
    encryption. Split out from the former combined SM-03 check, which bundled
    these resources under a SageMaker.21 label that only covers notebook
    storage encryption.
    """
    logger.debug(
        "Starting check for SageMaker domain and training job data protection"
    )
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        resources_without_encryption = []
        resources_without_vpc_encryption = []
        total_resources_checked = 0

        # Check SageMaker Domains
        try:
            paginator = sagemaker_client.get_paginator("list_domains")
            for page in paginator.paginate():
                for domain in page.get("Domains", []):
                    domain_id = domain.get("DomainId")
                    if domain_id:
                        domain_details = sagemaker_client.describe_domain(
                            DomainId=domain_id
                        )
                        total_resources_checked += 1
                        domain_label = domain_details.get("DomainName", domain_id)

                        # Presence-as-proxy for customer-managed KMS (Rule 1);
                        # do not string-match the key id/ARN.
                        if not domain_details.get("KmsKeyId"):
                            resources_without_encryption.append(
                                {
                                    "type": "Domain",
                                    "name": domain_label,
                                    "issue": "No KMS key configured",
                                }
                            )

                        # Check VPC configuration
                        vpc_id = domain_details.get("VpcId")
                        subnet_ids = domain_details.get("SubnetIds", [])
                        if not vpc_id or not subnet_ids:
                            resources_without_vpc_encryption.append(
                                {
                                    "type": "Domain",
                                    "name": domain_label,
                                    "issue": "No VPC configuration",
                                }
                            )
        except Exception as e:
            logger.error(f"Error checking domain encryption: {str(e)}")
            raise

        # Check Training Jobs encryption
        try:
            paginator = sagemaker_client.get_paginator("list_training_jobs")
            for page in paginator.paginate():
                for job in page.get("TrainingJobSummaries", []):
                    job_name = job.get("TrainingJobName")
                    if job_name:
                        job_details = sagemaker_client.describe_training_job(
                            TrainingJobName=job_name
                        )
                        total_resources_checked += 1

                        output_config = job_details.get("OutputDataConfig", {})
                        if not output_config.get("KmsKeyId"):
                            resources_without_encryption.append(
                                {
                                    "type": "Training Job",
                                    "name": job_name,
                                    "issue": "No output encryption configured",
                                }
                            )

                        # Check inter-node encryption for distributed training
                        if (
                            job_details.get("EnableInterContainerTrafficEncryption")
                            is not True
                        ):
                            resources_without_vpc_encryption.append(
                                {
                                    "type": "Training Job",
                                    "name": job_name,
                                    "issue": "Inter-container traffic encryption not enabled",
                                }
                            )
        except Exception as e:
            logger.error(f"Error checking training jobs encryption: {str(e)}")
            raise

        if resources_without_encryption or resources_without_vpc_encryption:
            for resource in resources_without_encryption:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-26",
                        finding_name="Missing Encryption Configuration",
                        finding_details=f"{resource['type']} '{resource['name']}' - {resource['issue']}",
                        resolution="Configure encryption using AWS KMS customer managed keys for enhanced security",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/key-management.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

            for resource in resources_without_vpc_encryption:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-26",
                        finding_name="Missing VPC Encryption",
                        finding_details=f"{resource['type']} '{resource['name']}' - {resource['issue']}",
                        resolution="Enable encryption for inter-container traffic and VPC communication",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-in-transit.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if total_resources_checked > 0:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-26",
                        finding_name="Domain and Training Job Data Protection Check",
                        finding_details="All domains and training jobs use appropriate encryption configurations",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-26",
                        finding_name="Domain and Training Job Data Protection Check",
                        finding_details="No SageMaker domains or training jobs found to check",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_domain_and_training_job_encryption: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-26",
                    "Domain and Training Job Data Protection Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_mlops_utilization(
    permission_cache, region: str = ""
) -> Dict[str, Any]:
    """
    Check if SageMaker MLOps features (Model Registry, Feature Store, and Pipelines)
    are being utilized properly
    """
    logger.debug("Starting check for SageMaker MLOps features utilization")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )
        issues_found = []

        # Check Model Registry Usage
        try:
            model_packages = []
            paginator = sagemaker_client.get_paginator("list_model_package_groups")
            for page in paginator.paginate():
                model_packages.extend(page.get("ModelPackageGroupSummaryList", []))

            if not model_packages:
                issues_found.append(
                    {
                        "component": "Model Registry",
                        "issue": "No model package groups found",
                        "impact": "Model versioning and governance may not be properly tracked",
                        "severity": "Informational",
                        "status": "N/A",
                    }
                )
            else:
                # Check if models are being versioned
                for group in model_packages:
                    group_name = group.get("ModelPackageGroupName")
                    if group_name:
                        response = sagemaker_client.list_model_packages(
                            ModelPackageGroupName=group_name
                        )
                        if len(response.get("ModelPackageSummaryList", [])) <= 1:
                            issues_found.append(
                                {
                                    "component": "Model Registry",
                                    "issue": f"Model group '{group_name}' has minimal versioning",
                                    "impact": "Limited model version tracking detected",
                                    "severity": "Low",
                                    "status": "Failed",
                                }
                            )
        except Exception as e:
            # A component-check failure (e.g. AccessDenied) is an unknown
            # state, not a confirmed control failure — route directly through
            # the COULD_NOT_ASSESS disposition (Low/N-A) rather than
            # collecting a false High/Failed into issues_found.
            logger.error(f"Error checking Model Registry: {str(e)}")
            findings["csv_data"].append(
                could_not_assess_row(
                    create_finding,
                    "SM-05",
                    "SageMaker Model Registry Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/mlops.html",
                    region=region,
                )
            )

        # Check Feature Store Usage
        try:
            feature_groups = []
            paginator = sagemaker_client.get_paginator("list_feature_groups")
            for page in paginator.paginate():
                feature_groups.extend(page.get("FeatureGroupSummaries", []))

            if not feature_groups:
                issues_found.append(
                    {
                        "component": "Feature Store",
                        "issue": "No feature groups found",
                        "impact": "Feature reuse and sharing may be limited",
                        "severity": "Informational",
                        "status": "N/A",
                    }
                )
            else:
                # Check feature group status and configuration
                for group in feature_groups:
                    if group.get("FeatureGroupStatus") != "Created":
                        issues_found.append(
                            {
                                "component": "Feature Store",
                                "issue": f"Feature group '{group.get('FeatureGroupName')}' is not in Created state",
                                "impact": "Feature group may not be properly configured",
                                "severity": "Medium",
                                "status": "Failed",
                            }
                        )
        except Exception as e:
            # A component-check failure (e.g. AccessDenied) is an unknown
            # state, not a confirmed control failure — route directly through
            # the COULD_NOT_ASSESS disposition (Low/N-A) rather than
            # collecting a false High/Failed into issues_found.
            logger.error(f"Error checking Feature Store: {str(e)}")
            findings["csv_data"].append(
                could_not_assess_row(
                    create_finding,
                    "SM-05",
                    "SageMaker Feature Store Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/mlops.html",
                    region=region,
                )
            )

        # Check Pipeline Usage
        try:
            pipelines = []
            paginator = sagemaker_client.get_paginator("list_pipelines")
            for page in paginator.paginate():
                pipelines.extend(page.get("PipelineSummaries", []))

            if not pipelines:
                issues_found.append(
                    {
                        "component": "Pipelines",
                        "issue": "No ML pipelines found",
                        "impact": "Automated ML workflows may not be implemented",
                        "severity": "Informational",
                        "status": "N/A",
                    }
                )
            else:
                # Check pipeline status and execution history
                for pipeline in pipelines:
                    pipeline_name = pipeline.get("PipelineName")
                    if pipeline_name:
                        executions = sagemaker_client.list_pipeline_executions(
                            PipelineName=pipeline_name, MaxResults=1
                        )
                        if not executions.get("PipelineExecutionSummaries"):
                            issues_found.append(
                                {
                                    "component": "Pipelines",
                                    "issue": f"Pipeline '{pipeline_name}' has no execution history",
                                    "impact": "Pipeline may be defined but not actively used",
                                    "severity": "Low",
                                    "status": "Failed",
                                }
                            )
        except Exception as e:
            # A component-check failure (e.g. AccessDenied) is an unknown
            # state, not a confirmed control failure — route directly through
            # the COULD_NOT_ASSESS disposition (Low/N-A) rather than
            # collecting a false High/Failed into issues_found.
            logger.error(f"Error checking Pipelines: {str(e)}")
            findings["csv_data"].append(
                could_not_assess_row(
                    create_finding,
                    "SM-05",
                    "SageMaker Pipelines Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/mlops.html",
                    region=region,
                )
            )

        # Generate findings based on issues found
        if issues_found:
            findings["status"] = "WARN"
            findings["details"] = (
                f"Found {len(issues_found)} issues with SageMaker MLOps features"
            )

            for issue in issues_found:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-05",
                        finding_name=f"SageMaker {issue['component']} Issue",
                        finding_details=issue["issue"],
                        resolution=get_resolution_for_component(issue["component"]),
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/mlops.html",
                        severity=issue["severity"],
                        status=issue["status"],
                        region=region,
                    )
                )
        else:
            findings["details"] = "All SageMaker MLOps features are properly utilized"
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-05",
                    finding_name="SageMaker MLOps Features Check",
                    finding_details="All SageMaker MLOps features are properly utilized",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/mlops.html",
                    severity="Low",
                    status="Passed",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_mlops_utilization: {str(e)}", exc_info=True
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-05",
                    "SageMaker MLOps Features Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/mlops.html",
                    region=region,
                )
            ]
        }


def get_resolution_for_component(component: str) -> str:
    """
    Helper function to provide specific resolutions based on the component
    """
    resolutions = {
        "Model Registry": (
            "Implement model versioning using SageMaker Model Registry to track model lineage, "
            "approve model versions, and manage model deployment"
        ),
        "Feature Store": (
            "Utilize SageMaker Feature Store to create, share, and manage features "
            "for machine learning development and production"
        ),
        "Pipelines": (
            "Implement SageMaker Pipelines to automate and manage ML workflows, "
            "including data preparation, training, and model deployment"
        ),
    }
    return resolutions.get(
        component, "Review and implement appropriate SageMaker MLOps features"
    )


def check_sagemaker_clarify_usage(permission_cache, region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker Clarify is being used for bias detection and model explainability
    """
    logger.debug("Starting check for SageMaker Clarify usage")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )
        issues_found = []

        try:
            # Check Processing Jobs for Clarify
            paginator = sagemaker_client.get_paginator("list_processing_jobs")
            clarify_jobs_found = False

            for page in paginator.paginate():
                for job in page["ProcessingJobSummaries"]:
                    job_name = job["ProcessingJobName"]
                    job_details = sagemaker_client.describe_processing_job(
                        ProcessingJobName=job_name
                    )

                    # Check if it's a Clarify job
                    if (
                        "clarify"
                        in job_details.get("AppSpecification", {})
                        .get("ImageUri", "")
                        .lower()
                    ):
                        clarify_jobs_found = True
                        # Check job status
                        if job_details["ProcessingJobStatus"] == "Failed":
                            issues_found.append(
                                {
                                    "issue_type": "Failed Clarify Job",
                                    "details": f"Clarify job {job_name} failed",
                                    "severity": "High",
                                    "status": "Failed",
                                }
                            )

            if not clarify_jobs_found:
                issues_found.append(
                    {
                        "issue_type": "No Clarify Usage",
                        "details": "No SageMaker Clarify jobs found",
                        "severity": "Informational",
                        "status": "N/A",
                    }
                )

        except Exception as e:
            # Enumeration itself failed (e.g. AccessDenied) — re-raise so the
            # outer handler reports COULD_NOT_ASSESS rather than fabricating
            # a High/Failed result into issues_found.
            logger.error(f"Error checking Clarify jobs: {str(e)}")
            raise

        if issues_found:
            for issue in issues_found:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-06",
                        finding_name=f"SageMaker Clarify {issue['issue_type']}",
                        finding_details=issue["details"],
                        resolution="Implement SageMaker Clarify for model explainability and bias detection",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-configure-processing-jobs.html",
                        severity=issue["severity"],
                        status=issue["status"],
                        region=region,
                    )
                )
        else:
            findings["details"] = "SageMaker Clarify is properly utilized"
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-06",
                    finding_name="SageMaker Clarify Usage Check",
                    finding_details="SageMaker Clarify is properly utilized",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-configure-processing-jobs.html",
                    severity="Low",
                    status="Passed",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(f"Error in check_sagemaker_clarify_usage: {str(e)}", exc_info=True)
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-06",
                    "SageMaker Clarify Usage Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-configure-processing-jobs.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_model_monitor_usage(
    permission_cache, region: str = ""
) -> Dict[str, Any]:
    """
    Check if SageMaker Model Monitor is configured and actively monitoring models
    """
    # FinServ extension (FS-17): The FinServ guide (PDF §1.2.14) asks for Model
    # Monitor data-quality baselines to be refreshed on a regulator-aligned cadence
    # (SR 11-7 ongoing monitoring) and for the baseline statistics to be emitted to
    # CloudWatch under namespace /aws/sagemaker/Endpoints/data-metric with
    # emit_metrics=Enabled. See docs/SECURITY_CHECKS_FINSERV.md
    # (FS-17 → SM-07 extension note).
    logger.debug("Starting check for SageMaker Model Monitor usage")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )
        issues_found = []

        try:
            # Check monitoring schedules
            paginator = sagemaker_client.get_paginator("list_monitoring_schedules")
            monitoring_found = False

            for page in paginator.paginate():
                for schedule in page["MonitoringScheduleSummaries"]:
                    monitoring_found = True
                    schedule_name = schedule["MonitoringScheduleName"]
                    schedule_details = sagemaker_client.describe_monitoring_schedule(
                        MonitoringScheduleName=schedule_name
                    )

                    # Check schedule status
                    if schedule_details["MonitoringScheduleStatus"] != "Scheduled":
                        issues_found.append(
                            {
                                "issue_type": "Inactive Monitor",
                                "details": f"Monitoring schedule {schedule_name} is not active",
                                "severity": "Medium",
                                "status": "Failed",
                            }
                        )

            if not monitoring_found:
                issues_found.append(
                    {
                        "issue_type": "No Model Monitoring",
                        "details": "No Model Monitor schedules found",
                        "severity": "Informational",
                        "status": "N/A",
                    }
                )

        except Exception as e:
            # A component-check failure (e.g. AccessDenied) is an unknown
            # state, not a confirmed control failure — route directly through
            # the COULD_NOT_ASSESS disposition (Low/N-A) rather than
            # collecting a false High/Failed into issues_found.
            logger.error(f"Error checking Model Monitor: {str(e)}")
            findings["csv_data"].append(
                could_not_assess_row(
                    create_finding,
                    "SM-07",
                    "SageMaker Model Monitor Usage Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor.html",
                    region=region,
                )
            )

        if issues_found:
            for issue in issues_found:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-07",
                        finding_name=f"SageMaker Model Monitor {issue['issue_type']}",
                        finding_details=issue["details"],
                        resolution="Configure comprehensive model monitoring schedules",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor.html",
                        severity=issue["severity"],
                        status=issue["status"],
                        region=region,
                    )
                )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-07",
                    finding_name="SageMaker Model Monitor Usage Check",
                    finding_details="SageMaker Model Monitor is actively tracking model performance",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor.html",
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_model_monitor_usage: {str(e)}", exc_info=True
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-07",
                    "SageMaker Model Monitor Usage Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_notebook_root_access(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker notebook instances have root access disabled.
    Root access enables privilege escalation and should be disabled for security.
    Aligns with AWS Security Hub control SageMaker.3
    """
    logger.debug("Starting check for SageMaker notebook root access")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        notebooks_with_root = []
        notebooks_without_root = []

        try:
            paginator = sagemaker_client.get_paginator("list_notebook_instances")
            for page in paginator.paginate():
                for instance in page.get("NotebookInstances", []):
                    instance_name = instance.get("NotebookInstanceName")
                    if instance_name:
                        instance_details = sagemaker_client.describe_notebook_instance(
                            NotebookInstanceName=instance_name
                        )

                        root_access = instance_details.get("RootAccess", "Enabled")

                        if root_access == "Enabled":
                            notebooks_with_root.append(
                                {
                                    "name": instance_name,
                                    "status": instance_details.get(
                                        "NotebookInstanceStatus", "Unknown"
                                    ),
                                }
                            )
                        else:
                            notebooks_without_root.append(instance_name)

        except Exception as e:
            logger.error(f"Error checking notebook instances: {str(e)}")
            raise

        if notebooks_with_root:
            for notebook in notebooks_with_root:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-09",
                        finding_name="SageMaker Notebook Root Access Enabled",
                        finding_details=f"Notebook instance '{notebook['name']}' has root access enabled. Root access allows users to install arbitrary software, modify system configurations, and potentially escalate privileges.",
                        resolution="Disable root access by updating the notebook instance with RootAccess=Disabled. Note: Lifecycle configurations will still run with root access.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/nbi-root-access.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if notebooks_without_root:
                # Notebooks exist and all have root access disabled - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-09",
                        finding_name="SageMaker Notebook Root Access Check",
                        finding_details=f"All {len(notebooks_without_root)} notebook instances have root access disabled",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/nbi-root-access.html",
                        severity="High",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No notebook instances found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-09",
                        finding_name="SageMaker Notebook Root Access Check",
                        finding_details="No notebook instances found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/nbi-root-access.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_notebook_root_access: {str(e)}", exc_info=True
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-09",
                    "SageMaker Notebook Root Access Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_notebook_vpc_deployment(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker notebook instances are deployed within a custom VPC.
    Notebooks outside VPC use shared infrastructure with less isolation.
    Aligns with AWS Security Hub control SageMaker.2
    """
    logger.debug("Starting check for SageMaker notebook VPC deployment")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        notebooks_without_vpc = []
        notebooks_with_vpc = []

        try:
            paginator = sagemaker_client.get_paginator("list_notebook_instances")
            for page in paginator.paginate():
                for instance in page.get("NotebookInstances", []):
                    instance_name = instance.get("NotebookInstanceName")
                    if instance_name:
                        instance_details = sagemaker_client.describe_notebook_instance(
                            NotebookInstanceName=instance_name
                        )

                        subnet_id = instance_details.get("SubnetId")

                        if not subnet_id:
                            notebooks_without_vpc.append(
                                {
                                    "name": instance_name,
                                    "status": instance_details.get(
                                        "NotebookInstanceStatus", "Unknown"
                                    ),
                                }
                            )
                        else:
                            notebooks_with_vpc.append(
                                {
                                    "name": instance_name,
                                    "subnet_id": subnet_id,
                                    "vpc_id": instance_details.get("VpcId", "N/A"),
                                }
                            )

        except Exception as e:
            logger.error(f"Error checking notebook instances VPC: {str(e)}")
            raise

        if notebooks_without_vpc:
            for notebook in notebooks_without_vpc:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-10",
                        finding_name="SageMaker Notebook Not in VPC",
                        finding_details=f"Notebook instance '{notebook['name']}' is not deployed in a custom VPC. This uses SageMaker's service VPC with reduced network isolation.",
                        resolution="Create the notebook instance within a custom VPC by specifying SubnetId and SecurityGroupIds. This provides network isolation and allows use of VPC endpoints.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/appendix-notebook-and-internet-access.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if notebooks_with_vpc:
                # Notebooks exist and all are in VPCs - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-10",
                        finding_name="SageMaker Notebook VPC Deployment Check",
                        finding_details=f"All {len(notebooks_with_vpc)} notebook instances are deployed in custom VPCs",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/appendix-notebook-and-internet-access.html",
                        severity="High",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No notebook instances found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-10",
                        finding_name="SageMaker Notebook VPC Deployment Check",
                        finding_details="No notebook instances found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/appendix-notebook-and-internet-access.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_notebook_vpc_deployment: {str(e)}", exc_info=True
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-10",
                    "SageMaker Notebook VPC Deployment Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_model_network_isolation(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker hosted models have network isolation enabled.
    Without isolation, model containers can make outbound calls and exfiltrate data.
    Aligns with AWS Security Hub control SageMaker.5
    """
    logger.debug("Starting check for SageMaker model network isolation")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        models_without_isolation = []
        models_with_isolation = []

        try:
            paginator = sagemaker_client.get_paginator("list_models")
            for page in paginator.paginate():
                for model in page.get("Models", []):
                    model_name = model.get("ModelName")
                    if model_name:
                        try:
                            model_details = sagemaker_client.describe_model(
                                ModelName=model_name
                            )

                            enable_network_isolation = model_details.get(
                                "EnableNetworkIsolation", False
                            )

                            if not enable_network_isolation:
                                models_without_isolation.append(
                                    {
                                        "name": model_name,
                                        "creation_time": str(
                                            model_details.get("CreationTime", "Unknown")
                                        ),
                                    }
                                )
                            else:
                                models_with_isolation.append(model_name)

                        except Exception as e:
                            logger.warning(
                                f"Error describing model {model_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing models: {str(e)}")
            raise

        if models_without_isolation:
            # Limit findings to avoid overwhelming output
            for model in models_without_isolation[:20]:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-11",
                        finding_name="SageMaker Model Network Isolation Disabled",
                        finding_details=f"Model '{model['name']}' does not have network isolation enabled. Model containers can make outbound network calls, potentially exfiltrating data.",
                        resolution="Enable network isolation by setting EnableNetworkIsolation=True when creating models. This prevents containers from making outbound network calls.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/mkt-algo-model-internet-free.html",
                        # SageMaker.5 (model network isolation) is Medium
                        # severity in Security Hub. One severity applies to
                        # every Passed/Failed row of a control (severity
                        # methodology Rule 2); this previously emitted High on
                        # the Failed path while the Passed path below used
                        # Medium.
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

            if len(models_without_isolation) > 20:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-11",
                        finding_name="SageMaker Model Network Isolation Summary",
                        finding_details=f"Found {len(models_without_isolation)} total models without network isolation (showing first 20)",
                        resolution="Review all models and enable network isolation where appropriate",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/mkt-algo-model-internet-free.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if models_with_isolation:
                # Models exist and all have network isolation - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-11",
                        finding_name="SageMaker Model Network Isolation Check",
                        finding_details=f"All {len(models_with_isolation)} models have network isolation enabled",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/mkt-algo-model-internet-free.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No models found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-11",
                        finding_name="SageMaker Model Network Isolation Check",
                        finding_details="No models found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/mkt-algo-model-internet-free.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_model_network_isolation: {str(e)}", exc_info=True
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-11",
                    "SageMaker Model Network Isolation Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_endpoint_instance_count(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker endpoint configurations specify more than one initial
    instance for availability. Single instance creates availability risk and
    a single point of compromise.

    Aligns with AWS Security Hub control SageMaker.4 (severity Medium), which
    evaluates ProductionVariants[*].InitialInstanceCount on the endpoint
    CONFIGURATION resource, not the live endpoint's CurrentInstanceCount.
    Reading live endpoints missed configs that are not currently attached to
    an InService endpoint and used the wrong field for the control's
    documented fail condition. Serverless variants (ServerlessConfig present,
    no InitialInstanceCount) are skipped; the control applies only to
    instance-based variants.
    """
    logger.debug("Starting check for SageMaker endpoint config instance count")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        configs_single_instance = []
        configs_multi_instance = []

        try:
            paginator = sagemaker_client.get_paginator("list_endpoint_configs")
            for page in paginator.paginate():
                for config_summary in page.get("EndpointConfigs", []):
                    config_name = config_summary.get("EndpointConfigName")
                    if not config_name:
                        continue

                    try:
                        config_details = sagemaker_client.describe_endpoint_config(
                            EndpointConfigName=config_name
                        )

                        production_variants = config_details.get(
                            "ProductionVariants", []
                        )

                        for variant in production_variants:
                            variant_name = variant.get("VariantName", "Unknown")

                            # Serverless variants specify ServerlessConfig
                            # instead of InitialInstanceCount and scale
                            # automatically; Security Hub SageMaker.4 applies
                            # only to instance-based variants. Without this
                            # skip, every serverless config would be reported
                            # as a false "single instance" failure (the
                            # absent InitialInstanceCount would default to 0).
                            if variant.get("ServerlessConfig"):
                                continue

                            initial_instance_count = variant.get(
                                "InitialInstanceCount"
                            )
                            if initial_instance_count is None:
                                # Not an instance-based variant (or count
                                # unavailable); do not fabricate a zero.
                                continue

                            if initial_instance_count <= 1:
                                configs_single_instance.append(
                                    {
                                        "config_name": config_name,
                                        "variant_name": variant_name,
                                        "instance_count": initial_instance_count,
                                    }
                                )
                            else:
                                configs_multi_instance.append(
                                    {
                                        "config_name": config_name,
                                        "variant_name": variant_name,
                                        "instance_count": initial_instance_count,
                                    }
                                )

                    except Exception as e:
                        logger.warning(
                            f"Error describing endpoint config {config_name}: {str(e)}"
                        )

        except Exception as e:
            logger.error(f"Error listing endpoint configs: {str(e)}")
            raise

        if configs_single_instance:
            for config in configs_single_instance:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-12",
                        finding_name="SageMaker Endpoint Config Single Instance",
                        finding_details=f"Endpoint config '{config['config_name']}' variant '{config['variant_name']}' has an initial instance count of {config['instance_count']}. Single instance creates availability risk and no failover capability.",
                        resolution="Configure production variants with InitialInstanceCount >= 2 across multiple Availability Zones for high availability and fault tolerance.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/endpoint-auto-scaling.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if configs_multi_instance:
                # Endpoint configs exist and all instance-based variants have
                # multiple instances - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-12",
                        finding_name="SageMaker Endpoint Instance Count Check",
                        finding_details=f"All {len(configs_multi_instance)} instance-based endpoint config variants specify multiple initial instances",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/endpoint-auto-scaling.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No instance-based endpoint config variants found - N/A
                # (serverless variants are out of scope for this control)
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-12",
                        finding_name="SageMaker Endpoint Instance Count Check",
                        finding_details="No instance-based endpoint config variants found (serverless variants are not evaluated by this check)",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/endpoint-auto-scaling.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_endpoint_instance_count: {str(e)}", exc_info=True
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-12",
                    "SageMaker Endpoint Instance Count Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


# Maps MonitoringScheduleConfig.MonitoringType to the SageMaker DescribeXJobDefinition
# operation used to resolve a *named* job definition (MonitoringJobDefinitionName).
# Reused by both SM-13 (network isolation) and the SM-22 traffic-encryption check.
_MONITORING_TYPE_DESCRIBE_OPERATION = {
    "DataQuality": "describe_data_quality_job_definition",
    "ModelQuality": "describe_model_quality_job_definition",
    "ModelBias": "describe_model_bias_job_definition",
    "ModelExplainability": "describe_model_explainability_job_definition",
}

# Maps the same MonitoringType values to the job-definition-name kwarg used by
# each DescribeXJobDefinition operation.
_MONITORING_TYPE_NAME_PARAM = {
    "DataQuality": "JobDefinitionName",
    "ModelQuality": "JobDefinitionName",
    "ModelBias": "JobDefinitionName",
    "ModelExplainability": "JobDefinitionName",
}


def _resolve_monitoring_job_definition(
    sagemaker_client, schedule_config: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Resolve the effective MonitoringJobDefinition for a monitoring schedule.

    MonitoringScheduleConfig carries the job definition one of two ways:
      - Inline: MonitoringJobDefinition is embedded directly.
      - Named: MonitoringJobDefinitionName + MonitoringType reference a
        separately-created job definition (DataQuality, ModelQuality,
        ModelBias, or ModelExplainability) that must be fetched via its own
        DescribeXJobDefinition API.

    Reading only the inline field (the previous behavior) yields an empty
    config for every named-definition schedule, which made isolation/
    encryption checks default to "disabled" and false-FAIL every such
    schedule. Returns {} if the definition cannot be resolved (unknown type,
    lookup error), the same "assume not configured" default as before, but
    only as a genuine last resort rather than the common case.
    """
    inline_definition = schedule_config.get("MonitoringJobDefinition")
    if inline_definition:
        return inline_definition

    job_definition_name = schedule_config.get("MonitoringJobDefinitionName")
    monitoring_type = schedule_config.get("MonitoringType")
    if not job_definition_name or not monitoring_type:
        return {}

    operation_name = _MONITORING_TYPE_DESCRIBE_OPERATION.get(monitoring_type)
    name_param = _MONITORING_TYPE_NAME_PARAM.get(monitoring_type)
    if not operation_name or not name_param:
        logger.warning(
            f"Unrecognized MonitoringType '{monitoring_type}' for named "
            f"monitoring job definition '{job_definition_name}'"
        )
        return {}

    try:
        operation = getattr(sagemaker_client, operation_name)
        return operation(**{name_param: job_definition_name})
    except Exception as e:
        logger.warning(
            f"Error resolving named monitoring job definition "
            f"'{job_definition_name}' ({monitoring_type}): {str(e)}"
        )
        return {}


def check_sagemaker_monitoring_network_isolation(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker monitoring schedules have network isolation enabled.
    Aligns with AWS Security Hub control SageMaker.14

    Resolves both inline job definitions and named job definitions
    (MonitoringJobDefinitionName + MonitoringType) via
    _resolve_monitoring_job_definition; reading only the inline field
    previously false-FAILed every named-definition schedule (empty config
    defaults isolation to disabled).
    """
    logger.debug("Starting check for SageMaker monitoring schedule network isolation")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        schedules_without_isolation = []
        schedules_with_isolation = []

        try:
            paginator = sagemaker_client.get_paginator("list_monitoring_schedules")
            for page in paginator.paginate():
                for schedule in page.get("MonitoringScheduleSummaries", []):
                    schedule_name = schedule.get("MonitoringScheduleName")
                    if schedule_name:
                        try:
                            schedule_details = (
                                sagemaker_client.describe_monitoring_schedule(
                                    MonitoringScheduleName=schedule_name
                                )
                            )

                            schedule_config = schedule_details.get(
                                "MonitoringScheduleConfig", {}
                            )
                            job_definition = _resolve_monitoring_job_definition(
                                sagemaker_client, schedule_config
                            )
                            network_config = job_definition.get("NetworkConfig", {})
                            enable_network_isolation = network_config.get(
                                "EnableNetworkIsolation", False
                            )

                            if not enable_network_isolation:
                                schedules_without_isolation.append(
                                    {
                                        "name": schedule_name,
                                        "status": schedule_details.get(
                                            "MonitoringScheduleStatus", "Unknown"
                                        ),
                                    }
                                )
                            else:
                                schedules_with_isolation.append(schedule_name)

                        except Exception as e:
                            logger.warning(
                                f"Error describing monitoring schedule {schedule_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing monitoring schedules: {str(e)}")
            raise

        if schedules_without_isolation:
            for schedule in schedules_without_isolation:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-13",
                        finding_name="SageMaker Monitoring Network Isolation Disabled",
                        finding_details=f"Monitoring schedule '{schedule['name']}' does not have network isolation enabled. Monitoring jobs can make outbound network calls.",
                        resolution="Enable network isolation in the monitoring job definition NetworkConfig to prevent outbound network access.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_MonitoringNetworkConfig.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if schedules_with_isolation:
                # Monitoring schedules exist and all have network isolation - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-13",
                        finding_name="SageMaker Monitoring Network Isolation Check",
                        finding_details=f"All {len(schedules_with_isolation)} monitoring schedules have network isolation enabled",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_MonitoringNetworkConfig.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No monitoring schedules found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-13",
                        finding_name="SageMaker Monitoring Network Isolation Check",
                        finding_details="No monitoring schedules found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_MonitoringNetworkConfig.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_monitoring_network_isolation: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-13",
                    "SageMaker Monitoring Network Isolation Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_model_container_repository(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker models pull container images from private ECR in VPC.
    Using Platform mode exposes supply chain risks.
    Aligns with AWS Security Hub controls SageMaker.16 (primary containers)
    and SageMaker.19 (multi-container inference pipelines)
    """
    logger.debug("Starting check for SageMaker model container repository access")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        models_platform_mode = []
        models_vpc_mode = []

        try:
            paginator = sagemaker_client.get_paginator("list_models")
            for page in paginator.paginate():
                for model in page.get("Models", []):
                    model_name = model.get("ModelName")
                    if model_name:
                        try:
                            model_details = sagemaker_client.describe_model(
                                ModelName=model_name
                            )

                            # DescribeModel returns EITHER PrimaryContainer
                            # (single-container models; Security Hub
                            # SageMaker.16) OR Containers (multi-container
                            # inference pipelines; SageMaker.19). Only evaluate
                            # the container definitions that actually exist:
                            # treating an absent PrimaryContainer as a
                            # Platform-mode container would flag every
                            # multi-container model with a phantom failure.
                            model_flagged = False

                            primary_container = model_details.get("PrimaryContainer")
                            if primary_container:
                                repository_access_mode = primary_container.get(
                                    "ImageConfig", {}
                                ).get("RepositoryAccessMode", "Platform")
                                # Absent ImageConfig defaults to Platform, which
                                # matches the control's "image is not configured"
                                # fail condition.
                                if repository_access_mode == "Platform":
                                    models_platform_mode.append(
                                        {
                                            "name": model_name,
                                            "image": primary_container.get(
                                                "Image", "Unknown"
                                            )[:50],
                                        }
                                    )
                                    model_flagged = True

                            # Check multi-container inference pipeline containers
                            containers = model_details.get("Containers", [])
                            platform_containers = [
                                container.get("ContainerHostname", "Unknown")
                                for container in containers
                                if container.get("ImageConfig", {}).get(
                                    "RepositoryAccessMode", "Platform"
                                )
                                == "Platform"
                            ]
                            if platform_containers:
                                models_platform_mode.append(
                                    {
                                        "name": model_name,
                                        "container": ", ".join(platform_containers),
                                    }
                                )
                                model_flagged = True

                            if not model_flagged and (primary_container or containers):
                                models_vpc_mode.append(model_name)

                        except Exception as e:
                            logger.warning(
                                f"Error describing model {model_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing models: {str(e)}")
            raise

        if models_platform_mode:
            # Limit findings
            for model in models_platform_mode[:15]:
                container_note = (
                    f" (containers: {model['container']})"
                    if model.get("container")
                    else ""
                )
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-14",
                        finding_name="SageMaker Model Platform Repository Access",
                        finding_details=f"Model '{model['name']}'{container_note} uses Platform repository access mode. Container images are pulled from public/external registries, exposing supply chain risks.",
                        resolution="Configure RepositoryAccessMode=Vpc in ImageConfig to pull images from private ECR repositories through VPC. This provides supply chain security.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-container-repositories.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

            if len(models_platform_mode) > 15:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-14",
                        finding_name="SageMaker Model Repository Access Summary",
                        finding_details=f"Found {len(models_platform_mode)} total models using Platform repository access (showing first 15)",
                        resolution="Review all models and configure VPC repository access where appropriate",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-container-repositories.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if models_vpc_mode:
                # Models exist and all use VPC repository access - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-14",
                        finding_name="SageMaker Model Repository Access Check",
                        finding_details=f"All {len(models_vpc_mode)} models use VPC repository access",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-container-repositories.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No models found - N/A (models using Platform access are
                # reported as Failed above, never collapsed into this branch)
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-14",
                        finding_name="SageMaker Model Repository Access Check",
                        finding_details="No models found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-container-repositories.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_model_container_repository: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-14",
                    "SageMaker Model Container Repository Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_feature_store_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker Feature Store offline stores have KMS encryption.
    Aligns with AWS Security Hub control SageMaker.17
    """
    logger.debug("Starting check for SageMaker Feature Store offline encryption")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        feature_groups_without_encryption = []
        feature_groups_with_encryption = []

        try:
            paginator = sagemaker_client.get_paginator("list_feature_groups")
            for page in paginator.paginate():
                for group in page.get("FeatureGroupSummaries", []):
                    group_name = group.get("FeatureGroupName")
                    if group_name:
                        try:
                            group_details = sagemaker_client.describe_feature_group(
                                FeatureGroupName=group_name
                            )

                            offline_config = group_details.get("OfflineStoreConfig", {})

                            if offline_config:
                                s3_storage_config = offline_config.get(
                                    "S3StorageConfig", {}
                                )
                                kms_key_id = s3_storage_config.get("KmsKeyId")

                                if not kms_key_id:
                                    feature_groups_without_encryption.append(
                                        {
                                            "name": group_name,
                                            "s3_uri": s3_storage_config.get(
                                                "S3Uri", "Unknown"
                                            ),
                                        }
                                    )
                                else:
                                    feature_groups_with_encryption.append(
                                        {"name": group_name, "kms_key": kms_key_id}
                                    )

                        except Exception as e:
                            logger.warning(
                                f"Error describing feature group {group_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing feature groups: {str(e)}")
            raise

        if feature_groups_without_encryption:
            for group in feature_groups_without_encryption:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-15",
                        finding_name="SageMaker Feature Store Offline Encryption Missing",
                        finding_details=f"Feature group '{group['name']}' offline store does not have KMS encryption configured. Feature data in S3 may not be encrypted with customer-managed keys.",
                        resolution="Configure KmsKeyId in OfflineStoreConfig.S3StorageConfig when creating feature groups to encrypt offline store data with customer-managed KMS keys.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/feature-store-security.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if feature_groups_with_encryption:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-15",
                        finding_name="SageMaker Feature Store Encryption Check",
                        finding_details=f"All {len(feature_groups_with_encryption)} feature groups with offline stores have KMS encryption configured",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/feature-store-security.html",
                        # SageMaker.17 (offline feature store KMS) is Medium
                        # severity in Security Hub; the Failed path above
                        # already uses Medium. One severity applies to every
                        # Passed/Failed row of a control (severity
                        # methodology Rule 2); this previously emitted High.
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No feature groups with offline stores found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-15",
                        finding_name="SageMaker Feature Store Encryption Check",
                        finding_details="No feature groups with offline stores found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/feature-store-security.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_feature_store_encryption: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-15",
                    "SageMaker Feature Store Encryption Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_data_quality_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker data quality job definitions have inter-container traffic encryption.
    Aligns with AWS Security Hub control SageMaker.9
    """
    logger.debug("Starting check for SageMaker data quality job encryption")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        jobs_without_encryption = []
        jobs_with_encryption = []

        try:
            paginator = sagemaker_client.get_paginator(
                "list_data_quality_job_definitions"
            )
            for page in paginator.paginate():
                for job in page.get("JobDefinitionSummaries", []):
                    job_name = job.get("MonitoringJobDefinitionName")

                    if job_name:
                        try:
                            job_details = (
                                sagemaker_client.describe_data_quality_job_definition(
                                    JobDefinitionName=job_name
                                )
                            )

                            network_config = job_details.get("NetworkConfig", {})
                            enable_inter_container_encryption = network_config.get(
                                "EnableInterContainerTrafficEncryption", False
                            )

                            if not enable_inter_container_encryption:
                                jobs_without_encryption.append({"name": job_name})
                            else:
                                jobs_with_encryption.append(job_name)

                        except Exception as e:
                            logger.warning(
                                f"Error describing data quality job {job_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing data quality jobs: {str(e)}")
            raise

        if jobs_without_encryption:
            for job in jobs_without_encryption:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-16",
                        finding_name="SageMaker Data Quality Job Encryption Disabled",
                        finding_details=f"Data quality job definition '{job['name']}' does not have inter-container traffic encryption enabled. Data transmitted between containers is not encrypted.",
                        resolution="Enable EnableInterContainerTrafficEncryption in NetworkConfig when creating data quality job definitions.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-data-quality.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if jobs_with_encryption:
                # Data quality jobs exist and all have encryption - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-16",
                        finding_name="SageMaker Data Quality Job Encryption Check",
                        finding_details=f"All {len(jobs_with_encryption)} data quality job definitions have inter-container encryption enabled",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-data-quality.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No data quality job definitions found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-16",
                        finding_name="SageMaker Data Quality Job Encryption Check",
                        finding_details="No data quality job definitions found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-data-quality.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_data_quality_encryption: {str(e)}", exc_info=True
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-16",
                    "SageMaker Data Quality Job Encryption Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_processing_job_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker processing jobs have volume encryption enabled.
    Repo-specific hardening check with no Security Hub equivalent.
    (Security Hub SageMaker.10 covers model explainability job definition
    inter-container traffic encryption, not processing jobs.)
    """
    logger.debug("Starting check for SageMaker processing job encryption")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        jobs_without_encryption = []
        jobs_with_encryption = []

        try:
            paginator = sagemaker_client.get_paginator("list_processing_jobs")
            for page in paginator.paginate():
                for job in page.get("ProcessingJobSummaries", []):
                    job_name = job.get("ProcessingJobName")
                    job_status = job.get("ProcessingJobStatus")

                    if job_name:
                        try:
                            job_details = sagemaker_client.describe_processing_job(
                                ProcessingJobName=job_name
                            )

                            processing_resources = job_details.get(
                                "ProcessingResources", {}
                            )
                            cluster_config = processing_resources.get(
                                "ClusterConfig", {}
                            )
                            volume_kms_key = cluster_config.get("VolumeKmsKeyId")

                            if not volume_kms_key:
                                jobs_without_encryption.append(
                                    {"name": job_name, "status": job_status}
                                )
                            else:
                                jobs_with_encryption.append(job_name)

                        except Exception as e:
                            logger.warning(
                                f"Error describing processing job {job_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing processing jobs: {str(e)}")
            raise

        if jobs_without_encryption:
            for job in jobs_without_encryption[:15]:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-17",
                        finding_name="SageMaker Processing Job Volume Encryption Missing",
                        finding_details=f"Processing job '{job['name']}' does not have volume encryption configured. Data at rest on processing instances is not encrypted with customer-managed keys.",
                        resolution="Configure VolumeKmsKeyId in ProcessingResources.ClusterConfig when creating processing jobs to encrypt attached EBS volumes.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/processing-job.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

            if len(jobs_without_encryption) > 15:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-17",
                        finding_name="SageMaker Processing Job Encryption Summary",
                        finding_details=f"Found {len(jobs_without_encryption)} total processing jobs without volume encryption (showing first 15)",
                        resolution="Review all processing jobs and configure volume encryption",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/processing-job.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if jobs_with_encryption:
                # Processing jobs exist and all have encryption - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-17",
                        finding_name="SageMaker Processing Job Encryption Check",
                        finding_details=f"All {len(jobs_with_encryption)} processing jobs have volume encryption configured",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/processing-job.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No processing jobs found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-17",
                        finding_name="SageMaker Processing Job Encryption Check",
                        finding_details="No processing jobs found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/processing-job.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_processing_job_encryption: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-17",
                    "SageMaker Processing Job Encryption Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_transform_job_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker transform jobs have volume encryption enabled.
    Repo-specific hardening check with no Security Hub equivalent.
    (Security Hub SageMaker.11 covers data quality job definition network
    isolation, not transform jobs.)
    """
    logger.debug("Starting check for SageMaker transform job encryption")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        jobs_without_encryption = []
        jobs_with_encryption = []

        try:
            paginator = sagemaker_client.get_paginator("list_transform_jobs")
            for page in paginator.paginate():
                for job in page.get("TransformJobSummaries", []):
                    job_name = job.get("TransformJobName")
                    job_status = job.get("TransformJobStatus")

                    if job_name:
                        try:
                            job_details = sagemaker_client.describe_transform_job(
                                TransformJobName=job_name
                            )

                            transform_resources = job_details.get(
                                "TransformResources", {}
                            )
                            volume_kms_key = transform_resources.get("VolumeKmsKeyId")

                            if not volume_kms_key:
                                jobs_without_encryption.append(
                                    {"name": job_name, "status": job_status}
                                )
                            else:
                                jobs_with_encryption.append(job_name)

                        except Exception as e:
                            logger.warning(
                                f"Error describing transform job {job_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing transform jobs: {str(e)}")
            raise

        if jobs_without_encryption:
            for job in jobs_without_encryption[:15]:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-18",
                        finding_name="SageMaker Transform Job Volume Encryption Missing",
                        finding_details=f"Transform job '{job['name']}' does not have volume encryption configured. Data at rest on transform instances is not encrypted with customer-managed keys.",
                        resolution="Configure VolumeKmsKeyId in TransformResources when creating transform jobs to encrypt attached EBS volumes.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/batch-transform.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

            if len(jobs_without_encryption) > 15:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-18",
                        finding_name="SageMaker Transform Job Encryption Summary",
                        finding_details=f"Found {len(jobs_without_encryption)} total transform jobs without volume encryption (showing first 15)",
                        resolution="Review all transform jobs and configure volume encryption",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/batch-transform.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if jobs_with_encryption:
                # Transform jobs exist and all have encryption - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-18",
                        finding_name="SageMaker Transform Job Encryption Check",
                        finding_details=f"All {len(jobs_with_encryption)} transform jobs have volume encryption configured",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/batch-transform.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No transform jobs found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-18",
                        finding_name="SageMaker Transform Job Encryption Check",
                        finding_details="No transform jobs found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/batch-transform.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_transform_job_encryption: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-18",
                    "SageMaker Transform Job Encryption Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_hyperparameter_tuning_encryption(
    region: str = "",
) -> Dict[str, Any]:
    """
    Check if SageMaker hyperparameter tuning jobs have volume encryption enabled.
    Repo-specific hardening check with no Security Hub equivalent.
    (Security Hub SageMaker.12 covers model bias job definition network
    isolation, not hyperparameter tuning jobs.)
    """
    logger.debug("Starting check for SageMaker hyperparameter tuning job encryption")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        jobs_without_encryption = []
        jobs_with_encryption = []

        try:
            paginator = sagemaker_client.get_paginator(
                "list_hyper_parameter_tuning_jobs"
            )
            for page in paginator.paginate():
                for job in page.get("HyperParameterTuningJobSummaries", []):
                    job_name = job.get("HyperParameterTuningJobName")
                    job_status = job.get("HyperParameterTuningJobStatus")

                    if job_name:
                        try:
                            job_details = (
                                sagemaker_client.describe_hyper_parameter_tuning_job(
                                    HyperParameterTuningJobName=job_name
                                )
                            )

                            training_job_definition = job_details.get(
                                "TrainingJobDefinition", {}
                            )
                            resource_config = training_job_definition.get(
                                "ResourceConfig", {}
                            )
                            volume_kms_key = resource_config.get("VolumeKmsKeyId")

                            if not volume_kms_key:
                                jobs_without_encryption.append(
                                    {"name": job_name, "status": job_status}
                                )
                            else:
                                jobs_with_encryption.append(job_name)

                        except Exception as e:
                            logger.warning(
                                f"Error describing hyperparameter tuning job {job_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing hyperparameter tuning jobs: {str(e)}")
            raise

        if jobs_without_encryption:
            for job in jobs_without_encryption[:15]:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-19",
                        finding_name="SageMaker Hyperparameter Tuning Job Encryption Missing",
                        finding_details=f"Hyperparameter tuning job '{job['name']}' does not have volume encryption configured. Training data at rest is not encrypted with customer-managed keys.",
                        resolution="Configure VolumeKmsKeyId in TrainingJobDefinition.ResourceConfig when creating hyperparameter tuning jobs.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

            if len(jobs_without_encryption) > 15:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-19",
                        finding_name="SageMaker Hyperparameter Tuning Job Encryption Summary",
                        finding_details=f"Found {len(jobs_without_encryption)} total hyperparameter tuning jobs without volume encryption (showing first 15)",
                        resolution="Review all hyperparameter tuning jobs and configure volume encryption",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if jobs_with_encryption:
                # Hyperparameter tuning jobs exist and all have encryption - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-19",
                        finding_name="SageMaker Hyperparameter Tuning Job Encryption Check",
                        finding_details=f"All {len(jobs_with_encryption)} hyperparameter tuning jobs have volume encryption configured",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No hyperparameter tuning jobs found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-19",
                        finding_name="SageMaker Hyperparameter Tuning Job Encryption Check",
                        finding_details="No hyperparameter tuning jobs found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_hyperparameter_tuning_encryption: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-19",
                    "SageMaker Hyperparameter Tuning Job Encryption Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_compilation_job_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker compilation jobs have volume encryption enabled.
    Repo-specific hardening check with no Security Hub equivalent.
    (Security Hub SageMaker.13 covers model quality job definition
    inter-container traffic encryption, not compilation jobs.)
    """
    logger.debug("Starting check for SageMaker compilation job encryption")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        jobs_without_encryption = []
        jobs_with_encryption = []

        try:
            paginator = sagemaker_client.get_paginator("list_compilation_jobs")
            for page in paginator.paginate():
                for job in page.get("CompilationJobSummaries", []):
                    job_name = job.get("CompilationJobName")
                    job_status = job.get("CompilationJobStatus")

                    if job_name:
                        try:
                            job_details = sagemaker_client.describe_compilation_job(
                                CompilationJobName=job_name
                            )

                            output_config = job_details.get("OutputConfig", {})
                            kms_key_id = output_config.get("KmsKeyId")

                            if not kms_key_id:
                                jobs_without_encryption.append(
                                    {"name": job_name, "status": job_status}
                                )
                            else:
                                jobs_with_encryption.append(job_name)

                        except Exception as e:
                            logger.warning(
                                f"Error describing compilation job {job_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing compilation jobs: {str(e)}")
            raise

        if jobs_without_encryption:
            for job in jobs_without_encryption[:15]:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-20",
                        finding_name="SageMaker Compilation Job Encryption Missing",
                        finding_details=f"Compilation job '{job['name']}' does not have output encryption configured. Compiled model artifacts are not encrypted with customer-managed keys.",
                        resolution="Configure KmsKeyId in OutputConfig when creating compilation jobs to encrypt compiled model output.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/neo.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

            if len(jobs_without_encryption) > 15:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-20",
                        finding_name="SageMaker Compilation Job Encryption Summary",
                        finding_details=f"Found {len(jobs_without_encryption)} total compilation jobs without encryption (showing first 15)",
                        resolution="Review all compilation jobs and configure output encryption",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/neo.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if jobs_with_encryption:
                # Compilation jobs exist and all have encryption - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-20",
                        finding_name="SageMaker Compilation Job Encryption Check",
                        finding_details=f"All {len(jobs_with_encryption)} compilation jobs have output encryption configured",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/neo.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No compilation jobs found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-20",
                        finding_name="SageMaker Compilation Job Encryption Check",
                        finding_details="No compilation jobs found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/neo.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_compilation_job_encryption: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-20",
                    "SageMaker Compilation Job Encryption Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_automl_network_isolation(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker AutoML (Autopilot) jobs have inter-container traffic
    encryption enabled (AutoMLJobConfig.SecurityConfig).
    Repo-specific hardening check with no Security Hub equivalent.
    (Security Hub SageMaker.15 covers model bias job definition
    inter-container traffic encryption, not AutoML jobs.)
    """
    logger.debug("Starting check for SageMaker AutoML job network isolation")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        jobs_without_isolation = []
        jobs_with_isolation = []

        try:
            paginator = sagemaker_client.get_paginator("list_auto_ml_jobs")
            for page in paginator.paginate():
                for job in page.get("AutoMLJobSummaries", []):
                    job_name = job.get("AutoMLJobName")
                    job_status = job.get("AutoMLJobStatus")

                    if job_name:
                        try:
                            job_details = sagemaker_client.describe_auto_ml_job(
                                AutoMLJobName=job_name
                            )

                            security_config = job_details.get(
                                "AutoMLJobConfig", {}
                            ).get("SecurityConfig", {})
                            enable_inter_container_encryption = security_config.get(
                                "EnableInterContainerTrafficEncryption", False
                            )

                            if not enable_inter_container_encryption:
                                jobs_without_isolation.append(
                                    {"name": job_name, "status": job_status}
                                )
                            else:
                                jobs_with_isolation.append(job_name)

                        except Exception as e:
                            logger.warning(
                                f"Error describing AutoML job {job_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing AutoML jobs: {str(e)}")
            raise

        if jobs_without_isolation:
            for job in jobs_without_isolation[:15]:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-21",
                        finding_name="SageMaker AutoML Job Network Isolation Disabled",
                        finding_details=f"AutoML job '{job['name']}' does not have inter-container traffic encryption enabled. Data transmitted between containers during training is not encrypted.",
                        resolution="Enable EnableInterContainerTrafficEncryption in AutoMLJobConfig.SecurityConfig when creating AutoML jobs.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_AutoMLSecurityConfig.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

            if len(jobs_without_isolation) > 15:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-21",
                        finding_name="SageMaker AutoML Job Network Isolation Summary",
                        finding_details=f"Found {len(jobs_without_isolation)} total AutoML jobs without network isolation (showing first 15)",
                        resolution="Review all AutoML jobs and enable inter-container traffic encryption",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_AutoMLSecurityConfig.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if jobs_with_isolation:
                # AutoML jobs exist and all have encryption - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-21",
                        finding_name="SageMaker AutoML Job Network Isolation Check",
                        finding_details=f"All {len(jobs_with_isolation)} AutoML jobs have inter-container encryption enabled",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_AutoMLSecurityConfig.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No AutoML jobs found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-21",
                        finding_name="SageMaker AutoML Job Network Isolation Check",
                        finding_details="No AutoML jobs found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_AutoMLSecurityConfig.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_automl_network_isolation: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-21",
                    "SageMaker AutoML Job Network Isolation Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


# ============================================================================
# JOB-DEFINITION-BASED CONTROLS (SageMaker.10/.11/.12/.13/.15/.20/.25)
#
# Clarify (ModelBias, ModelExplainability) and Model Monitor
# (DataQuality, ModelQuality) job definitions each expose a NetworkConfig
# with EnableInterContainerTrafficEncryption and EnableNetworkIsolation. Each
# Security Hub control below checks one field on one job-definition type; the
# List/Describe fetch is shared via _list_job_definitions_with_details.
# ============================================================================

# job type -> (list operation, describe operation, describe kwarg name)
_JOB_DEFINITION_APIS: Dict[str, tuple] = {
    "DataQuality": (
        "list_data_quality_job_definitions",
        "describe_data_quality_job_definition",
        "JobDefinitionName",
    ),
    "ModelQuality": (
        "list_model_quality_job_definitions",
        "describe_model_quality_job_definition",
        "JobDefinitionName",
    ),
    "ModelBias": (
        "list_model_bias_job_definitions",
        "describe_model_bias_job_definition",
        "JobDefinitionName",
    ),
    "ModelExplainability": (
        "list_model_explainability_job_definitions",
        "describe_model_explainability_job_definition",
        "JobDefinitionName",
    ),
}


def _list_job_definitions_with_details(
    sagemaker_client, job_type: str
) -> List[Dict[str, Any]]:
    """
    List all job definitions of the given Clarify/Model-Monitor type
    (DataQuality, ModelQuality, ModelBias, ModelExplainability) and fetch
    full details for each via the matching DescribeXJobDefinition API.

    Returns a list of {"name": str, "details": dict} entries. Definitions
    that fail to describe are skipped (logged) rather than raising, so one
    bad definition does not abort the whole check.
    """
    list_op, describe_op, name_param = _JOB_DEFINITION_APIS[job_type]
    results: List[Dict[str, Any]] = []

    paginator = sagemaker_client.get_paginator(list_op)
    for page in paginator.paginate():
        for job in page.get("JobDefinitionSummaries", []):
            job_name = job.get("MonitoringJobDefinitionName")
            if not job_name:
                continue
            try:
                describe = getattr(sagemaker_client, describe_op)
                details = describe(**{name_param: job_name})
                results.append({"name": job_name, "details": details})
            except Exception as e:
                logger.warning(
                    f"Error describing {job_type} job definition {job_name}: {str(e)}"
                )

    return results


def check_sagemaker_explainability_traffic_encryption(
    region: str = "",
) -> Dict[str, Any]:
    """
    Check if SageMaker model explainability job definitions have
    inter-container traffic encryption enabled.
    Aligns with AWS Security Hub control SageMaker.10 (severity Medium).
    """
    logger.debug("Starting check for SageMaker explainability traffic encryption")
    try:
        findings = {"csv_data": []}
        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        without_encryption = []
        with_encryption = []
        try:
            jobs = _list_job_definitions_with_details(
                sagemaker_client, "ModelExplainability"
            )
            for job in jobs:
                network_config = job["details"].get("NetworkConfig", {})
                if network_config.get("EnableInterContainerTrafficEncryption", False):
                    with_encryption.append(job["name"])
                else:
                    without_encryption.append(job["name"])
        except Exception as e:
            logger.error(f"Error listing explainability job definitions: {str(e)}")
            raise

        if without_encryption:
            for name in without_encryption:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-29",
                        finding_name="SageMaker Explainability Job Traffic Encryption Disabled",
                        finding_details=f"Model explainability job definition '{name}' does not have inter-container traffic encryption enabled. Data transmitted between containers is not encrypted.",
                        resolution="Enable EnableInterContainerTrafficEncryption in NetworkConfig when creating model explainability job definitions.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-model-explainability-baseline-schedule.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        elif with_encryption:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-29",
                    finding_name="SageMaker Explainability Job Traffic Encryption Check",
                    finding_details=f"All {len(with_encryption)} model explainability job definitions have inter-container encryption enabled",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-model-explainability-baseline-schedule.html",
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-29",
                    finding_name="SageMaker Explainability Job Traffic Encryption Check",
                    finding_details="No model explainability job definitions found",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-model-explainability-baseline-schedule.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_explainability_traffic_encryption: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-29",
                    "SageMaker Explainability Job Traffic Encryption Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_data_quality_network_isolation(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker data quality job definitions have network isolation
    enabled.
    Aligns with AWS Security Hub control SageMaker.11 (severity Medium).
    """
    logger.debug("Starting check for SageMaker data quality network isolation")
    try:
        findings = {"csv_data": []}
        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        without_isolation = []
        with_isolation = []
        try:
            jobs = _list_job_definitions_with_details(sagemaker_client, "DataQuality")
            for job in jobs:
                network_config = job["details"].get("NetworkConfig", {})
                if network_config.get("EnableNetworkIsolation", False):
                    with_isolation.append(job["name"])
                else:
                    without_isolation.append(job["name"])
        except Exception as e:
            # Enumeration itself failed (e.g. AccessDenied) — re-raise so the
            # outer handler reports COULD_NOT_ASSESS rather than silently
            # falling through to a "no resources found" N/A.
            logger.error(f"Error listing data quality job definitions: {str(e)}")
            raise

        if without_isolation:
            for name in without_isolation:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-30",
                        finding_name="SageMaker Data Quality Job Network Isolation Disabled",
                        finding_details=f"Data quality job definition '{name}' does not have network isolation enabled. The job's containers can make outbound network calls.",
                        resolution="Enable EnableNetworkIsolation in NetworkConfig when creating data quality job definitions.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-data-quality.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        elif with_isolation:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-30",
                    finding_name="SageMaker Data Quality Job Network Isolation Check",
                    finding_details=f"All {len(with_isolation)} data quality job definitions have network isolation enabled",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-data-quality.html",
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-30",
                    finding_name="SageMaker Data Quality Job Network Isolation Check",
                    finding_details="No data quality job definitions found",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-data-quality.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_data_quality_network_isolation: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-30",
                    "SageMaker Data Quality Job Network Isolation Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_model_bias_network_isolation(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker model bias job definitions have network isolation
    enabled.
    Aligns with AWS Security Hub control SageMaker.12 (severity Medium).
    """
    logger.debug("Starting check for SageMaker model bias network isolation")
    try:
        findings = {"csv_data": []}
        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        without_isolation = []
        with_isolation = []
        try:
            jobs = _list_job_definitions_with_details(sagemaker_client, "ModelBias")
            for job in jobs:
                network_config = job["details"].get("NetworkConfig", {})
                if network_config.get("EnableNetworkIsolation", False):
                    with_isolation.append(job["name"])
                else:
                    without_isolation.append(job["name"])
        except Exception as e:
            # Enumeration itself failed (e.g. AccessDenied) — re-raise so the
            # outer handler reports COULD_NOT_ASSESS rather than silently
            # falling through to a "no resources found" N/A.
            logger.error(f"Error listing model bias job definitions: {str(e)}")
            raise

        if without_isolation:
            for name in without_isolation:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-31",
                        finding_name="SageMaker Model Bias Job Network Isolation Disabled",
                        finding_details=f"Model bias job definition '{name}' does not have network isolation enabled. The job's containers can make outbound network calls.",
                        resolution="Enable EnableNetworkIsolation in NetworkConfig when creating model bias job definitions.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-model-bias-schedule.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        elif with_isolation:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-31",
                    finding_name="SageMaker Model Bias Job Network Isolation Check",
                    finding_details=f"All {len(with_isolation)} model bias job definitions have network isolation enabled",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-model-bias-schedule.html",
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-31",
                    finding_name="SageMaker Model Bias Job Network Isolation Check",
                    finding_details="No model bias job definitions found",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-model-bias-schedule.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_model_bias_network_isolation: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-31",
                    "SageMaker Model Bias Job Network Isolation Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_model_quality_traffic_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker model quality job definitions have inter-container
    traffic encryption enabled.
    Aligns with AWS Security Hub control SageMaker.13 (severity Medium).
    """
    logger.debug("Starting check for SageMaker model quality traffic encryption")
    try:
        findings = {"csv_data": []}
        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        without_encryption = []
        with_encryption = []
        try:
            jobs = _list_job_definitions_with_details(sagemaker_client, "ModelQuality")
            for job in jobs:
                network_config = job["details"].get("NetworkConfig", {})
                if network_config.get("EnableInterContainerTrafficEncryption", False):
                    with_encryption.append(job["name"])
                else:
                    without_encryption.append(job["name"])
        except Exception as e:
            # Enumeration itself failed (e.g. AccessDenied) — re-raise so the
            # outer handler reports COULD_NOT_ASSESS rather than silently
            # falling through to a "no resources found" N/A.
            logger.error(f"Error listing model quality job definitions: {str(e)}")
            raise

        if without_encryption:
            for name in without_encryption:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-32",
                        finding_name="SageMaker Model Quality Job Traffic Encryption Disabled",
                        finding_details=f"Model quality job definition '{name}' does not have inter-container traffic encryption enabled. Data transmitted between containers is not encrypted.",
                        resolution="Enable EnableInterContainerTrafficEncryption in NetworkConfig when creating model quality job definitions.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-model-quality.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        elif with_encryption:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-32",
                    finding_name="SageMaker Model Quality Job Traffic Encryption Check",
                    finding_details=f"All {len(with_encryption)} model quality job definitions have inter-container encryption enabled",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-model-quality.html",
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-32",
                    finding_name="SageMaker Model Quality Job Traffic Encryption Check",
                    finding_details="No model quality job definitions found",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-model-quality.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_model_quality_traffic_encryption: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-32",
                    "SageMaker Model Quality Job Traffic Encryption Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_model_bias_traffic_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if multi-instance SageMaker model bias job definitions have
    inter-container traffic encryption enabled.
    Aligns with AWS Security Hub control SageMaker.15 (severity Medium): the
    control fails only when traffic encryption is disabled/absent AND the
    job's cluster has 2 or more instances (a single-instance job has no
    inter-container traffic to encrypt).
    """
    logger.debug("Starting check for SageMaker model bias traffic encryption")
    try:
        findings = {"csv_data": []}
        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        without_encryption = []
        with_encryption_or_single_instance = []
        try:
            jobs = _list_job_definitions_with_details(sagemaker_client, "ModelBias")
            for job in jobs:
                details = job["details"]
                network_config = details.get("NetworkConfig", {})
                encryption_enabled = network_config.get(
                    "EnableInterContainerTrafficEncryption", False
                )
                instance_count = (
                    details.get("JobResources", {})
                    .get("ClusterConfig", {})
                    .get("InstanceCount", 1)
                )

                if not encryption_enabled and instance_count >= 2:
                    without_encryption.append(
                        {"name": job["name"], "instance_count": instance_count}
                    )
                else:
                    with_encryption_or_single_instance.append(job["name"])
        except Exception as e:
            # Enumeration itself failed (e.g. AccessDenied) — re-raise so the
            # outer handler reports COULD_NOT_ASSESS rather than silently
            # falling through to a "no resources found" N/A.
            logger.error(f"Error listing model bias job definitions: {str(e)}")
            raise

        if without_encryption:
            for job in without_encryption:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-33",
                        finding_name="SageMaker Model Bias Job Traffic Encryption Disabled",
                        finding_details=f"Model bias job definition '{job['name']}' runs on {job['instance_count']} instances without inter-container traffic encryption enabled. Data transmitted between containers is not encrypted.",
                        resolution="Enable EnableInterContainerTrafficEncryption in NetworkConfig when creating multi-instance model bias job definitions.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-model-bias-schedule.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        elif with_encryption_or_single_instance:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-33",
                    finding_name="SageMaker Model Bias Job Traffic Encryption Check",
                    finding_details=f"All {len(with_encryption_or_single_instance)} model bias job definitions are single-instance or have inter-container encryption enabled",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-model-bias-schedule.html",
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-33",
                    finding_name="SageMaker Model Bias Job Traffic Encryption Check",
                    finding_details="No model bias job definitions found",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-model-bias-schedule.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_model_bias_traffic_encryption: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-33",
                    "SageMaker Model Bias Job Traffic Encryption Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_explainability_network_isolation(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker model explainability job definitions have network
    isolation enabled.

    Aligns with AWS Security Hub control SageMaker.20 (severity High).
    Register decision: SageMaker.20 and SageMaker.25 are High in Security Hub
    while sibling isolation controls (SageMaker.11, .12, .14) are Medium and
    the severity methodology's governance/monitoring family band is Medium.
    This check seeds from the Security Hub published severity (High) since
    it is a real Security Hub control; the sibling asymmetry is intentional
    and documented here per the gap-analysis Severity Model guidance.
    """
    logger.debug("Starting check for SageMaker explainability network isolation")
    try:
        findings = {"csv_data": []}
        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        without_isolation = []
        with_isolation = []
        try:
            jobs = _list_job_definitions_with_details(
                sagemaker_client, "ModelExplainability"
            )
            for job in jobs:
                network_config = job["details"].get("NetworkConfig", {})
                if network_config.get("EnableNetworkIsolation", False):
                    with_isolation.append(job["name"])
                else:
                    without_isolation.append(job["name"])
        except Exception as e:
            # Enumeration itself failed (e.g. AccessDenied) — re-raise so the
            # outer handler reports COULD_NOT_ASSESS rather than silently
            # falling through to a "no resources found" N/A.
            logger.error(f"Error listing explainability job definitions: {str(e)}")
            raise

        if without_isolation:
            for name in without_isolation:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-35",
                        finding_name="SageMaker Explainability Job Network Isolation Disabled",
                        finding_details=f"Model explainability job definition '{name}' does not have network isolation enabled. The job's containers can make outbound network calls.",
                        resolution="Enable EnableNetworkIsolation in NetworkConfig when creating model explainability job definitions.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-model-explainability-baseline-schedule.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )
        elif with_isolation:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-35",
                    finding_name="SageMaker Explainability Job Network Isolation Check",
                    finding_details=f"All {len(with_isolation)} model explainability job definitions have network isolation enabled",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-model-explainability-baseline-schedule.html",
                    severity="High",
                    status="Passed",
                    region=region,
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-35",
                    finding_name="SageMaker Explainability Job Network Isolation Check",
                    finding_details="No model explainability job definitions found",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-model-explainability-baseline-schedule.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_explainability_network_isolation: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-35",
                    "SageMaker Explainability Job Network Isolation Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_model_quality_network_isolation(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker model quality job definitions have network isolation
    enabled.

    Aligns with AWS Security Hub control SageMaker.25 (severity High).
    Register decision: see check_sagemaker_explainability_network_isolation
    (SM-35) docstring — SageMaker.25 is High in Security Hub even though the
    sibling isolation controls are Medium; seeded from Security Hub.
    """
    logger.debug("Starting check for SageMaker model quality network isolation")
    try:
        findings = {"csv_data": []}
        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        without_isolation = []
        with_isolation = []
        try:
            jobs = _list_job_definitions_with_details(sagemaker_client, "ModelQuality")
            for job in jobs:
                network_config = job["details"].get("NetworkConfig", {})
                if network_config.get("EnableNetworkIsolation", False):
                    with_isolation.append(job["name"])
                else:
                    without_isolation.append(job["name"])
        except Exception as e:
            # Enumeration itself failed (e.g. AccessDenied) — re-raise so the
            # outer handler reports COULD_NOT_ASSESS rather than silently
            # falling through to a "no resources found" N/A.
            logger.error(f"Error listing model quality job definitions: {str(e)}")
            raise

        if without_isolation:
            for name in without_isolation:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-39",
                        finding_name="SageMaker Model Quality Job Network Isolation Disabled",
                        finding_details=f"Model quality job definition '{name}' does not have network isolation enabled. The job's containers can make outbound network calls.",
                        resolution="Enable EnableNetworkIsolation in NetworkConfig when creating model quality job definitions.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-model-quality.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )
        elif with_isolation:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-39",
                    finding_name="SageMaker Model Quality Job Network Isolation Check",
                    finding_details=f"All {len(with_isolation)} model quality job definitions have network isolation enabled",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-model-quality.html",
                    severity="High",
                    status="Passed",
                    region=region,
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-39",
                    finding_name="SageMaker Model Quality Job Network Isolation Check",
                    finding_details="No model quality job definitions found",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-model-quality.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_model_quality_network_isolation: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-39",
                    "SageMaker Model Quality Job Network Isolation Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_monitoring_traffic_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker monitoring schedules have inter-container traffic
    encryption enabled.
    Aligns with AWS Security Hub control SageMaker.22 (severity Medium).

    Resolves both inline job definitions and named job definitions
    (MonitoringJobDefinitionName + MonitoringType) via
    _resolve_monitoring_job_definition, the same helper used by SM-13
    (SageMaker.14 network isolation) to fix the identical named-definition
    defect for this traffic-encryption control.
    """
    logger.debug("Starting check for SageMaker monitoring traffic encryption")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        schedules_without_encryption = []
        schedules_with_encryption = []

        try:
            paginator = sagemaker_client.get_paginator("list_monitoring_schedules")
            for page in paginator.paginate():
                for schedule in page.get("MonitoringScheduleSummaries", []):
                    schedule_name = schedule.get("MonitoringScheduleName")
                    if not schedule_name:
                        continue
                    try:
                        schedule_details = (
                            sagemaker_client.describe_monitoring_schedule(
                                MonitoringScheduleName=schedule_name
                            )
                        )

                        schedule_config = schedule_details.get(
                            "MonitoringScheduleConfig", {}
                        )
                        job_definition = _resolve_monitoring_job_definition(
                            sagemaker_client, schedule_config
                        )
                        network_config = job_definition.get("NetworkConfig", {})
                        encryption_enabled = network_config.get(
                            "EnableInterContainerTrafficEncryption", False
                        )

                        if not encryption_enabled:
                            schedules_without_encryption.append(schedule_name)
                        else:
                            schedules_with_encryption.append(schedule_name)

                    except Exception as e:
                        logger.warning(
                            f"Error describing monitoring schedule {schedule_name}: {str(e)}"
                        )

        except Exception as e:
            logger.error(f"Error listing monitoring schedules: {str(e)}")
            raise

        if schedules_without_encryption:
            for name in schedules_without_encryption:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-36",
                        finding_name="SageMaker Monitoring Traffic Encryption Disabled",
                        finding_details=f"Monitoring schedule '{name}' does not have inter-container traffic encryption enabled. Data transmitted between monitoring job containers is not encrypted.",
                        resolution="Enable EnableInterContainerTrafficEncryption in the monitoring job definition NetworkConfig.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_MonitoringNetworkConfig.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        elif schedules_with_encryption:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-36",
                    finding_name="SageMaker Monitoring Traffic Encryption Check",
                    finding_details=f"All {len(schedules_with_encryption)} monitoring schedules have inter-container traffic encryption enabled",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_MonitoringNetworkConfig.html",
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-36",
                    finding_name="SageMaker Monitoring Traffic Encryption Check",
                    finding_details="No monitoring schedules found",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_MonitoringNetworkConfig.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_monitoring_traffic_encryption: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-36",
                    "SageMaker Monitoring Traffic Encryption Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_notebook_platform(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker notebook instances use a supported platform identifier.
    Aligns with AWS Security Hub control SageMaker.8 (severity Medium): the
    control fails when PlatformIdentifier is not the supported value
    notebook-al2-v3 (the current Amazon Linux 2 platform).
    """
    logger.debug("Starting check for SageMaker notebook platform identifier")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        notebooks_unsupported_platform = []
        notebooks_supported_platform = []

        supported_platform = "notebook-al2-v3"

        try:
            paginator = sagemaker_client.get_paginator("list_notebook_instances")
            for page in paginator.paginate():
                for instance in page.get("NotebookInstances", []):
                    instance_name = instance.get("NotebookInstanceName")
                    if not instance_name:
                        continue
                    try:
                        instance_details = sagemaker_client.describe_notebook_instance(
                            NotebookInstanceName=instance_name
                        )
                        platform_identifier = instance_details.get(
                            "PlatformIdentifier"
                        )

                        if platform_identifier != supported_platform:
                            notebooks_unsupported_platform.append(
                                {
                                    "name": instance_name,
                                    "platform": platform_identifier or "unknown",
                                }
                            )
                        else:
                            notebooks_supported_platform.append(instance_name)

                    except Exception as e:
                        logger.warning(
                            f"Error describing notebook instance {instance_name}: {str(e)}"
                        )

        except Exception as e:
            # Enumeration itself failed (e.g. AccessDenied) — re-raise so the
            # outer handler reports COULD_NOT_ASSESS rather than silently
            # falling through to a "no resources found" N/A.
            logger.error(f"Error listing notebook instances: {str(e)}")
            raise

        if notebooks_unsupported_platform:
            for notebook in notebooks_unsupported_platform:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-28",
                        finding_name="SageMaker Notebook Unsupported Platform",
                        finding_details=f"Notebook instance '{notebook['name']}' uses platform '{notebook['platform']}' instead of the supported '{supported_platform}' (Amazon Linux 2) platform.",
                        resolution=f"Update the notebook instance to use PlatformIdentifier={supported_platform} for current security patches and supported software.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/notebook-instance-platform-support-notice.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if notebooks_supported_platform:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-28",
                        finding_name="SageMaker Notebook Platform Check",
                        finding_details=f"All {len(notebooks_supported_platform)} notebook instances use the supported '{supported_platform}' platform",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/notebook-instance-platform-support-notice.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-28",
                        finding_name="SageMaker Notebook Platform Check",
                        finding_details="No notebook instances found",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/notebook-instance-platform-support-notice.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_notebook_platform: {str(e)}", exc_info=True
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-28",
                    "SageMaker Notebook Platform Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_online_feature_store_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker Feature Store online stores using standard storage
    have KMS encryption configured (any KMS key satisfies this control).
    Aligns with AWS Security Hub control SageMaker.18 (severity Medium).

    Any KMS key (customer-managed or AWS-managed) satisfies this control —
    unlike SageMaker.21/.23/.24, this control fails only when NO KMS key is
    configured (Correctness Rule 1: "any KMS" family). Only feature groups
    with StorageType=Standard online stores are evaluated; InMemory storage
    does not support this configuration.
    """
    logger.debug("Starting check for SageMaker online feature store encryption")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        groups_without_encryption = []
        groups_with_encryption = []

        try:
            paginator = sagemaker_client.get_paginator("list_feature_groups")
            for page in paginator.paginate():
                for group in page.get("FeatureGroupSummaries", []):
                    group_name = group.get("FeatureGroupName")
                    if not group_name:
                        continue
                    try:
                        group_details = sagemaker_client.describe_feature_group(
                            FeatureGroupName=group_name
                        )

                        online_config = group_details.get("OnlineStoreConfig", {})
                        if not online_config.get("EnableOnlineStore"):
                            continue

                        # StorageType defaults to Standard when unspecified;
                        # InMemory storage is out of this control's scope.
                        storage_type = online_config.get("StorageType", "Standard")
                        if storage_type != "Standard":
                            continue

                        kms_key_id = online_config.get("SecurityConfig", {}).get(
                            "KmsKeyId"
                        )

                        if not kms_key_id:
                            groups_without_encryption.append(group_name)
                        else:
                            groups_with_encryption.append(group_name)

                    except Exception as e:
                        logger.warning(
                            f"Error describing feature group {group_name}: {str(e)}"
                        )

        except Exception as e:
            logger.error(f"Error listing feature groups: {str(e)}")
            raise

        if groups_without_encryption:
            for name in groups_without_encryption:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-34",
                        finding_name="SageMaker Online Feature Store Encryption Missing",
                        finding_details=f"Feature group '{name}' online store (standard storage) does not have a KMS key configured. Feature data may not be encrypted with a KMS key.",
                        resolution="Configure KmsKeyId in OnlineStoreConfig.SecurityConfig when creating or updating feature groups with a standard-storage online store.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/feature-store-security.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        elif groups_with_encryption:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-34",
                    finding_name="SageMaker Online Feature Store Encryption Check",
                    finding_details=f"All {len(groups_with_encryption)} feature groups with standard-storage online stores have a KMS key configured",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/feature-store-security.html",
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-34",
                    finding_name="SageMaker Online Feature Store Encryption Check",
                    finding_details="No feature groups with standard-storage online stores found",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/feature-store-security.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_online_feature_store_encryption: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-34",
                    "SageMaker Online Feature Store Encryption Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_sagemaker_inference_experiment_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker inference experiments have customer-managed KMS keys
    configured for instance storage and (when data capture is enabled) data
    storage.

    Aligns with AWS Security Hub controls SageMaker.23 (severity Medium,
    instance storage volume KMS key) and SageMaker.24 (severity Medium, data
    capture storage KMS key). Both are evaluated together since both read
    the same DescribeInferenceExperiment response; findings are tagged with
    the specific check they apply to. Detection is presence-as-proxy
    (Correctness Rule 1, customer-managed family): the KmsKey/DataStorageConfig
    .KmsKey fields only hold a value when the customer configured one.
    SageMaker.24 is skipped for experiments without data capture enabled.
    """
    logger.debug("Starting check for SageMaker inference experiment encryption")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        instance_storage_without_kms = []
        instance_storage_with_kms = []
        data_storage_without_kms = []
        data_storage_with_kms = []

        try:
            paginator = sagemaker_client.get_paginator("list_inference_experiments")
            for page in paginator.paginate():
                for experiment in page.get("InferenceExperiments", []):
                    experiment_name = experiment.get("Name")
                    if not experiment_name:
                        continue
                    try:
                        details = sagemaker_client.describe_inference_experiment(
                            Name=experiment_name
                        )

                        # SageMaker.23: instance storage volume KMS key
                        if details.get("KmsKey"):
                            instance_storage_with_kms.append(experiment_name)
                        else:
                            instance_storage_without_kms.append(experiment_name)

                        # SageMaker.24: data capture storage KMS key. Only
                        # applies when data capture is configured; a missing
                        # DataStorageConfig means data capture is not enabled
                        # for this experiment, so the control does not apply.
                        data_storage_config = details.get("DataStorageConfig")
                        if data_storage_config:
                            if data_storage_config.get("KmsKey"):
                                data_storage_with_kms.append(experiment_name)
                            else:
                                data_storage_without_kms.append(experiment_name)

                    except Exception as e:
                        logger.warning(
                            f"Error describing inference experiment {experiment_name}: {str(e)}"
                        )

        except Exception as e:
            logger.error(f"Error listing inference experiments: {str(e)}")

        # SageMaker.23 findings
        if instance_storage_without_kms:
            for name in instance_storage_without_kms:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-37",
                        finding_name="SageMaker Inference Experiment Instance Storage Encryption Missing",
                        finding_details=f"Inference experiment '{name}' does not have a customer-managed KMS key configured for the instance storage volume.",
                        resolution="Configure KmsKey when creating the inference experiment to encrypt the ML compute instance storage volume with a customer-managed key.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/shadow-tests.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        elif instance_storage_with_kms:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-37",
                    finding_name="SageMaker Inference Experiment Instance Storage Encryption Check",
                    finding_details=f"All {len(instance_storage_with_kms)} inference experiments have a customer-managed KMS key configured for instance storage",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/shadow-tests.html",
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-37",
                    finding_name="SageMaker Inference Experiment Instance Storage Encryption Check",
                    finding_details="No inference experiments found",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/shadow-tests.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )

        # SageMaker.24 findings
        if data_storage_without_kms:
            for name in data_storage_without_kms:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-38",
                        finding_name="SageMaker Inference Experiment Data Storage Encryption Missing",
                        finding_details=f"Inference experiment '{name}' has data capture enabled but does not have a customer-managed KMS key configured for the captured data storage.",
                        resolution="Configure DataStorageConfig.KmsKey when creating the inference experiment to encrypt captured inference data with a customer-managed key.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/shadow-tests.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        elif data_storage_with_kms:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-38",
                    finding_name="SageMaker Inference Experiment Data Storage Encryption Check",
                    finding_details=f"All {len(data_storage_with_kms)} inference experiments with data capture enabled have a customer-managed KMS key configured",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/shadow-tests.html",
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-38",
                    finding_name="SageMaker Inference Experiment Data Storage Encryption Check",
                    finding_details="No inference experiments with data capture enabled found",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/shadow-tests.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_sagemaker_inference_experiment_encryption: {str(e)}",
            exc_info=True,
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-37",
                    "SageMaker Inference Experiment Instance Storage Encryption Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                ),
                could_not_assess_row(
                    create_finding,
                    "SM-38",
                    "SageMaker Inference Experiment Data Storage Encryption Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                ),
            ]
        }


# ============================================================================
# MODEL GOVERNANCE CHECKS
# ============================================================================


def check_model_approval_workflow(region: str = "") -> Dict[str, Any]:
    """
    Check if Model Registry has proper approval workflows configured.
    Validates that models go through approval process before production deployment.
    """
    # FinServ extension (FS-19): The FinServ guide (PDF §1.2.14) expects model
    # package groups to enforce ModelApprovalStatus=PendingManualApproval by default
    # and to flag model packages that are auto-approved as their latest version.
    # See docs/SECURITY_CHECKS_FINSERV.md (FS-19 → SM-22
    # extension note) for the detection refinement.
    logger.debug("Starting check for model approval workflow")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        issues_found = []
        groups_checked = 0

        try:
            paginator = sagemaker_client.get_paginator("list_model_package_groups")
            for page in paginator.paginate():
                for group in page.get("ModelPackageGroupSummaryList", []):
                    group_name = group.get("ModelPackageGroupName")
                    groups_checked += 1

                    if group_name:
                        try:
                            # List model packages in this group
                            models_response = sagemaker_client.list_model_packages(
                                ModelPackageGroupName=group_name, MaxResults=100
                            )

                            model_packages = models_response.get(
                                "ModelPackageSummaryList", []
                            )

                            if not model_packages:
                                continue

                            # Check approval status distribution
                            pending_count = 0
                            approved_count = 0
                            rejected_count = 0

                            for model in model_packages:
                                status = model.get(
                                    "ModelApprovalStatus", "PendingManualApproval"
                                )
                                if status == "PendingManualApproval":
                                    pending_count += 1
                                elif status == "Approved":
                                    approved_count += 1
                                elif status == "Rejected":
                                    rejected_count += 1

                            # Check if any models are approved without going through pending
                            total_models = len(model_packages)

                            # If all models are approved and none are pending/rejected, might indicate auto-approval
                            if approved_count == total_models and total_models > 3:
                                issues_found.append(
                                    {
                                        "type": "Auto-Approval Suspected",
                                        "group": group_name,
                                        "details": f"All {total_models} models in group '{group_name}' are approved with no pending or rejected models. Manual approval workflow may not be enforced.",
                                        "severity": "Medium",
                                    }
                                )

                            # Check for models stuck in pending
                            if pending_count > 5:
                                issues_found.append(
                                    {
                                        "type": "Stale Pending Models",
                                        "group": group_name,
                                        "details": f"Model group '{group_name}' has {pending_count} models pending approval. Review and process pending model approvals.",
                                        "severity": "Low",
                                    }
                                )

                        except Exception as e:
                            logger.warning(
                                f"Error checking model group {group_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing model package groups: {str(e)}")

        if groups_checked == 0:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-22",
                    finding_name="Model Approval Workflow Check",
                    finding_details="No model package groups found. Model Registry is not being used for model governance.",
                    resolution="Implement Model Registry to track model versions and enforce approval workflows before production deployment.",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry-approve.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )
        elif issues_found:
            for issue in issues_found:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-22",
                        finding_name=f"Model Approval Workflow - {issue['type']}",
                        finding_details=issue["details"],
                        resolution="Configure proper model approval workflows using SageMaker Model Registry. Require manual approval or automated validation before models are approved for production.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry-approve.html",
                        severity=issue["severity"],
                        status="Failed",
                        region=region,
                    )
                )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-22",
                    finding_name="Model Approval Workflow Check",
                    finding_details=f"Checked {groups_checked} model package groups. Approval workflows appear to be properly configured.",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry-approve.html",
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(f"Error in check_model_approval_workflow: {str(e)}", exc_info=True)
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-22",
                    "Model Approval Workflow Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_model_drift_detection(region: str = "") -> Dict[str, Any]:
    """
    Check if Model Monitor is configured for drift detection with proper baselines.
    Validates that models have data quality and model quality monitoring configured.
    """
    # FinServ extension (FS-18): In addition to ModelQuality drift monitoring, the
    # FinServ guide (PDF §1.2.14) calls out low-entropy classification monitoring
    # as an early-warning indicator of training-data poisoning. See
    # docs/SECURITY_CHECKS_FINSERV.md (FS-18 → SM-23
    # extension note) for the remediation step to add.
    logger.debug("Starting check for model drift detection")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        endpoints_without_monitoring = []
        endpoints_with_monitoring = []
        monitoring_issues = []

        try:
            # Get all InService endpoints
            paginator = sagemaker_client.get_paginator("list_endpoints")
            endpoints = []

            for page in paginator.paginate():
                for endpoint in page.get("Endpoints", []):
                    if endpoint.get("EndpointStatus") == "InService":
                        endpoints.append(endpoint.get("EndpointName"))

            # Get all monitoring schedules
            monitoring_schedules = {}
            schedule_paginator = sagemaker_client.get_paginator(
                "list_monitoring_schedules"
            )

            for page in schedule_paginator.paginate():
                for schedule in page.get("MonitoringScheduleSummaries", []):
                    endpoint_name = schedule.get("EndpointName")
                    if endpoint_name:
                        if endpoint_name not in monitoring_schedules:
                            monitoring_schedules[endpoint_name] = []
                        monitoring_schedules[endpoint_name].append(
                            {
                                "name": schedule.get("MonitoringScheduleName"),
                                "type": schedule.get("MonitoringType", "Unknown"),
                                "status": schedule.get("MonitoringScheduleStatus"),
                            }
                        )

            # Check each endpoint for monitoring
            for endpoint_name in endpoints:
                if endpoint_name not in monitoring_schedules:
                    endpoints_without_monitoring.append(endpoint_name)
                else:
                    schedules = monitoring_schedules[endpoint_name]
                    endpoints_with_monitoring.append(endpoint_name)

                    # Check for comprehensive monitoring
                    monitoring_types = [s["type"] for s in schedules]

                    # Check if data quality monitoring is configured
                    if "DataQuality" not in monitoring_types:
                        monitoring_issues.append(
                            {
                                "endpoint": endpoint_name,
                                "issue": "Missing Data Quality Monitoring",
                                "details": f"Endpoint '{endpoint_name}' does not have data quality monitoring configured.",
                            }
                        )

                    # Check if model quality monitoring is configured
                    if "ModelQuality" not in monitoring_types:
                        monitoring_issues.append(
                            {
                                "endpoint": endpoint_name,
                                "issue": "Missing Model Quality Monitoring",
                                "details": f"Endpoint '{endpoint_name}' does not have model quality monitoring configured.",
                            }
                        )

                    # Check for inactive schedules
                    for schedule in schedules:
                        if schedule["status"] != "Scheduled":
                            monitoring_issues.append(
                                {
                                    "endpoint": endpoint_name,
                                    "issue": "Inactive Monitoring Schedule",
                                    "details": f"Monitoring schedule '{schedule['name']}' for endpoint '{endpoint_name}' is {schedule['status']}, not actively scheduled.",
                                }
                            )

        except Exception as e:
            logger.error(f"Error checking model drift detection: {str(e)}")

        # Generate findings
        if endpoints_without_monitoring:
            for endpoint in endpoints_without_monitoring[:10]:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-23",
                        finding_name="Model Drift Detection Not Configured",
                        finding_details=f"Endpoint '{endpoint}' has no Model Monitor schedules configured. Model drift and data quality issues will not be detected.",
                        resolution="Configure Model Monitor with data quality, model quality, bias, and feature attribution drift monitoring for production endpoints.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

            if len(endpoints_without_monitoring) > 10:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-23",
                        finding_name="Model Drift Detection Summary",
                        finding_details=f"Found {len(endpoints_without_monitoring)} total endpoints without drift detection (showing first 10)",
                        resolution="Configure Model Monitor for all production endpoints",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )

        if monitoring_issues:
            for issue in monitoring_issues[:10]:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-23",
                        finding_name=f"Model Drift Detection - {issue['issue']}",
                        finding_details=issue["details"],
                        resolution="Configure comprehensive monitoring including data quality, model quality, bias drift, and feature attribution drift monitoring.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor.html",
                        severity="Low",
                        status="Failed",
                        region=region,
                    )
                )

        if not endpoints_without_monitoring and not monitoring_issues:
            if endpoints_with_monitoring:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-23",
                        finding_name="Model Drift Detection Check",
                        finding_details=f"All {len(endpoints_with_monitoring)} InService endpoints have drift detection monitoring configured.",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-23",
                        finding_name="Model Drift Detection Check",
                        finding_details="No InService endpoints found to monitor.",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(f"Error in check_model_drift_detection: {str(e)}", exc_info=True)
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-23",
                    "Model Drift Detection Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_ab_testing_shadow_deployment(region: str = "") -> Dict[str, Any]:
    """
    Check if endpoints are configured with proper A/B testing or shadow deployment patterns.
    Validates production variant configurations for safe model deployment.
    """
    logger.debug("Starting check for A/B testing and shadow deployment patterns")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        single_variant_endpoints = []
        multi_variant_endpoints = []
        shadow_endpoints = []

        try:
            paginator = sagemaker_client.get_paginator("list_endpoints")
            for page in paginator.paginate():
                for endpoint in page.get("Endpoints", []):
                    endpoint_name = endpoint.get("EndpointName")
                    endpoint_status = endpoint.get("EndpointStatus")

                    if endpoint_name and endpoint_status == "InService":
                        try:
                            endpoint_details = sagemaker_client.describe_endpoint(
                                EndpointName=endpoint_name
                            )

                            production_variants = endpoint_details.get(
                                "ProductionVariants", []
                            )
                            shadow_variants = endpoint_details.get(
                                "ShadowProductionVariants", []
                            )

                            if shadow_variants:
                                shadow_endpoints.append(
                                    {
                                        "name": endpoint_name,
                                        "shadow_variants": len(shadow_variants),
                                        "production_variants": len(production_variants),
                                    }
                                )
                            elif len(production_variants) > 1:
                                # Check if it's A/B testing (multiple variants with traffic split)
                                variant_weights = [
                                    v.get("CurrentWeight", 0)
                                    for v in production_variants
                                ]
                                if all(w > 0 for w in variant_weights):
                                    multi_variant_endpoints.append(
                                        {
                                            "name": endpoint_name,
                                            "variants": len(production_variants),
                                            "weights": variant_weights,
                                        }
                                    )
                                else:
                                    single_variant_endpoints.append(endpoint_name)
                            else:
                                single_variant_endpoints.append(endpoint_name)

                        except Exception as e:
                            logger.warning(
                                f"Error describing endpoint {endpoint_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing endpoints: {str(e)}")

        # Generate findings - this is informational, not a failure
        total_endpoints = (
            len(single_variant_endpoints)
            + len(multi_variant_endpoints)
            + len(shadow_endpoints)
        )

        if total_endpoints == 0:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-24",
                    finding_name="A/B Testing and Shadow Deployment Check",
                    finding_details="No InService endpoints found.",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-ab-testing.html",
                    severity="Low",
                    status="Passed",
                    region=region,
                )
            )
        else:
            # Report on shadow deployments (best practice)
            if shadow_endpoints:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-24",
                        finding_name="Shadow Deployment Pattern Detected",
                        finding_details=f"Found {len(shadow_endpoints)} endpoint(s) using shadow deployment pattern for safe model validation. This is a recommended practice for production deployments.",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-shadow-deployment.html",
                        severity="Low",
                        status="Passed",
                        region=region,
                    )
                )

            # Report on A/B testing
            if multi_variant_endpoints:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-24",
                        finding_name="A/B Testing Pattern Detected",
                        finding_details=f"Found {len(multi_variant_endpoints)} endpoint(s) using A/B testing with multiple production variants. This enables gradual rollout and comparison of model versions.",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-ab-testing.html",
                        severity="Low",
                        status="Passed",
                        region=region,
                    )
                )

            # Report on single variant endpoints - informational, not necessarily bad
            if single_variant_endpoints and len(single_variant_endpoints) > 5:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-24",
                        finding_name="Single Variant Endpoints",
                        finding_details=f"Found {len(single_variant_endpoints)} endpoint(s) with single production variants. Consider using A/B testing or shadow deployments for safer model updates in production.",
                        resolution="For production-critical endpoints, consider implementing A/B testing (multiple production variants) or shadow deployments to validate new model versions before full deployment.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-ab-testing.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )
            elif not shadow_endpoints and not multi_variant_endpoints:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-24",
                        finding_name="Safe Deployment Patterns Check",
                        finding_details=f"Found {len(single_variant_endpoints)} endpoint(s) without A/B testing or shadow deployment patterns configured.",
                        resolution="Consider implementing A/B testing or shadow deployments for production endpoints to enable safe model updates.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-ab-testing.html",
                        severity="Informational",
                        status="N/A",
                        region=region,
                    )
                )
            else:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-24",
                        finding_name="Safe Deployment Patterns Check",
                        finding_details=f"Safe deployment patterns are being utilized. {len(shadow_endpoints)} shadow deployments, {len(multi_variant_endpoints)} A/B tests configured.",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-ab-testing.html",
                        severity="Low",
                        status="Passed",
                        region=region,
                    )
                )

        return findings

    except Exception as e:
        logger.error(
            f"Error in check_ab_testing_shadow_deployment: {str(e)}", exc_info=True
        )
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-24",
                    "A/B Testing and Shadow Deployment Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_ml_lineage_tracking(region: str = "") -> Dict[str, Any]:
    """
    Check if ML Lineage Tracking is being used to track model artifacts and experiments.
    Validates that experiments, trials, and artifact associations are configured.
    """
    logger.debug("Starting check for ML Lineage Tracking")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )

        experiments_found = False
        trials_found = False
        lineage_issues = []

        try:
            # Check for Experiments
            try:
                experiments_response = sagemaker_client.list_experiments(MaxResults=10)
                experiments = experiments_response.get("ExperimentSummaries", [])
                experiments_found = len(experiments) > 0

                if experiments_found:
                    # Check trial status for recent experiments
                    for experiment in experiments[:5]:
                        experiment_name = experiment.get("ExperimentName")
                        try:
                            trials_response = sagemaker_client.list_trials(
                                ExperimentName=experiment_name, MaxResults=10
                            )
                            trials = trials_response.get("TrialSummaries", [])
                            if trials:
                                trials_found = True
                        except Exception as e:
                            logger.warning(
                                f"Error listing trials for experiment {experiment_name}: {str(e)}"
                            )

            except Exception as e:
                # Enumeration itself failed (e.g. AccessDenied) — re-raise so
                # the outer handler reports COULD_NOT_ASSESS rather than
                # silently falling through to a "no resources found" N/A.
                logger.warning(f"Error listing experiments: {str(e)}")
                raise

            # Check for Model Package lineage
            try:
                model_packages_paginator = sagemaker_client.get_paginator(
                    "list_model_package_groups"
                )
                for page in model_packages_paginator.paginate(MaxResults=10):
                    for group in page.get("ModelPackageGroupSummaryList", []):
                        group_name = group.get("ModelPackageGroupName")
                        try:
                            models_response = sagemaker_client.list_model_packages(
                                ModelPackageGroupName=group_name, MaxResults=5
                            )
                            for model_pkg in models_response.get(
                                "ModelPackageSummaryList", []
                            ):
                                model_arn = model_pkg.get("ModelPackageArn")
                                try:
                                    # Check if model has lineage associations
                                    associations = sagemaker_client.list_associations(
                                        SourceArn=model_arn, MaxResults=5
                                    )
                                    if not associations.get("AssociationSummaries"):
                                        lineage_issues.append(
                                            {
                                                "type": "Missing Lineage",
                                                "resource": model_pkg.get(
                                                    "ModelPackageName", model_arn
                                                ),
                                                "details": "Model package has no lineage associations. Training data and experiment lineage not tracked.",
                                            }
                                        )
                                except Exception:
                                    # list_associations might not be available or might fail
                                    pass
                        except Exception as e:
                            logger.warning(
                                f"Error checking model packages in group {group_name}: {str(e)}"
                            )
                    break  # Only check first page

            except Exception as e:
                # Enumeration itself failed (e.g. AccessDenied) — re-raise so
                # the outer handler reports COULD_NOT_ASSESS rather than
                # silently falling through to a "no resources found" N/A.
                logger.warning(f"Error checking model package lineage: {str(e)}")
                raise

        except Exception as e:
            # Re-raise so the outer handler (which wraps this whole function)
            # reports COULD_NOT_ASSESS instead of silently swallowing an
            # enumeration failure raised from the nested blocks above.
            logger.error(f"Error in lineage tracking check: {str(e)}")
            raise

        # Generate findings
        if not experiments_found:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-25",
                    finding_name="ML Lineage Tracking - Experiments Not Used",
                    finding_details="No SageMaker Experiments found. ML Lineage tracking through Experiments is not being utilized.",
                    resolution="Implement SageMaker Experiments to track ML training runs, hyperparameters, metrics, and model artifacts. This enables reproducibility and auditability.",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/experiments.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )
        elif not trials_found:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-25",
                    finding_name="ML Lineage Tracking - No Active Trials",
                    finding_details="SageMaker Experiments exist but no trials found. Experiments may not be actively used for tracking training runs.",
                    resolution="Create trials within experiments to track individual training runs, their parameters, and results.",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/experiments.html",
                    severity="Low",
                    status="Failed",
                    region=region,
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-25",
                    finding_name="ML Lineage Tracking - Experiments Active",
                    finding_details="SageMaker Experiments and Trials are being used for ML lineage tracking.",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/experiments.html",
                    severity="Low",
                    status="Passed",
                    region=region,
                )
            )

        # Add lineage issues if found
        for issue in lineage_issues[:5]:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-25",
                    finding_name=f"ML Lineage Tracking - {issue['type']}",
                    finding_details=issue["details"],
                    resolution="Configure lineage associations for model packages to track the full ML pipeline from data to deployed model.",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/lineage-tracking.html",
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(f"Error in check_ml_lineage_tracking: {str(e)}", exc_info=True)
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-25",
                    "ML Lineage Tracking Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    region=region,
                )
            ]
        }


def check_model_registry_usage(permission_cache, region: str = "") -> Dict[str, Any]:
    """
    Check if Amazon Model Registry is being used effectively for model management
    """
    logger.debug("Starting check for Model Registry usage")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client(
            "sagemaker", config=boto3_config, region_name=region
        )
        issues_found = []

        try:
            # Check Model Package Groups
            paginator = sagemaker_client.get_paginator("list_model_package_groups")
            registry_used = False

            for page in paginator.paginate():
                for group in page["ModelPackageGroupSummaryList"]:
                    registry_used = True
                    group_name = group["ModelPackageGroupName"]

                    # Check model versions in the group
                    try:
                        models = sagemaker_client.list_model_packages(
                            ModelPackageGroupName=group_name
                        )

                        if not models.get("ModelPackageSummaryList"):
                            issues_found.append(
                                {
                                    "issue_type": "Empty Model Group",
                                    "details": f"Model group {group_name} has no registered models",
                                    "severity": "Low",
                                    "status": "Failed",
                                }
                            )
                        else:
                            # Check model approval status
                            approved_models = [
                                m
                                for m in models["ModelPackageSummaryList"]
                                if m.get("ModelApprovalStatus") == "Approved"
                            ]
                            if not approved_models:
                                issues_found.append(
                                    {
                                        "issue_type": "No Approved Models",
                                        "details": f"Model group {group_name} has no approved models",
                                        "severity": "Low",
                                        "status": "Failed",
                                    }
                                )

                    except Exception as e:
                        # A per-group check failure (e.g. AccessDenied) is an
                        # unknown state, not a confirmed control failure —
                        # route directly through the COULD_NOT_ASSESS
                        # disposition rather than fabricating a Medium/Failed
                        # result into issues_found.
                        logger.error(
                            f"Error checking models in group {group_name}: {str(e)}"
                        )
                        findings["csv_data"].append(
                            could_not_assess_row(
                                create_finding,
                                "SM-08",
                                "Model Registry Usage Check",
                                e,
                                "https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry.html",
                                region=region,
                            )
                        )

            if not registry_used:
                issues_found.append(
                    {
                        "issue_type": "Registry Not Used",
                        "details": "Model Registry is not being utilized",
                        "severity": "Informational",
                        "status": "N/A",
                    }
                )

        except Exception as e:
            # Enumeration itself failed (e.g. AccessDenied) — re-raise so the
            # outer handler reports COULD_NOT_ASSESS rather than fabricating
            # a High/Failed result.
            logger.error(f"Error checking Model Registry: {str(e)}")
            raise

        if issues_found:
            for issue in issues_found:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-08",
                        finding_name=f"Model Registry {issue['issue_type']}",
                        finding_details=issue["details"],
                        resolution="Implement proper model versioning and approval workflows",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry.html",
                        severity=issue["severity"],
                        status=issue["status"],
                        region=region,
                    )
                )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="SM-08",
                    finding_name="Model Registry Usage Check",
                    finding_details="Model Registry is being used effectively",
                    resolution="No action required",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry.html",
                    severity="Medium",
                    status="Passed",
                    region=region,
                )
            )

        return findings

    except Exception as e:
        logger.error(f"Error in check_model_registry_usage: {str(e)}", exc_info=True)
        return {
            "csv_data": [
                could_not_assess_row(
                    create_finding,
                    "SM-08",
                    "Model Registry Usage Check",
                    e,
                    "https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry.html",
                    region=region,
                )
            ]
        }


def get_role_usage(role_name: str) -> str:
    """
    Check where a specific IAM role is being used
    """
    logger.debug(f"Checking usage for role: {role_name}")
    usage_list = []

    try:
        # Check Lambda functions
        lambda_client = boto3.client("lambda")
        lambda_functions = lambda_client.list_functions()
        for function in lambda_functions["Functions"]:
            if role_name in function["Role"]:
                usage_list.append(f"Lambda: {function['FunctionName']}")
                logger.debug(f"Found role usage in Lambda: {function['FunctionName']}")
    except Exception as e:
        logger.error(f"Error checking Lambda usage: {str(e)}")

    try:
        # Check ECS tasks
        ecs_client = boto3.client("ecs")
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
) -> Dict[str, str]:
    """
    Write CSV reports to S3 bucket
    """
    logger.debug(f"Writing reports to S3 bucket: {bucket_name}")
    try:
        s3_client = boto3.client("s3", config=boto3_config)

        if region:
            csv_file_name = f"sagemaker_security_report_{execution_id}_{region}.csv"
        else:
            csv_file_name = f"sagemaker_security_report_{execution_id}.csv"
        s3_client.put_object(
            Bucket=bucket_name,
            Key=csv_file_name,
            Body=csv_content,
            ContentType="text/csv",
        )

        return {
            "csv_url": f"https://{bucket_name}.s3.amazonaws.com/{csv_file_name}",
        }
    except Exception as e:
        logger.error(f"Error writing to S3: {str(e)}", exc_info=True)
        raise


def lambda_handler(event, context):
    """
    Main Lambda handler
    """
    logger.info("Starting SageMaker security assessment")
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
        # and stale-access violations are not reported once per scanned region.
        # These run before the regional availability gate so they are still emitted
        # even if SageMaker is not available in the primary region.
        if is_primary_region:
            logger.info("Running global SageMaker IAM permissions check (SM-02)")
            sagemaker_iam_findings = check_sagemaker_iam_permissions(
                permission_cache, region=GLOBAL_REGION_LABEL
            )
            all_findings.append(sagemaker_iam_findings)

        # Verify SageMaker is available in this region
        try:
            test_client = boto3.client(
                "sagemaker", config=boto3_config, region_name=region
            )
            test_client.list_notebook_instances(MaxResults=1)
        except EndpointConnectionError:
            logger.info(f"SageMaker service not available in region {region}, skipping")
            all_findings.append(
                {
                    "check_name": "SageMaker Service Availability",
                    "status": "N/A",
                    "details": f"SageMaker is not available in region {region}",
                    "csv_data": [
                        create_finding(
                            check_id="SM-00",
                            finding_name="SageMaker Service Availability",
                            finding_details=f"Amazon SageMaker is not available in region {region}. No checks performed.",
                            resolution="No action required. SageMaker is not deployed in this region.",
                            reference="https://docs.aws.amazon.com/general/latest/gr/sagemaker.html",
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
                    "message": f"SageMaker not available in {region}",
                    "report_url": s3_url,
                },
            }
        except ClientError as e:
            # A region that exists but is not enabled for the account surfaces as
            # an auth/opt-in error rather than a connection failure. Treat it the
            # same as "not available" instead of running every check against it.
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in REGION_UNAVAILABLE_ERROR_CODES:
                logger.info(
                    f"SageMaker not accessible in region {region} ({error_code}), skipping"
                )
                all_findings.append(
                    {
                        "check_name": "SageMaker Service Availability",
                        "status": "N/A",
                        "details": f"SageMaker is not available in region {region}",
                        "csv_data": [
                            create_finding(
                                check_id="SM-00",
                                finding_name="SageMaker Service Availability",
                                finding_details=f"Amazon SageMaker is not available or not enabled in region {region} ({error_code}). No checks performed.",
                                resolution="No action required if the region is intentionally disabled. Otherwise enable the region for this account.",
                                reference="https://docs.aws.amazon.com/general/latest/gr/sagemaker.html",
                                severity="Informational",
                                status="N/A",
                                region=region,
                            )
                        ],
                    }
                )
                csv_content = generate_csv_report(all_findings)
                bucket_name = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
                s3_url = write_to_s3(
                    execution_id, csv_content, bucket_name, region=region
                )
                return {
                    "statusCode": 200,
                    "body": {
                        "message": f"SageMaker not available in {region}",
                        "report_url": s3_url,
                    },
                }
            # Service is reachable but returned another API error (e.g. AccessDenied)
            # — proceed; individual checks handle their own errors.
            logger.info(
                f"SageMaker availability probe returned {error_code}; proceeding with checks"
            )

        logger.info("Running SageMaker internet access check (SageMaker.1, notebooks)")
        sagemaker_internet_access_findings = check_sagemaker_internet_access(
            region=region
        )
        all_findings.append(sagemaker_internet_access_findings)

        logger.info("Running SageMaker domain network access check (repo-specific)")
        sagemaker_domain_network_findings = check_sagemaker_domain_network_access(
            region=region
        )
        all_findings.append(sagemaker_domain_network_findings)

        logger.info("Running SageMaker SSO configuration check")
        sagemaker_sso_findings = check_sagemaker_sso_configuration(region=region)
        all_findings.append(sagemaker_sso_findings)

        logger.info(
            "Running SageMaker notebook storage encryption check (SageMaker.21)"
        )
        sagemaker_notebook_encryption_findings = (
            check_sagemaker_notebook_storage_encryption(region=region)
        )
        all_findings.append(sagemaker_notebook_encryption_findings)

        logger.info(
            "Running SageMaker domain and training job encryption check (repo-specific)"
        )
        sagemaker_domain_training_encryption_findings = (
            check_sagemaker_domain_and_training_job_encryption(region=region)
        )
        all_findings.append(sagemaker_domain_training_encryption_findings)

        logger.info("Running GuardDuty SageMaker monitoring check")
        guardduty_findings = check_guardduty_enabled(region=region)
        all_findings.append(guardduty_findings)

        logger.info("Running SageMaker MLOps features utilization check")
        mlops_findings = check_sagemaker_mlops_utilization(
            permission_cache, region=region
        )
        all_findings.append(mlops_findings)

        logger.info("Running SageMaker Clarify usage check")
        clarify_findings = check_sagemaker_clarify_usage(
            permission_cache, region=region
        )
        all_findings.append(clarify_findings)

        logger.info("Running SageMaker Model Monitor usage check")
        monitor_findings = check_sagemaker_model_monitor_usage(
            permission_cache, region=region
        )
        all_findings.append(monitor_findings)

        logger.info("Running Model Registry usage check")
        registry_findings = check_model_registry_usage(permission_cache, region=region)
        all_findings.append(registry_findings)

        logger.info("Running SageMaker notebook root access check")
        notebook_root_findings = check_sagemaker_notebook_root_access(region=region)
        all_findings.append(notebook_root_findings)

        logger.info("Running SageMaker notebook VPC deployment check")
        notebook_vpc_findings = check_sagemaker_notebook_vpc_deployment(region=region)
        all_findings.append(notebook_vpc_findings)

        logger.info("Running SageMaker model network isolation check")
        model_isolation_findings = check_sagemaker_model_network_isolation(
            region=region
        )
        all_findings.append(model_isolation_findings)

        logger.info("Running SageMaker endpoint instance count check")
        endpoint_instance_findings = check_sagemaker_endpoint_instance_count(
            region=region
        )
        all_findings.append(endpoint_instance_findings)

        logger.info("Running SageMaker monitoring network isolation check")
        monitoring_isolation_findings = check_sagemaker_monitoring_network_isolation(
            region=region
        )
        all_findings.append(monitoring_isolation_findings)

        logger.info("Running SageMaker model container repository check")
        model_repository_findings = check_sagemaker_model_container_repository(
            region=region
        )
        all_findings.append(model_repository_findings)

        logger.info("Running SageMaker Feature Store encryption check")
        feature_store_encryption_findings = check_sagemaker_feature_store_encryption(
            region=region
        )
        all_findings.append(feature_store_encryption_findings)

        logger.info("Running SageMaker data quality job encryption check")
        data_quality_encryption_findings = check_sagemaker_data_quality_encryption(
            region=region
        )
        all_findings.append(data_quality_encryption_findings)

        # Additional AWS Security Hub Controls
        logger.info("Running SageMaker processing job encryption check (SageMaker.10)")
        processing_job_encryption_findings = check_sagemaker_processing_job_encryption(
            region=region
        )
        all_findings.append(processing_job_encryption_findings)

        logger.info("Running SageMaker transform job encryption check (SageMaker.11)")
        transform_job_encryption_findings = check_sagemaker_transform_job_encryption(
            region=region
        )
        all_findings.append(transform_job_encryption_findings)

        logger.info(
            "Running SageMaker hyperparameter tuning job encryption check (SageMaker.12)"
        )
        hyperparameter_tuning_encryption_findings = (
            check_sagemaker_hyperparameter_tuning_encryption(region=region)
        )
        all_findings.append(hyperparameter_tuning_encryption_findings)

        logger.info("Running SageMaker compilation job encryption check (SageMaker.13)")
        compilation_job_encryption_findings = (
            check_sagemaker_compilation_job_encryption(region=region)
        )
        all_findings.append(compilation_job_encryption_findings)

        logger.info(
            "Running SageMaker AutoML job network isolation check (SageMaker.15)"
        )
        automl_network_isolation_findings = check_sagemaker_automl_network_isolation(
            region=region
        )
        all_findings.append(automl_network_isolation_findings)

        # PR-3: Security Hub gap-closure checks (Clarify / Model Monitor job
        # definitions, notebook platform, feature store, inference experiments)
        logger.info("Running SageMaker notebook platform check (SageMaker.8)")
        all_findings.append(check_sagemaker_notebook_platform(region=region))

        logger.info(
            "Running SageMaker explainability traffic encryption check (SageMaker.10)"
        )
        all_findings.append(
            check_sagemaker_explainability_traffic_encryption(region=region)
        )

        logger.info(
            "Running SageMaker data quality network isolation check (SageMaker.11)"
        )
        all_findings.append(
            check_sagemaker_data_quality_network_isolation(region=region)
        )

        logger.info(
            "Running SageMaker model bias network isolation check (SageMaker.12)"
        )
        all_findings.append(check_sagemaker_model_bias_network_isolation(region=region))

        logger.info(
            "Running SageMaker model quality traffic encryption check (SageMaker.13)"
        )
        all_findings.append(
            check_sagemaker_model_quality_traffic_encryption(region=region)
        )

        logger.info(
            "Running SageMaker model bias traffic encryption check (SageMaker.15)"
        )
        all_findings.append(check_sagemaker_model_bias_traffic_encryption(region=region))

        logger.info(
            "Running SageMaker online feature store encryption check (SageMaker.18)"
        )
        all_findings.append(
            check_sagemaker_online_feature_store_encryption(region=region)
        )

        logger.info(
            "Running SageMaker explainability network isolation check (SageMaker.20)"
        )
        all_findings.append(
            check_sagemaker_explainability_network_isolation(region=region)
        )

        logger.info("Running SageMaker monitoring traffic encryption check (SageMaker.22)")
        all_findings.append(check_sagemaker_monitoring_traffic_encryption(region=region))

        logger.info(
            "Running SageMaker inference experiment encryption check (SageMaker.23/.24)"
        )
        all_findings.append(
            check_sagemaker_inference_experiment_encryption(region=region)
        )

        logger.info(
            "Running SageMaker model quality network isolation check (SageMaker.25)"
        )
        all_findings.append(
            check_sagemaker_model_quality_network_isolation(region=region)
        )

        # Model Governance Checks
        logger.info("Running model approval workflow check")
        model_approval_workflow_findings = check_model_approval_workflow(region=region)
        all_findings.append(model_approval_workflow_findings)

        logger.info("Running model drift detection check")
        model_drift_detection_findings = check_model_drift_detection(region=region)
        all_findings.append(model_drift_detection_findings)

        logger.info("Running A/B testing and shadow deployment check")
        ab_testing_findings = check_ab_testing_shadow_deployment(region=region)
        all_findings.append(ab_testing_findings)

        logger.info("Running ML lineage tracking check")
        ml_lineage_tracking_findings = check_ml_lineage_tracking(region=region)
        all_findings.append(ml_lineage_tracking_findings)

        # Generate and upload report
        logger.info("Generating reports")
        csv_content = generate_csv_report(all_findings)

        bucket_name = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
        if not bucket_name:
            raise ValueError(
                "AIML_ASSESSMENT_BUCKET_NAME environment variable is not set"
            )

        logger.info("Writing reports to S3")
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
