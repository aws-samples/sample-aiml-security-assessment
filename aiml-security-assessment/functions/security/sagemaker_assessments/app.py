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
    Check if SageMaker notebook instances and domains have direct internet access
    """
    logger.debug("Starting check for SageMaker direct internet access")
    try:
        findings = {"csv_data": []}

        instances_with_direct_access = []
        domains_with_direct_access = []
        total_resources_checked = 0

        # Create SageMaker client
        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)

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

        # Check SageMaker Domains
        try:
            paginator = sagemaker_client.get_paginator("list_domains")
            for page in paginator.paginate():
                for domain in page.get("Domains", []):
                    domain_id = domain.get("DomainId")
                    if domain_id:
                        # Get detailed information about the domain
                        domain_details = sagemaker_client.describe_domain(
                            DomainId=domain_id
                        )

                        vpc_id = domain_details.get("DomainSettings", {}).get(
                            "SecurityGroupIds", ["N/A"]
                        )[0]
                        domain_name = domain_details.get("DomainName", "N/A")

                        # Check network access type
                        if domain_details.get("AppNetworkAccessType") != "VpcOnly":
                            domains_with_direct_access.append(
                                {
                                    "domain_id": domain_id,
                                    "name": domain_name,
                                    "vpc_id": vpc_id,
                                }
                            )
                        total_resources_checked += 1
        except Exception as e:
            logger.error(f"Error checking domains: {str(e)}")

        # Generate findings
        if instances_with_direct_access or domains_with_direct_access:
            findings["status"] = "WARN"

            # Add findings for notebook instances
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

            # Add findings for domains
            for domain in domains_with_direct_access:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-01",
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
            findings["details"] = (
                "No SageMaker resources found with direct internet access"
            )
            if total_resources_checked > 0:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-01",
                        finding_name="SageMaker Internet Access Check",
                        finding_details="All SageMaker resources are properly configured to use VPC connectivity",
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
                        finding_details="No SageMaker notebook instances or domains found to check",
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
                create_finding(
                    check_id="SM-01",
                    finding_name="SageMaker Internet Access Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="High",
                    status="Failed",
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
        guardduty_client = boto3.client("guardduty", config=boto3_config, region_name=region)

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
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        findings["csv_data"].append(
            create_finding(
                check_id="SM-04",
                finding_name="GuardDuty Check Error",
                finding_details=f"Error checking GuardDuty status: {error_code} - {error_message}",
                resolution="Ensure proper IAM permissions to check GuardDuty status",
                reference="https://docs.aws.amazon.com/guardduty/latest/ug/security-iam.html",
                severity="High",
                status="Failed",
                region=region,
            )
        )
    except Exception as e:
        findings["csv_data"].append(
            create_finding(
                check_id="SM-04",
                finding_name="GuardDuty Check Error",
                finding_details=f"Unexpected error checking GuardDuty status: {str(e)}",
                resolution="Investigate and resolve the unexpected error",
                reference="https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html",
                severity="High",
                status="Failed",
                region=region,
            )
        )

    return findings


def check_sagemaker_iam_permissions(permission_cache, region: str = "") -> Dict[str, Any]:
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
            "check_name": "SageMaker IAM Permissions Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [],
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
        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)
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
            "check_name": "SageMaker SSO Configuration Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [],
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


def check_sagemaker_data_protection(region: str = "") -> Dict[str, Any]:
    """
    Check SageMaker data protection configurations including encryption at rest and in transit
    """
    logger.debug("Starting check for SageMaker data protection")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)

        # Track resources with encryption issues
        resources_with_aws_managed_keys = []
        resources_without_encryption = []
        resources_without_vpc_encryption = []
        total_resources_checked = 0

        # Check Notebook Instances
        try:
            paginator = sagemaker_client.get_paginator("list_notebook_instances")
            for page in paginator.paginate():
                for instance in page.get("NotebookInstances", []):
                    instance_name = instance.get("NotebookInstanceName")
                    if instance_name:
                        instance_details = sagemaker_client.describe_notebook_instance(
                            NotebookInstanceName=instance_name
                        )
                        total_resources_checked += 1

                        # Check KMS key usage
                        kms_key_id = instance_details.get("KmsKeyId")
                        if not kms_key_id:
                            resources_without_encryption.append(
                                {
                                    "type": "Notebook Instance",
                                    "name": instance_name,
                                    "issue": "No KMS key configured",
                                }
                            )
                        elif "aws/sagemaker" in kms_key_id:
                            resources_with_aws_managed_keys.append(
                                {
                                    "type": "Notebook Instance",
                                    "name": instance_name,
                                    "key_id": kms_key_id,
                                }
                            )
        except Exception as e:
            logger.error(f"Error checking notebook instances encryption: {str(e)}")

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

                        # Check KMS key usage for domain
                        kms_key_id = domain_details.get("KmsKeyId")
                        if not kms_key_id:
                            resources_without_encryption.append(
                                {
                                    "type": "Domain",
                                    "name": domain_details.get("DomainName", domain_id),
                                    "issue": "No KMS key configured",
                                }
                            )
                        elif "aws/sagemaker" in kms_key_id:
                            resources_with_aws_managed_keys.append(
                                {
                                    "type": "Domain",
                                    "name": domain_details.get("DomainName", domain_id),
                                    "key_id": kms_key_id,
                                }
                            )

                        # Check VPC configuration
                        vpc_id = domain_details.get("VpcId")
                        subnet_ids = domain_details.get("SubnetIds", [])
                        if not vpc_id or not subnet_ids:
                            resources_without_vpc_encryption.append(
                                {
                                    "type": "Domain",
                                    "name": domain_details.get("DomainName", domain_id),
                                    "issue": "No VPC configuration",
                                }
                            )
        except Exception as e:
            logger.error(f"Error checking domain encryption: {str(e)}")

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

                        # Check output encryption
                        output_config = job_details.get("OutputDataConfig", {})
                        kms_key_id = output_config.get("KmsKeyId")

                        if not kms_key_id:
                            resources_without_encryption.append(
                                {
                                    "type": "Training Job",
                                    "name": job_name,
                                    "issue": "No output encryption configured",
                                }
                            )
                        elif "aws/sagemaker" in kms_key_id:
                            resources_with_aws_managed_keys.append(
                                {
                                    "type": "Training Job",
                                    "name": job_name,
                                    "key_id": kms_key_id,
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

        # Generate findings
        if (
            resources_without_encryption
            or resources_with_aws_managed_keys
            or resources_without_vpc_encryption
        ):
            # Resources without encryption
            for resource in resources_without_encryption:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-03",
                        finding_name="Missing Encryption Configuration",
                        finding_details=f"{resource['type']} '{resource['name']}' - {resource['issue']}",
                        resolution="Configure encryption using AWS KMS customer managed keys for enhanced security",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/key-management.html",
                        severity="High",
                        status="Failed",
                        region=region,
                    )
                )

            # Resources using AWS managed keys
            for resource in resources_with_aws_managed_keys:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-03",
                        finding_name="AWS Managed Key Usage",
                        finding_details=f"{resource['type']} '{resource['name']}' uses AWS managed key {resource['key_id']}",
                        resolution="Consider using customer managed keys for better control over encryption",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/key-management.html",
                        severity="Low",
                        status="Failed",
                        region=region,
                    )
                )

            # Resources without VPC encryption
            for resource in resources_without_vpc_encryption:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-03",
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
                        check_id="SM-03",
                        finding_name="Data Protection Check",
                        finding_details="All resources use appropriate encryption configurations",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                        severity="High",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-03",
                        finding_name="Data Protection Check",
                        finding_details="No SageMaker resources found to check for data protection",
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
            f"Error in check_sagemaker_data_protection: {str(e)}", exc_info=True
        )
        return {
            "csv_data": [
                create_finding(
                    check_id="SM-03",
                    finding_name="SageMaker Data Protection Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ]
        }


def check_sagemaker_mlops_utilization(permission_cache, region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker MLOps features (Model Registry, Feature Store, and Pipelines)
    are being utilized properly
    """
    logger.debug("Starting check for SageMaker MLOps features utilization")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)
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
            logger.error(f"Error checking Model Registry: {str(e)}")
            issues_found.append(
                {
                    "component": "Model Registry",
                    "issue": f"Error checking configuration: {str(e)}",
                    "impact": "Unable to verify model versioning",
                    "severity": "High",
                    "status": "Failed",
                }
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
            logger.error(f"Error checking Feature Store: {str(e)}")
            issues_found.append(
                {
                    "component": "Feature Store",
                    "issue": f"Error checking configuration: {str(e)}",
                    "impact": "Unable to verify feature management",
                    "severity": "High",
                    "status": "Failed",
                }
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
            logger.error(f"Error checking Pipelines: {str(e)}")
            issues_found.append(
                {
                    "component": "Pipelines",
                    "issue": f"Error checking configuration: {str(e)}",
                    "impact": "Unable to verify pipeline automation",
                    "severity": "High",
                    "status": "Failed",
                }
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
            "check_name": "SageMaker MLOps Features Utilization Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [],
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

        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)
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
            logger.error(f"Error checking Clarify jobs: {str(e)}")
            issues_found.append(
                {
                    "issue_type": "Clarify Check Error",
                    "details": f"Error checking Clarify configuration: {str(e)}",
                    "severity": "High",
                    "status": "Failed",
                }
            )

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
            "check_name": "SageMaker Clarify Usage Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [],
        }


def check_sagemaker_model_monitor_usage(permission_cache, region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker Model Monitor is configured and actively monitoring models
    """
    # FinServ extension (FS-17): The FinServ guide (PDF §1.2.14) asks for Model
    # Monitor data-quality baselines to be refreshed on a regulator-aligned cadence
    # (SR 11-7 ongoing monitoring) and for the baseline statistics to be emitted to
    # CloudWatch under namespace /aws/sagemaker/Endpoints/data-metric with
    # emit_metrics=Enabled. See docs/SECURITY_CHECKS_FINSERV_PART1_INFRA_CONTROLS.md
    # (FS-17 → SM-07 extension note).
    logger.debug("Starting check for SageMaker Model Monitor usage")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)
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
            logger.error(f"Error checking Model Monitor: {str(e)}")
            issues_found.append(
                {
                    "issue_type": "Monitor Check Error",
                    "details": f"Error checking Model Monitor configuration: {str(e)}",
                    "severity": "High",
                    "status": "Failed",
                }
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
            "check_name": "SageMaker Model Monitor Usage Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [],
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

        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)

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
                create_finding(
                    check_id="SM-09",
                    finding_name="SageMaker Notebook Root Access Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="High",
                    status="Failed",
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

        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)

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
                create_finding(
                    check_id="SM-10",
                    finding_name="SageMaker Notebook VPC Deployment Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="High",
                    status="Failed",
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

        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)

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
                        severity="High",
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
                        severity="High",
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
                create_finding(
                    check_id="SM-11",
                    finding_name="SageMaker Model Network Isolation Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ]
        }


def check_sagemaker_endpoint_instance_count(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker endpoints have more than one instance for availability.
    Single instance creates availability risk and single point of compromise.
    Aligns with AWS Security Hub control SageMaker.4
    """
    logger.debug("Starting check for SageMaker endpoint instance count")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)

        endpoints_single_instance = []
        endpoints_multi_instance = []

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

                            for variant in production_variants:
                                current_instance_count = variant.get(
                                    "CurrentInstanceCount", 0
                                )
                                variant_name = variant.get("VariantName", "Unknown")

                                if current_instance_count <= 1:
                                    endpoints_single_instance.append(
                                        {
                                            "endpoint_name": endpoint_name,
                                            "variant_name": variant_name,
                                            "instance_count": current_instance_count,
                                        }
                                    )
                                else:
                                    endpoints_multi_instance.append(
                                        {
                                            "endpoint_name": endpoint_name,
                                            "variant_name": variant_name,
                                            "instance_count": current_instance_count,
                                        }
                                    )

                        except Exception as e:
                            logger.warning(
                                f"Error describing endpoint {endpoint_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing endpoints: {str(e)}")

        if endpoints_single_instance:
            for endpoint in endpoints_single_instance:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-12",
                        finding_name="SageMaker Endpoint Single Instance",
                        finding_details=f"Endpoint '{endpoint['endpoint_name']}' variant '{endpoint['variant_name']}' has only {endpoint['instance_count']} instance(s). Single instance creates availability risk and no failover capability.",
                        resolution="Configure production endpoints with at least 2 instances across multiple Availability Zones for high availability and fault tolerance.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/endpoint-auto-scaling.html",
                        severity="Medium",
                        status="Failed",
                        region=region,
                    )
                )
        else:
            if endpoints_multi_instance:
                # Endpoints exist and all have multiple instances - Passed
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-12",
                        finding_name="SageMaker Endpoint Instance Count Check",
                        finding_details=f"All {len(endpoints_multi_instance)} endpoint variants have multiple instances",
                        resolution="No action required",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/endpoint-auto-scaling.html",
                        severity="Medium",
                        status="Passed",
                        region=region,
                    )
                )
            else:
                # No InService endpoints found - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-12",
                        finding_name="SageMaker Endpoint Instance Count Check",
                        finding_details="No InService endpoints found",
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
                create_finding(
                    check_id="SM-12",
                    finding_name="SageMaker Endpoint Instance Count Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ]
        }


def check_sagemaker_monitoring_network_isolation(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker monitoring schedules have network isolation enabled.
    Aligns with AWS Security Hub control SageMaker.14
    """
    logger.debug("Starting check for SageMaker monitoring schedule network isolation")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)

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

                            job_definition = schedule_details.get(
                                "MonitoringScheduleConfig", {}
                            ).get("MonitoringJobDefinition", {})
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

        if schedules_without_isolation:
            for schedule in schedules_without_isolation:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-13",
                        finding_name="SageMaker Monitoring Network Isolation Disabled",
                        finding_details=f"Monitoring schedule '{schedule['name']}' does not have network isolation enabled. Monitoring jobs can make outbound network calls.",
                        resolution="Enable network isolation in the monitoring job definition NetworkConfig to prevent outbound network access.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-network-isolation.html",
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
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-network-isolation.html",
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
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-network-isolation.html",
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
                create_finding(
                    check_id="SM-13",
                    finding_name="SageMaker Monitoring Network Isolation Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ]
        }


def check_sagemaker_model_container_repository(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker models pull container images from private ECR in VPC.
    Using Platform mode exposes supply chain risks.
    Aligns with AWS Security Hub control SageMaker.16
    """
    logger.debug("Starting check for SageMaker model container repository access")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)

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

                            # Check primary container
                            primary_container = model_details.get(
                                "PrimaryContainer", {}
                            )
                            image_config = primary_container.get("ImageConfig", {})
                            repository_access_mode = image_config.get(
                                "RepositoryAccessMode", "Platform"
                            )

                            if repository_access_mode == "Platform":
                                models_platform_mode.append(
                                    {
                                        "name": model_name,
                                        "image": primary_container.get(
                                            "Image", "Unknown"
                                        )[:50],
                                    }
                                )
                            else:
                                models_vpc_mode.append(model_name)

                            # Check additional containers
                            for container in model_details.get("Containers", []):
                                container_image_config = container.get(
                                    "ImageConfig", {}
                                )
                                container_access_mode = container_image_config.get(
                                    "RepositoryAccessMode", "Platform"
                                )

                                if container_access_mode == "Platform":
                                    container_name = container.get(
                                        "ContainerHostname", "Unknown"
                                    )
                                    if {
                                        "name": model_name,
                                        "container": container_name,
                                    } not in models_platform_mode:
                                        models_platform_mode.append(
                                            {
                                                "name": model_name,
                                                "container": container_name,
                                            }
                                        )

                        except Exception as e:
                            logger.warning(
                                f"Error describing model {model_name}: {str(e)}"
                            )

        except Exception as e:
            logger.error(f"Error listing models: {str(e)}")

        if models_platform_mode:
            # Limit findings
            for model in models_platform_mode[:15]:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-14",
                        finding_name="SageMaker Model Platform Repository Access",
                        finding_details=f"Model '{model['name']}' uses Platform repository access mode. Container images are pulled from public/external registries, exposing supply chain risks.",
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
                # No models found or all use default Platform access - N/A
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-14",
                        finding_name="SageMaker Model Repository Access Check",
                        finding_details="No models found or all use default Platform access",
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
                create_finding(
                    check_id="SM-14",
                    finding_name="SageMaker Model Container Repository Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="High",
                    status="Failed",
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

        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)

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
                        severity="High",
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
                create_finding(
                    check_id="SM-15",
                    finding_name="SageMaker Feature Store Encryption Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="High",
                    status="Failed",
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

        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)

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
                create_finding(
                    check_id="SM-16",
                    finding_name="SageMaker Data Quality Encryption Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ]
        }


def check_sagemaker_processing_job_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker processing jobs have volume encryption enabled.
    Aligns with AWS Security Hub control SageMaker.10
    """
    logger.debug("Starting check for SageMaker processing job encryption")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)

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
                create_finding(
                    check_id="SM-17",
                    finding_name="SageMaker Processing Job Encryption Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ]
        }


def check_sagemaker_transform_job_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker transform jobs have volume encryption enabled.
    Aligns with AWS Security Hub control SageMaker.11
    """
    logger.debug("Starting check for SageMaker transform job encryption")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)

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
                create_finding(
                    check_id="SM-18",
                    finding_name="SageMaker Transform Job Encryption Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ]
        }


def check_sagemaker_hyperparameter_tuning_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker hyperparameter tuning jobs have volume encryption enabled.
    Aligns with AWS Security Hub control SageMaker.12
    """
    logger.debug("Starting check for SageMaker hyperparameter tuning job encryption")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)

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
                create_finding(
                    check_id="SM-19",
                    finding_name="SageMaker Hyperparameter Tuning Encryption Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ]
        }


def check_sagemaker_compilation_job_encryption(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker compilation jobs have volume encryption enabled.
    Aligns with AWS Security Hub control SageMaker.13
    """
    logger.debug("Starting check for SageMaker compilation job encryption")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)

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
                create_finding(
                    check_id="SM-20",
                    finding_name="SageMaker Compilation Job Encryption Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
            ]
        }


def check_sagemaker_automl_network_isolation(region: str = "") -> Dict[str, Any]:
    """
    Check if SageMaker AutoML (Autopilot) jobs have network isolation enabled.
    Aligns with AWS Security Hub control SageMaker.15
    """
    logger.debug("Starting check for SageMaker AutoML job network isolation")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)

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

        if jobs_without_isolation:
            for job in jobs_without_isolation[:15]:
                findings["csv_data"].append(
                    create_finding(
                        check_id="SM-21",
                        finding_name="SageMaker AutoML Job Network Isolation Disabled",
                        finding_details=f"AutoML job '{job['name']}' does not have inter-container traffic encryption enabled. Data transmitted between containers during training is not encrypted.",
                        resolution="Enable EnableInterContainerTrafficEncryption in AutoMLJobConfig.SecurityConfig when creating AutoML jobs.",
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/autopilot-security.html",
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
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/autopilot-security.html",
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
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/autopilot-security.html",
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
                        reference="https://docs.aws.amazon.com/sagemaker/latest/dg/autopilot-security.html",
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
                create_finding(
                    check_id="SM-21",
                    finding_name="SageMaker AutoML Network Isolation Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="High",
                    status="Failed",
                    region=region,
                )
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
    # See docs/SECURITY_CHECKS_FINSERV_PART1_INFRA_CONTROLS.md (FS-19 → SM-22
    # extension note) for the detection refinement.
    logger.debug("Starting check for model approval workflow")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)

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
                create_finding(
                    check_id="SM-22",
                    finding_name="Model Approval Workflow Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="High",
                    status="Failed",
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
    # docs/SECURITY_CHECKS_FINSERV_PART1_INFRA_CONTROLS.md (FS-18 → SM-23
    # extension note) for the remediation step to add.
    logger.debug("Starting check for model drift detection")
    try:
        findings = {"csv_data": []}

        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)

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
                create_finding(
                    check_id="SM-23",
                    finding_name="Model Drift Detection Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="High",
                    status="Failed",
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

        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)

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
                create_finding(
                    check_id="SM-24",
                    finding_name="A/B Testing Shadow Deployment Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="High",
                    status="Failed",
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

        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)

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
                logger.warning(f"Error listing experiments: {str(e)}")

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
                logger.warning(f"Error checking model package lineage: {str(e)}")

        except Exception as e:
            logger.error(f"Error in lineage tracking check: {str(e)}")

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
                create_finding(
                    check_id="SM-25",
                    finding_name="ML Lineage Tracking Check",
                    finding_details=f"Error during check: {str(e)}",
                    resolution="Investigate error and retry assessment",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/security.html",
                    severity="High",
                    status="Failed",
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

        sagemaker_client = boto3.client("sagemaker", config=boto3_config, region_name=region)
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
                        logger.error(
                            f"Error checking models in group {group_name}: {str(e)}"
                        )
                        issues_found.append(
                            {
                                "issue_type": "Model Check Error",
                                "details": f"Error checking models in group {group_name}",
                                "severity": "Medium",
                                "status": "Failed",
                            }
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
            logger.error(f"Error checking Model Registry: {str(e)}")
            issues_found.append(
                {
                    "issue_type": "Registry Check Error",
                    "details": f"Error checking Model Registry configuration: {str(e)}",
                    "severity": "High",
                    "status": "Failed",
                }
            )

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
            "check_name": "Model Registry Usage Check",
            "status": "ERROR",
            "details": f"Error during check: {str(e)}",
            "csv_data": [],
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


def write_to_s3(execution_id, csv_content: str, bucket_name: str, region: str = "") -> Dict[str, str]:
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
            test_client = boto3.client("sagemaker", config=boto3_config, region_name=region)
            test_client.list_notebook_instances(MaxResults=1)
        except EndpointConnectionError:
            logger.info(f"SageMaker service not available in region {region}, skipping")
            all_findings.append({
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
            })
            csv_content = generate_csv_report(all_findings)
            bucket_name = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
            s3_url = write_to_s3(execution_id, csv_content, bucket_name, region=region)
            return {"statusCode": 200, "body": {"message": f"SageMaker not available in {region}", "report_url": s3_url}}
        except ClientError as e:
            # A region that exists but is not enabled for the account surfaces as
            # an auth/opt-in error rather than a connection failure. Treat it the
            # same as "not available" instead of running every check against it.
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in REGION_UNAVAILABLE_ERROR_CODES:
                logger.info(f"SageMaker not accessible in region {region} ({error_code}), skipping")
                all_findings.append({
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
                })
                csv_content = generate_csv_report(all_findings)
                bucket_name = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
                s3_url = write_to_s3(execution_id, csv_content, bucket_name, region=region)
                return {"statusCode": 200, "body": {"message": f"SageMaker not available in {region}", "report_url": s3_url}}
            # Service is reachable but returned another API error (e.g. AccessDenied)
            # — proceed; individual checks handle their own errors.
            logger.info(f"SageMaker availability probe returned {error_code}; proceeding with checks")

        logger.info("Running SageMaker internet access check")
        sagemaker_internet_access_findings = check_sagemaker_internet_access(region=region)
        all_findings.append(sagemaker_internet_access_findings)

        logger.info("Running SageMaker SSO configuration check")
        sagemaker_sso_findings = check_sagemaker_sso_configuration(region=region)
        all_findings.append(sagemaker_sso_findings)

        logger.info("Running SageMaker data protection check")
        sagemaker_data_protection_findings = check_sagemaker_data_protection(region=region)
        all_findings.append(sagemaker_data_protection_findings)

        logger.info("Running GuardDuty SageMaker monitoring check")
        guardduty_findings = check_guardduty_enabled(region=region)
        all_findings.append(guardduty_findings)

        logger.info("Running SageMaker MLOps features utilization check")
        mlops_findings = check_sagemaker_mlops_utilization(permission_cache, region=region)
        all_findings.append(mlops_findings)

        logger.info("Running SageMaker Clarify usage check")
        clarify_findings = check_sagemaker_clarify_usage(permission_cache, region=region)
        all_findings.append(clarify_findings)

        logger.info("Running SageMaker Model Monitor usage check")
        monitor_findings = check_sagemaker_model_monitor_usage(permission_cache, region=region)
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
        model_isolation_findings = check_sagemaker_model_network_isolation(region=region)
        all_findings.append(model_isolation_findings)

        logger.info("Running SageMaker endpoint instance count check")
        endpoint_instance_findings = check_sagemaker_endpoint_instance_count(region=region)
        all_findings.append(endpoint_instance_findings)

        logger.info("Running SageMaker monitoring network isolation check")
        monitoring_isolation_findings = check_sagemaker_monitoring_network_isolation(region=region)
        all_findings.append(monitoring_isolation_findings)

        logger.info("Running SageMaker model container repository check")
        model_repository_findings = check_sagemaker_model_container_repository(region=region)
        all_findings.append(model_repository_findings)

        logger.info("Running SageMaker Feature Store encryption check")
        feature_store_encryption_findings = check_sagemaker_feature_store_encryption(region=region)
        all_findings.append(feature_store_encryption_findings)

        logger.info("Running SageMaker data quality job encryption check")
        data_quality_encryption_findings = check_sagemaker_data_quality_encryption(region=region)
        all_findings.append(data_quality_encryption_findings)

        # Additional AWS Security Hub Controls
        logger.info("Running SageMaker processing job encryption check (SageMaker.10)")
        processing_job_encryption_findings = check_sagemaker_processing_job_encryption(region=region)
        all_findings.append(processing_job_encryption_findings)

        logger.info("Running SageMaker transform job encryption check (SageMaker.11)")
        transform_job_encryption_findings = check_sagemaker_transform_job_encryption(region=region)
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
        automl_network_isolation_findings = check_sagemaker_automl_network_isolation(region=region)
        all_findings.append(automl_network_isolation_findings)

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
