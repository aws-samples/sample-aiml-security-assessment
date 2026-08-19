# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AWS HIPAA Compliance Lens for AI/ML
====================================
Implements security checks (HP-01 through HP-07) derived from HIPAA/HITECH
security requirements for AI/ML workloads on AWS.

Focus areas:
- Data at rest encryption (CMK)
- Network isolation (VPC Endpoints, Network Isolation)
- Auditability (CloudWatch Log Masking, CloudTrail)
- Content Safety (PII Redaction)
"""

import csv
import json
import logging
import os
from io import StringIO
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from schema import create_finding

# Boto3 config with adaptive retries
boto3_config = Config(retries={"max_attempts": 10, "mode": "adaptive"})

logger = logging.getLogger()
logger.setLevel(logging.WARNING)

HIPAA_LENS_URL = "https://aws.amazon.com/compliance/hipaa-compliance/"

# Compliance Mapping for HIPAA
COMPLIANCE_MAP = {
    "HP-01": "HIPAA Security Rule 164.312(a)(2)(iv) | 164.312(e)(2)(ii)",
    "HP-02": "HIPAA Security Rule 164.312(a)(2)(iv) | 164.312(e)(2)(ii)",
    "HP-03": "HIPAA Security Rule 164.312(e)(1)",
    "HP-04": "HIPAA Security Rule 164.312(e)(1)",
    "HP-05": "HIPAA Security Rule 164.312(b)",
    "HP-06": "HIPAA Security Rule 164.312(e)(2)(ii) | PII Redaction",
    "HP-07": "HIPAA Security Rule 164.312(c)(1) | Integrity",
}


def _paginate(
    client, operation_name: str, result_key: str, **kwargs
) -> list[dict[str, Any]]:
    method = getattr(client, operation_name)
    items = []
    call_kwargs = dict(kwargs)
    while True:
        resp = method(**call_kwargs)
        items.extend(resp.get(result_key, []) or [])
        next_token = (
            resp.get("nextToken") or resp.get("NextToken") or resp.get("Marker")
        )
        if not next_token:
            break
        call_kwargs[
            "nextToken"
            if "nextToken" in resp
            else "NextToken"
            if "NextToken" in resp
            else "Marker"
        ] = next_token
    return items


def check_bedrock_custom_model_encryption(
    bedrock_client, region: str
) -> list[dict[str, Any]]:
    """HP-01: Verify Bedrock custom models use Customer Managed Keys (CMK)."""
    findings = []
    try:
        models = _paginate(bedrock_client, "list_custom_models", "modelSummaries")
        if not models:
            return []

        for model in models:
            model_arn = model["modelArn"]
            model_details = bedrock_client.get_custom_model(modelIdentifier=model_arn)
            kms_key = model_details.get("customModelKmsKeyId")

            status = "Passed" if kms_key else "Failed"
            severity = "High" if not kms_key else "Informational"

            findings.append(
                create_finding(
                    check_id="HP-01",
                    finding_name="Bedrock Custom Model CMK Encryption",
                    resource_id=model_arn,
                    region=region,
                    status=status,
                    severity=severity,
                    details=f"Model {model['modelName']} is {'encrypted with CMK' if kms_key else 'not using a Customer Managed Key'}.",
                    resolution="Configure a Customer Managed Key (CMK) for Bedrock custom models to meet HIPAA encryption control requirements.",
                    compliance_frameworks=COMPLIANCE_MAP["HP-01"],
                )
            )
    except Exception as e:  # noqa: BLE001
        logger.error(f"Error in HP-01: {e}")
    return findings


def check_bedrock_vpc_endpoints(ec2_client, region: str) -> list[dict[str, Any]]:
    """HP-03: Verify Bedrock VPC Endpoints exist for private connectivity."""
    findings = []
    try:
        # Check for Bedrock and Bedrock Runtime endpoints
        endpoints = _paginate(ec2_client, "describe_vpc_endpoints", "VpcEndpoints")

        bedrock_service = f"com.amazonaws.{region}.bedrock"
        runtime_service = f"com.amazonaws.{region}.bedrock-runtime"

        has_bedrock = any(e["ServiceName"] == bedrock_service for e in endpoints)
        has_runtime = any(e["ServiceName"] == runtime_service for e in endpoints)

        status = "Passed" if (has_bedrock and has_runtime) else "Failed"
        severity = "Medium" if status == "Failed" else "Informational"

        findings.append(
            create_finding(
                check_id="HP-03",
                finding_name="Bedrock VPC Interface Endpoints",
                resource_id=f"vpc-endpoints-{region}",
                region=region,
                status=status,
                severity=severity,
                details=f"VPC Endpoints for Bedrock: {'Found' if has_bedrock else 'Missing'}, Runtime: {'Found' if has_runtime else 'Missing'}.",
                resolution="Create Interface VPC Endpoints for Amazon Bedrock to ensure PHI traffic stays within the AWS network.",
                compliance_frameworks=COMPLIANCE_MAP["HP-03"],
            )
        )
    except Exception as e:  # noqa: BLE001
        logger.error(f"Error in HP-03: {e}")
    return findings


def check_sagemaker_encryption(sagemaker_client, region: str) -> list[dict[str, Any]]:
    """HP-02: Verify SageMaker Endpoints use Customer Managed Keys (CMK)."""
    findings = []
    try:
        endpoints = _paginate(sagemaker_client, "list_endpoints", "Endpoints")
        for ep in endpoints:
            ep_name = ep["EndpointName"]
            desc = sagemaker_client.describe_endpoint(EndpointName=ep_name)
            # Check production variants for KMS keys
            config_name = desc["EndpointConfigName"]
            conf = sagemaker_client.describe_endpoint_config(
                EndpointConfigName=config_name
            )
            kms_key = conf.get("KmsKeyId")

            status = "Passed" if kms_key else "Failed"
            severity = "High" if not kms_key else "Informational"

            findings.append(
                create_finding(
                    check_id="HP-02",
                    finding_name="SageMaker Endpoint CMK Encryption",
                    resource_id=ep["EndpointArn"],
                    region=region,
                    status=status,
                    severity=severity,
                    details=f"Endpoint {ep_name} is {'encrypted with CMK' if kms_key else 'using default AWS encryption'}.",
                    resolution="Encrypt SageMaker endpoints with Customer Managed Keys (CMK) to comply with HIPAA data-at-rest requirements.",
                    compliance_frameworks=COMPLIANCE_MAP["HP-02"],
                )
            )
    except Exception as e:  # noqa: BLE001
        logger.error(f"Error in HP-02: {e}")
    return findings


def check_sagemaker_network_isolation(
    sagemaker_client, region: str
) -> list[dict[str, Any]]:
    """HP-04: Verify SageMaker Training Jobs use Network Isolation."""
    findings = []
    try:
        jobs = _paginate(sagemaker_client, "list_training_jobs", "TrainingJobSummaries")
        for job in jobs:
            job_name = job["TrainingJobName"]
            desc = sagemaker_client.describe_training_job(TrainingJobName=job_name)
            isolated = desc.get("EnableNetworkIsolation", False)

            status = "Passed" if isolated else "Failed"
            severity = "Medium" if not isolated else "Informational"

            findings.append(
                create_finding(
                    check_id="HP-04",
                    finding_name="SageMaker Training Network Isolation",
                    resource_id=job["TrainingJobArn"],
                    region=region,
                    status=status,
                    severity=severity,
                    details=f"Training job {job_name} has network isolation {'enabled' if isolated else 'disabled'}.",
                    resolution="Enable Network Isolation for SageMaker training jobs to prevent unauthorized data exfiltration.",
                    compliance_frameworks=COMPLIANCE_MAP["HP-04"],
                )
            )
    except Exception as e:  # noqa: BLE001
        logger.error(f"Error in HP-04: {e}")
    return findings


def check_cloudwatch_log_masking(logs_client, region: str) -> list[dict[str, Any]]:
    """HP-05: Verify CloudWatch Log Groups have Data Protection Policies (PII Masking)."""
    findings = []
    try:
        log_groups = _paginate(logs_client, "describe_log_groups", "logGroups")
        for lg in log_groups:
            lg_name = lg["logGroupName"]
            # Only check logs related to AI/ML
            if not any(
                k in lg_name.lower()
                for k in ["bedrock", "sagemaker", "aws/lambda/aiml"]
            ):
                continue

            try:
                policy = logs_client.get_data_protection_policy(
                    logGroupIdentifier=lg_name
                )
                has_policy = bool(policy.get("policyDocument"))
            except ClientError:
                has_policy = False

            status = "Passed" if has_policy else "Failed"
            severity = "Medium" if not has_policy else "Informational"

            findings.append(
                create_finding(
                    check_id="HP-05",
                    finding_name="CloudWatch Log PII Masking",
                    resource_id=lg_name,
                    region=region,
                    status=status,
                    severity=severity,
                    details=f"Log group {lg_name} {'has' if has_policy else 'lacks'} a Data Protection Policy.",
                    resolution="Implement CloudWatch Logs Data Protection policies to automatically mask PII/PHI in AI/ML logs.",
                    compliance_frameworks=COMPLIANCE_MAP["HP-05"],
                )
            )
    except Exception as e:  # noqa: BLE001
        logger.error(f"Error in HP-05: {e}")
    return findings


def check_bedrock_guardrail_pii(bedrock_client, region: str) -> list[dict[str, Any]]:
    """HP-06: Verify Bedrock Guardrails have PII Redaction enabled."""
    findings = []
    try:
        guardrails = _paginate(bedrock_client, "list_guardrails", "guardrailSummaries")
        for gr in guardrails:
            gr_id = gr["guardrailId"]
            details = bedrock_client.get_guardrail(guardrailIdentifier=gr_id)
            sensitive_config = details.get("sensitiveInformationPolicy", {})
            pii_entities = sensitive_config.get("piiEntitiesConfig", [])

            has_pii_filter = len(pii_entities) > 0

            status = "Passed" if has_pii_filter else "Failed"
            severity = "High" if not has_pii_filter else "Informational"

            findings.append(
                create_finding(
                    check_id="HP-06",
                    finding_name="Bedrock Guardrail PII Redaction",
                    resource_id=gr["guardrailArn"],
                    region=region,
                    status=status,
                    severity=severity,
                    details=f"Guardrail {gr['name']} {'has' if has_pii_filter else 'lacks'} PII redaction filters.",
                    resolution="Enable PII entity filters in Bedrock Guardrails to prevent PHI leakage in model responses.",
                    compliance_frameworks=COMPLIANCE_MAP["HP-06"],
                )
            )
    except Exception as e:  # noqa: BLE001
        logger.error(f"Error in HP-06: {e}")
    return findings


def check_s3_hipaa_integrity(s3_client, region: str) -> list[dict[str, Any]]:
    """HP-07: Verify S3 Buckets have Versioning and Default Encryption (Integrity/Security)."""
    findings = []
    try:
        buckets = s3_client.list_buckets()["Buckets"]
        for b in buckets:
            b_name = b["Name"]
            # Only check buckets likely containing AI/ML data
            if not any(
                k in b_name.lower()
                for k in ["aiml", "bedrock", "sagemaker", "training", "model"]
            ):
                continue

            # Check Versioning
            versioning = (
                s3_client.get_bucket_versioning(Bucket=b_name).get("Status")
                == "Enabled"
            )
            # Check Encryption
            try:
                s3_client.get_bucket_encryption(Bucket=b_name)
                has_encryption = True
            except ClientError:
                has_encryption = False

            status = "Passed" if (versioning and has_encryption) else "Failed"
            severity = "Medium" if status == "Failed" else "Informational"

            findings.append(
                create_finding(
                    check_id="HP-07",
                    finding_name="S3 HIPAA Data Integrity",
                    resource_id=b_name,
                    region=region,
                    status=status,
                    severity=severity,
                    details=f"Bucket {b_name}: Versioning {'Enabled' if versioning else 'Disabled'}, Encryption {'Enabled' if has_encryption else 'Disabled'}.",
                    resolution="Enable S3 Bucket Versioning and Default Encryption to ensure data integrity and security for HIPAA workloads.",
                    compliance_frameworks=COMPLIANCE_MAP["HP-07"],
                )
            )
    except Exception as e:  # noqa: BLE001
        logger.error(f"Error in HP-07: {e}")
    return findings


def lambda_handler(event, context):
    region = event.get("region", os.environ.get("AWS_REGION", "us-east-1"))
    execution_id = event.get("execution_id", "manual")

    bedrock = boto3.client("bedrock", region_name=region, config=boto3_config)
    ec2 = boto3.client("ec2", region_name=region, config=boto3_config)

    all_findings = []
    all_findings.extend(check_bedrock_custom_model_encryption(bedrock, region))
    all_findings.extend(check_bedrock_vpc_endpoints(ec2, region))

    sagemaker = boto3.client("sagemaker", region_name=region, config=boto3_config)
    all_findings.extend(check_sagemaker_encryption(sagemaker, region))
    all_findings.extend(check_sagemaker_network_isolation(sagemaker, region))

    logs = boto3.client("logs", region_name=region, config=boto3_config)
    all_findings.extend(check_cloudwatch_log_masking(logs, region))

    all_findings.extend(check_bedrock_guardrail_pii(bedrock, region))

    s3_client = boto3.client("s3", config=boto3_config)
    all_findings.extend(check_s3_hipaa_integrity(s3_client, region))

    # Prepare CSV output
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "Check_ID",
            "Finding_Name",
            "Resource_ID",
            "Region",
            "Status",
            "Severity",
            "Details",
            "Resolution",
            "Compliance_Frameworks",
        ],
    )
    writer.writeheader()
    for f in all_findings:
        writer.writerow(
            {
                "Check_ID": f.check_id,
                "Finding_Name": f.finding_name,
                "Resource_ID": f.resource_id,
                "Region": f.region,
                "Status": f.status,
                "Severity": f.severity,
                "Details": f.details,
                "Resolution": f.resolution,
                "Compliance_Frameworks": f.compliance_frameworks,
            }
        )

    csv_content = output.getvalue()

    # Save to S3 (simulating framework behavior)
    s3 = boto3.client("s3", config=boto3_config)
    bucket = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
    s3.put_object(
        Bucket=bucket,
        Key=f"hipaa_security_report_{region}_{execution_id}.csv",
        Body=csv_content,
    )

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": f"HIPAA assessment completed for {region}",
                "findings_count": len(all_findings),
            }
        ),
    }
