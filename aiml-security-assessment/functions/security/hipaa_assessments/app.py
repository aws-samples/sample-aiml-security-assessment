# Copyright (c) Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
AWS HIPAA Compliance Lens for AI/ML
====================================
Implements security checks (HP-01 through HP-07) derived from HIPAA/HITECH
security requirements for AI/ML workloads on AWS.
"""

import csv
import json
import logging
import os
from io import StringIO
from typing import Any, Dict, List

import boto3
from botocore.config import Config
from schema import create_finding

# Boto3 config with adaptive retries
boto3_config = Config(retries=dict(max_attempts=10, mode="adaptive"))

logger = logging.getLogger()
logger.setLevel(logging.ERROR)

HIPAA_LENS_URL = "https://aws.amazon.com/compliance/hipaa-compliance/"


def _paginate(
    client, op_name: str, res_key: str, **kwargs
 ) -> List[Dict[str, Any]]:
    """Helper function to paginate AWS API calls."""
    method = getattr(client, op_name)
    items = []
    call_kwargs = dict(kwargs)
    while True:
        resp = method(**call_kwargs)
        items.extend(resp.get(res_key, []) or [])
        next_token = (
            resp.get("nextToken") or
            resp.get("NextToken") or
            resp.get("Marker")
        )
        if not next_token:
            break
        token_key = (
            "nextToken" if "nextToken" in resp else
            "NextToken" if "NextToken" in resp else "Marker"
        )
        call_kwargs[token_key] = next_token
    return items


def check_bedrock_custom_model_encryption(
    bedrock_client, region: str
) -> Dict[str, Any]:
    """HP-01: Verify Bedrock custom models use Customer Managed Keys (CMK)."""
    csv_data = []
    try:
        models = _paginate(bedrock_client, "list_custom_models", "modelSummaries")
        if not models:
            csv_data.append(create_finding(
                check_id="HP-01",
                finding_name="Bedrock Custom Model CMK Encryption",
                finding_details="No custom models found in region.",
                resolution="No action required.",
                reference=HIPAA_LENS_URL,
                severity="Informational",
                status="Passed",
                region=region
            ))
        for model in models:
            model_arn = model["modelArn"]
            model_details = bedrock_client.get_custom_model(
                modelIdentifier=model_arn
            )
            kms_key = model_details.get("customModelKmsKeyId")
            status = "Passed" if kms_key else "Failed"
            severity = "High" if not kms_key else "Informational"
            details = (
                f"Model {model['modelName']} is "
                f"{'encrypted with CMK' if kms_key else 'not using a CMK'}."
            )
            csv_data.append(create_finding(
                check_id="HP-01",
                finding_name="Bedrock Custom Model CMK Encryption",
                finding_details=details,
                resolution="Configure a CMK for Bedrock custom models.",
                reference=HIPAA_LENS_URL,
                severity=severity,
                status=status,
                region=region
            ))
    except Exception as e:
        logger.error("Error in HP-01: %s", e)
    return {"csv_data": csv_data}


def check_sagemaker_encryption(
    sagemaker_client, region: str
) -> Dict[str, Any]:
    """HP-02: Verify SageMaker Endpoints use Customer Managed Keys (CMK)."""
    csv_data = []
    try:
        endpoints = _paginate(sagemaker_client, "list_endpoints", "Endpoints")
        if not endpoints:
            csv_data.append(create_finding(
                check_id="HP-02",
                finding_name="SageMaker Endpoint CMK Encryption",
                finding_details="No SageMaker endpoints found in region.",
                resolution="No action required.",
                reference=HIPAA_LENS_URL,
                severity="Informational",
                status="Passed",
                region=region
            ))
        for ep in endpoints:
            desc = sagemaker_client.describe_endpoint(
                EndpointName=ep["EndpointName"]
            )
            conf = sagemaker_client.describe_endpoint_config(
                EndpointConfigName=desc["EndpointConfigName"]
            )
            kms_key = conf.get("KmsKeyId")
            status = "Passed" if kms_key else "Failed"
            severity = "High" if not kms_key else "Informational"
            details = (
                f"Endpoint {ep['EndpointName']} "
                f"{'uses CMK' if kms_key else 'uses default encryption'}."
            )
            csv_data.append(create_finding(
                check_id="HP-02",
                finding_name="SageMaker Endpoint CMK Encryption",
                finding_details=details,
                resolution="Encrypt SageMaker endpoints with CMK.",
                reference=HIPAA_LENS_URL,
                severity=severity,
                status=status,
                region=region
            ))
    except Exception as e:
        logger.error("Error in HP-02: %s", e)
    return {"csv_data": csv_data}


def check_bedrock_vpc_endpoints(
    ec2_client, region: str
) -> Dict[str, Any]:
    """HP-03: Verify Bedrock VPC Endpoints exist."""
    csv_data = []
    try:
        endpoints = _paginate(
            ec2_client, "describe_vpc_endpoints", "VpcEndpoints"
        )
        has_bedrock = any(
            e["ServiceName"] == f"com.amazonaws.{region}.bedrock"
            for e in endpoints
        )
        has_runtime = any(
            e["ServiceName"] == f"com.amazonaws.{region}.bedrock-runtime"
            for e in endpoints
        )
        status = "Passed" if (has_bedrock and has_runtime) else "Failed"
        details = (
            f"Bedrock: {'Found' if has_bedrock else 'Missing'}, "
            f"Runtime: {'Found' if has_runtime else 'Missing'}."
        )
        csv_data.append(create_finding(
            check_id="HP-03",
            finding_name="Bedrock VPC Interface Endpoints",
            finding_details=details,
            resolution="Create Interface VPC Endpoints for Amazon Bedrock.",
            reference=HIPAA_LENS_URL,
            severity="Medium" if status == "Failed" else "Informational",
            status=status,
            region=region
        ))
    except Exception as e:
        logger.error("Error in HP-03: %s", e)
    return {"csv_data": csv_data}


def check_sagemaker_network_isolation(
    sagemaker_client, region: str
) -> Dict[str, Any]:
    """HP-04: Verify SageMaker Training Jobs use Network Isolation."""
    csv_data = []
    try:
        jobs = _paginate(
            sagemaker_client, "list_training_jobs", "TrainingJobSummaries"
        )
        if not jobs:
            csv_data.append(create_finding(
                check_id="HP-04",
                finding_name="SageMaker Training Network Isolation",
                finding_details="No training jobs found in region.",
                resolution="No action required.",
                reference=HIPAA_LENS_URL,
                severity="Informational",
                status="Passed",
                region=region
            ))
        for job in jobs:
            desc = sagemaker_client.describe_training_job(
                TrainingJobName=job["TrainingJobName"]
            )
            isolated = desc.get("EnableNetworkIsolation", False)
            csv_data.append(create_finding(
                check_id="HP-04",
                finding_name="SageMaker Training Network Isolation",
                finding_details=f"Job {job['TrainingJobName']} isolation: {isolated}.",
                resolution="Enable Network Isolation for SageMaker training.",
                reference=HIPAA_LENS_URL,
                severity="Medium" if not isolated else "Informational",
                status="Passed" if isolated else "Failed",
                region=region
            ))
    except Exception as e:
        logger.error("Error in HP-04: %s", e)
    return {"csv_data": csv_data}


def check_cloudwatch_log_masking(
    logs_client, region: str
) -> Dict[str, Any]:
    """HP-05: Verify CloudWatch Log Groups have PII Masking."""
    csv_data = []
    try:
        log_groups = _paginate(logs_client, "describe_log_groups", "logGroups")
        targets = ["bedrock", "sagemaker", "aiml"]
        matched_groups = [
            lg for lg in log_groups
            if any(k in lg["logGroupName"].lower() for k in targets)
        ]
        if not matched_groups:
            csv_data.append(create_finding(
                check_id="HP-05",
                finding_name="CloudWatch Log PII Masking",
                finding_details="No AI/ML log groups found in region.",
                resolution="No action required.",
                reference=HIPAA_LENS_URL,
                severity="Informational",
                status="Passed",
                region=region
            ))
        for lg in matched_groups:
            name = lg["logGroupName"]
            try:
                policy_resp = logs_client.get_data_protection_policy(
                    logGroupIdentifier=name
                )
                has_policy = bool(policy_resp.get("policyDocument"))
            except Exception:
                has_policy = False
            csv_data.append(create_finding(
                check_id="HP-05",
                finding_name="CloudWatch Log PII Masking",
                finding_details=f"Log group {name} data protection: {has_policy}.",
                resolution="Implement CloudWatch Logs Data Protection.",
                reference=HIPAA_LENS_URL,
                severity="Medium" if not has_policy else "Informational",
                status="Passed" if has_policy else "Failed",
                region=region
            ))
    except Exception as e:
        logger.error("Error in HP-05: %s", e)
    return {"csv_data": csv_data}


def check_bedrock_guardrail_pii(
    bedrock_client, region: str
) -> Dict[str, Any]:
    """HP-06: Verify Bedrock Guardrails have PII Redaction."""
    csv_data = []
    try:
        guardrails = _paginate(
            bedrock_client, "list_guardrails", "guardrailSummaries"
        )
        if not guardrails:
            csv_data.append(create_finding(
                check_id="HP-06",
                finding_name="Bedrock Guardrail PII Redaction",
                finding_details="No guardrails found in region.",
                resolution="No action required.",
                reference=HIPAA_LENS_URL,
                severity="Informational",
                status="Passed",
                region=region
            ))
        for gr in guardrails:
            details = bedrock_client.get_guardrail(
                guardrailIdentifier=gr["guardrailId"]
            )
            pii_config = details.get(
                "sensitiveInformationPolicy", {}
            ).get("piiEntitiesConfig", [])
            has_pii = len(pii_config) > 0
            csv_data.append(create_finding(
                check_id="HP-06",
                finding_name="Bedrock Guardrail PII Redaction",
                finding_details=f"Guardrail {gr['name']} PII filters: {has_pii}.",
                resolution="Enable PII entity filters in Bedrock Guardrails.",
                reference=HIPAA_LENS_URL,
                severity="High" if not has_pii else "Informational",
                status="Passed" if has_pii else "Failed",
                region=region
            ))
    except Exception as e:
        logger.error("Error in HP-06: %s", e)
    return {"csv_data": csv_data}


def check_s3_hipaa_integrity(
    s3_client, region: str
) -> Dict[str, Any]:
    """HP-07: Verify S3 Buckets have Versioning and Encryption."""
    csv_data = []
    try:
        buckets = s3_client.list_buckets()["Buckets"]
        targets = ["aiml", "bedrock", "sagemaker"]
        matched_buckets = [
            b for b in buckets
            if any(k in b["Name"].lower() for k in targets)
        ]
        if not matched_buckets:
            csv_data.append(create_finding(
                check_id="HP-07",
                finding_name="S3 HIPAA Data Integrity",
                finding_details="No AI/ML buckets found.",
                resolution="No action required.",
                reference=HIPAA_LENS_URL,
                severity="Informational",
                status="Passed",
                region=region
            ))
        for b in matched_buckets:
            name = b["Name"]
            v_resp = s3_client.get_bucket_versioning(Bucket=name)
            v_status = v_resp.get("Status")
            versioning = v_status == "Enabled"
            try:
                s3_client.get_bucket_encryption(Bucket=name)
                has_enc = True
            except Exception:
                has_enc = False
            csv_data.append(create_finding(
                check_id="HP-07",
                finding_name="S3 HIPAA Data Integrity",
                finding_details=f"Bucket {name}: Vers={versioning}, Enc={has_enc}.",
                resolution="Enable S3 Bucket Versioning and Encryption.",
                reference=HIPAA_LENS_URL,
                severity="Medium" if not (versioning and has_enc) else "Informational",
                status="Passed" if (versioning and has_enc) else "Failed",
                region=region
            ))
    except Exception as e:
        logger.error("Error in HP-07: %s", e)
    return {"csv_data": csv_data}


def generate_csv_report(findings: List[Dict[str, Any]]) -> str:
    """Generate CSV report from all security check findings."""
    csv_buffer = StringIO()
    fieldnames = [
        "Check_ID", "Finding", "Finding_Details", "Resolution",
        "Reference", "Severity", "Status", "Region"
    ]
    writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)
    writer.writeheader()
    for finding in findings:
        for row in finding.get("csv_data", []):
            writer.writerow(row)
    return csv_buffer.getvalue()


def lambda_handler(event, context):
    """Main entry point for the HIPAA security assessment Lambda."""
    region = event.get("Region", os.environ.get("AWS_REGION", "us-east-1"))
    execution_id = event["Execution"]["Name"]
    bedrock = boto3.client("bedrock", region_name=region, config=boto3_config)
    ec2 = boto3.client("ec2", region_name=region, config=boto3_config)
    sagemaker = boto3.client(
        "sagemaker", region_name=region, config=boto3_config
    )
    logs = boto3.client("logs", region_name=region, config=boto3_config)
    s3 = boto3.client("s3", config=boto3_config)

    all_findings = []
    all_findings.append(check_bedrock_custom_model_encryption(bedrock, region))
    all_findings.append(check_sagemaker_encryption(sagemaker, region))
    all_findings.append(check_bedrock_vpc_endpoints(ec2, region))
    all_findings.append(check_sagemaker_network_isolation(sagemaker, region))
    all_findings.append(check_cloudwatch_log_masking(logs, region))
    all_findings.append(check_bedrock_guardrail_pii(bedrock, region))
    all_findings.append(check_s3_hipaa_integrity(s3, region))

    csv_content = generate_csv_report(all_findings)
    bucket_name = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
    file_name = f"hipaa_security_report_{execution_id}_{region}.csv"

    s3.put_object(
        Bucket=bucket_name,
        Key=file_name,
        Body=csv_content,
        ContentType="text/csv"
    )
    return {
        "statusCode": 200,
        "body": json.dumps({"findings_count": len(all_findings)})
    }
