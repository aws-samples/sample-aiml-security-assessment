# Copyright (c) Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
AWS HIPAA Compliance Lens for AI/ML
====================================
Implements security checks (HP-01 through HP-07) derived from HIPAA/HITECH 
security requirements for AI/ML workloads on AWS.
"""

import boto3
import csv
import logging
import os
import json
from io import StringIO
from typing import Any, Dict, List, Optional
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError
from schema import create_finding

# Boto3 config with adaptive retries
boto3_config = Config(retries=dict(max_attempts=10, mode="adaptive"))

logger = logging.getLogger()
logger.setLevel(logging.WARNING)

HIPAA_LENS_URL = "https://aws.amazon.com/compliance/hipaa-compliance/"

# Compliance Mapping for HIPAA
COMPLIANCE_MAP = {
    "HP-01": "HIPAA Security Rule 164.312(a )(2)(iv) | 164.312(e)(2)(ii)",
    "HP-02": "HIPAA Security Rule 164.312(a)(2)(iv) | 164.312(e)(2)(ii)",
    "HP-03": "HIPAA Security Rule 164.312(e)(1)",
    "HP-04": "HIPAA Security Rule 164.312(e)(1)",
    "HP-05": "HIPAA Security Rule 164.312(b)",
    "HP-06": "HIPAA Security Rule 164.312(e)(2)(ii) | PII Redaction",
    "HP-07": "HIPAA Security Rule 164.312(c)(1) | Integrity",
}

def _paginate(client, operation_name: str, result_key: str, **kwargs) -> List[Dict[str, Any]]:
    method = getattr(client, operation_name)
    items = []
    call_kwargs = dict(kwargs)
    while True:
        resp = method(**call_kwargs)
        items.extend(resp.get(result_key, []) or [])
        next_token = resp.get("nextToken") or resp.get("NextToken") or resp.get("Marker")
        if not next_token:
            break
        call_kwargs["nextToken" if "nextToken" in resp else "NextToken" if "NextToken" in resp else "Marker"] = next_token
    return items

def check_bedrock_custom_model_encryption(bedrock_client, region: str) -> List[Dict[str, Any]]:
    """HP-01: Verify Bedrock custom models use Customer Managed Keys (CMK)."""
    findings = []
    try:
        models = _paginate(bedrock_client, "list_custom_models", "modelSummaries")
        for model in models:
            model_arn = model["modelArn"]
            model_details = bedrock_client.get_custom_model(modelIdentifier=model_arn)
            kms_key = model_details.get("customModelKmsKeyId")
            status = "Passed" if kms_key else "Failed"
            severity = "High" if not kms_key else "Informational"
            findings.append(create_finding(
                check_id="HP-01", finding_name="Bedrock Custom Model CMK Encryption",
                resource_id=model_arn, region=region, status=status, severity=severity,
                details=f"Model {model['modelName']} is {'encrypted with CMK' if kms_key else 'not using a CMK'}.",
                resolution="Configure a Customer Managed Key (CMK) for Bedrock custom models.",
                compliance_frameworks=COMPLIANCE_MAP["HP-01"]
            ))
    except Exception as e: logger.error(f"Error in HP-01: {e}")
    return findings

def check_sagemaker_encryption(sagemaker_client, region: str) -> List[Dict[str, Any]]:
    """HP-02: Verify SageMaker Endpoints use Customer Managed Keys (CMK)."""
    findings = []
    try:
        endpoints = _paginate(sagemaker_client, "list_endpoints", "Endpoints")
        for ep in endpoints:
            desc = sagemaker_client.describe_endpoint(EndpointName=ep["EndpointName"])
            conf = sagemaker_client.describe_endpoint_config(EndpointConfigName=desc["EndpointConfigName"])
            kms_key = conf.get("KmsKeyId")
            status = "Passed" if kms_key else "Failed"
            severity = "High" if not kms_key else "Informational"
            findings.append(create_finding(
                check_id="HP-02", finding_name="SageMaker Endpoint CMK Encryption",
                resource_id=ep["EndpointArn"], region=region, status=status, severity=severity,
                details=f"Endpoint {ep['EndpointName']} {'uses CMK' if kms_key else 'uses default encryption'}.",
                resolution="Encrypt SageMaker endpoints with Customer Managed Keys (CMK).",
                compliance_frameworks=COMPLIANCE_MAP["HP-02"]
            ))
    except Exception as e: logger.error(f"Error in HP-02: {e}")
    return findings

def check_bedrock_vpc_endpoints(ec2_client, region: str) -> List[Dict[str, Any]]:
    """HP-03: Verify Bedrock VPC Endpoints exist."""
    findings = []
    try:
        endpoints = _paginate(ec2_client, "describe_vpc_endpoints", "VpcEndpoints")
        has_bedrock = any(e["ServiceName"] == f"com.amazonaws.{region}.bedrock" for e in endpoints)
        has_runtime = any(e["ServiceName"] == f"com.amazonaws.{region}.bedrock-runtime" for e in endpoints)
        status = "Passed" if (has_bedrock and has_runtime) else "Failed"
        findings.append(create_finding(
            check_id="HP-03", finding_name="Bedrock VPC Interface Endpoints",
            resource_id=f"vpc-endpoints-{region}", region=region, status=status, severity="Medium" if status=="Failed" else "Informational",
            details=f"Bedrock: {'Found' if has_bedrock else 'Missing'}, Runtime: {'Found' if has_runtime else 'Missing'}.",
            resolution="Create Interface VPC Endpoints for Amazon Bedrock.",
            compliance_frameworks=COMPLIANCE_MAP["HP-03"]
        ))
    except Exception as e: logger.error(f"Error in HP-03: {e}")
    return findings

def check_sagemaker_network_isolation(sagemaker_client, region: str) -> List[Dict[str, Any]]:
    """HP-04: Verify SageMaker Training Jobs use Network Isolation."""
    findings = []
    try:
        jobs = _paginate(sagemaker_client, "list_training_jobs", "TrainingJobSummaries")
        for job in jobs:
            desc = sagemaker_client.describe_training_job(TrainingJobName=job["TrainingJobName"])
            isolated = desc.get("EnableNetworkIsolation", False)
            findings.append(create_finding(
                check_id="HP-04", finding_name="SageMaker Training Network Isolation",
                resource_id=job["TrainingJobArn"], region=region, status="Passed" if isolated else "Failed",
                severity="Medium" if not isolated else "Informational",
                details=f"Job {job['TrainingJobName']} network isolation: {isolated}.",
                resolution="Enable Network Isolation for SageMaker training jobs.",
                compliance_frameworks=COMPLIANCE_MAP["HP-04"]
            ))
    except Exception as e: logger.error(f"Error in HP-04: {e}")
    return findings

def check_cloudwatch_log_masking(logs_client, region: str) -> List[Dict[str, Any]]:
    """HP-05: Verify CloudWatch Log Groups have PII Masking."""
    findings = []
    try:
        log_groups = _paginate(logs_client, "describe_log_groups", "logGroups")
        for lg in log_groups:
            name = lg["logGroupName"]
            if not any(k in name.lower() for k in ["bedrock", "sagemaker", "aiml"]): continue
            try:
                has_policy = bool(logs_client.get_data_protection_policy(logGroupIdentifier=name).get("policyDocument"))
            except: has_policy = False
            findings.append(create_finding(
                check_id="HP-05", finding_name="CloudWatch Log PII Masking",
                resource_id=name, region=region, status="Passed" if has_policy else "Failed",
                severity="Medium" if not has_policy else "Informational",
                details=f"Log group {name} data protection: {has_policy}.",
                resolution="Implement CloudWatch Logs Data Protection policies.",
                compliance_frameworks=COMPLIANCE_MAP["HP-05"]
            ))
    except Exception as e: logger.error(f"Error in HP-05: {e}")
    return findings

def check_bedrock_guardrail_pii(bedrock_client, region: str) -> List[Dict[str, Any]]:
    """HP-06: Verify Bedrock Guardrails have PII Redaction."""
    findings = []
    try:
        guardrails = _paginate(bedrock_client, "list_guardrails", "guardrailSummaries")
        for gr in guardrails:
            details = bedrock_client.get_guardrail(guardrailIdentifier=gr["guardrailId"])
            has_pii = len(details.get("sensitiveInformationPolicy", {}).get("piiEntitiesConfig", [])) > 0
            findings.append(create_finding(
                check_id="HP-06", finding_name="Bedrock Guardrail PII Redaction",
                resource_id=gr["guardrailArn"], region=region, status="Passed" if has_pii else "Failed",
                severity="High" if not has_pii else "Informational",
                details=f"Guardrail {gr['name']} PII filters: {has_pii}.",
                resolution="Enable PII entity filters in Bedrock Guardrails.",
                compliance_frameworks=COMPLIANCE_MAP["HP-06"]
            ))
    except Exception as e: logger.error(f"Error in HP-06: {e}")
    return findings

def check_s3_hipaa_integrity(s3_client, region: str) -> List[Dict[str, Any]]:
    """HP-07: Verify S3 Buckets have Versioning and Encryption."""
    findings = []
    try:
        buckets = s3_client.list_buckets()["Buckets"]
        for b in buckets:
            name = b["Name"]
            if not any(k in name.lower() for k in ["aiml", "bedrock", "sagemaker"]): continue
            versioning = s3_client.get_bucket_versioning(Bucket=name).get("Status") == "Enabled"
            try: s3_client.get_bucket_encryption(Bucket=name); has_enc = True
            except: has_enc = False
            findings.append(create_finding(
                check_id="HP-07", finding_name="S3 HIPAA Data Integrity",
                resource_id=name, region=region, status="Passed" if (versioning and has_enc) else "Failed",
                severity="Medium" if not (versioning and has_enc) else "Informational",
                details=f"Bucket {name}: Versioning={versioning}, Encryption={has_enc}.",
                resolution="Enable S3 Bucket Versioning and Default Encryption.",
                compliance_frameworks=COMPLIANCE_MAP["HP-07"]
            ))
    except Exception as e: logger.error(f"Error in HP-07: {e}")
    return findings

def lambda_handler(event, context):
    region = event.get("region", os.environ.get("AWS_REGION", "us-east-1"))
    execution_id = event.get("execution_id", "manual")
    bedrock = boto3.client("bedrock", region_name=region, config=boto3_config)
    ec2 = boto3.client("ec2", region_name=region, config=boto3_config)
    sagemaker = boto3.client("sagemaker", region_name=region, config=boto3_config)
    logs = boto3.client("logs", region_name=region, config=boto3_config)
    s3 = boto3.client("s3", config=boto3_config)
    
    all_findings = []
    all_findings.extend(check_bedrock_custom_model_encryption(bedrock, region))
    all_findings.extend(check_sagemaker_encryption(sagemaker, region))
    all_findings.extend(check_bedrock_vpc_endpoints(ec2, region))
    all_findings.extend(check_sagemaker_network_isolation(sagemaker, region))
    all_findings.extend(check_cloudwatch_log_masking(logs, region))
    all_findings.extend(check_bedrock_guardrail_pii(bedrock, region))
    all_findings.extend(check_s3_hipaa_integrity(s3, region))
    
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=["Check_ID", "Finding_Name", "Resource_ID", "Region", "Status", "Severity", "Details", "Resolution", "Compliance_Frameworks"])
    writer.writeheader()
    for f in all_findings:
        writer.writerow({"Check_ID": f.check_id, "Finding_Name": f.finding_name, "Resource_ID": f.resource_id, "Region": f.region, "Status": f.status, "Severity": f.severity, "Details": f.details, "Resolution": f.resolution, "Compliance_Frameworks": f.compliance_frameworks})
    
    s3.put_object(Bucket=os.environ.get("AIML_ASSESSMENT_BUCKET_NAME"), Key=f"hipaa_security_report_{region}_{execution_id}.csv", Body=output.getvalue())
    return {"statusCode": 200, "body": json.dumps({"findings_count": len(all_findings)})}
