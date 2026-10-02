"""HIPAA/HITECH-aligned automated configuration checks.

This Lambda emits HP-01 through HP-07 rows that inspect a specific subset of
AWS AI/ML resources and related services against automated configuration
patterns aligned with the HIPAA Security Rule (45 CFR Part 164 Subpart C)
and, where referenced, the HITECH Breach Notification Rule.

DISCLAIMER — REQUIRED SCOPE LANGUAGE (DO NOT DELETE OR SOFTEN):
These are AUTOMATED CONFIGURATION CHECKS. They do NOT:
  * constitute a HIPAA compliance audit or certification,
  * establish the presence or absence of electronic protected health
    information (ePHI) in any resource,
  * cover administrative, physical, or organizational safeguards beyond
    what can be read from the AWS API surface,
  * replace a formal Risk Analysis (164.308(a)(1)) conducted by a
    HIPAA-covered entity or business associate,
  * guarantee that any workload is compliant with HIPAA, HITECH, or any
    state-law equivalent.

Each emitted finding carries its aligned HIPAA citation in the
Compliance_Frameworks column. That mapping is illustrative only; each
covered entity is responsible for its own control mapping against its
own documented policies.

This Lambda is gated at the Step Functions layer by the `HIPAA Enabled?`
Choice state and writes
`hipaa_security_report_<execution_id>_<region>.csv` per region.
"""

import boto3
import csv
import logging
import os
from io import StringIO
from typing import Any, Dict, List

from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError

from schema import SeverityEnum, StatusEnum, create_finding

boto3_config = Config(retries=dict(max_attempts=10, mode="adaptive"))

logger = logging.getLogger()
logger.setLevel(logging.ERROR)


# Error codes returned when a region is not enabled / not accessible.
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

# Log-group name prefixes whose data-protection policy is considered within
# scope for the AI/ML assessment. HP-05 intentionally avoids flagging every
# log group in the account — we only emit a row when at least one of these
# AIML-prefixed groups exists in the region and is missing a data-protection
# policy. This scoping keeps HIPAA findings focused on the AI/ML surface.
AIML_LOG_GROUP_PREFIXES = (
    "/aws/bedrock/",
    "/aws/sagemaker/",
    "/aws/sagemaker/endpoints/",
    "/aws/vendedlogs/bedrock/",
    "/aws/sagemaker/studio/",
)


# ---------------------------------------------------------------------------
# HIPAA reference + citation map for HP-01..HP-07.
#
# Citations deliberately use the widely-cited 45 CFR 164.312 section numbers
# for the Technical Safeguards and, where applicable, the HITECH Breach
# Notification Rule (78 FR 42698 et seq.). Each check also includes a
# reference URL to the corresponding AWS HIPAA page.
# ---------------------------------------------------------------------------
AWS_HIPAA_REFERENCE_URL = "https://aws.amazon.com/compliance/hipaa-compliance/"

HIPAA_CHECK_REFERENCES = {
    "HP-01": "https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-at-rest.html",
    "HP-02": "https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-content-filters.html",
    "HP-03": "https://docs.aws.amazon.com/sagemaker/latest/dg/mkt-algo-model-internet-free.html",
    "HP-04": "https://docs.aws.amazon.com/sagemaker/latest/dg/sms-security-kms-keys.html",
    "HP-05": "https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_GetDataProtectionPolicy.html",
    "HP-06": "https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints.html",
    "HP-07": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html",
}

# Citations: 164.312(a)(2)(iv) = Encryption and Decryption;
#            164.312(e)(1)      = Transmission Security;
#            164.312(e)(2)(ii)  = Encryption during transmission;
#            164.312(a)(1)      = Access Control;
#            164.308(a)(1)(ii)(D) = Information System Activity Review;
#            164.312(b)         = Audit Controls.
HIPAA_COMPLIANCE_MAP = {
    "HP-01": "HIPAA Security Rule 45 CFR 164.312(a)(2)(iv) — Encryption and Decryption (static ePHI at rest on Bedrock custom models)",
    "HP-02": "HIPAA Security Rule 45 CFR 164.312(a)(2)(iv) — Encryption and Decryption and 164.312(a)(1) — Access Control (Bedrock Guardrail PII redaction)",
    "HP-03": "HIPAA Security Rule 45 CFR 164.312(a)(1) — Access Control and 164.312(e)(2)(ii) — Encryption during transmission (SageMaker network isolation)",
    "HP-04": "HIPAA Security Rule 45 CFR 164.312(a)(2)(iv) — Encryption and Decryption (ePHI at rest on SageMaker endpoints/training jobs)",
    "HP-05": "HIPAA Security Rule 45 CFR 164.308(a)(1)(ii)(D) — Information System Activity Review and 164.312(b) — Audit Controls (ePHI-bearing logs)",
    "HP-06": "HIPAA Security Rule 45 CFR 164.312(e)(1) — Transmission Security and 164.312(e)(2)(ii) — Encryption during transmission (private AWS networking)",
    "HP-07": "HIPAA Security Rule 45 CFR 164.312(a)(2)(iv) — Encryption and Decryption and HITECH Breach Notification Rule (78 FR 42698) (ePHI at rest in S3 datasets)",
}


def _region_unavailable_error(err: ClientError) -> bool:
    return err.response.get("Error", {}).get("Code") in REGION_UNAVAILABLE_ERROR_CODES


def _access_denied_error(err: ClientError) -> bool:
    return err.response.get("Error", {}).get("Code") in ACCESS_DENIED_ERROR_CODES


def _make_na_finding(check_id: str, region: str, explanation: str) -> Dict[str, Any]:
    """Return a single N/A finding used when the check cannot be evaluated
    in the region (region disabled, required API access denied, etc.)."""
    title = {
        "HP-01": "Bedrock Custom Model Encryption Check Unavailable",
        "HP-02": "Bedrock Guardrail PII Configuration Check Unavailable",
        "HP-03": "SageMaker Network Isolation Check Unavailable",
        "HP-04": "SageMaker Resource Encryption Check Unavailable",
        "HP-05": "CloudWatch Logs Data Protection Check Unavailable",
        "HP-06": "VPC Endpoint Configuration Check Unavailable",
        "HP-07": "S3 Dataset Encryption and Versioning Check Unavailable",
    }.get(check_id, f"{check_id} Check Unavailable")
    return create_finding(
        check_id=check_id,
        finding_name=title,
        finding_details=explanation,
        resolution="Enable the region or grant the required read-only IAM permissions to the HIPAA Lambda role.",
        reference=HIPAA_CHECK_REFERENCES.get(check_id, AWS_HIPAA_REFERENCE_URL),
        severity=SeverityEnum.INFORMATIONAL,
        status=StatusEnum.NA,
        region=region,
        compliance_frameworks=HIPAA_COMPLIANCE_MAP.get(check_id, ""),
    )


# ---------------------------------------------------------------------------
# Individual HIPAA checks (HP-01 through HP-07).
# ---------------------------------------------------------------------------
def check_bedrock_custom_model_encryption(region: str) -> List[Dict[str, Any]]:
    """HP-01 — Bedrock custom model encryption at rest.

    Scans Bedrock `list_custom_models` and, for each model that exposes an
    encryption key via `get_custom_model`, verifies that the model storage
    is at least SSE-KMS encrypted (any non-empty `modelKmsKeyArn` satisfies
    the check; SSE-S3-style server-side default encryption on Bedrock
    managed storage is NOT sufficient for our ePHI-at-rest heuristic).

    Emits ONE row per non-compliant model, plus ONE Passed aggregate row
    when at least one model exists and all are encrypted, plus ONE N/A
    row when the Bedrock API is inaccessible in this region.
    """
    check_id = "HP-01"
    findings: List[Dict[str, Any]] = []
    try:
        bedrock = boto3.client("bedrock", region_name=region, config=boto3_config)
        try:
            custom_models = bedrock.list_custom_models().get("modelSummaries", [])
        except ClientError as err:
            if _region_unavailable_error(err) or _access_denied_error(err):
                findings.append(
                    _make_na_finding(
                        check_id,
                        region,
                        (
                            "Bedrock custom-models endpoint is unavailable or "
                            f"the assessment role lacks access: {err.response.get('Error', {}).get('Code')}"
                        ),
                    )
                )
                return findings
            raise

        if not custom_models:
            return findings  # Zero Bedrock custom models → no row emitted.

        total_models = 0
        compliant_models = 0
        for model in custom_models:
            model_arn = model.get("modelArn") or model.get("modelId") or "unknown"
            model_name = model.get("modelName") or model_arn
            total_models += 1
            kms_arn = ""
            try:
                detail = bedrock.get_custom_model(modelIdentifier=model_arn)
                kms_arn = detail.get("modelKmsKeyArn") or ""
            except ClientError as err:
                if _region_unavailable_error(err) or _access_denied_error(err):
                    findings.append(
                        _make_na_finding(
                            check_id,
                            region,
                            (
                                "Cannot read Bedrock get_custom_model for "
                                f"{model_name}: {err.response.get('Error', {}).get('Code')}"
                            ),
                        )
                    )
                    continue
                raise
            except EndpointConnectionError:
                findings.append(
                    _make_na_finding(
                        check_id,
                        region,
                        f"Bedrock endpoint unreachable while inspecting {model_name}.",
                    )
                )
                continue

            if kms_arn:
                compliant_models += 1
            else:
                findings.append(
                    create_finding(
                        check_id=check_id,
                        finding_name="Bedrock Custom Model Not Encrypted with KMS",
                        finding_details=(
                            f"Bedrock custom model '{model_name}' ({model_arn}) in region {region} "
                            "does not reference a KMS encryption key (modelKmsKeyArn is empty). "
                            "Bedrock-managed default SSE on underlying storage without a customer-"
                            "or service-managed KMS key does not satisfy the HIPAA 164.312(a)(2)(iv) "
                            "evidence goal used by this automated check."
                        ),
                        resolution=(
                            "Re-create the Bedrock custom model specifying a customer KMS key or a "
                            "Bedrock service-managed KMS key via modelKmsKeyArn. KMS keys used for "
                            "ePHI-bearing Bedrock resources should be recorded in your HIPAA "
                            "configuration-management program and have rotation enabled."
                        ),
                        reference=HIPAA_CHECK_REFERENCES[check_id],
                        severity=SeverityEnum.HIGH,
                        status=StatusEnum.FAILED,
                        region=region,
                        compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                    )
                )

        if total_models > 0 and compliant_models == total_models:
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name="Bedrock Custom Models Encrypted with KMS",
                    finding_details=(
                        f"All {total_models} Bedrock custom models in region {region} reference a "
                        "KMS encryption key (modelKmsKeyArn populated). This is the automated "
                        "configuration state we correlate with the HIPAA at-rest encryption goal."
                    ),
                    resolution=(
                        "No action required. Document this evidence in your HIPAA Risk Analysis "
                        "alongside your own ePHI-inventory decision that custom models do or do not "
                        "process protected health information."
                    ),
                    reference=HIPAA_CHECK_REFERENCES[check_id],
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.PASSED,
                    region=region,
                    compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                )
            )
        return findings

    except ClientError as err:
        if _region_unavailable_error(err) or _access_denied_error(err):
            return [
                _make_na_finding(
                    check_id,
                    region,
                    (
                        "Bedrock API unavailable or access denied while scanning custom models: "
                        f"{err.response.get('Error', {}).get('Code')}"
                    ),
                )
            ]
        raise


def check_sagemaker_resource_encryption(region: str) -> List[Dict[str, Any]]:
    """HP-04 — SageMaker endpoints and training jobs encrypted at rest.

    Emits Failed rows when: an endpoint's EndpointConfig lacks a KmsKeyId;
    a DescribeTrainingJob's OutputDataConfig lacks KmsKeyId. Emits a Passed
    aggregate row when at least one resource exists and all are encrypted;
    N/A on access-denied or unavailable region.
    """
    check_id = "HP-04"
    findings: List[Dict[str, Any]] = []
    try:
        sagemaker = boto3.client("sagemaker", region_name=region, config=boto3_config)
        try:
            endpoints = sagemaker.list_endpoints().get("Endpoints", [])
        except ClientError as err:
            if _region_unavailable_error(err) or _access_denied_error(err):
                return [
                    _make_na_finding(
                        check_id,
                        region,
                        (
                            "SageMaker list_endpoints unavailable or access denied: "
                            f"{err.response.get('Error', {}).get('Code')}"
                        ),
                    )
                ]
            raise

        inspected = 0
        compliant = 0

        for ep in endpoints:
            ep_name = ep.get("EndpointName", "unknown")
            try:
                ep_desc = sagemaker.describe_endpoint(EndpointName=ep_name)
                cfg_name = ep_desc.get("EndpointConfigName")
                if not cfg_name:
                    continue
                cfg = sagemaker.describe_endpoint_config(EndpointConfigName=cfg_name)
            except ClientError as err:
                if _region_unavailable_error(err) or _access_denied_error(err):
                    findings.append(
                        _make_na_finding(
                            check_id,
                            region,
                            f"Cannot describe SageMaker endpoint {ep_name}: {err.response.get('Error', {}).get('Code')}",
                        )
                    )
                    continue
                raise
            inspected += 1
            kms = cfg.get("KmsKeyId") or ""
            if kms:
                compliant += 1
            else:
                findings.append(
                    create_finding(
                        check_id=check_id,
                        finding_name="SageMaker Endpoint Not Encrypted with KMS",
                        finding_details=(
                            f"SageMaker endpoint '{ep_name}' in region {region} uses EndpointConfig "
                            f"'{cfg_name}' without a KmsKeyId. SageMaker-managed default storage "
                            "encryption without an explicit KMS key is not sufficient evidence "
                            "for the 164.312(a)(2)(iv) at-rest encryption goal used here."
                        ),
                        resolution=(
                            "Deploy a new EndpointConfig specifying a customer KmsKeyId, attach it "
                            "to the endpoint with UpdateEndpoint, and record the key in your HIPAA "
                            "configuration-management program."
                        ),
                        reference=HIPAA_CHECK_REFERENCES[check_id],
                        severity=SeverityEnum.HIGH,
                        status=StatusEnum.FAILED,
                        region=region,
                        compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                    )
                )

        try:
            training_jobs = sagemaker.list_training_jobs(
                SortBy="CreationTime", SortOrder="Descending", MaxResults=50
            ).get("TrainingJobSummaries", [])
        except ClientError as err:
            if _region_unavailable_error(err) or _access_denied_error(err):
                training_jobs = []
                findings.append(
                    _make_na_finding(
                        check_id,
                        region,
                        f"Cannot list SageMaker training jobs: {err.response.get('Error', {}).get('Code')}",
                    )
                )
            else:
                raise

        for tj in training_jobs:
            tj_name = tj.get("TrainingJobName")
            if not tj_name:
                continue
            try:
                tj_desc = sagemaker.describe_training_job(TrainingJobName=tj_name)
            except ClientError as err:
                if _region_unavailable_error(err) or _access_denied_error(err):
                    findings.append(
                        _make_na_finding(
                            check_id,
                            region,
                            f"Cannot describe training job {tj_name}: {err.response.get('Error', {}).get('Code')}",
                        )
                    )
                    continue
                raise
            inspected += 1
            out = tj_desc.get("OutputDataConfig", {})
            kms_out = out.get("KmsKeyId") or ""
            if kms_out:
                compliant += 1
            else:
                findings.append(
                    create_finding(
                        check_id=check_id,
                        finding_name="SageMaker Training Job Output Not Encrypted with KMS",
                        finding_details=(
                            f"SageMaker training job '{tj_name}' in region {region} writes output "
                            "to S3 without a KmsKeyId in OutputDataConfig. Artifacts produced by "
                            "training jobs that touch ePHI must carry explicit KMS encryption."
                        ),
                        resolution=(
                            "Run the training job again with OutputDataConfig.KmsKeyId pointing to "
                            "a customer KMS key, and ensure the same key is configured on any "
                            "SageMaker Notebook / Studio instances that read the artifacts."
                        ),
                        reference=HIPAA_CHECK_REFERENCES[check_id],
                        severity=SeverityEnum.HIGH,
                        status=StatusEnum.FAILED,
                        region=region,
                        compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                    )
                )

        if inspected > 0 and compliant == inspected:
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name="SageMaker Resources Encrypted with KMS",
                    finding_details=(
                        f"All {inspected} SageMaker endpoints and recent training jobs in region "
                        f"{region} reference a KmsKeyId for their storage/training output."
                    ),
                    resolution=(
                        "No action required. Cross-reference against your ePHI inventory and "
                        "document this evidence in your HIPAA Risk Analysis."
                    ),
                    reference=HIPAA_CHECK_REFERENCES[check_id],
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.PASSED,
                    region=region,
                    compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                )
            )
        return findings

    except ClientError as err:
        if _region_unavailable_error(err) or _access_denied_error(err):
            return [
                _make_na_finding(
                    check_id,
                    region,
                    (
                        "SageMaker API unavailable or access denied: "
                        f"{err.response.get('Error', {}).get('Code')}"
                    ),
                )
            ]
        raise


def check_vpc_endpoints_configured(region: str) -> List[Dict[str, Any]]:
    """HP-06 — Required VPC Interface / Gateway endpoints present.

    A PASS requires, for every described VPC (at least one VPC must exist
    for a row to emit), each of the following AWS service endpoints to be
    present as an attached VPC endpoint:
      * com.amazonaws.<region>.bedrock-runtime (Bedrock runtime)
      * com.amazonaws.<region>.bedrock-agent-runtime (Agent runtime)
      * com.amazonaws.<region>.bedrock-agent (Agent control)
      * com.amazonaws.<region>.sagemaker.api (SageMaker API)
      * com.amazonaws.<region>.sagemaker.runtime (SageMaker runtime)
      * com.amazonaws.<region>.logs (CloudWatch Logs — audit trail transport)
      * com.amazonaws.<region>.s3 (S3 — dataset/artifacts transport)

    Emits one Failed row per missing service (aggregated across VPCs),
    one Passed aggregate row if every VPC in the region has the full set,
    N/A when the EC2 describe API is unreachable or when zero VPCs exist
    in the region (default VPC removed — we cannot evaluate).
    """
    check_id = "HP-06"
    findings: List[Dict[str, Any]] = []
    required_services_template = (
        "bedrock-runtime",
        "bedrock-agent-runtime",
        "bedrock-agent",
        "sagemaker.api",
        "sagemaker.runtime",
        "logs",
        "s3",
    )
    try:
        ec2 = boto3.client("ec2", region_name=region, config=boto3_config)
        try:
            vpcs = ec2.describe_vpcs().get("Vpcs", [])
        except ClientError as err:
            if _region_unavailable_error(err) or _access_denied_error(err):
                return [
                    _make_na_finding(
                        check_id,
                        region,
                        f"EC2 describe_vpcs unavailable or access denied: {err.response.get('Error', {}).get('Code')}",
                    )
                ]
            raise
        vpc_ids = [v.get("VpcId") for v in vpcs if v.get("VpcId")]
        if not vpc_ids:
            return [
                _make_na_finding(
                    check_id,
                    region,
                    "Zero VPCs are defined in this region. AI/ML VPC endpoint reachability cannot be evaluated without any VPC to inspect.",
                )
            ]

        try:
            endpoints = ec2.describe_vpc_endpoints().get("VpcEndpoints", [])
        except ClientError as err:
            if _region_unavailable_error(err) or _access_denied_error(err):
                return [
                    _make_na_finding(
                        check_id,
                        region,
                        f"EC2 describe_vpc_endpoints unavailable: {err.response.get('Error', {}).get('Code')}",
                    )
                ]
            raise

        required_services = [
            f"com.amazonaws.{region}.{svc}" for svc in required_services_template
        ]

        vpc_endpoints: Dict[str, set] = {v: set() for v in vpc_ids}
        for ep in endpoints:
            vpc = ep.get("VpcId")
            svc = ep.get("ServiceName")
            if vpc in vpc_endpoints and svc:
                vpc_endpoints[vpc].add(svc)

        all_compliant = True
        missing_aggregated: Dict[str, List[str]] = {}
        for vpc, present in vpc_endpoints.items():
            missing = [s for s in required_services if s not in present]
            if missing:
                all_compliant = False
                missing_aggregated[vpc] = missing

        if missing_aggregated:
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name="Required AI/ML VPC Endpoints Not Attached",
                    finding_details=(
                        "The following VPCs in region "
                        + region
                        + " are missing one or more AI/ML service endpoints "
                        "(required for private AWS-networking access to the AI/ML data plane and "
                        "its audit trail under the 164.312(e)(1)/(e)(2)(ii) transmission-security "
                        "heuristic used here): "
                        + "; ".join(
                            f"{vpc} missing [{', '.join(sorted(missing))}]"
                            for vpc, missing in missing_aggregated.items()
                        )
                    ),
                    resolution=(
                        "Provision Interface endpoints (S3 is a Gateway endpoint) for the missing "
                        "services, attach them to the applicable VPCs with appropriate subnet/security-"
                        "group selection, and record them in your HIPAA network-configuration inventory."
                    ),
                    reference=HIPAA_CHECK_REFERENCES[check_id],
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                    region=region,
                    compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                )
            )

        if all_compliant:
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name="Required AI/ML VPC Endpoints Attached",
                    finding_details=(
                        f"All {len(vpc_ids)} VPCs in region {region} expose the required set of AI/ML "
                        "and supporting VPC endpoints for private transport of model/data/log traffic."
                    ),
                    resolution=(
                        "No action required. Document the VPC endpoint topology as evidence for the "
                        "HIPAA 164.312(e)(1) Transmission Security control alongside workload-level "
                        "evidence that ePHI-bearing AI/ML calls traverse only those endpoints."
                    ),
                    reference=HIPAA_CHECK_REFERENCES[check_id],
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.PASSED,
                    region=region,
                    compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                )
            )
        return findings

    except ClientError as err:
        if _region_unavailable_error(err) or _access_denied_error(err):
            return [
                _make_na_finding(
                    check_id,
                    region,
                    f"EC2 API unavailable or access denied: {err.response.get('Error', {}).get('Code')}",
                )
            ]
        raise


def check_sagemaker_network_isolation(region: str) -> List[Dict[str, Any]]:
    """HP-03 — SageMaker endpoints and recent training jobs network-isolated.

    Evaluates EnableNetworkIsolation on every described endpoint config and
    training job in the region. A PASS requires every endpoint/training-job
    to have the flag enabled. Emits an aggregate Passed row if at least one
    resource is present and all are isolated, Failed rows otherwise, N/A on
    access denied or region unavailable.
    """
    check_id = "HP-03"
    findings: List[Dict[str, Any]] = []
    try:
        sagemaker = boto3.client("sagemaker", region_name=region, config=boto3_config)
        try:
            endpoints = sagemaker.list_endpoints().get("Endpoints", [])
        except ClientError as err:
            if _region_unavailable_error(err) or _access_denied_error(err):
                return [
                    _make_na_finding(
                        check_id,
                        region,
                        f"SageMaker list_endpoints unavailable: {err.response.get('Error', {}).get('Code')}",
                    )
                ]
            raise

        inspected = 0
        isolated = 0

        for ep in endpoints:
            ep_name = ep.get("EndpointName", "unknown")
            try:
                ep_desc = sagemaker.describe_endpoint(EndpointName=ep_name)
                cfg_name = ep_desc.get("EndpointConfigName")
                if not cfg_name:
                    continue
                cfg = sagemaker.describe_endpoint_config(EndpointConfigName=cfg_name)
            except ClientError as err:
                if _region_unavailable_error(err) or _access_denied_error(err):
                    findings.append(
                        _make_na_finding(
                            check_id,
                            region,
                            f"Cannot describe endpoint {ep_name}: {err.response.get('Error', {}).get('Code')}",
                        )
                    )
                    continue
                raise
            inspected += 1
            if cfg.get("EnableNetworkIsolation") is True:
                isolated += 1
            else:
                findings.append(
                    create_finding(
                        check_id=check_id,
                        finding_name="SageMaker Endpoint Not Network-Isolated",
                        finding_details=(
                            f"SageMaker endpoint '{ep_name}' in region {region} uses EndpointConfig "
                            f"'{cfg_name}' that does not have EnableNetworkIsolation=true. "
                            "Network isolation is the automated evidence we use to correlate with "
                            "HIPAA 164.312(e)(2)(ii) transmission security and 164.312(a)(1) access-"
                            "control goals for containerized ePHI-bearing models."
                        ),
                        resolution=(
                            "Deploy a new EndpointConfig with EnableNetworkIsolation=true and "
                            "attach it via UpdateEndpoint. Confirm that the model and its dependencies "
                            "do not require outbound internet after isolation — containers without "
                            "internet access cannot pull post-deployment dependencies or exfiltrate data."
                        ),
                        reference=HIPAA_CHECK_REFERENCES[check_id],
                        severity=SeverityEnum.MEDIUM,
                        status=StatusEnum.FAILED,
                        region=region,
                        compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                    )
                )

        try:
            training_jobs = sagemaker.list_training_jobs(
                SortBy="CreationTime", SortOrder="Descending", MaxResults=50
            ).get("TrainingJobSummaries", [])
        except ClientError as err:
            if _region_unavailable_error(err) or _access_denied_error(err):
                training_jobs = []
                findings.append(
                    _make_na_finding(
                        check_id,
                        region,
                        f"Cannot list SageMaker training jobs: {err.response.get('Error', {}).get('Code')}",
                    )
                )
            else:
                raise

        for tj in training_jobs:
            tj_name = tj.get("TrainingJobName")
            if not tj_name:
                continue
            try:
                tj_desc = sagemaker.describe_training_job(TrainingJobName=tj_name)
            except ClientError as err:
                if _region_unavailable_error(err) or _access_denied_error(err):
                    findings.append(
                        _make_na_finding(
                            check_id,
                            region,
                            f"Cannot describe training job {tj_name}: {err.response.get('Error', {}).get('Code')}",
                        )
                    )
                    continue
                raise
            inspected += 1
            if tj_desc.get("EnableNetworkIsolation") is True:
                isolated += 1
            else:
                findings.append(
                    create_finding(
                        check_id=check_id,
                        finding_name="SageMaker Training Job Not Network-Isolated",
                        finding_details=(
                            f"SageMaker training job '{tj_name}' in region {region} has "
                            "EnableNetworkIsolation != true. Training containers handling ePHI "
                            "should be isolated from the network to reduce transmission- and "
                            "exfiltration-risk vectors tracked under 164.312(e)(1)."
                        ),
                        resolution=(
                            "Re-run the training job with EnableNetworkIsolation=true. Confirm "
                            "training containers use VpcConfig with private subnets if they need "
                            "to reach VPC-local services (network isolation still allows VPC-"
                            "scoped traffic)."
                        ),
                        reference=HIPAA_CHECK_REFERENCES[check_id],
                        severity=SeverityEnum.MEDIUM,
                        status=StatusEnum.FAILED,
                        region=region,
                        compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                    )
                )

        if inspected > 0 and isolated == inspected:
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name="SageMaker Resources Are Network-Isolated",
                    finding_details=(
                        f"All {inspected} SageMaker endpoints and recent training jobs in region "
                        f"{region} have EnableNetworkIsolation enabled."
                    ),
                    resolution=(
                        "No action required. Keep network isolation enabled and document the "
                        "configuration in your HIPAA access-control evidence inventory."
                    ),
                    reference=HIPAA_CHECK_REFERENCES[check_id],
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.PASSED,
                    region=region,
                    compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                )
            )
        return findings

    except ClientError as err:
        if _region_unavailable_error(err) or _access_denied_error(err):
            return [
                _make_na_finding(
                    check_id,
                    region,
                    f"SageMaker API unavailable or access denied: {err.response.get('Error', {}).get('Code')}",
                )
            ]
        raise


def check_cloudwatch_logs_data_protection(region: str) -> List[Dict[str, Any]]:
    """HP-05 — CloudWatch Logs data-protection policy on AIML log groups.

    Only log groups whose name starts with one of the AIML_LOG_GROUP_PREFIXES
    are evaluated. A Pass requires every matched log group to have a
    data-protection policy attached; any missing one produces Failed. When
    zero AIML-prefixed groups exist in the region, no row is emitted.
    """
    check_id = "HP-05"
    findings: List[Dict[str, Any]] = []
    try:
        logs = boto3.client("logs", region_name=region, config=boto3_config)
        try:
            log_groups = logs.describe_log_groups(limit=50).get("logGroups", [])
        except ClientError as err:
            if _region_unavailable_error(err) or _access_denied_error(err):
                return [
                    _make_na_finding(
                        check_id,
                        region,
                        f"CloudWatch describe_log_groups unavailable: {err.response.get('Error', {}).get('Code')}",
                    )
                ]
            raise

        scoped = [
            lg
            for lg in log_groups
            if any(
                (lg.get("logGroupName") or "").startswith(pfx)
                for pfx in AIML_LOG_GROUP_PREFIXES
            )
        ]
        if not scoped:
            return findings  # No AIML-related log groups in region → skip.

        missing: List[str] = []
        for lg in scoped:
            lg_name = lg.get("logGroupName") or "unknown"
            try:
                logs.get_data_protection_policy(logGroupIdentifier=lg_name)
            except ClientError as err:
                code = err.response.get("Error", {}).get("Code", "")
                if (
                    code == "ResourceNotFoundException"
                    or "ResourceNotFoundException" in code
                ):
                    missing.append(lg_name)
                    continue
                if _region_unavailable_error(err) or _access_denied_error(err):
                    findings.append(
                        _make_na_finding(
                            check_id,
                            region,
                            (
                                f"Cannot read data-protection policy for {lg_name}: "
                                f"{err.response.get('Error', {}).get('Code')}"
                            ),
                        )
                    )
                    continue
                raise

        if missing:
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name="AI/ML Log Groups Missing CloudWatch Data-Protection Policy",
                    finding_details=(
                        "These AIML-related CloudWatch Logs log groups in region "
                        + region
                        + " lack a data-protection policy that could detect or mask ePHI/PII "
                        "before it is written to long-term log storage: "
                        + ", ".join(sorted(missing))
                        + ". The 164.312(b) audit-control and 164.308(a)(1)(ii)(D) activity-review "
                        "safeguards require logged ePHI to be identified and handled."
                    ),
                    resolution=(
                        "Put a CloudWatch Logs data-protection policy on each scoped log group "
                        "identifying at least Name, SSN, DoB, MRN, telephone, email, and any "
                        "custom identifiers used by your ePHI. Choose DEACTIVATE masking for "
                        "groups whose downstream readers are themselves compliant (SIEM) and "
                        "MASK for groups accessible to operations dashboards without a "
                        "break-glass approval flow."
                    ),
                    reference=HIPAA_CHECK_REFERENCES[check_id],
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                    region=region,
                    compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                )
            )
        else:
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name="AI/ML Log Groups Have Data-Protection Policies",
                    finding_details=(
                        f"All {len(scoped)} AIML-prefixed CloudWatch log groups in region {region} "
                        "carry an attached data-protection policy. This is the automated evidence "
                        "we correlate with the audit-control / activity-review safeguards."
                    ),
                    resolution=(
                        "No action required. Periodically review policy statement coverage "
                        "against your documented ePHI identifier inventory; add custom data "
                        "identifiers for any health-specific fields unique to your organization."
                    ),
                    reference=HIPAA_CHECK_REFERENCES[check_id],
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.PASSED,
                    region=region,
                    compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                )
            )
        return findings

    except ClientError as err:
        if _region_unavailable_error(err) or _access_denied_error(err):
            return [
                _make_na_finding(
                    check_id,
                    region,
                    f"CloudWatch Logs API unavailable or access denied: {err.response.get('Error', {}).get('Code')}",
                )
            ]
        raise


def check_bedrock_guardrail_pii(region: str) -> List[Dict[str, Any]]:
    """HP-02 — Bedrock guardrails have PII detection with a deny/mask action.

    Scans `list_guardrails` (Bedrock guardrails are region-scoped). For each
    guardrail, calls `get_guardrail` and verifies that the GuardrailVersion
    config includes PII with at least one GENERAL PII entity whose Action
    is BLOCK or MASK. A Pass aggregate is emitted when at least one guardrail
    exists and every guardrail has at least one qualifying PII entity.
    """
    check_id = "HP-02"
    findings: List[Dict[str, Any]] = []
    try:
        bedrock = boto3.client("bedrock", region_name=region, config=boto3_config)
        try:
            guardrails = bedrock.list_guardrails().get("guardrails", [])
        except ClientError as err:
            if _region_unavailable_error(err) or _access_denied_error(err):
                return [
                    _make_na_finding(
                        check_id,
                        region,
                        f"Bedrock list_guardrails unavailable: {err.response.get('Error', {}).get('Code')}",
                    )
                ]
            raise
        if not guardrails:
            return findings  # No guardrails in region → skip.

        total = 0
        compliant = 0
        non_compliant_names: List[str] = []
        for g in guardrails:
            arn = g.get("arn") or g.get("id") or ""
            name = g.get("name") or arn
            version = g.get("version", "DRAFT")
            if not arn:
                continue
            try:
                detail = bedrock.get_guardrail(
                    guardrailIdentifier=arn, guardrailVersion=str(version)
                )
            except ClientError as err:
                if _region_unavailable_error(err) or _access_denied_error(err):
                    findings.append(
                        _make_na_finding(
                            check_id,
                            region,
                            (
                                f"Cannot read guardrail detail for {name}: "
                                f"{err.response.get('Error', {}).get('Code')}"
                            ),
                        )
                    )
                    continue
                raise
            except EndpointConnectionError:
                findings.append(
                    _make_na_finding(
                        check_id,
                        region,
                        f"Bedrock endpoint unreachable while reading guardrail {name}.",
                    )
                )
                continue

            total += 1
            pii_config = detail.get("sensitiveInformationPolicy", {}).get(
                "piiEntities", []
            )
            qualifying = False
            for pii in pii_config:
                action = str(pii.get("action", "")).upper()
                pii_type = str(pii.get("type", "")).upper()
                if pii_type.startswith("GENERAL") or pii_type == "GENERAL":
                    if action in {"BLOCK", "MASK", "ANONYMIZE", "DETECT"}:
                        qualifying = True
                        break
                # Some SDK shape names use `name` instead of `type`. Fall back.
                pii_name = str(pii.get("name", "")).upper()
                if pii_name.startswith("GENERAL") and action in {
                    "BLOCK",
                    "MASK",
                    "ANONYMIZE",
                    "DETECT",
                }:
                    qualifying = True
                    break
            if qualifying:
                compliant += 1
            else:
                non_compliant_names.append(name)

        if non_compliant_names:
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name="Bedrock Guardrails Lack Configured PII Detection",
                    finding_details=(
                        "These Bedrock guardrails in region "
                        + region
                        + " do not declare at least one GENERAL PII entity with BLOCK/MASK/"
                        "ANONYMIZE/DETECT action: "
                        + ", ".join(sorted(non_compliant_names))
                        + ". Guardrails are the automated evidence we correlate with the "
                        "164.312(a)(1) access-control and 164.312(a)(2)(iv) encryption-of-stored-"
                        "data goals when the model output might echo ePHI from the context."
                    ),
                    resolution=(
                        "For each affected guardrail, add at least the following GENERAL PII "
                        "entities with MASK or BLOCK action: NAME, US_SOCIAL_SECURITY_NUMBER, "
                        "EMAIL, PHONE, US_DRIVER_ID, ADDRESS, DATE_OF_BIRTH. Use custom regex "
                        "patterns for MRNs, account numbers, or any protected identifiers "
                        "specific to your organization."
                    ),
                    reference=HIPAA_CHECK_REFERENCES[check_id],
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                    region=region,
                    compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                )
            )

        if total > 0 and compliant == total:
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name="Bedrock Guardrails Have PII Detection with Deny/Mask Actions",
                    finding_details=(
                        f"All {total} Bedrock guardrails in region {region} include at least one "
                        "GENERAL PII entity with BLOCK/MASK/ANONYMIZE/DETECT action."
                    ),
                    resolution=(
                        "No action required. Cross-reference the configured PII entities with "
                        "your documented ePHI inventory and extend the guardrails as needed for "
                        "custom identifiers."
                    ),
                    reference=HIPAA_CHECK_REFERENCES[check_id],
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.PASSED,
                    region=region,
                    compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                )
            )
        return findings

    except ClientError as err:
        if _region_unavailable_error(err) or _access_denied_error(err):
            return [
                _make_na_finding(
                    check_id,
                    region,
                    f"Bedrock API unavailable or access denied: {err.response.get('Error', {}).get('Code')}",
                )
            ]
        raise


def check_s3_bucket_encryption_and_versioning(region: str) -> List[Dict[str, Any]]:
    """HP-07 — S3 buckets that look like AI/ML datasets are encrypted and
    versioned.

    To avoid auditing every bucket in the account (which would breach the
    scope of the AI/ML assessment and potentially over-flag unrelated
    storage), we only evaluate buckets whose name contains one of the
    following AI/ML dataset indicators: bedrock, sagemaker, aiml, ml-,
    -model, -dataset, -training, -data, models, datasets, fine-tune,
    finetune, -training-, training-data, -genai-, genai-, rag-data.

    A PASS requires each matched bucket to have:
      * default server-side encryption enabled (PutBucketEncryption populated
        with AES256 or aws:kms); and
      * object versioning Enabled (Suspended or unconfigured = FAIL).

    N/A rows are emitted when `s3:ListAllMyBuckets` or the per-bucket calls
    return AccessDenied or region-unavailable error codes.
    """
    check_id = "HP-07"
    findings: List[Dict[str, Any]] = []
    DATASET_NAME_HINTS = (
        "bedrock",
        "sagemaker",
        "aiml",
        "ml-",
        "-model",
        "-dataset",
        "-training",
        "-data",
        "models",
        "datasets",
        "fine-tune",
        "finetune",
        "training-data",
        "-genai-",
        "genai-",
        "rag-data",
    )
    try:
        s3 = boto3.client("s3", config=boto3_config)
        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except ClientError as err:
            if _region_unavailable_error(err) or _access_denied_error(err):
                return [
                    _make_na_finding(
                        check_id,
                        region,
                        f"s3:ListAllMyBuckets unavailable or access denied: {err.response.get('Error', {}).get('Code')}",
                    )
                ]
            raise

        scoped_names: List[str] = []
        for b in buckets:
            name = (b.get("Name") or "").lower()
            if not name:
                continue
            if any(hint in name for hint in DATASET_NAME_HINTS):
                scoped_names.append(b["Name"])
        if not scoped_names:
            return findings  # No candidate AI/ML dataset buckets → skip.

        failed: List[str] = []
        not_encrypted: List[str] = []
        not_versioned: List[str] = []
        for bname in scoped_names:
            enc_ok = False
            ver_ok = False
            try:
                enc = s3.get_bucket_encryption(Bucket=bname)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get(
                    "Rules", []
                )
                for r in rules:
                    sse = r.get("ApplyServerSideEncryptionByDefault", {})
                    algo = str(sse.get("SSEAlgorithm", "")).upper()
                    if algo in {"AES256", "AWS:MANAGED", "AWS:KMS"} or (
                        algo.startswith("AES") or algo.startswith("AWS")
                    ):
                        enc_ok = True
                        break
            except ClientError as err:
                code = err.response.get("Error", {}).get("Code", "")
                if (
                    "ServerSideEncryptionConfigurationNotFound" in code
                    or code == "ServerSideEncryptionConfigurationNotFoundError"
                ):
                    enc_ok = False
                elif _region_unavailable_error(err) or _access_denied_error(err):
                    findings.append(
                        _make_na_finding(
                            check_id,
                            region,
                            (
                                f"Cannot read S3 encryption config for {bname}: "
                                f"{err.response.get('Error', {}).get('Code')}"
                            ),
                        )
                    )
                    continue
                else:
                    raise

            try:
                ver = s3.get_bucket_versioning(Bucket=bname)
                ver_ok = ver.get("Status") == "Enabled"
            except ClientError as err:
                if _region_unavailable_error(err) or _access_denied_error(err):
                    findings.append(
                        _make_na_finding(
                            check_id,
                            region,
                            (
                                f"Cannot read S3 versioning config for {bname}: "
                                f"{err.response.get('Error', {}).get('Code')}"
                            ),
                        )
                    )
                    continue
                raise

            if enc_ok and ver_ok:
                continue
            failed.append(bname)
            if not enc_ok:
                not_encrypted.append(bname)
            if not ver_ok:
                not_versioned.append(bname)

        if failed:
            parts: List[str] = []
            if not_encrypted:
                parts.append(
                    "Missing default encryption: " + ", ".join(sorted(not_encrypted))
                )
            if not_versioned:
                parts.append("Missing versioning: " + ", ".join(sorted(not_versioned)))
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name="AI/ML Dataset S3 Buckets Lack Encryption or Versioning",
                    finding_details=(
                        "These candidate AI/ML dataset buckets in region "
                        + region
                        + " do not satisfy both default server-side encryption AND object "
                        "versioning evidence required by the HIPAA 164.312(a)(2)(iv) at-rest "
                        "encryption and HITECH breach-notification controls used here: "
                        + "; ".join(parts)
                    ),
                    resolution=(
                        "Apply PutBucketEncryption with SSE-KMS (aws:kms, customer key for "
                        "buckets confirmed to hold ePHI) and PutBucketVersioning with "
                        "Status=Enabled on each affected bucket. Enable an S3 lifecycle rule "
                        "that rolls expired object versions to Glacier Flexible Retrieval for "
                        "retention aligned with your documented records-retention schedule."
                    ),
                    reference=HIPAA_CHECK_REFERENCES[check_id],
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                    region=region,
                    compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                )
            )
        else:
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name="AI/ML Dataset S3 Buckets Are Encrypted and Versioned",
                    finding_details=(
                        f"All {len(scoped_names)} candidate AI/ML dataset S3 buckets in region "
                        f"{region} have default server-side encryption and object versioning enabled."
                    ),
                    resolution=(
                        "No action required. Cross-reference the bucket list against your "
                        "documented ePHI inventory and extend bucket policies to enforce "
                        "in-transit TLS and deny unencrypted object uploads (aws:SecureTransport "
                        "and s3:x-amz-server-side-encryption conditions)."
                    ),
                    reference=HIPAA_CHECK_REFERENCES[check_id],
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.PASSED,
                    region=region,
                    compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                )
            )
        return findings

    except ClientError as err:
        if _region_unavailable_error(err) or _access_denied_error(err):
            return [
                _make_na_finding(
                    check_id,
                    region,
                    f"S3 API unavailable or access denied: {err.response.get('Error', {}).get('Code')}",
                )
            ]
        raise


# ---------------------------------------------------------------------------
# CSV writer + S3 upload.
# ---------------------------------------------------------------------------
CSV_COLUMNS = [
    "Check_ID",
    "Finding",
    "Finding_Details",
    "Resolution",
    "Reference",
    "Severity",
    "Status",
    "Region",
    "Compliance_Frameworks",
]


def generate_csv_report(rows: List[Dict[str, Any]]) -> str:
    csv_buffer = StringIO()
    writer = csv.DictWriter(csv_buffer, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    for row in rows:
        writer.writerow({k: row.get(k, "") for k in CSV_COLUMNS})
    return csv_buffer.getvalue()


def write_to_s3(
    execution_id: str, csv_content: str, bucket_name: str, region: str = ""
) -> str:
    s3_client = boto3.client("s3", config=boto3_config)
    file_name = (
        f"hipaa_security_report_{execution_id}_{region}.csv"
        if region
        else f"hipaa_security_report_{execution_id}.csv"
    )
    s3_client.put_object(
        Bucket=bucket_name, Key=file_name, Body=csv_content, ContentType="text/csv"
    )
    s3_url = f"https://{bucket_name}.s3.amazonaws.com/{file_name}"
    logger.info(f"Successfully wrote HIPAA report to S3: {s3_url}")
    return s3_url


# ---------------------------------------------------------------------------
# Lambda entry point.
# ---------------------------------------------------------------------------
def run_all_checks(region: str) -> List[Dict[str, Any]]:
    """Invoke every HP-## check and return the flattened finding list.

    Each check function is responsible for its own exception handling and
    emits N/A rows when its required API is inaccessible; a top-level guard
    converts any residual unexpected ClientError into N/A for that check so
    the overall Lambda never fails on a single-check error.
    """
    check_fns = (
        check_bedrock_custom_model_encryption,
        check_sagemaker_resource_encryption,
        check_vpc_endpoints_configured,
        check_sagemaker_network_isolation,
        check_cloudwatch_logs_data_protection,
        check_bedrock_guardrail_pii,
        check_s3_bucket_encryption_and_versioning,
    )
    findings: List[Dict[str, Any]] = []
    for fn in check_fns:
        try:
            findings.extend(fn(region))
        except ClientError as err:
            check_id_token = {
                "check_bedrock_custom_model_encryption": "HP-01",
                "check_sagemaker_resource_encryption": "HP-02",
                "check_vpc_endpoints_configured": "HP-03",
                "check_sagemaker_network_isolation": "HP-04",
                "check_cloudwatch_logs_data_protection": "HP-05",
                "check_bedrock_guardrail_pii": "HP-06",
                "check_s3_bucket_encryption_and_versioning": "HP-07",
            }[fn.__name__]
            findings.append(
                _make_na_finding(
                    check_id_token,
                    region,
                    (
                        "Unexpected boto3 ClientError while evaluating check: "
                        f"{err.response.get('Error', {}).get('Code')}"
                    ),
                )
            )
        except EndpointConnectionError:
            check_id_token = {
                "check_bedrock_custom_model_encryption": "HP-01",
                "check_sagemaker_resource_encryption": "HP-02",
                "check_vpc_endpoints_configured": "HP-03",
                "check_sagemaker_network_isolation": "HP-04",
                "check_cloudwatch_logs_data_protection": "HP-05",
                "check_bedrock_guardrail_pii": "HP-06",
                "check_s3_bucket_encryption_and_versioning": "HP-07",
            }[fn.__name__]
            findings.append(
                _make_na_finding(
                    check_id_token,
                    region,
                    "AWS service endpoint unreachable for this check in the region.",
                )
            )
    return findings


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Main entry point for the HIPAA assessment Lambda.

    Expects the Step Functions payload used by the OWASP Lambda:
      { Execution: {Name: ...}, StateMachine: ..., Region: ..., RegionIndex: 0 }

    Unlike Responsible AI GRC which runs once (RegionIndex==0), HIPAA runs
    in every region because every check is region-scoped.
    """
    logger.info("Starting HIPAA/HITECH-aligned automated configuration checks")
    try:
        region = event.get("Region", os.environ.get("AWS_REGION", "us-east-1"))
        execution_id = event["Execution"]["Name"]
        bucket_name = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
        if not bucket_name:
            raise ValueError(
                "AIML_ASSESSMENT_BUCKET_NAME environment variable is not set"
            )

        logger.info(f"HIPAA assessment for region={region} execution={execution_id}")

        findings = run_all_checks(region)
        logger.info(f"HIPAA checks produced {len(findings)} rows for region={region}")

        csv_content = generate_csv_report(findings)
        s3_url = write_to_s3(execution_id, csv_content, bucket_name, region)

        return {
            "status": "success",
            "assessment": "hipaa",
            "region": region,
            "finding_count": len(findings),
            "report_s3_url": s3_url,
        }
    except ClientError:
        # Let the Step Functions Catch path wrap any infrastructure-layer
        # ClientError (wrong bucket IAM, etc.) into the Incomplete Pass.
        raise
