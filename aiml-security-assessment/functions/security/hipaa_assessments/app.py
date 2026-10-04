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
from datetime import datetime, timedelta, timezone
from io import StringIO
from typing import Any, Dict, List, Optional, Tuple

from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError

from schema import SeverityEnum, StatusEnum, create_finding

boto3_config = Config(retries=dict(max_attempts=10, mode="adaptive"))

logger = logging.getLogger()
logger.setLevel(logging.ERROR)


REGION_UNAVAILABLE_ERROR_CODES = {
    "UnrecognizedClientException",
    "OptInRequired",
}

CREDENTIAL_ERROR_CODES = {
    "InvalidClientTokenId",
    "AuthFailure",
    "ExpiredToken",
    "ExpiredTokenException",
    "RequestExpired",
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

PHI_ENTITY_TYPES = frozenset(
    {
        "NAME",
        "EMAIL",
        "PHONE",
        "ADDRESS",
        "AGE",
        "US_SOCIAL_SECURITY_NUMBER",
        "US_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER",
        "US_BANK_ACCOUNT_NUMBER",
        "US_CREDIT_DEBIT_CARD_NUMBER",
        "DATE_OF_BIRTH",
        "PASSWORD",
        "IP_ADDRESS",
        "MAC_ADDRESS",
        "URL",
    }
)

GUARDRAIL_PII_PROTECTED_ACTIONS = frozenset({"BLOCK", "ANONYMIZE"})

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


def _credential_error(err: ClientError) -> bool:
    return err.response.get("Error", {}).get("Code") in CREDENTIAL_ERROR_CODES


def _access_denied_error(err: ClientError) -> bool:
    return err.response.get("Error", {}).get("Code") in ACCESS_DENIED_ERROR_CODES


def _error_code(err: ClientError) -> str:
    return err.response.get("Error", {}).get("Code", "Unknown")


def _error_detail(err: ClientError) -> str:
    code = _error_code(err)
    message = err.response.get("Error", {}).get("Message", "")
    if message:
        return f"{code}: {message}"
    return code


def _run_check_safely(check_fn, check_id: str, region: str) -> List[Dict[str, Any]]:
    """Invoke one HIPAA check wrapped so an unexpected exception becomes a single
    Informational N/A incomplete row for that check_id instead of aborting the
    whole Lambda.  The CSV is still written with the remaining checks'
    findings.

    Mirrors agent_registry_assessments/app.py::_run_check_safely.
    """
    try:
        return list(check_fn(region))
    except ClientError as err:
        if _region_unavailable_error(err):
            return [
                _make_na_finding(
                    check_id,
                    region,
                    (
                        f"Region/service feature unavailable in region {region}: "
                        f"{_error_detail(err)}"
                    ),
                )
            ]
        if _credential_error(err):
            return [
                _make_na_finding(
                    check_id,
                    region,
                    (
                        "Credential or assume_role/authentication failure while calling AWS "
                        f"evaluating {check_id} in region {region}: "
                        f"{_error_detail(err)}. Verify the assessment role's "
                        "trust policy, session duration, and temporary "
                        "credential lifetime."
                    ),
                )
            ]
        if _access_denied_error(err):
            return [
                _make_na_finding(
                    check_id,
                    region,
                    (
                        f"Access denied evaluating {check_id} in region "
                        f"{region}: {_error_detail(err)}"
                    ),
                )
            ]
        raise
    except EndpointConnectionError as err:
        return [
            _make_na_finding(
                check_id,
                region,
                f"AWS endpoint unreachable for {check_id} in region {region}: {err}",
            )
        ]
    except Exception as err:  # noqa: BLE001
        return [
            create_finding(
                check_id=check_id,
                finding_name=f"{check_id} Incomplete",
                finding_details=(
                    f"Unexpected exception evaluating {check_id} in region "
                    f"{region}: {type(err).__name__}: {err}"
                ),
                resolution=(
                    "Review Lambda logs for the stack trace.  This N/A row is "
                    "evidence the check did not complete.  Remaining checks in "
                    "this Lambda continue unaffected."
                ),
                reference=AWS_HIPAA_REFERENCE_URL,
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.NA,
                region=region,
                compliance_frameworks=HIPAA_COMPLIANCE_MAP.get(check_id, ""),
            )
        ]


# ---------------------------------------------------------------------------
# Pagination + CMK helpers used across HP-01/HP-03/HP-04/HP-05/HP-06/HP-07.
# ---------------------------------------------------------------------------


def _ninety_days_ago_utc() -> datetime:
    """Return an offset-aware UTC datetime 90 calendar days before now.

    SageMaker ListTrainingJobs CreationTimeAfter accepts a datetime and
    filters jobs whose CreatedTime is at or after that instant.  90 days is
    the HIPAA/HITECH look-back window used by HP-04 so a reasonable subset
    of the training-job history is audited without truncating the catalog
    for a busy account.
    """
    return datetime.now(tz=timezone.utc) - timedelta(days=90)


def _bedrock_list_all_custom_models(bedrock_client) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        paginator = bedrock_client.get_paginator("list_custom_models")
        for page in paginator.paginate(PaginationConfig={"PageSize": 100}):
            out.extend(page.get("modelSummaries", []))
    except ClientError:
        out = bedrock_client.list_custom_models().get("modelSummaries", [])
    return out


def _sagemaker_list_all_endpoints(sagemaker_client) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        paginator = sagemaker_client.get_paginator("list_endpoints")
        for page in paginator.paginate(PaginationConfig={"PageSize": 100}):
            out.extend(page.get("Endpoints", []))
    except ClientError:
        out = sagemaker_client.list_endpoints(MaxResults=100).get("Endpoints", [])
    return out


def _sagemaker_list_recent_training_jobs(sagemaker_client) -> List[Dict[str, Any]]:
    """List training jobs created in the last 90 days (HP-04 look-back window).

    Uses CreationTimeAfter when available; otherwise falls back to a raw
    list + client-side filter so the check still runs on older SDK builds.
    """
    cutoff = _ninety_days_ago_utc()
    out: List[Dict[str, Any]] = []
    try:
        paginator = sagemaker_client.get_paginator("list_training_jobs")
        for page in paginator.paginate(
            SortBy="CreationTime",
            SortOrder="Descending",
            CreationTimeAfter=cutoff,
            PaginationConfig={"PageSize": 100},
        ):
            summaries = page.get("TrainingJobSummaries", [])
            for s in summaries:
                created = s.get("CreationTime")
                if isinstance(created, datetime) and created < cutoff:
                    return out
                out.append(s)
    except ClientError:
        raw = sagemaker_client.list_training_jobs(
            SortBy="CreationTime",
            SortOrder="Descending",
            MaxResults=500,
        ).get("TrainingJobSummaries", [])
        for s in raw:
            created = s.get("CreationTime")
            if isinstance(created, datetime) and created < cutoff:
                break
            out.append(s)
    return out


def _ec2_list_all_vpcs(ec2_client) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        paginator = ec2_client.get_paginator("describe_vpcs")
        for page in paginator.paginate(PaginationConfig={"PageSize": 100}):
            out.extend(page.get("Vpcs", []))
    except ClientError:
        out = ec2_client.describe_vpcs(MaxResults=100).get("Vpcs", [])
    return out


def _ec2_list_all_vpc_endpoints(ec2_client) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        paginator = ec2_client.get_paginator("describe_vpc_endpoints")
        for page in paginator.paginate(PaginationConfig={"PageSize": 100}):
            out.extend(page.get("VpcEndpoints", []))
    except ClientError:
        out = ec2_client.describe_vpc_endpoints(MaxResults=100).get("VpcEndpoints", [])
    return out


def _logs_list_log_groups_for_prefix(
    logs_client, log_group_name_prefix: str, cap: int = 200
) -> List[Dict[str, Any]]:
    """Return at most `cap` log groups matching one AIML prefix.

    HP-05 uses six independent prefix scans because CloudWatch's
    DescribeLogGroups paginator only accepts a single `logGroupNamePrefix`
    per call, and the HIPAA scope is deliberately limited to AIML-shaped
    groups so we never scan every group in a busy account.
    """
    out: List[Dict[str, Any]] = []
    try:
        paginator = logs_client.get_paginator("describe_log_groups")
        for page in paginator.paginate(
            logGroupNamePrefix=log_group_name_prefix,
            PaginationConfig={"PageSize": 50, "MaxItems": cap},
        ):
            page_groups = page.get("logGroups", [])
            if not page_groups:
                break
            out.extend(page_groups)
            if len(out) >= cap:
                return out[:cap]
    except ClientError:
        raw = logs_client.describe_log_groups(
            logGroupNamePrefix=log_group_name_prefix, limit=50
        ).get("logGroups", [])
        out.extend(raw)
    return out[:cap]


def _s3_list_all_buckets(s3_client) -> List[Dict[str, Any]]:
    """Return s3:ListAllMyBuckets result; pagination is not supported for
    this operation in the SDK so a single call is sufficient."""
    return s3_client.list_buckets().get("Buckets", [])


def _kms_is_customer_managed_key(
    kms_client, key_arn: str
) -> Tuple[bool, Optional[str]]:
    """Validate `key_arn` resolves to a customer-managed KMS key via
    kms:DescribeKey returning KeyManager == "CUSTOMER".

    Returns (is_cmk, note) where note is a non-empty string with the
    evidence reason when the key cannot be verified as customer-managed and
    None otherwise.  Transient access-denied / region-unavailable errors
    result in (False, reason) so the calling check can still emit an
    informative finding rather than guessing.
    """
    if not key_arn:
        return False, "key ARN is empty"
    try:
        resp = kms_client.describe_key(KeyId=key_arn)
    except ClientError as err:
        if _region_unavailable_error(err) or _access_denied_error(err):
            return False, (
                f"kms:DescribeKey inaccessible for {key_arn}: {_error_detail(err)}"
            )
        if _credential_error(err):
            return False, (
                f"kms:DescribeKey credential failure for {key_arn}: "
                f"{_error_detail(err)}"
            )
        return False, (
            f"kms:DescribeKey unexpected error for {key_arn}: {_error_detail(err)}"
        )
    key_meta = resp.get("KeyMetadata", {})
    manager = str(key_meta.get("KeyManager", "")).upper()
    state = str(key_meta.get("KeyState", "")).upper()
    if manager == "CUSTOMER" and state in {"ENABLED", "PENDING_DELETION"}:
        return True, None
    note = f"KeyManager={manager!r} KeyState={state!r}"
    if state not in {"ENABLED", "PENDING_DELETION"}:
        note += " (key is disabled or unusable)"
    return False, note


# Required VPC endpoint service names used by HP-06.  Order is the report
# output order; keep consistent with docs.
REQUIRED_HIPAA_VPC_ENDPOINT_SERVICES: Tuple[str, ...] = (
    "com.amazonaws.{region}.bedrock",
    "com.amazonaws.{region}.bedrock-agent",
    "com.amazonaws.{region}.bedrock-agent-runtime",
    "com.amazonaws.{region}.sagemaker.api",
    "com.amazonaws.{region}.sagemaker.runtime",
    "com.amazonaws.{region}.sagemaker.featurestore-runtime",
    "com.amazonaws.{region}.sts",
    "com.amazonaws.{region}.kms",
    "com.amazonaws.{region}.secretsmanager",
    "com.amazonaws.{region}.logs",
    "com.amazonaws.{region}.s3",
    "com.amazonaws.{region}.ec2",
)


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
    """HP-01 — Bedrock custom model encryption at rest validated via CMK."""
    check_id = "HP-01"
    findings: List[Dict[str, Any]] = []
    bedrock = boto3.client("bedrock", region_name=region, config=boto3_config)
    kms = boto3.client("kms", region_name=region, config=boto3_config)
    try:
        custom_models = _bedrock_list_all_custom_models(bedrock)
    except ClientError as err:
        if _region_unavailable_error(err) or _access_denied_error(err):
            return [
                _make_na_finding(
                    check_id,
                    region,
                    (
                        "Cannot enumerate Bedrock custom models "
                        f"(list_custom_models): {_error_detail(err)}"
                    ),
                )
            ]
        if _credential_error(err):
            return [
                _make_na_finding(
                    check_id,
                    region,
                    (
                        "Cannot enumerate Bedrock custom models "
                        f"(credential error on list_custom_models): "
                        f"{_error_detail(err)}"
                    ),
                )
            ]
        raise
    except EndpointConnectionError:
        return [
            _make_na_finding(
                check_id,
                region,
                "Bedrock endpoint unreachable while enumerating custom models.",
            )
        ]

    if not custom_models:
        return [
            _make_na_finding(
                check_id,
                region,
                (
                    f"No Bedrock custom models (imported or fine-tuned) found in region "
                    f"{region}. No 164.312(a)(2)(iv) at-rest encryption evidence to inspect."
                ),
            )
        ]

    total = 0
    compliant = 0
    truncated = False
    for model in custom_models:
        if total >= 200:
            truncated = True
            break
        model_arn = model.get("modelArn") or model.get("modelId") or "unknown"
        model_name = model.get("modelName") or model_arn
        total += 1
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
                            f"Cannot read get_custom_model for {model_name} in "
                            f"region {region}: {_error_detail(err)}"
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

        if not kms_arn:
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name="Bedrock Custom Model Lacks CMK Encryption Key",
                    finding_details=(
                        f"Bedrock custom model '{model_name}' ({model_arn}) in region "
                        f"{region} has no modelKmsKeyArn.  Bedrock-managed default storage "
                        "encryption (no explicit customer or service KMS key) does not meet "
                        "the HIPAA 164.312(a)(2)(iv) ePHI-at-rest evidence rule used here."
                    ),
                    resolution=(
                        "Re-create the custom model (import or fine-tuning job) with an "
                        "explicit customer-managed KMS key ARN in modelKmsKeyArn.  Enable "
                        "key rotation and record the key in your HIPAA configuration-"
                        "management program."
                    ),
                    reference=HIPAA_CHECK_REFERENCES[check_id],
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                    region=region,
                    compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                )
            )
            continue

        is_cmk, note = _kms_is_customer_managed_key(kms, kms_arn)
        if not is_cmk:
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name=(
                        "Bedrock Custom Model Uses Non-Customer-Managed KMS Key"
                    ),
                    finding_details=(
                        f"Bedrock custom model '{model_name}' ({model_arn}) in region "
                        f"{region} references a non-customer-managed KMS key: "
                        f"{note or 'KeyManager != CUSTOMER'}.  Only CUSTOMER keys are "
                        "accepted as 164.312(a)(2)(iv) evidence by this automated check."
                    ),
                    resolution=(
                        "Re-create the custom model specifying a customer-managed KMS key "
                        "(KeyManager=CUSTOMER) in modelKmsKeyArn.  Enable KMS key rotation."
                    ),
                    reference=HIPAA_CHECK_REFERENCES[check_id],
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                    region=region,
                    compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                )
            )
            continue

        compliant += 1

    if truncated:
        findings.append(
            _make_na_finding(
                check_id,
                region,
                (
                    "Bedrock custom-model inventory was truncated at the 200-item "
                    f"safety cap.  Only the first {total} custom models in region "
                    f"{region} were evaluated.  Any non-compliant models beyond the "
                    "cap are not reflected in the Passed/Failed rows below."
                ),
            )
        )

    if total > 0 and compliant == total:
        phrase = "All"
        if truncated:
            phrase = f"All {total} inspected"
        findings.append(
            create_finding(
                check_id=check_id,
                finding_name=(
                    "Bedrock Custom Models Use Customer-Managed KMS Encryption"
                ),
                finding_details=(
                    f"{phrase} Bedrock custom models in region {region} carry an "
                    "explicit modelKmsKeyArn that resolves to a customer-managed KMS "
                    "key (KeyManager == CUSTOMER) via kms:DescribeKey."
                ),
                resolution="No action required.",
                reference=HIPAA_CHECK_REFERENCES[check_id],
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.PASSED,
                region=region,
                compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
            )
        )
    return findings


def check_sagemaker_resource_encryption(region: str) -> List[Dict[str, Any]]:
    """HP-04 — SageMaker endpoints and training jobs encrypted at rest.

    SageMaker endpoint scopes two independent evidence streams:

      * **Endpoints* — for each endpoint returned by paginated `list_endpoints`,
        resolve the endpoint's EndpointConfig `KmsKeyId` plus, when populated,
        validate the key is customer-managed via `kms:DescribeKey`
        (KeyManager == CUSTOMER).
      * **Training jobs** — for each training job created in the last 90 days
        (CreationTimeAfter), validate (a) `ResourceConfig.VolumeKmsKeyId` is CMK;
        (b) `OutputDataConfig.KmsKeyId` is CMK; (c)
        `EnableInterContainerTrafficEncryption == True`; and emit one Failed row
        per non-compliant job.

    Emits a Passed aggregate row when at least one SageMaker resource exists and
    every inspected item is CMK-bound and EnableInterContainerTrafficEncryption is
    True for the training jobs inspected.  Empty inventories produce explicit N/A rows so
    readers see the check ran and found nothing to inspect.
    """
    check_id = "HP-04"
    findings: List[Dict[str, Any]] = []
    sagemaker = boto3.client("sagemaker", region_name=region, config=boto3_config)
    kms = boto3.client("kms", region_name=region, config=boto3_config)

    endpoints = _sagemaker_list_all_endpoints(sagemaker)
    training_jobs = _sagemaker_list_recent_training_jobs(sagemaker)

    if not endpoints and not training_jobs:
        return [
            _make_na_finding(
                check_id,
                region,
                (
                    "No SageMaker endpoints and no SageMaker training jobs created in the "
                    f"last 90 days in region {region}.  No 164.312(a)(2)(iv) at-rest "
                    "encryption evidence to inspect."
                ),
            )
        ]

    total = 0
    compliant = 0
    truncated_endpoints = 0
    truncated = False
    ENDPOINT_CAP = 150
    TRAINING_CAP = 150

    # —— Endpoints.
    for ep in endpoints:
        if truncated_endpoints >= ENDPOINT_CAP:
            truncated = True
            break
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
                        f"Cannot describe SageMaker endpoint {ep_name}: {_error_detail(err)}",
                    )
                )
                continue
            raise
        truncated_endpoints += 1
        total += 1
        kms_id = cfg.get("KmsKeyId") or ""
        if not kms_id:
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name=("SageMaker EndpointConfig Lacks CMK Encryption Key"),
                    finding_details=(
                        f"SageMaker endpoint '{ep_name}' in region {region} uses "
                        f"EndpointConfig '{cfg_name}' with no KmsKeyId.  SageMaker-managed "
                        "default storage encryption without an explicit customer KMS key "
                        "is not sufficient 164.312(a)(2)(iv) evidence."
                    ),
                    resolution=(
                        "Deploy a new EndpointConfig specifying a customer-managed "
                        "KmsKeyId and attach it with UpdateEndpoint.  Enable KMS key "
                        "rotation and document the key in your HIPAA CM program."
                    ),
                    reference=HIPAA_CHECK_REFERENCES[check_id],
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                    region=region,
                    compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                )
            )
            continue
        is_cmk, note = _kms_is_customer_managed_key(kms, kms_id)
        if not is_cmk:
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name=(
                        "SageMaker EndpointConfig Uses Non-Customer-Managed KMS Key"
                    ),
                    finding_details=(
                        f"SageMaker endpoint '{ep_name}' in region {region} "
                        f"EndpointConfig '{cfg_name}' references a non-customer "
                        f"KMS key: {note or 'KeyManager != CUSTOMER'}.  Only "
                        "customer-managed keys are accepted as HP-04 evidence."
                    ),
                    resolution=(
                        "Re-create the EndpointConfig with a customer-managed "
                        "KMS key and run UpdateEndpoint.  Re-deploy under the "
                        "new config."
                    ),
                    reference=HIPAA_CHECK_REFERENCES[check_id],
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                    region=region,
                    compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                )
            )
            continue
        compliant += 1

    # —— Training jobs (last 90 days).
    tj_count = 0
    for tj in training_jobs:
        if tj_count >= TRAINING_CAP:
            truncated = True
            break
        tj_name = tj.get("TrainingJobName")
        if not tj_name:
            continue
        tj_count += 1
        try:
            tj_desc = sagemaker.describe_training_job(TrainingJobName=tj_name)
        except ClientError as err:
            if _region_unavailable_error(err) or _access_denied_error(err):
                findings.append(
                    _make_na_finding(
                        check_id,
                        region,
                        f"Cannot describe SageMaker training job {tj_name}: "
                        f"{_error_detail(err)}",
                    )
                )
                continue
            raise
        total += 1
        # Collect each item counts as two evidence items (volume + output + inter-container encryption).

        resource_cfg = tj_desc.get("ResourceConfig", {})
        vol_kms = resource_cfg.get("VolumeKmsKeyId") or ""
        out_cfg = tj_desc.get("OutputDataConfig", {})
        out_kms = out_cfg.get("KmsKeyId") or ""
        inter = bool(tj_desc.get("EnableInterContainerTrafficEncryption", False))
        fail_reasons: List[str] = []

        if not vol_kms:
            fail_reasons.append("ResourceConfig.VolumeKmsKeyId empty")
        else:
            is_cmk, vol_note = _kms_is_customer_managed_key(kms, vol_kms)
            if not is_cmk:
                fail_reasons.append(
                    "ResourceConfig.VolumeKmsKeyId not customer-managed"
                    f" ({vol_note or 'KeyManager != CUSTOMER'})"
                )

        if not out_kms:
            fail_reasons.append("OutputDataConfig.KmsKeyId empty")
        else:
            is_cmk, out_note = _kms_is_customer_managed_key(kms, out_kms)
            if not is_cmk:
                fail_reasons.append(
                    "OutputDataConfig.KmsKeyId not customer-managed"
                    f" ({out_note or 'KeyManager != CUSTOMER'})"
                )

        if not inter:
            fail_reasons.append("EnableInterContainerTrafficEncryption is not True")

        if fail_reasons:
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name=(
                        "SageMaker Training Job Missing Required CMK Encryption or "
                        "Inter-Container Encryption"
                    ),
                    finding_details=(
                        f"SageMaker training job '{tj_name}' in region {region} "
                        "failed HP-04 evidence checks: " + "; ".join(fail_reasons) + "."
                    ),
                    resolution=(
                        "Run the training job again with (a) ResourceConfig."
                        "VolumeKmsKeyId = customer CMK; (b) OutputDataConfig."
                        "KmsKeyId = customer CMK; (c) "
                        "EnableInterContainerTrafficEncryption = True."
                    ),
                    reference=HIPAA_CHECK_REFERENCES[check_id],
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                    region=region,
                    compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                )
            )
            continue

        compliant += 1

    if truncated:
        findings.append(
            _make_na_finding(
                check_id,
                region,
                (
                    "SageMaker resource inventory was truncated at the "
                    f"{ENDPOINT_CAP}-endpoint / {TRAINING_CAP}-training-job safety "
                    f"caps.  Only the first {truncated_endpoints} endpoints "
                    f"endpoints and {tj_count} recent training jobs in region "
                    f"{region} were evaluated."
                ),
            )
        )

    if total > 0 and compliant == total:
        phrase = "All"
        if truncated:
            phrase = f"All {total} inspected"
        findings.append(
            create_finding(
                check_id=check_id,
                finding_name=(
                    "SageMaker Endpoints and Recent Training Jobs Use CMK Encryption"
                ),
                finding_details=(
                    f"{phrase} inspected SageMaker endpoints and training jobs in region "
                    f"{region} satisfy HP-04: endpoint KmsKeyId customer-managed; "
                    "training job volume/output CMK keys customer-managed; and "
                    "EnableInterContainerTrafficEncryption = True."
                ),
                resolution="No action required.",
                reference=HIPAA_CHECK_REFERENCES[check_id],
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.PASSED,
                region=region,
                compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
            )
        )
    return findings


def check_vpc_endpoints_configured(region: str) -> List[Dict[str, Any]]:
    """HP-06 — Required VPC Interface/Gateway endpoints present and available
    in at least one VPC.

    Rule change vs naive per-VPC checklist: the automated evidence we
    correlate with 164.312(e)(1) Transmission Security does not require
    *every* VPC to attach every endpoint; it requires each required
    AI/ML-and-supporting service endpoint to exist with State=="available"
    in *at least one* VPC in the assessed region.  Workloads handling ePHI
    are expected to run from those VPCs.

    Required services (12 total):
      * bedrock, bedrock-agent, bedrock-agent-runtime
      * sagemaker.api, sagemaker.runtime, sagemaker.featurestore-runtime
      * sts, kms, secretsmanager
      * logs, s3, ec2

    Emits one Failed row listing missing/non-available endpoint services,
    one aggregate Passed row if every required service has at least one
    available VPC endpoint, an explicit Informational N/A when zero VPCs
    exist, and a truncation N/A when the VPC/endpoint inventories exceed
    the safety caps.
    """
    check_id = "HP-06"
    findings: List[Dict[str, Any]] = []
    VPC_CAP = 100
    ENDPOINT_CAP = 200
    try:
        ec2 = boto3.client("ec2", region_name=region, config=boto3_config)
        vpcs = _ec2_list_all_vpcs(ec2)
        vpc_ids = [v.get("VpcId") for v in vpcs if v.get("VpcId")]

        if not vpc_ids:
            return [
                _make_na_finding(
                    check_id,
                    region,
                    (
                        f"Zero VPCs are defined in region {region}.  AI/ML VPC "
                        "endpoint reachability cannot be evaluated without any "
                        "VPC to inspect."
                    ),
                )
            ]

        vpc_truncated = len(vpc_ids) > VPC_CAP
        if vpc_truncated:
            vpc_ids = vpc_ids[:VPC_CAP]
            findings.append(
                _make_na_finding(
                    check_id,
                    region,
                    (
                        f"VPC inventory was truncated at {VPC_CAP} VPCs in region "
                        f"{region}.  Endpoints attached to VPCs beyond the cap are "
                        "not reflected in the Passed/Failed rows below."
                    ),
                )
            )

        endpoints = _ec2_list_all_vpc_endpoints(ec2)
        endpoint_truncated = len(endpoints) > ENDPOINT_CAP
        if endpoint_truncated:
            endpoints = endpoints[:ENDPOINT_CAP]
            findings.append(
                _make_na_finding(
                    check_id,
                    region,
                    (
                        f"VPC endpoint inventory was truncated at {ENDPOINT_CAP} "
                        f"endpoints in region {region}.  Endpoints beyond the cap "
                        "are not reflected in the Passed/Failed rows below."
                    ),
                )
            )

        required_services = tuple(
            tmpl.format(region=region) for tmpl in REQUIRED_HIPAA_VPC_ENDPOINT_SERVICES
        )

        available_services: set = set()
        for ep in endpoints:
            svc = ep.get("ServiceName") or ""
            state = str(ep.get("State", "")).lower()
            if svc in required_services and state == "available":
                available_services.add(svc)

        missing = sorted(s for s in required_services if s not in available_services)
        if missing:
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name="Required AI/ML VPC Endpoints Missing or Unavailable",
                    finding_details=(
                        "In region "
                        + region
                        + ", the following required AI/ML-and-supporting VPC "
                        "endpoint services have no endpoint with State=='available' "
                        "in any inspected VPC ("
                        + str(len(vpc_ids))
                        + " VPCs, "
                        + str(len(endpoints))
                        + " endpoints inspected): "
                        + ", ".join(missing)
                        + ".  Private-network egress for ePHI-bearing AI/ML traffic "
                        "(164.312(e)(1)/(e)(2)(ii) transmission-security evidence) "
                        "cannot be confirmed without every required endpoint service "
                        "reachable in at least one VPC."
                    ),
                    resolution=(
                        "Provision Interface endpoints (s3 is a Gateway endpoint) "
                        "for each missing service, attach them to at least one "
                        "AI/ML-workload VPC with appropriate subnet/security-group "
                        "selection, and wait until each endpoint reports "
                        "State==available before retrying this assessment."
                    ),
                    reference=HIPAA_CHECK_REFERENCES[check_id],
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                    region=region,
                    compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                )
            )
        else:
            inventory_phrase = "Every required"
            if vpc_truncated or endpoint_truncated:
                inventory_phrase = (
                    f"Every required (among {len(endpoints)} inspected endpoints in "
                    f"{len(vpc_ids)} inspected VPCs)"
                )
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name="Required AI/ML VPC Endpoints Available",
                    finding_details=(
                        f"{inventory_phrase} AI/ML-and-supporting VPC endpoint "
                        f"service in region {region} is attached with "
                        "State=='available' in at least one inspected VPC."
                    ),
                    resolution="No action required.",
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
                    f"EC2 API unavailable or access denied: {_error_detail(err)}",
                )
            ]
        raise


def check_sagemaker_network_isolation(region: str) -> List[Dict[str, Any]]:
    """HP-03 — SageMaker endpoints and recent training jobs network-isolated.

    Evidence paths (endpoint chain, per ProductionVariant):
      * For each endpoint returned by paginated `list_endpoints`, resolve
        describe_endpoint → ProductionVariants[].VariantName + ModelName.
      * Call `sagemaker:DescribeModel(ModelName=…)` and check
        `Model.EnableNetworkIsolation == True`.  This is the authoritative
        evidence for 164.312(a)(1) access-control and 164.312(e)(2)(ii)
        transmission-security alignment for standard single-model endpoints.
      * Inference-component endpoints (which do not populate
        ProductionVariants[].ModelName) fall back to the endpoint config's
        `EnableNetworkIsolation` field.

    Training jobs: each training job created in the last 90 days must have
    its top-level `EnableNetworkIsolation == True`.

    Emits one Failed row per non-isolated endpoint/TJ, explicit empty N/A
    when inventory is empty, caps at ENDPOINT_CAP=150 / TRAINING_CAP=150
    with truncation N/A notices, and an aggregate Passed row when every
    inspected resource is isolated with Resolution exact "No action required."
    """
    check_id = "HP-03"
    findings: List[Dict[str, Any]] = []
    ENDPOINT_CAP = 150
    TRAINING_CAP = 150
    sagemaker = boto3.client("sagemaker", region_name=region, config=boto3_config)

    endpoints = _sagemaker_list_all_endpoints(sagemaker)
    endpoint_truncated = len(endpoints) > ENDPOINT_CAP
    if endpoint_truncated:
        endpoints = endpoints[:ENDPOINT_CAP]
        findings.append(
            _make_na_finding(
                check_id,
                region,
                (
                    f"SageMaker endpoint inventory was truncated at {ENDPOINT_CAP} "
                    f"endpoints in region {region}.  Non-isolated endpoints beyond "
                    "the cap are not reflected in the Passed/Failed rows below."
                ),
            )
        )

    training_jobs = _sagemaker_list_recent_training_jobs(sagemaker)
    training_truncated = len(training_jobs) > TRAINING_CAP
    if training_truncated:
        training_jobs = training_jobs[:TRAINING_CAP]
        findings.append(
            _make_na_finding(
                check_id,
                region,
                (
                    f"SageMaker recent-training-job inventory was truncated at "
                    f"{TRAINING_CAP} jobs in region {region}.  Non-isolated jobs "
                    "beyond the cap are not reflected in the Passed/Failed rows below."
                ),
            )
        )

    total_endpoints = 0
    compliant_endpoints = 0
    non_compliant_endpoints: List[str] = []
    for ep in endpoints:
        ep_name = ep.get("EndpointName") or "unknown"
        total_endpoints += 1
        try:
            ep_desc = sagemaker.describe_endpoint(EndpointName=ep_name)
        except ClientError as err:
            if _region_unavailable_error(err) or _access_denied_error(err):
                findings.append(
                    _make_na_finding(
                        check_id,
                        region,
                        (
                            f"Cannot describe_endpoint for {ep_name}: "
                            f"{_error_detail(err)}"
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
                    f"SageMaker endpoint unreachable while inspecting {ep_name}.",
                )
            )
            continue

        cfg_name = ep_desc.get("EndpointConfigName") or ""
        variants = ep_desc.get("ProductionVariants", []) or []
        ep_isolated = True
        ep_evidence: List[str] = []
        if variants:
            for v in variants:
                vname = v.get("VariantName") or "unnamed-variant"
                model_name = v.get("ModelName") or ""
                if not model_name:
                    ep_evidence.append(
                        f"variant {vname}: no ModelName (inference-component fallback)"
                    )
                    continue
                try:
                    model_desc = sagemaker.describe_model(ModelName=model_name)
                except ClientError as err:
                    if _region_unavailable_error(err) or _access_denied_error(err):
                        findings.append(
                            _make_na_finding(
                                check_id,
                                region,
                                (
                                    f"Cannot sagemaker:DescribeModel for "
                                    f"model={model_name} on endpoint={ep_name}: "
                                    f"{_error_detail(err)}"
                                ),
                            )
                        )
                        ep_isolated = False
                        continue
                    raise
                if model_desc.get("EnableNetworkIsolation") is True:
                    ep_evidence.append(
                        f"variant {vname} model={model_name}: EnableNetworkIsolation=true (DescribeModel)"
                    )
                else:
                    ep_isolated = False
                    ep_evidence.append(
                        f"variant {vname} model={model_name}: EnableNetworkIsolation != true (DescribeModel)"
                    )
        else:
            ep_evidence.append("endpoint has no ProductionVariants")

        if not variants or any("no ModelName" in e for e in ep_evidence):
            if cfg_name:
                try:
                    cfg = sagemaker.describe_endpoint_config(
                        EndpointConfigName=cfg_name
                    )
                    if cfg.get("EnableNetworkIsolation") is True:
                        ep_evidence.append(
                            f"fallback EndpointConfig {cfg_name}: EnableNetworkIsolation=true"
                        )
                    else:
                        ep_isolated = False
                        ep_evidence.append(
                            f"fallback EndpointConfig {cfg_name}: EnableNetworkIsolation != true"
                        )
                except ClientError as err:
                    if _region_unavailable_error(err) or _access_denied_error(err):
                        findings.append(
                            _make_na_finding(
                                check_id,
                                region,
                                (
                                    f"Cannot describe_endpoint_config for "
                                    f"{cfg_name} on endpoint {ep_name}: "
                                    f"{_error_detail(err)}"
                                ),
                            )
                        )
                        ep_isolated = False
                    else:
                        raise

        if ep_isolated and all("EnableNetworkIsolation=true" in e for e in ep_evidence):
            compliant_endpoints += 1
        else:
            non_compliant_endpoints.append(f"{ep_name} ({'; '.join(ep_evidence)})")

    total_training = 0
    compliant_training = 0
    non_compliant_training: List[str] = []
    for tj in training_jobs:
        tj_name = tj.get("TrainingJobName") or "unknown"
        total_training += 1
        try:
            tj_desc = sagemaker.describe_training_job(TrainingJobName=tj_name)
        except ClientError as err:
            if _region_unavailable_error(err) or _access_denied_error(err):
                findings.append(
                    _make_na_finding(
                        check_id,
                        region,
                        (
                            f"Cannot describe_training_job for {tj_name}: "
                            f"{_error_detail(err)}"
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
                    f"SageMaker training-job API unreachable while inspecting {tj_name}.",
                )
            )
            continue
        if tj_desc.get("EnableNetworkIsolation") is True:
            compliant_training += 1
        else:
            non_compliant_training.append(tj_name)

    total_resources = total_endpoints + total_training
    if not total_resources and not (endpoint_truncated or training_truncated):
        findings.append(
            _make_na_finding(
                check_id,
                region,
                (
                    f"No SageMaker endpoints or recent (last-90-day) training jobs "
                    f"found in region {region}.  No 164.312(a)(1) network-isolation "
                    "evidence to inspect."
                ),
            )
        )
        return findings

    if non_compliant_endpoints or non_compliant_training:
        if non_compliant_endpoints:
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name="SageMaker Endpoint Models Not Network-Isolated",
                    finding_details=(
                        "In region "
                        + region
                        + ", the following SageMaker endpoints host at least "
                        "one ProductionVariant whose model's "
                        "sagemaker:DescribeModel EnableNetworkIsolation field "
                        "is not True (inference-component endpoints fall back "
                        "to EndpointConfig.EnableNetworkIsolation): "
                        + "; ".join(non_compliant_endpoints)
                        + ".  Non-isolated containers handling ePHI are not "
                        "consistent with the 164.312(a)(1) access-control and "
                        "164.312(e)(2)(ii) transmission-security evidence "
                        "goals used by HP-03."
                    ),
                    resolution=(
                        "Deploy replacement models with "
                        "EnableNetworkIsolation=true passed to CreateModel, "
                        "attach them via new EndpointConfig + UpdateEndpoint, "
                        "and re-run recent training jobs with "
                        "EnableNetworkIsolation=true.  Confirm workload "
                        "containers do not require post-deployment outbound "
                        "internet before enabling isolation."
                    ),
                    reference=HIPAA_CHECK_REFERENCES[check_id],
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                    region=region,
                    compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                )
            )
        if non_compliant_training:
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name="SageMaker Training Jobs Not Network-Isolated",
                    finding_details=(
                        "In region "
                        + region
                        + ", the following SageMaker recent (last-90-day) "
                        "training jobs have EnableNetworkIsolation != True: "
                        + ", ".join(sorted(non_compliant_training))
                        + ".  Training containers processing ePHI should be "
                        "network-isolated to reduce exfiltration vectors "
                        "tracked under 164.312(e)(1)."
                    ),
                    resolution=(
                        "Re-submit the affected training jobs with "
                        "EnableNetworkIsolation=true and, if they need to "
                        "reach VPC-local services, with an explicit "
                        "VpcConfig (network isolation still allows VPC-"
                        "scoped traffic)."
                    ),
                    reference=HIPAA_CHECK_REFERENCES[check_id],
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                    region=region,
                    compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                )
            )

    compliant_total = compliant_endpoints + compliant_training
    if total_resources > 0 and compliant_total == total_resources:
        inventory_phrase = "All"
        if endpoint_truncated or training_truncated:
            inventory_phrase = f"All {total_resources} inspected"
        findings.append(
            create_finding(
                check_id=check_id,
                finding_name="SageMaker Resources Are Network-Isolated",
                finding_details=(
                    f"{inventory_phrase} SageMaker resources in region "
                    f"{region} are network-isolated: {compliant_endpoints} "
                    f"endpoints (evidence via sagemaker:DescribeModel per "
                    f"ProductionVariant, EndpointConfig fallback where "
                    f"applicable) and {compliant_training} recent training "
                    "jobs (EnableNetworkIsolation == True on describe_training_job)."
                ),
                resolution="No action required.",
                reference=HIPAA_CHECK_REFERENCES[check_id],
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.PASSED,
                region=region,
                compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
            )
        )
    return findings


def check_cloudwatch_logs_data_protection(region: str) -> List[Dict[str, Any]]:
    """HP-05 — CloudWatch Logs AIML-scoped log groups protected by a
    data-protection policy (account-level or per-group).

    Scopes evaluation to log groups whose name starts with one of
    AIML_LOG_GROUP_PREFIXES using six independent prefix-paginated scans
    (cap 200 per prefix).  A log group is "protected" when EITHER:
      (a) its per-group `get_data_protection_policy` call returns a
          non-empty, parseable policy body with `dataProtectionStatus`
          equal to "ACTIVATED"; OR
      (b) the account-level `logs:DescribeAccountPolicies`
          (policyType="DATA_PROTECTION_POLICY") reports an account-wide
          data-protection policy that applies to the group.

    Critically, when `get_data_protection_policy` returns an empty `{}`
    body (as opposed to a 200-OK with populated policy, or
    ResourceNotFoundException) the group is NOT protected; this was a
    previous silent-pass bug and is now flagged Failed.

    Emits one Failed row for each non-protected group (aggregated),
    explicit empty N/A when zero AIML-prefixed groups exist, truncation
    N/A notice at cap, and aggregate Passed row when every inspected
    group is protected with Resolution exact "No action required."
    """
    check_id = "HP-05"
    findings: List[Dict[str, Any]] = []
    LOG_GROUP_CAP_PER_PREFIX = 200
    logs = boto3.client("logs", region_name=region, config=boto3_config)

    account_policy_present = False
    account_policy_note: Optional[str] = None
    try:
        account_resp = logs.describe_account_policies(
            policyType="DATA_PROTECTION_POLICY"
        )
        account_policies = account_resp.get("accountPolicies", []) or []
        account_policy_present = len(account_policies) > 0
        if account_policy_present:
            names = sorted(p.get("policyName", "unnamed") for p in account_policies)
            account_policy_note = (
                f"account-level DATA_PROTECTION_POLICY present: {', '.join(names)}"
            )
    except ClientError as err:
        if _region_unavailable_error(err) or _access_denied_error(err):
            findings.append(
                _make_na_finding(
                    check_id,
                    region,
                    (
                        "logs:DescribeAccountPolicies(DATA_PROTECTION_POLICY) "
                        f"unavailable: {_error_detail(err)}"
                    ),
                )
            )
        else:
            raise

    scoped: List[Dict[str, Any]] = []
    truncated_any_prefix = False
    for pfx in AIML_LOG_GROUP_PREFIXES:
        try:
            groups = _logs_list_log_groups_for_prefix(
                logs, pfx, cap=LOG_GROUP_CAP_PER_PREFIX
            )
        except ClientError as err:
            if _region_unavailable_error(err) or _access_denied_error(err):
                findings.append(
                    _make_na_finding(
                        check_id,
                        region,
                        (
                            f"describe_log_groups for prefix {pfx!r} unavailable: "
                            f"{_error_detail(err)}"
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
                    f"CloudWatch Logs endpoint unreachable scanning prefix {pfx!r}.",
                )
            )
            continue
        if len(groups) >= LOG_GROUP_CAP_PER_PREFIX:
            truncated_any_prefix = True
        scoped.extend(groups)

    if truncated_any_prefix:
        findings.append(
            _make_na_finding(
                check_id,
                region,
                (
                    "CloudWatch Logs AIML-prefix inventory was truncated at "
                    f"{LOG_GROUP_CAP_PER_PREFIX} groups per prefix in region "
                    f"{region}.  Non-protected groups beyond the cap are not "
                    "reflected in the Passed/Failed rows below."
                ),
            )
        )

    if not scoped:
        findings.append(
            _make_na_finding(
                check_id,
                region,
                (
                    f"No AIML-prefixed CloudWatch Logs log groups (prefixes: "
                    f"{', '.join(sorted(AIML_LOG_GROUP_PREFIXES))}) found in "
                    f"region {region}.  No 164.312(b) audit-control ePHI "
                    "log-protection evidence to inspect."
                ),
            )
        )
        return findings

    total = 0
    protected = 0
    not_protected: List[str] = []
    for lg in scoped:
        lg_name = lg.get("logGroupName") or "unknown"
        total += 1
        per_group_activated = False
        per_group_empty_body = False
        per_group_err_skip = False
        try:
            dp_resp = logs.get_data_protection_policy(logGroupIdentifier=lg_name)
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code", "")
            if (
                code == "ResourceNotFoundException"
                or "ResourceNotFoundException" in code
            ):
                per_group_activated = False
            elif _region_unavailable_error(err) or _access_denied_error(err):
                findings.append(
                    _make_na_finding(
                        check_id,
                        region,
                        (
                            f"Cannot get_data_protection_policy for group "
                            f"{lg_name}: {_error_detail(err)}"
                        ),
                    )
                )
                per_group_err_skip = True
            else:
                raise
        else:
            body = (
                dp_resp.get("policyDocument")
                or dp_resp.get("dataProtectionPolicy")
                or {}
            )
            if isinstance(body, dict) and not body:
                per_group_empty_body = True
                per_group_activated = False
            elif isinstance(body, str) and body.strip() in {"", "{}"}:
                per_group_empty_body = True
                per_group_activated = False
            else:
                status = dp_resp.get("dataProtectionStatus", "")
                if status == "ACTIVATED":
                    per_group_activated = True
                elif isinstance(body, (dict, str)) and body:
                    per_group_activated = True

        group_protected = per_group_activated or (
            account_policy_present and not per_group_err_skip
        )
        if per_group_err_skip:
            continue
        if group_protected:
            protected += 1
        else:
            reason_parts = []
            if per_group_empty_body:
                reason_parts.append("get_data_protection_policy returned empty body")
            elif not per_group_activated:
                reason_parts.append("no per-group ACTIVATED data-protection policy")
            if not account_policy_present:
                reason_parts.append("no account-level DATA_PROTECTION_POLICY")
            not_protected.append(f"{lg_name} ({'; '.join(reason_parts)})")

    if not_protected:
        evidence_line = account_policy_note or (
            "no account-level DATA_PROTECTION_POLICY observed via logs:DescribeAccountPolicies"
        )
        findings.append(
            create_finding(
                check_id=check_id,
                finding_name="AI/ML Log Groups Not Protected by CloudWatch Data-Protection Policy",
                finding_details=(
                    "In region "
                    + region
                    + ", the following AIML-prefixed CloudWatch Logs log "
                    "groups are not protected by an activated data-protection "
                    "policy (neither per-group get_data_protection_policy with "
                    "dataProtectionStatus==ACTIVATED, nor an account-level "
                    "logs:DescribeAccountPolicies DATA_PROTECTION_POLICY): "
                    + "; ".join(sorted(not_protected))
                    + ".  ("
                    + evidence_line
                    + ").  164.312(b) audit-control and "
                    "164.308(a)(1)(ii)(D) activity-review safeguards require "
                    "logged ePHI to be identified and handled before long-term "
                    "storage."
                ),
                resolution=(
                    "Apply PutDataProtectionPolicy on each scoped log group "
                    "(or account-wide via PutAccountPolicy) declaring at "
                    "least managed identifiers Name, USSocialSecurityNumber, "
                    "USDriverLicenseNumber, Birthdate, USBankAccountNumber, "
                    "Email, Phone plus any custom identifiers unique to your "
                    "ePHI inventory.  Set dataProtectionStatus=ACTIVATED; "
                    "DEACTIVATE masking is only appropriate for downstream "
                    "SIEM pipelines that themselves enforce 164.312(b)."
                ),
                reference=HIPAA_CHECK_REFERENCES[check_id],
                severity=SeverityEnum.MEDIUM,
                status=StatusEnum.FAILED,
                region=region,
                compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
            )
        )

    if total > 0 and protected == total:
        inventory_phrase = "All"
        if truncated_any_prefix:
            inventory_phrase = f"All {total} inspected"
        qual = (
            f" ({account_policy_note})"
            if account_policy_note
            else " (per-group policy on each group)"
        )
        findings.append(
            create_finding(
                check_id=check_id,
                finding_name="AI/ML Log Groups Have CloudWatch Data-Protection Coverage",
                finding_details=(
                    f"{inventory_phrase} AIML-prefixed CloudWatch log groups in "
                    f"region {region} report data-protection policy coverage{qual}.  "
                    "This is the automated evidence we correlate with the "
                    "164.312(b) audit-control and 164.308(a)(1)(ii)(D) "
                    "activity-review safeguards."
                ),
                resolution="No action required.",
                reference=HIPAA_CHECK_REFERENCES[check_id],
                severity=SeverityEnum.INFORMATIONAL,
                status=StatusEnum.PASSED,
                region=region,
                compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
            )
        )
    return findings


def _bedrock_list_all_guardrails(
    bedrock_client,
) -> List[Dict[str, Any]]:
    """Paginate bedrock.ListGuardrails so a non-compliant guardrail on page 2
    is never silently skipped."""
    result: List[Dict[str, Any]] = []
    try:
        paginator = bedrock_client.get_paginator("list_guardrails")
        for page in paginator.paginate(PaginationConfig={"PageSize": 100}):
            result.extend(page.get("guardrails", []))
    except ClientError as err:
        code = err.response.get("Error", {}).get("Code", "")
        if code == "InvalidParameterException" or code.endswith("ValidationException"):
            guardrails = bedrock_client.list_guardrails()
            result = guardrails.get("guardrails", [])
        else:
            raise
    return result


def check_bedrock_guardrail_pii(region: str) -> List[Dict[str, Any]]:
    """HP-02 — Bedrock guardrails configure PHI-entity redaction via BLOCK or
    ANONYMIZE actions on recognized PII entity types.

    Scans `list_guardrails` with pagination. For each guardrail, calls
    `get_guardrail` and verifies that the guardrail's sensitiveInformationPolicy
    declares at least one PII entity whose action is BLOCK or ANONYMIZE. A
    Passed row is emitted when at least one guardrail exists and every
    guardrail has at least one qualifying entity; otherwise a single Failed
    row enumerates the non-compliant guardrail names. An empty inventory
    (zero guardrails in the region) produces an Informational N/A row so
    report reviewers see explicit evidence that the check ran and found
    nothing to inspect.
    """
    check_id = "HP-02"
    findings: List[Dict[str, Any]] = []
    try:
        bedrock = boto3.client("bedrock", region_name=region, config=boto3_config)
        try:
            guardrails = _bedrock_list_all_guardrails(bedrock)
        except ClientError as err:
            if _region_unavailable_error(err) or _access_denied_error(err):
                return [
                    _make_na_finding(
                        check_id,
                        region,
                        (
                            "Bedrock list_guardrails unavailable: "
                            f"{err.response.get('Error', {}).get('Code')}"
                        ),
                    )
                ]
            raise
        if not guardrails:
            return [
                _make_na_finding(
                    check_id,
                    region,
                    (
                        "No Bedrock guardrails found in region "
                        + region
                        + ". Without guardrails the scanner cannot produce automated "
                        "evidence of PII redaction for 164.312(a)(2)(iv) and "
                        "164.312(a)(1) controls."
                    ),
                )
            ]

        total = 0
        compliant = 0
        non_compliant_names: List[str] = []
        truncated = False
        for g in guardrails:
            if total >= 500:
                truncated = True
                break
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
                if action in GUARDRAIL_PII_PROTECTED_ACTIONS and (
                    pii_type in PHI_ENTITY_TYPES or not PHI_ENTITY_TYPES
                ):
                    qualifying = True
                    break
            if qualifying:
                compliant += 1
            else:
                non_compliant_names.append(name)

        if truncated:
            findings.append(
                _make_na_finding(
                    check_id,
                    region,
                    (
                        "Guardrail inventory was truncated at the 500-item safety cap. "
                        f"Only the first {total} guardrails in region {region} were "
                        "evaluated. Any non-compliant guardrails beyond the cap are "
                        "not reflected in the Passed/Failed rows below."
                    ),
                )
            )

        if non_compliant_names:
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name="Bedrock Guardrails Lack PHI-Entity Redaction Actions",
                    finding_details=(
                        "These Bedrock guardrails in region "
                        + region
                        + " do not declare at least one PII entity with BLOCK or "
                        "ANONYMIZE action: "
                        + ", ".join(sorted(non_compliant_names))
                        + ". Guardrails are the automated evidence we correlate with "
                        "the 164.312(a)(1) access-control and 164.312(a)(2)(iv) "
                        "encryption-of-stored-data goals when the model output might "
                        "echo ePHI from the context."
                    ),
                    resolution=(
                        "For each affected guardrail, add at least the following PII "
                        "entities with BLOCK or ANONYMIZE action: NAME, "
                        "US_SOCIAL_SECURITY_NUMBER, EMAIL, PHONE, ADDRESS, "
                        "DATE_OF_BIRTH. Use custom regex patterns for MRNs, account "
                        "numbers, or any protected identifiers specific to your "
                        "organization."
                    ),
                    reference=HIPAA_CHECK_REFERENCES[check_id],
                    severity=SeverityEnum.MEDIUM,
                    status=StatusEnum.FAILED,
                    region=region,
                    compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                )
            )

        if total > 0 and compliant == total and not non_compliant_names:
            inventory_phrase = "All"
            if truncated:
                inventory_phrase = f"All {total} inspected"
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name="Bedrock Guardrails Have Configured PHI-Entity Redaction",
                    finding_details=(
                        f"{inventory_phrase} Bedrock guardrails in region {region} "
                        "include at least one PII entity with BLOCK or ANONYMIZE "
                        "action."
                    ),
                    resolution="No action required.",
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
                        "Bedrock API unavailable or access denied: "
                        f"{err.response.get('Error', {}).get('Code')}"
                    ),
                )
            ]
        raise


def check_s3_bucket_encryption_and_versioning(
    region: str, *, region_index: int = 0, account_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """HP-07 — AI/ML-shaped S3 buckets use CMK encryption, object versioning,
    and account+bucket-level PublicAccessBlock all true.

    Run-once gating: this check emits findings ONLY when region_index == 0
    (first region the Step Functions map visits).  When called from a later
    region (region_index > 0), it returns an empty list so no duplicate
    per-region findings appear.  Account-wide findings carry Region="Global"
    rather than the calling Lambda's AWS_REGION.

    Candidate buckets (scope-tight to avoid auditing unrelated storage):
    buckets whose name contains one of DATASET_NAME_HINTS substrings
    (bedrock, sagemaker, aiml, ml-, -model, -dataset, -training, -data,
    models, datasets, fine-tune, finetune, training-data, -genai-, genai-,
    rag-data).  Each candidate must satisfy:
      (1) Default SSE is `aws:kms` with KeyManager=="CUSTOMER"
          (validated via kms:DescribeKey).  AES256 SSE-S3 (no KMS) or a
          service-managed AWS KMS key do NOT pass.
      (2) Bucket Versioning Status == "Enabled" (Suspended or unset = Fail).
      (3) Per-bucket s3:GetPublicAccessBlock returns four booleans True
          (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy,
          RestrictPublicBuckets).  An account-level
          s3:GetAccountPublicAccessBlock with all four True exempts any
          per-bucket PAB gap because account-level PAB enforces the same
          restriction across all buckets in the partition.

    Per-bucket exception isolation:
      * NoSuchBucket → silently skip (delete race vs list_buckets).
      * Throttling (SlowDown/ServiceUnavailable) or per-bucket access-denied
        → append a per-bucket HP-07 N/A finding, preserve all other bucket
        findings, NEVER replace the entire findings list with a single
        fallback row.
    """
    check_id = "HP-07"
    GLOBAL_REGION = "Global"
    DATASET_NAME_HINTS: Tuple[str, ...] = (
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
    BUCKET_CAP = 200

    if region_index != 0:
        return []

    findings: List[Dict[str, Any]] = []
    try:
        s3 = boto3.client("s3", config=boto3_config)
        s3control = boto3.client("s3control", config=boto3_config)
        kms = boto3.client("kms", region_name=region, config=boto3_config)

        account_pab_all_true = False
        resolved_account_id = account_id or ""
        try:
            if not resolved_account_id:
                caller = boto3.client("sts", config=boto3_config).get_caller_identity()
                resolved_account_id = caller.get("Account") or ""
            if resolved_account_id:
                pab_resp = s3control.get_public_access_block(
                    AccountId=resolved_account_id
                )
                pab_cfg = pab_resp.get("PublicAccessBlockConfiguration", {}) or {}
                account_pab_all_true = all(
                    pab_cfg.get(k) is True
                    for k in (
                        "BlockPublicAcls",
                        "IgnorePublicAcls",
                        "BlockPublicPolicy",
                        "RestrictPublicBuckets",
                    )
                )
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code", "")
            if (
                "NoSuchPublicAccessBlockConfiguration" in code
                or "NotFound" in code
                or code == "NoSuchPublicAccessBlockConfiguration"
            ):
                account_pab_all_true = False
            elif _region_unavailable_error(err) or _access_denied_error(err):
                findings.append(
                    _make_na_finding(
                        check_id,
                        GLOBAL_REGION,
                        (
                            "s3:GetAccountPublicAccessBlock (via s3control) "
                            f"unavailable: {_error_detail(err)}"
                        ),
                    )
                )
            else:
                raise

        buckets = _s3_list_all_buckets(s3)
        scoped_names: List[str] = []
        for b in buckets:
            name = (b.get("Name") or "").lower()
            if not name:
                continue
            if any(hint in name for hint in DATASET_NAME_HINTS):
                scoped_names.append(b["Name"])

        bucket_truncated = len(scoped_names) > BUCKET_CAP
        if bucket_truncated:
            scoped_names = scoped_names[:BUCKET_CAP]
            findings.append(
                _make_na_finding(
                    check_id,
                    GLOBAL_REGION,
                    (
                        f"S3 candidate-bucket inventory was truncated at "
                        f"{BUCKET_CAP} buckets.  Non-compliant buckets beyond "
                        "the cap are not reflected in the Passed/Failed rows below."
                    ),
                )
            )

        if not scoped_names:
            findings.append(
                _make_na_finding(
                    check_id,
                    GLOBAL_REGION,
                    (
                        "No candidate AI/ML dataset S3 buckets found in "
                        "account (name-matching one of: "
                        + ", ".join(sorted(DATASET_NAME_HINTS))
                        + ").  No 164.312(a)(2)(iv) at-rest S3 encryption "
                        "evidence to inspect."
                    ),
                )
            )
            return findings

        total = 0
        compliant = 0
        non_compliant_rows: List[Tuple[str, List[str]]] = []
        for bname in scoped_names:
            total += 1
            reasons: List[str] = []
            try:
                enc_ok = False
                try:
                    enc = s3.get_bucket_encryption(Bucket=bname)
                    rules = (
                        enc.get("ServerSideEncryptionConfiguration", {}).get(
                            "Rules", []
                        )
                        or []
                    )
                    for r in rules:
                        sse = r.get("ApplyServerSideEncryptionByDefault", {}) or {}
                        algo = str(sse.get("SSEAlgorithm", "")).upper()
                        if algo == "AES256":
                            enc_ok = False
                            reasons.append("SSE=AES256 (SSE-S3, no KMS) — CMK required")
                            break
                        if algo in {"AWS:KMS", "aws:kms"}:
                            kms_key_id = sse.get("KMSMasterKeyID", "") or sse.get(
                                "KMSKeyId", ""
                            )
                            if not kms_key_id:
                                enc_ok = False
                                reasons.append("aws:kms declared but no KMS key ARN")
                                break
                            is_cmk, note = _kms_is_customer_managed_key(kms, kms_key_id)
                            if is_cmk:
                                enc_ok = True
                                break
                            else:
                                enc_ok = False
                                reasons.append(
                                    "KMS key not customer-managed: "
                                    + (note or "KeyManager != CUSTOMER")
                                )
                                break
                except ClientError as err:
                    code = err.response.get("Error", {}).get("Code", "")
                    if (
                        "ServerSideEncryptionConfigurationNotFound" in code
                        or code == "ServerSideEncryptionConfigurationNotFoundError"
                    ):
                        enc_ok = False
                        reasons.append("no default server-side encryption configured")
                    elif _region_unavailable_error(err) or _access_denied_error(err):
                        findings.append(
                            _make_na_finding(
                                check_id,
                                GLOBAL_REGION,
                                (
                                    f"Cannot read S3 encryption config for "
                                    f"bucket {bname}: {_error_detail(err)}"
                                ),
                            )
                        )
                        total -= 1
                        continue
                    elif code in {
                        "SlowDown",
                        "ServiceUnavailable",
                        "ServiceUnavailableException",
                    }:
                        findings.append(
                            _make_na_finding(
                                check_id,
                                GLOBAL_REGION,
                                (
                                    f"Throttled reading encryption for bucket "
                                    f"{bname}: {_error_detail(err)}"
                                ),
                            )
                        )
                        total -= 1
                        continue
                    elif code == "NoSuchBucket":
                        total -= 1
                        continue
                    else:
                        raise
                else:
                    if not enc_ok and not any(
                        "encryption" in r.lower()
                        or "cmk" in r.lower()
                        or "kms" in r.lower()
                        for r in reasons
                    ):
                        reasons.append(
                            "no compliant default SSE rule (aws:kms + customer-managed CMK)"
                        )

                ver_ok = False
                try:
                    ver = s3.get_bucket_versioning(Bucket=bname)
                    ver_ok = ver.get("Status") == "Enabled"
                except ClientError as err:
                    code = err.response.get("Error", {}).get("Code", "")
                    if _region_unavailable_error(err) or _access_denied_error(err):
                        findings.append(
                            _make_na_finding(
                                check_id,
                                GLOBAL_REGION,
                                (
                                    f"Cannot read S3 versioning config for "
                                    f"bucket {bname}: {_error_detail(err)}"
                                ),
                            )
                        )
                        total -= 1
                        continue
                    elif code in {
                        "SlowDown",
                        "ServiceUnavailable",
                        "ServiceUnavailableException",
                    }:
                        findings.append(
                            _make_na_finding(
                                check_id,
                                GLOBAL_REGION,
                                (
                                    f"Throttled reading versioning for bucket "
                                    f"{bname}: {_error_detail(err)}"
                                ),
                            )
                        )
                        total -= 1
                        continue
                    elif code == "NoSuchBucket":
                        total -= 1
                        continue
                    else:
                        raise
                else:
                    if not ver_ok:
                        reasons.append(
                            "bucket versioning not Enabled (Suspended or unset)"
                        )

                pab_ok = False
                if account_pab_all_true:
                    pab_ok = True
                else:
                    try:
                        pab_b = s3.get_public_access_block(Bucket=bname)
                        pab_cfg_b = (
                            pab_b.get("PublicAccessBlockConfiguration", {}) or {}
                        )
                        pab_ok = all(
                            pab_cfg_b.get(k) is True
                            for k in (
                                "BlockPublicAcls",
                                "IgnorePublicAcls",
                                "BlockPublicPolicy",
                                "RestrictPublicBuckets",
                            )
                        )
                    except ClientError as err:
                        code = err.response.get("Error", {}).get("Code", "")
                        if (
                            "NoSuchPublicAccessBlockConfiguration" in code
                            or "NotFound" in code
                            or code == "NoSuchPublicAccessBlockConfiguration"
                        ):
                            pab_ok = False
                            reasons.append(
                                "no per-bucket PublicAccessBlock and no account-level PAB"
                            )
                        elif _region_unavailable_error(err) or _access_denied_error(
                            err
                        ):
                            findings.append(
                                _make_na_finding(
                                    check_id,
                                    GLOBAL_REGION,
                                    (
                                        f"Cannot read S3 bucket PublicAccessBlock "
                                        f"for {bname}: {_error_detail(err)}"
                                    ),
                                )
                            )
                            total -= 1
                            continue
                        elif code in {
                            "SlowDown",
                            "ServiceUnavailable",
                            "ServiceUnavailableException",
                        }:
                            findings.append(
                                _make_na_finding(
                                    check_id,
                                    GLOBAL_REGION,
                                    (
                                        f"Throttled reading bucket PAB for "
                                        f"{bname}: {_error_detail(err)}"
                                    ),
                                )
                            )
                            total -= 1
                            continue
                        elif code == "NoSuchBucket":
                            total -= 1
                            continue
                        else:
                            raise
                    else:
                        if not pab_ok:
                            reasons.append(
                                "per-bucket PublicAccessBlock has at least one boolean not True"
                            )

                if enc_ok and ver_ok and pab_ok:
                    compliant += 1
                else:
                    non_compliant_rows.append((bname, reasons))

            except ClientError as err:
                code = err.response.get("Error", {}).get("Code", "")
                if code == "NoSuchBucket":
                    total -= 1
                    continue
                if _region_unavailable_error(err) or _access_denied_error(err):
                    findings.append(
                        _make_na_finding(
                            check_id,
                            GLOBAL_REGION,
                            (f"Cannot evaluate bucket {bname}: {_error_detail(err)}"),
                        )
                    )
                    total -= 1
                    continue
                if code in {
                    "SlowDown",
                    "ServiceUnavailable",
                    "ServiceUnavailableException",
                }:
                    findings.append(
                        _make_na_finding(
                            check_id,
                            GLOBAL_REGION,
                            (
                                f"Throttled evaluating bucket {bname}: "
                                f"{_error_detail(err)}"
                            ),
                        )
                    )
                    total -= 1
                    continue
                raise

        if non_compliant_rows:
            evidence_parts = []
            if account_pab_all_true:
                evidence_parts.append(
                    "account-level s3:GetAccountPublicAccessBlock all-boolean-true observed; per-bucket PAB pass is satisfied by account override"
                )
            else:
                evidence_parts.append(
                    "no account-level PublicAccessBlock override — per-bucket PAB evaluated independently"
                )
            evidence = "; ".join(evidence_parts)
            joined = "; ".join(
                f"{bname} [{', '.join(rs)}]" for bname, rs in non_compliant_rows
            )
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name="AI/ML Dataset S3 Buckets Not CMK-Encrypted, Versioned, or Public-Access-Blocked",
                    finding_details=(
                        "Account-wide (Region=Global) evaluation: the following "
                        "candidate AI/ML dataset S3 buckets do not meet every "
                        "HP-07 requirement (CMK-bound aws:kms default SSE, "
                        "Versioning=Enabled, PublicAccessBlock all-True or "
                        "equivalent account-level override): "
                        + joined
                        + ".  ("
                        + evidence
                        + ").  164.312(a)(2)(iv) at-rest ePHI encryption, "
                        "164.308(a)(7)(i) contingency/versioning recoverability, "
                        "and 164.312(a)(1)/(e)(1) public-access gating evidence "
                        "are not satisfied by the affected buckets."
                    ),
                    resolution=(
                        "For each affected bucket apply: PutBucketEncryption "
                        "with SSEAlgorithm=aws:kms and a customer-managed KMS key "
                        "(KeyManager==CUSTOMER, rotation enabled); "
                        "PutBucketVersioning with Status=Enabled; "
                        "PutPublicAccessBlock with all four booleans True "
                        "(or apply account-level PAB via PutAccountPublicAccessBlock).  "
                        "Add an S3 bucket policy condition requiring "
                        "aws:SecureTransport=true to deny cleartext ePHI uploads."
                    ),
                    reference=HIPAA_CHECK_REFERENCES[check_id],
                    severity=SeverityEnum.HIGH,
                    status=StatusEnum.FAILED,
                    region=GLOBAL_REGION,
                    compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                )
            )

        if total > 0 and compliant == total:
            inventory_phrase = "All"
            if bucket_truncated:
                inventory_phrase = f"All {total} inspected"
            qual = (
                "account-level PAB override in effect"
                if account_pab_all_true
                else "each bucket's own PAB all-True"
            )
            findings.append(
                create_finding(
                    check_id=check_id,
                    finding_name="AI/ML Dataset S3 Buckets Are CMK-Encrypted, Versioned, and Public-Access-Blocked",
                    finding_details=(
                        f"{inventory_phrase} candidate AI/ML dataset S3 buckets "
                        f"(account-wide, Region=Global) satisfy HP-07: every "
                        "bucket has aws:kms default SSE with a customer-managed "
                        "CMK (validated via kms:DescribeKey), Versioning=Enabled, "
                        "and PublicAccessBlock all-True evidence (" + qual + ")."
                    ),
                    resolution="No action required.",
                    reference=HIPAA_CHECK_REFERENCES[check_id],
                    severity=SeverityEnum.INFORMATIONAL,
                    status=StatusEnum.PASSED,
                    region=GLOBAL_REGION,
                    compliance_frameworks=HIPAA_COMPLIANCE_MAP[check_id],
                )
            )
        return findings

    except ClientError as err:
        if _region_unavailable_error(err) or _access_denied_error(err):
            return [
                _make_na_finding(
                    check_id,
                    GLOBAL_REGION,
                    f"S3/S3Control/KMS API unavailable or access denied: {_error_detail(err)}",
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
HIPAA_CHECKS: tuple[tuple[str, Any], ...] = (
    ("HP-01", check_bedrock_custom_model_encryption),
    ("HP-03", check_sagemaker_network_isolation),
    ("HP-04", check_sagemaker_resource_encryption),
    ("HP-05", check_cloudwatch_logs_data_protection),
    ("HP-06", check_vpc_endpoints_configured),
    ("HP-02", check_bedrock_guardrail_pii),
    ("HP-07", check_s3_bucket_encryption_and_versioning),
)


def run_all_checks(
    region: str, region_index: int = 0, *, account_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Invoke every HP-## check via _run_check_safely and return the
    flattened finding list.

    Each check is isolated: an unexpected exception for one HP-ID yields an
    Informational N/A incomplete row; the remaining six checks still run and
    the HIPAA CSV is still written with all seven IDs present.
    """
    findings: List[Dict[str, Any]] = []
    for check_id, fn in HIPAA_CHECKS:
        if check_id == "HP-07":
            try:
                findings.extend(
                    list(fn(region, region_index=region_index, account_id=account_id))
                )
            except ClientError as err:
                raise RuntimeError(
                    f"unexpected outer ClientError for HP-07 region "
                    f"{region}: {_error_detail(err)}"
                ) from err
        else:
            findings.extend(_run_check_safely(fn, check_id, region))
    return findings


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Main entry point for the HIPAA assessment Lambda.

    Expects the Step Functions payload used by the OWASP Lambda:
      { Execution: {Name: ...}, StateMachine: ..., Region: ..., RegionIndex: 0 }

    HP-07 runs once on RegionIndex == 0 with Region=Global to avoid duplicate
    per-region findings.  Every other check is region-scoped and runs in each
    region.
    """
    logger.info("Starting HIPAA/HITECH-aligned automated configuration checks")
    try:
        region = event.get("Region", os.environ.get("AWS_REGION", "us-east-1"))
        region_index = int(event.get("RegionIndex", 0))
        execution_id = event["Execution"]["Name"]
        bucket_name = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
        if not bucket_name:
            raise ValueError(
                "AIML_ASSESSMENT_BUCKET_NAME environment variable is not set"
            )

        invoked_arn = getattr(context, "invoked_function_arn", "") or ""
        account_id: Optional[str] = None
        if invoked_arn and invoked_arn.count(":") >= 4:
            account_id = invoked_arn.split(":")[4]

        logger.info(
            f"HIPAA assessment region={region} region_index={region_index} "
            f"execution={execution_id}"
        )

        findings = run_all_checks(
            region, region_index=region_index, account_id=account_id
        )
        logger.info(f"HIPAA checks produced {len(findings)} rows for region={region}")

        csv_content = generate_csv_report(findings)
        s3_url = write_to_s3(execution_id, csv_content, bucket_name, region)

        return {
            "status": "success",
            "assessment": "hipaa",
            "region": region,
            "region_index": region_index,
            "finding_count": len(findings),
            "report_s3_url": s3_url,
        }
    except ClientError:
        raise
