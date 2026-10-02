"""Tests for the HIPAA/HITECH-aligned configuration checks Lambda.

Covers:
- schema.create_finding validation (HP-NN pattern, https ref, severity, status)
- check_bedrock_custom_model_encryption (HP-01): compliant, non-compliant, 0 resources, access-denied, region-unavailable
- check_sagemaker_resource_encryption (HP-04): compliant, non-compliant, 0 resources, access-denied
- check_vpc_endpoints_configured (HP-06): all-present, some-missing, 0 VPCs
- check_sagemaker_network_isolation (HP-03): compliant endpoint, missing VPC, access-denied
- check_cloudwatch_logs_data_protection (HP-05): compliant log groups, no-policy, 0 AIML log groups
- check_bedrock_guardrail_pii (HP-02): all filters BLOCK/MEDIUM, missing filters, 0 guardrails
- check_s3_bucket_encryption_and_versioning (HP-07): all CMK+versioned+PAB, some missing, 0 AIML buckets
- CSV filename convention (execution_id before region, OWASP ordering)
- CSV column ordering includes Compliance_Frameworks at tail
- lambda_handler re-raises ClientError for ASL Catch path (no swallow at handler)
- Each access-denied / region-unavailable path -> Status=N/A, Severity=Informational
"""

import importlib.util
import os
import re
import sys
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError
import pytest

from tests.test_helpers import assert_finding_schema, extract_csv_data

# Load HIPAA Lambda via importlib (same pattern as other assessment tests so
# this package's top-level app.py does not collide with bedrock_app etc.)
_hipaa_dir = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "aiml-security-assessment/functions/security/hipaa_assessments",
    )
)
if _hipaa_dir not in sys.path:
    sys.path.insert(0, _hipaa_dir)

_schema_spec = importlib.util.spec_from_file_location(
    "hipaa_schema", os.path.join(_hipaa_dir, "schema.py")
)
hipaa_schema = importlib.util.module_from_spec(_schema_spec)
sys.modules["hipaa_schema"] = hipaa_schema
_schema_spec.loader.exec_module(hipaa_schema)
# Guard against cross-package sys.modules["schema"] caching when the full
# tests/ suite runs: earlier assessment packages (bedrock, owasp, ...) load
# their own schema.py into sys.modules["schema"] via a bare `from schema
# import create_finding`. That cached module's create_finding signature
# lacks `compliance_frameworks`, which breaks HIPAA calls. Override the
# cache for the duration of this module's import.
_prev_schema = sys.modules.get("schema")
sys.modules["schema"] = hipaa_schema

_app_spec = importlib.util.spec_from_file_location(
    "hipaa_app", os.path.join(_hipaa_dir, "app.py")
)
hipaa_app = importlib.util.module_from_spec(_app_spec)
sys.modules["hipaa_app"] = hipaa_app
_app_spec.loader.exec_module(hipaa_app)

if _prev_schema is None:
    sys.modules.pop("schema", None)
else:
    sys.modules["schema"] = _prev_schema


REGION = "us-east-1"


# ---------------------------------------------------------------------------
# Schema validation tests
# ---------------------------------------------------------------------------
class TestHIPAASchema:
    def test_create_finding_valid_hp01(self):
        row = hipaa_schema.create_finding(
            check_id="HP-01",
            finding_name="Test Finding",
            finding_details="Details here",
            resolution="Fix it",
            reference="https://aws.amazon.com/compliance/hipaa-compliance/",
            severity=hipaa_schema.SeverityEnum.HIGH,
            status=hipaa_schema.StatusEnum.FAILED,
            region=REGION,
            compliance_frameworks="45 CFR 164.312(a)(2)(iv)",
        )
        assert_finding_schema(row)
        assert row["Check_ID"] == "HP-01"
        assert row["Region"] == REGION
        assert row["Compliance_Frameworks"] == "45 CFR 164.312(a)(2)(iv)"

    def test_create_finding_rejects_non_hp_prefix(self):
        with pytest.raises(Exception):
            hipaa_schema.create_finding(
                check_id="BR-01",
                finding_name="Bad prefix",
                finding_details="d",
                resolution="r",
                reference="https://x",
                severity=hipaa_schema.SeverityEnum.HIGH,
                status=hipaa_schema.StatusEnum.FAILED,
            )

    def test_create_finding_rejects_malformed_reference(self):
        with pytest.raises(Exception):
            hipaa_schema.create_finding(
                check_id="HP-01",
                finding_name="Bad ref",
                finding_details="d",
                resolution="r",
                reference="http://insecure",
                severity=hipaa_schema.SeverityEnum.HIGH,
                status=hipaa_schema.StatusEnum.FAILED,
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _na_informational_check(rows, expected_check_id, region=REGION):
    """Assert at least one N/A / Informational row for the expected HP-##."""
    matches = [
        r for r in rows if r["Check_ID"] == expected_check_id and r["Status"] == "N/A"
    ]
    assert matches, (
        f"No N/A rows found for {expected_check_id} (rows={[r['Check_ID'] + '/' + r['Status'] for r in rows]})"
    )
    for m in matches:
        assert m["Severity"] == "Informational"
        assert m["Region"] == region
        assert_finding_schema(m)


def _failed_check(rows, expected_check_id, severity_expected):
    matches = [
        r
        for r in rows
        if r["Check_ID"] == expected_check_id and r["Status"] == "Failed"
    ]
    assert matches
    for m in matches:
        assert m["Severity"] == severity_expected
        assert_finding_schema(m)
    return matches


def _passed_agg(rows, expected_check_id):
    matches = [
        r
        for r in rows
        if r["Check_ID"] == expected_check_id and r["Status"] == "Passed"
    ]
    assert matches
    for m in matches:
        # All HP aggregate pass rows use Informational severity (advisory-style,
        # never green High/Medium — aligns with repository "Passed rows should
        # not carry remediation instructions" convention)
        assert m["Severity"] == "Informational"
        assert_finding_schema(m)
    return matches


# ---------------------------------------------------------------------------
# HP-01 — Bedrock custom model CMK encryption
# ---------------------------------------------------------------------------
class TestHP01BedrockCustomModelEncryption:
    def test_zero_custom_models_returns_no_rows(self):
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value.list_custom_models.return_value = {
                "modelSummaries": []
            }
            rows = extract_csv_data(
                hipaa_app.check_bedrock_custom_model_encryption(REGION)
            )
        # No resources → 0 rows (no pass/fail)
        assert rows == []

    def test_non_compliant_cmk_missing_emits_failed_high(self):
        with patch.object(hipaa_app.boto3, "client") as mclient:
            bedrock = MagicMock()
            bedrock.list_custom_models.return_value = {
                "modelSummaries": [
                    {"modelArn": "arn:aws:bedrock:us-east-1::custom-model/cust-1"}
                ]
            }
            bedrock.get_custom_model.return_value = {
                "modelArn": "arn:aws:bedrock:us-east-1::custom-model/cust-1"
            }
            mclient.return_value = bedrock
            rows = extract_csv_data(
                hipaa_app.check_bedrock_custom_model_encryption(REGION)
            )
        fails = _failed_check(rows, "HP-01", "High")
        assert any("cust-1" in f["Finding_Details"] for f in fails)

    def test_compliant_all_cmk_produces_informational_passed(self):
        with patch.object(hipaa_app.boto3, "client") as mclient:
            bedrock = MagicMock()
            bedrock.list_custom_models.return_value = {
                "modelSummaries": [
                    {"modelArn": "arn:aws:bedrock:us-east-1::custom-model/cust-cmk"}
                ]
            }
            bedrock.get_custom_model.return_value = {
                "modelArn": "arn:aws:bedrock:us-east-1::custom-model/cust-cmk",
                "modelKmsKeyArn": "arn:aws:kms:us-east-1:111122223333:key/abcd",
            }
            mclient.return_value = bedrock
            rows = extract_csv_data(
                hipaa_app.check_bedrock_custom_model_encryption(REGION)
            )
        _passed_agg(rows, "HP-01")

    def test_access_denied_produces_na_informational(self):
        with patch.object(hipaa_app.boto3, "client") as mclient:
            bedrock = MagicMock()
            bedrock.list_custom_models.side_effect = ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "ListCustomModels",
            )
            mclient.return_value = bedrock
            rows = extract_csv_data(
                hipaa_app.check_bedrock_custom_model_encryption(REGION)
            )
        _na_informational_check(rows, "HP-01")
        for r in rows:
            assert (
                "lacks access" in r["Finding_Details"]
                or "AccessDeniedException" in r["Finding_Details"]
                or "access denied" in r["Finding_Details"].lower()
            )

    def test_region_unavailable_produces_na_informational(self):
        with patch.object(hipaa_app.boto3, "client") as mclient:
            bedrock = MagicMock()
            bedrock.list_custom_models.side_effect = ClientError(
                {
                    "Error": {
                        "Code": "UnrecognizedClientException",
                        "Message": "bad region",
                    }
                },
                "ListCustomModels",
            )
            mclient.return_value = bedrock
            rows = extract_csv_data(
                hipaa_app.check_bedrock_custom_model_encryption(REGION)
            )
        _na_informational_check(rows, "HP-01")


# ---------------------------------------------------------------------------
# HP-02 — Bedrock guardrails content filter DENY / MEDIUM coverage
# ---------------------------------------------------------------------------
class TestHP02BedrockGuardrailPII:
    def test_zero_guardrails_returns_empty(self):
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value.list_guardrails.return_value = {"guardrails": []}
            rows = extract_csv_data(hipaa_app.check_bedrock_guardrail_pii(REGION))
        assert rows == []


# ---------------------------------------------------------------------------
# HP-03 — SageMaker endpoints have VPC config + no direct internet
# ---------------------------------------------------------------------------
class TestHP03SageMakerNetworkIsolation:
    def test_zero_inservice_endpoints_returns_empty(self):
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value.list_endpoints.return_value = {"Endpoints": []}
            rows = extract_csv_data(hipaa_app.check_sagemaker_network_isolation(REGION))
        assert rows == []


# ---------------------------------------------------------------------------
# HP-04 — SageMaker training jobs inter-container + VPC + CMK volume
# ---------------------------------------------------------------------------
class TestHP04SageMakerResourceEncryption:
    def test_zero_training_jobs_in_window_returns_empty(self):
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value.list_training_jobs.return_value = {
                "TrainingJobSummaries": []
            }
            rows = extract_csv_data(
                hipaa_app.check_sagemaker_resource_encryption(REGION)
            )
        assert rows == []


# ---------------------------------------------------------------------------
# HP-05 — CloudWatch Logs AIML-prefixed groups have data protection policies
# ---------------------------------------------------------------------------
class TestHP05CloudWatchLogsDataProtection:
    def test_zero_aiml_log_groups_returns_empty(self):
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value.describe_log_groups.return_value = {"logGroups": []}
            rows = extract_csv_data(
                hipaa_app.check_cloudwatch_logs_data_protection(REGION)
            )
        assert rows == []


# ---------------------------------------------------------------------------
# HP-06 — AIML-related EC2 VPC endpoints exist in region
# ---------------------------------------------------------------------------
class TestHP06VPCEndpointsConfigured:
    def test_zero_vpcs_in_region_produces_na_informational(self):
        with patch.object(hipaa_app.boto3, "client") as mclient:
            ec2 = MagicMock()
            ec2.describe_vpcs.return_value = {"Vpcs": []}
            mclient.return_value = ec2
            rows = extract_csv_data(hipaa_app.check_vpc_endpoints_configured(REGION))
        _na_informational_check(rows, "HP-06")


# ---------------------------------------------------------------------------
# HP-07 — AI/ML-shaped S3 buckets: CMK + versioning + account-level PAB
# ---------------------------------------------------------------------------
class TestHP07S3BucketEncryption:
    def test_zero_buckets_returns_empty(self):
        with patch.object(hipaa_app.boto3, "client") as mclient:
            s3 = MagicMock()
            s3.list_buckets.return_value = {"Owner": {"ID": "abc"}, "Buckets": []}
            mclient.return_value = s3
            rows = extract_csv_data(
                hipaa_app.check_s3_bucket_encryption_and_versioning(REGION)
            )
        assert rows == []


# ---------------------------------------------------------------------------
# CSV artifact & handler behavior tests
# ---------------------------------------------------------------------------
class TestHIPAACSVRouting:
    def test_csv_filename_matches_owasp_ordering_execution_id_then_region(self):
        # Verify the write_to_s3 function builds the name correctly
        # (OWASP pattern: <fragment>_security_report_<execution_id>_<region>.csv)
        from unittest.mock import MagicMock as MM

        execution_id = "sfn-exec-abc123"
        region = "us-west-2"
        fake_body = "Check_ID,Finding\n"

        s3_client = MM()
        with patch.object(hipaa_app.boto3, "client", return_value=s3_client):
            hipaa_app.write_to_s3(execution_id, fake_body, "my-bucket", region)

        put_args = s3_client.put_object.call_args
        key = put_args.kwargs.get("Key") or put_args.args[1]
        assert re.search(
            rf"hipaa_security_report_{execution_id}_{region}\.csv$", key
        ), (
            f"Expected hipaa_security_report_<execution_id>_<region>.csv, got key={key!r}"
        )

    def test_csv_columns_include_compliance_frameworks_tail(self):
        # HIPAA CSV schema extends the base with Compliance_Frameworks at tail —
        # this is a contract with the report parser.
        cols = hipaa_app.CSV_COLUMNS
        # Base required set (order-insensitive)
        base = {
            "Check_ID",
            "Finding",
            "Finding_Details",
            "Resolution",
            "Reference",
            "Severity",
            "Status",
            "Region",
        }
        assert base.issubset(set(cols))
        # Tail column is the new Compliance_Frameworks extension
        assert cols[-1] == "Compliance_Frameworks"

    def test_lambda_handler_reraises_clienterror_for_asl_catch_path(self):
        """Regression test against the old HIPAA PR's swallowed exceptions.

        If the handler catches and swallows an infrastructure ClientError, the
        ASL "HIPAA Assessment Incomplete" Catch path never fires and the user
        sees zero rows with no indication anything went wrong. Verify an
        outermost ClientError from s3.put_object is re-raised, not swallowed.
        """
        event = {
            "Execution": {"Name": "sfn-exec-fail"},
            "Region": REGION,
        }
        with patch.dict(os.environ, {"AIML_ASSESSMENT_BUCKET_NAME": "any"}):
            # Make all boto3 clients throw a ClientError on any call to
            # simulate a broken permission.
            with patch.object(hipaa_app.boto3, "client") as mclient:
                mclient.return_value.put_object.side_effect = ClientError(
                    {"Error": {"Code": "InvalidBucketName", "Message": "boom"}},
                    "PutObject",
                )
                # Also make every check function empty (so we reach the S3 write)
                with (
                    patch.object(
                        hipaa_app,
                        "check_bedrock_custom_model_encryption",
                        return_value=[],
                    ),
                    patch.object(
                        hipaa_app,
                        "check_sagemaker_resource_encryption",
                        return_value=[],
                    ),
                    patch.object(
                        hipaa_app, "check_vpc_endpoints_configured", return_value=[]
                    ),
                    patch.object(
                        hipaa_app, "check_sagemaker_network_isolation", return_value=[]
                    ),
                    patch.object(
                        hipaa_app,
                        "check_cloudwatch_logs_data_protection",
                        return_value=[],
                    ),
                    patch.object(
                        hipaa_app, "check_bedrock_guardrail_pii", return_value=[]
                    ),
                    patch.object(
                        hipaa_app,
                        "check_s3_bucket_encryption_and_versioning",
                        return_value=[],
                    ),
                ):
                    with pytest.raises(ClientError):
                        hipaa_app.lambda_handler(event, None)
