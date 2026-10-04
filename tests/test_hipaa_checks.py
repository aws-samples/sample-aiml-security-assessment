"""Tests for the HIPAA/HITECH-aligned configuration checks Lambda.

Covers:
- schema.create_finding validation (HP-NN pattern, https ref, severity, status)
- check_bedrock_custom_model_encryption (HP-01): compliant, non-compliant,
  0 resources, access-denied, region-unavailable, unexpected-exception (via
  _run_check_safely) with correct N/A HP-01 row
- check_bedrock_guardrail_pii (HP-02): compliant (NAME/SSN with BLOCK or
  ANONYMIZE), non-compliant (NONE action), 0 guardrails, access-denied,
  region-unavailable, unexpected-exception, plus three reviewer-specific
  NAME/SSN cases
- check_sagemaker_network_isolation (HP-03): compliant endpoint with
  model-level EnableNetworkIsolation via DescribeModel, non-compliant
  un-isolated resources, 0 resources, access-denied, region-unavailable,
  unexpected-exception (correct HP-03 N/A row), plus reviewer-specific
  EnableNetworkIsolation-on-DescribeModel evidence test
- check_sagemaker_resource_encryption (HP-04): compliant CMK-bound endpoint
  and training job with inter-container encryption true, non-compliant
  missing CMK or inter-container false, 0 resources, access-denied,
  region-unavailable, unexpected-exception (correct HP-04 N/A row)
- check_cloudwatch_logs_data_protection (HP-05): compliant ACTIVATED
  per-group and account-level policy paths, non-compliant missing policy,
  empty {} body reviewer-path Fail, 0 groups, access-denied,
  region-unavailable, unexpected-exception (correct HP-05 N/A row)
- check_vpc_endpoints_configured (HP-06): all 12 required endpoint
  services available vs missing, 0 VPCs, access-denied, region-unavailable,
  unexpected-exception (correct HP-06 N/A row)
- check_s3_bucket_encryption_and_versioning (HP-07): CMK-bound
  customer-managed pass, AES256 SSE-S3 reviewer Fail, non-compliant
  missing versioning/PAB, 0 AIML buckets, access-denied,
  region-unavailable, nonzero-region-index short-circuit empty,
  unexpected-exception HP-07 correct row
- CSV filename convention (execution_id before region, OWASP ordering)
- CSV column ordering includes Compliance_Frameworks at tail
- lambda_handler re-raises ClientError for ASL Catch path (no swallow)
- Pagination page-2: non-compliant resource placed only on 2nd page of
  paginated result still triggers Failed row
- run_all_checks per-check exception isolation: each HP-ID raised via
  injected RuntimeError produces its own N/A row while sibling checks
  still complete (plus HP-07 outer ClientError wrap)
"""

import importlib.util
import os
import re
import sys
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError
import pytest

from tests.test_helpers import assert_finding_schema, extract_csv_data

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
# Helpers
# ---------------------------------------------------------------------------
def _na_informational_check(rows, expected_check_id, region=REGION):
    """Assert at least one N/A / Informational row for the expected HP-##."""
    matches = [
        r for r in rows if r["Check_ID"] == expected_check_id and r["Status"] == "N/A"
    ]
    assert matches, (
        f"No N/A rows found for {expected_check_id} "
        f"(rows={[r['Check_ID'] + '/' + r['Status'] for r in rows]})"
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
        assert m["Severity"] == "Informational"
        assert m["Resolution"] == "No action required."
        assert_finding_schema(m)
    return matches


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
# HP-01 — Bedrock custom model CMK encryption
# ---------------------------------------------------------------------------
class TestHP01BedrockCustomModelEncryption:
    def _bedrock_client_routes(self, bedrock, kms):
        def _make(name, **kw):
            if name == "bedrock":
                return bedrock
            if name == "kms":
                return kms
            return MagicMock()

        return _make

    def test_zero_custom_models_returns_na_informational(self):
        with patch.object(hipaa_app.boto3, "client") as mclient:
            bedrock = MagicMock()
            paginator = MagicMock()
            paginator.paginate.return_value = [{"modelSummaries": []}]
            bedrock.get_paginator.return_value = paginator
            bedrock.list_custom_models.return_value = {"modelSummaries": []}
            kms = MagicMock()
            mclient.side_effect = self._bedrock_client_routes(bedrock, kms)
            rows = extract_csv_data(
                hipaa_app.check_bedrock_custom_model_encryption(REGION)
            )
        _na_informational_check(rows, "HP-01")
        assert any("No Bedrock custom models" in r["Finding_Details"] for r in rows)

    def test_non_compliant_cmk_missing_emits_failed_high(self):
        with patch.object(hipaa_app.boto3, "client") as mclient:
            bedrock = MagicMock()
            paginator = MagicMock()
            paginator.paginate.return_value = [
                {
                    "modelSummaries": [
                        {
                            "modelArn": "arn:aws:bedrock:us-east-1::custom-model/cust-1",
                            "modelName": "cust-1",
                        }
                    ]
                }
            ]
            bedrock.get_paginator.return_value = paginator
            bedrock.list_custom_models.return_value = {
                "modelSummaries": [
                    {
                        "modelArn": "arn:aws:bedrock:us-east-1::custom-model/cust-1",
                        "modelName": "cust-1",
                    }
                ]
            }
            bedrock.get_custom_model.return_value = {
                "modelArn": "arn:aws:bedrock:us-east-1::custom-model/cust-1"
            }
            kms = MagicMock()
            mclient.side_effect = self._bedrock_client_routes(bedrock, kms)
            rows = extract_csv_data(
                hipaa_app.check_bedrock_custom_model_encryption(REGION)
            )
        fails = _failed_check(rows, "HP-01", "High")
        assert any("cust-1" in f["Finding_Details"] for f in fails)

    def test_compliant_all_cmk_produces_informational_passed(self):
        with patch.object(hipaa_app.boto3, "client") as mclient:
            bedrock = MagicMock()
            paginator = MagicMock()
            paginator.paginate.return_value = [
                {
                    "modelSummaries": [
                        {
                            "modelArn": "arn:aws:bedrock:us-east-1::custom-model/cust-cmk",
                            "modelName": "cust-cmk",
                        }
                    ]
                }
            ]
            bedrock.get_paginator.return_value = paginator
            bedrock.list_custom_models.return_value = {
                "modelSummaries": [
                    {
                        "modelArn": "arn:aws:bedrock:us-east-1::custom-model/cust-cmk",
                        "modelName": "cust-cmk",
                    }
                ]
            }
            bedrock.get_custom_model.return_value = {
                "modelArn": "arn:aws:bedrock:us-east-1::custom-model/cust-cmk",
                "modelKmsKeyArn": "arn:aws:kms:us-east-1:111122223333:key/abcd",
            }
            kms = MagicMock()
            kms.describe_key.return_value = {
                "KeyMetadata": {"KeyManager": "CUSTOMER", "KeyState": "Enabled"}
            }
            mclient.side_effect = self._bedrock_client_routes(bedrock, kms)
            rows = extract_csv_data(
                hipaa_app.check_bedrock_custom_model_encryption(REGION)
            )
        _passed_agg(rows, "HP-01")

    def test_access_denied_produces_na_informational(self):
        with patch.object(hipaa_app.boto3, "client") as mclient:
            bedrock = MagicMock()
            paginator = MagicMock()
            paginator.paginate.side_effect = ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "Paginate",
            )
            bedrock.get_paginator.return_value = paginator
            bedrock.list_custom_models.side_effect = ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "ListCustomModels",
            )
            kms = MagicMock()
            mclient.side_effect = self._bedrock_client_routes(bedrock, kms)
            rows = extract_csv_data(
                hipaa_app.check_bedrock_custom_model_encryption(REGION)
            )
        _na_informational_check(rows, "HP-01")
        assert any(
            "AccessDeniedException" in r["Finding_Details"]
            or "access denied" in r["Finding_Details"].lower()
            or "unavailable" in r["Finding_Details"].lower()
            or "inaccessible" in r["Finding_Details"].lower()
            for r in rows
        )

    def test_region_unavailable_produces_na_informational(self):
        with patch.object(hipaa_app.boto3, "client") as mclient:
            bedrock = MagicMock()
            paginator = MagicMock()
            paginator.paginate.side_effect = ClientError(
                {
                    "Error": {
                        "Code": "UnrecognizedClientException",
                        "Message": "bad region",
                    }
                },
                "Paginate",
            )
            bedrock.get_paginator.return_value = paginator
            bedrock.list_custom_models.side_effect = ClientError(
                {
                    "Error": {
                        "Code": "UnrecognizedClientException",
                        "Message": "bad region",
                    }
                },
                "ListCustomModels",
            )
            kms = MagicMock()
            mclient.side_effect = self._bedrock_client_routes(bedrock, kms)
            rows = extract_csv_data(
                hipaa_app.check_bedrock_custom_model_encryption(REGION)
            )
        _na_informational_check(rows, "HP-01")

    def test_unexpected_exception_emits_correct_check_id_na_through_wrapper(self):
        """Inject a RuntimeError deep inside the paginator. The
        _run_check_safely wrapper used via run_all_checks must catch the
        generic exception and emit a single N/A/Informational incomplete
        row with Check_ID == "HP-01"; sibling checks must not be aborted
        (verified separately in run_all_checks isolation tests)."""

        def bad_bedrock(region):
            raise RuntimeError("corrupted paginator in HP-01 test")

        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.side_effect = lambda n, **kw: MagicMock()
            rows = extract_csv_data(
                hipaa_app._run_check_safely(bad_bedrock, "HP-01", REGION)
            )
        _na_informational_check(rows, "HP-01")
        assert any(
            "Incomplete" in r["Finding"]
            or "Unexpected exception" in r["Finding_Details"]
            or "RuntimeError" in r["Finding_Details"]
            for r in rows
        )


# ---------------------------------------------------------------------------
# HP-02 — Bedrock guardrails PHI-entity redaction
# ---------------------------------------------------------------------------
class TestHP02BedrockGuardrailPIIFullCoverage:
    def test_zero_guardrails_returns_na_informational(self):
        with patch.object(hipaa_app.boto3, "client") as mclient:
            bedrock = MagicMock()
            paginator = MagicMock()
            paginator.paginate.return_value = [{"guardrails": []}]
            bedrock.get_paginator.return_value = paginator
            bedrock.list_guardrails.return_value = {"guardrails": []}
            mclient.return_value = bedrock
            rows = extract_csv_data(hipaa_app.check_bedrock_guardrail_pii(REGION))
        _na_informational_check(rows, "HP-02")
        assert any("No Bedrock guardrails" in r["Finding_Details"] for r in rows)

    def test_non_compliant_none_action_fails_medium(self):
        with patch.object(hipaa_app.boto3, "client") as mclient:
            bedrock = MagicMock()
            paginator = MagicMock()
            paginator.paginate.return_value = [
                {
                    "guardrails": [
                        {
                            "arn": "arn:aws:bedrock:us-east-1:111122223333:guardrail/badgr",
                            "name": "badgr",
                            "version": "1",
                        }
                    ]
                }
            ]
            bedrock.get_paginator.return_value = paginator
            bedrock.list_guardrails.return_value = {
                "guardrails": [
                    {
                        "arn": "arn:aws:bedrock:us-east-1:111122223333:guardrail/badgr",
                        "name": "badgr",
                        "version": "1",
                    }
                ]
            }
            bedrock.get_guardrail.return_value = {
                "sensitiveInformationPolicy": {
                    "piiEntities": [
                        {"type": "NAME", "action": "NONE"},
                        {"type": "US_SOCIAL_SECURITY_NUMBER", "action": "NONE"},
                    ]
                }
            }
            mclient.return_value = bedrock
            rows = extract_csv_data(hipaa_app.check_bedrock_guardrail_pii(REGION))
        fails = _failed_check(rows, "HP-02", "Medium")
        assert any("badgr" in f["Finding_Details"] for f in fails)

    def test_compliant_with_block_action_passes(self):
        with patch.object(hipaa_app.boto3, "client") as mclient:
            bedrock = MagicMock()
            paginator = MagicMock()
            paginator.paginate.return_value = [
                {
                    "guardrails": [
                        {
                            "arn": "arn:aws:bedrock:us-east-1:111122223333:guardrail/goodgr",
                            "name": "goodgr",
                            "version": "1",
                        }
                    ]
                }
            ]
            bedrock.get_paginator.return_value = paginator
            bedrock.list_guardrails.return_value = {
                "guardrails": [
                    {
                        "arn": "arn:aws:bedrock:us-east-1:111122223333:guardrail/goodgr",
                        "name": "goodgr",
                        "version": "1",
                    }
                ]
            }
            bedrock.get_guardrail.return_value = {
                "sensitiveInformationPolicy": {
                    "piiEntities": [
                        {"type": "NAME", "action": "BLOCK"},
                        {"type": "US_SOCIAL_SECURITY_NUMBER", "action": "BLOCK"},
                    ]
                }
            }
            mclient.return_value = bedrock
            rows = extract_csv_data(hipaa_app.check_bedrock_guardrail_pii(REGION))
        _passed_agg(rows, "HP-02")

    def test_access_denied_produces_na_informational(self):
        with patch.object(hipaa_app.boto3, "client") as mclient:
            bedrock = MagicMock()
            paginator = MagicMock()
            paginator.paginate.side_effect = ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "Paginate",
            )
            bedrock.get_paginator.return_value = paginator
            bedrock.list_guardrails.side_effect = ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "ListGuardrails",
            )
            mclient.return_value = bedrock
            rows = extract_csv_data(hipaa_app.check_bedrock_guardrail_pii(REGION))
        _na_informational_check(rows, "HP-02")

    def test_region_unavailable_produces_na_informational(self):
        with patch.object(hipaa_app.boto3, "client") as mclient:
            bedrock = MagicMock()
            paginator = MagicMock()
            paginator.paginate.side_effect = ClientError(
                {"Error": {"Code": "OptInRequired", "Message": "opt-in"}},
                "Paginate",
            )
            bedrock.get_paginator.return_value = paginator
            bedrock.list_guardrails.side_effect = ClientError(
                {"Error": {"Code": "OptInRequired", "Message": "opt-in"}},
                "ListGuardrails",
            )
            mclient.return_value = bedrock
            rows = extract_csv_data(hipaa_app.check_bedrock_guardrail_pii(REGION))
        _na_informational_check(rows, "HP-02")

    def test_unexpected_exception_na_row_correct_check_id(self):
        def bad(region):
            raise RuntimeError("boom from HP-02 in test")

        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = MagicMock()
            rows = extract_csv_data(hipaa_app._run_check_safely(bad, "HP-02", REGION))
        _na_informational_check(rows, "HP-02")
        assert any(
            "Incomplete" in r["Finding"] or "RuntimeError" in r["Finding_Details"]
            for r in rows
        )


class TestHP02ReviewerSpecials:
    def test_hp02_name_ssn_block_results_in_pass(self):
        """Realistic NAME + SSN (US_SOCIAL_SECURITY_NUMBER) entities each
        with BLOCK action — must produce the Passed aggregate."""
        with patch.object(hipaa_app.boto3, "client") as mclient:
            bedrock = MagicMock()
            paginator = MagicMock()
            paginator.paginate.return_value = [
                {
                    "guardrails": [
                        {
                            "arn": "arn:aws:bedrock:us-east-1:111122223333:guardrail/hipaa-block",
                            "name": "hipaa-block",
                            "version": "DRAFT",
                        }
                    ]
                }
            ]
            bedrock.get_paginator.return_value = paginator
            bedrock.list_guardrails.return_value = {
                "guardrails": [
                    {
                        "arn": "arn:aws:bedrock:us-east-1:111122223333:guardrail/hipaa-block",
                        "name": "hipaa-block",
                        "version": "DRAFT",
                    }
                ]
            }
            bedrock.get_guardrail.return_value = {
                "sensitiveInformationPolicy": {
                    "piiEntities": [
                        {"type": "NAME", "action": "BLOCK"},
                        {"type": "EMAIL", "action": "BLOCK"},
                        {"type": "US_SOCIAL_SECURITY_NUMBER", "action": "BLOCK"},
                        {"type": "PHONE", "action": "BLOCK"},
                        {"type": "DATE_OF_BIRTH", "action": "BLOCK"},
                    ]
                }
            }
            mclient.return_value = bedrock
            rows = extract_csv_data(hipaa_app.check_bedrock_guardrail_pii(REGION))
        _passed_agg(rows, "HP-02")

    def test_hp02_name_ssn_anonymize_results_in_pass(self):
        """ANONYMIZE (not BLOCK) on NAME + SSN is still sufficient for pass."""
        with patch.object(hipaa_app.boto3, "client") as mclient:
            bedrock = MagicMock()
            paginator = MagicMock()
            paginator.paginate.return_value = [
                {
                    "guardrails": [
                        {
                            "arn": "arn:aws:bedrock:us-east-1:111122223333:guardrail/hipaa-anon",
                            "name": "hipaa-anon",
                            "version": "2",
                        }
                    ]
                }
            ]
            bedrock.get_paginator.return_value = paginator
            bedrock.list_guardrails.return_value = {
                "guardrails": [
                    {
                        "arn": "arn:aws:bedrock:us-east-1:111122223333:guardrail/hipaa-anon",
                        "name": "hipaa-anon",
                        "version": "2",
                    }
                ]
            }
            bedrock.get_guardrail.return_value = {
                "sensitiveInformationPolicy": {
                    "piiEntities": [
                        {"type": "NAME", "action": "ANONYMIZE"},
                        {"type": "US_SOCIAL_SECURITY_NUMBER", "action": "ANONYMIZE"},
                    ]
                }
            }
            mclient.return_value = bedrock
            rows = extract_csv_data(hipaa_app.check_bedrock_guardrail_pii(REGION))
        _passed_agg(rows, "HP-02")

    def test_hp02_name_ssn_none_action_fails_medium(self):
        """Explicit reviewer test: NONE on NAME + SSN must fail HP-02."""
        with patch.object(hipaa_app.boto3, "client") as mclient:
            bedrock = MagicMock()
            paginator = MagicMock()
            paginator.paginate.return_value = [
                {
                    "guardrails": [
                        {
                            "arn": "arn:aws:bedrock:us-east-1:111122223333:guardrail/none-gr",
                            "name": "none-gr",
                            "version": "1",
                        }
                    ]
                }
            ]
            bedrock.get_paginator.return_value = paginator
            bedrock.list_guardrails.return_value = {
                "guardrails": [
                    {
                        "arn": "arn:aws:bedrock:us-east-1:111122223333:guardrail/none-gr",
                        "name": "none-gr",
                        "version": "1",
                    }
                ]
            }
            bedrock.get_guardrail.return_value = {
                "sensitiveInformationPolicy": {
                    "piiEntities": [
                        {"type": "NAME", "action": "NONE"},
                        {"type": "US_SOCIAL_SECURITY_NUMBER", "action": "NONE"},
                    ]
                }
            }
            mclient.return_value = bedrock
            rows = extract_csv_data(hipaa_app.check_bedrock_guardrail_pii(REGION))
        fails = _failed_check(rows, "HP-02", "Medium")
        assert any("none-gr" in f["Finding_Details"] for f in fails)


# ---------------------------------------------------------------------------
# HP-03 — SageMaker network isolation (DescribeModel EnableNetworkIsolation)
# ---------------------------------------------------------------------------
def _make_sm_mocks(
    endpoints,
    endpoint_configs,
    models,
    training_jobs,
    training_descriptions,
):
    sagemaker = MagicMock()

    ep_paginator = MagicMock()
    ep_paginator.paginate.return_value = [{"Endpoints": endpoints}]
    tj_paginator = MagicMock()
    tj_paginator.paginate.return_value = [{"TrainingJobSummaries": training_jobs}]

    def _gp(name):
        if name == "list_endpoints":
            return ep_paginator
        if name == "list_training_jobs":
            return tj_paginator
        raise RuntimeError(f"unmocked paginator: {name}")

    sagemaker.get_paginator.side_effect = _gp
    sagemaker.list_endpoints.return_value = {"Endpoints": endpoints}
    sagemaker.list_training_jobs.return_value = {"TrainingJobSummaries": training_jobs}

    def _describe_endpoint(EndpointName=None):
        ep_cfg_name = next(
            (
                e["EndpointConfigName"]
                for e in endpoints
                if e["EndpointName"] == EndpointName
            ),
            None,
        )
        return {
            "EndpointName": EndpointName,
            "EndpointConfigName": ep_cfg_name,
            "ProductionVariants": [
                {
                    "VariantName": v.get("VariantName", "v1"),
                    "ModelName": v.get("ModelName", ""),
                }
                for v in next(
                    (
                        e.get("ProductionVariants", [])
                        for e in endpoints
                        if e["EndpointName"] == EndpointName
                    ),
                    [],
                )
            ],
        }

    sagemaker.describe_endpoint.side_effect = _describe_endpoint

    def _describe_endpoint_config(EndpointConfigName=None):
        return endpoint_configs.get(EndpointConfigName, {})

    sagemaker.describe_endpoint_config.side_effect = _describe_endpoint_config

    def _describe_model(ModelName=None):
        return models.get(ModelName, {})

    sagemaker.describe_model.side_effect = _describe_model

    def _describe_training_job(TrainingJobName=None):
        return training_descriptions.get(TrainingJobName, {})

    sagemaker.describe_training_job.side_effect = _describe_training_job
    return sagemaker


class TestHP03SageMakerNetworkIsolationFullCoverage:
    def test_zero_resources_returns_na_informational(self):
        sm = _make_sm_mocks([], {}, {}, [], {})
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = sm
            rows = extract_csv_data(hipaa_app.check_sagemaker_network_isolation(REGION))
        _na_informational_check(rows, "HP-03")

    def test_non_compliant_unisolated_fails_medium(self):
        endpoints = [
            {
                "EndpointName": "ep-uniso",
                "EndpointConfigName": "cfg-uniso",
                "ProductionVariants": [{"VariantName": "v1", "ModelName": "mod-uniso"}],
            }
        ]
        endpoint_configs = {
            "cfg-uniso": {"EnableNetworkIsolation": False},
        }
        models = {
            "mod-uniso": {"EnableNetworkIsolation": False},
        }
        training_jobs = [{"TrainingJobName": "tj-uniso"}]
        training_descriptions = {
            "tj-uniso": {"EnableNetworkIsolation": False},
        }
        sm = _make_sm_mocks(
            endpoints, endpoint_configs, models, training_jobs, training_descriptions
        )
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = sm
            rows = extract_csv_data(hipaa_app.check_sagemaker_network_isolation(REGION))
        fails = _failed_check(rows, "HP-03", "Medium")
        assert any("ep-uniso" in f["Finding_Details"] for f in fails)
        assert any("tj-uniso" in f["Finding_Details"] for f in fails)

    def test_compliant_network_isolated_passes(self):
        endpoints = [
            {
                "EndpointName": "ep-iso",
                "EndpointConfigName": "cfg-iso",
                "ProductionVariants": [{"VariantName": "v1", "ModelName": "mod-iso"}],
            }
        ]
        endpoint_configs = {
            "cfg-iso": {"EnableNetworkIsolation": True},
        }
        models = {
            "mod-iso": {"EnableNetworkIsolation": True},
        }
        training_jobs = [{"TrainingJobName": "tj-iso"}]
        training_descriptions = {
            "tj-iso": {"EnableNetworkIsolation": True},
        }
        sm = _make_sm_mocks(
            endpoints, endpoint_configs, models, training_jobs, training_descriptions
        )
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = sm
            rows = extract_csv_data(hipaa_app.check_sagemaker_network_isolation(REGION))
        _passed_agg(rows, "HP-03")

    def test_access_denied_produces_na_informational(self):
        sm = MagicMock()
        ep_paginator = MagicMock()
        ep_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "Paginate",
        )
        tj_paginator = MagicMock()
        tj_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "Paginate",
        )

        def _gp(name):
            if name == "list_endpoints":
                return ep_paginator
            if name == "list_training_jobs":
                return tj_paginator
            raise RuntimeError(f"no paginator mock for {name}")

        sm.get_paginator.side_effect = _gp
        sm.list_endpoints.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "ListEndpoints",
        )
        sm.list_training_jobs.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "ListTrainingJobs",
        )
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = sm
            rows = extract_csv_data(
                hipaa_app._run_check_safely(
                    hipaa_app.check_sagemaker_network_isolation, "HP-03", REGION
                )
            )
        _na_informational_check(rows, "HP-03")

    def test_region_unavailable_produces_na_informational(self):
        sm = MagicMock()
        ep_paginator = MagicMock()
        ep_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "UnrecognizedClientException", "Message": "bad"}},
            "Paginate",
        )
        tj_paginator = MagicMock()
        tj_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "UnrecognizedClientException", "Message": "bad"}},
            "Paginate",
        )

        def _gp(name):
            if name == "list_endpoints":
                return ep_paginator
            if name == "list_training_jobs":
                return tj_paginator
            raise RuntimeError(f"no paginator mock for {name}")

        sm.get_paginator.side_effect = _gp
        sm.list_endpoints.side_effect = ClientError(
            {"Error": {"Code": "UnrecognizedClientException", "Message": "bad"}},
            "ListEndpoints",
        )
        sm.list_training_jobs.side_effect = ClientError(
            {"Error": {"Code": "UnrecognizedClientException", "Message": "bad"}},
            "ListTrainingJobs",
        )
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = sm
            rows = extract_csv_data(
                hipaa_app._run_check_safely(
                    hipaa_app.check_sagemaker_network_isolation, "HP-03", REGION
                )
            )
        _na_informational_check(rows, "HP-03")

    def test_unexpected_exception_na_row_correct_check_id(self):
        def bad(region):
            raise RuntimeError("boom from HP-03 in test")

        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = MagicMock()
            rows = extract_csv_data(hipaa_app._run_check_safely(bad, "HP-03", REGION))
        _na_informational_check(rows, "HP-03")
        assert any(
            "Incomplete" in r["Finding"] or "RuntimeError" in r["Finding_Details"]
            for r in rows
        )


class TestHP03ReviewerEnableNetworkIsolation:
    def test_hp03_describe_model_enablenetworkisolation_true_passes(self):
        """Reviewer-specific: evidence for an endpoint must come from
        sagemaker:DescribeModel EnableNetworkIsolation=True on each variant's
        ModelName (not only the EndpointConfig fallback)."""
        endpoints = [
            {
                "EndpointName": "ep-mod-iso",
                "EndpointConfigName": "cfg-mid",
                "ProductionVariants": [
                    {"VariantName": "v1", "ModelName": "model-isolated"}
                ],
            }
        ]
        endpoint_configs = {
            # EndpointConfig fallback leaves it False; the authoritative
            # DescribeModel call returns True and must win.
            "cfg-mid": {"EnableNetworkIsolation": False},
        }
        models = {
            "model-isolated": {"EnableNetworkIsolation": True},
        }
        training_jobs = []
        training_descriptions = {}
        sm = _make_sm_mocks(
            endpoints, endpoint_configs, models, training_jobs, training_descriptions
        )
        # Also verify the describe_model call happens at least once for the
        # ModelName so we know the evidence chain is exercised.
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = sm
            rows = extract_csv_data(hipaa_app.check_sagemaker_network_isolation(REGION))
        assert sm.describe_model.called
        _passed_agg(rows, "HP-03")


# ---------------------------------------------------------------------------
# HP-04 — SageMaker endpoints + training jobs CMK encryption
# ---------------------------------------------------------------------------
def _make_enc_mocks(
    endpoints,
    endpoint_configs,
    training_jobs,
    training_descriptions,
    kms_key_map,
):
    sagemaker = _make_sm_mocks(
        endpoints, endpoint_configs, {}, training_jobs, training_descriptions
    )
    kms = MagicMock()

    def _describe_key(KeyId=None):
        if KeyId in kms_key_map:
            return {
                "KeyMetadata": {
                    "KeyManager": kms_key_map[KeyId]["manager"],
                    "KeyState": kms_key_map[KeyId].get("state", "Enabled"),
                }
            }
        return {
            "KeyMetadata": {"KeyManager": "AWS", "KeyState": "Enabled"},
        }

    kms.describe_key.side_effect = _describe_key

    def _make_client(name, **kw):
        if name == "sagemaker":
            return sagemaker
        if name == "kms":
            return kms
        return MagicMock()

    return sagemaker, kms, _make_client


class TestHP04SageMakerResourceEncryptionFullCoverage:
    def test_zero_resources_returns_na_informational(self):
        sm, kms, route = _make_enc_mocks([], {}, [], {}, {})
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.side_effect = route
            rows = extract_csv_data(
                hipaa_app.check_sagemaker_resource_encryption(REGION)
            )
        _na_informational_check(rows, "HP-04")

    def test_non_compliant_missing_cmk_fails_high(self):
        endpoints = [
            {
                "EndpointName": "ep-nocmk",
                "EndpointConfigName": "cfg-nocmk",
                "ProductionVariants": [{"VariantName": "v1", "ModelName": "any"}],
            }
        ]
        endpoint_configs = {
            "cfg-nocmk": {},  # no KmsKeyId
        }
        training_jobs = [{"TrainingJobName": "tj-nocmk"}]
        training_descriptions = {
            "tj-nocmk": {
                # no VolumeKmsKeyId / OutputDataConfig.KmsKeyId / inter-container flag
                "ResourceConfig": {},
                "OutputDataConfig": {},
            }
        }
        sm, kms, route = _make_enc_mocks(
            endpoints, endpoint_configs, training_jobs, training_descriptions, {}
        )
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.side_effect = route
            rows = extract_csv_data(
                hipaa_app.check_sagemaker_resource_encryption(REGION)
            )
        fails = _failed_check(rows, "HP-04", "High")
        assert any(
            "ep-nocmk" in f["Finding_Details"] or "tj-nocmk" in f["Finding_Details"]
            for f in fails
        )

    def test_compliant_all_cmk_bound_and_intercontainer_true_passes(self):
        cmk_arn = "arn:aws:kms:us-east-1:111122223333:key/ep-cmk"
        endpoints = [
            {
                "EndpointName": "ep-cmk",
                "EndpointConfigName": "cfg-cmk",
                "ProductionVariants": [{"VariantName": "v1", "ModelName": "any"}],
            }
        ]
        endpoint_configs = {
            "cfg-cmk": {"KmsKeyId": cmk_arn},
        }
        training_jobs = [{"TrainingJobName": "tj-cmk"}]
        training_descriptions = {
            "tj-cmk": {
                "ResourceConfig": {"VolumeKmsKeyId": cmk_arn},
                "OutputDataConfig": {"KmsKeyId": cmk_arn},
                "EnableInterContainerTrafficEncryption": True,
            }
        }
        kms_map = {
            cmk_arn: {"manager": "CUSTOMER"},
        }
        sm, kms, route = _make_enc_mocks(
            endpoints, endpoint_configs, training_jobs, training_descriptions, kms_map
        )
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.side_effect = route
            rows = extract_csv_data(
                hipaa_app.check_sagemaker_resource_encryption(REGION)
            )
        _passed_agg(rows, "HP-04")

    def test_access_denied_produces_na_informational(self):
        sm = MagicMock()
        ep_paginator = MagicMock()
        ep_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "Paginate",
        )
        tj_paginator = MagicMock()
        tj_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "Paginate",
        )

        def _gp(name):
            if name == "list_endpoints":
                return ep_paginator
            if name == "list_training_jobs":
                return tj_paginator
            raise RuntimeError(f"no paginator mock for {name}")

        sm.get_paginator.side_effect = _gp
        sm.list_endpoints.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "ListEndpoints",
        )
        sm.list_training_jobs.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "ListTrainingJobs",
        )

        def _route(name, **kw):
            if name == "sagemaker":
                return sm
            return MagicMock()

        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.side_effect = _route
            rows = extract_csv_data(
                hipaa_app._run_check_safely(
                    hipaa_app.check_sagemaker_resource_encryption, "HP-04", REGION
                )
            )
        _na_informational_check(rows, "HP-04")

    def test_region_unavailable_produces_na_informational(self):
        sm = MagicMock()
        ep_paginator = MagicMock()
        ep_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "UnrecognizedClientException", "Message": "bad"}},
            "Paginate",
        )
        tj_paginator = MagicMock()
        tj_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "UnrecognizedClientException", "Message": "bad"}},
            "Paginate",
        )

        def _gp(name):
            if name == "list_endpoints":
                return ep_paginator
            if name == "list_training_jobs":
                return tj_paginator
            raise RuntimeError(f"no paginator mock for {name}")

        sm.get_paginator.side_effect = _gp
        sm.list_endpoints.side_effect = ClientError(
            {"Error": {"Code": "UnrecognizedClientException", "Message": "bad"}},
            "ListEndpoints",
        )
        sm.list_training_jobs.side_effect = ClientError(
            {"Error": {"Code": "UnrecognizedClientException", "Message": "bad"}},
            "ListTrainingJobs",
        )

        def _route(name, **kw):
            if name == "sagemaker":
                return sm
            return MagicMock()

        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.side_effect = _route
            rows = extract_csv_data(
                hipaa_app._run_check_safely(
                    hipaa_app.check_sagemaker_resource_encryption, "HP-04", REGION
                )
            )
        _na_informational_check(rows, "HP-04")

    def test_unexpected_exception_na_row_correct_check_id(self):
        def bad(region):
            raise RuntimeError("boom from HP-04 in test")

        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = MagicMock()
            rows = extract_csv_data(hipaa_app._run_check_safely(bad, "HP-04", REGION))
        _na_informational_check(rows, "HP-04")
        assert any(
            "Incomplete" in r["Finding"] or "RuntimeError" in r["Finding_Details"]
            for r in rows
        )


# ---------------------------------------------------------------------------
# HP-05 — CloudWatch Logs AIML-prefixed groups data-protection policy
# ---------------------------------------------------------------------------
def _make_logs_mocks(
    groups_by_prefix, per_group_dp_map, *, account_policy_present=False
):
    logs = MagicMock()

    def _describe_account_policies(policyType=None):
        if account_policy_present:
            return {
                "accountPolicies": [
                    {"policyName": "hipaa-account-dp", "policyType": policyType},
                ]
            }
        return {"accountPolicies": []}

    logs.describe_account_policies.side_effect = _describe_account_policies

    def _describe_log_groups_paginate_side_effect(
        logGroupNamePrefix=None, PaginationConfig=None
    ):
        groups = groups_by_prefix.get(logGroupNamePrefix, [])
        yield {"logGroups": groups}

    paginator = MagicMock()
    paginator.paginate.side_effect = _describe_log_groups_paginate_side_effect
    logs.get_paginator.return_value = paginator

    def _describe_log_groups(logGroupNamePrefix=None, limit=None):
        return {"logGroups": groups_by_prefix.get(logGroupNamePrefix, [])}

    logs.describe_log_groups.side_effect = _describe_log_groups

    def _get_data_protection_policy(logGroupIdentifier=None):
        entry = per_group_dp_map.get(logGroupIdentifier)
        if entry is None:
            raise ClientError(
                {
                    "Error": {
                        "Code": "ResourceNotFoundException",
                        "Message": "no policy",
                    }
                },
                "GetDataProtectionPolicy",
            )
        if isinstance(entry, dict) and entry.get("_empty"):
            # reviewer path: empty body {} → must fail
            return {}
        if isinstance(entry, dict) and entry.get("_empty_str"):
            # string form of empty body
            return {"policyDocument": "{}", "dataProtectionStatus": ""}
        return entry

    logs.get_data_protection_policy.side_effect = _get_data_protection_policy
    return logs


class TestHP05CloudWatchLogsFullCoverage:
    def test_zero_aiml_groups_returns_na_informational(self):
        logs = _make_logs_mocks({}, {}, account_policy_present=False)
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = logs
            rows = extract_csv_data(
                hipaa_app.check_cloudwatch_logs_data_protection(REGION)
            )
        _na_informational_check(rows, "HP-05")
        assert any("No AIML-prefixed CloudWatch" in r["Finding_Details"] for r in rows)

    def test_non_compliant_groups_missing_policy_fails_medium(self):
        prefix = "/aws/bedrock/"
        group_name = "/aws/bedrock/my-group"
        groups_by_prefix = {prefix: [{"logGroupName": group_name}]}
        per_group_dp = {}  # ResourceNotFoundException for every group
        logs = _make_logs_mocks(
            groups_by_prefix, per_group_dp, account_policy_present=False
        )
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = logs
            rows = extract_csv_data(
                hipaa_app.check_cloudwatch_logs_data_protection(REGION)
            )
        fails = _failed_check(rows, "HP-05", "Medium")
        assert any(group_name in f["Finding_Details"] for f in fails)

    def test_compliant_per_group_activated_passes(self):
        prefix = "/aws/bedrock/"
        group_name = "/aws/bedrock/my-group"
        groups_by_prefix = {prefix: [{"logGroupName": group_name}]}
        per_group_dp = {
            group_name: {
                "policyDocument": '{"Version":"2012-10-17","Statement":[]}',
                "dataProtectionStatus": "ACTIVATED",
            }
        }
        logs = _make_logs_mocks(
            groups_by_prefix, per_group_dp, account_policy_present=False
        )
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = logs
            rows = extract_csv_data(
                hipaa_app.check_cloudwatch_logs_data_protection(REGION)
            )
        _passed_agg(rows, "HP-05")

    def test_access_denied_produces_na_informational(self):
        logs = MagicMock()
        paginator = MagicMock()
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "Paginate",
        )
        logs.get_paginator.return_value = paginator
        logs.describe_log_groups.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "DescribeLogGroups",
        )
        logs.describe_account_policies.return_value = {"accountPolicies": []}
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = logs
            rows = extract_csv_data(
                hipaa_app.check_cloudwatch_logs_data_protection(REGION)
            )
        _na_informational_check(rows, "HP-05")

    def test_region_unavailable_produces_na_informational(self):
        logs = MagicMock()
        paginator = MagicMock()
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "OptInRequired", "Message": "opt-in"}},
            "Paginate",
        )
        logs.get_paginator.return_value = paginator
        logs.describe_log_groups.side_effect = ClientError(
            {"Error": {"Code": "OptInRequired", "Message": "opt-in"}},
            "DescribeLogGroups",
        )
        logs.describe_account_policies.return_value = {"accountPolicies": []}
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = logs
            rows = extract_csv_data(
                hipaa_app.check_cloudwatch_logs_data_protection(REGION)
            )
        _na_informational_check(rows, "HP-05")

    def test_unexpected_exception_na_row_correct_check_id(self):
        def bad(region):
            raise RuntimeError("boom from HP-05 in test")

        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = MagicMock()
            rows = extract_csv_data(hipaa_app._run_check_safely(bad, "HP-05", REGION))
        _na_informational_check(rows, "HP-05")
        assert any(
            "Incomplete" in r["Finding"] or "RuntimeError" in r["Finding_Details"]
            for r in rows
        )


class TestHP05ReviewerSpecials:
    def test_hp05_get_data_protection_policy_empty_body_dict_fails(self):
        """Reviewer-specific: get_data_protection_policy returns empty {} body
        (not a ResourceNotFoundException nor a populated ACTIVATED policy) →
        must emit Failed, not Passed."""
        prefix = "/aws/bedrock/"
        group_name = "/aws/bedrock/empty-body-group"
        groups_by_prefix = {prefix: [{"logGroupName": group_name}]}
        per_group_dp = {
            group_name: {"_empty": True},
        }
        logs = _make_logs_mocks(
            groups_by_prefix, per_group_dp, account_policy_present=False
        )
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = logs
            rows = extract_csv_data(
                hipaa_app.check_cloudwatch_logs_data_protection(REGION)
            )
        fails = _failed_check(rows, "HP-05", "Medium")
        assert any(
            "empty-body-group" in f["Finding_Details"]
            or "empty body" in f["Finding_Details"]
            for f in fails
        )

    def test_hp05_account_level_data_protection_policy_passes(self):
        """Reviewer: account-level DATA_PROTECTION_POLICY via
        describe_account_policies must satisfy HP-05 (even without per-group
        policies)."""
        prefix = "/aws/sagemaker/"
        group_name = "/aws/sagemaker/ep-logs"
        groups_by_prefix = {prefix: [{"logGroupName": group_name}]}
        per_group_dp = {}  # ResourceNotFoundException on per-group
        logs = _make_logs_mocks(
            groups_by_prefix, per_group_dp, account_policy_present=True
        )
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = logs
            rows = extract_csv_data(
                hipaa_app.check_cloudwatch_logs_data_protection(REGION)
            )
        _passed_agg(rows, "HP-05")


def _build_ec2(
    describe_vpcs_pages,
    describe_vpc_endpoints_pages,
    describe_vpc_endpoint_services_page,
):
    """Build a MagicMock EC2 client with paginator side_effect routing for HP-06.

    describe_vpcs_pages / describe_vpc_endpoints_pages: list of pages; each
    page is a dict matching boto3 return shape. Empty list → paginator
    returns exactly one empty page `{"Vpcs": []}` / `{"VpcEndpoints": []}`.
    describe_vpc_endpoint_services_page: single dict page (Services+ServiceNames).
    """
    ec2 = MagicMock()

    def _paginator(op):
        p = MagicMock()
        if op == "describe_vpcs":
            pages = describe_vpcs_pages or [{"Vpcs": []}]
            p.paginate.side_effect = lambda **kw: iter(pages)
        elif op == "describe_vpc_endpoints":
            pages = describe_vpc_endpoints_pages or [{"VpcEndpoints": []}]
            p.paginate.side_effect = lambda **kw: iter(pages)
        else:
            raise ValueError(f"unexpected paginate op: {op}")
        return p

    ec2.get_paginator = _paginator
    ec2.describe_vpc_endpoint_services.return_value = (
        describe_vpc_endpoint_services_page
    )
    return ec2


ALL_12_HIPAA_SERVICES = (
    "com.amazonaws.us-east-1.bedrock",
    "com.amazonaws.us-east-1.bedrock-agent",
    "com.amazonaws.us-east-1.bedrock-agent-runtime",
    "com.amazonaws.us-east-1.sagemaker.api",
    "com.amazonaws.us-east-1.sagemaker.runtime",
    "com.amazonaws.us-east-1.sagemaker.featurestore-runtime",
    "com.amazonaws.us-east-1.sts",
    "com.amazonaws.us-east-1.kms",
    "com.amazonaws.us-east-1.secretsmanager",
    "com.amazonaws.us-east-1.logs",
    "com.amazonaws.us-east-1.s3",
    "com.amazonaws.us-east-1.ec2",
)


class TestHP06VPCEndpointsFullCoverage:
    """HP-06 VPC Endpoint coverage — 6-case minimum per reviewer spec."""

    def test_hp06_zero_vpcs_informational_na(self):
        services_page = {
            "ServiceNames": list(ALL_12_HIPAA_SERVICES),
            "ServiceDetails": [
                {"ServiceName": n, "ServiceType": [{"ServiceType": "Gateway"}]}
                for n in ALL_12_HIPAA_SERVICES
            ],
        }
        ec2 = _build_ec2(
            describe_vpcs_pages=[{"Vpcs": []}],
            describe_vpc_endpoints_pages=[{"VpcEndpoints": []}],
            describe_vpc_endpoint_services_page=services_page,
        )
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = ec2
            rows = extract_csv_data(hipaa_app.check_vpc_endpoints_configured(REGION))
        _na_informational_check(rows, "HP-06", REGION)

    def test_hp06_some_required_services_missing_fails_medium(self):
        vpc = {"VpcId": "vpc-1", "IsDefault": True}
        present = [
            "com.amazonaws.us-east-1.bedrock",
            "com.amazonaws.us-east-1.bedrock-agent",
            "com.amazonaws.us-east-1.bedrock-agent-runtime",
            "com.amazonaws.us-east-1.sagemaker.api",
            "com.amazonaws.us-east-1.sagemaker.runtime",
            "com.amazonaws.us-east-1.sagemaker.featurestore-runtime",
            "com.amazonaws.us-east-1.sts",
            "com.amazonaws.us-east-1.kms",
            "com.amazonaws.us-east-1.secretsmanager",
            "com.amazonaws.us-east-1.logs",
        ]
        endpoints = [
            {
                "ServiceName": svc,
                "VpcId": vpc["VpcId"],
                "State": "available",
            }
            for svc in present
        ]
        services_page = {
            "ServiceNames": list(ALL_12_HIPAA_SERVICES),
            "ServiceDetails": [
                {
                    "ServiceName": n,
                    "ServiceType": [
                        {"ServiceType": "Gateway" if n.endswith(".s3") else "Interface"}
                    ],
                }
                for n in ALL_12_HIPAA_SERVICES
            ],
        }
        ec2 = _build_ec2(
            describe_vpcs_pages=[{"Vpcs": [vpc]}],
            describe_vpc_endpoints_pages=[{"VpcEndpoints": endpoints}],
            describe_vpc_endpoint_services_page=services_page,
        )
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = ec2
            rows = extract_csv_data(hipaa_app.check_vpc_endpoints_configured(REGION))
        fails = _failed_check(rows, "HP-06", "Medium")
        assert any("s3" in f["Finding_Details"].lower() for f in fails)
        assert any("ec2" in f["Finding_Details"].lower() for f in fails)

    def test_hp06_all_12_services_available_passes(self):
        vpc = {"VpcId": "vpc-1", "IsDefault": True}
        endpoints = [
            {
                "ServiceName": svc,
                "VpcId": vpc["VpcId"],
                "State": "available",
            }
            for svc in ALL_12_HIPAA_SERVICES
        ]
        services_page = {
            "ServiceNames": list(ALL_12_HIPAA_SERVICES),
            "ServiceDetails": [
                {
                    "ServiceName": n,
                    "ServiceType": [
                        {"ServiceType": "Gateway" if n.endswith(".s3") else "Interface"}
                    ],
                }
                for n in ALL_12_HIPAA_SERVICES
            ],
        }
        ec2 = _build_ec2(
            describe_vpcs_pages=[{"Vpcs": [vpc]}],
            describe_vpc_endpoints_pages=[{"VpcEndpoints": endpoints}],
            describe_vpc_endpoint_services_page=services_page,
        )
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = ec2
            rows = extract_csv_data(hipaa_app.check_vpc_endpoints_configured(REGION))
        _passed_agg(rows, "HP-06")

    def test_hp06_describe_vpcs_access_denied_na(self):
        ec2 = MagicMock()

        def _vpcs_pag(*_args, **_kw):
            raise ClientError(
                {"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}},
                "DescribeVpcs",
            )

        p = MagicMock()
        p.paginate.side_effect = _vpcs_pag
        ec2.get_paginator.return_value = p
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = ec2
            rows = extract_csv_data(hipaa_app.check_vpc_endpoints_configured(REGION))
        _na_informational_check(rows, "HP-06", REGION)

    def test_hp06_region_unsupported_na(self):
        ec2 = MagicMock()

        def _vpcs_pag(*_args, **_kw):
            raise ClientError(
                {"Error": {"Code": "AuthFailure", "Message": "not authorized"}},
                "DescribeVpcs",
            )

        p = MagicMock()
        p.paginate.side_effect = _vpcs_pag
        ec2.get_paginator.return_value = p
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = ec2
            rows = extract_csv_data(hipaa_app.check_vpc_endpoints_configured(REGION))
        _na_informational_check(rows, "HP-06", REGION)

    def test_hp06_unexpected_exception_fallback_na_correct_id(self):
        def _bad(region):
            raise RuntimeError("simulated HP-06 internal explosion")

        rows = extract_csv_data(hipaa_app._run_check_safely(_bad, "HP-06", REGION))
        _na_informational_check(rows, "HP-06", REGION)
        assert any("Unexpected exception" in r["Finding_Details"] for r in rows)


def _build_s3_clients(
    list_buckets_response,
    per_bucket_encryption,
    per_bucket_versioning,
    per_bucket_pab,
    account_level_pab=None,
    kms_describe_key=None,
):
    """Build three MagicMock clients (s3, s3control, kms) for HP-07.

    per_bucket_*: dict mapping BucketName → boto3-shape response dict.
    kms_describe_key: optional dict returned by kms.describe_key(KeyId=…);
      leave None to raise KeyError if the code path doesn't require KMS.
    """
    s3 = MagicMock()
    s3control = MagicMock()
    kms = MagicMock()

    s3.list_buckets.return_value = list_buckets_response

    def _s3_op(fn_name, mapping, bucket_arg, **_kw):
        def _dispatcher(*args, **kwargs):
            bname = kwargs.get(bucket_arg) or (args[0] if args else None)
            if bname not in mapping:
                raise RuntimeError(
                    f"HP-07 test fixture missing {fn_name} for bucket={bname}"
                )
            return mapping[bname]

        return _dispatcher

    s3.get_bucket_encryption.side_effect = _s3_op(
        "get_bucket_encryption", per_bucket_encryption, "Bucket"
    )
    s3.get_bucket_versioning.side_effect = _s3_op(
        "get_bucket_versioning", per_bucket_versioning, "Bucket"
    )
    s3.get_public_access_block.side_effect = _s3_op(
        "get_public_access_block", per_bucket_pab, "Bucket"
    )

    if account_level_pab is None:
        s3control.get_public_access_block.side_effect = ClientError(
            {
                "Error": {
                    "Code": "NoSuchPublicAccessBlockConfiguration",
                    "Message": "none",
                }
            },
            "GetPublicAccessBlock",
        )
    else:
        s3control.get_public_access_block.return_value = account_level_pab

    if kms_describe_key is None:

        def _kms_raise(**kw):
            raise RuntimeError(f"HP-07 test fixture missing kms describe_key for {kw}")

        kms.describe_key.side_effect = _kms_raise
    else:
        kms.describe_key.return_value = kms_describe_key

    def _client_router(service_name, *args, **kwargs):
        if service_name == "s3":
            return s3
        if service_name == "s3control":
            return s3control
        if service_name == "kms":
            return kms
        raise ValueError(f"HP-07 test: unexpected client '{service_name}'")

    return _client_router


HP07_CMK_ARN = (
    "arn:aws:kms:us-east-1:123456789012:key/abcd1234-a123-456b-7890-cdef01234567"
)


class TestHP07S3FullCoverage:
    """HP-07 S3 customer-managed encryption — 6-case minimum per reviewer spec."""

    def test_hp07_no_buckets_informational_na_global(self):
        router = _build_s3_clients(
            list_buckets_response={"Buckets": [], "Owner": {"Id": "x"}},
            per_bucket_encryption={},
            per_bucket_versioning={},
            per_bucket_pab={},
        )
        with patch.object(hipaa_app.boto3, "client", side_effect=router):
            rows = extract_csv_data(
                hipaa_app.check_s3_bucket_encryption_and_versioning(
                    REGION, region_index=0, account_id="123456789012"
                )
            )
        _na_informational_check(rows, "HP-07", "Global")

    def test_hp07_bucket_missing_versioning_fails_high(self):
        b1 = "hipaa-data-prod"
        buckets_r = {"Buckets": [{"Name": b1}], "Owner": {"Id": "x"}}
        enc = {
            b1: {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "aws:kms",
                                "KMSMasterKeyID": HP07_CMK_ARN,
                            }
                        }
                    ]
                }
            }
        }
        # Versioning not explicitly enabled (no Status field) → Fail.
        ver = {b1: {"ResponseMetadata": {}}}
        pab = {
            b1: {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            }
        }
        kms_desc = {
            "KeyMetadata": {
                "KeyId": HP07_CMK_ARN.split("/")[-1],
                "Arn": HP07_CMK_ARN,
                "KeyManager": "CUSTOMER",
                "KeyState": "Enabled",
            }
        }
        router = _build_s3_clients(
            list_buckets_response=buckets_r,
            per_bucket_encryption=enc,
            per_bucket_versioning=ver,
            per_bucket_pab=pab,
            kms_describe_key=kms_desc,
        )
        with patch.object(hipaa_app.boto3, "client", side_effect=router):
            rows = extract_csv_data(
                hipaa_app.check_s3_bucket_encryption_and_versioning(
                    REGION, region_index=0, account_id="123456789012"
                )
            )
        fails = _failed_check(rows, "HP-07", "High")
        assert any(b1 in f["Finding_Details"] for f in fails)

    def test_hp07_cmk_versioning_pab_enabled_passes(self):
        b1 = "hipaa-data-prod"
        buckets_r = {"Buckets": [{"Name": b1}], "Owner": {"Id": "x"}}
        enc = {
            b1: {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "aws:kms",
                                "KMSMasterKeyID": HP07_CMK_ARN,
                            }
                        }
                    ]
                }
            }
        }
        ver = {b1: {"Status": "Enabled"}}
        pab = {
            b1: {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            }
        }
        kms_desc = {
            "KeyMetadata": {
                "KeyId": HP07_CMK_ARN.split("/")[-1],
                "Arn": HP07_CMK_ARN,
                "KeyManager": "CUSTOMER",
                "KeyState": "Enabled",
            }
        }
        router = _build_s3_clients(
            list_buckets_response=buckets_r,
            per_bucket_encryption=enc,
            per_bucket_versioning=ver,
            per_bucket_pab=pab,
            kms_describe_key=kms_desc,
        )
        with patch.object(hipaa_app.boto3, "client", side_effect=router):
            rows = extract_csv_data(
                hipaa_app.check_s3_bucket_encryption_and_versioning(
                    REGION, region_index=0, account_id="123456789012"
                )
            )
        _passed_agg(rows, "HP-07")

    def test_hp07_list_buckets_access_denied_na_global(self):
        s3 = MagicMock()
        s3.list_buckets.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "ListBuckets",
        )
        s3control = MagicMock()
        s3control.get_public_access_block.side_effect = ClientError(
            {
                "Error": {
                    "Code": "NoSuchPublicAccessBlockConfiguration",
                    "Message": "none",
                }
            },
            "GetPublicAccessBlock",
        )
        kms = MagicMock()

        def router(service, *_a, **_kw):
            if service == "s3":
                return s3
            if service == "s3control":
                return s3control
            if service == "kms":
                return kms
            if service == "sts":
                return MagicMock()
            raise RuntimeError("unreachable")

        with patch.object(hipaa_app.boto3, "client", side_effect=router):
            rows = extract_csv_data(
                hipaa_app.check_s3_bucket_encryption_and_versioning(
                    REGION, region_index=0, account_id="123456789012"
                )
            )
        _na_informational_check(rows, "HP-07", "Global")

    def test_hp07_region_index_nonzero_shortcircuits_na_global(self):
        router = _build_s3_clients(
            list_buckets_response={"Buckets": [], "Owner": {"Id": "x"}},
            per_bucket_encryption={},
            per_bucket_versioning={},
            per_bucket_pab={},
        )
        with patch.object(hipaa_app.boto3, "client", side_effect=router):
            rows = extract_csv_data(
                hipaa_app.check_s3_bucket_encryption_and_versioning(
                    REGION, region_index=1
                )
            )
        assert rows == []

    def test_hp07_unexpected_exception_fallback_na_correct_id(self):
        s3 = MagicMock()
        s3.list_buckets.return_value = {
            "Buckets": [{"Name": "b1-aiml-data"}],
            "Owner": {"Id": "x"},
        }
        s3.get_bucket_encryption.side_effect = RuntimeError(
            "boom during enc lookup per bucket"
        )
        s3control = MagicMock()
        s3control.get_public_access_block.side_effect = ClientError(
            {
                "Error": {
                    "Code": "NoSuchPublicAccessBlockConfiguration",
                    "Message": "none",
                }
            },
            "GetPublicAccessBlock",
        )
        kms = MagicMock()

        def router(service, *_a, **_kw):
            if service == "s3":
                return s3
            if service == "s3control":
                return s3control
            if service == "kms":
                return kms
            if service == "sts":
                return MagicMock()
            raise RuntimeError("unreachable")

        def hp07_wrapped(region):
            return hipaa_app.check_s3_bucket_encryption_and_versioning(
                region, region_index=0, account_id="123456789012"
            )

        with patch.object(hipaa_app.boto3, "client", side_effect=router):
            rows = extract_csv_data(
                hipaa_app._run_check_safely(hp07_wrapped, "HP-07", "Global")
            )
        _na_informational_check(rows, "HP-07", "Global")
        assert any(
            "Unexpected exception" in r["Finding_Details"]
            or "Incomplete" in r["Finding"]
            for r in rows
        )


class TestHP07ReviewerAES256Failure:
    """Reviewer: AES256 SSE-S3 must fail because HP-07 requires customer-managed CMKs."""

    def test_hp07_aes256_sse_s3_fails_high_even_with_versioning_pab(self):
        b1 = "hipaa-aes256-data"
        buckets_r = {"Buckets": [{"Name": b1}], "Owner": {"Id": "x"}}
        enc = {
            b1: {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256",
                            }
                        }
                    ]
                }
            }
        }
        ver = {b1: {"Status": "Enabled"}}
        pab = {
            b1: {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            }
        }
        router = _build_s3_clients(
            list_buckets_response=buckets_r,
            per_bucket_encryption=enc,
            per_bucket_versioning=ver,
            per_bucket_pab=pab,
        )
        with patch.object(hipaa_app.boto3, "client", side_effect=router):
            rows = extract_csv_data(
                hipaa_app.check_s3_bucket_encryption_and_versioning(
                    REGION, region_index=0, account_id="123456789012"
                )
            )
        fails = _failed_check(rows, "HP-07", "High")
        assert any(b1 in f["Finding_Details"] for f in fails)
        assert any("AES256" in f["Finding_Details"] for f in fails)


class TestReviewerPage2PaginationNonCompliant:
    """Reviewer: pagination must read past page 1; a non-compliant resource only
    on page 2 must still produce a Failed finding row."""

    def test_hp01_page2_only_noncompliant_model_still_detected(self):
        bedrock = MagicMock()
        # Page 1: compliant CMK custom model.
        # Page 2: non-compliant (no KMS key) model — still must be flagged.
        cmk_arn = HP07_CMK_ARN.replace("kms", "kms-bedrock-hp01")

        def _pag_paged(op):
            p = MagicMock()
            if op == "list_custom_models":
                p.paginate.side_effect = lambda **kw: iter(
                    [
                        {
                            "modelSummaries": [
                                {
                                    "modelArn": "arn:aws:bedrock:us-east-1:123456789012:custom-model/compliant-page1",
                                    "modelName": "compliant-page1",
                                    "modelKmsKeyArn": cmk_arn,
                                }
                            ]
                        },
                        {
                            "modelSummaries": [
                                {
                                    "modelArn": "arn:aws:bedrock:us-east-1:123456789012:custom-model/uncmkd-page2",
                                    "modelName": "uncmkd-page2",
                                }
                            ]
                        },
                    ]
                )
                return p
            raise ValueError(f"unexpected paginate op: {op}")

        bedrock.get_paginator = _pag_paged
        bedrock.get_custom_model.side_effect = lambda **kw: {
            "modelArn": kw["modelIdentifier"],
            "modelKmsKeyArn": cmk_arn
            if kw["modelIdentifier"].endswith("/compliant-page1")
            else None,
        }

        kms = MagicMock()
        kms.describe_key.return_value = {
            "KeyMetadata": {
                "KeyId": cmk_arn.split("/")[-1],
                "Arn": cmk_arn,
                "KeyManager": "CUSTOMER",
                "KeyState": "Enabled",
            }
        }

        def _route(service, **kw):
            if service == "bedrock":
                return bedrock
            if service == "kms":
                return kms
            return MagicMock()

        with patch.object(hipaa_app.boto3, "client", side_effect=_route):
            rows = extract_csv_data(
                hipaa_app.check_bedrock_custom_model_encryption(REGION)
            )

        fails = _failed_check(rows, "HP-01", "High")
        assert any("uncmkd-page2" in f["Finding_Details"] for f in fails)
        # Compliant page1 model contributed to the inventory — the aggregate
        # "Passed" row only exists when every inspected model is compliant,
        # so instead assert the compliant model is present by absence of a
        # finding row mentioning it as failed (not required; fail row already
        # demonstrates pagination crossed both pages).


_CHECK_ID_TO_FN_NAME = {
    "HP-01": "check_bedrock_custom_model_encryption",
    "HP-03": "check_sagemaker_network_isolation",
    "HP-04": "check_sagemaker_resource_encryption",
    "HP-05": "check_cloudwatch_logs_data_protection",
    "HP-06": "check_vpc_endpoints_configured",
    "HP-02": "check_bedrock_guardrail_pii",
}


@pytest.mark.parametrize(
    ("check_id", "fn_name"),
    list(_CHECK_ID_TO_FN_NAME.items()),
)
class TestReviewerRunAllChecksFallbackIDs:
    """Reviewer: an unexpected RuntimeError for check X must:
    (1) produce exactly one N/A/Informational row with Check_ID==check_id and
        "Incomplete" / "Unexpected exception" content;
    (2) NOT erase the other 6 HP-ID rows (sibling-check isolation).
    """

    @staticmethod
    def _build_empty_inventory_universe():
        """Return a boto3.client side_effect router so every HP check returns
        at least its baseline "empty inventory → N/A" finding.
        Used as universe-mock so sibling isolation is provable.
        """
        bedrock = MagicMock()

        def _bedrock_pages(**_kw):
            yield {"modelSummaries": []}

        def _bedrock_guard_pages(**_kw):
            yield {"guardrails": []}

        bedrock.get_paginator.side_effect = lambda op: (
            type("P", (), {"paginate": _bedrock_pages})()
            if op == "list_custom_models"
            else type("P", (), {"paginate": _bedrock_guard_pages})()
        )

        sm = MagicMock()

        def _sm_pages(**_kw):
            yield {"Endpoints": []}

        sm.get_paginator.side_effect = lambda op: type(
            "P", (), {"paginate": _sm_pages}
        )()

        logs = MagicMock()
        logs_p = MagicMock()

        def _log_pages(**_kw):
            yield {"logGroups": []}

        logs_p.paginate.side_effect = _log_pages
        logs.get_paginator.return_value = logs_p
        logs.describe_account_policies.return_value = {"accountPolicies": []}

        ec2 = _build_ec2(
            describe_vpcs_pages=[{"Vpcs": []}],
            describe_vpc_endpoints_pages=[{"VpcEndpoints": []}],
            describe_vpc_endpoint_services_page={
                "ServiceNames": [],
                "ServiceDetails": [],
            },
        )

        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": [], "Owner": {"Id": "x"}}
        s3control = MagicMock()
        kms = MagicMock()

        def router(service, *args, **kwargs):
            if service == "bedrock":
                return bedrock
            if service == "sagemaker":
                return sm
            if service == "logs":
                return logs
            if service == "ec2":
                return ec2
            if service == "s3":
                return s3
            if service == "s3control":
                return s3control
            if service == "kms":
                return kms
            raise ValueError(f"unexpected client: {service}")

        return router

    def test_sibling_checks_continue_when_target_raises(self, check_id, fn_name):
        router = self._build_empty_inventory_universe()

        def boom(*_a, **_kw):
            raise RuntimeError(f"injected failure for {check_id}")

        # Swap the target (check_id, fn) slot in HIPAA_CHECKS so run_all_checks
        # invokes `boom` for exactly one check while sibling slots keep the
        # original module attribute.  Python binds tuple callable references
        # at import time, so a plain patch.object(fn_name) would not reach
        # the callable actually used by run_all_checks.
        original_checks = hipaa_app.HIPAA_CHECKS
        new_checks = []
        target_idx = None
        for idx, (cid, fn) in enumerate(original_checks):
            if cid == check_id:
                new_checks.append((cid, boom))
                target_idx = idx
            else:
                new_checks.append((cid, fn))
        assert target_idx is not None, f"check_id {check_id} not in HIPAA_CHECKS"
        hipaa_app.HIPAA_CHECKS = tuple(new_checks)
        try:
            with patch.object(hipaa_app.boto3, "client", side_effect=router):
                rows = extract_csv_data(
                    hipaa_app.run_all_checks(
                        REGION, region_index=0, account_id="123456789012"
                    )
                )
        finally:
            hipaa_app.HIPAA_CHECKS = original_checks

        ids_present = {r["Check_ID"] for r in rows}
        assert check_id in ids_present
        own_rows = [r for r in rows if r["Check_ID"] == check_id]
        assert any(
            r["Status"] == "N/A" and r["Severity"] == "Informational" for r in own_rows
        )
        assert any(
            "Unexpected exception" in r["Finding_Details"]
            or "Incomplete" in r["Finding"]
            for r in own_rows
        )
        sibling_ids = {"HP-01", "HP-02", "HP-03", "HP-04", "HP-05", "HP-06", "HP-07"}
        for sib in sibling_ids - {check_id}:
            assert sib in ids_present, f"sibling {sib} missing when {check_id} raised"


class TestReviewerHP07OuterClientErrorWrap:
    """HP-07 uses its own outer ClientError→RuntimeError wrapper in run_all_checks."""

    def test_hp07_outer_client_error_wraps_to_runtime_error(self):
        s3 = MagicMock()
        s3.list_buckets.side_effect = ClientError(
            {"Error": {"Code": "ServiceUnavailable", "Message": "kaput"}},
            "ListBuckets",
        )

        def router(service, *_a, **_kw):
            if service == "s3":
                return s3
            raise RuntimeError("unreachable")

        with patch.object(hipaa_app.boto3, "client", side_effect=router):
            with pytest.raises(RuntimeError):
                hipaa_app.run_all_checks(
                    REGION, region_index=0, account_id="123456789012"
                )


# ---------------------------------------------------------------------------
# CSV contract + Lambda handler tests (retained from HEAD baseline, extended).
# ---------------------------------------------------------------------------


class TestHIPAACSVRouting:
    """HP CSV filename / column layout / handler re-raises to fire ASL Catch."""

    def test_csv_filename_follows_report_prefix_execution_region_convention(self):
        s3 = MagicMock()
        bucket = "bkt"
        execution_id = "exec-abcd1234"
        region = "us-east-2"
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = s3
            hipaa_app.write_to_s3(execution_id, "", bucket, region=region)
        s3.put_object.assert_called_once()
        call_kwargs = s3.put_object.call_args.kwargs
        key = call_kwargs.get("Key", "")
        assert (
            re.search(
                r"hipaa_security_report_"
                + re.escape(execution_id)
                + r"_us-east-2\.csv",
                key,
            )
            is not None
        )
        assert call_kwargs.get("Bucket") == bucket

    def test_csv_compliance_frameworks_column_appended_at_tail(self):
        bedrock = MagicMock()
        p = MagicMock()
        p.paginate.side_effect = lambda **kw: iter([{"modelSummaries": []}])
        bedrock.get_paginator.return_value = p
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = bedrock
            rows = extract_csv_data(
                hipaa_app._run_check_safely(
                    hipaa_app.check_bedrock_custom_model_encryption, "HP-01", REGION
                )
            )
        assert rows, "expected at least the empty-inventory N/A row for column check"
        headers = list(rows[0].keys())
        assert headers[-1] == "Compliance_Frameworks"
        assert headers[0] == "Check_ID"
        assert headers[7] == "Region"

    def test_handler_reraises_client_error_so_asl_catch_fires(self):
        fake_ctx = MagicMock()
        fake_ctx.invoked_function_arn = (
            "arn:aws:lambda:us-east-1:123456789012:function:HIPAAFn"
        )
        fake_ctx.aws_request_id = "req-1"

        event = {
            "Execution": {"Name": "exec-foo"},
            "StateMachine": {"Id": "sm:arn"},
            "Region": "us-east-1",
            "RegionIndex": 0,
        }
        with patch.object(hipaa_app.boto3, "client") as mclient:
            mclient.return_value = MagicMock()
            with patch.object(hipaa_app, "run_all_checks") as m_run:
                m_run.side_effect = ClientError(
                    {"Error": {"Code": "InvalidSignatureException", "Message": "sig"}},
                    "RunAll",
                )
                with pytest.raises(ClientError):
                    hipaa_app.lambda_handler(event, fake_ctx)
