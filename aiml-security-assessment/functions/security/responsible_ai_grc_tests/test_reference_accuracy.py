"""Remediation-reference and resolution-accuracy tests for the FS checks.

Pins the corrections from the 2026-11 reference audit: each listed check cites a
page about its own topic, resolution text no longer claims what the AWS docs
contradict, and FS-39 / FS-41 no longer fail an account only because it has no
SageMaker Clarify schedule (Clarify is closed to new customers).
"""

from __future__ import annotations

import importlib.util
import os
from unittest.mock import MagicMock, patch

import pytest

from .support import finserv_app as app
from .support import make_resource_inventory

DOCS = "https://docs.aws.amazon.com/"
_REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
)


def _references(result) -> set:
    return {row["Reference"] for row in result["csv_data"]}


def _blob(result) -> str:
    return " ".join(
        f"{row['Finding']} {row['Finding_Details']} {row['Resolution']}"
        for row in result["csv_data"]
    )


def _assert_only_reference(result, expected: str) -> None:
    assert result["csv_data"], "check emitted no rows"
    assert _references(result) == {expected}


def _guardrail_inventory():
    return make_resource_inventory(
        guardrails=app.GuardrailInventory(
            summaries=[{"id": "g1", "name": "example-guard"}],
            detail_by_id={"g1": {}},
        )
    )


# ---------------------------------------------------------------------------
# Wrong-topic references
# ---------------------------------------------------------------------------


class TestWrongTopicReferences:
    def test_fs54_cites_security_agent_penetration_test_page(self):
        result = app.check_penetration_testing_evidence()
        _assert_only_reference(
            result,
            DOCS + "securityagent/latest/userguide/perform-penetration-test.html",
        )
        assert "Resilience page" not in _blob(result)

    def test_fs58_cites_bedrock_structured_output(self):
        result = app.check_output_schema_validation(make_resource_inventory())
        _assert_only_reference(
            result, DOCS + "bedrock/latest/userguide/structured-output.html"
        )

    @patch("finserv_app.boto3.client")
    def test_fs46_cites_bucket_tagging_not_object_tagging(self, mock_client):
        c = MagicMock()
        c.get_bucket_tagging.return_value = {
            "TagSet": [{"Key": "Environment", "Value": "example"}]
        }
        mock_client.return_value = c
        inv = make_resource_inventory(buckets=[{"Name": "aiml-training-data"}])
        result = app.check_data_classification_tagging(inv)
        _assert_only_reference(
            result, DOCS + "AmazonS3/latest/userguide/buckets-tagging.html"
        )

    def test_fs37_cites_genai_lens_user_feedback(self):
        result = app.check_user_feedback_mechanism()
        _assert_only_reference(
            result,
            DOCS + "wellarchitected/latest/generative-ai-lens/genops01-bp02.html",
        )

    def test_fs22_failed_and_passed_rows_cite_identity_policy_examples(self):
        expected = (
            DOCS + "bedrock/latest/userguide/security_iam_id-based-policy-examples.html"
        )
        wildcard = {
            "role_permissions": {
                "KBRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "document": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "bedrock:*",
                                        "Resource": "*",
                                    }
                                ]
                            }
                        }
                    ],
                }
            }
        }
        failed = app.check_knowledge_base_iam_least_privilege(wildcard)
        assert {r["Status"] for r in failed["csv_data"]} == {"Failed"}
        _assert_only_reference(failed, expected)

        scoped = {
            "role_permissions": {
                "KBRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "document": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "s3:GetObject",
                                        "Resource": "arn:aws:s3:::example-bucket/*",
                                    }
                                ]
                            }
                        }
                    ],
                }
            }
        }
        passed = app.check_knowledge_base_iam_least_privilege(scoped)
        assert {r["Status"] for r in passed["csv_data"]} == {"Passed"}
        _assert_only_reference(passed, expected)


# ---------------------------------------------------------------------------
# Too-generic references replaced with the specific feature page
# ---------------------------------------------------------------------------


class TestSpecificReferences:
    @patch("finserv_app.boto3.client")
    def test_fs01_waf_rows_cite_rate_based_rules(self, mock_client):
        mock_client.return_value = MagicMock()  # Shield subscription present
        result = app.check_waf_shield_on_bedrock_endpoints(make_resource_inventory())
        waf_rows = [r for r in result["csv_data"] if "WAF" in r["Finding"]]
        assert waf_rows
        assert {r["Reference"] for r in waf_rows} == {
            DOCS + "waf/latest/developerguide/waf-rule-statement-type-rate-based.html"
        }

    @patch("finserv_app.boto3.client")
    def test_fs14_cites_custom_config_rules(self, mock_client):
        c = MagicMock()
        c.describe_config_rules.return_value = {"ConfigRules": []}
        mock_client.return_value = c
        result = app.check_model_onboarding_governance()
        _assert_only_reference(
            result,
            DOCS + "config/latest/developerguide/evaluate-config_develop-rules.html",
        )

    @pytest.mark.parametrize(
        "func_name",
        ["check_guardrail_denied_topics_financial", "check_guardrail_topic_allowlist"],
    )
    @pytest.mark.parametrize("with_guardrail", [False, True])
    def test_fs28_fs59_cite_denied_topics(self, func_name, with_guardrail):
        inv = _guardrail_inventory() if with_guardrail else make_resource_inventory()
        result = getattr(app, func_name)(inv)
        _assert_only_reference(
            result, DOCS + "bedrock/latest/userguide/guardrails-denied-topics.html"
        )

    @pytest.mark.parametrize("with_guardrail", [False, True])
    def test_fs38_cites_word_filters(self, with_guardrail):
        inv = _guardrail_inventory() if with_guardrail else make_resource_inventory()
        result = app.check_guardrail_word_filters(inv)
        _assert_only_reference(
            result, DOCS + "bedrock/latest/userguide/guardrails-word-filters.html"
        )

    @patch("finserv_app.boto3.client")
    def test_fs44_cites_automated_sensitive_data_discovery(self, mock_client):
        c = MagicMock()
        c.get_macie_session.return_value = {"status": "ENABLED"}
        c.get_automated_discovery_configuration.return_value = {"status": "DISABLED"}
        mock_client.return_value = c
        result = app.check_macie_on_training_data_buckets()
        assert "Failed" in {r["Status"] for r in result["csv_data"]}
        _assert_only_reference(result, DOCS + "macie/latest/user/discovery-asdd.html")

    def test_fs49_cites_contextual_grounding(self):
        result = app.check_hallucination_disclaimer_advisory()
        _assert_only_reference(
            result,
            DOCS
            + "bedrock/latest/userguide/guardrails-contextual-grounding-check.html",
        )

    @pytest.mark.parametrize(
        "functions",
        [
            [],
            [{"FunctionName": "bedrock-handler", "Runtime": "python2.7"}],
            [{"FunctionName": "bedrock-handler", "Runtime": "python3.13"}],
        ],
    )
    def test_fs52_cites_lambda_runtimes(self, functions):
        inv = make_resource_inventory(lambda_functions=functions)
        result = app.check_bedrock_sdk_version_currency(inv)
        _assert_only_reference(result, DOCS + "lambda/latest/dg/lambda-runtimes.html")


# ---------------------------------------------------------------------------
# Resolution text that contradicted the AWS docs
# ---------------------------------------------------------------------------


class TestResolutionAccuracy:
    def test_fs53_does_not_claim_known_bad_inputs_covers_prompt_injection(self):
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(
                summaries=[{"Id": "acl-1", "Name": "example-acl"}],
                detail_by_id={"acl-1": {"Rules": []}},
            )
        )
        result = app.check_waf_sql_injection_rules(inv)
        rows = result["csv_data"]
        assert [r["Status"] for r in rows] == ["Failed"]
        resolution = rows[0]["Resolution"]
        assert "(prompt injection patterns)" not in resolution
        assert "does not detect prompt injection" in resolution
        _assert_only_reference(
            result,
            DOCS + "waf/latest/developerguide/aws-managed-rule-groups-use-case.html",
        )

    def test_fs29_does_not_claim_word_filters_detect_missing_disclaimers(self):
        result = app.check_compliance_disclaimer_in_outputs()
        resolution = result["csv_data"][0]["Resolution"]
        assert "omit required disclosures" not in resolution
        assert "cannot detect a missing disclaimer" in resolution


# ---------------------------------------------------------------------------
# FS-39 / FS-41 — SageMaker Clarify is closed to new customers
# ---------------------------------------------------------------------------

CLARIFY_CASES = [
    ("ModelBias", "check_sagemaker_clarify_bias", "FS-39"),
    ("ModelExplainability", "check_sagemaker_clarify_explainability", "FS-41"),
]


def _sagemaker(schedules):
    c = MagicMock()
    c.list_monitoring_schedules.return_value = {
        "MonitoringScheduleSummaries": schedules
    }
    return c


@pytest.mark.parametrize("monitoring_type,func_name,check_id", CLARIFY_CASES)
class TestClarifyAbsenceIsAdvisory:
    @pytest.mark.parametrize(
        "schedules",
        [
            [],
            [
                {
                    "MonitoringScheduleName": "quality-1",
                    "MonitoringType": "DataQuality",
                    "MonitoringScheduleStatus": "Scheduled",
                }
            ],
        ],
    )
    @patch("finserv_app.boto3.client")
    def test_no_clarify_schedule_is_na_informational(
        self, mock_client, schedules, monitoring_type, func_name, check_id
    ):
        mock_client.return_value = _sagemaker(schedules)
        result = getattr(app, func_name)()
        rows = result["csv_data"]
        assert len(rows) == 1
        row = rows[0]
        assert row["Check_ID"] == check_id
        assert row["Status"] == "N/A"
        assert row["Severity"] == "Informational"
        assert result["status"] != "WARN"
        assert "no longer open to new customers" in row["Finding_Details"]
        assert row["Reference"] == app.CLARIFY_AVAILABILITY_URL
        assert row["Reference"] == (
            DOCS + "sagemaker/latest/dg/clarify-availability-change.html"
        )
        assert app.SEVERITY_REGISTER[row["Finding"]] == "Informational"

    @patch("finserv_app.boto3.client")
    def test_stopped_schedule_still_fails_high(
        self, mock_client, monitoring_type, func_name, check_id
    ):
        mock_client.return_value = _sagemaker(
            [
                {
                    "MonitoringScheduleName": "sched-1",
                    "MonitoringType": monitoring_type,
                    "MonitoringScheduleStatus": "Stopped",
                }
            ]
        )
        result = getattr(app, func_name)()
        failed = [r for r in result["csv_data"] if r["Status"] == "Failed"]
        assert len(failed) == 1
        assert failed[0]["Severity"] == "High"
        assert result["status"] == "WARN"
        # No schedule is running, so nothing may be reported as Passed.
        assert [r["Status"] for r in result["csv_data"]] == ["Failed"]

    @patch("finserv_app.boto3.client")
    def test_mixed_schedules_pass_only_the_running_ones(
        self, mock_client, monitoring_type, func_name, check_id
    ):
        mock_client.return_value = _sagemaker(
            [
                {
                    "MonitoringScheduleName": "sched-running",
                    "MonitoringType": monitoring_type,
                    "MonitoringScheduleStatus": "Scheduled",
                },
                {
                    "MonitoringScheduleName": "sched-stopped",
                    "MonitoringType": monitoring_type,
                    "MonitoringScheduleStatus": "Stopped",
                },
            ]
        )
        rows = getattr(app, func_name)()["csv_data"]
        by_status = {r["Status"]: r for r in rows}
        assert sorted(by_status) == ["Failed", "Passed"]
        assert "sched-running" in by_status["Passed"]["Finding_Details"]
        assert "sched-stopped" not in by_status["Passed"]["Finding_Details"]
        assert "sched-stopped" in by_status["Failed"]["Finding_Details"]


@patch("finserv_app.boto3.client")
def test_fs41_schedule_rows_cite_feature_attribution_drift(mock_client):
    mock_client.return_value = _sagemaker(
        [
            {
                "MonitoringScheduleName": "sched-1",
                "MonitoringType": "ModelExplainability",
                "MonitoringScheduleStatus": "Scheduled",
            },
            {
                "MonitoringScheduleName": "sched-2",
                "MonitoringType": "ModelExplainability",
                "MonitoringScheduleStatus": "Stopped",
            },
        ]
    )
    result = app.check_sagemaker_clarify_explainability()
    assert {r["Status"] for r in result["csv_data"]} == {"Passed", "Failed"}
    _assert_only_reference(
        result,
        DOCS
        + "sagemaker/latest/dg/clarify-model-monitor-feature-attribution-drift.html",
    )


# ---------------------------------------------------------------------------
# FS-00 cites the primary normative source, at its current URL
# ---------------------------------------------------------------------------


def _load_generate_provenance():
    path = os.path.join(_REPO_ROOT, "generate_provenance.py")
    spec = importlib.util.spec_from_file_location("grc_generate_provenance", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fs00_cites_primary_grc_user_guide():
    row = app._no_regional_genai_resources_row("us-east-1")
    assert row["Reference"] == app.GRC_USER_GUIDE_URL
    assert row["Reference"] != app.FINSERV_GUIDE_URL
    provenance = _load_generate_provenance()
    assert provenance.PRIMARY_SOURCE["source_url"] == app.GRC_USER_GUIDE_URL
    assert provenance.SECONDARY_SOURCE["source_url"] == app.FINSERV_GUIDE_URL
    assert app.GRC_USER_GUIDE_URL.startswith(
        "https://d1.awsstatic.com/onedam/marketing-channels/website/aws/en_US/"
    )
