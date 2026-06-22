"""
Integration tests for the lambda_handler in finserv_assessments/app.py

These tests verify:
  - lambda_handler runs end-to-end with all checks mocked
  - Response structure (statusCode, body, findings, report_url)
  - All 59 standalone check functions are called (5 merged upstream)
  - CSV is written to S3
  - Error handling when AIML_ASSESSMENT_BUCKET_NAME is missing
  - Error handling when S3 write fails
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from .support import finserv_app as app


# =========================================================================
# Full handler smoke test — all boto3 calls mocked
# =========================================================================


class TestLambdaHandler:
    """End-to-end handler tests with fully mocked AWS clients."""

    @patch("finserv_app.write_to_s3")
    @patch("finserv_app.get_permissions_cache")
    @patch("finserv_app.boto3.client")
    def test_handler_returns_200(self, mock_client, mock_cache, mock_s3, lambda_event):
        """Smoke test: handler completes and returns 200."""
        # Return a generic mock for every boto3 client
        generic = MagicMock()
        # Make paginators return empty pages
        paginator = MagicMock()
        paginator.paginate.return_value = [{}]
        generic.get_paginator.return_value = paginator
        # Make list/describe calls return empty collections
        generic.list_web_acls.return_value = {"WebACLs": []}
        generic.describe_subscription.side_effect = Exception("no shield")
        generic.get_usage_plans.return_value = {"items": []}
        generic.list_service_quotas.return_value = {"Quotas": []}
        generic.get_anomaly_monitors.return_value = {"AnomalyMonitors": []}
        generic.describe_budgets.return_value = {"Budgets": []}
        generic.get_caller_identity.return_value = {"Account": "123456789012"}
        generic.list_agents.return_value = {"agentSummaries": []}
        generic.list_agent_runtimes.return_value = {"agentRuntimes": []}
        generic.list_functions.return_value = {"Functions": []}
        generic.list_state_machines.return_value = {"stateMachines": []}
        generic.list_policies.return_value = {"Policies": []}
        generic.list_custom_models.return_value = {"modelSummaries": []}
        generic.list_models.return_value = {"Models": []}
        generic.describe_config_rules.return_value = {"ConfigRules": []}
        generic.list_evaluation_jobs.return_value = {"jobSummaries": []}
        generic.describe_repositories.return_value = {"repositories": []}
        generic.list_feature_groups.return_value = {"FeatureGroupSummaries": []}
        generic.list_buckets.return_value = {"Buckets": []}
        generic.list_knowledge_bases.return_value = {"knowledgeBaseSummaries": []}
        generic.list_guardrails.return_value = {"guardrails": []}
        generic.list_log_groups.return_value = {"logGroups": []}
        generic.get_macie_session.side_effect = Exception("not enabled")
        generic.list_foundation_models.return_value = {"modelSummaries": []}
        generic.list_model_cards.return_value = {"ModelCardSummaries": []}
        generic.list_rules.return_value = {"Rules": []}
        generic.list_schedules.return_value = {"Schedules": []}
        generic.get_rest_apis.return_value = {"items": []}
        generic.list_processing_jobs.return_value = {"ProcessingJobSummaries": []}
        generic.list_automated_reasoning_policies.return_value = {
            "automatedReasoningPolicySummaries": []
        }

        mock_client.return_value = generic
        mock_cache.return_value = {"role_permissions": {}, "user_permissions": {}}
        mock_s3.return_value = "https://test-bucket.s3.amazonaws.com/finserv_security_report_unit-test-001.csv"

        result = app.lambda_handler(lambda_event, None)

        assert result["statusCode"] == 200
        assert "findings" in result["body"]
        assert "report_url" in result["body"]
        assert isinstance(result["body"]["findings"], list)
        # The handler runs 65 registry entries (64 standalone checks + the new
        # FS-27 ARC policies check that shares the FS-27 check_id).
        assert len(result["body"]["findings"]) == 65

    @patch("finserv_app.write_to_s3")
    @patch("finserv_app.get_permissions_cache")
    @patch("finserv_app.boto3.client")
    def test_handler_findings_all_have_check_name(
        self, mock_client, mock_cache, mock_s3, lambda_event
    ):
        """Every finding dict should have check_name and status keys."""
        generic = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{}]
        generic.get_paginator.return_value = paginator
        generic.list_web_acls.return_value = {"WebACLs": []}
        generic.describe_subscription.side_effect = Exception("no shield")
        generic.get_usage_plans.return_value = {"items": []}
        generic.list_service_quotas.return_value = {"Quotas": []}
        generic.get_anomaly_monitors.return_value = {"AnomalyMonitors": []}
        generic.describe_budgets.return_value = {"Budgets": []}
        generic.get_caller_identity.return_value = {"Account": "123456789012"}
        generic.list_agents.return_value = {"agentSummaries": []}
        generic.list_agent_runtimes.return_value = {"agentRuntimes": []}
        generic.list_functions.return_value = {"Functions": []}
        generic.list_state_machines.return_value = {"stateMachines": []}
        generic.list_policies.return_value = {"Policies": []}
        generic.list_custom_models.return_value = {"modelSummaries": []}
        generic.list_models.return_value = {"Models": []}
        generic.describe_config_rules.return_value = {"ConfigRules": []}
        generic.list_evaluation_jobs.return_value = {"jobSummaries": []}
        generic.describe_repositories.return_value = {"repositories": []}
        generic.list_feature_groups.return_value = {"FeatureGroupSummaries": []}
        generic.list_buckets.return_value = {"Buckets": []}
        generic.list_knowledge_bases.return_value = {"knowledgeBaseSummaries": []}
        generic.list_guardrails.return_value = {"guardrails": []}
        generic.list_log_groups.return_value = {"logGroups": []}
        generic.get_macie_session.side_effect = Exception("not enabled")
        generic.list_foundation_models.return_value = {"modelSummaries": []}
        generic.list_model_cards.return_value = {"ModelCardSummaries": []}
        generic.list_rules.return_value = {"Rules": []}
        generic.list_schedules.return_value = {"Schedules": []}
        generic.get_rest_apis.return_value = {"items": []}
        generic.list_processing_jobs.return_value = {"ProcessingJobSummaries": []}
        generic.list_automated_reasoning_policies.return_value = {
            "automatedReasoningPolicySummaries": []
        }

        mock_client.return_value = generic
        mock_cache.return_value = {"role_permissions": {}, "user_permissions": {}}
        mock_s3.return_value = "https://test-bucket.s3.amazonaws.com/report.csv"

        result = app.lambda_handler(lambda_event, None)

        for finding in result["body"]["findings"]:
            assert "check_name" in finding, f"Missing check_name in {finding}"
            assert "status" in finding, f"Missing status in {finding}"
            assert finding["status"] in ("PASS", "WARN", "ERROR"), (
                f"Unexpected status '{finding['status']}' in {finding['check_name']}"
            )
            assert "csv_data" in finding

    def test_handler_raises_without_bucket_env(self, lambda_event, monkeypatch):
        """Handler should raise ValueError when AIML_ASSESSMENT_BUCKET_NAME is unset."""
        monkeypatch.delenv("AIML_ASSESSMENT_BUCKET_NAME", raising=False)

        # We need to mock all boto3 calls so the checks themselves don't fail
        with (
            patch("finserv_app.boto3.client") as mock_client,
            patch("finserv_app.get_permissions_cache") as mock_cache,
        ):
            generic = MagicMock()
            paginator = MagicMock()
            paginator.paginate.return_value = [{}]
            generic.get_paginator.return_value = paginator
            # Set up enough mocks for checks to complete
            for attr in [
                "list_web_acls",
                "get_usage_plans",
                "list_service_quotas",
                "get_anomaly_monitors",
                "describe_budgets",
                "list_agents",
                "list_agent_runtimes",
                "list_functions",
                "list_state_machines",
                "list_policies",
                "list_custom_models",
                "list_models",
                "describe_config_rules",
                "list_evaluation_jobs",
                "describe_repositories",
                "list_feature_groups",
                "list_buckets",
                "list_knowledge_bases",
                "list_guardrails",
                "list_log_groups",
                "list_foundation_models",
                "list_model_cards",
                "list_rules",
                "get_rest_apis",
                "list_processing_jobs",
            ]:
                getattr(generic, attr).return_value = (
                    {"WebACLs": []}
                    if "acl" in attr.lower()
                    else {"items": []}
                    if "items" in attr.lower() or "rest_api" in attr.lower()
                    else {next(iter({})): []}
                    if False  # fallback
                    else {}
                )
            generic.describe_subscription.side_effect = Exception("no shield")
            generic.get_caller_identity.return_value = {"Account": "123456789012"}
            generic.get_macie_session.side_effect = Exception("not enabled")

            mock_client.return_value = generic
            mock_cache.return_value = {"role_permissions": {}, "user_permissions": {}}

            with pytest.raises(ValueError, match="AIML_ASSESSMENT_BUCKET_NAME"):
                app.lambda_handler(lambda_event, None)


class TestInventoryCollectedAndPassed:
    """Task 5.1 — Assert lambda_handler always collects and passes a real inventory.

    Guards against the default-None footgun: even though build_finserv_checks
    accepts inventory=None for backward-compat with the drift-guard, lambda_handler
    must always call collect_resource_inventory() and pass its return value.

    Validates: REQ-6.5
    """

    @patch("finserv_app.write_to_s3")
    @patch("finserv_app.get_permissions_cache")
    @patch("finserv_app.build_finserv_checks")
    @patch("finserv_app.collect_resource_inventory")
    def test_handler_calls_collect_inventory_exactly_once(
        self,
        mock_collect,
        mock_build,
        mock_cache,
        mock_s3,
        lambda_event,
    ):
        """lambda_handler calls collect_resource_inventory() exactly once per invocation."""
        fake_inventory = object()  # any sentinel — not None
        mock_collect.return_value = fake_inventory
        mock_build.return_value = []  # no checks to run
        mock_cache.return_value = {"role_permissions": {}, "user_permissions": {}}
        mock_s3.return_value = "https://bucket.s3.amazonaws.com/report.csv"

        app.lambda_handler(lambda_event, None)

        mock_collect.assert_called_once_with()

    @patch("finserv_app.write_to_s3")
    @patch("finserv_app.get_permissions_cache")
    @patch("finserv_app.build_finserv_checks")
    @patch("finserv_app.collect_resource_inventory")
    def test_handler_passes_inventory_to_build_finserv_checks(
        self,
        mock_collect,
        mock_build,
        mock_cache,
        mock_s3,
        lambda_event,
    ):
        """The return value of collect_resource_inventory() is passed as inventory=
        to build_finserv_checks, and it is never None."""
        fake_inventory = object()  # distinct sentinel
        mock_collect.return_value = fake_inventory
        mock_build.return_value = []
        mock_cache.return_value = {"role_permissions": {}, "user_permissions": {}}
        mock_s3.return_value = "https://bucket.s3.amazonaws.com/report.csv"

        app.lambda_handler(lambda_event, None)

        # build_finserv_checks must have been called with the real inventory
        mock_build.assert_called_once()
        call_args, call_kwargs = mock_build.call_args
        # inventory can be passed positionally or as a keyword argument
        passed_inventory = call_kwargs.get(
            "inventory", call_args[1] if len(call_args) > 1 else None
        )
        assert passed_inventory is fake_inventory, (
            "lambda_handler must pass the collect_resource_inventory() return value "
            f"to build_finserv_checks; got {passed_inventory!r}"
        )
        assert passed_inventory is not None, (
            "lambda_handler must never pass None as the inventory argument"
        )


class TestWriteToS3:
    """Test the write_to_s3 helper."""

    @patch("finserv_app.boto3.client")
    def test_writes_csv_to_s3(self, mock_client):
        s3 = MagicMock()
        mock_client.return_value = s3

        url = app.write_to_s3("exec-123", "col1,col2\nval1,val2", "my-bucket")

        s3.put_object.assert_called_once_with(
            Bucket="my-bucket",
            Key="finserv_security_report_exec-123.csv",
            Body="col1,col2\nval1,val2",
            ContentType="text/csv",
        )
        assert "my-bucket" in url
        assert "exec-123" in url

    @patch("finserv_app.boto3.client")
    def test_s3_error_propagates(self, mock_client):
        s3 = MagicMock()
        s3.put_object.side_effect = RuntimeError("S3 write failed")
        mock_client.return_value = s3

        with pytest.raises(RuntimeError, match="S3 write failed"):
            app.write_to_s3("exec-123", "data", "my-bucket")


class TestGetPermissionsCache:
    """Test the get_permissions_cache helper."""

    @patch("finserv_app.boto3.client")
    def test_returns_parsed_json(self, mock_client):
        s3 = MagicMock()
        body = MagicMock()
        body.read.return_value = json.dumps({"role_permissions": {"r1": {}}}).encode()
        s3.get_object.return_value = {"Body": body}
        mock_client.return_value = s3

        result = app.get_permissions_cache("exec-123")
        assert result == {"role_permissions": {"r1": {}}}

    @patch("finserv_app.boto3.client")
    def test_returns_none_on_client_error(self, mock_client):
        from botocore.exceptions import ClientError

        s3 = MagicMock()
        s3.get_object.side_effect = ClientError(
            {"Error": {"Code": "NoSuchKey", "Message": "Not found"}},
            "GetObject",
        )
        mock_client.return_value = s3

        result = app.get_permissions_cache("exec-123")
        assert result is None

    @patch("finserv_app.boto3.client")
    def test_returns_none_on_unexpected_error(self, mock_client):
        s3 = MagicMock()
        s3.get_object.side_effect = RuntimeError("unexpected")
        mock_client.return_value = s3

        result = app.get_permissions_cache("exec-123")
        assert result is None


# =========================================================================
# Importability smoke test — all 59 check functions are importable
# =========================================================================


class TestAllCheckFunctionsImportable:
    """Verify every check function referenced in lambda_handler is importable."""

    EXPECTED_CHECK_FUNCTIONS = [
        "check_waf_shield_on_bedrock_endpoints",
        "check_api_gateway_rate_limiting",
        "check_bedrock_token_quotas",
        "check_cost_anomaly_detection",
        "check_cloudwatch_token_alarms",
        "check_aws_budgets_for_aiml",
        "check_bedrock_agent_action_boundaries",
        "check_agentcore_policy_engine",
        "check_agent_transaction_limits",
        "check_human_in_the_loop_for_high_risk_actions",
        "check_agent_rate_alarms",
        "check_scp_model_access_restrictions",
        "check_model_inventory_tagging",
        "check_model_onboarding_governance",
        "check_bedrock_model_evaluation_adversarial",
        "check_ecr_image_scanning",
        "check_feature_store_rollback_capability",
        "check_training_data_s3_versioning",
        "check_knowledge_base_iam_least_privilege",
        "check_knowledge_base_metadata_filtering",
        "check_opensearch_serverless_encryption",
        "check_knowledge_base_vpc_access",
        # FS-27 is now two separate functions: contextual grounding + ARC policies
        "check_guardrail_contextual_grounding",
        "check_automated_reasoning_policies",
        "check_guardrail_denied_topics_financial",
        "check_compliance_disclaimer_in_outputs",
        "check_bedrock_evaluation_compliance_datasets",
        "check_knowledge_base_data_source_sync",
        "check_source_attribution_in_guardrails",
        "check_knowledge_base_integrity_monitoring",
        "check_fm_version_currency",
        "check_fmeval_harmful_content",
        "check_guardrail_content_filters",
        "check_user_feedback_mechanism",
        "check_guardrail_word_filters",
        "check_sagemaker_clarify_bias",
        "check_bedrock_evaluation_bias_datasets",
        "check_sagemaker_clarify_explainability",
        "check_ai_service_cards_documentation",
        "check_cloudwatch_log_pii_masking",
        "check_macie_on_training_data_buckets",
        "check_guardrail_pii_filters",
        "check_data_classification_tagging",
        "check_guardrail_grounding_threshold",
        "check_rag_knowledge_base_configured",
        "check_hallucination_disclaimer_advisory",
        # FS-50 renamed from check_automated_reasoning_checks_hallucination
        "check_guardrail_relevance_grounding",
        "check_prompt_injection_input_validation",
        "check_bedrock_sdk_version_currency",
        "check_waf_sql_injection_rules",
        "check_penetration_testing_evidence",
        "check_output_validation_lambda",
        "check_xss_prevention_waf",
        "check_output_encoding_advisory",
        "check_output_schema_validation",
        "check_guardrail_topic_allowlist",
        "check_contextual_grounding_for_offtopic",
        "check_knowledge_base_sync_schedule",
        "check_data_currency_disclaimer_advisory",
        "check_foundation_model_lifecycle_policy",
        "check_kb_datasource_s3_event_notifications",
        "check_agentcore_end_user_identity_propagation",
        "check_agent_financial_transaction_thresholds",
        "check_api_gateway_request_body_size_limits",
        "check_prompt_input_validation_function",
    ]

    @pytest.mark.parametrize("func_name", EXPECTED_CHECK_FUNCTIONS)
    def test_function_exists(self, func_name):
        assert hasattr(app, func_name), f"app.{func_name} not found"
        assert callable(getattr(app, func_name)), f"app.{func_name} is not callable"

    def test_expected_count(self):
        """Sanity check: 65 check functions (64 standalone + new ARC check sharing FS-27)."""
        assert len(self.EXPECTED_CHECK_FUNCTIONS) == 65
