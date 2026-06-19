"""
Tests for all check functions in finserv_assessments/app.py

Strategy:
  - Every check function is tested for at least two scenarios:
    1. "PASS / N/A" path — mocked AWS responses indicate compliant state
    2. "WARN / FAIL" path — mocked AWS responses indicate non-compliant state
  - Advisory-only checks (no AWS API calls) are tested for correct structure
  - Functions that accept permission_cache are tested with both empty and
    populated caches
  - Every check is tested for graceful error handling (boto3 ClientError)

All boto3 clients are patched via unittest.mock so no real AWS calls are made.
"""

import json
import sys
import os
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

# Ensure finserv_assessments is importable
FINSERV_DIR = os.path.join(os.path.dirname(__file__), "..", "finserv_assessments")
if FINSERV_DIR not in sys.path:
    sys.path.insert(0, FINSERV_DIR)

# Ensure tests/ directory is importable (for conftest helpers)
TESTS_DIR = os.path.dirname(__file__)
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

import app  # noqa: E402  (import must follow sys.path setup above)
from conftest import make_resource_inventory  # noqa: E402


# =========================================================================
# Helpers
# =========================================================================


def _client_error(code="AccessDeniedException", message="Access Denied"):
    """Build a botocore ClientError for mocking."""
    return ClientError(
        {"Error": {"Code": code, "Message": message}},
        "TestOperation",
    )


def _assert_finding_structure(result):
    """Assert the standard check-function return dict shape."""
    assert "check_name" in result
    assert "status" in result
    assert result["status"] in ("PASS", "WARN", "ERROR")
    assert "csv_data" in result
    assert isinstance(result["csv_data"], list)
    for row in result["csv_data"]:
        assert "Check_ID" in row
        assert "Finding" in row
        assert "Severity" in row
        assert "Status" in row
        # Compliance_Frameworks must be present in every row (D3 fix)
        assert "Compliance_Frameworks" in row, (
            f"Missing Compliance_Frameworks in row for {row.get('Check_ID')}"
        )


def _assert_advisory_retag(result, check_id):
    """
    REQ-6 Option B: an advisory check must emit a finding with Status="N/A",
    Severity="Informational", and a Finding name prefixed "ADVISORY: ".
    (The wrapper result["status"] is separate and may still be "PASS".)
    """
    rows = [r for r in result["csv_data"] if r["Check_ID"] == check_id]
    assert rows, f"no rows for {check_id}"
    for r in rows:
        assert r["Status"] == "N/A", f"{check_id} Status={r['Status']}"
        assert r["Severity"] == "Informational", f"{check_id} Severity={r['Severity']}"
        assert r["Finding"].startswith("ADVISORY: "), (
            f"{check_id} Finding={r['Finding']}"
        )


# =========================================================================
# CATEGORY 1: UNBOUNDED CONSUMPTION (FS-01 to FS-06)
# =========================================================================


class TestFS01WafShield:
    """FS-01 — WAF and Shield Protection Check."""

    def test_pass_shield_enabled_acls_present(self):
        """Shield enabled + ACLs present via inventory → PASS."""
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(
                summaries=[{"Name": "acl1", "Id": "id1"}],
                detail_by_id={},
            )
        )
        with patch("app.boto3.client") as mock_client:
            shield_mock = MagicMock()
            shield_mock.describe_subscription.return_value = {}
            shield_mock.exceptions.ResourceNotFoundException = type(
                "ResourceNotFoundException", (ClientError,), {}
            )
            mock_client.return_value = shield_mock

            result = app.check_waf_shield_on_bedrock_endpoints(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"
        assert len(result["csv_data"]) == 2  # shield pass + waf pass
        # REQ-6: Shield Advanced findings are Low; WAF findings are Medium.
        shield_rows = [r for r in result["csv_data"] if "Shield" in r["Finding"]]
        waf_rows = [r for r in result["csv_data"] if "WAF" in r["Finding"]]
        assert shield_rows and all(r["Severity"] == "Low" for r in shield_rows)
        assert waf_rows and all(r["Severity"] == "Medium" for r in waf_rows)

    def test_severity_shield_low_waf_medium_on_fail(self):
        """REQ-6: Shield-absent = Low, WAF-absent = Medium (was both High)."""
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(summaries=[], detail_by_id={})
        )
        with patch("app.boto3.client") as mock_client:
            shield_mock = MagicMock()
            shield_mock.describe_subscription.side_effect = ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": ""}},
                "DescribeSubscription",
            )
            shield_mock.exceptions.ResourceNotFoundException = type(
                "ResourceNotFoundException", (ClientError,), {}
            )
            mock_client.return_value = shield_mock

            result = app.check_waf_shield_on_bedrock_endpoints(inv)
        _assert_finding_structure(result)
        assert any(
            r["Finding"] == "AWS Shield Advanced Not Enabled" and r["Severity"] == "Low"
            for r in result["csv_data"]
        )
        assert any(
            r["Finding"] == "No Regional WAF Web ACLs Found"
            and r["Severity"] == "Medium"
            for r in result["csv_data"]
        )

    def test_warn_no_shield_no_acls(self):
        """No shield + no ACLs in inventory → WARN."""
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(summaries=[], detail_by_id={})
        )
        with patch("app.boto3.client") as mock_client:
            shield_mock = MagicMock()
            shield_mock.describe_subscription.side_effect = ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": ""}},
                "DescribeSubscription",
            )
            shield_mock.exceptions.ResourceNotFoundException = type(
                "ResourceNotFoundException", (ClientError,), {}
            )
            mock_client.return_value = shield_mock

            result = app.check_waf_shield_on_bedrock_endpoints(inv)
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    def test_error_on_exception(self):
        """Unavailable inventory → COULD_NOT_ASSESS (ERROR envelope)."""
        inv = make_resource_inventory(web_acls=app._Unavailable(RuntimeError("boom")))
        with patch("app.boto3.client") as mock_client:
            shield_mock = MagicMock()
            shield_mock.describe_subscription.return_value = {}
            shield_mock.exceptions.ResourceNotFoundException = type(
                "ResourceNotFoundException", (ClientError,), {}
            )
            mock_client.return_value = shield_mock
            result = app.check_waf_shield_on_bedrock_endpoints(inv)
        assert result["status"] == "ERROR"
        assert "boom" in result["details"]

    def test_error_on_shield_exception(self):
        """Shield client raises → overall ERROR."""
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(summaries=[], detail_by_id={})
        )
        with patch("app.boto3.client") as mock_client:
            mock_client.side_effect = RuntimeError("boom")
            result = app.check_waf_shield_on_bedrock_endpoints(inv)
        assert result["status"] == "ERROR"
        assert "boom" in result["details"]

    # --- Pagination-correctness proof: >100 ACLs (Wave-3, task 8) ---
    def test_pass_more_than_100_acls(self):
        """Inventory with >100 ACLs (truncated in old code) → FS-01 PASS with correct count."""
        acls = [{"Name": f"acl{i}", "Id": f"id{i}"} for i in range(150)]
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(summaries=acls, detail_by_id={})
        )
        with patch("app.boto3.client") as mock_client:
            shield_mock = MagicMock()
            shield_mock.describe_subscription.return_value = {}
            shield_mock.exceptions.ResourceNotFoundException = type(
                "ResourceNotFoundException", (ClientError,), {}
            )
            mock_client.return_value = shield_mock
            result = app.check_waf_shield_on_bedrock_endpoints(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"
        waf_rows = [r for r in result["csv_data"] if "WAF" in r["Finding"]]
        assert waf_rows
        assert "150" in waf_rows[0]["Finding_Details"]

    # --- ≤1-page equivalence: 2-ACL case matches Wave-0 baseline ---
    def test_two_acl_case_unchanged(self):
        """The ≤1-page (2-ACL) case must produce the same finding as the pre-refactor baseline."""
        acls = [
            {"Name": "FinServACL1", "Id": "acl-id-001"},
            {"Name": "FinServACL2", "Id": "acl-id-002"},
        ]
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(summaries=acls, detail_by_id={})
        )
        with patch("app.boto3.client") as mock_client:
            shield_mock = MagicMock()
            shield_mock.describe_subscription.return_value = {}
            shield_mock.exceptions.ResourceNotFoundException = type(
                "ResourceNotFoundException", (ClientError,), {}
            )
            mock_client.return_value = shield_mock
            result = app.check_waf_shield_on_bedrock_endpoints(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"
        waf_rows = [r for r in result["csv_data"] if "WAF" in r["Finding"]]
        assert waf_rows
        assert waf_rows[0]["Finding"] == "Regional WAF Web ACLs Present"


class TestFS02ApiGatewayRateLimiting:
    """FS-02 — API Gateway Rate Limiting Check."""

    @patch("app.boto3.client")
    def test_pass_all_plans_have_throttle(self, mock_client):
        c = MagicMock()
        c.get_usage_plans.return_value = {
            "items": [
                {"name": "plan1", "throttle": {"rateLimit": 100, "burstLimit": 50}},
            ]
        }
        mock_client.return_value = c
        result = app.check_api_gateway_rate_limiting()
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    @patch("app.boto3.client")
    def test_warn_plan_missing_throttle(self, mock_client):
        c = MagicMock()
        c.get_usage_plans.return_value = {
            "items": [
                {"name": "no-throttle-plan", "throttle": {"rateLimit": 0}},
            ]
        }
        mock_client.return_value = c
        result = app.check_api_gateway_rate_limiting()
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    @patch("app.boto3.client")
    def test_no_plans_returns_na(self, mock_client):
        c = MagicMock()
        c.get_usage_plans.return_value = {"items": []}
        mock_client.return_value = c
        result = app.check_api_gateway_rate_limiting()
        _assert_finding_structure(result)
        # No plans → advisory finding, status stays PASS
        assert any(r["Status"] == "N/A" for r in result["csv_data"])

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("api error")
        result = app.check_api_gateway_rate_limiting()
        assert result["status"] == "ERROR"


class TestFS03BedrockTokenQuotas:
    """FS-03 — Bedrock Token Quota Review (value-based, paginated)."""

    @staticmethod
    def _sq_client(applied_quotas, default_quotas):
        """Build a service-quotas client mock with paginated applied + default quotas."""
        c = MagicMock()

        def get_paginator(op_name):
            paginator = MagicMock()
            if op_name == "list_service_quotas":
                paginator.paginate.return_value = [{"Quotas": applied_quotas}]
            elif op_name == "list_aws_default_service_quotas":
                paginator.paginate.return_value = [{"Quotas": default_quotas}]
            else:
                paginator.paginate.return_value = [{}]
            return paginator

        c.get_paginator.side_effect = get_paginator
        return c

    @patch("app.boto3.client")
    def test_pass_customized_quota(self, mock_client):
        # Applied value (200000) exceeds AWS default (100000) → customized → PASS/Passed
        applied = [
            {
                "QuotaName": "On-demand InvokeModel tokens per minute for anthropic.claude",
                "QuotaCode": "L-1234ABCD",
                "Value": 200000,
            }
        ]
        defaults = [{"QuotaCode": "L-1234ABCD", "Value": 100000}]
        mock_client.return_value = self._sq_client(applied, defaults)
        result = app.check_bedrock_token_quotas()
        _assert_finding_structure(result)
        assert result["status"] == "PASS"
        assert any(r["Status"] == "Passed" for r in result["csv_data"])

    @patch("app.boto3.client")
    def test_warn_default_quota(self, mock_client):
        # Applied value == AWS default → still at default → WARN/N-A (soft, not a failure)
        applied = [
            {
                "QuotaName": "On-demand InvokeModel tokens per minute for anthropic.claude",
                "QuotaCode": "L-1234ABCD",
                "Value": 100000,
            }
        ]
        defaults = [{"QuotaCode": "L-1234ABCD", "Value": 100000}]
        mock_client.return_value = self._sq_client(applied, defaults)
        result = app.check_bedrock_token_quotas()
        _assert_finding_structure(result)
        assert result["status"] == "WARN"
        assert any(r["Status"] == "N/A" for r in result["csv_data"])
        # At-default is NOT a failure.
        assert not any(r["Status"] == "Failed" for r in result["csv_data"])

    @patch("app.boto3.client")
    def test_token_only_no_rpm(self, mock_client):
        # Only token-based quotas present (no "request"/RPM quota). RPM is deprecated
        # on bedrock-runtime; its absence must not drive a Failed verdict.
        applied = [
            {
                "QuotaName": "Model invocation max tokens per day for anthropic.claude",
                "QuotaCode": "L-TPDAY01",
                "Value": 5000000,
            }
        ]
        defaults = [{"QuotaCode": "L-TPDAY01", "Value": 1000000}]
        mock_client.return_value = self._sq_client(applied, defaults)
        result = app.check_bedrock_token_quotas()
        _assert_finding_structure(result)
        # Customized token quota → PASS, regardless of any RPM quota existing.
        assert result["status"] == "PASS"

    @patch("app.boto3.client")
    def test_empty_applied_quotas(self, mock_client):
        # No token quotas returned at all → WARN/Failed + explanatory details.
        mock_client.return_value = self._sq_client([], [])
        result = app.check_bedrock_token_quotas()
        _assert_finding_structure(result)
        assert result["status"] == "WARN"
        assert any(r["Status"] == "Failed" for r in result["csv_data"])
        assert any(
            "No Bedrock token-based service quotas" in r["Finding_Details"]
            for r in result["csv_data"]
        )

    @patch("app.boto3.client")
    def test_default_lookup_fail(self, mock_client):
        # Applied token quotas exist but defaults could not be retrieved →
        # WARN/Failed + "undetermined" (NOT a silent value-vs-itself comparison).
        applied = [
            {
                "QuotaName": "On-demand InvokeModel tokens per minute for anthropic.claude",
                "QuotaCode": "L-1234ABCD",
                "Value": 100000,
            }
        ]
        mock_client.return_value = self._sq_client(applied, [])
        result = app.check_bedrock_token_quotas()
        _assert_finding_structure(result)
        assert result["status"] == "WARN"
        assert any(r["Status"] == "Failed" for r in result["csv_data"])
        assert any(
            "could not be retrieved" in r["Finding_Details"]
            or "Undetermined" in r["Finding"]
            for r in result["csv_data"]
        )

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("quota error")
        result = app.check_bedrock_token_quotas()
        assert result["status"] == "ERROR"


class TestFS04CostAnomalyDetection:
    """FS-04 — Cost Anomaly Detection Check."""

    @patch("app.boto3.client")
    def test_pass_monitors_exist(self, mock_client):
        c = MagicMock()
        c.get_anomaly_monitors.return_value = {
            "AnomalyMonitors": [
                {
                    "MonitorType": "DIMENSIONAL",
                    "MonitorDimension": "SERVICE",
                    "MonitorSpecification": {},
                }
            ]
        }
        mock_client.return_value = c
        result = app.check_cost_anomaly_detection()
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    @patch("app.boto3.client")
    def test_warn_monitors_without_bedrock_coverage(self, mock_client):
        # A DIMENSIONAL monitor scoped to LINKED_ACCOUNT does NOT provide
        # Bedrock service-level coverage → non-PASS (previously masked false positive).
        c = MagicMock()
        c.get_anomaly_monitors.return_value = {
            "AnomalyMonitors": [
                {
                    "MonitorType": "DIMENSIONAL",
                    "MonitorDimension": "LINKED_ACCOUNT",
                    "MonitorSpecification": {},
                }
            ]
        }
        mock_client.return_value = c
        result = app.check_cost_anomaly_detection()
        _assert_finding_structure(result)
        assert result["status"] != "PASS"
        assert any(r["Status"] == "Failed" for r in result["csv_data"])

    @patch("app.boto3.client")
    def test_warn_no_monitors(self, mock_client):
        c = MagicMock()
        c.get_anomaly_monitors.return_value = {"AnomalyMonitors": []}
        mock_client.return_value = c
        result = app.check_cost_anomaly_detection()
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    @patch("app.boto3.client")
    def test_pagination_finds_bedrock_monitor_on_second_page(self, mock_client):
        # The Bedrock-covering monitor is on page 2. The check must paginate via
        # NextPageToken and still find it (otherwise a false "no coverage" finding).
        c = MagicMock()
        c.get_anomaly_monitors.side_effect = [
            {
                "AnomalyMonitors": [
                    {
                        "MonitorType": "DIMENSIONAL",
                        "MonitorDimension": "LINKED_ACCOUNT",
                        "MonitorSpecification": {},
                    }
                ],
                "NextPageToken": "page2",
            },
            {
                "AnomalyMonitors": [
                    {
                        "MonitorType": "DIMENSIONAL",
                        "MonitorDimension": "SERVICE",
                        "MonitorSpecification": {},
                    }
                ]
            },
        ]
        mock_client.return_value = c
        result = app.check_cost_anomaly_detection()
        _assert_finding_structure(result)
        assert result["status"] == "PASS"
        # Verify it actually consumed both pages (passed the token on the 2nd call).
        assert c.get_anomaly_monitors.call_count == 2
        c.get_anomaly_monitors.assert_any_call(NextPageToken="page2")

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("ce error")
        result = app.check_cost_anomaly_detection()
        assert result["status"] == "ERROR"


class TestFS05CloudWatchTokenAlarms:
    """FS-05 — CloudWatch Token Usage Alarms Check."""

    @patch("app.boto3.client")
    def test_pass_bedrock_alarms_exist(self, mock_client):
        c = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "MetricAlarms": [
                    {
                        "AlarmName": "bedrock-throttle-alarm",
                        "Namespace": "AWS/Bedrock",
                        "MetricName": "InvocationThrottles",
                    }
                ]
            }
        ]
        c.get_paginator.return_value = paginator
        mock_client.return_value = c
        result = app.check_cloudwatch_token_alarms()
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    @patch("app.boto3.client")
    def test_warn_no_bedrock_alarms(self, mock_client):
        c = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "MetricAlarms": [
                    {
                        "AlarmName": "cpu-alarm",
                        "Namespace": "AWS/EC2",
                        "MetricName": "CPUUtilization",
                    }
                ]
            }
        ]
        c.get_paginator.return_value = paginator
        mock_client.return_value = c
        result = app.check_cloudwatch_token_alarms()
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("cw error")
        result = app.check_cloudwatch_token_alarms()
        assert result["status"] == "ERROR"


class TestFS06AwsBudgets:
    """FS-06 — AWS Budgets AI/ML Spend Check (ShowFilterExpression, paginated)."""

    @staticmethod
    def _budgets_client(budgets, capture=None, raise_param_validation_on_show=False):
        """
        Build a budgets client whose describe_budgets paginator returns `budgets`.
        If raise_param_validation_on_show is True, paginate raises ParamValidationError
        when called with ShowFilterExpression (simulating old botocore), and returns
        budgets when called without it.
        """
        from botocore.exceptions import ParamValidationError

        c = MagicMock()
        paginator = MagicMock()

        def paginate(**kwargs):
            if capture is not None:
                capture.append(kwargs)
            if raise_param_validation_on_show and "ShowFilterExpression" in kwargs:
                raise ParamValidationError(report="ShowFilterExpression not accepted")
            return [{"Budgets": budgets}]

        paginator.paginate.side_effect = paginate
        c.get_paginator.return_value = paginator
        return c

    def _client_factory(self, budgets, capture=None, raise_pv=False):
        def side_effect(service, **kwargs):
            if service == "budgets":
                return self._budgets_client(budgets, capture, raise_pv)
            if service == "sts":
                c = MagicMock()
                c.get_caller_identity.return_value = {"Account": "123456789012"}
                return c
            return MagicMock()

        return side_effect

    @patch("app.boto3.client")
    def test_pass_aiml_budgets_exist(self, mock_client):
        capture = []
        mock_client.side_effect = self._client_factory(
            [{"BudgetName": "bedrock-budget", "CostFilters": {"Service": ["bedrock"]}}],
            capture=capture,
        )
        result = app.check_aws_budgets_for_aiml()
        _assert_finding_structure(result)
        assert result["status"] == "PASS"
        # Regression guard: the call MUST pass ShowFilterExpression=True.
        assert any(kw.get("ShowFilterExpression") is True for kw in capture)

    @patch("app.boto3.client")
    def test_warn_no_aiml_budgets(self, mock_client):
        mock_client.side_effect = self._client_factory(
            [{"BudgetName": "general", "CostFilters": {"Service": ["ec2"]}}]
        )
        result = app.check_aws_budgets_for_aiml()
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    @patch("app.boto3.client")
    def test_pass_filterexpression_budget(self, mock_client):
        # New-style budget using only FilterExpression (no CostFilters) → detected.
        mock_client.side_effect = self._client_factory(
            [
                {
                    "BudgetName": "genai-budget",
                    "CostFilters": {},
                    "FilterExpression": {
                        "Dimensions": {"Key": "SERVICE", "Values": ["Amazon Bedrock"]}
                    },
                }
            ]
        )
        result = app.check_aws_budgets_for_aiml()
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    @patch("app.boto3.client")
    def test_param_validation_fallback(self, mock_client):
        # Old botocore: ShowFilterExpression rejected with ParamValidationError.
        # FS-06 must degrade to CostFilters-only (non-ERROR) and still match.
        capture = []
        mock_client.side_effect = self._client_factory(
            [{"BudgetName": "bedrock-budget", "CostFilters": {"Service": ["bedrock"]}}],
            capture=capture,
            raise_pv=True,
        )
        result = app.check_aws_budgets_for_aiml()
        _assert_finding_structure(result)
        assert result["status"] != "ERROR"
        assert result["status"] == "PASS"
        # It attempted with ShowFilterExpression, then retried without it.
        assert any("ShowFilterExpression" in kw for kw in capture)
        assert any("ShowFilterExpression" not in kw for kw in capture)

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("budgets error")
        result = app.check_aws_budgets_for_aiml()
        assert result["status"] == "ERROR"


# =========================================================================
# CATEGORY 2: EXCESSIVE AGENCY (FS-07 to FS-11)
# =========================================================================


class TestFS07AgentActionBoundaries:
    """FS-07 — Agent Action Boundary Check (takes permission_cache)."""

    @patch("app.boto3.client")
    def test_pass_no_agents(self, mock_client):
        c = MagicMock()
        c.list_agents.return_value = {"agentSummaries": []}
        mock_client.return_value = c
        result = app.check_bedrock_agent_action_boundaries({})
        _assert_finding_structure(result)
        assert any(r["Status"] == "N/A" for r in result["csv_data"])

    @patch("app.boto3.client")
    def test_warn_wildcard_permissions(
        self, mock_client, permission_cache_with_wildcard
    ):
        c = MagicMock()
        c.list_agents.return_value = {
            "agentSummaries": [{"agentId": "a1", "agentName": "TestAgent"}]
        }
        c.get_agent.return_value = {
            "agent": {"agentResourceRoleArn": "arn:aws:iam::123:role/BedrockAgentRole"}
        }
        mock_client.return_value = c
        result = app.check_bedrock_agent_action_boundaries(
            permission_cache_with_wildcard
        )
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    @patch("app.boto3.client")
    def test_pass_narrow_permissions(self, mock_client, permission_cache_safe):
        c = MagicMock()
        c.list_agents.return_value = {
            "agentSummaries": [{"agentId": "a1", "agentName": "TestAgent"}]
        }
        c.get_agent.return_value = {
            "agent": {"agentResourceRoleArn": "arn:aws:iam::123:role/BedrockAgentRole"}
        }
        mock_client.return_value = c
        result = app.check_bedrock_agent_action_boundaries(permission_cache_safe)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("agent error")
        result = app.check_bedrock_agent_action_boundaries({})
        assert result["status"] == "ERROR"


class TestFS08AgentcorePolicyEngine:
    """FS-08 — AgentCore Policy Engine Check."""

    @patch("app.boto3.client")
    def test_pass_runtimes_with_authorizer(self, mock_client):
        c = MagicMock()
        c.list_agent_runtimes.return_value = {
            "agentRuntimes": [
                {
                    "agentRuntimeName": "rt1",
                    "authorizerConfiguration": {"customJWTAuthorizer": {}},
                }
            ]
        }
        mock_client.return_value = c
        result = app.check_agentcore_policy_engine()
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    @patch("app.boto3.client")
    def test_warn_runtimes_without_authorizer(self, mock_client):
        c = MagicMock()
        c.list_agent_runtimes.return_value = {
            "agentRuntimes": [{"agentRuntimeName": "rt1"}]
        }
        mock_client.return_value = c
        result = app.check_agentcore_policy_engine()
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    @patch("app.boto3.client")
    def test_na_no_runtimes(self, mock_client):
        c = MagicMock()
        c.list_agent_runtimes.return_value = {"agentRuntimes": []}
        mock_client.return_value = c
        result = app.check_agentcore_policy_engine()
        _assert_finding_structure(result)
        assert any(r["Status"] == "N/A" for r in result["csv_data"])

    @patch("app.boto3.client")
    def test_access_denied_returns_na(self, mock_client):
        c = MagicMock()
        c.list_agent_runtimes.side_effect = _client_error("AccessDeniedException")
        mock_client.return_value = c
        result = app.check_agentcore_policy_engine()
        _assert_finding_structure(result)
        assert any(r["Status"] == "N/A" for r in result["csv_data"])

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("agentcore error")
        result = app.check_agentcore_policy_engine()
        assert result["status"] == "ERROR"


class TestFS09AgentTransactionLimits:
    """FS-09 — Agent Transaction Limits Check."""

    @patch("app.boto3.client")
    def test_pass_concurrency_set(self, mock_client):
        c = MagicMock()
        c.get_function_concurrency.return_value = {"ReservedConcurrentExecutions": 10}
        mock_client.return_value = c
        inv = make_resource_inventory(
            lambda_functions=[{"FunctionName": "my-agent-handler"}]
        )
        result = app.check_agent_transaction_limits(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    @patch("app.boto3.client")
    def test_warn_no_concurrency(self, mock_client):
        c = MagicMock()
        c.get_function_concurrency.return_value = {}
        mock_client.return_value = c
        inv = make_resource_inventory(
            lambda_functions=[{"FunctionName": "my-agent-handler"}]
        )
        result = app.check_agent_transaction_limits(inv)
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    def test_error_on_unavailable_inventory(self):
        inv = make_resource_inventory(
            lambda_functions=app._Unavailable(RuntimeError("lambda error"))
        )
        result = app.check_agent_transaction_limits(inv)
        assert result["status"] == "ERROR"


class TestFS10HumanInTheLoop:
    """FS-10 — Human-in-the-Loop Approval Check."""

    @patch("app.boto3.client")
    def test_pass_wait_for_task_token(self, mock_client):
        c = MagicMock()
        c.list_state_machines.return_value = {
            "stateMachines": [
                {
                    "name": "agent-approval-flow",
                    "stateMachineArn": "arn:aws:states:us-east-1:123:sm:test",
                }
            ]
        }
        # The function checks for '"waitForTaskToken"' (with JSON quotes) in the
        # definition string, so we embed it as a standalone JSON string value.
        defn = json.dumps(
            {
                "States": {
                    "Approve": {
                        "Type": "Task",
                        "Resource": "arn:aws:states:::sqs:sendMessage",
                        "Integration": "waitForTaskToken",
                    }
                }
            }
        )
        c.describe_state_machine.return_value = {"definition": defn}
        mock_client.return_value = c
        result = app.check_human_in_the_loop_for_high_risk_actions()
        _assert_finding_structure(result)
        # The function finds "waitForTaskToken" in the definition → PASS path
        assert result["status"] == "PASS"
        assert len(result["csv_data"]) >= 1

    @patch("app.boto3.client")
    def test_warn_no_wait_token(self, mock_client):
        c = MagicMock()
        c.list_state_machines.return_value = {
            "stateMachines": [
                {
                    "name": "agent-workflow",
                    "stateMachineArn": "arn:aws:states:us-east-1:123:sm:test",
                }
            ]
        }
        c.describe_state_machine.return_value = {
            "definition": json.dumps({"States": {"Run": {"Type": "Task"}}})
        }
        mock_client.return_value = c
        result = app.check_human_in_the_loop_for_high_risk_actions()
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("sfn error")
        result = app.check_human_in_the_loop_for_high_risk_actions()
        assert result["status"] == "ERROR"


class TestFS11AgentRateAlarms:
    """FS-11 — Agent Rate Alarms Check."""

    @patch("app.boto3.client")
    def test_pass_agent_alarms_exist(self, mock_client):
        c = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "MetricAlarms": [
                    {
                        "AlarmName": "agent-invocation-rate",
                        "Namespace": "AWS/Bedrock",
                        "MetricName": "AgentInvocations",
                    }
                ]
            }
        ]
        c.get_paginator.return_value = paginator
        mock_client.return_value = c
        result = app.check_agent_rate_alarms()
        _assert_finding_structure(result)
        # The function looks for agent-related alarms
        assert result["status"] in ("PASS", "WARN")

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("cw error")
        result = app.check_agent_rate_alarms()
        assert result["status"] == "ERROR"


# =========================================================================
# CATEGORY 3: SUPPLY CHAIN VULNERABILITIES (FS-12 to FS-16)
# =========================================================================


class TestFS12ScpModelAccess:
    """FS-12 — SCP Model Access Restrictions."""

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("org error")
        result = app.check_scp_model_access_restrictions()
        assert result["status"] == "ERROR"

    @patch("app.boto3.client")
    def test_returns_valid_structure(self, mock_client):
        c = MagicMock()
        c.list_policies.return_value = {"Policies": []}
        mock_client.return_value = c
        result = app.check_scp_model_access_restrictions()
        _assert_finding_structure(result)


class TestFS13ModelInventoryTagging:
    """FS-13 — Model Inventory Tagging."""

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("tagging error")
        result = app.check_model_inventory_tagging()
        assert result["status"] == "ERROR"

    @patch("app.boto3.client")
    def test_returns_valid_structure(self, mock_client):
        c = MagicMock()
        c.list_custom_models.return_value = {"modelSummaries": []}
        c.list_models.return_value = {"Models": []}
        mock_client.return_value = c
        result = app.check_model_inventory_tagging()
        _assert_finding_structure(result)


class TestFS14ModelOnboardingGovernance:
    """FS-14 — Model Onboarding Governance."""

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("config error")
        result = app.check_model_onboarding_governance()
        assert result["status"] == "ERROR"

    @patch("app.boto3.client")
    def test_returns_valid_structure(self, mock_client):
        c = MagicMock()
        c.describe_config_rules.return_value = {"ConfigRules": []}
        mock_client.return_value = c
        result = app.check_model_onboarding_governance()
        _assert_finding_structure(result)


class TestFS15BedrockModelEvalAdversarial:
    """FS-15 — Bedrock Model Evaluation Adversarial."""

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("eval error")
        result = app.check_bedrock_model_evaluation_adversarial()
        assert result["status"] == "ERROR"

    @patch("app.boto3.client")
    def test_returns_valid_structure(self, mock_client):
        c = MagicMock()
        c.list_evaluation_jobs.return_value = {"jobSummaries": []}
        mock_client.return_value = c
        result = app.check_bedrock_model_evaluation_adversarial()
        _assert_finding_structure(result)

    @patch("app.boto3.client")
    def test_fail_no_eval_jobs(self, mock_client):
        """REQ-10a: no Bedrock evaluation jobs → Failed/Medium (was N/A)."""
        c = MagicMock()
        c.list_evaluation_jobs.return_value = {"jobSummaries": []}
        mock_client.return_value = c
        result = app.check_bedrock_model_evaluation_adversarial()
        _assert_finding_structure(result)
        assert any(
            r["Finding"] == "No Bedrock Evaluation Jobs Found"
            and r["Status"] == "Failed"
            and r["Severity"] == "Medium"
            for r in result["csv_data"]
        )

    @patch("app.boto3.client")
    def test_pass_eval_jobs_present(self, mock_client):
        """Eval jobs present → Passed/Medium."""
        c = MagicMock()
        c.list_evaluation_jobs.return_value = {
            "jobSummaries": [{"jobName": "robustness-eval"}]
        }
        mock_client.return_value = c
        result = app.check_bedrock_model_evaluation_adversarial()
        _assert_finding_structure(result)
        assert any(
            r["Finding"] == "Bedrock Evaluation Jobs Present"
            and r["Status"] == "Passed"
            for r in result["csv_data"]
        )


class TestFS16EcrImageScanning:
    """FS-16 — ECR Image Scanning."""

    @patch("app.boto3.client")
    def test_pass_scanning_enabled(self, mock_client):
        c = MagicMock()
        c.describe_repositories.return_value = {
            "repositories": [
                {
                    "repositoryName": "ml-model",
                    "imageScanningConfiguration": {"scanOnPush": True},
                }
            ]
        }
        mock_client.return_value = c
        result = app.check_ecr_image_scanning()
        _assert_finding_structure(result)

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("ecr error")
        result = app.check_ecr_image_scanning()
        assert result["status"] == "ERROR"


# =========================================================================
# CATEGORY 4: TRAINING DATA & MODEL POISONING (FS-20, FS-21)
# =========================================================================


class TestFS20FeatureStoreRollback:
    """FS-20 — Feature Store Rollback Capability."""

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("fs error")
        result = app.check_feature_store_rollback_capability()
        assert result["status"] == "ERROR"

    @patch("app.boto3.client")
    def test_returns_valid_structure(self, mock_client):
        c = MagicMock()
        c.list_feature_groups.return_value = {"FeatureGroupSummaries": []}
        mock_client.return_value = c
        result = app.check_feature_store_rollback_capability()
        _assert_finding_structure(result)


class TestFS21TrainingDataS3Versioning:
    """FS-21 — Training Data S3 Versioning."""

    def test_error_on_unavailable_inventory(self):
        """When the buckets inventory is _Unavailable, check must return ERROR."""
        inv = make_resource_inventory(
            buckets=app._Unavailable(RuntimeError("s3 error"))
        )
        result = app.check_training_data_s3_versioning(inv)
        assert result["status"] == "ERROR"

    @patch("app.boto3.client")
    def test_returns_valid_structure(self, mock_client):
        """Empty bucket list → N/A finding (no training buckets identified)."""
        inv = make_resource_inventory(buckets=[])
        mock_client.return_value = MagicMock()
        result = app.check_training_data_s3_versioning(inv)
        _assert_finding_structure(result)


# =========================================================================
# CATEGORY 5: VECTOR & EMBEDDING WEAKNESSES (FS-22, FS-24, FS-25, FS-26)
# =========================================================================


class TestFS22KnowledgeBaseIamLeastPrivilege:
    """FS-22 — Knowledge Base IAM Least Privilege (takes permission_cache)."""

    def test_pass_empty_cache(self, permission_cache_empty):
        # FS-22 reads only the permission cache (no boto3 calls). An empty cache
        # means no roles to inspect → PASS with no wildcard findings.
        result = app.check_knowledge_base_iam_least_privilege(permission_cache_empty)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        """FS-22 only reads permission_cache (no boto3 calls). To trigger
        the error path, pass a cache that causes an exception during iteration."""
        # A non-dict value for role_permissions will cause .items() to fail
        bad_cache = {"role_permissions": "not-a-dict"}
        result = app.check_knowledge_base_iam_least_privilege(bad_cache)
        assert result["status"] == "ERROR"

    def test_single_statement_dict_no_crash_wildcard(self):
        """REQ-3: a policy whose Statement is a single dict (not a list) must not
        crash ('str' object has no attribute 'get'); a wildcard is still flagged."""
        cache = {
            "role_permissions": {
                "AmazonBedrockExecutionRoleForKnowledgeBase_Test": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "KBInline",
                            "document": {
                                "Version": "2012-10-17",
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": "bedrock-agent:*",
                                    "Resource": "*",
                                },
                            },
                        }
                    ],
                }
            }
        }
        result = app.check_knowledge_base_iam_least_privilege(cache)
        _assert_finding_structure(result)
        assert result["status"] != "ERROR"
        assert any(
            r["Finding"] == "Overly Permissive Knowledge Base IAM Roles"
            and r["Status"] == "Failed"
            and r["Severity"] == "High"
            for r in result["csv_data"]
        )

    def test_single_statement_dict_no_wildcard(self):
        """Single-statement-dict policy without a wildcard → Passed/High, no crash."""
        cache = {
            "role_permissions": {
                "KBRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "KBInline",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": "bedrock:Retrieve",
                                    "Resource": "arn:aws:bedrock:*:*:knowledge-base/*",
                                }
                            },
                        }
                    ],
                }
            }
        }
        result = app.check_knowledge_base_iam_least_privilege(cache)
        _assert_finding_structure(result)
        assert result["status"] != "ERROR"
        assert any(
            r["Finding"] == "Knowledge Base IAM Permissions Look Appropriate"
            and r["Status"] == "Passed"
            for r in result["csv_data"]
        )

    def test_partial_wildcard_flagged(self):
        """REQ-14/D: a partial wildcard (e.g. 'bedrock-agent:Get*') is over-broad
        and must be flagged, not just the three exact full wildcards."""
        cache = {
            "role_permissions": {
                "KBRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "KBInline",
                            "document": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "bedrock-agent:Get*",
                                        "Resource": "arn:aws:bedrock:*:*:knowledge-base/kb-1",
                                    }
                                ]
                            },
                        }
                    ],
                }
            }
        }
        result = app.check_knowledge_base_iam_least_privilege(cache)
        _assert_finding_structure(result)
        assert result["status"] == "WARN"
        assert any(
            r["Finding"] == "Overly Permissive Knowledge Base IAM Roles"
            and r["Status"] == "Failed"
            for r in result["csv_data"]
        )

    def test_unscoped_resource_flagged(self):
        """REQ-14/D: a scoped action on Resource '*' (no ARN scoping) is flagged."""
        cache = {
            "role_permissions": {
                "KBRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "KBInline",
                            "document": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "bedrock:Retrieve",
                                        "Resource": "*",
                                    }
                                ]
                            },
                        }
                    ],
                }
            }
        }
        result = app.check_knowledge_base_iam_least_privilege(cache)
        _assert_finding_structure(result)
        assert result["status"] == "WARN"
        assert any(r["Status"] == "Failed" for r in result["csv_data"])

    def test_not_action_allow_flagged(self):
        """REQ-14/D: a NotAction Allow grants everything except listed actions and
        is inherently over-broad → flagged."""
        cache = {
            "role_permissions": {
                "KBRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "KBInline",
                            "document": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "NotAction": "s3:DeleteObject",
                                        "Resource": "arn:aws:bedrock:*:*:knowledge-base/kb-1",
                                    }
                                ]
                            },
                        }
                    ],
                }
            }
        }
        result = app.check_knowledge_base_iam_least_privilege(cache)
        _assert_finding_structure(result)
        assert result["status"] == "WARN"
        assert any(r["Status"] == "Failed" for r in result["csv_data"])

    def test_scoped_specific_actions_pass(self):
        """REQ-14/D: properly scoped specific actions on a specific KB ARN → Passed
        (no false positive from the widened detection)."""
        cache = {
            "role_permissions": {
                "KBRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "KBInline",
                            "document": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "bedrock:Retrieve",
                                            "bedrock:RetrieveAndGenerate",
                                        ],
                                        "Resource": "arn:aws:bedrock:us-east-1:111122223333:knowledge-base/kb-1",
                                    }
                                ]
                            },
                        }
                    ],
                }
            }
        }
        result = app.check_knowledge_base_iam_least_privilege(cache)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"
        assert any(
            r["Finding"] == "Knowledge Base IAM Permissions Look Appropriate"
            and r["Status"] == "Passed"
            for r in result["csv_data"]
        )


class TestFS24KnowledgeBaseMetadataFiltering:
    """FS-24 — Knowledge Base Metadata Filtering."""

    def test_error_on_unavailable_inventory(self):
        inv = make_resource_inventory(
            knowledge_bases=app._Unavailable(RuntimeError("kb error"))
        )
        result = app.check_knowledge_base_metadata_filtering(inv)
        assert result["status"] == "ERROR"

    def test_returns_valid_structure_no_kbs(self):
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[], data_sources_by_kb={}, data_source_detail={}
            )
        )
        result = app.check_knowledge_base_metadata_filtering(inv)
        _assert_finding_structure(result)

    def test_returns_advisory_with_kbs(self):
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[{"knowledgeBaseId": "kb1", "name": "rag-kb"}],
                data_sources_by_kb={},
                data_source_detail={},
            )
        )
        result = app.check_knowledge_base_metadata_filtering(inv)
        _assert_finding_structure(result)
        assert any("ADVISORY" in r.get("Finding", "") for r in result["csv_data"])


class TestFS25OpensearchServerlessEncryption:
    """FS-25 — OpenSearch Serverless Encryption."""

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("oss error")
        result = app.check_opensearch_serverless_encryption()
        assert result["status"] == "ERROR"


class TestFS26KnowledgeBaseVpcAccess:
    """FS-26 — Knowledge Base VPC Access."""

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("vpc error")
        result = app.check_knowledge_base_vpc_access()
        assert result["status"] == "ERROR"


# =========================================================================
# CATEGORY 6: NON-COMPLIANT OUTPUT (FS-27 to FS-30)
# =========================================================================


class TestFS27GuardrailContextualGrounding:
    """FS-27 — Guardrail Contextual Grounding Check (renamed from check_automated_reasoning_checks)."""

    def test_pass_grounding_configured(self):
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "finserv-guard"}],
                detail_by_id={
                    "g1": {
                        "contextualGroundingPolicy": {
                            "filters": [{"type": "GROUNDING", "threshold": 0.7}]
                        }
                    }
                },
            )
        )
        result = app.check_guardrail_contextual_grounding(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    def test_warn_no_grounding(self):
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "finserv-guard"}],
                detail_by_id={"g1": {}},
            )
        )
        result = app.check_guardrail_contextual_grounding(inv)
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    def test_error_on_exception(self):
        inv = make_resource_inventory(
            guardrails=app._Unavailable(RuntimeError("arc error"))
        )
        result = app.check_guardrail_contextual_grounding(inv)
        assert result["status"] == "ERROR"


class TestFS27AutomatedReasoningPolicies:
    """FS-27b — Automated Reasoning Policies Check (new, GA August 2025)."""

    @patch("app.boto3.client")
    def test_pass_policies_exist(self, mock_client):
        c = MagicMock()
        c.list_automated_reasoning_policies.return_value = {
            "automatedReasoningPolicySummaries": [
                {"name": "loan-eligibility-policy", "policyId": "pol-001"}
            ]
        }
        mock_client.return_value = c
        result = app.check_automated_reasoning_policies()
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    @patch("app.boto3.client")
    def test_warn_no_policies(self, mock_client):
        c = MagicMock()
        c.list_automated_reasoning_policies.return_value = {
            "automatedReasoningPolicySummaries": []
        }
        mock_client.return_value = c
        result = app.check_automated_reasoning_policies()
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    @patch("app.boto3.client")
    def test_access_denied_returns_na(self, mock_client):
        c = MagicMock()
        c.list_automated_reasoning_policies.side_effect = _client_error(
            "AccessDeniedException"
        )
        mock_client.return_value = c
        result = app.check_automated_reasoning_policies()
        _assert_finding_structure(result)
        assert any(r["Status"] == "N/A" for r in result["csv_data"])

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("arc error")
        result = app.check_automated_reasoning_policies()
        assert result["status"] == "ERROR"


class TestFS28GuardrailDeniedTopicsFinancial:
    """FS-28 — Guardrail Denied Topics Financial."""

    def test_pass_denied_topics_configured(self):
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "finserv-guard"}],
                detail_by_id={
                    "g1": {
                        "topicPolicy": {
                            "topics": [{"name": "financial-advice", "type": "DENY"}],
                            "tier": {"tierName": "STANDARD"},
                        }
                    }
                },
            )
        )
        result = app.check_guardrail_denied_topics_financial(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    def test_classic_tier_advisory(self):
        # Topics exist but on CLASSIC tier → Low-severity advisory (still Passed wrapper).
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "finserv-guard"}],
                detail_by_id={
                    "g1": {
                        "topicPolicy": {
                            "topics": [{"name": "financial-advice", "type": "DENY"}],
                            "tier": {"tierName": "CLASSIC"},
                        }
                    }
                },
            )
        )
        result = app.check_guardrail_denied_topics_financial(inv)
        _assert_finding_structure(result)
        assert any(
            r["Finding"] == "Denied Topics Configured on CLASSIC Tier"
            and r["Severity"] == "High"
            for r in result["csv_data"]
        )

    def test_error_on_exception(self):
        inv = make_resource_inventory(
            guardrails=app._Unavailable(RuntimeError("topic error"))
        )
        result = app.check_guardrail_denied_topics_financial(inv)
        assert result["status"] == "ERROR"


class TestFS29ComplianceDisclaimer:
    """FS-29 — Advisory check (no AWS API calls)."""

    def test_returns_valid_structure(self):
        result = app.check_compliance_disclaimer_in_outputs()
        _assert_finding_structure(result)
        assert result["status"] == "PASS"
        _assert_advisory_retag(result, "FS-29")
        assert len(result["csv_data"]) >= 1
        assert result["csv_data"][0]["Check_ID"] == "FS-29"


class TestFS30BedrockEvalComplianceDatasets:
    """FS-30 — Advisory (cannot inspect eval-job dataset content; REQ-10a)."""

    def test_returns_advisory_structure(self):
        result = app.check_bedrock_evaluation_compliance_datasets()
        _assert_finding_structure(result)
        _assert_advisory_retag(result, "FS-30")
        assert result["csv_data"][0]["Check_ID"] == "FS-30"


# =========================================================================
# CATEGORY 7: MISINFORMATION (FS-31 to FS-34)
# =========================================================================


class TestFS31KnowledgeBaseDataSourceSync:
    """FS-31 — Knowledge Base Data Source Sync."""

    def test_error_on_unavailable_inventory(self):
        inv = make_resource_inventory(
            knowledge_bases=app._Unavailable(RuntimeError("sync error"))
        )
        result = app.check_knowledge_base_data_source_sync(inv)
        assert result["status"] == "ERROR"

    def test_na_no_kbs(self):
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[], data_sources_by_kb={}, data_source_detail={}
            )
        )
        result = app.check_knowledge_base_data_source_sync(inv)
        _assert_finding_structure(result)
        assert any(r["Status"] == "N/A" for r in result["csv_data"])


class TestFS32SourceAttribution:
    """FS-32 — Advisory check (no AWS API calls)."""

    def test_returns_valid_structure(self):
        result = app.check_source_attribution_in_guardrails()
        _assert_finding_structure(result)
        assert result["status"] == "PASS"
        _assert_advisory_retag(result, "FS-32")
        assert result["csv_data"][0]["Check_ID"] == "FS-32"


class TestFS33KnowledgeBaseIntegrityMonitoring:
    """FS-33 — Knowledge Base Integrity Monitoring."""

    def test_error_on_unavailable_inventory(self):
        inv = make_resource_inventory(
            knowledge_bases=app._Unavailable(RuntimeError("integrity error"))
        )
        result = app.check_knowledge_base_integrity_monitoring(inv)
        assert result["status"] == "ERROR"

    def test_na_no_kbs(self):
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[], data_sources_by_kb={}, data_source_detail={}
            )
        )
        result = app.check_knowledge_base_integrity_monitoring(inv)
        _assert_finding_structure(result)
        assert any(r["Status"] == "N/A" for r in result["csv_data"])


class TestFS34FmVersionCurrency:
    """FS-34 — FM Version Currency Advisory."""

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("fm error")
        result = app.check_fm_version_currency()
        assert result["status"] == "ERROR"


# =========================================================================
# CATEGORY 8: ABUSIVE OR HARMFUL OUTPUT (FS-35 to FS-38)
# =========================================================================


class TestFS35FmevalHarmfulContent:
    """FS-35 — Advisory (cannot inspect eval-job dataset content; REQ-10a)."""

    def test_returns_advisory_structure(self):
        result = app.check_fmeval_harmful_content()
        _assert_finding_structure(result)
        _assert_advisory_retag(result, "FS-35")
        assert result["csv_data"][0]["Check_ID"] == "FS-35"


class TestFS36GuardrailContentFilters:
    """FS-36 — Guardrail Content Filters."""

    def test_pass_content_filters_configured(self):
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "guard1"}],
                detail_by_id={
                    "g1": {
                        "contentPolicy": {
                            "filters": [
                                {
                                    "type": "SEXUAL",
                                    "inputStrength": "HIGH",
                                    "outputStrength": "HIGH",
                                },
                                {
                                    "type": "VIOLENCE",
                                    "inputStrength": "HIGH",
                                    "outputStrength": "HIGH",
                                },
                                {
                                    "type": "HATE",
                                    "inputStrength": "HIGH",
                                    "outputStrength": "HIGH",
                                },
                                {
                                    "type": "INSULTS",
                                    "inputStrength": "HIGH",
                                    "outputStrength": "HIGH",
                                },
                            ]
                        }
                    }
                },
            )
        )
        result = app.check_guardrail_content_filters(inv)
        _assert_finding_structure(result)

    def test_error_on_exception(self):
        inv = make_resource_inventory(
            guardrails=app._Unavailable(RuntimeError("content error"))
        )
        result = app.check_guardrail_content_filters(inv)
        assert result["status"] == "ERROR"


class TestFS37UserFeedbackMechanism:
    """FS-37 — Advisory check (no AWS API calls)."""

    def test_returns_valid_structure(self):
        result = app.check_user_feedback_mechanism()
        _assert_finding_structure(result)
        assert result["status"] == "PASS"
        _assert_advisory_retag(result, "FS-37")
        assert result["csv_data"][0]["Check_ID"] == "FS-37"


class TestFS38GuardrailWordFilters:
    """FS-38 — Guardrail Word Filters."""

    def test_error_on_exception(self):
        inv = make_resource_inventory(
            guardrails=app._Unavailable(RuntimeError("word error"))
        )
        result = app.check_guardrail_word_filters(inv)
        assert result["status"] == "ERROR"


# =========================================================================
# CATEGORY 9: BIASED OUTPUT (FS-39 to FS-42)
# =========================================================================


class TestFS39SagemakerClarifyBias:
    """FS-39 — SageMaker Clarify Bias."""

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("clarify error")
        result = app.check_sagemaker_clarify_bias()
        assert result["status"] == "ERROR"


class TestFS40BedrockEvalBiasDatasets:
    """FS-40 — Advisory (cannot inspect eval-job dataset content; REQ-10a)."""

    def test_returns_advisory_structure(self):
        result = app.check_bedrock_evaluation_bias_datasets()
        _assert_finding_structure(result)
        _assert_advisory_retag(result, "FS-40")
        assert result["csv_data"][0]["Check_ID"] == "FS-40"


class TestFS41SagemakerClarifyExplainability:
    """FS-41 — SageMaker Clarify Explainability."""

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("explain error")
        result = app.check_sagemaker_clarify_explainability()
        assert result["status"] == "ERROR"


class TestFS42AiServiceCards:
    """FS-42 — AI Service Cards Documentation Advisory."""

    @patch("app.boto3.client")
    def test_returns_valid_structure(self, mock_client):
        c = MagicMock()
        c.list_model_cards.return_value = {"ModelCardSummaries": []}
        mock_client.return_value = c
        result = app.check_ai_service_cards_documentation()
        _assert_finding_structure(result)

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("cards error")
        result = app.check_ai_service_cards_documentation()
        assert result["status"] == "ERROR"


# =========================================================================
# CATEGORY 10: SENSITIVE INFORMATION DISCLOSURE (FS-43 to FS-46)
# =========================================================================


class TestFS43CloudwatchLogPiiMasking:
    """FS-43 — CloudWatch Log PII Masking."""

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("logs error")
        result = app.check_cloudwatch_log_pii_masking()
        assert result["status"] == "ERROR"


class TestFS44MacieOnTrainingDataBuckets:
    """FS-44 — Macie on Training Data Buckets."""

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("macie error")
        result = app.check_macie_on_training_data_buckets()
        assert result["status"] == "ERROR"


class TestFS45GuardrailPiiFilters:
    """FS-45 — Guardrail PII Filters."""

    def test_pass_pii_filters_configured(self):
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "guard1"}],
                detail_by_id={
                    "g1": {
                        "sensitiveInformationPolicy": {
                            "piiEntities": [
                                {"type": "SSN", "action": "BLOCK"},
                                {"type": "CREDIT_DEBIT_CARD_NUMBER", "action": "BLOCK"},
                            ]
                        }
                    }
                },
            )
        )
        result = app.check_guardrail_pii_filters(inv)
        _assert_finding_structure(result)

    def test_error_on_exception(self):
        inv = make_resource_inventory(
            guardrails=app._Unavailable(RuntimeError("pii error"))
        )
        result = app.check_guardrail_pii_filters(inv)
        assert result["status"] == "ERROR"


class TestFS46DataClassificationTagging:
    """FS-46 — Data Classification Tagging."""

    def test_error_on_unavailable_inventory(self):
        """When the buckets inventory is _Unavailable, check must return ERROR."""
        inv = make_resource_inventory(
            buckets=app._Unavailable(RuntimeError("tag error"))
        )
        result = app.check_data_classification_tagging(inv)
        assert result["status"] == "ERROR"


# =========================================================================
# CATEGORY 11: HALLUCINATION (FS-47 to FS-50)
# =========================================================================


class TestFS47GuardrailGroundingThreshold:
    """FS-47 — Guardrail Grounding Threshold."""

    def test_error_on_exception(self):
        inv = make_resource_inventory(
            guardrails=app._Unavailable(RuntimeError("grounding error"))
        )
        result = app.check_guardrail_grounding_threshold(inv)
        assert result["status"] == "ERROR"


class TestFS48RagKnowledgeBaseConfigured:
    """FS-48 — RAG Knowledge Base Configured."""

    def test_pass_kbs_exist(self):
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[
                    {"knowledgeBaseId": "kb1", "name": "rag-kb", "status": "ACTIVE"}
                ],
                data_sources_by_kb={},
                data_source_detail={},
            )
        )
        result = app.check_rag_knowledge_base_configured(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    def test_error_on_unavailable_inventory(self):
        inv = make_resource_inventory(
            knowledge_bases=app._Unavailable(RuntimeError("rag error"))
        )
        result = app.check_rag_knowledge_base_configured(inv)
        assert result["status"] == "ERROR"


class TestFS49HallucinationDisclaimer:
    """FS-49 — Advisory check (no AWS API calls)."""

    def test_returns_valid_structure(self):
        result = app.check_hallucination_disclaimer_advisory()
        _assert_finding_structure(result)
        assert result["status"] == "PASS"
        _assert_advisory_retag(result, "FS-49")
        assert result["csv_data"][0]["Check_ID"] == "FS-49"


class TestFS50GuardrailRelevanceGrounding:
    """FS-50 — Guardrail Relevance Grounding Check (renamed from check_automated_reasoning_checks_hallucination)."""

    def test_pass_relevance_filter_present(self):
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "guard1"}],
                detail_by_id={
                    "g1": {
                        "contextualGroundingPolicy": {
                            "filters": [{"type": "RELEVANCE", "threshold": 0.7}]
                        }
                    }
                },
            )
        )
        result = app.check_guardrail_relevance_grounding(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    def test_warn_no_relevance_filter(self):
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "guard1"}],
                detail_by_id={
                    "g1": {
                        "contextualGroundingPolicy": {
                            "filters": [{"type": "GROUNDING", "threshold": 0.7}]
                        }
                    }
                },
            )
        )
        result = app.check_guardrail_relevance_grounding(inv)
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    def test_error_on_exception(self):
        inv = make_resource_inventory(
            guardrails=app._Unavailable(RuntimeError("arc error"))
        )
        result = app.check_guardrail_relevance_grounding(inv)
        assert result["status"] == "ERROR"


# =========================================================================
# CATEGORY 12: PROMPT INJECTION (FS-51 to FS-54)
# =========================================================================


class TestFS51PromptInjectionInputValidation:
    """FS-51 — Prompt Injection Input Validation."""

    def test_pass_prompt_attack_filter(self):
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "guard1"}],
                detail_by_id={
                    "g1": {
                        "contentPolicy": {
                            "filters": [
                                {
                                    "type": "PROMPT_ATTACK",
                                    "inputStrength": "HIGH",
                                    "outputStrength": "NONE",
                                }
                            ]
                        }
                    }
                },
            )
        )
        result = app.check_prompt_injection_input_validation(inv)
        _assert_finding_structure(result)

    def test_error_on_exception(self):
        inv = make_resource_inventory(
            guardrails=app._Unavailable(RuntimeError("prompt error"))
        )
        result = app.check_prompt_injection_input_validation(inv)
        assert result["status"] == "ERROR"


class TestFS52BedrockSdkVersionCurrency:
    """FS-52 — Bedrock SDK Version Currency Advisory."""

    def test_error_on_unavailable_inventory(self):
        inv = make_resource_inventory(
            lambda_functions=app._Unavailable(RuntimeError("sdk error"))
        )
        result = app.check_bedrock_sdk_version_currency(inv)
        assert result["status"] == "ERROR"


class TestFS53WafSqlInjectionRules:
    """FS-53 — WAF SQL Injection Rules."""

    def test_pass_managed_rules_present(self):
        """ACL with AWSManagedRulesSQLiRuleSet in inventory → PASS."""
        acl_detail = {
            "Rules": [
                {
                    "Name": "AWS-AWSManagedRulesSQLiRuleSet",
                    "Statement": {
                        "ManagedRuleGroupStatement": {
                            "VendorName": "AWS",
                            "Name": "AWSManagedRulesSQLiRuleSet",
                        }
                    },
                }
            ]
        }
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(
                summaries=[{"Name": "acl1", "Id": "id1"}],
                detail_by_id={"id1": acl_detail},
            )
        )
        result = app.check_waf_sql_injection_rules(inv)
        _assert_finding_structure(result)

    def test_na_no_acls(self):
        """Empty summaries list → N/A (no ACLs found)."""
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(summaries=[], detail_by_id={})
        )
        result = app.check_waf_sql_injection_rules(inv)
        _assert_finding_structure(result)
        assert any(r["Status"] == "N/A" for r in result["csv_data"])

    def test_warn_acls_without_injection_rules(self):
        """ACL with no injection rule groups → WARN."""
        acl_detail = {
            "Rules": [
                {
                    "Name": "rate-limit",
                    "Statement": {"RateBasedStatement": {"Limit": 1000}},
                }
            ]
        }
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(
                summaries=[{"Name": "acl1", "Id": "id1"}],
                detail_by_id={"id1": acl_detail},
            )
        )
        result = app.check_waf_sql_injection_rules(inv)
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    def test_error_on_exception(self):
        """Unavailable inventory → COULD_NOT_ASSESS (ERROR envelope)."""
        inv = make_resource_inventory(
            web_acls=app._Unavailable(RuntimeError("waf error"))
        )
        result = app.check_waf_sql_injection_rules(inv)
        assert result["status"] == "ERROR"

    # --- Pagination-correctness proof: >100 ACLs ---
    def test_pass_more_than_100_acls_all_have_rules(self):
        """Inventory with 150 ACLs all having injection rules → PASS (all pages visible)."""
        acl_detail = {
            "Rules": [
                {
                    "Statement": {
                        "ManagedRuleGroupStatement": {
                            "Name": "AWSManagedRulesSQLiRuleSet"
                        }
                    }
                }
            ]
        }
        summaries = [{"Name": f"acl{i}", "Id": f"id{i}"} for i in range(150)]
        detail_by_id = {f"id{i}": acl_detail for i in range(150)}
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(summaries=summaries, detail_by_id=detail_by_id)
        )
        result = app.check_waf_sql_injection_rules(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"
        assert any(
            r["Finding"] == "WAF Injection Protection Rules Present"
            and "150" in r["Finding_Details"]
            for r in result["csv_data"]
        )

    def test_warn_more_than_100_acls_some_missing_rules(self):
        """Inventory with 150 ACLs, last 50 missing rules → WARN (previously truncated acls now detected)."""
        good_detail = {
            "Rules": [
                {
                    "Statement": {
                        "ManagedRuleGroupStatement": {
                            "Name": "AWSManagedRulesSQLiRuleSet"
                        }
                    }
                }
            ]
        }
        bad_detail = {"Rules": []}
        summaries = [{"Name": f"acl{i}", "Id": f"id{i}"} for i in range(150)]
        detail_by_id = {}
        for i in range(100):
            detail_by_id[f"id{i}"] = good_detail
        for i in range(100, 150):
            detail_by_id[f"id{i}"] = bad_detail
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(summaries=summaries, detail_by_id=detail_by_id)
        )
        result = app.check_waf_sql_injection_rules(inv)
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    # --- ≤1-page equivalence: 2-ACL case matches Wave-0 baseline ---
    def test_two_acl_case_unchanged(self):
        """The 2-ACL scenario produces the same PASS finding as the pre-refactor baseline."""
        acl_detail = {
            "Rules": [
                {
                    "Statement": {
                        "ManagedRuleGroupStatement": {
                            "Name": "AWSManagedRulesSQLiRuleSet"
                        }
                    }
                }
            ]
        }
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(
                summaries=[
                    {"Name": "FinServACL1", "Id": "acl-id-001"},
                    {"Name": "FinServACL2", "Id": "acl-id-002"},
                ],
                detail_by_id={
                    "acl-id-001": acl_detail,
                    "acl-id-002": acl_detail,
                },
            )
        )
        result = app.check_waf_sql_injection_rules(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"
        assert any(
            r["Finding"] == "WAF Injection Protection Rules Present"
            for r in result["csv_data"]
        )


class TestFS54PenetrationTestingEvidence:
    """FS-54 — Advisory check (no AWS API calls)."""

    def test_returns_valid_structure(self):
        result = app.check_penetration_testing_evidence()
        _assert_finding_structure(result)
        assert result["status"] == "PASS"
        _assert_advisory_retag(result, "FS-54")
        assert result["csv_data"][0]["Check_ID"] == "FS-54"


# =========================================================================
# CATEGORY 13: IMPROPER OUTPUT HANDLING (FS-55 to FS-58)
# =========================================================================


class TestFS55OutputValidationLambda:
    """FS-55 — Output Validation Lambda Check."""

    def test_pass_validation_functions_exist(self):
        inv = make_resource_inventory(
            lambda_functions=[{"FunctionName": "output-validate-handler"}]
        )
        result = app.check_output_validation_lambda(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    def test_warn_no_validation_functions(self):
        inv = make_resource_inventory(
            lambda_functions=[{"FunctionName": "my-api-handler"}]
        )
        result = app.check_output_validation_lambda(inv)
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    def test_error_on_unavailable_inventory(self):
        inv = make_resource_inventory(
            lambda_functions=app._Unavailable(RuntimeError("lambda error"))
        )
        result = app.check_output_validation_lambda(inv)
        assert result["status"] == "ERROR"


class TestFS56XssPreventionWaf:
    """FS-56 — XSS Prevention WAF Check."""

    def test_pass_acls_present(self):
        """ACL with AWSManagedRulesCommonRuleSet in inventory → PASS."""
        acl_detail = {
            "Rules": [
                {
                    "Statement": {
                        "ManagedRuleGroupStatement": {
                            "Name": "AWSManagedRulesCommonRuleSet"
                        }
                    }
                }
            ]
        }
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(
                summaries=[{"Name": "acl1", "Id": "id1"}],
                detail_by_id={"id1": acl_detail},
            )
        )
        result = app.check_xss_prevention_waf(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"
        assert any(
            r["Finding"] == "XSS Prevention Common Rule Set Present"
            for r in result["csv_data"]
        )

    def test_fail_acls_without_common_rule_set(self):
        """ACL without AWSManagedRulesCommonRuleSet → FAIL."""
        acl_detail = {"Rules": []}
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(
                summaries=[{"Name": "acl1", "Id": "id1"}],
                detail_by_id={"id1": acl_detail},
            )
        )
        result = app.check_xss_prevention_waf(inv)
        _assert_finding_structure(result)
        assert any(
            r["Finding"] == "WAF ACLs Missing Common Rule Set (XSS)"
            and r["Status"] == "Failed"
            and r["Severity"] == "Medium"
            for r in result["csv_data"]
        )

    def test_na_no_acls(self):
        """Empty summaries → N/A."""
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(summaries=[], detail_by_id={})
        )
        result = app.check_xss_prevention_waf(inv)
        _assert_finding_structure(result)
        assert any(r["Status"] == "N/A" for r in result["csv_data"])

    def test_error_on_exception(self):
        """Unavailable inventory → COULD_NOT_ASSESS (ERROR envelope)."""
        inv = make_resource_inventory(
            web_acls=app._Unavailable(RuntimeError("xss error"))
        )
        result = app.check_xss_prevention_waf(inv)
        assert result["status"] == "ERROR"

    # --- Pagination-correctness proof: >100 ACLs ---
    def test_pass_more_than_100_acls_all_have_common_rule_set(self):
        """150 ACLs all with AWSManagedRulesCommonRuleSet → PASS (previously truncated ACLs visible)."""
        acl_detail = {
            "Rules": [
                {
                    "Statement": {
                        "ManagedRuleGroupStatement": {
                            "Name": "AWSManagedRulesCommonRuleSet"
                        }
                    }
                }
            ]
        }
        summaries = [{"Name": f"acl{i}", "Id": f"id{i}"} for i in range(150)]
        detail_by_id = {f"id{i}": acl_detail for i in range(150)}
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(summaries=summaries, detail_by_id=detail_by_id)
        )
        result = app.check_xss_prevention_waf(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    def test_warn_more_than_100_acls_some_missing_xss_rules(self):
        """150 ACLs, last 50 missing AWSManagedRulesCommonRuleSet → WARN (pagination fix detects them)."""
        good_detail = {
            "Rules": [
                {
                    "Statement": {
                        "ManagedRuleGroupStatement": {
                            "Name": "AWSManagedRulesCommonRuleSet"
                        }
                    }
                }
            ]
        }
        bad_detail = {"Rules": []}
        summaries = [{"Name": f"acl{i}", "Id": f"id{i}"} for i in range(150)]
        detail_by_id = {}
        for i in range(100):
            detail_by_id[f"id{i}"] = good_detail
        for i in range(100, 150):
            detail_by_id[f"id{i}"] = bad_detail
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(summaries=summaries, detail_by_id=detail_by_id)
        )
        result = app.check_xss_prevention_waf(inv)
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    # --- ≤1-page equivalence: 2-ACL case matches Wave-0 baseline ---
    def test_two_acl_case_unchanged(self):
        """The 2-ACL PASS scenario is unchanged vs the pre-refactor baseline."""
        acl_detail = {
            "Rules": [
                {
                    "Statement": {
                        "ManagedRuleGroupStatement": {
                            "Name": "AWSManagedRulesCommonRuleSet"
                        }
                    }
                }
            ]
        }
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(
                summaries=[
                    {"Name": "FinServACL1", "Id": "acl-id-001"},
                    {"Name": "FinServACL2", "Id": "acl-id-002"},
                ],
                detail_by_id={
                    "acl-id-001": acl_detail,
                    "acl-id-002": acl_detail,
                },
            )
        )
        result = app.check_xss_prevention_waf(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"
        assert any(
            r["Finding"] == "XSS Prevention Common Rule Set Present"
            for r in result["csv_data"]
        )


class TestFS57OutputEncodingAdvisory:
    """FS-57 — Advisory check (no AWS API calls)."""

    def test_returns_valid_structure(self):
        result = app.check_output_encoding_advisory()
        _assert_finding_structure(result)
        assert result["status"] == "PASS"
        _assert_advisory_retag(result, "FS-57")
        assert result["csv_data"][0]["Check_ID"] == "FS-57"


class TestFS58OutputSchemaValidation:
    """FS-58 — Output Schema Validation Check."""

    def test_returns_valid_structure(self):
        inv = make_resource_inventory(
            lambda_functions=[{"FunctionName": "schema-validate-fn"}]
        )
        result = app.check_output_schema_validation(inv)
        _assert_finding_structure(result)
        # REQ-2: FS-58 is advisory — N/A + Informational + "ADVISORY: " prefix, never Passed.
        _assert_advisory_retag(result, "FS-58")
        assert not any(r["Status"] == "Passed" for r in result["csv_data"])

    def test_error_on_unavailable_inventory(self):
        inv = make_resource_inventory(
            lambda_functions=app._Unavailable(RuntimeError("schema error"))
        )
        result = app.check_output_schema_validation(inv)
        assert result["status"] == "ERROR"


# =========================================================================
# CATEGORY 14: OFF-TOPIC & INAPPROPRIATE OUTPUT (FS-59 to FS-60)
# =========================================================================


class TestFS59GuardrailTopicAllowlist:
    """FS-59 — Guardrail Topic Allowlist Check."""

    def test_pass_topics_configured(self):
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "guard1"}],
                detail_by_id={
                    "g1": {
                        "topicPolicy": {
                            "topics": [{"name": "medical-advice", "type": "DENY"}],
                            "tier": {"tierName": "STANDARD"},
                        }
                    }
                },
            )
        )
        result = app.check_guardrail_topic_allowlist(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    def test_classic_tier_advisory(self):
        # Topics on CLASSIC tier → Low advisory finding (wrapper stays PASS).
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "guard1"}],
                detail_by_id={
                    "g1": {
                        "topicPolicy": {
                            "topics": [{"name": "medical-advice", "type": "DENY"}],
                            "tier": {"tierName": "CLASSIC"},
                        }
                    }
                },
            )
        )
        result = app.check_guardrail_topic_allowlist(inv)
        _assert_finding_structure(result)
        assert any(
            r["Finding"] == "Topic Restrictions Configured on CLASSIC Tier"
            and r["Severity"] == "Medium"
            for r in result["csv_data"]
        )

    def test_warn_no_topics(self):
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "guard1"}],
                detail_by_id={"g1": {"topicPolicy": {"topics": []}}},
            )
        )
        result = app.check_guardrail_topic_allowlist(inv)
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    def test_na_no_guardrails(self):
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(summaries=[], detail_by_id={})
        )
        result = app.check_guardrail_topic_allowlist(inv)
        _assert_finding_structure(result)
        assert any(r["Status"] == "N/A" for r in result["csv_data"])

    def test_error_on_exception(self):
        inv = make_resource_inventory(
            guardrails=app._Unavailable(RuntimeError("topic error"))
        )
        result = app.check_guardrail_topic_allowlist(inv)
        assert result["status"] == "ERROR"


class TestFS60ContextualGroundingForOfftopic:
    """FS-60 — Advisory check (no AWS API calls)."""

    def test_returns_valid_structure(self):
        result = app.check_contextual_grounding_for_offtopic()
        _assert_finding_structure(result)
        assert result["status"] == "PASS"
        _assert_advisory_retag(result, "FS-60")
        assert result["csv_data"][0]["Check_ID"] == "FS-60"


# =========================================================================
# CATEGORY 15: OUT-OF-DATE TRAINING DATA (FS-61 to FS-63)
# =========================================================================


class TestFS61KnowledgeBaseSyncSchedule:
    """FS-61 — Knowledge Base Sync Schedule Check."""

    @patch("app.boto3.client")
    def test_pass_sync_rules_exist(self, mock_client):
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[{"knowledgeBaseId": "kb1"}],
                data_sources_by_kb={},
                data_source_detail={},
            )
        )

        def side_effect(service, **kwargs):
            if service == "events":
                c = MagicMock()
                c.list_rules.return_value = {
                    "Rules": [{"Name": "bedrock-kb-sync-daily"}]
                }
                return c
            if service == "scheduler":
                c = MagicMock()
                c.list_schedules.return_value = {"Schedules": []}
                return c
            return MagicMock()

        mock_client.side_effect = side_effect
        result = app.check_knowledge_base_sync_schedule(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    @patch("app.boto3.client")
    def test_pass_scheduler_schedule_exists(self, mock_client):
        # No legacy EventBridge rule, but an EventBridge Scheduler schedule targets
        # KB sync — the AWS-recommended approach must be detected (no false WARN).
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[{"knowledgeBaseId": "kb1"}],
                data_sources_by_kb={},
                data_source_detail={},
            )
        )

        def side_effect(service, **kwargs):
            if service == "events":
                c = MagicMock()
                c.list_rules.return_value = {"Rules": []}
                return c
            if service == "scheduler":
                c = MagicMock()
                c.list_schedules.return_value = {
                    "Schedules": [
                        {
                            "Name": "bedrock-kb-ingestion-daily",
                            "Target": {
                                "Arn": "arn:aws:lambda:us-east-1:1:function:sync"
                            },
                        }
                    ]
                }
                return c
            return MagicMock()

        mock_client.side_effect = side_effect
        result = app.check_knowledge_base_sync_schedule(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    @patch("app.boto3.client")
    def test_warn_no_sync_rules(self, mock_client):
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[{"knowledgeBaseId": "kb1"}],
                data_sources_by_kb={},
                data_source_detail={},
            )
        )

        def side_effect(service, **kwargs):
            if service == "events":
                c = MagicMock()
                c.list_rules.return_value = {"Rules": [{"Name": "unrelated-rule"}]}
                return c
            if service == "scheduler":
                c = MagicMock()
                c.list_schedules.return_value = {
                    "Schedules": [
                        {"Name": "unrelated-schedule", "Target": {"Arn": "x"}}
                    ]
                }
                return c
            return MagicMock()

        mock_client.side_effect = side_effect
        result = app.check_knowledge_base_sync_schedule(inv)
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    @patch("app.boto3.client")
    def test_scheduler_access_denied_falls_back_to_rules(self, mock_client):
        # scheduler:ListSchedules denied → fall back to EventBridge rules only,
        # do NOT error the whole check.
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[{"knowledgeBaseId": "kb1"}],
                data_sources_by_kb={},
                data_source_detail={},
            )
        )

        def side_effect(service, **kwargs):
            if service == "events":
                c = MagicMock()
                c.list_rules.return_value = {
                    "Rules": [{"Name": "bedrock-kb-sync-daily"}]
                }
                return c
            if service == "scheduler":
                c = MagicMock()
                c.list_schedules.side_effect = _client_error("AccessDeniedException")
                return c
            return MagicMock()

        mock_client.side_effect = side_effect
        result = app.check_knowledge_base_sync_schedule(inv)
        _assert_finding_structure(result)
        # EventBridge rule still matched → PASS despite scheduler access denial.
        assert result["status"] == "PASS"

    @patch("app.boto3.client")
    def test_scheduler_access_denied_no_rules_could_not_assess(self, mock_client):
        """REQ-11/A3: scheduler:ListSchedules denied AND no matching EventBridge
        rule → we cannot conclude absence → COULD_NOT_ASSESS (check returns ERROR
        so the handler synthesizes the N/A row), NOT a false Failed."""
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[{"knowledgeBaseId": "kb1"}],
                data_sources_by_kb={},
                data_source_detail={},
            )
        )

        def side_effect(service, **kwargs):
            if service == "events":
                c = MagicMock()
                c.list_rules.return_value = {"Rules": []}
                return c
            if service == "scheduler":
                c = MagicMock()
                c.list_schedules.side_effect = _client_error("AccessDeniedException")
                return c
            return MagicMock()

        mock_client.side_effect = side_effect
        result = app.check_knowledge_base_sync_schedule(inv)
        # Re-raised access error → ERROR envelope (handler → COULD NOT ASSESS row).
        assert result["status"] == "ERROR"
        assert not any(r.get("Status") == "Failed" for r in result.get("csv_data", []))

    def test_error_on_unavailable_inventory(self):
        inv = make_resource_inventory(
            knowledge_bases=app._Unavailable(RuntimeError("sync error"))
        )
        result = app.check_knowledge_base_sync_schedule(inv)
        assert result["status"] == "ERROR"


class TestFS62DataCurrencyDisclaimer:
    """FS-62 — Advisory check (no AWS API calls)."""

    def test_returns_valid_structure(self):
        result = app.check_data_currency_disclaimer_advisory()
        _assert_finding_structure(result)
        assert result["status"] == "PASS"
        _assert_advisory_retag(result, "FS-62")
        assert result["csv_data"][0]["Check_ID"] == "FS-62"


class TestFS63FoundationModelLifecyclePolicy:
    """FS-63 — Foundation Model Lifecycle Policy Check."""

    @patch("app.boto3.client")
    def test_pass_no_legacy_models(self, mock_client):
        c = MagicMock()
        c.list_foundation_models.return_value = {
            "modelSummaries": [
                {
                    "modelId": "anthropic.claude-v2",
                    "modelLifecycle": {"status": "ACTIVE"},
                }
            ]
        }
        c.describe_config_rules.return_value = {"ConfigRules": []}
        mock_client.return_value = c
        result = app.check_foundation_model_lifecycle_policy()
        _assert_finding_structure(result)

    @patch("app.boto3.client")
    def test_warn_legacy_models_no_rules(self, mock_client):
        c = MagicMock()
        c.list_foundation_models.return_value = {
            "modelSummaries": [
                {"modelId": "old-model-v1", "modelLifecycle": {"status": "LEGACY"}}
            ]
        }
        c.describe_config_rules.return_value = {"ConfigRules": []}
        mock_client.return_value = c
        result = app.check_foundation_model_lifecycle_policy()
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("lifecycle error")
        result = app.check_foundation_model_lifecycle_policy()
        assert result["status"] == "ERROR"


# =========================================================================
# MATERIAL GAP CHECKS (FS-65 to FS-69)
# =========================================================================


class TestFS65KbDatasourceS3EventNotifications:
    """FS-65 — KB Data Source S3 Event Notifications Check."""

    def test_na_no_kbs(self):
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[], data_sources_by_kb={}, data_source_detail={}
            )
        )
        result = app.check_kb_datasource_s3_event_notifications(inv)
        _assert_finding_structure(result)
        assert any(r["Status"] == "N/A" for r in result["csv_data"])

    @patch("app.boto3.client")
    def test_pass_notifications_configured(self, mock_client):
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[{"knowledgeBaseId": "kb1"}],
                data_sources_by_kb={"kb1": [{"dataSourceId": "ds1", "name": "s3-src"}]},
                data_source_detail={
                    ("kb1", "ds1"): {
                        "dataSource": {
                            "dataSourceConfiguration": {
                                "s3Configuration": {
                                    "bucketArn": "arn:aws:s3:::my-kb-bucket"
                                }
                            }
                        }
                    }
                },
            )
        )

        def side_effect(service, **kwargs):
            if service == "s3":
                c = MagicMock()
                c.get_bucket_notification_configuration.return_value = {
                    "EventBridgeConfiguration": {"EventBridgeEnabled": True}
                }
                return c
            return MagicMock()

        mock_client.side_effect = side_effect
        result = app.check_kb_datasource_s3_event_notifications(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    @patch("app.boto3.client")
    def test_warn_no_notifications(self, mock_client):
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[{"knowledgeBaseId": "kb1"}],
                data_sources_by_kb={"kb1": [{"dataSourceId": "ds1", "name": "s3-src"}]},
                data_source_detail={
                    ("kb1", "ds1"): {
                        "dataSource": {
                            "dataSourceConfiguration": {
                                "s3Configuration": {
                                    "bucketArn": "arn:aws:s3:::my-kb-bucket"
                                }
                            }
                        }
                    }
                },
            )
        )

        def side_effect(service, **kwargs):
            if service == "s3":
                c = MagicMock()
                c.get_bucket_notification_configuration.return_value = {}
                return c
            return MagicMock()

        mock_client.side_effect = side_effect
        result = app.check_kb_datasource_s3_event_notifications(inv)
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    def test_error_on_unavailable_inventory(self):
        inv = make_resource_inventory(
            knowledge_bases=app._Unavailable(RuntimeError("s3 event error"))
        )
        result = app.check_kb_datasource_s3_event_notifications(inv)
        assert result["status"] == "ERROR"


class TestFS66AgentcoreEndUserIdentityPropagation:
    """FS-66 — AgentCore End-User Identity Propagation Check."""

    @patch("app.boto3.client")
    def test_pass_authorizer_configured(self, mock_client):
        c = MagicMock()
        c.list_agent_runtimes.return_value = {
            "agentRuntimes": [
                {
                    "agentRuntimeName": "rt1",
                    "authorizerConfiguration": {
                        "customJWTAuthorizer": {"issuerUrl": "https://example.com"}
                    },
                }
            ]
        }
        mock_client.return_value = c
        result = app.check_agentcore_end_user_identity_propagation()
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    @patch("app.boto3.client")
    def test_warn_no_authorizer(self, mock_client):
        c = MagicMock()
        c.list_agent_runtimes.return_value = {
            "agentRuntimes": [
                {"agentRuntimeName": "rt1", "authorizerConfiguration": {}}
            ]
        }
        mock_client.return_value = c
        result = app.check_agentcore_end_user_identity_propagation()
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    @patch("app.boto3.client")
    def test_access_denied_returns_na(self, mock_client):
        c = MagicMock()
        c.list_agent_runtimes.side_effect = _client_error("AccessDeniedException")
        mock_client.return_value = c
        result = app.check_agentcore_end_user_identity_propagation()
        _assert_finding_structure(result)
        assert any(r["Status"] == "N/A" for r in result["csv_data"])

    @patch("app.boto3.client")
    def test_error_on_exception(self, mock_client):
        mock_client.side_effect = RuntimeError("identity error")
        result = app.check_agentcore_end_user_identity_propagation()
        assert result["status"] == "ERROR"


class TestFS67AgentFinancialTransactionThresholds:
    """FS-67 — Agent Financial Transaction Value Thresholds Check."""

    def test_pass_threshold_env_vars(self):
        inv = make_resource_inventory(
            lambda_functions=[
                {
                    "FunctionName": "agent-transaction-handler",
                    "Environment": {"Variables": {"MAX_TRANSACTION_AMOUNT": "10000"}},
                }
            ]
        )
        result = app.check_agent_financial_transaction_thresholds(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    def test_warn_no_threshold_env_vars(self):
        inv = make_resource_inventory(
            lambda_functions=[
                {
                    "FunctionName": "agent-transaction-handler",
                    "Environment": {"Variables": {"LOG_LEVEL": "INFO"}},
                }
            ]
        )
        result = app.check_agent_financial_transaction_thresholds(inv)
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    def test_na_no_agent_lambdas(self):
        inv = make_resource_inventory(
            lambda_functions=[{"FunctionName": "unrelated-function"}]
        )
        result = app.check_agent_financial_transaction_thresholds(inv)
        _assert_finding_structure(result)
        assert any(r["Status"] == "N/A" for r in result["csv_data"])

    def test_error_on_unavailable_inventory(self):
        inv = make_resource_inventory(
            lambda_functions=app._Unavailable(RuntimeError("transaction error"))
        )
        result = app.check_agent_financial_transaction_thresholds(inv)
        assert result["status"] == "ERROR"


class TestFS68ApiGatewayRequestBodySizeLimits:
    """FS-68 — API Gateway Request Body Size Limits Check."""

    def _size_constraint_detail(self):
        return {
            "Rules": [
                {
                    "Name": "body-size-rule",
                    "Statement": {
                        "SizeConstraintStatement": {
                            "FieldToMatch": {"Body": {}},
                            "ComparisonOperator": "LE",
                            "Size": 8192,
                        }
                    },
                }
            ]
        }

    def test_pass_validators_and_waf_rules(self):
        """API with maxLength model + WAF ACL with SizeConstraint → PASS."""
        acl_detail = self._size_constraint_detail()
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(
                summaries=[{"Name": "acl1", "Id": "id1"}],
                detail_by_id={"id1": acl_detail},
            )
        )
        with patch("app.boto3.client") as mock_client:

            def side_effect(service, **kwargs):
                if service == "apigateway":
                    c = MagicMock()
                    c.get_rest_apis.return_value = {
                        "items": [{"id": "api1", "name": "genai-api"}]
                    }
                    c.get_request_validators.return_value = {
                        "items": [{"id": "v1", "name": "body-validator"}]
                    }
                    return c
                return MagicMock()

            mock_client.side_effect = side_effect
            result = app.check_api_gateway_request_body_size_limits(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    def test_na_no_rest_apis_no_waf(self):
        """REQ-4: zero REST APIs AND zero WAF ACLs → N/A (not a false Passed)."""
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(summaries=[], detail_by_id={})
        )
        with patch("app.boto3.client") as mock_client:

            def side_effect(service, **kwargs):
                if service == "apigateway":
                    c = MagicMock()
                    c.get_rest_apis.return_value = {"items": []}
                    return c
                return MagicMock()

            mock_client.side_effect = side_effect
            result = app.check_api_gateway_request_body_size_limits(inv)
        _assert_finding_structure(result)
        assert any(
            r["Finding"] == "API Gateway Request Body Size Limits — Not Applicable"
            and r["Status"] == "N/A"
            and r["Severity"] == "Informational"
            for r in result["csv_data"]
        )
        assert not any(r["Status"] == "Passed" for r in result["csv_data"])

    def test_fail_rest_api_without_validator(self):
        """REST API exists but has no request validator → Failed/Medium."""
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(summaries=[], detail_by_id={})
        )
        with patch("app.boto3.client") as mock_client:

            def side_effect(service, **kwargs):
                if service == "apigateway":
                    c = MagicMock()
                    c.get_rest_apis.return_value = {
                        "items": [{"id": "api1", "name": "genai-api"}]
                    }
                    c.get_request_validators.return_value = {"items": []}
                    return c
                return MagicMock()

            mock_client.side_effect = side_effect
            result = app.check_api_gateway_request_body_size_limits(inv)
        _assert_finding_structure(result)
        assert any(
            r["Finding"] == "API Gateway Request Body Size Limits Not Enforced"
            and r["Status"] == "Failed"
            and r["Severity"] == "Medium"
            for r in result["csv_data"]
        )

    def test_validator_presence_without_size_model_not_passed(self):
        """REQ-11/A1: validator without maxLength bound → Failed, not Passed."""
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(summaries=[], detail_by_id={})
        )
        with patch("app.boto3.client") as mock_client:

            def side_effect(service, **kwargs):
                if service == "apigateway":
                    c = MagicMock()
                    c.get_rest_apis.return_value = {
                        "items": [{"id": "api1", "name": "genai-api"}]
                    }
                    c.get_request_validators.return_value = {
                        "items": [
                            {
                                "id": "v1",
                                "name": "body-validator",
                                "validateRequestBody": True,
                            }
                        ]
                    }
                    c.get_models.return_value = {
                        "items": [{"name": "Empty", "schema": '{"type":"object"}'}]
                    }
                    return c
                return MagicMock()

            mock_client.side_effect = side_effect
            result = app.check_api_gateway_request_body_size_limits(inv)
        _assert_finding_structure(result)
        assert not any(r["Status"] == "Passed" for r in result["csv_data"])
        assert any(
            r["Finding"] == "API Gateway Request Body Size Limits Not Enforced"
            and r["Status"] == "Failed"
            for r in result["csv_data"]
        )

    def test_validator_with_maxlength_model_passed(self):
        """REQ-11/A1: validator with maxLength model IS a real size control → Passed."""
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(summaries=[], detail_by_id={})
        )
        with patch("app.boto3.client") as mock_client:

            def side_effect(service, **kwargs):
                if service == "apigateway":
                    c = MagicMock()
                    c.get_rest_apis.return_value = {
                        "items": [{"id": "api1", "name": "genai-api"}]
                    }
                    c.get_request_validators.return_value = {
                        "items": [{"id": "v1", "validateRequestBody": True}]
                    }
                    c.get_models.return_value = {
                        "items": [
                            {
                                "name": "Prompt",
                                "schema": '{"type":"object","properties":{"prompt":{"type":"string","maxLength":4000}}}',
                            }
                        ]
                    }
                    return c
                return MagicMock()

            mock_client.side_effect = side_effect
            result = app.check_api_gateway_request_body_size_limits(inv)
        _assert_finding_structure(result)
        assert any(
            r["Finding"] == "API Gateway Request Body Size Limits Configured"
            and r["Status"] == "Passed"
            for r in result["csv_data"]
        )

    def test_waf_oversize_constraint_above_window_not_credited(self):
        """REQ-11/A2: GT body SizeConstraint above 16 KB with CONTINUE oversize → not credited → Failed."""
        bad_detail = {
            "Rules": [
                {
                    "Name": "too-big",
                    "Statement": {
                        "SizeConstraintStatement": {
                            "FieldToMatch": {"Body": {"OversizeHandling": "CONTINUE"}},
                            "ComparisonOperator": "GT",
                            "Size": 32768,
                        }
                    },
                }
            ]
        }
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(
                summaries=[{"Name": "acl1", "Id": "id1"}],
                detail_by_id={"id1": bad_detail},
            )
        )
        with patch("app.boto3.client") as mock_client:

            def side_effect(service, **kwargs):
                if service == "apigateway":
                    c = MagicMock()
                    c.get_rest_apis.return_value = {
                        "items": [{"id": "api1", "name": "genai-api"}]
                    }
                    c.get_request_validators.return_value = {"items": []}
                    c.get_models.return_value = {"items": []}
                    return c
                return MagicMock()

            mock_client.side_effect = side_effect
            result = app.check_api_gateway_request_body_size_limits(inv)
        _assert_finding_structure(result)
        assert not any(r["Status"] == "Passed" for r in result["csv_data"])
        assert any(r["Status"] == "Failed" for r in result["csv_data"])

    def test_waf_body_substring_rule_not_credited(self):
        """REQ-11/A2: XSS match on body is NOT a SizeConstraint → not credited."""
        xss_detail = {
            "Rules": [
                {
                    "Name": "xss-on-body",
                    "Statement": {
                        "XssMatchStatement": {
                            "FieldToMatch": {"Body": {}},
                            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        }
                    },
                }
            ]
        }
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(
                summaries=[{"Name": "acl1", "Id": "id1"}],
                detail_by_id={"id1": xss_detail},
            )
        )
        with patch("app.boto3.client") as mock_client:

            def side_effect(service, **kwargs):
                if service == "apigateway":
                    c = MagicMock()
                    c.get_rest_apis.return_value = {
                        "items": [{"id": "api1", "name": "genai-api"}]
                    }
                    c.get_request_validators.return_value = {"items": []}
                    c.get_models.return_value = {"items": []}
                    return c
                return MagicMock()

            mock_client.side_effect = side_effect
            result = app.check_api_gateway_request_body_size_limits(inv)
        _assert_finding_structure(result)
        assert not any(r["Status"] == "Passed" for r in result["csv_data"])

    def test_error_on_unavailable_inventory(self):
        """Unavailable inventory → COULD_NOT_ASSESS (ERROR envelope)."""
        inv = make_resource_inventory(
            web_acls=app._Unavailable(RuntimeError("apigw error"))
        )
        with patch("app.boto3.client") as mock_client:

            def side_effect(service, **kwargs):
                if service == "apigateway":
                    c = MagicMock()
                    c.get_rest_apis.return_value = {"items": []}
                    return c
                return MagicMock()

            mock_client.side_effect = side_effect
            result = app.check_api_gateway_request_body_size_limits(inv)
        assert result["status"] == "ERROR"

    def test_error_on_apigw_exception(self):
        """apigateway client raises → overall ERROR."""
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(summaries=[], detail_by_id={})
        )
        with patch("app.boto3.client") as mock_client:
            mock_client.side_effect = RuntimeError("apigw error")
            result = app.check_api_gateway_request_body_size_limits(inv)
        assert result["status"] == "ERROR"

    # --- Pagination-correctness proof: >100 ACLs ---
    def test_pass_more_than_100_acls_with_size_constraints(self):
        """150 ACLs all with SizeConstraint → PASS (previously truncated ACLs now assessed)."""
        acl_detail = self._size_constraint_detail()
        summaries = [{"Name": f"acl{i}", "Id": f"id{i}"} for i in range(150)]
        detail_by_id = {f"id{i}": acl_detail for i in range(150)}
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(summaries=summaries, detail_by_id=detail_by_id)
        )
        with patch("app.boto3.client") as mock_client:

            def side_effect(service, **kwargs):
                if service == "apigateway":
                    c = MagicMock()
                    c.get_rest_apis.return_value = {"items": []}
                    return c
                return MagicMock()

            mock_client.side_effect = side_effect
            result = app.check_api_gateway_request_body_size_limits(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    # --- ≤1-page equivalence: 2-ACL case matches Wave-0 baseline ---
    def test_two_acl_case_unchanged(self):
        """The 2-ACL PASS scenario is unchanged vs the pre-refactor baseline."""
        from test_inventory_equivalence import _acl_detail as _baseline_acl_detail

        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(
                summaries=[
                    {"Name": "FinServACL1", "Id": "acl-id-001"},
                    {"Name": "FinServACL2", "Id": "acl-id-002"},
                ],
                detail_by_id={
                    "acl-id-001": _baseline_acl_detail("FinServACL1", "acl-id-001")[
                        "WebACL"
                    ],
                    "acl-id-002": _baseline_acl_detail("FinServACL2", "acl-id-002")[
                        "WebACL"
                    ],
                },
            )
        )
        with patch("app.boto3.client") as mock_client:

            def side_effect(service, **kwargs):
                if service == "apigateway":
                    c = MagicMock()
                    c.get_rest_apis.return_value = {"items": []}
                    return c
                return MagicMock()

            mock_client.side_effect = side_effect
            result = app.check_api_gateway_request_body_size_limits(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"
        assert any(
            r["Finding"] == "API Gateway Request Body Size Limits Configured"
            for r in result["csv_data"]
        )


class TestFS69PromptInputValidationFunction:
    """FS-69 — Prompt Input Validation Function Check."""

    def test_pass_validation_lambda_exists(self):
        inv = make_resource_inventory(
            lambda_functions=[{"FunctionName": "prompt-input-sanitizer"}]
        )
        result = app.check_prompt_input_validation_function(inv)
        _assert_finding_structure(result)
        assert result["status"] == "PASS"

    def test_warn_no_validation_lambda(self):
        inv = make_resource_inventory(
            lambda_functions=[{"FunctionName": "my-api-handler"}]
        )
        result = app.check_prompt_input_validation_function(inv)
        _assert_finding_structure(result)
        assert result["status"] == "WARN"

    def test_error_on_unavailable_inventory(self):
        inv = make_resource_inventory(
            lambda_functions=app._Unavailable(RuntimeError("input error"))
        )
        result = app.check_prompt_input_validation_function(inv)
        assert result["status"] == "ERROR"


# =========================================================================
# HELPERS
# =========================================================================


class TestHelpers:
    """Test _empty_findings and _error_findings helpers."""

    def test_empty_findings_structure(self):
        result = app._empty_findings("Test Check")
        assert result["check_name"] == "Test Check"
        assert result["status"] == "PASS"
        assert result["csv_data"] == []

    def test_error_findings_structure(self):
        err = RuntimeError("something broke")
        result = app._error_findings("Test Check", err)
        assert result["check_name"] == "Test Check"
        assert result["status"] == "ERROR"
        assert "something broke" in result["details"]
        # REQ-13: _error_findings contract is unchanged (csv_data stays empty);
        # the visible row is synthesized by the handler, not here.
        assert result["csv_data"] == []

    def test_could_not_assess_row_shape(self):
        # COULD_NOT_ASSESS disposition: synthesized row is N/A + Low (methodology §3.4).
        row = app._could_not_assess_row(
            "FS-44", "Amazon Macie PII Scanning Check", "AccessDenied"
        )
        assert row["Check_ID"] == "FS-44"
        assert row["Status"] == "N/A"
        assert row["Severity"] == "Low"
        assert row["Finding"].startswith(app.COULD_NOT_ASSESS_PREFIX)
        assert "AccessDenied" in row["Finding_Details"]


# =========================================================================
# REQ-13: CHECK REGISTRY + COULD-NOT-ASSESS HANDLING
# =========================================================================


class TestFinservChecksRegistry:
    """REQ-13 — registry-driven dispatch and could-not-assess rows."""

    def test_registry_covers_all_checks_in_order(self):
        registry = app.build_finserv_checks(
            {"role_permissions": {}, "user_permissions": {}}
        )
        # 65 entries: 64 standalone checks (FS-17/18/19/23/64 merged upstream)
        # plus the new check_automated_reasoning_policies() which shares the FS-27
        # check_id with check_guardrail_contextual_grounding().
        assert len(registry) == 65
        ids = [cid for cid, _ in registry]
        # FS-27 appears twice (contextual grounding + ARC policies); allow that.
        unique_ids = set(ids)
        assert len(unique_ids) == 64
        for cid, fn in registry:
            assert callable(fn), f"{cid} is not callable"
        # Order is non-decreasing by numeric FS id (execution order preserved).
        nums = [int(cid.split("-")[1]) for cid in ids]
        assert nums == sorted(nums)
        # The two permission-cache checks are present.
        assert "FS-07" in ids and "FS-22" in ids

    @patch("app.write_to_s3", return_value="https://example.com/report.csv")
    @patch.dict(os.environ, {"AIML_ASSESSMENT_BUCKET_NAME": "test-bucket"})
    @patch("app.get_permissions_cache", return_value=None)
    @patch("app.build_finserv_checks")
    def test_errored_check_emits_could_not_assess_row(
        self, mock_build, mock_cache, mock_write
    ):
        # One check raises (uncaught) → handler synthesizes one could-not-assess row.
        def boom():
            return app._error_findings("Boom Check", RuntimeError("AccessDenied: nope"))

        def normal():
            return {
                "check_name": "Normal Check",
                "status": "PASS",
                "csv_data": [
                    {
                        "Check_ID": "FS-02",
                        "Finding": "Normal Finding",
                        "Finding_Details": "ok",
                        "Resolution": "none",
                        "Reference": "https://example.com",
                        "Severity": "Informational",
                        "Status": "Passed",
                    }
                ],
            }

        mock_build.return_value = [("FS-44", boom), ("FS-02", normal)]

        resp = app.lambda_handler({"Execution": {"Name": "exec-1"}}, None)
        findings = resp["body"]["findings"]
        # Errored check now contributes exactly one row, not zero (no silent drop).
        boom_result = next(f for f in findings if f["check_name"] == "Boom Check")
        assert len(boom_result["csv_data"]) == 1
        row = boom_result["csv_data"][0]
        assert row["Check_ID"] == "FS-44"
        assert row["Status"] == "N/A"
        assert row["Severity"] == "Low"
        assert row["Finding"].startswith(app.COULD_NOT_ASSESS_PREFIX)
        # Normal check passes through unchanged (no spurious row added).
        normal_result = next(f for f in findings if f["check_name"] == "Normal Check")
        assert len(normal_result["csv_data"]) == 1
        assert normal_result["csv_data"][0]["Finding"] == "Normal Finding"

    @patch("app.write_to_s3", return_value="https://example.com/report.csv")
    @patch.dict(os.environ, {"AIML_ASSESSMENT_BUCKET_NAME": "test-bucket"})
    @patch("app.get_permissions_cache", return_value=None)
    @patch("app.build_finserv_checks")
    def test_non_error_empty_result_still_emits_could_not_assess_row(
        self, mock_build, mock_cache, mock_write
    ):
        # A check that returns a NON-error wrapper status but zero csv_data must
        # NOT silently vanish — the handler synthesizes a could-not-assess row for
        # any empty result, not only ERROR ones. This guards the no-silent-drop
        # invariant structurally (Property 7) rather than by data coincidence.
        def empty_pass():
            return {"check_name": "Empty Pass Check", "status": "PASS", "csv_data": []}

        mock_build.return_value = [("FS-13", empty_pass)]

        resp = app.lambda_handler({"Execution": {"Name": "exec-3"}}, None)
        findings = resp["body"]["findings"]
        result = next(f for f in findings if f["check_name"] == "Empty Pass Check")
        assert len(result["csv_data"]) == 1
        row = result["csv_data"][0]
        assert row["Check_ID"] == "FS-13"
        assert row["Status"] == "N/A"
        assert row["Severity"] == "Low"
        assert row["Finding"].startswith(app.COULD_NOT_ASSESS_PREFIX)

    @patch("app.write_to_s3", return_value="https://example.com/report.csv")
    @patch.dict(os.environ, {"AIML_ASSESSMENT_BUCKET_NAME": "test-bucket"})
    @patch("app.get_permissions_cache", return_value=None)
    def test_no_check_contributes_zero_rows(self, mock_cache, mock_write):
        # Full handler run with mocked AWS (all clients raise) — every check must
        # still contribute at least one row (real rows or a could-not-assess row).
        with patch("app.boto3.client", side_effect=RuntimeError("AccessDenied")):
            resp = app.lambda_handler({"Execution": {"Name": "exec-2"}}, None)
        findings = resp["body"]["findings"]
        for f in findings:
            assert len(f["csv_data"]) >= 1, f"{f['check_name']} contributed zero rows"


# =========================================================================
# _paginate helper — multi-page collection across token conventions
# =========================================================================


class TestPaginateHelper:
    """app._paginate must collect all pages regardless of the API's token field."""

    def test_single_page(self):
        c = MagicMock()
        c.list_things.return_value = {"items": [{"a": 1}, {"a": 2}]}
        out = app._paginate(c, "list_things", "items")
        assert out == [{"a": 1}, {"a": 2}]
        assert c.list_things.call_count == 1

    def test_lambda_marker_pagination(self):
        # Lambda uses Marker (request) / NextMarker (response).
        c = MagicMock()
        c.list_functions.side_effect = [
            {"Functions": [{"FunctionName": "f1"}], "NextMarker": "m1"},
            {"Functions": [{"FunctionName": "f2"}]},
        ]
        out = app._paginate(c, "list_functions", "Functions")
        assert [f["FunctionName"] for f in out] == ["f1", "f2"]
        assert c.list_functions.call_count == 2
        _, kwargs = c.list_functions.call_args
        assert kwargs.get("Marker") == "m1"

    def test_next_token_lowercase_pagination(self):
        # Bedrock uses nextToken.
        c = MagicMock()
        c.list_guardrails.side_effect = [
            {"guardrails": [{"id": "g1"}], "nextToken": "t1"},
            {"guardrails": [{"id": "g2"}]},
        ]
        out = app._paginate(c, "list_guardrails", "guardrails")
        assert [g["id"] for g in out] == ["g1", "g2"]

    def test_apigateway_position_pagination(self):
        # API Gateway uses position (request and response).
        c = MagicMock()
        c.get_usage_plans.side_effect = [
            {"items": [{"id": "p1"}], "position": "pos1"},
            {"items": [{"id": "p2"}]},
        ]
        out = app._paginate(c, "get_usage_plans", "items")
        assert [p["id"] for p in out] == ["p1", "p2"]

    def test_missing_result_key_returns_empty(self):
        c = MagicMock()
        c.list_things.return_value = {}
        assert app._paginate(c, "list_things", "items") == []


class TestIsAccessError:
    """app._is_access_error classifies permission errors vs other ClientErrors."""

    def test_access_denied_is_access_error(self):
        assert app._is_access_error(_client_error("AccessDenied")) is True
        assert app._is_access_error(_client_error("AccessDeniedException")) is True
        assert app._is_access_error(_client_error("UnauthorizedOperation")) is True

    def test_other_clienterror_is_not_access_error(self):
        assert app._is_access_error(_client_error("NoSuchTagSet")) is False
        assert app._is_access_error(_client_error("NoSuchBucket")) is False

    def test_non_clienterror_is_not_access_error(self):
        # A plain exception without a .response attribute must not be misclassified.
        assert app._is_access_error(RuntimeError("boom")) is False


class TestIsMissingBucketError:
    """app._is_missing_bucket_error classifies deleted-bucket errors (NoSuchBucket /
    404 / NotFound) distinctly from access errors and other ClientErrors."""

    def test_nosuchbucket_is_missing(self):
        assert app._is_missing_bucket_error(_client_error("NoSuchBucket")) is True
        assert app._is_missing_bucket_error(_client_error("404")) is True
        assert app._is_missing_bucket_error(_client_error("NotFound")) is True

    def test_access_and_other_errors_are_not_missing(self):
        assert app._is_missing_bucket_error(_client_error("AccessDenied")) is False
        assert app._is_missing_bucket_error(_client_error("InvalidRequest")) is False
        assert app._is_missing_bucket_error(_client_error("NoSuchTagSet")) is False

    def test_non_clienterror_is_not_missing(self):
        assert app._is_missing_bucket_error(RuntimeError("boom")) is False


# =========================================================================
# REQ-14: REQUIREMENTS.TXT VERSION FLOOR GUARD
# =========================================================================


class TestRequirementVersionFloors:
    """
    REQ-14 — Guard against future regression that lowers the botocore/boto3 floor
    below the minimum needed for:
      - FS-03: list_aws_default_service_quotas paginator
      - FS-06: describe_budgets(ShowFilterExpression=True)

    Tests assert the floor in requirements.txt, not the installed version, so
    they catch a source-file regression regardless of what pip has resolved in
    the dev environment. The dev environment may be behind the floor
    (e.g., 1.42.70 installed vs 1.43.21 required) — run
    `pip install --upgrade boto3 botocore` to reach the floor.

    These tests do NOT hard-pin to 1.43.21; they assert a structural property
    (floor >= minimum needed) so they stay valid as the floor is bumped over time.
    """

    # Minimum versions required for the features used in this Lambda.
    # Chosen because 1.43.x is the first series that reliably supports both
    # describe_budgets(ShowFilterExpression=True) and list_aws_default_service_quotas.
    MIN_BOTO3 = (1, 43, 0)
    MIN_BOTOCORE = (1, 43, 0)

    @staticmethod
    def _parse_floor(line: str) -> tuple:
        """
        Parse a 'pkg>=X.Y.Z' line from requirements.txt into (X, Y, Z).
        Returns None if the line doesn't match the expected pattern.
        """
        import re

        m = re.match(r"^\s*(boto[3core]*)\s*>=\s*(\d+)\.(\d+)\.(\d+)", line)
        if m:
            return (int(m.group(2)), int(m.group(3)), int(m.group(4)))
        return None

    @staticmethod
    def _load_requirements() -> str:
        """Load finserv_assessments/requirements.txt relative to the tests/ dir."""
        req_path = os.path.join(
            os.path.dirname(__file__), "..", "finserv_assessments", "requirements.txt"
        )
        with open(req_path) as f:
            return f.read()

    def test_boto3_floor_meets_minimum(self):
        """requirements.txt must floor boto3 at >= 1.43.0."""
        content = self._load_requirements()
        boto3_floor = None
        for line in content.splitlines():
            if line.strip().startswith("boto3>="):
                boto3_floor = self._parse_floor(line)
                break
        assert boto3_floor is not None, (
            "boto3 floor not found in requirements.txt — expected 'boto3>=X.Y.Z'"
        )
        assert boto3_floor >= self.MIN_BOTO3, (
            f"boto3 floor {boto3_floor} is below minimum {self.MIN_BOTO3}; "
            "FS-06 describe_budgets(ShowFilterExpression=True) requires boto3>=1.43.0. "
            "Bump the floor in finserv_assessments/requirements.txt."
        )

    def test_botocore_floor_meets_minimum(self):
        """requirements.txt must floor botocore at >= 1.43.0."""
        content = self._load_requirements()
        botocore_floor = None
        for line in content.splitlines():
            if line.strip().startswith("botocore>="):
                botocore_floor = self._parse_floor(line)
                break
        assert botocore_floor is not None, (
            "botocore floor not found in requirements.txt — expected 'botocore>=X.Y.Z'"
        )
        assert botocore_floor >= self.MIN_BOTOCORE, (
            f"botocore floor {botocore_floor} is below minimum {self.MIN_BOTOCORE}; "
            "FS-03 list_aws_default_service_quotas and FS-06 ShowFilterExpression "
            "require botocore>=1.43.0. Bump the floor in finserv_assessments/requirements.txt."
        )

    def test_pydantic_floor_present(self):
        """pydantic>=2.0.0 must be present and unchanged (schema depends on Pydantic v2)."""
        content = self._load_requirements()
        assert "pydantic>=2.0.0" in content, (
            "pydantic>=2.0.0 not found in requirements.txt — Pydantic v2 is required "
            "for the Finding model in schema.py."
        )

    def test_no_exact_pins_on_aws_sdk(self):
        """
        boto3 and botocore must use >= floors, not exact pins (==).
        Exact pins would block Lambda from resolving security patches.
        """
        content = self._load_requirements()
        import re

        exact_pins = re.findall(r"boto(?:3|core)==\S+", content)
        assert not exact_pins, (
            f"Exact version pins found for AWS SDK: {exact_pins}. "
            "Use >= floors instead so the Lambda can receive security patches."
        )


class TestFinservRegionalFootprint:
    """Regional footprint gating used to avoid false FinServ failures."""

    @staticmethod
    def _client_factory(clients):
        def factory(service_name, **kwargs):
            return clients[service_name]

        return factory

    @patch("app.boto3.client")
    def test_detect_returns_true_when_any_genai_resource_exists(self, mock_client):
        bedrock = MagicMock()
        bedrock.list_guardrails.return_value = {"guardrails": [{"id": "gr-1"}]}
        clients = {
            "bedrock": bedrock,
            "bedrock-agent": MagicMock(),
            "bedrock-agentcore-control": MagicMock(),
            "sagemaker": MagicMock(),
        }
        mock_client.side_effect = self._client_factory(clients)

        assert app.detect_finserv_regional_footprint("us-east-1") is True
        mock_client.assert_any_call(
            "bedrock", config=app.boto3_config, region_name="us-east-1"
        )

    @patch("app.boto3.client")
    def test_detect_returns_false_when_all_supported_probes_are_empty(
        self, mock_client
    ):
        bedrock = MagicMock()
        bedrock.list_guardrails.return_value = {"guardrails": []}
        bedrock_agent = MagicMock()
        bedrock_agent.list_agents.return_value = {"agentSummaries": []}
        bedrock_agent.list_knowledge_bases.return_value = {"knowledgeBaseSummaries": []}
        agentcore = MagicMock()
        agentcore.list_agent_runtimes.return_value = {"agentRuntimes": []}
        sagemaker = MagicMock()
        sagemaker.list_endpoints.return_value = {"Endpoints": []}
        sagemaker.list_models.return_value = {"Models": []}
        sagemaker.list_feature_groups.return_value = {"FeatureGroupSummaries": []}
        mock_client.side_effect = self._client_factory(
            {
                "bedrock": bedrock,
                "bedrock-agent": bedrock_agent,
                "bedrock-agentcore-control": agentcore,
                "sagemaker": sagemaker,
            }
        )

        assert app.detect_finserv_regional_footprint("us-west-2") is False

    @patch("app.boto3.client")
    def test_detect_returns_none_when_footprint_is_indeterminate(self, mock_client):
        bedrock = MagicMock()
        bedrock.list_guardrails.side_effect = _client_error("AccessDeniedException")
        bedrock_agent = MagicMock()
        bedrock_agent.list_agents.side_effect = _client_error("AccessDeniedException")
        bedrock_agent.list_knowledge_bases.side_effect = _client_error(
            "AccessDeniedException"
        )
        agentcore = MagicMock()
        agentcore.list_agent_runtimes.side_effect = _client_error(
            "AccessDeniedException"
        )
        sagemaker = MagicMock()
        sagemaker.list_endpoints.side_effect = _client_error("AccessDeniedException")
        sagemaker.list_models.side_effect = _client_error("AccessDeniedException")
        sagemaker.list_feature_groups.side_effect = _client_error(
            "AccessDeniedException"
        )
        mock_client.side_effect = self._client_factory(
            {
                "bedrock": bedrock,
                "bedrock-agent": bedrock_agent,
                "bedrock-agentcore-control": agentcore,
                "sagemaker": sagemaker,
            }
        )

        assert app.detect_finserv_regional_footprint("eu-west-1") is None

    @patch("app.detect_finserv_regional_footprint")
    def test_partition_keeps_indeterminate_regions_in_scope(self, mock_detect):
        mock_detect.side_effect = [None, False, True]

        assessable, empty = app._partition_regions_by_finserv_footprint(
            ["unknown-region", "empty-region", "active-region"]
        )

        assert assessable == ["unknown-region", "active-region"]
        assert empty == ["empty-region"]


class TestGenerateCsvReport:
    """Test CSV report generation."""

    def test_empty_findings_produces_header_only(self):
        csv_content = app.generate_csv_report([])
        lines = csv_content.strip().split("\n")
        assert len(lines) == 1  # header only
        assert "Check_ID" in lines[0]
        assert "Region" in lines[0]

    def test_findings_produce_csv_rows(self):
        findings = [
            {
                "check_name": "Test",
                "status": "PASS",
                "csv_data": [
                    {
                        "Check_ID": "FS-01",
                        "Finding": "Test Finding",
                        "Finding_Details": "Details",
                        "Resolution": "Fix",
                        "Reference": "https://example.com",
                        "Severity": "High",
                        "Status": "Passed",
                    }
                ],
            }
        ]
        csv_content = app.generate_csv_report(findings)
        lines = csv_content.strip().split("\n")
        assert len(lines) == 2  # header + 1 data row
        assert "FS-01" in lines[1]

    def test_region_scopes_use_configured_target_regions_from_event(self):
        event = {"Region": "fallback-region", "TargetRegions": ["region-a", "region-b"]}

        assert app._get_region_scopes(event) == ["region-a", "region-b"]

    def test_region_scopes_use_target_regions_env_when_event_list_absent(
        self, monkeypatch
    ):
        monkeypatch.setenv("TARGET_REGIONS", "region-a,region-b")

        assert app._get_region_scopes({"Region": "fallback-region"}) == [
            "region-a",
            "region-b",
        ]

    def test_stamp_regions_expands_missing_csv_regions(self):
        findings = [
            {
                "check_name": "Test",
                "status": "PASS",
                "csv_data": [
                    {
                        "Check_ID": "FS-01",
                        "Finding": "Test Finding",
                        "Finding_Details": "Details",
                        "Resolution": "Fix",
                        "Reference": "https://example.com",
                        "Severity": "High",
                        "Status": "Passed",
                    },
                    {
                        "Check_ID": "FS-02",
                        "Finding": "Already Scoped",
                        "Finding_Details": "Details",
                        "Resolution": "Fix",
                        "Reference": "https://example.com",
                        "Severity": "Medium",
                        "Status": "Failed",
                        "Region": "Global",
                    },
                ],
            }
        ]

        app._stamp_regions(findings, ["region-a", "region-b"])

        regions = [row["Region"] for row in findings[0]["csv_data"]]
        assert regions == ["region-a", "region-b", "Global"]

    def test_apply_region_scope_does_not_copy_failures_to_empty_regions(self):
        findings = [
            {
                "check_name": "Test",
                "status": "WARN",
                "csv_data": [
                    {
                        "Check_ID": "FS-01",
                        "Finding": "Test Failed Finding",
                        "Finding_Details": "Details",
                        "Resolution": "Fix",
                        "Reference": "https://example.com",
                        "Severity": "High",
                        "Status": "Failed",
                    }
                ],
            }
        ]

        with patch(
            "app._partition_regions_by_finserv_footprint",
            return_value=(["region-with-resources"], ["region-without-resources"]),
        ):
            app._apply_region_scope(
                findings, ["region-with-resources", "region-without-resources"]
            )

        rows = [row for finding in findings for row in finding["csv_data"]]
        failed_rows = [row for row in rows if row["Status"] == "Failed"]
        na_rows = [row for row in rows if row["Status"] == "N/A"]

        assert [row["Region"] for row in failed_rows] == ["region-with-resources"]
        assert [row["Region"] for row in na_rows] == ["region-without-resources"]
        assert na_rows[0]["Check_ID"] == "FS-00"

    def test_apply_region_scope_suppresses_unscoped_rows_when_all_regions_empty(self):
        findings = [
            {
                "check_name": "Test",
                "status": "WARN",
                "csv_data": [
                    {
                        "Check_ID": "FS-01",
                        "Finding": "Test Failed Finding",
                        "Finding_Details": "Details",
                        "Resolution": "Fix",
                        "Reference": "https://example.com",
                        "Severity": "High",
                        "Status": "Failed",
                    }
                ],
            }
        ]

        with patch(
            "app._partition_regions_by_finserv_footprint",
            return_value=([], ["region-a", "region-b"]),
        ):
            app._apply_region_scope(findings, ["region-a", "region-b"])

        rows = [row for finding in findings for row in finding["csv_data"]]

        assert {row["Region"] for row in rows} == {"region-a", "region-b"}
        assert {row["Status"] for row in rows} == {"N/A"}
        assert {row["Check_ID"] for row in rows} == {"FS-00"}

    def test_multiple_findings_multiple_rows(self):
        findings = [
            {
                "check_name": "Check A",
                "status": "WARN",
                "csv_data": [
                    {
                        "Check_ID": "FS-01",
                        "Finding": "A",
                        "Finding_Details": "D",
                        "Resolution": "R",
                        "Reference": "https://a.com",
                        "Severity": "High",
                        "Status": "Failed",
                    },
                    {
                        "Check_ID": "FS-01",
                        "Finding": "B",
                        "Finding_Details": "D",
                        "Resolution": "R",
                        "Reference": "https://b.com",
                        "Severity": "Medium",
                        "Status": "Passed",
                    },
                ],
            },
            {
                "check_name": "Check B",
                "status": "PASS",
                "csv_data": [
                    {
                        "Check_ID": "FS-02",
                        "Finding": "C",
                        "Finding_Details": "D",
                        "Resolution": "R",
                        "Reference": "https://c.com",
                        "Severity": "Low",
                        "Status": "Passed",
                    },
                ],
            },
        ]
        csv_content = app.generate_csv_report(findings)
        lines = csv_content.strip().split("\n")
        assert len(lines) == 4  # header + 3 data rows
