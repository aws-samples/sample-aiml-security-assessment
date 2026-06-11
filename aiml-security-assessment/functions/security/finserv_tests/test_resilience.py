"""
Resilience and partial-inventory tests for finserv_assessments/app.py.

Verifies:
  1. Single-inventory failure → only dependent checks emit COULD_NOT_ASSESS
     (status="ERROR", csv_data=[]), while all other checks produce normal dispositions.
  2. Multiple-inventory failure → each failure recorded independently, run completes.
  3. Multi-inventory independence (REQ-8): unavailability of one inventory does not
     affect checks that depend on a different inventory.

Validates: Requirements REQ-4.2, REQ-4.3, REQ-4.6, REQ-8
"""

import os
import sys
from unittest.mock import MagicMock, patch


FINSERV_DIR = os.path.join(os.path.dirname(__file__), "..", "finserv_assessments")
if FINSERV_DIR not in sys.path:
    sys.path.insert(0, FINSERV_DIR)

TESTS_DIR = os.path.dirname(__file__)
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

import app  # noqa: E402
from conftest import make_resource_inventory  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_could_not_assess(result: dict) -> bool:
    """Return True if the check result signals COULD_NOT_ASSESS:
    status="ERROR" and csv_data is empty (the handler will synthesize the
    COULD_NOT_ASSESS row from the empty csv_data — design DD-3)."""
    return result["status"] == "ERROR" and result["csv_data"] == []


def _is_normal_result(result: dict) -> bool:
    """Return True if the check produced a real disposition (not ERROR)."""
    return result["status"] in ("PASS", "WARN") or (
        result["status"] == "PASS" and isinstance(result["csv_data"], list)
    )


def _has_rows(result: dict) -> bool:
    """Return True if the check emitted at least one CSV row."""
    return bool(result.get("csv_data"))


def _make_shield_mock_no_subscription():
    """Build a mock shield client whose describe_subscription raises the
    ResourceNotFoundException subclass that FS-01 catches, so the check
    proceeds past the shield block and tests the WAFv2 inventory path."""

    class ResourceNotFoundException(Exception):
        """Minimal stand-in for botocore's ResourceNotFoundException."""

    class FakeExceptions:
        pass

    shield = MagicMock()
    FakeExceptions.ResourceNotFoundException = ResourceNotFoundException
    shield.exceptions = FakeExceptions
    shield.describe_subscription.side_effect = ResourceNotFoundException("no sub")
    return shield


# ---------------------------------------------------------------------------
# 1. Single-inventory failure — Lambda inventory
# ---------------------------------------------------------------------------


class TestLambdaInventoryUnavailable:
    """Lambda inventory unavailable → FS-09, FS-52, FS-55, FS-58, FS-67, FS-69
    become COULD_NOT_ASSESS; checks on other inventories are unaffected."""

    _ACCESS_DENIED = PermissionError("AccessDenied: lambda:ListFunctions")

    def _make_inv(self):
        return make_resource_inventory(
            lambda_functions=app._Unavailable(self._ACCESS_DENIED)
        )

    # --- FS-09 (check_agent_transaction_limits) ---
    def test_fs09_becomes_could_not_assess(self):
        """Validates: Requirements REQ-4.2"""
        result = app.check_agent_transaction_limits(self._make_inv())
        assert _is_could_not_assess(result), (
            f"Expected COULD_NOT_ASSESS but got status={result['status']!r}, "
            f"csv_data={result['csv_data']!r}"
        )

    # --- FS-52 (check_bedrock_sdk_version_currency) ---
    def test_fs52_becomes_could_not_assess(self):
        """Validates: Requirements REQ-4.2"""
        result = app.check_bedrock_sdk_version_currency(self._make_inv())
        assert _is_could_not_assess(result), (
            f"Expected COULD_NOT_ASSESS but got status={result['status']!r}"
        )

    # --- FS-55 (check_output_validation_lambda) ---
    def test_fs55_becomes_could_not_assess(self):
        """Validates: Requirements REQ-4.2"""
        result = app.check_output_validation_lambda(self._make_inv())
        assert _is_could_not_assess(result), (
            f"Expected COULD_NOT_ASSESS but got status={result['status']!r}"
        )

    # --- FS-58 (check_output_schema_validation) ---
    def test_fs58_becomes_could_not_assess(self):
        """Validates: Requirements REQ-4.2"""
        result = app.check_output_schema_validation(self._make_inv())
        assert _is_could_not_assess(result), (
            f"Expected COULD_NOT_ASSESS but got status={result['status']!r}"
        )

    # --- Guardrail check unaffected when lambda is unavailable ---
    def test_guardrail_check_unaffected(self):
        """REQ-4.3 / REQ-8: A guardrail check still produces a normal result
        when only the lambda inventory is unavailable."""
        inv = self._make_inv()
        result = app.check_guardrail_contextual_grounding(inv)
        # Empty guardrails → "No Guardrails" informational row (normal disposition)
        assert result["status"] != "ERROR", (
            "Guardrail check should not be affected by lambda inventory failure"
        )
        assert _has_rows(result)

    # --- WAFv2 check unaffected when lambda is unavailable ---
    def test_waf_check_unaffected(self):
        """REQ-4.3 / REQ-8: WAFv2 check is unaffected by lambda unavailability."""
        inv = self._make_inv()
        with patch(
            "app.boto3.client", return_value=_make_shield_mock_no_subscription()
        ):
            result = app.check_waf_shield_on_bedrock_endpoints(inv)
        assert result["status"] != "ERROR", (
            "WAFv2 check should not be affected by lambda inventory failure"
        )

    # --- S3 check unaffected when lambda is unavailable ---
    def test_s3_check_unaffected(self):
        """REQ-4.3 / REQ-8: S3 check is unaffected by lambda unavailability."""
        inv = self._make_inv()
        with patch("app.boto3.client") as mock_boto:
            mock_boto.return_value = MagicMock()
            result = app.check_training_data_s3_versioning(inv)
        assert result["status"] != "ERROR", (
            "S3 versioning check should not be affected by lambda inventory failure"
        )

    # --- KB check unaffected when lambda is unavailable ---
    def test_kb_check_unaffected(self):
        """REQ-4.3 / REQ-8: KB metadata check is unaffected by lambda unavailability."""
        inv = self._make_inv()
        result = app.check_knowledge_base_metadata_filtering(inv)
        assert result["status"] != "ERROR", (
            "KB metadata check should not be affected by lambda inventory failure"
        )


# ---------------------------------------------------------------------------
# 2. Single-inventory failure — Guardrail inventory
# ---------------------------------------------------------------------------


class TestGuardrailInventoryUnavailable:
    """Guardrail inventory unavailable → guardrail-consuming checks become
    COULD_NOT_ASSESS; lambda, S3, KB, WAFv2 checks are unaffected."""

    _ACCESS_DENIED = PermissionError("AccessDenied: bedrock:ListGuardrails")

    def _make_inv(self):
        return make_resource_inventory(guardrails=app._Unavailable(self._ACCESS_DENIED))

    # --- FS-27 (check_guardrail_contextual_grounding) ---
    def test_fs27_becomes_could_not_assess(self):
        """Validates: Requirements REQ-4.2"""
        result = app.check_guardrail_contextual_grounding(self._make_inv())
        assert _is_could_not_assess(result), (
            f"Expected COULD_NOT_ASSESS but got status={result['status']!r}"
        )

    # --- FS-28 (check_guardrail_denied_topics_financial) ---
    def test_fs28_becomes_could_not_assess(self):
        """Validates: Requirements REQ-4.2"""
        result = app.check_guardrail_denied_topics_financial(self._make_inv())
        assert _is_could_not_assess(result), (
            f"Expected COULD_NOT_ASSESS but got status={result['status']!r}"
        )

    # --- FS-36 (check_guardrail_content_filters) ---
    def test_fs36_becomes_could_not_assess(self):
        """Validates: Requirements REQ-4.2"""
        result = app.check_guardrail_content_filters(self._make_inv())
        assert _is_could_not_assess(result), (
            f"Expected COULD_NOT_ASSESS but got status={result['status']!r}"
        )

    # --- Lambda check unaffected when guardrails are unavailable ---
    def test_lambda_check_unaffected(self):
        """REQ-4.3: Lambda check is unaffected by guardrail inventory failure."""
        inv = self._make_inv()
        with patch("app.boto3.client") as mock_boto:
            mock_boto.return_value = MagicMock(
                get_function_concurrency=MagicMock(
                    return_value={"ReservedConcurrentExecutions": 5}
                )
            )
            result = app.check_agent_transaction_limits(inv)
        assert result["status"] != "ERROR", (
            "Lambda check should not be affected by guardrail inventory failure"
        )

    # --- KB check unaffected when guardrails are unavailable ---
    def test_kb_check_unaffected(self):
        """REQ-4.3: KB check is unaffected by guardrail inventory failure."""
        inv = self._make_inv()
        result = app.check_knowledge_base_metadata_filtering(inv)
        assert result["status"] != "ERROR", (
            "KB check should not be affected by guardrail inventory failure"
        )

    # --- S3 check unaffected when guardrails are unavailable ---
    def test_s3_check_unaffected(self):
        """REQ-4.3: S3 check is unaffected by guardrail inventory failure."""
        inv = self._make_inv()
        with patch("app.boto3.client") as mock_boto:
            mock_boto.return_value = MagicMock()
            result = app.check_training_data_s3_versioning(inv)
        assert result["status"] != "ERROR", (
            "S3 check should not be affected by guardrail inventory failure"
        )


# ---------------------------------------------------------------------------
# 3. Single-inventory failure — S3 inventory
# ---------------------------------------------------------------------------


class TestS3InventoryUnavailable:
    """S3 inventory unavailable → FS-21 and FS-46 become COULD_NOT_ASSESS;
    other inventories' dependent checks are unaffected."""

    _ACCESS_DENIED = PermissionError("AccessDenied: s3:ListBuckets")

    def _make_inv(self):
        return make_resource_inventory(buckets=app._Unavailable(self._ACCESS_DENIED))

    # --- FS-21 (check_training_data_s3_versioning) ---
    def test_fs21_becomes_could_not_assess(self):
        """Validates: Requirements REQ-4.2"""
        result = app.check_training_data_s3_versioning(self._make_inv())
        assert _is_could_not_assess(result), (
            f"Expected COULD_NOT_ASSESS but got status={result['status']!r}"
        )

    # --- FS-46 (check_data_classification_tagging) ---
    def test_fs46_becomes_could_not_assess(self):
        """Validates: Requirements REQ-4.2"""
        result = app.check_data_classification_tagging(self._make_inv())
        assert _is_could_not_assess(result), (
            f"Expected COULD_NOT_ASSESS but got status={result['status']!r}"
        )

    # --- Guardrail check unaffected when S3 is unavailable ---
    def test_guardrail_check_unaffected(self):
        """REQ-4.3 / REQ-8: Guardrail check is unaffected by S3 inventory failure."""
        inv = self._make_inv()
        result = app.check_guardrail_contextual_grounding(inv)
        assert result["status"] != "ERROR", (
            "Guardrail check should not be affected by S3 inventory failure"
        )

    # --- KB check unaffected when S3 is unavailable ---
    def test_kb_check_unaffected(self):
        """REQ-4.3 / REQ-8: KB check is unaffected by S3 inventory failure."""
        inv = self._make_inv()
        result = app.check_knowledge_base_metadata_filtering(inv)
        assert result["status"] != "ERROR", (
            "KB check should not be affected by S3 inventory failure"
        )


# ---------------------------------------------------------------------------
# 4. Single-inventory failure — WAFv2 inventory
# ---------------------------------------------------------------------------


class TestWafInventoryUnavailable:
    """WAFv2 inventory unavailable → FS-01, FS-53, FS-56, FS-68 become
    COULD_NOT_ASSESS; lambda, guardrail, S3, KB checks are unaffected."""

    _ACCESS_DENIED = PermissionError("AccessDenied: wafv2:ListWebACLs")

    def _make_inv(self):
        return make_resource_inventory(web_acls=app._Unavailable(self._ACCESS_DENIED))

    # --- FS-01 (check_waf_shield_on_bedrock_endpoints) ---
    def test_fs01_becomes_could_not_assess(self):
        """Validates: Requirements REQ-4.2"""
        with patch(
            "app.boto3.client", return_value=_make_shield_mock_no_subscription()
        ):
            result = app.check_waf_shield_on_bedrock_endpoints(self._make_inv())
        assert _is_could_not_assess(result), (
            f"Expected COULD_NOT_ASSESS but got status={result['status']!r}"
        )

    # --- FS-53 (check_waf_sql_injection_rules) ---
    def test_fs53_becomes_could_not_assess(self):
        """Validates: Requirements REQ-4.2"""
        result = app.check_waf_sql_injection_rules(self._make_inv())
        assert _is_could_not_assess(result), (
            f"Expected COULD_NOT_ASSESS but got status={result['status']!r}"
        )

    # --- FS-56 (check_xss_prevention_waf) ---
    def test_fs56_becomes_could_not_assess(self):
        """Validates: Requirements REQ-4.2"""
        result = app.check_xss_prevention_waf(self._make_inv())
        assert _is_could_not_assess(result), (
            f"Expected COULD_NOT_ASSESS but got status={result['status']!r}"
        )

    # --- Lambda check unaffected when WAFv2 is unavailable ---
    def test_lambda_check_unaffected(self):
        """REQ-4.3 / REQ-8: Lambda check is unaffected by WAFv2 inventory failure."""
        inv = self._make_inv()
        with patch("app.boto3.client") as mock_boto:
            mock_boto.return_value = MagicMock(
                get_function_concurrency=MagicMock(
                    return_value={"ReservedConcurrentExecutions": 5}
                )
            )
            result = app.check_agent_transaction_limits(inv)
        assert result["status"] != "ERROR", (
            "Lambda check should not be affected by WAFv2 inventory failure"
        )

    # --- Guardrail check unaffected when WAFv2 is unavailable ---
    def test_guardrail_check_unaffected(self):
        """REQ-4.3 / REQ-8: Guardrail check is unaffected by WAFv2 inventory failure."""
        inv = self._make_inv()
        result = app.check_guardrail_contextual_grounding(inv)
        assert result["status"] != "ERROR", (
            "Guardrail check should not be affected by WAFv2 inventory failure"
        )

    # --- S3 check unaffected when WAFv2 is unavailable ---
    def test_s3_check_unaffected(self):
        """REQ-4.3 / REQ-8: S3 check is unaffected by WAFv2 inventory failure."""
        inv = self._make_inv()
        with patch("app.boto3.client") as mock_boto:
            mock_boto.return_value = MagicMock()
            result = app.check_training_data_s3_versioning(inv)
        assert result["status"] != "ERROR", (
            "S3 check should not be affected by WAFv2 inventory failure"
        )


# ---------------------------------------------------------------------------
# 5. Single-inventory failure — Knowledge Base inventory
# ---------------------------------------------------------------------------


class TestKbInventoryUnavailable:
    """KB inventory unavailable → FS-24, FS-31, FS-33, FS-48, FS-61, FS-65
    become COULD_NOT_ASSESS; other inventories' checks are unaffected."""

    _ACCESS_DENIED = PermissionError("AccessDenied: bedrock-agent:ListKnowledgeBases")

    def _make_inv(self):
        return make_resource_inventory(
            knowledge_bases=app._Unavailable(self._ACCESS_DENIED)
        )

    # --- FS-24 (check_knowledge_base_metadata_filtering) ---
    def test_fs24_becomes_could_not_assess(self):
        """Validates: Requirements REQ-4.2"""
        result = app.check_knowledge_base_metadata_filtering(self._make_inv())
        assert _is_could_not_assess(result), (
            f"Expected COULD_NOT_ASSESS but got status={result['status']!r}"
        )

    # --- FS-31 (check_knowledge_base_data_source_sync) ---
    def test_fs31_becomes_could_not_assess(self):
        """Validates: Requirements REQ-4.2"""
        result = app.check_knowledge_base_data_source_sync(self._make_inv())
        assert _is_could_not_assess(result), (
            f"Expected COULD_NOT_ASSESS but got status={result['status']!r}"
        )

    # --- FS-48 (check_rag_knowledge_base_configured) ---
    def test_fs48_becomes_could_not_assess(self):
        """Validates: Requirements REQ-4.2"""
        result = app.check_rag_knowledge_base_configured(self._make_inv())
        assert _is_could_not_assess(result), (
            f"Expected COULD_NOT_ASSESS but got status={result['status']!r}"
        )

    # --- Guardrail check unaffected when KB is unavailable ---
    def test_guardrail_check_unaffected(self):
        """REQ-4.3 / REQ-8: Guardrail check is unaffected by KB inventory failure."""
        inv = self._make_inv()
        result = app.check_guardrail_contextual_grounding(inv)
        assert result["status"] != "ERROR", (
            "Guardrail check should not be affected by KB inventory failure"
        )

    # --- Lambda check unaffected when KB is unavailable ---
    def test_lambda_check_unaffected(self):
        """REQ-4.3 / REQ-8: Lambda check is unaffected by KB inventory failure."""
        inv = self._make_inv()
        with patch("app.boto3.client") as mock_boto:
            mock_boto.return_value = MagicMock(
                get_function_concurrency=MagicMock(
                    return_value={"ReservedConcurrentExecutions": 5}
                )
            )
            result = app.check_agent_transaction_limits(inv)
        assert result["status"] != "ERROR", (
            "Lambda check should not be affected by KB inventory failure"
        )

    # --- S3 check unaffected when KB is unavailable ---
    def test_s3_check_unaffected(self):
        """REQ-4.3 / REQ-8: S3 check is unaffected by KB inventory failure."""
        inv = self._make_inv()
        with patch("app.boto3.client") as mock_boto:
            mock_boto.return_value = MagicMock()
            result = app.check_training_data_s3_versioning(inv)
        assert result["status"] != "ERROR", (
            "S3 check should not be affected by KB inventory failure"
        )

    # --- WAFv2 check unaffected when KB is unavailable ---
    def test_waf_check_unaffected(self):
        """REQ-4.3 / REQ-8: WAFv2 check is unaffected by KB inventory failure."""
        inv = self._make_inv()
        with patch(
            "app.boto3.client", return_value=_make_shield_mock_no_subscription()
        ):
            result = app.check_waf_shield_on_bedrock_endpoints(inv)
        assert result["status"] != "ERROR", (
            "WAFv2 check should not be affected by KB inventory failure"
        )


# ---------------------------------------------------------------------------
# 6. Multiple-inventory failure — independent sentinels, run completes
# ---------------------------------------------------------------------------


class TestMultipleInventoryFailure:
    """REQ-4.6: multiple simultaneous inventory failures are each recorded
    independently; the run completes and checks on available inventories
    produce normal results."""

    def _make_inv_guardrails_and_web_acls_unavailable(self):
        return make_resource_inventory(
            guardrails=app._Unavailable(
                PermissionError("AccessDenied: bedrock:ListGuardrails")
            ),
            web_acls=app._Unavailable(
                PermissionError("AccessDenied: wafv2:ListWebACLs")
            ),
        )

    def _make_inv_lambda_and_s3_unavailable(self):
        return make_resource_inventory(
            lambda_functions=app._Unavailable(
                PermissionError("AccessDenied: lambda:ListFunctions")
            ),
            buckets=app._Unavailable(PermissionError("AccessDenied: s3:ListBuckets")),
        )

    # --- Guardrails AND WAFv2 both unavailable ---

    def test_guardrail_check_could_not_assess_when_guardrails_unavailable(self):
        """Validates: Requirements REQ-4.6 — guardrail failure independently recorded."""
        inv = self._make_inv_guardrails_and_web_acls_unavailable()
        result = app.check_guardrail_contextual_grounding(inv)
        assert _is_could_not_assess(result), (
            "FS-27 should be COULD_NOT_ASSESS when guardrails inventory is unavailable"
        )

    def test_waf_check_could_not_assess_when_web_acls_unavailable(self):
        """Validates: Requirements REQ-4.6 — WAFv2 failure independently recorded."""
        inv = self._make_inv_guardrails_and_web_acls_unavailable()
        result = app.check_waf_sql_injection_rules(inv)
        assert _is_could_not_assess(result), (
            "FS-53 should be COULD_NOT_ASSESS when web_acls inventory is unavailable"
        )

    def test_kb_check_normal_when_guardrails_and_waf_unavailable(self):
        """REQ-4.3: KB check produces a normal result despite guardrail+WAFv2 failures."""
        inv = self._make_inv_guardrails_and_web_acls_unavailable()
        result = app.check_knowledge_base_metadata_filtering(inv)
        assert result["status"] != "ERROR", (
            "KB check should not be affected when guardrails and WAFv2 are unavailable"
        )

    def test_s3_check_normal_when_guardrails_and_waf_unavailable(self):
        """REQ-4.3: S3 check is unaffected by guardrail and WAFv2 failures."""
        inv = self._make_inv_guardrails_and_web_acls_unavailable()
        with patch("app.boto3.client") as mock_boto:
            mock_boto.return_value = MagicMock()
            result = app.check_training_data_s3_versioning(inv)
        assert result["status"] != "ERROR", (
            "S3 check should not be affected when guardrails and WAFv2 are unavailable"
        )

    # --- Lambda AND S3 both unavailable ---

    def test_lambda_check_could_not_assess_when_lambda_unavailable(self):
        """Validates: Requirements REQ-4.6 — lambda failure independently recorded."""
        inv = self._make_inv_lambda_and_s3_unavailable()
        result = app.check_agent_transaction_limits(inv)
        assert _is_could_not_assess(result), (
            "FS-09 should be COULD_NOT_ASSESS when lambda_functions inventory is unavailable"
        )

    def test_s3_check_could_not_assess_when_s3_unavailable(self):
        """Validates: Requirements REQ-4.6 — S3 failure independently recorded."""
        inv = self._make_inv_lambda_and_s3_unavailable()
        result = app.check_training_data_s3_versioning(inv)
        assert _is_could_not_assess(result), (
            "FS-21 should be COULD_NOT_ASSESS when buckets inventory is unavailable"
        )

    def test_guardrail_check_normal_when_lambda_and_s3_unavailable(self):
        """REQ-4.3: Guardrail check is unaffected by lambda+S3 failures."""
        inv = self._make_inv_lambda_and_s3_unavailable()
        result = app.check_guardrail_contextual_grounding(inv)
        assert result["status"] != "ERROR", (
            "Guardrail check should not be affected when lambda and S3 are unavailable"
        )

    def test_kb_check_normal_when_lambda_and_s3_unavailable(self):
        """REQ-4.3: KB check is unaffected by lambda+S3 failures."""
        inv = self._make_inv_lambda_and_s3_unavailable()
        result = app.check_knowledge_base_metadata_filtering(inv)
        assert result["status"] != "ERROR", (
            "KB check should not be affected when lambda and S3 are unavailable"
        )

    def test_waf_check_normal_when_lambda_and_s3_unavailable(self):
        """REQ-4.3: WAFv2 check is unaffected by lambda+S3 failures."""
        inv = self._make_inv_lambda_and_s3_unavailable()
        with patch(
            "app.boto3.client", return_value=_make_shield_mock_no_subscription()
        ):
            result = app.check_waf_shield_on_bedrock_endpoints(inv)
        assert result["status"] != "ERROR", (
            "WAFv2 check should not be affected when lambda and S3 are unavailable"
        )

    # --- All five inventories unavailable simultaneously ---

    def test_all_inventories_unavailable_run_still_completes(self):
        """REQ-4.6: When all inventories fail, calling each dependent check
        individually still returns a result (no unhandled exception propagates)."""
        err = PermissionError("AccessDenied: all inventories")
        inv = make_resource_inventory(
            lambda_functions=app._Unavailable(err),
            guardrails=app._Unavailable(err),
            knowledge_bases=app._Unavailable(err),
            buckets=app._Unavailable(err),
            web_acls=app._Unavailable(err),
        )

        checks_and_kwargs = [
            (app.check_agent_transaction_limits, {"inventory": inv}),
            (app.check_guardrail_contextual_grounding, {"inventory": inv}),
            (app.check_knowledge_base_metadata_filtering, {"inventory": inv}),
            (app.check_training_data_s3_versioning, {"inventory": inv}),
            (app.check_waf_sql_injection_rules, {"inventory": inv}),
            (app.check_guardrail_denied_topics_financial, {"inventory": inv}),
            (app.check_guardrail_content_filters, {"inventory": inv}),
            (app.check_knowledge_base_data_source_sync, {"inventory": inv}),
            (app.check_rag_knowledge_base_configured, {"inventory": inv}),
            (app.check_bedrock_sdk_version_currency, {"inventory": inv}),
            (app.check_output_validation_lambda, {"inventory": inv}),
            (app.check_waf_sql_injection_rules, {"inventory": inv}),
        ]

        for check_fn, kwargs in checks_and_kwargs:
            # Must not raise; must return a dict with status and csv_data
            result = check_fn(**kwargs)
            assert isinstance(result, dict), (
                f"{check_fn.__name__} raised instead of returning a result"
            )
            assert "status" in result
            assert "csv_data" in result
            assert _is_could_not_assess(result), (
                f"{check_fn.__name__} should be COULD_NOT_ASSESS when all inventories unavailable; "
                f"got status={result['status']!r}"
            )


# ---------------------------------------------------------------------------
# 7. Full handler run with partial-inventory failure
# ---------------------------------------------------------------------------


class TestHandlerWithPartialInventory:
    """Verify that when collect_resource_inventory returns a partially-unavailable
    ResourceInventory (patched in), the handler still completes (statusCode=200)
    and synthesizes visible COULD_NOT_ASSESS rows for the affected checks while
    other checks produce normal rows.

    Validates: Requirements REQ-4.2, REQ-4.3, REQ-4.6
    """

    def _make_generic_mock_client(self):
        generic = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{}]
        generic.get_paginator.return_value = paginator
        generic.list_web_acls.return_value = {"WebACLs": []}

        # FS-01 uses shield.exceptions.ResourceNotFoundException — set up a proper
        # exception class so describe_subscription's side_effect is caught correctly.
        class ResourceNotFoundException(Exception):
            pass

        class FakeExceptions:
            pass

        FakeExceptions.ResourceNotFoundException = ResourceNotFoundException
        generic.exceptions = FakeExceptions
        generic.describe_subscription.side_effect = ResourceNotFoundException("no sub")

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
        return generic

    @patch("app.write_to_s3")
    @patch("app.get_permissions_cache")
    @patch("app.collect_resource_inventory")
    @patch("app.boto3.client")
    def test_handler_completes_with_lambda_inventory_unavailable(
        self,
        mock_boto_client,
        mock_collect_inv,
        mock_cache,
        mock_s3,
        lambda_event,
    ):
        """Handler returns 200 and all 65 findings are present (COULD_NOT_ASSESS
        rows are synthesized for lambda-dependent checks) when lambda inventory fails.

        Validates: Requirements REQ-4.2, REQ-4.3, REQ-4.6
        """
        err = PermissionError("AccessDenied: lambda:ListFunctions")
        partial_inv = make_resource_inventory(lambda_functions=app._Unavailable(err))
        mock_collect_inv.return_value = partial_inv
        mock_boto_client.return_value = self._make_generic_mock_client()
        mock_cache.return_value = {"role_permissions": {}, "user_permissions": {}}
        mock_s3.return_value = "https://test-bucket.s3.amazonaws.com/report.csv"

        result = app.lambda_handler(lambda_event, None)

        assert result["statusCode"] == 200
        findings = result["body"]["findings"]
        # All 65 registry entries must produce a result dict
        assert len(findings) == 65

        # Lambda-dependent checks should have a synthesized COULD_NOT_ASSESS row
        # in their csv_data (the handler's guard calls _could_not_assess_row for
        # checks that return empty csv_data — design DD-3).
        lambda_dependent_check_names = {
            "Agent Transaction Limits Check",  # FS-09
            "Bedrock SDK Version Currency Check",  # FS-52
            "Output Validation Lambda Check",  # FS-55
            "Output Schema Validation Check",  # FS-58
        }

        for finding in findings:
            check_name = finding.get("check_name", "")
            rows = finding.get("csv_data", [])
            if check_name in lambda_dependent_check_names:
                # The handler synthesizes a COULD_NOT_ASSESS row and appends it
                # to csv_data before returning — so we expect exactly 1 row with
                # the COULD NOT ASSESS prefix and Status="N/A".
                assert len(rows) == 1, (
                    f"{check_name} should have 1 synthesized COULD_NOT_ASSESS row, "
                    f"got {len(rows)}: {rows!r}"
                )
                assert rows[0]["Finding"].startswith(app.COULD_NOT_ASSESS_PREFIX), (
                    f"{check_name} row Finding should start with COULD NOT ASSESS prefix"
                )
                # StatusEnum.NA == "N/A" because StatusEnum inherits from str
                assert rows[0]["Status"] == "N/A", (
                    f"{check_name} COULD_NOT_ASSESS row should have Status=N/A, "
                    f"got {rows[0]['Status']!r}"
                )

    @patch("app.write_to_s3")
    @patch("app.get_permissions_cache")
    @patch("app.collect_resource_inventory")
    @patch("app.boto3.client")
    def test_handler_completes_with_guardrails_and_waf_unavailable(
        self,
        mock_boto_client,
        mock_collect_inv,
        mock_cache,
        mock_s3,
        lambda_event,
    ):
        """Handler returns 200 with all 65 findings when guardrails and WAFv2 fail.

        Validates: Requirements REQ-4.6 — multiple independent failures
        """
        partial_inv = make_resource_inventory(
            guardrails=app._Unavailable(
                PermissionError("AccessDenied: bedrock:ListGuardrails")
            ),
            web_acls=app._Unavailable(
                PermissionError("AccessDenied: wafv2:ListWebACLs")
            ),
        )
        mock_collect_inv.return_value = partial_inv
        mock_boto_client.return_value = self._make_generic_mock_client()
        mock_cache.return_value = {"role_permissions": {}, "user_permissions": {}}
        mock_s3.return_value = "https://test-bucket.s3.amazonaws.com/report.csv"

        result = app.lambda_handler(lambda_event, None)

        assert result["statusCode"] == 200
        assert len(result["body"]["findings"]) == 65
