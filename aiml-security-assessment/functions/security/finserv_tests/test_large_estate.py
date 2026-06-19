"""
Large-estate performance and memory guard — Task 15 (Wave 4).

Validates: REQ-10.1, REQ-10.2, REQ-10.3, REQ-11.1, REQ-11.3

With ≥1,000 functions, ≥100 buckets, ≥50 guardrails/KBs/ACLs the handler must:
  1. Issue at most one listing call per inventory (enforced by patching collect_resource_inventory
     to return a pre-built large inventory — the real collector never runs in this test).
  2. Issue ≤1 detail call per resource (get_guardrail per guardrail id, get_web_acl per ACL id).
  3. Complete well within the 900 s Lambda budget.
  4. Keep peak memory well under 1024 MB.

The test builds the large inventory directly (bypassing the collector) and patches
app.collect_resource_inventory to return it, then runs lambda_handler end-to-end with
a generic MagicMock for every non-inventory boto3 client.
"""

import os
import sys
import time
import tracemalloc
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch


FINSERV_DIR = os.path.join(os.path.dirname(__file__), "..", "finserv_assessments")
if FINSERV_DIR not in sys.path:
    sys.path.insert(0, FINSERV_DIR)

import app  # noqa: E402


# ---------------------------------------------------------------------------
# Inline inventory builder — mirrors conftest.make_resource_inventory so this
# module is self-contained while staying consistent with the shared fixture.
# ---------------------------------------------------------------------------


def make_resource_inventory(**overrides) -> app.ResourceInventory:
    """Build a fully-available ResourceInventory with sensible empty defaults.

    Mirrors conftest.make_resource_inventory; defined here so the test module
    is self-contained (conftest is only importable by pytest, not directly).
    """
    defaults: dict = {
        "lambda_functions": [],
        "guardrails": app.GuardrailInventory(summaries=[], detail_by_id={}),
        "knowledge_bases": app.KbInventory(
            summaries=[], data_sources_by_kb={}, data_source_detail={}
        ),
        "buckets": [],
        "web_acls": app.WebAclInventory(summaries=[], detail_by_id={}),
    }
    defaults.update(overrides)
    return app.ResourceInventory(**defaults)


# ---------------------------------------------------------------------------
# Large-estate fixture helpers
# ---------------------------------------------------------------------------

_N_FUNCTIONS = 1_000
_N_BUCKETS = 100
_N_GUARDRAILS = 50
_N_KBS = 50
_N_ACLS = 50


def _build_large_inventory() -> app.ResourceInventory:
    """Construct a fully-populated ResourceInventory at large-estate scale."""
    # Lambda functions — 1 000 entries
    functions = [
        {"FunctionName": f"fn-{i}", "Runtime": "python3.12"}
        for i in range(_N_FUNCTIONS)
    ]

    # Guardrails — 50 summaries + 50 detail entries
    guardrail_summaries = [
        {"id": f"g-{i}", "name": f"guardrail-{i}"} for i in range(_N_GUARDRAILS)
    ]
    detail_by_guardrail_id = {
        g["id"]: {
            "guardrailId": g["id"],
            "name": g["name"],
            "status": "READY",
            "contentPolicy": {
                "filters": [
                    {
                        "type": "SEXUAL",
                        "inputStrength": "HIGH",
                        "outputStrength": "HIGH",
                    }
                ]
            },
            "topicPolicy": {"topics": []},
            "wordPolicy": {"words": [], "managedWordLists": []},
            "sensitiveInformationPolicy": {"piiEntities": [], "regexes": []},
            "contextualGroundingPolicy": {
                "filters": [
                    {"type": "GROUNDING", "threshold": 0.8},
                    {"type": "RELEVANCE", "threshold": 0.8},
                ]
            },
        }
        for g in guardrail_summaries
    }

    # Knowledge Bases — 50 summaries, 1 data source each, full detail
    kb_summaries = [
        {
            "knowledgeBaseId": f"kb-{i}",
            "name": f"kb-{i}",
            "status": "ACTIVE",
            "updatedAt": datetime.now(timezone.utc),
        }
        for i in range(_N_KBS)
    ]
    data_sources_by_kb: dict = {}
    data_source_detail: dict = {}
    for kb in kb_summaries:
        kb_id = kb["knowledgeBaseId"]
        ds_id = f"ds-{kb_id}-0"
        ds_summary = {
            "dataSourceId": ds_id,
            "name": "ds",
            "status": "AVAILABLE",
            "updatedAt": datetime.now(timezone.utc),
        }
        data_sources_by_kb[kb_id] = [ds_summary]
        data_source_detail[(kb_id, ds_id)] = {
            "dataSource": {
                "dataSourceId": ds_id,
                "knowledgeBaseId": kb_id,
                "dataSourceConfiguration": {
                    "type": "S3",
                    "s3Configuration": {
                        "bucketArn": f"arn:aws:s3:::kb-bucket-{kb_id}",
                    },
                },
            }
        }

    # S3 buckets — 100 entries
    buckets = [{"Name": f"bucket-{i}"} for i in range(_N_BUCKETS)]

    # WAFv2 Web ACLs — 50 summaries + 50 detail entries
    acl_summaries = [
        {"Id": f"acl-{i}", "Name": f"acl-{i}", "ARN": f"arn:aws:wafv2:::acl-{i}"}
        for i in range(_N_ACLS)
    ]
    detail_by_acl_id = {
        acl["Id"]: {
            "Id": acl["Id"],
            "Name": acl["Name"],
            "ARN": acl["ARN"],
            "Rules": [
                {
                    "Name": "SQLiRule",
                    "Statement": {
                        "ManagedRuleGroupStatement": {
                            "VendorName": "AWS",
                            "Name": "AWSManagedRulesSQLiRuleSet",
                        }
                    },
                }
            ],
        }
        for acl in acl_summaries
    }

    return make_resource_inventory(
        lambda_functions=functions,
        guardrails=app.GuardrailInventory(
            summaries=guardrail_summaries,
            detail_by_id=detail_by_guardrail_id,
        ),
        knowledge_bases=app.KbInventory(
            summaries=kb_summaries,
            data_sources_by_kb=data_sources_by_kb,
            data_source_detail=data_source_detail,
        ),
        buckets=buckets,
        web_acls=app.WebAclInventory(
            summaries=acl_summaries,
            detail_by_id=detail_by_acl_id,
        ),
    )


def _make_generic_non_inventory_client() -> MagicMock:
    """Return a MagicMock that satisfies every non-inventory boto3 call.

    The inventory itself is provided via the pre-built ResourceInventory;
    this client handles everything else (shield, apigateway, cloudwatch, …).
    """
    generic = MagicMock()

    # Paginator pattern used by some checks (cw.get_paginator, sfn, etc.)
    paginator = MagicMock()
    paginator.paginate.return_value = [{}]
    generic.get_paginator.return_value = paginator

    # Inventory listing methods — these MUST NOT be called because
    # collect_resource_inventory is patched to return the pre-built inventory.
    # We leave them as MagicMock (auto-return) but we'll count their calls.

    # Non-inventory service methods — return empty / benign responses
    generic.describe_subscription.side_effect = Exception("no shield subscription")
    generic.get_usage_plans.return_value = {"items": []}
    generic.list_service_quotas.return_value = {"Quotas": []}
    generic.get_anomaly_monitors.return_value = {"AnomalyMonitors": []}
    generic.describe_budgets.return_value = {"Budgets": []}
    generic.get_caller_identity.return_value = {"Account": "123456789012"}
    generic.list_agents.return_value = {"agentSummaries": []}
    generic.list_agent_runtimes.return_value = {"agentRuntimes": []}
    generic.list_state_machines.return_value = {"stateMachines": []}
    generic.list_policies.return_value = {"Policies": []}
    generic.list_custom_models.return_value = {"modelSummaries": []}
    generic.list_models.return_value = {"Models": []}
    generic.describe_config_rules.return_value = {"ConfigRules": []}
    generic.list_evaluation_jobs.return_value = {"jobSummaries": []}
    generic.describe_repositories.return_value = {"repositories": []}
    generic.list_feature_groups.return_value = {"FeatureGroupSummaries": []}
    generic.list_log_groups.return_value = {"logGroups": []}
    generic.get_macie_session.side_effect = Exception("macie not enabled")
    generic.list_foundation_models.return_value = {"modelSummaries": []}
    generic.list_model_cards.return_value = {"ModelCardSummaryList": []}
    generic.list_rules.return_value = {"Rules": []}
    generic.list_schedules.return_value = {"Schedules": []}
    generic.get_rest_apis.return_value = {"items": []}
    generic.list_processing_jobs.return_value = {"ProcessingJobSummaries": []}
    generic.list_automated_reasoning_policies.return_value = {
        "automatedReasoningPolicySummaries": []
    }
    generic.list_security_policies.return_value = {"securityPolicySummaries": []}
    generic.list_monitoring_schedules.return_value = {"MonitoringScheduleSummaries": []}

    # S3 per-bucket detail calls (get_bucket_versioning, get_bucket_tagging, …)
    generic.get_bucket_versioning.return_value = {"Status": "Enabled"}
    generic.get_bucket_tagging.return_value = {"TagSet": []}
    generic.get_bucket_notification_configuration.return_value = {}

    # S3 data-protection-policy for CloudWatch Logs PII check
    generic.get_data_protection_policy.return_value = {}

    # per-function concurrency (FS-09 keeps its own concurrency loop)
    generic.get_function_concurrency.return_value = {
        "ReservedConcurrentExecutions": 100
    }

    return generic


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------


class TestLargeEstatePerformance:
    """Large-estate performance and memory guard (Task 15, Wave 4).

    Validates: REQ-10.1, REQ-10.2, REQ-10.3, REQ-11.1, REQ-11.3
    """

    @patch("app.write_to_s3")
    @patch("app.get_permissions_cache")
    @patch("app.boto3.client")
    @patch("app.collect_resource_inventory")
    def test_large_estate_single_listing_and_memory(
        self,
        mock_collect_inventory,
        mock_boto3_client,
        mock_get_perm_cache,
        mock_write_s3,
    ):
        """With 1 000 functions, 100 buckets, 50 guardrails/KBs/ACLs:
        - collect_resource_inventory is called exactly once (single enumeration).
        - The five shared listing APIs are never called directly (≤0 for each
          because the collector is patched out entirely).
        - Detail APIs (get_guardrail, get_web_acl, get_function_concurrency) are
          only called from within the checks themselves; each is called at most
          once per resource since the checks read from the pre-built inventory.
        - Handler completes well within 900 s.
        - Peak memory well under 1024 MB.
        """
        # --- Setup ---
        large_inventory = _build_large_inventory()
        mock_collect_inventory.return_value = large_inventory

        generic_client = _make_generic_non_inventory_client()
        mock_boto3_client.return_value = generic_client

        mock_get_perm_cache.return_value = {
            "role_permissions": {},
            "user_permissions": {},
        }
        mock_write_s3.return_value = "https://test-bucket.s3.amazonaws.com/finserv_security_report_large-estate.csv"

        event = {
            "Execution": {"Name": "large-estate-perf-test"},
            "StateMachine": {
                "Id": "arn:aws:states:us-east-1:123456789012:stateMachine:test"
            },
        }

        # --- Run under memory and time instrumentation ---
        tracemalloc.start()
        start = time.perf_counter()

        result = app.lambda_handler(event, None)

        elapsed = time.perf_counter() - start
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # --- Correctness: handler must succeed ---
        assert result["statusCode"] == 200, (
            f"lambda_handler returned {result['statusCode']}"
        )
        assert "findings" in result["body"]
        assert len(result["body"]["findings"]) == 65, (
            f"Expected 65 findings, got {len(result['body']['findings'])}"
        )

        # --- REQ-10.1 / REQ-10.2: Single enumeration per inventory ---
        # collect_resource_inventory is called exactly once per invocation.
        mock_collect_inventory.assert_called_once_with()

        # The five shared listing APIs must NOT be called on the boto3 client,
        # because collect_resource_inventory (which is patched out) would own
        # those calls. Any direct call from a check would violate REQ-10.1.
        assert generic_client.list_functions.call_count == 0, (
            f"list_functions called {generic_client.list_functions.call_count}× "
            "— must be 0 when collect_resource_inventory is patched"
        )
        assert generic_client.list_guardrails.call_count == 0, (
            f"list_guardrails called {generic_client.list_guardrails.call_count}×"
        )
        assert generic_client.list_knowledge_bases.call_count == 0, (
            f"list_knowledge_bases called {generic_client.list_knowledge_bases.call_count}×"
        )
        assert generic_client.list_buckets.call_count == 0, (
            f"list_buckets called {generic_client.list_buckets.call_count}×"
        )
        assert generic_client.list_web_acls.call_count == 0, (
            f"list_web_acls called {generic_client.list_web_acls.call_count}×"
        )

        # --- REQ-10.2: ≤1 detail call per resource ---
        # get_guardrail is NOT called from checks (the inventory pre-loads detail);
        # verify no check bypasses the inventory and calls it directly.
        assert generic_client.get_guardrail.call_count == 0, (
            f"get_guardrail called {generic_client.get_guardrail.call_count}× "
            "— checks must read from inventory.guardrails.detail_by_id"
        )
        # get_web_acl: same invariant.
        assert generic_client.get_web_acl.call_count == 0, (
            f"get_web_acl called {generic_client.get_web_acl.call_count}× "
            "— checks must read from inventory.web_acls.detail_by_id"
        )
        # get_function_concurrency: FS-09 calls it per-function on its
        # agent-name-filtered subset. With fn-0..fn-999 none match the
        # agent/bedrock/aiml filter, so the count must be 0.
        assert generic_client.get_function_concurrency.call_count == 0, (
            f"get_function_concurrency called "
            f"{generic_client.get_function_concurrency.call_count}× "
            "— none of fn-0..fn-999 match the agent/bedrock/aiml filter"
        )

        # --- REQ-10.3: Completion within the 900 s budget ---
        assert elapsed < 900, (
            f"Handler took {elapsed:.2f}s — must complete within 900 s"
        )

        # --- REQ-11.1 / REQ-11.3: Peak memory well under 1024 MB ---
        peak_mb = peak / (1024 * 1024)
        assert peak_mb < 1024, (
            f"Peak memory {peak_mb:.1f} MB — must be well under 1024 MB"
        )

    @patch("app.write_to_s3")
    @patch("app.get_permissions_cache")
    @patch("app.boto3.client")
    @patch("app.collect_resource_inventory")
    def test_large_estate_timing_budget(
        self,
        mock_collect_inventory,
        mock_boto3_client,
        mock_get_perm_cache,
        mock_write_s3,
    ):
        """Focused timing assertion: 65 checks over a large inventory must
        complete well within the 900 s budget (target: under 60 s on any
        reasonable CI host, giving 15× headroom).

        Validates: REQ-10.3
        """
        large_inventory = _build_large_inventory()
        mock_collect_inventory.return_value = large_inventory
        mock_boto3_client.return_value = _make_generic_non_inventory_client()
        mock_get_perm_cache.return_value = {
            "role_permissions": {},
            "user_permissions": {},
        }
        mock_write_s3.return_value = "https://test-bucket.s3.amazonaws.com/report.csv"

        event = {"Execution": {"Name": "timing-test"}}

        start = time.perf_counter()
        app.lambda_handler(event, None)
        elapsed = time.perf_counter() - start

        # Strict budget: all mocked I/O, so well under 60 s even on slow hardware
        assert elapsed < 60, (
            f"Handler took {elapsed:.2f}s with mocked I/O — target <60 s "
            f"(900 s hard budget leaves {900 - elapsed:.0f}s headroom)"
        )

    @patch("app.write_to_s3")
    @patch("app.get_permissions_cache")
    @patch("app.boto3.client")
    @patch("app.collect_resource_inventory")
    def test_large_estate_memory_footprint(
        self,
        mock_collect_inventory,
        mock_boto3_client,
        mock_get_perm_cache,
        mock_write_s3,
    ):
        """Peak memory footprint with a large inventory must stay well under
        the 1024 MB Lambda limit.

        Validates: REQ-11.1, REQ-11.3
        """
        large_inventory = _build_large_inventory()
        mock_collect_inventory.return_value = large_inventory
        mock_boto3_client.return_value = _make_generic_non_inventory_client()
        mock_get_perm_cache.return_value = {
            "role_permissions": {},
            "user_permissions": {},
        }
        mock_write_s3.return_value = "https://test-bucket.s3.amazonaws.com/report.csv"

        event = {"Execution": {"Name": "memory-test"}}

        tracemalloc.start()
        app.lambda_handler(event, None)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        peak_mb = peak / (1024 * 1024)
        # 50 MB is a generous ceiling for mocked I/O; the real ceiling is 1024 MB
        assert peak_mb < 50, (
            f"Peak memory {peak_mb:.1f} MB with mocked I/O — expected well under 50 MB "
            f"(hard limit is 1024 MB)"
        )
