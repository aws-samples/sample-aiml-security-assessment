"""
"At most once" enforcement harness — Task 11

Handler-level tests with counting mocks that assert each shared listing API is
called ≤ 1 per run, each detail API ≤ 1 per resource per run, and
ListDataSources ≤ 1 per KB.  The tests fail the build if any invariant is
exceeded.

Requirements: REQ-9.1, REQ-9.4, REQ-9.6

Design reference: design.md §9.3
    list_functions ≤ 1
    list_guardrails ≤ 1
    list_knowledge_bases ≤ 1
    list_buckets ≤ 1
    list_web_acls ≤ 1
    list_data_sources ≤ 1 per KB
    get_guardrail ≤ 1 per distinct guardrail id
    get_web_acl ≤ 1 per distinct ACL id
    get_data_source ≤ 1 per (kb_id, ds_id) pair
"""

from __future__ import annotations

import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Make finserv_assessments importable
# ---------------------------------------------------------------------------
FINSERV_DIR = os.path.join(os.path.dirname(__file__), "..", "finserv_assessments")
if FINSERV_DIR not in sys.path:
    sys.path.insert(0, FINSERV_DIR)

import app  # noqa: E402


# ===========================================================================
# Call-counting mock infrastructure
# ===========================================================================


class _CountingClient:
    """Thin wrapper around a MagicMock that counts calls to specific methods.

    For listing APIs we track the total number of calls (must be ≤ 1).
    For per-resource detail APIs we track calls per argument key (must be ≤ 1
    per distinct resource).
    """

    def __init__(self, service: str):
        self.service = service
        self.list_call_counts: dict[str, int] = defaultdict(int)
        self.detail_call_counts: dict[str, dict] = defaultdict(lambda: defaultdict(int))
        self._mock = MagicMock()

    # ------------------------------------------------------------------
    # Wire counted list + detail methods and delegate rest to the mock
    # ------------------------------------------------------------------

    def __getattr__(self, name: str):
        return getattr(self._mock, name)


# ---------------------------------------------------------------------------
# Reusable "full account state" data (same as test_inventory_equivalence.py
# but kept local so this module has no import dependency on that module).
# ---------------------------------------------------------------------------

_NOW = datetime.now(timezone.utc)

_LAMBDA_FUNCTIONS = [
    {"FunctionName": "my-bedrock-agent-handler"},
    {"FunctionName": "my-output-validate-fn"},
    {"FunctionName": "my-schema-validator-fn"},
]

_GUARDRAIL_SUMMARIES = [
    {"id": "gr-001", "name": "GuardrailA"},
    {"id": "gr-002", "name": "GuardrailB"},
]

_GUARDRAIL_DETAIL = {
    "contextualGroundingPolicy": {
        "filters": [
            {"type": "GROUNDING", "threshold": 0.8},
            {"type": "RELEVANCE", "threshold": 0.8},
        ]
    },
    "topicPolicy": {
        "topics": [{"name": "investment-advice", "type": "DENY"}],
        "tier": {"tierName": "CLASSIC"},
    },
    "contentPolicy": {
        "filters": [
            {"type": "HATE", "inputStrength": "HIGH", "outputStrength": "HIGH"},
        ]
    },
    "wordPolicy": {
        "words": [{"text": "fraud"}],
        "managedWordLists": [{"type": "PROFANITY"}],
    },
    "sensitiveInformationPolicy": {
        "piiEntities": [{"type": "US_SOCIAL_SECURITY_NUMBER", "action": "BLOCK"}]
    },
}

_KB_SUMMARIES = [
    {"knowledgeBaseId": "kb-001", "name": "KB_Alpha"},
    {"knowledgeBaseId": "kb-002", "name": "KB_Beta"},
]

_KB_DATA_SOURCE_SUMMARIES = {
    "kb-001": [
        {"dataSourceId": "ds-001", "name": "DS_1", "updatedAt": _NOW},
        {"dataSourceId": "ds-002", "name": "DS_2", "updatedAt": _NOW},
    ],
    "kb-002": [
        {"dataSourceId": "ds-003", "name": "DS_3", "updatedAt": _NOW},
    ],
}

_S3_BUCKETS = [
    {"Name": "my-training-dataset-bucket"},
    {"Name": "my-bedrock-kb-bucket"},
    {"Name": "my-kb-datasource-bucket"},
]

_ACL_SUMMARIES = [
    {"Name": "ACL_One", "Id": "acl-id-001", "ARN": "arn:aws:wafv2:::acl-id-001"},
    {"Name": "ACL_Two", "Id": "acl-id-002", "ARN": "arn:aws:wafv2:::acl-id-002"},
]

_ACL_DETAIL_TEMPLATE = {
    "Rules": [
        {
            "Name": "SQLi",
            "Statement": {
                "ManagedRuleGroupStatement": {"Name": "AWSManagedRulesSQLiRuleSet"}
            },
        },
        {
            "Name": "Common",
            "Statement": {
                "ManagedRuleGroupStatement": {"Name": "AWSManagedRulesCommonRuleSet"}
            },
        },
        {
            "Name": "KnownBadInputs",
            "Statement": {
                "ManagedRuleGroupStatement": {
                    "Name": "AWSManagedRulesKnownBadInputsRuleSet"
                }
            },
        },
        {
            "Name": "SizeConstraint",
            "Statement": {
                "SizeConstraintStatement": {
                    "FieldToMatch": {"Body": {}},
                    "ComparisonOperator": "LE",
                    "Size": 8192,
                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                }
            },
        },
    ],
}


# ===========================================================================
# Counting mock client factory
# ===========================================================================


def _build_counting_client_factory():
    """Return a (side_effect_fn, call_tracker) pair.

    side_effect_fn: passed to mock_client.side_effect — returns a client mock
        whose inventory-relevant methods are wrapped with call counters.
    call_tracker: a dict containing all recorded call counts so tests can
        assert at-most-once invariants after lambda_handler returns.

    Structure of call_tracker::

        {
            "list_functions": <int>,        # total calls
            "list_guardrails": <int>,
            "list_knowledge_bases": <int>,
            "list_buckets": <int>,
            "list_web_acls": <int>,
            "list_data_sources": {kb_id: <int>, ...},  # per-KB
            "get_guardrail": {guardrail_id: <int>, ...},  # per guardrail id
            "get_web_acl": {acl_id: <int>, ...},          # per ACL id
            "get_data_source": {(kb_id, ds_id): <int>, ...},  # per (kb, ds)
        }
    """
    tracker: dict = {
        "list_functions": 0,
        "list_guardrails": 0,
        "list_knowledge_bases": 0,
        "list_buckets": 0,
        "list_web_acls": 0,
        "list_data_sources": defaultdict(int),
        "get_guardrail": defaultdict(int),
        "get_web_acl": defaultdict(int),
        "get_data_source": defaultdict(int),
    }

    def side_effect(service, **kwargs):  # noqa: C901
        c = MagicMock()

        # ------------------------------------------------------------------ #
        # wafv2 — count list_web_acls and get_web_acl calls
        # ------------------------------------------------------------------ #
        if service == "wafv2":

            def _list_web_acls(Scope, **kw):
                tracker["list_web_acls"] += 1
                return {"WebACLs": _ACL_SUMMARIES}

            c.list_web_acls.side_effect = _list_web_acls

            def _get_web_acl(Name, Scope, Id, **kw):
                tracker["get_web_acl"][Id] += 1
                detail = dict(_ACL_DETAIL_TEMPLATE)
                detail["Name"] = Name
                detail["Id"] = Id
                return {"WebACL": detail}

            c.get_web_acl.side_effect = _get_web_acl
            return c

        # ------------------------------------------------------------------ #
        # lambda — count list_functions
        # ------------------------------------------------------------------ #
        if service == "lambda":

            def _list_functions(**kw):
                tracker["list_functions"] += 1
                return {"Functions": _LAMBDA_FUNCTIONS}

            c.list_functions.side_effect = _list_functions

            def _get_function_concurrency(FunctionName, **kw):
                if "agent" in FunctionName.lower():
                    return {"ReservedConcurrentExecutions": 5}
                return {}

            c.get_function_concurrency.side_effect = _get_function_concurrency
            return c

        # ------------------------------------------------------------------ #
        # bedrock — count list_guardrails and get_guardrail per id
        # ------------------------------------------------------------------ #
        if service == "bedrock":

            def _list_guardrails(**kw):
                tracker["list_guardrails"] += 1
                return {"guardrails": _GUARDRAIL_SUMMARIES}

            c.list_guardrails.side_effect = _list_guardrails

            def _get_guardrail(guardrailIdentifier, guardrailVersion="DRAFT", **kw):
                tracker["get_guardrail"][guardrailIdentifier] += 1
                return _GUARDRAIL_DETAIL

            c.get_guardrail.side_effect = _get_guardrail

            # Non-inventory calls for other bedrock checks
            c.list_foundation_models.return_value = {
                "modelSummaries": [
                    {
                        "modelId": "anthropic.claude-3-sonnet-20240229-v1:0",
                        "modelLifecycle": {"status": "ACTIVE"},
                    }
                ]
            }
            c.list_custom_models.return_value = {"modelSummaries": []}
            c.list_model_cards.return_value = {"ModelCardSummaries": []}
            c.list_evaluation_jobs.return_value = {"jobSummaries": []}
            c.list_automated_reasoning_policies.return_value = {
                "automatedReasoningPolicySummaries": []
            }
            return c

        # ------------------------------------------------------------------ #
        # bedrock-agent — count list_knowledge_bases, list_data_sources (per KB),
        #                  get_data_source (per (kb, ds))
        # ------------------------------------------------------------------ #
        if service == "bedrock-agent":

            def _list_knowledge_bases(**kw):
                tracker["list_knowledge_bases"] += 1
                return {"knowledgeBaseSummaries": _KB_SUMMARIES}

            c.list_knowledge_bases.side_effect = _list_knowledge_bases

            def _list_data_sources(knowledgeBaseId, **kw):
                tracker["list_data_sources"][knowledgeBaseId] += 1
                return {
                    "dataSourceSummaries": _KB_DATA_SOURCE_SUMMARIES.get(
                        knowledgeBaseId, []
                    )
                }

            c.list_data_sources.side_effect = _list_data_sources

            def _get_data_source(knowledgeBaseId, dataSourceId, **kw):
                tracker["get_data_source"][(knowledgeBaseId, dataSourceId)] += 1
                return {
                    "dataSource": {
                        "dataSourceConfiguration": {
                            "s3Configuration": {
                                "bucketArn": "arn:aws:s3:::my-kb-datasource-bucket"
                            }
                        }
                    }
                }

            c.get_data_source.side_effect = _get_data_source

            # list_agents for FS-07
            c.list_agents.return_value = {"agentSummaries": []}
            return c

        # ------------------------------------------------------------------ #
        # s3 — count list_buckets
        # ------------------------------------------------------------------ #
        if service == "s3":

            def _list_buckets(**kw):
                tracker["list_buckets"] += 1
                return {"Buckets": _S3_BUCKETS}

            c.list_buckets.side_effect = _list_buckets

            def _get_bucket_versioning(Bucket, **kw):
                return {"Status": "Enabled"}

            c.get_bucket_versioning.side_effect = _get_bucket_versioning

            def _get_bucket_tagging(Bucket, **kw):
                return {
                    "TagSet": [{"Key": "data-classification", "Value": "Confidential"}]
                }

            c.get_bucket_tagging.side_effect = _get_bucket_tagging

            def _get_bucket_notification_configuration(Bucket, **kw):
                return {"EventBridgeConfiguration": {}}

            c.get_bucket_notification_configuration.side_effect = (
                _get_bucket_notification_configuration
            )
            return c

        # ------------------------------------------------------------------ #
        # shield — needed for FS-01
        # ------------------------------------------------------------------ #
        if service == "shield":
            c.describe_subscription.return_value = {}
            return c

        # ------------------------------------------------------------------ #
        # Non-inventory services — return minimal responses so checks complete
        # ------------------------------------------------------------------ #
        if service == "apigateway":
            c.get_usage_plans.return_value = {
                "items": [
                    {
                        "name": "default",
                        "throttle": {"rateLimit": 500, "burstLimit": 200},
                    }
                ]
            }
            c.get_rest_apis.return_value = {"items": []}
            return c

        if service == "ce":
            c.get_anomaly_monitors.return_value = {
                "AnomalyMonitors": [
                    {
                        "MonitorType": "DIMENSIONAL",
                        "MonitorDimension": "SERVICE",
                        "MonitorSpecification": {},
                    }
                ]
            }
            return c

        if service == "cloudwatch":
            pag = MagicMock()
            pag.paginate.return_value = [
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
            c.get_paginator.return_value = pag
            return c

        if service == "budgets":
            pag = MagicMock()
            pag.paginate.return_value = [
                {
                    "Budgets": [
                        {
                            "BudgetName": "bedrock-spend",
                            "CostFilters": {"Service": ["Amazon Bedrock"]},
                        }
                    ]
                }
            ]
            c.get_paginator.return_value = pag
            return c

        if service == "sts":
            c.get_caller_identity.return_value = {"Account": "123456789012"}
            return c

        if service == "service-quotas":
            applied_pag = MagicMock()
            applied_pag.paginate.return_value = [
                {
                    "Quotas": [
                        {
                            "QuotaName": "On-demand InvokeModel tokens per minute for anthropic.claude",
                            "QuotaCode": "L-TPMTEST",
                            "Value": 200000,
                        }
                    ]
                }
            ]
            defaults_pag = MagicMock()
            defaults_pag.paginate.return_value = [
                {"Quotas": [{"QuotaCode": "L-TPMTEST", "Value": 100000}]}
            ]

            def get_paginator(op):
                if op == "list_service_quotas":
                    return applied_pag
                if op == "list_aws_default_service_quotas":
                    return defaults_pag
                p = MagicMock()
                p.paginate.return_value = [{}]
                return p

            c.get_paginator.side_effect = get_paginator
            return c

        if service == "stepfunctions":
            c.list_state_machines.return_value = {"stateMachines": []}
            return c

        if service == "iam":
            c.list_policies.return_value = {"Policies": []}
            pag = MagicMock()
            pag.paginate.return_value = [{}]
            c.get_paginator.return_value = pag
            return c

        if service == "config":
            c.describe_config_rules.return_value = {"ConfigRules": []}
            return c

        if service == "ecr":
            c.describe_repositories.return_value = {"repositories": []}
            return c

        if service == "sagemaker":
            c.list_feature_groups.return_value = {"FeatureGroupSummaries": []}
            c.list_processing_jobs.return_value = {"ProcessingJobSummaries": []}
            c.list_models.return_value = {"Models": []}
            pag = MagicMock()
            pag.paginate.return_value = [{}]
            c.get_paginator.return_value = pag
            return c

        if service == "logs":
            c.list_log_groups.return_value = {"logGroups": []}
            pag = MagicMock()
            pag.paginate.return_value = [{"logGroups": []}]
            c.get_paginator.return_value = pag
            return c

        if service == "macie2":
            c.get_macie_session.side_effect = Exception("macie not enabled")
            return c

        if service == "opensearchserverless":
            c.list_security_policies.return_value = {"securityPolicySummaries": []}
            return c

        if service == "bedrock-agent-runtime":
            return c

        if service == "bedrock-runtime":
            return c

        if service == "events":
            c.list_rules.return_value = {"Rules": []}
            return c

        if service == "scheduler":
            c.list_schedules.return_value = {"Schedules": []}
            return c

        if service == "agentcore":
            c.list_agent_runtimes.return_value = {"agentRuntimes": []}
            return c

        if service == "organizations":
            c.list_policies.return_value = {"Policies": []}
            return c

        # Catch-all: return generic mock for any other service
        pag = MagicMock()
        pag.paginate.return_value = [{}]
        c.get_paginator.return_value = pag
        return c

    return side_effect, tracker


# ===========================================================================
# Helper: run lambda_handler with counting mocks
# ===========================================================================


def _run_with_counting_mocks(event=None):
    """Run lambda_handler end-to-end with counting mocks.

    Returns the (result, tracker) pair where tracker holds all call counts.
    """
    if event is None:
        event = {"Execution": {"Name": "at-most-once-test-001"}}

    side_effect, tracker = _build_counting_client_factory()

    with (
        patch("app.boto3.client") as mock_client,
        patch("app.get_permissions_cache") as mock_cache,
        patch("app.write_to_s3") as mock_s3,
    ):
        mock_client.side_effect = side_effect
        mock_cache.return_value = {"role_permissions": {}, "user_permissions": {}}
        mock_s3.return_value = "https://test-bucket.s3.amazonaws.com/finserv_security_report_at-most-once-test-001.csv"

        result = app.lambda_handler(event, None)

    return result, tracker


# ===========================================================================
# Test class
# ===========================================================================


class TestAtMostOnceInvariants:
    """Handler-level counting-mock harness for the at-most-once invariants.

    Validates: Requirements REQ-9.1, REQ-9.4, REQ-9.6
    INV-2: Each shared listing API ≤ 1×/invocation; each shared detail API
           ≤ 1× per resource/invocation.
    """

    @pytest.fixture(autouse=True)
    def _run_handler(self):
        """Run lambda_handler once and expose result + tracker to every test."""
        self.result, self.tracker = _run_with_counting_mocks()

    # ------------------------------------------------------------------
    # Sanity: handler completed successfully
    # ------------------------------------------------------------------

    def test_handler_completes_successfully(self):
        """Counting mocks are sufficient for the handler to return 200."""
        assert self.result["statusCode"] == 200

    # ------------------------------------------------------------------
    # Listing API invariants (≤ 1 per run)
    # ------------------------------------------------------------------

    def test_list_functions_at_most_once(self):
        """list_functions SHALL be called ≤ 1 per run (REQ-9.1, INV-2).

        6 checks consume Lambda functions; the collector must issue at most one
        call regardless.
        """
        count = self.tracker["list_functions"]
        assert count <= 1, (
            f"list_functions was called {count} time(s); expected ≤ 1. "
            "Multiple calls indicate the inventory was not consolidated."
        )

    def test_list_guardrails_at_most_once(self):
        """list_guardrails SHALL be called ≤ 1 per run (REQ-9.1, INV-2).

        9 checks consume guardrails; the collector must issue at most one call.
        """
        count = self.tracker["list_guardrails"]
        assert count <= 1, f"list_guardrails was called {count} time(s); expected ≤ 1."

    def test_list_knowledge_bases_at_most_once(self):
        """list_knowledge_bases SHALL be called ≤ 1 per run (REQ-9.1, INV-2).

        6 checks consume knowledge bases; the collector must issue at most one call.
        """
        count = self.tracker["list_knowledge_bases"]
        assert count <= 1, (
            f"list_knowledge_bases was called {count} time(s); expected ≤ 1."
        )

    def test_list_buckets_at_most_once(self):
        """list_buckets SHALL be called ≤ 1 per run (REQ-9.1, INV-2).

        2 checks consume S3 buckets; the collector must issue at most one call.
        """
        count = self.tracker["list_buckets"]
        assert count <= 1, f"list_buckets was called {count} time(s); expected ≤ 1."

    def test_list_web_acls_at_most_once(self):
        """list_web_acls SHALL be called ≤ 1 per run (REQ-9.1, INV-2).

        4 checks consume WAFv2 Web ACLs; the collector must issue at most one
        call (previously each check called it independently).
        """
        count = self.tracker["list_web_acls"]
        assert count <= 1, f"list_web_acls was called {count} time(s); expected ≤ 1."

    def test_list_data_sources_at_most_once_per_kb(self):
        """list_data_sources SHALL be called ≤ 1 per KB per run (REQ-9.1, REQ-3.5, INV-2).

        3 checks consume data-source summaries (FS-31, FS-33, FS-65); each
        KB's list_data_sources must be called at most once.
        """
        for kb_id, count in self.tracker["list_data_sources"].items():
            assert count <= 1, (
                f"list_data_sources for KB '{kb_id}' was called {count} time(s); "
                "expected ≤ 1."
            )

    # ------------------------------------------------------------------
    # Detail API invariants (≤ 1 per distinct resource per run)
    # ------------------------------------------------------------------

    def test_get_guardrail_at_most_once_per_id(self):
        """get_guardrail SHALL be called ≤ 1 per distinct guardrail id per run.

        Requirements REQ-9.1, REQ-3.1, INV-2.
        9 checks inspect guardrail detail; the inventory must serve it from
        cache without issuing further get_guardrail calls.
        """
        for gid, count in self.tracker["get_guardrail"].items():
            assert count <= 1, (
                f"get_guardrail for guardrail '{gid}' was called {count} time(s); "
                "expected ≤ 1."
            )

    def test_get_web_acl_at_most_once_per_id(self):
        """get_web_acl SHALL be called ≤ 1 per distinct ACL id per run.

        Requirements REQ-9.1, REQ-3.2, INV-2.
        3 checks (FS-53, FS-56, FS-68) inspect ACL detail; the inventory must
        serve it from cache.
        """
        for acl_id, count in self.tracker["get_web_acl"].items():
            assert count <= 1, (
                f"get_web_acl for ACL '{acl_id}' was called {count} time(s); "
                "expected ≤ 1."
            )

    def test_get_data_source_at_most_once_per_pair(self):
        """get_data_source SHALL be called ≤ 1 per (kb_id, ds_id) pair per run.

        Requirements REQ-9.1, REQ-3.5, INV-2.
        2 checks (FS-33, FS-65) call get_data_source; the inventory must cache
        the result and serve it to both.
        """
        for (kb_id, ds_id), count in self.tracker["get_data_source"].items():
            assert count <= 1, (
                f"get_data_source for (kb='{kb_id}', ds='{ds_id}') was called "
                f"{count} time(s); expected ≤ 1."
            )

    # ------------------------------------------------------------------
    # Positive coverage: calls were made (inventory was actually collected)
    # ------------------------------------------------------------------

    def test_listing_apis_were_called_at_least_once(self):
        """Verify the counting mocks were exercised — all five listing APIs called."""
        assert self.tracker["list_functions"] >= 1, "list_functions was never called"
        assert self.tracker["list_guardrails"] >= 1, "list_guardrails was never called"
        assert self.tracker["list_knowledge_bases"] >= 1, (
            "list_knowledge_bases was never called"
        )
        assert self.tracker["list_buckets"] >= 1, "list_buckets was never called"
        assert self.tracker["list_web_acls"] >= 1, "list_web_acls was never called"

    def test_guardrail_detail_called_for_every_guardrail(self):
        """get_guardrail was called for each guardrail in the summary list."""
        expected_ids = {g["id"] for g in _GUARDRAIL_SUMMARIES}
        called_ids = set(self.tracker["get_guardrail"].keys())
        assert expected_ids == called_ids, (
            f"Expected get_guardrail calls for {expected_ids}; "
            f"actually called for {called_ids}."
        )

    def test_web_acl_detail_called_for_every_acl(self):
        """get_web_acl was called for each ACL in the summary list."""
        expected_ids = {acl["Id"] for acl in _ACL_SUMMARIES}
        called_ids = set(self.tracker["get_web_acl"].keys())
        assert expected_ids == called_ids, (
            f"Expected get_web_acl calls for {expected_ids}; "
            f"actually called for {called_ids}."
        )

    def test_data_source_detail_called_for_all_data_sources(self):
        """get_data_source was called for each (kb_id, ds_id) pair."""
        expected_pairs = {
            (kb_id, ds["dataSourceId"])
            for kb_id, ds_list in _KB_DATA_SOURCE_SUMMARIES.items()
            for ds in ds_list
        }
        called_pairs = set(self.tracker["get_data_source"].keys())
        assert expected_pairs == called_pairs, (
            f"Expected get_data_source calls for {expected_pairs}; "
            f"actually called for {called_pairs}."
        )

    def test_list_data_sources_called_for_all_kbs(self):
        """list_data_sources was called for each KB in the summary list."""
        expected_kb_ids = {kb["knowledgeBaseId"] for kb in _KB_SUMMARIES}
        called_kb_ids = set(self.tracker["list_data_sources"].keys())
        assert expected_kb_ids == called_kb_ids, (
            f"Expected list_data_sources calls for {expected_kb_ids}; "
            f"actually called for {called_kb_ids}."
        )

    # ------------------------------------------------------------------
    # Exact counts (not just ≤ 1: assert exactly 1 for non-empty inventories)
    # ------------------------------------------------------------------

    def test_list_functions_called_exactly_once(self):
        """list_functions is called exactly once — not zero, not more than one."""
        assert self.tracker["list_functions"] == 1

    def test_list_guardrails_called_exactly_once(self):
        """list_guardrails is called exactly once — not zero, not more than one."""
        assert self.tracker["list_guardrails"] == 1

    def test_list_knowledge_bases_called_exactly_once(self):
        """list_knowledge_bases is called exactly once."""
        assert self.tracker["list_knowledge_bases"] == 1

    def test_list_buckets_called_exactly_once(self):
        """list_buckets is called exactly once."""
        assert self.tracker["list_buckets"] == 1

    def test_list_web_acls_called_exactly_once(self):
        """list_web_acls is called exactly once."""
        assert self.tracker["list_web_acls"] == 1

    def test_list_data_sources_called_exactly_once_per_kb(self):
        """list_data_sources is called exactly once for each KB (not zero, not more)."""
        for kb_id in {kb["knowledgeBaseId"] for kb in _KB_SUMMARIES}:
            count = self.tracker["list_data_sources"][kb_id]
            assert count == 1, (
                f"list_data_sources for KB '{kb_id}' was called {count} time(s); "
                "expected exactly 1."
            )

    def test_get_guardrail_called_exactly_once_per_guardrail(self):
        """get_guardrail is called exactly once per guardrail id."""
        for g in _GUARDRAIL_SUMMARIES:
            gid = g["id"]
            count = self.tracker["get_guardrail"][gid]
            assert count == 1, (
                f"get_guardrail for '{gid}' was called {count} time(s); "
                "expected exactly 1."
            )

    def test_get_web_acl_called_exactly_once_per_acl(self):
        """get_web_acl is called exactly once per ACL id."""
        for acl in _ACL_SUMMARIES:
            acl_id = acl["Id"]
            count = self.tracker["get_web_acl"][acl_id]
            assert count == 1, (
                f"get_web_acl for '{acl_id}' was called {count} time(s); "
                "expected exactly 1."
            )

    def test_get_data_source_called_exactly_once_per_pair(self):
        """get_data_source is called exactly once per (kb_id, ds_id) pair."""
        for kb_id, ds_list in _KB_DATA_SOURCE_SUMMARIES.items():
            for ds in ds_list:
                ds_id = ds["dataSourceId"]
                count = self.tracker["get_data_source"][(kb_id, ds_id)]
                assert count == 1, (
                    f"get_data_source for (kb='{kb_id}', ds='{ds_id}') was called "
                    f"{count} time(s); expected exactly 1."
                )
