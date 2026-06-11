#!/usr/bin/env python3
"""
Phase 2 — Live AWS integration test for finserv_assessments.

Invokes each check function individually against a real AWS account,
captures results, and produces a triage report showing:
  - PASS: check completed successfully, resources found compliant or N/A
  - WARN: check completed, found non-compliant resources (expected in dev)
  - ERROR: check failed — likely IAM permission issue or API incompatibility

Usage:
    # Run all checks (default):
    python tests/test_phase2_live.py

    # Run a single check by name:
    python tests/test_phase2_live.py check_waf_shield_on_bedrock_endpoints

    # Run with a specific S3 bucket for CSV output:
    AIML_ASSESSMENT_BUCKET_NAME=my-bucket python tests/test_phase2_live.py

Prerequisites:
    - AWS credentials configured (aws configure or env vars)
    - Read-only access to the target account
    - No Docker required
"""

import json
import os
import sys
import time
from datetime import datetime

# Make finserv_assessments importable
FINSERV_DIR = os.path.join(os.path.dirname(__file__), "..", "finserv_assessments")
if FINSERV_DIR not in sys.path:
    sys.path.insert(0, FINSERV_DIR)

# Set env var if not already set
if not os.environ.get("AIML_ASSESSMENT_BUCKET_NAME"):
    os.environ["AIML_ASSESSMENT_BUCKET_NAME"] = "mehta-test-v55"

import app  # noqa: E402  (import must follow sys.path + env setup above)


# ---------------------------------------------------------------------------
# All check functions in execution order (matches lambda_handler).
#
# Each entry is a 3-tuple: (func_name, needs_cache, needs_inventory)
#   needs_cache     True  → pass permission_cache as first argument
#   needs_inventory True  → pass inventory as first argument
#   (both False)   → call with no arguments
# ---------------------------------------------------------------------------
CHECK_FUNCTIONS = [
    # Category 1: Unbounded Consumption
    ("check_waf_shield_on_bedrock_endpoints", False, True),
    ("check_api_gateway_rate_limiting", False, False),
    ("check_bedrock_token_quotas", False, False),
    ("check_cost_anomaly_detection", False, False),
    ("check_cloudwatch_token_alarms", False, False),
    ("check_aws_budgets_for_aiml", False, False),
    # Category 2: Excessive Agency
    ("check_bedrock_agent_action_boundaries", True, False),
    ("check_agentcore_policy_engine", False, False),
    ("check_agent_transaction_limits", False, True),
    ("check_human_in_the_loop_for_high_risk_actions", False, False),
    ("check_agent_rate_alarms", False, False),
    # Category 3: Supply Chain Vulnerabilities
    ("check_scp_model_access_restrictions", False, False),
    ("check_model_inventory_tagging", False, False),
    ("check_model_onboarding_governance", False, False),
    ("check_bedrock_model_evaluation_adversarial", False, False),
    ("check_ecr_image_scanning", False, False),
    # Category 4: Training Data & Model Poisoning
    ("check_feature_store_rollback_capability", False, False),
    ("check_training_data_s3_versioning", False, True),
    # Category 5: Vector & Embedding Weaknesses
    ("check_knowledge_base_iam_least_privilege", True, False),
    ("check_knowledge_base_metadata_filtering", False, True),
    ("check_opensearch_serverless_encryption", False, False),
    ("check_knowledge_base_vpc_access", False, False),
    # Category 6: Non-Compliant Output
    ("check_guardrail_contextual_grounding", False, True),
    ("check_automated_reasoning_policies", False, False),
    ("check_guardrail_denied_topics_financial", False, True),
    ("check_compliance_disclaimer_in_outputs", False, False),
    ("check_bedrock_evaluation_compliance_datasets", False, False),
    # Category 7: Misinformation
    ("check_knowledge_base_data_source_sync", False, True),
    ("check_source_attribution_in_guardrails", False, False),
    ("check_knowledge_base_integrity_monitoring", False, True),
    ("check_fm_version_currency", False, False),
    # Category 8: Abusive or Harmful Output
    ("check_fmeval_harmful_content", False, False),
    ("check_guardrail_content_filters", False, True),
    ("check_user_feedback_mechanism", False, False),
    ("check_guardrail_word_filters", False, True),
    # Category 9: Biased Output
    ("check_sagemaker_clarify_bias", False, False),
    ("check_bedrock_evaluation_bias_datasets", False, False),
    ("check_sagemaker_clarify_explainability", False, False),
    ("check_ai_service_cards_documentation", False, False),
    # Category 10: Sensitive Information Disclosure
    ("check_cloudwatch_log_pii_masking", False, False),
    ("check_macie_on_training_data_buckets", False, False),
    ("check_guardrail_pii_filters", False, True),
    ("check_data_classification_tagging", False, True),
    # Category 11: Hallucination
    ("check_guardrail_grounding_threshold", False, True),
    ("check_rag_knowledge_base_configured", False, True),
    ("check_hallucination_disclaimer_advisory", False, False),
    ("check_guardrail_relevance_grounding", False, True),
    # Category 12: Prompt Injection
    ("check_prompt_injection_input_validation", False, True),
    ("check_bedrock_sdk_version_currency", False, True),
    ("check_waf_sql_injection_rules", False, True),
    ("check_penetration_testing_evidence", False, False),
    # Category 13: Improper Output Handling
    ("check_output_validation_lambda", False, True),
    ("check_xss_prevention_waf", False, True),
    ("check_output_encoding_advisory", False, False),
    ("check_output_schema_validation", False, True),
    # Category 14: Off-Topic & Inappropriate Output
    ("check_guardrail_topic_allowlist", False, True),
    ("check_contextual_grounding_for_offtopic", False, False),
    # Category 15: Out-of-Date Training Data
    ("check_knowledge_base_sync_schedule", False, True),
    ("check_data_currency_disclaimer_advisory", False, False),
    ("check_foundation_model_lifecycle_policy", False, False),
    # Material Gap Checks
    ("check_kb_datasource_s3_event_notifications", False, True),
    ("check_agentcore_end_user_identity_propagation", False, False),
    ("check_agent_financial_transaction_thresholds", False, True),
    ("check_api_gateway_request_body_size_limits", False, True),
    ("check_prompt_input_validation_function", False, True),
]


def run_single_check(
    func_name, needs_cache, needs_inventory, permission_cache, inventory
):
    """Run a single check function and return a result dict."""
    func = getattr(app, func_name)
    start = time.time()
    try:
        if needs_cache:
            result = func(permission_cache)
        elif needs_inventory:
            result = func(inventory)
        else:
            result = func()
        elapsed = time.time() - start
        status = result.get("status", "UNKNOWN")
        detail = result.get("details", "")
        csv_count = len(result.get("csv_data", []))

        # Extract check IDs and statuses from csv_data for the report
        csv_summary = []
        for row in result.get("csv_data", []):
            csv_summary.append(f"{row.get('Check_ID', '?')}: {row.get('Status', '?')}")

        return {
            "func": func_name,
            "status": status,
            "elapsed": round(elapsed, 2),
            "csv_count": csv_count,
            "csv_summary": csv_summary,
            "error": detail if status == "ERROR" else "",
        }
    except Exception as e:
        elapsed = time.time() - start
        return {
            "func": func_name,
            "status": "EXCEPTION",
            "elapsed": round(elapsed, 2),
            "csv_count": 0,
            "csv_summary": [],
            "error": f"{type(e).__name__}: {e}",
        }


def main():
    filter_name = sys.argv[1] if len(sys.argv) > 1 else None

    print("=" * 78)
    print("Phase 2 — Live AWS Integration Test")
    print(
        f"Account: {os.popen('aws sts get-caller-identity --query Account --output text 2>/dev/null').read().strip()}"
    )
    print(
        f"Region:  {os.popen('aws configure get region 2>/dev/null').read().strip() or 'us-east-1 (default)'}"
    )
    print(f"Bucket:  {os.environ.get('AIML_ASSESSMENT_BUCKET_NAME', 'NOT SET')}")
    print(f"Time:    {datetime.now().isoformat()}")
    print("=" * 78)

    # Build a minimal permission cache (empty — no pre-cached IAM data)
    permission_cache = {"role_permissions": {}, "user_permissions": {}}

    # Collect the shared resource inventory once — mirrors lambda_handler behaviour.
    print("\nCollecting resource inventory ...", end=" ", flush=True)
    inventory_start = time.time()
    inventory = app.collect_resource_inventory()
    inventory_elapsed = round(time.time() - inventory_start, 2)
    print(f"done ({inventory_elapsed}s)")

    checks_to_run = CHECK_FUNCTIONS
    if filter_name:
        checks_to_run = [(n, c, i) for n, c, i in CHECK_FUNCTIONS if n == filter_name]
        if not checks_to_run:
            print(f"ERROR: No check function named '{filter_name}'")
            sys.exit(1)

    results = []
    total = len(checks_to_run)

    for idx, (func_name, needs_cache, needs_inventory) in enumerate(checks_to_run, 1):
        print(f"\n[{idx:2d}/{total}] {func_name} ...", end=" ", flush=True)
        r = run_single_check(
            func_name, needs_cache, needs_inventory, permission_cache, inventory
        )
        results.append(r)

        # Color-coded status
        status = r["status"]
        if status == "PASS":
            icon = "✅"
        elif status == "WARN":
            icon = "⚠️ "
        elif status == "ERROR":
            icon = "❌"
        elif status == "EXCEPTION":
            icon = "💥"
        else:
            icon = "❓"

        print(f"{icon} {status} ({r['elapsed']}s, {r['csv_count']} findings)")
        if r["error"]:
            # Truncate long error messages
            err = r["error"][:200]
            print(f"     └─ {err}")
        for cs in r["csv_summary"]:
            print(f"     └─ {cs}")

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    print("\n" + "=" * 78)
    print("TRIAGE SUMMARY")
    print("=" * 78)

    pass_count = sum(1 for r in results if r["status"] == "PASS")
    warn_count = sum(1 for r in results if r["status"] == "WARN")
    error_count = sum(1 for r in results if r["status"] == "ERROR")
    exception_count = sum(1 for r in results if r["status"] == "EXCEPTION")
    total_findings = sum(r["csv_count"] for r in results)
    total_time = sum(r["elapsed"] for r in results)

    print(f"  ✅ PASS:      {pass_count:3d}")
    print(f"  ⚠️  WARN:      {warn_count:3d}")
    print(f"  ❌ ERROR:     {error_count:3d}")
    print(f"  💥 EXCEPTION: {exception_count:3d}")
    print("  ─────────────────")
    print(f"  Total checks: {len(results):3d}")
    print(f"  Total findings: {total_findings}")
    print(f"  Total time:   {total_time:.1f}s")

    if error_count > 0 or exception_count > 0:
        print("\n--- ERRORS TO TRIAGE ---")
        for r in results:
            if r["status"] in ("ERROR", "EXCEPTION"):
                print(f"  {r['func']}: {r['error'][:150]}")

    # -----------------------------------------------------------------------
    # Write JSON report for further analysis
    # -----------------------------------------------------------------------
    report_path = os.path.join(os.path.dirname(__file__), "..", "phase2_results.json")
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nDetailed results written to: {report_path}")

    # Exit code: 0 if no EXCEPTION, non-zero otherwise
    sys.exit(1 if exception_count > 0 else 0)


if __name__ == "__main__":
    main()
