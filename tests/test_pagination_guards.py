"""Prevent new assessment list calls from silently reading only one page."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SECURITY_FUNCTIONS = REPO_ROOT / "aiml-security-assessment/functions/security"

ASSESSMENT_APPS = (
    "bedrock_assessments/app.py",
    "sagemaker_assessments/app.py",
    "agentcore_assessments/app.py",
    "responsible_ai_grc_assessments/app.py",
    "owasp_assessments/app.py",
)

# These operations have no continuation fields in their botocore service
# models. Scope each exemption to its current function so a pageable operation
# with the same name on another client is not accidentally exempted.
NON_PAGEABLE_CALLS = {
    (
        "bedrock_assessments/app.py",
        "check_bedrock_inference_profile_governance",
        "list_tags_for_resource",
    ),
    (
        "bedrock_assessments/app.py",
        "check_bedrock_resource_owner_tag",
        "list_tags_for_resource",
    ),
    (
        "responsible_ai_grc_assessments/app.py",
        "check_model_inventory_tagging",
        "list_tags_for_resource",
    ),
    # AC-41: bedrock-agentcore-control and logs ListTagsForResource take only
    # resourceArn and return only tags.
    (
        "agentcore_assessments/app.py",
        "read_tags",
        "list_tags_for_resource",
    ),
    (
        "agentcore_assessments/app.py",
        "check_agentcore_evaluation_personal_data",
        "list_tags_for_resource",
    ),
    (
        "responsible_ai_grc_assessments/app.py",
        "check_model_inventory_tagging",
        "list_tags",
    ),
    (
        "responsible_ai_grc_assessments/app.py",
        "check_fm_version_currency",
        "list_foundation_models",
    ),
    (
        "responsible_ai_grc_assessments/app.py",
        "check_foundation_model_lifecycle_policy",
        "list_foundation_models",
    ),
}

# Direct bounded calls are permitted only at these reviewed call sites. Most
# are one-item existence probes; SM-25 deliberately samples recent metadata.
# Freezing each operation and exact bound prevents a newly added ``MaxResults=1``
# call from bypassing the guard without review.
BOUNDED_DIRECT_CALLS = {
    (
        "bedrock_assessments/app.py",
        "detect_bedrock_regional_footprint",
        "list_guardrails",
    ): ("maxResults", 1),
    # A member account probes whether it is a delegated administrator for
    # policy management; the result of the read decides, not its content.
    (
        "bedrock_assessments/app.py",
        "_organization_policy_context",
        "list_policies",
    ): ("MaxResults", 1),
    (
        "bedrock_assessments/app.py",
        "detect_bedrock_regional_footprint",
        "list_prompts",
    ): ("maxResults", 1),
    (
        "bedrock_assessments/app.py",
        "detect_bedrock_regional_footprint",
        "list_agents",
    ): ("maxResults", 1),
    (
        "sagemaker_assessments/app.py",
        "get_model_package_lineage_artifact_arn",
        "list_artifacts",
    ): ("MaxResults", 1),
    (
        "sagemaker_assessments/app.py",
        "has_lineage_associations",
        "list_associations",
    ): ("MaxResults", 1),
    (
        "sagemaker_assessments/app.py",
        "get_guardduty_detector_inventory",
        "list_detectors",
    ): ("MaxResults", 1),
    (
        "sagemaker_assessments/app.py",
        "check_sagemaker_mlops_utilization",
        "list_pipeline_executions",
    ): ("MaxResults", 1),
    (
        "sagemaker_assessments/app.py",
        "check_ml_lineage_tracking",
        "list_experiments",
    ): ("MaxResults", 10),
    (
        "sagemaker_assessments/app.py",
        "check_ml_lineage_tracking",
        "list_trials",
    ): ("MaxResults", 10),
    (
        "sagemaker_assessments/app.py",
        "lambda_handler",
        "list_notebook_instances",
    ): ("MaxResults", 1),
    (
        "agentcore_assessments/app.py",
        "lambda_handler",
        "list_agent_runtimes",
    ): ("maxResults", 1),
    # AC-48 probes each other Region with the handler's availability call
    # before it lists that Region's resources in full.
    (
        "agentcore_assessments/app.py",
        "_agentcore_other_region_role_references",
        "list_agent_runtimes",
    ): ("maxResults", 1),
    # AC-33 probes each assessed Region the same way before it reads that
    # Region's runtimes and gateways in full.
    (
        "agentcore_assessments/app.py",
        "_workload_identities_by_role_in_regions",
        "list_agent_runtimes",
    ): ("maxResults", 1),
    # AC-32 probes each assessed Region before it reads the issuers that
    # Region's runtime and gateway authorizers trust.
    (
        "agentcore_assessments/app.py",
        "_jwt_authorizer_issuers",
        "list_agent_runtimes",
    ): ("maxResults", 1),
    # AC-46 and AC-51 probe each other assessed Region before they list its
    # runtimes or gateways in full, once, on the primary Region.
    (
        "agentcore_assessments/app.py",
        "_agentcore_resources_in_regions",
        "list_agent_runtimes",
    ): ("maxResults", 1),
    (
        "responsible_ai_grc_assessments/app.py",
        "detect_finserv_regional_footprint",
        "list_guardrails",
    ): ("maxResults", 1),
    (
        "responsible_ai_grc_assessments/app.py",
        "detect_finserv_regional_footprint",
        "list_agents",
    ): ("maxResults", 1),
    (
        "responsible_ai_grc_assessments/app.py",
        "detect_finserv_regional_footprint",
        "list_knowledge_bases",
    ): ("maxResults", 1),
    (
        "responsible_ai_grc_assessments/app.py",
        "detect_finserv_regional_footprint",
        "list_agent_runtimes",
    ): ("maxResults", 1),
    (
        "responsible_ai_grc_assessments/app.py",
        "detect_finserv_regional_footprint",
        "list_endpoints",
    ): ("MaxResults", 1),
    (
        "responsible_ai_grc_assessments/app.py",
        "detect_finserv_regional_footprint",
        "list_models",
    ): ("MaxResults", 1),
    (
        "responsible_ai_grc_assessments/app.py",
        "detect_finserv_regional_footprint",
        "list_feature_groups",
    ): ("MaxResults", 1),
}


def _parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _containing_function(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str:
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current.name
    return "<module>"


def _inside_continuation_while(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, ast.While):
            token_names = {
                child.id.lower()
                for child in ast.walk(current)
                if isinstance(child, ast.Name)
                and ("token" in child.id.lower() or "marker" in child.id.lower())
            }
            return bool(token_names)
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
    return False


def _integer_page_limit(call: ast.Call) -> tuple[str, int] | None:
    for keyword in call.keywords:
        if (
            keyword.arg in {"MaxResults", "maxResults", "MaxItems"}
            and isinstance(keyword.value, ast.Constant)
            and isinstance(keyword.value.value, int)
        ):
            return keyword.arg, keyword.value.value
    return None


def _direct_list_calls(relative_path: str):
    path = SECURITY_FUNCTIONS / relative_path
    tree = ast.parse(path.read_text(), filename=str(path))
    parents = _parent_map(tree)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr.startswith("list_")
        ):
            yield (
                node,
                _containing_function(node, parents),
                node.func.attr,
                parents,
            )


@pytest.mark.parametrize("relative_path", ASSESSMENT_APPS)
def test_direct_list_calls_have_continuation_handling_or_explicit_scope(
    relative_path,
):
    violations = []
    observed_exemptions = set()

    for call, function_name, operation_name, parents in _direct_list_calls(
        relative_path
    ):
        key = (relative_path, function_name, operation_name)

        if _inside_continuation_while(call, parents):
            continue

        page_limit = _integer_page_limit(call)

        if key in NON_PAGEABLE_CALLS:
            observed_exemptions.add(key)
            continue

        expected_bound = BOUNDED_DIRECT_CALLS.get(key)
        if expected_bound and page_limit == expected_bound:
            observed_exemptions.add(key)
            continue

        violations.append(
            f"{relative_path}:{call.lineno} {function_name}() calls "
            f"{operation_name}() directly without continuation handling"
        )

    expected_exemptions = {
        key
        for key in NON_PAGEABLE_CALLS | set(BOUNDED_DIRECT_CALLS)
        if key[0] == relative_path
    }
    stale_exemptions = expected_exemptions - observed_exemptions

    assert not violations, (
        "\n".join(violations)
        + "\nUse a paginator/continuation helper, an explicit one-item "
        "existence probe, or a narrowly justified exemption."
    )
    assert not stale_exemptions, (
        f"Remove stale pagination exemptions for {relative_path}: "
        f"{sorted(stale_exemptions)}"
    )
