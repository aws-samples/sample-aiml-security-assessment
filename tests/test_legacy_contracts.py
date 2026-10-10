"""Compatibility locks for report selectors, CSS classes, and deployment identities.

Phase 1 changed visible *labels* only and froze every machine identity. Phase
2 Stage 2b (see docs/RESPONSIBLE_AI_GRC_PHASE2_STAGE2B_DESIGN.md, now
superseded) renamed the CloudFormation logical ID, the physical Lambda name
suffix, all four Step Functions state names, and the ASL error result path
from FinServ-branded names to Responsible AI GRC-branded names, and this file
was updated to lock in those new values.

A later, full rebrand (this commit) went further and hard-renamed every
remaining FinServ-branded machine identity as well: the report DOM slug and
CSS class names, the CSV filename prefix, the doc filenames, and the IAM Sid.
There is no dual-write and no additive alias for any of these — the old
"finserv" values are fully retired, and the assertions below lock in the new
values, not the old ones. Only the "aiml-security-" physical-name prefix
(kept for a reason specific to Stage 2b — see the physical-name test below)
remains genuinely unchanged.

If an INTENTIONAL, reviewed rename makes one of these fail, update the
assertion to lock in the new value and record why in the commit — do not
silently delete the assertion. If an UNINTENTIONAL change makes one of these
fail, the change is wrong, not the test.
"""

import importlib.util
import json
import os
import sys

import pytest
import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORT_DIR = os.path.join(
    REPO_ROOT,
    "aiml-security-assessment",
    "functions",
    "security",
    "generate_consolidated_report",
)
TEMPLATE_PATH = os.path.join(REPO_ROOT, "aiml-security-assessment", "template.yaml")
TEMPLATE_MULTI_PATH = os.path.join(
    REPO_ROOT, "aiml-security-assessment", "template-multi-account.yaml"
)
ASL_PATH = os.path.join(
    REPO_ROOT, "aiml-security-assessment", "statemachine", "assessments.asl.json"
)

if REPORT_DIR not in sys.path:
    sys.path.insert(0, REPORT_DIR)

_spec = importlib.util.spec_from_file_location(
    "legacy_contract_report_template", os.path.join(REPORT_DIR, "report_template.py")
)
report_template = importlib.util.module_from_spec(_spec)
sys.modules["legacy_contract_report_template"] = report_template
_spec.loader.exec_module(report_template)


# ---------------------------------------------------------------------------
# CloudFormation: SAM templates parse with an intrinsic-tolerant loader.
# ---------------------------------------------------------------------------


class _CfnLoader(yaml.SafeLoader):
    """SafeLoader that tolerates CloudFormation short-form intrinsics."""


def _cfn_multi_constructor(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return {f"Fn::{tag_suffix}": loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {f"Fn::{tag_suffix}": loader.construct_sequence(node)}
    return {f"Fn::{tag_suffix}": loader.construct_mapping(node)}


_CfnLoader.add_multi_constructor("!", _cfn_multi_constructor)


def _load_template(path):
    with open(path) as handle:
        # _CfnLoader subclasses yaml.SafeLoader and adds only a multi-constructor
        # that turns CloudFormation short-form intrinsics (!Sub, !Ref, !GetAtt)
        # into plain dicts, so no arbitrary object instantiation is possible.
        # yaml.safe_load() cannot be used here: it hardcodes SafeLoader and gives
        # no way to register the intrinsic handler these templates require.
        return yaml.load(handle, Loader=_CfnLoader)  # nosec B506


@pytest.fixture(scope="module")
def template():
    return _load_template(TEMPLATE_PATH)


@pytest.fixture(scope="module")
def template_multi():
    return _load_template(TEMPLATE_MULTI_PATH)


@pytest.fixture(scope="module")
def asl():
    with open(ASL_PATH) as handle:
        return handle.read()


# ---------------------------------------------------------------------------
# Step Functions: all FOUR Responsible AI GRC state names are customer-visible
# in the console and in execution history. Renamed in Phase 2 Stage 2b from
# their FinServ-branded predecessors — this is the one reviewed exception to
# "state names don't change" the Phase 1 test suite otherwise enforced.
# ---------------------------------------------------------------------------

ASL_STATE_NAMES = [
    "Responsible AI GRC Enabled?",
    "Responsible AI GRC Security Assessment",
    "Responsible AI GRC Assessment Incomplete",
    "Responsible AI GRC Assessment Skipped",
]

RETIRED_ASL_STATE_NAMES = [
    "FinServ Enabled?",
    "FinServ Security Assessment",
    "FinServ Assessment Incomplete",
    "FinServ Assessment Skipped",
]


@pytest.mark.parametrize("state_name", ASL_STATE_NAMES)
def test_asl_state_names_are_frozen(asl, state_name):
    assert f'"{state_name}"' in asl


@pytest.mark.parametrize("state_name", RETIRED_ASL_STATE_NAMES)
def test_retired_finserv_asl_state_names_are_gone(asl, state_name):
    """The old names must not linger anywhere the ASL is compared byte-for-byte.

    A partial rename (some occurrences updated, some missed) is worse than no
    rename: it would leave dangling Next/Default references. Assert absence
    explicitly rather than relying on the presence assertions above alone.
    """
    assert f'"{state_name}"' not in asl


def test_asl_error_result_path_is_frozen(asl):
    assert '"ResultPath": "$.responsibleAIGRCError"' in asl


def test_retired_finserv_error_result_path_is_gone(asl):
    assert '"ResultPath": "$.finservError"' not in asl


def test_asl_lambda_substitution_is_frozen(asl):
    assert "${ResponsibleAIGRCAssessmentFunction}" in asl


def test_retired_finserv_lambda_substitution_is_gone(asl):
    assert "${FinServSecurityAssessmentFunction}" not in asl


def test_asl_is_a_substituted_template_not_plain_json(asl):
    """The ASL carries unquoted CloudFormation substitutions.

    e.g. `"MaxConcurrency": ${MaxRegionConcurrency}` — so the file is NOT valid
    JSON on its own and must not be parsed with json.loads by tooling. It
    becomes valid only after SAM performs DefinitionSubstitutions.
    """
    with pytest.raises(json.JSONDecodeError):
        json.loads(asl)
    assert "${MaxRegionConcurrency}" in asl


def test_asl_state_names_fit_the_step_functions_limit():
    """State names are capped at 80 characters."""
    for state_name in ASL_STATE_NAMES:
        assert len(state_name) <= 80


# ---------------------------------------------------------------------------
# Legacy enableFinServ execution-input key: rejected loudly, not skipped
# silently.
#
# EnableFinServAssessment / ENABLE_FINSERV are retained as a legacy alias, but
# only up through the CloudFormation-parameter / CodeBuild-environment-variable
# layer -- buildspec.yml resolves that alias into the effective
# ENABLE_RESPONSIBLE_AI_GRC value and passes only "enableResponsibleAIGRC" into
# StartExecution. There is no execution-input-level alias for "enableFinServ".
#
# A direct StartExecution call using the pre-rebrand input shape
# {"enableFinServ": "true"} (bypassing CodeBuild/buildspec.yml entirely) is
# therefore rejected with a hard Fail state, rather than silently falling
# through to "Responsible AI GRC Assessment Skipped" and completing with a
# report missing the FS section. Fail states cannot carry Retry/Catch/Next, so
# this error propagates past the "Run Security Assessments" Parallel state and
# the "Scan Regions" Map state -- neither has a Catch -- failing the whole
# execution. That full-execution blast radius is intentional: it is the exact
# fail-fast philosophy buildspec.yml already uses for the analogous
# EnableFinServAssessment / EnableResponsibleAIGRCAssessment conflict, applied
# one layer down.
# ---------------------------------------------------------------------------


def _substituted_asl(raw: str) -> dict:
    """Return the ASL parsed as JSON after simulating SAM's DefinitionSubstitutions.

    Mirrors what SAM actually does at deploy time: every ``${Placeholder}``
    becomes a plain string. This lets structural assertions (state graph,
    Fail-state shape, absence of an enclosing Catch) run against a real parsed
    dict instead of brittle substring matching.
    """
    import re

    placeholders = sorted(set(re.findall(r"\$\{([A-Za-z0-9_]+)\}", raw)))
    substituted = raw
    for name in placeholders:
        if name == "MaxRegionConcurrency":
            substituted = substituted.replace(f"${{{name}}}", "2")
        else:
            substituted = substituted.replace(
                f'"${{{name}}}"',
                f'"arn:aws:lambda:us-east-1:123456789012:function:{name}"',
            )
    return json.loads(substituted)


@pytest.fixture(scope="module")
def asl_parsed(asl):
    return _substituted_asl(asl)


@pytest.fixture(scope="module")
def responsible_ai_grc_branch(asl_parsed):
    branches = asl_parsed["States"]["Scan Regions"]["ItemProcessor"]["States"][
        "Run Security Assessments"
    ]["Branches"]
    matches = [b for b in branches if b["StartAt"] == "Responsible AI GRC Enabled?"]
    assert len(matches) == 1
    return matches[0]


LEGACY_INPUT_FAIL_STATE = "Legacy enableFinServ Input Rejected"


def test_legacy_finserv_input_has_a_rejecting_choice_branch(responsible_ai_grc_branch):
    choice = responsible_ai_grc_branch["States"]["Responsible AI GRC Enabled?"]
    matching = [c for c in choice["Choices"] if c["Next"] == LEGACY_INPUT_FAIL_STATE]
    assert len(matching) == 1, (
        "Expected exactly one Choice branch routing to the legacy-input Fail state"
    )
    conditions = matching[0]["And"]
    variables = {c["Variable"] for c in conditions}
    assert "$.OriginalInput.enableFinServ" in variables
    assert "$.RegionIndex" in variables
    string_equals = {
        c["Variable"]: c.get("StringEquals") for c in conditions if "StringEquals" in c
    }
    assert string_equals.get("$.OriginalInput.enableFinServ") == "true"


def test_legacy_finserv_input_choice_does_not_change_the_default(
    responsible_ai_grc_branch,
):
    """Absence of enableFinServ must still fall through to the ordinary skip."""
    choice = responsible_ai_grc_branch["States"]["Responsible AI GRC Enabled?"]
    assert choice["Default"] == "Responsible AI GRC Assessment Skipped"


def test_legacy_finserv_input_reject_precedes_the_run_choices(
    responsible_ai_grc_branch,
):
    """The reject branch must be evaluated before any branch that runs the scan.

    Choice states are first-match-wins. If a caller passes the retired
    ``enableFinServ`` shape *alongside* ``enableResponsibleAIGRC`` or
    ``enableOWASP`` (both routing to "Responsible AI GRC Security Assessment"),
    an ordering where a run-branch precedes the reject would silently honor the
    scan and swallow the stale-input signal -- exactly the bug this ordering
    fixes for the enableOWASP+enableFinServ combination. Lock the reject to the
    front so it cannot be shadowed.
    """
    choices = responsible_ai_grc_branch["States"]["Responsible AI GRC Enabled?"][
        "Choices"
    ]
    reject_indexes = [
        i for i, c in enumerate(choices) if c["Next"] == LEGACY_INPUT_FAIL_STATE
    ]
    run_indexes = [
        i
        for i, c in enumerate(choices)
        if c["Next"] == "Responsible AI GRC Security Assessment"
    ]
    assert reject_indexes, "Expected a Choice routing to the legacy-input Fail state"
    assert run_indexes, "Expected at least one Choice routing to the scan"
    assert max(reject_indexes) < min(run_indexes), (
        "The enableFinServ reject Choice must precede every run Choice so it is "
        "not shadowed when enableFinServ is combined with enableResponsibleAIGRC "
        "or enableOWASP"
    )


def test_legacy_finserv_input_fail_state_shape(responsible_ai_grc_branch):
    fail_state = responsible_ai_grc_branch["States"][LEGACY_INPUT_FAIL_STATE]
    assert fail_state["Type"] == "Fail"
    assert fail_state["Error"] == "LegacyEnableFinServInputRejected"
    assert "enableFinServ" in fail_state["Cause"]
    assert "enableResponsibleAIGRC" in fail_state["Cause"]
    # Fail states cannot carry Retry, Catch, or Next -- ASL rejects the
    # deployment outright if any of these are present.
    assert "Retry" not in fail_state
    assert "Catch" not in fail_state
    assert "Next" not in fail_state
    assert "End" not in fail_state


def test_legacy_finserv_input_failure_is_not_caught_by_an_ancestor(asl_parsed):
    """Confirms the intended full-execution blast radius, not an accident.

    A Fail state's error propagates to the nearest ancestor with a Catch. If
    someone later adds a Catch to "Run Security Assessments" or
    "Scan Regions" -- to make some other error non-fatal -- it would silently
    also swallow this one, turning the deliberate loud failure back into a
    quiet skip. Assert neither ancestor has a Catch/ToleratedFailure today so
    that regression is caught here instead of discovered in production.
    """
    parallel = asl_parsed["States"]["Scan Regions"]["ItemProcessor"]["States"][
        "Run Security Assessments"
    ]
    assert "Catch" not in parallel

    scan_regions = asl_parsed["States"]["Scan Regions"]
    assert "Catch" not in scan_regions
    assert "ToleratedFailurePercentage" not in scan_regions
    assert "ToleratedFailureCount" not in scan_regions


def test_legacy_finserv_input_fail_state_name_fits_the_step_functions_limit():
    assert len(LEGACY_INPUT_FAIL_STATE) <= 80


def test_agentcore_payload_carries_every_resolved_region(asl_parsed):
    """AC-48 and AC-26 compare Regions at RegionIndex 0, so the AgentCore
    Lambda must receive the Region list the Map iterates over."""
    scan_regions = asl_parsed["States"]["Scan Regions"]
    branches = scan_regions["ItemProcessor"]["States"]["Run Security Assessments"][
        "Branches"
    ]
    matches = [b for b in branches if "AgentCore Security Assessment" in b["States"]]
    assert len(matches) == 1
    payload = matches[0]["States"]["AgentCore Security Assessment"]["Parameters"][
        "Payload"
    ]

    assert scan_regions["ItemsPath"] == "$.ResolvedRegions.regions"
    assert scan_regions["ItemSelector"]["OriginalInput.$"] == "$"
    assert payload["TargetRegions.$"] == "$.OriginalInput.ResolvedRegions.regions"
    assert payload["RegionIndex.$"] == "$.RegionIndex"


# ---------------------------------------------------------------------------
# CloudFormation identities: renaming the logical ID or FunctionName forces a
# Lambda replacement, changing ARNs, permissions, logs, and rollback behavior.
#
# Phase 2 Stage 2b renamed both, deliberately, as a reviewed CloudFormation
# replacement (see docs/RESPONSIBLE_AI_GRC_PHASE2_STAGE2B_DESIGN.md). The
# "aiml-security-" physical-name PREFIX is intentionally UNCHANGED — see
# test_own_lambda_prefix_matches_self_exclusion_assumption below for why.
# ---------------------------------------------------------------------------

LOGICAL_ID = "ResponsibleAIGRCAssessmentFunction"
RETIRED_LOGICAL_ID = "FinServSecurityAssessmentFunction"


def test_logical_id_is_frozen(template, template_multi):
    assert LOGICAL_ID in template["Resources"]
    assert LOGICAL_ID in template_multi["Resources"]


def test_retired_logical_id_is_gone(template, template_multi):
    assert RETIRED_LOGICAL_ID not in template["Resources"]
    assert RETIRED_LOGICAL_ID not in template_multi["Resources"]


def test_physical_function_name_is_frozen(template):
    function_name = template["Resources"][LOGICAL_ID]["Properties"]["FunctionName"]
    assert function_name == {
        "Fn::Sub": "aiml-security-${AWS::StackName}-RAIGRCAssessment"
    }


def test_own_lambda_prefix_matches_self_exclusion_assumption():
    """The "aiml-security-" prefix must survive Stage 2b unchanged.

    responsible_ai_grc_assessments/app.py's _self_lambda_name_prefix() derives
    the FS-67 self-exclusion prefix by checking AWS_LAMBDA_FUNCTION_NAME
    against this exact literal at runtime — it does not derive the prefix
    from the stack name. Dropping it (the redundant
    aiml-security-aiml-security-<acct>-... prefix noted in rebrand-plan.md
    section 14) would silently disable self-exclusion for every sibling
    assessment Lambda, not just this one. That is why Stage 2b renames only
    the function-name SUFFIX and explicitly does not implement the prefix
    removal recorded as item 8 in the Stage 2b design doc.
    """
    app_path = os.path.join(
        REPO_ROOT,
        "aiml-security-assessment",
        "functions",
        "security",
        "responsible_ai_grc_assessments",
        "app.py",
    )
    with open(app_path) as handle:
        source = handle.read()
    assert 'own_name.startswith("aiml-security-")' in source


def test_assessment_bucket_retention_cannot_regress(template, template_multi):
    """Retention is already in force; this guards against silent removal."""
    for parsed in (template, template_multi):
        bucket = parsed["Resources"]["AIMLAssessmentBucket"]
        assert bucket["DeletionPolicy"] == "Retain"
        assert bucket["UpdateReplacePolicy"] == "Retain"


def test_stack_outputs_are_frozen(template):
    outputs = template["Outputs"]
    assert "AIMLAssessmentStateMachineArn" in outputs
    assert "AssessmentBucketName" in outputs


@pytest.mark.parametrize(
    "deployment_template",
    ["aiml-security-single-account.yaml", "2-aiml-security-codebuild.yaml"],
)
def test_legacy_toggle_parameter_is_frozen(deployment_template):
    """EnableFinServAssessment is a customer-supplied CloudFormation parameter,
    retained permanently as a legacy alias for EnableResponsibleAIGRCAssessment
    (the primary parameter).

    It lives in the deployment templates, not in the SAM application template —
    the effective toggle reaches the state machine as the
    ENABLE_RESPONSIBLE_AI_GRC CodeBuild environment variable and then the
    enableResponsibleAIGRC execution input, with ENABLE_FINSERV resolved into
    it upstream in buildspec.yml.
    """
    parsed = _load_template(os.path.join(REPO_ROOT, "deployment", deployment_template))
    assert "EnableFinServAssessment" in parsed["Parameters"]
    assert "EnableResponsibleAIGRCAssessment" in parsed["Parameters"]


SUFFIX = "RAIGRCAssessment"
RETIRED_SUFFIX = "FinServAssessment"

# Every stack-name form buildspec.yml actually produces (see buildspec.yml's
# `sam deploy --stack-name` call sites): single-account, multi-account member
# (which nests the literal "aiml-security-" prefix a second time inside the
# stack name itself, per rebrand-plan.md section 14), and the management
# account. All three must stay under Lambda's 64-character FunctionName limit.
STACK_NAME_FORMS = {
    "single-account": "aiml-sec-123456789012",
    "multi-account-member": "aiml-security-123456789012",
    "management": "aiml-security-mgmt",
}


@pytest.mark.parametrize(
    "stack_name", STACK_NAME_FORMS.values(), ids=STACK_NAME_FORMS.keys()
)
def test_function_name_fits_the_lambda_limit(stack_name):
    rendered = f"aiml-security-{stack_name}-{SUFFIX}"
    assert len(rendered) <= 64, f"{rendered} is {len(rendered)} characters"


def test_retired_suffix_would_have_also_fit_but_new_suffix_is_shorter():
    """Confirms the Stage 2b suffix choice, not just its own budget.

    RAIGRCAssessment (16 chars) is shorter than the retired FinServAssessment
    (17 chars) it replaces, so this is not a regression against the old
    budget even though it is not the tightest possible name.
    """
    assert len(SUFFIX) < len(RETIRED_SUFFIX)


def test_infeasible_full_name_candidates_are_recorded_as_infeasible():
    """rebrand-plan.md section 14's identifier-length budget, asserted.

    ResponsibleAIGRCAssessment and ResponsibleAIGovAssessment both exceed the
    64-character limit for the multi-account member stack form -- this is WHY
    Stage 2b uses the abbreviated RAIGRCAssessment suffix instead.
    """
    worst_case_stack_name = STACK_NAME_FORMS["multi-account-member"]
    for infeasible_suffix in (
        "ResponsibleAIGRCAssessment",
        "ResponsibleAIGovAssessment",
    ):
        rendered = f"aiml-security-{worst_case_stack_name}-{infeasible_suffix}"
        assert len(rendered) > 64, (
            f"{rendered} ({len(rendered)} chars) was expected to exceed the "
            "64-character limit -- if it no longer does, the recorded "
            "identifier-length budget in rebrand-plan.md section 14 is stale."
        )


# ---------------------------------------------------------------------------
# Report DOM: slug, anchor, data attributes, and CSS class names. The visible
# text above these may change; these strings may not. The rebrand replaced
# the legacy "finserv" slug and industry-* CSS classes with
# "responsible-ai-grc" and governance-* everywhere -- there is no dual-write
# and no additive alias; the values below are the only ones this report ever
# emits now.
# ---------------------------------------------------------------------------

SERVICE_SLUG = "responsible-ai-grc"

FROZEN_SELECTORS = [
    'id="responsible-ai-grc"',
    'data-service="responsible-ai-grc"',
    'data-filter-service="responsible-ai-grc"',
    'data-scope-service="responsible-ai-grc"',
    '<option value="responsible-ai-grc">',
    'href="#responsible-ai-grc"',
]

FROZEN_CSS_CLASSES = [
    "governance-item",
    "governance-nav",
    "governance-chip",
    "scope-governance",
    "scope-governance-label",
]


def _render_with_responsible_ai_grc() -> str:
    findings = [
        {
            "account_id": "123456789012",
            "check_id": "FS-01",
            "finding": "Example Responsible AI GRC Finding",
            "details": "Example details.",
            "resolution": "Example resolution.",
            "reference": "https://example.com/doc",
            "severity": "High",
            "status": "Failed",
            "region": "us-east-1",
            "_service": SERVICE_SLUG,
        }
    ]
    return report_template.generate_html_report(
        all_findings=findings,
        service_findings={SERVICE_SLUG: findings},
        service_stats={SERVICE_SLUG: {"passed": 0, "failed": 1, "na": 0}},
        mode="single",
        account_id="123456789012",
        regions=["us-east-1"],
    )


@pytest.fixture(scope="module")
def rendered_html():
    return _render_with_responsible_ai_grc()


@pytest.mark.parametrize("selector", FROZEN_SELECTORS)
def test_report_selectors_are_frozen(rendered_html, selector):
    assert selector in rendered_html


@pytest.mark.parametrize("css_class", FROZEN_CSS_CLASSES)
def test_report_css_classes_are_frozen(rendered_html, css_class):
    assert css_class in rendered_html


def test_legacy_finserv_selectors_are_fully_retired(rendered_html):
    """The rebrand is a hard rename, not an alias: the legacy "finserv" slug
    and industry-* CSS classes must not appear anywhere in rendered output.
    """
    for legacy_selector in (
        'id="finserv"',
        'data-service="finserv"',
        'data-filter-service="finserv"',
        'data-scope-service="finserv"',
        '<option value="finserv">',
        'href="#finserv"',
    ):
        assert legacy_selector not in rendered_html
    for legacy_css_class in (
        "industry-item",
        "industry-nav",
        "industry-chip",
        "scope-industry",
        "scope-industry-label",
    ):
        assert legacy_css_class not in rendered_html


def test_service_slug_is_frozen():
    """The display name may change; the slug keyed by the parser may not."""
    assert SERVICE_SLUG == "responsible-ai-grc"
    assert report_template.RESPONSIBLE_AI_GRC_GUIDE_URL.startswith("https://")


@pytest.mark.parametrize(
    "source_path",
    [
        os.path.join(REPORT_DIR, "app.py"),
        os.path.join(REPO_ROOT, "consolidate_html_reports.py"),
    ],
)
def test_show_finserv_flag_is_frozen(source_path):
    """show_finserv suppresses FS-* rows when the capability ran OWASP-only.

    It is a keyword argument on generate_html_report in the report app and a
    local in the multi-account consolidator. It is NOT in report_template.py.
    """
    with open(source_path) as handle:
        assert "show_finserv" in handle.read()


# ---------------------------------------------------------------------------
# Persisted object names.
# ---------------------------------------------------------------------------


def test_csv_prefix_is_frozen():
    owasp_app_path = os.path.join(
        REPO_ROOT,
        "aiml-security-assessment",
        "functions",
        "security",
        "owasp_assessments",
        "app.py",
    )
    source = open(owasp_app_path).read()
    assert (
        'RESPONSIBLE_AI_GRC_SERVICE_CSV_PREFIX = "responsible_ai_grc_security_report"'
        in source
    )
    assert 'FINSERV_SERVICE_CSV_PREFIX = "finserv_security_report"' not in source
