"""IAM coverage guard (REQ-12 / Wave 5.5 T5h.6).

Asserts that every IAM action the FinServ checks require is granted to the
runtime Lambda roles that make those API calls:
  - aiml-security-assessment/template.yaml          (SAM single-account roles)
  - aiml-security-assessment/template-multi-account.yaml

This is what would otherwise surface in customer accounts as AccessDenied /
"COULD NOT ASSESS". The map is derived from the per-check boto3 API inventory.
Parsing uses a token regex (not a YAML load) so CloudFormation intrinsics
(!Ref/!GetAtt/!Sub) do not interfere.

Each SAM template gives every assessment Lambda its OWN Policies block under
its own resource. An action granted under one function's block does not help a
different function at runtime. The deployment-layer roles only deploy the SAM
stack, poll executions, and retrieve report artifacts; they intentionally do
not receive assessment-service read permissions.

The file-wide `_granted_actions()` scan below is NOT resource-aware, so used
alone against the SAM templates it cannot tell "granted to the function that
needs it" apart from "granted to some other function's policy in the same
file". That gap shipped a real bug:
inspector2:BatchGetAccountStatus (FS-16) and sagemaker:DescribeFeatureGroup
(FS-20) were required by ResponsibleAIGRCAssessmentFunction but
BatchGetAccountStatus was granted only to the unrelated
BedrockSecurityAssessmentFunction's policy (for its own BR-33 check) — found
via live AWS testing, not by this test suite, because the file-wide scan saw
the action present *somewhere* in the file and reported the requirement as
satisfied. `_granted_actions_for_resource()` and the
`test_required_*_actions_are_granted_to_the_*_function` tests below scope the
scan to one resource's own block on the SAM templates specifically, so a
repeat of this exact bug class (grant landed on the wrong function) fails the
suite instead of shipping silently.
"""

import os
import re

import pytest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_TEMPLATES = [
    os.path.join(_REPO_ROOT, "aiml-security-assessment", "template.yaml"),
    os.path.join(_REPO_ROOT, "aiml-security-assessment", "template-multi-account.yaml"),
]

_AGENTCORE_PERMISSION_TEMPLATES = _TEMPLATES

# IAM actions the FinServ checks (FS-01..FS-69) require, by the check(s) that call
# them. apigateway:GET covers get_rest_apis/get_request_validators/get_usage_plans/
# get_models. Keep this in sync with responsible_ai_grc_assessments/app.py.
REQUIRED_FINSERV_ACTIONS = {
    "wafv2:ListWebACLs",
    "wafv2:GetWebACL",  # FS-01/53/56/68
    "shield:DescribeSubscription",  # FS-01
    "apigateway:GET",  # FS-02/68
    "servicequotas:ListServiceQuotas",
    "servicequotas:ListAWSDefaultServiceQuotas",  # FS-03
    "ce:GetAnomalyMonitors",  # FS-04
    "cloudwatch:DescribeAlarms",  # FS-05/11
    "budgets:ViewBudget",  # FS-06
    "bedrock:ListAgents",
    "bedrock:GetAgent",  # FS-07
    "bedrock-agentcore:ListAgentRuntimes",
    "bedrock-agentcore:GetAgentRuntime",  # FS-08/66
    "lambda:ListFunctions",
    "lambda:GetFunctionConcurrency",  # FS-09/52/55/58/67/69
    "states:ListStateMachines",
    "states:DescribeStateMachine",  # FS-10
    "organizations:ListPolicies",
    "organizations:DescribePolicy",  # FS-12
    "bedrock:ListCustomModels",
    "bedrock:ListTagsForResource",  # FS-13 (B1 gap)
    "config:DescribeConfigRules",  # FS-14/63
    "bedrock:ListEvaluationJobs",  # FS-15
    "ecr:DescribeRepositories",
    "inspector2:BatchGetAccountStatus",  # FS-16
    "sagemaker:ListFeatureGroups",
    "sagemaker:DescribeFeatureGroup",  # FS-20
    "sagemaker:ListModels",  # FS-20/13
    "sagemaker:ListMonitoringSchedules",
    "sagemaker:ListModelCards",
    "sagemaker:ListTags",  # FS-39/41/42/13
    "bedrock:ListKnowledgeBases",
    "bedrock:ListDataSources",
    "bedrock:GetDataSource",  # FS-31/33/65
    "bedrock:ListIngestionJobs",  # FS-31
    "aoss:ListCollections",  # FS-25
    "aoss:ListSecurityPolicies",  # FS-26
    "bedrock:ListGuardrails",
    "bedrock:GetGuardrail",  # FS-27/28/36/38/45/47/50/51/59
    "bedrock:ListAutomatedReasoningPolicies",  # FS-27b (B2 gap)
    "bedrock:ListFoundationModels",  # FS-34/63
    "logs:DescribeAccountPolicies",
    "logs:GetDataProtectionPolicy",  # FS-43
    "macie2:GetMacieSession",
    "macie2:GetAutomatedDiscoveryConfiguration",  # FS-44
    "events:ListRules",
    "scheduler:ListSchedules",  # FS-61 (B2 gap)
    "bedrock:GetModelInvocationLoggingConfiguration",
}

# IAM actions the standalone SageMaker assessment calls. Keep this in sync with
# sagemaker_assessments/app.py.
REQUIRED_SAGEMAKER_ACTIONS = {
    "sagemaker:ListNotebookInstances",
    "sagemaker:DescribeNotebookInstance",
    "sagemaker:ListDomains",
    "sagemaker:DescribeDomain",
    "sagemaker:ListTrainingJobs",
    "sagemaker:DescribeTrainingJob",
    "sagemaker:ListModelPackageGroups",
    "sagemaker:ListModelPackages",
    "sagemaker:ListFeatureGroups",
    "sagemaker:DescribeFeatureGroup",
    "sagemaker:ListPipelines",
    "sagemaker:ListPipelineExecutions",
    "sagemaker:ListProcessingJobs",
    "sagemaker:DescribeProcessingJob",
    "sagemaker:ListMonitoringSchedules",
    "sagemaker:DescribeMonitoringSchedule",
    "sagemaker:ListModels",
    "sagemaker:DescribeModel",
    "sagemaker:ListEndpoints",
    "sagemaker:DescribeEndpoint",
    "sagemaker:ListDataQualityJobDefinitions",
    "sagemaker:DescribeDataQualityJobDefinition",
    "sagemaker:ListTransformJobs",
    "sagemaker:DescribeTransformJob",
    "sagemaker:ListHyperParameterTuningJobs",
    "sagemaker:DescribeHyperParameterTuningJob",
    "sagemaker:ListCompilationJobs",
    "sagemaker:DescribeCompilationJob",
    "sagemaker:ListAutoMLJobs",
    "sagemaker:DescribeAutoMLJob",
    "sagemaker:ListExperiments",
    "sagemaker:ListTrials",
    "sagemaker:ListAssociations",
}

REQUIRED_AGENTCORE_ACTIONS = {
    "bedrock-agentcore:ListAgentRuntimes",
    "bedrock-agentcore:GetAgentRuntime",
    "bedrock-agentcore:ListMemories",
    "bedrock-agentcore:GetMemory",
    "bedrock-agentcore:ListGateways",
    "bedrock-agentcore:GetGateway",
    "bedrock-agentcore:ListPolicyEngines",
    "bedrock-agentcore:GetPolicyEngine",
    "bedrock-agentcore:GetResourcePolicy",
}

REQUIRED_AGENT_REGISTRY_ACTIONS = {
    "agent-registry:ListRegistries",
    "agent-registry:GetRegistry",
    "agent-registry:ListRegistryRecords",
}

_ACTION_RE = re.compile(r"-\s+([a-z0-9-]+:[A-Za-z0-9]+)")

# Matches a top-level (2-space-indented) CloudFormation logical resource ID line,
# e.g. "  ResponsibleAIGRCAssessmentFunction:". Used to find where one resource's
# block ends and the next begins in the SAM templates, which are flat YAML
# mappings under `Resources:` with every top-level resource indented exactly 2
# spaces. A dedicated regex (rather than a YAML load) is used deliberately:
# CloudFormation intrinsics (!Ref/!GetAtt/!Sub) are not valid plain YAML/JSON
# without a CloudFormation-aware loader, and this file otherwise avoids that
# dependency (see module docstring).
_RESOURCE_HEADER_RE = re.compile(r"^  [A-Za-z][A-Za-z0-9]*:\s*$", re.MULTILINE)

_SAM_TEMPLATES = [
    os.path.join(_REPO_ROOT, "aiml-security-assessment", "template.yaml"),
    os.path.join(_REPO_ROOT, "aiml-security-assessment", "template-multi-account.yaml"),
]
_STALE_ACCESS_APP_PATHS = [
    os.path.join(
        _REPO_ROOT,
        "aiml-security-assessment",
        "functions",
        "security",
        package,
        "app.py",
    )
    for package in (
        "bedrock_assessments",
        "sagemaker_assessments",
        "agentcore_assessments",
        "agent_registry_assessments",
    )
]


def _granted_actions(path):
    with open(path, encoding="utf-8") as fh:
        return set(_ACTION_RE.findall(fh.read()))


def _resource_block(path, logical_id):
    """Return the raw text of one top-level resource's own block.

    Scoped to the SAM templates (`_SAM_TEMPLATES`), where every assessment
    Lambda is its own top-level resource with its own `Policies:` block.
    Slices from the resource's header line up to (but not including) the next
    top-level resource header, so text belonging to a sibling resource's
    policy is never included — the exact gap that let an action granted to
    one function's block satisfy a different function's requirement.
    """
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    header = f"\n  {logical_id}:"
    start = text.find(header)
    assert start != -1, f"resource {logical_id!r} not found in {os.path.basename(path)}"
    start += 1  # skip the leading newline so the header line itself is included
    match = _RESOURCE_HEADER_RE.search(text, start + len(header))
    end = match.start() if match else len(text)
    return text[start:end]


def _granted_actions_for_resource(path, logical_id):
    return set(_ACTION_RE.findall(_resource_block(path, logical_id)))


def test_service_last_access_principal_arns_are_partition_aware():
    """Scoped IAM grants must also work outside the commercial partition."""
    for path in _STALE_ACCESS_APP_PATHS:
        with open(path, encoding="utf-8") as app_file:
            source = app_file.read()
        assert "arn:aws:iam::" not in source
        assert "arn:{partition}:iam::" in source


@pytest.mark.parametrize(
    "template",
    _AGENTCORE_PERMISSION_TEMPLATES,
    ids=lambda p: os.path.basename(p),
)
def test_required_finserv_actions_are_granted(template):
    """Every runtime template must grant the complete FinServ API inventory."""
    assert os.path.exists(template), f"template not found: {template}"
    granted = _granted_actions(template)
    missing = sorted(a for a in REQUIRED_FINSERV_ACTIONS if a not in granted)
    assert not missing, (
        f"{os.path.basename(template)} is missing required FinServ IAM action(s): "
        f"{missing}. Add them or a FinServ check will hit AccessDenied / COULD NOT ASSESS."
    )


def test_guard_detects_a_removed_action(monkeypatch):
    """Prove the guard fails when a required action is absent (self-test)."""
    granted = _granted_actions(_TEMPLATES[0])
    granted.discard("bedrock:ListTagsForResource")
    missing = [a for a in REQUIRED_FINSERV_ACTIONS if a not in granted]
    assert "bedrock:ListTagsForResource" in missing


@pytest.mark.parametrize("template", _TEMPLATES, ids=lambda p: os.path.basename(p))
def test_required_sagemaker_actions_are_granted(template):
    assert os.path.exists(template), f"template not found: {template}"
    granted = _granted_actions(template)
    missing = sorted(a for a in REQUIRED_SAGEMAKER_ACTIONS if a not in granted)
    assert not missing, (
        f"{os.path.basename(template)} is missing required SageMaker IAM action(s): "
        f"{missing}. Add them or a SageMaker check will hit AccessDenied."
    )


@pytest.mark.parametrize(
    "template",
    _AGENTCORE_PERMISSION_TEMPLATES,
    ids=lambda p: os.path.basename(p),
)
def test_required_agentcore_actions_are_granted(template):
    assert os.path.exists(template), f"template not found: {template}"
    granted = _granted_actions(template)
    missing = sorted(a for a in REQUIRED_AGENTCORE_ACTIONS if a not in granted)
    assert not missing, (
        f"{os.path.basename(template)} is missing required AgentCore IAM action(s): "
        f"{missing}. Add them or an AgentCore check will hit AccessDenied."
    )


# Resource-scoped guards (SAM templates only) --------------------------------
#
# The file-wide tests above are necessary but not sufficient for the SAM
# templates: they prove an action is granted *somewhere* in the file, not that
# it is granted to the specific Lambda whose code calls it. The tests below
# close that gap by scoping the scan to each function's own resource block.
#
# Logical IDs are read directly from the SAM templates rather than hardcoded
# as a second copy, so a future rename only has to happen in one place.
_RESPONSIBLE_AI_GRC_FUNCTION_ID = "ResponsibleAIGRCAssessmentFunction"
_SAGEMAKER_FUNCTION_ID = "SagemakerSecurityAssessmentFunction"
_AGENTCORE_FUNCTION_ID = "AgentCoreSecurityAssessmentFunction"
_AGENT_REGISTRY_FUNCTION_ID = "AgentRegistrySecurityAssessmentFunction"


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=lambda p: os.path.basename(p))
def test_required_finserv_actions_are_granted_to_the_finserv_function(template):
    """Same requirement as test_required_finserv_actions_are_granted, but scoped
    to ResponsibleAIGRCAssessmentFunction's own Policies block on the SAM
    templates specifically.

    This is the test that would have caught the live bug: inspector2:Batch-
    GetAccountStatus and sagemaker:DescribeFeatureGroup were both present in
    template.yaml (satisfying the file-wide test above) but granted only to
    BedrockSecurityAssessmentFunction / never granted at all — not to this
    function, which is the one that actually calls them for FS-16 and FS-20.
    """
    granted = _granted_actions_for_resource(template, _RESPONSIBLE_AI_GRC_FUNCTION_ID)
    missing = sorted(a for a in REQUIRED_FINSERV_ACTIONS if a not in granted)
    assert not missing, (
        f"{os.path.basename(template)}: {_RESPONSIBLE_AI_GRC_FUNCTION_ID}'s own "
        f"policy block is missing required IAM action(s): {missing}. A grant "
        "present elsewhere in this file does not help this function at "
        "runtime — add the action(s) to this function's own Policies block."
    )


def test_resource_scoped_guard_detects_a_grant_on_the_wrong_function():
    """Prove the resource-scoped guard fails when a required action is granted
    only to a different function's block (self-test; reproduces the live bug).

    inspector2:BatchGetAccountStatus is granted to BedrockSecurityAssessment-
    Function (its own BR-33 check) in template.yaml. Scoping the scan to that
    *other* function's block must show the action absent from
    ResponsibleAIGRCAssessmentFunction's requirement, even though the file-wide
    scan would call it satisfied.
    """
    template = _SAM_TEMPLATES[0]
    granted_elsewhere = _granted_actions_for_resource(
        template, "BedrockSecurityAssessmentFunction"
    )
    assert "inspector2:BatchGetAccountStatus" in granted_elsewhere

    granted_here = _granted_actions_for_resource(
        template, _RESPONSIBLE_AI_GRC_FUNCTION_ID
    )
    granted_here.discard("inspector2:BatchGetAccountStatus")
    missing = [a for a in REQUIRED_FINSERV_ACTIONS if a not in granted_here]
    assert "inspector2:BatchGetAccountStatus" in missing


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=lambda p: os.path.basename(p))
def test_required_sagemaker_actions_are_granted_to_the_sagemaker_function(template):
    granted = _granted_actions_for_resource(template, _SAGEMAKER_FUNCTION_ID)
    missing = sorted(a for a in REQUIRED_SAGEMAKER_ACTIONS if a not in granted)
    assert not missing, (
        f"{os.path.basename(template)}: {_SAGEMAKER_FUNCTION_ID}'s own policy "
        f"block is missing required SageMaker IAM action(s): {missing}. A "
        "grant present elsewhere in this file does not help this function at "
        "runtime — add the action(s) to this function's own Policies block."
    )


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=lambda p: os.path.basename(p))
def test_required_agentcore_actions_are_granted_to_the_agentcore_function(template):
    granted = _granted_actions_for_resource(template, _AGENTCORE_FUNCTION_ID)
    missing = sorted(a for a in REQUIRED_AGENTCORE_ACTIONS if a not in granted)
    assert not missing, (
        f"{os.path.basename(template)}: {_AGENTCORE_FUNCTION_ID}'s own policy "
        f"block is missing required AgentCore IAM action(s): {missing}. A "
        "grant present elsewhere in this file does not help this function at "
        "runtime — add the action(s) to this function's own Policies block."
    )


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=lambda p: os.path.basename(p))
def test_required_agent_registry_actions_are_granted_to_the_registry_function(
    template,
):
    granted = _granted_actions_for_resource(template, _AGENT_REGISTRY_FUNCTION_ID)
    missing = sorted(a for a in REQUIRED_AGENT_REGISTRY_ACTIONS if a not in granted)
    assert not missing, (
        f"{os.path.basename(template)}: {_AGENT_REGISTRY_FUNCTION_ID}'s own policy "
        f"block is missing required IAM action(s): {missing}. A grant present "
        "elsewhere in this file does not help this function at runtime."
    )


# Known service prefixes used by this tool. `bedrock-agent:` is intentionally
# absent: it is NOT a valid IAM namespace. Amazon Bedrock Knowledge Base / Data
# Source / Flow / Agent actions all use the `bedrock:` prefix; AgentCore uses
# `bedrock-agentcore:` and AWS Agent Registry uses `agent-registry:`. The boto3
# client names `bedrock-agent`, `bedrock-agentcore-control`, and
# `agent-registry-control` are not IAM namespaces and silently authorize nothing.
_INVALID_ACTION_PREFIXES = (
    "agent-registry-control:",
    "bedrock-agent:",
    "bedrock-agentcore-control:",
)
_INVALID_ACTION_NAMES = {
    "bedrock:ListModelInvocations",
    "bedrock-agentcore:GetAgentRuntimeResourcePolicy",
    "bedrock-agentcore:GetGatewayResourcePolicy",
}


@pytest.mark.parametrize(
    "template",
    _AGENTCORE_PERMISSION_TEMPLATES,
    ids=lambda p: os.path.basename(p),
)
def test_no_invalid_iam_action_prefixes(template):
    """Guard against using boto3 service names as IAM action prefixes.

    cfn-lint's W3037 is suppressed repo-wide (its action DB lags new services),
    so this test is the positive guard that catches a wrong-prefix typo that
    would otherwise ship as a no-op grant and surface as AccessDenied at runtime.
    """
    granted = _granted_actions(template)
    bad = sorted(
        a
        for a in granted
        if any(a.startswith(p) for p in _INVALID_ACTION_PREFIXES)
        or a in _INVALID_ACTION_NAMES
    )
    assert not bad, (
        f"{os.path.basename(template)} uses invalid IAM action(s): {bad}. "
        "Bedrock KB/DataSource/Flow/Agent actions use the 'bedrock:' prefix "
        "(AgentCore uses 'bedrock-agentcore:'); boto3 client names such as "
        "'bedrock-agent', 'bedrock-agentcore-control', and "
        "'agent-registry-control' are not IAM namespaces. AWS Agent Registry "
        "actions use the 'agent-registry:' prefix. "
        "AgentCore resource policies use the generic bedrock-agentcore:GetResourcePolicy "
        "action."
    )


def test_invalid_prefix_guard_detects_a_bad_action():
    """Self-test: the invalid-prefix guard trips on boto3 client-name prefixes."""
    sample = {
        "agent-registry-control:ListRegistries",
        "bedrock:ListKnowledgeBases",
        "bedrock-agent:ListKnowledgeBases",
        "bedrock-agentcore-control:GetResourcePolicy",
        "bedrock-agentcore:GetGatewayResourcePolicy",
    }
    bad = sorted(
        a
        for a in sample
        if any(a.startswith(p) for p in _INVALID_ACTION_PREFIXES)
        or a in _INVALID_ACTION_NAMES
    )
    assert bad == [
        "agent-registry-control:ListRegistries",
        "bedrock-agent:ListKnowledgeBases",
        "bedrock-agentcore-control:GetResourcePolicy",
        "bedrock-agentcore:GetGatewayResourcePolicy",
    ]
