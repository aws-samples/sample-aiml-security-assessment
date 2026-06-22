"""IAM coverage guard (REQ-12 / Wave 5.5 T5h.6).

Asserts that every IAM action the FinServ checks require is granted in all runtime
grant sources:
  - aiml-security-assessment/template.yaml          (SAM single-account roles)
  - aiml-security-assessment/template-multi-account.yaml
  - deployment/1-aiml-security-member-roles.yaml    (multi-account member role)
  - deployment/aiml-security-single-account.yaml    (single-account CFN wrapper)

This is what would otherwise surface in customer accounts as AccessDenied /
"COULD NOT ASSESS". The map is derived from the per-check boto3 API inventory.
Parsing uses a token regex (not a YAML load) so CloudFormation intrinsics
(!Ref/!GetAtt/!Sub) do not interfere.
"""

import os
import re

import pytest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_TEMPLATES = [
    os.path.join(_REPO_ROOT, "aiml-security-assessment", "template.yaml"),
    os.path.join(_REPO_ROOT, "aiml-security-assessment", "template-multi-account.yaml"),
    os.path.join(_REPO_ROOT, "deployment", "1-aiml-security-member-roles.yaml"),
    os.path.join(_REPO_ROOT, "deployment", "aiml-security-single-account.yaml"),
]

_AGENTCORE_PERMISSION_TEMPLATES = [
    *_TEMPLATES,
    os.path.join(_REPO_ROOT, "deployment", "2-aiml-security-codebuild.yaml"),
]

# IAM actions the FinServ checks (FS-01..FS-69) require, by the check(s) that call
# them. apigateway:GET covers get_rest_apis/get_request_validators/get_usage_plans/
# get_models. Keep this in sync with finserv_assessments/app.py.
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
    "ecr:DescribeRepositories",  # FS-16
    "sagemaker:ListFeatureGroups",
    "sagemaker:ListModels",  # FS-20/13
    "sagemaker:ListMonitoringSchedules",
    "sagemaker:ListModelCards",
    "sagemaker:ListTags",  # FS-39/41/42/13
    "bedrock:ListKnowledgeBases",
    "bedrock:GetKnowledgeBase",  # FS-24/31/33/48/61/65
    "bedrock:ListDataSources",
    "bedrock:GetDataSource",  # FS-31/33/65
    "aoss:ListSecurityPolicies",  # FS-25/26
    "bedrock:ListGuardrails",
    "bedrock:GetGuardrail",  # FS-27/28/36/38/45/47/50/51/59
    "bedrock:ListAutomatedReasoningPolicies",  # FS-27b (B2 gap)
    "bedrock:ListFoundationModels",  # FS-34/63
    "logs:DescribeAccountPolicies",  # FS-43
    "macie2:GetMacieSession",  # FS-44
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

_ACTION_RE = re.compile(r"-\s+([a-z0-9-]+:[A-Za-z0-9]+)")


def _granted_actions(path):
    with open(path, encoding="utf-8") as fh:
        return set(_ACTION_RE.findall(fh.read()))


@pytest.mark.parametrize("template", _TEMPLATES, ids=lambda p: os.path.basename(p))
def test_required_finserv_actions_are_granted(template):
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


# Known service prefixes used by this tool. `bedrock-agent:` is intentionally
# absent: it is NOT a valid IAM namespace. Amazon Bedrock Knowledge Base / Data
# Source / Flow / Agent actions all use the `bedrock:` prefix; AgentCore uses
# `bedrock-agentcore:`. A `bedrock-agent:` grant silently authorizes nothing.
_INVALID_ACTION_PREFIXES = ("bedrock-agent:", "bedrock-agentcore-control:")
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
    """Guard against reintroducing the invalid `bedrock-agent:` IAM prefix.

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
        "'bedrock-agent' and 'bedrock-agentcore-control' are not IAM namespaces. "
        "AgentCore resource policies use the generic bedrock-agentcore:GetResourcePolicy "
        "action."
    )


def test_invalid_prefix_guard_detects_a_bad_action():
    """Self-test: the invalid-prefix guard trips on a `bedrock-agent:` action."""
    sample = {
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
        "bedrock-agent:ListKnowledgeBases",
        "bedrock-agentcore-control:GetResourcePolicy",
        "bedrock-agentcore:GetGatewayResourcePolicy",
    ]
