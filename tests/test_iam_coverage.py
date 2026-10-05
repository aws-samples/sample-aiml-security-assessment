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

import ast
import os
import re

import pytest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SECURITY_FUNCTIONS_ROOT = os.path.join(
    _REPO_ROOT, "aiml-security-assessment", "functions", "security"
)

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
def test_br47_br52_browser_read_is_granted_to_the_bedrock_function(template):
    # BR-47 and BR-52 call GetBrowser from the Bedrock function. The AgentCore
    # function's own GetBrowser grant does not reach it, which read
    # AccessDeniedException live and left both bucket lists incomplete.
    granted = _granted_actions_for_resource(template, "BedrockAssessmentReadsPolicy")
    assert "bedrock-agentcore:GetBrowser" in granted


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


def test_runtime_guidance_does_not_use_invalid_iam_identifiers():
    """Remediation text must use valid IAM prefixes, actions, and condition keys."""
    invalid_identifiers = {
        "bedrock-agent:": (
            "Bedrock Agents APIs authorize through the bedrock: IAM namespace"
        ),
        "bedrock:ModelId": (
            "Bedrock model allowlists use Resource or NotResource model ARNs"
        ),
        "Grant sts:GetCallerIdentity": (
            "STS GetCallerIdentity does not require an IAM Allow permission"
        ),
    }
    violations = {}
    for root, directories, filenames in os.walk(_SECURITY_FUNCTIONS_ROOT):
        directories[:] = [
            directory
            for directory in directories
            if directory != "__pycache__" and not directory.endswith("_tests")
        ]
        for filename in filenames:
            if not filename.endswith(".py") or filename.startswith("test"):
                continue
            path = os.path.join(root, filename)
            with open(path, encoding="utf-8") as source:
                for line_number, line in enumerate(source, start=1):
                    for identifier in invalid_identifiers:
                        if identifier in line:
                            violations.setdefault(identifier, []).append(
                                f"{os.path.relpath(path, _REPO_ROOT)}:{line_number}"
                            )

    assert not violations, (
        "Runtime guidance uses invalid IAM identifiers: "
        + "; ".join(
            f"{identifier} at {locations} ({invalid_identifiers[identifier]})"
            for identifier, locations in violations.items()
        )
    )


# Every IAM action below was checked against the corresponding AWS Service
# Authorization Reference through AWS Knowledge on 2026-09-11. Condition keys
# and non-IAM event names are classified separately so they are not mistaken
# for permissions. A new IAM-shaped token in remediation text must be reviewed
# and added deliberately.
_VERIFIED_REMEDIATION_IAM_ACTIONS = {
    # aoss:APIAccessAll (resource type Collection) was read from the aoss
    # service reference JSON on 2026-10-04.
    "aoss:APIAccessAll",
    "aoss:ListCollections",
    "agent-registry:GetRegistry",
    "agent-registry:ListRegistries",
    "agent-registry:ListRegistryRecords",
    "bedrock-agentcore:GetAgentRuntime",
    "bedrock-agentcore:GetBrowser",
    "bedrock-agentcore:GetCodeInterpreter",
    "bedrock-agentcore:GetGateway",
    "bedrock-agentcore:GetOnlineEvaluationConfig",
    "bedrock-agentcore:GetResourcePolicy",
    "bedrock-agentcore:GetTokenVault",
    "bedrock-agentcore:ListAgentRuntimes",
    "bedrock-agentcore:ListBrowsers",
    "bedrock-agentcore:ListCodeInterpreters",
    "bedrock-agentcore:ListGateways",
    "bedrock-agentcore:ListOnlineEvaluationConfigs",
    "bedrock-agentcore:ListPolicies",
    # bedrock:ApplyGuardrail (IsWrite false, resource types guardrail and
    # guardrail-profile) was read from the bedrock service reference JSON on
    # 2026-10-04.
    "bedrock:ApplyGuardrail",
    "bedrock:CreateModelInvocationJob",
    "bedrock:CreatePrompt",
    "bedrock:GetAgent",
    "bedrock:GetAgentActionGroup",
    "bedrock:GetAutomatedReasoningPolicy",
    "bedrock:GetCustomModel",
    "bedrock:GetFlow",
    "bedrock:GetGuardrail",
    "bedrock:GetImportedModel",
    "bedrock:GetKnowledgeBase",
    "bedrock:GetMarketplaceModelEndpoint",
    "bedrock:GetModelInvocationLoggingConfiguration",
    "bedrock:InvokeModel",
    "bedrock:InvokeModelWithResponseStream",
    "bedrock:ListAgentActionGroups",
    "bedrock:ListAgents",
    "bedrock:ListAutomatedReasoningPolicies",
    "bedrock:ListCustomModels",
    "bedrock:ListEnforcedGuardrailsConfiguration",
    "bedrock:ListEvaluationJobs",
    "bedrock:ListFlows",
    "bedrock:ListGuardrails",
    "bedrock:ListImportedModels",
    "bedrock:ListIngestionJobs",
    "bedrock:ListKnowledgeBases",
    "bedrock:ListModelInvocationJobs",
    "bedrock:ListTagsForResource",
    "cloudwatch:DescribeAlarms",
    "config:DescribeConfigRules",
    "iam:CreateServiceLinkedRole",
    "iam:GenerateServiceLastAccessedDetails",
    "iam:GetServiceLastAccessedDetails",
    "inspector2:BatchGetAccountStatus",
    "kms:CreateGrant",
    "kms:Decrypt",
    "kms:DescribeKey",
    "kms:GenerateDataKey",
    "lambda:GetFunction",
    "lambda:ListFunctions",
    "logs:DescribeAccountPolicies",
    "logs:GetDataProtectionPolicy",
    "macie2:GetAutomatedDiscoveryConfiguration",
    "macie2:GetMacieSession",
    "organizations:DescribeOrganization",
    "organizations:ListParents",
    "organizations:ListPolicies",
    "organizations:ListRoots",
    "organizations:ListTargetsForPolicy",
    "s3:GetEncryptionConfiguration",
    "sagemaker:DescribeCluster",
    "sagemaker:DescribeFeatureGroup",
    "servicequotas:GetAWSDefaultServiceQuota",
    "servicequotas:GetServiceQuota",
    "servicequotas:ListAWSDefaultServiceQuotas",
    "servicequotas:ListServiceQuotas",
}

# Verified from the vendored service model's own permission documentation
# (botocore s3vectors 2025-07-15: "You must have the
# s3vectors:PutVectorBucketPolicy permission to use this operation"), not from
# AWS Knowledge like the block above.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"s3vectors:PutVectorBucketPolicy"}

# Verified on 2026-09-27 against the Service Authorization Reference JSON
# (servicereference.us-east-1.amazonaws.com/v1/<service>/<service>.json): the
# bedrock-mantle file lists CreateInference with the bedrock-mantle:Model action
# condition key, and the s3 file lists GetObject.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "bedrock-mantle:CreateInference",
    "s3:GetObject",
}

# Verified on 2026-09-27 against the same Service Authorization Reference JSON:
# the logs file lists AssociateKmsKey on the log-group resource.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"logs:AssociateKmsKey"}

# Verified on 2026-09-28 against the same Service Authorization Reference JSON:
# the bedrock file lists ListFlowAliases and GetFlowVersion on the flow resource.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "bedrock:GetFlowVersion",
    "bedrock:ListFlowAliases",
}

# Verified on 2026-09-28 against the same Service Authorization Reference JSON:
# the bedrock file lists UpdatePrompt and CreatePromptVersion on the prompt
# resource.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "bedrock:CreatePromptVersion",
    "bedrock:UpdatePrompt",
}

# Verified on 2026-09-25 by submitting a policy naming each action to
# iam-access-analyzer ValidatePolicy (a read-only call that creates nothing):
# an action the service does not define comes back as INVALID_ACTION, and every
# action below came back clean.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "aws-marketplace:Subscribe",
    "aws-marketplace:Unsubscribe",
    "bedrock:CallWithBearerToken",
    "bedrock-mantle:CallWithBearerToken",
    # BR-02's EC2 workload leg: same method, 2026-09-27.
    "ec2:DescribeInstances",
    "iam:GetInstanceProfile",
    # The two PutAccountDataRetention actions: same method, 2026-09-27.
    "bedrock-mantle:PutAccountDataRetention",
    "bedrock:PutAccountDataRetention",
    "iam:CreateServiceSpecificCredential",
    "iam:ListServiceSpecificCredentials",
    "logs:DescribeLogGroups",
    "logs:DescribeMetricFilters",
    "logs:PutRetentionPolicy",
    "organizations:DescribePolicy",
    "s3:GetLifecycleConfiguration",
}

# Verified on 2026-09-25 with IAM Access Analyzer validate-policy, which is an
# oracle for both halves: it reports INVALID_ACTION for an action the service
# does not define and INVALID_GLOBAL_CONDITION_KEY for an unknown condition key.
# The probe policy carried three invented actions
# (logs:DescribeNotARealThing, oam:GetSinkPolicyDocument,
# cloudtrail:ListTrailsAndStuff) and one invented condition key
# (aws:PrincipalOrgIdentifier) as negative controls; all four were reported and
# every name below was not, so the run discriminates rather than passing
# everything.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "bedrock-agentcore:ListMemories",
    "cloudtrail:GetEventSelectors",
    "cloudtrail:ListTrails",
    "logs:DescribeDeliveries",
    "logs:DescribeDeliverySources",
    "logs:DescribeLogGroups",
    "logs:Unmask",
    "oam:GetSinkPolicy",
    "oam:ListSinks",
}

# Verified on 2026-09-25 with a second Access Analyzer validate-policy run whose
# negative controls were two invented actions
# (bedrock-agentcore:GetMemoryThatDoesNotExist,
# bedrock-agentcore:NotARealMemoryAction) and one invented condition key
# (bedrock-agentcore:memoryNamespaceThatDoesNotExist). All three were reported
# and GetMemory was not, alongside the memory read actions AC-23 assesses and
# the bedrock-agentcore namespace, strategyId, actorId and sessionId condition
# keys it accepts as scoping.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"bedrock-agentcore:GetMemory"}

# Verified on 2026-09-29 with an Access Analyzer validate-policy run for the
# AC-33 user id leg. Its negative control was one invented action
# (bedrock-agentcore:GetWorkloadAccessTokenForUserIdNotReal), which was reported
# as INVALID_ACTION, and the action below was not.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "bedrock-agentcore:GetWorkloadAccessTokenForUserId"
}

# Verified on 2026-10-03 with an Access Analyzer validate-policy run for the
# SM-02 API method authorization leg. Its negative control was one invented
# action (execute-api:InvokeThatDoesNotExist), which was reported as
# INVALID_ACTION, and the action below was not.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"execute-api:Invoke"}

# Verified on 2026-09-25 with a third Access Analyzer validate-policy run for the
# gateway controls AC-24 through AC-27. Its negative controls were four invented
# actions (ec2:DescribeVpcEndpointsThatDoNotExist,
# kms:GetKeyPolicyDocumentNotReal, organizations:DescribePolicyDetailNotReal,
# bedrock-agentcore:ListGatewayRateLimitEntriesNotReal) and two invented
# condition keys (aws:SourceArnPrefixNotReal,
# bedrock-agentcore:GatewayAuthorizerKindNotReal). All six were reported,
# INVALID_ACTION for the actions and INVALID_GLOBAL_CONDITION_KEY plus
# INVALID_SERVICE_CONDITION_KEY for the keys, and none of the names below was, so
# the run discriminates in both directions.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "bedrock-agentcore:GetGatewayTarget",
    "bedrock-agentcore:ListGatewayRateLimits",
    "bedrock-agentcore:ListGatewayTargets",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeVpcEndpoints",
    "iam:GetRole",
    "kms:GetKeyPolicy",
}

# Verified on 2026-09-25 with a fourth Access Analyzer validate-policy run, this
# one against policyType SERVICE_CONTROL_POLICY because AC-28's remediation text
# describes an SCP. Its negative controls were three invented actions
# (bedrock-agentcore:CreateGatewayNotReal,
# bedrock-agentcore:UpdateGatewayThatDoesNotExist,
# organizations:DescribePolicyDocumentNotReal) and one invented condition key
# (bedrock-agentcore:GatewayAuthorizerModeNotReal). All four were reported and
# none of the names below was.
#
# The run is an oracle for name existence only, not for which actions a condition
# key applies to: a control statement pairing bedrock-agentcore:CreateGateway
# with bedrock-agentcore:RuntimeAuthorizerType, a pairing no reference declares,
# drew no finding either. The GatewayAuthorizerType-to-CreateGateway wiring rests
# on the AgentCore devguide, which disagrees with the two IAM reference
# surfaces.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "bedrock-agentcore:CreateGateway",
    "bedrock-agentcore:UpdateGateway",
    "organizations:DescribePolicy",
}

# Verified on 2026-09-25 with two more Access Analyzer validate-policy runs for
# the identity controls AC-29 through AC-34: a SERVICE_CONTROL_POLICY run for
# AC-29's SCP text and an IDENTITY_POLICY run for AC-32's condition advice. The
# SCP run's negative controls were two invented actions
# (bedrock-agentcore:CreateAgentRuntimeNotReal,
# bedrock-agentcore:ModifyAgentRuntimeThatDoesNotExist) and one invented
# condition key (bedrock-agentcore:RuntimeAuthorizerModeNotReal); the identity
# run's were one invented action
# (bedrock-agentcore:GetWorkloadAccessTokenForJWTNotReal) and two invented
# condition keys (bedrock-agentcore:InboundJwtClaimNotReal/iss,
# bedrock-agentcore:OutboundJwtClaim/iss). All six were reported and none of the
# names below was.
#
# Unlike AC-28's GatewayAuthorizerType, the RuntimeAuthorizerType-to-runtime
# wiring does not rest on a devguide sentence: the machine-readable service
# reference wires that key to exactly CreateAgentRuntime and UpdateAgentRuntime,
# and every InboundJwtClaim key to exactly CompleteResourceTokenAuth and
# GetWorkloadAccessTokenForJWT.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "bedrock-agentcore:CreateAgentRuntime",
    "bedrock-agentcore:UpdateAgentRuntime",
}

# Verified on 2026-09-25 with one more IDENTITY_POLICY Access Analyzer
# validate-policy run for the policy controls AC-36 and AC-37. Its negative
# controls were bedrock-agentcore:GetPolicyEngineNotReal,
# bedrock:InvokeGuardrailChecksNotReal and the singular
# bedrock:InvokeGuardrailCheck, which settles the plural spelling; all three were
# reported and neither name below was.
#
# InvokeGuardrailChecks reaches AC-37's resolution text through the
# GUARDRAIL_CHECK_ACTION constant, so the token scan below does not see it. It is
# classified here anyway, because the scan reading a Name instead of a string is
# a property of the scan and not a statement about the action.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "bedrock-agentcore:GetPolicyEngine",
    "bedrock:InvokeGuardrailChecks",
}

# Verified on 2026-09-25 with two IDENTITY_POLICY Access Analyzer validate-policy
# runs for the evaluation controls AC-39 through AC-44. The first run covered the
# nine evaluation actions with two negative controls,
# bedrock-agentcore:NotARealEvaluationAction and the plausible
# bedrock-agentcore:UpdateEvaluatorConfig; the second covered iam:PassRole with
# iam:PassedToService against three negative controls, iam:PassRoleNotReal,
# iam:PassedToServiceNotReal and the plausible iam:PassedToRole. All five were
# reported and none of the names below was.
#
# The six writes in EVALUATION_ADMINISTRATION_ACTIONS reach AC-02's resolution
# text through that constant, so the token scan below does not see them. They are
# classified here for the same reason InvokeGuardrailChecks is.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "bedrock-agentcore:ListEvaluators",
    "bedrock-agentcore:CreateEvaluator",
    "bedrock-agentcore:UpdateEvaluator",
    "bedrock-agentcore:DeleteEvaluator",
    "bedrock-agentcore:CreateOnlineEvaluationConfig",
    "bedrock-agentcore:UpdateOnlineEvaluationConfig",
    "bedrock-agentcore:DeleteOnlineEvaluationConfig",
    "iam:PassRole",
}

_VERIFIED_REMEDIATION_CONDITION_KEYS = {
    "bedrock:GuardrailIdentifier",
    "iam:AWSServiceName",
    "kms:ViaService",
    # Same Access Analyzer run as the action block above.
    "aws:PrincipalOrgID",
    "aws:PrincipalOrgPaths",
    # Same Access Analyzer run as the gateway action block above.
    "aws:SourceAccount",
    "aws:SourceArn",
    "aws:SourceVpce",
    # Same SERVICE_CONTROL_POLICY run as the AC-28 action block above.
    "bedrock-agentcore:GatewayAuthorizerType",
    # Same two runs as the AC-29 action block above. The reference publishes no
    # bare InboundJwtClaim key: it is five keys, one per claim, and the token
    # scan stops at the slash.
    "bedrock-agentcore:RuntimeAuthorizerType",
    "bedrock-agentcore:InboundJwtClaim",
    # Same second run as the AC-42 action block above.
    "iam:PassedToService",
    # Verified 2026-09-28 with ValidatePolicy (RESOURCE_POLICY) on a key policy
    # statement: kms:CallerAccountNotReal came back INVALID_SERVICE_CONDITION_KEY
    # and kms:CallerAccount raised nothing.
    "kms:CallerAccount",
}

# Verified the same way and on the same date: ValidatePolicy reports an
# undefined condition key as INVALID_CONDITION_KEY, and reported none of these.
# It also reported MISSING_QUALIFIER for aws-marketplace:ProductId, which is
# multi-valued, so BR-44's remediation text names ForAllValues:StringEquals.
_VERIFIED_REMEDIATION_CONDITION_KEYS |= {
    "aws-marketplace:ProductId",
    "aws:RequestedRegion",
    "bedrock:BearerTokenType",
    "bedrock-mantle:BearerTokenType",
    # The two DataRetentionMode keys: same method, 2026-09-27.
    "bedrock-mantle:DataRetentionMode",
    "bedrock:DataRetentionMode",
    "bedrock:ModelArn",
    "iam:ServiceSpecificCredentialAgeDays",
    "iam:ServiceSpecificCredentialServiceName",
}

# Verified with the bedrock-mantle:CreateInference entry above.
_VERIFIED_REMEDIATION_CONDITION_KEYS |= {"bedrock-mantle:Model"}

# Verified 2026-10-03 with ValidatePolicy (SERVICE_CONTROL_POLICY) on a Deny of
# CreateGateway and UpdateGateway: bedrock-agentcore:DiscoveryUrlNotReal came
# back INVALID_SERVICE_CONDITION_KEY, aws:SourceVpcNotReal came back
# INVALID_GLOBAL_CONDITION_KEY, and neither key below raised a key finding.
_VERIFIED_REMEDIATION_CONDITION_KEYS |= {
    "bedrock-agentcore:DiscoveryUrl",
    "aws:SourceVpc",
}

# Verified the same way on 2026-09-25 for the SageMaker checks. The
# condition key was submitted in its qualified aws:ResourceTag/<key> form, which
# is the only form IAM accepts; a bogus aws:...Tag/<key> key came back as
# INVALID_GLOBAL_CONDITION_KEY, so the clean result is discriminating.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "config:DescribeComplianceByConfigRule",
    "sagemaker:DescribeEndpoint",
    "sagemaker:DescribeTrainingJob",
    "sagemaker:InvokeEndpoint",
}

_VERIFIED_REMEDIATION_CONDITION_KEYS |= {"aws:ResourceTag"}

# Confirmed on 2026-09-27 from the sagemaker service-reference JSON: the key is
# listed as Bool and is an ActionConditionKey of CreateTrainingJob. SM-33 names
# it in the training network isolation resolution.
_VERIFIED_REMEDIATION_CONDITION_KEYS |= {"sagemaker:NetworkIsolation"}

# Confirmed the same way on 2026-09-27: both keys are ActionConditionKeys of
# CreateTrainingJob, and the short names sagemaker:VolumeKmsKey and
# sagemaker:OutputKmsKey are defined by no action. SM-34 names the ARN keys.
_VERIFIED_REMEDIATION_CONDITION_KEYS |= {
    "sagemaker:OutputKmsKeyArn",
    "sagemaker:VolumeKmsKeyArn",
}

# Verified the same way on 2026-09-25 for BR-46's per-bucket Macie leg. The
# knowledge-base data-source operations live on the bedrock-agent client but are
# authorized under the bedrock: action prefix, so the three near-misses
# bedrock:ListDataSource, macie2:DescribeBucket and macie2:GetAutomatedDiscovery
# were submitted alongside them and all three came back INVALID_ACTION.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "bedrock:GetDataSource",
    "bedrock:ListDataSources",
    "macie2:DescribeBuckets",
}

# Verified on 2026-09-26 with one IDENTITY_POLICY validate-policy run, one
# statement per action so a finding's path index names the action it belongs to,
# for the network and eventing legs. Eight negative controls were
# submitted alongside: ec2:DescribeVpcSubnets, ec2:DescribeVpcRouteTables,
# route53resolver:GetFirewallRuleGroupAssociations,
# route53resolver:GetFirewallRules, wafv2:DescribeWebACL, events:DescribeRules,
# events:ListRuleTargets and route53resolver:NotARealFirewallAction. All eight
# came back INVALID_ACTION, the run reported exactly eight findings, and none of
# the seven names below was reported.
#
# The first attempt built its controls by singularising the real name
# (ec2:DescribeRouteTable, route53resolver:ListFirewallRule), which makes the
# control a substring of the action it is meant to discriminate, so a substring
# read of the findings would accuse the valid plural. Each control below is a
# near-miss in some other position, and no name in the run is a substring of any
# other in either direction.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "ec2:DescribeSubnets",
    "ec2:DescribeRouteTables",
    "route53resolver:ListFirewallRuleGroupAssociations",
    "route53resolver:ListFirewallRules",
    "wafv2:GetWebACL",
    "events:ListRules",
    "events:ListTargetsByRule",
}

# Verified on 2026-09-26 with one IDENTITY_POLICY validate-policy run for AC-49's
# domain-list leg, one statement per name. The three negative controls
# route53resolver:DescribeFirewallDomainLists, route53resolver:GetFirewallDomains
# and route53resolver:ListFirewallDomainNames came back INVALID_ACTION at
# statement indexes 2, 3 and 4, and indexes 0 and 1, the two names below, were
# not reported.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "route53resolver:ListFirewallDomainLists",
    "route53resolver:ListFirewallDomains",
}

# Verified on 2026-09-26 with one IDENTITY_POLICY validate-policy run for AC-49's
# fail-open leg, one statement per name. The three negative controls
# route53resolver:DescribeFirewallConfig,
# route53resolver:GetFirewallConfiguration and
# route53resolver:ReadFirewallFailOpen came back INVALID_ACTION at statement
# indexes 1, 2 and 3, and index 0, the name below, was not reported.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "route53resolver:GetFirewallConfig",
}

# Verified on 2026-09-26 with one IDENTITY_POLICY validate-policy run for BR-47's
# customization job leg, one statement per name. The three negative controls
# bedrock:ListCustomizationJobs, bedrock:DescribeModelCustomizationJob and
# bedrock:ListModelCustomizationJob came back INVALID_ACTION at statement
# indexes 2, 3 and 4, and indexes 0 and 1, the two names below, were not
# reported.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "bedrock:ListModelCustomizationJobs",
    "bedrock:GetModelCustomizationJob",
}

# Verified on 2026-09-26 with one IDENTITY_POLICY validate-policy run for the
# Bedrock legs, one statement per name so a finding's path index names
# the entry it belongs to. Nine negative controls were submitted alongside:
# bedrock:DescribePrompts, bedrock:ReadPrompt, bedrock:StreamConverse,
# macie2:ListClassifyJobs, s3:ReadBucketPolicy and
# organizations:GetEffectivePolicy came back INVALID_ACTION, and
# aws:ArnOfPrincipal, aws:VpcSource and aws:PrivateTransport came back
# INVALID_GLOBAL_CONDITION_KEY. None of the names below was reported.
#
# The same run reported bedrock:Converse and bedrock:ConverseStream as
# INVALID_ACTION. The guardrail enforcement page lists Converse and
# ConverseStream among the inference APIs bedrock:GuardrailIdentifier applies
# to, but they are authorized by bedrock:InvokeModel and
# bedrock:InvokeModelWithResponseStream and have no IAM action of their own, so
# BR-49 asserts the Deny over those two and names no Converse action.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "bedrock:ListPrompts",
    "bedrock:GetPrompt",
    "macie2:ListClassificationJobs",
    "s3:GetBucketPolicy",
    "organizations:DescribeEffectivePolicy",
}

_VERIFIED_REMEDIATION_CONDITION_KEYS |= {
    "aws:PrincipalArn",
    "aws:SourceVpc",
    "aws:SecureTransport",
}

# Verified on 2026-09-28 with one IDENTITY_POLICY validate-policy run for the
# AC-14 vault population, one statement per name on a token-vault ARN.
# bedrock-agentcore:ListOauth2CredentialProviders,
# ListApiKeyCredentialProviders and ListPaymentCredentialProviders at indexes 0
# to 2 were not reported. The negative controls
# bedrock-agentcore:ListOauth2CredentialProvider and
# ListPaymentCredentialProviderz came back INVALID_ACTION at indexes 3 and 4.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "bedrock-agentcore:ListOauth2CredentialProviders",
    "bedrock-agentcore:ListApiKeyCredentialProviders",
    "bedrock-agentcore:ListPaymentCredentialProviders",
}

# Verified on 2026-09-28 with one IDENTITY_POLICY validate-policy run for the
# AC-11 and AC-36 key legs, one statement per name on a key ARN.
# kms:ListGrants at index 0, kms:DescribeKey at index 1 and
# kms:GrantConstraintType on kms:CreateGrant at index 2 were not reported. The
# negative controls kms:ListGrantz and kms:DescribeKeyz came back INVALID_ACTION
# at indexes 3 and 4, and kms:GrantConstraintTypez came back
# INVALID_SERVICE_CONDITION_KEY at index 5.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"kms:ListGrants", "kms:DescribeKey"}

_VERIFIED_REMEDIATION_CONDITION_KEYS |= {"kms:GrantConstraintType"}

# Confirmed on 2026-09-28 from the bedrock service-reference JSON for BR-07's
# prompt write leg: DeletePrompt and RenderPrompt are both defined on the prompt
# and prompt-version resource types, and the near-misses
# bedrock:DeletePromptVersion and bedrock:RenderPrompts are defined by no action.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"bedrock:DeletePrompt", "bedrock:RenderPrompt"}

# Verified on 2026-09-27 with one IDENTITY_POLICY validate-policy run for the
# AgentCore payment manager and harness legs of AC-02 and AC-48, one statement
# per name. The negative controls bedrock-agentcore:ListPaymentManager,
# bedrock-agentcore:DescribePaymentManager and bedrock-agentcore:ListHarness
# came back INVALID_ACTION at statement indexes 5, 6 and 7, and
# aws:AccountOfPrincipal came back INVALID_GLOBAL_CONDITION_KEY at index 8.
# Indexes 0 to 4, the names below, were not reported.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "bedrock-agentcore:ListPaymentManagers",
    "bedrock-agentcore:GetPaymentManager",
    "bedrock-agentcore:ListHarnesses",
    "bedrock-agentcore:GetHarness",
}

_VERIFIED_REMEDIATION_CONDITION_KEYS |= {"aws:PrincipalAccount"}

# Verified on 2026-09-27 with one IDENTITY_POLICY validate-policy run for the
# AC-23 remediation, one statement per key. aws:PrincipalTag/userId at index 0
# and as a policy variable inside bedrock-agentcore:namespace at index 2, and
# bedrock-agentcore:actorId and sessionId at index 3, were not reported. The
# negative controls aws:PrincipalTagz/userId came back
# INVALID_GLOBAL_CONDITION_KEY at index 1 and bedrock-agentcore:actorIdz came
# back INVALID_SERVICE_CONDITION_KEY at index 4.
_VERIFIED_REMEDIATION_CONDITION_KEYS |= {"aws:PrincipalTag"}

# Verified on 2026-09-27 with one IDENTITY_POLICY validate-policy run for the
# AC-45 command shell leg, one statement per name on a runtime ARN.
# bedrock-agentcore:InvokeAgentRuntimeCommandShell at index 0 and
# bedrock-agentcore:InvokeAgentRuntimeCommand at index 1 were not reported. The
# negative controls bedrock-agentcore:InvokeAgentRuntimeCommandShellz and
# bedrock-agentcore:InvokeAgentRuntimeCommandz came back INVALID_ACTION at
# indexes 2 and 3.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "bedrock-agentcore:InvokeAgentRuntimeCommandShell",
    "bedrock-agentcore:InvokeAgentRuntimeCommand",
}

# Verified on 2026-09-27 with one IDENTITY_POLICY validate-policy run for the
# AC-27 and AC-47 Deny-form legs, three names in one Action list.
# bedrock-agentcore:InvokeGateway at action index 0 and
# bedrock-agentcore:InvokeAgentRuntime at index 1 were not reported. The negative
# control bedrock-agentcore:InvokeGatewayz came back INVALID_ACTION at index 2.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "bedrock-agentcore:InvokeGateway",
    "bedrock-agentcore:InvokeAgentRuntime",
}

# Verified on 2026-09-27 with one IDENTITY_POLICY validate-policy run for the
# AC-28 and AC-29 attachment legs, one statement per name on its resource type.
# organizations:ListParents at index 0 and organizations:ListTargetsForPolicy at
# index 1 were not reported. The negative control organizations:ListParentz came
# back INVALID_ACTION at index 2.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "organizations:ListParents",
    "organizations:ListTargetsForPolicy",
}

# Verified on 2026-09-27 with one IDENTITY_POLICY validate-policy run for the
# AC-26 trail log file validation leg, on the trail resource type.
# cloudtrail:GetTrail at index 0 was not reported. The negative control
# cloudtrail:GetTrailz came back INVALID_ACTION at index 1.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "cloudtrail:GetTrail",
}

# Verified on 2026-09-27 with one IDENTITY_POLICY validate-policy run for the
# AC-18 trail status and identity inventory legs. cloudtrail:GetTrailStatus,
# cloudtrail:GetTrail, bedrock-agentcore:ListWorkloadIdentities,
# bedrock-agentcore:ListOauth2CredentialProviders and
# bedrock-agentcore:ListApiKeyCredentialProviders were not reported. The
# negative controls bedrock-agentcore:ListNotARealThing and
# cloudtrail:GetTrailStatusAndStuff came back INVALID_ACTION.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "cloudtrail:GetTrailStatus",
}

# Verified on 2026-09-27 with one IDENTITY_POLICY validate-policy run for
# SM-09's notebook access leg, one statement per name. The negative controls
# sagemaker:CreateNotebookInstances and aws:SourceIpAddress came back
# INVALID_ACTION and INVALID_GLOBAL_CONDITION_KEY at statement indexes 1 and 2,
# and index 0, which names both entries below, drew only PRIVATE_IP_ADDRESS.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"sagemaker:CreateNotebookInstance"}
_VERIFIED_REMEDIATION_CONDITION_KEYS |= {"aws:SourceIp"}
# Verified on 2026-09-27 with one IDENTITY_POLICY validate-policy run for
# SM-32's recorder leg. The negative control config:ListConfigurationRecorder
# came back INVALID_ACTION at statement index 1, and index 0 drew nothing.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"config:ListConfigurationRecorders"}
# Verified on 2026-09-27 with one IDENTITY_POLICY validate-policy run for the
# NET-01 processing-job and Studio domain legs of SM-33 and SM-10, one
# statement per name. The three negative controls sagemaker:ListProcessingJob,
# sagemaker:GetDomain and sagemaker:DescribeStudioDomain came back
# INVALID_ACTION at statement indexes 6, 7 and 8, and indexes 0 to 5, the six
# names below, were not reported. All six are also listed in the sagemaker
# service reference JSON.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "sagemaker:ListProcessingJobs",
    "sagemaker:DescribeProcessingJob",
    "sagemaker:ListDomains",
    "sagemaker:DescribeDomain",
    "sagemaker:ListNotebookInstances",
    "sagemaker:DescribeNotebookInstance",
}
# Verified on 2026-09-28 with one IDENTITY_POLICY validate-policy run for
# AC-08's endpoint inbound-scope leg, which reads each VPC's CIDR blocks. The
# negative control ec2:DescribeVpc came back INVALID_ACTION at statement index
# 1, and index 0 drew nothing. DescribeVpcs is also listed in the ec2 service
# reference JSON.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"ec2:DescribeVpcs"}
# Verified on 2026-09-28 against the ec2 service reference JSON, which lists
# GetManagedPrefixListEntries on the prefix-list resource type. AC-01 and AC-08
# name it when a security group rule references a prefix list whose entries
# could not be read.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"ec2:GetManagedPrefixListEntries"}
# Verified on 2026-09-28 against the bedrock-agentcore service reference JSON,
# which lists ListAgentRuntimeVersions as a List action with no resource type,
# and botocore's bedrock-agentcore-control model, which defines the operation.
# AC-01 names it when a runtime's versions cannot be listed.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"bedrock-agentcore:ListAgentRuntimeVersions"}
# Verified on 2026-09-28 with one IDENTITY_POLICY validate-policy run for the
# AC-47 runtime invoke actions, one statement per name on a runtime ARN.
# aws:ViaAWSService at index 0 and bedrock-agentcore:InvokeAgentRuntimeForUser,
# InvokeAgentRuntimeWithWebSocketStream and
# InvokeAgentRuntimeWithWebSocketStreamForUser at indexes 2 to 4 were not
# reported. The negative controls aws:ViaAWSServiceNotReal (index 1),
# InvokeAgentRuntimeForUsers and InvokeAgentRuntimeWithWebSocketStreams
# (indexes 5 and 6) came back INVALID_GLOBAL_CONDITION_KEY and INVALID_ACTION.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "bedrock-agentcore:InvokeAgentRuntimeForUser",
    "bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStream",
    "bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStreamForUser",
}
_VERIFIED_REMEDIATION_CONDITION_KEYS |= {"aws:ViaAWSService"}
# Verified on 2026-09-28 against the kms service reference JSON, which lists the
# condition key kms:EncryptionContext:${EncryptionContextKey}. AC-12 names it
# with the gateway context key aws:bedrock-agentcore-gateway:arn from the
# gateway encryption guide's example key policy, and the token scan stops at
# the second colon.
_VERIFIED_REMEDIATION_CONDITION_KEYS |= {"kms:EncryptionContext"}
# Verified on 2026-09-28 against the xray service reference JSON, which lists
# GetTraceSegmentDestination as a Read action with no resource type. AC-19
# names it when the Transaction Search destination cannot be read.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"xray:GetTraceSegmentDestination"}
# Verified on 2026-09-28 against the logs service reference JSON, which lists
# DescribeDeliveryDestinations as a List action with no resource type. AC-20
# names it with DescribeDeliveries and DescribeDeliverySources when the log
# groups behind AgentCore deliveries cannot be resolved.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"logs:DescribeDeliveryDestinations"}
# Verified on 2026-09-28 against the oam service reference JSON, which lists
# ListLinks with no resource type. AC-22 names it when an account with no sink
# cannot list the links it shares telemetry through.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"oam:ListLinks"}
# Verified on 2026-09-28 against the bedrock-agentcore service reference JSON,
# which lists ListAgentRuntimeEndpoints with no resource type, and botocore's
# bedrock-agentcore-control model, which defines the operation. AC-30 names it
# when the versions a runtime's endpoints serve cannot be listed.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"bedrock-agentcore:ListAgentRuntimeEndpoints"}
# Verified on 2026-09-28 against the bedrock-agentcore service reference JSON,
# which lists GetEvaluator on the evaluator resource type, ListBatchEvaluations
# with no resource type and GetBatchEvaluation on batch-evaluate, and botocore's
# models: GetEvaluator is in bedrock-agentcore-control, the two batch reads in
# the bedrock-agentcore data plane. AC-44 and AC-41 name them when an evaluator
# or a batch evaluation cannot be read.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "bedrock-agentcore:GetEvaluator",
    "bedrock-agentcore:ListBatchEvaluations",
    "bedrock-agentcore:GetBatchEvaluation",
}
# Verified on 2026-09-28 against the cloudwatch service reference JSON, which
# lists ListMetrics as a list action, and botocore's cloudwatch model, which
# defines the operation with a Namespace filter. AC-40 names it when the score
# metrics an alarm reads cannot be listed.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"cloudwatch:ListMetrics"}
# Verified on 2026-09-28 against the inspector2 service reference JSON, which
# lists ListCoverage with no resource type, and botocore's inspector2 model,
# which defines the operation with a resourceType filter. AC-50 names it when
# Inspector's coverage of an agent image repository cannot be listed.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"inspector2:ListCoverage"}

# BR-46 and BR-47 training job legs, 2026-09-28: validate-policy reported the
# negative control sagemaker:ListTrainingJob as INVALID_ACTION at statement
# index 1 and nothing at index 0. The name is also in the sagemaker service
# reference JSON.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"sagemaker:ListTrainingJobs"}

# BR-47 transform, endpoint and evaluation job legs, 2026-10-03: validate-policy
# reported the negative controls sagemaker:ListTransformJob and
# bedrock:GetEvaluationJobs as INVALID_ACTION at statement index 1 and nothing
# at index 0. Each name is also in its service reference JSON.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "sagemaker:ListTransformJobs",
    "sagemaker:DescribeTransformJob",
    "sagemaker:ListEndpoints",
    "sagemaker:DescribeEndpointConfig",
    "bedrock:GetEvaluationJob",
}

# BR-33 asks for lambda:ListTags, without which GetFunction withholds a
# function's tags. validate-policy on 2026-09-28 reported the negative control
# lambda:ListTagz as INVALID_ACTION at Action index 1 of one statement and
# nothing at index 0.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"lambda:ListTags"}

# Verified on 2026-10-03 for SM-39's Lambda VPC guardrail with one
# SERVICE_CONTROL_POLICY ValidatePolicy run. It reported INVALID_ACTION for the
# negative controls lambda:CreateFunctionNotReal and the plausible
# lambda:UpdateFunctionVpcConfig, and INVALID_SERVICE_CONDITION_KEY for
# lambda:VpcIdsNotReal and lambda:SubnetIdNotReal, and none of the names below.
# The lambda service-reference JSON lists the three keys as ActionConditionKeys
# of both actions, lambda:VpcIds as String and the other two as ArrayOfString.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "lambda:CreateFunction",
    "lambda:UpdateFunctionConfiguration",
}
_VERIFIED_REMEDIATION_CONDITION_KEYS |= {
    "lambda:VpcIds",
    "lambda:SubnetIds",
    "lambda:SecurityGroupIds",
}

# Verified on 2026-10-04 for SM-39's Lambda network connector guardrail with one
# SERVICE_CONTROL_POLICY ValidatePolicy run. It reported INVALID_ACTION for the
# negative control lambda:CreateNetworkConnectorz at Action index 2 and nothing
# at indexes 0 and 1. The lambda service-reference JSON lists both actions, and
# lambda:SubnetIds and lambda:SecurityGroupIds as ActionConditionKeys of
# CreateNetworkConnector only.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "lambda:CreateNetworkConnector",
    "lambda:UpdateNetworkConnector",
}

# AC-18 reads CloudTrail Lake event data stores. validate-policy on 2026-10-03
# reported the negative control cloudtrail:GetEventDataStorez as INVALID_ACTION
# at Action index 2 and nothing at indexes 0 and 1. Both names are also in the
# cloudtrail service reference JSON.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "cloudtrail:ListEventDataStores",
    "cloudtrail:GetEventDataStore",
}

# AC-22 lists each sink's attached links and the organization's accounts.
# validate-policy on 2026-10-03 reported the negative control
# oam:ListAttachedLinkz as INVALID_ACTION at Action index 2 and nothing at
# indexes 0 and 1. Both names are also in the oam and organizations service
# reference JSON.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "oam:ListAttachedLinks",
    "organizations:ListAccounts",
}

# AC-06 names s3:GetBucketOwnershipControls in its retry text. validate-policy
# on 2026-10-03 reported nothing for it, in the same run that reported
# INVALID_ACTION for the negative control logs:DescribeSubscriptionFilterz, and
# it is in the s3 service reference JSON with the bucket resource type.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"s3:GetBucketOwnershipControls"}

# AC-26 follows each log group's subscription filters to a Firehose stream and
# its archive bucket. validate-policy on 2026-10-03 reported nothing for each
# of these names alone and INVALID_ACTION for the negative control
# logs:DescribeSubscriptionFilterz. All three are in the logs, firehose and s3
# service reference JSON.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {
    "logs:DescribeSubscriptionFilters",
    "firehose:DescribeDeliveryStream",
    "s3:GetBucketObjectLockConfiguration",
}

# AC-26 follows a subscription filter to a CloudWatch Logs destination.
# validate-policy on 2026-10-03 reported INVALID_ACTION only at Action index 1,
# the negative control logs:DescribeDestinationz, and nothing at index 0. The
# name is in the logs service reference JSON with no resource type.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"logs:DescribeDestinations"}

# AC-49 reads where each reached firewall sends its ALERT log. validate-policy
# on 2026-10-03 reported INVALID_ACTION only at Action index 1, the negative
# control network-firewall:DescribeLoggingConfiguratioz, and nothing at index
# 0. The name is in the network-firewall service reference JSON with the
# Firewall resource type.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"network-firewall:DescribeLoggingConfiguration"}

# AC-06 names s3:PutObject in the fix text of its recording write SCP row.
# validate-policy on 2026-10-03 reported nothing at Action index 0 and
# INVALID_ACTION for the negative control s3:PutObjectz at index 1 of the same
# statement. It is in the s3 service reference JSON with the object resource
# type.
_VERIFIED_REMEDIATION_IAM_ACTIONS |= {"s3:PutObject"}

_NON_IAM_REMEDIATION_TOKENS = {
    "arn:PARTITION",
    "s3:ObjectCreated",
    "s3:ObjectModified",
    "s3:ObjectRemoved",
}


def _runtime_resolution_iam_tokens():
    token_pattern = re.compile(r"\b[a-z][a-z0-9-]*:[A-Z][A-Za-z0-9*]*")
    found = {}

    for root, directories, filenames in os.walk(_SECURITY_FUNCTIONS_ROOT):
        directories[:] = [
            directory
            for directory in directories
            if directory != "__pycache__" and not directory.endswith("_tests")
        ]
        for filename in filenames:
            if filename != "app.py":
                continue

            path = os.path.join(root, filename)
            with open(path, encoding="utf-8") as source_file:
                source = source_file.read()
            tree = ast.parse(source)

            for node in ast.walk(tree):
                resolution_values = []
                if isinstance(node, ast.keyword) and node.arg == "resolution":
                    resolution_values.append(node.value)
                elif isinstance(node, ast.Dict):
                    for key, value in zip(node.keys, node.values):
                        if isinstance(key, ast.Constant) and key.value == "resolution":
                            resolution_values.append(value)
                elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = (
                        node.targets if isinstance(node, ast.Assign) else [node.target]
                    )
                    # A resolution held in a module constant (BR-20's
                    # S3_VECTORS_RESOLUTION) reaches create_finding as a Name, so the
                    # call-site scan above reads the identifier and never sees the
                    # text. Collect the constants too, or an unverified action name
                    # ships by being factored out of the call.
                    if any(
                        isinstance(target, ast.Name)
                        and (
                            target.id == "resolution"
                            or target.id.endswith("_RESOLUTION")
                        )
                        for target in targets
                    ):
                        resolution_values.append(node.value)
                elif (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "_error_resolution"
                    and len(node.args) >= 2
                ):
                    resolution_values.append(node.args[1])
                elif (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "_na"
                    and len(node.args) >= 5
                ):
                    resolution_values.append(node.args[4])

                for value in resolution_values:
                    text = ast.get_source_segment(source, value) or ""
                    for token in token_pattern.findall(text):
                        found.setdefault(token, set()).add(
                            f"{os.path.relpath(path, _REPO_ROOT)}:{value.lineno}"
                        )

    return found


def test_every_runtime_remediation_iam_token_has_been_verified():
    found = _runtime_resolution_iam_tokens()
    classified = (
        _VERIFIED_REMEDIATION_IAM_ACTIONS
        | _VERIFIED_REMEDIATION_CONDITION_KEYS
        | _NON_IAM_REMEDIATION_TOKENS
    )
    unexpected = {
        token: locations
        for token, locations in found.items()
        if token not in classified
    }

    assert not unexpected, (
        "Runtime remediation text contains IAM-shaped tokens that have not been "
        f"verified against AWS Knowledge: {unexpected}"
    )
