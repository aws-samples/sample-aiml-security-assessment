"""Least-privilege guards for the SAM-generated runtime execution roles.

The assessment Lambdas intentionally inventory broad portions of an AWS
account, so many read-only List/Describe/Get actions require ``Resource: '*'``.
That does not justify unrelated actions or bucket-wide CRUD. This file records
the reviewed action inventory for each SAM resource and verifies that both
single- and multi-account runtime templates stay synchronized with it.
"""

import json
import os
import re

import pytest
import yaml


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SAM_TEMPLATES = [
    os.path.join(_REPO_ROOT, "aiml-security-assessment", "template.yaml"),
    os.path.join(_REPO_ROOT, "aiml-security-assessment", "template-multi-account.yaml"),
]

_ACTION_RE = re.compile(r"-\s+([a-z0-9-]+:[A-Za-z0-9]+)")
_RESOURCE_HEADER_RE = re.compile(r"^  [A-Za-z][A-Za-z0-9]*:\s*$", re.MULTILINE)
_LARGEST_PARTITION = "aws-us-gov"
_INLINE_ROLE_POLICY_LIMIT = 10_240
_INLINE_ROLE_POLICY_BUDGET = 9_000


class _CfnLoader(yaml.SafeLoader):
    """Safe YAML loader that preserves CloudFormation short-form intrinsics."""


def _cfn_multi_constructor(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {f"Fn::{tag_suffix}": value}


_CfnLoader.add_multi_constructor("!", _cfn_multi_constructor)


def _resource_block(path, logical_id):
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    header = f"\n  {logical_id}:"
    start = text.find(header)
    assert start != -1, f"resource {logical_id!r} not found in {path}"
    start += 1
    match = _RESOURCE_HEADER_RE.search(text, start + len(header))
    end = match.start() if match else len(text)
    return text[start:end]


def _actions(path, logical_id):
    return set(_ACTION_RE.findall(_resource_block(path, logical_id)))


def _statement_block(path, logical_id, sid):
    resource = _resource_block(path, logical_id)
    marker = f"- Sid: {sid}"
    start = resource.find(marker)
    assert start != -1, f"statement {sid!r} not found in {logical_id} ({path})"
    match = re.search(r"^\s+- Sid:\s+", resource[start + len(marker) :], re.MULTILINE)
    end = start + len(marker) + match.start() if match else len(resource)
    return resource[start:end]


def _render_policy_intrinsics(value):
    """Render policy intrinsics conservatively for IAM character-count checks."""
    if isinstance(value, list):
        return [_render_policy_intrinsics(item) for item in value]
    if not isinstance(value, dict):
        return value
    if set(value) == {"Fn::Sub"}:
        template = value["Fn::Sub"]
        assert isinstance(template, str), "size guard supports string !Sub values"
        return template.replace("${AWS::Partition}", _LARGEST_PARTITION).replace(
            "${AWS::AccountId}", "123456789012"
        )
    if len(value) == 1 and next(iter(value)).startswith("Fn::"):
        # A realistic upper-bound placeholder for !GetAtt/!Ref policy values.
        return "x" * 128
    return {key: _render_policy_intrinsics(item) for key, item in value.items()}


_EXPECTED_ACTIONS = {
    "AIMLAssessmentStateMachine": set(),
    "ResolveRegionsFunction": set(),
    "CleanupBucketFunction": {
        "s3:DeleteObject",
        "s3:ListBucket",
    },
    "IAMPermissionCachingFunction": {
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:GetRolePolicy",
        "iam:GetUserPolicy",
        "iam:ListAttachedRolePolicies",
        "iam:ListAttachedUserPolicies",
        "iam:ListRolePolicies",
        "iam:ListRoles",
        "iam:ListUserPolicies",
        "iam:ListUsers",
        "s3:PutObject",
    },
    "GenerateConsolidatedReportFunction": {
        "s3:DeleteObject",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:PutObject",
    },
    "BedrockSecurityAssessmentFunction": {
        "bedrock:GetAccountDataRetention",
        "bedrock:GetAgent",
        "bedrock:GetAgentActionGroup",
        "bedrock:GetAutomatedReasoningPolicy",
        "bedrock:GetCustomModel",
        "bedrock:GetFlow",
        "bedrock:GetGuardrail",
        "bedrock:GetImportedModel",
        "bedrock:GetKnowledgeBase",
        "bedrock:GetMarketplaceModelEndpoint",
        "bedrock:GetModelCustomizationJob",
        "bedrock:GetModelInvocationLoggingConfiguration",
        "bedrock:GetPrompt",
        "bedrock:ListAgentActionGroups",
        "bedrock:ListAgents",
        "bedrock:ListAutomatedReasoningPolicies",
        "bedrock:ListCustomModels",
        "bedrock:ListEnforcedGuardrailsConfiguration",
        "bedrock:ListEvaluationJobs",
        "bedrock:ListFlows",
        "bedrock:ListGuardrails",
        "bedrock:ListImportedModels",
        "bedrock:ListInferenceProfiles",
        "bedrock:ListKnowledgeBases",
        "bedrock:ListMarketplaceModelEndpoints",
        "bedrock:ListModelInvocationJobs",
        "bedrock:ListPrompts",
        "bedrock:ListTagsForResource",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:GetTrail",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:ListTrails",
        "cloudwatch:DescribeAlarms",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeVpcs",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:GetServiceLastAccessedDetails",
        "inspector2:BatchGetAccountStatus",
        "kms:DescribeKey",
        "lambda:GetFunction",
        "organizations:DescribeOrganization",
        "organizations:ListPolicies",
        "organizations:ListRoots",
        "organizations:ListTargetsForPolicy",
        "s3:GetEncryptionConfiguration",
        "s3:GetObject",
        "s3:PutObject",
        "servicequotas:GetAWSDefaultServiceQuota",
        "servicequotas:GetServiceQuota",
        "servicequotas:ListServiceQuotas",
    },
    "SagemakerSecurityAssessmentFunction": {
        "guardduty:GetDetector",
        "guardduty:ListDetectors",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:GetServiceLastAccessedDetails",
        "s3:GetObject",
        "s3:PutObject",
        "sagemaker:DescribeAutoMLJob",
        "sagemaker:DescribeCluster",
        "sagemaker:DescribeCompilationJob",
        "sagemaker:DescribeDataQualityJobDefinition",
        "sagemaker:DescribeDomain",
        "sagemaker:DescribeEndpoint",
        "sagemaker:DescribeFeatureGroup",
        "sagemaker:DescribeHyperParameterTuningJob",
        "sagemaker:DescribeModel",
        "sagemaker:DescribeMonitoringSchedule",
        "sagemaker:DescribeNotebookInstance",
        "sagemaker:DescribeProcessingJob",
        "sagemaker:DescribeTrainingJob",
        "sagemaker:DescribeTransformJob",
        "sagemaker:GetModelPackageGroupPolicy",
        "sagemaker:ListArtifacts",
        "sagemaker:ListAssociations",
        "sagemaker:ListAutoMLJobs",
        "sagemaker:ListClusters",
        "sagemaker:ListCompilationJobs",
        "sagemaker:ListDataQualityJobDefinitions",
        "sagemaker:ListDomains",
        "sagemaker:ListEndpoints",
        "sagemaker:ListExperiments",
        "sagemaker:ListFeatureGroups",
        "sagemaker:ListHyperParameterTuningJobs",
        "sagemaker:ListModelPackageGroups",
        "sagemaker:ListModelPackages",
        "sagemaker:ListModels",
        "sagemaker:ListMonitoringSchedules",
        "sagemaker:ListNotebookInstances",
        "sagemaker:ListPipelineExecutions",
        "sagemaker:ListPipelines",
        "sagemaker:ListProcessingJobs",
        "sagemaker:ListTrainingJobs",
        "sagemaker:ListTransformJobs",
        "sagemaker:ListTrials",
    },
    "AgentCoreSecurityAssessmentFunction": {
        "bedrock-agentcore:GetAgentRuntime",
        "bedrock-agentcore:GetBrowser",
        "bedrock-agentcore:GetCodeInterpreter",
        "bedrock-agentcore:GetGateway",
        "bedrock-agentcore:GetMemory",
        "bedrock-agentcore:GetOnlineEvaluationConfig",
        "bedrock-agentcore:GetPolicyEngine",
        "bedrock-agentcore:GetResourcePolicy",
        "bedrock-agentcore:GetTokenVault",
        "bedrock-agentcore:ListAgentRuntimes",
        "bedrock-agentcore:ListBrowsers",
        "bedrock-agentcore:ListCodeInterpreters",
        "bedrock-agentcore:ListGateways",
        "bedrock-agentcore:ListMemories",
        "bedrock-agentcore:ListOnlineEvaluationConfigs",
        "bedrock-agentcore:ListPolicies",
        "bedrock-agentcore:ListPolicyEngines",
        "cloudwatch:PutMetricData",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSubnets",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeVpcs",
        "ecr:DescribeRepositories",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:GetRole",
        "iam:GetServiceLastAccessedDetails",
        "logs:DescribeLogGroups",
        "s3:GetObject",
        "s3:PutObject",
    },
    "AgentRegistrySecurityAssessmentFunction": {
        "agent-registry:GetRegistry",
        "agent-registry:ListRegistries",
        "agent-registry:ListRegistryRecords",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:GetServiceLastAccessedDetails",
        "s3:GetObject",
        "s3:PutObject",
    },
    "ResponsibleAIGRCAssessmentFunction": {
        "aoss:ListCollections",
        "aoss:ListSecurityPolicies",
        "apigateway:GET",
        "bedrock-agentcore:GetAgentRuntime",
        "bedrock-agentcore:ListAgentRuntimes",
        "bedrock:GetAgent",
        "bedrock:GetDataSource",
        "bedrock:GetGuardrail",
        "bedrock:GetModelInvocationLoggingConfiguration",
        "bedrock:ListAgents",
        "bedrock:ListAutomatedReasoningPolicies",
        "bedrock:ListCustomModels",
        "bedrock:ListDataSources",
        "bedrock:ListEvaluationJobs",
        "bedrock:ListFoundationModels",
        "bedrock:ListGuardrails",
        "bedrock:ListIngestionJobs",
        "bedrock:ListKnowledgeBases",
        "bedrock:ListTagsForResource",
        "budgets:ViewBudget",
        "ce:GetAnomalyMonitors",
        "cloudwatch:DescribeAlarms",
        "config:DescribeConfigRules",
        "ecr:DescribeRepositories",
        "events:ListRules",
        "inspector2:BatchGetAccountStatus",
        "lambda:GetFunctionConcurrency",
        "lambda:ListFunctions",
        "logs:DescribeAccountPolicies",
        "logs:GetDataProtectionPolicy",
        "macie2:GetAutomatedDiscoveryConfiguration",
        "macie2:GetMacieSession",
        "organizations:DescribePolicy",
        "organizations:ListPolicies",
        "s3:GetBucketNotification",
        "s3:GetBucketTagging",
        "s3:GetBucketVersioning",
        "s3:GetObject",
        "s3:ListAllMyBuckets",
        "s3:PutObject",
        "sagemaker:DescribeFeatureGroup",
        "sagemaker:ListEndpoints",
        "sagemaker:ListFeatureGroups",
        "sagemaker:ListModelCards",
        "sagemaker:ListModels",
        "sagemaker:ListMonitoringSchedules",
        "sagemaker:ListTags",
        "scheduler:ListSchedules",
        "servicequotas:ListAWSDefaultServiceQuotas",
        "servicequotas:ListServiceQuotas",
        "shield:DescribeSubscription",
        "states:DescribeStateMachine",
        "states:ListStateMachines",
        "wafv2:GetWebACL",
        "wafv2:ListWebACLs",
    },
    "OWASPSecurityAssessmentFunction": {
        "bedrock:GetGuardrail",
        "bedrock:ListGuardrails",
        "lambda:ListFunctions",
        "s3:GetObject",
        "s3:PutObject",
    },
}


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
@pytest.mark.parametrize("logical_id", sorted(_EXPECTED_ACTIONS))
def test_sam_resource_actions_match_reviewed_inventory(template, logical_id):
    actual = _actions(template, logical_id)
    expected = _EXPECTED_ACTIONS[logical_id]
    assert actual == expected, (
        f"{os.path.basename(template)} {logical_id} IAM drift. "
        f"Missing: {sorted(expected - actual)}; excess: {sorted(actual - expected)}"
    )


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_sam_templates_do_not_use_bucket_wide_crud_policy(template):
    with open(template, encoding="utf-8") as fh:
        text = fh.read()
    assert "S3CrudPolicy" not in text
    assert "sts:GetCallerIdentity" not in text
    assert "s3:GetBucketEncryption" not in text


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_sam_lambda_inline_policy_documents_stay_within_budget(template):
    with open(template, encoding="utf-8") as template_file:
        data = yaml.load(template_file, Loader=_CfnLoader)  # nosec B506

    for logical_id, resource in data["Resources"].items():
        if resource.get("Type") != "AWS::Serverless::Function":
            continue
        policy_documents = []
        for policy in resource.get("Properties", {}).get("Policies", []) or []:
            if isinstance(policy, dict) and "Statement" in policy:
                policy_documents.append(
                    {"Version": "2012-10-17", "Statement": policy["Statement"]}
                )

        aggregate_size = sum(
            len(
                json.dumps(
                    _render_policy_intrinsics(document),
                    separators=(",", ":"),
                )
            )
            for document in policy_documents
        )
        assert aggregate_size <= _INLINE_ROLE_POLICY_BUDGET, (
            f"{os.path.basename(template)} {logical_id} renders to an estimated "
            f"{aggregate_size:,} inline-policy characters in {_LARGEST_PARTITION}; "
            f"keep it below the {_INLINE_ROLE_POLICY_BUDGET:,}-character project "
            f"budget and never exceed IAM's aggregate "
            f"{_INLINE_ROLE_POLICY_LIMIT:,}-character role quota."
        )


_ARTIFACT_PREFIXES = {
    "IAMPermissionCachingFunction": ("permissions_cache_*.json",),
    "GenerateConsolidatedReportFunction": (
        "bedrock_security_report_*.csv",
        "sagemaker_security_report_*.csv",
        "agentcore_security_report_*.csv",
        "agent_registry_security_report_*.csv",
        "responsible_ai_grc_security_report_*.csv",
        "owasp_security_report_*.csv",
        "security_assessment_single_account_*.html",
        "permissions_cache_*.json",
    ),
    "BedrockSecurityAssessmentFunction": (
        "permissions_cache_*.json",
        "bedrock_security_report_*.csv",
    ),
    "SagemakerSecurityAssessmentFunction": (
        "permissions_cache_*.json",
        "sagemaker_security_report_*.csv",
    ),
    "AgentCoreSecurityAssessmentFunction": (
        "permissions_cache_*.json",
        "agentcore_security_report_*.csv",
    ),
    "AgentRegistrySecurityAssessmentFunction": (
        "permissions_cache_*.json",
        "agent_registry_security_report_*.csv",
    ),
    "ResponsibleAIGRCAssessmentFunction": (
        "permissions_cache_*.json",
        "responsible_ai_grc_security_report_*.csv",
    ),
    "OWASPSecurityAssessmentFunction": (
        "bedrock_security_report_*.csv",
        "sagemaker_security_report_*.csv",
        "agentcore_security_report_*.csv",
        "responsible_ai_grc_security_report_*.csv",
        "owasp_security_report_*.csv",
    ),
}


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
@pytest.mark.parametrize("logical_id", sorted(_ARTIFACT_PREFIXES))
def test_assessment_artifact_access_is_prefix_scoped(template, logical_id):
    block = _resource_block(template, logical_id)
    assert "${AIMLAssessmentBucket.Arn}/*" not in block
    for prefix in _ARTIFACT_PREFIXES[logical_id]:
        assert f"${{AIMLAssessmentBucket.Arn}}/{prefix}" in block


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_iam_permission_cache_identity_reads_are_resource_scoped(template):
    block = _resource_block(template, "IAMPermissionCachingFunction")
    required_resources = {
        "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/*",
        "arn:${AWS::Partition}:iam::${AWS::AccountId}:user/*",
        "arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/*",
        "arn:${AWS::Partition}:iam::aws:policy/*",
    }
    missing = sorted(
        resource for resource in required_resources if resource not in block
    )
    assert not missing


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
@pytest.mark.parametrize(
    "logical_id",
    [
        "BedrockSecurityAssessmentFunction",
        "SagemakerSecurityAssessmentFunction",
        "AgentCoreSecurityAssessmentFunction",
        "AgentRegistrySecurityAssessmentFunction",
    ],
)
def test_service_last_access_generation_is_identity_scoped(template, logical_id):
    generation = _statement_block(
        template, logical_id, "IAMServiceLastAccessGeneration"
    )
    assert "iam:GenerateServiceLastAccessedDetails" in generation
    assert "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/*" in generation
    assert "arn:${AWS::Partition}:iam::${AWS::AccountId}:user/*" in generation
    assert not re.search(r"Resource:\s+['\"]\*['\"]", generation)

    results = _statement_block(template, logical_id, "IAMServiceLastAccessResults")
    assert "iam:GetServiceLastAccessedDetails" in results
    assert re.search(r"Resource:\s+['\"]\*['\"]", results)


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_bedrock_resource_level_actions_are_arn_scoped(template):
    """Bedrock inventory stays wildcarded only where IAM requires it."""
    inventory = _statement_block(
        template,
        "BedrockSecurityAssessmentFunction",
        "BedrockAccountInventoryPermissions",
    )
    assert re.search(r"Resource:\s+['\"]\*['\"]", inventory)
    # Account-level enumerations with no resource-level authorization support
    # stay on the wildcard inventory statement.
    for action in (
        "bedrock:ListGuardrails",
        "bedrock:ListPrompts",
        "bedrock:ListAutomatedReasoningPolicies",
    ):
        assert action in inventory
    for action in (
        "bedrock:GetKnowledgeBase",
        "bedrock:GetAgent",
        "bedrock:GetGuardrail",
        "bedrock:GetPrompt",
        "bedrock:GetCustomModel",
        "bedrock:GetFlow",
    ):
        assert action not in inventory

    expected_resources = {
        "BedrockGuardrailRead": "bedrock:*:${AWS::AccountId}:guardrail/*",
        "BedrockPromptRead": "bedrock:*:${AWS::AccountId}:prompt/*",
        "BedrockAgentRead": "bedrock:*:${AWS::AccountId}:agent/*",
        "BedrockCustomModelRead": "bedrock:*:${AWS::AccountId}:custom-model/*",
        "BedrockCustomizationJobRead": (
            "bedrock:*:${AWS::AccountId}:model-customization-job/*"
        ),
        "BedrockFlowRead": "bedrock:*:${AWS::AccountId}:flow/*",
        "BedrockKnowledgeBaseRead": "bedrock:*:${AWS::AccountId}:knowledge-base/*",
        "BedrockImportedModelRead": "bedrock:*:${AWS::AccountId}:imported-model/*",
        "BedrockInferenceProfileTagRead": (
            "bedrock:*:${AWS::AccountId}:inference-profile/*"
        ),
        "BedrockAutomatedReasoningRead": (
            "bedrock:*:${AWS::AccountId}:automated-reasoning-policy/*"
        ),
        "BedrockMarketplaceEndpointRead": (
            "bedrock:*:${AWS::AccountId}:marketplace/model-endpoint/all-access"
        ),
    }
    for sid, resource in expected_resources.items():
        statement = _statement_block(template, "BedrockSecurityAssessmentFunction", sid)
        assert resource in statement
        assert not re.search(r"Resource:\s+['\"]\*['\"]", statement)


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_bedrock_organizations_policy_target_read_is_arn_scoped(template):
    inventory = _statement_block(
        template,
        "BedrockSecurityAssessmentFunction",
        "OrganizationsInventoryPermissions",
    )
    assert "organizations:ListPolicies" in inventory
    assert "organizations:ListTargetsForPolicy" not in inventory
    assert re.search(r"Resource:\s+['\"]\*['\"]", inventory)

    policy_targets = _statement_block(
        template,
        "BedrockSecurityAssessmentFunction",
        "OrganizationsPolicyTargetRead",
    )
    assert "organizations:ListTargetsForPolicy" in policy_targets
    assert "organizations::*:policy/*/*/*" in policy_targets
    assert "organizations::aws:policy/*/*" in policy_targets
    assert not re.search(r"Resource:\s+['\"]\*['\"]", policy_targets)


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_bedrock_quota_and_alarm_reads_are_arn_scoped(template):
    quota = _statement_block(
        template, "BedrockSecurityAssessmentFunction", "BedrockServiceQuotaRead"
    )
    assert "servicequotas:GetServiceQuota" in quota
    assert "servicequotas:*:${AWS::AccountId}:bedrock/*" in quota
    assert not re.search(r"Resource:\s+['\"]\*['\"]", quota)

    alarms = _statement_block(
        template, "BedrockSecurityAssessmentFunction", "CloudWatchPermissions"
    )
    assert "cloudwatch:DescribeAlarms" in alarms
    assert "cloudwatch:*:${AWS::AccountId}:alarm:*" in alarms
    assert not re.search(r"Resource:\s+['\"]\*['\"]", alarms)


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_sagemaker_and_guardduty_resource_reads_are_arn_scoped(template):
    inventory = _statement_block(
        template,
        "SagemakerSecurityAssessmentFunction",
        "SageMakerAccountInventoryPermissions",
    )
    assert "sagemaker:ListNotebookInstances" in inventory
    # ListPipelineExecutions is an account-level enumeration with no
    # resource-level authorization support, so it stays on Resource '*'.
    assert "sagemaker:ListPipelineExecutions" in inventory
    for action in (
        "sagemaker:DescribeNotebookInstance",
        "sagemaker:ListModelPackages",
        "sagemaker:GetModelPackageGroupPolicy",
    ):
        assert action not in inventory
    assert re.search(r"Resource:\s+['\"]\*['\"]", inventory)

    reads = _statement_block(
        template,
        "SagemakerSecurityAssessmentFunction",
        "SageMakerResourceReadPermissions",
    )
    assert "sagemaker:ListPipelineExecutions" not in reads
    for action in (
        "sagemaker:DescribeNotebookInstance",
        "sagemaker:ListModelPackages",
        "sagemaker:GetModelPackageGroupPolicy",
    ):
        assert action in reads
    for resource in (
        "sagemaker:*:${AWS::AccountId}:notebook-instance/*",
        "sagemaker:*:${AWS::AccountId}:model-package/*",
        "sagemaker:*:${AWS::AccountId}:model-package-group/*",
        "sagemaker:*:${AWS::AccountId}:pipeline/*",
        "sagemaker:*:${AWS::AccountId}:cluster/*",
    ):
        assert resource in reads
    assert not re.search(r"Resource:\s+['\"]\*['\"]", reads)

    detector = _statement_block(
        template, "SagemakerSecurityAssessmentFunction", "GuardDutyDetectorRead"
    )
    assert "guardduty:GetDetector" in detector
    assert "guardduty:*:${AWS::AccountId}:detector/*" in detector
    assert not re.search(r"Resource:\s+['\"]\*['\"]", detector)


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_agentcore_resource_reads_and_metric_writes_are_constrained(template):
    inventory = _statement_block(
        template,
        "AgentCoreSecurityAssessmentFunction",
        "AgentCoreAccountInventoryPermissions",
    )
    assert "bedrock-agentcore:ListAgentRuntimes" in inventory
    assert "bedrock-agentcore:GetAgentRuntime" not in inventory
    assert "bedrock-agentcore:ListPolicies" not in inventory
    assert re.search(r"Resource:\s+['\"]\*['\"]", inventory)

    reads = _statement_block(
        template,
        "AgentCoreSecurityAssessmentFunction",
        "AgentCoreResourceReadPermissions",
    )
    for action in (
        "bedrock-agentcore:GetAgentRuntime",
        "bedrock-agentcore:GetGateway",
        "bedrock-agentcore:GetResourcePolicy",
        "bedrock-agentcore:GetTokenVault",
        "bedrock-agentcore:ListPolicies",
    ):
        assert action in reads
    for resource in (
        "bedrock-agentcore:*:${AWS::AccountId}:runtime/*",
        "bedrock-agentcore:*:${AWS::AccountId}:runtime/*/runtime-endpoint/*",
        "bedrock-agentcore:*:${AWS::AccountId}:gateway/*",
        "bedrock-agentcore:*:${AWS::AccountId}:policy-engine/*",
        "bedrock-agentcore:*:${AWS::AccountId}:token-vault/*",
        "bedrock-agentcore:*:${AWS::AccountId}:online-evaluation-config/*",
    ):
        assert resource in reads
    assert not re.search(r"Resource:\s+['\"]\*['\"]", reads)

    service_role = _statement_block(
        template, "AgentCoreSecurityAssessmentFunction", "IAMRolePermissions"
    )
    assert (
        "iam::${AWS::AccountId}:role/aws-service-role/"
        "network.bedrock-agentcore.amazonaws.com/"
        "AWSServiceRoleForBedrockAgentCoreNetwork"
    ) in service_role
    assert "iam::*:role/" not in service_role

    metrics = _statement_block(
        template, "AgentCoreSecurityAssessmentFunction", "CloudWatchPermissions"
    )
    assert "cloudwatch:PutMetricData" in metrics
    assert "cloudwatch:namespace: AIMLSecurity/AgentCore" in metrics

    repositories = _statement_block(
        template, "AgentCoreSecurityAssessmentFunction", "ECRPermissions"
    )
    assert "ecr:DescribeRepositories" in repositories
    assert "ecr:*:${AWS::AccountId}:repository/*" in repositories
    assert not re.search(r"Resource:\s+['\"]\*['\"]", repositories)


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_responsible_ai_bedrock_and_owasp_reads_are_arn_scoped(template):
    inventory = _statement_block(
        template,
        "ResponsibleAIGRCAssessmentFunction",
        "BedrockAccountInventoryPermissions",
    )
    assert re.search(r"Resource:\s+['\"]\*['\"]", inventory)
    # Account-level enumerations with no resource-level authorization support
    # stay on the wildcard inventory statement.
    assert "bedrock:ListGuardrails" in inventory
    assert "bedrock:ListAutomatedReasoningPolicies" in inventory
    for action in (
        "bedrock:GetAgent",
        "bedrock:GetGuardrail",
        "bedrock:GetDataSource",
        "bedrock:ListDataSources",
        "bedrock:ListIngestionJobs",
    ):
        assert action not in inventory

    for sid, resource in {
        "BedrockGuardrailRead": "bedrock:*:${AWS::AccountId}:guardrail/*",
        "BedrockCustomModelTagRead": "bedrock:*:${AWS::AccountId}:custom-model/*",
        "BedrockAgentRead": "bedrock:*:${AWS::AccountId}:agent/*",
        "BedrockKnowledgeBaseDataSourceRead": (
            "bedrock:*:${AWS::AccountId}:knowledge-base/*"
        ),
    }.items():
        statement = _statement_block(
            template, "ResponsibleAIGRCAssessmentFunction", sid
        )
        assert resource in statement
        assert not re.search(r"Resource:\s+['\"]\*['\"]", statement)

    # GetGuardrail stays ARN-scoped; ListGuardrails is a wildcard enumeration.
    owasp = _statement_block(
        template, "OWASPSecurityAssessmentFunction", "OWASPBedrockPermissions"
    )
    assert "bedrock:GetGuardrail" in owasp
    assert "bedrock:*:${AWS::AccountId}:guardrail/*" in owasp
    assert not re.search(r"Resource:\s+['\"]\*['\"]", owasp)

    owasp_list = _statement_block(
        template, "OWASPSecurityAssessmentFunction", "OWASPBedrockGuardrailList"
    )
    assert "bedrock:ListGuardrails" in owasp_list
    assert re.search(r"Resource:\s+['\"]\*['\"]", owasp_list)


@pytest.mark.parametrize("template", _SAM_TEMPLATES, ids=os.path.basename)
def test_responsible_ai_non_bedrock_resource_reads_are_arn_scoped(template):
    logical_id = "ResponsibleAIGRCAssessmentFunction"
    expected = {
        "WAFWebACLRead": (
            "wafv2:GetWebACL",
            "wafv2:*:${AWS::AccountId}:regional/webacl/*/*",
        ),
        "BudgetRead": (
            "budgets:ViewBudget",
            "budgets::${AWS::AccountId}:budget/*",
        ),
        "LogsDataProtectionPolicyRead": (
            "logs:GetDataProtectionPolicy",
            "logs:*:${AWS::AccountId}:log-group:*",
        ),
        "BedrockAgentCoreRuntimeRead": (
            "bedrock-agentcore:GetAgentRuntime",
            "bedrock-agentcore:*:${AWS::AccountId}:runtime/*",
        ),
        "SageMakerFeatureGroupRead": (
            "sagemaker:DescribeFeatureGroup",
            "sagemaker:*:${AWS::AccountId}:feature-group/*",
        ),
        "SageMakerModelTagRead": (
            "sagemaker:ListTags",
            "sagemaker:*:${AWS::AccountId}:model/*",
        ),
        "LambdaConcurrencyRead": (
            "lambda:GetFunctionConcurrency",
            "lambda:*:${AWS::AccountId}:function:*",
        ),
        "StepFunctionsDefinitionRead": (
            "states:DescribeStateMachine",
            "states:*:${AWS::AccountId}:stateMachine:*",
        ),
        "CloudWatchPermissions": (
            "cloudwatch:DescribeAlarms",
            "cloudwatch:*:${AWS::AccountId}:alarm:*",
        ),
        "ECRPermissions": (
            "ecr:DescribeRepositories",
            "ecr:*:${AWS::AccountId}:repository/*",
        ),
    }
    for sid, (action, resource) in expected.items():
        statement = _statement_block(template, logical_id, sid)
        assert action in statement
        assert resource in statement
        assert not re.search(r"Resource:\s+['\"]\*['\"]", statement)

    api_gateway = _statement_block(template, logical_id, "APIGatewayPermissions")
    for resource in (
        "apigateway:*::/usageplans",
        "apigateway:*::/restapis",
        "apigateway:*::/restapis/*/requestvalidators",
        "apigateway:*::/restapis/*/models",
    ):
        assert resource in api_gateway
    assert not re.search(r"Resource:\s+['\"]\*['\"]", api_gateway)

    organizations = _statement_block(template, logical_id, "OrganizationsPolicyRead")
    assert "organizations:DescribePolicy" in organizations
    assert "organizations::*:policy/*/*/*" in organizations
    assert "organizations::aws:policy/*/*" in organizations
    assert not re.search(r"Resource:\s+['\"]\*['\"]", organizations)
