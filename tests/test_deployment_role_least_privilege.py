"""Regression guards for assessment deployment-role least privilege."""

import re
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[1]
_MEMBER_TEMPLATE = _REPO_ROOT / "deployment" / "1-aiml-security-member-roles.yaml"
_SINGLE_TEMPLATE = _REPO_ROOT / "deployment" / "aiml-security-single-account.yaml"
_MULTI_TEMPLATE = _REPO_ROOT / "deployment" / "2-aiml-security-codebuild.yaml"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _role_policies(path: Path, role_header: str) -> str:
    text = _text(path)
    start = text.index("      Policies:", text.index(role_header))
    end = text.index("  # CodeBuild project", start)
    return text[start:end]


def _contains_action(policy: str, action: str) -> bool:
    return bool(re.search(rf"-\s+{re.escape(action)}(?:\s|#|$)", policy))


def test_cross_account_member_role_does_not_receive_assessment_api_permissions():
    """Only SAM Lambda execution roles call assessment service APIs."""
    text = _text(_MEMBER_TEMPLATE)

    for service_prefix in (
        "bedrock:",
        "bedrock-agentcore:",
        "sagemaker:",
        "agent-registry:",
        "guardduty:",
        "wafv2:",
        "apigateway:",
    ):
        assert service_prefix not in text


def test_top_level_codebuild_templates_exclude_assessment_api_permissions():
    """Assessment inventory APIs belong only to SAM Lambda execution roles."""
    for template in (_SINGLE_TEMPLATE, _MULTI_TEMPLATE):
        text = _text(template)
        for service_prefix in (
            "bedrock:",
            "bedrock-agentcore:",
            "sagemaker:",
            "agent-registry:",
            "guardduty:",
            "wafv2:",
            "apigateway:",
            "inspector2:",
            "macie2:",
            "aoss:",
        ):
            assert service_prefix not in text


def test_deployment_roles_limit_passrole_to_assessment_roles_and_runtime_services():
    for template in (_MEMBER_TEMPLATE, _SINGLE_TEMPLATE, _MULTI_TEMPLATE):
        text = _text(template)
        assert "iam:PassRole" in text
        assert "iam:PassedToService" in text
        assert "lambda.amazonaws.com" in text
        assert "states.amazonaws.com" in text


def test_codebuild_roles_exclude_unused_lambda_and_s3_administration_actions():
    for template, role_header in (
        (_SINGLE_TEMPLATE, "  CodeBuildRole:\n"),
        (_MULTI_TEMPLATE, "  MultiAccountCodeBuildRole:\n"),
    ):
        codebuild_policy = _role_policies(template, role_header)
        for action in (
            "lambda:InvokeFunction",
            "lambda:PublishVersion",
            "lambda:GetPolicy",
            "lambda:AddPermission",
            "lambda:RemovePermission",
            "cloudformation:UpdateStack",
            "cloudformation:DescribeStackResources",
            "cloudformation:GetTemplate",
            "cloudformation:ListStackResources",
            "cloudformation:DeleteChangeSet",
            "cloudformation:ListStacks",
            "s3:PutBucketAcl",
            "s3:GetBucketAcl",
            "s3:PutBucketNotification",
            "s3:GetBucketNotification",
            "s3:PutBucketLogging",
            "s3:GetBucketLogging",
            "s3:DeleteObjectVersion",
        ):
            assert not _contains_action(codebuild_policy, action)


def test_codebuild_role_scopes_every_action_with_a_resource_arn():
    """Only service actions without resource-level authorization retain wildcards."""
    for template, role_header in (
        (_SINGLE_TEMPLATE, "  CodeBuildRole:\n"),
        (_MULTI_TEMPLATE, "  MultiAccountCodeBuildRole:\n"),
    ):
        codebuild_policy = _role_policies(template, role_header)

        iam_start = codebuild_policy.index("Sid: IAMPermissions")
        iam_end = codebuild_policy.index("Sid: IAMBasicLoggingPolicy", iam_start)
        assert not re.search(
            r"Resource:\s+['\"]?\*['\"]?", codebuild_policy[iam_start:iam_end]
        )
        deployment_start = codebuild_policy.index(
            "PolicyName: CloudFormationPermissions"
        )
        deployment_policy = codebuild_policy[deployment_start:]
        assert not re.search(r"Resource:\s+['\"]?\*['\"]?", deployment_policy)
        assert "Sid: AssessmentStateMachinePermissions" in codebuild_policy
        assert "Sid: AssessmentAndSamBucketConfiguration" in codebuild_policy
        assert "changeSet/samcli-deploy*/*" in codebuild_policy
        assert "changeSet/InitialCreation/*" in codebuild_policy
        assert (
            "states:*:${AWS::AccountId}:stateMachine:aiml-security-*"
            in codebuild_policy
        )
        assert (
            "states:*:${AWS::AccountId}:stateMachine:AIMLAssessmentStateMachine-*"
            in codebuild_policy
        )
        assert (
            "states:*:${AWS::AccountId}:execution:AIMLAssessmentStateMachine-*:*"
            in codebuild_policy
        )
        assert "s3:::aws-sam-cli-managed-default-*" in codebuild_policy
        assert "Sid: IAMBasicLoggingPolicy" in codebuild_policy
        assert "iam:PolicyARN" in codebuild_policy
        assert "iam:UpdateAssumeRolePolicy" in codebuild_policy

    multi_policy = _text(_MULTI_TEMPLATE)
    organizations_start = multi_policy.index("PolicyName: ListOrganizationAccounts")
    organizations_end = multi_policy.index(
        "PolicyName: CloudFormationPermissions", organizations_start
    )
    organizations_policy = multi_policy[organizations_start:organizations_end]
    assert 'Resource: "*"' in organizations_policy


def test_member_role_scopes_create_operations_and_has_no_wildcard_resource():
    text = _text(_MEMBER_TEMPLATE)
    assert not re.search(r"Resource:\s+['\"]?\*['\"]?", text)
    assert "cloudformation:CreateStack" in text
    assert "changeSet/samcli-deploy*/*" in text
    assert "states:CreateStateMachine" in text
    assert "stateMachine:aiml-security-*" in text
    assert "stateMachine:AIMLAssessmentStateMachine-*" in text
    assert "execution:AIMLAssessmentStateMachine-*:*" in text
    assert "s3:CreateBucket" in text
    assert "s3:::aiml-security-*" in text
    assert "iam:UpdateAssumeRolePolicy" in text


def test_codebuild_log_permissions_are_project_scoped():
    single_policy = _role_policies(_SINGLE_TEMPLATE, "  CodeBuildRole:\n")
    multi_policy = _role_policies(_MULTI_TEMPLATE, "  MultiAccountCodeBuildRole:\n")
    assert "/aws/codebuild/AIMLSecurityCodeBuild:log-stream:*" in single_policy
    assert "/aws/codebuild/AIMLSecurityMultiAccountCodeBuild:log-stream:*" in (
        multi_policy
    )
    assert "/aws/codebuild/*" not in single_policy
    assert "/aws/codebuild/*" not in multi_policy


def test_report_transfer_permissions_separate_bucket_and_object_access():
    for template in (_SINGLE_TEMPLATE, _MULTI_TEMPLATE):
        text = _text(template)
        assert "Sid: CentralReportBucketInventory" in text
        assert "Sid: CentralReportObjectReadWrite" in text
        assert "Sid: AssessmentReportRead" in text or (
            "Sid: ManagementAssessmentReportRead" in text
        )
        assert "arn:${AWS::Partition}:s3:::aiml-security-*/*" in text
        assert "arn:${AWS::Partition}:s3:::aiml-sec-*/*" in text


def test_local_legacy_member_role_resources_are_removed():
    """Single-account workflows deploy directly under their CodeBuild role."""
    for template in (_SINGLE_TEMPLATE, _MULTI_TEMPLATE):
        text = _text(template)
        assert "\n  MemberRole:\n" not in text
        assert "AIMLSecurityAssessmentPermissions" not in text


def test_multi_account_assume_role_uses_the_configured_member_role_name():
    text = _text(_MULTI_TEMPLATE)
    assert "arn:${AWS::Partition}:iam::*:role/service-role/${MemberRoleName}" in text
    assert (
        "arn:${AWS::Partition}:iam::*:role/service-role/AIMLSecurityMemberRole"
        not in text
    )
    assert "arn:${AWS::Partition}:iam::*:role/aiml-security-*" not in text
    assert "arn:${AWS::Partition}:iam::*:role/aiml-sec-*" not in text
