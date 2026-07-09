"""Guard the core Bedrock deployment roles against missing runtime IAM actions."""

import os

import pytest


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_SECTION_CHECKS = [
    {
        "path": os.path.join(_REPO_ROOT, "aiml-security-assessment", "template.yaml"),
        "start": "- Sid: BedrockAssessmentPermissions",
        "end": "- Sid: S3BucketEncryptionPermissions",
        "required": {
            "bedrock:GetModelInvocationLoggingConfiguration",
            "bedrock:ListKnowledgeBases",
            "bedrock:GetKnowledgeBase",
            "bedrock:ListEvaluationJobs",  # BR-18
            "bedrock:ListImportedModels",  # BR-30
            "bedrock:GetImportedModel",  # BR-30
            "bedrock:ListModelInvocationJobs",  # BR-31
            "servicequotas:ListServiceQuotas",  # BR-22
            "servicequotas:GetServiceQuota",  # BR-22
            "servicequotas:GetAWSDefaultServiceQuota",  # BR-22
            "cloudwatch:DescribeAlarms",
            "organizations:DescribeOrganization",  # BR-15
            "organizations:ListPolicies",  # BR-15
        },
    },
    {
        "path": os.path.join(_REPO_ROOT, "aiml-security-assessment", "template.yaml"),
        "start": "- Sid: S3BucketEncryptionPermissions",
        "end": "- Sid: CloudTrailPermissions",
        "required": {"s3:GetEncryptionConfiguration"},
    },
    {
        "path": os.path.join(
            _REPO_ROOT, "aiml-security-assessment", "template-multi-account.yaml"
        ),
        "start": "- Sid: BedrockAssessmentPermissions",
        "end": "- Sid: S3BucketEncryptionPermissions",
        "required": {
            "bedrock:GetModelInvocationLoggingConfiguration",
            "bedrock:ListKnowledgeBases",
            "bedrock:GetKnowledgeBase",
            "bedrock:ListEvaluationJobs",  # BR-18
            "bedrock:ListImportedModels",  # BR-30
            "bedrock:GetImportedModel",  # BR-30
            "bedrock:ListModelInvocationJobs",  # BR-31
            "servicequotas:ListServiceQuotas",  # BR-22
            "servicequotas:GetServiceQuota",  # BR-22
            "servicequotas:GetAWSDefaultServiceQuota",  # BR-22
            "cloudwatch:DescribeAlarms",
            "organizations:DescribeOrganization",  # BR-15
            "organizations:ListPolicies",  # BR-15
        },
    },
    {
        "path": os.path.join(
            _REPO_ROOT, "aiml-security-assessment", "template-multi-account.yaml"
        ),
        "start": "- Sid: S3BucketEncryptionPermissions",
        "end": "- Sid: CloudTrailPermissions",
        "required": {"s3:GetEncryptionConfiguration"},
    },
    {
        "path": os.path.join(
            _REPO_ROOT, "deployment", "aiml-security-single-account.yaml"
        ),
        "start": "# Bedrock Permissions",
        "end": "# SageMaker Permissions",
        "required": {
            "bedrock:GetModelInvocationLoggingConfiguration",
            "bedrock:ListKnowledgeBases",
            "bedrock:GetKnowledgeBase",
        },
    },
    {
        "path": os.path.join(
            _REPO_ROOT, "deployment", "aiml-security-single-account.yaml"
        ),
        "start": "# S3 Permissions for encryption checks",
        "end": 'Resource: "*"',
        "required": {"s3:GetEncryptionConfiguration"},
    },
    {
        "path": os.path.join(
            _REPO_ROOT, "deployment", "2-aiml-security-codebuild.yaml"
        ),
        "start": "# Bedrock Permissions",
        "end": "# SageMaker Permissions",
        "required": {
            "bedrock:GetModelInvocationLoggingConfiguration",
            "bedrock:ListKnowledgeBases",
            "bedrock:GetKnowledgeBase",
        },
    },
    {
        "path": os.path.join(
            _REPO_ROOT, "deployment", "2-aiml-security-codebuild.yaml"
        ),
        "start": "# S3 Permissions for encryption checks",
        "end": 'Resource: "*"',
        "required": {"s3:GetEncryptionConfiguration"},
    },
    {
        "path": os.path.join(
            _REPO_ROOT, "deployment", "1-aiml-security-member-roles.yaml"
        ),
        "start": "# Bedrock Agent Permissions (Agents for Amazon Bedrock)",
        "end": 'Resource: "*"',
        "required": {"bedrock:ListKnowledgeBases", "bedrock:GetKnowledgeBase"},
    },
    {
        "path": os.path.join(
            _REPO_ROOT, "deployment", "1-aiml-security-member-roles.yaml"
        ),
        "start": "# S3 Bucket Permissions for encryption checks",
        "end": 'Resource: "arn:aws:s3:::*"',
        "required": {"s3:GetEncryptionConfiguration"},
    },
]


def _load_section(path, start_marker, end_marker):
    with open(path, encoding="utf-8") as fh:
        text = fh.read()

    start = text.index(start_marker)
    end = text.index(end_marker, start)
    return text[start:end]


@pytest.mark.parametrize(
    "check",
    _SECTION_CHECKS,
    ids=lambda c: f"{os.path.basename(c['path'])}:{c['start']}",
)
def test_required_core_bedrock_actions_are_granted(check):
    section = _load_section(check["path"], check["start"], check["end"])
    missing = sorted(action for action in check["required"] if action not in section)
    assert not missing, (
        f"{os.path.basename(check['path'])} section starting at "
        f"'{check['start']}' is missing required IAM action(s): {missing}"
    )
