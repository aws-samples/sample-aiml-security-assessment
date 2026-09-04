"""Guard the core Bedrock deployment roles against missing runtime IAM actions."""

import os

import pytest


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_INSPECTOR_ACTIONS = {"inspector2:BatchGetAccountStatus"}  # BR-33
_KMS_ACTIONS = {"kms:DescribeKey"}  # BR-40


_SECTION_CHECKS = [
    {
        "path": os.path.join(_REPO_ROOT, "aiml-security-assessment", "template.yaml"),
        "start": "- Sid: BedrockAccountInventoryPermissions",
        "end": "- Sid: S3BucketEncryptionPermissions",
        "required": {
            "bedrock:GetModelInvocationLoggingConfiguration",
            "bedrock:ListKnowledgeBases",
            "bedrock:GetKnowledgeBase",
            "bedrock:ListEvaluationJobs",  # BR-18
            "bedrock:ListImportedModels",  # BR-30
            "bedrock:GetImportedModel",  # BR-30
            "bedrock:ListModelInvocationJobs",  # BR-31
            "kms:DescribeKey",  # BR-40
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
        "start": "- Sid: BedrockAccountInventoryPermissions",
        "end": "- Sid: S3BucketEncryptionPermissions",
        "required": {
            "bedrock:GetModelInvocationLoggingConfiguration",
            "bedrock:ListKnowledgeBases",
            "bedrock:GetKnowledgeBase",
            "bedrock:ListEvaluationJobs",  # BR-18
            "bedrock:ListImportedModels",  # BR-30
            "bedrock:GetImportedModel",  # BR-30
            "bedrock:ListModelInvocationJobs",  # BR-31
            "kms:DescribeKey",  # BR-40
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
    # OWASP native checks (OW-11 / OW-12) run on the dedicated
    # OWASPSecurityAssessmentFunction. FinServ grants the same actions elsewhere
    # in the SAM templates, so a file-wide search would pass even if the OWASP
    # function's own grants were deleted (OW-11/OW-12 would then silently degrade
    # to AccessDenied -> N/A). Scope these assertions to the OWASP policy block.
    {
        "path": os.path.join(_REPO_ROOT, "aiml-security-assessment", "template.yaml"),
        "start": "- Sid: OWASPBedrockGuardrailList",
        "end": "AIMLAssessmentBucket",
        "required": {
            "bedrock:ListGuardrails",  # OW-12 (account-level list on Resource '*')
            "bedrock:GetGuardrail",  # OW-12
            "lambda:ListFunctions",  # OW-11
        },
    },
    {
        "path": os.path.join(
            _REPO_ROOT, "aiml-security-assessment", "template-multi-account.yaml"
        ),
        "start": "- Sid: OWASPBedrockGuardrailList",
        "end": "AIMLAssessmentBucket",
        "required": {
            "bedrock:ListGuardrails",  # OW-12 (account-level list on Resource '*')
            "bedrock:GetGuardrail",  # OW-12
            "lambda:ListFunctions",  # OW-11
        },
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


_ALL_POLICY_TEMPLATES = [
    os.path.join(_REPO_ROOT, "aiml-security-assessment", "template.yaml"),
    os.path.join(_REPO_ROOT, "aiml-security-assessment", "template-multi-account.yaml"),
]


@pytest.mark.parametrize(
    "template",
    _ALL_POLICY_TEMPLATES,
    ids=lambda p: os.path.basename(p),
)
def test_br40_kms_actions_granted(template):
    """BR-40 must classify each configured key through KMS in every runtime role."""
    with open(template, encoding="utf-8") as fh:
        text = fh.read()
    missing = sorted(action for action in _KMS_ACTIONS if action not in text)
    assert not missing, (
        f"{os.path.basename(template)} is missing required KMS IAM action(s): "
        f"{missing}. Grant them or BR-40 will surface as AccessDenied / N/A."
    )


@pytest.mark.parametrize(
    "template",
    _ALL_POLICY_TEMPLATES,
    ids=lambda p: os.path.basename(p),
)
def test_br33_inspector_actions_granted(template):
    """BR-33 (Amazon Inspector Lambda code scanning) requires inspector2:BatchGetAccountStatus
    in every policy location. A missing grant silently resolves to N/A + AccessDenied
    and the check disappears from the report."""
    with open(template, encoding="utf-8") as fh:
        text = fh.read()
    missing = sorted(action for action in _INSPECTOR_ACTIONS if action not in text)
    assert not missing, (
        f"{os.path.basename(template)} is missing required Inspector IAM action(s): "
        f"{missing}. Grant them or BR-33 will surface as AccessDenied / N/A."
    )
