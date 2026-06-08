"""
Shared fixtures for AI/ML Security Assessment tests.

Provides mock permission caches, environment setup, and helper utilities
used across Bedrock, SageMaker, and AgentCore test modules.
"""

import pytest


# ---------------------------------------------------------------------------
# Environment variables required by Lambda functions
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def aws_env_vars(monkeypatch):
    """Set required AWS environment variables for all tests."""
    monkeypatch.setenv("AIML_ASSESSMENT_BUCKET_NAME", "test-assessment-bucket")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")


# ---------------------------------------------------------------------------
# Permission cache fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def empty_permission_cache():
    """Permission cache with no roles or users."""
    return {
        "role_permissions": {},
        "user_permissions": {},
    }


@pytest.fixture
def permission_cache_with_full_access():
    """Permission cache where a role has AmazonBedrockFullAccess."""
    return {
        "role_permissions": {
            "FullAccessRole": {
                "attached_policies": [
                    {
                        "name": "AmazonBedrockFullAccess",
                        "arn": "arn:aws:iam::aws:policy/AmazonBedrockFullAccess",
                        "document": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "bedrock:*",
                                    "Resource": "*",
                                }
                            ],
                        },
                    }
                ],
                "inline_policies": [],
                "permission_boundary": None,
            }
        },
        "user_permissions": {},
    }


@pytest.fixture
def permission_cache_compliant():
    """Permission cache with least-privilege policies (no full access)."""
    return {
        "role_permissions": {
            "LeastPrivilegeRole": {
                "attached_policies": [
                    {
                        "name": "CustomBedrockReadOnly",
                        "arn": "arn:aws:iam::123456789012:policy/CustomBedrockReadOnly",
                        "document": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "bedrock:InvokeModel",
                                        "bedrock:ListFoundationModels",
                                    ],
                                    "Resource": "arn:aws:bedrock:us-east-1::foundation-model/*",
                                }
                            ],
                        },
                    }
                ],
                "inline_policies": [],
                "permission_boundary": "arn:aws:iam::123456789012:policy/boundary",
            }
        },
        "user_permissions": {
            "RegularUser": {
                "attached_policies": [
                    {
                        "name": "CustomBedrockInvoke",
                        "arn": "arn:aws:iam::123456789012:policy/CustomBedrockInvoke",
                        "document": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "bedrock:InvokeModel",
                                    "Resource": "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v2",
                                }
                            ],
                        },
                    }
                ],
                "inline_policies": [],
            }
        },
    }


@pytest.fixture
def permission_cache_marketplace_overpermissive():
    """Permission cache with overly permissive marketplace subscription access."""
    return {
        "role_permissions": {
            "MarketplaceRole": {
                "attached_policies": [
                    {
                        "name": "MarketplaceFullAccess",
                        "arn": "arn:aws:iam::123456789012:policy/MarketplaceFullAccess",
                        "document": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "aws-marketplace:Subscribe",
                                    "Resource": "*",
                                }
                            ],
                        },
                    }
                ],
                "inline_policies": [],
            }
        },
        "user_permissions": {},
    }


@pytest.fixture
def permission_cache_with_guardrail_condition():
    """Permission cache with guardrail IAM condition keys."""
    return {
        "role_permissions": {
            "GuardrailEnforcedRole": {
                "attached_policies": [
                    {
                        "name": "BedrockWithGuardrail",
                        "arn": "arn:aws:iam::123456789012:policy/BedrockWithGuardrail",
                        "document": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "bedrock:InvokeModel",
                                        "bedrock:InvokeModelWithResponseStream",
                                    ],
                                    "Resource": "*",
                                    "Condition": {
                                        "StringEquals": {
                                            "bedrock:GuardrailIdentifier": "arn:aws:bedrock:us-east-1:123456789012:guardrail/abc123"
                                        }
                                    },
                                }
                            ],
                        },
                    }
                ],
                "inline_policies": [],
                "permission_boundary": None,
            }
        },
        "user_permissions": {},
    }


@pytest.fixture
def permission_cache_sagemaker_full_access():
    """Permission cache with SageMaker full access."""
    return {
        "role_permissions": {
            "SageMakerFullAccessRole": {
                "attached_policies": [
                    {
                        "name": "AmazonSageMakerFullAccess",
                        "arn": "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
                        "document": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "sagemaker:*",
                                    "Resource": "*",
                                }
                            ],
                        },
                    }
                ],
                "inline_policies": [],
            }
        },
        "user_permissions": {},
    }


@pytest.fixture
def permission_cache_agentcore_full_access():
    """Permission cache with AgentCore full access."""
    return {
        "role_permissions": {
            "AgentCoreFullAccessRole": {
                "attached_policies": [
                    {
                        "name": "AmazonBedrockAgentCoreFullAccess",
                        "arn": "arn:aws:iam::aws:policy/AmazonBedrockAgentCoreFullAccess",
                        "document": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "bedrock-agentcore:*",
                                    "Resource": "*",
                                }
                            ],
                        },
                    }
                ],
                "inline_policies": [],
            }
        },
        "user_permissions": {},
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def extract_csv_data(result):
    """Extract csv_data findings from a check function result.

    Works for both Bedrock/SageMaker style (dict with 'csv_data' key)
    and AgentCore style (returns list directly).
    """
    if isinstance(result, list):
        return result
    return result.get("csv_data", [])


def assert_finding_schema(finding):
    """Assert that a single finding dict has all required schema fields."""
    required_keys = {
        "Check_ID",
        "Finding",
        "Finding_Details",
        "Resolution",
        "Reference",
        "Severity",
        "Status",
    }
    assert required_keys.issubset(finding.keys()), (
        f"Missing keys: {required_keys - finding.keys()}"
    )
    assert finding["Severity"] in ("High", "Medium", "Low", "Informational")
    assert finding["Status"] in ("Failed", "Passed", "N/A")
    assert finding["Reference"].startswith("https://")
