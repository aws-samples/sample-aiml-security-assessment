"""Shared fixtures for FinServ assessment tests."""

import pytest


# ---------------------------------------------------------------------------
# Environment variables expected by the Lambda
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _set_env(monkeypatch):
    monkeypatch.setenv("AIML_ASSESSMENT_BUCKET_NAME", "test-bucket")


# ---------------------------------------------------------------------------
# A reusable permission_cache fixture
# ---------------------------------------------------------------------------
@pytest.fixture
def permission_cache_empty():
    return {"role_permissions": {}, "user_permissions": {}}


@pytest.fixture
def permission_cache_with_wildcard():
    """Permission cache where an agent role has iam:* — triggers FS-07 WARN."""
    return {
        "role_permissions": {
            "BedrockAgentRole": {
                "attached_policies": [
                    {
                        "document": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "iam:*",
                                    "Resource": "*",
                                }
                            ]
                        }
                    }
                ],
                "inline_policies": [],
            }
        },
        "user_permissions": {},
    }


@pytest.fixture
def permission_cache_safe():
    """Permission cache where agent role has narrow permissions — triggers FS-07 PASS."""
    return {
        "role_permissions": {
            "BedrockAgentRole": {
                "attached_policies": [
                    {
                        "document": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "bedrock:InvokeModel",
                                    "Resource": "arn:aws:bedrock:*:*:model/*",
                                }
                            ]
                        }
                    }
                ],
                "inline_policies": [],
            }
        },
        "user_permissions": {},
    }


# ---------------------------------------------------------------------------
# Synthetic Lambda event
# ---------------------------------------------------------------------------
@pytest.fixture
def lambda_event():
    return {
        "Execution": {"Name": "unit-test-001"},
        "StateMachine": {
            "Id": "arn:aws:states:us-east-1:123456789012:stateMachine:test"
        },
    }
