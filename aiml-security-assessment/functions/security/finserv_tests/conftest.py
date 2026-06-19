"""
Shared fixtures and mock helpers for finserv_assessments tests.

All boto3 clients are patched at the module level so check functions
never make real AWS API calls.
"""

import os
import sys

import pytest

# ---------------------------------------------------------------------------
# Make finserv_assessments importable — the Lambda runtime adds the package
# root to sys.path, so we replicate that here.
# ---------------------------------------------------------------------------
FINSERV_DIR = os.path.join(os.path.dirname(__file__), "..", "finserv_assessments")
if FINSERV_DIR not in sys.path:
    sys.path.insert(0, FINSERV_DIR)

import app  # noqa: E402  (imported after sys.path manipulation)


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


# ---------------------------------------------------------------------------
# ResourceInventory test builder (REQ-6.4, REQ-9.3)
# ---------------------------------------------------------------------------


def make_resource_inventory(**overrides) -> app.ResourceInventory:
    """Build a fully-available ``ResourceInventory`` with sensible empty defaults.

    Any field can be replaced via keyword arguments.  Pass an
    ``app._Unavailable(exc)`` value to simulate a per-inventory collection
    failure.

    Examples::

        inv = make_resource_inventory()                         # fully available
        inv = make_resource_inventory(lambda_functions=[...])  # real data
        inv = make_resource_inventory(
            guardrails=app._Unavailable(PermissionError("AccessDenied"))
        )                                                       # failed field
    """
    defaults: dict = dict(
        lambda_functions=[],
        guardrails=app.GuardrailInventory(summaries=[], detail_by_id={}),
        knowledge_bases=app.KbInventory(
            summaries=[], data_sources_by_kb={}, data_source_detail={}
        ),
        buckets=[],
        web_acls=app.WebAclInventory(summaries=[], detail_by_id={}),
    )
    defaults.update(overrides)
    return app.ResourceInventory(**defaults)
