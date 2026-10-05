"""Tests for the standalone AWS Agent Registry assessment Lambda."""

import csv
import importlib.util
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from io import StringIO
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError
import pytest

from tests.test_helpers import assert_finding_schema

_REGISTRY_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "aiml-security-assessment/functions/security/agent_registry_assessments",
    )
)
if _REGISTRY_DIR not in sys.path:
    sys.path.insert(0, _REGISTRY_DIR)

_SPEC = importlib.util.spec_from_file_location(
    "agent_registry_app", os.path.join(_REGISTRY_DIR, "app.py")
)
agent_registry_app = importlib.util.module_from_spec(_SPEC)
sys.modules["agent_registry_app"] = agent_registry_app
_SPEC.loader.exec_module(agent_registry_app)


@pytest.mark.parametrize(
    ("caller_identity", "expected_partition"),
    [
        ({"Arn": "arn:aws:sts::123456789012:assumed-role/test/session"}, "aws"),
        (
            {"Arn": "arn:aws-us-gov:sts::123456789012:assumed-role/test/session"},
            "aws-us-gov",
        ),
        ({}, "aws"),
        ({"Arn": ""}, "aws"),
        ({"Arn": None}, "aws"),
        ({"Arn": "not-an-arn"}, "aws"),
    ],
)
def test_caller_identity_partition_handles_incomplete_arns(
    caller_identity, expected_partition
):
    assert (
        agent_registry_app._caller_identity_partition(caller_identity)
        == expected_partition
    )


def _registry_inventory():
    return {
        "items": [],
        "errors": [],
        "list_error": None,
        "unavailable": False,
        "timed_out": False,
    }


def _record_inventory(registry_inventory=None):
    return {
        "items": [],
        "errors": [],
        "list_errors": [],
        "registry_inventory": registry_inventory or _registry_inventory(),
        "timed_out": False,
        "truncated": False,
    }


def _ready_registry_inventory(detail=None):
    inventory = _registry_inventory()
    inventory["items"] = [
        {
            "summary": {"registryId": "registry-123", "name": "inventory"},
            "detail": {
                "registryId": "registry-123",
                "name": "inventory",
                "status": "READY",
                **(detail or {}),
            },
        }
    ]
    return inventory


def _access_denied_registry_inventory():
    inventory = _registry_inventory()
    inventory["list_error"] = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
        "ListRegistries",
    )
    return inventory


def _registry_permission_cache():
    return {
        "role_permissions": {
            "registry-reader": {
                "attached_policies": [],
                "inline_policies": [
                    {
                        "document": {
                            "Version": "2012-10-17",
                            "Statement": {
                                "Effect": "Allow",
                                "Action": "agent-registry:*",
                                "Resource": "*",
                            },
                        }
                    }
                ],
            }
        },
        "user_permissions": {},
    }


def test_provenance_uses_botocore_source_id_shape():
    provenance = [
        {
            "relation": "DETECTED_FROM",
            "sourceId": (
                "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/runtime-123"
            ),
            "sourceType": "AWS::BedrockAgentCore::Runtime",
        }
    ]

    assert agent_registry_app._valid_provenance(provenance) is True


def test_provenance_rejects_missing_or_mismatched_source_id():
    assert (
        agent_registry_app._valid_provenance(
            [
                {
                    "relation": "DETECTED_FROM",
                    "sourceId": (
                        "arn:aws:bedrock-agentcore:us-east-1:123456789012:"
                        "gateway/gateway-123"
                    ),
                    "sourceType": "AWS::BedrockAgentCore::Runtime",
                }
            ]
        )
        is False
    )
    assert (
        agent_registry_app._valid_provenance(
            [
                {
                    "relation": "DETECTED_FROM",
                    "sourceId": (
                        "arn:aws:bedrock-agentcore:us-east-1:123456789012:"
                        "runtime/runtime-123"
                    ),
                }
            ]
        )
        is None
    )


def test_provenance_check_passes_for_correctly_provenanced_record():
    registry_inventory = _registry_inventory()
    registry_inventory["items"] = [
        {
            "summary": {"registryId": "registry-123", "name": "inventory"},
            "detail": {
                "registryId": "registry-123",
                "name": "inventory",
                "status": "READY",
            },
        }
    ]
    inventory = _record_inventory(registry_inventory)
    inventory["items"] = [
        {
            "detail": {
                "displayName": "inventory-runtime",
                "createdByAutoDetection": True,
                "provenanceSummaryList": [
                    {
                        "relation": "DETECTED_FROM",
                        "sourceId": (
                            "arn:aws:bedrock-agentcore:us-east-1:123456789012:"
                            "runtime/runtime-123"
                        ),
                        "sourceType": "AWS::BedrockAgentCore::Runtime",
                    }
                ],
            }
        }
    ]

    finding = agent_registry_app.check_agent_registry_record_provenance(inventory)[0]

    assert finding["Check_ID"] == "AR-08"
    assert finding["Status"] == "Passed"
    assert_finding_schema(finding)


def test_handler_uses_execution_name_for_cache_and_registry_csv_key():
    captured = {}

    def fake_write(execution_id, csv_content, region):
        captured["execution_id"] = execution_id
        captured["region"] = region
        return "s3://test-assessment-bucket/agent_registry_security_report_exec-123_us-east-1.csv"

    with (
        patch.object(agent_registry_app.boto3, "client", return_value=MagicMock()),
        patch.object(
            agent_registry_app,
            "_get_permissions_cache",
            return_value={"role_permissions": {}, "user_permissions": {}},
        ) as get_cache,
        patch.object(
            agent_registry_app, "check_agent_registry_stale_access", return_value=[]
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_inventory",
            return_value=_registry_inventory(),
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_record_inventory",
            return_value=_record_inventory(),
        ),
        patch.object(agent_registry_app, "generate_csv_report", return_value="csv"),
        patch.object(agent_registry_app, "write_to_s3", side_effect=fake_write),
    ):
        response = agent_registry_app.lambda_handler(
            {
                "Execution": {"Name": "exec-123"},
                "Region": "us-east-1",
                "RegionIndex": 0,
            },
            None,
        )

    assert response["statusCode"] == 200
    get_cache.assert_called_once_with("exec-123")
    assert captured == {"execution_id": "exec-123", "region": "us-east-1"}


def test_registry_inventory_access_denied_is_indeterminate():
    client = MagicMock()
    client.get_paginator.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
        "ListRegistries",
    )

    with patch.object(agent_registry_app, "agent_registry_control_client", client):
        inventory = agent_registry_app.get_agent_registry_inventory()

    finding = agent_registry_app.check_agent_registry_approval_governance(inventory)[0]
    assert finding["Check_ID"] == "AR-03"
    assert finding["Status"] == "N/A"
    assert "agent-registry:ListRegistries" in finding["Resolution"]


def test_agentic_registry_mapping_uses_ar_source_ids():
    findings = agent_registry_app.build_agentic_agent_registry_findings(
        [
            {
                "Check_ID": "AR-08",
                "Finding_Details": "Provenance is valid.",
                "Severity": "Medium",
                "Status": "Passed",
                "Region": "us-east-1",
            }
        ]
    )

    assert len(findings) == 1
    assert findings[0]["Check_ID"] == "AG-38"
    assert findings[0]["Status"] == "Passed"
    assert_finding_schema(findings[0])


def test_single_statement_policy_is_evaluated_for_registry_wildcards():
    findings = agent_registry_app.check_agent_registry_full_access(
        _registry_permission_cache()
    )

    assert any(finding["Status"] == "Failed" for finding in findings)
    assert "registry-reader" in findings[0]["Finding_Details"]


def test_ar01_passes_for_scoped_permissions_and_is_na_without_cached_roles():
    scoped_cache = _registry_permission_cache()
    scoped_cache["role_permissions"]["registry-reader"]["inline_policies"][0][
        "document"
    ]["Statement"]["Action"] = "agent-registry:GetRegistry"
    scoped_cache["role_permissions"]["registry-reader"]["inline_policies"][0][
        "document"
    ]["Statement"][
        "Resource"
    ] = "arn:aws:agent-registry:us-east-1:123456789012:registry/registry-123"

    assert (
        agent_registry_app.check_agent_registry_full_access(scoped_cache)[0]["Status"]
        == "Passed"
    )
    assert (
        agent_registry_app.check_agent_registry_full_access(
            {"role_permissions": {}, "user_permissions": {}}
        )[0]["Status"]
        == "N/A"
    )


def _ar01_two_role_cache(statement):
    """A scoped reader beside one role holding ``statement``."""
    cache = _registry_permission_cache()
    scoped = cache["role_permissions"]["registry-reader"]["inline_policies"][0][
        "document"
    ]["Statement"]
    scoped["Action"] = "agent-registry:GetRegistry"
    scoped["Resource"] = (
        "arn:aws:agent-registry:us-east-1:123456789012:registry/abcdef123456"
    )
    cache["role_permissions"]["registry-browser"] = {
        "attached_policies": [],
        "inline_policies": [
            {"document": {"Version": "2012-10-17", "Statement": statement}}
        ],
    }
    cache["principal_errors"] = []
    return cache


@pytest.mark.parametrize(
    "scope",
    [
        {"Resource": "arn:aws:agent-registry:*:*:*"},
        {"Resource": "arn:aws:agent-registry:us-east-1:123456789012:registry/*"},
        {"Resource": "arn:aws:agent-registry:us-east-1:*:registry/abcdef123456"},
        {"Resource": "arn:aws:agent-registry:us-east-1:123456789012:registry/ab??*"},
        {
            "Resource": [
                "arn:aws:agent-registry:us-east-1:123456789012:registry/abcdef123456",
                "arn:aws:agent-registry:*:123456789012:registry/*",
            ]
        },
        {
            "NotResource": (
                "arn:aws:agent-registry:us-east-1:123456789012:registry/abcdef123456"
            )
        },
    ],
)
def test_ar01_a_wildcard_grant_on_a_partial_wildcard_resource_is_not_bounded(scope):
    findings = agent_registry_app.check_agent_registry_full_access(
        _ar01_two_role_cache(
            {"Effect": "Allow", "Action": "agent-registry:Get*", **scope}
        )
    )

    assert [(f["Finding"], f["Status"]) for f in findings] == [
        ("AWS Agent Registry IAM Wildcard Permissions", "Failed")
    ]
    assert "registry-browser" in findings[0]["Finding_Details"]
    assert "registry-reader" not in findings[0]["Finding_Details"]
    assert "a wildcard in any segment" in findings[0]["Finding_Details"]


@pytest.mark.parametrize(
    "statement",
    [
        {
            "Effect": "Allow",
            "Action": "agent-registry:Get*",
            "Resource": (
                "arn:aws:agent-registry:us-east-1:123456789012:registry/abcdef123456"
            ),
        },
        {
            "Effect": "Allow",
            "Action": "agent-registry:GetRegistry",
            "Resource": "arn:aws:agent-registry:*:*:*",
        },
    ],
)
def test_ar01_a_named_resource_or_an_explicit_action_stays_passed(statement):
    findings = agent_registry_app.check_agent_registry_full_access(
        _ar01_two_role_cache(statement)
    )

    assert [f["Status"] for f in findings] == ["Passed"]
    assert (
        "a resource ARN with a wildcard in any segment"
        in (findings[0]["Finding_Details"])
    )


def test_ar01_reports_permission_cache_access_denied_as_indeterminate():
    captured = {}

    def fake_write(_execution_id, csv_content, _region):
        captured["csv"] = csv_content
        return "s3://test-assessment-bucket/report.csv"

    with (
        patch.object(agent_registry_app.boto3, "client", return_value=MagicMock()),
        patch.object(
            agent_registry_app,
            "_get_permissions_cache",
            side_effect=ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
                "GetObject",
            ),
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_inventory",
            return_value=_registry_inventory(),
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_record_inventory",
            return_value=_record_inventory(),
        ),
        patch.object(agent_registry_app, "write_to_s3", side_effect=fake_write),
    ):
        response = agent_registry_app.lambda_handler(
            {"Execution": {"Name": "exec-123"}, "Region": "us-east-1"},
            None,
        )

    assert response["statusCode"] == 200
    assert "AR-01" in captured["csv"]
    assert "IAM permission cache" in captured["csv"]


def test_ar04_matrix_covers_constrained_unconstrained_empty_and_access_denied():
    constrained = _ready_registry_inventory(
        {
            "discoveryConfiguration": {
                "authorizerType": "CUSTOM_JWT",
                "authorizerConfiguration": {
                    "customJWTAuthorizer": {
                        "discoveryUrl": "https://issuer.example.com/.well-known/openid-configuration",
                        "allowedAudience": ["registry-consumer"],
                    }
                },
            }
        }
    )
    unconstrained = _ready_registry_inventory(
        {
            "discoveryConfiguration": {
                "authorizerType": "CUSTOM_JWT",
                "authorizerConfiguration": {"customJWTAuthorizer": {}},
            }
        }
    )

    assert (
        agent_registry_app.check_agent_registry_discovery_authorization(constrained)[0][
            "Status"
        ]
        == "N/A"
    )
    assert (
        agent_registry_app.check_agent_registry_discovery_authorization(unconstrained)[
            0
        ]["Status"]
        == "Failed"
    )
    assert (
        agent_registry_app.check_agent_registry_discovery_authorization(
            _registry_inventory()
        )[0]["Status"]
        == "N/A"
    )
    assert (
        agent_registry_app.check_agent_registry_discovery_authorization(
            _access_denied_registry_inventory()
        )[0]["Status"]
        == "N/A"
    )


def test_ar05_matrix_covers_cmk_default_empty_and_access_denied(monkeypatch):
    encrypted = _ready_registry_inventory(
        {
            "encryptionConfiguration": {
                "kmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/key-123"
            }
        }
    )
    default_key = _ready_registry_inventory({"encryptionConfiguration": {}})
    monkeypatch.setenv("REQUIRE_AGENT_REGISTRY_CMK", "true")

    assert (
        agent_registry_app.check_agent_registry_cmk_encryption(encrypted)[0]["Status"]
        == "Passed"
    )
    assert (
        agent_registry_app.check_agent_registry_cmk_encryption(default_key)[0]["Status"]
        == "Failed"
    )
    assert (
        agent_registry_app.check_agent_registry_cmk_encryption(_registry_inventory())[
            0
        ]["Status"]
        == "N/A"
    )
    assert (
        agent_registry_app.check_agent_registry_cmk_encryption(
            _access_denied_registry_inventory()
        )[0]["Status"]
        == "N/A"
    )


def test_ar06_matrix_covers_active_advisory_empty_and_access_denied():
    active = _ready_registry_inventory(
        {
            "autoDetection": {
                "configuration": {"enabled": True, "scope": "ORGANIZATION"},
                "status": "ACTIVE",
            }
        }
    )
    disabled = _ready_registry_inventory(
        {
            "autoDetection": {
                "configuration": {"enabled": False, "scope": "ACCOUNT"},
                "status": "INACTIVE",
            }
        }
    )

    assert (
        agent_registry_app.check_agent_registry_auto_detection(active)[0]["Status"]
        == "Passed"
    )
    assert (
        agent_registry_app.check_agent_registry_auto_detection(disabled)[0]["Status"]
        == "N/A"
    )
    assert (
        agent_registry_app.check_agent_registry_auto_detection(_registry_inventory())[
            0
        ]["Status"]
        == "N/A"
    )
    assert (
        agent_registry_app.check_agent_registry_auto_detection(
            _access_denied_registry_inventory()
        )[0]["Status"]
        == "N/A"
    )


def test_ar07_matrix_covers_record_observation_empty_and_access_denied():
    registry_inventory = _ready_registry_inventory()
    observed = _record_inventory(registry_inventory)
    observed["items"] = [
        {
            "detail": {
                "displayName": "approved-record",
                "status": "APPROVED",
            }
        }
    ]
    denied = _record_inventory(registry_inventory)
    denied["list_errors"] = [
        (
            registry_inventory["items"][0],
            ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
                "ListRegistryRecords",
            ),
        )
    ]

    assert (
        agent_registry_app.check_agent_registry_record_lifecycle(observed)[0]["Status"]
        == "N/A"
    )
    assert (
        agent_registry_app.check_agent_registry_record_lifecycle(
            _record_inventory(registry_inventory)
        )[0]["Status"]
        == "N/A"
    )
    assert (
        agent_registry_app.check_agent_registry_record_lifecycle(denied)[0]["Status"]
        == "N/A"
    )


def test_stale_access_uses_service_last_accessed_data():
    iam = MagicMock()
    iam.generate_service_last_accessed_details.return_value = {"JobId": "job-123"}
    iam.get_service_last_accessed_details.return_value = {
        "JobStatus": "COMPLETED",
        "ServicesLastAccessed": [
            {
                "ServiceNamespace": "agent-registry",
                "LastAuthenticated": datetime.now(timezone.utc) - timedelta(days=61),
            }
        ],
    }
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012"}

    with (
        patch.object(agent_registry_app.boto3, "client", return_value=sts),
        patch.object(agent_registry_app, "iam_client", iam),
    ):
        findings = agent_registry_app.check_agent_registry_stale_access(
            _registry_permission_cache()
        )

    assert iam.generate_service_last_accessed_details.called
    assert any(finding["Status"] == "Failed" for finding in findings)
    assert "61 days" in findings[-1]["Finding_Details"]


def test_stale_access_sts_error_does_not_recommend_an_iam_grant():
    sts = MagicMock()
    sts.get_caller_identity.side_effect = ClientError(
        {"Error": {"Code": "InvalidClientTokenId", "Message": "Invalid token"}},
        "GetCallerIdentity",
    )

    with (
        patch.object(agent_registry_app.boto3, "client", return_value=sts),
        patch.object(agent_registry_app, "iam_client", MagicMock()),
    ):
        finding = agent_registry_app.check_agent_registry_stale_access(
            _registry_permission_cache()
        )[0]

    assert finding["Status"] == "N/A"
    assert "does not require an IAM Allow permission" in finding["Resolution"]
    assert "Grant sts:GetCallerIdentity" not in finding["Resolution"]


def test_provenance_missing_origin_mode_is_indeterminate():
    registry_inventory = _ready_registry_inventory()
    inventory = _record_inventory(registry_inventory)
    inventory["items"] = [{"detail": {"displayName": "record-123"}}]

    finding = agent_registry_app.check_agent_registry_record_provenance(inventory)[0]

    assert finding["Status"] == "N/A"
    assert "origin-mode metadata" in finding["Finding_Details"]


def test_provenance_reports_record_listing_errors_when_no_records_are_returned():
    registry_inventory = _ready_registry_inventory()
    inventory = _record_inventory(registry_inventory)
    inventory["list_errors"] = [
        (
            registry_inventory["items"][0],
            ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
                "ListRegistryRecords",
            ),
        )
    ]

    findings = agent_registry_app.check_agent_registry_record_provenance(inventory)

    assert len(findings) == 1
    assert findings[0]["Check_ID"] == "AR-08"
    assert findings[0]["Status"] == "N/A"
    assert "ListRegistryRecords" in findings[0]["Resolution"]


def test_record_truncation_keeps_collected_records_and_adds_incomplete_notice():
    registry_inventory = _ready_registry_inventory()
    inventory = _record_inventory(registry_inventory)
    inventory["truncated"] = True
    inventory["items"] = [
        {
            "detail": {
                "displayName": "manual-record",
                "createdByAutoDetection": False,
                "createdBy": "123456789012",
            }
        }
    ]

    findings = agent_registry_app.check_agent_registry_record_provenance(inventory)

    assert {finding["Status"] for finding in findings} == {"N/A", "Passed"}
    assert any("safety limit" in finding["Finding_Details"] for finding in findings)


def test_unknown_discovery_authorizer_is_not_labeled_as_custom_jwt():
    findings = agent_registry_app.check_agent_registry_discovery_authorization(
        _ready_registry_inventory(
            {"discoveryConfiguration": {"authorizerType": "FUTURE_AUTHORIZER"}}
        )
    )

    assert findings[0]["Status"] == "N/A"
    assert "unsupported discovery authorizer type" in findings[0]["Finding_Details"]
    assert "custom JWT" not in findings[0]["Finding_Details"]


def test_missing_auto_detection_metadata_is_indeterminate_not_absent():
    findings = agent_registry_app.check_agent_registry_auto_detection(
        _ready_registry_inventory()
    )

    assert findings[0]["Status"] == "N/A"
    assert (
        "did not return optional auto-detection metadata"
        in findings[0]["Finding_Details"]
    )


def test_handler_isolates_check_failure_and_writes_csv():
    captured = {}

    def fake_write(_execution_id, csv_content, _region):
        captured["csv"] = csv_content
        return "s3://test-assessment-bucket/agent_registry_security_report_exec-123_us-east-1.csv"

    with (
        patch.object(agent_registry_app.boto3, "client", return_value=MagicMock()),
        patch.object(
            agent_registry_app,
            "_get_permissions_cache",
            return_value={"role_permissions": {}, "user_permissions": {}},
        ),
        patch.object(
            agent_registry_app, "check_agent_registry_full_access", return_value=[]
        ),
        patch.object(
            agent_registry_app, "check_agent_registry_stale_access", return_value=[]
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_inventory",
            return_value=_registry_inventory(),
        ),
        patch.object(
            agent_registry_app,
            "check_agent_registry_approval_governance",
            side_effect=RuntimeError("boom"),
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_record_inventory",
            return_value=_record_inventory(),
        ),
        patch.object(agent_registry_app, "write_to_s3", side_effect=fake_write),
    ):
        response = agent_registry_app.lambda_handler(
            {"Execution": {"Name": "exec-123"}, "Region": "us-east-1"},
            None,
        )

    assert response["statusCode"] == 200
    assert "AR-03" in captured["csv"]
    assert "Publication Approval Governance Incomplete" in captured["csv"]


def test_handler_reraises_unrecoverable_csv_write_failures():
    with (
        patch.object(agent_registry_app.boto3, "client", return_value=MagicMock()),
        patch.object(
            agent_registry_app,
            "_get_permissions_cache",
            return_value={"role_permissions": {}, "user_permissions": {}},
        ),
        patch.object(
            agent_registry_app, "check_agent_registry_full_access", return_value=[]
        ),
        patch.object(
            agent_registry_app, "check_agent_registry_stale_access", return_value=[]
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_inventory",
            return_value=_registry_inventory(),
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_record_inventory",
            return_value=_record_inventory(),
        ),
        patch.object(
            agent_registry_app,
            "write_to_s3",
            side_effect=RuntimeError("S3 unavailable"),
        ),
    ):
        with pytest.raises(RuntimeError, match="S3 unavailable"):
            agent_registry_app.lambda_handler(
                {"Execution": {"Name": "exec-123"}, "Region": "us-east-1"},
                None,
            )


def test_handler_does_not_fetch_records_after_registry_inventory_timeout():
    inventory = _ready_registry_inventory()
    inventory["timed_out"] = True

    with (
        patch.object(agent_registry_app.boto3, "client", return_value=MagicMock()),
        patch.object(
            agent_registry_app,
            "get_agent_registry_inventory",
            return_value=inventory,
        ),
        patch.object(
            agent_registry_app, "get_agent_registry_record_inventory"
        ) as record_inventory,
        patch.object(
            agent_registry_app,
            "write_to_s3",
            return_value="s3://test-assessment-bucket/report.csv",
        ),
    ):
        response = agent_registry_app.lambda_handler(
            {
                "Execution": {"Name": "exec-123"},
                "Region": "us-east-1",
                "RegionIndex": 1,
            },
            None,
        )

    assert response["statusCode"] == 200
    record_inventory.assert_not_called()


# ===================================================================
# AR-09: check_agent_registry_approval_separation
# ===================================================================
_SEPARATION_FINDING = "AWS Agent Registry Approval Authority Separation"
_REGISTRY_NAMESPACES = ("agent-registry", "bedrock-agentcore")
_PUBLISH_ACTIONS = (
    "CreateRegistryRecord",
    "UpdateRegistryRecord",
    "SubmitRegistryRecordForApproval",
)
_APPROVAL_ACTION = "UpdateRegistryRecordStatus"


def _allow(actions, resource="*"):
    return {"Effect": "Allow", "Action": actions, "Resource": resource}


def _deny(actions, resource="*", **extra):
    return {"Effect": "Deny", "Action": actions, "Resource": resource, **extra}


def _principal(inline=None, attached=None):
    def _policy(name, statements):
        return {
            "name": name,
            "document": {"Version": "2012-10-17", "Statement": statements},
        }

    return {
        "attached_policies": [_policy("attached", attached)] if attached else [],
        "inline_policies": [_policy("inline", inline)] if inline else [],
    }


def _separation_cache(statements, principal_kind="role", principal_name="publisher"):
    """A permission cache holding one principal with one inline policy."""
    cache = {"role_permissions": {}, "user_permissions": {}}
    cache[f"{principal_kind}_permissions"] = {
        principal_name: _principal(inline=statements)
    }
    return cache


def _separation_finding(cache):
    findings = agent_registry_app.check_agent_registry_approval_separation(cache)
    assert len(findings) == 1
    assert findings[0]["Check_ID"] == "AR-09"
    assert findings[0]["Finding"].startswith(_SEPARATION_FINDING)
    assert_finding_schema(findings[0])
    return findings[0]


def _listed_publish_actions(finding):
    """The publish actions the finding names for its one reported principal."""
    return finding["Finding_Details"].rsplit("(", 1)[-1].rstrip(")").split(", ")


@pytest.mark.parametrize("namespace", _REGISTRY_NAMESPACES)
@pytest.mark.parametrize("publish_action", _PUBLISH_ACTIONS)
def test_ar09_reports_each_publish_action_held_beside_approval(
    namespace, publish_action
):
    finding = _separation_finding(
        _separation_cache(
            [
                _allow(
                    [
                        f"{namespace}:{publish_action}",
                        f"{namespace}:{_APPROVAL_ACTION}",
                    ]
                )
            ]
        )
    )

    assert finding["Status"] == "Failed"
    assert finding["Severity"] == "High"
    assert "role 'publisher'" in finding["Finding_Details"]
    assert _listed_publish_actions(finding) == [f"{namespace}:{publish_action}"]


@pytest.mark.parametrize(
    "actions",
    [
        pytest.param(
            ["agent-registry:CreateRegistryRecord"], id="publish-without-approval"
        ),
        pytest.param(
            [f"agent-registry:{_APPROVAL_ACTION}"], id="approval-without-publish"
        ),
        pytest.param(
            ["agent-registry:GetRegistryRecord", "agent-registry:ListRegistryRecords"],
            id="reads-only",
        ),
        pytest.param(
            [
                "agent-registry:DeleteRegistryRecord",
                f"agent-registry:{_APPROVAL_ACTION}",
            ],
            id="delete-is-not-a-publish-authority",
        ),
    ],
)
def test_ar09_passes_a_principal_holding_one_authority(actions):
    finding = _separation_finding(_separation_cache([_allow(actions)]))

    assert finding["Status"] == "Passed"
    assert finding["Severity"] == "High"
    assert "1 cached IAM identities" in finding["Finding_Details"]


def test_ar09_reads_a_collision_that_spans_the_two_namespaces():
    """The preview namespace grants the same two authorities as the new one."""
    finding = _separation_finding(
        _separation_cache(
            [
                _allow(
                    [
                        "agent-registry:CreateRegistryRecord",
                        f"bedrock-agentcore:{_APPROVAL_ACTION}",
                    ]
                )
            ]
        )
    )

    assert finding["Status"] == "Failed"
    assert _listed_publish_actions(finding) == ["agent-registry:CreateRegistryRecord"]


def test_ar09_reads_a_wildcard_pattern_as_every_authority_it_reaches():
    finding = _separation_finding(
        _separation_cache([_allow(["agent-registry:*RegistryRecord*"])])
    )

    assert finding["Status"] == "Failed"
    assert _listed_publish_actions(finding) == sorted(
        f"agent-registry:{action}" for action in _PUBLISH_ACTIONS
    )


@pytest.mark.parametrize(
    "actions",
    [
        pytest.param(["*"], id="bare-wildcard"),
        pytest.param(["*:*"], id="wildcard-service"),
    ],
)
def test_ar09_reports_a_service_agnostic_grant(actions):
    """A bare `*` or `*:*` grants publication and approval alike, so the
    administrator it names is the publisher and curator of the same record."""
    finding = _separation_finding(_separation_cache([_allow(actions)]))

    assert finding["Status"] == "Failed"
    assert "role 'publisher'" in finding["Finding_Details"]
    assert _listed_publish_actions(finding) == sorted(
        f"{namespace}:{action}"
        for namespace in _REGISTRY_NAMESPACES
        for action in _PUBLISH_ACTIONS
    )


def _colliding_statements(*extra):
    return [
        _allow(
            [
                f"{namespace}:{action}"
                for namespace in _REGISTRY_NAMESPACES
                for action in ("CreateRegistryRecord", _APPROVAL_ACTION)
            ]
        ),
        *extra,
    ]


@pytest.mark.parametrize(
    "deny",
    [
        pytest.param(
            _deny([f"{ns}:{_APPROVAL_ACTION}" for ns in _REGISTRY_NAMESPACES]),
            id="both-namespaces-named",
        ),
        pytest.param(
            _deny(["agent-registry:*", "bedrock-agentcore:*"]), id="namespaces"
        ),
        pytest.param(_deny(["*"]), id="service-agnostic"),
        pytest.param(
            {"Effect": "Deny", "NotAction": ["s3:*"], "Resource": "*"},
            id="not-action-spares-nothing-registry",
        ),
    ],
)
def test_ar09_an_account_wide_deny_excuses_the_principal(deny):
    finding = _separation_finding(_separation_cache(_colliding_statements(deny)))

    assert finding["Status"] == "Passed"


@pytest.mark.parametrize(
    "deny",
    [
        pytest.param(
            _deny([f"agent-registry:{_APPROVAL_ACTION}"]), id="one-namespace-only"
        ),
        pytest.param(
            _deny(
                [f"{ns}:{_APPROVAL_ACTION}" for ns in _REGISTRY_NAMESPACES],
                resource="arn:aws:agent-registry:us-east-1:123456789012:registry/abc",
            ),
            id="scoped-to-one-registry",
        ),
        pytest.param(
            _deny(
                [f"{ns}:{_APPROVAL_ACTION}" for ns in _REGISTRY_NAMESPACES],
                Condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
            ),
            id="conditioned",
        ),
        pytest.param(
            {
                "Effect": "Deny",
                "NotAction": ["agent-registry:*", "bedrock-agentcore:*"],
                "Resource": "*",
            },
            id="not-action-spares-both-namespaces",
        ),
    ],
)
def test_ar09_a_narrower_deny_does_not_excuse_the_principal(deny):
    finding = _separation_finding(_separation_cache(_colliding_statements(deny)))

    assert finding["Status"] == "Failed"


def test_ar09_reads_a_deny_from_a_different_policy_document():
    cache = {
        "role_permissions": {
            "publisher": _principal(
                inline=[_allow([f"agent-registry:{_APPROVAL_ACTION}"])],
                attached=[
                    _deny([f"{ns}:{_APPROVAL_ACTION}" for ns in _REGISTRY_NAMESPACES]),
                    _allow(["agent-registry:CreateRegistryRecord"]),
                ],
            )
        },
        "user_permissions": {},
    }

    assert _separation_finding(cache)["Status"] == "Passed"


def test_ar09_reads_a_collision_that_spans_attached_and_inline_policies():
    cache = {
        "role_permissions": {
            "publisher": _principal(
                inline=[_allow(["agent-registry:SubmitRegistryRecordForApproval"])],
                attached=[_allow([f"agent-registry:{_APPROVAL_ACTION}"])],
            )
        },
        "user_permissions": {},
    }
    finding = _separation_finding(cache)

    assert finding["Status"] == "Failed"
    assert _listed_publish_actions(finding) == [
        "agent-registry:SubmitRegistryRecordForApproval"
    ]


def test_ar09_judges_every_principal_not_only_the_first():
    cache = {
        "role_permissions": {
            "reader": _principal(inline=[_allow(["agent-registry:GetRegistryRecord"])]),
            "self-approver": _principal(
                inline=[
                    _allow(
                        [
                            "agent-registry:UpdateRegistryRecord",
                            f"agent-registry:{_APPROVAL_ACTION}",
                        ]
                    )
                ]
            ),
        },
        "user_permissions": {},
    }
    finding = _separation_finding(cache)

    assert finding["Status"] == "Failed"
    assert "role 'self-approver'" in finding["Finding_Details"]
    assert "reader" not in finding["Finding_Details"]


def test_ar09_judges_iam_users_beside_roles():
    cache = _separation_cache(
        [
            _allow(
                [
                    "agent-registry:CreateRegistryRecord",
                    f"agent-registry:{_APPROVAL_ACTION}",
                ]
            )
        ],
        principal_kind="user",
        principal_name="ci-publisher",
    )
    finding = _separation_finding(cache)

    assert finding["Status"] == "Failed"
    assert "user 'ci-publisher'" in finding["Finding_Details"]


def test_ar09_passes_when_the_publisher_and_the_curator_are_separate_principals():
    cache = {
        "role_permissions": {
            "publisher": _principal(
                inline=[
                    _allow(
                        [
                            "agent-registry:CreateRegistryRecord",
                            "agent-registry:SubmitRegistryRecordForApproval",
                        ]
                    )
                ]
            ),
            "curator": _principal(
                inline=[_allow([f"agent-registry:{_APPROVAL_ACTION}"])]
            ),
        },
        "user_permissions": {"auditor": _principal()},
    }
    finding = _separation_finding(cache)

    assert finding["Status"] == "Passed"
    assert "3 cached IAM identities" in finding["Finding_Details"]


def test_ar09_is_indeterminate_without_a_cached_principal():
    finding = _separation_finding({"role_permissions": {}, "user_permissions": {}})

    assert finding["Status"] == "N/A"
    assert finding["Severity"] == "Informational"


def test_ar09_watches_both_namespace_spellings_of_every_authority():
    allowed, denied = agent_registry_app._registry_authority_actions(
        _principal(inline=[_allow([f"{ns}:*" for ns in _REGISTRY_NAMESPACES])])
    )

    assert allowed == {
        f"{namespace}:{action}"
        for namespace in _REGISTRY_NAMESPACES
        for action in (*_PUBLISH_ACTIONS, _APPROVAL_ACTION)
    }
    assert denied == set()
    assert agent_registry_app.REGISTRY_IAM_NAMESPACES == _REGISTRY_NAMESPACES
    assert agent_registry_app.REGISTRY_PUBLISH_ACTIONS == _PUBLISH_ACTIONS
    assert agent_registry_app.REGISTRY_APPROVAL_ACTION == _APPROVAL_ACTION


def test_ar09_authorities_are_the_modelled_registry_record_operations():
    """The two authorities are named after real control-plane operations."""
    model = agent_registry_app.boto3.client(
        "agent-registry-control",
        region_name="us-east-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
    ).meta.service_model
    operations = set(model.operation_names)

    assert set(_PUBLISH_ACTIONS) | {_APPROVAL_ACTION} <= operations
    # Backward leg: no other modelled operation can set a record's status, so the
    # approval authority really is this one action.
    assert {
        name
        for name in operations
        if "status" in (model.operation_model(name).input_shape.members or {})
    } == {_APPROVAL_ACTION}
    # Backward leg: the publish set is every record write except the two that do
    # not put content into the approval workflow.
    record_operations = {
        name
        for name in operations
        if name.endswith("RegistryRecord") or name == "SubmitRegistryRecordForApproval"
    }
    assert record_operations - {"GetRegistryRecord", "DeleteRegistryRecord"} == set(
        _PUBLISH_ACTIONS
    )
    # APPROVED is the status that makes a record discoverable, which is what makes
    # holding the approval action beside a record write a self-approval path.
    assert (
        "APPROVED"
        in model.operation_model(_APPROVAL_ACTION).input_shape.members["status"].enum
    )


def test_handler_emits_ar09_as_a_global_row():
    captured = {}

    def fake_write(_execution_id, csv_content, _region):
        captured["csv"] = csv_content
        return "s3://test-assessment-bucket/report.csv"

    cache = _separation_cache(
        [
            _allow(
                [
                    "agent-registry:CreateRegistryRecord",
                    f"agent-registry:{_APPROVAL_ACTION}",
                ]
            )
        ]
    )
    with (
        patch.object(agent_registry_app.boto3, "client", return_value=MagicMock()),
        patch.object(agent_registry_app, "_get_permissions_cache", return_value=cache),
        patch.object(
            agent_registry_app, "check_agent_registry_stale_access", return_value=[]
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_inventory",
            return_value=_registry_inventory(),
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_record_inventory",
            return_value=_record_inventory(),
        ),
        patch.object(agent_registry_app, "write_to_s3", side_effect=fake_write),
    ):
        response = agent_registry_app.lambda_handler(
            {"Execution": {"Name": "exec-123"}, "Region": "us-east-1"},
            None,
        )

    assert response["statusCode"] == 200
    rows = [
        row
        for row in csv.DictReader(StringIO(captured["csv"]))
        if row["Check_ID"] == "AR-09"
    ]
    assert [(row["Status"], row["Region"]) for row in rows] == [("Failed", "Global")]


def test_ar09_reports_a_permission_cache_failure_as_indeterminate():
    captured = {}

    def fake_write(_execution_id, csv_content, _region):
        captured["csv"] = csv_content
        return "s3://test-assessment-bucket/report.csv"

    with (
        patch.object(agent_registry_app.boto3, "client", return_value=MagicMock()),
        patch.object(
            agent_registry_app,
            "_get_permissions_cache",
            side_effect=ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
                "GetObject",
            ),
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_inventory",
            return_value=_registry_inventory(),
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_record_inventory",
            return_value=_record_inventory(),
        ),
        patch.object(agent_registry_app, "write_to_s3", side_effect=fake_write),
    ):
        response = agent_registry_app.lambda_handler(
            {"Execution": {"Name": "exec-123"}, "Region": "us-east-1"},
            None,
        )

    assert response["statusCode"] == 200
    rows = [
        row
        for row in csv.DictReader(StringIO(captured["csv"]))
        if row["Check_ID"] == "AR-09"
    ]
    assert [(row["Status"], row["Region"]) for row in rows] == [("N/A", "Global")]
    assert "IAM permission cache" in rows[0]["Finding_Details"]


# ===================================================================
# AR-10: AIR-ACR-REG-02, registry lifecycle events are actually routed
# ===================================================================
def _rule(name, pattern=None, state="ENABLED", bus="default"):
    rule = {
        "Name": name,
        "Arn": f"arn:aws:events:us-east-1:123456789012:rule/{bus}/{name}",
        "State": state,
        "EventBusName": bus,
    }
    if pattern is not None:
        rule["EventPattern"] = (
            pattern if isinstance(pattern, str) else json.dumps(pattern)
        )
    return rule


def _approval_pattern(source=None, detail_types=None):
    pattern = {"source": source or [agent_registry_app.REGISTRY_EVENT_SOURCE]}
    if detail_types is not None:
        pattern["detail-type"] = detail_types
    return pattern


def _events_client(
    rules,
    targets=None,
    list_error=None,
    target_errors=None,
    bus_rules=None,
    target_arns=None,
    bus_list_errors=None,
):
    """An EventBridge client over ListRules and ListTargetsByRule.

    `rules` are the default bus's rules and `bus_rules` those of other buses in
    the account. `targets` gives a rule a count of SNS targets; `target_arns`
    gives it an explicit target ARN list instead.
    """
    client = MagicMock()
    targets = targets or {}
    target_errors = target_errors or {}
    bus_rules = bus_rules or {}
    target_arns = target_arns or {}
    bus_list_errors = bus_list_errors or {}
    client.target_calls = []
    client.rule_calls = []

    def get_paginator(operation_name):
        paginator = MagicMock()
        if operation_name == "list_rules":

            def paginate_rules(**kwargs):
                if list_error is not None:
                    raise list_error
                assert list(kwargs) == ["EventBusName"]
                bus = kwargs["EventBusName"]
                client.rule_calls.append(bus)
                if bus == "default":
                    return [{"Rules": rules}]
                if bus in bus_list_errors:
                    raise bus_list_errors[bus]
                assert bus in bus_rules, f"unexpected ListRules on bus {bus}"
                return [{"Rules": bus_rules[bus]}]

            paginator.paginate.side_effect = paginate_rules
        elif operation_name == "list_targets_by_rule":

            def paginate_targets(Rule, EventBusName):
                client.target_calls.append(Rule)
                if Rule in target_errors:
                    raise target_errors[Rule]
                if Rule in target_arns:
                    return [
                        {
                            "Targets": [
                                {"Id": f"target-{index}", "Arn": arn}
                                for index, arn in enumerate(target_arns[Rule])
                            ]
                        }
                    ]
                count = targets.get(Rule, 0)
                return [
                    {
                        "Targets": [
                            {
                                "Id": f"target-{index}",
                                "Arn": f"arn:aws:sns:us-east-1:123456789012:t{index}",
                            }
                            for index in range(count)
                        ]
                    }
                ]

            paginator.paginate.side_effect = paginate_targets
        else:
            raise AssertionError(f"unexpected events paginator: {operation_name}")
        return paginator

    client.get_paginator.side_effect = get_paginator
    return client


def _routing_findings(rules, inventory=None, **client_kwargs):
    client = _events_client(rules, **client_kwargs)
    with patch.object(agent_registry_app, "events_client", client):
        rule_inventory = agent_registry_app.get_registry_event_rule_inventory()
    findings = agent_registry_app.check_agent_registry_lifecycle_event_routing(
        inventory if inventory is not None else _ready_registry_inventory(),
        rule_inventory,
    )
    for finding in findings:
        assert finding["Check_ID"] == "AR-10"
        assert_finding_schema(finding)
    return findings, client


def test_ar10_routed_approval_events_pass_and_name_the_rule():
    findings, client = _routing_findings(
        [
            _rule(
                "registry-approvals",
                _approval_pattern(
                    detail_types=list(agent_registry_app.REGISTRY_APPROVAL_DETAIL_TYPES)
                ),
            )
        ],
        targets={"registry-approvals": 1},
    )
    assert [f["Status"] for f in findings] == ["Passed"]
    assert "registry-approvals" in findings[0]["Finding_Details"]
    assert "1 target(s)" in findings[0]["Finding_Details"]
    assert "'inventory'" in findings[0]["Finding_Details"]
    assert client.target_calls == ["registry-approvals"]


def test_ar10_rule_with_no_detail_type_filter_matches_every_transition():
    # An absent event-pattern field matches every value, so a rule filtered on
    # source alone routes all three approval transitions.
    findings, _ = _routing_findings(
        [_rule("all-registry-events", _approval_pattern())],
        targets={"all-registry-events": 2},
    )
    assert [f["Status"] for f in findings] == ["Passed"]
    assert "2 target(s)" in findings[0]["Finding_Details"]


def test_ar10_rule_with_no_source_filter_matches_the_registry_source():
    findings, _ = _routing_findings(
        [
            _rule(
                "catch-all",
                {"detail-type": ["Registry Record State changed to Approved"]},
            )
        ],
        targets={"catch-all": 1},
    )
    statuses = [f["Status"] for f in findings]
    assert statuses == ["Failed"]
    # It reaches the source but only one of the three approval transitions.
    assert (
        "Registry Record State changed to Pending Approval"
        in (findings[0]["Finding_Details"])
    )
    assert "catch-all" in findings[0]["Finding_Details"]


def test_ar10_matching_rule_with_zero_targets_is_failed_twice_over():
    findings, _ = _routing_findings(
        [_rule("discarding-rule", _approval_pattern())],
        targets={"discarding-rule": 0},
    )
    assert [f["Status"] for f in findings] == ["Failed", "Failed"]
    assert "has no targets" in findings[0]["Finding_Details"]
    assert "discarding-rule" in findings[0]["Finding_Details"]
    assert "route none of them to a target" in findings[1]["Finding_Details"]


def test_ar10_no_rules_at_all_is_failed_and_says_how_many_were_examined():
    findings, client = _routing_findings([])
    assert [f["Status"] for f in findings] == ["Failed"]
    assert "None of the 0 rule(s)" in findings[0]["Finding_Details"]
    assert client.target_calls == []


def test_ar10_unrelated_rules_are_counted_but_not_queried_for_targets():
    findings, client = _routing_findings(
        [
            _rule("s3-events", {"source": ["aws.s3"]}),
            _rule("ec2-events", {"source": "aws.ec2"}),
            _rule("scheduled", None),
        ]
    )
    assert [f["Status"] for f in findings] == ["Failed"]
    assert "None of the 3 rule(s)" in findings[0]["Finding_Details"]
    assert client.target_calls == []


def test_ar10_preview_only_source_is_reported_not_accepted_as_coverage():
    findings, _ = _routing_findings(
        [
            _rule(
                "preview-rule",
                _approval_pattern(
                    source=[agent_registry_app.REGISTRY_PREVIEW_EVENT_SOURCE]
                ),
            )
        ],
        targets={"preview-rule": 3},
    )
    assert [f["Status"] for f in findings] == ["Failed", "Failed"]
    assert (
        agent_registry_app.REGISTRY_PREVIEW_EVENT_SOURCE
        in findings[0]["Finding_Details"]
    )
    assert (
        agent_registry_app.REGISTRY_PREVIEW_EVENT_SOURCE_END
        in findings[0]["Finding_Details"]
    )
    assert "route none of them to a target" in findings[1]["Finding_Details"]


def test_ar10_preview_source_rule_for_other_agentcore_events_is_not_a_registry_rule():
    # aws.bedrock-agentcore also carries events that are not Registry
    # approvals; a rule filtered to those is not a Registry rule going stale.
    findings, client = _routing_findings(
        [
            _rule(
                "runtime-events",
                _approval_pattern(
                    source=[agent_registry_app.REGISTRY_PREVIEW_EVENT_SOURCE],
                    detail_types=["AgentCore Runtime Endpoint Status Change"],
                ),
            )
        ],
        targets={"runtime-events": 1},
    )
    assert [f["Status"] for f in findings] == ["Failed"]
    assert "None of the 1 rule(s)" in findings[0]["Finding_Details"]
    assert (
        agent_registry_app.REGISTRY_PREVIEW_EVENT_SOURCE_END
        not in (findings[0]["Finding_Details"])
    )
    assert client.target_calls == []


def test_ar10_preview_source_rule_naming_an_approval_type_is_still_stale():
    findings, _ = _routing_findings(
        [
            _rule(
                "preview-approvals",
                _approval_pattern(
                    source=[agent_registry_app.REGISTRY_PREVIEW_EVENT_SOURCE],
                    detail_types=[
                        "AgentCore Runtime Endpoint Status Change",
                        agent_registry_app.REGISTRY_APPROVAL_DETAIL_TYPES[0],
                    ],
                ),
            )
        ],
        targets={"preview-approvals": 1},
    )
    assert [f["Status"] for f in findings] == ["Failed", "Failed"]
    assert (
        agent_registry_app.REGISTRY_PREVIEW_EVENT_SOURCE_END
        in findings[0]["Finding_Details"]
    )


@pytest.mark.parametrize(
    "narrowing",
    [
        {"detail": {"registryId": ["reg-one"]}},
        {"resources": ["arn:aws:bedrock-agentcore:us-east-1:123456789012:registry/r1"]},
        {"account": ["111122223333"]},
        {"region": ["eu-west-1"]},
        {"region": [{"prefix": "eu-"}]},
        {"time": [{"prefix": "2026-"}]},
        {"id": ["00000000-0000-0000-0000-000000000000"]},
    ],
)
def test_ar10_a_rule_narrowed_beyond_source_and_detail_type_is_not_full_coverage(
    narrowing,
):
    # Any field beyond source and detail-type passes only the matching events,
    # so the rule cannot be credited with every approval transition unless the
    # field provably matches every event of the rule's own account and Region.
    pattern = _approval_pattern()
    pattern.update(narrowing)
    field = next(iter(narrowing))
    findings, _ = _routing_findings(
        [_rule("filtered-approvals", pattern)],
        targets={"filtered-approvals": 2},
    )
    assert [f["Status"] for f in findings] == ["N/A", "Failed"]
    assert "filtered-approvals" in findings[0]["Finding_Details"]
    assert f"'{field}'" in findings[0]["Finding_Details"]
    assert "route none of them to a target" in findings[1]["Finding_Details"]


@pytest.mark.parametrize(
    "own_scope",
    [
        {"region": ["us-east-1"]},
        {"region": ["eu-west-1", "us-east-1"]},
        {"account": ["123456789012"]},
        {"account": [{"prefix": "1234"}], "region": [{"prefix": "us-"}]},
    ],
    ids=["own-region", "own-region-in-list", "own-account", "own-both-by-prefix"],
)
def test_ar10_a_field_matching_the_rules_own_account_and_region_does_not_narrow(
    own_scope,
):
    # The rule's ARN names us-east-1 and 123456789012, and every Registry event
    # of that account and Region carries those values, so these filters drop
    # none of the events the check judges.
    pattern = _approval_pattern()
    pattern.update(own_scope)
    findings, _ = _routing_findings(
        [_rule("own-scope", pattern)], targets={"own-scope": 1}
    )
    assert [f["Status"] for f in findings] == ["Passed"]


def test_ar10_rule_listing_both_sources_counts_as_ga_coverage():
    findings, _ = _routing_findings(
        [
            _rule(
                "both-sources",
                _approval_pattern(
                    source=[
                        agent_registry_app.REGISTRY_PREVIEW_EVENT_SOURCE,
                        agent_registry_app.REGISTRY_EVENT_SOURCE,
                    ]
                ),
            )
        ],
        targets={"both-sources": 1},
    )
    assert [f["Status"] for f in findings] == ["Passed"]


def test_ar10_disabled_rule_routes_nothing():
    findings, _ = _routing_findings(
        [_rule("paused-rule", _approval_pattern(), state="DISABLED")],
        targets={"paused-rule": 1},
    )
    assert [f["Status"] for f in findings] == ["Failed", "Failed"]
    assert "is DISABLED" in findings[0]["Finding_Details"]


def test_ar10_cloudtrail_management_state_still_counts_as_enabled():
    findings, _ = _routing_findings(
        [
            _rule(
                "audited-rule",
                _approval_pattern(),
                state="ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS",
            )
        ],
        targets={"audited-rule": 1},
    )
    assert [f["Status"] for f in findings] == ["Passed"]


def test_ar10_two_rules_together_cover_the_approval_transitions():
    approval_types = list(agent_registry_app.REGISTRY_APPROVAL_DETAIL_TYPES)
    findings, _ = _routing_findings(
        [
            _rule("pending-rule", _approval_pattern(detail_types=approval_types[:1])),
            _rule("decision-rule", _approval_pattern(detail_types=approval_types[1:])),
        ],
        targets={"pending-rule": 1, "decision-rule": 1},
    )
    assert [f["Status"] for f in findings] == ["Passed"]
    assert "pending-rule" in findings[0]["Finding_Details"]
    assert "decision-rule" in findings[0]["Finding_Details"]


def test_ar10_partial_detail_type_coverage_names_the_missing_transitions():
    approval_types = list(agent_registry_app.REGISTRY_APPROVAL_DETAIL_TYPES)
    findings, _ = _routing_findings(
        [_rule("pending-only", _approval_pattern(detail_types=approval_types[:1]))],
        targets={"pending-only": 1},
    )
    assert [f["Status"] for f in findings] == ["Failed"]
    for detail_type in approval_types[1:]:
        assert detail_type in findings[0]["Finding_Details"]
    assert "pending-only" in findings[0]["Finding_Details"]


@pytest.mark.parametrize(
    ("pattern", "reason"),
    [
        ("{not json", "not valid JSON"),
        ("[]", "not a JSON object"),
        (
            {
                "$or": [
                    {"source": [agent_registry_app.REGISTRY_EVENT_SOURCE]},
                    {"detail-type": ["Other"]},
                ]
            },
            "$or",
        ),
        # Matcher shapes the check does not evaluate stand in for any matcher
        # EventBridge adds later.
        (
            {"source": [{"prefix": "aws.", "suffix": "-registry"}]},
            "which event sources",
        ),
        ({"source": []}, "which event sources"),
        (
            {
                "source": [agent_registry_app.REGISTRY_EVENT_SOURCE],
                "detail-type": [{"regex": "Registry Record State.*"}],
            },
            "which detail types",
        ),
    ],
)
def test_ar10_a_pattern_this_check_cannot_decide_is_indeterminate(pattern, reason):
    # The rule may route every approval transition, so no Failed follows its N/A.
    findings, client = _routing_findings([_rule("opaque-rule", pattern)])
    assert [f["Status"] for f in findings] == ["N/A"]
    assert "opaque-rule" in findings[0]["Finding_Details"]
    assert reason in findings[0]["Finding_Details"]
    assert client.target_calls == []


@pytest.mark.parametrize(
    "pattern",
    [
        {"source": [{"prefix": "aws.agent-"}]},
        {"source": [{"prefix": {"equals-ignore-case": "AWS.AGENT"}}]},
        {"source": [{"suffix": "-registry"}]},
        {"source": [{"equals-ignore-case": "AWS.Agent-Registry"}]},
        {"source": [{"wildcard": "aws.*-reg*"}]},
        {"source": [{"anything-but": ["aws.s3", "aws.ec2"]}]},
        {"source": [{"anything-but": {"prefix": "aws.s"}}]},
        {"source": [{"exists": True}]},
        {"source": ["aws.s3", {"prefix": "aws.agent"}]},
        {
            "source": [agent_registry_app.REGISTRY_EVENT_SOURCE],
            "detail-type": [{"prefix": "Registry Record State"}],
        },
        {
            "source": [agent_registry_app.REGISTRY_EVENT_SOURCE],
            "detail-type": [{"wildcard": "Registry Record State changed to *"}],
        },
        {
            "source": [agent_registry_app.REGISTRY_EVENT_SOURCE],
            "detail-type": [
                {"anything-but": {"prefix": "Registry Record State changed to D"}}
            ],
        },
    ],
)
def test_ar10_a_content_matcher_reaching_the_approval_events_is_credited(pattern):
    findings, client = _routing_findings(
        [_rule("matcher-rule", pattern)], targets={"matcher-rule": 1}
    )
    assert [f["Status"] for f in findings] == ["Passed"]
    assert "'matcher-rule' (1 target(s))" in findings[0]["Finding_Details"]
    assert client.target_calls == ["matcher-rule"]


@pytest.mark.parametrize(
    "pattern",
    [
        {"source": [{"prefix": "aws.s3"}]},
        {"source": [{"suffix": ".ec2"}]},
        # Wildcard matching is case-sensitive.
        {"source": [{"wildcard": "AWS.*"}]},
        {"source": [{"wildcard": "aws.agent\\*"}]},
        {
            "source": [
                {
                    "anything-but": [
                        agent_registry_app.REGISTRY_EVENT_SOURCE,
                        agent_registry_app.REGISTRY_PREVIEW_EVENT_SOURCE,
                    ]
                }
            ]
        },
        {"source": [{"anything-but": {"prefix": "aws."}}]},
        {"source": [{"exists": False}]},
        {"source": [{"numeric": [">", 0]}]},
        {"source": [5, {"prefix": "aws.s3"}]},
    ],
)
def test_ar10_a_content_matcher_missing_the_registry_source_is_another_rule(
    pattern,
):
    # The rule cannot receive Registry events, so it is counted, its targets
    # are not read, and it neither earns an N/A row nor holds back the Failed.
    findings, client = _routing_findings(
        [_rule("s3-prefix", pattern)], targets={"s3-prefix": 1}
    )
    assert [f["Status"] for f in findings] == ["Failed"]
    assert "None of the 1 rule(s)" in findings[0]["Finding_Details"]
    assert client.target_calls == []


def test_ar10_a_detail_type_matcher_is_credited_only_with_what_it_matches():
    approval_types = list(agent_registry_app.REGISTRY_APPROVAL_DETAIL_TYPES)
    findings, _ = _routing_findings(
        [
            _rule(
                "approved-only",
                _approval_pattern(detail_types=[{"suffix": "to Approved"}]),
            ),
            _rule(
                "rejected-only",
                _approval_pattern(
                    detail_types=[{"equals-ignore-case": approval_types[2].upper()}]
                ),
            ),
        ],
        targets={"approved-only": 1, "rejected-only": 1},
    )
    assert [f["Status"] for f in findings] == ["Failed"]
    assert f"detail type(s) {approval_types[0]}, so" in findings[0]["Finding_Details"]
    assert "'approved-only'" in findings[0]["Finding_Details"]
    assert "'rejected-only'" in findings[0]["Finding_Details"]


def test_ar10_a_literal_ga_source_beside_an_unknown_matcher_is_still_credited():
    # The unknown element could only add the preview source, which does not
    # change the kind of a rule that already matches the GA source.
    findings, _ = _routing_findings(
        [
            _rule(
                "ga-plus-unknown",
                {
                    "source": [
                        agent_registry_app.REGISTRY_EVENT_SOURCE,
                        {"regex": "aws\\..*"},
                    ]
                },
            )
        ],
        targets={"ga-plus-unknown": 1},
    )
    assert [f["Status"] for f in findings] == ["Passed"]


def test_ar10_an_unreadable_rule_holds_back_the_failed_a_clean_miss_would_earn():
    approval_types = list(agent_registry_app.REGISTRY_APPROVAL_DETAIL_TYPES)
    findings, _ = _routing_findings(
        [
            _rule("pending-only", _approval_pattern(detail_types=approval_types[:1])),
            _rule("opaque-rule", {"$or": [{"source": ["aws.agent-registry"]}]}),
            _rule("s3-events", {"source": ["aws.s3"]}),
        ],
        targets={"pending-only": 1},
    )
    assert [f["Status"] for f in findings] == ["N/A"]
    assert "opaque-rule" in findings[0]["Finding_Details"]


def test_ar10_an_unreadable_rule_does_not_hold_back_a_proven_pass():
    findings, _ = _routing_findings(
        [
            _rule("opaque-rule", {"$or": [{"source": ["aws.agent-registry"]}]}),
            _rule("all-registry-events", _approval_pattern()),
        ],
        targets={"all-registry-events": 1},
    )
    assert [f["Status"] for f in findings] == ["N/A", "Passed"]
    assert "all-registry-events" in findings[1]["Finding_Details"]


def test_ar10_wildcard_matching_does_not_backtrack():
    wildcard = agent_registry_app._wildcard_matches
    assert wildcard("aws.*-registry", "aws.agent-registry")
    assert wildcard("*", "")
    assert wildcard("a\\*b", "a*b")
    assert not wildcard("a\\*b", "axb")
    assert not wildcard("*registry*agent", "aws.agent-registry")
    # Segments must not overlap the fixed head and tail.
    assert not wildcard("ab*ba", "aba")
    started = time.monotonic()
    assert not wildcard("a*" * 40 + "b", "a" * 200)
    assert time.monotonic() - started < 1


def test_ar10_target_listing_failure_is_indeterminate_for_that_rule():
    denied = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
        "ListTargetsByRule",
    )
    findings, _ = _routing_findings(
        [
            _rule("unreadable-rule", _approval_pattern()),
            _rule("good-rule", _approval_pattern()),
        ],
        targets={"good-rule": 1},
        target_errors={"unreadable-rule": denied},
    )
    assert [f["Status"] for f in findings] == ["N/A", "Passed"]
    assert "unreadable-rule" in findings[0]["Finding_Details"]
    assert "events:ListTargetsByRule" in findings[0]["Resolution"]
    assert "good-rule" in findings[1]["Finding_Details"]


_TARGETS_DENIED = ClientError(
    {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
    "ListTargetsByRule",
)


def test_ar10_unread_targets_hold_back_only_the_transitions_that_rule_matches():
    # The unread rule matches Pending Approval only, so the other two
    # transitions, which no rule matches, are still Failed.
    approval_types = list(agent_registry_app.REGISTRY_APPROVAL_DETAIL_TYPES)
    findings, _ = _routing_findings(
        [
            _rule(
                "unreadable-rule", _approval_pattern(detail_types=approval_types[:1])
            ),
            _rule("s3-events", {"source": ["aws.s3"]}),
        ],
        target_errors={"unreadable-rule": _TARGETS_DENIED},
    )
    assert [f["Status"] for f in findings] == ["N/A", "Failed"]
    assert findings[0]["Finding"].endswith("Incomplete")
    for detail_type in approval_types[1:]:
        assert detail_type in findings[1]["Finding_Details"]
    assert f"{approval_types[0]}," not in findings[1]["Finding_Details"]


def test_ar10_unread_targets_on_a_full_rule_are_not_failed():
    findings, _ = _routing_findings(
        [_rule("unreadable-rule", _approval_pattern())],
        target_errors={"unreadable-rule": _TARGETS_DENIED},
    )
    assert [f["Status"] for f in findings] == ["N/A"]
    assert findings[0]["Finding"].endswith("Incomplete")


@pytest.mark.parametrize(
    ("pattern", "state"),
    [
        ({**_approval_pattern(), "detail": {"registryId": ["r1"]}}, "ENABLED"),
        (_approval_pattern(), "DISABLED"),
        (_approval_pattern(source=["aws.bedrock-agentcore"]), "ENABLED"),
    ],
    ids=["narrowed", "disabled", "preview"],
)
def test_ar10_unread_targets_on_a_rule_that_cannot_be_credited_keep_the_failed(
    pattern, state
):
    # Reading those targets could not credit the rule, so the Failed stands.
    findings, _ = _routing_findings(
        [_rule("unreadable-rule", pattern, state=state)],
        target_errors={"unreadable-rule": _TARGETS_DENIED},
    )
    assert [f["Status"] for f in findings] == ["N/A", "Failed"]
    assert findings[0]["Finding"].endswith("Incomplete")


def test_ar10_rule_listing_access_denied_is_indeterminate():
    findings, _ = _routing_findings(
        [],
        list_error=ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
            "ListRules",
        ),
    )
    assert [f["Status"] for f in findings] == ["N/A"]
    assert "events:ListRules" in findings[0]["Resolution"]


def test_ar10_eventbridge_unavailable_in_region_is_indeterminate():
    findings, _ = _routing_findings(
        [],
        list_error=ClientError(
            {"Error": {"Code": "UnrecognizedClientException", "Message": "no"}},
            "ListRules",
        ),
    )
    assert [f["Status"] for f in findings] == ["N/A"]
    assert "not available in this region" in findings[0]["Finding_Details"]


def test_ar10_missing_events_client_is_indeterminate():
    with patch.object(agent_registry_app, "events_client", None):
        rule_inventory = agent_registry_app.get_registry_event_rule_inventory()
    findings = agent_registry_app.check_agent_registry_lifecycle_event_routing(
        _ready_registry_inventory(), rule_inventory
    )
    assert [f["Status"] for f in findings] == ["N/A"]
    assert "EventBridge client" in findings[0]["Finding_Details"]


def test_ar10_timeout_during_the_rule_sweep_is_indeterminate():
    client = _events_client([_rule("late-rule", _approval_pattern())])
    with patch.object(agent_registry_app, "events_client", client):
        with patch.object(agent_registry_app, "check_timeout", return_value=False):
            rule_inventory = agent_registry_app.get_registry_event_rule_inventory()
    findings = agent_registry_app.check_agent_registry_lifecycle_event_routing(
        _ready_registry_inventory(), rule_inventory
    )
    assert [f["Status"] for f in findings] == ["N/A"]
    assert "Lambda timeout" in findings[0]["Finding_Details"]
    assert client.target_calls == []


def test_ar10_matrix_covers_no_registries_and_registry_access_denied():
    no_registries, _ = _routing_findings(
        [_rule("registry-approvals", _approval_pattern())],
        inventory=_registry_inventory(),
        targets={"registry-approvals": 1},
    )
    denied, _ = _routing_findings(
        [_rule("registry-approvals", _approval_pattern())],
        inventory=_access_denied_registry_inventory(),
        targets={"registry-approvals": 1},
    )
    assert [f["Status"] for f in no_registries] == ["N/A"]
    assert (
        "No AWS Agent Registry registries found"
        in (no_registries[0]["Finding_Details"])
    )
    assert [f["Status"] for f in denied] == ["N/A"]


def test_ar10_names_every_registry_the_verdict_covers():
    inventory = _registry_inventory()
    inventory["items"] = [
        {
            "summary": {"registryId": f"registry-{index}", "name": f"registry-{index}"},
            "detail": {
                "registryId": f"registry-{index}",
                "name": f"reg-{index}",
                "status": "READY",
            },
        }
        for index in range(2)
    ]
    findings, _ = _routing_findings(
        [_rule("registry-approvals", _approval_pattern())],
        inventory=inventory,
        targets={"registry-approvals": 1},
    )
    assert [f["Status"] for f in findings] == ["Passed"]
    assert "registries 'reg-0', 'reg-1'" in findings[0]["Finding_Details"]


_SNS_TARGET = "arn:aws:sns:us-east-1:123456789012:registry-review"
_AUDIT_BUS = "arn:aws:events:us-east-1:123456789012:event-bus/audit-bus"


def _forward(name="forward-to-audit", bus_arn=_AUDIT_BUS, detail_types=None):
    """A default-bus rule matching Registry events whose only target is a bus."""
    return (
        _rule(name, _approval_pattern(detail_types=detail_types)),
        {name: [bus_arn]},
    )


def test_ar10_a_rule_forwarding_to_a_local_bus_is_credited_by_that_bus_rule():
    # AWS services deliver to the default bus, so the rule on audit-bus sees the
    # Registry events only because forward-to-audit sends them there. The
    # unrelated rule on audit-bus has a target too, and must not be the one
    # credited.
    forward, arns = _forward()
    findings, client = _routing_findings(
        [forward],
        target_arns={
            **arns,
            "audit-s3": [_SNS_TARGET],
            "audit-approvals": [_SNS_TARGET],
        },
        bus_rules={
            "audit-bus": [
                _rule("audit-s3", {"source": ["aws.s3"]}, bus="audit-bus"),
                _rule("audit-approvals", _approval_pattern(), bus="audit-bus"),
            ]
        },
    )
    assert [f["Status"] for f in findings] == ["Passed"]
    details = findings[0]["Finding_Details"]
    assert (
        "'forward-to-audit' via event bus 'audit-bus' rule 'audit-approvals' "
        "(1 target(s))" in details
    )
    assert "audit-s3" not in details
    assert client.rule_calls == ["default", "audit-bus"]
    assert client.target_calls == ["forward-to-audit", "audit-approvals"]


def test_ar10_a_forward_to_a_bus_with_no_delivering_rule_is_failed():
    # Both audit-bus rules match; one has no target and the other only sends the
    # events back to the default bus. Neither delivers, and the second is not
    # followed, so a bus-to-bus cycle stops after one hop.
    forward, arns = _forward()
    default_bus = "arn:aws:events:us-east-1:123456789012:event-bus/default"
    findings, client = _routing_findings(
        [forward],
        target_arns={**arns, "audit-empty": [], "audit-loop": [default_bus]},
        bus_rules={
            "audit-bus": [
                _rule("audit-empty", _approval_pattern(), bus="audit-bus"),
                _rule("audit-loop", _approval_pattern(), bus="audit-bus"),
            ]
        },
    )
    assert [f["Status"] for f in findings] == ["Failed", "Failed"]
    assert "forward-to-audit" in findings[0]["Finding_Details"]
    assert "only to event bus 'audit-bus'" in findings[0]["Finding_Details"]
    assert "route none of them to a target" in findings[1]["Finding_Details"]
    assert client.rule_calls == ["default", "audit-bus"]


def test_ar10_a_disabled_rule_on_the_forwarded_bus_delivers_nothing():
    forward, arns = _forward()
    findings, _ = _routing_findings(
        [forward],
        target_arns={**arns, "audit-paused": [_SNS_TARGET]},
        bus_rules={
            "audit-bus": [
                _rule(
                    "audit-paused",
                    _approval_pattern(),
                    state="DISABLED",
                    bus="audit-bus",
                )
            ]
        },
    )
    assert [f["Status"] for f in findings] == ["Failed", "Failed"]


@pytest.mark.parametrize(
    "bus_arn",
    [
        "arn:aws:events:us-east-1:111122223333:event-bus/central-audit",
        "arn:aws:events:eu-west-1:123456789012:event-bus/audit-bus",
    ],
    ids=["cross-account", "cross-region"],
)
def test_ar10_a_forward_to_a_bus_this_check_cannot_read_is_indeterminate(bus_arn):
    forward, arns = _forward(bus_arn=bus_arn)
    findings, client = _routing_findings([forward], target_arns=arns)
    assert [f["Status"] for f in findings] == ["N/A"]
    assert bus_arn in findings[0]["Finding_Details"]
    assert "another account or Region" in findings[0]["Finding_Details"]
    assert client.rule_calls == ["default"]


def test_ar10_an_unreadable_forward_leaves_only_its_own_transitions_open():
    # The remote forward carries Pending Approval only, so the local rule's
    # missing Approved and Rejected transitions are still reported as missing.
    approval_types = list(agent_registry_app.REGISTRY_APPROVAL_DETAIL_TYPES)
    forward, arns = _forward(
        bus_arn="arn:aws:events:us-east-1:111122223333:event-bus/central-audit",
        detail_types=approval_types[:1],
    )
    findings, _ = _routing_findings([forward], target_arns=arns)
    assert [f["Status"] for f in findings] == ["N/A", "Failed"]
    for detail_type in approval_types[1:]:
        assert detail_type in findings[1]["Finding_Details"]
    assert approval_types[0] not in findings[1]["Finding_Details"]


def test_ar10_local_routing_plus_an_unreadable_forward_is_not_passed():
    approval_types = list(agent_registry_app.REGISTRY_APPROVAL_DETAIL_TYPES)
    forward, arns = _forward(
        bus_arn="arn:aws:events:us-east-1:111122223333:event-bus/central-audit",
        detail_types=approval_types[:1],
    )
    findings, _ = _routing_findings(
        [
            forward,
            _rule("decisions", _approval_pattern(detail_types=approval_types[1:])),
        ],
        target_arns={**arns, "decisions": [_SNS_TARGET]},
    )
    assert [f["Status"] for f in findings] == ["N/A"]


def test_ar10_a_forwarded_rule_is_credited_only_with_both_hops_detail_types():
    approval_types = list(agent_registry_app.REGISTRY_APPROVAL_DETAIL_TYPES)
    forward, arns = _forward(detail_types=approval_types[:1])
    findings, _ = _routing_findings(
        [forward],
        target_arns={**arns, "audit-approvals": [_SNS_TARGET]},
        bus_rules={
            "audit-bus": [
                _rule("audit-approvals", _approval_pattern(), bus="audit-bus")
            ]
        },
    )
    assert [f["Status"] for f in findings] == ["Failed"]
    for detail_type in approval_types[1:]:
        assert detail_type in findings[0]["Finding_Details"]
    assert "via event bus 'audit-bus'" in findings[0]["Finding_Details"]


def test_ar10_a_rule_with_a_bus_and_a_delivering_target_is_not_followed():
    findings, client = _routing_findings(
        [_rule("mixed-targets", _approval_pattern())],
        target_arns={"mixed-targets": [_AUDIT_BUS, _SNS_TARGET]},
    )
    assert [f["Status"] for f in findings] == ["Passed"]
    # Only the review-pipeline target is counted, not the event bus.
    assert "'mixed-targets' (1 target(s))" in findings[0]["Finding_Details"]
    assert client.rule_calls == ["default"]


def test_ar10_two_forwards_to_one_bus_list_that_bus_once():
    first, first_arns = _forward("forward-one")
    second, second_arns = _forward("forward-two")
    findings, client = _routing_findings(
        [first, second],
        target_arns={
            **first_arns,
            **second_arns,
            "audit-approvals": [_SNS_TARGET],
        },
        bus_rules={
            "audit-bus": [
                _rule("audit-approvals", _approval_pattern(), bus="audit-bus")
            ]
        },
    )
    assert [f["Status"] for f in findings] == ["Passed"]
    assert "'forward-one' via event bus" in findings[0]["Finding_Details"]
    assert "'forward-two' via event bus" in findings[0]["Finding_Details"]
    assert client.rule_calls == ["default", "audit-bus"]


@pytest.mark.parametrize(
    ("audit_rule", "statuses"),
    [
        (
            _rule(
                "audit-opaque",
                {"source": [{"prefix": "aws.", "suffix": "-registry"}]},
                bus="audit-bus",
            ),
            ["N/A"],
        ),
        (
            _rule(
                "audit-opaque",
                {
                    "source": [agent_registry_app.REGISTRY_EVENT_SOURCE],
                    "detail": {"registryId": ["reg-one"]},
                },
                bus="audit-bus",
            ),
            ["N/A", "Failed"],
        ),
    ],
    ids=["content-filter", "narrowed"],
)
def test_ar10_a_forwarded_bus_rule_this_check_cannot_decide_is_indeterminate(
    audit_rule, statuses
):
    # An unreadable pattern may deliver every forwarded transition, so it holds
    # back the Failed; a narrowed rule was read and delivers only its filter.
    forward, arns = _forward()
    findings, _ = _routing_findings(
        [forward],
        target_arns={**arns, "audit-opaque": [_SNS_TARGET]},
        bus_rules={"audit-bus": [audit_rule]},
    )
    assert [f["Status"] for f in findings] == statuses
    assert "'audit-opaque'" in findings[0]["Finding_Details"]
    assert "event bus 'audit-bus'" in findings[0]["Finding_Details"]


def test_ar10_a_forwarded_bus_rule_with_a_matching_prefix_is_credited():
    forward, arns = _forward()
    findings, _ = _routing_findings(
        [forward],
        target_arns={**arns, "audit-prefix": [_SNS_TARGET]},
        bus_rules={
            "audit-bus": [
                _rule("audit-prefix", {"source": [{"prefix": "aws."}]}, bus="audit-bus")
            ]
        },
    )
    assert [f["Status"] for f in findings] == ["Passed"]
    assert "rule 'audit-prefix'" in findings[0]["Finding_Details"]


def test_ar10_an_unread_forward_holds_back_only_its_own_transitions():
    # forward-pending reaches a bus whose rules cannot be listed; forward-rest
    # reaches a bus with no delivering rule, so its transitions stay Failed.
    approval_types = list(agent_registry_app.REGISTRY_APPROVAL_DETAIL_TYPES)
    pending, pending_arns = _forward("forward-pending", detail_types=approval_types[:1])
    rest, rest_arns = _forward(
        "forward-rest",
        bus_arn="arn:aws:events:us-east-1:123456789012:event-bus/empty-bus",
        detail_types=approval_types[1:],
    )
    findings, _ = _routing_findings(
        [pending, rest],
        target_arns={**pending_arns, **rest_arns},
        bus_rules={"empty-bus": []},
        bus_list_errors={
            "audit-bus": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
                "ListRules",
            )
        },
    )
    assert [f["Status"] for f in findings] == ["N/A", "Failed", "Failed"]
    assert findings[0]["Finding"].endswith("Incomplete")
    for detail_type in approval_types[1:]:
        assert detail_type in findings[2]["Finding_Details"]
    assert f"{approval_types[0]}," not in findings[2]["Finding_Details"]


def test_ar10_a_forwarded_bus_rule_listing_failure_is_incomplete():
    forward, arns = _forward()
    findings, _ = _routing_findings(
        [forward],
        target_arns=arns,
        bus_list_errors={
            "audit-bus": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
                "ListRules",
            )
        },
    )
    # The unread leg may deliver every forwarded transition, so none is Failed.
    assert [f["Status"] for f in findings] == ["N/A"]
    assert findings[0]["Finding"].endswith("Incomplete")
    assert "event bus 'audit-bus'" in findings[0]["Finding_Details"]
    assert "events:ListRules" in findings[0]["Resolution"]


def test_ar10_a_forwarded_bus_rule_target_failure_is_incomplete():
    forward, arns = _forward()
    findings, _ = _routing_findings(
        [forward],
        target_arns=arns,
        bus_rules={
            "audit-bus": [
                _rule("audit-approvals", _approval_pattern(), bus="audit-bus")
            ]
        },
        target_errors={
            "audit-approvals": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
                "ListTargetsByRule",
            )
        },
    )
    # The unread leg may deliver every forwarded transition, so none is Failed.
    assert [f["Status"] for f in findings] == ["N/A"]
    assert findings[0]["Finding"].endswith("Incomplete")
    assert "events:ListTargetsByRule" in findings[0]["Resolution"]


def test_ar10_a_forwarded_narrowed_rule_with_unread_targets_keeps_the_failed():
    # Reading the targets could not credit a narrowed rule, so the Failed stands.
    forward, arns = _forward()
    findings, _ = _routing_findings(
        [forward],
        target_arns=arns,
        bus_rules={
            "audit-bus": [
                _rule(
                    "audit-narrowed",
                    {**_approval_pattern(), "detail": {"registryId": ["r1"]}},
                    bus="audit-bus",
                )
            ]
        },
        target_errors={"audit-narrowed": _TARGETS_DENIED},
    )
    assert [f["Status"] for f in findings] == ["N/A", "Failed"]
    assert findings[0]["Finding"].endswith("Incomplete")


def test_handler_emits_ar10_for_the_assessed_region():
    captured = {}

    def fake_write(_execution_id, csv_content, _region):
        captured["csv"] = csv_content
        return "s3://test-assessment-bucket/report.csv"

    events = _events_client(
        [_rule("registry-approvals", _approval_pattern())],
        targets={"registry-approvals": 1},
    )

    def client_factory(service_name, **kwargs):
        if service_name == "events":
            assert kwargs.get("region_name") == "us-east-1"
            return events
        return MagicMock()

    with (
        patch.object(agent_registry_app.boto3, "client", side_effect=client_factory),
        patch.object(
            agent_registry_app,
            "_get_permissions_cache",
            return_value={"role_permissions": {}, "user_permissions": {}},
        ),
        patch.object(
            agent_registry_app, "check_agent_registry_full_access", return_value=[]
        ),
        patch.object(
            agent_registry_app, "check_agent_registry_stale_access", return_value=[]
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_inventory",
            return_value=_ready_registry_inventory(),
        ),
        patch.object(
            agent_registry_app,
            "get_agent_registry_record_inventory",
            return_value=_record_inventory(),
        ),
        patch.object(agent_registry_app, "write_to_s3", side_effect=fake_write),
    ):
        response = agent_registry_app.lambda_handler(
            {"Execution": {"Name": "exec-123"}, "Region": "us-east-1"},
            None,
        )

    assert response["statusCode"] == 200
    rows = [
        row
        for row in csv.DictReader(StringIO(captured["csv"]))
        if row["Check_ID"] == "AR-10"
    ]
    assert [row["Status"] for row in rows] == ["Passed"]
    assert rows[0]["Finding"] == "AWS Agent Registry Lifecycle Event Routing"
    assert rows[0]["Region"] == "us-east-1"
    assert events.target_calls == ["registry-approvals"]


# ===================================================================
# AIR-ACR-REG-02: AR-03 fails auto-approval by default, AR-10 credits only a
# review pipeline
# ===================================================================
def _registries(*details):
    inventory = _registry_inventory()
    inventory["items"] = [
        {
            "summary": {"registryId": f"registry-{index}", "name": f"r{index}"},
            "detail": {
                "registryId": f"registry-{index}",
                "name": f"r{index}",
                "status": "READY",
                **detail,
            },
        }
        for index, detail in enumerate(details)
    ]
    return inventory


_AUTO = {"approvalConfiguration": {"autoApprovalRules": ["APPROVE_ALL"]}}


@pytest.mark.parametrize("flag", [None, "false", "true"])
def test_ar03_auto_approval_fails_whatever_the_retired_flag_says(flag, monkeypatch):
    if flag is None:
        monkeypatch.delenv("REQUIRE_AGENT_REGISTRY_MANUAL_APPROVAL", raising=False)
    else:
        monkeypatch.setenv("REQUIRE_AGENT_REGISTRY_MANUAL_APPROVAL", flag)
    findings = agent_registry_app.check_agent_registry_approval_governance(
        _registries({"approvalConfiguration": {"autoApprovalRules": []}}, _AUTO, {})
    )
    assert [f["Status"] for f in findings] == ["Passed", "Failed", "Passed"]
    failed = findings[1]
    assert failed["Finding_Details"] == (
        "Registry 'r1' (registry-1) automatically approves submitted records "
        "(autoApprovalRules: APPROVE_ALL)."
    )
    assert failed["Severity"] == "Medium"
    assert failed["Resolution"] == (
        "Remove auto-approval rules so submitted records require manual review."
    )
    for finding in findings:
        assert_finding_schema(finding)


@pytest.mark.parametrize(
    "detail",
    [
        pytest.param({}, id="approval-configuration-omitted"),
        pytest.param({"approvalConfiguration": None}, id="null"),
        pytest.param({"approvalConfiguration": {}}, id="rules-omitted"),
        pytest.param({"approvalConfiguration": {"autoApprovalRules": []}}, id="empty"),
    ],
)
def test_ar03_no_auto_approval_rule_is_manual_review(detail):
    (finding,) = agent_registry_app.check_agent_registry_approval_governance(
        _registries(detail)
    )
    assert finding["Status"] == "Passed"
    assert finding["Finding_Details"] == (
        "Registry 'r0' (registry-0) requires manual review for submitted records: "
        "it returns no auto-approval rules."
    )


_LOG_GROUP = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/events/registry"
_API_DESTINATION = "arn:aws:events:us-east-1:123456789012:api-destination/review/abc"


@pytest.mark.parametrize(
    "arn",
    [
        "arn:aws:lambda:us-east-1:123456789012:function:review",
        "arn:aws:sns:us-east-1:123456789012:review",
        "arn:aws:sqs:us-east-1:123456789012:review",
        "arn:aws:states:us-east-1:123456789012:stateMachine:review",
    ],
)
def test_ar10_each_review_pipeline_service_is_credited(arn):
    findings, _ = _routing_findings(
        [_rule("approvals", _approval_pattern())], target_arns={"approvals": [arn]}
    )
    assert [f["Status"] for f in findings] == ["Passed"]
    assert "'approvals' (1 target(s))" in findings[0]["Finding_Details"]


@pytest.mark.parametrize("arn", [_LOG_GROUP, _API_DESTINATION])
def test_ar10_a_rule_with_no_review_pipeline_target_is_not_credited(arn):
    findings, _ = _routing_findings(
        [_rule("logged-only", _approval_pattern())],
        target_arns={"logged-only": [arn]},
    )
    assert [f["Status"] for f in findings] == ["Failed", "Failed"]
    assert findings[0]["Finding_Details"] == (
        "EventBridge rule 'logged-only' routes the lifecycle events of registry "
        "'inventory' to 1 target(s), none of which is a Lambda function, SNS "
        "topic, SQS queue or Step Functions state machine, so no state change "
        "reaches a review pipeline."
    )
    assert "route none of them to a target" in findings[1]["Finding_Details"]


def test_ar10_one_unreviewed_rule_beside_a_reviewed_one_is_reported():
    findings, _ = _routing_findings(
        [
            _rule("logged-only", _approval_pattern()),
            _rule("reviewed", _approval_pattern()),
        ],
        target_arns={"logged-only": [_LOG_GROUP], "reviewed": [_SNS_TARGET]},
    )
    assert [f["Status"] for f in findings] == ["Failed", "Passed"]
    assert "'logged-only'" in findings[0]["Finding_Details"]
    assert "'reviewed' (1 target(s))" in findings[1]["Finding_Details"]
    assert "logged-only" not in findings[1]["Finding_Details"]


def test_ar10_a_bus_beside_a_non_pipeline_target_is_followed():
    findings, client = _routing_findings(
        [_rule("mixed", _approval_pattern())],
        target_arns={
            "mixed": [_AUDIT_BUS, _LOG_GROUP],
            "audit-approvals": [
                "arn:aws:lambda:us-east-1:123456789012:function:review"
            ],
        },
        bus_rules={
            "audit-bus": [
                _rule("audit-approvals", _approval_pattern(), bus="audit-bus")
            ]
        },
    )
    assert client.rule_calls == ["default", "audit-bus"]
    assert [f["Status"] for f in findings] == ["Passed"]
    assert (
        "'mixed' via event bus 'audit-bus' rule 'audit-approvals' (1 target(s))"
        in findings[0]["Finding_Details"]
    )


def test_ar10_a_forwarded_bus_with_only_a_log_target_is_not_credited():
    forward, arns = _forward()
    findings, _ = _routing_findings(
        [forward],
        target_arns={**arns, "audit-log": [_LOG_GROUP]},
        bus_rules={
            "audit-bus": [_rule("audit-log", _approval_pattern(), bus="audit-bus")]
        },
    )
    assert findings[0]["Status"] == "Failed"
    assert (
        "has a target that is a Lambda function, SNS topic, SQS queue or Step "
        "Functions state machine, so no forwarded state change reaches a review "
        "pipeline." in findings[0]["Finding_Details"]
    )
