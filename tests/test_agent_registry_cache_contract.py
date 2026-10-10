"""AR-01, AR-02 and AR-09 read the version-2 IAM permission cache contract.

Users are read beside roles, a permissions boundary removes what it does not
allow, a principal named in principal_errors blocks a Passed, a cache without
principal_errors says the errors were not recorded, and AR-01 reports a
wildcard or NotAction grant that merges Registry read and write on one
resource type (AIR-FND-IAM-09).
"""

import importlib.util
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

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
    "agent_registry_cache_contract_app", os.path.join(_REGISTRY_DIR, "app.py")
)
app = importlib.util.module_from_spec(_SPEC)
sys.modules["agent_registry_cache_contract_app"] = app
_SPEC.loader.exec_module(app)

REGISTRY_ARN = "arn:aws:agent-registry:us-east-1:123456789012:registry/registry-123"
MERGED = "AWS Agent Registry Read and Write in One Grant"


def _allow(actions, resource="*"):
    return {"Effect": "Allow", "Action": actions, "Resource": resource}


def _policy(*statements, name="inline"):
    return {
        "name": name,
        "document": {"Version": "2012-10-17", "Statement": list(statements)},
    }


def _identity(*statements, boundary=None, groups=()):
    return {
        "attached_policies": [],
        "inline_policies": [_policy(*statements)] if statements else [],
        "group_policies": [_policy(*g, name="group") for g in groups],
        "permissions_boundary": boundary,
    }


def _boundary(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def _cache(roles=None, users=None, errors=()):
    return {
        "cache_schema_version": 2,
        "role_permissions": roles or {},
        "user_permissions": users or {},
        "principal_errors": list(errors),
    }


def _error(name, kind="role", stage="list_attached_policies"):
    return {"type": kind, "name": name, "stage": stage, "error": "AccessDenied"}


SCOPED_READ = _allow("agent-registry:GetRegistry", REGISTRY_ARN)


def _ar01(cache):
    findings = app.check_agent_registry_full_access(cache)
    for finding in findings:
        assert finding["Check_ID"] == "AR-01"
        assert_finding_schema(finding)
    return findings


def _by_name(findings, name):
    return [f for f in findings if f["Finding"] == name]


class TestAR01Population:
    def test_a_user_among_clean_users_is_reported(self):
        findings = _ar01(
            _cache(
                users={
                    "alice": _identity(SCOPED_READ),
                    "mallory": _identity(_allow("agent-registry:*")),
                    "bob": _identity(SCOPED_READ),
                }
            )
        )
        (wildcard,) = _by_name(findings, "AWS Agent Registry IAM Wildcard Permissions")
        assert wildcard["Status"] == "Failed"
        assert "user mallory" in wildcard["Finding_Details"]
        assert "alice" not in wildcard["Finding_Details"]

    def test_a_group_policy_grant_is_reported_on_the_user(self):
        findings = _ar01(
            _cache(
                users={
                    "alice": _identity(groups=[[_allow("agent-registry:*")]]),
                    "bob": _identity(SCOPED_READ),
                }
            )
        )
        (wildcard,) = _by_name(findings, "AWS Agent Registry IAM Wildcard Permissions")
        assert "user alice" in wildcard["Finding_Details"]
        assert "bob" not in wildcard["Finding_Details"]


class TestAR01MergedReadWrite:
    def test_a_resource_scoped_namespace_wildcard_merges_read_and_write(self):
        findings = _ar01(
            _cache(
                roles={
                    "scoped": _identity(_allow("agent-registry:*", REGISTRY_ARN)),
                    "reader": _identity(SCOPED_READ),
                }
            )
        )
        assert _by_name(findings, "AWS Agent Registry IAM Wildcard Permissions") == []
        (merged,) = _by_name(findings, MERGED)
        assert merged["Status"] == "Failed"
        assert merged["Finding_Details"].startswith(
            "Role 'scoped': Action 'agent-registry:*' grants read and write on 2 "
            "agent-registry resource type(s), for example "
        )
        assert (
            "a condition or resource scope applies to both alike"
            in (merged["Finding_Details"])
        )
        assert app.SCP_NOT_EVALUATED_NOTE in merged["Finding_Details"]

    @pytest.mark.parametrize(
        "statement",
        [
            pytest.param(_allow("*"), id="bare-wildcard"),
            pytest.param(_allow("*:*"), id="wildcard-service"),
            pytest.param(_allow("bedrock-agentcore:*"), id="agentcore-namespace"),
            pytest.param(
                {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
                id="not-action",
            ),
        ],
    )
    def test_a_grant_outside_the_literal_namespace_is_read(self, statement):
        findings = _ar01(
            _cache(roles={"admin": _identity(statement), "ok": _identity(SCOPED_READ)})
        )
        (merged,) = _by_name(findings, MERGED)
        assert merged["Finding_Details"].startswith("Role 'admin': ")
        assert "Role 'ok'" not in merged["Finding_Details"]

    def test_a_wildcard_over_reads_only_is_not_merged(self):
        findings = _ar01(
            _cache(roles={"reader": _identity(_allow("agent-registry:Get*"))})
        )
        assert _by_name(findings, MERGED) == []

    def test_an_account_wide_deny_of_every_write_removes_the_merge(self):
        writes = [
            f"{ns}:{action}"
            for ns, types in app.ACCESS_LEVELS.items()
            for levels in types.values()
            for action in levels["write"]
        ]
        deny = {"Effect": "Deny", "Action": writes, "Resource": "*"}
        findings = _ar01(_cache(roles={"admin": _identity(_allow("*"), deny)}))
        assert _by_name(findings, MERGED) == []

    def test_more_than_twenty_principals_are_capped_with_a_summary(self):
        users = {f"u{i:02d}": _identity(_allow("*")) for i in range(21)}
        findings = _by_name(_ar01(_cache(users=users)), MERGED)
        assert len(findings) == 21
        assert findings[-1]["Finding_Details"].startswith(
            "21 principals hold an AWS Agent Registry grant that merges read and write"
        )


class TestAR01PermissionsBoundary:
    def test_a_boundary_outside_the_registry_removes_the_grant(self):
        outside = _boundary(_allow("s3:GetObject"))
        findings = _ar01(
            _cache(
                roles={
                    "bounded": _identity(_allow("agent-registry:*"), boundary=outside),
                    "open": _identity(_allow("agent-registry:*")),
                }
            )
        )
        (wildcard,) = _by_name(findings, "AWS Agent Registry IAM Wildcard Permissions")
        assert "open" in wildcard["Finding_Details"]
        assert "bounded" not in wildcard["Finding_Details"]
        (merged,) = _by_name(findings, MERGED)
        assert "bounded" not in merged["Finding_Details"]

    def test_a_bounded_only_population_passes(self):
        outside = _boundary(_allow("s3:GetObject"))
        (finding,) = _ar01(
            _cache(roles={"bounded": _identity(_allow("*"), boundary=outside)})
        )
        assert finding["Status"] == "Passed"

    def test_a_boundary_that_leaves_reads_keeps_the_wildcard_but_not_the_merge(self):
        reads = _boundary(_allow("agent-registry:Get*"))
        findings = _ar01(
            _cache(roles={"r": _identity(_allow("agent-registry:*"), boundary=reads)})
        )
        (wildcard,) = _by_name(findings, "AWS Agent Registry IAM Wildcard Permissions")
        assert wildcard["Status"] == "Failed"
        assert _by_name(findings, MERGED) == []


class TestAR01PrincipalErrors:
    def test_an_errored_principal_among_clean_ones_is_incomplete(self):
        findings = _ar01(
            _cache(
                roles={"a": _identity(SCOPED_READ), "broken": _identity()},
                users={"bob": _identity(SCOPED_READ)},
                errors=[_error("broken"), _error("bob", "user", "inline_policy")],
            )
        )
        (finding,) = findings
        assert finding["Status"] == "N/A"
        assert (
            finding["Finding"] == "AWS Agent Registry IAM Full Access Check Incomplete"
        )
        assert finding["Finding_Details"].endswith(
            "2 principal(s) could not be fully read into the IAM permissions cache, "
            "so their grants are unknown: role 'broken' (list_attached_policies), "
            "user 'bob' (inline_policy)."
        )

    def test_a_failed_row_is_kept_beside_the_incomplete_row(self):
        findings = _ar01(
            _cache(
                roles={"wide": _identity(_allow("agent-registry:*")), "b": _identity()},
                errors=[_error("b")],
            )
        )
        statuses = sorted(f["Status"] for f in findings)
        assert statuses == ["Failed", "Failed", "N/A"]
        assert "role 'b' (list_attached_policies)" in findings[-1]["Finding_Details"]

    def test_a_v1_cache_passes_and_says_errors_were_not_recorded(self):
        cache = {
            "role_permissions": {"a": _identity(SCOPED_READ)},
            "user_permissions": {},
        }
        (finding,) = _ar01(cache)
        assert finding["Status"] == "Passed"
        assert finding["Finding_Details"].endswith(app.UNRECORDED_PRINCIPAL_ERRORS_NOTE)

    def test_a_v2_cache_with_no_errors_passes_without_the_note(self):
        (finding,) = _ar01(_cache(roles={"a": _identity(SCOPED_READ)}))
        assert finding["Status"] == "Passed"
        assert finding["Finding_Details"] == (
            "None of the 1 cached roles and users has an AWS Agent Registry "
            "full-access policy, a wildcard or allow-except Registry grant on every "
            "resource, on a resource ARN with a wildcard that reaches beyond one "
            "named registry or on a NotResource, or a grant that merges Registry "
            "read and write actions on one resource type."
        )


def _ar09(cache):
    return app.check_agent_registry_approval_separation(cache)


PUBLISH_AND_APPROVE = _allow(
    ["agent-registry:CreateRegistryRecord", "agent-registry:UpdateRegistryRecordStatus"]
)


class TestAR09CacheContract:
    def test_a_not_action_allow_grants_both_authorities(self):
        (finding,) = _ar09(
            _cache(
                roles={
                    "admin": _identity(
                        {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}
                    ),
                    "reader": _identity(SCOPED_READ),
                }
            )
        )
        assert finding["Status"] == "Failed"
        assert "role 'admin'" in finding["Finding_Details"]
        assert "reader" not in finding["Finding_Details"]
        assert finding["Finding_Details"].startswith(app.SCP_NOT_EVALUATED_NOTE)

    def test_a_group_policy_collision_is_reported_on_the_user(self):
        (finding,) = _ar09(
            _cache(users={"u": _identity(groups=[[PUBLISH_AND_APPROVE]])})
        )
        assert finding["Status"] == "Failed"
        assert (
            "user 'u' (agent-registry:CreateRegistryRecord)"
            in (finding["Finding_Details"])
        )

    def test_a_boundary_without_approval_removes_the_collision(self):
        no_approval = _boundary(_allow("agent-registry:CreateRegistryRecord"))
        (finding,) = _ar09(
            _cache(roles={"p": _identity(PUBLISH_AND_APPROVE, boundary=no_approval)})
        )
        assert finding["Status"] == "Passed"

    def test_a_boundary_denying_only_part_of_publication_keeps_the_collision(self):
        partial = _boundary(
            _allow("*"),
            {
                "Effect": "Deny",
                "Action": "agent-registry:Update*",
                "Resource": "*",
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
        )
        (finding,) = _ar09(
            _cache(roles={"p": _identity(PUBLISH_AND_APPROVE, boundary=partial)})
        )
        assert finding["Status"] == "Failed"

    def test_an_errored_principal_blocks_a_passed(self):
        (finding,) = _ar09(
            _cache(
                roles={"a": _identity(SCOPED_READ), "x": _identity()},
                errors=[_error("x", stage="permissions_boundary")],
            )
        )
        assert finding["Status"] == "N/A"
        assert finding["Finding"] == (
            "AWS Agent Registry Approval Authority Separation Incomplete"
        )
        assert "role 'x' (permissions_boundary)" in finding["Finding_Details"]

    def test_a_v1_cache_passes_and_says_errors_were_not_recorded(self):
        cache = {
            "role_permissions": {"a": _identity(SCOPED_READ)},
            "user_permissions": {},
        }
        (finding,) = _ar09(cache)
        assert finding["Status"] == "Passed"
        assert finding["Finding_Details"].endswith(app.UNRECORDED_PRINCIPAL_ERRORS_NOTE)


def _ar02(cache):
    iam = MagicMock()
    iam.generate_service_last_accessed_details.return_value = {"JobId": "job-1"}
    iam.get_service_last_accessed_details.return_value = {
        "JobStatus": "COMPLETED",
        "ServicesLastAccessed": [
            {
                "ServiceNamespace": "agent-registry",
                "LastAuthenticated": datetime.now(timezone.utc) - timedelta(days=3),
            }
        ],
    }
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012"}
    with (
        patch.object(app.boto3, "client", return_value=sts),
        patch.object(app, "iam_client", iam),
    ):
        return app.check_agent_registry_stale_access(cache), iam


class TestAR02CacheContract:
    def test_an_errored_principal_blocks_a_passed(self):
        findings, _ = _ar02(
            _cache(
                roles={"used": _identity(_allow("agent-registry:GetRegistry"))},
                errors=[_error("hidden")],
            )
        )
        (finding,) = findings
        assert finding["Status"] == "N/A"
        assert finding["Finding"] == "AWS Agent Registry Stale Access Check Incomplete"
        assert "role 'hidden' (list_attached_policies)" in finding["Finding_Details"]

    def test_a_boundary_that_removes_registry_access_drops_the_principal(self):
        outside = _boundary(_allow("s3:GetObject"))
        _, iam = _ar02(
            _cache(
                roles={
                    "bounded": _identity(
                        _allow("agent-registry:GetRegistry"), boundary=outside
                    ),
                    "used": _identity(_allow("agent-registry:GetRegistry")),
                }
            )
        )
        arns = [
            c.kwargs["Arn"]
            for c in iam.generate_service_last_accessed_details.call_args_list
        ]
        assert arns == ["arn:aws:iam::123456789012:role/used"]


class TestUnreadBoundary:
    """A null boundary with a permissions_boundary error means the boundary was
    not read. A boundary could remove the grant, so AR-01, AR-02 and AR-09
    name the principal as not read and never report it Failed."""

    def test_ar01_fails_only_the_principal_whose_boundary_was_read(self):
        findings = _ar01(
            _cache(
                roles={
                    "open": _identity(_allow("agent-registry:*")),
                    "unread": _identity(_allow("agent-registry:*")),
                },
                errors=[_error("unread", stage="permissions_boundary")],
            )
        )
        failed = [f for f in findings if f["Status"] == "Failed"]
        assert failed
        assert all("unread" not in f["Finding_Details"] for f in failed)
        assert any("open" in f["Finding_Details"] for f in failed)
        assert "role 'unread' (permissions_boundary)" in findings[-1]["Finding_Details"]
        assert findings[-1]["Status"] == "N/A"

    def test_ar01_an_unread_boundary_alone_is_not_failed(self):
        (finding,) = _ar01(
            _cache(
                users={"unread": _identity(_allow("*"))},
                errors=[_error("unread", "user", "permissions_boundary")],
            )
        )
        assert finding["Status"] == "N/A"
        assert "user 'unread' (permissions_boundary)" in finding["Finding_Details"]

    def test_ar09_an_unread_boundary_is_not_a_collision(self):
        (finding,) = _ar09(
            _cache(
                roles={
                    "unread": _identity(PUBLISH_AND_APPROVE),
                    "reader": _identity(SCOPED_READ),
                },
                errors=[_error("unread", stage="permissions_boundary")],
            )
        )
        assert finding["Status"] == "N/A"
        assert "role 'unread' (permissions_boundary)" in finding["Finding_Details"]

    def test_ar09_keeps_the_collision_whose_boundary_was_read(self):
        findings = _ar09(
            _cache(
                roles={
                    "open": _identity(PUBLISH_AND_APPROVE),
                    "unread": _identity(PUBLISH_AND_APPROVE),
                },
                errors=[_error("unread", stage="permissions_boundary")],
            )
        )
        assert [f["Status"] for f in findings] == ["Failed", "N/A"]
        assert "role 'open'" in findings[0]["Finding_Details"]
        assert "'unread'" not in findings[0]["Finding_Details"]

    def test_ar02_does_not_query_a_principal_whose_boundary_was_not_read(self):
        findings, iam = _ar02(
            _cache(
                roles={
                    "unread": _identity(_allow("agent-registry:GetRegistry")),
                    "used": _identity(_allow("agent-registry:GetRegistry")),
                },
                errors=[_error("unread", stage="permissions_boundary")],
            )
        )
        arns = [
            c.kwargs["Arn"]
            for c in iam.generate_service_last_accessed_details.call_args_list
        ]
        assert arns == ["arn:aws:iam::123456789012:role/used"]
        assert "Failed" not in [f["Status"] for f in findings]
        assert any(
            "role 'unread' (permissions_boundary)" in f["Finding_Details"]
            for f in findings
        )
