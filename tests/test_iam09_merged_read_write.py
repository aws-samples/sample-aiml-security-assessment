"""AIR-FND-IAM-09 merged read-and-write leg of BR-01.

Each check reports a wildcard or NotAction Allow that grants both a read and a
write action on one resource type of its namespace, as the service
authorization reference classifies them. The leg reads every cached role and
user, AWS managed and group policies included, applies account-wide Denies and
the permissions boundary, drops resource types no Resource entry can name,
holds a Passed back while principal_errors names an unread principal, and says
when a v1 cache did not record those errors.
"""

import importlib.util
import json
import os
import sys
from dataclasses import dataclass
from typing import Any, Callable

import pytest

from tests.test_helpers import assert_finding_schema, extract_csv_data

_SECURITY = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__), "..", "aiml-security-assessment/functions/security"
    )
)


def _load(package, module_name):
    directory = os.path.join(_SECURITY, package)
    if directory not in sys.path:
        sys.path.insert(0, directory)
    spec = importlib.util.spec_from_file_location(
        module_name, os.path.join(directory, "app.py")
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


bedrock_app = _load("bedrock_assessments", "iam09_bedrock_app")


@dataclass
class Package:
    check_id: str
    run: Callable[[dict], list]
    merged: str
    namespace: str
    partial: str
    reads_only: str
    scoped_same_type: tuple
    app: Any
    iam09_findings: tuple


PACKAGES = [
    Package(
        "BR-01",
        lambda cache: extract_csv_data(
            bedrock_app.check_bedrock_full_access_roles(cache, "us-east-1")
        ),
        "Bedrock or Data Store Read and Write Merged in One Grant",
        "bedrock",
        "bedrock:*Guardrail*",
        "bedrock:Get*",
        ("bedrock:*Guardrail*", "arn:aws:bedrock:us-east-1:123456789012:guardrail/g1"),
        bedrock_app,
        (
            "Bedrock or Data Store Read and Write Merged in One Grant",
            "Bedrock Wildcard Action Grant",
        ),
    ),
]


@pytest.fixture(params=PACKAGES, ids=[p.check_id for p in PACKAGES])
def pkg(request):
    return request.param


def _allow(actions, resource="*"):
    return {"Effect": "Allow", "Action": actions, "Resource": resource}


def _policy(*statements, name="inline"):
    return {
        "name": name,
        "document": {"Version": "2012-10-17", "Statement": list(statements)},
    }


def _identity(*statements, boundary=None, groups=(), attached=()):
    return {
        "attached_policies": list(attached),
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


def _explicit(pkg):
    """An explicit list of one read and one write on one resource type: an
    action list separates read from write, so it is never merged."""
    levels = next(iter(pkg.app.IAM_ACCESS_LEVELS[pkg.namespace].values()))
    return _allow(
        [
            f"{pkg.namespace}:{levels['read'][0]}",
            f"{pkg.namespace}:{levels['write'][0]}",
        ]
    )


def _rows(pkg, cache):
    rows = pkg.run(cache)
    for row in rows:
        assert row["Check_ID"] == pkg.check_id
        assert_finding_schema(row)
    return rows


def _merged(pkg, rows):
    return [
        row
        for row in rows
        if row["Finding"] == pkg.merged and row["Status"] != "Passed"
    ]


class TestMergedGrant:
    def test_one_partial_wildcard_among_clean_identities_is_the_only_row(self, pkg):
        rows = _rows(
            pkg,
            _cache(
                roles={
                    "clean": _identity(_explicit(pkg)),
                    "bad": _identity(_allow(pkg.partial)),
                },
                users={"alice": _identity(_explicit(pkg))},
            ),
        )
        (merged,) = _merged(pkg, rows)
        assert merged["Status"] == "Failed"
        assert merged["Finding_Details"].startswith("Role 'bad': Action ")
        assert (
            f"resource type(s), for example {pkg.namespace}:"
            in merged["Finding_Details"]
        )
        assert pkg.app.SCP_NOT_EVALUATED_NOTE in merged["Finding_Details"]
        assert "clean" not in merged["Finding_Details"]
        assert "alice" not in merged["Finding_Details"]

    @pytest.mark.parametrize(
        "statement",
        [
            pytest.param(_allow("*"), id="bare-star"),
            pytest.param(_allow("*:*"), id="star-colon-star"),
            pytest.param(
                {"Effect": "Allow", "NotAction": ["iam:*"], "Resource": "*"},
                id="not-action",
            ),
        ],
    )
    def test_a_grant_that_names_no_namespace_is_read(self, pkg, statement):
        rows = _rows(
            pkg,
            _cache(
                roles={"admin": _identity(statement), "ok": _identity(_explicit(pkg))}
            ),
        )
        merged = _merged(pkg, rows)
        assert [row["Status"] for row in merged] == ["Failed"]
        assert merged[0]["Finding_Details"].startswith("Role 'admin': ")

    def test_an_aws_managed_policy_is_read(self, pkg):
        managed = _policy(_allow("*"), name="AdministratorAccess")
        rows = _rows(pkg, _cache(roles={"admin": _identity(attached=[managed])}))
        assert [row["Status"] for row in _merged(pkg, rows)] == ["Failed"]

    def test_a_group_policy_is_read_on_the_user(self, pkg):
        rows = _rows(
            pkg, _cache(users={"u": _identity(groups=[[_allow(pkg.partial)]])})
        )
        (merged,) = _merged(pkg, rows)
        assert merged["Finding_Details"].startswith("User 'u': ")

    def test_a_wildcard_over_reads_only_is_not_merged(self, pkg):
        rows = _rows(pkg, _cache(roles={"reader": _identity(_allow(pkg.reads_only))}))
        assert _merged(pkg, rows) == []

    def test_an_account_wide_deny_of_every_write_removes_the_merge(self, pkg):
        writes = sorted(
            {
                f"{ns}:{action}"
                for ns, types in pkg.app.IAM_ACCESS_LEVELS.items()
                for levels in types.values()
                for action in levels["write"]
            }
        )
        deny = {"Effect": "Deny", "Action": writes, "Resource": "*"}
        rows = _rows(pkg, _cache(roles={"admin": _identity(_allow("*"), deny)}))
        assert _merged(pkg, rows) == []

    def test_a_conditioned_deny_of_every_write_keeps_the_merge(self, pkg):
        deny = {
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}},
        }
        rows = _rows(pkg, _cache(roles={"admin": _identity(_allow(pkg.partial), deny)}))
        assert [row["Status"] for row in _merged(pkg, rows)] == ["Failed"]


class TestResourceScope:
    def test_a_wildcard_scoped_to_one_resource_of_the_merged_type_is_merged(self, pkg):
        action, arn = pkg.scoped_same_type
        rows = _rows(pkg, _cache(roles={"scoped": _identity(_allow(action, arn))}))
        (merged,) = _merged(pkg, rows)
        assert (
            "a condition or resource scope applies to both alike"
            in merged["Finding_Details"]
        )

    def test_a_wildcard_scoped_to_another_service_reaches_no_type(self, pkg):
        rows = _rows(
            pkg,
            _cache(
                roles={
                    "logs-only": _identity(
                        _allow("*", "arn:aws:logs:us-east-1:123456789012:log-group:g")
                    )
                }
            ),
        )
        assert _merged(pkg, rows) == []

    def test_a_policy_variable_in_the_resource_reads_as_any_value(self, pkg):
        action, arn = pkg.scoped_same_type
        rows = _rows(
            pkg,
            _cache(
                roles={
                    "var": _identity(
                        _allow(action, arn.rsplit("/", 1)[0] + "/${aws:username}")
                    )
                }
            ),
        )
        assert [row["Status"] for row in _merged(pkg, rows)] == ["Failed"]


class TestPermissionsBoundary:
    def test_a_boundary_outside_the_namespace_removes_the_grant(self, pkg):
        outside = _boundary(_allow("logs:PutLogEvents"))
        rows = _rows(
            pkg,
            _cache(
                roles={
                    "bounded": _identity(_allow("*"), boundary=outside),
                    "open": _identity(_allow(pkg.partial)),
                }
            ),
        )
        (merged,) = _merged(pkg, rows)
        assert merged["Finding_Details"].startswith("Role 'open': ")

    def test_a_boundary_that_leaves_only_reads_removes_the_merge(self, pkg):
        reads = _boundary(_allow(pkg.reads_only))
        rows = _rows(
            pkg, _cache(roles={"r": _identity(_allow(pkg.partial), boundary=reads)})
        )
        assert _merged(pkg, rows) == []


class TestUnreadBoundary:
    """A null boundary with a permissions_boundary error means the boundary was
    not read, and a boundary could remove the grant, so the principal is named
    as not read and never reported Failed."""

    def test_only_the_principal_whose_boundary_was_read_is_failed(self, pkg):
        rows = _rows(
            pkg,
            _cache(
                roles={
                    "open": _identity(_allow(pkg.partial)),
                    "unread": _identity(_allow(pkg.partial)),
                },
                errors=[_error("unread", stage="permissions_boundary")],
            ),
        )
        (merged,) = _merged(pkg, rows)
        assert merged["Status"] == "Failed"
        assert merged["Finding_Details"].startswith("Role 'open': ")
        assert any(
            row["Status"] == "N/A"
            and "role 'unread' (permissions_boundary)" in row["Finding_Details"]
            for row in rows
        )

    def test_an_unread_boundary_on_a_wildcard_grant_is_not_failed(self, pkg):
        rows = _rows(
            pkg,
            _cache(
                users={"unread": _identity(_allow("*"))},
                errors=[_error("unread", "user", "permissions_boundary")],
            ),
        )
        leg = [row for row in rows if row["Finding"] in pkg.iam09_findings]
        assert [row for row in leg if row["Status"] in ("Failed", "Passed")] == []
        assert any(
            row["Status"] == "N/A"
            and "user 'unread' (permissions_boundary)" in row["Finding_Details"]
            for row in rows
        )

    def test_another_stage_error_keeps_the_boundary_as_read(self, pkg):
        rows = _rows(
            pkg,
            _cache(
                roles={"wide": _identity(_allow(pkg.partial))},
                errors=[_error("wide", stage="inline_policy")],
            ),
        )
        assert [row["Status"] for row in _merged(pkg, rows)] == ["Failed"]


class TestBedrockDataStores:
    def _rows(self, *statements):
        return extract_csv_data(
            bedrock_app.check_bedrock_full_access_roles(
                _cache(roles={"data": _identity(*statements)}), "us-east-1"
            )
        )

    def test_a_data_store_wildcard_without_bedrock_is_left_to_other_checks(self):
        merged = [
            r
            for r in self._rows(_allow("s3:*"))
            if r["Finding"] == PACKAGES[0].merged and r["Status"] != "Passed"
        ]
        assert merged == []

    def test_a_data_store_wildcard_beside_a_bedrock_grant_is_merged(self):
        rows = self._rows(_allow("s3:*"), _allow("bedrock:InvokeModel"))
        (merged,) = [r for r in rows if r["Finding"] == PACKAGES[0].merged]
        assert "Action 's3:*' grants read and write on" in merged["Finding_Details"]
        assert " s3 resource type(s)" in merged["Finding_Details"]


class TestUnreadPopulation:
    def test_an_unparseable_policy_is_not_a_passed(self, pkg):
        """A leg that reads policy documents reports N/A for one it could not
        parse. A leg that matches attached policy names read them, so it may
        still pass."""
        broken = {"name": "broken", "document": "{not-json"}
        rows = _rows(
            pkg,
            _cache(
                roles={
                    "b": _identity(attached=[broken]),
                    "ok": _identity(_explicit(pkg)),
                }
            ),
        )
        assert [
            row["Finding"]
            for row in rows
            if row["Status"] == "Passed" and row["Finding"] in pkg.iam09_findings
        ] == []
        assert any(
            row["Status"] == "N/A" and "'b'" in row["Finding_Details"] for row in rows
        )

    def test_an_errored_principal_among_clean_ones_holds_the_passed(self, pkg):
        rows = _rows(
            pkg,
            _cache(
                roles={"a": _identity(_explicit(pkg)), "broken": _identity()},
                errors=[_error("broken"), _error("bob", "user", "inline_policy")],
            ),
        )
        assert "Passed" not in [row["Status"] for row in rows]
        incomplete = [row for row in rows if row["Finding"].endswith(" Incomplete")]
        assert incomplete and all(row["Status"] == "N/A" for row in incomplete)
        assert any(
            "role 'broken' (list_attached_policies), user 'bob' (inline_policy)."
            in row["Finding_Details"]
            for row in incomplete
        )

    def test_a_failed_row_is_kept_beside_the_unread_principals(self, pkg):
        rows = _rows(
            pkg,
            _cache(
                roles={"wide": _identity(_allow(pkg.partial)), "b": _identity()},
                errors=[_error("b")],
            ),
        )
        assert [row["Status"] for row in _merged(pkg, rows)] == ["Failed"]
        assert "Passed" not in [row["Status"] for row in rows]
        assert any(
            "role 'b' (list_attached_policies)" in row["Finding_Details"]
            for row in rows
        )

    def test_a_v1_cache_passes_and_says_errors_were_not_recorded(self, pkg):
        cache = {
            "role_permissions": {"a": _identity(_explicit(pkg))},
            "user_permissions": {},
        }
        passed = [row for row in _rows(pkg, cache) if row["Status"] == "Passed"]
        assert passed
        assert all(
            row["Finding_Details"].endswith(pkg.app.UNRECORDED_PRINCIPAL_ERRORS_NOTE)
            for row in passed
        )

    def test_a_v2_cache_with_no_errors_passes_without_the_note(self, pkg):
        rows = _rows(pkg, _cache(roles={"a": _identity(_explicit(pkg))}))
        assert "Passed" in [row["Status"] for row in rows]
        assert all(
            pkg.app.UNRECORDED_PRINCIPAL_ERRORS_NOTE not in row["Finding_Details"]
            for row in rows
        )

    def test_more_than_twenty_principals_are_capped_with_a_summary(self, pkg):
        users = {f"u{i:02d}": _identity(_allow(pkg.partial)) for i in range(21)}
        merged = _merged(pkg, _rows(pkg, _cache(users=users)))
        assert len(merged) == 21
        assert merged[-1]["Finding_Details"].startswith(
            "21 principals hold a grant that merges "
        )


def test_the_access_level_tables_are_generated_from_the_service_reference():
    """Every type carries the three keys the leg reads, and every ARN glob has
    no unreplaced ${Variable}."""
    for package in ("bedrock_assessments",):
        with open(
            os.path.join(_SECURITY, package, "iam_access_levels.json"), encoding="utf-8"
        ) as handle:
            services = json.load(handle)["services"]
        for types in services.values():
            for levels in types.values():
                assert set(levels) == {"arns", "read", "write"}
                assert levels["read"] and levels["write"] and levels["arns"]
                assert all("${" not in arn for arn in levels["arns"])
