"""The IAM permission cache producer honours the version-2 contract.

principal_errors replaces swallowed per-principal exceptions, each principal
carries its permissions_boundary document, every policy list is paginated, and
the file carries cache_schema_version 2.
"""

import importlib.util
import json
import os
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

_spec = importlib.util.spec_from_file_location(
    "iam_permission_cache_contract_app",
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "aiml-security-assessment/functions/security/iam_permission_caching/app.py",
    ),
)
cache_app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cache_app)


def _denied(operation):
    return ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}}, operation
    )


def _doc(action):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": action, "Resource": "*"}],
    }


BOUNDARY_ARN = "arn:aws:iam::123456789012:policy/Boundary"


class FakeIam:
    """Serves roles and users page by page and raises where told to."""

    def __init__(self, roles=None, users=None, fail=None):
        # name -> {"attached": [[arn, ...], ...], "inline": [[name, ...], ...],
        #          "boundary": arn or None}
        self.roles = roles or {}
        self.users = users or {}
        # (operation, principal or policy) -> exception
        self.fail = fail or {}
        self.policies = {}

    def _check(self, operation, key):
        if (operation, key) in self.fail:
            raise self.fail[(operation, key)]

    def get_paginator(self, name):
        paginator = MagicMock()

        def paginate(**kwargs):
            if name == "list_roles":
                return [{"Roles": [{"RoleName": n}]} for n in self.roles]
            if name == "list_users":
                return [{"Users": [{"UserName": n}]} for n in self.users]
            if name == "list_groups_for_user":
                return [{"Groups": []}]
            principal = kwargs.get("RoleName") or kwargs.get("UserName")
            table = self.roles if "RoleName" in kwargs else self.users
            self._check(name, principal)
            if name.startswith("list_attached_"):
                return [
                    {
                        "AttachedPolicies": [
                            {"PolicyName": arn.rsplit("/", 1)[1], "PolicyArn": arn}
                            for arn in page
                        ]
                    }
                    for page in table[principal]["attached"]
                ]
            return [{"PolicyNames": list(page)} for page in table[principal]["inline"]]

        paginator.paginate.side_effect = paginate
        return paginator

    def get_policy(self, PolicyArn):
        self._check("get_policy", PolicyArn)
        return {"Policy": {"DefaultVersionId": "v3"}}

    def get_policy_version(self, PolicyArn, VersionId):
        self._check("get_policy_version", PolicyArn)
        assert VersionId == "v3"
        return {"PolicyVersion": {"Document": _doc(PolicyArn.rsplit("/", 1)[1])}}

    def get_role_policy(self, RoleName, PolicyName):
        self._check("get_role_policy", (RoleName, PolicyName))
        return {"PolicyDocument": _doc(PolicyName)}

    def get_user_policy(self, UserName, PolicyName):
        self._check("get_user_policy", (UserName, PolicyName))
        return {"PolicyDocument": _doc(PolicyName)}

    def _detail(self, kind, table, name):
        self._check(f"get_{kind.lower()}", name)
        boundary = table[name].get("boundary")
        detail = {f"{kind}Name": name}
        if boundary:
            detail["PermissionsBoundary"] = {
                "PermissionsBoundaryType": "Policy",
                "PermissionsBoundaryArn": boundary,
            }
        return {kind: detail}

    def get_role(self, RoleName):
        return self._detail("Role", self.roles, RoleName)

    def get_user(self, UserName):
        return self._detail("User", self.users, UserName)


def _principal(attached=(), inline=(), boundary=None):
    return {"attached": list(attached), "inline": list(inline), "boundary": boundary}


def _names(policies):
    return [p["name"] for p in policies]


def test_attached_and_inline_lists_are_read_past_the_first_page():
    iam = FakeIam(
        roles={
            "worker": _principal(
                attached=[
                    ["arn:aws:iam::123456789012:policy/P1"],
                    ["arn:aws:iam::123456789012:policy/P2"],
                ],
                inline=[["I1"], ["I2", "I3"]],
            )
        },
        users={
            "alice": _principal(
                attached=[[], ["arn:aws:iam::aws:policy/U2"]],
                inline=[["UI1"], ["UI2"]],
            )
        },
    )
    cache = cache_app.IAMPermissionCache(iam)
    cache.initialize()

    role = cache.role_permissions["worker"]
    assert _names(role["attached_policies"]) == ["P1", "P2"]
    assert _names(role["inline_policies"]) == ["I1", "I2", "I3"]
    user = cache.user_permissions["alice"]
    assert _names(user["attached_policies"]) == ["U2"]
    assert _names(user["inline_policies"]) == ["UI1", "UI2"]
    assert cache.principal_errors == []


def test_permissions_boundary_is_the_boundary_document_or_null():
    iam = FakeIam(
        roles={
            "bounded": _principal(boundary=BOUNDARY_ARN),
            "unbounded": _principal(),
        },
        users={"bob": _principal(boundary=BOUNDARY_ARN), "carol": _principal()},
    )
    cache = cache_app.IAMPermissionCache(iam)
    cache.initialize()

    assert cache.role_permissions["bounded"]["permissions_boundary"] == _doc("Boundary")
    assert cache.role_permissions["unbounded"]["permissions_boundary"] is None
    assert cache.user_permissions["bob"]["permissions_boundary"] == _doc("Boundary")
    assert cache.user_permissions["carol"]["permissions_boundary"] is None


def test_one_failing_principal_is_recorded_and_the_others_are_complete():
    arn = "arn:aws:iam::123456789012:policy/P1"
    iam = FakeIam(
        roles={
            "good-a": _principal(attached=[[arn]], inline=[["I1"]]),
            "broken": _principal(attached=[[arn]], inline=[["I1"]]),
            "good-b": _principal(attached=[[arn]], inline=[["I1"]]),
        },
        users={
            "dave": _principal(inline=[["UI1", "UI2"]]),
            "erin": _principal(inline=[["UI1"]]),
        },
        fail={
            ("list_attached_role_policies", "broken"): _denied(
                "ListAttachedRolePolicies"
            ),
            ("get_user_policy", ("dave", "UI2")): _denied("GetUserPolicy"),
        },
    )
    cache = cache_app.IAMPermissionCache(iam)
    cache.initialize()

    assert [(e["type"], e["name"], e["stage"]) for e in cache.principal_errors] == [
        ("role", "broken", "list_attached_policies"),
        ("user", "dave", "inline_policy"),
    ]
    assert all("AccessDenied" in e["error"] for e in cache.principal_errors)
    assert "UI2" in cache.principal_errors[1]["error"]
    # What the failing principals did yield is kept.
    assert _names(cache.role_permissions["broken"]["inline_policies"]) == ["I1"]
    assert _names(cache.user_permissions["dave"]["inline_policies"]) == ["UI1"]
    for role in ("good-a", "good-b"):
        assert _names(cache.role_permissions[role]["attached_policies"]) == ["P1"]
    assert _names(cache.user_permissions["erin"]["inline_policies"]) == ["UI1"]


def test_a_policy_version_read_failure_is_recorded_not_dropped():
    good = "arn:aws:iam::123456789012:policy/Good"
    bad = "arn:aws:iam::123456789012:policy/Bad"
    iam = FakeIam(
        roles={"mixed": _principal(attached=[[good, bad]])},
        fail={("get_policy_version", bad): _denied("GetPolicyVersion")},
    )
    cache = cache_app.IAMPermissionCache(iam)
    cache.initialize()

    assert _names(cache.role_permissions["mixed"]["attached_policies"]) == ["Good"]
    assert [(e["name"], e["stage"]) for e in cache.principal_errors] == [
        ("mixed", "attached_policy")
    ]
    assert bad in cache.principal_errors[0]["error"]


def test_a_boundary_read_failure_is_recorded():
    iam = FakeIam(
        roles={
            "denied-role": _principal(boundary=BOUNDARY_ARN),
            "ok-role": _principal(boundary=BOUNDARY_ARN),
        },
        fail={("get_role", "denied-role"): _denied("GetRole")},
    )
    cache = cache_app.IAMPermissionCache(iam)
    cache.initialize()

    assert cache.role_permissions["denied-role"]["permissions_boundary"] is None
    assert cache.role_permissions["ok-role"]["permissions_boundary"] == _doc("Boundary")
    assert [(e["name"], e["stage"]) for e in cache.principal_errors] == [
        ("denied-role", "permissions_boundary")
    ]


def test_a_group_read_failure_is_also_a_principal_error():
    iam = FakeIam(users={"frank": _principal(), "gina": _principal()})
    original = iam.get_paginator

    def get_paginator(name):
        if name == "list_groups_for_user":
            paginator = MagicMock()

            def paginate(UserName):
                if UserName == "frank":
                    raise _denied("ListGroupsForUser")
                return [{"Groups": []}]

            paginator.paginate.side_effect = paginate
            return paginator
        return original(name)

    iam.get_paginator = get_paginator
    cache = cache_app.IAMPermissionCache(iam)
    cache.initialize()

    assert [(e["type"], e["name"], e["stage"]) for e in cache.principal_errors] == [
        ("user", "frank", "group_policies")
    ]
    assert "AccessDenied" in cache.user_permissions["frank"]["group_policies_error"]
    assert cache.user_permissions["gina"]["group_policies"] == []


def test_written_cache_carries_version_2_and_the_errors():
    iam = FakeIam(
        roles={"broken": _principal(), "fine": _principal()},
        fail={("list_role_policies", "broken"): _denied("ListRolePolicies")},
    )
    cache = cache_app.IAMPermissionCache(iam)
    cache.initialize()
    s3 = MagicMock()
    with patch.object(cache_app.boto3, "client", return_value=s3):
        key = cache_app.write_permissions_to_s3(cache, "exec-1")

    assert key == "permissions_cache_exec-1.json"
    body = json.loads(s3.put_object.call_args.kwargs["Body"])
    assert body["cache_schema_version"] == 2
    assert body["principal_errors"] == [
        {
            "type": "role",
            "name": "broken",
            "stage": "list_inline_policies",
            "error": body["principal_errors"][0]["error"],
        }
    ]
    assert "AccessDenied" in body["principal_errors"][0]["error"]
    assert body["role_permissions"]["fine"]["permissions_boundary"] is None
