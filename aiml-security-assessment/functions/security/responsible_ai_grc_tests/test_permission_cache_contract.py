"""FS-07 and FS-22 read the version-2 IAM permission cache contract.

A role named in principal_errors blocks a Passed and is named in the text, a
permissions boundary removes the actions it does not allow, and a cache without
principal_errors (schema v1) says the errors were not recorded.
"""

from unittest.mock import MagicMock, patch

import pytest

from .support import finserv_app as app


def _policy(*statements):
    return {"document": {"Version": "2012-10-17", "Statement": list(statements)}}


def _allow(action, resource="*"):
    return {"Effect": "Allow", "Action": action, "Resource": resource}


def _role(*statements, boundary=None):
    return {
        "attached_policies": [_policy(*statements)] if statements else [],
        "inline_policies": [],
        "permissions_boundary": boundary,
    }


def _cache(roles, errors=()):
    return {
        "cache_schema_version": 2,
        "role_permissions": roles,
        "user_permissions": {},
        "principal_errors": list(errors),
    }


def _error(name, stage="list_attached_policies", kind="role"):
    return {"type": kind, "name": name, "stage": stage, "error": "AccessDenied"}


def _boundary(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


SAFE = _allow(
    "bedrock:GetKnowledgeBase",
    "arn:aws:bedrock:us-east-1:123456789012:knowledge-base/KB1",
)


def _only_row(result):
    assert len(result["csv_data"]) == 1
    return result["csv_data"][0]


class TestFS22PrincipalErrors:
    def test_an_errored_role_among_clean_roles_is_incomplete_not_passed(self):
        cache = _cache(
            {"clean-a": _role(SAFE), "broken": _role(), "clean-b": _role(SAFE)},
            errors=[_error("broken")],
        )
        result = app.check_knowledge_base_iam_least_privilege(cache)
        row = _only_row(result)
        assert result["status"] == "N/A"
        assert row["Status"] == "N/A"
        assert row["Finding"] == "Knowledge Base IAM Least Privilege Check Incomplete"
        assert (
            "1 role(s) could not be fully read from the IAM permissions cache, so "
            "their grants are unknown: 'broken'." in row["Finding_Details"]
        )

    def test_a_failed_row_still_names_the_unread_roles_and_scps(self):
        cache = _cache(
            {"wide": _role(_allow("bedrock:*")), "broken": _role(), "other": _role()},
            errors=[_error("broken"), _error("other", stage="inline_policy")],
        )
        row = _only_row(app.check_knowledge_base_iam_least_privilege(cache))
        assert row["Status"] == "Failed"
        assert "- Role 'wide' allows 'bedrock:*'" in row["Finding_Details"]
        assert "their grants are unknown: 'broken', 'other'." in row["Finding_Details"]
        assert app.SCP_NOT_EVALUATED_NOTE in row["Finding_Details"]

    def test_user_errors_do_not_block_the_role_population(self):
        cache = _cache({"clean": _role(SAFE)}, errors=[_error("alice", kind="user")])
        row = _only_row(app.check_knowledge_base_iam_least_privilege(cache))
        assert row["Status"] == "Passed"
        assert app.UNRECORDED_PRINCIPAL_ERRORS_NOTE not in row["Finding_Details"]

    def test_a_v1_cache_passes_and_says_errors_were_not_recorded(self):
        cache = {"role_permissions": {"clean": _role(SAFE)}, "user_permissions": {}}
        row = _only_row(app.check_knowledge_base_iam_least_privilege(cache))
        assert row["Status"] == "Passed"
        assert row["Finding_Details"].endswith(app.UNRECORDED_PRINCIPAL_ERRORS_NOTE)


class TestFS22PermissionsBoundary:
    def test_a_boundary_that_excludes_bedrock_removes_the_grant(self):
        outside = _boundary(_allow("s3:GetObject"))
        cache = _cache(
            {
                "bounded": _role(_allow("bedrock:*"), boundary=outside),
                "unbounded": _role(_allow("bedrock:Retrieve*")),
            }
        )
        row = _only_row(app.check_knowledge_base_iam_least_privilege(cache))
        assert row["Status"] == "Failed"
        assert "Role 'unbounded' allows 'bedrock:Retrieve*'" in row["Finding_Details"]
        assert "'bounded'" not in row["Finding_Details"]

    def test_a_bounded_only_population_passes(self):
        outside = _boundary(_allow(["s3:GetObject", "logs:*"]))
        cache = _cache({"bounded": _role(_allow("bedrock:*"), boundary=outside)})
        assert (
            _only_row(app.check_knowledge_base_iam_least_privilege(cache))["Status"]
            == "Passed"
        )

    @pytest.mark.parametrize(
        "boundary",
        [
            _boundary(_allow("bedrock:Get*")),
            _boundary(_allow("*")),
            _boundary({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}),
            _boundary(
                _allow("*"),
                {
                    "Effect": "Deny",
                    "Action": "bedrock:*",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:RequestedRegion": "eu-west-1"}},
                },
            ),
            _boundary(
                _allow("*"),
                {"Effect": "Deny", "Action": "bedrock:Get*", "Resource": "*"},
            ),
            _boundary(_allow("bedrock:?et*")),
        ],
    )
    def test_a_boundary_that_leaves_part_of_the_grant_keeps_it(self, boundary):
        cache = _cache({"wide": _role(_allow("bedrock:*"), boundary=boundary)})
        row = _only_row(app.check_knowledge_base_iam_least_privilege(cache))
        assert row["Status"] == "Failed"
        assert "Role 'wide' allows 'bedrock:*'" in row["Finding_Details"]

    @pytest.mark.parametrize(
        "boundary",
        [
            _boundary(
                _allow("*"), {"Effect": "Deny", "Action": "bedrock:*", "Resource": "*"}
            ),
            _boundary({"Effect": "Allow", "NotAction": "bedrock:*", "Resource": "*"}),
            _boundary(_allow("sagemaker:*")),
        ],
    )
    def test_a_boundary_that_denies_the_whole_grant_removes_it(self, boundary):
        cache = _cache({"wide": _role(_allow("bedrock:*"), boundary=boundary)})
        assert (
            _only_row(app.check_knowledge_base_iam_least_privilege(cache))["Status"]
            == "Passed"
        )


def _agents_client(agents):
    client = MagicMock()
    client.list_agents.return_value = {
        "agentSummaries": [{"agentId": a, "agentName": a} for a in agents]
    }
    client.get_agent.side_effect = lambda agentId: {
        "agent": {
            "agentResourceRoleArn": f"arn:aws:iam::123456789012:role/service-role/{agents[agentId]}"
        }
    }
    return client


class TestFS07CacheContract:
    @patch("finserv_app.boto3.client")
    def test_an_agent_whose_role_errored_blocks_a_passed(self, mock_client):
        mock_client.return_value = _agents_client({"a1": "RoleA", "a2": "RoleB"})
        cache = _cache(
            {"RoleA": _role(SAFE), "RoleB": _role()},
            errors=[_error("RoleB", stage="inline_policy")],
        )
        result = app.check_bedrock_agent_action_boundaries(cache)
        row = _only_row(result)
        assert result["status"] == "N/A"
        assert row["Finding"] == "Agent Action Boundary Check Incomplete"
        assert (
            "Not read (1): agent 'a2' role 'RoleB' (cache read failed at inline_policy)."
            in row["Finding_Details"]
        )
        assert "Reviewed 1 of 2 agent(s)" in row["Finding_Details"]

    @patch("finserv_app.boto3.client")
    def test_an_agent_role_missing_from_the_cache_is_unread(self, mock_client):
        mock_client.return_value = _agents_client({"a1": "RoleA", "a2": "Absent"})
        result = app.check_bedrock_agent_action_boundaries(
            _cache({"RoleA": _role(SAFE)})
        )
        row = _only_row(result)
        assert row["Status"] == "N/A"
        assert (
            "agent 'a2' role 'Absent' (not in the permissions cache)"
            in row["Finding_Details"]
        )

    @patch("finserv_app.boto3.client")
    def test_a_failed_agent_row_names_unread_roles_and_scps(self, mock_client):
        mock_client.return_value = _agents_client({"a1": "Wide", "a2": "Broken"})
        cache = _cache(
            {"Wide": _role(_allow("iam:*")), "Broken": _role()},
            errors=[_error("Broken")],
        )
        row = _only_row(app.check_bedrock_agent_action_boundaries(cache))
        assert row["Status"] == "Failed"
        assert "Agent 'a1' role 'Wide' allows 'iam:*'" in row["Finding_Details"]
        assert "agent 'a2' role 'Broken'" in row["Finding_Details"]
        assert app.SCP_NOT_EVALUATED_NOTE in row["Finding_Details"]

    @patch("finserv_app.boto3.client")
    def test_a_boundary_removes_a_wildcard_only_on_the_bounded_role(self, mock_client):
        mock_client.return_value = _agents_client({"a1": "Bounded", "a2": "Open"})
        narrow = _boundary(_allow("bedrock:InvokeModel"))
        cache = _cache(
            {
                "Bounded": _role(_allow("iam:*"), boundary=narrow),
                "Open": _role(_allow("s3:*")),
            }
        )
        row = _only_row(app.check_bedrock_agent_action_boundaries(cache))
        assert row["Status"] == "Failed"
        assert "Agent 'a2' role 'Open' allows 's3:*'" in row["Finding_Details"]
        assert "'Bounded'" not in row["Finding_Details"]

    @patch("finserv_app.boto3.client")
    def test_a_v2_cache_with_no_errors_passes_without_the_v1_note(self, mock_client):
        mock_client.return_value = _agents_client({"a1": "RoleA"})
        row = _only_row(
            app.check_bedrock_agent_action_boundaries(_cache({"RoleA": _role(SAFE)}))
        )
        assert row["Status"] == "Passed"
        assert row["Finding_Details"] == (
            "Reviewed 1 agent(s); no wildcard sensitive actions found."
        )

    @patch("finserv_app.boto3.client")
    def test_a_v1_cache_passes_and_says_errors_were_not_recorded(self, mock_client):
        mock_client.return_value = _agents_client({"a1": "RoleA"})
        cache = {"role_permissions": {"RoleA": _role(SAFE)}, "user_permissions": {}}
        row = _only_row(app.check_bedrock_agent_action_boundaries(cache))
        assert row["Status"] == "Passed"
        assert row["Finding_Details"].endswith(app.UNRECORDED_PRINCIPAL_ERRORS_NOTE)


class TestUnreadBoundary:
    """A null boundary with a permissions_boundary error means the boundary was
    not read. A boundary could remove the grant, so the role is named as not
    read and never reported Failed."""

    def test_fs22_fails_only_the_role_whose_boundary_was_read(self):
        cache = _cache(
            {"open": _role(_allow("bedrock:*")), "unread": _role(_allow("bedrock:*"))},
            errors=[_error("unread", stage="permissions_boundary")],
        )
        row = _only_row(app.check_knowledge_base_iam_least_privilege(cache))
        assert row["Status"] == "Failed"
        assert "- Role 'open' allows 'bedrock:*'" in row["Finding_Details"]
        assert "Role 'unread' allows" not in row["Finding_Details"]
        assert "their grants are unknown: 'unread'." in row["Finding_Details"]

    def test_fs22_an_unread_boundary_alone_is_not_failed(self):
        cache = _cache(
            {"unread": _role(_allow("bedrock:*")), "clean": _role(SAFE)},
            errors=[_error("unread", stage="permissions_boundary")],
        )
        row = _only_row(app.check_knowledge_base_iam_least_privilege(cache))
        assert row["Status"] == "N/A"
        assert "their grants are unknown: 'unread'." in row["Finding_Details"]

    @patch("finserv_app.boto3.client")
    def test_fs07_fails_only_the_role_whose_boundary_was_read(self, mock_client):
        mock_client.return_value = _agents_client({"a1": "Open", "a2": "Unread"})
        cache = _cache(
            {"Open": _role(_allow("iam:*")), "Unread": _role(_allow("iam:*"))},
            errors=[_error("Unread", stage="permissions_boundary")],
        )
        row = _only_row(app.check_bedrock_agent_action_boundaries(cache))
        assert row["Status"] == "Failed"
        assert "Agent 'a1' role 'Open' allows 'iam:*'" in row["Finding_Details"]
        assert "role 'Unread' allows" not in row["Finding_Details"]
        assert (
            "agent 'a2' role 'Unread' (cache read failed at permissions_boundary)"
            in row["Finding_Details"]
        )

    @patch("finserv_app.boto3.client")
    def test_fs07_an_unread_boundary_alone_is_not_failed(self, mock_client):
        mock_client.return_value = _agents_client({"a1": "Unread"})
        cache = _cache(
            {"Unread": _role(_allow("*"))},
            errors=[_error("Unread", stage="permissions_boundary")],
        )
        row = _only_row(app.check_bedrock_agent_action_boundaries(cache))
        assert row["Status"] == "N/A"
        assert row["Finding"] == "Agent Action Boundary Check Incomplete"
