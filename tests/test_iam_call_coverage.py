from pathlib import Path
from copy import deepcopy
from functools import lru_cache
from fnmatch import fnmatchcase

import pytest

from tests.iam_call_coverage import (
    ApiCall,
    extract_calls,
    granted_actions,
    load_template,
    missing_calls,
    iam_action,
    function_statements,
)


ROOT = Path(__file__).resolve().parents[1] / "aiml-security-assessment"
TEMPLATES = [ROOT / "template.yaml", ROOT / "template-multi-account.yaml"]


@lru_cache(maxsize=None)
def package_calls(code_uri):
    calls = set()
    for source in (ROOT / code_uri).rglob("*.py"):
        if not source.name.startswith("test_"):
            calls.update(extract_calls(source.read_text(), source.relative_to(ROOT)))
    return calls


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda p: p.name)
def test_each_lambda_has_its_source_derived_actions(path):
    template = load_template(path)
    errors = []
    for name, resource in template["Resources"].items():
        if resource["Type"] != "AWS::Serverless::Function":
            continue
        code_uri = resource["Properties"].get("CodeUri", "")
        if not isinstance(code_uri, str) or not code_uri.startswith(
            "functions/security/"
        ):
            continue
        calls = package_calls(code_uri)
        for call in missing_calls(calls, granted_actions(template, name)):
            errors.append(
                f"{path.name} {name}: {call.path}:{call.line} {call.service}.{call.method} requires {call.action}"
            )
    assert not errors, "\n".join(sorted(errors))


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda p: p.name)
def test_actual_required_actions_fail_when_their_grant_is_removed(path):
    template = load_template(path)
    checked = 0
    for name, resource in template["Resources"].items():
        code_uri = resource.get("Properties", {}).get("CodeUri", "")
        if (
            resource["Type"] != "AWS::Serverless::Function"
            or not isinstance(code_uri, str)
            or not code_uri.startswith("functions/security/")
        ):
            continue
        by_action = {
            call.action: call for call in package_calls(code_uri) if call.action
        }
        for action, call in by_action.items():
            changed = deepcopy(template)
            for statement in function_statements(changed, name):
                actions = statement["Action"]
                actions = actions if isinstance(actions, list) else [actions]
                statement["Action"] = [
                    grant
                    for grant in actions
                    if not fnmatchcase(action.lower(), grant.lower())
                ]
            assert missing_calls([call], granted_actions(changed, name)), (
                f"Removed grant for {name} {action} was not detected"
            )
            checked += 1
    assert checked > 400


def test_lexical_bindings_do_not_confuse_identically_named_clients():
    calls = extract_calls("""
import boto3
def first():
    bedrock_client = boto3.client("bedrock-agent")
    bedrock_client.list_agents()
def second():
    bedrock_client = boto3.client("s3")
    bedrock_client.list_objects_v2(Bucket="fixture")
""")
    assert {c.action for c in calls} == {"bedrock:ListAgents", "s3:ListBucket"}


def test_aliases_factories_and_string_helpers_are_derived_from_source():
    calls = extract_calls("""
import boto3
def make():
    return boto3.client("wafv2")
def collect(client, operation):
    method = getattr(client, operation)
    return method()
client = make()
alias = client
collect(alias, "get_logging_configuration")
alias.get_paginator("list_web_acls")
""")
    assert {c.action for c in calls} == {
        "wafv2:GetLoggingConfiguration",
        "wafv2:ListWebACLs",
    }
    assert all(c.line > 0 and c.path == "fixture.py" for c in calls)
    assert missing_calls(calls, {"wafv2:listwebacls"})


def test_dynamic_helper_does_not_cross_pair_service_and_operation():
    calls = extract_calls("""
import boto3
def collect(client, operation):
    return client.get_paginator(operation).paginate()
a = boto3.client("s3")
b = boto3.client("iam")
collect(a, "list_objects_v2")
collect(b, "list_roles")
""")
    assert {c.action for c in calls} == {"s3:ListBucket", "iam:ListRoles"}


@pytest.mark.parametrize(
    "service,method,expected",
    [
        ("bedrock-agent", "list_agents", "bedrock:ListAgents"),
        (
            "bedrock-agentcore-control",
            "list_gateways",
            "bedrock-agentcore:ListGateways",
        ),
        ("agent-registry-control", "list_registries", "agent-registry:ListRegistries"),
        ("s3", "get_public_access_block", "s3:GetBucketPublicAccessBlock"),
        ("s3control", "get_public_access_block", "s3:GetAccountPublicAccessBlock"),
        ("s3", "get_bucket_encryption", "s3:GetEncryptionConfiguration"),
        ("apigatewayv2", "get_apis", "apigateway:GET"),
        ("apigatewayv2", "create_api", "apigateway:POST"),
        ("sts", "get_caller_identity", None),
    ],
)
def test_operation_to_iam_mapping(service, method, expected):
    assert iam_action(service, method) == expected


def test_unknown_sdk_operation_is_an_error_not_a_silently_skipped_call():
    with pytest.raises(AssertionError, match="Unknown SDK operation"):
        missing_calls(
            extract_calls(
                'import boto3\nc = boto3.client("wafv2")\nc.nonexistent_operation()'
            ),
            set(),
        )


def template_fixture():
    return {
        "Resources": {
            "One": {
                "Type": "AWS::Serverless::Function",
                "Properties": {
                    "Policies": [
                        {
                            "Statement": {
                                "Effect": "Allow",
                                "Action": "wafv2:ListWebACLs",
                                "Resource": "*",
                            }
                        },
                        {"Ref": "Reads"},
                    ]
                },
            },
            "Other": {
                "Type": "AWS::Serverless::Function",
                "Properties": {
                    "Policies": [
                        {
                            "Statement": {
                                "Effect": "Allow",
                                "Action": "wafv2:GetLoggingConfiguration",
                                "Resource": "*",
                            }
                        },
                    ]
                },
            },
            "Reads": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["iam:GetRole"],
                                "Resource": "*",
                            }
                        ]
                    }
                },
            },
        }
    }


def test_misplaced_and_unattached_policy_grants_do_not_satisfy_coverage():
    template = template_fixture()
    call = ApiCall("app.py", 7, "wafv2", "get_logging_configuration")
    assert missing_calls([call], granted_actions(template, "One"))
    assert not missing_calls([call], granted_actions(template, "Other"))
    assert "iam:getrole" in granted_actions(template, "One")
    changed = deepcopy(template)
    changed["Resources"]["One"]["Properties"]["Policies"].pop()
    assert "iam:getrole" not in granted_actions(changed, "One")


def test_deny_comment_and_scalar_list_action_handling():
    template = template_fixture()
    policies = template["Resources"]["One"]["Properties"]["Policies"]
    policies.append(
        {"Statement": {"Effect": "Deny", "Action": "wafv2:GetWebACL", "Resource": "*"}}
    )
    policies.append({"Description": "wafv2:GetWebACL"})
    assert granted_actions(template, "One") == {"wafv2:listwebacls", "iam:getrole"}


def test_local_role_and_attached_managed_policies_are_followed():
    template = template_fixture()
    template["Resources"]["Role"] = {
        "Type": "AWS::IAM::Role",
        "Properties": {
            "ManagedPolicyArns": [{"Ref": "Reads"}],
            "Policies": [],
        },
    }
    template["Resources"]["One"]["Properties"] = {
        "Role": {"Fn::GetAtt": ["Role", "Arn"]}
    }
    assert granted_actions(template, "One") == {"iam:getrole"}


def test_unapproved_read_in_second_sagemaker_managed_policy_is_rejected(monkeypatch):
    from tests import test_sagemaker_template_permissions as gate

    template = load_template(TEMPLATES[0])
    policy = template["Resources"]["SageMakerAssessmentReadsPolicy2"]["Properties"][
        "PolicyDocument"
    ]
    policy["Statement"].append(
        {"Effect": "Allow", "Action": "organizations:*", "Resource": "*"}
    )
    monkeypatch.setattr(gate, "load_template", lambda _: template)
    with pytest.raises(AssertionError, match="granted without approval"):
        gate.test_unapproved_reads_are_not_granted_to_the_sagemaker_function()


def test_literal_loop_paginators_and_global_client_bindings():
    calls = extract_calls("""
import boto3
client = None
def setup():
    global client
    client = boto3.client("iam")
def collect():
    for operation in ("list_roles", "list_users"):
        client.get_paginator(operation)
""")
    assert {call.action for call in calls} == {"iam:ListRoles", "iam:ListUsers"}


def test_unknown_service_is_not_silently_ignored():
    with pytest.raises(AssertionError, match="unknown SDK service"):
        extract_calls(
            'import boto3\nclient = boto3.client("not-a-service")\nclient.list_roles()'
        )


def test_imported_client_alias_is_not_a_coverage_escape():
    calls = extract_calls(
        'from boto3 import client as sdk_client\nc = sdk_client("wafv2")\nc.get_logging_configuration()'
    )
    assert missing_calls(calls, {"wafv2:listwebacls"})
    assert {call.action for call in calls} == {"wafv2:GetLoggingConfiguration"}


def test_unknown_literal_string_helper_operation_is_not_skipped():
    calls = extract_calls("""
import boto3
def collect(client, operation):
    return getattr(client, operation)()
c = boto3.client("wafv2")
collect(c, "not_an_operation")
""")
    with pytest.raises(AssertionError, match="Unknown SDK operation"):
        missing_calls(calls, set())


def test_conditional_statements_are_coverage_possibilities_not_evaluated_iam():
    template = template_fixture()
    template["Resources"]["One"]["Properties"]["Policies"] = [
        {
            "Statement": [
                {
                    "Fn::If": [
                        "Enabled",
                        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
                        {"Ref": "AWS::NoValue"},
                    ]
                }
            ]
        }
    ]
    assert granted_actions(template, "One") == {"s3:getobject"}
