"""Guard the multi-account member role against IAM policy-size deployment failures."""

import json
from pathlib import Path

import yaml


_REPO_ROOT = Path(__file__).resolve().parents[1]
_TEMPLATE_PATH = _REPO_ROOT / "deployment" / "1-aiml-security-member-roles.yaml"
_MEMBER_ROLE_POLICY_IDS = ("MemberRoleDeploymentAndReportPermissions",)
_LARGEST_PARTITION = "aws-us-gov"
_MANAGED_POLICY_SIZE_LIMIT = 6_144
_POLICY_SIZE_BUDGET = 5_500


class _CfnLoader(yaml.SafeLoader):
    """Safe YAML loader that preserves CloudFormation short-form intrinsics."""


def _cfn_multi_constructor(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {f"Fn::{tag_suffix}": value}


_CfnLoader.add_multi_constructor("!", _cfn_multi_constructor)


def _load_template():
    with _TEMPLATE_PATH.open(encoding="utf-8") as template_file:
        return yaml.load(template_file, Loader=_CfnLoader)  # nosec B506


def _render_intrinsics(value):
    """Render the pseudo-parameters that contribute to policy document size."""
    if isinstance(value, list):
        return [_render_intrinsics(item) for item in value]
    if not isinstance(value, dict):
        return value
    if set(value) == {"Fn::Sub"}:
        template = value["Fn::Sub"]
        assert isinstance(template, str), "size guard supports only string !Sub values"
        return (
            template.replace("${AWS::Partition}", _LARGEST_PARTITION)
            .replace("${AWS::AccountId}", "123456789012")
            .replace("${ManagementAccountID}", "123456789012")
        )
    return {key: _render_intrinsics(item) for key, item in value.items()}


def _compact_json_size(policy_document):
    rendered = _render_intrinsics(policy_document)
    return len(json.dumps(rendered, separators=(",", ":")))


def test_member_role_uses_customer_managed_policies_not_inline_policies():
    template = _load_template()
    member_role = template["Resources"]["MemberRole"]["Properties"]

    assert "Policies" not in member_role
    for logical_id in _MEMBER_ROLE_POLICY_IDS:
        policy = template["Resources"][logical_id]
        assert policy["Type"] == "AWS::IAM::ManagedPolicy"
        assert policy["Properties"]["Roles"] == [{"Fn::Ref": "MemberRole"}]


def test_member_role_managed_policy_documents_stay_within_budget():
    template = _load_template()

    for logical_id in _MEMBER_ROLE_POLICY_IDS:
        document = template["Resources"][logical_id]["Properties"]["PolicyDocument"]
        size = _compact_json_size(document)
        assert size <= _POLICY_SIZE_BUDGET, (
            f"{logical_id} renders to {size:,} characters in {_LARGEST_PARTITION}; "
            f"keep it below the {_POLICY_SIZE_BUDGET:,}-character project budget "
            f"and never exceed IAM's {_MANAGED_POLICY_SIZE_LIMIT:,}-character "
            "customer-managed policy limit."
        )
