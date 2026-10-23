"""Deployment contracts for the opt-in Security Hub export."""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


class CfnLoader(yaml.SafeLoader):
    pass


def intrinsic(loader, tag, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {tag: value}


CfnLoader.add_multi_constructor("!", intrinsic)


@pytest.mark.parametrize("name", ["template.yaml", "template-multi-account.yaml"])
def test_export_is_disabled_by_default_and_grant_is_conditional(name):
    template = yaml.load(
        (ROOT / "aiml-security-assessment" / name).read_text(), Loader=CfnLoader
    )
    assert template["Parameters"]["EnableSecurityHubExport"]["Default"] == "false"
    function = template["Resources"]["GenerateConsolidatedReportFunction"]["Properties"]
    assert function["Environment"]["Variables"]["ENABLE_SECURITY_HUB_EXPORT"] == {
        "Ref": "EnableSecurityHubExport"
    }
    grant = next(policy for policy in function["Policies"] if "If" in policy)
    condition, policy, disabled = grant["If"]
    assert condition == "SecurityHubExportEnabled"
    assert disabled == {"Ref": "AWS::NoValue"}
    statement = policy["Statement"][0]
    assert statement["Action"] == ["securityhub:BatchImportFindings"]
    assert statement["Resource"] == {
        "Sub": "arn:${AWS::Partition}:securityhub:${AWS::Region}:${AWS::AccountId}:product/${AWS::AccountId}/default"
    }


@pytest.mark.parametrize(
    "name", ["2-aiml-security-codebuild.yaml", "aiml-security-single-account.yaml"]
)
def test_export_parameter_reaches_codebuild(name):
    template = yaml.load((ROOT / "deployment" / name).read_text(), Loader=CfnLoader)
    assert template["Parameters"]["EnableSecurityHubExport"]["Default"] == "false"
    projects = [
        resource["Properties"]
        for resource in template["Resources"].values()
        if resource["Type"] == "AWS::CodeBuild::Project"
    ]
    assert len(projects) == 1
    variables = projects[0]["Environment"]["EnvironmentVariables"]
    assert {
        "Name": "ENABLE_SECURITY_HUB_EXPORT",
        "Value": {"Ref": "EnableSecurityHubExport"},
        "Type": "PLAINTEXT",
    } in variables


def test_every_sam_deploy_path_forwards_export_parameter():
    buildspec = yaml.safe_load((ROOT / "buildspec.yml").read_text())
    commands = buildspec["phases"]["build"]["commands"]
    deploys = [
        line
        for command in commands
        if isinstance(command, str)
        for line in command.splitlines()
        if "sam deploy --" in line
    ]
    assert len(deploys) == 3
    assert all(
        '"$SAM_ENABLE_SECURITY_HUB_EXPORT_PARAMETER"' in line for line in deploys
    )
