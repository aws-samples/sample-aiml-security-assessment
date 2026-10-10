import os
import subprocess
from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATHS = [
    REPO_ROOT / "aiml-security-assessment" / "template.yaml",
    REPO_ROOT / "aiml-security-assessment" / "template-multi-account.yaml",
]
EXPECTED_ENV_OWNERS = {
    "REQUIRE_BEDROCK_ZERO_DATA_RETENTION": (
        "BedrockSecurityAssessmentFunction",
        "RequireBedrockZeroDataRetention",
    ),
    "REQUIRE_MARKETPLACE_ENDPOINT_CMK": (
        "BedrockSecurityAssessmentFunction",
        "RequireMarketplaceEndpointCMK",
    ),
    "AIML_APPROVED_EXTERNAL_ACCOUNT_IDS": (
        "SagemakerSecurityAssessmentFunction",
        "ApprovedExternalAccountIds",
    ),
    "AIML_APPROVED_ORG_IDS": (
        "SagemakerSecurityAssessmentFunction",
        "ApprovedOrganizationIds",
    ),
    "AGENTCORE_TOKEN_VAULT_ID": (
        "AgentCoreSecurityAssessmentFunction",
        "AgentCoreTokenVaultId",
    ),
    "REQUIRE_AGENTCORE_ONLINE_EVALUATION": (
        "AgentCoreSecurityAssessmentFunction",
        "RequireAgentCoreOnlineEvaluation",
    ),
    "REQUIRE_AGENT_REGISTRY_MANUAL_APPROVAL": (
        "AgentRegistrySecurityAssessmentFunction",
        "RequireAgentRegistryManualApproval",
    ),
    "REQUIRE_AGENT_REGISTRY_CMK": (
        "AgentRegistrySecurityAssessmentFunction",
        "RequireAgentRegistryCMK",
    ),
    "ENABLE_SAGEMAKER_ARTIFACT_OBJECT_READS": (
        "SagemakerSecurityAssessmentFunction",
        "EnableSageMakerArtifactObjectReads",
    ),
}
CLEARABLE_SAM_PARAMETERS = {
    "SAM_TARGET_REGIONS_PARAMETER": "TargetRegions",
    "SAM_APPROVED_EXTERNAL_ACCOUNT_IDS_PARAMETER": "ApprovedExternalAccountIds",
    "SAM_APPROVED_ORGANIZATION_IDS_PARAMETER": "ApprovedOrganizationIds",
}
SYNTHETIC_APPROVED_ACCOUNT_IDS = "111122223333,444455556666"
SYNTHETIC_APPROVED_ORGANIZATION_ID = "o-a1b2c3d4e5"


class CfnLoader(yaml.SafeLoader):
    pass


def _construct_intrinsic(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {f"Fn::{tag_suffix}": value}


CfnLoader.add_multi_constructor("!", _construct_intrinsic)


def _load_sam_parameter_script():
    with (REPO_ROOT / "buildspec.yml").open(encoding="utf-8") as buildspec_file:
        buildspec = yaml.safe_load(buildspec_file)

    for command in buildspec["phases"]["build"]["commands"]:
        if "SAM_TARGET_REGIONS_PARAMETER=" in command:
            return command

    raise AssertionError("Could not find the SAM parameter construction block")


def _run_sam_parameter_script(env_overrides):
    parameter_script = _load_sam_parameter_script()
    output_commands = "\n".join(
        f"printf '%s=%s\\n' '{variable}' \"${{{variable}}}\""
        for variable in CLEARABLE_SAM_PARAMETERS
    )
    result = subprocess.run(
        ["bash", "-c", f"{parameter_script}\n{output_commands}"],
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **env_overrides},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    return dict(
        line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
    )


@pytest.mark.parametrize("template_path", TEMPLATE_PATHS, ids=lambda path: path.name)
def test_optional_policy_baselines_are_wired_to_consuming_lambdas(template_path):
    with template_path.open(encoding="utf-8") as template_file:
        template = yaml.load(template_file, Loader=CfnLoader)  # nosec B506

    resources = template["Resources"]
    for variable, (expected_owner, parameter) in EXPECTED_ENV_OWNERS.items():
        owners = []
        for logical_id, resource in resources.items():
            variables = (
                resource.get("Properties", {})
                .get("Environment", {})
                .get("Variables", {})
            )
            if variable in variables:
                owners.append(logical_id)
                assert variables[variable] == {"Fn::Ref": parameter}

        assert owners == [expected_owner], (
            f"{variable} must be configured only on {expected_owner}; found {owners}"
        )


@pytest.mark.parametrize(
    ("env_overrides", "expected_values"),
    [
        (
            {},
            {
                "TargetRegions": "",
                "ApprovedExternalAccountIds": "",
                "ApprovedOrganizationIds": "",
            },
        ),
        (
            {
                "TARGET_REGIONS": "us-east-1,us-west-2",
                "APPROVED_EXTERNAL_ACCOUNT_IDS": SYNTHETIC_APPROVED_ACCOUNT_IDS,
                "APPROVED_ORGANIZATION_IDS": SYNTHETIC_APPROVED_ORGANIZATION_ID,
            },
            {
                "TargetRegions": "us-east-1,us-west-2",
                "ApprovedExternalAccountIds": SYNTHETIC_APPROVED_ACCOUNT_IDS,
                "ApprovedOrganizationIds": SYNTHETIC_APPROVED_ORGANIZATION_ID,
            },
        ),
    ],
    ids=["empty-values", "non-empty-values"],
)
def test_clearable_sam_parameters_preserve_literal_quotes(
    env_overrides, expected_values
):
    parameters = _run_sam_parameter_script(env_overrides)

    for variable, parameter_name in CLEARABLE_SAM_PARAMETERS.items():
        assert parameters[variable] == (
            f"ParameterKey={parameter_name},ParameterValue="
            f'"{expected_values[parameter_name]}"'
        )


def test_readme_uses_json_for_comma_separated_cloudformation_parameters():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    assert "--parameters file://params.json" in readme
    assert '"ParameterKey": "ApprovedExternalAccountIds"' in readme
    assert '"ParameterValue": "111122223333,444455556666"' in readme
    assert '"ParameterKey": "ApprovedOrganizationIds"' in readme


def test_agent_registry_manual_approval_baseline_reaches_every_deploy_path():
    buildspec = (REPO_ROOT / "buildspec.yml").read_text(encoding="utf-8")
    parameter_variable = "SAM_REQUIRE_AGENT_REGISTRY_MANUAL_APPROVAL_PARAMETER"

    assert (
        f'{parameter_variable}="ParameterKey=RequireAgentRegistryManualApproval,'
        'ParameterValue=${REQUIRE_AGENT_REGISTRY_MANUAL_APPROVAL:-false}"' in buildspec
    )
    deploy_commands = [
        line for line in buildspec.splitlines() if "sam deploy --template-file" in line
    ]
    assert len(deploy_commands) == 3
    assert all(f'"${parameter_variable}"' in line for line in deploy_commands)

    for template_name in (
        "deployment/aiml-security-single-account.yaml",
        "deployment/2-aiml-security-codebuild.yaml",
    ):
        template = (REPO_ROOT / template_name).read_text(encoding="utf-8")
        assert "RequireAgentRegistryManualApproval:" in template
        assert "Name: REQUIRE_AGENT_REGISTRY_MANUAL_APPROVAL" in template
        assert "Value: !Ref RequireAgentRegistryManualApproval" in template


def test_agent_registry_cmk_baseline_reaches_every_deploy_path():
    buildspec = (REPO_ROOT / "buildspec.yml").read_text(encoding="utf-8")
    parameter_variable = "SAM_REQUIRE_AGENT_REGISTRY_CMK_PARAMETER"

    assert (
        f'{parameter_variable}="ParameterKey=RequireAgentRegistryCMK,'
        'ParameterValue=${REQUIRE_AGENT_REGISTRY_CMK:-false}"' in buildspec
    )
    deploy_commands = [
        line for line in buildspec.splitlines() if "sam deploy --template-file" in line
    ]
    assert len(deploy_commands) == 3
    assert all(f'"${parameter_variable}"' in line for line in deploy_commands)

    for template_name in (
        "deployment/aiml-security-single-account.yaml",
        "deployment/2-aiml-security-codebuild.yaml",
    ):
        template = (REPO_ROOT / template_name).read_text(encoding="utf-8")
        assert "RequireAgentRegistryCMK:" in template
        assert "Name: REQUIRE_AGENT_REGISTRY_CMK" in template
        assert "Value: !Ref RequireAgentRegistryCMK" in template


def test_sagemaker_artifact_object_reads_reach_every_deploy_path():
    buildspec = (REPO_ROOT / "buildspec.yml").read_text(encoding="utf-8")
    parameter_variable = "SAM_ENABLE_SAGEMAKER_ARTIFACT_OBJECT_READS_PARAMETER"

    assert (
        f'{parameter_variable}="ParameterKey=EnableSageMakerArtifactObjectReads,'
        'ParameterValue=${ENABLE_SAGEMAKER_ARTIFACT_OBJECT_READS:-false}"' in buildspec
    )
    assert f"export {parameter_variable}" in buildspec
    deploy_commands = [
        line for line in buildspec.splitlines() if "sam deploy --template-file" in line
    ]
    assert len(deploy_commands) == 3
    assert all(f'"${parameter_variable}"' in line for line in deploy_commands)

    for template_name in (
        "deployment/aiml-security-single-account.yaml",
        "deployment/2-aiml-security-codebuild.yaml",
    ):
        with (REPO_ROOT / template_name).open(encoding="utf-8") as template_file:
            template = yaml.load(template_file, Loader=CfnLoader)  # nosec B506
        parameter = template["Parameters"]["EnableSageMakerArtifactObjectReads"]
        assert parameter["Default"] == "false"
        assert parameter["AllowedValues"] == ["true", "false"]
        text = (REPO_ROOT / template_name).read_text(encoding="utf-8")
        assert "Name: ENABLE_SAGEMAKER_ARTIFACT_OBJECT_READS" in text
        assert "Value: !Ref EnableSageMakerArtifactObjectReads" in text


@pytest.mark.parametrize("template_path", TEMPLATE_PATHS, ids=lambda path: path.name)
def test_sagemaker_artifact_object_read_grant_exists_only_when_enabled(
    template_path,
):
    with template_path.open(encoding="utf-8") as template_file:
        template = yaml.load(template_file, Loader=CfnLoader)  # nosec B506

    parameter = template["Parameters"]["EnableSageMakerArtifactObjectReads"]
    assert parameter["Default"] == "false"
    assert parameter["AllowedValues"] == ["true", "false"]
    assert template["Conditions"]["SageMakerArtifactObjectReadsEnabled"] == {
        "Fn::Equals": [{"Fn::Ref": "EnableSageMakerArtifactObjectReads"}, "true"]
    }
    statements = [
        statement
        for policy in template["Resources"]["SagemakerSecurityAssessmentFunction"][
            "Properties"
        ]["Policies"]
        for statement in policy.get("Statement", [])
    ]
    conditional = [s for s in statements if "Fn::If" in s]
    assert len(conditional) == 1
    condition, granted, otherwise = conditional[0]["Fn::If"]
    assert condition == "SageMakerArtifactObjectReadsEnabled"
    assert granted["Sid"] == "ModelArtifactObjectRead"
    assert granted["Action"] == ["s3:GetObject"]
    assert otherwise == {"Fn::Ref": "AWS::NoValue"}
    # No unconditional statement grants s3:GetObject beyond the permissions cache.
    unconditional = [
        s
        for s in statements
        if "Fn::If" not in s and "s3:GetObject" in (s.get("Action") or [])
    ]
    assert [s["Sid"] for s in unconditional] == ["PermissionCacheRead"]


def test_agentcore_artifact_content_reads_reach_every_deploy_path():
    buildspec = (REPO_ROOT / "buildspec.yml").read_text(encoding="utf-8")
    parameter_variable = "SAM_ENABLE_AGENTCORE_ARTIFACT_CONTENT_READS_PARAMETER"

    assert (
        f'{parameter_variable}="ParameterKey=EnableAgentCoreArtifactContentReads,'
        'ParameterValue=${ENABLE_AGENTCORE_ARTIFACT_CONTENT_READS:-false}"' in buildspec
    )
    assert f"export {parameter_variable}" in buildspec
    deploy_commands = [
        line for line in buildspec.splitlines() if "sam deploy --template-file" in line
    ]
    assert len(deploy_commands) == 3
    assert all(f'"${parameter_variable}"' in line for line in deploy_commands)

    for template_name, project in (
        ("deployment/aiml-security-single-account.yaml", "CodeBuild"),
        ("deployment/2-aiml-security-codebuild.yaml", "MultiAccountCodeBuild"),
    ):
        with (REPO_ROOT / template_name).open(encoding="utf-8") as template_file:
            template = yaml.load(template_file, Loader=CfnLoader)  # nosec B506
        parameter = template["Parameters"]["EnableAgentCoreArtifactContentReads"]
        assert parameter["Default"] == "false"
        assert parameter["AllowedValues"] == ["true", "false"]
        environment = template["Resources"][project]["Properties"]["Environment"][
            "EnvironmentVariables"
        ]
        assert {
            "Name": "ENABLE_AGENTCORE_ARTIFACT_CONTENT_READS",
            "Value": {"Fn::Ref": "EnableAgentCoreArtifactContentReads"},
            "Type": "PLAINTEXT",
        } in environment


@pytest.mark.parametrize("template_path", TEMPLATE_PATHS, ids=lambda path: path.name)
def test_agentcore_artifact_content_grants_exist_only_when_opted_in(template_path):
    with template_path.open(encoding="utf-8") as template_file:
        template = yaml.load(template_file, Loader=CfnLoader)  # nosec B506

    parameter = template["Parameters"]["EnableAgentCoreArtifactContentReads"]
    assert parameter["Default"] == "false"
    assert template["Conditions"]["AgentCoreArtifactContentReadsEnabled"] == {
        "Fn::Equals": [{"Fn::Ref": "EnableAgentCoreArtifactContentReads"}, "true"]
    }
    statements = template["Resources"]["AgentCoreAssessmentReadsPolicy"]["Properties"][
        "PolicyDocument"
    ]["Statement"]
    conditional = {}
    for statement in statements:
        if "Fn::If" in statement:
            condition, granted, otherwise = statement["Fn::If"]
            assert condition == "AgentCoreArtifactContentReadsEnabled"
            assert otherwise == {"Fn::Ref": "AWS::NoValue"}
            conditional[granted["Sid"]] = set(granted["Action"])
    assert conditional == {
        "RuntimeImageConfigRead": {"ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"},
        "AgentRuntimeArtifactObjectRead": {"s3:GetObject", "s3:GetObjectVersion"},
    }
    # No unconditional statement reads object or image contents. The image
    # digest read AC-50 needs stays unconditional.
    unconditional = [statement for statement in statements if "Fn::If" not in statement]
    actions = {action for statement in unconditional for action in statement["Action"]}
    assert not actions & {
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
        "s3:GetObjectVersion",
    }
    assert "ecr:DescribeImages" in actions
    assert all(
        statement["Resource"] != {"Fn::Sub": "arn:${AWS::Partition}:s3:::*/*"}
        for statement in unconditional
    )
