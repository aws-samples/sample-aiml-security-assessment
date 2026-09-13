"""Deployment selection must agree with executed tasks and report coverage."""

import csv
import itertools
import json
import os
from pathlib import Path
import re
import subprocess
from unittest.mock import MagicMock, patch

from bs4 import BeautifulSoup
from botocore.exceptions import ClientError
import pytest
import yaml

from tests.test_consolidated_report import consolidated_app
from tests.test_owasp_checks import owasp_app
from tests.test_optional_policy_baseline_wiring import CfnLoader
import consolidate_html_reports as multi_report

ROOT = Path(__file__).resolve().parents[1]
SERVICES = {
    "bedrock": ("Bedrock", "BEDROCK", "BR-00"),
    "sagemaker": ("SageMaker", "SAGEMAKER", "SM-00"),
    "agentcore": ("AgentCore", "AGENTCORE", "AC-00"),
    "agent-registry": ("AgentRegistry", "AGENT_REGISTRY", "AR-00"),
}
REGIONS = ["us-east-1", "us-west-2"]
EXECUTION = "selection-test"


def _definition(selection):
    text = (
        ROOT / "aiml-security-assessment/statemachine/assessments.asl.json"
    ).read_text()
    text = text.replace("${MaxRegionConcurrency}", "5")
    for service, (parameter, _, _) in SERVICES.items():
        text = text.replace("${Enable" + parameter + "Assessment}", selection[service])
    return json.loads(text)


def _row(service):
    return {
        "Check_ID": SERVICES[service][2],
        "Finding": "No resources found",
        "Finding_Details": "Synthetic assessment fixture",
        "Resolution": "No action required",
        "Reference": "https://docs.aws.amazon.com/",
        "Severity": "Informational",
        "Status": "N/A",
        "Region": REGIONS[0],
    }


def _results(selection):
    return {
        service: {
            f"{service.replace('-', '_')}_security_report_{EXECUTION}_{region}": [
                _row(service)
            ]
            for region in REGIONS
        }
        for service, enabled in selection.items()
        if enabled == "true"
    }


def _run_branch(branch, data):
    """Execute the relevant ASL states with Lambda tasks replaced by a recorder."""
    state_name = branch["StartAt"]
    invoked = []
    for _ in range(10):
        state = branch["States"][state_name]
        if state["Type"] == "Choice":
            next_state = state["Default"]
            for choice in state["Choices"]:
                path = re.fullmatch(
                    r"\$\.OriginalInput\.ServiceSelection\['([^']+)'\]",
                    choice["Variable"],
                )
                assert path, choice["Variable"]
                value = data["OriginalInput"]["ServiceSelection"][path.group(1)]
                if isinstance(value, str) and value == choice["StringEquals"]:
                    next_state = choice["Next"]
                    break
            state_name = next_state
        elif state["Type"] == "Task":
            invoked.append(state["Parameters"]["FunctionName"])
            assert state["End"] is True
            return invoked, {"statusCode": 200}
        elif state["Type"] == "Pass":
            assert state["End"] is True
            return invoked, state["Result"]
        else:
            pytest.fail(f"Unexpected state type: {state['Type']}")
    pytest.fail("Branch did not terminate")


@pytest.mark.parametrize("values", list(itertools.product(("true", "false"), repeat=4)))
def test_every_selection_executes_only_selected_lambdas_and_validates_their_artifacts(
    values,
):
    selection = dict(zip(SERVICES, values))
    definition = _definition(selection)
    configure = definition["States"][definition["StartAt"]]
    assert configure["Type"] == "Pass"
    assert configure["ResultPath"] == "$.ServiceSelection"
    assert configure["Next"] == "Cleanup S3 Bucket"
    original_input = {
        "ServiceSelection": configure["Result"],
        "ResolvedRegions": {"regions": REGIONS},
    }
    region_processor = definition["States"]["Scan Regions"]["ItemProcessor"]["States"]
    branches = region_processor["Run Security Assessments"]["Branches"]
    for (service, enabled), branch in zip(selection.items(), branches):
        for region in REGIONS:
            calls, result = _run_branch(
                branch, {"OriginalInput": original_input, "Region": region}
            )
            if enabled == "true":
                assert len(calls) == 1
                function = {
                    "bedrock": "BedrockSecurityAssessmentFunction",
                    "sagemaker": "SagemakerSecurityAssessmentFunction",
                    "agentcore": "AgentCoreSecurityAssessmentFunction",
                    "agent-registry": "AgentRegistrySecurityAssessmentFunction",
                }[service]
                assert calls == ["${" + function + "}"]
            else:
                assert calls == []
                assert result["reason"] == "not-selected"
                assert result["service"] == service
    results = _results(selection)
    consolidated_app.validate_assessment_artifacts(results, EXECUTION, original_input)
    for service, enabled in selection.items():
        if enabled == "true":
            incomplete = {**results, service: {}}
            with pytest.raises(ValueError, match=service.replace("-", "_")):
                consolidated_app.validate_assessment_artifacts(
                    incomplete, EXECUTION, original_input
                )


@pytest.mark.parametrize(
    "template",
    [
        "aiml-security-assessment/template.yaml",
        "aiml-security-assessment/template-multi-account.yaml",
        "deployment/aiml-security-single-account.yaml",
        "deployment/2-aiml-security-codebuild.yaml",
    ],
)
def test_all_deployment_paths_expose_default_enabled_switches(template):
    doc = yaml.load((ROOT / template).read_text(), Loader=CfnLoader)
    for parameter, environment, _ in SERVICES.values():
        name = f"Enable{parameter}Assessment"
        assert doc["Parameters"][name]["Default"] == "true"
        assert doc["Parameters"][name]["AllowedValues"] == ["true", "false"]
        if template.startswith("aiml-"):
            substitutions = doc["Resources"]["AIMLAssessmentStateMachine"][
                "Properties"
            ]["DefinitionSubstitutions"]
            assert substitutions[name] == {"Fn::Ref": name}
        else:
            projects = [
                r
                for r in doc["Resources"].values()
                if r["Type"] == "AWS::CodeBuild::Project"
            ]
            assert len(projects) == 1
            env = {
                v["Name"]: v["Value"]
                for v in projects[0]["Properties"]["Environment"][
                    "EnvironmentVariables"
                ]
            }
            assert env[f"ENABLE_{environment}"] == {"Fn::Ref": name}


@pytest.mark.parametrize("values", list(itertools.product(("true", "false"), repeat=4)))
def test_codebuild_collects_exactly_the_selected_service_artifacts(values):
    text = (ROOT / "buildspec.yml").read_text()
    start = text.index("                required_artifact_prefixes=()")
    end = text.index("                artifacts_complete=true", start)
    script = text[start:end] + '\nprintf "%s\\n" "${required_artifact_prefixes[@]}"\n'
    env = {**os.environ, "ENABLE_RESPONSIBLE_AI_GRC": "false", "ENABLE_OWASP": "false"}
    env.update(
        {f"ENABLE_{meta[1]}": value for meta, value in zip(SERVICES.values(), values)}
    )
    result = subprocess.run(
        ["bash", "-c", script], env=env, capture_output=True, text=True, check=True
    )
    assert result.stdout.split() == [
        service.replace("-", "_")
        for service, value in zip(SERVICES, values)
        if value == "true"
    ]


def test_sam_overrides_reach_member_management_and_single_account_deploys():
    commands = yaml.safe_load((ROOT / "buildspec.yml").read_text())["phases"]["build"][
        "commands"
    ]
    deploys = [
        line
        for command in commands
        for line in str(command).splitlines()
        if "sam deploy " in line
    ]
    assert len(deploys) == 3
    for line in deploys:
        for _, env, _ in SERVICES.values():
            assert f'"$SAM_ENABLE_{env}_PARAMETER"' in line
    setup = next(
        command
        for command in commands
        if "SAM_TARGET_REGIONS_PARAMETER=" in str(command)
    )
    env = {**os.environ, **{f"ENABLE_{meta[1]}": "false" for meta in SERVICES.values()}}
    outputs = "\n".join(
        f'printf "%s\\n" "$SAM_ENABLE_{meta[1]}_PARAMETER"'
        for meta in SERVICES.values()
    )
    result = subprocess.run(
        ["bash", "-c", setup + "\n" + outputs],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    for parameter, _, _ in SERVICES.values():
        assert (
            f"ParameterKey=Enable{parameter}Assessment,ParameterValue=false"
            in result.stdout
        )


def test_owasp_does_not_read_deselected_sources_but_still_reports_missing_selected_sources():
    selection = {service: "false" for service in SERVICES}
    selection["bedrock"] = "true"
    s3 = MagicMock()
    s3.get_object.side_effect = ClientError(
        {"Error": {"Code": "NoSuchKey"}}, "GetObject"
    )
    with patch.object(owasp_app.boto3, "client", return_value=s3):
        rows, missing = owasp_app._read_service_csvs_for_region(
            "test-assessment-bucket",
            EXECUTION,
            REGIONS[0],
            include_finserv=True,
            return_missing=True,
            service_selection=selection,
        )
    assert rows == []
    assert missing == [
        f"bedrock_security_report_{EXECUTION}_{REGIONS[0]}.csv",
        f"responsible_ai_grc_security_report_{EXECUTION}.csv",
    ]
    assert s3.get_object.call_count == 2
    payload = _definition(selection)["States"]["Scan Regions"]["ItemProcessor"][
        "States"
    ]["OWASP Security Assessment"]["Parameters"]["Payload"]
    assert payload["ServiceSelection.$"] == "$.OriginalInput.ServiceSelection"


def test_report_distinguishes_not_selected_from_assessed_na_and_filters_unselected_rows():
    results = _results(dict.fromkeys(SERVICES, "true"))
    selection = {service: service == "bedrock" for service in SERVICES}
    html = consolidated_app.generate_html_report(results, service_selection=selection)
    soup = BeautifulSoup(html, "html.parser")
    assert "Not selected" in soup.select_one("#service-selection").get_text()
    for service in SERVICES:
        section = soup.select_one(f"#{service}")
        assert section is not None
        assert ("Not selected" in section.get_text()) == (service != "bedrock")
    assert '"SM-00"' not in html
    cards = soup.select("#risk .metric")
    for label in ("SageMaker", "AgentCore", "AWS Agent Registry"):
        card = next(card for card in cards if label in card.get_text())
        assert "Not selected" in card.get_text()
        assert "0 Passed" not in card.get_text()
    assert "Agentic AI Security contains only" in html
    default_html = consolidated_app.generate_html_report(results)
    assert "assessment-not-selected" not in default_html
    assert 'id="service-selection"' not in default_html


def test_empty_selection_generates_an_explicit_scope_report_without_artifacts():
    event = {
        "Execution": {"Name": EXECUTION},
        "OriginalInput": {
            "ServiceSelection": dict.fromkeys(SERVICES, "false"),
            "ResolvedRegions": {"regions": REGIONS},
        },
    }
    client = MagicMock()
    client.get_caller_identity.return_value = {"Account": "111122223333"}
    with (
        patch.object(consolidated_app.boto3, "client", return_value=client),
        patch.object(consolidated_app, "get_assessment_results", return_value={}),
        patch.object(
            consolidated_app, "write_html_to_s3", return_value="report.html"
        ) as write,
        patch.object(consolidated_app, "delete_permissions_cache"),
    ):
        response = consolidated_app.lambda_handler(event, None)
    assert response["statusCode"] == 200
    assert BeautifulSoup(write.call_args.args[0], "html.parser").select_one(
        "#service-selection"
    )


@pytest.mark.parametrize("empty", [False, True])
def test_multi_account_scope_matches_single_account_and_ignores_deselected_csvs(
    tmp_path, monkeypatch, empty
):
    account = tmp_path / "111122223333"
    account.mkdir()
    (account / "security_assessment_single_account_test.html").write_text(
        "scope report"
    )
    selection = {service: "false" for service in SERVICES}
    if not empty:
        selection["bedrock"] = "true"
        for service in SERVICES:
            row = _row(service)
            with (
                account
                / f"{service.replace('-', '_')}_security_report_test_us-east-1.csv"
            ).open("w") as stream:
                writer = csv.DictWriter(stream, fieldnames=list(row))
                writer.writeheader()
                writer.writerow(row)
    for service, (_, env, _) in SERVICES.items():
        monkeypatch.setenv(f"ENABLE_{env}", selection[service])
    monkeypatch.setenv("ACCOUNT_FILES_DIR", str(tmp_path))
    monkeypatch.setenv("BUCKET_REPORT", "test-assessment-bucket")
    client = MagicMock()
    with patch.object(multi_report.boto3, "client", return_value=client):
        multi_report.consolidate_html_reports()
    client.put_object.assert_called_once()
    html = client.put_object.call_args.kwargs["Body"]
    soup = BeautifulSoup(html, "html.parser")
    assert soup.select_one("#service-selection")
    assert "Not selected" in soup.select_one("#sagemaker").get_text()
    assert '"SM-00"' not in html
