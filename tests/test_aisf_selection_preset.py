"""AISF selection must expand collection and preserve evidence boundaries."""

from collections import Counter
from copy import deepcopy
from functools import lru_cache
import itertools
import json
import os
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace

import pytest
import yaml

from tests.test_aisf_catalog_alignment import (
    ACCOUNT,
    EXECUTION,
    OTHER_ACCOUNT,
    REGIONS,
    SERVICES,
    assert_check_inventory,
    matching_checks,
    embedded_register,
    multi,
    observation,
    single,
)
from tests.test_aisf_comprehensive_mapping import (
    native_rows,
    report_pair,
    source_owner,
)
from tests.test_optional_policy_baseline_wiring import CfnLoader

ROOT = Path(__file__).resolve().parents[1]
CORE = {
    "bedrock": ("Bedrock", "BEDROCK", "BedrockSecurityAssessmentFunction"),
    "sagemaker": ("SageMaker", "SAGEMAKER", "SagemakerSecurityAssessmentFunction"),
    "agentcore": ("AgentCore", "AGENTCORE", "AgentCoreSecurityAssessmentFunction"),
    "agent-registry": (
        "AgentRegistry",
        "AGENT_REGISTRY",
        "AgentRegistrySecurityAssessmentFunction",
    ),
}
GRC = "ResponsibleAIGRCAssessmentFunction"
OWASP = "OWASPSecurityAssessmentFunction"
REPORT = "GenerateConsolidatedReportFunction"
SAM_TEMPLATES = [
    "aiml-security-assessment/template.yaml",
    "aiml-security-assessment/template-multi-account.yaml",
]
CODEBUILD_TEMPLATES = [
    "deployment/aiml-security-single-account.yaml",
    "deployment/2-aiml-security-codebuild.yaml",
]
FLAG_MATRIX = list(itertools.product(("false", "true"), repeat=7))
MISSING = object()


@lru_cache
def template_document(path):
    return yaml.load((ROOT / path).read_text(), Loader=CfnLoader)


def cfn_value(value, document, parameters):
    if not isinstance(value, dict):
        return value
    if "Fn::Ref" in value:
        return parameters[value["Fn::Ref"]]
    if "Fn::Equals" in value:
        left, right = value["Fn::Equals"]
        return cfn_value(left, document, parameters) == cfn_value(
            right, document, parameters
        )
    if "Fn::If" in value:
        condition, yes, no = value["Fn::If"]
        enabled = cfn_value(document["Conditions"][condition], document, parameters)
        return cfn_value(yes if enabled else no, document, parameters)
    pytest.fail(f"Unsupported selection intrinsic: {value}")


@pytest.mark.parametrize("template", SAM_TEMPLATES + CODEBUILD_TEMPLATES)
def test_aisf_is_opt_in_in_every_deployment_entrypoint(template):
    document = template_document(template)
    declaration = document["Parameters"]["EnableAISFAssessment"]
    assert declaration["Default"] == "false"
    assert set(declaration["AllowedValues"]) == {"true", "false"}
    if template in CODEBUILD_TEMPLATES:
        project = next(
            resource
            for resource in document["Resources"].values()
            if resource["Type"] == "AWS::CodeBuild::Project"
        )
        variable = next(
            entry
            for entry in project["Properties"]["Environment"]["EnvironmentVariables"]
            if entry["Name"] == "ENABLE_AISF"
        )
        for value in ("false", "true"):
            assert (
                cfn_value(variable["Value"], document, {"EnableAISFAssessment": value})
                == value
            )


def definition(template, aisf, direct):
    document = template_document(template)
    parameters = {
        name: parameter.get("Default")
        for name, parameter in document["Parameters"].items()
    }
    parameters["EnableAISFAssessment"] = aisf
    for service, (parameter, _, _) in CORE.items():
        parameters[f"Enable{parameter}Assessment"] = direct[service]
    substitutions = document["Resources"]["AIMLAssessmentStateMachine"]["Properties"][
        "DefinitionSubstitutions"
    ]
    text = (
        ROOT / "aiml-security-assessment/statemachine/assessments.asl.json"
    ).read_text()
    names = ["EnableAISFAssessment", "MaxRegionConcurrency"] + [
        f"Enable{parameter}Assessment" for parameter, _, _ in CORE.values()
    ]
    for name in names:
        value = cfn_value(substitutions[name], document, parameters)
        text = text.replace("${" + name + "}", str(value))
    return json.loads(text)


def path_value(path, data, context):
    value = context if path.startswith("$$") else data
    suffix = path[2:] if path.startswith("$$") else path[1:]
    for dot, bracket in re.findall(r"\.([A-Za-z0-9_]+)|\['([^']+)'\]", suffix):
        if not isinstance(value, dict) or (dot or bracket) not in value:
            return MISSING
        value = value[dot or bracket]
    return value


def parameters_value(value, data, context):
    if isinstance(value, list):
        return [parameters_value(item, data, context) for item in value]
    if not isinstance(value, dict):
        return deepcopy(value)
    result = {}
    for key, item in value.items():
        if key.endswith(".$"):
            resolved = path_value(item, data, context)
            assert resolved is not MISSING, item
            result[key[:-2]] = deepcopy(resolved)
        else:
            result[key] = parameters_value(item, data, context)
    return result


def choice_matches(choice, data, context):
    if "And" in choice:
        return all(choice_matches(item, data, context) for item in choice["And"])
    if "Or" in choice:
        return any(choice_matches(item, data, context) for item in choice["Or"])
    if "Not" in choice:
        return not choice_matches(choice["Not"], data, context)
    value = path_value(choice["Variable"], data, context)
    if "IsPresent" in choice:
        return (value is not MISSING) == choice["IsPresent"]
    for operator, expected_type in (
        ("StringEquals", str),
        ("NumericEquals", int),
        ("BooleanEquals", bool),
    ):
        if operator in choice:
            return type(value) is expected_type and value == choice[operator]
    pytest.fail(f"Unsupported workflow choice: {choice}")


def merge_result(data, result, path="$"):
    if path is None:
        return deepcopy(data)
    if path == "$":
        return deepcopy(result)
    assert re.fullmatch(r"\$\.[A-Za-z0-9_]+", path), path
    return {**deepcopy(data), path[2:]: deepcopy(result)}


def run_workflow(machine, data, calls, context, fail_function=None):
    """Execute the shipped ASL; replace Lambda IO with success/failure receipts."""
    name = machine["StartAt"]
    for _ in range(40):
        state = machine["States"][name]
        kind = state["Type"]
        if kind == "Choice":
            name = next(
                (
                    choice["Next"]
                    for choice in state["Choices"]
                    if choice_matches(choice, data, context)
                ),
                state["Default"],
            )
            continue
        if kind == "Fail":
            raise ValueError(state["Error"])
        if kind == "Pass":
            result = (
                parameters_value(state["Parameters"], data, context)
                if "Parameters" in state
                else deepcopy(state.get("Result", data))
            )
        elif kind == "Task":
            arguments = parameters_value(state["Parameters"], data, context)
            function = arguments["FunctionName"].removeprefix("${").removesuffix("}")
            calls.append((function, arguments["Payload"]))
            if function == fail_function:
                catcher = state["Catch"][0]
                assert "States.ALL" in catcher["ErrorEquals"]
                data = merge_result(
                    data,
                    {"Error": "SyntheticCollectorFailure", "Cause": "Access denied"},
                    catcher["ResultPath"],
                )
                name = catcher["Next"]
                continue
            payload = (
                {"regions": REGIONS}
                if function == "ResolveRegionsFunction"
                else {"statusCode": 200}
            )
            result = {"Payload": payload}
        elif kind == "Parallel":
            result = [
                run_workflow(branch, deepcopy(data), calls, context, fail_function)
                for branch in state["Branches"]
            ]
        elif kind == "Map":
            result = []
            for index, item in enumerate(path_value(state["ItemsPath"], data, context)):
                item_context = {
                    **context,
                    "Map": {"Item": {"Value": item, "Index": index}},
                }
                item_input = parameters_value(state["ItemSelector"], data, item_context)
                result.append(
                    run_workflow(
                        state["ItemProcessor"],
                        item_input,
                        calls,
                        item_context,
                        fail_function,
                    )
                )
        else:
            pytest.fail(f"Unsupported workflow state: {kind}")
        if "ResultSelector" in state:
            result = parameters_value(state["ResultSelector"], result, context)
        data = merge_result(data, result, state.get("ResultPath", "$"))
        if "OutputPath" in state:
            data = path_value(state["OutputPath"], data, context)
            assert data is not MISSING
        if state.get("End"):
            return data
        name = state["Next"]
    pytest.fail("Workflow did not terminate")


def execution(template, aisf, direct, optional=None, fail_function=None):
    calls = []
    run_workflow(
        definition(template, aisf, direct),
        optional or {},
        calls,
        {
            "Execution": {
                "Name": EXECUTION,
                "Id": f"arn:aws:states:{REGIONS[0]}:{ACCOUNT}:execution:test:{EXECUTION}",
            },
            "StateMachine": {"Name": "synthetic-aisf"},
        },
        fail_function,
    )
    original = next(
        payload["OriginalInput"] for function, payload in calls if function == REPORT
    )
    return calls, original


@pytest.mark.parametrize("template", SAM_TEMPLATES)
@pytest.mark.parametrize("flags", FLAG_MATRIX)
def test_sam_preset_executes_effective_collectors_and_preserves_disabled_selection(
    template, flags
):
    aisf, *direct_values, grc, owasp = flags
    direct = dict(zip(CORE, direct_values))
    calls, original = execution(
        template,
        aisf,
        direct,
        {"enableResponsibleAIGRC": grc, "enableOWASP": owasp},
    )
    effective = {
        owner: "true" if aisf == "true" else value for owner, value in direct.items()
    }
    assert original["ServiceSelection"] == effective
    assert original["enableAISF"] == aisf
    assert original["enableResponsibleAIGRC"] == ("true" if aisf == "true" else grc)
    assert original["enableOWASP"] == ("true" if aisf == "true" else owasp)
    expected = Counter(
        (function, region)
        for owner, (_, _, function) in CORE.items()
        if effective[owner] == "true"
        for region in REGIONS
    )
    if "true" in (aisf, grc, owasp):
        expected[(GRC, REGIONS[0])] = 1
    if "true" in (aisf, owasp):
        expected.update((OWASP, region) for region in REGIONS)
    collectors = {item[2] for item in CORE.values()} | {GRC, OWASP}
    assert (
        Counter(
            (function, payload["Region"])
            for function, payload in calls
            if function in collectors
        )
        == expected
    )
    for function, payload in calls:
        if function == OWASP:
            assert payload["ServiceSelection"] == effective
        if function == GRC:
            assert payload["RegionIndex"] == 0
            assert payload["TargetRegions"] == REGIONS


@pytest.mark.parametrize("template", SAM_TEMPLATES)
@pytest.mark.parametrize("aisf", ["false", "true"])
def test_deployment_preset_works_without_execution_flags_and_cannot_be_overridden(
    template, aisf
):
    direct = dict.fromkeys(CORE, "false")
    for optional in ({}, {"enableAISF": "false" if aisf == "true" else "true"}):
        calls, original = execution(template, aisf, direct, optional)
        assert original["enableAISF"] == aisf
        assert sum(function == OWASP for function, _ in calls) == (
            len(REGIONS) if aisf == "true" else 0
        )
    with pytest.raises(ValueError, match="LegacyEnableFinServInputRejected"):
        execution(template, aisf, direct, {"enableFinServ": "true"})


@lru_cache
def buildspec():
    return yaml.safe_load((ROOT / "buildspec.yml").read_text())


def build_preamble():
    commands = buildspec()["phases"]["build"]["commands"]
    end = next(
        index
        for index, command in enumerate(commands)
        if "SAM_TARGET_REGIONS_PARAMETER=" in command
    )
    return "\n".join(commands[: end + 1])


def bash_output(script, environment):
    clean = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("ENABLE_", "SAM_", "AWS_", "TARGET_REGIONS"))
    }
    clean.update(
        AWS_DEFAULT_REGION=REGIONS[0],
        AWS_ACCOUNT_ID=ACCOUNT,
        MULTI_ACCOUNT_SCAN="false",
        BUCKET_REPORT="synthetic-assessment-reports",
        TARGET_REGIONS=",".join(REGIONS),
    )
    process = subprocess.run(
        ["bash", "-c", script],
        env={**clean, **environment},
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    return process


def flag_environment(flags):
    aisf, *direct, grc, owasp = flags
    return {
        "ENABLE_AISF": aisf,
        "ENABLE_RESPONSIBLE_AI_GRC": grc,
        "ENABLE_OWASP": owasp,
        **{
            "ENABLE_" + environment: value
            for (_, environment, _), value in zip(CORE.values(), direct)
        },
    }


def postbuild_fragment(start, end):
    text = (ROOT / "buildspec.yml").read_text()
    return text[text.index(start) : text.index(end, text.index(start))]


@pytest.mark.parametrize("flags", FLAG_MATRIX)
def test_codebuild_effective_scope_reaches_deploy_artifacts_copy_and_history(flags):
    environment = flag_environment(flags)
    aisf, *direct, grc, owasp = flags
    effective = dict(
        zip(CORE, (True,) * 4 if aisf == "true" else (v == "true" for v in direct))
    )
    expected_prefixes = {
        owner.replace("-", "_") for owner, selected in effective.items() if selected
    }
    if "true" in (aisf, grc, owasp):
        expected_prefixes.add("responsible_ai_grc")
    if "true" in (aisf, owasp):
        expected_prefixes.add("owasp")
    deploys = re.findall(
        r"\bsam deploy\b[^\n]*?(?=; then)", (ROOT / "buildspec.yml").read_text()
    )
    assert len(deploys) == 3
    required = postbuild_fragment(
        "                required_artifact_prefixes=()",
        "                artifacts_complete=true",
    )
    copy_selection = postbuild_fragment(
        "        fs_exclude_args=()", '\n        # "Changes since last assessment"'
    )
    receipt = (
        postbuild_fragment(
            "        record_assessment_run() {",
            "\n        }\n",
        )
        + "\n}"
    )
    script = "\n".join(
        [
            build_preamble(),
            'sam() { printf "DEPLOY:%s\\n" "$@"; }',
            *deploys,
            "\n".join(f"export {key}={value}" for key, value in environment.items()),
            buildspec()["phases"]["post_build"]["commands"][0],
            required,
            'printf "ARTIFACT:%s\\n" "${required_artifact_prefixes[@]}"',
            copy_selection,
            'printf "EXCLUDE:%s\\n" "${fs_exclude_args[@]}"',
            "aws() { cat; }",
            receipt,
            f'record_assessment_run "{EXECUTION}" SUCCEEDED false',
        ]
    )
    process = bash_output(script, environment)
    assert process.returncode == 0, process.stderr + process.stdout
    lines = process.stdout.splitlines()
    assert {
        line.removeprefix("ARTIFACT:")
        for line in lines
        if line.startswith("ARTIFACT:") and line != "ARTIFACT:"
    } == expected_prefixes
    assert ("EXCLUDE:responsible_ai_grc_security_report_*.csv" in lines) == (
        aisf != "true" and grc != "true"
    )
    record = json.loads(
        next(line for line in lines if line.startswith('{"execution_id"'))
    )
    assert record["selected_services"] == effective
    assert record["succeeded"] is True
    for owner, (parameter, _, _) in CORE.items():
        argument = f"DEPLOY:ParameterKey=Enable{parameter}Assessment,ParameterValue={str(effective[owner]).lower()}"
        assert lines.count(argument) == 3
    assert (
        lines.count(f"DEPLOY:ParameterKey=EnableAISFAssessment,ParameterValue={aisf}")
        == 3
    )
    for parameter in (
        "EnableAgentCoreArtifactObjectReads",
        "EnableSageMakerArtifactObjectReads",
    ):
        assert lines.count(f"DEPLOY:ParameterKey={parameter},ParameterValue=false") == 3


@pytest.mark.parametrize("aisf", ["false", "true"])
def test_codebuild_legacy_alias_conflict_still_fails_before_preset(aisf):
    process = bash_output(
        build_preamble(),
        {
            "ENABLE_AISF": aisf,
            "ENABLE_RESPONSIBLE_AI_GRC": "true",
            "ENABLE_FINSERV": "false",
        },
    )
    assert process.returncode != 0
    assert "These are aliases for the same toggle and must agree" in process.stdout
    alias = bash_output(
        build_preamble() + '\nprintf "GRC:%s\\n" "$ENABLE_RESPONSIBLE_AI_GRC"',
        {"ENABLE_AISF": aisf, "ENABLE_FINSERV": "true"},
    )
    assert alias.returncode == 0, alias.stdout + alias.stderr
    assert "GRC:true" in alias.stdout


@pytest.mark.parametrize("template", SAM_TEMPLATES)
def test_aisf_does_not_enable_optional_object_content_reads(template):
    document = template_document(template)
    parameters = {
        name: item.get("Default") for name, item in document["Parameters"].items()
    }
    parameters["EnableAISFAssessment"] = "true"
    for function, parameter, variable in (
        (
            "AgentCoreSecurityAssessmentFunction",
            "EnableAgentCoreArtifactObjectReads",
            "ENABLE_AGENTCORE_ARTIFACT_OBJECT_READS",
        ),
        (
            "SagemakerSecurityAssessmentFunction",
            "EnableSageMakerArtifactObjectReads",
            "ENABLE_SAGEMAKER_ARTIFACT_OBJECT_READS",
        ),
    ):
        assert parameters[parameter] == "false"
        value = document["Resources"][function]["Properties"]["Environment"][
            "Variables"
        ][variable]
        assert cfn_value(value, document, parameters) == "false"


def test_aisf_alone_preserves_native_ai_check_results_in_both_reports(
    tmp_path,
):
    _, original = execution(
        SAM_TEMPLATES[0],
        "true",
        dict.fromkeys(CORE, "false"),
        {"enableResponsibleAIGRC": "false", "enableOWASP": "false"},
    )
    selection = {
        owner: enabled == "true"
        for owner, enabled in original["ServiceSelection"].items()
    }
    rows = native_rows()
    for html in report_pair(
        tmp_path,
        rows,
        selection=selection,
        grc=original["enableResponsibleAIGRC"] == "true",
        owasp=original["enableOWASP"] == "true",
    ):
        register = embedded_register(html)
        assert_check_inventory(register)
        for row in rows:
            matches = matching_checks(register, row["Check_ID"])
            assert matches, row["Check_ID"]
            assert all(check["status"] == "Failed" for check in matches)
        assert {check["source_check_id"] for check in register["checks"]} == {
            row["Check_ID"] for row in rows
        }


def complete_evidence():
    rows = native_rows()
    results = {
        "account_id": ACCOUNT,
        "execution_id": EXECUTION,
        "expected_regions": REGIONS,
        "enable_owasp": True,
    }
    for owner in (*SERVICES, "responsible-ai-grc", "owasp"):
        results[owner] = {}
        for region in REGIONS[:1] if owner == "responsible-ai-grc" else REGIONS:
            accepted = [
                row
                for row in rows
                if source_owner(row["Check_ID"]) == owner
                and row["Region"] in (region, "Global")
            ] or [
                observation(
                    {
                        "bedrock": "BR-00",
                        "sagemaker": "SM-00",
                        "agentcore": "AC-00",
                        "agent-registry": "AR-00",
                        "responsible-ai-grc": "FS-00",
                        "owasp": "OW-00",
                    }[owner],
                    "N/A",
                    region=region,
                    Finding="Assessment complete",
                )
            ]
            suffix = "" if owner == "responsible-ai-grc" else "_" + region
            stem = f"{owner.replace('-', '_')}_security_report_{EXECUTION}{suffix}"
            results[owner][stem] = accepted
    return results


@pytest.mark.parametrize("aisf", ["false", "true"])
def test_lambda_preserves_preset_marker_and_ai_evidence_in_written_report(
    monkeypatch, aisf
):
    _, original = execution(
        SAM_TEMPLATES[0],
        aisf,
        dict.fromkeys(CORE, "true"),
        {"enableResponsibleAIGRC": "true", "enableOWASP": "true"},
    )
    monkeypatch.setenv("AIML_ASSESSMENT_BUCKET_NAME", "synthetic-assessment-reports")
    monkeypatch.setattr(
        single.boto3,
        "client",
        lambda *args, **kwargs: SimpleNamespace(
            get_caller_identity=lambda: {"Account": ACCOUNT}
        ),
    )
    monkeypatch.setattr(
        single, "get_assessment_results", lambda *args, **kwargs: complete_evidence()
    )
    written = []
    cleaned = []
    monkeypatch.setattr(
        single,
        "write_html_to_s3",
        lambda html, *args: written.append(html) or "synthetic-report.html",
    )
    monkeypatch.setattr(
        single, "delete_permissions_cache", lambda *args: cleaned.append(args)
    )
    result = single.lambda_handler(
        {"Execution": {"Name": EXECUTION}, "OriginalInput": original}, None
    )
    assert result["statusCode"] == 200
    assert len(written) == len(cleaned) == 1
    register = embedded_register(written[0])
    assert_check_inventory(register)
    assert register["scope"]["enable_aisf"] is (aisf == "true")
    assert ("AISF assessment preset enabled" in written[0]) is (aisf == "true")
    for row in native_rows():
        assert matching_checks(register, row["Check_ID"]), row["Check_ID"]


@pytest.mark.parametrize("aisf", ["false", "true"])
def test_multi_account_runtime_preserves_preset_marker_from_build_environment(
    tmp_path, monkeypatch, aisf
):
    report_pair(tmp_path, native_rows())
    manifest = tmp_path / "scope.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "accounts": [
                    {
                        "account_id": account,
                        "execution_id": EXECUTION,
                        "regions": REGIONS,
                        "status": "SUCCEEDED",
                    }
                    for account in (ACCOUNT, OTHER_ACCOUNT)
                ],
            }
        )
    )
    for key, value in flag_environment((aisf,) + ("true",) * 6).items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("BUCKET_REPORT", "synthetic-assessment-reports")
    monkeypatch.setenv("ASSESSMENT_SCOPE_MANIFEST", str(manifest))
    monkeypatch.setattr(multi, "_account_files_dir", lambda: tmp_path)
    written = []
    monkeypatch.setattr(
        multi.boto3,
        "client",
        lambda *args, **kwargs: SimpleNamespace(
            put_object=lambda **kwargs: written.append(kwargs)
        ),
    )
    multi.consolidate_html_reports()
    assert len(written) == 1
    html = written[0]["Body"]
    if isinstance(html, bytes):
        html = html.decode()
    register = embedded_register(html)
    assert_check_inventory(register)
    assert register["scope"]["enable_aisf"] is (aisf == "true")
    assert ("AISF assessment preset enabled" in html) is (aisf == "true")
    for row in native_rows():
        assert matching_checks(register, row["Check_ID"]), row["Check_ID"]


@pytest.mark.parametrize("mode", ["single", "multi"])
def test_requested_preset_with_partial_scope_keeps_flags_and_reports_incomplete(
    tmp_path, mode
):
    selection = {owner: owner == "bedrock" for owner in CORE}
    if mode == "single":
        results = complete_evidence()
        results = {
            key: value
            for key, value in results.items()
            if key not in (*CORE, "responsible-ai-grc", "owasp") or key == "bedrock"
        }
        results["enable_owasp"] = False
        html = single.generate_html_report(
            results,
            show_finserv=False,
            service_selection=selection,
            enable_aisf=True,
        )
    else:
        report_pair(
            tmp_path, native_rows(), selection=selection, grc=False, owasp=False
        )
        results = multi.load_multi_account_results(
            tmp_path,
            service_selection=selection,
            show_finserv=False,
            enable_owasp=False,
            enable_aisf=True,
        )
        html = multi.render_multi_account_report(results)
    register = embedded_register(html)
    assert_check_inventory(register)
    assert register["scope"]["enable_aisf"] is True
    assert register["scope"]["source_selection"] == {
        **selection,
        "responsible-ai-grc": False,
        "owasp": False,
    }
    assert "AISF assessment preset enabled" not in html
    assert "AISF assessment preset requested; effective scope is incomplete." in html
    assert "Effective collectors: Amazon Bedrock." in html


@pytest.mark.parametrize("failed", [GRC, OWASP, CORE["agentcore"][2]])
def test_aisf_caught_collector_failure_reaches_artifact_validation_and_register(failed):
    _, original = execution(
        SAM_TEMPLATES[0], "true", dict.fromkeys(CORE, "false"), fail_function=failed
    )
    results = complete_evidence()
    with pytest.raises(ValueError, match="Incomplete assessment artifacts"):
        single.validate_assessment_artifacts(
            results, EXECUTION, original, require_receipts=True
        )
    failed_owner = {
        GRC: "responsible-ai-grc",
        OWASP: "owasp",
        CORE["agentcore"][2]: "agentcore",
    }[failed]
    assert any(issue["owner"] == failed_owner for issue in results["artifact_issues"])
    html = single.generate_html_report(
        results, show_finserv=True, service_selection=original["ServiceSelection"]
    )
    register = embedded_register(html)
    assert_check_inventory(register)
    assert register["gaps"]
    assert any(issue["owner"] == failed_owner for issue in register["artifact_issues"])
