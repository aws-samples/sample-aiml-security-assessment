"""Wiring for the changes report: buildspec.yml, deployment templates, CI.

The buildspec.yml function is extracted verbatim and run in bash with
stand-in ``python3`` and ``timeout`` commands (the approach of
test_fs_exclude_args.py). Templates are parsed with a loader that tolerates
CloudFormation intrinsics (as in test_optional_policy_baseline_wiring.py).
"""

import os
import re
import subprocess
import time
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
BUILDSPEC = REPO_ROOT / "buildspec.yml"
TEMPLATES = [
    REPO_ROOT / "deployment" / "aiml-security-single-account.yaml",
    REPO_ROOT / "deployment" / "2-aiml-security-codebuild.yaml",
]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "python-tests.yml"

PYTHON_STANDIN = """#!/bin/bash
{ echo "cwd=$PWD"; echo "setting=$ENABLE_ASSESSMENT_HISTORY"; printf 'arg=%s\\n' "$@"; } > "$STANDIN_LOG"
exit "${STANDIN_EXIT:-0}"
"""
TIMEOUT_STANDIN = """#!/bin/bash
echo "limit=$1" > "$STANDIN_LOG.timeout"
shift
exec "$@"
"""


# --- buildspec.yml ------------------------------------------------------------


def _post_build():
    with BUILDSPEC.open(encoding="utf-8") as handle:
        commands = yaml.safe_load(handle)["phases"]["post_build"]["commands"]
    return "\n".join(command for command in commands if isinstance(command, str))


def _function_script():
    lines = _post_build().splitlines()
    start = next(
        index
        for index, line in enumerate(lines)
        if line.startswith("run_changes_report() {")
    )
    end = next(index for index in range(start + 1, len(lines)) if lines[index] == "}")
    return "\n".join(lines[start : end + 1])


def _run_function(tmp_path, env=None):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("python3", PYTHON_STANDIN), ("timeout", TIMEOUT_STANDIN)):
        path = bin_dir / name
        path.write_text(body, encoding="utf-8")
        path.chmod(0o755)
    work = tmp_path / "repo" / "aiml-security-assessment"
    work.mkdir(parents=True)
    log = tmp_path / "python.log"
    script = (
        _function_script()
        + "\nrun_changes_report --accounts 123456789012 --execution-id run-c"
        + '\necho "status=$?"\n'
    )
    result = subprocess.run(
        ["bash", "-c", script],
        cwd=work,
        env={
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "BUCKET_REPORT": "central-bucket",
            "STANDIN_LOG": str(log),
            **(env or {}),
        },
        capture_output=True,
        text=True,
        timeout=20,
    )
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else None
    limit_file = tmp_path / "python.log.timeout"
    limit = (
        limit_file.read_text(encoding="utf-8").strip() if limit_file.exists() else None
    )
    return result.stdout.splitlines(), calls, limit


def test_the_step_runs_the_tool_from_the_repo_root(tmp_path):
    stdout, calls, limit = _run_function(tmp_path)
    assert stdout == ["Creating changes-since-last-assessment reports...", "status=0"]
    assert calls == [
        f"cwd={os.path.realpath(tmp_path / 'repo')}",
        "setting=true",
        "arg=-m",
        "arg=assessment_history",
        "arg=compare",
        "arg=--bucket",
        "arg=central-bucket",
        "arg=--time-budget",
        "arg=300",
        "arg=--accounts",
        "arg=123456789012",
        "arg=--execution-id",
        "arg=run-c",
    ]
    assert limit == "limit=300"


@pytest.mark.parametrize("value", ["false", "False"])
def test_the_step_does_nothing_when_the_setting_is_off(tmp_path, value):
    stdout, calls, _limit = _run_function(
        tmp_path, {"ENABLE_ASSESSMENT_HISTORY": value}
    )
    assert stdout == [
        "Changes report disabled (EnableAssessmentHistory=false)",
        "status=0",
    ]
    assert calls is None


def test_an_unrecognized_setting_is_reported_and_treated_as_on(tmp_path):
    stdout, calls, _limit = _run_function(
        tmp_path, {"ENABLE_ASSESSMENT_HISTORY": "yes"}
    )
    assert stdout[0] == (
        "WARNING: ENABLE_ASSESSMENT_HISTORY is 'yes', not true or false; using true"
    )
    assert calls[1] == "setting=true"


def test_the_step_is_skipped_when_little_build_time_is_left(tmp_path):
    started_ms = str(int((time.time() - 3500) * 1000))
    stdout, calls, _limit = _run_function(
        tmp_path, {"CODEBUILD_START_TIME": started_ms, "BUILD_TIMEOUT_MINUTES": "60"}
    )
    assert re.fullmatch(
        r"WARNING: Changes report skipped: only \d+s of build time left", stdout[0]
    )
    assert stdout[-1] == "status=0"
    assert calls is None


def test_the_step_runs_when_enough_build_time_is_left(tmp_path):
    started_ms = str(int((time.time() - 60) * 1000))
    _stdout, calls, limit = _run_function(
        tmp_path, {"CODEBUILD_START_TIME": started_ms, "BUILD_TIMEOUT_MINUTES": "60"}
    )
    assert calls is not None
    assert limit == "limit=300"


def test_a_failing_tool_is_a_warning_and_never_fails_the_build(tmp_path):
    stdout, _calls, _limit = _run_function(tmp_path, {"STANDIN_EXIT": "1"})
    assert stdout[-2:] == [
        "WARNING: The changes report step did not complete; "
        "assessment results are not affected",
        "status=0",
    ]


def test_the_step_never_writes_the_failure_ledger():
    script = _function_script()
    assert "record_failure" not in script
    assert "ASSESSMENT_FAILURES_FILE" not in script


def test_the_step_is_defined_once_and_called_once_per_branch():
    text = _post_build()
    calls = re.findall(r"^\s*run_changes_report --", text, flags=re.MULTILINE)
    assert len(calls) == 2
    assert text.index("run_changes_report() {") < text.index("run_changes_report --")


def test_multi_account_step_runs_after_the_multi_account_report():
    text = _post_build()
    call = text.index('run_changes_report --accounts "$account_list"')
    line = text[call : text.index("\n", call)]
    assert (
        text.index("python3 ../consolidate_html_reports.py")
        < call
        < text.index("Multi-account assessment incomplete")
    )
    assert "--execution-arn-dir /tmp/execution_arns" in line
    assert '--failures-file "$ASSESSMENT_FAILURES_FILE"' in line


def test_single_account_step_runs_after_the_sync_and_only_if_the_run_succeeded():
    text = _post_build()
    call = text.index('run_changes_report --accounts "$AWS_ACCOUNT_ID"')
    assert (
        text.index("Syncing results to consolidated bucket")
        < call
        < text.index("ERROR: Assessment failed.")
    )
    before = [line.strip() for line in text[:call].rstrip().splitlines()[-3:]]
    assert before == [
        "if [[ $sf_failed == true ]]; then",
        'echo "Changes report skipped: the assessment run did not succeed"',
        "else",
    ]
    assert (
        '--execution-id "${EXECUTION_ARN##*:}"' in text[call : text.index("\n", call)]
    )


# --- deployment templates -------------------------------------------------------


class _CfnLoader(yaml.SafeLoader):
    """SafeLoader that tolerates CloudFormation short-form intrinsics."""


def _construct_intrinsic(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return {f"Fn::{tag_suffix}": loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {f"Fn::{tag_suffix}": loader.construct_sequence(node)}
    return {f"Fn::{tag_suffix}": loader.construct_mapping(node)}


_CfnLoader.add_multi_constructor("!", _construct_intrinsic)


@pytest.fixture(params=TEMPLATES, ids=lambda path: path.name)
def template(request):
    with request.param.open(encoding="utf-8") as handle:
        return yaml.load(handle, Loader=_CfnLoader)  # nosec B506


def test_setting_parameter_defaults_to_on(template):
    parameter = template["Parameters"]["EnableAssessmentHistory"]
    assert parameter["Type"] == "String"
    assert parameter["AllowedValues"] == ["true", "false"]
    assert parameter["Default"] == "true"
    assert parameter["Description"]


def test_setting_is_listed_with_the_other_assessment_options(template):
    interface = template["Metadata"]["AWS::CloudFormation::Interface"]
    (group,) = [
        group
        for group in interface["ParameterGroups"]
        if group["Label"]["default"] == "Assessment Options"
    ]
    names = group["Parameters"]
    assert names[names.index("EnableOWASPAssessment") + 1] == "EnableAssessmentHistory"
    assert interface["ParameterLabels"]["EnableAssessmentHistory"]["default"]


def test_setting_reaches_codebuild(template):
    projects = [
        resource
        for resource in template["Resources"].values()
        if resource.get("Type") == "AWS::CodeBuild::Project"
    ]
    variables = [
        variable
        for project in projects
        for variable in project["Properties"]["Environment"].get(
            "EnvironmentVariables", []
        )
        if variable["Name"] == "ENABLE_ASSESSMENT_HISTORY"
    ]
    assert variables == [
        {
            "Name": "ENABLE_ASSESSMENT_HISTORY",
            "Value": {"Fn::Ref": "EnableAssessmentHistory"},
            "Type": "PLAINTEXT",
        }
    ]


# --- CI workflow -------------------------------------------------------------------


@pytest.fixture(scope="module")
def workflow():
    with WORKFLOW.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def test_ci_runs_when_the_package_or_its_inputs_change(workflow):
    # PyYAML reads the bare key "on" as True.
    triggers = workflow.get("on", workflow.get(True))
    for event in ("push", "pull_request"):
        paths = triggers[event]["paths"]
        # The package, the build step and templates the wiring tests read, and
        # the sample reports the golden tests read.
        for path in (
            "assessment_history/**",
            "buildspec.yml",
            "deployment/**",
            "sample-reports/**",
        ):
            assert path in paths, (event, path)


def test_ci_enforces_full_coverage_for_the_package(workflow):
    runs = [
        step.get("run", "")
        for job in workflow["jobs"].values()
        for step in job["steps"]
    ]
    gate = [run for run in runs if "--cov=assessment_history" in run]
    assert len(gate) == 1
    for flag in (
        "tests/test_assessment_history_*.py",
        "--cov-branch",
        "--cov-fail-under=100",
    ):
        assert flag in gate[0], flag


def test_ci_actions_are_pinned_to_commits(workflow):
    uses = [
        step["uses"]
        for job in workflow["jobs"].values()
        for step in job["steps"]
        if "uses" in step
    ]
    assert uses
    for reference in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", reference), reference


def test_ci_token_can_only_read(workflow):
    assert workflow["permissions"] == {"contents": "read"}
