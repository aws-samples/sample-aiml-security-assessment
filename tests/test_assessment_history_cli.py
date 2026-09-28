"""Command line: python3 -m assessment_history compare.

S3 is replaced by FakeS3 from tests/assessment_history_helpers.py; boto3 is
patched only where the real client would be created. Output lines are
collected instead of printed.
"""

import csv
import io
import os
import runpy
import sys
import warnings
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from assessment_history import __main__ as cli
from assessment_history.discover import StoredFile, parse_report_name
from assessment_history.models import CORE_MODULES, CSV_COLUMNS, Comparison
from assessment_history.render_common import RenderError
from tests.assessment_history_helpers import (
    ACCOUNT,
    OTHER_ACCOUNT,
    FakeS3,
    make_finding,
    put_run,
    report_name,
    utc,
)

BUCKET = "central-bucket"
MGMT = "777788889999"
MISSING = "444455556666"
CHANGES_KEY = f"{ACCOUNT}/security_assessment_changes_20260927_000000.csv"
CHANGES_PAGE_KEY = CHANGES_KEY.replace(".csv", ".html")


def _run(argv, *, s3=None, environ=None, clock=None):
    lines = []
    options = {
        "s3_client": s3,
        "environ": {} if environ is None else environ,
        "out": lines.append,
    }
    if clock is not None:
        options["clock"] = clock
    return cli.main(argv, **options), lines


def _single(execution_id="run-c"):
    return [
        "compare",
        "--bucket",
        BUCKET,
        "--accounts",
        ACCOUNT,
        "--execution-id",
        execution_id,
    ]


def _cannot(account, reason):
    return (
        f"WARNING: Changes report cannot be completed for account {account}. "
        f"Reason(s): {reason}."
    )


# --- S3 mode: one account ------------------------------------------------------


def test_single_account_writes_the_changes_csv():
    s3 = FakeS3()
    put_run(s3, "run-p", utc(3, 23, 37), [make_finding("BR-01", "Passed")])
    put_run(s3, "run-c", utc(27, 6, 15), [make_finding("BR-01", details="Role x")])
    code, lines = _run(_single(), s3=s3)

    key = f"{ACCOUNT}/security_assessment_changes_20260927_061500.csv"
    page_key = key.replace(".csv", ".html")
    assert code == 0
    assert s3.writes == [
        (key, "text/csv; charset=utf-8"),
        (page_key, "text/html; charset=utf-8"),
    ]
    assert lines == [
        f"Changes report for account {ACCOUNT}",
        "  Compared run run-c (saved 2026-09-27T06:15:00Z) with run run-p "
        "(saved 2026-09-03T23:37:00Z), 24 day(s) apart",
        "  Bedrock, SageMaker, AgentCore, Agent Registry: Regressed 1, New 0, "
        "Still open 0, Resolved 0, No longer reported 0, No longer assessed 0",
        f"  Written: s3://{BUCKET}/{key}",
        f"  Written: s3://{BUCKET}/{page_key}",
    ]
    page = s3.objects[page_key][0].decode("utf-8")
    assert "Changes Since Last Assessment" in page
    assert 'href="security_assessment_changes_20260927_061500.csv"' in page
    assert "open main report" not in page  # no main report in the folder
    rows = list(csv.DictReader(io.StringIO(s3.objects[key][0].decode("utf-8"))))
    assert tuple(rows[0]) == CSV_COLUMNS
    assert len(rows) == 4
    (regressed,) = [row for row in rows if row["Change"] == "Regressed"]
    assert (
        regressed["Check_ID"],
        regressed["Match_Rule"],
        regressed["Previous_Execution_ID"],
        regressed["Current_Execution_ID"],
    ) == ("BR-01", "single-row", "run-p", "run-c")


def test_first_run_writes_nothing():
    s3 = FakeS3()
    put_run(s3, "run-c", utc(27))
    code, lines = _run(_single(), s3=s3)
    assert (code, s3.writes) == (0, [])
    assert lines == [
        f"Changes report for account {ACCOUNT}",
        f"  {cli.first_run_note(ACCOUNT)}",
    ]


def test_no_changes_still_writes_the_csv():
    s3 = FakeS3()
    put_run(s3, "run-p", utc(3))
    put_run(s3, "run-c", utc(27))
    code, lines = _run(_single(), s3=s3)
    assert code == 0
    assert lines[2] == "  No changes since the last assessment"
    assert [key for key, _ in s3.writes] == [CHANGES_KEY, CHANGES_PAGE_KEY]


def test_modules_regions_and_check_ids_in_only_one_run_are_listed():
    s3 = FakeS3()
    put_run(s3, "run-p", utc(3), [make_finding("BR-01")])
    extra = [make_finding(f"BR-{number}") for number in range(40, 52)]
    put_run(
        s3,
        "run-c",
        utc(27),
        [make_finding("BR-01"), *extra],
        regions=("us-east-1", "us-west-2"),
        modules=CORE_MODULES + ("owasp",),
    )
    code, lines = _run(_single(), s3=s3)
    listed = ", ".join(f"BR-{number} (current run only)" for number in range(40, 50))
    assert lines[2:] == [
        "  Bedrock, SageMaker, AgentCore, Agent Registry: Regressed 0, New 12, "
        "Still open 1, Resolved 0, No longer reported 0, No longer assessed 0",
        "  Not compared (enabled in only one run): owasp (current run only)",
        "  Not compared (scanned in only one run): us-west-2 (current run only)",
        f"  Check IDs found in only one run: {listed}, and 2 more",
        f"  Written: s3://{BUCKET}/{CHANGES_KEY}",
        f"  Written: s3://{BUCKET}/{CHANGES_PAGE_KEY}",
    ]


# --- the setting ----------------------------------------------------------------


@pytest.mark.parametrize("value", ["false", "False", " FALSE "])
def test_setting_off_makes_no_aws_calls(value):
    with patch("boto3.client") as client:
        code, lines = _run(_single(), environ={"ENABLE_ASSESSMENT_HISTORY": value})
    assert (code, lines) == (
        0,
        ["Changes report disabled (EnableAssessmentHistory=false)"],
    )
    client.assert_not_called()


@pytest.mark.parametrize(
    "environ, enabled, warnings_out",
    [
        ({}, True, []),
        ({"ENABLE_ASSESSMENT_HISTORY": "TRUE"}, True, []),
        ({"ENABLE_ASSESSMENT_HISTORY": "false"}, False, []),
        (
            {"ENABLE_ASSESSMENT_HISTORY": "yes"},
            True,
            [
                "WARNING: ENABLE_ASSESSMENT_HISTORY='yes' is not true or false; using true"
            ],
        ),
        (
            {"ENABLE_ASSESSMENT_HISTORY": ""},
            True,
            ["WARNING: ENABLE_ASSESSMENT_HISTORY='' is not true or false; using true"],
        ),
    ],
)
def test_history_enabled(environ, enabled, warnings_out):
    lines = []
    assert cli.history_enabled(environ, lines.append) is enabled
    assert lines == warnings_out


# --- S3 mode: several accounts -------------------------------------------------------


def _arn_dir(tmp_path, runs):
    folder = tmp_path / "execution_arns"
    folder.mkdir()
    for account, execution_id in runs.items():
        arn = f"arn:aws:states:us-east-1:{account}:execution:sm:{execution_id}\n"
        (folder / f"{account}.txt").write_text(arn, encoding="utf-8")
    return folder


def test_several_accounts_with_failures_missing_arns_and_notes(tmp_path):
    s3 = FakeS3()
    put_run(s3, "run-p", utc(3))
    put_run(s3, "run-c", utc(27))
    s3.put(f"{ACCOUNT}/nist_security_report_run-c_us-east-1.csv", "x", utc(27))
    put_run(s3, "run-m", utc(27), account_id=MGMT)
    arns = _arn_dir(tmp_path, {ACCOUNT: "run-c", MGMT: "run-m", OTHER_ACCOUNT: "run-o"})
    ledger = tmp_path / "assessment_failures.tsv"
    ledger_text = (
        f"{OTHER_ACCOUNT}\texecution\tStep Functions completed with status FAILED\n"
        f"{OTHER_ACCOUNT}\tartifact-validation\tNo complete artifact set was available.\n"
        f"{OTHER_ACCOUNT}\tartifact-validation\tNo complete artifact set was available.\n"
        f"{MGMT}\tconsolidation\tFailed to create or upload the consolidated HTML report\n"
        "not a ledger line\n"
    )
    ledger.write_text(ledger_text, encoding="utf-8")

    code, lines = _run(
        [
            "compare",
            "--bucket",
            BUCKET,
            "--accounts",
            f"{ACCOUNT} {OTHER_ACCOUNT},{MISSING}  {MGMT} consolidated-reports ",
            "--execution-arn-dir",
            str(arns),
            "--failures-file",
            str(ledger),
            "--time-budget",
            "300",
        ],
        s3=s3,
    )
    assert code == 0
    assert lines == [
        f"Changes report for account {ACCOUNT}",
        "  Not read: nist_security_report_run-c_us-east-1.csv "
        "(unknown findings file type)",
        "  Compared run run-c (saved 2026-09-27T00:00:00Z) with run run-p "
        "(saved 2026-09-03T00:00:00Z), 24 day(s) apart",
        "  No changes since the last assessment",
        f"  Written: s3://{BUCKET}/{CHANGES_KEY}",
        f"  Written: s3://{BUCKET}/{CHANGES_PAGE_KEY}",
        _cannot(
            OTHER_ACCOUNT,
            "Step Functions completed with status FAILED; "
            "No complete artifact set was available",
        ),
        _cannot(MISSING, "no execution ARN was saved for the current run"),
        f"Changes report for account {MGMT}",
        f"  {cli.first_run_note(MGMT)}",
        "Skipped 'consolidated-reports': not an AWS account ID",
    ]
    assert ledger.read_text(encoding="utf-8") == ledger_text  # only read
    assert [key for key, _ in s3.writes] == [CHANGES_KEY, CHANGES_PAGE_KEY]


def test_a_missing_failure_ledger_means_no_failures(tmp_path):
    assert cli.read_failures(str(tmp_path / "none.tsv")) == {}


def test_accounts_past_the_time_budget_get_a_warning(tmp_path):
    s3 = FakeS3()
    put_run(s3, "run-c", utc(27))
    arns = _arn_dir(tmp_path, {ACCOUNT: "run-c"})
    ticks = iter([0, 0, 250])
    code, lines = _run(
        [
            "compare",
            "--bucket",
            BUCKET,
            "--accounts",
            f"{ACCOUNT} {OTHER_ACCOUNT} {MGMT}",
            "--execution-arn-dir",
            str(arns),
            "--time-budget",
            "300",
        ],
        s3=s3,
        clock=lambda: next(ticks),
    )
    limit = "the time limit for the changes report was reached"
    assert code == 0
    assert lines == [
        f"Changes report for account {ACCOUNT}",
        f"  {cli.first_run_note(ACCOUNT)}",
        _cannot(OTHER_ACCOUNT, limit),
        _cannot(MGMT, limit),
    ]


# --- S3 mode: problems are warnings -------------------------------------------------


def test_current_run_not_found_is_a_warning():
    s3 = FakeS3()
    put_run(s3, "run-c", utc(27))
    code, lines = _run(_single("run-x"), s3=s3)
    reason = f"the current run's results were not found in s3://{BUCKET}/{ACCOUNT}/"
    assert (code, lines) == (0, [_cannot(ACCOUNT, reason)])


def test_an_unreadable_csv_is_a_warning():
    s3 = FakeS3()
    put_run(s3, "run-c", utc(27))
    name = report_name("bedrock", "run-c", "us-east-1")
    s3.put(f"{ACCOUNT}/{name}", "Check_ID\nBR-01\n", utc(27))
    code, (line,) = _run(_single(), s3=s3)
    assert code == 0
    assert line.startswith(
        _cannot(ACCOUNT, f"{name} is missing column(s): Finding")[:-1]
    )
    assert s3.writes == []


class _BrokenS3(FakeS3):
    def get_paginator(self, operation):
        raise RuntimeError("SlowDown")


def test_an_unexpected_error_is_a_warning_and_exit_code_stays_0():
    code, lines = _run(_single(), s3=_BrokenS3())
    assert (code, lines) == (0, [_cannot(ACCOUNT, "RuntimeError: SlowDown")])


def test_the_s3_client_uses_the_repos_retry_settings():
    s3 = FakeS3()
    put_run(s3, "run-c", utc(27))
    with patch("boto3.client", return_value=s3) as client:
        code, _lines = _run(_single())
    assert code == 0
    ((args, kwargs),) = client.call_args_list
    assert args == ("s3",)
    assert kwargs["config"].retries == {"max_attempts": 10, "mode": "adaptive"}


# --- local mode ----------------------------------------------------------------------


def _write_folder(s3, execution_id, folder):
    folder.mkdir(parents=True, exist_ok=True)
    for key, (body, saved_at) in s3.objects.items():
        name = key.split("/", 1)[1]
        if f"_security_report_{execution_id}" in name:
            path = folder / name
            path.write_bytes(body)
            os.utime(path, (saved_at.timestamp(), saved_at.timestamp()))


def _local_runs(tmp_path):
    s3 = FakeS3()
    put_run(s3, "run-p", utc(3), [make_finding("BR-01")])
    put_run(s3, "run-c", utc(27), [make_finding("BR-01", "Passed")])
    _write_folder(s3, "run-p", tmp_path / "previous")
    _write_folder(s3, "run-c", tmp_path / "current")
    return s3


def _local(tmp_path, previous="previous", current="current"):
    return [
        "compare",
        "--account",
        ACCOUNT,
        "--previous-dir",
        str(tmp_path / previous),
        "--current-dir",
        str(tmp_path / current),
        "--output-dir",
        str(tmp_path / "out" / "nested"),
    ]


def test_local_mode_writes_the_csv_and_ignores_the_setting(tmp_path):
    _local_runs(tmp_path)
    main_report = (
        tmp_path / "current" / "security_assessment_single_account_20260927_000003.html"
    )
    main_report.write_text("<html></html>", encoding="utf-8")
    os.utime(main_report, (utc(27, 0, 1).timestamp(), utc(27, 0, 1).timestamp()))
    environ = {"ENABLE_ASSESSMENT_HISTORY": "false"}
    code, lines = _run(_local(tmp_path), environ=environ)
    written = (
        tmp_path / "out" / "nested" / "security_assessment_changes_20260927_000000.csv"
    )
    page = written.with_suffix(".html")
    assert code == 0
    assert written.is_file()
    assert 'href="security_assessment_single_account_20260927_000003.html"' in (
        page.read_text(encoding="utf-8")
    )
    assert lines == [
        f"Changes report for account {ACCOUNT}",
        "  Compared run run-c (saved 2026-09-27T00:00:00Z) with run run-p "
        "(saved 2026-09-03T00:00:00Z), 24 day(s) apart",
        "  Bedrock, SageMaker, AgentCore, Agent Registry: Regressed 0, New 0, "
        "Still open 0, Resolved 1, No longer reported 0, No longer assessed 0",
        f"  Written: {written}",
        f"  Written: {page}",
    ]


def test_local_mode_needs_one_run_per_folder(tmp_path):
    s3 = _local_runs(tmp_path)
    _write_folder(s3, "run-c", tmp_path / "previous")
    code, lines = _run(_local(tmp_path))
    folder = tmp_path / "previous"
    assert (code, lines) == (
        1,
        [f"ERROR: {folder} should hold one run's findings CSVs; found 2 runs"],
    )


def test_local_mode_needs_complete_runs(tmp_path):
    _local_runs(tmp_path)
    (tmp_path / "current" / report_name("agentcore", "run-c", "us-east-1")).unlink()
    code, lines = _run(_local(tmp_path))
    folder = tmp_path / "current"
    assert (code, lines) == (
        1,
        [
            f"ERROR: the run in {folder} is incomplete "
            "(missing agentcore CSV for us-east-1)"
        ],
    )


def test_local_mode_reports_a_missing_folder(tmp_path):
    _local_runs(tmp_path)
    code, (line,) = _run(_local(tmp_path, previous="nowhere"))
    assert code == 1
    assert line.startswith("ERROR: ")


def test_local_mode_rejects_the_same_run_twice(tmp_path):
    _local_runs(tmp_path)
    code, lines = _run(_local(tmp_path, previous="current"))
    assert (code, lines) == (1, ["ERROR: Both runs are execution run-c"])


# --- arguments --------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv, message",
    [
        ([], "the following arguments are required"),
        (["compare"], "S3 mode needs --bucket and --accounts"),
        (
            ["compare", "--bucket", BUCKET, "--accounts", ACCOUNT],
            "S3 mode needs one of --execution-id or --execution-arn-dir",
        ),
        (
            [
                "compare",
                "--bucket",
                BUCKET,
                "--accounts",
                ACCOUNT,
                "--execution-id",
                "x",
                "--execution-arn-dir",
                "d",
            ],
            "S3 mode needs one of --execution-id or --execution-arn-dir",
        ),
        (
            [
                "compare",
                "--bucket",
                BUCKET,
                "--accounts",
                f"{ACCOUNT} {MGMT}",
                "--execution-id",
                "x",
            ],
            "--execution-id works with exactly one account",
        ),
        (
            ["compare", "--account", ACCOUNT, "--previous-dir", "p"],
            "local mode needs --account, --previous-dir, --current-dir",
        ),
        (
            [
                "compare",
                "--bucket",
                BUCKET,
                "--account",
                ACCOUNT,
                "--previous-dir",
                "p",
                "--current-dir",
                "c",
                "--output-dir",
                "o",
            ],
            "use either the S3 options or the local-folder options",
        ),
    ],
)
def test_argument_errors(argv, message, capsys):
    with pytest.raises(SystemExit) as exit_info:
        _run(argv)
    assert exit_info.value.code == 2
    assert message in capsys.readouterr().err


def test_running_the_package_calls_main(capsys):
    with (
        patch.object(sys, "argv", ["assessment_history", "--help"]),
        warnings.catch_warnings(),
    ):
        warnings.simplefilter("ignore", RuntimeWarning)
        with pytest.raises(SystemExit) as exit_info:
            runpy.run_module("assessment_history", run_name="__main__")
    assert exit_info.value.code == 0
    assert "compare" in capsys.readouterr().out


# --- the CSV file ------------------------------------------------------------------


def test_changes_file_name_uses_utc_and_is_never_read_as_findings():
    chicago = timezone(timedelta(hours=-5))
    comparison = Comparison(
        account_id=ACCOUNT,
        previous_execution_id="p",
        current_execution_id="c",
        rows=(),
        current_saved_at=datetime(2026, 9, 26, 20, 0, tzinfo=chicago),
    )
    name = cli.changes_file_name(comparison)
    assert name == "security_assessment_changes_20260927_010000.csv"
    assert parse_report_name(name) is None
    assert "_security_report_" not in name


# --- the changes page and the main report link --------------------------------------


def test_the_page_links_the_main_report_saved_with_the_run():
    s3 = FakeS3()
    put_run(s3, "run-p", utc(3))
    s3.put(
        f"{ACCOUNT}/security_assessment_single_account_20260903_000001.html",
        "<html></html>",
        utc(3, 0, 1),
    )
    put_run(s3, "run-c", utc(27))
    name = "security_assessment_single_account_20260927_000002.html"
    s3.put(f"{ACCOUNT}/{name}", "<html></html>", utc(27, 0, 2))
    code, _lines = _run(_single(), s3=s3)
    page = s3.objects[CHANGES_PAGE_KEY][0].decode("utf-8")
    assert code == 0
    assert page.count(f'href="{name}"') == 2  # header and sidebar
    assert "20260903_000001" not in page


def _main_report(day, hour, minute):
    name = f"security_assessment_single_account_202609{day:02d}_{hour:02d}{minute:02d}00.html"
    return StoredFile(name, utc(day, hour, minute))


@pytest.mark.parametrize(
    "reports, expected",
    [
        ([(27, 0, 5)], "security_assessment_single_account_20260927_000500.html"),
        ([(27, 0, 10)], "security_assessment_single_account_20260927_001000.html"),
        ([(26, 23, 55)], "security_assessment_single_account_20260926_235500.html"),
        ([(27, 0, 11)], None),  # more than 10 minutes from the run's CSVs
        ([(27, 0, 1), (27, 0, 2)], None),  # two candidates: not certain
        ([], None),
    ],
)
def test_find_main_report(reports, expected):
    files = [_main_report(*report) for report in reports] + [
        StoredFile("security_assessment_changes_20260927_000000.html", utc(27)),
        StoredFile("security_assessment_single_account_latest.html", utc(27)),
    ]
    assert cli.find_main_report(files, utc(27)) == expected


def test_a_page_that_cannot_be_rendered_writes_nothing():
    s3 = FakeS3()
    put_run(s3, "run-p", utc(3))
    put_run(s3, "run-c", utc(27))
    with patch.object(cli, "render_changes_page", side_effect=RenderError("gone")):
        code, lines = _run(_single(), s3=s3)
    assert code == 0
    assert lines[-1] == _cannot(ACCOUNT, "RenderError: gone")
    assert s3.writes == []


def test_changes_file_name_takes_an_extension():
    comparison = Comparison(
        account_id=ACCOUNT,
        previous_execution_id="p",
        current_execution_id="c",
        rows=(),
        current_saved_at=utc(27, 6, 15),
    )
    assert cli.changes_file_name(comparison, "html") == (
        "security_assessment_changes_20260927_061500.html"
    )


def test_first_run_note_explains_where_history_went():
    assert cli.first_run_note(ACCOUNT) == (
        f"No previous run for account {ACCOUNT}; changes report skipped. If this "
        "stack was redeployed, or earlier results were moved or deleted, they "
        "aren't compared. The next run will compare with this one."
    )
