"""Finding and reading an account's runs (assessment_history/discover.py).

S3 is replaced by FakeS3 from tests/assessment_history_helpers.py. The
example account folder in tests/fixtures/assessment_history/dataset_a/ is
written by hand, and its expected results below were worked out by hand, so
it checks the reader independently of the helpers that write test CSVs.
"""

import json
import os
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from assessment_history.compare import compare_runs
from assessment_history.discover import (
    MAX_SKIPPED_NOTES,
    DirectorySource,
    DiscoveryError,
    ReportFile,
    ReportName,
    RunFiles,
    S3Source,
    StoredFile,
    discover,
    format_utc,
    group_runs,
    parse_findings_csv,
    parse_report_name,
    read_complete_run,
    run_record_name,
    run_records,
)
from assessment_history.models import (
    CORE_MODULES,
    CURRENT_RUN,
    MODULE_NOT_IN_BOTH_RUNS,
    REGION_NOT_IN_BOTH_RUNS,
    Change,
    InvalidFindingError,
    MatchRule,
)
from tests.assessment_history_helpers import (
    ACCOUNT,
    OTHER_ACCOUNT,
    FakeS3,
    findings_csv,
    make_finding,
    make_run,
    put_run,
    report_name,
    utc,
)

FIXTURES = (
    Path(__file__).resolve().parent / "fixtures" / "assessment_history" / "dataset_a"
)
HEADER = (
    "Check_ID,Finding,Finding_Details,Resolution,Reference,Severity,Status,Region\n"
)
ALL_MODULES = CORE_MODULES + ("responsible-ai-grc", "owasp")


def _source(s3):
    return S3Source(s3, s3.bucket, ACCOUNT)


def _key(name, account_id=ACCOUNT):
    return f"{account_id}/{name}"


def _discover(s3, current="run-c"):
    return discover(_source(s3), ACCOUNT, current)


# --- file names ----------------------------------------------------------------

UUID = "4b1f0c2e-9d7a-4c3b-8e5f-6a7b8c9d0e1f"


@pytest.mark.parametrize(
    "name, expected",
    [
        (
            f"bedrock_security_report_{UUID}_us-east-1.csv",
            ReportName("bedrock", UUID, "us-east-1"),
        ),
        (
            "sagemaker_security_report_run-1_ap-southeast-2.csv",
            ReportName("sagemaker", "run-1", "ap-southeast-2"),
        ),
        (
            "agentcore_security_report_run-1_us-gov-west-1.csv",
            ReportName("agentcore", "run-1", "us-gov-west-1"),
        ),
        (
            "agent_registry_security_report_run-1_eu-central-1.csv",
            ReportName("agent-registry", "run-1", "eu-central-1"),
        ),
        (
            "responsible_ai_grc_security_report_run-1.csv",
            ReportName("responsible-ai-grc", "run-1", None),
        ),
        (
            "owasp_security_report_run-1_us-west-2.csv",
            ReportName("owasp", "run-1", "us-west-2"),
        ),
        # Fallback form the scanners use when no region is passed.
        ("bedrock_security_report_run-1.csv", ReportName("bedrock", "run-1", None)),
        (
            "BEDROCK_security_report_run-1_us-east-1.CSV",
            ReportName("bedrock", "run-1", "us-east-1"),
        ),
        # A hand-started execution with a custom name containing underscores.
        (
            "bedrock_security_report_my_run_2_us-east-1.csv",
            ReportName("bedrock", "my_run_2", "us-east-1"),
        ),
        # A findings file of a kind this version doesn't know.
        (
            "nist_security_report_run-1_us-east-1.csv",
            ReportName(None, "run-1", "us-east-1"),
        ),
    ],
)
def test_parse_report_name(name, expected):
    assert parse_report_name(name) == expected


@pytest.mark.parametrize(
    "name",
    [
        "security_assessment_single_account_20260927_061500.html",
        "security_assessment_changes_20260927_061500.csv",
        "_security_report_run-1.csv",
        "bedrock_security_report_.csv",
        "bedrock_security_report__us-east-1.csv",
        "bedrock_security_report_run-1_us-east-1.json",
        "notes.txt",
    ],
)
def test_other_files_are_not_findings_files(name):
    assert parse_report_name(name) is None


# --- where files are read from ---------------------------------------------------


def test_s3_source_lists_the_account_folder_top_level_across_pages():
    s3 = FakeS3(page_size=2)
    for key in (
        f"{ACCOUNT}/",  # folder marker
        f"{ACCOUNT}/a.csv",
        f"{ACCOUNT}/b.csv",
        f"{ACCOUNT}/c.html",
        f"{ACCOUNT}/archive/d.csv",  # subfolder: runs are written flat
        f"{OTHER_ACCOUNT}/e.csv",
        "consolidated-reports/f.html",
    ):
        s3.put(key, "x", utc(27))
    source = _source(s3)
    assert source.location == f"s3://central-bucket/{ACCOUNT}/"
    files = source.list_files()
    assert sorted(file.name for file in files) == ["a.csv", "b.csv", "c.html"]
    assert {file.saved_at for file in files} == {utc(27)}
    assert source.read_bytes("a.csv") == b"x"
    assert s3.reads == [f"{ACCOUNT}/a.csv"]


def test_s3_source_rejects_an_invalid_account_id():
    with pytest.raises(InvalidFindingError, match="Invalid AWS account ID"):
        S3Source(FakeS3(), "central-bucket", "consolidated-reports")


def test_directory_source_lists_top_level_files_with_utc_times(tmp_path):
    (tmp_path / "a.csv").write_text("x", encoding="utf-8")
    (tmp_path / "archive").mkdir()
    (tmp_path / "archive" / "b.csv").write_text("y", encoding="utf-8")
    stamp = utc(3, 23, 37).timestamp()
    os.utime(tmp_path / "a.csv", (stamp, stamp))
    source = DirectorySource(tmp_path)
    assert source.location == str(tmp_path)
    assert source.list_files() == [StoredFile("a.csv", utc(3, 23, 37))]
    assert source.read_bytes("a.csv") == b"x"


# --- reading one CSV --------------------------------------------------------------


def test_parse_findings_csv_reads_back_what_the_scanners_write():
    findings = [
        make_finding("BR-01", "Passed"),
        make_finding("AG-01", module="bedrock", details="Source check BR-01"),
        make_finding(
            "BR-05", region="us-east-1", details='a, "b"\nc <script>x</script>'
        ),
    ]
    data = findings_csv(findings).encode()
    assert parse_findings_csv(data, "f.csv", "bedrock", ACCOUNT) == findings
    assert [finding.area for finding in findings] == ["bedrock", "agentic", "bedrock"]


def test_parse_findings_csv_normalizes_status_and_trims_ids():
    data = HEADER + " BR-01 ,Check,details,fix,ref, High , failed , us-east-1 \n"
    (finding,) = parse_findings_csv(data.encode(), "f.csv", "bedrock", ACCOUNT)
    assert (
        finding.account_id,
        finding.check_id,
        finding.severity,
        finding.status,
        finding.region,
    ) == (ACCOUNT, "BR-01", "High", "Failed", "us-east-1")


def test_parse_findings_csv_accepts_the_mark_excel_adds():
    data = "\ufeff".encode() + findings_csv([make_finding()]).encode()
    assert parse_findings_csv(data, "f.csv", "bedrock", ACCOUNT) == [make_finding()]


@pytest.mark.parametrize("data", [b"", b"\n", HEADER.encode()])
def test_parse_findings_csv_empty_file_has_no_rows(data):
    assert parse_findings_csv(data, "f.csv", "bedrock", ACCOUNT) == []


@pytest.mark.parametrize(
    "data, pattern",
    [
        (b"\xff\xfe\x00", re.escape("f.csv is not UTF-8 text")),
        (
            b"Check_ID,Finding\nBR-01,x\n",
            re.escape(
                "f.csv is missing column(s): Finding_Details, Resolution, "
                "Reference, Severity, Status, Region"
            ),
        ),
        (
            (HEADER + "BR-01,x,d,r,ref,High,WARN,Global\n").encode(),
            re.escape("f.csv line 2: Unrecognized Status value: 'WARN'"),
        ),
        (
            (HEADER + "BR-01,x,d,r,ref,High,Failed,Global,extra\n").encode(),
            re.escape("f.csv line 2: wrong number of values"),
        ),
        (
            (HEADER + "BR-01,x,d\n").encode(),
            re.escape("f.csv line 2: wrong number of values"),
        ),
        # Python's csv module refuses cells over 128 KB; fail with a reason.
        (
            (
                HEADER + 'BR-01,x,"' + "a" * 200_000 + '",r,ref,High,Failed,Global\n'
            ).encode(),
            r"f\.csv line \d+: field larger than field limit",
        ),
    ],
)
def test_parse_findings_csv_rejects_what_it_cannot_read_safely(data, pattern):
    with pytest.raises(InvalidFindingError, match=pattern):
        parse_findings_csv(data, "f.csv", "bedrock", ACCOUNT)


# --- a run's files ------------------------------------------------------------------


def _run_files(*specs, execution_id="run-1"):
    """RunFiles from (module, region, saved_at) specs."""
    return RunFiles(
        execution_id,
        tuple(
            ReportFile(report_name(module, execution_id, region), module, region, at)
            for module, region, at in specs
        ),
    )


def _core(regions=("us-east-1", "us-west-2"), skip=()):
    return [
        (module, region, utc(1))
        for module in CORE_MODULES
        for region in regions
        if (module, region) not in skip
    ]


def test_run_files_summary():
    run = _run_files(
        ("bedrock", "us-east-1", utc(1, 1)),
        ("sagemaker", "us-west-2", utc(1, 3)),
        ("responsible-ai-grc", None, utc(1, 2)),
    )
    assert run.saved_at == utc(1, 3)
    assert run.modules == {"bedrock", "sagemaker", "responsible-ai-grc"}
    assert run.regions == {"us-east-1", "us-west-2"}


def test_regions_are_unknown_without_region_suffixes_or_core_files():
    no_suffix = _run_files(
        ("bedrock", None, utc(1)), ("sagemaker", "us-east-1", utc(1))
    )
    assert no_suffix.regions is None
    assert _run_files(("responsible-ai-grc", None, utc(1))).regions is None


@pytest.mark.parametrize(
    "specs, missing",
    [
        (_core(), []),
        (_core() + [("responsible-ai-grc", None, utc(1))], []),
        (
            _core(skip={("agentcore", "us-west-2")}),
            ["agentcore CSV for us-west-2"],
        ),
        (_core() + [("owasp", "us-east-1", utc(1))], ["owasp CSV for us-west-2"]),
        (
            [("responsible-ai-grc", None, utc(1))],
            [
                "bedrock CSV",
                "sagemaker CSV",
                "agentcore CSV",
                "agent-registry CSV",
            ],
        ),
        (
            [(module, None, utc(1)) for module in CORE_MODULES[:3]],
            ["agent-registry CSV"],
        ),
        ([(module, None, utc(1)) for module in CORE_MODULES], []),
    ],
)
def test_missing_files_follow_the_main_reports_rule(specs, missing):
    assert _run_files(*specs).missing_files() == missing


def test_group_runs_by_execution_id():
    names = [
        report_name("bedrock", "run-b", "us-east-1"),
        report_name("sagemaker", "run-a", "us-east-1"),
        report_name("bedrock", "run-a", "us-east-1"),
        "nist_security_report_run-a_us-east-1.csv",
        "security_assessment_single_account_20260927_061500.html",
    ]
    runs, unknown = group_runs(StoredFile(name, utc(1)) for name in names)
    assert sorted(runs) == ["run-a", "run-b"]
    assert runs["run-a"].files == (
        ReportFile(names[2], "bedrock", "us-east-1", utc(1)),
        ReportFile(names[1], "sagemaker", "us-east-1", utc(1)),
    )
    assert unknown == ["nist_security_report_run-a_us-east-1.csv"]


def test_read_complete_run_finds_missing_files_without_reading():
    s3 = FakeS3()
    s3.put(_key(report_name("bedrock", "run-1", "us-east-1")), "x", utc(1))
    runs, _ = group_runs(_source(s3).list_files())
    assert read_complete_run(_source(s3), ACCOUNT, runs["run-1"]) == (
        None,
        "missing sagemaker CSV for us-east-1, agentcore CSV for us-east-1, "
        "agent-registry CSV for us-east-1",
    )
    assert s3.reads == []


# --- choosing the previous run -----------------------------------------------------


def test_first_run_has_no_previous_run():
    s3 = FakeS3()
    written = put_run(s3, "run-c", utc(27))
    result = _discover(s3)
    assert result.previous is None
    assert result.notes == ()
    assert Counter(result.current.findings) == Counter(written)
    assert (
        result.current.execution_id,
        result.current.saved_at,
        result.current.regions,
        result.current.modules,
    ) == ("run-c", utc(27), {"us-east-1"}, set(CORE_MODULES))


def test_previous_run_is_the_latest_complete_run_before_the_current_one():
    s3 = FakeS3()
    put_run(s3, "run-a", utc(1))
    put_run(s3, "run-b", utc(10))
    put_run(s3, "run-c", utc(27))
    result = _discover(s3)
    assert result.previous.execution_id == "run-b"
    assert result.previous.saved_at == utc(10)
    assert not [key for key in s3.reads if "run-a" in key]  # older runs aren't read


def test_a_run_with_a_missing_csv_is_skipped_and_noted():
    s3 = FakeS3()
    put_run(s3, "run-a", utc(1))
    put_run(s3, "run-b", utc(10))
    del s3.objects[_key(report_name("agentcore", "run-b", "us-east-1"))]
    put_run(s3, "run-c", utc(27))
    result = _discover(s3)
    assert result.previous.execution_id == "run-a"
    assert result.notes == (
        "Skipped run run-b saved 2026-09-10T00:00:00Z: incomplete "
        "(missing agentcore CSV for us-east-1)",
    )


def test_a_run_with_an_empty_csv_is_skipped_and_noted():
    s3 = FakeS3()
    put_run(s3, "run-a", utc(1))
    put_run(s3, "run-b", utc(10))
    s3.put(_key(report_name("sagemaker", "run-b", "us-east-1")), HEADER, utc(10))
    put_run(s3, "run-c", utc(27))
    result = _discover(s3)
    assert result.previous.execution_id == "run-a"
    assert result.notes == (
        "Skipped run run-b saved 2026-09-10T00:00:00Z: incomplete "
        "(sagemaker_security_report_run-b_us-east-1.csv has no findings)",
    )


def test_runs_saved_after_the_current_run_are_ignored_and_noted():
    s3 = FakeS3()
    put_run(s3, "run-a", utc(1))
    put_run(s3, "run-c", utc(27))
    put_run(s3, "run-later", utc(28))
    result = _discover(s3)
    assert result.previous.execution_id == "run-a"
    assert result.notes == ("Ignored 1 run(s) saved after the current run: run-later",)


def test_same_save_time_is_ordered_by_execution_id():
    s3 = FakeS3()
    for execution_id in ("run-a", "run-b", "run-c"):
        put_run(s3, execution_id, utc(27))
    result = _discover(s3, "run-b")
    assert result.previous.execution_id == "run-a"
    assert result.notes == ("Ignored 1 run(s) saved after the current run: run-c",)


def test_skipped_run_notes_are_capped():
    s3 = FakeS3()
    for day in range(1, 8):
        name = report_name("bedrock", f"run-{day}", "us-east-1")
        s3.put(_key(name), findings_csv([make_finding()]), utc(day))
    put_run(s3, "run-c", utc(27))
    result = _discover(s3)
    assert result.previous is None
    assert len(result.notes) == MAX_SKIPPED_NOTES + 1
    assert result.notes[0].startswith("Skipped run run-7 saved 2026-09-07T00:00:00Z")
    assert result.notes[-1] == "Skipped 2 more run(s)"


# --- run records: a run whose Step Functions execution failed (review F2) ----------


def _put_record(s3, execution_id, body, saved_at=None):
    s3.put(_key(run_record_name(execution_id)), body, saved_at or utc(10))


def _record(execution_id, succeeded, status="FAILED"):
    return json.dumps(
        {
            "execution_id": execution_id,
            "succeeded": succeeded,
            "status": status,
            "written_at": "2026-09-10T00:00:05Z",
        }
    )


def _three_runs(s3):
    put_run(s3, "run-a", utc(1))
    put_run(s3, "run-b", utc(10))
    put_run(s3, "run-c", utc(27))


def test_a_run_recorded_as_failed_is_skipped_without_reading_its_csvs():
    # Its CSVs look complete: only the record shows the run failed.
    s3 = FakeS3()
    _three_runs(s3)
    _put_record(s3, "run-b", _record("run-b", False))
    result = _discover(s3)
    assert result.previous.execution_id == "run-a"
    assert result.notes == (
        "Skipped run run-b saved 2026-09-10T00:00:00Z: the assessment run did not "
        "succeed (Step Functions status FAILED)",
    )
    assert not [key for key in s3.reads if "run-b" in key and key.endswith(".csv")]


def test_a_run_recorded_as_succeeded_is_used():
    s3 = FakeS3()
    _three_runs(s3)
    _put_record(s3, "run-b", _record("run-b", True, "SUCCEEDED"))
    result = _discover(s3)
    assert (result.previous.execution_id, result.notes) == ("run-b", ())


def test_a_run_recorded_as_succeeded_must_still_be_complete():
    # The record says the run succeeded, but one of its CSVs has since gone.
    s3 = FakeS3()
    _three_runs(s3)
    _put_record(s3, "run-b", _record("run-b", True, "SUCCEEDED"))
    del s3.objects[_key(report_name("agentcore", "run-b", "us-east-1"))]
    result = _discover(s3)
    assert result.previous.execution_id == "run-a"
    assert result.notes == (
        "Skipped run run-b saved 2026-09-10T00:00:00Z: incomplete "
        "(missing agentcore CSV for us-east-1)",
    )


@pytest.mark.parametrize(
    "fields, detail",
    [
        ({"status": "TIMED_OUT"}, " (Step Functions status TIMED_OUT)"),
        ({"status": ""}, ""),
        ({}, ""),
    ],
)
def test_the_recorded_status_is_named_when_there_is_one(fields, detail):
    s3 = FakeS3()
    _three_runs(s3)
    _put_record(
        s3, "run-b", json.dumps({"execution_id": "run-b", "succeeded": False, **fields})
    )
    (note,) = _discover(s3).notes
    assert note.endswith(f": the assessment run did not succeed{detail}")


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(b"{", id="not JSON"),
        pytest.param(b"\xff\xfe", id="not UTF-8"),
        pytest.param(b"[]", id="not an object"),
        pytest.param(_record("run-x", True).encode(), id="another run's record"),
        pytest.param(
            json.dumps({"execution_id": "run-b", "succeeded": "yes"}).encode(),
            id="succeeded is not true or false",
        ),
        pytest.param(json.dumps({"execution_id": "run-b"}).encode(), id="no succeeded"),
    ],
)
def test_a_run_record_that_cant_be_read_rules_the_run_out(body):
    s3 = FakeS3()
    _three_runs(s3)
    _put_record(s3, "run-b", body)
    result = _discover(s3)
    assert result.previous.execution_id == "run-a"
    assert result.notes == (
        "Skipped run run-b saved 2026-09-10T00:00:00Z: its run record "
        "assessment_history_run_run-b.json can't be read",
    )


def test_run_records_are_found_by_name():
    assert run_record_name("run-b") == "assessment_history_run_run-b.json"
    files = [
        StoredFile("assessment_history_run_run-b.json", utc(1)),
        StoredFile("assessment_history_run_.json", utc(1)),
        StoredFile("notes.json", utc(1)),
        StoredFile(report_name("bedrock", "run-b", "us-east-1"), utc(1)),
    ]
    assert run_records(files) == {"run-b": "assessment_history_run_run-b.json"}


def test_unknown_findings_files_are_noted_and_not_read():
    s3 = FakeS3()
    put_run(s3, "run-c", utc(27))
    unknown = "nist_security_report_run-c_us-east-1.csv"
    s3.put(_key(unknown), "x", utc(27))
    result = _discover(s3)
    assert result.notes == (f"Not read: {unknown} (unknown findings file type)",)
    assert _key(unknown) not in s3.reads


def test_other_accounts_files_are_not_seen():
    s3 = FakeS3()
    put_run(s3, "run-o", utc(10), account_id=OTHER_ACCOUNT)
    put_run(s3, "run-c", utc(27))
    assert _discover(s3).previous is None


@pytest.mark.parametrize(
    "current, message",
    [
        ("", "the current run's execution ID is missing"),
        (
            "run-x",
            "the current run's results were not found in "
            "s3://central-bucket/123456789012/",
        ),
    ],
)
def test_the_current_run_must_be_found(current, message):
    s3 = FakeS3()
    put_run(s3, "run-c", utc(27))
    with pytest.raises(DiscoveryError, match=re.escape(message)):
        _discover(s3, current)


def test_an_incomplete_current_run_is_an_error():
    s3 = FakeS3()
    put_run(s3, "run-c", utc(27))
    del s3.objects[_key(report_name("bedrock", "run-c", "us-east-1"))]
    message = "the current run is incomplete (missing bedrock CSV for us-east-1)"
    with pytest.raises(DiscoveryError, match=re.escape(message)):
        _discover(s3)


def test_a_current_run_with_an_empty_csv_is_an_error():
    s3 = FakeS3()
    put_run(s3, "run-c", utc(27))
    s3.put(_key(report_name("bedrock", "run-c", "us-east-1")), "", utc(27))
    message = (
        "the current run is incomplete "
        "(bedrock_security_report_run-c_us-east-1.csv has no findings)"
    )
    with pytest.raises(DiscoveryError, match=re.escape(message)):
        _discover(s3)


def test_an_unreadable_older_run_is_skipped_and_the_next_one_tried():
    # Review item L3: one unreadable CSV used to stop the whole account.
    s3 = FakeS3()
    _three_runs(s3)
    s3.put(_key(report_name("bedrock", "run-b", "us-east-1")), "Check_ID\n", utc(10))
    result = _discover(s3)
    assert result.previous.execution_id == "run-a"
    (note,) = result.notes
    assert note.startswith(
        "Skipped run run-b saved 2026-09-10T00:00:00Z: unreadable "
        "(bedrock_security_report_run-b_us-east-1.csv is missing column(s): "
    )


def test_an_unreadable_csv_in_the_current_run_is_still_an_error():
    s3 = FakeS3()
    _three_runs(s3)
    s3.put(_key(report_name("bedrock", "run-c", "us-east-1")), "Check_ID\n", utc(27))
    with pytest.raises(InvalidFindingError, match="missing column"):
        _discover(s3)


def test_discovery_works_on_a_local_folder(tmp_path):
    s3 = FakeS3()
    put_run(s3, "run-p", utc(3))
    put_run(s3, "run-c", utc(27))
    for key, (body, saved_at) in s3.objects.items():
        path = tmp_path / key.split("/", 1)[1]
        path.write_bytes(body)
        os.utime(path, (saved_at.timestamp(), saved_at.timestamp()))
    result = discover(DirectorySource(tmp_path), ACCOUNT, "run-c")
    assert (result.previous.execution_id, result.previous.saved_at) == (
        "run-p",
        utc(3),
    )


def test_format_utc_converts_to_utc():
    chicago = timezone(timedelta(hours=-5))
    moment = datetime(2026, 9, 26, 20, 0, tzinfo=chicago)
    assert format_utc(moment) == "2026-09-27T01:00:00Z"


# --- written, then read back ---------------------------------------------------------

PREVIOUS_ROWS = [
    make_finding("BR-01", "Passed", details="No roles found"),
    make_finding("BR-03", details="Role 'a' has access"),
    make_finding("BR-03", details="Role 'b' has access"),
    make_finding("SM-26", region="us-west-2"),
    make_finding("AC-03", details="role 'x' (255 days)"),
    make_finding(
        "AG-17", module="agentcore", details="Source check AC-03: role 'x' (255 days)"
    ),
    make_finding("AR-02", "N/A", severity="Informational"),
    make_finding("FS-31", region="us-east-1", details="kb-1 last synced 120 days ago"),
    make_finding("OW-03", region="us-west-2", details='=cmd, "quoted"\nsecond line'),
]
CURRENT_ROWS = [
    make_finding("BR-01", details="Role 'admin' has the policy"),
    make_finding("BR-03", details="Role 'a' has access"),
    make_finding("SM-26", "Passed", region="us-west-2"),
    make_finding("AC-03", details="role 'x' (279 days)"),
    make_finding(
        "AG-17", module="agentcore", details="Source check AC-03: role 'x' (279 days)"
    ),
    make_finding("AR-02"),
    make_finding("FS-31", region="us-east-1", details="kb-1 last synced 144 days ago"),
    make_finding("FS-05", details="new check"),
    make_finding("OW-03", region="us-west-2", details='=cmd, "quoted"\nsecond line'),
]


@pytest.mark.parametrize("regions", [("us-east-1", "us-west-2"), None])
def test_reading_back_gives_the_same_comparison_as_in_memory(regions):
    s3 = FakeS3()
    options = {"regions": regions, "modules": ALL_MODULES}
    written_previous = put_run(s3, "run-p", utc(3), PREVIOUS_ROWS, **options)
    written_current = put_run(s3, "run-c", utc(27), CURRENT_ROWS, **options)
    result = _discover(s3)

    assert Counter(result.previous.findings) == Counter(written_previous)
    assert Counter(result.current.findings) == Counter(written_current)
    expected_regions = None if regions is None else set(regions)
    assert result.previous.regions == expected_regions
    assert result.current.regions == expected_regions
    assert result.current.modules == set(ALL_MODULES)

    in_memory = compare_runs(
        make_run(
            written_previous,
            execution_id="run-p",
            modules=ALL_MODULES,
            regions=regions,
            saved_at=utc(3),
        ),
        make_run(
            written_current,
            execution_id="run-c",
            modules=ALL_MODULES,
            regions=regions,
            saved_at=utc(27),
        ),
    )
    assert compare_runs(result.previous, result.current) == in_memory
    assert in_memory.has_changes


# --- the hand-written example folder -----------------------------------------------

PREVIOUS_ID = "00000000-0000-4000-8000-000000000903"
CURRENT_ID = "00000000-0000-4000-8000-000000000927"


def _load_example_folder():
    times = json.loads((FIXTURES / "saved_times.json").read_text(encoding="utf-8"))
    folder = FIXTURES / ACCOUNT
    paths = sorted(path for path in folder.rglob("*") if path.is_file())
    keys = [f"{ACCOUNT}/{path.relative_to(folder).as_posix()}" for path in paths]
    assert sorted(keys) == sorted(times), "saved_times.json must list every file"
    s3 = FakeS3()
    for key, path in zip(keys, paths, strict=True):
        s3.put(key, path.read_bytes(), datetime.fromisoformat(times[key]))
    return s3


def test_example_folder_discovery():
    s3 = _load_example_folder()
    result = discover(_source(s3), ACCOUNT, CURRENT_ID)

    assert result.previous.execution_id == PREVIOUS_ID
    assert result.previous.saved_at == datetime.fromisoformat("2026-09-03T23:37:04Z")
    assert result.current.saved_at == datetime.fromisoformat("2026-09-27T06:15:10Z")
    assert result.previous.regions == {"us-east-1"}
    assert result.current.regions == {"us-east-1", "us-west-2"}
    assert result.previous.modules == set(CORE_MODULES) | {"responsible-ai-grc"}
    assert result.current.modules == set(ALL_MODULES)
    assert (len(result.previous.findings), len(result.current.findings)) == (12, 19)
    assert result.notes == (
        f"Not read: nist_security_report_{CURRENT_ID}_us-east-1.csv "
        "(unknown findings file type)",
        "Ignored 1 run(s) saved after the current run: "
        "00000000-0000-4000-8000-000000000928",
        "Skipped run 00000000-0000-4000-8000-000000000915 saved "
        "2026-09-15T10:00:01Z: incomplete (missing agentcore CSV for us-east-1, "
        "agent-registry CSV for us-east-1)",
    )
    # Only the two compared runs are read.
    read_runs = {key.split("_security_report_")[1][:36] for key in s3.reads}
    assert read_runs == {PREVIOUS_ID, CURRENT_ID}


def test_example_folder_comparison():
    s3 = _load_example_folder()
    result = discover(_source(s3), ACCOUNT, CURRENT_ID)
    comparison = compare_runs(result.previous, result.current)

    assert Counter(
        (row.area, row.check_id, row.change, row.match_rule) for row in comparison.rows
    ) == Counter(
        [
            ("bedrock", "BR-01", Change.REGRESSED, MatchRule.SINGLE_ROW),
            ("bedrock", "BR-03", Change.STILL_OPEN, MatchRule.EXACT),
            ("bedrock", "BR-03", Change.NO_LONGER_REPORTED, MatchRule.UNMATCHED),
            ("bedrock", "BR-05", Change.RESOLVED, MatchRule.SINGLE_ROW),
            ("bedrock", "BR-14", Change.STILL_OPEN, MatchRule.NORMALIZED),
            ("sagemaker", "SM-02", Change.STILL_OPEN, MatchRule.EXACT),
            ("sagemaker", "SM-26", Change.NO_LONGER_ASSESSED, MatchRule.SINGLE_ROW),
            ("agentcore", "AC-03", Change.STILL_OPEN, MatchRule.NORMALIZED),
            ("agent-registry", "AR-02", Change.RESOLVED, MatchRule.SINGLE_ROW),
            ("agentic", "AG-17", Change.STILL_OPEN, MatchRule.NORMALIZED),
            ("responsible-ai-grc", "FS-01", Change.NOT_FAILING, MatchRule.EXACT),
            ("responsible-ai-grc", "FS-05", Change.NEW, MatchRule.UNMATCHED),
            ("responsible-ai-grc", "FS-31", Change.STILL_OPEN, MatchRule.NORMALIZED),
        ]
    )
    assert Counter(
        (item.side, item.reason, item.finding.check_id) for item in comparison.excluded
    ) == Counter(
        [
            (CURRENT_RUN, REGION_NOT_IN_BOTH_RUNS, "BR-05"),
            (CURRENT_RUN, REGION_NOT_IN_BOTH_RUNS, "SM-26"),
            (CURRENT_RUN, REGION_NOT_IN_BOTH_RUNS, "AC-17"),
            (CURRENT_RUN, REGION_NOT_IN_BOTH_RUNS, "AR-01"),
            (CURRENT_RUN, REGION_NOT_IN_BOTH_RUNS, "FS-12"),
            (CURRENT_RUN, MODULE_NOT_IN_BOTH_RUNS, "OW-03"),
            (CURRENT_RUN, MODULE_NOT_IN_BOTH_RUNS, "OW-06"),
        ]
    )
    assert comparison.tile_counts() == Counter(
        {
            Change.STILL_OPEN: 4,
            Change.RESOLVED: 2,
            Change.REGRESSED: 1,
            Change.NO_LONGER_REPORTED: 1,
            Change.NO_LONGER_ASSESSED: 1,
        }
    )
    assert comparison.not_compared_modules == {"owasp": "current run only"}
    assert comparison.not_compared_regions == {"us-west-2": "current run only"}
    assert comparison.single_run_check_ids == {"FS-05": "current run only"}
    assert comparison.days_apart == 24
    sm26 = next(row for row in comparison.rows if row.check_id == "SM-26")
    assert sm26.severity == "High"  # the previous run's, since it's no longer assessed
