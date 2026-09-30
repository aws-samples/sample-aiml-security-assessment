"""Golden tests: both sample reports, each compared with an edited copy.

sample-reports/scripts/build_changes_sample.py turns each sample report back
into the findings CSVs the scanners write (the previous run) and applies its
EDITS to make a current run. The tests write those CSVs to a temporary folder
and read them back with the build's own code; only the saved answers
(golden/expected_*.json) are committed. The saved answers are checked here,
together with results worked out by hand from the edits.

Values that AWS generated in the sample reports (resource IDs, the random parts
of resource names) are replaced with made-up values of the same shape first;
the last tests check that none of them reaches a committed file.

After a sample report or a comparison rule changes, regenerate and review
the diff:

    .venv/bin/python sample-reports/scripts/build_changes_sample.py
"""

import dataclasses
import hashlib
import importlib.util
import json
import re
import sys
from collections import Counter
from pathlib import Path

import pytest

from assessment_history.compare import compare_runs
from assessment_history.discover import DirectorySource, group_runs, read_complete_run
from assessment_history.models import Change, MatchRule
from tests.assessment_history_helpers import assert_invariants

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "sample-reports" / "scripts" / "build_changes_sample.py"
GOLDEN = REPO_ROOT / "tests" / "fixtures" / "assessment_history" / "golden"
SINGLE = "123456789012"


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "assessment_history_build_changes_sample", SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look the module up by name
    spec.loader.exec_module(module)
    return module


script = _load_script()
PREVIOUS_RUNS = script.previous_runs()
ACCOUNTS = [
    (sample, account_id)
    for sample, runs in PREVIOUS_RUNS.items()
    for account_id in runs
]


@pytest.fixture(scope="module")
def folders(tmp_path_factory):
    """Each account's previous-run CSVs, written to a temporary folder."""
    root = tmp_path_factory.mktemp("golden")
    for sample, runs in PREVIOUS_RUNS.items():
        for account_id, files in runs.items():
            folder = root / sample / account_id
            folder.mkdir(parents=True)
            for name, text in files.items():
                (folder / name).write_bytes(text.encode("utf-8"))
    return root


def _read_folder(folder, account_id, saved_at):
    source = DirectorySource(folder)
    runs, unknown = group_runs(source.list_files())
    assert unknown == []
    (run_files,) = runs.values()
    run, reason = read_complete_run(source, account_id, run_files)
    assert run is not None, reason
    return dataclasses.replace(run, saved_at=saved_at)


def _previous(folders, sample, account_id):
    return _read_folder(
        folders / sample / account_id, account_id, script.PREVIOUS_SAVED_AT
    )


def _compared(folders, sample, account_id):
    previous = _previous(folders, sample, account_id)
    current = script.make_current_run(previous)
    return previous, current, compare_runs(previous, current)


def _rows_by_check(comparison):
    rows = {}
    for row in comparison.rows:
        rows.setdefault((row.check_id, row.region), []).append(row)
    return rows


# --- the saved files match what the script builds -------------------------------


def test_saved_files_are_up_to_date():
    outputs = script.build()
    stale = [str(path.relative_to(REPO_ROOT)) for path in script.out_of_date(outputs)]
    assert stale == [], (
        "Regenerate with: .venv/bin/python sample-reports/scripts/"
        "build_changes_sample.py\n" + "\n".join(stale)
    )


def test_no_input_csvs_are_committed():
    # The previous runs' CSVs are built at test time (review item L7).
    assert sorted(GOLDEN.rglob("*.csv")) == []


def test_the_script_is_found_by_the_expected_paths():
    assert script.REPO_ROOT == REPO_ROOT
    assert [sample for sample, _ in ACCOUNTS] == [
        "single_account",
        "multi_account",
        "multi_account",
        "multi_account",
    ]


# --- reading the runs back gives the sample reports' rows -------------------------


@pytest.mark.parametrize("sample", list(script.SAMPLES))
def test_runs_read_back_as_the_sample_reports_rows(folders, sample):
    expected = Counter(
        (
            row.account_id,
            row.area,  # the main report's own area for the row
            row.region,
            row.check_id,
            row.finding,
            row.details,
            row.severity,
            row.status,
        )
        for row in script.sample_rows(sample)
    )
    found = Counter()
    for account_id in PREVIOUS_RUNS[sample]:
        previous = _previous(folders, sample, account_id)
        found.update(
            (
                finding.account_id,
                finding.area,
                finding.region,
                finding.check_id,
                finding.finding,
                finding.details,
                finding.severity,
                finding.status,
            )
            for finding in previous.findings
        )
    assert found == expected


# --- the saved answers ----------------------------------------------------------------


@pytest.mark.parametrize("sample, account_id", ACCOUNTS)
def test_comparison_matches_the_saved_answer(folders, sample, account_id):
    previous, current, comparison = _compared(folders, sample, account_id)
    expected = json.loads(
        (GOLDEN / f"expected_{sample}.json").read_text(encoding="utf-8")
    )
    assert script.summarize(comparison) == expected[account_id]
    assert_invariants(previous, current, comparison)


@pytest.mark.parametrize("sample, account_id", ACCOUNTS)
def test_a_sample_compared_with_itself_has_no_changes(folders, sample, account_id):
    previous = _previous(folders, sample, account_id)
    again = dataclasses.replace(
        previous, execution_id="copy", saved_at=script.CURRENT_SAVED_AT
    )
    comparison = compare_runs(previous, again)
    assert not comparison.has_changes
    assert {row.match_rule for row in comparison.rows} == {MatchRule.EXACT}
    assert_invariants(previous, again, comparison)


@pytest.mark.parametrize("sample, account_id", ACCOUNTS)
def test_current_run_survives_a_csv_round_trip(folders, sample, account_id, tmp_path):
    current = script.make_current_run(_previous(folders, sample, account_id))
    files = script.write_run(
        current.findings, script.CURRENT_ID, script.agentic_owners()
    )
    for name, text in files.items():
        (tmp_path / name).write_bytes(text.encode("utf-8"))
    again = _read_folder(tmp_path, account_id, script.CURRENT_SAVED_AT)
    assert Counter(again.findings) == Counter(current.findings)
    assert (again.modules, again.regions) == (current.modules, current.regions)


# --- worked out by hand from the edits --------------------------------------------------


def test_single_account_sample_results(folders):
    _previous_run, _current, comparison = _compared(folders, "single_account", SINGLE)
    rows = _rows_by_check(comparison)

    def only(check_id, region):
        changed = [
            row for row in rows[(check_id, region)] if row.change in script.CHANGES
        ]
        assert len(changed) == 1, changed
        return changed[0].change, changed[0].match_rule

    assert only("SM-04", "us-east-1") == (Change.REGRESSED, MatchRule.SINGLE_ROW)
    assert only("AC-09", "Global") == (Change.RESOLVED, MatchRule.SINGLE_ROW)
    assert only("SM-26", "us-east-2") == (
        Change.NO_LONGER_ASSESSED,
        MatchRule.SINGLE_ROW,
    )
    assert only("BR-37", "us-west-2") == (
        Change.NO_LONGER_REPORTED,
        MatchRule.UNMATCHED,
    )
    assert only("AR-02", "Global") == (Change.NEW, MatchRule.SINGLE_ROW)
    assert only("AC-14", "us-east-1") == (Change.RESOLVED, MatchRule.SINGLE_ROW)
    assert only("BR-03", "Global") == (Change.NEW, MatchRule.UNMATCHED)
    # The three roles already in BR-03 are still open, paired by identical details.
    assert Counter(
        (row.change, row.match_rule) for row in rows[("BR-03", "Global")]
    ) == Counter(
        {(Change.STILL_OPEN, MatchRule.EXACT): 3, (Change.NEW, MatchRule.UNMATCHED): 1}
    )
    # Titles change with the status, as the scanners write them (review F1).
    (sm04,) = rows[("SM-04", "us-east-1")]
    assert (sm04.previous.finding, sm04.current.finding) == (
        "GuardDuty Enabled",
        "GuardDuty Not Enabled",
    )
    # AR-01: one Passed summary row became two Failed rows with their own
    # titles; both pair with the summary row (check-level) and show Regressed.
    ar01 = rows[("AR-01", "Global")]
    assert Counter((row.change, row.match_rule) for row in ar01) == Counter(
        {(Change.REGRESSED, MatchRule.CHECK_LEVEL): 2}
    )
    assert {row.previous.finding for row in ar01} == {
        "AWS Agent Registry IAM Full Access Check"
    }
    # The severity shown for a finding no longer assessed is the previous run's.
    (sm26,) = rows[("SM-26", "us-east-2")]
    assert sm26.severity == "High"
    # Previous run: 17 failed By Service rows. AC-09, AC-14, SM-26 and BR-37
    # changed. Regressed: SM-04 and the two AR-01 rows.
    tiles = comparison.tile_counts()
    assert {change: tiles[change] for change in script.CHANGES} == {
        Change.REGRESSED: 3,
        Change.NEW: 2,
        Change.RESOLVED: 2,
        Change.NO_LONGER_REPORTED: 1,
        Change.NO_LONGER_ASSESSED: 1,
    }
    assert tiles[Change.STILL_OPEN] == 17 - 4
    assert comparison.days_apart == 24


def test_multi_account_sample_results(folders):
    # This account's only previous BR-03 row was its Passed summary row, so the
    # new failing role is paired with it: Regressed, not New.
    _p, _c, comparison = _compared(folders, "multi_account", "444455556666")
    (br03,) = _rows_by_check(comparison)[("BR-03", "Global")]
    assert (br03.change, br03.match_rule) == (Change.REGRESSED, MatchRule.SINGLE_ROW)

    # Every account had AR-01's Passed summary row: two Regressed, check-level.
    for account_id in ("111122223333", "444455556666", "777788889999"):
        ar01 = _rows_by_check(_compared(folders, "multi_account", account_id)[2])[
            ("AR-01", "Global")
        ]
        assert Counter((row.change, row.match_rule) for row in ar01) == Counter(
            {(Change.REGRESSED, MatchRule.CHECK_LEVEL): 2}
        ), account_id

    # Day counts moved on by 24 days; the rows still pair (matching step 1b).
    normalized = {
        account_id: sorted(
            row.check_id
            for row in _compared(folders, "multi_account", account_id)[2].rows
            if row.match_rule is MatchRule.NORMALIZED
        )
        for account_id in ("111122223333", "444455556666", "777788889999")
    }
    assert normalized == {
        "111122223333": ["AC-03", "AG-17", "FS-31", "OW-09"],
        "444455556666": ["AC-03", "AG-17"],
        "777788889999": ["FS-31", "OW-09"],
    }


@pytest.mark.parametrize("sample, account_id", ACCOUNTS)
def test_derived_rows_change_with_their_source(folders, sample, account_id):
    # AC-14 us-east-1 resolved: its AG-28 and OW-02 rows are resolved too.
    # SM-26 us-east-2 no longer assessed: its OW-01 and OW-10 rows too.
    # BR-37 us-west-2 gone: its OW-02 row too.
    _p, _c, comparison = _compared(folders, sample, account_id)
    derived = Counter(
        (row.area, row.check_id, row.region, row.change, row.match_rule)
        for row in comparison.rows
        if row.area in script.DERIVED_AREAS and row.change in script.CHANGES
    )
    assert derived == Counter(
        [
            ("agentic", "AG-28", "us-east-1", Change.RESOLVED, MatchRule.SINGLE_ROW),
            ("owasp", "OW-02", "us-east-1", Change.RESOLVED, MatchRule.SINGLE_ROW),
            (
                "owasp",
                "OW-01",
                "us-east-2",
                Change.NO_LONGER_ASSESSED,
                MatchRule.SINGLE_ROW,
            ),
            (
                "owasp",
                "OW-10",
                "us-east-2",
                Change.NO_LONGER_ASSESSED,
                MatchRule.SINGLE_ROW,
            ),
            (
                "owasp",
                "OW-02",
                "us-west-2",
                Change.NO_LONGER_REPORTED,
                MatchRule.UNMATCHED,
            ),
        ]
    )


def test_an_edit_that_matches_no_row_is_an_error(folders):
    previous = _previous(folders, "single_account", SINGLE)
    without = tuple(
        finding for finding in previous.findings if finding.check_id != "SM-04"
    )
    with pytest.raises(
        ValueError, match="edit SM-04 us-east-1 Passed: expected one row"
    ):
        script.apply_edits(without)


def test_day_counts_move_on_by_the_days_between_runs():
    assert script.shift_days("role 'a' (255 days), role 'b' (1 day)") == (
        "role 'a' (279 days), role 'b' (25 days)"
    )
    assert script.shift_days("kb last completed ingestion 8 days ago") == (
        "kb last completed ingestion 32 days ago"
    )
    assert script.shift_days("no day counts here, 2026-09-27") == (
        "no day counts here, 2026-09-27"
    )


# --- values AWS generated in the sample reports (review item L8) ------------------


def _values_in_samples():
    """Every generated value in the sample reports, by kind (read, never saved)."""
    found = {}
    for name in script.SAMPLES.values():
        report = (REPO_ROOT / "sample-reports" / name).read_text(encoding="utf-8")
        for row in script.parse_report(report):
            for text in (row.finding, row.details, row.resolution):
                for start, end, kind in script.generated_values(text):
                    found.setdefault(kind, set()).add(text[start:end])
    return found


SAMPLE_VALUES = _values_in_samples()
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "assessment_history"
# Files this PR adds, or whose text it writes.
COMMITTED_FILES = sorted(
    {
        REPO_ROOT / "sample-reports" / script.SAMPLE_CHANGES_PAGE,
        REPO_ROOT / "sample-reports" / script.SAMPLE_CHANGES_CSV,
        SCRIPT,
        SCRIPT.parent / "capture_changes_screenshot.py",
        REPO_ROOT / "docs" / "ASSESSMENT_HISTORY.md",
        REPO_ROOT / "tests" / "assessment_history_helpers.py",
        REPO_ROOT / "tests" / "test_capture_changes_screenshot.py",
        *(REPO_ROOT / "assessment_history").glob("*.py"),
        *(REPO_ROOT / "tests").glob("test_assessment_history_*.py"),
        *(
            path
            for path in FIXTURES.rglob("*")
            if path.is_file() and not path.name.startswith(".")
        ),
    }
)


def test_every_kind_of_generated_value_occurs_in_the_samples():
    # A pattern that matches nothing is a mistake, or no longer needed.
    kinds = {kind for kind, _pattern in script.GENERATED_VALUE_KINDS}
    assert set(SAMPLE_VALUES) == kinds | {script.PERSONAL_NAME}


@pytest.mark.parametrize(
    "path", COMMITTED_FILES, ids=lambda path: str(path.relative_to(REPO_ROOT))
)
def test_no_generated_value_from_the_samples_is_committed(path):
    text = path.read_text(encoding="utf-8")
    # Kinds and counts only, so a failure doesn't print the values in CI logs.
    leaked = Counter(
        kind
        for kind, values in SAMPLE_VALUES.items()
        for value in values
        if value in text
    )
    assert not leaked, f"values copied from the sample reports: {dict(leaked)}"


def _shape(value):
    return [
        "9" if c.isdigit() else "a" if c.islower() else "A" if c.isupper() else c
        for c in value
    ]


def test_replacing_generated_values_keeps_everything_else():
    text = (
        "Role 'DemoStack-Ec2Role4B1C2D3E-Qx4mTr8vLp2K' uses vpc-0a1b2c3d4e5f60718 "
        "and vpc-1a2b3c4d. Knowledge base 'kb-demo' (ID: K7Q2ZP9XWA); role "
        "'cdk-hnb659fds-lookup-role-123456789012-us-east-1'; bucket "
        "'demo-bucket-111122223333'; last used 12 days ago, on 2026-09-01."
    )
    spans = script.generated_values(text)
    assert [text[start:end] for start, end, _kind in spans] == [
        "4B1C2D3E",
        "Qx4mTr8vLp2K",
        "0a1b2c3d4e5f60718",
        "1a2b3c4d",
        "K7Q2ZP9XWA",
    ]
    replaced = script.replace_generated_values(text)
    assert len(replaced) == len(text)
    covered = set()
    for start, end, _kind in spans:
        assert replaced[start:end] != text[start:end]
        assert _shape(replaced[start:end]) == _shape(text[start:end])
        covered.update(range(start, end))
    kept = [i for i in range(len(text)) if i not in covered]
    assert [replaced[i] for i in kept] == [text[i] for i in kept]
    start, end, _kind = spans[2]
    assert re.fullmatch(r"[0-9a-f]{17}", replaced[start:end])  # hex stays hex
    assert script.replace_generated_values(text) == replaced  # same every time


def test_a_personal_name_is_replaced(monkeypatch):
    names = frozenset({hashlib.sha256(b"jdoe").hexdigest()})
    monkeypatch.setattr(script, "PERSONAL_NAME_SHA256", names)
    text = "Bucket 'kb-agent-jdoe', owner JDoe"
    spans = script.generated_values(text)
    assert [(text[start:end], kind) for start, end, kind in spans] == [
        ("jdoe", script.PERSONAL_NAME),
        ("JDoe", script.PERSONAL_NAME),
    ]
    assert "jdoe" not in script.replace_generated_values(text).lower()


@pytest.mark.parametrize("sample", list(script.SAMPLES))
def test_replacing_generated_values_changes_no_comparison_result(sample):
    report = (REPO_ROOT / "sample-reports" / script.SAMPLES[sample]).read_text(
        encoding="utf-8"
    )
    rows = script.parse_report(report)
    owners = script.agentic_owners()

    def results(sample_rows):
        found = {}
        for account_id in sorted({row.account_id for row in sample_rows}):
            files = script.write_run(
                [row for row in sample_rows if row.account_id == account_id],
                script.PREVIOUS_ID,
                owners,
            )
            previous = script.read_run(files, account_id, script.PREVIOUS_SAVED_AT)
            comparison = compare_runs(previous, script.make_current_run(previous))
            found[account_id] = Counter(
                (row.area, row.region, row.check_id, row.change, row.match_rule)
                for row in comparison.rows
            )
        return found

    assert results(script.anonymize(rows)) == results(rows)
