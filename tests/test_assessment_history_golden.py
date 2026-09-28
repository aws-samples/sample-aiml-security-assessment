"""Golden tests: both sample reports, each compared with an edited copy.

sample-reports/scripts/build_changes_sample.py turns each sample report back
into the findings CSVs the scanners write (the previous run, saved under
tests/fixtures/assessment_history/golden/) and applies its EDITS to make a
current run. The saved answers are checked here, together with results
worked out by hand from the edits.

After a sample report or a comparison rule changes, regenerate and review
the diff:

    .venv/bin/python sample-reports/scripts/build_changes_sample.py
"""

import dataclasses
import importlib.util
import json
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
ACCOUNTS = [
    (sample, folder.name)
    for sample in script.SAMPLES
    for folder in sorted((GOLDEN / sample).iterdir())
    if folder.is_dir()
]


def _read_folder(folder, account_id, saved_at):
    source = DirectorySource(folder)
    runs, unknown = group_runs(source.list_files())
    assert unknown == []
    (run_files,) = runs.values()
    run, reason = read_complete_run(source, account_id, run_files)
    assert run is not None, reason
    return dataclasses.replace(run, saved_at=saved_at)


def _previous(sample, account_id):
    return _read_folder(
        GOLDEN / sample / account_id, account_id, script.PREVIOUS_SAVED_AT
    )


def _compared(sample, account_id):
    previous = _previous(sample, account_id)
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


def test_the_script_is_found_by_the_expected_paths():
    assert script.REPO_ROOT == REPO_ROOT
    assert [sample for sample, _ in ACCOUNTS] == [
        "single_account",
        "multi_account",
        "multi_account",
        "multi_account",
    ]


# --- reading the saved runs back gives the sample reports' rows --------------------


@pytest.mark.parametrize("sample", list(script.SAMPLES))
def test_saved_runs_read_back_as_the_sample_reports_rows(sample):
    report = (REPO_ROOT / "sample-reports" / script.SAMPLES[sample]).read_text(
        encoding="utf-8"
    )
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
        for row in script.parse_report(report)
    )
    found = Counter()
    for account_id in sorted(path.name for path in (GOLDEN / sample).iterdir()):
        if not (GOLDEN / sample / account_id).is_dir():
            continue
        previous = _previous(sample, account_id)
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
def test_comparison_matches_the_saved_answer(sample, account_id):
    previous, current, comparison = _compared(sample, account_id)
    expected = json.loads(
        (GOLDEN / f"expected_{sample}.json").read_text(encoding="utf-8")
    )
    assert script.summarize(comparison) == expected[account_id]
    assert_invariants(previous, current, comparison)


@pytest.mark.parametrize("sample, account_id", ACCOUNTS)
def test_a_sample_compared_with_itself_has_no_changes(sample, account_id):
    previous = _previous(sample, account_id)
    again = dataclasses.replace(
        previous, execution_id="copy", saved_at=script.CURRENT_SAVED_AT
    )
    comparison = compare_runs(previous, again)
    assert not comparison.has_changes
    assert {row.match_rule for row in comparison.rows} == {MatchRule.EXACT}
    assert_invariants(previous, again, comparison)


@pytest.mark.parametrize("sample, account_id", ACCOUNTS)
def test_current_run_survives_a_csv_round_trip(sample, account_id, tmp_path):
    current = script.make_current_run(_previous(sample, account_id))
    files = script.write_run(
        current.findings, script.CURRENT_ID, script.agentic_owners()
    )
    for name, text in files.items():
        (tmp_path / name).write_bytes(text.encode("utf-8"))
    again = _read_folder(tmp_path, account_id, script.CURRENT_SAVED_AT)
    assert Counter(again.findings) == Counter(current.findings)
    assert (again.modules, again.regions) == (current.modules, current.regions)


# --- worked out by hand from the edits --------------------------------------------------


def test_single_account_sample_results():
    _previous_run, _current, comparison = _compared("single_account", SINGLE)
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
    # The severity shown for a finding no longer assessed is the previous run's.
    (sm26,) = rows[("SM-26", "us-east-2")]
    assert sm26.severity == "High"
    # Previous run: 17 failed By Service rows. AC-09, AC-14, SM-26 and BR-37
    # changed.
    tiles = comparison.tile_counts()
    assert {change: tiles[change] for change in script.CHANGES} == {
        Change.REGRESSED: 1,
        Change.NEW: 2,
        Change.RESOLVED: 2,
        Change.NO_LONGER_REPORTED: 1,
        Change.NO_LONGER_ASSESSED: 1,
    }
    assert tiles[Change.STILL_OPEN] == 17 - 4
    assert comparison.days_apart == 24


def test_multi_account_sample_results():
    # This account's only previous BR-03 row was its Passed summary row, so the
    # new failing role is paired with it: Regressed, not New.
    _p, _c, comparison = _compared("multi_account", "444455556666")
    (br03,) = _rows_by_check(comparison)[("BR-03", "Global")]
    assert (br03.change, br03.match_rule) == (Change.REGRESSED, MatchRule.SINGLE_ROW)

    # Day counts moved on by 24 days; the rows still pair (matching step 1b).
    normalized = {
        account_id: sorted(
            row.check_id
            for row in _compared("multi_account", account_id)[2].rows
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
def test_derived_rows_change_with_their_source(sample, account_id):
    # AC-14 us-east-1 resolved: its AG-28 and OW-02 rows are resolved too.
    # SM-26 us-east-2 no longer assessed: its OW-01 and OW-10 rows too.
    # BR-37 us-west-2 gone: its OW-02 row too.
    _p, _c, comparison = _compared(sample, account_id)
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


def test_an_edit_that_matches_no_row_is_an_error():
    previous = _previous("single_account", SINGLE)
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
