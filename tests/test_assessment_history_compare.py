"""Comparison rules for the changes-since-last-assessment report.

Dataset A scenarios A01-A14 are built in memory with
tests/assessment_history_helpers.py. Every comparison is also checked
against the invariants: each row of each run appears exactly once, and no
row is paired twice.
"""

import random
from collections import Counter

import pytest

from assessment_history.compare import classify, compare_runs, dedupe
from assessment_history.models import (
    CURRENT_RUN,
    MODULE_NOT_IN_BOTH_RUNS,
    PREVIOUS_RUN,
    REGION_NOT_IN_BOTH_RUNS,
    Change,
    MatchRule,
)
from tests.assessment_history_helpers import (
    ACCOUNT,
    OTHER_ACCOUNT,
    assert_invariants,
    changes,
    make_finding,
    make_run,
    utc,
)

NF = Change.NOT_FAILING


def _compare(previous_findings, current_findings, *, previous=None, current=None):
    previous_run = make_run(
        previous_findings, execution_id="run-previous", **(previous or {})
    )
    current_run = make_run(
        current_findings, execution_id="run-current", **(current or {})
    )
    result = compare_runs(previous_run, current_run)
    assert_invariants(previous_run, current_run, result)
    return result


def _by_rule(result):
    return Counter((row.change, row.match_rule) for row in result.rows)


# --- A01 identical runs -------------------------------------------------------


def test_a01_identical_runs_have_no_changes():
    findings = [
        make_finding("BR-01", "Failed"),
        make_finding("SM-26", "Passed", region="us-east-1"),
        make_finding("AC-17", "N/A", region="us-east-1", severity="Informational"),
    ]
    result = _compare(findings, findings)
    assert not result.has_changes
    assert changes(result) == Counter({Change.STILL_OPEN: 1, NF: 2})
    assert {row.match_rule for row in result.rows} == {MatchRule.EXACT}


# --- A02 transition matrix ------------------------------------------------------

TRANSITIONS = [
    ("Passed", "Passed", NF),
    ("Passed", "Failed", Change.REGRESSED),
    ("Passed", "N/A", NF),
    ("Passed", None, NF),
    ("Failed", "Passed", Change.RESOLVED),
    ("Failed", "Failed", Change.STILL_OPEN),
    ("Failed", "N/A", Change.NO_LONGER_ASSESSED),
    ("Failed", None, Change.NO_LONGER_REPORTED),
    ("N/A", "Passed", NF),
    ("N/A", "Failed", Change.NEW),
    ("N/A", "N/A", NF),
    ("N/A", None, NF),
    (None, "Passed", NF),
    (None, "Failed", Change.NEW),
    (None, "N/A", NF),
]


def test_a02_matrix_covers_every_combination():
    statuses = ["Passed", "Failed", "N/A", None]
    expected = {(p, c) for p in statuses for c in statuses} - {(None, None)}
    assert {(p, c) for p, c, _ in TRANSITIONS} == expected
    assert len(TRANSITIONS) == 15


@pytest.mark.parametrize("previous, current, expected", TRANSITIONS)
def test_a02_transition_matrix(previous, current, expected):
    assert classify(previous, current) is expected
    result = _compare(
        [make_finding("BR-01", previous)] if previous else [],
        [make_finding("BR-01", current)] if current else [],
    )
    assert [row.change for row in result.rows] == [expected]


def test_classify_needs_one_side():
    with pytest.raises(ValueError, match="at least one side"):
        classify(None, None)


# --- A03 BR-03: one row per IAM role, one fixed and one new ----------------------


def _br03(role, status="Failed"):
    return make_finding(
        "BR-03",
        status,
        finding="Marketplace Subscription Access Check",
        details=f"Role '{role}' has overly permissive marketplace subscription access",
    )


def test_a03_per_resource_rows_pair_by_details():
    result = _compare(
        [_br03("role-a"), _br03("role-b"), _br03("role-c")],
        [_br03("role-a"), _br03("role-b"), _br03("role-d")],
    )
    assert _by_rule(result) == Counter(
        {
            (Change.STILL_OPEN, MatchRule.EXACT): 2,
            (Change.NO_LONGER_REPORTED, MatchRule.UNMATCHED): 1,
            (Change.NEW, MatchRule.UNMATCHED): 1,
        }
    )
    gone = next(r for r in result.rows if r.change is Change.NO_LONGER_REPORTED)
    new = next(r for r in result.rows if r.change is Change.NEW)
    assert "role-c" in gone.previous.details
    assert "role-d" in new.current.details


# --- A04 BR-01: single row whose details changed ---------------------------------


def test_a04_single_row_pairs_even_when_details_change():
    result = _compare(
        [make_finding("BR-01", "Passed", details="No roles found with the policy")],
        [make_finding("BR-01", "Failed", details="Role 'x' has the policy attached")],
    )
    assert _by_rule(result) == Counter({(Change.REGRESSED, MatchRule.SINGLE_ROW): 1})


# --- A05 AG-17 / AC-03: day counts change every run -------------------------------


def _ag17(details):
    return make_finding(
        "AG-17",
        module="agentcore",
        finding="Agent Identity & Access",
        details=f"Source check AC-03: {details}",
    )


def test_a05_day_counts_are_blanked_before_matching():
    stale = "not accessed AgentCore in 60+ days: role 'a' ({} days)"
    never = "have never accessed the service: role 'b'"
    result = _compare(
        [
            _ag17(stale.format(255)),
            _ag17(never),
            make_finding("AC-03", details=stale.format(255)),
        ],
        [
            _ag17(stale.format(279)),
            _ag17(never),
            make_finding("AC-03", details=stale.format(279)),
        ],
    )
    assert _by_rule(result) == Counter(
        {
            (Change.STILL_OPEN, MatchRule.NORMALIZED): 2,
            (Change.STILL_OPEN, MatchRule.EXACT): 1,
        }
    )


# --- A06 BR-14: last-accessed dates change ----------------------------------------


def test_a06_dates_are_blanked_before_matching():
    def br14(identity, date):
        return make_finding(
            "BR-14",
            finding="Stale Bedrock Access Check",
            severity="Medium",
            details=f"{identity} last accessed Bedrock on {date}",
        )

    result = _compare(
        [br14("Role 'r1'", "2026-05-01"), br14("User 'u1'", "2026-04-01")],
        [br14("Role 'r1'", "2026-06-02"), br14("User 'u1'", "2026-06-01")],
    )
    assert _by_rule(result) == Counter({(Change.STILL_OPEN, MatchRule.NORMALIZED): 2})


# --- A07 AC-03 list of roles changed (documented limitation) -----------------------


def test_a07_changed_role_list_shows_as_gone_and_new():
    stale = "not accessed AgentCore in 60+ days: {}"
    never = "have never accessed the service: role 'z'"
    result = _compare(
        [_ag17(stale.format("role 'a' (255 days), role 'b' (90 days)")), _ag17(never)],
        [_ag17(stale.format("role 'a' (279 days), role 'c' (61 days)")), _ag17(never)],
    )
    assert _by_rule(result) == Counter(
        {
            (Change.STILL_OPEN, MatchRule.EXACT): 1,
            (Change.NO_LONGER_REPORTED, MatchRule.UNMATCHED): 1,
            (Change.NEW, MatchRule.UNMATCHED): 1,
        }
    )


def test_normalized_collisions_are_not_guessed():
    # Two previous rows read the same once day counts are blanked, so step 1b
    # can't tell which one continues; nothing is paired by guessing.
    result = _compare(
        [_ag17("role 'a' (10 days)"), _ag17("role 'a' (20 days)")],
        [_ag17("role 'a' (30 days)")],
    )
    assert {row.match_rule for row in result.rows} == {MatchRule.UNMATCHED}
    assert changes(result) == Counter({Change.NO_LONGER_REPORTED: 2, Change.NEW: 1})


# --- A08 optional module in one run only --------------------------------------------


def test_a08_module_in_one_run_only_is_not_compared():
    result = _compare(
        [make_finding("BR-01"), make_finding("OW-03")],
        [make_finding("BR-01"), make_finding("FS-01"), make_finding("FS-02")],
    )
    assert result.not_compared_modules == {
        "owasp": "previous run only",
        "responsible-ai-grc": "current run only",
    }
    assert [row.check_id for row in result.rows] == ["BR-01"]
    assert [(e.side, e.reason, e.finding.check_id) for e in result.excluded] == [
        (CURRENT_RUN, MODULE_NOT_IN_BOTH_RUNS, "FS-01"),
        (CURRENT_RUN, MODULE_NOT_IN_BOTH_RUNS, "FS-02"),
        (PREVIOUS_RUN, MODULE_NOT_IN_BOTH_RUNS, "OW-03"),
    ]


def test_a08_module_in_both_runs_is_compared():
    result = _compare(
        [make_finding("FS-01", "Failed")], [make_finding("FS-01", "Passed")]
    )
    assert result.not_compared_modules == {}
    assert changes(result) == Counter({Change.RESOLVED: 1})


# --- A09 regions added, removed, swapped ---------------------------------------------


@pytest.mark.parametrize(
    "previous_regions, current_regions, not_compared",
    [
        ({"us-east-1"}, {"us-east-1", "eu-west-1"}, {"eu-west-1": "current run only"}),
        ({"us-east-1", "us-west-2"}, {"us-east-1"}, {"us-west-2": "previous run only"}),
        (
            {"us-east-1", "us-west-2"},
            {"us-east-1", "eu-west-1"},
            {"eu-west-1": "current run only", "us-west-2": "previous run only"},
        ),
    ],
)
def test_a09_only_regions_in_both_runs_are_compared(
    previous_regions, current_regions, not_compared
):
    def regional(regions):
        return [make_finding("SM-26", region=region) for region in sorted(regions)]

    result = _compare(
        regional(previous_regions),
        regional(current_regions),
        previous={"regions": previous_regions},
        current={"regions": current_regions},
    )
    assert result.not_compared_regions == not_compared
    assert [row.region for row in result.rows] == ["us-east-1"]
    assert {e.reason for e in result.excluded} == {REGION_NOT_IN_BOTH_RUNS}
    assert {e.finding.region for e in result.excluded} == set(not_compared)


# --- A10 empty runs ------------------------------------------------------------------


def test_a10_current_run_with_no_findings():
    result = _compare([make_finding("BR-01"), make_finding("SM-26", "Passed")], [])
    assert changes(result) == Counter({Change.NO_LONGER_REPORTED: 1, NF: 1})


def test_a10_both_runs_empty():
    result = _compare([], [])
    assert result.rows == ()
    assert not result.has_changes
    assert result.tile_counts() == Counter()


# --- A11 Global rows are always compared ------------------------------------------


def test_a11_global_rows_ignore_region_scope():
    result = _compare(
        [
            make_finding("BR-01", region="Global"),
            make_finding("SM-26", region="us-east-1"),
        ],
        [
            make_finding("BR-01", region="Global"),
            make_finding("SM-26", region="us-west-2"),
        ],
        previous={"regions": {"us-east-1"}},
        current={"regions": {"us-west-2"}},
    )
    assert [row.check_id for row in result.rows] == ["BR-01"]
    assert len(result.excluded) == 2


# --- A12 regions unknown (CSV names without a region) --------------------------


@pytest.mark.parametrize(
    "previous_regions, current_regions",
    [(None, None), (None, {"us-east-1"}), ({"us-east-1"}, None)],
)
def test_a12_unknown_regions_compare_everything(previous_regions, current_regions):
    result = _compare(
        [make_finding("SM-26", region="us-west-2")],
        [make_finding("SM-26", region="us-west-2")],
        previous={"regions": previous_regions},
        current={"regions": current_regions},
    )
    assert result.not_compared_regions == {}
    assert result.excluded == ()
    assert len(result.rows) == 1


# --- A13 Agentic AI and OWASP rows repeat a core change ---------------------------


def test_a13_mapped_views_are_counted_per_area_not_in_tiles():
    def rows(status):
        return [
            make_finding("BR-01", status),
            make_finding("AG-01", status, details="Source check BR-01"),
            make_finding("OW-06", status, details="Source check BR-01"),
        ]

    result = _compare(rows("Passed"), rows("Failed"))
    assert {area: dict(counts) for area, counts in result.counts_by_area().items()} == {
        "bedrock": {Change.REGRESSED: 1},
        "agentic": {Change.REGRESSED: 1},
        "owasp": {Change.REGRESSED: 1},
    }
    assert result.tile_counts() == Counter({Change.REGRESSED: 1})


# --- A14 severity differs only because of N/A ------------------------------------------


def test_a14_severity_shown_and_both_kept_in_csv():
    result = _compare(
        [
            make_finding("SM-06", "N/A", region="us-east-1", severity="Informational"),
            make_finding("BR-37", "Failed", region="us-west-2", severity="High"),
        ],
        [
            make_finding("SM-06", "Failed", region="us-east-1", severity="Medium"),
            make_finding("BR-37", "N/A", region="us-west-2", severity="Informational"),
        ],
    )
    by_check = {row.check_id: row for row in result.rows}
    assert (by_check["SM-06"].change, by_check["SM-06"].severity) == (
        Change.NEW,
        "Medium",
    )
    assert (by_check["BR-37"].change, by_check["BR-37"].severity) == (
        Change.NO_LONGER_ASSESSED,
        "High",
    )
    records = {r["Check_ID"]: r for r in result.to_csv_records()}
    assert (
        records["SM-06"]["Previous_Severity"],
        records["SM-06"]["Current_Severity"],
    ) == (
        "Informational",
        "Medium",
    )


# --- other rules --------------------------------------------------------------------


def test_repeated_rows_are_dropped_with_the_main_report_key():
    first = make_finding("BR-01", "Failed", severity="High")
    repeat = make_finding(
        "BR-01", "Passed", severity="Low"
    )  # same key, differs elsewhere
    other_details = make_finding("BR-01", details="other")
    assert dedupe([first, repeat, other_details]) == (first, other_details)
    result = _compare([first, repeat], [first])
    assert changes(result) == Counter({Change.STILL_OPEN: 1})


def test_check_ids_in_only_one_run_are_listed():
    result = _compare(
        [make_finding("BR-01"), make_finding("BR-40")],
        [make_finding("BR-01"), make_finding("BR-41")],
    )
    assert result.single_run_check_ids == {
        "BR-40": "previous run only",
        "BR-41": "current run only",
    }


def test_excluded_rows_do_not_count_as_single_run_check_ids():
    result = _compare(
        [make_finding("BR-01")], [make_finding("BR-01"), make_finding("OW-03")]
    )
    assert result.single_run_check_ids == {}


def test_comparison_carries_run_details():
    previous = make_run([], execution_id="run-a", saved_at=utc(3, 23, 37))
    current = make_run([], execution_id="run-b", saved_at=utc(27, 6, 15))
    result = compare_runs(previous, current)
    assert (
        result.account_id,
        result.previous_execution_id,
        result.current_execution_id,
    ) == (
        ACCOUNT,
        "run-a",
        "run-b",
    )
    assert result.days_apart == 24


def test_rows_are_sorted_by_area_then_region_then_check():
    findings = [
        make_finding("OW-03", region="us-east-1"),
        make_finding("SM-26", region="us-west-2"),
        make_finding("SM-26", region="us-east-1"),
        make_finding("BR-02"),
        make_finding("BR-01"),
    ]
    result = _compare(findings, findings)
    assert [(r.area, r.region, r.check_id) for r in result.rows] == [
        ("bedrock", "Global", "BR-01"),
        ("bedrock", "Global", "BR-02"),
        ("sagemaker", "us-east-1", "SM-26"),
        ("sagemaker", "us-west-2", "SM-26"),
        ("owasp", "us-east-1", "OW-03"),
    ]


def _mixed_runs():
    previous = [
        _br03("role-a"),
        _br03("role-b"),
        _br03("role-c"),
        make_finding("BR-01", "Passed", details="none"),
        _ag17("role 'a' (255 days)"),
        make_finding("SM-26", "Failed", region="us-east-1"),
        make_finding("SM-02", "N/A", region="us-east-1"),
        make_finding("OW-03", "Failed"),
    ]
    current = [
        _br03("role-a"),
        _br03("role-d"),
        make_finding("BR-01", "Failed", details="Role 'x'"),
        _ag17("role 'a' (279 days)"),
        make_finding("SM-26", "Passed", region="us-east-1"),
        make_finding("SM-02", "Failed", region="us-east-1"),
        make_finding("FS-01", "Failed"),
    ]
    return previous, current


def test_results_do_not_depend_on_row_order():
    previous, current = _mixed_runs()
    expected = _compare(previous, current)
    shuffler = random.Random(20260927)
    for _ in range(25):
        shuffled_previous, shuffled_current = previous[:], current[:]
        shuffler.shuffle(shuffled_previous)
        shuffler.shuffle(shuffled_current)
        result = _compare(shuffled_previous, shuffled_current)
        assert result.rows == expected.rows
        assert result.excluded == expected.excluded


def test_comparing_a_run_with_a_copy_of_itself_finds_no_changes():
    previous, current = _mixed_runs()
    for findings in (previous, current):
        result = _compare(findings, findings)
        assert not result.has_changes
        assert result.not_compared_modules == {}


def test_runs_of_different_accounts_are_rejected():
    with pytest.raises(ValueError, match="different accounts"):
        compare_runs(
            make_run([], execution_id="a"),
            make_run([], execution_id="b", account_id=OTHER_ACCOUNT),
        )


def test_a_run_compared_with_itself_by_id_is_rejected():
    run = make_run([], execution_id="same")
    with pytest.raises(ValueError, match="Both runs are execution same"):
        compare_runs(run, run)
