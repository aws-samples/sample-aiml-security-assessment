"""Record shapes for the changes-since-last-assessment comparison.

Covers status normalization, area routing (checked against the main report),
input validation, severity shown per change, the changes-CSV record, and the
comparison summaries.
"""

import importlib.util
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from assessment_history.models import (
    AREAS,
    COMPLIANCE_PREFIX_TO_AREA,
    CORE_AREAS,
    CSV_COLUMNS,
    NOT_PRESENT,
    Change,
    ComparedRow,
    Comparison,
    Finding,
    InvalidFindingError,
    MatchRule,
    Run,
    assign_area,
    csv_safe,
    normalize_status,
)
from tests.assessment_history_helpers import (
    ACCOUNT,
    OTHER_ACCOUNT,
    make_finding,
    make_run,
    utc,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORT_TEMPLATE = (
    REPO_ROOT
    / "aiml-security-assessment"
    / "functions"
    / "security"
    / "generate_consolidated_report"
    / "report_template.py"
)


def _load_report_template():
    spec = importlib.util.spec_from_file_location(
        "assessment_history_test_report_template", REPORT_TEMPLATE
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- normalize_status -------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("Failed", "Failed"),
        (" failed ", "Failed"),
        ("PASSED", "Passed"),
        ("n/a", "N/A"),
        ("N/A", "N/A"),
    ],
)
def test_normalize_status_ignores_case_and_spaces(raw, expected):
    assert normalize_status(raw) == expected


@pytest.mark.parametrize("raw", ["", None, "Unknown", "WARN", "NA"])
def test_normalize_status_rejects_other_values(raw):
    with pytest.raises(InvalidFindingError, match="Unrecognized Status"):
        normalize_status(raw)


# --- assign_area --------------------------------------------------------------


@pytest.mark.parametrize(
    "module, check_id, area",
    [
        ("bedrock", "BR-01", "bedrock"),
        ("sagemaker", "SM-26", "sagemaker"),
        ("agentcore", "AC-03", "agentcore"),
        ("bedrock", "AG-01", "agentic"),
        ("agentcore", "ag-17", "agentic"),
        ("agent-registry", "AR-02", "agent-registry"),
        ("agentcore", "AR-01", "agent-registry"),
        ("responsible-ai-grc", "FS-31", "responsible-ai-grc"),
        ("owasp", "OW-03", "owasp"),
        # Unknown prefix or no dash: stays with its module, like the main report.
        ("owasp", "NR-01", "owasp"),
        ("bedrock", "BR01", "bedrock"),
    ],
)
def test_assign_area_routes_like_the_main_report(module, check_id, area):
    assert assign_area(module, check_id) == area


def test_assign_area_rejects_unknown_module():
    with pytest.raises(InvalidFindingError, match="Unknown assessment module"):
        assign_area("comprehend", "CM-01")


def test_compliance_prefixes_match_report_template():
    template = _load_report_template()
    expected = {
        standard["prefix"].upper().rstrip("-"): standard["slug"]
        for standard in template.COMPLIANCE_STANDARDS
    }
    assert COMPLIANCE_PREFIX_TO_AREA == expected
    assert template.RESPONSIBLE_AI_GRC_SLUG in AREAS
    assert set(expected.values()) <= set(AREAS)


# --- validation ---------------------------------------------------------------


def _finding_kwargs(**overrides):
    values = dict(
        account_id=ACCOUNT,
        module="bedrock",
        area="bedrock",
        region="Global",
        check_id="BR-01",
        finding="check",
        details="details",
        severity="High",
        status="Failed",
    )
    values.update(overrides)
    return values


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"account_id": "12345"}, "Invalid AWS account ID"),
        ({"account_id": "12345678901a"}, "Invalid AWS account ID"),
        ({"module": "comprehend"}, "Unknown assessment module"),
        ({"area": "comprehend"}, "Unknown assessment area"),
        ({"status": "failed"}, "Status must be normalized"),
    ],
)
def test_finding_rejects_invalid_values(overrides, message):
    with pytest.raises(InvalidFindingError, match=message):
        Finding(**_finding_kwargs(**overrides))


def test_run_coerces_collections():
    finding = make_finding()
    run = Run(
        account_id=ACCOUNT,
        execution_id="run-1",
        findings=[finding],
        modules={"bedrock"},
        regions=["us-east-1"],
    )
    assert run.findings == (finding,)
    assert run.modules == frozenset({"bedrock"})
    assert run.regions == frozenset({"us-east-1"})


def test_run_allows_unknown_regions():
    assert make_run(regions=None).regions is None


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"account_id": "bad"}, "Invalid AWS account ID"),
        ({"execution_id": ""}, "needs an execution ID"),
        ({"modules": {"bedrock", "comprehend"}}, "Unknown assessment modules"),
        ({"saved_at": datetime(2026, 9, 27)}, "timezone-aware"),
    ],
)
def test_run_rejects_invalid_values(kwargs, message):
    values = dict(
        account_id=ACCOUNT, execution_id="run-1", findings=(), modules={"bedrock"}
    )
    values.update(kwargs)
    with pytest.raises(InvalidFindingError, match=message):
        Run(**values)


def test_run_rejects_finding_from_another_account():
    finding = make_finding(account_id=OTHER_ACCOUNT)
    with pytest.raises(InvalidFindingError, match="Finding for account"):
        make_run([finding])


def test_run_rejects_finding_from_a_module_it_did_not_write():
    finding = make_finding("OW-03")
    with pytest.raises(InvalidFindingError, match="didn't write"):
        make_run([finding], modules={"bedrock"})


# --- ComparedRow ------------------------------------------------------------


def test_compared_row_needs_one_side():
    with pytest.raises(ValueError, match="at least one side"):
        ComparedRow(Change.NOT_FAILING, MatchRule.UNMATCHED, None, None)


def test_compared_row_reads_current_side_when_paired():
    previous = make_finding(
        "BR-03", severity="Medium", details="old", resolution="old fix"
    )
    current = make_finding(
        "BR-03", severity="High", details="new", resolution="new fix"
    )
    row = ComparedRow(Change.STILL_OPEN, MatchRule.SINGLE_ROW, previous, current)
    assert (row.account_id, row.area, row.region, row.check_id, row.finding) == (
        ACCOUNT,
        "bedrock",
        "Global",
        "BR-03",
        "BR-03 check",
    )
    assert (row.previous_status, row.current_status) == ("Failed", "Failed")
    assert row.severity == "High"
    assert row.resolution == "new fix"
    assert row.reference == "https://docs.aws.amazon.com/"


@pytest.mark.parametrize(
    "change, rule, current_details, expected",
    [
        (Change.STILL_OPEN, MatchRule.SINGLE_ROW, "resource b", True),
        (Change.STILL_OPEN, MatchRule.SINGLE_ROW, "resource a", False),
        (Change.STILL_OPEN, MatchRule.EXACT, "resource a", False),
        (Change.STILL_OPEN, MatchRule.DETAILS, "resource a", False),
        (Change.REGRESSED, MatchRule.SINGLE_ROW, "resource b", False),
    ],
)
def test_details_changed_only_for_a_single_row_still_open_pair(
    change, rule, current_details, expected
):
    # Review item F3: two Failed rows paired only because each run had one.
    row = ComparedRow(
        change,
        rule,
        make_finding("SM-01", details="resource a"),
        make_finding("SM-01", details=current_details),
    )
    assert row.details_changed is expected


def test_compared_row_one_sided_statuses():
    only_previous = ComparedRow(
        Change.NO_LONGER_REPORTED, MatchRule.UNMATCHED, make_finding(), None
    )
    only_current = ComparedRow(Change.NEW, MatchRule.UNMATCHED, None, make_finding())
    assert only_previous.current_status == NOT_PRESENT
    assert only_current.previous_status == NOT_PRESENT
    assert only_previous.resolution == "Fix it."


@pytest.mark.parametrize(
    "change, current_status, shown",
    [
        (Change.NO_LONGER_REPORTED, None, "High"),
        (Change.NO_LONGER_ASSESSED, "N/A", "High"),
        (Change.STILL_OPEN, "Failed", "Informational"),
        (Change.NOT_FAILING, None, "High"),
    ],
)
def test_severity_shown_per_change(change, current_status, shown):
    previous = make_finding(severity="High")
    current = (
        make_finding(status=current_status, severity="Informational")
        if current_status
        else None
    )
    assert ComparedRow(change, MatchRule.EXACT, previous, current).severity == shown


def test_csv_record_has_every_column_in_order():
    previous = make_finding("SM-26", "N/A", severity="Informational", details="before")
    current = make_finding("SM-26", "Failed", severity="Medium", details="after")
    record = ComparedRow(
        Change.NEW, MatchRule.SINGLE_ROW, previous, current
    ).to_csv_record("prev-id", "cur-id")
    assert tuple(record) == CSV_COLUMNS
    assert record["Assessment_Area"] == "sagemaker"
    assert record["Change"] == "New"
    assert (record["Previous_Status"], record["Current_Status"]) == ("N/A", "Failed")
    assert (record["Previous_Severity"], record["Current_Severity"]) == (
        "Informational",
        "Medium",
    )
    assert (
        record["Previous_Finding_Details"],
        record["Current_Finding_Details"],
    ) == ("before", "after")
    assert record["Match_Rule"] == "single-row"
    assert (record["Previous_Execution_ID"], record["Current_Execution_ID"]) == (
        "prev-id",
        "cur-id",
    )


def test_csv_record_for_one_sided_row_leaves_other_side_blank():
    record = ComparedRow(
        Change.NEW, MatchRule.UNMATCHED, None, make_finding()
    ).to_csv_record("p", "c")
    assert record["Previous_Status"] == NOT_PRESENT
    assert record["Previous_Severity"] == ""
    assert record["Previous_Finding_Details"] == ""


@pytest.mark.parametrize("text", ["=1+1", "+SUM(A1)", "-2", "@cmd", "\tx", "\rx"])
def test_csv_safe_neutralizes_formulas(text):
    assert csv_safe(text) == "'" + text


@pytest.mark.parametrize("text", ["", "Role 'a=b'", "Failed", "2026-09-27"])
def test_csv_safe_leaves_other_text(text):
    assert csv_safe(text) == text


def test_csv_record_applies_formula_protection():
    current = make_finding(details='=HYPERLINK("http://example.com")')
    record = ComparedRow(Change.NEW, MatchRule.UNMATCHED, None, current).to_csv_record(
        "p", "c"
    )
    assert record["Current_Finding_Details"].startswith("'=")


# --- Comparison summaries ------------------------------------------------------


def _comparison(rows, **kwargs):
    return Comparison(
        account_id=ACCOUNT,
        previous_execution_id="p",
        current_execution_id="c",
        rows=tuple(rows),
        **kwargs,
    )


def _row(change, check_id):
    return ComparedRow(change, MatchRule.EXACT, None, make_finding(check_id))


def test_has_changes_ignores_still_open_and_not_failing():
    quiet = _comparison(
        [_row(Change.STILL_OPEN, "BR-01"), _row(Change.NOT_FAILING, "SM-01")]
    )
    assert not quiet.has_changes
    assert _comparison([_row(Change.RESOLVED, "BR-01")]).has_changes


def test_counts_by_area_follow_report_order():
    comparison = _comparison(
        [
            _row(Change.REGRESSED, "OW-03"),
            _row(Change.REGRESSED, "AG-01"),
            _row(Change.REGRESSED, "BR-01"),
            _row(Change.NEW, "BR-02"),
        ]
    )
    by_area = comparison.counts_by_area()
    assert list(by_area) == ["bedrock", "agentic", "owasp"]
    assert by_area["bedrock"] == Counter({Change.REGRESSED: 1, Change.NEW: 1})


def test_tile_counts_use_by_service_areas_only():
    comparison = _comparison(
        [
            _row(Change.REGRESSED, "BR-01"),
            _row(Change.REGRESSED, "AG-01"),
            _row(Change.REGRESSED, "OW-03"),
            _row(Change.REGRESSED, "FS-01"),
            _row(Change.RESOLVED, "SM-26"),
        ]
    )
    assert comparison.tile_counts() == Counter(
        {Change.REGRESSED: 1, Change.RESOLVED: 1}
    )
    assert CORE_AREAS == ("bedrock", "sagemaker", "agentcore", "agent-registry")


def test_tile_counts_empty():
    assert _comparison([]).tile_counts() == Counter()


@pytest.mark.parametrize(
    "previous, current, days",
    [
        (utc(3, 23, 37), utc(27, 6, 15), 24),
        (utc(3, 23, 0), utc(4, 1, 0), 1),
        (utc(27, 1, 0), utc(27, 23, 0), 0),
        (None, utc(27), None),
        (utc(3), None, None),
    ],
)
def test_days_apart_counts_utc_calendar_days(previous, current, days):
    comparison = _comparison([], previous_saved_at=previous, current_saved_at=current)
    assert comparison.days_apart == days


def test_days_apart_converts_to_utc_first():
    chicago = timezone(timedelta(hours=-5))
    # 20:00 CDT on Sep 26 is 01:00 UTC on Sep 27.
    comparison = _comparison(
        [],
        previous_saved_at=datetime(2026, 9, 26, 20, 0, tzinfo=chicago),
        current_saved_at=utc(27, 2),
    )
    assert comparison.days_apart == 0


def test_to_csv_records_carry_both_execution_ids():
    records = _comparison([_row(Change.NEW, "BR-01")]).to_csv_records()
    assert len(records) == 1
    assert records[0]["Previous_Execution_ID"] == "p"
    assert records[0]["Current_Execution_ID"] == "c"
