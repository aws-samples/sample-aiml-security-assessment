"""AWS AI Security Framework (AISF) rows in the changes report.

No findings CSV holds AISF rows; the comparison derives them from each run's
compared findings with the main report's own aisf_mappings.py.
"""

import html
from collections import Counter

import pytest

from assessment_history import __main__ as cli
from assessment_history import compare as compare_module
from assessment_history import derived
from assessment_history.compare import compare_runs
from assessment_history.models import (
    DERIVED_MODULE,
    SERVICE_NOT_IN_BOTH_RUNS,
    Change,
    Finding,
    InvalidFindingError,
    MatchRule,
)
from assessment_history.render_changes import render_changes_page
from tests.assessment_history_helpers import (
    ACCOUNT,
    assert_invariants,
    make_finding,
    make_run,
    utc,
)

REGION = "us-east-1"


def _compare(previous_findings, current_findings, *, previous=None, current=None):
    previous_run = make_run(
        previous_findings,
        execution_id="run-previous",
        saved_at=utc(3),
        **(previous or {}),
    )
    current_run = make_run(
        current_findings,
        execution_id="run-current",
        saved_at=utc(27),
        **(current or {}),
    )
    result = compare_runs(previous_run, current_run)
    assert_invariants(previous_run, current_run, result)
    return result


def _aisf(result):
    return {row.check_id: row for row in result.rows if row.area == "aisf"}


def _sources(br20="Passed", sm="Passed", region=REGION):
    """Every source check of the three AISF controls, in one region."""
    return [
        make_finding("BR-20", br20, region=region),
        make_finding("SM-18", sm, region=region),
        make_finding("SM-42", sm, region=region),
        make_finding("SM-09", sm, region=region),
        make_finding("SM-01", sm, region=region),
        make_finding("SM-03", sm, region=region),
    ]


def test_an_aisf_row_changes_with_its_source():
    result = _compare(_sources(), _sources(br20="Failed"))
    rows = _aisf(result)
    assert sorted(rows) == ["AISF-05", "AISF-07", "AISF-08"]
    regressed = rows["AISF-05"]
    assert regressed.change is Change.REGRESSED
    assert regressed.match_rule is MatchRule.SINGLE_ROW
    assert (regressed.previous_status, regressed.current_status) == (
        "Passed",
        "Failed",
    )
    assert regressed.previous.module == regressed.current.module == DERIVED_MODULE
    assert regressed.region == REGION
    assert regressed.finding.startswith("AISF AIR-BDR-KB-03")
    assert rows["AISF-07"].change is Change.NOT_FAILING
    assert result.notes == ()


def test_aisf_rows_are_not_in_the_headline_counts():
    result = _compare(_sources(), _sources(br20="Failed"))
    assert result.counts_by_area()["aisf"][Change.REGRESSED] == 1
    assert result.tile_counts()[Change.REGRESSED] == 1  # BR-20 only


def test_aisf_rows_are_written_to_the_changes_csv():
    result = _compare(_sources(), _sources(br20="Failed"))
    records = [r for r in result.to_csv_records() if r["Check_ID"] == "AISF-05"]
    assert [(r["Assessment_Area"], r["Change"]) for r in records] == [
        ("aisf", "Regressed")
    ]


def test_a_service_selected_in_one_run_derives_none_of_its_controls():
    # SageMaker was selected in the current run only: its findings aren't
    # compared, so neither run gets an AISF row from them.
    bedrock_only = [make_finding("BR-20", "Passed", region=REGION)]
    result = _compare(
        bedrock_only,
        _sources(),
        previous={"modules": {"bedrock", "agentcore", "agent-registry"}},
    )
    assert sorted(_aisf(result)) == ["AISF-05"]
    assert {item.reason for item in result.excluded} == {SERVICE_NOT_IN_BOTH_RUNS}
    note = (
        "AWS AI Security Framework controls not compared "
        "(a source check's service was not selected in both runs): AISF-07, AISF-08"
    )
    assert result.notes == (note,)
    assert f"  {note}" in cli.describe(result)
    assert note in html.unescape(render_changes_page(result, csv_name="changes.csv"))


def test_a_region_scanned_in_one_run_derives_no_aisf_row_there():
    result = _compare(
        _sources(),
        _sources() + _sources(region="eu-west-1"),
        previous={"regions": {REGION}},
        current={"regions": {REGION, "eu-west-1"}},
    )
    assert {row.region for row in result.rows if row.area == "aisf"} == {REGION}


def test_a_run_without_aisf_sources_gets_no_aisf_rows():
    findings = [make_finding("BR-01", "Failed")]
    assert _aisf(_compare(findings, findings)) == {}


def test_a_derivation_problem_is_a_note_not_a_failure(monkeypatch):
    def broken(findings, account_id, services, **_):
        raise derived.DerivationError("aisf_mappings.py is missing")

    monkeypatch.setattr(compare_module, "derive_aisf", broken)
    result = _compare(_sources(), _sources(br20="Failed"))
    assert _aisf(result) == {}
    assert Counter(row.check_id for row in result.rows)["BR-20"] == 1
    note = "AWS AI Security Framework rows not compared: aisf_mappings.py is missing"
    assert result.notes == (note,)
    assert f"  {note}" in cli.describe(result)
    page = render_changes_page(result, csv_name="changes.csv")
    assert html.escape(note) in page


def test_derive_aisf_reports_an_error_inside_the_mapping():
    class Broken:
        AISF_DERIVED_MAP = []

        @staticmethod
        def derive_aisf_findings(rows, selected, **_):
            raise KeyError("Check_ID")

    with pytest.raises(derived.DerivationError, match="KeyError"):
        derived.derive_aisf([], ACCOUNT, frozenset(), mappings=Broken)


def test_derive_aisf_passes_the_compared_services_as_the_selection():
    seen = {}

    class Recording:
        AISF_DERIVED_MAP = []

        @staticmethod
        def derive_aisf_findings(rows, selected, **_):
            seen["rows"], seen["selected"] = rows, selected
            return []

    finding = make_finding("SM-01", "Passed", region=REGION)
    assert derived.derive_aisf([finding], ACCOUNT, {"sagemaker"}, Recording) == []
    assert seen["rows"] == [
        {
            "Check_ID": "SM-01",
            "Account_ID": ACCOUNT,
            "Region": REGION,
            "Status": "Passed",
        }
    ]
    assert seen["selected"] == {
        "bedrock": False,
        "sagemaker": True,
        "agentcore": False,
        "agent-registry": False,
    }


def test_load_aisf_mappings_names_a_file_that_cannot_be_loaded(tmp_path):
    with pytest.raises(derived.DerivationError, match="can't load"):
        derived.load_aisf_mappings(tmp_path / "missing.py")
    broken = tmp_path / "broken.py"
    broken.write_text("def (:\n", encoding="utf-8")
    with pytest.raises(derived.DerivationError, match="can't load"):
        derived.load_aisf_mappings(broken)


def test_the_mapping_is_the_main_reports_own_module():
    module = derived.aisf_mappings()
    assert module is derived.aisf_mappings()  # loaded once
    assert module.__name__ == derived.AISF_MODULE_NAME
    assert derived.AISF_MAPPINGS_PATH.is_file()
    assert module.AISF_SERVICE_SLUG == derived.AISF_AREA


def test_omitted_aisf_controls_follow_the_compared_services():
    assert derived.omitted_aisf_control_ids(frozenset({"bedrock"})) == [
        "AISF-07",
        "AISF-08",
    ]
    assert derived.omitted_aisf_control_ids(frozenset({"bedrock", "sagemaker"})) == []


def test_omitted_aisf_controls_preserve_a_derivation_error(monkeypatch):
    def broken():
        raise derived.DerivationError("missing mapping")

    monkeypatch.setattr(derived, "aisf_mappings", broken)
    with pytest.raises(derived.DerivationError, match="missing mapping"):
        derived.omitted_aisf_control_ids(frozenset())


def test_omitted_aisf_controls_wrap_an_unexpected_error(monkeypatch):
    class Broken:
        @staticmethod
        def omitted_aisf_controls(_selected):
            raise KeyError("sources")

    monkeypatch.setattr(derived, "aisf_mappings", lambda: Broken)
    with pytest.raises(derived.DerivationError, match="KeyError: 'sources'"):
        derived.omitted_aisf_control_ids(frozenset())


def test_unreadable_omitted_controls_keep_other_aisf_rows(monkeypatch):
    def broken(_services):
        raise derived.DerivationError("missing sources")

    monkeypatch.setattr(compare_module, "omitted_aisf_control_ids", broken)
    result = _compare(_sources(), _sources(br20="Failed"))
    assert _aisf(result)["AISF-05"].change is Change.REGRESSED
    assert result.notes == (
        "AWS AI Security Framework omitted controls could not be listed: "
        "missing sources",
    )


def test_a_derived_finding_has_its_own_module_and_others_are_still_rejected():
    def finding(module):
        return Finding(
            account_id=ACCOUNT,
            module=module,
            area="aisf",
            region=REGION,
            check_id="AISF-05",
            finding="AISF AIR-BDR-KB-03",
            details="details",
            severity="High",
            status="Passed",
        )

    assert finding(DERIVED_MODULE).module == DERIVED_MODULE
    with pytest.raises(InvalidFindingError, match="Unknown assessment module"):
        finding("aisf")


def test_any_error_loading_the_mapping_is_a_derivation_error(tmp_path):
    # Not only OSError and SyntaxError: whatever the module raises on import.
    for name, source in (
        ("imports.py", "import assessment_history_no_such_module\n"),
        ("names.py", "VALUE = undefined_name\n"),
        ("keys.py", "VALUE = {}['missing']\n"),
    ):
        path = tmp_path / name
        path.write_text(source, encoding="utf-8")
        with pytest.raises(derived.DerivationError, match="can't load"):
            derived.load_aisf_mappings(path)


def test_a_mapping_that_fails_to_import_is_a_note(monkeypatch, tmp_path):
    broken = tmp_path / "aisf_mappings.py"
    broken.write_text("import assessment_history_no_such_module\n", encoding="utf-8")
    monkeypatch.setattr(
        derived, "aisf_mappings", lambda: derived.load_aisf_mappings(broken)
    )
    result = _compare(_sources(), _sources(br20="Failed"))
    assert _aisf(result) == {}
    assert Counter(row.check_id for row in result.rows)["BR-20"] == 1
    (note,) = result.notes
    assert note.startswith("AWS AI Security Framework rows not compared: can't load")
    assert "ModuleNotFoundError" in note


def _aisf_sides(result):
    """(region, Check_ID) -> which runs have the AISF row."""
    return {
        (row.region, row.check_id): (row.previous is not None, row.current is not None)
        for row in result.rows
        if row.area == "aisf"
    }


def test_a_global_only_control_keeps_its_region_when_regional_rows_appear():
    # BR-20 reports under Global in both runs and doesn't change. The current
    # run also has a regional SageMaker row, which in the main report moves
    # the account's Global rows into that Region.
    previous = [make_finding("BR-20", "Passed")]
    current = [
        make_finding("BR-20", "Passed"),
        make_finding("SM-01", "Passed", region=REGION),
    ]
    sides = _aisf_sides(_compare(previous, current))
    assert sides[("Global", "AISF-05")] == (True, True)
    assert (REGION, "AISF-05") not in sides
    # The new regional source gets its own rows, in the current run only.
    assert sides[(REGION, "AISF-08")] == (False, True)
    # The coverage row names the controls with no source in the account: under
    # Global while the account has no regional rows, then under the Region.
    assert sides[("Global", "AISF-00")] == (True, False)
    assert sides[(REGION, "AISF-00")] == (False, True)


def test_no_global_coverage_row_beside_regional_rows():
    # AISF-07 is assessed in the Region, so no Global row may call it
    # unassessed; the main report shows no Global AISF-00 here either.
    findings = [
        make_finding("BR-20", "Failed"),
        make_finding("SM-18", "Passed", region=REGION),
        make_finding("SM-42", "Passed", region=REGION),
    ]
    rows = {
        (row.region, row.check_id): row for row in _compare(findings, findings).rows
    }
    assert rows[("Global", "AISF-05")].current_status == "Failed"
    assert rows[(REGION, "AISF-07")].current_status == "Passed"
    assert ("Global", "AISF-00") not in rows
    assert "AISF-07" not in rows[(REGION, "AISF-00")].current.details
    assert "AISF-08" in rows[(REGION, "AISF-00")].current.details


@pytest.mark.parametrize(
    ("global_check", "regional_checks"),
    [
        ("SM-42", ("SM-18",)),
        ("SM-09", ("SM-01", "SM-03")),
    ],
)
@pytest.mark.parametrize(
    ("before", "after", "change"),
    [
        ("Failed", "Passed", Change.RESOLVED),
        ("Passed", "Failed", Change.REGRESSED),
    ],
)
def test_global_source_change_has_only_regional_aisf_changes(
    global_check, regional_checks, before, after, change
):
    def findings(global_status):
        return [
            make_finding(global_check, global_status, region="Global"),
            *[
                make_finding(check_id, "Passed", region=region)
                for region in (REGION, "eu-west-1")
                for check_id in regional_checks
            ],
        ]

    control = "AISF-07" if global_check == "SM-42" else "AISF-08"
    result = _compare(findings(before), findings(after))
    rows = [
        row for row in result.rows if row.area == "aisf" and row.check_id == control
    ]
    assert {(row.region, row.change) for row in rows} == {
        (REGION, change),
        ("eu-west-1", change),
    }
    assert all(row.previous_status == before for row in rows)
    assert all(row.current_status == after for row in rows)


def test_a_regional_row_still_includes_the_global_verdict():
    # A Global Failed for BR-20 still fails the regional AISF-05, as in the
    # main report. Its Global row is suppressed because BR-20 ran regionally.
    findings = [
        make_finding("BR-20", "Failed"),
        make_finding("BR-20", "Passed", region=REGION),
    ]
    rows = {
        (row.region, row.check_id): row for row in _compare(findings, findings).rows
    }
    assert rows[(REGION, "AISF-05")].current_status == "Failed"
    assert ("Global", "AISF-05") not in rows
    assert rows[(REGION, "AISF-05")].change is Change.STILL_OPEN


def test_derive_aisf_keeps_the_global_key_separate():
    seen = {}

    class Recording:
        AISF_DERIVED_MAP = []

        @staticmethod
        def derive_aisf_findings(rows, selected, **options):
            seen.update(options)
            return []

    finding = make_finding("BR-20", "Passed", region=REGION)
    derived.derive_aisf([finding], ACCOUNT, frozenset(), Recording)
    assert seen == {"separate_global": True, "diagnostics": []}


def test_every_aisf_control_draws_on_one_service():
    # The comparison derives both runs from the services selected in both, so
    # a control whose sources span two services, one selected in only one
    # run, would change from Failed to N/A with no finding changing. Today no
    # control spans two services; a mapping that adds one must handle that
    # case in compare.py first.
    module = derived.aisf_mappings()
    for mapping in module.AISF_DERIVED_MAP:
        services = {module.source_service(c) for c in mapping["sources"]}
        assert len(services) == 1, (mapping["check_id"], services)


def _row(check_id, **overrides):
    row = {
        "Check_ID": check_id,
        "Finding": f"{check_id} finding",
        "Finding_Details": "details",
        "Resolution": "Fix it.",
        "Reference": "",
        "Severity": "High",
        "Status": "Passed",
        "Account_ID": ACCOUNT,
        "Region": REGION,
    }
    row.update(overrides)
    return row


class _Rows:
    """A mapping module whose derivation returns fixed rows."""

    AISF_DERIVED_MAP = []
    rows = []

    @classmethod
    def derive_aisf_findings(cls, rows, selected, **_):
        return cls.rows


def test_one_unreadable_derived_row_skips_only_itself(monkeypatch):
    missing_title = _row("AISF-07")
    del missing_title["Finding"]
    monkeypatch.setattr(
        _Rows,
        "rows",
        [_row("AISF-05"), missing_title, _row("AISF-08", Status="Unknown"), None],
    )
    notes = []
    findings = derived.derive_aisf([], ACCOUNT, frozenset(), _Rows, notes=notes)
    assert [finding.check_id for finding in findings] == ["AISF-05"]
    assert notes == [
        "AWS AI Security Framework rows not compared for 3 derived row(s) "
        "(AISF-07, AISF-08, None): KeyError: 'Finding'"
    ]
    # Without a notes list the readable rows are still returned.
    assert [
        finding.check_id
        for finding in derived.derive_aisf([], ACCOUNT, frozenset(), _Rows)
    ] == ["AISF-05"]


def test_no_note_when_every_derived_row_is_readable(monkeypatch):
    monkeypatch.setattr(_Rows, "rows", [_row("AISF-05")])
    notes = []
    findings = derived.derive_aisf([], ACCOUNT, frozenset(), _Rows, notes=notes)
    assert [finding.check_id for finding in findings] == ["AISF-05"]
    assert notes == []


def test_a_skipped_mapping_is_reported_without_losing_other_controls(monkeypatch):
    module = derived.load_aisf_mappings()
    valid = module.AISF_DERIVED_MAP[0]
    missing_title = {**valid, "check_id": "AISF-90"}
    del missing_title["finding"]
    module.AISF_DERIVED_MAP = [valid, missing_title]
    monkeypatch.setattr(derived, "aisf_mappings", lambda: module)

    source = make_finding("BR-20", "Failed", region=REGION)
    result = _compare([source], [source])

    assert _aisf(result)["AISF-05"].change is Change.STILL_OPEN
    assert "AISF-90" not in _aisf(result)
    note = (
        "AWS AI Security Framework rows not compared for 1 mapping error(s) "
        "(AISF-90): KeyError: 'finding'"
    )
    assert result.notes == (note,)
    assert f"  {note}" in cli.describe(result)
    assert note in html.unescape(render_changes_page(result, csv_name="changes.csv"))
    assert [
        finding.check_id
        for finding in derived.derive_aisf(
            [source], ACCOUNT, frozenset({"bedrock"}), mappings=module
        )
    ] == ["AISF-05"]
