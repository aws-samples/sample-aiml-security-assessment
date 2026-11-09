"""Behavioral acceptance for native AI findings exposed by the AISF preset."""

import copy
import json
import re

import pytest

from tests.test_aisf_catalog_alignment import (
    ACCOUNT,
    EXECUTION,
    REGIONS,
    SERVICES,
    aisf_results,
    assert_check_inventory,
    embedded_register,
    observation,
    register,
)
from tests.test_aisf_comprehensive_mapping import (
    NATIVE_IDS,
    assert_downloaded_check,
    downloaded_exports,
    report_pair,
)

MANUAL_SOURCE_IDS = {
    "BR-09",
    "FS-24",
    "FS-29",
    "FS-30",
    "FS-32",
    "FS-35",
    "FS-37",
    "FS-40",
    "FS-49",
    "FS-54",
    "FS-57",
    "FS-58",
    "FS-60",
    "FS-62",
}
ACTIVE_NATIVE_IDS = set.union(*NATIVE_IDS.values()) - {"BR-14"}


def full_inventory_rows():
    return [
        observation(
            check,
            "N/A"
            if check in MANUAL_SOURCE_IDS
            else ("Passed" if index % 2 else "Failed"),
            region="Global" if check.startswith("AR-") else REGIONS[0],
            Severity="Informational" if check in MANUAL_SOURCE_IDS else "High",
            Finding=f"Synthetic source result {check}",
            Finding_Details=(
                f"Synthetic source advisory for native check {check}."
                if check in MANUAL_SOURCE_IDS
                else f"Synthetic evidence for native check {check}."
            ),
            Resource_ID=f"synthetic-resource-{check}",
            Resolution="Review the existing source advisory."
            if check in MANUAL_SOURCE_IDS
            else f"Use the source remediation for {check}.",
        )
        for index, check in enumerate(sorted(ACTIVE_NATIVE_IDS))
    ]


def test_every_active_native_source_check_survives_the_customer_projection_and_exports(
    tmp_path,
):
    rows = full_inventory_rows()
    assert len(rows) == 232
    expected = {row["Check_ID"]: row for row in rows}
    for html in report_pair(tmp_path, rows, aisf=True):
        exported = downloaded_exports(html)
        result = exported["json"]
        assert_check_inventory(result)
        assert result["scope"]["enable_aisf"] is True
        assert all(result["scope"]["source_selection"].values())
        actual = {check["source_check_id"] for check in result["checks"]}
        assert actual == ACTIVE_NATIVE_IDS
        assert "controls" not in result
        assert not re.search(r"218\s+(?:canonical\s+)?controls", html, re.I)
        assert "Manual assessment required" not in html
        assert not any(
            check["source_check_id"].startswith("AIR-") for check in result["checks"]
        )
        for check in result["checks"]:
            original = expected[check["source_check_id"]]
            for field, source in (
                ("status", "Status"),
                ("severity", "Severity"),
                ("finding", "Finding"),
                ("finding_details", "Finding_Details"),
                ("resource", "Resource_ID"),
                ("action_required", "Resolution"),
            ):
                assert check[field] == original[source]
            assert check["account"] in {ACCOUNT, "444455556666"}
            if check["source_check_id"] in MANUAL_SOURCE_IDS:
                assert check["status"] == "N/A"
                assert check["result_kind"] == "source-advisory"
                assert check["evidence_kind"] == "manual evidence required"
            assert_downloaded_check(exported, check)
        assert {
            check["source_check_id"]
            for check in result["checks"]
            if not check["aisf_control_ids"]
        } >= {"AG-26", "BR-31"}
        for check in result["checks"]:
            if not check["aisf_control_ids"]:
                assert check["unmapped_reason"]


def test_projection_keeps_failed_unmapped_ai_checks_and_native_network_traceability():
    rows = [
        observation(
            "AC-01",
            "Failed",
            Finding="AgentCore Runtime Network Isolation Missing",
            Finding_Details="Runtime has no VPC network configuration.",
        ),
        observation(
            "AG-26",
            "Failed",
            Finding="Agentic AI Long-Term Memory Consolidation",
            Resolution="Review the native memory finding.",
        ),
    ]
    result = aisf_results.build_aisf_check_results(register(rows))
    by_id = {check["source_check_id"]: check for check in result["checks"]}
    assert set(by_id) == {"AC-01", "AG-26"}
    assert {
        "AIR-FND-NET-01",
        "AIR-FND-NET-03",
        "AIR-FND-NET-06",
        "AIR-ACR-RT-08",
        "AIR-ACR-RT-13",
        "AIR-SLF-RT-02",
    } <= set(by_id["AC-01"]["aisf_control_ids"])
    assert by_id["AG-26"]["status"] == "Failed"
    assert by_id["AG-26"]["action_required"] == rows[1]["Resolution"]
    assert by_id["AG-26"]["aisf_control_ids"] == []
    assert by_id["AG-26"]["unmapped_reason"]


def test_projection_does_not_mutate_internal_catalog_or_observations():
    internal = register([observation("BR-20", "Passed")])
    before = copy.deepcopy(internal)
    result = aisf_results.build_aisf_check_results(internal)
    assert internal == before
    assert len(internal["controls"]) == 218
    assert "controls" not in result
    assert result["checks"][0]["status"] == "Passed"
    assert result["checks"][0]["source_check_id"] == "BR-20"


@pytest.mark.parametrize("owner", (*SERVICES, "responsible-ai-grc", "owasp"))
def test_missing_selected_collector_is_a_gap_without_fabricated_check_status(owner):
    selection = dict.fromkeys(SERVICES, True)
    internal = register(
        [],
        service_selection=selection,
        enable_grc=True,
        enable_owasp=True,
        enable_aisf=True,
    )
    result = aisf_results.build_aisf_check_results(internal)
    assert result["checks"] == []
    assert any(
        gap["kind"] == "source-absent" and gap["owner"] == owner
        for gap in result["gaps"]
    )
    assert "whole_control_passes" not in result["summary"]


@pytest.mark.parametrize(
    "formula",
    [
        '=HYPERLINK("https://invalid.example")',
        "+SUM(1,2)",
        "-1+2",
        "@SUM(1,2)",
        "\t=1+1",
        "\r=1+1",
    ],
)
def test_actual_exports_neutralize_formula_cells_but_preserve_raw_evidence(
    tmp_path, formula
):
    attack = '</script><img src=x onerror="alert(1)">'
    row = observation(
        "BR-20",
        "Failed",
        Finding=formula,
        Finding_Details=attack,
        Resolution=formula,
        Resource_ID=formula,
        Reference="javascript:alert(1)",
    )
    for html in report_pair(tmp_path, [row]):
        assert attack not in html
        assert 'href="javascript:' not in html
        exported = downloaded_exports(html)
        checks = exported["json"]["checks"]
        assert checks
        for check in checks:
            assert check["finding"] == formula
            assert check["finding_details"] == attack
            assert check["reference"] == "javascript:alert(1)"
        for csv_row in exported["csv"]:
            if csv_row["Record_Type"] != "check":
                assert csv_row["Status"] == ""
                continue
            assert csv_row["Finding"] == "'" + formula
            assert csv_row["Resource_ID"] == "'" + formula
            assert csv_row["Resolution"] == "'" + formula
            raw = json.loads(csv_row["Observation"])
            assert raw["Finding"] == formula
            assert raw["Finding_Details"] == attack
        assert embedded_register(html) == exported["json"]


@pytest.mark.parametrize(
    "check", ["BR-00", "SM-00", "AC-00", "AR-00", "FS-00", "OW-00"]
)
def test_discovery_signals_remain_collection_gaps_without_invented_native_checks(check):
    original = observation(
        check,
        "N/A",
        Finding="Assessment complete",
        Finding_Details="No resources discovered.",
    )
    result = aisf_results.build_aisf_check_results(
        register([original], enable_grc=True, enable_owasp=True)
    )
    assert result["checks"] == []
    gap = next(item for item in result["gaps"] if item["kind"] == "collection-advisory")
    assert gap["observation"]["Check_ID"] == check
    assert gap["observation"]["Status"] == "N/A"
    assert gap["observation"]["Finding_Details"] == original["Finding_Details"]
    assert gap["account"] == ACCOUNT
    assert gap["region"] == REGIONS[0]
    assert "aisf_control_ids" not in gap


def test_grc_delivery_is_account_scoped_while_direct_and_owasp_remain_regional():
    selection = dict.fromkeys(SERVICES, True)
    rows = [
        observation("FS-01", "Failed"),
        observation("BR-20", "Passed"),
        observation("OW-11", "Failed"),
    ]
    projected = aisf_results.build_aisf_check_results(
        register(rows, service_selection=selection, enable_grc=True, enable_owasp=True)
    )
    absent = [gap for gap in projected["gaps"] if gap["kind"] == "source-absent"]
    assert not any(gap["owner"] == "responsible-ai-grc" for gap in absent)
    for owner in ("bedrock", "owasp"):
        assert any(
            gap["owner"] == owner and gap["region"] == REGIONS[1] for gap in absent
        )
    grc = next(
        check for check in projected["checks"] if check["source_check_id"] == "FS-01"
    )
    assert grc["region"] == REGIONS[0]
    assert grc["status"] == "Failed"


def test_grc_delivery_cannot_fill_another_account_or_execution():
    other_account = "444455556666"
    other_execution = "different-execution"
    scopes = [
        {"account": account, "region": region, "execution_id": execution}
        for account, execution in (
            (ACCOUNT, EXECUTION),
            (ACCOUNT, other_execution),
            (other_account, EXECUTION),
        )
        for region in REGIONS
    ]
    projected = aisf_results.build_aisf_check_results(
        register(
            [observation("FS-01", "Failed")],
            accounts=[ACCOUNT, other_account],
            scopes=scopes,
            service_selection=dict.fromkeys(SERVICES, True),
            enable_grc=True,
            enable_owasp=True,
        )
    )
    gaps = [
        gap
        for gap in projected["gaps"]
        if gap["kind"] == "source-absent" and gap["owner"] == "responsible-ai-grc"
    ]
    assert not any(
        gap["account"] == ACCOUNT and gap["execution_id"] == EXECUTION for gap in gaps
    )
    assert {(gap["account"], gap["execution_id"]) for gap in gaps} == {
        (ACCOUNT, other_execution),
        (other_account, EXECUTION),
    }
    assert len(gaps) == 2
    assert all(gap["region"] == "" for gap in gaps)
    assert all("first selected region" in gap["message"] for gap in gaps)
    assert len(projected["checks"]) == 1
    assert projected["checks"][0]["status"] == "Failed"


@pytest.mark.parametrize(
    "check_id,finding,details",
    [
        (
            "AC-45",
            "AgentCore Runtime Execution Role Scope",
            "Runtime rt-1 runs as MissingRole, which is not in the IAM permissions cache; its sandbox access could not be judged.",
        ),
        (
            "AC-48",
            "AgentCore Execution Role Trust",
            "Runtime rt-1 runs as MissingRole, whose trust policy could not be read: NoSuchEntity.",
        ),
    ],
)
def test_live_inspection_gaps_keep_native_na_and_action(check_id, finding, details):
    row = observation(
        check_id,
        "N/A",
        Finding=finding,
        Finding_Details=details,
        Severity="Informational",
        Resolution="Verify the referenced role and refresh the assessment inventory.",
    )
    result = aisf_results.build_aisf_check_results(register([row]))
    [check] = result["checks"]
    assert check["source_check_id"] == check_id
    assert check["status"] == row["Status"]
    assert check["severity"] == row["Severity"]
    assert check["finding_details"] == details
    assert check["action_required"] == row["Resolution"]
    assert check["evidence_kind"] == "unavailable"
    assert check["result_kind"] == "unavailable"
    assert any(
        gap["kind"] == "unavailable-observation" and gap["source_check_id"] == check_id
        for gap in result["gaps"]
    )


@pytest.mark.parametrize(
    "check_id,details,evidence_kind,result_kind",
    [
        (
            "AC-45",
            "No applicable resources found in this Region.",
            "no resource observation",
            "source-result",
        ),
        (
            "AC-48",
            "No resources found in this Region.",
            "no resource observation",
            "source-result",
        ),
        (
            "FS-66",
            "Manual review required: verify identity binding and downstream tool authorization.",
            "manual evidence required",
            "source-advisory",
        ),
    ],
)
def test_live_gap_classification_preserves_no_resource_and_manual_advisories(
    check_id, details, evidence_kind, result_kind
):
    row = observation(
        check_id,
        "N/A",
        Finding="Synthetic native observation",
        Finding_Details=details,
        Severity="Informational",
    )
    result = aisf_results.build_aisf_check_results(register([row], enable_grc=True))
    [check] = result["checks"]
    assert check["status"] == "N/A"
    assert check["action_required"] == row["Resolution"]
    assert check["evidence_kind"] == evidence_kind
    assert check["result_kind"] == result_kind
    assert not any(gap["kind"] == "unavailable-observation" for gap in result["gaps"])
