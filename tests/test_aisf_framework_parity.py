"""AISF uses the same report experience as the other assessment areas."""

from collections import Counter

import pytest
from bs4 import BeautifulSoup

from tests.report_browser import exercise_report
from tests.test_aisf_automated_report import ACTIVE_NATIVE_IDS, full_inventory_rows
from tests.test_aisf_catalog_alignment import (
    ACCOUNT,
    OTHER_ACCOUNT as OTHER,
    REGIONS,
    embedded_register,
    observation,
)
from tests.test_aisf_comprehensive_mapping import report_pair
from tests.test_report_template_owasp import _base_kwargs, report_template


def parity_rows():
    rows = [
        observation(
            "BR-20",
            "Failed",
            Finding="Guardrail resource alpha",
            Resource_ID="synthetic-guardrail-alpha",
            Resolution="Repair alpha guardrail configuration.",
        ),
        observation(
            "BR-20",
            "Passed",
            Finding="Guardrail resource beta",
            Resource_ID="synthetic-guardrail-beta",
            Severity="Medium",
        ),
        observation(
            "BR-20",
            "Failed",
            region=REGIONS[1],
            Finding="Guardrail resource west",
            Resource_ID="synthetic-guardrail-west",
        ),
        observation(
            "AC-45",
            "N/A",
            Finding="AgentCore Runtime Execution Role Permissions",
            Finding_Details="Role synthetic-missing-role not in the IAM permissions cache.",
            Resource_ID="synthetic-runtime-unreadable",
            Severity="Low",
            Resolution="Verify the role reference and retry the assessment.",
        ),
        observation(
            "AR-01",
            "Failed",
            region="Global",
            Finding="Registry IAM observation",
            Resource_ID="synthetic-registry-record",
        ),
        observation(
            "FS-66",
            "N/A",
            Finding="Runtime identity propagation requires manual review",
            Resource_ID="synthetic-runtime-identity",
            Severity="Informational",
            Resolution="Review end-user identity propagation.",
        ),
        observation(
            "AG-26",
            "Failed",
            Finding="Native agent memory finding",
            Resource_ID="synthetic-memory",
            Resolution="Inspect memory consolidation configuration.",
        ),
        observation("OW-11", "Passed", Resource_ID="synthetic-owasp-lambda"),
        observation(
            "SM-29",
            "Failed",
            Finding="Inactive source should never become an AISF result",
        ),
    ]
    return rows


def summary_metrics(section):
    grid = section.select_one(".assessment-summary-grid")
    assert grid is not None, "Each assessment must use the shared summary."
    return {
        metric.select_one(".metric-label").get_text(strip=True): int(
            metric.select_one(".metric-value").get_text(strip=True)
        )
        for metric in grid.select(".metric")
    }


def projected_rows(soup):
    return soup.select('#findingsTable tbody tr[data-aisf-result="true"]')


def test_frameworks_share_summary_actions_table_and_remediation(monkeypatch):
    monkeypatch.setattr(
        report_template,
        "COMPLIANCE_STANDARDS",
        report_template.COMPLIANCE_STANDARDS
        + [
            {
                "slug": "nist",
                "name": "Synthetic future compliance standard",
                "prefix": "NR-",
                "icon": "<span>N</span>",
                "icon_small": "<span>N</span>",
                "reference_url": "https://example.com/nist",
                "section_title": "Synthetic NIST Findings",
                "scope_text": "Synthetic standard scope.",
            }
        ],
    )
    kwargs = _base_kwargs()
    for service, check_id, status in (
        ("bedrock", "BR-20", "Failed"),
        ("agentic", "AG-25", "Failed"),
        ("responsible-ai-grc", "FS-08", "Passed"),
        ("owasp", "OW-11", "N/A"),
        ("nist", "NR-01", "Passed"),
    ):
        row = observation(check_id, status, _service=service)
        kwargs["all_findings"].append(row)
        kwargs["service_findings"][service] = [row]
        kwargs["service_stats"][service] = {
            "passed": int(status == "Passed"),
            "failed": int(status == "Failed"),
            "na": int(status == "N/A"),
        }
    kwargs.update(enable_aisf=True, enable_grc=True, enable_owasp=True)
    html = report_template.generate_html_report(**kwargs)
    soup = BeautifulSoup(html, "html.parser")
    for service in ("aisf", "owasp", "agentic", "responsible-ai-grc", "nist"):
        section = soup.select_one(f"section#{service}")
        assert section is not None
        metrics = summary_metrics(section)
        assert set(metrics) == {"Failed", "Passed", "N/A", "Total"}
        buttons = section.select(".assessment-actions button[data-filter-service]")
        assert [
            (button.get_text(strip=True), button["data-filter-status"])
            for button in buttons
        ] == [("View failed findings", "failed"), ("View all rows", "")]
        assert all(button["data-filter-service"] == service for button in buttons)
        assert soup.select_one(f'#serviceFilter option[value="{service}"]')
    assert len(soup.select("#findingsTable")) == 1
    assert not soup.select(".aisf-check, #aisf-search, #aisf-status, #aisf-owner")
    for row in soup.select("#findingsTable tbody tr[data-service]"):
        assert row.select_one(".finding-more summary").get_text(strip=True) == (
            "Details and remediation"
        )
        labels = {
            strong.get_text(strip=True)
            for strong in row.select(".finding-more-body > div > strong")
        }
        assert {"Details", "Resolution", "Reference"} <= labels
    # The existing OWASP/lens/other-standard summary contracts remain unchanged.
    for service in ("owasp", "agentic", "responsible-ai-grc", "nist"):
        section = soup.select_one(f"section#{service}")
        assert (
            section.select_one(".metric.highlight .metric-sub").get_text(strip=True)
            == "Controls met"
        )
        expected = kwargs["service_stats"][service]
        assert summary_metrics(section) == {
            "Failed": expected["failed"],
            "Passed": expected["passed"],
            "N/A": expected["na"],
            "Total": 1,
        }


@pytest.mark.parametrize("mode_index", [0, 1], ids=["single", "multi"])
def test_observation_counts_membership_and_details_remain_complete(
    tmp_path, mode_index
):
    html = report_pair(tmp_path, parity_rows(), aisf=True)[mode_index]
    soup = BeautifulSoup(html, "html.parser")
    result = embedded_register(html)
    table_rows = projected_rows(soup)
    assert len(table_rows) == len(result["checks"])
    expected_accounts = {ACCOUNT} if mode_index == 0 else {ACCOUNT, OTHER}
    assert {item["account"] for item in result["checks"]} == expected_accounts
    assert len(result["checks"]) == 8 * len(expected_accounts)
    assert len({item["result_id"] for item in result["checks"]}) == len(table_rows)
    statuses = Counter(item["status"] for item in result["checks"])
    assert summary_metrics(soup.select_one("section#aisf")) == {
        "Failed": statuses["Failed"],
        "Passed": statuses["Passed"],
        "N/A": statuses["N/A"],
        "Total": len(table_rows),
    }
    assert int(
        soup.select_one('nav a[href="#aisf"] .count').get_text(strip=True)
    ) == len(table_rows)
    for row, check in zip(table_rows, result["checks"], strict=True):
        assert row["data-service"] == "aisf"
        assert row["data-account"] == check["account"]
        assert row["data-region"] == check["region"]
        assert row["data-status"] == check["status"].lower()
        assert (
            row.select_one("td:nth-child(3) code").get_text()
            == check["source_check_id"]
        )
        assert row.select_one(".status").get_text() == check["status"]
        assert row.select_one(".severity").get_text() == check["severity"]
        detail = row.select_one(".finding-more-body").get_text(" ", strip=True)
        for field in ("finding_details", "resource", "action_required"):
            assert check[field] in detail
        assert check["result_kind"] in detail
        for mapping in check["aisf_links"]:
            assert mapping["control_id"] in detail
            if mapping["coverage"] == "partial":
                assert mapping["limitations"] in detail
        if not check["aisf_links"]:
            assert check["unmapped_reason"] in detail
    unavailable = next(
        item for item in result["checks"] if item["source_check_id"] == "AC-45"
    )
    assert unavailable["status"] == "N/A"
    assert unavailable["result_kind"] == "unavailable"
    assert any(gap["kind"] == "unavailable-observation" for gap in result["gaps"])
    assert not soup.select(".aisf-check, .aisf-control")
    assert all(item["source_check_id"] != "SM-29" for item in result["checks"])
    assert "controls" not in result


def test_shared_buttons_filters_search_reset_and_sort_drive_aisf_rows(tmp_path):
    html = report_pair(tmp_path, parity_rows(), aisf=True)[1]
    actions = [
        {"type": "filter-button", "service": "aisf", "status": "failed"},
        {"type": "filter-button", "service": "aisf", "status": ""},
        {"type": "change", "id": "accountFilter", "value": OTHER},
        {"type": "change", "id": "regionFilter", "value": "us-east-1"},
        {"type": "change", "id": "statusFilter", "value": "n/a"},
        {"type": "change", "id": "severityFilter", "value": "low"},
        {"type": "input", "id": "searchInput", "value": "synthetic-runtime-unreadable"},
        {"type": "input", "id": "searchInput", "value": "synthetic-not-present"},
        {"type": "click", "id": "resetFilters"},
        {"type": "filter-button", "service": "aisf", "status": ""},
        {"type": "change", "id": "regionFilter", "value": "Global"},
        {"type": "click", "id": "resetFilters"},
        {"type": "filter-button", "service": "owasp", "status": ""},
        {"type": "filter-button", "service": "agentic", "status": ""},
        {"type": "filter-button", "service": "aisf", "status": ""},
        {"type": "sort", "column": "checkId"},
        {"type": "sort", "column": "checkId"},
        {"type": "click", "id": "aisf-json"},
        {"type": "click", "id": "aisf-csv"},
    ]
    browser = exercise_report(html, actions)
    rows = browser["rows"]
    states = browser["snapshots"]

    def visible(index):
        return [rows[i] for i in states[index]["visible"]]

    source_failed = [
        row["index"]
        for row in rows
        if row["dataset"].get("aisfResult") != "true"
        and row["dataset"]["status"] == "failed"
    ]
    assert states[0]["visible"] == source_failed
    assert all(row["dataset"]["aisfResult"] == "true" for row in visible(1))
    assert all(row["dataset"]["status"] == "failed" for row in visible(1))
    all_aisf = [row for row in rows if row["dataset"].get("aisfResult") == "true"]
    assert states[2]["visible"] == [row["index"] for row in all_aisf]
    assert states[2]["scrolls"][-1] == "findings"
    assert len(visible(3)) == 8
    assert all(row["dataset"]["account"] == OTHER for row in visible(3))
    assert len(visible(4)) == 6
    assert {row["checkId"] for row in visible(5)} == {"AC-45", "FS-66"}
    assert [row["checkId"] for row in visible(6)] == ["AC-45"]
    assert states[7]["visible"] == states[6]["visible"]
    assert states[8]["visible"] == []
    assert states[9]["visible"] == source_failed
    assert all(
        states[9]["values"][name] == ""
        for name in (
            "searchInput",
            "serviceFilter",
            "severityFilter",
            "accountFilter",
            "regionFilter",
        )
    )
    assert states[9]["values"]["statusFilter"] == "failed"
    assert {row["checkId"] for row in visible(11)} == {"AR-01"}
    assert len(visible(11)) == 2
    assert visible(13) and all(
        row["dataset"]["service"] == "owasp" for row in visible(13)
    )
    assert visible(14) and all(
        row["dataset"]["service"] == "agentic" for row in visible(14)
    )
    ids = [row["checkId"] for row in visible(16)]
    assert ids == sorted(ids)
    assert [row["checkId"] for row in visible(17)] == sorted(ids, reverse=True)
    assert set(states[16]["visible"]) == set(states[15]["visible"])
    assert set(browser["downloads"]) == {"aisf-checks.json", "aisf-checks.csv"}


def test_all_active_native_checks_are_accessible_once_per_scope_in_shared_table(
    tmp_path,
):
    for html in report_pair(tmp_path, full_inventory_rows(), aisf=True):
        soup = BeautifulSoup(html, "html.parser")
        result = embedded_register(html)
        rows = projected_rows(soup)
        assert len(rows) == len(result["checks"])
        assert {row["data-check-id"] for row in rows} == ACTIVE_NATIVE_IDS
        identities = [
            (item["source_check_id"], item["account"], item["region"], item["resource"])
            for item in result["checks"]
        ]
        assert len(set(identities)) == len(rows)
        assert summary_metrics(soup.select_one("section#aisf"))["Total"] == len(rows)
        assert "controls" not in result
        assert not any(row["data-check-id"].startswith("AIR-") for row in rows)
        assert not soup.select(".aisf-check, .aisf-control")


def test_untrusted_mapping_evidence_and_resource_are_text_inside_shared_details(
    tmp_path,
):
    attack = '</script><img src=x onerror="alert(1)">'
    row = observation(
        "AG-26",
        "Failed",
        Finding="Native unmapped finding",
        Finding_Details=attack,
        Resource_ID=f"synthetic-resource-{attack}",
        Resolution=f"Review {attack} as evidence.",
        Reference="javascript:alert(1)",
    )
    for html in report_pair(tmp_path, [row], aisf=True):
        soup = BeautifulSoup(html, "html.parser")
        checks = embedded_register(html)["checks"]
        for table_row, check in zip(projected_rows(soup), checks, strict=True):
            detail = table_row.select_one(".finding-more-body")
            assert not detail.select("script, img, iframe")
            assert attack in detail.get_text()
            assert check["resource"] in detail.get_text()
            assert check["unmapped_reason"] in detail.get_text()
            assert not detail.select('a[href^="javascript:"]')
        assert attack not in html
