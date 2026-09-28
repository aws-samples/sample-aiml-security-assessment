"""The changes page (render_changes.py) and the parts it borrows (render_common.py).

The page is checked with BeautifulSoup. Its script can't run under pytest,
so a test checks that every element the script looks up exists; open a page
made by sample-reports/scripts/build_changes_sample.py in a browser to try it.
"""

import re
from datetime import UTC, datetime

import pytest
from bs4 import BeautifulSoup

from assessment_history.compare import compare_runs
from assessment_history.models import AREAS
from assessment_history.render_changes import (
    ROW_ORDER,
    SCRIPT,
    change_slug,
    days_apart_text,
    format_time,
    render_changes_page,
)
from assessment_history.render_common import (
    EXTRA_CSS,
    TEMPLATE_PATH,
    RenderError,
    load_parts,
    page_parts,
)
from tests.assessment_history_helpers import ACCOUNT, make_finding, make_run, utc

CSV_NAME = "security_assessment_changes_20260927_061500.csv"
MAIN_REPORT = "security_assessment_single_account_20260927_061433.html"
GENERATED = datetime(2026, 9, 27, 6, 20, tzinfo=UTC)
TEMPLATE_TEXT = TEMPLATE_PATH.read_text(encoding="utf-8")


def _comparison(previous_rows, current_rows, *, previous=None, current=None):
    return compare_runs(
        make_run(
            previous_rows,
            execution_id="run-p",
            saved_at=utc(3, 23, 37),
            **(previous or {}),
        ),
        make_run(
            current_rows,
            execution_id="run-c",
            saved_at=utc(27, 6, 15),
            **(current or {}),
        ),
    )


def _page(comparison, **options):
    options.setdefault("csv_name", CSV_NAME)
    options.setdefault("generated_at", GENERATED)
    return BeautifulSoup(render_changes_page(comparison, **options), "html.parser")


def _every_state():
    previous = [
        make_finding("BR-01", "Passed", details="No roles found"),
        make_finding("BR-02", "Failed", severity="Medium"),
        make_finding("SM-26", "Failed", region="us-east-1"),
        make_finding("SM-02", "Failed", region="us-east-1", severity="Low"),
        make_finding("AC-09", "Failed", severity="Medium"),
        make_finding("AR-02", "N/A", severity="Informational"),
        make_finding("AC-17", "Passed"),
        make_finding("AG-01", "Passed", details="Source check BR-01"),
    ]
    current = [
        make_finding("BR-01", "Failed", details="Role 'admin' has the policy"),
        make_finding("BR-02", "Failed", severity="Medium"),
        make_finding("SM-26", "Passed", region="us-east-1"),
        make_finding("AC-09", "N/A", severity="Informational"),
        make_finding("AR-02", "Failed", severity="Medium"),
        make_finding("AC-17", "Passed"),
        make_finding("AG-01", "Failed", details="Source check BR-01"),
    ]
    return _comparison(previous, current)


# --- borrowed parts ----------------------------------------------------------------


def test_parts_are_borrowed_from_the_main_report():
    parts = page_parts()
    for css_class in (
        ".layout",
        ".sidebar",
        ".nav-item",
        ".metric",
        ".card",
        ".filter-bar",
        "#findingsTable.single-account-report",
        ".finding-more",
        ".severity.high",
        ".status.error",
        ".status.warning",
        ".status.success",
        '[data-theme="dark"]',
    ):
        assert css_class in parts.css, css_class
    assert "{{" not in parts.css and "}}" not in parts.css
    assert parts.css.endswith(EXTRA_CSS)
    assert parts.fonts_link.startswith('<link href="https://fonts.googleapis.com')
    assert 'id="themeToggle"' in parts.theme_button
    assert 'class="theme-label"' in parts.theme_button
    assert parts.page_footer.startswith('<footer class="page-footer">')
    assert set(parts.area_labels) == set(AREAS) == set(parts.area_icons)
    assert [group[0] for group in parts.nav_groups] == [
        "By Service",
        "By Lens",
        "By Governance Framework",
        "By Compliance Standard",
    ]
    assert page_parts() is parts  # read once


def test_copied_icons_and_names_still_match_the_main_report():
    parts = page_parts()
    for area in ("bedrock", "sagemaker", "agentcore"):
        icon = parts.area_icons[area]
        assert icon.startswith('<span class="service-icon"><svg')
        assert icon in TEMPLATE_TEXT
    # The main report's Assessment Area filter uses the same names.
    for area in ("bedrock", "sagemaker", "agentcore", "agent-registry", "agentic"):
        option = f'<option value="{area}">{parts.area_labels[area]}</option>'
        assert option in TEMPLATE_TEXT, option


def test_the_main_reports_theme_setting_is_shared():
    # Both pages keep the reader's light/dark choice under the same key.
    assert "localStorage.getItem('theme')" in TEMPLATE_TEXT
    assert "localStorage.getItem('theme')" in SCRIPT
    assert "localStorage.setItem('theme', 'dark')" in SCRIPT


def test_a_missing_template_is_a_render_error(tmp_path):
    with pytest.raises(RenderError, match="can't load"):
        load_parts(tmp_path / "missing.py")


FAKE_TEMPLATE = """
COMPLIANCE_STANDARDS = [{"slug": "owasp", "name": "OWASP", "icon": "<i></i>"}]
RESPONSIBLE_AI_GRC_LABEL = "GRC"
RESPONSIBLE_AI_GRC_NAV_HEADING = "By Governance Framework"
AGENT_REGISTRY_ICON = AGENTIC_ICON = RESPONSIBLE_AI_GRC_ICON = ""
_escape_text = _escape_attr = _safe_https_url = str


def get_html_template():
    return "<html><body>no styles</body></html>"
"""


@pytest.mark.parametrize(
    "source, message",
    [
        ("def get_html_template():\n    return ''\n", "no longer provides"),
        (FAKE_TEMPLATE.replace('"owasp"', '"nist"'), "no longer provides"),
        (FAKE_TEMPLATE, "no longer has the report styles"),
    ],
)
def test_a_changed_template_is_a_render_error(tmp_path, source, message):
    path = tmp_path / "report_template.py"
    path.write_text(source, encoding="utf-8")
    with pytest.raises(RenderError, match=message):
        load_parts(path)


# --- small helpers -------------------------------------------------------------------


@pytest.mark.parametrize(
    "days, text", [(0, "same day"), (1, "1 day apart"), (24, "24 days apart")]
)
def test_days_apart_text(days, text):
    assert days_apart_text(days) == text


def test_format_time_uses_utc():
    assert format_time(utc(3, 23, 37)) == "Sep 3, 2026 23:37 UTC"


def test_change_slugs():
    assert [change_slug(change) for change in ROW_ORDER] == [
        "regressed",
        "new",
        "still-open",
        "resolved",
        "no-longer-reported",
        "no-longer-assessed",
        "not-failing",
    ]


# --- the page ---------------------------------------------------------------------------


def test_header_shows_both_runs_and_the_account():
    page = _page(_every_state())
    assert page.title.string == f"Changes Since Last Assessment - {ACCOUNT}"
    meta = page.select_one(".page-header-meta").get_text(" ", strip=True)
    assert "Previous run saved Sep 3, 2026 23:37 UTC" in meta
    assert "Current run saved Sep 27, 2026 06:15 UTC" in meta
    assert "24 days apart" in meta
    assert f"Account {ACCOUNT}" in meta
    assert "open main report" not in meta


def test_main_report_is_linked_in_the_header_and_sidebar_when_known():
    page = _page(_every_state(), main_report_name=MAIN_REPORT)
    links = [a["href"] for a in page.find_all("a")]
    assert links.count(MAIN_REPORT) == 2
    assert page.select_one(".page-header-meta a").string == "open main report"
    footer = page.select_one(".sidebar-footer")
    assert [a["href"] for a in footer.find_all("a")][:2] == [MAIN_REPORT, CSV_NAME]
    assert "Links work when these files are in the same folder" in footer.get_text()


def test_without_a_main_report_only_the_csv_is_linked():
    footer = _page(_every_state()).select_one(".sidebar-footer")
    assert [a["href"] for a in footer.find_all("a")][:1] == [CSV_NAME]
    assert "Generated: Sep 27, 2026 06:20 UTC" in footer.get_text()


def test_tiles_count_the_four_services():
    page = _page(_every_state())
    tiles = {
        tile.select_one(".metric-label").get_text()[2:]: int(
            tile.select_one(".metric-value").get_text()
        )
        for tile in page.select(".metrics .metric")
    }
    # AG-01 regressed too, but it's derived, so it isn't counted here.
    assert tiles == {
        "Regressed": 1,
        "New": 1,
        "Still open": 1,
        "Resolved": 1,
        "No longer reported": 1,
        "No longer assessed": 1,
    }
    classes = [tile["class"] for tile in page.select(".metrics .metric")]
    assert classes[0] == ["metric", "danger"]
    assert classes[4] == ["metric"]


def test_area_table_groups_areas_under_the_main_reports_headings():
    page = _page(_every_state())
    rows = [
        [cell.get_text() for cell in row.find_all("td")]
        for row in page.select(".area-table tbody tr")
    ]
    assert [row[0] for row in rows] == [
        "By Service",
        "Bedrock",
        "SageMaker",
        "AgentCore",
        "AWS Agent Registry",
        "By Service total",
        "By Lens",
        "Agentic AI Security",
    ]
    assert rows[1] == ["Bedrock", "1", "0", "1", "0", "0", "0"]
    assert rows[5] == ["By Service total", "1", "1", "1", "1", "1", "1"]
    assert rows[7] == ["Agentic AI Security", "1", "0", "0", "0", "0", "0"]


def test_sidebar_lists_areas_with_the_rows_shown_by_default():
    page = _page(_every_state())
    items = {
        item["data-filter-area"]: int(item.select_one(".count").get_text())
        for item in page.select("a.nav-item[data-filter-area]")
    }
    assert items == {
        "bedrock": 2,
        "sagemaker": 2,
        "agentcore": 1,  # AC-17 is Not failing
        "agent-registry": 1,
        "agentic": 1,
    }
    changes = page.select_one('.nav-section a[href="#changes"]:not([data-filter-area])')
    assert changes.select_one(".count").get_text() == "7"
    assert page.select_one(".lens-nav h3").get_text() == "By Lens"
    assert page.select_one(".governance-nav") is None  # GRC wasn't compared


def test_changes_table_matches_the_main_reports_columns():
    page = _page(_every_state())
    table = page.select_one("#findingsTable")
    assert table["class"] == ["single-account-report"]
    assert [th.get_text() for th in table.select("thead th")] == [
        "Account ID",
        "Region",
        "Check ID",
        "Finding",
        "Severity",
        "Change",
    ]
    assert [th["data-sort"] for th in table.select("thead th")] == [
        "account",
        "region",
        "checkId",
        "finding",
        "severity",
        "change",
    ]
    rows = table.select("tbody tr")
    # Ordered by change, as the Change column sorts.
    assert [row["data-rank"] for row in rows] == sorted(
        row["data-rank"] for row in rows
    )
    regressed = rows[0]
    assert (regressed["data-change"], regressed["data-service"]) == (
        "regressed",
        "bedrock",
    )
    cells = regressed.find_all("td", recursive=False)
    assert [cell.get_text(strip=True) for cell in cells[:3]] == [
        ACCOUNT,
        "Global",
        "BR-01",
    ]
    assert cells[4].select_one(".severity.high")
    assert cells[5].select_one(".status.error").get_text() == "▼ Regressed"
    assert cells[5].select_one(".change-sub").get_text() == "Passed → Failed"


def test_change_labels_use_the_main_reports_colors():
    page = _page(_every_state())
    labels = {
        row["data-change"]: row.select_one("td:last-child .status")["class"]
        for row in page.select("#findingsTable tbody tr")
    }
    assert labels == {
        "regressed": ["status", "error"],
        "new": ["status", "error"],
        "still-open": ["status", "warning"],
        "resolved": ["status", "success"],
        "no-longer-reported": ["status", "muted"],
        "no-longer-assessed": ["status", "muted"],
        "not-failing": ["status", "muted"],
    }
    assert ".status.muted" in EXTRA_CSS


def _details(page, check_id):
    row = next(
        row
        for row in page.select("#findingsTable tbody tr")
        if row.select("code")[2].get_text() == check_id
    )
    return [
        (part.strong.get_text(), part.p.get_text())
        for part in row.select(".finding-more-body > div")
    ]


def test_details_show_both_runs_only_when_they_differ():
    page = _page(_every_state())
    assert _details(page, "BR-01")[:2] == [
        ("Details (previous run)", "No roles found"),
        ("Details (current run)", "Role 'admin' has the policy"),
    ]
    assert _details(page, "BR-02")[0] == ("Details", "details")  # same in both
    assert _details(page, "SM-02")[0] == ("Details", "details")  # previous only
    assert [label for label, _ in _details(page, "SM-02")] == [
        "Details",
        "Resolution",
        "Reference",
    ]


def test_a_finding_only_in_the_current_run_shows_its_details():
    comparison = _comparison([], [make_finding("BR-05", details="only now")])
    assert _details(_page(comparison), "BR-05")[0] == ("Details", "only now")


def test_severity_shown_is_the_previous_runs_for_findings_that_went_away():
    page = _page(_every_state())
    rows = {
        row.select("code")[2].get_text(): row.select_one(".severity")
        for row in page.select("#findingsTable tbody tr")
    }
    assert rows["AC-09"].get_text() == "Medium"  # No longer assessed
    assert rows["AC-09"]["class"] == ["severity", "medium"]
    assert rows["SM-02"]["class"] == ["severity", "low"]  # No longer reported
    assert rows["AR-02"]["class"] == ["severity", "medium"]  # New: current run's


def test_resource_text_is_escaped_and_unsafe_links_are_not_links():
    hostile = '<script>alert(1)</script> & "quoted"'
    comparison = _comparison(
        [],
        [
            make_finding(
                "BR-05",
                finding=hostile,
                details=hostile,
                resolution=hostile,
                reference="javascript:alert(1)",
            ),
            make_finding("BR-06", reference="https://docs.aws.amazon.com/x?a=1&b=2"),
        ],
    )
    html = render_changes_page(comparison, csv_name=CSV_NAME, generated_at=GENERATED)
    assert "<script>alert(1)</script>" not in html
    assert html.count("<script>") == 1  # the page's own script
    page = BeautifulSoup(html, "html.parser")
    assert page.select_one(".col-domain").get_text() == hostile
    references = [
        row.select(".finding-more-body > div")[-1]
        for row in page.select("#findingsTable tbody tr")
    ]
    assert references[0].a is None
    assert references[1].a["href"] == "https://docs.aws.amazon.com/x?a=1&b=2"
    assert references[1].a["rel"] == ["noopener", "noreferrer"]


def test_filters_offer_only_what_is_on_the_page():
    page = _page(_every_state())
    options = {
        select["id"]: [(o["value"], o.get_text()) for o in select.find_all("option")]
        for select in page.select(".filter-bar select")
    }
    assert options["regionFilter"] == [
        ("", "All Regions"),
        ("global", "Global"),
        ("us-east-1", "us-east-1"),
    ]
    assert options["serviceFilter"] == [
        ("", "All Assessment Areas"),
        ("bedrock", "Bedrock"),
        ("sagemaker", "SageMaker"),
        ("agentcore", "AgentCore"),
        ("agent-registry", "AWS Agent Registry"),
        ("agentic", "Agentic AI Security"),
    ]
    assert options["changeFilter"][0] == ("changes", "All Changes")
    assert page.select_one("#changeFilter option[selected]")["value"] == "changes"
    assert [value for value, _ in options["changeFilter"]][1:] == [
        change_slug(change) for change in ROW_ORDER[:-1]
    ] + ["not-failing", "all"]


def test_every_element_the_script_uses_exists():
    html = render_changes_page(
        _every_state(), csv_name=CSV_NAME, generated_at=GENERATED
    )
    page = BeautifulSoup(html, "html.parser")
    ids = set(re.findall(r"getElementById\('(\w+)'\)", SCRIPT))
    ids |= set(re.findall(r"'(\w+Filter)'", SCRIPT))
    assert ids == {
        "themeToggle",
        "searchInput",
        "regionFilter",
        "serviceFilter",
        "severityFilter",
        "changeFilter",
        "resetFilters",
    }
    for element_id in ids:
        assert page.find(id=element_id) is not None, element_id
    for target in {a["href"] for a in page.select("a.nav-item")}:
        assert page.select_one(target) is not None, target
    for key in (
        "data-change",
        "data-rank",
        "data-service",
        "data-severity",
        "data-region",
    ):
        assert page.select_one(f"#findingsTable tbody tr[{key}]") is not None


def test_notes_list_what_was_not_compared():
    extra = [make_finding(f"BR-{number}") for number in range(40, 62)]
    comparison = _comparison(
        [make_finding("BR-01"), make_finding("SM-26", region="us-east-1")],
        [make_finding("BR-01"), *extra, make_finding("OW-03")],
        previous={"regions": {"us-east-1", "us-west-2"}},
        current={"regions": {"us-east-1"}},
    )
    notes = [li.get_text() for li in _page(comparison).select("#notes li")]
    assert notes[0] == (
        "Not compared (enabled in only one run): OWASP Top 10 LLM (current run only)"
    )
    assert (
        notes[1]
        == "Not compared (scanned in only one run): us-west-2 (previous run only)"
    )
    assert notes[2].startswith(
        "Check IDs found in only one run: BR-40 (current run only)"
    )
    assert notes[2].endswith(", and 3 more")


def test_no_changes_is_said_plainly_and_empty_areas_still_show():
    same = [make_finding("BR-01", "Failed")]
    page = _page(_comparison(same, same))
    assert [li.get_text() for li in page.select("#notes li")] == [
        "No changes since the last assessment."
    ]
    assert [row["data-change"] for row in page.select("#findingsTable tbody tr")] == [
        "still-open"
    ]
    assert len(page.select("a.nav-item[data-filter-area]")) == 4


def test_no_notes_card_when_there_is_nothing_to_note():
    comparison = _comparison([make_finding("BR-01", "Passed")], [make_finding("BR-01")])
    assert _page(comparison).select_one("#notes") is None


def test_an_empty_comparison_says_no_findings():
    page = _page(_comparison([], []))
    assert page.select_one("#findingsTable tbody").get_text(strip=True) == (
        "No findings to display"
    )


def test_optional_areas_appear_under_their_headings():
    comparison = _comparison(
        [make_finding("FS-01"), make_finding("OW-03")],
        [make_finding("FS-01", "Passed"), make_finding("OW-03")],
    )
    page = _page(comparison)
    assert page.select_one(".governance-nav h3").get_text() == "By Governance Framework"
    assert page.select_one(".compliance-nav a")["data-filter-area"] == "owasp"
    groups = [row.get_text() for row in page.select(".area-table tr.group")]
    assert groups == ["By Service", "By Governance Framework", "By Compliance Standard"]


def test_both_saved_times_are_required():
    comparison = compare_runs(
        make_run([], execution_id="run-p"), make_run([], execution_id="run-c")
    )
    with pytest.raises(ValueError, match="saved time"):
        render_changes_page(comparison, csv_name=CSV_NAME)


def test_generated_time_defaults_to_now():
    html = render_changes_page(_comparison([], []), csv_name=CSV_NAME)
    assert f"Generated: {format_time(datetime.now(UTC))[:12]}" in html


def test_methodology_explains_every_change_state():
    page = _page(_every_state())
    labels = [
        cell.get_text()[2:] for cell in page.select("#methodology table td:first-child")
    ]
    assert labels == [change.value for change in ROW_ORDER]
    assert len(page.select("#methodology .note-list li")) == 3


def test_every_icon_has_a_size():
    # An inline SVG with no size of its own stretches to fill its container.
    # Icons are sized by width/height attributes or by a CSS rule for where
    # they sit (sidebar items, buttons, service icons, the dark-mode button).
    page = _page(_every_state(), main_report_name=MAIN_REPORT)
    sized_by_css = ".nav-item, .btn, .service-icon, .theme-toggle, .reference-btn"
    for svg in page.find_all("svg"):
        if svg.find_parent(
            class_=["nav-item", "btn", "service-icon", "theme-toggle", "reference-btn"]
        ):
            continue
        assert svg.get("width") and svg.get("height"), (sized_by_css, str(svg)[:120])
    for svg in page.select(".section-title > svg"):
        assert (svg["width"], svg["height"]) == ("24", "24")
