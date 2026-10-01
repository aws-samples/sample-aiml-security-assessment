"""The "Changes since last assessment" HTML page for one account.

Built from a ``models.Comparison`` with the main report's styling
(``render_common``). Layout and filters follow the main report:

- sidebar with the main report's area headings; clicking an area filters the
  changes table to it;
- header with both runs' saved times, days apart, the account, and a link to
  the current run's main report when it's known;
- six headline counts for the four services, and counts by area;
- the main report's findings table, with a Change column in place of Status.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from .models import CORE_AREAS, Change, ComparedRow, Comparison
from .render_common import PageParts, page_parts

TILE_ORDER = (
    Change.REGRESSED,
    Change.NEW,
    Change.STILL_OPEN,
    Change.RESOLVED,
    Change.NO_LONGER_REPORTED,
    Change.NO_LONGER_ASSESSED,
)
# Table order, and the order the Change column sorts in.
ROW_ORDER = TILE_ORDER + (Change.NOT_FAILING,)
# Symbol and status-label color for each change (D10.4). The symbol and the
# word are always shown, so color is never the only clue.
LABELS = {
    Change.REGRESSED: ("▼", "error"),
    Change.NEW: ("✚", "error"),
    Change.STILL_OPEN: ("●", "warning"),
    Change.RESOLVED: ("✓", "success"),
    Change.NO_LONGER_REPORTED: ("○", "muted"),
    Change.NO_LONGER_ASSESSED: ("?", "muted"),
    Change.NOT_FAILING: ("–", "muted"),
}
TILES = {
    Change.REGRESSED: ("danger", "Passed before, failing now"),
    Change.NEW: ("danger", "Failing now, not before"),
    Change.STILL_OPEN: ("warning", "Failing in both runs"),
    Change.RESOLVED: ("highlight", "Failing before, passing now"),
    Change.NO_LONGER_REPORTED: ("", "Failing before, not in this run"),
    Change.NO_LONGER_ASSESSED: ("", "Failing before, N/A now"),
}
SCORED_SEVERITIES = ("high", "medium", "low")
MAX_LISTED = 20
GITHUB_URL = "https://github.com/aws-samples/sample-aiml-security-assessment"
SAME_FOLDER_NOTE = (
    "Links work when these files are in the same folder, for example "
    "downloaded together or copied with aws s3 sync."
)

LINK_ICON = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'
    '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>'
    '<polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>'
)
CALENDAR_ICON = (
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
    'stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/>'
    '<line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/>'
    '<line x1="3" y1="10" x2="21" y2="10"/></svg>'
)
PERSON_ICON = (
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
    'stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>'
    '<circle cx="12" cy="7" r="4"/></svg>'
)
OVERVIEW_ICON = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'
    '<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/>'
    '<rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>'
)
CHANGES_ICON = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'
    '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>'
)
METHODOLOGY_ICON = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'
    '<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/>'
    '<line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
)
RESET_ICON = (
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
    'stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/>'
    '<path d="M3 3v5h5"/></svg>'
)


def section_icon(icon: str) -> str:
    """A nav icon sized for a section heading (24 px), as the main report does.

    Nav icons get their size from the ``.nav-item svg`` CSS rule; nothing sizes
    an icon inside ``.section-title``, so without this it fills the page.
    """
    return icon.replace("<svg ", '<svg width="24" height="24" ', 1)


def change_slug(change: Change) -> str:
    """The value used for a change in data attributes and the Change filter."""
    return change.value.lower().replace(" ", "-")


def format_time(moment: datetime) -> str:
    """A saved time as shown on the page, e.g. "Sep 3, 2026 23:37 UTC"."""
    moment = moment.astimezone(UTC)
    return f"{moment:%b} {moment.day}, {moment:%Y %H:%M} UTC"


def days_apart_text(days: int) -> str:
    if days == 0:
        return "same day"
    if days == 1:
        return "1 day apart"
    return f"{days} days apart"


def change_label(change: Change) -> str:
    symbol, color = LABELS[change]
    return f'<span class="status {color}">{symbol} {change.value}</span>'


def _shown_by_default(counts: Counter) -> int:
    return sum(n for change, n in counts.items() if change is not Change.NOT_FAILING)


def _present(areas: tuple[str, ...], by_area: dict) -> list[str]:
    """Areas to show: the four services always, the others when compared."""
    return [area for area in areas if area in CORE_AREAS or area in by_area]


def _page_areas(parts: PageParts, by_area: dict) -> list[str]:
    """Every area the sidebar lists, in sidebar order. The area filter offers
    exactly these, so clicking any sidebar area selects it (review item L4)."""
    return [
        area
        for _heading, _css, areas in parts.nav_groups
        for area in _present(areas, by_area)
    ]


def _listing(items: dict[str, str], name) -> str:
    shown = [
        f"{name(item)} ({side})" for item, side in list(items.items())[:MAX_LISTED]
    ]
    if len(items) > MAX_LISTED:
        shown.append(f"and {len(items) - MAX_LISTED} more")
    return ", ".join(shown)


# --- the page's parts -------------------------------------------------------------


def _sidebar(comparison, by_area, parts: PageParts, main_report, csv_name, generated):
    esc, attr = parts.escape_text, parts.escape_attr
    changed = sum(_shown_by_default(counts) for counts in by_area.values())
    groups = []
    for heading, css_class, areas in parts.nav_groups:
        present = _present(areas, by_area)
        if not present:
            continue
        links = "".join(
            f'<a href="#changes" class="nav-item" data-filter-area="{attr(area)}">'
            f"{parts.area_icons[area]} {esc(parts.area_labels[area])}"
            f'<span class="count">{_shown_by_default(by_area.get(area, Counter()))}</span></a>'
            for area in present
        )
        groups.append(
            f'<nav class="nav-section {css_class}"><h3>{esc(heading)}</h3>{links}</nav>'
        )
    main_link = (
        f'<p><a href="{attr(main_report)}">{esc(main_report)}</a></p>'
        if main_report
        else ""
    )
    return f"""<aside class="sidebar">
            <div class="sidebar-header">
                <h1>AI/ML Security</h1>
                <p>Changes Since Last Assessment</p>
            </div>
            {parts.theme_button}
            <nav class="nav-section">
                <h3>Navigation</h3>
                <a href="#overview" class="nav-item active">{OVERVIEW_ICON} Overview</a>
                <a href="#changes" class="nav-item">{CHANGES_ICON} Changes<span class="count">{changed}</span></a>
                <a href="#methodology" class="nav-item">{METHODOLOGY_ICON} Methodology</a>
            </nav>
            {"".join(groups)}
            <div class="sidebar-footer">
                <p>Generated: {esc(generated)}</p>
                <p>Account: {esc(comparison.account_id)}</p>
                <p style="margin-top: 8px;"><strong>Related files</strong></p>
                {main_link}
                <p><a href="{attr(csv_name)}">{esc(csv_name)}</a></p>
                <p>{SAME_FOLDER_NOTE}</p>
                <p style="margin-top: 8px;"><a href="{GITHUB_URL}">GitHub Repository</a></p>
            </div>
        </aside>"""


def _header(comparison, parts: PageParts, main_report) -> str:
    esc, attr = parts.escape_text, parts.escape_attr
    main_link = (
        f' · <a href="{attr(main_report)}">open main report</a>' if main_report else ""
    )
    return f"""<div class="page-header">
                    <h2>Changes Since Last Assessment</h2>
                    <div class="page-header-meta">
                        <span>{CALENDAR_ICON}Previous run saved {format_time(comparison.previous_saved_at)}</span>
                        <span>{CALENDAR_ICON}Current run saved {format_time(comparison.current_saved_at)}{main_link}</span>
                        <span>{days_apart_text(comparison.days_apart)}</span>
                        <span>{PERSON_ICON}Account {esc(comparison.account_id)}</span>
                    </div>
                </div>"""


def _tiles(comparison) -> str:
    counts = comparison.tile_counts()
    tiles = "".join(
        f'<div class="metric {TILES[change][0]}">'
        f'<div class="metric-label">{LABELS[change][0]} {change.value}</div>'
        f'<div class="metric-value">{counts[change]}</div>'
        f'<div class="metric-sub">{TILES[change][1]}</div></div>'
        for change in TILE_ORDER
    )
    return (
        f'<div class="metrics">{tiles}</div>'
        '<p class="finding-details tile-note">Counts are for Bedrock, SageMaker, '
        "AgentCore, and AWS Agent Registry. Agentic AI Security and OWASP rows are "
        "mostly derived from those findings, so one change can appear in several "
        "areas. The table below includes all assessment areas.</p>"
    )


def _notes(comparison, parts: PageParts) -> str:
    def name(area):
        return parts.area_labels.get(area, area)

    items = []
    if not comparison.has_changes:
        items.append("No changes since the last assessment.")
    if comparison.not_compared_modules:
        items.append(
            "Not compared (enabled in only one run): "
            + _listing(comparison.not_compared_modules, name)
        )
    if comparison.not_compared_regions:
        items.append(
            "Not compared (scanned in only one run): "
            + _listing(comparison.not_compared_regions, str)
        )
    if comparison.single_run_check_ids:
        items.append(
            "Check IDs found in only one run: "
            + _listing(comparison.single_run_check_ids, str)
        )
    if not items:
        return ""
    listed = "".join(f"<li>{parts.escape_text(item)}</li>" for item in items)
    return (
        '<div class="card" id="notes"><div class="card-header"><h3>Notes</h3></div>'
        f'<div class="card-body"><ul class="note-list finding-details">{listed}</ul></div></div>'
    )


def _count_row(label: str, counts: Counter, css_class: str = "") -> str:
    cells = "".join(f"<td>{counts[change]}</td>" for change in TILE_ORDER)
    return f'<tr class="{css_class}"><td>{label}</td>{cells}</tr>'


def _area_table(comparison, by_area, parts: PageParts) -> str:
    esc = parts.escape_text
    rows = []
    for heading, _css_class, areas in parts.nav_groups:
        present = _present(areas, by_area)
        if not present:
            continue
        rows.append(f'<tr class="group"><td colspan="7">{esc(heading)}</td></tr>')
        rows += [
            _count_row(esc(parts.area_labels[area]), by_area.get(area, Counter()))
            for area in present
        ]
        if areas == CORE_AREAS:
            rows.append(
                _count_row("By Service total", comparison.tile_counts(), "total")
            )
    header = "".join(f"<th>{change.value}</th>" for change in TILE_ORDER)
    return (
        '<div class="card"><div class="card-header"><h3>Changes by Assessment Area</h3></div>'
        '<div class="table-wrap"><table class="area-table">'
        f"<thead><tr><th>Assessment Area</th>{header}</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div></div>"
    )


DETAILS_CHANGED = "details changed"
DETAILS_CHANGED_NOTE = (
    "Each run reported one Failed row for this check, so the two rows were paired, but their "
    "details differ. Check whether one resource was fixed and another started failing."
)


def _details(row: ComparedRow, esc) -> str:
    previous = row.previous.details if row.previous else None
    current = row.current.details if row.current else None
    if previous is None or current is None or previous == current:
        text = previous if current is None else current
        return f"<div><strong>Details</strong><p>{esc(text)}</p></div>"
    note = (
        f"<div><strong>Note</strong><p>{esc(DETAILS_CHANGED_NOTE)}</p></div>"
        if row.details_changed
        else ""
    )
    return (
        f"<div><strong>Details (previous run)</strong><p>{esc(previous)}</p></div>"
        f"<div><strong>Details (current run)</strong><p>{esc(current)}</p></div>" + note
    )


def _statuses(row: ComparedRow, esc) -> str:
    text = f"{row.previous_status} → {row.current_status}"
    if row.details_changed:
        text += f" · {DETAILS_CHANGED}"
    return esc(text)


def table_row(row: ComparedRow, parts: PageParts) -> str:
    """One row of the changes table, in the main report's row markup."""
    esc, attr = parts.escape_text, parts.escape_attr
    severity = row.severity.lower()
    severity_class = severity if severity in SCORED_SEVERITIES else "na"
    reference = parts.safe_https_url(row.reference)
    reference_html = (
        f'<a href="{reference}" target="_blank" rel="noopener noreferrer" '
        f'class="reference-btn" title="View AWS Documentation">{LINK_ICON}</a>'
        if reference
        else '<span style="color: var(--text-3);">-</span>'
    )
    return f"""<tr data-service="{attr(row.area)}" data-region="{attr(row.region)}" data-severity="{attr(severity)}" data-change="{change_slug(row.change)}" data-rank="{ROW_ORDER.index(row.change)}" data-account="{attr(row.account_id)}">
            <td><code>{esc(row.account_id)}</code></td>
            <td><code>{esc(row.region)}</code></td>
            <td><code>{esc(row.check_id)}</code></td>
            <td class="finding-summary">
                <div class="col-domain">{esc(row.finding)}</div>
                <details class="finding-more">
                    <summary>Details and remediation</summary>
                    <div class="finding-more-body">
                        {_details(row, esc)}
                        <div><strong>Resolution</strong><p>{esc(row.resolution)}</p></div>
                        <div><strong>Reference</strong><p>{reference_html}</p></div>
                    </div>
                </details>
            </td>
            <td><span class="severity {severity_class}">{esc(row.severity)}</span></td>
            <td>{change_label(row.change)}<div class="change-sub">{_statuses(row, esc)}</div></td>
        </tr>"""


def _options(pairs) -> str:
    return "".join(
        f'<option value="{value}">{label}</option>' for value, label in pairs
    )


def _changes_section(comparison, by_area, parts: PageParts) -> str:
    esc, attr = parts.escape_text, parts.escape_attr
    rows = sorted(comparison.rows, key=lambda row: ROW_ORDER.index(row.change))
    body = "".join(table_row(row, parts) for row in rows) or (
        '<tr><td colspan="6" style="text-align: center; padding: 40px; '
        'color: var(--text-3);">No findings to display</td></tr>'
    )
    regions = sorted({row.region for row in comparison.rows})
    region_options = _options((attr(region.lower()), esc(region)) for region in regions)
    area_options = _options(
        (attr(area), esc(parts.area_labels[area]))
        for area in _page_areas(parts, by_area)
    )
    change_options = _options(
        [(change_slug(change), change.value) for change in TILE_ORDER]
        + [("not-failing", "Not failing"), ("all", "All Findings")]
    )
    return f"""<section id="changes" class="section">
                <div class="section-title">{section_icon(CHANGES_ICON)}Changes</div>
                <div class="filter-bar">
                    <div class="filter-group"><label>Search</label><input type="text" placeholder="Search findings..." id="searchInput"></div>
                    <div class="filter-group"><label>Region</label><select id="regionFilter"><option value="">All Regions</option>{region_options}</select></div>
                    <div class="filter-group"><label>Assessment Area</label><select id="serviceFilter"><option value="">All Assessment Areas</option>{area_options}</select></div>
                    <div class="filter-group"><label>Severity</label><select id="severityFilter"><option value="">All Severities</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="informational">Informational</option></select></div>
                    <div class="filter-group"><label>Change</label><select id="changeFilter"><option value="changes" selected>All Changes</option>{change_options}</select></div>
                    <button class="btn btn-reset" id="resetFilters">{RESET_ICON}Reset</button>
                </div>
                <div class="card"><div class="table-wrap"><table id="findingsTable" class="single-account-report"><thead><tr><th class="sortable" data-sort="account">Account ID</th><th class="sortable" data-sort="region">Region</th><th class="sortable" data-sort="checkId">Check ID</th><th class="sortable" data-sort="finding">Finding</th><th class="sortable" data-sort="severity">Severity</th><th class="sortable" data-sort="change">Change</th></tr></thead><tbody>{body}</tbody></table></div></div>
            </section>"""


def _methodology() -> str:
    states = "".join(
        f"<tr><td>{change_label(change)}</td><td class='finding-details'>{meaning}</td></tr>"
        for change, meaning in (
            (Change.REGRESSED, "Passed in the previous run, Failed now."),
            (Change.NEW, "Failed now; N/A or not present in the previous run."),
            (Change.STILL_OPEN, "Failed in both runs."),
            (Change.RESOLVED, "Failed in the previous run, Passed now."),
            (Change.NO_LONGER_REPORTED, "Failed in the previous run, not present now."),
            (
                Change.NO_LONGER_ASSESSED,
                "Failed in the previous run, N/A now. Not counted as resolved: "
                "N/A also covers access-denied and unavailable-region results.",
            ),
            (Change.NOT_FAILING, "No Failed result in either run. Hidden by default."),
        )
    )
    return f"""<section id="methodology" class="section">
                <div class="section-title">{section_icon(METHODOLOGY_ICON)}Methodology</div>
                <div class="card"><div class="card-header"><h3>Change States</h3></div><div class="card-body" style="padding: 0;"><table style="min-width: 100%;"><thead><tr><th style="width: 24%;">Change</th><th>Meaning</th></tr></thead><tbody>{states}</tbody></table></div></div>
                <div class="card"><div class="card-header"><h3>How Findings Are Matched</h3></div><div class="card-body"><ol class="note-list finding-details">
                    <li>Rows are grouped by assessment area, Region, and Check ID. The Finding title isn't part of the group, because many checks use one title when they fail and another when they pass.</li>
                    <li>Within a group, rows with the same title and identical details are paired, then rows whose details match once day counts and dates are blanked out, then rows with matching details under a different title.</li>
                    <li>Two remaining rows are paired if each is its run's only row, in the group or with its title. If both are Failed and their details differ, the row is marked "details changed": one resource may have been fixed and another started failing.</li>
                    <li>If one run has several Failed rows and the other a single row that isn't Failed, such as a Passed summary, each Failed row is paired with that row.</li>
                    <li>Anything left is unpaired and shows as New or No longer reported.</li>
                </ol>
                <p class="finding-details" style="margin-top: 12px;">The previous run is the most recent usable run saved before this one: its results are complete and, in single-account mode, its run record doesn't say it failed. Only modules enabled and regions scanned in both runs are compared. The changes CSV records which rule paired each row. See docs/ASSESSMENT_HISTORY.md in the repository.</p></div></div>
            </section>"""


# Our own small script (D10.2). The dark-mode toggle, navigation, filters, and
# sorting follow the main report's script; the theme is kept in the same
# localStorage key, so the reader's choice carries over between the reports.
SCRIPT = """
        const themeToggle = document.getElementById('themeToggle');
        const themeLabel = themeToggle.querySelector('.theme-label');
        const html = document.documentElement;
        if ((localStorage.getItem('theme') || 'light') === 'dark') { html.setAttribute('data-theme', 'dark'); themeLabel.textContent = 'Light Mode'; }
        themeToggle.addEventListener('click', function() {
            if (html.getAttribute('data-theme') === 'dark') { html.removeAttribute('data-theme'); localStorage.setItem('theme', 'light'); themeLabel.textContent = 'Dark Mode'; }
            else { html.setAttribute('data-theme', 'dark'); localStorage.setItem('theme', 'dark'); themeLabel.textContent = 'Light Mode'; }
        });
        function applyFilters() {
            const search = document.getElementById('searchInput').value.toLowerCase();
            const region = document.getElementById('regionFilter').value;
            const area = document.getElementById('serviceFilter').value;
            const severity = document.getElementById('severityFilter').value;
            const change = document.getElementById('changeFilter').value;
            document.querySelectorAll('#findingsTable tbody tr[data-change]').forEach(row => {
                let show = true;
                if (search && !row.textContent.toLowerCase().includes(search)) show = false;
                if (region && (row.dataset.region || '').toLowerCase() !== region) show = false;
                if (area && row.dataset.service !== area) show = false;
                if (severity && row.dataset.severity !== severity) show = false;
                if (change === 'changes') { if (row.dataset.change === 'not-failing') show = false; }
                else if (change !== 'all' && row.dataset.change !== change) show = false;
                row.style.display = show ? '' : 'none';
            });
        }
        document.getElementById('resetFilters').addEventListener('click', function() {
            document.getElementById('searchInput').value = '';
            document.getElementById('regionFilter').value = '';
            document.getElementById('serviceFilter').value = '';
            document.getElementById('severityFilter').value = '';
            document.getElementById('changeFilter').value = 'changes';
            applyFilters();
        });
        document.getElementById('searchInput').addEventListener('input', applyFilters);
        ['regionFilter', 'serviceFilter', 'severityFilter', 'changeFilter'].forEach(id => document.getElementById(id).addEventListener('change', applyFilters));
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', function(e) {
                e.preventDefault();
                document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
                this.classList.add('active');
                if (this.dataset.filterArea) {
                    document.getElementById('serviceFilter').value = this.dataset.filterArea;
                    document.getElementById('changeFilter').value = 'changes';
                    applyFilters();
                }
                const target = document.querySelector(this.getAttribute('href'));
                if (target) { target.scrollIntoView({ behavior: 'smooth' }); }
            });
        });
        window.addEventListener('scroll', () => {
            let current = '';
            document.querySelectorAll('.section').forEach(section => {
                if (window.pageYOffset >= section.offsetTop - 100) { current = section.getAttribute('id'); }
            });
            document.querySelectorAll('.nav-item:not([data-filter-area])').forEach(item => {
                item.classList.toggle('active', item.getAttribute('href') === '#' + current);
            });
        });
        const severityOrder = { 'high': 0, 'medium': 1, 'low': 2, 'informational': 3 };
        let currentSort = { column: null, direction: 'asc' };
        document.querySelectorAll('#findingsTable th.sortable').forEach(th => {
            th.addEventListener('click', function() {
                const key = this.dataset.sort;
                const tbody = document.querySelector('#findingsTable tbody');
                const rows = Array.from(tbody.querySelectorAll('tr[data-change]'));
                currentSort.direction = currentSort.column === key && currentSort.direction === 'asc' ? 'desc' : 'asc';
                currentSort.column = key;
                document.querySelectorAll('#findingsTable th.sortable').forEach(h => h.classList.remove('asc', 'desc'));
                this.classList.add(currentSort.direction);
                const value = row => {
                    switch (key) {
                        case 'account': return row.dataset.account || '';
                        case 'region': return row.dataset.region || '';
                        case 'checkId': return row.querySelector('td:nth-child(3) code')?.textContent || '';
                        case 'finding': return row.querySelector('.col-domain')?.textContent.toLowerCase() || '';
                        case 'severity': return severityOrder[row.dataset.severity] ?? 99;
                        default: return Number(row.dataset.rank);
                    }
                };
                rows.sort((a, b) => {
                    const x = value(a), y = value(b);
                    if (x < y) return currentSort.direction === 'asc' ? -1 : 1;
                    if (x > y) return currentSort.direction === 'asc' ? 1 : -1;
                    return 0;
                });
                rows.forEach(row => tbody.appendChild(row));
            });
        });
        applyFilters();
"""


def render_changes_page(
    comparison: Comparison,
    *,
    csv_name: str,
    main_report_name: str | None = None,
    generated_at: datetime | None = None,
    parts: PageParts | None = None,
) -> str:
    """The changes page for one comparison, as HTML text.

    ``csv_name`` and ``main_report_name`` are file names in the same folder,
    linked relatively. Pass ``main_report_name`` only when the current run's
    main report is known for certain; otherwise the link is left out.
    """
    if comparison.previous_saved_at is None or comparison.current_saved_at is None:
        raise ValueError("both runs need a saved time to render the changes page")
    parts = parts or page_parts()
    esc = parts.escape_text
    by_area = comparison.counts_by_area()
    generated = format_time(generated_at or datetime.now(UTC))
    title = f"Changes Since Last Assessment - {comparison.account_id}"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{esc(title)}</title>
    {parts.fonts_link}
    <style>{parts.css}</style>
</head>
<body>
    <div class="layout">
        {_sidebar(comparison, by_area, parts, main_report_name, csv_name, generated)}
        <main class="main">
            <section id="overview" class="section">
                {_header(comparison, parts, main_report_name)}
                {_tiles(comparison)}
                {_notes(comparison, parts)}
                {_area_table(comparison, by_area, parts)}
            </section>
            {_changes_section(comparison, by_area, parts)}
            {_methodology()}
        </main>
    </div>
    {parts.page_footer}
    <script>{SCRIPT}</script>
</body>
</html>
"""
