"""
Shared HTML report template for AI/ML Security Assessment Reports.

This module provides a unified report generation function used by both:
- Single-account Lambda (app.py)
- Multi-account CodeBuild consolidation (consolidate_html_reports.py)
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional


def generate_table_rows(findings: List[Dict], include_data_attrs: bool = True) -> str:
    """
    Generate HTML table rows from findings list.

    Args:
        findings: List of finding dictionaries
        include_data_attrs: Whether to include data-* attributes for filtering/sorting

    Returns:
        HTML string of table rows
    """
    rows = []
    for finding in findings:
        severity = finding.get(
            "severity", finding.get("Severity", "Informational")
        ).lower()
        severity_class = severity if severity in ["high", "medium", "low"] else "na"
        status = finding.get("status", finding.get("Status", "")).lower()
        status_class = (
            "passed" if status == "passed" else "na" if status == "n/a" else "failed"
        )
        service = finding.get("_service", "bedrock")
        account_id = finding.get("account_id", finding.get("Account_ID", ""))
        check_id = finding.get("check_id", finding.get("Check_ID", ""))
        finding_name = finding.get("finding", finding.get("Finding", ""))
        details = finding.get("details", finding.get("Finding_Details", ""))
        resolution = finding.get("resolution", finding.get("Resolution", ""))
        ref = finding.get("reference", finding.get("Reference", ""))

        if ref and ref.strip() and ref.strip() != "-":
            ref_html = f'''<a href="{ref}" target="_blank" class="reference-btn" title="View AWS Documentation"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg></a>'''
        else:
            ref_html = '<span style="color: var(--text-3);">-</span>'

        data_attrs = (
            f'data-service="{service}" data-severity="{severity}" data-status="{status}" data-account="{account_id}"'
            if include_data_attrs
            else ""
        )

        severity_display = finding.get(
            "severity", finding.get("Severity", "Informational")
        )
        status_display = finding.get("status", finding.get("Status", ""))

        row = f"""<tr {data_attrs}>
            <td><code>{account_id}</code></td>
            <td><code>{check_id}</code></td>
            <td class="col-domain">{finding_name}</td>
            <td class="finding-details">{details}</td>
            <td class="resolution-text">{resolution}</td>
            <td class="reference-cell">{ref_html}</td>
            <td><span class="severity {severity_class}">{severity_display}</span></td>
            <td><span class="status {"success" if status_class == "passed" else "error" if status_class == "failed" else "warning"}">{status_display}</span></td>
        </tr>"""
        rows.append(row)

    return (
        "\n".join(rows)
        if rows
        else '<tr><td colspan="8" style="text-align: center; padding: 40px; color: var(--text-3);">No findings to display</td></tr>'
    )


def get_html_template() -> str:
    """
    Returns the HTML template string with placeholders.

    This is a single source of truth for the report HTML/CSS/JS.
    """
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #f8fafc;
            --surface: #fff;
            --surface-2: #f1f5f9;
            --border: #cbd5e1;
            --text: #0f172a;
            --text-2: #64748b;
            --text-3: #94a3b8;
            --accent: #6366f1;
            --accent-soft: #eef2ff;
            --success: #10b981;
            --success-soft: #ecfdf5;
            --warning: #f59e0b;
            --warning-soft: #fffbeb;
            --danger: #ef4444;
            --danger-soft: #fef2f2;
        }}
        [data-theme="dark"] {{
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-2: #334155;
            --border: #64748b;
            --text: #f1f5f9;
            --text-2: #94a3b8;
            --text-3: #64748b;
            --accent: #818cf8;
            --accent-soft: rgba(129, 140, 248, 0.15);
            --success: #4ade80;
            --success-soft: rgba(74, 222, 128, 0.15);
            --warning: #fbbf24;
            --warning-soft: rgba(251, 191, 36, 0.15);
            --danger: #f87171;
            --danger-soft: rgba(248, 113, 113, 0.15);
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'DM Sans', system-ui, sans-serif; font-size: 14px; line-height: 1.6; color: var(--text); background: var(--bg); -webkit-font-smoothing: antialiased; }}
        .layout {{ display: grid; grid-template-columns: 280px 1fr; min-height: 100vh; }}
        .sidebar {{ background: var(--surface); border-right: 1px solid var(--border); padding: 24px 0; position: sticky; top: 0; height: 100vh; overflow-y: auto; display: flex; flex-direction: column; }}
        .sidebar-header {{ padding: 0 20px 24px; border-bottom: 1px solid var(--border); margin-bottom: 16px; }}
        .sidebar-header h1 {{ font-size: 18px; font-weight: 700; color: var(--text); margin-bottom: 4px; }}
        .sidebar-header p {{ font-size: 12px; color: var(--text-3); }}
        .theme-toggle {{ display: flex; align-items: center; gap: 8px; margin: 16px 20px; padding: 10px 14px; background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 500; color: var(--text); transition: all 0.15s; }}
        .theme-toggle:hover {{ border-color: var(--accent); background: var(--accent-soft); }}
        .theme-toggle svg {{ width: 18px; height: 18px; }}
        .theme-toggle .sun-icon {{ display: none; }}
        .theme-toggle .moon-icon {{ display: block; }}
        [data-theme="dark"] .theme-toggle .sun-icon {{ display: block; }}
        [data-theme="dark"] .theme-toggle .moon-icon {{ display: none; }}
        .nav-section {{ padding: 0 16px; margin-bottom: 24px; }}
        .nav-section h3 {{ font-size: 11px; font-weight: 600; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.5px; padding: 0 8px; margin-bottom: 8px; }}
        .nav-item {{ display: flex; align-items: center; gap: 10px; padding: 10px 12px; border-radius: 8px; color: var(--text-2); font-size: 14px; font-weight: 500; cursor: pointer; transition: all 0.15s; text-decoration: none; }}
        .nav-item:hover {{ background: var(--surface-2); color: var(--text); }}
        .nav-item.active {{ background: var(--accent-soft); color: var(--accent); }}
        .nav-item svg {{ width: 18px; height: 18px; opacity: 0.7; flex-shrink: 0; }}
        .service-icon {{ display: inline-flex; align-items: center; justify-content: center; width: 24px; height: 24px; border-radius: 6px; flex-shrink: 0; overflow: hidden; }}
        .service-icon svg {{ width: 100%; height: 100%; border-radius: 6px; }}
        .section-title .service-icon {{ width: 32px; height: 32px; }}
        .section-title .service-icon svg {{ border-radius: 8px; }}
        .nav-item .count {{ margin-left: auto; font-size: 12px; font-weight: 600; background: var(--surface-2); padding: 2px 8px; border-radius: 10px; }}
        .nav-item.active .count {{ background: var(--accent); color: #fff; }}
        .sidebar-footer {{ margin-top: auto; padding: 16px 20px; border-top: 1px solid var(--border); font-size: 12px; color: var(--text-3); }}
        .sidebar-footer a {{ color: var(--accent); text-decoration: none; }}
        .main {{ padding: 32px 40px; max-width: 1400px; }}
        .page-header {{ margin-bottom: 32px; }}
        .page-header h2 {{ font-size: 24px; font-weight: 700; margin-bottom: 8px; }}
        .page-header-meta {{ display: flex; gap: 24px; font-size: 13px; color: var(--text-2); }}
        .page-header-meta span {{ display: flex; align-items: center; gap: 6px; }}
        .metrics {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 16px; margin-bottom: 32px; }}
        .metric {{ background: var(--surface); border: 2px solid var(--border); border-radius: 12px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
        .metric-label {{ font-size: 13px; color: var(--text-2); margin-bottom: 8px; display: flex; align-items: center; gap: 6px; }}
        .metric-value {{ font-size: 28px; font-weight: 700; color: var(--text); }}
        .metric-sub {{ font-size: 12px; color: var(--text-3); margin-top: 4px; }}
        .metric.highlight {{ background: linear-gradient(135deg, var(--success-soft) 0%, rgba(16, 185, 129, 0.2) 100%); border-color: var(--success); }}
        .metric.highlight .metric-value {{ color: var(--success); }}
        .metric.danger .metric-value {{ color: var(--danger); }}
        .metric.warning .metric-value {{ color: var(--warning); }}
        .card {{ background: var(--surface); border: 2px solid var(--border); border-radius: 12px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
        .card-header {{ padding: 16px 20px; border-bottom: 2px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: var(--surface-2); }}
        .card-header h3 {{ font-size: 15px; font-weight: 600; display: flex; align-items: center; gap: 10px; }}
        .card-body {{ padding: 20px; }}
        .alerts {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; }}
        .alert-item {{ display: flex; align-items: center; gap: 12px; padding: 12px 16px; border-radius: 8px; background: var(--surface-2); cursor: pointer; transition: all 0.15s; }}
        .alert-item:hover {{ background: var(--border); }}
        .alert-item.critical {{ background: var(--danger-soft); border-left: 3px solid var(--danger); }}
        .alert-item.warning {{ background: var(--warning-soft); border-left: 3px solid var(--warning); }}
        .alert-count {{ font-size: 20px; font-weight: 700; min-width: 32px; text-align: center; }}
        .alert-item.critical .alert-count {{ color: var(--danger); }}
        .alert-item.warning .alert-count {{ color: var(--warning); }}
        .alert-info {{ flex: 1; min-width: 0; }}
        .alert-domain {{ font-weight: 600; font-size: 14px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
        .alert-category {{ font-size: 12px; color: var(--text-2); margin-top: 2px; }}
        .table-wrap {{ overflow-x: auto; max-height: 900px; overflow-y: auto; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; table-layout: fixed; min-width: 900px; }}
        table th:nth-child(1) {{ width: 11%; }}
        table th:nth-child(2) {{ width: 7%; }}
        table th:nth-child(3) {{ width: 13%; }}
        table th:nth-child(4) {{ width: 20%; }}
        table th:nth-child(5) {{ width: 20%; }}
        table th:nth-child(6) {{ width: 7%; }}
        table th:nth-child(7) {{ width: 10%; }}
        table th:nth-child(8) {{ width: 10%; }}
        th {{ text-align: left; padding: 14px 16px; font-weight: 700; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text); background: var(--surface-2); border-bottom: 3px solid var(--accent); white-space: nowrap; position: sticky; top: 0; }}
        th.sortable {{ cursor: pointer; user-select: none; transition: background 0.15s; }}
        th.sortable:hover {{ background: var(--border); }}
        th.sortable::after {{ content: ''; display: inline-block; width: 0; height: 0; margin-left: 6px; vertical-align: middle; border-left: 4px solid transparent; border-right: 4px solid transparent; border-top: 4px solid var(--text-3); opacity: 0.5; }}
        th.sortable.asc::after {{ border-top: none; border-bottom: 4px solid var(--accent); opacity: 1; }}
        th.sortable.desc::after {{ border-top: 4px solid var(--accent); opacity: 1; }}
        th:nth-last-child(-n+3), td:nth-last-child(-n+3) {{ text-align: center; }}
        td {{ padding: 14px 16px; border-bottom: 1px solid var(--border); vertical-align: top; line-height: 1.5; word-wrap: break-word; overflow-wrap: break-word; }}
        tr:hover td {{ background: var(--surface-2); }}
        .col-domain {{ font-weight: 500; color: var(--text); }}
        .status {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 500; font-family: 'JetBrains Mono', monospace; }}
        .status.success {{ background: var(--success-soft); color: var(--success); }}
        .status.error {{ background: var(--danger-soft); color: var(--danger); }}
        .status.warning {{ background: var(--warning-soft); color: var(--warning); }}
        .severity {{ display: inline-flex; align-items: center; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }}
        .severity.high {{ background: var(--danger-soft); color: var(--danger); }}
        .severity.medium {{ background: var(--warning-soft); color: var(--warning); }}
        .severity.low {{ background: var(--accent-soft); color: var(--accent); }}
        .severity.na {{ background: var(--surface-2); color: var(--text-3); }}
        .filter-bar {{ display: flex; gap: 16px; margin-bottom: 20px; flex-wrap: wrap; align-items: flex-end; }}
        .filter-group {{ display: flex; flex-direction: column; gap: 4px; }}
        .filter-group label {{ font-size: 11px; font-weight: 600; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.3px; }}
        .filter-group input, .filter-group select {{ padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 13px; font-family: inherit; background: var(--surface); color: var(--text); min-width: 160px; transition: border-color 0.15s; }}
        .filter-group input:focus, .filter-group select:focus {{ outline: none; border-color: var(--accent); }}
        .btn {{ display: inline-flex; align-items: center; gap: 6px; padding: 8px 16px; border-radius: 6px; font-size: 13px; font-weight: 500; font-family: inherit; cursor: pointer; transition: all 0.15s; border: none; }}
        .btn svg {{ width: 16px; height: 16px; }}
        .btn-reset {{ background: var(--surface); color: var(--text-2); border: 1px solid var(--border); padding: 8px 14px; }}
        .btn-reset:hover {{ background: var(--danger-soft); color: var(--danger); border-color: var(--danger); }}
        .section {{ scroll-margin-top: 20px; margin-bottom: 40px; }}
        .section-title {{ font-size: 18px; font-weight: 700; margin-bottom: 20px; padding-bottom: 12px; border-bottom: 3px solid var(--accent); display: flex; align-items: center; gap: 12px; }}
        code {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; background: var(--surface-2); padding: 2px 6px; border-radius: 4px; white-space: nowrap; }}
        .reference-cell {{ text-align: center; }}
        .reference-btn {{ display: inline-flex; align-items: center; justify-content: center; width: 28px; height: 28px; background: var(--accent-soft); color: var(--accent); text-decoration: none; border-radius: 6px; border: 1px solid var(--border); transition: all 0.15s; }}
        .reference-btn:hover {{ background: var(--accent); color: white; border-color: var(--accent); }}
        .reference-btn svg {{ width: 14px; height: 14px; }}
        .finding-details {{ color: var(--text-2); font-size: 12px; line-height: 1.6; word-break: break-word; overflow-wrap: break-word; hyphens: auto; }}
        .resolution-text {{ color: var(--text-2); font-size: 12px; line-height: 1.6; word-break: break-word; overflow-wrap: break-word; hyphens: auto; }}
        @media (max-width: 1024px) {{ .layout {{ grid-template-columns: 1fr; }} .sidebar {{ display: none; }} .metrics {{ grid-template-columns: repeat(2, 1fr); }} }}
        @media (max-width: 640px) {{ .metrics {{ grid-template-columns: 1fr; }} .main {{ padding: 20px; }} }}
        .page-footer {{ padding: 16px 40px; border-top: 1px solid var(--border); font-size: 10px; line-height: 1.6; color: var(--text-3); text-align: center; background: var(--surface); }}
        .page-footer a {{ color: var(--accent); text-decoration: none; }}
    </style>
</head>
<body>
    <div class="layout">
        <aside class="sidebar">
            <div class="sidebar-header">
                <h1>AI/ML Security</h1>
                <p>{sidebar_subtitle}</p>
            </div>
            <button class="theme-toggle" id="themeToggle" aria-label="Toggle dark mode">
                <svg class="moon-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M6 .278a.768.768 0 0 1 .08.858 7.208 7.208 0 0 0-.878 3.46c0 4.021 3.278 7.277 7.318 7.277.527 0 1.04-.055 1.533-.16a.787.787 0 0 1 .81.316.733.733 0 0 1-.031.893A8.349 8.349 0 0 1 8.344 16C3.734 16 0 12.286 0 7.71 0 4.266 2.114 1.312 5.124.06A.752.752 0 0 1 6 .278z"/></svg>
                <svg class="sun-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M8 11a3 3 0 1 1 0-6 3 3 0 0 1 0 6zm0 1a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM8 0a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-1 0v-2A.5.5 0 0 1 8 0zm0 13a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-1 0v-2A.5.5 0 0 1 8 13zm8-5a.5.5 0 0 1-.5.5h-2a.5.5 0 0 1 0-1h2a.5.5 0 0 1 .5.5zM3 8a.5.5 0 0 1-.5.5h-2a.5.5 0 0 1 0-1h2A.5.5 0 0 1 3 8zm10.657-5.657a.5.5 0 0 1 0 .707l-1.414 1.415a.5.5 0 1 1-.707-.708l1.414-1.414a.5.5 0 0 1 .707 0zm-9.193 9.193a.5.5 0 0 1 0 .707L3.05 13.657a.5.5 0 0 1-.707-.707l1.414-1.414a.5.5 0 0 1 .707 0zm9.193 2.121a.5.5 0 0 1-.707 0l-1.414-1.414a.5.5 0 0 1 .707-.707l1.414 1.414a.5.5 0 0 1 0 .707zM4.464 4.465a.5.5 0 0 1-.707 0L2.343 3.05a.5.5 0 1 1 .707-.707l1.414 1.414a.5.5 0 0 1 0 .708z"/></svg>
                <span class="theme-label">Dark Mode</span>
            </button>
            <nav class="nav-section">
                <h3>Navigation</h3>
                <a href="#overview" class="nav-item active">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>
                    Overview
                </a>
                <a href="#findings" class="nav-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    Security Findings
                    <span class="count">{total_rows}</span>
                </a>
                <a href="#risk" class="nav-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                    Risk Distribution
                </a>
                <a href="#methodology" class="nav-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                    Methodology
                </a>
            </nav>
            <nav class="nav-section">
                <h3>By Service</h3>
                <a href="#bedrock" class="nav-item">
                    <span class="service-icon"><svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg"><rect fill="#01A88D" width="80" height="80"/><path fill="#FFF" transform="translate(12,12)" d="M52,26.999C50.897,26.999 50,26.103 50,25 50,23.897 50.897,23 52,23 53.103,23 54,23.897 54,25 54,26.103 53.103,26.999 52,26.999L52,26.999ZM20.113,53.908L16.865,52.014 23.53,47.848 22.47,46.152 14.913,50.875 9,47.426 9,38.535 14.555,34.832 13.445,33.168 7.959,36.825 2,33.42 2,28.58 8.496,24.868 7.504,23.132 2,26.277 2,22.58 8,19.152 14,22.58 14,26.434 9.485,29.143 10.515,30.857 15,28.166 19.485,30.857 20.515,29.143 16,26.434 16,22.535 21.555,18.832C21.833,18.646 22,18.334 22,18L22,11 20,11 20,17.465 14.959,20.825 9,17.42 9,8.574 14,5.658 14,14 16,14 16,4.491 20.113,2.092 28,4.721 28,33.434 13.485,42.143 14.515,43.857 28,35.766 28,51.279 20.113,53.908ZM50,38C50,39.103 49.103,40 48,40 46.897,40 46,39.103 46,38 46,36.897 46.897,36 48,36 49.103,36 50,36.897 50,38L50,38ZM40,48C40,49.103 39.103,50 38,50 36.897,50 36,49.103 36,48 36,46.897 36.897,46 38,46 39.103,46 40,46.897 40,48L40,48ZM39,8C39,6.897 39.897,6 41,6 42.103,6 43,6.897 43,8 43,9.103 42.103,10 41,10 39.897,10 39,9.103 39,8L39,8ZM52,21C50.141,21 48.589,22.28 48.142,24L30,24 30,19 41,19C41.553,19 42,18.552 42,18L42,11.858C43.72,11.411 45,9.858 45,8 45,5.794 43.206,4 41,4 38.794,4 37,5.794 37,8 37,9.858 38.28,11.411 40,11.858L40,17 30,17 30,4C30,3.569 29.725,3.188 29.316,3.051L20.316,0.051C20.042,-0.039 19.744,-0.009 19.496,0.136L7.496,7.136C7.188,7.315 7,7.645 7,8L7,17.42 0.504,21.132C0.192,21.31 0,21.641 0,22L0,34C0,34.359 0.192,34.69 0.504,34.868L7,38.58 7,48C7,48.355 7.188,48.685 7.496,48.864L19.496,55.864C19.65,55.954 19.825,56 20,56 20.106,56 20.213,55.983 20.316,55.949L29.316,52.949C29.725,52.812 30,52.431 30,52L30,40 37,40 37,44.142C35.28,44.589 34,46.142 34,48 34,50.206 35.794,52 38,52 40.206,52 42,50.206 42,48 42,46.142 40.72,44.589 39,44.142L39,39C39,38.448 38.553,38 38,38L30,38 30,33 42.5,33 44.638,35.85C44.239,36.472 44,37.207 44,38 44,40.206 45.794,42 48,42 50.206,42 52,40.206 52,38 52,35.794 50.206,34 48,34 47.316,34 46.682,34.188 46.119,34.492L43.8,31.4C43.611,31.148 43.314,31 43,31L30,31 30,26 48.142,26C48.589,27.72 50.141,29 52,29 54.206,29 56,27.206 56,25 56,22.794 54.206,21 52,21L52,21Z"/></svg></span>
                    Bedrock
                    <span class="count">{bedrock_total}</span>
                </a>
                <a href="#sagemaker" class="nav-item">
                    <span class="service-icon"><svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg"><rect fill="#01A88D" width="80" height="80"/><path fill="#FFF" d="M54.034,26.034C54.034,26.594 53.578,27.05 53.017,27.05 52.458,27.05 52.002,26.594 52.002,26.034 52.002,25.474 52.458,25.018 53.017,25.018 53.578,25.018 54.034,25.474 54.034,26.034L54.034,26.034ZM48.002,36C48.002,35.449 48.45,35 49.002,35 49.554,35 50.002,35.449 50.002,36 50.002,36.551 49.554,37 49.002,37 48.45,37 48.002,36.551 48.002,36L48.002,36ZM48.002,55C48.002,54.449 48.45,54 49.002,54 49.554,54 50.002,54.449 50.002,55 50.002,55.551 49.554,56 49.002,56 48.45,56 48.002,55.551 48.002,55L48.002,55ZM58.002,42C58.002,42.551 57.554,43 57.002,43 56.45,43 56.002,42.551 56.002,42 56.002,41.449 56.45,41 57.002,41 57.554,41 58.002,41.449 58.002,42L58.002,42ZM65,45.272L59.963,42.382C59.979,42.256 60.002,42.131 60.002,42 60.002,40.346 58.656,39 57.002,39 55.347,39 54.002,40.346 54.002,42 54.002,43.654 55.347,45 57.002,45 57.801,45 58.523,44.681 59.061,44.171L63.886,46.939 59.555,49.105C59.216,49.275 59.002,49.621 59.002,50L59.002,58.441 46.983,65.837 41.003,62.42 41.003,56 46.186,56C46.6,57.161 47.7,58 49.002,58 50.656,58 52.002,56.654 52.002,55 52.002,53.345 50.656,52 49.002,52 47.7,52 46.6,52.838 46.186,54L41.003,54 41.003,40C41.003,39.649 40.818,39.323 40.517,39.142L35.516,36.142 34.487,37.857 39.003,40.566 39.003,43.507 33.002,48.123 33.002,44C33.002,43.696 32.864,43.408 32.627,43.219L28.002,39.519 28.002,34.535 33.556,30.832C33.835,30.646 34.002,30.334 34.002,30L34.002,24 32.002,24 32.002,29.465 27.013,32.79 22.002,29.464 22.002,21.575 27.002,18.659 27.002,27 29.002,27 29.002,17.492 33.005,15.157 39.001,18.616 39.002,31C39.002,31.359 39.194,31.69 39.506,31.868L46.042,35.603C46.024,35.734 46.002,35.864 46.002,36 46.002,37.654 47.347,39 49.002,39 50.656,39 52.002,37.654 52.002,36 52.002,34.346 50.656,33 49.002,33 48.208,33 47.49,33.315 46.953,33.82L41.002,30.419 41.001,18.618 46.964,15.177 58.002,22.536 58.002,25 55.851,25C55.429,23.845 54.318,23.018 53.017,23.018 51.354,23.018 50.002,24.371 50.002,26.034 50.002,27.697 51.354,29.05 53.017,29.05 54.343,29.05 55.471,28.191 55.875,27L58.002,27 58.002,30C58.002,30.36 58.194,30.691 58.506,30.869L65,34.58 65,45.272ZM33.02,65.837L29.867,63.897 35.583,59.814 34.421,58.186 28.018,62.759 21.002,58.441 21.002,50.566 25.516,47.857 24.487,46.142 19.958,48.86 15.002,46.383 15.001,40.617 20.449,37.894 19.555,36.105 15.001,38.381 15.002,34.58 20.963,31.175 26.002,34.519 26.002,39.48 20.449,43.167 21.555,44.833 26.958,41.245 31.002,44.48 31.002,49.662 26.392,53.207 27.611,54.792 39.003,46.03 39.003,62.419 33.02,65.837ZM66.496,33.132L60.002,29.42 60.002,22C60.002,21.666 59.835,21.354 59.556,21.169L47.556,13.169C47.24,12.959 46.832,12.945 46.502,13.135L40.004,16.885 33.502,13.135C33.19,12.955 32.807,12.955 32.498,13.137L20.498,20.137C20.19,20.316 20.002,20.645 20.002,21L20.002,29.42 13.506,33.132C13.194,33.31 13.002,33.641 13.002,34L13.002,34.417C13.001,34.438 13,34.458 13,34.479L13,45.363C13,45.383 13.001,45.403 13.002,45.422L13.002,47C13.002,47.379 13.216,47.725 13.555,47.894L19.002,50.618 19.002,59C19.002,59.347 19.181,59.669 19.477,59.851L32.477,67.851C32.638,67.95 32.82,68 33.002,68 33.173,68 33.344,67.956 33.498,67.868L40.003,64.152 46.506,67.868C46.821,68.049 47.213,68.042 47.526,67.851L60.526,59.851C60.822,59.669 61.002,59.347 61.002,59L61.002,50.618 66.447,47.894C66.786,47.725 67,47.379 67,47L67,34C67,33.641 66.807,33.31 66.496,33.132L66.496,33.132Z"/></svg></span>
                    SageMaker
                    <span class="count">{sagemaker_total}</span>
                </a>
                <a href="#agentcore" class="nav-item">
                    <span class="service-icon"><svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg"><rect fill="#01A88D" width="80" height="80"/><path fill="#FFF" d="M67.372,28.073L64.178,26.792 62.933,23.634C62.781,23.252 62.412,23.001 62.002,23.001 61.591,23.001 61.222,23.253 61.071,23.636L59.814,26.838 56.638,28.071C56.253,28.22 55.999,28.592 56,29.005 56.001,29.419 56.257,29.79 56.643,29.937L59.89,31.178 61.063,34.348C61.205,34.735 61.572,34.995 61.985,35.001L62,35.001C62.407,35.001 62.774,34.754 62.928,34.375L64.231,31.142 67.36,29.934C67.743,29.786 67.997,29.418 68,29.007 68.003,28.597 67.754,28.226 67.372,28.073ZM63.106,29.432C62.849,29.532 62.643,29.734 62.539,29.991L62.04,31.228 61.607,30.058C61.508,29.788 61.296,29.574 61.027,29.471L59.782,28.996 60.947,28.543C61.207,28.442 61.414,28.237 61.516,27.977L62.004,26.732 62.435,27.822C62.523,28.142 62.767,28.398 63.079,28.506L64.269,28.983 63.106,29.432ZM64.053,38.6L54.914,34.935 51.351,25.902C51.123,25.325 50.575,24.953 49.955,24.953 49.335,24.954 48.786,25.327 48.56,25.905L44.958,35.083 42,36.23 42,16C42,15.569 41.725,15.188 41.316,15.051L32.316,12.051C32.042,11.961 31.744,11.991 31.496,12.136L19.496,19.136C19.189,19.315 19,19.645 19,20L19,29.42 12.504,33.132C12.192,33.31 12,33.641 12,34L12,46C12,46.359 12.192,46.69 12.504,46.868L19,50.58 19,60C19,60.355 19.189,60.685 19.496,60.864L31.496,67.864C31.65,67.954 31.825,68 32,68 32.106,68 32.213,67.983 32.316,67.949L41.316,64.949C41.725,64.813 42,64.431 42,64L42,43.738 45.2,44.961 48.561,54.046C48.777,54.632 49.32,55.017 49.945,55.026L49.969,55.026C50.584,55.026 51.128,54.66 51.359,54.087L55.089,44.845 64.035,41.392C64.614,41.168 64.991,40.623 64.995,40.001 64.999,39.381 64.629,38.831 64.053,38.6ZM32.113,65.908L28.865,64.014 35.53,59.848 34.47,58.186 26.913,62.759 21,58.441 21,50.566 26.555,46.832 25.445,45.168 19.959,48.825 14,45.42 14,40.58 20.496,36.868 19.504,35.132 14,38.277 14,34.58 20,31.152 26,34.58 26,38.434 21.485,41.143 22.515,42.857 27,40.166 31.485,42.857 32.515,41.143 28,38.434 28,34.535 33.555,30.832C33.833,30.646 34,30.334 34,30L34,24 32,24 32,29.465 26.959,32.825 21,29.42 21,20.574 26,17.658 26,27 28,27 28,16.491 32.113,14.092 40,16.721 40,45.434 25.485,54.143 26.515,55.857 40,47.766 40,63.279 32.113,65.908ZM53.964,43.135C53.706,43.235 53.501,43.438 53.397,43.694L49.988,52.14 46.918,43.842C46.818,43.572 46.607,43.358 46.338,43.255L42,41.597 42,38.375 46.09,36.788C46.351,36.687 46.558,36.481 46.659,36.221L49.957,27.818 53.14,35.886C53.209,36.252 53.486,36.548 53.84,36.659L62.129,39.983 53.964,43.135Z"/></svg></span>
                    AgentCore
                    <span class="count">{agentcore_total}</span>
                </a>
            </nav>
            <div class="sidebar-footer">
                <p>Generated: {date_display}</p>
                <p>{account_info}</p>
                <p style="margin-top: 8px;"><a href="https://github.com/aws-samples/sample-aiml-security-assessment">GitHub Repository</a></p>
            </div>
        </aside>
        <main class="main">
            <section id="overview" class="section">
                <div class="page-header">
                    <h2>Security Assessment Overview</h2>
                    <div class="page-header-meta">
                        <span><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>{timestamp}</span>
                        <span><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>{header_account_info}</span>
                    </div>
                </div>
                <div class="metrics">
                    <div class="metric"><div class="metric-label">Security Checks</div><div class="metric-value">{security_checks}</div><div class="metric-sub">Evaluated per account</div></div>
                    <div class="metric"><div class="metric-label">Total Findings</div><div class="metric-value">{total_findings}</div><div class="metric-sub">{findings_sub}</div></div>
                    <div class="metric danger"><div class="metric-label">Actionable Findings</div><div class="metric-value">{actionable_findings}</div><div class="metric-sub">High, Medium, and Low severity</div></div>
                    <div class="metric danger"><div class="metric-label">High Severity</div><div class="metric-value">{high_passed}/{high_count}</div><div class="metric-sub">{high_pass_rate}% passed · Immediate action required</div></div>
                    <div class="metric warning"><div class="metric-label">Medium Severity</div><div class="metric-value">{medium_passed}/{medium_count}</div><div class="metric-sub">{medium_pass_rate}% passed · Should be addressed</div></div>
                    <div class="metric highlight"><div class="metric-label">Low Severity</div><div class="metric-value">{low_passed}/{low_count}</div><div class="metric-sub">{low_pass_rate}% passed · Best practices</div></div>
                </div>
                <div class="card"><div class="card-header"><h3>Priority Recommendations</h3></div><div class="card-body"><div class="alerts">{alerts}</div></div></div>
                <div class="card">
                    <div class="card-header"><h3>Severity Legend</h3><a href="#methodology" style="font-size: 12px; color: var(--accent); text-decoration: none;">View full methodology</a></div>
                    <div class="card-body" style="padding: 0;">
                        <table style="min-width: 100%; table-layout: fixed;">
                            <thead><tr><th style="width: 12%;">Severity</th><th style="width: 44%;">Meaning</th><th style="width: 44%;">Recommended Action</th></tr></thead>
                            <tbody>
                                <tr><td style="text-align: center;"><span class="severity high">High</span></td><td class="finding-details">Direct security risk - IAM/access control gaps, missing audit trails, guardrail bypasses that could lead to unauthorized access or data exposure</td><td class="resolution-text">Remediate within <strong>7 days</strong></td></tr>
                                <tr><td style="text-align: center;"><span class="severity medium">Medium</span></td><td class="finding-details">Defense-in-depth gaps - encryption, logging, or configuration issues that reduce security posture</td><td class="resolution-text">Remediate within <strong>30 days</strong></td></tr>
                                <tr><td style="text-align: center;"><span class="severity low">Low</span></td><td class="finding-details">Best practice deviations - optimization opportunities that improve security hygiene</td><td class="resolution-text">Remediate within <strong>90 days</strong></td></tr>
                                <tr><td style="text-align: center;"><span class="severity na">Informational</span></td><td class="finding-details">No resources found or advisory recommendations - check does not apply or suggests optional improvements</td><td class="resolution-text">No action required</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </section>
            <section id="findings" class="section">
                <div class="section-title"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>All Security Findings</div>
                <div class="filter-bar">
                    <div class="filter-group"><label>Search</label><input type="text" placeholder="Search findings..." id="searchInput"></div>
                    {account_filter}
                    <div class="filter-group"><label>Service</label><select id="serviceFilter"><option value="">All Services</option><option value="bedrock">Bedrock</option><option value="sagemaker">SageMaker</option><option value="agentcore">AgentCore</option></select></div>
                    <div class="filter-group"><label>Severity</label><select id="severityFilter"><option value="">All Severities</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="informational">Informational</option></select></div>
                    <div class="filter-group"><label>Status</label><select id="statusFilter"><option value="">All Statuses</option><option value="failed">Failed</option><option value="passed">Passed</option><option value="n/a">N/A</option></select></div>
                    <button class="btn btn-reset" id="resetFilters"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>Reset</button>
                </div>
                <div class="card"><div class="table-wrap"><table id="findingsTable"><thead><tr><th class="sortable" data-sort="account">Account ID</th><th class="sortable" data-sort="checkId">Check ID</th><th class="sortable" data-sort="finding">Finding</th><th>Details</th><th>Resolution</th><th>Reference</th><th class="sortable" data-sort="severity">Severity</th><th class="sortable" data-sort="status">Status</th></tr></thead><tbody>{all_rows}</tbody></table></div></div>
            </section>
            <section id="risk" class="section">
                <div class="section-title"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>Risk Distribution</div>
                <h4 style="font-size: 14px; font-weight: 600; color: var(--text-2); margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.5px;">Pass Rate by Severity</h4>
                <div class="metrics" style="margin-bottom: 32px;">
                    <div class="metric danger"><div class="metric-label"><span class="severity high" style="padding: 2px 6px; font-size: 10px;">HIGH</span></div><div class="metric-value">{high_pass_rate}%</div><div class="metric-sub">{high_passed} of {high_count} checks passed</div><div style="margin-top: 8px; height: 4px; background: var(--surface-2); border-radius: 2px; overflow: hidden;"><div style="width: {high_pass_rate}%; height: 100%; background: var(--danger);"></div></div></div>
                    <div class="metric warning"><div class="metric-label"><span class="severity medium" style="padding: 2px 6px; font-size: 10px;">MEDIUM</span></div><div class="metric-value">{medium_pass_rate}%</div><div class="metric-sub">{medium_passed} of {medium_count} checks passed</div><div style="margin-top: 8px; height: 4px; background: var(--surface-2); border-radius: 2px; overflow: hidden;"><div style="width: {medium_pass_rate}%; height: 100%; background: var(--warning);"></div></div></div>
                    <div class="metric" style="border-color: var(--accent);"><div class="metric-label"><span class="severity low" style="padding: 2px 6px; font-size: 10px;">LOW</span></div><div class="metric-value" style="color: var(--accent);">{low_pass_rate}%</div><div class="metric-sub">{low_passed} of {low_count} checks passed</div><div style="margin-top: 8px; height: 4px; background: var(--surface-2); border-radius: 2px; overflow: hidden;"><div style="width: {low_pass_rate}%; height: 100%; background: var(--accent);"></div></div></div>
                    <div class="metric"><div class="metric-label">Overall</div><div class="metric-value">{pass_rate}%</div><div class="metric-sub">{passed_count} of {actionable_findings} actionable checks</div><div style="margin-top: 8px; height: 4px; background: var(--surface-2); border-radius: 2px; overflow: hidden;"><div style="width: {pass_rate}%; height: 100%; background: var(--text-3);"></div></div></div>
                </div>
                {account_risk_section}
                <h4 style="font-size: 14px; font-weight: 600; color: var(--text-2); margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.5px;">Findings by Service</h4>
                <div class="metrics">
                    <div class="metric"><div class="metric-label"><span class="service-icon" style="width: 18px; height: 18px;"><svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg"><rect fill="#01A88D" width="80" height="80"/><path fill="#FFF" transform="translate(12,12)" d="M52,26.999C50.897,26.999 50,26.103 50,25 50,23.897 50.897,23 52,23 53.103,23 54,23.897 54,25 54,26.103 53.103,26.999 52,26.999L52,26.999ZM20.113,53.908L16.865,52.014 23.53,47.848 22.47,46.152 14.913,50.875 9,47.426 9,38.535 14.555,34.832 13.445,33.168 7.959,36.825 2,33.42 2,28.58 8.496,24.868 7.504,23.132 2,26.277 2,22.58 8,19.152 14,22.58 14,26.434 9.485,29.143 10.515,30.857 15,28.166 19.485,30.857 20.515,29.143 16,26.434 16,22.535 21.555,18.832C21.833,18.646 22,18.334 22,18L22,11 20,11 20,17.465 14.959,20.825 9,17.42 9,8.574 14,5.658 14,14 16,14 16,4.491 20.113,2.092 28,4.721 28,33.434 13.485,42.143 14.515,43.857 28,35.766 28,51.279 20.113,53.908ZM50,38C50,39.103 49.103,40 48,40 46.897,40 46,39.103 46,38 46,36.897 46.897,36 48,36 49.103,36 50,36.897 50,38L50,38ZM40,48C40,49.103 39.103,50 38,50 36.897,50 36,49.103 36,48 36,46.897 36.897,46 38,46 39.103,46 40,46.897 40,48L40,48ZM39,8C39,6.897 39.897,6 41,6 42.103,6 43,6.897 43,8 43,9.103 42.103,10 41,10 39.897,10 39,9.103 39,8L39,8ZM52,21C50.141,21 48.589,22.28 48.142,24L30,24 30,19 41,19C41.553,19 42,18.552 42,18L42,11.858C43.72,11.411 45,9.858 45,8 45,5.794 43.206,4 41,4 38.794,4 37,5.794 37,8 37,9.858 38.28,11.411 40,11.858L40,17 30,17 30,4C30,3.569 29.725,3.188 29.316,3.051L20.316,0.051C20.042,-0.039 19.744,-0.009 19.496,0.136L7.496,7.136C7.188,7.315 7,7.645 7,8L7,17.42 0.504,21.132C0.192,21.31 0,21.641 0,22L0,34C0,34.359 0.192,34.69 0.504,34.868L7,38.58 7,48C7,48.355 7.188,48.685 7.496,48.864L19.496,55.864C19.65,55.954 19.825,56 20,56 20.106,56 20.213,55.983 20.316,55.949L29.316,52.949C29.725,52.812 30,52.431 30,52L30,40 37,40 37,44.142C35.28,44.589 34,46.142 34,48 34,50.206 35.794,52 38,52 40.206,52 42,50.206 42,48 42,46.142 40.72,44.589 39,44.142L39,39C39,38.448 38.553,38 38,38L30,38 30,33 42.5,33 44.638,35.85C44.239,36.472 44,37.207 44,38 44,40.206 45.794,42 48,42 50.206,42 52,40.206 52,38 52,35.794 50.206,34 48,34 47.316,34 46.682,34.188 46.119,34.492L43.8,31.4C43.611,31.148 43.314,31 43,31L30,31 30,26 48.142,26C48.589,27.72 50.141,29 52,29 54.206,29 56,27.206 56,25 56,22.794 54.206,21 52,21L52,21Z"/></svg></span> Bedrock</div><div class="metric-value">{bedrock_total}</div><div class="metric-sub">{bedrock_failed} Failed · {bedrock_passed} Passed</div></div>
                    <div class="metric"><div class="metric-label"><span class="service-icon" style="width: 18px; height: 18px;"><svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg"><rect fill="#01A88D" width="80" height="80"/><path fill="#FFF" d="M54.034,26.034C54.034,26.594 53.578,27.05 53.017,27.05 52.458,27.05 52.002,26.594 52.002,26.034 52.002,25.474 52.458,25.018 53.017,25.018 53.578,25.018 54.034,25.474 54.034,26.034L54.034,26.034ZM48.002,36C48.002,35.449 48.45,35 49.002,35 49.554,35 50.002,35.449 50.002,36 50.002,36.551 49.554,37 49.002,37 48.45,37 48.002,36.551 48.002,36L48.002,36ZM48.002,55C48.002,54.449 48.45,54 49.002,54 49.554,54 50.002,54.449 50.002,55 50.002,55.551 49.554,56 49.002,56 48.45,56 48.002,55.551 48.002,55L48.002,55ZM58.002,42C58.002,42.551 57.554,43 57.002,43 56.45,43 56.002,42.551 56.002,42 56.002,41.449 56.45,41 57.002,41 57.554,41 58.002,41.449 58.002,42L58.002,42ZM65,45.272L59.963,42.382C59.979,42.256 60.002,42.131 60.002,42 60.002,40.346 58.656,39 57.002,39 55.347,39 54.002,40.346 54.002,42 54.002,43.654 55.347,45 57.002,45 57.801,45 58.523,44.681 59.061,44.171L63.886,46.939 59.555,49.105C59.216,49.275 59.002,49.621 59.002,50L59.002,58.441 46.983,65.837 41.003,62.42 41.003,56 46.186,56C46.6,57.161 47.7,58 49.002,58 50.656,58 52.002,56.654 52.002,55 52.002,53.345 50.656,52 49.002,52 47.7,52 46.6,52.838 46.186,54L41.003,54 41.003,40C41.003,39.649 40.818,39.323 40.517,39.142L35.516,36.142 34.487,37.857 39.003,40.566 39.003,43.507 33.002,48.123 33.002,44C33.002,43.696 32.864,43.408 32.627,43.219L28.002,39.519 28.002,34.535 33.556,30.832C33.835,30.646 34.002,30.334 34.002,30L34.002,24 32.002,24 32.002,29.465 27.013,32.79 22.002,29.464 22.002,21.575 27.002,18.659 27.002,27 29.002,27 29.002,17.492 33.005,15.157 39.001,18.616 39.002,31C39.002,31.359 39.194,31.69 39.506,31.868L46.042,35.603C46.024,35.734 46.002,35.864 46.002,36 46.002,37.654 47.347,39 49.002,39 50.656,39 52.002,37.654 52.002,36 52.002,34.346 50.656,33 49.002,33 48.208,33 47.49,33.315 46.953,33.82L41.002,30.419 41.001,18.618 46.964,15.177 58.002,22.536 58.002,25 55.851,25C55.429,23.845 54.318,23.018 53.017,23.018 51.354,23.018 50.002,24.371 50.002,26.034 50.002,27.697 51.354,29.05 53.017,29.05 54.343,29.05 55.471,28.191 55.875,27L58.002,27 58.002,30C58.002,30.36 58.194,30.691 58.506,30.869L65,34.58 65,45.272ZM33.02,65.837L29.867,63.897 35.583,59.814 34.421,58.186 28.018,62.759 21.002,58.441 21.002,50.566 25.516,47.857 24.487,46.142 19.958,48.86 15.002,46.383 15.001,40.617 20.449,37.894 19.555,36.105 15.001,38.381 15.002,34.58 20.963,31.175 26.002,34.519 26.002,39.48 20.449,43.167 21.555,44.833 26.958,41.245 31.002,44.48 31.002,49.662 26.392,53.207 27.611,54.792 39.003,46.03 39.003,62.419 33.02,65.837ZM66.496,33.132L60.002,29.42 60.002,22C60.002,21.666 59.835,21.354 59.556,21.169L47.556,13.169C47.24,12.959 46.832,12.945 46.502,13.135L40.004,16.885 33.502,13.135C33.19,12.955 32.807,12.955 32.498,13.137L20.498,20.137C20.19,20.316 20.002,20.645 20.002,21L20.002,29.42 13.506,33.132C13.194,33.31 13.002,33.641 13.002,34L13.002,34.417C13.001,34.438 13,34.458 13,34.479L13,45.363C13,45.383 13.001,45.403 13.002,45.422L13.002,47C13.002,47.379 13.216,47.725 13.555,47.894L19.002,50.618 19.002,59C19.002,59.347 19.181,59.669 19.477,59.851L32.477,67.851C32.638,67.95 32.82,68 33.002,68 33.173,68 33.344,67.956 33.498,67.868L40.003,64.152 46.506,67.868C46.821,68.049 47.213,68.042 47.526,67.851L60.526,59.851C60.822,59.669 61.002,59.347 61.002,59L61.002,50.618 66.447,47.894C66.786,47.725 67,47.379 67,47L67,34C67,33.641 66.807,33.31 66.496,33.132L66.496,33.132Z"/></svg></span> SageMaker</div><div class="metric-value">{sagemaker_total}</div><div class="metric-sub">{sagemaker_failed} Failed · {sagemaker_passed} Passed</div></div>
                    <div class="metric"><div class="metric-label"><span class="service-icon" style="width: 18px; height: 18px;"><svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg"><rect fill="#01A88D" width="80" height="80"/><path fill="#FFF" d="M67.372,28.073L64.178,26.792 62.933,23.634C62.781,23.252 62.412,23.001 62.002,23.001 61.591,23.001 61.222,23.253 61.071,23.636L59.814,26.838 56.638,28.071C56.253,28.22 55.999,28.592 56,29.005 56.001,29.419 56.257,29.79 56.643,29.937L59.89,31.178 61.063,34.348C61.205,34.735 61.572,34.995 61.985,35.001L62,35.001C62.407,35.001 62.774,34.754 62.928,34.375L64.231,31.142 67.36,29.934C67.743,29.786 67.997,29.418 68,29.007 68.003,28.597 67.754,28.226 67.372,28.073ZM63.106,29.432C62.849,29.532 62.643,29.734 62.539,29.991L62.04,31.228 61.607,30.058C61.508,29.788 61.296,29.574 61.027,29.471L59.782,28.996 60.947,28.543C61.207,28.442 61.414,28.237 61.516,27.977L62.004,26.732 62.435,27.822C62.523,28.142 62.767,28.398 63.079,28.506L64.269,28.983 63.106,29.432ZM64.053,38.6L54.914,34.935 51.351,25.902C51.123,25.325 50.575,24.953 49.955,24.953 49.335,24.954 48.786,25.327 48.56,25.905L44.958,35.083 42,36.23 42,16C42,15.569 41.725,15.188 41.316,15.051L32.316,12.051C32.042,11.961 31.744,11.991 31.496,12.136L19.496,19.136C19.189,19.315 19,19.645 19,20L19,29.42 12.504,33.132C12.192,33.31 12,33.641 12,34L12,46C12,46.359 12.192,46.69 12.504,46.868L19,50.58 19,60C19,60.355 19.189,60.685 19.496,60.864L31.496,67.864C31.65,67.954 31.825,68 32,68 32.106,68 32.213,67.983 32.316,67.949L41.316,64.949C41.725,64.813 42,64.431 42,64L42,43.738 45.2,44.961 48.561,54.046C48.777,54.632 49.32,55.017 49.945,55.026L49.969,55.026C50.584,55.026 51.128,54.66 51.359,54.087L55.089,44.845 64.035,41.392C64.614,41.168 64.991,40.623 64.995,40.001 64.999,39.381 64.629,38.831 64.053,38.6ZM32.113,65.908L28.865,64.014 35.53,59.848 34.47,58.186 26.913,62.759 21,58.441 21,50.566 26.555,46.832 25.445,45.168 19.959,48.825 14,45.42 14,40.58 20.496,36.868 19.504,35.132 14,38.277 14,34.58 20,31.152 26,34.58 26,38.434 21.485,41.143 22.515,42.857 27,40.166 31.485,42.857 32.515,41.143 28,38.434 28,34.535 33.555,30.832C33.833,30.646 34,30.334 34,30L34,24 32,24 32,29.465 26.959,32.825 21,29.42 21,20.574 26,17.658 26,27 28,27 28,16.491 32.113,14.092 40,16.721 40,45.434 25.485,54.143 26.515,55.857 40,47.766 40,63.279 32.113,65.908ZM53.964,43.135C53.706,43.235 53.501,43.438 53.397,43.694L49.988,52.14 46.918,43.842C46.818,43.572 46.607,43.358 46.338,43.255L42,41.597 42,38.375 46.09,36.788C46.351,36.687 46.558,36.481 46.659,36.221L49.957,27.818 53.14,35.886C53.209,36.252 53.486,36.548 53.84,36.659L62.129,39.983 53.964,43.135Z"/></svg></span> AgentCore</div><div class="metric-value">{agentcore_total}</div><div class="metric-sub">{agentcore_failed} Failed · {agentcore_passed} Passed</div></div>
                </div>
            </section>
            <section id="bedrock" class="section">
                <div class="section-title"><span class="service-icon"><svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg"><rect fill="#01A88D" width="80" height="80"/><path fill="#FFF" transform="translate(12,12)" d="M52,26.999C50.897,26.999 50,26.103 50,25 50,23.897 50.897,23 52,23 53.103,23 54,23.897 54,25 54,26.103 53.103,26.999 52,26.999L52,26.999ZM20.113,53.908L16.865,52.014 23.53,47.848 22.47,46.152 14.913,50.875 9,47.426 9,38.535 14.555,34.832 13.445,33.168 7.959,36.825 2,33.42 2,28.58 8.496,24.868 7.504,23.132 2,26.277 2,22.58 8,19.152 14,22.58 14,26.434 9.485,29.143 10.515,30.857 15,28.166 19.485,30.857 20.515,29.143 16,26.434 16,22.535 21.555,18.832C21.833,18.646 22,18.334 22,18L22,11 20,11 20,17.465 14.959,20.825 9,17.42 9,8.574 14,5.658 14,14 16,14 16,4.491 20.113,2.092 28,4.721 28,33.434 13.485,42.143 14.515,43.857 28,35.766 28,51.279 20.113,53.908ZM50,38C50,39.103 49.103,40 48,40 46.897,40 46,39.103 46,38 46,36.897 46.897,36 48,36 49.103,36 50,36.897 50,38L50,38ZM40,48C40,49.103 39.103,50 38,50 36.897,50 36,49.103 36,48 36,46.897 36.897,46 38,46 39.103,46 40,46.897 40,48L40,48ZM39,8C39,6.897 39.897,6 41,6 42.103,6 43,6.897 43,8 43,9.103 42.103,10 41,10 39.897,10 39,9.103 39,8L39,8ZM52,21C50.141,21 48.589,22.28 48.142,24L30,24 30,19 41,19C41.553,19 42,18.552 42,18L42,11.858C43.72,11.411 45,9.858 45,8 45,5.794 43.206,4 41,4 38.794,4 37,5.794 37,8 37,9.858 38.28,11.411 40,11.858L40,17 30,17 30,4C30,3.569 29.725,3.188 29.316,3.051L20.316,0.051C20.042,-0.039 19.744,-0.009 19.496,0.136L7.496,7.136C7.188,7.315 7,7.645 7,8L7,17.42 0.504,21.132C0.192,21.31 0,21.641 0,22L0,34C0,34.359 0.192,34.69 0.504,34.868L7,38.58 7,48C7,48.355 7.188,48.685 7.496,48.864L19.496,55.864C19.65,55.954 19.825,56 20,56 20.106,56 20.213,55.983 20.316,55.949L29.316,52.949C29.725,52.812 30,52.431 30,52L30,40 37,40 37,44.142C35.28,44.589 34,46.142 34,48 34,50.206 35.794,52 38,52 40.206,52 42,50.206 42,48 42,46.142 40.72,44.589 39,44.142L39,39C39,38.448 38.553,38 38,38L30,38 30,33 42.5,33 44.638,35.85C44.239,36.472 44,37.207 44,38 44,40.206 45.794,42 48,42 50.206,42 52,40.206 52,38 52,35.794 50.206,34 48,34 47.316,34 46.682,34.188 46.119,34.492L43.8,31.4C43.611,31.148 43.314,31 43,31L30,31 30,26 48.142,26C48.589,27.72 50.141,29 52,29 54.206,29 56,27.206 56,25 56,22.794 54.206,21 52,21L52,21Z"/></svg></span>Amazon Bedrock Findings</div>
                <div class="filter-bar">
                    <div class="filter-group"><label>Search</label><input type="text" placeholder="Search findings..." id="bedrockSearchInput"></div>
                    {bedrock_account_filter}
                    <div class="filter-group"><label>Severity</label><select id="bedrockSeverityFilter"><option value="">All Severities</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="informational">Informational</option></select></div>
                    <div class="filter-group"><label>Status</label><select id="bedrockStatusFilter"><option value="">All Statuses</option><option value="failed">Failed</option><option value="passed">Passed</option><option value="n/a">N/A</option></select></div>
                    <button class="btn btn-reset" id="bedrockResetFilters"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>Reset</button>
                </div>
                <div class="card"><div class="table-wrap"><table id="bedrockTable"><thead><tr><th>Account ID</th><th>Check ID</th><th>Finding</th><th>Details</th><th>Resolution</th><th>Reference</th><th>Severity</th><th>Status</th></tr></thead><tbody>{bedrock_rows}</tbody></table></div></div>
            </section>
            <section id="sagemaker" class="section">
                <div class="section-title"><span class="service-icon"><svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg"><rect fill="#01A88D" width="80" height="80"/><path fill="#FFF" d="M54.034,26.034C54.034,26.594 53.578,27.05 53.017,27.05 52.458,27.05 52.002,26.594 52.002,26.034 52.002,25.474 52.458,25.018 53.017,25.018 53.578,25.018 54.034,25.474 54.034,26.034L54.034,26.034ZM48.002,36C48.002,35.449 48.45,35 49.002,35 49.554,35 50.002,35.449 50.002,36 50.002,36.551 49.554,37 49.002,37 48.45,37 48.002,36.551 48.002,36L48.002,36ZM48.002,55C48.002,54.449 48.45,54 49.002,54 49.554,54 50.002,54.449 50.002,55 50.002,55.551 49.554,56 49.002,56 48.45,56 48.002,55.551 48.002,55L48.002,55ZM58.002,42C58.002,42.551 57.554,43 57.002,43 56.45,43 56.002,42.551 56.002,42 56.002,41.449 56.45,41 57.002,41 57.554,41 58.002,41.449 58.002,42L58.002,42ZM65,45.272L59.963,42.382C59.979,42.256 60.002,42.131 60.002,42 60.002,40.346 58.656,39 57.002,39 55.347,39 54.002,40.346 54.002,42 54.002,43.654 55.347,45 57.002,45 57.801,45 58.523,44.681 59.061,44.171L63.886,46.939 59.555,49.105C59.216,49.275 59.002,49.621 59.002,50L59.002,58.441 46.983,65.837 41.003,62.42 41.003,56 46.186,56C46.6,57.161 47.7,58 49.002,58 50.656,58 52.002,56.654 52.002,55 52.002,53.345 50.656,52 49.002,52 47.7,52 46.6,52.838 46.186,54L41.003,54 41.003,40C41.003,39.649 40.818,39.323 40.517,39.142L35.516,36.142 34.487,37.857 39.003,40.566 39.003,43.507 33.002,48.123 33.002,44C33.002,43.696 32.864,43.408 32.627,43.219L28.002,39.519 28.002,34.535 33.556,30.832C33.835,30.646 34.002,30.334 34.002,30L34.002,24 32.002,24 32.002,29.465 27.013,32.79 22.002,29.464 22.002,21.575 27.002,18.659 27.002,27 29.002,27 29.002,17.492 33.005,15.157 39.001,18.616 39.002,31C39.002,31.359 39.194,31.69 39.506,31.868L46.042,35.603C46.024,35.734 46.002,35.864 46.002,36 46.002,37.654 47.347,39 49.002,39 50.656,39 52.002,37.654 52.002,36 52.002,34.346 50.656,33 49.002,33 48.208,33 47.49,33.315 46.953,33.82L41.002,30.419 41.001,18.618 46.964,15.177 58.002,22.536 58.002,25 55.851,25C55.429,23.845 54.318,23.018 53.017,23.018 51.354,23.018 50.002,24.371 50.002,26.034 50.002,27.697 51.354,29.05 53.017,29.05 54.343,29.05 55.471,28.191 55.875,27L58.002,27 58.002,30C58.002,30.36 58.194,30.691 58.506,30.869L65,34.58 65,45.272ZM33.02,65.837L29.867,63.897 35.583,59.814 34.421,58.186 28.018,62.759 21.002,58.441 21.002,50.566 25.516,47.857 24.487,46.142 19.958,48.86 15.002,46.383 15.001,40.617 20.449,37.894 19.555,36.105 15.001,38.381 15.002,34.58 20.963,31.175 26.002,34.519 26.002,39.48 20.449,43.167 21.555,44.833 26.958,41.245 31.002,44.48 31.002,49.662 26.392,53.207 27.611,54.792 39.003,46.03 39.003,62.419 33.02,65.837ZM66.496,33.132L60.002,29.42 60.002,22C60.002,21.666 59.835,21.354 59.556,21.169L47.556,13.169C47.24,12.959 46.832,12.945 46.502,13.135L40.004,16.885 33.502,13.135C33.19,12.955 32.807,12.955 32.498,13.137L20.498,20.137C20.19,20.316 20.002,20.645 20.002,21L20.002,29.42 13.506,33.132C13.194,33.31 13.002,33.641 13.002,34L13.002,34.417C13.001,34.438 13,34.458 13,34.479L13,45.363C13,45.383 13.001,45.403 13.002,45.422L13.002,47C13.002,47.379 13.216,47.725 13.555,47.894L19.002,50.618 19.002,59C19.002,59.347 19.181,59.669 19.477,59.851L32.477,67.851C32.638,67.95 32.82,68 33.002,68 33.173,68 33.344,67.956 33.498,67.868L40.003,64.152 46.506,67.868C46.821,68.049 47.213,68.042 47.526,67.851L60.526,59.851C60.822,59.669 61.002,59.347 61.002,59L61.002,50.618 66.447,47.894C66.786,47.725 67,47.379 67,47L67,34C67,33.641 66.807,33.31 66.496,33.132L66.496,33.132Z"/></svg></span>Amazon SageMaker Findings</div>
                <div class="filter-bar">
                    <div class="filter-group"><label>Search</label><input type="text" placeholder="Search findings..." id="sagemakerSearchInput"></div>
                    {sagemaker_account_filter}
                    <div class="filter-group"><label>Severity</label><select id="sagemakerSeverityFilter"><option value="">All Severities</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="informational">Informational</option></select></div>
                    <div class="filter-group"><label>Status</label><select id="sagemakerStatusFilter"><option value="">All Statuses</option><option value="failed">Failed</option><option value="passed">Passed</option><option value="n/a">N/A</option></select></div>
                    <button class="btn btn-reset" id="sagemakerResetFilters"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>Reset</button>
                </div>
                <div class="card"><div class="table-wrap"><table id="sagemakerTable"><thead><tr><th>Account ID</th><th>Check ID</th><th>Finding</th><th>Details</th><th>Resolution</th><th>Reference</th><th>Severity</th><th>Status</th></tr></thead><tbody>{sagemaker_rows}</tbody></table></div></div>
            </section>
            <section id="agentcore" class="section">
                <div class="section-title"><span class="service-icon"><svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg"><rect fill="#01A88D" width="80" height="80"/><path fill="#FFF" d="M67.372,28.073L64.178,26.792 62.933,23.634C62.781,23.252 62.412,23.001 62.002,23.001 61.591,23.001 61.222,23.253 61.071,23.636L59.814,26.838 56.638,28.071C56.253,28.22 55.999,28.592 56,29.005 56.001,29.419 56.257,29.79 56.643,29.937L59.89,31.178 61.063,34.348C61.205,34.735 61.572,34.995 61.985,35.001L62,35.001C62.407,35.001 62.774,34.754 62.928,34.375L64.231,31.142 67.36,29.934C67.743,29.786 67.997,29.418 68,29.007 68.003,28.597 67.754,28.226 67.372,28.073ZM63.106,29.432C62.849,29.532 62.643,29.734 62.539,29.991L62.04,31.228 61.607,30.058C61.508,29.788 61.296,29.574 61.027,29.471L59.782,28.996 60.947,28.543C61.207,28.442 61.414,28.237 61.516,27.977L62.004,26.732 62.435,27.822C62.523,28.142 62.767,28.398 63.079,28.506L64.269,28.983 63.106,29.432ZM64.053,38.6L54.914,34.935 51.351,25.902C51.123,25.325 50.575,24.953 49.955,24.953 49.335,24.954 48.786,25.327 48.56,25.905L44.958,35.083 42,36.23 42,16C42,15.569 41.725,15.188 41.316,15.051L32.316,12.051C32.042,11.961 31.744,11.991 31.496,12.136L19.496,19.136C19.189,19.315 19,19.645 19,20L19,29.42 12.504,33.132C12.192,33.31 12,33.641 12,34L12,46C12,46.359 12.192,46.69 12.504,46.868L19,50.58 19,60C19,60.355 19.189,60.685 19.496,60.864L31.496,67.864C31.65,67.954 31.825,68 32,68 32.106,68 32.213,67.983 32.316,67.949L41.316,64.949C41.725,64.813 42,64.431 42,64L42,43.738 45.2,44.961 48.561,54.046C48.777,54.632 49.32,55.017 49.945,55.026L49.969,55.026C50.584,55.026 51.128,54.66 51.359,54.087L55.089,44.845 64.035,41.392C64.614,41.168 64.991,40.623 64.995,40.001 64.999,39.381 64.629,38.831 64.053,38.6ZM32.113,65.908L28.865,64.014 35.53,59.848 34.47,58.186 26.913,62.759 21,58.441 21,50.566 26.555,46.832 25.445,45.168 19.959,48.825 14,45.42 14,40.58 20.496,36.868 19.504,35.132 14,38.277 14,34.58 20,31.152 26,34.58 26,38.434 21.485,41.143 22.515,42.857 27,40.166 31.485,42.857 32.515,41.143 28,38.434 28,34.535 33.555,30.832C33.833,30.646 34,30.334 34,30L34,24 32,24 32,29.465 26.959,32.825 21,29.42 21,20.574 26,17.658 26,27 28,27 28,16.491 32.113,14.092 40,16.721 40,45.434 25.485,54.143 26.515,55.857 40,47.766 40,63.279 32.113,65.908ZM53.964,43.135C53.706,43.235 53.501,43.438 53.397,43.694L49.988,52.14 46.918,43.842C46.818,43.572 46.607,43.358 46.338,43.255L42,41.597 42,38.375 46.09,36.788C46.351,36.687 46.558,36.481 46.659,36.221L49.957,27.818 53.14,35.886C53.209,36.252 53.486,36.548 53.84,36.659L62.129,39.983 53.964,43.135Z"/></svg></span>Amazon Bedrock AgentCore Findings</div>
                <div class="filter-bar">
                    <div class="filter-group"><label>Search</label><input type="text" placeholder="Search findings..." id="agentcoreSearchInput"></div>
                    {agentcore_account_filter}
                    <div class="filter-group"><label>Severity</label><select id="agentcoreSeverityFilter"><option value="">All Severities</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="informational">Informational</option></select></div>
                    <div class="filter-group"><label>Status</label><select id="agentcoreStatusFilter"><option value="">All Statuses</option><option value="failed">Failed</option><option value="passed">Passed</option><option value="n/a">N/A</option></select></div>
                    <button class="btn btn-reset" id="agentcoreResetFilters"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>Reset</button>
                </div>
                <div class="card"><div class="table-wrap"><table id="agentcoreTable"><thead><tr><th>Account ID</th><th>Check ID</th><th>Finding</th><th>Details</th><th>Resolution</th><th>Reference</th><th>Severity</th><th>Status</th></tr></thead><tbody>{agentcore_rows}</tbody></table></div></div>
            </section>
            <section id="methodology" class="section">
                <div class="section-title"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>Assessment Methodology</div>
                <div class="card"><div class="card-header" style="padding: 12px 16px;"><h3 style="font-size: 14px;">Severity Levels &amp; Status Values</h3></div><div class="card-body" style="padding: 12px 16px;"><table style="width: 100%; font-size: 12px;"><tbody><tr><td style="padding: 4px 12px 4px 0; width: 100px;"><span class="severity high">High</span></td><td style="padding: 4px 0; color: var(--text-2); width: 45%;">Direct security risk</td><td style="padding: 4px 12px 4px 24px; width: 60px;"><span class="status error">Failed</span></td><td style="padding: 4px 0; color: var(--text-2);">Remediation needed</td></tr><tr><td style="padding: 4px 12px 4px 0;"><span class="severity medium">Medium</span></td><td style="padding: 4px 0; color: var(--text-2);">Defense-in-depth gap</td><td style="padding: 4px 12px 4px 24px;"><span class="status success">Passed</span></td><td style="padding: 4px 0; color: var(--text-2);">Meets requirements</td></tr><tr><td style="padding: 4px 12px 4px 0;"><span class="severity low">Low</span></td><td style="padding: 4px 0; color: var(--text-2);">Best practice</td><td style="padding: 4px 12px 4px 24px;"><span class="status warning">N/A</span></td><td style="padding: 4px 0; color: var(--text-2);">Not applicable</td></tr><tr><td style="padding: 4px 12px 4px 0;"><span class="severity na">Informational</span></td><td style="padding: 4px 0; color: var(--text-2);">No action required</td><td></td><td></td></tr></tbody></table></div></div>
                <div class="card"><div class="card-header" style="padding: 12px 16px;"><h3 style="font-size: 14px;">Remediation Guidance</h3></div><div class="card-body" style="padding: 12px 16px;"><table style="width: 100%; font-size: 12px;"><tbody><tr><td style="padding: 4px 12px 4px 0; width: 80px;"><span class="severity high">High</span></td><td style="padding: 4px 0; color: var(--text-2); width: 60px;">7 days</td><td style="padding: 4px 0; color: var(--text-2);">Address immediately; block deployment if unresolved</td></tr><tr><td style="padding: 4px 12px 4px 0;"><span class="severity medium">Medium</span></td><td style="padding: 4px 0; color: var(--text-2);">30 days</td><td style="padding: 4px 0; color: var(--text-2);">Schedule in next sprint; may require change window</td></tr><tr><td style="padding: 4px 12px 4px 0;"><span class="severity low">Low</span></td><td style="padding: 4px 0; color: var(--text-2);">90 days</td><td style="padding: 4px 0; color: var(--text-2);">Include in backlog; address during regular maintenance</td></tr></tbody></table></div></div>
                <div class="card"><div class="card-header" style="padding: 12px 16px;"><h3 style="font-size: 14px;">Assessment Notes</h3></div><div class="card-body" style="padding: 12px 16px; font-size: 12px; color: var(--text-2); line-height: 1.6;"><strong style="color: var(--text);">Point-in-time:</strong> Security posture changes as resources are modified. <strong style="color: var(--text);">Scope limited:</strong> Passed checks verify tested controls only. <strong style="color: var(--text);">Context matters:</strong> Adjust severity for compliance requirements and environment type.</div></div>
                <div class="card"><div class="card-header"><h3>Assessment Scope</h3></div><div class="card-body"><div style="display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 12px;"><div style="display: flex; align-items: center; gap: 8px; padding: 8px 12px; background: var(--surface-2); border-radius: 6px;"><span class="service-icon" style="width: 20px; height: 20px;"><svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg"><rect fill="#01A88D" width="80" height="80"/><path fill="#FFF" transform="translate(12,12)" d="M52,26.999C50.897,26.999 50,26.103 50,25 50,23.897 50.897,23 52,23 53.103,23 54,23.897 54,25 54,26.103 53.103,26.999 52,26.999L52,26.999ZM20.113,53.908L16.865,52.014 23.53,47.848 22.47,46.152 14.913,50.875 9,47.426 9,38.535 14.555,34.832 13.445,33.168 7.959,36.825 2,33.42 2,28.58 8.496,24.868 7.504,23.132 2,26.277 2,22.58 8,19.152 14,22.58 14,26.434 9.485,29.143 10.515,30.857 15,28.166 19.485,30.857 20.515,29.143 16,26.434 16,22.535 21.555,18.832C21.833,18.646 22,18.334 22,18L22,11 20,11 20,17.465 14.959,20.825 9,17.42 9,8.574 14,5.658 14,14 16,14 16,4.491 20.113,2.092 28,4.721 28,33.434 13.485,42.143 14.515,43.857 28,35.766 28,51.279 20.113,53.908ZM50,38C50,39.103 49.103,40 48,40 46.897,40 46,39.103 46,38 46,36.897 46.897,36 48,36 49.103,36 50,36.897 50,38L50,38ZM40,48C40,49.103 39.103,50 38,50 36.897,50 36,49.103 36,48 36,46.897 36.897,46 38,46 39.103,46 40,46.897 40,48L40,48ZM39,8C39,6.897 39.897,6 41,6 42.103,6 43,6.897 43,8 43,9.103 42.103,10 41,10 39.897,10 39,9.103 39,8L39,8ZM52,21C50.141,21 48.589,22.28 48.142,24L30,24 30,19 41,19C41.553,19 42,18.552 42,18L42,11.858C43.72,11.411 45,9.858 45,8 45,5.794 43.206,4 41,4 38.794,4 37,5.794 37,8 37,9.858 38.28,11.411 40,11.858L40,17 30,17 30,4C30,3.569 29.725,3.188 29.316,3.051L20.316,0.051C20.042,-0.039 19.744,-0.009 19.496,0.136L7.496,7.136C7.188,7.315 7,7.645 7,8L7,17.42 0.504,21.132C0.192,21.31 0,21.641 0,22L0,34C0,34.359 0.192,34.69 0.504,34.868L7,38.58 7,48C7,48.355 7.188,48.685 7.496,48.864L19.496,55.864C19.65,55.954 19.825,56 20,56 20.106,56 20.213,55.983 20.316,55.949L29.316,52.949C29.725,52.812 30,52.431 30,52L30,40 37,40 37,44.142C35.28,44.589 34,46.142 34,48 34,50.206 35.794,52 38,52 40.206,52 42,50.206 42,48 42,46.142 40.72,44.589 39,44.142L39,39C39,38.448 38.553,38 38,38L30,38 30,33 42.5,33 44.638,35.85C44.239,36.472 44,37.207 44,38 44,40.206 45.794,42 48,42 50.206,42 52,40.206 52,38 52,35.794 50.206,34 48,34 47.316,34 46.682,34.188 46.119,34.492L43.8,31.4C43.611,31.148 43.314,31 43,31L30,31 30,26 48.142,26C48.589,27.72 50.141,29 52,29 54.206,29 56,27.206 56,25 56,22.794 54.206,21 52,21L52,21Z"/></svg></span><span style="font-size: 13px; font-weight: 500;">Amazon Bedrock</span></div><div style="display: flex; align-items: center; gap: 8px; padding: 8px 12px; background: var(--surface-2); border-radius: 6px;"><span class="service-icon" style="width: 20px; height: 20px;"><svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg"><rect fill="#01A88D" width="80" height="80"/><path fill="#FFF" d="M54.034,26.034C54.034,26.594 53.578,27.05 53.017,27.05 52.458,27.05 52.002,26.594 52.002,26.034 52.002,25.474 52.458,25.018 53.017,25.018 53.578,25.018 54.034,25.474 54.034,26.034L54.034,26.034ZM48.002,36C48.002,35.449 48.45,35 49.002,35 49.554,35 50.002,35.449 50.002,36 50.002,36.551 49.554,37 49.002,37 48.45,37 48.002,36.551 48.002,36L48.002,36ZM48.002,55C48.002,54.449 48.45,54 49.002,54 49.554,54 50.002,54.449 50.002,55 50.002,55.551 49.554,56 49.002,56 48.45,56 48.002,55.551 48.002,55L48.002,55ZM58.002,42C58.002,42.551 57.554,43 57.002,43 56.45,43 56.002,42.551 56.002,42 56.002,41.449 56.45,41 57.002,41 57.554,41 58.002,41.449 58.002,42L58.002,42ZM65,45.272L59.963,42.382C59.979,42.256 60.002,42.131 60.002,42 60.002,40.346 58.656,39 57.002,39 55.347,39 54.002,40.346 54.002,42 54.002,43.654 55.347,45 57.002,45 57.801,45 58.523,44.681 59.061,44.171L63.886,46.939 59.555,49.105C59.216,49.275 59.002,49.621 59.002,50L59.002,58.441 46.983,65.837 41.003,62.42 41.003,56 46.186,56C46.6,57.161 47.7,58 49.002,58 50.656,58 52.002,56.654 52.002,55 52.002,53.345 50.656,52 49.002,52 47.7,52 46.6,52.838 46.186,54L41.003,54 41.003,40C41.003,39.649 40.818,39.323 40.517,39.142L35.516,36.142 34.487,37.857 39.003,40.566 39.003,43.507 33.002,48.123 33.002,44C33.002,43.696 32.864,43.408 32.627,43.219L28.002,39.519 28.002,34.535 33.556,30.832C33.835,30.646 34.002,30.334 34.002,30L34.002,24 32.002,24 32.002,29.465 27.013,32.79 22.002,29.464 22.002,21.575 27.002,18.659 27.002,27 29.002,27 29.002,17.492 33.005,15.157 39.001,18.616 39.002,31C39.002,31.359 39.194,31.69 39.506,31.868L46.042,35.603C46.024,35.734 46.002,35.864 46.002,36 46.002,37.654 47.347,39 49.002,39 50.656,39 52.002,37.654 52.002,36 52.002,34.346 50.656,33 49.002,33 48.208,33 47.49,33.315 46.953,33.82L41.002,30.419 41.001,18.618 46.964,15.177 58.002,22.536 58.002,25 55.851,25C55.429,23.845 54.318,23.018 53.017,23.018 51.354,23.018 50.002,24.371 50.002,26.034 50.002,27.697 51.354,29.05 53.017,29.05 54.343,29.05 55.471,28.191 55.875,27L58.002,27 58.002,30C58.002,30.36 58.194,30.691 58.506,30.869L65,34.58 65,45.272ZM33.02,65.837L29.867,63.897 35.583,59.814 34.421,58.186 28.018,62.759 21.002,58.441 21.002,50.566 25.516,47.857 24.487,46.142 19.958,48.86 15.002,46.383 15.001,40.617 20.449,37.894 19.555,36.105 15.001,38.381 15.002,34.58 20.963,31.175 26.002,34.519 26.002,39.48 20.449,43.167 21.555,44.833 26.958,41.245 31.002,44.48 31.002,49.662 26.392,53.207 27.611,54.792 39.003,46.03 39.003,62.419 33.02,65.837ZM66.496,33.132L60.002,29.42 60.002,22C60.002,21.666 59.835,21.354 59.556,21.169L47.556,13.169C47.24,12.959 46.832,12.945 46.502,13.135L40.004,16.885 33.502,13.135C33.19,12.955 32.807,12.955 32.498,13.137L20.498,20.137C20.19,20.316 20.002,20.645 20.002,21L20.002,29.42 13.506,33.132C13.194,33.31 13.002,33.641 13.002,34L13.002,34.417C13.001,34.438 13,34.458 13,34.479L13,45.363C13,45.383 13.001,45.403 13.002,45.422L13.002,47C13.002,47.379 13.216,47.725 13.555,47.894L19.002,50.618 19.002,59C19.002,59.347 19.181,59.669 19.477,59.851L32.477,67.851C32.638,67.95 32.82,68 33.002,68 33.173,68 33.344,67.956 33.498,67.868L40.003,64.152 46.506,67.868C46.821,68.049 47.213,68.042 47.526,67.851L60.526,59.851C60.822,59.669 61.002,59.347 61.002,59L61.002,50.618 66.447,47.894C66.786,47.725 67,47.379 67,47L67,34C67,33.641 66.807,33.31 66.496,33.132L66.496,33.132Z"/></svg></span><span style="font-size: 13px; font-weight: 500;">Amazon SageMaker</span></div><div style="display: flex; align-items: center; gap: 8px; padding: 8px 12px; background: var(--surface-2); border-radius: 6px;"><span class="service-icon" style="width: 20px; height: 20px;"><svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg"><rect fill="#01A88D" width="80" height="80"/><path fill="#FFF" d="M67.372,28.073L64.178,26.792 62.933,23.634C62.781,23.252 62.412,23.001 62.002,23.001 61.591,23.001 61.222,23.253 61.071,23.636L59.814,26.838 56.638,28.071C56.253,28.22 55.999,28.592 56,29.005 56.001,29.419 56.257,29.79 56.643,29.937L59.89,31.178 61.063,34.348C61.205,34.735 61.572,34.995 61.985,35.001L62,35.001C62.407,35.001 62.774,34.754 62.928,34.375L64.231,31.142 67.36,29.934C67.743,29.786 67.997,29.418 68,29.007 68.003,28.597 67.754,28.226 67.372,28.073ZM63.106,29.432C62.849,29.532 62.643,29.734 62.539,29.991L62.04,31.228 61.607,30.058C61.508,29.788 61.296,29.574 61.027,29.471L59.782,28.996 60.947,28.543C61.207,28.442 61.414,28.237 61.516,27.977L62.004,26.732 62.435,27.822C62.523,28.142 62.767,28.398 63.079,28.506L64.269,28.983 63.106,29.432ZM64.053,38.6L54.914,34.935 51.351,25.902C51.123,25.325 50.575,24.953 49.955,24.953 49.335,24.954 48.786,25.327 48.56,25.905L44.958,35.083 42,36.23 42,16C42,15.569 41.725,15.188 41.316,15.051L32.316,12.051C32.042,11.961 31.744,11.991 31.496,12.136L19.496,19.136C19.189,19.315 19,19.645 19,20L19,29.42 12.504,33.132C12.192,33.31 12,33.641 12,34L12,46C12,46.359 12.192,46.69 12.504,46.868L19,50.58 19,60C19,60.355 19.189,60.685 19.496,60.864L31.496,67.864C31.65,67.954 31.825,68 32,68 32.106,68 32.213,67.983 32.316,67.949L41.316,64.949C41.725,64.813 42,64.431 42,64L42,43.738 45.2,44.961 48.561,54.046C48.777,54.632 49.32,55.017 49.945,55.026L49.969,55.026C50.584,55.026 51.128,54.66 51.359,54.087L55.089,44.845 64.035,41.392C64.614,41.168 64.991,40.623 64.995,40.001 64.999,39.381 64.629,38.831 64.053,38.6ZM32.113,65.908L28.865,64.014 35.53,59.848 34.47,58.186 26.913,62.759 21,58.441 21,50.566 26.555,46.832 25.445,45.168 19.959,48.825 14,45.42 14,40.58 20.496,36.868 19.504,35.132 14,38.277 14,34.58 20,31.152 26,34.58 26,38.434 21.485,41.143 22.515,42.857 27,40.166 31.485,42.857 32.515,41.143 28,38.434 28,34.535 33.555,30.832C33.833,30.646 34,30.334 34,30L34,24 32,24 32,29.465 26.959,32.825 21,29.42 21,20.574 26,17.658 26,27 28,27 28,16.491 32.113,14.092 40,16.721 40,45.434 25.485,54.143 26.515,55.857 40,47.766 40,63.279 32.113,65.908ZM53.964,43.135C53.706,43.235 53.501,43.438 53.397,43.694L49.988,52.14 46.918,43.842C46.818,43.572 46.607,43.358 46.338,43.255L42,41.597 42,38.375 46.09,36.788C46.351,36.687 46.558,36.481 46.659,36.221L49.957,27.818 53.14,35.886C53.209,36.252 53.486,36.548 53.84,36.659L62.129,39.983 53.964,43.135Z"/></svg></span><span style="font-size: 13px; font-weight: 500;">Amazon Bedrock AgentCore</span></div></div><p style="color: var(--text-3); font-size: 12px;">Based on AWS Well-Architected Framework (Generative AI Lens) and service-specific security documentation.</p></div></div>
            </section>
        </main>
    </div>
    <footer class="page-footer">Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. Licensed under MIT-0. This report is provided as-is for informational purposes only and does not constitute professional security advice, compliance certification, or audit evidence. You are responsible for validating findings and determining applicability to your environment. See the <a href="https://aws.amazon.com/agreement/">AWS Customer Agreement</a> for terms of use.</footer>
    <script>
        const themeToggle = document.getElementById('themeToggle');
        const themeLabel = themeToggle.querySelector('.theme-label');
        const html = document.documentElement;
        const savedTheme = localStorage.getItem('theme') || 'light';
        if (savedTheme === 'dark') {{ html.setAttribute('data-theme', 'dark'); themeLabel.textContent = 'Light Mode'; }}
        themeToggle.addEventListener('click', function() {{
            const currentTheme = html.getAttribute('data-theme');
            if (currentTheme === 'dark') {{ html.removeAttribute('data-theme'); localStorage.setItem('theme', 'light'); themeLabel.textContent = 'Dark Mode'; }}
            else {{ html.setAttribute('data-theme', 'dark'); localStorage.setItem('theme', 'dark'); themeLabel.textContent = 'Light Mode'; }}
        }});
        document.querySelectorAll('.nav-item').forEach(item => {{
            item.addEventListener('click', function(e) {{
                e.preventDefault();
                const targetId = this.getAttribute('href');
                const targetSection = document.querySelector(targetId);
                document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
                this.classList.add('active');
                if (targetSection) {{ targetSection.scrollIntoView({{ behavior: 'smooth' }}); }}
            }});
        }});
        function applyFilters() {{
            const searchText = document.getElementById('searchInput').value.toLowerCase();
            const accountFilter = document.getElementById('accountFilter')?.value.toLowerCase() || '';
            const serviceFilter = document.getElementById('serviceFilter').value.toLowerCase();
            const severityFilter = document.getElementById('severityFilter').value.toLowerCase();
            const statusFilter = document.getElementById('statusFilter').value.toLowerCase();
            const rows = document.querySelectorAll('#findingsTable tbody tr');
            rows.forEach(row => {{
                const rowText = row.textContent.toLowerCase();
                const rowAccount = row.dataset.account || '';
                const rowService = row.dataset.service || '';
                const rowSeverity = row.dataset.severity || '';
                const rowStatus = row.dataset.status || '';
                let show = true;
                if (searchText && !rowText.includes(searchText)) show = false;
                if (accountFilter && rowAccount !== accountFilter) show = false;
                if (serviceFilter && rowService !== serviceFilter) show = false;
                if (severityFilter && rowSeverity !== severityFilter) show = false;
                if (statusFilter && rowStatus !== statusFilter) show = false;
                row.style.display = show ? '' : 'none';
            }});
        }}
        document.getElementById('resetFilters').addEventListener('click', function() {{
            document.getElementById('searchInput').value = '';
            if (document.getElementById('accountFilter')) document.getElementById('accountFilter').value = '';
            document.getElementById('serviceFilter').value = '';
            document.getElementById('severityFilter').value = '';
            document.getElementById('statusFilter').value = '';
            applyFilters();
        }});
        document.getElementById('searchInput').addEventListener('input', applyFilters);
        if (document.getElementById('accountFilter')) document.getElementById('accountFilter').addEventListener('change', applyFilters);
        document.getElementById('serviceFilter').addEventListener('change', applyFilters);
        document.getElementById('severityFilter').addEventListener('change', applyFilters);
        document.getElementById('statusFilter').addEventListener('change', applyFilters);
        window.addEventListener('scroll', () => {{
            const sections = document.querySelectorAll('.section');
            let current = '';
            sections.forEach(section => {{
                const sectionTop = section.offsetTop;
                if (window.pageYOffset >= sectionTop - 100) {{ current = section.getAttribute('id'); }}
            }});
            document.querySelectorAll('.nav-item').forEach(item => {{
                item.classList.remove('active');
                if (item.getAttribute('href') === '#' + current) {{ item.classList.add('active'); }}
            }});
        }});
        const severityOrder = {{ 'high': 0, 'medium': 1, 'low': 2, 'na': 3 }};
        const statusOrder = {{ 'failed': 0, 'passed': 1 }};
        let currentSort = {{ column: null, direction: 'asc' }};
        document.querySelectorAll('#findingsTable th.sortable').forEach(th => {{
            th.addEventListener('click', function() {{
                const sortKey = this.dataset.sort;
                const tbody = document.querySelector('#findingsTable tbody');
                const rows = Array.from(tbody.querySelectorAll('tr'));
                if (currentSort.column === sortKey) {{
                    currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
                }} else {{
                    currentSort.column = sortKey;
                    currentSort.direction = 'asc';
                }}
                document.querySelectorAll('#findingsTable th.sortable').forEach(h => {{
                    h.classList.remove('asc', 'desc');
                }});
                this.classList.add(currentSort.direction);
                rows.sort((a, b) => {{
                    let aVal, bVal;
                    switch (sortKey) {{
                        case 'account':
                            aVal = a.dataset.account || '';
                            bVal = b.dataset.account || '';
                            break;
                        case 'checkId':
                            aVal = a.querySelector('td:nth-child(2) code')?.textContent || '';
                            bVal = b.querySelector('td:nth-child(2) code')?.textContent || '';
                            break;
                        case 'finding':
                            aVal = a.querySelector('.col-domain')?.textContent.toLowerCase() || '';
                            bVal = b.querySelector('.col-domain')?.textContent.toLowerCase() || '';
                            break;
                        case 'severity':
                            aVal = severityOrder[a.dataset.severity] ?? 99;
                            bVal = severityOrder[b.dataset.severity] ?? 99;
                            break;
                        case 'status':
                            aVal = statusOrder[a.dataset.status] ?? 99;
                            bVal = statusOrder[b.dataset.status] ?? 99;
                            break;
                    }}
                    if (aVal < bVal) return currentSort.direction === 'asc' ? -1 : 1;
                    if (aVal > bVal) return currentSort.direction === 'asc' ? 1 : -1;
                    return 0;
                }});
                rows.forEach(row => tbody.appendChild(row));
            }});
        }});
        // Service-specific filter functions
        function createServiceFilter(tableId, searchId, accountId, severityId, statusId, resetId) {{
            const table = document.getElementById(tableId);
            if (!table) return;
            const searchInput = document.getElementById(searchId);
            const accountFilter = document.getElementById(accountId);
            const severityFilter = document.getElementById(severityId);
            const statusFilter = document.getElementById(statusId);
            const resetBtn = document.getElementById(resetId);
            function applyServiceFilters() {{
                const searchText = searchInput?.value.toLowerCase() || '';
                const accountValue = accountFilter?.value.toLowerCase() || '';
                const severityValue = severityFilter?.value.toLowerCase() || '';
                const statusValue = statusFilter?.value.toLowerCase() || '';
                const rows = table.querySelectorAll('tbody tr');
                rows.forEach(row => {{
                    const rowText = row.textContent.toLowerCase();
                    const rowAccount = row.dataset.account || '';
                    const rowSeverity = row.dataset.severity || '';
                    const rowStatus = row.dataset.status || '';
                    let show = true;
                    if (searchText && !rowText.includes(searchText)) show = false;
                    if (accountValue && rowAccount !== accountValue) show = false;
                    if (severityValue && rowSeverity !== severityValue) show = false;
                    if (statusValue && rowStatus !== statusValue) show = false;
                    row.style.display = show ? '' : 'none';
                }});
            }}
            searchInput?.addEventListener('input', applyServiceFilters);
            accountFilter?.addEventListener('change', applyServiceFilters);
            severityFilter?.addEventListener('change', applyServiceFilters);
            statusFilter?.addEventListener('change', applyServiceFilters);
            resetBtn?.addEventListener('click', function() {{
                if (searchInput) searchInput.value = '';
                if (accountFilter) accountFilter.value = '';
                if (severityFilter) severityFilter.value = '';
                if (statusFilter) statusFilter.value = '';
                applyServiceFilters();
            }});
        }}
        createServiceFilter('bedrockTable', 'bedrockSearchInput', 'bedrockAccountFilter', 'bedrockSeverityFilter', 'bedrockStatusFilter', 'bedrockResetFilters');
        createServiceFilter('sagemakerTable', 'sagemakerSearchInput', 'sagemakerAccountFilter', 'sagemakerSeverityFilter', 'sagemakerStatusFilter', 'sagemakerResetFilters');
        createServiceFilter('agentcoreTable', 'agentcoreSearchInput', 'agentcoreAccountFilter', 'agentcoreSeverityFilter', 'agentcoreStatusFilter', 'agentcoreResetFilters');

        // Apply initial filters for main table
        applyFilters();
    </script>
</body>
</html>"""


def generate_html_report(
    all_findings: List[Dict],
    service_findings: Dict[str, List[Dict]],
    service_stats: Dict[str, Dict[str, int]],
    mode: str = "single",
    account_id: Optional[str] = None,
    account_ids: Optional[List[str]] = None,
    timestamp: Optional[str] = None,
) -> str:
    """
    Generate HTML report from findings data.

    Args:
        all_findings: List of all finding dictionaries
        service_findings: Dict mapping service name to list of findings
        service_stats: Dict mapping service name to {'passed': int, 'failed': int}
        mode: 'single' for single-account, 'multi' for multi-account
        account_id: Account ID (for single-account mode)
        account_ids: List of account IDs (for multi-account mode)
        timestamp: Optional timestamp string

    Returns:
        Complete HTML report string
    """
    # Calculate metrics
    total_findings = len(all_findings)  # All findings including N/A for table display
    unique_check_ids = set(
        f.get("check_id", f.get("Check_ID", "")) for f in all_findings
    )
    security_checks = len(unique_check_ids)  # Unique security controls evaluated
    high_count = sum(
        1
        for f in all_findings
        if f.get("severity", f.get("Severity", "")).lower() == "high"
    )
    medium_count = sum(
        1
        for f in all_findings
        if f.get("severity", f.get("Severity", "")).lower() == "medium"
    )
    low_count = sum(
        1
        for f in all_findings
        if f.get("severity", f.get("Severity", "")).lower() == "low"
    )
    actionable_findings = (
        high_count + medium_count + low_count
    )  # Only High/Medium/Low severity

    # Severity-specific pass rates
    high_passed = sum(
        1
        for f in all_findings
        if f.get("severity", f.get("Severity", "")).lower() == "high"
        and f.get("status", f.get("Status", "")).lower() == "passed"
    )
    medium_passed = sum(
        1
        for f in all_findings
        if f.get("severity", f.get("Severity", "")).lower() == "medium"
        and f.get("status", f.get("Status", "")).lower() == "passed"
    )
    low_passed = sum(
        1
        for f in all_findings
        if f.get("severity", f.get("Severity", "")).lower() == "low"
        and f.get("status", f.get("Status", "")).lower() == "passed"
    )
    passed_count = high_passed + medium_passed + low_passed
    pass_rate = (
        round((passed_count / actionable_findings * 100), 1)
        if actionable_findings > 0
        else 0
    )
    high_pass_rate = round((high_passed / high_count * 100), 1) if high_count > 0 else 0
    medium_pass_rate = (
        round((medium_passed / medium_count * 100), 1) if medium_count > 0 else 0
    )
    low_pass_rate = round((low_passed / low_count * 100), 1) if low_count > 0 else 0

    # Timestamp handling
    if not timestamp:
        timestamp = datetime.now(timezone.utc).strftime("%B %d, %Y %H:%M:%S UTC")
    date_display = datetime.now(timezone.utc).strftime("%B %d, %Y")

    # Build priority alerts
    high_priority = [
        f
        for f in all_findings
        if f.get("severity", f.get("Severity", "")).lower() == "high"
        and f.get("status", f.get("Status", "")).lower() == "failed"
    ]
    medium_priority = [
        f
        for f in all_findings
        if f.get("severity", f.get("Severity", "")).lower() == "medium"
        and f.get("status", f.get("Status", "")).lower() == "failed"
    ]

    alerts_html = ""
    alert_groups = {}
    for f in high_priority[:4]:
        key = f.get("finding", f.get("Finding", ""))
        if key not in alert_groups:
            alert_groups[key] = {"count": 0, "finding": f}
        alert_groups[key]["count"] += 1

    for key, data in list(alert_groups.items())[:3]:
        f = data["finding"]
        service_name = (
            "Bedrock"
            if f.get("_service") == "bedrock"
            else "SageMaker"
            if f.get("_service") == "sagemaker"
            else "AgentCore"
        )
        alerts_html += f"""<div class="alert-item critical">
            <div class="alert-count">{data["count"]}</div>
            <div class="alert-info">
                <div class="alert-domain">{f.get("finding", f.get("Finding", ""))}</div>
                <div class="alert-category">{service_name}</div>
            </div>
        </div>"""

    for f in medium_priority[:1]:
        service_name = (
            "Bedrock"
            if f.get("_service") == "bedrock"
            else "SageMaker"
            if f.get("_service") == "sagemaker"
            else "AgentCore"
        )
        alerts_html += f"""<div class="alert-item warning">
            <div class="alert-count">1</div>
            <div class="alert-info">
                <div class="alert-domain">{f.get("finding", f.get("Finding", ""))}</div>
                <div class="alert-category">{service_name}</div>
            </div>
        </div>"""

    if not alerts_html:
        alerts_html = '<div class="alert-item"><div class="alert-info"><div class="alert-domain">No critical findings</div></div></div>'

    # Generate table rows
    all_rows = generate_table_rows(all_findings, include_data_attrs=True)
    bedrock_rows = generate_table_rows(
        service_findings.get("bedrock", []), include_data_attrs=True
    )
    sagemaker_rows = generate_table_rows(
        service_findings.get("sagemaker", []), include_data_attrs=True
    )
    agentcore_rows = generate_table_rows(
        service_findings.get("agentcore", []), include_data_attrs=True
    )

    # Mode-specific content
    num_accounts = len(account_ids) if account_ids else 1
    if mode == "multi":
        title = "Multi-Account AI/ML Security Assessment Report"
        sidebar_subtitle = "Multi-Account Assessment"
        account_info = f"Accounts: {num_accounts}"
        header_account_info = f"{num_accounts} Accounts"
        findings_sub = f"Across {num_accounts} accounts"
        account_options = "".join(
            [
                f'<option value="{acc}">{acc}</option>'
                for acc in sorted(account_ids or [])
            ]
        )
        account_filter = f'<div class="filter-group"><label>Account</label><select id="accountFilter"><option value="">All Accounts</option>{account_options}</select></div>'
        bedrock_account_filter = f'<div class="filter-group"><label>Account</label><select id="bedrockAccountFilter"><option value="">All Accounts</option>{account_options}</select></div>'
        sagemaker_account_filter = f'<div class="filter-group"><label>Account</label><select id="sagemakerAccountFilter"><option value="">All Accounts</option>{account_options}</select></div>'
        agentcore_account_filter = f'<div class="filter-group"><label>Account</label><select id="agentcoreAccountFilter"><option value="">All Accounts</option>{account_options}</select></div>'

        # Calculate per-account risk metrics
        account_metrics_html = ""
        for acc_id in sorted(account_ids or []):
            acc_findings = [
                f
                for f in all_findings
                if f.get("account_id", f.get("Account_ID", "")) == acc_id
            ]
            acc_high = sum(
                1
                for f in acc_findings
                if f.get("severity", f.get("Severity", "")).lower() == "high"
                and f.get("status", f.get("Status", "")).lower() == "failed"
            )
            acc_medium = sum(
                1
                for f in acc_findings
                if f.get("severity", f.get("Severity", "")).lower() == "medium"
                and f.get("status", f.get("Status", "")).lower() == "failed"
            )
            acc_low = sum(
                1
                for f in acc_findings
                if f.get("severity", f.get("Severity", "")).lower() == "low"
                and f.get("status", f.get("Status", "")).lower() == "failed"
            )
            acc_total_failed = acc_high + acc_medium + acc_low

            # Determine risk level color
            if acc_high > 0:
                risk_class = "danger"
                border_color = "var(--danger)"
            elif acc_medium > 0:
                risk_class = "warning"
                border_color = "var(--warning)"
            else:
                risk_class = ""
                border_color = "var(--success)"

            account_metrics_html += f"""<div class="metric {risk_class}" style="border-left: 3px solid {border_color};"><div class="metric-label" style="font-family: \'JetBrains Mono\', monospace; font-size: 12px;">{acc_id}</div><div class="metric-value">{acc_total_failed}</div><div class="metric-sub"><span style="color: var(--danger);">{acc_high} High</span> · <span style="color: var(--warning);">{acc_medium} Med</span> · <span style="color: var(--accent);">{acc_low} Low</span></div></div>"""

        account_risk_section = f"""<h4 style="font-size: 14px; font-weight: 600; color: var(--text-2); margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.5px;">Risk by Account</h4>
                <div class="metrics" style="margin-bottom: 32px;">{account_metrics_html}</div>"""
    else:
        title = "AI/ML Security Assessment Report"
        sidebar_subtitle = "Assessment Report"
        account_info = f"Account: {account_id or 'Unknown'}"
        header_account_info = f"Account: {account_id or 'Unknown'}"
        findings_sub = "Across 1 account"
        account_filter = ""
        bedrock_account_filter = ""
        sagemaker_account_filter = ""
        agentcore_account_filter = ""
        account_risk_section = ""

    # Fill template
    html_template = get_html_template()

    return html_template.format(
        title=title,
        sidebar_subtitle=sidebar_subtitle,
        account_info=account_info,
        header_account_info=header_account_info,
        account_filter=account_filter,
        timestamp=timestamp,
        date_display=date_display,
        security_checks=security_checks,
        total_findings=total_findings,
        findings_sub=findings_sub,
        actionable_findings=actionable_findings,
        total_rows=total_findings,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        passed_count=passed_count,
        pass_rate=pass_rate,
        high_passed=high_passed,
        medium_passed=medium_passed,
        low_passed=low_passed,
        high_pass_rate=high_pass_rate,
        medium_pass_rate=medium_pass_rate,
        low_pass_rate=low_pass_rate,
        bedrock_total=service_stats.get("bedrock", {}).get("passed", 0)
        + service_stats.get("bedrock", {}).get("failed", 0)
        + service_stats.get("bedrock", {}).get("na", 0),
        bedrock_failed=service_stats.get("bedrock", {}).get("failed", 0),
        bedrock_passed=service_stats.get("bedrock", {}).get("passed", 0),
        sagemaker_total=service_stats.get("sagemaker", {}).get("passed", 0)
        + service_stats.get("sagemaker", {}).get("failed", 0)
        + service_stats.get("sagemaker", {}).get("na", 0),
        sagemaker_failed=service_stats.get("sagemaker", {}).get("failed", 0),
        sagemaker_passed=service_stats.get("sagemaker", {}).get("passed", 0),
        agentcore_total=service_stats.get("agentcore", {}).get("passed", 0)
        + service_stats.get("agentcore", {}).get("failed", 0)
        + service_stats.get("agentcore", {}).get("na", 0),
        agentcore_failed=service_stats.get("agentcore", {}).get("failed", 0),
        agentcore_passed=service_stats.get("agentcore", {}).get("passed", 0),
        alerts=alerts_html,
        all_rows=all_rows,
        bedrock_rows=bedrock_rows,
        sagemaker_rows=sagemaker_rows,
        agentcore_rows=agentcore_rows,
        bedrock_account_filter=bedrock_account_filter,
        sagemaker_account_filter=sagemaker_account_filter,
        agentcore_account_filter=agentcore_account_filter,
        account_risk_section=account_risk_section,
    )
