"""
Shared HTML report template for AI/ML Security Assessment Reports.

This module provides a unified report generation function used by both:
- Single-account Lambda (app.py)
- Multi-account CodeBuild consolidation (consolidate_html_reports.py)
"""

from datetime import datetime, timezone
import html
from typing import Dict, List, Optional
from urllib.parse import urlparse

# FinServ service icon (no official AWS icon exists for "Financial Services").
FINSERV_ICON = (
    '<span class="service-icon"><svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg">'
    '<rect fill="#7C3AED" width="80" height="80"/>'
    '<path fill="#FFF" d="M40 14 L66 26 L66 31 L14 31 L14 26 Z '
    'M20 35 h6 v23 h-6 z M37 35 h6 v23 h-6 z M54 35 h6 v23 h-6 z M14 62 h52 v5 h-52 z"/></svg></span>'
 )
FINSERV_ICON_SMALL = (
    '<span class="service-icon" style="width: 18px; height: 18px;">'
    '<svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg">'
    '<rect fill="#7C3AED" width="80" height="80"/>'
    '<path fill="#FFF" d="M40 14 L66 26 L66 31 L14 31 L14 26 Z '
    'M20 35 h6 v23 h-6 z M37 35 h6 v23 h-6 z M54 35 h6 v23 h-6 z M14 62 h52 v5 h-52 z"/></svg></span>'
 )
AGENTIC_ICON = (
    '<span class="service-icon"><svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg">'
    '<rect fill="#0F766E" width="80" height="80"/>'
    '<path fill="#FFF" d="M40 10 64 20v16c0 15-9.8 27.8-24 34-14.2-6.2-24-19-24-34V20l24-10zm0 8-16 6.7V36c0 10.4 6.1 19.9 16 25 9.9-5.1 16-14.6 16-25V24.7L40 18zm-8 17a8 8 0 1 1 14.9 4.1L52 48h-8l-3.2-5.3h-1.6L36 48h-8l5.1-8.9A8 8 0 0 1 32 35z"/></svg></span>'
 )
AGENTIC_ICON_SMALL = (
    '<span class="service-icon" style="width: 18px; height: 18px;">'
    '<svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg">'
    '<rect fill="#0F766E" width="80" height="80"/>'
    '<path fill="#FFF" d="M40 10 64 20v16c0 15-9.8 27.8-24 34-14.2-6.2-24-19-24-34V20l24-10zm0 8-16 6.7V36c0 10.4 6.1 19.9 16 25 9.9-5.1 16-14.6 16-25V24.7L40 18zm-8 17a8 8 0 1 1 14.9 4.1L52 48h-8l-3.2-5.3h-1.6L36 48h-8l5.1-8.9A8 8 0 0 1 32 35z"/></svg></span>'
 )
GENAI_LENS_URL = (
    "https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/"
    "generative-ai-lens.html"
 )
AGENTIC_AI_LENS_URL = (
    "https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/"
    "agentic-ai-lens.html"
 )
FINSERV_GUIDE_URL = (
    "https://aws.amazon.com/blogs/security/"
    "introducing-the-updated-aws-user-guide-to-governance-risk-and-compliance-for-responsible-ai-adoption/"
 )

# OWASP Top 10 for LLM icon (no official AWS icon; shield outline).
OWASP_ICON = (
    '<span class="service-icon"><svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg">'
    '<rect fill="#10B981" width="80" height="80"/>'
    '<path fill="#FFF" d="M40 12 20 20v18c0 14 8 26 20 30 12-4 20-16 20-30V20L40 12zm0 8 12 4.8V38c0 10-5.2 18.6-12 22-6.8-3.4-12-12-12-22V24.8L40 20zm-3 12h6l-3 8-3-8z"/></svg></span>'
 )
OWASP_ICON_SMALL = (
    '<span class="service-icon" style="width: 18px; height: 18px;">'
    '<svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg">'
    '<rect fill="#10B981" width="80" height="80"/>'
    '<path fill="#FFF" d="M40 12 20 20v18c0 14 8 26 20 30 12-4 20-16 20-30V20L40 12zm0 8 12 4.8V38c0 10-5.2 18.6-12 22-6.8-3.4-12-12-12-22V24.8L40 20zm-3 12h6l-3 8-3-8z"/></svg></span>'
 )
OWASP_LLM_TOP10_URL = "https://genai.owasp.org/llm-top-10/"

# HIPAA icon (medical shield ).
HIPAA_ICON = (
    '<span class="service-icon"><svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg">'
    '<rect fill="#2563EB" width="80" height="80"/>'
    '<path fill="#FFF" d="M40 15 L60 25 L60 45 C60 55 52 65 40 70 C28 65 20 55 20 45 L20 25 Z M40 30 v25 M28 42 h24"/></svg></span>'
 )
HIPAA_ICON_SMALL = (
    '<span class="service-icon" style="width: 18px; height: 18px;">'
    '<svg viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg">'
    '<rect fill="#2563EB" width="80" height="80"/>'
    '<path fill="#FFF" d="M40 15 L60 25 L60 45 C60 55 52 65 40 70 C28 65 20 55 20 45 L20 25 Z M40 30 v25 M28 42 h24"/></svg></span>'
 )
HIPAA_COMPLIANCE_URL = "https://aws.amazon.com/compliance/hipaa-compliance/"

# COMPLIANCE_STANDARDS — registry of compliance-standard sections.
COMPLIANCE_STANDARDS: List[Dict[str, str]] = [
    {
        "slug": "owasp",
        "name": "OWASP Top 10 LLM",
        "prefix": "OW-",
        "icon": OWASP_ICON,
        "icon_small": OWASP_ICON_SMALL,
        "reference_url": OWASP_LLM_TOP10_URL,
        "section_title": "OWASP Top 10 for LLM Findings",
        "scope_text": (
            "Scope: mapping-based derivation from existing BR/SM/AC/AG/FS checks "
            "plus two net-new checks for LLM07 (System Prompt Leakage ). "
            "Each finding's OWASP category (LLM01–LLM10) is encoded in the "
            "Finding_Details text. Preliminary and illustrative — validate "
            "mappings with your Security/Compliance team before using as evidence."
        ),
    },
    {
        "slug": "hipaa",
        "name": "HIPAA Compliance",
        "prefix": "HP-",
        "icon": HIPAA_ICON,
        "icon_small": HIPAA_ICON_SMALL,
        "reference_url": HIPAA_COMPLIANCE_URL,
        "section_title": "HIPAA Compliance Lens Findings",
        "scope_text": (
            "Scope: Automated security checks for Bedrock and SageMaker environments "
            "aligned with HIPAA/HITECH security and privacy controls. Focuses on "
            "encryption (CMK), network isolation, and data protection policies."
        ),
    },
]


def _escape_text(value) -> str:
    """Escape untrusted text before placing it in HTML body text."""
    return html.escape("" if value is None else str(value), quote=False)


def _escape_attr(value) -> str:
    """Escape untrusted text before placing it in an HTML attribute."""
    return html.escape("" if value is None else str(value), quote=True)


def _safe_https_url(value ) -> Optional[str]:
    """Return an escaped HTTPS URL, or None when the value is not link-safe."""
    raw = "" if value is None else str(value).strip()
    if not raw or raw == "-":
        return None
    parsed = urlparse(raw)
    if parsed.scheme != "https" or not parsed.netloc:
        return None
    return _escape_attr(raw )


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
        region = finding.get("region", finding.get("Region", ""))
        check_id = finding.get("check_id", finding.get("Check_ID", ""))
        finding_name = finding.get("finding", finding.get("Finding", ""))
        details = finding.get("details", finding.get("Finding_Details", ""))
        resolution = finding.get("resolution", finding.get("Resolution", ""))
        ref = finding.get("reference", finding.get("Reference", ""))

        safe_ref = _safe_https_url(ref )
        if safe_ref:
            ref_html = f'''<a href="{safe_ref}" target="_blank" rel="noopener noreferrer" class="reference-btn" title="View AWS Documentation"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg></a>'''
        else:
            ref_html = '<span style="color: var(--text-3);">-</span>'

        data_attrs = (
            f'data-service="{_escape_attr(service)}" data-severity="{_escape_attr(severity)}" data-status="{_escape_attr(status)}" data-account="{_escape_attr(account_id)}" data-region="{_escape_attr(region)}"'
            if include_data_attrs
            else ""
        )

        severity_display = finding.get(
            "severity", finding.get("Severity", "Informational")
        )
        status_display = finding.get("status", finding.get("Status", ""))

        row = f"""<tr {data_attrs}>
            <td><code>{_escape_text(account_id)}</code></td>
            <td><code>{_escape_text(region)}</code></td>
            <td><code>{_escape_text(check_id)}</code></td>
            <td class="finding-summary">
                <div class="col-domain">{_escape_text(finding_name)}</div>
                <details class="finding-more">
                    <summary>Details and remediation</summary>
                    <div class="finding-more-body">
                        <div><strong>Details</strong><p>{_escape_text(details)}</p></div>
                        <div><strong>Resolution</strong><p>{_escape_text(resolution)}</p></div>
                        <div><strong>Reference</strong><p>{ref_html}</p></div>
                    </div>
                </details>
            </td>
            <td><span class="severity {severity_class}">{_escape_text(severity_display)}</span></td>
            <td><span class="status {"success" if status_class == "passed" else "error" if status_class == "failed" else "warning"}">{_escape_text(status_display)}</span></td>
        </tr>"""
        rows.append(row)

    return (
        "\n".join(rows)
        if rows
        else '<tr><td colspan="6" style="text-align: center; padding: 40px; color: var(--text-3);">No findings to display</td></tr>'
    )


def generate_assessment_summary(
    service_key: str,
    total: int,
    failed: int,
    passed: int,
    na_count: int,
    scope_text: str = "",
) -> str:
    """Generate a compact assessment-area summary that filters the main table."""
    scope_html = (
        f'<p class="finding-details" style="margin-bottom: 16px;">{scope_text}</p>'
        if scope_text
        else ""
    )
    return f"""<div class="card"><div class="card-body">
                    {scope_html}
                    <div class="assessment-summary-grid">
                        <div class="metric danger"><div class="metric-label">Failed</div><div class="metric-value">{failed}</div><div class="metric-sub">Open findings</div></div>
                        <div class="metric highlight"><div class="metric-label">Passed</div><div class="metric-value">{passed}</div><div class="metric-sub">Controls met</div></div>
                        <div class="metric"><div class="metric-label">N/A</div><div class="metric-value">{na_count}</div><div class="metric-sub">Not applicable</div></div>
                        <div class="metric"><div class="metric-label">Total</div><div class="metric-value">{total}</div><div class="metric-sub">Rows in report</div></div>
                    </div>
                    <div class="assessment-actions">
                        <button class="btn btn-reset" data-filter-service="{_escape_attr(service_key)}" data-filter-status="failed">View failed findings</button>
                        <button class="btn btn-reset" data-filter-service="{_escape_attr(service_key)}" data-filter-status="">View all rows</button>
                    </div>
                </div></div>"""
