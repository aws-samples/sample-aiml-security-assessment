#!/usr/bin/env python3
"""
Build the AI/ML Security Assessment report for account 676206921018, formatted
BYTE-FOR-BYTE like the official resco template, with OWASP added as a single
seamless additive section.

Hard regression rules (to avoid any back-and-forth with reviewers):
  - <head>, CSS and JS are taken VERBATIM from the official sample report
    (sample-reports/security_assessment_single_account.html).
  - Element IDs, filter-bar markup, sortable headers, per-service sections,
    Overview metrics, Risk Distribution, Methodology and the page footer are
    identical in structure to the official report.
  - Existing sections contain ONLY the native service findings (BR/SM/AC), so
    their counts match what the tool produces today.
  - OWASP is added as exactly ONE new section (#compliance): a single OWASP
    Top 10 table (Agasthi's "combine into one table" ask), placed under a new
    "Compliance" nav item. OWASP is NOT treated as a service.
  - The only JS delta is ONE extra createServiceFilter() call for the OWASP
    table, reusing the official generic filter function unchanged.
"""

import csv
import html
import json
import os

ACCOUNT_ID = "676206921018"
REGION = "us-east-1"
GENERATED_AT = "April 18, 2026"
GENERATED_ISO = "2026-04-18T23:30:15.848846"
GITHUB_URL = "https://github.com/aws-samples/sample-aiml-security-assessment"

OFFICIAL = "/Users/biswasrp/resco-aiml-assessment/sample-resco-aiml-assessment/sample-reports/security_assessment_single_account.html"
SERVICE_ICONS = json.load(open("/tmp/service_icons.json"))

# Official CSS + JS, verbatim
_official_html = open(OFFICIAL).read()
CSS = _official_html[_official_html.index("<style>") + 7:_official_html.index("</style>")].strip()
_js_start = _official_html.rindex("<script>") + len("<script>")
_js_end = _official_html.rindex("</script>")
OFFICIAL_JS = _official_html[_js_start:_js_end].rstrip()

DOCS_ICON = ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'
             '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>'
             '<polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>')

# -----------------------------------------------------------------------------
# Load real service findings
# -----------------------------------------------------------------------------

def load_findings(path, service):
    out = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            ref = (r.get("Reference") or "").strip()
            ref = ref.split()[0] if ref else ""
            out.append({"check_id": r["Check_ID"], "service": service,
                        "finding": r["Finding"], "details": r["Finding_Details"],
                        "resolution": r["Resolution"], "reference": ref,
                        "severity": r["Severity"], "status": r["Status"]})
    return out


BEDROCK = load_findings("/tmp/bedrock_report.csv", "bedrock")
SAGEMAKER = load_findings("/tmp/sagemaker_report.csv", "sagemaker")
AGENTCORE = load_findings("/tmp/agentcore_report.csv", "agentcore")
SERVICE_FINDINGS = BEDROCK + SAGEMAKER + AGENTCORE   # existing sections use ONLY these

# -----------------------------------------------------------------------------
# OWASP Top 10 mapping (single combined table — the one additive section)
# -----------------------------------------------------------------------------

OWASP_TOP10 = [
    {"id": "LLM01", "name": "Prompt Injection",
     "doc": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
     "checks": ["BR-05", "BR-13", "OW-01", "OW-02"]},
    {"id": "LLM02", "name": "Sensitive Information Disclosure",
     "doc": "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/",
     "checks": ["BR-04", "BR-06", "BR-09", "BR-12", "SM-03", "AC-07", "OW-03", "OW-04", "OW-17"]},
    {"id": "LLM03", "name": "Supply Chain",
     "doc": "https://genai.owasp.org/llmrisk/llm032025-supply-chain/",
     "checks": ["BR-03", "AC-05", "SM-14", "OW-05", "OW-06", "OW-16"]},
    {"id": "LLM04", "name": "Data and Model Poisoning",
     "doc": "https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/",
     "checks": ["SM-05", "SM-07", "SM-22", "OW-07"]},
    {"id": "LLM05", "name": "Improper Output Handling",
     "doc": "https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/",
     "checks": ["OW-08"]},
    {"id": "LLM06", "name": "Excessive Agency",
     "doc": "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
     "checks": ["BR-01", "BR-08", "BR-10", "AC-02", "AC-10", "OW-09", "OW-10", "OW-18"]},
    {"id": "LLM07", "name": "System Prompt Leakage",
     "doc": "https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/",
     "checks": ["BR-07", "OW-11"]},
    {"id": "LLM08", "name": "Vector and Embedding Weaknesses",
     "doc": "https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/",
     "checks": ["BR-09", "OW-12", "OW-13"]},
    {"id": "LLM09", "name": "Misinformation",
     "doc": "https://genai.owasp.org/llmrisk/llm092025-misinformation/",
     "checks": ["SM-07", "SM-23", "OW-14"]},
    {"id": "LLM10", "name": "Unbounded Consumption",
     "doc": "https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/",
     "checks": ["OW-15"]},
]

# Live OWASP-overlay results (account 676206921018, 2026-04-18) used only to
# decide each category's status. Only failures observed: OW-04, OW-15, OW-16.
OW_FAILED = {"OW-04", "OW-15", "OW-16"}
OW_PASSED = {"OW-11"}

STATUS_BY_CHECK = {}
for f in SERVICE_FINDINGS:
    STATUS_BY_CHECK.setdefault(f["check_id"], []).append(f["status"])


def category_status(checks):
    statuses = []
    for c in checks:
        if c.startswith("OW-"):
            if c in OW_FAILED:
                statuses.append("Failed")
            elif c in OW_PASSED:
                statuses.append("Passed")
            else:
                statuses.append("N/A")
        else:
            statuses += STATUS_BY_CHECK.get(c, [])
    failed = sum(1 for s in statuses if s.lower() == "failed")
    passed = sum(1 for s in statuses if s.lower() == "passed")
    if failed:
        return "Non-Compliant", failed, passed, len(statuses)
    if passed:
        return "Compliant", failed, passed, len(statuses)
    return "N/A", failed, passed, len(statuses)

# -----------------------------------------------------------------------------
# Render helpers (match official markup exactly)
# -----------------------------------------------------------------------------

def esc(s):
    return html.escape(str(s or ""))


def sev_class(sev):
    s = (sev or "").lower()
    return {"high": "severity high", "medium": "severity medium",
            "low": "severity low"}.get(s, "severity na")


def status_class(status):
    s = (status or "").lower()
    if s == "failed":
        return "status error"
    if s == "passed":
        return "status success"
    return "status warning"


def compliance_status_class(status):
    s = (status or "").lower()
    if s == "non-compliant":
        return "status error"
    if s == "compliant":
        return "status success"
    return "status warning"


def docs_cell(url, title="View AWS Documentation"):
    if not url:
        return '<td class="reference-cell"></td>'
    return (f'<td class="reference-cell"><a href="{esc(url)}" target="_blank" '
            f'class="reference-btn" title="{esc(title)}">{DOCS_ICON}</a></td>')


def finding_row(f):
    return (f'<tr data-service="{f["service"]}" data-severity="{f["severity"].lower()}" '
            f'data-status="{f["status"].lower()}" data-account="{ACCOUNT_ID}">'
            f'<td><code>{ACCOUNT_ID}</code></td>'
            f'<td><code>{esc(f["check_id"])}</code></td>'
            f'<td class="col-domain">{esc(f["finding"])}</td>'
            f'<td class="finding-details">{esc(f["details"])}</td>'
            f'<td class="resolution-text">{esc(f["resolution"])}</td>'
            f'{docs_cell(f["reference"])}'
            f'<td><span class="{sev_class(f["severity"])}">{esc(f["severity"])}</span></td>'
            f'<td><span class="{status_class(f["status"])}">{esc(f["status"])}</span></td>'
            f'</tr>')


RESET_SVG = ('<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
             'stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"></path>'
             '<path d="M3 3v5h5"></path></svg>')

# Metrics (service findings ONLY — identical semantics to official)
distinct_checks = len(set(f["check_id"] for f in SERVICE_FINDINGS))
total_findings = len(SERVICE_FINDINGS)


def sev_counts(sev):
    rows = [f for f in SERVICE_FINDINGS if f["severity"].lower() == sev]
    return sum(1 for f in rows if f["status"].lower() == "passed"), len(rows)


high_p, high_t = sev_counts("high")
med_p, med_t = sev_counts("medium")
low_p, low_t = sev_counts("low")
actionable = high_t + med_t + low_t


def pct(p, t):
    return f"{(100*p/t):.1f}" if t else "0.0"


# Priority Recommendations (failed findings grouped by check, High first)
from collections import OrderedDict
prio = OrderedDict()
for f in sorted(SERVICE_FINDINGS, key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x["severity"].lower(), 3)):
    if f["status"].lower() != "failed":
        continue
    key = (f["finding"], f["service"], f["severity"])
    prio[key] = prio.get(key, 0) + 1
prio_html = ""
for (finding, service, severity), count in list(prio.items())[:6]:
    cls = "critical" if severity.lower() == "high" else "warning"
    prio_html += (f'<div class="alert-item {cls}">\n            <div class="alert-count">{count}</div>\n'
                  f'            <div class="alert-info">\n                <div class="alert-domain">{esc(finding)}</div>\n'
                  f'                <div class="alert-category">{service.title()}</div>\n            </div>\n        </div>')


def svc_card(name, rows):
    failed = sum(1 for f in rows if f["status"].lower() == "failed")
    passed = sum(1 for f in rows if f["status"].lower() == "passed")
    return (f'<div class="metric"><div class="metric-label">{name}</div>'
            f'<div class="metric-value">{len(rows)}</div>'
            f'<div class="metric-sub">{failed} Failed · {passed} Passed</div></div>')


# OWASP scorecard rows + counts
owasp_compliant = owasp_noncompliant = owasp_na = 0
owasp_rows = ""
for c in OWASP_TOP10:
    status, failed, passed, total = category_status(c["checks"])
    if status == "Compliant":
        owasp_compliant += 1
    elif status == "Non-Compliant":
        owasp_noncompliant += 1
    else:
        owasp_na += 1
    chips = " ".join(f'<code>{x}</code>' for x in c["checks"])
    sev_dot = "n/a" if status == "N/A" else ("non-compliant" if status == "Non-Compliant" else "compliant")
    owasp_rows += (
        f'<tr data-severity="" data-status="{sev_dot}" data-account="{ACCOUNT_ID}">'
        f'<td><code>{c["id"]}</code></td>'
        f'<td class="col-domain">{esc(c["name"])}</td>'
        f'<td class="finding-details">{chips}</td>'
        f'<td><span class="{compliance_status_class(status)}">{status}</span></td>'
        f'<td class="finding-details">{failed} failed · {passed} passed · {total} mapped</td>'
        f'{docs_cell(c["doc"], "OWASP " + c["id"])}'
        f'</tr>')

# -----------------------------------------------------------------------------
# Section builders (official markup)
# -----------------------------------------------------------------------------

def main_filter_bar():
    return ('                <div class="filter-bar">\n'
            '                    <div class="filter-group"><label>Search</label><input type="text" placeholder="Search findings..." id="searchInput"></div>\n'
            '                    <div class="filter-group"><label>Service</label><select id="serviceFilter"><option value="">All Services</option><option value="bedrock">Bedrock</option><option value="sagemaker">SageMaker</option><option value="agentcore">AgentCore</option></select></div>\n'
            '                    <div class="filter-group"><label>Severity</label><select id="severityFilter"><option value="">All Severities</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="informational">Informational</option></select></div>\n'
            '                    <div class="filter-group"><label>Status</label><select id="statusFilter"><option value="">All Statuses</option><option value="failed">Failed</option><option value="passed">Passed</option><option value="n/a">N/A</option></select></div>\n'
            f'                    <button class="btn btn-reset" id="resetFilters">{RESET_SVG}Reset</button>\n'
            '                </div>')


def service_filter_bar(prefix):
    return (f'                <div class="filter-bar">\n'
            f'                    <div class="filter-group"><label>Search</label><input type="text" placeholder="Search findings..." id="{prefix}SearchInput"></div>\n'
            f'                    <div class="filter-group"><label>Severity</label><select id="{prefix}SeverityFilter"><option value="">All Severities</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="informational">Informational</option></select></div>\n'
            f'                    <div class="filter-group"><label>Status</label><select id="{prefix}StatusFilter"><option value="">All Statuses</option><option value="failed">Failed</option><option value="passed">Passed</option><option value="n/a">N/A</option></select></div>\n'
            f'                    <button class="btn btn-reset" id="{prefix}ResetFilters">{RESET_SVG}Reset</button>\n'
            f'                </div>')


def service_section(sec_id, title, icon, prefix, rows):
    body = "\n".join(finding_row(f) for f in rows)
    return (f'            <section id="{sec_id}" class="section">\n'
            f'                <div class="section-title"><span class="service-icon">{icon}</span>{title}</div>\n'
            f'{service_filter_bar(prefix)}\n'
            f'                <div class="card"><div class="table-wrap"><table id="{prefix}Table"><thead><tr><th>Account ID</th><th>Check ID</th><th>Finding</th><th>Details</th><th>Resolution</th><th>Reference</th><th>Severity</th><th>Status</th></tr></thead><tbody>\n'
            f'{body}\n                </tbody></table></div></div>\n'
            f'            </section>')


main_rows = "\n".join(finding_row(f) for f in SERVICE_FINDINGS)
overall_p = high_p + med_p + low_p
overall_pct = pct(overall_p, actionable)


def passrate(label, sev, color):
    p, t = sev_counts(sev)
    return (f'<div class="metric"><div class="metric-label">{label}</div>'
            f'<div class="metric-value">{pct(p,t)}%</div>'
            f'<div class="metric-sub">{p} of {t} checks passed</div>'
            f'<div style="margin-top: 8px; height: 4px; background: var(--surface-2); border-radius: 2px; overflow: hidden;">'
            f'<div style="width: {pct(p,t)}%; height: 100%; background: var(--{color});"></div></div></div>')


# -----------------------------------------------------------------------------
# Assemble
# -----------------------------------------------------------------------------

HTML = f'''<!DOCTYPE html>
<html lang="en"><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI/ML Security Assessment Report</title>
    <style>
{CSS}
    </style>
</head>
<body>
    <div class="layout">
        <aside class="sidebar">
            <div class="sidebar-header">
                <h1>AI/ML Security</h1>
                <p>Assessment Report</p>
            </div>
            <button class="theme-toggle" id="themeToggle" aria-label="Toggle dark mode">
                <svg class="moon-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M6 .278a.768.768 0 0 1 .08.858 7.208 7.208 0 0 0-.878 3.46c0 4.021 3.278 7.277 7.318 7.277.527 0 1.04-.055 1.533-.16a.787.787 0 0 1 .81.316.733.733 0 0 1-.031.893A8.349 8.349 0 0 1 8.344 16C3.734 16 0 12.286 0 7.71 0 4.266 2.114 1.312 5.124.06A.752.752 0 0 1 6 .278z"></path></svg>
                <svg class="sun-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M8 11a3 3 0 1 1 0-6 3 3 0 0 1 0 6zm0 1a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM8 0a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-1 0v-2A.5.5 0 0 1 8 0zm0 13a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-1 0v-2A.5.5 0 0 1 8 13zm8-5a.5.5 0 0 1-.5.5h-2a.5.5 0 0 1 0-1h2a.5.5 0 0 1 .5.5zM3 8a.5.5 0 0 1-.5.5h-2a.5.5 0 0 1 0-1h2A.5.5 0 0 1 3 8zm10.657-5.657a.5.5 0 0 1 0 .707l-1.414 1.415a.5.5 0 1 1-.707-.708l1.414-1.414a.5.5 0 0 1 .707 0zm-9.193 9.193a.5.5 0 0 1 0 .707L3.05 13.657a.5.5 0 0 1-.707-.707l1.414-1.414a.5.5 0 0 1 .707 0zm9.193 2.121a.5.5 0 0 1-.707 0l-1.414-1.414a.5.5 0 0 1 .707-.707l1.414 1.414a.5.5 0 0 1 0 .707zM4.464 4.465a.5.5 0 0 1-.707 0L2.343 3.05a.5.5 0 1 1 .707-.707l1.414 1.414a.5.5 0 0 1 0 .708z"></path></svg>
                <span class="theme-label">Dark Mode</span>
            </button>
            <nav class="nav-section">
                <h3>Navigation</h3>
                <a href="#overview" class="nav-item active"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect></svg>Overview</a>
                <a href="#findings" class="nav-item"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>Security Findings<span class="count">{total_findings}</span></a>
                <a href="#risk" class="nav-item"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>Risk Distribution</a>
                <a href="#compliance" class="nav-item"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 11l3 3L22 4"></path><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path></svg>Compliance Dashboard</a>
                <a href="#methodology" class="nav-item"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>Methodology</a>
            </nav>
            <nav class="nav-section">
                <h3>By Service</h3>
                <a href="#bedrock" class="nav-item"><span class="service-icon">{SERVICE_ICONS["bedrock"]}</span>Bedrock<span class="count">{len(BEDROCK)}</span></a>
                <a href="#sagemaker" class="nav-item"><span class="service-icon">{SERVICE_ICONS["sagemaker"]}</span>SageMaker<span class="count">{len(SAGEMAKER)}</span></a>
                <a href="#agentcore" class="nav-item"><span class="service-icon">{SERVICE_ICONS["agentcore"]}</span>AgentCore<span class="count">{len(AGENTCORE)}</span></a>
            </nav>
            <nav class="nav-section">
                <h3>Compliance Frameworks</h3>
                <a href="#compliance" class="nav-item"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M12 8v4"></path><circle cx="12" cy="16" r="1"></circle></svg>OWASP Top 10 LLM<span class="count">{len(OWASP_TOP10)}</span></a>
                <a href="#compliance" class="nav-item" style="opacity:0.5;"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"></rect><path d="M3 9h18"></path><path d="M9 21V9"></path></svg>NIST AI RMF 1.0<span class="count">—</span></a>
                <a href="#compliance" class="nav-item" style="opacity:0.5;"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><path d="M2 12h20"></path></svg>MITRE ATLAS<span class="count">—</span></a>
                <a href="#compliance" class="nav-item" style="opacity:0.5;"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 14c1.49-1.46 3-3.21 3-5.5A5.5 5.5 0 0 0 16.5 3c-1.76 0-3 .5-4.5 2-1.5-1.5-2.74-2-4.5-2A5.5 5.5 0 0 0 2 8.5c0 2.3 1.5 4.05 3 5.5l7 7Z"></path></svg>HIPAA<span class="count">—</span></a>
            </nav>
            <div class="sidebar-footer">
                <p>Generated: {GENERATED_AT}</p>
                <p>Account: {ACCOUNT_ID}</p>
                <p style="margin-top: 8px;"><a href="{GITHUB_URL}">GitHub Repository</a></p>
            </div>
        </aside>
        <main class="main">
            <section id="overview" class="section">
                <div class="page-header">
                    <h2>Security Assessment Overview</h2>
                    <div class="page-header-meta">
                        <span><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>{GENERATED_ISO}</span>
                        <span><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>Account: {ACCOUNT_ID}</span>
                    </div>
                </div>
                <div class="metrics">
                    <div class="metric"><div class="metric-label">Security Checks</div><div class="metric-value">{distinct_checks}</div><div class="metric-sub">Evaluated per account</div></div>
                    <div class="metric"><div class="metric-label">Total Findings</div><div class="metric-value">{total_findings}</div><div class="metric-sub">Across 1 account</div></div>
                    <div class="metric danger"><div class="metric-label">Actionable Findings</div><div class="metric-value">{actionable}</div><div class="metric-sub">High, Medium, and Low severity</div></div>
                    <div class="metric danger"><div class="metric-label">High Severity</div><div class="metric-value">{high_p}/{high_t}</div><div class="metric-sub">{pct(high_p,high_t)}% passed · Immediate action required</div></div>
                    <div class="metric warning"><div class="metric-label">Medium Severity</div><div class="metric-value">{med_p}/{med_t}</div><div class="metric-sub">{pct(med_p,med_t)}% passed · Should be addressed</div></div>
                    <div class="metric highlight"><div class="metric-label">Low Severity</div><div class="metric-value">{low_p}/{low_t}</div><div class="metric-sub">{pct(low_p,low_t)}% passed · Best practices</div></div>
                </div>
                <div class="card"><div class="card-header"><h3>Priority Recommendations</h3></div><div class="card-body"><div class="alerts">{prio_html}</div></div></div>
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
                <div class="section-title"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>All Security Findings</div>
{main_filter_bar()}
                <div class="card"><div class="table-wrap"><table id="findingsTable"><thead><tr><th class="sortable" data-sort="account">Account ID</th><th class="sortable" data-sort="checkId">Check ID</th><th class="sortable" data-sort="finding">Finding</th><th>Details</th><th>Resolution</th><th>Reference</th><th class="sortable asc" data-sort="severity">Severity</th><th class="sortable" data-sort="status">Status</th></tr></thead><tbody>
{main_rows}
                </tbody></table></div></div>
            </section>
            <section id="compliance" class="section">
                <div class="section-title"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 11l3 3L22 4"></path><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path></svg>Compliance — OWASP Top 10 for LLM Applications 2025</div>
                <div class="metrics" style="grid-template-columns: repeat(4, 1fr);">
                    <div class="metric"><div class="metric-label">OWASP Categories</div><div class="metric-value">{len(OWASP_TOP10)}</div><div class="metric-sub">LLM01–LLM10 evaluated</div></div>
                    <div class="metric highlight"><div class="metric-label">Compliant</div><div class="metric-value">{owasp_compliant}</div><div class="metric-sub">All mapped checks passed</div></div>
                    <div class="metric danger"><div class="metric-label">Non-Compliant</div><div class="metric-value">{owasp_noncompliant}</div><div class="metric-sub">At least one mapped check failed</div></div>
                    <div class="metric"><div class="metric-label">Not Applicable</div><div class="metric-value">{owasp_na}</div><div class="metric-sub">No resources to assess</div></div>
                </div>
                <div class="filter-bar">
                    <div class="filter-group"><label>Search</label><input type="text" placeholder="Search categories..." id="owaspSearchInput"></div>
                    <div class="filter-group"><label>Status</label><select id="owaspStatusFilter"><option value="">All Statuses</option><option value="compliant">Compliant</option><option value="non-compliant">Non-Compliant</option><option value="n/a">N/A</option></select></div>
                    <button class="btn btn-reset" id="owaspResetFilters">{RESET_SVG}Reset</button>
                </div>
                <div class="card"><div class="table-wrap"><table id="owaspTable"><thead><tr><th>ID</th><th>Vulnerability</th><th>Contributing Checks (BR-/SM-/AC- &amp; OW-)</th><th>Status</th><th>Coverage</th><th>Reference</th></tr></thead><tbody>
{owasp_rows}
                </tbody></table></div></div>
            </section>
            <section id="risk" class="section">
                <div class="section-title"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>Risk Distribution</div>
                <h4 style="font-size: 14px; font-weight: 600; color: var(--text-2); margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.5px;">Pass Rate by Severity</h4>
                <div class="metrics" style="margin-bottom: 32px;">
                    {passrate("HIGH", "high", "danger")}
                    {passrate("MEDIUM", "medium", "warning")}
                    {passrate("LOW", "low", "accent")}
                    <div class="metric"><div class="metric-label">Overall</div><div class="metric-value">{overall_pct}%</div><div class="metric-sub">{overall_p} of {actionable} actionable checks passed</div><div style="margin-top: 8px; height: 4px; background: var(--surface-2); border-radius: 2px; overflow: hidden;"><div style="width: {overall_pct}%; height: 100%; background: var(--text-3);"></div></div></div>
                </div>
                <h4 style="font-size: 14px; font-weight: 600; color: var(--text-2); margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.5px;">Findings by Service</h4>
                <div class="metrics">
                    {svc_card("Bedrock", BEDROCK)}
                    {svc_card("SageMaker", SAGEMAKER)}
                    {svc_card("AgentCore", AGENTCORE)}
                </div>
            </section>
{service_section("bedrock", "Amazon Bedrock Findings", SERVICE_ICONS["bedrock"], "bedrock", BEDROCK)}
{service_section("sagemaker", "Amazon SageMaker Findings", SERVICE_ICONS["sagemaker"], "sagemaker", SAGEMAKER)}
{service_section("agentcore", "Amazon Bedrock AgentCore Findings", SERVICE_ICONS["agentcore"], "agentcore", AGENTCORE)}
            <section id="methodology" class="section">
                <div class="section-title"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>Assessment Methodology</div>
                <div class="card"><div class="card-header"><h3>Severity Levels &amp; Status Values</h3></div><div class="card-body" style="padding: 0;">
                    <table style="min-width: 100%; table-layout: fixed;">
                        <thead><tr><th style="width: 12%;">Severity</th><th style="width: 30%;">Meaning</th><th style="width: 12%;">Status</th><th style="width: 46%;">Meaning</th></tr></thead>
                        <tbody>
                            <tr><td style="text-align:center;"><span class="severity high">High</span></td><td class="finding-details">Direct security risk</td><td style="text-align:center;"><span class="status error">Failed</span></td><td class="finding-details">Remediation needed</td></tr>
                            <tr><td style="text-align:center;"><span class="severity medium">Medium</span></td><td class="finding-details">Defense-in-depth gap</td><td style="text-align:center;"><span class="status success">Passed</span></td><td class="finding-details">Meets requirements</td></tr>
                            <tr><td style="text-align:center;"><span class="severity low">Low</span></td><td class="finding-details">Best practice</td><td style="text-align:center;"><span class="status warning">N/A</span></td><td class="finding-details">Not applicable</td></tr>
                            <tr><td style="text-align:center;"><span class="severity na">Informational</span></td><td class="finding-details">No action required</td><td></td><td></td></tr>
                        </tbody>
                    </table>
                </div></div>
                <div class="card"><div class="card-header"><h3>Assessment Scope</h3></div><div class="card-body">
                    <p class="finding-details">Amazon Bedrock · Amazon SageMaker · Amazon Bedrock AgentCore. The Compliance section maps these service checks plus 18 OWASP checks (OW-01–OW-18) onto the OWASP Top 10 for LLM Applications (2025). Based on the AWS Well-Architected Framework (Generative AI Lens) and service-specific security documentation.</p>
                </div></div>
            </section>
        </main>
    </div>
    <div class="page-footer">Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. Licensed under MIT-0. This report is provided as-is for informational purposes only and does not constitute professional security advice, compliance certification, or audit evidence. You are responsible for validating findings and determining applicability to your environment.</div>
    <script>
{OFFICIAL_JS}
        // --- OWASP compliance section: reuse the official generic filter, no other changes ---
        createServiceFilter('owaspTable', 'owaspSearchInput', null, null, 'owaspStatusFilter', 'owaspResetFilters');
    </script>
</body>
</html>
'''

OUT = "/Users/biswasrp/resco-aiml-assessment/security_assessment_owasp_676206921018.html"
open(OUT, "w").write(HTML)
print(f"Wrote {OUT} ({os.path.getsize(OUT)//1024} KB)")
print(f"Service checks (distinct): {distinct_checks} | Service findings: {total_findings}")
print(f"Bedrock={len(BEDROCK)} SageMaker={len(SAGEMAKER)} AgentCore={len(AGENTCORE)}")
print(f"High {high_p}/{high_t} · Medium {med_p}/{med_t} · Low {low_p}/{low_t} · Actionable {actionable}")
print(f"OWASP Top10: {owasp_compliant} compliant, {owasp_noncompliant} non-compliant, {owasp_na} N/A")
