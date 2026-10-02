"""Test that report_template.generate_html_report renders the HIPAA
compliance-standard section when the "hipaa" service key has findings.

Mirrors test_report_template_owasp.py structure so routing/stats behavior is
comparable between the two optional compliance standards.
"""

import importlib.util
import os
import sys

_report_dir = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "aiml-security-assessment/functions/security/generate_consolidated_report",
    )
)
if _report_dir not in sys.path:
    sys.path.insert(0, _report_dir)

_spec = importlib.util.spec_from_file_location(
    "report_template_mod_hipaa", os.path.join(_report_dir, "report_template.py")
)
report_template = importlib.util.module_from_spec(_spec)
sys.modules["report_template_mod_hipaa"] = report_template
_spec.loader.exec_module(report_template)


def _base_kwargs():
    """Minimum valid inputs for generate_html_report.

    Note: service_findings must include "hipaa" alongside owasp because the
    renderer unions COMPLIANCE_STANDARDS.slug entries. We include both here so
    absence/presence assertions only vary by the individual test.
    """
    return {
        "all_findings": [],
        "service_findings": {
            "bedrock": [],
            "sagemaker": [],
            "agentcore": [],
            "agent_registry": [],
            "agentic": [],
            "responsible-ai-grc": [],
            "owasp": [],
            "hipaa": [],
        },
        "service_stats": {
            "bedrock": {"passed": 0, "failed": 0, "na": 0},
            "sagemaker": {"passed": 0, "failed": 0, "na": 0},
            "agentcore": {"passed": 0, "failed": 0, "na": 0},
            "agent_registry": {"passed": 0, "failed": 0, "na": 0},
            "agentic": {"passed": 0, "failed": 0, "na": 0},
            "responsible-ai-grc": {"passed": 0, "failed": 0, "na": 0},
            "owasp": {"passed": 0, "failed": 0, "na": 0},
            "hipaa": {"passed": 0, "failed": 0, "na": 0},
        },
        "mode": "single",
        "account_id": "111122223333",
        "timestamp": "January 1, 2026 00:00:00 UTC",
        "regions": ["us-east-1"],
    }


def _hipaa_finding(check_id, status="Passed", severity="Informational"):
    return {
        "Check_ID": check_id,
        "Finding": f"{check_id} test finding",
        "Finding_Details": "finding details here",
        "Resolution": "remediation steps",
        "Reference": "https://aws.amazon.com/compliance/hipaa-compliance/",
        "Severity": severity,
        "Status": status,
        "Region": "us-east-1",
        "_service": "hipaa",
        "Compliance_Frameworks": "45 CFR 164.312(a)(2)(iv) | HITECH § 13401",
    }


class TestHIPAARegistryPresence:
    """Sanity-check COMPLIANCE_STANDARDS data-driven registration for HP-*."""

    def test_hipaa_in_compliance_standards_registry(self):
        slugs = {s["slug"] for s in report_template.COMPLIANCE_STANDARDS}
        assert "hipaa" in slugs, "HIPAA must be registered in COMPLIANCE_STANDARDS"

    def test_hipaa_prefix_registered_as_hp_dash(self):
        hipaa = next(
            s for s in report_template.COMPLIANCE_STANDARDS if s["slug"] == "hipaa"
        )
        assert hipaa["prefix"] == "HP-", (
            "HIPAA prefix must be HP- to route HP-01..HP-07 rows"
        )

    def test_hipaa_scope_text_contains_required_non_certification_disclaimer(self):
        hipaa = next(
            s for s in report_template.COMPLIANCE_STANDARDS if s["slug"] == "hipaa"
        )
        text = hipaa["scope_text"]
        # Constraint 8: never claim certification / audit / risk analysis
        assert "NOT" in text or "do NOT" in text or "does NOT" in text
        assert "certification" in text.lower() or "audit" in text.lower()
        assert "164.308" in text or "Risk Analysis" in text


class TestHIPAASectionRendering:
    def test_no_hipaa_findings_hides_hipaa_section_id(self):
        html = report_template.generate_html_report(**_base_kwargs())
        assert 'id="hipaa"' not in html
        assert "HIPAA/HITECH-Aligned Configuration Findings" not in html

    def test_with_hipaa_findings_renders_hipaa_ui_elements(self):
        kwargs = _base_kwargs()
        f1 = _hipaa_finding("HP-01", status="Failed", severity="High")
        f2 = _hipaa_finding("HP-07", status="Passed", severity="Informational")
        kwargs["all_findings"] = [f1, f2]
        kwargs["service_findings"]["hipaa"] = [f1, f2]
        kwargs["service_stats"]["hipaa"] = {"passed": 1, "failed": 1, "na": 0}

        html = report_template.generate_html_report(**kwargs)

        # Section anchor + registry section_title
        assert 'id="hipaa"' in html, "Missing section id=hipaa"
        assert "HIPAA/HITECH-Aligned Configuration Findings" in html, (
            "Missing HIPAA section_title render"
        )
        # Sidebar compliance-nav appears whenever any compliance slug has rows
        assert 'class="nav-section compliance-nav"' in html
        # Filter value slug
        assert 'value="hipaa"' in html
        # 45 CFR citation must appear from scope_text (rendered under the
        # compliance-standard header)
        assert "45 CFR" in html

    def test_zero_hipaa_rows_but_service_present_empty_still_hides_section(self):
        """Match OWASP behavior: section only renders when rows exist."""
        kwargs = _base_kwargs()
        kwargs["service_findings"]["hipaa"] = []
        html = report_template.generate_html_report(**kwargs)
        assert 'id="hipaa"' not in html
        assert "HP-" not in html

    def test_hipaa_scope_disclaimer_present_in_rendered_scope_text(self):
        """The required non-certification scope disclaimer MUST be user-visible
        when HIPAA is rendered; it should appear verbatim near the HIPAA
        section scope heading."""
        kwargs = _base_kwargs()
        f = _hipaa_finding("HP-03", status="Failed", severity="Medium")
        kwargs["all_findings"] = [f]
        kwargs["service_findings"]["hipaa"] = [f]
        kwargs["service_stats"]["hipaa"] = {"passed": 0, "failed": 1, "na": 0}

        html = report_template.generate_html_report(**kwargs)

        lower_html = html.lower()
        assert "automated configuration" in lower_html, (
            "Scope must state these are automated configuration checks"
        )
