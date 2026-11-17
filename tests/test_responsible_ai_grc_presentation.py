"""Presentation gate for the Responsible AI GRC rebrand.

The rebrand's central constraint is that labels change while machine identities
do not. tests/test_legacy_contracts.py pins the machine side; this module pins
the label side and, critically, asserts that the five retired capability names
never come back.

Before the rebrand the same capability appeared under five competing visible
names across ten hardcoded sites: FinServ, Financial Services, Financial
Services Risk, Financial Services GenAI Risk, and Financial Services GenAI Risk
Findings. Exactly one canonical label is permitted now.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORT_DIR = os.path.join(
    REPO_ROOT,
    "aiml-security-assessment",
    "functions",
    "security",
    "generate_consolidated_report",
)
PROVENANCE_PATH = os.path.join(
    REPO_ROOT,
    "aiml-security-assessment",
    "functions",
    "security",
    "responsible_ai_grc_assessments",
    "provenance.json",
)

if REPORT_DIR not in sys.path:
    sys.path.insert(0, REPORT_DIR)

_spec = importlib.util.spec_from_file_location(
    "grc_presentation_report_template", os.path.join(REPORT_DIR, "report_template.py")
)
report_template = importlib.util.module_from_spec(_spec)
sys.modules["grc_presentation_report_template"] = report_template
_spec.loader.exec_module(report_template)

CANONICAL_LABEL = "Responsible AI GRC"
CANONICAL_SLUG = "responsible-ai-grc"

# Every visible capability name the rebrand retires. None may appear in output.
RETIRED_LABELS = [
    "Financial Services Risk",
    "Financial Services GenAI Risk",
    "Financial Services GenAI Risk Findings",
    "<h3>By Industry</h3>",
    ">FinServ<",
]

# ">FinServ<" above is tag-delimited, so it only catches "FinServ" appearing as
# its own HTML text node -- it cannot catch the word inside a table cell that
# also contains other text (e.g. a finding name or resolution sentence), or
# inside prose split across markup. test_bare_finserv_word_is_absent_from_rendered_text
# below closes that gap with a substring check against de-tagged text content.
# The one legitimate survivor is the source PDF's URL slug
# (".../global-FinServ-ComplianceGuide-GenAIRisks-public.pdf"), which names an
# external AWS document, not this project's retired capability name.
_ACCEPTABLE_FINSERV_SUBSTRINGS = [
    "global-FinServ-ComplianceGuide-GenAIRisks-public.pdf",
]


def _render(with_capability: bool = True) -> str:
    findings = [
        {
            "account_id": "123456789012",
            "check_id": "FS-01",
            "finding": "Example Finding",
            "details": "Example details.",
            "resolution": "Example resolution.",
            "reference": "https://example.com/doc",
            "severity": "High",
            "status": "Failed",
            "region": "us-east-1",
            "_service": CANONICAL_SLUG if with_capability else "bedrock",
        }
    ]
    slug = CANONICAL_SLUG if with_capability else "bedrock"
    return report_template.generate_html_report(
        all_findings=findings,
        service_findings={slug: findings},
        service_stats={slug: {"passed": 0, "failed": 1, "na": 0}},
        mode="single",
        account_id="123456789012",
        regions=["us-east-1"],
    )


@pytest.fixture(scope="module")
def html() -> str:
    return _render(with_capability=True)


@pytest.fixture(scope="module")
def html_without() -> str:
    return _render(with_capability=False)


# ---------------------------------------------------------------------------
# Centralized labels
# ---------------------------------------------------------------------------


def test_label_constants_are_centralized():
    """Ten label sites now resolve through these constants, not hardcoded text."""
    assert report_template.RESPONSIBLE_AI_GRC_LABEL == CANONICAL_LABEL
    assert report_template.RESPONSIBLE_AI_GRC_NAV_HEADING == "By Governance Framework"
    assert report_template.RESPONSIBLE_AI_GRC_SCOPE_LABEL == "Governance Framework"


def test_display_map_renames_the_slug_without_changing_it():
    assert report_template.RESPONSIBLE_AI_GRC_LABEL == CANONICAL_LABEL
    source = open(os.path.join(REPORT_DIR, "report_template.py")).read()
    assert "RESPONSIBLE_AI_GRC_SLUG: RESPONSIBLE_AI_GRC_LABEL" in source
    assert '"finserv": "FinServ"' not in source
    assert '"finserv": RESPONSIBLE_AI_GRC_LABEL' not in source


# ---------------------------------------------------------------------------
# Canonical label appears; retired names do not.
# ---------------------------------------------------------------------------


def test_canonical_label_renders(html):
    assert CANONICAL_LABEL in html


@pytest.mark.parametrize("retired", RETIRED_LABELS)
def test_retired_labels_do_not_render(html, retired):
    assert retired not in html


def test_bare_finserv_word_is_absent_from_rendered_text(html):
    """Case-insensitive substring check, not tag-delimited.

    ">FinServ<" in RETIRED_LABELS only matches "FinServ" as an isolated HTML
    text node. It cannot catch the word occurring inside a table cell that
    also has other text (a finding name, a resolution sentence) or split
    across markup -- exactly the shape of the 7 finding_details/resolution
    leaks this test was added to close. Strip every substring known to be an
    acceptable, non-capability-name occurrence first (currently only the
    source PDF's URL slug), then require the word to be gone from what
    remains.
    """
    remaining = html
    for acceptable in _ACCEPTABLE_FINSERV_SUBSTRINGS:
        remaining = remaining.replace(acceptable, "")
    assert "finserv" not in remaining.lower(), (
        "A literal 'FinServ' occurrence survived outside the known-acceptable "
        "source-URL substrings -- likely a leaked finding_details/resolution "
        "string or check_name. Reword it to remove the retired capability name."
    )


def test_no_financial_services_capability_label_in_report_chrome(html):
    """Canonical source guidance may name an industry; capability labels may not."""
    chrome = re.findall(
        r"<nav\b[^>]*>.*?</nav>|<option\b[^>]*>.*?</option>"
        r'|<div class="(?:metric-label|scope-[^"]+-label|section-title)"[^>]*>.*?</div>',
        html,
        re.S,
    )
    assert chrome and any(CANONICAL_LABEL in element for element in chrome)
    assert all("Financial Services" not in element for element in chrome)


def test_taxonomy_moved_out_of_by_industry(html):
    assert "<h3>By Governance Framework</h3>" in html
    assert "<h3>By Industry</h3>" not in html
    assert '<div class="scope-governance-label">Governance Framework</div>' in html
    assert '<div class="scope-industry-label">Industry</div>' not in html
    assert '<div class="scope-industry-label">' not in html


def test_capability_absent_from_the_by_service_nav(html):
    """It is a governance grouping, not a service."""
    by_service = html.split("<h3>By Service</h3>", 1)[1].split("<h3>", 1)[0]
    assert CANONICAL_LABEL not in by_service


# ---------------------------------------------------------------------------
# Machine identity. Duplicated deliberately from test_legacy_contracts.py:
# this is the pairing that makes the rebrand safe, so it is asserted in the
# same breath as the label change. Unlike an earlier, additive-only revision
# of this capability, the machine identity itself changed here -- there is no
# legacy "finserv" selector or industry-* class left to assert alongside the
# label.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "selector",
    [
        'id="responsible-ai-grc"',
        'href="#responsible-ai-grc"',
        'data-service="responsible-ai-grc"',
        'data-filter-service="responsible-ai-grc"',
        'data-scope-service="responsible-ai-grc"',
        '<option value="responsible-ai-grc">',
    ],
)
def test_selectors_use_the_new_slug(html, selector):
    assert selector in html


@pytest.mark.parametrize(
    "selector",
    [
        'id="finserv"',
        'href="#finserv"',
        'data-service="finserv"',
        'data-filter-service="finserv"',
        'data-scope-service="finserv"',
        '<option value="finserv">',
    ],
)
def test_legacy_finserv_selectors_are_retired(html, selector):
    assert selector not in html


@pytest.mark.parametrize(
    "css_class",
    [
        "governance-item",
        "governance-nav",
        "governance-chip",
        "scope-governance",
        "scope-governance-label",
    ],
)
def test_governance_css_classes_are_present(html, css_class):
    """The visible heading moved off "Industry"; the class names moved with it."""
    assert css_class in html


@pytest.mark.parametrize(
    "css_class",
    [
        "industry-item",
        "industry-nav",
        "industry-chip",
        "scope-industry",
        "scope-industry-label",
    ],
)
def test_legacy_industry_css_classes_are_retired(html, css_class):
    assert css_class not in html


# ---------------------------------------------------------------------------
# Required qualification travels with the name.
# ---------------------------------------------------------------------------


def test_scope_statement_accompanies_the_name(html):
    assert "64 automated checks" in html
    assert "do not establish regulatory compliance" in html
    assert "Regulatory framework mappings are preliminary" in html


def test_scope_statement_check_count_matches_provenance():
    """The "64 automated checks" figure in RESPONSIBLE_AI_GRC_SCOPE_STATEMENT is a
    bare string literal in report_template.py, unconnected to any other source
    of truth for the check count. provenance.json's control_count (also
    generated, and gated against staleness by test_provenance.py) is that
    source of truth. This test is the tripwire: if the check count ever
    changes, this fails loudly instead of the two silently drifting apart.
    """
    with open(PROVENANCE_PATH) as handle:
        provenance = json.load(handle)
    expected = provenance["control_count"]
    assert (
        f"{expected} automated checks"
        in report_template.RESPONSIBLE_AI_GRC_SCOPE_STATEMENT
    ), (
        f"RESPONSIBLE_AI_GRC_SCOPE_STATEMENT says a different count than "
        f"provenance.json's control_count ({expected}). Update the literal in "
        f"report_template.py to match."
    )


def test_lens_disambiguation_is_present(html):
    """Mandatory: the rename moves closer to the Lens than "FinServ" did."""
    assert "Responsible AI GRC is not the" in html
    assert "Responsible AI Lens" in html
    assert "eight focus areas" in html
    assert "does not" in html


def test_lens_is_never_claimed_as_implemented(html):
    for forbidden in (
        "implements the AWS Well-Architected Responsible AI Lens",
        "Responsible AI Lens compliant",
        "Responsible AI Lens alignment",
        "Responsible AI Lens coverage",
    ):
        assert forbidden not in html


def test_no_certification_or_completeness_claim(html):
    for forbidden in (
        "Responsible AI GRC certification",
        "Responsible AI GRC compliance",
        "Complete Responsible AI",
        "fully compliant",
    ):
        assert forbidden not in html


def test_source_shorthand_never_names_the_capability(html):
    """ "the Responsible AI GRC guide" is reserved for the AWS source document."""
    assert "Responsible AI GRC guide" not in html


# ---------------------------------------------------------------------------
# Absence behavior is unchanged.
# ---------------------------------------------------------------------------


def test_capability_chrome_omitted_when_no_findings(html_without):
    assert CANONICAL_LABEL not in html_without
    assert 'id="responsible-ai-grc"' not in html_without
    assert "<h3>By Governance Framework</h3>" not in html_without
    assert 'id="bedrock"' in html_without
