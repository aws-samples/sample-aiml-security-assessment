"""The committed sample reports hold no values from the source account.

The samples come from real runs and are cleaned in place by
sample-reports/scripts/capture_screenshots.py --anonymize-only. These tests
check the result, and the patterns the cleaning relies on.
"""

import hashlib
import importlib.util
import json
import re
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path

import pytest

from assessment_history.compare import compare_runs
from assessment_history.models import Finding, MatchRule, Run
from tests.assessment_history_helpers import assert_invariants

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLES = REPO_ROOT / "sample-reports"
SCRIPTS = SAMPLES / "scripts"
MAIN_REPORTS = (
    "security_assessment_single_account.html",
    "security_assessment_multi_account.html",
)
CHANGES_PAGE = "security_assessment_changes.html"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look the module up by name
    spec.loader.exec_module(module)
    return module


patterns = _load("sample_report_patterns", SCRIPTS / "anonymize_patterns.py")
capture = _load("sample_report_capture", SCRIPTS / "capture_screenshots.py")


@pytest.mark.parametrize("report_name", (*MAIN_REPORTS, CHANGES_PAGE))
def test_samples_are_anonymized_with_placeholder_account_ids(report_name):
    report = (SAMPLES / report_name).read_text(encoding="utf-8")

    assert capture.ANONYMIZED_MARKER in report
    assert capture.ANONYMIZED_NAMES_MARKER in report
    unexpected_ids = set(re.findall(r"(?<!\d)\d{12}(?!\d)", report)) - set(
        capture.ANONYMIZED_ACCOUNT_IDS
    )
    assert not unexpected_ids, f"{len(unexpected_ids)} unrecognized account IDs"
    assert ":root {" in report  # the page's CSS is intact


@pytest.mark.parametrize("report_name", MAIN_REPORTS)
def test_bedrock_na_rows_are_informational(report_name):
    report = (SAMPLES / report_name).read_text(encoding="utf-8")
    bedrock_na = [
        row
        for row in patterns.parse_report(report)
        if row.area == "bedrock" and row.status == "N/A"
    ]
    assert bedrock_na
    assert all(row.severity == "Informational" for row in bedrock_na)


def test_changes_page_links_to_the_sample_files():
    page = (SAMPLES / CHANGES_PAGE).read_text(encoding="utf-8")
    links = set(re.findall(r'href="(security_assessment_[^"]*)"', page))
    assert links
    assert all((SAMPLES / link).is_file() for link in links), links


def test_full_size_single_account_sample_compared_with_itself_has_no_changes():
    report = (SAMPLES / MAIN_REPORTS[0]).read_text(encoding="utf-8")
    module_by_prefix = {
        "BR": "bedrock",
        "SM": "sagemaker",
        "AC": "agentcore",
        "AR": "agent-registry",
        "FS": "responsible-ai-grc",
        "OW": "owasp",
    }
    findings = tuple(
        Finding(
            account_id=row.account_id,
            module=module_by_prefix[row.check_id.split("-", 1)[0]],
            area=row.area,
            region=row.region,
            check_id=row.check_id,
            finding=row.finding,
            details=row.details,
            severity=row.severity,
            status=row.status,
            resolution=row.resolution,
            reference=row.reference,
        )
        for row in patterns.parse_report(report)
        if row.area != "agentic"
    )
    assert len(findings) > 500
    previous = Run(
        account_id=findings[0].account_id,
        execution_id="sample-previous",
        findings=findings,
        modules=frozenset(finding.module for finding in findings),
    )
    current = replace(previous, execution_id="sample-current")

    comparison = compare_runs(previous, current)

    assert not comparison.has_changes
    assert {row.match_rule for row in comparison.rows} == {MatchRule.EXACT}
    assert_invariants(previous, current, comparison)


def test_sample_report_tree_has_no_source_account_names():
    identity_center_id = re.compile(r"\bssoins-[0-9a-f]{16}\b")
    identity_center_role = re.compile(r"\bAWSReservedSSO_[A-Za-z0-9_+=,.@-]+\b")
    leaked = {}
    for path in sorted(SAMPLES.rglob("*")):
        if not path.is_file() or path.suffix not in {".html", ".md", ".py", ".txt"}:
            continue
        text = path.read_text(encoding="utf-8")
        counts = Counter(
            {
                "source-specific name": len(patterns.source_account_names(text)),
                "personal name": sum(
                    hashlib.sha256(match.group().lower().encode()).hexdigest()
                    in patterns.PERSONAL_NAME_SHA256
                    for match in patterns._WORD.finditer(text)
                ),
                "Identity Center instance ID": len(identity_center_id.findall(text)),
                "Identity Center role name": len(identity_center_role.findall(text)),
            }
        )
        if any(counts.values()):
            # Kinds and counts only, so a failure doesn't print the names.
            leaked[str(path.relative_to(REPO_ROOT))] = {
                kind: count for kind, count in counts.items() if count
            }
    assert not leaked, f"source account names remain: {leaked}"


def test_sample_pages_match_reviewed_generated_value_inventory():
    # The patterns also find synthetic replacements. Pin their reviewed
    # (kind, value) inventory without printing or saving any value. A new
    # value in Notes, navigation, or any other page text changes its digest.
    expected = {
        "index.html": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
        "security_assessment_changes.html": "8eb81dcf0f6c10c713634cceffb0718736c105e7eb159248ffd8946f6152e9ea",
        "security_assessment_multi_account.html": "2d9c52fa4031a150d00d5f750fdc9adf73c58ad8d7cca5786251f164f67f2dda",
        "security_assessment_single_account.html": "5b0db0542b38579fe5731b4cfcefe7d505126783fcd0080a4233bf21eaa917cb",
        "selection-bedrock.html": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
        "selection-governance-only.html": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    }
    actual = {}
    for path in sorted(SAMPLES.glob("*.html")):
        text = path.read_text(encoding="utf-8")
        in_code = capture._page_code_test(text)
        values = sorted(
            {
                (kind, text[start:end])
                for start, end, kind in patterns.generated_values(text)
                if not in_code(start)
            }
        )
        for kind, value in values:
            # A UUID-shaped substring inside a synthetic name can match the
            # UUID pattern; the digest below checks that reviewed inventory.
            if kind in capture.ZERO_PADDED_KINDS and kind != "UUID":
                assert re.fullmatch(r"0*a[1-9]\d*", value), (path.name, kind)
        actual[path.name] = hashlib.sha256(
            json.dumps(values, separators=(",", ":")).encode()
        ).hexdigest()
    assert actual == expected


def test_generated_values_are_found_and_fixed_names_are_not():
    text = (
        "Role 'DemoStack-Ec2Role4B1C2D3E-Qx4mTr8vLp2K' uses vpc-0a1b2c3d4e5f60718 "
        "and vpc-1a2b3c4d. Knowledge base 'kb-demo' (ID: K7Q2ZP9XWA); role "
        "'cdk-hnb659fds-lookup-role-123456789012-us-east-1'; bucket "
        "'demo-bucket-111122223333'; last used 12 days ago, on 2026-09-01. "
        "The function re-fetches the user ARN."
    )
    spans = patterns.generated_values(text)
    assert [text[start:end] for start, end, _kind in spans] == [
        "DemoStack-Ec2Role4B1C2D3E-Qx4mTr8vLp2K",
        "0a1b2c3d4e5f60718",
        "1a2b3c4d",
        "K7Q2ZP9XWA",
        "cdk-hnb659fds-lookup-role-123456789012-us-east-1",
        "demo-bucket-111122223333",
    ]


def test_a_personal_name_is_found(monkeypatch):
    names = frozenset({hashlib.sha256(b"jdoe").hexdigest()})
    monkeypatch.setattr(patterns, "PERSONAL_NAME_SHA256", names)
    text = "Bucket 'kb-agent-jdoe', owner JDoe"
    spans = patterns.generated_values(text)
    assert [(text[start:end], kind) for start, end, kind in spans] == [
        ("kb-agent-jdoe", "quoted resource name"),
        ("JDoe", patterns.PERSONAL_NAME),
    ]


def test_source_name_fingerprint_inside_compound_names(monkeypatch):
    monkeypatch.setattr(
        patterns,
        "SOURCE_NAME_FINGERPRINTS",
        {(4, hashlib.sha256(b"acme").hexdigest())},
    )
    text = "ops@acme.com www.acme-corp.com MyAcmeRole team/acme abc+acme=x"
    matches = patterns.source_account_names(text)
    assert [text[start:end] for start, end, _kind in matches] == [
        "ops@acme.com",
        "www.acme-corp.com",
        "MyAcmeRole",
        "acme",
        "abc+acme=x",
    ]
