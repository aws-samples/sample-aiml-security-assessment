"""The committed sample reports hold no values from the source account.

The samples come from real runs and are cleaned in place by
sample-reports/scripts/capture_screenshots.py --anonymize-only. These tests
check the result, and the patterns the cleaning relies on.
"""

import hashlib
import importlib.util
import re
import sys
from collections import Counter
from pathlib import Path

import pytest

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
    unexpected_ids = set(re.findall(r"\b\d{12}\b", report)) - set(
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


def test_sample_report_tree_has_no_source_account_names():
    identity_center_id = re.compile(r"\bssoins-[0-9a-f]{16}\b")
    identity_center_role = re.compile(r"\bAWSReservedSSO_[A-Za-z0-9_+=,.@-]+\b")
    leaked = {}
    for path in sorted(SAMPLES.rglob("*")):
        if not path.is_file():
            continue
        text = path.read_bytes().decode("utf-8", errors="ignore")
        counts = Counter(
            {
                "source-specific name": len(patterns.source_account_names(text)),
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
