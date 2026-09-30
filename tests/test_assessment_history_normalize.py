"""Blanking out values that change every run (matching step 1b).

Each registered pattern is tested with the text its scanner writes. The guard
tests fail when scanner code starts writing a day count or date into finding
details that isn't registered in assessment_history/normalize.py.
"""

import re
from pathlib import Path

import pytest

from assessment_history.normalize import (
    IGNORED_SOURCES,
    SCANNER_ROOT,
    VOLATILE_PATTERNS,
    normalize_details,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SCANNERS = REPO_ROOT / SCANNER_ROOT

# A placeholder followed by "days", or a YYYY-MM-DD date format.
VOLATILE_LOOKING = re.compile(r"\{[^{}]+\} days|strftime\(\s*['\"]%Y-%m-%d['\"]\s*\)")


@pytest.mark.parametrize(
    "text, expected",
    [
        # AC-03 / AG-17 / AR-02
        (
            "not accessed in 60+ days: role 'A' (255 days), role 'B' (1 day)",
            "not accessed in 60+ days: role 'A' (# days), role 'B' (# days)",
        ),
        # FS-31
        (
            "- kb-1 last completed ingestion 45 days ago",
            "- kb-1 last completed ingestion # days ago",
        ),
        # BR-14
        (
            "Role 'r1' last accessed Bedrock on 2026-05-01",
            "Role 'r1' last accessed Bedrock on <date>",
        ),
        # SM-02
        (
            "User 'u1' hasn't accessed SageMaker since 2026-04-30",
            "User 'u1' hasn't accessed SageMaker since <date>",
        ),
    ],
)
def test_registered_patterns_are_blanked(text, expected):
    assert normalize_details(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        # Digits and dates inside resource names are never touched.
        "Role 'DemoAppStack-Ec2Role4B1C2D3E-Qx4mTr8vLp2K' has access",
        "Role 'AmazonSageMaker-ExecutionRole-20250525T153161' (never accessed)",
        "Training Job 'xgboost-2021-12-19-01-07-17-012' is not encrypted",
        "not accessed in 60+ days",
        "Role 'r1' last accessed Bedrock on never",
        "",
    ],
)
def test_other_text_is_unchanged(text):
    assert normalize_details(text) == text


def test_pattern_names_are_unique():
    names = [volatile.name for volatile in VOLATILE_PATTERNS]
    assert len(names) == len(set(names))


def _scanner_files():
    return sorted(
        path
        for folder in SCANNERS.glob("*_assessments")
        for path in folder.rglob("*.py")
    )


def test_guard_every_volatile_value_in_scanner_code_is_registered():
    known = [source for volatile in VOLATILE_PATTERNS for source in volatile.sources]
    known += [(file, snippet) for file, snippet, _reason in IGNORED_SOURCES]
    assert _scanner_files(), "no scanner files found"
    unregistered = []
    for path in _scanner_files():
        relative = path.relative_to(SCANNERS).as_posix()
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if VOLATILE_LOOKING.search(line) and not any(
                relative == file and snippet in line for file, snippet in known
            ):
                unregistered.append(f"{relative}:{number}: {line.strip()}")
    assert not unregistered, (
        "Scanner code writes a day count or date that normalize.py doesn't know. "
        "Add a pattern to VOLATILE_PATTERNS, or an IGNORED_SOURCES entry with a "
        "reason:\n" + "\n".join(unregistered)
    )


def test_guard_registered_sources_still_exist():
    sources = [source for volatile in VOLATILE_PATTERNS for source in volatile.sources]
    sources += [(file, snippet) for file, snippet, _reason in IGNORED_SOURCES]
    missing = [
        f"{file}: {snippet}"
        for file, snippet in sources
        if snippet not in (SCANNERS / file).read_text(encoding="utf-8")
    ]
    assert not missing, "Registered scanner code no longer exists:\n" + "\n".join(
        missing
    )
