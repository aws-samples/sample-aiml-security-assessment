"""Blank out values in finding details that change on every run.

Some checks write day counts or dates into Finding_Details, so the same
finding reads differently each run. Matching compares details with these
values blanked out. Only patterns traced to specific scanner code are listed,
and each names its sources; a test fails when scanner code writes a new day
count or date that isn't registered here. Digits in general are never masked,
because resource names contain digits.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Scanner source files are named relative to this folder.
SCANNER_ROOT = "aiml-security-assessment/functions/security"


@dataclass(frozen=True)
class VolatilePattern:
    """A value that changes between runs, and the scanner code that writes it."""

    name: str
    pattern: re.Pattern[str]
    replacement: str
    sources: tuple[tuple[str, str], ...]  # (scanner file, code snippet)


VOLATILE_PATTERNS = (
    VolatilePattern(
        name="days-in-parentheses",
        pattern=re.compile(r"\(\d+ days?\)"),
        replacement="(# days)",
        sources=(
            # AC-03 stale access (also mapped into AG-17)
            ("agentcore_assessments/app.py", "({p['days']} days)"),
            # AR-02 stale access
            ("agent_registry_assessments/app.py", "({item['days']} days)"),
        ),
    ),
    VolatilePattern(
        name="days-ago",
        pattern=re.compile(r"\b\d+ days? ago\b"),
        replacement="# days ago",
        sources=(
            # FS-31 knowledge base data sources past review threshold
            (
                "responsible_ai_grc_assessments/app.py",
                "last completed ingestion {age_days} days ago",
            ),
            # SM-40 secret rotation age
            ("sagemaker_assessments/app.py", "last rotated {int(age_days)} days ago"),
        ),
    ),
    VolatilePattern(
        name="date-after-on-or-since",
        pattern=re.compile(r"\b(on|since) \d{4}-\d{2}-\d{2}\b"),
        replacement=r"\1 <date>",
        sources=(
            # BR-14 stale Bedrock access, and its all-active details
            (
                "bedrock_assessments/app.py",
                'identity["last_accessed"].strftime("%Y-%m-%d")',
            ),
            # SM-02 stale SageMaker access
            (
                "sagemaker_assessments/app.py",
                "hasn't accessed SageMaker since "
                "{user['last_accessed'].strftime('%Y-%m-%d')}",
            ),
        ),
    ),
)

# Scanner code that looks like a changing value but never reaches finding
# details, or never changes: (scanner file, code snippet, reason).
IGNORED_SOURCES = (
    (
        "agentcore_assessments/app.py",
        "last accessed AgentCore {days_since_access} days ago",
        "log message only",
    ),
    (
        "responsible_ai_grc_assessments/app.py",
        "{STALE_AFTER_DAYS} days",
        "fixed threshold, the same every run",
    ),
    (
        "bedrock_assessments/app.py",
        "{subject} keeps session summaries for {days} days ",
        "configured value (agent memory storageDays), the same every run",
    ),
    (
        "bedrock_assessments/app.py",
        "{} {} allows keys up to {:g} days, above the {}-day cap",
        "configured value (policy condition) and a fixed threshold",
    ),
    (
        "bedrock_assessments/app.py",
        "{} denies lifetimes above {:g} days with {}",
        "configured value (policy condition), the same every run",
    ),
    (
        "bedrock_assessments/app.py",
        "of at most {BEDROCK_API_KEY_MAX_AGE_DAYS} days, then delete ",
        "fixed threshold, the same every run",
    ),
    (
        "sagemaker_assessments/app.py",
        'f"{GUARDDUTY_REVIEW_WINDOW_DAYS} days; findings created more recently are "',
        "fixed threshold, the same every run",
    ),
    (
        "sagemaker_assessments/app.py",
        'f"{GUARDDUTY_REVIEW_WINDOW_DAYS} days after they were created, so "',
        "fixed threshold, the same every run",
    ),
    (
        "sagemaker_assessments/app.py",
        'f"Workflow.Status NEW more than {GUARDDUTY_REVIEW_WINDOW_DAYS} days after "',
        "fixed threshold, the same every run",
    ),
    (
        "sagemaker_assessments/app.py",
        'f"{IOT_AUDIT_FINDING_WINDOW_DAYS} days"',
        "fixed threshold, the same every run",
    ),
    (
        "sagemaker_assessments/app.py",
        'else f"the last {IOT_AUDIT_FINDING_WINDOW_DAYS} days hold "',
        "fixed threshold, the same every run",
    ),
    (
        "sagemaker_assessments/app.py",
        'f"{interval:g} days, longer than {SECRET_ROTATION_MAX_DAYS} days, "',
        "fixed threshold, the same every run",
    ),
)


def normalize_details(text: str) -> str:
    """Return details with registered changing values replaced by placeholders."""
    for volatile in VOLATILE_PATTERNS:
        text = volatile.pattern.sub(volatile.replacement, text)
    return text
