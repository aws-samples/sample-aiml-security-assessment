#!/usr/bin/env python3
"""Build the "Changes since last assessment" sample and its golden test data.

The repository has one sample report per deployment mode, but no second run
of the same accounts to compare them with. This script:

1. turns each sample report back into the findings CSVs the scanners write
   (the "previous run");
2. makes a "current run" by applying EDITS, a short hand-written list of
   changes that covers every change state and each matching step;
3. compares the two runs with assessment_history and saves the results.

The output is the same on every run. Files written, from the repository root:

    tests/fixtures/assessment_history/golden/expected_<sample>.json
        the saved answers: counts per area, and every row that changed or
        wasn't paired by identical details
    sample-reports/security_assessment_changes.csv, .html
        the sample changes CSV and page, from the single-account sample

The previous runs' CSVs are built again every time and not saved: the golden
tests write them to a temporary folder. Values that AWS generated in the sample
reports (resource IDs, the random parts of resource names) are first replaced
with made-up values of the same shape (GENERATED_VALUE_KINDS), so no value from
a real account is copied into the files above.

Usage, from the repository root:

    .venv/bin/python sample-reports/scripts/build_changes_sample.py
    .venv/bin/python sample-reports/scripts/build_changes_sample.py --check

--check writes nothing and exits 1 when a file is out of date.
tests/test_assessment_history_golden.py makes the same check.
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import hashlib
import html
import io
import json
import re
import string
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from assessment_history.__main__ import changes_csv  # noqa: E402
from assessment_history.compare import compare_runs  # noqa: E402
from assessment_history.discover import (  # noqa: E402
    PREFIX_TO_MODULE,
    StoredFile,
    group_runs,
    read_complete_run,
)
from assessment_history.render_changes import render_changes_page  # noqa: E402
from assessment_history.models import (  # noqa: E402
    CHANGES,
    CORE_MODULES,
    GLOBAL_REGION,
    Change,
    Comparison,
    Finding,
    MatchRule,
    Run,
    assign_area,
)

SAMPLES = {
    "single_account": "security_assessment_single_account.html",
    "multi_account": "security_assessment_multi_account.html",
}
GOLDEN_PARTS = ("tests", "fixtures", "assessment_history", "golden")
SAMPLE_CHANGES_CSV = "security_assessment_changes.csv"
SAMPLE_CHANGES_PAGE = "security_assessment_changes.html"
# Areas whose rows are derived from core checks; their details end with
# "Source check <ID>: <that row's details>".
DERIVED_AREAS = ("agentic", "owasp")

PREVIOUS_ID = "2f6c1a7e-5b3d-4e8a-9c0f-000000000903"
CURRENT_ID = "2f6c1a7e-5b3d-4e8a-9c0f-000000000927"
PREVIOUS_SAVED_AT = datetime(2026, 9, 3, 23, 37, 4, tzinfo=UTC)
CURRENT_SAVED_AT = datetime(2026, 9, 27, 6, 15, 10, tzinfo=UTC)
DAYS_BETWEEN_RUNS = 24

MODULE_BY_CHECK_PREFIX = {
    "BR": "bedrock",
    "SM": "sagemaker",
    "AC": "agentcore",
    "AR": "agent-registry",
    "FS": "responsible-ai-grc",
    "OW": "owasp",
}
FILE_PREFIX_BY_MODULE = {module: prefix for prefix, module in PREFIX_TO_MODULE.items()}
CSV_FIELDS = (
    ("Check_ID", "check_id"),
    ("Finding", "finding"),
    ("Finding_Details", "details"),
    ("Resolution", "resolution"),
    ("Reference", "reference"),
    ("Severity", "severity"),
    ("Status", "status"),
    ("Region", "region"),
)


# --- reading a sample report ----------------------------------------------------

_TABLE_BODY = re.compile(
    r'<table id="findingsTable"[^>]*>.*?<tbody>(.*?)</tbody>', re.S
)
_ROW = re.compile(r"<tr ([^>]*)>(.*?)</tr>", re.S)
_ATTRIBUTE = re.compile(r'data-(\w+)="([^"]*)"')
_CODE_CELL = re.compile(r"<td><code>(.*?)</code></td>", re.S)
_FINDING = re.compile(r'<div class="col-domain">(.*?)</div>', re.S)
_PART = re.compile(r"<div><strong>(\w+)</strong><p>(.*?)</p></div>", re.S)
_LINK = re.compile(r'<a href="([^"]*)"')
_SEVERITY = re.compile(r'<span class="severity [^"]*">(.*?)</span>', re.S)
_STATUS = re.compile(r'<span class="status [^"]*">(.*?)</span>', re.S)


@dataclass(frozen=True)
class SampleRow:
    """One row of a sample report's findings table.

    ``area`` is the report's own assessment area for the row (data-service).
    """

    area: str
    account_id: str
    region: str
    check_id: str
    finding: str
    details: str
    resolution: str
    reference: str
    severity: str
    status: str


def _text(value: str) -> str:
    return html.unescape(value)


def parse_report(text: str) -> list[SampleRow]:
    """Read the findings table of a report written by report_template.py."""
    body = _TABLE_BODY.search(text)
    if body is None:
        raise ValueError("no findings table in the report")
    rows = []
    for attributes, cells in _ROW.findall(body.group(1)):
        account_id, region, check_id = _CODE_CELL.findall(cells)[:3]
        parts = dict(_PART.findall(cells))
        link = _LINK.search(parts.get("Reference", ""))
        rows.append(
            SampleRow(
                area=_text(dict(_ATTRIBUTE.findall(attributes))["service"]),
                account_id=_text(account_id),
                region=_text(region),
                check_id=_text(check_id),
                finding=_text(_FINDING.search(cells).group(1)),
                details=_text(parts["Details"]),
                resolution=_text(parts["Resolution"]),
                reference=_text(link.group(1)) if link else "",
                severity=_text(_SEVERITY.search(cells).group(1)),
                status=_text(_STATUS.search(cells).group(1)),
            )
        )
    return rows


# --- values AWS generated (review item L8) -------------------------------------------

# Values in the sample reports that AWS or CloudFormation generated: resource
# IDs and the random parts of resource names. They're replaced with made-up
# values of the same shape before anything is built from the rows, so none is
# copied into the sample changes report or the saved answers. In each pattern,
# group "v" is the value. tests/test_assessment_history_golden.py checks that
# every kind still occurs in the sample reports and that no value reaches a
# committed file.
GENERATED_VALUE_KINDS = (
    (
        "UUID",
        r"(?<![0-9a-f])(?P<v>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
        r"[0-9a-f]{1,12})(?![0-9a-f])",
    ),
    (
        "AWS resource ID",
        r"\b(?:vpc|subnet|sg|eni|igw|rtb|vpce|nat|acl|i|ami|vol|snap|lt|tgw|pcx"
        r"|eipalloc)-(?P<v>[0-9a-f]{17}|[0-9a-f]{8})\b",
    ),
    ("Bedrock ID", r"(?<=ID: )(?P<v>[A-Z0-9]{10})(?![A-Za-z0-9])"),
    ("Bedrock ID in parentheses", r"(?<=\()(?P<v>[A-Z0-9]{10})(?=\))"),
    ("Bedrock ID in a role name", r"(?<=[a-z]_)(?P<v>[A-Z0-9]{10})(?![A-Za-z0-9])"),
    (
        "CloudFormation name suffix",
        r"(?<=[-_])(?P<v>(?=[A-Za-z0-9]*[0-9])(?=[A-Za-z0-9]*[A-Za-z])"
        r"[A-Za-z0-9]{12,13})(?![A-Za-z0-9])",
    ),
    ("CloudFormation logical ID hash", r"(?<=[a-z])(?P<v>[0-9A-F]{8})(?=-)"),
    (
        "CloudFormation stack name part",
        r"(?<=[A-Z0-9]-)(?P<v>(?=[A-Z0-9]*[A-Z])[A-Z0-9]{8,10})(?=-)",
    ),
    (
        "generated lowercase suffix",
        r"(?<=-)(?P<v>(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])[a-z0-9]{8,11})"
        r"(?![A-Za-z0-9])",
    ),
    ("SageMaker domain ID", r"\bd-(?P<v>[a-z0-9]{12})\b"),
    (
        "generated bucket suffix",
        r"(?<=bucket-)(?P<v>(?=[a-z0-9]*[a-z])[a-z0-9]{12})(?![a-z0-9])",
    ),
    (
        "console role suffix",
        r"(?<=-role-)(?P<v>(?=[a-z0-9]*[a-z])[a-z0-9]{8})(?![a-z0-9])",
    ),
    (
        "conformance pack suffix",
        r"(?<=conformance-pack-)(?P<v>[a-z0-9]{6,12})(?![a-z0-9])",
    ),
    ("quick-start suffix", r"(?<=quick-start-)(?P<v>[a-z0-9]{4,8})(?![a-z0-9])"),
    (
        "suffix after a Region",
        r"(?<=-[0-9]-)(?P<v>(?=[a-z0-9]*[0-9])[a-z0-9]{4,12})(?![a-z0-9])",
    ),
)
# Matches of the patterns above that are fixed names, not generated: the CDK
# bootstrap's default qualifier, a service name, and part of a stack name.
NOT_GENERATED = frozenset({"hnb659fds", "s3express", "PATTERN1STACK"})
# SHA-256 of personal names in the sample reports (one is part of a bucket
# name), kept as hashes so this file doesn't repeat them. A word that matches
# is replaced like a generated value.
PERSONAL_NAME = "personal name"
PERSONAL_NAME_SHA256 = frozenset(
    {"8044948181460cf23c5fd5ad6a432c2fbd8ce1e06cbd4ea1955d37685c81ce6b"}
)
_GENERATED = tuple(
    (kind, re.compile(pattern)) for kind, pattern in GENERATED_VALUE_KINDS
)
_WORD = re.compile(r"[A-Za-z]+")
_HEX = re.compile(r"[0-9a-f]+|[0-9A-F]+")


def generated_values(text: str) -> list[tuple[int, int, str]]:
    """(start, end, kind) of each generated value in text, left to right.

    Where two matches overlap, the one that starts first (then the longer one)
    is kept.
    """
    found = [
        (*match.span("v"), kind)
        for kind, pattern in _GENERATED
        for match in pattern.finditer(text)
        if match.group("v") not in NOT_GENERATED
    ]
    found += [
        (*match.span(), PERSONAL_NAME)
        for match in _WORD.finditer(text)
        if hashlib.sha256(match.group().lower().encode()).hexdigest()
        in PERSONAL_NAME_SHA256
    ]
    kept: list[tuple[int, int, str]] = []
    end = 0
    for start, stop, kind in sorted(
        found, key=lambda item: (item[0], item[0] - item[1])
    ):
        if start >= end:
            kept.append((start, stop, kind))
            end = stop
    return kept


def _made_up_character(character: str, byte: int, hex_only: bool) -> str:
    if character.isdigit():
        pool = string.digits
    elif character.islower():
        pool = "abcdef" if hex_only else string.ascii_lowercase
    elif character.isupper():
        pool = "ABCDEF" if hex_only else string.ascii_uppercase
    else:
        return character
    return pool[byte % len(pool)]


def placeholder(value: str) -> str:
    """A made-up value shaped like value.

    Each digit becomes a digit and each letter a letter of the same case (a hex
    digit if value is hex); other characters are kept. The same value always
    gets the same placeholder.
    """
    hex_only = _HEX.fullmatch(value.replace("-", "")) is not None
    attempt = 0
    while True:
        stream = hashlib.shake_256(f"{attempt}:{value}".encode()).digest(len(value))
        made_up = "".join(
            _made_up_character(character, byte, hex_only)
            for character, byte in zip(value, stream)
        )
        if made_up != value:
            return made_up
        attempt += 1


def replace_generated_values(text: str) -> str:
    """text with each generated value replaced by its placeholder."""
    parts, last = [], 0
    for start, end, _kind in generated_values(text):
        parts += [text[last:start], placeholder(text[start:end])]
        last = end
    return "".join(parts) + text[last:]


def anonymize(rows: list[SampleRow]) -> list[SampleRow]:
    """Rows with generated values replaced in the finding, details and resolution."""
    return [
        dataclasses.replace(
            row,
            finding=replace_generated_values(row.finding),
            details=replace_generated_values(row.details),
            resolution=replace_generated_values(row.resolution),
        )
        for row in rows
    ]


# --- writing and reading a run's findings CSVs ---------------------------------------


def agentic_owners(root: Path = REPO_ROOT) -> dict[str, str]:
    """Which core scanner writes each AG-* check, read from the scanners' code."""
    scanners = root / "aiml-security-assessment" / "functions" / "security"
    owners: dict[str, str] = {}
    for module in CORE_MODULES:
        path = scanners / f"{FILE_PREFIX_BY_MODULE[module]}_assessments" / "app.py"
        source = path.read_text(encoding="utf-8")
        for check_id in sorted(set(re.findall(r'"(AG-\d+)"', source))):
            if owners.setdefault(check_id, module) != module:
                raise ValueError(f"{check_id} appears in more than one scanner")
    return owners


def module_for(check_id: str, owners: dict[str, str]) -> str:
    """The scanner module whose CSV holds a check's rows."""
    prefix = check_id.split("-", 1)[0].upper()
    if prefix == "AG":
        return owners[check_id]
    return MODULE_BY_CHECK_PREFIX[prefix]


def write_run(rows, execution_id: str, owners: dict[str, str]) -> dict[str, str]:
    """A run's findings CSVs as the scanners name and fill them: {name: text}.

    ``rows`` are SampleRow or Finding values of one account. Global rows, and
    rows for a region the run didn't scan, go in the first region's file, as
    the primary-region scanner writes them. Responsible AI GRC has one file.
    """
    regions = sorted(
        {
            row.region
            for row in rows
            if module_for(row.check_id, owners) in CORE_MODULES
            and row.region != GLOBAL_REGION
        }
    )
    files: dict[str, list[list[str]]] = {}
    header = [column for column, _ in CSV_FIELDS]
    for row in rows:
        module = module_for(row.check_id, owners)
        prefix = f"{FILE_PREFIX_BY_MODULE[module]}_security_report_{execution_id}"
        if module == "responsible-ai-grc":
            name = f"{prefix}.csv"
        else:
            region = row.region if row.region in regions else regions[0]
            name = f"{prefix}_{region}.csv"
        values = [getattr(row, attribute) for _, attribute in CSV_FIELDS]
        files.setdefault(name, [header]).append(values)
    texts = {}
    for name, lines in sorted(files.items()):
        buffer = io.StringIO()
        csv.writer(buffer, lineterminator="\n").writerows(lines)
        texts[name] = buffer.getvalue()
    return texts


class _MemoryFolder:
    """An account folder held in memory, for discover's reading functions."""

    location = "memory"

    def __init__(self, files: dict[str, str], saved_at: datetime) -> None:
        self._files = files
        self._saved_at = saved_at

    def list_files(self) -> list[StoredFile]:
        return [StoredFile(name, self._saved_at) for name in sorted(self._files)]

    def read_bytes(self, name: str) -> bytes:
        return self._files[name].encode("utf-8")


def read_run(files: dict[str, str], account_id: str, saved_at: datetime) -> Run:
    """Read one run's CSVs with the same code the build uses."""
    folder = _MemoryFolder(files, saved_at)
    runs, unknown = group_runs(folder.list_files())
    if unknown or len(runs) != 1:
        raise ValueError(f"expected one run's findings CSVs, got {sorted(files)}")
    (run_files,) = runs.values()
    run, reason = read_complete_run(folder, account_id, run_files)
    if run is None:
        raise ValueError(f"the run for account {account_id} is incomplete: {reason}")
    return run


# --- the edits that make the current run --------------------------------------------


@dataclass(frozen=True)
class Edit:
    """One change made to the previous run to make the current run.

    ``update`` and ``remove`` act on the one row with this Check_ID, Region,
    and Status; any other number of matching rows is an error. They also
    apply to the Agentic AI and OWASP rows derived from that row, as the
    scanners would write them. ``add`` adds a row and first removes the
    check's Passed row in that region, because a scanner reports either one
    Passed summary row or one row per failing resource.
    """

    shows: str
    action: str
    check_id: str
    region: str
    status: str = ""
    values: dict[str, str] = field(default_factory=dict)


# Chosen from rows that exist in every account of both sample reports, so the
# same list applies everywhere. Agentic AI and OWASP rows derived from an
# edited row change with it (see _derived_rows).
AR01_REFERENCE = "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html"
EDITS = (
    Edit(
        "Regressed (single-row pairing: the title and details changed, as the "
        "scanner writes them)",
        "update",
        "SM-04",
        "us-east-1",
        "Passed",
        {
            "status": "Failed",
            "finding": "GuardDuty Not Enabled",
            "severity": "High",
            "details": "Amazon GuardDuty is not enabled, so threats to SageMaker "
            "workloads in this Region are not monitored.",
            "resolution": "Enable Amazon GuardDuty in this Region.",
        },
    ),
    Edit(
        "Resolved (the title changes from 'Missing' to 'Check', as the scanner "
        "writes it)",
        "update",
        "AC-09",
        "Global",
        "Failed",
        {
            "status": "Passed",
            "finding": "AgentCore Service-Linked Role Check",
            "details": "Service-linked role 'AWSServiceRoleForBedrockAgentCoreNetwork' "
            "exists.",
            "resolution": "No action required",
        },
    ),
    Edit(
        "No longer assessed (Failed to N/A, not counted as Resolved); its two "
        "OWASP rows (OW-01, OW-10) too",
        "update",
        "SM-26",
        "us-east-2",
        "Failed",
        {
            "status": "N/A",
            "severity": "Informational",
            "details": "GuardDuty AI Protection status could not be read: "
            "AccessDeniedException.",
            "resolution": "Grant guardduty:GetDetector and retry the assessment.",
        },
    ),
    Edit(
        "No longer reported (the row is gone); its OWASP row (OW-02) goes too",
        "remove",
        "BR-37",
        "us-west-2",
        "Failed",
    ),
    Edit(
        "Resolved, flowing through to its Agentic AI (AG-28) and OWASP (OW-02) rows",
        "update",
        "AC-14",
        "us-east-1",
        "Failed",
        {
            "status": "Passed",
            "details": "AgentCore token vault 'default' uses a customer-managed KMS key.",
            "resolution": "No action required",
        },
    ),
    Edit(
        "New (N/A to Failed; the title changes from 'Unused Permissions' to "
        "'Stale Access Check', as the scanner writes it)",
        "update",
        "AR-02",
        "Global",
        "N/A",
        {
            "status": "Failed",
            "finding": "AWS Agent Registry Stale Access Check",
            "severity": "Medium",
            "details": "The following principals have AWS Agent Registry permissions "
            "they have not used: role 'sample-registry-role'",
        },
    ),
    Edit(
        "New (one more role for a check with one row per role); Regressed where "
        "the check's only previous row was its Passed summary row",
        "add",
        "BR-03",
        "Global",
        values={
            "finding": "Marketplace Subscription Access Check",
            "details": "Role 'sample-new-app-role' has overly permissive marketplace "
            "subscription access through policy 'AWSMarketplaceFullAccess'",
            "resolution": "Ensure that users have access to only the models that you "
            "want user to be able to subscribe to based on your organizational "
            "policies. For example, you may want users to have access to only text "
            "based models and not image and video generation model. This can also "
            "help to keep cost in check.",
            "reference": "https://docs.aws.amazon.com/bedrock/latest/userguide/"
            "security-iam-awsmanpol.html#security-iam-awsmanpol-bedrock-marketplace",
            "severity": "High",
            "status": "Failed",
        },
    ),
    Edit(
        "Regressed x2 (check-level pairing): the check's Passed summary row is "
        "replaced by two Failed rows with their own titles, as the scanner writes "
        "them",
        "add",
        "AR-01",
        "Global",
        values={
            "finding": "AWS Agent Registry IAM Full Access Policy",
            "details": "The following roles have AWS Agent Registry full-access "
            "policies: sample-registry-admin-role",
            "resolution": "Replace full-access policies with least-privilege AWS "
            "Agent Registry actions and scoped resources.",
            "reference": AR01_REFERENCE,
            "severity": "High",
            "status": "Failed",
        },
    ),
    Edit(
        "(second AR-01 row; see above)",
        "add",
        "AR-01",
        "Global",
        values={
            "finding": "AWS Agent Registry IAM Wildcard Permissions",
            "details": "The following roles have wildcard or allow-except AWS Agent "
            "Registry permissions on all resources: sample-registry-admin-role",
            "resolution": "Replace wildcard permissions with required AWS Agent "
            "Registry actions and scoped resources.",
            "reference": AR01_REFERENCE,
            "severity": "High",
            "status": "Failed",
        },
    ),
    Edit(
        "Still open, details changed (single-row pairing; review item F3): AC-17 "
        "had no online evaluation configuration, now it has one that isn't "
        "complete. One Failed row each, about different things.",
        "update",
        "AC-17",
        "us-east-2",
        "Failed",
        {
            "details": "Online evaluation 'sample-agent-eval' (sample-agent-eval-0001) "
            "is missing one or more operational coverage settings.",
            "resolution": "Set the evaluation ACTIVE and ENABLED, use non-zero "
            "sampling, add evaluators, and configure CloudWatch input and output "
            "log groups.",
        },
    ),
)

_DAYS_IN_PARENTHESES = re.compile(r"\((\d+) days?\)")
_DAYS_AGO = re.compile(r"\b(\d+) days? ago\b")


def shift_days(text: str) -> str:
    """Advance day counts by the time between the runs (matching step 1b)."""
    text = _DAYS_IN_PARENTHESES.sub(
        lambda match: f"({int(match.group(1)) + DAYS_BETWEEN_RUNS} days)", text
    )
    return _DAYS_AGO.sub(
        lambda match: f"{int(match.group(1)) + DAYS_BETWEEN_RUNS} days ago", text
    )


def _derived_rows(rows: list[Finding], source: Finding) -> list[int]:
    """Indexes of the Agentic AI and OWASP rows derived from ``source``."""
    marker = f"Source check {source.check_id}: {source.details}"
    return [
        index
        for index, row in enumerate(rows)
        if row.area in DERIVED_AREAS
        and row.region == source.region
        and row.details.endswith(marker)
    ]


def _follow(row: Finding, source: Finding, changed: Finding) -> Finding:
    """A derived row after its source row changed, as the scanners write it."""
    prefix = row.details[: -len(source.details)]
    return dataclasses.replace(
        row,
        status=changed.status,
        severity="Informational" if changed.status == "N/A" else row.severity,
        details=prefix + changed.details,
    )


def apply_edits(findings: tuple[Finding, ...]) -> list[Finding]:
    """The previous run's findings with EDITS and the day-count shift applied."""
    rows = list(findings)
    account_id = rows[0].account_id
    for edit in EDITS:
        if edit.action == "add":
            module = MODULE_BY_CHECK_PREFIX[edit.check_id.split("-", 1)[0]]
            rows = [
                row
                for row in rows
                if not (
                    row.check_id == edit.check_id
                    and row.region == edit.region
                    and row.status == "Passed"
                )
            ]
            rows.append(
                Finding(
                    account_id=account_id,
                    module=module,
                    area=assign_area(module, edit.check_id),
                    region=edit.region,
                    check_id=edit.check_id,
                    **edit.values,
                )
            )
            continue
        matches = [
            index
            for index, row in enumerate(rows)
            if (row.check_id, row.region, row.status)
            == (edit.check_id, edit.region, edit.status)
        ]
        if len(matches) != 1:
            raise ValueError(
                f"edit {edit.check_id} {edit.region} {edit.status}: expected one row "
                f"in account {account_id}, found {len(matches)}"
            )
        source = rows[matches[0]]
        derived = _derived_rows(rows, source)
        if edit.action == "remove":
            rows = [
                row
                for index, row in enumerate(rows)
                if index != matches[0] and index not in derived
            ]
        else:
            changed = dataclasses.replace(source, **edit.values)
            rows[matches[0]] = changed
            for index in derived:
                rows[index] = _follow(rows[index], source, changed)
    return [dataclasses.replace(row, details=shift_days(row.details)) for row in rows]


def make_current_run(previous: Run) -> Run:
    return Run(
        account_id=previous.account_id,
        execution_id=CURRENT_ID,
        findings=tuple(apply_edits(previous.findings)),
        modules=previous.modules,
        regions=previous.regions,
        saved_at=CURRENT_SAVED_AT,
    )


# --- saved answers ----------------------------------------------------------------


def summarize(comparison: Comparison) -> dict:
    """The saved answer: counts and notes, plus every row that changed or was
    paired by a rule other than identical details. Rows paired exactly and
    still open, or not failing, are covered by the counts."""

    def counts(counter) -> dict[str, int]:
        return {change.value: counter[change] for change in Change if counter[change]}

    return {
        "previous_execution_id": comparison.previous_execution_id,
        "current_execution_id": comparison.current_execution_id,
        "days_apart": comparison.days_apart,
        "tile_counts": counts(comparison.tile_counts()),
        "counts_by_area": {
            area: counts(counter)
            for area, counter in comparison.counts_by_area().items()
        },
        "not_compared_modules": comparison.not_compared_modules,
        "not_compared_regions": comparison.not_compared_regions,
        "single_run_check_ids": comparison.single_run_check_ids,
        "rows": [
            {
                "area": row.area,
                "region": row.region,
                "check_id": row.check_id,
                "finding": row.finding,
                "change": row.change.value,
                "match_rule": row.match_rule.value,
                "previous_status": row.previous_status,
                "current_status": row.current_status,
                "severity": row.severity,
                "previous_details": row.previous.details if row.previous else None,
                "current_details": row.current.details if row.current else None,
            }
            for row in comparison.rows
            if row.change in CHANGES or row.match_rule is not MatchRule.EXACT
        ],
    }


# --- building every output file ------------------------------------------------------


def golden_dir(root: Path = REPO_ROOT) -> Path:
    return root.joinpath(*GOLDEN_PARTS)


def sample_rows(sample: str, root: Path = REPO_ROOT) -> list[SampleRow]:
    """A sample report's rows, with the values AWS generated replaced."""
    report = (root / "sample-reports" / SAMPLES[sample]).read_text(encoding="utf-8")
    return anonymize(parse_report(report))


def previous_runs(root: Path = REPO_ROOT) -> dict[str, dict[str, dict[str, str]]]:
    """Each sample's previous run: {sample: {account_id: {CSV name: text}}}.

    Built from the sample reports every time, not saved (review item L7).
    """
    owners = agentic_owners(root)
    runs: dict[str, dict[str, dict[str, str]]] = {}
    for sample in SAMPLES:
        rows = sample_rows(sample, root)
        runs[sample] = {
            account_id: write_run(
                [row for row in rows if row.account_id == account_id],
                PREVIOUS_ID,
                owners,
            )
            for account_id in sorted({row.account_id for row in rows})
        }
    return runs


def build(root: Path = REPO_ROOT) -> dict[Path, str]:
    """Every file this script writes, as {path: text}."""
    golden = golden_dir(root)
    outputs: dict[Path, str] = {}
    for sample, runs in previous_runs(root).items():
        report_name = SAMPLES[sample]
        expected = {}
        for account_id, files in runs.items():
            previous = read_run(files, account_id, PREVIOUS_SAVED_AT)
            comparison = compare_runs(previous, make_current_run(previous))
            expected[account_id] = summarize(comparison)
            if sample == "single_account":
                samples = root / "sample-reports"
                outputs[samples / SAMPLE_CHANGES_CSV] = changes_csv(comparison).decode(
                    "utf-8"
                )
                # The sample main report sits next to it, so its link works.
                outputs[samples / SAMPLE_CHANGES_PAGE] = render_changes_page(
                    comparison,
                    csv_name=SAMPLE_CHANGES_CSV,
                    main_report_name=report_name,
                    generated_at=CURRENT_SAVED_AT,
                )
        outputs[golden / f"expected_{sample}.json"] = (
            json.dumps(expected, indent=1, ensure_ascii=False) + "\n"
        )
    return outputs


def _read(path: Path) -> str | None:
    if not path.is_file():
        return None
    with open(path, encoding="utf-8", newline="") as handle:
        return handle.read()


def _normalized(text: str | None) -> str | None:
    return None if text is None else text.replace("\r\n", "\n")


def out_of_date(outputs: dict[Path, str], root: Path = REPO_ROOT) -> list[Path]:
    """Output files that differ from what's on disk, plus leftover files (such as
    the input CSVs this script used to save)."""
    stale = [
        path
        for path, text in outputs.items()
        if _normalized(_read(path)) != _normalized(text)
    ]
    leftovers = [
        path
        for sample in SAMPLES
        for path in sorted((golden_dir(root) / sample).rglob("*"))
        if path.is_file() and path not in outputs
    ]
    return stale + leftovers


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build the changes-report sample and its golden test data."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="write nothing; exit 1 if any file is out of date",
    )
    args = parser.parse_args(argv)
    outputs = build()
    stale = out_of_date(outputs)
    if args.check:
        for path in stale:
            print(f"Out of date: {path.relative_to(REPO_ROOT)}")
        return 1 if stale else 0
    for path in stale:
        if path not in outputs:
            path.unlink()
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(outputs[path])
    print(f"{len(stale)} of {len(outputs)} files written or removed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
