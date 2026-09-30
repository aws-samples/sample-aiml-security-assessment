"""Find an account's assessment runs and read them into ``Run`` values.

Every run writes its findings CSVs flat into the account's folder in the
central results bucket (``<bucket>/<account_id>/``), named
``<prefix>_security_report_<execution_id>[_<region>].csv``. Files are grouped
into runs by execution ID. Execution IDs are random, so runs are ordered by
when S3 saved their files; a run's time is its latest file's time.

The previous run is the most recent usable run saved before the current one.
A run is usable when:

- its files are complete: each core service, and OWASP when present, has a CSV
  with at least one row for every region the core CSV names show, and the
  Responsible AI GRC CSV, when present, has at least one row. This follows the
  main report's own check (``validate_assessment_artifacts`` in
  generate_consolidated_report/app.py) but from the files alone: that check
  knows the regions the run was asked to scan and which options were on, and
  the files don't. A run that failed partway can still look complete from its
  files (review item F2);
- and its run record, if it has one, says it succeeded. In single-account mode
  buildspec.yml writes ``assessment_history_run_<execution_id>.json`` after
  every run. A Step Functions execution only succeeds when the main report's
  check passes, because the report step fails the execution otherwise.

An older run with a CSV that can't be read is skipped too, and the next older
run is tried (review item L3).

Discovery never compares; it hands ``Run`` values to ``compare``.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .models import (
    ACCOUNT_ID_PATTERN,
    CORE_MODULES,
    Finding,
    InvalidFindingError,
    Run,
    assign_area,
    normalize_status,
)

# File-name prefix -> module: the six the main report and buildspec.yml read.
# Any other "*_security_report_*.csv" is named in the notes, not read.
PREFIX_TO_MODULE = {
    "bedrock": "bedrock",
    "sagemaker": "sagemaker",
    "agentcore": "agentcore",
    "agent_registry": "agent-registry",
    "responsible_ai_grc": "responsible-ai-grc",
    "owasp": "owasp",
}
REPORT_MARKER = "_security_report_"
FINDINGS_COLUMNS = (
    "Check_ID",
    "Finding",
    "Finding_Details",
    "Resolution",
    "Reference",
    "Severity",
    "Status",
    "Region",
)
# An AWS Region at the end of a file name, e.g. "_us-east-1", "_us-gov-west-1".
_REGION_SUFFIX = re.compile(r"_([a-z]{2}(?:-[a-z]+)+-\d+)$")
# Skipped runs listed one by one in the notes; any more are counted.
MAX_SKIPPED_NOTES = 5
# The run record buildspec.yml writes in single-account mode (review item F2).
RUN_RECORD_PREFIX = "assessment_history_run_"
_RUN_RECORD_NAME = re.compile(r"assessment_history_run_(.+)\.json")


class DiscoveryError(Exception):
    """The account's runs can't be compared; the message says why."""


def format_utc(moment: datetime) -> str:
    """Format a timezone-aware time as UTC, e.g. 2026-09-27T06:15:00Z."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class StoredFile:
    """A file in an account folder and when it was saved (timezone-aware)."""

    name: str
    saved_at: datetime


class S3Source:
    """The top level of an account's folder in the central results bucket."""

    def __init__(self, client, bucket: str, account_id: str) -> None:
        if not ACCOUNT_ID_PATTERN.fullmatch(account_id):
            raise InvalidFindingError(f"Invalid AWS account ID: {account_id!r}")
        self._client = client
        self._bucket = bucket
        self._prefix = f"{account_id}/"
        self.location = f"s3://{bucket}/{self._prefix}"

    def list_files(self) -> list[StoredFile]:
        # Delimiter="/" leaves subfolders out: every run is written flat.
        paginator = self._client.get_paginator("list_objects_v2")
        files = []
        for page in paginator.paginate(
            Bucket=self._bucket, Prefix=self._prefix, Delimiter="/"
        ):
            for item in page.get("Contents", []):
                name = item["Key"][len(self._prefix) :]
                if name:
                    files.append(StoredFile(name, item["LastModified"]))
        return files

    def read_bytes(self, name: str) -> bytes:
        response = self._client.get_object(Bucket=self._bucket, Key=self._prefix + name)
        return response["Body"].read()


class DirectorySource:
    """The top level of a local folder holding one account's files."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self.location = str(self._path)

    def list_files(self) -> list[StoredFile]:
        return [
            StoredFile(entry.name, datetime.fromtimestamp(entry.stat().st_mtime, UTC))
            for entry in sorted(self._path.iterdir())
            if entry.is_file()
        ]

    def read_bytes(self, name: str) -> bytes:
        return (self._path / name).read_bytes()


@dataclass(frozen=True)
class ReportName:
    """What a findings CSV's name says. ``module`` is None for an unknown
    kind of findings file; ``region`` is None when the name has no region."""

    module: str | None
    execution_id: str
    region: str | None


def parse_report_name(name: str) -> ReportName | None:
    """Parse a findings CSV name, or return None for any other file."""
    if not name.lower().endswith(".csv"):
        return None
    stem = name[:-4]
    index = stem.lower().find(REPORT_MARKER)
    if index <= 0:
        return None
    rest = stem[index + len(REPORT_MARKER) :]
    match = _REGION_SUFFIX.search(rest)
    execution_id = rest[: match.start()] if match else rest
    if not execution_id:
        return None
    return ReportName(
        module=PREFIX_TO_MODULE.get(stem[:index].lower()),
        execution_id=execution_id,
        region=match.group(1) if match else None,
    )


@dataclass(frozen=True)
class ReportFile:
    """One findings CSV of a run."""

    name: str
    module: str
    region: str | None
    saved_at: datetime


@dataclass(frozen=True)
class RunFiles:
    """One run's findings CSVs, known from the folder listing alone."""

    execution_id: str
    files: tuple[ReportFile, ...]

    @property
    def saved_at(self) -> datetime:
        return max(file.saved_at for file in self.files)

    @property
    def modules(self) -> frozenset[str]:
        return frozenset(file.module for file in self.files)

    @property
    def regions(self) -> frozenset[str] | None:
        """Regions the run scanned (core CSV names), or None if unknown."""
        regions = [file.region for file in self.files if file.module in CORE_MODULES]
        if not regions or None in regions:
            return None
        return frozenset(regions)

    def missing_files(self) -> list[str]:
        """Required CSVs this run doesn't have, judged by file names."""
        present = {(file.module, file.region) for file in self.files}
        required = list(CORE_MODULES)
        if "owasp" in self.modules:
            required.append("owasp")
        regions = self.regions
        missing = []
        for module in required:
            if regions is None:
                if module not in self.modules:
                    missing.append(f"{module} CSV")
            else:
                missing += [
                    f"{module} CSV for {region}"
                    for region in sorted(regions)
                    if (module, region) not in present
                ]
        return missing


def group_runs(
    files: Iterable[StoredFile],
) -> tuple[dict[str, RunFiles], list[str]]:
    """Group findings CSVs into runs; also return unknown findings file names."""
    grouped: dict[str, list[ReportFile]] = defaultdict(list)
    unknown = []
    for stored in files:
        parsed = parse_report_name(stored.name)
        if parsed is None:
            continue
        if parsed.module is None:
            unknown.append(stored.name)
            continue
        grouped[parsed.execution_id].append(
            ReportFile(stored.name, parsed.module, parsed.region, stored.saved_at)
        )
    runs = {
        execution_id: RunFiles(
            execution_id, tuple(sorted(run_files, key=lambda file: file.name))
        )
        for execution_id, run_files in grouped.items()
    }
    return runs, sorted(unknown)


def parse_findings_csv(
    data: bytes, name: str, module: str, account_id: str
) -> list[Finding]:
    """Read one findings CSV; raise InvalidFindingError if it can't be read safely."""
    try:
        # utf-8-sig also accepts the mark Excel adds when a CSV is re-saved.
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise InvalidFindingError(f"{name} is not UTF-8 text") from None
    if not text.strip():
        return []
    reader = csv.DictReader(io.StringIO(text, newline=""))
    try:
        return _read_rows(reader, name, module, account_id)
    except csv.Error as error:
        raise InvalidFindingError(f"{name} line {reader.line_num}: {error}") from None


def _read_rows(
    reader: csv.DictReader, name: str, module: str, account_id: str
) -> list[Finding]:
    columns = reader.fieldnames or ()
    missing = [column for column in FINDINGS_COLUMNS if column not in columns]
    if missing:
        raise InvalidFindingError(f"{name} is missing column(s): {', '.join(missing)}")
    findings = []
    for row in reader:
        if None in row or None in row.values():
            raise InvalidFindingError(
                f"{name} line {reader.line_num}: wrong number of values"
            )
        try:
            status = normalize_status(row["Status"])
        except InvalidFindingError as error:
            raise InvalidFindingError(
                f"{name} line {reader.line_num}: {error}"
            ) from None
        check_id = row["Check_ID"].strip()
        findings.append(
            Finding(
                account_id=account_id,
                module=module,
                area=assign_area(module, check_id),
                region=row["Region"].strip(),
                check_id=check_id,
                finding=row["Finding"],
                details=row["Finding_Details"],
                severity=row["Severity"].strip(),
                status=status,
                resolution=row["Resolution"],
                reference=row["Reference"],
            )
        )
    return findings


def run_record_name(execution_id: str) -> str:
    """The name of a run's record file in its account folder."""
    return f"{RUN_RECORD_PREFIX}{execution_id}.json"


def run_records(files: Iterable[StoredFile]) -> dict[str, str]:
    """Execution ID -> run record file name, from a folder listing."""
    records = {}
    for stored in files:
        match = _RUN_RECORD_NAME.fullmatch(stored.name)
        if match:
            records[match.group(1)] = stored.name
    return records


def run_record_problem(
    source: S3Source | DirectorySource, name: str, execution_id: str
) -> str | None:
    """Why a run's record rules it out as the previous run, or None if it
    says the run succeeded."""
    unreadable = f"its run record {name} can't be read"
    try:
        record = json.loads(source.read_bytes(name).decode("utf-8"))
    except ValueError:  # not UTF-8, or not JSON
        return unreadable
    if (
        not isinstance(record, dict)
        or record.get("execution_id") != execution_id
        or not isinstance(record.get("succeeded"), bool)
    ):
        return unreadable
    if record["succeeded"]:
        return None
    status = record.get("status")
    detail = (
        f" (Step Functions status {status})"
        if isinstance(status, str) and status
        else ""
    )
    return f"the assessment run did not succeed{detail}"


def read_complete_run(
    source: S3Source | DirectorySource, account_id: str, run_files: RunFiles
) -> tuple[Run | None, str]:
    """Return (run, "") if the run is complete, else (None, the reason).

    Missing files are found from the listing without reading anything.
    """
    missing = run_files.missing_files()
    if missing:
        return None, "missing " + ", ".join(missing)
    findings = []
    empty = []
    for file in run_files.files:
        rows = parse_findings_csv(
            source.read_bytes(file.name), file.name, file.module, account_id
        )
        if not rows:
            empty.append(f"{file.name} has no findings")
        findings.extend(rows)
    if empty:
        return None, ", ".join(empty)
    run = Run(
        account_id=account_id,
        execution_id=run_files.execution_id,
        findings=tuple(findings),
        modules=run_files.modules,
        regions=run_files.regions,
        saved_at=run_files.saved_at,
    )
    return run, ""


@dataclass(frozen=True)
class Discovery:
    """The current run, the run to compare it with (None on a first run), and
    notes for the log."""

    current: Run
    previous: Run | None
    notes: tuple[str, ...]


def _usable_run(
    source: S3Source | DirectorySource,
    account_id: str,
    run_files: RunFiles,
    records: dict[str, str],
) -> tuple[Run | None, str]:
    """(run, "") for a run that can be the previous run, else (None, why not).

    The run record is checked first, so a failed run's CSVs aren't read.
    """
    record = records.get(run_files.execution_id)
    if record is not None:
        problem = run_record_problem(source, record, run_files.execution_id)
        if problem is not None:
            return None, problem
    try:
        run, reason = read_complete_run(source, account_id, run_files)
    except InvalidFindingError as error:
        return None, f"unreadable ({error})"
    if run is None:
        return None, f"incomplete ({reason})"
    return run, ""


def _order_key(run_files: RunFiles) -> tuple[datetime, str]:
    # Ties on save time are broken by execution ID, so the order is stable.
    return run_files.saved_at, run_files.execution_id


def discover(
    source: S3Source | DirectorySource, account_id: str, current_execution_id: str
) -> Discovery:
    """Read the current run and the most recent usable run saved before it.

    Raises DiscoveryError when the current run can't be used, and
    InvalidFindingError when one of its CSVs can't be read safely. An older
    run that can't be used or read is skipped with a note. Runs older than the
    chosen previous run are never read.
    """
    if not current_execution_id:
        raise DiscoveryError("the current run's execution ID is missing")
    files = source.list_files()
    runs, unknown = group_runs(files)
    records = run_records(files)
    notes = [f"Not read: {name} (unknown findings file type)" for name in unknown]

    current_files = runs.get(current_execution_id)
    if current_files is None:
        raise DiscoveryError(
            f"the current run's results were not found in {source.location}"
        )
    current, reason = read_complete_run(source, account_id, current_files)
    if current is None:
        raise DiscoveryError(f"the current run is incomplete ({reason})")

    current_key = _order_key(current_files)
    later = sorted(
        run.execution_id for run in runs.values() if _order_key(run) > current_key
    )
    if later:
        notes.append(
            f"Ignored {len(later)} run(s) saved after the current run: "
            + ", ".join(later)
        )

    candidates = sorted(
        (run for run in runs.values() if _order_key(run) < current_key),
        key=_order_key,
        reverse=True,
    )
    previous = None
    skipped = []
    for candidate in candidates:
        previous, why = _usable_run(source, account_id, candidate, records)
        if previous is not None:
            break
        skipped.append(
            f"Skipped run {candidate.execution_id} saved "
            f"{format_utc(candidate.saved_at)}: {why}"
        )
    notes += skipped[:MAX_SKIPPED_NOTES]
    if len(skipped) > MAX_SKIPPED_NOTES:
        notes.append(f"Skipped {len(skipped) - MAX_SKIPPED_NOTES} more run(s)")
    return Discovery(current=current, previous=previous, notes=tuple(notes))
