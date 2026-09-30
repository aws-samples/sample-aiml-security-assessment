"""Record shapes for the assessment history package.

A ``Finding`` is one row from a run's findings CSVs, a ``Run`` is one
assessment run of one account, and a ``Comparison`` is the result of comparing
two runs. Nothing here calls AWS, so every module can share these types and
test them with plain in-memory data.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

ACCOUNT_ID_PATTERN = re.compile(r"\d{12}")
GLOBAL_REGION = "Global"

# Source modules, one per findings-CSV family. Same slugs as the main report's
# csv_source_slugs (generate_consolidated_report/app.py).
CORE_MODULES = ("bedrock", "sagemaker", "agentcore", "agent-registry")
OPTIONAL_MODULES = ("responsible-ai-grc", "owasp")
MODULES = CORE_MODULES + OPTIONAL_MODULES

# Assessment areas, in the main report's sidebar order: By Service, By Lens,
# By Governance Framework, By Compliance Standard. Headline counts use the
# By Service areas only.
CORE_AREAS = CORE_MODULES
AREAS = CORE_AREAS + ("agentic", "responsible-ai-grc", "owasp")

# Compliance-standard Check_ID prefixes. Mirrors COMPLIANCE_STANDARDS in
# report_template.py; a test fails if the two drift apart.
COMPLIANCE_PREFIX_TO_AREA = {"OW": "owasp"}

PASSED = "Passed"
FAILED = "Failed"
NOT_APPLICABLE = "N/A"
STATUSES = (PASSED, FAILED, NOT_APPLICABLE)
_STATUS_BY_LOWERCASE = {status.lower(): status for status in STATUSES}
NOT_PRESENT = "Not present"

PREVIOUS_RUN = "previous run"
CURRENT_RUN = "current run"
MODULE_NOT_IN_BOTH_RUNS = "module not enabled in both runs"
REGION_NOT_IN_BOTH_RUNS = "region not scanned in both runs"

CSV_COLUMNS = (
    "Account_ID",
    "Assessment_Area",
    "Region",
    "Check_ID",
    "Finding",
    "Change",
    "Previous_Status",
    "Current_Status",
    "Previous_Severity",
    "Current_Severity",
    "Previous_Finding_Details",
    "Current_Finding_Details",
    "Resolution",
    "Reference",
    "Match_Rule",
    "Previous_Execution_ID",
    "Current_Execution_ID",
)

# Leading characters a spreadsheet may run as a formula (OWASP CSV injection).
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


class InvalidFindingError(ValueError):
    """Input that can't be compared safely; the comparison must not continue."""


class Change(StrEnum):
    """How a finding changed between the previous and current run."""

    REGRESSED = "Regressed"
    NEW = "New"
    STILL_OPEN = "Still open"
    RESOLVED = "Resolved"
    NO_LONGER_REPORTED = "No longer reported"
    NO_LONGER_ASSESSED = "No longer assessed"
    NOT_FAILING = "Not failing"


# "Still open" and "Not failing" mean nothing changed.
CHANGES = frozenset(
    {
        Change.REGRESSED,
        Change.NEW,
        Change.RESOLVED,
        Change.NO_LONGER_REPORTED,
        Change.NO_LONGER_ASSESSED,
    }
)


class MatchRule(StrEnum):
    """Which matching step paired a row (recorded so results can be audited)."""

    EXACT = "exact"
    NORMALIZED = "normalized"
    DETAILS = "details"
    SINGLE_ROW = "single-row"
    CHECK_LEVEL = "check-level"
    UNMATCHED = "unmatched"


def normalize_status(value: object) -> str:
    """Return the canonical status, ignoring case and surrounding spaces."""
    text = "" if value is None else str(value).strip()
    try:
        return _STATUS_BY_LOWERCASE[text.lower()]
    except KeyError:
        raise InvalidFindingError(f"Unrecognized Status value: {value!r}") from None


def assign_area(module: str, check_id: str) -> str:
    """Return the assessment area for a row, routed the way the main report does."""
    if module not in MODULES:
        raise InvalidFindingError(f"Unknown assessment module: {module!r}")
    check = check_id.strip().upper()
    if check.startswith("AG-"):
        return "agentic"
    if check.startswith("AR-"):
        return "agent-registry"
    prefix = check.split("-", 1)[0] if "-" in check else ""
    return COMPLIANCE_PREFIX_TO_AREA.get(prefix, module)


def csv_safe(value: str) -> str:
    """Prefix text a spreadsheet would run as a formula with a single quote."""
    return f"'{value}" if value.startswith(_FORMULA_PREFIXES) else value


def _require_account_id(account_id: str) -> None:
    if not ACCOUNT_ID_PATTERN.fullmatch(account_id):
        raise InvalidFindingError(f"Invalid AWS account ID: {account_id!r}")


@dataclass(frozen=True)
class Finding:
    """One row of a run's findings CSVs."""

    account_id: str
    module: str
    area: str
    region: str
    check_id: str
    finding: str
    details: str
    severity: str
    status: str
    resolution: str = ""
    reference: str = ""

    def __post_init__(self) -> None:
        _require_account_id(self.account_id)
        if self.module not in MODULES:
            raise InvalidFindingError(f"Unknown assessment module: {self.module!r}")
        if self.area not in AREAS:
            raise InvalidFindingError(f"Unknown assessment area: {self.area!r}")
        if self.status not in STATUSES:
            raise InvalidFindingError(f"Status must be normalized: {self.status!r}")


@dataclass(frozen=True)
class Run:
    """One assessment run of one account.

    ``modules`` are the findings-CSV families the run wrote. ``regions`` are
    the regions it scanned, or None when unknown. ``saved_at`` is when its
    results were saved (timezone-aware).
    """

    account_id: str
    execution_id: str
    findings: tuple[Finding, ...]
    modules: frozenset[str]
    regions: frozenset[str] | None = None
    saved_at: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(self, "modules", frozenset(self.modules))
        if self.regions is not None:
            object.__setattr__(self, "regions", frozenset(self.regions))
        _require_account_id(self.account_id)
        if not self.execution_id:
            raise InvalidFindingError("A run needs an execution ID")
        unknown = sorted(self.modules - set(MODULES))
        if unknown:
            raise InvalidFindingError(f"Unknown assessment modules: {unknown}")
        if self.saved_at is not None and self.saved_at.tzinfo is None:
            raise InvalidFindingError("saved_at must be timezone-aware")
        for finding in self.findings:
            if finding.account_id != self.account_id:
                raise InvalidFindingError(
                    f"Finding for account {finding.account_id} in a run of "
                    f"account {self.account_id}"
                )
            if finding.module not in self.modules:
                raise InvalidFindingError(
                    f"Finding from module {finding.module!r}, which this run "
                    "didn't write"
                )


@dataclass(frozen=True)
class ComparedRow:
    """One finding after comparison: both runs' rows, or one of them."""

    change: Change
    match_rule: MatchRule
    previous: Finding | None
    current: Finding | None

    def __post_init__(self) -> None:
        if self.previous is None and self.current is None:
            raise ValueError("A compared row needs at least one side")

    @property
    def _latest(self) -> Finding:
        return self.current or self.previous

    @property
    def account_id(self) -> str:
        return self._latest.account_id

    @property
    def area(self) -> str:
        return self._latest.area

    @property
    def region(self) -> str:
        return self._latest.region

    @property
    def check_id(self) -> str:
        return self._latest.check_id

    @property
    def finding(self) -> str:
        return self._latest.finding

    @property
    def previous_status(self) -> str:
        return self.previous.status if self.previous else NOT_PRESENT

    @property
    def current_status(self) -> str:
        return self.current.status if self.current else NOT_PRESENT

    @property
    def severity(self) -> str:
        """Severity to show: the previous run's when the finding went away."""
        if self.change in (Change.NO_LONGER_REPORTED, Change.NO_LONGER_ASSESSED):
            return self.previous.severity
        return self._latest.severity

    @property
    def resolution(self) -> str:
        return self._latest.resolution

    @property
    def reference(self) -> str:
        return self._latest.reference

    def to_csv_record(
        self, previous_execution_id: str, current_execution_id: str
    ) -> dict[str, str]:
        """Return this row as a changes-CSV record, keyed by CSV_COLUMNS."""
        previous, current = self.previous, self.current
        values = (
            self.account_id,
            self.area,
            self.region,
            self.check_id,
            self.finding,
            self.change.value,
            self.previous_status,
            self.current_status,
            previous.severity if previous else "",
            current.severity if current else "",
            previous.details if previous else "",
            current.details if current else "",
            self.resolution,
            self.reference,
            self.match_rule.value,
            previous_execution_id,
            current_execution_id,
        )
        return {
            column: csv_safe(value)
            for column, value in zip(CSV_COLUMNS, values, strict=True)
        }


@dataclass(frozen=True)
class ExcludedFinding:
    """A finding left out of the comparison, with the side and the reason."""

    side: str
    reason: str
    finding: Finding


@dataclass(frozen=True)
class Comparison:
    """The result of comparing two runs of one account."""

    account_id: str
    previous_execution_id: str
    current_execution_id: str
    rows: tuple[ComparedRow, ...]
    excluded: tuple[ExcludedFinding, ...] = ()
    not_compared_modules: dict[str, str] = field(default_factory=dict)
    not_compared_regions: dict[str, str] = field(default_factory=dict)
    single_run_check_ids: dict[str, str] = field(default_factory=dict)
    previous_saved_at: datetime | None = None
    current_saved_at: datetime | None = None

    @property
    def has_changes(self) -> bool:
        return any(row.change in CHANGES for row in self.rows)

    @property
    def days_apart(self) -> int | None:
        """Calendar days between the two runs' UTC dates, or None if unknown."""
        if self.previous_saved_at is None or self.current_saved_at is None:
            return None
        previous_day = self.previous_saved_at.astimezone(UTC).date()
        current_day = self.current_saved_at.astimezone(UTC).date()
        return (current_day - previous_day).days

    def counts_by_area(self) -> dict[str, Counter[Change]]:
        """Rows per change state for each area, in report order."""
        counts: dict[str, Counter[Change]] = {}
        for row in self.rows:
            counts.setdefault(row.area, Counter())[row.change] += 1
        return {area: counts[area] for area in AREAS if area in counts}

    def tile_counts(self) -> Counter[Change]:
        """Headline counts: By Service areas only, so nothing is counted twice."""
        by_area = self.counts_by_area()
        total: Counter[Change] = Counter()
        for area in CORE_AREAS:
            total.update(by_area.get(area, Counter()))
        return total

    def to_csv_records(self) -> list[dict[str, str]]:
        return [
            row.to_csv_record(self.previous_execution_id, self.current_execution_id)
            for row in self.rows
        ]
