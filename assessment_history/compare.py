"""Compare two assessment runs of one account.

Rows are grouped by assessment area, region, Check_ID, and Finding. Within a
group, rows are paired in three steps:

1. identical Finding_Details (step 1a), then identical details once values
   that change every run are blanked out (step 1b);
2. if the group has exactly one row in each run, those two rows;
3. anything left is unpaired.

A pair is only made when its key is unique on both sides, so rows are never
guessed into pairs. Only modules enabled, and regions scanned, in both runs
are compared; the rest is returned as excluded with a reason. Rows marked
Global, or with no region, are always compared.

No AWS calls: runs arrive as ``models.Run`` values.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Sequence

from .models import (
    AREAS,
    CURRENT_RUN,
    FAILED,
    GLOBAL_REGION,
    MODULE_NOT_IN_BOTH_RUNS,
    NOT_APPLICABLE,
    PASSED,
    PREVIOUS_RUN,
    REGION_NOT_IN_BOTH_RUNS,
    Change,
    ComparedRow,
    Comparison,
    ExcludedFinding,
    Finding,
    MatchRule,
    Run,
)
from .normalize import normalize_details

_Pairs = list[tuple[Finding, Finding]]


def classify(previous_status: str | None, current_status: str | None) -> Change:
    """Return the change state for two statuses (None means not present)."""
    if previous_status is None and current_status is None:
        raise ValueError("A compared row needs at least one side")
    if current_status == FAILED:
        if previous_status == FAILED:
            return Change.STILL_OPEN
        if previous_status == PASSED:
            return Change.REGRESSED
        return Change.NEW
    if previous_status == FAILED:
        if current_status == PASSED:
            return Change.RESOLVED
        if current_status == NOT_APPLICABLE:
            return Change.NO_LONGER_ASSESSED
        return Change.NO_LONGER_REPORTED
    return Change.NOT_FAILING


def dedupe(findings: Iterable[Finding]) -> tuple[Finding, ...]:
    """Drop repeated rows, keeping the first, with the main report's key.

    Key from generate_consolidated_report/app.py: Account_ID, area,
    Check_ID, Region, Finding_Details.
    """
    seen: set[tuple[str, ...]] = set()
    kept = []
    for finding in findings:
        key = (
            finding.account_id,
            finding.area,
            finding.check_id,
            finding.region,
            finding.details,
        )
        if key not in seen:
            seen.add(key)
            kept.append(finding)
    return tuple(kept)


def compare_runs(previous: Run, current: Run) -> Comparison:
    """Compare a previous run with the current run of the same account."""
    if previous.account_id != current.account_id:
        raise ValueError(
            f"Runs are for different accounts: {previous.account_id} and "
            f"{current.account_id}"
        )
    if previous.execution_id == current.execution_id:
        raise ValueError(f"Both runs are execution {current.execution_id}")

    shared_modules = previous.modules & current.modules
    shared_regions = None
    not_compared_regions: dict[str, str] = {}
    if previous.regions is not None and current.regions is not None:
        shared_regions = previous.regions & current.regions
        not_compared_regions = _one_sided(previous.regions, current.regions)

    excluded: list[ExcludedFinding] = []
    previous_rows = _in_scope(
        dedupe(previous.findings),
        shared_modules,
        shared_regions,
        PREVIOUS_RUN,
        excluded,
    )
    current_rows = _in_scope(
        dedupe(current.findings), shared_modules, shared_regions, CURRENT_RUN, excluded
    )

    return Comparison(
        account_id=current.account_id,
        previous_execution_id=previous.execution_id,
        current_execution_id=current.execution_id,
        rows=tuple(_match(previous_rows, current_rows)),
        excluded=tuple(sorted(excluded, key=_excluded_sort_key)),
        not_compared_modules=_one_sided(previous.modules, current.modules),
        not_compared_regions=not_compared_regions,
        single_run_check_ids=_one_sided(
            {f.check_id for f in previous_rows}, {f.check_id for f in current_rows}
        ),
        previous_saved_at=previous.saved_at,
        current_saved_at=current.saved_at,
    )


def _one_sided(previous: Iterable[str], current: Iterable[str]) -> dict[str, str]:
    """Items in only one of the two runs, mapped to which run has them."""
    previous, current = set(previous), set(current)
    sides = {item: "previous run only" for item in previous - current}
    sides.update({item: "current run only" for item in current - previous})
    return dict(sorted(sides.items()))


def _in_scope(
    findings: Sequence[Finding],
    modules: frozenset[str],
    regions: frozenset[str] | None,
    side: str,
    excluded: list[ExcludedFinding],
) -> list[Finding]:
    kept = []
    for finding in findings:
        if finding.module not in modules:
            excluded.append(ExcludedFinding(side, MODULE_NOT_IN_BOTH_RUNS, finding))
        elif regions is not None and not _region_in_scope(finding.region, regions):
            excluded.append(ExcludedFinding(side, REGION_NOT_IN_BOTH_RUNS, finding))
        else:
            kept.append(finding)
    return kept


def _region_in_scope(region: str, regions: frozenset[str]) -> bool:
    """Whether a row is compared: Global, blank, or listing only shared regions.

    A Region value can list several regions ("us-east-1, us-west-2"); the
    main report's readers guard against that form too.
    """
    listed = [part.strip() for part in region.split(",") if part.strip()]
    return all(part == GLOBAL_REGION or part in regions for part in listed)


def _group_key(finding: Finding) -> tuple[str, str, str, str]:
    return (finding.area, finding.region, finding.check_id, finding.finding)


def _match(
    previous: Sequence[Finding], current: Sequence[Finding]
) -> list[ComparedRow]:
    groups: dict[tuple[str, ...], tuple[list[Finding], list[Finding]]] = defaultdict(
        lambda: ([], [])
    )
    for finding in previous:
        groups[_group_key(finding)][0].append(finding)
    for finding in current:
        groups[_group_key(finding)][1].append(finding)
    rows = []
    for previous_group, current_group in groups.values():
        rows.extend(_match_group(previous_group, current_group))
    return sorted(rows, key=_row_sort_key)


def _match_group(previous: list[Finding], current: list[Finding]) -> list[ComparedRow]:
    rows = []
    pairs, rest_previous, rest_current = _pair_unique(
        previous, current, lambda finding: finding.details
    )
    rows += [_row(p, c, MatchRule.EXACT) for p, c in pairs]
    pairs, rest_previous, rest_current = _pair_unique(
        rest_previous, rest_current, lambda finding: normalize_details(finding.details)
    )
    rows += [_row(p, c, MatchRule.NORMALIZED) for p, c in pairs]
    if len(previous) == 1 and len(current) == 1 and rest_previous and rest_current:
        rows.append(_row(rest_previous[0], rest_current[0], MatchRule.SINGLE_ROW))
        rest_previous, rest_current = [], []
    rows += [_row(p, None, MatchRule.UNMATCHED) for p in rest_previous]
    rows += [_row(None, c, MatchRule.UNMATCHED) for c in rest_current]
    return rows


def _pair_unique(
    previous: list[Finding],
    current: list[Finding],
    key: Callable[[Finding], str],
) -> tuple[_Pairs, list[Finding], list[Finding]]:
    """Pair rows whose key appears exactly once on each side."""
    previous_counts = Counter(key(finding) for finding in previous)
    current_counts = Counter(key(finding) for finding in current)
    unique = {
        value
        for value, count in previous_counts.items()
        if count == 1 and current_counts[value] == 1
    }
    current_by_key = {key(c): c for c in current if key(c) in unique}
    pairs = [(p, current_by_key[key(p)]) for p in previous if key(p) in unique]
    rest_previous = [p for p in previous if key(p) not in unique]
    rest_current = [c for c in current if key(c) not in unique]
    return pairs, rest_previous, rest_current


def _row(
    previous: Finding | None, current: Finding | None, rule: MatchRule
) -> ComparedRow:
    change = classify(
        previous.status if previous else None, current.status if current else None
    )
    return ComparedRow(change, rule, previous, current)


def _row_sort_key(row: ComparedRow) -> tuple:
    return (
        AREAS.index(row.area),
        row.region,
        row.check_id,
        row.finding,
        row.previous.details if row.previous else "",
        row.current.details if row.current else "",
    )


def _excluded_sort_key(item: ExcludedFinding) -> tuple:
    finding = item.finding
    return (
        item.side,
        AREAS.index(finding.area),
        finding.region,
        finding.check_id,
        finding.finding,
        finding.details,
    )
