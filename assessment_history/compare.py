"""Compare two assessment runs of one account.

Rows are grouped by assessment area, region, and Check_ID. The Finding title
is not part of the group: many scanners use one title when a check fails and
another when it passes or can't be assessed (review item F1). Within a group,
rows are paired in five steps:

1. the same title and identical Finding_Details (exact), then the same title
   and identical details once values that change every run are blanked out
   (normalized);
2. identical details, blanked the same way, under a different title
   (details), for a title that changed between releases;
3. two remaining rows that are each their run's only row, in the group or
   with their title (single-row);
4. several remaining Failed rows in one run, and in the other run a single
   row that isn't Failed, such as a Passed summary or an N/A error row: each
   Failed row is paired with that row (check-level);
5. anything left is unpaired.

A pair is only made when it's unambiguous: steps 1 and 2 need a key that is
unique on both sides, so rows are never guessed into pairs. In step 4 one row
is shared by several pairs; it's the only way a row appears more than once.
Only core services selected, optional modules enabled, and regions scanned,
in both runs are compared; the rest is returned as excluded with a reason.
Rows marked Global, or with no region, are always compared.

No AWS calls: runs arrive as ``models.Run`` values.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Sequence

from .models import (
    AREAS,
    CORE_MODULES,
    CURRENT_RUN,
    FAILED,
    GLOBAL_REGION,
    MODULE_NOT_IN_BOTH_RUNS,
    NOT_APPLICABLE,
    PASSED,
    PREVIOUS_RUN,
    REGION_NOT_IN_BOTH_RUNS,
    SERVICE_NOT_IN_BOTH_RUNS,
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
        compared_modules=shared_modules,
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
            reason = (
                SERVICE_NOT_IN_BOTH_RUNS
                if finding.module in CORE_MODULES
                else MODULE_NOT_IN_BOTH_RUNS
            )
            excluded.append(ExcludedFinding(side, reason, finding))
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


def _group_key(finding: Finding) -> tuple[str, str, str]:
    return (finding.area, finding.region, finding.check_id)


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


_KEYED_STEPS: tuple[tuple[MatchRule, Callable[[Finding], object]], ...] = (
    (MatchRule.EXACT, lambda finding: (finding.finding, finding.details)),
    (
        MatchRule.NORMALIZED,
        lambda finding: (finding.finding, normalize_details(finding.details)),
    ),
    (MatchRule.DETAILS, lambda finding: normalize_details(finding.details)),
)


def _match_group(previous: list[Finding], current: list[Finding]) -> list[ComparedRow]:
    rows = []
    rest_previous, rest_current = list(previous), list(current)
    for rule, key in _KEYED_STEPS:
        pairs, rest_previous, rest_current = _pair_unique(
            rest_previous, rest_current, key
        )
        rows += [_row(p, c, rule) for p, c in pairs]
    for rule, find_pairs in (
        (MatchRule.SINGLE_ROW, _single_row_pairs),
        (MatchRule.CHECK_LEVEL, _check_level_pairs),
    ):
        pairs = find_pairs(previous, current, rest_previous, rest_current)
        rows += [_row(p, c, rule) for p, c in pairs]
        rest_previous = [p for p in rest_previous if p not in {p for p, _ in pairs}]
        rest_current = [c for c in rest_current if c not in {c for _, c in pairs}]
    rows += [_row(p, None, MatchRule.UNMATCHED) for p in rest_previous]
    rows += [_row(None, c, MatchRule.UNMATCHED) for c in rest_current]
    return rows


def _single_row_pairs(
    previous: list[Finding],
    current: list[Finding],
    rest_previous: list[Finding],
    rest_current: list[Finding],
) -> _Pairs:
    """Remaining rows that are each their run's only row: in the whole group
    (the title may differ), or with their title (the title must match)."""
    if len(previous) == 1 and len(current) == 1:
        return list(zip(rest_previous, rest_current))
    previous_titles = Counter(finding.finding for finding in previous)
    current_titles = Counter(finding.finding for finding in current)
    only_current = {
        finding.finding: finding
        for finding in rest_current
        if current_titles[finding.finding] == 1
    }
    return [
        (finding, only_current[finding.finding])
        for finding in rest_previous
        if previous_titles[finding.finding] == 1 and finding.finding in only_current
    ]


def _check_level_pairs(
    previous: list[Finding],
    current: list[Finding],
    rest_previous: list[Finding],
    rest_current: list[Finding],
) -> _Pairs:
    """Remaining Failed rows on one side, all paired with the other side's one
    row: the group's only row in that run, still unpaired, and not Failed."""
    if _is_lone_other_row(current, rest_current) and _all_failed(rest_previous):
        return [(finding, rest_current[0]) for finding in rest_previous]
    if _is_lone_other_row(previous, rest_previous) and _all_failed(rest_current):
        return [(rest_previous[0], finding) for finding in rest_current]
    return []


def _is_lone_other_row(side: list[Finding], rest: list[Finding]) -> bool:
    return len(side) == 1 and len(rest) == 1 and rest[0].status != FAILED


def _all_failed(rest: list[Finding]) -> bool:
    return bool(rest) and all(finding.status == FAILED for finding in rest)


def _pair_unique(
    previous: list[Finding],
    current: list[Finding],
    key: Callable[[Finding], object],
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
