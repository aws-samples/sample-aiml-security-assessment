"""Test-data builders for the assessment_history tests.

Not collected by pytest (no ``test_`` prefix). Kept small and reusable so
later test data sets can be built the same way.
"""

from collections import Counter
from datetime import UTC, datetime

from assessment_history.compare import dedupe
from assessment_history.models import (
    CORE_MODULES,
    CURRENT_RUN,
    PREVIOUS_RUN,
    Finding,
    Run,
    assign_area,
)

# AWS documentation placeholder account IDs, as in the sample reports.
ACCOUNT = "123456789012"
OTHER_ACCOUNT = "111122223333"

_MODULE_BY_PREFIX = {
    "BR": "bedrock",
    "SM": "sagemaker",
    "AC": "agentcore",
    "AR": "agent-registry",
    "AG": "bedrock",
    "FS": "responsible-ai-grc",
    "OW": "owasp",
}


def make_finding(
    check_id="BR-01",
    status="Failed",
    *,
    region="Global",
    finding=None,
    details="details",
    severity="High",
    module=None,
    account_id=ACCOUNT,
    resolution="Fix it.",
    reference="https://docs.aws.amazon.com/",
):
    module = module or _MODULE_BY_PREFIX[check_id.split("-", 1)[0]]
    return Finding(
        account_id=account_id,
        module=module,
        area=assign_area(module, check_id),
        region=region,
        check_id=check_id,
        finding=finding or f"{check_id} check",
        details=details,
        severity=severity,
        status=status,
        resolution=resolution,
        reference=reference,
    )


def make_run(
    findings=(),
    *,
    execution_id="run-current",
    modules=None,
    regions=None,
    account_id=ACCOUNT,
    saved_at=None,
):
    findings = tuple(findings)
    if modules is None:
        modules = set(CORE_MODULES) | {finding.module for finding in findings}
    return Run(
        account_id=account_id,
        execution_id=execution_id,
        findings=findings,
        modules=frozenset(modules),
        regions=regions,
        saved_at=saved_at,
    )


def utc(day, hour=0, minute=0):
    """A timezone-aware September 2026 time in UTC."""
    return datetime(2026, 9, day, hour, minute, tzinfo=UTC)


def changes(comparison):
    """Count of rows per change state."""
    return Counter(row.change for row in comparison.rows)


def assert_invariants(previous, current, comparison):
    """Every row of each run appears exactly once, and no row is paired twice."""
    for side, run, attribute in (
        (PREVIOUS_RUN, previous, "previous"),
        (CURRENT_RUN, current, "current"),
    ):
        expected = Counter(dedupe(run.findings))
        seen = Counter(
            getattr(row, attribute)
            for row in comparison.rows
            if getattr(row, attribute) is not None
        )
        seen.update(item.finding for item in comparison.excluded if item.side == side)
        assert seen == expected, f"{side}: rows lost or used twice"
