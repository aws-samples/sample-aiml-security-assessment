"""Test-data builders for the assessment_history tests.

Not collected by pytest (no ``test_`` prefix). Kept small and reusable so
later test data sets can be built the same way.
"""

import csv
import io
from collections import Counter
from datetime import UTC, datetime

from assessment_history.compare import dedupe
from assessment_history.discover import FINDINGS_COLUMNS, PREFIX_TO_MODULE
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
_MODULE_TO_FILE_PREFIX = {module: prefix for prefix, module in PREFIX_TO_MODULE.items()}
_FILLER_CHECK = {
    "bedrock": "BR-99",
    "sagemaker": "SM-99",
    "agentcore": "AC-99",
    "agent-registry": "AR-99",
    "responsible-ai-grc": "FS-99",
    "owasp": "OW-99",
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


# --- findings CSV files and a stand-in for S3 --------------------------------


def report_name(module, execution_id, region=None):
    """A findings CSV name, as the scanners write it."""
    suffix = f"_{region}" if region else ""
    prefix = _MODULE_TO_FILE_PREFIX[module]
    return f"{prefix}_security_report_{execution_id}{suffix}.csv"


def findings_csv(findings):
    """Findings as CSV text in the scanners' column order."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=FINDINGS_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for finding in findings:
        writer.writerow(
            {
                "Check_ID": finding.check_id,
                "Finding": finding.finding,
                "Finding_Details": finding.details,
                "Resolution": finding.resolution,
                "Reference": finding.reference,
                "Severity": finding.severity,
                "Status": finding.status,
                "Region": finding.region,
            }
        )
    return buffer.getvalue()


class FakeS3:
    """Stand-in for the two S3 client calls discovery makes."""

    def __init__(self, bucket="central-bucket", page_size=2):
        self.bucket = bucket
        self.page_size = page_size
        self.objects = {}  # key -> (bytes, saved_at)
        self.reads = []

    def put(self, key, body, saved_at):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.objects[key] = (data, saved_at)

    def get_paginator(self, operation):
        assert operation == "list_objects_v2"
        return self

    def paginate(self, *, Bucket, Prefix, Delimiter):
        assert Bucket == self.bucket
        assert Delimiter == "/"
        keys = sorted(
            key
            for key in self.objects
            if key.startswith(Prefix) and "/" not in key[len(Prefix) :]
        )
        for start in range(0, len(keys), self.page_size):
            page = keys[start : start + self.page_size]
            yield {
                "Contents": [
                    {"Key": key, "LastModified": self.objects[key][1]} for key in page
                ]
            }
        yield {"CommonPrefixes": []}  # S3 can return a page with no Contents

    def get_object(self, *, Bucket, Key):
        assert Bucket == self.bucket
        self.reads.append(Key)
        return {"Body": io.BytesIO(self.objects[Key][0])}


def put_run(
    s3,
    execution_id,
    saved_at,
    findings=(),
    *,
    regions=("us-east-1",),
    modules=CORE_MODULES,
    account_id=ACCOUNT,
):
    """Write a complete run the way the scanners do; return every row written.

    Each module gets one file per region (or one file when ``regions`` is
    None); Responsible AI GRC always gets one file. A finding goes to its
    module's file for its region; Global and other rows go to the first
    region's file. A file with no findings gets one Passed row, so the run is
    complete.
    """
    files = {}
    for module in modules:
        if module == "responsible-ai-grc" or regions is None:
            files[(module, None)] = []
        else:
            for region in regions:
                files[(module, region)] = []
    for finding in findings:
        if finding.module == "responsible-ai-grc" or regions is None:
            region = None
        else:
            region = finding.region if finding.region in regions else regions[0]
        files[(finding.module, region)].append(finding)
    written = []
    for (module, region), rows in files.items():
        if not rows:
            rows = [
                make_finding(
                    _FILLER_CHECK[module],
                    "Passed",
                    module=module,
                    region=region or "Global",
                    details=f"filler for {region or 'all regions'}",
                    severity="Low",
                    account_id=account_id,
                )
            ]
        key = f"{account_id}/{report_name(module, execution_id, region)}"
        s3.put(key, findings_csv(rows), saved_at)
        written += rows
    return written
