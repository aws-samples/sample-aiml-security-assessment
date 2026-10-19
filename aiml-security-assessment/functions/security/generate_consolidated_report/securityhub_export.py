"""Opt-in, account-level ASFF assessment snapshots (no resource remediation)."""

import hashlib
from collections import defaultdict

import boto3
from botocore.config import Config

PRODUCT_NAME = "AI/ML Security Assessment"
SEVERITIES = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def build_findings(
    results, account_id, region, partition, execution, selection, show_grc
):
    """Summarize CSV observations by check and region, with retry-stable IDs.

    CSV rows do not carry a uniform resource identifier. Do not invent one or
    treat a changing free-text description as a resource identity. Each export
    is an execution-scoped account/check snapshot, not resource lifecycle sync.
    """
    groups = defaultdict(list)
    for category, reports in results.items():
        if not isinstance(reports, dict) or not selection.get(category, True):
            continue
        if category == "responsible-ai-grc" and not show_grc:
            continue
        for rows in reports.values():
            if not isinstance(rows, list):
                continue
            for row in rows:
                check_id = row.get("Check_ID")
                if not check_id or row.get("Status") not in {"Passed", "Failed", "N/A"}:
                    raise ValueError("Invalid assessment row for Security Hub export")
                groups[(check_id, row.get("Region") or region)].append(row)

    product_arn = f"arn:{partition}:securityhub:{region}:{account_id}:product/{account_id}/default"
    timestamp = execution["StartTime"]
    findings = []
    for (check_id, observed_region), rows in sorted(groups.items()):
        # The same Global observation may appear in more than one CSV.
        unique_rows = {tuple(sorted(row.items())): row for row in rows}
        rows = [unique_rows[key] for key in sorted(unique_rows, key=repr)]
        failed = [row for row in rows if row["Status"] == "Failed"]
        status = (
            "FAILED"
            if failed
            else "NOT_AVAILABLE"
            if any(row["Status"] == "N/A" for row in rows)
            else "PASSED"
        )
        relevant = failed or rows
        labels = [row.get("Severity", "Informational").upper() for row in relevant]
        if any(label not in SEVERITIES for label in labels):
            raise ValueError("Unknown assessment severity for Security Hub export")
        severity = max(labels, key=SEVERITIES.index) if failed else "INFORMATIONAL"
        identity = f"{execution['Id']}|{timestamp}|{check_id}|{observed_region}"
        digest = hashlib.sha256(identity.encode()).hexdigest()
        details = sorted(
            {f"{row['Status']}: {row.get('Finding_Details', '')}" for row in relevant}
        )
        description = (
            f"Assessment snapshot: {len(rows)} observations; {len(failed)} failed. "
            + "\n".join(details)
        )
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"aiml-security-assessment/{digest}",
            "ProductArn": product_arn,
            "ProductName": PRODUCT_NAME,
            "CompanyName": "AI/ML Security Assessment Framework",
            "GeneratorId": f"aiml-security-assessment/{check_id}",
            "AwsAccountId": account_id,
            "Region": region,
            "CreatedAt": timestamp,
            "UpdatedAt": timestamp,
            "Title": f"{check_id}: {relevant[0].get('Finding', 'Assessment result')}"[
                :256
            ],
            "Description": description[:1024],
            "FindingProviderFields": {
                "Severity": {"Label": severity},
                "Types": [
                    "Software and Configuration Checks/Industry and Regulatory Standards"
                ],
            },
            "Compliance": {"Status": status},
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": account_id,
                    "Partition": partition,
                    "Region": region
                    if observed_region == "Global"
                    else observed_region,
                }
            ],
            "ProductFields": {
                "CheckId": check_id,
                "AssessedRegion": observed_region,
                "ExecutionId": execution["Id"],
                "ExecutionStartTime": timestamp,
                "ObservationCount": str(len(rows)),
                "FailedObservationCount": str(len(failed)),
            },
        }
        resolution = relevant[0].get("Resolution")
        if resolution:
            finding["Remediation"] = {"Recommendation": {"Text": resolution[:512]}}
        findings.append(finding)
    return findings


def export_findings(findings, region):
    """Import bounded batches; partial failures must not be reported as success."""
    if not findings:
        return 0
    client = boto3.client(
        "securityhub",
        region_name=region,
        config=Config(retries={"mode": "standard", "max_attempts": 5}),
    )
    for start in range(0, len(findings), 100):
        response = client.batch_import_findings(Findings=findings[start : start + 100])
        if (
            response.get("FailedCount")
            or response.get("FailedFindings")
            or response.get("SuccessCount") != len(findings[start : start + 100])
        ):
            raise RuntimeError(
                "Security Hub export partially failed; check Security Hub availability and import permissions"
            )
    return len(findings)
