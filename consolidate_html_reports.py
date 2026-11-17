#!/usr/bin/env python3
"""Consolidate scoped CSV evidence, including incomplete account executions."""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(__file__),
        "aiml-security-assessment",
        "functions",
        "security",
        "generate_consolidated_report",
    ),
)

from aisf_mappings import aisf_scope, derive_aisf_findings
from aisf_results import build_aisf_register
from assessment_artifacts import (
    CSV_FRAGMENTS,
    REGION_PATTERN,
    artifact_identity,
    artifact_issue,
    coverage_issues,
    equivalent_observation_key,
    read_csv_artifact,
)
from report_template import (
    COMPLIANCE_STANDARDS,
    core_service_selection,
    generate_html_report,
)


def build_multi_account_report_key(timestamp: str) -> str:
    """Build the consolidated multi-account HTML report object key."""
    return f"consolidated-reports/security_assessment_multi_account_{timestamp}.html"


def _account_files_dir() -> str:
    # CodeBuild stages account artifacts here; local callers can override it.
    return os.environ.get("ACCOUNT_FILES_DIR", "/tmp/account-files")  # nosec B108


def _selected(owner: str, selection: dict, show_finserv: bool, owasp: bool) -> bool:
    if owner == "responsible-ai-grc":
        return show_finserv or owasp
    if owner == "owasp":
        return owasp
    return selection.get(owner, True)


def _execution_scope(root: Path, manifest: dict | str | Path | None) -> tuple:
    """Read authoritative scope, or label directory-only scope as incomplete."""
    issues = []
    if manifest is None:
        entries = []
        for directory in sorted(root.glob("*/")):
            if directory.name == "consolidated-reports":
                continue
            identities = [
                identity
                for path in sorted(directory.rglob("*.csv"))
                if (identity := artifact_identity(path.name))
            ]
            execution_ids = {identity["execution_id"] for identity in identities}
            entries.append(
                {
                    "account_id": directory.name,
                    "execution_id": next(iter(execution_ids))
                    if len(execution_ids) == 1
                    else "",
                    "regions": sorted(
                        {identity["region"] for identity in identities} - {"", "Global"}
                    ),
                }
            )
            issues.append(
                artifact_issue(
                    "unknown-scope",
                    "Supply the expected execution scope manifest; downloaded files "
                    "cannot prove that all selected accounts and regions completed.",
                    account=directory.name,
                )
            )
        if not entries:
            issues.append(
                artifact_issue(
                    "unknown-scope",
                    "Supply selected accounts, regions, and execution IDs; no account "
                    "artifacts were found.",
                )
            )
        return entries, issues
    try:
        data = (
            json.loads(Path(manifest).read_text(encoding="utf-8"))
            if isinstance(manifest, (str, Path))
            else manifest
        )
        if (
            not isinstance(data, dict)
            or data.get("schema_version") != 1
            or not isinstance(data.get("accounts"), list)
        ):
            raise ValueError("Expected schema_version 1 and an accounts list.")
    except (OSError, ValueError, TypeError) as error:
        return [], [
            artifact_issue(
                "invalid-scope",
                "Restore the expected execution scope manifest before trusting coverage.",
                error=str(error),
            )
        ]
    entries, seen = [], set()
    for original in data["accounts"]:
        if not isinstance(original, dict) or not re.fullmatch(
            r"\d{12}", str(original.get("account_id", ""))
        ):
            issues.append(
                artifact_issue(
                    "invalid-scope",
                    "Restore an expected account ID in the scope manifest.",
                )
            )
            continue
        account = str(original["account_id"])
        if account in seen:
            issues.append(
                artifact_issue(
                    "invalid-scope",
                    "Resolve duplicate account execution scopes in the manifest.",
                    account=account,
                )
            )
            continue
        seen.add(account)
        entry = dict(original)
        entry["account_id"] = account
        entry["execution_id"] = str(entry.get("execution_id") or "")
        regions = entry.get("regions")
        if (
            not isinstance(regions, list)
            or not regions
            or any(
                not isinstance(region, str) or not re.fullmatch(REGION_PATTERN, region)
                for region in regions
            )
        ):
            issues.append(
                artifact_issue(
                    "missing-regions",
                    "Restore the complete selected region list for this account.",
                    account=account,
                )
            )
            regions = []
        entry["regions"] = list(dict.fromkeys(regions))
        if not entry["execution_id"]:
            issues.append(
                artifact_issue(
                    "missing-execution",
                    "Restore the selected account's execution ID and rerun.",
                    account=account,
                )
            )
        if entry.get("status", "SUCCEEDED") != "SUCCEEDED":
            issues.append(
                artifact_issue(
                    "failed-assessment",
                    "Restore the failed account assessment and rerun: "
                    + str(entry.get("failure") or entry.get("status")),
                    account=account,
                )
            )
        entries.append(entry)
    if not entries:
        issues.append(
            artifact_issue(
                "missing-accounts",
                "Restore the selected account list; an empty manifest proves no assessment.",
            )
        )
    return entries, issues


def load_multi_account_results(
    account_files_dir: str | Path,
    *,
    scope_manifest: dict | str | Path | None = None,
    service_selection: dict | None = None,
    show_finserv: bool = False,
    enable_owasp: bool = False,
    enable_aisf: bool = False,
    timestamp: str | None = None,
) -> dict:
    """Load evidence without AWS calls and retain every missing expected scope."""
    root = Path(account_files_dir)
    selection = core_service_selection(service_selection)
    entries, issues = _execution_scope(root, scope_manifest)
    accounts = sorted({entry["account_id"] for entry in entries})
    regions = sorted({region for entry in entries for region in entry["regions"]})
    scopes = [
        {
            "account": entry["account_id"],
            "region": region,
            "execution_id": entry["execution_id"],
        }
        for entry in entries
        for region in entry["regions"] or ["Unspecified"]
    ]
    slugs = [
        "bedrock",
        "sagemaker",
        "agentcore",
        "agent-registry",
        "agentic",
        "responsible-ai-grc",
    ] + [standard["slug"] for standard in COMPLIANCE_STANDARDS]
    findings, evidence, seen = [], [], set()
    service_findings = {slug: [] for slug in slugs}
    service_stats = {slug: {"passed": 0, "failed": 0, "na": 0} for slug in slugs}

    def append_finding(row: dict) -> None:
        slug = "agentic" if row["Check_ID"].startswith("AG-") else row["_owner"]
        row["_service"] = slug
        findings.append(row)
        service_findings[slug].append(row)
        status = {"Passed": "passed", "Failed": "failed", "N/A": "na"}[row["Status"]]
        service_stats[slug][status] += 1

    if scope_manifest is not None:
        for directory in sorted(root.glob("*/")):
            if (
                directory.name not in accounts
                and directory.name != "consolidated-reports"
            ):
                issues.append(
                    artifact_issue(
                        "scope-mismatch",
                        "Isolate this unselected account directory; it cannot supply evidence.",
                        account=directory.name,
                        artifact=directory.name,
                    )
                )
    for entry in entries:
        account, execution_id = entry["account_id"], entry["execution_id"]
        account_results = {}
        for path in sorted((root / account).rglob("*.csv")):
            prefix_owner = next(
                (
                    owner
                    for owner, fragment in CSV_FRAGMENTS.items()
                    if path.name.startswith(fragment + "_security_report_")
                ),
                "",
            )
            if not _selected(prefix_owner, selection, show_finserv, enable_owasp):
                continue
            identity = artifact_identity(path.name, execution_id)
            if (
                not identity
                or not identity["matches_execution"]
                or not execution_id
                or (identity["region"] and identity["region"] not in entry["regions"])
            ):
                issues.append(
                    artifact_issue(
                        "scope-mismatch",
                        "Isolate this artifact and restore the expected producer, "
                        "execution, and region evidence.",
                        account=account,
                        owner=prefix_owner,
                        artifact=path.name,
                    )
                )
                continue
            owner = identity["owner"]
            region = identity["region"] or (
                entry["regions"][0] if entry["regions"] else ""
            )
            parsed = read_csv_artifact(
                path,
                account=account,
                region=region,
                regions=entry["regions"] if owner == "responsible-ai-grc" else None,
                selected_regions=entry["regions"],
                owner=owner,
                execution_id=execution_id,
            )
            issues.extend(parsed["issues"])
            account_results.setdefault(owner, {}).setdefault(path.stem, []).extend(
                parsed["rows"]
            )
            for row in parsed["rows"]:
                key = equivalent_observation_key(row)
                if key in seen:
                    continue
                seen.add(key)
                evidence.append(row)
                if owner != "responsible-ai-grc" or show_finserv:
                    append_finding(row)
        issues.extend(
            coverage_issues(
                account_results,
                account=account,
                execution_id=execution_id,
                regions=entry["regions"],
                service_selection=selection,
                enable_grc=show_finserv,
                enable_owasp=enable_owasp,
            )
        )
    for row in derive_aisf_findings(findings, selection):
        row["_owner"] = "aisf"
        append_finding(row)
    register = build_aisf_register(
        evidence,
        accounts=accounts or ["Unknown"],
        regions=regions,
        service_selection=selection,
        artifact_issues=issues,
        scopes=scopes,
        enable_grc=show_finserv,
        enable_owasp=enable_owasp,
        enable_aisf=enable_aisf,
    )
    return {
        "all_findings": findings,
        "service_findings": service_findings,
        "service_stats": service_stats,
        "service_selection": selection,
        "account_ids": accounts,
        "regions": regions,
        "timestamp": timestamp
        or os.environ.get("AISF_REPORT_TIMESTAMP")
        or datetime.now(timezone.utc).isoformat(),
        "scopes": scopes,
        "artifact_issues": issues,
        "aisf_register": register,
        "strict_scope": scope_manifest is not None,
    }


def render_multi_account_report(results: dict) -> str:
    """Render the same loaded evidence used by runtime and committed examples."""
    return generate_html_report(
        all_findings=results["all_findings"],
        service_findings=results["service_findings"],
        service_stats=results["service_stats"],
        service_selection=results["service_selection"],
        compliance_scope={"aisf": aisf_scope(results["service_selection"])},
        mode="multi",
        account_ids=results["account_ids"],
        timestamp=results["timestamp"],
        regions=results["regions"],
        aisf_register=results["aisf_register"],
    )


def consolidate_html_reports() -> None:
    """Upload useful evidence first; failed strict scope still fails completion."""
    s3 = boto3.client("s3")
    bucket = os.environ.get("BUCKET_REPORT")
    if not bucket:
        raise ValueError("BUCKET_REPORT environment variable is required")
    results = load_multi_account_results(
        _account_files_dir(),
        scope_manifest=os.environ.get("ASSESSMENT_SCOPE_MANIFEST"),
        service_selection={
            "bedrock": os.environ.get("ENABLE_BEDROCK", "true"),
            "sagemaker": os.environ.get("ENABLE_SAGEMAKER", "true"),
            "agentcore": os.environ.get("ENABLE_AGENTCORE", "true"),
            "agent-registry": os.environ.get("ENABLE_AGENT_REGISTRY", "true"),
        },
        show_finserv=os.environ.get("ENABLE_RESPONSIBLE_AI_GRC", "false").lower()
        == "true",
        enable_owasp=os.environ.get("ENABLE_OWASP", "false").lower() == "true",
        enable_aisf=os.environ.get("ENABLE_AISF", "false").lower() == "true",
    )
    timestamp = os.environ.get("AISF_REPORT_TIMESTAMP")
    instant = (
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if timestamp
        else datetime.now(timezone.utc)
    )
    key = build_multi_account_report_key(instant.strftime("%Y%m%d_%H%M%S"))
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=render_multi_account_report(results),
        ContentType="text/html",
    )
    print(f"Consolidated report saved to s3://{bucket}/{key}")
    if results["artifact_issues"]:
        print(f"Incomplete input evidence: {len(results['artifact_issues'])} issues")
        if results["strict_scope"]:
            raise ValueError(
                "Incomplete assessment artifacts; the uploaded report retains "
                "valid evidence and lists every input gap."
            )


def write_scope_manifest(
    output: str | Path,
    accounts_file: str | Path,
    execution_arn_dir: str | Path,
    failures_file: str | Path,
) -> None:
    """Persist CodeBuild's selected accounts independently of downloaded files."""
    accounts = Path(accounts_file).read_text(encoding="utf-8").split()
    failures = {}
    for line in Path(failures_file).read_text(encoding="utf-8").splitlines():
        account, _, reason = line.partition("\t")
        failures.setdefault(account, []).append(reason)
    regions = [
        region.strip()
        for region in os.environ.get("TARGET_REGIONS", "").split(",")
        if region.strip()
    ] or [os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION", "")]
    entries = []
    for account in accounts:
        arn_file = Path(execution_arn_dir) / f"{account}.txt"
        arn = arn_file.read_text(encoding="utf-8").strip() if arn_file.exists() else ""
        entries.append(
            {
                "account_id": account,
                "execution_id": arn.rsplit(":", 1)[-1] if arn else "",
                "regions": regions,
                "status": "FAILED" if account in failures or not arn else "SUCCEEDED",
                "failure": "; ".join(failures.get(account, [])),
            }
        )
    Path(output).write_text(
        json.dumps({"schema_version": 1, "accounts": entries}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-scope-manifest")
    parser.add_argument("--accounts-file")
    parser.add_argument("--execution-arn-dir")
    parser.add_argument("--failures-file")
    args = parser.parse_args()
    if args.write_scope_manifest:
        write_scope_manifest(
            args.write_scope_manifest,
            args.accounts_file,
            args.execution_arn_dir,
            args.failures_file,
        )
    else:
        consolidate_html_reports()
