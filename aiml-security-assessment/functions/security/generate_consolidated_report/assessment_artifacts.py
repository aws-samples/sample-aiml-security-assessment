"""Strict, scope-aware input handling shared by both report consolidators."""

import csv
import io
import json
import re
from pathlib import Path

from aisf_mappings import AGENTIC_SOURCE_SERVICE

REQUIRED_COLUMNS = (
    "Check_ID",
    "Finding",
    "Finding_Details",
    "Resolution",
    "Reference",
    "Severity",
    "Status",
    "Region",
)
CSV_FRAGMENTS = {
    "bedrock": "bedrock",
    "sagemaker": "sagemaker",
    "agentcore": "agentcore",
    "agent-registry": "agent_registry",
    "responsible-ai-grc": "responsible_ai_grc",
    "owasp": "owasp",
}
SOURCE_IDS = {
    **{f"BR-{n:02d}": "bedrock" for n in range(58)},
    **{f"SM-{n:02d}": "sagemaker" for n in range(44) if n != 29},
    **{f"AC-{n:02d}": "agentcore" for n in range(54)},
    **{f"AR-{n:02d}": "agent-registry" for n in range(11)},
    **{
        f"FS-{n:02d}": "responsible-ai-grc"
        for n in range(70)
        if n not in (17, 18, 19, 23, 64)
    },
    **{f"OW-{n:02d}": "owasp" for n in range(13)},
    **AGENTIC_SOURCE_SERVICE,
}
REGION_PATTERN = r"[a-z]{2}(?:-[a-z0-9]+)+-\d+"


def artifact_issue(
    kind: str,
    message: str,
    *,
    account: str = "",
    region: str = "",
    owner: str = "",
    artifact: str = "",
    **details,
) -> dict:
    return {
        "kind": kind,
        "message": message,
        "account": account,
        "region": region,
        "owner": owner,
        "artifact": artifact,
        **details,
    }


def artifact_identity(filename: str, execution_id: str = "") -> dict | None:
    """Read the producer contract; an execution prefix alone is not a match."""
    name = Path(filename).name
    for owner, fragment in CSV_FRAGMENTS.items():
        prefix = fragment + "_security_report_"
        if not name.startswith(prefix) or not name.endswith(".csv"):
            continue
        suffix = name[len(prefix) : -4]
        if owner == "responsible-ai-grc":
            actual_execution, region = suffix, ""
        else:
            match = re.fullmatch(rf"(.+)_({REGION_PATTERN})", suffix)
            if not match:
                return None
            actual_execution, region = match.groups()
        return {
            "owner": owner,
            "region": region,
            "execution_id": actual_execution,
            "matches_execution": not execution_id or execution_id == actual_execution,
        }
    return None


def expected_artifacts(
    execution_id: str,
    regions: list[str],
    service_selection: dict,
    *,
    enable_grc: bool = False,
    enable_owasp: bool = False,
) -> list[dict]:
    expected = []
    for owner, fragment in CSV_FRAGMENTS.items():
        if owner == "responsible-ai-grc":
            if enable_grc or enable_owasp:
                expected.append(
                    {
                        "owner": owner,
                        "region": regions[0] if regions else "",
                        "artifact": f"{fragment}_security_report_{execution_id}.csv",
                    }
                )
        elif enable_owasp if owner == "owasp" else service_selection.get(owner, True):
            expected.extend(
                {
                    "owner": owner,
                    "region": region,
                    "artifact": f"{fragment}_security_report_{execution_id}_{region}.csv",
                }
                for region in regions
            )
    return expected


def bucket_observation_region_matches(
    row: dict,
    *,
    owner: str,
    artifact_region: str,
    selected_regions: list[str] | None,
) -> bool:
    """BR-47/52 bucket rows use the selected bucket region, not the CSV region."""
    return bool(
        owner == "bedrock"
        and row.get("Check_ID", "").strip().upper() in ("BR-47", "BR-52")
        and re.match(
            r"^Bucket [^\s]+ is on the Bedrock data path(?: and |, but )",
            row.get("Finding_Details", ""),
        )
        and selected_regions
        and artifact_region in selected_regions
        and row.get("Region") in selected_regions
    )


def parse_csv_artifact(
    content: str | bytes,
    *,
    artifact: str = "",
    account: str = "",
    region: str = "",
    regions: list[str] | None = None,
    selected_regions: list[str] | None = None,
    owner: str = "",
    execution_id: str = "",
) -> dict:
    """Return accepted rows and explicit issues; keep valid rows before errors."""
    rows, issues = [], []
    scope = dict(account=account, region=region, owner=owner, artifact=artifact)

    def problem(kind, message, **details):
        issues.append(artifact_issue(kind, message, **scope, **details))

    if not content:
        problem("zero-byte", "Restore the zero-byte assessment CSV and rerun.")
        return {"rows": rows, "issues": issues}
    try:
        text = content.decode("utf-8-sig") if isinstance(content, bytes) else content
    except UnicodeDecodeError as error:
        problem("unreadable", "Restore a UTF-8 assessment CSV.", error=str(error))
        return {"rows": rows, "issues": issues}
    reader = csv.DictReader(io.StringIO(text), strict=True)
    try:
        fields = reader.fieldnames or []
        if (
            not set(REQUIRED_COLUMNS).issubset(fields)
            or len(fields) != len(set(fields))
            or any(not field for field in fields)
        ):
            problem(
                "wrong-schema",
                "Restore an assessment CSV with every required column and unique headers.",
                missing_columns=sorted(set(REQUIRED_COLUMNS) - set(fields)),
                columns=fields,
            )
            return {"rows": rows, "issues": issues}
        for original in reader:
            row = dict(original)
            if None in row or any(value is None for value in row.values()):
                problem(
                    "malformed",
                    "Restore the malformed CSV row; its column count is wrong.",
                    line=reader.line_num,
                    observation={
                        key if key is not None else "_extra_columns": value
                        for key, value in row.items()
                    },
                )
                continue
            check_id = row["Check_ID"].strip().upper()
            row_owner = SOURCE_IDS.get(check_id)
            if not row_owner:
                problem(
                    "unknown-check",
                    "Update or remove the unknown/retired source ID; it cannot prove a control.",
                    line=reader.line_num,
                    observation=row,
                )
                continue
            mismatch = []
            if owner and row_owner != owner:
                mismatch.append("owner")
            for field, expected in (
                ("Account_ID", account),
                ("Execution_ID", execution_id),
            ):
                values = {row[key] for key in (field, field.lower()) if row.get(key)}
                if len(values) > 1 or (expected and values - {expected}):
                    mismatch.append(field)
            actual_region = row["Region"]
            allowed_regions = regions if regions is not None else [region]
            if not actual_region or (
                (region or regions is not None)
                and actual_region not in (*allowed_regions, "Global")
                and not bucket_observation_region_matches(
                    row,
                    owner=owner,
                    artifact_region=region,
                    selected_regions=selected_regions,
                )
            ):
                mismatch.append("region")
            if mismatch:
                problem(
                    "scope-mismatch",
                    "Isolate the observation and restore the expected "
                    + ", ".join(mismatch)
                    + " evidence.",
                    line=reader.line_num,
                    observation=row,
                )
                continue
            if row["Status"] not in ("Passed", "Failed", "N/A"):
                problem(
                    "invalid-status",
                    "Restore a source verdict of Passed, Failed, or N/A.",
                    line=reader.line_num,
                    observation=row,
                )
                continue
            row["Check_ID"] = check_id
            if account:
                row.setdefault("Account_ID", account)
                if not row["Account_ID"]:
                    row["Account_ID"] = account
            if execution_id:
                row.setdefault("Execution_ID", execution_id)
                if not row["Execution_ID"]:
                    row["Execution_ID"] = execution_id
            row["_owner"] = row_owner
            row["_artifact"] = artifact
            row["_artifact_region"] = region
            rows.append(row)
    except csv.Error as error:
        problem(
            "malformed",
            "Restore the malformed CSV; earlier valid observations were retained.",
            line=reader.line_num,
            error=str(error),
        )
    if not rows and not issues:
        problem(
            "header-only",
            "Rerun the selected assessment: headers alone prove no discovery or checks.",
        )
    return {"rows": rows, "issues": issues}


def read_csv_artifact(path: str | Path, **scope) -> dict:
    path = Path(path)
    try:
        content = path.read_bytes()
    except OSError as error:
        return {
            "rows": [],
            "issues": [
                artifact_issue(
                    "unreadable",
                    "Restore read access to the selected assessment CSV and rerun.",
                    artifact=path.name,
                    error=str(error),
                    **{key: value for key, value in scope.items() if key != "regions"},
                )
            ],
        }
    return parse_csv_artifact(content, artifact=path.name, **scope)


def equivalent_observation_key(row: dict) -> str:
    """Keep different verdicts, resources, errors, and executions distinct."""
    return json.dumps(
        {
            key: value
            for key, value in row.items()
            if key not in ("_artifact", "_artifact_region", "_service", "service")
        },
        sort_keys=True,
    )


def coverage_issues(
    results: dict,
    *,
    account: str,
    execution_id: str,
    regions: list[str],
    service_selection: dict,
    enable_grc: bool = False,
    enable_owasp: bool = False,
) -> list[dict]:
    """Require every selected producer artifact in every expected scope."""
    issues = []
    for expected in expected_artifacts(
        execution_id,
        regions,
        service_selection,
        enable_grc=enable_grc,
        enable_owasp=enable_owasp,
    ):
        name = expected["artifact"]
        rows = (results.get(expected["owner"]) or {}).get(name[:-4])
        if not rows:
            issues.append(
                artifact_issue(
                    "missing" if rows is None else "no-valid-observations",
                    f"Restore and rerun selected assessment artifact {name}.",
                    account=account,
                    **expected,
                )
            )
    return issues


def scoped_issues(
    issues: list[dict],
    service_selection: dict,
    *,
    enable_grc: bool,
    enable_owasp: bool,
) -> list[dict]:
    """Deselected producers neither supply evidence nor create missing work."""
    return [
        issue
        for issue in issues
        if (
            enable_grc or enable_owasp
            if issue.get("owner") == "responsible-ai-grc"
            else enable_owasp
            if issue.get("owner") == "owasp"
            else service_selection.get(issue.get("owner"), True)
        )
    ]
