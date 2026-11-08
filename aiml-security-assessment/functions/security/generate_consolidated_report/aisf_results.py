"""Canonical controls and scoped observations, shared by both report paths."""

import hashlib
import json
import re
from collections import Counter

from aisf_catalog import CATALOG_DIRECTORY, load_catalog
from assessment_artifacts import SOURCE_IDS

SERVICES = ("bedrock", "sagemaker", "agentcore", "agent-registry")
ALIASES = {
    "AIR-BDR-KB-03": "AISF-05",
    "AIR-SGM-EP-08": "AISF-07",
    "AIR-SGM-TRN-05": "AISF-08",
}
SOURCE_METADATA = (
    "source_check_id",
    "source_owner",
    "source_finding_details",
    "source_alias_only",
    "source_evidence_gap",
    "source_presentation",
    "source_presentations",
)


def value(row: dict, key: str, default: str = "") -> str:
    if key == "Finding_Details" and "details" in row:
        return str(row.get(key, row.get(key.lower(), row["details"])) or default)
    return str(row.get(key, row.get(key.lower(), default)) or default)


def observation_key(row: dict) -> str:
    """Only identical evidence may collapse; conflicting outcomes must survive."""
    return json.dumps(
        {
            key.lower(): val
            for key, val in row.items()
            if key not in ("_artifact", "_artifact_region", "_service", "service")
        },
        sort_keys=True,
        ensure_ascii=False,
    )


def _mapping_bundle() -> tuple[dict, str]:
    content = (CATALOG_DIRECTORY / "mapping.json").read_bytes()
    ledger = json.loads(content)
    catalog = load_catalog()
    if ledger["source_revision"] != catalog["manifest"]["source_revision"]:
        raise ValueError("Stale AISF mapping revision")
    entries = {entry["control_id"]: entry for entry in ledger["controls"]}
    if len(ledger["controls"]) != 218 or set(entries) != {
        control["id"] for control in catalog["controls"]
    }:
        raise ValueError("AISF mapping inventory mismatch")
    if any(
        entry["coverage"] not in ("partial", "absent") for entry in entries.values()
    ):
        raise ValueError(
            "Whole-control mapping requires independent predicate adjudication"
        )
    return ledger, hashlib.sha256(content).hexdigest()


def load_mapping() -> tuple[dict, str]:
    ledger, digest = _mapping_bundle()
    return {entry["control_id"]: entry for entry in ledger["controls"]}, digest


def source_check(row: dict) -> str:
    return row.get("source_check_id", value(row, "Check_ID"))


def source_details(row: dict) -> str:
    return row.get("source_finding_details", value(row, "Finding_Details"))


def matches_source(row: dict, source: dict) -> bool:
    """Compound checks contribute only the rows reviewed for this predicate."""
    if source_check(row) != source["check_id"]:
        return False
    filters = source.get("observation_filters", {})
    if set(filters) - {"finding_prefixes", "finding_equals", "details_contains"}:
        raise ValueError("Unsupported AISF observation filter")
    if row.get("source_alias_only") and (
        "finding_prefixes" in filters or "finding_equals" in filters
    ):
        # Lens/category CSVs discard the original Finding. Its value cannot be
        # recovered from the alias title or a check-level mapping.
        return False
    finding = value(row, "Finding")
    return (
        (
            "finding_prefixes" not in filters
            or any(finding.startswith(prefix) for prefix in filters["finding_prefixes"])
        )
        and ("finding_equals" not in filters or finding == filters["finding_equals"])
        and all(
            marker in source_details(row)
            for marker in filters.get("details_contains", [])
        )
    )


def _alias_source(row: dict, ledger: dict) -> tuple[str | None, str]:
    check = value(row, "Check_ID")
    aliases = ledger.get("source_aliases", {})
    categories = ledger.get("category_aliases", {})
    if check not in aliases and check not in categories:
        return check, ""
    match = re.search(
        r"\bSource check ([A-Z]+-\d{2}): (.*)", value(row, "Finding_Details"), re.S
    )
    allowed = [aliases[check]] if check in aliases else categories[check]
    if not match or match[1] not in allowed or match[1] not in SOURCE_IDS:
        return None, "Lens/category observation has no verified native source marker."
    return match[1], match[2]


def _projection_key(row: dict) -> tuple:
    """Fields retained by the producers' documented lens/category projection."""
    return (
        source_check(row),
        value(row, "Account_ID"),
        value(row, "Region"),
        value(row, "Execution_ID"),
        value(row, "Status"),
        # The OWASP projection intentionally changes N/A severity to
        # Informational. The original native row keeps its actual severity.
        "" if value(row, "Status") == "N/A" else value(row, "Severity"),
        source_details(row),
    )


def _collapse_aliases(rows: list[dict]) -> list[dict]:
    native = {}
    aliases = {}
    for row in sorted(rows, key=observation_key):
        target = aliases if row.get("source_alias_only") else native
        target.setdefault(_projection_key(row), []).append(row)
    result = []
    for key in sorted(set(native) | set(aliases)):
        sources = native.get(key, [])
        presentations = aliases.get(key, [])
        if sources:
            # The native rows retain their own Finding, action and any extra
            # resource/error fields. Differing native rows never collapse.
            if presentations:
                sources[0]["source_presentations"] = [
                    row["source_presentation"] for row in presentations
                ]
            result.extend(sources)
        elif presentations:
            row = presentations[0]
            row["source_presentations"] = [
                presentation["source_presentation"] for presentation in presentations
            ]
            result.append(row)
    return sorted(result, key=observation_key)


def evidence_unavailable(row: dict) -> bool:
    text = (value(row, "Finding") + " " + value(row, "Finding_Details")).lower()
    return any(
        word in text
        for word in (
            "accessdenied",
            "access denied",
            "permission denied",
            "unsupported",
            "unavailable",
            "incomplete",
            "pagination",
            "truncated",
            "timeout",
            "safety cap",
            "could not assess",
            "could not be assessed",
            "could not read",
            "could not be read",
            "not in the iam permissions cache",
        )
    )


def evidence_kind(row: dict) -> str:
    status = value(row, "Status").lower()
    text = (value(row, "Finding") + " " + value(row, "Finding_Details")).lower()
    if evidence_unavailable(row):
        return "unavailable"
    if status == "failed":
        return "failed predicate"
    if status != "passed" and any(
        marker in text
        for marker in (
            "manual review required",
            "manual code review required",
            "manually verify",
            "advisory",
        )
    ):
        return "manual evidence required"
    if any(
        word in text
        for word in ("no resources", "no applicable", "not found", "empty inventory")
    ):
        return "no resource observation"
    if status == "passed":
        return "passed predicate"
    return "inconclusive"


def build_aisf_register(
    findings: list[dict],
    *,
    accounts: list[str],
    regions: list[str],
    service_selection: dict | None = None,
    artifact_issues: list[dict] | None = None,
    execution_id: str = "",
    scopes: list[dict] | None = None,
    enable_grc: bool = False,
    enable_owasp: bool = False,
    enable_aisf: bool = False,
) -> dict:
    """Represent every control without equating mapped evidence with proof."""
    catalog = load_catalog()
    ledger, mapping_digest = _mapping_bundle()
    mappings = {entry["control_id"]: entry for entry in ledger["controls"]}
    selection = {
        service: (service_selection or {}).get(service, True) for service in SERVICES
    }
    selection.update(
        {"responsible-ai-grc": enable_grc or enable_owasp, "owasp": enable_owasp}
    )
    issues = list(artifact_issues or [])
    accounts = sorted(set(accounts or ["Unknown"]))
    regions = sorted(set(regions) - {"Global"})
    scope_list = scopes or [
        {"account": account, "region": region, "execution_id": execution_id}
        for account in accounts
        for region in (regions or ["Unspecified"])
    ]
    scope_list = [dict(scope) for scope in scope_list]
    accepted = {}
    rejected = []
    for original in findings:
        row = dict(original)
        supplied_metadata = {key: row.pop(key) for key in SOURCE_METADATA if key in row}
        if supplied_metadata:
            row["input_source_metadata"] = supplied_metadata
        check = value(row, "Check_ID")
        if check.startswith("AISF-"):
            continue
        account = value(row, "Account_ID")
        region = value(row, "Region")
        owner = SOURCE_IDS.get(check)
        if not owner:
            rejected.append(
                {"reason": "unknown or retired source ID", "observation": row}
            )
            continue
        candidates = [
            scope
            for scope in scope_list
            if scope["account"] == account
            and (scope["region"] == region or region == "Global")
        ]
        row_execution = value(row, "Execution_ID")
        candidate_executions = {scope.get("execution_id", "") for scope in candidates}
        if not row_execution and len(candidate_executions) > 1:
            rejected.append(
                {"reason": "ambiguous execution identity", "observation": row}
            )
            continue
        matching_scopes = [
            scope
            for scope in candidates
            if (
                not row_execution
                or not scope.get("execution_id")
                or row_execution == scope["execution_id"]
            )
        ]
        artifact_owner = row.get("_owner", owner)
        if not matching_scopes or artifact_owner != owner:
            rejected.append(
                {
                    "reason": "account/region/execution/owner mismatch",
                    "observation": row,
                }
            )
            continue
        if not selection.get(owner, True):
            rejected.append({"reason": "source owner not selected", "observation": row})
            continue
        native_check, native_details = _alias_source(row, ledger)
        if native_check is None:
            rejected.append({"reason": native_details, "observation": row})
            continue
        native_owner = SOURCE_IDS[native_check]
        if not selection.get(native_owner, False):
            rejected.append(
                {"reason": "native source owner not selected", "observation": row}
            )
            continue
        if native_check != check:
            row.update(
                source_check_id=native_check,
                source_owner=native_owner,
                source_finding_details=native_details,
                source_alias_only=True,
                source_presentation=dict(original),
                source_evidence_gap=(
                    "Only a lens/category projection is available. Obtain the original "
                    f"{native_check} row, including its Finding, resources and source action."
                ),
            )
        row["evidence_kind"] = evidence_kind(row)
        row["observed_failure"] = value(row, "Status").lower() == "failed"
        row["unavailable"] = evidence_unavailable(row)
        accepted.setdefault(observation_key(row), row)
        if region == "Global":
            for matching in matching_scopes:
                global_scope = {
                    "account": account,
                    "region": "Global",
                    "execution_id": matching.get("execution_id", ""),
                }
                if global_scope not in scope_list:
                    scope_list.append(global_scope)
    observations = _collapse_aliases(list(accepted.values()))
    controls = []
    for canonical in catalog["controls"]:
        control_id = canonical["id"]
        mapping = mappings[control_id]
        owners = mapping["owners"]
        selected_owners = [owner for owner in owners if selection.get(owner, True)]
        deselected_owners = [
            owner for owner in owners if not selection.get(owner, True)
        ]
        checks = {source["check_id"] for source in mapping["source_checks"]}
        outcomes = []
        control_scopes = list(scope_list)
        if any(
            "global" in source["scope"] and selection.get(source["owner"], True)
            for source in mapping["source_checks"]
        ):
            for scope in scope_list:
                global_scope = {**scope, "region": "Global"}
                if global_scope not in control_scopes:
                    control_scopes.append(global_scope)
        for scope in sorted(
            control_scopes,
            key=lambda s: (s["account"], s["region"], s.get("execution_id", "")),
        ):
            rows = [
                row
                for row in observations
                if value(row, "Account_ID") == scope["account"]
                and value(row, "Region") == scope["region"]
                and any(
                    matches_source(row, source) for source in mapping["source_checks"]
                )
                and (
                    not value(row, "Execution_ID")
                    or not scope.get("execution_id")
                    or value(row, "Execution_ID") == scope["execution_id"]
                )
            ]
            relevant_issues = [
                issue
                for issue in issues
                if issue.get("account", "") in ("", scope["account"])
                and issue.get("region", scope["region"])
                in (scope["region"], "Global", "")
                and issue.get("owner", "") in ("", *selected_owners)
                and (
                    not issue.get("execution_id")
                    or not scope.get("execution_id")
                    or issue["execution_id"] == scope["execution_id"]
                )
            ]
            missing_checks = sorted(
                source["check_id"]
                for source in mapping["source_checks"]
                if selection.get(source["owner"], True)
                and (
                    source["scope"] == "global-and-regional"
                    or (source["scope"] == "global") == (scope["region"] == "Global")
                )
                and not any(matches_source(row, source) for row in rows)
            )
            gaps = list(mapping["uncovered_predicates"])
            gaps.extend(
                row["source_evidence_gap"]
                for row in rows
                if row.get("source_evidence_gap")
            )
            if missing_checks:
                gaps.append(
                    "Gather missing source observations in this scope: "
                    + ", ".join(missing_checks)
                )
            if deselected_owners:
                gaps.append("Not selected: " + ", ".join(deselected_owners))
            if not rows:
                gaps.append(
                    "No source observations in this account and region. "
                    + mapping["required_proof"]
                )
            gaps.extend(issue["message"] for issue in relevant_issues)
            kinds = Counter(row["evidence_kind"] for row in rows)
            observed_failure = any(row["observed_failure"] for row in rows)
            violation = any(
                row["evidence_kind"] == "failed predicate"
                and not row.get("source_alias_only")
                and any(
                    matches_source(row, source)
                    and source.get("failure_proves_violation", False)
                    for source in mapping["source_checks"]
                )
                for row in rows
            )
            incomplete = bool(
                gaps
                or relevant_issues
                or kinds["unavailable"]
                or kinds["inconclusive"]
                or kinds["manual evidence required"]
                or kinds["no resource observation"]
            )
            if not selected_owners:
                status = "Not selected"
                rows = []
            elif violation:
                status = "Failed"
            elif relevant_issues or kinds["unavailable"]:
                status = "Unavailable"
            elif not checks:
                status = (
                    "No collector"
                    if catalog["classifications"][control_id]["machine_checkable"]
                    else "Manual evidence"
                )
                if status == "No collector":
                    gaps.append(
                        "This machine-classified control has no mapped collector. "
                        "Gather the required proof independently; classification is not coverage."
                    )
            elif rows:
                # The reviewed ledger never delegates application/process proof
                # to a source status. A future complete predicate needs a new
                # adjudicator and independent proof tests before allowing pass.
                status = "Partial evidence"
            else:
                status = "Missing evidence"
            if kinds["unavailable"]:
                gaps.append(
                    "Restore access/availability and rerun affected source checks; retain prior findings."
                )
            if kinds["inconclusive"] or kinds["no resource observation"]:
                gaps.append(
                    "Confirm applicability and complete discovery; N/A is not control proof."
                )
            for row in rows:
                if row["evidence_kind"] == "manual evidence required":
                    gaps.append(
                        f"Supply manual source proof for {source_check(row)}: "
                        + source_details(row)
                    )
            if observed_failure and not violation:
                gaps.append(
                    "A source check failed. Review its concrete evidence against the canonical "
                    "requirement; the source predicate alone does not establish a control violation."
                )
            actions = []
            for row in rows:
                if value(row, "Status").lower() != "passed":
                    action = value(row, "Resolution")
                    if action and not action.lower().startswith("no action"):
                        actions.append(action)
                    actions.extend(
                        value(presentation, "Resolution")
                        for presentation in row.get("source_presentations", [])
                        if value(presentation, "Resolution")
                        and not value(presentation, "Resolution")
                        .lower()
                        .startswith("no action")
                    )
            if status != "Passed":
                actions.extend(step["do"] for step in canonical.get("steps", []))
                actions.extend(gaps)
            outcomes.append(
                {
                    **scope,
                    "status": status,
                    "incomplete": incomplete,
                    "observed_failure": observed_failure,
                    "proven_violation": violation,
                    "selected_owners": selected_owners,
                    "unselected_owners": deselected_owners,
                    "observations": rows,
                    "missing_proof": list(dict.fromkeys(gaps)),
                    "actions": list(dict.fromkeys(actions)),
                }
            )
        priorities = (
            "Failed",
            "Unavailable",
            "Partial evidence",
            "Missing evidence",
            "No collector",
            "Manual evidence",
            "Not selected",
        )
        status = next(
            (
                state
                for state in priorities
                if any(o["status"] == state for o in outcomes)
            ),
            "Missing evidence",
        )
        controls.append(
            {
                "control_id": control_id,
                "legacy_check_id": ALIASES.get(control_id),
                "canonical": canonical,
                "mapping": mapping,
                "classification": catalog["classifications"][control_id],
                "status": status,
                "incomplete": any(o["incomplete"] for o in outcomes),
                "observed_failure": any(o["observed_failure"] for o in outcomes),
                "proven_violation": any(o["proven_violation"] for o in outcomes),
                "scopes": outcomes,
            }
        )
    return {
        "schema_version": 1,
        "source_revision": catalog["manifest"]["source_revision"],
        "catalog_sha256": catalog["manifest"]["outputs"]["controls.json"],
        "mapping_sha256": mapping_digest,
        "controls": controls,
        "scope": {
            "accounts": accounts,
            "regions": regions,
            "service_selection": {service: selection[service] for service in SERVICES},
            "source_selection": selection,
            "enable_grc": enable_grc,
            "enable_owasp": enable_owasp,
            "enable_aisf": enable_aisf,
        },
        "assessment_scopes": scope_list,
        "source_observations": observations,
        "artifact_issues": issues,
        "rejected_observations": rejected,
        "summary": {
            "canonical_controls": len(controls),
            "selected_controls": sum(c["status"] != "Not selected" for c in controls),
            "controls_with_observations": sum(
                any(s["observations"] for s in c["scopes"]) for c in controls
            ),
            "whole_control_passes": 0,
            "machine_classified_controls": sum(
                c["classification"]["machine_checkable"] for c in controls
            ),
            "mapped_controls": sum(
                bool(c["mapping"]["source_checks"]) for c in controls
            ),
            "outcomes": dict(Counter(c["status"] for c in controls)),
        },
    }


def _source_field(row: dict, *names: str) -> object:
    for name in names:
        for key in (name, name.lower()):
            if key in row:
                return row[key]
    return ""


def build_aisf_check_results(register: dict) -> dict:
    """Project accepted check observations without inventing canonical outcomes."""
    mappings, _ = load_mapping()
    inventory = {
        check["check_id"]: check
        for check in json.loads(
            (CATALOG_DIRECTORY / "check_inventory.json").read_bytes()
        )["checks"]
        if check["kind"] == "native"
    }
    by_source = {}
    for mapping in mappings.values():
        for source in mapping["source_checks"]:
            by_source.setdefault(source["check_id"], []).append((mapping, source))
    checks = []
    gaps = []
    for row in register["source_observations"]:
        check_id = source_check(row)
        if check_id not in inventory:
            gaps.append(
                {
                    "kind": "collection-advisory",
                    "message": "The collector emitted a discovery or operational signal rather than a native workload check. Its original outcome and details are retained.",
                    "owner": SOURCE_IDS.get(value(row, "Check_ID"), ""),
                    "source_check_id": check_id,
                    "account": value(row, "Account_ID"),
                    "region": value(row, "Region"),
                    "execution_id": value(row, "Execution_ID"),
                    "observation": dict(row),
                }
            )
            continue
        check = inventory[check_id]
        links = []
        for mapping, source in by_source.get(check_id, []):
            if matches_source(row, source):
                links.append(
                    {
                        "control_id": mapping["control_id"],
                        "question": mapping["canonical_question"],
                        "coverage": mapping["coverage"],
                        "covered_predicates": source["covered_predicates"],
                        "limitations": source["limitations"],
                    }
                )
        links.sort(key=lambda item: item["control_id"])
        kind = row["evidence_kind"]
        result_kind = (
            "unavailable"
            if row["unavailable"]
            else "source-advisory"
            if kind == "manual evidence required"
            or check["evidence_kind"] == "manual evidence required"
            else "source-result"
        )
        unmapped = ""
        if not links:
            unmapped = check.get("exclusion_reason") or (
                "This observation does not match a reviewed AISF predicate filter."
                if by_source.get(check_id)
                else "No reviewed AISF mapping is established for this source check."
            )
        result = {
            "result_id": hashlib.sha256(observation_key(row).encode()).hexdigest(),
            "source_check_id": check_id,
            "source_owner": check["owner"],
            "account": value(row, "Account_ID"),
            "region": value(row, "Region"),
            "execution_id": value(row, "Execution_ID"),
            "status": value(row, "Status"),
            "severity": value(row, "Severity"),
            "finding": value(row, "Finding"),
            "finding_details": source_details(row),
            "resource": _source_field(row, "Resource_ID", "Resource", "Resources"),
            "action_required": _source_field(
                row, "Resolution", "Action_Required", "Action"
            ),
            "reference": _source_field(row, "Reference"),
            "observation": dict(row),
            "evidence_kind": kind,
            "result_kind": result_kind,
            "predicate": check["predicate"],
            "limitations": check["limitations"],
            "aisf_control_ids": [link["control_id"] for link in links],
            "aisf_links": links,
            "unmapped_reason": unmapped,
        }
        checks.append(result)
        identity = {
            "account": result["account"],
            "region": result["region"],
            "execution_id": result["execution_id"],
            "owner": result["source_owner"],
            "source_check_id": check_id,
            "result_id": result["result_id"],
        }
        if row["unavailable"]:
            gaps.append(
                {
                    "kind": "unavailable-observation",
                    "message": "The source reports unavailable or incomplete evidence; its original status is retained.",
                    **identity,
                }
            )
        if row.get("source_alias_only"):
            gaps.append(
                {
                    "kind": "alias-only",
                    "message": row["source_evidence_gap"],
                    **identity,
                }
            )
    scope = register["scope"]
    for owner, selected in scope["source_selection"].items():
        if not selected:
            gaps.append(
                {
                    "kind": "source-not-selected",
                    "owner": owner,
                    "message": "This collector was not selected; its AI workload checks are outside this execution's scope.",
                }
            )
    # Artifact issues identify unavailable deliveries. Also expose a selected
    # source with no accepted observation, without inventing a check outcome.
    scopes = register.get("assessment_scopes") or [
        {"account": account, "region": region, "execution_id": ""}
        for account in scope["accounts"]
        for region in (scope["regions"] or ["Unspecified"])
    ]
    delivered = []
    for row in register["source_observations"]:
        delivered.append(row)
        delivered.extend(row.get("source_presentations", []))
    checked_deliveries = set()
    for selected_scope in scopes:
        if selected_scope["region"] == "Global":
            continue
        for owner, selected in scope["source_selection"].items():
            if not selected:
                continue
            # GRC has one unsuffixed artifact per account/execution, produced at
            # RegionIndex 0. Its rows retain their actual regional or global scope.
            delivery_scope = {
                **selected_scope,
                "region": ""
                if owner == "responsible-ai-grc"
                else selected_scope["region"],
            }
            delivery_key = (
                owner,
                delivery_scope["account"],
                delivery_scope["region"],
                delivery_scope.get("execution_id", ""),
            )
            if delivery_key in checked_deliveries:
                continue
            checked_deliveries.add(delivery_key)
            if any(
                SOURCE_IDS.get(value(row, "Check_ID")) == owner
                and value(row, "Account_ID") == selected_scope["account"]
                and (
                    owner == "responsible-ai-grc"
                    or value(row, "Region") == selected_scope["region"]
                )
                and (
                    not selected_scope.get("execution_id")
                    or not value(row, "Execution_ID")
                    or value(row, "Execution_ID") == selected_scope["execution_id"]
                )
                for row in delivered
            ):
                continue
            gaps.append(
                {
                    "kind": "source-absent",
                    "owner": owner,
                    **delivery_scope,
                    "message": (
                        "No accepted source observations were delivered for this selected collector and scope. "
                        + (
                            "GRC is collected once per account/execution in the first selected region. "
                            if owner == "responsible-ai-grc"
                            else ""
                        )
                        + "Check its execution and artifacts; absence is not a Passed or N/A result."
                    ),
                }
            )
    for issue in register["artifact_issues"]:
        gaps.append(
            {
                "kind": "artifact-issue",
                "issue": issue,
                "message": issue.get("message", "Artifact could not be accepted."),
                **{
                    key: issue[key]
                    for key in ("account", "region", "execution_id", "owner")
                    if key in issue
                },
            }
        )
    for rejected in register["rejected_observations"]:
        gaps.append(
            {
                "kind": "rejected-observation",
                "message": rejected["reason"],
                "observation": rejected["observation"],
            }
        )
    return {
        "schema_version": 2,
        "view": "automated-check-results",
        **{
            key: register[key]
            for key in ("source_revision", "catalog_sha256", "mapping_sha256", "scope")
        },
        "checks": checks,
        "gaps": gaps,
        "artifact_issues": register["artifact_issues"],
        "rejected_observations": register["rejected_observations"],
        "summary": {
            "check_results": len(checks),
            "distinct_source_checks": len(
                {check["source_check_id"] for check in checks}
            ),
            "source_results": sum(
                check["result_kind"] == "source-result" for check in checks
            ),
            "source_advisories": sum(
                check["result_kind"] == "source-advisory" for check in checks
            ),
            "unavailable_results": sum(
                check["result_kind"] == "unavailable" for check in checks
            ),
            "mapped_results": sum(bool(check["aisf_links"]) for check in checks),
            "unmapped_results": sum(not check["aisf_links"] for check in checks),
            "statuses": dict(Counter(check["status"] for check in checks)),
            "gap_count": len(gaps),
        },
    }
