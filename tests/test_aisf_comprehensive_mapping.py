"""Independent native-source inventory and comprehensive AISF report acceptance."""

import ast
import copy
import csv
import io
import itertools
import json
import re

import pytest

from tests.report_browser import exercise_report

from tests.test_aisf_catalog_alignment import (
    ACCOUNT,
    EXECUTION,
    EXPECTED_IDS,
    OTHER_ACCOUNT,
    REGIONS,
    REPORT,
    ROOT,
    SERVICES,
    assert_check_inventory,
    controls,
    matching_checks,
    embedded_register,
    multi,
    observation,
    register,
    scope,
    single,
)

SECURITY = ROOT / "aiml-security-assessment/functions/security"

# Frozen from the source catalog, including its explicit retired/reserved IDs.
# These expectations never depend on AISF's implementation mapping.
NATIVE_IDS = {
    "BR": {f"BR-{n:02}" for n in range(1, 58)},
    "SM": {f"SM-{n:02}" for n in range(1, 44)} - {"SM-29"},
    "AC": {f"AC-{n:02}" for n in range(1, 54)},
    "AR": {f"AR-{n:02}" for n in range(1, 11)},
    "FS": {f"FS-{n:02}" for n in range(1, 70)}
    - {"FS-17", "FS-18", "FS-19", "FS-23", "FS-64"},
    "AG": {"AG-24", "AG-25", "AG-26", "AG-27", "AG-39"},
    "OW": {"OW-11", "OW-12"},
}
AG_ALIASES = {
    "AG-01": "BR-28",
    "AG-02": "BR-23",
    "AG-03": "BR-26",
    "AG-04": "BR-24",
    "AG-05": "BR-27",
    "AG-06": "BR-21",
    "AG-07": "BR-04",
    "AG-08": "BR-06",
    "AG-09": "BR-15",
    "AG-10": "BR-18",
    "AG-11": "BR-19",
    "AG-12": "BR-22",
    "AG-13": "BR-29",
    "AG-14": "BR-32",
    "AG-15": "AC-01",
    "AG-16": "AC-02",
    "AG-17": "AC-03",
    "AG-18": "AC-04",
    "AG-19": "AC-07",
    "AG-20": "AC-08",
    "AG-21": "AC-10",
    "AG-22": "AC-11",
    "AG-23": "AC-12",
    "AG-28": "AC-14",
    "AG-29": "AC-15",
    "AG-30": "BR-34",
    "AG-31": "AC-16",
    "AG-32": "AC-17",
    "AG-33": "AR-03",
    "AG-34": "AR-04",
    "AG-35": "AR-05",
    "AG-36": "AR-06",
    "AG-37": "AR-07",
    "AG-38": "AR-08",
}
PACKAGES = {
    "BR": "bedrock",
    "SM": "sagemaker",
    "AC": "agentcore",
    "AR": "agent_registry",
    "FS": "responsible_ai_grc",
    "OW": "owasp",
}
SOURCE_OWNERS = {
    "BR": "bedrock",
    "SM": "sagemaker",
    "AC": "agentcore",
    "AR": "agent-registry",
    "FS": "responsible-ai-grc",
    "AG": "agentcore",
    "OW": "owasp",
}
EXPECTED_EVIDENCE_CONTROL = {
    "BR-34": "AIR-BDR-GRD-02",
    "SM-18": "AIR-SGM-EP-08",
    "AC-20": "AIR-ACR-OBS-04",
    "AR-01": "AIR-FND-IAM-09",
    "FS-51": "AIR-BDR-GRD-02",
    "AG-25": "AIR-ACR-POL-01",
    "OW-11": "AIR-BDR-MDL-08",
    "OW-12": "AIR-BDR-GRD-02",
}


def source_ast(package):
    return ast.parse((SECURITY / f"{package}_assessments/app.py").read_text())


def literal_ids(tree, prefix):
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and re.fullmatch(rf"{prefix}-\d{{2}}", node.value)
        and not node.value.endswith("-00")
    }


def assignment(tree, name):
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        if any(isinstance(t, ast.Name) and t.id == name for t in targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f"Missing independent source contract {name}")


def test_source_and_presentation_inventory_reconcile_independently():
    for prefix, package in PACKAGES.items():
        if prefix != "OW":
            assert literal_ids(source_ast(package), prefix) == NATIVE_IDS[prefix]
    actual_aliases = {}
    all_ag = set()
    for package, name in (
        ("bedrock", "AGENTIC_BEDROCK_CHECK_MAPPINGS"),
        ("agentcore", "AGENTIC_AGENTCORE_CHECK_MAPPINGS"),
        ("agent_registry", "AGENTIC_AGENT_REGISTRY_CHECK_MAPPINGS"),
    ):
        tree = source_ast(package)
        all_ag |= literal_ids(tree, "AG")
        actual_aliases.update(
            {
                edge["check_id"]: source
                for source, edge in assignment(tree, name).items()
            }
        )
    assert actual_aliases == AG_ALIASES
    assert all_ag - set(actual_aliases) == NATIVE_IDS["AG"]
    owasp = assignment(source_ast("owasp"), "OWASP_CHECK_MAPPINGS")
    categories = {edge["check_id"] for edges in owasp.values() for edge in edges}
    assert categories == {f"OW-{n:02}" for n in range(1, 11)}
    assert literal_ids(source_ast("owasp"), "OW") - categories == NATIVE_IDS["OW"]
    assert len(owasp) == 84
    assert sum(map(len, owasp.values())) == 95
    assert sum(map(len, NATIVE_IDS.values())) == 233
    assert len(actual_aliases) + len(categories) == 44
    assert len(set.union(*NATIVE_IDS.values()) | all_ag | categories) == 277
    assert len(EXPECTED_IDS) == len(set(EXPECTED_IDS)) == 218


def test_catalog_documents_the_same_source_inventory():
    direct_catalog = (ROOT / "docs/SECURITY_CHECKS.md").read_text()
    for prefix in ("BR", "SM", "AC", "AR"):
        headings = set(
            re.findall(rf"^#{{2,6}}\s+({prefix}-\d{{2}})\b", direct_catalog, re.M)
        )
        assert headings == NATIVE_IDS[prefix]
    grc_catalog = (ROOT / "docs/SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md").read_text()
    headings = set(re.findall(r"^#{2,6}\s+(FS-\d{2})\b", grc_catalog, re.M))
    retired = {"FS-00", "FS-17", "FS-18", "FS-19", "FS-23", "FS-64"}
    assert headings - retired == NATIVE_IDS["FS"]


def test_exhaustive_ledger_accounts_for_native_checks_and_actual_aliases():
    package = REPORT / "aisf_catalog"
    inventory = json.loads((package / "check_inventory.json").read_text())
    mapping = json.loads((package / "mapping.json").read_text())
    records = inventory["checks"]
    by_id = {record["check_id"]: record for record in records}
    native = set.union(*NATIVE_IDS.values())
    categories = {f"OW-{n:02}" for n in range(1, 11)}
    assert len(records) == len(by_id) == 277
    assert set(by_id) == native | set(AG_ALIASES) | categories
    assert {key for key, row in by_id.items() if row["kind"] == "native"} == native
    assert {key for key, row in by_id.items() if row["kind"] == "alias"} == (
        set(AG_ALIASES) | categories
    )

    control_map = {item["control_id"]: item for item in mapping["controls"]}
    assert set(control_map) == set(EXPECTED_IDS)
    mapped_edges = {
        (control_id, source["check_id"])
        for control_id, item in control_map.items()
        for source in item["source_checks"]
    }
    ledger_edges = set()
    for check_id, row in by_id.items():
        assert row["predicate"] and row["limitations"]
        assert row["code_witnesses"], f"No concrete source for {check_id}"
        for witness in row["code_witnesses"]:
            source_lines = (ROOT / witness["path"]).read_text().splitlines()
            assert 1 <= witness["line"] <= witness["end_line"] <= len(source_lines)
            source_excerpt = "\n".join(
                source_lines[witness["line"] - 1 : witness["end_line"]]
            )
            assert witness["function"] in source_excerpt
        for link in row["canonical_links"]:
            assert link["control_id"] in EXPECTED_IDS
            assert link["canonical_relation"] and link["limitations"]
            assert link["coverage"] == "partial"
            assert link["failure_proves_violation"] is False
        if check_id not in native:
            assert row["disposition"] == "derived presentation"
            assert row["exclusion_reason"]
            continue
        assert row["collector_status"] in {"active", "inactive"}
        if row["canonical_links"]:
            assert row["disposition"] == "partial"
            ledger_edges.update(
                (link["control_id"], check_id) for link in row["canonical_links"]
            )
        else:
            assert row["disposition"] == "excluded"
            assert row["exclusion_reason"].strip()
    assert ledger_edges == mapped_edges
    assert all(check_id in native for _, check_id in mapped_edges)
    assert by_id["BR-14"]["collector_status"] == "inactive"
    assert "commented out" in by_id["BR-14"]["collector_reason"]

    # Alias relations are read from the producer AST, never inferred from AISF.
    assert mapping["source_aliases"] == AG_ALIASES
    for alias, source in AG_ALIASES.items():
        assert by_id[alias]["source_check_ids"] == [source]
        assert by_id[alias]["canonical_links"] == by_id[source]["canonical_links"]
    actual_categories = assignment(source_ast("owasp"), "OWASP_CHECK_MAPPINGS")
    for category in categories:
        expected = {
            source
            for source, links in actual_categories.items()
            if any(link["check_id"] == category for link in links)
        }
        assert set(by_id[category]["source_check_ids"]) == expected
        assert set(mapping["category_aliases"][category]) == expected
        expected_links = {
            (source, link["control_id"])
            for source in expected
            for link in by_id[source]["canonical_links"]
        }
        assert {
            (link["source_check_id"], link["control_id"])
            for link in by_id[category]["canonical_links"]
        } == expected_links
        for edge in by_id[category]["source_edges"]:
            producer_edge = next(
                item
                for item in actual_categories[edge["source_check_id"]]
                if item["check_id"] == category
            )
            assert edge["source_finding_prefixes"] == list(
                producer_edge.get("source_finding_prefixes", [])
            )

    counts = inventory["counts"]
    mapped_native = {source for _, source in ledger_edges}
    mapped_controls = {control for control, _ in ledger_edges}
    assert counts["native_checks_reviewed"] == len(native)
    assert counts["presentation_aliases"] == len(AG_ALIASES) + len(categories)
    assert counts["presentation_ids"] == len(by_id)
    assert counts["source_checks"] == len(mapped_native)
    assert counts["source_edges"] == len(ledger_edges)
    assert counts["native_checks_excluded"] == len(native - mapped_native)
    assert counts["mapped_controls"] == len(mapped_controls)
    assert counts["unmapped_controls"] == len(set(EXPECTED_IDS) - mapped_controls)
    assert counts["complete"] == 0


def native_rows():
    """Real predicate titles prevent filtered compound checks being overcredited."""
    facts = {
        "BR-34": (
            "Deployed Guardrail Prompt Attack Filter",
            "Synthetic deployed guardrail version lacks a preventive PROMPT_ATTACK input filter.",
            "Add a PROMPT_ATTACK filter and test its use by the application.",
        ),
        "SM-18": (
            "SageMaker Transform Job Output Key and Model Boundary",
            "Transform job 'synthetic-transform' has no output customer-managed key.",
            "Run the transform job with a customer-managed output key.",
        ),
        "AC-20": (
            "AgentCore Log Data Protection",
            "Log group 'synthetic-log' has no data-protection policy that de-identifies log events.",
            "Set a log data protection policy and test masking.",
        ),
        "AR-01": (
            "AWS Agent Registry IAM Wildcard Permissions",
            "Synthetic role has wildcard AWS Agent Registry permissions on every resource.",
            "Replace wildcard permissions with required registry actions and scoped resources.",
        ),
        "FS-51": (
            "No Guardrails With Prompt Attack Filters",
            "Found 1 guardrail(s) but none have PROMPT_ATTACK filters.",
            "Add PROMPT_ATTACK filtering and review application coverage.",
        ),
        "AG-25": (
            "Agentic AI Gateway Tool Policy Enforcement Missing",
            "Gateway 'synthetic-gateway' does not have a policy engine configuration.",
            "Attach an AgentCore policy engine and use ENFORCE mode.",
        ),
        "OW-11": (
            "OWASP LLM07: System Prompt Embedded in Lambda Env Var",
            "Synthetic Lambda uses a SYSTEM_PROMPT environment variable.",
            "Remove the prompt from environment variables and review access.",
        ),
        "OW-12": (
            "OWASP LLM07: System-Prompt-Disclosure Denied Topic",
            "No account guardrail has a system-prompt-disclosure denied topic.",
            "Add a disclosure-denying topic and verify application invocation.",
        ),
    }
    return [
        observation(
            check,
            "Failed",
            Finding=finding,
            Finding_Details=details,
            Resolution=action,
            Resource_ID=f"synthetic-resource-{check}",
            region="Global" if check == "AR-01" else REGIONS[0],
        )
        for check, (finding, details, action) in facts.items()
    ]


def report_pair(tmp_path, rows, *, selection=None, grc=True, owasp=True, aisf=False):
    selection = selection or dict.fromkeys(SERVICES, True)
    enabled = [owner for owner, selected in selection.items() if selected]
    if grc or owasp:
        enabled.append("responsible-ai-grc")
    if owasp:
        enabled.append("owasp")
    assessment = {
        "account_id": ACCOUNT,
        "execution_id": EXECUTION,
        "expected_regions": REGIONS,
        "timestamp": "2026-01-01T00:00:00Z",
        "enable_owasp": owasp,
    }
    for account in (ACCOUNT, OTHER_ACCOUNT):
        directory = tmp_path / account
        directory.mkdir()
        for owner in enabled:
            assessment.setdefault(owner, {})
            for region in REGIONS:
                if owner == "responsible-ai-grc" and region != REGIONS[0]:
                    continue
                accepted = [
                    {**row, "Account_ID": account}
                    for row in rows
                    if source_owner(row["Check_ID"]) == owner
                    and (
                        row["Region"] == region
                        or owner == "responsible-ai-grc"
                        or (row["Region"] == "Global" and region == REGIONS[0])
                    )
                ]
                if not accepted:
                    prefix = next(p for p, o in SOURCE_OWNERS.items() if o == owner)
                    accepted = [
                        observation(
                            prefix + "-00",
                            "N/A",
                            account=account,
                            region=region,
                            Finding="Assessment complete",
                            Finding_Details="Synthetic empty discovery completed.",
                        )
                    ]
                suffix = "" if owner == "responsible-ai-grc" else "_" + region
                stem = f"{owner.replace('-', '_')}_security_report_{EXECUTION}{suffix}"
                (directory / (stem + ".csv")).write_text(source_csv(accepted))
                if account == ACCOUNT:
                    assessment[owner][stem] = accepted
    manifest = {
        "schema_version": 1,
        "accounts": [
            {
                "account_id": account,
                "execution_id": EXECUTION,
                "regions": REGIONS,
                "status": "SUCCEEDED",
            }
            for account in (ACCOUNT, OTHER_ACCOUNT)
        ],
    }
    single_html = single.generate_html_report(
        assessment, show_finserv=grc, service_selection=selection, enable_aisf=aisf
    )
    multi_result = multi.load_multi_account_results(
        tmp_path,
        scope_manifest=manifest,
        service_selection=selection,
        show_finserv=grc,
        enable_owasp=owasp,
        enable_aisf=aisf,
        timestamp=assessment["timestamp"],
    )
    return single_html, multi.render_multi_account_report(multi_result)


def source_csv(rows):
    stream = io.StringIO(newline="")
    columns = list(dict.fromkeys(key for row in rows for key in row))
    writer = csv.DictWriter(stream, fieldnames=columns)
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def downloaded_exports(html):
    result = exercise_report(
        html,
        [
            {"type": "filter-button", "service": "aisf", "status": "failed"},
            {"type": "click", "id": "aisf-json"},
            {"type": "click", "id": "aisf-csv"},
        ],
    )
    checks = iter(embedded_register(html)["checks"])
    identities = {
        row["index"]: next(checks)["result_id"]
        for row in result["rows"]
        if row["dataset"].get("aisfResult") == "true"
    }
    result["visible"] = [
        identities[index] for index in result["snapshots"][1]["visible"]
    ]
    result["json"] = json.loads(result["downloads"]["aisf-checks.json"])
    result["csv"] = list(
        csv.DictReader(io.StringIO(result["downloads"]["aisf-checks.csv"]))
    )
    return result


def csv_check(exported, item):
    return next(
        row
        for row in exported["csv"]
        if row["Record_Type"] == "check"
        and row["Check_ID"] == item["source_check_id"]
        and row["Account_ID"] == item["account"]
        and row["Region"] == item["region"]
        and row["Status"] == item["status"]
    )


def assert_downloaded_check(exported, item):
    row = csv_check(exported, item)
    assert json.loads(row["Observation"]) == item["observation"]
    assert json.loads(row["AISF_Control_IDs"]) == item["aisf_control_ids"]
    assert json.loads(row["AISF_Mappings"]) == item["aisf_links"]
    for column, field in (
        ("Check_ID", "source_check_id"),
        ("Status", "status"),
        ("Severity", "severity"),
        ("Account_ID", "account"),
        ("Region", "region"),
        ("Execution_ID", "execution_id"),
        ("Finding", "finding"),
        ("Finding_Details", "finding_details"),
        ("Resource_ID", "resource"),
        ("Resolution", "action_required"),
        ("Reference", "reference"),
        ("Result_Kind", "result_kind"),
        ("Evidence_Kind", "evidence_kind"),
        ("Unmapped_Reason", "unmapped_reason"),
    ):
        assert row[column] == str(item[field]), (item["source_check_id"], column)
    for column, key in (
        ("Source_revision", "source_revision"),
        ("Catalog_SHA256", "catalog_sha256"),
        ("Mapping_SHA256", "mapping_sha256"),
    ):
        assert row[column] == exported["json"][key]


def matching_scopes(result, check):
    return [
        (control, scoped)
        for control in result["controls"]
        for scoped in control["scopes"]
        if any(
            row.get("source_check_id", row["Check_ID"]) == check
            for row in scoped["observations"]
        )
    ]


def source_owner(check):
    source = AG_ALIASES.get(check, check)
    return SOURCE_OWNERS[source.split("-")[0]]


def test_every_native_family_failure_reaches_both_reports_and_real_downloads(tmp_path):
    rows = native_rows()
    for html in report_pair(tmp_path, rows):
        exported = downloaded_exports(html)
        result = exported["json"]
        assert_check_inventory(result)
        assert {item["source_check_id"] for item in result["checks"]} == {
            row["Check_ID"] for row in rows
        }
        assert {
            row["Check_ID"] for row in exported["csv"] if row["Record_Type"] == "check"
        } == {row["Check_ID"] for row in rows}
        assert set(exported["visible"]) == {
            item["result_id"] for item in result["checks"] if item["status"] == "Failed"
        }
        for original in rows:
            check = original["Check_ID"]
            found = matching_checks(result, check)
            assert found, f"Source family evidence lost: {check}"
            for item in found:
                assert EXPECTED_EVIDENCE_CONTROL[check] in item["aisf_control_ids"]
                assert item["result_id"] in exported["visible"]
                assert item["status"] == "Failed"
                assert item["action_required"] == original["Resolution"]
                actual = item["observation"]
                for field in (
                    "Check_ID",
                    "Finding",
                    "Finding_Details",
                    "Resolution",
                    "Reference",
                    "Resource_ID",
                    "Status",
                    "Region",
                    "Execution_ID",
                ):
                    assert actual[field] == original[field], (check, field)
                assert actual["Account_ID"] == item["account"]
                assert_downloaded_check(exported, item)
                assert original["Finding"] in html
                assert original["Resource_ID"] in html
                assert original["Resolution"] in html


@pytest.mark.parametrize("flags", list(itertools.product((False, True), repeat=6)))
def test_all_64_selections_keep_selected_native_sources_in_both_paths(tmp_path, flags):
    selection = dict(zip(SERVICES, flags[:4]))
    grc, owasp = flags[4:]
    rows = native_rows()
    expected_checks = {
        row["Check_ID"]
        for row in rows
        if (
            (grc or owasp)
            if row["Check_ID"].startswith("FS-")
            else owasp
            if row["Check_ID"].startswith("OW-")
            else selection[SOURCE_OWNERS[row["Check_ID"].split("-")[0]]]
        )
    }
    for html in report_pair(tmp_path, rows, selection=selection, grc=grc, owasp=owasp):
        result = embedded_register(html)
        assert_check_inventory(result)
        assert {item["source_check_id"] for item in result["checks"]} == expected_checks
        assert all(item["status"] == "Failed" for item in result["checks"])
        assert all(
            result["scope"]["source_selection"][item["source_owner"]]
            for item in result["checks"]
        )


@pytest.mark.parametrize(
    "check,control_id,finding,terms",
    [
        (
            "FS-51",
            "AIR-BDR-GRD-02",
            "Guardrail Prompt Attack Filters Configured",
            ("prompt", "attack"),
        ),
        (
            "FS-45",
            "AIR-BDR-GRD-03",
            "Guardrail PII Filters Configured",
            ("pii",),
        ),
        (
            "FS-47",
            "AIR-BDR-GRD-09",
            "Guardrail Grounding Thresholds Appropriate",
            ("ground",),
        ),
        (
            "FS-50",
            "AIR-BDR-GRD-09",
            "Relevance Grounding Filters Present",
            ("relevance",),
        ),
    ],
)
def test_guardrail_presence_sources_are_relevant_but_never_whole_proof(
    check, control_id, finding, terms
):
    original = observation(check, "Passed", Finding=finding, Finding_Details=finding)
    control = controls(register([original], enable_grc=True))[control_id]
    scoped = scope(control)
    assert any(row["Check_ID"] == check for row in scoped["observations"])
    assert control["status"] != "Passed" and scoped["incomplete"]
    assert scoped["missing_proof"]
    proof = json.dumps(control["canonical"]).lower()
    assert all(term in proof for term in terms)
    assert not original["Resolution"] or original["Resolution"] not in scoped["actions"]


@pytest.mark.parametrize(
    "check,finding,details",
    [
        (
            "BR-24",
            "Automated Reasoning Policy Implementation Check",
            "1 guardrails have Automated Reasoning policies configured for formal verification",
        ),
        (
            "FS-27",
            "Automated Reasoning Policies Found",
            "Found 1 Automated Reasoning policy(ies): synthetic-rules. "
            "Verify policies are associated with active guardrails via the "
            "automatedReasoningPolicy field in GetGuardrail.",
        ),
    ],
)
def test_reasoning_configuration_keeps_source_pass_and_mapping_limitations(
    tmp_path, check, finding, details
):
    original = observation(
        check,
        "Passed",
        Finding=finding,
        Finding_Details=details,
        Resource_ID=f"synthetic-reasoning-{check}",
    )
    internal = register([original], enable_grc=True, enable_owasp=True)
    canonical = controls(internal)["AIR-BDR-GRD-09"]
    assert "response contradicts an encoded policy" in canonical["canonical"]["h"]
    assert "return verifiable explanations" in canonical["canonical"]["rec"]
    assert canonical["status"] == "Partial evidence"
    scoped = scope(canonical)
    gaps = " ".join(scoped["missing_proof"]).lower()
    for alternatives in (
        ("association", "associated", "production binding"),
        ("invocation", "applied to", "production use"),
        ("rule completeness", "complete encoded", "complete business rules"),
        ("response validation", "response example", "contradictory"),
    ):
        assert any(term in gaps for term in alternatives), (alternatives, gaps)
    for html in report_pair(tmp_path, [original]):
        exported = downloaded_exports(html)
        assert_check_inventory(exported["json"])
        for item in matching_checks(exported["json"], check):
            assert item["status"] == "Passed", (
                "Source predicate status must not be rewritten as a canonical task."
            )
            link = next(
                link
                for link in item["aisf_links"]
                if link["control_id"] == "AIR-BDR-GRD-09"
            )
            assert link["coverage"] == "partial"
            assert link["limitations"]
            assert item["finding_details"] == details
            assert_downloaded_check(exported, item)


@pytest.mark.parametrize(
    "check,finding,details",
    [
        (
            "FS-57",
            "ADVISORY: Output Encoding — Manual Review Required",
            "Output encoding practices cannot be verified via AWS APIs. Manual code review required.",
        ),
        (
            "FS-58",
            "ADVISORY: Output Schema Validation — Manual Review Required",
            "Structured-output / JSON-schema validation is application-layer evidence; manual review required.",
        ),
    ],
)
def test_manual_grc_findings_are_preserved_and_never_clean(
    tmp_path, check, finding, details
):
    original = observation(
        check,
        "N/A",
        Finding=finding,
        Finding_Details=details,
        Severity="Informational",
        Resolution="Review application output encoding and schema validation.",
    )
    for html in report_pair(tmp_path, [original], grc=False, owasp=True):
        exported = downloaded_exports(html)
        assert_check_inventory(exported["json"])
        found = matching_checks(exported["json"], check)
        assert found
        for item in found:
            assert "AIR-ACR-RT-05" in item["aisf_control_ids"]
            assert item["status"] == "N/A"
            assert item["severity"] == "Informational"
            assert item["finding_details"] == details
            assert item["evidence_kind"] == "manual evidence required"
            assert item["result_kind"] == "source-advisory"
            assert item["action_required"] == original["Resolution"]
            assert_downloaded_check(exported, item)


def alias_row(native, check):
    return {
        **native,
        "Check_ID": check,
        "Finding": "Lens/category presentation",
        "Finding_Details": (
            f"Derived presentation. Source check {native['Check_ID']}: "
            f"{native['Finding_Details']}"
        ),
        "Resource_ID": "",
        "Resolution": "Generic lens/category action.",
    }


def test_equivalent_aliases_deduplicate_but_conflicting_source_rows_survive(tmp_path):
    native = native_rows()[0]
    ag, ow = alias_row(native, "AG-30"), alias_row(native, "OW-01")
    passed = {**native, "Status": "Passed", "Resolution": ""}
    rows = [native, ag, ow, passed, alias_row(passed, "AG-30")]
    result = register(rows, enable_owasp=True)
    backward = register(list(reversed(rows)), enable_owasp=True)
    assert result == backward
    sources = [r for r in result["source_observations"] if r["Check_ID"] == "BR-34"]
    assert {r["Status"] for r in sources} == {"Passed", "Failed"}
    assert len(sources) == 2
    failed = next(r for r in sources if r["Status"] == "Failed")
    assert failed["Finding"] == native["Finding"]
    assert failed["Resource_ID"] == native["Resource_ID"]
    assert {r["Check_ID"] for r in failed["source_presentations"]} == {"AG-30", "OW-01"}
    for control, scoped in matching_scopes(result, "BR-34"):
        assert scoped["observed_failure"] and scoped["incomplete"]
        assert {r["Status"] for r in scoped["observations"]} == {"Passed", "Failed"}
        assert control["status"] != "Passed"
    for html in report_pair(tmp_path, rows):
        exported = downloaded_exports(html)
        actual = exported["json"]
        assert_check_inventory(actual)
        for account in actual["scope"]["accounts"]:
            found = matching_checks(actual, "BR-34", account=account)
            assert len(found) == 2
            assert {item["status"] for item in found} == {"Passed", "Failed"}
            failed = next(item for item in found if item["status"] == "Failed")
            assert {
                row["Check_ID"] for row in failed["observation"]["source_presentations"]
            } == {"AG-30", "OW-01"}
            for item in found:
                assert_downloaded_check(exported, item)


def test_gateway_debug_error_detail_is_preserved_without_false_telemetry_mapping(
    tmp_path,
):
    original = observation(
        "AG-26",
        "Failed",
        Finding="Agentic AI Gateway Debug Error Detail Enabled",
        Finding_Details="Gateway 'synthetic-gateway' returns DEBUG-level exception detail.",
        Resolution="Remove DEBUG exceptionLevel for production gateways.",
    )
    for html in report_pair(tmp_path, [original]):
        result = downloaded_exports(html)["json"]
        assert_check_inventory(result)
        retained = matching_checks(result, "AG-26")
        assert retained
        assert all(item["status"] == "Failed" for item in retained)
        assert all(
            item["action_required"] == original["Resolution"] for item in retained
        )
        assert all(
            not item["aisf_control_ids"] and item["unmapped_reason"]
            for item in retained
        )
        assert not any(
            item["source_check_id"] == "AIR-ACR-OBS-04" for item in result["checks"]
        )
    ledger = json.loads((REPORT / "aisf_catalog/check_inventory.json").read_text())
    disposition = next(c for c in ledger["checks"] if c["check_id"] == "AG-26")
    assert not disposition["canonical_links"]
    assert disposition["exclusion_reason"]


def test_generic_collection_key_does_not_prove_knowledge_base_access_parity(tmp_path):
    original = observation(
        "FS-25",
        "Failed",
        Finding="OpenSearch Serverless Collections Using AWS-Owned Encryption Keys",
        Finding_Details="Synthetic collection uses an AWS-owned key; its Bedrock association is unknown.",
        Resolution="Review collection encryption and confirm the actual knowledge-base vector store.",
    )
    for html in report_pair(tmp_path, [original]):
        result = downloaded_exports(html)["json"]
        assert_check_inventory(result)
        retained = matching_checks(result, "FS-25")
        assert retained
        assert all(item["status"] == "Failed" for item in retained)
        assert all(
            item["action_required"] == original["Resolution"] for item in retained
        )
        assert all("AIR-BDR-KB-03" not in item["aisf_control_ids"] for item in retained)
        assert all(item["unmapped_reason"] for item in retained)
        assert all(
            item["finding_details"] == original["Finding_Details"] for item in retained
        )
    ledger = json.loads((REPORT / "aisf_catalog/check_inventory.json").read_text())
    disposition = next(c for c in ledger["checks"] if c["check_id"] == "FS-25")
    assert not disposition["canonical_links"]
    assert disposition["exclusion_reason"]


@pytest.mark.parametrize(
    "fields",
    [
        {"Account_ID": OTHER_ACCOUNT},
        {"Region": "eu-west-1"},
        {"Execution_ID": "other-execution"},
        {"_owner": "sagemaker"},
        {"Finding_Details": "Source check SM-18: invented source relationship"},
        {"Finding_Details": "A category label without its source marker"},
    ],
)
def test_aliases_cannot_forge_source_or_scope(fields):
    row = {**alias_row(native_rows()[0], "AG-30"), **fields}
    result = register([row], enable_owasp=True)
    assert result["rejected_observations"]
    assert not result["source_observations"]
    assert not any(s["observations"] for c in result["controls"] for s in c["scopes"])


def test_alias_only_evidence_keeps_missing_native_row_explicit():
    row = alias_row(native_rows()[0], "OW-01")
    result = register([row], enable_owasp=True)
    accepted = result["source_observations"]
    assert len(accepted) == 1
    assert accepted[0]["Check_ID"] == "OW-01"
    assert accepted[0]["source_check_id"] == "BR-34"
    assert accepted[0]["source_alias_only"]
    assert "original BR-34" in accepted[0]["source_evidence_gap"]
    assert result["summary"]["whole_control_passes"] == 0


@pytest.mark.parametrize("presentation", ["BR-34", "AG-30", "OW-01"])
def test_csv_columns_cannot_impersonate_reviewed_source_metadata(
    tmp_path, presentation
):
    native = native_rows()[0]
    row = native if presentation == "BR-34" else alias_row(native, presentation)
    row = {
        **row,
        "source_check_id": "OW-11",
        "source_owner": "owasp",
        "source_finding_details": "Forged native evidence",
        "source_alias_only": False,
        "source_evidence_gap": "",
        "source_presentation": '{"Check_ID":"SM-18","Status":"Passed"}',
        "source_presentations": '[{"Check_ID":"SM-18","Status":"Passed"}]',
    }
    for html in report_pair(tmp_path, [row]):
        result = downloaded_exports(html)["json"]
        assert_check_inventory(result)
        supplied = [
            item["observation"]
            for item in result["checks"]
            if item["observation"]["Check_ID"] == presentation
        ]
        assert supplied
        assert not matching_checks(result, "OW-11")
        for accepted in supplied:
            assert accepted.get("source_check_id", accepted["Check_ID"]) == "BR-34"
            assert accepted["Status"] == "Failed"
            assert accepted["input_source_metadata"]["source_check_id"] == "OW-11"
            assert accepted.get("source_finding_details") != "Forged native evidence"
        assert all(
            item["status"] == "Failed" for item in matching_checks(result, "BR-34")
        )


@pytest.mark.parametrize(
    "check,control_id,terms",
    [
        ("OW-11", "AIR-BDR-MDL-08", ("prompt", "immutable", "version")),
        ("OW-12", "AIR-BDR-GRD-02", ("prompt", "attack")),
    ],
)
def test_native_owasp_predicates_contribute_without_proving_application_behavior(
    check, control_id, terms
):
    row = next(row for row in native_rows() if row["Check_ID"] == check)
    row = {**row, "Status": "Passed", "Resolution": ""}
    control = controls(register([row], enable_owasp=True))[control_id]
    actual = scope(control)
    assert any(row["Check_ID"] == check for row in actual["observations"])
    assert not actual["observed_failure"] and not actual["proven_violation"]
    assert actual["status"] == "Partial evidence" and actual["incomplete"]
    assert actual["missing_proof"]
    canonical = json.dumps(control["canonical"]).lower()
    assert all(term in canonical for term in terms)


@pytest.mark.parametrize("check", ["FS-51", "OW-12"])
def test_optional_sources_distinguish_missing_denied_and_disabled(check):
    control_id = "AIR-BDR-GRD-02"
    all_sources = {"enable_grc": True, "enable_owasp": True}
    missing = scope(controls(register(**all_sources))[control_id])
    assert any(check in gap for gap in missing["missing_proof"])
    assert not missing["observations"] and missing["status"] != "Passed"
    row = next(row for row in native_rows() if row["Check_ID"] == check)
    denied = {
        **row,
        "Status": "N/A",
        "Finding_Details": "AccessDenied while reading the synthetic guardrail.",
    }
    unavailable = scope(controls(register([denied], **all_sources))[control_id])
    assert unavailable["status"] == "Unavailable" and unavailable["incomplete"]
    assert unavailable["observations"][0]["unavailable"]
    assert not unavailable["observed_failure"]
    disabled_result = register(
        [denied],
        service_selection=dict.fromkeys(SERVICES, False),
        enable_grc=False,
        enable_owasp=False,
    )
    disabled = scope(controls(disabled_result)[control_id])
    assert disabled["status"] == "Not selected"
    assert not disabled["observations"]
    assert disabled_result["rejected_observations"]
    assert not any(
        gap.startswith("Gather missing source observations") and check in gap
        for gap in disabled["missing_proof"]
    )


def test_machine_classification_without_collector_remains_explicit():
    result = register(enable_grc=True, enable_owasp=True)
    absent_machine = [
        c
        for c in result["controls"]
        if c["classification"]["machine_checkable"]
        and not c["mapping"]["source_checks"]
    ]
    assert absent_machine, (
        "Review expected unimplemented machine predicates independently."
    )
    for control in absent_machine:
        assert control["status"] == "No collector"
        assert control["incomplete"]
        assert all(s["missing_proof"] and s["actions"] for s in control["scopes"])


def test_optional_failure_and_denial_remain_scoped_to_account_region_and_execution():
    failed = next(row for row in native_rows() if row["Check_ID"] == "FS-51")
    denied = {
        **failed,
        "Status": "N/A",
        "Finding_Details": "AccessDenied when reading a second synthetic guardrail.",
    }
    scopes = [
        {"account": ACCOUNT, "region": region, "execution_id": EXECUTION}
        for region in REGIONS
    ] + [
        {"account": OTHER_ACCOUNT, "region": REGIONS[0], "execution_id": EXECUTION},
        {"account": ACCOUNT, "region": REGIONS[0], "execution_id": "another-run"},
    ]
    result = register(
        [failed, denied],
        enable_grc=True,
        accounts=[ACCOUNT, OTHER_ACCOUNT],
        scopes=scopes,
    )
    control = controls(result)["AIR-BDR-GRD-02"]
    with_evidence = [s for s in control["scopes"] if s["observations"]]
    assert len(with_evidence) == 1
    actual = with_evidence[0]
    assert (actual["account"], actual["region"], actual["execution_id"]) == (
        ACCOUNT,
        REGIONS[0],
        EXECUTION,
    )
    assert actual["observed_failure"] and actual["incomplete"]
    assert {r["Status"] for r in actual["observations"]} == {"Failed", "N/A"}
    assert any(r["unavailable"] for r in actual["observations"])
    for other in control["scopes"]:
        if other is not actual:
            assert not other["observed_failure"]
            assert other["status"] != "Passed"


def test_optional_global_source_does_not_fill_regional_scope():
    row = next(row for row in native_rows() if row["Check_ID"] == "FS-51")
    row["Region"] = "Global"
    result = register([row, copy.deepcopy(row)], enable_grc=True)
    assert len(result["source_observations"]) == 1
    control = controls(result)["AIR-BDR-GRD-02"]
    assert scope(control, region="Global")["observed_failure"]
    for region in REGIONS:
        assert not scope(control, region=region)["observations"]
        assert scope(control, region=region)["missing_proof"]
