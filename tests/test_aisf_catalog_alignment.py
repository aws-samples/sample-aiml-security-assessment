"""Independent catalog, evidence, scope and report acceptance checks.

The expected inventory/content are frozen from the pre-implementation review.
Tests deliberately do not derive the oracle from runtime mapping dictionaries.
"""

import copy
import csv
import hashlib
import importlib.util
import io
import itertools
import json
import re
import shutil
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
REPORT = (
    ROOT / "aiml-security-assessment/functions/security/generate_consolidated_report"
)
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(REPORT))

import aisf_catalog  # noqa: E402
import aisf_results  # noqa: E402
import aisf_view  # noqa: E402
import assessment_artifacts  # noqa: E402
import consolidate_html_reports as multi  # noqa: E402

_SPEC = importlib.util.spec_from_file_location("aisf_acceptance_app", REPORT / "app.py")
single = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(single)

EXPECTED_IDS = (ROOT / "tests/fixtures/aisf/canonical-ids.txt").read_text().splitlines()
REVISION = "5df3295024713ac3ce88130c549bbc4fb2cebd53"
CONTENT_SHA256 = "0853047d6c919fb8a6506ca0fdbd3996e516d322417386dde29a42ea020274af"
ACCOUNT = "111122223333"
OTHER_ACCOUNT = "444455556666"
REGIONS = ["us-east-1", "us-west-2"]
EXECUTION = "synthetic-alignment-run"
SERVICES = ("bedrock", "sagemaker", "agentcore", "agent-registry")
SOURCE_CHECKS = {
    "bedrock": "BR-20",
    "sagemaker": "SM-18",
    "agentcore": "AC-20",
    "agent-registry": "AR-01",
}
COLUMNS = [
    "Check_ID",
    "Finding",
    "Finding_Details",
    "Resolution",
    "Reference",
    "Severity",
    "Status",
    "Region",
    "Account_ID",
    "Execution_ID",
    "Resource_ID",
]


def observation(
    check="BR-20", status="Passed", *, account=ACCOUNT, region="us-east-1", **fields
):
    return {
        "Check_ID": check,
        "Finding": "Synthetic source observation",
        "Finding_Details": "Synthetic concrete source evidence",
        "Resolution": ""
        if status == "Passed"
        else "Restore access and rerun this source check.",
        "Reference": "https://docs.aws.amazon.com/",
        "Severity": "High",
        "Status": status,
        "Region": region,
        "Account_ID": account,
        "Execution_ID": EXECUTION,
        "Resource_ID": f"arn:aws:bedrock:{region}:{account}:knowledge-base/synthetic",
        **fields,
    }


def register(rows=(), **kwargs):
    return aisf_results.build_aisf_register(
        list(rows),
        **{
            "accounts": [ACCOUNT],
            "regions": REGIONS,
            "execution_id": EXECUTION,
            **kwargs,
        },
    )


def controls(result):
    return {control["control_id"]: control for control in result["controls"]}


def scope(control, *, account=ACCOUNT, region="us-east-1"):
    return next(
        s
        for s in control["scopes"]
        if s["account"] == account and s["region"] == region
    )


def csv_text(rows):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=COLUMNS)
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def embedded_register(html):
    match = re.search(r'<script\b[^>]*\bid="aisf-data"[^>]*>(.*?)</script>', html, re.S)
    assert match, (
        "AISF source-check projection must be rendered even without source rows."
    )
    return json.loads(match.group(1))


def assert_check_inventory(result):
    assert result["schema_version"] == 2
    assert result["view"] == "automated-check-results"
    assert "controls" not in result
    assert result["source_revision"] == REVISION
    assert all(
        re.fullmatch(r"[0-9a-f]{64}", result[key])
        for key in ("catalog_sha256", "mapping_sha256")
    )
    assert (
        not {
            "canonical_controls",
            "whole_control_passes",
            "machine_classified_controls",
            "mapped_controls",
        }
        & result["summary"].keys()
    )
    ids = [check["result_id"] for check in result["checks"]]
    assert len(ids) == len(set(ids))
    for check in result["checks"]:
        raw = check["observation"]
        assert check["source_check_id"] == raw.get("source_check_id", raw["Check_ID"])
        assert not check["source_check_id"].startswith("AISF-")
        for field, original in (
            ("status", "Status"),
            ("severity", "Severity"),
            ("finding", "Finding"),
            ("resource", "Resource_ID"),
            ("action_required", "Resolution"),
            ("reference", "Reference"),
        ):
            assert check[field] == raw.get(original, ""), (
                check["source_check_id"],
                field,
            )
        assert check["finding_details"] == raw.get(
            "source_finding_details", raw.get("Finding_Details", "")
        )
        assert set(check["aisf_control_ids"]) <= set(EXPECTED_IDS)
        assert set(check["aisf_control_ids"]) == {
            link["control_id"] for link in check["aisf_links"]
        }
        assert check["aisf_control_ids"] or check["unmapped_reason"]
        assert not {"missing_proof", "manual_tasks", "canonical"} & check.keys()


def matching_checks(result, check, *, account=None, region=None):
    return [
        item
        for item in result["checks"]
        if item["source_check_id"] == check
        and (account is None or item["account"] == account)
        and (region is None or item["region"] == region)
    ]


def assert_inventory(result):
    ids = [control["control_id"] for control in result["controls"]]
    assert len(ids) == len(set(ids)) == 218
    assert ids == EXPECTED_IDS
    assert result["source_revision"] == REVISION
    canonical = [control["canonical"] for control in result["controls"]]
    serialized = json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    assert hashlib.sha256(serialized.encode()).hexdigest() == CONTENT_SHA256
    assert result["summary"]["canonical_controls"] == 218
    assert result["summary"]["machine_classified_controls"] == 104
    assert result["summary"]["mapped_controls"] == 126
    assert result["summary"]["whole_control_passes"] == 0
    assert all(control["status"] != "Passed" for control in result["controls"])
    assert all(s["status"] != "Passed" for c in result["controls"] for s in c["scopes"])


def test_frozen_inventory_is_exact_and_empty_assessments_keep_every_control():
    assert len(EXPECTED_IDS) == len(set(EXPECTED_IDS)) == 218
    result = register()
    assert_inventory(result)
    assert all(not s["observations"] for c in result["controls"] for s in c["scopes"])
    assert all(
        s["missing_proof"] and s["actions"]
        for c in result["controls"]
        for s in c["scopes"]
    )
    assert {c["status"] for c in result["controls"]} == {
        "Missing evidence",
        "Manual evidence",
        "No collector",
        "Not selected",
    }
    assert {
        c["legacy_check_id"] for c in result["controls"] if c["legacy_check_id"]
    } == {"AISF-05", "AISF-07", "AISF-08"}


def test_frozen_oracle_rejects_removed_extra_and_content_changed_controls():
    result = register()
    mutations = [copy.deepcopy(result) for _ in range(3)]
    mutations[0]["controls"].pop()
    mutations[1]["controls"][-1]["control_id"] = "AIR-OBSOLETE-01"
    mutations[2]["controls"][0]["canonical"]["question"] = "Weakened question"
    for mutant in mutations:
        with pytest.raises(AssertionError):
            assert_inventory(mutant)


@pytest.mark.parametrize(
    "mutation", ["revision", "deleted-control", "content", "classification"]
)
def test_catalog_loader_rejects_stale_revision_inventory_and_content(
    tmp_path, mutation
):
    catalog = tmp_path / "catalog"
    shutil.copytree(aisf_catalog.CATALOG_DIRECTORY, catalog)
    manifest_path = catalog / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if mutation == "revision":
        manifest["source_revision"] = "0" * 40
        manifest_path.write_text(json.dumps(manifest))
    elif mutation == "deleted-control":
        document_path = catalog / "controls.json"
        document = json.loads(document_path.read_text())
        document["controls"].pop()
        document_path.write_text(json.dumps(document))
        # Even an updated local checksum may not replace the independent pin.
        manifest["outputs"]["controls.json"] = hashlib.sha256(
            document_path.read_bytes()
        ).hexdigest()
        manifest_path.write_text(json.dumps(manifest))
    else:
        filename = "controls.json" if mutation == "content" else "classification.json"
        with (catalog / filename).open("ab") as stream:
            stream.write(b" ")
    with pytest.raises(ValueError):
        aisf_catalog.load_catalog(catalog)


def test_runtime_refuses_partial_mapping_promoted_to_whole(tmp_path, monkeypatch):
    shutil.copytree(aisf_catalog.CATALOG_DIRECTORY, tmp_path / "catalog")
    path = tmp_path / "catalog/mapping.json"
    document = json.loads(path.read_text())
    next(c for c in document["controls"] if c["control_id"] == "AIR-BDR-KB-03")[
        "coverage"
    ] = "whole"
    path.write_text(json.dumps(document))
    monkeypatch.setattr(aisf_results, "CATALOG_DIRECTORY", path.parent)
    with pytest.raises(ValueError, match="Whole-control"):
        aisf_results.load_mapping()


# These witnesses come from canonical requirements reviewed before the mapping
# ledger existed. A term tuple allows equivalent wording, not missing proof.
WITNESSES = [
    (
        "AIR-ACR-MEM-07",
        (),
        (
            ("ttl", "retention"),
            ("permission",),
            ("expiry", "deletion"),
            ("downstream",),
        ),
    ),
    ("AIR-FND-GOV-12", (), (("priority",), ("backlog",), ("quality",))),
    (
        "AIR-ACR-OBS-04",
        ("AC-20", "AC-21"),
        (("redact",), ("synthetic",), ("export",), ("sdk", "adot")),
    ),
    ("AIR-ACR-RT-08", ("AC-01",), (("sandbox",), ("network", "egress"))),
    ("AIR-ACR-ID-10", ("AC-33",), (("mint", "issuance"), ("identity",))),
    (
        "AIR-BDR-KB-03",
        ("BR-20",),
        (("access-policy parity",), ("external stores",), ("key ownership",)),
    ),
    (
        "AIR-SGM-EP-08",
        ("SM-18", "SM-42"),
        (("vpc", "isolation", "private-network"), ("kms", "encrypt")),
    ),
    ("AIR-SGM-TRN-05", ("SM-09", "SM-01", "SM-03"), (("notebook",), ("access",))),
]


@pytest.mark.parametrize("control_id,checks,required_terms", WITNESSES)
def test_independent_required_predicates_remain_visible(
    control_id, checks, required_terms
):
    result = register([observation(check) for check in checks])
    control = controls(result)[control_id]
    assert control["status"] != "Passed"
    assert control["incomplete"]
    assert control["mapping"]["coverage"] == ("partial" if checks else "absent")
    gaps = " ".join(scope(control)["missing_proof"]).lower()
    for alternatives in required_terms:
        assert any(term in gaps for term in alternatives), (
            control_id,
            alternatives,
            gaps,
        )
    if not checks:
        assert control["mapping"]["source_checks"] == []
        assert control["classification"]["machine_checkable"]
        assert control["status"] == "No collector"
    if control_id == "AIR-ACR-OBS-04":
        assert not control["classification"]["machine_checkable"]


@pytest.mark.parametrize(
    "check,control_id", [("AC-01", "AIR-ACR-RT-08"), ("AC-33", "AIR-ACR-ID-10")]
)
def test_source_failure_is_not_automatically_a_canonical_violation(check, control_id):
    control = controls(register([observation(check, "Failed")]))[control_id]
    assert control["observed_failure"]
    assert not control["proven_violation"]
    assert control["incomplete"]
    assert scope(control)["observations"][0]["Status"] == "Failed"
    assert scope(control)["actions"]


def test_failure_denial_conflict_and_all_evidence_survive_in_both_orders():
    failure = observation(
        "BR-20", "Failed", Finding_Details="Resource synthetic has no encryption."
    )
    denial = observation(
        "BR-20", "N/A", Finding_Details="AccessDenied on second discovery page."
    )
    passed = observation("BR-20", "Passed")
    results = [
        register(rows)
        for rows in ([failure, denial, passed], [passed, denial, failure])
    ]
    assert results[0] == results[1]
    control = controls(results[0])["AIR-BDR-KB-03"]
    assert control["observed_failure"] and control["incomplete"]
    evidence = scope(control)["observations"]
    assert {row["Status"] for row in evidence} == {"Passed", "Failed", "N/A"}
    assert {row["Finding_Details"] for row in evidence} == {
        failure["Finding_Details"],
        denial["Finding_Details"],
        passed["Finding_Details"],
    }
    for row in evidence:
        for field in ("Account_ID", "Region", "Resolution", "Reference", "Resource_ID"):
            assert field in row
    assert any(
        "Restore" in action or "AccessDenied" in action
        for action in scope(control)["actions"]
    )


@pytest.mark.parametrize(
    "details",
    [
        "AccessDenied: describe denied.",
        "Unsupported region.",
        "Discovery unavailable.",
        "Pagination failed after page 2; prior findings retained.",
        "Discovery safety cap reached.",
        "Timeout during discovery.",
    ],
)
def test_unavailable_observations_never_become_clean(details):
    control = controls(
        register([observation("BR-20", "N/A", Finding_Details=details)])
    )["AIR-BDR-KB-03"]
    assert control["status"] == "Unavailable"
    assert control["incomplete"]
    assert scope(control)["observations"][0]["Finding_Details"] == details
    assert scope(control)["actions"]


def test_complete_empty_discovery_differs_from_failed_discovery_and_proves_no_control():
    empty = controls(
        register([observation("BR-20", "N/A", Finding_Details="No resources found.")])
    )["AIR-BDR-KB-03"]
    denied = controls(
        register([observation("BR-20", "N/A", Finding_Details="AccessDenied.")])
    )["AIR-BDR-KB-03"]
    assert scope(empty)["observations"][0]["evidence_kind"] == "no resource observation"
    assert scope(denied)["observations"][0]["evidence_kind"] == "unavailable"
    assert empty["status"] != denied["status"]
    assert empty["incomplete"] and denied["incomplete"]


def test_scope_never_borrows_evidence_between_accounts_regions_or_global():
    rows = [
        observation("BR-20", "Failed"),
        observation("BR-20", "Passed", account=OTHER_ACCOUNT, region="us-west-2"),
        observation(
            "BR-20",
            "N/A",
            region="Global",
            Finding_Details="Global-only synthetic evidence",
        ),
    ]
    result = register(rows, accounts=[ACCOUNT, OTHER_ACCOUNT])
    control = controls(result)["AIR-BDR-KB-03"]
    assert scope(control)["observed_failure"]
    assert not scope(control, region="us-west-2")["observations"]
    assert not scope(control, account=OTHER_ACCOUNT)["observations"]
    assert (
        scope(control, account=OTHER_ACCOUNT, region="us-west-2")["status"]
        == "Partial evidence"
    )
    assert len(scope(control, region="Global")["observations"]) == 1
    assert not scope(control, region="Global")["observed_failure"]
    assert "Global" not in result["scope"]["regions"]


def test_equivalent_global_observations_deduplicate_but_conflicts_do_not():
    row = observation("BR-20", "Failed", region="Global")
    rows = [
        dict(row, _artifact="east.csv", _artifact_region="us-east-1"),
        dict(row, _artifact="west.csv", _artifact_region="us-west-2"),
        dict(row, Status="Passed", _artifact="west.csv", _artifact_region="us-west-2"),
    ]
    result = register(rows)
    control = controls(result)["AIR-BDR-KB-03"]
    global_scope = scope(control, region="Global")
    assert len(global_scope["observations"]) == 2
    assert global_scope["observed_failure"]
    assert not scope(control)["observations"]


def test_global_execution_identity_matches_its_own_run():
    expected_scopes = [
        {"account": ACCOUNT, "region": "us-east-1", "execution_id": "run-one"},
        {"account": ACCOUNT, "region": "us-west-2", "execution_id": "run-two"},
    ]
    result = register(
        [observation("BR-51", region="Global", Execution_ID="run-two")],
        scopes=expected_scopes,
    )
    observed_scopes = [
        scoped
        for control in result["controls"]
        for scoped in control["scopes"]
        if scoped["observations"]
    ]
    assert observed_scopes
    assert {
        (s["account"], s["region"], s["execution_id"]) for s in observed_scopes
    } == {(ACCOUNT, "Global", "run-two")}


def test_global_only_predicate_is_requested_in_global_scope():
    result = register()
    mapped = [
        control
        for control in result["controls"]
        if any(
            source["check_id"] == "BR-51"
            for source in control["mapping"]["source_checks"]
        )
    ]
    assert mapped
    for control in mapped:
        global_gap = " ".join(scope(control, region="Global")["missing_proof"])
        assert "BR-51" in global_gap
        for region in REGIONS:
            regional_gap = " ".join(scope(control, region=region)["missing_proof"])
            assert "BR-51" not in regional_gap


def test_failed_row_with_denied_details_keeps_failure_and_unavailable():
    control = controls(
        register(
            [
                observation(
                    "BR-20",
                    "Failed",
                    Finding_Details="AccessDenied after an observed failure.",
                )
            ]
        )
    )["AIR-BDR-KB-03"]
    scoped = scope(control)
    evidence = scoped["observations"][0]
    assert evidence["observed_failure"] and evidence["unavailable"]
    assert evidence["evidence_kind"] == "unavailable"
    assert control["observed_failure"] and control["incomplete"]
    assert evidence["Resolution"] in scoped["actions"]


def test_missing_execution_identity_cannot_credit_two_runs_of_one_scope():
    expected_scopes = [
        {"account": ACCOUNT, "region": "us-east-1", "execution_id": run}
        for run in ("run-one", "run-two")
    ]
    result = register([observation(Execution_ID="")], scopes=expected_scopes)
    assert result["rejected_observations"]
    assert "ambiguous execution" in result["rejected_observations"][0]["reason"]
    assert not any(s["observations"] for c in result["controls"] for s in c["scopes"])


def test_unscoped_artifact_failure_marks_all_expected_account_region_scopes():
    issue = {
        "kind": "failed-assessment",
        "account": "",
        "region": "",
        "owner": "",
        "message": "Restore failed shared execution and rerun.",
    }
    result = register(accounts=[ACCOUNT, OTHER_ACCOUNT], artifact_issues=[issue])
    for scoped in controls(result)["AIR-BDR-KB-03"]["scopes"]:
        assert scoped["status"] == "Unavailable"
        assert issue["message"] in scoped["missing_proof"]


@pytest.mark.parametrize(
    "fields",
    [
        {"Check_ID": "AC-999"},
        {"Check_ID": "SM-29"},
        {"Check_ID": "FS-17"},
        {"Account_ID": OTHER_ACCOUNT},
        {"Region": "eu-west-1"},
        {"Execution_ID": "other-execution"},
        {"_owner": "sagemaker"},
    ],
)
def test_unknown_retired_and_cross_scope_observations_are_isolated(fields):
    result = register([observation(**fields)])
    assert result["rejected_observations"]
    assert not any(s["observations"] for c in result["controls"] for s in c["scopes"])


def test_missing_selected_artifact_and_second_region_remain_explicit():
    issue = {
        "kind": "missing",
        "account": ACCOUNT,
        "region": "us-west-2",
        "owner": "bedrock",
        "artifact": "missing-west.csv",
        "message": "Restore the selected us-west-2 Bedrock artifact and rerun.",
    }
    result = register([observation()], artifact_issues=[issue])
    control = controls(result)["AIR-BDR-KB-03"]
    assert scope(control)["status"] == "Partial evidence"
    assert scope(control, region="us-west-2")["status"] == "Unavailable"
    assert issue["message"] in scope(control, region="us-west-2")["missing_proof"]
    assert not scope(control, region="us-west-2")["observations"]


@pytest.mark.parametrize(
    "content,kind",
    [
        (b"", "zero-byte"),
        (b"\xff", "unreadable"),
        ("Check_ID,Status\nBR-20,Passed\n", "wrong-schema"),
        (csv_text([]), "header-only"),
        (csv_text([]) + '"unterminated', "malformed"),
    ],
)
def test_selected_invalid_artifacts_are_not_silently_empty(content, kind):
    result = assessment_artifacts.parse_csv_artifact(
        content,
        account=ACCOUNT,
        region="us-east-1",
        owner="bedrock",
        execution_id=EXECUTION,
    )
    assert result["rows"] == []
    assert kind in {issue["kind"] for issue in result["issues"]}


def test_malformed_tail_retains_prior_valid_failure():
    result = assessment_artifacts.parse_csv_artifact(
        csv_text([observation(status="Failed")]) + '"unterminated',
        account=ACCOUNT,
        region="us-east-1",
        owner="bedrock",
        execution_id=EXECUTION,
    )
    assert len(result["rows"]) == 1
    assert result["rows"][0]["Status"] == "Failed"
    assert {issue["kind"] for issue in result["issues"]} == {"malformed"}


def test_unreadable_file_is_reported_with_its_scope(tmp_path, monkeypatch):
    path = tmp_path / "selected.csv"
    path.write_text(csv_text([observation()]))

    def deny(*args, **kwargs):
        raise PermissionError("Synthetic unreadable artifact")

    monkeypatch.setattr(Path, "read_bytes", deny)
    result = assessment_artifacts.read_csv_artifact(
        path,
        account=ACCOUNT,
        region="us-east-1",
        owner="bedrock",
        execution_id=EXECUTION,
    )
    assert result["rows"] == []
    assert result["issues"][0]["kind"] == "unreadable"
    assert result["issues"][0]["account"] == ACCOUNT


@pytest.mark.parametrize(
    "fields",
    [
        {"Account_ID": OTHER_ACCOUNT},
        {"Region": "us-west-2"},
        {"Execution_ID": "other-execution"},
        {"Check_ID": "SM-18"},
        {"Check_ID": "AISF-01"},
        {"Check_ID": "AC-999"},
    ],
)
def test_csv_scope_and_unknown_ids_are_rejected_before_adjudication(fields):
    result = assessment_artifacts.parse_csv_artifact(
        csv_text([observation(**fields)]),
        account=ACCOUNT,
        region="us-east-1",
        owner="bedrock",
        execution_id=EXECUTION,
    )
    assert result["rows"] == []
    assert result["issues"]


def _prepared_reports(tmp_path, selection, grc, owasp):
    assessment = {
        "account_id": ACCOUNT,
        "execution_id": EXECUTION,
        "expected_regions": REGIONS,
        "timestamp": "2026-01-01T00:00:00Z",
        "enable_owasp": owasp,
    }
    owners = [owner for owner, enabled in selection.items() if enabled]
    if grc or owasp:
        owners.append("responsible-ai-grc")
    if owasp:
        owners.append("owasp")
    for account in (ACCOUNT, OTHER_ACCOUNT):
        directory = tmp_path / account
        directory.mkdir()
        for owner in owners:
            assessment.setdefault(owner, {})
            for region in REGIONS:
                check = SOURCE_CHECKS.get(
                    owner, "FS-01" if owner == "responsible-ai-grc" else "OW-01"
                )
                fragment = owner.replace("-", "_")
                if owner == "responsible-ai-grc" and region != REGIONS[0]:
                    continue
                suffix = "" if owner == "responsible-ai-grc" else "_" + region
                stem = f"{fragment}_security_report_{EXECUTION}{suffix}"
                row = observation(check, account=account, region=region)
                (directory / (stem + ".csv")).write_text(csv_text([row]))
                if account == ACCOUNT:
                    assessment[owner][stem] = [row]
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
    return assessment, manifest


def completion_input(selection, *, grc=False, owasp=False):
    receipts = []
    for index, region in enumerate(REGIONS):
        wrappers = [
            {
                "service": owner,
                "statusCode": 200,
                **({} if enabled else {"skipped": True, "reason": "Not selected"}),
            }
            for owner, enabled in selection.items()
        ]
        wrappers.append(
            {
                "service": "responsible-ai-grc",
                "statusCode": 200,
                **({} if (grc or owasp) and index == 0 else {"skipped": True}),
            }
        )
        receipts.append(
            {
                "Region": region,
                "RegionIndex": index,
                "ExecutionId": EXECUTION,
                "ServiceResults": wrappers,
                "OWASPResult": {
                    "service": "owasp",
                    "statusCode": 200,
                    **({} if owasp else {"skipped": True}),
                },
            }
        )
    return {
        "ResolvedRegions": {"regions": REGIONS},
        "ServiceSelection": selection,
        "enableResponsibleAIGRC": grc,
        "enableOWASP": owasp,
        "AssessmentResults": receipts,
    }


@pytest.mark.parametrize("flags", list(itertools.product((False, True), repeat=6)))
def test_all_64_selections_have_complete_equal_account_scope_in_both_report_paths(
    tmp_path, flags
):
    selection = dict(zip(SERVICES, flags[:4]))
    grc, owasp = flags[4:]
    assessment, manifest = _prepared_reports(tmp_path, selection, grc, owasp)
    single.validate_assessment_artifacts(
        assessment,
        EXECUTION,
        completion_input(selection, grc=grc, owasp=owasp),
        require_receipts=True,
    )
    assert not assessment["artifact_issues"]
    single_html = single.generate_html_report(
        assessment, show_finserv=grc, service_selection=selection
    )
    multi_result = multi.load_multi_account_results(
        tmp_path,
        scope_manifest=manifest,
        service_selection=selection,
        show_finserv=grc,
        enable_owasp=owasp,
        timestamp="2026-01-01T00:00:00Z",
    )
    multi_html = multi.render_multi_account_report(multi_result)
    one, many = embedded_register(single_html), embedded_register(multi_html)
    assert_check_inventory(one)
    assert_check_inventory(many)
    assert set(many["scope"]["accounts"]) == {ACCOUNT, OTHER_ACCOUNT}
    assert (
        one["scope"]["service_selection"]
        == many["scope"]["service_selection"]
        == selection
    )

    def own_findings(result):
        return sorted(
            (
                check["source_check_id"],
                check["region"],
                check["status"],
                check["observation"]["Finding_Details"],
            )
            for check in result["checks"]
            if check["account"] == ACCOUNT
        )

    assert own_findings(one) == own_findings(many)
    for result in (one, many):
        assert all(
            result["scope"]["source_selection"][check["source_owner"]]
            for check in result["checks"]
        )
    for html in (single_html, multi_html):
        assert 'id="aisf-json"' in html and 'id="aisf-csv"' in html
        assert all(
            f'id="{filter_id}"' in html
            for filter_id in (
                "searchInput",
                "statusFilter",
                "regionFilter",
                "serviceFilter",
                "severityFilter",
            )
        )
    assert 'id="accountFilter"' not in single_html
    assert 'id="accountFilter"' in multi_html


@pytest.mark.parametrize(
    "failed_wrapper",
    [
        {"statusCode": 207, "incomplete": True},
        {
            "statusCode": 200,
            "error": {"Error": "SyntheticTimeout", "Cause": "Stopped after CSV"},
        },
        {"statusCode": 200, "incomplete": "true"},
        {"statusCode": 200, "skipped": True},
    ],
)
def test_valid_csv_never_masks_a_failed_or_skipped_selected_assessment(
    tmp_path, failed_wrapper
):
    selection = {owner: owner == "bedrock" for owner in SERVICES}
    assessment, _ = _prepared_reports(tmp_path, selection, False, False)
    assessment["bedrock"][f"bedrock_security_report_{EXECUTION}_us-east-1"][0][
        "Status"
    ] = "Failed"
    original = completion_input(selection)
    original["AssessmentResults"][0]["ServiceResults"][0].update(failed_wrapper)
    with pytest.raises(ValueError, match="Incomplete assessment artifacts"):
        single.validate_assessment_artifacts(
            assessment, EXECUTION, original, require_receipts=True
        )
    issues = assessment["artifact_issues"]
    assert {issue["kind"] for issue in issues} == {"failed-assessment"}
    assert issues[0]["region"] == "us-east-1" and issues[0]["owner"] == "bedrock"
    assert issues[0]["observation"].items() >= failed_wrapper.items()
    rendered = embedded_register(
        single.generate_html_report(assessment, service_selection=selection)
    )
    assert_check_inventory(rendered)
    actual = matching_checks(rendered, "BR-20", region="us-east-1")
    assert actual and actual[0]["status"] == "Failed"
    assert issues[0] in rendered["artifact_issues"]
    assert issues[0]["message"] in json.dumps(rendered["gaps"])


@pytest.mark.parametrize(
    "mismatch",
    [
        {"Account": OTHER_ACCOUNT},
        {"ExecutionId": "other-execution"},
        {"Region": "eu-west-1"},
        {"RegionIndex": 1},
    ],
)
def test_wrong_scope_receipt_cannot_complete_selected_artifacts(tmp_path, mismatch):
    selection = {owner: owner == "bedrock" for owner in SERVICES}
    assessment, _ = _prepared_reports(tmp_path, selection, False, False)
    original = completion_input(selection)
    original["AssessmentResults"][0].update(mismatch)
    with pytest.raises(ValueError, match="Incomplete assessment artifacts"):
        single.validate_assessment_artifacts(
            assessment, EXECUTION, original, require_receipts=True
        )
    assert {issue["kind"] for issue in assessment["artifact_issues"]} == {
        "scope-mismatch",
        "missing-receipt",
    }
    assert all(assessment["bedrock"].values())


@pytest.mark.parametrize("missing", ["all", "region", "owner"])
def test_missing_selected_receipts_block_completion_despite_valid_artifacts(
    tmp_path, missing
):
    selection = {owner: owner == "bedrock" for owner in SERVICES}
    assessment, _ = _prepared_reports(tmp_path, selection, False, False)
    original = completion_input(selection)
    if missing == "all":
        del original["AssessmentResults"]
    elif missing == "region":
        original["AssessmentResults"].pop()
    else:
        original["AssessmentResults"][0]["ServiceResults"].pop(0)
    with pytest.raises(ValueError, match="Incomplete assessment artifacts"):
        single.validate_assessment_artifacts(
            assessment, EXECUTION, original, require_receipts=True
        )
    assert any(
        issue["kind"].startswith("missing-receipt")
        for issue in assessment["artifact_issues"]
    )


def test_grc_receipt_is_required_only_once_and_deselected_skips_are_valid(tmp_path):
    selection = dict.fromkeys(SERVICES, False)
    assessment, _ = _prepared_reports(tmp_path, selection, True, False)
    original = completion_input(selection, grc=True)
    single.validate_assessment_artifacts(
        assessment, EXECUTION, original, require_receipts=True
    )
    assert assessment["artifact_issues"] == []
    original["AssessmentResults"][0]["ServiceResults"][-1]["skipped"] = True
    with pytest.raises(ValueError, match="failed responsible-ai-grc"):
        single.validate_assessment_artifacts(
            assessment, EXECUTION, original, require_receipts=True
        )
    assert {
        (issue["owner"], issue["region"]) for issue in assessment["artifact_issues"]
    } == {("responsible-ai-grc", REGIONS[0])}


def test_artifact_pagination_failure_preserves_prior_findings(monkeypatch):
    key = f"bedrock_security_report_{EXECUTION}_us-east-1.csv"
    client = MagicMock()

    def pages(**kwargs):
        if kwargs["Prefix"].startswith("bedrock_"):
            yield {"Contents": [{"Key": key}]}
            raise RuntimeError("Synthetic pagination timeout after first page")
        yield {"Contents": []}

    client.get_paginator.return_value.paginate.side_effect = pages
    client.get_object.return_value = {
        "Body": io.BytesIO(csv_text([observation(status="Failed")]).encode())
    }
    monkeypatch.setattr(single.boto3, "client", lambda *args, **kwargs: client)
    monkeypatch.setenv("AIML_ASSESSMENT_BUCKET_NAME", "synthetic-artifact-bucket")
    assessment = single.get_assessment_results(EXECUTION, ACCOUNT)
    findings = [row for rows in assessment["bedrock"].values() for row in rows]
    assert len(findings) == 1 and findings[0]["Status"] == "Failed"
    assert {issue["kind"] for issue in assessment["artifact_issues"]} == {
        "discovery-failed"
    }
    assert "earlier pages were retained" in assessment["artifact_issues"][0]["message"]


@pytest.mark.parametrize("row_execution", ["exact", "lowercase", "different"])
def test_execution_case_and_csv_identity_survive_both_report_paths(
    tmp_path, monkeypatch, row_execution
):
    monkeypatch.setitem(globals(), "EXECUTION", "Synthetic-Mixed-Case-Run")
    selection = {owner: owner == "bedrock" for owner in SERVICES}
    direct_assessment, manifest = _prepared_reports(tmp_path, selection, False, False)
    supplied_execution = {
        "exact": EXECUTION,
        "lowercase": EXECUTION.lower(),
        "different": "another-run",
    }[row_execution]
    stem = f"bedrock_security_report_{EXECUTION}_us-east-1"
    row = direct_assessment["bedrock"][stem][0]
    row["Execution_ID"] = supplied_execution
    directory = tmp_path / ACCOUNT
    (directory / (stem + ".csv")).write_text(csv_text([row]))

    client = MagicMock()
    client.get_paginator.return_value.paginate.side_effect = lambda **kwargs: [
        {
            "Contents": [
                {"Key": path.name}
                for path in sorted(directory.iterdir())
                if path.name.startswith(kwargs["Prefix"])
            ]
        }
    ]
    client.get_object.side_effect = lambda **kwargs: {
        "Body": io.BytesIO((directory / kwargs["Key"]).read_bytes())
    }
    monkeypatch.setattr(single.boto3, "client", lambda *args, **kwargs: client)
    monkeypatch.setenv("AIML_ASSESSMENT_BUCKET_NAME", "synthetic-artifact-bucket")
    ingested_assessment = single.get_assessment_results(
        EXECUTION, ACCOUNT, expected_regions=REGIONS
    )
    template = single.generate_report_from_template
    direct_findings = []

    def capture(**kwargs):
        direct_findings.append(kwargs["all_findings"])
        return template(**kwargs)

    monkeypatch.setattr(single, "generate_report_from_template", capture)
    reports = [
        single.generate_html_report(
            assessment, show_finserv=False, service_selection=selection
        )
        for assessment in (direct_assessment, ingested_assessment)
    ]
    multi_result = multi.load_multi_account_results(
        tmp_path,
        scope_manifest=manifest,
        service_selection=selection,
        timestamp="2026-01-01T00:00:00Z",
    )
    reports.append(multi.render_multi_account_report(multi_result))
    for findings in [*direct_findings, multi_result["all_findings"]]:
        own_rows = [
            row
            for row in findings
            if row["Account_ID"] == ACCOUNT and row["Check_ID"] == "BR-20"
        ]
        assert len(own_rows) == (2 if row_execution == "exact" else 1)
        assert all(row["Execution_ID"] == EXECUTION for row in own_rows)
    for html in reports:
        result = embedded_register(html)
        assert_check_inventory(result)
        east = matching_checks(result, "BR-20", account=ACCOUNT, region="us-east-1")
        west = matching_checks(result, "BR-20", account=ACCOUNT, region="us-west-2")
        assert west
        if row_execution == "exact":
            assert east
            assert not result["artifact_issues"]
        else:
            assert not east
            assert result["gaps"]
            assert any(
                issue["kind"] == "scope-mismatch"
                and issue.get("observation", {}).get("Execution_ID")
                == supplied_execution
                for issue in result["artifact_issues"]
            )


def test_history_template_loads_without_report_directory_on_import_path(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            "import sys; sys.path.insert(0, sys.argv[1]); "
            "from assessment_history.render_common import load_parts; "
            "assert sys.argv[2] not in sys.path; "
            "parts = load_parts(); "
            "assert parts.css and parts.area_labels['aisf']; "
            "assert parts.safe_https_url('https://example.com/')",
            str(ROOT),
            str(REPORT),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "check,case",
    [
        ("BR-47", "bucket"),
        ("BR-52", "bucket"),
        ("BR-47", "denied"),
        ("BR-52", "denied"),
        ("BR-20", "other-check"),
        ("BR-47", "reference"),
        ("BR-52", "inventory"),
        ("BR-47", "unselected-target"),
        ("BR-52", "unselected-producer"),
        ("BR-47", "wrong-account"),
        ("BR-52", "wrong-execution"),
        ("BR-47", "wrong-owner"),
    ],
)
def test_bucket_home_region_exception_is_bounded_in_both_ingestion_paths(
    tmp_path, monkeypatch, check, case
):
    selection = {owner: owner in ("bedrock", "agentcore") for owner in SERVICES}
    direct_assessment, manifest = _prepared_reports(tmp_path, selection, False, False)
    details = "Bucket synthetic-ai-data is on the Bedrock data path" + (
        ", but AccessDenied prevented the policy read."
        if case == "denied"
        else " and lacks the required protection."
    )
    if case == "reference":
        details = "A Bedrock data source references bucket synthetic-ai-data."
    elif case == "inventory":
        details = "Bucket inventory failed before the data path was fully discovered."
    row = observation(
        check,
        "N/A" if case == "denied" else "Failed",
        region="eu-west-1" if case == "unselected-target" else "us-west-2",
        Finding_Details=details,
        Resource_ID="arn:aws:s3:::synthetic-ai-data",
        Account_ID=OTHER_ACCOUNT if case == "wrong-account" else ACCOUNT,
        Execution_ID="another-run" if case == "wrong-execution" else EXECUTION,
    )
    owner = "agentcore" if case == "wrong-owner" else "bedrock"
    producer = "eu-west-1" if case == "unselected-producer" else "us-east-1"
    stem = f"{owner}_security_report_{EXECUTION}_{producer}"
    rows = direct_assessment[owner].setdefault(stem, [])
    rows.append(row)
    directory = tmp_path / ACCOUNT
    (directory / (stem + ".csv")).write_text(csv_text(rows))
    client = MagicMock()
    client.get_paginator.return_value.paginate.side_effect = lambda **kwargs: [
        {
            "Contents": [
                {"Key": path.name}
                for path in sorted(directory.iterdir())
                if path.name.startswith(kwargs["Prefix"])
            ]
        }
    ]
    client.get_object.side_effect = lambda **kwargs: {
        "Body": io.BytesIO((directory / kwargs["Key"]).read_bytes())
    }
    monkeypatch.setattr(single.boto3, "client", lambda *args, **kwargs: client)
    monkeypatch.setenv("AIML_ASSESSMENT_BUCKET_NAME", "synthetic-artifact-bucket")
    assessment = single.get_assessment_results(
        EXECUTION, ACCOUNT, expected_regions=REGIONS
    )
    multi_result = multi.load_multi_account_results(
        tmp_path,
        scope_manifest=manifest,
        service_selection=selection,
        timestamp="2026-01-01T00:00:00Z",
    )
    accepted = case in ("bucket", "denied")
    ingested_rows = [
        finding
        for owner in SERVICES
        for findings in assessment.get(owner, {}).values()
        for finding in findings
    ]
    for findings in (ingested_rows, multi_result["all_findings"]):
        bucket_rows = [
            finding
            for finding in findings
            if finding.get("Resource_ID") == row["Resource_ID"]
            and finding["Check_ID"] == check
        ]
        assert len(bucket_rows) == int(accepted)
        if accepted:
            assert bucket_rows[0]["Region"] == "us-west-2"
            assert bucket_rows[0]["_artifact_region"] == "us-east-1"
            assert bucket_rows[0]["Finding_Details"] == details
            assert bucket_rows[0]["Status"] == row["Status"]
        assert any(
            finding["Check_ID"] == "BR-20"
            and finding["Account_ID"] == ACCOUNT
            and finding["Region"] == "us-east-1"
            for finding in findings
        ), "Valid observations in the same artifact must survive isolation."
    reports = [
        single.generate_html_report(
            data, show_finserv=False, service_selection=selection
        )
        for data in (direct_assessment, assessment)
    ]
    reports.append(multi.render_multi_account_report(multi_result))
    for html in reports:
        result = embedded_register(html)
        assert_check_inventory(result)
        found = [
            item
            for item in result["checks"]
            if item["source_check_id"] == check
            and item["resource"] == row["Resource_ID"]
        ]
        if accepted:
            assert len(found) == 1
            actual = found[0]
            assert actual["region"] == "us-west-2"
            assert actual["observation"]["_artifact_region"] == "us-east-1"
            assert actual["status"] == row["Status"]
            if case == "denied":
                assert actual["result_kind"] == "unavailable"
            else:
                control_id = "AIR-FND-DAT-02" if check == "BR-47" else "AIR-FND-DAT-05"
                assert control_id in actual["aisf_control_ids"]
            assert not result["artifact_issues"]
        else:
            assert not found
            assert any(
                issue["kind"] == "scope-mismatch" for issue in result["artifact_issues"]
            )


@pytest.mark.parametrize(
    "failure_kind",
    [
        "missing",
        "zero-byte",
        "header-only",
        "malformed",
        "bad-utf8",
        "wrong-schema",
        "unreadable",
    ],
)
def test_invalid_selected_csv_is_incomplete_at_both_real_ingestion_boundaries(
    tmp_path, monkeypatch, failure_kind
):
    selection = {owner: owner == "bedrock" for owner in SERVICES}
    _, manifest = _prepared_reports(tmp_path, selection, False, False)
    directory = tmp_path / ACCOUNT
    broken = directory / f"bedrock_security_report_{EXECUTION}_us-east-1.csv"
    if failure_kind == "missing":
        broken.unlink()
    elif failure_kind != "unreadable":
        content = {
            "zero-byte": b"",
            "header-only": csv_text([]).encode(),
            "malformed": (
                csv_text([observation(status="Failed")]) + '"unterminated'
            ).encode(),
            "bad-utf8": b"\xff",
            "wrong-schema": b"Check_ID,Status\nBR-20,Passed\n",
        }[failure_kind]
        broken.write_bytes(content)
    original_read = Path.read_bytes

    def read(path):
        if failure_kind == "unreadable" and path == broken:
            raise PermissionError("Synthetic selected artifact read denied")
        return original_read(path)

    monkeypatch.setattr(Path, "read_bytes", read)
    client = MagicMock()
    client.get_paginator.return_value.paginate.side_effect = lambda **kwargs: [
        {
            "Contents": [
                {"Key": path.name}
                for path in sorted(directory.iterdir())
                if path.name.startswith(kwargs["Prefix"])
            ]
        }
    ]
    client.get_object.side_effect = lambda **kwargs: {
        "Body": io.BytesIO((directory / kwargs["Key"]).read_bytes())
    }
    monkeypatch.setattr(single.boto3, "client", lambda *args, **kwargs: client)
    monkeypatch.setenv("AIML_ASSESSMENT_BUCKET_NAME", "synthetic-artifact-bucket")
    assessment = single.get_assessment_results(EXECUTION, ACCOUNT)
    with pytest.raises(ValueError, match="Incomplete assessment artifacts"):
        single.validate_assessment_artifacts(
            assessment,
            EXECUTION,
            completion_input(selection),
            require_receipts=True,
        )
    single_html = single.generate_html_report(
        assessment, show_finserv=False, service_selection=selection
    )
    multi_result = multi.load_multi_account_results(
        tmp_path,
        scope_manifest=manifest,
        service_selection=selection,
        timestamp="2026-01-01T00:00:00Z",
    )
    multi_html = multi.render_multi_account_report(multi_result)
    expected_kind = "unreadable" if failure_kind == "bad-utf8" else failure_kind
    for html in (single_html, multi_html):
        result = embedded_register(html)
        assert_check_inventory(result)
        assert expected_kind in {issue["kind"] for issue in result["artifact_issues"]}
        assert result["gaps"]
        east = matching_checks(result, "BR-20", account=ACCOUNT, region="us-east-1")
        west = matching_checks(result, "BR-20", account=ACCOUNT, region="us-west-2")
        assert west and west[0]["status"] == "Passed"
        if failure_kind == "malformed":
            assert east and east[0]["status"] == "Failed"
        else:
            assert not east, (
                "Unavailable collector scope must not manufacture a source result."
            )


def test_multi_keeps_failed_empty_account_missing_region_and_valid_evidence(tmp_path):
    selection = {owner: owner == "bedrock" for owner in SERVICES}
    assessment, manifest = _prepared_reports(tmp_path, selection, False, False)
    del assessment  # Multi-account path must read staged CSVs and the manifest.
    west = tmp_path / ACCOUNT / f"bedrock_security_report_{EXECUTION}_us-west-2.csv"
    west.unlink()
    other = tmp_path / OTHER_ACCOUNT
    for path in other.iterdir():
        path.unlink()
    manifest["accounts"][1]["status"] = "FAILED"
    manifest["accounts"][1]["failure"] = "Synthetic assessment timeout"
    result = multi.load_multi_account_results(
        tmp_path,
        scope_manifest=manifest,
        service_selection=selection,
        timestamp="2026-01-01T00:00:00Z",
    )
    exported = embedded_register(multi.render_multi_account_report(result))
    assert_check_inventory(exported)
    assert set(exported["scope"]["accounts"]) == {ACCOUNT, OTHER_ACCOUNT}
    assert matching_checks(exported, "BR-20", account=ACCOUNT, region=REGIONS[0])
    assert not matching_checks(exported, "BR-20", account=ACCOUNT, region=REGIONS[1])
    assert not matching_checks(exported, "BR-20", account=OTHER_ACCOUNT)
    assert exported["gaps"]
    assert "Synthetic assessment timeout" in json.dumps(exported["artifact_issues"])


class _Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []
        self.event_handlers = []

    def handle_starttag(self, tag, attrs):
        self.hrefs.extend(value for key, value in attrs if key == "href")
        self.event_handlers.extend(key for key, _ in attrs if key.startswith("on"))


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "//evil.example.invalid/",
        "file:///etc/passwd",
        'https://safe.example.invalid/" onclick="alert(1)',
        "https://[",
        "https://user:password@example.invalid/",
        "https://example.invalid/\nunsafe",
    ],
)
def test_untrusted_evidence_is_escaped_and_unsafe_links_never_emitted(url):
    payload = '</script><img src=x onerror="alert(1)">'
    result = register(
        [observation(status="Failed", Finding_Details=payload, Reference=url)]
    )
    projected = aisf_results.build_aisf_check_results(result)
    html = aisf_view.render_context(projected) + "".join(
        aisf_view.render_check_details(check) for check in projected["checks"]
    )
    assert payload not in html
    links = _Links()
    links.feed(html)
    assert not links.event_handlers
    assert url not in links.hrefs
    assert all(href.startswith("https://") for href in links.hrefs if href)
    assert all('"' not in href and "\n" not in href for href in links.hrefs if href)
    exported = embedded_register(html)
    assert_check_inventory(exported)
    evidence = matching_checks(exported, "BR-20")[0]["observation"]
    assert evidence["Finding_Details"] == payload
    assert evidence["Reference"] == url
