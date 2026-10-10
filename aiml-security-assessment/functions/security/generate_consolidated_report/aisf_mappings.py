"""AISF framework view: derive `AISF-*` rows from check verdicts that already ship.

The AWS AI Security Framework (AISF) is registered in
`report_template.COMPLIANCE_STANDARDS` as a **derived** standard. No Lambda runs
AISF checks, no AISF CSV is written to S3, and no Step Functions branch exists
for it. Every row in this module is a relabelling of a verdict an incumbent
check already produced, computed at consolidation time by
`derive_aisf_findings()`.

Why derived rather than a producing module: an incumbent check already asserts
each of the three AISF controls handled here exactly, so there is nothing new to
call. A control an incumbent asserts only in part must NOT be added here:
restating its `Passed` under the AISF control id would publish a false pass.

**Ids are allocated once and never renumbered.** `AISF_DERIVED_MAP` is
append-only: a new control takes the next free `AISF-` number. Reusing or
resequencing an id silently rewrites the meaning of every archived report and
CSV that already carries it. `AISF-00` is reserved for the coverage marker row
emitted by `derive_aisf_findings()` and must never be allocated to a control.
An id removed from the map moves to `RETIRED_AISF_IDS` and is never
reallocated either, so the next control takes the number after the highest id
in the two together.

The control text (risk, severity, resolution, reference) is baked into the literal
because the AISF repository is not on the Lambda's filesystem at runtime. A
change to a control's YAML in that repository has to be copied here by hand.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# The report slug this standard's rows route to. Must match the `slug` on the
# AISF entry in `report_template.COMPLIANCE_STANDARDS`.
AISF_SERVICE_SLUG = "aisf"

# Reserved for the coverage marker row (the `OW-00` analogue). Never a control.
AISF_COVERAGE_CHECK_ID = "AISF-00"

# The Region value the assessment modules put on once-per-account findings.
# Must match `GLOBAL_REGION_LABEL` in the module Lambdas and in `app.py`.
AISF_GLOBAL_REGION = "Global"

# Severity comes from the AISF control's own `risk` field, NOT from the source
# check's severity. This deviates from OWASP, which inherits the source row's
# severity (AGENTS.md:132). The deviation is deliberate: an `AISF-` row is a
# verdict on an AISF control, and the severity of one incumbent check is not
# that control's risk rating. AISF-08 makes the difference concrete: it derives
# from three source checks whose own severities differ, so there is no single
# source severity to inherit.
#
# AISF `risk` has five bands and this repository's `SeverityEnum` has four:
# there is no `Critical`. The collapse below follows the decision recorded at
# `docs/SECURITY_CHECKS_RESPONSIBLE_AI_GRC_SEVERITY_METHODOLOGY.md:156-169`
# ("keep four levels; a genuinely critical risk is reported as High"), so this
# module inherits an existing repository decision rather than inventing one.
AISF_RISK_TO_SEVERITY = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}

# A band whose collapse changes its name is disclosed in every row it produces.
# The methodology accepts "a genuinely critical risk is reported as High" as a
# known cost of keeping four levels; stating it in the row keeps that cost in
# front of the person reading the finding, who otherwise sees `High` against a
# control AISF rates critical and has no way to tell that a downgrade happened.
# `critical` is the only such band today: `high`, `medium` and `low` keep their
# names. A future band that does not is caught by
# `tests/test_aisf_derived_standard.py`. Adding
# a control in a collapsed band also changes the sentence in
# `docs/SECURITY_CHECKS_AISF.md` that names the three critical ones, which is
# what `TestSeverityCollapseDisclosure.CRITICAL_IDS` pins.
SEVERITY_COLLAPSE_NOTE = {
    "critical": (
        "AISF risk: critical, reported as High because this framework's "
        "severity scale has four levels and no Critical band (see "
        "docs/SECURITY_CHECKS_RESPONSIBLE_AI_GRC_SEVERITY_METHODOLOGY.md "
        "section 6)."
    ),
}

# Status `N/A` forces `Severity=Informational`, matching the OWASP rule at
# AGENTS.md:132: a row that asserts nothing must not carry High/Medium.
NA_SEVERITY = "Informational"

# Ids removed from AISF_DERIVED_MAP, each with the control it named and why.
# Allocated for good: none of these may be given to another control. The five
# below left the map once their incumbents were found to assert only part of
# the control, because a restated Passed would claim the whole control.
RETIRED_AISF_IDS: Dict[str, Dict[str, str]] = {
    "AISF-01": {
        "control": "AIR-ACR-GW-01",
        "reason": "the incumbent asserts only part of the control",
    },
    "AISF-02": {
        "control": "AIR-ACR-RT-09",
        "reason": "the incumbent asserts only part of the control",
    },
    "AISF-03": {
        "control": "AIR-BDR-GRD-01",
        "reason": "the incumbent asserts only part of the control",
    },
    "AISF-04": {
        "control": "AIR-BDR-GRD-03",
        "reason": "the incumbent asserts only part of the control",
    },
    "AISF-06": {
        "control": "AIR-BDR-MDL-10",
        "reason": "the incumbent asserts only part of the control",
    },
}

# Append-only. See the module docstring: ids are allocated once, never renumbered.
AISF_DERIVED_MAP: List[Dict[str, Any]] = [
    {
        "check_id": "AISF-05",
        "control": "AIR-BDR-KB-03",
        # asserted in full by: BR-20
        "sources": ["BR-20"],
        "finding": "AISF AIR-BDR-KB-03: Knowledge Base Vector Store Encryption",
        "risk": "high",
        "severity": "High",
        "resolution": "Do not assume one customer managed key covers the whole knowledge base — the default is an AWS owned key, and how far a CMK reaches depends on the vector store. On a Bedrock Managed Knowledge Base the CMK set at creation covers transient ingestion storage and the managed vector store through a Bedrock-created KMS grant, so the creating identity needs kms:CreateGrant, kms:GenerateDataKey and kms:Decrypt on that key conditioned with kms:ViaService bedrock.<region>.amazonaws.com, while the knowledge base service role needs no KMS permissions at all. On a bring-your-own vector store the Bedrock CMK covers only transient ingestion storage and the retrieval session (kmsKeyArn on RetrieveAndGenerate); it reaches the index itself only where Bedrock created that store for you (quick create for OpenSearch Serverless or Amazon S3 Vectors). Otherwise encrypt each store on its own terms: an OpenSearch Serverless collection is always encrypted at rest but uses a CMK only when an encryption policy sets AWSOwnedKey false with KmsARN (or CreateCollection names the key), and the choice is immutable — changing it means recreating the collection. Aurora pgvector inherits the DB cluster's own StorageEncrypted KMS key. Pinecone, Redis Enterprise Cloud and MongoDB Atlas are third-party SaaS that AWS KMS does not encrypt, so the AWS-side controls there are a CMK on the Secrets Manager secret holding the credentials plus TLS in transit. Set serverSideEncryptionConfiguration.kmsKeyArn on each data source. Critically, the key is not the access boundary: OpenSearch Serverless does not check a caller's permissions on the CMK, so anyone a data access policy admits can query the encrypted vectors — restrict the index with the collection's data access policy and network policy plus aoss:APIAccessAll scoped to that one collection ARN.",
        "reference": "https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-kb.html",
    },
    {
        "check_id": "AISF-07",
        "control": "AIR-SGM-EP-08",
        # asserted in full by: SM-18, SM-42
        "sources": ["SM-18", "SM-42"],
        "finding": "AISF AIR-SGM-EP-08: Batch Inference Network and Encryption Parity",
        "risk": "high",
        "severity": "High",
        "resolution": "A batch transform job inherits its private-network posture from the model, not from the job: set VpcConfig (private-subnet Subnets + SecurityGroupIds) and EnableNetworkIsolation=true on CreateModel, then reference that model by ModelName on CreateTransformJob — the transform job itself takes no VpcConfig or isolation flag. Get the S3 path right, because the obvious reading of network isolation is wrong here and it changes what your endpoint and bucket policies must admit: the algorithm container never reads or writes S3 itself. AWS documents that internal SageMaker processes running on the nodes download the input data and upload the results, and that whether or not you specify VpcConfig the container is given no AWS credentials. With VpcConfig, SageMaker creates two elastic network interfaces — one for the algorithm container and one for Amazon S3 — and EnableNetworkIsolation removes the container's interface while the S3 interface remains and is what carries the transfer. So an Amazon S3 gateway VPC endpoint is still required for a private path, but scope its endpoint policy and the bucket policy to the SageMaker-managed transfer and the job's execution role rather than to any identity inside the container. Encrypt at rest with KMS customer-managed keys on the job — TransformResources.VolumeKmsKeyId for the compute EBS volume and TransformOutput.KmsKeyId for the S3 results — and keep the source/output buckets SSE-KMS with an aws:SecureTransport deny. Note where preventive IAM can and cannot carry this: CreateTransformJob defines sagemaker:OutputKmsKeyArn and sagemaker:VolumeKmsKeyArn condition keys, so the KMS half is enforceable with an SCP on the job itself, while sagemaker:NetworkIsolation, sagemaker:VpcSubnets and sagemaker:VpcSecurityGroupIds are CreateModel keys only — the guardrail has to be written across both actions, and a policy that conditions only on CreateTransformJob leaves the network posture unenforced. This closes the batch-inference path that the real-time endpoint controls (AIR-SGM-EP-01/03) do not cover.",
        "reference": "https://docs.aws.amazon.com/sagemaker/latest/dg/batch-vpc.html",
    },
    {
        "check_id": "AISF-08",
        "control": "AIR-SGM-TRN-05",
        # asserted in full by: SM-09, SM-01, SM-03
        "sources": ["SM-09", "SM-01", "SM-03"],
        "finding": "AISF AIR-SGM-TRN-05: Notebook and Development Environment Access Control",
        "risk": "medium",
        "severity": "Medium",
        "resolution": "Hold SageMaker Studio and Notebook Instances to the same bar as production: attach least-privilege execution roles (avoid broad AmazonSageMakerFullAccess), enforce sagemaker:DirectInternetAccess=Disabled, sagemaker:RootAccess=Disabled, private VpcSubnets/VpcSecurityGroupIds and sagemaker:VolumeKmsKeyArn via IAM, and restrict presigned-URL access with aws:SourceIp / aws:sourceVpce conditions on CreatePresignedDomainUrl / CreatePresignedNotebookInstanceUrl. Log all API activity through CloudTrail into CloudWatch and monitor with the AWS Config rules sagemaker-notebook-no-direct-internet-access and sagemaker-notebook-instance-kms-key-configured (both Periodic, so treat them as a lagging backstop to the IAM conditions, and pass kmsKeyArns to the latter to pin approved keys).",
        "reference": "https://docs.aws.amazon.com/whitepapers/latest/sagemaker-studio-admin-best-practices/permissions-management.html",
    },
]


# Source Check_ID prefix -> the service switch (`report_template.CORE_SERVICE_LABELS`)
# that runs it. A control whose sources all belong to a deselected service is
# not derived: the report shows that service as "Not selected", and an AISF-00
# row for it would ask the user to rerun a check they chose not to run.
SOURCE_PREFIX_TO_SERVICE = {
    "BR": "bedrock",
    "SM": "sagemaker",
    "AC": "agentcore",
    "AG": "agentcore",
    "AR": "agent-registry",
}


def _source_selected(check_id: str, selected_services: Dict[str, bool]) -> bool:
    service = SOURCE_PREFIX_TO_SERVICE.get(check_id.split("-", 1)[0].upper())
    return selected_services.get(service, True) if service else True


def _source_check_ids() -> set:
    """Every incumbent Check_ID any mapping derives from."""
    return {cid for m in AISF_DERIVED_MAP for cid in m["sources"]}


def _normalise(row: Dict[str, Any]) -> Dict[str, str]:
    """Read a source row under either key casing.

    The report Lambda hands this function CSV-cased rows (`Check_ID`, `Region`,
    `Account_ID`); the root consolidator's rows are lowercase-keyed
    (`consolidate_html_reports.py:146-156`). Normalising on input means one
    derivation serves both callers.
    """
    return {
        "check_id": str(row.get("Check_ID", row.get("check_id", "")) or "").strip(),
        "account_id": str(
            row.get("Account_ID", row.get("account_id", "")) or ""
        ).strip(),
        "region": str(row.get("Region", row.get("region", "")) or "").strip(),
        "status": str(row.get("Status", row.get("status", "")) or "").strip(),
    }


def _collapse_note(risk: str, status: str) -> str:
    """The pre-collapse disclosure for one row, empty when nothing was collapsed.

    An `N/A` row carries `Informational` regardless of the control's risk, so it
    says which severity it is carrying and why: without that clause the note
    would read as a claim about this row's severity instead of about the band.
    """
    note = SEVERITY_COLLAPSE_NOTE.get(risk, "")
    if note and status == "N/A":
        note = f"{note} This row carries {NA_SEVERITY} because it asserts no verdict."
    return note


def _legs_txt(present: Dict[str, List[str]], have: List[str]) -> str:
    """Name each present leg with its verdicts, multiplicity included.

    One incumbent check emits one finding per resource, so a leg routinely holds
    several statuses for one account and region: 16 for `AG-24` and 11 for the
    `SM-09`/`SM-01`/`SM-03` leg in one account and region, measured against a
    real account. Quoting one status per leg would credit a Failed resource to
    whichever verdict happened to be listed last, and the derived status is
    aggregated over all of them, so the sentence that explains the status has to
    show the same population.
    """
    order = {"failed": 0, "passed": 1, "n/a": 2}
    parts = []
    for cid in have:
        statuses = present[cid]
        if len(statuses) == 1:
            parts.append(f"{cid} ({statuses[0]})")
            continue
        counts: Dict[str, int] = {}
        for status in statuses:
            counts[status] = counts.get(status, 0) + 1
        # Sorted by verdict, not by the order the rows arrived in, so the same
        # findings in a different CSV order produce the same sentence.
        breakdown = ", ".join(
            f"{n} {s or 'blank'}"
            for s, n in sorted(
                counts.items(), key=lambda kv: (order.get(kv[0].lower(), 3), kv[0])
            )
        )
        parts.append(f"{cid} ({len(statuses)} findings: {breakdown})")
    return ", ".join(parts)


def _aggregate_status(statuses: List[str]) -> str:
    """Failed if any leg failed; Passed only if every leg passed; else N/A."""
    lowered = [s.lower() for s in statuses]
    if any(s == "failed" for s in lowered):
        return "Failed"
    if lowered and all(s == "passed" for s in lowered):
        return "Passed"
    return "N/A"


def _row(
    check_id: str,
    finding: str,
    details: str,
    resolution: str,
    reference: str,
    severity: str,
    status: str,
    account_id: str,
    region: str,
) -> Dict[str, str]:
    """Build one derived finding in the CSV-cased shape the report layer reads.

    Every key here is read by `report_template.generate_table_rows` (:201-234),
    which accepts either casing via `finding.get("x", finding.get("X"))`.
    """
    if status == "N/A":
        severity = NA_SEVERITY
    return {
        "Check_ID": check_id,
        "Finding": finding,
        "Finding_Details": details,
        "Resolution": resolution,
        "Reference": reference,
        "Severity": severity,
        "Status": status,
        "Region": region,
        "Account_ID": account_id,
        "_service": AISF_SERVICE_SLUG,
    }


def derive_aisf_findings(
    source_rows: List[Dict[str, Any]],
    selected_services: Optional[Dict[str, bool]] = None,
) -> List[Dict[str, str]]:
    """Restate incumbent verdicts as `AISF-` rows, one per control per join key.

    The join key is `(Account_ID, Region)`. A source check can also emit rows
    under the `Global` sentinel, from a once-per-account leg on the primary
    Region. An account-wide verdict holds in every Region, so each `Global` row
    is folded into every regional key of the same account and aggregated there
    with the regional rows. The `Global` key itself
    is emitted only for an account that has no regional key: beside a regional
    verdict it would repeat the same evidence as a half-populated `N/A`.

    A control whose legs are not all present for a key that has at least one leg
    is emitted naming the missing `Check_ID`s, never dropped: `Failed` when a
    present leg failed, otherwise `Status=N/A`. A
    silent drop would read as "this control was not relevant here" when what
    actually happened is that coverage was incomplete. A control whose sources
    all belong to a service deselected in `selected_services` (the
    `core_service_selection()` dict) gets no row and no AISF-00 mention.

    Per-row work is isolated with try/except, matching
    `owasp_assessments.build_owasp_mapping_findings`, so one malformed source
    row drops only itself.
    """
    selected_services = selected_services or {}
    relevant = _source_check_ids()
    # (account_id, region) -> {source check id: [status per source finding]}
    # A list, not a status: an incumbent check emits one finding per resource, so
    # one check id contributes several statuses to one key. Keeping only the last
    # one published a Passed for a key that held a Failed resource whenever the
    # check emitted its summary Passed row after its per-resource rows, which is
    # the order BR-20 emits in.
    legs: Dict[tuple, Dict[str, List[str]]] = {}
    for raw in source_rows:
        try:
            row = _normalise(raw)
            if row["check_id"].upper() not in relevant:
                continue
            key = (row["account_id"], row["region"])
            legs.setdefault(key, {}).setdefault(row["check_id"].upper(), []).append(
                row["status"]
            )
        except Exception as e:
            logger.warning(f"AISF: skipping unreadable source row: {e}")
            continue

    # Kept apart from the regional keys, so a regional Passed cannot publish while
    # the same check's Global row for that account is Failed.
    global_legs = {
        account_id: present
        for (account_id, region), present in legs.items()
        if region == AISF_GLOBAL_REGION
    }
    regional_accounts = {
        account_id for (account_id, region) in legs if region != AISF_GLOBAL_REGION
    }
    # (account_id, region) -> source check ids that carry folded Global rows
    folded: Dict[tuple, List[str]] = {}
    for (account_id, region), present in list(legs.items()):
        if region == AISF_GLOBAL_REGION:
            if account_id in regional_accounts:
                del legs[(account_id, region)]
            continue
        for cid, statuses in global_legs.get(account_id, {}).items():
            present.setdefault(cid, []).extend(statuses)
            folded.setdefault((account_id, region), []).append(cid)

    findings: List[Dict[str, str]] = []
    for (account_id, region), present in sorted(legs.items()):
        folded_here = folded.get((account_id, region), [])
        absent_controls: List[str] = []
        for mapping in AISF_DERIVED_MAP:
            try:
                sources = mapping["sources"]
                if not any(_source_selected(c, selected_services) for c in sources):
                    continue
                have = [cid for cid in sources if cid in present]
                missing = [cid for cid in sources if cid not in present]
                if not have:
                    # No leg at all for this key. Reported once per key by the
                    # AISF-00 row below rather than as a per-control N/A, so an
                    # account that never ran a service does not get a wall of
                    # rows for controls that were never in play.
                    absent_controls.append(
                        f"{mapping['check_id']} ({mapping['control']}, "
                        f"sources {', '.join(sources)})"
                    )
                    continue
                legs_txt = _legs_txt(present, have)
                status = _aggregate_status([s for cid in have for s in present[cid]])
                if missing and status == "Failed":
                    # A present leg already failed, so the control is
                    # non-compliant whatever the missing legs would report.
                    details = (
                        f"AISF control {mapping['control']}. Derived from "
                        f"{legs_txt}. Source checks not found for this account "
                        f"and region: {', '.join(missing)}. A present source "
                        "check failed, so the control fails regardless of them."
                    )
                elif missing:
                    status = "N/A"
                    details = (
                        f"AISF control {mapping['control']}. Derived from "
                        f"{legs_txt}. Source checks not found for this account "
                        f"and region: {', '.join(missing)}. Coverage is "
                        "incomplete, so no verdict is asserted for this control."
                    )
                else:
                    details = (
                        f"AISF control {mapping['control']}. Derived from "
                        f"{legs_txt}. This row restates existing check verdicts "
                        "under an AISF control id; it is not an additional check."
                    )
                folded_legs = [cid for cid in have if cid in folded_here]
                if folded_legs:
                    details = (
                        f"{details} The findings for {', '.join(folded_legs)} "
                        "include the account-wide findings reported under "
                        f"{AISF_GLOBAL_REGION}, which apply in every Region."
                    )
                note = _collapse_note(mapping["risk"], status)
                if note:
                    details = f"{details} {note}"
                findings.append(
                    _row(
                        check_id=mapping["check_id"],
                        finding=mapping["finding"],
                        details=details,
                        resolution=mapping["resolution"],
                        reference=mapping["reference"],
                        severity=mapping["severity"],
                        status=status,
                        account_id=account_id,
                        region=region,
                    )
                )
            except Exception as e:
                logger.warning(
                    f"AISF: skipping mapping {mapping.get('check_id')} for "
                    f"{account_id}/{region}: {e}"
                )
                continue

        if absent_controls:
            findings.append(
                _row(
                    check_id=AISF_COVERAGE_CHECK_ID,
                    finding="AISF Derived Control Coverage",
                    details=(
                        "AISF-relevant source checks were present for this "
                        "account and region, but no source check was found for "
                        f"{len(absent_controls)} derived control(s): "
                        f"{'; '.join(absent_controls)}. Those controls are "
                        "unassessed here rather than compliant."
                    ),
                    resolution=(
                        "Review the upstream assessment for the named source "
                        "checks and rerun. This row is informational and "
                        "records incomplete AISF coverage, not a control "
                        "failure."
                    ),
                    reference="",
                    severity=NA_SEVERITY,
                    status="N/A",
                    account_id=account_id,
                    region=region,
                )
            )

    return findings
