# AWS AI Security Framework (AISF) Checks

This document catalogs the `AISF-XX` rows the report renders under "By
Compliance Standard", the AWS AI Security Framework control each one reports on,
and the shipped BR/SM/AC/AG check every row is derived from.

- **Reference:** [AWS Well-Architected Generative AI Lens](https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/generative-ai-lens.html),
  plus the control-specific AWS documentation linked in the per-control tables
  below.
- **Opt-in:** none. AISF is a derived view over checks that already run, so it
  needs no deployment parameter and adds no scan time.
- **Report location:** the "By Compliance Standard" sidebar section, alongside
  OWASP Top 10 for LLM.
- **Coverage:** 3 of the 105 in-scope AISF controls carry a derived `AISF-` row;
  the remaining 102 are not yet rendered as a row. The scope is every
  machine-checkable AISF control, including the foundation controls, which assert
  over the account or runtime an AI workload sits on. A row is a narrower claim
  than coverage: 64 of the 105 are covered by checks that already ship and assert
  the whole control, 39 are asserted only in part, and 2 are not implementable
  from configuration, because each asks about evidence no AWS API returns. These
  are the figures the report's own scope text states, and
  `tests/test_aisf_derived_standard.py` reconciles that text against
  `AISF_DERIVED_MAP`.
  Five ids, `AISF-01`, `AISF-02`, `AISF-03`, `AISF-04` and `AISF-06`, are
  retired: each restated a check that asserts only part of its control, so the
  view no longer derives them, and the ids are never reallocated.
- **Traceability:** a control asserted only in part never earns an `AISF-` row.
  The `Compliance_Frameworks` CSV column names it on the producer rows instead,
  with a `(partial)` qualifier, beside the covered controls that have no row yet.
  It is described under
  [Traceability column on producer rows](#traceability-column-on-producer-rows).
  A tag carries no verdict.

## Disclaimer

> **These mappings are PRELIMINARY and ILLUSTRATIVE.** They have not been
> reviewed by AWS Security Assurance Services or external auditors. Validate
> each mapping against your own reading of the AISF control before relying on
> an `AISF-` row as audit evidence. A control that is absent from this catalog
> is unassessed, which is not evidence of compliance.

## Design

AISF is a **derived** compliance standard. No Lambda runs AISF checks, no
`aisf_security_report_*.csv` is written to S3, and the state machine has no
AISF branch. `derive_aisf_findings()` in
`aiml-security-assessment/functions/security/generate_consolidated_report/aisf_mappings.py`
runs at consolidation time in both report paths (the
`generate_consolidated_report` Lambda for single-account runs, and the root
`consolidate_html_reports.py` for multi-account runs) and restates verdicts the
incumbent checks already produced under AISF control ids.

Every control below is covered, meaning one or more incumbent checks assert
the control exactly. A control its incumbents assert only in part is
deliberately excluded: republishing that incumbent's `Passed` under the AISF
control id would publish a pass the assessment never earned.
`tests/test_aisf_derived_standard.py` pins the map: each id carries the
registered `AISF-` prefix, no retired id or control reappears, and each
mapped control's baked severity is the collapse of its declared risk band.

**`AISF-` rows are not counted in the framework's 277-check total.** They carry
no new assertion, so counting them would double-count the incumbent check. They
are excluded from the report's pass-rate denominator and from Open Action Items
for the same reason, which is how OWASP-mapped rows already behave.

**Ids are allocated once and never renumbered.** `AISF_DERIVED_MAP` is
append-only: a new control takes the next free `AISF-` number. Reusing or
resequencing an id rewrites the meaning of every archived report that already
carries it.

### Registry entry

The standard is registered by one entry in `COMPLIANCE_STANDARDS`
(`report_template.py`) carrying `"derived": True`. That key keeps the slug out
of the S3 prefix list the report Lambda builds in `app.py`: the Lambda's
`s3:ListBucket` grant restricts `s3:prefix` to the producing artifacts, so
listing a prefix for a standard that writes no CSV returns `AccessDenied` and
fails report generation for every category. A producing standard (the
OWASP-style wire-up in
[DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md#adding-a-compliance-standard-owasp-style))
omits the key.

### Status semantics

| Situation | Emitted |
| ----------- | --------- |
| every source check for the control passed | `Passed` |
| any source check for the control failed | `Failed` |
| a source check reported `N/A`, so no verdict is available | `N/A`, `Informational` |
| some source checks present for the account and region, others absent | `N/A`, `Informational`, naming the absent `Check_ID`s |
| no source check for the control present at all | no `AISF-` row for that control; the absence is reported once per account and region by `AISF-00` |

A source check emits one finding per resource, so a leg normally carries several
verdicts for one account and region. All of them are aggregated, and
`Finding_Details` names the count per leg (`BR-20 (10 findings: 9 Failed, 1
Passed)`), so a failing resource cannot be hidden behind a later `Passed` row
from the same check. BR-20 emits its summary `Passed` row after its per-resource
rows, which is the order that made this concrete.

A source check that runs once per account, on the primary Region, reports under
the `Global` Region. An account-wide verdict holds in every Region, so each `Global` row is aggregated into every
regional key of the same account, and `Finding_Details` says so. The `Global`
key gets its own `AISF-` rows only for an account with no regional key.
Otherwise a `Global` `Failed` would sit beside a regional `Passed` for the same
control.

`AISF-00` is a report-completeness marker, not an AISF control. It lists every
derived control that had no source check for that account and region, so an
incomplete scan reads as unassessed instead of silently omitting rows.

### Severity

Severity comes from the AISF control's own `risk` band, not from the source
row. An `AISF-` row is a verdict on an AISF control, and one incumbent check's
severity is not that control's risk rating; `AISF-08` makes that concrete,
since its three source checks carry different severities. AISF uses five risk
bands and this framework's `SeverityEnum` has four, so `critical` and `high`
both report as `High`, following section 6 of
[SECURITY_CHECKS_RESPONSIBLE_AI_GRC_SEVERITY_METHODOLOGY.md](SECURITY_CHECKS_RESPONSIBLE_AI_GRC_SEVERITY_METHODOLOGY.md),
which keeps four levels and accepts that a genuinely critical risk is reported
as `High`. No derived control is rated `critical`: the three that were
(`AISF-01`, `AISF-03`, `AISF-04`) are retired. A control in that band names the
band and the downgrade in its `Finding_Details`, so a reader who sees `High`
against a critical control learns why from the finding itself. A row with `Status=N/A` always reports `Informational`.

## Check catalogue

| Check | AISF control | Severity | Source checks |
| ------- | -------------- | ---------- | --------------- |
| AISF-00 | none (coverage marker) | Informational | none |
| AISF-05 | AIR-BDR-KB-03 | High | `BR-20` |
| AISF-07 | AIR-SGM-EP-08 | High | `SM-18`, `SM-42` |
| AISF-08 | AIR-SGM-TRN-05 | Medium | `SM-09`, `SM-01`, `SM-03` |

### AISF-05 AIR-BDR-KB-03 Knowledge Base Vector Store Encryption

Is the underlying vector store or index for a knowledge base encrypted and
access-restricted the same way as the source data it was built from?

| Source | Signal |
| -------- | -------- |
| BR-20 | Knowledge Base Customer-Managed KMS Encryption Check |

Reference: <https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-kb.html>

### AISF-07 AIR-SGM-EP-08 Batch Inference Network and Encryption Parity

Are batch (offline) inference jobs that process data in bulk held to the same
private-network and encryption standard as real-time inference?

| Source | Signal |
| -------- | -------- |
| SM-18 | SageMaker Transform Job Encryption Check (model VPC/isolation config plus job KMS configuration) |
| SM-42 | SageMaker Batch Transform Creation Guardrail (SCP and identity guardrails on `CreateModel` and `CreateTransformJob` for encryption, approved network and no direct internet access) |

Reference: <https://docs.aws.amazon.com/sagemaker/latest/dg/batch-vpc.html>

### AISF-08 AIR-SGM-TRN-05 Notebook and Development Environment Access Control

Is access to notebook instances and development environments used for model
experimentation restricted and monitored the same way as production access?

This is the one control with several source checks. All three legs must report
`Passed` for `AISF-08` to report `Passed`; any `Failed` leg makes it `Failed`;
a leg that is missing or `N/A` makes it `N/A` and the finding details name the
leg.

| Source | Signal |
| -------- | -------- |
| SM-09 | SageMaker Notebook Root Access Check |
| SM-01 | SageMaker Internet Access Check |
| SM-03 | SageMaker Data Protection Check |

Reference: <https://docs.aws.amazon.com/whitepapers/latest/sagemaker-studio-admin-best-practices/permissions-management.html>

### Retired ids

These ids were derived once and are not derived now. Each restated an incumbent
check that asserts only part of its control, so a
restated `Passed` would have claimed the whole control. The ids stay allocated
in `RETIRED_AISF_IDS` and are never given to another control, so an archived
report that carries one still means the control below. The incumbent checks
still run, and their producer rows still name the control in the
`Compliance_Frameworks` column with a `(partial)` tag.

| Id | AISF control | Incumbent | Why retired |
| ---- | -------------- | ----------- | ------------- |
| AISF-01 | AIR-ACR-GW-01 | `AG-24` | the incumbent asserts only part of the control |
| AISF-02 | AIR-ACR-RT-09 | `AC-06` | the incumbent asserts only part of the control |
| AISF-03 | AIR-BDR-GRD-01 | `BR-10` | the incumbent asserts only part of the control |
| AISF-04 | AIR-BDR-GRD-03 | `BR-26` | the incumbent asserts only part of the control |
| AISF-06 | AIR-BDR-MDL-10 | `BR-37` | the incumbent asserts only part of the control |

## Traceability column on producer rows

The `AISF-` rows above are derived verdicts. The `Compliance_Frameworks` column
publishes no verdict at all: it tags rows the BR/SM/AC/AG/AR checks already emit
with the AISF control each check contributes to, so a reader of
`bedrock_security_report_*.csv` can trace a row back to the framework. The
`Status` column still carries the verdict.

### The qualifier is what makes a partly asserted control safe to name

An `AISF-` row restates the incumbent's `Passed` under the control id, so only a
covered control may reach `AISF_DERIVED_MAP`. A tag restates nothing, so it may
name a partly asserted control as long as it says so. Three forms:

| Tag | Means |
| ----- | ------- |
| `AISF AIR-BDR-KB-03` | this check alone asserts the whole control |
| `AISF AIR-SGM-TRN-05 (1 of 3 checks)` | the control is covered, but jointly, so no single leg asserts it |
| `AISF <control> (partial)` | the check asserts less than the control requires, and the tightening is outstanding |

A check that contributes to several controls carries them pipe-joined, with the
`AISF ` prefix repeated on each element so a consumer that splits on `|` gets a
complete token. One value may mix forms, because a check that asserts one
control in full often asserts only part of another, so read each element on its
own and never the value as a whole.

### One map module per producer

The map files are named per producer (`aisf_compliance_bedrock.py` and so on)
for a measured reason. All six producers name their files `schema.py` and
`app.py`, and `app.py` reaches its schema with `from schema import
create_finding`, resolved through `sys.modules` under that bare name. With four
files all called `aisf_compliance.py`, loading two producers into one
interpreter gave the second one the first one's map, and
`aisf_frameworks("BR-10")` returned `""` inside the bedrock module. The symptom
is an empty tag and no `ImportError`, so nothing raises.
`test_two_producers_in_one_interpreter_keep_their_own_maps` holds this.

### Scope, and what it does not cover

- **CSV and the schema contract only.** The column reaches all four producer
  CSVs. `generate_table_rows` renders 6 columns and never reads the field, so
  the HTML report does not show it; a 7th column would touch the OWASP and
  FinServ sections plus the `colspan="6"` assertions.
- **4 producer modules, not 5.** `owasp_assessments` is excluded because no
  `OW-` check is an incumbent for any AISF control, so the field would ship
  unpopulated on every OWASP row.
- **`responsible_ai_grc_assessments` is untouched.** It already declared the
  field and populates it from its own `COMPLIANCE_MAP`, none of whose tokens
  is AISF. Its frozen inventory baseline, whose tuples carry the
  compliance string as their 5th element, is unchanged.
- **The lookup cannot be bypassed.** Every finding in the four producers is
  built by `create_finding`, and
  `test_no_producer_builds_a_finding_outside_create_finding` fails if any is
  assembled as a literal dict. Such a row would ship an empty tag silently,
  because `csv.DictWriter` raises on a key the fieldnames lack and never on a
  key a row is missing. That same `extrasaction="raise"` default couples the
  schema field to the fieldnames list, so landing one without the other raises
  `ValueError` on the first row. `agentcore_assessments` builds its header
  twice, once for the no-findings case, and both lists are asserted.

## Prowler AISF requirements

Prowler publishes its own AWS AI Security Framework compliance mapping, whose
requirement ids (`AISF-AI-06`, `AISF-IAM-07` and so on) are Prowler's and are
not AISF catalogue control ids. Two checks answer Prowler requirements that no
check here asserted:

| Prowler requirement | Check | What it reproduces |
| --------------------- | ------- | -------------------- |
| AISF-AI-06 Bedrock API Audit Trail | `BR-56` Bedrock LLM Jacking Activity | `cloudtrail_threat_detection_llm_jacking`, with the departures listed in [SECURITY_CHECKS.md](SECURITY_CHECKS.md#br-56-bedrock-llm-jacking-activity) |
| AISF-IAM-07 Cognito User Authentication for AI Apps | `AC-52` Cognito User Pool Authentication | the user pool and app client checks, for the pools an AgentCore JWT authorizer names |

Neither check carries a `Compliance_Frameworks` tag. The tag names an AISF
catalogue control, and a Prowler requirement id is not one, so writing it into a
map would publish a control the catalogue does not have. Mapping either check to
a catalogue control it was not assessed against would publish a coverage claim
nothing backs. The cross-reference lives in this table and in the code comment
on each check instead.

These Prowler requirements are out of charter and have no check here. Each is
account hygiene that applies whether or not the account runs an AI workload,
Prowler already checks it, and this scanner's scope is the AI/ML resources in
the account:

- `AISF-IAM-04`, root account protection.
- `AISF-IAM-06`, the IAM password policy.
- `AISF-IAM-08`, API Gateway authorizers.
- `AISF-GOV-03`, the account security contact.
- `AISF-DATA-02`, IAM Access Analyzer enablement.

## Adding a control

1. Confirm the incumbent checks assert the whole control. A check that asserts
   less belongs in the tag column with a `(partial)` qualifier; close the gap in
   the incumbent check first.
2. Append an entry to `AISF_DERIVED_MAP` with the next free `AISF-` number,
   counting the ids in `RETIRED_AISF_IDS` as taken, the incumbent `Check_ID`s,
   and the control's `risk`, `rec`, and first `src` URL copied from the AISF
   control definition.
3. Update the `scope_text` figures on the AISF entry in `COMPLIANCE_STANDARDS`
   and the coverage bullet in this file.
   `test_scope_text_states_the_denominator_and_it_reconciles` fails if the
   scope text disagrees with `AISF_DERIVED_MAP`.
4. Add the row to the check catalogue above with its own per-control section.
5. Change the control's tags in the `aisf_compliance_<module>.py` map of each
   producer that emits an incumbent: a control that became covered is bare or
   `(1 of N checks)`, never `(partial)`.
6. Run the full test suite, ruff, cfn-lint and `sam validate --lint` as CI does.
