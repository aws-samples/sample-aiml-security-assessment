# Responsible AI GRC Check Severity Methodology

This document defines how every Responsible AI GRC (`FS-`) finding is assigned a severity, and
contains the per-finding [Severity Register](#severity-register). Severity follows a reproducible
**Likelihood × Impact** formula aligned with AWS and industry risk models, expressed in the AWS
Security Hub ASFF label set — not per-check intuition.

The enforced source of truth is the `SEVERITY_REGISTER` dictionary in
[`responsible_ai_grc_assessments/app.py`](../aiml-security-assessment/functions/security/responsible_ai_grc_assessments/app.py),
keyed by finding name. The [Severity Register](#severity-register) below mirrors it and adds the
disposition, Impact, Likelihood, and notes for each finding. When the two disagree, the code wins
and this document must be corrected.

> **Scope:** this methodology applies to the Responsible AI GRC checks. The Bedrock, SageMaker AI,
> AgentCore, and AWS Agent Registry checks assign severities per check without a documented
> scoring model; the methodology is written so it can be adopted tool-wide later.

## Contents

1. [Research basis](#1-research-basis)
2. [The severity scale (ASFF-aligned)](#2-the-severity-scale-asff-aligned)
3. [The scoring model (Likelihood × Impact → label)](#3-the-scoring-model-likelihood--impact--label)
   - [3.1 Impact](#31-impact-i--harm-if-the-control-is-absent-and-the-risk-materializes)
   - [3.2 Likelihood](#32-likelihood-l--probability-the-adverse-outcome-occurs-given-the-control-is-absent)
   - [3.3 Lookup matrix](#33-lookup-matrix-33--asff-label)
   - [3.4 Outcome disposition rules](#34-outcome-disposition-rules)
   - [3.5 Control-family bands](#35-control-family-bands)
4. [Worked examples](#4-worked-examples)
5. [Enforcement and drift prevention](#5-enforcement-and-drift-prevention)
6. [Why `Critical` is not used](#6-why-critical-is-not-used)
7. [Effect on the report](#7-effect-on-the-report)
8. [Severity Register](#severity-register)
   - [How to read the register](#how-to-read-the-register)
   - [Notes on specific dispositions](#notes-on-specific-dispositions): [Not-applicable rows](#not-applicable-rows), [Could-not-assess rows](#could-not-assess-rows), [CLASSIC-tier guardrails](#classic-tier-guardrails)
   - [FS-00 — not a control](#fs-00--not-a-control)
   - [Category 1 — Unbounded Consumption (FS-01 to FS-06)](#category-1--unbounded-consumption-fs-01-to-fs-06)
   - [Category 2 — Excessive Agency (FS-07 to FS-11)](#category-2--excessive-agency-fs-07-to-fs-11)
   - [Category 3 — Supply Chain Vulnerabilities (FS-12 to FS-16)](#category-3--supply-chain-vulnerabilities-fs-12-to-fs-16)
   - [Category 4 — Training Data and Model Poisoning (FS-17 to FS-21)](#category-4--training-data-and-model-poisoning-fs-17-to-fs-21)
   - [Category 5 — Vector and Embedding Weaknesses (FS-22 to FS-26)](#category-5--vector-and-embedding-weaknesses-fs-22-to-fs-26)
   - [Category 6 — Non-Compliant Output (FS-27 to FS-30)](#category-6--non-compliant-output-fs-27-to-fs-30)
   - [Category 7 — Misinformation (FS-31 to FS-34)](#category-7--misinformation-fs-31-to-fs-34)
   - [Category 8 — Abusive or Harmful Output (FS-35 to FS-38)](#category-8--abusive-or-harmful-output-fs-35-to-fs-38)
   - [Category 9 — Biased Output (FS-39 to FS-42)](#category-9--biased-output-fs-39-to-fs-42)
   - [Category 10 — Sensitive Information Disclosure (FS-43 to FS-46)](#category-10--sensitive-information-disclosure-fs-43-to-fs-46)
   - [Category 11 — Hallucination (FS-47 to FS-50)](#category-11--hallucination-fs-47-to-fs-50)
   - [Category 12 — Prompt Injection (FS-51 to FS-54)](#category-12--prompt-injection-fs-51-to-fs-54)
   - [Category 13 — Improper Output Handling (FS-55 to FS-58)](#category-13--improper-output-handling-fs-55-to-fs-58)
   - [Category 14 — Off-Topic and Inappropriate Output (FS-59 to FS-60)](#category-14--off-topic-and-inappropriate-output-fs-59-to-fs-60)
   - [Category 15 — Out-of-Date Training Data (FS-61 to FS-63)](#category-15--out-of-date-training-data-fs-61-to-fs-63)
   - [Material gap checks (FS-65 to FS-69)](#material-gap-checks-fs-65-to-fs-69)
   - [Cross-cutting synthesized rows](#cross-cutting-synthesized-rows)

---

<a id="1-research-basis-authoritative-sources-reviewed"></a>

## 1. Research basis

<details>
<summary>Authoritative sources reviewed and why each was or was not adopted</summary>

| Standard | What it contributes | Why we did / didn't adopt it wholesale |
| --- | --- | --- |
| **AWS Security Hub ASFF Severity** ([API_Severity](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_Severity.html)) | The AWS-native label set (`INFORMATIONAL/LOW/MEDIUM/HIGH/CRITICAL`) with precise semantics and normalized 0–100 ranges. | **Adopted as the target label vocabulary** so findings align with Security Hub, the service customers use to aggregate posture findings. |
| **AWS exposure-finding severity factors** ([doc](https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-findings-severity.html)) | AWS's own model: *Awareness, Ease of discovery, Ease of exploit, Likelihood of exploit, Impact* — i.e. **Likelihood × Impact**. | **Adopted the Likelihood × Impact shape**; AWS itself uses it, so it is the most defensible AWS-aligned model. |
| **NIST SP 800-30 r1** ([CSRC](https://csrc.nist.gov/pubs/sp/800/30/final)) | Risk = Likelihood × Impact, a 5×5 qualitative matrix with a published lookup table. | **Adopted the matrix-lookup approach** (foundational US-government risk standard; financial-services regulators expect NIST-lineage rigor). Simplified to 3×3 for explainability. |
| **OWASP Risk Rating Methodology** ([OWASP](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)) | Likelihood (threat-agent + vulnerability) × Impact (technical + business), averaged and banded LOW/MEDIUM/HIGH. | **Adopted the factor-decomposition idea** (score sub-factors, then combine) and the business-impact dimension. |
| **CVSS v3.1** ([FIRST](https://www.first.org/cvss/)) qualitative bands (0 None / 0.1–3.9 Low / 4.0–6.9 Medium / 7.0–8.9 High / 9.0–10.0 Critical) | Standard numeric→qualitative banding. | **Referenced** for band shape; **not adopted wholesale** — CVSS scores *software vulnerabilities (CVEs)*, not *missing-control posture findings*. Using CVSS metrics (Attack Vector, etc.) on a "no WAF configured" finding is a category error. |
| **CISA SSVC** (Stakeholder-Specific Vulnerability Categorization) | Decision-tree (Exploitation/Automatable/Technical Impact/Mission) → Track/Attend/Act. | **Referenced**, not adopted — also CVE/vulnerability-centric and produces action labels, not the severity labels the report and Security Hub expect. |

</details>

**Conclusion:** A control-gap posture tool should score **Likelihood × Impact** (per AWS's own
exposure model and NIST 800-30) and express the result in the **ASFF label set**. CVSS and SSVC are
for CVEs and are out of scope as the scoring engine, though the report remains compatible with
Security Hub's ASFF labels for customers who ingest it.

---

## 2. The severity scale (ASFF-aligned)

The labels follow AWS's ASFF semantics. The tool's `SeverityEnum` is
`High | Medium | Low | Informational` (no `Critical`) and is shared with the other services.

| Label | ASFF meaning | ASFF normalized | Used by Responsible AI GRC for |
| --- | --- | --- | --- |
| **Informational** | No issue / not action-bearing on its own | 0 | Advisory checks (no API can verify them) and `N/A` rows where there is nothing to assess |
| **Low** | Does not require action on its own | 1–39 | Residual-risk / observability controls, controls with strong compensating alternatives, and could-not-assess rows (§3.4) |
| **Medium** | Must be addressed, not urgently | 40–69 | Controls whose absence materially increases risk but is not itself a breach |
| **High** | Must be addressed as a priority | 70–89 | Controls whose absence can directly cause regulatory breach, data exposure, large loss, or full guardrail bypass |
| **Critical** | Remediate immediately | 90–100 | **Not used** (see [§6](#6-why-critical-is-not-used)). Reserved. |

---

## 3. The scoring model (Likelihood × Impact → label)

Each **risk a control mitigates** is scored on two axes, each Low (1), Medium (2), or High (3).
Severity is the inherent risk the control addresses, so the **same severity applies to that
check's Passed and Failed rows** (and to risk-bearing N/A rows); a Passed finding keeps the
control's documented severity.

### 3.1 Impact (I) — harm if the control is absent and the risk materializes

| Score | Criteria (any one qualifies) |
| --- | --- |
| **3 — High** | Direct regulatory breach (e.g., fair-lending/ECOA, disclosure rules); sensitive-data/PII exposure; large-scale financial loss; full bypass of safety guardrails; unsafe automated financial action. |
| **2 — Medium** | Materially weakens oversight, model-risk governance, or assurance; increases blast radius of another failure; degraded auditability of a regulated decision — but not a breach by itself. |
| **1 — Low** | Reduces residual risk, supports observability/audit, or is fully covered by a compensating control; cost-optimization or defense-in-depth value. |

### 3.2 Likelihood (L) — probability the adverse outcome occurs given the control is absent

Blends AWS's *awareness / ease of discovery / ease of exploit* with the presence of compensating
controls. Applies to both attack-driven risks (prompt injection, cost exhaustion) and
governance-driven risks (an unreviewed model reaches production).

| Score | Criteria |
| --- | --- |
| **3 — High** | Internet-reachable or default-on surface; common, automatable attack pattern; or near-certain to occur in normal operation; no compensating control. |
| **2 — Medium** | Reachable under common conditions; partial or adjacent compensating control exists; periodic rather than continuous exposure. |
| **1 — Low** | Requires unusual conditions or insider access; strong compensating controls substantially reduce exposure; rare in practice. |

### 3.3 Lookup matrix (3×3 → ASFF label)

| Impact / Likelihood | **L = Low (1)** | **L = Medium (2)** | **L = High (3)** |
| --- | --- | --- | --- |
| **I = High (3)** | Medium | High | High *(Critical-eligible — see §6)* |
| **I = Medium (2)** | Low | Medium | High |
| **I = Low (1)** | Low | Low | Medium |

Equivalent rule: `score = I × L`; `1–2 → Low`, `3–4 → Medium`, `6–9 → High` (with the
`I=3,L=3 → 9` cell Critical-eligible). Advisory and `N/A` outcomes are not risk-scored; the
disposition rules in §3.4 set their severity. The matrix is implemented as `_SEVERITY_MATRIX` in
`app.py`.

<a id="34-outcome-disposition-rules-critical--resolves-the-na-inconsistency"></a>

### 3.4 Outcome disposition rules

**Severity is a property of the control (the risk), not the outcome.** A control is scored once
(§3.1–3.3) and that severity is applied to **every** Passed and Failed row of that control. Each
`N/A` row maps to exactly one **disposition**, and the disposition fixes its severity
(`_DISPOSITION_SEVERITY` in `app.py`):

| Disposition | When it applies | Severity | ASFF rationale |
| --- | --- | --- | --- |
| **FAIL** | control assessed, not satisfied | control severity (§3.3) | the asserted issue |
| **PASS** | control assessed, satisfied | control severity (§3.3) | a pass keeps the control's documented severity |
| **NOT_APPLICABLE** | the control's resource type is absent (no KBs, no guardrails, no WAF, no REST APIs, not in an Org) | **Informational** | ASFF: *"INFORMATIONAL — No issue was found."* The "you should create guardrails/eval jobs" signal belongs to that resource's **own** existence check, not to every sub-check (avoids double-counting). |
| **ADVISORY** | no AWS API can verify the control (app-layer) | **Informational** | finding name carries the `ADVISORY: ` prefix |
| **COULD_NOT_ASSESS** | the check could not run (access denied, unsupported region, SDK gap) | **Low** | not a confirmed issue (unknown state); the `COULD NOT ASSESS: ` or access-check finding name keeps it visible and prompts a re-run |
| **SOFT_WARNING** | control assessed; a legitimate-but-suboptimal non-failing state (the only instance is **FS-03 quotas at default**) | control severity | documented exception |

Every NOT_APPLICABLE row is therefore Informational, every ADVISORY row is Informational, and every
COULD_NOT_ASSESS row is Low. One emitted row departs from this rule: when no agent-related Lambda
function matches, FS-09 emits `Agent Lambda Concurrency Limits Present` with `Status=N/A` at its
registered Medium severity rather than a separate Informational row.

A few checks use their status deliberately so it neither understates nor overstates risk:
FS-15 "no evaluation jobs" is `Failed`, because the existence of model-evaluation jobs is
programmatically checkable; FS-30, FS-35, and FS-40 are advisory, because no API exposes evaluation
dataset content; and FS-56 fails when Web ACLs exist without the XSS rules. CLASSIC-tier guardrails
for FS-28, FS-36, FS-51, and FS-59 remain `Passed` — see
[CLASSIC-tier guardrails](#classic-tier-guardrails).

<a id="35-control-family-bands-ensures-cross-check-consistency"></a>

### 3.5 Control-family bands

To ensure similar controls get the same severity, every FS control is assigned to a family with
a default band. Per-control I×L may refine within ±1 with a documented reason.

| Family | Risk on absence | Default | Example checks |
| --- | --- | --- | --- |
| **Safety-guardrail / content safety** | harmful output, guardrail bypass, PII leak | **High** | FS-36 content, FS-45 PII, FS-47 grounding threshold, FS-51 prompt-attack, FS-53 injection, FS-27 contextual grounding; FS-56 XSS is refined to **Medium** because request-side WAF rules cannot inspect model output (output encoding, FS-57, is the root control) |
| **Sensitive-data exposure / integrity** | PII exposure or training-data, image, or knowledge-base tampering | **High** | FS-16 image scanning, FS-21 training-data versioning, FS-25 KB encryption, FS-33/FS-65 deleted data-source bucket, FS-43 log data-protection, FS-44 Macie |
| **Excessive agency / access control / isolation** | unauthorized action, over-broad permissions, regulated-decision breach | **High** | FS-07, FS-08, FS-10, FS-12, FS-22, FS-26, FS-39 bias, FS-41 explainability, FS-66, FS-67 |
| **Regulated-output controls** | non-compliant / off-regulatory output | **High** (denied topics) / **Medium** (softer: word filters, topic allowlist, relevance) | FS-28 (High), FS-38/FS-59/FS-50 (Medium) |
| **Unbounded consumption / cost / rate-limiting** | cost exhaustion, DoS — compensating controls exist, no breach | **Medium** | FS-01 WAF, FS-02, FS-03, FS-05, FS-06, FS-09, FS-11, FS-68 |
| **Governance / model-risk / monitoring / currency** | weakened oversight/assurance, not a breach | **Medium** | FS-04, FS-13, FS-14, FS-15, FS-20, FS-31, FS-33 versioning, FS-34, FS-42, FS-46, FS-48, FS-52, FS-55, FS-61, FS-63, FS-65 notifications, FS-69 |
| **Premium-cost defense-in-depth** | residual DDoS risk; Shield Standard + WAF compensate; ~$3k/mo | **Low** | FS-01 Shield Advanced |
| **Emerging/advanced control** | formal-verification gap; contextual grounding partly compensates | **Medium** | FS-27 Automated Reasoning |
| **Non-verifiable advisory** | app-layer; no API | **Informational** | FS-24, FS-29, FS-30, FS-32, FS-35, FS-37, FS-40, FS-49, FS-54, FS-57, FS-58, FS-60, FS-62 |

The per-finding assignments are in the [Severity Register](#severity-register).

---

<a id="4-worked-examples-including-the-reviewers-case"></a>

## 4. Worked examples

| Check | Control | I | L | Rationale | Result |
| --- | --- | --- | --- | --- | --- |
| **FS-01 (Shield Advanced)** | Shield Advanced subscription | **1** | **2** | Impact Low: Shield *Standard* is always-on and free; WAF rate-limiting (FS-01 WAF / FS-02 usage plans) is a compensating control; absence is a premium-cost decision (~$3,000/mo), not a breach. Likelihood Medium: endpoints are discoverable but volumetric DDoS on a Bedrock-fronting endpoint is not the common case. | **Low** |
| **FS-01 (Regional WAF)** | WAF Web ACL present | **2** | **2** | Impact Medium: no WAF → exposed to abusive callers / cost exhaustion, but API Gateway usage-plan throttling (FS-02) is a compensating control and there is no direct breach. Likelihood Medium: common but mitigated by throttling. | **Medium** |
| **FS-43 (PII in logs)** | Sensitive-data masking | **3** | **2** | Impact High: PII exposure = regulatory breach. Likelihood Medium: requires a logging misconfiguration. | **High** |
| **FS-58 (output schema validation)** | App-layer validation | — | — | No AWS API can verify it → advisory. | **Informational** (advisory) |
| **FS-27 (Automated Reasoning policies)** | Automated Reasoning policy present | **2** | **2** | Impact Medium: Automated Reasoning adds formal verification of factual claims; its absence leaves grounding-only assurance. Likelihood Medium: contextual grounding (the other FS-27 control) only partly compensates. | **Medium** |

---

<a id="5-application-governance-and-drift-prevention"></a>

## 5. Enforcement and drift prevention

1. **Per-finding severity register.** `SEVERITY_REGISTER` in `app.py` maps every static `FS-`
   finding name to its label. It is keyed by finding name, so FS-01 can carry Shield (Low) and WAF
   (Medium) findings under one `Check_ID`.
2. **Code matches register.** `responsible_ai_grc_tests/test_severity_register.py` asserts that the
   matrix and disposition rules match §3.3–§3.4, that the register uses only the four allowed
   labels (no `Critical`), that the synthesized could-not-assess row is Low / `N/A`, that advisory
   rows are Informational / `N/A`, that the FS-00 row matches the register, and that every row the
   checks emit with AWS calls failing has its registered severity. That last test exercises the
   error and advisory paths, not every success path, so changes to finding names or severities
   must update `SEVERITY_REGISTER` and this document together.
3. **Docs match register.** The per-check severity fields in
   [`SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md`](./SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md) and the
   register tables below must agree with `SEVERITY_REGISTER`.
4. **Methodology surfaced to users.** `README.md` summarizes §2–§3, and the Responsible AI GRC
   report section states that severities follow a documented Likelihood × Impact methodology.
5. **ASFF mapping documented.** The label↔ASFF-normalized mapping in §2 lets customers who forward
   findings to Security Hub assign correct severities.

---

<a id="6-decision-confirmed-2026-06-10-keep-four-levels-do-not-introduce-critical-yet"></a>

## 6. Why `Critical` is not used

The matrix has a Critical-eligible cell (I = High, L = High). It is capped at **High**, so the
label set stays `{High, Medium, Low, Informational}`:

- It stays consistent with the Bedrock, SageMaker AI, AgentCore, and AWS Agent Registry checks,
  which have no `Critical`.
- Adopting `Critical` would be a tool-wide change: adding it to `SeverityEnum` in every service,
  updating the report's severity filters and colors, and re-scoring the I=3, L=3 controls.

Because §2 already documents the `Critical` band, adopting it later is a labeling change, not a
methodology change. Until then the drift-guard test asserts that no `Critical` label is used.

---

<a id="7-how-this-changes-the-report-expected-document-for-reviewers"></a>

## 7. Effect on the report

Responsible AI GRC findings are shown in their own governance area. They do not enter the report's
overall or per-severity pass rates, which are computed from the direct service checks only, and
Informational and `N/A` rows are never scored. Severity determines each finding's badge and the
severity filter it appears under.

---

## Severity Register

The register applies this methodology (Likelihood × Impact → ASFF label; §3.4 disposition rules;
§3.5 family bands) to every static finding name that `responsible_ai_grc_assessments/app.py`
emits. It has one row per (check ID, finding name) pair; a few names, such as
`No Knowledge Bases Found`, are shared by several check IDs and so appear once per check. Finding
names built at runtime are covered by the
[cross-cutting synthesized rows](#cross-cutting-synthesized-rows).

### How to read the register

- **Disposition:** FAIL / PASS / NA-NotApplicable / NA-CouldNotAssess / NA-Advisory / NA-SoftWarning
  (§3.4).
- **I, L:** Impact and Likelihood (1–3) for the *control*. A dash means the severity comes from the
  disposition rule, not I×L.
- **Severity:** the register-assigned severity, equal to the `SEVERITY_REGISTER` value.
- One severity applies per control across its PASS and FAIL rows.

### Notes on specific dispositions

#### Not-applicable rows

"Nothing to assess" rows are Informational (ASFF "no issue found"). The signal that a resource
should exist stays with that resource's own check — for example, FS-15 for evaluation jobs.

#### Could-not-assess rows

Inline access checks and the shared `_could_not_assess_row()` helper both emit Low, so an unknown
state is reported consistently.

#### CLASSIC-tier guardrails

CLASSIC-tier guardrails (FS-28, FS-36, FS-51, FS-59) are **Passed** at the control's severity.
CLASSIC provides real protection (English, French, and Spanish) and is not deprecated; STANDARD adds
broader language support and stronger prompt-attack classification. A hard FAIL would falsely fail
adequate English-only deployments, so the STANDARD-upgrade recommendation lives in the finding
details, and severity reflects the control's inherent risk rather than the tier.

### FS-00 — not a control

Emitted by `_no_regional_genai_resources_row` and persisted to the CSV, so it needs a severity, but
FS-00 is deliberately absent from the check registry and from the compliance mapping (see the
[FS-00 section](./SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md#fs-00--regional-scope-not-applicable-not-a-control)
of the checks reference). There is no I×L: the severity comes from the NOT_APPLICABLE disposition
rule (§3.4).

| Check | Finding name | Disposition | I | L | Severity | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| FS-00 | Responsible AI GRC — Regional Scope Not Applicable | NA-NotApplicable | – | – | **Informational** | Registered so severity drift on this row is detectable |

### Category 1 — Unbounded Consumption (FS-01 to FS-06)

<details>
<summary>18 findings</summary>

| Check | Finding name | Disposition | I | L | Severity | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| FS-01 | AWS Shield Advanced Not Enabled | FAIL | 1 | 2 | **Low** |  |
| FS-01 | AWS Shield Advanced Enabled | PASS | 1 | 2 | **Low** |  |
| FS-01 | No Regional WAF Web ACLs Found | FAIL | 2 | 2 | **Medium** |  |
| FS-01 | Regional WAF Web ACLs Present | PASS | 2 | 2 | **Medium** |  |
| FS-02 | No API Gateway Usage Plans Found | NA-NotApplicable | – | – | **Informational** |  |
| FS-02 | API Gateway Usage Plans Missing Throttle | FAIL | 2 | 2 | **Medium** |  |
| FS-02 | API Gateway Rate Limiting Configured | PASS | 2 | 2 | **Medium** |  |
| FS-03 | No Bedrock Token Quotas Returned | FAIL | 2 | 2 | **Medium** |  |
| FS-03 | Bedrock Default Quotas Unavailable — Customization Undetermined | FAIL | 2 | 2 | **Medium** |  |
| FS-03 | Bedrock Token Quotas Customized | PASS | 2 | 2 | **Medium** |  |
| FS-03 | Bedrock Token Quotas At Default | NA-SoftWarning | 2 | 2 | **Medium** | Documented SOFT_WARNING exception (§3.4) |
| FS-04 | No Cost Anomaly Detection Monitors | FAIL | 2 | 2 | **Medium** |  |
| FS-04 | Cost Anomaly Monitors Do Not Cover Bedrock/SageMaker | FAIL | 2 | 2 | **Medium** |  |
| FS-04 | Cost Anomaly Detection Configured | PASS | 2 | 2 | **Medium** |  |
| FS-05 | No Bedrock CloudWatch Alarms Found | FAIL | 2 | 2 | **Medium** |  |
| FS-05 | Bedrock CloudWatch Alarms Present | PASS | 2 | 2 | **Medium** |  |
| FS-06 | No AI/ML Service Budgets Configured | FAIL | 2 | 2 | **Medium** |  |
| FS-06 | AI/ML Service Budgets Configured | PASS | 2 | 2 | **Medium** |  |

</details>

### Category 2 — Excessive Agency (FS-07 to FS-11)

<details>
<summary>15 findings</summary>

| Check | Finding name | Disposition | I | L | Severity | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| FS-07 | Agent Action Boundary Check | NA-NotApplicable | – | – | **Informational** |  |
| FS-07 | Bedrock Agent Overly Broad Action Permissions | FAIL | 3 | 2 | **High** |  |
| FS-07 | Agent Action Boundaries Look Appropriate | PASS | 3 | 2 | **High** |  |
| FS-08 | AgentCore Runtime Inbound Authorizer — Access Check | NA-CouldNotAssess | – | – | **Low** |  |
| FS-08 | No AgentCore Runtimes Found | NA-NotApplicable | – | – | **Informational** |  |
| FS-08 | AgentCore Runtimes Without Inbound Authorizer | FAIL | 3 | 2 | **High** |  |
| FS-08 | AgentCore Runtimes With Inbound Authorizer Configured | PASS | 3 | 2 | **High** |  |
| FS-08 | COULD NOT ASSESS: AgentCore Runtime Inbound Authorizer Check | NA-CouldNotAssess | – | – | **Low** |  |
| FS-09 | Agent Lambda Functions Without Concurrency Limits | FAIL | 2 | 2 | **Medium** |  |
| FS-09 | Agent Lambda Concurrency Limits Present | PASS (computed) | 2 | 2 | **Medium** | `Passed` when agent-related functions all have reserved concurrency; `N/A` (still Medium) when no function matches |
| FS-10 | Human-in-the-Loop Check — No Agent Workflows Found | NA-NotApplicable | – | – | **Informational** |  |
| FS-10 | Human Approval Steps Found in Agent Workflows | PASS | 3 | 2 | **High** |  |
| FS-10 | Agent Workflows Missing Human Approval Steps | FAIL | 3 | 2 | **High** |  |
| FS-11 | No Agent Rate Alarms Found | FAIL | 2 | 2 | **Medium** |  |
| FS-11 | Agent Rate Alarms Present | PASS | 2 | 2 | **Medium** |  |

</details>

### Category 3 — Supply Chain Vulnerabilities (FS-12 to FS-16)

<details>
<summary>14 findings</summary>

| Check | Finding name | Disposition | I | L | Severity | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| FS-12 | SCP Model Access Check — Not in Organization | NA-NotApplicable | – | – | **Informational** |  |
| FS-12 | No Bedrock-Scoped SCPs Found | FAIL | 3 | 2 | **High** |  |
| FS-12 | Bedrock SCPs Found | PASS | 3 | 2 | **High** |  |
| FS-13 | Models Missing Provenance Tags | FAIL | 2 | 2 | **Medium** |  |
| FS-13 | Model Provenance Tags Present | PASS | 2 | 2 | **Medium** | Also emitted when the account owns no custom Bedrock or SageMaker models |
| FS-14 | No Model Governance Config Rules Found | FAIL | 2 | 2 | **Medium** |  |
| FS-14 | Model Governance Config Rules Present | PASS | 2 | 2 | **Medium** |  |
| FS-15 | No Bedrock Evaluation Jobs Found | FAIL | 2 | 2 | **Medium** |  |
| FS-15 | Bedrock Evaluation Jobs Present | PASS | 2 | 2 | **Medium** |  |
| FS-16 | No ECR Repositories Found | NA-NotApplicable | – | – | **Informational** |  |
| FS-16 | ECR Repositories Without Image Scanning | FAIL | 3 | 2 | **High** |  |
| FS-16 | ECR Image Scanning Enabled | PASS | 3 | 2 | **High** |  |
| FS-16 | ECR Image Scanning Covered by Inspector Enhanced Scanning | PASS | 3 | 2 | **High** | Inspector enhanced ECR scanning is an equivalent control, so `scanOnPush=false` alone is not a FAIL |
| FS-16 | COULD NOT ASSESS: ECR Image Scanning Check | NA-CouldNotAssess | – | – | **Low** | Inspector status unreadable (`inspector2:BatchGetAccountStatus` error, or the account in `failedAccounts` or absent) while repositories without scan-on-push exist; unknown Inspector coverage does not default to FAIL |

</details>

### Category 4 — Training Data and Model Poisoning (FS-17 to FS-21)

<details>
<summary>7 findings</summary>

| Check | Finding name | Disposition | I | L | Severity | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| FS-20 | No SageMaker Feature Groups Found | NA-NotApplicable | – | – | **Informational** |  |
| FS-20 | Feature Groups Without Offline Store | FAIL | 2 | 2 | **Medium** |  |
| FS-20 | Feature Groups With Offline Store Configured | PASS | 2 | 2 | **Medium** | Keyed off `OfflineStoreConfig` from `DescribeFeatureGroup`; `OfflineStoreStatus` is not populated on the list or describe response |
| FS-20 | COULD NOT ASSESS: Feature Store Rollback Check | NA-CouldNotAssess | – | – | **Low** | `sagemaker:DescribeFeatureGroup` denied |
| FS-21 | No Training Data Buckets Identified | NA-NotApplicable | – | – | **Informational** |  |
| FS-21 | Training Data Buckets Without Versioning | FAIL | 3 | 2 | **High** | Data-integrity/poisoning recovery |
| FS-21 | Training Data Buckets Have Versioning | PASS | 3 | 2 | **High** |  |

</details>

### Category 5 — Vector and Embedding Weaknesses (FS-22 to FS-26)

<details>
<summary>11 findings</summary>

| Check | Finding name | Disposition | I | L | Severity | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| FS-22 | Overly Permissive Knowledge Base IAM Roles | FAIL | 3 | 2 | **High** |  |
| FS-22 | Knowledge Base IAM Permissions Look Appropriate | PASS | 3 | 2 | **High** |  |
| FS-24 | No Knowledge Bases Found | NA-NotApplicable | – | – | **Informational** |  |
| FS-24 | ADVISORY: Knowledge Base Metadata Filtering — Manual Review Required | NA-Advisory | – | – | **Informational** |  |
| FS-25 | No OpenSearch Serverless Collections Found | NA-NotApplicable | – | – | **Informational** | Keyed off `ListCollections`, not encryption policies (orphaned policies protect no data) |
| FS-25 | OpenSearch Serverless Collections Using AWS-Owned Encryption Keys | FAIL | 3 | 2 | **High** |  |
| FS-25 | OpenSearch Serverless Collections Using Customer-Managed Keys | PASS | 3 | 2 | **High** | Keyed off each collection's `kmsKeyArn`; `ListSecurityPolicies` summaries carry no `policy` member |
| FS-25 | COULD NOT ASSESS: OpenSearch Serverless Encryption Check | NA-CouldNotAssess | – | – | **Low** | `aoss:ListCollections` denied, or a collection returned no `kmsKeyArn` |
| FS-26 | No OpenSearch Serverless Network Policies | FAIL | 3 | 2 | **High** | Also emitted when no collections exist |
| FS-26 | OpenSearch Serverless Collections Not VPC-Restricted | FAIL | 3 | 2 | **High** | Currently emitted whenever network policies exist; see the FS-26 Detection limitation |
| FS-26 | OpenSearch Serverless VPC Access Configured | PASS | 3 | 2 | **High** | Not currently reachable; see the FS-26 Detection limitation |

</details>

### Category 6 — Non-Compliant Output (FS-27 to FS-30)

<details>
<summary>12 findings</summary>

| Check | Finding name | Disposition | I | L | Severity | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| FS-27 | No Guardrails — Contextual Grounding Not Applicable | NA-NotApplicable | – | – | **Informational** |  |
| FS-27 | No Guardrails With Contextual Grounding | FAIL | 3 | 2 | **High** |  |
| FS-27 | Contextual Grounding Enabled on Guardrails | PASS | 3 | 2 | **High** |  |
| FS-27 | Automated Reasoning Policies — Access Check | NA-CouldNotAssess | – | – | **Low** |  |
| FS-27 | No Automated Reasoning Policies Found | FAIL | 2 | 2 | **Medium** |  |
| FS-27 | Automated Reasoning Policies Found | PASS | 2 | 2 | **Medium** |  |
| FS-28 | No Guardrails — Topic Policy Not Applicable | NA-NotApplicable | – | – | **Informational** |  |
| FS-28 | No Guardrails With Topic Policies | FAIL | 3 | 2 | **High** | Confirms a topic policy exists, not that the denied topics are financial |
| FS-28 | Topic Policies Configured on CLASSIC Tier | PASS | 3 | 2 | **High** | See [CLASSIC-tier guardrails](#classic-tier-guardrails) |
| FS-28 | Guardrails With Topic Policies Found | PASS | 3 | 2 | **High** |  |
| FS-29 | ADVISORY: Compliance Disclaimer — Manual Review Required | NA-Advisory | – | – | **Informational** |  |
| FS-30 | ADVISORY: Compliance Dataset Coverage — Manual Review Required | NA-Advisory | – | – | **Informational** | Dataset content cannot be inspected through any API |

</details>

### Category 7 — Misinformation (FS-31 to FS-34)

<details>
<summary>13 findings</summary>

| Check | Finding name | Disposition | I | L | Severity | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| FS-31 | No Knowledge Bases Found | NA-NotApplicable | – | – | **Informational** |  |
| FS-31 | Knowledge Base Data Sources Past Review Threshold | FAIL | 2 | 2 | **Medium** |  |
| FS-31 | No Knowledge Base Data Sources Found | NA-NotApplicable | – | – | **Informational** | Knowledge Bases exist but none has a data source, so there is no ingestion to age |
| FS-31 | Knowledge Base Data Sources Never Successfully Synced | FAIL | 2 | 2 | **Medium** | No COMPLETE ingestion job exists, a distinct failure from a stale sync |
| FS-31 | Knowledge Base Data Sources Recently Synced | PASS | 2 | 2 | **Medium** |  |
| FS-31 | COULD NOT ASSESS: Knowledge Base Data Source Sync Check | NA-CouldNotAssess | – | – | **Low** | `bedrock:ListIngestionJobs` denied |
| FS-32 | ADVISORY: Source Attribution — Manual Review Required | NA-Advisory | – | – | **Informational** |  |
| FS-33 | No Knowledge Bases Found | NA-NotApplicable | – | – | **Informational** |  |
| FS-33 | KB Data Source References a Deleted S3 Bucket | FAIL | 3 | 2 | **High** | Distinct risk: dangling reference / integrity |
| FS-33 | KB Data Source Buckets Without Versioning | FAIL | 2 | 2 | **Medium** | Distinct risk |
| FS-33 | KB Data Source Buckets Have Versioning | PASS | 2 | 2 | **Medium** |  |
| FS-34 | Legacy Foundation Models Available in Region | NA-NotApplicable | – | – | **Informational** |  |
| FS-34 | Foundation Models Are Current | PASS | 2 | 2 | **Medium** |  |

</details>

### Category 8 — Abusive or Harmful Output (FS-35 to FS-38)

<details>
<summary>9 findings</summary>

| Check | Finding name | Disposition | I | L | Severity | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| FS-35 | ADVISORY: Harmful-Content Test Coverage — Manual Review Required | NA-Advisory | – | – | **Informational** | Dataset content cannot be inspected through any API |
| FS-36 | No Guardrails — Content Filters Not Applicable | NA-NotApplicable | – | – | **Informational** |  |
| FS-36 | No Guardrails With Content Filters | FAIL | 3 | 2 | **High** |  |
| FS-36 | Guardrail Content Filters on CLASSIC Tier | PASS | 3 | 2 | **High** | See [CLASSIC-tier guardrails](#classic-tier-guardrails) |
| FS-36 | Guardrails With Content Filters Found | PASS | 3 | 2 | **High** |  |
| FS-37 | ADVISORY: User Feedback Mechanism — Manual Review Required | NA-Advisory | – | – | **Informational** |  |
| FS-38 | No Guardrails — Word Filters Not Applicable | NA-NotApplicable | – | – | **Informational** |  |
| FS-38 | No Guardrails With Word Filters | FAIL | 2 | 2 | **Medium** |  |
| FS-38 | Guardrail Word Filters Configured | PASS | 2 | 2 | **Medium** |  |

</details>

### Category 9 — Biased Output (FS-39 to FS-42)

<details>
<summary>10 findings</summary>

| Check | Finding name | Disposition | I | L | Severity | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| FS-39 | No SageMaker Clarify Bias Monitoring | FAIL | 3 | 2 | **High** |  |
| FS-39 | SageMaker Clarify Bias Monitoring Schedules Not Running | FAIL | 3 | 2 | **High** | A bias schedule exists but is not in the Scheduled state, a distinct failure from having no schedule |
| FS-39 | SageMaker Clarify Bias Monitoring Schedules Found | PASS | 3 | 2 | **High** | Observes schedule existence; running state is reported by the row above |
| FS-40 | ADVISORY: Bias Dataset Coverage — Manual Review Required | NA-Advisory | – | – | **Informational** | Dataset content cannot be inspected through any API |
| FS-41 | No SageMaker Clarify Explainability Monitoring | FAIL | 3 | 2 | **High** |  |
| FS-41 | SageMaker Clarify Explainability Schedules Not Running | FAIL | 3 | 2 | **High** | An explainability schedule exists but is not in the Scheduled state |
| FS-41 | SageMaker Clarify Explainability Monitoring Schedules Found | PASS | 3 | 2 | **High** | Observes schedule existence; running state is reported by the row above |
| FS-42 | No SageMaker Model Cards Found | NA-NotApplicable | – | – | **Informational** | A Bedrock-only estate legitimately has no SageMaker model cards, so absence is not a finding |
| FS-42 | SageMaker Model Cards Not Approved | FAIL | 2 | 2 | **Medium** | Keyed off `ModelCardStatus` |
| FS-42 | SageMaker Model Cards Approved | PASS | 2 | 2 | **Medium** | Card presence alone is not the control |

</details>

### Category 10 — Sensitive Information Disclosure (FS-43 to FS-46)

<details>
<summary>16 findings</summary>

| Check | Finding name | Disposition | I | L | Severity | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| FS-43 | Bedrock Invocation Logging Not Enabled | NA-NotApplicable | – | – | **Informational** | There is no invocation log to mask |
| FS-43 | Bedrock Invocation Logs Not Delivered to CloudWatch Logs | NA-NotApplicable | – | – | **Informational** | S3-only delivery makes CloudWatch data-protection policies irrelevant to this control |
| FS-43 | No CloudWatch Logs Data Protection Policies | FAIL | 3 | 2 | **High** | Reached only when invocation logs are delivered to CloudWatch Logs |
| FS-43 | CloudWatch Logs Data Protection Policies Present | PASS | 3 | 2 | **High** |  |
| FS-43 | COULD NOT ASSESS: CloudWatch Log PII Masking Check | NA-CouldNotAssess | – | – | **Low** | `bedrock:GetModelInvocationLoggingConfiguration` failed, or no policy was found while `logs:DescribeAccountPolicies` or `logs:GetDataProtectionPolicy` failed |
| FS-44 | Amazon Macie Not Enabled | FAIL | 3 | 2 | **High** |  |
| FS-44 | Amazon Macie Enabled but Automated Discovery Disabled | FAIL | 3 | 2 | **High** | An ENABLED session with automated discovery DISABLED scans nothing |
| FS-44 | Amazon Macie Automated Discovery Enabled | PASS | 3 | 2 | **High** | An enabled Macie session alone is not sufficient |
| FS-44 | COULD NOT ASSESS: Macie Automated Discovery Status | NA-CouldNotAssess | – | – | **Low** | `macie2:GetAutomatedDiscoveryConfiguration` denied |
| FS-44 | COULD NOT ASSESS: Amazon Macie PII Scanning Check | NA-CouldNotAssess | – | – | **Low** | `macie2:GetMacieSession` denied for a reason other than Macie not being enabled |
| FS-45 | No Guardrails — PII Filters Not Applicable | NA-NotApplicable | – | – | **Informational** |  |
| FS-45 | No Guardrails With PII Filters | FAIL | 3 | 2 | **High** |  |
| FS-45 | Guardrail PII Filters Configured | PASS | 3 | 2 | **High** |  |
| FS-46 | No AI/ML Data Buckets Identified | NA-NotApplicable | – | – | **Informational** |  |
| FS-46 | AI/ML Buckets Without Data Classification Tags | FAIL | 2 | 2 | **Medium** |  |
| FS-46 | AI/ML Buckets Have Classification Tags | PASS | 2 | 2 | **Medium** |  |

</details>

### Category 11 — Hallucination (FS-47 to FS-50)

<details>
<summary>9 findings</summary>

| Check | Finding name | Disposition | I | L | Severity | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| FS-47 | No Guardrails — Grounding Threshold Not Applicable | NA-NotApplicable | – | – | **Informational** |  |
| FS-47 | Guardrails With Low Grounding Thresholds | FAIL | 3 | 2 | **High** |  |
| FS-47 | No Guardrails With a Grounding Filter | FAIL | 3 | 2 | **High** |  |
| FS-47 | Guardrail Grounding Thresholds Appropriate | PASS | 3 | 2 | **High** |  |
| FS-48 | No Active Knowledge Bases for RAG | FAIL | 2 | 2 | **Medium** | Also emitted when no Knowledge Bases exist |
| FS-48 | Active Knowledge Bases for RAG Present | PASS | 2 | 2 | **Medium** |  |
| FS-49 | ADVISORY: Hallucination Disclaimer — Manual Review Required | NA-Advisory | – | – | **Informational** |  |
| FS-50 | No Guardrails With Relevance Grounding Filters | FAIL | 2 | 2 | **Medium** | Also emitted when no guardrails exist; FS-50 has no NOT_APPLICABLE row |
| FS-50 | Relevance Grounding Filters Present | PASS | 2 | 2 | **Medium** |  |

</details>

### Category 12 — Prompt Injection (FS-51 to FS-54)

<details>
<summary>11 findings</summary>

| Check | Finding name | Disposition | I | L | Severity | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| FS-51 | No Guardrails — Prompt Attack Filters Not Applicable | NA-NotApplicable | – | – | **Informational** |  |
| FS-51 | No Guardrails With Prompt Attack Filters | FAIL | 3 | 2 | **High** |  |
| FS-51 | Prompt Attack Filters on CLASSIC Tier | PASS | 3 | 2 | **High** | See [CLASSIC-tier guardrails](#classic-tier-guardrails) |
| FS-51 | Guardrails With Prompt Attack Filters Found | PASS | 3 | 2 | **High** |  |
| FS-52 | No Bedrock-Related Lambda Functions Found | NA-NotApplicable | – | – | **Informational** |  |
| FS-52 | Bedrock Lambda Functions on Deprecated Runtimes | FAIL | 2 | 2 | **Medium** |  |
| FS-52 | Bedrock Lambda Functions on Current Runtimes | PASS | 2 | 2 | **Medium** |  |
| FS-53 | No WAF Web ACLs — Injection Rules Not Applicable | NA-NotApplicable | – | – | **Informational** |  |
| FS-53 | WAF ACLs Missing Injection Protection Rules | FAIL | 3 | 2 | **High** |  |
| FS-53 | WAF Injection Protection Rules Present | PASS | 3 | 2 | **High** |  |
| FS-54 | ADVISORY: Penetration Testing — Manual Review Required | NA-Advisory | – | – | **Informational** |  |

</details>

### Category 13 — Improper Output Handling (FS-55 to FS-58)

<details>
<summary>7 findings</summary>

| Check | Finding name | Disposition | I | L | Severity | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| FS-55 | No Output Validation Functions Found | FAIL | 2 | 2 | **Medium** |  |
| FS-55 | Output Validation Functions Present | PASS | 2 | 2 | **Medium** |  |
| FS-56 | No WAF ACLs — XSS Prevention Not Applicable | NA-NotApplicable | – | – | **Informational** |  |
| FS-56 | WAF ACLs Missing Common Rule Set (XSS) | FAIL | 2 | 2 | **Medium** |  |
| FS-56 | XSS Prevention Common Rule Set Present | PASS | 2 | 2 | **Medium** |  |
| FS-57 | ADVISORY: Output Encoding — Manual Review Required | NA-Advisory | – | – | **Informational** |  |
| FS-58 | ADVISORY: Output Schema Validation — Manual Review Required | NA-Advisory | – | – | **Informational** |  |

</details>

### Category 14 — Off-Topic and Inappropriate Output (FS-59 to FS-60)

<details>
<summary>5 findings</summary>

| Check | Finding name | Disposition | I | L | Severity | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| FS-59 | No Guardrails — Topic Allowlist Not Applicable | NA-NotApplicable | – | – | **Informational** |  |
| FS-59 | No Guardrails With Topic Restrictions | FAIL | 2 | 2 | **Medium** |  |
| FS-59 | Topic Restrictions Configured on CLASSIC Tier | PASS | 2 | 2 | **Medium** | See [CLASSIC-tier guardrails](#classic-tier-guardrails) |
| FS-59 | Guardrail Topic Restrictions Configured | PASS | 2 | 2 | **Medium** |  |
| FS-60 | ADVISORY: Contextual Grounding for Off-Topic Prevention | NA-Advisory | – | – | **Informational** |  |

</details>

### Category 15 — Out-of-Date Training Data (FS-61 to FS-63)

<details>
<summary>7 findings</summary>

| Check | Finding name | Disposition | I | L | Severity | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| FS-61 | No Knowledge Bases Found | NA-NotApplicable | – | – | **Informational** |  |
| FS-61 | No Automated KB Sync Schedules Detected | FAIL | 2 | 2 | **Medium** |  |
| FS-61 | Automated KB Sync Schedules Present | PASS | 2 | 2 | **Medium** |  |
| FS-62 | ADVISORY: Data Currency Disclaimer — Manual Review Required | NA-Advisory | – | – | **Informational** |  |
| FS-63 | No Foundation Model Lifecycle Governance Detected | FAIL | 2 | 2 | **Medium** | Keyed off account-side AWS Config rules, not the regional model catalog |
| FS-63 | Foundation Model Lifecycle Governance Detected | PASS | 2 | 2 | **Medium** |  |
| FS-63 | COULD NOT ASSESS: Foundation Model Lifecycle Policy Check | NA-CouldNotAssess | – | – | **Low** | `config:DescribeConfigRules` denied |

</details>

### Material gap checks (FS-65 to FS-69)

<details>
<summary>17 findings</summary>

| Check | Finding name | Disposition | I | L | Severity | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| FS-65 | No Knowledge Bases Found | NA-NotApplicable | – | – | **Informational** |  |
| FS-65 | KB Data Source References a Deleted S3 Bucket | FAIL | 3 | 2 | **High** | Distinct risk |
| FS-65 | KB Data Source Buckets Missing S3 Event Notifications | FAIL | 2 | 2 | **Medium** | Distinct risk |
| FS-65 | KB Data Source S3 Event Notifications Configured | PASS | 2 | 2 | **Medium** |  |
| FS-66 | AgentCore Identity Propagation — Access Check | NA-CouldNotAssess | – | – | **Low** |  |
| FS-66 | No AgentCore Runtimes Found | NA-NotApplicable | – | – | **Informational** |  |
| FS-66 | AgentCore Runtimes Without JWT Authorizer | FAIL | 3 | 2 | **High** | Reads `authorizerConfiguration`, which shows whether inbound JWT authorization is configured, not whether an end-user identity reaches downstream calls |
| FS-66 | AgentCore Runtimes With JWT Authorizer Configured | PASS | 3 | 2 | **High** | Same scope limit as the FAIL row above |
| FS-66 | COULD NOT ASSESS: AgentCore End-User Identity Propagation Check | NA-CouldNotAssess | – | – | **Low** | Emitted when the runtime detail cannot be read (distinct from the inbound-authorizer access check above) |
| FS-67 | No Agent Action-Group Lambda Functions Found | NA-NotApplicable | – | – | **Informational** |  |
| FS-67 | Agent Action-Group Lambdas May Lack Transaction Thresholds | FAIL | 3 | 2 | **High** |  |
| FS-67 | Agent Action-Group Lambdas Have Threshold-Named Variables | PASS | 3 | 2 | **High** | The check matches Lambda environment variable NAMES and cannot see whether a threshold value is set or enforced |
| FS-68 | API Gateway Request Body Size Limits Not Enforced | FAIL | 2 | 2 | **Medium** |  |
| FS-68 | API Gateway Request Body Size Limits — Not Applicable | NA-NotApplicable | – | – | **Informational** |  |
| FS-68 | API Gateway Request Body Size Limits Configured | PASS | 2 | 2 | **Medium** |  |
| FS-69 | No Prompt Input Validation Function Found | FAIL | 2 | 2 | **Medium** |  |
| FS-69 | Prompt Input Validation Functions Present | PASS | 2 | 2 | **Medium** |  |

</details>

### Cross-cutting synthesized rows

| Source | Finding name | Disposition | Severity | Notes |
| --- | --- | --- | --- | --- |
| `_could_not_assess_row()` | `COULD NOT ASSESS: <check name>` (any check that errors with no rows) | NA-CouldNotAssess | **Low** | Validated by the disposition rule, not by name |
| `_permission_cache_unavailable_findings()` | `<check name> Incomplete` (FS-07 `Agent Action Boundary Check Incomplete`, FS-22 `Knowledge Base IAM Least Privilege Check Incomplete`) | N/A (tooling condition) | **Informational** | Emitted when the IAM permissions cache is missing, unreadable, or malformed. Not in `SEVERITY_REGISTER`. |
