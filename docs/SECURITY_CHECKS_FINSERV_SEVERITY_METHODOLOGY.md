# FinServ GenAI Check Severity Methodology

**Status:** Adopted for FinServ. Implemented in `finserv_assessments/app.py` (`SEVERITY_REGISTER`,
`_SEVERITY_MATRIX`, `_DISPOSITION_SEVERITY`, `_could_not_assess_row`) and enforced by the
drift-guard test suite `finserv_tests/test_severity_register.py`. This document is the
authoritative reference for how every FinServ (`FS-`) check is assigned a severity. It answers reviewer Finding 6 ("How are the priorities of the findings determined?") with a concrete reproducible, industry- and AWS-aligned formula — not per-check intuition.

**Tool-wide adoption status (Bedrock/AgentCore/SageMaker):** the general checks now apply the
same disposition principles pointwise — `COULD_NOT_ASSESS` (access-denied, unsupported region)
routes to `N/A`/`Low` rather than a false `Failed` or a silent no-resources `N/A` (see `AC-06`,
`AG-24`), and severity is kept consistent across a control's Passed/Failed rows (see the `AC-12`,
`AC-07`, `SM-11`, `SM-15` fixes). A unified `SEVERITY_REGISTER`/`_could_not_assess_row` shared
across all four modules (rather than the FinServ-only implementation below) remains a follow-up;
today each general-check module applies the same rules pointwise rather than through one shared
register.

> Scope note: today the FinServ checks and the upstream Bedrock/SageMaker/AgentCore checks all use ad-hoc severities with **no documented methodology** (verified by inspection — the upstream `app.py` files hardcode `severity="High"|"Medium"|...` with no rationale and no rubric doc). This methodology is introduced for the FinServ checks first and is written so it can later be adopted tool-wide.

---

## 1. Research basis (authoritative sources reviewed)

| Standard | What it contributes | Why we did / didn't adopt it wholesale |
|---|---|---|
| **AWS Security Hub ASFF Severity** ([API_Severity](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_Severity.html)) | The AWS-native label set (`INFORMATIONAL/LOW/MEDIUM/HIGH/CRITICAL`) with precise semantics and normalized 0–100 ranges. | **Adopted as the target label vocabulary** so findings align with Security Hub, the service customers use to aggregate posture findings. |
| **AWS exposure-finding severity factors** ([doc](https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-findings-severity.html)) | AWS's own model: *Awareness, Ease of discovery, Ease of exploit, Likelihood of exploit, Impact* — i.e. **Likelihood × Impact**. | **Adopted the Likelihood × Impact shape**; AWS itself uses it, so it is the most defensible AWS-aligned model. |
| **NIST SP 800-30 r1** ([CSRC](https://csrc.nist.gov/pubs/sp/800/30/final)) | Risk = Likelihood × Impact, a 5×5 qualitative matrix with a published lookup table. | **Adopted the matrix-lookup approach** (foundational US-government risk standard; FinServ regulators expect NIST-lineage rigor). Simplified to 3×3 for explainability. |
| **OWASP Risk Rating Methodology** ([OWASP](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)) | Likelihood (threat-agent + vulnerability) × Impact (technical + business), averaged and banded LOW/MEDIUM/HIGH. | **Adopted the factor-decomposition idea** (score sub-factors, then combine) and the business-impact dimension. |
| **CVSS v3.1** ([FIRST](https://www.first.org/cvss/)) qualitative bands (0 None / 0.1–3.9 Low / 4.0–6.9 Medium / 7.0–8.9 High / 9.0–10.0 Critical) | Standard numeric→qualitative banding. | **Referenced** for band shape; **not adopted wholesale** — CVSS scores *software vulnerabilities (CVEs)*, not *missing-control posture findings*. Using CVSS metrics (Attack Vector, etc.) on a "no WAF configured" finding is a category error. |
| **CISA SSVC** (Stakeholder-Specific Vulnerability Categorization) | Decision-tree (Exploitation/Automatable/Technical Impact/Mission) → Track/Attend/Act. | **Referenced**, not adopted — also CVE/vulnerability-centric and produces action labels, not the severity labels the report and Security Hub expect. |

**Conclusion:** A control-gap posture tool should score **Likelihood × Impact** (per AWS's own
exposure model and NIST 800-30) and express the result in the **ASFF label set**. CVSS/SSVC are
for CVEs and are explicitly out of scope as the scoring engine, though the report remains
compatible with Security Hub's ASFF labels for customers who ingest it.

---

## 2. The severity scale (ASFF-aligned)

We use the ASFF labels with AWS's exact semantics. The tool's `SeverityEnum` today is
`High | Medium | Low | Informational` (no `Critical`) and is shared with the upstream services.

| Label | ASFF meaning | ASFF normalized | Used by FinServ for |
|---|---|---|---|
| **Informational** | No issue / not action-bearing on its own | 0 | Advisory checks (no API to verify) and `N/A` (nothing to assess / could-not-assess) |
| **Low** | Does not require action on its own | 1–39 | Residual-risk / observability controls, or controls with strong compensating alternatives |
| **Medium** | Must be addressed, not urgently | 40–69 | Controls whose absence materially increases risk but is not itself a breach |
| **High** | Must be addressed as a priority | 70–89 | Controls whose absence can directly cause regulatory breach, data exposure, large loss, or full guardrail bypass |
| **Critical** | Remediate immediately | 90–100 | **Not currently used** (see §6 decision). Reserved. |

---

## 3. The scoring model (Likelihood × Impact → label)

Each **risk a control mitigates** is scored on two axes, each Low(1)/Medium(2)/High(3). Severity
is the inherent risk the control addresses, so the **same severity applies to that check's Passed,
Failed, and (where risk-bearing) N/A rows** — preserving the Round-2 invariant that Passed
findings keep their documented severity.

### 3.1 Impact (I) — harm if the control is absent and the risk materializes

| Score | Criteria (any one qualifies) |
|---|---|
| **3 — High** | Direct regulatory breach (e.g., fair-lending/ECOA, disclosure rules); sensitive-data/PII exposure; large-scale financial loss; full bypass of safety guardrails; unsafe automated financial action. |
| **2 — Medium** | Materially weakens oversight, model-risk governance, or assurance; increases blast radius of another failure; degraded auditability of a regulated decision — but not a breach by itself. |
| **1 — Low** | Reduces residual risk, supports observability/audit, or is fully covered by a compensating control; cost-optimization or defense-in-depth value. |

### 3.2 Likelihood (L) — probability the adverse outcome occurs given the control is absent

Blends AWS's *awareness / ease of discovery / ease of exploit* with the presence of compensating
controls. Applies to both attack-driven risks (prompt injection, cost exhaustion) and
governance-driven risks (an unreviewed model reaches production).

| Score | Criteria |
|---|---|
| **3 — High** | Internet-reachable or default-on surface; common, automatable attack pattern; or near-certain to occur in normal operation; no compensating control. |
| **2 — Medium** | Reachable under common conditions; partial or adjacent compensating control exists; periodic rather than continuous exposure. |
| **1 — Low** | Requires unusual conditions or insider access; strong compensating controls substantially reduce exposure; rare in practice. |

### 3.3 Lookup matrix (3×3 → ASFF label)

|              | **L = Low (1)** | **L = Medium (2)** | **L = High (3)** |
|--------------|-----------------|--------------------|------------------|
| **I = High (3)**   | Medium | High | High *(Critical-eligible — see §6)* |
| **I = Medium (2)** | Low | Medium | High |
| **I = Low (1)**    | Low | Low | Medium |

Equivalent rule: `score = I × L`; `1–2 → Low`, `3–4 → Medium`, `6–9 → High` (with the
`I=3,L=3 → 9` cell Critical-eligible). Advisory/non-verifiable and `N/A` outcomes are handled by
the disposition rules in §3.4 (they are not risk-scored).

### 3.4 Outcome disposition rules (CRITICAL — resolves the N/A inconsistency)

**Severity is a property of the control (the risk), not the outcome.** A control is scored once
(§3.1–3.3) and that severity is applied to **every** Passed and Failed row of that control
(preserving the Round-2 invariant). The `N/A` family is where the current code is inconsistent
(audit found "nothing to assess" rows tagged High, Medium, AND Informational across checks). Each
row maps to exactly one **disposition**, and the disposition fixes the severity:

| Disposition | When it applies | Severity | ASFF rationale |
|---|---|---|---|
| **FAIL** | control assessed, not satisfied | control severity (§3.3) | the asserted issue |
| **PASS** | control assessed, satisfied | control severity (§3.3) | Round-2 invariant: pass keeps documented severity |
| **NOT_APPLICABLE** | the control's resource type is absent (no KBs, no guardrails, no WAF, no REST APIs, not in an Org) | **Informational** | ASFF: *"INFORMATIONAL — No issue was found."* The "you should create guardrails/eval jobs" signal belongs to that resource's **own** existence check, not to every sub-check (avoids double-counting). |
| **ADVISORY** | no AWS API can verify the control (app-layer) | **Informational** | Option-B convention (Round 1); `"ADVISORY: "` name prefix |
| **COULD_NOT_ASSESS** | the check could not run (access-denied, unsupported region, SDK gap) | **Low** | not a confirmed issue (unknown state); the `"COULD NOT ASSESS: "` / access-check name keeps it visible; prompts a re-run. Unifies today's Low/Medium split. |
| **SOFT_WARNING** | control assessed; a legitimate-but-suboptimal non-failing state (the only instance is **FS-03 quotas-at-default**, an intentional Round-1 decision) | control severity | documented exception |

This single table eliminates the audit-found inconsistency: every NOT_APPLICABLE row → Informational;
every COULD_NOT_ASSESS row → Low; every ADVISORY row → Informational.

> **Check-logic items (now in scope as REQ-10):** a few checks used `N/A`/`Passed` in ways that
> understate or overstate risk. These are fixed in this round: FS-15 "no eval jobs" → `Failed`;
> FS-30/35/40 (cannot inspect dataset content) → advisory; FS-56 gains a real FAIL path. FS-28/36/
> 51/59 CLASSIC-tier was investigated and intentionally kept `Passed` (CLASSIC provides real
> protection; not deprecated). See REQ-10 and `severity-register.md`.

### 3.5 Control-family bands (ensures cross-check consistency)

To guarantee similar controls get the same severity, every FS control is assigned to a family with
a default band. Per-control I×L may refine within ±1 with a documented reason.

| Family | Risk on absence | Default | Example checks |
|---|---|---|---|
| **Safety-guardrail / content safety** | harmful output, guardrail bypass, PII leak | **High** | FS-36 content, FS-45 PII, FS-47 grounding threshold, FS-51 prompt-attack, FS-53 injection, FS-27 contextual grounding |
| **Sensitive-data exposure / integrity** | PII exposure or training-data tampering | **High** | FS-21 training-data versioning, FS-25 KB encryption, FS-43 log data-protection, FS-44 Macie |
| **Excessive agency / access control / isolation** | unauthorized action, over-broad permissions, regulated-decision breach | **High** | FS-07, FS-08, FS-10, FS-12, FS-22, FS-26, FS-39 bias, FS-41 explainability, FS-66, FS-67 |
| **Regulated-output controls** | non-compliant / off-regulatory output | **High** (denied-topics) / **Medium** (softer: word filters, topic allowlist, relevance) | FS-28 (High), FS-38/FS-59/FS-50 (Medium) |
| **Unbounded consumption / cost / rate-limiting** | cost exhaustion, DoS — compensating controls exist, no breach | **Medium** | FS-01 WAF, FS-02, FS-03, FS-05, FS-06, FS-09, FS-11, FS-68 |
| **Governance / model-risk / monitoring / currency** | weakened oversight/assurance, not a breach | **Medium** | FS-04, FS-13, FS-14, FS-15, FS-20, FS-30/34/35/40/42, FS-31/61, FS-46, FS-48, FS-52, FS-55, FS-63, FS-69 |
| **Premium-cost defense-in-depth** | residual DDoS risk; Shield Standard + WAF compensate; ~$3k/mo | **Low** | FS-01 Shield Advanced |
| **Emerging/advanced advisory control** | formal-verification gap; grounding compensates | **Medium→Low** | FS-27 ARC |
| **Non-verifiable advisory** | app-layer; no API | **Informational** | FS-24, FS-29, FS-32, FS-37, FS-49, FS-54, FS-57, FS-58, FS-60, FS-62 |

The authoritative per-finding assignments are in
[`SECURITY_CHECKS_FINSERV_SEVERITY_REGISTER.md`](./SECURITY_CHECKS_FINSERV_SEVERITY_REGISTER.md).



---

## 4. Worked examples (including the reviewer's case)

| Check | Control | I | L | Rationale | Result |
|---|---|---|---|---|---|
| **FS-01 (Shield Advanced)** | Shield Advanced subscription | **1** | **2** | Impact Low: Shield *Standard* is always-on and free; WAF rate-limiting (FS-01 WAF / FS-02 usage plans) is a compensating control; absence is a premium-cost decision (~$3,000/mo), not a breach. Likelihood Medium: endpoints are discoverable but volumetric DDoS on a Bedrock-fronting endpoint is not the common case. | **Low** *(was High — fixes Finding 6)* |
| **FS-01 (Regional WAF)** | WAF Web ACL present | **2** | **2** | Impact Medium: no WAF → exposed to abusive callers / cost exhaustion, but API Gateway usage-plan throttling (FS-02) is a compensating control and there is no direct breach. Likelihood Medium: common but mitigated by throttling. | **Medium** |
| **FS-43-style (PII in logs / data exposure)** | Sensitive-data masking | **3** | **2** | Impact High: PII exposure = regulatory breach. Likelihood Medium: requires logging misconfig. | **High** |
| **FS-58 (output schema validation)** | App-layer validation | — | — | No AWS API can verify it → advisory. | **Informational** (advisory) |
| **FS-27 ARC (no policies)** | Automated Reasoning policy present | **2** | **2** | Impact Medium: ARC adds formal verification of factual claims; its absence leaves grounding-only assurance. Likelihood Medium: unverified factual claims occur under common operating conditions; contextual grounding (FS-27 grounding) partially compensates but is threshold-based, not formal verification. | **Medium** (matches register) |

---

## 5. Application, governance, and drift-prevention

1. **Per-finding severity register.** A machine-checkable register (`severity-register.csv` or a `SEVERITY_REGISTER` dict in `app.py`) lists every `FS-` finding-name with its `I`, `L`, resulting label, and a one-line justification. This is the single source of truth.
   *(FS-01 emits four finding-names under one Check_ID; the register is keyed by finding-name so Shield=Low and WAF=Medium can coexist under FS-01.)*
2. **Code matches register.** Every `create_finding(... severity=...)` must equal the register's label for that finding. A unit test enforces this (prevents future drift) — a strong guard for a public tool.
3. **Docs match register.** The per-check severity columns and the `Severity rubric` section in
   `SECURITY_CHECKS_FINSERV.md` are regenerated/checked against
   the register. The "Advisory" tier in the existing rubric is reconciled (Advisory = the Informational disposition for non-verifiable controls).
4. **Methodology surfaced to users.** A condensed version of §2–§3 is added to the README and
   linked from the FinServ report section so the methodology travels with the artifact (directly answering the reviewer).
5. **ASFF mapping documented.** README states the label↔ASFF-normalized mapping so customers who forward findings to Security Hub get correct severities.

---

## 6. Decision (CONFIRMED 2026-06-10): keep four levels; do not introduce `Critical` yet

The matrix has a Critical-eligible cell (I=High, L=High). Two paths:

- **Path A — keep four levels (recommended for this PR).** Cap the I=3,L=3 cell at **High**.
  Pro: stays consistent with the upstream Bedrock/SageMaker/AgentCore checks (which have no
  Critical), no `SeverityEnum`/report/test changes, smaller reviewable PR. Con: a genuinely
  critical FinServ risk is reported as High.
- **Path B — adopt `Critical` tool-wide (separate follow-up PR).** Add `CRITICAL` to
  `SeverityEnum`, update the report template's severity filters/colors, and re-score the I=3,L=3
  FinServ checks. Pro: full ASFF alignment. Con: cross-cutting change touching all four services,
  the schema, the report, and every service's tests — out of scope for a correctness-focused round.

**Confirmed decision:** **Path A** for this round — keep `{High, Medium, Low, Informational}`. A follow-up issue will evaluate Path B tool-wide. The methodology already documents the `Critical` band (§2), so adopting it later is a labeling change, not a methodology change; until then the drift-guard test asserts no `Critical` is emitted.

---

## 7. How this changes the report (expected, document for reviewers)

Downgrading FS-01 Shield from High→Low (and any other audit-driven changes) **moves those findings into the Low band, which still counts toward the pass-rate denominator when the row is scored (Passed/Failed)**. So pass rates and the High-severity count will shift; this is
intended and must be called out in the PR description with before/after numbers so reviewers do not mistake it for a new regression.

**Pass-rate scoring rule (enforced by the report template):** pass-rate denominators count
only rows with `Status` of `Passed` or `Failed`. Every `N/A`-status row is excluded from the
denominators regardless of its severity label — that covers `NOT_APPLICABLE` and `ADVISORY`
rows (Informational), `COULD_NOT_ASSESS` rows (Low), and the FS-03 `SOFT_WARNING` row
(Medium). A `COULD_NOT_ASSESS` row therefore never silently depresses the pass rate; it is
surfaced instead in the report's dedicated **Unassessed Checks** metric, which prompts the
customer to fix assessment-role access and re-run. This keeps the §3.4 promise that
"unknown state" is visible without being scored as a failure.
