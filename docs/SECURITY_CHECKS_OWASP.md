# OWASP Top 10 for LLM Security Checks

This document catalogs the 12 OWASP Top 10 for LLM (OW-XX) checks produced by
the AI/ML Security Assessment framework, and how each maps back to the
underlying BR/SM/AC/FS checks it is derived from.

- **Reference:** [OWASP Top 10 for LLM 2025](https://genai.owasp.org/llm-top-10/)
  and the category-specific remediation pages linked from that page.
- **Opt-in:** Set `EnableOWASPAssessment=true` on the deployment stack.
- **Report location:** New "By Compliance Standard" sidebar section, alongside
  the existing "By Lens" (Agentic AI) and "By Industry" (Financial Services)
  sections.
- **FinServ auto-runs when OWASP is enabled.** ~2/3 of the OWASP mapping rows
  (and all of LLM05) derive from the FinServ (FS-XX) checks. To guarantee
  full OWASP coverage, the state machine automatically runs the FinServ
  Lambda whenever `EnableOWASPAssessment=true`, even when
  `EnableFinServAssessment=false`. In that case, FinServ findings are used
  only to derive OW-XX rows and are **hidden from the report UI** (no
  FinServ nav item, service card, or section). Enable
  `EnableFinServAssessment=true` explicitly if you want the FinServ section
  to appear alongside OWASP.

## Disclaimer

> **These mappings are PRELIMINARY and ILLUSTRATIVE.** They have not been
> reviewed by AWS Security Assurance Services or external auditors. Each
> organisation should validate them against its own interpretation of the
> OWASP Top 10 for LLM 2025 controls before relying on them as audit evidence.

## Design

OW-01 through OW-10 are **derived** by mapping existing findings, so the
OWASP Lambda itself does not call AWS APIs for those mapped rows. When OWASP
is enabled and FinServ is not, the state machine still runs FinServ once to
produce the FS-* source findings that feed OWASP mappings; that can increase
scan time and use the FinServ IAM surface. OW-11 and OW-12 are the only
**native** OWASP checks: they inspect Bedrock guardrails and Lambda env vars
for signals specific to LLM07 (System Prompt Leakage) that the existing
checks do not cover.

The OWASP Lambda runs after the per-service Lambdas (Bedrock, SageMaker,
AgentCore, FinServ) have written their per-region CSVs. It reads those CSVs,
applies the `OWASP_CHECK_MAPPINGS` dict, runs OW-11 and OW-12, and writes
`owasp_security_report_<execution>_<region>.csv`.

If a required source CSV is missing, the Lambda emits an informational `OW-00`
coverage row instead of silently omitting all derived rows from that source.
`OW-00` is not an OWASP Top 10 control; it is a report-completeness marker.

## Extensibility

The "By Compliance Standard" sidebar section is data-driven — future NIST AI
RMF (`NR-` prefix) and EU AI Act (`EU-` prefix) additions require only
appending a new entry to `COMPLIANCE_STANDARDS` in `report_template.py` and
following the same Lambda/CFN wire-up pattern (`EnableNISTAssessment` /
`EnableEUAIActAssessment`). Each new prefix must be 2–3 uppercase letters to
satisfy the Check_ID regex `^[A-Z]{2,3}-\d{2}$`.

## Check catalogue

Each emitted OW row uses the category-specific OWASP remediation reference
for its `Reference` field:

| Check | OWASP category | Reference |
| ------- | ---------------- | ----------- |
| OW-01 | LLM01:2025 Prompt Injection | <https://genai.owasp.org/llmrisk/llm01-prompt-injection/> |
| OW-02 | LLM02:2025 Sensitive Information Disclosure | <https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/> |
| OW-03 | LLM03:2025 Supply Chain | <https://genai.owasp.org/llmrisk/llm032025-supply-chain/> |
| OW-04 | LLM04:2025 Data and Model Poisoning | <https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/> |
| OW-05 | LLM05:2025 Improper Output Handling | <https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/> |
| OW-06 | LLM06:2025 Excessive Agency | <https://genai.owasp.org/llmrisk/llm062025-excessive-agency/> |
| OW-07, OW-11, OW-12 | LLM07:2025 System Prompt Leakage | <https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/> |
| OW-08 | LLM08:2025 Vector and Embedding Weaknesses | <https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/> |
| OW-09 | LLM09:2025 Misinformation | <https://genai.owasp.org/llmrisk/llm092025-misinformation/> |
| OW-10 | LLM10:2025 Unbounded Consumption | <https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/> |

### LLM01 Prompt Injection — OW-01

Maps from:

| Source | Signal |
| -------- | -------- |
| BR-04 | Bedrock model invocation logging enabled (§4.3 prompt logging) |
| BR-23 | Guardrail content filter coverage |
| BR-27 | Contextual grounding guardrail |
| FS-51 | PROMPT_ATTACK filter at Standard tier |
| FS-52 | Bedrock-calling Lambda runtimes not deprecated |
| FS-53 | WAF SQLi + KnownBadInputs managed rule groups |
| FS-54 | Adversarial testing evidence via tagging |
| FS-69 | Prompt-input validation Lambda present |

### LLM02 Sensitive Information Disclosure — OW-02

Maps from:

| Source | Signal |
| -------- | -------- |
| BR-26 | Guardrail PII / regex filter policy |
| FS-43 | CloudWatch log data protection policies |
| FS-44 | Amazon Macie sensitive-data discovery |
| FS-45 | Guardrail PII entities coverage (FinServ) |
| FS-46 | S3 data-classification tagging |
| SM-03 | SageMaker notebooks, domains, and training jobs use encryption controls |
| SM-15 | SageMaker Feature Store offline stores use KMS encryption |

### LLM03 Supply Chain — OW-03

Maps from:

| Source | Signal |
| -------- | -------- |
| BR-30 | Imported-model KMS encryption |
| BR-33 | Amazon Inspector Lambda code scanning (§2.5 SBOM / static analysis) |
| FS-12 | SCP-enforced model allowlist |
| FS-13 | Custom-model provenance tags |
| FS-14 | AWS Config rules for model onboarding |
| FS-15 | Adversarial evaluation coverage |
| FS-16 | ECR image scanning |
| SM-01 | SageMaker notebooks/domains avoid direct internet exposure |
| SM-10 | SageMaker notebooks are deployed inside a VPC |
| SM-11 | SageMaker model containers use network isolation |
| SM-14 | SageMaker models pull containers through controlled repository access |
| SM-21 | SageMaker AutoML jobs use network isolation |
| SM-25 | SageMaker Experiments and lineage associations track model provenance |

### LLM04 Data and Model Poisoning — OW-04

Maps from:

| Source | Signal |
| -------- | -------- |
| BR-25 | RAG evaluation coverage |
| BR-27 | Contextual grounding on retrieved data |
| FS-20 | Feature Store OfflineStoreConfig |
| FS-21 | Training-data S3 versioning |
| FS-42 | SageMaker Model Card documentation (§3.1 model system card reviews) |
| SM-07 | SageMaker Model Monitor schedules detect quality regressions |
| SM-22 | SageMaker Model Registry approval workflows gate model promotion |
| SM-23 | SageMaker drift detection monitors production endpoints |
| SM-25 | SageMaker lineage tracking links data, training runs, and model artifacts |

### LLM05 Improper Output Handling — OW-05

Maps from:

| Source | Signal |
| -------- | -------- |
| FS-55 | Output-validation Lambda in response path |
| FS-56 | WAF XSS protection |
| FS-57 | Output encoding libraries in Lambda |
| FS-58 | Step Functions output schema validation |

### LLM06 Excessive Agency — OW-06

Maps from:

| Source | Signal |
| -------- | -------- |
| BR-21 | Agent action-group Lambda role least privilege |
| BR-28 | Bedrock agent guardrail association |
| BR-29 | Agent idle session TTL bound |
| AC-02 | AgentCore IAM least privilege |
| AC-10 | AgentCore resource-based policies |
| FS-07 | Agent execution role least privilege (FinServ) |
| FS-08 | AgentCore Gateway Policy Engine ENFORCE |
| FS-09 | Agent tool concurrency limits |
| FS-10 | Step Functions HITL callback tasks |
| FS-67 | Agent transaction thresholds in Cedar / config |

### LLM07 System Prompt Leakage — OW-07 (mapping) + OW-11, OW-12 (native)

Mapping-based (OW-07) signals:

| Source | Signal |
| -------- | -------- |
| BR-04 | Bedrock model invocation logging enabled (§4.3 prompt logging) |
| BR-07 | Bedrock Prompt Management adoption (§2.2 prompts as code) |
| BR-16 | Guardrail Standard tier (Standard tier additionally detects prompt-leakage) |

Native checks fill the gap:

- **OW-11: System Prompt Embedded in Lambda Env Var**
  Heuristic: flag Lambda functions whose env vars are ≥ 200 chars and
  match **at least two distinct** prompt-shaped multi-word phrases from
  `SYSTEM_PROMPT_HEURISTIC_PHRASES` (e.g. `"you are a"`, `"you are an"`,
  `"your role"`, `"your task"`, `"you must"`, `"you should"`,
  `"helpful assistant"`, `"as an assistant"`, `"system prompt"`,
  `"system instruction"`, `"never reveal"`, `"do not reveal"`,
  `"internal instruction"`, `"respond politely"`). Multi-word phrases
  and the ≥ 2-match requirement are deliberate — the check is designed
  **not** to flag ordinary configuration blobs (policy JSON, log format
  strings, runbook text) that contain isolated words like `"system"` or
  `"instruction"`. Recommend moving prompts to Bedrock Prompt Management.
  Severity: Medium (control-inherent — same on Passed and Failed).

- **OW-12: System-Prompt-Disclosure Denied Topic**
  Verify at least one Bedrock guardrail's `topicPolicy` contains a DENY
  topic whose name or definition mentions "system prompt", "instruction
  disclosure", "prompt leakage", "reveal instructions", or "internal prompt".
  Severity: Medium (control-inherent — same on Passed and Failed).

**Severity convention.** OW-11 and OW-12 are native checks; their
severity is control-inherent (same on Passed and Failed), matching the
FinServ severity methodology. OW-01..OW-10 mapping rows inherit the
source check's severity except when the source is `N/A`, in which case
the OWASP row is downgraded to `Informational` to avoid inflating
severity totals with tooling / no-resource rows.

### LLM08 Vector and Embedding Weaknesses — OW-08

Maps from:

| Source | Signal |
| -------- | -------- |
| BR-20 | Managed Knowledge Base CMK encryption |
| FS-22 | KB IAM scoping |
| FS-24 | KB metadata filtering |
| FS-25 | OpenSearch Serverless encryption (CMK) |
| FS-26 | OpenSearch Serverless network policy |

### LLM09 Misinformation — OW-09

Maps from:

| Source | Signal |
| -------- | -------- |
| BR-18 | Model evaluation jobs |
| BR-25 | RAG evaluation for faithfulness |
| BR-27 | Contextual grounding for faithfulness |
| FS-31 | Knowledge Base ingestion freshness |
| FS-32 | Source attribution via citations |
| FS-33 | KB S3 data-source integrity |
| FS-42 | SageMaker Model Card documentation (§3.1 model system card reviews) |
| FS-47 | Grounding filter threshold ≥ 0.70 |
| FS-48 | Active Knowledge Base present |
| SM-06 | SageMaker Clarify evaluates bias and explainability |
| SM-07 | SageMaker Model Monitor schedules detect quality regressions |
| SM-22 | SageMaker Model Registry approval workflows gate production release |
| SM-23 | SageMaker drift detection monitors production endpoints |

### LLM10 Unbounded Consumption — OW-10

Maps from:

| Source | Signal |
| -------- | -------- |
| BR-22 | Service Quotas throttling limits |
| BR-32 | CloudWatch consumption alarms |
| FS-01 | WAF rate-based & Shield protection |
| FS-02 | API Gateway usage plans |
| FS-03 | Bedrock TPM/RPM quotas customised |
| FS-04 | AWS Cost Anomaly Detection |
| FS-05 | Token / throttle alarms |
| FS-06 | AWS Budgets with Bedrock filters |
| FS-68 | API Gateway request body size limits |
| SM-11 | SageMaker model network isolation limits uncontrolled outbound calls |

## Severity / status semantics

OW rows follow the same rules as every other check in the framework:

- The row's `Severity` and `Status` are inherited from the source finding.
  An N/A source produces an OW row with `Severity=Informational` and
  `Status=N/A` — never an inflated High/Medium.
- Access-denied / region-unsupported paths in OW-11/OW-12 → `N/A`, never
  `Failed`.
- Missing source CSVs for mapping-derived rows produce `OW-00` with
  `Severity=Informational` and `Status=N/A`.
- The `Reference` field on every OW row points to the category-specific
  remediation page linked from <https://genai.owasp.org/llm-top-10/>, not the
  AWS docs. This keeps report rows aligned to the OWASP category they satisfy
  even when the underlying misconfiguration was surfaced by a BR/SM/AC/FS
  source check.
