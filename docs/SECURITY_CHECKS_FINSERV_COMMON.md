# FinServ GenAI Risk Checks — Common Reference

This file contains shared reference material used by all three parts of the FinServ GenAI
security checks. It is not a checks file itself — the 64 standalone checks are split across Parts 1-3
(5 additional FS checks are merged into upstream SM/BR checks — see the consolidation table below):

- `SECURITY_CHECKS_FINSERV_PART1_INFRA_CONTROLS.md` — FS-01 to FS-26 (Unbounded, Excessive Agency, Supply Chain, Training Poisoning, Vector Weaknesses); FS-17, FS-18, FS-19, FS-23 merged into upstream
- `SECURITY_CHECKS_FINSERV_PART2_GUARDRAILS_CONTENT_SAFETY.md` — FS-27 to FS-46 (Non-Compliant, Misinformation, Abusive, Biased, Sensitive Info)
- `SECURITY_CHECKS_FINSERV_PART3_APP_LAYER_AND_GAPS.md` — FS-47 to FS-69 (Hallucination, Prompt Injection, Output Handling, Off-Topic, Stale Data, Material Gaps); FS-64 merged into upstream

Together, Parts 1-3 plus this common file replace the earlier single-file `SECURITY_CHECKS_FINSERV_ADDITION.md`.

## About the source

The 69 FS checks are derived from the [AWS guide for Financial Services risk management of the
use of Generative AI (March 2026)](https://d1.awsstatic.com/onedam/marketing-channels/website/public/global-FinServ-ComplianceGuide-GenAIRisks-public.pdf)
(referred to throughout as "the FinServ Guide").

Each check includes how it is **detected** (the AWS API calls or configuration inspected)
and how a failure is **remediated** (the specific AWS actions to take).

## PDF traceability

The FinServ Guide organises AI-specific risks into **15 categories** (§1.2.1 through §1.2.15
in the PDF). Every check below is tagged with one of:

- **[PDF §x.y.z]** — mitigation is explicitly listed in that PDF section's "Mitigations or controls"
  table or "Practical guidance" callout.
- **[PDF §x.y.z, extension]** — mitigation is consistent with the PDF's risk description but is
  not verbatim in the PDF; included because it is a widely-accepted AWS best practice for the
  same risk. These are labelled so reviewers know the provenance.

## Severity rubric

Severities follow a documented **Likelihood × Impact** methodology mapped to the AWS Security Hub
ASFF label set (`Informational | Low | Medium | High`; `Critical` is reserved, not used this
round). The full methodology, the 3×3 scoring matrix, the N/A **disposition rules**, and the
authoritative per-finding assignments are in
[`SECURITY_CHECKS_FINSERV_SEVERITY_METHODOLOGY.md`](./SECURITY_CHECKS_FINSERV_SEVERITY_METHODOLOGY.md)
and [`SECURITY_CHECKS_FINSERV_SEVERITY_REGISTER.md`](./SECURITY_CHECKS_FINSERV_SEVERITY_REGISTER.md).

| Severity | Criteria (ASFF-aligned) |
|---|---|
| **High** | Control whose absence can lead to direct regulatory breach, data exposure, large-scale financial loss, or full bypass of safety guardrails. |
| **Medium** | Control whose absence materially increases the likelihood or impact of a risk category but does not by itself produce a breach. |
| **Low** | Control that reduces residual risk or supports audit/observability but has alternative or compensating controls. |
| **Informational** | No actionable issue is asserted. Used for three dispositions: (1) **NOT_APPLICABLE** — the control's resource type is absent (e.g., no Knowledge Bases, no guardrails); (2) **ADVISORY** — the control cannot be verified via AWS APIs and requires human review (finding name prefixed `ADVISORY:`); (3) checks awaiting manual verification. |

> **Disposition rules (how a finding's severity is set):** severity is a property of the *control*
> (its Likelihood × Impact), applied to that control's `Passed` and `Failed` rows alike. The `N/A`
> family is fixed by disposition: **NOT_APPLICABLE → Informational**, **ADVISORY → Informational**,
> **COULD_NOT_ASSESS** (access denied / unsupported region) **→ Low**. The legacy "Advisory" tier in
> earlier revisions of this document is reconciled to the **Informational** label + `N/A` status +
> `ADVISORY:` name prefix.

## Validation note

Detection and remediation guidance in this document was systematically validated against the
FinServ Guide (March 2026), current AWS documentation, API references, and AWS announcements as
of April 2026. IAM action names were verified against the AWS Service Authorization Reference
for [Amazon Bedrock](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonbedrock.html),
[Amazon Bedrock AgentCore](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonbedrockagentcore.html),
and [Amazon OpenSearch Serverless](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonopensearchserverless.html)
(note: the OpenSearch Serverless IAM prefix is `aoss:`, not `opensearchserverless:` — the latter
is the boto3 client name).
CloudWatch metric namespaces were verified against the service-specific monitoring docs (Bedrock,
Bedrock Agents, Bedrock Guardrails, SageMaker Model Monitor, SageMaker Clarify). CloudTrail
event-type classification (management vs data) for Bedrock API operations was verified against the
[Bedrock CloudTrail integration guide](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html).
Cost Anomaly Detection monitor-type values were verified against the
[AnomalyMonitor API reference](https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_AnomalyMonitor.html).
Where AWS does not prescribe a specific value (e.g., grounding thresholds), this is explicitly
called out as an assessment recommendation rather than an AWS requirement. AWS regional
availability of new features (Automated Reasoning, AgentCore Policy, AWS Security Agent,
cross-account guardrails) evolves rapidly — region lists in Parts 1-3 reflect the state at the
cited announcement date and should be re-verified before audit reliance.

## Contribution workflow

The FS checks are contributed upstream as a single pull request via a personal GitHub fork
of `aws-samples/sample-aiml-security-assessment`. The full 9-step process — feature-request
GitHub issue, fork + feature branch, local ASH security scan, Conventional Commits, PR,
GitHub Actions verification, reviewer assignment, and (only if needed) Git Defender
exception — lives in [`GIT_WORKFLOW.md`](./GIT_WORKFLOW.md) at the repository root. A
condensed version is in the `Git Workflow` section of [`IMPLEMENTATION_PLAN.md`](./IMPLEMENTATION_PLAN.md).

Key quality gates before opening the PR (see `GIT_WORKFLOW.md` Step 5):

1. `ruff check` and `ruff format --check` pass on `functions/security/finserv_assessments/`.
2. `cfn-lint` and `sam validate --lint` pass on the SAM templates.
3. [ASH v3](https://awslabs.github.io/automated-security-helper/) scan
   (`ash --source-dir . --fail-on-findings --config-overrides
   'global_settings.severity_threshold=MEDIUM'`) reports zero Critical / High findings,
   or suppressions are documented in `.ash/.ash.yaml`.
4. Amazon Code Defender (`git defender scan`) reports no secrets in the staged diff.

Because `aws-samples` is an OSPO-managed organization, pushes to your personal fork of
`aws-samples/*` are auto-allowed by Code Defender — a Git Defender exception ticket is
**not expected** for this contribution.

## Relationship to upstream SM/BR/AC checks

The upstream [sample-aiml-security-assessment](https://github.com/aws-samples/sample-aiml-security-assessment)
framework already provides 52 security checks (SM-01 to SM-25, BR-01 to BR-14, AC-01 to AC-13).
The 69 FS checks in this document are **additive**: they enhance the upstream with FinServ-specific
detection and remediation guidance drawn from the AWS FinServ GenAI Guide (March 2026). A few FS
checks overlap with upstream checks — in those cases, the FS check adds FinServ-specific depth
(e.g., protected-attribute facets, regulatory cadence requirements, denied-topic content for
financial advice). The table below surfaces each overlap with a systematic recommendation based
on five factors: (1) whether the detection target is the same AWS resource/configuration, (2)
whether the FS check adds FinServ-specific regulatory specificity, (3) severity differentiation,
(4) whether a customer would remediate them differently, and (5) PDF-traceability value.

**Recommendation values:**

- **Extend upstream** — merge FS detection/remediation detail into the upstream check; do not ship FS as a standalone entry in the final report. Best when both checks target the same resource and the FS content is an enhancement.
- **Keep separate** — ship as a standalone FS check alongside the upstream check. Best when the FS check targets a different AWS resource, has materially different severity, or encodes a FinServ-specific regulatory requirement that would be diluted by merging.

| FS check | Upstream check | Overlap analysis | Recommendation |
|---|---|---|---|
| FS-17 (Model Monitor Data Quality) | SM-07 (Model Monitor) | Same resource (`sagemaker:ListMonitoringSchedules`); FS-17 adds training-data-drift-specific guidance, exact CloudWatch namespace (`/aws/sagemaker/Endpoints/data-metric`), and `emit_metrics` requirement. | **Extend SM-07** — add FS-17's detection detail (namespace, `emit_metrics`) as a refinement of the existing check |
| FS-18 (Model Drift Detection) | SM-23 (Model Drift Detection) | Same name, same resource, same detection logic (`MonitoringType=ModelQuality`). FS-18 adds PDF §1.2.14 low-entropy classification monitoring as an early-warning poisoning indicator. | **Extend SM-23** — add low-entropy monitoring as a new remediation step on SM-23; do not ship FS-18 separately |
| FS-19 (Model Registry Approval) | SM-08 (Model Registry) / SM-22 (Model Approval Workflow) | SM-22 is conceptually identical. FS-19 specifies exact `ModelApprovalStatus=PendingManualApproval` default and flags auto-approved latest versions. | **Extend SM-22** — add FS-19's detection specificity (flag auto-approved latest versions) to SM-22; do not ship FS-19 separately |
| FS-20 (Feature Store Rollback) | SM-15 (Feature Store Encryption) | Different security properties on the same resource: SM-15 checks encryption; FS-20 checks `OfflineStoreConfig` presence for point-in-time rollback. | **Keep separate** — different security property; no true overlap |
| FS-39 (SageMaker Clarify Bias) | SM-06 (Clarify Usage) | Same resource family but SM-06 is Severity Low and generic ("validates Clarify for bias detection"); FS-39 is Severity High with specific `MonitoringType=ModelBias`, protected-attribute facets (age/gender/race/geography), and specific bias metrics (DPL, DI, DPPL) for FinServ decision models. | **Keep separate** — severity, detection specificity, and FinServ regulatory context (ECOA/Fair Housing) warrant a standalone check |
| FS-41 (SageMaker Clarify Explainability) | SM-06 (Clarify Usage) | Same as FS-39 but for `MonitoringType=ModelExplainability`. FS-41 is Severity High with SHAP analysis for adverse-action-notice use cases. | **Keep separate** — severity and adverse-action-notice regulatory context justify a standalone check |
| FS-22 (KB IAM Least Privilege) | BR-01 (IAM Least Privilege) | BR-01 detects the managed policy `AmazonBedrockFullAccess` on any role. FS-22 inspects role policy documents for wildcard `bedrock:*` affecting KB actions and requires ARN-scoped resource restrictions. | **Keep separate** — different detection logic (managed-policy attachment vs policy-document statement analysis); FS-22 fills a detection gap BR-01 does not cover |
| FS-23 (KB CloudTrail Logging) | BR-06 (CloudTrail Logging) | BR-06 verifies CloudTrail is logging Bedrock API calls generally. FS-23 specifically requires an advanced event selector for `AWS::Bedrock::KnowledgeBase` to capture `Retrieve`/`RetrieveAndGenerate` data events (NOT logged by default). | **Extend BR-06** — add FS-23's data-event-selector requirement as a refinement of the same CloudTrail check |
| FS-25 (OpenSearch Serverless Encryption) | BR-09 (Knowledge Base Encryption) | Different AWS resources: BR-09 checks the Bedrock KB's `kmsKeyArn`; FS-25 checks the underlying AOSS collection's encryption policy (`aoss:ListSecurityPolicies(type=encryption)`). A KB can be CMK-encrypted while its vector store is not. | **Keep separate** — different AWS resources with independent encryption configurations; both needed for defense-in-depth |
| FS-26 (KB VPC Access) | BR-02 (VPC Endpoint Configuration) | BR-02 checks Bedrock VPC endpoints exist. FS-26 checks the AOSS collection's network policy for `AllowFromPublic=true` (whether the vector store itself is internet-reachable). | **Keep separate** — orthogonal controls: Bedrock VPC endpoint vs vector-store network policy |
| FS-27 (Automated Reasoning / Contextual Grounding) | BR-05 (Guardrail Configuration) | BR-05 verifies a guardrail exists and is enforced. FS-27 checks for `automatedReasoningPolicy` or `contextualGroundingPolicy` with specific threshold (≥ 0.7). | **Keep separate** — policy-level guardrail content BR-05 does not evaluate |
| FS-28 (Financial Denied Topics) | BR-05 | BR-05 is existence; FS-28 inspects `topicPolicy.topics` for FinServ-specific denied topics (investment advice, tax advice, guaranteed returns). | **Keep separate** — FinServ denied-topic content is a regulatory-specific requirement not representable as a generic extension |
| FS-36 (Guardrail Content Filters) | BR-05 | FS-36 inspects `contentPolicy.filters` for HATE/VIOLENCE/SEXUAL/INSULTS/MISCONDUCT/PROMPT_ATTACK with strength ≥ MEDIUM. | **Keep separate** — policy-level detection BR-05 does not cover |
| FS-38 (Word Filters and Allowlists) | BR-05 | FS-38 inspects `wordPolicy.words` and `managedWordLists` for FinServ business-term allowlist guidance. | **Keep separate** — advisory business-term allowlist has no upstream equivalent |
| FS-45 (Guardrail PII Filters) | BR-05 | FS-45 inspects `sensitiveInformationPolicy.piiEntities` for 12 specific PII types critical to FinServ (SSN, bank account, SWIFT code, etc.) with `inputAction=BLOCK`/`outputAction=ANONYMIZE`. | **Keep separate** — FinServ-specific PII entity list is a distinct regulatory requirement |
| FS-47 (Grounding Threshold) | BR-05 | FS-47 checks `contextualGroundingPolicy.filters` for `GROUNDING` filter with threshold ≥ 0.7. | **Keep separate** — threshold-value check BR-05 does not perform |
| FS-50 (Relevance Grounding Filters) | BR-05 | Same as FS-47 but for `RELEVANCE` filter type. | **Keep separate** — distinct filter type |
| FS-51 (Prompt Attack Filters) | BR-05 | FS-51 checks `PROMPT_ATTACK` filter in Standard tier with input-tagging requirement and `inputStrength=HIGH`. | **Keep separate** — Standard-tier cross-region-inference opt-in and input-tagging nuance warrant standalone guidance |
| FS-59 (Guardrail Topic Allowlist) | BR-05 | FS-59 checks `topicPolicy.topics` exist to block off-topic conversations (politics, entertainment, medical advice). | **Keep separate** — off-topic content restrictions are distinct from FS-28's regulated-advice restrictions; different PDF section (§1.2.2 vs §1.2.1) |
| FS-64 (Guardrail Trace Logging) | BR-04 (Model Invocation Logging) | BR-04 verifies invocation logging is enabled. FS-64 additionally verifies the log output captures `guardrailTrace` with `action`/`inputAssessments`/`outputAssessments` and adds NYDFS/SR 11-7 retention guidance. | **Extend BR-04** — add guardrail-trace verification as a refinement of the same invocation-logging check; retention guidance can be a remediation note |

### Summary of consolidation recommendations

- **Extend upstream (5 FS checks merged into 5 upstream checks):** FS-17 → SM-07; FS-18 → SM-23; FS-19 → SM-22; FS-23 → BR-06; FS-64 → BR-04. These checks are replaced by upstream-extension notes in Parts 1 and 3 and are removed from `finserv_assessments/app.py`.
- **Keep separate (64 FS checks):** All other FS checks ship as standalone entries. This includes FS-20, FS-22, FS-25, FS-26, FS-39, FS-41, all Guardrail-policy-level checks (FS-27, FS-28, FS-36, FS-38, FS-45, FS-47, FS-50, FS-51, FS-59), and all FS checks that have no upstream overlap at all.

After consolidation the combined framework contains **52 upstream + 64 FS = 116 distinct checks** (down from 52 + 69 = 121 before merging). The consolidation reduces duplication without losing FinServ-specific regulatory depth.


---

## Compliance Framework Mapping

> **Disclaimer:** The mappings below are **preliminary and illustrative**, provided by the
> authors of this assessment to help FSI teams start conversations with their MRM/compliance
> colleagues. They are **not** authoritative AWS compliance guidance and they have **not** been
> reviewed by AWS Security Assurance Services, external auditors, or the regulators whose
> frameworks are named. Each firm should have its own MRM, Legal, and Compliance teams
> validate these mappings against the firm's specific interpretation of each framework before
> relying on them as audit evidence.

Each FS check maps to one or more FinServ regulatory frameworks (preliminary mapping):

| Framework | Description | Relevant Checks |
|-----------|-------------|-----------------|
| SR 11-7 | Federal Reserve Model Risk Management Guidance | FS-07, FS-10, FS-12 to FS-16, FS-20, FS-21, FS-27 to FS-33, FS-34, FS-39 to FS-42, FS-66, FS-67 |
| FFIEC CAT | Cybersecurity Assessment Tool | All FS checks |
| NYDFS 500 | NY Cybersecurity Regulation | FS-22, FS-43 to FS-46, FS-51 to FS-54, FS-66 |
| PCI-DSS | Payment Card Industry Data Security Standard | FS-22, FS-25, FS-26, FS-43 to FS-46, FS-53, FS-56, FS-67, FS-68 |
| DORA | EU Digital Operational Resilience Act | FS-01 to FS-06, FS-08, FS-11, FS-54, FS-65, FS-68 |
| MAS TRM 9 | Monetary Authority of Singapore Technology Risk Management | FS-07 to FS-11, FS-15, FS-27 to FS-30, FS-32, FS-37, FS-39 to FS-42, FS-66, FS-67 |
| ISO 27001 | Information Security Management | FS-13, FS-14, FS-16, FS-21, FS-33, FS-46, FS-52, FS-63, FS-65 |
| ECOA/Fair Housing | Equal Credit Opportunity Act (US) | FS-39 to FS-42 (advisory — applicability depends on whether the model is used for ECOA-covered credit decisions; confirm with your compliance team) |
| OWASP LLM Top 10 | OWASP LLM Application Security | FS-51 to FS-58, FS-68, FS-69 |

> **FS-34 note:** FS-34 (TPRM for FM Providers) is listed above under SR 11-7. Although the
> check appears in the Misinformation section of Part 2 for numbering continuity, its
> primary PDF source is §1.2.12 Supply Chain, which is the lens MRM and TPRM teams will
> evaluate it through.
