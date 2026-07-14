# FinServ GenAI Risk Checks (FS-01 to FS-69)

This document is the complete reference for the Financial Services (FS-XX) GenAI security
checks derived from the [AWS User Guide to Governance, Risk, and Compliance for Responsible AI
Adoption](https://aws.amazon.com/blogs/security/introducing-the-updated-aws-user-guide-to-governance-risk-and-compliance-for-responsible-ai-adoption/)
(referred to throughout as "the Responsible AI GRC guide"). It combines the shared reference material
(severity rubric, guide traceability, upstream-overlap table, compliance mapping) with the full
set of check definitions, organised into three parts:

- **Part 1 — Infrastructure & Resource Controls (FS-01 to FS-26):** unbounded consumption,
  excessive agency, supply chain, training-data poisoning, vector & embedding weaknesses.
- **Part 2 — Guardrails & Content Safety (FS-27 to FS-46):** non-compliant output,
  misinformation, abusive/harmful output, biased output, sensitive information disclosure.
- **Part 3 — Application-Layer Controls & Material Gaps (FS-47 to FS-69):** hallucination,
  prompt injection, improper output handling, off-topic output, out-of-date training data,
  cross-category gap checks.

Of the 69 FS numbers, **64 ship as standalone checks**; 5 (FS-17, FS-18, FS-19, FS-23, FS-64)
are merged into upstream SM/BR checks and appear here as upstream-extension notes. See
[Relationship to upstream SM/BR/AC checks](#relationship-to-upstream-smbrac-checks) for the
consolidation table.

Each check includes how it is **detected** (the AWS API calls or configuration inspected) and
how a failure is **remediated** (the specific AWS actions to take). Severities follow a
documented Likelihood × Impact methodology — see the
[FinServ Severity Methodology](./SECURITY_CHECKS_FINSERV_SEVERITY_METHODOLOGY.md), with
authoritative per-finding assignments in the
[FinServ Severity Register](./SECURITY_CHECKS_FINSERV_SEVERITY_REGISTER.md).

## Table of Contents

**Shared reference**

- [About the source](#about-the-source)
- [Guide traceability](#guide-traceability)
- [Severity rubric](#severity-rubric)
- [Validation note](#validation-note)
- [Contribution workflow](#contribution-workflow)
- [Relationship to upstream SM/BR/AC checks](#relationship-to-upstream-smbrac-checks)
- [Compliance Framework Mapping](#compliance-framework-mapping)

**Checks**

- [Part 1 — Infrastructure & Resource Controls (FS-01 to FS-26)](#part-1--infrastructure--resource-controls-fs-01-to-fs-26)
- [Part 2 — Guardrails & Content Safety (FS-27 to FS-46)](#part-2--guardrails--content-safety-fs-27-to-fs-46)
- [Part 3 — Application-Layer Controls & Material Gaps (FS-47 to FS-69)](#part-3--application-layer-controls--material-gaps-fs-47-to-fs-69)

---

## About the source

The 69 FS checks are derived from the [AWS User Guide to Governance, Risk, and Compliance for
Responsible AI Adoption](https://aws.amazon.com/blogs/security/introducing-the-updated-aws-user-guide-to-governance-risk-and-compliance-for-responsible-ai-adoption/)
(referred to throughout as "the Responsible AI GRC guide").

Each check includes how it is **detected** (the AWS API calls or configuration inspected)
and how a failure is **remediated** (the specific AWS actions to take).

## Guide traceability

The Responsible AI GRC guide organizes AI-specific risks into **15 categories** (§1.2.1 through
§1.2.15). Every check below is tagged with one of:

- **[Guide §x.y.z]** — mitigation is explicitly listed in that guide section's "Mitigations or controls"
  table or "Practical guidance" callout.
- **[Guide §x.y.z, extension]** — mitigation is consistent with the guide's risk description but is
  not verbatim in the guide; included because it is a widely-accepted AWS best practice for the
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
Responsible AI GRC guide, current AWS documentation, API references, and AWS announcements as
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

The FS checks are contributed via a pull request from a personal GitHub fork of
`aws-samples/sample-aiml-security-assessment`. For the contribution process — feature-request
GitHub issue, fork + feature branch, Conventional Commits, PR, and reviewer assignment — see
[`CONTRIBUTING.md`](../CONTRIBUTING.md) and the [Developer Guide](./DEVELOPER_GUIDE.md).

Key quality gates before opening the PR:

1. `ruff check` and `ruff format --check` pass on `functions/security/finserv_assessments/`.
2. `cfn-lint` and `sam validate --lint` pass on the SAM templates.
3. [ASH v3](https://awslabs.github.io/automated-security-helper/) scan
   (`ash --source-dir . --fail-on-findings --config-overrides
   'global_settings.severity_threshold=MEDIUM'`) reports zero Critical / High findings,
   or suppressions are documented in the ASH configuration used for the scan.
4. Amazon Code Defender (`git defender scan`) reports no secrets in the staged diff.

Because `aws-samples` is an OSPO-managed organization, pushes to your personal fork of
`aws-samples/*` are auto-allowed by Code Defender — a Git Defender exception ticket is
**not expected** for this contribution.

## Relationship to upstream SM/BR/AC checks

The upstream [sample-aiml-security-assessment](https://github.com/aws-samples/sample-aiml-security-assessment)
framework already provides 70 core security checks (SM-01 to SM-25, BR-01 to BR-32, AC-01 to AC-13) and 27 always-on Agentic AI Security checks (AG-01 to AG-27).
The 69 FS checks in this document are **additive**: they enhance the upstream with FinServ-specific
detection and remediation guidance drawn from the Responsible AI GRC guide. A few FS
checks overlap with upstream checks — in those cases, the FS check adds FinServ-specific depth
(e.g., protected-attribute facets, regulatory cadence requirements, denied-topic content for
financial advice). The table below surfaces each overlap with a systematic recommendation based
on five factors: (1) whether the detection target is the same AWS resource/configuration, (2)
whether the FS check adds FinServ-specific regulatory specificity, (3) severity differentiation,
(4) whether a customer would remediate them differently, and (5) guide-traceability value.

**Recommendation values:**

- **Extend upstream** — merge FS detection/remediation detail into the upstream check; do not ship FS as a standalone entry in the final report. Best when both checks target the same resource and the FS content is an enhancement.
- **Keep separate** — ship as a standalone FS check alongside the upstream check. Best when the FS check targets a different AWS resource, has materially different severity, or encodes a FinServ-specific regulatory requirement that would be diluted by merging.

| FS check | Upstream check | Overlap analysis | Recommendation |
|---|---|---|---|
| FS-17 (Model Monitor Data Quality) | SM-07 (Model Monitor) | Same resource (`sagemaker:ListMonitoringSchedules`); FS-17 adds training-data-drift-specific guidance, exact CloudWatch namespace (`/aws/sagemaker/Endpoints/data-metric`), and `emit_metrics` requirement. | **Extend SM-07** — add FS-17's detection detail (namespace, `emit_metrics`) as a refinement of the existing check |
| FS-18 (Model Drift Detection) | SM-23 (Model Drift Detection) | Same name, same resource, same detection logic (`MonitoringType=ModelQuality`). FS-18 adds Guide §1.2.14 low-entropy classification monitoring as an early-warning poisoning indicator. | **Extend SM-23** — add low-entropy monitoring as a new remediation step on SM-23; do not ship FS-18 separately |
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
| FS-59 (Guardrail Topic Allowlist) | BR-05 | FS-59 checks `topicPolicy.topics` exist to block off-topic conversations (politics, entertainment, medical advice). | **Keep separate** — off-topic content restrictions are distinct from FS-28's regulated-advice restrictions; different guide section (§1.2.2 vs §1.2.1) |
| FS-64 (Guardrail Trace Logging) | BR-04 (Model Invocation Logging) | BR-04 verifies invocation logging is enabled. FS-64 additionally verifies the log output captures `guardrailTrace` with `action`/`inputAssessments`/`outputAssessments` and adds NYDFS/SR 11-7 retention guidance. | **Extend BR-04** — add guardrail-trace verification as a refinement of the same invocation-logging check; retention guidance can be a remediation note |

### Summary of consolidation recommendations

- **Extend upstream (5 FS checks merged into 5 upstream checks):** FS-17 → SM-07; FS-18 → SM-23; FS-19 → SM-22; FS-23 → BR-06; FS-64 → BR-04. These checks are replaced by upstream-extension notes in Parts 1 and 3 and are removed from `finserv_assessments/app.py`.
- **Keep separate (64 FS checks):** All other FS checks ship as standalone entries. This includes FS-20, FS-22, FS-25, FS-26, FS-39, FS-41, all Guardrail-policy-level checks (FS-27, FS-28, FS-36, FS-38, FS-45, FS-47, FS-50, FS-51, FS-59), and all FS checks that have no upstream overlap at all.

After consolidation the combined framework contains **72 upstream + 27 AG + 64 FS = 163 distinct checks** (down from 70 + 27 AG + 69 FS = 166 before merging FinServ overlaps; the upstream count increased from 70 to 72 when SM-01/SM-03 were split into notebook-scoped and repo-specific checks in a later PR-0 correctness pass). The consolidation reduces duplication without losing FinServ-specific regulatory depth.


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
| SR 11-7 | Federal Reserve Model Risk Management Guidance | FS-03, FS-04, FS-06 to FS-10, FS-12 to FS-15, FS-20, FS-21, FS-27 to FS-42, FS-47 to FS-50, FS-59 to FS-63, FS-66, FS-67 |
| FFIEC CAT | Cybersecurity Assessment Tool | All FS checks except FS-08, FS-56, FS-66 |
| NYDFS 500 | NY Cybersecurity Regulation | FS-22, FS-24 to FS-26, FS-28 to FS-30, FS-43 to FS-46, FS-51 to FS-54, FS-56, FS-57, FS-66, FS-69 |
| PCI-DSS | Payment Card Industry Data Security Standard | FS-02, FS-22, FS-24 to FS-26, FS-43 to FS-46, FS-53, FS-56, FS-66 to FS-68 |
| DORA | EU Digital Operational Resilience Act | FS-01, FS-02, FS-05, FS-11, FS-16, FS-65, FS-68 |
| MAS TRM 9 | Monetary Authority of Singapore Technology Risk Management | FS-08, FS-10, FS-15, FS-27 to FS-29, FS-32, FS-37, FS-49, FS-62, FS-66, FS-67 |
| ISO 27001 | Information Security Management | FS-12 to FS-14, FS-16, FS-21, FS-33, FS-46, FS-52, FS-63, FS-65 |
| ECOA/Fair Housing | Equal Credit Opportunity Act (US) | FS-39, FS-40 (advisory — applicability depends on whether the model is used for ECOA-covered credit decisions; confirm with your compliance team) |
| OWASP LLM Top 10 | OWASP LLM Application Security | FS-51 to FS-58, FS-68, FS-69 |

> **FS-34 note:** FS-34 (TPRM for FM Providers) is listed above under SR 11-7. Although the
> check appears in the Misinformation section of Part 2 for numbering continuity, its
> primary guide source is §1.2.12 Supply Chain, which is the lens MRM and TPRM teams will
> evaluate it through.

---

## Part 1 — Infrastructure & Resource Controls (FS-01 to FS-26)

> **Guide risk categories:** Unbounded Consumption (FS-01..06, §1.2.11), Excessive Agency (FS-07..11, §1.2.9), Supply Chain Vulnerabilities (FS-12..16, §1.2.12), Training Data & Model Poisoning (FS-17..21, §1.2.14), Vector & Embedding Weaknesses (FS-22..26, §1.2.15). FS-17, FS-18, FS-19, and FS-23 are merged into upstream checks — see the extension notes in each section.

### Unbounded Consumption (FS-01 to FS-06)

> **Guide source:** §1.2.11 Unbounded consumption. Guide-listed mitigations: (a) AWS WAF and Shield
> Advanced for LLM APIs; (b) maximum input length limits; (c) rate limits/quotas on APIs
> accessing LLMs; (d) cost-and-usage tracking for generative AI. Practical guidance in the guide
> also calls out `max_tokens` optimisation and CloudWatch metrics for token usage.

#### FS-01 — WAF and Shield Protection

| Field | Detail |
|-------|--------|
| Severity | Medium (WAF) / Low (Shield Advanced) |
| Guide ref | [Guide §1.2.11] — "Protect your LLM APIs and Amazon Bedrock-hosted LLMs by using AWS WAF and AWS Shield Advanced." Also covers: "To protect your API endpoints, set maximum length limits for input requests when you use large language models (LLMs) directly or through Amazon Bedrock." |
| Description | Verifies AWS WAF Web ACLs and Shield Advanced protect GenAI API endpoints, and verifies the Web ACL enforces both rate-based limits and body-size (input-length) constraints. |
| Detection | Calls `shield:DescribeSubscription` to check Shield Advanced is active. Calls `wafv2:ListWebACLs(Scope=REGIONAL)` in each region where GenAI API endpoints run to verify at least one regional Web ACL exists (covers API Gateway, ALB, AppSync). **Additionally** calls `wafv2:ListWebACLs(Scope=CLOUDFRONT)` in `us-east-1` to detect Web ACLs protecting CloudFront distributions fronting GenAI workloads — CLOUDFRONT-scope Web ACLs must be created and queried in `us-east-1` per the [WAF resources documentation](https://docs.aws.amazon.com/waf/latest/developerguide/how-aws-waf-works-resources.html). For each Web ACL found, calls `wafv2:GetWebACL` and inspects the `Rules` array for: (a) at least one `RateBasedStatement` (rate limiting) and (b) at least one `SizeConstraintStatement` with `FieldToMatch=Body` or `FieldToMatch=JsonBody` (input-size limit — this implements Guide §1.2.11 mitigation "set maximum length limits for input requests when you use large language models (LLMs) directly or through Amazon Bedrock"). Flags accounts with no Web ACL in either scope, a Web ACL with no rate-based rule, a Web ACL with no body size-constraint rule, or where Shield Advanced is inactive. |
| Remediation | 1. Subscribe to AWS Shield Advanced via the Shield console. 2. Create a WAF Web ACL with both (a) a rate-based rule (e.g., 1 000 req / 5 min per IP) and (b) a `SizeConstraintStatement` that blocks requests where `FieldToMatch=Body` (or `JsonBody` for JSON APIs) exceeds your LLM's expected maximum input size — for example, `ComparisonOperator=GT, Size=100000` (100 KB) — use `Scope=REGIONAL` for API Gateway/ALB/AppSync resources, or `Scope=CLOUDFRONT` (created in `us-east-1`) for CloudFront distributions fronting Bedrock. The body size-constraint rule directly implements the Guide §1.2.11 mitigation "set maximum length limits for input requests when you use large language models (LLMs) directly or through Amazon Bedrock" and prevents large-prompt token-exhaustion attacks before they reach Bedrock. 3. Associate the ACL with the fronting resource (API Gateway stage, ALB, or CloudFront distribution). 4. Add AWS Managed Rules (e.g., `AWSManagedRulesCommonRuleSet`, which includes additional size checks). 5. For CloudFront-fronted workloads, register the distribution with Shield Advanced via `shield:CreateProtection` to unlock automatic application-layer DDoS mitigation. 6. For API Gateway REST APIs, also note the service's own payload-size quota: the default is 10 MB per request (see [API Gateway quotas](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-execution-service-limits-table.html)); use a request validator or Lambda authorizer for sub-10 MB limits where WAF size constraints are unsuitable. |
| Reference | [Shield Advanced](https://docs.aws.amazon.com/waf/latest/developerguide/shield-chapter.html), [WAF](https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html), [WAF Size Constraint Rule](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-size-constraint-match.html), [API Gateway Quotas](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-execution-service-limits-table.html) |

#### FS-02 — API Gateway Rate Limiting

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.11] — "protect your API endpoints by implementing rate limits and quotas for APIs that access large language models (LLMs)". |
| Description | Checks API Gateway usage plans enforce throttling on GenAI endpoints. |
| Detection | Calls `apigateway:GetUsagePlans` and inspects each plan's `throttle.rateLimit` and `throttle.burstLimit`. Flags plans where either is zero or absent. |
| Remediation | 1. Create or update usage plans with `rateLimit` and `burstLimit` values appropriate for your traffic. 2. Associate plans with API stages serving Bedrock. 3. Issue per-consumer API keys with individual quotas. |
| Reference | [API Gateway Throttling](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html) |

#### FS-03 — Bedrock Token Quota Review

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.11, extension] — guide practical guidance notes "Bedrock has default quota on model inference based on token usage" and recommends optimising `max_tokens`. Quota review as an operational control is an extension aligned with this guidance. |
| Description | Verifies Bedrock TPM/RPM quotas have been reviewed and set appropriately. |
| Detection | Calls `service-quotas:ListServiceQuotas(ServiceCode=bedrock)` for applied quotas and `ListAWSDefaultServiceQuotas` for defaults, then compares each adjustable quota's `Value` against the default `Value`. Flags accounts where every quota equals the service default (indicating no quota review or increase has been requested). |
| Remediation | 1. Review current quotas in the Service Quotas console. 2. Request increases aligned with expected peak load via `service-quotas:RequestServiceQuotaIncrease`. 3. Implement client-side token counting and pre-flight quota checks. 4. Use Bedrock cross-region inference profiles to distribute load — note that cross-region inference routes requests across destination regions automatically with no additional cost, but requires the invoked model to be available in the destination regions defined in the inference profile. |
| Reference | [Bedrock Quotas](https://docs.aws.amazon.com/bedrock/latest/userguide/quotas.html) |

#### FS-04 — Cost Anomaly Detection

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.11] — "Track, allocate, and manage your costs and usage for generative AI." |
| Description | Checks AWS Cost Anomaly Detection monitors cover Bedrock/SageMaker. |
| Detection | Calls `ce:GetAnomalyMonitors` and inspects each monitor. AWS Cost Anomaly Detection supports exactly two `MonitorType` values per the [AnomalyMonitor API](https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_AnomalyMonitor.html): `DIMENSIONAL` (AWS-managed, where `MonitorDimension` is one of `SERVICE`, `LINKED_ACCOUNT`, `TAG`, or `COST_CATEGORY`) and `CUSTOM` (customer-managed, scoped via `MonitorSpecification` to specific values). For `DIMENSIONAL` monitors, checks `MonitorDimension=SERVICE` (the AWS-managed "AWS services" monitor that automatically covers all services including Bedrock and SageMaker — the recommended default). For `CUSTOM` monitors, inspects `MonitorSpecification` for references to Bedrock or SageMaker. Flags accounts with no monitors, or with only narrowly-scoped monitors that would not detect Bedrock cost anomalies (e.g., `DIMENSIONAL` with `MonitorDimension=LINKED_ACCOUNT` only). |
| Remediation | 1. Create an AWS-managed `DIMENSIONAL` monitor with `MonitorDimension=SERVICE` for comprehensive coverage across all AWS services (the recommended default — in the console this appears as "AWS services" under "Managed by AWS"). For narrower scope, add a `CUSTOM` monitor using `MonitorSpecification` with a `Dimensions` expression scoped to specific service values (e.g., `{"Dimensions": {"Key": "SERVICE", "Values": ["Amazon Bedrock", "Amazon SageMaker"]}}`) — note that for `CUSTOM` monitors you use `MonitorSpecification`, not `MonitorDimension`. 2. Configure alert subscriptions (SNS/email) for anomalies above threshold. 3. Set daily spend budgets with AWS Budgets as a secondary control. 4. Enable Bedrock IAM principal cost allocation: tag IAM users/roles with team or cost-center attributes, activate them as cost allocation tags in the Billing and Cost Management console, and include caller identity data in CUR 2.0 exports for per-user/per-team Bedrock spend attribution. |
| Reference | [Cost Anomaly Detection](https://docs.aws.amazon.com/cost-management/latest/userguide/getting-started-ad.html), [Bedrock IAM Cost Allocation](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/iam-principal-cost-allocation.html) |

#### FS-05 — CloudWatch Token Usage Alarms

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.11] — guide practical guidance cites CloudWatch metrics for token usage; alarms operationalise that guidance. |
| Description | Verifies CloudWatch alarms exist for Bedrock throttling and token metrics. |
| Detection | Paginates `cloudwatch:DescribeAlarms(AlarmTypes=MetricAlarm)` and filters for alarms in the `AWS/Bedrock` namespace or with "bedrock" in the alarm name. Separately counts throttle-specific alarms. |
| Remediation | 1. Create alarms for `AWS/Bedrock InvocationThrottles` (threshold > 0). 2. Create alarms for `AWS/Bedrock EstimatedTPMQuotaUsage` to track approach to token quota limits, and separately on `InputTokenCount` + `OutputTokenCount` (sum via CloudWatch metric math) for absolute token consumption. Note: `TokensProcessed` is not a valid Bedrock metric — the correct runtime metrics are `InputTokenCount`, `OutputTokenCount`, `InvocationThrottles`, `EstimatedTPMQuotaUsage`, `Invocations`, `InvocationLatency`, `TimeToFirstToken`. 3. Publish custom application-level token counters via Embedded Metric Format (EMF) if you need per-tenant or per-feature attribution. 4. Attach SNS actions to all alarms. |
| Reference | [Bedrock CloudWatch Metrics](https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring.html) |

#### FS-06 — AWS Budgets AI/ML Spend

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.11] — "Track, allocate, and manage your costs and usage for generative AI." |
| Description | Checks AWS Budgets are configured with alerts for AI/ML service spend. |
| Detection | Calls `budgets:DescribeBudgets` and inspects each budget's `FilterExpression` (the current field) and `CostFilters` (deprecated but may still be populated on older budgets) for references to "bedrock" or "sagemaker". Note: `CostFilters` is marked deprecated in the AWS Budgets API — new budgets use `FilterExpression` with an `Expression` object; the detection should check both fields to cover both old and new budgets. |
| Remediation | 1. Create cost budgets for Bedrock and SageMaker with 80 %/100 % alert thresholds. 2. Add SNS notifications to on-call channels. 3. Consider budget actions to apply IAM deny policies when thresholds are breached. 4. Enable Bedrock IAM principal cost allocation to attribute inference costs to specific IAM users/roles via Cost Explorer and CUR 2.0 — tag IAM principals with team or cost-center attributes and activate them as cost allocation tags. |
| Reference | [AWS Budgets](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html), [Bedrock IAM Cost Allocation](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/iam-principal-cost-allocation.html) |

### Excessive Agency (FS-07 to FS-11)

> **Guide source:** §1.2.9 Excessive agency. Guide-listed mitigations: (a) Amazon Bedrock AgentCore
> for managing complex tasks; (b) least-privilege permissions on plugins; (c) human-in-the-loop
> output validation; (d) explicit action boundaries in agent configuration (AgentCore Policy);
> (e) audit logging of agent actions with reasoning chain (AgentCore Observability);
> (f) transaction-value thresholds on agent tool calls; (g) monitoring agent call rates with
> alarms (AgentCore Evaluations). Mitigation (e) is covered by the expanded FS-08 check, which
> now verifies both AgentCore Policy Engine and AgentCore Observability are configured.

#### FS-07 — Agent Action Boundaries

| Field | Detail |
|-------|--------|
| Severity | High |
| Guide ref | [Guide §1.2.9] — "grant only the minimum permissions required"; "Define and enforce explicit action boundaries in the agent configuration". |
| Description | Verifies Bedrock agent execution roles have no wildcard sensitive actions (iam:\*, s3:\*, ec2:\*, lambda:\*, \*). |
| Detection | Calls `ListAgents` and `GetAgent` (via the `bedrock-agent` boto3 client; IAM actions are `bedrock:ListAgents` and `bedrock:GetAgent`) to retrieve each agent's `agentResourceRoleArn`. Resolves the role name and inspects attached and inline policy documents from the permissions cache for wildcard Allow statements. |
| Remediation | 1. Replace wildcard actions with the specific actions the agent needs. 2. Apply IAM permission boundaries to agent execution roles. 3. Use resource-level conditions to restrict to specific ARNs. 4. Implement human-in-the-loop approval for high-impact actions. 5. For agents deployed in a VPC, use **AWS Network Firewall** with domain-based filtering to control which external domains agents can reach — this provides a network-layer boundary that limits agent tool access to approved endpoints regardless of IAM permissions. |
| Reference | [Bedrock Agent Permissions](https://docs.aws.amazon.com/bedrock/latest/userguide/agents-permissions.html), [Control Agent Domain Access](https://aws.amazon.com/blogs/machine-learning/control-which-domains-your-ai-agents-can-access/) |

#### FS-08 — AgentCore Policy Engine and Observability

| Field | Detail |
|-------|--------|
| Severity | High |
| Guide ref | [Guide §1.2.9] — "Use Amazon Bedrock AgentCore to manage complex tasks and connect securely"; "Define and enforce explicit action boundaries"; **"Implement audit logging of all actions taken by AI agents, including the reasoning chain that led to each action."** (The audit-logging mitigation's guide reference is "Observe your agent applications on Amazon Bedrock AgentCore Observability.") |
| Description | Checks AgentCore Gateways have a Policy Engine attached to authorize agent-to-tool interactions, verifies AgentCore Runtimes have an inbound authorizer configured, and verifies AgentCore Observability is enabled so agent reasoning chains and tool calls are auditable. |
| Detection | (a) Calls `ListGateways` and `GetGateway` (via the `bedrock-agentcore-control` boto3 client; IAM actions are `bedrock-agentcore:ListGateways` and `bedrock-agentcore:GetGateway`); inspects `policyEngineConfiguration.arn` and `policyEngineConfiguration.mode` (must be `ENFORCE` for production). (b) Calls `ListAgentRuntimes` (IAM action `bedrock-agentcore:ListAgentRuntimes`) and inspects each runtime's `authorizerConfiguration.customJWTAuthorizer` for inbound auth. (c) Verifies **AgentCore Observability** is enabled by (i) checking that CloudWatch Transaction Search is on via `xray:GetTraceSegmentDestination` (destination should be `CloudWatchLogs`) and that the X-Ray → CloudWatch Logs resource policy is in place via `logs:GetResourcePolicy`, and (ii) calling `logs:DescribeDeliveries` / `logs:DescribeDeliverySources` for AgentCore resource sources (runtime, memory, gateway, built-in tools, identity) — flags runtimes/gateways with no log delivery configured. For memory resources, additionally checks that tracing was enabled at memory creation time. Flags gateways without a Policy Engine in `ENFORCE` mode, runtimes without an authorizer, or accounts where Transaction Search is not enabled or no delivery exists for AgentCore resources. |
| Remediation | 1. Configure a Policy Engine: create via `CreatePolicyEngine` (IAM action `bedrock-agentcore:CreatePolicyEngine`), then author Cedar policies using one of three methods: (a) write Cedar directly for fine-grained control via `CreatePolicy` (IAM action `bedrock-agentcore:CreatePolicy`), (b) use the form-based console UI, or (c) generate Cedar from natural language descriptions (natural-language-to-Cedar is a documented capability in the GA announcement; verify the exact IAM action name against the current [AgentCore Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonbedrockagentcore.html) before writing IAM policies for it). Policy in AgentCore went GA on March 3, 2026 in thirteen AWS regions (US East N. Virginia, US East Ohio, US West Oregon, Asia Pacific Mumbai/Seoul/Singapore/Sydney/Tokyo, Europe Frankfurt/Ireland/London/Paris/Stockholm) — verify current regional availability on the [launch announcement](https://aws.amazon.com/about-aws/whats-new/2026/03/policy-amazon-bedrock-agentcore-generally-available/) before audit reliance. 2. Attach the Policy Engine to each Gateway by specifying the Policy Engine ARN in the `policyEngineConfiguration` field during `CreateGateway`, or attach later via `UpdateGateway`. 3. Start in `LOG_ONLY` mode — the policy engine evaluates actions and logs whether they would be allowed or denied without enforcing the decision — then switch to `ENFORCE` mode once confident. 4. Configure a JWT inbound authorizer on each Runtime with discovery URL, allowed audiences, and allowed clients. 5. **Enable AgentCore Observability** so agent reasoning chains are captured (directly addresses the Guide §1.2.9 audit-logging mitigation): (a) one-time enable CloudWatch Transaction Search — console path **CloudWatch → Application Signals (APM) → Transaction search → Enable Transaction Search**, or CLI: `aws xray update-trace-segment-destination --destination CloudWatchLogs` plus a `logs:PutResourcePolicy` granting `xray.amazonaws.com` permission to `logs:PutLogEvents` on `aws/spans:*` and `/aws/application-signals/data:*`; (b) configure log delivery for AgentCore runtime, memory, gateway, built-in tools, and identity resources via `logs:PutDeliverySource` + `logs:PutDeliveryDestination` + `logs:CreateDelivery` (CloudWatch Logs / S3 / Firehose destinations supported; note the write APIs use `Put*` for source and destination but `Create*` for the delivery pairing); (c) enable tracing at memory creation. For traditional Bedrock Agents (non-AgentCore), set `enableTrace=true` on `InvokeAgent` calls to receive the reasoning-chain trace in the response. |
| Reference | [Policy in AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html), [Inbound JWT Authorizer](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/inbound-jwt-authorizer.html), [AgentCore Observability Configuration](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability-configure.html), [Bedrock Agent Trace View](https://docs.aws.amazon.com/bedrock/latest/userguide/trace-view.html) |

#### FS-09 — Agent Transaction Limits

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.9, extension] — Lambda reserved concurrency is not named in the guide, but it directly implements the guide mitigation "Monitor agent call rates and alarm upon exceeding defined thresholds" by capping execution parallelism. |
| Description | Verifies agent Lambda functions have reserved concurrency limits to cap execution parallelism. |
| Detection | Calls `lambda:ListFunctions` and filters for functions with agent-related naming patterns. For each, calls `lambda:GetFunctionConcurrency` and flags functions with no reserved concurrency set. |
| Remediation | 1. Set reserved concurrency on each agent action-group Lambda (e.g., 10–50 depending on expected load). 2. Add CloudWatch alarms for `Throttles` metric on these functions. 3. Consider Step Functions execution limits as an additional control. |
| Reference | [Lambda Reserved Concurrency](https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html) |

#### FS-10 — Human-in-the-Loop Approval

| Field | Detail |
|-------|--------|
| Severity | High |
| Guide ref | [Guide §1.2.9, §1.2.1, §1.2.2, §1.2.3, §1.2.7, §1.2.10] — "For internal AI systems, validate outputs with human review before business use (human-in-the-loop)." HITL is referenced in six separate guide risk sections. |
| Description | Checks Step Functions workflows have human approval steps for high-risk agent actions. |
| Detection | Calls `stepfunctions:ListStateMachines` and filters for agent/GenAI-related names. Retrieves each definition via `stepfunctions:DescribeStateMachine` and parses the ASL JSON for task states with `.waitForTaskToken` or callback patterns indicating human approval gates. |
| Remediation | 1. Add a callback-pattern task state in your Step Functions workflow before any high-risk action (financial transactions, data modifications, external communications). 2. Route the approval token to a human reviewer via SNS/SQS/Slack. 3. Set a `HeartbeatSeconds` timeout so stale approvals expire. 4. Enable **user confirmation on Bedrock Agent action groups** for inline approval — when configured, the agent returns a confirmation prompt in the `returnControl.invocationInputs` field of the `InvokeAgent` response (alongside `invocationType` and a unique `invocationId`); the client displays the prompt, collects confirm/deny, and returns the user's decision via `sessionState.returnControlInvocationResults` (with `confirmationState` on each `apiResult`/`functionResult`) in the next `InvokeAgent` request (there is no standalone `GetUserConfirmation` API). |
| Reference | [Step Functions Callback Pattern](https://docs.aws.amazon.com/step-functions/latest/dg/connect-to-resource.html#connect-wait-token), [Bedrock Agent User Confirmation](https://docs.aws.amazon.com/bedrock/latest/userguide/agents-userconfirmation.html) |

#### FS-11 — Agent Rate Alarms

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.9] — "Monitor agent call rates and alarm upon exceeding defined thresholds." |
| Description | Verifies CloudWatch alarms exist for agent invocation rates. |
| Detection | Paginates `cloudwatch:DescribeAlarms` and filters for alarms referencing "agent" in the alarm name or targeting `AWS/Bedrock/Agents` agent-related metrics (such as `InvocationCount` or `InvocationThrottles` with the `Operation, AgentAliasArn, ModelId` dimension combination). |
| Remediation | 1. Create CloudWatch alarms on the `AWS/Bedrock/Agents` namespace for `InvocationCount` and `InvocationThrottles`. Per AWS docs, the available dimensions are: `Operation` alone; `Operation, ModelId`; or `Operation, AgentAliasArn, ModelId` — use the `Operation, AgentAliasArn, ModelId` combination to scope alarms to a specific agent alias. 2. Set thresholds based on expected peak agent call rates, established via CloudWatch metric math on historical `InvocationCount` data. 3. Attach SNS actions for on-call notification. 4. Use **AgentCore Evaluations** (GA March 2026, available in 9 AWS regions — verify current regional availability on the [GA announcement](https://aws.amazon.com/about-aws/whats-new/2026/03/agentcore-evaluations-generally-available/)) to monitor agent *quality* alongside rate-based alarms: online evaluation continuously scores production traffic against 13 built-in evaluators (response quality, safety, task completion, tool usage), and on-demand evaluation supports regression testing. |
| Reference | [Bedrock Agents CloudWatch Metrics](https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-agents-cw-metrics.html), [AgentCore Evaluation Types](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/evaluations-types.html) |

### Supply Chain Vulnerabilities (FS-12 to FS-16)

> **Guide source:** §1.2.12 Supply chain vulnerabilities. Guide-listed mitigations:
> (a) control access to serverless and marketplace models (IAM policies, SCPs);
> (b) model onboarding process — EULA review, procurement, security/compliance review,
> MRM assessment, documentation, stakeholder approvals;
> (c) update TPRM to continuously monitor model providers — vendor security advisories,
> deprecation notices, T&C changes;
> (d) maintain a model inventory recording provenance, version, license terms, and risk
> assessment status;
> (e) use Bedrock Evaluations against attack test cases (practical guidance);
> (f) allow-list approved models via SCP (practical guidance).

#### FS-12 — SCP Model Access Restrictions

| Field | Detail |
|-------|--------|
| Severity | High |
| Guide ref | [Guide §1.2.12 — Practical guidance] — "Implement an allow-list of models using a Service Control Policy (SCP) for your AWS organization." |
| Description | Checks SCPs restrict Bedrock model access to approved models only. |
| Detection | Calls `organizations:ListPolicies(Filter=SERVICE_CONTROL_POLICY)` and inspects each SCP document for Deny statements on `bedrock:InvokeModel*` with `StringNotEquals` conditions on `bedrock:ModelId`. Flags if no SCP restricts model access. |
| Remediation | 1. Create an SCP that denies `bedrock:InvokeModel*` except for an explicit allowlist of approved model ARNs. 2. Attach the SCP to the OU containing GenAI workload accounts. 3. For multi-account guardrail enforcement, use the Bedrock cross-account safeguards feature (GA April 3, 2026, available in all AWS commercial and GovCloud regions where Bedrock Guardrails is supported): enable the Amazon Bedrock policy type in AWS Organizations, create a guardrail in the management account, create a versioned guardrail, optionally attach a resource-based policy granting `bedrock:ApplyGuardrail` to member accounts for cross-account access, then create and attach an AWS Organizations Bedrock policy referencing the guardrail ARN and version to the target OUs or accounts. This automatically enforces content filters, denied topics, word filters, sensitive information filters, and contextual grounding checks across all member accounts for every model invocation — no application code changes required. **Important limitation:** Automated Reasoning checks are **not supported** with cross-account safeguards — omit Automated Reasoning policies from any guardrail used for org-level enforcement. If you rely on AR (see FS-27), you must configure AR guardrails separately at the application or account level. 4. Test with both allowed and denied model IDs. |
| Reference | [Managing Access in AWS Organizations](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html), [Bedrock Cross-Account Guardrails](https://aws.amazon.com/blogs/aws/amazon-bedrock-guardrails-supports-cross-account-safeguards-with-centralized-control-and-management/) |

#### FS-13 — Model Inventory Tagging

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.12] — "Maintain a model inventory that records the provenance, version, license terms, and risk assessment status of all models in use across the organization." |
| Description | Verifies models are tagged with provenance metadata (source, version, approval-date). |
| Detection | Calls `bedrock:ListFoundationModels` and `bedrock:ListCustomModels`. For custom models, calls `bedrock:ListTagsForResource` and checks for required tag keys: `model-source`, `model-version`, `approval-date`, `risk-tier`. |
| Remediation | 1. Define a mandatory tagging policy for all AI/ML models. 2. Tag each custom model with provenance metadata. 3. Create an AWS Config rule (`required-tags`) to enforce the tagging policy. 4. For foundation models, maintain an external inventory spreadsheet or CMDB entry. |
| Reference | [Bedrock Tagging](https://docs.aws.amazon.com/bedrock/latest/userguide/tagging.html) |

#### FS-14 — Model Onboarding Governance

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.12] — "To onboard a model, follow these steps: Review EULA, Complete procurement, Follow security and compliance procedures, Assess MRM requirements, Document findings, Get necessary approvals from stakeholders." |
| Description | Checks AWS Config rules enforce model onboarding governance (EULA review, MRM assessment, stakeholder approval). |
| Detection | Calls `config:DescribeConfigRules` and searches for rules targeting `AWS::Bedrock::*` resources or custom rules with "model" or "onboarding" in the name. |
| Remediation | 1. Create a custom AWS Config rule that checks new Bedrock custom models have required tags (approval-date, risk-tier, eula-reviewed). 2. Document the model onboarding process: EULA review → procurement → security/compliance review → MRM assessment → stakeholder sign-off. 3. Store approval artifacts in a versioned S3 bucket. |
| Reference | [AWS Config Custom Rules](https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_develop-rules.html) |

#### FS-15 — Adversarial Model Evaluation

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.12 — Practical guidance] — "Amazon Bedrock Evaluations can help to evaluate models against specific types of attacks by automating your test cases, scoring, reporting and to enable comparison of different models." |
| Description | Verifies Bedrock evaluation jobs include adversarial test datasets. |
| Detection | Calls `bedrock:ListEvaluationJobs` and inspects each job's configuration for evaluation datasets. Flags if no evaluation jobs exist or if none reference adversarial/red-team test data. |
| Remediation | 1. Create a Bedrock model evaluation job with adversarial prompt datasets (prompt injection attempts, jailbreak sequences, harmful content probes). 2. Include both automated metrics and human evaluation. 3. Run evaluations before production deployment and after model updates. 4. Store results for audit. |
| Reference | [Bedrock Model Evaluation](https://docs.aws.amazon.com/bedrock/latest/userguide/evaluation.html) |

#### FS-16 — ECR Image Scanning

| Field | Detail |
|-------|--------|
| Severity | High |
| Guide ref | [Guide §1.2.12, extension] — ECR image scanning is not named in the guide, but directly mitigates the guide's listed risk "Third-party package vulnerabilities" in LLM supply chains. Included for completeness of the supply-chain risk category. |
| Description | Checks ECR repositories have scan-on-push enabled for supply chain security of model containers. |
| Detection | Calls `ecr:DescribeRepositories` and for each repository checks `imageScanningConfiguration.scanOnPush`. Also checks whether Amazon Inspector ECR scanning is enabled via `inspector2:BatchGetAccountStatus`. Flags repositories relying solely on basic scanning or with no scanning configured. |
| Remediation | 1. Enable **enhanced scanning** via Amazon Inspector (the current best practice) — Inspector provides continuous vulnerability monitoring, re-scanning images automatically when new CVEs are published, and covers both OS and programming language package vulnerabilities. This requires two steps: (a) enable Inspector ECR scanning at the account level — `aws inspector2 enable --account-ids <account-id> --resource-types ECR`; (b) set the ECR registry scanning configuration to enhanced mode — `aws ecr put-registry-scanning-configuration --scan-type ENHANCED --rules '[{"scanFrequency":"CONTINUOUS_SCAN","repositoryFilters":[{"filter":"*","filterType":"WILDCARD"}]}]'`. **Important limitations:** (i) When enhanced scanning is first enabled, Amazon Inspector only discovers images pushed within the **last 14 days** — older images receive `SCAN_ELIGIBILITY_EXPIRED` status and must be re-pushed to be scanned. (ii) After the initial scan, scan duration is controlled by the ECR re-scan duration setting in the Amazon Inspector console (defaults to `LIFETIME`); if you shorten this duration, images whose last scan exceeds the new window also move to `SCAN_ELIGIBILITY_EXPIRED`. (iii) Enhanced scanning incurs Amazon Inspector charges (no additional ECR cost). (iv) Repositories not matching a scan filter will have `Off` scan frequency and won't be scanned. 2. If enhanced scanning is not available in your region, enable basic scan-on-push as a fallback: `aws ecr put-image-scanning-configuration --repository-name <name> --image-scanning-configuration scanOnPush=true`. 3. Create EventBridge rules to alert on CRITICAL/HIGH findings from Inspector. 4. Integrate findings into your vulnerability management workflow. |
| Reference | [ECR Enhanced Scanning](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning-enhanced.html), [Amazon Inspector ECR Scanning](https://docs.aws.amazon.com/inspector/latest/user/scanning-ecr.html) |

### Training Data & Model Poisoning (FS-17 to FS-21)

> **Guide source:** §1.2.14 Training data and model poisoning. Guide-listed mitigations:
> (a) protect training datasets via data protection best practices;
> (b) use trusted data sources with audit controls tracking changes (who/when);
> (c) monitor training data for pattern/distribution changes (data drift);
> (d) compare retrained model performance against baseline before production;
> (e) rollback plan using versioned training data and models (Feature Store);
> (f) monitor low-entropy classification with thresholds and alerts;
> (g) AI Service Cards for evaluating third-party model testing procedures.

#### FS-17 — Model Monitor Data Quality → *Merged into upstream SM-07*

> **Upstream extension note (do not ship as a standalone check):** The detection and remediation
> content from FS-17 should be added as a refinement of the existing **SM-07 (Model Monitor)**
> check in the upstream `aws-samples/sample-aiml-security-assessment` repo.
>
> **What to add to SM-07:**
>
> - Filter `ListMonitoringSchedules` results for `MonitoringType=DataQuality` (not just any schedule). Note the format difference: `ListMonitoringSchedules`/`MonitoringScheduleSummary` returns `MonitoringType` in PascalCase (`DataQuality`, `ModelQuality`, `ModelBias`, `ModelExplainability`); `DescribeMonitoringSchedule` returns the same type in SCREAMING_SNAKE_CASE (`DATA_QUALITY`, `MODEL_QUALITY`, `MODEL_BIAS`, `MODEL_EXPLAINABILITY`) — the detection should normalise both forms.
> - Require `emit_metrics` to be enabled on the monitoring schedule.
> - Verify CloudWatch alarms exist on the `feature_baseline_drift_<feature_name>` metrics published
>   to namespace `/aws/sagemaker/Endpoints/data-metric` (real-time endpoints, dimensions
>   `EndpointName` + `ScheduleName`) or `/aws/sagemaker/ModelMonitoring/data-metric` (batch
>   transform, dimension `MonitoringSchedule`).
> - Guide traceability: [Guide §1.2.14] — "Monitor your training data for pattern and distribution
>   changes to detect data drift"; "Amazon SageMaker Model Monitor – Data quality."
>
> **Reference:** [SageMaker Model Monitor Data Quality](https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-data-quality.html)

#### FS-18 — Model Drift Detection → *Merged into upstream SM-23*

> **Upstream extension note (do not ship as a standalone check):** The detection and remediation
> content from FS-18 should be added as a refinement of the existing **SM-23 (Model Drift
> Detection)** check in the upstream repo.
>
> **What to add to SM-23:**
> - Filter `ListMonitoringSchedules` results for `MonitoringType=ModelQuality`.
> - Add a new remediation step for **low-entropy classification monitoring** (Guide §1.2.14
>   mitigation): publish custom CloudWatch metrics tracking prediction confidence distributions,
>   set threshold boundaries for unexpected low-confidence/high-confidence clusters, and alert
>   when the retrained model produces unexpected classification patterns — this can indicate
>   training data poisoning before accuracy metrics degrade.
> - Guide traceability: [Guide §1.2.14] — "Before deploying to production, compare your retrained
>   model's performance against previous iterations using historical test data as a baseline."
>
> **Reference:** [SageMaker Model Monitor Model Quality](https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-model-quality.html)

#### FS-19 — Model Registry Approval → *Merged into upstream SM-22*

> **Upstream extension note (do not ship as a standalone check):** The detection and remediation
> content from FS-19 should be added as a refinement of the existing **SM-22 (Model Approval
> Workflow)** check in the upstream repo.
>
> **What to add to SM-22:**
> - Explicitly check that `ModelApprovalStatus=PendingManualApproval` is the default for new
>   model package versions (not `Approved`).
> - Flag any model package group where the latest version has `ModelApprovalStatus=Approved`
>   without evidence of a manual approval step (i.e., auto-approved at creation time).
> - Guide traceability: [Guide §1.2.14] — cites "Amazon SageMaker AI – Model Registration and
>   Deployment with Model Registry" as a reference for staged deployment with rollback.
>
> **Reference:** [SageMaker Model Registry](https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry.html)

#### FS-20 — Feature Store Rollback

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.14] — "Create a rollback plan by using versioned training data and models. This ensures that you can revert to a stable, working model if failures occur." References "Amazon SageMaker AI Feature Store". |
| Description | Checks SageMaker Feature Store has offline store for rollback capability. |
| Detection | Calls `sagemaker:ListFeatureGroups` to enumerate all groups, then `sagemaker:DescribeFeatureGroup` for each to inspect `OfflineStoreConfig`. Flags feature groups where `OfflineStoreConfig` is absent (online-only groups with no offline store for rollback). |
| Remediation | 1. Enable the offline store on each feature group: specify an S3 URI and data catalog in `OfflineStoreConfig`. 2. The offline store provides a versioned, immutable history of feature values for point-in-time rollback. 3. Test rollback by querying the offline store with a historical timestamp. |
| Reference | [SageMaker Feature Store](https://docs.aws.amazon.com/sagemaker/latest/dg/feature-store.html) |

#### FS-21 — Training Data S3 Versioning and Audit Trail

| Field | Detail |
|-------|--------|
| Severity | High |
| Guide ref | [Guide §1.2.14] — "Use trusted data sources for your training data. Implement audit controls that let you track and review changes, including who made them and when they occurred." |
| Description | Verifies S3 buckets used for training data have versioning enabled so poisoned datasets can be rolled back. Recommends CloudTrail data-event logging as remediation to record who modified training data and when. |
| Detection | Identifies training-data S3 buckets by naming convention (`train`/`dataset`/`model`/`sagemaker`/`bedrock`). Calls `s3:GetBucketVersioning` to verify `Status=Enabled`. (CloudTrail data-event logging is recommended in remediation but is not asserted by this check — verifying it is covered by the upstream BR-06 CloudTrail control and the FS-23 extension.) |
| Remediation | 1. Enable versioning: `aws s3api put-bucket-versioning --bucket <name> --versioning-configuration Status=Enabled`. 2. Enable CloudTrail S3 data events for the training-data buckets to capture PutObject/DeleteObject with caller identity. 3. Enable MFA Delete for critical training datasets. 4. Apply S3 Object Lock for immutable baselines. |
| Reference | [S3 Versioning](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html), [CloudTrail Data Events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html) |

### Vector & Embedding Weaknesses (FS-22 to FS-26)

> **Guide source:** §1.2.15 Vector and embedding weaknesses. Guide-listed mitigations:
> (a) apply least privilege to vector and embedding database access;
> (b) validate knowledge base data sources;
> (c) add data only from trusted sources to knowledge bases;
> (d) monitor and log all activities in knowledge base control plane (CloudTrail);
> (e) enable encryption at rest and in transit for vector and embedding databases;
> (f) implement document/record-level access controls via KB metadata filtering for
> multi-tenancy.

#### FS-22 — Knowledge Base IAM Least Privilege

| Field | Detail |
|-------|--------|
| Severity | High |
| Guide ref | [Guide §1.2.15] — "Apply the principle of least privilege to control access to your vector and embedding database. Only grant users and services the minimum permissions they need to perform their tasks." |
| Description | Checks IAM roles accessing Knowledge Bases have no wildcard `bedrock:*` permissions covering KB actions. |
| Detection | Inspects the permissions cache for all IAM roles. Flags any role with an Allow statement granting `bedrock:*` without resource-level restrictions, or broad `bedrock:` actions covering KB operations without a specific knowledge-base ARN. Note: Bedrock agent and KB operations use the single IAM service prefix `bedrock:` (not `bedrock-agent:`) — the `bedrock-agent` token refers to the boto3 SDK client name, not the IAM action prefix. |
| Remediation | 1. Replace wildcard `bedrock:*` with specific KB actions: `bedrock:Retrieve`, `bedrock:RetrieveAndGenerate`, `bedrock:GetKnowledgeBase` (these are the actual IAM action names — verify via the AWS Service Authorization Reference for Amazon Bedrock). 2. Scope the resource ARN to specific Knowledge Base IDs (e.g., `arn:aws:bedrock:<region>:<account>:knowledge-base/<kb-id>`). 3. Apply IAM permission boundaries to limit blast radius. |
| Reference | [Bedrock Knowledge Base Permissions](https://docs.aws.amazon.com/bedrock/latest/userguide/kb-permissions.html) |

#### FS-23 — Knowledge Base CloudTrail Logging → *Merged into upstream BR-06*

> **Upstream extension note (do not ship as a standalone check):** The detection and remediation
> content from FS-23 should be added as a refinement of the existing **BR-06 (CloudTrail
> Logging)** check in the upstream repo.
>
> **What to add to BR-06:**
> - After verifying that a CloudTrail trail is active and logging Bedrock management events,
>   additionally check for an **advanced event selector** with
>   `resources.type = AWS::Bedrock::KnowledgeBase` to capture `Retrieve` and
>   `RetrieveAndGenerate` data events (these are NOT logged by default — they require an
>   explicit advanced event selector).
> - Note: `InvokeAgent` / `InvokeInlineAgent` are also data events requiring
>   `resources.type = AWS::Bedrock::AgentAlias` or `AWS::Bedrock::InlineAgent` respectively.
>   Data events incur additional CloudTrail charges and can produce high volumes under load.
> - Guide traceability: [Guide §1.2.15] — "Monitor and log all activities in knowledge base
>   control plane" with reference "Monitor Amazon Bedrock API calls using CloudTrail."
>
> **Reference:** [CloudTrail Bedrock Logging](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html)

#### FS-24 — Knowledge Base Metadata Filtering

| Field | Detail |
|-------|--------|
| Severity | Informational |
| Guide ref | [Guide §1.2.15] — "Implement access controls at the document or record level within knowledge bases where different users or applications should only have access to specific subsets of data. Use Amazon Bedrock Knowledge Bases metadata filtering to enforce data segmentation." |
| Description | Advisory: verifies KB metadata fields support tenant-level filtering for multi-tenancy. |
| Detection | Calls `ListKnowledgeBases` and `GetKnowledgeBase` (via the `bedrock-agent` boto3 client; IAM actions are `bedrock:ListKnowledgeBases` and `bedrock:GetKnowledgeBase`). Inspects the storage configuration for metadata field definitions. Flags KBs with no metadata fields defined (no tenant isolation possible). |
| Remediation | 1. Define metadata fields on your KB data sources (e.g., `tenant_id`, `department`, `classification`). 2. Populate metadata during document ingestion. 3. Use the `filter` parameter in Retrieve/RetrieveAndGenerate API calls to enforce tenant-scoped queries. 4. Test that cross-tenant data leakage is prevented. |
| Reference | [Bedrock KB Metadata Filtering](https://docs.aws.amazon.com/bedrock/latest/userguide/kb-test-config.html) |

#### FS-25 — OpenSearch Serverless Encryption

| Field | Detail |
|-------|--------|
| Severity | High |
| Guide ref | [Guide §1.2.15] — "Enable encryption at rest and in transit for vector and embedding databases." |
| Description | Checks OpenSearch Serverless collections used by KBs have CMK encryption policies. |
| Detection | Calls `opensearchserverless:ListCollections` (IAM action `aoss:ListCollections`) and for each calls `opensearchserverless:ListSecurityPolicies(type=encryption)` (IAM action `aoss:ListSecurityPolicies`). Inspects each encryption policy's document for `AWSOwnedKey=true` or missing `KmsARN`. Note: the encryption **policy JSON document** uses PascalCase field names — `AWSOwnedKey` and `KmsARN` — while the direct API `EncryptionConfig` struct uses camelCase (`aWSOwnedKey`, `kmsKeyArn`); detection should inspect the policy document form returned by `GetSecurityPolicy`/`ListSecurityPolicies`. Flags collections using AWS-owned keys instead of customer-managed KMS keys. Note: the boto3 client name is `opensearchserverless`, but IAM actions use the service prefix `aoss:` (not `opensearchserverless:`). Note also: encryption in transit is automatic (TLS 1.2, AES-256) for all OpenSearch Serverless traffic and is not configurable — this check focuses on encryption at rest. |
| Remediation | 1. Create an encryption security policy specifying a customer-managed KMS key: set `AWSOwnedKey=false` and provide `KmsARN` with the ARN of your KMS key. 2. Apply the policy to the collection by matching the collection name or prefix pattern in the policy `Rules`. 3. Ensure the KMS key policy grants the OpenSearch Serverless service principal `kms:Decrypt` and `kms:GenerateDataKey`. Note: if you provide a KMS key directly in the `CreateCollection` request, it takes precedence over any matching security policies. |
| Reference | [OpenSearch Serverless Encryption](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-encryption.html) |

#### FS-26 — Knowledge Base VPC Access

| Field | Detail |
|-------|--------|
| Severity | High |
| Guide ref | [Guide §1.2.15, extension] — network isolation is not verbatim in the guide but directly implements "Apply the principle of least privilege to control access to your vector and embedding database" at the network layer. |
| Description | Verifies OpenSearch Serverless collections have VPC-only network policies (no public access). |
| Detection | Calls `opensearchserverless:ListSecurityPolicies(type=network)` (IAM action `aoss:ListSecurityPolicies` — the service prefix for OpenSearch Serverless is `aoss`, not `opensearchserverless`) and inspects each policy rule for `AllowFromPublic=true`. Flags collections accessible from the public internet. Note: a policy with `AllowFromPublic=false` may still grant private access to Bedrock via `SourceServices: ["bedrock.amazonaws.com"]` or to specific VPC endpoints via `SourceVPCEs` — these are the recommended private-access patterns and are not flagged. |
| Remediation | 1. Create a network security policy that restricts access to specific VPC endpoints only via `SourceVPCEs`, or grants private AWS service access (e.g., Bedrock) via `SourceServices: ["bedrock.amazonaws.com"]`. Per AWS docs, private access to AWS services applies only to the collection's OpenSearch endpoint, not to the OpenSearch Dashboards endpoint. 2. Create an OpenSearch Serverless VPC endpoint in your VPC if VPC-private access is required. 3. Remove any policy rules with `AllowFromPublic=true`. 4. Test connectivity from within the VPC. |
| Reference | [OpenSearch Serverless Network Access](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-network.html) |

---

## Part 2 — Guardrails & Content Safety (FS-27 to FS-46)

> **Guide risk categories:** Non-Compliant Output (FS-27..30, §1.2.1), Misinformation (FS-31..34, §1.2.3; FS-34 sources from §1.2.12 — see note), Abusive or Harmful Output (FS-35..38, §1.2.4), Biased Output (FS-39..42, §1.2.5), Sensitive Information Disclosure (FS-43..46, §1.2.6).

### Non-Compliant Output (FS-27 to FS-30)

> **Guide source:** §1.2.1 Non-compliant output. Guide-listed mitigations:
> (a) prompt engineering to guide the model and prevent unwanted responses;
> (b) content filters and denied topics in Bedrock Guardrails;
> (c) RAG with Bedrock Knowledge Bases;
> (d) Automated Reasoning checks in Bedrock Guardrails;
> (e) human-in-the-loop validation for internal AI systems;
> (f) audit logs of AI-generated outputs and guardrails applied for regulatory reporting.

#### FS-27 — Automated Reasoning Checks

| Field | Detail |
|-------|--------|
| Severity | High (contextual grounding) / Medium (Automated Reasoning) |
| Guide ref | [Guide §1.2.1, §1.2.7] — "Automated Reasoning checks in Amazon Bedrock Guardrails uses automated reasoning to verify that natural language content complies with your defined policies. This mathematical verification helps ensure that your content strictly follows your guardrails." |
| Description | Verifies Bedrock Guardrails have Automated Reasoning checks or contextual grounding enabled. |
| Detection | Calls `bedrock:ListGuardrails` and `bedrock:GetGuardrail` for each. Inspects the response fields `contextualGroundingPolicy` and `automatedReasoningPolicy`. Flags guardrails with neither enabled. |
| Remediation | 1. Enable contextual grounding filters (type `GROUNDING`) with a threshold ≥ 0.7 — these filters CAN block content that fails grounding checks. Note: valid threshold values are 0 to 0.99; a threshold of 1.0 is invalid and will block all content. **Important use-case limitation:** Contextual grounding checks support summarization, paraphrasing, and question answering use cases only — **Conversational QA / Chatbot use cases are not supported**. If your FinServ application is a conversational chatbot, contextual grounding cannot be used for hallucination detection; use Automated Reasoning checks or human-in-the-loop validation instead. 2. If available in your region, additionally enable Automated Reasoning checks by creating an Automated Reasoning policy and attaching it to the guardrail. **Cross-Region inference is REQUIRED for AR:** Guardrails that use Automated Reasoning checks require a cross-Region inference profile — set `crossRegionConfig.guardrailProfileIdentifier` to a profile matching your Region (for example, `us.guardrail.v1:0` for US Regions or `eu.guardrail.v1:0` for EU Regions). Omitting this parameter returns `ValidationException`. As of April 2026, AR is generally available in US East (N. Virginia), US East (Ohio), US West (Oregon), EU (Frankfurt), EU (Ireland), and EU (Paris) — verify current regional availability on the [AR documentation page](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-automated-reasoning-checks.html) before audit reliance, as AWS regularly expands coverage. Attach the **versioned** policy ARN (for example, `...:1`) — the unversioned ARN returns an error. You can attach a maximum of 2 AR policies per guardrail. Important: Automated Reasoning operates in **detect mode only** — it returns findings and feedback but does NOT block content. AR finding types (per the AWS user guide) are: `VALID` (response is consistent with policy), `INVALID` (response contradicts policy rules), `SATISFIABLE` (response could be true or false depending on unstated conditions), `IMPOSSIBLE` (premises are contradictory), `TRANSLATION_AMBIGUOUS` (natural language could not be reliably translated to formal logic), `TOO_COMPLEX` (policy complexity exceeded processing limits), and `NO_TRANSLATIONS` (some or all input was not translated into logic due to irrelevance or lack of matching policy variables). Note: in the `AutomatedReasoningCheckFinding` runtime response, these appear as a **union** with lowercase camelCase keys (`valid`, `invalid`, `satisfiable`, `impossible`, `translationAmbiguous`, `tooComplex`, `noTranslations`) — exactly one key is present per finding. Per AWS docs, AR also **does not protect against prompt injection attacks**, **cannot detect off-topic responses**, **does not support streaming APIs**, and **supports English (US) only** — use content filters, topic policies, and other guardrail components alongside AR. **Critical limitation for cross-account enforcement:** AR policies are NOT supported with Bedrock Guardrails cross-account safeguards (org-level or account-level enforcement) — including an AR policy in a guardrail used for enforcement will cause runtime failures. If you rely on AR, configure it at the application or account level separately. Your application must inspect the AR findings via the `ApplyGuardrail` (or `Converse` / `InvokeModel` / `InvokeAgent` / `RetrieveAndGenerate`) API response and decide whether to serve the response, rewrite it using AR feedback, ask the user for clarification, or fall back to a default behavior. 3. For `INVALID` responses, implement an iterative rewriting loop that feeds AR feedback (contradicting rules) back to the LLM to self-correct. 4. Build an audit trail of all AR validation iterations — log `supportingRules` and `claimsTrueScenario` for `VALID` findings as mathematically verifiable compliance evidence. |
| Reference | [Automated Reasoning in Bedrock Guardrails](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-automated-reasoning-checks.html), [AR Checks Concepts (Validation Results Reference)](https://docs.aws.amazon.com/bedrock/latest/userguide/automated-reasoning-checks-concepts.html), [Integrate AR Checks in Your Application](https://docs.aws.amazon.com/bedrock/latest/userguide/integrate-automated-reasoning-checks.html), [Deploy Automated Reasoning Policy](https://docs.aws.amazon.com/bedrock/latest/userguide/deploy-automated-reasoning-policy.html) |

#### FS-28 — Financial Denied Topics

| Field | Detail |
|-------|--------|
| Severity | High |
| Guide ref | [Guide §1.2.1] — "Configure content filters and guardrails to restrict model responses to approved topics" with reference "Amazon Bedrock User Guide – Guardrails – Denied topics". |
| Description | Checks guardrails have denied topics for regulated financial advice. |
| Detection | Calls `bedrock:GetGuardrail` and inspects `topicPolicy.topics` for entries with `type=DENY`. Flags guardrails with no denied topics or with no topics related to financial advice, investment recommendations, or tax guidance. |
| Remediation | 1. Add denied topics to the guardrail following the AWS best-practice golden rules: (a) **Be crisp and precise** — e.g., "Investment advice is inquiries, guidance, or recommendations about the management or allocation of funds or assets with the goal of generating returns or achieving specific financial objectives" rather than vague "Investment advice". (b) **Define, don't instruct** — write "All content associated with specific investment recommendations" not "Block all investment advice". (c) **Stay positive** — never define topics negatively (e.g., avoid "All content except general financial education"). (d) **Focus on themes, not words** — denied topics capture subjects contextually; use word filters for specific names or entities. (e) **Provide sample phrases** — add up to 5 representative inputs per topic (each up to 100 characters). 2. **Quantity and character limits:** A guardrail can contain a maximum of **30 denied topics**. In Classic tier, topic definitions are limited to 200 characters; in Standard tier, up to 1,000 characters — use Standard tier for complex financial topic definitions. 3. Recommended denied topics for FinServ: "specific investment recommendations", "tax advice", "specific financial product recommendations", "guaranteed returns or performance claims". 4. For multi-account enforcement, use Bedrock cross-account safeguards to apply denied topics from a management-account guardrail across all member accounts automatically. When configuring account-level or org-level enforcement, set **both** `selectiveContentGuarding.messages` AND `selectiveContentGuarding.system` to `COMPREHENSIVE` to ensure guardrails evaluate all user messages AND system prompts regardless of input tags — use `SELECTIVE` only when you trust callers to correctly tag content. Setting only `messages` to COMPREHENSIVE leaves system prompts potentially unguarded. 5. Enforce guardrails via IAM policy conditions (`bedrock:GuardrailIdentifier`) to prevent any Bedrock inference call without a guardrail attached. 6. Test with prompts that attempt to elicit regulated financial advice. |
| Reference | [Bedrock Guardrails Denied Topics](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-denied-topics.html), [Safeguard Tiers for Guardrails](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-tiers.html), [Cross-Account Safeguards with Enforcements](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-enforcements.html), [Guardrails Best Practices](https://aws.amazon.com/blogs/machine-learning/build-safe-generative-ai-applications-like-a-pro-best-practices-with-amazon-bedrock-guardrails/) |

#### FS-29 — Compliance Disclaimer

| Field | Detail |
|-------|--------|
| Severity | Informational |
| Guide ref | [Guide §1.2.1, extension] — disclaimers are not verbatim in §1.2.1 but the guide references "Implement response disclaimers in customer-facing applications" under §1.2.7 Hallucination, which is conceptually the same control applied here for non-compliant financial-advice output. |
| Description | Advisory: verifies application adds required regulatory disclaimers to AI-generated outputs. |
| Detection | Advisory check — cannot be fully automated. Inspects application Lambda function environment variables or configuration for disclaimer-related settings (e.g., `DISCLAIMER_ENABLED`, `COMPLIANCE_FOOTER`). |
| Remediation | 1. Add a standard regulatory disclaimer to all customer-facing AI-generated responses (e.g., "This information is generated by AI and does not constitute financial advice. Please consult a qualified financial advisor."). 2. Make the disclaimer text configurable via environment variable or parameter store. 3. Ensure disclaimers are not removable by prompt manipulation. |
| Reference | [AWS Well-Architected GenAI Lens — Guardrails](https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/gensec02-bp01.html) |

#### FS-30 — Compliance Evaluation Datasets

| Field | Detail |
|-------|--------|
| Severity | Informational |
| Guide ref | [Guide §1.2.1, extension] — the Guide §1.2.12 practical guidance mentions "Amazon Bedrock Evaluations can help to evaluate models against specific types of attacks"; this check extends that concept to compliance-specific evaluation for FS-regulated outputs. |
| Description | Checks Bedrock evaluation jobs use compliance-specific test datasets. |
| Detection | Calls `bedrock:ListEvaluationJobs` to enumerate existing jobs, then calls `bedrock:GetEvaluationJob` for each to inspect the full `evaluationConfig` including dataset configuration. Flags if no evaluation jobs exist or if none reference compliance/regulatory test data. Note: `ListEvaluationJobs` returns only job summaries — dataset configuration details require `GetEvaluationJob`. |
| Remediation | 1. Create a compliance-specific evaluation dataset containing: prompts requesting regulated financial advice, prompts testing disclaimer presence, prompts testing denied-topic enforcement. 2. Run Bedrock evaluation jobs with this dataset before each production deployment. 3. Set pass/fail thresholds and gate deployments on results. |
| Reference | [Bedrock Model Evaluation](https://docs.aws.amazon.com/bedrock/latest/userguide/evaluation.html) |

### Misinformation (FS-31 to FS-33)

> **Guide source:** §1.2.3 Misinformation through inadvertent or malicious action. Guide-listed mitigations:
> (a) prompt engineering;
> (b) verify knowledge base data sources are up-to-date, accurate, reliable, and complete;
> (c) human-in-the-loop validation for internal AI systems;
> (d) source attribution in RAG responses for end users to verify provenance;
> (e) integrity monitoring on knowledge base data sources — e.g., S3 event notifications to
> track document changes.

#### FS-31 — Knowledge Base Data Source Sync

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.3, §1.2.10] — "Verify that your knowledge base data sources are up-to-date, accurate, reliable, and complete"; "Sync your data with your Amazon Bedrock knowledge base". |
| Description | Verifies KB data sources have been synced within 7 days. |
| Detection | Calls `ListDataSources` then `ListIngestionJobs` for each data source (via the `bedrock-agent` boto3 client; IAM actions are `bedrock:ListDataSources` and `bedrock:ListIngestionJobs`). Checks the most recent successful ingestion job's `updatedAt` timestamp. Flags data sources not synced within 7 days. |
| Remediation | 1. Create an EventBridge scheduled rule to trigger KB data source sync at least weekly. 2. Use `StartIngestionJob` (IAM action `bedrock:StartIngestionJob`) as the rule target. 3. Add CloudWatch alarms for failed ingestion jobs. 4. For rapidly changing data, increase sync frequency. |
| Reference | [Bedrock KB Data Source Sync](https://docs.aws.amazon.com/bedrock/latest/userguide/kb-data-source-sync-ingest.html) |

#### FS-32 — Source Attribution

| Field | Detail |
|-------|--------|
| Severity | Informational |
| Guide ref | [Guide §1.2.3, §1.2.10] — "Use source attribution in RAG-based response for end users to verify provenance of information" (§1.2.3); "Use source attribution in RAG-based response for end users to verify currency of information" (§1.2.10). |
| Description | Advisory: verifies application implements source citations in RAG responses. |
| Detection | Advisory check — inspects application code or configuration for use of the `citations` field in `RetrieveAndGenerate` API responses. Checks Lambda environment variables for attribution-related settings. |
| Remediation | 1. Use the `RetrieveAndGenerate` API (IAM action `bedrock:RetrieveAndGenerate`) which returns `citations` with source document references. Each citation contains `retrievedReferences` — an array where each reference has a `content` object (the cited text), a `location` object (data source type and URI — for S3 sources, `location.type=S3` and `location.s3Location.uri` contains the S3 URI), and optional `metadata` (a string-to-JSON map with any custom metadata attributes stored on the chunk, which can hold document title and other fields). Note: there is no fixed `title` field in the API — if you need to display document titles to end users, store them as a metadata attribute during KB ingestion and retrieve them via `retrievedReferences[].metadata`. 2. Display source citations to end users alongside AI-generated responses. 3. Include the data source location (URI or other location identifier depending on source type: S3, Web, Confluence, SharePoint, Salesforce, Kendra, SQL, or Custom) and the cited text excerpt (from `content`). 4. If document titles are required, ensure they are populated in KB metadata and propagated to your UI. 5. Allow users to click through to the original source document where possible. |
| Reference | [Bedrock RetrieveAndGenerate API](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_RetrieveAndGenerate.html) |

#### FS-33 — Knowledge Base Integrity Monitoring

| Field | Detail |
|-------|--------|
| Severity | High (deleted bucket) / Medium (versioning) |
| Guide ref | [Guide §1.2.3] — "Use integrity monitoring on knowledge base data sources to detect unauthorized modifications. Track changes to documents used in knowledge bases." References "For example on S3 data sources use Amazon S3 event notification to track changes to documents." |
| Description | Checks KB data source S3 buckets have versioning enabled and S3 event notifications (EventBridge or SNS) configured to detect unauthorized document modifications in real time. |
| Detection | Identifies KB data-source S3 buckets via `GetDataSource` (via the `bedrock-agent` boto3 client; IAM action `bedrock:GetDataSource`). Calls `s3:GetBucketVersioning` to verify `Status=Enabled`. Calls `s3:GetBucketNotificationConfiguration` and checks for `EventBridgeConfiguration`, `TopicConfigurations`, `QueueConfigurations`, or `LambdaFunctionConfigurations`. Flags buckets missing either control. |
| Remediation | 1. Enable versioning: `aws s3api put-bucket-versioning --bucket <name> --versioning-configuration Status=Enabled`. 2. Enable EventBridge notifications on the bucket: `aws s3api put-bucket-notification-configuration --bucket <name> --notification-configuration '{"EventBridgeConfiguration":{}}'`. Once enabled, S3 automatically sends **all** bucket events to EventBridge — you do not select specific event types at the bucket level. 3. Create an EventBridge rule that matches S3 events for this bucket — use the `detail-type` field values `Object Created` and `Object Deleted` (these are the EventBridge event type names; note: `s3:ObjectCreated:*` and `s3:ObjectRemoved:*` are the legacy SNS/SQS/Lambda notification event type names and are NOT used in EventBridge rules). Route matched events to an SNS topic or Lambda function for alerting. 4. Integrate alerts into your security incident response workflow. |
| Reference | [S3 EventBridge Integration](https://docs.aws.amazon.com/AmazonS3/latest/userguide/EventBridge.html) |

> **Note:** FS-34 (Third-Party Risk Management for FM Providers) is kept adjacent to Misinformation
> in this file for continuity with the prior draft numbering, but its guide source is §1.2.12
> Supply Chain Vulnerabilities. Treat FS-34 as a Supply Chain check for compliance-framework
> mapping purposes.

#### FS-34 — Third-Party Risk Management (TPRM) for Foundation Model Providers

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.12] — *"Update existing third-party risk management processes to continuously monitor model providers and third-party dependencies, including tracking vendor security advisories, model deprecation notices, and change to terms and conditions."* (Note: moved from the Misinformation section in the prior draft; the guide places TPRM under Supply Chain.) |
| Description | Verifies a documented third-party risk management (TPRM) process exists to monitor FM providers for security advisories, model deprecation notices, and T&C changes; also flags legacy FMs currently in use. |
| Detection | Calls `bedrock:ListFoundationModels`, then `bedrock:GetFoundationModel` for each in-use model; inspects `modelLifecycle.status` and flags models with status `LEGACY`. Note: the `FoundationModelLifecycle.status` API field has only **two** valid values — `ACTIVE` and `LEGACY`. There is no `EOL` status value in the API; models that have passed their EOL date are removed from the service entirely and API calls referencing them will fail. The user-facing lifecycle page describes three conceptual states (Active, Legacy, EOL) but the API only exposes two. Advisory component checks for evidence of a TPRM process — e.g., an AWS Config rule or a tag on Bedrock resources indicating periodic review (`tprm-last-reviewed=<ISO-date>`). |
| Remediation | 1. Establish a documented TPRM process: at least quarterly review of each in-use FM provider's security advisories, model lifecycle announcements, and T&C changes. 2. Assign an owner for the TPRM process and record review evidence in your MRM system. 3. Subscribe to AWS Bedrock model lifecycle notifications. 4. Migrate workloads from `LEGACY` models to active versions before their published EOL date — note that for models with EOL dates after February 1, 2026, there is a "public extended access" period where Legacy models remain usable but at higher pricing set by the model provider. 5. For third-party models procured via AWS Marketplace or consumed directly, evaluate the provider's own testing procedures — AWS AI Service Cards provide this transparency for Amazon-trained models. |
| Reference | [Bedrock Model Lifecycle](https://docs.aws.amazon.com/bedrock/latest/userguide/model-lifecycle.html), [Access Amazon Bedrock foundation models](https://docs.aws.amazon.com/bedrock/latest/userguide/model-access.html) |

### Abusive or Harmful Output (FS-35 to FS-38)

> **Guide source:** §1.2.4 Model output is abusive or harmful. Guide-listed mitigations:
> (a) AWS AI Service Cards to understand how Amazon addresses toxicity per model;
> (b) Amazon Bedrock Guardrails to detect and filter harmful content;
> (c) FMEval to evaluate for inappropriate content (sexual, profanity, hate, aggression,
> insults, flirtation, identity attacks, threats);
> (d) user reporting mechanism so end users can flag abusive outputs, reviewed within a
> defined process;
> (e) Practical guidance: create allowlists for approved business terminology to reduce
> false positives on brand, product, industry, and technical vocabulary.

#### FS-35 — FMEval Harmful Content

| Field | Detail |
|-------|--------|
| Severity | Informational |
| Guide ref | [Guide §1.2.4] — "Foundation Model Evaluations (FMEval) evaluates your model to detect inappropriate content, including sexual references, profanity, hate speech, aggression, insults, flirtation, identity-based attacks, and threats." |
| Description | Checks Bedrock evaluation jobs test for harmful/toxic content. |
| Detection | Calls `bedrock:ListEvaluationJobs` to enumerate existing jobs, then calls `bedrock:GetEvaluationJob` for each to inspect the full `evaluationConfig`. The correct metric name depends on the evaluation job type: (a) For **automated model evaluation jobs** (pre-computed metrics), the toxicity metric is `"Builtin.Toxicity"` — the only valid harmful-content metric for this job type. (b) For **judge-based model evaluation jobs** (LLM-as-judge), the harmful content metrics are `"Builtin.Harmfulness"` and `"Builtin.Stereotyping"`. (c) For **knowledge base (RAG) evaluation jobs**, `"Builtin.Harmfulness"` and `"Builtin.Stereotyping"` are also valid. Flags if no evaluation jobs exist or none include a harmful-content metric (`Builtin.Toxicity` for automated, `Builtin.Harmfulness` for judge-based/RAG). Note: `ListEvaluationJobs` returns only job summaries — dataset configuration details require `GetEvaluationJob`. |
| Remediation | 1. For **automated model evaluation** (fastest, no judge model required): create a Bedrock evaluation job with `"Builtin.Toxicity"` in the `metricNames` array. Valid task types are `Summarization`, `Classification`, `QuestionAndAnswer`, `Generation`, and `Custom`. 2. For **judge-based model evaluation** (more nuanced, requires a judge model): create a Bedrock evaluation job with `"Builtin.Harmfulness"` and/or `"Builtin.Stereotyping"` in the `metricNames` array — these metrics are only valid for judge-based and RAG evaluation jobs, not automated model evaluation jobs. 3. Include test prompts designed to elicit harmful content. 4. Set pass/fail thresholds based on the scores returned. 5. Run evaluations before production deployment and after model updates. 6. For more granular toxicity scoring (the 7-category UnitaryAI Detoxify-unbiased scores: `toxicity`, `severe_toxicity`, `obscene`, `threat`, `insult`, `sexual_explicit`, `identity_attack` — or the Toxigen-roberta binary classifier), use SageMaker FMEval via SageMaker Studio or the `fmeval` Python library as a complementary evaluation path. |
| Reference | [Bedrock Model Evaluation Metrics](https://docs.aws.amazon.com/bedrock/latest/userguide/model-evaluation-metrics.html), [SageMaker FMEval Toxicity](https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-toxicity-evaluation.html) |

#### FS-36 — Guardrail Content Filters

| Field | Detail |
|-------|--------|
| Severity | High |
| Guide ref | [Guide §1.2.4] — "Use Amazon Bedrock's guardrails to detect and filter harmful content." |
| Description | Verifies guardrails have content filters for hate, violence, sexual, and other harmful content. |
| Detection | Calls `bedrock:GetGuardrail` and inspects `contentPolicy.filters`. Flags guardrails missing filters for HATE, VIOLENCE, SEXUAL, INSULTS, or MISCONDUCT categories. Also checks that `inputStrength` and `outputStrength` are at least `MEDIUM`. |
| Remediation | 1. Update the guardrail to include content filters for all harmful categories: HATE, VIOLENCE, SEXUAL, INSULTS, MISCONDUCT. 2. Select the **Standard tier** (not Classic) for content filters — it offers better accuracy, broader language support (extensive multilingual support vs. English/French/Spanish only in Classic), prompt leakage detection, and extends protection to harmful content within code elements. Standard tier requires cross-Region inference to be enabled on the guardrail (configurable at creation or by modifying an existing guardrail). 3. Start with **HIGH** filter strength for customer-facing applications; evaluate false-positive rates on representative sample traffic and lower to MEDIUM only if necessary. 4. Apply filters to both INPUT and OUTPUT. 5. Before enabling blocking in production, use **detect mode** (`action=NONE`) to test guardrail behavior on live traffic — review trace output to validate decisions, then switch to `action=BLOCK` once confident. 6. Enforce guardrails organization-wide via IAM policy-based enforcement: add an IAM condition key (`bedrock:GuardrailIdentifier`) to deny any `InvokeModel`/`Converse` call that does not include a guardrail. For account-level or org-level enforcement configurations, set **both** `selectiveContentGuarding.messages` AND `selectiveContentGuarding.system` to `COMPREHENSIVE` to ensure guardrails evaluate all user messages AND system prompts regardless of input tags (use `SELECTIVE` only when you trust callers to correctly tag content). Setting only `messages` to COMPREHENSIVE leaves system prompts potentially unguarded. |
| Reference | [Bedrock Guardrails Content Filters](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-content-filters.html), [Safeguard Tiers for Guardrails](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-tiers.html), [Cross-Account Safeguards with Enforcements](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-enforcements.html), [Guardrails Best Practices](https://aws.amazon.com/blogs/machine-learning/build-safe-generative-ai-applications-like-a-pro-best-practices-with-amazon-bedrock-guardrails/), [IAM Guardrail Enforcement](https://aws.amazon.com/blogs/machine-learning/amazon-bedrock-guardrails-announces-iam-policy-based-enforcement-to-deliver-safe-ai-interactions/) |

#### FS-37 — User Feedback Mechanism

| Field | Detail |
|-------|--------|
| Severity | Informational |
| Guide ref | [Guide §1.2.4] — "Implement a user reporting mechanism that allows end users to flag abusive or harmful outputs. Reported incidents [are] reviewed within a defined process to refine content filters." |
| Description | Advisory: verifies application has a user reporting mechanism for harmful outputs. |
| Detection | Advisory check — inspects application configuration for feedback-related settings (e.g., `FEEDBACK_ENABLED`, `REPORT_ABUSE_ENDPOINT`). Checks for Lambda functions with "feedback" or "report" in the name. |
| Remediation | 1. Implement a "Report this response" button in the application UI. 2. Route reported responses to an SQS queue or DynamoDB table for review. 3. Define an SLA for reviewing reported content (e.g., 24 hours). 4. Use reported incidents to refine guardrail content filters and word lists. 5. Log all reports with Bedrock invocation logging correlation IDs. |
| Reference | [Bedrock Model Invocation Logging](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html) |

#### FS-38 — Guardrail Word Filters and Business Term Allowlists

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.4 — Practical guidance] — "Create allowlists for business terms that include approved terminology for: brand names, product names, industry terms, and technical vocabulary. Also test filter settings to verify that your content filters allow necessary business communications and generate accurate alerts. Monitor and adjust regularly your filtering system to reduce false positives." |
| Description | Checks guardrails have word/phrase block filters configured and that approved business terminology allowlists are defined to prevent false positives on legitimate financial services vocabulary. |
| Detection | Calls `bedrock:GetGuardrail` and inspects `wordPolicy`. Flags guardrails with no custom `words` array (blocked phrases). Also checks `managedWordLists` for the AWS-managed `PROFANITY` list. Note: a guardrail with only the profanity filter and no custom FinServ-specific blocked terms should still be flagged as incomplete for financial services use cases. |
| Remediation | 1. Add blocked words/phrases to the guardrail word filter (profanity, slurs, competitor names if applicable). Each custom word/phrase entry has a maximum length of **100 characters** per the API (`GuardrailWordConfig.text`); the console UI additionally limits entries to **up to three words** per phrase. You can add up to **10,000 items** to the custom word filter. 2. Enable the AWS-managed profanity filter (`managedWordListsConfig` with `type=PROFANITY`) as a baseline. 3. Create an allowlist of approved business terminology: brand names, product names, industry terms, technical vocabulary — document this separately as the guardrail word filter only blocks, it does not allowlist. Test filter settings to verify legitimate business communications are not blocked. 4. Monitor and adjust regularly to reduce false positives. |
| Reference | [Bedrock Guardrails Word Filters](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-word-filters.html) |

### Biased Output (FS-39 to FS-42)

> **Guide source:** §1.2.5 Model output is biased. Guide-listed mitigations:
> (a) AWS AI Service Cards to understand how providers address fairness/bias per model;
> (b) prompt engineering;
> (c) Amazon Bedrock Guardrails;
> (d) Bedrock Evaluations to measure bias;
> (e) Amazon SageMaker Clarify for bias detection, transparency, and prediction explanation
> on fine-tuned and self-trained models;
> (f) develop and maintain a bias testing dataset with representative cases across
> demographic groups, geographic regions, and sensitive attributes — run periodically and
> after each model update.

#### FS-39 — SageMaker Clarify Bias

| Field | Detail |
|-------|--------|
| Severity | High |
| Guide ref | [Guide §1.2.5] — "Use Amazon SageMaker Clarify to detect bias, increase transparency, and explain predictions for your fine-tuned and self-trained AI models." |
| Description | Verifies Clarify model bias monitoring is configured for financial decision models. |
| Detection | Calls `sagemaker:ListMonitoringSchedules` with the `MonitoringTypeEquals=ModelBias` filter parameter (the `MonitoringType` field on the `MonitoringScheduleSummary` response has one of four values: `DataQuality`, `ModelQuality`, `ModelBias`, `ModelExplainability`). Flags if no bias monitoring schedules exist. Cross-references with endpoints tagged `use-case=financial-decision` or similar. Clarify bias monitoring publishes metrics to the `aws/sagemaker/Endpoints/bias-metrics` namespace for real-time endpoints (and `aws/sagemaker/ModelMonitoring/bias-metrics` for batch transform jobs) with `Endpoint`, `MonitoringSchedule`, `BiasStage`, `Label`, `LabelValue`, `Facet`, and `FacetValue` dimensions. |
| Remediation | 1. Create a SageMaker Clarify bias monitoring schedule for each financial decision model endpoint. 2. Specify facets (protected attributes: age, gender, race, geography) and bias metrics (DPL, DI, DPPL). 3. Provide a baseline bias report from training data. 4. Configure CloudWatch alarms on bias metric violations on the `aws/sagemaker/Endpoints/bias-metrics` namespace. Note: `publish_cloudwatch_metrics` is enabled by default — do NOT set it to `Disabled` in the model bias job definition's `Environment` map, as that would stop metrics from being published to CloudWatch. |
| Reference | [SageMaker Clarify Bias Detection](https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-detect-post-training-bias.html) |

#### FS-40 — Bedrock Bias Evaluation Datasets and Cadence

| Field | Detail |
|-------|--------|
| Severity | Informational |
| Guide ref | [Guide §1.2.5] — "Develop and maintain a bias testing dataset that includes representative test cases across demographic groups, geographic regions, and other sensitive attributes relevant to your use case. Run these test cases periodically and after model updates." |
| Description | Checks evaluation jobs include demographic fairness test cases across protected groups and verifies evaluations are run on a defined periodic schedule and after each model update. |
| Detection | Calls `bedrock:ListEvaluationJobs` to enumerate existing jobs, then calls `bedrock:GetEvaluationJob` for each to inspect the full `evaluationConfig` including dataset configuration for demographic diversity test cases. Checks the `creationTime` of the most recent evaluation job and flags if it is older than 90 days or if no evaluation was run after the most recent model deployment. Note: `ListEvaluationJobs` returns only job summaries — dataset configuration details require `GetEvaluationJob`. |
| Remediation | 1. Create a bias evaluation dataset with representative test cases across demographic groups, geographic regions, and other sensitive attributes. 2. Schedule evaluation jobs to run at least quarterly via EventBridge. 3. Trigger an evaluation job automatically after each model update in your CI/CD pipeline. 4. Store results for audit and trend analysis. |
| Reference | [Bedrock Model Evaluation](https://docs.aws.amazon.com/bedrock/latest/userguide/evaluation.html) |

#### FS-41 — SageMaker Clarify Explainability

| Field | Detail |
|-------|--------|
| Severity | High |
| Guide ref | [Guide §1.2.5, extension] — Guide §1.2.5 recommends "Amazon SageMaker Clarify to detect bias, increase transparency, and explain predictions". ECOA/Fair Housing adverse-action-notice use case is an FS-specific extension of Clarify explainability not named verbatim in the guide. |
| Description | Verifies Clarify explainability monitoring for adverse action notices (commonly cited under ECOA for credit decisions; this is an FS industry-practice extension, not a guide-prescribed control). |
| Detection | Calls `sagemaker:ListMonitoringSchedules` with the `MonitoringTypeEquals=ModelExplainability` filter parameter. Flags if no explainability monitoring schedules exist for financial decision model endpoints. Clarify explainability monitoring publishes metrics to the `aws/sagemaker/Endpoints/explainability-metrics` namespace for real-time endpoints (and `aws/sagemaker/ModelMonitoring/explainability-metrics` for batch transform jobs) with `Endpoint`, `MonitoringSchedule`, `ExplainabilityMethod` (value: `KernelShap`), `Label`, and `ValueType` (values: `GlobalShapValues` or `ExpectedValue`) dimensions. |
| Remediation | 1. Create a SageMaker Clarify explainability monitoring schedule using SHAP analysis. 2. Configure feature attribution baselines. 3. Use explainability outputs to generate adverse action notices (top contributing factors for negative decisions) where your firm's use case and regulatory interpretation require them. 4. Retain explainability reports for regulatory audit. |
| Reference | [SageMaker Clarify Explainability](https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-model-explainability.html) |

#### FS-42 — AI Service Cards

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.4, §1.2.5, §1.2.14] — "Amazon provides AI Service Cards for models that are pre-trained for AWS services like Amazon Bedrock and Amazon Q. These cards help you understand how Amazon addresses toxicity in each model." Referenced in three separate guide risk sections. |
| Description | Checks SageMaker Model Cards document intended use and bias evaluations. |
| Detection | Calls `sagemaker:ListModelCards`. For each card, calls `sagemaker:DescribeModelCard` and inspects the content JSON for `intended_uses`, `business_details`, and `evaluation_details` sections. Flags cards missing these sections. |
| Remediation | 1. Create a SageMaker Model Card for each production model. 2. Document: intended use cases, out-of-scope uses, training data description, bias evaluation results, performance metrics. 3. Review and update cards after each model retrain. 4. For Bedrock foundation models, reference the AWS AI Service Cards published by Amazon. |
| Reference | [SageMaker Model Cards](https://docs.aws.amazon.com/sagemaker/latest/dg/model-cards.html), [AWS AI Service Cards](https://aws.amazon.com/ai/responsible-ai/resources/) |

### Sensitive Information Disclosure (FS-43 to FS-46)

> **Guide source:** §1.2.6 Sensitive information disclosure. Guide-listed mitigations:
> (a) Bedrock Guardrails sensitive information filters for PII, PHI;
> (b) data classification scanning and access controls on AI data sources;
> (c) strict IAM access controls for Bedrock API;
> (d) mask sensitive information in CloudWatch Logs and custom application logging;
> (e) protect training and fine-tuning data via data protection best practices;
> (f) monitor PII in training/fine-tuning/RAG data with Amazon Macie;
> (g) remove, mask, or tokenize PII before use in training, fine-tuning, or RAG;
> (h) Practical guidance: least privilege for agent identities; user-authorized communications
> to tool services; propagate end-user identities so tool services can validate them without
> revealing them to unauthorized third parties.

#### FS-43 — CloudWatch Log PII Masking

| Field | Detail |
|-------|--------|
| Severity | High |
| Guide ref | [Guide §1.2.6] — "If you implement model invocation logging for the LLM or custom logging logic in your application, make sure to mask sensitive information in your log data." References "Amazon CloudWatch – Help protect sensitive log data with masking". |
| Description | Checks CloudWatch Logs data protection policies mask PII in Bedrock invocation logs. |
| Detection | Identifies CloudWatch log groups used by Bedrock invocation logging (from `bedrock:GetModelInvocationLoggingConfiguration`). Calls `logs:GetDataProtectionPolicy` for each log group. Flags log groups with no data protection policy or policies missing PII identifiers. Note: model invocation logging only captures calls made through the `bedrock-runtime` endpoint (`Converse`, `ConverseStream`, `InvokeModel`, `InvokeModelWithResponseStream`); calls through other endpoints such as the Responses API (`bedrock-mantle` endpoint) are not captured. |
| Remediation | 1. Create a CloudWatch Logs data protection policy on each Bedrock log group. 2. Include managed data identifiers using their exact ARN-based IDs — country-code suffixes are **required** in the ARN for most identifiers (the data-types table uses the short name such as `Ssn`, but the ARN must include the country code): `Ssn-US` (US Social Security Number; `Ssn-ES` for Spain — there is no bare `Ssn` ARN), `CreditCardNumber` (no suffix), `CreditCardSecurityCode` (no suffix), `EmailAddress` (no suffix), `Address` (no suffix), `PhoneNumber-US`, `BankAccountNumber-US`, `DriversLicense-US`, `PassportNumber-US`, `IndividualTaxIdentificationNumber-US`. 3. Add a `Deidentify` operation statement (no hyphen — this is the exact JSON key required in the policy document, even though AWS prose documentation uses "De-identify") to mask sensitive data, and a separate `Audit` statement to emit findings to CloudWatch. The `Deidentify` operation must contain an empty `"MaskConfig": {}` object. 4. **Retroactive masking scope:** A **log group-level** data protection policy only masks data ingested **after** the policy is applied — historical log events are not retroactively masked. However, an **account-level** data protection policy applies to both existing log groups and log groups created in the future. For maximum coverage, consider creating an account-level policy in addition to log group-level policies. Apply policies at log group creation time or as early as possible. 5. Test by sending a log entry containing sample PII and verifying it is masked in subsequent reads. |
| Reference | [CloudWatch Logs Data Protection](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/mask-sensitive-log-data.html), [PII Data Identifier ARNs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/protect-sensitive-log-data-types-pii.html), [Financial Data Identifier ARNs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/protect-sensitive-log-data-types-financial.html) |

#### FS-44 — Amazon Macie PII Scanning and Pre-Processing

| Field | Detail |
|-------|--------|
| Severity | High |
| Guide ref | [Guide §1.2.6] — "Monitor personally identifiable information (PII) in your data when you train models, fine-tune them, or use retrieval-augmented generation (RAG)" and "Remove, mask, or tokenize personally identifiable information (PII) or sensitive data before you use it for training, fine-tuning, or retrieval-augmented generation (RAG)." |
| Description | Verifies Macie is enabled and scanning AI/ML data buckets, and checks that a PII pre-processing step (tokenization, masking, or removal) exists in training and RAG ingestion pipelines before data reaches the model. |
| Detection | Calls `macie2:GetMacieSession` to verify Macie is enabled. Calls `macie2:GetAutomatedDiscoveryConfiguration` to check whether automated sensitive data discovery is enabled (preferred over manual classification jobs — automated discovery evaluates S3 buckets daily without explicit job creation). Also calls `macie2:ListClassificationJobs` to check for any additional targeted jobs covering S3 buckets tagged for AI/ML use. Additionally inspects SageMaker Processing jobs or Glue jobs for PII-related naming patterns indicating a pre-processing pipeline. |
| Remediation | 1. Enable Amazon Macie in the account. 2. **Preferred:** Enable Macie **Automated Sensitive Data Discovery** (via `macie2:UpdateAutomatedDiscoveryConfiguration` set to `ENABLED`) — this continuously evaluates ALL S3 buckets in the account or organization daily, selects representative objects, and produces sensitive-data findings without requiring manual job creation. 3. For higher-priority AI/ML buckets where you need full-depth scans, supplement with targeted classification jobs (`macie2:CreateClassificationJob`) scheduled at least weekly. 4. Implement a PII pre-processing step in your data pipeline (SageMaker Processing job, Glue job, or Lambda) that tokenizes, masks, or removes PII before data is used for training or RAG ingestion. 5. Use Amazon Comprehend `DetectPiiEntities` or Macie findings to identify PII locations and feed them into the pre-processing step. 6. Route Macie findings to EventBridge and then to your SIEM or ticketing system for timely investigation. |
| Reference | [Amazon Macie](https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html), [Macie Automated Sensitive Data Discovery](https://docs.aws.amazon.com/macie/latest/user/discovery-asdd.html), [Amazon Comprehend PII Detection](https://docs.aws.amazon.com/comprehend/latest/dg/pii.html) |

#### FS-45 — Guardrail PII Filters

| Field | Detail |
|-------|--------|
| Severity | High |
| Guide ref | [Guide §1.2.6] — "Use Amazon Bedrock Guardrails to detect and filter structured sensitive information in model inputs and outputs, such as personally identifiable information (PII), protected health information (PHI)." |
| Description | Checks guardrails have PII entity filters for SSN, credit card, and account numbers. |
| Detection | Calls `bedrock:GetGuardrail` and inspects `sensitiveInformationPolicy.piiEntities`. Flags guardrails missing filters for critical PII types: `US_SOCIAL_SECURITY_NUMBER`, `CREDIT_DEBIT_CARD_NUMBER`, `CREDIT_DEBIT_CARD_CVV`, `CREDIT_DEBIT_CARD_EXPIRY`, `US_BANK_ACCOUNT_NUMBER`, `US_BANK_ROUTING_NUMBER`, `PIN`, `SWIFT_CODE`, `INTERNATIONAL_BANK_ACCOUNT_NUMBER`, `US_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER`, `EMAIL`, `PHONE`. |
| Remediation | 1. Update the guardrail to add PII entity filters for all relevant types. 2. Configure separate input and output actions using the `inputAction` and `outputAction` fields: set `outputAction=ANONYMIZE` (replace with placeholder such as `{US_SOCIAL_SECURITY_NUMBER}`) so PII in model responses is masked before reaching the user; set `inputAction=BLOCK` for PII types that should never be submitted (e.g., SSN, credit card numbers). 3. Use `inputEnabled` and `outputEnabled` to selectively enable evaluation per direction — disable evaluation on a direction you don't need to reduce cost and latency. 4. **PHI coverage nuance:** The Bedrock Guardrails sensitive information filter has only limited built-in PHI entities — specifically `CA_HEALTH_NUMBER` (Canada) and `UK_NATIONAL_HEALTH_SERVICE_NUMBER` (UK). For US HIPAA PHI (for example, Medical Record Numbers, Health Plan Beneficiary Numbers, Medicare Beneficiary Identifiers), there is no built-in entity type — use `regexesConfig` (custom regex patterns) on the guardrail to detect these patterns, complemented by downstream CloudWatch Logs data protection policies (see FS-43) which have PHI identifiers under the HIPAA category. 5. **Critical limitation — tool_use outputs:** The sensitive information filter does NOT detect PII when models respond with `tool_use` (function call) output parameters via supported APIs. For FinServ agentic applications where models invoke tools and return structured function-call responses, implement application-layer PII scanning on tool outputs before they are processed or displayed. 6. **Critical limitation — invocation logs:** Guardrail PII masking applies only to content sent to and returned from the inference model. It does NOT apply to model invocation logs — the `input` field in CloudWatch Logs always contains the original, unmasked request regardless of guardrail intervention. Use CloudWatch Logs data protection policies (see FS-43) to mask PII in logs separately. Similarly, the `match` field in guardrail trace output contains the original PII value, not the masked output. 7. Test with sample inputs containing each PII type and verify both input blocking and output anonymization work as expected. |
| Reference | [Bedrock Guardrails Sensitive Information Filters](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-sensitive-filters.html) |

#### FS-46 — Data Classification Tagging

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.6] — "Implement data classification scanning and access controls on the data sources connected to your AI system to prevent disclosure of company-confidential or proprietary information." |
| Description | Verifies AI/ML S3 buckets are tagged with data classification labels. |
| Detection | Lists S3 buckets and filters for AI/ML-related names or tags. Calls `s3:GetBucketTagging` for each and checks for a `data-classification` tag with values like `public`, `internal`, `confidential`, `restricted`. Flags buckets missing the tag. |
| Remediation | 1. Define a data classification taxonomy (e.g., Public, Internal, Confidential, Restricted). 2. Tag all AI/ML S3 buckets with `data-classification=<level>`. 3. **Detective enforcement:** Create an AWS Config managed rule (`required-tags`, checks up to six tag keys at a time) to identify buckets missing the tag and trigger remediation via a custom SSM automation document (note: the AWS-managed `AWS-SetRequiredTags` automation document does NOT work as a remediation with this rule — you must author a custom Systems Manager automation document). 4. **Preventive enforcement:** Use AWS Organizations **Tag Policies** to require the `data-classification` tag key with allowed values (Public, Internal, Confidential, Restricted) across accounts — Tag Policies are preventive and complement the detective Config rule. 5. Use tag-based IAM policies (via condition keys `aws:ResourceTag/data-classification`) to restrict S3 access based on classification level. 6. Pair with Macie classification jobs (see FS-44) so that buckets automatically classified as containing sensitive data are flagged if their `data-classification` tag is missing or inconsistent with the Macie findings. |
| Reference | [AWS Tagging Best Practices](https://docs.aws.amazon.com/tag-editor/latest/userguide/tagging.html), [AWS Config required-tags Rule](https://docs.aws.amazon.com/config/latest/developerguide/required-tags.html), [AWS Organizations Tag Policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_tag-policies.html) |

---

## Part 3 — Application-Layer Controls & Material Gaps (FS-47 to FS-69)

> **Guide risk categories:** Hallucination (FS-47..50, §1.2.7), Prompt Injection (FS-51..54, §1.2.8), Improper Output Handling (FS-55..58, §1.2.13), Off-Topic & Inappropriate Output (FS-59..60, §1.2.2), Out-of-Date Training Data (FS-61..63, §1.2.10), Additional Controls — Material Gaps (FS-64..69). FS-64 is merged into upstream BR-04 — see the extension note in the Material Gaps section.

### Hallucination (FS-47 to FS-50)

> **Guide source:** §1.2.7 Hallucination. Guide-listed mitigations:
> (a) prompt engineering;
> (b) RAG with Bedrock Knowledge Bases;
> (c) detect hallucinations in RAG and agent-based systems;
> (d) HITL validation for internal AI systems;
> (e) Automated Reasoning checks in Bedrock Guardrails;
> (f) Bedrock Guardrails contextual grounding checks with reference source and query;
> (g) response disclaimers in customer-facing applications informing users that AI responses
> should be verified for critical decisions.

#### FS-47 — Guardrail Grounding Threshold

| Field | Detail |
|-------|--------|
| Severity | High |
| Guide ref | [Guide §1.2.7] — "You can use Amazon Bedrock Guardrails to detect and filter hallucinations in model responses by performing contextual grounding checks when you provide a reference source and query." |
| Description | Verifies guardrail grounding thresholds are set appropriately for financial use cases (this assessment recommends ≥ 0.7; AWS does not prescribe a specific minimum, but the valid range is 0 to 0.99). Note: contextual grounding checks are not supported for conversational chatbot use cases — only for summarization, paraphrasing, and Q&A. |
| Detection | Calls `bedrock:GetGuardrail` and inspects `contextualGroundingPolicy.filters` for the `GROUNDING` filter type. Checks that the `threshold` value is ≥ 0.7. Flags guardrails with lower thresholds or no grounding filter. |
| Remediation | 1. Update the guardrail to set the grounding filter threshold to at least 0.7 (this assessment recommends 0.8 for financial services to reduce hallucination risk — note: AWS does not prescribe a specific minimum, but the valid range is **0 to 0.99**; a value of 1.0 is explicitly invalid and will block all content per AWS documentation). 2. Enable the grounding filter for both the `GROUNDING` and `RELEVANCE` types. 3. Test with prompts that should and should not be grounded in the reference source — tune the threshold based on your false-positive/false-negative tolerance. 4. Monitor grounding filter invocation rates via CloudWatch using the `AWS/Bedrock/Guardrails` namespace. **Important limitation:** Contextual grounding checks support only summarization, paraphrasing, and question-answering use cases — **Conversational QA / Chatbot use cases are explicitly not supported** per AWS documentation. For FinServ chatbot deployments, use denied topics and content filters (FS-28, FS-36, FS-59) as the primary hallucination-mitigation controls instead. |
| Reference | [Bedrock Guardrails Contextual Grounding](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-contextual-grounding-check.html) |

#### FS-48 — RAG Knowledge Base

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.1, §1.2.7, §1.2.10] — "Use Retrieval-Augmented Generation (RAG) to enhance your model responses with information from trusted knowledge bases." Referenced in three separate guide risk sections. |
| Description | Checks active Knowledge Bases are configured for RAG grounding. |
| Detection | Calls `ListKnowledgeBases` (via the `bedrock-agent` boto3 client; IAM action `bedrock:ListKnowledgeBases`) and checks that at least one KB exists with `status=ACTIVE`. Flags accounts with no active KBs when Bedrock models are in use (indicating responses are ungrounded). |
| Remediation | 1. Create a Bedrock Knowledge Base with your authoritative data sources. 2. Configure the KB with an appropriate embedding model and vector store. 3. Use `RetrieveAndGenerate` API instead of direct `InvokeModel` for customer-facing use cases. 4. Sync data sources on a regular schedule. |
| Reference | [Bedrock Knowledge Bases](https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base.html) |

#### FS-49 — Hallucination Disclaimer

| Field | Detail |
|-------|--------|
| Severity | Informational |
| Guide ref | [Guide §1.2.7] — "Implement response disclaimers in customer-facing applications, to inform end users that AI-generated responses should be verified for critical decisions." References "AWS Well-Architected Framework Generative AI Lens - Implement guardrails to mitigate harmful or incorrect model responses". |
| Description | Advisory: verifies application adds hallucination disclaimers to AI-generated outputs. |
| Detection | Advisory check — inspects application Lambda environment variables for disclaimer-related settings. Checks for post-processing Lambda functions that append disclaimers. |
| Remediation | 1. Add a standard disclaimer to all AI-generated responses: "This response is generated by AI and may contain inaccuracies. Please verify critical information independently." 2. Make the disclaimer configurable and non-removable by prompt manipulation. 3. For financial decisions, add: "This does not constitute financial advice." |
| Reference | [AWS Well-Architected GenAI Lens](https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/gensec02-bp01.html) |

#### FS-50 — Relevance Grounding Filters

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.2, §1.2.7] — "Use Amazon Bedrock Guardrails to detect and filter hallucinations in model responses by performing contextual grounding checks." Contextual grounding covers both `GROUNDING` and `RELEVANCE` filter sub-types. |
| Description | Checks guardrails have relevance grounding filters to prevent off-topic responses. |
| Detection | Calls `bedrock:GetGuardrail` and inspects `contextualGroundingPolicy.filters` for the `RELEVANCE` filter type. Flags guardrails with no relevance filter configured. |
| Remediation | 1. Update the guardrail to enable the `RELEVANCE` contextual grounding filter. 2. Set the threshold to at least 0.7 (valid range is **0 to 0.99**; a value of 1.0 is explicitly invalid per AWS documentation). 3. This ensures responses are relevant to the user's query and the provided reference source, filtering out off-topic hallucinations. **Important limitation:** Contextual grounding checks (both `GROUNDING` and `RELEVANCE`) support only summarization, paraphrasing, and question-answering use cases — **Conversational QA / Chatbot use cases are explicitly not supported** per AWS documentation. For FinServ chatbot deployments, use denied topics (FS-59) as the primary off-topic control. |
| Reference | [Bedrock Guardrails Contextual Grounding](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-contextual-grounding-check.html) |

### Prompt Injection (FS-51 to FS-54)

> **Guide source:** §1.2.8 Prompt injection. Guide-listed mitigations:
> (a) prompt engineering best practices to avoid prompt injection;
> (b) input validation — sanitize user input, remove special characters or use escape sequences,
> match expected format;
> (c) secure coding practices — parameterized queries, avoid string concatenation, minimal
> privileges;
> (d) security testing — regular testing for prompt injection and vulnerabilities, pentest,
> static code analysis, DAST;
> (e) stay updated — keep Bedrock SDK, libraries, and dependencies current;
> (f) Bedrock Guardrails to detect and block user inputs attempting to override system
> instructions through prompt attacks.

#### FS-51 — Prompt Attack Filters

| Field | Detail |
|-------|--------|
| Severity | High |
| Guide ref | [Guide §1.2.8] — "Use Amazon Bedrock Guardrails to detect and block user inputs that attempt to override system instructions through prompt attacks." |
| Description | Verifies guardrails have PROMPT_ATTACK content filters enabled and are configured correctly for the Standard tier. |
| Detection | Calls `bedrock:GetGuardrail` and inspects `contentPolicy.filters` for a filter with `type=PROMPT_ATTACK`. Flags guardrails where this filter is absent, has `inputStrength` set to `NONE` or `LOW` (note: PROMPT_ATTACK only applies to inputs — there is no `outputStrength` for this filter type), or where `contentPolicy.tier.tierName=CLASSIC` (the PROMPT_ATTACK filter in Classic tier detects jailbreaks and prompt injection; in Standard tier it additionally detects **prompt leakage** — attempts to extract system prompts or developer instructions). |
| Remediation | 1. Ensure the guardrail is configured with the **Standard** content filters tier — prompt leakage detection (extracting system prompts/developer instructions) is available only in Standard tier; jailbreak and prompt injection detection are available in both tiers. Standard tier requires cross-Region inference to be enabled on the guardrail. You can configure Standard tier on a **new or existing guardrail**: for an existing guardrail, modify it via `UpdateGuardrail` (set `tierConfig.tierName=STANDARD` in `contentPolicyConfig` and add a `crossRegionConfig.guardrailProfileIdentifier`), or use the console by editing the guardrail and selecting Standard tier with cross-Region inference. 2. Add a `PROMPT_ATTACK` content filter with `inputStrength=HIGH`. 3. **Wrap user input in guardrail input tags when using `InvokeModel` or `InvokeModelResponseStream`** — for these APIs, PROMPT_ATTACK only evaluates content enclosed in input tags (e.g., `<amazon-bedrock-guardrails-guardContent_xyz>user text</amazon-bedrock-guardrails-guardContent_xyz>` — the reserved prefix is `amazon-bedrock-guardrails-guardContent` and the suffix should be a unique random string per request to prevent an attacker from closing the tag and appending malicious content). Untagged content is not evaluated for PROMPT_ATTACK when using these APIs. **Note:** When using the `Converse` API, use the `guardContent` field (`GuardrailConverseContentBlock`) in user messages to scope PROMPT_ATTACK evaluation to specific content — this is the Converse API equivalent of input tags. Without `guardContent`, the guardrail evaluates ALL message content (the entire messages array). Using `guardContent` in user messages ensures only user-provided content is evaluated for prompt attacks, while system prompts and conversation history are excluded. If no `guardContent` blocks are present in messages, the guardrail evaluates everything in the messages array. 4. Test with known prompt injection patterns (role-play attacks, instruction override, delimiter injection). 5. Monitor filter invocation rates via CloudWatch guardrail metrics (`InvocationsIntervened` in the `AWS/Bedrock/Guardrails` namespace, filtered by `GuardrailPolicyType=ContentPolicy`) for trending attack patterns. |
| Reference | [Bedrock Guardrails Prompt Attack](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-prompt-attack.html), [Safeguard tiers for guardrails](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-tiers.html), [Securing Amazon Bedrock Agents against indirect prompt injections](https://aws.amazon.com/blogs/machine-learning/securing-amazon-bedrock-agents-a-guide-to-safeguarding-against-indirect-prompt-injections/) |

#### FS-52 — Bedrock SDK Version Currency

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.8] — "Stay Updated – Keep your Amazon Bedrock SDK, libraries, and dependencies current to receive the latest security patches and updates." |
| Description | Checks Bedrock Lambda functions use current (non-deprecated) runtimes and SDK versions. |
| Detection | Calls `lambda:ListFunctions` and filters for functions with Bedrock-related names or environment variables referencing Bedrock. Checks each function's `Runtime` against the list of deprecated Lambda runtimes. |
| Remediation | 1. Update Lambda functions to use a currently supported runtime — as of April 2026, recommended runtimes are `python3.13` or `python3.14` for Python (both deprecation date June 30, 2029; `python3.12` remains supported through Oct 31, 2028), and `nodejs22.x` or `nodejs24.x` for Node.js (`nodejs20.x` reaches deprecation on April 30, 2026 and should not be used for new deployments). 2. Update the Bedrock SDK (boto3/botocore) to the latest version in your requirements.txt or package.json. 3. Test after upgrading to verify no breaking changes. 4. Subscribe to AWS Lambda runtime deprecation notifications via EventBridge or SNS (Lambda also surfaces runtime deprecation notices via AWS Health Dashboard and Trusted Advisor). |
| Reference | [Lambda Runtime Deprecation Policy](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html) |

#### FS-53 — WAF Injection Protection Rules

| Field | Detail |
|-------|--------|
| Severity | High |
| Guide ref | [Guide §1.2.8, extension] — WAF SQLi and known-bad-inputs rule groups are not named in the guide, but implement the guide mitigation "Secure Coding Practices – use parameterized queries, avoid string concatenation for input, grant minimal access privileges" at the network edge for web-facing GenAI endpoints. |
| Description | Verifies WAF ACLs include SQL injection (`AWSManagedRulesSQLiRuleSet`) and known-bad-inputs (`AWSManagedRulesKnownBadInputsRuleSet`) managed rule groups for GenAI endpoints. |
| Detection | Calls `wafv2:ListWebACLs(Scope=REGIONAL)` and for each calls `wafv2:GetWebACL`. Inspects the rules list for `AWSManagedRulesSQLiRuleSet` and `AWSManagedRulesKnownBadInputsRuleSet`. Flags ACLs missing either rule group. |
| Remediation | 1. Add `AWSManagedRulesSQLiRuleSet` to your WAF Web ACL (contains SQLi detection rules for body, URI path, cookie, and query-string components). 2. Add `AWSManagedRulesKnownBadInputsRuleSet` for known Remote Command Execution (RCE) and vulnerability-discovery patterns (e.g., Log4j, Spring Core deserialization, path traversal) — note this rule group does NOT cover XSS; XSS is in `AWSManagedRulesCommonRuleSet` (see FS-56). 3. Set both rule groups to COUNT mode initially, review logs for false positives, then switch to BLOCK. 4. Create custom rules for GenAI-specific injection patterns if needed. |
| Reference | [AWS WAF Managed Rules](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html) |

#### FS-54 — Penetration Testing Evidence

| Field | Detail |
|-------|--------|
| Severity | Informational |
| Guide ref | [Guide §1.2.8] — "Security Testing – Test your applications regularly for prompt injection and other security vulnerabilities. Use penetration testing, static code analysis, and dynamic application security testing (DAST)." |
| Description | Advisory: verifies GenAI applications have been penetration tested for prompt injection and other AI-specific vulnerabilities. |
| Detection | Advisory check — inspects resource tags for `last-pentest-date` or checks for a documented penetration testing schedule. Cannot be fully automated. |
| Remediation | 1. Conduct penetration testing of your GenAI application at least annually and before major releases. 2. Include AI-specific test cases: prompt injection, jailbreak attempts, data extraction, system prompt leakage. 3. Use tools like Garak, PyRIT, manual red-teaming, or the **AWS Security Agent**. As of the March 2026 GA announcement, Security Agent runs from 6 AWS regions (N. Virginia, Oregon, Ireland, Frankfurt, Sydney, Tokyo) but can test targets across AWS, Azure, GCP, and on-premises environments. For multi-account FinServ deployments, Security Agent supports penetration testing on VPC resources **shared across AWS accounts in the same AWS Organization** via AWS Resource Access Manager (RAM) — enable this by launching Security Agent from a central security account and sharing VPC resources from sub-accounts via RAM. **Verify current region coverage on the [AWS Security Agent page](https://aws.amazon.com/security-agent/) before citing**, as AWS has been expanding regional availability and feature set rapidly. 4. Document findings and track remediation. 5. Tag resources with `last-pentest-date` for audit trail. |
| Reference | [AWS Penetration Testing Policy](https://aws.amazon.com/security/penetration-testing/), [AWS Security Agent GA](https://aws.amazon.com/about-aws/whats-new/2026/03/aws-security-agent-ondemand-penetration/) |

### Improper Output Handling (FS-55 to FS-58)

> **Guide source:** §1.2.13 Improper output handling. Guide-listed mitigations:
> (a) implement output validation rules against expected response format (e.g., JSON schema,
> SQL schema);
> (b) apply context-specific output sanitization — HTML encoding for web apps, SQL
> parameterization for database queries, command escaping for system integrations;
> (c) Practical guidance: treat model output as untrusted user input; use Bedrock Agents
> action-group Lambda to implement output encoding so output text is non-executable by
> JavaScript or Markdown.

#### FS-55 — Output Validation Lambda

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.13] — "Implement output validation rules specific to the expected response format. For example, if the AI system is expected to return structured data (JSON, SQL), validate the output against the expected schema before processing." |
| Description | Checks for Lambda functions implementing output validation/sanitization before AI responses reach downstream consumers. |
| Detection | Calls `lambda:ListFunctions` and searches for functions with naming patterns indicating output validation (e.g., "output-valid", "sanitiz", "post-process", "response-filter"). Flags if no such functions exist. |
| Remediation | 1. Implement a post-processing Lambda that validates AI model output before it reaches the end user or downstream system. 2. Validate output against expected schema (JSON schema validation for structured responses). 3. Strip or escape any executable content (HTML tags, JavaScript, SQL fragments). 4. Log rejected outputs for security monitoring. |
| Reference | [OWASP LLM05:2025 Improper Output Handling](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/), [AWS Well-Architected Security Pillar — Application Security](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/application-security.html), [Bedrock Prompt Injection Security](https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-injection.html), [Well-Architected FSI Lens — FSISEC14 Monitor AI system outputs for security issues](https://docs.aws.amazon.com/wellarchitected/latest/financial-services-industry-lens/fsisec14.html) |

#### FS-56 — XSS Prevention WAF

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.13, extension] — WAF XSS rule groups are not named in the guide, but implement the guide mitigation "Apply context-specific output sanitization ... apply HTML encoding for web applications" at the network edge. |
| Description | Verifies WAF ACLs include XSS prevention rules to protect against AI-generated outputs containing malicious scripts. |
| Detection | Calls `wafv2:GetWebACL` for each regional ACL and inspects rules for `AWSManagedRulesCommonRuleSet` (which includes the four `CrossSiteScripting_*` rules covering request body, query arguments, cookies, and URI path) or custom rules using `XssMatchStatement` on request components. Flags ACLs missing XSS protection. |
| Remediation | 1. Add `AWSManagedRulesCommonRuleSet` to your WAF Web ACL (includes `CrossSiteScripting_COOKIE`, `CrossSiteScripting_QUERYARGUMENTS`, `CrossSiteScripting_BODY`, and `CrossSiteScripting_URIPATH` rules — all four inspect **inbound request** components). 2. `XssMatchStatement` and the CRS XSS rules inspect **request** components only (body, query string, URI path, cookies, headers). WAF does NOT inspect arbitrary response bodies for XSS — response inspection (`ResponseInspection`) is available only in `AWSManagedRulesATPRuleSet`/`AWSManagedRulesACFPRuleSet` for CloudFront-protected ACLs and only scans for configured success/failure strings. 3. To protect against XSS in **AI-generated output**, enforce output encoding at the application layer (see FS-57) — rendering raw model output in a browser without encoding is the root cause that WAF cannot mitigate after the fact. 4. Apply output encoding in your application layer as defense-in-depth. |
| Reference | [AWS WAF XSS Protection](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html) |

#### FS-57 — Output Encoding

| Field | Detail |
|-------|--------|
| Severity | Informational |
| Guide ref | [Guide §1.2.13] — "Apply context-specific output sanitization based on the downstream consumer. For example, apply HTML encoding for web applications, SQL parameterization for database queries, and command escaping for system integrations." Practical guidance: "Use Amazon Bedrock Agents to securely integrate with AWS native and third-party services and implement output encoding in the action group Lambda function under an Amazon Bedrock Agent. Encoding all output text presented to end-users makes it automatically non-executable by JavaScript or Markdown." |
| Description | Advisory: verifies application encodes GenAI outputs appropriately for the rendering context (HTML, JSON, SQL). |
| Detection | Advisory check — inspects application Lambda functions for encoding libraries or patterns (e.g., `html.escape`, `json.dumps`, `markupsafe`). Checks environment variables for encoding-related configuration. |
| Remediation | 1. Treat all model output as untrusted user input. 2. Apply context-specific encoding: HTML encoding for web display, SQL parameterization for database queries, command escaping for system integrations. 3. Use Bedrock Agents action-group Lambda functions to implement output encoding — encoding all output text makes it non-executable by JavaScript or Markdown renderers. 4. Never render raw model output in a web page without encoding. |
| Reference | [OWASP Output Encoding](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) |

#### FS-58 — Output Schema Validation

| Field | Detail |
|-------|--------|
| Severity | Informational |
| Guide ref | [Guide §1.2.13] — "Implement output validation rules specific to the expected response format. For example, if the AI system is expected to return structured data (JSON, SQL), validate the output against the expected schema before processing." |
| Description | Checks for structured output validation in GenAI pipelines (JSON schema, XML schema, or custom validators). |
| Detection | Inspects Step Functions state machine definitions for states that perform schema validation (e.g., `Choice` states with JSON path conditions, Lambda states with "schema" or "validate" in the name). Does not rely on API Gateway response models as a validation signal because those are used for SDK generation, not runtime validation. |
| Remediation | 1. Define a JSON schema for expected AI output format. 2. Add a validation step in your pipeline (Lambda function or Step Functions Choice state) that rejects non-conforming outputs **before** returning the response to clients — this is the runtime enforcement point. 3. Note: API Gateway *response models* in REST APIs are used for SDK generation (user-defined data types) and documentation — they do NOT perform runtime validation of response payloads. API Gateway *request validators* only validate inbound requests against request models. To validate AI output at runtime, implement the check in Lambda/Step Functions before the response reaches API Gateway. 4. Return a safe fallback response when validation fails. 5. Log rejected outputs (without leaking sensitive content) for security monitoring. |
| Reference | [API Gateway Request and Response Validation](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-request-validation.html) |

### Off-Topic & Inappropriate Output (FS-59 to FS-60)

> **Guide source:** §1.2.2 Off-topic and inappropriate output. Guide-listed mitigations:
> (a) prompt engineering with an allowlist of approved topics aligned with business purpose;
> (b) content filters and denied topics in Bedrock Guardrails;
> (c) Bedrock Guardrails contextual grounding check with reference source and query;
> (d) HITL validation for internal AI systems.

#### FS-59 — Guardrail Topic Allowlist

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.2] — "Configure content filters and guardrails to restrict model responses to approved topics." The check name uses "allowlist" loosely — implementation uses denied-topic lists to block out-of-scope content. |
| Description | Verifies guardrails restrict GenAI to on-topic financial services responses via denied topics. |
| Detection | Calls `bedrock:GetGuardrail` and inspects `topicPolicy.topics`. Checks that denied topics exist to block off-topic conversations (e.g., politics, entertainment, medical advice). Flags guardrails with no topic restrictions. |
| Remediation | 1. Define denied topics that are outside your business scope (e.g., "medical advice", "legal advice", "political opinions", "entertainment recommendations"). 2. Add these as denied topics in the guardrail with clear descriptions and sample phrases. 3. Test with off-topic prompts to verify they are blocked. 4. Use the system prompt to positively scope the assistant's role. |
| Reference | [Bedrock Guardrails Topic Policies](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-denied-topics.html) |

#### FS-60 — Contextual Grounding for Off-Topic

| Field | Detail |
|-------|--------|
| Severity | Informational |
| Guide ref | [Guide §1.2.2] — "Use prompt engineering techniques to guide the model toward appropriate topics and prevent unwanted responses. Include an allowlist of approved topics aligned with the business purpose." Use of Bedrock Prompt Management for system prompt versioning is an implementation choice. |
| Description | Advisory: verifies system prompts explicitly scope the assistant's role to prevent off-topic responses. |
| Detection | Advisory check — inspects Bedrock Prompt Management templates (via `ListPrompts` on the `bedrock-agent` boto3 client; IAM action `bedrock:ListPrompts`) for system prompt content that defines the assistant's role, scope, and boundaries. Flags if no prompt templates exist. |
| Remediation | 1. Define a clear system prompt that states: the assistant's role, allowed topics, prohibited topics, and response format. 2. Use Bedrock Prompt Management to version and manage system prompts. 3. Include explicit instructions like "You are a financial services assistant. Only answer questions related to [specific topics]. Decline all other requests politely." 4. Test with boundary-case prompts. |
| Reference | [Bedrock Prompt Management](https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-management.html) |

### Out-of-Date Training Data (FS-61 to FS-63)

> **Guide source:** §1.2.10 Out-of-date training data. Guide-listed mitigations:
> (a) RAG with Bedrock Knowledge Bases;
> (b) keep knowledge bases up to date (sync data sources);
> (c) HITL validation for internal AI systems;
> (d) data currency disclaimers in AI system responses; source attribution via
> RetrieveAndGenerate API for users to verify currency.

#### FS-61 — Knowledge Base Sync Schedule

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.10] — "Keep your knowledge bases up to date." Automated scheduling via EventBridge operationalises this mitigation. |
| Description | Checks EventBridge Scheduler or EventBridge rules automate KB data source sync on a regular schedule. |
| Detection | Calls `events:ListRules` and searches for rules with targets that invoke `StartIngestionJob` (IAM action `bedrock:StartIngestionJob`) or Lambda functions that trigger KB sync. Also checks AWS Scheduler (`scheduler:ListSchedules`) for schedules targeting KB sync. Flags if no scheduled sync mechanism exists. |
| Remediation | 1. Use **EventBridge Scheduler** (the current recommended approach — EventBridge scheduled rules are a legacy feature) to create a recurring schedule that triggers KB data source sync: create a schedule with a rate expression (e.g., `rate(1 day)`) or cron expression (e.g., `cron(0 2 * * ? *)`) targeting a Lambda function. 2. The Lambda function calls `StartIngestionJob` (IAM action `bedrock:StartIngestionJob`) for each data source. 3. Add error handling and CloudWatch alarms for failed syncs. |
| Reference | [EventBridge Scheduler](https://docs.aws.amazon.com/scheduler/latest/UserGuide/what-is-scheduler.html), [EventBridge Scheduled Rules (legacy)](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-rule-schedule.html) |

#### FS-62 — Data Currency Disclaimer

| Field | Detail |
|-------|--------|
| Severity | Informational |
| Guide ref | [Guide §1.2.10] — "Include data currency disclaimers in AI system responses where appropriate. Use source attribution in RAG-based response for end users to verify currency of information." |
| Description | Advisory: verifies application adds data currency disclaimers to AI-generated outputs. |
| Detection | Advisory check — inspects application configuration for data-currency disclaimer settings. Checks system prompts for instructions to include data freshness information. |
| Remediation | 1. Add a data currency disclaimer to responses: "This information is based on data available as of [date]. It may not reflect the most recent changes." 2. Use the `RetrieveAndGenerate` API's source attribution to display document dates. 3. Configure the system prompt to instruct the model to caveat time-sensitive information. |
| Reference | [Bedrock RetrieveAndGenerate API](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_RetrieveAndGenerate.html) |

#### FS-63 — Foundation Model Lifecycle Policy

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.10, extension] — FM currency is conceptually related to "out-of-date training data" but the specific Bedrock lifecycle-status check is not named in the guide. The guide's "1.1.6 Monitor and improve" general guidance says "Update your foundation models when new versions become available" — this FS check operationalises that guidance. See also FS-34 (TPRM) which the guide places under §1.2.12. |
| Description | Checks for a model lifecycle management process and Config rules to ensure models are updated when new versions are available. |
| Detection | Calls `config:DescribeConfigRules` and searches for rules targeting Bedrock resources. Calls `bedrock:GetFoundationModel` for each model in use and inspects `modelLifecycle.status`. Flags models with status `LEGACY` (note: the Bedrock API exposes only two lifecycle status values — `ACTIVE` and `LEGACY`; models past their `endOfLifeTime` are removed from the service entirely and return a ResourceNotFound error, so any model still reachable via the API that is not `ACTIVE` will be `LEGACY`). |
| Remediation | 1. Create an AWS Config custom rule that flags Bedrock models with `modelLifecycle.status=LEGACY`. 2. Establish a model lifecycle policy: evaluate new model versions within 30 days of release, test in staging, migrate production within 90 days (and before the `endOfLifeTime` published in the Bedrock model lifecycle page). 3. Subscribe to AWS Bedrock model lifecycle notifications. 4. Document the policy and assign an owner. 5. **Budget planning for FinServ:** For models with EOL dates after February 1, 2026, after a minimum of 3 months in Legacy state a model enters a **public extended access period** during which the model provider may set higher pricing. The `publicExtendedAccessTime` timestamp in the `FoundationModelLifecycle` response indicates when this phase begins. Include this phase in contract-and-budget review so FinServ cost governance teams are aware of potential price changes before migrating off Legacy models. |
| Reference | [Bedrock Model Lifecycle](https://docs.aws.amazon.com/bedrock/latest/userguide/model-lifecycle.html) |

### Additional Controls — Material Gaps (FS-64 to FS-69)

These checks address mitigations explicitly called out in the Responsible AI GRC guide that were
not covered by the original checks in the upstream AIML Security Assessment (BR/SM/AC).
FS-64 is merged into upstream BR-04 (see extension note below); FS-65 to FS-69 ship as
standalone checks.

#### FS-64 — Guardrail Trace Logging → *Merged into upstream BR-04*

> **Upstream extension note (do not ship as a standalone check):** The detection and remediation
> content from FS-64 should be added as a refinement of the existing **BR-04 (Model Invocation
> Logging)** check in the upstream repo.
>
> **What to add to BR-04:**
> - After verifying that `bedrock:GetModelInvocationLoggingConfiguration` shows logging is
>   enabled, additionally verify the log output captures **guardrail trace data**: when
>   guardrails are applied during inference, the invocation log contains a `guardrailTrace`
>   object with `action` (values: `INTERVENED` or `NONE`), `inputAssessments`, and
>   `outputAssessments` arrays detailing which policies were evaluated and their results.
> - **Important logging coverage gap:** Model invocation logging only captures calls made through the `bedrock-runtime` endpoint (`Converse`, `ConverseStream`, `InvokeModel`, `InvokeModelWithResponseStream`). Calls made through the `bedrock-mantle` endpoint (e.g., the Responses API) are **not currently captured** by invocation logging. If your application uses the Responses API, implement application-level logging as a compensating control.
> - Add a remediation note on **retention requirements**: NYDFS 23 NYCRR 500.06 explicitly
>   requires cybersecurity records for ≥ 5 years; SR 11-7 does not prescribe a specific period
>   but requires documentation be maintained for the duration of model use plus a reasonable
>   period thereafter (commonly met with 5–7 year retention per firm policy). Consult your
>   compliance and records-management team for exact requirements.
> - Suggest creating CloudWatch Metrics filters to track guardrail intervention rates (filter
>   on `guardrailTrace.action = INTERVENED`) and applying CloudWatch Logs data protection
>   policies to mask PII in traces.
> - Guide traceability: [Guide §1.2.1] — "Maintain audit logs of AI-generated outputs and the
>   guardrails applied to support regulatory reporting and post-incident analysis." Also
>   §1.2.9 — "Implement audit logging of all actions taken by AI agents."
>
> **Reference:** [Bedrock Model Invocation Logging](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html)

#### FS-65 — KB Data Source S3 Event Notifications

| Field | Detail |
|-------|--------|
| Severity | High (deleted bucket) / Medium (notifications) |
| Guide ref | [Guide §1.2.3] — "Use integrity monitoring on knowledge base data sources to detect unauthorized modifications... For example on S3 data sources use Amazon S3 event notification to track changes to documents." **Note:** This check overlaps with FS-33; FS-33 verifies notifications are *enabled* on the bucket, while FS-65 verifies that notifications are *routed to an alerting destination* (SNS/Lambda/EventBridge rule with a target). In the final PR to aws-samples these two checks may be consolidated into a single check at the reviewer's discretion. |
| Description | Checks that S3 event notifications on KB data-source buckets are routed to an alerting destination (EventBridge rule with SNS/Lambda target, or direct SNS/SQS/Lambda notification) — not just enabled with no consumer. |
| Detection | Identifies KB data-source S3 buckets via `ListDataSources` and `GetDataSource` (via the `bedrock-agent` boto3 client; IAM actions `bedrock:ListDataSources` and `bedrock:GetDataSource`). For each bucket, calls `s3:GetBucketNotificationConfiguration` and checks for the presence of `EventBridgeConfiguration`, `TopicConfigurations`, `QueueConfigurations`, or `LambdaFunctionConfigurations`. Flags buckets with no notifications configured. |
| Remediation | 1. Enable EventBridge notifications on each KB data-source bucket: `aws s3api put-bucket-notification-configuration --bucket <name> --notification-configuration '{"EventBridgeConfiguration":{}}'`. 2. Create an EventBridge rule matching S3 event detail types `"Object Created"` and `"Object Deleted"` for the bucket (note: when S3 sends events to **EventBridge**, the event detail types are `Object Created`/`Object Deleted`; the `s3:ObjectCreated:*` and `s3:ObjectRemoved:*` wildcard names are used only for **direct** SNS/SQS/Lambda notification configurations, not for EventBridge rule patterns). 3. Route events to an SNS topic or Lambda function for alerting. 4. Integrate alerts into your security incident response workflow. |
| Reference | [S3 EventBridge Integration](https://docs.aws.amazon.com/AmazonS3/latest/userguide/EventBridge.html) |

#### FS-66 — AgentCore End-User Identity Propagation

| Field | Detail |
|-------|--------|
| Severity | High |
| Guide ref | [Guide §1.2.6 — Practical guidance] — "1. Implement least privilege for identities associated with agents and tool services. 2. Where supported by the tool service ensure that communications to tool services or agents are authorized by the end user. 3. Customers building their own tool services should consider propagating end-user identities separately; ensuring these identities can be validated and are not revealed to unauthorized third parties." |
| Description | Verifies AgentCore runtimes are configured to propagate end-user identities to downstream tool services, ensuring tool calls are authorized by the originating user and not solely by the agent execution role. |
| Detection | Calls `ListAgentRuntimes` (via the `bedrock-agentcore-control` boto3 client; IAM action `bedrock-agentcore:ListAgentRuntimes`) and inspects each runtime's `authorizerConfiguration.customJWTAuthorizer` for a `discoveryUrl` and allowed audiences/clients/scopes. Flags runtimes with no JWT authorizer (meaning inbound calls carry no verifiable end-user identity), and advises configuring outbound OAuth for downstream tool services. |
| Remediation | 1. Configure a custom JWT inbound authorizer on each AgentCore runtime: specify `discoveryUrl`, `allowedAudience`, `allowedClients`, and optional required custom claims. 2. Propagate the end-user's identity via the `X-Amzn-Bedrock-AgentCore-Runtime-User-Id` header and JWT token in the `Authorization` header when calling downstream tool services. **Important:** Invoking `InvokeAgentRuntime` with the `X-Amzn-Bedrock-AgentCore-Runtime-User-Id` header requires the distinct IAM action `bedrock-agentcore:InvokeAgentRuntimeForUser` in addition to `bedrock-agentcore:InvokeAgentRuntime`. Only trusted principals should hold this permission — scope it to specific runtime resources with IAM resource conditions, never via wildcard. For runtimes that do not need user-id delegation, explicitly **deny** `bedrock-agentcore:InvokeAgentRuntimeForUser` to prevent the header from being accepted. Additionally, derive the user-id from the authenticated principal's context (IAM caller identity or JWT claims) rather than from arbitrary client-supplied values to prevent user impersonation, and log the relationship between the authenticated IAM principal (via CloudTrail's SigV4 context) and the `user-id` value passed. 3. Configure outbound OAuth 2.0 for agents accessing third-party resources on behalf of the user. 4. Ensure tool services validate the propagated JWT before executing actions. 5. Implement agent identity segregation: assign distinct identities to each sub-agent in multi-agent workflows so actions are separately attributable. 6. Apply a maker-checker pattern for critical financial actions — require a second agent or human to verify before execution. 7. Do not log or expose propagated identity tokens to unauthorized third parties. |
| Reference | [Configure Inbound JWT Authorizer](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/inbound-jwt-authorizer.html), [Inbound and Outbound Auth](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-oauth.html) |

#### FS-67 — Agent Financial Transaction Value Thresholds

| Field | Detail |
|-------|--------|
| Severity | High |
| Guide ref | [Guide §1.2.9] — "Enforce transaction value thresholds and action boundaries on agent tool calls (for example to cap financial transaction amounts)." |
| Description | Checks AgentCore Policy Engine (attached to Gateways) or action-group Lambda functions enforce maximum transaction-value limits (e.g., cap on financial amounts an agent can initiate) to prevent runaway or unauthorized high-value transactions. |
| Detection | (a) Calls `ListGateways` (via the `bedrock-agentcore-control` boto3 client; IAM action `bedrock-agentcore:ListGateways`) and for each inspects attached Policy Engine Cedar policies for transaction-value constraints (policies referencing amount, limit, or threshold context attributes). (b) Calls `lambda:ListFunctions` and filters for agent action-group Lambda functions. Inspects each function's environment variables for threshold-related keys (e.g., `MAX_TRANSACTION_AMOUNT`, `TRANSACTION_LIMIT`). Flags gateways and functions with no threshold configuration. |
| Remediation | 1. Add transaction-value threshold environment variables to each agent action-group Lambda (e.g., `MAX_TRANSACTION_AMOUNT=10000`). 2. Implement threshold enforcement logic in the Lambda handler that rejects or escalates transactions exceeding the limit. 3. Author Cedar policies in the AgentCore Policy Engine that evaluate tool-call context attributes (amount, currency, tool) and deny calls exceeding defined limits. 4. Route transactions exceeding thresholds to a human-in-the-loop approval step via Step Functions callback pattern. |
| Reference | [Policy in AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html), [AgentCore Example Policies](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/example-policies.html) |

#### FS-68 — API Gateway Request Body Size Limits

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.11] — "To protect your API endpoints, set maximum length limits for input requests when you use large language models (LLMs) directly or through Amazon Bedrock." |
| Description | Verifies API Gateway REST/HTTP APIs fronting GenAI endpoints have WAF `SizeConstraintStatement` rules enforcing a maximum request body size, optionally paired with an API Gateway request-body JSON schema that bounds individual field lengths — to prevent token-exhaustion attacks via oversized prompts. |
| Detection | Calls `apigateway:GetRestApis` and for each calls `apigateway:GetRequestValidators` to check for validators (validators enforce parameter-existence and request-body JSON schema conformance — not total body size). Calls `wafv2:GetWebACL` for associated ACLs and inspects rules for `SizeConstraintStatement` targeting the request body. Flags APIs with no WAF `SizeConstraintStatement` on body, since that is the only AWS-native mechanism that enforces a custom maximum body size in front of API Gateway. |
| Remediation | 1. **Primary control — WAF `SizeConstraintStatement`:** Add a WAF `SizeConstraintStatement` rule on your regional Web ACL that blocks requests whose body size exceeds your maximum allowed prompt length (e.g., 32 KB). Verify that the Web ACL's `AssociationConfig.RequestBody.DefaultSizeInspectionLimit` is set high enough (16 KB default; can be increased to 32/48/64 KB) so WAF can actually inspect bodies at the size you are enforcing against — if the inspection limit is lower than the `SizeConstraintStatement` threshold, oversized requests fall through to oversize handling instead of the rule. This is the only AWS-native way to enforce a custom maximum body size before requests reach API Gateway. 2. **Secondary control — API Gateway request validation:** Add an API Gateway request validator with a request-body model (JSON schema). Request validators do **not** enforce total body size, but a JSON schema can constrain individual string fields with `maxLength` and arrays with `maxItems`, which indirectly bounds payload content. Note API Gateway REST APIs also enforce a service-level hard limit of 10 MB per request (6 MB when integrated with Lambda) that you cannot lower. 3. Set the `max_tokens` parameter in Bedrock API calls to cap output length. 4. Implement client-side token counting before submitting requests. |
| Reference | [WAF Size Constraint](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-size-constraint-match.html), [WAF Body Inspection Size Limit](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-setting-body-inspection-limit.html), [API Gateway Request Validation](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-request-validation.html) |

#### FS-69 — Prompt Input Validation Function

| Field | Detail |
|-------|--------|
| Severity | Medium |
| Guide ref | [Guide §1.2.8] — "Input Validation – Before you send user input to Amazon Bedrock or the tokenizer, validate and sanitize it by removing special characters or using escape sequences. Make sure the input matches your expected format." |
| Description | Checks for a Lambda function or API Gateway request validator that sanitizes user prompt input (strips special characters, enforces expected format, rejects oversized inputs) before forwarding to Bedrock, complementing WAF-level controls. |
| Detection | Calls `lambda:ListFunctions` and searches for functions with input-validation naming patterns (e.g., "sanitiz", "validat", "input-filter", "prompt-guard", "preprocess"). Flags if no such functions exist. |
| Remediation | 1. Implement a Lambda authorizer or pre-processing function that: strips or escapes special characters from user input; validates input against an expected format (e.g., regex allowlist); rejects inputs exceeding maximum token/character limits; logs rejected inputs for security monitoring. 2. Use parameterized prompt templates (Bedrock Prompt Management) instead of string concatenation. 3. Apply Bedrock Guardrails PROMPT_ATTACK filter as a complementary control. 4. Integrate the validation function as an API Gateway Lambda authorizer or Step Functions pre-processing step. 5. Implement schema validation for all tool interactions — validate both inputs to and outputs from tools against defined JSON schemas per AWS Prescriptive Guidance for tool integration security. 6. Enforce TLS for all remote tool communications. |
| Reference | [Bedrock Prompt Injection Security](https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-injection.html), [Security Best Practices for Tool Integration](https://docs.aws.amazon.com/prescriptive-guidance/latest/agentic-ai-frameworks/security-best-practices-for-tool-integration.html) |
