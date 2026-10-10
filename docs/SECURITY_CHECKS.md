# Security Checks Reference

This document provides a comprehensive reference for all 208 security checks performed by the AI/ML Security Assessment framework (94 core checks across Amazon Bedrock, Amazon SageMaker AI, Amazon Bedrock AgentCore, and AWS Agent Registry, up to 38 Agentic AI Security checks, 64 Responsible AI GRC checks, and 12 OWASP Top 10 for LLM checks).

Sources differ by assessment area and are not interchangeable: the core Bedrock, SageMaker, AgentCore, and AWS Agent Registry checks derive from the AWS Well-Architected **Generative AI Lens** security best practices (`gensec*`) and service security documentation; the Agentic AI Security checks from the AWS Well-Architected **Agentic AI Lens**; the `FS-*` **Responsible AI GRC** checks from the AWS GRC User Guide; and the `OW-*` checks from the OWASP Top 10 for LLM. The AWS Well-Architected **Responsible AI Lens** is not a source for any of them — see [Responsible AI GRC — scope, sources, and compatibility](RESPONSIBLE_AI_GRC_SCOPE.md).

The 64 Responsible AI GRC checks occupy 69 `FS-*` numbers: 64 ship as standalone checks and 5 are merged into upstream Bedrock/SageMaker checks. The framework also emits `BR-00`, `SM-00`, `AC-00`, `AR-00`, `FS-00`, and `OW-00` operational marker rows at runtime; these are not controls and are excluded from the 208-check total. Per-control provenance, including which controls are project extensions rather than guide-derived, is recorded in [`provenance.json`](../aiml-security-assessment/functions/security/responsible_ai_grc_assessments/provenance.json).

The counts above describe the full catalog. Core service assessments are enabled
by default and can be selected independently with the four
[`Enable*Assessment` switches](../README.md#selecting-service-assessments).
Deselected services produce no findings and appear as **Not selected** in the
report; this is not an N/A finding or a compliant result. Agentic AI and OWASP
mapping coverage decreases when their direct-service sources are deselected.

## Table of Contents

- [Check Index](#check-index)
- [Overview](#overview)
- [Check ID Convention](#check-id-convention)
- [Report Scoring](#report-scoring)
- [Severity Levels](#severity-levels)
- [Status Values](#status-values)
- [Amazon Bedrock Security Checks (40)](#amazon-bedrock-security-checks-40)
- [Amazon SageMaker AI Security Checks (29)](#amazon-sagemaker-ai-security-checks-29)
- [Amazon Bedrock AgentCore Security Checks (17)](#amazon-bedrock-agentcore-security-checks-17)
- [AWS Agent Registry Security Checks (8)](#aws-agent-registry-security-checks-8)
- [Agentic AI Security Checks (38)](#agentic-ai-security-checks-38)
- [Responsible AI GRC Checks (64 additional, 5 upstream extensions)](#responsible-ai-grc-checks-64-additional-5-upstream-extensions)
- [OWASP Top 10 for LLM Checks (12)](#owasp-top-10-for-llm-checks-12)
- [Additional Resources](#additional-resources)

---

## Check Index

Expand a service to list its checks; each ID links to the full entry. Agentic AI checks are listed in the [Agentic AI table](#mapped-agentic-ai-checks), Responsible AI GRC checks in [`SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md`](./SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md), and OWASP checks in [`SECURITY_CHECKS_OWASP.md`](./SECURITY_CHECKS_OWASP.md).

<details><summary>Amazon Bedrock (40 checks: BR-01 to BR-40)</summary>

| ID | Title | Severity |
| -- | ----- | -------- |
| [BR-01](#br-01-aws-iam-least-privilege) | AWS IAM Least Privilege | High |
| [BR-02](#br-02-amazon-vpc-endpoint-configuration) | Amazon VPC Endpoint Configuration | Medium |
| [BR-03](#br-03-marketplace-subscription-access) | Marketplace Subscription Access | High |
| [BR-04](#br-04-model-invocation-logging) | Model Invocation Logging | Medium |
| [BR-05](#br-05-guardrail-configuration) | Guardrail Configuration | Medium |
| [BR-06](#br-06-aws-cloudtrail-logging) | AWS CloudTrail Logging | High |
| [BR-07](#br-07-prompt-management) | Prompt Management | Low |
| [BR-08](#br-08-agent-aws-iam-configuration) | Agent AWS IAM Configuration | High |
| [BR-09](#br-09-knowledge-base-encryption) | Knowledge Base Encryption | Informational (manual review) |
| [BR-10](#br-10-guardrail-aws-iam-enforcement) | Guardrail AWS IAM Enforcement | High |
| [BR-11](#br-11-custom-model-encryption) | Custom Model Encryption | Medium |
| [BR-12](#br-12-invocation-log-encryption) | Invocation Log Encryption | Medium |
| [BR-13](#br-13-flows-guardrails) | Flows Guardrails | High |
| [BR-14](#br-14-stale-bedrock-access) | Stale Bedrock Access | Medium (not currently emitted) |
| [BR-15](#br-15-cross-account-guardrails-enforcement) | Cross-Account Guardrails Enforcement | High |
| [BR-16](#br-16-guardrail-tier-validation) | Guardrail Tier Validation | Medium |
| [BR-17](#br-17-custom-model-customer-managed-kms-encryption) | Custom Model Customer-Managed KMS Encryption | High |
| [BR-18](#br-18-model-evaluation-implementation) | Model Evaluation Implementation | Medium |
| [BR-19](#br-19-prompt-flow-validation) | Prompt Flow Validation | Medium |
| [BR-20](#br-20-knowledge-base-encryption-enhancement) | Knowledge Base Encryption Enhancement | High |
| [BR-21](#br-21-agent-action-group-iam-least-privilege) | Agent Action Group IAM Least Privilege | High |
| [BR-22](#br-22-model-invocation-throttling-limits) | Model Invocation Throttling Limits | Medium |
| [BR-23](#br-23-guardrail-content-filter-coverage) | Guardrail Content Filter Coverage | High |
| [BR-24](#br-24-automated-reasoning-policy-implementation) | Automated Reasoning Policy Implementation | Medium |
| [BR-25](#br-25-rag-evaluation-jobs) | RAG Evaluation Jobs | Low |
| [BR-26](#br-26-guardrail-sensitive-information-filter) | Guardrail Sensitive Information Filter | High |
| [BR-27](#br-27-guardrail-contextual-grounding-check) | Guardrail Contextual Grounding Check | Medium |
| [BR-28](#br-28-agent-guardrail-association) | Agent Guardrail Association | High |
| [BR-29](#br-29-agent-idle-session-ttl) | Agent Idle Session TTL | Low |
| [BR-30](#br-30-imported-model-customer-managed-kms-encryption) | Imported Model Customer-Managed KMS Encryption | High |
| [BR-31](#br-31-batch-inference-output-encryption) | Batch Inference Output Encryption | Medium |
| [BR-32](#br-32-cloudwatch-alarms-on-bedrock-metrics) | CloudWatch Alarms on Bedrock Metrics | Medium |
| [BR-33](#br-33-amazon-inspector-lambda-code-scanning) | Amazon Inspector Lambda Code Scanning | Medium |
| [BR-34](#br-34-guardrail-prompt-attack-filter) | Guardrail Prompt Attack Filter | High |
| [BR-35](#br-35-guardrail-image-content-filter-coverage) | Guardrail Image Content Filter Coverage | Informational |
| [BR-36](#br-36-application-inference-profile-governance) | Application Inference Profile Governance | Low |
| [BR-37](#br-37-bedrock-account-data-retention) | Bedrock Account Data Retention | High for provider sharing or an explicitly required zero-data-retention violation |
| [BR-38](#br-38-automated-reasoning-policy-cmk-encryption) | Automated Reasoning Policy CMK Encryption | Medium |
| [BR-39](#br-39-marketplace-model-endpoint-vpc-configuration) | Marketplace Model Endpoint VPC Configuration | High |
| [BR-40](#br-40-marketplace-model-endpoint-cmk-encryption) | Marketplace Model Endpoint CMK Encryption | Medium by default |

</details>

<details><summary>Amazon SageMaker AI (29 checks: SM-01 to SM-30)</summary>

| ID | Title | Severity |
| -- | ----- | -------- |
| [SM-01](#sm-01-internet-access) | Internet Access | High |
| [SM-02](#sm-02-aws-iam-permissions) | AWS IAM Permissions | High for full access; Medium for stale users and domain authentication |
| [SM-03](#sm-03-data-protection) | Data Protection | High for missing KMS keys; Medium for network encryption; Low for AWS managed keys |
| [SM-04](#sm-04-amazon-guardduty-integration) | Amazon GuardDuty Integration | High |
| [SM-05](#sm-05-mlops-features) | MLOps Features | Low; Medium for feature groups not in `Created` state |
| [SM-06](#sm-06-clarify-usage) | Clarify Usage | High |
| [SM-07](#sm-07-model-monitor) | Model Monitor | Medium |
| [SM-08](#sm-08-model-registry) | Model Registry | Low |
| [SM-09](#sm-09-notebook-root-access) | Notebook Root Access | High |
| [SM-10](#sm-10-notebook-amazon-vpc-deployment) | Notebook Amazon VPC Deployment | High |
| [SM-11](#sm-11-model-network-isolation) | Model Network Isolation | High |
| [SM-12](#sm-12-endpoint-instance-count) | Endpoint Instance Count | Medium |
| [SM-13](#sm-13-monitoring-network-isolation) | Monitoring Network Isolation | Medium |
| [SM-14](#sm-14-model-container-repository) | Model Container Repository | Medium |
| [SM-15](#sm-15-feature-store-encryption) | Feature Store Encryption | Medium |
| [SM-16](#sm-16-data-quality-encryption) | Data Quality Encryption | Medium |
| [SM-17](#sm-17-processing-job-encryption) | Processing Job Encryption | Medium |
| [SM-18](#sm-18-transform-job-encryption) | Transform Job Encryption | Medium |
| [SM-19](#sm-19-hyperparameter-tuning-encryption) | Hyperparameter Tuning Encryption | Medium |
| [SM-20](#sm-20-compilation-job-encryption) | Compilation Job Encryption | Medium |
| [SM-21](#sm-21-automl-network-isolation) | AutoML Network Isolation | Medium |
| [SM-22](#sm-22-model-approval-workflow) | Model Approval Workflow | Medium; Low for pending-approval backlog |
| [SM-23](#sm-23-model-drift-detection) | Model Drift Detection | Medium; Low for incomplete monitoring |
| [SM-24](#sm-24-ab-testing-and-shadow-deployment) | A/B Testing and Shadow Deployment | Informational (advisory) |
| [SM-25](#sm-25-ml-lineage-tracking) | ML Lineage Tracking | Low |
| [SM-26](#sm-26-guardduty-ai-protection) | GuardDuty AI Protection | High |
| [SM-27](#sm-27-hyperpod-ebs-cmk-encryption) | HyperPod EBS CMK Encryption | Medium |
| [SM-28](#sm-28-hyperpod-vpc-configuration) | HyperPod VPC Configuration | Medium |
| [SM-30](#sm-30-model-package-group-resource-policy-exposure) | Model Package Group Resource Policy Exposure | High for public or configured-boundary violations; Informational `Passed` for unclassified external sharing |

</details>

<details><summary>Amazon Bedrock AgentCore (17 checks: AC-01 to AC-17)</summary>

| ID | Title | Severity |
| -- | ----- | -------- |
| [AC-01](#ac-01-runtime-amazon-vpc-configuration) | Runtime Amazon VPC Configuration | High for `PUBLIC` network mode; Medium for a runtime subnet with an internet gateway route |
| [AC-02](#ac-02-aws-iam-full-access) | AWS IAM Full Access | High |
| [AC-03](#ac-03-stale-access) | Stale Access | Medium for 60+ day inactivity; Low when all principals are active; Informational when never used or incomplete |
| [AC-04](#ac-04-observability) | Observability | Medium |
| [AC-05](#ac-05-amazon-ecr-repository-encryption) | Amazon ECR Repository Encryption | High for an unencrypted repository; Low for `AES256` (AWS-managed keys) |
| [AC-06](#ac-06-browser-tool-recording) | Browser Tool Recording | Medium |
| [AC-07](#ac-07-memory-encryption) | Memory Encryption | Medium |
| [AC-08](#ac-08-amazon-vpc-endpoints) | Amazon VPC Endpoints | High when no AgentCore endpoint exists; Medium when an endpoint is not `available` |
| [AC-09](#ac-09-service-linked-role) | Service-Linked Role | Medium |
| [AC-10](#ac-10-resource-based-policies) | Resource-Based Policies | High |
| [AC-11](#ac-11-policy-engine-encryption) | Policy Engine Encryption | High |
| [AC-12](#ac-12-gateway-encryption) | Gateway Encryption | Low |
| [AC-13](#ac-13-gateway-configuration) | Gateway Configuration | Medium |
| [AC-14](#ac-14-identity-token-vault-cmk-encryption) | Identity Token Vault CMK Encryption | High |
| [AC-15](#ac-15-code-interpreter-network-isolation) | Code Interpreter Network Isolation | High |
| [AC-16](#ac-16-custom-browser-network-isolation) | Custom Browser Network Isolation | High |
| [AC-17](#ac-17-online-evaluation-coverage) | Online Evaluation Coverage | Informational by default; Medium when required |

</details>

<details><summary>AWS Agent Registry (8 checks: AR-01 to AR-08)</summary>

| ID | Title | Severity |
| -- | ----- | -------- |
| [AR-01](#ar-01-aws-iam-full-access) | AWS IAM Full Access | High |
| [AR-02](#ar-02-stale-access) | Stale Access | Medium for 60+ day inactivity; Low when all principals are active; Informational when never used or incomplete |
| [AR-03](#ar-03-registry-publication-approval-governance) | Registry Publication Approval Governance | Informational by default; Medium when required |
| [AR-04](#ar-04-registry-discovery-authorization) | Registry Discovery Authorization | Informational for configured authorizers; High for an unconstrained custom JWT authorizer |
| [AR-05](#ar-05-registry-customer-managed-kms-encryption) | Registry Customer-Managed KMS Encryption | Informational by default; Medium when required |
| [AR-06](#ar-06-registry-organization-auto-detection) | Registry Organization Auto-Detection | Medium when active; otherwise Informational |
| [AR-07](#ar-07-registry-record-lifecycle-governance) | Registry Record Lifecycle Governance | Informational |
| [AR-08](#ar-08-registry-record-provenance) | Registry Record Provenance | Medium |

</details>

---

## Overview

The framework evaluates your AI/ML workloads against AWS security best practices across seven assessment areas: four direct service assessments, the synthesized Agentic AI Security lens, and two optional compliance areas. Each direct service assessment can be turned on or off individually; see [Selecting Service Assessments](../README.md#selecting-service-assessments).

| Assessment area | Checks | Controlled by (default) | Focus areas |
| --------------- | ------ | ----------------------- | ----------- |
| [Amazon Bedrock](#amazon-bedrock-security-checks-40) | 40 | `EnableBedrockAssessment` (`true`) | Guardrails, IAM, encryption, networking, logging, evaluation, and Marketplace endpoints |
| [Amazon SageMaker AI](#amazon-sagemaker-ai-security-checks-29) | 29 | `EnableSageMakerAssessment` (`true`) | Security Hub controls, encryption, network isolation, GuardDuty, HyperPod, and MLOps |
| [Amazon Bedrock AgentCore](#amazon-bedrock-agentcore-security-checks-17) | 17 | `EnableAgentCoreAssessment` (`true`) | Runtime and tool isolation, IAM, encryption, observability, and online evaluation |
| [AWS Agent Registry](#aws-agent-registry-security-checks-8) | 8 | `EnableAgentRegistryAssessment` (`true`) | IAM access, approval and discovery governance, encryption, and record provenance |
| [Agentic AI Security](#agentic-ai-security-checks-38) | Up to 38 | Derived from the selected Bedrock, AgentCore, and Agent Registry assessments | Agentic AI Lens view of Bedrock, AgentCore, and Registry evidence, plus AgentCore gateway checks |
| [Responsible AI GRC](#responsible-ai-grc-checks-64-additional-5-upstream-extensions) | 64 | `EnableResponsibleAIGRCAssessment` (`false`) | AI governance, risk, and compliance controls across 15 risk categories |
| [OWASP Top 10 for LLM](#owasp-top-10-for-llm-checks-12) | 12 | `EnableOWASPAssessment` (`false`) | LLM01 through LLM10, mapped from existing findings plus two native LLM07 checks |

---

## Check ID Convention

Each security check has a unique identifier with a service prefix:

| Prefix | Service | Example |
| -------- | --------- | --------- |
| **SM-XX** | Amazon SageMaker AI | SM-01, SM-30 (`SM-29` reserved) |
| **BR-XX** | Amazon Bedrock | BR-01, BR-40 |
| **AC-XX** | Amazon Bedrock AgentCore | AC-01, AC-17 |
| **AR-XX** | AWS Agent Registry | AR-01, AR-08 |
| **AG-XX** | Agentic AI Security | AG-01, AG-38 |
| **FS-XX** | Responsible AI GRC | FS-01, FS-69 |
| **OW-XX** | OWASP Top 10 for LLM | OW-01, OW-12 |

### Runtime marker IDs (not controls)

The `*-00` rows below make assessment coverage and execution problems visible in
CSV and HTML reports. They are operational markers rather than security
controls, do not increase the published check counts, and must not be treated as
evidence that a control passed or failed.

| Marker | Runtime meaning | Normal status / severity |
| -------- | --------------- | ------------------------ |
| `BR-00` | Amazon Bedrock is unavailable or not enabled in the target region, so regional Bedrock checks were not run. | `N/A` / Informational |
| `SM-00` | Amazon SageMaker AI is unavailable or not enabled in the target region, so regional SageMaker checks were not run. | `N/A` / Informational |
| `AC-00` | Amazon Bedrock AgentCore is unavailable in the target region, or the Runtime availability probe rejected the assessment credentials before regional checks could run. Unexpected errors inside individual checks use their affected `AC-*` or `AG-*` control IDs instead. | `N/A` / Informational |
| `AR-00` | AWS Agent Registry is unavailable in the target region. `AR-03` through `AR-06` each also report an `N/A` unavailable row, and the record checks `AR-07` and `AR-08` are skipped. | `N/A` / Informational |
| `FS-00` | No regional Bedrock, AgentCore, or SageMaker resource footprint was found, so Responsible AI GRC was not applicable to that region. | `N/A` / Informational |
| `OW-00` | A required upstream assessment CSV was missing, so one or more mapping-derived OWASP rows could not be generated. | `N/A` / Informational |

When a Bedrock API is access-denied or an AgentCore check raises an unexpected
execution error, the affected control ID is reported as informational `N/A`
with an incomplete-assessment message. These rows remain visible for
troubleshooting but are excluded from scoring. A control is `Failed` only when
the scanner successfully observes evidence that violates its baseline.

`FS-00` is described in more detail in
[Responsible AI GRC Checks](SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md#fs-00--regional-scope-not-applicable-not-a-control),
and `OW-00` in
[OWASP Top 10 for LLM Security Checks](SECURITY_CHECKS_OWASP.md).

---

## Report Scoring

Pass rates are calculated from unique direct-service `Check_ID` values, not
from report-row counts. Findings for resources, Regions, or accounts are
aggregated into one result per control: any assessable `Failed` row makes the
control fail, and a control passes only when all assessable rows pass.
Informational and `N/A` rows are excluded from the score. Responsible AI GRC
rows are also excluded, as are Agentic AI and compliance-mapping rows, which
are contextual views of source evidence and would otherwise be double counted.
A failed control is counted at the highest severity among its failed rows. Resource-level rows remain visible for
investigation and remediation.

---

## Severity Levels

| Severity | Description | Action Required |
| ---------- | ------------- | ----------------- |
| **High** | Critical security issues that could lead to data exposure, unauthorized access, or compliance violations | Immediate remediation recommended |
| **Medium** | Important security improvements that strengthen your security posture | Address in next maintenance window |
| **Low** | Minor optimizations and best practice recommendations | Address when convenient |
| **Informational** | Advisory information about your configuration | No action required |

---

## Status Values

| Status | Description |
| -------- | ------------- |
| **Failed** | Security issue identified that requires remediation |
| **Passed** | Checked resources met the assessed best practice at time of scan |
| **N/A** | The check was not applicable, advisory-only, unavailable in the region, or could not be assessed (for example, because no resources exist or access was denied). |

In the core Amazon Bedrock, Amazon SageMaker AI, Amazon Bedrock AgentCore, and
AWS Agent Registry assessments, a check that could not be assessed is reported
as `N/A` with `Informational` severity. Responsible AI GRC is the exception: its
could-not-assess findings (finding names prefixed `COULD NOT ASSESS:`) are `N/A`
with `Low` severity, so an unknown control state stays visible until access is
fixed and the assessment is re-run. Not-applicable and advisory GRC findings
remain `Informational`. See the
[Responsible AI GRC severity rubric](SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md#severity-rubric).

---

## Amazon Bedrock Security Checks (40)

### BR-01: AWS IAM Least Privilege

- **Severity:** High
- **Type:** Global (runs once)
- **Description:** Fails each IAM role with the `AmazonBedrockFullAccess` managed policy attached, using the shared IAM permissions cache. IAM users are not evaluated.

### BR-02: Amazon VPC Endpoint Configuration

- **Severity:** Medium
- **Description:** When cached IAM policies grant any Bedrock action and the region has Bedrock resources, fails if no VPC endpoint exists in the region for `bedrock`, `bedrock-runtime`, `bedrock-agent`, or `bedrock-agent-runtime`. No row is emitted when no identity has Bedrock permissions.

### BR-03: Marketplace Subscription Access

- **Severity:** High
- **Type:** Global (runs once)
- **Description:** Fails each IAM role or user with an `Allow` statement that lists `aws-marketplace:Subscribe` on `Resource: "*"`. Wildcard actions such as `aws-marketplace:*` are not matched.

BR-01, BR-02, BR-03, BR-08, BR-10, and BR-21 depend on the shared IAM
permissions cache. If that prerequisite is missing, unreadable, or malformed,
each affected control is reported as informational `N/A`; an empty replacement
inventory is never treated as evidence of compliance.

### BR-04: Model Invocation Logging

- **Severity:** Medium
- **Description:** In regions with Bedrock resources, fails when `GetModelInvocationLoggingConfiguration` reports neither an S3 bucket nor a CloudWatch Logs log group destination.

### BR-05: Guardrail Configuration

- **Severity:** Medium
- **Description:** Passes when at least one guardrail exists in the region; fails when none exist and the region has other Bedrock resources. It does not check whether guardrails are attached to or enforced on invocations (see BR-10, BR-13, and BR-28).

### BR-06: AWS CloudTrail Logging

- **Severity:** High
- **Description:** In regions with Bedrock resources, passes when a logging multi-Region trail has an advanced event selector whose `eventSource` names Bedrock, or a basic event selector that includes management events with `ReadWriteType` `All` or `Write`. Otherwise fails.

### BR-07: Prompt Management

- **Severity:** Low
- **Description:** Passes when Prompt Management prompts exist and adds a `Failed` row when any prompt has one variant or none. No prompts produces `N/A`.

### BR-08: Agent AWS IAM Configuration

- **Severity:** High
- **Description:** For each agent service role found in the IAM permissions cache, fails when the role has a policy whose name contains `BedrockFullAccess`, any `Allow` statement on `Resource: "*"`, no permissions boundary, or no VPC-related condition.

### BR-09: Knowledge Base Encryption

- **Severity:** Informational (manual review)
- **Description:** Lists knowledge bases and reports each one as `N/A` for manual review, because storage-layer encryption cannot be read from the Knowledge Base API. This check never emits `Failed`; BR-20 checks managed knowledge base keys.

### BR-10: Guardrail AWS IAM Enforcement

- **Severity:** High
- **Description:** When guardrails exist, fails if any IAM role allows `bedrock:InvokeModel*`, `bedrock:Invoke*`, or `bedrock:*` without a `bedrock:GuardrailIdentifier` condition. IAM users and `Action: "*"` statements are not evaluated.

### BR-11: Custom Model Encryption

- **Severity:** Medium
- **Description:** Fails each custom model whose customization job (`GetModelCustomizationJob`) does not report a KMS key in `outputDataConfig`. The current API returns only `s3Uri` there, so every custom model is reported; BR-17 checks the model's own `modelKmsKeyArn`.

### BR-12: Invocation Log Encryption

- **Severity:** Medium
- **Description:** Fails when the invocation-logging S3 bucket's default encryption is not SSE-KMS with a key other than an `alias/aws/` key. CloudWatch-only logging, logging not configured, and buckets with no encryption configuration are `N/A`.

### BR-13: Flows Guardrails

- **Severity:** High
- **Description:** Fails each flow with a Prompt or Knowledge Base node that has no `guardrailConfiguration.guardrailIdentifier`.

### BR-14: Stale Bedrock Access

- **Severity:** Medium
- **Description:** Not currently emitted: the handler call is disabled, so no BR-14 row appears in reports. When enabled, it fails IAM roles and users with Bedrock permissions whose IAM service-last-accessed data shows no Bedrock use in 60 days, or no use at all.

### BR-15: Cross-Account Guardrails Enforcement

- **Severity:** High
- **Type:** Global (runs once)
- **Description:** Verifies enforced guardrails through AWS Organizations Bedrock policies (the `BEDROCK_POLICY` type) or account-level enforced guardrail configurations (`ListEnforcedGuardrailsConfiguration`). In the management account it passes when a Bedrock policy is attached to a target or account-level configurations exist, and fails when neither exists. In a member account, or when Organizations is not in use and no account-level configuration exists, the result is `N/A` because inheritance cannot be confirmed.

### BR-16: Guardrail Tier Validation

- **Severity:** Medium
- **Type:** Regional
- **Description:** Verifies guardrails use the `STANDARD` content-filter tier (vs the `CLASSIC` tier) for enhanced protection and broader language support. Lists all guardrails in the region and inspects each guardrail's `contentPolicy.tier.tierName`. The STANDARD tier requires cross-Region inference.

### BR-17: Custom Model Customer-Managed KMS Encryption

- **Severity:** High
- **Type:** Regional
- **Description:** Verifies fine-tuned/customized models use customer-managed KMS keys instead of AWS-owned keys for greater control over encryption. Fails each custom model whose `GetCustomModel` response has no `modelKmsKeyArn`; a key ARN starting with `arn:aws:kms` passes.

### BR-18: Model Evaluation Implementation

- **Severity:** Medium
- **Type:** Regional
- **Description:** In regions with Bedrock resources, fails when there are no model evaluation jobs, or when no job created in the last 30 days has status `Completed`. Evaluation metrics and configurations are not inspected.

### BR-19: Prompt Flow Validation

- **Severity:** Medium
- **Type:** Regional
- **Description:** Reads each flow with `GetFlow` and fails flows whose `validations` include an `ERROR`-severity entry, or whose status is not `Prepared`. The scanner does not call `ValidateFlowDefinition`.

### BR-20: Knowledge Base Encryption Enhancement

- **Severity:** High
- **Type:** Regional
- **Description:** Extends existing BR-09 to verify Knowledge Base encryption uses customer-managed KMS keys.

<details><summary>Details</summary>

Uses the authoritative knowledge base `type` (`VECTOR | KENDRA | SQL | MANAGED`) to decide how to assess each KB: for `MANAGED` knowledge bases it reads `knowledgeBaseConfiguration.managedKnowledgeBaseConfiguration.serverSideEncryptionConfiguration.kmsKeyArn` and fails KBs encrypted with an AWS-owned key; for custom vector stores (OpenSearch, RDS, Pinecone, etc.) the encryption key lives on the underlying storage resource and cannot be read from the KB API, so those are reported as N/A for manual review. If a `MANAGED` KB's encryption block is missing from the API response (deployed botocore older than 1.43.32, which silently drops the unmodeled field), the KB is reported as N/A "indeterminate" rather than a false-positive failure.

</details>

### BR-21: Agent Action Group IAM Least Privilege

- **Severity:** High
- **Type:** Regional
- **Description:** Extends existing BR-08 to specifically check if Bedrock Agent action groups use scoped Lambda execution roles with minimal permissions. For each `DRAFT` action group with a Lambda executor, looks up the function's execution role in the IAM permissions cache and fails when it has the `AdministratorAccess` managed policy, any attached managed policy whose name contains `FullAccess`, or an inline policy that allows `Action: "*"` on `Resource: "*"`.

### BR-22: Model Invocation Throttling Limits

- **Severity:** Medium
- **Type:** Regional
- **Description:** In regions with Bedrock resources, compares each Bedrock quota whose name mentions tokens per minute, TPM, requests per, throughput, or invocations with its AWS default value. Fails when every readable quota still equals its default; passes when any applied value differs.

### BR-23: Guardrail Content Filter Coverage

- **Severity:** High
- **Type:** Regional
- **Description:** Extends existing BR-05 to verify guardrails have ALL content filters enabled (hate, insults, sexual, violence) with appropriate thresholds. For each guardrail, checks content filter configuration for all four filter types, verifies filter thresholds are configured, and reports missing or misconfigured filters.

### BR-24: Automated Reasoning Policy Implementation

- **Severity:** Medium
- **Type:** Regional
- **Description:** Fails each guardrail whose `GetGuardrail` response has an empty `automatedReasoningPolicy.policies` list. Policy content and state are not validated.

### BR-25: RAG Evaluation Jobs

- **Severity:** Low
- **Type:** Regional
- **Description:** Fails each knowledge base whose ID does not appear in the name of an evaluation job created in the last 30 days with status `Completed`. Matching is a job-name heuristic; evaluation metrics are not inspected.

### BR-26: Guardrail Sensitive Information Filter

- **Severity:** High
- **Type:** Regional
- **Description:** Extends BR-23 (which covers the harmful-content filters) to verify guardrails configure sensitive-information protection. For each guardrail, reads `GetGuardrail.sensitiveInformationPolicy` and reports guardrails that have no PII entity types (`piiEntities`) or custom regex patterns (`regexes`) configured, leaving prompts and responses unscreened for sensitive data.

### BR-27: Guardrail Contextual Grounding Check

- **Severity:** Medium
- **Type:** Regional
- **Description:** Verifies guardrails enable contextual grounding checks to detect hallucinated (ungrounded) and off-topic model responses. Reads `GetGuardrail.contextualGroundingPolicy.filters` and reports guardrails with no enabled grounding/relevance filters. Complements BR-25 (RAG evaluation) with a runtime control.

### BR-28: Agent Guardrail Association

- **Severity:** High
- **Type:** Regional
- **Description:** Verifies each Bedrock Agent has a guardrail associated so agent interactions are subject to content filtering, PII protection, and denied-topic controls. Reads `guardrailConfiguration` from the agent summaries returned by `ListAgents` and reports agents with no guardrail attached.

### BR-29: Agent Idle Session TTL

- **Severity:** Low
- **Type:** Regional
- **Description:** Verifies Bedrock Agents do not use an excessively long idle session TTL, which widens the window for session and conversation-context reuse. Reads `GetAgent.idleSessionTTLInSeconds` and reports agents whose TTL exceeds a conservative ceiling (3600 seconds).

### BR-30: Imported Model Customer-Managed KMS Encryption

- **Severity:** High
- **Type:** Regional
- **Description:** Complements BR-11/BR-17 by verifying imported custom models use customer-managed KMS keys. Lists imported models and reads `GetImportedModel.modelKmsKeyArn`, reporting models encrypted with AWS-owned keys instead of a customer-managed key.

### BR-31: Batch Inference Output Encryption

- **Severity:** Medium
- **Type:** Regional
- **Description:** Verifies batch inference (model invocation) jobs encrypt their S3 output with a customer-managed KMS key. Reads `outputDataConfig.s3OutputDataConfig.s3EncryptionKeyId` from the job summaries returned by `ListModelInvocationJobs` and fails jobs that specify no output key. The key type is not verified.

### BR-32: CloudWatch Alarms on Bedrock Metrics

- **Severity:** Medium
- **Type:** Regional
- **Description:** Verifies CloudWatch alarms exist on Amazon Bedrock runtime metrics (the `AWS/Bedrock` namespace) to detect abuse, denial-of-wallet, sustained throttling, and content-filter spikes. Uses `DescribeAlarms` and matches alarms that target the `AWS/Bedrock` namespace directly or via a metric-math expression. Only assessed in regions that have Bedrock resources.

### BR-33: Amazon Inspector Lambda Code Scanning

- **Severity:** Medium
- **Type:** Regional
- **Description:** When Lambda functions with Bedrock indicators are detected in the region, verifies Amazon Inspector Lambda standard scanning (`lambda`) and Lambda code scanning (`lambdaCode`) are both enabled so those in-scope functions and their dependencies are scanned for vulnerable packages and hardcoded secrets.

<details><summary>Details</summary>

Calls `lambda:ListFunctions` for scoping and `inspector2:BatchGetAccountStatus` for Inspector status. Reports `Failed` only when in-scope Lambda functions exist and either `resourceState.lambda.status` or `resourceState.lambdaCode.status` is not `ENABLED`. No in-scope Lambda functions, access denied, and region-unavailable states resolve to `N/A`.

</details>

### BR-34: Guardrail Prompt Attack Filter

- **Severity:** High
- **Description:** Requires each guardrail to have a preventive `PROMPT_ATTACK` input filter with `inputEnabled=true`, `inputAction=BLOCK`, and a non-`NONE` input strength. Standard tier is reported as a strengthening note.

### BR-35: Guardrail Image Content Filter Coverage

- **Severity:** Informational
- **Description:** Uses `HATE`, `INSULTS`, `SEXUAL`, and `VIOLENCE` as the cross-region image-filter baseline. Because AWS documents `MISCONDUCT` image filtering as region-dependent, its absence is not reported as a gap, but a configured `MISCONDUCT` filter is reported when its input or output modalities omit `IMAGE`. Complete coverage is `Passed`; advisory gaps are `N/A`/Informational because the scanner cannot infer whether protected applications accept or produce images.

### BR-36: Application Inference Profile Governance

- **Severity:** Low
- **Description:** Lists application inference profiles and reports completely untagged profiles. Organization-specific required tag keys can be enforced outside the default baseline.

### BR-37: Bedrock Account Data Retention

- **Severity:** High for provider sharing or an explicitly required zero-data-retention violation
- **Description:** Fails `provider_data_share`, passes `none`, and reports `default`/`inherit` as informational unless the `RequireBedrockZeroDataRetention` deployment parameter is `true` (`REQUIRE_BEDROCK_ZERO_DATA_RETENTION` in the Lambda), in which case those modes fail.

### BR-38: Automated Reasoning Policy CMK Encryption

- **Severity:** Medium
- **Description:** Deduplicates Automated Reasoning policy summaries and verifies each policy exposes a non-empty `kmsKeyArn`.

### BR-39: Marketplace Model Endpoint VPC Configuration

- **Severity:** High
- **Description:** Requires SageMaker-backed Bedrock Marketplace endpoint configurations to include non-empty VPC subnet and security-group lists.

### BR-40: Marketplace Model Endpoint CMK Encryption

- **Severity:** Medium by default
- **Description:** Resolves the Marketplace endpoint `kmsEncryptionKey` with `kms:DescribeKey` and requires `KeyMetadata.KeyManager` to be `CUSTOMER`; AWS-managed keys do not pass. The `RequireMarketplaceEndpointCMK` deployment parameter defaults to `true` (`REQUIRE_MARKETPLACE_ENDPOINT_CMK` in the Lambda). Set it to `false` to make a missing or AWS-managed key an `N/A`/Informational hardening advisory rather than a failure. An inconclusive KMS lookup is always `N/A`/Informational.

---

## Amazon SageMaker AI Security Checks (29)

### SM-01: Internet Access

- **Severity:** High
- **AWS Security Hub Control:** SageMaker.1
- **Description:** Fails notebook instances with `DirectInternetAccess` set to `Enabled` and domains whose `AppNetworkAccessType` is not `VpcOnly`.

### SM-02: AWS IAM Permissions

- **Severity:** High for full access; Medium for stale users and domain authentication
- **Description:** A global part (runs once) uses the shared IAM permissions
  cache to fail roles with the `AmazonSageMakerFullAccess` managed policy
  (High) and IAM users with SageMaker permissions who last used SageMaker more
  than 60 days ago (Medium). A missing, unreadable, or malformed cache produces
  an informational `N/A` incomplete-assessment row rather than a compliant
  result. A regional part fails domains whose `AuthMode` is not `SSO`, or that
  use SSO without an `IdentityStoreId` (Medium).

### SM-03: Data Protection

- **Severity:** High for missing KMS keys; Medium for network encryption; Low for AWS managed keys
- **Related AWS Security Hub Control:** SageMaker.21 (notebook instances only)
- **Description:** Fails notebook instances, domains, and training jobs with no KMS key (High) or an `aws/sagemaker` AWS managed key (Low). Also fails domains without a VPC and subnets, and training jobs without inter-container traffic encryption (Medium).

### SM-04: Amazon GuardDuty Integration

- **Severity:** High
- **Description:** Fails when the region has no GuardDuty detector or the detector status is not `ENABLED`.

### SM-05: MLOps Features

- **Severity:** Low; Medium for feature groups not in `Created` state
- **Description:** Fails model package groups with one model package or none (Low), feature groups not in `Created` state (Medium), and pipelines with no executions (Low). A component with no resources is `N/A`.

### SM-06: Clarify Usage

- **Severity:** High
- **Description:** Treats processing jobs whose image URI contains `clarify` as Clarify jobs and fails each one with status `Failed`. No Clarify jobs is `N/A`.

### SM-07: Model Monitor

- **Severity:** Medium
- **Description:** Fails monitoring schedules whose status is not `Scheduled`. No schedules is `N/A`.

### SM-08: Model Registry

- **Severity:** Low
- **Description:** Fails model package groups that have no model packages or no `Approved` package. No groups is `N/A`.

### SM-09: Notebook Root Access

- **Severity:** High
- **AWS Security Hub Control:** SageMaker.3
- **Description:** Validates root access is disabled on notebooks.

### SM-10: Notebook Amazon VPC Deployment

- **Severity:** High
- **AWS Security Hub Control:** SageMaker.2
- **Description:** Ensures notebooks are deployed within an Amazon VPC.

### SM-11: Model Network Isolation

- **Severity:** High
- **AWS Security Hub Control:** SageMaker.5
- **Description:** Fails models whose `EnableNetworkIsolation` is not `true`.

### SM-12: Endpoint Instance Count

- **Severity:** Medium
- **AWS Security Hub Control:** SageMaker.4
- **Description:** Fails production variants of `InService` endpoints whose `CurrentInstanceCount` is 1 or less.

### SM-13: Monitoring Network Isolation

- **Severity:** Medium
- **Description:** Fails monitoring schedules whose inline `MonitoringJobDefinition.NetworkConfig.EnableNetworkIsolation` is not `true`. Schedules that reference a separate job definition have no inline definition and are also reported.

### SM-14: Model Container Repository

- **Severity:** Medium
- **Description:** Fails models whose primary or additional containers use `RepositoryAccessMode` `Platform` (the default) instead of `Vpc`.

### SM-15: Feature Store Encryption

- **Severity:** Medium
- **Description:** Fails feature groups whose offline store has no `S3StorageConfig.KmsKeyId`. Online stores are not checked.

### SM-16: Data Quality Encryption

- **Severity:** Medium
- **Description:** Fails data quality job definitions without inter-container traffic encryption (`NetworkConfig.EnableInterContainerTrafficEncryption`).

### SM-17: Processing Job Encryption

- **Severity:** Medium
- **Description:** Fails processing jobs with no `ClusterConfig.VolumeKmsKeyId`.

### SM-18: Transform Job Encryption

- **Severity:** Medium
- **Description:** Fails transform jobs with no `TransformResources.VolumeKmsKeyId`.

### SM-19: Hyperparameter Tuning Encryption

- **Severity:** Medium
- **Description:** Fails hyperparameter tuning jobs whose training job definition has no `ResourceConfig.VolumeKmsKeyId`.

### SM-20: Compilation Job Encryption

- **Severity:** Medium
- **Description:** Fails compilation jobs with no `OutputConfig.KmsKeyId`.

### SM-21: AutoML Network Isolation

- **Severity:** Medium
- **Description:** Despite its title, fails AutoML jobs without inter-container traffic encryption (`SecurityConfig.EnableInterContainerTrafficEncryption`); network isolation is not checked.

### SM-22: Model Approval Workflow

- **Severity:** Medium; Low for pending-approval backlog
- **Description:** Fails model package groups with more than three packages that are all `Approved`, which suggests auto-approval (Medium), and groups with more than five packages pending manual approval (Low).

### SM-23: Model Drift Detection

- **Severity:** Medium; Low for incomplete monitoring
- **Description:** Fails `InService` endpoints with no Model Monitor schedule (Medium), and monitored endpoints that lack `DataQuality` or `ModelQuality` monitoring or have a schedule that is not `Scheduled` (Low).

### SM-24: A/B Testing and Shadow Deployment

- **Severity:** Informational (advisory)
- **Description:** Passes when `InService` endpoints use shadow variants or several weighted production variants. Endpoints with one variant are reported as `N/A`/Informational advisories; this check never emits `Failed`.

### SM-25: ML Lineage Tracking

- **Severity:** Low
- **Description:** Fails when SageMaker Experiments exist but none of the first five sampled experiments has trials. No experiments is `N/A`. Model packages without lineage associations are listed as `N/A`/Informational rows.

### SM-26: GuardDuty AI Protection

- **Severity:** High
- **Description:** Reuses the regional GuardDuty detector inventory and verifies the `AI_PROTECTION` feature is `ENABLED`. A region with no detector is reported as N/A because SM-04 separately reports GuardDuty enablement.

### SM-27: HyperPod EBS CMK Encryption

- **Severity:** Medium
- **Description:** Verifies every HyperPod instance group configures a customer-managed KMS key for its root EBS volume and all configured secondary EBS volumes. AWS documents that HyperPod root volumes use an AWS-owned key by default and that a customer-managed key is supplied through `InstanceStorageConfigs`; therefore, an absent root-volume storage configuration fails this CMK baseline rather than producing `N/A`.

### SM-28: HyperPod VPC Configuration

- **Severity:** Medium
- **Description:** Verifies each HyperPod instance group's effective VPC configuration has subnets and security groups, honoring `OverrideVpcConfig` before the cluster-level `VpcConfig`.

`SM-29` is reserved for SageMaker Unified Studio private networking. It is not currently emitted because the available domain APIs do not expose a sufficient domain-level networking configuration.

### SM-30: Model Package Group Resource Policy Exposure

- **Severity:** High for public or configured-boundary violations; Informational `Passed` for unclassified external sharing
- **Description:** Parses model package group resource policies to identify public wildcard principals and external accounts or organizations outside optional `AIML_APPROVED_EXTERNAL_ACCOUNT_IDS` / `AIML_APPROVED_ORG_IDS` boundaries. Configure those boundaries through the `ApprovedExternalAccountIds` and `ApprovedOrganizationIds` deployment parameters, respectively; both default to empty. When both are empty, external sharing is reported as `Passed` with Informational severity and a review recommendation.

<details><summary>Details</summary>

Wildcard principals constrained by exact `aws:PrincipalAccount` or `aws:PrincipalOrgID` values, fixed-account `aws:PrincipalArn` patterns, or fixed-organization `aws:PrincipalOrgPaths` patterns are treated as bounded. Wildcard account/organization identifiers remain public; `ForAllValues` organization-path conditions count as boundaries only when a matching `Null: false` condition requires the key to be present. Because AWS supports `NotPrincipal` only with `Deny`, an `Allow` statement containing `NotPrincipal` is reported as unsupported and `N/A` rather than silently passing or being treated as public. Valid `Deny` statements do not create exposure and are ignored. If `sts:GetCallerIdentity` is unavailable, public wildcard statements are still reported, but account principals that cannot be distinguished as same-account or external produce `N/A` instead of an external-access finding. This is a conservative heuristic, not a complete IAM authorization simulator.

</details>

---

## Amazon Bedrock AgentCore Security Checks (17)

`AC-02`, `AC-03`, and `AC-09` inspect account-global IAM data and run once, on
the first assessed region, under the `Global` region. The other AgentCore
checks and the native `AG-24` through `AG-27` gateway checks are regional and
use the `bedrock-agentcore-control` API. A regional check with no matching
resources reports informational `N/A`.

### AC-01: Runtime Amazon VPC Configuration

- **Severity:** High for `PUBLIC` network mode; Medium for a runtime subnet with an internet gateway route
- **Description:** Calls `GetAgentRuntime` for each runtime and fails runtimes whose `networkConfiguration.networkMode` is `PUBLIC` or missing. For VPC-mode runtimes, it also checks each subnet's route tables and fails a subnet that has an `igw-` route.

### AC-02: AWS IAM Full Access

- **Severity:** High
- **Description:** Checks IAM roles' attached and inline policy documents for AgentCore full-access managed policies, wildcard IAM action patterns, and `Allow`/`NotAction` allow-except statements that still grant the AgentCore namespace when they apply to all resources.

<details><summary>Details</summary>

Only the valid `bedrock-agentcore` IAM namespace is evaluated; overly permissive `agent-registry` grants are reported by [AR-01](#ar-01-aws-iam-full-access) instead. Service-agnostic administrator-style grants are out of scope in both forms: a bare `Action: "*"` and a `NotAction` whose exclusions name no platform namespace are treated alike and not reported as AgentCore-specific grants. A missing, unreadable, or malformed permissions cache is reported as informational `N/A`. If an individual cached policy document cannot be parsed, valid findings from other policies are retained and an additional informational `N/A` row marks the control incomplete; the unparsed policy cannot produce a compliant pass.

</details>

### AC-03: Stale Access

- **Severity:** Medium for 60+ day inactivity; Low when all principals are active; Informational when never used or incomplete
- **Description:** Detects unused AgentCore permissions by inspecting `Allow` and `NotAction` grants in IAM roles' and users' attached and inline policy documents before querying IAM service-last-accessed history.

<details><summary>Details</summary>

Only the `bedrock-agentcore` namespace is evaluated; `agent-registry` grants are reported by [AR-02](#ar-02-stale-access) instead. As in AC-02, a `NotAction` whose exclusions name no platform namespace is a service-agnostic administrator grant and is not treated as an AgentCore-specific permission. Attached policy names alone are never treated as proof of access. IAM last-accessed jobs are polled within the Lambda deadline; a job that does not complete in time is reported as an indeterminate `N/A` rather than a failed control. A missing, unreadable, or malformed permissions cache is also reported as informational `N/A`. This identifies candidate grants from the cached policy documents; it is not a complete effective-permissions simulation across boundaries, session policies, or organization controls.

</details>

### AC-04: Observability

- **Severity:** Medium
- **Description:** Reads each runtime's `GetAgentRuntime` response and fails a runtime without `loggingConfig.cloudWatchLogsConfig` or with `tracingConfig.enabled` not set to `true`. A configured log group that CloudWatch Logs reports as not found also fails.

### AC-05: Amazon ECR Repository Encryption

- **Severity:** High for an unencrypted repository; Low for `AES256` (AWS-managed keys)
- **Description:** Selects Amazon ECR repositories whose names contain `agentcore` or `bedrock-agent`. Repositories with no encryption configuration fail with High severity, and repositories using `AES256` fail with Low severity because they do not use a customer-managed AWS KMS key. `KMS` encryption passes.

### AC-06: Browser Tool Recording

- **Severity:** Medium
- **Description:** Uses custom browser inventory and requires `recording.enabled=true` with a non-empty S3 recording bucket.

### AC-07: Memory Encryption

- **Severity:** Medium
- **Description:** Fails each AgentCore memory whose `GetMemory` response has no `encryptionKeyArn`, meaning it does not use a customer-managed AWS KMS key.

### AC-08: Amazon VPC Endpoints

- **Severity:** High when no AgentCore endpoint exists; Medium when an endpoint is not `available`
- **Description:** When the region has at least one AgentCore runtime, lists the region's VPC endpoints and fails if none has a service name containing `agentcore`. If AgentCore endpoints exist but any is not in the `available` state, the check fails with Medium severity.

### AC-09: Service-Linked Role

- **Severity:** Medium
- **Description:** Calls `iam:GetRole` for `AWSServiceRoleForBedrockAgentCoreNetwork`. The check passes when the role's trust policy names an AgentCore service principal and fails when the role is missing or its trust policy does not.

### AC-10: Resource-Based Policies

- **Severity:** High
- **Description:** Calls `GetResourcePolicy` for every runtime and gateway and fails resources that have no resource-based policy. The check does not evaluate the policy's contents. Access-denied and other API errors are reported as informational `N/A` rows.

### AC-11: Policy Engine Encryption

- **Severity:** High
- **Description:** Fails policy engines whose `GetPolicyEngine` response has no `encryptionKeyArn`, meaning they do not use a customer-managed AWS KMS key.

### AC-12: Gateway Encryption

- **Severity:** Low
- **Description:** Fails gateways whose `GetGateway` response has no `kmsKeyArn`, meaning they use AWS-managed rather than customer-managed encryption.

### AC-13: Gateway Configuration

- **Severity:** Medium
- **Description:** Inventories AgentCore gateways and passes when any exist. It does not evaluate gateway settings; gateway authorization, policy enforcement, error detail, and WAF protection are evaluated by [AG-24](#ag-24-gateway-inbound-authorization) through [AG-27](#ag-27-gateway-waf-protection).

### AC-14: Identity Token Vault CMK Encryption

- **Severity:** High
- **Description:** Checks the configured/default regional Identity token vault and requires `CustomerManagedKey` with a KMS key ARN. Set the `AgentCoreTokenVaultId` deployment parameter to override the `default` vault ID (`AGENTCORE_TOKEN_VAULT_ID` in the Lambda).

### AC-15: Code Interpreter Network Isolation

- **Severity:** High
- **Description:** Requires custom Code Interpreters to use `VPC` network mode with non-empty subnets and security groups.

### AC-16: Custom Browser Network Isolation

- **Severity:** High
- **Description:** Requires custom browsers to use `VPC` network mode with non-empty subnets and security groups. Shares browser inventory with AC-06.

### AC-17: Online Evaluation Coverage

- **Severity:** Informational by default; Medium when required
- **Description:** Reports whether online evaluation configurations are active/enabled and include non-zero sampling, evaluators, CloudWatch input data, and output logging. Set the `RequireAgentCoreOnlineEvaluation` deployment parameter to `true` (`REQUIRE_AGENTCORE_ONLINE_EVALUATION` in the Lambda) to make incomplete coverage fail.

---

## AWS Agent Registry Security Checks (8)

AWS Agent Registry checks use the `AR-XX` namespace and run in a dedicated
regional Lambda that writes its own CSV artifact and HTML report area. They are
included with the default assessment.

`AR-01` and `AR-02` are account-scoped IAM checks that read the shared
permissions cache and are reported once under the `Global` region. `AR-03`
through `AR-08` are regional and use the generally available
`agent-registry-control` API. Registry detail is read once per registry and
shared across `AR-03` through `AR-06`; record inventory is shared between
`AR-07` and `AR-08`.

<details><summary>Inventory bounds and error handling</summary>

Record inventory is bounded to 1,000 records and paginates within the Lambda
deadline. When the cap or the deadline is reached, `AR-07` and `AR-08` report a
single informational `N/A` incomplete-assessment row and continue assessing
the records already collected. A registry that is not `READY`, a registry
whose detail call fails, an access-denied response, and a region where AWS
Agent Registry is unavailable all resolve to informational `N/A` with
error-specific remediation rather than to a failure.

</details>

### AR-01: AWS IAM Full Access

- **Severity:** High
- **Description:** Checks IAM roles' attached and inline policy documents from the permissions cache for AWS Agent Registry full-access managed policies, wildcard IAM action patterns, and `Allow`/`NotAction` allow-except statements that still grant the `agent-registry` namespace when they apply to all resources.

<details><summary>Details</summary>

Only the valid `agent-registry` IAM namespace is evaluated; `bedrock-agentcore` grants are reported by [AC-02](#ac-02-aws-iam-full-access) instead. Service-agnostic administrator-style grants are out of scope in both forms: a bare `Action: "*"` and a `NotAction` whose exclusions name no platform namespace are treated alike and not reported as Registry-specific grants. An empty permissions cache is an informational `N/A` tooling condition, not a failure.

</details>

### AR-02: Stale Access

- **Severity:** Medium for 60+ day inactivity; Low when all principals are active; Informational when never used or incomplete
- **Description:** Identifies IAM roles and users whose attached or inline policy documents grant the `agent-registry` namespace, either through an `Allow` action or through a `NotAction` allow-except statement that does not fully cover the namespace.

<details><summary>Details</summary>

Attached policy names alone are never treated as proof of access. The check uses IAM service-last-accessed jobs to identify access older than 60 days and principals with no Registry usage evidence. IAM job errors, timeouts, and inaccessible principals are indeterminate informational `N/A` findings rather than failures.

</details>

### AR-03: Registry Publication Approval Governance

- **Severity:** Informational by default; Medium when required
- **Description:** Verifies whether each `READY` registry requires manual review for submitted records.

<details><summary>Details</summary>

A registry whose `approvalConfiguration` carries `autoApprovalRules` approves submitted records automatically and is informational by default; set `RequireAgentRegistryManualApproval` to `true` (`REQUIRE_AGENT_REGISTRY_MANUAL_APPROVAL` in the Lambda) to make automatic approval fail, which also switches the remediation text from advisory to actionable. A registry with no auto-approval rules passes. `approvalConfiguration` is optional in the GA response; a registry that omits it is reported as informational `N/A` because manual review was never observed, not as a pass.

</details>

### AR-04: Registry Discovery Authorization

- **Severity:** Informational for configured authorizers; High for an unconstrained custom JWT authorizer
- **Description:** Inventories the discovery authorizer on each `READY` registry. A custom JWT authorizer without **both** an OpenID Connect discovery URL and at least one caller constraint (`allowedAudience`, `allowedClients`, `allowedScopes`, or `customClaims`) fails.

<details><summary>Details</summary>

Every other outcome is informational `N/A` pending review, because the authorizer configuration alone does not establish which callers hold effective discovery access: `AWS_IAM` requires an effective-policy review, a constrained custom JWT authorizer requires comparing the approved audiences, clients, scopes, and claims against intended consumers, and an absent or unrecognized `discoveryConfiguration` establishes no authorization fact either way.

</details>

### AR-05: Registry Customer-Managed KMS Encryption

- **Severity:** Informational by default; Medium when required
- **Description:** Reads `GetRegistry.encryptionConfiguration.kmsKeyArn`. Registries with a customer-managed KMS key pass.

<details><summary>Details</summary>

Registries using the default AWS-owned key are informational by default because AWS Agent Registry still encrypts them at rest. Set `RequireAgentRegistryCMK` to `true` (`REQUIRE_AGENT_REGISTRY_CMK` in the Lambda) to make the AWS-owned key configuration fail. The registry encryption key is immutable after creation, so remediation requires a replacement registry and record migration.

</details>

### AR-06: Registry Organization Auto-Detection

- **Severity:** Medium when active; otherwise Informational
- **Description:** Passes only when a `READY` registry reports auto-detection that is enabled, scoped to `ORGANIZATION`, and `ACTIVE`.

<details><summary>Details</summary>

Disabled or `INACTIVE` configurations are informational `N/A` because the feature is optional. An omitted or incomplete optional `autoDetection` block, and a registry that has not reached `READY`, are also informational `N/A` because the control state could not be established.

</details>

### AR-07: Registry Record Lifecycle Governance

- **Severity:** Informational
- **Description:** Paginates `ListRegistryRecords` across every accessible registry and reports the lifecycle state returned in each record summary as an advisory `N/A` observation, because occupying a documented service state does not by itself prove a security control.

<details><summary>Details</summary>

Review failed or unknown lifecycle states operationally. Per-registry listing failures are reported individually with error-specific remediation so one inaccessible registry does not hide the rest. `AR-07` does not affect the score.

</details>

### AR-08: Registry Record Provenance

- **Severity:** Medium
- **Description:** Verifies that manually created records retain a 12-digit creator-account attribution and that auto-detected records carry a `DETECTED_FROM` provenance summary whose `sourceId` is a `bedrock-agentcore` ARN matching its declared `sourceType`: a `runtime/...` resource for `AWS::BedrockAgentCore::Runtime` or a `gateway/...` resource for `AWS::BedrockAgentCore::Gateway`.

<details><summary>Details</summary>

A record whose declared lineage does not match fails, and it continues to fail even when another provenance entry omits its own source type. Optional origin-mode, creator-attribution, provenance, and source-type metadata are reported as informational `N/A` rather than as operator-remediable failures.

</details>

---

## Agentic AI Security Checks (38)

Agentic AI Security checks use the `AG-XX` namespace and are included with the
default assessment. They follow a hybrid model:

- Reused API-backed controls from Amazon Bedrock, Amazon Bedrock AgentCore,
  and AWS Agent Registry are mapped into agentic security domains.
- Native checks (`AG-24` through `AG-27`) exist only where AWS APIs can prove
  the control state.
- Controls that cannot be proven by AWS APIs are not scored. Human-in-the-loop
  governance is therefore documented as a methodology note, not emitted as an
  automated pass/fail finding.

These checks reference the
[AWS Well-Architected Agentic AI Lens](https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html),
with scope limited to the Security pillar.

### Mapped Agentic AI checks

Mapped `AG-*` rows reuse the source finding's status, details, and Region and inherit its
severity; a source row with status `N/A` produces an `Informational` `AG-*` row. Mapped
rows are contextual views of source evidence and are excluded from scoring.

| ID | Title | Domain | Source check | Severity | Notes |
| -- | ----- | ------ | ------------ | -------- | ----- |
| <a id="ag-01-agent-guardrail-association"></a>AG-01 | Agent Guardrail Association | Guardrail Enforcement | [BR-28](#br-28-agent-guardrail-association) | Inherits source | |
| <a id="ag-02-harmful-content-guardrail-coverage"></a>AG-02 | Harmful Content Guardrail Coverage | Guardrail Enforcement | [BR-23](#br-23-guardrail-content-filter-coverage) | Inherits source | |
| <a id="ag-03-sensitive-information-protection"></a>AG-03 | Sensitive Information Protection | Memory & Data Privacy | [BR-26](#br-26-guardrail-sensitive-information-filter) | Inherits source | |
| <a id="ag-04-automated-reasoning-guardrails"></a>AG-04 | Automated Reasoning Guardrails | Guardrail Enforcement | [BR-24](#br-24-automated-reasoning-policy-implementation) | Inherits source | |
| <a id="ag-05-grounding-controls"></a>AG-05 | Grounding Controls | Prompt & Input Protection | [BR-27](#br-27-guardrail-contextual-grounding-check) | Inherits source | |
| <a id="ag-06-tool-execution-least-privilege"></a>AG-06 | Tool Execution Least Privilege | Tool Authorization | [BR-21](#br-21-agent-action-group-iam-least-privilege) | Inherits source | |
| <a id="ag-07-model-invocation-logging"></a>AG-07 | Model Invocation Logging | Auditability & Observability | [BR-04](#br-04-model-invocation-logging) | Inherits source | |
| <a id="ag-08-api-audit-trail"></a>AG-08 | API Audit Trail | Auditability & Observability | [BR-06](#br-06-aws-cloudtrail-logging) | Inherits source | |
| <a id="ag-09-guardrail-enforcement-boundary"></a>AG-09 | Guardrail Enforcement Boundary | Guardrail Enforcement | [BR-15](#br-15-cross-account-guardrails-enforcement) | Inherits source | |
| <a id="ag-10-adversarial-evaluation-coverage"></a>AG-10 | Adversarial Evaluation Coverage | Prompt & Input Protection | [BR-18](#br-18-model-evaluation-implementation) | Inherits source | |
| <a id="ag-11-prompt-flow-validation"></a>AG-11 | Prompt Flow Validation | Prompt & Input Protection | [BR-19](#br-19-prompt-flow-validation) | Inherits source | |
| <a id="ag-12-invocation-abuse-controls"></a>AG-12 | Invocation Abuse Controls | Abuse & Cost Protection | [BR-22](#br-22-model-invocation-throttling-limits) | Inherits source | |
| <a id="ag-13-session-boundary"></a>AG-13 | Session Boundary | Bounded Autonomy | [BR-29](#br-29-agent-idle-session-ttl) | Inherits source | |
| <a id="ag-14-operational-abuse-alarms"></a>AG-14 | Operational Abuse Alarms | Abuse & Cost Protection | [BR-32](#br-32-cloudwatch-alarms-on-bedrock-metrics) | Inherits source | |
| <a id="ag-15-runtime-network-boundary"></a>AG-15 | Runtime Network Boundary | Bounded Autonomy | [AC-01](#ac-01-runtime-amazon-vpc-configuration) | Inherits source | |
| <a id="ag-16-agentcore-least-privilege"></a>AG-16 | AgentCore Least Privilege | Agent Identity & Access | [AC-02](#ac-02-aws-iam-full-access) | Inherits source | |
| <a id="ag-17-stale-agentcore-access"></a>AG-17 | Stale AgentCore Access | Agent Identity & Access | [AC-03](#ac-03-stale-access) | Inherits source | |
| <a id="ag-18-agentcore-observability"></a>AG-18 | AgentCore Observability | Auditability & Observability | [AC-04](#ac-04-observability) | Inherits source | |
| <a id="ag-19-memory-data-protection"></a>AG-19 | Memory Data Protection | Memory & Data Privacy | [AC-07](#ac-07-memory-encryption) | Inherits source | |
| <a id="ag-20-private-agentcore-connectivity"></a>AG-20 | Private AgentCore Connectivity | Bounded Autonomy | [AC-08](#ac-08-amazon-vpc-endpoints) | Inherits source | |
| <a id="ag-21-resource-policy-boundary"></a>AG-21 | Resource Policy Boundary | Agent Identity & Access | [AC-10](#ac-10-resource-based-policies) | Inherits source | |
| <a id="ag-22-policy-engine-data-protection"></a>AG-22 | Policy Engine Data Protection | Tool Authorization | [AC-11](#ac-11-policy-engine-encryption) | Inherits source | |
| <a id="ag-23-gateway-data-protection"></a>AG-23 | Gateway Data Protection | Tool Authorization | [AC-12](#ac-12-gateway-encryption) | Inherits source | |
| <a id="ag-28-identity-token-vault-protection"></a>AG-28 | Identity Token Vault Protection | Agent Identity & Access | [AC-14](#ac-14-identity-token-vault-cmk-encryption) | Inherits source | |
| <a id="ag-29-code-interpreter-isolation"></a>AG-29 | Code Interpreter Isolation | Bounded Autonomy | [AC-15](#ac-15-code-interpreter-network-isolation) | Inherits source | |
| <a id="ag-30-prompt-attack-protection"></a>AG-30 | Prompt Attack Protection | Prompt & Input Protection | [BR-34](#br-34-guardrail-prompt-attack-filter) | Inherits source | |
| <a id="ag-31-browser-tool-isolation"></a>AG-31 | Browser Tool Isolation | Bounded Autonomy | [AC-16](#ac-16-custom-browser-network-isolation) | Inherits source | |
| <a id="ag-32-online-evaluation-assurance"></a>AG-32 | Online Evaluation Assurance | Auditability & Continuous Assurance | [AC-17](#ac-17-online-evaluation-coverage) | Inherits source | Does not claim universal runtime trace coverage. |
| <a id="ag-33-registry-publication-approval-governance"></a>AG-33 | Registry Publication Approval Governance | Agent Identity & Access | [AR-03](#ar-03-registry-publication-approval-governance) | Inherits source | |
| <a id="ag-34-registry-discovery-authorization"></a>AG-34 | Registry Discovery Authorization | Agent Identity & Access | [AR-04](#ar-04-registry-discovery-authorization) | Inherits source | Configured IAM and constrained JWT authorizers stay informational until effective access or approved JWT caller values can be established. |
| <a id="ag-35-registry-metadata-encryption"></a>AG-35 | Registry Metadata Encryption | Memory & Data Privacy | [AR-05](#ar-05-registry-customer-managed-kms-encryption) | Inherits source | |
| <a id="ag-36-organization-discovery-coverage"></a>AG-36 | Organization Discovery Coverage | Auditability & Continuous Assurance | [AR-06](#ar-06-registry-organization-auto-detection) | Inherits source | |
| <a id="ag-37-registry-record-lifecycle-governance"></a>AG-37 | Registry Record Lifecycle Governance | Agent Identity & Access | [AR-07](#ar-07-registry-record-lifecycle-governance) | Inherits source | Advisory lifecycle observations only. |
| <a id="ag-38-registry-record-provenance"></a>AG-38 | Registry Record Provenance | Auditability & Continuous Assurance | [AR-08](#ar-08-registry-record-provenance) | Inherits source | |

### Native Agentic AI checks

These four checks inspect AgentCore gateways directly and are emitted by the AgentCore assessment for each gateway in each assessed region. When a region has no gateways, each check reports informational `N/A`. Like mapped rows, native `AG-*` rows appear in the Agentic AI area and are excluded from scoring.

### AG-24: Gateway Inbound Authorization

- **Severity:** High
- **Source:** AgentCore `ListGateways` and `GetGateway`
- **Domain:** Tool Authorization
- **Description:** Fails gateways with missing, unknown, or `NONE` authorizers. Passes `AWS_IAM` and `CUSTOM_JWT`. `AUTHENTICATE_ONLY` passes only when an AgentCore policy engine is attached in `ENFORCE` mode, because the gateway authenticates the SigV4 caller but does not make an authorization decision for that authorizer type.

### AG-25: Gateway Tool Policy Enforcement

- **Severity:** High
- **Source:** AgentCore `GetGateway.policyEngineConfiguration` plus `ListPolicies`
- **Domain:** Tool Authorization
- **Description:** Fails gateways without a policy engine, with mode other than `ENFORCE`, or with no `ACTIVE` policy whose enforcement mode is `ACTIVE`. A mix of enforcing and `LOG_ONLY`/inactive policies passes with an advisory.

### AG-26: Gateway Error Detail Exposure

- **Severity:** Medium
- **Source:** AgentCore `GetGateway.exceptionLevel`
- **Domain:** Auditability & Observability
- **Description:** Fails gateways configured to return `DEBUG`-level exception detail.

### AG-27: Gateway WAF Protection

- **Severity:** Low
- **Source:** AgentCore `GetGateway.webAclArn`
- **Domain:** Abuse & Cost Protection
- **Description:** Fails AgentCore gateways without an associated AWS WAF web ACL.

### Runtime guardrail methodology note

`InvokeGuardrailChecks` / `ApplyGuardrail` are per-request runtime APIs rather than a persistent configuration surface. The assessment therefore does not emit a pass/fail finding for their use; applications should validate these calls through runtime architecture review, telemetry, and testing.

---

## Responsible AI GRC Checks (64 additional, 5 upstream extensions)

These 64 opt-in standalone checks (`FS-XX`) add cross-industry AI governance,
risk, and compliance controls derived from the
[AWS User Guide to Governance, Risk, and Compliance for Responsible AI Adoption](https://d1.awsstatic.com/whitepapers/compliance/AWS-User-Guide-Governance-Risk-Compliance-for-Responsible-AI-Adoption-Financial-Services.pdf)
(see also the
[AWS Security Blog announcement](https://aws.amazon.com/blogs/security/introducing-the-updated-aws-user-guide-to-governance-risk-and-compliance-for-responsible-ai-adoption/)).
Enable them with the `EnableResponsibleAIGRCAssessment` deployment parameter.
Five more `FS` numbers (FS-17, FS-18, FS-19, FS-23, and FS-64) are merged into
the SM-07, SM-23, SM-22, BR-06, and BR-04 checks rather than shipped
separately; see
[Relationship to SM/BR/AC checks](SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md#relationship-to-smbrac-checks).

The full catalog is in **[`SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md`](./SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md)**,
organized into three parts:

- **Part 1 — Infrastructure & Resource Controls** — FS-01 to FS-26
  (Unbounded Consumption, Excessive Agency, Supply Chain, Training Poisoning, Vector
  Weaknesses).
- **Part 2 — Guardrails & Content Safety** — FS-27 to FS-46
  (Non-Compliant Output, Misinformation, Abusive/Harmful Output, Biased Output,
  Sensitive Information Disclosure).
- **Part 3 — Application-Layer Controls & Material Gaps** — FS-47 to FS-69
  (Hallucination, Prompt Injection, Improper Output Handling, Off-Topic Output,
  Out-of-Date Training Data, and 6 cross-category material gap checks).

That document also contains the severity rubric, validation note,
upstream-overlap table, and compliance framework mapping table
(SR 11-7, FFIEC CAT, NYDFS 500.06, PCI-DSS 12.3.2, DORA Art.6, MAS TRM 9,
ISO 27001 A.12, ECOA, OWASP LLM Top 10).

---

## OWASP Top 10 for LLM Checks (12)

These 12 opt-in checks (`OW-XX`) align findings to the
[OWASP Top 10 for LLM 2025](https://genai.owasp.org/llm-top-10/). OW-01 through
OW-10 are mapped from existing Bedrock, SageMaker AI, AgentCore, and
Responsible AI GRC findings; OW-11 and OW-12 are native LLM07 (System Prompt
Leakage) checks. Enable them with the `EnableOWASPAssessment` deployment
parameter. Because many mappings (and all of LLM05) use `FS-*` evidence, enabling OWASP also runs
Responsible AI GRC as a hidden source dependency when GRC itself is disabled.
The full catalog, mappings, and disclaimer are in
**[`SECURITY_CHECKS_OWASP.md`](./SECURITY_CHECKS_OWASP.md)**.

---

## Additional Resources

- [Amazon SageMaker Security Best Practices](https://docs.aws.amazon.com/sagemaker/latest/dg/security.html)
- [Amazon Bedrock Security](https://docs.aws.amazon.com/bedrock/latest/userguide/security.html)
- [Amazon Bedrock AgentCore Security](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security.html)
- [OWASP Top 10 for LLM 2025](https://genai.owasp.org/llm-top-10/)
- [AWS Well-Architected Generative AI Lens](https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/generative-ai-lens.html)
- [AWS Well-Architected Agentic AI Lens](https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html)
- [AWS Security Hub SageMaker Controls](https://docs.aws.amazon.com/securityhub/latest/userguide/sagemaker-controls.html)
- [AWS Well-Architected Framework - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
