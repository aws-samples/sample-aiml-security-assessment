# Security Checks Reference

This document provides a comprehensive reference for all 208 security checks performed by the AI/ML Security Assessment framework (94 core checks across Amazon Bedrock, Amazon SageMaker AI, Amazon Bedrock AgentCore, and AWS Agent Registry, 38 Agentic AI Security checks, 64 Responsible AI GRC checks, and 12 OWASP Top 10 for LLM checks).

Sources differ by bucket and are not interchangeable: the core Bedrock, SageMaker, AgentCore, and AWS Agent Registry checks derive from the AWS Well-Architected **Generative AI Lens** security best practices (`gensec*`) and service security documentation; the Agentic AI Security checks from the AWS Well-Architected **Agentic AI Lens**; the `FS-*` **Responsible AI GRC** checks from the AWS GRC User Guide; and the `OW-*` checks from the OWASP Top 10 for LLM. The AWS Well-Architected **Responsible AI Lens** is not a source for any of them — see [Responsible AI GRC — scope, sources, and compatibility](RESPONSIBLE_AI_GRC_SCOPE.md).

The 64 Responsible AI GRC checks occupy 69 `FS-*` numbers: 64 ship as standalone checks and 5 are merged into upstream Bedrock/SageMaker checks. The framework also emits `BR-00`, `SM-00`, `AC-00`, `AR-00`, `FS-00`, and `OW-00` operational marker rows at runtime; these are not controls and are excluded from the 208-check total. Per-control provenance, including which controls are project extensions rather than guide-derived, is recorded in [`provenance.json`](../aiml-security-assessment/functions/security/responsible_ai_grc_assessments/provenance.json).

The counts above describe the full catalog. Core service assessments are enabled
by default and can be selected independently with the four
[`Enable*Assessment` switches](../README.md#selecting-service-assessments).
Deselected services produce no findings and appear as **Not selected** in the
report; this is not an N/A finding or a compliant result. Agentic AI and OWASP
mapping coverage decreases when their direct-service sources are deselected.

## Table of Contents

- [Overview](#overview)
- [Check ID Convention](#check-id-convention)
- [Report Scoring](#report-scoring)
- [Severity Levels](#severity-levels)
- [Status Values](#status-values)
- [Amazon SageMaker AI Security Checks (29)](#amazon-sagemaker-ai-security-checks-29)
- [Amazon Bedrock Security Checks (40)](#amazon-bedrock-security-checks-40)
- [Amazon Bedrock AgentCore Security Checks (17)](#amazon-bedrock-agentcore-security-checks-17)
- [AWS Agent Registry Security Checks (8)](#aws-agent-registry-security-checks-8)
- [Agentic AI Security Checks (38)](#agentic-ai-security-checks-38)
- [Responsible AI GRC Checks (64)](#responsible-ai-grc-checks-64-additional-5-upstream-extensions)
- [OWASP Top 10 for LLM Checks (12)](#owasp-top-10-for-llm-checks-12)

---

## Overview

The framework evaluates your AI/ML workloads against AWS security best practices across four services:

| Service | Number of Checks | Focus Areas |
| --------- | ------------------ | ------------- |
| Amazon SageMaker AI | 29 | Security Hub controls, encryption, network isolation, GuardDuty AI Protection, HyperPod, IAM, MLOps, Model Registry policy exposure |
| Amazon Bedrock | 40 | Guardrails, prompt-attack/image filters, retention, inference profiles, automated reasoning and Marketplace endpoint governance, encryption, networking, IAM, logging, monitoring, and evaluation |
| Amazon Bedrock AgentCore | 17 | Runtime/tool VPC isolation, encryption, browser recording, observability, resource policies, Identity token vaults, and online evaluation |
| AWS Agent Registry | 8 | IAM access, approval governance, discovery authorization, encryption, organization auto-detection, record lifecycle, and provenance |
| Agentic AI Security | 38 | Bounded autonomy, agent identity, tool authorization, Registry governance and provenance, guardrail enforcement, prompt/input protection, memory privacy, auditability, continuous assurance, abuse protection |
| Responsible AI GRC | 64 | Unbounded consumption, excessive agency, supply chain, training data poisoning, vector weaknesses, non-compliant output, misinformation, harmful output, biased output, PII disclosure, hallucination, prompt injection, improper output handling, off-topic output, out-of-date training data |
| OWASP Top 10 for LLM | 12 | LLM01 Prompt Injection, LLM02 Sensitive Info Disclosure, LLM03 Supply Chain, LLM04 Data/Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector/Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption |

---

## Check ID Convention

Each security check has a unique identifier with a service prefix:

| Prefix | Service | Example |
| -------- | --------- | --------- |
| **SM-XX** | Amazon SageMaker | SM-01, SM-30 (`SM-29` reserved) |
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
| `AR-00` | AWS Agent Registry is unavailable in the target region, so regional `AR-03` through `AR-08` checks were not run. | `N/A` / Informational |
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
Informational and `N/A` rows are excluded from the score. Agentic AI and
compliance-mapping rows are contextual views of source evidence and are also
excluded to prevent double counting. Resource-level rows remain visible for
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

---

## Amazon SageMaker AI Security Checks (29)

### SM-01: Internet Access

- **Severity:** High
- **AWS Security Hub Control:** SageMaker.2
- **Description:** Checks for direct internet access on notebooks and domains.

### SM-02: AWS IAM Permissions

- **Severity:** High
- **Description:** Identifies overly permissive policies and stale access from
  the shared IAM permissions cache. A missing, unreadable, or malformed cache
  produces an informational `N/A` incomplete-assessment row rather than a
  compliant result.

### SM-03: Data Protection

- **Severity:** High
- **AWS Security Hub Control:** SageMaker.1
- **Description:** Verifies encryption at rest and in transit for notebooks and domains.

### SM-04: Amazon GuardDuty Integration

- **Severity:** High
- **Description:** Verifies Amazon GuardDuty runtime threat detection is enabled.

### SM-05: MLOps Features

- **Severity:** Low
- **Description:** Checks MLOps pipelines, experiment tracking, and model registry usage.

### SM-06: Clarify Usage

- **Severity:** Low
- **Description:** Validates SageMaker Clarify for bias detection and explainability.

### SM-07: Model Monitor

- **Severity:** Medium
- **Description:** Checks Model Monitor configuration for drift detection.

### SM-08: Model Registry

- **Severity:** Medium
- **Description:** Validates model registry usage and permissions.

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
- **AWS Security Hub Control:** SageMaker.4
- **Description:** Checks inference containers have network isolation.

### SM-12: Endpoint Instance Count

- **Severity:** Medium
- **AWS Security Hub Control:** SageMaker.5
- **Description:** Verifies endpoints have 2+ instances for high availability.

### SM-13: Monitoring Network Isolation

- **Severity:** Medium
- **Description:** Checks monitoring job network isolation.

### SM-14: Model Container Repository

- **Severity:** Medium
- **Description:** Validates model container repository access.

### SM-15: Feature Store Encryption

- **Severity:** High
- **Description:** Checks feature group encryption settings.

### SM-16: Data Quality Encryption

- **Severity:** Medium
- **Description:** Validates data quality job encryption.

### SM-17: Processing Job Encryption

- **Severity:** Medium
- **Description:** Verifies processing job encryption.

### SM-18: Transform Job Encryption

- **Severity:** Medium
- **Description:** Checks transform job volume encryption.

### SM-19: Hyperparameter Tuning Encryption

- **Severity:** Medium
- **Description:** Validates hyperparameter tuning job encryption.

### SM-20: Compilation Job Encryption

- **Severity:** Medium
- **Description:** Checks compilation job encryption.

### SM-21: AutoML Network Isolation

- **Severity:** Medium
- **Description:** Validates AutoML job network isolation.

### SM-22: Model Approval Workflow

- **Severity:** Medium
- **Description:** Checks model approval and governance workflow.

### SM-23: Model Drift Detection

- **Severity:** Medium
- **Description:** Validates model drift monitoring configuration.

### SM-24: A/B Testing and Shadow Deployment

- **Severity:** Low
- **Description:** Checks for safe deployment patterns.

### SM-25: ML Lineage Tracking

- **Severity:** Low
- **Description:** Validates experiment tracking and lineage.

### SM-26: GuardDuty AI Protection

- **Severity:** High
- **Description:** Reuses the regional GuardDuty detector inventory and verifies the `AI_PROTECTION` feature is `ENABLED`. No detector is N/A because SM-04 separately reports GuardDuty enablement.

### SM-27: HyperPod EBS CMK Encryption

- **Severity:** Medium
- **Description:** Verifies every HyperPod instance group configures a customer-managed KMS key for its root EBS volume and all configured secondary EBS volumes. AWS documents that HyperPod root volumes use an AWS-owned key by default and that a customer-managed key is supplied through `InstanceStorageConfigs`; therefore, an absent root-volume storage configuration fails this CMK baseline rather than producing `N/A`.

### SM-28: HyperPod VPC Configuration

- **Severity:** Medium
- **Description:** Verifies each HyperPod instance group's effective VPC configuration has subnets and security groups, honoring `OverrideVpcConfig` before the cluster-level `VpcConfig`.

`SM-29` is reserved for SageMaker Unified Studio private networking. It is not currently emitted because the available domain APIs do not expose a sufficient domain-level networking configuration.

### SM-30: Model Package Group Resource Policy Exposure

- **Severity:** High for public or configured-boundary violations; Informational for unclassified external sharing
- **Description:** Parses model package group resource policies to identify public wildcard principals and external accounts or organizations outside optional `AIML_APPROVED_EXTERNAL_ACCOUNT_IDS` / `AIML_APPROVED_ORG_IDS` boundaries. Configure those boundaries through the `ApprovedExternalAccountIds` and `ApprovedOrganizationIds` deployment parameters, respectively; both default to empty. Wildcard principals constrained by exact `aws:PrincipalAccount` or `aws:PrincipalOrgID` values, fixed-account `aws:PrincipalArn` patterns, or fixed-organization `aws:PrincipalOrgPaths` patterns are treated as bounded. Wildcard account/organization identifiers remain public; `ForAllValues` organization-path conditions count as boundaries only when a matching `Null: false` condition requires the key to be present. Because AWS supports `NotPrincipal` only with `Deny`, an `Allow` statement containing `NotPrincipal` is reported as unsupported and `N/A` rather than silently passing or being treated as public. Valid `Deny` statements do not create exposure and are ignored. If `sts:GetCallerIdentity` is unavailable, public wildcard statements are still reported, but account principals that cannot be distinguished as same-account or external produce `N/A` instead of an external-access finding. This is a conservative heuristic, not a complete IAM authorization simulator.

---

## Amazon Bedrock Security Checks (40)

### BR-01: AWS IAM Least Privilege

- **Severity:** High
- **Description:** Identifies roles with AmazonBedrockFullAccess policy.

### BR-02: Amazon VPC Endpoint Configuration

- **Severity:** High
- **Description:** Validates Bedrock Amazon VPC endpoints exist for private connectivity.

### BR-03: Marketplace Subscription Access

- **Severity:** Medium
- **Description:** Checks for overly permissive marketplace subscription access.

BR-01, BR-02, BR-03, BR-08, BR-10, and BR-21 depend on the shared IAM
permissions cache. If that prerequisite is missing, unreadable, or malformed,
each affected control is reported as informational `N/A`; an empty replacement
inventory is never treated as evidence of compliance.

### BR-04: Model Invocation Logging

- **Severity:** Medium
- **Description:** Checks invocation logging is enabled.

### BR-05: Guardrail Configuration

- **Severity:** High
- **Description:** Verifies guardrails are configured and enforced.

### BR-06: AWS CloudTrail Logging

- **Severity:** Medium
- **Description:** Validates AWS CloudTrail logging for Bedrock API calls.

### BR-07: Prompt Management

- **Severity:** Low
- **Description:** Validates Bedrock Prompt template usage and variants.

### BR-08: Agent AWS IAM Configuration

- **Severity:** Medium
- **Description:** Checks agent execution role permissions.

### BR-09: Knowledge Base Encryption

- **Severity:** High
- **Description:** Checks knowledge base encryption settings.

### BR-10: Guardrail AWS IAM Enforcement

- **Severity:** Medium
- **Description:** Verifies guardrails are enforced through AWS IAM conditions.

### BR-11: Custom Model Encryption

- **Severity:** High
- **Description:** Validates custom models use customer-managed AWS KMS keys.

### BR-12: Invocation Log Encryption

- **Severity:** Medium
- **Description:** Verifies logs are encrypted with AWS KMS.

### BR-13: Flows Guardrails

- **Severity:** Medium
- **Description:** Validates Bedrock Flows have guardrails attached.

### BR-14: Stale Bedrock Access

- **Severity:** Medium
- **Description:** Detects principals with Bedrock permissions that have not used the service recently, using IAM service-last-accessed data. As an IAM-global check, it runs once per execution and is tagged with the `Global` region in multi-region scans.

### BR-15: Cross-Account Guardrails Enforcement

- **Severity:** High
- **Type:** Global (runs once)
- **Description:** Verifies organization-level guardrails are configured using AWS Organizations Amazon Bedrock policies (the `BEDROCK_POLICY` policy type) for centralized safety control enforcement across all accounts. Checks if running in the AWS Organizations management account, validates the Bedrock policy type is enabled at the organization root, and verifies that Bedrock policies are attached.

### BR-16: Guardrail Tier Validation

- **Severity:** Medium
- **Type:** Regional
- **Description:** Verifies guardrails use the `STANDARD` content-filter tier (vs the `CLASSIC` tier) for enhanced protection and broader language support. Lists all guardrails in the region and inspects each guardrail's `contentPolicy.tier.tierName`. The STANDARD tier requires cross-Region inference.

### BR-17: Custom Model Customer-Managed KMS Encryption

- **Severity:** High
- **Type:** Regional
- **Description:** Verifies fine-tuned/customized models use customer-managed KMS keys instead of AWS-owned keys for greater control over encryption. Lists all custom models, retrieves model details to check KMS key configuration, and validates KMS key ARN format. This extends the existing BR-11 check by specifically verifying the type of encryption key used.

### BR-18: Model Evaluation Implementation

- **Severity:** Medium
- **Type:** Regional
- **Description:** Checks if model evaluation jobs exist to assess safety metrics (toxicity, accuracy, semantic robustness) before production deployment. Lists all model evaluation jobs, identifies recent evaluations (completed within 30 days), and analyzes evaluation configurations for safety metrics.

### BR-19: Prompt Flow Validation

- **Severity:** Medium
- **Type:** Regional
- **Description:** Verifies Bedrock Agents prompt flows are validated using `validate_flow_definition` API before deployment to prevent misconfigured flows. Lists all flows in the region, checks for validation records or status, identifies unvalidated flows, and reports flows deployed without validation.

### BR-20: Knowledge Base Encryption Enhancement

- **Severity:** High
- **Type:** Regional
- **Description:** Extends existing BR-09 to verify Knowledge Base encryption uses customer-managed KMS keys. Uses the authoritative knowledge base `type` (`VECTOR | KENDRA | SQL | MANAGED`) to decide how to assess each KB: for `MANAGED` knowledge bases it reads `knowledgeBaseConfiguration.managedKnowledgeBaseConfiguration.serverSideEncryptionConfiguration.kmsKeyArn` and fails KBs encrypted with an AWS-owned key; for custom vector stores (OpenSearch, RDS, Pinecone, etc.) the encryption key lives on the underlying storage resource and cannot be read from the KB API, so those are reported as N/A for manual review. If a `MANAGED` KB's encryption block is missing from the API response (deployed botocore older than 1.43.32, which silently drops the unmodeled field), the KB is reported as N/A "indeterminate" rather than a false-positive failure.

### BR-21: Agent Action Group IAM Least Privilege

- **Severity:** High
- **Type:** Regional
- **Description:** Extends existing BR-08 to specifically check if Bedrock Agent action groups use scoped Lambda execution roles with minimal permissions. Enumerates agents and their action groups, retrieves Lambda execution roles for each action group, analyzes IAM policies for overly broad permissions (AdministratorAccess, FullAccess, Resource: "*"), and verifies principle of least privilege.

### BR-22: Model Invocation Throttling Limits

- **Severity:** Medium
- **Type:** Regional
- **Description:** Verifies service quotas are configured for model invocation throttling to prevent abuse/DoS and control costs. Queries Service Quotas for Bedrock, checks if custom limits are set for on-demand model invocation TPM (tokens per minute), provisioned throughput limits, and concurrent requests. Reports accounts relying solely on default quotas.

### BR-23: Guardrail Content Filter Coverage

- **Severity:** High
- **Type:** Regional
- **Description:** Extends existing BR-05 to verify guardrails have ALL content filters enabled (hate, insults, sexual, violence) with appropriate thresholds. For each guardrail, checks content filter configuration for all four filter types, verifies filter thresholds are configured, and reports missing or misconfigured filters.

### BR-24: Automated Reasoning Policy Implementation

- **Severity:** Medium
- **Type:** Regional
- **Description:** Checks if Automated Reasoning policies are configured on guardrails for formal verification of model responses. Enumerates guardrails, checks for Automated Reasoning policy configuration, validates policy syntax and enabled state, and reports guardrails without formal verification capability.

### BR-25: RAG Evaluation Jobs

- **Severity:** Low
- **Type:** Regional
- **Description:** Verifies RAG applications have evaluation jobs configured to assess context relevance, response correctness, and prevent hallucinations. Lists Knowledge Bases, checks for associated RAG evaluation jobs for each KB, verifies evaluation metrics include context relevance, response correctness, faithfulness, and harmfulness checks. Reports KBs without evaluation jobs.

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
- **Description:** Verifies batch inference (model invocation) jobs encrypt their S3 output with a customer-managed KMS key. Reads `outputDataConfig.s3OutputDataConfig.s3EncryptionKeyId` from the job summaries returned by `ListModelInvocationJobs` and reports jobs without a customer-managed output key.

### BR-32: CloudWatch Alarms on Bedrock Metrics

- **Severity:** Medium
- **Type:** Regional
- **Description:** Verifies CloudWatch alarms exist on Amazon Bedrock runtime metrics (the `AWS/Bedrock` namespace) to detect abuse, denial-of-wallet, sustained throttling, and content-filter spikes. Uses `DescribeAlarms` and matches alarms that target the `AWS/Bedrock` namespace directly or via a metric-math expression. Only assessed in regions that have Bedrock resources.

### BR-33: Amazon Inspector Lambda Code Scanning

- **Severity:** Medium
- **Type:** Regional
- **Description:** When Lambda functions with Bedrock indicators are detected in the region, verifies Amazon Inspector Lambda standard scanning (`lambda`) and Lambda code scanning (`lambdaCode`) are both enabled so those in-scope functions and their dependencies are scanned for vulnerable packages and hardcoded secrets. Calls `lambda:ListFunctions` for scoping and `inspector2:BatchGetAccountStatus` for Inspector status. Reports `Failed` only when in-scope Lambda functions exist and either `resourceState.lambda.status` or `resourceState.lambdaCode.status` is not `ENABLED`. No in-scope Lambda functions, access denied, and region-unavailable states resolve to `N/A`.

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

## Amazon Bedrock AgentCore Security Checks (17)

### AC-01: Runtime Amazon VPC Configuration

- **Severity:** High
- **Description:** Validates agent runtimes have proper Amazon VPC settings.

### AC-02: AWS IAM Full Access

- **Severity:** High
- **Description:** Checks attached and inline policy documents for AgentCore full-access managed policies, wildcard IAM action patterns, and `Allow`/`NotAction` allow-except statements that still grant the AgentCore namespace when they apply to all resources. Only the valid `bedrock-agentcore` IAM namespace is evaluated; overly permissive `agent-registry` grants are reported by [AR-01](#ar-01-aws-iam-full-access) instead. Service-agnostic administrator-style grants are out of scope in both forms: a bare `Action: "*"` and a `NotAction` whose exclusions name no platform namespace are treated alike and not reported as AgentCore-specific grants. A missing, unreadable, or malformed permissions cache is reported as informational `N/A`. If an individual cached policy document cannot be parsed, valid findings from other policies are retained and an additional informational `N/A` row marks the control incomplete; the unparsed policy cannot produce a compliant pass.

### AC-03: Stale Access

- **Severity:** Low
- **Description:** Detects unused AgentCore permissions by inspecting `Allow` and `NotAction` grants in attached and inline policy documents before querying IAM service-last-accessed history. Only the `bedrock-agentcore` namespace is evaluated; `agent-registry` grants are reported by [AR-02](#ar-02-stale-access) instead. As in AC-02, a `NotAction` whose exclusions name no platform namespace is a service-agnostic administrator grant and is not treated as an AgentCore-specific permission. Attached policy names alone are never treated as proof of access. IAM last-accessed jobs are polled within the Lambda deadline; a job that does not complete in time is reported as an indeterminate `N/A` rather than a failed control. A missing, unreadable, or malformed permissions cache is also reported as informational `N/A`. This identifies candidate grants from the cached policy documents; it is not a complete effective-permissions simulation across boundaries, session policies, or organization controls.

### AC-04: Observability

- **Severity:** Medium
- **Description:** Verifies Amazon CloudWatch Logs and AWS X-Ray tracing configuration.

### AC-05: Amazon ECR Repository Encryption

- **Severity:** High
- **Description:** Validates Amazon ECR repositories use encryption.

### AC-06: Browser Tool Recording

- **Severity:** Medium
- **Description:** Uses custom browser inventory and requires `recording.enabled=true` with a non-empty S3 recording bucket.

### AC-07: Memory Encryption

- **Severity:** Medium
- **Description:** Checks agent memory encryption with AWS KMS.

### AC-08: Amazon VPC Endpoints

- **Severity:** High
- **Description:** Validates Amazon VPC endpoints for AgentCore services.

### AC-09: Service-Linked Role

- **Severity:** Medium
- **Description:** Verifies the AgentCore service-linked role exists.

### AC-10: Resource-Based Policies

- **Severity:** Medium
- **Description:** Checks runtime and gateway resource policies.

### AC-11: Policy Engine Encryption

- **Severity:** Medium
- **Description:** Validates policy engine encryption settings.

### AC-12: Gateway Encryption

- **Severity:** Medium
- **Description:** Verifies gateway encryption settings.

### AC-13: Gateway Configuration

- **Severity:** Medium
- **Description:** Validates gateway security configuration.

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
permission cache and are reported once under the `Global` region. `AR-03`
through `AR-08` are regional and use the generally available
`agent-registry-control` API. Registry detail is read once per registry and
shared across `AR-03` through `AR-06`; record inventory is shared between
`AR-07` and `AR-08`.

Record inventory is bounded to 1,000 records and paginates within the Lambda
deadline. When the cap or the deadline is reached, `AR-07` and `AR-08` report a
single informational `N/A` incomplete-assessment row and continue assessing
the records already collected. A registry that is not `READY`, a registry
whose detail call fails, an access-denied response, and a region where AWS
Agent Registry is unavailable all resolve to informational `N/A` with
error-specific remediation rather than to a failure.

### AR-01: AWS IAM Full Access

- **Severity:** High
- **Description:** Checks attached and inline policy documents from the permission cache for AWS Agent Registry full-access managed policies, wildcard IAM action patterns, and `Allow`/`NotAction` allow-except statements that still grant the `agent-registry` namespace when they apply to all resources. Only the valid `agent-registry` IAM namespace is evaluated; `bedrock-agentcore` grants are reported by [AC-02](#ac-02-aws-iam-full-access) instead. Service-agnostic administrator-style grants are out of scope in both forms: a bare `Action: "*"` and a `NotAction` whose exclusions name no platform namespace are treated alike and not reported as Registry-specific grants. An empty permission cache is an informational `N/A` tooling condition, not a failure.

### AR-02: Stale Access

- **Severity:** Medium for 60+ day inactivity; Low when all principals are active; Informational when never used or incomplete
- **Description:** Identifies IAM roles and users whose attached or inline policy documents grant the `agent-registry` namespace, either through an `Allow` action or through a `NotAction` allow-except statement that does not fully cover the namespace. Attached policy names alone are never treated as proof of access. It uses IAM service-last-accessed jobs to identify access older than 60 days and principals with no Registry usage evidence. IAM job errors, timeouts, and inaccessible principals are indeterminate informational `N/A` findings rather than failures.

### AR-03: Registry Publication Approval Governance

- **Severity:** Informational by default; Medium when required
- **Description:** Verifies whether each `READY` registry requires manual review for submitted records. A registry whose `approvalConfiguration` carries `autoApprovalRules` approves submitted records automatically and is informational by default; set `RequireAgentRegistryManualApproval` to `true` (`REQUIRE_AGENT_REGISTRY_MANUAL_APPROVAL` in the Lambda) to make automatic approval fail, which also switches the remediation text from advisory to actionable. A registry with no auto-approval rules passes. `approvalConfiguration` is optional in the GA response; a registry that omits it is reported as informational `N/A` because manual review was never observed, not as a pass.

### AR-04: Registry Discovery Authorization

- **Severity:** Informational for configured authorizers; High for an unconstrained custom JWT authorizer
- **Description:** Inventories the discovery authorizer on each `READY` registry. A custom JWT authorizer without **both** an OpenID Connect discovery URL and at least one caller constraint (`allowedAudience`, `allowedClients`, `allowedScopes`, or `customClaims`) fails. Every other outcome is informational `N/A` pending review, because the authorizer configuration alone does not establish which callers hold effective discovery access: `AWS_IAM` requires an effective-policy review, a constrained custom JWT authorizer requires comparing the approved audiences, clients, scopes, and claims against intended consumers, and an absent or unrecognized `discoveryConfiguration` establishes no authorization fact either way.

### AR-05: Registry Customer-Managed KMS Encryption

- **Severity:** Informational by default; Medium when required
- **Description:** Reads `GetRegistry.encryptionConfiguration.kmsKeyArn`. Registries with a customer-managed KMS key pass. Registries using the default AWS owned key are informational by default because AWS Agent Registry still encrypts them at rest. Set `RequireAgentRegistryCMK` to `true` (`REQUIRE_AGENT_REGISTRY_CMK` in the Lambda) to make the AWS owned key configuration fail. The registry encryption key is immutable after creation, so remediation requires a replacement registry and record migration.

### AR-06: Registry Organization Auto-Detection

- **Severity:** Medium when active; otherwise Informational
- **Description:** Passes only when a `READY` registry reports auto-detection that is enabled, scoped to `ORGANIZATION`, and `ACTIVE`. Disabled, account-scoped, or `INACTIVE` configurations are informational `N/A` because the feature is optional. An omitted or incomplete optional `autoDetection` block, and a registry that has not reached `READY`, are also informational `N/A` because the control state could not be established.

### AR-07: Registry Record Lifecycle Governance

- **Severity:** Informational
- **Description:** Paginates `ListRegistryRecords` across every accessible registry and reports the lifecycle state returned in each record summary as an advisory `N/A` observation, because occupying a documented service state does not by itself prove a security control. Review failed or unknown lifecycle states operationally. Per-registry listing failures are reported individually with error-specific remediation so one inaccessible registry does not hide the rest. `AR-07` does not affect the score unless a future baseline defines a genuine noncompliant lifecycle state.

### AR-08: Registry Record Provenance

- **Severity:** Medium
- **Description:** Verifies that manually created records retain a 12-digit creator-account attribution and that auto-detected records carry a `DETECTED_FROM` provenance summary whose `sourceId` is a `bedrock-agentcore` ARN matching its declared `sourceType`: a `runtime/...` resource for `AWS::BedrockAgentCore::Runtime` or a `gateway/...` resource for `AWS::BedrockAgentCore::Gateway`. A record whose declared lineage does not match fails, and it continues to fail even when another provenance entry omits its own source type. Optional origin-mode, creator-attribution, provenance, and source-type metadata are reported as informational `N/A` rather than as operator-remediable failures.

---

## Agentic AI Security Checks (38)

Agentic AI Security checks use the `AG-XX` namespace and are included with the
default assessment. They follow a hybrid model:

- Reused API-backed controls from Amazon Bedrock, Amazon Bedrock AgentCore,
  and AWS Agent Registry are mapped into agentic security domains.
- New checks are added only where AWS APIs can prove the control state.
- Controls that cannot be proven by AWS APIs are not scored. Human-in-the-loop
  governance is therefore documented as a methodology note, not emitted as an
  automated pass/fail finding.

These checks reference the
[AWS Well-Architected Agentic AI Lens](https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html),
with scope limited to the Security pillar.

### AG-01: Agent Guardrail Association

- **Severity:** High
- **Source:** BR-28
- **Domain:** Guardrail Enforcement
- **Description:** Maps Bedrock agent guardrail association into the Agentic AI Security view.

### AG-02: Harmful Content Guardrail Coverage

- **Severity:** Source check severity
- **Source:** BR-23
- **Domain:** Guardrail Enforcement
- **Description:** Maps guardrail content filter coverage for agent-facing workloads.

### AG-03: Sensitive Information Protection

- **Severity:** Source check severity
- **Source:** BR-26
- **Domain:** Memory & Data Privacy
- **Description:** Maps guardrail sensitive-information and PII protection controls.

### AG-04: Automated Reasoning Guardrails

- **Severity:** Source check severity
- **Source:** BR-24
- **Domain:** Guardrail Enforcement
- **Description:** Maps automated reasoning policies used to verify responses against deterministic rules.

### AG-05: Grounding Controls

- **Severity:** Source check severity
- **Source:** BR-27
- **Domain:** Prompt & Input Protection
- **Description:** Maps contextual grounding checks for RAG and tool-using agents.

### AG-06: Tool Execution Least Privilege

- **Severity:** Source check severity
- **Source:** BR-21
- **Domain:** Tool Authorization
- **Description:** Maps Bedrock agent action group IAM least-privilege findings.

### AG-07: Model Invocation Logging

- **Severity:** Source check severity
- **Source:** BR-04
- **Domain:** Auditability & Observability
- **Description:** Maps model invocation logging for agent prompts, responses, and guardrail traces.

### AG-08: API Audit Trail

- **Severity:** Source check severity
- **Source:** BR-06
- **Domain:** Auditability & Observability
- **Description:** Maps CloudTrail coverage for Bedrock activity.

### AG-09: Guardrail Enforcement Boundary

- **Severity:** Source check severity
- **Source:** BR-15
- **Domain:** Guardrail Enforcement
- **Description:** Maps organization-level guardrail enforcement controls.

### AG-10: Adversarial Evaluation Coverage

- **Severity:** Source check severity
- **Source:** BR-18
- **Domain:** Prompt & Input Protection
- **Description:** Maps model/application evaluation coverage for adversarial and safety testing.

### AG-11: Prompt Flow Validation

- **Severity:** Source check severity
- **Source:** BR-19
- **Domain:** Prompt & Input Protection
- **Description:** Maps Bedrock flow validation before deployment.

### AG-12: Invocation Abuse Controls

- **Severity:** Source check severity
- **Source:** BR-22
- **Domain:** Abuse & Cost Protection
- **Description:** Maps Bedrock service quota and throttling controls.

### AG-13: Session Boundary

- **Severity:** Source check severity
- **Source:** BR-29
- **Domain:** Bounded Autonomy
- **Description:** Maps Bedrock agent idle session TTL controls.

### AG-14: Operational Abuse Alarms

- **Severity:** Source check severity
- **Source:** BR-32
- **Domain:** Abuse & Cost Protection
- **Description:** Maps CloudWatch alarms for Bedrock invocation abuse and operational anomalies.

### AG-15: Runtime Network Boundary

- **Severity:** Source check severity
- **Source:** AC-01
- **Domain:** Bounded Autonomy
- **Description:** Maps AgentCore runtime VPC configuration.

### AG-16: AgentCore Least Privilege

- **Severity:** Source check severity
- **Source:** AC-02
- **Domain:** Agent Identity & Access
- **Description:** Maps AgentCore full-access IAM findings.

### AG-17: Stale AgentCore Access

- **Severity:** Source check severity
- **Source:** AC-03
- **Domain:** Agent Identity & Access
- **Description:** Maps stale AgentCore permissions.

### AG-18: AgentCore Observability

- **Severity:** Source check severity
- **Source:** AC-04
- **Domain:** Auditability & Observability
- **Description:** Maps AgentCore logging, tracing, and observability coverage.

### AG-19: Memory Data Protection

- **Severity:** Source check severity
- **Source:** AC-07
- **Domain:** Memory & Data Privacy
- **Description:** Maps AgentCore memory encryption controls.

### AG-20: Private AgentCore Connectivity

- **Severity:** Source check severity
- **Source:** AC-08
- **Domain:** Bounded Autonomy
- **Description:** Maps VPC endpoint coverage for AgentCore services.

### AG-21: Resource Policy Boundary

- **Severity:** Source check severity
- **Source:** AC-10
- **Domain:** Agent Identity & Access
- **Description:** Maps AgentCore runtime and gateway resource-based policy controls.

### AG-22: Policy Engine Data Protection

- **Severity:** Source check severity
- **Source:** AC-11
- **Domain:** Tool Authorization
- **Description:** Maps AgentCore policy engine encryption controls.

### AG-23: Gateway Data Protection

- **Severity:** Source check severity
- **Source:** AC-12
- **Domain:** Tool Authorization
- **Description:** Maps AgentCore gateway encryption controls.

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

### AG-28: Identity Token Vault Protection

- **Severity:** Source check severity
- **Source:** AC-14
- **Domain:** Agent Identity & Access
- **Description:** Maps AgentCore Identity token-vault CMK encryption.

### AG-29: Code Interpreter Isolation

- **Severity:** Source check severity
- **Source:** AC-15
- **Domain:** Bounded Autonomy
- **Description:** Maps custom Code Interpreter VPC isolation.

### AG-30: Prompt Attack Protection

- **Severity:** Source check severity
- **Source:** BR-34
- **Domain:** Prompt & Input Protection
- **Description:** Maps preventive Bedrock Guardrails prompt-attack filtering.

### AG-31: Browser Tool Isolation

- **Severity:** Source check severity
- **Source:** AC-16
- **Domain:** Bounded Autonomy
- **Description:** Maps custom AgentCore browser VPC isolation.

### AG-32: Online Evaluation Assurance

- **Severity:** Source check severity
- **Source:** AC-17
- **Domain:** Auditability & Continuous Assurance
- **Description:** Maps AgentCore online evaluation configuration without claiming universal runtime trace coverage.

### AG-33: Registry Publication Approval Governance

- **Severity:** Source check severity
- **Source:** AR-03
- **Domain:** Agent Identity & Access
- **Description:** Maps Agent Registry publication approval configuration into the Agentic AI Security view.

### AG-34: Registry Discovery Authorization

- **Severity:** Source check severity
- **Source:** AR-04
- **Domain:** Agent Identity & Access
- **Description:** Maps Agent Registry authorizer inventory and manual-review guidance into the Agentic AI Security view. Configured IAM and constrained JWT authorizers remain informational until effective access or approved JWT caller values can be established.

### AG-35: Registry Metadata Encryption

- **Severity:** Source check severity
- **Source:** AR-05
- **Domain:** Memory & Data Privacy
- **Description:** Maps Agent Registry customer-managed KMS encryption into the Agentic AI Security view.

### AG-36: Organization Discovery Coverage

- **Severity:** Source check severity
- **Source:** AR-06
- **Domain:** Auditability & Continuous Assurance
- **Description:** Maps organization-scoped Agent Registry auto-detection health into the Agentic AI Security view.

### AG-37: Registry Record Lifecycle Governance

- **Severity:** Source check severity
- **Source:** AR-07
- **Domain:** Agent Identity & Access
- **Description:** Maps advisory Agent Registry record lifecycle observations into the Agentic AI Security view.

### AG-38: Registry Record Provenance

- **Severity:** Source check severity
- **Source:** AR-08
- **Domain:** Auditability & Continuous Assurance
- **Description:** Maps Agent Registry creator attribution and auto-detected runtime or gateway lineage into the Agentic AI Security view.

### Runtime guardrail methodology note

`InvokeGuardrailChecks` / `ApplyGuardrail` are per-request runtime APIs rather than a persistent configuration surface. The assessment therefore does not emit a pass/fail finding for their use; applications should validate these calls through runtime architecture review, telemetry, and testing.

---

## Additional Resources

- [Amazon SageMaker Security Best Practices](https://docs.aws.amazon.com/sagemaker/latest/dg/security.html)
- [Amazon Bedrock Security](https://docs.aws.amazon.com/bedrock/latest/userguide/security.html)
- [AWS Well-Architected Agentic AI Lens](https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html)
- [AWS Security Hub SageMaker Controls](https://docs.aws.amazon.com/securityhub/latest/userguide/sagemaker-controls.html)
- [AWS Well-Architected Framework - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)

---

## Responsible AI GRC Checks (64 additional, 5 upstream extensions)

These 64 standalone checks (FS-XX) extend the framework with cross-industry AI
governance, risk, and compliance controls derived from the
[AWS User Guide to Governance, Risk, and Compliance for Responsible AI Adoption](https://aws.amazon.com/blogs/security/introducing-the-updated-aws-user-guide-to-governance-risk-and-compliance-for-responsible-ai-adoption/).
An additional 5 FS checks are contributed as extensions to existing SM-07,
SM-22, SM-23, BR-04, and BR-06 (see in-file extension notes).

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

The same document includes the shared intro, severity rubric, validation note,
upstream-overlap table, and the compliance framework mapping table
(SR 11-7, FFIEC CAT, NYDFS 500.06, PCI-DSS 12.3.2, DORA Art.6, MAS TRM 9,
ISO 27001 A.12, ECOA, OWASP LLM Top 10).

---

## OWASP Top 10 for LLM Checks (12)

These 12 checks (OW-XX) map the AI/ML Security Assessment findings to the
[OWASP Top 10 for LLM 2025](https://genai.owasp.org/llm-top-10/) categories.
OW-01..OW-10 are **derived by mapping** from existing BR/SM/AC/FS findings.
The OWASP Lambda itself does not call AWS APIs for mapped rows, but enabling
OWASP can auto-run Responsible AI GRC to produce FS-* source findings when
Responsible AI GRC is otherwise disabled. OW-11 and OW-12 are net-new checks
that address LLM07 (System Prompt Leakage), which the existing checks do not
directly cover.
If a required source CSV is missing, the OWASP Lambda emits an informational
`OW-00` completeness row rather than silently dropping derived rows.

**Opt-in.** OWASP checks run only when the `EnableOWASPAssessment` deployment
parameter is `true` and the Step Functions execution includes `"enableOWASP": "true"`.

**Rendered under a new "By Compliance Standard" sidebar section** of the HTML
report, alongside future NIST AI RMF and EU AI Act sections.

The full catalog is in **[`SECURITY_CHECKS_OWASP.md`](./SECURITY_CHECKS_OWASP.md)**,
organized by OWASP category:

- **LLM01 Prompt Injection** — OW-01
- **LLM02 Sensitive Information Disclosure** — OW-02
- **LLM03 Supply Chain** — OW-03
- **LLM04 Data and Model Poisoning** — OW-04
- **LLM05 Improper Output Handling** — OW-05
- **LLM06 Excessive Agency** — OW-06
- **LLM07 System Prompt Leakage** — OW-07 (mapping-based) + OW-11, OW-12 (native)
- **LLM08 Vector and Embedding Weaknesses** — OW-08
- **LLM09 Misinformation** — OW-09
- **LLM10 Unbounded Consumption** — OW-10

**Preliminary and illustrative.** OWASP mappings have not been reviewed by
external auditors. Validate mappings with your Security/Compliance team
before using as audit evidence.
