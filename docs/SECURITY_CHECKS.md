# Security Checks Reference

This document provides a comprehensive reference for all 174 security checks performed by the AI/ML Security Assessment framework (71 core checks across Amazon Bedrock, Amazon SageMaker AI, and Amazon Bedrock AgentCore, 27 Agentic AI Security checks, 64 Financial Services GenAI Risk checks, and 12 OWASP Top 10 for LLM checks).

## Table of Contents

- [Overview](#overview)
- [Check ID Convention](#check-id-convention)
- [Severity Levels](#severity-levels)
- [Status Values](#status-values)
- [Amazon SageMaker AI Security Checks (25)](#amazon-sagemaker-ai-security-checks-25)
- [Amazon Bedrock Security Checks (33)](#amazon-bedrock-security-checks-33)
- [Amazon Bedrock AgentCore Security Checks (13)](#amazon-bedrock-agentcore-security-checks-13)
- [Agentic AI Security Checks (27)](#agentic-ai-security-checks-27)
- [Financial Services GenAI Risk Checks (64)](#financial-services-genai-risk-checks-64-additional-5-upstream-extensions)
- [OWASP Top 10 for LLM Checks (12)](#owasp-top-10-for-llm-checks-12)

---

## Overview

The framework evaluates your AI/ML workloads against AWS security best practices across three services:

| Service | Number of Checks | Focus Areas |
| --------- | ------------------ | ------------- |
| Amazon SageMaker AI | 25 | Security Hub controls, encryption, network isolation, IAM, MLOps |
| Amazon Bedrock | 33 | Guardrails, content filters, sensitive-information/PII filters, contextual grounding, automated reasoning, encryption (custom, imported, knowledge base, batch inference output), VPC endpoints, IAM permissions, agent guardrail association and least privilege, logging, CloudWatch alarms, cross-account policies, model evaluation, prompt flow validation, RAG evaluation, service quotas, Lambda code scanning (Amazon Inspector) |
| Amazon Bedrock AgentCore | 13 | VPC configuration, encryption, observability, resource policies |
| Agentic AI Security | 27 | Bounded autonomy, agent identity, tool authorization, guardrail enforcement, prompt/input protection, memory privacy, auditability, abuse protection |
| Financial Services GenAI Risk | 64 | Unbounded consumption, excessive agency, supply chain, training data poisoning, vector weaknesses, non-compliant output, misinformation, harmful output, biased output, PII disclosure, hallucination, prompt injection, improper output handling, off-topic output, out-of-date training data |
| OWASP Top 10 for LLM | 12 | LLM01 Prompt Injection, LLM02 Sensitive Info Disclosure, LLM03 Supply Chain, LLM04 Data/Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector/Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption |

---

## Check ID Convention

Each security check has a unique identifier with a service prefix:

| Prefix | Service | Example |
| -------- | --------- | --------- |
| **SM-XX** | Amazon SageMaker | SM-01, SM-25 |
| **BR-XX** | Amazon Bedrock | BR-01, BR-33 |
| **AC-XX** | Amazon Bedrock AgentCore | AC-01, AC-13 |
| **AG-XX** | Agentic AI Security | AG-01, AG-27 |
| **FS-XX** | Financial Services GenAI Risk | FS-01, FS-69 |
| **OW-XX** | OWASP Top 10 for LLM | OW-01, OW-12 |

---

## Severity Levels

| Severity | Description | Action Required |
| ---------- | ------------- | ----------------- |
| **High** | Critical security issues that could lead to data exposure, unauthorized access, or compliance violations | Immediate remediation recommended |
| **Medium** | Important security improvements that strengthen your security posture | Address in next maintenance window |
| **Low** | Minor optimizations and best practice recommendations | Address when convenient |
| **Informational** | Advisory information about your configuration | No action required |
| **N/A** | Check not applicable (no resources to assess) | No action required |

---

## Status Values

| Status | Description |
| -------- | ------------- |
| **Failed** | Security issue identified that requires remediation |
| **Passed** | Checked resources met the assessed best practice at time of scan |
| **N/A** | No resources exist to check (for example, no notebooks, no guardrails configured) |

---

## Amazon SageMaker AI Security Checks (25)

### SM-01: Internet Access

- **Severity:** High
- **AWS Security Hub Control:** SageMaker.2
- **Description:** Checks for direct internet access on notebooks and domains.

### SM-02: AWS IAM Permissions

- **Severity:** High
- **Description:** Identifies overly permissive policies, stale access, and IAM Identity Center configuration.

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

---

## Amazon Bedrock Security Checks (33)

### BR-01: AWS IAM Least Privilege

- **Severity:** High
- **Description:** Identifies roles with AmazonBedrockFullAccess policy.

### BR-02: Amazon VPC Endpoint Configuration

- **Severity:** High
- **Description:** Validates Bedrock Amazon VPC endpoints exist for private connectivity.

### BR-03: Marketplace Subscription Access

- **Severity:** Medium
- **Description:** Checks for overly permissive marketplace subscription access.

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

---

## Amazon Bedrock AgentCore Security Checks (13)

### AC-01: Runtime Amazon VPC Configuration

- **Severity:** High
- **Description:** Validates agent runtimes have proper Amazon VPC settings.

### AC-02: AWS IAM Full Access

- **Severity:** High
- **Description:** Checks for overly permissive AgentCore AWS IAM policies.

### AC-03: Stale Access

- **Severity:** Low
- **Description:** Detects unused AgentCore permissions.

### AC-04: Observability

- **Severity:** Medium
- **Description:** Verifies Amazon CloudWatch Logs and AWS X-Ray tracing configuration.

### AC-05: Amazon ECR Repository Encryption

- **Severity:** High
- **Description:** Validates Amazon ECR repositories use encryption.

### AC-06: Browser Tool Recording

- **Severity:** Medium
- **Description:** Checks storage configuration for browser tools.

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

---

## Agentic AI Security Checks (27)

Agentic AI Security checks use the `AG-XX` namespace and are included with the
default assessment. They follow a hybrid model:

- Reused API-backed controls from Amazon Bedrock and Amazon Bedrock AgentCore
  are mapped into agentic security domains.
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
- **Source:** AgentCore `GetGateway.policyEngineConfiguration`
- **Domain:** Tool Authorization
- **Description:** Fails gateways without a policy engine or with policy engine mode other than `ENFORCE`.

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

---

## Additional Resources

- [Amazon SageMaker Security Best Practices](https://docs.aws.amazon.com/sagemaker/latest/dg/security.html)
- [Amazon Bedrock Security](https://docs.aws.amazon.com/bedrock/latest/userguide/security.html)
- [AWS Well-Architected Agentic AI Lens](https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html)
- [AWS Security Hub SageMaker Controls](https://docs.aws.amazon.com/securityhub/latest/userguide/sagemaker-controls.html)
- [AWS Well-Architected Framework - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)

---

## Financial Services GenAI Risk Checks (64 additional, 5 upstream extensions)

These 64 standalone checks (FS-XX) extend the framework with Financial Services
risk-management controls derived from the
[AWS User Guide to Governance, Risk, and Compliance for Responsible AI Adoption](https://aws.amazon.com/blogs/security/introducing-the-updated-aws-user-guide-to-governance-risk-and-compliance-for-responsible-ai-adoption/).
An additional 5 FS checks are contributed as extensions to existing SM-07,
SM-22, SM-23, BR-04, and BR-06 (see in-file extension notes).

The full catalog is in **[`SECURITY_CHECKS_FINSERV.md`](./SECURITY_CHECKS_FINSERV.md)**,
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
OWASP can auto-run FinServ to produce FS-* source findings when FinServ is
otherwise disabled. OW-11 and OW-12 are net-new checks that address LLM07
(System Prompt Leakage), which the existing checks do not directly cover.
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
