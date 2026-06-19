# Security Checks Reference

This document provides a comprehensive reference for all 116 security checks performed by the AI/ML Security Assessment framework (52 core checks across Amazon Bedrock, Amazon SageMaker AI, and Amazon Bedrock AgentCore, plus 64 Financial Services GenAI Risk checks).

## Table of Contents

- [Overview](#overview)
- [Check ID Convention](#check-id-convention)
- [Severity Levels](#severity-levels)
- [Status Values](#status-values)
- [Amazon SageMaker AI Security Checks (25)](#amazon-sagemaker-ai-security-checks-25)
- [Amazon Bedrock Security Checks (14)](#amazon-bedrock-security-checks-14)
- [Amazon Bedrock AgentCore Security Checks (13)](#amazon-bedrock-agentcore-security-checks-13)
- [Financial Services GenAI Risk Checks (64)](#financial-services-genai-risk-checks-64-additional-5-upstream-extensions)

---

## Overview

The framework evaluates your AI/ML workloads against AWS security best practices across three services:

| Service | Number of Checks | Focus Areas |
|---------|------------------|-------------|
| Amazon SageMaker AI | 25 | Security Hub controls, encryption, network isolation, IAM, MLOps |
| Amazon Bedrock | 14 | Guardrails, encryption, VPC endpoints, IAM permissions, logging |
| Amazon Bedrock AgentCore | 13 | VPC configuration, encryption, observability, resource policies |
| Financial Services GenAI Risk | 64 | Unbounded consumption, excessive agency, supply chain, training data poisoning, vector weaknesses, non-compliant output, misinformation, harmful output, biased output, PII disclosure, hallucination, prompt injection, improper output handling, off-topic output, out-of-date training data |

---

## Check ID Convention

Each security check has a unique identifier with a service prefix:

| Prefix | Service | Example |
|--------|---------|---------|
| **SM-XX** | Amazon SageMaker | SM-01, SM-25 |
| **BR-XX** | Amazon Bedrock | BR-01, BR-14 |
| **AC-XX** | Amazon Bedrock AgentCore | AC-01, AC-13 |
| **FS-XX** | Financial Services GenAI Risk | FS-01, FS-69 |

---

## Severity Levels

| Severity | Description | Action Required |
|----------|-------------|-----------------|
| **High** | Critical security issues that could lead to data exposure, unauthorized access, or compliance violations | Immediate remediation recommended |
| **Medium** | Important security improvements that strengthen your security posture | Address in next maintenance window |
| **Low** | Minor optimizations and best practice recommendations | Address when convenient |
| **Informational** | Advisory information about your configuration | No action required |
| **N/A** | Check not applicable (no resources to assess) | No action required |

---

## Status Values

| Status | Description |
|--------|-------------|
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

- **Severity:** Medium
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

- **Severity:** Medium
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

## Amazon Bedrock Security Checks (14)

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

- **Severity:** High
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

## Additional Resources

- [Amazon SageMaker Security Best Practices](https://docs.aws.amazon.com/sagemaker/latest/dg/security.html)
- [Amazon Bedrock Security](https://docs.aws.amazon.com/bedrock/latest/userguide/security.html)
- [AWS Security Hub SageMaker Controls](https://docs.aws.amazon.com/securityhub/latest/userguide/sagemaker-controls.html)
- [AWS Well-Architected Framework - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)

---

## Financial Services GenAI Risk Checks (64 additional, 5 upstream extensions)

These 64 standalone checks (FS-XX) extend the framework with Financial Services
regulatory controls derived from the
[AWS guide for Financial Services risk management of the use of Generative AI (March 2026)](https://d1.awsstatic.com/onedam/marketing-channels/website/public/global-FinServ-ComplianceGuide-GenAIRisks-public.pdf).
An additional 5 FS checks are contributed as extensions to existing SM-07,
SM-22, SM-23, BR-04, and BR-06 (see in-file extension notes).

The full catalog is split across three companion files for readability:

- **[`SECURITY_CHECKS_FINSERV_COMMON.md`](./SECURITY_CHECKS_FINSERV_COMMON.md)** — shared
  intro, severity rubric, validation note, upstream-overlap table, compliance framework
  mapping.
- **[`SECURITY_CHECKS_FINSERV_PART1_INFRA_CONTROLS.md`](./SECURITY_CHECKS_FINSERV_PART1_INFRA_CONTROLS.md)** — FS-01 to FS-26
  (Unbounded Consumption, Excessive Agency, Supply Chain, Training Poisoning, Vector
  Weaknesses).
- **[`SECURITY_CHECKS_FINSERV_PART2_GUARDRAILS_CONTENT_SAFETY.md`](./SECURITY_CHECKS_FINSERV_PART2_GUARDRAILS_CONTENT_SAFETY.md)** — FS-27 to FS-46
  (Non-Compliant Output, Misinformation, Abusive/Harmful Output, Biased Output,
  Sensitive Information Disclosure).
- **[`SECURITY_CHECKS_FINSERV_PART3_APP_LAYER_AND_GAPS.md`](./SECURITY_CHECKS_FINSERV_PART3_APP_LAYER_AND_GAPS.md)** — FS-47 to FS-69
  (Hallucination, Prompt Injection, Improper Output Handling, Off-Topic Output,
  Out-of-Date Training Data, and 6 cross-category material gap checks).

Compliance framework mapping table is in `SECURITY_CHECKS_FINSERV_COMMON.md`
(SR 11-7, FFIEC CAT, NYDFS 500.06, PCI-DSS 12.3.2, DORA Art.6, MAS TRM 9,
ISO 27001 A.12, ECOA, OWASP LLM Top 10).
