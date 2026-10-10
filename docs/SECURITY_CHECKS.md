# Security Checks Reference

This document provides a comprehensive reference for all 238 security checks performed by the AI/ML Security Assessment framework (124 core checks across Amazon Bedrock, Amazon SageMaker AI, Amazon Bedrock AgentCore, and AWS Agent Registry, 38 Agentic AI Security checks, 64 Responsible AI GRC checks, and 12 OWASP Top 10 for LLM checks).

Sources differ by bucket and are not interchangeable: the core Bedrock, SageMaker, AgentCore, and AWS Agent Registry checks derive from the AWS Well-Architected **Generative AI Lens** security best practices (`gensec*`) and service security documentation; the Agentic AI Security checks from the AWS Well-Architected **Agentic AI Lens**; the `FS-*` **Responsible AI GRC** checks from the AWS GRC User Guide; and the `OW-*` checks from the OWASP Top 10 for LLM. The AWS Well-Architected **Responsible AI Lens** is not a source for any of them — see [Responsible AI GRC — scope, sources, and compatibility](RESPONSIBLE_AI_GRC_SCOPE.md).

The 64 Responsible AI GRC checks occupy 69 `FS-*` numbers: 64 ship as standalone checks and 5 are merged into upstream Bedrock/SageMaker checks. The framework also emits `BR-00`, `SM-00`, `AC-00`, `AR-00`, `FS-00`, and `OW-00` operational marker rows at runtime; these are not controls and are excluded from the 238-check total. Per-control provenance, including which controls are project extensions rather than guide-derived, is recorded in [`provenance.json`](../aiml-security-assessment/functions/security/responsible_ai_grc_assessments/provenance.json).

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
- [Amazon SageMaker AI Security Checks (42)](#amazon-sagemaker-ai-security-checks-42)
- [Amazon Bedrock Security Checks (57)](#amazon-bedrock-security-checks-57)
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
| Amazon SageMaker AI | 42 | Security Hub controls, encryption, network isolation, GuardDuty AI Protection, HyperPod, IAM, MLOps, Model Registry policy exposure, inference data capture, Config compliance evaluation, training VPC boundary, creation guardrails, security service delegated administration, the Security Hub AI standard, GuardDuty Lambda Protection and Runtime Monitoring, EKS network policy, secret rotation, IoT device-scoped policies |
| Amazon Bedrock | 57 | Guardrails, prompt-attack/image filters, retention, inference profiles, automated reasoning and Marketplace endpoint governance, encryption, networking, IAM, logging, monitoring, evaluation, central guardrail enforcement, model allow-lists, Region and Marketplace subscription control, API key governance, knowledge base source classification, LLM jacking activity in CloudTrail event history, agent handoff source identity |
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
| **SM-XX** | Amazon SageMaker | SM-01, SM-43 (`SM-29` reserved) |
| **BR-XX** | Amazon Bedrock | BR-01, BR-57 |
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

## Amazon SageMaker AI Security Checks (42)

A SageMaker check that stops on an unexpected error writes one `N/A` `SageMaker Check Incomplete` row for its check ID, naming the check function, and the other checks still run. The SageMaker Lambda stops starting checks 120 seconds before its 900-second timeout; each check ID it did not reach gets one `N/A` `SageMaker Check Not Assessed (Timeout)` row that begins "Timeout, not assessed" and names the skipped functions, and every row collected before the deadline is still written.

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
  A separate `SageMaker Service-Wide Grant in Customer Policy` finding reads
  customer-managed and inline policies on roles and users and fails any Allow
  statement that grants every SageMaker action, through `sagemaker:*`, a bare
  `"*"` or a pattern that covers it, or through a `NotAction` list that does
  not exclude SageMaker, on an identity whose permissions boundary allows a
  SageMaker action. It also reads group policies. AWS managed policies are left
  to the full-access finding above and to the next finding. A policy that
  cannot be parsed produces `N/A` naming it.
  A `SageMaker Read and Write Merged in One Grant` finding covers
  AIR-FND-IAM-09 over the `sagemaker` namespace. It reads every attached (AWS managed included), inline and group policy of every cached role and user, and fails a wildcard `Action` pattern (a bare `"*"`, `*:*` and a partial pattern among them) or a `NotAction` Allow that grants both a read and a write action on one resource type, as the [service authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference.html) classifies them (the table is `iam_access_levels.json`, generated by `generate_iam_access_levels.py`). An explicit action list is never reported, because it separates read from write. An action counts only when no unconditioned `Resource: "*"` Deny removes it and the permissions boundary also allows it. A condition applies to the read and the write alike and is not read; the `Resource` entries are read only to drop resource types none of them can name, with a policy variable read as any value. Service control policies are not evaluated per principal, which can only make a row a false `Failed`, and each failing row says so. A policy that cannot be parsed produces `N/A` naming the principal. While the cache's `principal_errors` names a principal, each `Passed` row becomes `N/A` naming the unread principals; a cache without `principal_errors` (schema v1) keeps its verdict and says the errors were not recorded. A principal whose permissions boundary the cache could not read (a `permissions_boundary` stage in `principal_errors`) is not reported `Failed` by the service-wide or merged rows, because a boundary could remove the grant; the `N/A` row names it.
- **Rows emitted:**
  - `SageMaker Full Access Policy Used`, `Stale SageMaker Access` and `SageMaker IAM Permissions Check` (with `SageMaker IAM Permissions Check Incomplete` when the cache is missing): the IAM cache legs above. They run once, on the primary Region, tagged `Global`.
  - `SageMaker Service-Wide Grant in Customer Policy` (and its `Incomplete` form) and `SageMaker Read and Write Merged in One Grant`: described above, also `Global`.
  - `Endpoint Invocation Policy Scoping` (AIR-SGM-EP-02): fails an identity whose Allow reaches `sagemaker:InvokeEndpoint`, `InvokeEndpointAsync` or `InvokeEndpointWithResponseStream` on every endpoint, because a SageMaker endpoint accepts no resource-based policy and the identity policy is the only place the call can be scoped. `Global`.
  - `SSO Not Properly Configured` and `SageMaker SSO Configuration Check`: per Region, each SageMaker domain's IAM Identity Center configuration.
  - `SageMaker Runtime VPC Endpoint Policy Scoping` (AIR-SGM-EP-02): per Region, fails a `sagemaker.runtime` interface VPC endpoint whose policy has an Allow reaching `sagemaker:InvokeEndpoint` on every endpoint, which the default full-access policy does. Deny statements are not evaluated. A Region with no runtime VPC endpoint emits no row here; SM-11 reports the missing private path.
  - `AI API Method Authorization` (AIR-FND-IAM-09 request layer): per Region, every API Gateway REST and HTTP API method whose integration reaches a Bedrock, AgentCore or SageMaker runtime, a Lambda function an agent action group or AgentCore gateway target names, or a Lambda function whose role is granted an AI invoke action. A method with no authorizer fails, and so do read and write methods on one resource that a token authorizer gives the same scopes or an IAM authorizer leaves under one `execute-api:Invoke` grant. `AI API Method Authorization Not Judged` (`N/A`) names the methods behind a Lambda authorizer, whose code is not read, and IAM grants the cache could not resolve.

### SM-03: Data Protection

- **Severity:** High
- **AWS Security Hub Control:** SageMaker.1
- **Description:** Verifies encryption at rest and in transit for notebooks and domains.

### SM-04: Amazon GuardDuty Integration

- **Severity:** High
- **Description:** Verifies Amazon GuardDuty runtime threat detection is enabled. `GuardDuty Findings Routed to Security Hub` passes when Security Hub in the Region imports GuardDuty findings (product subscription `aws/guardduty`). Security Hub not enabled in the Region (`InvalidAccessException`, "not subscribed to AWS Security Hub") fails, with a resolution to enable Security Hub and then its GuardDuty integration; Security Hub not offered in the Region is `N/A`. Any other read error, access denied among them, is `N/A` as `GuardDuty Findings Routed to Security Hub Incomplete`. `GuardDuty Findings Reviewed in Security Hub` is then `N/A` naming the routing row, and is `Incomplete` only when the routing row is.

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
- **Description:** Ensures notebooks are deployed within an Amazon VPC, and fails a notebook whose subnet's route table routes to an internet gateway. A notebook list or describe error is `N/A` and withholds the all-in-VPC `Passed`. The same check reads every SageMaker Studio domain (AIR-FND-NET-01): `DescribeDomain` reporting `AppNetworkAccessType` `PublicInternetOnly`, or omitting it (the default is `PublicInternetOnly`), fails `SageMaker Studio Domain Network Boundary`, because that mode sends non-EFS traffic through a SageMaker-managed VPC that allows direct internet access. A `VpcOnly` domain's `SubnetIds` go through the same route-table read under `SageMaker Studio Domain Subnet Internet Exposure`. A domain list or describe error, or a `VpcOnly` domain with no `SubnetIds`, is `N/A`.

### SM-11: Model Network Isolation

- **Severity:** High
- **AWS Security Hub Control:** SageMaker.4
- **Description:** Checks inference containers have network isolation.
- **Rows emitted:**
  - `SageMaker Model Network Isolation Disabled`, `SageMaker Model Network Isolation Summary` and `SageMaker Model Network Isolation Check`: each model's `EnableNetworkIsolation`. Only these rows feed OWASP OW-03 and OW-10 (see `SECURITY_CHECKS_OWASP.md`).
  - `SageMaker Model VPC Attachment` and `SageMaker Model Subnet Internet Exposure` (AIR-SGM-EP-01): each model's `VpcConfig`, judged apart from isolation because a model can be isolated with no VPC attachment, and its subnets' routes to an internet gateway.
  - `SageMaker Endpoint Model Network Path` and `SageMaker Endpoint Config Subnet Internet Exposure` (AIR-SGM-EP-01, EP-03): isolation and `VpcConfig` of the models each endpoint serves, inference components included. A model the endpoint names that could not be described leaves that endpoint `N/A`.
  - `SageMaker Endpoint Config Storage Encryption` (AIR-SGM-EP-03): the endpoint config `KmsKeyId`. No endpoint API field turns on inter-container traffic encryption, and the row says so.
  - `SageMaker Runtime Private Invoke Path` (AIR-SGM-EP-01): where the Region hosts an endpoint, an available `sagemaker.runtime` interface endpoint with private DNS, in a VPC with `enableDnsSupport` and `enableDnsHostnames` true.
  - `SageMaker Endpoint Invocation Source Network` (AIR-SGM-EP-01): each principal that can invoke an endpoint must be held to `aws:SourceVpce` or `aws:SourceVpc`. An attached service control policy Deny on every invoke action passes on its own; without one the account root user fails the leg. The service control policies are read once per invocation and shared with SM-34, SM-39, SM-09 and SM-42 on the primary Region.
  - `AI Lambda Function Network Boundary` (AIR-FND-NET-01): every Lambda function an agent action group or AgentCore gateway target invokes, and every Lambda function and ECS awsvpc workload whose role is granted an AI invoke action, must run in VPC subnets with no route to an internet gateway. Bedrock Agents or AgentCore not offered in the Region adds a note and is not a failed read.

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
- **Description:** Reuses the regional GuardDuty detector inventory and verifies the detector `Status` and its `AI_PROTECTION` feature are both `ENABLED`. A detector with status `DISABLED` fails whatever its feature status, and a Region with no detector fails, because neither produces AI Protection findings. For an `ENABLED` detector, a second row, `GuardDuty AI Protection Organization Auto-Enable`, reads `DescribeOrganizationConfiguration` (every page) and passes only when `AutoEnableOrganizationMembers` is `ALL` and the `AI_PROTECTION` feature's `AutoEnable` is `ALL`. `NEW`, `NONE` or a missing entry fails. A failed read is `N/A`, because only the GuardDuty delegated administrator can call the API. Each member account's own detector is not read.

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

### SM-31: Endpoint Inference Data Capture

- **Severity:** Medium
- **Description:** Requires each SageMaker endpoint to capture inference requests and responses. `DescribeEndpoint` reports the live capture state as `DataCaptureConfig.EnableCapture` plus `CaptureStatus`, so an endpoint whose configuration enables capture but whose `CaptureStatus` is `Stopped` is reported as a failure and not as compliant.

### SM-32: SageMaker Configuration Compliance Evaluation

- **Severity:** Medium
- **Description:** Two independent legs, each with its own finding. `SageMaker Configuration Recording` requires an AWS Config recorder whose recording group covers SageMaker resource types. `SageMaker Config Rule Compliance` requires at least one active Config rule evaluating SageMaker and reports that rule's current compliance result. Neither verdict implies the other: a recorder with no rules evaluates nothing, and a rule with no recorder cannot see configuration changes. Service-linked rules, which carry `CreatedBy` (for example `securityhub.amazonaws.com`), are reported `N/A` naming the owning service, because AWS Config returns their compliance results to no caller.

### SM-33: Training Job Network Boundary

- **Severity:** Medium
- **Description:** Requires training jobs to run inside a customer VPC. Network isolation and `VpcConfig` are reported separately, because a job can set `EnableNetworkIsolation` with no VPC attachment, and an isolated job without a VPC attachment still has no private path to Amazon S3 or Amazon ECR. SM-21 asserts the same VPC boundary for AutoML jobs only. Every training job is listed and described, with no item cap. The same check lists and describes every processing job (AIR-FND-NET-01): a job whose `NetworkConfig` names no `VpcConfig` fails `Processing Job Network Boundary`, and the subnets of the others go through the route-table read under `SageMaker Processing Job Subnet Internet Exposure`. A list or describe error is `N/A`, and `No SageMaker training or processing jobs found` appears only when both lists read empty. In an estate with many jobs this check makes one describe call per job.

### SM-34: SageMaker Creation Guardrails

- **Severity:** Medium
- **Description:** Requires a service control policy that denies creation of unencrypted, internet-exposed, or non-VPC SageMaker resources, with one verdict per guardrail category: `encryption` (`sagemaker:VolumeKmsKey`, `sagemaker:OutputKmsKey`, `sagemaker:InterContainerTrafficEncryption`), `approved network` (`sagemaker:VpcSubnets`, `sagemaker:VpcSecurityGroupIds`, `sagemaker:NetworkIsolation`), and `no direct internet access` (`sagemaker:DirectInternetAccess`). Categories are reported separately because an organization commonly guards encryption at creation and leaves the network parameters unguarded. A Deny that fires when the parameter is absent or holds a non-approved value counts as enforced; a Deny naming one specific value is reported as ambiguous, because whether that value is the non-compliant one depends on the value and this check does not interpret it. An unreadable organization view produces `N/A`.

### SM-35: Security Service Delegated Administrator

- **Severity:** High
- **Description:** Emits one row per security service principal from a fixed list (Amazon GuardDuty, AWS Security Hub, Amazon Inspector, Amazon Macie, AWS Config through `config.amazonaws.com`, AWS Config multi-account setup through `config-multiaccountsetup.amazonaws.com`, IAM Access Analyzer, AWS CloudTrail, Amazon Detective, Amazon Security Lake, AWS Firewall Manager, AWS Audit Manager), each row naming the list. A service passes when an `ACTIVE` delegated administrator other than the organization management account is registered and the service principal is among the organization's trusted-access principals (`ListAWSServiceAccessForOrganization`). It fails when none is registered, when the only active one is the management account, or when trusted access for the principal is not enabled. That failure for `macie.amazonaws.com`, `detective.amazonaws.com`, `fms.amazonaws.com` or `auditmanager.amazonaws.com` says the principal name is not confirmed by a live read. When the trusted-access list cannot be read, every service with such an administrator is `N/A`. `ListDelegatedAdministrators` is readable only from the management account or a delegated administrator account, so an access denial for one service is `N/A` for that service alone. An account outside AWS Organizations produces one `N/A` row. Runs once, on the primary region, tagged `Global`. A second row, `Security Service Regional Delegated Administrator`, runs per Region and passes when GuardDuty, Security Hub, Amazon Inspector, Amazon Macie and Amazon Detective are all administered there from one account other than the organization management account. A service not enabled in the Region (no GuardDuty detector, Security Hub `InvalidAccessException`, Macie "not enabled") fails. A service not offered in the Region is left out with a note on the row, and access denied is `N/A` naming the service.

### SM-36: Security Hub AI Security Standard

- **Severity:** High
- **Description:** Requires the AWS Security Hub AI Security Best Practices v1.0.0 standard (`standards/ai-security-best-practices/v/1.0.0`) to be enabled in the region. `READY` passes; `INCOMPLETE` passes with a note to review the standard's `StatusReason`; any other subscription status fails. Security Hub not enabled in the region (`InvalidAccessException`) fails, because no standard is evaluating anything.

### SM-37: GuardDuty Lambda Protection

- **Severity:** Medium
- **Description:** Requires the GuardDuty `LAMBDA_NETWORK_LOGS` feature to be `ENABLED` on an enabled detector, so network activity from AI workload Lambda functions is monitored. A disabled or absent feature fails and names its state. No detector produces `N/A`; SM-04 reports the missing detector.
- **Rows emitted:**
  - `GuardDuty Lambda Protection`: the feature leg above.
  - `SageMaker Endpoint Network Anomaly Alerting`: every SageMaker endpoint and AgentCore runtime passes only when each subnet it runs in is covered by an `ACTIVE` VPC or subnet flow log that captures accepted traffic into CloudWatch Logs, and that log group has a metric filter that can match a flow-log record whose metric an alarm with an action evaluates, with a threshold the published values can cross. AgentCore not offered in the Region adds a note and is not a failed read.
  - `VPC DNS Resolver Visible to GuardDuty`: fails a VPC whose DHCP option set names a domain name server other than `AmazonProvidedDNS`, because GuardDuty analyzes only DNS queries that reach the AWS-provided resolver. `VPC DNS Resolver Visible to GuardDuty Not Judged` (`N/A`) names VPCs whose option set names no server.

### SM-38: GuardDuty Runtime Monitoring

- **Severity:** High
- **Description:** Requires the GuardDuty `RUNTIME_MONITORING` feature to be `ENABLED` and reports the automated agent management state for EKS, ECS Fargate and EC2. The legacy `EKS_RUNTIME_MONITORING` feature covers EKS only, so a detector with only that feature enabled fails. No detector produces `N/A`.
- **Rows emitted** (all per Region, because each reads that Region's detector, functions and trails):
  - `GuardDuty Runtime Monitoring`: the feature leg above.
  - `GuardDuty Runtime Monitoring Coverage`: per-resource coverage against the EKS and ECS cluster population. A detector with every agent-management option off and no manual agent fails here.
  - `GuardDuty EKS Audit Log Monitoring`: where EKS clusters exist, the `EKS_AUDIT_LOGS` feature.
  - `Lambda Runtime Detection Tier`: Lambda has no runtime agent, so the tier is GuardDuty Lambda Protection, Amazon Inspector Lambda standard and code scanning read per function, and, where functions exist, CloudTrail data events on `AWS::Lambda::Function`.
  - `ECS Managed Instances Runtime Detection Tier`: Runtime Monitoring does not support ECS Managed Instances, so each running task needs `awsvpc` mode with an `ACTIVE` flow log recording `ALL` traffic on its ENI, subnet or VPC, every container's logs sent to CloudWatch Logs through `awslogs`, and a trail or event data store recording the Region's ECS management events.
  - `Lambda MicroVM Runtime Detection Tier`: VPC Flow Logs on every egress connector subnet, the image version's application logging to CloudWatch Logs, and CloudTrail data events on `AWS::Lambda::MicrovmImage`. A MicroVM with no egress connector fails.

### SM-39: EKS VPC CNI Network Policy

- **Severity:** Medium
- **Description:** For each EKS cluster, reads the managed `vpc-cni` add-on's `configurationValues` and requires `enableNetworkPolicy` to be true (EKS returns the value as the string `"true"` inside a JSON or YAML document). A pass means network-policy enforcement is enabled on the add-on; whether NetworkPolicy objects restrict pod traffic is a Kubernetes-API fact this scan cannot read. An EKS Auto Mode cluster (`computeConfig.enabled`) is reported `N/A`, because Auto Mode sets network policy on the NodeClass, a Kubernetes object no AWS API returns. Any other cluster without the managed add-on is reported `N/A`, because enforcement by a self-managed CNI is not readable through the EKS API. One cluster's read error is reported for that cluster alone.
- **Rows emitted:**
  - `EKS VPC CNI Network Policy Enforcement`: the add-on leg above.
  - `EKS Network Policy Default-Deny Mode`: a cluster with network policy enabled fails unless `env.NETWORK_POLICY_ENFORCING_MODE` is `strict`, the only default-deny an AWS API returns. Each row says whether security groups for pods are enabled.
  - `Agent Workload Security Group Segmentation` (AIR-SLF-RT-05): the security groups of each ECS service and standalone task, Lambda function, Lambda MicroVM egress connector and EC2 instance (one per Auto Scaling group). A rule to a /16 (IPv6 /48) or wider fails. `Agent Workload Security Group Segmentation CIDR Width Not Judged` (`N/A`) names rules narrower than that and wider than a /24 (IPv6 /64).
  - `Lambda MicroVM Ingress` (AIR-SLF-RT-05): a `SHELL_INGRESS` connector fails; a connector type the check does not recognize is `N/A`. Auth token port scope is not returned by `GetMicrovm` and is stated, not judged.
  - `Agent Workload DNS Egress Control` and `Agent Workload Network Firewall Egress` (AIR-SLF-RT-02): one row each per VPC that an ECS awsvpc service, VPC-attached Lambda function, EKS cluster, EC2 instance, SageMaker endpoint, running training, processing or transform job, HyperPod cluster, notebook instance or Studio domain, or active Bedrock customization or batch inference job runs in. DNS passes only when the first DNS Firewall rule in force over `*` is a `BLOCK` with no query type and `FirewallFailOpen` is `DISABLED`. Network Firewall follows each hosting subnet's internet routes one hop, through a NAT gateway or a transit gateway attachment, to a firewall endpoint; a route to an internet gateway bypasses inspection and fails. An agent Lambda function outside a VPC fails both rows.
  - `Agent Workload Egress Allow-List Sync`: where a DNS Firewall applies, compares the names it answers ahead of its `BLOCK` over `*` with each reached firewall's `ALLOWLIST` targets.
  - `Agent Workload Security Group Egress` (AIR-FND-NET-03): fails a SageMaker, EKS or Bedrock workload whose groups' all-protocol egress reaches any destination.
  - `Lambda VPC Creation Guardrail` and `Lambda Network Connector Creation Guardrail`: the SM-34 legs over the Lambda VPC and network connector condition keys. They run once, on the primary Region, tagged `Global`.
  - Lambda MicroVMs, Bedrock Agents or AgentCore not offered in the Region make an empty population with a note on each row, and are not failed reads. Access denied stays `N/A` naming the call.

### SM-40: Secrets Manager Rotation

- **Severity:** Medium
- **Description:** For each customer-managed secret, requires automatic rotation to be turned on and the last rotation to fall within the rotation schedule plus one day. A secret with rotation turned on that has never rotated fails, as does one whose schedule allows a gap longer than 90 days, the default `maxDaysSinceRotation` of Security Hub control `SecretsManager.4`. Schedules are read from `rate()` (hours or days), `cron()` (the longest gap between two scheduled dates), or `AutomaticallyAfterDays`; a `cron()` form this check does not interpret, such as `W`, is reported `N/A`. Secrets with `OwningService` set rotate under that service's control and are skipped and counted. Secret values are never read.
- **Rows emitted:**
  - `Secrets Manager Automatic Rotation`: the schedule leg above.
  - `Secrets Manager Rotation History`: for each rotating secret, reads 90 days of CloudTrail event history. A `RotationFailed` or `RotationAbandoned` event after the last rotation fails, as does a `RotationStarted` event more than 24 hours old with no rotation since. A rotation started within 24 hours is `N/A` with no outcome yet.
  - `Rotated Secret Propagation`: an ECS task that injects a rotating secret fails when no `ENABLED` EventBridge rule on Secrets Manager rotation events has a target, because ECS resolves the value at task start. An injection from Parameter Store fails, as does an `ACTIVE` Lambda MicroVM image version whose `resume` hook is not `ENABLED`. With a rule that has a target the row is `N/A`, because what the target runs is not read. Lambda functions are not graded.
  - `Credential Held Outside Secrets Manager`: fails a credential-named environment variable (matched on the name; the value is not logged) set in plaintext on an ECS container, a Lambda function, a SageMaker model or a Lambda MicroVM image version.

### SM-41: AWS IoT Device-Scoped Policy

- **Severity:** High
- **Description:** For each AWS IoT policy attached to a certificate or other principal, fails an Allow statement that reaches `Publish`, `Subscribe`, `Receive` or `Connect` on `*`, on all topics, topic filters or client IDs, or through `NotResource`, unless the resource embeds `${iot:Connection.Thing.ThingName}` as a whole path segment, with no wildcard or other text before or after it in that segment. `NotAction` Allow statements are expanded to the device actions they reach. A statement allowing `Connect` also needs a `Bool` condition requiring `iot:Connection.Thing.IsAttached` to be `true`. Unattached policies are skipped. No attached policy produces `N/A`. For a policy attached to a thing group, the unique-certificate row lists the group's things with child groups included (`iot:ListThingsInThingGroup` with `recursive`) and each thing's certificate principals (`iot:ListThingPrincipals`), and judges each such certificate like one attached directly; an unread group or thing is `N/A` and named. An `AWS IoT Role Alias Device Scope` row lists every credentials-provider role alias (`ListRoleAliases`), describes each (`DescribeRoleAlias`) and judges its `roleArn` from the IAM permissions cache: the role fails when no Allow statement in its attached or inline policies names a `credentials-iot:` policy variable in `Resource` or `Condition`, because every device that assumes the alias then gets the same AWS access. Whether every statement of the role is device-scoped is not judged. A describe error, a missing `roleArn`, a role absent from the cache, a cache read error or no cache is `N/A`. A Region with no role alias gets no row.

### SM-42: Batch Transform Creation Guardrail

- **Severity:** Medium
- **Description:** Applies the `SM-34` creation guardrail to the batch transform path only: `CreateTransformJob` on `sagemaker:VolumeKmsKeyArn` and `sagemaker:OutputKmsKeyArn`, and `CreateModel` on `sagemaker:VpcSubnets` or `sagemaker:VpcSecurityGroupIds` and on `sagemaker:NetworkIsolation`. A transform job takes its network posture from its model, so `CreateModel` carries the network keys. Each requirement is met by a service control policy Deny on this account's path to the root or by a condition in every identity policy that grants the action. A training, endpoint configuration or notebook gap does not fail this check. Service control policies are organization-wide, so it runs once, on the primary Region, and its rows are tagged `Global`.

### SM-43: Model Artifact Integrity

- **Severity:** Medium
- **Description:** Judges every container each InService endpoint serves, including the containers of a model package the model names and of each inference component. The image passes when it is pinned by digest (`@sha256:`) or by a tag that its Amazon ECR repository holds immutable: `IMMUTABLE`, `IMMUTABLE_WITH_EXCLUSION` for a tag no exclusion filter matches, or `MUTABLE_WITH_EXCLUSION` for a tag an exclusion filter matches. An untagged image is read as `latest`. When a managed signing rule of the registry covers the repository (a rule with no filters covers every repository), the image also needs a `COMPLETE` status from `DescribeImageSigningStatus`, read by the digest `DescribeEndpoint` reports the image resolved to; no status, or a `FAILED` one, fails. S3 model data passes when `ModelDataSource.S3DataSource` records an `ETag` or `ManifestEtag`, when a model package container records `ModelDataETag`, or when the source names SageMaker hub content (`HubAccessConfig.HubContentArn`). A bare `ModelDataUrl` fails, as does each `AdditionalModelDataSources` entry with no ETag, and a container whose environment sets `HF_MODEL_ID` with no model data. Only environment keys are read, never values. Each artifact bucket must default to SSE-KMS with a named `KMSMasterKeyID` that `kms:DescribeKey` reports as `KeyManager` `CUSTOMER`; an `alias/aws/` alias or an AWS managed key fails. A repository in another account, an image outside ECR with a tag, or any denied read leaves the endpoint `N/A` naming the permission. A recorded value means an expected value is recorded: whether it was compared at load time is not returned by any API this check reads, and weights fetched by startup code, and models loaded on ECS, EKS or EC2, are not read. Inference components are listed per variant with `ListInferenceComponents`; only `InService` components hosted on the endpoint are judged, every entry of a multi-specification component is judged, and a component that returns no model name, image or artifact URL reads `N/A`. The per-object leg (`HeadObject` on each artifact named as one S3 object, to compare its current `ETag` and its own server-side encryption) runs only when the `EnableSageMakerArtifactObjectReads` deployment parameter is `true`, because `HeadObject` is authorized by `s3:GetObject`, which also allows downloading any object. It defaults to `false`, and an `N/A` row then names the parameter and the number of objects not read; image pinning, recorded expected values, bucket default encryption and role read scope are still judged.

---

## Amazon Bedrock Security Checks (57)

### BR-01: AWS IAM Least Privilege

- **Severity:** High
- **Description:** Identifies roles with AmazonBedrockFullAccess policy. A second finding, `Bedrock Wildcard Action Grant`, reads every customer-managed, inline and group policy on each cached role and user and fails an Allow that grants every Bedrock action (`bedrock:*` or an equivalent wildcard such as `bed*`) or that grants Bedrock through `NotAction` without excluding it. A bare `*` or `*:*` counts. AWS managed policies are left to the first finding. An identity whose permissions boundary allows no Bedrock action is not reported. A policy or group policy list that could not be read produces `N/A`, and the `Passed` row is then downgraded to `N/A`. A third finding, `Bedrock or Data Store Read and Write Merged in One Grant`, covers AIR-FND-IAM-09 over the `bedrock` namespace, and over the `s3`, `dynamodb` and `s3vectors` namespaces for an identity that is granted some Bedrock action. It reads every attached (AWS managed included), inline and group policy of every cached role and user, and fails a wildcard `Action` pattern (a bare `"*"`, `*:*` and a partial pattern among them) or a `NotAction` Allow that grants both a read and a write action on one resource type, as the [service authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference.html) classifies them (the table is `iam_access_levels.json`, generated by `generate_iam_access_levels.py`). An explicit action list is never reported, because it separates read from write. An action counts only when no unconditioned `Resource: "*"` Deny removes it and the permissions boundary also allows it. A condition applies to the read and the write alike and is not read; the `Resource` entries are read only to drop resource types none of them can name, with a policy variable read as any value. Service control policies are not evaluated per principal, which can only make a row a false `Failed`, and each failing row says so. A policy that cannot be parsed produces `N/A` naming the principal. While the cache's `principal_errors` names a principal, each `Passed` row becomes `N/A` naming the unread principals; a cache without `principal_errors` (schema v1) keeps its verdict and says the errors were not recorded. A principal whose permissions boundary the cache could not read (a `permissions_boundary` stage in `principal_errors`) is not reported `Failed` by the wildcard or merged rows, because a boundary could remove the grant; the `N/A` row names it.

### BR-02: Amazon VPC Endpoint Configuration

- **Severity:** High
- **Description:** Lists interface endpoints for the five Bedrock surfaces (`bedrock`, `bedrock-runtime`, `bedrock-agent`, `bedrock-agent-runtime` and `bedrock-mantle`) across every VPC page, then reads each Lambda function, ECS service and standalone ECS task, SageMaker notebook instance and endpoint model, EKS pod identity association, EC2 instance and VPC-mode AgentCore runtime version in the Region, resolves its execution, task, notebook, model, pod identity, instance-profile or runtime role, and computes from the IAM cache which surfaces that role is granted (attached, inline and group policies, with a permissions boundary that denies an action removing it). The three AgentCore surfaces (`bedrock-agentcore`, `bedrock-agentcore-control` and `bedrock-agentcore.gateway`) count as surfaces for this leg only: a `bedrock-agentcore` action is placed on the data plane or control plane by its botocore model, and `bedrock-agentcore:InvokeGateway` on the Gateway endpoint. The `Bedrock Workload Private Connectivity` finding fails a workload outside a VPC, and a workload whose VPC has no private-DNS endpoint for a surface its role is granted. Only an endpoint in State `available` counts; a `pendingAcceptance`, `rejected` or `failed` endpoint carries no traffic. A workload granted a Bedrock, AgentCore or SageMaker runtime (`sagemaker.runtime`) surface is in scope, and also needs a private-DNS endpoint for each SageMaker API or runtime surface its role is granted, and a gateway or private-DNS endpoint for S3 and DynamoDB. A gateway endpoint covers a workload only when its `RouteTableIds` hold the route table of every subnet the workload runs in: the subnet's explicit association from `ec2:DescribeRouteTables` (read for each VPC that holds a gateway endpoint), else the VPC's main table. A subnet whose table the endpoint does not name fails. A workload whose subnets were not read, which includes every EKS pod identity association because the cluster's subnets are not the pods' subnets, a VPC whose route tables were not read, or a subnet with no association and no main table, withholds `Passed`. Endpoint presence alone is reported as `N/A` and no longer passes. An endpoint listing that fails is reported as not read. ECS services are listed on every page of every cluster (`ecs:ListClusters`, `ecs:ListServices`; a denied cluster list falls back to the default cluster and is named, and then lists no standalone task, because `ecs:ListTasks` is granted only for a named cluster), described 10 at a time (`ecs:DescribeServices`), and placed in the VPC of each `awsvpc` subnet with the task role of their task definition (`ecs:DescribeTaskDefinition`). The service's own `roleArn` is not read as the task role. A service with no `awsvpc` subnets, or one that `ecs:DescribeServices` returns in its `failures` list, is reported as not read. The tasks in each cluster are listed (`ecs:ListTasks`) and described 100 at a time (`ecs:DescribeTasks`); a task whose `group` starts with `service:` belongs to a service and is skipped. A standalone task is placed in the VPC of its ENI attachment's `subnetId` with its `overrides.taskRoleArn`, or else the task role of its task definition, and one with no ENI subnet is reported as not read. Each notebook instance is described (`sagemaker:DescribeNotebookInstance`), and one with no `SubnetId` runs outside a VPC and fails. Each AgentCore runtime is listed (`bedrock-agentcore:ListAgentRuntimes`), its latest version and every version an endpoint serves (`bedrock-agentcore:ListAgentRuntimeEndpoints` `liveVersion` and `targetVersion`) are read with `bedrock-agentcore:GetAgentRuntime`, and a `VPC`-mode version is placed in the VPC of its `networkModeConfig.subnets` with its `roleArn`. A `PUBLIC`-mode version is left to AC-01. A version with no `networkMode`, a `VPC`-mode version with no subnets, or a subnet `ec2:DescribeSubnets` does not return is reported as not read. Each SageMaker endpoint (`sagemaker:ListEndpoints`, `sagemaker:DescribeEndpoint`) has its configuration read (`sagemaker:DescribeEndpointConfig`); every model a production or shadow variant names, and every model an inference component names (`sagemaker:ListInferenceComponents`, `sagemaker:DescribeInferenceComponent`), is read with `sagemaker:DescribeModel` and placed in the VPC of its `VpcConfig` subnets with its `ExecutionRoleArn`. A model behind an inference component with no `VpcConfig` of its own takes the endpoint configuration's `VpcConfig`, and an endpoint configuration with its own `ExecutionRoleArn` is judged as a workload too. A model with no VPC fails. Each EKS cluster (`eks:ListClusters`) is read for its `vpcId` (`eks:DescribeCluster`), and each pod identity association (`eks:ListPodIdentityAssociations`, `eks:DescribePodIdentityAssociation`) is judged in that VPC with its `roleArn`. An association with a `targetRoleArn` in another account is reported as not read, since the IAM cache holds this account's roles only. A pod that takes its role through IAM roles for service accounts is not read, because that binding is a service account annotation held by the Kubernetes API. Private hosted zones shared from another VPC are not read. The finding text names each of these. A workload whose role the cache does not hold, a collector error, or cache `principal_errors` downgrade the `Passed` row to `N/A`. Service control policies are not evaluated per principal. An endpoint policy counts as scoped only through a `Deny` on `bedrock:InvokeModel` with `Resource` `*`, no `NotResource`, and exactly one condition: a negated test on exact values of a principal or network scope key. A `Null` test, a second condition key, or a wildcard value is not credited. An `Allow` is scoped by a key only under a positive, non-`IfExists` test on exact values, and a principal with `*` or `?` in it is unbounded.

### BR-03: Marketplace Subscription Access

- **Severity:** Medium
- **Description:** Checks for overly permissive marketplace subscription access.

BR-01, BR-02, BR-03, BR-08, BR-10, and BR-21 depend on the shared IAM
permissions cache. If that prerequisite is missing, unreadable, or malformed,
each affected control is reported as informational `N/A`; an empty replacement
inventory is never treated as evidence of compliance.

### BR-04: Model Invocation Logging

- **Severity:** Medium
- **Description:** Checks invocation logging is enabled. The check is scoped by use, not by resources: a Region with no Bedrock resource is still judged when its CloudTrail event history holds an `InvokeModel`, `InvokeModelWithResponseStream`, `Converse` or `ConverseStream` call from `bedrock.amazonaws.com`, because on-demand inference creates no resource to list. Only a Region with neither is `N/A` as out of scope; when either read fails, the result is `N/A` and names the read that failed. Enabled logging is judged whatever the footprint. For S3 delivery, the retention leg credits only an enabled lifecycle rule whose filter covers `<keyPrefix>/AWSLogs/`, the root Bedrock writes under. A rule on another prefix, or one that also filters on tags or object size, is named and not credited. When the bucket has versioning `Enabled` or `Suspended`, a rule that expires noncurrent versions is also required, because expiring the current object leaves a noncurrent version behind. An unreadable versioning status is `N/A`, never a pass. A CloudWatch Logs destination with `retentionInDays` is credited only when `logs:FilterLogEvents`, with no filter pattern and `limit` 1, returns no event older than `retentionInDays` plus the 72 hours CloudWatch Logs takes to delete an expired event; only the event timestamp is read. An event returned fails the destination, and an unread search, or one still paging after 5 pages, is `N/A`. The same lifecycle test runs on the CloudWatch large-data delivery bucket when it differs from the S3 destination, and on every bucket an enabled replication rule copies a log bucket to, because a replica keeps every prompt and response after the source expires them. An Object Lock default retention on a log bucket fails the retention leg, because S3 Lifecycle does not delete a version Object Lock retains, so the lifecycle period is not the period the record is kept. A log bucket with an enabled replication rule has each invocation log object under `<keyPrefix>/AWSLogs/<account>/BedrockModelInvocationLogs/` read with `HeadObject`, at most 500 per bucket, because S3 Lifecycle takes no action on an object whose replication status is `PENDING` or `FAILED`: an object whose `ReplicationStatus` is `FAILED` fails the retention leg, and a failed `HeadObject` is `N/A` naming what was not read. Whether lifecycle deletion ran is judged from the oldest current object under that root: `ListObjectsV2` lists each Region folder and enters only the earliest date folder at each `yyyy`, `mm`, `dd` and `hh` level, and an object written longer ago than the earliest `Expiration` `Days` or `Date` of the counted rules, plus 2 days for the daily lifecycle run, fails the bucket. An unread listing is `N/A`. The same read runs on every replica. A bucket past the 500th `HeadObject` with no `FAILED` status read and no overdue object is retained, because an object a `FAILED` status holds past the rule would itself be older than the rule. On a versioned bucket `ListObjectVersions` finds the version that became noncurrent longest ago, counted from the write of the next newer version or delete marker of its key, and enters date folders in key order until one holds a noncurrent version, since a folder whose versions expired can still hold delete markers. A version past the shortest `NoncurrentDays` plus 2 days fails the bucket, and an unread version listing is `N/A`. Each replica is still judged. The logging row that names the destinations states that it records the destinations only. A `Bedrock Invocation Log Retained Entry` row per destination looks for one retained entry by metadata alone: the log group's most recently written stream (`logs:DescribeLogStreams`, `orderBy` `LastEventTime`, `limit` 1) passes when it reports a `lastEventTimestamp`, and the S3 destination passes when `ListObjectsV2`, read for one item, returns an object under `<keyPrefix>/AWSLogs/`. No event content or object body is read. A destination with no entry is `N/A`, never `Failed`, because a Region where no model was invoked since logging was set holds none either, and an unread destination is `N/A` naming the action. AgentCore Memory event retention is reported as one `AgentCore Memory Event Retention` row per memory: every page of `ListMemories` is read, and each memory's `eventExpiryDuration` is read with `GetMemory` (the `without_decryption` view). A read memory is `Passed` and its row names the period in days as a service-enforced expiry after which AgentCore deletes events; botocore makes the field required and bounded 1 to 365 days, so a readable memory has no `Failed` outcome and no retention threshold is assumed. An unread list or memory is `N/A` naming the action, and one unread memory does not hide the others. Whether deletion has run, and legal holds on individual versions, are not read. A `Bedrock Agent Memory Retention` row is reported for every agent version that enables memory: every agent is read at DRAFT (`bedrock:GetAgent`) and at each version an alias routes to (`bedrock:ListAgentAliases`, `bedrock:GetAgentVersion`), and a version whose `memoryConfiguration.enabledMemoryTypes` is not empty is `Passed` with its `storageDays` named (botocore bounds it 0 to 365). An absent `storageDays`, a period of 0, or an unread agent is `N/A`. A `SageMaker Inference Data Retention` row judges the S3 destinations every SageMaker endpoint writes inference data to: the `DataCaptureConfig.DestinationS3Uri` of an endpoint with capture enabled, and the `AsyncInferenceConfig.OutputConfig` `S3OutputPath` and `S3FailurePath` of its endpoint configuration. Each gets the lifecycle, versioning, Object Lock and replica test above, with the URI's key path in place of `<keyPrefix>/AWSLogs/` as the root a rule must cover and the oldest current object under it read the same way. On a replicated destination the `ReplicationStatus` of its objects is not read, because `s3:GetObject` is granted only on invocation log records, so it is credited from the oldest current object alone: an object a `PENDING` or `FAILED` status holds past the rule would itself be older than the rule. An endpoint that was not read keeps the row off `Passed`.

### BR-05: Guardrail Configuration

- **Severity:** High
- **Description:** Verifies guardrails are configured and enforced.

### BR-06: AWS CloudTrail Logging

- **Severity:** Medium
- **Description:** Validates AWS CloudTrail logging for Bedrock API calls on logging multi-Region trails and on logging single-Region trails whose `HomeRegion` is the assessed Region, judging every selector field. The management row credits a basic selector with `IncludeManagementEvents` and `ReadWriteType` `All` that excludes neither `bedrock.amazonaws.com` nor `bedrock-mantle.amazonaws.com`, or an advanced `eventCategory` `Management` selector with no field that drops Bedrock (`readOnly`, or an `eventSource` that leaves either source out). Calls to the `bedrock-mantle` endpoint carry the `bedrock-mantle.amazonaws.com` event source, so a selector that keeps only `bedrock.amazonaws.com` records none of its management events. `WriteOnly` is not credited because `InvokeModel` is a read-only management event. A `NetworkActivity` selector is not management coverage. The data-event rows credit a resource type only from a selector whose sole other field is `eventCategory` `Data`; a type named only beside `eventName`, `readOnly`, `resources.ARN` or any other field is reported as narrowed. The knowledge base row needs `AWS::Bedrock::KnowledgeBase` and enabled model invocation logging with `textDataDeliveryEnabled` `true`; a flag the API does not return is reported as unread. It also lists every knowledge base's data sources (`ListDataSources`, `GetDataSource`) and reads `s3:GetBucketVersioning` on each S3 source bucket: a bucket whose `Status` is `Suspended` or absent (never versioned) fails the row, because a document overwritten after ingestion keeps no earlier version for a retrieved chunk to be traced back to. An unread data source or bucket makes the row `N/A`. Sources outside S3 keep versions with their provider and are named, not judged. The inference row needs `AWS::Bedrock::Model`, `AWS::Bedrock::AsyncInvoke`, `AWS::Bedrock::AgentAlias` and `AWS::Bedrock::InlineAgent`. `Bedrock Mantle Data Event Logging` needs all six `bedrock-mantle` resource types (`AWS::BedrockMantle::Project`, `Reservation`, `CustomizedModel`, `Environment`, `Runtime` and `Skill`), because the endpoint logs `CreateInference` and its file calls as data events; AWS's example selector names only the first three, and a selector copied from it fails naming the other three. `Bedrock Inference Forensic Record` needs invocation logging with `textDataDeliveryEnabled` and every destination under an enabled customer managed KMS key. A trail that cannot be read makes a row without coverage `N/A`. The Region's CloudTrail Lake event data stores are listed (`ListEventDataStores`, every page) and each is read with `cloudtrail:GetEventDataStore`. A store counts only with `Status` `ENABLED`, and its `AdvancedEventSelectors` are judged by the same rules as a trail's, so a store can credit the management row and each data-event row, and a narrowed store selector is named and not credited. A store that could not be read, and an unlisted store list, turn a gap on those rows into `N/A` naming the action. A gap that no read store closes fails. The stores homed in every other assessed Region (`TARGET_REGIONS`) and every other Region enabled for the account (`account:ListRegions`) are listed too, and one of them counts only when `GetEventDataStore` reports `MultiRegionEnabled` `true`; an unlisted Region, or a Region list that could not be read, turns a gap into `N/A`. The check is scoped by use as BR-04 is. Not read: RetrieveAndGenerate citations.
- **End-to-end trace row:** `Bedrock Inference End-to-End Trace` reads event history (`LookupEvents`) for `InvokeModel`, `InvokeModelWithResponseStream`, `Converse` and `ConverseStream` between 24 hours and 15 minutes ago, keeps the 10 newest successful calls that carry a `requestID`, and looks for their invocation log records by `requestId` (`FilterLogEvents` on the log group, or the S3 records as BR-34 reads them). A joined call is the `Passed` trace example: it names the caller ARN, source IP, model ID and inference Region from CloudTrail, and the identity, model, timestamp and whether input and output bodies were logged from the record, plus the request IDs that did not join. No joined call fails, invocation logging without text delivery fails, and a failed or capped read is `N/A`.
- **Centralization row:** `Bedrock Inference Trace Centralization` needs both halves of a trace queryable centrally. The CloudTrail half is met by a CloudTrail Lake event data store (as read above) that records Bedrock management events, or by an AWS Glue Data Catalog table in this or any enabled Region (`GetDatabases`, `GetTables`, every page) whose location is under `s3://<S3BucketName>/<S3KeyPrefix>/AWSLogs/` of a logging trail (`ListTrails`, `GetTrail`, `GetTrailStatus`, `GetEventSelectors`) that records this Region and every Bedrock management event, read and write. A table under another root, under a trail that records fewer events, or whose `CloudTrail/<region>/` segment names another Region is named as not credited, and so is an Amazon Security Lake `CLOUD_TRAIL_MGMT` source, because whether it collects this Region is not read. The invocation log half is met by a Glue table whose location contains `BedrockModelInvocationLogs/` and is a prefix of `s3://<bucket>/<keyPrefix>/AWSLogs/<account>/BedrockModelInvocationLogs/<region>/`. For invocation logs that go only to CloudWatch Logs, each subscription filter on the group (`logs:DescribeSubscriptionFilters`, every page) is followed when it has no filter pattern, no field selection criteria and does not apply to transformed logs, and its destination is a Firehose stream of this account: the stream (`firehose:DescribeDeliveryStream`) must be `ACTIVE` with an S3 destination and no Lambda record processor, and a Glue table whose location is at or above the destination prefix, cut at its first `!{...}` expression, meets the half. With no such table, an Athena data catalog in any of those Regions (`athena:ListDataCatalogs`) of type `LAMBDA`, or `FEDERATED` with no `ConnectionType`, could be a CloudWatch Logs connector, so it holds the row at `N/A`, as does a subscription to another destination type or account, a Lambda processor or a failed read; otherwise the half is unmet. Either half unmet fails the row; an unread part is `N/A`. Whether each table's schema parses the records is not judged.

### BR-07: Prompt Management

- **Severity:** Low
- **Description:** Reports whether Prompt Management is in use, then judges the prompts it holds. A prompt with only a DRAFT fails `Bedrock Prompt Production Version` (Medium). `Bedrock Prompt Version Encryption` reads `GetPrompt(promptVersion=N)` for every numbered version, since any version stays invocable by its ARN, and fails a prompt when any version reports no `customerEncryptionKeyArn`, or names a key that `kms:DescribeKey` does not report as `KeyManager` `CUSTOMER` and `KeyState` `Enabled`; an unread version or key is `N/A` naming the version. The flow leg walks the prompt nodes of each flow's working draft and of every flow version an alias routes to, including nodes inside DoWhile loops, and fails a `promptArn` with no version suffix and a prompt node that defines its prompt inline. The flow leg runs whether or not the Region holds a Prompt management prompt. A flow, alias list or flow version that cannot be read is `N/A`. `Bedrock Runtime Prompt Version Reference` reads every page of the last 24 hours of `LookupEvents` for `InvokeModel`, `InvokeModelWithResponseStream`, `Converse` and `ConverseStream`, up to 10 pages of 50 events per operation, and fails when a call's `requestParameters.modelId` is a prompt ARN with no version suffix, which runs the prompt's DRAFT. Calls that all name a numbered version pass; an unread lookup, an operation with more events than the page cap, or no call that passes a prompt ARN is `N/A`, and a capped operation is named with the time before which its calls were not read (event history is read newest first). `Bedrock Prompt Change Permission Scope` fails each role or user whose identity policies allow `bedrock:UpdatePrompt`, `bedrock:CreatePromptVersion` or `bedrock:DeletePrompt` on a `Resource` with a `*` or `?` in any segment, or through `NotResource`, and each one that holds one of those actions beside `bedrock:RenderPrompt`; `bedrock:CreatePrompt` takes no resource type, so no ARN bounds it: the row names every role and user it allows, unless a permissions boundary or an account-wide Deny removes it, and fails one that also holds `bedrock:RenderPrompt`; service control policies are not evaluated per principal. The `Bedrock Prompt Variants Check` row is an Informational `N/A` advisory outside these verdicts. Prompts held in application code, and the split between the roles that release a version and the roles that call `RenderPrompt`, are not judged.

### BR-08: Agent AWS IAM Configuration

- **Severity:** Medium
- **Description:** Checks agent execution role permissions.

### BR-09: Knowledge Base Encryption

- **Severity:** High
- **Description:** Checks knowledge base encryption settings.

### BR-10: Guardrail AWS IAM Enforcement

- **Severity:** Medium
- **Description:** Verifies guardrails are enforced through AWS IAM conditions. Each role or user that may invoke a model must name an approved guardrail on every invoke grant, or be covered by a central mechanism in the Region: an account-enforced guardrail configuration scoped to all models with comprehensive guarding, a configuration for the Region in the effective Organizations Bedrock policy at a non-`DRAFT` version, or, in a member account, an attached service control policy denying both invoke actions without an approved `bedrock:GuardrailIdentifier` on a `Resource` that covers every invoke resource type in the service authorization reference. A central source that cannot be read is named and keeps the identity failed. Each guardrail version that may be named, directly or centrally, must apply, to the input and to the output, at least one `HATE`, `INSULTS`, `MISCONDUCT`, `SEXUAL` or `VIOLENCE` content filter with strength `LOW`, `MEDIUM` or `HIGH` and action `BLOCK`; the `Passed` row names the categories found on each side and says filter strength above `LOW` is not judged. The `PROMPT_ATTACK` filter, which detects and blocks malicious intents in user inputs and filters no harmful content, and denied topics, word filters, sensitive information filters, contextual grounding and automated reasoning checks do not count toward either direction. Service control policies are not evaluated per principal.

### BR-11: Custom Model Encryption

- **Severity:** High
- **Description:** Judges every custom model's key and every bucket its customization data sits in. The key is `GetCustomModel.modelKmsKeyArn`, or the customization job's `outputModelKmsKeyArn` when the model record names none, and it passes only when `kms:DescribeKey` reports `KeyManager` `CUSTOMER` and `KeyState` `Enabled`. A model with no key anywhere, an AWS managed key, or a key in any state other than Enabled fails (Medium). A model record or a customization job that cannot be read, or a key that cannot be described, is `N/A` naming the model and the failed call, so a model nobody read never sits under the Passed summary, which counts models as "N of M". A second finding, `Bedrock Customization Data Bucket Encryption`, reads the default encryption of each bucket named by the model's `trainingDataConfig.s3Uri`, `trainingDataConfig.invocationLogsConfig.invocationLogSource.s3Uri`, `validationDataConfig.validators[].s3Uri` and `outputDataConfig.s3Uri`, once per bucket. The same four locations are read from every model customization job (`ListModelCustomizationJobs`, every page, then `GetModelCustomizationJob`), because a failed or stopped job leaves its data in its buckets and creates no custom model; a model whose job cannot be read still has its own buckets judged. When the job list or a job cannot be read, the bucket `Passed` row is `N/A` naming the failed reads. SSE-S3, `aws:kms` with no key id (served with `aws/s3`), no default encryption configuration, and a key that fails the same DescribeKey test all fail (High); a bucket or key that cannot be read is `N/A`.

### BR-12: Invocation Log Encryption

- **Severity:** Medium
- **Description:** Judges the key on every destination invocation logs are written to: the S3 bucket, the large-data delivery bucket when it differs, and the CloudWatch Logs group. A bucket passes only when its default encryption is `aws:kms` or `aws:kms:dsse` with a key that `kms:DescribeKey` reports as `KeyManager` `CUSTOMER` and `KeyState` `Enabled`. SSE-S3, the `aws/s3` managed key, and `aws:kms` with no key id (which S3 serves with `aws/s3`) fail. A bucket whose `GetBucketEncryption` returns `ServerSideEncryptionConfigurationNotFoundError` fails, and the text says whether S3 applied SSE-S3 to each object was not read. The log group finding, `Bedrock Invocation Log Group Encryption`, fails when the group has no `kmsKeyId` or its key is not an enabled customer managed key. A key that cannot be described, including a key in another account, is `N/A`. A second finding, `Bedrock Invocation Log Group Deletion Protection`, reads `deletionProtectionEnabled` on the CloudWatch Logs group that receives invocation logs and fails when it is not `true`; `DescribeLogGroups` omits the field on a group that never had it set, so an absent value reads as off. No CloudWatch delivery, or a group that is not returned to this account, is `N/A`. A third finding, `Bedrock Invocation Log WORM Archive`, judges each invocation log bucket (the S3 destination and the large-data bucket) on its Object Lock default retention, and the CloudWatch Logs group on its subscription filters (every page). A bucket passes only with `ObjectLockEnabled` `Enabled` and default retention in `COMPLIANCE` mode; Object Lock off, no default retention or `GOVERNANCE` mode fails. The log group passes when one filter with an empty filter pattern, no field selection criteria and not applied on transformed logs sends to an `ACTIVE` Firehose stream of this account whose S3 destination runs no Lambda record processor and whose bucket passes the same Object Lock test. No filter, a narrowed filter, a non-S3 destination or an unlocked bucket fails. A CloudWatch Logs destination, a Kinesis or Lambda target, another account's stream or a failed read is `N/A` naming it. Whether a bucket is in a separate Log Archive account is not read.

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
- **Description:** Lists every custom model and reads `GetCustomModel.modelKmsKeyArn`. No key fails as the AWS owned key. A named key passes only when `kms:DescribeKey` reports it `KeyManager` `CUSTOMER` and `KeyState` `Enabled`; an AWS managed or disabled key fails. A model whose details or key cannot be read is `N/A` naming the model and the read that failed.

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
- **Description:** Extends existing BR-09 to verify Knowledge Base encryption uses customer-managed KMS keys. Uses the authoritative knowledge base `type` (`VECTOR | KENDRA | SQL | MANAGED`) to decide how to assess each KB: for `MANAGED` knowledge bases it reads `knowledgeBaseConfiguration.managedKnowledgeBaseConfiguration.serverSideEncryptionConfiguration.kmsKeyArn` and passes only when `kms:DescribeKey` reports the key customer managed and Enabled. Each S3 location in its `supplementalDataStorageConfiguration.storageLocations` is judged on the bucket's default encryption with `s3:GetEncryptionConfiguration`: no configuration, SSE-S3 or an AWS managed key fails, and an unread one is `N/A`. Who can read a `MANAGED` store is set by Amazon Bedrock, and `ManagedKnowledgeBaseConfiguration` has no access member, so it is not judged. An S3 Vectors bucket or index key is judged the same way, and an undescribable one is `N/A`. For a custom vector store it follows the store to its own resource: an OpenSearch Serverless collection through `aoss:BatchGetCollection` (`kmsKeyArn`), an Aurora cluster through `rds:DescribeDBClusters` (`StorageEncrypted` and `KmsKeyId`), an OpenSearch domain through `es:DescribeDomain` (`EncryptionAtRestOptions`), and a Neptune Analytics graph through `neptune-graph:GetGraph` (`kmsKeyIdentifier`), and judges the key it finds with the same DescribeKey test. `aoss:BatchGetCollection` has no resource type, so the role holds it on `Resource: '*'`; a collection it cannot read is `N/A` naming the action. For an OpenSearch Serverless collection the check also lists every data access policy (`aoss:ListAccessPolicies`, every page) and reads each one (`aoss:GetAccessPolicy`, both on `Resource: '*'` for want of a resource type), because OpenSearch Serverless does not check a caller's permission on the collection's KMS key. Data policies are additive, so each index rule whose `Resource` pattern matches `index/<collection>/<vectorIndexName>` is judged: a wildcard in the collection segment (`index/*/*`, `index/kb*/*`) reaches other collections and fails, and so does a principal with a wildcard. A policy that could not be read or parsed, or a knowledge base with no `vectorIndexName`, is `N/A`. Rules on other resource types, such as `collection`, are not counted. Every network policy is listed (`aoss:ListSecurityPolicies` with `type` `network`, every page) and read (`aoss:GetSecurityPolicy`, both on `Resource: '*'` for want of a resource type): a `collection` or `dashboard` rule whose `Resource` pattern matches `collection/<name>` with `AllowFromPublic` `true` fails, since a public rule overrides a private one; private rules are named with their `SourceVPCEs` and `SourceServices`, and an unread policy or a collection no rule names is `N/A`. Each IAM role or user a reaching index rule admits is looked up in the IAM permissions cache, and an unconditioned Allow of `aoss:APIAccessAll` whose `Resource` has a wildcard in any segment, or that uses `NotResource`, fails unless the permissions boundary denies it or names its resources; a conditioned grant, a principal the cache does not hold or a missing cache is `N/A`. The same `DescribeDomain` response gives an OpenSearch domain's `AccessPolicies`: an Allow whose principal is a wildcard or `NotPrincipal`, with no exact principal condition, fails unless `AdvancedSecurityOptions.Enabled` is `true` and `AnonymousAuthEnabled` is not `true`, since fine-grained access control then authenticates each request. An empty policy passes this leg, and an absent or unparsable one is `N/A`. The same `GetGraph` response gives a Neptune Analytics graph's `publicConnectivity`: `true` fails, `false` passes, and an absent field is `N/A`. For an Aurora store, each `DBClusterMembers` instance is read with `rds:DescribeDBInstances`: an instance with `PubliclyAccessible` `true` fails, and an unread instance is `N/A`. The cluster's `IAMDatabaseAuthenticationEnabled` `false` fails too, because database users then authenticate only with passwords no IAM policy governs; an absent value is `N/A`, and whether password logins remain beside IAM authentication is not read. For Pinecone, MongoDB Atlas and Redis Enterprise Cloud the vector data sits with the provider; the check reads the credentials secret with `secretsmanager:DescribeSecret` and fails a secret with no `KmsKeyId` (the `aws/secretsmanager` key), and otherwise reports the store `N/A` because the provider's key cannot be judged. A `KENDRA` knowledge base is judged on its Kendra index key through `kendra:DescribeIndex` (`ServerSideEncryptionConfiguration.KmsKeyId`): an index naming no key fails, a named key gets the same DescribeKey test, and an unread index or a missing `kendraIndexArn` is `N/A`. A `SQL` knowledge base is judged on its Redshift query engine. A provisioned engine is read with `redshift:DescribeClusters`: `PubliclyAccessible` `true` fails, `Encrypted` other than `true` or no `KmsKeyId` fails, and the key gets the same DescribeKey test. A Serverless engine's workgroup is found by `workgroupArn` across every `redshift-serverless:ListWorkgroups` page (`Resource: '*'`, the action has no resource type): `publiclyAccessible` `true` fails, and its namespace is read with `redshift-serverless:GetNamespace`, where a `kmsKeyId` that is absent or `AWS_OWNED_KMS_KEY` fails and any other key gets the DescribeKey test. An unread cluster, workgroup or namespace, or a workgroup ListWorkgroups does not return, is `N/A` naming the action. A storage configuration of type `AWS_DATA_CATALOG` keeps its tables in S3, so each name in `awsDataCatalogConfiguration.tableNames` is resolved as `database.table`: a literal table through `glue:GetTable`, and a wildcard in the table part against every `glue:GetTables` page for the database. Each table's `StorageDescriptor.Location` and `AdditionalLocations` are read, and for a partitioned table each partition's location through `glue:GetPartitions` (`ExcludeColumnSchema`), up to 20 pages. Every S3 bucket found is judged on its default encryption with `s3:GetEncryptionConfiguration`: no configuration, SSE-S3 or the AWS managed key fails, and a customer managed key gets the same DescribeKey test. The key of each object already written is not read. A table name with no single database, a wildcard matching no table, a table with no location or a non-S3 location, more than 20 partition pages, an unread call or a configuration naming no table holds a would-be `Passed` at `N/A`; a failure stands. The Glue reads are held on the `catalog`, `database/*` and `table/*/*` ARNs of the account. A knowledge base whose `GetKnowledgeBase` call fails is `N/A` under `Knowledge Base Customer-Managed KMS Encryption Review`. Each data source's `serverSideEncryptionConfiguration.kmsKeyArn`, the key for transient data during ingestion, is judged under `Knowledge Base Data Source Transient Data Key`: no key fails, and each key is described once. Under `Knowledge Base Vector Access Against Source Bucket Policy`, each S3 source bucket of an OpenSearch Serverless or S3 Vectors knowledge base is read with `s3:GetBucketPolicy`, and a principal the vector store admits (named by a reaching data access rule, or exempted by `aws:PrincipalArn` or `NotPrincipal` in the restricting vector bucket Deny) fails when a Deny of `s3:GetObject` on every object of the source bucket keeps it out, through one negated `aws:PrincipalArn` condition (`IfExists` and set prefixes stripped) or by naming it. A Deny with any other condition, on part of the bucket or with `NotResource` or `NotPrincipal`, an unread policy, or a vector store whose admitted principals were not all read is `N/A`. Each admitted IAM role or user is then looked up in the IAM permissions cache: an unconditioned Deny of `s3:GetObject` covering every object of the bucket (a `Resource` ending in `*` that matches `arn:<partition>:s3:::<bucket>/`) in an identity policy or the permissions boundary fails, as does a boundary allowing `s3:GetObject` on no object of the bucket, or no identity Allow reaching the bucket when the bucket policy allows `s3:GetObject` to no one. It reads only when an identity Allow covers every object, within a boundary that does too. An Allow or boundary on part of the bucket, a conditioned, partial or `NotResource` Deny, no identity Allow beside a bucket policy Allow, or a principal the cache does not hold is `N/A`. Each level of the organization path above the account must then have an attached service control policy allowing `s3:GetObject` on every object of the bucket, and `kms:Decrypt` on a customer managed default key, read from the SCP inventory BR-10 and BR-43 use (`organizations:ListTargetsForPolicy` and `ListParents`): a level with no such Allow or an unconditioned SCP Deny covering the read fails, an SCP Allow or Deny on part of the bucket or under a Condition, a `NotResource` Deny or an unread SCP inventory is `N/A`, and the management account or an account in no organization is not restricted. When the bucket's default encryption names a customer managed key, its key policy (`kms:GetKeyPolicy`) and grants (`kms:ListGrants`, every page) are read once per key: the principal reads when the key policy allows it `kms:Decrypt` by ARN or `*`, when the key policy allows the account root and an identity Allow of `kms:Decrypt` covers the key, or when an unconstrained grant to it lists `Decrypt`. A key policy Deny, or none of those, fails, and a role's permissions boundary limits a key policy grant naming the role. A key policy statement whose Condition is other than `kms:ViaService` for `s3.<region>.amazonaws.com` or `kms:CallerAccount` for the account, a constrained grant or an unread key is `N/A`. An AWS managed key is not judged and the row says so, and the key of each object already written is not read. Conditions on identity-policy Allow statements are not evaluated. If a `MANAGED` KB's encryption block is missing from the API response (deployed botocore older than 1.43.32, which silently drops the unmodeled field), the KB is reported as N/A "indeterminate" rather than a false-positive failure.
- **S3 Vectors:** An `S3_VECTORS` storage configuration is the one custom store this check assesses instead of deferring, because both halves of the control are readable one ARN hop away. It follows `storageConfiguration.s3VectorsConfiguration.vectorBucketArn` and calls `s3vectors:GetVectorBucket` (fails unless `encryptionConfiguration.sseType` is `aws:kms` with a `kmsKeyArn`, so SSE-S3 `AES256` fails, the same bar as every other storage type) and `s3vectors:GetVectorBucketPolicy`. The policy passes only when it holds no Allow whose principal is a wildcard or `NotPrincipal` unless an exact-valued positive condition on a principal key bounds it, and holds a Deny with `Principal` `*` covering `s3vectors:QueryVectors`, `GetVectors` and `ListVectors` on the index, whose every condition is a negated principal-key operator with exact values and no `IfExists`. An attached policy with no such Deny fails, as does no policy at all (`NotFoundException` is an answer about the workload, not an assessment gap). Which principals the Deny's exception list names is not judged on this row; they are compared with the source bucket policy on the vector access row. A third leg calls `s3vectors:GetIndex` on the one index the knowledge base names, by `indexArn` when the API returns one and otherwise by the bucket name plus `indexName`: an index created with its own `encryptionConfiguration` overrides the bucket's default for every vector it holds, so an `aws:kms` bucket holding an `AES256` index is Failed. An index that carries no `encryptionConfiguration` of its own inherits the bucket's and is not held against the knowledge base. Only the index that knowledge base names is read, because a vector bucket can hold indexes belonging to other workloads. The client is built for the region in the bucket ARN, which need not be the scanned region. One finding per knowledge base. `AccessDenied` on any of the three calls is reported as N/A naming the missing action, so a permission gap stays visible, and a knowledge base reporting a `vectorBucketArn` but neither `indexArn` nor `indexName` is N/A for the same reason: an index-level override cannot be ruled out.

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
- **Description:** Extends BR-23 (which covers the harmful-content filters). Reads `GetGuardrail.sensitiveInformationPolicy` and judges each PII entity and regex by the action it takes on each side: `inputAction` or `outputAction`, falling back to `action`, with `inputEnabled` or `outputEnabled` false meaning the side is off. A guardrail passes when some entity or regex blocks or masks on the input and on the output, each side that sets an entity also sets `AWS_ACCESS_KEY`, `AWS_SECRET_KEY` and `PASSWORD` to `BLOCK` or `ANONYMIZE` on that side, and a custom regex blocks or masks on the input and on the output for secrets, credentials and internal identifiers the built-in types do not name. A regex that acts on one side only fails and names the other side. Detect-only (`NONE`) entities are named. The regex patterns are not evaluated, and the filter does not reach toolUse input, toolResult content or a toolSpec. The same judgment runs on each deployed guardrail version: every version an agent (DRAFT and each version an alias routes to), a flow Prompt or KnowledgeBase node (DRAFT and each alias-routed version) an account-enforced configuration, the effective Organizations Bedrock policy configuration for the Region, or a `bedrock:GuardrailIdentifier` condition on an invoke action applies is read with `GetGuardrail` at that version, including a guardrail ARN in another Region. Condition values are read from role, user and group policies and permissions boundaries in the IAM permissions cache and, in a member account, from service control policies attached to the root, an OU in the account's path or the account. A condition that names a guardrail without a version joins every version `ListGuardrails` returns plus DRAFT, a value in another Region is left to that Region's run, and a wildcard value is reported as not enumerated. A version that could not be read, an agent, flow or enforced-configuration list that could not be read, a wildcard condition value, a principal the IAM cache recorded an error for, a version 1 cache (which recorded no principal errors) or an unavailable cache keeps the deployed `Passed` row at `N/A`. A guardrail passed per request to InvokeModel, Converse, ApplyGuardrail or RetrieveAndGenerate is recorded by no configuration API and is not judged, and neither is guardContent tagging. Each deployed version that passes the settings test is then applied once with `bedrock:ApplyGuardrail` (`source` `OUTPUT`, `outputScope` `INTERVENTIONS`) to a fixed probe string built from AWS's documented example access key and secret key, as the `Deployed Guardrail Sensitive Information Output Probe` row: both blocked or anonymized is `Passed`, either let through is `Failed`, and an ApplyGuardrail error is `N/A` naming the version. Only the response's action and each entity's type and action are read. PASSWORD detection of the probe text and the custom regex patterns are stated, not judged. The Knowledge Base PII Redaction Before Model rows fail a knowledge base that ingests a source with no redaction step, whatever guardrail an agent version or flow node that retrieves from it applies: the agent guardrail guide describes a guardrail evaluating user messages and model responses and names no evaluation of retrieved knowledge base chunks, so such a guardrail is not credited as screening them, and the row names each such agent or node. One masked entity type, such as `EMAIL` alone, is not credited on an account-enforced configuration either. For each knowledge base, every data source is read with `GetDataSource` for a `POST_CHUNKING` transformation Lambda, and every agent version (DRAFT and each alias-routed version, through `ListAgentKnowledgeBases`, skipping `DISABLED` links) and flow KnowledgeBase node (DRAFT and each alias-routed version) that retrieves from it is paired with the guardrail version it applies. An S3 source is also credited when a `COMPLETED` Comprehend `ONLY_REDACTION` job writes to its bucket at a prefix holding every inclusion prefix the source ingests, its `RedactionConfig.PiiEntityTypes` names any PII entity type (the row names them, and whether types other than `ALL` cover the source's PII is not judged, as on the Glue leg), and the source's latest ingestion job (from `ListIngestionJobs`) started after the job's `EndTime`, or no ingestion job is recorded. Both `MaskMode` values meet the control and are named. Every object the source ingests is then listed with `s3:ListBucket` (`ListObjectsV2`, every page, up to 100,000 objects): an object last modified after the job's `EndTime` was not redacted by it, so the source is not credited and the row fails and names up to three such keys. An unread or capped listing keeps the source at `N/A`. Whether each listed object was written by the job is recorded by no API, so a source whose objects all predate the end time is still `N/A`, named as not failed. An S3 source is credited the same way by an AWS Glue visual job: `GetJobs` returns each job's `CodeGenConfigurationNodes`, and a job is credited for an S3 target (a `Path`, or a catalog target whose table location `GetTable` returns) when every path into the target passes a `PIIDetection` node whose `PiiType` masks or hashes (`RowMasking`, `RowPartialMasking`, `RowHashing`, `ColumnMasking`, `ColumnHashing`; the Audit types only report), and the newest `SUCCEEDED` run across every `GetJobRuns` page ended before the source's latest ingestion job. The node's `EntityTypesToDetect` are named, and whether they cover the PII the source holds is not judged. A Glue script job carries no node graph, so its code is not read. An unread `GetJobs`, `GetJobRuns` or `GetTable` keeps an S3 source with no other redaction step at `N/A` naming that read. An unread `ListPiiEntitiesDetectionJobs`, or an unread `ListIngestionJobs` for a source a job covers, keeps an S3 source with no transformation step at `N/A` naming that read. It never passes a knowledge base: a transformation Lambda's logic is not read, a knowledge base carries no guardrail of its own, and a direct RetrieveAndGenerate caller supplies its guardrail per request, so a knowledge base with a screening step is `N/A` and named as not failed. An account-enforced guardrail that meets the same test clears every knowledge base only when the configuration applies to every model and every message: a configuration whose `includedModels` does not name `ALL`, that excludes models, that guards system or message content `SELECTIVE`, or that sets `inputTags` `HONOR` is named as not credited. An agent, flow, guardrail or enforced-configuration read that failed turns a would-be `Failed` into `N/A` naming what was not read.

### BR-27: Guardrail Contextual Grounding Check

- **Severity:** Medium
- **Type:** Regional
- **Description:** Verifies guardrails enable contextual grounding checks to detect hallucinated (ungrounded) and off-topic model responses. Reads `GetGuardrail.contextualGroundingPolicy.filters` and fails a guardrail unless both GROUNDING and RELEVANCE block with a threshold above 0 and no higher than 0.99. Each deployed row names the Automated Reasoning policies and confidence threshold the version applies, or says none is attached. Whether callers supply the grounding_source and query qualifiers, and any scored response, are not recorded by a configuration API, and RetrieveAndGenerate passes no grounding source. The same judgment runs on each deployed guardrail version: every version an agent (DRAFT and each version an alias routes to), a flow Prompt or KnowledgeBase node (DRAFT and each alias-routed version) an account-enforced configuration, the effective Organizations Bedrock policy configuration for the Region, or a `bedrock:GuardrailIdentifier` condition on an invoke action applies is read with `GetGuardrail` at that version, including a guardrail ARN in another Region. Condition values are read from role, user and group policies and permissions boundaries in the IAM permissions cache and, in a member account, from service control policies attached to the root, an OU in the account's path or the account. A condition that names a guardrail without a version joins every version `ListGuardrails` returns plus DRAFT, a value in another Region is left to that Region's run, and a wildcard value is reported as not enumerated. A version that could not be read, an agent, flow or enforced-configuration list that could not be read, a wildcard condition value, a principal the IAM cache recorded an error for, a version 1 cache (which recorded no principal errors) or an unavailable cache keeps the deployed `Passed` row at `N/A`. A guardrail passed per request to InvokeModel, Converse, ApplyGuardrail or RetrieveAndGenerate is recorded by no configuration API, so the deployed rows do not judge it, and neither is guardContent tagging judged there. The CloudTrail management event of an InvokeModel, InvokeModelWithResponseStream or Converse call names that guardrail and version in `requestParameters`, and the `Guardrail Contextual Grounding Score Evidence` row reads and judges each version so named for the calls logged in the last 24 hours. Complements BR-25 (RAG evaluation) with a runtime control.
- **Score evidence row:** `Guardrail Contextual Grounding Score Evidence` reads `GetModelInvocationLoggingConfiguration` and fails when `textDataDeliveryEnabled` is not `true`, because no response body, and so no grounding score, is logged. With a CloudWatch Logs destination it reads the last 24 hours of records matching `contextualGroundingPolicy` with `logs:FilterLogEvents` (25 per page, at most 10 pages). With an S3-only destination it lists the UTC hour folders of the last 24 hours under `<keyPrefix>/AWSLogs/<account>/BedrockModelInvocationLogs/<region>/`, skips the `data/` large-data bodies, and reads at most 40 record objects with `s3:GetObject`, each object once for all three record legs of the row. A capped read names the time from which matching records were not all read. It passes on a `GROUNDING` or `RELEVANCE` filter entry with a numeric `score`, naming the request ID, score, threshold and action. It also reads each guarded call's logged request. The logged Converse request never names its `guardrailConfig`, so each `Converse` or `ConverseStream` call whose response carries no `contextualGroundingPolicy` assessment is joined by `requestId` to its CloudTrail event, whose `requestParameters.guardrailConfig` names the guardrail and version. A Converse call through a guardrail version with contextual grounding filters fails unless `guardContent` blocks qualify both a `grounding_source` and a `query`; a call whose event names no guardrail is excluded. An InvokeModel call (one whose response carries `amazon-bedrock-guardrailAction`) fails unless it wraps both an `amazon-bedrock-guardrails-groundingSource_<tagSuffix>` and an `amazon-bedrock-guardrails-query_<tagSuffix>` tag matching its `amazon-bedrock-guardrailConfig` `tagSuffix`. That rule is applied when the call sends either tag or its response carries a `contextualGroundingPolicy` assessment. An InvokeModel call sending neither tag, with no such assessment, names its guardrail only in request headers the log does not record, so it is joined by `requestId` to its CloudTrail event, read with one `cloudtrail:LookupEvents` stream per operation name from 5 minutes before the earliest such call to 5 minutes after the latest, paged until every call is matched or the stream ends, at most 50 pages per operation and 100 pages for every join of the region run, BR-34's included; a call joined once is not looked up again. Calls still unmatched at that cap are not judged and are counted. A Converse call logged in the last 15 minutes with no event yet is counted and not judged, because event history lags the call. It fails when the `guardrailIdentifier` and `guardrailVersion` in that event's `requestParameters` name a version with contextual grounding filters (`GetGuardrail`), and is not judged for tags when the version has none. Each guardrail version that the CloudTrail event of a guarded Converse or InvokeModel call names is read once and fails unless `GROUNDING` and `RELEVANCE` both block with a threshold above 0 and no higher than 0.99, so a version with no grounding filter fails; an unread version or event withholds the pass. No matching event, an event naming no guardrail or a failed read is not judged and withholds the pass. No scored entry, a capped read or an unread log is `N/A`. No request or response text is reported.

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
- **Description:** Lists imported models and reads `GetImportedModel.modelKmsKeyArn`. No key fails as the AWS owned key. A named key passes only when `kms:DescribeKey` reports it customer managed and Enabled; an AWS managed or disabled key fails, and a model or key that cannot be read is `N/A`.

### BR-31: Batch Inference Output Encryption

- **Severity:** Medium
- **Type:** Regional
- **Description:** Verifies batch inference (model invocation) jobs encrypt their S3 output with a customer-managed KMS key. Reads `outputDataConfig.s3OutputDataConfig.s3EncryptionKeyId` from the job summaries returned by `ListModelInvocationJobs` and reports jobs without a customer-managed output key.

### BR-32: CloudWatch Alarms on Bedrock Metrics

- **Severity:** Medium
- **Type:** Regional
- **Description:** Verifies CloudWatch alarms that reach an action exist on Amazon Bedrock runtime metrics (the `AWS/Bedrock` namespace) to detect abuse, denial-of-wallet, sustained throttling, and content-filter spikes. Uses `DescribeAlarms` for metric and composite alarms and matches alarms that target the `AWS/Bedrock` namespace in the alarm or in a metric-math expression. An alarm counts only when `ActionsEnabled` is true and `AlarmActions` names a target, or when its `ALARM` state alone makes an acting composite alarm's rule true, whatever state the rule's other alarms are in: an alarm under `OR` counts, one `AND`ed with another alarm does not, and a rule that uses `AT_LEAST` or mixes `AND` and `OR` without parentheses credits none of its alarms. A rule may name an alarm by name or by ARN. DescribeAlarms returns composite alarms only to a `cloudwatch:DescribeAlarms` grant on `*`, so the assessment role holds it there. The runtime row is assessed only in regions that have Bedrock resources. A second row, Guardrail Intervention Monitoring Signal, is judged wherever a guardrail applies: a guardrail in the Region, or a version an agent, flow node or account-enforced configuration applies. It passes on an acting alarm on `InvocationsIntervened` whose only dimension is `Operation` `ApplyGuardrail`: that is the one `Operation` value the namespace publishes (monitoring-guardrails-cw-metrics), and AWS counts the guardrail evaluations made during model invocation as `ApplyGuardrail` calls (logging-using-cloudtrail), so the series counts every intervention in the Region. It also passes when every guardrail version defined or applied in the Region has an acting alarm with that `GuardrailArn` and `GuardrailVersion`: each guardrail's versions come from `ListGuardrails` with `guardrailIdentifier`, plus DRAFT, and every version an agent, flow node or account-enforced configuration applies is added. A version with no such alarm is named and keeps the row at `N/A`, and so does a version list that could not be read. A metric filter over the invocation log group is credited when its pattern selects `INTERVENED` or `guardrail_intervened` (no `!=` and no `-` exclusion) and whose emitted metric an acting alarm evaluates, but a credited filter alone keeps the row at `N/A`: a direct `ApplyGuardrail` call reaches no invocation log, and `ApplyGuardrail` is a CloudTrail data event, which `LookupEvents` does not return, so an empty lookup is not evidence that no call is made. The filter counts only when `GetModelInvocationLoggingConfiguration` returns `textDataDeliveryEnabled` `true`, because the output body is where the log carries an intervention: `false` withdraws the credit, and an absent flag keeps the row at `N/A`. Filter patterns are case sensitive, so a pattern that names neither spelling is not credited, and neither is one that ANDs the intervention test with another test (`&&` in a JSON pattern, a second required term, or the value only in a `?` term beside a required one). An alarm counts only when a spike in interventions raises it: a static `Threshold` crossed upward (`GreaterThanThreshold` or `GreaterThanOrEqualToThreshold`) on statistic `Sum`, `SampleCount` or `Maximum`, at any threshold and any number of breaching datapoints, or an anomaly detection alarm whose `ThresholdMetricId` names an `ANOMALY_DETECTION_BAND` over the counted metric on one of those statistics, crossed with `GreaterThanUpperThreshold` or `LessThanLowerOrGreaterThanUpperThreshold`. Each credited alarm's bound (statistic, threshold, datapoints, periods and period length, or the band) is named in the row, and whether that bound fits the Region's intervention volume is not judged. An alarm that fails that test, or that carries a `GuardrailContentSource` or `GuardrailPolicyType` dimension, or `Operation` beside another dimension or with another value, and so sees one slice of interventions, is named as not credited. Any other metric-math alarm is not judged and keeps the row at `N/A`. CloudWatch publishes `InvocationsIntervened` only under a dimension (monitoring-guardrails-cw-metrics), so an alarm that names no dimension evaluates a series that receives no datapoint and is named as not credited. A metric filter alone fails when event history does show an `ApplyGuardrail` call and no `InvocationsIntervened` alarm counts every intervention. Either alarm passes only when the intervention record also reaches monitoring, on two legs. The invocation log group must be forwarded: `logs:DescribeSubscriptionFilters` must return a subscription filter on it (whether the destination is a reviewed SIEM is not read). No filter fails, and so does invocation logging that is off; an unread filter list is `N/A`. An S3-only destination, or a log group with no filter beside an S3 destination, is judged by `s3:GetBucketNotificationConfiguration` on the bucket: a queue, topic or Lambda configuration that sends `s3:ObjectCreated:*` with no suffix rule and a prefix rule (if any) that is a prefix of `<keyPrefix>/AWSLogs/<account>/BedrockModelInvocationLogs/<region>/` forwards the logs. Any other configuration, an EventBridge-only bucket, no configuration, or an unread one is named and keeps the row at `N/A`, because a reader that polls the bucket is not visible to any read. A logging trail that records the Region (multi-Region, or homed here) or an `ENABLED` event data store must record `AWS::Bedrock::Guardrail` data events with an advanced event selector naming no field beyond `eventCategory` and `resources.type`; AWS records `ApplyGuardrail`, including the guardrail evaluations made during model invocation, only as that data event (logging-using-cloudtrail). Every trail is read (`ListTrails`, `GetTrail`, `GetTrailStatus`, `GetEventSelectors`) and every event data store as BR-06 reads them. A selector narrowed by `eventName`, `readOnly` or another field is named and not credited. No recorder fails; with no recorder, an unread trail or store is `N/A`. Each `Passed` row names one open edge as UNVERIFIED: whether `AWS/Bedrock/Guardrails` metrics for a guardrail that another account owns, or that the organization enforces, are emitted in this account.

### BR-33: Amazon Inspector Lambda Code Scanning

- **Severity:** Medium
- **Type:** Regional
- **Description:** When in-scope Lambda functions exist in the region, verifies Amazon Inspector Lambda standard scanning (`lambda`) and Lambda code scanning (`lambdaCode`) are both enabled so those functions and their dependencies are scanned for vulnerable packages and hardcoded secrets. A function is in scope when its name, ARN, description, handler, role or environment names Bedrock, or when the IAM cache shows its execution role granted a Bedrock or AgentCore action (attached, inline and group policies, with the permissions boundary applied). Calls `lambda:ListFunctions` for scoping, `inspector2:BatchGetAccountStatus` for Inspector status, and `lambda:GetFunction` per in-scope function for its tags and image. Reports `Failed` when either `resourceState.lambda.status` or `resourceState.lambdaCode.status` is not `ENABLED`; that row also reads `inspector2:ListCoverage` and names each in-scope function without `ACTIVE` coverage, with its reason (for example `SCAN_ELIGIBILITY_EXPIRED`), so a disabled code scan and an expired eligibility are both named, and, with both enabled, for each in-scope function that Inspector does not scan: one with a `KMSKeyArn` (a customer managed key) or one tagged `InspectorExclusion=LambdaStandardScanning` (key and value compared without case). GetFunction returns tags only to a caller allowed `lambda:ListTags`, which the scan role holds; a function whose tags were still withheld, or whose role the IAM cache does not hold, is named in an `N/A` row and the `Passed` row becomes `N/A`; cache `principal_errors` do the same. Every page of `inspector2:ListCoverage` for `AWS_LAMBDA_FUNCTION` is read, and each zip function not already excluded fails unless its `$LATEST` record for both the `PACKAGE` and `CODE` scan types is `ACTIVE`; a missing record or an inactive one is named with its reason, so a function idle for 90 days or on an unsupported runtime fails. A container-image function is judged by its image instead: `lambda:GetFunction` `Code.ResolvedImageUri` names the repository and digest, `inspector2:ListCoverage` is read for `AWS_ECR_CONTAINER_IMAGE` records in that repository (`ecrRepositoryName`), and the function fails unless the record for that digest is `ACTIVE` and the repository's `AWS_ECR_REPOSITORY` record has `scanFrequency` `CONTINUOUS_SCAN` (`SCAN_ON_PUSH` alone fails, because a CVE published after the push is not reported; a missing repository record is `N/A`), so a `MANUAL` repository or an expired image is named. An image with no resolved digest, an image from another account, or an unread image coverage list is named in the `N/A` row. An unread coverage list makes the `Passed` row `N/A`. The rows name each `ENABLED` EventBridge rule on the default bus whose pattern matches source `aws.inspector2` (`events:ListRules`), or say none does, and name each such rule's targets from `events:ListTargetsByRule`: a rule with no target is said to reach nothing, and a target list that could not be read is named. No API records whether a deployment pipeline blocks on a finding, so the row states that ceiling. No in-scope Lambda functions, access denied, and region-unavailable states resolve to `N/A`.
- **Container workload rows:** `Bedrock Container Workload Image Scanning` reads every running ECS task in every cluster (`ecs:ListTasks`, `ecs:DescribeTasks`; the overridden task role before the task definition's, and for a task with neither on an EC2 container instance, the instance profile role of that instance through `ecs:DescribeContainerInstances`, `ec2:DescribeInstances` and `iam:GetInstanceProfile`) and every SageMaker endpoint variant and inference component (`DeployedImages` and `DeployedImage.ResolvedImage`, with the model's `ExecutionRoleArn`), and keeps those whose role the IAM cache shows granted a Bedrock or AgentCore action. Each container image digest is judged the same way as a container-image function: an `ACTIVE` coverage record for that digest in a repository with `CONTINUOUS_SCAN`. An image outside a private Amazon ECR registry fails, because Inspector does not scan it. An image from another account or another Region's registry, a role the cache does not hold, an unread container instance, or any unread list is `N/A`. EKS pods are not read, because the EKS API returns no pod image.

### BR-34: Guardrail Prompt Attack Filter

- **Severity:** High
- **Description:** Requires each guardrail to have a preventive `PROMPT_ATTACK` input filter with `inputEnabled=true`, `inputAction=BLOCK` and `inputStrength` `LOW`, `MEDIUM` or `HIGH` on the STANDARD content-filter tier. The row names the strength it found, because no API records whether that strength was tuned against production traffic. A CLASSIC tier fails because prompt-leakage detection is STANDARD only, and a tier `GetGuardrail` does not report is `N/A`. The same judgment runs on each deployed guardrail version: every version an agent (DRAFT and each version an alias routes to), a flow Prompt or KnowledgeBase node (DRAFT and each alias-routed version) an account-enforced configuration, the effective Organizations Bedrock policy configuration for the Region, or a `bedrock:GuardrailIdentifier` condition on an invoke action applies is read with `GetGuardrail` at that version, including a guardrail ARN in another Region. Condition values are read from role, user and group policies and permissions boundaries in the IAM permissions cache and, in a member account, from service control policies attached to the root, an OU in the account's path or the account. A condition that names a guardrail without a version joins every version `ListGuardrails` returns plus DRAFT, a value in another Region is left to that Region's run, and a wildcard value is reported as not enumerated. A version that could not be read, an agent, flow or enforced-configuration list that could not be read, a wildcard condition value, a principal the IAM cache recorded an error for, a version 1 cache (which recorded no principal errors) or an unavailable cache keeps the deployed `Passed` row at `N/A`. A guardrail passed per request to InvokeModel, Converse, ApplyGuardrail or RetrieveAndGenerate is recorded by no configuration API, so the deployed rows do not judge it, and neither is guardContent tagging judged there. The CloudTrail management event of an InvokeModel, InvokeModelWithResponseStream or Converse call names that guardrail and version in `requestParameters`, and the `Guardrail Prompt Attack Invocation Evidence` row reads and judges each version so named for the calls logged in the last 24 hours. The Knowledge Base Ingestion Prompt Attack Screening rows fail a knowledge base that ingests a source with no transformation step and is reached through an agent version or flow node, whatever guardrail it applies: those retrieve through managed retrieval, which builds the prompt itself and cannot wrap the retrieved chunks in `guardContent` tags, so a `PROMPT_ATTACK` filter on that path does not evaluate them. For each knowledge base, every data source is read with `GetDataSource` for a `POST_CHUNKING` transformation Lambda, and every agent version (DRAFT and each alias-routed version, through `ListAgentKnowledgeBases`, skipping `DISABLED` links) and flow KnowledgeBase node (DRAFT and each alias-routed version) that retrieves from it is listed. It never passes a knowledge base: a transformation Lambda's logic is not read, a knowledge base carries no guardrail of its own, and a direct RetrieveAndGenerate caller supplies its guardrail per request, so a knowledge base with a screening step is `N/A` and named as not failed. An account-enforced guardrail whose `PROMPT_ATTACK` input filter blocks (the deployed-version test above, with an unreported tier credited) clears every knowledge base only when the configuration applies to every model and every message: a configuration whose `includedModels` does not name `ALL`, that excludes models, that guards system or message content `SELECTIVE`, or that sets `inputTags` `HONOR` is named as not credited. An agent or flow list, guardrail or enforced-configuration read that failed turns a would-be `Failed` into `N/A` naming what was not read. The Guardrail Intervention Logging row reads `GetModelInvocationLoggingConfiguration` in each Region: it fails when invocation logging has no S3 or CloudWatch Logs destination, or when `textDataDeliveryEnabled` is not `true`, because the text output body (a Converse `stopReason` of `guardrail_intervened`) is the record of an intervention. An absent flag or an unread configuration is `N/A`. A `Passed` row does not say that any call carried a guardrail, and only calls through the `bedrock-runtime` endpoint are logged.
- **Invocation evidence row:** `Guardrail Prompt Attack Invocation Evidence` reads the last 24 hours of the CloudWatch Logs invocation log records with `logs:FilterLogEvents` (25 per page, at most 10 pages per pattern), or, for an S3-only destination, at most 40 record objects from the UTC hour folders under `<keyPrefix>/AWSLogs/<account>/BedrockModelInvocationLogs/<region>/` with `s3:GetObject`, each object once for all three record legs, skipping the `data/` large-data bodies. A capped read names the time from which matching records were not all read. It fails each `InvokeModel` or `InvokeModelWithResponseStream` call whose response carries `amazon-bedrock-guardrailAction` and whose request body does not wrap input in both the opening and closing `amazon-bedrock-guardrails-guardContent_<tagSuffix>` tag for the `tagSuffix` its `amazon-bedrock-guardrailConfig` names, because the prompt attack filter does not evaluate untagged input on those operations. A body that uses the tag name but names no `tagSuffix` is `N/A`. It fails each `Converse` or `ConverseStream` call counted as guarded whose latest user message carries no `guardContent` block, and each one whose latest user message does but an earlier user message carries a `text` block with no `guardContent` block, because once any `guardContent` block is present the guardrail evaluates only those blocks (a user message holding only `toolResult` blocks is skipped, also when it is the latest, because `guardContent` cannot wrap a tool result, and the row counts those turns as not judged); a Converse call counts as guarded when its response carries a guardrail trace or `stopReason` `guardrail_intervened`, or else when its CloudTrail event, joined by `requestId` through BR-27's shared `cloudtrail:LookupEvents` streams and page budget, names a `requestParameters.guardrailConfig`, because the logged request never names it. A call with no event, an unread event or a capped join withholds the pass; one logged in the last 15 minutes with no event yet is counted and not judged. Each guarded InvokeModel, InvokeModelWithResponseStream and Converse call is joined the same way, and each guardrail version its event's `requestParameters` name is read once with `GetGuardrail` and fails without a `PROMPT_ATTACK` input filter that is enabled, blocks and is set to `LOW`, `MEDIUM` or `HIGH` on the `STANDARD` tier; an unread version or event withholds the pass, and a call whose event names no guardrail, as with an account-enforced guardrail, is named and left to the deployed rows. It passes when a `PROMPT_ATTACK` filter entry with action `BLOCKED` was logged and every guarded call read marked its input. Each row says per-turn `InvokeGuardrailChecks` calls are not judged, because CloudTrail does not record them as management events. No catch, a request body that is not inline, a capped or failed read, or text delivery off is `N/A`. Only request IDs, operations and model IDs are reported.
- **GuardDuty row:** `GuardDuty AI Protection Prompt Injection Detection` lists every GuardDuty detector in the Region. It fails when there is none, or when the detector's `Status` is not `ENABLED` or its `Features` do not list `AI_PROTECTION` as `ENABLED`, because that feature raises `Impact:IAMUser/PromptInjection.Direct`. Otherwise it reads every `ListFindings` page for unarchived findings whose `service.action.awsApiCallAction.serviceName` is `bedrock.amazonaws.com`, reads them with `GetFindings` in batches of 50, and passes, counting them by type and naming the three newest prompt injection findings with their API, severity and update time as the example flagged events. A detector, detector list or finding read that failed is `N/A`. Which Bedrock APIs AI Protection analyzes is not judged.

### BR-35: Guardrail Image Content Filter Coverage

- **Severity:** Informational
- **Description:** Uses `HATE`, `INSULTS`, `SEXUAL`, and `VIOLENCE` as the cross-region image-filter baseline. Because AWS documents `MISCONDUCT` image filtering as region-dependent, its absence is not reported as a gap, but a configured `MISCONDUCT` filter is reported when its input or output modalities omit `IMAGE`. Complete coverage is `Passed`; advisory gaps are `N/A`/Informational because the scanner cannot infer whether protected applications accept or produce images.

### BR-36: Application Inference Profile Governance

- **Severity:** Low
- **Description:** Lists application inference profiles and reports completely untagged profiles. Organization-specific required tag keys can be enforced outside the default baseline.

### BR-37: Bedrock Account Data Retention

- **Severity:** High for the regional mode, Medium for the service control policy
- **Description:** Passes the regional `GetAccountDataRetention` mode only when it is `none`; `default`, `inherit`, `aws_review` and `provider_data_share` fail. A second, organization-wide row passes only when attached service control policies Deny `bedrock:PutAccountDataRetention` on `StringNotEquals bedrock:DataRetentionMode` and `bedrock-mantle:PutAccountDataRetention`, `CreateProject` and `UpdateProject` on `StringNotEquals bedrock-mantle:DataRetentionMode`, each with `none` as the only approved value. The `Bedrock Mantle Project Data Retention` rows read the bedrock-mantle scopes over HTTPS, SigV4-signed as `bedrock-mantle`, because botocore has no client for that endpoint: the mantle account mode (`bedrock-mantle:GetAccountDataRetention`, `GET /v1/data_retention`) and every page of projects (`bedrock-mantle:ListProjects`, `GET /v1/organization/projects`, paged with `after`). Each project's effective mode is its own value unless `inherit`, then the mantle account value unless `inherit`, and otherwise each model's default. Only `none` passes. A project left on the model default is judged on every page of models (`bedrock-mantle:ListModels`, `GET /v1/models`): it fails when any listed model has no `none` in `data_retention.allowed_modes`, naming up to 10 of them, passes when every listed model has `none`, and is `N/A` when the models are not read, none is listed, or no model fails but one carries no `allowed_modes`. The mantle account mode is a separate setting from the control-plane mode and has its own `Bedrock Mantle Account Data Retention` row: only `none` passes, and an unread mode is `N/A`. An unread project list or a failed connection is one `N/A` row, an unread or unknown mantle account mode makes each inheriting project `N/A`, and an unknown project mode is `N/A`. The `RequireBedrockZeroDataRetention` parameter is no longer read.

### BR-38: Automated Reasoning Policy CMK Encryption

- **Severity:** Medium
- **Description:** Deduplicates Automated Reasoning policy summaries and judges each policy's `kmsKeyArn` with `kms:DescribeKey`: no key fails, a key that is not customer managed and Enabled fails, and a key that cannot be described is `N/A`.

### BR-39: Marketplace Model Endpoint VPC Configuration

- **Severity:** High
- **Description:** Requires SageMaker-backed Bedrock Marketplace endpoint configurations to include non-empty VPC subnet and security-group lists. It also resolves the effective route table of each named subnet (its explicit association, else the VPC main table) and fails a subnet whose table routes to an internet gateway. A named subnet that is not present in the Region is reported `N/A` by id, and the other subnets are still judged. Every named subnet is described, 50 per `DescribeSubnets` request; there is no cap on how many are resolved. A second finding, `Bedrock Job VPC Configuration`, reads every model customization job (`bedrock:ListModelCustomizationJobs`, then `bedrock:GetModelCustomizationJob` for its `vpcConfig`) and every batch inference job (`bedrock:ListModelInvocationJobs`, whose summaries carry `vpcConfig`), whatever the job's status. A job with no `vpcConfig` or no subnets fails, and a job whose subnet routes to an internet gateway fails, resolved the same way as the endpoint subnets. A list or describe call that fails, or a subnet that is not resolved, is named in an `N/A` row and the `Passed` row becomes `N/A`.

### BR-40: Marketplace Model Endpoint CMK Encryption

- **Severity:** Medium by default
- **Description:** Resolves the Marketplace endpoint `kmsEncryptionKey` with `kms:DescribeKey` and requires `KeyMetadata.KeyManager` to be `CUSTOMER`; AWS-managed keys do not pass. The `RequireMarketplaceEndpointCMK` deployment parameter defaults to `true` (`REQUIRE_MARKETPLACE_ENDPOINT_CMK` in the Lambda). Set it to `false` to make a missing or AWS-managed key an `N/A`/Informational hardening advisory rather than a failure. An inconclusive KMS lookup is always `N/A`/Informational.

### BR-41: Central Guardrail Enforcement

- **Severity:** High
- **Description:** Requires a published guardrail to apply to every model the account can invoke. Three independent legs satisfy it: an account-enforced guardrail configuration whose model and content scope covers all models, an attached Organizations Bedrock policy naming a non-`DRAFT` guardrail version, or a service control policy denying invocation unless an approved `bedrock:GuardrailIdentifier` is supplied. `ListEnforcedGuardrailsConfiguration` is the leg that runs from any account, and its `owner` field enumerates `ACCOUNT` alone, so a configuration inherited from an Organizations policy never appears in it; an unreadable organization view therefore produces `N/A` instead of being reported as an absence. BR-15 reads the same API but decides on how many configurations exist, while this check reads the model and content scope inside each one. A configuration with `inputTags` `HONOR` fails, since a caller choosing input tags chooses which content is evaluated. The Organizations leg reads each configuration under `bedrock.guardrail_inference.<region>` of the effective policy, credits it only in its own Region, fails a `DRAFT` or missing version, and fails a configuration whose `model_enforcement` names models or excludes any, or whose `selective_content_guarding` is `SELECTIVE`; an empty `included_models` covers all models. A policy that names a guardrail outside that layout is `N/A`. Each Bedrock policy listed in the organization is first matched against the account's path (`organizations:ListParents`): one attached nowhere on it, including one attached to no target, does not apply to the account and is named in one Informational `N/A` row; it is judged as a finding only when it is on the path, or when the path was not read. The service control policy leg is judged per Region and credits a Deny only when its `Resource` covers every invoke resource type, so a Deny on `foundation-model/*` alone fails. When the Bedrock policy is the only mechanism in a Region and whether members can apply its guardrail was not read, the enforcement row is `N/A`. A service control policy never restricts the management account, so run there an attached guardrail `Deny` fails and the row names the account. Each account-enforced and effective-policy guardrail version is read with `GetGuardrail`: a version carrying Automated Reasoning policies fails, because enforcement does not apply them and enforced invocations then fail at runtime, and an unread version keeps its Region at `N/A`. A guardrail resource policy that shares the guardrail only with named accounts, with no `aws:PrincipalOrgID` or `aws:PrincipalOrgPaths` condition, fails, because member accounts it does not name cannot apply the guardrail.

### BR-42: Foundation Model Invocation Allow-List

- **Severity:** High
- **Description:** Requires identity policies to scope `bedrock:InvokeModel` and `bedrock:InvokeModelWithResponseStream` to named foundation model or inference-profile ARNs. Only Allow statements that cover an invoke action are judged, so a policy that never grants invocation is not counted against this control. An unscoped resource with no `bedrock:ModelArn` condition fails, because the models it matches can then be invoked without being named; the finding says every model available in the account can be invoked only when the unscoped resources match every model resource type. A `Resource` that can match no ARN of a model resource type, such as `agent-alias/*` or `knowledge-base/*`, grants no model and is not counted; neither is `async-invoke/*` or `system-tool/*`, nor `project/*` for the streaming action, which names no project type. `bedrock-mantle:CreateInference` is counted only on a `Resource` that can match a bedrock-mantle `project`, its one resource type. An `Allow` whose `NotResource` matches every ARN, in any Region and account, of each model resource type the action can reach, such as `arn:aws:bedrock:*`, grants no model and is not counted; a `NotResource` that leaves any such ARN, such as `arn:aws:bedrock:us-east-1:*`, is counted. The same test against `project` ARNs applies to `bedrock-mantle:CreateInference`. An unscoped resource carrying a `bedrock:ModelArn` condition also fails for the streaming action, which does not support that condition key. A resource is unscoped when it is `*`, ends in `/*` or `:*`, or is a Bedrock ARN pattern whose resource segment ends in `*` and matches `foundation-model/` or `inference-profile/` followed by any model ID, such as `arn:aws:bedrock:*::foundation-model*` or `arn:aws:bedrock:::foundation-model/?*`, in any Region, account or partition. A family pattern such as `foundation-model/anthropic.*` is not unscoped. An identity `Deny` outside a named model list scopes the grant only when every list value names one model or profile ID with no wildcard and the statement carries no other condition key. A list written as a negated condition counts only on `bedrock:ModelArn` or `bedrock:InferenceProfileArn` and only when the statement's `Resource` is `*` or a Bedrock pattern matching every model. The bucket policy of each training data bucket of a model customization or SageMaker training job is read with `s3:GetBucketPolicy`: an `Allow` of `s3:GetObject` on the bucket's objects to `*` or through `NotPrincipal`, with no condition, fails. One with a condition passes only when a positive `StringEquals`, `StringLike`, `ArnEquals` or `ArnLike` test (no `IfExists`, no `ForAllValues:`) on `aws:PrincipalAccount`, `aws:SourceAccount`, `aws:PrincipalOrgID`, `aws:PrincipalArn` or `aws:SourceArn` names only this account or an exact organization ID; a test that also names another account, a wildcard account, or a condition on other keys only, such as `aws:SourceVpce`, fails. A grant to a principal of another account fails too, because that account's own IAM policies then decide who reads the data; this account's ID comes from `sts:GetCallerIdentity`. An unread policy or account ID turns the `Passed` row into `N/A`.

### BR-43: Region Invocation Control

- **Severity:** Medium
- **Description:** Reads two halves of cross-Region invocation, because neither answers the other. Service control policies conditioned on `aws:RequestedRegion` bound the Region a request is sent to, and the inference profiles the account can route through determine where the inference is then served. A global profile call presents the literal `unspecified` for that condition key, so a Region allow-list bounds a global profile only when it excludes `unspecified`. A direct invocation bounded by an SCP alongside an unbounded global profile is reported as a failure, and so is an allow-list that omits a destination Region of a geographic profile listed in an assessed Region. When a profile routes outside the allow-list, the row names which such profiles a call named as `requestParameters.modelId` (an inference profile ARN is reduced to its ID) in the last 24 hours of `InvokeModel`, `InvokeModelWithResponseStream`, `Converse` and `ConverseStream` event history in every assessed Region, read to the BR-56 page cap. The verdict still covers every available profile, because a profile no call named in that window can be called later; event history not read in full is named. A second, organization-wide finding, `Bedrock Approved Model Control`, requires a service control policy `Deny` on `bedrock:InvokeModel` and `bedrock:InvokeModelWithResponseStream` outside a named list of foundation-model or inference-profile ARNs, written either as `NotResource` or as a negated condition on `bedrock:ModelArn` or `bedrock:InferenceProfileArn` over a `Resource` of `*` or a Bedrock pattern matching every model. It also requires a `Deny` on `bedrock-mantle:CreateInference` with `Resource` `*` and a `StringNotEquals` or `StringNotLike` test on `bedrock-mantle:Model` naming models without wildcards and no other condition key, because that action authorizes against a project ARN and names the model only in that key. A `Deny` written with `NotAction` covers every action it does not name. The Region leg covers every action that sends a prompt to a model: `InvokeModel`, `InvokeModelWithResponseStream`, `CreateModelInvocationJob`, `InvokeAgent`, `InvokeInlineAgent`, `InvokeFlow`, `RetrieveAndGenerate`, `bedrock-agentcore:InvokeAgentRuntime` and `bedrock-mantle:CreateInference`, and a list missing any of them fails and names it. Each of `bedrock`, `bedrock-agentcore` and `bedrock-mantle` is also read through a probe action whose name no action contains, so only a `Deny` covering the whole prefix (`bedrock:*`, or a `NotAction` that leaves the service out) covers it, and a `Deny` naming only those nine actions, or families such as `bedrock:Invoke*`, fails and names the prefix as `bedrock:*`. The `AI Service Region Control` row requires the same allow-list over SageMaker endpoint, notebook, training, processing, transform and invocation, Bedrock knowledge base and customization job creation, AgentCore memory creation, and S3 bucket, S3 Vectors bucket and OpenSearch Serverless collection creation, and probes the whole `sagemaker`, `bedrock`, `bedrock-agentcore`, `s3`, `s3vectors`, `aoss`, `es`, `rds`, `neptune-graph` and `kendra` prefixes the same way, the last four because a knowledge base can write to those vector stores. An `aws:PrincipalArn` exemption is credited only when its role or user name segment has no wildcard; a wildcard partition or account segment is tolerated because an SCP governs this account's principals only. An allow-list value matching every Region, such as `*-*`, is no list. A `NotResource` on the Region `Deny` narrows it only when a value names the service of a covered action. When the allow-list would pass but `ListInferenceProfiles` failed in a Region, the row is `N/A` naming `bedrock:ListInferenceProfiles`. A list written as a wildcard over every model counts as no list. A list is not credited, and is named as `Not credited` in the text, when any value has a wildcard in the model or profile ID (the Region and account segments may be wildcards, because an SCP spans accounts) or when the statement requires a second condition key, since it then denies only the requests that meet that test too, and a list that covers only one of the two actions fails because the other can invoke any model. Which models belong on the list is the customer's decision and is not judged. Batch inference jobs are not read. An unreadable organization view is `N/A`. A service control policy never restricts the management account, so run there a Region allow-list, an approved model list or the AI service Region deny that would pass fails at Medium and names the account. The `Bedrock Custom Model Cross-Account Access` row reads the resource policy of every custom model the account owns: an Allow to `*`, to a principal with a wildcard account, or through `NotPrincipal`, with no `aws:PrincipalOrgID` or `aws:PrincipalOrgPaths` value that limits it to this account's organization (`organizations:DescribeOrganization`), fails. A share to named accounts or to the organization passes at Medium, an unread policy or organization id is `N/A`, and an account that owns no custom model is `N/A`.

### BR-44: Marketplace Model Subscription Control

- **Severity:** High
- **Description:** Requires an `aws-marketplace:ProductId` condition to restrict `aws-marketplace:Subscribe` to approved products. An Allow statement granting the action with no product condition fails. A Deny that names approved products positively is reported as failing open, because a product the statement does not name is not denied; only an Allow carrying the product condition, or a Deny with a negated or `Null` test, restricts the set of subscribable models. A `Deny` with `ForAnyValue:StringNotEquals` is false when the product key is absent, so it is credited only beside a `Deny` on the same action whose one condition is `Null` `true` on `aws-marketplace:ProductId`. A `Deny` on the action over `Resource` `*` with no condition, in an identity policy or a service control policy, removes the grant for that action only. The service authorization reference declares `aws-marketplace:ProductId` only on `AcceptAgreementRequest` and `CreateAgreementRequest`, but the Bedrock user guide (model-access) says the key restricts `aws-marketplace:Subscribe`, so a product test on `Subscribe` is credited. The same page says "Denying aws-marketplace:Subscribe alone will not block the first model invocation, because Amazon Bedrock auto-initiates the subscription in the background." So every row that would pass, including the row for no cached subscription grant, passes only when BR-42 also blocks unapproved models at invocation: its identity leg finds no cached role or user that can invoke a model outside named ARNs, or its organization leg has only `Passed` rows. Without that block the row fails at High, quotes the user guide and names the identities that can invoke a model outside named ARNs, and says what the organization leg found: no attached model list, a list covering only some invoke actions, or a list in the management account, which service control policies never restrict. A list covering only some invoke actions beside an attached service control policy that was not read names the other actions as not found in the policies read, with the unread count, and the row is `N/A`, not `Failed`, outside the management account. An unbounded `Subscribe` or `Unsubscribe` grant is `N/A`, not `Failed`, while an attached service control policy is unread, except in the management account. A BR-42 leg that was not read, or an organization leg with an `N/A` row, makes the row `N/A`. `aws-marketplace:ViewSubscriptions` is not judged: it lists subscriptions and grants no model.

### BR-45: API Key Governance

- **Severity:** High
- **Description:** Two findings. `Bedrock API Key Inventory` lists the `bedrock.amazonaws.com` service-specific credentials in the account. An active long-term key whose lifetime is inside the 90-day cap is still a static credential on a standing IAM user, so its row is a Medium `Failed`. `Bedrock API Key Age And Token Type Control` passes only when both legs hold: a cap of 90 days on `iam:ServiceSpecificCredentialAgeDays` for `iam:CreateServiceSpecificCredential`, either a `Deny` or an `Allow` with `NumericLessThanEquals` (credited only when every `Allow` that grants the action carries it), and a `Deny` on the `LONG_TERM` bearer token type on both `bedrock:CallWithBearerToken` and `bedrock-mantle:CallWithBearerToken`, each with its own key. Either leg alone fails and names the missing one. A plain `NumericGreaterThan` cap is credited only beside a separate `Deny` with `Null` `true` on the age key; the two tests in one statement are ANDed and match only a credential with no expiry, so that statement caps nothing. The age cap is read from service control policies and, failing that, from the identity policies and permissions boundary of every cached principal granted `iam:CreateServiceSpecificCredential`; the identity-policy cap is credited only when every such principal carries one, and the text says it binds those principals only. No cached principal holding the grant is not a cap. Cache `principal_errors` make an uncredited age leg `N/A`. The token leg is read from service control policies and, failing that, from the identity policies and permissions boundary of each IAM user holding an active key, because a long-term key signs requests as its user; it is credited only when every such user carries the `Deny` on both actions, and the text says it binds those users only. No user holding an active key is not a token `Deny`. A failed token leg names the key holders without one. Each endpoint of each holder counts as held by an attached service control policy `Deny`, the holder's own `Deny`, or no grant of that action to the holder, so a policy `Deny` on one endpoint and a holder's own on the other together hold the holder, and a holder granted neither action is not named. The `Passed` row names a service control policy statement as a `LONG_TERM` token `Deny` only when it denies the token type, calls an age-only statement an age cap, and splits the holders into those held by a `Deny`, by no grant, or by a `Deny` on one endpoint and no grant of the other. A key holder the permissions cache did not read, or a holder list taken from the cache because the account-wide listing was refused, makes an uncredited token leg `N/A`. An unreadable organization view produces `N/A`.

### BR-46: Knowledge Base Source Data Classification

- **Severity:** High
- **Description:** Requires every S3 bucket an AI data path reads to be classified by a recurring, full-depth Amazon Macie classification job. The population is every knowledge base S3 data source (with its `inclusionPrefixes`) the training, validation and invocation-log source buckets of every model customization job, and the `InputDataConfig` channel buckets of every SageMaker training job (`Search` with `Resource` `TrainingJob`, which returns each job's full description, 100 to a page, with no cap); customization and training output buckets are excluded. Every knowledge base, data source and customization job is read with no cap. For each source bucket the check describes (`DescribeClassificationJob`, once per job) every job whose `bucketDefinitions` name the bucket and the job in the bucket's `DescribeBuckets` `jobDetails.lastJobId`. A job clears the source only when `jobType` is `SCHEDULED`, `jobStatus` is `RUNNING` or `IDLE`, `lastRunErrorStatus.code` is not `ERROR`, `statistics.numberOfRuns` is at least 1, `initialRun` is true, `samplingPercentage` is 100, its data identifiers are not empty (`managedDataIdentifierSelector` `NONE`, or `INCLUDE` with no managed ids, and no custom ids), every include condition is an `OBJECT_KEY` `STARTS_WITH` term that covers the source prefix, and no `OBJECT_KEY` `STARTS_WITH` exclude overlaps it. An exclude condition on extension, size, date or tag makes the source `N/A`, because it is not compared with what the source ingests. The job's `createdAt` is compared with when the source was first read: the earliest `startedAt` over every page of `ListIngestionJobs` for a knowledge base data source, or the `creationTime` of the customization job or `CreationTime` of the SageMaker training job. A reader that started before the job was created fails. A missing `createdAt` when a reader started is `N/A`. An unread `ListIngestionJobs` is `N/A` naming `bedrock:ListIngestionJobs`. When the latest read of a source (the latest ingestion job, or the customization, training or batch job itself) started after the job's `lastRunTime`, the source is listed with `ListObjectsV2` (at most 100 pages, 100,000 objects, a source and 150 pages a region run) and each object's `LastModified` is compared with the two: an object written between the last run and that read fails, because it was read before any run classified it. An unlisted source, a listing past the cap, or an object with no `LastModified` is `N/A`. An object written before the last run is not ordered against each earlier read, because Macie returns only `lastRunTime`. Each knowledge base source that clears the job leg is then paired document by document with the `<document>.metadata.json` sidecar the knowledge base reads metadata from: a document with no sidecar, or a sidecar whose `metadataAttributes` is empty, fails at Medium, because the classification is not carried into per-document metadata. At most 300 sidecars a region run are read with `s3:GetObject`, across every source; a failed read or a sidecar past the budget is `N/A`, counting the unread sidecars and naming the first. A capped listing names the last key it read. Both budgets are measured in the code comment against the 600 s Lambda timeout, and a listing or sidecar read that reaches the invocation deadline, a fixed margin before that timeout, is `N/A` in the same way. Which attribute names the classification is not judged. The input locations of batch inference jobs (`ListModelInvocationJobs`) join the source population, and a failed or capped source read turns every `Passed` row into `N/A`. Automated sensitive data discovery samples objects, so a `MONITORED` bucket with no qualifying job fails, and the discovery status is reported in the Failed text. A qualifying job alone does not clear a source: the control asks for both Macie mechanisms, so automated sensitive data discovery must also be `ENABLED` (`macie2:GetAutomatedDiscoveryConfiguration`) and `DescribeBuckets` must report the bucket's `automatedDiscoveryMonitoringStatus` as `MONITORED`. A `NOT_MONITORED` bucket, or discovery that is off, fails in its own row; an unread discovery configuration or an absent monitoring status is `N/A`. `GetClassificationScope` is deliberately not used: its `s3` member is `excludes.bucketNames`, an exclusion list. A failed read is `N/A` and names what was not read: the Macie session, the bucket inventory, the job list, a job describe, a bucket `errorCode`, a bucket absent from the inventory, or a failed data source, customization job or SageMaker training job read. A bucket Macie reports `isMonitoredByJob` `TRUE` that no candidate job clears, while a job that selects buckets by criteria was not tied to it, is `N/A`. When Macie is not enabled in the Region, the check lists completed Amazon Comprehend PII detection jobs (`comprehend:ListPiiEntitiesDetectionJobs`, every page, either mode) and matches each job's `InputDataConfig.S3Uri` against the source bucket and prefix. A source that no completed job read in full fails, because nothing classifies it. A source a job read is `N/A` naming the job and its `EndTime`, and is not `Passed`, because a one-time job does not reach objects written after it ran. An unread job list makes the sources `N/A`. FS-44 asserts the two account-level Macie legs. Passed rows are published as `Knowledge Base Source Classification Job Coverage` and state which orderings were compared and that the attribute naming the classification is not judged. A `Prompt PII Screening` row judges each guardrail version evidenced on invocations (by an agent, a flow node, an account-enforced configuration, a guardrail condition pin, or a logged invocation joined to its CloudTrail event): a version that sets no PII entity type to `BLOCK` or `ANONYMIZE` on the input fails, and one that does passes. When no guardrail applies, the row fails at High only when the Region has a Bedrock footprint and invocation logging is not shown to be off. A Region with no footprint is Informational `N/A`, worded as indeterminate when the footprint probe was denied, and a Region whose invocation logging is off is Informational `N/A`, because a guardrail passed per request is then never seen.

### BR-47: Bedrock Data Path Bucket TLS Enforcement

- **Severity:** High
- **Description:** Reads the bucket policy of each S3 bucket on the Bedrock data path: knowledge base S3 data sources, the S3 destination of model invocation logging, the `cloudWatchConfig.largeDataDeliveryS3Config` bucket that holds payloads over 100 KB when logs go to CloudWatch Logs, and the training, validation, output and distillation invocation-log source (`trainingDataConfig.invocationLogsConfig.invocationLogSource`) buckets of every model customization job, the input and output buckets of every batch inference job (`ListModelInvocationJobs`), the training channel, output and model artifact buckets of every SageMaker training job (`Search` with `Resource` `TrainingJob`, no cap), the input and output buckets of every SageMaker transform job (`ListTransformJobs`) and processing job (`ListProcessingJobs`), each read from the trial component SageMaker records for it (`Search` with `Resource` `ExperimentTrialComponent` on `Source.SourceArn`) or, with none, from `DescribeTransformJob` or `DescribeProcessingJob` for the newest 200 such jobs of each kind, the data capture destination of every SageMaker endpoint with capture enabled and the asynchronous inference output and failure paths of its endpoint configuration (`ListEndpoints`, `DescribeEndpoint`, `DescribeEndpointConfig`), the dataset and output buckets of the newest 600 Bedrock evaluation jobs (`ListEvaluationJobs`, every page, then `GetEvaluationJob`, with each job past the 600th named in an `N/A` row; 600 reads take under 113 s at the slowest measured call, while the 5,000-job quota would exceed the function's 600 s timeout; a job whose read the invocation deadline stopped, a fixed margin before that timeout, is named the same way), the code artifact bucket of each AgentCore runtime version that is listed or that an endpoint serves as its live or target version (`ListAgentRuntimes`, `ListAgentRuntimeEndpoints`, `GetAgentRuntime`), and the recording bucket of each custom AgentCore browser with recording enabled (`ListBrowsers`, `GetBrowser`). A failed read of any of these is named with its action and makes the bucket list incomplete. A bucket named by several sources is read once. Each bucket is judged in its own row, which carries the bucket's own Region from `s3:GetBucketLocation` (no `LocationConstraint` is `us-east-1` and `EU` is `eu-west-1`) and text that does not depend on the assessed Region, so a bucket that resources in several Regions reference is reported once. When the location is not read, the row keeps the assessed Region and says so. One Informational `N/A` row per assessed Region names the resources in that Region that reference each bucket. A bucket passes only when one `Deny` statement, conditioned by `Bool` or `BoolIfExists` on `aws:SecureTransport` `false`, applies to principal `*`, covers `s3:*`, and names both the bucket and `bucket/*`. A `Deny` that falls short is reported with the principals, resources or actions it misses, and `NotPrincipal` or `NotAction` counts as falling short. A `Deny` whose `Condition` also tests a key other than `aws:SecureTransport`, such as `aws:SourceVpce` or an `aws:PrincipalArn` exemption for a role, is not credited, because a plaintext request that does not match that key is not denied. The one exception is `Bool` or `BoolIfExists` `aws:PrincipalIsAWSService` `false`, the form in the S3 TLS-only example policy: the Deny still reaches every IAM identity and anonymous caller, and the Passed text names the exemption. The same key tested as `true` is not credited. The exact exclusion that AIR-FND-DAT-02 prescribes when ingestion breaks is credited too: an `ArnNotEquals`, `ArnNotLike`, `StringNotEquals` or `StringNotLike` test on `aws:PrincipalArn`, or its `IfExists` form, with no `ForAnyValue:` or `ForAllValues:` prefix and every value an ARN with no wildcard or policy variable, or `Bool` or `BoolIfExists` `aws:ViaAWSService` `false`. The Passed row of a bucket with an exemption names each exempted ARN as keeping plaintext access to the bucket, and does not say every plaintext request is denied. A wildcard in any ARN segment, a set-operator prefix or any other narrowing key still fails. A bucket with no bucket policy fails, because S3 then accepts plaintext requests. Any other policy read error is informational `N/A`. Every data source and customization job is read with no cap. When the bucket list is incomplete through a failed read, the buckets that enforce TLS are reported as `N/A` and not as `Passed`, because a bucket that was never read may accept plaintext. Failed buckets are still reported `Failed`.

### BR-48: AI Services Opt-Out Policy Enforcement

- **Severity:** High
- **Description:** Reads `DescribeEffectivePolicy` for `AISERVICES_OPT_OUT_POLICY`. No effective policy, or the policy type not enabled, fails, because the account is then opted in to AI service data use. The policy type does not govern Amazon Bedrock, and every row says it does not establish how Bedrock handles content. `optOut` and `optIn` are compared exactly, so a value in another case is reported as unreadable and the default does not pass. An account outside an organization, or a denied read, is informational `N/A`. The effective document has its inheritance operators stripped, so an optOut default passes only when an opt-out policy attached to the root (the account's path is read with `ListParents` and each policy's attachments with `ListTargetsForPolicy`) assigns `optOut` and sets `@@operators_allowed_for_child_policies` to `["@@none"]` at all of `services`, `services.default` and `services.default.opt_out_policy` (AWS Example 1). A lock on the value alone still lets a child policy add a service section that opts back in (AWS Example 2), so it fails, as does an unset operator, which defaults to `@@all`. A locking policy that sets a child operator such as `@@assign` on a section below its lock, such as `services.lex`, fails and names the section, including a service section that sets the operator and no `opt_out_policy` of its own. A policy attached outside the path is not credited. A lock attached to an OU or to the account binds only the policies below it, so a policy attached to the root or an OU above it can still opt a service back in, and it fails. A member-account run, an unread path or an unread policy is `N/A` and names what was not read, and a root lock beside an unread policy is `N/A`, never `Passed`.

### BR-49: Guardrail Invocation Deny Enforcement

- **Severity:** High
- **Description:** For each IAM role and user allowed to invoke a model, requires a `Deny` on `bedrock:InvokeModel` and `bedrock:InvokeModelWithResponseStream`, on an unscoped `Resource` (as defined for [BR-42](#br-42-foundation-model-invocation-allow-list)), conditioned by a negated operator or by `Null` `true` on `bedrock:GuardrailIdentifier`, so a call without an approved guardrail is refused. Those two IAM actions also authorize `Converse` and `ConverseStream`, which have no IAM action of their own. BR-34 judges the guardrail content and BR-41 the account-level enforced guardrail configuration; this check covers identities whose calls neither of those reaches. Only role and user policies (attached and inline) are read. Group policies, permissions boundaries and service control policies are not read, so a `Deny` placed in one of them is not credited.

### BR-50: AI User Long-Term Access Key

- **Severity:** High
- **Description:** For each IAM user whose attached, inline or group policies allow any Bedrock, bedrock-mantle, SageMaker AI or AgentCore action, reads included, fails an `Active` access key and reports its age and last four characters. A user allowed only `bedrock:Get*` is in scope, since a long-term key that reads a model or a guardrail still reaches the service; a `NotAction` Allow that does not exclude the service puts the user in scope too. A user who can assume a cached role holding such an action is in scope as well: the role's trust policy, read with `iam:GetRole`, names the user, or trusts the account, `*` or `NotPrincipal` while the user's identity policies allow `sts:AssumeRole` on the role. The walk is transitive: a cached role whose trust policy admits another cached role the same way (naming it, or trusting the account or `*` while the other role's identity policies allow `sts:AssumeRole` on it) joins the path, and a user who can assume any role on it is in scope, with the row naming each hop. Trust conditions are not evaluated, and an unread trust policy is an `N/A` row naming the role. A permissions boundary that allows no such action takes the user out of scope. Inactive keys cannot sign a request and are not counted. Deny statements and service control policies are not evaluated. A user whose group policies or policy documents could not be read is reported `N/A`, never clean. Without the IAM permissions cache the check reports `N/A`. A second row, `Root User Access Key`, reads `iam:GetAccountSummary` and fails when `AccountAccessKeysPresent` is `1`, since a root access key signs any request; that summary does not say whether the key is active. `0` passes, and a denied call or any other value is `N/A`. This row needs no permissions cache and runs even when the cache is unavailable.

### BR-51: AI User Console MFA

- **Severity:** High
- **Description:** For the BR-50 user population, fails a user with a console password (`GetLoginProfile`) and no MFA device (`ListMFADevices`). A user without a console password is not failed. A user is skipped as held to MFA on its console password and its access keys alike only by a `Deny` on `Resource` `*` over every AI service it holds with `BoolIfExists` `aws:MultiFactorAuthPresent` `false`. A `Null` `true` test fires only when the key is absent, which is the access key case, and a console session carries the key as `false`, so that form, alone or ANDed with `BoolIfExists` in one statement, clears the user's active access keys but not a console password without an MFA device. A plain `Bool` `false` test does the reverse: a console session carries the key as `false` without MFA, so it holds the console password, but a long-term access key request carries no such key, so it leaves an active key open, and a user with both is failed on the access-key leg with the text naming its console session as held and the operator that holds it. Only IAM users are read: users signing in through IAM Identity Center are not covered, and every row says so. Each cached role granted an AI write fails when an Allow of `sts:AssumeRole` in its trust policy names an IAM user, an account or `*` with no `Bool` `aws:MultiFactorAuthPresent` `true` condition. A role principal it trusts without that condition is followed, through `iam:GetRole` and on to the roles that role trusts, and the AI role fails naming the chain when any role on it can be assumed by a user or an account without MFA, because a role session carries only the MFA of the session that assumed it. A role whose own policies, permissions boundary or attached service control policies carry a `Deny` on `Resource` `*` over every AI service it grants with `Bool` or `BoolIfExists` `aws:MultiFactorAuthPresent` `false` is held to MFA and listed, with the operator, on the `Passed` row instead, because a role session carries the key, as `false` when the role was assumed without MFA; while an attached service control policy is unread, a role no `Deny` holds is `N/A`. A role on the chain in another account, or one whose trust policy was not read, makes that role's row `N/A`. An `AWSReservedSSO_` or SAML role granted AI writes trusts a federated provider whose MFA no API returns, so it is named apart and keeps the row at `N/A`. The `Passed` row lists the Regions enabled for the account with `account:ListRegions` (every page, `ENABLED` and `ENABLED_BY_DEFAULT`) and lists IAM Identity Center instances with `sso:ListInstances` (every page) in each of them. An instance visible to the account makes that row `N/A`, "Partial, ceiling reached", naming the instance and its owner account, because no sso-admin operation returns an instance's MFA settings. The row also pages through each instance's permission sets (`sso:ListPermissionSets`) and reads each inline policy (`sso:GetInlinePolicyForPermissionSet`) and, through every page of `sso:ListManagedPoliciesInPermissionSet`, the default version of each attached AWS managed policy (`iam:GetPolicy`, `iam:GetPolicyVersion` on `arn:aws:iam::aws:policy/*`, each ARN read once), naming the permission sets whose inline or AWS managed policies grant an AI write, or saying none that was read does. An unread list or policy is named, and that permission set is neither failed nor credited, so the row stays `N/A`. Customer managed policy references (`sso:ListCustomerManagedPolicyReferencesInPermissionSet`) resolve to a policy of that name in each account the permission set is provisioned to, so they are named by path and name and not read, and a permission set that has one is not judged. A permission set whose inline or AWS managed policies grant an AI write fails in its own row, naming the policies that grant it, unless one of its policies carries a `Deny` on `Resource` `*` over every AI service it grants, with one `aws:PrincipalTag/<key>` test under `StringNotEquals`, `StringNotEqualsIgnoreCase` or `StringNotLike`; an `IfExists` form, a set operator or a second condition key is not credited, and a Deny that covers only some services leaves the others named. A Deny on `aws:MultiFactorAuthPresent` does not count, because the key is absent from federated sessions. Each instance's attributes for access control are read with `sso:DescribeInstanceAccessControlAttributeConfiguration`, and each guarded permission set names where its tag comes from: the attribute's configured source with the configuration status, or that the key is not a configured attribute, so any value comes only from the identity provider's SAML assertion, which is not read. Whether a source reflects MFA is not judged, and an unread configuration is named. An unlisted instance list in any Region is `N/A` naming the action and the Region. When the enabled Regions cannot be listed, only the primary scan Region is read and the row is `N/A`. When every enabled Region was read and none returns an instance, the IAM Identity Center leg does not hold back `Passed`. A denied read is `N/A`. Without the IAM permissions cache the check reports `N/A`.

### BR-52: Bedrock Data Path Bucket Object Lock

- **Severity:** Medium
- **Description:** For each S3 bucket on the Bedrock data path (the population BR-47 reads), requires Object Lock `Enabled` with a `COMPLIANCE`-mode default retention that states `Days` or `Years`. `GOVERNANCE` mode fails, because a principal with `s3:BypassGovernanceRetention` can delete or shorten the retention. A bucket with no Object Lock configuration fails; any other read error is `N/A`. A bucket without that lock passes when its newest `COMPLETED` or `AVAILABLE` AWS Backup recovery point (`ListRecoveryPointsByResource`) is in a vault whose Vault Lock (`DescribeBackupVault`) is in compliance mode past its `LockDate` grace period with a `MinRetentionDays` set. The minimum retention binds only backups made after the lock, so a newest recovery point created before the `LockDate` is read with `DescribeRecoveryPoint`: it clears the bucket only when its `CalculatedLifecycle.DeleteAt` is absent or at least `MinRetentionDays` after its creation, and an unread point never clears it. A vault lock with no `LockDate` is governance mode and fails, as do a grace period still running and a lock with no minimum retention. An unread recovery point list, recovery point or vault never clears a bucket: a bucket without the Object Lock whose backup was not read is `N/A`, not `Failed`. Both SAM templates grant `backup:ListRecoveryPointsByResource` and `backup:DescribeRecoveryPoint`, so a denial of either is named with a pointer to a service control policy, a permissions boundary, or an assessment deployment older than the grant. AWS Backup is read in the bucket's own Region, and that Region's locked vaults are listed with their mode as evidence. When the bucket list is incomplete, compliant buckets are reported `N/A` and not `Passed`. Rows follow the BR-47 Region rule: one row per bucket in the bucket's Region, and one Informational `N/A` row per assessed Region naming what references each bucket.

### BR-53: Bedrock Resource Owner Tag

- **Severity:** Low
- **Description:** Lists agents, knowledge bases, flows, prompts, guardrails, custom models, imported models, provisioned throughputs, application inference profiles, and batch inference, model customization and evaluation jobs, reads their tags through the Resource Groups Tagging API in batches of 100 ARNs (each job's tags through `bedrock:ListTagsForResource`, since whether `GetResources` returns Bedrock jobs is not documented), and fails each resource with no owner tag whose value names someone. An owner key is `owner` (any case) after any `:` or `/` namespace, alone or beside words that only say which owner it is or how to reach them (`BusinessOwner`, `owner-email`, `team:owner`). Any other word, as in `previous_owner` or `FormerOwner`, is not credited, and neither is an empty value or a placeholder such as `TBD`, `unknown` or `n/a`. Each rejected tag is named on the row. Whether a value resolves to a person or an on-call rotation is not verified, and no API marks a resource as production, so every listed resource is judged. `GetResources` omits an ARN that has no tags, so a missing ARN is reported as untagged. Failed rows are capped at 25 plus one overflow row. A tag read error is `N/A`; a list error is `N/A` and downgrades the `Passed` row. An empty inventory is `N/A`. The AI Resource Owner Tag Outside Bedrock rows page through `GetResources` with `ResourceTypeFilters` `sagemaker` and then `bedrock-agentcore`, apply the same owner-tag test, and fail each returned resource without one. `GetResources` returns only resources that are or were tagged. When a filter's `GetResources` read succeeds, every page of its list operations is compared with it by resource segment, without case: `sagemaker:ListEndpoints`, `ListModels`, `ListNotebookInstances`, `ListTrainingJobs`, `ListDomains`, `ListInferenceComponents`, `ListPipelines` and `ListProcessingJobs`, and `bedrock-agentcore:ListAgentRuntimes`, `ListMemories`, `ListGateways` (matched as `gateway/<id>`, since a gateway summary carries no ARN), `ListBrowsers` for custom browsers, `ListCodeInterpreters` for custom code interpreters and `ListWorkloadIdentities`. A listed resource that `GetResources` did not return fails as never tagged; an unlisted list is named on the summary row. Other resource types are read only through `GetResources`, so one never tagged is not seen. A summary row counts the owned resources, says which types are unlisted and why, cites the `GetResources` API reference, and names each read that failed. It is `Passed` only when both `GetResources` filters and all fourteen list reads succeeded, at least one resource was read and none lacks an owner, and its text then says that whether a value names a person and whether a resource is production are not judged; otherwise it is `N/A`.

### BR-54: Lambda Function Public Invoke Configuration

- **Severity:** High
- **Description:** Reads every Lambda function in the Region. A function URL with `AuthType` `NONE` fails, because it disables IAM authentication. The resource-based policy still decides whether the URL accepts requests, so the finding says the URL is invocable by unauthenticated callers only when the policy also grants public access, and otherwise says the policy grants no public access today and one permission granted to `*` would open it. A function URL whose CORS `AllowOrigins` holds a `*`, alone or inside a pattern, fails whatever its `AuthType`. A resource-based policy `Allow` to principal `*` covering `lambda:InvokeFunction` or `lambda:InvokeFunctionUrl` fails unless one condition test names a single source: `aws:SourceAccount` with 12-digit account IDs, `aws:PrincipalOrgID` with `o-` organization IDs, or `aws:SourceArn` with an ARN whose partition, service, Region and account segments and resource ID carry no wildcard and whose account is a 12-digit ID. Only `StringEquals`, `StringLike`, `ArnEquals` and `ArnLike` count; an `IfExists` form, a `ForAllValues:` prefix or a negated operator does not, and one wildcard value among several leaves the test open. An S3 source ARN names no account, so it needs `aws:SourceAccount` beside it. `lambda:FunctionUrlAuthType` and `lambda:InvokedViaFunctionUrl` describe how the function is called, not who calls it, so neither clears a `*` principal; this includes the public statement pair Lambda writes for a `NONE` URL. A public `lambda:InvokeFunctionUrl` statement on a function with no URL fails too, because deleting a URL leaves its statement in place. The unqualified policy and the policy of every alias (`ListAliases`) and published version (`ListVersionsByFunction`) are read, and a URL on an alias is judged against that alias's policy. The check makes no network reachability claim; every row says so. On the primary Region a `Global` row judges the attached service control policies: it passes when `Deny` statements on `Resource` `*` (or a function ARN pattern with wildcard Region, account and name) cover both `lambda:CreateFunctionUrlConfig` and `lambda:UpdateFunctionUrlConfig`, each with no condition or with only a `lambda:FunctionUrlAuthType` test that matches `NONE` (`StringEquals NONE`, `StringNotEquals AWS_IAM`, and their `IfExists` forms). A `Deny` also conditioned on another key is not credited. Unread policies make it `N/A`, and the management account, which service control policies do not restrict, fails it. Per-function read errors are aggregated into one `N/A` row. A Region with no functions is `N/A`.

### BR-55: KMS Key Enclave Attestation Binding

- **Severity:** High
- **Description:** For each customer-managed KMS key whose policy uses a `kms:RecipientAttestation:` condition, fails an `Allow` covering `kms:Decrypt`, `kms:DeriveSharedSecret`, `kms:GenerateDataKey`, `kms:GenerateDataKeyPair` or `kms:ReEncryptFrom` with no attestation pin (`ReEncrypt` carries no attestation, so it moves the plaintext under another key), unless a `Deny` to principal `*` with a negated or `Null` `true` test on an attestation key already refuses such calls. `kms:GenerateRandom` also honors attestation but takes no key, so no key policy grants it. A pin is an exact value on `ImageSha384`, any `PCR<ID>` or any `NitroTPMPCR<ID>`, under an operator that is not negated, not `Null` and not `...IfExists`, with no wildcard values and no all-zero value. A debug-mode enclave presents all-zero PCRs, so a pin on zeros is not a measurement, and an `Allow` whose only attestation test is of that kind is named as having no exact attestation measurement. `ImageSha384` corresponds to `PCR0`. The enclave image file is not secret, so an image pin alone is met by the same image launched from any parent instance: every statement that releases those operations on a Nitro Enclave binding needs both an exact image measurement (`ImageSha384`, `PCR0` or `PCR8`, the signing certificate) and an exact deployment value (`PCR3`, parent IAM role, or `PCR4`, parent instance ID), each in the statement itself or through a `Deny` to `*` with a negated exact test on it. A `PCR3`-only or `PCR8`-only pin fails. A `NitroTPMPCR<ID>` pin needs no enclave deployment PCR. Every row names the family that matched: Nitro Enclave for `ImageSha384` and `PCR<ID>`, NitroTPM for `NitroTPMPCR<ID>`. The default key-policy statement that delegates to IAM through the account root is reported as a bypass with its own text, and the key can pass only when that statement carries an attestation pin or a `Deny` covers every operation it opens. A `Deny` that tests only for a missing attestation (`Null` `true`, or a negated test on wildcard values) closes that path but does not by itself pin an image. A `Deny` under a positive operator, with or without `IfExists`, is not credited. Condition keys in one statement are ANDed, so a `Deny` that also tests a non-attestation key is not credited, and a `Deny` with two attestation tests only refuses a missing attestation and pins neither measurement. Each key's grants (`ListGrants`, every page) are read too: a grant of `Decrypt`, `DeriveSharedSecret`, `GenerateDataKey`, `GenerateDataKeyPair` or `ReEncryptFrom` carries no attestation condition, so it fails the key unless a key-policy `Deny` covers that operation. A key whose grants could not be read is `N/A`, never `Passed`. Each key's CloudTrail event history is read with `LookupEvents` by its ARN (the 90 days event history holds, at most 20 pages of 50): a `Decrypt`, `DeriveSharedSecret`, `GenerateDataKey` or `GenerateDataKeyPair` request whose `additionalEventData.recipient.attestationDocumentEnclaveImageDigest` is all zeros, hex or base64, fails the key, because an enclave run with `--debug-mode` or `--attach-console` presents every PCR as zeros. A history that could not be read, or has more than 20 pages, is `N/A`. Keys whose policy uses no attestation are summarized in one `N/A` row. AWS managed keys are skipped.

### BR-56: Bedrock LLM Jacking Activity

- **Severity:** High
- **Description:** Reproduces Prowler's `cloudtrail_threat_detection_llm_jacking`, which Prowler maps to its AISF-AI-06 "Bedrock API Audit Trail" requirement. Reads the Region's CloudTrail event history with `LookupEvents`, one event name at a time, over the last 24 hours, for Prowler's 14 actions: `PutUseCaseForModelAccess`, `PutFoundationModelEntitlement`, `PutModelInvocationLoggingConfiguration`, `CreateFoundationModelAgreement`, `InvokeModel`, `InvokeModelWithResponseStream`, `GetUseCaseForModelAccess`, `GetModelInvocationLoggingConfiguration`, `GetFoundationModelAvailability`, `ListFoundationModelAgreementOffers`, `ListFoundationModels`, `ListProvisionedModelThroughputs`, `SearchAgreements` and `AcceptAgreementRequest`. An identity, keyed by `userIdentity.arn` and `userIdentity.type`, fails when the share of those actions it called is above 0.4, which is 6 or more of the 14, and at least one of its calls is `PutUseCaseForModelAccess`, `PutFoundationModelEntitlement`, `PutModelInvocationLoggingConfiguration`, `CreateFoundationModelAgreement` or `AcceptAgreementRequest`, the actions that grant model access, accept an agreement or rewrite invocation logging. An identity above the share that only read and invoked is named in one informational `N/A` row, not failed, because a console user browsing model access reaches the share that way; when one of those five actions was not read in full, such an identity is held with the unread names instead. Events with no identity ARN are skipped as AWS service calls, as Prowler does. Event history holds management events only, whether or not a trail exists: it sees `InvokeModel` and `InvokeModelWithResponseStream`, and it cannot see `InvokeModelWithBidirectionalStream`, `StartAsyncInvoke`, `GetAsyncInvoke`, `InvokeAgent` or `InvokeInlineAgent`, which Bedrock logs as data events. `Converse` and `ConverseStream` are management events but are not in Prowler's list. Every `Passed` and `N/A` row states this. Four departures from Prowler: the write-action requirement above, and each event name is read up to 5 pages of 50 events, where Prowler reads one page; the Region under assessment is read, where Prowler reads only its trails' home Region and passes an account with no trail; and an event name that was cut off at the page limit, failed to read, or held an unparseable event is never passed over. Such a name is credited to every identity, and an identity that could then exceed the threshold is reported in one informational `N/A` row with the names that were not read in full. The `Passed` row names any such names when crediting them changes no verdict. When every lookup fails the check is informational `N/A` with the error code.

### BR-57: Agent Handoff Source Identity

- **Severity:** High
- **Description:** Fails an agent-to-agent handoff that carries no checked caller binding. The agent roles are the roles Bedrock agents run as (`GetAgent` for the working draft and `GetAgentVersion` for every version an alias routes to, `agentResourceRoleArn`) the roles AgentCore runtimes run as (`GetAgentRuntime` `roleArn` for the latest version and for the live and target version of every endpoint), and the execution role of every Lambda MicroVM in a `PENDING`, `RUNNING`, `SUSPENDING` or `SUSPENDED` state (`ListMicrovms`, then `GetMicrovm` `executionRoleArn`; the MicroVMs of one image count as one agent). A MicroVM whose `ingressNetworkConnectors` include the `SHELL_INGRESS` connector fails, because `CreateMicrovmShellAuthToken` works only on such a MicroVM; `lambda:ListMicrovms` is granted on `*`, which it requires, and `lambda:GetMicrovm` on the `microvm-image` ARNs of this account and of the AWS-managed `aws` account. Two legs are judged. First, for every supervisor version (`agentCollaboration` `SUPERVISOR` or `SUPERVISOR_ROUTER`), `ListAgentCollaborators` names each collaborator's alias, the alias routing is resolved to the collaborator's version roles, and a collaborator that runs as its supervisor's own role fails, because it acts with the supervisor's authority. Two collaborators of one supervisor that run as one role fail, as do two agents or runtimes that run as one role, because a handoff between them carries no distinct identity; versions of one agent may share a role. IAM roles are global, so when more than one Region is assessed the primary Region also reads every assessed Region's agent roles and fails a role run by agents in two Regions; an unread part of any Region's inventory withholds `Passed` and is named in an `N/A` row. Second, the trust policy of every role in the IAM permissions cache is read with `iam:GetRole`, and an `Allow` statement on `sts:AssumeRole` is an edge from an agent role when it names the agent role as a principal, or when it names the agent role's account or `*` (or uses `NotPrincipal`) and the agent role's own cached identity policy allows `sts:AssumeRole` on that role. A permissions boundary that allows `sts:AssumeRole` nowhere removes the edge. An edge passes only when the statement pins `sts:SourceIdentity` (or `aws:SourceIdentity`) with `StringEquals`, `StringEqualsIgnoreCase` or `StringLike` and no value holds a wildcard; an `IfExists` operator, a `ForAllValues:` prefix, a negated operator or a `Null` test does not pin it. Identity-policy `Deny` statements and service control policies are not evaluated per principal, which can only add an edge. A collaborator alias in another account or Region, an agent or runtime that failed to read, an agent role missing from the cache, a trust policy that failed to read, and a principal the cache recorded as unread each report an informational `N/A` row, and the `Passed` row becomes `N/A`. Runtimes are listed with `bedrock-agentcore:ListAgentRuntimes` and `bedrock-agentcore:ListAgentRuntimeEndpoints`, granted on `*` because neither has a resource type; a list that fails reports `N/A` naming the action. Third, each AgentCore runtime's inbound gate is read. A runtime version whose `authorizerConfiguration.customJWTAuthorizer` names no `allowedAudience`, `allowedClients`, `allowedScopes` or `customClaims` fails, because any token its issuer signs invokes it; an IAM-authorized runtime has no authorizer block and is judged by the trust edges above. `bedrock-agentcore:GetResourcePolicy` is read on the runtime ARN and every endpoint's `agentRuntimeEndpointArn`, and an `Allow` on any of the six `InvokeAgentRuntime*` actions fails when it reaches every principal (`*` or `NotPrincipal`) with no exact `aws:PrincipalAccount`, `aws:SourceAccount`, `aws:PrincipalArn`, `aws:SourceArn` or `aws:PrincipalOrgID` test limiting it to the runtime's account or an organization, or when it names another account's principals. `ResourceNotFoundException` means no policy, and any other failure to read one withholds `Passed`. Which organization an `aws:PrincipalOrgID` value names is not compared with the caller's own. Partial, ceiling reached: no AWS API marks which ECS task roles, Lambda function roles or other roles host an agent, a JWT authorizer names the tokens a runtime accepts and not which agent presented one, no `lambda-microvms` API lists issued MicroVM auth tokens or their `allowedPorts`, and a role in another account that trusts an agent role is not read.
- **Workload identity rows:** `Bedrock Agent Role Confused Deputy Condition` reads each Bedrock agent role (the `agentResourceRoleArn` of every DRAFT and alias-routed version) with `iam:GetRole`. A `bedrock.amazonaws.com` trust statement fails unless it carries a positive `aws:SourceAccount` test and a positive `aws:SourceArn` test, neither an `IfExists` form nor `ForAllValues:`, whose every value names the role's own account (a `SourceArn` with a wildcard before the resource ID fails). `Bedrock Agent Action Group Function Role` reads the Lambda function of every action group of those versions (`ListAgentActionGroups`, `GetAgentActionGroup`, `lambda:GetFunction`) and fails an execution role two or more of them run as. It also lists every Lambda function version in the Region (`lambda:ListFunctions` with `FunctionVersion` `ALL`) and fails an agent or action group role that a function outside every action group runs as; another version of an action group function is not counted as outside. Any unread agent, role or function makes the row `N/A`, never `Passed`.
- **Role scope row:** `Bedrock Agent Role Resource Scope` reads each Bedrock agent role, Lambda MicroVM execution role and action group function role from the IAM permissions cache. It fails a role whose attached or inline policy has an unconditioned `Allow` of any action on more than the resources it names (`*`, a pattern covering every model, `NotResource`, or a wildcard in the partition, service, account, Region outside Bedrock, resource type or resource name, including a path inside a name that may hold `/` such as `role/service-role/*`, `log-group:/aws/lambda/*` or `secret:prod/*`). A wildcard is credited only inside a sub-resource the service authorization reference publishes after a fully named parent, such as `table/orders/index/*`, `function:tool:*`, `agent-alias/AGENT/*` or `arn:aws:s3:::kb-docs/*`, read from `arn_sub_resources.json`, which `generate_arn_sub_resources.py` builds from the published ARN formats. A Secrets Manager `secret:name-??????` with no other wildcard matches the six-character suffix of the one secret named `name` and is scoped; `secret:name-*` widens. The role still passes when its permissions boundary denies the action or allows it only on named resources. A pinned list of 18 actions the service reference gives no resource type (such as `xray:PutTraceSegments`, `sts:GetCallerIdentity` and `ec2:DescribeNetworkInterfaces`) is exempt and named in the `Passed` row; a resourceless action outside that list is judged like any other. A `NotAction` Allow fails outright when the role has no permissions boundary, and under a boundary it is judged on `bedrock:InvokeModel`, `bedrock:InvokeModelWithResponseStream`, `bedrock:Retrieve`, `bedrock:InvokeAgent`, `s3:GetObject`, `s3:PutObject`, `dynamodb:GetItem`, `dynamodb:PutItem`, `secretsmanager:GetSecretValue`, `lambda:InvokeFunction` and `execute-api:Invoke`. A wide grant under a `Condition`, an action pattern under a boundary that does not allow it on every resource, a role missing from the cache or recorded with a policy read error, and an unread agent or function inventory are `N/A`. `Deny` statements and service control policies are not judged, so a `Failed` row may overstate the effective grant.

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
