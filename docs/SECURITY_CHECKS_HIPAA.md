# HIPAA/HITECH-Aligned Configuration Checks (7)

This document provides a complete reference for the seven optional **HP-XX** automated configuration checks (HP-01 through HP-07) aligned with selected HIPAA Security Rule and HITECH Act technical safeguards.

---

- **Reference:** [HIPAA Security Rule 45 CFR Part 164 Subpart C](https://www.hhs.gov/hipaa/for-professionals/security/index.html), [HITECH Act § 13401](https://www.gpo.gov/fdsys/pkg/PLAW-111publ5/html/PLAW-111publ5.htm)
- **Opt-in:** Set `EnableHIPAAAssessment=true` on the deployment stack. Default is `false`.
- **Report location:** New "By Compliance Standard" sidebar section, alongside OWASP Top 10 for LLM. HP findings appear only when the HIPAA Lambda is enabled.
- **No hidden source dependency:** Unlike OWASP (which ingests BR/SM/AC/FS source CSVs), HIPAA Lambda calls AWS APIs directly. Disabling every other assessment still yields HP-01..HP-07 findings when resources exist.
- **Independent of direct services:** HIPAA runs separately from the four Enable*Assessment service toggles; HP checks do not depend on BR/SM/AC/AR being enabled.

## Important Scope and Limitations

> **WARNING — REQUIRED DISCLAIMER:**
>
> These are **AUTOMATED CONFIGURATION CHECKS ONLY** applied to AI/ML-related AWS resources. They do **NOT**:
> * constitute a HIPAA compliance audit, assessment, or certification,
> * establish the presence or absence of electronic protected health information (ePHI) in any resource,
> * cover the Administrative Safeguards (164.308), Physical Safeguards (164.310), or Organizational/Policy requirements of the HIPAA Security Rule,
> * verify BAAs (Business Associate Agreements) between the covered entity and AWS or any subcontractor,
> * replace formal Risk Analysis required under 164.308(a)(1) or Risk Management under 164.308(a)(2).
>
> The **covered entity** remains solely responsible for full HIPAA/HITECH compliance, including all administrative, physical, technical, organizational, and documentation requirements.

### Relationship to enabled services

HIPAA checks are **independent of the four direct-service enablement switches** (`EnableBedrockAssessment`, `EnableSageMakerAssessment`, `EnableAgentCoreAssessment`, `EnableAgentRegistryAssessment`). Enabling `EnableHIPAAAssessment=true` always runs HP-01..HP-07 across every target region when AI/ML-shaped resources exist, regardless of which direct services are toggled. HIPAA has **no hidden source-data dependency** on Responsible AI GRC or any other assessment; unlike OWASP→FS, the HIPAA Lambda calls AWS APIs directly and does not read other CSVs.

### AI/ML resource scoping

To avoid flagging every resource in a large account, HP-05 and HP-07 are scoped to AI/ML-shaped resources:
* **HP-05 (CloudWatch Logs data protection)** inspects only log groups whose names match the `(bedrock|sagemaker|agent|agentcore|aiml|ml-|genai|model|inference|training)` prefixes.
* **HP-07 (S3 bucket encryption + versioning)** inspects only buckets whose names contain dataset/model/artifact/inference/training/bedrock/sagemaker/aiml/ml hints or whose tags contain relevant AI/ML keys.

All other checks iterate their full respective AI/ML service inventories.

### Check ID prefix

All HIPAA findings use the `HP-` prefix followed by a two-digit check number (`HP-01` .. `HP-07`).

---

## Severity rubric

HP findings follow the repository-wide [Severity Levels](SECURITY_CHECKS.md#severity-levels) rubric:

| Severity | When used in HP checks |
| --- | --- |
| **High** | Encryption at rest is absent or uses account-default AWS-managed keys without a CMK on a data-bearing AI/ML resource (custom model artifacts, SageMaker endpoint data, S3 ML buckets). Maps to 164.312(a)(2)(iv) / 164.312(e)(2)(ii). |
| **Medium** | Audit logging, VPC isolation, access-policy hardening, or content-policy guardrails are missing; network egress to public internet is not prohibited. Maps to 164.312(b) / 164.312(c) / 164.312(e)(1). |
| **Low** | Advisory-only conditions where a configuration hardening exists but lacks explicit opt-in enforcement (e.g., guardrails attached but not DENY-mode). |
| **Informational** | Per-check N/A (no resources found, regional feature unavailable, access denied), or aggregate "All resources compliant" summary rows. |

---

## Compliance Framework Citations

Findings surface relevant citations in the `Compliance_Frameworks` CSV column using pipe (`|`)-separated tags:

| Tag | Citation |
| --- | --- |
| `45 CFR 164.312(a)(2)(iv)` | Encryption and decryption (at rest) |
| `45 CFR 164.312(b)` | Audit controls |
| `45 CFR 164.312(c)(1)` | Integrity |
| `45 CFR 164.312(c)(2)` | Mechanism to authenticate ePHI |
| `45 CFR 164.312(d)` | Person or entity authentication |
| `45 CFR 164.312(e)(1)` | Transmission security (general) |
| `45 CFR 164.312(e)(2)(ii)` | Encryption (in transit) |
| `HITECH § 13401` | HITECH Security Rule enhancements |
| `HITECH § 13402` | HITECH Breach Notification enhancements |

---

## HP-01 — Bedrock Custom Models: CMK Encryption Enabled

| Property | Value |
| --- | --- |
| **Check ID** | `HP-01` |
| **What it does** | Verifies every imported or fine-tuned Amazon Bedrock custom model has `kmsKeyArn` configured (customer-managed KMS key for at-rest encryption of model artifacts and training data). |
| **Relevant services** | Amazon Bedrock `bedrock` client — `ListCustomModels` + `GetCustomModel` |
| **Citation(s)** | `45 CFR 164.312(a)(2)(iv)` \| `HITECH § 13401` |
| **Failure severity** | High for absent CMK; Informational/N/A for region unsupported / no custom models / access denied |
| **Remediation** | Re-create the custom model (import or fine-tuning job) with an explicit customer-managed KMS key specified in `kmsKeyId`/`kmsKeyArn`. Bedrock does not support post-hoc CMK rotation on existing custom models. |
| **Reference** | https://docs.aws.amazon.com/bedrock/latest/userguide/encryption-at-rest.html |

---

## HP-02 — Bedrock Guardrails: Content Filter Policies Attached in DENY Mode

| Property | Value |
| --- | --- |
| **Check ID** | `HP-02` |
| **What it does** | Verifies every Bedrock guardrail has all six content filter categories configured at strength >= `MEDIUM` and action set to `BLOCK` (DENY-mode). Detects guardrails that exist but are permissive (LOW/MEDIUM only, or FILTER-log-only). |
| **Relevant services** | Amazon Bedrock `bedrock` client — `ListGuardrails` + `GetGuardrail` |
| **Citation(s)** | `45 CFR 164.312(c)(1)` \| `45 CFR 164.312(e)(1)` \| `HITECH § 13401` |
| **Failure severity** | Medium for missing categories or permissive action; Low for BLOCK but strength < MEDIUM on PII/sexual categories; Informational/N/A otherwise |
| **Remediation** | Update the guardrail version to raise `contentPolicyConfig` filters to at least `MEDIUM` strength with `action=BLOCK` for every defined filter. Apply the updated version to all Bedrock aliases and agents that invoke the guardrail. |
| **Reference** | https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-configure-content-filters.html |

---

## HP-03 — SageMaker Endpoints: VPC Configured (No Public Internet Egress Default)

| Property | Value |
| --- | --- |
| **Check ID** | `HP-03` |
| **What it does** | Verifies every in-service SageMaker endpoint has a non-empty `VpcConfig` (SecurityGroupIds + Subnets) configured AND that `DirectInternetAccess=Disabled`. Detects endpoints deployed into the public SageMaker network with default internet egress, which bypasses VPC flow logging and perimeter controls. |
| **Relevant services** | Amazon SageMaker `sagemaker` client — `ListEndpoints(StatusEquals=InService)` + `DescribeEndpoint` + `DescribeEndpointConfig` |
| **Citation(s)** | `45 CFR 164.312(e)(1)` \| `45 CFR 164.312(e)(2)(ii)` \| `HITECH § 13401` |
| **Failure severity** | High for no VpcConfig; Medium for VpcConfig present but `DirectInternetAccess=Enabled`; Informational/N/A otherwise |
| **Remediation** | Create a new endpoint configuration that specifies `VpcConfig` with private-only subnets and `DirectInternetAccess=Disabled`. Add VPC Gateway/Interface Endpoints for `sagemaker.api`, `sagemaker.runtime`, `s3`, `kms`, `logs`, and `monitoring` before updating the endpoint to the new config. |
| **Reference** | https://docs.aws.amazon.com/sagemaker/latest/dg/infrastructure-give-access.html |

---

## HP-04 — SageMaker Training Jobs: Inter-Container Traffic Encryption + VPC + CMK Volume KMS

| Property | Value |
| --- | --- |
| **Check ID** | `HP-04` |
| **What it does** | Aggregate per-training-job check: verifies `EnableInterContainerTrafficEncryption=true`, non-empty `VpcConfig` with `EnableNetworkIsolation=true`, and an explicit `VolumeKmsKeyId` (customer-managed CMK, NOT the default SageMaker service key). Runs on completed/in-progress/stopped training jobs from the last 90 days to avoid noise from years-old historical jobs. |
| **Relevant services** | Amazon SageMaker `sagemaker` client — `ListTrainingJobs(CreatedTimeAfter=now-90d)` + `DescribeTrainingJob` |
| **Citation(s)** | `45 CFR 164.312(a)(2)(iv)` \| `45 CFR 164.312(e)(2)(ii)` \| `HITECH § 13401` |
| **Failure severity** | High for missing CMK volume encryption (uses default service key); Medium for missing inter-container encryption OR missing VPC/NetworkIsolation; Informational/N/A for access denied, region unsupported, or 0 training jobs in window |
| **Remediation** | For all new training jobs, set `EnableInterContainerTrafficEncryption=true`, `EnableNetworkIsolation=true`, a `VpcConfig` with private subnets, and a customer-managed `VolumeKmsKeyId`. Re-run affected historical jobs if their model artifacts are used in production. Add the same KMS key to `OutputDataConfig.KmsKeyId`. |
| **Reference** | https://docs.aws.amazon.com/sagemaker/latest/dg/train-encrypt.html |

---

## HP-05 — CloudWatch Logs: AIML-Prefixed Log Groups Have Data Protection Policies with Audit + Identify ePHI Patterns

| Property | Value |
| --- | --- |
| **Check ID** | `HP-05` |
| **What it does** | For every CloudWatch Logs log group whose name matches AIML-shaped prefixes (`bedrock*`, `sagemaker*`, `agent*`, `agentcore*`, `aiml*`, `ml-*`, `genai*`, `model*`, `inference*`, `training*`), verifies that a `GetDataProtectionPolicy` is attached with: (a) at least one `Audit` statement targeting CloudWatch Logs itself, S3, or Firehose, AND (b) at least one `Protect`/`Deidentify` `Mask` statement that includes managed data identifiers for U.S. SSN, NPI, or HIPAA-relevant PII types (PHI pattern detection is not automated, but the absence of any masking is a flag). |
| **Relevant services** | Amazon CloudWatch Logs `logs` client — `DescribeLogGroups` (prefix-scoped) + `GetDataProtectionPolicy` |
| **Citation(s)** | `45 CFR 164.312(b)` (audit logging) \| `45 CFR 164.312(c)(1)` (integrity) \| `HITECH § 13402` (breach notification) |
| **Failure severity** | Medium for no policy attached; Low for policy attached but missing Audit statement OR missing any masking on PHI/PII identifiers; Informational/N/A for no matching log groups, access denied, or region unsupported |
| **Remediation** | Attach a CloudWatch Logs Data Protection Policy that includes: (1) an `Audit` `FindingsDestination` for `CloudWatchLogs`, `S3`, or `Firehose`; (2) a `Deidentify` `Mask` operation covering the managed data identifiers `Arn:aws:dataprotection::aws:data-identifier/Social-Security-Number-Us`, `Arn:aws:dataprotection::aws:data-identifier/Healthcare-National-Provider-Identifier-Us`, and a custom pattern for MRN/account numbers when applicable. Apply to every AIML-scoped log group, or to the account-wide default via the CloudWatch Logs Account Policy API. |
| **Reference** | https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/cloudwatch-logs-data-protection-policies.html |

---

## HP-06 — AI/ML VPC Reachability: AIML-Related EC2 VPC Endpoints Exist in Every Target Region (Bedrock, SageMaker API/Runtime, Agent Runtime, KMS, S3, SecretsManager)

| Property | Value |
| --- | --- |
| **Check ID** | `HP-06` |
| **What it does** | For every scanned region, asserts that VPC Endpoints (Interface or Gateway) of the following services exist in at least one VPC: `com.amazonaws.<region>.s3` (Gateway), `com.amazonaws.<region>.kms`, `com.amazonaws.<region>.logs`, `com.amazonaws.<region>.bedrock-runtime`, `com.amazonaws.<region>.bedrock-agent-runtime`, `com.amazonaws.<region>.sagemaker.api`, `com.amazonaws.<region>.sagemaker.runtime`, `com.amazonaws.<region>.secretsmanager`. Missing endpoints indicate AI/ML traffic may transit public internet instead of AWS private network, violating 164.312(e) transit security expectations. |
| **Relevant services** | Amazon EC2 `ec2` client — `DescribeVpcs` + `DescribeVpcEndpoints(Filters=[{Name=service-name, Values=[…]}])` |
| **Citation(s)** | `45 CFR 164.312(e)(1)` \| `45 CFR 164.312(e)(2)(ii)` \| `HITECH § 13401` |
| **Failure severity** | Medium per missing endpoint (S3, KMS, Logs = high-priority set); Informational aggregate row when all required endpoints exist; Informational/N/A for 0 VPCs in region, access denied, or region unsupported |
| **Remediation** | In each target region, create Interface Endpoints for `bedrock-runtime`, `bedrock-agent-runtime`, `sagemaker.api`, `sagemaker.runtime`, `kms`, `logs`, `secretsmanager`, plus a Gateway Endpoint for `s3` in every VPC that hosts AI/ML workloads. Enable **Private DNS** on every Interface Endpoint so DNS resolution routes to private IPs. Attach security groups that restrict 443 inbound to the AI/ML VPC CIDRs only. |
| **Reference** | https://docs.aws.amazon.com/whitepapers/latest/building-scalable-secure-multi-vpc-network-infrastructure/vpc-endpoints.html |

---

## HP-07 — AI/ML-Related S3 Buckets: Default Encryption = CMK + Versioning Enabled + Public Access Block = Account-Level Enforced

| Property | Value |
| --- | --- |
| **Check ID** | `HP-07` |
| **What it does** | Scans the union of (a) buckets whose names contain AI/ML-hint substrings (`dataset`, `model`, `artifact`, `checkpoint`, `inference`, `training`, `bedrock`, `sagemaker`, `aiml`, `genai`, `ml-`, `fine-tune`) OR whose tag keys/values match those hints, AND (b) any bucket referenced in SageMaker training jobs, model data, or endpoint configs from the last 90 days. Verifies per-bucket: (1) `ServerSideEncryptionConfiguration` uses `aws:kms` with an explicit customer-managed key (NOT `aws:kms:dsse` nor `AES256` SSE-S3); (2) `VersioningConfiguration.Status=Enabled`; (3) `PublicAccessBlockConfiguration` all four flags `true`. Additionally verifies that the **account-level** `GetPublicAccessBlock` returns all four flags `true`. |
| **Relevant services** | Amazon S3 `s3` client — `ListAllMyBuckets`, `GetBucketEncryption`, `GetBucketVersioning`, `GetPublicAccessBlock`, plus cross-reference from SageMaker endpoint/training data URIs |
| **Citation(s)** | `45 CFR 164.312(a)(2)(iv)` (at-rest encryption) \| `45 CFR 164.312(c)(1)` \| `45 CFR 164.312(c)(2)` (integrity + versioning = authentication of integrity) \| `45 CFR 164.312(e)(1)` \| `HITECH § 13401` / `§ 13402` |
| **Failure severity** | High for SSE-S3 (AES256) or absent encryption; Medium for AWS-managed KMS (not CMK), or versioning suspended/absent, or any PAB flag = false; Medium for account-level PAB != all-true; Informational aggregate row for all compliant; N/A for 0 matching buckets, access denied, region unsupported |
| **Remediation** | For every affected bucket: (1) Set default encryption to `aws:kms` with a customer-managed KMS key that has a key policy restricted to the AI/ML service principals + scoped IAM roles; enable bucket key. (2) Enable versioning. (3) Put `PublicAccessBlockConfiguration` all-four-true at bucket level. (4) Put `PublicAccessBlock` all-four-true at the **account** level via `s3control:PutPublicAccessBlock` for `AccountId=<your-account>`. Enforce the same rules via SCP in AWS Organizations to prevent drift. |
| **Reference** | https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html |

---

## N/A and Incomplete Paths

Every HP-01..HP-07 check individually handles the following non-failure cases and returns an informational `N/A` finding rather than a `Failed` row, consistent with the repository's [Status Values](SECURITY_CHECKS.md#status-values) semantics:

| Condition | HP finding status | Detail wording |
| --- | --- | --- |
| No resources exist in region for the target service | `N/A` | `"No {service} resources found in {region}"` |
| Regional API / feature is not available (e.g., `UnrecognizedClientException` w/ region text, `OptInRequired`, or `UnknownOperationException`) | `N/A` | `"HP-XX is not available in {region}: {reason}"` |
| IAM `AccessDeniedException` (Lambda execution role lacks scoped permission) | `N/A` | `"HP-XX could not run in {region} due to missing IAM permission. Verify the HIPAASecurityAssessmentFunction SAM policy grants {action}."` |
| Any unexpected per-resource exception during detail enumeration | `N/A` | Incomplete-assessment notice appended after per-resource rows already collected (mirrors AR-07/AR-08 bounded-inventory pattern). Never aborts the entire check. |

When the Step Functions `Catch` path triggers on the `HIPAA Security Assessment` Task (e.g., S3 write failure or unhandled infrastructure ClientError), the "HIPAA Assessment Incomplete" Pass state emits a Step Functions status 207, and the report generator renders the HIPAA section with a red status chip instead of omitting it.

---

## Additional Resources

* [HIPAA Security Rule Overview](https://www.hhs.gov/hipaa/for-professionals/security/index.html) — HHS Office for Civil Rights
* [AWS HIPAA Compliance Whitepaper](https://docs.aws.amazon.com/whitepapers/latest/architecting-hipaa-security-and-compliance-on-aws/welcome.html)
* [45 CFR Part 164 Subpart C — Security Standards for the Protection of Electronic Protected Health Information](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C)
* [HITECH Act Summary](https://www.hhs.gov/hipaa/for-professionals/special-topics/hitech-enforcement/index.html)
