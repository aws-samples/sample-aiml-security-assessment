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
* **HP-05 (CloudWatch Logs data protection)** inspects only log groups whose names match six AIML-shaped prefixes: `bedrock*`, `sagemaker*`, `agent*`, `agentcore*`, `aiml*`, `ml-*` (six separate paginated scans, each capped at 200 groups).
* **HP-07 (S3 bucket encryption + versioning)** inspects only buckets whose **names** contain any of 17 AI/ML dataset-name hints (`bedrock`, `sagemaker`, `aiml`, `ml-`, `-model`, `-dataset`, `-training`, `-data`, `models`, `datasets`, `fine-tune`, `finetune`, `training-data`, `-genai-`, `genai-`, `rag-data`). No resource-tag matching, no SageMaker training-job-URI cross-reference, and no endpoint-config URI cross-reference are performed.

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

## HP-02 — Bedrock Guardrails: PHI-Entity PII Redaction Configured (BLOCK or ANONYMIZE)

| Property | Value |
| --- | --- |
| **Check ID** | `HP-02` |
| **What it does** | Verifies every Bedrock guardrail declares at least one PII entity in `sensitiveInformationPolicy.piiEntities` whose action is **`BLOCK`** or **`ANONYMIZE`**. Guardrails with no qualifying PII entity, or whose every PII entry uses action `NONE`, are non-compliant. Inventories are paginated; a 500-item safety cap emits an additional Informational N/A truncation notice if hit. Empty inventories (no guardrails in region) emit an Informational N/A row with explicit wording instead of silently returning zero rows. |
| **Relevant services** | Amazon Bedrock `bedrock` client — paginated `ListGuardrails` + `GetGuardrail` (GuardrailVersion / DRAFT resolution) |
| **Citation(s)** | `45 CFR 164.312(a)(2)(iv)` \| `45 CFR 164.312(a)(1)` \| `HITECH § 13401` |
| **Failure severity** | Medium for guardrails missing any BLOCK/ANONYMIZE PII action; Informational/N/A for region unsupported / no guardrails / access denied / inventory truncation |
| **Remediation** | For each non-compliant guardrail, add at least the following PII entities with BLOCK or ANONYMIZE action (minimum realistic set): `NAME`, `US_SOCIAL_SECURITY_NUMBER`, `EMAIL`, `PHONE`, `ADDRESS`, `DATE_OF_BIRTH`. Add custom regex patterns for MRNs, account numbers, or any ePHI identifiers specific to your organization. |
| **Reference** | https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-content-filters.html |

---

## HP-03 — SageMaker Endpoints + Training Jobs: EnableNetworkIsolation=True (No Public Internet Egress)

| Property | Value |
| --- | --- |
| **Check ID** | `HP-03` |
| **What it does** | For every in-service SageMaker endpoint, resolves `ProductionVariants[].ModelName → calls `sagemaker:DescribeModel(ModelName=…)` and asserts `EnableNetworkIsolation==True` on each variant's model. Inference-component endpoints (variants without a `ModelName`) fall back to `describe_endpoint_config(EndpointConfigName).EnableNetworkIsolation`. Additionally inspects every training job created within the last 90 days (CreationTimeAfter=now-90d) and asserts `EnableNetworkIsolation==True` via `describe_training_job`. Endpoint and training-job inventories are paginated with a 150-item safety cap each; truncation appends an Informational N/A row if the cap is exceeded. Empty inventories emit an Informational N/A row with explicit wording instead of silently returning zero rows. |
| **Relevant services** | Amazon SageMaker `sagemaker` client — paginated `ListEndpoints(StatusEquals=InService)` + `DescribeEndpoint` + `DescribeEndpointConfig` + `DescribeModel` + paginated `ListTrainingJobs(CreationTimeAfter=now-90d)` + `DescribeTrainingJob` |
| **Citation(s)** | `45 CFR 164.312(e)(1)` \| `45 CFR 164.312(e)(2)(ii)` \| `HITECH § 13401` |
| **Failure severity** | High for `EnableNetworkIsolation=False` on any endpoint variant model or any 90-day training job; Informational/N/A for empty inventory, region unsupported, access denied, or truncation |
| **Remediation** | For endpoints: re-create the model(s) with `EnableNetworkIsolation=True` and deploy to a new endpoint configuration; for inference-component endpoints: deploy via `EnableNetworkIsolation=True` on the endpoint config. Re-run training jobs with `EnableNetworkIsolation=True`. Add VPC Gateway/Interface Endpoints for `sagemaker.api`, `sagemaker.runtime`, `s3`, `kms`, `logs`, and `monitoring` so isolated resources still reach required AWS services. |
| **Reference** | https://docs.aws.amazon.com/sagemaker/latest/dg/infrastructure-give-access.html |

---

## HP-04 — SageMaker Endpoint and Training Encryption: CMK Keys + Inter-Container Traffic Encryption

| Property | Value |
| --- | --- |
| **Check ID** | `HP-04` |
| **What it does** | Per-resource encryption check covering two inventory paths. (A) In-service SageMaker endpoints: for each endpoint, reads `describe_endpoint_config(EndpointConfigName=…).KmsKeyId` and validates it references a customer-managed KMS key (via `kms:DescribeKey → KeyManager == "CUSTOMER"`), NOT the default SageMaker service key. (B) Training jobs from the last 90 days (CreationTimeAfter=now-90d): each must satisfy both (i) `VolumeKmsKeyId` AND `OutputDataConfig.KmsKeyId` are set, and each references a customer-managed KMS key validated through `kms:DescribeKey`; and (ii) `EnableInterContainerTrafficEncryption == True`. All inventories are paginated; a 150-item cap on each emits a truncation Informational N/A if exceeded. Empty inventories return an explicit N/A row rather than zero rows. Network isolation is NOT checked here (see HP-03). |
| **Relevant services** | Amazon SageMaker `sagemaker` client — paginated `ListEndpoints(StatusEquals=InService)` + `DescribeEndpointConfig`; paginated `ListTrainingJobs(CreatedTimeAfter=now-90d)` + `DescribeTrainingJob`; AWS KMS `kms` client — `DescribeKey` for KeyManager=="CUSTOMER" validation |
| **Citation(s)** | `45 CFR 164.312(a)(2)(iv)` (at-rest encryption) \| `45 CFR 164.312(e)(2)(ii)` (in-transit inter-container) \| `HITECH § 13401` |
| **Failure severity** | High for absent or non-CMK KmsKeyId / VolumeKmsKeyId / OutputDataConfig.KmsKeyId; Medium for `EnableInterContainerTrafficEncryption=False` on any training job; Informational/N/A for empty inventory, region unsupported, access denied, or truncation |
| **Remediation** | Deploy new endpoint configurations with an explicit `KmsKeyId` referencing a customer-managed CMK (not the default `aws/sagemaker` service key). Re-create affected models and re-deploy to the new endpoint config. For training jobs, set `VolumeKmsKeyId` to a customer-managed CMK, set `OutputDataConfig.KmsKeyId` to the same (or equivalent scoped) customer-managed CMK, and enable `EnableInterContainerTrafficEncryption=true` on every SageMaker training job submission. Re-run affected historical jobs if their model artifacts feed production workloads. |
| **Reference** | https://docs.aws.amazon.com/sagemaker/latest/dg/train-encrypt.html |

---

## HP-05 — CloudWatch Logs: AIML-Prefixed Log Groups Have Active Data Protection Policies (Per-Group or Account-Level)

| Property | Value |
| --- | --- |
| **Check ID** | `HP-05` |
| **What it does** | Runs six separate paginated `DescribeLogGroups` scans, one per AIML-shaped prefix (`bedrock*`, `sagemaker*`, `agent*`, `agentcore*`, `aiml*`, `ml-*`), each capped at 200 groups (a truncation Informational N/A is appended if any cap is hit). Each log group counts as protected only when either: (a) its `dataProtectionStatus == "ACTIVATED"`; OR (b) an account-level policy exists because `logs.describe_account_policies(policyType="DATA_PROTECTION_POLICY")` returns at least one valid account-wide DATA_PROTECTION policy. Empty `{}` bodies from `get_data_protection_policy` (no attached policy at the log-group level) are NOT treated as protected; they fail path (a) and only pass if an account-level override exists per path (b). Empty inventories emit an Informational N/A row with explicit wording; zero-row prefixes are aggregated into one consolidated N/A message rather than six duplicate rows. |
| **Relevant services** | Amazon CloudWatch Logs `logs` client — `DescribeLogGroups` (six prefix-scoped, paginated) + `GetDataProtectionPolicy` + `DescribeAccountPolicies(policyType=DATA_PROTECTION_POLICY)` |
| **Citation(s)** | `45 CFR 164.312(b)` (audit logging) \| `45 CFR 164.312(c)(1)` (integrity) \| `HITECH § 13402` (breach notification) |
| **Failure severity** | Medium when a group is not covered by either per-group data protection activation or an account-level DATA_PROTECTION policy; Informational/N/A for empty inventory, region unsupported, access denied, or inventory truncation |
| **Remediation** | For every AIML-scoped log group that currently returns no coverage, choose ONE of the following approaches: (A) Attach a per-group data protection policy using `logs:PutDataProtectionPolicy` (which sets `dataProtectionStatus=ACTIVATED`) including at least `Audit` and `Deidentify`/`Mask` operations for your regulated PII identifiers. OR (B) Put a single account-level CloudWatch Logs Account Policy of type `DATA_PROTECTION_POLICY` via `logs:PutAccountPolicy`, which covers every log group in the account region. Add the `aws:SecureTransport` condition key on the log-group resource policy where the HIPAA-scoped data egresses CloudWatch Logs. |
| **Reference** | https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/cloudwatch-logs-data-protection-policies.html |

---

## HP-06 — AI/ML VPC Reachability: 12 HIPAA-Scoped EC2 VPC Endpoints Are Available (State=available) in At Least One Regional VPC

| Property | Value |
| --- | --- |
| **Check ID** | `HP-06` |
| **What it does** | Enumerates regional VPCs (paginated describe_vpcs, cap 100 VPCs) and VPC Endpoints (paginated describe_vpc_endpoints, cap 200 endpoints), then validates that each of the following twelve HIPAA-scoped endpoint services exists with `State=="available"` in at least one VPC in every scanned region: `com.amazonaws.<region>.bedrock`, `com.amazonaws.<region>.bedrock-agent`, `com.amazonaws.<region>.bedrock-agent-runtime`, `com.amazonaws.<region>.sagemaker.api`, `com.amazonaws.<region>.sagemaker.runtime`, `com.amazonaws.<region>.sagemaker.featurestore-runtime`, `com.amazonaws.<region>.sts`, `com.amazonaws.<region>.kms`, `com.amazonaws.<region>.secretsmanager`, `com.amazonaws.<region>.logs`, `com.amazonaws.<region>.s3` (Gateway Endpoint), `com.amazonaws.<region>.ec2`. A per-region Informational aggregate Passed row is emitted only when all twelve services have at least one available endpoint. Per-service Medium Failed rows are emitted for any missing or not-available service set. Truncation caps (100 VPCs or 200 endpoints) append a warning N/A; zero-VPC regions emit an explicit Informational N/A rather than silently skipping the region. |
| **Relevant services** | Amazon EC2 `ec2` client — paginated `DescribeVpcs` (VPC_CAP 100) + paginated `DescribeVpcEndpoints(Filters=[{Name=service-name, Values=[…]}])` (ENDPOINT_CAP 200) |
| **Citation(s)** | `45 CFR 164.312(e)(1)` (transmission security general) \| `45 CFR 164.312(e)(2)(ii)` (encryption in transit) \| `HITECH § 13401` |
| **Failure severity** | Medium per missing or non-available endpoint (S3, KMS, Logs, STS, SecretsManager = high-priority credential-bearing set); Informational aggregate row when all twelve required endpoints are satisfied; Informational/N/A for 0 VPCs in region, access denied, region unsupported, or inventory truncation |
| **Remediation** | In every target region, create twelve endpoints across VPCs hosting AI/ML workloads: three Bedrock-family Interface Endpoints (`bedrock`, `bedrock-agent`, `bedrock-agent-runtime`), three SageMaker Interface Endpoints (`sagemaker.api`, `sagemaker.runtime`, `sagemaker.featurestore-runtime`), six infrastructure Interface Endpoints (`sts`, `kms`, `secretsmanager`, `logs`, `ec2`), plus one S3 Gateway Endpoint in every AI/ML VPC. Enable Private DNS on every Interface Endpoint so the service DNS name resolves to a private IP inside the VPC. Restrict endpoint security groups to allow TCP 443 inbound from AI/ML VPC CIDRs only. |
| **Reference** | https://docs.aws.amazon.com/whitepapers/latest/building-scalable-secure-multi-vpc-network-infrastructure/vpc-endpoints.html |

---

## HP-07 — AI/ML-Related S3 Buckets: CMK Encryption + Versioning Enabled + Account/Bucket-Level Public Access Block (Global, RegionIndex==0 Only)

| Property | Value |
| --- | --- |
| **Check ID** | `HP-07` |
| **What it does** | Account-wide S3 inventory that runs **once** only when `RegionIndex == 0`; findings emit with `Region=Global` to avoid duplicate bucket findings appearing in every scanned region. Filters the result of `s3:ListAllMyBuckets` by bucket **name substrings only** against 17 AI/ML dataset name hints (`bedrock`, `sagemaker`, `aiml`, `ml-`, `-model`, `-dataset`, `-training`, `-data`, `models`, `datasets`, `fine-tune`, `finetune`, `training-data`, `-genai-`, `genai-`, `rag-data`). No resource-tag matching and no SageMaker-training-job-URI or endpoint-config cross-reference is performed. Each matching bucket is independently checked for: (1) Default encryption uses `aws:kms` with a customer-managed KMS key verified via `kms:DescribeKey → KeyManager=="CUSTOMER"`. `AES256` (SSE-S3) or the default aws/s3 AWS-managed KMS service key = Fail. (2) Bucket versioning `Status == "Enabled"` (Suspended or never-enabled = Fail). (3) Per-bucket `PublicAccessBlockConfiguration` all-four-flags-true, EXEMPT when the **account-level** `s3control:GetPublicAccessBlock` returns all four flags true (a separate Medium Failed row is emitted for account-level PAB != all-true, and per-bucket PAB gaps are suppressed in that case). Per-bucket exception isolation: `NoSuchBucket` on detail calls silently skips the deleted bucket; throttling or transient errors produce a per-bucket Informational N/A row while preserving all previously collected findings; any other detail-level error never erases already-collected findings. Empty inventory (zero ListAllMyBuckets results match DATASET_NAME_HINTS) produces one explicit Informational N/A row rather than silently returning zero rows. Lambda-context `invoked_function_arn.split(":")[4]` resolves the account ID for `s3control.GetPublicAccessBlock(AccountId=…)`; `sts:GetCallerIdentity` is only used as a last-resort fallback when no Lambda context is available (non-Lambda invocation environments such as pytest or manual scripts). |
| **Relevant services** | Amazon S3 `s3` client — `ListAllMyBuckets`, `GetEncryptionConfiguration` (alias `GetBucketEncryption`), `GetBucketVersioning`, `GetPublicAccessBlock`; Amazon S3 Control `s3control` client — `GetPublicAccessBlock(AccountId=…)`; AWS KMS `kms` client — `DescribeKey` for KeyManager=="CUSTOMER" CMK validation |
| **Citation(s)** | `45 CFR 164.312(a)(2)(iv)` (at-rest encryption) \| `45 CFR 164.312(c)(1)` \| `45 CFR 164.312(c)(2)` (integrity + versioning = authentication of integrity) \| `45 CFR 164.312(e)(1)` \| `HITECH § 13401` / `§ 13402` |
| **Failure severity** | High for `AES256` SSE-S3 default encryption or for absent encryption entirely; Medium for `aws:kms` with the default AWS-managed service key (non-CMK), for versioning not equal to Enabled, or for any Public Access Block flag = false (per-bucket or account-level); Medium for account-level PAB != all-four-true; Informational aggregate row when all matching buckets satisfy all three checks AND account PAB is all-four-true; Informational/N/A for empty inventory, access denied, region-scoped errors, or per-bucket transient/throttling errors |
| **Remediation** | For every affected bucket: (1) Re-configure default encryption to use `aws:kms` with a customer-managed KMS key whose key policy restricts `kms:Encrypt`/`kms:Decrypt` only to AI/ML service principals + scoped IAM role ARNs; enable the S3 Bucket Key. Enable `aws:SecureTransport` as a condition on the bucket policy so HTTP without TLS is rejected. (2) Run `s3:PutBucketVersioning(Status=Enabled)`. (3) Run `s3:PutPublicAccessBlock(Bucket=…, PublicAccessBlockConfiguration{BlockPublicAcls=true, IgnorePublicAcls=true, BlockPublicPolicy=true, RestrictPublicBuckets=true})`. (4) Run `s3control:PutPublicAccessBlock(AccountId=<your-account>, PublicAccessBlockConfiguration={all-four-true})` at the account level once to exempt future per-bucket PAB drift. Add an SCP in AWS Organizations to prevent these four settings from being disabled on any AI/ML-scoped OU. |
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
