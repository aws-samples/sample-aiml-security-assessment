# AI Security Best Practices Gap Analysis

Date checked: 2026-07-14

Status: reviewed and corrected (second verification pass, 2026-07-14). This
pass is validated against the actual `v1.0.0` codebase, against every AWS
Security Hub control-detail page (not just the standard index), against the
SDK version the solution actually deploys with, against a code-level audit of
all 14 "covered" checks, and against the repo's own documented severity
methodology and register. An independent re-verification found and corrected
several errors in the earlier pass (see "Corrections From The Second Pass");
a set of defects identified by that re-verification has already been fixed in
code ahead of the parity PRs (see "Already Fixed Ahead Of The PR Plan"). The
audit findings are best read as defect classes with a per-control checklist,
not as a guaranteed-closed list. The Financial Services GenAI Risk checks are
excluded from the coverage decision, but their severity methodology is adopted
here as the tool-wide model (see "Severity Model").

Baseline under analysis:

- Repo: `aws-samples/sample-aiml-security-assessment`
- Commit: `c39f9a1` (tag `v1.0.0`, `upstream/main`)
- Working branch: `feat/securityhub-ai-best-practices-parity` (branched from
  `v1.0.0`)
- Deployed SDK: `boto3`/`botocore` **1.43.32** (exact pins in the Bedrock,
  SageMaker, AgentCore, and report functions; the FinServ function uses
  `>=1.43.32` floors by design so security patches can resolve at build time).
  All response fields used by the proposed checks were confirmed present in
  botocore 1.43.21, a strict subset of 1.43.32; re-confirm against 1.43.32 in
  implementation.

Source standard: AWS Security Hub CSPM AI Security Best Practices v1.0.0,
`arn:aws:securityhub:<region>::standards/ai-security-best-practices/v/1.0.0`
(31 controls; launched June 2026; no later version exists as of this date).

Primary sources:

- Standard index and the Bedrock, AgentCore, and SageMaker control-detail pages
  under https://docs.aws.amazon.com/securityhub/latest/userguide/
- Repo severity methodology: `docs/SECURITY_CHECKS_FINSERV_SEVERITY_METHODOLOGY.md`
- Repo severity register: `docs/SECURITY_CHECKS_FINSERV_SEVERITY_REGISTER.md`
- Implementation: `finserv_assessments/app.py` (`_label_from_matrix`,
  `_DISPOSITION_SEVERITY`, `SEVERITY_REGISTER`, `_could_not_assess_row`) and its
  drift-guard `finserv_tests/test_severity_register.py`.

## Reader's Guide

- Implementing checks: read "Severity Model", "Known Defects In Covered
  Controls", "Authoritative Control Reference", "Correctness Rules",
  "Permission Handling", then "Locked PR Plan".
- Reviewing scope: read "Executive Conclusion" and "Coverage Matrix".
- Deployment/README owner: read "SDK Version Management" and "Permission
  Handling".

## Executive Conclusion

Against `v1.0.0`, 14 of 31 controls were covered and 17 needed work (1 Bedrock,
3 AgentCore, 13 SageMaker; one SageMaker item is a wrong-resource fix). Five
SageMaker checks were mislabeled with Security Hub numbers they do not
implement (docstrings now corrected). The code-level audit of the covered
controls found accuracy defects in 8 of 14 — the first pass reported 6; the
second pass found two more in controls the first pass had declared correct
(AgentCore `.3` pass-path severity, SageMaker `.16`/`.19` phantom primary
container). Treat "correct" claims as checklist items to re-verify during
implementation, not as settled facts.

The most important structural finding: the repo already has an authoritative,
tested Likelihood x Impact severity methodology (built for FinServ) that is
explicitly written to be adopted tool-wide. The general Bedrock/AgentCore/
SageMaker checks do not use it, and that is the root cause of every covered-
control severity defect and of the inconsistent permission handling. The fix is
not to hand-edit severities to "match Security Hub"; it is to adopt the
methodology tool-wide. See "Severity Model".

Release blockers (false PASSes, false FAILs, and misleading metrics all erode
trust; treat them symmetrically):

1. Adopt the severity methodology tool-wide (register + disposition model +
   drift-guard) and fix the remaining covered-control defects through it
   (PR-0).
2. Route every permission/region/SDK failure through the `COULD_NOT_ASSESS`
   disposition (`N/A` + `Low` + `"COULD NOT ASSESS:"`), never a false `Failed`
   and never a silent "no resources" `N/A`. See "Permission Handling".
3. KMS controls must apply the correct standard per control: customer-managed
   only where the control text says so; any KMS key for `SageMaker.17`/`.18`.
   Fix the `SM-03` substring key test (false PASS risk). See Correctness Rule 1.
4. Do not read a version-sensitive-but-absent field as "insecure"; disposition
   it as `COULD_NOT_ASSESS`. See "SDK Version Management".
5. FIXED — report pass-rate denominators previously counted `N/A`-status rows
   (a `COULD_NOT_ASSESS` Low/N-A row could never pass, so it silently
   depressed the pass rate). The template now scores only Passed/Failed rows
   and surfaces `COULD NOT ASSESS` rows in a dedicated "Unassessed Checks"
   metric. Without this fix, blocker 2's tool-wide rollout would have cratered
   displayed pass rates for any customer with a stale IAM role.
6. FIXED — `AC-06` read a nonexistent `storageConfig` field from
   `GetAgentRuntime`, false-failing every runtime in every account. Rewritten
   against `ListBrowsers(type=CUSTOM)`/`GetBrowser.recording`
   (`BedrockAgentCore.6`).
7. FIXED — `SM-12` treated serverless endpoint variants (no
   `CurrentInstanceCount`) as zero instances, false-failing every serverless
   endpoint. Serverless variants are now skipped per the `SageMaker.4` scope
   note.

## Severity Model (adopt the FinServ Likelihood x Impact methodology tool-wide)

The repo's severity methodology (`SECURITY_CHECKS_FINSERV_SEVERITY_METHODOLOGY.md`)
scores each control's inherent risk as Impact x Likelihood on a 3x3 matrix and
maps the result to the ASFF label set (`High/Medium/Low/Informational`; no
`Critical` this round). It is AWS-aligned (AWS's own exposure-finding severity
model plus NIST SP 800-30) and is already implemented and drift-guarded for the
FinServ checks. Its scope note states it "is written so it can later be adopted
tool-wide." Adopt it now for the general checks.

What this replaces: earlier drafts of this document told implementers to make
each finding's severity "match Security Hub's severity." That was a mistake in
framing. The repo's standard is L x I expressed in ASFF labels, not copying a
per-control number. The two usually agree, but not always, and presenting
"match Security Hub" as a freestanding rule conflicts with the methodology the
repo is governed by.

How to reconcile for the general checks specifically. Unlike the bespoke FinServ
risks, the general checks mirror real Security Hub controls, and AWS's published
severity for a control is itself an authoritative L x I-derived rating. So:

- The methodology is the framework (matrix, disposition rules, one severity per
  control across Pass/Fail rows, register as single source of truth, drift-guard
  test).
- For each general check, the control-severity input to the register is the
  Security Hub published severity for the control it implements. Record it in
  the register with the `SecurityHub_Control` mapping.
- Where a family band in the methodology (methodology 3.5) would disagree with
  the Security Hub severity, that is a documented decision in the register, not
  an accident. The known instance is `SageMaker.20`/`.25` (below).

Mechanics to reuse (do not reinvent):

- `SEVERITY_REGISTER`: finding-name -> severity, the single source of truth.
- `_DISPOSITION_SEVERITY`: `NOT_APPLICABLE -> Informational`,
  `ADVISORY -> Informational`, `COULD_NOT_ASSESS -> Low`.
- `_could_not_assess_row(...)`: emits `Status="N/A", Severity="Low"`, name
  prefixed `"COULD NOT ASSESS: "`, with remediation naming missing IAM,
  unsupported region, and outdated botocore as the causes.
- The drift-guard test suite (`test_severity_register.py`), strengthened to a
  bidirectional source-scan: every static `finding_name` literal in the source
  must exist in the register, every register key must correspond to a finding
  name in the source (no orphans), and rows emitted at runtime must carry the
  register severity, with unregistered emitted names failing the test rather
  than being skipped. Note the runtime collection only exercises paths
  reachable with AWS mocked down; Pass/Fail-path severities are covered by the
  source-scan plus per-scenario assertions in `test_checks.py`. Replicate the
  source-scan pattern (not just the runtime spot-check) when extending to
  Bedrock/AgentCore/SageMaker.

No `Critical` is required: every AI-standard control is High/Medium/Low, so the
methodology's four-level cap fits with zero schema change.

Decision to record in the register: `SageMaker.20` (explainability network
isolation) and `SageMaker.25` (model quality network isolation) are High in
Security Hub, while their sibling isolation controls (`.11`, `.12`, `.14`) are
Medium and the methodology's governance/monitoring family band is Medium. Choose
explicitly: seed from Security Hub (High) or apply the family band (Medium). The
recommendation is to seed from Security Hub (High) since these are real Security
Hub controls, and note the sibling asymmetry in the register justification.

## Known Defects In Covered Controls

Code-level audit of all 14 covered controls across two verification passes.
Defects in 8 of 14; the remaining 6 audited as correct: AgentCore `.1`, `.2`;
SageMaker `.2`, `.3`, `.9` — re-verify each during implementation rather than
trusting this list (the first pass declared 8 correct and was wrong twice).
Severity defects are resolved by adopting the register/disposition model in
PR-0 (not by hand-editing individual `severity=` values); rows marked FIXED
were corrected in code ahead of the PR plan.

| Control | Local check | Defect | Impact | Register/disposition fix |
| --- | --- | --- | --- | --- |
| `BedrockAgentCore.3` | `AC-07` | FIXED — Passed emitted `High`; Failed used Medium; control is Medium. Missed by the first pass (same class as `SM-15`). | Inconsistent severity on the pass path. | Fixed in code (Passed now Medium); register Medium; one severity all paths. |
| `BedrockAgentCore.4` | `AC-12` | Failed finding emits `severity=LOW`; control is Medium. | `.html` under-reports gateway CMK findings. | Register control severity Medium; one severity all paths. |
| `SageMaker.5` | `SM-11` | Failed findings emit `High`; Passed uses Medium; control is Medium. | Model-isolation failures over-reported as High. | Register Medium; one severity all paths. |
| `SageMaker.14` | `SM-13` | Reads only inline `MonitoringJobDefinition.NetworkConfig`; named definitions (`MonitoringJobDefinitionName` + `MonitoringType`) yield empty config, so isolation defaults to False. | False FAIL for named-definition schedules. | Resolve the named definition by monitoring type before evaluating. |
| `SageMaker.17` | `SM-15` | Passed finding emits `High`; Failed uses Medium; control is Medium. Fail logic correct (any-KMS presence). | Inconsistent severity on the pass path. | Register Medium; one severity all paths. |
| `SageMaker.21` | `SM-03` | (1) severity inconsistent/wrong (missing-key Failed=High, AWS-managed-key Failed=Low, Passed=High; control is Medium); (2) customer-managed detection uses the substring test `"aws/sagemaker" in kms_key_id`, which misses AWS-managed keys referenced by key id or ARN -> false PASS; (3) one check bundles notebooks, domains, and training jobs but is mapped to `SageMaker.21` (notebook KMS only). | Wrong severity, possible false PASS on an encryption control, mislabeled scope. | Split notebook KMS into its own Medium `SageMaker.21` check (presence-as-proxy, Rule 1); reclassify domain and training-job encryption as repo-only; register the severity. |
| `SageMaker.1` | `SM-01` | Also flags SageMaker Domains (`AppNetworkAccessType != VpcOnly`); Security Hub `SageMaker.1` scope is `NotebookInstance` only. | Domain findings surface under a `SageMaker.1` label Security Hub would not produce. | Keep the notebook check as `SageMaker.1`; reclassify the domain sub-check as repo-only. |
| `SageMaker.16`/`.19` | `SM-14` | FIXED — multi-container models (`Containers[]`, no `PrimaryContainer`) were evaluated against a phantom primary container whose absent `ImageConfig` defaulted to Platform mode, false-failing every inference-pipeline model even when all real containers used `Vpc` mode. Missed by the first pass, which declared `.16`/`.19` correct. | False FAIL on exactly the models `.19` exists for. | Fixed in code: only existing container definitions are evaluated; `.16` (primary) and `.19` (multi-container) paths separated; failing container hostnames listed in the finding. |

Systemic issues (all fixed by the methodology, which was built to fix exactly
these four classes for FinServ):

- Per-path severity drift: severity set per `create_finding()` call, so Passed,
  Failed, and error paths disagree (`SM-11`, `SM-15`, `SM-03`). The register's
  one-severity-per-control invariant fixes this.
- Error-fallback severity hardcoded `High` regardless of control severity, and
  worse, `status=Failed` (see "Permission Handling").
- Inconsistent no-resource severity (High/Medium/Informational across checks).
  Disposition `NOT_APPLICABLE -> Informational` fixes this.
- Stale code/comments (FIXED): `AC-01` carried an incorrect comment that
  AgentCore browsers and code interpreters "don't have separate list/describe
  APIs" (they do; this is why `.5`/`.6`/`.7` were never built) plus a dead
  `subnetIds` sub-check (the real field is
  `networkConfiguration.networkModeConfig.subnets`, so the sub-check never
  ran). Both removed; `AC-01` now evaluates exactly the `BedrockAgentCore.1`
  fail condition.

## Coverage Matrix (v1.0.0)

Status legend: Covered = a correct check exists; Covered (bug) = a check exists
but has a confirmed defect (above); Incorrect = the check inspects the wrong
resource; Gap = no correct check exists. "SH sev" is the Security Hub published
severity, which seeds the register's control severity for the general checks.

| Control | SH sev | Resource | Status | Evidence / covering check |
| --- | --- | --- | --- | --- |
| `Bedrock.1` data source CMK | Medium | `AWS::Bedrock::DataSource` | Gap | `BR-20` inspects knowledge-base managed KMS, not data sources. |
| `BedrockAgentCore.1` runtime VPC mode | High | Runtime | Covered | `AC-01` reads `networkConfiguration.networkMode` (absent -> PUBLIC -> fail). Stale comment/dead subnet code removed. |
| `BedrockAgentCore.2` gateway inbound auth | High | Gateway | Covered (reconcile) | `AG-24` reads `authorizerType`; richer than the binary control (see Parity Divergence). AccessDenied now routes through `COULD_NOT_ASSESS` (Low), fixed in PR-0. `SECURITY_HUB_CONTROL_MAP` mapping gap also closed in PR-0. |
| `BedrockAgentCore.3` memory CMK | Medium | Memory | Covered (fixed) | `AC-07` fails when key absent; presence-as-proxy. Pass-path severity fixed to Medium. |
| `BedrockAgentCore.4` gateway CMK | Medium | Gateway | Covered (bug) | `AC-12` logic correct but emits severity LOW; register Medium. |
| `BedrockAgentCore.5` browser not public network | High | BrowserCustom | Gap | No browser network-mode check yet; IAM (`ListBrowsers`/`GetBrowser`) now granted, so only check code is needed. |
| `BedrockAgentCore.6` browser session recording | Medium | BrowserCustom | Covered (fixed) | `AC-06` rewritten: was reading a nonexistent runtime `storageConfig` field (false FAIL on every runtime); now reads `ListBrowsers(type=CUSTOM)` + `GetBrowser.recording.enabled`/`s3Location.bucket`. |
| `BedrockAgentCore.7` code interpreter private network | High | CodeInterpreterCustom | Gap | No `ListCodeInterpreters`/`GetCodeInterpreter`. |
| `SageMaker.1` no direct internet | High | NotebookInstance | Covered (bug) | `SM-01` correct for notebooks, but also flags Domains (out of `.1` scope). |
| `SageMaker.2` custom VPC | High | NotebookInstance | Covered | `check_sagemaker_notebook_vpc_deployment`. |
| `SageMaker.3` no root access | High | NotebookInstance | Covered | `check_sagemaker_notebook_root_access`. |
| `SageMaker.4` initial instance count > 1 | Medium | EndpointConfig | Incorrect (partially fixed) | Serverless-variant skip is fixed in `SM-12` (was false-failing every serverless endpoint). The wrong-resource issue remains: uses `list_endpoints`/`CurrentInstanceCount`; must use `DescribeEndpointConfig`/`ProductionVariants[*].InitialInstanceCount`. |
| `SageMaker.5` model network isolation | Medium | Model | Covered (bug) | `SM-11` Failed findings emit High; register Medium. |
| `SageMaker.8` supported notebook platform | Medium | NotebookInstance | Gap | No `PlatformIdentifier` check. |
| `SageMaker.9` data quality traffic encryption | Medium | DataQualityJobDefinition | Covered | `check_sagemaker_data_quality_encryption`. |
| `SageMaker.10` explainability traffic encryption | Medium | ModelExplainabilityJobDefinition | Gap | `processing_job` mislabeled as `.10`. |
| `SageMaker.11` data quality network isolation | Medium | DataQualityJobDefinition | Gap | `transform_job` mislabeled as `.11`. |
| `SageMaker.12` model bias network isolation | Medium | ModelBiasJobDefinition | Gap | `hyperparameter_tuning` mislabeled as `.12`. |
| `SageMaker.13` model quality traffic encryption | Medium | ModelQualityJobDefinition | Gap | `compilation_job` mislabeled as `.13`. |
| `SageMaker.14` monitoring network isolation | Medium | MonitoringSchedule | Covered (bug) | `SM-13` false-FAILs named-definition schedules. |
| `SageMaker.15` model bias traffic encryption | Medium | ModelBiasJobDefinition | Gap | `automl` mislabeled as `.15`. Fails only when instance count >= 2. |
| `SageMaker.16` primary container private registry | Medium | Model | Covered (fixed) | `SM-14` fails on `RepositoryAccessMode == Platform`. Phantom-primary bug for multi-container models fixed. |
| `SageMaker.17` offline feature store KMS (any KMS) | Medium | FeatureGroup | Covered (bug) | `SM-15` logic correct (any KMS), but Passed emits High; register Medium. |
| `SageMaker.18` online feature store standard-storage KMS (any KMS) | Medium | FeatureGroup | Gap | No `OnlineStoreConfig.SecurityConfig.KmsKeyId` check. |
| `SageMaker.19` multi-container private registry | Medium | Model | Covered (fixed) | `SM-14` iterates `Containers[]`; VPC-mode multi-container models now pass instead of false-failing on a phantom primary container. |
| `SageMaker.20` explainability network isolation | High | ModelExplainabilityJobDefinition | Gap | No explainability job-definition calls. Register-decision vs family band. |
| `SageMaker.21` notebook storage CMK | Medium | NotebookInstance | Covered (bug) | `SM-03` bundles resources, wrong severities, unreliable substring CMK test. |
| `SageMaker.22` monitoring traffic encryption | Medium | MonitoringSchedule | Gap | Monitoring check only inspects isolation; must handle named definitions. |
| `SageMaker.23` inference experiment instance storage CMK | Medium | InferenceExperiment | Gap | No inference-experiment calls. |
| `SageMaker.24` inference experiment data storage CMK | Medium | InferenceExperiment | Gap | No `DataStorageConfig.KmsKey` check; applies only when data capture is enabled. |
| `SageMaker.25` model quality network isolation | High | ModelQualityJobDefinition | Gap | No quality job-definition calls. Register-decision vs family band. |

Covered (15, after fixes): AgentCore `.1`, `.2`, `.3`, `.4`, `.6`; SageMaker
`.1`, `.2`, `.3`, `.5`, `.9`, `.14`, `.16`, `.17`, `.19`, `.21`. Of these, 8
had defects (AgentCore `.3`, `.4`; SageMaker `.1`, `.5`, `.14`, `.16`/`.19`,
`.17`, `.21`); AgentCore `.3` and SageMaker `.16`/`.19` are already fixed in
code, and `BedrockAgentCore.6` moved from Gap to Covered via the `AC-06`
rewrite. The remaining defects (AgentCore `.4`; SageMaker `.1`, `.5`, `.14`,
`.17`, `.21`) are PR-0 register/disposition work.

## Authoritative Control Reference For The Remaining 16 Gaps

Severity, resource, API, field, and exact fail condition verified from each AWS
control-detail page. "Sev" is the Security Hub published severity that seeds the
register. Implement the fail condition exactly. (`BedrockAgentCore.6` has been
implemented via the `AC-06` rewrite and is retained below as the reference its
implementation was built against.)

| Control | Sev | API (client) | Field | Fail condition |
| --- | --- | --- | --- | --- |
| `Bedrock.1` | Medium | `bedrock-agent`: `ListKnowledgeBases` -> `ListDataSources` -> `GetDataSource` | `dataSource.serverSideEncryptionConfiguration.kmsKeyArn` | Not encrypted with a customer managed KMS key (presence-as-proxy; Rule 1). |
| `BedrockAgentCore.5` | High | `bedrock-agentcore-control`: `ListBrowsers`, `GetBrowser` | `networkConfiguration.networkMode` (enum `PUBLIC`, `VPC`) | Network mode is `PUBLIC`. Custom browsers only (Rule 7). |
| `BedrockAgentCore.6` (implemented) | Medium | `bedrock-agentcore-control`: `ListBrowsers(type=CUSTOM)`, `GetBrowser` | `recording.enabled`, `recording.s3Location.bucket` | Recording disabled OR no S3 bucket. Custom browsers only (server-side `type` filter, Rule 7). |
| `BedrockAgentCore.7` | High | `bedrock-agentcore-control`: `ListCodeInterpreters`, `GetCodeInterpreter` | `networkConfiguration.networkMode` (enum `PUBLIC`, `SANDBOX`, `VPC`) | Network mode is `PUBLIC` or `SANDBOX`. Custom code interpreters only. |
| `SageMaker.4` | Medium | `sagemaker`: `ListEndpointConfigs`, `DescribeEndpointConfig` | `ProductionVariants[*].InitialInstanceCount` | Instance-based variant has only 1 initial instance. Skip serverless variants. |
| `SageMaker.8` | Medium | `sagemaker`: `DescribeNotebookInstance` | `PlatformIdentifier` | Not the supported value `notebook-al2-v3`. |
| `SageMaker.10` | Medium | `sagemaker`: `ListModelExplainabilityJobDefinitions`, `Describe...` | `NetworkConfig.EnableInterContainerTrafficEncryption` | Not enabled. |
| `SageMaker.11` | Medium | `sagemaker`: `ListDataQualityJobDefinitions`, `Describe...` | `NetworkConfig.EnableNetworkIsolation` | Disabled or not configured. |
| `SageMaker.12` | Medium | `sagemaker`: `ListModelBiasJobDefinitions`, `Describe...` | `NetworkConfig.EnableNetworkIsolation` | Disabled or not configured. |
| `SageMaker.13` | Medium | `sagemaker`: `ListModelQualityJobDefinitions`, `Describe...` | `NetworkConfig.EnableInterContainerTrafficEncryption` | Not enabled. |
| `SageMaker.15` | Medium | `sagemaker`: `ListModelBiasJobDefinitions`, `Describe...` | `NetworkConfig.EnableInterContainerTrafficEncryption`, `JobResources.ClusterConfig.InstanceCount` | Encryption false/absent AND instance count >= 2. |
| `SageMaker.18` | Medium | `sagemaker`: `ListFeatureGroups`, `DescribeFeatureGroup` | `OnlineStoreConfig.EnableOnlineStore`, `StorageType`, `SecurityConfig.KmsKeyId` | Standard-storage online store has no KMS key (any KMS satisfies). Evaluate only `StorageType == Standard`. |
| `SageMaker.20` | High | `sagemaker`: `ListModelExplainabilityJobDefinitions`, `Describe...` | `NetworkConfig.EnableNetworkIsolation` | Disabled or not configured. Register-decision (High vs family Medium). |
| `SageMaker.22` | Medium | `sagemaker`: `ListMonitoringSchedules`, `DescribeMonitoringSchedule` (+ named-definition resolution) | `MonitoringJobDefinition.NetworkConfig.EnableInterContainerTrafficEncryption` | Not enabled. Handle inline and named definitions (see `.14` defect). |
| `SageMaker.23` | Medium | `sagemaker`: `ListInferenceExperiments`, `DescribeInferenceExperiment` | `KmsKey` | No KMS key for instance storage volume (customer managed; presence-as-proxy). |
| `SageMaker.24` | Medium | `sagemaker`: `ListInferenceExperiments`, `DescribeInferenceExperiment` | `DataStorageConfig.KmsKey` | Data capture enabled but no KMS key. Skip experiments without data capture. |
| `SageMaker.25` | High | `sagemaker`: `ListModelQualityJobDefinitions`, `Describe...` | `NetworkConfig.EnableNetworkIsolation` | Disabled or not configured. Register-decision (High vs family Medium). |

Verified SDK facts (botocore 1.43.21, subset of deployed 1.43.32): browser
`networkMode` enum `PUBLIC`,`VPC`; code interpreter `PUBLIC`,`SANDBOX`,`VPC`;
`GetBrowser.recording` = `enabled`, `s3Location{bucket,prefix,versionId}`;
`OnlineStoreConfig` = `SecurityConfig{KmsKeyId}`, `EnableOnlineStore`,
`TtlDuration`, `StorageType`(`Standard`,`InMemory`); `.15` is the only
traffic-encryption control with an instance-count condition.

## Correctness Rules That Apply To Every Check

Rule 1: Apply the correct KMS standard per control, using presence-as-proxy.

- Customer-managed required (control text says "customer managed"): `Bedrock.1`,
  `BedrockAgentCore.3`, `BedrockAgentCore.4`, `SageMaker.21`, `SageMaker.23`,
  `SageMaker.24`.
- Any KMS key accepted (control fails only when no KMS key is configured):
  `SageMaker.17`, `SageMaker.18`. Requiring customer-managed here is a false
  FAIL.
- Detection: the config field holds a key ARN only when the customer set one, so
  presence is the practical signal; document the assumption. Do NOT infer
  customer-managed by string-matching the ARN (the `SM-03` bug uses
  `"aws/sagemaker" in kms_key_id`, which misses AWS-managed keys by key id/ARN
  and false-PASSes). Truly distinguishing `KeyManager = CUSTOMER` requires
  `kms:DescribeKey` (extra IAM, fails cross-account); none of these controls
  need it at the field level.

Rule 2: Severity comes from the register, and one severity applies to a
control's Passed, Failed, and (risk-bearing) rows. Never set severity ad hoc per
`create_finding()` call. The `N/A` family severity comes from the disposition
(next rule), not from the control severity.

Rule 3: Use the disposition model for every non-Pass/Fail outcome (this replaces
the earlier "N/A with reason" invention):

- `NOT_APPLICABLE` (the control's resource type is genuinely absent) ->
  `Status="N/A"`, `Severity="Informational"`.
- `COULD_NOT_ASSESS` (access denied, unsupported region, or SDK field missing)
  -> use `_could_not_assess_row(...)`: `Status="N/A"`, `Severity="Low"`, name
  `"COULD NOT ASSESS: ..."`. Never `Failed`, never a silent "no resources".
- `ADVISORY` (no AWS API can verify the control) -> `Status="N/A"`,
  `Severity="Informational"`, name prefix `"ADVISORY: "`.

Rule 4: Default-to-fail for isolation controls. An absent isolation flag means
not enabled and must fail (matches "false or not configured").

Rule 5: No-resource vs no-access must be distinguished by disposition
(`NOT_APPLICABLE` vs `COULD_NOT_ASSESS`), not collapsed to the same "no
resources found" `N/A`. The current general checks collapse them; that is a
defect (see "Permission Handling").

Rule 6: Region availability. Reuse the region-availability probe; unavailable
regions are `NOT_APPLICABLE` or `COULD_NOT_ASSESS`, never `Failed`.

Rule 7: Evaluate customer-owned resources only for AgentCore browser and code
interpreter controls. The controls target `BrowserCustom`/
`CodeInterpreterCustom`, and while the list summaries expose no
system-vs-custom flag, `ListBrowsers` and `ListCodeInterpreters` both accept a
`type` request parameter (enum `SYSTEM | CUSTOM`, verified in the deployed
botocore). Call the list APIs with `type="CUSTOM"` so AWS system tools
(`aws.browser.v1`, `aws.codeinterpreter.v1`) are excluded server-side. Do NOT
maintain a hardcoded list of well-known system ids — it would silently rot as
AWS adds system tools. (`AC-06` already implements this pattern.)

## Permission Handling

The three services handle a permission failure three different ways today; only
FinServ is correct.

- SageMaker checks wrap enumeration in `try/except` that logs and continues, so
  an `AccessDenied` on `list_*` leaves the result set empty and the check emits
  `N/A "No ... found."` A customer whose role lacks the permission is told they
  have no notebooks/models/etc. This is a silent understatement of risk (it
  collapses `COULD_NOT_ASSESS` into `NOT_APPLICABLE`).
- SageMaker outer exception handlers emit `Status=Failed, Severity=High` for
  errors that escape the inner try (a false-High risk).
- AgentCore `AG-24` correctly detects `AccessDenied` and returns `N/A`, but tags
  it `Informational`; the methodology says `COULD_NOT_ASSESS -> Low`.
- FinServ routes all of these through `_could_not_assess_row` (`N/A` + `Low` +
  `"COULD NOT ASSESS:"` + remediation naming missing IAM, region, and botocore).

Adopting `COULD_NOT_ASSESS` tool-wide is the fix and also resolves the migration
risk: a customer who deploys new code with an old IAM role sees visible Low
"COULD NOT ASSESS" rows pointing at the role, not a wave of false `Failed` or a
misleading "no resources". Every new check must route enumeration/permission/
region/SDK errors through this helper. Call out the required IAM update
prominently in release notes.

Two adjacent layers had the same defect class and are FIXED:

- Report metrics: `N/A`-status rows previously entered the pass-rate
  denominators by severity, so `COULD_NOT_ASSESS` rows silently depressed the
  displayed pass rate. The template now scores only Passed/Failed rows and
  surfaces `COULD NOT ASSESS` rows in a dedicated "Unassessed Checks" metric
  (see methodology §7 for the enforced scoring rule).
- Orchestration: the state machine catches `States.ALL` per service branch and
  routes to an "Assessment Incomplete" Pass state, so a service Lambda that
  timed out or crashed used to vanish from the report silently. The report
  generator now compares the CSVs found in S3 against the expected
  service/region matrix (and against `enableFinServ` for the FinServ branch)
  and synthesizes visible `COULD NOT ASSESS: <Service> assessment results
  missing` rows (`XX-00` check ids, Low/N-A) for every missing cell.

IAM completeness for the 17 gaps is in "IAM Additions For Parity"; the new
actions there are the only ones the parity checks add.

## SDK Version Management

botocore silently drops response fields it does not model, so an
older-than-required SDK can read a compliant resource as non-compliant. The
control: pin the floor in `requirements.txt` (already 1.43.32) so the build
bundles it; add a cold-start version guard; add a CI service-model guard that
fails the build if a referenced operation/field is missing from the pinned SDK.
The check-level safety net is Rule 3: a version-sensitive field that is absent
is `COULD_NOT_ASSESS` (Low/N/A), never `Failed`.

A README prerequisite asking customers to install a boto3 version is the wrong
control: for a Lambda/SAM solution the effective SDK is the bundled artifact,
not a customer workstation, so the README step adds manual work without
controlling runtime accuracy. A README note documenting the floor is fine for
contributors, not as the accuracy guarantee.

## Security Hub Control Mapping (design)

Repo-local IDs are not Security Hub IDs, the namespaces are crowded and mixed
(`BR-00..BR-32`, `AC-00..AC-13` plus `AG-24..AG-27`, `SM-00..SM-25`), and one
local check can map to more than one Security Hub control (`SM-14` -> `.16` and
`.19`).

Schema facts: each module defines its own `Finding` model and `create_finding()`
with a fixed signature; the FinServ `create_finding` already carries an extra
`compliance_frameworks` field, so extending the finding model is established
precedent. `Check_ID` is validated by `^[A-Z]{2,3}-\d{2}$` (two digits; latent
cap `-99`). The HTML report reads keys defensively with `.get(...)`, so unknown
fields are ignored until the template renders them.

Options:

- Option A (recommended): a static `Check_ID -> [SecurityHub_Control...]` lookup
  applied in the consolidation/report layer, plus a "Security Hub control"
  report column. Lowest blast radius; supports one-to-many; the register keys
  severity by finding-name in parallel.
- Option B: add a `SecurityHub_Control` field to every `Finding` model (as
  FinServ did for `compliance_frameworks`). More invasive but gives per-finding
  provenance in the raw CSV.

Note: adopting the methodology tool-wide means either unifying the five
`Finding`/`create_finding` definitions and the register/disposition helpers, or
replicating them per module. Prefer unifying to avoid drift across modules.

## Mislabeled Checks To Correct

Keep these checks (valid hardening) but remove the incorrect Security Hub labels
and classify them repo-only. Relabeling changes a check's displayed identity;
note the one-time discontinuity for customers who diff reports across runs.

| Function | Currently labeled | Actually implements | Real owner of that number |
| --- | --- | --- | --- |
| `check_sagemaker_processing_job_encryption` | SageMaker.10 | processing-job volume encryption | model explainability traffic encryption |
| `check_sagemaker_transform_job_encryption` | SageMaker.11 | transform-job volume encryption | data quality network isolation |
| `check_sagemaker_hyperparameter_tuning_encryption` | SageMaker.12 | tuning-job encryption | model bias network isolation |
| `check_sagemaker_compilation_job_encryption` | SageMaker.13 | compilation-job encryption | model quality traffic encryption |
| `check_sagemaker_automl_network_isolation` | SageMaker.15 | AutoML network isolation | model bias traffic encryption |

## Corrections From The Second Pass

An independent re-verification of this document against the code, the AWS
control pages, and the deployed botocore found these errors in the first pass;
all are corrected in the text above:

1. "`BR-14` is active, not commented out" was false — the only call site is
   commented out; BR-14 emits nothing (see "Already Closed By Upstream").
2. "The other 8 covered controls are correct" was false — `AC-07`
   (`BedrockAgentCore.3`) had a pass-path severity of High vs the Medium
   control severity, and `SM-14` (`SageMaker.16`/`.19`) false-failed every
   multi-container model via a phantom primary container. Defect count is 8 of
   14, not 6.
3. The drift-guard description overstated the test's guarantee: the runtime
   collection only exercises paths reachable with AWS mocked down, and the
   original test silently skipped emitted names missing from the register. The
   test has been strengthened (bidirectional source-scan) and the description
   updated.
4. Rule 7 prescribed excluding AWS system browser/code-interpreter ids by a
   hardcoded list; `ListBrowsers`/`ListCodeInterpreters` support a server-side
   `type=CUSTOM` filter, which is now the required pattern.
5. The first pass classified `BedrockAgentCore.6` as a plain coverage gap; the
   existing `AC-06` was in fact an active false-FAIL generator (it read a
   field that does not exist in `GetAgentRuntime`, failing every runtime).
   Misclassifying live false positives as "gaps" understates urgency.
6. The report layer's pass-rate denominators counted `N/A`-status rows, which
   contradicted the methodology's stated metric semantics and would have been
   amplified by the tool-wide `COULD_NOT_ASSESS` rollout. The first pass
   missed this cross-layer interaction entirely.
7. The orchestration layer (Step Functions `Catch` -> "Assessment Incomplete")
   could silently drop an entire service or region from the report — the same
   silent-understatement class this document flags at check level, one layer
   up.

## Already Fixed Ahead Of The PR Plan

The following are implemented and tested on this branch, before PR-0. Do not
redo them; do extend their patterns:

- Report metrics: Passed/Failed-only pass-rate denominators; "Unassessed
  Checks" metric; severity legend aligned with the methodology
  (`report_template.py`, shared by the single-account Lambda and the
  multi-account CodeBuild consolidator).
- Missing-service/region synthesis in the report generator
  (`generate_consolidated_report/app.py`), keyed off the expected
  service/region CSV matrix and `enableFinServ`.
- `AC-06` rewrite to `BedrockAgentCore.6` semantics (custom browsers, `type=
  CUSTOM`, recording + S3 bucket, `COULD_NOT_ASSESS` on errors), plus
  `bedrock-agentcore:ListBrowsers`/`GetBrowser` in all five role templates.
- `AC-07` pass-path severity Medium; `AC-01` stale comment and dead
  `subnetIds` sub-check removed.
- `SM-12` serverless-variant skip; `SM-14` phantom-primary fix; the five
  incorrect SageMaker docstring labels corrected to "repo-specific".
- Drift-guard strengthened to the bidirectional source-scan described in
  "Severity Model".
- Docs: `SECURITY_CHECKS.md` wrong mappings fixed (SM-01 -> `.1`, SM-03 ->
  `.21` partial, SM-11 -> `.5`, SM-12 -> `.4`), BR-14 marked disabled, AC-06
  re-described; methodology status/worked-example/§7 metric rule updated;
  register doc status and cross-module CMK divergence note added.

## PR-0 Status: COMPLETE

The severity-model extraction and adoption described in PR-0 above is now
implemented on this branch:

- `agentcore_assessments/severity_disposition.py`,
  `bedrock_assessments/severity_disposition.py`,
  `sagemaker_assessments/severity_disposition.py` — one sibling module per
  service (matching the existing `schema.py` per-module duplication
  precedent, not a shared Lambda layer), each with `_DISPOSITION_SEVERITY`,
  `COULD_NOT_ASSESS_PREFIX`, `could_not_assess_row(...)`, and a
  `SEVERITY_REGISTER` (AgentCore: 46 entries, AC-00..AC-15 + AG-24..27;
  Bedrock: 45 entries, all 34 BR- checks; SageMaker: covers all 39 SM- checks).
  AgentCore's helper is enum-based (`SeverityEnum`/`StatusEnum`) to match its
  `create_finding` call convention; Bedrock's and SageMaker's are string-based
  (`severity="Low"`) to match theirs.
- Every outer `except Exception` in all three modules' check functions (plus
  both `lambda_handler` enumeration loops in AgentCore) now returns
  `could_not_assess_row(...)` instead of a fabricated `Failed`/`High` result.
  This closes the `AC-12` fix already noted above, plus the `SM-11`/`SM-15`
  Passed/Failed severity-drift fixes and 13 additional Bedrock Passed/Failed
  drift cases (Agent Action Group IAM Least Privilege, Agent Guardrail
  Association, Automated Reasoning Policy Implementation, Batch Inference
  Output Encryption, Bedrock Custom Model Encryption, Bedrock Flows
  Guardrails, Bedrock Knowledge Base Encryption, Imported Model CMK
  Encryption, Knowledge Base CMK Encryption, Model Evaluation Implementation,
  Model Invocation Throttling Limits, Prompt Flow Validation, Bedrock
  CloudTrail Logging).
- Inner enumeration failures previously silently collapsed into a false
  "no resources found" `N/A` (Rule 5 violation) were converted to re-raise
  into the outer handler: AgentCore `AC-04`, `AC-05` (ECR), `AC-10`
  (runtime/gateway listing loops); SageMaker's `_list_job_definitions_with_
  details` callers across SM-29..SM-39, plus `SM-06` (Clarify), `SM-08`
  (Model Registry), `SM-25` (ML Lineage, both the Experiments and Model
  Package Lineage enumeration branches, including a middle-level wrapper
  `try/except` that had been re-swallowing the inner `raise`), `SM-28`
  (Notebook Platform). A further Rule-5 pattern — a per-component `except`
  that appended a fabricated `High`/`Medium`/`Failed` "component check error"
  dict alongside real findings instead of a disposition — was found and fixed
  in `SM-05` (Model Registry/Feature Store/Pipelines sub-checks), `SM-06`
  (Clarify), `SM-07` (Model Monitor), and `SM-08` (per-group model check).
  AgentCore's `AC-10` `policy_access_denied`/`policy_check_errors` branches
  and `AG-24`'s per-gateway `get_gateway` failure branch moved from
  `Informational` to `COULD_NOT_ASSESS` (Low).
- A per-module drift-guard test file mirrors
  `finserv_tests/test_severity_register.py`'s bidirectional source-scan:
  `tests/test_agentcore_severity_register.py`,
  `tests/test_bedrock_severity_register.py`,
  `tests/test_sagemaker_severity_register.py`. Existing check tests
  (`tests/test_agentcore_checks.py`, `tests/test_bedrock_checks.py`,
  `tests/test_sagemaker_checks.py`) were updated wherever they asserted the
  old fabricated `Failed`/`High` (or under-severitied `Informational`)
  exception behavior.
- The AG-24 -> `BedrockAgentCore.2` gap in `SECURITY_HUB_CONTROL_MAP`
  (`generate_consolidated_report/report_template.py`) is closed.
- Verified: full `tests/` suite = 517 passed (in both forward and reverse
  file-collection order — the register tests' `sys.modules` cache-eviction
  guard, needed because `agentcore_assessments`, `bedrock_assessments`, and
  `sagemaker_assessments` each define their own same-named
  `schema.py`/`severity_disposition.py`, is now applied consistently in all
  three `test_*_checks.py` and all three `test_*_severity_register.py`
  files); `finserv_tests/` = 582 passed, unchanged; `ruff check` clean on all
  touched files.

Not addressed by this PR-0 pass (still open per "Coverage Matrix" and the
remaining PRs above): the wrong-resource/mislabeling defects (`SM-01` domain
scope, `SM-03` substring KMS test + resource-bundling split, `SM-13` named
monitoring-definition resolution, the five SageMaker.10-.15 mislabeled
functions), and the 16 coverage gaps in PR-1/PR-2/PR-3. Those require
check-logic changes, not severity/disposition mechanics, and remain future
work.

## Already Closed By Upstream (do not redo)

- `BedrockAgentCore.2` gateway inbound authorization is implemented (`AG-24`).
- `BedrockAgentCore.4` gateway CMK uses the correct list key and
  `gatewayIdentifier` (has the severity bug above).
- `BedrockAgentCore.3` memory CMK reads the correct key field and fails closed.
- The `list_gateways`/`get_gateway` API-shape bugs are resolved.
- `bedrock-agentcore:GetResourcePolicy` is already granted in templates.
- CORRECTION: the first pass claimed "`BR-14` is active, not commented out."
  That was wrong. `check_stale_bedrock_access` is defined but its only call
  site is commented out (disabled during the multi-region refactor, most
  likely because it polls `iam:GetServiceLastAccessedDetails` for up to 30
  seconds per identity and can exhaust the Lambda timeout in large accounts).
  It emits no findings today. Re-enabling requires bounding the total wait
  first; the call site and `docs/SECURITY_CHECKS.md` now document the disabled
  status so it cannot be mistaken for an active check.

## Enterprise-Scale And Accuracy Risks

- Meaning of "100% accuracy". A point-in-time API scan cannot equal Security
  Hub's continuous Config evaluation. Define the target as "matches each
  control's documented fail condition for resources the role can enumerate at
  scan time", and position the tool as complementary to enabling the native
  standard.
- Pass-rate shift. Adopting the register moves several findings between bands
  (methodology 7), and the report-layer scoring fix (Passed/Failed-only
  denominators plus the "Unassessed Checks" metric) changes displayed rates on
  its own. Report before/after High-count and pass-rate numbers in the PR
  description so reviewers do not read the shift as a regression.
- Low-prevalence checks. Most new checks target niche, region-limited resources;
  most customers get `N/A`. Prioritize high-prevalence items (`SageMaker.4` fix,
  `Bedrock.1`).
- Parity divergence. `AG-24` is intentionally richer than `BedrockAgentCore.2`.
  Report findings as "aligned with" the standard and reconcile the pass/fail
  edges.
- Finding caps. Some checks itemize only the first N noncompliant resources (for
  example `SM-14` uses `[:15]`); keep summary counts accurate and state the cap.

## IAM Additions For Parity

Add to all core assessment role templates. Prefixes match existing grants.

Bedrock (`bedrock-agent` client -> `bedrock:` prefix):

- `bedrock:ListDataSources`, `bedrock:GetDataSource` (`ListKnowledgeBases`
  already present). Note: these two actions already exist in the FinServ
  function's role statement in every template (for the FS knowledge-base
  checks); the addition here is to the core Bedrock assessment role, which
  lacks them. Do not mistake the FinServ grant for coverage.

AgentCore (`bedrock-agentcore:` prefix):

- DONE: `bedrock-agentcore:ListBrowsers`, `GetBrowser` (added to all five
  templates for the `AC-06` rewrite).
- Remaining: `bedrock-agentcore:ListCodeInterpreters`, `GetCodeInterpreter`
  (for `BedrockAgentCore.7`).

SageMaker (`sagemaker:` prefix; only these are new. Feature-group and
monitoring-schedule permissions already exist, so `.18` and `.22` need no new
SageMaker IAM):

- `ListEndpointConfigs`, `DescribeEndpointConfig`,
  `ListModelExplainabilityJobDefinitions`,
  `DescribeModelExplainabilityJobDefinition`, `ListModelBiasJobDefinitions`,
  `DescribeModelBiasJobDefinition`, `ListModelQualityJobDefinitions`,
  `DescribeModelQualityJobDefinition`, `ListInferenceExperiments`,
  `DescribeInferenceExperiment`.

Templates to update: `aiml-security-assessment/template.yaml`,
`template-multi-account.yaml`, `deployment/1-aiml-security-member-roles.yaml`,
`deployment/2-aiml-security-codebuild.yaml`,
`deployment/aiml-security-single-account.yaml`.

## Locked PR Plan

### PR-0 (severity model + covered-control correctness; one PR covering both
extraction and adoption)

- Extract the register + disposition helpers so Bedrock/AgentCore/SageMaker can
  use them (unify the finding model/helpers across modules) and adopt them in
  the same PR. Publish before/after High-count and pass-rate numbers in the PR
  description so reviewers can separate the mechanical extraction from the
  behavioral adoption.
- Build the general-check `SEVERITY_REGISTER` seeded from Security Hub published
  severities; record the `SageMaker.20`/`.25` High-vs-Medium decision. Key the
  register with the source-scan guard from day one (see "Severity Model"):
  finding names are display strings, and without the bidirectional scan a
  rename silently orphans its register entry.
- Route all no-resource / access-denied / region / SDK-gap paths through the
  `NOT_APPLICABLE` and `COULD_NOT_ASSESS` dispositions; remove the SageMaker
  outer-except `Failed/High` handlers and the AgentCore `Informational`
  access-denied severity. (`AC-06` already implements the target pattern.)
- Fix the remaining covered-control defects via the register/disposition
  adoption (`AC-12`, `SM-11`, `SM-13` named-definition, `SM-15`, `SM-03` split
  + KMS-test, `SM-01` domain reclassification). `AC-07` and `SM-14` are
  already fixed (see "Already Fixed Ahead Of The PR Plan").
- Extend the drift-guard to all modules using the bidirectional source-scan
  pattern (static finding names <-> register keys, plus runtime severity
  equality; `Informational` only for genuine `N/A`).
- Report-layer scoring, the "Unassessed Checks" metric, the legend update, and
  the missing-service synthesis are already done — verify, do not reimplement.

### PR-1 (mapping + labeling + wrong-resource fix)

- Security Hub mapping (Option A) and a report column.
- Remove the 5 incorrect SageMaker labels; reclassify repo-only.
- Fix `SageMaker.4` (endpoint configs, `InitialInstanceCount`, skip serverless).

### PR-2 (Bedrock + AgentCore parity)

- `Bedrock.1`; `BedrockAgentCore.5`, `.7` (custom resources only, via the
  `type=CUSTOM` list filter; `.6` is already implemented by the `AC-06`
  rewrite).
- Register entries seeded from SH severity; IAM
  (`ListCodeInterpreters`/`GetCodeInterpreter`; browser actions already
  granted); dispositions; tests.

### PR-3 (SageMaker parity)

- `.8`, `.10`, `.11`, `.12`, `.13`, `.15`, `.18`, `.20`, `.22`, `.23`, `.24`,
  `.25`.
- PR-3a: the seven Clarify/Model-Monitor job-definition controls via one
  table-driven helper (also supplies the named-definition resolution for
  `.14`/`.22`). PR-3b: online feature store KMS, inference experiments, notebook
  platform, monitoring traffic encryption.

## Testing And Validation Requirements

- Extend the register drift-guard test to Bedrock/AgentCore/SageMaker: every
  emitted `severity=` equals the register; `Informational` only for genuine
  `N/A`; matrix and disposition helpers match the methodology tables.
- For each new or rewritten check: pass, fail, no-resource (`NOT_APPLICABLE`),
  access-denied (`COULD_NOT_ASSESS`), and absent-version-sensitive-field
  (`COULD_NOT_ASSESS`) cases.
- KMS tests: customer-managed controls, absent key -> Failed, present key ->
  Passed (presence-as-proxy); `.17`/`.18`, an AWS-managed KMS key -> Passed.
- `SageMaker.4` serverless-variant skip; `SageMaker.15` single-vs-multi-instance;
  named-monitoring-definition tests for `.14` (regression) and `.22`.
- AgentCore browser/code-interpreter tests that exclude AWS system tools.
- CI service-model guard for the pinned SDK.
- Use botocore 1.43.32 response shapes in fixtures.

## Documentation And Reporting Cleanup

- Add a condensed severity-methodology section to the README and link it from
  the report, and document the ASFF label mapping (methodology 5).
- Correct `docs/SECURITY_CHECKS.md` mappings and counts; recalculate any
  "N core / M total" claims.
- Regenerate sample reports only after implementation is stable; note the
  pass-rate/severity-count shift.
- Release notes: required IAM update, SDK floor, and the severity re-banding.

## Challenged Assumptions

- "Match Security Hub severity" is the standard. False. The repo's standard is
  the documented L x I methodology expressed in ASFF labels. For general checks
  the Security Hub severity is the authoritative input to that framework, not a
  parallel rule.
- A new finding status is needed for permission/SDK gaps. False. The existing
  `COULD_NOT_ASSESS` disposition (`N/A` + `Low`) already handles it and is
  drift-guarded — but only once the report layer stops counting `N/A`-status
  rows in pass-rate denominators (now fixed; see "Permission Handling").
- Covered means correct. False. 8 of 14 covered controls had defects, most
  traceable to not using the severity methodology, two (AC-07, SM-14) found
  only on re-audit.
- "A false PASS is worse than a false FAIL." Directionally right for
  encryption controls, but not a license to deprioritize false FAILs: the two
  live false-FAIL generators found on re-audit (`AC-06` failing every runtime,
  `SM-12` failing every serverless endpoint) and a pass-rate metric that
  penalized unassessed checks are trust-killers of equal magnitude for a
  report customers screenshot into governance decks. Treat both directions as
  release blockers.
- Are all 17 gaps mandatory? Treat as prioritized by prevalence and
  false-positive risk, not a flat backlog.
- Is Security Hub parity the right goal? Re-implementing Config-rule logic is a
  maintenance treadmill (the standard evolves; `SageMaker.5` was retitled in
  August 2025). Position the tool as a complementary point-in-time lens.

## Bottom Line

The gap list is accurate, and the decisive finding is structural: the repo
already has a documented, tested Likelihood x Impact severity methodology built
to be adopted tool-wide, and the general checks do not use it. Adopting it
(register + disposition model + `_could_not_assess_row` + the strengthened
drift-guard) fixes the remaining covered-control severity defects, gives one
consistent severity philosophy across the whole `.html`, and provides the
correct permission/region/SDK handling (`COULD_NOT_ASSESS` = Low/N/A, never a
false FAIL and never a silent "no resources"). The second pass fixed the
prerequisites that adoption depends on: the report layer no longer penalizes
`N/A`-status rows in pass rates and surfaces unassessed checks explicitly,
orchestration-level omissions are now visible, and the two live false-FAIL
generators (`AC-06`, `SM-12` serverless) plus the `SM-14` and `AC-07` defects
are corrected. For the general checks, seed the control severity from the
Security Hub published severity and record it in the register. The top
independent safety item remains `SM-03`'s substring KMS test, which can false
PASS an encryption control.
