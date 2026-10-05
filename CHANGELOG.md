# Changelog

All notable user-facing and deployable changes to this project are documented
in this file.

Changes are accumulated under **Unreleased** as they are merged. Creating a
release is not required for every change. When a version is tagged, move its
entries into a dated version section and create a new empty **Unreleased**
section.

## Unreleased

### Added

- Added independent, default-enabled switches for Bedrock, SageMaker AI,
  AgentCore, and AWS Agent Registry assessments in both deployment modes.
  Disabled services skip their assessment Lambda and CSV requirements; reports
  label them Not selected and explain reduced Agentic AI / OWASP source coverage.
  Optional Responsible AI GRC and OWASP assessments remain independently enabled.
- Added a "Changes since last assessment" report. After each run, every
  account whose run completed gets
  `security_assessment_changes_<YYYYMMDD_HHMMSS>.html` and `.csv` next to its
  main report, comparing the run with the account's previous usable run and
  labeling each finding Resolved, Still open, Regressed, New, No longer
  reported, or No longer assessed. It reads only the existing findings CSVs,
  runs in the CodeBuild post-build phase in both deployment modes, and can't
  fail a run: problems are logged as warnings, and the step is skipped when
  little build time is left. The first run of an account is skipped. See
  `docs/ASSESSMENT_HISTORY.md`.
- Added the `EnableAssessmentHistory` deployment parameter (default `true`) to
  both deployment templates, passed to CodeBuild as
  `ENABLE_ASSESSMENT_HISTORY`. Set it to `false` to turn the report off. A
  CodeBuild project without the variable (a stack not yet updated) is treated
  as `true`.
- Added a sample changes report (`sample-reports/security_assessment_changes.html`
  and `.csv`, with `changes-overview.png`), built from the single-account
  sample by `sample-reports/scripts/build_changes_sample.py`; the screenshot
  comes from `sample-reports/scripts/capture_changes_screenshot.py`.

- **30 new checks**, growing the catalog from 208 to 238 checks (124 core).
  - **Amazon Bedrock (17):** `BR-41` Central Guardrail Enforcement, `BR-42`
    Foundation Model Invocation Allow-List, `BR-43` Region Invocation Control,
    `BR-44` Marketplace Model Subscription Control, `BR-45` API Key Governance,
    `BR-46` Knowledge Base Source Data Classification, `BR-47` Bedrock Data
    Path Bucket TLS Enforcement, `BR-48` AI Services Opt-Out Policy
    Enforcement, `BR-49` Guardrail Invocation Deny Enforcement, `BR-50` AI
    User Long-Term Access Key, `BR-51` AI User Console MFA, `BR-52` Bedrock
    Data Path Bucket Object Lock, `BR-53` Bedrock Resource Owner Tag, `BR-54`
    Lambda Function Public Invoke Configuration, `BR-55` KMS Key Enclave
    Attestation Binding, `BR-56` Bedrock LLM Jacking Activity and `BR-57`
    Agent Handoff Source Identity.
  - **Amazon SageMaker AI (13):** `SM-31` Endpoint Inference Data Capture,
    `SM-32` SageMaker Configuration Compliance Evaluation, `SM-33` Training Job
    Network Boundary, `SM-34` SageMaker Creation Guardrails, `SM-35` Security
    Service Delegated Administrator, `SM-36` Security Hub AI Security
    Standard, `SM-37` GuardDuty Lambda Protection, `SM-38` GuardDuty Runtime
    Monitoring, `SM-39` EKS VPC CNI Network Policy, `SM-40` Secrets Manager
    Rotation, `SM-41` AWS IoT Device-Scoped Policy, `SM-42` Batch Transform
    Creation Guardrail and `SM-43` Model Artifact Integrity.
  Behavior worth knowing:
  - A new check that cannot read the whole population it judges reports
    `N/A` naming the failed read or the denied action, not `Passed`.
  - `BR-37` now reads the `bedrock-mantle` data-retention scopes over SigV4
    (`https://bedrock-mantle.<region>.api.aws`), one row per project. The
    mantle account mode is a separate setting from
    `bedrock:GetAccountDataRetention`, and the two can disagree; the row names
    both values.
  - `BR-06` adds a `Bedrock Mantle Data Event Logging` row. Mantle inference is
    a CloudTrail data event, so a trail that selects only `AWS::Bedrock::*`
    types records none of it, and the row fails until all six
    `AWS::BedrockMantle::*` resource types are selected.
  - `BR-56` reads 24 hours of the Region's CloudTrail event history, which
    holds management events only, and names the Bedrock data events it cannot
    see. Unlike Prowler, it fails an identity above the 0.4 share only when one
    of its calls is `PutUseCaseForModelAccess`, `PutFoundationModelEntitlement`,
    `PutModelInvocationLoggingConfiguration`, `CreateFoundationModelAgreement`
    or `AcceptAgreementRequest`. An identity that only read and invoked is named
    in an Informational `N/A` row.
  - `BR-37` judges a mantle project left on the model default on every model
    `bedrock-mantle:ListModels` returns: it fails when a model has no `none` in
    `data_retention.allowed_modes`, and is `N/A` when the models are not read.
  - `BR-41` names an Organizations Bedrock policy attached nowhere on the
    account's organization path in an Informational `N/A` row, and no longer
    fails the account on it.
  - `BR-43` reports an account that owns no custom model as `N/A`, fails a
    custom model resource policy that allows through `NotPrincipal`, and
    credits an `aws:PrincipalOrgID` condition only when it names this
    account's organization.
  - `BR-44` reports an identity whose policy document cannot be parsed in one
    `N/A` row, not as `Failed`.
  - `BR-46` adds a `Prompt PII Screening` row. With no guardrail applied, it
    fails only in a Region that has a Bedrock footprint and whose invocation
    logging is not shown to be off; otherwise it is `N/A`.
  - `BR-49` passes an identity allowed a guardrail-capable action only under a
    `bedrock:GuardrailIdentifier` condition that names an approved guardrail,
    and does not treat a wildcard Allow on resources that name no model as an
    invoker.
  - `BR-52` reports a bucket without a `COMPLIANCE` Object Lock whose AWS Backup
    recovery points were not read as `N/A`, not as `Failed`.
  - `BR-47` and `BR-52` report each data path bucket once. Each bucket gets its
    own row in the bucket's Region, read with `s3:GetBucketLocation`, and the
    row text does not depend on the assessed Region, so a bucket that
    resources in several Regions reference is no longer repeated in the report.
    `BR-52` reads AWS Backup in the bucket's Region. The resources that
    reference each bucket move from the verdict rows to one Informational
    `N/A` row per assessed Region. A check with several enforcing buckets now
    has one `Passed` row per bucket instead of one shared row.
  - `BR-54` and `BR-57` stop at the invocation deadline and name what they did
    not read, instead of running the Lambda into its timeout.
  - An unexpected error in one Bedrock check no longer ends the Bedrock
    assessment. That check reports one `N/A` row named
    `<Check_ID> Check Incomplete`, and every other check still writes its rows
    to the regional CSV.
  - The first "Changes since last assessment" report after upgrading lists
    Bedrock findings whose text was rewritten as "No longer reported" beside
    the same finding as "New", because findings are matched on their text.
    Later reports compare like with like.
  - `SM-43` reads model artifact objects with `HeadObject` and records whether
    an expected value is stored, never that it was compared at load time.
    Weights fetched by container startup code and models served from ECS, EKS
    or EC2 are not read.

### Changed

Existing checks judge the values they read and the whole population they
cover, where many used to pass on the presence of a field or on a partial
read. Rows that passed before can fail after the upgrade. Each row that holds
back `Passed` names what it could not read.

- **IAM permissions cache.** The cache (schema version 2) records each user's
  group policies and each role's and user's permissions boundary, and lists
  under `principal_errors` every principal whose policy or boundary read
  failed. A failed read of one group policy keeps the user's other group
  policies. A role or user deleted during the run is left out of the cache
  instead of being listed. `FS-07` and `FS-22` report a listed principal as not
  read instead of clean, and do not report `Passed` while one is listed. A
  boundary that removes an action now removes it from the grant those checks
  judge. Each managed policy is now fetched once per run.
- **IAM evaluation in the Bedrock and SageMaker AI checks.** Policy
  conditions are read as IAM evaluates them: `ArnEquals` and `ArnLike` both
  treat `*` and `?` as wildcards, values in one condition are ORed, a
  set-operator prefix (`ForAllValues:`, `ForAnyValue:`) is required on a
  multivalued key, and a `*` anywhere in a resource segment that still matches
  every resource reads as unscoped. A negated or `Null`-only condition that
  names a key without enforcing it earns no credit. Every consumer of the IAM
  permissions cache reports a principal listed under `principal_errors` as
  `N/A` instead of clean.
- **Amazon Bedrock.** `BR-01` fails policies that grant every Bedrock action or
  grant it through `NotAction`. `BR-02` reads ECS services, SageMaker notebook
  instances and EC2 instances beside Lambda functions, and fails an AgentCore
  workload without a private DNS endpoint for the plane it calls. `BR-04`
  credits only a lifecycle rule over the log root, with noncurrent-version
  expiration on a versioned bucket. `BR-07` reads the encryption key of every
  numbered prompt version, so an older version with no
  `customerEncryptionKeyArn` fails even when the latest version carries a
  customer managed key, and an unread version is `N/A`. Its flow leg reads each
  flow version an alias routes to (`ListFlowAliases`, `GetFlowVersion`) as well
  as the working draft, so a deployed version that references an unversioned
  prompt fails. The `Bedrock Prompt Variants Check` row is now an Informational
  `N/A` advisory and no longer sets the check status to `WARN`. `BR-10` counts a
  guardrail direction only from a `BLOCK` content filter at `LOW` or above.
  `BR-12` reads the CloudWatch Logs destination and the large-data delivery
  bucket beside the S3 destination, so an account that logs only to CloudWatch
  Logs is judged where it reported `N/A`: the log group needs a customer managed
  key and deletion protection. A `Bedrock Invocation Log WORM Archive` row
  requires each destination to reach an Object Lock `COMPLIANCE` bucket in
  another account, the log group through an unfiltered subscription filter and
  Firehose. `BR-26`, `BR-27` and `BR-34` judge every guardrail version a
  `bedrock:GuardrailIdentifier` condition can pin. `BR-32` sees composite
  alarms. `BR-33` judges per-function Inspector coverage. `BR-37` fails a
  control-plane mode of `aws_review`. `BR-39` adds rows for customization and
  batch inference job VPCs and for every `BR-02` workload granted an AI service,
  judged on its VPC and subnet routes. `BR-53` compares the Resource Groups
  Tagging API with each listed resource type and fails a resource it never
  returned as untagged.
- **Amazon SageMaker AI.** `SM-02`, `SM-11` and `SM-35` add rows for API method
  authorization, Lambda function network boundary and per-Region delegated
  administrators. `SM-04` adds rows for whether GuardDuty findings reach
  Security Hub and an EventBridge rule with a target, and fails an `ACTIVE`
  finding left at workflow status `NEW` for more than 30 days. `SM-09` reads
  Studio user profiles and default space roles. `SM-10` fails a VPC notebook
  whose `DirectInternetAccess` is not `Disabled`. `SM-14` judges every container
  of the models an endpoint or inference component serves, so an unserved model
  is no longer `Failed`, and a Region with no served model is `N/A`. `SM-22`,
  `SM-23` and `SM-31` read shadow variants, batch transform models, monitoring
  baselines and capture options. `SM-26` adds an organization auto-enable row:
  the delegated administrator must report `ALL` for both members and the
  `AI_PROTECTION` feature, and the row is `N/A` in any other account. `SM-34`
  holds every SageMaker action that defines a guardrail key in the service
  authorization reference. `SM-37`, `SM-38` and `SM-39` judge AgentCore
  runtimes, EKS Fargate profiles and node counts, MicroVMs, and the egress of
  every VPC a SageMaker workload runs in. `SM-40` fails a rotation gap over 90
  days. `SM-43` fails an artifact bucket under an AWS managed key.
- **Report wording.** `Passed` text names only what the check read, and
  `Finding_Details` names each unread leg instead of describing the whole
  control as satisfied.
- Pinned `boto3` and `botocore` 1.43.108 in every function's
  `requirements.txt` and in `tests/requirements.txt`.

### Deprecated

- The `RequireBedrockZeroDataRetention` deployment parameter is deprecated and
  no longer read. `BR-37` judges the Bedrock data-retention mode at every
  setting, so an account left on `default` now fails where the parameter set
  to `false` used to let it pass. The parameter is still accepted and
  forwarded, so `update-stack` with an existing value keeps working.

### Fixed

- Preserve default-enabled artifact completeness checks when an older CodeBuild
  project has not yet received service-selection environment variables.
- Derive selection notices and scope descriptions from the selected assessments.
  Keep Responsible AI GRC out of direct-service scores and explain that its API
  calls can still assess deselected services, including as an OWASP dependency.
- Emit N/A/Informational coverage rows on each OWASP control affected by omitted
  direct-service evidence, including controls that lose their only source.
  Make the GRC guardrail prerequisite text self-contained.
- The IAM permissions cache no longer drops a principal's policies silently
  when a read fails.
- `BR-02` no longer calls `ecs:ListTasks` without a cluster when
  `ecs:ListClusters` is denied.
- `BR-47` no longer reads a bucket list cut off at its 50-source cap as
  complete and `Passed`.
- `BR-04` no longer names `bedrock-agentcore:GetMemory` as a missing grant.
- `BR-42` and `BR-52` build S3 bucket ARNs in the partition of the Region the
  function runs in, where they hard-coded `aws` and misjudged buckets in
  AWS GovCloud (US) and China Regions.
- `BR-03`, `BR-08` and `BR-21` hold back `Passed` while the IAM permissions
  cache lists a principal under `principal_errors`, as the other cache
  consumers do. `BR-08` reads a policy whose `Statement` is a single object.
- `BR-41` names a failed Organizations policy read by its error code, not by
  the raw exception text.
- The Bedrock assessment Lambda's timeout is 900 seconds, the Lambda maximum,
  up from 600, so its per-read deadline stops 60 seconds before 900 instead of
  before 600.
- `SM-35`'s Detective membership read and `SM-38`'s event data store listing
  stop when a service returns the same `NextToken` twice.
- `SM-23` reports a Region with no InService endpoint as `N/A`, where it used to
  pass with nothing to judge.

### Deployment impact

- **Service selection:** Update `deployment/aiml-security-single-account.yaml`
  for single-account deployments or `deployment/2-aiml-security-codebuild.yaml`
  for multi-account central infrastructure, set the desired service switches,
  then start CodeBuild using this revision. No member-role StackSet update is
  required for this feature. Direct SAM users must redeploy `template.yaml` or
  `template-multi-account.yaml` with the desired `Enable*Assessment` parameters
  and start a new execution. All switches default to true on upgrade.
- **Changes since last assessment report:** A CodeBuild run is required,
  because `buildspec.yml` changed and the new `assessment_history/` package
  runs in the post-build phase. If `GitHubBranch` pins a tag or commit, update
  it first. Updating `deployment/aiml-security-single-account.yaml` or
  `deployment/2-aiml-security-codebuild.yaml` is optional: it adds the
  `EnableAssessmentHistory` parameter, needed only to be able to turn the
  report off. No member-role StackSet update is required. The first run after
  upgrading is compared with the account's latest usable earlier run, if one
  is in the bucket. In single-account mode each run also writes a small
  `assessment_history_run_<execution_id>.json` next to its findings CSVs,
  recording whether the run succeeded and which services it selected, so a
  failed run is never used as the previous run. It isn't written while
  `EnableAssessmentHistory` is `false`. With service selection, only the
  services selected in both runs are compared; a service selected in only one
  of them is listed as not compared.

These instructions assume the 2.0.0 prerequisites below are already applied.
When upgrading from an earlier release, complete the 2.0.0 member-role and
central infrastructure updates first. Then apply this feature's parameters
and rerun CodeBuild to deploy the assessment/report changes. No additional
IAM permissions are introduced by service selection.

**New checks.** Apply these updates in order.

1. **Multi-account member-role StackSet update required first** because
   `deployment/1-aiml-security-member-roles.yaml` changed. The member
   deployment role gains the `AssessmentManagedPolicyLifecycle` statement
   (`iam:CreatePolicy`, `iam:DeletePolicy`, `iam:GetPolicy`,
   `iam:GetPolicyVersion`, `iam:ListPolicyVersions`, `iam:CreatePolicyVersion`,
   `iam:DeletePolicyVersion` and `iam:ListEntitiesForPolicy` on the account's
   `policy/aiml-security-*` and `policy/aiml-sec-*` ARNs), and its
   `iam:AttachRolePolicy` and `iam:DetachRolePolicy` condition admits those two
   policy patterns beside `AWSLambdaBasicExecutionRole`. Without it, the next
   assessment deploy fails with `iam:CreatePolicy` denied and rolls back.
2. **Central or single-account infrastructure update required next** because
   `deployment/2-aiml-security-codebuild.yaml` and
   `deployment/aiml-security-single-account.yaml` changed. The CodeBuild
   deployment role gains the same managed-policy permissions.
3. **CodeBuild run required last.** Rerun CodeBuild; it redeploys the AWS SAM
   template for your mode. Direct SAM users must redeploy the template they
   use.

The AWS SAM templates (`aiml-security-assessment/template.yaml` and
`aiml-security-assessment/template-multi-account.yaml`) carry the same IAM
change:

- Four new `AWS::IAM::ManagedPolicy` resources, each attached only to one
  assessment function, for reads that do not fit that function's
  9,000-character inline policy budget: `BedrockAssessmentReadsPolicy` and
  `BedrockAssessmentReadsPolicy2` and `SageMakerAssessmentReadsPolicy` and
  `SageMakerAssessmentReadsPolicy2`. Each stack creates four more customer
  managed policies, named with the stack name as a prefix.
- New actions on the Bedrock and SageMaker AI assessment roles and the IAM
  permissions cache role. The IAM permissions cache role gains `iam:GetRole` on
  the account's roles, `iam:GetUser` and `iam:ListGroupsForUser` on its users,
  and an `IAMGroupPolicyRead` statement (`iam:ListAttachedGroupPolicies`,
  `iam:ListGroupPolicies` and `iam:GetGroupPolicy`) on its groups. Every new
  action is a Get, List, Describe, Search, BatchGet or Lookup read, except
  `apigateway:GET` (a read), `logs:FilterLogEvents` (a read) and
  `bedrock:ApplyGuardrail`. Actions without a resource type in the service
  authorization reference are granted on `*`. S3 bucket ARNs carry no account,
  so the S3 bucket reads are granted on `arn:${AWS::Partition}:s3:::*` and
  reach any bucket whose policy admits the role. Every other action is scoped
  to this account's resource ARNs, except where noted below. No statement
  grants `Action: '*'`.
- Grants to review before deploying:
  - `bedrock:ApplyGuardrail` (`BR-26`) probes a guardrail's output and is
    billed per text unit. `CrossAccountGuardrailRead` and
    `CrossAccountGuardrailOutputProbe` leave the account segment open, so the
    role can read and apply a guardrail another account shares or the
    organization enforces.
  - `s3:GetObject` on `arn:${AWS::Partition}:s3:::*/*` for the SageMaker AI
    role (`SM-43`), because the buckets are named by the customer. `SM-43`
    calls only `HeadObject`, but the grant also permits reading object contents
    in any bucket whose policy admits the role.
  - The Bedrock role's new `s3:GetObject` is limited to invocation log keys and
    `.metadata.json` objects.
  - `BR-52` reads AWS Backup recovery points with
    `backup:ListRecoveryPointsByResource` (on `*`, which has no resource type)
    and `backup:DescribeRecoveryPoint` (on the account's `recovery-point:*`
    ARNs), and `BR-37` lists models with `bedrock-mantle:ListModels` (on the
    account's mantle `project/*` ARNs). `BR-47` and `BR-52` read each bucket's
    Region with `s3:GetBucketLocation` (on `arn:${AWS::Partition}:s3:::*`).
    All four are reads.
  - `cloudwatch:DescribeAlarms` moves from the account's `alarm:*` ARNs to `*`
    on the Bedrock role, and the SageMaker AI role gains it on `*`, because
    composite alarms are returned only to a `*` grant.
  - `ec2:GetManagedPrefixListEntries`, the Route 53 Resolver firewall rule and
    domain list reads, and the Network Firewall policy and rule group reads
    leave the account segment open, because those resources can be shared
    through AWS RAM.
  - The SageMaker AI role's CloudTrail trail reads (`SM-09`) leave the account
    segment open, because an organization trail's ARN names the management
    account. Its AWS Organizations reads (`organizations:DescribePolicy`,
    `organizations:ListParents` and `organizations:ListTargetsForPolicy`) are
    scoped to organization ARNs, which name the management account too.
  - `ecs:ListTasks` is granted on `*` under an `ArnLike` `ecs:cluster`
    condition on the account's clusters, following the Amazon ECS developer
    guide's example; the service authorization reference names a resource type
    a listing by cluster does not use.
- The Bedrock function now also makes HTTPS calls to
  `bedrock-mantle.<region>.api.aws`.

**Deprecated parameter.** The four templates that declare
`RequireBedrockZeroDataRetention` mark it deprecated in its description and
label. Updating the deployment templates for that is optional; the CodeBuild
run above deploys the SAM template change.

**Lambda timeouts.** The AWS SAM templates raise the Bedrock assessment
function's `Timeout` to 900. A CodeBuild run of this revision deploys it. No
IAM permission changes.

## 2.0.0 - 2026-09-18

This release grows the catalog from 161 checks across five areas to 208 checks
across seven, adding OWASP Top 10 for LLM and AWS Agent Registry as assessment
areas and renaming the Financial Services GenAI risk capability to Responsible
AI GRC. It also hardens the assessment IAM roles and makes incomplete
multi-account coverage fail a run rather than publish a partial report.

Upgrading is not a single step and is not fully backward compatible:

- Apply the updates in the order given under **Deployment impact** below. The
  multi-account member-role StackSet must be updated first.
- `TargetRegions=all` is no longer accepted. Any stored parameter value, saved
  stack input, or automation using it must change to an empty value or an
  explicit region list before upgrading.
- `EnableFinServAssessment` still works as a deprecated alias for
  `EnableResponsibleAIGRCAssessment`, but direct Step Functions input using
  `"enableFinServ": "true"` is rejected.

### Added

- Added AWS Agent Registry as an independent assessment area with its own
  regional Lambda, Step Functions branch, CSV artifact, and HTML report area
  (including a dashboard summary tile and assessment-scope chip), plus an
  `AR-00` through `AR-08` check namespace covering IAM full access, IAM stale
  access, publication approval governance, discovery authorization,
  customer-managed KMS encryption, organization auto-detection, record
  lifecycle governance, and record provenance. Behavior worth knowing:
  - `AR-01` and `AR-02` evaluate attached and inline policies whose
    `Statement` is either a single object or a list. `AR-02` uses IAM
    service-last-accessed data: access older than 60 days fails, while IAM job
    errors and deadlines stay visible as indeterminate `N/A` rows.
  - Record inventory is bounded to 1,000 records and paginates within the
    Lambda deadline. A truncation or deadline notice is reported as an
    additional `N/A`/Informational row and does not discard the records
    already assessed.
  - Absent optional service metadata — approval configuration, discovery
    authorizer, auto-detection, creator attribution, and provenance source
    type — is reported as indeterminate `N/A` rather than as a failure, and an
    unrecognized authorizer type is reported as unsupported instead of as a
    reviewed JWT configuration. Auto-detected records must carry
    `DETECTED_FROM` lineage naming an AgentCore runtime or gateway matching
    the declared source type.
  - Discovery authorization and record lifecycle states are reported as
    informational evidence requiring review rather than as passes.
  - Registries in regions the account has not enabled are reported as
    unavailable, and client initialization or API failures become incomplete
    assessments with error-specific remediation. A single failing check
    produces an incomplete `N/A` row while the regional CSV is still written;
    an unrecoverable CSV-generation or S3-write failure raises so Step
    Functions records the failed task instead of treating a returned
    `statusCode: 500` payload as success.
- Added Agentic AI Security mappings `AG-33` through `AG-38`, derived from the
  new `AR-03` through `AR-08` controls. The catalog now contains 208 checks
  (94 core, 38 Agentic AI, 64 Responsible AI GRC, and 12 OWASP). Agent
  Registry findings are deliberately outside OWASP scope — the `AR-*` controls
  establish Registry governance but do not directly prove an OWASP
  LLM01–LLM10 control — so enabling OWASP does not change Registry counts.
- Added configurable `RequireAgentRegistryManualApproval` and
  `RequireAgentRegistryCMK` deployment baselines. Both are advisory by
  default, so a registry that auto-approves submitted records or uses the AWS
  owned encryption key is reported as informational, and remediation guidance
  is shown only when the baseline requires the control.
- Added SDK contract, IAM coverage, baseline-wiring, registry inventory,
  error-path, and finding-behavior tests, including pass/fail (or advisory
  `N/A`), no-resource, and access-denied coverage for `AR-01` and `AR-04`
  through `AR-07`.

### Changed

- Hardened assessment deployment roles. `AIMLSecurityMemberRole` now contains
  only cross-account deployment, Step Functions polling, and report-retrieval
  permissions; assessment APIs remain exclusively on the SAM-created Lambda
  execution roles. CodeBuild roles now scope Lambda, IAM, S3, and `PassRole`
  access to assessment resources, restrict `PassRole` to Lambda and Step
  Functions, remove stale Lambda/S3 administration actions, and no longer
  define unused local member roles. SAM runtime roles now use exact,
  prefix-scoped S3 artifact permissions instead of bucket-wide
  `S3CrudPolicy`, and remove stale IAM, SageMaker, GuardDuty, AgentCore, ECR,
  Logs, EC2, Lambda, ECS, CloudTrail, and S3 actions. The IAM permission-cache
  Lambda retains only the identity and policy reads it actually performs.
  Per-resource reads are ARN-scoped wherever the AWS service supports it;
  account-level enumeration APIs that do not support resource-level
  authorization (`bedrock:ListGuardrails`, `bedrock:ListPrompts`,
  `bedrock:ListAutomatedReasoningPolicies`, `sagemaker:ListPipelineExecutions`)
  remain on `Resource: "*"` so their checks are not silently denied.
  IAM service-last-access job creation is limited to roles and users in the
  assessed account using partition-aware principal ARNs, and AgentCore metric
  publication is constrained to the `AIMLSecurity/AgentCore` CloudWatch
  namespace.
- Standardized all AWS SDK dependencies on exact `boto3==1.43.85` and
  `botocore==1.43.85` pins.
- Narrowed `AC-02` wildcard findings and `AC-03` stale-access discovery to the
  `bedrock-agentcore` IAM namespace. Overly permissive `agent-registry` grants
  are now reported by `AR-01` and `AR-02`.
- Added end-user guidance for determining whether an upgrade requires only a
  CodeBuild run, a top-level infrastructure stack update, or a multi-account
  member-role StackSet update.
- Clarified that the provided deployment is validated and supported only in
  the standard AWS commercial partition. The README, developer guide,
  troubleshooting guidance, and `TargetRegions` parameter descriptions now
  state that partition-aware implementation details do not establish support
  for AWS GovCloud (US) or AWS China.
- Updated the screenshot capture tool to enforce the repository-root `.venv`,
  install its optional Python dependencies when missing, and verify a
  venv-local Playwright Chromium browser before capturing screenshots. Capture
  height now expands dynamically so every left-navigation section is visible.
- Removed the `all` value from the `TargetRegions` parameter. Scans now target
  either the deployment region (default, empty value) or an explicit comma- or
  space-separated region list; the `all` fan-out is no longer accepted because
  it could produce very long assessment runs and oversized HTML reports. The
  runtime region parsers, the `AllowedPattern` in all four SAM and deployment
  templates, the `buildspec.yml` validation gate, and the README and
  troubleshooting guidance are updated to match.

### Fixed

- Classify Bedrock access-denied results and AgentCore check execution errors
  as incomplete informational `N/A` findings instead of security failures.
  AgentCore now records unexpected errors under each affected `AC-*` or
  `AG-*` control ID, preserves valid findings collected before an error, and
  does not emit a compliant pass when a cached IAM policy cannot be parsed.
  Confirmed workload misconfigurations remain scored failures.
- Treat a missing, unreadable, or malformed IAM permissions cache as an
  incomplete assessment prerequisite instead of replacing it with empty role
  and user collections. Bedrock, SageMaker, AgentCore, and Responsible AI GRC
  cache-dependent controls now emit explicit informational `N/A` rows rather
  than false passes or ambiguous “no permissions” results, while independent
  service checks continue running.
- Correct IAM remediation guidance across Bedrock, AgentCore, Responsible AI
  GRC, and derived OWASP findings. Bedrock model allowlists now use valid
  model and inference-profile ARN scoping instead of the nonexistent
  `bedrock:ModelId` condition key; BR-15 lists every Organizations permission
  it calls; AC-09 documents the exact service-linked-role creation permission
  and condition; AC-11 lists the complete KMS permissions and constraints for
  policy-engine encryption; and FS-27 directs operators to redeploy the
  SAM-created Lambda execution role through CodeBuild instead of changing the
  multi-account member role. Agent Registry stale-access errors no longer
  recommend granting `sts:GetCallerIdentity`, which requires no IAM Allow.
- Correct Bedrock Agents, Flows, Knowledge Bases, and Prompt Management
  remediation guidance to use the valid `bedrock:` IAM namespace instead of
  the `bedrock-agent` boto3 client name.
- Flag wildcard-resource `bedrock:TagResource` and `bedrock:UntagResource`
  grants in FS-22 when reviewing Bedrock Knowledge Base IAM policies.
- Recover assessment deployment stacks in `ROLLBACK_COMPLETE` or
  `DELETE_FAILED` before rerunning SAM deployment. The build now performs this
  recovery for member-account, multi-account management, and single-account
  paths, using narrowly scoped `cloudformation:DeleteStack` permissions for
  assessment and SAM-managed stacks.
- Fail multi-account CodeBuild runs when any expected account cannot deploy,
  start or complete its Step Functions execution, expose its assessment
  bucket, or produce and upload the current execution's required CSV and HTML
  artifacts. The separately launched management-account assessment is always
  included in the expected set, including when `MultiAccountListOverride`
  contains only member accounts. Healthy accounts still complete and upload
  their individual results, but a consolidated report is withheld when
  coverage is incomplete, and the build prints every affected account, stage,
  and reason before exiting unsuccessfully.
- Fail report generation when HTML rendering or S3 upload raises an exception,
  so Step Functions and CodeBuild cannot treat an uploaded error page as a
  successful assessment report. Before rendering, the report Lambda also
  requires a non-empty execution-scoped CSV from every regional service in
  every resolved target region, plus the one-time Responsible AI GRC artifact
  whenever that assessment or OWASP is enabled. The execution-scoped IAM
  permissions cache is still removed on both successful and failed
  report-generation attempts.
- Stop OWASP inventory pagination when an AWS API repeats a continuation token,
  preventing OW-11 or OW-12 from looping until the Lambda timeout.
- Restore `bedrock-agentcore:GetTokenVault` on `Resource: "*"` for AC-14.
  Although the service reference documents a token-vault resource type, the
  runtime authorization request is evaluated against `"*"`. The scoped policy
  therefore returned access denied and silently changed a failed token-vault
  customer-managed-KMS check into informational `N/A`; the Agentic AI and
  OWASP findings derived from AC-14 now receive the real result again.
- Restore CodeBuild and cross-account member-role access to start and poll the
  SAM-generated `AIMLAssessmentStateMachine-*` state machines. The
  least-privilege policies now explicitly include the generated state-machine
  and execution ARN patterns without widening access to unrelated workflows.
- Restore `lambda:ListFunctions` to the Bedrock assessment Lambda role so
  BR-33 can inventory Bedrock-related Lambda functions before checking Amazon
  Inspector code-scanning status, instead of reporting an access-denied
  assessment as informational `N/A`.
- Permit the AgentCore service-linked-role check to return the intended missing
  role finding by authorizing `iam:GetRole` for both the root-path lookup ARN
  and the service-linked-role ARN.
- Keep Bedrock, SageMaker, AgentCore, and Agent Registry stale-access checks
  running when an incomplete or malformed STS caller ARN is returned by
  falling back safely to the standard AWS partition.
- Prevented `FS-22` from flagging assessment-created roles solely for Bedrock
  inventory APIs that AWS requires to use `Resource: "*"`. It still flags
  wildcard Bedrock actions and exact Bedrock actions with supported resource
  scoping that remain unscoped. Corrected the FS-22 action catalog so
  non-scopable query actions do not create false positives and actions with
  supported Bedrock resource scoping—including data-source, association,
  resource-policy, tag, and log-delivery actions—remain covered; remediation
  now identifies the supported resource ARN(s)
  instead of incorrectly prescribing a Knowledge Base ARN for every action.
- Calculate report pass rates from unique direct-service controls instead of
  resource-row counts: any failed assessable row fails its `Check_ID`, controls
  pass only when all assessable rows pass, and N/A rows are excluded.
- Stop `AC-03` IAM last-access polling before the Lambda timeout, preserve
  completed results with an explicit incomplete-assessment row, and classify
  IAM job timeouts as indeterminate instead of failed controls.
- Require `AC-03` candidate permissions to come from attached or inline policy
  documents instead of inferring access from attached-policy names.
- Evaluate attached customer-managed IAM policy documents as well as inline
  policies in `AC-02` and `AC-03`, and score `Allow`/`NotAction` allow-except
  policies only when their exclusions name the AgentCore namespace without
  fully covering it, so an administrator-style grant is treated the same
  whether it is written as `Action: "*"` or as `NotAction`.
- Preserve case-insensitive IAM wildcard matching while supporting embedded and
  partial wildcard action patterns.
- Report AgentCore as unavailable in regions the account has not enabled. A
  missing regional endpoint and the credential-shaped codes AWS returns for a
  disabled region (`UnrecognizedClientException`, `InvalidClientTokenId`,
  `AuthFailure`) are classified as regional unavailability, so scanning all
  partition regions no longer produces per-region rows advising operators to
  troubleshoot DNS, VPC routing, or credentials. Genuinely expired or malformed
  credentials (`ExpiredToken`, `SignatureDoesNotMatch`) and other API failures
  remain incomplete assessments with credential- or error-specific
  remediation.
- Backfill deadline-skipped AgentCore and Agentic AI checks before writing the
  regional CSV so an approaching timeout no longer drops controls from the
  report.
- Make screenshot capture failures, including clipped-sidebar guard failures,
  terminate the capture tool with a non-zero exit status.

### Deployment impact

Apply these updates in order.

1. **Multi-account member-role StackSet update required first** because
   `deployment/1-aiml-security-member-roles.yaml` changed. It creates the
   member-role customer-managed deployment policy and narrows
   `AIMLSecurityMemberRole` to deployment, execution-polling, and
   report-retrieval operations, including narrowly scoped recovery of failed
   assessment or SAM-managed stacks; assessment service API permissions remain
   on SAM Lambda execution roles.
2. **Multi-account central infrastructure update required next** because
   `deployment/2-aiml-security-codebuild.yaml` changed with the AWS Agent
   Registry baselines, least-privilege CodeBuild deployment policy, and
   narrowly scoped failed-stack recovery. This update also removes the obsolete
   conditional local member-role resource if an older stack still tracks it.
3. **Single-account infrastructure update required** because
   `deployment/aiml-security-single-account.yaml` changed with the same
   baselines, CodeBuild policy hardening, and failed-stack recovery. This
   update also removes the obsolete local member-role resource if an older
   stack still tracks it.
4. **CodeBuild run required last** to deploy the updated assessment code,
   dependencies, `buildspec.yml`, and AWS SAM templates
   (`aiml-security-assessment/template.yaml` and
   `aiml-security-assessment/template-multi-account.yaml`). The updated
   buildspec also makes incomplete multi-account coverage fail the run instead
   of publishing an apparently complete consolidated report, and report
   rendering or upload failures now fail the Step Functions execution. The SAM
   templates create the standalone AWS Agent Registry assessment Lambda and
   update the state machine.

The template and CodeBuild updates above also tighten the `TargetRegions`
`AllowedPattern` to reject `all`. Any stored parameter value, saved stack
input, or automation that passes `TargetRegions=all` must be changed to an
empty value or an explicit region list before the next deployment or CodeBuild
run, or CloudFormation/buildspec validation will fail.

Deployments pinned to a tag or commit must update the `GitHubBranch`
CloudFormation parameter to the revision containing these changes before
starting CodeBuild.

## 1.0.0 - 2026-07-10

- Initial tagged release.
