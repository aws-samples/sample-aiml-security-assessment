# AI/ML Security Assessment Framework - Developer Guide

## Table of Contents

- [Agentic Development](#agentic-development)
- [Architecture Overview](#architecture-overview)
  - [Security Design Principles](#security-design-principles)
  - [Architecture Diagrams](#architecture-diagrams)
- [Two-Phase Architecture](#two-phase-architecture)
  - [Phase 1: Infrastructure Deployment](#phase-1-infrastructure-deployment)
  - [Phase 2: Assessment Execution (AWS CodeBuild Orchestration)](#phase-2-assessment-execution-aws-codebuild-orchestration)
  - [Project Structure](#project-structure)
- [Assessment Execution Workflow](#assessment-execution-workflow)
  - [AWS Step Functions State Machine](#aws-step-functions-state-machine)
  - [Service Selection](#service-selection)
- [Assessment Structure](#assessment-structure)
  - [AWS Lambda Functions](#aws-lambda-functions)
  - [Optional Policy Baseline Propagation](#optional-policy-baseline-propagation)
- [Assessment History (Changes Since Last Assessment)](#assessment-history-changes-since-last-assessment)
  - [Modules and Files](#modules-and-files)
  - [Keeping Assessment History in Sync](#keeping-assessment-history-in-sync)
  - [Coverage Gate](#coverage-gate)
  - [Rebuilding the Changes Sample and Golden Files](#rebuilding-the-changes-sample-and-golden-files)
- [Report Generation Architecture](#report-generation-architecture)
  - [Shared Template Module](#shared-template-module)
  - [How It Works](#how-it-works)
  - [Modifying the Report Template](#modifying-the-report-template)
- [Adding a New Check Inside an Existing Service](#adding-a-new-check-inside-an-existing-service)
  - [Check ID, Status, and Severity Conventions](#check-id-status-and-severity-conventions)
- [Adding New AI/ML Service Assessments](#adding-new-aiml-service-assessments)
  - [Step 1: Create the Service Assessment Function](#step-1-create-the-service-assessment-function)
  - [Step 2: Update the AWS SAM Templates](#step-2-update-the-aws-sam-templates)
  - [Step 3: Update the AWS Step Functions Definition](#step-3-update-the-aws-step-functions-definition)
  - [Step 4: Wire Service Selection and Report Artifacts](#step-4-wire-service-selection-and-report-artifacts)
  - [Step 5: Update AWS IAM Permissions](#step-5-update-aws-iam-permissions)
  - [Step 6: Test Locally](#step-6-test-locally)
- [Extending or Adding Lenses](#extending-or-adding-lenses)
- [Adding a Compliance Standard (OWASP-style)](#adding-a-compliance-standard-owasp-style)
  - [1. Choose a Check ID prefix](#1-choose-a-check-id-prefix)
  - [2. Create the Lambda package](#2-create-the-lambda-package)
  - [3. Wire the opt-in flag through deployment and execution](#3-wire-the-opt-in-flag-through-deployment-and-execution)
  - [4. Add IAM grants for APIs and CSV artifacts](#4-add-iam-grants-for-apis-and-csv-artifacts)
  - [5. Add the Step Functions Choice state](#5-add-the-step-functions-choice-state)
  - [6. Register the standard in the report](#6-register-the-standard-in-the-report)
  - [7. Check routing and artifact completeness](#7-check-routing-and-artifact-completeness)
  - [8. Update documentation](#8-update-documentation)
  - [9. Add tests](#9-add-tests)
  - [10. Generate and verify the HTML report](#10-generate-and-verify-the-html-report)
- [Testing Your Extensions](#testing-your-extensions)
  - [1. Local Testing](#1-local-testing)
  - [2. Integration Testing](#2-integration-testing)
  - [3. Multi-Account Testing](#3-multi-account-testing)
  - [4. Report Verification (Required Before Opening a PR)](#4-report-verification-required-before-opening-a-pr)
- [Documentation and Screenshots](#documentation-and-screenshots)
  - [Updating Sample Reports](#updating-sample-reports)
  - [Documentation Best Practices](#documentation-best-practices)
- [Contributing and Releases](#contributing-and-releases)
  - [Declaring Deployment Impact](#declaring-deployment-impact)
- [CI/CD Workflows](#cicd-workflows)
  - [PR Checks](#pr-checks)
  - [Post-Merge and Automation Workflows](#post-merge-and-automation-workflows)
  - [Running Checks Locally](#running-checks-locally)
- [Support and Resources](#support-and-resources)
  - [Debugging](#debugging)
  - [Documentation](#documentation)

---

## Agentic Development

AI coding agents should load the repository-root [AGENTS.md](../AGENTS.md)
first; it is the canonical source for repository conventions and review gates.
[CLAUDE.md](../CLAUDE.md) only delegates to it. This guide covers the
implementation workflows and architecture behind those conventions.

## Architecture Overview

The AI/ML Security Assessment Framework is a serverless, multi-account security
assessment solution for AWS AI/ML workloads. It performs 94 core security checks
across Amazon Bedrock, Amazon SageMaker AI, Amazon Bedrock AgentCore, and AWS
Agent Registry. It also synthesizes up to 38 Agentic AI Security checks from the
selected Amazon Bedrock, Amazon Bedrock AgentCore, and AWS Agent Registry
assessments, and offers an optional 64-check Responsible AI GRC assessment and
an optional 12-check OWASP Top 10 for LLM assessment. Results are rendered as
interactive HTML reports with findings and remediation guidance.

The current deployment is validated only in the standard AWS commercial
partition (`aws`). Partition-aware implementation details must not be treated
as support for AWS GovCloud (US) (`aws-us-gov`) or AWS China (`aws-cn`).
Adding either partition requires a service-availability review, partition-safe
Step Functions integrations and generated URLs, and end-to-end validation of
both single-account and multi-account deployment modes.

### Security Design Principles

- Runtime assessment Lambda roles are read-oriented and scoped per function to the APIs that function calls.
- AWS CodeBuild and member-account roles hold deployment permissions only: they create or update the SAM assessment stacks, poll executions, and retrieve reports.
- Cross-account trust is limited to the AWS CodeBuild role in the central assessment account.
- Amazon S3 buckets enforce SSL-only access, and assessment data is encrypted in transit and at rest.
- No persistent credentials are stored in AWS CodeBuild.

### Architecture Diagrams

#### Phase 1: Deployment Setup (AWS CloudFormation)

![Deployment Phase](./diagrams/deployment-phase.png)

#### Phase 2: Assessment Execution (AWS CodeBuild)

![Execution Phase](./diagrams/execution-phase.png)

#### Service-Level Assessment Architecture

![Service-Level Architecture](./diagrams/service-level-architecture.png)

## Two-Phase Architecture

Phase 1 deploys roles and central infrastructure with AWS CloudFormation.
Phase 2 runs `buildspec.yml` in AWS CodeBuild, which deploys the AWS SAM
assessment stack into each account and starts its AWS Step Functions
execution. Single-account mode uses one template,
`deployment/aiml-security-single-account.yaml`, whose `CodeBuildRole` deploys
directly in the same account. Multi-account mode uses the two templates
described below.

### Phase 1: Infrastructure Deployment

#### Step 1: Member Account Roles (`1-aiml-security-member-roles.yaml`)

- **AWS CloudFormation StackSets deployment**: Deploys `AIMLSecurityMemberRole` to all target accounts.
- **Cross-account trust**: Trusts the central assessment account's CodeBuild role.
- **Deployment permissions**: Grants only the cross-account deployment, Step Functions execution-polling, and report-retrieval permissions CodeBuild needs to create or update per-account SAM stacks. The SAM-created Lambda execution roles hold the assessment-service API permissions.

#### Step 2: Central Infrastructure (`2-aiml-security-codebuild.yaml`)

- **AWS CodeBuild project**: Orchestrates multi-account deployments and assessments.
- **Amazon S3 bucket**: Central storage for consolidated assessment results.
- **AWS IAM role**: `MultiAccountCodeBuildRole`, which assumes the member role in each account.
- **Amazon SNS topic**: Optional email notifications for build state changes.
- **Amazon EventBridge rule**: Forwards CodeBuild state changes to the SNS topic.
- **AWS Lambda trigger**: Starts the CodeBuild project automatically after stack creation.

<a id="aws-codebuild-orchestration"></a>

### Phase 2: Assessment Execution (AWS CodeBuild Orchestration)

#### AWS CodeBuild Execution Flow

1. **Account discovery**: In multi-account mode, lists active accounts from AWS Organizations, or uses `MultiAccountListOverride`.
2. **Role assumption**: In multi-account mode, assumes `AIMLSecurityMemberRole` in each target account.
3. **AWS SAM deployment**: Deploys or updates the assessment stack (`aiml-security-<account-id>` for member accounts, `aiml-security-mgmt` for the central account that runs CodeBuild, which multi-account runs always assess, or `aiml-sec-<account-id>` in single-account mode). The stack contains these AWS Lambda functions:
   - Amazon Bedrock assessment (`BedrockSecurityAssessmentFunction`)
   - Amazon SageMaker AI assessment (`SagemakerSecurityAssessmentFunction`)
   - Amazon Bedrock AgentCore assessment (`AgentCoreSecurityAssessmentFunction`)
   - AWS Agent Registry assessment (`AgentRegistrySecurityAssessmentFunction`)
   - Responsible AI GRC assessment (`ResponsibleAIGRCAssessmentFunction`)
   - OWASP Top 10 for LLM assessment (`OWASPSecurityAssessmentFunction`)
   - Amazon S3 cleanup (`CleanupBucketFunction`)
   - AWS IAM permission caching (`IAMPermissionCachingFunction`)
   - Region resolution (`ResolveRegionsFunction`)
   - Consolidated report generation (`GenerateConsolidatedReportFunction`)
4. **Assessment execution**: Starts the AWS Step Functions workflow in each account, passing `enableResponsibleAIGRC` and `enableOWASP` from the deployment parameters. Service selection is baked into the stack (see [Service Selection](#service-selection)).
5. **Results collection**: Each assessment Lambda writes its CSV to the account's local Amazon S3 bucket, and the report Lambda writes the per-account HTML report.
6. **Consolidation**: CodeBuild copies each account's artifacts to the central bucket and, for multi-account runs with no recorded account failures, builds the consolidated HTML report (`consolidated-reports/security_assessment_multi_account_<timestamp>.html`) with `consolidate_html_reports.py`.
7. **Changes report**: In the post-build phase, `run_changes_report` compares each account with its previous usable run (see [Assessment History](#assessment-history-changes-since-last-assessment)).
8. **Notification**: Sends a completion notification through Amazon SNS, if configured.

#### Member Account Resources (Deployed by AWS SAM)

- **AWS SAM application**: The AI/ML security assessment stack.
- **AWS Step Functions**: A single workflow orchestrating all assessments.
- **AWS Lambda functions**: The functions listed above. The Responsible AI GRC Lambda is invoked only when Responsible AI GRC is enabled or OWASP needs its `FS-*` source rows; the OWASP Lambda is invoked only when OWASP is enabled.
- **Local Amazon S3 bucket**: Storage for account-specific results.

### Project Structure

<details>
<summary>Repository layout</summary>

```text
sample-aiml-security-assessment/
├── README.md                         # Project overview and deployment guide
├── AGENTS.md                         # Canonical AI coding-agent guidance
├── CLAUDE.md                         # Compatibility shim that loads AGENTS.md
├── CHANGELOG.md                      # Release history and deployment impact
├── CONTRIBUTING.md                   # Contribution guidelines
├── CODE_OF_CONDUCT.md                # Code of conduct
├── LICENSE                           # License
├── aiml-security-assessment/
│   ├── functions/security/
│   │   ├── bedrock_assessments/      # Amazon Bedrock checks (40)
│   │   ├── sagemaker_assessments/    # Amazon SageMaker AI checks (29; SM-29 reserved)
│   │   ├── agentcore_assessments/    # Amazon Bedrock AgentCore checks (17)
│   │   ├── agent_registry_assessments/  # AWS Agent Registry checks (8)
│   │   ├── responsible_ai_grc_assessments/  # Optional Responsible AI GRC checks (64)
│   │   ├── responsible_ai_grc_tests/ # Responsible AI GRC test session (own conftest)
│   │   ├── owasp_assessments/        # Optional OWASP Top 10 for LLM checks (12)
│   │   ├── iam_permission_caching/   # AWS IAM permissions cache
│   │   ├── cleanup_bucket/           # Amazon S3 cleanup
│   │   ├── resolve_regions/          # Target-region resolution for the Map state
│   │   └── generate_consolidated_report/  # HTML/CSV report generation
│   ├── statemachine/                 # AWS Step Functions definition
│   ├── images/                       # SAM application images
│   ├── template.yaml                 # AWS SAM template (single-account)
│   ├── template-multi-account.yaml   # AWS SAM template (multi-account)
│   ├── samconfig.toml                # SAM deployment configuration
│   ├── envvars.json                  # Environment variables for local testing
│   └── testfile.json                 # Test event for local invocation
├── assessment_history/               # Changes-since-last-assessment report (CodeBuild post-build)
├── deployment/                       # Top-level AWS CloudFormation templates
├── docs/
│   ├── ASSESSMENT_HISTORY.md         # Changes since last assessment report
│   ├── CLEANUP.md                    # Resource removal guide
│   ├── DEVELOPER_GUIDE.md            # This guide
│   ├── FAQ.md                        # Frequently asked questions
│   ├── RESPONSIBLE_AI_GRC_SCOPE.md   # Responsible AI GRC scope, sources, and alias migration
│   ├── SECURITY_CHECKS.md            # Security checks reference (core + Agentic AI)
│   ├── SECURITY_CHECKS_OWASP.md      # OWASP Top 10 for LLM checks reference
│   ├── SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md  # Responsible AI GRC checks reference
│   ├── SECURITY_CHECKS_RESPONSIBLE_AI_GRC_SEVERITY_METHODOLOGY.md  # Severity model and register
│   ├── TROUBLESHOOTING.md            # Troubleshooting guide
│   ├── UPGRADING.md                  # Upgrading an existing deployment
│   ├── diagrams/                     # Architecture diagrams
│   └── icons/                        # AWS service icons
├── sample-reports/                   # Sample reports, screenshots, and scripts/
├── tests/                            # Main pytest session (requirements.txt, fixtures/)
├── .github/                          # Workflows, labeler configuration, and templates
├── .cfnlintrc                        # cfn-lint suppressions
├── buildspec.yml                     # AWS CodeBuild orchestration
├── consolidate_html_reports.py       # Multi-account report consolidation
├── generate_provenance.py            # Responsible AI GRC provenance generator
└── ruff.toml                         # Ruff lint and format configuration
```

</details>

## Assessment Execution Workflow

<a id="aws-step-functions-per-module"></a>

### AWS Step Functions State Machine

The definition is `aiml-security-assessment/statemachine/assessments.asl.json`.
Both SAM templates substitute `${...}` placeholders (function ARNs, the four
`Enable*Assessment` values, and `MaxRegionConcurrency`) through
`DefinitionSubstitutions`. The condensed state list:

```text
Configure Service Assessments (Pass, ResultPath $.ServiceSelection)
└─ Cleanup S3 Bucket (Task, ResultPath null)
   └─ IAM Permission Caching (Task, ResultPath null, global, runs once)
      └─ Resolve Target Regions (Task, ResultPath $.ResolvedRegions)
         └─ Scan Regions (Map over $.ResolvedRegions.regions, MaxConcurrency = MaxRegionConcurrency, ResultPath null)
            │  ItemSelector: Region, RegionIndex, Execution, StateMachine, OriginalInput
            ├─ Run Security Assessments (Parallel, ResultPath null)
            │  ├─ Bedrock Assessment Enabled? (Choice on OriginalInput.ServiceSelection.bedrock)
            │  │    → Bedrock Security Assessment (Task; Catch → Bedrock Assessment Incomplete)
            │  │    → default: Bedrock Assessment Not Selected (Pass)
            │  ├─ Sagemaker Assessment Enabled?            (same three-state pattern)
            │  ├─ AgentCore Assessment Enabled?            (same three-state pattern)
            │  ├─ AWS Agent Registry Assessment Enabled?   (same three-state pattern)
            │  └─ Responsible AI GRC Enabled? (Choice)
            │       → Legacy enableFinServ Input Rejected (Fail, LegacyEnableFinServInputRejected)
            │       → Responsible AI GRC Security Assessment (Task, RegionIndex 0 only, when
            │         enableResponsibleAIGRC or enableOWASP is "true"; Catch → ... Incomplete)
            │       → default: Responsible AI GRC Assessment Skipped (Pass)
            └─ OWASP Enabled? (Choice on OriginalInput.enableOWASP)
                 → OWASP Security Assessment (Task; Catch → OWASP Assessment Incomplete)
                 → default: OWASP Assessment Skipped (Pass)
After Scan Regions completes → Generate Consolidated Report (Task)
```

Each assessment Task has a `Catch` on `States.ALL` with an explicit
`ResultPath` (`$.assessmentError` for the four direct services,
`$.responsibleAIGRCError` and `$.owaspError` for the optional assessments) that
routes to an `Incomplete` Pass state (`statusCode: 207`, `incomplete: true`),
so one failed Lambda cannot abort the other branches. `Not Selected` and
`Skipped` Pass states return a small marker object. Because the Parallel state
uses `ResultPath: null`, its branch outputs are discarded and `OWASP Enabled?`
still sees `OriginalInput`, `Region`, and `RegionIndex`.

### Service Selection

User-facing behavior (the **Not selected** labeling, score denominators,
historical CSVs, and Responsible AI GRC independence) is documented in
[Selecting Service Assessments](../README.md#selecting-service-assessments).
This section covers the implementation wiring.

- **Parameters.** `EnableBedrockAssessment`, `EnableSageMakerAssessment`,
  `EnableAgentCoreAssessment`, and `EnableAgentRegistryAssessment` are string
  parameters (`true`/`false`, default `true`) in both SAM templates and both
  top-level deployment templates.
- **Pass-state wiring.** Both SAM templates substitute the values into the
  `Configure Service Assessments` Pass state, which writes
  `$.ServiceSelection` (keys `bedrock`, `sagemaker`, `agentcore`,
  `agent-registry`) before cleanup and region resolution. The regional Choice
  states read `$.OriginalInput.ServiceSelection[...]`. Because the Pass state
  overwrites `$.ServiceSelection`, execution input cannot override the
  deployment's selected scope.
- **CodeBuild forwarding.** The top-level deployment templates expose the
  switches as the `ENABLE_BEDROCK`, `ENABLE_SAGEMAKER`, `ENABLE_AGENTCORE`, and
  `ENABLE_AGENT_REGISTRY` CodeBuild environment variables. `buildspec.yml`
  validates them and forwards them as `SAM_ENABLE_*_PARAMETER` overrides to all
  three `sam deploy` sites (member account, management account, and single
  account). The feature adds no API calls or IAM permissions, so the
  member-role StackSet is unaffected.
- **Artifact validation.** The report Lambda
  (`generate_consolidated_report/app.py`) builds `per_region_categories` and
  `expected_artifacts` from the selection and requires every selected service's
  CSV for every resolved region; missing selected artifacts still fail report
  generation, while deselected artifacts are not required. An all-disabled
  selection may produce an HTML report without service CSVs. The CodeBuild
  artifact checks in `buildspec.yml` likewise require CSV prefixes only for
  enabled services.
- **OWASP coverage rows.** The OWASP Task receives
  `$.OriginalInput.ServiceSelection`. It skips reads of deselected Amazon
  Bedrock, Amazon SageMaker AI, and Amazon Bedrock AgentCore CSVs (AWS Agent
  Registry CSVs are never read), and `build_selection_coverage_findings()`
  emits one `N/A`/`Informational` selection-coverage row per regional
  invocation for each OW ID whose mapped sources include a deselected service.
  Missing selected artifacts still use `OW-00` and are not conflated with
  intentional deselection.
- **Upgrade-path defaulting.** The post-build phase reapplies default-enabled
  flags (`${ENABLE_BEDROCK:-true}` and so on) for older CodeBuild projects that
  lack the service-selection environment variables. Artifact validation must
  still reject missing selected-service CSVs on that path.

Regression coverage in `tests/test_service_selection.py` exercises all 16
direct-service combinations, both deployment paths, artifact requirements,
OWASP source selection, and single- and multi-account reporting.

## Assessment Structure

The assessment areas and current check counts are summarized in
[Architecture Overview](#architecture-overview). For individual checks, see
the [Security Checks Reference](SECURITY_CHECKS.md).

### AWS Lambda Functions

Each direct service assessment Lambda (Amazon Bedrock, Amazon SageMaker AI,
Amazon Bedrock AgentCore, and AWS Agent Registry):

1. Receives `Execution`, `Region`, and `RegionIndex` from the Step Functions Map state.
2. Probes service availability in the target region and emits an `N/A`/`Informational` finding if the service is unavailable.
3. Reads cached AWS IAM permissions from Amazon S3 where a check needs them.
4. Creates regional boto3 clients with an explicit `region_name`.
5. Runs its checks, passing `region=` to every `create_finding()` call.
6. Writes a region-suffixed CSV, `<service>_security_report_<execution_id>_<region>.csv`, keyed on `Execution.Name`.
7. Returns a summary to AWS Step Functions.

AWS Agent Registry uses its own `agent-registry-control` client and runs
independently of Amazon Bedrock AgentCore availability because the services
have separate endpoints.

The Responsible AI GRC Lambda is deployed by both SAM templates, but Step
Functions invokes it only from the first region iteration (`RegionIndex == 0`)
when the execution input includes `"enableResponsibleAIGRC": "true"` or
`"enableOWASP": "true"`. It receives the full `TargetRegions` list, emits
findings with `Region` values, and writes the unsuffixed
`responsible_ai_grc_security_report_<execution_id>.csv`. When only OWASP is
enabled, its `FS-*` rows are hidden source rows. For the legacy
`EnableFinServAssessment` alias and the rejected `enableFinServ` execution
input, see
[Migrating from EnableFinServAssessment](RESPONSIBLE_AI_GRC_SCOPE.md#migrating-from-enablefinservassessment).

**Supporting functions:**

- **AWS IAM Permission Caching**: Pre-fetches AWS IAM policies once per execution (global).
- **Cleanup Bucket**: Removes current assessment objects before each run. Version history and delete markers remain until removed manually; see the [Cleanup Guide](CLEANUP.md).
- **Resolve Regions**: Resolves the `TargetRegions` parameter into the Map state's region list.
- **Generate Consolidated Report**: Validates selected artifacts and creates the HTML report with region filtering.

### Optional Policy Baseline Propagation

Scanner behavior for each baseline is documented in
[Optional Security Policy Baselines](../README.md#optional-security-policy-baselines).
Organization-specific baselines are CloudFormation parameters rather than
hard-coded scanner assumptions. **Wire every layer**: both SAM templates, both
top-level deployment templates, the corresponding CodeBuild environment
variable, and every `sam deploy` path in `buildspec.yml`.

| CloudFormation parameter | Lambda environment variable | Check |
| --- | --- | --- |
| `RequireBedrockZeroDataRetention` | `REQUIRE_BEDROCK_ZERO_DATA_RETENTION` | BR-37 |
| `RequireMarketplaceEndpointCMK` | `REQUIRE_MARKETPLACE_ENDPOINT_CMK` | BR-40 |
| `RequireAgentCoreOnlineEvaluation` | `REQUIRE_AGENTCORE_ONLINE_EVALUATION` | AC-17 |
| `RequireAgentRegistryManualApproval` | `REQUIRE_AGENT_REGISTRY_MANUAL_APPROVAL` | AR-03 |
| `RequireAgentRegistryCMK` | `REQUIRE_AGENT_REGISTRY_CMK` | AR-05 |
| `AgentCoreTokenVaultId` | `AGENTCORE_TOKEN_VAULT_ID` | AC-14 |
| `ApprovedExternalAccountIds` | `AIML_APPROVED_EXTERNAL_ACCOUNT_IDS` | SM-30 |
| `ApprovedOrganizationIds` | `AIML_APPROVED_ORG_IDS` | SM-30 |

The top-level deployment templates expose the approved-account and
approved-organization values to CodeBuild as `APPROVED_EXTERNAL_ACCOUNT_IDS`
and `APPROVED_ORGANIZATION_IDS`; `buildspec.yml` maps them to the SAM
parameters above. Add or rename a baseline only when all layers and the public
deployment documentation are updated together.
`tests/test_optional_policy_baseline_wiring.py` checks the wiring.

## Assessment History (Changes Since Last Assessment)

The `assessment_history/` package at the repository root compares each
account's current run with its previous usable run and writes the changes
report. `buildspec.yml` runs it in the post-build phase (`run_changes_report`)
after the existing reports, with warnings only, a time limit, and a skip when
little build time is left. It reads only the findings CSVs in the central
bucket (and, in single-account mode, the run records written by
`record_assessment_run`), only reads the multi-account failure ledger, and
never fails the build. User-facing behavior is in
[Changes Since Last Assessment](ASSESSMENT_HISTORY.md).

### Modules and Files

| Path | Role |
| --- | --- |
| `assessment_history/models.py` | Record shapes, change states, area routing, CSV columns |
| `assessment_history/normalize.py` | Day counts and dates blanked out before matching, each tied to the scanner code that writes it |
| `assessment_history/compare.py` | Pairs two runs' rows and labels each; no AWS calls |
| `assessment_history/discover.py` | Groups an account folder's CSVs into runs (S3 or local folder), picks the previous usable run (complete files, and a run record that does not say it failed), and reads the CSVs |
| `assessment_history/render_common.py`, `render_changes.py` | The HTML page, reusing `report_template.py`'s CSS, escaping, names, and icons |
| `assessment_history/__main__.py` | `python3 -m assessment_history compare`: S3 mode for the build, local-folder mode for people |
| `tests/test_assessment_history_*.py` | Tests; `tests/assessment_history_helpers.py` builds test data |
| `tests/fixtures/assessment_history/` | A hand-written example account folder and the golden saved answers (`golden/expected_*.json`) |
| `sample-reports/scripts/build_changes_sample.py` | Builds the sample changes page and CSV and the golden saved answers |
| `sample-reports/scripts/capture_changes_screenshot.py` | Captures `sample-reports/changes-overview.png` from the sample changes page |

### Keeping Assessment History in Sync

- **A check that writes a day count or date into `Finding_Details`:** add a
  pattern to `VOLATILE_PATTERNS` in `normalize.py`, or an `IGNORED_SOURCES`
  entry with a reason. `tests/test_assessment_history_normalize.py` fails
  until you do.
- **A new findings CSV prefix or assessment area:** update `PREFIX_TO_MODULE`
  in `discover.py` and the module and area lists in `models.py`. Files with an
  unknown prefix are logged and not read.
- **A new compliance standard:** `COMPLIANCE_PREFIX_TO_AREA` in `models.py`
  must match `COMPLIANCE_STANDARDS` in `report_template.py`; a test checks it.
- **`report_template.py`:** the changes page reuses its styling and helpers;
  guard tests fail if something it relies on moves.
- **A sample report or a comparison rule:** rebuild the changes sample (below)
  and review the diff.

### Coverage Gate

The package keeps 100% line and branch coverage; CI runs the same check:

```bash
.venv/bin/python -m pytest tests/test_assessment_history_*.py \
  --cov=assessment_history --cov-branch --cov-report=term-missing \
  --cov-fail-under=100
```

### Rebuilding the Changes Sample and Golden Files

The golden tests use both sample reports. Each is turned back into the findings
CSVs the scanners write (in a temporary folder; only the saved answers are
committed), and a current run is made by applying a short list of edits
(`EDITS` in the script) that covers every change state and each matching step.
Values that AWS generated in the sample reports (resource IDs and the random
parts of resource names) are first replaced with synthetic values of the same
shape, and a test fails if any of them reaches a committed file.

After changing a sample report or a comparison rule:

1. Regenerate the sample and the golden answers:

   ```bash
   .venv/bin/python sample-reports/scripts/build_changes_sample.py
   ```

   `--check` makes no changes and exits 1 if anything is out of date.
2. Review the diff under `sample-reports/` and
   `tests/fixtures/assessment_history/golden/`.
3. Refresh the screenshot. The script uses the same browser setup as
   `capture_screenshots.py`, captures only the changes page into
   `sample-reports/changes-overview.png`, and does not rewrite any report:

   ```bash
   ./sample-reports/scripts/capture_changes_screenshot.py
   ```

## Report Generation Architecture

### Shared Template Module

Report generation uses a single shared template (`report_template.py`) for both
deployment modes:

```text
aiml-security-assessment/functions/security/generate_consolidated_report/
├── app.py              # Lambda handler (single-account)
├── report_template.py  # Shared HTML/CSS/JS template
└── ...

consolidate_html_reports.py  # CodeBuild script (multi-account)
```

### How It Works

| Component | Mode | Description |
| --- | --- | --- |
| `app.py` (AWS Lambda) | `mode='single'` | Generates per-account HTML reports during the AWS Step Functions execution |
| `consolidate_html_reports.py` | `mode='multi'` | Builds one report from every account's CSV files in the AWS CodeBuild post-build phase |

Both call `generate_html_report()` from `report_template.py` with different
parameters. The report routes rows by `Check_ID` prefix, and
`COMPLIANCE_STANDARDS` in `report_template.py` drives every compliance-standard
section.

### Modifying the Report Template

1. Edit `report_template.py` only; changes apply to both single- and multi-account reports.
2. Key functions:
   - `get_html_template()`: HTML/CSS/JS structure.
   - `generate_table_rows()`: finding row generation.
   - `generate_html_report()`: main entry point with the `mode` parameter (`'single'` or `'multi'`).
3. The Assessment Scope block is patched after rendering with exact `str.replace()` anchors. If you change the markup an anchor targets, update the anchor too; a missed match fails silently.
4. Run the report-pipeline tests from the report package directory: `../../../../.venv/bin/python -m pytest test_generate_report.py -v`.
5. Generate and inspect both report modes (see [Report Verification](#4-report-verification-required-before-opening-a-pr)).

<a id="assessment-best-practices"></a>
<a id="1-security-check-implementation"></a>
<a id="2-performance-optimization"></a>
<a id="3-error-handling"></a>

## Adding a New Check Inside an Existing Service

Most contributions add or update individual checks inside an existing
assessment package (Amazon Bedrock, Amazon SageMaker AI, Amazon Bedrock
AgentCore, or AWS Agent Registry) rather than creating a new package.

1. **Define the check contract before coding.** Record the `Check_ID`, the exact resource and its regional or account-global scope, the AWS client and operation, the response field and allowed values, the successful empty-response behavior, and the evidence that produces `Passed`, `Failed`, or `N/A`. Verify request/response shapes and enum values against the installed botocore service model (`data/<service>/*/service-2.json`) and AWS documentation. An HTTP 200 or an empty response does not establish compliance; distinguish account-level policies from resource-level settings. Compare the predicate with the catalog description and remediation before writing tests.

2. **Locate the target file**: `bedrock_assessments/app.py`, `sagemaker_assessments/app.py`, `agentcore_assessments/app.py`, or `agent_registry_assessments/app.py`. Follow the existing function structure and naming in that file, and check the service string each client was constructed with rather than its variable name.

   IAM policy `Statement` accepts either a single object or a list. Normalize both
   forms before evaluating policy statements; `agent_registry_assessments/app.py`
   uses `_policy_statements()` for this. Test both forms so a single-statement
   policy cannot be silently skipped.

3. **Implement the check.** Follow the package's existing return shape (for example, a dict with a `csv_data` list in Amazon Bedrock, or a list of findings in AWS Agent Registry). Pass `region=region` (or the loop variable) to every `create_finding()` call, and use the same `Check_ID` in normal, fallback, and error findings. Use cached IAM permissions instead of re-listing policies, and keep each call to the minimum IAM permissions it needs.

4. **Status and severity semantics** (critical):
   - Access-denied, region-unavailable, and "service not present" paths return `N/A`. Unsupported regional APIs and features are `Informational`; follow the package's convention for access-denied and other could-not-assess results (Responsible AI GRC uses `Low`).
   - Reuse the package helpers instead of raw string matching: `is_region_unsupported()` and `describe_api_error()` in `bedrock_assessments/app.py`, or `_is_unavailable()`, `_is_access_denied()`, `_error_detail()`, `_error_resolution()`, and `_na()` in `agent_registry_assessments/app.py`. Do not classify credential failures or programming errors as region unavailability.
   - Never emit `Failed` with `resolution="No action required"`. Tooling conditions, such as an empty permission cache, are `N/A`/`Informational`.
   - A completed empty inventory needs an explicit `N/A` row for each affected check. An access-denied or partial inventory must not claim that no resources exist. Keep `Passed` resolution text free of remediation instructions.
   - For optional policy baselines (for example, `REQUIRE_MARKETPLACE_ENDPOINT_CMK=false`), emit `N/A`/`Informational` when the hardening gap is observed; reserve `Passed` for controls that were checked and satisfied.

5. **Inventory scope, pagination, and error isolation.** Use `get_paginator()` or an explicit next-token helper such as `_agentcore_list_all`, and test a non-compliant item on a later page. If a safety cap or deadline truncates the list, keep the findings collected and add an `N/A` incomplete-inventory notice. Wrap per-resource detail calls individually so one throttle or delete race does not erase other resources' findings. Run account-global inventories once, or de-duplicate them with a truthful `Region` value. Make sure the handler wraps the check (for example, `_run_check_safely()` in `agent_registry_assessments/app.py`) so an unexpected exception becomes one visible `N/A` "Incomplete" row under the same `Check_ID` while the CSV is still written. Let an artifact-write failure raise after logging so the Step Functions `Catch` fires; returning `{"statusCode": 500}` without raising hides the failure.

6. **Synthesized mappings** (if applicable). If the check should also appear under the Agentic AI lens (`AG-`) or an OWASP category, update the mapping dictionary. Values in `OWASP_CHECK_MAPPINGS` are lists because one source check can emit multiple `OW-` rows. Allocate new AG numbers by hand across the Amazon Bedrock, Amazon Bedrock AgentCore, and AWS Agent Registry mapping modules and the native checks (the catalog currently ends at AG-38). Confirm every mapped source ID exists, every emitted OW ID appears in `docs/SECURITY_CHECKS_OWASP.md`, and an `N/A` source produces an `OW-` row with `Informational` severity.

7. **Add IAM grants.** Every new boto3 operation needs its exact IAM action on the owning Lambda's policy in both SAM templates; see [Step 5: Update AWS IAM Permissions](#step-5-update-aws-iam-permissions).

8. **Add tests.** Use SDK-shaped responses for compliant/pass, non-compliant/fail (or advisory `N/A` where defined), no-resource, access-denied, region-unavailable, and unexpected-error cases, including a successful empty response where the API can return one. Empty-inventory tests alone do not exercise a check's predicate. Shared inventories need later-page, list-error, and per-resource detail-error cases; account-global inventories need a two-region case. Assert the exact `Check_ID` on fallback rows and that a failed check leaves the other checks' rows in the CSV. See `tests/test_bedrock_checks.py`, `tests/test_sagemaker_checks.py`, and `tests/test_agent_registry_checks.py`.

9. **Update documentation.** Align the check's evidence, scope, status behavior, severity, and remediation with `docs/SECURITY_CHECKS.md` and the applicable `docs/SECURITY_CHECKS_*.md` catalog. Check counts appear in four places that must move together: `README.md`, this guide, and both the intro paragraph and the per-service table in `docs/SECURITY_CHECKS.md`. Section headings carry their count (for example, `## AWS Agent Registry Security Checks (8)`), so changing a count changes the anchor; re-check every `SECURITY_CHECKS.md#...` deep link and table of contents. Also review `docs/TROUBLESHOOTING.md`, `CHANGELOG.md`, and relevant scope, sample-report, and diagram documents.

10. **Run the gates before committing** (commands in [Running Checks Locally](#running-checks-locally)):
    - Whole-repository `ruff check` and `ruff format --check`, which include CI's changed-file scope and uncommitted work.
    - The pytest sessions: `tests/`, `responsible_ai_grc_tests/`, the report-pipeline session, and the `assessment_history` coverage gate.
    - `cfn-lint` on any edited templates.
    - The repository-wide [delivery gate in AGENTS.md](../AGENTS.md#before-delivering-assessment-changes), including API evidence, IAM and artifact coverage, status semantics, mappings, and CSV schema.

11. **Generate and verify the HTML report** (mandatory before opening a PR). Follow [Report Verification](#4-report-verification-required-before-opening-a-pr) and confirm the check renders correctly in the table, sidebar, filters, and both light and dark modes.

### Check ID, Status, and Severity Conventions

**Check ID prefixes** drive report routing and match `^[A-Z]{2,3}-\d{2}$`:

| Prefix | Assessment area |
| --- | --- |
| `BR-` | Amazon Bedrock |
| `SM-` | Amazon SageMaker AI |
| `AC-` | Amazon Bedrock AgentCore |
| `AR-` | AWS Agent Registry |
| `AG-` | Agentic AI Security (synthesized lens plus native AG-24..27) |
| `FS-` | Responsible AI GRC (legacy identifier retained for compatibility) |
| `OW-` | OWASP Top 10 for LLM |

**Status values:**

- `Passed`: resources were checked and met the assessed best practice.
- `Failed`: resources were checked and found non-compliant.
- `N/A`: nothing to check, the API or region is unavailable, manual review is needed, or no result could be determined.

**Severity values:**

- `High`: critical security issues requiring immediate attention.
- `Medium`: important security improvements.
- `Low`: minor improvements (also Responsible AI GRC's could-not-assess results).
- `Informational`: advisory information, no-resource results, and unavailable-feature `N/A` results.

## Adding New AI/ML Service Assessments

Adding a service (for example, Amazon Comprehend) means a new Lambda package
plus wiring through both SAM templates, the state machine, both top-level
deployment templates, `buildspec.yml`, and the report. The examples below use
`comprehend` as a placeholder.

<a id="step-1-create-service-assessment-function"></a>

### Step 1: Create the Service Assessment Function

Copy `aiml-security-assessment/functions/security/agent_registry_assessments/`
as the template. It is the most recent package and shows every current
pattern:

- `schema.py`: the pydantic `Finding` model. It validates `Check_ID` against `^[A-Z]{2,3}-\d{2}$`, requires an `https://` `Reference`, and restricts `Severity` and `Status` to the enum values. Copy it verbatim.
- `requirements.txt`: pinned `boto3`/`botocore` plus `pydantic>=2.0` and `typing-extensions`.
- `app.py`:
  - Availability helpers (`_is_unavailable()`, `_is_access_denied()`, `_error_detail()`, `_error_resolution()`) and `_na()` for `N/A`/`Informational` rows.
  - `_run_check_safely()` around every check, so one check's exception becomes a visible `Incomplete` row.
  - `_execution_name()` to read `Execution.Name`, and `write_to_s3()` to write `<service>_security_report_<execution_id>_<region>.csv`.
  - A handler that raises on unexpected top-level errors after logging, so the Step Functions `Catch` routes to the `Incomplete` state.

A structural handler sketch follows. Implement `get_inventory()` and
`assess_inventory()` for the chosen service: distinguish unavailable, denied,
partial, and empty inventories; emit explicit `N/A` findings where assessment
is incomplete or there is nothing to check; and wrap each verified control
with `_run_check_safely()`. The example does not define a Comprehend security
control. In particular, [Comprehend `DescribeEndpoint`](https://docs.aws.amazon.com/comprehend/latest/APIReference/API_DescribeEndpoint.html)
does not return an endpoint encryption setting, so its response cannot prove
an endpoint-encryption check.

```python
def lambda_handler(event, context):
    execution_id = _execution_name(event)
    region = event.get("Region") or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    try:
        client = boto3.client("comprehend", config=boto3_config, region_name=region)
        inventory = get_inventory(client)  # paginate and retain partial results
        findings = assess_inventory(client, inventory, region)
        for finding in findings:
            finding["Region"] = finding.get("Region") or region
        return {"statusCode": 200, "body": json.dumps(
            {"s3_url": write_to_s3(execution_id, generate_csv_report(findings), region)})}
    except Exception:
        logger.exception("Amazon Comprehend assessment failed")
        raise
```

Checklist for the new package:

- [ ] A unique two- or three-letter `Check_ID` prefix, added to the report routing and the [prefix table](#check-id-status-and-severity-conventions).
- [ ] Every regional check handles unsupported regions and features with an `N/A`/`Informational` row, distinct from access-denied and unexpected errors.
- [ ] Every list API paginates; per-resource detail calls are isolated; empty, denied, and partial inventories are distinguishable.
- [ ] The handler always writes the CSV when it returns and raises when it cannot.
- [ ] Tests load the package through `importlib.util.spec_from_file_location` under a distinct module name (for example, `comprehend_app`), not a bare `import app`.

<a id="step-2-update-aws-sam-template"></a>

### Step 2: Update the AWS SAM Templates

Add the function to both `aiml-security-assessment/template.yaml` and
`aiml-security-assessment/template-multi-account.yaml`:

- The `AWS::Serverless::Function` resource, with `AIML_ASSESSMENT_BUCKET_NAME` and `TARGET_REGIONS` environment variables.
- A `DefinitionSubstitutions` entry for its ARN and a `LambdaInvokePolicy` on the state machine.
- An `Enable<Service>Assessment` parameter (`AllowedValues: ["true", "false"]`, default `true`), its parameter group entry, and a `DefinitionSubstitutions` entry.

<details>
<summary>Example function resource</summary>

```yaml
  ComprehendSecurityAssessmentFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: !Sub 'aiml-security-${AWS::StackName}-ComprehendAssessment'
      CodeUri: functions/security/comprehend_assessments/
      Handler: app.lambda_handler
      Runtime: python3.12
      Architectures:
        - x86_64
      Timeout: 600
      MemorySize: 1024
      Environment:
        Variables:
          AIML_ASSESSMENT_BUCKET_NAME: !Ref AIMLAssessmentBucket
          TARGET_REGIONS: !Ref TargetRegions
      Policies:
        - Statement:
            - Sid: ComprehendReportWrite
              Effect: Allow
              Action:
                - s3:PutObject
              Resource: !Sub '${AIMLAssessmentBucket.Arn}/comprehend_security_report_*.csv'
            - Sid: ComprehendListEndpoints
              Effect: Allow
              Action: comprehend:ListEndpoints
              Resource: '*'
            - Sid: ComprehendDescribeEndpoints
              Effect: Allow
              Action: comprehend:DescribeEndpoint
              Resource:
                - !Sub 'arn:${AWS::Partition}:comprehend:*:${AWS::AccountId}:document-classifier-endpoint/*'
                - !Sub 'arn:${AWS::Partition}:comprehend:*:${AWS::AccountId}:entity-recognizer-endpoint/*'
```

</details>

These permissions cover an illustrative endpoint inventory using
`ListEndpoints` and `DescribeEndpoint`; they do not define a complete
assessment. The region wildcard covers the configured target regions, which
can differ from the Lambda's deployment region. Check each implemented
operation against the
[Comprehend service authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_comprehend.html)
and grant only the resources it needs in both SAM templates.

<a id="step-3-update-aws-step-functions-definition"></a>

### Step 3: Update the AWS Step Functions Definition

Add a branch to the `Run Security Assessments` Parallel state inside the
`Scan Regions` Map state in
`aiml-security-assessment/statemachine/assessments.asl.json`. Mirror an
existing branch exactly:

- `<Service> Assessment Enabled?` (Choice) reading `$.OriginalInput.ServiceSelection['<key>']`, with `Default` set to `<Service> Assessment Not Selected`.
- `<Service> Security Assessment` (Task) passing `Execution`, `StateMachine`, `Region`, and `RegionIndex` in its payload, with the standard Lambda `Retry` block.
- A `Catch` on `States.ALL` with `"ResultPath": "$.assessmentError"` routing to `<Service> Assessment Incomplete`.
- `<Service> Assessment Incomplete` and `<Service> Assessment Not Selected` Pass states that end the branch.

<details>
<summary>Branch skeleton</summary>

```json
{
  "StartAt": "Comprehend Assessment Enabled?",
  "States": {
    "Comprehend Assessment Enabled?": {
      "Type": "Choice",
      "Choices": [
        {
          "Variable": "$.OriginalInput.ServiceSelection['comprehend']",
          "StringEquals": "true",
          "Next": "Comprehend Security Assessment"
        }
      ],
      "Default": "Comprehend Assessment Not Selected"
    },
    "Comprehend Security Assessment": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${ComprehendSecurityAssessmentFunction}",
        "Payload": {
          "Execution.$": "$.Execution",
          "StateMachine.$": "$.StateMachine",
          "Region.$": "$.Region",
          "RegionIndex.$": "$.RegionIndex"
        }
      },
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "ResultPath": "$.assessmentError",
          "Next": "Comprehend Assessment Incomplete"
        }
      ],
      "End": true
    },
    "Comprehend Assessment Incomplete": {
      "Type": "Pass",
      "Result": {"statusCode": 207, "incomplete": true, "body": {"findings": []}},
      "End": true
    },
    "Comprehend Assessment Not Selected": {
      "Type": "Pass",
      "Result": {"statusCode": 200, "skipped": true, "reason": "not-selected", "service": "comprehend"},
      "End": true
    }
  }
}
```

The `Retry` block is omitted here for brevity; copy it from an existing branch.

</details>

### Step 4: Wire Service Selection and Report Artifacts

- [ ] Add the `<key>: "${Enable<Service>Assessment}"` entry to the `Configure Service Assessments` Pass state's `Result`.
- [ ] Add `Enable<Service>Assessment` to `deployment/aiml-security-single-account.yaml` and `deployment/2-aiml-security-codebuild.yaml` (parameter, parameter group, and an `ENABLE_<SERVICE>` CodeBuild environment variable).
- [ ] In `buildspec.yml`, default and validate `ENABLE_<SERVICE>` in the build phase, reapply its default in the post-build phase, export a `SAM_ENABLE_<SERVICE>_PARAMETER`, and pass it to all three `sam deploy` sites (member account, management account, and single account).
- [ ] Add the service's CSV prefix to the selected-artifact checks in `buildspec.yml` and to `per_region_categories` in `generate_consolidated_report/app.py`, so a missing selected CSV is reported as incomplete.
- [ ] Add report routing for the new prefix and a service section in `report_template.py` and `consolidate_html_reports.py`, including the **Not selected** state.
- [ ] Add the CSV prefix to `PREFIX_TO_MODULE` in `assessment_history/discover.py` and the module lists in `models.py`.
- [ ] Extend `tests/test_service_selection.py` for the new combinations.

<a id="step-4-update-aws-iam-permissions"></a>

### Step 5: Update AWS IAM Permissions

Add every exact assessment-service action used by the new function to that
function's `Policies` block in both SAM templates. Do not use service-wide
wildcards such as `comprehend:List*`. Do not add assessment-service actions to
`deployment/1-aiml-security-member-roles.yaml`,
`deployment/2-aiml-security-codebuild.yaml`, or
`deployment/aiml-security-single-account.yaml`; those templates hold
deployment and orchestration roles, not assessment runtime roles.

- Validate every new boto3 operation and its IAM action against the AWS Knowledge MCP documentation tools before merging. Confirm the client (control plane versus data plane), the IAM prefix, and any resource or condition-key constraints.
- Grant the producer `s3:PutObject` on its exact CSV key pattern, and grant every consumer (including the report Lambda) `s3:ListBucket` on the prefix it lists and `s3:GetObject` on the objects it reads.
- Add the new Lambda to the IAM coverage tests (`tests/test_iam_coverage.py`, `tests/test_core_iam_coverage.py`).

The boto3 client name, IAM prefix, and Python variable name can differ. Check
the actual service string passed to `boto3.client()` and the installed botocore
model before using an operation or paginator:

| boto3 client | IAM action prefix | Review detail |
| --- | --- | --- |
| `bedrock-agent` | `bedrock:` | Agent, knowledge-base, flow, and prompt operations use this prefix; some functions call this client `bedrock_client`. |
| `bedrock-agentcore-control` | `bedrock-agentcore:` | AgentCore list, describe, and configuration operations are on the control-plane client, not `bedrock-agentcore`. |
| `agent-registry-control` | `agent-registry:` | `ProvenanceSummary` fields are `relation`, `sourceId`, and `sourceType`, not `source`. |

<a id="step-5-test-locally"></a>

### Step 6: Test Locally

Follow [Local Testing](#1-local-testing) using
`ComprehendSecurityAssessmentFunction` as the function name.

`testfile.json` contains only an `Execution.Name`. Add `"Region"` and
`"RegionIndex"` to a copy of it to exercise a specific region.

## Extending or Adding Lenses

The Agentic AI Security lens (AG-01 through AG-38) is **synthesized at
runtime**, not produced by a separate scanner. It reuses findings from the
selected Amazon Bedrock, Amazon Bedrock AgentCore, and AWS Agent Registry
assessments plus a small number of native gateway checks.

- Mapping dictionaries live in three places:
  - `bedrock_assessments/app.py` → `AGENTIC_BEDROCK_CHECK_MAPPINGS`
  - `agentcore_assessments/app.py` → `AGENTIC_AGENTCORE_CHECK_MAPPINGS`
  - `agent_registry_assessments/app.py` → `AGENTIC_AGENT_REGISTRY_CHECK_MAPPINGS`
- Native checks (currently AG-24 through AG-27) live in the AgentCore package because they need the `bedrock-agentcore-control` client.
- Allocate new AG numbers by hand to avoid collisions across all three mapping dictionaries and the native checks. The current high-water mark is AG-38.
- The HTML report routes the lens through the `AG-` prefix as its own assessment area. `COMPLIANCE_STANDARDS` is the separate registry for OWASP and future compliance standards.
- Follow the same cross-file execution, artifact, and report checks as a new compliance standard. The Agentic AI lens needs no CloudFormation parameter of its own, but new native checks still need IAM grants in both SAM templates.
- Update `docs/SECURITY_CHECKS.md` and run the mapping-drift, test-coverage, and gate checklist before merging.
- **Generate and verify the HTML report** (mandatory before opening a PR): follow [Report Verification](#4-report-verification-required-before-opening-a-pr) and confirm AG-* findings appear under the lens section with the right severity and routing.

## Adding a Compliance Standard (OWASP-style)

The HTML presentation under "By Compliance Standard" is **data-driven**.
Adding a standard such as NIST AI RMF or the EU AI Act follows the OWASP
pattern, but the execution flag, artifact access, and required-artifact checks
must also be wired.

### 1. Choose a Check ID prefix

<details>
<summary>Details</summary>

Use two or three letters that satisfy `^[A-Z]{2,3}-\d{2}$`:

- OWASP → `OW-` (implemented)
- NIST AI RMF → suggested `NR-`
- EU AI Act → suggested `EU-`

</details>

### 2. Create the Lambda package

<details>
<summary>Details</summary>

Create `aiml-security-assessment/functions/security/<slug>_assessments/`:

- Copy `owasp_assessments/schema.py` verbatim and `owasp_assessments/requirements.txt`.
- Author `app.py` following the OWASP pattern: read per-service CSVs from S3, apply your `<STANDARD>_CHECK_MAPPINGS` dict, run any native checks, and write `<slug>_security_report_<execution>_<region>.csv`.
- For every native control, complete the [check contract and test cases](#adding-a-new-check-inside-an-existing-service). A rendered row does not prove that its AWS API predicate is correct.

</details>

### 3. Wire the opt-in flag through deployment and execution

<details>
<summary>Details</summary>

Follow the `EnableOWASPAssessment` pattern:

- `deployment/aiml-security-single-account.yaml` and `deployment/2-aiml-security-codebuild.yaml`: parameter definition, parameter group, and CodeBuild environment variable.
- `buildspec.yml`: the `ENABLE_<STANDARD>` export and every applicable `aws stepfunctions start-execution` input.
- `aiml-security-assessment/template.yaml` and `template-multi-account.yaml`: the function resource, `LambdaInvokePolicy`, definition-substitution entry, and any SAM-level parameter for direct deployments.
- `aiml-security-assessment/statemachine/assessments.asl.json`: the flag reference and enabled/skipped branches (step 5).

Verify that every declared SAM parameter is consumed by the state machine. A
direct `StartExecution` must supply the flag in its input when the state
machine expects it; a CodeBuild environment variable alone does not set
direct-execution input.

</details>

### 4. Add IAM grants for APIs and CSV artifacts

<details>
<summary>Details</summary>

Follow [AGENTS.md](../AGENTS.md) and scope each grant correctly:

- In both SAM templates, add the grant to the **specific function's `Policies` block** that makes the call.
- Grant the new Lambda write access to its exact CSV key pattern. For each consumer, including the report Lambda, add `s3:ListBucket` on the prefix it lists and `s3:GetObject` on the objects it reads.
- Do **not** add assessment-service read actions to the three top-level deployment templates. Those roles only create or update the SAM stack, poll executions, and retrieve reports; a new deployment-time AWS operation needs a separate least-privilege review.
- The canonical multi-account member role uses one customer-managed policy document. Keep it within the 5,500-character rendered budget enforced by `tests/test_member_role_policy_size.py`.

</details>

### 5. Add the Step Functions Choice state

<details>
<summary>Details</summary>

In `aiml-security-assessment/statemachine/assessments.asl.json`:

- Add a `<Standard> Enabled?` Choice state reading `$.OriginalInput.enable<Standard>`, and a `<Standard> Security Assessment` Task that invokes the new function, with a `Catch` to a `<Standard> Assessment Incomplete` state and a `<Standard> Assessment Skipped` default.
- Chain it after `OWASP Enabled?` inside the region Map: replace `End: true` with `Next` on each OWASP success, skipped, and incomplete route that must reach the new Choice.
- Preserve `OriginalInput`, `Execution`, `Region`, `RegionIndex`, and other downstream fields on success, skipped, and caught-error paths. Set `ResultPath` explicitly on result-producing Task and Pass states as well as on `Catch`; a `Catch` `ResultPath` does not protect the success path. Test each path through the next Choice and the report-generation state.

</details>

### 6. Register the standard in the report

<details>
<summary>Details</summary>

Append a dict to `COMPLIANCE_STANDARDS` in `report_template.py` with `slug`,
`name`, `prefix`, `icon`, `icon_small`, `reference_url`, `section_title`, and
truthful `scope_text`. The `slug` and prefix must be unique; choose an icon
color distinct from the existing navigation colors.

- The shared loop in `generate_html_report()` builds the sidebar entry, filter option, dashboard card, findings section and summary, Assessment Scope chip, and source link when the standard has rows. Extend the registry instead of copying OWASP-specific HTML.
- If the HTML structure must change, edit the shared loop and the affected `get_html_template()` placeholders together. Keep one `slug` across the section `id`, finding-row `data-service`, filter option value, summary `data-filter-service`, and scope-chip `data-scope-service`, and review affected CSS/JavaScript selectors. Update any Assessment Scope `str.replace()` anchors whose source markup changes.

</details>

### 7. Check routing and artifact completeness

<details>
<summary>Details</summary>

The report Lambda (`generate_consolidated_report/app.py`) and the multi-account
consolidator (`consolidate_html_reports.py`) both iterate `COMPLIANCE_STANDARDS`
to initialize `service_stats` and `service_findings` and to route rows by
prefix. That handles presentation and routing, but it does **not** add the new
CSV to `per_region_categories`/`expected_artifacts` or grant permission to list
and read it. Extend those selected-artifact checks, map any CSV filename
fragment that differs from the slug, and verify CodeBuild stages the CSV for
the consolidator. A selected standard with a missing, unreadable, or
header-only CSV must be reported as incomplete, not shown with zero findings.
Also update `COMPLIANCE_PREFIX_TO_AREA` in `assessment_history/models.py`.

</details>

### 8. Update documentation

<details>
<summary>Details</summary>

Add a `docs/SECURITY_CHECKS_<STANDARD>.md` in the OWASP style and update every
check-count location, table of contents, and deep link listed in
[Adding a New Check Inside an Existing Service](#adding-a-new-check-inside-an-existing-service).

</details>

### 9. Add tests

<details>
<summary>Details</summary>

Cover mapping emission, native-check behavior, enabled and skipped Step
Functions paths, artifact completeness, routing, and report rendering. Use
representative synthetic CSVs with positive, negative, `N/A`, and
empty-inventory findings, and test missing and unreadable artifacts
separately. Include IAM coverage assertions for the new Lambda and the report
reader in both SAM templates. Use `tests/test_owasp_checks.py` and
`tests/test_report_template_owasp.py` as templates.

</details>

### 10. Generate and verify the HTML report

<details>
<summary>Details</summary>

This is mandatory before opening a PR. Follow
[Report Verification](#4-report-verification-required-before-opening-a-pr).
In single- and multi-account output, check sidebar navigation, filtering, card
and section counts, severity and status, Assessment Scope chips and source text,
and desktop/mobile and light/dark rendering. Test enabled, disabled, and
empty-result cases. When changing the Assessment Scope markup, confirm the
post-render insertion is present in the generated HTML.

</details>

## Testing Your Extensions

### 1. Local Testing

Run the pytest sessions in [Running Checks Locally](#running-checks-locally),
including the SAM build, then invoke the changed function with AWS SAM:

```bash
(cd aiml-security-assessment \
  && sam local invoke BedrockSecurityAssessmentFunction --event testfile.json)
```

### 2. Integration Testing

Deploy to a non-production test account and start an execution. Service
selection comes from the stack parameters; the execution input carries only
the optional-assessment flags.

```bash
sam deploy --stack-name aiml-security-test --capabilities CAPABILITY_IAM --resolve-s3

aws stepfunctions start-execution \
  --state-machine-arn arn:aws:states:us-east-1:123456789012:stateMachine:ExampleStateMachine \
  --input '{"enableResponsibleAIGRC":"false","enableOWASP":"false"}'
```

### 3. Multi-Account Testing

1. Deploy the member roles to test accounts with AWS CloudFormation StackSets.
2. Deploy the central infrastructure with test parameters.
3. Monitor the AWS CodeBuild logs for deployment and execution status.
4. Verify the results in the central Amazon S3 bucket.

### 4. Report Verification (Required Before Opening a PR)

When you add a check, extend a lens (`AG-*`), or introduce a compliance
standard (`OW-*`, `NR-*`, `EU-*`, and so on), you **must** generate the HTML
reports from the test fixtures and inspect them before creating a pull
request. This catches routing, template, and rendering issues that unit tests
can miss.

The command below renders only the test's fixed synthetic findings; it does
not collect rows from a newly added scanner. First add representative findings
for the new `Check_ID`, lens, or standard to the relevant report test fixtures
and assert that the generated HTML contains them. For a new standard, also
cover enabled, disabled, and empty-result reports in the applicable mode.

```bash
(cd aiml-security-assessment/functions/security/generate_consolidated_report \
  && ../../../../.venv/bin/python -m pytest test_generate_report.py \
    -k "generate_viewable_report or generate_multi_account_report" -s --tb=no)
```

The reports are written under
`aiml-security-assessment/functions/security/generate_consolidated_report/test_reports/`
(git-ignored). Open the single- and multi-account HTML files in a browser at
desktop and mobile widths and verify:

- The new `Check_ID` (for example, BR-41, SM-31, AR-09, AG-39, OW-13, or NR-01) appears with the expected Finding name, Severity badge, Status, Region, and Resolution text.
- The row is routed into the right sidebar group:
  - Core service checks (`BR-*`, `SM-*`, `AC-*`, `AR-*`) appear under "By Service".
  - `AG-*` findings appear under "By Lens" → Agentic AI Security.
  - `OW-*` and any new `NR-*`/`EU-*` standards appear under "By Compliance Standard".
- A new compliance standard's sidebar link, filter option, dashboard card, findings section, Assessment Scope chip, and source link use the same slug and show the right counts and scope. A disabled standard does not appear as an empty or clean assessment.
- Filters (region, severity, status, and search) work for existing and new rows.
- Long finding details or remediation text do not break the table layout.
- Dark mode, responsive layout, and the executive dashboard reflect the new content accurately.

## Documentation and Screenshots

### Updating Sample Reports

When you change the report template or add report features, update the sample
reports and screenshots.

#### 1. Generate New Sample Reports

Regenerate sample reports from a fresh assessment run or from the local report
fixtures with the command in
[Report Verification](#4-report-verification-required-before-opening-a-pr).
`test_generate_report.py` is a test module, not a standalone CLI. Use the
fixture output to validate rendering before refreshing the canonical files in
`sample-reports/`, and keep every identifier synthetic.

#### 2. Capture Screenshots

```bash
# Install or verify dependencies and Chromium; leave sample reports untouched
./sample-reports/scripts/capture_screenshots.py --check-dependencies

# Capture and optimize screenshots
./sample-reports/scripts/capture_screenshots.py
```

The repository-root `.venv` must already exist and use Python 3.12. The script
re-launches itself with `.venv/bin/python`, installs
`sample-reports/dev-requirements.txt` into that environment when needed, and
installs Chromium under `.venv/playwright-browsers`. It opens the sample
reports in a headless browser, expands the viewport to include every
left-navigation section, captures each view, and optimizes the images (target
200-300 KB each, converting large PNGs to JPEG if needed). It writes four
screenshots to `sample-reports/`:

- `dashboard-overview-light.png`: executive dashboard in light mode
- `dashboard-overview-dark.png`: executive dashboard in dark mode
- `findings-table.png`: findings table with filters
- `multi-account-summary.png`: multi-account consolidated view

The changes-page screenshot, `changes-overview.png`, comes from
`capture_changes_screenshot.py`; see
[Rebuilding the Changes Sample and Golden Files](#rebuilding-the-changes-sample-and-golden-files).

<details>
<summary>Customizing the screenshot script</summary>

Edit `sample-reports/scripts/capture_screenshots.py`:

```python
# Viewport size
VIEWPORT_WIDTH = 1440
VIEWPORT_HEIGHT = 900

# Image quality
JPEG_QUALITY = 85  # Range: 1-100
PNG_OPTIMIZE = True

# Add new screenshots to the SCREENSHOTS list
SCREENSHOTS = [
    {
        "name": "my-screenshot",
        "file": "security_assessment_single_account.html",
        "description": "My Custom View",
        "actions": [
            {"type": "wait", "selector": ".element", "timeout": 2000},
            {"type": "click", "selector": ".button"},
            {"type": "scroll", "position": 500},
        ],
        "clip": {"x": 0, "y": 0, "width": 1440, "height": 800},
    }
]
```

Available action types:

- `wait`: wait for a selector, for example `{"type": "wait", "selector": ".metrics", "timeout": 2000}`
- `click`: click an element, for example `{"type": "click", "selector": ".theme-toggle"}`
- `scroll`: scroll to a position, for example `{"type": "scroll", "position": 500}`
- `wait_time`: wait a number of milliseconds, for example `{"type": "wait_time", "ms": 300}`

</details>

<details>
<summary>Screenshot troubleshooting</summary>

| Issue | Solution |
| --- | --- |
| `.venv` not found | Create it with `python3.12 -m venv .venv`, then bootstrap the repository dependencies |
| Playwright or Chromium missing | Run `./sample-reports/scripts/capture_screenshots.py --check-dependencies` |
| Sample reports not found | Run from the repository root |
| Screenshots too large | Lower `JPEG_QUALITY` or reduce the viewport size |
| Browser launch fails | Run `playwright install-deps` (Linux only) |

</details>

<a id="3-update-readme"></a>

#### 3. Update the README

After generating new screenshots, confirm that `README.md` references them
(for example, `sample-reports/dashboard-overview-light.png` and
`sample-reports/findings-table.png`) with accurate captions.

#### 4. Rebuild the Changes Sample

After regenerating a sample report, rebuild the changes sample and golden files
with the procedure in
[Rebuilding the Changes Sample and Golden Files](#rebuilding-the-changes-sample-and-golden-files).

### Documentation Best Practices

- **Keep screenshots optimized**: target 200-300 KB per image.
- **Use descriptive filenames**: `dashboard-overview-light.png`, not `screenshot1.png`.
- **Update HTML and screenshots together** when making UI changes.
- **Check rendering** in GitHub's Markdown preview.
- **Keep all screenshot tooling** in `sample-reports/`.

## Contributing and Releases

### Declaring Deployment Impact

Every releasable behavior or deployment change must update the root
`CHANGELOG.md` under `## Unreleased`; a release need not be created for every
merged change. Consolidate multiple commits for one logical change into one
user-focused entry under the applicable `Added`, `Changed`, `Fixed`,
`Deprecated`, `Removed`, or `Security` subsection.

Whenever deployable files change, the `Unreleased` section needs a
`Deployment impact` subsection. State exactly which actions users must take
(no deployment, a CodeBuild run, a single-account infrastructure update, a
multi-account member-role StackSet update, and/or a multi-account central
infrastructure update), name every changed top-level template, and give the
required order; the member-role StackSet update must complete before CodeBuild
runs. For the mapping from changed paths to required actions, see
[Determine what changed](UPGRADING.md#determine-what-changed). When a release is
pinned by tag or commit, remind users to update the `GitHubBranch` stack
parameter.

When a version is tagged, move the accumulated entries into a dated
`## <version> - YYYY-MM-DD` section and recreate an empty `Unreleased`
section. Do not rewrite released entries except to correct an error.

## CI/CD Workflows

GitHub Actions workflows validate code quality and security on pull requests.

### PR Checks

| Workflow | File | What it checks |
| --- | --- | --- |
| **Python Code Quality** | `.github/workflows/python-lint.yml` | `ruff check` and `ruff format --check` on the PR's changed `.py` files |
| **AI/ML Security Assessment Tests** | `.github/workflows/python-tests.yml` | Four pytest steps: `tests/` with coverage; `responsible_ai_grc_tests/`; the report pipeline (`tests/test_consolidate_responsible_ai_grc.py`, then `test_generate_report.py` from the report package directory); and the `assessment_history` 100% line and branch coverage gate |
| **CloudFormation Lint** | `.github/workflows/cfn-lint.yml` | `cfn-lint` on the deployment and SAM templates |
| **SAM Validate & Build** | `.github/workflows/sam-validate.yml` | `sam validate --lint` on both SAM templates and `sam build` on the single-account template |
| **ASH Security Scan** | `.github/workflows/ash-security-scan.yml` | Secrets, dependency vulnerabilities, and IaC misconfigurations in changed files |

PR checks target `main`. The test workflow runs only when its watched paths
change: `aiml-security-assessment/functions/security/**`, `tests/**`,
`assessment_history/**`, `buildspec.yml`, `deployment/**`, `sample-reports/**`,
`consolidate_html_reports.py`, or the workflow file itself. It also runs on
pushes to `main` and `develop` that touch those paths.

cfn-lint suppressions for IAM actions not yet in its database (for example,
`bedrock-agentcore` actions) are configured in `.cfnlintrc` at the repository
root.

### Post-Merge and Automation Workflows

| Workflow | File | Trigger |
| --- | --- | --- |
| **ASH Full Repository Scan** | `.github/workflows/ash-full-repository-scan.yml` | Push to `main`, monthly schedule, and manual dispatch |
| **Labeler** | `.github/workflows/label.yml` | Every pull request (`pull_request_target`); applies labels from `.github/labeler.yml` by changed path: `bedrock`, `sagemaker`, `agentcore`, `report`, `deployment`, `documentation`, and `infrastructure` |

### Running Checks Locally

This is the canonical command list linked from [AGENTS.md](../AGENTS.md).
Run Python, pip, pytest, Ruff, and cfn-lint through `.venv/bin/` so a stale
shell activation cannot reach the system interpreter. Use `git` and the
system-installed `sam` normally.

```bash
# Bootstrap or refresh the repository-local virtual environment
# (create it first with `python3.12 -m venv .venv`; ruff and cfn-lint are not
# in any requirements file, so they are installed explicitly)
.venv/bin/pip install ruff cfn-lint -r tests/requirements.txt \
  -r aiml-security-assessment/functions/security/agentcore_assessments/requirements.txt \
  -r aiml-security-assessment/functions/security/agent_registry_assessments/requirements.txt \
  -r aiml-security-assessment/functions/security/bedrock_assessments/requirements.txt \
  -r aiml-security-assessment/functions/security/cleanup_bucket/requirements.txt \
  -r aiml-security-assessment/functions/security/responsible_ai_grc_assessments/requirements.txt \
  -r aiml-security-assessment/functions/security/generate_consolidated_report/requirements.txt \
  -r aiml-security-assessment/functions/security/iam_permission_caching/requirements.txt \
  -r aiml-security-assessment/functions/security/owasp_assessments/requirements.txt \
  -r aiml-security-assessment/functions/security/resolve_regions/requirements.txt \
  -r aiml-security-assessment/functions/security/sagemaker_assessments/requirements.txt
.venv/bin/pip check

# Lint and format the whole repository, including uncommitted work.
# This covers the changed Python files that CI checks.
# Ruff automatically loads the repository's ruff.toml.
.venv/bin/ruff check .
.venv/bin/ruff format --check .

# Environment for every pytest session
export AIML_ASSESSMENT_BUCKET_NAME=test-assessment-bucket
export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=testing
export AWS_SECRET_ACCESS_KEY=testing

# 1. Main suite: one session covers every package under tests/
.venv/bin/python -m pytest tests/ -v --tb=short

# 2. assessment_history: 100% line and branch coverage
.venv/bin/python -m pytest tests/test_assessment_history_*.py \
  --cov=assessment_history --cov-branch --cov-report=term-missing \
  --cov-fail-under=100

# 3. Responsible AI GRC suite: separate session with its own conftest
.venv/bin/python -m pytest aiml-security-assessment/functions/security/responsible_ai_grc_tests/ -v --tb=short

# 4. Report pipeline: runs from the report package directory
(cd aiml-security-assessment/functions/security/generate_consolidated_report \
  && ../../../../.venv/bin/python -m pytest test_generate_report.py -v --tb=short)

# Responsible AI GRC provenance (when changing its app.py or catalog)
.venv/bin/python generate_provenance.py --check

# CloudFormation lint
.venv/bin/cfn-lint deployment/*.yaml \
  aiml-security-assessment/template.yaml \
  aiml-security-assessment/template-multi-account.yaml

# SAM validate and build (sam is installed system-wide)
(cd aiml-security-assessment \
  && sam validate --template template.yaml --lint \
  && sam validate --template template-multi-account.yaml --lint \
  && sam build --template template.yaml \
  && sam build --template template-multi-account.yaml)
```

If `generate_provenance.py --check` reports stale provenance, run
`.venv/bin/python generate_provenance.py` and commit the regenerated
`responsible_ai_grc_assessments/provenance.json`; do not edit it by hand.

<a id="monitoring-and-debugging"></a>

## Support and Resources

### Debugging

For common issues, CodeBuild and Step Functions debugging, and incomplete
findings, see [Debugging](TROUBLESHOOTING.md#debugging) in the Troubleshooting
Guide.

### Documentation

- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [AWS Security Best Practices](https://aws.amazon.com/security/security-resources/)
- [AWS SAM Developer Guide](https://docs.aws.amazon.com/serverless-application-model/)

---

As you add services, checks, lenses, or compliance standards, update this guide
so future contributors can build on your work.
