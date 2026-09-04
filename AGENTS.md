# AGENTS.md

This file provides guidance to coding agents when working with code in this repository.

## What this is

A serverless framework that scans AWS accounts for AI/ML security misconfigurations and produces interactive HTML reports. The full catalog contains 208 checks across seven assessment areas: 94 core checks (40 Amazon Bedrock, 29 Amazon SageMaker AI with `SM-29` reserved, 17 Amazon Bedrock AgentCore, and 8 AWS Agent Registry), 38 always-on Agentic AI Security checks, 64 optional Responsible AI GRC checks, and 12 optional OWASP Top 10 for LLM checks. Checks are derived from the AWS Well-Architected Generative AI Lens, the Agentic AI Lens, AWS Responsible AI GRC guidance, and the OWASP Top 10 for LLM 2025.

## Commands

**All Python tooling runs from the repo-local `.venv/`** — pytest, ruff, cfn-lint, and pip live under `.venv/bin/`. Do not use system `python`/`python3` or `pip install` globally; the version pins in `tests/requirements.txt` and each Lambda's `requirements.txt` are only reproducible inside the venv. `sam` is system-installed (Homebrew).

**Everything under `tests/` runs as one pytest session.** Multiple assessment packages each have a top-level `app.py`, so each test module loads its package through `importlib.util.spec_from_file_location` under a distinct module name (`bedrock_app`, `agentcore_app`, `agent_registry_app`, …) rather than a bare `import app`. Follow that pattern for a new package's tests; a bare `import app` after `sys.path.insert` collides with whichever package was imported first and produces confusing cross-package failures.

The suites that need their **own** session are the ones that live outside `tests/`: `responsible_ai_grc_tests/` (its own `conftest.py`) and `generate_consolidated_report/test_generate_report.py` (runs from its own directory).

```bash
# Bootstrap / refresh venv (run once, or after requirements files change)
.venv/bin/pip install -r tests/requirements.txt \
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

# Verify tooling is picked up from the venv (not the system Python)
.venv/bin/python --version         # 3.12.x matches the Lambda runtime and CI
.venv/bin/pip check                 # dependency sanity — no conflicts
which -a python pytest ruff cfn-lint  # the venv paths should win when PATH-activated

# Required env vars for any test run (see tests/conftest.py for the autouse fixture)
export AIML_ASSESSMENT_BUCKET_NAME=test-assessment-bucket
export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=testing
export AWS_SECRET_ACCESS_KEY=testing

# Core suite — one session covers every package under tests/
.venv/bin/python -m pytest tests/ -v --tb=short

# Responsible AI GRC suite — separate session (lives outside tests/, own conftest)
.venv/bin/python -m pytest aiml-security-assessment/functions/security/responsible_ai_grc_tests/ -v --tb=short

# Report-pipeline tests live next to the report code and run from that dir
(cd aiml-security-assessment/functions/security/generate_consolidated_report \
  && ../../../../.venv/bin/python -m pytest test_generate_report.py -v --tb=short)

# Single test
.venv/bin/python -m pytest tests/test_bedrock_checks.py::test_name -v

# Lint / format (CI gate — Ruff automatically loads the repository's ruff.toml).
# CI (.github/workflows/python-lint.yml) runs ruff over the PR's *changed*
# .py files, not a fixed directory. Match that scope locally — otherwise a
# ruff diff in tests/ or consolidate_html_reports.py passes the security/
# subtree scan and still fails CI (this bit us on PR #53).
changed_py=$(git diff --name-only --diff-filter=ACMR origin/main...HEAD -- '*.py')
.venv/bin/ruff check         $changed_py
.venv/bin/ruff format --check $changed_py
# Fallback / belt-and-braces — check the whole repo before pushing:
.venv/bin/ruff check .
.venv/bin/ruff format --check .

# Template validation
.venv/bin/cfn-lint deployment/*.yaml aiml-security-assessment/template.yaml aiml-security-assessment/template-multi-account.yaml
(cd aiml-security-assessment && sam validate --template template.yaml --lint && sam build --template template.yaml)

# Invoke one assessment Lambda locally (sam build requires Python 3.12 on PATH for the target runtime)
(cd aiml-security-assessment && sam build --template template.yaml && sam local invoke BedrockSecurityAssessmentFunction --event testfile.json)
```

Prefix every command with `.venv/bin/` explicitly (rather than relying on `source .venv/bin/activate`) so a stale shell activation cannot silently reach the system interpreter — that mistake is why previous runs failed with `No module named pytest`.

## Architecture

**Two-phase, two-mode.** Phase 1 is CloudFormation deployment of roles + central infra; phase 2 is CodeBuild (`buildspec.yml`) orchestrating per-account SAM deploys and Step Functions executions. The same code runs in **single-account** mode (one account, deployed via `template.yaml`) and **multi-account** mode (Organizations-wide, `template-multi-account.yaml` + `deployment/2-aiml-security-codebuild.yaml` assuming `AIMLSecurityMemberRole` cross-account).

**Step Functions workflow** (`aiml-security-assessment/statemachine/assessments.asl.json`): Cleanup S3 → IAM Permission Caching (global, once) → Resolve Regions → **Map over regions** (`MaxRegionConcurrency`) → Bedrock / SageMaker / AgentCore / AWS Agent Registry plus conditional Responsible AI GRC → conditional OWASP → Generate Consolidated Report. Responsible AI GRC runs only at `RegionIndex == 0` when `enableResponsibleAIGRC == "true"` or `enableOWASP == "true"`. Direct execution input using legacy `"enableFinServ": "true"` is rejected; the legacy CloudFormation parameter remains supported through CodeBuild alias resolution.

**Each direct service Lambda** (`functions/security/{bedrock,sagemaker,agentcore,agent_registry}_assessments/app.py`) probes service availability, reads cached IAM permissions from S3 where needed, creates regional boto3 clients with explicit `region_name`, runs checks, and writes a region-suffixed CSV. Agent Registry receives the Step Functions `Execution` object and must derive the shared artifact/cache key from `Execution.Name`, writing `agent_registry_security_report_<execution_id>_<region>.csv`. Pass `region=` to every `create_finding()` call. `responsible_ai_grc_assessments/app.py` runs once and writes `responsible_ai_grc_security_report_<execution_id>.csv`. `owasp_assessments/app.py` reads the BR/SM/AC regional CSVs plus that unsuffixed Responsible AI GRC CSV on the first region, maps OW-01..OW-10, runs native OW-11/OW-12 checks, and writes region-suffixed OWASP CSVs. Agent Registry rows are intentionally excluded from OWASP source ingestion because the current AR controls do not prove an LLM01–LLM10 control. When OWASP is enabled by itself, FS-* source rows are hidden from the report UI.

**Findings are CSV rows with a shared base schema** produced by `create_finding()` in each package's `schema.py`: `Check_ID, Finding, Finding_Details, Resolution, Reference, Severity, Status, Region`. Responsible AI GRC extends this with `Compliance_Frameworks`; the report layer ignores unknown extra columns but downstream CSV consumers may depend on them. The report layer parses CSVs back into findings, so the base column set and `Check_ID` prefix are a contract the report depends on.

### Conventions that span files

- **Check ID prefixes** drive report routing: `BR-` Bedrock, `SM-` SageMaker, `AC-` AgentCore, `AR-` AWS Agent Registry, `AG-` Agentic AI, `FS-` Responsible AI GRC (legacy identifier retained for compatibility), and `OW-` OWASP Top 10 for LLM. The report reconstructs Agentic AI from `AG-` and compliance sections through `COMPLIANCE_STANDARDS` in `report_template.py`.
- **Agentic AI lens is synthesized**, not separately scanned. `AGENTIC_BEDROCK_CHECK_MAPPINGS`, `AGENTIC_AGENTCORE_CHECK_MAPPINGS`, and `AGENTIC_AGENT_REGISTRY_CHECK_MAPPINGS` re-map BR-/AC-/AR- findings into AG- rows; `AG-24..27` are native AgentCore gateway checks. New AG numbers must be allocated by hand across all three mapping modules to avoid collisions.
- **OWASP is synthesized plus native checks.** `OWASP_CHECK_MAPPINGS` in `owasp_assessments/app.py` maps existing BR-/SM-/AC-/FS- source rows into OW-01..OW-10 rows. Agent Registry rows are intentionally not read or mapped: current `AR-*` controls establish Registry governance, not a direct OWASP LLM01–LLM10 control. OW-11 and OW-12 are native LLM07 checks. Mapping values are lists because one source check can emit multiple OW rows. When updating mappings, verify every mapped source ID still exists in its source scanner and every emitted OW ID is documented in `docs/SECURITY_CHECKS_OWASP.md`.
- **`schema.py` is duplicated into function packages because SAM packages each Lambda independently.** The base schema is shared across Bedrock, SageMaker, AgentCore, AWS Agent Registry, OWASP, IAM caching, and report generation. Responsible AI GRC intentionally adds `Compliance_Frameworks`. Edit all relevant copies together if the base schema changes, and preserve the Responsible AI GRC extension deliberately. `report_template.py` is shared by the Lambda (`mode='single'`) and root `consolidate_html_reports.py` (`mode='multi'`).
- **Assessment-runtime IAM permissions live only in the two SAM templates' per-Lambda `Policies`.** The three top-level deployment templates define orchestration roles that deploy/update the SAM stack, poll Step Functions, and retrieve reports; they must not receive Bedrock, SageMaker, AgentCore, Agent Registry, or other assessment-service read permissions. A new boto3 call that lacks a SAM grant fails silently at runtime, and because access-denied resolves to `N/A` (see status semantics), the affected checks vanish from the report rather than erroring, so the gap is invisible without an audit. `.cfnlintrc` suppresses cfn-lint errors for actions not yet in its database, such as `bedrock-agentcore`.
  - **The canonical multi-account member role uses one customer-managed deployment/report policy**, not inline policies. `tests/test_member_role_policy_size.py` renders it with `aws-us-gov` (the longest partition) and keeps it below the 5,500-character project budget.
  - `deployment/2-aiml-security-codebuild.yaml` and `deployment/aiml-security-single-account.yaml` do not define local `MemberRole` resources. Single-account runs deploy directly under `CodeBuildRole`; multi-account runs assume the StackSet-deployed role from `deployment/1-aiml-security-member-roles.yaml`.
  - The SAM templates scope permissions **per-Lambda**, so a new grant must land on the specific function's policy that makes the call (a `bedrock` call on `BedrockSecurityAssessmentFunction`, a `bedrock-agentcore` call on `AgentCoreSecurityAssessmentFunction`, or an `agent-registry` call on `AgentRegistrySecurityAssessmentFunction`), not just somewhere in the file.
  - **Auditing coverage:** extract every `<client>.<op>(` and `get_paginator("<op>")`, map each to its IAM action (PascalCase), and check presence per file. Watch the prefix nuances below; map ops to actions, not service-client names.
  - **Whenever a new check is added, its IAM permissions MUST be validated against the AWS Knowledge MCP server** (`mcp__AWS_Knowledge__aws___search_documentation` / `mcp__AWS_Knowledge__aws___read_documentation`) before merging. Use it to confirm (a) the exact IAM action name and prefix for every new boto3 op, (b) which client (data-plane vs. control-plane) the op lives on, and (c) any resource-ARN or condition-key constraints. If the audit shows a gap, update both SAM templates in the same commit that adds the check — never defer. Update a top-level deployment role only when the deployment workflow itself starts making a new AWS API call.
- **boto3 service, IAM prefix, and variable name are separate.** Four API/IAM review traps to keep straight: (1) `bedrock-agent` operations (`get_agent`, `list_agents`, `get_knowledge_base`, `get_flow`, `get_prompt`, `list_data_sources`, etc.) are granted under the **`bedrock:`** IAM prefix, not `bedrock-agent:`. (2) AgentCore describe/list/get-config ops live on the **`bedrock-agentcore-control`** client (control plane), not the data-plane `bedrock-agentcore` client; calling them on the wrong one is an `AttributeError` at runtime. The IAM prefix for both is `bedrock-agentcore:`. (3) AWS Agent Registry uses the **`agent-registry-control`** client but the **`agent-registry:`** IAM prefix; its `ProvenanceSummary` model uses `relation`, `sourceId`, and `sourceType` (not `source`). (4) Some functions name a variable `bedrock_client` that is actually bound to `boto3.client("bedrock-agent")`, such as `check_bedrock_prompt_management` and `check_bedrock_agent_roles`. Verify which **service string** a client was constructed with before judging whether an operation exists on it; do not trust the variable name. The authoritative source for whether an operation or paginator exists on a service is the installed botocore service model (`data/<service>/*/service-2.json`), not docs from memory.
- **Optional policy baselines are deployment parameters, not hard-coded assumptions.** Keep these wired through both SAM templates, both top-level deployment templates, CodeBuild environment variables, and `buildspec.yml`: `RequireBedrockZeroDataRetention`, `RequireMarketplaceEndpointCMK`, `RequireAgentCoreOnlineEvaluation`, `RequireAgentRegistryManualApproval`, `RequireAgentRegistryCMK`, `AgentCoreTokenVaultId`, `ApprovedExternalAccountIds`, and `ApprovedOrganizationIds`.
- **`CHANGELOG.md` is the end-user deployment-impact contract.** Every releasable code change that modifies assessment behavior, dependencies, `buildspec.yml`, `consolidate_html_reports.py`, anything under `aiml-security-assessment/`, or a top-level `deployment/*.yaml` template MUST update the root `CHANGELOG.md` under `## Unreleased`. Consolidate multiple commits for one logical change into one user-focused entry rather than recording commit-by-commit implementation details. Tests, formatting, and internal refactors need an entry only when they change user-visible behavior or deployment requirements.
  - Use the applicable `Added`, `Changed`, `Fixed`, `Deprecated`, `Removed`, or `Security` subsection.
  - The `Unreleased` section MUST contain a `Deployment impact` subsection whenever deployable files change. State exactly which actions are required: no deployment, CodeBuild run, single-account infrastructure update, multi-account member-role StackSet update, and/or multi-account central infrastructure update. Name every changed top-level template and specify ordering when the member-role StackSet must precede CodeBuild.
  - When creating a tagged release, move the accumulated entries from `Unreleased` into a versioned `## <version> - YYYY-MM-DD` section and recreate an empty `Unreleased` section. Never rewrite previously released entries except to correct an error.
- **Documentation review is mandatory for catalog changes.** When adding, removing, renumbering, or materially changing a check, service assessment, lens, or compliance standard, review every repository document that could describe its scope, count, architecture, check IDs, deployment parameters, artifacts, status semantics, mappings, or troubleshooting path. At minimum review `README.md`, `docs/DEVELOPER_GUIDE.md`, `docs/SECURITY_CHECKS.md`, the applicable `docs/SECURITY_CHECKS_*.md` catalog(s), `docs/TROUBLESHOOTING.md`, and `CHANGELOG.md`; also review the relevant scope, migration, severity, sample-report, and diagram documentation. Update every document that has drifted in the same change — do not limit the update to the per-check catalog. A new service or compliance standard additionally requires checking deep links, tables of contents, report screenshots/sample reports, and all check-count locations.
- **One check's failure must not erase the whole assessment.** Each check call in a handler is wrapped so an unexpected exception becomes a single visible `N/A` "Incomplete" row for that `Check_ID` — `_run_check_safely()` in `agent_registry_assessments/app.py`, `AC-00` diagnostic rows in `agentcore_assessments/app.py` — and the handler still writes its CSV. Watch the inverse trap: a top-level `except` that logs and returns `{"statusCode": 500}` **without raising** is an invisible failure. The Lambda invocation succeeds, so the Step Functions `Catch` never fires, no CSV is written, and the report renders that assessment area empty with zero counts and no error indication. Anything that swallows an exception at handler scope must still emit findings and write the artifact.
- **IAM policy `Statement` is a dict *or* a list.** Both forms are valid IAM. Iterating `_policy_document(policy).get("Statement", [])` directly walks dict *keys* when a policy has a single statement object, silently skipping it and under-reporting overly permissive grants. Normalize through a helper — `_policy_statements()` in `agent_registry_assessments/app.py` — and cover both shapes in tests.
- **The report's Assessment Scope block is patched by post-render string replacement.** `generate_html_report()` in `report_template.py` injects service chips and the lens-source sentence with `str.replace()` against exact HTML substrings from the template literal (see the `base_scope_source` and `AWS Agent Registry` chip replacements). Adding or renaming an assessment area means updating the template literal **and** every replace anchor that targets it. A drifted anchor fails silently: `str.replace` matches nothing, and the chip or sentence just never appears. Verify by generating a report, not by reading the code.
- **Never use real AWS identifiers in repository artifacts.** Tests, fixtures, documentation examples, snapshots, and generated sample reports must use synthetic account IDs, organization IDs, ARNs, and resource identifiers. Never copy identifiers from live accounts, logs, assessment output, screenshots, prompts, or reproduction evidence into committed files. Prefer the established synthetic account IDs `123456789012`, `111122223333`, and `444455556666`, and patterned organization IDs such as `o-a1b2c3d4e5` and `o-f6g7h8i9j0`. When a change introduces or modifies identifiers, scan the changed files before committing and verify that every value is synthetic.

### Status / error semantics

- `Passed` = checked and compliant; `Failed` = checked and non-compliant; `N/A` = nothing to check (no resources) or the API/feature is unavailable in this region/account. Region-unavailable and access-denied paths should resolve to `N/A`, not `Failed`/`ERROR`. Reuse the package's own helpers rather than re-inlining error-string checks: `is_region_unsupported()` and `describe_api_error()` in `bedrock_assessments/app.py`, and `_is_unavailable()` / `_is_access_denied()` / `_error_detail()` / `_error_resolution()` / `_na()` in `agent_registry_assessments/app.py`.
- **Every new regional check MUST handle regional API/feature unavailability explicitly.** When the service is reachable but the specific API or feature is unsupported in the assessed region, emit an `N/A` finding with `Informational` severity and a clear availability message; do not emit `Failed`, abort the Lambda, or suppress the regional report. Reuse the package's existing availability helpers and recognized service/region error codes instead of adding ad hoc exception-string checks. Do not classify `AccessDenied` or an unexpected SDK/programming error as regional unavailability. Tests for every new regional check must cover an unsupported API/feature or disabled-region path and verify that access-denied and unexpected-error paths remain distinguishable.
- Per-resource detail calls inside a list loop should be individually try/excepted so one resource's error, such as a throttle or delete race, does not abort the whole check.
- List APIs must paginate with `get_paginator` or an explicit next-token helper, such as `_agentcore_list_all` where no paginator exists. `maxResults=100` or `MaxResults=100` without continuation handling silently truncates and hides non-compliant resources.
- **Tooling/data conditions are not findings.** An empty permission cache, a missing prerequisite, or any "the assessment could not run this" state is `N/A` plus `Informational`, never `Failed`. A `Failed` finding paired with `resolution="No action required"` is a contradiction: it inflates the failed count with a non-actionable row and is a reliable smell that a tooling condition was mislabeled.
- **Advisory gaps are not compliant passes.** When a baseline is optional and the scanner observes a hardening gap, prefer `N/A`/`Informational`; reserve `Passed` for a control that was checked and satisfied. Passed rows should not carry remediation instructions.
- **An incomplete inventory still reports what it collected.** When pagination stops at a safety cap or the Lambda deadline, emit the `N/A`/Informational incomplete-assessment notice *in addition to* the per-resource findings already gathered, not instead of them. Returning only the notice hides non-compliant resources that were successfully inventoried — exactly the resources a large account most needs flagged. Both `AR-07` and `AR-08` follow this pattern for truncation and timeout; mirror it for any new bounded inventory.
- **"Indeterminate" is not "absent."** When a probe returns nothing because it was access-denied or inconclusive, such as `detect_bedrock_regional_footprint` returning `None` vs `False`, the N/A finding text must not assert "No resources found"; that claims an absence never established. Use distinct wording for the indeterminate case, such as `bedrock_footprint_na_detail`. When widening a guard from `is False` to `is not True`, check that the new `None` path does not inherit absence-claiming text.

### Review checklist (run before committing changes to checks or IAM)

When reviewing a diff that touches assessment code or policies, verify, in order:

1. **API names** — every boto3 op and paginator exists on the *service its client was constructed with* (check the `boto3.client("…")` string, not the variable name); validate against botocore service models.
2. **IAM coverage** — every new assessment op is granted in both SAM templates on the correct per-Lambda policy, and is absent from the deployment/member roles. **For any newly added check, validate the required IAM actions against the AWS Knowledge MCP server** (`mcp__AWS_Knowledge__aws___search_documentation` / `aws___read_documentation`) rather than relying on memory, and update both SAM templates in the same commit if any grant is missing. Review top-level deployment policies separately only for deployment-time API changes.
3. **Status semantics** — access-denied/region-unsupported → `N/A` (via `is_region_unsupported()`/`describe_api_error()`); tooling conditions → `N/A`/`Informational`, never `Failed`; no `Failed` + "No action required"; indeterminate ≠ absent in finding text.
4. **Pagination & per-resource try/except** — no truncating list calls; per-resource detail calls isolated.
5. **AG- numbering** — no collisions across the Bedrock, AgentCore, and Agent Registry mapping dictionaries and native `AG-24..27`; the current catalog is `AG-01..38`, and every mapped source ID must still exist.
6. **OWASP/compliance mapping drift** — every `OWASP_CHECK_MAPPINGS` source ID still exists in its scanner, every source CSV the OWASP Lambda reads actually feeds at least one mapping, every emitted `OW-` ID is documented in `docs/SECURITY_CHECKS_OWASP.md`, and `COMPLIANCE_STANDARDS` prefixes in `report_template.py` match the report/consolidator routing expectations. Values in mappings are lists (one source check can emit multiple OW rows). An `N/A` source must produce `Severity=Informational` on the OW row (never inherit High/Medium).
7. **CSV schema drift** — base columns remain present everywhere; Responsible AI GRC's `Compliance_Frameworks` remains intentional and documented; report parsing continues to tolerate the extra column.
8. **Test coverage** — every new check needs compliant/pass, non-compliant/fail (or advisory N/A), no-resource, and access-denied/API-unavailable coverage. Shared inventories need list-error and per-resource detail-error tests. Policy parsers need both accepted-boundary and false-positive/false-negative regression cases.
9. **Identifier hygiene** — no real AWS account IDs, organization IDs, ARNs, or resource identifiers appear in tests, fixtures, examples, snapshots, or generated reports; all newly introduced values are clearly synthetic.
10. **Documentation completeness** — for every catalog change, review `README.md`, `docs/DEVELOPER_GUIDE.md`, `docs/SECURITY_CHECKS.md`, applicable `docs/SECURITY_CHECKS_*.md` catalogs, `docs/TROUBLESHOOTING.md`, `CHANGELOG.md`, and any relevant scope, migration, severity, sample-report, or diagram documentation. Check count locations, headings/TOC/deep links, service and compliance-standard routing, report artifacts, deployment parameters, and user-facing troubleshooting. Update every affected document in the same change.
11. **Changelog and deployment impact** — every releasable behavior or deployment change is recorded under `CHANGELOG.md` → `Unreleased`; the deployment-impact entry matches the actual changed templates and required update order.
12. **Gates** — `ruff check` and `ruff format --check` clean over the PR's *changed* `.py` files, `cfn-lint` clean on edited templates, and each relevant pytest session passes. Tests assert exact finding text, so reword carefully.

## Docs to consult

- `docs/DEVELOPER_GUIDE.md` — full walkthrough for adding a new service assessment (the 5-step: function → SAM template → Step Functions branch → per-Lambda IAM → local test), report architecture, and the canonical local-check command list. Also covers:
  - "Adding a New Check Inside an Existing Service"
  - "Extending or Adding Lenses"
  - "Adding a Compliance Standard (OWASP-style)" — lists the seven wire-up sites for new OW-/NR-/EU-style standards
  - "Report Verification (Required Before Opening a PR)" — mandatory HTML report generation and visual verification for any new check, lens, or compliance standard
- `docs/SECURITY_CHECKS.md` / `docs/SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md` / `docs/SECURITY_CHECKS_OWASP.md` — authoritative check inventory. Check counts appear in five places and must move in lockstep: this file's "What this is" paragraph, `README.md`, `docs/DEVELOPER_GUIDE.md`, and both the intro paragraph and per-service table in `docs/SECURITY_CHECKS.md`. Section headings carry their count (`## AWS Agent Registry Security Checks (8)`), so changing a count changes the anchor — re-check every `SECURITY_CHECKS.md#...` deep link in `README.md` and the table of contents.
- `docs/RESPONSIBLE_AI_GRC_SCOPE.md` / `docs/RESPONSIBLE_AI_GRC_ALIAS_MIGRATION.md` — scope and legacy FinServ alias behavior.
- `docs/TROUBLESHOOTING.md` — runtime/deployment debugging.
- `CHANGELOG.md` — user-facing release history and the authoritative deployment actions for `Unreleased` and tagged versions.
