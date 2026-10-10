# AGENTS.md

Repository-wide instructions for coding agents working on this AWS AI/ML security assessment
framework. It deploys assessment Lambdas with SAM and Step Functions, writes findings CSVs, and
renders single- and multi-account HTML reports. The current check inventory, counts, and check
IDs are in [docs/SECURITY_CHECKS.md](docs/SECURITY_CHECKS.md).

## Start with the task guide

- [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md) covers architecture, adding checks,
  services, lenses and standards, IAM and artifact wiring, report verification, and the
  canonical [local commands](docs/DEVELOPER_GUIDE.md#running-checks-locally).
- [docs/SECURITY_CHECKS.md](docs/SECURITY_CHECKS.md) and the applicable
  `docs/SECURITY_CHECKS_*.md` catalog define each check's claim, evidence, severity, and
  remediation.
- [docs/ASSESSMENT_HISTORY.md](docs/ASSESSMENT_HISTORY.md) covers comparison behavior,
  normalization, coverage, and sample regeneration.
- [docs/RESPONSIBLE_AI_GRC_SCOPE.md](docs/RESPONSIBLE_AI_GRC_SCOPE.md) covers scope and the
  legacy FinServ alias;
  [docs/SECURITY_CHECKS_RESPONSIBLE_AI_GRC_SEVERITY_METHODOLOGY.md](docs/SECURITY_CHECKS_RESPONSIBLE_AI_GRC_SEVERITY_METHODOLOGY.md)
  covers FS severity.
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) covers incomplete results and deployment
  failures. [docs/UPGRADING.md](docs/UPGRADING.md) maps changed paths to deployment actions.
  [CHANGELOG.md](CHANGELOG.md) records release and deployment impact.

## Toolchain and tests

Use the repository `.venv/bin/` executables for Python, pip, pytest, Ruff, and cfn-lint. Do not
install Python packages globally or rely on a shell activation. Use `git` and the
system-installed `sam` normally. Setup, environment variables, SAM commands, and the full test
commands are in the developer guide's
[Running Checks Locally](docs/DEVELOPER_GUIDE.md#running-checks-locally) section.

Run everything under `tests/` in one pytest session. Test modules load each assessment package's
`app.py` under a distinct name with `importlib.util.spec_from_file_location`; a bare
`import app` can resolve to a different package's module. Run `responsible_ai_grc_tests/` in a
separate session and `generate_consolidated_report/test_generate_report.py` from its own directory.
Keep `assessment_history/` at 100% line and branch coverage.

Use the guide's whole-repository `.venv/bin/ruff check .` and `.venv/bin/ruff format --check .`
commands before delivery. Run the relevant pytest sessions, cfn-lint for changed templates, and
SAM validation/build when deployment wiring changes. Generate and inspect both report modes when
a check, lens, standard, or report UI changes.

## Execution and artifact contracts

- The two SAM templates, `aiml-security-assessment/template.yaml` and
  `template-multi-account.yaml`, deploy the assessment runtime. The top-level
  `deployment/*.yaml` templates and `buildspec.yml` deploy and orchestrate it in single- and
  multi-account modes. Keep runtime assessment API permissions on the calling Lambda in
  **both SAM templates**; the top-level roles hold deployment, execution polling, and report
  retrieval permissions.
- The four direct-service `Enable*Assessment` switches (Bedrock, SageMaker, AgentCore,
  AgentRegistry) flow through both deployment modes, CodeBuild, the
  `Configure Service Assessments` Step Functions state, CSV requirements, OWASP source reads,
  and report scope.
  Deselected services appear as **Not selected**, never clean or `N/A`. Optional Responsible AI
  GRC and OWASP remain independent. See the guide's [Service
  Selection](docs/DEVELOPER_GUIDE.md#service-selection) section.
- When adding an optional Step Functions branch, preserve `OriginalInput`, `Execution`,
  `Region`, `RegionIndex`, and selection flags through success, skipped, and caught-error paths.
  Set `ResultPath` explicitly on result-producing `Task` and `Pass` states as well as on
  `Catch`; a catch-path `ResultPath` does not protect successful transitions. Test through the
  following `Choice` and report state.
- A direct service Lambda uses an explicit regional client, passes `region=` to each
  `create_finding()` call, and writes a region-suffixed CSV keyed on `Execution.Name`.
  Responsible AI GRC runs once at `RegionIndex == 0` when GRC or OWASP is enabled and writes an
  unsuffixed CSV. OWASP reads the selected Bedrock, SageMaker, and AgentCore regional CSVs and
  the first-region GRC CSV; it does not ingest Agent Registry rows. Preserve these producer,
  consumer, and selected-artifact contracts when adding an area.
- Finding CSVs contain the base columns
  `Check_ID, Finding, Finding_Details, Resolution, Reference, Severity, Status, Region`.
  Responsible AI GRC also contains `Compliance_Frameworks`. Each SAM Lambda packages its own
  `schema.py`; update the relevant copies together and keep report parsing compatible with extra
  columns. Check ID prefixes (`BR-`, `SM-`, `AC-`, `AR-`, `AG-`, `FS-`, `OW-`) route findings into
  report sections and history.
- `AG-` rows are mapped from direct findings, with native AgentCore gateway checks. OWASP maps
  BR-/SM-/AC-/FS- sources plus native checks; its mapping values are lists, and an `N/A` source
  produces an `OW-` row with `Informational` severity. Verify mapped source IDs, allocated AG
  IDs, and catalog entries whenever these mappings change.
- For any new CSV, trace the key from writer through each consumer. Grant `s3:PutObject` to the
  writer, and `s3:ListBucket` and `s3:GetObject` to each consumer where it lists or reads, in
  both SAM templates. Missing, unreadable, or header-only *selected* artifacts must be reported
  as incomplete, including in the multi-account consolidator.
- Optional policy baselines are CloudFormation parameters, not hard-coded scanner assumptions.
  Wire new or changed baselines through both SAM templates, both top-level deployment templates,
  CodeBuild environment variables, and every `sam deploy` path in `buildspec.yml`.

## Check and status contracts

- Before implementing a check, establish the exact AWS client and operation, resource scope,
  response field and allowed values, and the behavior of a successful empty response. Confirm
  operations and paginators against the installed botocore service model and AWS documentation.
  A successful API call alone does not prove `Passed`; keep the predicate, `Check_ID`, finding
  text, resolution, and catalog description aligned.
- For **every new boto3 operation**, validate the IAM action, prefix, client plane, resource
  ARN, and condition keys with the AWS Knowledge MCP documentation tools. Add missing actions to
  the owning Lambda's policy in both SAM templates in the same change. Map actions from the
  client service string and operation, not from a variable name. Review deployment-role IAM only
  if the deployment workflow itself makes a new API call.
- `Passed` means checked and compliant; `Failed` means checked and non-compliant; `N/A` means no
  applicable resource or no conclusive assessment. Access denied and regional API or feature
  unavailability use `N/A`, not `Failed`. An unsupported region or feature must produce an
  `N/A`/`Informational` availability row. Keep denied, unavailable, empty, and incomplete
  inventories distinguishable; an inconclusive probe cannot claim that no resources exist. Use
  each package's existing error helpers.
- Tooling and missing-prerequisite conditions use `N/A`/`Informational`, not `Failed`. Do not
  emit `Failed` with “No action required” or call an optional hardening gap `Passed`; advisory
  gaps use `N/A`/`Informational`. Passed rows must not include remediation instructions.
- Paginate list APIs or handle every continuation token. Isolate per-resource detail errors. Run
  account-global inventories once or de-duplicate them with a truthful `Region`. A complete
  empty inventory emits an explicit `N/A` row for each affected check. On a safety cap or
  deadline, retain collected resource findings **and** add an incomplete notice.
- An unexpected check exception must become a visible incomplete row without erasing the other
  checks or the CSV. An artifact-write failure must raise so Step Functions can catch it; a
  handler that returns `{"statusCode": 500}` without raising can leave an invisible missing
  artifact.

## Before delivering assessment changes

1. Verify the boto3 client, operation, paginator, request/response shape, and the exact evidence
   behind each outcome. Test successful empty responses where the API permits them.
2. Audit per-Lambda assessment IAM in both SAM templates and S3 permissions for every artifact
   reader and writer. Keep assessment-service read actions out of top-level deployment roles.
3. Test compliant, non-compliant or advisory, no-resource, denied, unsupported-region, and
   unexpected-error paths with SDK-shaped responses. Cover later pages, list failures,
   per-resource failures, and two-region behavior where relevant. Assert the exact fallback
   `Check_ID` and visible partial results.
4. Check source-to-lens mappings, AG numbering, CSV schema, selection flags, Step Functions
   success/skip/catch paths, and missing selected artifacts. Render synthetic single- and
   multi-account reports and inspect scope, counts, navigation, and filters.
5. Use only **synthetic** account IDs, organization IDs, ARNs, and resource identifiers in
   tests, examples, fixtures, snapshots, and sample reports. Established example account IDs are
   `123456789012`, `111122223333`, `444455556666`, and `777788889999`.
6. For a catalog change, review `AGENTS.md`, `README.md`, `docs/DEVELOPER_GUIDE.md`,
   `docs/SECURITY_CHECKS.md`, the applicable check catalogs, `docs/TROUBLESHOOTING.md`,
   `CHANGELOG.md`, and affected scope, severity, sample-report, and diagram documentation.
   Update check counts, headings, table-of-contents links, deep links, remediation, and report
   examples where they drift.
7. For releasable behavior, dependency, `buildspec.yml`, consolidator, assessment runtime, or
   deployment-template changes, add one user-facing `CHANGELOG.md` `Unreleased` entry. When
   deployable files change, include `Deployment impact` with the exact single-account,
   CodeBuild, member-role StackSet, and/or central infrastructure actions in the required order.
   Follow [docs/UPGRADING.md](docs/UPGRADING.md).
8. When `responsible_ai_grc_assessments/app.py` or its check catalog changes, run
   `.venv/bin/python generate_provenance.py --check`; if stale, regenerate `provenance.json`
   with `generate_provenance.py` and commit it. When assessment-history matching or samples
   change, run its coverage gate and regenerate the changes sample as directed by
   [docs/ASSESSMENT_HISTORY.md](docs/ASSESSMENT_HISTORY.md).
