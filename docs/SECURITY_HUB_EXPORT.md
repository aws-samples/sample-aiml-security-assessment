# Security Hub CSPM export

Set `EnableSecurityHubExport=true` on either top-level deployment template to
export assessment snapshots after the HTML report is saved. It defaults to
`false`: no Security Hub client is created and no import permission is granted.
CodeBuild forwards the setting to every member, management, or single-account
SAM deployment. Direct SAM deployments accept the same parameter. Execution
input cannot enable export; the report Lambda reads its deployment setting.

## Prerequisites and permissions

Enable Security Hub CSPM in **each assessed account, in the deployment region**
first. Export uses the account's default custom product:
`arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default`.
The product name is `AI/ML Security Assessment` and generator IDs identify the
check, for example `aiml-security-assessment/BR-01`.

Only the report Lambda receives `securityhub:BatchImportFindings`, scoped to
that account's default-product ARN, and only when enabled. No import grants
are added to CodeBuild or member deployment roles. This feature does not enable
Security Hub, register a partner product, change account policies, or remediate
assessed resources. Additional Security Hub charges may apply.

Multi-account runs import locally in each member account; they do not send
another account's findings from the central account. Configure delegated
administration and aggregation separately for centralized visibility.
Multi-region observations are imported into the deployment-region endpoint;
their account resource identifies the assessed region. Global checks retain
`Global` in `ProductFields.AssessedRegion` and use the deployment region on
their resource.

## Snapshot semantics

Each ASFF finding summarizes one check and assessed region for one execution.
The CSV has no uniform resource identifier, so the resource is the assessed
AWS account, not an inferred ARN extracted from free text. Duplicate rows are
collapsed; multiple observations are counted and summarized. Titles,
descriptions, and remediation text are bounded to ASFF limits: consult the
HTML/CSV report for complete details.

- Failed observations take precedence and use the highest reported severity.
- Passed checks have `Compliance.Status=PASSED` and informational severity.
- Inconclusive/not-applicable checks have `NOT_AVAILABLE`, not a clean pass.
- Deselected services and hidden Responsible AI GRC source rows are excluded.
- IDs hash the execution ARN, start time, check ID and region. Retrying an execution
  reuses its IDs and observation timestamp. New assessments create new
  snapshots. **This is not resource-level lifecycle reconciliation:** old
  snapshots are not automatically resolved or archived. Filter by
  `ExecutionId` and apply a retention/workflow policy separately.
- Provider severity/types use `FindingProviderFields`; customer workflow,
  verification state, notes, and user-defined fields are not overwritten.

Batches contain at most 100 findings. API errors, partial rejections (including
Security Hub not being enabled), or unexpected success counts fail the report
task visibly rather than claiming a successful export. The HTML report has
already been stored. Fix the prerequisite and retry the task. Disabling export
stops new imports and removes the runtime grant; old findings are not deleted.

## Deployment and local verification

Update `deployment/aiml-security-single-account.yaml` for single-account mode
or `deployment/2-aiml-security-codebuild.yaml` for multi-account mode, then run
CodeBuild to redeploy the SAM stacks. Direct SAM users update the applicable
SAM template. No member-role StackSet update is required.

Tests use SDK-shaped mocks and botocore validation; they import no live
findings. Run `tests/test_securityhub_export.py`,
`tests/test_securityhub_export_wiring.py`, the required repository suites, and
both SAM validation/build paths before submitting changes.

References: [custom products](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-custom-providers.html),
[provider updates](https://docs.aws.amazon.com/securityhub/latest/userguide/finding-update-batchimportfindings.html),
[BatchImportFindings](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_BatchImportFindings.html).
