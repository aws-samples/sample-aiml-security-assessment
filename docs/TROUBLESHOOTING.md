# Troubleshooting Guide

This guide covers common issues and debugging steps for the AI/ML Security
Assessment framework. For upgrade procedures, see the
[Upgrade Guide](UPGRADING.md). For general questions about cost, scheduling,
and data handling, see the [FAQ](FAQ.md).

## Table of Contents

- [Common Issues](#common-issues)
  - [1. AWS CloudFormation StackSet Deployment Failures](#1-aws-cloudformation-stackset-deployment-failures)
  - [2. Cross-Account Role Assumption or Access Denied Errors](#2-cross-account-role-assumption-or-access-denied-errors)
  - [3. AWS SAM Deployment Failures](#3-aws-sam-deployment-failures)
  - [4. AWS Step Functions Execution Failures](#4-aws-step-functions-execution-failures)
  - [5. EarlyValidation::ResourceExistenceCheck Error](#5-earlyvalidationresourceexistencecheck-error)
  - [6. Responsible AI GRC Checks Do Not Appear in the Report](#6-responsible-ai-grc-checks-do-not-appear-in-the-report)
  - [6b. Execution Fails with `LegacyEnableFinServInputRejected`](#6b-execution-fails-with-legacyenablefinservinputrejected)
  - [7. TargetRegions Validation or Unexpected Region Coverage](#7-targetregions-validation-or-unexpected-region-coverage)
  - [8. CodeBuild Source or GitHub Branch Failures](#8-codebuild-source-or-github-branch-failures)
  - [9. CodeBuild Timeout or Out-of-Memory with Many Accounts](#9-codebuild-timeout-or-out-of-memory-with-many-accounts)
  - [10. No Reports in S3 Bucket](#10-no-reports-in-s3-bucket)
  - [11. Confused by Multiple CloudFormation Stacks](#11-confused-by-multiple-cloudformation-stacks)
  - [12. Upgrading an Existing Deployment to Multi-Region](#12-upgrading-an-existing-deployment-to-multi-region)
  - [13. No "Changes Since Last Assessment" Report](#13-no-changes-since-last-assessment-report)
- [Debugging](#debugging)
- [Moved Sections](#moved-sections)
  - [Check CodeBuild Logs](#check-codebuild-logs)
  - [Verify Cross-Account Role Trust Policies](#verify-cross-account-role-trust-policies)
  - [Check S3 Bucket Permissions](#check-s3-bucket-permissions)
  - [Investigate Incomplete Control Findings](#investigate-incomplete-control-findings)
  - [Investigate Incomplete IAM Permission Cache Findings](#investigate-incomplete-iam-permission-cache-findings)
  - [Monitor AWS Step Functions Executions](#monitor-aws-step-functions-executions)

---

## Common Issues

### 1. AWS CloudFormation StackSet Deployment Failures

**Symptoms:** StackSet instances fail to create in member accounts.

**Solutions:**

- Check that the service-linked roles for AWS CloudFormation StackSets exist.
- If accounts are discovered automatically, verify that the account running the
  central CodeBuild project has AWS Organizations permissions.
- Verify that the target OUs contain active accounts.
- Review the StackSet operation history for specific error messages.

<a id="2-cross-account-role-assumption-failures"></a>
<a id="troubleshooting-questions"></a>

### 2. Cross-Account Role Assumption or Access Denied Errors

**Symptoms:** "Access Denied" errors in the CodeBuild logs, often when assuming
roles in member accounts.

**Causes and solutions:**

- **Member role missing:** verify that `AIMLSecurityMemberRole` exists in each
  target account, and that the member-role StackSet completed successfully in
  every account.
- **Trust relationship:** check that the role's trust policy allows the central
  CodeBuild role (see
  [Verify Cross-Account Role Trust Policies](#verify-cross-account-role-trust-policies)).
  Confirm that the `ManagementAccountID` parameter matches the account where
  the central `MultiAccountCodeBuildRole` runs.
- **Missing permission:** the member role covers only deployment, Step Functions
  execution polling, and report retrieval. If the StackSet runs an older
  template than the central stack, update it (see
  [Multi-Account Upgrade](UPGRADING.md#multi-account-upgrade)).
- **Lambda `AccessDenied`:** errors inside the assessment Lambda functions come
  from the SAM-created execution roles, not the member role. Review the
  relevant function's policy in both SAM templates.

### 3. AWS SAM Deployment Failures

**Symptoms:** CodeBuild fails during the SAM deploy phase.

**Solutions:**

- Check the CodeBuild logs in CloudWatch for the specific error.
- Verify that the GitHub repository URL and `GitHubBranch` parameter point to a
  branch, tag, or commit that CodeBuild can clone.
- Verify that the S3 bucket for SAM artifacts exists and is accessible.
  CodeBuild tries to delete an `aws-sam-cli-managed-default` or assessment
  stack left in `ROLLBACK_COMPLETE` or `DELETE_FAILED` before deploying. If the
  log shows `Failed to delete deployment stack`, delete that stack yourself
  (emptying its bucket first if needed) and run CodeBuild again.
- Look for IAM permission errors in the logs.
- Check whether a previous deployment left orphaned resources (see
  [§5](#5-earlyvalidationresourceexistencecheck-error)).
- Check whether `TARGET_REGIONS` failed validation. It must be empty or a comma-
  or space-separated list such as `us-east-1,us-west-2` or
  `us-east-1 us-west-2`.

### 4. AWS Step Functions Execution Failures

**Symptoms:** A Step Functions execution shows a failed state or times out.

**Solutions:**

- Review the state machine executions in each account (see
  [Monitor AWS Step Functions Executions](#monitor-aws-step-functions-executions)).
- Check the Lambda function logs for errors.
- Verify the Lambda timeouts. Most assessment functions allow 10 minutes.
  Responsible AI GRC allows 15 minutes in the single-account SAM template
  (`template.yaml`) and 10 minutes in `template-multi-account.yaml`.
- Verify that the Lambda execution roles allow access to the required services.
- In multi-region scans, review each region's iteration of the `Scan Regions`
  Map state. One service branch can be marked incomplete while the state
  machine still generates a report for the remaining services and regions.

### 5. EarlyValidation::ResourceExistenceCheck Error

**Symptoms:** CloudFormation blocks stack creation with this error.

**Cause:** A resource with the same fixed name already exists outside the
stack, typically left over from a failed or deleted deployment. The templates
give fixed names to these resources:

- IAM roles `CodeBuildRole` (single-account), `MultiAccountCodeBuildRole`
  (multi-account central), and `AIMLSecurityMemberRole` with its managed policy
  `AIMLSecurityAssessmentDeploymentPermissions` (member accounts)
- CodeBuild projects `AIMLSecurityCodeBuild` and
  `AIMLSecurityMultiAccountCodeBuild`
- Lambda functions named `aiml-security-<assessment-stack-name>-*`

**Solution:** Find the resource named in the error, confirm it is not used by
another deployment, and delete it or delete the stack that still owns it. Then
start the deployment or CodeBuild again.

S3 buckets are not given fixed names, so they do not cause this error. To
remove leftover report buckets, see
[Emptying and Deleting Versioned S3 Buckets](CLEANUP.md#emptying-and-deleting-versioned-s3-buckets).

### 6. Responsible AI GRC Checks Do Not Appear in the Report

**Symptoms:** The report does not include the **Responsible AI GRC** section or
any `FS-` findings.

> **Note on names.** The feature is enabled with the
> `EnableResponsibleAIGRCAssessment` deployment parameter, which CodeBuild
> passes to Step Functions as the `"enableResponsibleAIGRC"` execution input.
> Its results are in `responsible_ai_grc_security_report_*.csv`. The legacy
> `EnableFinServAssessment` parameter and `ENABLE_FINSERV` CodeBuild variable
> are still accepted and converted by `buildspec.yml` (see the
> [alias migration guide](RESPONSIBLE_AI_GRC_SCOPE.md#migrating-from-enablefinservassessment)), but the
> execution input never accepts a legacy `"enableFinServ"` key. See
> [6b](#6b-execution-fails-with-legacyenablefinservinputrejected)
> if you start Step Functions directly with the old key.

**Expected when OWASP-only:** If `EnableOWASPAssessment=true` and
`EnableResponsibleAIGRCAssessment=false`, the `FS-` assessment still runs as a
source for OWASP, but the Responsible AI GRC section, `FS-` rows, and
`responsible_ai_grc_security_report_*.csv` are intentionally left out of the
report bucket.

**Solutions:**

- Confirm that the infrastructure stack parameter
  `EnableResponsibleAIGRCAssessment` is `true`.
- Confirm that the CodeBuild logs show
  `Responsible AI GRC assessment enabled is true`.
- If you updated an existing deployment, run CodeBuild again after the
  CloudFormation update completes. The setting reaches the Step Functions
  execution input only when CodeBuild starts the assessment.
- If you deploy the SAM template directly and start Step Functions yourself,
  include `"enableResponsibleAIGRC": "true"` in the `StartExecution` input.
- In the Step Functions execution, check the `Responsible AI GRC Enabled?`
  choice state and the `Responsible AI GRC Security Assessment` task.

<a id="6b-execution-fails-immediately-with-legacyenablefinservinputrejected"></a>

### 6b. Execution Fails with `LegacyEnableFinServInputRejected`

**Symptoms:** The Step Functions execution fails with the error
`LegacyEnableFinServInputRejected`, and no report is generated for any service
or region: Amazon Bedrock, Amazon SageMaker AI, Amazon Bedrock AgentCore, AWS
Agent Registry, Responsible AI GRC, and OWASP.

**Cause:** The `StartExecution` input included `"enableFinServ": "true"`, the
execution-input name used before Responsible AI GRC was renamed. The state
machine rejects it with a `Fail` state inside the parallel per-region
assessments, which fails the whole `Scan Regions` Map state, so the report
step never runs.

Only the CloudFormation parameter `EnableFinServAssessment` and the CodeBuild
variable `ENABLE_FINSERV` are kept as legacy aliases; `buildspec.yml` converts
them to `"enableResponsibleAIGRC"` before calling `StartExecution`. This failure
happens only when something calls `StartExecution` directly and bypasses
CodeBuild, such as a hand-written script, an old runbook, or a direct AWS CLI or
SDK call.

The failure is deliberate. Without it, an execution using the old key would
succeed but silently report no Responsible AI GRC findings.

**Solutions:**

- Replace `"enableFinServ": "true"` with `"enableResponsibleAIGRC": "true"` in
  whatever calls `StartExecution`.
- If you start assessments through the provided CodeBuild templates
  (`deployment/aiml-security-single-account.yaml` or
  `deployment/2-aiml-security-codebuild.yaml`), you are not affected; CodeBuild
  never passes `enableFinServ`.

### 7. TargetRegions Validation or Unexpected Region Coverage

**Symptoms:** CodeBuild fails with a `TARGET_REGIONS` validation error, or the
report covers fewer or different regions than expected.

The deployment is validated only in the standard AWS commercial partition.
`TargetRegions` controls regional coverage within that partition; it does not
enable AWS GovCloud (US) or AWS China.

**Solutions:**

- Leave `TargetRegions` empty to scan only the deployment region.
- Use a comma- or space-separated list, such as
  `us-east-1,us-west-2,eu-west-1` or `us-east-1 us-west-2 eu-west-1`. The
  deployment normalizes the value before passing it to SAM.
- Confirm that the assessed services are available in each target region. If a
  service is unavailable or has no resources in a region, the report can show
  `N/A` or no resource-specific findings for that service and region.
- Confirm that the account is opted in to any opt-in regions you include.

### 8. CodeBuild Source or GitHub Branch Failures

**Symptoms:** CodeBuild fails before SAM build, or the logs show repository
clone or source errors.

**Solutions:**

- Confirm that CodeBuild can reach `GitHubRepoUrl`.
- Confirm that `GitHubBranch` is a valid branch, tag, or commit.
- If you use a fork or feature branch, make sure the infrastructure stack
  points at it before starting CodeBuild.
- For private repositories, configure CodeBuild source credentials before
  deployment, or use a source location CodeBuild can access.

### 9. CodeBuild Timeout or Out-of-Memory with Many Accounts

**Symptoms:** The CodeBuild job times out or runs slowly when scanning many
accounts.

**Cause:** CodeBuild assesses accounts one at a time, so total run time grows
with the number of accounts. The `ConcurrentAccountScans` parameter selects the
CodeBuild compute type. Despite its name, it does not currently change how many
accounts are scanned at once: the template passes a `PARALLEL_ACCOUNTS` value to
CodeBuild, but `buildspec.yml` does not use it.

| ConcurrentAccountScans | CodeBuild compute type | Approximate cost per build minute |
| --- | --- | --- |
| Three (default) | `BUILD_GENERAL1_SMALL` | $0.005 |
| Six | `BUILD_GENERAL1_MEDIUM` | $0.01 |
| Twelve | `BUILD_GENERAL1_LARGE` | $0.02 |

**Solutions:**

- If builds time out, increase the `CodeBuildTimeout` parameter (the
  multi-account default is 300 minutes).
- If builds run out of memory, increase `ConcurrentAccountScans` to select a
  larger compute type. This increases the per-minute CodeBuild cost but does
  not shorten the run.
- For very large organizations (100 or more accounts), use
  `MultiAccountListOverride` to split assessments into batches. It accepts
  comma- or space-separated account IDs.
- For other causes of long runs, see
  [Why is the assessment taking longer than expected?](FAQ.md#why-is-the-assessment-taking-longer-than-expected)

### 10. No Reports in S3 Bucket

**Symptoms:** The assessment completes, but no HTML or CSV files appear.

**Solutions:**

1. **Wrong bucket:** use the `AssessmentBucket` output of the infrastructure
   stack, not the assessment stack (see
   [§11](#11-confused-by-multiple-cloudformation-stacks)).
2. **Still running:** check the CodeBuild console. Multi-region, multi-account,
   or Responsible AI GRC-enabled assessments take longer than a single-region
   run.
3. **Wrong prefix:** look under `{account_id}/` for per-account reports and
   `consolidated-reports/` for the multi-account consolidated HTML report.
4. **Post-build copy failed:** CodeBuild copies CSV and HTML files from each
   account's SAM assessment bucket into the report bucket. In multi-account
   mode, search the CodeBuild logs for `Copying files from`,
   `Failed to copy assessment artifacts`, `Missing ... CSV`, or
   `No validated artifact directory found`. In single-account mode, search for
   `Failed to list bucket contents` or `Failed to sync results`.
5. **Permissions:** check CloudWatch Logs for Lambda errors and the CodeBuild
   logs for S3 access errors.

**Note:** If OWASP is enabled and Responsible AI GRC is disabled, the absence of
`responsible_ai_grc_security_report_*.csv` in the report bucket is expected.
The internal SAM assessment bucket may still contain Responsible AI GRC source
files from the run; use the infrastructure stack's bucket for results.

### 11. Confused by Multiple CloudFormation Stacks

**Symptoms:** You see several stacks and aren't sure which one has your
results.

**Explanation:** You create the infrastructure stack. CodeBuild then creates
one AWS SAM assessment stack per assessed account, plus the AWS SAM CLI's own
artifact stack. The infrastructure stack is the one to use for reports.

| Stack type | How to identify | What to do |
| --- | --- | --- |
| **Infrastructure stack** (yours) | The name you chose (for example, `aiml-security-single-account` or `aiml-security-multi-account`) | Use this one. Open **Outputs** and copy `AssessmentBucket` |
| **Assessment stack**, single-account | `aiml-sec-{account_id}` | Internal execution stack. Its `AssessmentBucketName` output holds the raw reports, useful for debugging |
| **Assessment stack**, multi-account member | `aiml-security-{account_id}`, in each member account | Same as above |
| **Assessment stack**, multi-account central account | `aiml-security-mgmt` | Same as above, for the central account that runs CodeBuild (always assessed in multi-account runs) |
| **AWS SAM CLI artifact stack** | `aws-sam-cli-managed-default`, in each assessed account | Created by `sam deploy --resolve-s3` to hold deployment packages. Other AWS SAM projects in the account may share it |

**Quick check:** a stack named `aiml-sec-` or `aiml-security-` followed by an
account ID, or `aiml-security-mgmt`, was created automatically. Look for the
name you chose during deployment.

### 12. Upgrading an Existing Deployment to Multi-Region

See [Changing an Existing Deployment to Multi-Region](UPGRADING.md#changing-an-existing-deployment-to-multi-region)
in the Upgrade Guide. Update `TargetRegions` on the existing stack; no teardown
is required.

### 13. No "Changes Since Last Assessment" Report

**Symptoms:** A run completed, but no `security_assessment_changes_*.html` or
`.csv` appears in the account's folder.

**Solution:** Search the CodeBuild log for `Changes report`; the line explains
why. The first run for an account never has a report. For every message and
what to do, see
[Build log messages](ASSESSMENT_HISTORY.md#build-log-messages).

---

## Debugging

### Check CodeBuild Logs

1. Open **AWS CodeBuild** > **Build projects**.
2. Select your project (`AIMLSecurityCodeBuild` or
   `AIMLSecurityMultiAccountCodeBuild`).
3. Open the latest build.
4. Review the **Build logs** tab for errors.

### Verify Cross-Account Role Trust Policies

```bash
# In the member account, check the role trust policy
aws iam get-role --role-name AIMLSecurityMemberRole --query 'Role.AssumeRolePolicyDocument'
```

The trust policy should allow the central CodeBuild role:

```json
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::<central-assessment-account-id>:root"
  },
  "Action": "sts:AssumeRole",
  "Condition": {
    "ArnEquals": {
      "aws:PrincipalArn": "arn:aws:iam::<central-assessment-account-id>:role/service-role/MultiAccountCodeBuildRole"
    }
  }
}
```

### Check S3 Bucket Permissions

The infrastructure stack's bucket is the report bucket. In multi-account mode,
member accounts do not write to it directly. CodeBuild assumes the member role
in each account, copies report files from that account's SAM assessment bucket,
and uploads them to the central bucket.

If the upload fails, check the central bucket policy and the CodeBuild role's
S3 permissions:

```bash
aws s3api get-bucket-policy --bucket <infrastructure-assessment-bucket-name>
```

If per-account reports are missing, also open the account's SAM assessment
stack, find its `AssessmentBucketName` output, and confirm that the files were
created there.

### Investigate Incomplete Control Findings

An informational `N/A` row whose finding name ends in `Incomplete` means the
scanner could not establish whether that control passed or failed. These rows
use the affected control's ID so the missing evidence is visible without
adding to the failure count. They come from:

- A missing or unreadable IAM permissions cache, for example `BR-01` or
  `SM-02` (Bedrock API access-denied responses keep the control's normal
  finding name and say `Unable to check` or `Could not assess`, for example
  `BR-17`)
- Unexpected Amazon Bedrock AgentCore check errors, for example `AC-04` or
  `AG-24`
- Unexpected AWS Agent Registry check errors, for example `AR-03`

Find the matching Lambda invocation in the Step Functions execution and review
its CloudWatch logs. Fix the missing SAM Lambda permission, unavailable API,
throttling, malformed input, or code error shown there, and run the assessment
again. An incomplete row is not evidence that the workload is compliant.

### Investigate Incomplete IAM Permission Cache Findings

The identity-based controls for Amazon Bedrock, Amazon SageMaker AI, Amazon
Bedrock AgentCore, AWS Agent Registry, and Responsible AI GRC read
`permissions_cache_<execution-id>.json` from the account's SAM assessment
bucket. If that object is missing, unreadable, malformed, or lacks the expected
role and user lists, the affected controls appear as informational `N/A` rows
instead of passes.

Review the **IAM Permission Caching** task in the Step Functions execution and
check the caching Lambda logs for a successful write of that execution's
object. The report Lambda deletes the cache when report generation finishes,
so its absence after a completed run is expected. Fix the IAM or S3 error and
run the complete assessment again; do not reuse a cache from another execution.

### Monitor AWS Step Functions Executions

1. Open **AWS Step Functions** in the assessed account and deployment region.
2. Find the state machine whose name starts with `AIMLAssessmentStateMachine-`.
   CloudFormation adds a random suffix. You can also find its ARN in the
   `AIMLAssessmentStateMachineArn` output, or the `AIMLAssessmentStateMachine`
   resource, of the SAM assessment stack.
3. Review the execution history for failures.
4. Check the results of individual Lambda invocations.

## Moved Sections

These sections moved to their own documents. The anchors below keep older links
working.

<a id="upgrading-to-a-new-release"></a>
<a id="determine-the-required-upgrade-actions"></a>
<a id="before-upgrading"></a>
<a id="single-account-upgrade-procedure"></a>
<a id="multi-account-upgrade-procedure"></a>
<a id="direct-aws-sam-deployment"></a>
<a id="why-the-build-must-be-started-manually"></a>
<a id="post-upgrade-verification"></a>

- **Upgrading to a New Release** is now the [Upgrade Guide](UPGRADING.md).

<a id="frequently-asked-questions"></a>
<a id="general-questions"></a>
<a id="cost-and-billing"></a>
<a id="customization-and-configuration"></a>
<a id="security-and-compliance"></a>

- **Frequently Asked Questions** are now in the [FAQ](FAQ.md).
