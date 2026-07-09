# Troubleshooting Guide

This guide covers common issues, debugging tips, and frequently asked questions for the AI/ML Security Assessment framework.

## Table of Contents

- [Common Issues](#common-issues)
- [Debugging](#debugging)
- [Frequently Asked Questions](#frequently-asked-questions)
  - [General Questions](#general-questions)
  - [Cost and Billing](#cost-and-billing)
  - [Customization and Configuration](#customization-and-configuration)
  - [Troubleshooting Questions](#troubleshooting-questions)
  - [Security and Compliance](#security-and-compliance)

---

## Common Issues

### 1. AWS CloudFormation StackSet Deployment Failures

**Symptoms:** StackSet instances fail to create in member accounts.

**Solutions:**
- Check that service-linked roles exist for AWS CloudFormation StackSets
- Verify the account running the central CodeBuild project has AWS Organizations permissions, if it is discovering accounts automatically
- Verify target OUs contain active accounts
- Review the StackSet operation history for specific error messages

### 2. Cross-Account Role Assumption Failures

**Symptoms:** "Access Denied" errors when assuming roles in member accounts.

**Solutions:**
- Verify the `AIMLSecurityMemberRole` exists in target accounts
- Check the trust relationship allows the central CodeBuild role
- Confirm the `ManagementAccountID` parameter matches the account where the central `MultiAccountCodeBuildRole` runs
- Verify the StackSet deployment completed successfully in all accounts

### 3. AWS SAM Deployment Failures

**Symptoms:** CodeBuild fails during the SAM deploy phase.

**Solutions:**
- Check CodeBuild logs in CloudWatch for specific errors
- Verify the GitHub repository URL and `GitHubBranch` parameter point to a branch, tag, or commit that CodeBuild can clone
- Verify the S3 bucket for SAM artifacts exists and is accessible. If the `aws-sam-cli-managed-default` stack is stuck in `ROLLBACK_COMPLETE` or `DELETE_FAILED`, delete it and re-run CodeBuild
- Look for IAM permission errors in the logs
- Check if a previous deployment left orphaned resources
- Check whether `TARGET_REGIONS` failed validation. It must be empty, `all`, or a comma- or space-separated list such as `us-east-1,us-west-2` or `us-east-1 us-west-2`

### 4. AWS Step Functions Execution Failures

**Symptoms:** AWS Step Functions show failed state or timeout.

**Solutions:**
- Monitor state machine executions in each account
- Check Lambda function logs for errors
- Verify Lambda has sufficient timeout. Most assessment Lambdas default to 10 minutes; FinServ has its own timeout in the SAM templates
- Verify AWS IAM permissions allow Lambda to access required services
- In multi-region scans, review each region's Map state iteration. A single service branch can be marked incomplete while the state machine still generates a report for the remaining services and regions

### 5. EarlyValidation::ResourceExistenceCheck Error

**Symptoms:** CloudFormation blocks stack creation with this error.

**Cause:** A resource with the same physical name already exists outside of CloudFormation management, typically from a failed deployment.

**Solution:**
The versioned bucket cleanup command requires `jq`.

```bash
# Find likely orphaned buckets
aws s3 ls | grep aiml-security

BUCKET_NAME="<bucket-name>"

aws s3 rm "s3://${BUCKET_NAME}" --recursive

while true; do
  delete_payload=$(aws s3api list-object-versions \
    --bucket "${BUCKET_NAME}" \
    --output json \
    | jq '{Objects: (((.Versions // []) + (.DeleteMarkers // [])) | map({Key, VersionId}) | .[0:1000])}')

  object_count=$(echo "${delete_payload}" | jq '.Objects | length')
  if [ "${object_count}" -eq 0 ]; then
    break
  fi

  aws s3api delete-objects \
    --bucket "${BUCKET_NAME}" \
    --delete "${delete_payload}"
done

aws s3 rb "s3://${BUCKET_NAME}"

# Re-run the CodeBuild project
```

For full bucket cleanup guidance, see [Cleanup Guide](CLEANUP.md#emptying-and-deleting-versioned-s3-buckets).

### 6. Financial Services Checks Do Not Appear in the Report

**Symptoms:** The report does not include the **Financial Services** section or any `FS-` findings.

**Solutions:**
- Confirm the infrastructure stack parameter `EnableFinServAssessment` is set to `true`
- Confirm CodeBuild logs show `FinServ assessment enabled is true`
- If you updated an existing deployment, re-run the CodeBuild project after the CloudFormation update completes. The parameter is passed to the Step Functions execution input when CodeBuild starts the assessment
- Use the CodeBuild-based deployment templates for normal operation. If you deploy the SAM template directly and start Step Functions manually, include `"enableFinServ": "true"` in the `StartExecution` input
- Check the Step Functions execution for the `FinServ Enabled?` choice state and `FinServ Security Assessment` task

### 7. TargetRegions Validation or Unexpected Region Coverage

**Symptoms:** CodeBuild fails with a `TARGET_REGIONS` validation error, or the report scans fewer or different regions than expected.

**Solutions:**
- Leave `TargetRegions` empty to scan only the deployment region
- Use `all` to scan the union of regions returned by boto3 for Amazon Bedrock, Amazon SageMaker AI, and Amazon Bedrock AgentCore
- Use a comma- or space-separated list, such as `us-east-1,us-west-2,eu-west-1` or `us-east-1 us-west-2 eu-west-1`. The deployment normalizes the value before passing it to SAM
- Confirm the services being assessed are available in each target region. If a service is unavailable or has no resources in a region, the report can show `N/A` or no resource-specific findings for that service and region
- Confirm the account is opted in to any opt-in regions you include

### 8. CodeBuild Source or GitHub Branch Failures

**Symptoms:** CodeBuild fails before SAM build, or the logs show repository clone/source errors.

**Solutions:**
- Confirm `GitHubRepoUrl` is reachable by CodeBuild
- Confirm `GitHubBranch` is a valid branch, tag, or commit
- If you use a fork or feature branch, make sure the infrastructure stack points at that branch before starting CodeBuild
- For private repositories, configure CodeBuild source credentials before deployment or use a source location CodeBuild can access

### 9. CodeBuild Timeout or Out-of-Memory with Many Accounts

**Symptoms:** CodeBuild job times out or runs slowly when scanning a large number of accounts concurrently.

**Cause:** The `ConcurrentAccountScans` parameter controls both the number of parallel account scans and the CodeBuild compute type. Higher concurrency requires a larger (and more expensive) instance:

| ConcurrentAccountScans | Parallel Accounts | CodeBuild Compute Type | Approximate Cost per Build Minute |
|------------------------|-------------------|------------------------|-----------------------------------|
| Three (default) | 3 | `BUILD_GENERAL1_SMALL` | $0.005 |
| Six | 6 | `BUILD_GENERAL1_MEDIUM` | $0.01 |
| Twelve | 12 | `BUILD_GENERAL1_LARGE` | $0.02 |

**Solutions:**
- For organizations with fewer than 10 accounts, the default "Three" is usually sufficient
- If builds timeout, increase `ConcurrentAccountScans` to process more accounts in parallel -- but be aware this also increases the per-minute CodeBuild cost
- If builds timeout even at "Twelve," increase the `CodeBuildTimeout` parameter (default is 300 minutes for multi-account)
- For very large organizations (100+ accounts), consider using `MultiAccountListOverride` to split assessments into batches. It accepts comma- or space-separated account IDs

### 10. No Reports in S3 Bucket

**Symptoms:** Assessment completes but no HTML/CSV files appear.

**Solutions:**
1. **Wrong bucket**: Use the bucket from the **Infrastructure Stack** outputs, not the assessment stack
2. **Still running**: Check CodeBuild console. Multi-region, multi-account, or FinServ-enabled assessments can take longer than a single-region run
3. **Wrong prefix**: Look under `{account_id}/` for per-account reports and `consolidated-reports/` for the multi-account consolidated HTML report
4. **Post-build copy failed**: In multi-account mode, CodeBuild copies CSV/HTML files from each account's SAM assessment bucket into the central infrastructure bucket. Search CodeBuild logs for `Copying files from`, `Failed to list bucket contents`, or `No files to copy`
5. **Permissions**: Check CloudWatch Logs for Lambda execution errors and CodeBuild logs for S3 sync errors

### 11. Confused by Multiple CloudFormation Stacks

**Symptoms:** You see multiple stacks and aren't sure which one has your results.

**Explanation:** The deployment creates an infrastructure stack and one or more SAM assessment stacks. The infrastructure stack is the user-facing stack for report access.

| Stack Type | How to Identify | What to Do |
|------------|-----------------|------------|
| **Infrastructure Stack** (yours) | The name you chose (for example, `aiml-security-single-account`) | Use this — go to Outputs tab, copy `AssessmentBucket` |
| **Assessment Stack** (auto-generated) | `aiml-sec-{account_id}` (single), `aiml-security-{account_id}` (multi), or `aiml-security-mgmt` | Internal execution stack. Its `AssessmentBucketName` output is useful for debugging raw per-account reports and retained buckets |

**Quick Check**: If a stack name starts with `aiml-sec-` or `aiml-security-` followed by numbers (or `aiml-security-mgmt`), it's auto-generated. Look for the name you chose during deployment.

### 12. Upgrading an Existing Deployment to Multi-Region

**Symptoms:** You have an existing single-region deployment and want to enable multi-region scanning.

**Solution:** Update your existing CloudFormation stack — no teardown required.

1. Navigate to **AWS CloudFormation** > **Stacks**
2. Select your infrastructure stack (for example, `aiml-security-single-account` or `aiml-security-multi-account`)
3. Click **Update** > **Use current template**
4. Set the `TargetRegions` parameter (for example, `us-east-1,us-west-2,eu-west-1`, `us-east-1 us-west-2 eu-west-1`, or `all`)
5. Click through to **Submit**
6. The next assessment run will scan the specified regions in parallel

**What happens during the upgrade:**
- CloudFormation updates the `TARGET_REGIONS` environment variable on the CodeBuild project in the infrastructure stack
- On the next CodeBuild run, SAM deploy updates the assessment stack and passes the new `TargetRegions` value into the assessment Lambdas and state machine
- The Step Functions `Resolve Target Regions` state resolves the region list, then the Map state scans those regions in parallel
- No data is lost — the S3 bucket retains all previous reports
- Fully backward compatible — leaving `TargetRegions` empty preserves single-region behavior

---

## Debugging

### Check CodeBuild Logs

1. Navigate to **AWS CodeBuild** > **Build projects**
2. Select your project (for example, `AIMLSecurityCodeBuild` or `AIMLSecurityMultiAccountCodeBuild`)
3. Click on the latest build
4. Review the **Build logs** tab for errors

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

The central infrastructure bucket is the user-facing report bucket. In multi-account mode, member accounts do not write directly to this bucket. CodeBuild assumes into each account, copies report files from that account's SAM assessment bucket, then uploads them to the central infrastructure bucket.

Verify the central bucket policy and CodeBuild S3 permissions if report upload fails:

```bash
aws s3api get-bucket-policy --bucket <infrastructure-assessment-bucket-name>
```

If per-account reports are missing, also check the SAM assessment stack's `AssessmentBucketName` output for that account and confirm the files were created there.

### Monitor AWS Step Functions Executions

1. Navigate to **AWS Step Functions** in the target account
2. Find the `AIMLAssessmentStateMachine`
3. Review execution history for failures
4. Check individual Lambda invocation results

---

## Frequently Asked Questions

### General Questions

**Q: Does this assessment make any changes to my AWS resources?**

A: The security checks do not modify your AI/ML workloads or data. They query resource configuration and write assessment artifacts to framework-owned S3 buckets.

The framework itself does create and manage its own deployment resources, including CloudFormation stacks, IAM roles, Lambda functions, Step Functions state machines, CodeBuild projects, S3 buckets, EventBridge rules, and optional SNS notifications. At the start of each assessment run, it also cleans old objects from its own SAM assessment bucket before writing the new report artifacts.

**Q: How long does an assessment take to run?**

A:
- **Single account**: 5-10 minutes (depending on the number of resources)
- **Multi-account** (10 accounts): 15-20 minutes
- **Multi-account** (50+ accounts): 30-45 minutes

The assessment runs in parallel across accounts to minimize total execution time.

**Q: How often should I run security assessments?**

A:
- **Production AI/ML workloads**: Weekly or bi-weekly
- **Development/Test environments**: Monthly
- **After significant changes**: Always (new models, configuration changes, IAM updates)
- **Compliance requirements**: As mandated by your organization's security policies

You can automate regular assessments using Amazon EventBridge scheduled rules.

**Q: What AWS regions are supported?**

A: The framework is designed for standard AWS commercial regions where Amazon Bedrock, Amazon SageMaker AI, or Amazon Bedrock AgentCore are available. Leave `TargetRegions` empty for the deployment region, set it to `all` to resolve the union of assessed-service regions, or provide an explicit comma- or space-separated list. AWS GovCloud and AWS China regions may require template modifications.

**Q: Does this work if I don't have any AI/ML resources deployed yet?**

A: Yes. The assessment runs successfully and reports findings with status "N/A" (Not Applicable) for checks where no resources exist to assess. This is useful for establishing a security baseline before deploying AI/ML workloads.

---

### Cost and Billing

**Q: How much does it cost to run this assessment?**

A: **Estimated cost per assessment**: $0.50 - $2.00 for typical single-account usage

Cost breakdown:
- **AWS Lambda**: $0.10 - $0.50 (pay per execution, typically 5-10 function invocations)
- **AWS Step Functions**: $0.05 - $0.25 (state transitions)
- **Amazon S3**: $0.01 - $0.10 (report storage, negligible for most use cases)
- **AWS CodeBuild**: $0.10 - $0.50 (execution time, billed per minute)

**Multi-account deployments**: AWS Lambda and AWS Step Functions costs scale with the number of accounts. AWS Organizations API calls are free. AWS CodeBuild cost depends on the `ConcurrentAccountScans` setting, which determines the instance size:

| ConcurrentAccountScans | CodeBuild Compute Type | Approximate Cost per Build Minute |
|------------------------|------------------------|-----------------------------------|
| Three (default) | `BUILD_GENERAL1_SMALL` | $0.005 |
| Six | `BUILD_GENERAL1_MEDIUM` | $0.01 |
| Twelve | `BUILD_GENERAL1_LARGE` | $0.02 |

For example, a 30-minute multi-account assessment at "Twelve" concurrency costs roughly $0.60 in CodeBuild alone, compared to $0.15 at the default "Three." Choose the concurrency level that balances speed against cost for your organization size.

**Q: Are there any ongoing costs when not running assessments?**

A: Minimal ongoing costs:
- **Amazon S3 storage**: $0.023 per GB/month for storing historical reports
- **AWS CloudWatch Logs**: $0.50 per GB for log retention (can be configured or disabled)
- All other resources (AWS Lambda, AWS Step Functions, AWS CodeBuild) are pay-per-use with **no idle costs**

---

### Customization and Configuration

**Q: Can I customize which security checks are included?**

A: Currently, all 70 core checks and 27 Agentic AI Security checks run by default to provide comprehensive coverage. If `EnableFinServAssessment` is enabled, the 64 optional Financial Services GenAI risk checks also run. You can filter results in the generated HTML reports by severity, status, assessment area, industry, or region. Future versions may support selective check execution.

**Q: Can I add custom security checks?**

A: Yes! See the [Developer Guide](DEVELOPER_GUIDE.md#adding-new-aiml-service-assessments) for instructions on extending the framework with additional checks. The architecture is designed to be modular and extensible.

**Q: Can I export results to other formats (JSON, CSV, SIEM)?**

A: Yes. The framework generates:
- **CSV files** for each service (available in the Amazon S3 bucket per account)
- **HTML reports** for interactive viewing
- **JSON** (available through the permissions cache and raw Lambda outputs)

You can integrate with SIEM tools by processing the CSV or JSON outputs from the Amazon S3 bucket.

**Q: Can I schedule automated assessments?**

A: Yes. Use Amazon EventBridge to trigger the AWS CodeBuild project on a schedule:

```bash
aws events put-rule \
  --name "WeeklyAIMLAssessment" \
  --schedule-expression "cron(0 2 ? * MON *)"

aws events put-targets \
  --rule "WeeklyAIMLAssessment" \
  --targets '[{
    "Id": "1",
    "Arn": "arn:aws:codebuild:<region>:<account-id>:project/<project-name>",
    "RoleArn": "arn:aws:iam::<account-id>:role/<eventbridge-codebuild-start-role>"
  }]'
```

The target role must trust `events.amazonaws.com` and allow `codebuild:StartBuild` on the assessment CodeBuild project. For new schedules, Amazon EventBridge Scheduler is also a good option.

---

### Troubleshooting Questions

**Q: The assessment completed but I don't see any reports in my Amazon S3 bucket.**

A: Common causes:
1. **Wrong bucket**: Verify you're looking at the bucket from the **Infrastructure Stack** outputs (not the assessment stack)
2. **Still running**: Check AWS CodeBuild console. Multi-region, multi-account, or FinServ-enabled assessments can take longer than a single-region run
3. **Wrong prefix**: Look under `{account_id}/` for per-account reports and `consolidated-reports/` for the multi-account consolidated HTML report
4. **Post-build copy failed**: Search CodeBuild logs for `Copying files from`, `Failed to list bucket contents`, `No files to copy`, or S3 sync errors
5. **Permissions issue**: Check AWS CloudWatch Logs for Lambda errors and CodeBuild logs for S3 access errors

**Q: I see "Access Denied" errors in the AWS CodeBuild logs.**

A: This usually indicates:
1. **Multi-account**: The member role (`AIMLSecurityMemberRole`) is not deployed in target accounts through AWS CloudFormation StackSets
2. **Trust relationship**: The role trust policy doesn't allow the central AWS CodeBuild role to assume it
3. **Permissions**: The role lacks necessary read permissions for AI/ML services

Solution: Verify AWS CloudFormation StackSet deployment in Step 1 completed successfully across all target accounts.

**Q: The assessment is taking longer than expected.**

A: Performance factors:
- **Number of resources**: Accounts with hundreds of Amazon SageMaker notebooks or Amazon Bedrock models take longer
- **API throttling**: AWS API rate limits may slow down assessments in large environments
- **Concurrent executions**: Multi-account assessments run in parallel (configurable through the `ConcurrentAccountScans` parameter)
- **Region scope**: Multi-region scans multiply the amount of service inventory collected
- **Financial Services checks**: Enabling `EnableFinServAssessment` adds the optional `FS-` checks and can increase run time

If assessments consistently timeout, increase `CodeBuildTimeout`, reduce `TargetRegions`, reduce the account batch size with `MultiAccountListOverride`, or lower concurrency if throttling is the bottleneck. Lambda timeout changes require editing the SAM templates.

---

### Security and Compliance

**Q: Where is my assessment data stored?**

A: All assessment data remains **entirely within your AWS account**:
- Reports stored in **your Amazon S3 bucket** (you control retention and access)
- Logs in **your Amazon CloudWatch Logs** (configurable retention)
- No data is sent to external services or third parties

**Q: What IAM permissions does the framework need?**

A: The framework uses multiple roles, and only the Lambda runtime roles are close to read-only:
- **CodeBuild orchestration roles** (`CodeBuildRole`, `MultiAccountCodeBuildRole`) need deployment permissions to build SAM, create or update stacks, and start Step Functions executions.
- **`AIMLSecurityMemberRole`** in the target account is also not read-only in the multi-account flow, because it must allow the central CodeBuild project to deploy or update the per-account SAM stack before the assessment runs.
- **Assessment Lambda execution roles** are primarily read-oriented. They use AI/ML service `List*`, `Describe*`, and `Get*` APIs plus supporting read APIs, and S3 access to read the IAM cache and write reports.

See [README - Permissions Required](../README.md#permissions-required) for the role breakdown and the template files that define each policy.

**Q: Is this assessment sufficient for compliance requirements (SOC 2, HIPAA, and similar)?**

A: This assessment provides **a security evaluation against AWS best practices** and can support compliance efforts. However:
- Useful for demonstrating security controls and continuous monitoring
- Helps identify misconfigurations that could lead to compliance violations
- Not a substitute for formal compliance audits
- Does not cover all compliance framework requirements

Consult with your compliance team to determine how this assessment fits into your overall compliance program.

**Q: Does this framework comply with AWS Well-Architected Framework principles?**

A: Yes. The assessment checks align with the [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/) Security Pillar, specifically:
- SEC02: Identity and Access Management
- SEC03: Detection
- SEC04: Infrastructure Protection
- SEC08: Data Protection
