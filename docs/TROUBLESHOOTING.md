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
- Verify the management account has AWS Organizations permissions
- Verify target OUs contain active accounts
- Review the StackSet operation history for specific error messages

### 2. Cross-Account Role Assumption Failures

**Symptoms:** "Access Denied" errors when assuming roles in member accounts.

**Solutions:**
- Verify the `AIMLSecurityMemberRole` exists in target accounts
- Check the trust relationship allows the central CodeBuild role
- Confirm the `ManagementAccountID` parameter matches your management account
- Verify the StackSet deployment completed successfully in all accounts

### 3. AWS SAM Deployment Failures

**Symptoms:** CodeBuild fails during the SAM deploy phase.

**Solutions:**
- Check CodeBuild logs in CloudWatch for specific errors
- Verify the S3 bucket for SAM artifacts exists and is accessible
- Look for IAM permission errors in the logs
- Check if a previous deployment left orphaned resources

### 4. AWS Step Functions Execution Failures

**Symptoms:** AWS Step Functions show failed state or timeout.

**Solutions:**
- Monitor state machine executions in each account
- Check Lambda function logs for errors
- Verify Lambda has sufficient timeout (default 10 minutes)
- Verify AWS IAM permissions allow Lambda to access required services

### 5. EarlyValidation::ResourceExistenceCheck Error

**Symptoms:** CloudFormation blocks stack creation with this error.

**Cause:** A resource with the same physical name already exists outside of CloudFormation management, typically from a failed deployment.

**Solution:**
```bash
# Find the orphaned bucket
aws s3 ls | grep aiml-security

# Empty the bucket
aws s3 rm s3://<bucket-name> --recursive

# Delete version markers if versioned
aws s3api delete-objects --bucket <bucket-name> --delete \
  "$(aws s3api list-object-versions --bucket <bucket-name> \
  --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}')"

# Delete the bucket
aws s3 rb s3://<bucket-name>

# Re-run the CodeBuild project
```

### 6. CodeBuild Timeout or Out-of-Memory with Many Accounts

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
- For very large organizations (100+ accounts), consider using `MultiAccountListOverride` to split assessments into batches

### 7. No Reports in S3 Bucket

**Symptoms:** Assessment completes but no HTML/CSV files appear.

**Solutions:**
1. **Wrong bucket**: Use the bucket from the **Infrastructure Stack** outputs, not the assessment stack
2. **Still running**: Check CodeBuild console - assessment typically takes 5-10 minutes
3. **Wrong prefix**: Look under `{account_id}/` for single-account, `consolidated-reports/` for multi-account
4. **Permissions**: Check CloudWatch Logs for Lambda execution errors

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
    "AWS": "arn:aws:iam::<management-account-id>:root"
  },
  "Action": "sts:AssumeRole",
  "Condition": {
    "ArnEquals": {
      "aws:PrincipalArn": "arn:aws:iam::<management-account-id>:role/service-role/MultiAccountCodeBuildRole"
    }
  }
}
```

### Check S3 Bucket Permissions

Verify the bucket policy allows cross-account writes for multi-account deployments:

```bash
aws s3api get-bucket-policy --bucket <assessment-bucket-name>
```

### Monitor AWS Step Functions Executions

1. Navigate to **AWS Step Functions** in the target account
2. Find the `AIMLAssessmentStateMachine`
3. Review execution history for failures
4. Check individual Lambda invocation results

---

## Frequently Asked Questions

### General Questions

**Q: Does this assessment make any changes to my AWS resources?**

A: No. All security checks are **read-only**. The framework only queries your resources to evaluate their configurations. It does not create, modify, or delete any of your AI/ML workloads or data.

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

A: The framework supports all standard AWS commercial regions where Amazon Bedrock, Amazon SageMaker AI, or Amazon Bedrock AgentCore are available. AWS GovCloud and AWS China regions may require template modifications.

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

A: Currently, all 52 checks run by default to provide comprehensive coverage. You can filter results in the generated HTML reports by severity, status, or service. Future versions may support selective check execution.

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
  --targets "Id"="1","Arn"="arn:aws:codebuild:region:account:project/your-project"
```

---

### Troubleshooting Questions

**Q: The assessment completed but I don't see any reports in my Amazon S3 bucket.**

A: Common causes:
1. **Wrong bucket**: Verify you're looking at the bucket from the **Infrastructure Stack** outputs (not the assessment stack)
2. **Still running**: Check AWS CodeBuild console - the assessment may still be in progress (typically takes 5-10 minutes)
3. **Permissions issue**: Check AWS CloudWatch Logs for AWS Lambda execution errors
4. **Wrong prefix**: Look under `{account_id}/` prefix for single-account, `consolidated-reports/` for multi-account

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

If assessments consistently timeout, increase the AWS Lambda timeout in the AWS SAM template or reduce concurrent account scans.

---

### Security and Compliance

**Q: Where is my assessment data stored?**

A: All assessment data remains **entirely within your AWS account**:
- Reports stored in **your Amazon S3 bucket** (you control retention and access)
- Logs in **your Amazon CloudWatch Logs** (configurable retention)
- No data is sent to external services or third parties

**Q: What IAM permissions does the assessment role need?**

A: The framework uses **read-only permissions** only:
- AI/ML services: `List*`, `Describe*`, `Get*` actions
- AWS IAM: Read permissions for policy analysis
- Supporting services: AWS CloudTrail, Amazon GuardDuty, Amazon VPC (read-only)

See the main [README](../README.md#permissions-required) for the complete permission list.

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
