# Cleanup Guide

This guide provides step-by-step instructions for removing all resources deployed by the AI/ML Security Assessment framework.

## Cleanup Order

For a clean removal, delete resources in this order:

1. **Assessment stacks** (auto-created by SAM)
2. **Infrastructure stack** (the stack you deployed manually)
3. AWS CloudFormation StackSet member roles (multi-account only)
4. Any remaining Amazon S3 buckets manually

---

## Single-Account Cleanup

To remove all resources deployed for single-account assessment:

1. **Delete the AWS SAM-deployed assessment stack**:
   - Navigate to **AWS CloudFormation** > **Stacks**
   - Select the `aiml-sec-{account_id}` stack (for example, `aiml-sec-123456789012`)
   - Click **Delete**
   - Wait for stack deletion to complete

2. **Delete the AWS CodeBuild infrastructure stack**:
   - Select the `aiml-security-single-account` stack (or your custom stack name)
   - Click **Delete**
   - Wait for stack deletion to complete

3. **Clean up Amazon S3 buckets** (if stack deletion fails due to non-empty buckets):
   ```bash
   # Empty the assessment bucket
   aws s3 rm s3://<assessment-bucket-name> --recursive

   # If versioning is enabled, delete version markers
   aws s3api delete-objects --bucket <bucket-name> --delete \
     "$(aws s3api list-object-versions --bucket <bucket-name> \
     --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}')"

   # Delete the bucket
   aws s3 rb s3://<bucket-name>
   ```

---

## Multi-Account Cleanup

To remove all resources deployed for multi-account assessment:

1. **Delete AWS SAM-deployed stacks in each member account**:
   - For each account that was scanned, navigate to **AWS CloudFormation** > **Stacks**
   - Select the `aiml-security-{account_id}` stack (for example, `aiml-security-123456789012`)
   - For the management account, select `aiml-security-mgmt`
   - Click **Delete**
   - Alternatively, use the AWS CLI to delete across accounts:
     ```bash
     # Assume role in member account and delete stack
     aws cloudformation delete-stack --stack-name aiml-security-<account_id> \
       --region <region>
     ```

2. **Delete the central AWS CodeBuild infrastructure stack**:
   - In the management account, navigate to **AWS CloudFormation** > **Stacks**
   - Select the `aiml-security-multi-account` stack
   - Click **Delete**
   - Wait for stack deletion to complete

3. **Delete the AWS CloudFormation StackSet member roles**:
   - Navigate to **AWS CloudFormation** > **StackSets**
   - Select the `aiml-security-member-roles` AWS CloudFormation StackSet
   - Click **Actions** > **Delete stacks from StackSet**
   - Select all deployment targets (OUs or accounts)
   - Wait for stack instances to be deleted
   - Once all stack instances are removed, delete the AWS CloudFormation StackSet itself

4. **Clean up Amazon S3 buckets** (if stack deletion fails due to non-empty buckets):
   ```bash
   # List and identify assessment buckets
   aws s3 ls | grep aiml-security

   # Empty each bucket
   aws s3 rm s3://<bucket-name> --recursive

   # Delete version markers if versioning was enabled
   aws s3api delete-objects --bucket <bucket-name> --delete \
     "$(aws s3api list-object-versions --bucket <bucket-name> \
     --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}')"

   # Delete the bucket
   aws s3 rb s3://<bucket-name>
   ```

---

## Identifying Stack Types

The deployment creates multiple AWS CloudFormation stacks. Here's how to identify them:

| Stack Type | How to Identify | Action |
|------------|-----------------|--------|
| **Infrastructure Stack** (yours) | The name you chose (for example, `aiml-security-single-account`) | Delete second |
| **Assessment Stack** (auto-generated) | `aiml-sec-{account_id}` (single) or `aiml-security-{account_id}` (multi) | Delete first |

**Quick Check**: If you see a stack name starting with `aiml-sec-` or `aiml-security-` followed by numbers (or `aiml-security-mgmt`), that's an auto-generated assessment stack.
