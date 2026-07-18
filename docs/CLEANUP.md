# Cleanup Guide

This guide provides step-by-step instructions for removing resources deployed by the AI/ML Security Assessment framework.

Before deleting any stacks, record the S3 bucket names from the stack outputs. After a stack is deleted, its outputs are no longer available.

The deployment creates two kinds of buckets:

- **Infrastructure stack bucket**: The `AssessmentBucket` output from the stack you deployed manually, such as `aiml-security-single-account` or `aiml-security-multi-account`.
- **Assessment stack buckets**: The `AssessmentBucketName` output from the auto-created SAM stacks, such as `aiml-sec-{account_id}`, `aiml-security-{account_id}`, or `aiml-security-mgmt`. These buckets use `DeletionPolicy: Retain`, so they remain after the SAM assessment stack is deleted and must be deleted manually if you want a full cleanup.

## Cleanup Order

For a clean removal, delete resources in this order:

1. Record S3 bucket names from stack outputs
2. **Assessment stacks** (auto-created by SAM)
3. Manually empty and delete retained assessment buckets
4. **Infrastructure stack** (the stack you deployed manually)
5. Manually empty and delete the infrastructure stack bucket if stack deletion fails
6. AWS CloudFormation StackSet member roles (multi-account only)
7. Optional: CloudWatch log groups created during assessment runs

---

## Emptying and Deleting Versioned S3 Buckets

The buckets created by this framework are versioned. A recursive `aws s3 rm` removes current objects, but versioned buckets can still contain noncurrent versions and delete markers. Use the following helper to remove current objects, noncurrent versions, delete markers, and then the bucket.

This command requires `jq`.

```bash
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
```

Repeat this for each infrastructure and assessment bucket you want to remove.

---

## Single-Account Cleanup

To remove all resources deployed for single-account assessment:

1. **Delete the AWS SAM-deployed assessment stack**:
   - Navigate to **AWS CloudFormation** > **Stacks**
   - Select the `aiml-sec-{account_id}` stack (for example, `aiml-sec-123456789012`)
   - Before deleting it, open **Outputs** and record the `AssessmentBucketName` value
   - Click **Delete**
   - Wait for stack deletion to complete
   - The assessment bucket is retained by design, so delete it manually using the S3 cleanup helper above if you no longer need the report artifacts

2. **Delete the AWS CodeBuild infrastructure stack**:
   - Select the `aiml-security-single-account` stack (or your custom stack name)
   - Before deleting it, open **Outputs** and record the `AssessmentBucket` value
   - Click **Delete**
   - Wait for stack deletion to complete

3. **Clean up Amazon S3 buckets**:
   - Delete the retained `AssessmentBucketName` bucket from the SAM assessment stack.
   - If the infrastructure stack deletion fails because its `AssessmentBucket` is not empty, empty and delete that bucket, then retry stack deletion.

---

## Multi-Account Cleanup

To remove all resources deployed for multi-account assessment:

1. **Delete AWS SAM-deployed stacks in each member account**:
   - In the deployment region, for each account that was scanned, navigate to **AWS CloudFormation** > **Stacks**
   - Select the `aiml-security-{account_id}` stack (for example, `aiml-security-123456789012`)
   - For the management account, select `aiml-security-mgmt`
   - Before deleting each stack, open **Outputs** and record the `AssessmentBucketName` value
   - Click **Delete**
   - Alternatively, use the AWS CLI to delete across accounts:

     ```bash
     # Assume role in member account and delete stack
     aws cloudformation delete-stack --stack-name aiml-security-<account_id> \
       --region <deployment-region>
     ```

   - The assessment buckets are retained by design, so delete them manually using the S3 cleanup helper above if you no longer need the report artifacts

2. **Delete the central AWS CodeBuild infrastructure stack**:
   - In the management account, navigate to **AWS CloudFormation** > **Stacks**
   - Select the `aiml-security-multi-account` stack, or the custom stack name you chose
   - Before deleting it, open **Outputs** and record the `AssessmentBucket` value
   - Click **Delete**
   - Wait for stack deletion to complete

3. **Delete the AWS CloudFormation StackSet member roles**:
   - Navigate to **AWS CloudFormation** > **StackSets**
   - Select the StackSet created from `deployment/1-aiml-security-member-roles.yaml` (for example, `aiml-security-member-roles`, or your custom StackSet name)
   - Click **Actions** > **Delete stacks from StackSet**
   - Select all deployment targets (OUs or accounts)
   - Wait for stack instances to be deleted
   - Once all stack instances are removed, delete the AWS CloudFormation StackSet itself

4. **Clean up Amazon S3 buckets**:
   - Delete each retained `AssessmentBucketName` bucket from the per-account SAM assessment stacks.
   - If the central infrastructure stack deletion fails because its `AssessmentBucket` is not empty, empty and delete that bucket, then retry stack deletion.

   To find likely assessment buckets:

   ```bash
   aws s3 ls | grep aiml-security
   ```

---

## Identifying Stack Types

The deployment creates multiple AWS CloudFormation stacks. Here's how to identify them:

| Stack Type | How to Identify | Action |
| --- | --- | --- |
| **Infrastructure Stack** (yours) | The name you chose (for example, `aiml-security-single-account`) | Delete after assessment stacks |
| **Assessment Stack** (auto-generated) | `aiml-sec-{account_id}` (single) or `aiml-security-{account_id}` (multi) | Delete before the infrastructure stack |

**Quick Check**: If you see a stack name starting with `aiml-sec-` or `aiml-security-` followed by numbers (or `aiml-security-mgmt`), that's an auto-generated assessment stack.

---

## Optional CloudWatch Logs Cleanup

AWS Lambda and AWS CodeBuild create Amazon CloudWatch log groups during assessment runs. These log groups can remain after stack deletion unless you delete them or configure retention.

Common log group name patterns include:

- `/aws/lambda/aiml-security-*`
- `/aws/codebuild/AIMLSecurityCodeBuild`
- `/aws/codebuild/AIMLSecurityMultiAccountCodeBuild`

To list likely log groups:

```bash
aws logs describe-log-groups \
  --log-group-name-prefix /aws/lambda/aiml-security-

aws logs describe-log-groups \
  --log-group-name-prefix /aws/codebuild/AIMLSecurity
```

To delete a log group:

```bash
aws logs delete-log-group --log-group-name "<log-group-name>"
```
