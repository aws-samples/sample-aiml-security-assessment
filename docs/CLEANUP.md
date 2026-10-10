# Cleanup Guide

This guide explains how to remove the resources deployed by the AI/ML Security
Assessment framework.

Before deleting any stack, record the S3 bucket names from its outputs. After a
stack is deleted, its outputs are no longer available.

The deployment creates these buckets, all versioned:

- **Infrastructure stack bucket:** the `AssessmentBucket` output of the stack
  you deployed, such as `aiml-security-single-account` or
  `aiml-security-multi-account`. It holds every report, so it is never empty
  after a run. CloudFormation cannot delete a bucket that still contains
  objects, so empty it **before** deleting the stack.
- **Assessment stack buckets:** the `AssessmentBucketName` output of each
  AWS SAM assessment stack (`aiml-sec-{account_id}`, `aiml-security-{account_id}`,
  or `aiml-security-mgmt`). These buckets use `DeletionPolicy: Retain`, so they
  remain after the stack is deleted. Delete them yourself for a full cleanup.
- **AWS SAM CLI artifact bucket:** created by `sam deploy --resolve-s3` in the
  `aws-sam-cli-managed-default` stack of each assessed account. See
  [Optional: AWS SAM CLI Artifact Stack](#optional-aws-sam-cli-artifact-stack).

To tell the stacks apart, see
[Confused by Multiple CloudFormation Stacks](TROUBLESHOOTING.md#11-confused-by-multiple-cloudformation-stacks).

## Table of Contents

- [Cleanup Order](#cleanup-order)
- [Emptying and Deleting Versioned S3 Buckets](#emptying-and-deleting-versioned-s3-buckets)
- [Single-Account Cleanup](#single-account-cleanup)
- [Multi-Account Cleanup](#multi-account-cleanup)
- [Optional: AWS SAM CLI Artifact Stack](#optional-aws-sam-cli-artifact-stack)
- [Optional: CloudWatch Logs Cleanup](#optional-cloudwatch-logs-cleanup)

<a id="identifying-stack-types"></a>

## Cleanup Order

Delete resources in this order:

1. Record the S3 bucket names from the stack outputs.
2. Delete the **assessment stacks** (created by CodeBuild with AWS SAM).
3. Empty and delete the retained assessment buckets.
4. Empty the **infrastructure stack** bucket, then delete the infrastructure
   stack (the stack you deployed).
5. Delete the AWS CloudFormation StackSet member roles (multi-account only).
6. Optional: delete the `aws-sam-cli-managed-default` stack and its bucket.
7. Optional: delete the CloudWatch log groups created during assessment runs.

---

## Emptying and Deleting Versioned S3 Buckets

A recursive `aws s3 rm` removes only current objects; a versioned bucket still
holds noncurrent versions and delete markers. The following commands remove
current objects, noncurrent versions, and delete markers, and then the bucket.
They require `jq`.

To list likely buckets created by the framework (single-account names start
with `aiml-sec-`, multi-account names with `aiml-security-`, and the
infrastructure bucket name contains `assessmentbucket`):

```bash
aws s3 ls | grep -E 'aiml-sec|assessmentbucket'
```

Confirm each bucket against the names you recorded from the stack outputs
before deleting it.

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

Repeat for each bucket you want to remove. To empty a bucket but keep it (for
the infrastructure bucket, before deleting its stack), skip the final
`aws s3 rb` command.

---

## Single-Account Cleanup

1. **Delete the AWS SAM assessment stack:**
   - Open **AWS CloudFormation** > **Stacks**.
   - Select the `aiml-sec-{account_id}` stack (for example,
     `aiml-sec-123456789012`).
   - Open **Outputs** and record the `AssessmentBucketName` value.
   - Choose **Delete** and wait for the deletion to complete.
2. **Delete the retained assessment bucket** recorded in step 1, using
   [the commands above](#emptying-and-deleting-versioned-s3-buckets), if you no
   longer need its contents.
3. **Empty the infrastructure bucket:**
   - Select the `aiml-security-single-account` stack (or your stack name).
   - Open **Outputs** and record the `AssessmentBucket` value.
   - Download any reports you want to keep, then empty the bucket.
4. **Delete the infrastructure stack:** choose **Delete** and wait for the
   deletion to complete. If the bucket still has objects, the deletion fails;
   empty it and retry.

---

## Multi-Account Cleanup

1. **Delete the AWS SAM assessment stacks in each assessed account:**
   - In the deployment region of each scanned account, open
     **AWS CloudFormation** > **Stacks**.
   - Select the `aiml-security-{account_id}` stack (for example,
     `aiml-security-123456789012`). For the central account that runs
     CodeBuild, select `aiml-security-mgmt`.
   - Open **Outputs** and record the `AssessmentBucketName` value.
   - Choose **Delete**. Alternatively, with credentials for that account, use
     the AWS CLI:

     ```bash
     aws cloudformation delete-stack --stack-name aiml-security-<account_id> \
       --region <deployment-region>
     ```

2. **Delete the retained assessment buckets** recorded in step 1, using
   [the commands above](#emptying-and-deleting-versioned-s3-buckets), if you no
   longer need their contents.
3. **Empty the central infrastructure bucket:**
   - In the central account, select the `aiml-security-multi-account` stack
     (or your stack name).
   - Open **Outputs** and record the `AssessmentBucket` value.
   - Download any reports you want to keep, then empty the bucket.
4. **Delete the central infrastructure stack:** choose **Delete** and wait for
   the deletion to complete.
5. **Delete the member-role StackSet:**
   - Open **AWS CloudFormation** > **StackSets**.
   - Select the StackSet created from
     `deployment/1-aiml-security-member-roles.yaml` (for example,
     `aiml-security-member-roles`).
   - Choose **Actions** > **Delete stacks from StackSet**, select all deployment
     targets (OUs or accounts), and wait for the stack instances to be deleted.
   - When all stack instances are removed, delete the StackSet.

---

## Optional: AWS SAM CLI Artifact Stack

CodeBuild runs `sam deploy --resolve-s3`, which creates an
`aws-sam-cli-managed-default` stack and a versioned bucket (named
`aws-sam-cli-managed-default-samclisourcebucket-*`) for deployment packages. It
exists in the deployment region of each assessed account: the single account,
or each scanned member account and the central account that runs CodeBuild.

> **Warning:** This stack and bucket are shared by every AWS SAM CLI project
> that deploys with `--resolve-s3` in the same account and region. Delete them
> only if nothing else in that account and region uses the AWS SAM CLI.

To remove them:

1. Open the `aws-sam-cli-managed-default` stack, and record the `SourceBucket`
   output.
2. Empty that bucket using
   [the commands above](#emptying-and-deleting-versioned-s3-buckets), skipping
   the final `aws s3 rb`.
3. Delete the `aws-sam-cli-managed-default` stack.

---

## Optional: CloudWatch Logs Cleanup

AWS Lambda and AWS CodeBuild create Amazon CloudWatch log groups during
assessment runs. These log groups remain after the stacks are deleted unless you
delete them or set a retention period.

Log group names follow these patterns:

- `/aws/lambda/aiml-security-*`
- `/aws/codebuild/AIMLSecurityCodeBuild`
- `/aws/codebuild/AIMLSecurityMultiAccountCodeBuild`
- `/aws/lambda/<infrastructure-stack-name>-CodeBuildStartBuildLambda-*` (the
  function that starts the first build)

To list them:

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
