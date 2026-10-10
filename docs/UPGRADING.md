# Upgrading an Existing Deployment

This guide explains how to move an existing deployment to a new release, and
how to change an existing deployment to scan more than one region.

Update only the deployment layers that the release changed. For a code-only
fix, running CodeBuild again is normally enough: it pulls the configured source
revision and updates the AWS SAM assessment stack. CodeBuild cannot update the
top-level infrastructure stack or the multi-account member-role StackSet.

Do not delete the existing stacks. Update them in place so that report buckets,
configuration, and stack identities are kept.

## Table of Contents

- [Determine What Changed](#determine-what-changed)
- [Before Upgrading](#before-upgrading)
- [Single-Account Upgrade](#single-account-upgrade)
- [Multi-Account Upgrade](#multi-account-upgrade)
- [Direct AWS SAM Deployment](#direct-aws-sam-deployment)
- [Why CodeBuild Must Be Started Manually](#why-codebuild-must-be-started-manually)
- [Post-Upgrade Verification](#post-upgrade-verification)
- [Changing an Existing Deployment to Multi-Region](#changing-an-existing-deployment-to-multi-region)

---

## Determine What Changed

Each changed path maps to one deployment action:

| Changed path | Deployment action |
| --- | --- |
| `aiml-security-assessment/functions/**` or Lambda `requirements.txt` | Run CodeBuild to package and deploy the updated Lambda code |
| `aiml-security-assessment/statemachine/**` | Run CodeBuild to update the state machine through AWS SAM |
| `aiml-security-assessment/template.yaml` or `template-multi-account.yaml` | Run CodeBuild to update the corresponding AWS SAM assessment stack |
| `buildspec.yml` | Run CodeBuild so the build uses the updated orchestration |
| `consolidate_html_reports.py` | Run multi-account CodeBuild to apply the updated consolidator |
| `assessment_history/**` | Run CodeBuild; the changes-since-last-assessment report runs from this package in the post-build phase |
| `deployment/aiml-security-single-account.yaml` | Update the single-account infrastructure stack |
| `deployment/1-aiml-security-member-roles.yaml` | Update the multi-account member-role StackSet before running CodeBuild |
| `deployment/2-aiml-security-codebuild.yaml` | Update the multi-account central infrastructure stack |
| Only `docs/**`, tests, examples, or `.github/**` | No deployed-resource update is required |

Check the root [CHANGELOG](../CHANGELOG.md) first. Its `Unreleased` or
target-version `Deployment impact` section states which actions are required.
If the changelog does not cover the exact revisions you are comparing, compare
the commit used by the last successful build with the target tag or commit:

```bash
git diff --name-only <deployed-commit>..<target-tag-or-commit> -- \
  deployment/ \
  aiml-security-assessment/ \
  assessment_history/ \
  buildspec.yml \
  consolidate_html_reports.py
```

The CodeBuild build details show the resolved source commit. Use that commit,
not a moving branch name such as `main`, as `<deployed-commit>`.

Read the result as follows:

- If only deployable source or AWS SAM files changed, run CodeBuild.
- If a top-level `deployment/*.yaml` file changed, update only the stack or
  StackSet created from that file.
- If both the member-role template and assessment files changed, update the
  StackSet first, then run CodeBuild.
- If no deployable file changed, no AWS deployment is needed.

**How the source revision is picked up.** CodeBuild clones the revision named
by the infrastructure stack's `GitHubBranch` parameter on every build:

- A deployment that tracks a moving branch such as `main` picks up new code
  when you start CodeBuild. No stack update is needed unless a top-level
  template changed.
- A deployment pinned to a tag or commit keeps building that revision. Update
  `GitHubBranch` first. If the stack's template did not change, this can be a
  parameter-only update that uses the current template.

## Before Upgrading

1. Review the changelog's `Deployment impact` section, or compare the two
   revisions as described in [Determine What Changed](#determine-what-changed).
2. Choose the source revision to deploy. `GitHubBranch` accepts a branch, tag,
   or commit; an immutable release tag or commit is recommended for
   reproducible deployments.
3. Download only the templates that changed and apply to your deployment:

   | Deployment mode | Template to download when changed |
   | --- | --- |
   | Single account | `deployment/aiml-security-single-account.yaml` |
   | Multi-account | `deployment/1-aiml-security-member-roles.yaml` and `deployment/2-aiml-security-codebuild.yaml` |
   | Direct AWS SAM | `aiml-security-assessment/template.yaml` or `aiml-security-assessment/template-multi-account.yaml` |

4. Record the existing stack parameters and, for multi-account deployments, the
   StackSet deployment targets and regions.
5. Review new or changed IAM permissions before applying the templates.

## Single-Account Upgrade

1. Determine whether `deployment/aiml-security-single-account.yaml` changed.
2. If it changed, open the existing infrastructure stack in AWS CloudFormation
   and replace its template with the target release's version. This is the
   stack you created from `deployment/aiml-security-single-account.yaml`, not
   the generated `aiml-sec-{account_id}` assessment stack. Do not create a
   second stack.
3. If the template did not change but the deployment is pinned to an older tag
   or commit, update the stack using its current template and change only
   `GitHubRepoUrl` or `GitHubBranch` as needed.
4. Keep the remaining parameter values unless you intend to change the
   assessment configuration. Make sure `GitHubRepoUrl` and `GitHubBranch` point
   to the repository and revision that match the uploaded template.
5. If you are updating the stack, review the change set (including IAM
   changes), acknowledge `CAPABILITY_NAMED_IAM` when requested, apply it, and
   wait for `UPDATE_COMPLETE`.
6. If deployable source or AWS SAM files changed, open the CodeBuild project
   named in the infrastructure stack's outputs and start a build.
7. Confirm that the build updates the existing `aiml-sec-{account_id}` AWS SAM
   stack and that the assessment finishes. For documentation-only or test-only
   changes, no build is required.

## Multi-Account Upgrade

Perform only the applicable steps, in this order. When the member-role template
changed, update it before deploying assessment code.

1. Determine whether `deployment/1-aiml-security-member-roles.yaml` changed.
2. If it changed, update the existing member-role StackSet with the target
   release's template. Keep `ManagementAccountID`, deployment targets, regions,
   and other settings, and apply the update to every currently targeted
   account and region.
3. If you updated the StackSet, wait for the operation to finish and for every
   StackSet instance to report success. Resolve failed or outdated instances
   before continuing.
4. Determine whether `deployment/2-aiml-security-codebuild.yaml` changed. If it
   changed, open the existing central infrastructure stack and replace its
   template with the target release's version.
5. If the central template did not change but the deployment is pinned to an
   older tag or commit, update the central stack using its current template and
   change only `GitHubRepoUrl` or `GitHubBranch` as needed.
6. Keep all remaining parameters unless you are deliberately changing the
   deployment. Make sure `GitHubRepoUrl` and `GitHubBranch` match the release
   used for the member-role and central templates.
7. If you are updating the central stack, review the change set, acknowledge
   `CAPABILITY_NAMED_IAM` when requested, apply it, and wait for
   `UPDATE_COMPLETE`.
8. If deployable source or AWS SAM files changed, start the central
   multi-account CodeBuild project.
9. Confirm that CodeBuild can assume the member role (`MemberRoleName`, default
   `AIMLSecurityMemberRole`) in every target account, updates the existing
   `aiml-security-{account_id}` AWS SAM stacks (and `aiml-security-mgmt` in the
   central account, which every multi-account run assesses), and completes the
   assessments.

The order matters. The member role carries the permissions CodeBuild uses to
deploy the SAM stack, poll the Step Functions execution, and retrieve reports in
each account, so update it first when it changes. Assessment API permissions are
not on the member role; they are on the SAM-created Lambda execution roles, and
a missing one appears as `N/A` or an incomplete result rather than a build
failure.

## Direct AWS SAM Deployment

If you deployed the assessment directly with AWS SAM rather than through the
top-level CloudFormation templates:

1. Check out or download the intended release.
2. Build `aiml-security-assessment/template.yaml` or
   `aiml-security-assessment/template-multi-account.yaml`, whichever you use.
3. Deploy it to the existing AWS SAM stack name, keeping the existing parameter
   values unless you intend to change them.
4. Start the Step Functions execution with the execution input the release
   expects. For example, use `"enableResponsibleAIGRC": "true"`, not the
   legacy `"enableFinServ"` key (see
   [Troubleshooting §6b](TROUBLESHOOTING.md#6b-execution-fails-with-legacyenablefinservinputrejected)).

You are responsible for separately updating any cross-account roles or
orchestration infrastructure you created yourself.

## Why CodeBuild Must Be Started Manually

The `CodeBuildStartBuild` custom resource in both top-level infrastructure
templates starts CodeBuild only on a CloudFormation `Create` event. It does
nothing on `Update` events. Updating the infrastructure template or
`GitHubBranch` therefore does not start a build. Start CodeBuild yourself when
the target revision contains deployable assessment or orchestration changes.

## Post-Upgrade Verification

- Every infrastructure stack you updated is `UPDATE_COMPLETE`.
- If you updated the multi-account StackSet, all targeted instances are current
  and successful.
- The CodeBuild source revision is the intended branch, tag, or commit.
- If CodeBuild was required, it completed the AWS SAM deployment without IAM or
  role-assumption errors.
- If CodeBuild was required, the existing AWS SAM assessment stacks reached
  `CREATE_COMPLETE` or `UPDATE_COMPLETE`.
- If an assessment ran, a new report was written to the infrastructure stack's
  `AssessmentBucket` and contains the checks expected for the deployed release.

---

## Changing an Existing Deployment to Multi-Region

You can change an existing single-region deployment to scan several regions by
updating the existing infrastructure stack. No teardown is required.

1. Open **AWS CloudFormation** > **Stacks**.
2. Select your infrastructure stack (for example, `aiml-security-single-account`
   or `aiml-security-multi-account`).
3. Choose **Update** > **Use current template**.
4. Set `TargetRegions` to a comma- or space-separated region list, for example
   `us-east-1,us-west-2,eu-west-1` or `us-east-1 us-west-2 eu-west-1`.
5. Submit the update and wait for `UPDATE_COMPLETE`.
6. Start CodeBuild. The stack update does not start a build (see
   [Why CodeBuild Must Be Started Manually](#why-codebuild-must-be-started-manually)).

What happens:

- CloudFormation updates the `TARGET_REGIONS` environment variable on the
  CodeBuild project.
- On the next build, `sam deploy` updates the assessment stack and passes the
  new `TargetRegions` value to the assessment Lambda functions and state
  machine.
- The Step Functions `Resolve Target Regions` state resolves the list, and the
  `Scan Regions` Map state scans those regions in parallel.
- Earlier reports stay in the S3 bucket.
- Leaving `TargetRegions` empty keeps the single-region behavior, scanning only
  the deployment region.

For region validation errors or unexpected region coverage, see
[Troubleshooting §7](TROUBLESHOOTING.md#7-targetregions-validation-or-unexpected-region-coverage).
