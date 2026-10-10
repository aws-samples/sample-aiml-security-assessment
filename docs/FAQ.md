# Frequently Asked Questions

Answers to common questions about the AI/ML Security Assessment framework. For
error symptoms and fixes, see the [Troubleshooting Guide](TROUBLESHOOTING.md).

## Table of Contents

- [General Questions](#general-questions)
  - [Does this assessment make any changes to my AWS resources?](#does-this-assessment-make-any-changes-to-my-aws-resources)
  - [How long does an assessment take to run?](#how-long-does-an-assessment-take-to-run)
  - [How often should I run security assessments?](#how-often-should-i-run-security-assessments)
  - [What AWS Regions are supported?](#what-aws-regions-are-supported)
  - [Does this work if I don't have any AI/ML resources deployed yet?](#does-this-work-if-i-dont-have-any-aiml-resources-deployed-yet)
- [Cost and Billing](#cost-and-billing)
  - [How much does it cost to run this assessment?](#how-much-does-it-cost-to-run-this-assessment)
  - [Are there any ongoing costs when not running assessments?](#are-there-any-ongoing-costs-when-not-running-assessments)
- [Customization and Configuration](#customization-and-configuration)
  - [Can I customize which security checks are included?](#can-i-customize-which-security-checks-are-included)
  - [Can I add custom security checks?](#can-i-add-custom-security-checks)
  - [Can I export results to other formats?](#can-i-export-results-to-other-formats)
  - [Can I schedule automated assessments?](#can-i-schedule-automated-assessments)
  - [Why is the assessment taking longer than expected?](#why-is-the-assessment-taking-longer-than-expected)
- [Security and Compliance](#security-and-compliance)
  - [Where is my assessment data stored?](#where-is-my-assessment-data-stored)
  - [What IAM permissions does the framework need?](#what-iam-permissions-does-the-framework-need)
  - [Is this assessment sufficient for compliance requirements such as SOC 2 or HIPAA?](#is-this-assessment-sufficient-for-compliance-requirements-such-as-soc-2-or-hipaa)
  - [How do the checks relate to the AWS Well-Architected Framework?](#how-do-the-checks-relate-to-the-aws-well-architected-framework)

---

## General Questions

### Does this assessment make any changes to my AWS resources?

The security checks do not modify your AI/ML workloads or data. They read
resource configuration and write assessment artifacts to S3 buckets that the
framework owns.

The framework does create and manage its own resources: CloudFormation stacks,
IAM roles, Lambda functions, a Step Functions state machine, CodeBuild projects,
S3 buckets, and, when you provide an email address, an Amazon SNS topic and
an Amazon EventBridge rule for build notifications. At the start of each run it
removes the current CSV, HTML, and JSON objects from its own SAM assessment
bucket before writing new artifacts. Earlier object versions and delete markers remain until you remove
them; see the
[Cleanup Guide](CLEANUP.md#emptying-and-deleting-versioned-s3-buckets).

### How long does an assessment take to run?

Typical times, which vary with the number of resources, regions, and optional
assessments:

- **Single account, one region:** 5-10 minutes
- **Multi-account, about 10 accounts:** 15-20 minutes
- **Multi-account, 50 or more accounts:** 30-45 minutes

In multi-account mode, CodeBuild deploys and assesses accounts one at a time.
Within each account, regions are scanned in parallel (up to five at a time).

### How often should I run security assessments?

- **Production AI/ML workloads:** weekly or every two weeks
- **Development and test environments:** monthly
- **After significant changes:** always (new models, configuration changes,
  IAM updates)
- **Compliance requirements:** as your organization's security policies
  require

To run assessments on a schedule, see
[Can I schedule automated assessments?](#can-i-schedule-automated-assessments)

### What AWS Regions are supported?

The framework is validated and supported only in the standard AWS commercial
partition (`aws`). Leave `TargetRegions` empty to scan only the deployment
region, or provide a comma- or space-separated list of commercial regions.

AWS GovCloud (US) (`aws-us-gov`) and AWS China (`aws-cn`) are not validated or
supported. Supporting them requires code changes, a partition-specific review
of service availability, and end-to-end deployment testing; template changes
alone are not enough.

### Does this work if I don't have any AI/ML resources deployed yet?

Yes. The assessment completes and reports `N/A` for checks that have no
resources to assess. This is useful as a security baseline before you deploy
AI/ML workloads.

---

## Cost and Billing

### How much does it cost to run this assessment?

A typical single-account, single-region run costs roughly $0.50-$2.00:

- **AWS Lambda:** $0.10-$0.50
- **AWS Step Functions:** $0.05-$0.25 (state transitions)
- **Amazon S3:** $0.01-$0.10 (report storage)
- **AWS CodeBuild:** $0.10-$0.50 (billed per build minute)

Lambda and Step Functions costs grow with the number of accounts, regions, and
selected assessments. For each account, one run makes this many Lambda
invocations:

```text
4 + (R × S) + G + (R × O)

R = number of regions scanned
S = number of selected direct service assessments (0-4: Amazon Bedrock,
    Amazon SageMaker AI, Amazon Bedrock AgentCore, AWS Agent Registry)
G = 1 if Responsible AI GRC or OWASP is enabled, otherwise 0
O = 1 if OWASP is enabled, otherwise 0
```

The fixed 4 are bucket cleanup, IAM permission caching, region resolution, and
report generation. For example, one account with all four services selected,
three regions, and both optional assessments enabled makes
4 + 12 + 1 + 3 = 20 invocations.

AWS Organizations API calls are free. In multi-account mode, the CodeBuild
compute type, and so its per-minute price, depends on `ConcurrentAccountScans`;
see the table in
[Troubleshooting §9](TROUBLESHOOTING.md#9-codebuild-timeout-or-out-of-memory-with-many-accounts).
For example, a 30-minute multi-account build costs roughly $0.15 at the
default `Three` and $0.60 at `Twelve`.

### Are there any ongoing costs when not running assessments?

Only storage:

- **Amazon S3:** report storage, about $0.023 per GB-month in S3 Standard.
  Old object versions also count, because the buckets are versioned.
- **Amazon CloudWatch Logs:** log storage for Lambda and CodeBuild logs. Set a
  retention period on the log groups to limit it.

Lambda, Step Functions, and CodeBuild are billed per use and have no idle cost.
Prices vary by region; see each service's pricing page.

---

## Customization and Configuration

### Can I customize which security checks are included?

You can turn whole service assessments on or off with
`EnableBedrockAssessment`, `EnableSageMakerAssessment`,
`EnableAgentCoreAssessment`, and `EnableAgentRegistryAssessment`, and turn on
the optional assessments with `EnableResponsibleAIGRCAssessment` and
`EnableOWASPAssessment`. Individual checks cannot be turned off; filter them in
the HTML report instead. See
[Selecting Service Assessments](../README.md#selecting-service-assessments).

### Can I add custom security checks?

Yes. To add a check to an existing service, see
[Adding a New Check Inside an Existing Service](DEVELOPER_GUIDE.md#adding-a-new-check-inside-an-existing-service).
To add a new service, see
[Adding New AI/ML Service Assessments](DEVELOPER_GUIDE.md#adding-new-aiml-service-assessments).

### Can I export results to other formats?

Each run writes:

- **CSV files**, one per assessment (and per region for regional assessments),
  in each account's folder of the report bucket
- **HTML reports** for interactive viewing, including a consolidated report in
  multi-account mode
- A **changes since last assessment** HTML page and CSV (see
  [Changes Since Last Assessment](ASSESSMENT_HISTORY.md))

To send findings to a SIEM or another tool, process the CSV files from the
report bucket. Every CSV shares the columns `Check_ID`, `Finding`,
`Finding_Details`, `Resolution`, `Reference`, `Severity`, `Status`, and
`Region`.

### Can I schedule automated assessments?

Yes. Use Amazon EventBridge Scheduler or an EventBridge scheduled rule to start
the assessment CodeBuild project (`AIMLSecurityCodeBuild` for single-account,
`AIMLSecurityMultiAccountCodeBuild` for multi-account). The schedule's role must
trust the EventBridge service and allow `codebuild:StartBuild` on the project.

<details>
<summary>Example: weekly EventBridge rule with the AWS CLI</summary>

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

For a rule, the target role must trust `events.amazonaws.com`. For
EventBridge Scheduler, it must trust `scheduler.amazonaws.com`.

</details>

Every scheduled run also gets a
[Changes Since Last Assessment](ASSESSMENT_HISTORY.md) report that compares it
with the account's previous run.

### Why is the assessment taking longer than expected?

Run time depends on:

- **Number of resources:** accounts with many Amazon SageMaker AI notebooks or
  Amazon Bedrock resources take longer
- **API throttling:** AWS API rate limits can slow large environments
- **Number of accounts:** multi-account runs assess accounts one after another,
  so run time grows with the number of accounts
- **Region scope:** each region in `TargetRegions` adds another set of service
  scans
- **Optional assessments:** `EnableResponsibleAIGRCAssessment` adds the `FS-`
  checks; `EnableOWASPAssessment` adds the `OW-` checks and also runs the
  `FS-` assessment as a source

If builds time out, increase `CodeBuildTimeout`, reduce `TargetRegions`, split
accounts into batches with `MultiAccountListOverride`, or lower concurrency if
throttling is the bottleneck. Lambda timeouts are set in the SAM templates. See
also [Troubleshooting §9](TROUBLESHOOTING.md#9-codebuild-timeout-or-out-of-memory-with-many-accounts).

---

## Security and Compliance

### Where is my assessment data stored?

All assessment data stays in your AWS accounts:

- Reports are stored in your S3 buckets; you control retention and access.
- Logs are in your Amazon CloudWatch Logs; you control retention.
- No data is sent to external services or third parties.

### What IAM permissions does the framework need?

See [Permissions Required](../README.md#permissions-required) for each role,
what it can do, and the template that defines it.

### Is this assessment sufficient for compliance requirements such as SOC 2 or HIPAA?

No. It evaluates your configuration against AWS security best practices and
can support compliance work, for example by showing controls and by finding
misconfigurations that could lead to violations. It is not a formal compliance
audit and does not cover every requirement of any compliance framework. Work
with your compliance team to decide how it fits into your program.

### How do the checks relate to the AWS Well-Architected Framework?

The core and Agentic AI Security checks are derived from the
[AWS Well-Architected Generative AI Lens](https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/generative-ai-lens.html)
and the
[Agentic AI Lens](https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html),
which apply the
[Security pillar](https://docs.aws.amazon.com/wellarchitected/latest/framework/a-security.html)
to AI/ML workloads. The Security pillar questions are:

| Question | Topic |
| --- | --- |
| SEC 1 | Security foundations: operating your workload securely |
| SEC 2 | Identity management: authentication for people and machines |
| SEC 3 | Permissions management for people and machines |
| SEC 4 | Detecting and investigating security events |
| SEC 5 | Protecting network resources |
| SEC 6 | Protecting compute resources |
| SEC 7 | Data classification |
| SEC 8 | Protecting data at rest |
| SEC 9 | Protecting data in transit |
| SEC 10 | Incident response |
| SEC 11 | Application security |

Most checks relate to permissions (SEC 2, SEC 3), logging and detection
(SEC 4), network isolation (SEC 5), and encryption (SEC 8, SEC 9). The
assessment is not a Well-Architected review; it checks specific
configurations and does not answer the pillar questions for you.
