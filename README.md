# AWS AI/ML Security Assessment for Amazon Bedrock, Amazon SageMaker AI, and Amazon Bedrock AgentCore

*A serverless framework that scans your AWS accounts for AI/ML security misconfigurations and produces an interactive, shareable report.*

[![License: MIT-0](https://img.shields.io/badge/License-MIT--0-yellow.svg)](https://opensource.org/licenses/MIT-0) [![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/downloads/) [![AWS SAM](https://img.shields.io/badge/AWS-SAM-orange.svg)](https://aws.amazon.com/serverless/sam/)

**Open-source automated security scanner for generative AI and machine learning workloads on AWS.** Core checks for Amazon Bedrock, Amazon SageMaker AI, and Amazon Bedrock AgentCore are built on the [AWS Well-Architected Framework — Generative AI Lens](https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/generative-ai-lens.html). An optional Financial Services GenAI risk module adds 64 checks aligned to the [AWS User Guide to Governance, Risk, and Compliance for Responsible AI Adoption within Financial Services Industries](https://d1.awsstatic.com/onedam/marketing-channels/website/aws/en_US/whitepapers/compliance/AWS-User-Guide-Governance-Risk-Compliance-for-Responsible-AI-Adoption-Financial-Services.pdf). See the [AWS Security Blog announcement](https://aws.amazon.com/blogs/security/introducing-the-updated-aws-user-guide-to-governance-risk-and-compliance-for-responsible-ai-adoption/) for context on the updated guide.

Run **[174 security checks](docs/SECURITY_CHECKS.md)** across your AWS accounts and regions in one deployment. Surfaces IAM misconfigurations, encryption gaps, network isolation issues, missing guardrails, and governance gaps — with interactive HTML reports, severity ratings, and AWS documentation links for remediation. Single-account or full AWS Organizations multi-account scans; all data stays in your account.

---

## See It In Action

The framework generates professional, interactive security assessment reports with filtering, search, and dark mode support.

**Download Sample Reports** | [Single Account](https://aws-samples.github.io/sample-aiml-security-assessment/sample-reports/security_assessment_single_account.html) | [Multi-Account](https://aws-samples.github.io/sample-aiml-security-assessment/sample-reports/security_assessment_multi_account.html)

<table>
  <tr>
    <td width="50%">
      <img src="sample-reports/dashboard-overview-light.png" alt="AWS AI/ML security assessment dashboard showing Amazon Bedrock, Amazon SageMaker AI, and Amazon Bedrock AgentCore findings by severity"/>
      <p align="center"><em>Executive Dashboard (Light Mode)</em></p>
    </td>
    <td width="50%">
      <img src="sample-reports/dashboard-overview-dark.png" alt="AWS AI/ML security assessment dashboard showing Amazon Bedrock, Amazon SageMaker AI, and Amazon Bedrock AgentCore findings by severity"/>
      <p align="center"><em>Executive Dashboard (Dark Mode)</em></p>
    </td>
  </tr>
  <tr>
    <td colspan="2">
      <img src="sample-reports/findings-table.png" alt="Detailed Findings Table"/>
      <p align="center"><em>Interactive Findings Table with Filtering</em></p>
    </td>
  </tr>
</table>

### Key Features

- **Executive Summary** with severity counts and service breakdown
- **Priority Recommendations** highlighting critical issues requiring immediate attention
- **[174 Security Checks](docs/SECURITY_CHECKS.md)** across Amazon Bedrock, Amazon SageMaker AI, Amazon Bedrock AgentCore, Agentic AI Security, Financial Services GenAI Risk, and OWASP Top 10 for LLM
- **Multi-Region Support** for core Bedrock, SageMaker, and AgentCore checks, with per-region risk breakdown
- **Interactive Filtering** by account, region, service, severity, and status
- **Light/Dark Mode Toggle** with persistent user preference
- **Text Search** across all findings with real-time results
- **Direct AWS Documentation Links** for each finding with remediation guidance
- **Multi-Account Support** with consolidated reporting across your organization
- **Fully Automated** deployment and execution through AWS CloudFormation and AWS CodeBuild

---

## Table of Contents

- [What It Does](#what-it-does)
- [Why Use This Framework?](#why-use-this-framework)
- [Scope and Limitations](#scope-and-limitations)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Single-Account Deployment](#single-account-deployment)
- [Multi-Account Deployment](#multi-account-deployment)
- [How It Works](#how-it-works)
- [Permissions Required](#permissions-required)
- [Viewing Results](#viewing-results)
- [Customization](#customization)
- [Cleanup](docs/CLEANUP.md)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

---

## What It Does

This serverless assessment framework automatically evaluates your AI/ML workloads against AWS security best practices. It uses AWS serverless services to gather data from the control plane and generate reports containing the status of various security checks, severity levels, and recommended actions.

Designed for workloads using [Amazon Bedrock](https://aws.amazon.com/bedrock/), [Amazon Bedrock AgentCore](https://aws.github.io/bedrock-agentcore-starter-toolkit/), [Amazon SageMaker AI](https://aws.amazon.com/sagemaker/ai/), or the optional Financial Services GenAI risk assessment.

### Why Use This Framework?

| Challenge | How This Framework Helps |
| --- | --- |
| **Manual security audits are time-consuming** | Fully automated scanning with one-click CloudFormation deployment |
| **Inconsistent security checks across teams** | Standardized 174-check assessment based on AWS Well-Architected Generative AI Lens and Agentic AI Lens best practices, AWS Responsible AI governance/risk/compliance guidance for financial services, and OWASP Top 10 for LLM |
| **Difficulty tracking AI/ML security posture** | Interactive HTML dashboards with severity breakdown and per-account visibility |
| **Multi-account complexity** | Consolidated reporting across AWS Organizations with cross-account role assumption |
| **Compliance and audit support** | Exportable reports to supplement your compliance program, with remediation guidance linked to AWS documentation |
| **Generative AI security gaps** | Purpose-built checks for LLM guardrails, model access controls, and prompt injection prevention |

**Services Covered:**

- **[Amazon Bedrock](docs/SECURITY_CHECKS.md#amazon-bedrock-security-checks-33)** (33 always-on core checks) - Covers guardrails, cross-account policies, content and sensitive-information filters, contextual grounding, automated reasoning, AWS KMS encryption for models/knowledge bases/batch output, Amazon VPC endpoints, IAM permissions, agent guardrails and least privilege, model invocation logging, CloudTrail and CloudWatch monitoring, model/prompt/RAG evaluation, service quotas, and Amazon Inspector Lambda code scanning.
- **[Amazon SageMaker AI](docs/SECURITY_CHECKS.md#amazon-sagemaker-ai-security-checks-25)** (25 always-on core checks) - Covers AWS Security Hub controls, internet and VPC exposure, notebook root access, encryption at rest and in transit, network isolation, IAM permissions, Amazon GuardDuty integration, MLOps pipelines, SageMaker Clarify, Model Monitor, Model Registry, Feature Store, model approval, drift detection, safe deployment patterns, and lineage tracking.
- **[Amazon Bedrock AgentCore](docs/SECURITY_CHECKS.md#amazon-bedrock-agentcore-security-checks-13)** (13 always-on core checks) - Covers runtime VPC configuration, IAM least privilege and stale access, CloudWatch Logs and AWS X-Ray observability, Amazon ECR repository encryption, browser tool storage, memory encryption, policy engine encryption, gateway encryption, VPC endpoints, service-linked roles, resource-based policies, and gateway security configuration.
- **[Agentic AI Security](docs/SECURITY_CHECKS.md#agentic-ai-security-checks-27)** (27 always-on checks) - Covers bounded autonomy, agent identity and access, tool authorization, guardrail enforcement, prompt/input protection, memory privacy, auditability and observability, and abuse/cost protection. Maps selected Amazon Bedrock and Amazon Bedrock AgentCore findings into the [AWS Well-Architected Agentic AI Lens](https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html) view and adds native AgentCore gateway checks.
- **[Financial Services GenAI Risk](docs/SECURITY_CHECKS.md#financial-services-genai-risk-checks-64-additional-5-upstream-extensions)** (64 opt-in checks) - Covers unbounded consumption, excessive agency, supply chain, training data poisoning, vector weaknesses, non-compliant output, misinformation, harmful or biased output, PII disclosure, hallucination, prompt injection, improper output handling, off-topic output, and out-of-date training data. Enable with `EnableFinServAssessment`; checks are derived from the [AWS User Guide to Governance, Risk, and Compliance for Responsible AI Adoption within Financial Services Industries](https://d1.awsstatic.com/onedam/marketing-channels/website/aws/en_US/whitepapers/compliance/AWS-User-Guide-Governance-Risk-Compliance-for-Responsible-AI-Adoption-Financial-Services.pdf).
- **[OWASP Top 10 for LLM](docs/SECURITY_CHECKS.md#owasp-top-10-for-llm-checks-12)** (12 opt-in checks) - Covers LLM01 through LLM10 by mapping existing Amazon Bedrock, Amazon SageMaker AI, Amazon Bedrock AgentCore, and Financial Services findings, plus two native LLM07 checks for system prompt leakage. Enable with `EnableOWASPAssessment`; results align to the [OWASP Top 10 for LLM 2025](https://genai.owasp.org/llm-top-10/) and render in the "By Compliance Standard" report section. When needed, this also runs Financial Services as a hidden source dependency.

**Deployment Options:**

- **Single-Account**: Assess security in one AWS account
- **Multi-Account**: Scan entire AWS Organizations with consolidated reporting

**How It Works:**

1. Deploy through AWS CloudFormation (one-click deployment)
2. Framework automatically scans your AI/ML resources
3. Generates interactive HTML reports stored in your Amazon S3 bucket
4. All data stays in your AWS account - no external dependencies

---

## Scope and Limitations

This tool operates within the [AWS Shared Responsibility Model](https://aws.amazon.com/compliance/shared-responsibility-model/). It assesses **your configuration responsibilities** (IAM policies, encryption settings, network isolation, logging) for AI/ML services. It does not assess AWS-managed infrastructure, physical security, or the underlying service platform.

**Point-in-time assessment.** Each run captures your security posture at the moment of execution. Resource configurations can change immediately after an assessment completes. Run assessments regularly and after significant changes to maintain visibility.

**No guarantee of security or compliance.** This framework identifies common misconfigurations based on AWS best practices and the AWS Well-Architected Framework. It does not cover all possible security risks, does not replace formal compliance audits (SOC 2, HIPAA, and similar), and does not guarantee that your workloads are secure. Use the results as one input into your broader security program.

**174 checks across six areas.** The assessment covers Amazon Bedrock, Amazon SageMaker AI, Amazon Bedrock AgentCore, always-on Agentic AI Security, optional Financial Services GenAI risk checks, and optional OWASP Top 10 for LLM checks. Other AI/ML services (Amazon Comprehend, Amazon Rekognition, Amazon Textract, and others) are not currently assessed.

---

## Quick Start

- **Single-Account**: Jump to [Single-Account Deployment](#single-account-deployment)
- **Multi-Account**: Jump to [Multi-Account Deployment](#multi-account-deployment)

## Architecture

![Architecture](./docs/diagrams/ArchitectureDiagram.png)

## Prerequisites

- Python 3.12 — [Install Python](https://www.python.org/downloads/)
- AWS SAM CLI — [Install the AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html)
- Docker (optional) — [Install Docker](https://hub.docker.com/search/?type=edition&offering=community) — Only required for local development

---

## Single-Account Deployment

1. Download the [aiml-security-single-account.yaml](deployment/aiml-security-single-account.yaml) CloudFormation template.
2. **[Deploy to AWS CloudFormation](https://console.aws.amazon.com/cloudformation/home#/stacks/create/template?stackName=aiml-security-single-account)**
3. Upload the template and provide a stack name.
4. Optionally specify your email address to receive notifications.
5. **(Optional) Multi-Region**: Set `TargetRegions` to scan multiple regions:

   - Leave empty to scan only the deployment region (default)
   - Comma- or space-separated list (for example, `us-east-1,us-west-2,eu-west-1` or `us-east-1 us-west-2 eu-west-1`)
   - `all` to scan all regions where the services are available

6. Acknowledge IAM capabilities and click **Submit**.
7. Once complete, CodeBuild automatically runs the assessment.
8. View results: go to the stack **Outputs** tab → copy `AssessmentBucket` → open the report under the `/{account_id}/` prefix in that S3 bucket.

> **Tip**: The deployment creates two stacks. Your results are in the stack *you named*, not the auto-generated `aiml-sec-*` stack. See [Troubleshooting](docs/TROUBLESHOOTING.md#11-confused-by-multiple-cloudformation-stacks) for details.

---

## Multi-Account Deployment

### Step 1: Deploy Member Roles

Deploy [1-aiml-security-member-roles.yaml](deployment/1-aiml-security-member-roles.yaml) to all target accounts using CloudFormation StackSets with service-managed permissions.

1. Navigate to **CloudFormation** > **StackSets** in the AWS Organizations management account or delegated administrator account
2. Upload the template and set `ManagementAccountID` to the account ID where the central multi-account CodeBuild project runs
3. Select **Service-managed permissions** and target your OUs
4. Select your target region and submit

### Step 2: Deploy Central Infrastructure

Deploy [2-aiml-security-codebuild.yaml](deployment/2-aiml-security-codebuild.yaml) in your central assessment account. This can be your AWS Organizations management account or a delegated administrator/central tooling account.

1. Upload the template and set `MultiAccountScan` to `true`
2. Optionally set `TargetRegions` for multi-region scanning
3. Optionally provide an email address for notifications
4. Acknowledge IAM capabilities and submit
5. Stack creation automatically triggers the assessment across all accounts

---

## Multi-Region Scanning

Both deployment modes support scanning multiple AWS regions in parallel via the `TargetRegions` parameter:

| Value | Behavior |
| --- | --- |
| Empty (default) | Scans deployment region only — fully backward compatible |
| Comma- or space-separated (for example, `us-east-1,us-west-2` or `us-east-1 us-west-2`) | Scans those regions in parallel |
| `all` | Discovers and scans all regions where assessed services are available |

Scanning uses a Step Functions Map state, so multiple regions execute in parallel with no additional time cost. Services unavailable in a region produce an informational N/A finding.

The HTML report includes a Region column, filter dropdown, and "Risk by Region / Scope" summary.

> **Upgrading an existing deployment?** See [Troubleshooting](docs/TROUBLESHOOTING.md#12-upgrading-an-existing-deployment-to-multi-region) — it's a simple stack parameter update with no teardown.

---

## How It Works

1. **Deploy** — CloudFormation creates CodeBuild, S3, IAM roles, and a Lambda trigger
2. **CodeBuild runs** — builds and deploys the SAM assessment stack (per account in multi-account mode)
3. **Step Functions execute** — orchestrates: S3 cleanup → IAM permission caching → resolve regions → Map state fans out per-region assessments (Bedrock, SageMaker, AgentCore in parallel) → optionally run FinServ checks → optionally run OWASP Top 10 for LLM checks → generate consolidated report
4. **Results** — HTML and CSV reports are stored in your S3 bucket

### Optional: Financial Services GenAI Risk Checks (`EnableFinServAssessment`)

The 64 Financial Services (FS-XX) GenAI risk checks are **opt-in** and default
to `false`. Set the `EnableFinServAssessment` deployment parameter to `true`
when you want the additional Financial Services GenAI risk assessment. When
enabled, the FinServ assessment Lambda runs and its findings appear in a
dedicated **Financial Services** section of the HTML report. When left `false`,
no FinServ findings are produced and the report omits the FinServ section
entirely. The toggle is threaded into the Step Functions execution input
(`enableFinServ`); the FinServ Lambda is always deployed but is invoked only
when the flag is `true`.

> **Deployment path note.** The `EnableFinServAssessment` parameter is wired
> through the CodeBuild-based deployment templates
> (`deployment/aiml-security-single-account.yaml` and
> `deployment/2-aiml-security-codebuild.yaml`), which thread it into every Step
> Functions `start-execution` call as `enableFinServ`. This is the supported
> install path. If you instead deploy `aiml-security-assessment/template.yaml`
> directly with `sam deploy` and start executions yourself, the state machine has
> no built-in trigger, so FinServ stays **off** unless you include
> `"enableFinServ": "true"` in the execution input you pass to `StartExecution`.

### Optional: OWASP Top 10 for LLM Checks (`EnableOWASPAssessment`)

The 12 OWASP Top 10 for LLM (OW-XX) checks are **opt-in** and default to
`false`. Set the `EnableOWASPAssessment` deployment parameter to `true` when
you want the additional compliance-standard assessment. When enabled, the OWASP
Lambda runs per region after the Bedrock/SageMaker/AgentCore/FinServ Lambdas
complete: it reads each service's per-region CSV, applies mapping rules to emit
OW-01..OW-10 rows derived from existing findings, and runs two net-new checks
for LLM07 (System Prompt Leakage). Findings appear in a new **"By Compliance
Standard"** sidebar section of the HTML report. When left `false`, no OWASP
findings are produced and the section is omitted entirely. The toggle is
threaded into the Step Functions execution input (`enableOWASP`); the OWASP
Lambda is always deployed but is invoked only when the flag is `true`.

> **OWASP → FinServ dependency (transparent to users).** Roughly two-thirds of
> the OWASP mapping rows — including all of LLM05 (Improper Output Handling) —
> derive from the FinServ (FS-XX) checks. To guarantee **full** OWASP coverage,
> the state machine automatically runs the FinServ Lambda whenever
> `EnableOWASPAssessment=true`, even when `EnableFinServAssessment=false`. When
> the customer did not enable FinServ explicitly, its findings are used only to
> power the OW-XX mappings, are **hidden from the report UI** — no FinServ nav
> item, service card, or section appears — and the raw
> `finserv_security_report_*.csv` is not copied to the customer-facing report
> bucket. Setting both flags to `true` surfaces the FinServ section and CSV
> normally.

The "By Compliance Standard" section is **extensible**: adding NIST AI RMF (`EnableNISTAssessment`) or EU AI Act (`EnableEUAIActAssessment`) later follows the same pattern.

#### Scope and limitations

- **FinServ Region scope.** Core Bedrock, SageMaker, AgentCore, and optional FinServ checks use the resolved `TargetRegions` from the deployment parameters. FinServ findings are emitted with Region values so they appear alongside the same regional filter and per-region report views as the core service checks.
- **Heuristic and advisory checks.** Some controls cannot be verified through an API (application-layer controls, dataset contents, resource associations); these are reported as `ADVISORY`/`N/A` and require manual review. See [How finding severities are determined](#how-finding-severities-are-determined).
- **Permissions.** A check that lacks an IAM permission is reported as `COULD NOT ASSESS` (not a failure). Re-deploy the member role after any IAM template change so newer actions take effect.

For detailed architecture, execution flow, and extension guidance, see the [Developer Guide](docs/DEVELOPER_GUIDE.md).

---

## Viewing Results

1. Open your **infrastructure stack** in CloudFormation → **Outputs** tab → copy `AssessmentBucket`
2. Navigate to that S3 bucket
3. For single-account, open `{account_id}/security_assessment_single_account_*.html`
4. For multi-account, open `consolidated-reports/security_assessment_multi_account_*.html`

### Assessment Execution Process

#### Automatic Trigger

- The AWS CodeBuild project starts automatically after central stack creation
- An AWS Lambda trigger function initiates the assessment workflow

#### Multi-Account Orchestration

1. **Account Discovery**: AWS CodeBuild queries AWS Organizations for active accounts
2. **Role Assumption**: Assumes `AIMLSecurityMemberRole` in each target account
3. **Module Deployment**: Deploys the AI/ML assessment module:

   - Amazon Bedrock Assessment AWS Lambda
   - Amazon SageMaker AI Assessment AWS Lambda
   - Amazon Bedrock AgentCore Assessment AWS Lambda
   - Financial Services GenAI Risk Assessment AWS Lambda
   - OWASP Top 10 for LLM Assessment AWS Lambda
   - AWS IAM Permission Caching AWS Lambda
   - Consolidated Report Generation AWS Lambda

4. **Assessment Execution**: AWS Step Functions orchestrate parallel AWS Lambda execution
5. **Results Collection**: Individual AWS Lambda functions store results in local Amazon S3 buckets
6. **Consolidation**: AWS CodeBuild collects and consolidates results from all accounts
7. **Reporting**: Generates multi-account HTML and CSV reports
8. **Notification**: Sends completion notification through Amazon SNS (if configured)

## Monitoring and Results

- **Amazon S3 Bucket**: Central storage for all assessment results
- **Amazon CloudWatch Logs**: AWS CodeBuild execution logs
- **Amazon SNS Notifications**: Email alerts on completion/failure
- **Amazon EventBridge Rules**: Automated workflow triggers

You can check the AWS CodeBuild console to confirm the assessment completed successfully before accessing the results.

### Accessing Results

1. **Find the Amazon S3 Bucket Name**:

   - Navigate to **AWS CloudFormation** > **Stacks** in the AWS Console
   - For single-account deployments using the standalone template (`aiml-security-single-account.yaml`), select the stack you deployed (for example, `aiml-security-single-account`) and find the `AssessmentBucket` output. Results are synced to this bucket under the `{account_id}/` prefix.
   - For multi-account deployments, select the `aiml-security-multi-account` stack created in [Step 2: Deploy Central Infrastructure](#step-2-deploy-central-infrastructure) and find the `AssessmentBucket` output
   - Go to the **Outputs** tab
   - Copy the Amazon S3 bucket name

   > **Note**: The deployment creates multiple Amazon S3 buckets. Only use the bucket from the `AssessmentBucket` output above. Other buckets (such as `aiml-sec-*-aimlassessmentbucket-*` from nested stacks or `aws-sam-cli-managed-*` for deployment artifacts) are for internal use and can be ignored.

2. **Navigate to the Amazon S3 Bucket**:

   - Go to **Amazon S3** in the AWS Console
   - Search for and open your assessment bucket
   - For single-account deployments, open the `{account_id}/` folder and then open the `security_assessment_single_account_YYYYMMDD_HHMMSS.html` report
   - For multi-account deployments, follow the [Report Structure](#report-structure) guidance below

### Report Structure

#### Consolidated Reports

- **Location**: `consolidated-reports/` folder in the bucket
- **Content**: Multi-account HTML report combining all account assessments
- **File Format**: `security_assessment_multi_account_YYYYMMDD_HHMMSS.html`
- **Features**:

  - Executive summary with metrics (Total, High, Medium, Low severity counts)
  - Service breakdown (Amazon Bedrock, Amazon SageMaker AI, Amazon Bedrock AgentCore, Financial Services GenAI Risk)
  - Priority recommendations
  - Light/dark mode toggle (persists through localStorage)
  - Dropdown filters for Account ID, Region, Service, Severity, Status
  - Text search filter for findings
  - "View Docs" buttons for reference links

#### Individual Account Reports

- **Location**: Folders named with account IDs (for example, `123456789012/`)
- **Content**: Account-specific CSV and HTML files for AI/ML assessments
- **Files Include**:

  - `bedrock_security_report_{execution_id}.csv` - Amazon Bedrock security assessment results
  - `sagemaker_security_report_{execution_id}.csv` - Amazon SageMaker AI security assessment results
  - `agentcore_security_report_{execution_id}.csv` - Amazon Bedrock AgentCore security assessment results
  - `finserv_security_report_{execution_id}.csv` - Financial Services GenAI
    risk assessment results (64 FS-XX checks; present in the report bucket only
    when `EnableFinServAssessment` is enabled)
  - `owasp_security_report_{execution_id}.csv` - OWASP Top 10 for LLM
    assessment results (12 OW-XX checks; present only when
    `EnableOWASPAssessment` is enabled)
  - `permissions_cache_{execution_id}.json` - IAM permissions cache
  - `security_assessment_single_account_{timestamp}.html` - Consolidated HTML report (same features as multi-account report)

### Understanding Results

| Severity | Meaning |
| --- | --- |
| **High** | Critical — immediate action required |
| **Medium** | Important — should be addressed |
| **Low** | Minor — best practice optimization |
| **Informational** | Advisory — no action required |

| Status | Meaning |
| --- | --- |
| **Failed** | Security issue identified |
| **Passed** | Resource meets best practice |
| **N/A** | No resources to assess or service not available in region |

---

### How finding severities are determined

FinServ (`FS-`) check severities are assigned by a documented, reproducible methodology rather than per-check intuition. Each control is scored on two axes — **Impact** (harm if the control is absent) and **Likelihood** (probability the adverse outcome occurs given the control is absent) — and the pair is mapped to a severity via a 3×3 matrix. The labels align with the **AWS Security Hub ASFF** severity scale, so findings can be forwarded to Security Hub with consistent severities:

| Label | ASFF normalized | Meaning |
| --- | --- | --- |
| Informational | 0 | No actionable issue (control not applicable, advisory/manual-review, or could-not-assess context) |
| Low | 1–39 | Does not require action on its own; compensating controls exist |
| Medium | 40–69 | Should be addressed, but not urgently |
| High | 70–89 | Should be addressed as a priority |

Severity is a property of the **control** (its inherent risk), so a check's `Passed` and `Failed` rows carry the same severity. The `N/A` family is fixed by disposition: *not-applicable* and *advisory* findings are **Informational**; *could-not-assess* (access-denied / unsupported region) findings are **Low**. `Critical` is reserved and not currently emitted.

For the full methodology (matrix, factor definitions, disposition rules) and the authoritative per-finding assignments, see [FinServ Severity Methodology](docs/SECURITY_CHECKS_FINSERV_SEVERITY_METHODOLOGY.md) and the [FinServ Severity Register](docs/SECURITY_CHECKS_FINSERV_SEVERITY_REGISTER.md). Mappings are preliminary — validate with your MRM/Legal/Compliance teams before relying on them as audit evidence.

## Customization

| Task | How |
| --- | --- |
| Add new accounts | Add to StackSet deployment targets |
| Modify permissions scope | Edit `1-aiml-security-member-roles.yaml` |
| Adjust concurrency | Change `ConcurrentAccountScans` parameter |
| Add new service checks | See [Developer Guide](docs/DEVELOPER_GUIDE.md#adding-new-aiml-service-assessments) |

---

## Permissions Required

The deployment uses multiple IAM roles with different trust and permission boundaries. They are not all read-only.

- **`CodeBuildRole` / `MultiAccountCodeBuildRole`**: orchestration roles used by the infrastructure stack to clone the repo, build SAM, deploy/update the assessment stack, and start Step Functions executions. These roles require infrastructure-management permissions such as CloudFormation, Lambda, IAM, Step Functions, and S3 actions.
- **`AIMLSecurityMemberRole`**: role assumed in the target account during single-account and multi-account runs. In the multi-account flow this role is also **not read-only**. It needs both service-read permissions for the checks and deployment permissions so CodeBuild can create or update the per-account SAM assessment stack.
- **SAM-created Lambda execution roles**: runtime roles for the assessment functions. These are the closest thing to read-only assessment roles. They primarily use `List*`, `Describe*`, and `Get*` access against Bedrock, SageMaker, AgentCore, IAM analysis APIs, and supporting read APIs, plus S3 access to write reports and read the cached IAM permissions file.

If you need to reduce scope, review the role policies in:

- [deployment/aiml-security-single-account.yaml](deployment/aiml-security-single-account.yaml)
- [deployment/1-aiml-security-member-roles.yaml](deployment/1-aiml-security-member-roles.yaml)
- [deployment/2-aiml-security-codebuild.yaml](deployment/2-aiml-security-codebuild.yaml)
- [aiml-security-assessment/template.yaml](aiml-security-assessment/template.yaml)
- [aiml-security-assessment/template-multi-account.yaml](aiml-security-assessment/template-multi-account.yaml)

---

## Documentation

| Document | Description |
| --- | --- |
| [Security Checks Reference](docs/SECURITY_CHECKS.md) | Complete reference for all 174 security checks with severity levels |
| [OWASP Top 10 for LLM Checks](docs/SECURITY_CHECKS_OWASP.md) | Complete OW-01..12 reference: mapping-derived OWASP LLM01..LLM10 rows, native LLM07 checks, source dependencies, references, and status semantics |
| [FinServ GenAI Risk Checks](docs/SECURITY_CHECKS_FINSERV.md) | Complete FS-01..69 reference: shared introduction, severity rubric, upstream-overlap table, compliance framework mapping, and all check definitions (Part 1 infrastructure controls, Part 2 guardrails & content safety, Part 3 app-layer controls & gaps) |
| [FinServ Severity Methodology](docs/SECURITY_CHECKS_FINSERV_SEVERITY_METHODOLOGY.md) | Likelihood × Impact → ASFF severity model, disposition rules, and research basis for FS check severities |
| [FinServ Severity Register](docs/SECURITY_CHECKS_FINSERV_SEVERITY_REGISTER.md) | Authoritative per-finding severity assignments (the single source of truth enforced by the drift-guard test) |
| [FinServ Compliance Mappings](docs/SECURITY_CHECKS_FINSERV.md#compliance-framework-mapping) | Preliminary mapping of FS checks to SR 11-7, FFIEC CAT, NYDFS 500, PCI-DSS, DORA, MAS TRM, ISO 27001, ECOA, and OWASP LLM Top 10 |
| [Troubleshooting Guide](docs/TROUBLESHOOTING.md) | Common issues, stack identification, upgrade guide, debugging |
| [Developer Guide](docs/DEVELOPER_GUIDE.md) | Architecture details, adding custom checks, and contributing |
| [Cleanup Guide](docs/CLEANUP.md) | Step-by-step resource removal instructions |

---

## CI/CD

GitHub Actions workflows run automatically on pull requests and selected pushes:

| Workflow | Trigger | What It Checks |
| --- | --- | --- |
| **Python Code Quality** | PR | `ruff check` and `ruff format --check` on changed Python files |
| **AI/ML Security Assessment Tests** | PR, push to `main`/`develop` | Runs the `pytest` suite (assessment functions and report pipeline) on Python 3.12 |
| **CloudFormation Lint** | PR | Validates deployment and SAM templates with `cfn-lint` |
| **SAM Validate & Build** | PR | `sam validate --lint` and `sam build` on SAM templates |
| **ASH Security Scan** | PR | Scans for secrets, dependency vulnerabilities, and IaC misconfigurations |
| **ASH Full Repository Scan** | Push to main, monthly | Full repository security scan |

---

## Contributing

We welcome community contributions! See the [Developer Guide](docs/DEVELOPER_GUIDE.md) for guidelines.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for reporting security issues.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
