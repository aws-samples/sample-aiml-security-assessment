# AI/ML Security Assessment Framework - Developer Guide

## Table of Contents

- [Architecture Overview](#architecture-overview)
  - [Architecture Diagrams](#architecture-diagrams)
  - [Two-Phase Architecture](#two-phase-architecture)
  - [Assessment Execution Workflow](#assessment-execution-workflow)
- [Assessment Structure](#assessment-structure)
  - [AWS Lambda Functions](#aws-lambda-functions)
- [Adding New AI/ML Service Assessments](#adding-new-aiml-service-assessments)
  - [Step 1: Create Service Assessment Function](#step-1-create-service-assessment-function)
  - [Step 2: Update AWS SAM Template](#step-2-update-aws-sam-template)
  - [Step 3: Update AWS Step Functions Definition](#step-3-update-aws-step-functions-definition)
  - [Step 4: Update AWS IAM Permissions](#step-4-update-aws-iam-permissions)
  - [Step 5: Test Locally](#step-5-test-locally)
- [Assessment Best Practices](#assessment-best-practices)
  - [1. Security Check Implementation](#1-security-check-implementation)
  - [2. Performance Optimization](#2-performance-optimization)
  - [3. Error Handling](#3-error-handling)
- [Testing Your Extensions](#testing-your-extensions)
  - [1. Local Testing](#1-local-testing)
  - [2. Integration Testing](#2-integration-testing)
  - [3. Multi-Account Testing](#3-multi-account-testing)
- [Monitoring and Debugging](#monitoring-and-debugging)
- [Development Roadmap](#development-roadmap)
  - [Current Status](#current-status)
  - [Potential Additions](#potential-additions)
  - [Development Pattern](#development-pattern)
- [Report Generation Architecture](#report-generation-architecture)
  - [Shared Template Module](#shared-template-module)
  - [How It Works](#how-it-works)
  - [Modifying the Report Template](#modifying-the-report-template)
- [Documentation and Screenshots](#documentation-and-screenshots)
  - [Updating Sample Reports](#updating-sample-reports)
  - [Documentation Best Practices](#documentation-best-practices)
- [CI/CD Workflows](#cicd-workflows)
  - [PR Checks](#pr-checks)
  - [Running Checks Locally](#running-checks-locally)
- [Support and Resources](#support-and-resources)
  - [Documentation](#documentation)

---

## Architecture Overview

The AI/ML Security Assessment Framework is a serverless, multi-account security assessment solution for AWS AI/ML workloads. It performs 52 security checks across Amazon Bedrock, Amazon SageMaker AI, and Amazon Bedrock AgentCore, generating interactive HTML reports with findings and remediation guidance.

### Security Design Principles

- All roles follow the principle of least privilege
- Cross-account trust is limited to the specific AWS CodeBuild role
- Amazon S3 bucket enforces SSL-only access
- Assessment data is encrypted in transit and at rest
- No persistent credentials are stored in AWS CodeBuild

## Architecture Diagrams

### Phase 1: Deployment Setup (AWS CloudFormation)
![Deployment Phase](./diagrams/deployment-phase.png)

### Phase 2: Assessment Execution (AWS CodeBuild)
![Execution Phase](./diagrams/execution-phase.png)

### Service-Level Assessment Architecture
![Service-Level Architecture](./diagrams/service-level-architecture.png)

## Two-Phase Architecture

### Phase 1: Infrastructure Deployment

#### Step 1: Member Account Roles (`1-aiml-security-member-roles.yaml`)
- **AWS CloudFormation StackSets Deployment**: Deploys `AIMLSecurityMemberRole` to all target accounts
- **Cross-Account Trust**: Establishes trust relationship with central management account
- **Assessment Permissions**: Grants read-only access to AI/ML services (Amazon Bedrock, Amazon SageMaker AI, Amazon Bedrock AgentCore) for security assessment

#### Step 2: Central Infrastructure (`2-aiml-security-codebuild.yaml`)
- **AWS CodeBuild Project**: Orchestrates multi-account deployments and assessments
- **Amazon S3 Bucket**: Central storage for consolidated assessment results
- **AWS IAM Role**: `MultiAccountCodeBuildRole` with cross-account access permissions
- **Amazon SNS Topic**: Optional email notifications for assessment completion
- **Amazon EventBridge Rules**: Automated workflow triggers
- **AWS Lambda Trigger**: Automatically starts AWS CodeBuild after stack creation

### Phase 2: Assessment Execution (AWS CodeBuild Orchestration)

#### AWS CodeBuild Execution Flow
1. **Account Discovery**: Lists active accounts from AWS Organizations
2. **Role Assumption**: Assumes `AIMLSecurityMemberRole` in each target account
3. **AWS SAM Deployment**: Deploys the AI/ML assessment stack through AWS SAM
4. **Assessment Execution**: Triggers AWS Step Functions workflow in each account
5. **Results Consolidation**: Collects and consolidates results from all accounts

#### Project Structure
```
sample-aiml-security-assessment/
├── aiml-security-assessment/
│   ├── functions/security/
│   │   ├── bedrock_assessments/      # Bedrock security checks (14)
│   │   ├── sagemaker_assessments/    # SageMaker security checks (25)
│   │   ├── agentcore_assessments/    # AgentCore security checks (13)
│   │   ├── iam_permission_caching/   # AWS IAM permissions cache
│   │   ├── cleanup_bucket/           # Amazon S3 cleanup
│   │   └── generate_consolidated_report/  # HTML/CSV report generation
│   ├── statemachine/                 # AWS Step Functions definition
│   ├── images/                       # SAM application images
│   ├── template.yaml                 # AWS SAM template (single-account)
│   ├── template-multi-account.yaml   # AWS SAM template (multi-account)
│   ├── samconfig.toml                # SAM deployment configuration
│   ├── envvars.json                  # Environment variables for local testing
│   └── testfile.json                 # Test event file for local invocation
├── deployment/                       # AWS CloudFormation templates
├── docs/                             # Documentation
│   ├── DEVELOPER_GUIDE.md            # This guide
│   ├── SECURITY_CHECKS.md            # Security checks reference
│   ├── TROUBLESHOOTING.md            # Troubleshooting guide
│   ├── diagrams/                     # Architecture diagrams
│   └── icons/                        # AWS service icons
├── sample-reports/                   # Sample assessment reports
│   ├── scripts/                      # Screenshot capture scripts
│   ├── *.html                        # Sample HTML reports
│   └── *.png                         # Report screenshots
├── buildspec.yml                     # AWS CodeBuild orchestration
├── buildspec-modular-example.yml     # Modular buildspec example
└── consolidate_html_reports.py       # Multi-account report consolidation
```

#### Member Account Resources (Deployed by AWS SAM)
- **AWS SAM Application**: AI/ML security assessment stack
- **AWS Step Functions**: Single workflow orchestrating all assessments
- **AWS Lambda Functions**: One per service (Amazon Bedrock, Amazon SageMaker AI, Amazon Bedrock AgentCore) plus utilities
- **Local Amazon S3 Bucket**: Storage for account-specific results

### Assessment Execution Workflow

#### AWS CodeBuild Orchestration
```bash
# buildspec.yml execution flow
1. Get active accounts from AWS Organizations
2. For each account:
   - Assume AIMLSecurityMemberRole
   - Deploy AI/ML assessment stack through AWS SAM
   - Start AWS Step Functions execution
3. Wait for completion and consolidate results
```

#### AWS Step Functions (Per Module)
```json
{
  "Comment": "AI/ML Assessment Module",
  "StartAt": "Cleanup Amazon S3 Bucket",
  "States": {
    "Cleanup Amazon S3 Bucket": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Next": "AWS IAM Permission Caching"
    },
    "AWS IAM Permission Caching": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Next": "Parallel Service Assessments"
    },
    "Parallel Service Assessments": {
      "Type": "Parallel",
      "Branches": [
        {"StartAt": "Amazon Bedrock Assessment", "States": {...}},
        {"StartAt": "Amazon SageMaker AI Assessment", "States": {...}},
        {"StartAt": "Amazon Bedrock AgentCore Assessment", "States": {...}}
      ],
      "Next": "Generate Consolidated Report"
    },
    "Generate Consolidated Report": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "End": true
    }
  }
}
```

## Assessment Structure

The framework includes **52 security checks** across three AI/ML services. For the complete list of checks with descriptions, see the [Security Checks Reference](SECURITY_CHECKS.md).

### AWS Lambda Functions

Each assessment AWS Lambda function:
1. Receives execution context from AWS Step Functions
2. Reads cached AWS IAM permissions from Amazon S3
3. Performs security checks against AWS APIs
4. Generates CSV report with findings
5. Uploads results to Amazon S3
6. Returns findings summary to AWS Step Functions

**Additional Functions:**
- **AWS IAM Permission Caching**: Pre-fetches AWS IAM policies to optimize assessment
- **Cleanup Bucket**: Removes old assessment data
- **Generate Consolidated Report**: Creates HTML report from CSV findings

## Adding New AI/ML Service Assessments

To add a new AI/ML service (for example, Amazon Comprehend, Amazon Textract):

### Step 1: Create Service Assessment Function

1. **Create Function Directory** (One function per service):
```bash
# Example: Adding Comprehend security assessment
mkdir -p aiml-security-assessment/functions/security/comprehend_assessments
cd aiml-security-assessment/functions/security/comprehend_assessments
```

2. **Create Function Files**:
```python
# app.py
import boto3
import json
from schema import create_finding


def lambda_handler(event, context):
    """Main assessment handler for new service"""
    all_findings = []

    # Get cached permissions
    execution_id = event["Execution"]["Name"]
    permission_cache = get_permissions_cache(execution_id)

    # Run assessment checks
    findings = check_new_service_security(permission_cache)
    all_findings.append(findings)

    # Generate and upload report
    csv_content = generate_csv_report(all_findings)
    bucket_name = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
    s3_url = write_to_s3(execution_id, csv_content, bucket_name)

    return {
        "statusCode": 200,
        "body": {
            "message": "New service assessment completed",
            "findings": all_findings,
            "report_url": s3_url,
        },
    }


def check_new_service_security(permission_cache):
    """Implement your security checks here"""
    findings = {
        "check_name": "New Service Security Check",
        "status": "PASS",
        "details": "",
        "csv_data": [],
    }

    # Your assessment logic here
    # Use permission_cache to check IAM permissions
    # Use AWS SDK to check service configurations

    return findings
```

3. **Create Requirements File**:
```txt
# requirements.txt
boto3>=1.26.0
botocore>=1.29.0
```

4. **Create Schema File**:
```python
# schema.py
from enum import Enum


class SeverityEnum(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"
    NA = "N/A"


class StatusEnum(str, Enum):
    FAILED = "Failed"
    PASSED = "Passed"
    NA = "N/A"


def create_finding(
    check_id, finding_name, finding_details, resolution, reference, severity, status
):
    """Create standardized finding format

    Args:
        check_id: Unique check identifier (for example, SM-01, BR-01, AC-01)
        finding_name: Name of the finding
        finding_details: Detailed description
        resolution: Steps to resolve (empty string for N/A status)
        reference: Documentation URL
        severity: SeverityEnum value
        status: StatusEnum value (Failed, Passed, or N/A)
    """
    return {
        "Check_ID": check_id,
        "Finding": finding_name,
        "Finding_Details": finding_details,
        "Resolution": resolution,
        "Reference": reference,
        "Severity": severity,
        "Status": status,
    }
```

### Step 2: Update AWS SAM Template

Add your new function to `aiml-security-assessment/template.yaml`:

```yaml
  ComprehendSecurityAssessmentFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: !Sub 'ComprehendSecurityAssessment-${AWS::AccountId}'
      CodeUri: functions/security/comprehend_assessments/
      Handler: app.lambda_handler
      Runtime: python3.12
      Timeout: 600
      MemorySize: 1024
      Environment:
        Variables:
          AIML_ASSESSMENT_BUCKET_NAME: !Ref AIMLAssessmentBucket
      Policies:
        - S3CrudPolicy:
            BucketName: !Ref AIMLAssessmentBucket
        - Statement:
            - Sid: ComprehendReadPermissions
              Effect: Allow
              Action:
                - comprehend:List*
                - comprehend:Describe*
                - comprehend:Get*
              Resource: '*'
```

### Step 3: Update AWS Step Functions Definition

Add new service to the parallel execution in `aiml-security-assessment/statemachine/assessments.asl.json`:

```json
{
  "Parallel Service Assessments": {
    "Type": "Parallel",
    "Branches": [
      {
        "StartAt": "Bedrock Security Assessment",
        "States": {"Bedrock Security Assessment": {"Type": "Task", "Resource": "arn:aws:states:::lambda:invoke", "End": true}}
      },
      {
        "StartAt": "SageMaker Security Assessment",
        "States": {"SageMaker Security Assessment": {"Type": "Task", "Resource": "arn:aws:states:::lambda:invoke", "End": true}}
      },
      {
        "StartAt": "AgentCore Security Assessment",
        "States": {"AgentCore Security Assessment": {"Type": "Task", "Resource": "arn:aws:states:::lambda:invoke", "End": true}}
      },
      {
        "StartAt": "Comprehend Security Assessment",
        "States": {"Comprehend Security Assessment": {"Type": "Task", "Resource": "arn:aws:states:::lambda:invoke", "End": true}}
      }
    ]
  }
}
```

### Step 4: Update AWS IAM Permissions

Add required permissions to member role template:

**In `deployment/1-aiml-security-member-roles.yaml`**:
```yaml
- Effect: Allow
  Action:
    - comprehend:List*
    - comprehend:Describe*
    - comprehend:Get*
  Resource: '*'
```

**In `deployment/aiml-security-single-account.yaml`** (for single account mode):
```yaml
- comprehend:List*
- comprehend:Describe*
- comprehend:Get*
```

### Step 5: Test Locally

Test your new assessment function locally:

```bash
cd aiml-security-assessment
sam build
sam local invoke ComprehendSecurityAssessmentFunction --event testfile.json
```

## Assessment Best Practices

### 1. Security Check Implementation
- **Use Cached Permissions**: Always use the AWS IAM permission cache to avoid API throttling
- **Handle Exceptions**: Implement proper error handling and logging
- **Follow Least Privilege**: Only request necessary permissions
- **Standardize Findings**: Use the `create_finding()` function for consistent output
- **Check ID Convention**: Use service prefixes for check IDs (BR-XX for Amazon Bedrock, SM-XX for Amazon SageMaker AI, AC-XX for Amazon Bedrock AgentCore)
- **Status Semantics**: Use correct status values:
  - `Passed`: Resources were checked and met the assessed best practice
  - `Failed`: Resources were checked and found non-compliant
  - `N/A`: No resources exist to check (for example, "No notebooks found", "No guardrails configured")
- **Severity Values**: Use appropriate severity levels:
  - `High`: Critical security issues requiring immediate attention
  - `Medium`: Important security improvements recommended
  - `Low`: Minor optimizations suggested
  - `Informational`: Advisory information, no action required
  - `N/A`: Check not applicable (typically paired with N/A status)

### 2. Performance Optimization
- **Batch API Calls**: Use pagination and batch operations where possible
- **Implement Retries**: Use exponential backoff for AWS API calls
- **Cache Results**: Store intermediate results to avoid redundant API calls
- **Set Appropriate Timeouts**: Configure AWS Lambda timeout based on assessment complexity

### 3. Error Handling
```python
try:
    # Assessment logic
    result = aws_client.describe_service()
except ClientError as e:
    if e.response["Error"]["Code"] == "AccessDenied":
        # Handle permission issues
        logger.warning(f"Access denied for service check: {str(e)}")
        return create_finding(
            finding_name="Permission Check",
            finding_details="Insufficient permissions to assess service",
            resolution="Grant required permissions to assessment role",
            reference="https://docs.aws.amazon.com/service/permissions",
            severity="High",
            status="Failed",
        )
    else:
        # Handle other AWS errors
        logger.error(f"AWS API error: {str(e)}")
        raise
except Exception as e:
    # Handle unexpected errors
    logger.error(f"Unexpected error: {str(e)}", exc_info=True)
    raise
```

## Testing Your Extensions

### 1. Local Testing
```bash
# Test individual function
cd aiml-security-assessment
sam build
sam local invoke NewServiceSecurityAssessmentFunction --event test-event.json
```

### 2. Integration Testing
```bash
# Deploy to test account
sam deploy --stack-name aiml-security-test --capabilities CAPABILITY_IAM

# Execute AWS Step Functions
aws stepfunctions start-execution \
  --state-machine-arn arn:aws:states:region:account:stateMachine:TestStateMachine \
  --input '{"accountId":"123456789012"}'
```

### 3. Multi-Account Testing
1. Deploy member roles to test accounts using AWS CloudFormation StackSets
2. Deploy central infrastructure with test parameters
3. Monitor AWS CodeBuild logs for deployment and execution status
4. Verify results in central Amazon S3 bucket

## Monitoring and Debugging

For detailed troubleshooting guidance, common issues, and debugging tips, see the [Troubleshooting Guide](TROUBLESHOOTING.md).

## Development Roadmap

### Current Status
- **AI/ML Assessment**: 52 security checks across three services (see [Security Checks Reference](SECURITY_CHECKS.md))

### Potential Additions
- **Amazon Comprehend**: Data privacy, access controls, entity recognition security
- **Amazon Textract**: Document processing security, PII detection
- **Amazon Rekognition**: Image analysis security, content moderation
- **Amazon Polly/Amazon Transcribe**: Voice AI security assessments

### Development Pattern
- Each AWS AI/ML service gets its own dedicated AWS Lambda function
- AWS Step Functions orchestrates parallel execution of service assessments
- Results are consolidated into a single HTML/CSV report
- AWS CodeBuild orchestrates deployment and execution across multiple accounts

## Report Generation Architecture

### Shared Template Module

Report generation uses a single shared template (`report_template.py`) for both deployment modes:

```
aiml-security-assessment/functions/security/generate_consolidated_report/
├── app.py              # Lambda handler (single-account)
├── report_template.py  # Shared HTML/CSS/JS template
└── ...

consolidate_html_reports.py  # CodeBuild script (multi-account)
```

### How It Works

| Component | Mode | Description |
|-----------|------|-------------|
| `app.py` (AWS Lambda) | `mode='single'` | Generates per-account HTML reports during AWS Step Functions execution |
| `consolidate_html_reports.py` | `mode='multi'` | Consolidates all account reports in AWS CodeBuild post-build phase |

Both call `generate_html_report()` from `report_template.py` with different parameters.

### Modifying the Report Template

To update report styling, layout, or features:

1. Edit `report_template.py` only - changes apply to both single and multi-account reports
2. Run tests: `python test_generate_report.py`
3. Key functions:
   - `get_html_template()` - HTML/CSS/JS structure
   - `generate_table_rows()` - Finding row generation
   - `generate_html_report()` - Main entry point with `mode` parameter ('single' or 'multi')

## Documentation and Screenshots

### Updating Sample Reports

When you modify the report template or add new features, update the sample reports and screenshots:

#### 1. Generate New Sample Reports

After making changes to `report_template.py`, regenerate sample reports:

```bash
# Single-account mode
python test_generate_report.py --mode single --output sample-reports/security_assessment_single_account.html

# Multi-account mode
python test_generate_report.py --mode multi --output sample-reports/security_assessment_multi_account.html
```

#### 2. Capture Screenshots

The repository includes an automated screenshot capture tool:

```bash
# Activate virtual environment
source .venv/bin/activate

# Install dependencies (first time only)
pip install -r sample-reports/dev-requirements.txt
playwright install chromium

# Capture and optimize screenshots
python sample-reports/scripts/capture_screenshots.py
```

**What the script does:**
- Opens HTML reports in a headless browser
- Captures key views (dashboard, findings table, dark mode)
- Automatically optimizes images (target: 200-300KB each)
- Converts large PNGs to JPEG if needed
- Saves screenshots in `sample-reports/` folder

**What gets generated:**

The script captures 4 screenshots:
- `dashboard-overview-light.png` - Executive dashboard in light mode
- `dashboard-overview-dark.png` - Executive dashboard in dark mode
- `findings-table.png` - Detailed findings table with filters
- `multi-account-summary.png` - Multi-account consolidated view

All screenshots are automatically optimized (target: 200-300KB each, ~600KB total).

**Customization:**

Edit `sample-reports/scripts/capture_screenshots.py` to customize:

```python
# Viewport size
VIEWPORT_WIDTH = 1440
VIEWPORT_HEIGHT = 900

# Image quality
JPEG_QUALITY = 85  # Range: 1-100
PNG_OPTIMIZE = True

# Add new screenshots to SCREENSHOTS list
SCREENSHOTS = [
    {
        "name": "my-screenshot",
        "file": "security_assessment_single_account.html",
        "description": "My Custom View",
        "actions": [
            {"type": "wait", "selector": ".element", "timeout": 2000},
            {"type": "click", "selector": ".button"},
            {"type": "scroll", "position": 500},
        ],
        "clip": {"x": 0, "y": 0, "width": 1440, "height": 800},
    }
]
```

**Available action types:**
- `wait` - Wait for selector (for example, `{"type": "wait", "selector": ".metrics", "timeout": 2000}`)
- `click` - Click element (for example, `{"type": "click", "selector": ".theme-toggle"}`)
- `scroll` - Scroll to position (for example, `{"type": "scroll", "position": 500}`)
- `wait_time` - Wait milliseconds (for example, `{"type": "wait_time", "ms": 300}`)

**Troubleshooting:**

| Issue | Solution |
|-------|----------|
| `playwright not installed` | `pip install playwright && playwright install chromium` |
| Sample reports not found | Run from repository root |
| Screenshots too large | Lower `JPEG_QUALITY` or reduce viewport size |
| Browser launch fails | Run `playwright install-deps` (Linux only) |

#### 3. Update README

After generating new screenshots, update the README to reference them:

```markdown
### Sample Assessment Reports

**Preview:**

![Executive Dashboard](sample-reports/dashboard-overview-light.png)
*Executive summary with severity counts and service breakdown*

![Findings Table](sample-reports/findings-table.png)
*Interactive findings table with filtering capabilities*
```

### Documentation Best Practices

- **Keep screenshots optimized**: Target 200-300KB per image
- **Use descriptive filenames**: `dashboard-overview-light.png`, not `screenshot1.png`
- **Update both HTML and screenshots** when making UI changes
- **Test screenshots render correctly** in GitHub's markdown preview
- **All screenshot tooling**: Located in `sample-reports/` for easy organization

## CI/CD Workflows

GitHub Actions workflows run automatically to validate code quality and security on every pull request.

### PR Checks

| Workflow | File | What It Checks |
|----------|------|----------------|
| **Python Code Quality** | `.github/workflows/python-lint.yml` | `ruff check` (lint) and `ruff format --check` (formatting) on changed `.py` files |
| **CloudFormation Lint** | `.github/workflows/cfn-lint.yml` | Validates deployment and SAM templates with `cfn-lint` |
| **SAM Validate & Build** | `.github/workflows/sam-validate.yml` | Runs `sam validate --lint` and `sam build` on SAM templates |
| **ASH Security Scan** | `.github/workflows/ash-security-scan.yml` | Scans changed files for secrets, dependency vulnerabilities, and IaC misconfigurations |

Additional workflows run post-merge or on schedule:

| Workflow | File | Trigger |
|----------|------|---------|
| **ASH Full Repository Scan** | `.github/workflows/ash-full-repository-scan.yml` | Push to main, monthly schedule, manual |
| **Labeler** | `.github/workflows/label.yml` | Auto-labels PRs by changed paths (bedrock, sagemaker, agentcore, deployment, docs) |

cfn-lint suppressions are configured in `.cfnlintrc` at the repository root for IAM actions not yet in cfn-lint's database (for example, `bedrock-agentcore` actions).

### Running Checks Locally

Before pushing, run these checks locally to catch issues early:

```bash
# Install tools (first time only)
pip install ruff cfn-lint pytest boto3 pydantic

# Python lint and format
ruff check aiml-security-assessment/functions/security/
ruff format --check aiml-security-assessment/functions/security/

# Unit tests (213 tests, ~5 seconds, no AWS credentials needed)
python -m pytest tests/ -v

# CloudFormation lint
cfn-lint deployment/*.yaml
cfn-lint aiml-security-assessment/template.yaml
cfn-lint aiml-security-assessment/template-multi-account.yaml

# SAM validate and build
cd aiml-security-assessment
sam validate --template template.yaml --lint
sam build --template template.yaml
```

## Support and Resources

### Documentation
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [AWS Security Best Practices](https://aws.amazon.com/security/security-resources/)
- [AWS SAM Developer Guide](https://docs.aws.amazon.com/serverless-application-model/)

---

This developer guide provides the foundation for extending the AI/ML Security Assessment Framework. As you add new AI/ML services and security checks, please update this documentation to help future contributors understand and build upon your work.