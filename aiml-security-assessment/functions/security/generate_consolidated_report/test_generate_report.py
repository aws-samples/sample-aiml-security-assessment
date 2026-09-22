import unittest
import copy
import os
import sys
import importlib.util
from unittest import mock


_THIS_DIR = os.path.dirname(__file__)
_SAVED_SYS_PATH = list(sys.path)
_SAVED_REPORT_TEMPLATE = sys.modules.get("report_template")

try:
    if _THIS_DIR not in sys.path:
        sys.path.insert(0, _THIS_DIR)

    _template_spec = importlib.util.spec_from_file_location(
        "generate_report_template", os.path.join(_THIS_DIR, "report_template.py")
    )
    generate_report_template = importlib.util.module_from_spec(_template_spec)
    sys.modules["report_template"] = generate_report_template
    _template_spec.loader.exec_module(generate_report_template)

    _app_spec = importlib.util.spec_from_file_location(
        "generate_consolidated_report_app", os.path.join(_THIS_DIR, "app.py")
    )
    generate_report_app = importlib.util.module_from_spec(_app_spec)
    sys.modules["generate_consolidated_report_app"] = generate_report_app
    _app_spec.loader.exec_module(generate_report_app)
finally:
    sys.path[:] = _SAVED_SYS_PATH
    if _SAVED_REPORT_TEMPLATE is None:
        sys.modules.pop("report_template", None)
    else:
        sys.modules["report_template"] = _SAVED_REPORT_TEMPLATE


generate_html_report = generate_report_app.generate_html_report
generate_report_direct = generate_report_template.generate_html_report


class TestHtmlReportGeneration(unittest.TestCase):
    def setUp(self):
        self.test_dir = "test_reports"
        if not os.path.exists(self.test_dir):
            os.makedirs(self.test_dir)

        self.test_assessment_results = {
            "account_id": "123456789012",
            "timestamp": "2026-04-17 10:00:00 UTC",
            "bedrock": {
                "bedrock_security_report": [
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "BR-01",
                        "Finding": "Bedrock Model Access Control",
                        "Finding_Details": "The Bedrock model access is not restricted to specific IAM principals. This could allow unauthorized access to model endpoints.",
                        "Resolution": "Implement IAM policies to restrict access to specific principals and use resource-based policies for model invocations.",
                        "Reference": "https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples.html",
                        "Severity": "High",
                        "Status": "Failed",
                    },
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "BR-04",
                        "Finding": "Bedrock API Logging",
                        "Finding_Details": "CloudTrail logging is not enabled for Bedrock API calls. This limits audit capabilities and incident investigation.",
                        "Resolution": "Enable CloudTrail logging for Bedrock API actions and configure log retention policies.",
                        "Reference": "https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html",
                        "Severity": "Medium",
                        "Status": "Failed",
                    },
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "BR-05",
                        "Finding": "Bedrock Guardrails Check",
                        "Finding_Details": "Guardrails are properly configured for content filtering.",
                        "Resolution": "No action required",
                        "Reference": "https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html",
                        "Severity": "Informational",
                        "Status": "Passed",
                    },
                ]
            },
            "sagemaker": {
                "sagemaker_security_report": [
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "SM-01",
                        "Finding": "SageMaker Endpoint Encryption",
                        "Finding_Details": "SageMaker endpoint is not using encryption at rest. Sensitive data could be exposed if storage is compromised.",
                        "Resolution": "Enable AWS KMS encryption for SageMaker endpoints using customer managed keys.",
                        "Reference": "https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest.html",
                        "Severity": "High",
                        "Status": "Failed",
                    },
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "SM-02",
                        "Finding": "SageMaker Network Isolation",
                        "Finding_Details": "SageMaker training jobs are not configured with network isolation. This could expose the training environment to external networks.",
                        "Resolution": "Enable network isolation for SageMaker training jobs and use VPC configurations.",
                        "Reference": "https://docs.aws.amazon.com/sagemaker/latest/dg/mkt-algo-model-internet-free.html",
                        "Severity": "Medium",
                        "Status": "Failed",
                    },
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "SM-03",
                        "Finding": "SageMaker IAM Role Permissions",
                        "Finding_Details": "SageMaker execution role has overly permissive IAM policies. This violates the principle of least privilege.",
                        "Resolution": "Review and restrict IAM role permissions to only necessary actions and resources.",
                        "Reference": "https://docs.aws.amazon.com/sagemaker/latest/dg/security_iam_id-based-policy-examples.html",
                        "Severity": "High",
                        "Status": "Failed",
                    },
                ]
            },
            "agentcore": {
                "agentcore_security_report": [
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "AC-01",
                        "Finding": "AgentCore IAM Identity Center Check",
                        "Finding_Details": "AWS IAM Identity Center is properly configured.",
                        "Resolution": "No action required",
                        "Reference": "https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html",
                        "Severity": "Informational",
                        "Status": "Passed",
                    },
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "AR-03",
                        "Finding": "Agent Registry Publication Approval Governance",
                        "Finding_Details": "Registry 'production-agents' (reg-a1b2c3) automatically approves submitted records.",
                        "Resolution": "Remove auto-approval rules so submitted records require manual review.",
                        "Reference": "https://docs.aws.amazon.com/agent-registry-control/latest/APIReference/API_ApprovalConfiguration.html",
                        "Severity": "Medium",
                        "Status": "Failed",
                    },
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "AR-04",
                        "Finding": "Agent Registry Discovery Authorization",
                        "Finding_Details": "Registry 'production-agents' (reg-a1b2c3) uses a custom JWT authorizer without a caller constraint.",
                        "Resolution": "Configure at least one allowed audience, client, scope, or custom claim.",
                        "Reference": "https://docs.aws.amazon.com/agent-registry-control/latest/APIReference/API_CustomJWTAuthorizerConfiguration.html",
                        "Severity": "High",
                        "Status": "Failed",
                    },
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "AR-05",
                        "Finding": "Agent Registry Customer-Managed KMS Encryption",
                        "Finding_Details": "Registry 'production-agents' uses the default AWS owned key.",
                        "Resolution": "Create a replacement registry with a customer-managed KMS key.",
                        "Reference": "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/registry-data-encryption.html",
                        "Severity": "Medium",
                        "Status": "Failed",
                    },
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "AR-06",
                        "Finding": "Agent Registry Organization Auto-Detection",
                        "Finding_Details": "Registry 'production-agents' has active organization-scoped auto-detection.",
                        "Resolution": "No action required",
                        "Reference": "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/registry-organizations.html",
                        "Severity": "Medium",
                        "Status": "Passed",
                    },
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "AR-07",
                        "Finding": "Agent Registry Record Lifecycle Governance",
                        "Finding_Details": "Registry record 'payment-agent' is in the governed APPROVED lifecycle state.",
                        "Resolution": "No action required",
                        "Reference": "https://docs.aws.amazon.com/agent-registry-control/latest/APIReference/API_SubmitRegistryRecordForApproval.html",
                        "Severity": "Medium",
                        "Status": "Passed",
                    },
                    {
                        "Account_ID": "123456789012",
                        "Check_ID": "AR-08",
                        "Finding": "Agent Registry Record Provenance",
                        "Finding_Details": "Auto-detected registry record 'payment-agent' does not include valid DETECTED_FROM provenance.",
                        "Resolution": "Refresh or recreate the auto-detected record.",
                        "Reference": "https://docs.aws.amazon.com/agent-registry-control/latest/APIReference/API_Provenance.html",
                        "Severity": "Medium",
                        "Status": "Failed",
                    },
                ]
            },
        }

    def test_generate_viewable_report(self):
        """Generate a viewable HTML report with test data"""
        report_data = copy.deepcopy(self.test_assessment_results)
        report_data["agentcore"]["agentcore_security_report"].extend(
            [
                {
                    "Account_ID": "123456789012",
                    "Check_ID": "AG-33",
                    "Finding": "Agentic AI Registry Publication Approval Governance",
                    "Finding_Details": "Registry publication does not require manual approval.",
                    "Resolution": "Require manual review for registry publication.",
                    "Reference": "https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html",
                    "Severity": "Medium",
                    "Status": "Failed",
                },
                {
                    "Account_ID": "123456789012",
                    "Check_ID": "AG-34",
                    "Finding": "Agentic AI Registry Discovery Authorization",
                    "Finding_Details": "Registry discovery authorization is not constrained to intended callers.",
                    "Resolution": "Constrain registry discovery authorization.",
                    "Reference": "https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html",
                    "Severity": "High",
                    "Status": "Failed",
                },
                {
                    "Account_ID": "123456789012",
                    "Check_ID": "AG-35",
                    "Finding": "Agentic AI Registry Metadata Encryption",
                    "Finding_Details": "Registry metadata uses the default AWS owned key.",
                    "Resolution": "Create the registry with a customer-managed KMS key.",
                    "Reference": "https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html",
                    "Severity": "Medium",
                    "Status": "Failed",
                },
                {
                    "Account_ID": "123456789012",
                    "Check_ID": "AG-36",
                    "Finding": "Agentic AI Organization Discovery Coverage",
                    "Finding_Details": "Organization-scoped registry auto-detection is active.",
                    "Resolution": "No action required",
                    "Reference": "https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html",
                    "Severity": "Medium",
                    "Status": "Passed",
                },
                {
                    "Account_ID": "123456789012",
                    "Check_ID": "AG-37",
                    "Finding": "Agentic AI Registry Record Lifecycle Governance",
                    "Finding_Details": "The registry record is in the governed APPROVED state.",
                    "Resolution": "No action required",
                    "Reference": "https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html",
                    "Severity": "Medium",
                    "Status": "Passed",
                },
                {
                    "Account_ID": "123456789012",
                    "Check_ID": "AG-38",
                    "Finding": "Agentic AI Registry Record Provenance",
                    "Finding_Details": "The auto-detected record is missing source lineage.",
                    "Resolution": "Restore runtime or gateway provenance.",
                    "Reference": "https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html",
                    "Severity": "Medium",
                    "Status": "Failed",
                },
            ]
        )
        html_content = generate_html_report(report_data)

        # Save the HTML content to a file
        report_path = os.path.join(self.test_dir, "security_report.html")
        with open(report_path, "w") as f:
            f.write(html_content)

        print(f"\nReport generated at: {os.path.abspath(report_path)}")

        # Optionally open the report in the default browser
        # webbrowser.open('file://' + os.path.abspath(report_path))

        # Verify file exists and has content
        self.assertTrue(os.path.exists(report_path))
        self.assertTrue(os.path.getsize(report_path) > 0)

        # Basic content checks
        with open(report_path, "r") as f:
            content = f.read()
            # Bedrock findings
            self.assertIn("Bedrock Model Access Control", content)
            self.assertIn("Bedrock API Logging", content)

            # SageMaker findings
            self.assertIn("SageMaker Endpoint Encryption", content)
            self.assertIn("SageMaker Network Isolation", content)
            self.assertIn("SageMaker IAM Role Permissions", content)

            # AgentCore findings
            self.assertIn("AgentCore IAM Identity Center Check", content)
            self.assertIn("Agent Registry Publication Approval Governance", content)
            self.assertIn("Agent Registry Discovery Authorization", content)
            # The summary tile and scope chip both carry a service icon, so the
            # label is preceded by an icon span rather than opening the element.
            self.assertIn(
                '<div class="metric-label">'
                f"{generate_report_template.AGENT_REGISTRY_ICON_SMALL} "
                "AWS Agent Registry</div>",
                content,
            )
            self.assertIn(
                f"{generate_report_template.AGENT_REGISTRY_ICON_SCOPE}"
                '<span style="font-size: 13px; font-weight: 500;">'
                "AWS Agent Registry</span>",
                content,
            )
            self.assertIn(
                "Agentic AI Registry Publication Approval Governance", content
            )
            self.assertIn("Agentic AI Registry Discovery Authorization", content)

            # Severity levels
            self.assertIn("High", content)
            self.assertIn("Medium", content)

            # New design elements
            self.assertIn("sidebar", content)
            self.assertIn("service-icon", content)
            self.assertIn("theme-toggle", content)
            self.assertIn("Assessment Area", content)
            self.assertIn("All Assessment Areas", content)

            # Verify new features from consolidation
            self.assertIn("Methodology", content)
            self.assertIn("Severity Legend", content)
            self.assertIn("sortable", content)
            self.assertIn("Direct failed service rows", content)
            self.assertIn("Lens / Compliance Rows", content)
            self.assertIn('<option value="failed" selected>Failed</option>', content)
            self.assertIn('class="single-account-report"', content)
            self.assertIn(
                ".main { padding: 32px 40px; max-width: 1400px; min-width: 0; }",
                content,
            )
            self.assertIn(
                ".metrics, .assessment-summary-grid { grid-template-columns: 1fr; }",
                content,
            )
            self.assertIn("Details and remediation", content)
            self.assertLess(content.index('id="risk"'), content.index('id="findings"'))
            self.assertIn(
                "const status = this.hasAttribute('data-filter-status')",
                content,
            )
            self.assertNotIn("this.dataset.filterStatus || 'failed'", content)

    def test_generate_multi_account_report(self):
        """Test multi-account report generation using shared template directly"""
        # Create test data in multi-account format
        all_findings = [
            {
                "account_id": "111122223333",
                "check_id": "BR-01",
                "finding": "Test Finding 1",
                "details": "Details 1",
                "resolution": "Fix it",
                "reference": "https://example.com",
                "severity": "High",
                "status": "Failed",
                "_service": "bedrock",
            },
            {
                "account_id": "444455556666",
                "check_id": "SM-01",
                "finding": "Test Finding 2",
                "details": "Details 2",
                "resolution": "Fix it",
                "reference": "https://example.com",
                "severity": "Medium",
                "status": "Failed",
                "_service": "sagemaker",
            },
            {
                "account_id": "111122223333",
                "check_id": "AC-01",
                "finding": "Test Finding 3",
                "details": "Details 3",
                "resolution": "N/A",
                "reference": "https://example.com",
                "severity": "Low",
                "status": "Passed",
                "_service": "agentcore",
            },
            {
                "account_id": "111122223333",
                "check_id": "AR-03",
                "finding": "Agent Registry Publication Approval Governance",
                "details": "Registry 'shared-agents' automatically approves submitted records.",
                "resolution": "Require manual review.",
                "reference": "https://example.com",
                "severity": "Medium",
                "status": "Failed",
                "_service": "agentcore",
            },
            {
                "account_id": "111122223333",
                "check_id": "AG-34",
                "finding": "Agentic AI Registry Discovery Authorization",
                "details": "Registry discovery JWT authorization is not constrained.",
                "resolution": "Constrain intended callers.",
                "reference": "https://example.com",
                "severity": "High",
                "status": "Failed",
                "_service": "agentic",
            },
            {
                "account_id": "444455556666",
                "check_id": "FS-01",
                "finding": "Responsible AI GRC Regional Scope Not Applicable",
                "details": "No regional AI/ML resources found.",
                "resolution": "No action required.",
                "reference": "https://example.com",
                "severity": "Informational",
                "status": "N/A",
                "_service": "responsible-ai-grc",
            },
        ]
        service_findings = {
            "bedrock": [all_findings[0]],
            "sagemaker": [all_findings[1]],
            "agentcore": [all_findings[2], all_findings[3]],
            "agentic": [all_findings[4]],
            "responsible-ai-grc": [all_findings[5]],
        }
        service_stats = {
            "bedrock": {"passed": 0, "failed": 1},
            "sagemaker": {"passed": 0, "failed": 1},
            "agentcore": {"passed": 1, "failed": 1},
            "agentic": {"passed": 0, "failed": 1},
            "responsible-ai-grc": {"passed": 0, "failed": 0, "na": 1},
        }

        html_content = generate_report_direct(
            all_findings=all_findings,
            service_findings=service_findings,
            service_stats=service_stats,
            mode="multi",
            account_ids=["111122223333", "444455556666"],
        )

        report_path = os.path.join(self.test_dir, "multi_account_report.html")
        with open(report_path, "w") as f:
            f.write(html_content)

        print(f"\nMulti-account report generated at: {os.path.abspath(report_path)}")

        self.assertTrue(os.path.exists(report_path))
        self.assertIn("Agent Registry Publication Approval Governance", html_content)
        self.assertIn("Agentic AI Registry Discovery Authorization", html_content)

        with open(report_path, "r") as f:
            content = f.read()
            # Multi-account specific
            self.assertIn("Multi-Account", content)
            self.assertIn("2 Accounts", content)
            self.assertIn("accountFilter", content)
            self.assertIn("111122223333", content)
            self.assertIn("444455556666", content)
            self.assertIn("<h3>By Governance Framework</h3>", content)
            self.assertIn("<h3>By Lens</h3>", content)
            self.assertIn("Agentic AI Security", content)
            # governance-* CSS class names accompany the "By Governance
            # Framework" heading (renamed from industry-*/"By Industry").
            self.assertIn('class="nav-section governance-nav"', content)
            self.assertIn("Responsible AI GRC", content)
            self.assertIn('class="scope-governance"', content)
            by_service_nav = content.split("<h3>By Service</h3>", 1)[1].split(
                "<h3>By Governance Framework</h3>", 1
            )[0]
            self.assertNotIn("Responsible AI GRC", by_service_nav)
            self.assertNotIn("Financial Services", content)

    def test_missing_data_fields(self):
        """Test handling of assessment results with missing fields"""
        incomplete_data = {
            "account_id": "123456789012",
            "bedrock": {
                "bedrock_report": [
                    {"Finding": "Incomplete Bedrock Finding", "Severity": "High"}
                ]
            },
            "sagemaker": {},
            "agentcore": {},
        }

        html_content = generate_html_report(incomplete_data)

        # Save the HTML content to a file
        report_path = os.path.join(self.test_dir, "incomplete_report.html")
        with open(report_path, "w") as f:
            f.write(html_content)

        print(f"\nIncomplete data report generated at: {os.path.abspath(report_path)}")

        # Verify file exists and has content
        self.assertTrue(os.path.exists(report_path))
        self.assertTrue(os.path.getsize(report_path) > 0)

    def test_empty_findings(self):
        """Test handling of empty findings"""
        empty_data = {
            "account_id": "123456789012",
            "bedrock": {},
            "sagemaker": {},
            "agentcore": {},
        }

        html_content = generate_html_report(empty_data)
        report_path = os.path.join(self.test_dir, "empty_report.html")
        with open(report_path, "w") as f:
            f.write(html_content)

        print(f"\nEmpty data report generated at: {os.path.abspath(report_path)}")
        self.assertTrue(os.path.exists(report_path))

    def test_finserv_renders_when_present(self):
        """REQ-1: Responsible AI GRC findings render as a first-class service
        in the HTML."""
        data = dict(self.test_assessment_results)
        data["responsible-ai-grc"] = {
            "responsible_ai_grc_security_report": [
                {
                    "Account_ID": "123456789012",
                    "Check_ID": "FS-01",
                    "Finding": "No Regional WAF Web ACLs Found",
                    "Finding_Details": "No WAF.",
                    "Resolution": "Add WAF.",
                    "Reference": "https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html",
                    "Severity": "Medium",
                    "Status": "Failed",
                    "Region": "region-a",
                },
                {
                    "Account_ID": "123456789012",
                    "Check_ID": "FS-44",
                    "Finding": "Amazon Macie Enabled",
                    "Finding_Details": "Macie on.",
                    "Resolution": "None.",
                    "Reference": "https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html",
                    "Severity": "High",
                    "Status": "Passed",
                    "Region": "region-b",
                },
            ]
        }
        html = generate_html_report(data)
        self.assertIn('id="responsible-ai-grc"', html)
        self.assertIn('id="findingsTable"', html)
        self.assertNotIn('id="finservTable"', html)
        self.assertIn('<option value="responsible-ai-grc">', html)
        self.assertIn("FS-01", html)
        self.assertIn('data-service="responsible-ai-grc"', html)
        self.assertIn('data-filter-service="responsible-ai-grc"', html)
        self.assertIn("View failed findings", html)
        self.assertIn('data-scope-service="responsible-ai-grc"', html)
        self.assertIn('class="scope-governance"', html)
        self.assertIn('class="scope-chip governance-chip"', html)
        self.assertIn('class="nav-section governance-nav"', html)
        self.assertIn("Responsible AI GRC", html)
        self.assertIn("Assessment Area", html)
        self.assertIn("All Assessment Areas", html)
        self.assertIn(
            "wellarchitected/latest/generative-ai-lens/generative-ai-lens.html", html
        )
        self.assertIn(
            "introducing-the-updated-aws-user-guide-to-governance-risk-and-compliance-for-responsible-ai-adoption",
            html,
        )
        self.assertNotIn("global-FinServ-ComplianceGuide-GenAIRisks-public.pdf", html)
        self.assertIn("<h3>By Governance Framework</h3>", html)
        by_service_nav = html.split("<h3>By Service</h3>", 1)[1].split(
            "<h3>By Governance Framework</h3>", 1
        )[0]
        self.assertNotIn("Responsible AI GRC", by_service_nav)
        # The rebrand retires every "Financial Services" capability label,
        # and every legacy "finserv"/industry-* machine identity.
        self.assertNotIn("Financial Services Risk", html)
        self.assertNotIn("Financial Services GenAI Risk", html)
        self.assertNotIn('id="finserv"', html)
        self.assertNotIn('data-service="finserv"', html)
        self.assertNotIn("industry-nav", html)
        self.assertNotIn("scope-industry", html)
        # Required non-Lens disambiguation must accompany the name.
        self.assertIn("is not the", html)
        self.assertIn("Responsible AI Lens", html)
        self.assertIn("eight focus areas", html)

    def test_finserv_omitted_when_absent(self):
        """REQ-1/REQ-7: with no Responsible AI GRC data the section is
        omitted cleanly."""
        html = generate_html_report(self.test_assessment_results)
        self.assertNotIn('id="responsible-ai-grc"', html)
        self.assertNotIn("<h3>By Governance Framework</h3>", html)
        self.assertNotIn('<option value="responsible-ai-grc">', html)
        self.assertNotIn('data-scope-service="responsible-ai-grc"', html)
        self.assertNotIn('class="scope-governance"', html)
        self.assertNotIn("Responsible AI GRC", html)
        self.assertIn(
            "wellarchitected/latest/generative-ai-lens/generative-ai-lens.html", html
        )
        self.assertNotIn(
            "introducing-the-updated-aws-user-guide-to-governance-risk-and-compliance-for-responsible-ai-adoption",
            html,
        )
        self.assertNotIn("global-FinServ-ComplianceGuide-GenAIRisks-public.pdf", html)
        # Other services still render (regression check).
        self.assertIn('id="bedrock"', html)

    def test_agentic_security_renders_when_present(self):
        """Agentic AI Security AG-* rows render as a first-class assessment area."""
        data = dict(self.test_assessment_results)
        data["bedrock"] = {
            "bedrock_security_report": [
                {
                    "Account_ID": "123456789012",
                    "Check_ID": "BR-28",
                    "Finding": "Bedrock Agent Guardrail Association",
                    "Finding_Details": "Agent has a guardrail.",
                    "Resolution": "No action required.",
                    "Reference": "https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-use.html",
                    "Severity": "High",
                    "Status": "Passed",
                    "Region": "us-east-1",
                },
                {
                    "Account_ID": "123456789012",
                    "Check_ID": "AG-01",
                    "Finding": "Agentic AI Agent Guardrail Association",
                    "Finding_Details": "Agentic AI security domain: Guardrail Enforcement.",
                    "Resolution": "Associate an approved Bedrock guardrail with each Bedrock agent.",
                    "Reference": "https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html",
                    "Severity": "High",
                    "Status": "Passed",
                    "Region": "us-east-1",
                },
            ]
        }

        html = generate_html_report(data)

        self.assertIn('id="agentic"', html)
        self.assertIn('id="findingsTable"', html)
        self.assertNotIn('id="agenticTable"', html)
        self.assertIn('<option value="agentic">Agentic AI Security</option>', html)
        self.assertIn("<h3>By Lens</h3>", html)
        self.assertIn('class="nav-section lens-nav"', html)
        self.assertIn("AG-01", html)
        self.assertIn('data-service="agentic"', html)
        self.assertIn('data-filter-service="agentic"', html)
        self.assertIn("Agentic AI Security Findings", html)
        self.assertIn(
            "wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html", html
        )
        # The Agentic AI Lens hyperlink in the methodology must appear exactly
        # once even when agentic findings are present (no duplicate link).
        self.assertEqual(
            html.count('target="_blank">AWS Well-Architected Agentic AI Lens</a>'),
            1,
        )
        self.assertIn("Human-in-the-loop governance", html)
        by_service_nav = html.split("<h3>By Service</h3>", 1)[1].split(
            "<h3>By Lens</h3>", 1
        )[0]
        self.assertNotIn("Agentic AI Security", by_service_nav)
        by_lens_nav = html.split("<h3>By Lens</h3>", 1)[1].split("</nav>", 1)[0]
        self.assertIn("Agentic AI Security", by_lens_nav)

    def test_agentic_security_omitted_when_absent(self):
        """With no AG-* data the Agentic section is omitted cleanly."""
        html = generate_html_report(self.test_assessment_results)

        self.assertNotIn('id="agentic"', html)
        self.assertNotIn('id="agenticTable"', html)
        self.assertNotIn('<option value="agentic">Agentic AI Security</option>', html)
        self.assertNotIn("<h3>By Lens</h3>", html)
        self.assertNotIn('class="nav-section lens-nav"', html)
        self.assertNotIn(
            "wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html", html
        )

    def test_region_risk_includes_global_scope_card(self):
        """Global failed findings render in risk by region / scope without inflating regions."""
        all_findings = [
            {
                "account_id": "123456789012",
                "check_id": "BR-01",
                "finding": "Regional Bedrock Check",
                "details": "No regional issue.",
                "resolution": "No action required.",
                "reference": "https://example.com",
                "severity": "High",
                "status": "Passed",
                "region": "us-east-1",
                "_service": "bedrock",
            },
            {
                "account_id": "123456789012",
                "check_id": "BR-03",
                "finding": "Marketplace Subscription Access Check",
                "details": "Overly permissive marketplace subscription access.",
                "resolution": "Restrict subscription access.",
                "reference": "https://example.com",
                "severity": "High",
                "status": "Failed",
                "region": "Global",
                "_service": "bedrock",
            },
            {
                "account_id": "123456789012",
                "check_id": "AC-09",
                "finding": "AgentCore Service-Linked Role Missing",
                "details": "Service-linked role is missing.",
                "resolution": "Allow service-linked role creation.",
                "reference": "https://example.com",
                "severity": "Medium",
                "status": "Failed",
                "region": "Global",
                "_service": "agentcore",
            },
        ]

        html = generate_report_direct(
            all_findings=all_findings,
            service_findings={
                "bedrock": all_findings[:2],
                "agentcore": [all_findings[2]],
            },
            service_stats={
                "bedrock": {"passed": 1, "failed": 1, "na": 0},
                "agentcore": {"passed": 0, "failed": 1, "na": 0},
            },
            mode="single",
            account_id="123456789012",
            regions=["eu-west-1", "us-east-1", "us-west-2"],
        )

        self.assertIn("Direct Failed Rows by Region / Scope", html)
        self.assertIn('>eu-west-1</div><div class="metric-value">0</div>', html)
        self.assertIn('>us-east-1</div><div class="metric-value">0</div>', html)
        self.assertIn('>us-west-2</div><div class="metric-value">0</div>', html)
        self.assertIn('>Global</div><div class="metric-value">2</div>', html)
        self.assertIn(
            '<span style="color: var(--danger);">1 High</span> · '
            '<span style="color: var(--warning);">1 Med</span> · '
            '<span style="color: var(--accent);">0 Low</span>',
            html,
        )

    def test_unique_control_scoring_does_not_weight_resource_rows(self):
        """Repeated resource passes count once while any control failure remains."""
        failed_control = {
            "account_id": "123456789012",
            "check_id": "BR-01",
            "finding": "Bedrock Access Control",
            "details": "One direct control failed.",
            "resolution": "Restrict access.",
            "reference": "https://example.com",
            "severity": "High",
            "status": "Failed",
            "region": "us-east-1",
            "_service": "bedrock",
        }
        record_passes = [
            {
                "account_id": "123456789012",
                "check_id": "AR-08",
                "finding": "Agent Registry Record Provenance",
                "details": f"Record {record_index} has valid provenance.",
                "resolution": "No action required.",
                "reference": "https://example.com",
                "severity": "Medium",
                "status": "Passed",
                "region": "us-east-1",
                "_service": "agentcore",
            }
            for record_index in range(100)
        ]

        html = generate_report_direct(
            all_findings=[failed_control, *record_passes],
            service_findings={
                "bedrock": [failed_control],
                "agentcore": record_passes,
            },
            service_stats={
                "bedrock": {"passed": 0, "failed": 1, "na": 0},
                "agentcore": {"passed": 100, "failed": 0, "na": 0},
            },
            mode="single",
            account_id="123456789012",
        )

        self.assertIn(
            '<div class="metric-label">Overall</div>'
            '<div class="metric-value">50.0%</div>'
            '<div class="metric-sub">1 of 2 scored controls passed</div>',
            html,
        )
        self.assertNotIn("99.5%", html)

    def tearDown(self):
        """Clean up test files after running tests"""
        pass


class TestReportFailureHandling(unittest.TestCase):
    def setUp(self):
        self.event = {
            "Execution": {"Name": "synthetic-execution-id"},
            "OriginalInput": {
                "enableResponsibleAIGRC": "false",
                "enableOWASP": "false",
                "ResolvedRegions": {"regions": ["us-east-1"]},
            },
        }
        self.assessment_results = {
            "account_id": "123456789012",
            "timestamp": "2026-09-11 10:00:00 UTC",
            "bedrock": {
                "bedrock_security_report_synthetic-execution-id_us-east-1": [
                    {"Check_ID": "BR-00"}
                ]
            },
            "sagemaker": {
                "sagemaker_security_report_synthetic-execution-id_us-east-1": [
                    {"Check_ID": "SM-00"}
                ]
            },
            "agentcore": {
                "agentcore_security_report_synthetic-execution-id_us-east-1": [
                    {"Check_ID": "AC-00"}
                ]
            },
            "agent-registry": {
                "agent_registry_security_report_synthetic-execution-id_us-east-1": [
                    {"Check_ID": "AR-00"}
                ]
            },
        }

    def test_validation_rejects_a_missing_regional_artifact(self):
        self.event["OriginalInput"]["ResolvedRegions"]["regions"].append("us-west-2")

        with self.assertRaisesRegex(
            ValueError,
            "sagemaker_security_report_synthetic-execution-id_us-west-2.csv",
        ):
            generate_report_app.validate_assessment_artifacts(
                self.assessment_results,
                "synthetic-execution-id",
                self.event["OriginalInput"],
            )

    def test_validation_requires_responsible_ai_grc_as_owasp_dependency(self):
        self.event["OriginalInput"]["enableOWASP"] = "true"
        self.assessment_results["owasp"] = {
            "owasp_security_report_synthetic-execution-id_us-east-1": [
                {"Check_ID": "OW-01"}
            ]
        }

        with self.assertRaisesRegex(
            ValueError,
            "responsible_ai_grc_security_report_synthetic-execution-id.csv",
        ):
            generate_report_app.validate_assessment_artifacts(
                self.assessment_results,
                "synthetic-execution-id",
                self.event["OriginalInput"],
            )

    def test_generate_html_report_propagates_template_failure(self):
        with mock.patch.object(
            generate_report_app,
            "generate_report_from_template",
            side_effect=RuntimeError("template rendering failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "template rendering failed"):
                generate_report_app.generate_html_report(self.assessment_results)

    def test_handler_render_failure_uploads_nothing_and_cleans_cache(self):
        sts_client = mock.Mock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        s3_client = mock.Mock()
        s3_client.delete_object.side_effect = RuntimeError("cleanup failed")

        def boto_client(service_name, **_kwargs):
            return {"sts": sts_client, "s3": s3_client}[service_name]

        with (
            mock.patch.dict(
                os.environ,
                {"AIML_ASSESSMENT_BUCKET_NAME": "test-assessment-bucket"},
            ),
            mock.patch.object(
                generate_report_app.boto3,
                "client",
                side_effect=boto_client,
            ),
            mock.patch.object(
                generate_report_app,
                "get_assessment_results",
                return_value=self.assessment_results,
            ),
            mock.patch.object(
                generate_report_app,
                "generate_html_report",
                side_effect=RuntimeError("template rendering failed"),
            ),
            mock.patch.object(generate_report_app, "write_html_to_s3") as write_report,
        ):
            with self.assertRaisesRegex(RuntimeError, "template rendering failed"):
                generate_report_app.lambda_handler(self.event, None)

        write_report.assert_not_called()
        s3_client.delete_object.assert_called_once_with(
            Bucket="test-assessment-bucket",
            Key="permissions_cache_synthetic-execution-id.json",
        )

    def test_write_html_to_s3_propagates_upload_failure(self):
        s3_client = mock.Mock()
        s3_client.put_object.side_effect = RuntimeError("upload failed")

        with mock.patch.object(
            generate_report_app.boto3,
            "client",
            return_value=s3_client,
        ):
            with self.assertRaisesRegex(RuntimeError, "upload failed"):
                generate_report_app.write_html_to_s3(
                    "<html></html>",
                    "test-assessment-bucket",
                    "synthetic-execution-id",
                )

    def test_handler_success_still_returns_report_location(self):
        sts_client = mock.Mock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        s3_client = mock.Mock()

        def boto_client(service_name, **_kwargs):
            return {"sts": sts_client, "s3": s3_client}[service_name]

        with (
            mock.patch.dict(
                os.environ,
                {"AIML_ASSESSMENT_BUCKET_NAME": "test-assessment-bucket"},
            ),
            mock.patch.object(
                generate_report_app.boto3,
                "client",
                side_effect=boto_client,
            ),
            mock.patch.object(
                generate_report_app,
                "get_assessment_results",
                return_value=self.assessment_results,
            ),
            mock.patch.object(
                generate_report_app,
                "generate_html_report",
                return_value="<html></html>",
            ),
            mock.patch.object(
                generate_report_app,
                "write_html_to_s3",
                return_value="security_assessment_single_account_20260911_100000.html",
            ),
        ):
            response = generate_report_app.lambda_handler(self.event, None)

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(
            response["body"]["report_location"],
            (
                "s3://test-assessment-bucket/"
                "security_assessment_single_account_20260911_100000.html"
            ),
        )
        s3_client.delete_object.assert_called_once_with(
            Bucket="test-assessment-bucket",
            Key="permissions_cache_synthetic-execution-id.json",
        )


if __name__ == "__main__":
    unittest.main()
