import unittest
import os
import sys
import importlib.util


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
                    }
                ]
            },
        }

    def test_generate_viewable_report(self):
        """Generate a viewable HTML report with test data"""
        html_content = generate_html_report(self.test_assessment_results)

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
                "account_id": "444455556666",
                "check_id": "FS-01",
                "finding": "FinServ Regional Scope Not Applicable",
                "details": "No regional AI/ML resources found.",
                "resolution": "No action required.",
                "reference": "https://example.com",
                "severity": "Informational",
                "status": "N/A",
                "_service": "finserv",
            },
        ]
        service_findings = {
            "bedrock": [all_findings[0]],
            "sagemaker": [all_findings[1]],
            "agentcore": [all_findings[2]],
            "finserv": [all_findings[3]],
        }
        service_stats = {
            "bedrock": {"passed": 0, "failed": 1},
            "sagemaker": {"passed": 0, "failed": 1},
            "agentcore": {"passed": 1, "failed": 0},
            "finserv": {"passed": 0, "failed": 0, "na": 1},
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

        with open(report_path, "r") as f:
            content = f.read()
            # Multi-account specific
            self.assertIn("Multi-Account", content)
            self.assertIn("2 Accounts", content)
            self.assertIn("accountFilter", content)
            self.assertIn("111122223333", content)
            self.assertIn("444455556666", content)
            self.assertIn("<h3>By Industry</h3>", content)
            self.assertIn('class="nav-section industry-nav"', content)
            self.assertIn("Financial Services Risk", content)
            self.assertIn('class="scope-industry"', content)
            by_service_nav = content.split("<h3>By Service</h3>", 1)[1].split(
                "<h3>By Industry</h3>", 1
            )[0]
            self.assertNotIn("Financial Services", by_service_nav)

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
        """REQ-1: FinServ findings render as a first-class service in the HTML."""
        data = dict(self.test_assessment_results)
        data["finserv"] = {
            "finserv_security_report": [
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
        self.assertIn('id="finserv"', html)
        self.assertIn('id="finservTable"', html)
        self.assertIn('<option value="finserv">', html)
        self.assertIn("FS-01", html)
        self.assertIn('data-service="finserv"', html)
        self.assertIn('id="finservRegionFilter"', html)
        self.assertIn('<option value="region-a">region-a</option>', html)
        self.assertIn('<option value="region-b">region-b</option>', html)
        self.assertIn('data-scope-service="finserv"', html)
        self.assertIn('class="scope-industry"', html)
        self.assertIn('class="scope-chip industry-chip"', html)
        self.assertIn('class="nav-section industry-nav"', html)
        self.assertIn("Financial Services Risk", html)
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
        self.assertIn("<h3>By Industry</h3>", html)
        by_service_nav = html.split("<h3>By Service</h3>", 1)[1].split(
            "<h3>By Industry</h3>", 1
        )[0]
        self.assertNotIn("Financial Services", by_service_nav)

    def test_finserv_omitted_when_absent(self):
        """REQ-1/REQ-7: with no FinServ data the FinServ section is omitted cleanly."""
        html = generate_html_report(self.test_assessment_results)
        self.assertNotIn('id="finserv"', html)
        self.assertNotIn("<h3>By Industry</h3>", html)
        self.assertNotIn('<option value="finserv">', html)
        self.assertNotIn('data-scope-service="finserv"', html)
        self.assertNotIn('class="scope-industry"', html)
        self.assertNotIn("Financial Services Risk", html)
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
                    "Reference": "https://docs.aws.amazon.com/bedrock/latest/userguide/agents-guardrails.html",
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
        self.assertIn('id="agenticTable"', html)
        self.assertIn('<option value="agentic">Agentic AI Security</option>', html)
        self.assertIn("<h3>By Lens</h3>", html)
        self.assertIn('class="nav-section lens-nav"', html)
        self.assertIn("AG-01", html)
        self.assertIn('data-service="agentic"', html)
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
        self.assertIn(
            "wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html", html
        )

    def tearDown(self):
        """Clean up test files after running tests"""
        pass


if __name__ == "__main__":
    unittest.main()
