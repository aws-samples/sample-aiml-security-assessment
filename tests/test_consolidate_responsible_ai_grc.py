"""Multi-account consolidation categorizes FS-* checks as responsible-ai-grc."""

import csv
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import consolidate_html_reports as chr


class TestConsolidateResponsibleAIGRCCategorization(unittest.TestCase):
    ACCT = "111122223333"
    BASE = tempfile.mkdtemp(prefix="responsible-ai-grc-consolidate-test-")

    def setUp(self):
        os.makedirs(f"{self.BASE}/{self.ACCT}", exist_ok=True)
        rows = [
            {
                "Check_ID": "BR-01",
                "Finding": "Bedrock thing",
                "Finding_Details": "d",
                "Resolution": "r",
                "Reference": "https://x",
                "Severity": "High",
                "Status": "Failed",
                "Region": "us-east-1",
            },
            {
                "Check_ID": "FS-01",
                "Finding": "No Regional WAF Web ACLs Found",
                "Finding_Details": "d",
                "Resolution": "r",
                "Reference": "https://x",
                "Severity": "Medium",
                "Status": "Failed",
                "Region": "us-east-1",
            },
            {
                "Check_ID": "FS-44",
                "Finding": "Amazon Macie Enabled",
                "Finding_Details": "d",
                "Resolution": "r",
                "Reference": "https://x",
                "Severity": "High",
                "Status": "Passed",
                "Region": "us-east-1",
            },
        ]
        artifacts = {
            "bedrock_security_report_test_us-east-1.csv": rows[:1],
            "responsible_ai_grc_security_report_test.csv": rows[1:],
        }
        for filename, findings in artifacts.items():
            path = f"{self.BASE}/{self.ACCT}/{filename}"
            with open(path, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                w.writeheader()
                w.writerows(findings)

    def tearDown(self):
        shutil.rmtree(self.BASE, ignore_errors=True)

    def test_fs_prefix_categorized_as_responsible_ai_grc(self):
        captured = {}

        def fake_render(**kwargs):
            captured.update(kwargs)
            return "<html>ok</html>"

        with (
            patch.object(chr, "boto3") as mock_boto3,
            patch.object(chr, "generate_html_report", side_effect=fake_render),
            patch.dict(
                os.environ,
                {
                    "BUCKET_REPORT": "test-bucket",
                    "ACCOUNT_FILES_DIR": self.BASE,
                    # The consolidator hides FS-* rows unless the customer
                    # asked for Responsible AI GRC explicitly. This test's
                    # purpose is the FS->responsible-ai-grc categorisation
                    # path, so enable it.
                    "ENABLE_RESPONSIBLE_AI_GRC": "true",
                },
            ),
        ):
            mock_boto3.client.return_value = MagicMock()
            chr.consolidate_html_reports()

        sf = captured["service_findings"]
        finserv_ids = {f["Check_ID"] for f in sf["responsible-ai-grc"]}
        bedrock_ids = {f["Check_ID"] for f in sf["bedrock"]}
        self.assertIn("FS-01", finserv_ids)
        self.assertIn("FS-44", finserv_ids)
        self.assertNotIn("FS-01", bedrock_ids)
        self.assertIn("BR-01", bedrock_ids)
        self.assertEqual(captured["service_stats"]["responsible-ai-grc"]["failed"], 1)
        self.assertEqual(captured["service_stats"]["responsible-ai-grc"]["passed"], 1)

    def test_fs_rows_hidden_when_enable_responsible_ai_grc_false(self):
        # When Responsible AI GRC ran only as an OWASP dependency
        # (ENABLE_RESPONSIBLE_AI_GRC=false but ENABLE_OWASP=true), the
        # consolidator must drop FS-* rows so the multi-account report shows
        # an OWASP-only view.
        captured = {}

        def fake_render(**kwargs):
            captured.update(kwargs)
            return "<html>ok</html>"

        with (
            patch.object(chr, "boto3") as mock_boto3,
            patch.object(chr, "generate_html_report", side_effect=fake_render),
            patch.dict(
                os.environ,
                {
                    "BUCKET_REPORT": "test-bucket",
                    "ACCOUNT_FILES_DIR": self.BASE,
                    "ENABLE_RESPONSIBLE_AI_GRC": "false",
                    "ENABLE_OWASP": "true",
                },
            ),
        ):
            mock_boto3.client.return_value = MagicMock()
            chr.consolidate_html_reports()

        sf = captured["service_findings"]
        stats = captured["service_stats"]
        self.assertEqual(sf["responsible-ai-grc"], [])
        self.assertEqual(
            stats["responsible-ai-grc"], {"passed": 0, "failed": 0, "na": 0}
        )
        # BR-01 must still appear — only FS-* rows are dropped.
        bedrock_ids = {f["Check_ID"] for f in sf["bedrock"]}
        self.assertIn("BR-01", bedrock_ids)


if __name__ == "__main__":
    unittest.main()
