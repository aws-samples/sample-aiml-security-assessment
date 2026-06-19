"""Multi-account consolidation: FS-* Check-IDs must categorize to the finserv
service (not be mislabeled as bedrock). Patches S3 and the renderer to capture
the service_findings/service_stats passed to the shared template."""

import os
import csv
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import consolidate_html_reports as chr


class TestConsolidateFinservCategorization(unittest.TestCase):
    ACCT = "999988887777"
    BASE = tempfile.mkdtemp(prefix="finserv-consolidate-test-")

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
            },
            {
                "Check_ID": "FS-01",
                "Finding": "No Regional WAF Web ACLs Found",
                "Finding_Details": "d",
                "Resolution": "r",
                "Reference": "https://x",
                "Severity": "Medium",
                "Status": "Failed",
            },
            {
                "Check_ID": "FS-44",
                "Finding": "Amazon Macie Enabled",
                "Finding_Details": "d",
                "Resolution": "r",
                "Reference": "https://x",
                "Severity": "High",
                "Status": "Passed",
            },
        ]
        path = f"{self.BASE}/{self.ACCT}/finserv_security_report_test.csv"
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)

    def tearDown(self):
        shutil.rmtree(self.BASE, ignore_errors=True)

    def test_fs_prefix_categorized_as_finserv(self):
        captured = {}

        def fake_render(**kwargs):
            captured.update(kwargs)
            return "<html>ok</html>"

        with (
            patch.object(chr, "boto3") as mock_boto3,
            patch.object(chr, "generate_html_report", side_effect=fake_render),
            patch.dict(
                os.environ,
                {"BUCKET_REPORT": "test-bucket", "ACCOUNT_FILES_DIR": self.BASE},
            ),
        ):
            mock_boto3.client.return_value = MagicMock()
            chr.consolidate_html_reports()

        sf = captured["service_findings"]
        finserv_ids = {f["check_id"] for f in sf["finserv"]}
        bedrock_ids = {f["check_id"] for f in sf["bedrock"]}
        self.assertIn("FS-01", finserv_ids)
        self.assertIn("FS-44", finserv_ids)
        self.assertNotIn("FS-01", bedrock_ids)  # the bug was FS-* -> bedrock
        self.assertIn("BR-01", bedrock_ids)
        # finserv stats counted
        self.assertEqual(captured["service_stats"]["finserv"]["failed"], 1)
        self.assertEqual(captured["service_stats"]["finserv"]["passed"], 1)


if __name__ == "__main__":
    unittest.main()
