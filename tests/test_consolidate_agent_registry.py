"""Multi-account consolidation routes AR-* checks to the agent-registry area.

`consolidate_html_reports.py` is the root multi-account consolidator. It has its
own Check_ID prefix routing, separate from the single-account report Lambda, so
a new assessment area has to be wired in both places. These tests cover the
Agent Registry path: validated source routing, the AG-* lens split, isolation
of unknown or wrong-owner rows, and the per-account report stats.
"""

import csv
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import consolidate_html_reports as chr


def _row(check_id, finding, severity="High", status="Failed", region="us-east-1"):
    return {
        "Check_ID": check_id,
        "Finding": finding,
        "Finding_Details": "details",
        "Resolution": "Do the thing",
        "Reference": "https://docs.aws.amazon.com/",
        "Severity": severity,
        "Status": status,
        "Region": region,
    }


class TestConsolidateAgentRegistryCategorization(unittest.TestCase):
    ACCT = "111122223333"

    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="agent-registry-consolidate-test-")
        os.makedirs(f"{self.base}/{self.ACCT}", exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def _write(self, filename, rows):
        path = f"{self.base}/{self.ACCT}/{filename}"
        with open(path, "w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    def _consolidate(self):
        captured = {}

        def fake_render(**kwargs):
            captured.update(kwargs)
            return "<html>ok</html>"

        with (
            patch.object(chr, "boto3") as mock_boto3,
            patch.object(chr, "generate_html_report", side_effect=fake_render),
            patch.dict(
                os.environ,
                {"BUCKET_REPORT": "test-bucket", "ACCOUNT_FILES_DIR": self.base},
            ),
        ):
            mock_boto3.client.return_value = MagicMock()
            chr.consolidate_html_reports()
        return captured

    def test_ar_prefix_categorized_as_agent_registry(self):
        self._write(
            "agent_registry_security_report_test_us-east-1.csv",
            [
                _row(
                    "AR-01",
                    "AWS Agent Registry IAM Full Access Policy",
                    region="Global",
                ),
                _row(
                    "AR-05",
                    "AWS Agent Registry Customer-Managed KMS Encryption",
                    severity="Medium",
                    status="Passed",
                ),
                _row(
                    "AR-07",
                    "AWS Agent Registry Record Lifecycle Governance",
                    severity="Informational",
                    status="N/A",
                ),
            ],
        )
        captured = self._consolidate()

        registry_ids = {
            f["Check_ID"] for f in captured["service_findings"]["agent-registry"]
        }
        self.assertEqual(registry_ids, {"AR-01", "AR-05", "AR-07"})
        self.assertEqual(
            captured["service_stats"]["agent-registry"],
            {"passed": 1, "failed": 1, "na": 1},
        )
        # AgentCore must not absorb Registry rows.
        self.assertEqual(
            captured["service_stats"]["agentcore"],
            {"passed": 0, "failed": 0, "na": 0},
        )

    def test_ar_row_in_agentcore_csv_is_isolated(self):
        """A wrong-owner row cannot borrow the AgentCore producer's scope."""
        self._write(
            "agentcore_security_report_test_us-east-1.csv",
            [
                _row("AC-01", "Runtime Amazon VPC Configuration"),
                _row("AR-08", "AWS Agent Registry Record Provenance"),
            ],
        )
        captured = self._consolidate()

        self.assertEqual(captured["service_findings"]["agent-registry"], [])
        self.assertEqual(
            {f["Check_ID"] for f in captured["service_findings"]["agentcore"]},
            {"AC-01"},
        )
        issues = captured["aisf_register"]["artifact_issues"]
        self.assertTrue(
            any(
                issue["kind"] == "scope-mismatch"
                and issue.get("observation", {}).get("Check_ID") == "AR-08"
                for issue in issues
            )
        )

    def test_ag_rows_from_registry_csv_route_to_the_agentic_lens(self):
        """AG-33..AG-38 ship in the Registry CSV but are contextual lens rows."""
        self._write(
            "agent_registry_security_report_test_us-east-1.csv",
            [
                _row("AR-03", "AWS Agent Registry Publication Approval Governance"),
                _row("AG-33", "Agentic AI Registry Publication Approval Governance"),
            ],
        )
        captured = self._consolidate()

        self.assertEqual(
            {f["Check_ID"] for f in captured["service_findings"]["agentic"]},
            {"AG-33"},
        )
        self.assertEqual(
            {f["Check_ID"] for f in captured["service_findings"]["agent-registry"]},
            {"AR-03"},
        )

    def test_unknown_registry_check_is_isolated_with_original_evidence(self):
        """A finding's name cannot turn an unknown ID into a known check."""
        self._write(
            "agent_registry_security_report_test_us-east-1.csv",
            [_row("UNKNOWN", "AWS Agent Registry record provenance gap")],
        )
        captured = self._consolidate()

        self.assertEqual(captured["service_findings"]["agent-registry"], [])
        self.assertEqual(captured["service_findings"]["bedrock"], [])
        issues = captured["aisf_register"]["artifact_issues"]
        self.assertTrue(
            any(
                issue["kind"] == "unknown-check"
                and issue.get("observation", {}).get("Check_ID") == "UNKNOWN"
                and issue["observation"]["Finding_Details"] == "details"
                for issue in issues
            )
        )


if __name__ == "__main__":
    unittest.main()
