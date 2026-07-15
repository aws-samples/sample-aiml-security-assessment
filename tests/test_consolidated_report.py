"""
Tests for the consolidated report generator's finding aggregation.

Focus: multi-region dedup. Global/IAM findings (Region == "Global") are
produced once per run by the primary-region Lambda, but the consolidator must
not double-count a finding even if it ever lands in more than one region's CSV
(e.g. RegionIndex missing from the event). Regional findings that differ only
by Region must NOT be collapsed.
"""

import sys
import os
import importlib.util

# The consolidator imports `report_template` as a top-level module, so its
# directory must be on sys.path before app.py is loaded.
_report_dir = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "aiml-security-assessment/functions/security/generate_consolidated_report",
    )
)
if _report_dir not in sys.path:
    sys.path.insert(0, _report_dir)

_spec = importlib.util.spec_from_file_location(
    "consolidated_report_app", os.path.join(_report_dir, "app.py")
)
consolidated_app = importlib.util.module_from_spec(_spec)
sys.modules["consolidated_report_app"] = consolidated_app
_spec.loader.exec_module(consolidated_app)


def _finding(check_id, region, status="Failed", details=None, name="Test Finding"):
    """Build a CSV-style finding row as parsed from a per-region report."""
    return {
        "Check_ID": check_id,
        "Finding": name,
        "Finding_Details": details if details is not None else f"{check_id} details",
        "Resolution": "Do the thing",
        "Reference": "https://docs.aws.amazon.com/",
        "Severity": "High",
        "Status": status,
        "Region": region,
    }


def _build_results(bedrock_reports):
    """Wrap per-file finding lists into the assessment_results structure."""
    return {
        "execution_id": "exec-123",
        "account_id": "111122223333",
        "bedrock": bedrock_reports,
        "sagemaker": {},
        "agentcore": {},
    }


class TestGlobalFindingDedup:
    """A duplicated global finding across region files is counted once."""

    def test_global_finding_in_multiple_region_files_counted_once(self, monkeypatch):
        captured = {}

        def fake_template(**kwargs):
            captured.update(kwargs)
            return "<html></html>"

        monkeypatch.setattr(
            consolidated_app, "generate_report_from_template", fake_template
        )

        # Same global BR-01 finding written into two different region files.
        results = _build_results(
            {
                "bedrock_security_report_exec-123_us-east-1": [
                    _finding("BR-01", "Global"),
                ],
                "bedrock_security_report_exec-123_us-west-2": [
                    _finding("BR-01", "Global"),
                ],
            }
        )

        consolidated_app.generate_html_report(results)

        all_findings = captured["all_findings"]
        br01 = [f for f in all_findings if f["Check_ID"] == "BR-01"]
        assert len(br01) == 1, "Duplicated global finding should be deduped to one"
        assert captured["service_stats"]["bedrock"]["failed"] == 1

    def test_regional_findings_differing_by_region_are_kept(self, monkeypatch):
        captured = {}
        monkeypatch.setattr(
            consolidated_app,
            "generate_report_from_template",
            lambda **kwargs: captured.update(kwargs) or "<html></html>",
        )

        # Same check id but genuinely per-region findings -> must both survive.
        results = _build_results(
            {
                "bedrock_security_report_exec-123_us-east-1": [
                    _finding("BR-05", "us-east-1"),
                ],
                "bedrock_security_report_exec-123_us-west-2": [
                    _finding("BR-05", "us-west-2"),
                ],
            }
        )

        consolidated_app.generate_html_report(results)

        br05 = [f for f in captured["all_findings"] if f["Check_ID"] == "BR-05"]
        assert len(br05) == 2, "Distinct regional findings must not be collapsed"
        assert captured["service_stats"]["bedrock"]["failed"] == 2
        assert set(captured["regions"]) == {"us-east-1", "us-west-2"}

    def test_distinct_findings_same_region_are_kept(self, monkeypatch):
        captured = {}
        monkeypatch.setattr(
            consolidated_app,
            "generate_report_from_template",
            lambda **kwargs: captured.update(kwargs) or "<html></html>",
        )

        # Same check id and region but different details (e.g. two flagged roles).
        results = _build_results(
            {
                "bedrock_security_report_exec-123_us-east-1": [
                    _finding("BR-01", "Global", details="Role A is over-permissive"),
                    _finding("BR-01", "Global", details="Role B is over-permissive"),
                ],
            }
        )

        consolidated_app.generate_html_report(results)

        br01 = [f for f in captured["all_findings"] if f["Check_ID"] == "BR-01"]
        assert len(br01) == 2, "Findings differing by detail must be kept"


class TestRegionCounting:
    """The "Global" sentinel (IAM-only findings) must not be counted as a
    scanned region — otherwise a default single-region scan renders as
    multi-region (region filter, "Risk by Region", "N Regions" header)."""

    def _capture(self, monkeypatch):
        captured = {}
        monkeypatch.setattr(
            consolidated_app,
            "generate_report_from_template",
            lambda **kwargs: captured.update(kwargs) or "<html></html>",
        )
        return captured

    def test_global_only_does_not_count_as_region(self, monkeypatch):
        # Default single-region scan: one real region plus the IAM-global finding.
        captured = self._capture(monkeypatch)
        results = _build_results(
            {
                "bedrock_security_report_exec-123_us-east-1": [
                    _finding("BR-01", "Global"),
                    _finding("BR-05", "us-east-1", status="Passed"),
                ],
            }
        )

        consolidated_app.generate_html_report(results)

        # Only the real region is counted; "Global" is excluded.
        assert captured["regions"] == ["us-east-1"]
        assert "Global" not in captured["regions"]

    def test_genuine_multi_region_still_counted(self, monkeypatch):
        # Two real regions plus a global finding -> still multi-region.
        captured = self._capture(monkeypatch)
        results = _build_results(
            {
                "bedrock_security_report_exec-123_us-east-1": [
                    _finding("BR-01", "Global"),
                    _finding("BR-05", "us-east-1", status="Passed"),
                ],
                "bedrock_security_report_exec-123_us-west-2": [
                    _finding("BR-05", "us-west-2", status="Passed"),
                ],
            }
        )

        consolidated_app.generate_html_report(results)

        assert set(captured["regions"]) == {"us-east-1", "us-west-2"}

    def test_global_only_yields_no_regions(self, monkeypatch):
        # Every region unavailable: only global findings exist. regions -> None
        # so the report shows no multi-region UI rather than a "Global" region.
        captured = self._capture(monkeypatch)
        results = _build_results(
            {
                "bedrock_security_report_exec-123_us-east-1": [
                    _finding("BR-01", "Global"),
                ],
            }
        )

        consolidated_app.generate_html_report(results)

        assert captured["regions"] is None


class TestAgenticFindingClassification:
    """AG-* rows are classified into the Agentic assessment area."""

    def test_ag_rows_from_bedrock_csv_move_to_agentic_bucket(self, monkeypatch):
        captured = {}
        monkeypatch.setattr(
            consolidated_app,
            "generate_report_from_template",
            lambda **kwargs: captured.update(kwargs) or "<html></html>",
        )

        results = _build_results(
            {
                "bedrock_security_report_exec-123_us-east-1": [
                    _finding(
                        "AG-01",
                        "us-east-1",
                        status="Passed",
                        name="Agentic AI Agent Guardrail Association",
                    ),
                ],
            }
        )

        consolidated_app.generate_html_report(results)

        assert captured["service_stats"]["agentic"]["passed"] == 1
        assert captured["service_stats"]["bedrock"]["passed"] == 0
        assert captured["service_findings"]["agentic"][0]["_service"] == "agentic"


class TestPassRateExcludesNARows:
    """Pass-rate denominators must count only scored (Passed/Failed) rows.

    A COULD NOT ASSESS row (Severity=Low, Status=N/A) or a soft-warning row
    (Status=N/A) marks a check that was not assessed; counting it as a
    never-passing denominator entry would silently depress the pass rate.
    """

    def _results(self, findings):
        return {
            "execution_id": "exec-123",
            "account_id": "111122223333",
            "timestamp": "July 14, 2026 12:00:00 UTC",
            "bedrock": {"bedrock_security_report_exec-123_us-east-1": findings},
            "sagemaker": {},
            "agentcore": {},
            "finserv": {},
        }

    def test_could_not_assess_rows_do_not_enter_denominators(self):
        findings = [
            _finding("BR-01", "us-east-1", status="Passed"),
            _finding("BR-02", "us-east-1", status="Failed"),
            {
                "Check_ID": "BR-03",
                "Finding": "COULD NOT ASSESS: Some Check",
                "Finding_Details": "missing IAM permission",
                "Resolution": "Grant access and re-run",
                "Reference": "https://docs.aws.amazon.com/",
                "Severity": "Low",
                "Status": "N/A",
                "Region": "us-east-1",
            },
        ]
        html = consolidated_app.generate_html_report(self._results(findings))
        # 2 scored High rows (1 passed, 1 failed); the Low N/A row is excluded.
        assert "1 of 2 scored checks passed" in html
        # The COULD NOT ASSESS row surfaces in the Unassessed Checks metric.
        assert 'Unassessed Checks</div><div class="metric-value">1</div>' in html

    def test_soft_warning_na_row_does_not_enter_medium_denominator(self):
        medium_na = _finding("BR-04", "us-east-1", status="N/A")
        medium_na["Severity"] = "Medium"
        medium_passed = _finding("BR-05", "us-east-1", status="Passed")
        medium_passed["Severity"] = "Medium"
        html = consolidated_app.generate_html_report(
            self._results([medium_na, medium_passed])
        )
        # Only the Passed row is scored: 1 of 1 -> 100% pass rate overall.
        assert "1 of 1 scored checks passed" in html
        assert 'Unassessed Checks</div><div class="metric-value">0</div>' in html


class TestMissingResultsSynthesis:
    """Orchestration-level gaps (a service Lambda crashed or timed out and its
    CSV never landed in S3) must surface as visible COULD_NOT_ASSESS rows, not
    silently shrink the report."""

    @staticmethod
    def _empty_results():
        return {
            "execution_id": "exec-1",
            "account_id": "111122223333",
            "bedrock": {},
            "sagemaker": {},
            "agentcore": {},
            "finserv": {},
        }

    def test_missing_service_gets_one_row(self):
        results = self._empty_results()
        keys = [
            "bedrock_security_report_exec-1_us-east-1.csv",
            "sagemaker_security_report_exec-1_us-east-1.csv",
        ]
        consolidated_app.synthesize_missing_result_rows(
            results, keys, "exec-1", finserv_enabled=False, account_id="111122223333"
        )
        rows = results["agentcore"].get("missing_results")
        assert rows and len(rows) == 1
        row = rows[0]
        assert row["Check_ID"] == "AC-00"
        assert row["Finding"].startswith("COULD NOT ASSESS")
        assert row["Severity"] == "Low"
        assert row["Status"] == "N/A"
        assert row["Account_ID"] == "111122223333"
        # Services that reported are not flagged.
        assert "missing_results" not in results["bedrock"]
        assert "missing_results" not in results["sagemaker"]
        # FinServ was not enabled, so its absence is expected, not a gap.
        assert "missing_results" not in results["finserv"]

    def test_missing_region_for_one_service_gets_per_region_row(self):
        results = self._empty_results()
        keys = [
            "bedrock_security_report_exec-1_us-east-1.csv",
            "bedrock_security_report_exec-1_us-west-2.csv",
            "sagemaker_security_report_exec-1_us-east-1.csv",
            "agentcore_security_report_exec-1_us-east-1.csv",
            "agentcore_security_report_exec-1_us-west-2.csv",
        ]
        consolidated_app.synthesize_missing_result_rows(
            results, keys, "exec-1", finserv_enabled=False
        )
        rows = results["sagemaker"].get("missing_results")
        assert rows and len(rows) == 1
        assert rows[0]["Region"] == "us-west-2"
        assert rows[0]["Check_ID"] == "SM-00"
        assert "missing_results" not in results["bedrock"]
        assert "missing_results" not in results["agentcore"]

    def test_finserv_enabled_and_missing_is_flagged(self):
        results = self._empty_results()
        keys = ["bedrock_security_report_exec-1_us-east-1.csv"]
        consolidated_app.synthesize_missing_result_rows(
            results, keys, "exec-1", finserv_enabled=True
        )
        rows = results["finserv"].get("missing_results")
        assert rows and rows[0]["Check_ID"] == "FS-00"
        assert rows[0]["Finding"].startswith("COULD NOT ASSESS")

    def test_finserv_present_is_not_flagged(self):
        results = self._empty_results()
        keys = [
            "bedrock_security_report_exec-1_us-east-1.csv",
            "sagemaker_security_report_exec-1_us-east-1.csv",
            "agentcore_security_report_exec-1_us-east-1.csv",
            "finserv_security_report_exec-1.csv",
        ]
        consolidated_app.synthesize_missing_result_rows(
            results, keys, "exec-1", finserv_enabled=True
        )
        for service in ("bedrock", "sagemaker", "agentcore", "finserv"):
            assert "missing_results" not in results[service]

    def test_synthesized_rows_flow_into_report(self):
        """End-to-end: a synthesized missing-service row renders in the HTML
        and counts in the Unassessed Checks metric."""
        results = self._empty_results()
        results["timestamp"] = "July 14, 2026 12:00:00 UTC"
        results["bedrock"]["bedrock_security_report_exec-1_us-east-1"] = [
            _finding("BR-01", "us-east-1", status="Passed")
        ]
        consolidated_app.synthesize_missing_result_rows(
            results,
            ["bedrock_security_report_exec-1_us-east-1.csv"],
            "exec-1",
            finserv_enabled=False,
        )
        html = consolidated_app.generate_html_report(results)
        assert "COULD NOT ASSESS: SageMaker assessment results missing" in html
        assert "COULD NOT ASSESS: AgentCore assessment results missing" in html
        assert 'Unassessed Checks</div><div class="metric-value">2</div>' in html
