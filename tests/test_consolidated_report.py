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


class TestOWASPFindingClassification:
    """OW-* rows are classified into the OWASP compliance-standard area."""

    def _run(self, monkeypatch, results):
        captured = {}
        monkeypatch.setattr(
            consolidated_app,
            "generate_report_from_template",
            lambda **kwargs: captured.update(kwargs) or "<html></html>",
        )
        consolidated_app.generate_html_report(results)
        return captured

    def test_ow_rows_from_owasp_csv_route_to_owasp_bucket(self, monkeypatch):
        results = {
            "execution_id": "exec-123",
            "account_id": "111122223333",
            "bedrock": {},
            "sagemaker": {},
            "agentcore": {},
            "responsible-ai-grc": {},
            "owasp": {
                "owasp_security_report_exec-123_us-east-1": [
                    _finding(
                        "OW-01",
                        "us-east-1",
                        status="Failed",
                        name="OWASP LLM01: Prompt Injection Controls",
                    ),
                    _finding(
                        "OW-11",
                        "us-east-1",
                        status="Passed",
                        name="OWASP LLM07: System Prompt in Env Var",
                    ),
                ],
            },
        }
        captured = self._run(monkeypatch, results)
        assert captured["service_stats"]["owasp"]["failed"] == 1
        assert captured["service_stats"]["owasp"]["passed"] == 1
        assert all(
            f["_service"] == "owasp" for f in captured["service_findings"]["owasp"]
        )

    def test_ow_row_landing_in_bedrock_csv_is_isolated(self, monkeypatch):
        """An OWASP observation cannot borrow another producer's artifact."""
        results = _build_results(
            {
                "bedrock_security_report_exec-123_us-east-1": [
                    _finding(
                        "OW-06",
                        "us-east-1",
                        status="Failed",
                        name="OWASP LLM06: Excessive Agency",
                    ),
                ],
            }
        )
        captured = self._run(monkeypatch, results)
        assert captured["service_stats"]["owasp"]["failed"] == 0
        assert captured["service_stats"]["bedrock"]["failed"] == 0
        assert any(
            issue.get("observation", {}).get("Check_ID") == "OW-06"
            for issue in captured["aisf_register"]["artifact_issues"]
        )


class TestAgentRegistryFindingClassification:
    """AR-* rows are classified into the AWS Agent Registry assessment area."""

    def _run(self, monkeypatch, results):
        captured = {}
        monkeypatch.setattr(
            consolidated_app,
            "generate_report_from_template",
            lambda **kwargs: captured.update(kwargs) or "<html></html>",
        )
        consolidated_app.generate_html_report(results)
        return captured

    def test_ar_rows_from_registry_csv_route_to_agent_registry_bucket(
        self, monkeypatch
    ):
        results = {
            "execution_id": "exec-123",
            "account_id": "111122223333",
            "bedrock": {},
            "sagemaker": {},
            "agentcore": {},
            "agent-registry": {
                "agent_registry_security_report_exec-123_us-east-1": [
                    _finding(
                        "AR-01",
                        "Global",
                        status="Failed",
                        name="AWS Agent Registry IAM Full Access Policy",
                    ),
                    _finding(
                        "AR-05",
                        "us-east-1",
                        status="Passed",
                        name="AWS Agent Registry Customer-Managed KMS Encryption",
                    ),
                ],
            },
        }
        captured = self._run(monkeypatch, results)
        assert captured["service_stats"]["agent-registry"]["failed"] == 1
        assert captured["service_stats"]["agent-registry"]["passed"] == 1
        assert all(
            f["_service"] == "agent-registry"
            for f in captured["service_findings"]["agent-registry"]
        )
        # AgentCore must not absorb Registry rows now that they are separate.
        assert captured["service_stats"]["agentcore"] == {
            "passed": 0,
            "failed": 0,
            "na": 0,
        }

    def test_ar_row_landing_in_agentcore_csv_is_isolated(self, monkeypatch):
        """A stale AgentCore artifact cannot prove an Agent Registry check."""
        results = {
            "execution_id": "exec-123",
            "account_id": "111122223333",
            "bedrock": {},
            "sagemaker": {},
            "agentcore": {
                "agentcore_security_report_exec-123_us-east-1": [
                    _finding(
                        "AR-08",
                        "us-east-1",
                        status="Failed",
                        name="AWS Agent Registry Record Provenance",
                    ),
                ],
            },
        }
        captured = self._run(monkeypatch, results)
        assert captured["service_stats"]["agent-registry"]["failed"] == 0
        assert captured["service_stats"]["agentcore"]["failed"] == 0
        assert any(
            issue.get("observation", {}).get("Check_ID") == "AR-08"
            for issue in captured["aisf_register"]["artifact_issues"]
        )

    def test_ag_rows_from_registry_csv_route_to_the_agentic_lens(self, monkeypatch):
        """AG-33..AG-38 are synthesized by the Registry Lambda but are lens rows.

        They ship inside the Agent Registry CSV, so prefix routing must move
        them to the agentic bucket or they would double-count as direct
        Registry controls.
        """
        results = {
            "execution_id": "exec-123",
            "account_id": "111122223333",
            "bedrock": {},
            "sagemaker": {},
            "agentcore": {},
            "agent-registry": {
                "agent_registry_security_report_exec-123_us-east-1": [
                    _finding(
                        "AR-03",
                        "us-east-1",
                        status="Failed",
                        name="AWS Agent Registry Publication Approval Governance",
                    ),
                    _finding(
                        "AG-33",
                        "us-east-1",
                        status="Failed",
                        name="Agentic AI Registry Publication Approval Governance",
                    ),
                ],
            },
        }
        captured = self._run(monkeypatch, results)
        assert captured["service_stats"]["agentic"]["failed"] == 1
        assert captured["service_stats"]["agent-registry"]["failed"] == 1
        agentic_ids = {f["Check_ID"] for f in captured["service_findings"]["agentic"]}
        registry_ids = {
            f["Check_ID"] for f in captured["service_findings"]["agent-registry"]
        }
        assert agentic_ids == {"AG-33"}
        assert registry_ids == {"AR-03"}

    def test_global_agent_registry_row_is_not_counted_as_a_region(self, monkeypatch):
        """AR-01/AR-02 are account-scoped and tagged Global, not a scanned region."""
        results = {
            "execution_id": "exec-123",
            "account_id": "111122223333",
            "bedrock": {},
            "sagemaker": {},
            "agentcore": {},
            "agent-registry": {
                "agent_registry_security_report_exec-123_us-east-1": [
                    _finding(
                        "AR-02",
                        "Global",
                        status="Failed",
                        name="AWS Agent Registry Stale Access",
                    ),
                    _finding(
                        "AR-05",
                        "us-east-1",
                        status="Passed",
                        name="AWS Agent Registry Customer-Managed KMS Encryption",
                    ),
                ],
            },
        }
        captured = self._run(monkeypatch, results)
        assert captured["regions"] == ["us-east-1"]


class TestFinServSuppressionWhenOWASPOnly:
    """When Responsible AI GRC runs only as an OWASP dependency (customer did
    not enable it explicitly), FS-* rows must be hidden from the report
    entirely — no findings, no service_stats, no service_findings — while
    OW-* rows are kept intact.
    """

    def _run(self, monkeypatch, results, show_finserv):
        captured = {}
        monkeypatch.setattr(
            consolidated_app,
            "generate_report_from_template",
            lambda **kwargs: captured.update(kwargs) or "<html></html>",
        )
        consolidated_app.generate_html_report(results, show_finserv=show_finserv)
        return captured

    def test_show_finserv_false_hides_fs_rows(self, monkeypatch):
        results = {
            "execution_id": "exec-123",
            "account_id": "111122223333",
            "bedrock": {},
            "sagemaker": {},
            "agentcore": {},
            "responsible-ai-grc": {
                "responsible_ai_grc_security_report_exec-123": [
                    _finding("FS-51", "us-east-1", status="Failed"),
                    _finding("FS-52", "us-east-1", status="Passed"),
                ],
            },
            "owasp": {
                "owasp_security_report_exec-123_us-east-1": [
                    _finding("OW-01", "us-east-1", status="Failed"),
                ],
            },
        }
        captured = self._run(monkeypatch, results, show_finserv=False)
        assert captured["service_stats"]["responsible-ai-grc"] == {
            "passed": 0,
            "failed": 0,
            "na": 0,
        }
        assert captured["service_findings"]["responsible-ai-grc"] == []
        # OWASP rows survive untouched.
        assert captured["service_stats"]["owasp"]["failed"] == 1

    def test_show_finserv_true_keeps_fs_rows(self, monkeypatch):
        results = {
            "execution_id": "exec-123",
            "account_id": "111122223333",
            "bedrock": {},
            "sagemaker": {},
            "agentcore": {},
            "responsible-ai-grc": {
                "responsible_ai_grc_security_report_exec-123": [
                    _finding("FS-51", "us-east-1", status="Failed"),
                ],
            },
        }
        captured = self._run(monkeypatch, results, show_finserv=True)
        assert captured["service_stats"]["responsible-ai-grc"]["failed"] == 1

    def test_show_finserv_defaults_to_true(self, monkeypatch):
        # Backwards compatibility: existing callers that don't pass the kwarg
        # must keep seeing Responsible AI GRC rows.
        results = {
            "execution_id": "exec-123",
            "account_id": "111122223333",
            "bedrock": {},
            "sagemaker": {},
            "agentcore": {},
            "responsible-ai-grc": {
                "responsible_ai_grc_security_report_exec-123": [
                    _finding("FS-51", "us-east-1", status="Failed"),
                ],
            },
        }
        captured = {}
        monkeypatch.setattr(
            consolidated_app,
            "generate_report_from_template",
            lambda **kwargs: captured.update(kwargs) or "<html></html>",
        )
        consolidated_app.generate_html_report(results)
        assert captured["service_stats"]["responsible-ai-grc"]["failed"] == 1


class TestFlagParsing:
    """The Step Functions payload may carry booleans OR strings for flags."""

    def test_flag_is_true_accepts_string_true(self):
        assert consolidated_app._flag_is_true("true") is True
        assert consolidated_app._flag_is_true("True") is True
        assert consolidated_app._flag_is_true(" TRUE ") is True

    def test_flag_is_true_accepts_boolean_true(self):
        assert consolidated_app._flag_is_true(True) is True

    def test_flag_is_true_rejects_everything_else(self):
        assert consolidated_app._flag_is_true(None) is False
        assert consolidated_app._flag_is_true("false") is False
        assert consolidated_app._flag_is_true("") is False
        assert consolidated_app._flag_is_true(0) is False
        assert consolidated_app._flag_is_true(1) is False  # int, not bool
        assert consolidated_app._flag_is_true("yes") is False
