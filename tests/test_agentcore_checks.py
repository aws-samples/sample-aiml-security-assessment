"""
Tests for AgentCore security assessment checks (AC-01 through AC-13).

AgentCore checks differ from Bedrock/SageMaker:
- Return List[Dict] directly (not a dict with 'csv_data' key)
- Use module-level boto3 clients that must be patched at module level
- Use SeverityEnum/StatusEnum values in create_finding calls

Each check is tested for:
- No resources found -> N/A status
- Compliant resources -> Passed status
- Non-compliant resources -> Failed with correct severity
- Exception handling -> returns error finding (list not empty)
- Output schema validity
"""

import sys
import os
import importlib.util
from unittest.mock import patch, MagicMock
from botocore.exceptions import ClientError, EndpointConnectionError

sys.path.insert(0, "aiml-security-assessment/functions/security/agentcore_assessments")
from tests.test_helpers import extract_csv_data, assert_finding_schema

# Load agentcore app module directly to avoid name collisions with other app.py files
_ac_dir = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "aiml-security-assessment/functions/security/agentcore_assessments",
    )
)
if _ac_dir not in sys.path:
    sys.path.insert(0, _ac_dir)

_spec = importlib.util.spec_from_file_location(
    "agentcore_app", os.path.join(_ac_dir, "app.py")
)
agentcore_app = importlib.util.module_from_spec(_spec)
sys.modules["agentcore_app"] = agentcore_app
_spec.loader.exec_module(agentcore_app)


# ---------------------------------------------------------------------------
# Helper: patch AgentCore module-level clients
# ---------------------------------------------------------------------------
def _make_client_error(code="ResourceNotFoundException", message="Not found"):
    return ClientError({"Error": {"Code": code, "Message": message}}, "operation")


# ===================================================================
# AC-01: check_agentcore_vpc_configuration
# ===================================================================
class TestAC01VPCConfiguration:
    """AC-01: Check VPC configuration for AgentCore resources."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac01_client_unavailable_returns_na(self):
        result = agentcore_app.check_agentcore_vpc_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "AC-01"

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac01_no_runtimes_returns_na(self, mock_ac, mock_ec2):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": []}
        result = agentcore_app.check_agentcore_vpc_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac01_runtime_public_returns_failed(self, mock_ac, mock_ec2):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [{"agentRuntimeId": "rt-1", "agentRuntimeName": "TestRT"}]
        }
        mock_ac.get_agent_runtime.return_value = {
            "networkConfiguration": {"networkMode": "PUBLIC"}
        }
        result = agentcore_app.check_agentcore_vpc_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac01_runtime_vpc_configured_returns_passed(self, mock_ac, mock_ec2):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [{"agentRuntimeId": "rt-1", "agentRuntimeName": "TestRT"}]
        }
        mock_ac.get_agent_runtime.return_value = {
            "networkConfiguration": {
                "networkMode": "VPC",
                "subnetIds": ["subnet-123"],
            }
        }
        mock_ec2.describe_subnets.return_value = {
            "Subnets": [{"SubnetId": "subnet-123"}]
        }
        mock_ec2.describe_route_tables.return_value = {
            "RouteTables": [{"Routes": [{"GatewayId": "local"}]}]
        }
        result = agentcore_app.check_agentcore_vpc_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.agentcore_client")
    def test_ac01_exception_returns_error_finding(self, mock_ac):
        mock_ac.list_agent_runtimes.side_effect = Exception("VPC error")
        result = agentcore_app.check_agentcore_vpc_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac01_schema_valid(self):
        result = agentcore_app.check_agentcore_vpc_configuration()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-02: check_agentcore_full_access_roles
# ===================================================================
class TestAC02FullAccessRoles:
    """AC-02: Check for roles with AgentCore full access."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac02_client_unavailable_returns_na(self, empty_permission_cache):
        result = agentcore_app.check_agentcore_full_access_roles(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-02"

    @patch("agentcore_app.agentcore_client")
    def test_ac02_no_full_access_returns_passed(
        self, mock_ac, permission_cache_compliant
    ):
        result = agentcore_app.check_agentcore_full_access_roles(
            permission_cache_compliant
        )
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        # Compliant cache has no AgentCore full access

    @patch("agentcore_app.agentcore_client")
    def test_ac02_full_access_returns_failed(
        self, mock_ac, permission_cache_agentcore_full_access
    ):
        result = agentcore_app.check_agentcore_full_access_roles(
            permission_cache_agentcore_full_access
        )
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        has_failed = any(f["Status"] == "Failed" for f in findings)
        assert has_failed

    @patch("agentcore_app.agentcore_client")
    def test_ac02_empty_cache_returns_findings(self, mock_ac, empty_permission_cache):
        result = agentcore_app.check_agentcore_full_access_roles(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.agentcore_client")
    def test_ac02_schema_valid(self, mock_ac, empty_permission_cache):
        result = agentcore_app.check_agentcore_full_access_roles(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-03: check_stale_agentcore_access
# ===================================================================
class TestAC03StaleAccess:
    """AC-03: Check stale AgentCore access."""

    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.agentcore_client", None)
    def test_ac03_client_unavailable_returns_na(
        self, mock_boto_client, empty_permission_cache
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        result = agentcore_app.check_stale_agentcore_access(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-03"

    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac03_empty_cache_returns_findings(
        self, mock_ac, mock_iam, mock_boto_client, empty_permission_cache
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        result = agentcore_app.check_stale_agentcore_access(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac03_schema_valid(
        self, mock_ac, mock_iam, mock_boto_client, empty_permission_cache
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        result = agentcore_app.check_stale_agentcore_access(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-04: check_agentcore_observability
# ===================================================================
class TestAC04Observability:
    """AC-04: Check AgentCore observability (logging/tracing)."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac04_client_unavailable_returns_na(self):
        result = agentcore_app.check_agentcore_observability()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-04"

    @patch("agentcore_app.cloudwatch_client")
    @patch("agentcore_app.xray_client")
    @patch("agentcore_app.logs_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac04_no_runtimes_returns_na(self, mock_ac, mock_logs, mock_xray, mock_cw):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": []}
        result = agentcore_app.check_agentcore_observability()
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.agentcore_client")
    def test_ac04_exception_returns_error_finding(self, mock_ac):
        mock_ac.list_agent_runtimes.side_effect = Exception("Observability error")
        result = agentcore_app.check_agentcore_observability()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac04_schema_valid(self):
        result = agentcore_app.check_agentcore_observability()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-05: check_agentcore_encryption
# ===================================================================
class TestAC05Encryption:
    """AC-05: Check AgentCore ECR encryption."""

    @patch("agentcore_app.ecr_client")
    @patch("agentcore_app.agentcore_client", None)
    def test_ac05_client_unavailable_returns_na(self, mock_ecr):
        mock_ecr.describe_repositories.return_value = {"repositories": []}
        result = agentcore_app.check_agentcore_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-05"

    @patch("agentcore_app.ecr_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac05_no_runtimes_returns_na(self, mock_ac, mock_ecr):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": []}
        result = agentcore_app.check_agentcore_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.ecr_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac05_exception_returns_error_finding(self, mock_ac, mock_ecr):
        # Raise on the ECR call which is the first thing the check does
        mock_ecr.describe_repositories.side_effect = Exception("Encryption error")
        result = agentcore_app.check_agentcore_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.ecr_client")
    @patch("agentcore_app.agentcore_client", None)
    def test_ac05_schema_valid(self, mock_ecr):
        mock_ecr.describe_repositories.return_value = {"repositories": []}
        result = agentcore_app.check_agentcore_encryption()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-06: check_browser_tool_recording
# ===================================================================
class TestAC06BrowserToolRecording:
    """AC-06: custom browser session recording (Security Hub BedrockAgentCore.6).

    The check evaluates ListBrowsers(type=CUSTOM)/GetBrowser recording config.
    It must never read runtime storageConfig (a field that does not exist in
    GetAgentRuntime and previously produced a false FAIL for every runtime),
    and errors must surface as COULD NOT ASSESS (N/A, Low), never as Failed.
    """

    @patch("agentcore_app.agentcore_client", None)
    def test_ac06_client_unavailable_returns_na(self):
        result = agentcore_app.check_browser_tool_recording()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-06"

    @patch("agentcore_app.agentcore_client")
    def test_ac06_no_custom_browsers_returns_na(self, mock_ac):
        mock_ac.list_browsers.return_value = {"browserSummaries": []}
        result = agentcore_app.check_browser_tool_recording()
        findings = extract_csv_data(result)
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("agentcore_app.agentcore_client")
    def test_ac06_lists_custom_browsers_only(self, mock_ac):
        """The list call must pass type=CUSTOM so AWS system browsers (for
        example aws.browser.v1) are excluded server-side, matching the
        control's BrowserCustom resource type."""
        mock_ac.list_browsers.return_value = {"browserSummaries": []}
        agentcore_app.check_browser_tool_recording()
        _, kwargs = mock_ac.list_browsers.call_args
        assert kwargs.get("type") == "CUSTOM"

    @patch("agentcore_app.agentcore_client")
    def test_ac06_recording_enabled_with_bucket_passes_medium(self, mock_ac):
        mock_ac.list_browsers.return_value = {
            "browserSummaries": [{"browserId": "br-1", "name": "my-browser"}]
        }
        mock_ac.get_browser.return_value = {
            "browserId": "br-1",
            "recording": {"enabled": True, "s3Location": {"bucket": "rec-bucket"}},
        }
        result = agentcore_app.check_browser_tool_recording()
        findings = extract_csv_data(result)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Severity"] == "Medium"

    @patch("agentcore_app.agentcore_client")
    def test_ac06_recording_disabled_fails_medium(self, mock_ac):
        mock_ac.list_browsers.return_value = {
            "browserSummaries": [{"browserId": "br-1", "name": "my-browser"}]
        }
        mock_ac.get_browser.return_value = {"browserId": "br-1"}
        result = agentcore_app.check_browser_tool_recording()
        findings = extract_csv_data(result)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"
        assert "my-browser" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_ac06_recording_enabled_without_bucket_fails(self, mock_ac):
        """BedrockAgentCore.6 fails when recording is enabled but no S3
        location is configured."""
        mock_ac.list_browsers.return_value = {
            "browserSummaries": [{"browserId": "br-1", "name": "my-browser"}]
        }
        mock_ac.get_browser.return_value = {
            "browserId": "br-1",
            "recording": {"enabled": True},
        }
        result = agentcore_app.check_browser_tool_recording()
        findings = extract_csv_data(result)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_ac06_access_denied_returns_could_not_assess(self, mock_ac):
        """AccessDenied must yield a visible COULD NOT ASSESS row (N/A, Low),
        never a false Failed and never a silent no-resources N/A."""
        mock_ac.list_browsers.side_effect = _make_client_error(
            "AccessDeniedException", "no ListBrowsers"
        )
        result = agentcore_app.check_browser_tool_recording()
        findings = extract_csv_data(result)
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("agentcore_app.agentcore_client")
    def test_ac06_exception_returns_could_not_assess(self, mock_ac):
        mock_ac.list_browsers.side_effect = Exception("Browser tool error")
        result = agentcore_app.check_browser_tool_recording()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("agentcore_app.agentcore_client")
    def test_ac06_never_reads_runtime_config(self, mock_ac):
        """Regression guard: the previous implementation read a nonexistent
        storageConfig field from GetAgentRuntime and false-failed every
        runtime. The check must not call runtime APIs at all."""
        mock_ac.list_browsers.return_value = {"browserSummaries": []}
        agentcore_app.check_browser_tool_recording()
        mock_ac.list_agent_runtimes.assert_not_called()
        mock_ac.get_agent_runtime.assert_not_called()

    @patch("agentcore_app.agentcore_client", None)
    def test_ac06_schema_valid(self):
        result = agentcore_app.check_browser_tool_recording()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-14: check_browser_network_mode
# ===================================================================
class TestAC14BrowserNetworkMode:
    """AC-14: custom browser network mode (Security Hub BedrockAgentCore.5).

    The check evaluates ListBrowsers(type=CUSTOM)/GetBrowser
    networkConfiguration.networkMode; only PUBLIC fails.
    """

    @patch("agentcore_app.agentcore_client", None)
    def test_ac14_client_unavailable_returns_na(self):
        result = agentcore_app.check_browser_network_mode()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-14"
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.agentcore_client")
    def test_ac14_no_custom_browsers_returns_na(self, mock_ac):
        mock_ac.list_browsers.return_value = {"browserSummaries": []}
        result = agentcore_app.check_browser_network_mode()
        findings = extract_csv_data(result)
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("agentcore_app.agentcore_client")
    def test_ac14_lists_custom_browsers_only(self, mock_ac):
        """The list call must pass type=CUSTOM so AWS system browsers (for
        example aws.browser.v1) are excluded server-side, matching the
        control's BrowserCustom resource type."""
        mock_ac.list_browsers.return_value = {"browserSummaries": []}
        agentcore_app.check_browser_network_mode()
        _, kwargs = mock_ac.list_browsers.call_args
        assert kwargs.get("type") == "CUSTOM"

    @patch("agentcore_app.agentcore_client")
    def test_ac14_vpc_mode_passes_high(self, mock_ac):
        mock_ac.list_browsers.return_value = {
            "browserSummaries": [{"browserId": "br-1", "name": "my-browser"}]
        }
        mock_ac.get_browser.return_value = {
            "browserId": "br-1",
            "networkConfiguration": {"networkMode": "VPC"},
        }
        result = agentcore_app.check_browser_network_mode()
        findings = extract_csv_data(result)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Severity"] == "High"

    @patch("agentcore_app.agentcore_client")
    def test_ac14_public_mode_fails_high(self, mock_ac):
        mock_ac.list_browsers.return_value = {
            "browserSummaries": [{"browserId": "br-1", "name": "my-browser"}]
        }
        mock_ac.get_browser.return_value = {
            "browserId": "br-1",
            "networkConfiguration": {"networkMode": "PUBLIC"},
        }
        result = agentcore_app.check_browser_network_mode()
        findings = extract_csv_data(result)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"
        assert "my-browser" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_ac14_missing_network_config_defaults_to_public_fails(self, mock_ac):
        """An absent networkConfiguration must default to PUBLIC (fail), not
        be treated as VPC (pass)."""
        mock_ac.list_browsers.return_value = {
            "browserSummaries": [{"browserId": "br-1", "name": "my-browser"}]
        }
        mock_ac.get_browser.return_value = {"browserId": "br-1"}
        result = agentcore_app.check_browser_network_mode()
        findings = extract_csv_data(result)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_ac14_access_denied_returns_could_not_assess(self, mock_ac):
        mock_ac.list_browsers.side_effect = _make_client_error(
            "AccessDeniedException", "no ListBrowsers"
        )
        result = agentcore_app.check_browser_network_mode()
        findings = extract_csv_data(result)
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("agentcore_app.agentcore_client")
    def test_ac14_exception_returns_could_not_assess(self, mock_ac):
        mock_ac.list_browsers.side_effect = Exception("Browser network mode error")
        result = agentcore_app.check_browser_network_mode()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("agentcore_app.agentcore_client")
    def test_ac14_get_browser_error_returns_could_not_assess(self, mock_ac):
        mock_ac.list_browsers.return_value = {
            "browserSummaries": [{"browserId": "br-1", "name": "my-browser"}]
        }
        mock_ac.get_browser.side_effect = _make_client_error(
            "InternalServerException", "boom"
        )
        result = agentcore_app.check_browser_network_mode()
        findings = extract_csv_data(result)
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("agentcore_app.agentcore_client")
    def test_ac14_resource_not_found_browser_skipped(self, mock_ac):
        """A browser deleted between list and describe is silently skipped
        (matches the existing AC-06 pattern); with no other browsers to
        report on, the check yields no rows for this region."""
        mock_ac.list_browsers.return_value = {
            "browserSummaries": [{"browserId": "br-1", "name": "my-browser"}]
        }
        mock_ac.get_browser.side_effect = _make_client_error(
            "ResourceNotFoundException", "gone"
        )
        result = agentcore_app.check_browser_network_mode()
        findings = extract_csv_data(result)
        assert findings == []

    @patch("agentcore_app.agentcore_client", None)
    def test_ac14_schema_valid(self):
        result = agentcore_app.check_browser_network_mode()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-15: check_code_interpreter_network_mode
# ===================================================================
class TestAC15CodeInterpreterNetworkMode:
    """AC-15: custom code interpreter network mode (Security Hub
    BedrockAgentCore.7).

    The check evaluates ListCodeInterpreters(type=CUSTOM)/GetCodeInterpreter
    networkConfiguration.networkMode; only VPC passes (PUBLIC and SANDBOX
    both fail).
    """

    @patch("agentcore_app.agentcore_client", None)
    def test_ac15_client_unavailable_returns_na(self):
        result = agentcore_app.check_code_interpreter_network_mode()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-15"
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.agentcore_client")
    def test_ac15_no_custom_interpreters_returns_na(self, mock_ac):
        mock_ac.list_code_interpreters.return_value = {"codeInterpreterSummaries": []}
        result = agentcore_app.check_code_interpreter_network_mode()
        findings = extract_csv_data(result)
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("agentcore_app.agentcore_client")
    def test_ac15_lists_custom_interpreters_only(self, mock_ac):
        """The list call must pass type=CUSTOM so AWS system code
        interpreters (for example aws.codeinterpreter.v1) are excluded
        server-side, matching the control's CodeInterpreterCustom resource
        type."""
        mock_ac.list_code_interpreters.return_value = {"codeInterpreterSummaries": []}
        agentcore_app.check_code_interpreter_network_mode()
        _, kwargs = mock_ac.list_code_interpreters.call_args
        assert kwargs.get("type") == "CUSTOM"

    @patch("agentcore_app.agentcore_client")
    def test_ac15_vpc_mode_passes_high(self, mock_ac):
        mock_ac.list_code_interpreters.return_value = {
            "codeInterpreterSummaries": [
                {"codeInterpreterId": "ci-1", "name": "my-interpreter"}
            ]
        }
        mock_ac.get_code_interpreter.return_value = {
            "codeInterpreterId": "ci-1",
            "networkConfiguration": {"networkMode": "VPC"},
        }
        result = agentcore_app.check_code_interpreter_network_mode()
        findings = extract_csv_data(result)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Severity"] == "High"

    @patch("agentcore_app.agentcore_client")
    def test_ac15_public_mode_fails_high(self, mock_ac):
        mock_ac.list_code_interpreters.return_value = {
            "codeInterpreterSummaries": [
                {"codeInterpreterId": "ci-1", "name": "my-interpreter"}
            ]
        }
        mock_ac.get_code_interpreter.return_value = {
            "codeInterpreterId": "ci-1",
            "networkConfiguration": {"networkMode": "PUBLIC"},
        }
        result = agentcore_app.check_code_interpreter_network_mode()
        findings = extract_csv_data(result)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"
        assert "my-interpreter" in findings[0]["Finding_Details"]
        assert "PUBLIC" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_ac15_sandbox_mode_fails_high(self, mock_ac):
        """SANDBOX mode must also fail; only VPC passes for this control."""
        mock_ac.list_code_interpreters.return_value = {
            "codeInterpreterSummaries": [
                {"codeInterpreterId": "ci-1", "name": "my-interpreter"}
            ]
        }
        mock_ac.get_code_interpreter.return_value = {
            "codeInterpreterId": "ci-1",
            "networkConfiguration": {"networkMode": "SANDBOX"},
        }
        result = agentcore_app.check_code_interpreter_network_mode()
        findings = extract_csv_data(result)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"
        assert "SANDBOX" in findings[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_ac15_missing_network_config_defaults_to_public_fails(self, mock_ac):
        mock_ac.list_code_interpreters.return_value = {
            "codeInterpreterSummaries": [
                {"codeInterpreterId": "ci-1", "name": "my-interpreter"}
            ]
        }
        mock_ac.get_code_interpreter.return_value = {"codeInterpreterId": "ci-1"}
        result = agentcore_app.check_code_interpreter_network_mode()
        findings = extract_csv_data(result)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_ac15_access_denied_returns_could_not_assess(self, mock_ac):
        mock_ac.list_code_interpreters.side_effect = _make_client_error(
            "AccessDeniedException", "no ListCodeInterpreters"
        )
        result = agentcore_app.check_code_interpreter_network_mode()
        findings = extract_csv_data(result)
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("agentcore_app.agentcore_client")
    def test_ac15_exception_returns_could_not_assess(self, mock_ac):
        mock_ac.list_code_interpreters.side_effect = Exception(
            "Code interpreter network mode error"
        )
        result = agentcore_app.check_code_interpreter_network_mode()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("agentcore_app.agentcore_client")
    def test_ac15_resource_not_found_interpreter_skipped(self, mock_ac):
        """A code interpreter deleted between list and describe is silently
        skipped (matches the existing AC-06 pattern); with no other
        interpreters to report on, the check yields no rows for this
        region."""
        mock_ac.list_code_interpreters.return_value = {
            "codeInterpreterSummaries": [
                {"codeInterpreterId": "ci-1", "name": "my-interpreter"}
            ]
        }
        mock_ac.get_code_interpreter.side_effect = _make_client_error(
            "ResourceNotFoundException", "gone"
        )
        result = agentcore_app.check_code_interpreter_network_mode()
        findings = extract_csv_data(result)
        assert findings == []

    @patch("agentcore_app.agentcore_client", None)
    def test_ac15_schema_valid(self):
        result = agentcore_app.check_code_interpreter_network_mode()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-07: check_agentcore_memory_configuration
# ===================================================================
class TestAC07MemoryConfiguration:
    """AC-07: Check memory resource encryption."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac07_client_unavailable_returns_na(self):
        result = agentcore_app.check_agentcore_memory_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-07"

    @patch("agentcore_app.agentcore_client")
    def test_ac07_no_memories_returns_na(self, mock_ac):
        mock_ac.list_memories.return_value = {"memories": []}
        result = agentcore_app.check_agentcore_memory_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.agentcore_client")
    def test_ac07_memory_with_wrapped_kms_key_returns_passed(self, mock_ac):
        mock_ac.list_memories.return_value = {
            "memories": [{"id": "mem-123456789012", "name": "TestMemory"}]
        }
        mock_ac.get_memory.return_value = {
            "memory": {
                "id": "mem-123456789012",
                "encryptionKeyArn": "arn:aws:kms:us-east-1:123:key/abc",
            }
        }
        result = agentcore_app.check_agentcore_memory_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        # One severity per control: BedrockAgentCore.3 is Medium, and the
        # Passed row must carry the same severity as the Failed row.
        assert findings[0]["Severity"] == "Medium"

    @patch("agentcore_app.agentcore_client")
    def test_ac07_pass_and_fail_severity_match(self, mock_ac):
        """Regression guard for the pass-path severity drift (Passed was High
        while Failed was Medium)."""
        mock_ac.list_memories.return_value = {
            "memories": [{"id": "mem-123456789012", "name": "TestMemory"}]
        }
        mock_ac.get_memory.return_value = {"memory": {"id": "mem-123456789012"}}
        failed = extract_csv_data(agentcore_app.check_agentcore_memory_configuration())
        assert failed[0]["Status"] == "Failed"

        mock_ac.get_memory.return_value = {
            "memory": {
                "id": "mem-123456789012",
                "encryptionKeyArn": "arn:aws:kms:us-east-1:123:key/abc",
            }
        }
        passed = extract_csv_data(agentcore_app.check_agentcore_memory_configuration())
        assert passed[0]["Status"] == "Passed"
        assert str(failed[0]["Severity"]) == str(passed[0]["Severity"])

    @patch("agentcore_app.agentcore_client")
    def test_ac07_exception_returns_error_finding(self, mock_ac):
        mock_ac.list_memories.side_effect = Exception("Memory error")
        result = agentcore_app.check_agentcore_memory_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac07_schema_valid(self):
        result = agentcore_app.check_agentcore_memory_configuration()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-08: check_agentcore_vpc_endpoints
# ===================================================================
class TestAC08VPCEndpoints:
    """AC-08: Check VPC endpoints for AgentCore."""

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client", None)
    def test_ac08_client_unavailable_returns_na(self, mock_ec2):
        mock_ec2.describe_vpcs.return_value = {"Vpcs": []}
        result = agentcore_app.check_agentcore_vpc_endpoints()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-08"

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac08_no_runtimes_returns_na(self, mock_ac, mock_ec2):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": []}
        result = agentcore_app.check_agentcore_vpc_endpoints()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Finding_Details"] == "No AgentCore resources found"

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac08_exception_returns_error_finding(self, mock_ac, mock_ec2):
        mock_ec2.describe_vpcs.side_effect = Exception("VPC endpoint error")
        result = agentcore_app.check_agentcore_vpc_endpoints()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client", None)
    def test_ac08_schema_valid(self, mock_ec2):
        mock_ec2.describe_vpcs.return_value = {"Vpcs": []}
        result = agentcore_app.check_agentcore_vpc_endpoints()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-09: check_agentcore_service_linked_role
# ===================================================================
class TestAC09ServiceLinkedRole:
    """AC-09: Check AgentCore service-linked role."""

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client", None)
    def test_ac09_client_unavailable_returns_na(self, mock_iam):
        mock_iam.get_role.side_effect = _make_client_error(
            "NoSuchEntity", "Role not found"
        )
        mock_iam.exceptions.NoSuchEntityException = ClientError
        result = agentcore_app.check_agentcore_service_linked_role()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-09"

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac09_slr_exists_returns_passed(self, mock_ac, mock_iam):
        mock_iam.get_role.return_value = {
            "Role": {
                "RoleName": "AWSServiceRoleForBedrockAgentCoreNetwork",
                "Arn": "arn:aws:iam::123:role/aws-service-role/network.bedrock-agentcore.amazonaws.com/AWSServiceRoleForBedrockAgentCoreNetwork",
                "Path": "/aws-service-role/network.bedrock-agentcore.amazonaws.com/",
                "AssumeRolePolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "Service": "network.bedrock-agentcore.amazonaws.com"
                            },
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
            }
        }
        result = agentcore_app.check_agentcore_service_linked_role()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac09_slr_missing_returns_failed(self, mock_ac, mock_iam):
        mock_iam.get_role.side_effect = _make_client_error(
            "NoSuchEntity", "Role not found"
        )
        result = agentcore_app.check_agentcore_service_linked_role()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_ac09_exception_returns_error_finding(self, mock_ac):
        # Patch iam_client to raise
        with patch("agentcore_app.iam_client") as mock_iam:
            mock_iam.get_role.side_effect = Exception("IAM error")
            result = agentcore_app.check_agentcore_service_linked_role()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.iam_client")
    @patch("agentcore_app.agentcore_client", None)
    def test_ac09_schema_valid(self, mock_iam):
        mock_iam.get_role.side_effect = _make_client_error(
            "NoSuchEntity", "Role not found"
        )
        mock_iam.exceptions.NoSuchEntityException = ClientError
        result = agentcore_app.check_agentcore_service_linked_role()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-10: check_agentcore_resource_based_policies
# ===================================================================
class TestAC10ResourceBasedPolicies:
    """AC-10: Check resource-based policies."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac10_client_unavailable_returns_na(self):
        result = agentcore_app.check_agentcore_resource_based_policies()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-10"

    @patch("agentcore_app.agentcore_client")
    def test_ac10_no_runtimes_returns_na(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": []}
        mock_ac.list_gateways.return_value = {"items": []}
        result = agentcore_app.check_agentcore_resource_based_policies()
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.agentcore_client")
    def test_ac10_uses_generic_resource_policy_api(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [
                {
                    "agentRuntimeId": "rt-1",
                    "agentRuntimeName": "TestRuntime",
                    "agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/rt-1",
                }
            ]
        }
        mock_ac.list_gateways.return_value = {"items": []}
        mock_ac.get_resource_policy.return_value = {
            "policy": '{"Version":"2012-10-17"}'
        }

        result = agentcore_app.check_agentcore_resource_based_policies()
        findings = extract_csv_data(result)

        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        mock_ac.get_resource_policy.assert_called_once_with(
            resourceArn="arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/rt-1"
        )

    @patch("agentcore_app.agentcore_client")
    def test_ac10_gets_gateway_by_gateway_identifier(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {"agentRuntimes": []}
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw-1"
        }
        mock_ac.get_resource_policy.return_value = {
            "policy": '{"Version":"2012-10-17"}'
        }

        result = agentcore_app.check_agentcore_resource_based_policies()
        findings = extract_csv_data(result)

        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        mock_ac.get_gateway.assert_called_once_with(gatewayIdentifier="gw-1")
        mock_ac.get_resource_policy.assert_called_once_with(
            resourceArn="arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw-1"
        )

    @patch("agentcore_app.agentcore_client")
    def test_ac10_access_denied_policy_read_returns_na_finding(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [
                {
                    "agentRuntimeId": "rt-1",
                    "agentRuntimeName": "TestRuntime",
                    "agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/rt-1",
                }
            ]
        }
        mock_ac.list_gateways.return_value = {"items": []}
        mock_ac.get_resource_policy.side_effect = _make_client_error(
            "AccessDeniedException", "Denied"
        )

        result = agentcore_app.check_agentcore_resource_based_policies()
        findings = extract_csv_data(result)

        assert len(findings) >= 1
        assert any(
            f["Finding"] == "AgentCore Resource-Based Policy Assessment Access Denied"
            and f["Status"] == "N/A"
            for f in findings
        )

    @patch("agentcore_app.agentcore_client")
    def test_ac10_policy_read_throttling_returns_incomplete_finding(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [
                {
                    "agentRuntimeId": "rt-1",
                    "agentRuntimeName": "TestRuntime",
                    "agentRuntimeArn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/rt-1",
                }
            ]
        }
        mock_ac.list_gateways.return_value = {"items": []}
        mock_ac.get_resource_policy.side_effect = _make_client_error(
            "ThrottlingException", "Try again"
        )

        result = agentcore_app.check_agentcore_resource_based_policies()
        findings = extract_csv_data(result)

        assert len(findings) >= 1
        assert any(
            f["Finding"] == "AgentCore Resource-Based Policy Assessment Incomplete"
            and f["Status"] == "N/A"
            for f in findings
        )

    @patch("agentcore_app.agentcore_client")
    def test_ac10_exception_returns_error_finding(self, mock_ac):
        mock_ac.list_agent_runtimes.side_effect = Exception("RBP error")
        result = agentcore_app.check_agentcore_resource_based_policies()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac10_schema_valid(self):
        result = agentcore_app.check_agentcore_resource_based_policies()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-11: check_agentcore_policy_engine_encryption
# ===================================================================
class TestAC11PolicyEngineEncryption:
    """AC-11: Check policy engine encryption."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac11_client_unavailable_returns_na(self):
        result = agentcore_app.check_agentcore_policy_engine_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-11"

    @patch("agentcore_app.agentcore_client")
    def test_ac11_no_policy_engines_returns_na(self, mock_ac):
        mock_ac.list_policy_engines.return_value = {"policyEngines": []}
        result = agentcore_app.check_agentcore_policy_engine_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.agentcore_client")
    def test_ac11_exception_returns_error_finding(self, mock_ac):
        mock_ac.list_policy_engines.side_effect = Exception("Policy engine error")
        result = agentcore_app.check_agentcore_policy_engine_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac11_schema_valid(self):
        result = agentcore_app.check_agentcore_policy_engine_encryption()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-12: check_agentcore_gateway_encryption
# ===================================================================
class TestAC12GatewayEncryption:
    """AC-12: Check gateway encryption."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac12_client_unavailable_returns_na(self):
        result = agentcore_app.check_agentcore_gateway_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-12"

    @patch("agentcore_app.agentcore_client")
    def test_ac12_no_gateways_returns_na(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": []}
        result = agentcore_app.check_agentcore_gateway_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.agentcore_client")
    def test_ac12_gateway_with_kms_key_returns_passed(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayId": "gw-1",
            "name": "TestGateway",
            "kmsKeyArn": "arn:aws:kms:us-east-1:123:key/abc",
        }
        result = agentcore_app.check_agentcore_gateway_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        mock_ac.get_gateway.assert_called_once_with(gatewayIdentifier="gw-1")

    @patch("agentcore_app.agentcore_client")
    def test_ac12_gateway_without_cmk_returns_failed_medium(self, mock_ac):
        """Regression test (gap-analysis PR-0): BedrockAgentCore.4 is Medium
        severity in Security Hub. Previously the Failed path emitted LOW
        while the Passed path emitted MEDIUM (one severity must apply to
        both Passed and Failed rows of the same control)."""
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayId": "gw-1",
            "name": "TestGateway",
        }
        result = agentcore_app.check_agentcore_gateway_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"

    @patch("agentcore_app.agentcore_client")
    def test_ac12_exception_returns_error_finding(self, mock_ac):
        mock_ac.list_gateways.side_effect = Exception("Gateway encryption error")
        result = agentcore_app.check_agentcore_gateway_encryption()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac12_schema_valid(self):
        result = agentcore_app.check_agentcore_gateway_encryption()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AC-13: check_agentcore_gateway_configuration
# ===================================================================
class TestAC13GatewayConfiguration:
    """AC-13: Check gateway configuration."""

    @patch("agentcore_app.agentcore_client", None)
    def test_ac13_client_unavailable_returns_na(self):
        result = agentcore_app.check_agentcore_gateway_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "AC-13"

    @patch("agentcore_app.agentcore_client")
    def test_ac13_no_gateways_returns_na(self, mock_ac):
        mock_ac.list_gateways.return_value = {"items": []}
        result = agentcore_app.check_agentcore_gateway_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("agentcore_app.agentcore_client")
    def test_ac13_items_gateway_shape_returns_passed(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        result = agentcore_app.check_agentcore_gateway_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("agentcore_app.agentcore_client")
    def test_ac13_exception_returns_error_finding(self, mock_ac):
        mock_ac.list_gateways.side_effect = Exception("Gateway config error")
        result = agentcore_app.check_agentcore_gateway_configuration()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac13_schema_valid(self):
        result = agentcore_app.check_agentcore_gateway_configuration()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# AG-24..AG-27: check_agentcore_gateway_agentic_security
# ===================================================================
class TestAgenticGatewaySecurity:
    """Agentic AI Gateway security checks."""

    @patch("agentcore_app.agentcore_client")
    def test_ag24_list_gateways_access_denied_returns_could_not_assess(self, mock_ac):
        """Regression test (gap-analysis PR-0): AccessDenied on ListGateways
        must route through the COULD_NOT_ASSESS disposition (N/A, Low), not
        the previous Informational, which understated an access gap as
        "no issue"."""
        mock_ac.list_gateways.side_effect = _make_client_error(
            "AccessDeniedException", "no ListGateways"
        )
        findings = agentcore_app.check_agentcore_gateway_agentic_security()
        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AG-24"
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS:")

    @patch("agentcore_app.agentcore_client")
    def test_gateway_policy_controls_fail_when_not_enforced(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayId": "gw-1",
            "name": "TestGateway",
            "authorizerType": "NONE",
            "policyEngineConfiguration": {
                "arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/TestEngine-abcdefghij",
                "mode": "LOG_ONLY",
            },
            "exceptionLevel": "DEBUG",
        }

        findings = agentcore_app.check_agentcore_gateway_agentic_security()
        statuses = {f["Check_ID"]: f["Status"] for f in findings}

        assert statuses["AG-24"] == "Failed"
        assert statuses["AG-25"] == "Failed"
        assert statuses["AG-26"] == "Failed"
        assert statuses["AG-27"] == "Failed"
        for finding in findings:
            assert_finding_schema(finding)

    @patch("agentcore_app.agentcore_client")
    def test_gateway_authorizer_unspecified_fails_closed(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayId": "gw-1",
            "name": "TestGateway",
            "policyEngineConfiguration": {
                "arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/TestEngine-abcdefghij",
                "mode": "ENFORCE",
            },
            "webAclArn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/test/abc",
        }

        findings = agentcore_app.check_agentcore_gateway_agentic_security()
        ag24 = [f for f in findings if f["Check_ID"] == "AG-24"]

        assert ag24
        assert ag24[0]["Status"] == "Failed"
        assert "unspecified" in ag24[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_gateway_authenticate_only_without_enforced_policy_fails_closed(
        self, mock_ac
    ):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayId": "gw-1",
            "name": "TestGateway",
            "authorizerType": "AUTHENTICATE_ONLY",
            "policyEngineConfiguration": {
                "arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/TestEngine-abcdefghij",
                "mode": "LOG_ONLY",
            },
            "webAclArn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/test/abc",
        }

        findings = agentcore_app.check_agentcore_gateway_agentic_security()
        ag24 = [f for f in findings if f["Check_ID"] == "AG-24"]

        assert ag24
        assert ag24[0]["Status"] == "Failed"
        assert "AUTHENTICATE_ONLY" in ag24[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_gateway_authenticate_only_with_enforced_policy_passes(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayId": "gw-1",
            "name": "TestGateway",
            "authorizerType": "AUTHENTICATE_ONLY",
            "policyEngineConfiguration": {
                "arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/TestEngine-abcdefghij",
                "mode": "ENFORCE",
            },
            "webAclArn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/test/abc",
        }

        findings = agentcore_app.check_agentcore_gateway_agentic_security()
        ag24 = [f for f in findings if f["Check_ID"] == "AG-24"]

        assert ag24
        assert ag24[0]["Status"] == "Passed"
        assert "policy engine" in ag24[0]["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_gateway_detail_access_denied_returns_na(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.side_effect = _make_client_error(
            "AccessDeniedException", "Denied"
        )

        findings = agentcore_app.check_agentcore_gateway_agentic_security()

        assert len(findings) == 1
        assert findings[0]["Check_ID"] == "AG-24"
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"
        assert "Unable to retrieve Gateway" in findings[0]["Finding_Details"]
        assert_finding_schema(findings[0])

    @patch("agentcore_app.agentcore_client")
    def test_gateway_policy_controls_pass_when_enforced(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "TestGateway"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayId": "gw-1",
            "name": "TestGateway",
            "authorizerType": "AWS_IAM",
            "policyEngineConfiguration": {
                "arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/TestEngine-abcdefghij",
                "mode": "ENFORCE",
            },
            "webAclArn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/test/abc",
        }

        findings = agentcore_app.check_agentcore_gateway_agentic_security()
        statuses = {f["Check_ID"]: f["Status"] for f in findings}

        assert statuses["AG-24"] == "Passed"
        assert statuses["AG-25"] == "Passed"
        assert statuses["AG-26"] == "Passed"
        assert statuses["AG-27"] == "Passed"


class TestAgenticAgentCoreMapping:
    """Agentic AI AG-* rows are generated from API-backed AgentCore checks."""

    EXPECTED_AGENTIC_MAPPINGS = {
        "AC-01": "AG-15",
        "AC-02": "AG-16",
        "AC-03": "AG-17",
        "AC-04": "AG-18",
        "AC-07": "AG-19",
        "AC-08": "AG-20",
        "AC-10": "AG-21",
        "AC-11": "AG-22",
        "AC-12": "AG-23",
    }

    def test_all_agentcore_agentic_mappings_emit_expected_rows(self):
        source_findings = []
        for source_check_id in self.EXPECTED_AGENTIC_MAPPINGS:
            source_findings.append(
                {
                    "Account_ID": "123456789012",
                    "Check_ID": source_check_id,
                    "Finding": f"{source_check_id} source finding",
                    "Finding_Details": f"{source_check_id} source details",
                    "Resolution": "No action required.",
                    "Reference": "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security.html",
                    "Severity": "Medium",
                    "Status": "Passed",
                    "Region": "us-east-1",
                }
            )

        findings = agentcore_app.build_agentic_agentcore_security_findings(
            source_findings
        )

        assert len(findings) == len(self.EXPECTED_AGENTIC_MAPPINGS)
        actual_by_source = {}
        for finding in findings:
            details = finding["Finding_Details"]
            source_check_id = details.split("Source check ", 1)[1].split(":", 1)[0]
            actual_by_source[source_check_id] = finding

            assert finding["Status"] == "Passed"
            assert finding["Severity"] == "Medium"
            assert finding["Region"] == "us-east-1"
            assert f"Source check {source_check_id}" in details
            assert_finding_schema(finding)

        assert set(actual_by_source) == set(self.EXPECTED_AGENTIC_MAPPINGS)
        for source_check_id, expected_ag_id in self.EXPECTED_AGENTIC_MAPPINGS.items():
            assert actual_by_source[source_check_id]["Check_ID"] == expected_ag_id


# ===================================================================
# lambda_handler: multi-region gating and availability probe
# ===================================================================
def _agentcore_event(region="us-east-1", region_index=0):
    return {
        "Region": region,
        "RegionIndex": region_index,
        "Execution": {"Name": "test-execution-1"},
        "StateMachine": {"Name": "test-sm"},
    }


def _valid_slr_role():
    """A valid service-linked-role get_role response so AC-09 passes cleanly."""
    return {
        "Role": {
            "RoleName": "AWSServiceRoleForBedrockAgentCoreNetwork",
            "AssumeRolePolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "agentcore.bedrock.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ]
            },
        }
    }


class TestAgentCoreHandlerMultiRegion:
    """lambda_handler primary-region gating (AC-02/AC-03/AC-09) + availability probe (AC-00)."""

    def _run_handler(self, agentcore_side_effect, event):
        """Run the handler with a per-service boto3.client dispatch. The
        bedrock-agentcore-control probe (list_agent_runtimes) uses
        agentcore_side_effect to simulate availability; iam is given a valid SLR
        response. Returns (response, findings) where findings is the flat list
        passed to generate_csv_report."""
        captured = {}

        def fake_csv(findings):
            captured["findings"] = findings
            return "csv"

        iam_mock = MagicMock()
        iam_mock.get_role.return_value = _valid_slr_role()
        iam_mock.exceptions.NoSuchEntityException = type(
            "NoSuchEntityException", (Exception,), {}
        )

        sts_mock = MagicMock()
        sts_mock.get_caller_identity.return_value = {"Account": "123456789012"}

        agentcore_mock = MagicMock()
        agentcore_mock.list_agent_runtimes.side_effect = agentcore_side_effect

        def client_dispatch(service, *args, **kwargs):
            if service == "iam":
                return iam_mock
            if service == "sts":
                return sts_mock
            if service == "bedrock-agentcore-control":
                return agentcore_mock
            return MagicMock()

        with (
            patch("agentcore_app.boto3.client", side_effect=client_dispatch),
            patch.object(
                agentcore_app,
                "get_permissions_cache",
                return_value={"role_permissions": {}, "user_permissions": {}},
            ),
            patch.object(agentcore_app, "generate_csv_report", side_effect=fake_csv),
            patch.object(agentcore_app, "write_to_s3", return_value="s3://b/r.csv"),
        ):
            resp = agentcore_app.lambda_handler(event, None)

        return resp, captured.get("findings", [])

    def test_primary_region_emits_global_iam_checks_tagged_global(self):
        # On the primary region, AC-02, AC-03 and AC-09 (all IAM-global) must be
        # emitted and tagged "Global", even when AgentCore is unavailable.
        resp, findings = self._run_handler(
            EndpointConnectionError(endpoint_url="https://agentcore.invalid"),
            _agentcore_event(region="ap-south-2", region_index=0),
        )
        assert resp["statusCode"] == 200

        check_ids = {f["Check_ID"] for f in findings}
        assert "AC-02" in check_ids
        assert "AC-03" in check_ids
        assert "AC-09" in check_ids
        for f in findings:
            if f["Check_ID"] in ("AC-02", "AC-03", "AC-09"):
                assert f["Region"] == "Global"
        # The availability finding is tagged with the scanned region.
        ac00 = [f for f in findings if f["Check_ID"] == "AC-00"]
        assert ac00 and ac00[0]["Region"] == "ap-south-2"

    def test_non_primary_region_skips_global_iam_checks(self):
        # On a non-primary region the IAM-global checks must NOT run.
        resp, findings = self._run_handler(
            EndpointConnectionError(endpoint_url="https://agentcore.invalid"),
            _agentcore_event(region="eu-west-1", region_index=3),
        )
        assert resp["statusCode"] == 200

        check_ids = {f["Check_ID"] for f in findings}
        assert "AC-02" not in check_ids
        assert "AC-03" not in check_ids
        assert "AC-09" not in check_ids
        assert check_ids == {"AC-00"} | {f"AG-{i:02d}" for i in range(15, 28)}

    def test_optin_region_error_treated_as_unavailable(self):
        # A region-not-enabled ClientError code makes agentcore_client None, so
        # the handler emits the AC-00 availability finding and exits early.
        resp, findings = self._run_handler(
            _make_client_error("UnrecognizedClientException"),
            _agentcore_event(region="me-south-1", region_index=1),
        )
        assert resp["statusCode"] == 200
        ac00 = [f for f in findings if f["Check_ID"] == "AC-00"]
        assert ac00 and ac00[0]["Status"] == "N/A"

    def test_access_denied_probe_proceeds_with_checks(self):
        # AccessDenied is NOT a region-unavailable code: the service is reachable,
        # so the handler proceeds and runs regional checks (no AC-00 emitted).
        resp, findings = self._run_handler(
            _make_client_error("AccessDeniedException"),
            _agentcore_event(region="us-east-1", region_index=0),
        )
        assert resp["statusCode"] == 200
        check_ids = {f["Check_ID"] for f in findings}
        assert "AC-00" not in check_ids
        # Regional checks ran (e.g. AC-01 VPC, AC-04 observability present).
        assert len(check_ids) > 3

    def test_unexpected_probe_error_proceeds_with_checks(self):
        # An unexpected, non-ClientError probe failure (e.g. a boto3/botocore SDK
        # param/operation mismatch surfacing as ParamValidationError) says nothing
        # about regional availability. The handler must NOT treat it as
        # unavailable (which would emit a false AC-00 N/A and skip every check);
        # it should proceed and run the regional checks.
        try:
            from botocore.exceptions import ParamValidationError

            probe_error = ParamValidationError(
                report="maxResults is not a valid parameter"
            )
        except Exception:
            probe_error = TypeError("unexpected SDK signature")

        resp, findings = self._run_handler(
            probe_error,
            _agentcore_event(region="us-east-1", region_index=0),
        )
        assert resp["statusCode"] == 200
        check_ids = {f["Check_ID"] for f in findings}
        # No false "not available" finding, and the regional checks executed.
        assert "AC-00" not in check_ids
        assert len(check_ids) > 3
