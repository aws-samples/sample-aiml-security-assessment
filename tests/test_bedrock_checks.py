"""
Tests for Bedrock security assessment checks (BR-01 through BR-13).

Each check is tested for:
- No resources / empty cache -> N/A status
- Compliant resources -> Passed status
- Non-compliant resources -> Failed with correct severity
- Exception handling -> returns error finding (csv_data not empty)
- Output schema validity
"""

import contextlib
import sys
import os
import importlib.util
from unittest.mock import patch, MagicMock
from botocore.exceptions import EndpointConnectionError, ClientError

from tests.test_helpers import extract_csv_data, assert_finding_schema

# Load bedrock app module directly to avoid name collisions with other app.py files
_bedrock_dir = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "aiml-security-assessment/functions/security/bedrock_assessments",
    )
)
if _bedrock_dir not in sys.path:
    sys.path.insert(0, _bedrock_dir)

_spec = importlib.util.spec_from_file_location(
    "bedrock_app", os.path.join(_bedrock_dir, "app.py")
)
bedrock_app = importlib.util.module_from_spec(_spec)
sys.modules["bedrock_app"] = bedrock_app
_spec.loader.exec_module(bedrock_app)


# ===================================================================
# BR-01: check_bedrock_full_access_roles
# ===================================================================
class TestBR01FullAccessRoles:
    """BR-01: Check for roles with AmazonBedrockFullAccess policy."""

    def test_br01_no_roles_with_full_access_returns_passed(
        self, empty_permission_cache
    ):
        check = bedrock_app.check_bedrock_full_access_roles
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "BR-01"

    def test_br01_role_with_full_access_returns_failed(
        self, permission_cache_with_full_access
    ):
        check = bedrock_app.check_bedrock_full_access_roles
        result = check(permission_cache_with_full_access)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"
        assert "FullAccessRole" in findings[0]["Finding_Details"]

    def test_br01_compliant_roles_returns_passed(self, permission_cache_compliant):
        check = bedrock_app.check_bedrock_full_access_roles
        result = check(permission_cache_compliant)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    def test_br01_schema_valid(self, permission_cache_with_full_access):
        check = bedrock_app.check_bedrock_full_access_roles
        result = check(permission_cache_with_full_access)
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-02: check_bedrock_access_and_vpc_endpoints
# ===================================================================
class TestBR02VPCEndpoints:
    """BR-02: Check Bedrock access and VPC endpoints."""

    def test_br02_no_bedrock_access_returns_no_findings(self, empty_permission_cache):
        check = bedrock_app.check_bedrock_access_and_vpc_endpoints
        result = check(empty_permission_cache)
        # When no bedrock access found, csv_data may be empty or have info finding
        assert "csv_data" in result

    @patch("bedrock_app.check_bedrock_vpc_endpoints")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br02_bedrock_access_with_endpoints_returns_passed(
        self, mock_footprint, mock_vpc, permission_cache_compliant
    ):
        check = bedrock_app.check_bedrock_access_and_vpc_endpoints
        mock_vpc.return_value = {
            "has_endpoints": True,
            "found_endpoints": [
                {
                    "vpc_id": "vpc-123",
                    "service": "com.amazonaws.us-east-1.bedrock-runtime",
                }
            ],
            "all_vpcs": ["vpc-123"],
        }
        result = check(permission_cache_compliant)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "BR-02"

    @patch("bedrock_app.check_bedrock_vpc_endpoints")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br02_bedrock_access_no_endpoints_returns_failed(
        self, mock_footprint, mock_vpc, permission_cache_compliant
    ):
        check = bedrock_app.check_bedrock_access_and_vpc_endpoints
        mock_vpc.return_value = {
            "has_endpoints": False,
            "found_endpoints": [],
            "all_vpcs": ["vpc-123"],
        }
        result = check(permission_cache_compliant)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"

    @patch("bedrock_app.check_bedrock_vpc_endpoints")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=False)
    def test_br02_no_regional_footprint_returns_na(
        self, mock_footprint, mock_vpc, permission_cache_compliant
    ):
        check = bedrock_app.check_bedrock_access_and_vpc_endpoints
        result = check(permission_cache_compliant, region="eu-west-3")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Finding_Details"] == (
            "No regional Bedrock resources found to assess private connectivity"
        )
        mock_vpc.assert_not_called()

    @patch("bedrock_app.check_bedrock_vpc_endpoints")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br02_exception_returns_error_finding(
        self, mock_footprint, mock_vpc, permission_cache_compliant
    ):
        check = bedrock_app.check_bedrock_access_and_vpc_endpoints
        mock_vpc.side_effect = Exception("VPC check failed")
        result = check(permission_cache_compliant)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert "Error" in findings[0]["Finding_Details"]

    @patch("bedrock_app.check_bedrock_vpc_endpoints")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br02_schema_valid(
        self, mock_footprint, mock_vpc, permission_cache_compliant
    ):
        check = bedrock_app.check_bedrock_access_and_vpc_endpoints
        mock_vpc.return_value = {
            "has_endpoints": True,
            "found_endpoints": [{"vpc_id": "vpc-1", "service": "bedrock"}],
            "all_vpcs": ["vpc-1"],
        }
        result = check(permission_cache_compliant)
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-03: check_marketplace_subscription_access
# ===================================================================
class TestBR03MarketplaceAccess:
    """BR-03: Check marketplace subscription access."""

    def test_br03_no_overpermissive_returns_passed(self, permission_cache_compliant):
        check = bedrock_app.check_marketplace_subscription_access
        result = check(permission_cache_compliant)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "BR-03"

    def test_br03_overpermissive_returns_failed(
        self, permission_cache_marketplace_overpermissive
    ):
        check = bedrock_app.check_marketplace_subscription_access
        result = check(permission_cache_marketplace_overpermissive)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"

    def test_br03_empty_cache_returns_passed(self, empty_permission_cache):
        check = bedrock_app.check_marketplace_subscription_access
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    def test_br03_schema_valid(self, permission_cache_marketplace_overpermissive):
        check = bedrock_app.check_marketplace_subscription_access
        result = check(permission_cache_marketplace_overpermissive)
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-04: check_bedrock_logging_configuration
# ===================================================================
class TestBR04LoggingConfiguration:
    """BR-04: Check model invocation logging."""

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br04_logging_enabled_s3_returns_passed(self, mock_footprint, mock_client):
        check = bedrock_app.check_bedrock_logging_configuration
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {
                "s3Config": {"bucketName": "my-log-bucket"},
                "cloudWatchConfig": {},
            }
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "BR-04"

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br04_logging_disabled_returns_failed(self, mock_footprint, mock_client):
        check = bedrock_app.check_bedrock_logging_configuration
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {"s3Config": {}, "cloudWatchConfig": {}}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=False)
    def test_br04_no_regional_footprint_returns_na(self, mock_footprint, mock_client):
        check = bedrock_app.check_bedrock_logging_configuration
        result = check(region="eu-west-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Finding_Details"] == (
            "No regional Bedrock resources found to monitor with invocation logging"
        )
        mock_client.assert_not_called()

    @patch("boto3.client")
    def test_br04_exception_returns_error_finding(self, mock_client):
        check = bedrock_app.check_bedrock_logging_configuration
        mock_client.side_effect = Exception("Service unavailable")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br04_schema_valid(self, mock_footprint, mock_client):
        check = bedrock_app.check_bedrock_logging_configuration
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {
                "s3Config": {"bucketName": "bucket"},
                "cloudWatchConfig": {},
            }
        }
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    @patch("boto3.client")
    def test_br04_logging_enabled_s3_legacy_key_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_logging_configuration
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {
                "s3Config": {"s3BucketName": "legacy-log-bucket"},
                "cloudWatchConfig": {},
            }
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"


# ===================================================================
# BR-05: check_bedrock_guardrails
# ===================================================================
class TestBR05Guardrails:
    """BR-05: Check Bedrock guardrails exist."""

    @patch("boto3.client")
    def test_br05_guardrails_exist_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_guardrails
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.list_guardrails.return_value = {
            "guardrails": [{"name": "content-filter", "guardrailId": "gr-123"}]
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "BR-05"

    @patch("boto3.client")
    def test_br05_no_guardrails_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_guardrails
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.list_guardrails.return_value = {"guardrails": []}
        with patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True):
            result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"

    @patch("boto3.client")
    def test_br05_no_guardrails_and_no_regional_footprint_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_guardrails
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.list_guardrails.return_value = {"guardrails": []}
        with patch("bedrock_app.detect_bedrock_regional_footprint", return_value=False):
            result = check(region="eu-west-3")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Finding_Details"] == (
            "No regional Bedrock resources found to protect with guardrails"
        )

    @patch("boto3.client")
    def test_br05_exception_returns_error_finding(self, mock_client):
        check = bedrock_app.check_bedrock_guardrails
        mock_client.side_effect = Exception("Access denied")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("boto3.client")
    def test_br05_schema_valid(self, mock_client):
        check = bedrock_app.check_bedrock_guardrails
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.list_guardrails.return_value = {"guardrails": []}
        with patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True):
            result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-06: check_bedrock_cloudtrail_logging
# ===================================================================
class TestBR06CloudTrailLogging:
    """BR-06: Check CloudTrail logging for Bedrock."""

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br06_trail_is_logging_returns_passed(self, mock_footprint, mock_client):
        check = bedrock_app.check_bedrock_cloudtrail_logging
        mock_ct = MagicMock()
        mock_client.return_value = mock_ct
        mock_ct.list_trails.return_value = {
            "Trails": [
                {
                    "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/main",
                    "Name": "main",
                }
            ]
        }
        mock_ct.get_trail.return_value = {"Trail": {"IsMultiRegionTrail": True}}
        mock_ct.get_trail_status.return_value = {"IsLogging": True}
        mock_ct.get_event_selectors.return_value = {
            "EventSelectors": [
                {"IncludeManagementEvents": True, "ReadWriteType": "All"}
            ],
            "AdvancedEventSelectors": [],
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "BR-06"

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br06_no_trails_returns_failed(self, mock_footprint, mock_client):
        check = bedrock_app.check_bedrock_cloudtrail_logging
        mock_ct = MagicMock()
        mock_client.return_value = mock_ct
        mock_ct.list_trails.return_value = {"Trails": []}
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br06_trail_not_logging_returns_failed(self, mock_footprint, mock_client):
        check = bedrock_app.check_bedrock_cloudtrail_logging
        mock_ct = MagicMock()
        mock_client.return_value = mock_ct
        mock_ct.list_trails.return_value = {
            "Trails": [{"TrailARN": "arn:trail", "Name": "trail1"}]
        }
        mock_ct.get_trail.return_value = {"Trail": {"IsMultiRegionTrail": True}}
        mock_ct.get_trail_status.return_value = {"IsLogging": False}
        mock_ct.get_event_selectors.return_value = {
            "EventSelectors": [],
            "AdvancedEventSelectors": [],
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=False)
    def test_br06_no_regional_footprint_returns_na(self, mock_footprint, mock_client):
        check = bedrock_app.check_bedrock_cloudtrail_logging
        result = check(region="eu-west-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Finding_Details"] == (
            "No regional Bedrock resources found to audit with Bedrock-specific CloudTrail coverage"
        )
        mock_client.assert_not_called()

    @patch("boto3.client")
    def test_br06_exception_returns_error_finding(self, mock_client):
        check = bedrock_app.check_bedrock_cloudtrail_logging
        mock_client.side_effect = Exception("CloudTrail error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("boto3.client")
    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    def test_br06_schema_valid(self, mock_footprint, mock_client):
        check = bedrock_app.check_bedrock_cloudtrail_logging
        mock_ct = MagicMock()
        mock_client.return_value = mock_ct
        mock_ct.list_trails.return_value = {"Trails": []}
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-07: check_bedrock_prompt_management
# ===================================================================
class TestBR07PromptManagement:
    """BR-07: Check Bedrock Prompt Management usage."""

    @patch("boto3.client")
    def test_br07_prompts_exist_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_prompt_management
        mock_agent = MagicMock()
        paginator = MagicMock()
        mock_client.return_value = mock_agent
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"promptSummaries": [{"name": "prompt1", "id": "p1"}]}
        ]
        mock_agent.get_prompt.return_value = {"variants": ["v1", "v2"]}
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "BR-07"
        mock_agent.get_prompt.assert_called_once_with(promptIdentifier="p1")

    @patch("boto3.client")
    def test_br07_legacy_prompt_id_fallback_still_supported(self, mock_client):
        check = bedrock_app.check_bedrock_prompt_management
        mock_agent = MagicMock()
        paginator = MagicMock()
        mock_client.return_value = mock_agent
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"promptSummaries": [{"name": "prompt1", "promptId": "p1"}]}
        ]
        mock_agent.get_prompt.return_value = {"variants": ["v1", "v2"]}

        result = check()
        findings = extract_csv_data(result)

        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        mock_agent.get_prompt.assert_called_once_with(promptIdentifier="p1")

    @patch("boto3.client")
    def test_br07_no_prompts_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_prompt_management
        mock_agent = MagicMock()
        paginator = MagicMock()
        mock_client.return_value = mock_agent
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"promptSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"

    @patch("boto3.client")
    def test_br07_exception_returns_error_finding(self, mock_client):
        check = bedrock_app.check_bedrock_prompt_management
        mock_client.side_effect = Exception("Agent error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("boto3.client")
    def test_br07_list_prompts_api_error_returns_na(self, mock_client):
        # An API error (e.g. InternalServerErrorException after retries) is not a
        # security failure; it should surface as N/A, not Failed (matches BR-11).
        check = bedrock_app.check_bedrock_prompt_management
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        mock_agent.list_prompts.side_effect = Exception("InternalServerErrorException")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-07"

    @patch("boto3.client")
    def test_br07_schema_valid(self, mock_client):
        check = bedrock_app.check_bedrock_prompt_management
        mock_agent = MagicMock()
        paginator = MagicMock()
        mock_client.return_value = mock_agent
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"promptSummaries": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-08: check_bedrock_agent_roles
# ===================================================================
class TestBR08AgentRoles:
    """BR-08: Check Bedrock agent IAM roles."""

    @patch("boto3.client")
    def test_br08_no_agents_returns_na(self, mock_client, empty_permission_cache):
        check = bedrock_app.check_bedrock_agent_roles
        mock_agent = MagicMock()
        paginator = MagicMock()
        mock_client.return_value = mock_agent
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"agentSummaries": []}]
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-08"

    @patch("boto3.client")
    def test_br08_agent_with_compliant_role_returns_passed(
        self, mock_client, permission_cache_compliant
    ):
        check = bedrock_app.check_bedrock_agent_roles
        mock_agent = MagicMock()
        paginator = MagicMock()
        mock_client.return_value = mock_agent
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"agentSummaries": [{"agentId": "a1", "agentName": "TestAgent"}]}
        ]
        mock_agent.get_agent.return_value = {
            "agent": {
                "agentResourceRoleArn": "arn:aws:iam::123456789012:role/LeastPrivilegeRole"
            }
        }
        result = check(permission_cache_compliant)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        mock_agent.get_agent.assert_called_once_with(agentId="a1")

    @patch("boto3.client")
    def test_br08_legacy_role_arn_shape_still_supported(
        self, mock_client, permission_cache_compliant
    ):
        check = bedrock_app.check_bedrock_agent_roles
        mock_agent = MagicMock()
        paginator = MagicMock()
        mock_client.return_value = mock_agent
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"agentSummaries": [{"agentId": "a1", "agentName": "TestAgent"}]}
        ]
        mock_agent.get_agent.return_value = {
            "agentResourceRoleArn": "arn:aws:iam::123456789012:role/LeastPrivilegeRole"
        }

        result = check(permission_cache_compliant)
        findings = extract_csv_data(result)

        assert len(findings) >= 1
        mock_agent.get_agent.assert_called_once_with(agentId="a1")

    @patch("boto3.client")
    def test_br08_exception_returns_error_finding(
        self, mock_client, empty_permission_cache
    ):
        check = bedrock_app.check_bedrock_agent_roles
        mock_client.side_effect = Exception("Agent service error")
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("boto3.client")
    def test_br08_schema_valid(self, mock_client, empty_permission_cache):
        check = bedrock_app.check_bedrock_agent_roles
        mock_agent = MagicMock()
        paginator = MagicMock()
        mock_client.return_value = mock_agent
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"agentSummaries": []}]
        result = check(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-09: check_bedrock_knowledge_base_encryption
# ===================================================================
class TestBR09KBEncryption:
    """BR-09: Check Knowledge Base encryption."""

    @patch("boto3.client")
    def test_br09_no_kbs_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_knowledge_base_encryption
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        paginator = MagicMock()
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"knowledgeBaseSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-09"

    @patch("boto3.client")
    def test_br09_kb_exists_returns_findings(self, mock_client):
        check = bedrock_app.check_bedrock_knowledge_base_encryption
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        paginator = MagicMock()
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"knowledgeBaseSummaries": [{"knowledgeBaseId": "kb1", "name": "TestKB"}]}
        ]
        mock_agent.get_knowledge_base.return_value = {
            "knowledgeBase": {"storageConfiguration": {"type": "OPENSEARCH_SERVERLESS"}}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "BR-09"

    @patch("boto3.client")
    def test_br09_access_denied_in_region_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_knowledge_base_encryption
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        paginator = MagicMock()
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.side_effect = ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "missing permission",
                }
            },
            "ListKnowledgeBases",
        )
        result = check(region="eu-west-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert (
            "access to Knowledge Base metadata was denied"
            in findings[0]["Finding_Details"]
        )
        assert findings[0]["Region"] == "eu-west-1"

    @patch("boto3.client")
    def test_br09_exception_returns_error_finding(self, mock_client):
        check = bedrock_app.check_bedrock_knowledge_base_encryption
        mock_client.side_effect = Exception("KB error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("boto3.client")
    def test_br09_access_denied_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_knowledge_base_encryption
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        paginator = MagicMock()
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "ListKnowledgeBases",
        )
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("boto3.client")
    def test_br09_schema_valid(self, mock_client):
        check = bedrock_app.check_bedrock_knowledge_base_encryption
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        paginator = MagicMock()
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"knowledgeBaseSummaries": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-10: check_bedrock_guardrail_iam_enforcement
# ===================================================================
class TestBR10GuardrailIAMEnforcement:
    """BR-10: Check guardrail IAM condition enforcement."""

    @patch("boto3.client")
    def test_br10_no_guardrails_returns_na(
        self, mock_client, permission_cache_compliant
    ):
        check = bedrock_app.check_bedrock_guardrail_iam_enforcement
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.list_guardrails.return_value = {"guardrails": []}
        result = check(permission_cache_compliant)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "BR-10"

    @patch("boto3.client")
    def test_br10_guardrails_with_enforcement_returns_passed(
        self, mock_client, permission_cache_with_guardrail_condition
    ):
        check = bedrock_app.check_bedrock_guardrail_iam_enforcement
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.list_guardrails.return_value = {
            "guardrails": [{"guardrailId": "gr1", "name": "test-guardrail"}]
        }
        result = check(permission_cache_with_guardrail_condition)
        findings = extract_csv_data(result)
        assert len(findings) >= 1

    @patch("boto3.client")
    def test_br10_exception_returns_error_finding(
        self, mock_client, empty_permission_cache
    ):
        check = bedrock_app.check_bedrock_guardrail_iam_enforcement
        mock_client.side_effect = Exception("IAM error")
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("boto3.client")
    def test_br10_schema_valid(self, mock_client, empty_permission_cache):
        check = bedrock_app.check_bedrock_guardrail_iam_enforcement
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.list_guardrails.return_value = {"guardrails": []}
        result = check(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-11: check_bedrock_custom_model_encryption
# ===================================================================
class TestBR11CustomModelEncryption:
    """BR-11: Check custom model CMK encryption."""

    @patch("boto3.client")
    def test_br11_no_custom_models_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_custom_model_encryption
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        paginator = MagicMock()
        mock_bedrock.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"modelSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-11"

    @patch("boto3.client")
    def test_br11_model_without_cmk_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_custom_model_encryption
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        paginator = MagicMock()
        mock_bedrock.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"modelSummaries": [{"modelArn": "arn:model:1", "modelName": "my-model"}]}
        ]
        mock_bedrock.get_custom_model.return_value = {
            "jobArn": "arn:job:1",
            "baseModelArn": "arn:base:1",
        }
        mock_bedrock.get_model_customization_job.return_value = {"outputDataConfig": {}}
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"

    @patch("boto3.client")
    def test_br11_model_with_cmk_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_custom_model_encryption
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        paginator = MagicMock()
        mock_bedrock.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"modelSummaries": [{"modelArn": "arn:model:1", "modelName": "my-model"}]}
        ]
        mock_bedrock.get_custom_model.return_value = {
            "jobArn": "arn:job:1",
            "baseModelArn": "arn:base:1",
        }
        mock_bedrock.get_model_customization_job.return_value = {
            "outputDataConfig": {"kmsKeyId": "arn:aws:kms:us-east-1:123:key/abc"}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("boto3.client")
    def test_br11_exception_returns_error_finding(self, mock_client):
        check = bedrock_app.check_bedrock_custom_model_encryption
        mock_client.side_effect = Exception("Model error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("boto3.client")
    def test_br11_schema_valid(self, mock_client):
        check = bedrock_app.check_bedrock_custom_model_encryption
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        paginator = MagicMock()
        mock_bedrock.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"modelSummaries": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    @patch("boto3.client")
    def test_br11_unknown_operation_returns_clean_message(self, mock_client):
        # Regions without the custom model API surface "Unknown operation
        # ListCustomModels" / UnknownOperationException; report a clean message
        # instead of leaking the raw boto3 exception text.
        check = bedrock_app.check_bedrock_custom_model_encryption
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.get_paginator.side_effect = Exception(
            "ValidationException: Unknown operation ListCustomModels"
        )
        result = check(region="us-west-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert (
            findings[0]["Finding_Details"]
            == "Custom model API not available in us-west-1"
        )

    @patch("boto3.client")
    def test_br11_other_list_error_preserves_raw_message(self, mock_client):
        # Genuine errors (e.g. permissions) keep the raw text so they stay
        # diagnosable.
        check = bedrock_app.check_bedrock_custom_model_encryption
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.get_paginator.side_effect = Exception("AccessDeniedException")
        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert "AccessDeniedException" in findings[0]["Finding_Details"]


# ===================================================================
# BR-12: check_bedrock_invocation_log_encryption
# ===================================================================
class TestBR12InvocationLogEncryption:
    """BR-12: Check invocation log bucket encryption."""

    @patch("boto3.client")
    def test_br12_no_s3_logging_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_invocation_log_encryption
        mock_bedrock = MagicMock()
        mock_s3 = MagicMock()

        def client_factory(service, **kwargs):
            if service == "bedrock":
                return mock_bedrock
            return mock_s3

        mock_client.side_effect = client_factory
        mock_bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {"s3Config": {}}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-12"

    @patch("boto3.client")
    def test_br12_bucket_with_cmk_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_invocation_log_encryption
        mock_bedrock = MagicMock()
        mock_s3 = MagicMock()

        def client_factory(service, **kwargs):
            if service == "bedrock":
                return mock_bedrock
            return mock_s3

        mock_client.side_effect = client_factory
        mock_bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {"s3Config": {"bucketName": "log-bucket"}}
        }
        mock_s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": "arn:aws:kms:us-east-1:123:key/custom-key",
                        }
                    }
                ]
            }
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("boto3.client")
    def test_br12_bucket_without_cmk_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_invocation_log_encryption
        mock_bedrock = MagicMock()
        mock_s3 = MagicMock()

        def client_factory(service, **kwargs):
            if service == "bedrock":
                return mock_bedrock
            return mock_s3

        mock_client.side_effect = client_factory
        mock_bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {"s3Config": {"bucketName": "log-bucket"}}
        }
        mock_s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            }
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"

    @patch("boto3.client")
    def test_br12_exception_returns_error_finding(self, mock_client):
        check = bedrock_app.check_bedrock_invocation_log_encryption
        mock_client.side_effect = Exception("S3 error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("boto3.client")
    def test_br12_access_denied_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_invocation_log_encryption
        mock_bedrock = MagicMock()
        mock_s3 = MagicMock()

        def client_factory(service, **kwargs):
            if service == "bedrock":
                return mock_bedrock
            return mock_s3

        mock_client.side_effect = client_factory
        mock_bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {"s3Config": {"bucketName": "log-bucket"}}
        }
        mock_s3.get_bucket_encryption.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "GetBucketEncryption",
        )
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"

    @patch("boto3.client")
    def test_br12_schema_valid(self, mock_client):
        check = bedrock_app.check_bedrock_invocation_log_encryption
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {"s3Config": {}}
        }
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-13: check_bedrock_flows_guardrails
# ===================================================================
class TestBR13FlowsGuardrails:
    """BR-13: Check Bedrock Flows have guardrails."""

    @patch("boto3.client")
    def test_br13_no_flows_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_flows_guardrails
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        paginator = MagicMock()
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"flowSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-13"

    @patch("boto3.client")
    def test_br13_flow_with_guardrails_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_flows_guardrails
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        paginator = MagicMock()
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"flowSummaries": [{"id": "f1", "name": "TestFlow"}]}
        ]
        mock_agent.get_flow.return_value = {
            "definition": {
                "nodes": [
                    {
                        "name": "PromptNode",
                        "type": "Prompt",
                        "configuration": {
                            "prompt": {
                                "guardrailConfiguration": {
                                    "guardrailIdentifier": "gr-123"
                                }
                            }
                        },
                    }
                ]
            }
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("boto3.client")
    def test_br13_flow_without_guardrails_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_flows_guardrails
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        paginator = MagicMock()
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"flowSummaries": [{"id": "f1", "name": "TestFlow"}]}
        ]
        mock_agent.get_flow.return_value = {
            "definition": {
                "nodes": [
                    {
                        "name": "PromptNode",
                        "type": "Prompt",
                        "configuration": {"prompt": {}},
                    }
                ]
            }
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"

    @patch("boto3.client")
    def test_br13_exception_returns_error_finding(self, mock_client):
        check = bedrock_app.check_bedrock_flows_guardrails
        mock_client.side_effect = Exception("Flow error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("boto3.client")
    def test_br13_schema_valid(self, mock_client):
        check = bedrock_app.check_bedrock_flows_guardrails
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        paginator = MagicMock()
        mock_agent.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"flowSummaries": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    @patch("boto3.client")
    def test_br13_unknown_operation_returns_clean_message(self, mock_client):
        # Regions without the Flows API surface an "Unknown operation" error;
        # report a clean message instead of leaking the raw boto3 text.
        check = bedrock_app.check_bedrock_flows_guardrails
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        mock_agent.get_paginator.side_effect = Exception("UnknownOperationException")
        result = check(region="us-west-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert (
            findings[0]["Finding_Details"]
            == "Bedrock Flows API not available in us-west-1"
        )


# ===================================================================
# describe_api_error helper
# ===================================================================
class TestDescribeApiError:
    """Shared helper that maps region-unavailability errors to clean text."""

    def test_unknown_operation_phrase_returns_clean_message(self):
        msg = bedrock_app.describe_api_error(
            Exception("ValidationException: Unknown operation ListPrompts"),
            "Bedrock Prompt Management API",
            "us-east-2",
        )
        assert msg == "Bedrock Prompt Management API not available in us-east-2"

    def test_unknown_operation_exception_returns_clean_message(self):
        msg = bedrock_app.describe_api_error(
            Exception("UnknownOperationException"), "Custom model API", "us-west-1"
        )
        assert msg == "Custom model API not available in us-west-1"

    def test_missing_region_falls_back_to_generic_location(self):
        msg = bedrock_app.describe_api_error(
            Exception("Unknown operation Foo"), "Custom model API"
        )
        assert msg == "Custom model API not available in this region"

    def test_other_error_preserves_raw_text(self):
        msg = bedrock_app.describe_api_error(
            Exception("AccessDeniedException"), "Custom model API", "us-east-1"
        )
        assert msg == "Unable to check Custom model API: AccessDeniedException"


# ===================================================================
# lambda_handler: multi-region gating and availability probe
# ===================================================================
def _make_client_error(code, message="error"):
    return ClientError({"Error": {"Code": code, "Message": message}}, "operation")


def _bedrock_event(region="us-east-1", region_index=0):
    return {
        "Region": region,
        "RegionIndex": region_index,
        "Execution": {"Name": "test-execution-1"},
        "StateMachine": {"Name": "test-sm"},
    }


class TestBedrockHandlerMultiRegion:
    """lambda_handler primary-region gating + availability probe (BR-00/BR-01/BR-03)."""

    def _run_handler_unavailable(self, mock_client, event):
        """Drive the handler down the 'Bedrock unavailable' early-return path and
        return the findings captured via generate_csv_report. The availability
        probe raises EndpointConnectionError so no regional checks run."""
        captured = {}

        def fake_csv(findings):
            captured["findings"] = findings
            return "csv"

        test_client = MagicMock()
        test_client.get_model_invocation_logging_configuration.side_effect = (
            EndpointConnectionError(endpoint_url="https://bedrock.invalid")
        )
        mock_client.return_value = test_client

        with (
            patch.object(
                bedrock_app,
                "get_permissions_cache",
                return_value={"role_permissions": {}, "user_permissions": {}},
            ),
            patch.object(bedrock_app, "generate_csv_report", side_effect=fake_csv),
            patch.object(
                bedrock_app, "write_to_s3", return_value="s3://bucket/report.csv"
            ),
        ):
            resp = bedrock_app.lambda_handler(event, None)

        return resp, captured.get("findings", [])

    @patch("bedrock_app.boto3.client")
    def test_primary_region_emits_global_iam_checks_tagged_global(self, mock_client):
        # On the primary region, BR-01 and BR-03 (IAM-global) must be emitted and
        # tagged "Global", even when Bedrock itself is unavailable in the region.
        resp, findings = self._run_handler_unavailable(
            mock_client, _bedrock_event(region="ap-south-2", region_index=0)
        )
        assert resp["statusCode"] == 200

        rows = [r for f in findings for r in f.get("csv_data", [])]
        check_ids = {r["Check_ID"] for r in rows}
        assert "BR-01" in check_ids
        assert "BR-03" in check_ids
        # Every global IAM finding is tagged Global, not the scanned region.
        for r in rows:
            if r["Check_ID"] in ("BR-01", "BR-03"):
                assert r["Region"] == "Global"
        # The availability finding itself is tagged with the scanned region.
        br00 = [r for r in rows if r["Check_ID"] == "BR-00"]
        assert br00 and br00[0]["Region"] == "ap-south-2"

    @patch("bedrock_app.boto3.client")
    def test_non_primary_region_skips_global_iam_checks(self, mock_client):
        # On a non-primary region (index > 0), the IAM-global checks must NOT run,
        # so they are not duplicated once per scanned region.
        resp, findings = self._run_handler_unavailable(
            mock_client, _bedrock_event(region="eu-west-1", region_index=1)
        )
        assert resp["statusCode"] == 200

        rows = [r for f in findings for r in f.get("csv_data", [])]
        check_ids = {r["Check_ID"] for r in rows}
        assert "BR-01" not in check_ids
        assert "BR-03" not in check_ids
        # Only the BR-00 availability finding should be present.
        assert check_ids == {"BR-00"}

    @patch("bedrock_app.boto3.client")
    def test_optin_region_error_treated_as_unavailable(self, mock_client):
        # A region-not-enabled error code (e.g. UnrecognizedClientException) is
        # treated like an endpoint failure: emit a single BR-00 N/A finding.
        captured = {}

        def fake_csv(findings):
            captured["findings"] = findings
            return "csv"

        test_client = MagicMock()
        test_client.get_model_invocation_logging_configuration.side_effect = (
            _make_client_error("UnrecognizedClientException")
        )
        mock_client.return_value = test_client

        with (
            patch.object(
                bedrock_app,
                "get_permissions_cache",
                return_value={"role_permissions": {}, "user_permissions": {}},
            ),
            patch.object(bedrock_app, "generate_csv_report", side_effect=fake_csv),
            patch.object(bedrock_app, "write_to_s3", return_value="s3://b/r.csv"),
        ):
            resp = bedrock_app.lambda_handler(
                _bedrock_event(region="me-south-1", region_index=1), None
            )

        assert resp["statusCode"] == 200
        rows = [r for f in captured["findings"] for r in f.get("csv_data", [])]
        br00 = [r for r in rows if r["Check_ID"] == "BR-00"]
        assert br00 and br00[0]["Status"] == "N/A"
        assert "me-south-1" in br00[0]["Finding_Details"]

    @patch("bedrock_app.boto3.client")
    def test_validation_exception_proceeds_with_checks(self, mock_client):
        # A ValidationException from the probe means logging simply isn't
        # configured — the service IS reachable, so the handler must NOT short
        # circuit; it should run the regional checks (no BR-00 finding emitted).
        captured = {}

        def fake_csv(findings):
            captured["findings"] = findings
            return "csv"

        test_client = MagicMock()
        test_client.get_model_invocation_logging_configuration.side_effect = (
            _make_client_error("ValidationException")
        )
        mock_client.return_value = test_client

        with (
            patch.object(
                bedrock_app,
                "get_permissions_cache",
                return_value={"role_permissions": {}, "user_permissions": {}},
            ),
            patch.object(bedrock_app, "generate_csv_report", side_effect=fake_csv),
            patch.object(bedrock_app, "write_to_s3", return_value="s3://b/r.csv"),
        ):
            resp = bedrock_app.lambda_handler(
                _bedrock_event(region="us-east-1", region_index=0), None
            )

        assert resp["statusCode"] == 200
        rows = [r for f in captured["findings"] for r in f.get("csv_data", [])]
        check_ids = {r["Check_ID"] for r in rows}
        # Service reachable => no availability (BR-00) finding, and regional
        # checks ran (e.g. BR-04 logging, BR-05 guardrails are present).
        assert "BR-00" not in check_ids
        assert len(check_ids) > 3

    # Regional checks BR-26..32 (function name -> check id) that the handler must
    # invoke once per scanned region, passing region=region.
    NEW_REGIONAL_CHECKS = {
        "check_bedrock_guardrail_pii_filters": "BR-26",
        "check_bedrock_guardrail_contextual_grounding": "BR-27",
        "check_bedrock_agent_guardrail_association": "BR-28",
        "check_bedrock_agent_idle_session_ttl": "BR-29",
        "check_bedrock_imported_model_kms_encryption": "BR-30",
        "check_bedrock_batch_inference_output_encryption": "BR-31",
        "check_bedrock_cloudwatch_alarms": "BR-32",
    }

    def _run_handler_with_check_spies(self, event):
        """Drive the handler down the full regional path with every check function
        replaced by a spy that records the region it was called with. The probe
        raises ValidationException (service reachable) so all regional checks run.
        Returns {check_function_name: region_passed} plus whether BR-15 ran."""
        recorded = {}

        def make_spy(name):
            def spy(*args, region="", **kwargs):
                recorded[name] = region
                return {
                    "check_name": name,
                    "status": "PASS",
                    "details": "",
                    "csv_data": [],
                }

            return spy

        test_client = MagicMock()
        test_client.get_model_invocation_logging_configuration.side_effect = (
            _make_client_error("ValidationException")
        )

        # Spy on every check the handler calls so it runs cleanly end-to-end.
        spied = [
            "check_bedrock_full_access_roles",
            "check_marketplace_subscription_access",
            "check_bedrock_access_and_vpc_endpoints",
            "check_bedrock_logging_configuration",
            "check_bedrock_guardrails",
            "check_bedrock_cloudtrail_logging",
            "check_bedrock_prompt_management",
            "check_bedrock_agent_roles",
            "check_bedrock_knowledge_base_encryption",
            "check_bedrock_guardrail_iam_enforcement",
            "check_bedrock_custom_model_encryption",
            "check_bedrock_invocation_log_encryption",
            "check_bedrock_flows_guardrails",
            "check_bedrock_cross_account_guardrails",  # BR-15 (global)
            "check_bedrock_guardrail_tier",
            "check_bedrock_custom_model_kms_encryption",
            "check_bedrock_model_evaluations",
            "check_bedrock_prompt_flow_validation",
            "check_bedrock_knowledge_base_kms_encryption",
            "check_bedrock_agent_action_group_iam",
            "check_bedrock_service_quotas_throttling",
            "check_bedrock_guardrail_content_filters",
            "check_bedrock_automated_reasoning_policy",
            "check_bedrock_rag_evaluation_jobs",
            *self.NEW_REGIONAL_CHECKS.keys(),
        ]

        with contextlib.ExitStack() as stack:
            stack.enter_context(
                patch.object(bedrock_app.boto3, "client", return_value=test_client)
            )
            stack.enter_context(
                patch.object(
                    bedrock_app,
                    "get_permissions_cache",
                    return_value={"role_permissions": {}, "user_permissions": {}},
                )
            )
            stack.enter_context(
                patch.object(bedrock_app, "generate_csv_report", return_value="csv")
            )
            stack.enter_context(
                patch.object(bedrock_app, "write_to_s3", return_value="s3://b/r.csv")
            )
            for name in spied:
                stack.enter_context(
                    patch.object(bedrock_app, name, side_effect=make_spy(name))
                )
            resp = bedrock_app.lambda_handler(event, None)

        return resp, recorded

    def test_new_regional_checks_run_per_region_non_primary(self):
        # On a non-primary region, BR-26..32 must each run with region=<scanned>,
        # and the global BR-15 check must NOT run.
        resp, recorded = self._run_handler_with_check_spies(
            _bedrock_event(region="eu-west-3", region_index=2)
        )
        assert resp["statusCode"] == 200
        for fn_name in self.NEW_REGIONAL_CHECKS:
            assert recorded.get(fn_name) == "eu-west-3", (
                f"{fn_name} not run with scanned region: {recorded.get(fn_name)}"
            )
        # BR-15 (cross-account guardrails) is global -> skipped on non-primary.
        assert "check_bedrock_cross_account_guardrails" not in recorded

    def test_new_regional_checks_run_per_region_primary(self):
        # On the primary region, BR-26..32 run with region=<scanned> and the
        # global BR-15 check runs tagged Global.
        resp, recorded = self._run_handler_with_check_spies(
            _bedrock_event(region="us-east-1", region_index=0)
        )
        assert resp["statusCode"] == 200
        for fn_name in self.NEW_REGIONAL_CHECKS:
            assert recorded.get(fn_name) == "us-east-1", (
                f"{fn_name} not run with scanned region: {recorded.get(fn_name)}"
            )
        # Global check runs once, tagged Global.
        assert recorded.get("check_bedrock_cross_account_guardrails") == "Global"


# ===================================================================
# BR-15: check_bedrock_cross_account_guardrails
# ===================================================================
class TestBR15CrossAccountGuardrails:
    """BR-15: Check AWS Organizations Bedrock Guardrails policies."""

    @patch("bedrock_app.boto3.client")
    def test_br15_organizations_not_enabled_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_cross_account_guardrails

        org_client = MagicMock()
        org_client.describe_organization.side_effect = ClientError(
            {"Error": {"Code": "AWSOrganizationsNotInUseException"}},
            "DescribeOrganization",
        )
        mock_client.return_value = org_client

        result = check(region="Global")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-15"
        assert "not in use" in findings[0]["Finding_Details"]

    @patch("bedrock_app.boto3.client")
    def test_br15_policy_type_not_enabled_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_cross_account_guardrails

        org_client = MagicMock()
        org_client.describe_organization.return_value = {
            "Organization": {"MasterAccountId": "123456789012"}
        }
        org_client.list_roots.return_value = {
            "Roots": [
                {
                    "Id": "r-abc123",
                    "Arn": "arn:aws:organizations::123456789012:root/o-xyz/r-abc123",
                }
            ]
        }
        # No policies returned = policy type not enabled
        org_client.list_policies.return_value = {"Policies": []}

        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}

        def client_factory(service, **kwargs):
            if service == "organizations":
                return org_client
            return sts_client

        mock_client.side_effect = client_factory

        result = check(region="Global")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-15"
        assert findings[0]["Severity"] == "High"

    @patch("bedrock_app.boto3.client")
    def test_br15_policies_configured_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_cross_account_guardrails

        org_client = MagicMock()
        org_client.describe_organization.return_value = {
            "Organization": {"MasterAccountId": "123456789012"}
        }
        org_client.list_roots.return_value = {
            "Roots": [
                {
                    "Id": "r-abc123",
                    "Arn": "arn:aws:organizations::123456789012:root/o-xyz/r-abc123",
                    "PolicyTypes": [{"Type": "BEDROCK_POLICY", "Status": "ENABLED"}],
                }
            ]
        }
        org_client.list_policies.return_value = {
            "Policies": [{"Id": "p-123", "Name": "BedrockGuardrailPolicy"}]
        }

        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}

        def client_factory(service, **kwargs):
            if service == "organizations":
                return org_client
            return sts_client

        mock_client.side_effect = client_factory

        result = check(region="Global")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        passed_findings = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed_findings) >= 1
        assert passed_findings[0]["Check_ID"] == "BR-15"

    @patch("bedrock_app.boto3.client")
    def test_br15_access_denied_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_cross_account_guardrails

        org_client = MagicMock()
        org_client.describe_organization.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}}, "DescribeOrganization"
        )
        mock_client.return_value = org_client

        result = check(region="Global")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-15"

    def test_br15_schema_valid(self):
        check = bedrock_app.check_bedrock_cross_account_guardrails
        with patch("bedrock_app.boto3.client") as mock_client:
            org_client = MagicMock()
            org_client.describe_organization.side_effect = ClientError(
                {"Error": {"Code": "AWSOrganizationsNotInUseException"}},
                "DescribeOrganization",
            )
            mock_client.return_value = org_client
            result = check(region="Global")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-16: check_bedrock_guardrail_tier
# ===================================================================
class TestBR16GuardrailTier:
    """BR-16: Verify guardrails use Standard tier."""

    @patch("bedrock_app.boto3.client")
    def test_br16_no_guardrails_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_tier

        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {"guardrails": []}
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-16"

    @patch("bedrock_app.boto3.client")
    def test_br16_standard_tier_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_tier

        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr-123", "name": "test-guardrail"}]
        }
        bedrock_client.get_guardrail.return_value = {
            "guardrail": {"contentPolicy": {"tier": {"tierName": "STANDARD"}}}
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        passed_findings = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed_findings) >= 1
        assert passed_findings[0]["Check_ID"] == "BR-16"

    @patch("bedrock_app.boto3.client")
    def test_br16_non_standard_tier_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_tier

        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr-123", "name": "classic-guardrail"}]
        }
        bedrock_client.get_guardrail.return_value = {
            "guardrail": {"contentPolicy": {"tier": {"tierName": "CLASSIC"}}}
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-16"
        assert findings[0]["Severity"] == "Medium"

    @patch("bedrock_app.boto3.client")
    def test_br16_access_denied_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_tier

        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}}, "ListGuardrails"
        )
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-16"

    def test_br16_schema_valid(self):
        check = bedrock_app.check_bedrock_guardrail_tier
        with patch("bedrock_app.boto3.client") as mock_client:
            bedrock_client = MagicMock()
            bedrock_client.list_guardrails.return_value = {"guardrails": []}
            mock_client.return_value = bedrock_client
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-17: check_bedrock_custom_model_kms_encryption
# ===================================================================
class TestBR17CustomModelKMSEncryption:
    """BR-17: Verify custom models use customer-managed KMS keys."""

    @patch("bedrock_app.boto3.client")
    def test_br17_no_custom_models_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_custom_model_kms_encryption

        bedrock_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"modelSummaries": []}]
        bedrock_client.get_paginator.return_value = paginator
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-17"

    @patch("bedrock_app.boto3.client")
    def test_br17_customer_managed_kms_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_custom_model_kms_encryption

        bedrock_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "modelSummaries": [
                    {
                        "modelArn": "arn:aws:bedrock:us-east-1:123456789012:custom-model/my-model",
                        "modelName": "my-model",
                    }
                ]
            }
        ]
        bedrock_client.get_paginator.return_value = paginator
        bedrock_client.get_custom_model.return_value = {
            "modelKmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/abc-123"
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        passed_findings = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed_findings) >= 1
        assert passed_findings[0]["Check_ID"] == "BR-17"

    @patch("bedrock_app.boto3.client")
    def test_br17_aws_owned_keys_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_custom_model_kms_encryption

        bedrock_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "modelSummaries": [
                    {
                        "modelArn": "arn:aws:bedrock:us-east-1:123456789012:custom-model/my-model",
                        "modelName": "my-model",
                    }
                ]
            }
        ]
        bedrock_client.get_paginator.return_value = paginator
        # No KMS key ID = AWS-owned key
        bedrock_client.get_custom_model.return_value = {}
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-17"
        assert findings[0]["Severity"] == "High"

    @patch("bedrock_app.boto3.client")
    def test_br17_access_denied_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_custom_model_kms_encryption

        bedrock_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}}, "ListCustomModels"
        )
        bedrock_client.get_paginator.return_value = paginator
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-17"

    def test_br17_schema_valid(self):
        check = bedrock_app.check_bedrock_custom_model_kms_encryption
        with patch("bedrock_app.boto3.client") as mock_client:
            bedrock_client = MagicMock()
            paginator = MagicMock()
            paginator.paginate.return_value = [{"modelSummaries": []}]
            bedrock_client.get_paginator.return_value = paginator
            mock_client.return_value = bedrock_client
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-18: check_bedrock_model_evaluations
# ===================================================================
class TestBR18ModelEvaluations:
    """BR-18: Check if model evaluation jobs exist."""

    @patch("bedrock_app.boto3.client")
    def test_br18_no_evaluations_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_model_evaluations

        bedrock_client = MagicMock()
        bedrock_client.list_evaluation_jobs.return_value = {"jobSummaries": []}
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-18"
        assert findings[0]["Severity"] == "Medium"

    @patch("bedrock_app.boto3.client")
    def test_br18_recent_evaluations_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_model_evaluations

        from datetime import datetime, timezone, timedelta

        recent_time = datetime.now(timezone.utc) - timedelta(days=10)

        bedrock_client = MagicMock()
        bedrock_client.list_evaluation_jobs.return_value = {
            "jobSummaries": [
                {
                    "jobName": "eval-job-1",
                    "status": "Completed",
                    "creationTime": recent_time,
                }
            ]
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        passed_findings = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed_findings) >= 1
        assert passed_findings[0]["Check_ID"] == "BR-18"

    @patch("bedrock_app.boto3.client")
    def test_br18_stale_evaluations_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_model_evaluations

        from datetime import datetime, timezone, timedelta

        stale_time = datetime.now(timezone.utc) - timedelta(days=60)

        bedrock_client = MagicMock()
        bedrock_client.list_evaluation_jobs.return_value = {
            "jobSummaries": [
                {
                    "jobName": "eval-job-old",
                    "status": "Completed",
                    "creationTime": stale_time,
                }
            ]
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-18"
        assert findings[0]["Severity"] == "Medium"

    @patch("bedrock_app.boto3.client")
    def test_br18_unknown_operation_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_model_evaluations

        bedrock_client = MagicMock()
        bedrock_client.list_evaluation_jobs.side_effect = ClientError(
            {"Error": {"Code": "UnknownOperation", "Message": "Unknown operation"}},
            "ListEvaluationJobs",
        )
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-18"

    @patch("bedrock_app.boto3.client")
    def test_br18_access_denied_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_model_evaluations

        bedrock_client = MagicMock()
        bedrock_client.list_evaluation_jobs.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}}, "ListEvaluationJobs"
        )
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-18"

    def test_br18_schema_valid(self):
        check = bedrock_app.check_bedrock_model_evaluations
        with patch("bedrock_app.boto3.client") as mock_client:
            bedrock_client = MagicMock()
            bedrock_client.list_evaluation_jobs.return_value = {"jobSummaries": []}
            mock_client.return_value = bedrock_client
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-19: check_bedrock_prompt_flow_validation
# ===================================================================
class TestBR19PromptFlowValidation:
    """BR-19: Verify prompt flows are validated using GetFlow validations."""

    @patch("bedrock_app.boto3.client")
    def test_br19_no_flows_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_prompt_flow_validation
        agent_client = MagicMock()
        agent_client.list_flows.return_value = {"flowSummaries": []}
        mock_client.return_value = agent_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-19"

    @patch("bedrock_app.boto3.client")
    def test_br19_prepared_flow_no_errors_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_prompt_flow_validation
        agent_client = MagicMock()
        agent_client.list_flows.return_value = {
            "flowSummaries": [{"id": "f1", "name": "GoodFlow", "status": "Prepared"}]
        }
        agent_client.get_flow.return_value = {"validations": []}
        mock_client.return_value = agent_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) >= 1
        assert passed[0]["Check_ID"] == "BR-19"

    @patch("bedrock_app.boto3.client")
    def test_br19_flow_with_error_validation_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_prompt_flow_validation
        agent_client = MagicMock()
        agent_client.list_flows.return_value = {
            "flowSummaries": [{"id": "f1", "name": "BadFlow", "status": "Prepared"}]
        }
        agent_client.get_flow.return_value = {
            "validations": [{"severity": "ERROR", "message": "Node X is not connected"}]
        }
        mock_client.return_value = agent_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-19"
        assert "Node X is not connected" in findings[0]["Finding_Details"]

    @patch("bedrock_app.boto3.client")
    def test_br19_unprepared_flow_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_prompt_flow_validation
        agent_client = MagicMock()
        agent_client.list_flows.return_value = {
            "flowSummaries": [
                {"id": "f1", "name": "DraftFlow", "status": "NotPrepared"}
            ]
        }
        agent_client.get_flow.return_value = {"validations": []}
        mock_client.return_value = agent_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-19"

    def test_br19_schema_valid(self):
        check = bedrock_app.check_bedrock_prompt_flow_validation
        with patch("bedrock_app.boto3.client") as mock_client:
            agent_client = MagicMock()
            agent_client.list_flows.return_value = {"flowSummaries": []}
            mock_client.return_value = agent_client
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-20: check_bedrock_knowledge_base_kms_encryption
# ===================================================================
class TestBR20KnowledgeBaseKMS:
    """BR-20: Verify managed KB customer-managed KMS encryption."""

    @patch("bedrock_app.boto3.client")
    def test_br20_no_kbs_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_knowledge_base_kms_encryption
        agent_client = MagicMock()
        agent_client.list_knowledge_bases.return_value = {"knowledgeBaseSummaries": []}
        mock_client.return_value = agent_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-20"

    @patch("bedrock_app.boto3.client")
    def test_br20_managed_kb_with_cmk_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_knowledge_base_kms_encryption
        agent_client = MagicMock()
        agent_client.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [{"knowledgeBaseId": "kb1", "name": "ManagedKB"}]
        }
        agent_client.get_knowledge_base.return_value = {
            "knowledgeBase": {
                "knowledgeBaseConfiguration": {
                    "type": "MANAGED",
                    "managedKnowledgeBaseConfiguration": {
                        "serverSideEncryptionConfiguration": {
                            "kmsKeyArn": "arn:aws:kms:us-east-1:123:key/abc"
                        }
                    },
                }
            }
        }
        mock_client.return_value = agent_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) >= 1
        assert passed[0]["Check_ID"] == "BR-20"

    @patch("bedrock_app.boto3.client")
    def test_br20_managed_kb_without_cmk_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_knowledge_base_kms_encryption
        agent_client = MagicMock()
        agent_client.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [{"knowledgeBaseId": "kb1", "name": "ManagedKB"}]
        }
        agent_client.get_knowledge_base.return_value = {
            "knowledgeBase": {
                "knowledgeBaseConfiguration": {
                    "type": "MANAGED",
                    "managedKnowledgeBaseConfiguration": {},
                }
            }
        }
        mock_client.return_value = agent_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-20"
        assert findings[0]["Severity"] == "High"

    @patch("bedrock_app.boto3.client")
    def test_br20_managed_kb_sdk_gap_returns_na(self, mock_client):
        # A MANAGED knowledge base whose managedKnowledgeBaseConfiguration block is
        # absent (bundled botocore predates the field, < 1.43.32) must surface as
        # N/A "indeterminate", not a false-positive Failed.
        check = bedrock_app.check_bedrock_knowledge_base_kms_encryption
        agent_client = MagicMock()
        agent_client.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [{"knowledgeBaseId": "kb1", "name": "ManagedKB"}]
        }
        agent_client.get_knowledge_base.return_value = {
            "knowledgeBase": {"knowledgeBaseConfiguration": {"type": "MANAGED"}}
        }
        mock_client.return_value = agent_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        na = [f for f in findings if f["Status"] == "N/A"]
        assert len(na) >= 1
        assert na[0]["Check_ID"] == "BR-20"
        assert "1.43.32" in na[0]["Finding_Details"]
        # Must NOT be reported as a failure on incomplete data.
        assert all(f["Status"] != "Failed" for f in findings)

    @patch("bedrock_app.boto3.client")
    def test_br20_custom_vector_store_returns_na_review(self, mock_client):
        # Custom vector stores (no managed config) cannot be validated from the
        # KB API; they are flagged for manual review, not failed.
        check = bedrock_app.check_bedrock_knowledge_base_kms_encryption
        agent_client = MagicMock()
        agent_client.list_knowledge_bases.return_value = {
            "knowledgeBaseSummaries": [{"knowledgeBaseId": "kb1", "name": "VectorKB"}]
        }
        agent_client.get_knowledge_base.return_value = {
            "knowledgeBase": {
                "knowledgeBaseConfiguration": {
                    "type": "VECTOR",
                    "vectorKnowledgeBaseConfiguration": {},
                },
                "storageConfiguration": {"type": "OPENSEARCH_SERVERLESS"},
            }
        }
        mock_client.return_value = agent_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        na = [f for f in findings if f["Status"] == "N/A"]
        assert len(na) >= 1
        assert na[0]["Check_ID"] == "BR-20"
        assert "storage layer" in na[0]["Finding_Details"]

    def test_br20_schema_valid(self):
        check = bedrock_app.check_bedrock_knowledge_base_kms_encryption
        with patch("bedrock_app.boto3.client") as mock_client:
            agent_client = MagicMock()
            agent_client.list_knowledge_bases.return_value = {
                "knowledgeBaseSummaries": []
            }
            mock_client.return_value = agent_client
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-21: check_bedrock_agent_action_group_iam
# ===================================================================
class TestBR21AgentActionGroupIAM:
    """BR-21: Verify action-group Lambda roles follow least privilege."""

    @staticmethod
    def _agent_client_with_lambda_role(role_name):
        agent_client = MagicMock()
        agent_client.list_agents.return_value = {
            "agentSummaries": [{"agentId": "a1", "agentName": "TestAgent"}]
        }
        agent_client.list_agent_action_groups.return_value = {
            "actionGroupSummaries": [
                {"actionGroupId": "ag1", "actionGroupName": "ActionGroup1"}
            ]
        }
        agent_client.get_agent_action_group.return_value = {
            "agentActionGroup": {
                "actionGroupExecutor": {
                    "lambda": "arn:aws:lambda:us-east-1:123:function:my-func"
                }
            }
        }
        lambda_client = MagicMock()
        lambda_client.get_function.return_value = {
            "Configuration": {"Role": f"arn:aws:iam::123456789012:role/{role_name}"}
        }
        return agent_client, lambda_client

    @patch("bedrock_app.boto3.client")
    def test_br21_no_agents_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_agent_action_group_iam
        agent_client = MagicMock()
        agent_client.list_agents.return_value = {"agentSummaries": []}
        mock_client.return_value = agent_client

        result = check(region="us-east-1", permission_cache={"role_permissions": {}})
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-21"

    @patch("bedrock_app.boto3.client")
    def test_br21_admin_access_role_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_agent_action_group_iam
        agent_client, lambda_client = self._agent_client_with_lambda_role("AdminRole")

        def factory(service, **kwargs):
            return lambda_client if service == "lambda" else agent_client

        mock_client.side_effect = factory

        cache = {
            "role_permissions": {
                "AdminRole": {
                    "attached_policies": [{"name": "AdministratorAccess"}],
                    "inline_policies": [],
                }
            }
        }
        result = check(region="us-east-1", permission_cache=cache)
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-21"
        assert "AdministratorAccess" in findings[0]["Finding_Details"]

    @patch("bedrock_app.boto3.client")
    def test_br21_wildcard_inline_policy_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_agent_action_group_iam
        agent_client, lambda_client = self._agent_client_with_lambda_role("WildRole")

        def factory(service, **kwargs):
            return lambda_client if service == "lambda" else agent_client

        mock_client.side_effect = factory

        cache = {
            "role_permissions": {
                "WildRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "inline-wild",
                            "document": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "*",
                                        "Resource": "*",
                                    }
                                ],
                            },
                        }
                    ],
                }
            }
        }
        result = check(region="us-east-1", permission_cache=cache)
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-21"

    @patch("bedrock_app.boto3.client")
    def test_br21_scoped_role_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_agent_action_group_iam
        agent_client, lambda_client = self._agent_client_with_lambda_role("ScopedRole")

        def factory(service, **kwargs):
            return lambda_client if service == "lambda" else agent_client

        mock_client.side_effect = factory

        cache = {
            "role_permissions": {
                "ScopedRole": {
                    "attached_policies": [{"name": "CustomScopedPolicy"}],
                    "inline_policies": [],
                }
            }
        }
        result = check(region="us-east-1", permission_cache=cache)
        findings = extract_csv_data(result)
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) >= 1
        assert passed[0]["Check_ID"] == "BR-21"

    def test_br21_schema_valid(self):
        check = bedrock_app.check_bedrock_agent_action_group_iam
        with patch("bedrock_app.boto3.client") as mock_client:
            agent_client = MagicMock()
            agent_client.list_agents.return_value = {"agentSummaries": []}
            mock_client.return_value = agent_client
            result = check(
                region="us-east-1", permission_cache={"role_permissions": {}}
            )

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-23: check_bedrock_guardrail_content_filters
# ===================================================================
class TestBR23ContentFilters:
    """BR-23: Verify all content filters are enabled via contentPolicy.filters."""

    @staticmethod
    def _filters(types):
        return [
            {"type": t, "inputStrength": "HIGH", "outputStrength": "HIGH"}
            for t in types
        ]

    @patch("bedrock_app.boto3.client")
    def test_br23_no_guardrails_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_content_filters
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {"guardrails": []}
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-23"

    @patch("bedrock_app.boto3.client")
    def test_br23_all_filters_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_content_filters
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr1", "name": "FullGuardrail"}]
        }
        bedrock_client.get_guardrail.return_value = {
            "guardrail": {
                "contentPolicy": {
                    "filters": self._filters(["HATE", "INSULTS", "SEXUAL", "VIOLENCE"])
                }
            }
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) >= 1
        assert passed[0]["Check_ID"] == "BR-23"

    @patch("bedrock_app.boto3.client")
    def test_br23_missing_filters_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_content_filters
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr1", "name": "PartialGuardrail"}]
        }
        bedrock_client.get_guardrail.return_value = {
            "guardrail": {
                "contentPolicy": {"filters": self._filters(["HATE", "VIOLENCE"])}
            }
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-23"
        assert "INSULTS" in findings[0]["Finding_Details"]

    def test_br23_schema_valid(self):
        check = bedrock_app.check_bedrock_guardrail_content_filters
        with patch("bedrock_app.boto3.client") as mock_client:
            bedrock_client = MagicMock()
            bedrock_client.list_guardrails.return_value = {"guardrails": []}
            mock_client.return_value = bedrock_client
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-24: check_bedrock_automated_reasoning_policy
# ===================================================================
class TestBR24AutomatedReasoning:
    """BR-24: Verify Automated Reasoning policies via automatedReasoningPolicy."""

    @patch("bedrock_app.boto3.client")
    def test_br24_no_guardrails_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_automated_reasoning_policy
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {"guardrails": []}
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-24"

    @patch("bedrock_app.boto3.client")
    def test_br24_with_ar_policy_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_automated_reasoning_policy
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr1", "name": "VerifiedGuardrail"}]
        }
        bedrock_client.get_guardrail.return_value = {
            "guardrail": {
                "automatedReasoningPolicy": {
                    "policies": [
                        "arn:aws:bedrock:us-east-1:123:automated-reasoning-policy/p1"
                    ]
                }
            }
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) >= 1
        assert passed[0]["Check_ID"] == "BR-24"

    @patch("bedrock_app.boto3.client")
    def test_br24_without_ar_policy_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_automated_reasoning_policy
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr1", "name": "PlainGuardrail"}]
        }
        bedrock_client.get_guardrail.return_value = {"guardrail": {}}
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-24"

    def test_br24_schema_valid(self):
        check = bedrock_app.check_bedrock_automated_reasoning_policy
        with patch("bedrock_app.boto3.client") as mock_client:
            bedrock_client = MagicMock()
            bedrock_client.list_guardrails.return_value = {"guardrails": []}
            mock_client.return_value = bedrock_client
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-26: check_bedrock_guardrail_pii_filters
# ===================================================================
class TestBR26GuardrailPIIFilters:
    """BR-26: Verify guardrails configure sensitive-information (PII) filters."""

    @patch("bedrock_app.boto3.client")
    def test_br26_no_guardrails_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_pii_filters
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {"guardrails": []}
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-26"

    @patch("bedrock_app.boto3.client")
    def test_br26_pii_configured_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_pii_filters
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr1", "name": "PiiGuardrail"}]
        }
        bedrock_client.get_guardrail.return_value = {
            "guardrail": {
                "sensitiveInformationPolicy": {
                    "piiEntities": [{"type": "EMAIL", "action": "ANONYMIZE"}],
                    "regexes": [],
                }
            }
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) >= 1
        assert passed[0]["Check_ID"] == "BR-26"

    @patch("bedrock_app.boto3.client")
    def test_br26_no_pii_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_pii_filters
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr1", "name": "PlainGuardrail"}]
        }
        bedrock_client.get_guardrail.return_value = {
            "guardrail": {
                "sensitiveInformationPolicy": {"piiEntities": [], "regexes": []}
            }
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-26"
        assert findings[0]["Severity"] == "High"

    @patch("bedrock_app.boto3.client")
    def test_br26_access_denied_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_pii_filters
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}}, "ListGuardrails"
        )
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-26"

    def test_br26_schema_valid(self):
        check = bedrock_app.check_bedrock_guardrail_pii_filters
        with patch("bedrock_app.boto3.client") as mock_client:
            bedrock_client = MagicMock()
            bedrock_client.list_guardrails.return_value = {"guardrails": []}
            mock_client.return_value = bedrock_client
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-27: check_bedrock_guardrail_contextual_grounding
# ===================================================================
class TestBR27ContextualGrounding:
    """BR-27: Verify guardrails enable contextual grounding checks."""

    @patch("bedrock_app.boto3.client")
    def test_br27_no_guardrails_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_contextual_grounding
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {"guardrails": []}
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-27"

    @patch("bedrock_app.boto3.client")
    def test_br27_grounding_enabled_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_contextual_grounding
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr1", "name": "GroundedGuardrail"}]
        }
        bedrock_client.get_guardrail.return_value = {
            "guardrail": {
                "contextualGroundingPolicy": {
                    "filters": [
                        {"type": "GROUNDING", "threshold": 0.75, "enabled": True}
                    ]
                }
            }
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) >= 1
        assert passed[0]["Check_ID"] == "BR-27"

    @patch("bedrock_app.boto3.client")
    def test_br27_no_grounding_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_guardrail_contextual_grounding
        bedrock_client = MagicMock()
        bedrock_client.list_guardrails.return_value = {
            "guardrails": [{"id": "gr1", "name": "PlainGuardrail"}]
        }
        bedrock_client.get_guardrail.return_value = {
            "guardrail": {"contextualGroundingPolicy": {"filters": []}}
        }
        mock_client.return_value = bedrock_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-27"

    def test_br27_schema_valid(self):
        check = bedrock_app.check_bedrock_guardrail_contextual_grounding
        with patch("bedrock_app.boto3.client") as mock_client:
            bedrock_client = MagicMock()
            bedrock_client.list_guardrails.return_value = {"guardrails": []}
            mock_client.return_value = bedrock_client
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-28: check_bedrock_agent_guardrail_association
# ===================================================================
class TestBR28AgentGuardrailAssociation:
    """BR-28: Verify agents have an associated guardrail."""

    @staticmethod
    def _agent_client(summaries):
        agent_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"agentSummaries": summaries}]
        agent_client.get_paginator.return_value = paginator
        return agent_client

    @patch("bedrock_app.boto3.client")
    def test_br28_no_agents_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_agent_guardrail_association
        mock_client.return_value = self._agent_client([])

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-28"

    @patch("bedrock_app.boto3.client")
    def test_br28_agent_with_guardrail_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_agent_guardrail_association
        mock_client.return_value = self._agent_client(
            [
                {
                    "agentId": "a1",
                    "agentName": "SafeAgent",
                    "guardrailConfiguration": {
                        "guardrailIdentifier": "gr-1",
                        "guardrailVersion": "1",
                    },
                }
            ]
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) >= 1
        assert passed[0]["Check_ID"] == "BR-28"

    @patch("bedrock_app.boto3.client")
    def test_br28_agent_without_guardrail_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_agent_guardrail_association
        mock_client.return_value = self._agent_client(
            [{"agentId": "a1", "agentName": "OpenAgent"}]
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-28"
        assert findings[0]["Severity"] == "High"

    def test_br28_schema_valid(self):
        check = bedrock_app.check_bedrock_agent_guardrail_association
        with patch("bedrock_app.boto3.client") as mock_client:
            mock_client.return_value = self._agent_client([])
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-29: check_bedrock_agent_idle_session_ttl
# ===================================================================
class TestBR29AgentIdleSessionTTL:
    """BR-29: Verify agent idle session TTL is within the recommended bound."""

    @staticmethod
    def _agent_client(summaries, get_agent_return=None):
        agent_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"agentSummaries": summaries}]
        agent_client.get_paginator.return_value = paginator
        if get_agent_return is not None:
            agent_client.get_agent.return_value = get_agent_return
        return agent_client

    @patch("bedrock_app.boto3.client")
    def test_br29_no_agents_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_agent_idle_session_ttl
        mock_client.return_value = self._agent_client([])

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-29"

    @patch("bedrock_app.boto3.client")
    def test_br29_short_ttl_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_agent_idle_session_ttl
        mock_client.return_value = self._agent_client(
            [{"agentId": "a1", "agentName": "ShortAgent"}],
            {"agent": {"idleSessionTTLInSeconds": 600}},
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) >= 1
        assert passed[0]["Check_ID"] == "BR-29"

    @patch("bedrock_app.boto3.client")
    def test_br29_long_ttl_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_agent_idle_session_ttl
        mock_client.return_value = self._agent_client(
            [{"agentId": "a1", "agentName": "LongAgent"}],
            {"agent": {"idleSessionTTLInSeconds": 7200}},
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-29"

    def test_br29_schema_valid(self):
        check = bedrock_app.check_bedrock_agent_idle_session_ttl
        with patch("bedrock_app.boto3.client") as mock_client:
            mock_client.return_value = self._agent_client([])
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-30: check_bedrock_imported_model_kms_encryption
# ===================================================================
class TestBR30ImportedModelKMS:
    """BR-30: Verify imported models use customer-managed KMS keys."""

    @staticmethod
    def _bedrock_client(summaries, get_return=None, list_side_effect=None):
        bedrock_client = MagicMock()
        paginator = MagicMock()
        if list_side_effect is not None:
            paginator.paginate.side_effect = list_side_effect
        else:
            paginator.paginate.return_value = [{"modelSummaries": summaries}]
        bedrock_client.get_paginator.return_value = paginator
        if get_return is not None:
            bedrock_client.get_imported_model.return_value = get_return
        return bedrock_client

    @patch("bedrock_app.boto3.client")
    def test_br30_no_models_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_imported_model_kms_encryption
        mock_client.return_value = self._bedrock_client([])

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-30"

    @patch("bedrock_app.boto3.client")
    def test_br30_customer_key_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_imported_model_kms_encryption
        mock_client.return_value = self._bedrock_client(
            [{"modelArn": "arn:model:1", "modelName": "imported-1"}],
            {"modelKmsKeyArn": "arn:aws:kms:us-east-1:123:key/abc"},
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) >= 1
        assert passed[0]["Check_ID"] == "BR-30"

    @patch("bedrock_app.boto3.client")
    def test_br30_aws_owned_key_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_imported_model_kms_encryption
        mock_client.return_value = self._bedrock_client(
            [{"modelArn": "arn:model:1", "modelName": "imported-1"}],
            {},
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-30"
        assert findings[0]["Severity"] == "High"

    @patch("bedrock_app.boto3.client")
    def test_br30_access_denied_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_imported_model_kms_encryption
        mock_client.return_value = self._bedrock_client(
            [],
            list_side_effect=ClientError(
                {"Error": {"Code": "AccessDeniedException"}}, "ListImportedModels"
            ),
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-30"

    def test_br30_schema_valid(self):
        check = bedrock_app.check_bedrock_imported_model_kms_encryption
        with patch("bedrock_app.boto3.client") as mock_client:
            mock_client.return_value = self._bedrock_client([])
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-31: check_bedrock_batch_inference_output_encryption
# ===================================================================
class TestBR31BatchInferenceOutputEncryption:
    """BR-31: Verify batch inference jobs encrypt output with customer KMS."""

    @staticmethod
    def _bedrock_client(summaries, list_side_effect=None):
        bedrock_client = MagicMock()
        paginator = MagicMock()
        if list_side_effect is not None:
            paginator.paginate.side_effect = list_side_effect
        else:
            paginator.paginate.return_value = [{"invocationJobSummaries": summaries}]
        bedrock_client.get_paginator.return_value = paginator
        return bedrock_client

    @patch("bedrock_app.boto3.client")
    def test_br31_no_jobs_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_batch_inference_output_encryption
        mock_client.return_value = self._bedrock_client([])

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-31"

    @patch("bedrock_app.boto3.client")
    def test_br31_job_with_cmk_returns_passed(self, mock_client):
        check = bedrock_app.check_bedrock_batch_inference_output_encryption
        mock_client.return_value = self._bedrock_client(
            [
                {
                    "jobName": "batch-1",
                    "outputDataConfig": {
                        "s3OutputDataConfig": {
                            "s3Uri": "s3://out/",
                            "s3EncryptionKeyId": "arn:aws:kms:us-east-1:123:key/abc",
                        }
                    },
                }
            ]
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        passed = [f for f in findings if f["Status"] == "Passed"]
        assert len(passed) >= 1
        assert passed[0]["Check_ID"] == "BR-31"

    @patch("bedrock_app.boto3.client")
    def test_br31_job_without_cmk_returns_failed(self, mock_client):
        check = bedrock_app.check_bedrock_batch_inference_output_encryption
        mock_client.return_value = self._bedrock_client(
            [
                {
                    "jobName": "batch-1",
                    "outputDataConfig": {"s3OutputDataConfig": {"s3Uri": "s3://out/"}},
                }
            ]
        )

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-31"
        assert findings[0]["Severity"] == "Medium"

    def test_br31_schema_valid(self):
        check = bedrock_app.check_bedrock_batch_inference_output_encryption
        with patch("bedrock_app.boto3.client") as mock_client:
            mock_client.return_value = self._bedrock_client([])
            result = check(region="us-east-1")

        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# BR-32: check_bedrock_cloudwatch_alarms
# ===================================================================
class TestBR32CloudWatchAlarms:
    """BR-32: Verify CloudWatch alarms exist on AWS/Bedrock metrics."""

    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=False)
    @patch("bedrock_app.boto3.client")
    def test_br32_no_footprint_returns_na(self, mock_client, mock_footprint):
        check = bedrock_app.check_bedrock_cloudwatch_alarms
        result = check(region="eu-west-3")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-32"

    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    @patch("bedrock_app.boto3.client")
    def test_br32_bedrock_alarm_returns_passed(self, mock_client, mock_footprint):
        check = bedrock_app.check_bedrock_cloudwatch_alarms
        cw_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "MetricAlarms": [
                    {"AlarmName": "bedrock-throttle", "Namespace": "AWS/Bedrock"}
                ]
            }
        ]
        cw_client.get_paginator.return_value = paginator
        mock_client.return_value = cw_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "BR-32"

    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    @patch("bedrock_app.boto3.client")
    def test_br32_metric_math_alarm_returns_passed(self, mock_client, mock_footprint):
        check = bedrock_app.check_bedrock_cloudwatch_alarms
        cw_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "MetricAlarms": [
                    {
                        "AlarmName": "bedrock-tpm",
                        "Metrics": [
                            {"MetricStat": {"Metric": {"Namespace": "AWS/Bedrock"}}}
                        ],
                    }
                ]
            }
        ]
        cw_client.get_paginator.return_value = paginator
        mock_client.return_value = cw_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "BR-32"

    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    @patch("bedrock_app.boto3.client")
    def test_br32_no_bedrock_alarm_returns_failed(self, mock_client, mock_footprint):
        check = bedrock_app.check_bedrock_cloudwatch_alarms
        cw_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"MetricAlarms": [{"AlarmName": "ec2-cpu", "Namespace": "AWS/EC2"}]}
        ]
        cw_client.get_paginator.return_value = paginator
        mock_client.return_value = cw_client

        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "BR-32"
        assert findings[0]["Severity"] == "Medium"

    @patch("bedrock_app.detect_bedrock_regional_footprint", return_value=True)
    @patch("bedrock_app.boto3.client")
    def test_br32_schema_valid(self, mock_client, mock_footprint):
        check = bedrock_app.check_bedrock_cloudwatch_alarms
        cw_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"MetricAlarms": []}]
        cw_client.get_paginator.return_value = paginator
        mock_client.return_value = cw_client

        result = check(region="us-east-1")
        for f in extract_csv_data(result):
            assert_finding_schema(f)
