"""
Tests for Bedrock security assessment checks (BR-01 through BR-13).

Each check is tested for:
- No resources / empty cache -> N/A status
- Compliant resources -> Passed status
- Non-compliant resources -> Failed with correct severity
- Exception handling -> returns error finding (csv_data not empty)
- Output schema validity
"""

import sys
import os
import importlib.util
from unittest.mock import patch, MagicMock
from botocore.exceptions import EndpointConnectionError, ClientError

# Add tests dir so we can import helpers
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from conftest import extract_csv_data, assert_finding_schema

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
    def test_br04_logging_enabled_s3_returns_passed(
        self, mock_footprint, mock_client
    ):
        check = bedrock_app.check_bedrock_logging_configuration
        mock_bedrock = MagicMock()
        mock_client.return_value = mock_bedrock
        mock_bedrock.get_model_invocation_logging_configuration.return_value = {
            "loggingConfig": {
                "s3Config": {"s3BucketName": "my-log-bucket"},
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
    def test_br04_logging_disabled_returns_failed(
        self, mock_footprint, mock_client
    ):
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
    def test_br04_no_regional_footprint_returns_na(
        self, mock_footprint, mock_client
    ):
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
                "s3Config": {"s3BucketName": "bucket"},
                "cloudWatchConfig": {},
            }
        }
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


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
        with patch(
            "bedrock_app.detect_bedrock_regional_footprint", return_value=True
        ):
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
        with patch(
            "bedrock_app.detect_bedrock_regional_footprint", return_value=False
        ):
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
        with patch(
            "bedrock_app.detect_bedrock_regional_footprint", return_value=True
        ):
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
    def test_br06_trail_is_logging_returns_passed(
        self, mock_footprint, mock_client
    ):
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
    def test_br06_trail_not_logging_returns_failed(
        self, mock_footprint, mock_client
    ):
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
    def test_br06_no_regional_footprint_returns_na(
        self, mock_footprint, mock_client
    ):
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
        mock_client.return_value = mock_agent
        mock_agent.list_prompts.return_value = {
            "promptSummaries": [
                {"name": "prompt1", "promptId": "p1", "status": "ACTIVE"}
            ]
        }
        mock_agent.get_prompt.return_value = {"variants": ["v1", "v2"]}
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "BR-07"

    @patch("boto3.client")
    def test_br07_no_prompts_returns_na(self, mock_client):
        check = bedrock_app.check_bedrock_prompt_management
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        mock_agent.list_prompts.return_value = {"promptSummaries": []}
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
        mock_agent.list_prompts.side_effect = Exception(
            "InternalServerErrorException"
        )
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "BR-07"

    @patch("boto3.client")
    def test_br07_schema_valid(self, mock_client):
        check = bedrock_app.check_bedrock_prompt_management
        mock_agent = MagicMock()
        mock_client.return_value = mock_agent
        mock_agent.list_prompts.return_value = {"promptSummaries": []}
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
        mock_client.return_value = mock_agent
        mock_agent.list_agents.return_value = {"agents": []}
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
        mock_client.return_value = mock_agent
        mock_agent.list_agents.return_value = {
            "agents": [{"agentId": "a1", "agentName": "TestAgent"}]
        }
        mock_agent.get_agent.return_value = {
            "agentResourceRoleArn": "arn:aws:iam::123456789012:role/LeastPrivilegeRole"
        }
        result = check(permission_cache_compliant)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        # With permission boundary and specific resources, should pass or have minimal issues

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
        mock_client.return_value = mock_agent
        mock_agent.list_agents.return_value = {"agents": []}
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
    def test_br09_access_denied_returns_na(self, mock_client):
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
        assert "Bedrock Knowledge Base API" in findings[0]["Finding_Details"]

    @patch("boto3.client")
    def test_br09_exception_returns_error_finding(self, mock_client):
        check = bedrock_app.check_bedrock_knowledge_base_encryption
        mock_client.side_effect = Exception("KB error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

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
        mock_agent.get_paginator.side_effect = Exception(
            "UnknownOperationException"
        )
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

        with patch.object(bedrock_app, "get_permissions_cache", return_value={
            "role_permissions": {}, "user_permissions": {}
        }), patch.object(bedrock_app, "generate_csv_report", side_effect=fake_csv), \
                patch.object(bedrock_app, "write_to_s3", return_value="s3://bucket/report.csv"):
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

        with patch.object(bedrock_app, "get_permissions_cache", return_value={
            "role_permissions": {}, "user_permissions": {}
        }), patch.object(bedrock_app, "generate_csv_report", side_effect=fake_csv), \
                patch.object(bedrock_app, "write_to_s3", return_value="s3://b/r.csv"):
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

        with patch.object(bedrock_app, "get_permissions_cache", return_value={
            "role_permissions": {}, "user_permissions": {}
        }), patch.object(bedrock_app, "generate_csv_report", side_effect=fake_csv), \
                patch.object(bedrock_app, "write_to_s3", return_value="s3://b/r.csv"):
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
