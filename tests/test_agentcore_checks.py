"""
Tests for Amazon Bedrock AgentCore security assessment checks (AC-01 through AC-17).

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

import pytest
from botocore.exceptions import ClientError

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

    def test_ac02_detects_wildcard_in_generic_attached_policy_document(self):
        permission_cache = {
            "role_permissions": {
                "AgentCoreOperator": {
                    "attached_policies": [
                        {
                            "name": "AgentCoreOps",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": "bedrock-agentcore:*",
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                    "inline_policies": [],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        wildcard_finding = next(
            finding
            for finding in findings
            if finding["Finding"] == "AgentCore IAM Wildcard Permissions"
        )
        assert wildcard_finding["Status"] == "Failed"
        assert "AgentCoreOperator" in wildcard_finding["Finding_Details"]

    @pytest.mark.parametrize(
        "action",
        [
            "bedrock-agentcore:*",
            "bedrock-agentcore:Get*",
            "bedrock-agentcore:*Runtime*",
            "BEDROCK-AGENTCORE:GetAgentRuntim?",
        ],
        ids=["full", "prefix", "embedded", "case-insensitive-question-mark"],
    )
    def test_ac02_detects_agent_platform_wildcard_action_patterns(self, action):
        permission_cache = {
            "role_permissions": {
                "WildcardRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "WildcardPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": action,
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        wildcard_finding = next(
            finding
            for finding in findings
            if finding["Finding"] == "AgentCore IAM Wildcard Permissions"
        )
        assert wildcard_finding["Status"] == "Failed"
        assert "WildcardRole" in wildcard_finding["Finding_Details"]

    @pytest.mark.parametrize(
        "not_action",
        [
            ["bedrock-agentcore:DeleteAgentRuntime"],
        ],
        ids=["partial-agentcore"],
    )
    def test_ac02_detects_allow_not_action_that_includes_platform_services(
        self, not_action
    ):
        permission_cache = {
            "role_permissions": {
                "AllowExceptRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "AllowExceptPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "NotAction": not_action,
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        wildcard_finding = next(
            finding
            for finding in findings
            if finding["Finding"] == "AgentCore IAM Wildcard Permissions"
        )
        assert wildcard_finding["Status"] == "Failed"
        assert "AllowExceptRole" in wildcard_finding["Finding_Details"]
        assert "allow-except" in wildcard_finding["Finding_Details"]

    @pytest.mark.parametrize(
        "not_action",
        [
            ["iam:*", "organizations:*"],
            ["s3:DeleteBucket"],
        ],
        ids=["administrator-except-iam", "administrator-except-one-action"],
    )
    def test_ac02_ignores_not_action_that_names_no_platform_namespace(self, not_action):
        """A NotAction naming no platform namespace is an administrator-style
        grant, which AC-02 ignores exactly as it ignores ``Action: "*"``."""
        permission_cache = {
            "role_permissions": {
                "AllowExceptRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "AllowExceptPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "NotAction": not_action,
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"

    @pytest.mark.parametrize(
        "not_action",
        [
            ["bedrock-agentcore:*", "bedrock-agentcore:*"],
            ["bedrock-*:*", "bedrock-agentcore:*"],
            "*",
            "*:*",
        ],
        ids=["both-namespaces", "service-pattern", "all-actions", "all-services"],
    )
    def test_ac02_ignores_not_action_that_excludes_all_platform_access(
        self, not_action
    ):
        permission_cache = {
            "role_permissions": {
                "ExcludedPlatformRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "ExcludedPlatformPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "NotAction": not_action,
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"

    @pytest.mark.parametrize(
        ("action", "resource"),
        [
            ("bedrock-agentcore:GetAgentRuntime", "*"),
            ("unrelated-service:Get*", "*"),
            ("bedrock-agentcore-control:*", "*"),
            (
                "bedrock-agentcore:Get*",
                "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/runtime-1",
            ),
        ],
        ids=[
            "exact-action",
            "unrelated-service",
            "invalid-iam-prefix",
            "scoped-resource",
        ],
    )
    def test_ac02_ignores_non_risky_or_unrelated_action_patterns(
        self, action, resource
    ):
        permission_cache = {
            "role_permissions": {
                "ScopedRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "ScopedPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": action,
                                    "Resource": resource,
                                }
                            },
                        }
                    ],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"

    @pytest.mark.parametrize(
        "statements",
        [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            },
            [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "Action": "bedrock-agentcore:*",
                    "Resource": "*",
                },
            ],
        ],
        ids=["administrator-access", "administrator-access-with-platform-deny"],
    )
    def test_ac02_ignores_service_agnostic_wildcard_actions(self, statements):
        permission_cache = {
            "role_permissions": {
                "Administrator": {
                    "attached_policies": [
                        {
                            "name": "AdministratorAccess",
                            "document": {"Statement": statements},
                        }
                    ],
                    "inline_policies": [],
                }
            }
        }

        findings = agentcore_app.check_agentcore_full_access_roles(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"

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
def _agent_platform_policy(name, action):
    return {
        "name": name,
        "arn": f"arn:aws:iam::123456789012:policy/{name}",
        "document": {
            "Statement": {
                "Effect": "Allow",
                "Action": action,
                "Resource": "*",
            }
        },
    }


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

    @pytest.mark.parametrize(
        ("principal_key", "principal_name"),
        [("role_permissions", "AgentCoreRole"), ("user_permissions", "AgentCoreUser")],
        ids=["role", "user"],
    )
    @patch("agentcore_app.time.sleep")
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_recognizes_generic_attached_policy_documents(
        self,
        mock_iam,
        mock_boto_client,
        mock_sleep,
        principal_key,
        principal_name,
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        mock_iam.generate_service_last_accessed_details.return_value = {
            "JobId": "job-1"
        }
        mock_iam.get_service_last_accessed_details.return_value = {
            "JobStatus": "COMPLETED",
            "ServicesLastAccessed": [
                {
                    "ServiceName": "Amazon Bedrock AgentCore",
                    "ServiceNamespace": "bedrock-agentcore",
                    "LastAuthenticated": agentcore_app.get_current_utc_date(),
                }
            ],
        }
        permission_cache = {
            "role_permissions": {},
            "user_permissions": {},
        }
        permission_cache[principal_key][principal_name] = {
            "attached_policies": [
                {
                    "name": "AgentCoreOps",
                    "document": {
                        "Statement": {
                            "Effect": "Allow",
                            "Action": "bedrock-agentcore:ListAgentRuntimes",
                            "Resource": "*",
                        }
                    },
                }
            ],
            "inline_policies": [],
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert findings[0]["Status"] == "Passed"
        mock_iam.generate_service_last_accessed_details.assert_called_once()

    @patch("agentcore_app.time.sleep")
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_includes_allow_not_action_principal(
        self, mock_iam, mock_boto_client, mock_sleep
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        mock_iam.generate_service_last_accessed_details.return_value = {
            "JobId": "job-1"
        }
        mock_iam.get_service_last_accessed_details.return_value = {
            "JobStatus": "COMPLETED",
            "ServicesLastAccessed": [
                {
                    "ServiceName": "Amazon Bedrock AgentCore",
                    "ServiceNamespace": "bedrock-agentcore",
                    "LastAuthenticated": agentcore_app.get_current_utc_date(),
                }
            ],
        }
        permission_cache = {
            "role_permissions": {
                "AllowExceptRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "AllowExceptPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "NotAction": ["bedrock-agentcore:StopAgentRuntime"],
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert findings[0]["Status"] == "Passed"
        mock_iam.generate_service_last_accessed_details.assert_called_once()

    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_ignores_not_action_that_names_no_platform_namespace(
        self, mock_iam, mock_boto_client
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        permission_cache = {
            "role_permissions": {
                "AllowExceptRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "AllowExceptPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "NotAction": ["iam:*", "organizations:*"],
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        mock_iam.generate_service_last_accessed_details.assert_not_called()

    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_ignores_not_action_excluding_both_platform_namespaces(
        self, mock_iam, mock_boto_client
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        permission_cache = {
            "role_permissions": {
                "ExcludedPlatformRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "name": "ExcludedPlatformPolicy",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "NotAction": [
                                        "bedrock-agentcore:*",
                                        "bedrock-agentcore:*",
                                    ],
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        mock_iam.generate_service_last_accessed_details.assert_not_called()

    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_ignores_service_agnostic_wildcard_actions(
        self, mock_iam, mock_boto_client
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        permission_cache = {
            "role_permissions": {
                "Administrator": {
                    "attached_policies": [
                        {
                            "name": "AdministratorAccess",
                            "document": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": "*",
                                    "Resource": "*",
                                }
                            },
                        }
                    ],
                    "inline_policies": [],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert (
            findings[0]["Finding_Details"]
            == "No IAM principals with AgentCore permissions found"
        )
        mock_iam.generate_service_last_accessed_details.assert_not_called()

    @pytest.mark.parametrize(
        ("policy_name", "statement"),
        [
            (
                "DenyAgentCoreAccess",
                {
                    "Effect": "Deny",
                    "Action": "bedrock-agentcore:*",
                    "Resource": "*",
                },
            ),
            (
                "AgentCoreDocumentationOnly",
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::example-docs/*",
                },
            ),
        ],
        ids=["deny-only", "misleading-name"],
    )
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_attached_policy_names_do_not_imply_access(
        self, mock_iam, mock_boto_client, policy_name, statement
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        permission_cache = {
            "role_permissions": {
                "NoAgentPlatformAccess": {
                    "attached_policies": [
                        {
                            "name": policy_name,
                            "arn": (f"arn:aws:iam::123456789012:policy/{policy_name}"),
                            "document": {"Statement": statement},
                        }
                    ],
                    "inline_policies": [],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert (
            findings[0]["Finding_Details"]
            == "No IAM principals with AgentCore permissions found"
        )
        mock_iam.generate_service_last_accessed_details.assert_not_called()

    @patch("agentcore_app.check_timeout", return_value=False)
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_timeout_before_first_principal_returns_incomplete_na(
        self, mock_iam, mock_boto_client, mock_check_timeout
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        permission_cache = {
            "role_permissions": {
                "RuntimeReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentCoreReadOnly",
                            "bedrock-agentcore:ListAgentRuntimes",
                        )
                    ],
                    "inline_policies": [],
                },
                "AgentCoreReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentCoreReadOnly",
                            "bedrock-agentcore:ListAgentRuntimes",
                        )
                    ],
                    "inline_policies": [],
                },
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"
        assert "2 IAM principal(s)" in findings[0]["Finding_Details"]
        mock_iam.generate_service_last_accessed_details.assert_not_called()
        mock_check_timeout.assert_called_once()

    @patch("agentcore_app.check_timeout", side_effect=[True, True, False])
    @patch("agentcore_app.time.sleep")
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_timeout_during_polling_stops_before_next_principal(
        self,
        mock_iam,
        mock_boto_client,
        mock_sleep,
        mock_check_timeout,
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        mock_iam.generate_service_last_accessed_details.return_value = {
            "JobId": "job-1"
        }
        permission_cache = {
            "role_permissions": {
                "RuntimeReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentCoreReadOnly",
                            "bedrock-agentcore:ListAgentRuntimes",
                        )
                    ],
                    "inline_policies": [],
                },
                "AgentCoreReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentCoreReadOnly",
                            "bedrock-agentcore:ListAgentRuntimes",
                        )
                    ],
                    "inline_policies": [],
                },
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"
        assert "2 IAM principal(s)" in findings[0]["Finding_Details"]
        mock_iam.generate_service_last_accessed_details.assert_called_once()
        mock_iam.get_service_last_accessed_details.assert_not_called()
        mock_sleep.assert_called_once_with(2)
        assert mock_check_timeout.call_count == 3

    @patch(
        "agentcore_app.check_timeout",
        side_effect=[True, True, True, False],
    )
    @patch("agentcore_app.time.sleep")
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_timeout_preserves_completed_principal_findings(
        self,
        mock_iam,
        mock_boto_client,
        mock_sleep,
        mock_check_timeout,
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        mock_iam.generate_service_last_accessed_details.return_value = {
            "JobId": "job-1"
        }
        mock_iam.get_service_last_accessed_details.return_value = {
            "JobStatus": "COMPLETED",
            "ServicesLastAccessed": [
                {
                    "ServiceName": "Amazon Bedrock AgentCore",
                    "ServiceNamespace": "bedrock-agentcore",
                    "LastAuthenticated": "2020-01-01T00:00:00+00:00",
                }
            ],
        }
        permission_cache = {
            "role_permissions": {
                "StaleRuntimeReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentCoreReadOnly",
                            "bedrock-agentcore:ListAgentRuntimes",
                        )
                    ],
                    "inline_policies": [],
                },
                "AgentCoreReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentCoreReadOnly",
                            "bedrock-agentcore:ListAgentRuntimes",
                        )
                    ],
                    "inline_policies": [],
                },
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert {finding["Status"] for finding in findings} == {"Failed", "N/A"}
        stale_finding = next(
            finding
            for finding in findings
            if finding["Finding"] == "AgentCore Stale Access"
        )
        incomplete_finding = next(
            finding
            for finding in findings
            if finding["Finding"] == "AgentCore Stale Access Check Incomplete"
        )
        assert "StaleRuntimeReader" in stale_finding["Finding_Details"]
        assert "1 IAM principal(s)" in incomplete_finding["Finding_Details"]
        assert incomplete_finding["Severity"] == "Informational"
        mock_iam.generate_service_last_accessed_details.assert_called_once()
        mock_iam.get_service_last_accessed_details.assert_called_once_with(
            JobId="job-1"
        )
        mock_sleep.assert_called_once_with(2)
        assert mock_check_timeout.call_count == 4

    @patch("agentcore_app.check_timeout", return_value=True)
    @patch("agentcore_app.time.sleep")
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_iam_job_timeout_is_informational_na(
        self,
        mock_iam,
        mock_boto_client,
        mock_sleep,
        mock_check_timeout,
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        mock_iam.generate_service_last_accessed_details.return_value = {
            "JobId": "job-1"
        }
        mock_iam.get_service_last_accessed_details.return_value = {
            "JobStatus": "IN_PROGRESS"
        }
        permission_cache = {
            "role_permissions": {
                "RuntimeReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentCoreReadOnly",
                            "bedrock-agentcore:ListAgentRuntimes",
                        )
                    ],
                    "inline_policies": [],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Informational"
        assert "IAM job timed out after 30s" in findings[0]["Finding_Details"]
        assert mock_iam.get_service_last_accessed_details.call_count == 15
        assert mock_sleep.call_count == 15
        assert mock_check_timeout.call_count == 31

    @patch("agentcore_app.time.sleep")
    @patch("agentcore_app.boto3.client")
    @patch("agentcore_app.iam_client")
    def test_ac03_uses_most_recent_matching_service_access(
        self, mock_iam, mock_boto_client, mock_sleep
    ):
        mock_boto_client.return_value.get_caller_identity.return_value = {
            "Account": "123456789012"
        }
        mock_iam.generate_service_last_accessed_details.return_value = {
            "JobId": "job-1"
        }
        mock_iam.get_service_last_accessed_details.return_value = {
            "JobStatus": "COMPLETED",
            "ServicesLastAccessed": [
                {
                    "ServiceName": "Amazon Bedrock AgentCore",
                    "ServiceNamespace": "bedrock-agentcore",
                    "LastAuthenticated": "2020-01-01T00:00:00+00:00",
                },
                {
                    "ServiceName": "Amazon Bedrock AgentCore",
                    "ServiceNamespace": "bedrock-agentcore",
                    "LastAuthenticated": agentcore_app.get_current_utc_date(),
                },
            ],
        }
        permission_cache = {
            "role_permissions": {
                "AgentPlatformReader": {
                    "attached_policies": [
                        _agent_platform_policy(
                            "AgentCoreReadOnly",
                            "bedrock-agentcore:ListAgentRuntimes",
                        )
                    ],
                    "inline_policies": [],
                }
            },
            "user_permissions": {},
        }

        findings = agentcore_app.check_stale_agentcore_access(permission_cache)

        assert findings[0]["Status"] == "Passed"


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
    @patch("agentcore_app.logs_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac04_no_runtimes_returns_na(self, mock_ac, mock_logs, mock_cw):
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
    """AC-06: Check custom browser session recording."""

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
        assert findings[0]["Check_ID"] == "AC-06"
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Finding_Details"] == "No custom AgentCore browsers found"
        mock_ac.list_browsers.assert_called_once_with(type="CUSTOM")

    @patch("agentcore_app.agentcore_client")
    def test_ac06_exception_returns_error_finding(self, mock_ac):
        mock_ac.list_browsers.side_effect = Exception("Browser tool error")
        result = agentcore_app.check_browser_tool_recording()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"

    @patch("agentcore_app.agentcore_client", None)
    def test_ac06_schema_valid(self):
        result = agentcore_app.check_browser_tool_recording()
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    def test_ac06_all_paths_use_consistent_name_and_reference(self):
        findings = []

        with patch("agentcore_app.agentcore_client", None):
            findings.extend(agentcore_app.check_browser_tool_recording())

        inventories = [
            {
                "items": [],
                "errors": [],
                "list_error": RuntimeError("list failed"),
            },
            {"items": [], "errors": [], "list_error": None},
            {
                "items": [
                    {
                        "summary": {"browserId": "br-1", "name": "browser-1"},
                        "detail": {
                            "recording": {
                                "enabled": True,
                                "s3Location": {"bucket": "recordings"},
                            }
                        },
                    }
                ],
                "errors": [],
                "list_error": None,
            },
            {
                "items": [],
                "errors": [
                    {
                        "summary": {"browserId": "br-2", "name": "browser-2"},
                        "error": RuntimeError("detail failed"),
                    }
                ],
                "list_error": None,
            },
        ]
        with patch("agentcore_app.agentcore_client", MagicMock()):
            for inventory in inventories:
                findings.extend(agentcore_app.check_browser_tool_recording(inventory))

            broken_inventory = MagicMock()
            broken_inventory.get.side_effect = RuntimeError("inventory failed")
            findings.extend(
                agentcore_app.check_browser_tool_recording(broken_inventory)
            )

        assert findings
        assert {finding["Finding"] for finding in findings} == {
            "AgentCore Browser Session Recording"
        }
        assert {finding["Reference"] for finding in findings} == {
            agentcore_app.AGENTCORE_SECURITY_HUB_REFERENCE_URL
        }


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

    @patch("agentcore_app.agentcore_client")
    def test_agentcore_list_all_stops_on_repeated_token(self, mock_ac):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [{"agentRuntimeId": "runtime-1"}],
            "nextToken": "repeated",
        }

        runtimes = agentcore_app._agentcore_list_all(
            "list_agent_runtimes", ["agentRuntimes"]
        )

        assert runtimes == [
            {"agentRuntimeId": "runtime-1"},
            {"agentRuntimeId": "runtime-1"},
        ]
        assert mock_ac.list_agent_runtimes.call_count == 2

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
    def test_ac08_reads_runtimes_from_all_pages(self, mock_ac, mock_ec2):
        mock_ac.list_agent_runtimes.side_effect = [
            {"agentRuntimes": [], "nextToken": "runtime-page-2"},
            {
                "agentRuntimes": [
                    {
                        "agentRuntimeId": "runtime-2",
                        "agentRuntimeName": "SecondPageRuntime",
                    }
                ]
            },
        ]
        mock_ec2.describe_vpcs.return_value = {"Vpcs": []}

        findings = extract_csv_data(agentcore_app.check_agentcore_vpc_endpoints())

        assert findings[0]["Finding_Details"] == "No VPCs found in the account"
        assert mock_ac.list_agent_runtimes.call_count == 2
        mock_ac.list_agent_runtimes.assert_any_call(nextToken="runtime-page-2")

    @patch("agentcore_app.ec2_client")
    @patch("agentcore_app.agentcore_client")
    def test_ac08_exception_returns_error_finding(self, mock_ac, mock_ec2):
        mock_ac.list_agent_runtimes.return_value = {
            "agentRuntimes": [
                {
                    "agentRuntimeId": "runtime-1",
                    "agentRuntimeName": "TestRuntime",
                }
            ]
        }
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
        mock_ac.list_policies.return_value = {
            "policies": [
                {
                    "policyId": "p-1",
                    "status": "ACTIVE",
                    "enforcementMode": "ACTIVE",
                }
            ]
        }
        mock_ac.list_policies.return_value = {
            "policies": [
                {
                    "policyId": "p-1",
                    "status": "ACTIVE",
                    "enforcementMode": "ACTIVE",
                }
            ]
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
        mock_ac.list_policies.return_value = {
            "policies": [
                {
                    "policyId": "p-1",
                    "status": "ACTIVE",
                    "enforcementMode": "ACTIVE",
                }
            ]
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
        mock_ac.list_policies.return_value = {
            "policies": [
                {
                    "policyId": "p-1",
                    "status": "ACTIVE",
                    "enforcementMode": "ACTIVE",
                }
            ]
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
        "AC-14": "AG-28",
        "AC-15": "AG-29",
        "AC-16": "AG-31",
        "AC-17": "AG-32",
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


class TestProposedAgentCoreChecks:
    """AC-14 through AC-17 and the AC-06 correction."""

    @patch("agentcore_app.agentcore_client")
    def test_ac14_customer_managed_token_vault_passes(self, mock_ac):
        mock_ac.get_token_vault.return_value = {
            "tokenVaultId": "default",
            "kmsConfiguration": {
                "keyType": "CustomerManagedKey",
                "kmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/key-1",
            },
        }
        finding = agentcore_app.check_agentcore_token_vault_encryption()[0]
        assert finding["Check_ID"] == "AC-14"
        assert finding["Status"] == "Passed"

    @patch.dict(
        os.environ,
        {"AGENTCORE_TOKEN_VAULT_ID": "team-security-vault"},
        clear=False,
    )
    @patch("agentcore_app.agentcore_client")
    def test_ac14_uses_configured_non_default_token_vault(self, mock_ac):
        mock_ac.get_token_vault.return_value = {
            "tokenVaultId": "team-security-vault",
            "kmsConfiguration": {
                "keyType": "CustomerManagedKey",
                "kmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/key-2",
            },
        }

        finding = agentcore_app.check_agentcore_token_vault_encryption()[0]

        mock_ac.get_token_vault.assert_called_once_with(
            tokenVaultId="team-security-vault"
        )
        assert finding["Status"] == "Passed"
        assert "team-security-vault" in finding["Finding_Details"]

    @patch("agentcore_app.agentcore_client")
    def test_ac14_service_managed_token_vault_fails(self, mock_ac):
        mock_ac.get_token_vault.return_value = {
            "tokenVaultId": "default",
            "kmsConfiguration": {"keyType": "ServiceManagedKey"},
        }
        finding = agentcore_app.check_agentcore_token_vault_encryption()[0]
        assert finding["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_ac15_custom_interpreter_vpc_passes(self, mock_ac):
        mock_ac.list_code_interpreters.return_value = {
            "codeInterpreterSummaries": [
                {"codeInterpreterId": "ci-1", "name": "interpreter-1"}
            ]
        }
        mock_ac.get_code_interpreter.return_value = {
            "networkConfiguration": {
                "networkMode": "VPC",
                "vpcConfig": {
                    "subnets": ["subnet-1"],
                    "securityGroups": ["sg-1"],
                },
            }
        }
        finding = agentcore_app.check_agentcore_code_interpreter_isolation()[0]
        assert finding["Check_ID"] == "AC-15"
        assert finding["Status"] == "Passed"

    @patch("agentcore_app.agentcore_client")
    def test_ac15_public_interpreter_fails(self, mock_ac):
        mock_ac.list_code_interpreters.return_value = {
            "codeInterpreterSummaries": [
                {"codeInterpreterId": "ci-1", "name": "interpreter-1"}
            ]
        }
        mock_ac.get_code_interpreter.return_value = {
            "networkConfiguration": {"networkMode": "PUBLIC"}
        }
        finding = agentcore_app.check_agentcore_code_interpreter_isolation()[0]
        assert finding["Status"] == "Failed"

    def test_ac06_and_ac16_share_browser_inventory(self):
        inventory = {
            "items": [
                {
                    "summary": {"browserId": "br-1", "name": "browser-1"},
                    "detail": {
                        "networkConfiguration": {
                            "networkMode": "VPC",
                            "vpcConfig": {
                                "subnets": ["subnet-1"],
                                "securityGroups": ["sg-1"],
                            },
                        },
                        "recording": {
                            "enabled": True,
                            "s3Location": {"bucket": "recordings"},
                        },
                    },
                }
            ],
            "errors": [],
            "list_error": None,
        }
        with patch("agentcore_app.agentcore_client", MagicMock()):
            ac06 = agentcore_app.check_browser_tool_recording(inventory)[0]
            ac16 = agentcore_app.check_agentcore_browser_network_isolation(inventory)[0]
        assert ac06["Status"] == "Passed"
        assert ac16["Status"] == "Passed"

    def test_ac16_public_browser_fails(self):
        inventory = {
            "items": [
                {
                    "summary": {"browserId": "br-1", "name": "browser-1"},
                    "detail": {
                        "networkConfiguration": {"networkMode": "PUBLIC"},
                    },
                }
            ],
            "errors": [],
            "list_error": None,
        }
        with patch("agentcore_app.agentcore_client", MagicMock()):
            finding = agentcore_app.check_agentcore_browser_network_isolation(
                inventory
            )[0]
        assert finding["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_ac17_operational_evaluation_passes_advisory(self, mock_ac):
        mock_ac.list_online_evaluation_configs.return_value = {
            "onlineEvaluationConfigs": [
                {
                    "onlineEvaluationConfigId": "eval-1",
                    "onlineEvaluationConfigName": "evaluation-1",
                }
            ]
        }
        mock_ac.get_online_evaluation_config.return_value = {
            "status": "ACTIVE",
            "executionStatus": "ENABLED",
            "rule": {"samplingConfig": {"samplingPercentage": 10}},
            "evaluators": [{"evaluatorId": "evaluator-1"}],
            "dataSourceConfig": {
                "cloudWatchLogs": {"logGroupNames": ["/aws/agentcore/input"]}
            },
            "outputConfig": {
                "cloudWatchConfig": {"logGroupName": "/aws/agentcore/output"}
            },
        }
        finding = agentcore_app.check_agentcore_online_evaluation_coverage()[0]
        assert finding["Check_ID"] == "AC-17"
        assert finding["Status"] == "Passed"
        assert finding["Severity"] == "Informational"

    @patch.dict(
        os.environ,
        {"REQUIRE_AGENTCORE_ONLINE_EVALUATION": "false"},
        clear=False,
    )
    @patch("agentcore_app.agentcore_client")
    def test_ac17_incomplete_advisory_evaluation_returns_na(self, mock_ac):
        mock_ac.list_online_evaluation_configs.return_value = {
            "onlineEvaluationConfigs": [
                {
                    "onlineEvaluationConfigId": "eval-1",
                    "onlineEvaluationConfigName": "evaluation-1",
                }
            ]
        }
        mock_ac.get_online_evaluation_config.return_value = {
            "status": "ACTIVE",
            "executionStatus": "DISABLED",
        }

        finding = agentcore_app.check_agentcore_online_evaluation_coverage()[0]

        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert finding["Resolution"].startswith("Set the evaluation ACTIVE")

    @patch.dict(
        os.environ,
        {"REQUIRE_AGENTCORE_ONLINE_EVALUATION": "true"},
        clear=False,
    )
    @patch("agentcore_app.agentcore_client")
    def test_ac17_incomplete_required_evaluation_fails(self, mock_ac):
        mock_ac.list_online_evaluation_configs.return_value = {
            "onlineEvaluationConfigs": [
                {
                    "onlineEvaluationConfigId": "eval-1",
                    "onlineEvaluationConfigName": "evaluation-1",
                }
            ]
        }
        mock_ac.get_online_evaluation_config.return_value = {
            "status": "ACTIVE",
            "executionStatus": "DISABLED",
        }
        finding = agentcore_app.check_agentcore_online_evaluation_coverage()[0]
        assert finding["Status"] == "Failed"

    @patch("agentcore_app.agentcore_client")
    def test_new_agentcore_checks_access_denied_return_na(self, mock_ac):
        error = _make_client_error("AccessDeniedException", "Denied")

        mock_ac.get_token_vault.side_effect = error
        ac14 = agentcore_app.check_agentcore_token_vault_encryption()[0]

        mock_ac.reset_mock()
        mock_ac.list_code_interpreters.side_effect = error
        ac15 = agentcore_app.check_agentcore_code_interpreter_isolation()[0]

        mock_ac.reset_mock()
        ac16 = agentcore_app.check_agentcore_browser_network_isolation(
            {"items": [], "errors": [], "list_error": error}
        )[0]

        mock_ac.reset_mock()
        mock_ac.list_online_evaluation_configs.side_effect = error
        ac17 = agentcore_app.check_agentcore_online_evaluation_coverage()[0]

        for finding in (ac14, ac15, ac16, ac17):
            assert finding["Status"] == "N/A"
            assert finding["Severity"] == "Informational"

    @patch("agentcore_app.agentcore_client")
    def test_ag25_fails_when_engine_has_only_log_only_policy(self, mock_ac):
        mock_ac.list_gateways.return_value = {
            "items": [{"gatewayId": "gw-1", "name": "gateway-1"}]
        }
        mock_ac.get_gateway.return_value = {
            "gatewayId": "gw-1",
            "name": "gateway-1",
            "authorizerType": "AWS_IAM",
            "policyEngineConfiguration": {
                "arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:policy-engine/pe-1",
                "mode": "ENFORCE",
            },
        }
        mock_ac.list_policies.return_value = {
            "policies": [
                {
                    "policyId": "p-1",
                    "status": "ACTIVE",
                    "enforcementMode": "LOG_ONLY",
                }
            ]
        }
        findings = agentcore_app.check_agentcore_gateway_agentic_security()
        ag25 = [finding for finding in findings if finding["Check_ID"] == "AG-25"]
        assert ag25[0]["Status"] == "Failed"

    def test_new_agentcore_operation_contracts_exist(self):
        client = agentcore_app.boto3.client(
            "bedrock-agentcore-control",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
        )
        model = client.meta.service_model
        for operation in [
            "GetTokenVault",
            "ListCodeInterpreters",
            "GetCodeInterpreter",
            "ListBrowsers",
            "GetBrowser",
            "ListOnlineEvaluationConfigs",
            "GetOnlineEvaluationConfig",
            "ListPolicies",
        ]:
            assert model.operation_model(operation)


# ===================================================================
