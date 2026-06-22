"""
Additional tests targeting the uncovered branches in finserv_assessments/app.py.
These complement test_checks.py to push coverage from 83% → 90%+.

Each class targets a specific uncovered branch identified from coverage.json.
"""

import json
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError
from unittest.mock import MagicMock, patch

from .support import finserv_app as app
from .support import make_resource_inventory


def _client_error(code="AccessDeniedException", message="Access Denied"):
    return ClientError({"Error": {"Code": code, "Message": message}}, "Op")


def _assert_structure(result):
    assert "check_name" in result
    assert result["status"] in ("PASS", "WARN", "ERROR")
    assert isinstance(result["csv_data"], list)


# =========================================================================
# FS-01 — line 126: shield ClientError path (not ResourceNotFoundException)
# =========================================================================


class TestFS01ShieldClientError:
    def test_shield_generic_client_error_treated_as_no_shield(self):
        """Line 126-128: ClientError on describe_subscription → shield_enabled stays False."""
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(
                summaries=[{"Name": "acl1", "Id": "id1"}],
                detail_by_id={},
            )
        )
        with patch("finserv_app.boto3.client") as mock_client:

            def side_effect(service, **kwargs):
                if service == "shield":
                    c = MagicMock()
                    c.describe_subscription.side_effect = _client_error(
                        "ThrottlingException"
                    )
                    c.exceptions.ResourceNotFoundException = type(
                        "ResourceNotFoundException", (ClientError,), {}
                    )
                    return c
                return MagicMock()

            mock_client.side_effect = side_effect
            result = app.check_waf_shield_on_bedrock_endpoints(inv)
        _assert_structure(result)
        # Shield not enabled → WARN, but WAF ACLs present → only 1 WARN finding
        assert result["status"] == "WARN"
        statuses = [r["Status"] for r in result["csv_data"]]
        assert "Failed" in statuses  # shield failed
        assert "Passed" in statuses  # waf passed


# =========================================================================
# FS-07 — lines 532-534, 537, 543, 546: new per-agent error handling paths
# =========================================================================


class TestFS07AgentBoundariesNewPaths:
    @patch("finserv_app.boto3.client")
    def test_get_agent_client_error_skips_agent(self, mock_client):
        """Lines 532-534: get_agent raises ClientError → agent is skipped gracefully."""
        c = MagicMock()
        c.list_agents.return_value = {
            "agentSummaries": [{"agentId": "a1", "agentName": "EncryptedAgent"}]
        }
        c.get_agent.side_effect = _client_error("AccessDeniedException")
        mock_client.return_value = c
        result = app.check_bedrock_agent_action_boundaries({})
        _assert_structure(result)
        # Should PASS (no issues found, agent was skipped)
        assert result["status"] == "PASS"

    @patch("finserv_app.boto3.client")
    def test_agent_no_role_arn_skipped(self, mock_client):
        """Line 537: agent with no agentResourceRoleArn → continue."""
        c = MagicMock()
        c.list_agents.return_value = {
            "agentSummaries": [{"agentId": "a1", "agentName": "NoRoleAgent"}]
        }
        c.get_agent.return_value = {"agent": {"agentResourceRoleArn": ""}}
        mock_client.return_value = c
        result = app.check_bedrock_agent_action_boundaries({})
        _assert_structure(result)
        assert result["status"] == "PASS"

    @patch("finserv_app.boto3.client")
    def test_policy_doc_as_string_is_parsed(self, mock_client):
        """Line 543: policy document stored as JSON string → json.loads branch."""
        c = MagicMock()
        c.list_agents.return_value = {
            "agentSummaries": [{"agentId": "a1", "agentName": "Agent1"}]
        }
        c.get_agent.return_value = {
            "agent": {"agentResourceRoleArn": "arn:aws:iam::123:role/SafeRole"}
        }
        mock_client.return_value = c
        cache = {
            "role_permissions": {
                "SafeRole": {
                    "attached_policies": [
                        {
                            "document": json.dumps(
                                {
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": "bedrock:InvokeModel",
                                            "Resource": "*",
                                        }
                                    ]
                                }
                            )
                        }
                    ],
                    "inline_policies": [],
                }
            }
        }
        result = app.check_bedrock_agent_action_boundaries(cache)
        _assert_structure(result)
        assert result["status"] == "PASS"

    @patch("finserv_app.boto3.client")
    def test_deny_effect_statement_skipped(self, mock_client):
        """Line 546: Deny effect → continue (not counted as issue)."""
        c = MagicMock()
        c.list_agents.return_value = {
            "agentSummaries": [{"agentId": "a1", "agentName": "Agent1"}]
        }
        c.get_agent.return_value = {
            "agent": {"agentResourceRoleArn": "arn:aws:iam::123:role/DenyRole"}
        }
        mock_client.return_value = c
        cache = {
            "role_permissions": {
                "DenyRole": {
                    "attached_policies": [
                        {
                            "document": {
                                "Statement": [
                                    {
                                        "Effect": "Deny",
                                        "Action": "iam:*",
                                        "Resource": "*",
                                    }
                                ]
                            }
                        }
                    ],
                    "inline_policies": [],
                }
            }
        }
        result = app.check_bedrock_agent_action_boundaries(cache)
        _assert_structure(result)
        assert result["status"] == "PASS"


# =========================================================================
# FS-08 — line 622: re-raise non-AccessDenied ClientError
# =========================================================================


class TestFS08AgentcoreReraise:
    @patch("finserv_app.boto3.client")
    def test_non_access_denied_error_propagates_to_outer_except(self, mock_client):
        """Line 622: ClientError that is NOT AccessDenied/Unrecognized → re-raised → ERROR."""
        c = MagicMock()
        c.list_agent_runtimes.side_effect = _client_error("ServiceUnavailableException")
        mock_client.return_value = c
        result = app.check_agentcore_policy_engine()
        _assert_structure(result)
        assert result["status"] == "ERROR"


# =========================================================================
# FS-09 — lines 704-705: get_function_concurrency ClientError path
# =========================================================================


class TestFS09ConcurrencyClientError:
    @patch("finserv_app.boto3.client")
    def test_get_concurrency_client_error_adds_to_warn_list(self, mock_client):
        """Lines 704-705: get_function_concurrency raises ClientError → appended to warn list."""
        c = MagicMock()
        c.get_function_concurrency.side_effect = _client_error("AccessDeniedException")
        mock_client.return_value = c
        inv = make_resource_inventory(
            lambda_functions=[{"FunctionName": "my-agent-fn"}]
        )
        result = app.check_agent_transaction_limits(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"


# =========================================================================
# FS-12 — lines 902-923, 947: SCP paths
# =========================================================================


class TestFS12ScpPaths:
    @patch("finserv_app.boto3.client")
    def test_access_denied_returns_na(self, mock_client):
        """Lines 902-915: AccessDeniedException → N/A finding."""
        c = MagicMock()
        c.list_policies.side_effect = _client_error("AccessDeniedException")
        mock_client.return_value = c
        result = app.check_scp_model_access_restrictions()
        _assert_structure(result)
        assert any(r["Status"] == "N/A" for r in result["csv_data"])

    @patch("finserv_app.boto3.client")
    def test_orgs_not_in_use_returns_na(self, mock_client):
        """Lines 902-915: AWSOrganizationsNotInUseException → N/A finding."""
        c = MagicMock()
        c.list_policies.side_effect = _client_error("AWSOrganizationsNotInUseException")
        mock_client.return_value = c
        result = app.check_scp_model_access_restrictions()
        _assert_structure(result)
        assert any(r["Status"] == "N/A" for r in result["csv_data"])

    @patch("finserv_app.boto3.client")
    def test_non_access_denied_reraises(self, mock_client):
        """Line 916: non-AccessDenied ClientError → re-raised → ERROR."""
        c = MagicMock()
        c.list_policies.side_effect = _client_error("ServiceUnavailableException")
        mock_client.return_value = c
        result = app.check_scp_model_access_restrictions()
        _assert_structure(result)
        assert result["status"] == "ERROR"

    @patch("finserv_app.boto3.client")
    def test_warn_no_bedrock_scps(self, mock_client):
        """Lines 920-923, 925-945: policies exist but none reference bedrock → WARN."""
        c = MagicMock()
        c.list_policies.return_value = {
            "Policies": [{"Id": "p-001", "Name": "GeneralSCP"}]
        }
        c.describe_policy.return_value = {
            "Policy": {
                "Content": json.dumps(
                    {"Statement": [{"Effect": "Deny", "Action": "ec2:*"}]}
                )
            }
        }
        mock_client.return_value = c
        result = app.check_scp_model_access_restrictions()
        _assert_structure(result)
        assert result["status"] == "WARN"

    @patch("finserv_app.boto3.client")
    def test_pass_bedrock_scp_found(self, mock_client):
        """Line 947: bedrock SCP found → Passed finding."""
        c = MagicMock()
        c.list_policies.return_value = {
            "Policies": [{"Id": "p-001", "Name": "BedrockModelSCP"}]
        }
        c.describe_policy.return_value = {
            "Policy": {
                "Content": json.dumps(
                    {
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Action": "bedrock:InvokeModel",
                                "Condition": {
                                    "StringNotEquals": {
                                        "bedrock:ModelId": ["anthropic.claude-v2"]
                                    }
                                },
                            }
                        ]
                    }
                )
            }
        }
        mock_client.return_value = c
        result = app.check_scp_model_access_restrictions()
        _assert_structure(result)
        assert any(r["Status"] == "Passed" for r in result["csv_data"])


# =========================================================================
# FS-13 — lines 979-999: model tagging warn/pass paths
# =========================================================================


class TestFS13ModelTaggingPaths:
    @patch("finserv_app.boto3.client")
    def test_warn_bedrock_model_missing_tags(self, mock_client):
        """Lines 979-983, 998-999: Bedrock custom model missing required tags → WARN."""

        def side_effect(service, **kwargs):
            if service == "bedrock":
                c = MagicMock()
                c.list_custom_models.return_value = {
                    "modelSummaries": [
                        {
                            "modelName": "my-model",
                            "modelArn": "arn:aws:bedrock:us-east-1:123:model/my-model",
                        }
                    ]
                }
                c.list_tags_for_resource.return_value = {"tags": []}
                return c
            if service == "sagemaker":
                c = MagicMock()
                c.list_models.return_value = {"Models": []}
                return c
            return MagicMock()

        mock_client.side_effect = side_effect
        result = app.check_model_inventory_tagging()
        _assert_structure(result)
        assert result["status"] == "WARN"

    @patch("finserv_app.boto3.client")
    def test_warn_sagemaker_model_missing_tags(self, mock_client):
        """Lines 989-993: SageMaker model missing required tags → WARN."""

        def side_effect(service, **kwargs):
            if service == "bedrock":
                c = MagicMock()
                c.list_custom_models.return_value = {"modelSummaries": []}
                return c
            if service == "sagemaker":
                c = MagicMock()
                c.list_models.return_value = {
                    "Models": [
                        {
                            "ModelName": "sm-model",
                            "ModelArn": "arn:aws:sagemaker:us-east-1:123:model/sm-model",
                        }
                    ]
                }
                c.list_tags.return_value = {"Tags": []}
                return c
            return MagicMock()

        mock_client.side_effect = side_effect
        result = app.check_model_inventory_tagging()
        _assert_structure(result)
        assert result["status"] == "WARN"


# =========================================================================
# FS-14 — line 1072: pass path (config rules found)
# =========================================================================


class TestFS14ModelGovernancePass:
    @patch("finserv_app.boto3.client")
    def test_pass_config_rules_found(self, mock_client):
        """Line 1072: bedrock-related Config rules found → Passed."""
        c = MagicMock()
        c.describe_config_rules.return_value = {
            "ConfigRules": [{"ConfigRuleName": "bedrock-model-approval-rule"}]
        }
        mock_client.return_value = c
        result = app.check_model_onboarding_governance()
        _assert_structure(result)
        assert any(r["Status"] == "Passed" for r in result["csv_data"])


# =========================================================================
# FS-15 — line 1119: pass path (eval jobs found)
# =========================================================================


class TestFS15BedrockEvalPass:
    @patch("finserv_app.boto3.client")
    def test_pass_eval_jobs_found(self, mock_client):
        """Line 1119: evaluation jobs exist → Passed finding."""
        c = MagicMock()
        c.list_evaluation_jobs.return_value = {
            "jobSummaries": [{"jobName": "adversarial-eval-2025"}]
        }
        mock_client.return_value = c
        result = app.check_bedrock_model_evaluation_adversarial()
        _assert_structure(result)
        assert any(r["Status"] == "Passed" for r in result["csv_data"])


# =========================================================================
# FS-16 — lines 1167-1168: warn path (repos without scanning)
# =========================================================================


class TestFS16EcrScanningWarn:
    @patch("finserv_app.boto3.client")
    def test_warn_repos_without_scanning(self, mock_client):
        """Lines 1167-1168: repos exist but scan-on-push disabled → WARN."""
        c = MagicMock()
        c.describe_repositories.return_value = {
            "repositories": [
                {
                    "repositoryName": "ml-model-repo",
                    "imageScanningConfiguration": {"scanOnPush": False},
                }
            ]
        }
        mock_client.return_value = c
        result = app.check_ecr_image_scanning()
        _assert_structure(result)
        assert result["status"] == "WARN"


# =========================================================================
# FS-20 — lines 1238-1266: feature store warn/pass paths
# =========================================================================


class TestFS20FeatureStoreWarnPass:
    @patch("finserv_app.boto3.client")
    def test_warn_groups_without_offline_store(self, mock_client):
        """Lines 1244-1246: feature groups without active offline store → WARN."""
        c = MagicMock()
        c.list_feature_groups.return_value = {
            "FeatureGroupSummaries": [
                {
                    "FeatureGroupName": "customer-features",
                    "OfflineStoreStatus": {"Status": "Disabled"},
                }
            ]
        }
        mock_client.return_value = c
        result = app.check_feature_store_rollback_capability()
        _assert_structure(result)
        assert result["status"] == "WARN"

    @patch("finserv_app.boto3.client")
    def test_pass_all_groups_have_offline_store(self, mock_client):
        """Line 1266: all feature groups have active offline store → Passed."""
        c = MagicMock()
        c.list_feature_groups.return_value = {
            "FeatureGroupSummaries": [
                {
                    "FeatureGroupName": "customer-features",
                    "OfflineStoreStatus": {"Status": "Active"},
                }
            ]
        }
        mock_client.return_value = c
        result = app.check_feature_store_rollback_capability()
        _assert_structure(result)
        assert any(r["Status"] == "Passed" for r in result["csv_data"])


# =========================================================================
# FS-21 — lines 1312-1351: S3 versioning warn/pass paths
# =========================================================================


class TestFS21TrainingDataVersioningPaths:
    @patch("finserv_app.boto3.client")
    def test_warn_unversioned_training_buckets(self, mock_client):
        """Lines 1312-1316, 1318-1320: training buckets without versioning → WARN."""
        inv = make_resource_inventory(buckets=[{"Name": "training-data-bucket"}])
        c = MagicMock()
        c.get_bucket_tagging.return_value = {
            "TagSet": [{"Key": "Purpose", "Value": "training"}]
        }
        c.get_bucket_versioning.return_value = {}  # no versioning
        mock_client.return_value = c

        result = app.check_training_data_s3_versioning(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"

    @patch("finserv_app.boto3.client")
    def test_pass_all_training_buckets_versioned(self, mock_client):
        """Line 1338: all training buckets versioned → Passed."""
        inv = make_resource_inventory(buckets=[{"Name": "training-data-bucket"}])
        c = MagicMock()
        c.get_bucket_tagging.return_value = {
            "TagSet": [{"Key": "Purpose", "Value": "training"}]
        }
        c.get_bucket_versioning.return_value = {"Status": "Enabled"}
        mock_client.return_value = c

        result = app.check_training_data_s3_versioning(inv)
        _assert_structure(result)
        assert any(r["Status"] == "Passed" for r in result["csv_data"])

    @patch("finserv_app.boto3.client")
    def test_access_error_surfaces_as_could_not_assess(self, mock_client):
        """AccessDenied on get_bucket_versioning re-raises → ERROR (could-not-assess),
        not a false 'no versioning' finding."""
        inv = make_resource_inventory(buckets=[{"Name": "training-data-bucket"}])
        c = MagicMock()
        c.get_bucket_versioning.side_effect = _client_error("AccessDenied")
        mock_client.return_value = c

        result = app.check_training_data_s3_versioning(inv)
        _assert_structure(result)
        assert result["status"] == "ERROR"

    @patch("finserv_app.boto3.client")
    def test_nonaccess_error_flags_bucket(self, mock_client):
        """A non-access ClientError on get_bucket_versioning flags the bucket
        (WARN) without aborting the whole check."""
        inv = make_resource_inventory(buckets=[{"Name": "model-bucket"}])
        c = MagicMock()
        c.get_bucket_versioning.side_effect = _client_error("NoSuchBucket")
        mock_client.return_value = c

        result = app.check_training_data_s3_versioning(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"
        assert any(
            "(error)" in r.get("Finding_Details", "") for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_multi_page_buckets_completeness(self, mock_client):
        """Pagination completeness: buckets from multiple pages are all checked.

        With the inventory approach, the collector already drains all pages via
        _paginate with ContinuationToken. This test verifies that when 2+ pages
        of buckets are provided in the inventory, the check assesses them all.
        """
        # Simulate 2 "pages" of buckets — all training-named so they're all checked
        page1 = [
            {"Name": "training-bucket-page1-001"},
            {"Name": "model-bucket-page1-002"},
        ]
        page2 = [
            {"Name": "training-bucket-page2-001"},
            {"Name": "sagemaker-bucket-page2-002"},
        ]
        all_buckets = page1 + page2

        inv = make_resource_inventory(buckets=all_buckets)
        c = MagicMock()
        c.get_bucket_versioning.return_value = {"Status": "Enabled"}
        mock_client.return_value = c

        result = app.check_training_data_s3_versioning(inv)
        _assert_structure(result)
        # All 4 buckets versioned → Passed
        assert any(r["Status"] == "Passed" for r in result["csv_data"])
        # Verify all 4 were checked (versioning call per training bucket)
        assert c.get_bucket_versioning.call_count == 4

    @patch("finserv_app.boto3.client")
    def test_single_page_unchanged_vs_baseline(self, mock_client):
        """Single-page case: result is identical to pre-migration behavior (baseline).

        With ≤1 page of buckets (no ContinuationToken), the inventory holds
        all buckets and the check outcome is the same as before migration.
        """
        inv = make_resource_inventory(buckets=[{"Name": "training-data-bucket"}])
        c = MagicMock()
        c.get_bucket_versioning.return_value = {}  # no versioning
        mock_client.return_value = c

        result = app.check_training_data_s3_versioning(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"
        assert any(
            r["Finding"] == "Training Data Buckets Without Versioning"
            for r in result["csv_data"]
        )


# =========================================================================


class TestFS22KbIamWarnPath:
    def test_warn_wildcard_bedrock_agent_permission(self):
        """Lines 1370-1386: role with bedrock-agent:* → WARN."""
        cache = {
            "role_permissions": {
                "KBAccessRole": {
                    "attached_policies": [
                        {
                            "document": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "bedrock-agent:*",
                                        "Resource": "*",
                                    }
                                ]
                            }
                        }
                    ],
                    "inline_policies": [],
                }
            }
        }
        result = app.check_knowledge_base_iam_least_privilege(cache)
        _assert_structure(result)
        assert result["status"] == "WARN"

    def test_warn_wildcard_bedrock_permission(self):
        """Lines 1370-1386: role with bedrock:* → WARN."""
        cache = {
            "role_permissions": {
                "KBRole": {
                    "attached_policies": [],
                    "inline_policies": [
                        {
                            "document": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "bedrock:*",
                                        "Resource": "*",
                                    }
                                ]
                            }
                        }
                    ],
                }
            }
        }
        result = app.check_knowledge_base_iam_least_privilege(cache)
        _assert_structure(result)
        assert result["status"] == "WARN"

    def test_policy_doc_as_string_parsed(self):
        """Line 1372-1373: policy document as JSON string → parsed correctly."""
        cache = {
            "role_permissions": {
                "KBRole": {
                    "attached_policies": [
                        {
                            "document": json.dumps(
                                {
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": "*",
                                            "Resource": "*",
                                        }
                                    ]
                                }
                            )
                        }
                    ],
                    "inline_policies": [],
                }
            }
        }
        result = app.check_knowledge_base_iam_least_privilege(cache)
        _assert_structure(result)
        assert result["status"] == "WARN"

    def test_deny_effect_not_flagged(self):
        """Line 1375-1376: Deny effect → not counted as issue."""
        cache = {
            "role_permissions": {
                "KBRole": {
                    "attached_policies": [
                        {
                            "document": {
                                "Statement": [
                                    {
                                        "Effect": "Deny",
                                        "Action": "bedrock-agent:*",
                                        "Resource": "*",
                                    }
                                ]
                            }
                        }
                    ],
                    "inline_policies": [],
                }
            }
        }
        result = app.check_knowledge_base_iam_least_privilege(cache)
        _assert_structure(result)
        assert result["status"] == "PASS"

    def test_action_as_string_not_list(self):
        """Lines 1378-1379: Action as string (not list) → converted to list."""
        cache = {
            "role_permissions": {
                "KBRole": {
                    "attached_policies": [
                        {
                            "document": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "bedrock:*",
                                        "Resource": "*",
                                    }
                                ]
                            }
                        }
                    ],
                    "inline_policies": [],
                }
            }
        }
        result = app.check_knowledge_base_iam_least_privilege(cache)
        _assert_structure(result)
        assert result["status"] == "WARN"


# =========================================================================
# FS-24 — line 1450: KB metadata filtering pass path (KBs exist)
# =========================================================================


class TestFS24MetadataFilteringPass:
    def test_pass_kbs_exist(self):
        """KBs found → advisory N/A finding (metadata filtering not API-verifiable)."""
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[{"knowledgeBaseId": "kb1", "name": "rag-kb"}],
                data_sources_by_kb={},
                data_source_detail={},
            )
        )
        result = app.check_knowledge_base_metadata_filtering(inv)
        _assert_structure(result)
        assert any(
            r["Status"] == "N/A"
            and r["Severity"] == "Informational"
            and r["Finding"].startswith("ADVISORY: ")
            for r in result["csv_data"]
        )


# =========================================================================
# FS-25 — lines 1509-1511: OSS encryption with CMK path
# =========================================================================


class TestFS25OssEncryptionPaths:
    @patch("finserv_app.boto3.client")
    def test_pass_policies_with_cmk(self, mock_client):
        """Lines 1509-1511: encryption policies exist with CMK → Passed."""
        c = MagicMock()
        c.list_security_policies.return_value = {
            "securityPolicySummaries": [
                {
                    "name": "kb-encryption",
                    "policy": json.dumps(
                        {"Rules": [{"KmsARN": "arn:aws:kms:us-east-1:123:key/abc"}]}
                    ),
                }
            ]
        }
        mock_client.return_value = c
        result = app.check_opensearch_serverless_encryption()
        _assert_structure(result)
        assert any(r["Status"] == "Passed" for r in result["csv_data"])

    @patch("finserv_app.boto3.client")
    def test_pass_no_policies(self, mock_client):
        """Line 1488: no encryption policies → N/A finding."""
        c = MagicMock()
        c.list_security_policies.return_value = {"securityPolicySummaries": []}
        mock_client.return_value = c
        result = app.check_opensearch_serverless_encryption()
        _assert_structure(result)
        assert any(r["Status"] == "N/A" for r in result["csv_data"])

    @patch("finserv_app.boto3.client")
    def test_fail_policies_without_cmk(self, mock_client):
        """Encryption policies exist but all use AWS-owned keys → WARN/Failed
        (the customer-managed-key control is absent), not a false Pass."""
        c = MagicMock()
        c.list_security_policies.return_value = {
            "securityPolicySummaries": [
                {
                    "name": "aws-owned-enc",
                    "policy": json.dumps(
                        {"Rules": [{"ResourceType": "collection"}], "AWSOwnedKey": True}
                    ),
                }
            ]
        }
        mock_client.return_value = c
        result = app.check_opensearch_serverless_encryption()
        _assert_structure(result)
        assert result["status"] == "WARN"
        assert any(r["Status"] == "Failed" for r in result["csv_data"])


# =========================================================================
# FS-26 — lines 1546-1591: VPC access warn/pass paths
# =========================================================================


class TestFS26VpcAccessPaths:
    @patch("finserv_app.boto3.client")
    def test_warn_no_network_policies(self, mock_client):
        """Lines 1546-1547: no network policies → WARN."""
        c = MagicMock()
        c.list_security_policies.return_value = {"securityPolicySummaries": []}
        mock_client.return_value = c
        result = app.check_knowledge_base_vpc_access()
        _assert_structure(result)
        assert result["status"] == "WARN"

    @patch("finserv_app.boto3.client")
    def test_warn_policies_without_vpc(self, mock_client):
        """Lines 1567-1569: network policies exist but no VPC restriction → WARN."""
        c = MagicMock()
        c.list_security_policies.return_value = {
            "securityPolicySummaries": [
                {
                    "name": "public-access",
                    "policy": json.dumps({"Rules": [{"AllowFromPublic": True}]}),
                }
            ]
        }
        mock_client.return_value = c
        result = app.check_knowledge_base_vpc_access()
        _assert_structure(result)
        assert result["status"] == "WARN"

    @patch("finserv_app.boto3.client")
    def test_pass_vpc_restricted_policies(self, mock_client):
        """Line 1591: network policies with VPC restriction → Passed."""
        c = MagicMock()
        c.list_security_policies.return_value = {
            "securityPolicySummaries": [
                {
                    "name": "vpc-only",
                    "policy": json.dumps({"Rules": [{"SourceVPCEs": ["vpce-abc123"]}]}),
                }
            ]
        }
        mock_client.return_value = c
        result = app.check_knowledge_base_vpc_access()
        _assert_structure(result)
        assert any(r["Status"] == "Passed" for r in result["csv_data"])


# =========================================================================
# FS-27 — lines 1644, 1667: ARC guardrail paths
# =========================================================================


class TestFS27AutomatedReasoningPaths:
    def test_warn_guardrails_without_grounding(self):
        """Guardrails exist but none have contextual grounding → WARN."""
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "guard1"}],
                detail_by_id={"g1": {}},  # no contextualGroundingPolicy
            )
        )
        result = app.check_guardrail_contextual_grounding(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"

    def test_pass_guardrail_with_grounding(self):
        """Guardrail with contextual grounding → Passed."""
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "guard1"}],
                detail_by_id={
                    "g1": {
                        "contextualGroundingPolicy": {
                            "filters": [{"type": "GROUNDING", "threshold": 0.7}]
                        }
                    }
                },
            )
        )
        result = app.check_guardrail_contextual_grounding(inv)
        _assert_structure(result)
        assert any(r["Status"] == "Passed" for r in result["csv_data"])


# =========================================================================
# FS-28 — lines 1717-1718: denied topics warn path
# =========================================================================


class TestFS28DeniedTopicsWarn:
    def test_warn_guardrails_without_financial_topics(self):
        """Lines 1717-1718: guardrails exist but no topic policies → WARN."""
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "guard1"}],
                detail_by_id={"g1": {"topicPolicy": {"topics": []}}},
            )
        )
        result = app.check_guardrail_denied_topics_financial(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"


# =========================================================================
# FS-30 — line 1814: eval jobs found pass path
# =========================================================================


class TestFS30ComplianceEvalPass:
    def test_advisory_finding(self):
        """FS-30 is advisory (REQ-10a): always one N/A Informational ADVISORY row."""
        result = app.check_bedrock_evaluation_compliance_datasets()
        _assert_structure(result)
        assert any(
            r["Status"] == "N/A"
            and r["Severity"] == "Informational"
            and r["Finding"].startswith("ADVISORY: ")
            for r in result["csv_data"]
        )


# =========================================================================
# FS-31 — lines 1864-1914: KB data source sync stale/fresh paths
# =========================================================================


class TestFS31KbSyncPaths:
    def test_warn_stale_data_sources(self):
        """Lines 1864-1882: KB data sources not synced in >7 days → WARN."""
        stale_time = datetime.now(timezone.utc) - timedelta(days=10)
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[{"knowledgeBaseId": "kb1", "name": "my-kb"}],
                data_sources_by_kb={
                    "kb1": [
                        {
                            "dataSourceId": "ds1",
                            "name": "s3-source",
                            "updatedAt": stale_time,
                        }
                    ]
                },
                data_source_detail={},
            )
        )
        result = app.check_knowledge_base_data_source_sync(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"

    def test_pass_recently_synced(self):
        """Line 1901: all data sources synced within 7 days → Passed."""
        fresh_time = datetime.now(timezone.utc) - timedelta(days=1)
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[{"knowledgeBaseId": "kb1", "name": "my-kb"}],
                data_sources_by_kb={
                    "kb1": [
                        {
                            "dataSourceId": "ds1",
                            "name": "s3-source",
                            "updatedAt": fresh_time,
                        }
                    ]
                },
                data_source_detail={},
            )
        )
        result = app.check_knowledge_base_data_source_sync(inv)
        _assert_structure(result)
        assert any(r["Status"] == "Passed" for r in result["csv_data"])


# =========================================================================
# FS-33 — lines 1976-2034: KB integrity monitoring paths
# =========================================================================


class TestFS33KbIntegrityPaths:
    @patch("finserv_app.boto3.client")
    def test_warn_bucket_without_versioning(self, mock_client):
        """Lines 1976-2003: KB data source bucket without versioning → WARN."""
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[{"knowledgeBaseId": "kb1"}],
                data_sources_by_kb={"kb1": [{"dataSourceId": "ds1"}]},
                data_source_detail={
                    ("kb1", "ds1"): {
                        "dataSource": {
                            "dataSourceConfiguration": {
                                "s3Configuration": {
                                    "bucketArn": "arn:aws:s3:::kb-data-bucket"
                                }
                            }
                        }
                    }
                },
            )
        )

        def side_effect(service, **kwargs):
            if service == "s3":
                c = MagicMock()
                c.get_bucket_versioning.return_value = {}  # not enabled
                return c
            return MagicMock()

        mock_client.side_effect = side_effect
        result = app.check_knowledge_base_integrity_monitoring(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"

    @patch("finserv_app.boto3.client")
    def test_pass_bucket_with_versioning(self, mock_client):
        """Line 2021: all KB buckets have versioning → Passed."""
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[{"knowledgeBaseId": "kb1"}],
                data_sources_by_kb={"kb1": [{"dataSourceId": "ds1"}]},
                data_source_detail={
                    ("kb1", "ds1"): {
                        "dataSource": {
                            "dataSourceConfiguration": {
                                "s3Configuration": {
                                    "bucketArn": "arn:aws:s3:::kb-data-bucket"
                                }
                            }
                        }
                    }
                },
            )
        )

        def side_effect(service, **kwargs):
            if service == "s3":
                c = MagicMock()
                c.get_bucket_versioning.return_value = {"Status": "Enabled"}
                return c
            return MagicMock()

        mock_client.side_effect = side_effect
        result = app.check_knowledge_base_integrity_monitoring(inv)
        _assert_structure(result)
        assert any(r["Status"] == "Passed" for r in result["csv_data"])

    @patch("finserv_app.boto3.client")
    def test_deleted_bucket_reported_separately(self, mock_client):
        """A NoSuchBucket on get_bucket_versioning → distinct 'deleted bucket'
        finding (High), NOT conflated with 'without versioning' or labeled
        '(error)'. Regression guard for the FS-33 NoSuchBucket refinement."""
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[{"knowledgeBaseId": "kb1", "name": "kb-one"}],
                data_sources_by_kb={"kb1": [{"dataSourceId": "ds1", "name": "ds-one"}]},
                data_source_detail={
                    ("kb1", "ds1"): {
                        "dataSource": {
                            "dataSourceConfiguration": {
                                "s3Configuration": {
                                    "bucketArn": "arn:aws:s3:::deleted-bucket"
                                }
                            }
                        }
                    }
                },
            )
        )

        def side_effect(service, **kwargs):
            if service == "s3":
                c = MagicMock()
                c.get_bucket_versioning.side_effect = _client_error("NoSuchBucket")
                return c
            return MagicMock()

        mock_client.side_effect = side_effect
        result = app.check_knowledge_base_integrity_monitoring(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"
        # Distinct deleted-bucket finding present, High severity, not "(error)".
        deleted = [
            r
            for r in result["csv_data"]
            if r["Finding"] == "KB Data Source References a Deleted S3 Bucket"
        ]
        assert deleted, "expected a distinct deleted-bucket finding"
        assert deleted[0]["Severity"] == "High"
        assert "deleted-bucket" in deleted[0]["Finding_Details"]
        # No "(error)" mislabel and no "Without Versioning" finding for this bucket.
        assert not any(
            "(error)" in r.get("Finding_Details", "") for r in result["csv_data"]
        )
        assert not any(
            r["Finding"] == "KB Data Source Buckets Without Versioning"
            for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_bucket_nonaccess_nonmissing_error_treated_as_unversioned(
        self, mock_client
    ):
        """A non-access, non-missing ClientError on get_bucket_versioning →
        bucket flagged as '(error)' under the versioning finding (WARN), not
        silently dropped and not treated as a deleted bucket."""
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[{"knowledgeBaseId": "kb1"}],
                data_sources_by_kb={"kb1": [{"dataSourceId": "ds1"}]},
                data_source_detail={
                    ("kb1", "ds1"): {
                        "dataSource": {
                            "dataSourceConfiguration": {
                                "s3Configuration": {
                                    "bucketArn": "arn:aws:s3:::weird-bucket"
                                }
                            }
                        }
                    }
                },
            )
        )

        def side_effect(service, **kwargs):
            if service == "s3":
                c = MagicMock()
                c.get_bucket_versioning.side_effect = _client_error("InvalidRequest")
                return c
            return MagicMock()

        mock_client.side_effect = side_effect
        result = app.check_knowledge_base_integrity_monitoring(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"
        assert any(
            "(error)" in r.get("Finding_Details", "") for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_bucket_access_error_surfaces_as_could_not_assess(self, mock_client):
        """An AccessDenied on get_bucket_versioning must re-raise → ERROR envelope
        (could-not-assess), NOT a false 'no versioning' finding."""
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[{"knowledgeBaseId": "kb1"}],
                data_sources_by_kb={"kb1": [{"dataSourceId": "ds1"}]},
                data_source_detail={
                    ("kb1", "ds1"): {
                        "dataSource": {
                            "dataSourceConfiguration": {
                                "s3Configuration": {
                                    "bucketArn": "arn:aws:s3:::locked-bucket"
                                }
                            }
                        }
                    }
                },
            )
        )

        def side_effect(service, **kwargs):
            if service == "s3":
                c = MagicMock()
                c.get_bucket_versioning.side_effect = _client_error("AccessDenied")
                return c
            return MagicMock()

        mock_client.side_effect = side_effect
        result = app.check_knowledge_base_integrity_monitoring(inv)
        _assert_structure(result)
        assert result["status"] == "ERROR"


# =========================================================================
# FS-34 — lines 2056-2057: FM version currency pass path
# =========================================================================


class TestFS34FmVersionPass:
    @patch("finserv_app.boto3.client")
    def test_pass_no_legacy_models_in_use(self, mock_client):
        """Lines 2056-2057: no legacy models in use → Passed."""
        c = MagicMock()
        c.list_foundation_models.return_value = {
            "modelSummaries": [
                {
                    "modelId": "anthropic.claude-v2",
                    "modelLifecycle": {"status": "ACTIVE"},
                }
            ]
        }
        c.list_custom_models.return_value = {"modelSummaries": []}
        mock_client.return_value = c
        result = app.check_fm_version_currency()
        _assert_structure(result)
        assert any(r["Status"] == "Passed" for r in result["csv_data"])


# =========================================================================
# FS-35 — line 2127: eval jobs found pass path
# =========================================================================


class TestFS35FmevalPass:
    def test_advisory_finding(self):
        """FS-35 is advisory (REQ-10a): always one N/A Informational ADVISORY row."""
        result = app.check_fmeval_harmful_content()
        _assert_structure(result)
        assert any(
            r["Status"] == "N/A"
            and r["Severity"] == "Informational"
            and r["Finding"].startswith("ADVISORY: ")
            for r in result["csv_data"]
        )


# =========================================================================
# FS-36 — lines 2177-2178: content filters warn path
# =========================================================================


class TestFS36ContentFiltersWarn:
    def test_warn_guardrails_without_content_filters(self):
        """Lines 2177-2178: guardrails exist but no content filters → WARN."""
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "guard1"}],
                detail_by_id={"g1": {"contentPolicy": {"filters": []}}},
            )
        )
        result = app.check_guardrail_content_filters(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"


# =========================================================================
# FS-38 — lines 2266-2309: word filters warn/pass paths
# =========================================================================


class TestFS38WordFiltersPaths:
    def test_warn_guardrails_without_word_filters(self):
        """Lines 2266-2276: guardrails exist but no word filters → WARN."""
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "guard1"}],
                detail_by_id={
                    "g1": {"wordPolicy": {"words": [], "managedWordLists": []}}
                },
            )
        )
        result = app.check_guardrail_word_filters(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"

    def test_pass_word_filters_configured(self):
        """Line 2296: guardrail with word filters → Passed."""
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "guard1"}],
                detail_by_id={
                    "g1": {
                        "wordPolicy": {
                            "words": [{"text": "insider trading"}],
                            "managedWordLists": [{"type": "PROFANITY"}],
                        }
                    }
                },
            )
        )
        result = app.check_guardrail_word_filters(inv)
        _assert_structure(result)
        assert any(r["Status"] == "Passed" for r in result["csv_data"])


# =========================================================================
# FS-39 — line 2352: Clarify bias pass path
# =========================================================================


class TestFS39ClarifyBiasPass:
    @patch("finserv_app.boto3.client")
    def test_pass_bias_schedules_found(self, mock_client):
        """Line 2352: bias monitoring schedules found → Passed."""
        c = MagicMock()
        c.list_monitoring_schedules.return_value = {
            "MonitoringScheduleSummaries": [
                {
                    "MonitoringScheduleName": "bias-monitor",
                    "MonitoringType": "ModelBias",
                }
            ]
        }
        mock_client.return_value = c
        result = app.check_sagemaker_clarify_bias()
        _assert_structure(result)
        assert any(r["Status"] == "Passed" for r in result["csv_data"])


# =========================================================================
# FS-40 — line 2397: bias eval pass path
# =========================================================================


class TestFS40BiasEvalPass:
    def test_advisory_finding(self):
        """FS-40 is advisory (REQ-10a): always one N/A Informational ADVISORY row."""
        result = app.check_bedrock_evaluation_bias_datasets()
        _assert_structure(result)
        assert any(
            r["Status"] == "N/A"
            and r["Severity"] == "Informational"
            and r["Finding"].startswith("ADVISORY: ")
            for r in result["csv_data"]
        )


# =========================================================================
# FS-41 — line 2452: Clarify explainability pass path
# =========================================================================


class TestFS41ClarifyExplainabilityPass:
    @patch("finserv_app.boto3.client")
    def test_pass_explainability_schedules_found(self, mock_client):
        """Line 2452: explainability monitoring schedules found → Passed."""
        c = MagicMock()
        c.list_monitoring_schedules.return_value = {
            "MonitoringScheduleSummaries": [
                {
                    "MonitoringScheduleName": "explain-monitor",
                    "MonitoringType": "ModelExplainability",
                }
            ]
        }
        mock_client.return_value = c
        result = app.check_sagemaker_clarify_explainability()
        _assert_structure(result)
        assert any(r["Status"] == "Passed" for r in result["csv_data"])


# =========================================================================
# FS-42 — line 2501: model cards pass path
# =========================================================================


class TestFS42ModelCardsPass:
    @patch("finserv_app.boto3.client")
    def test_pass_model_cards_found(self, mock_client):
        """Line 2501: model cards exist → Passed (key is ModelCardSummaryList)."""
        c = MagicMock()
        c.list_model_cards.return_value = {
            "ModelCardSummaryList": [{"ModelCardName": "fraud-model-card"}]
        }
        mock_client.return_value = c
        result = app.check_ai_service_cards_documentation()
        _assert_structure(result)
        assert any(r["Status"] == "Passed" for r in result["csv_data"])


# =========================================================================
# FS-43 — lines 2536-2541: CloudWatch PII masking paths
# =========================================================================


class TestFS43CloudwatchPiiPaths:
    @patch("finserv_app.boto3.client")
    def test_warn_no_data_protection_policies(self, mock_client):
        """Lines 2540-2541: no data protection policies → WARN."""
        c = MagicMock()
        c.describe_account_policies.return_value = {"accountPolicies": []}
        mock_client.return_value = c
        result = app.check_cloudwatch_log_pii_masking()
        _assert_structure(result)
        assert result["status"] == "WARN"

    @patch("finserv_app.boto3.client")
    def test_client_error_on_describe_policies_treated_as_no_policies(
        self, mock_client
    ):
        """Line 2536: ClientError on describe_account_policies → policies = [] → WARN."""
        c = MagicMock()
        c.describe_account_policies.side_effect = _client_error("AccessDeniedException")
        mock_client.return_value = c
        result = app.check_cloudwatch_log_pii_masking()
        _assert_structure(result)
        assert result["status"] == "WARN"


# =========================================================================
# FS-44 — lines 2589-2628: Macie paths
# =========================================================================


class TestFS44MaciePaths:
    @patch("finserv_app.boto3.client")
    def test_warn_macie_not_enabled(self, mock_client):
        """Lines 2593-2595: Macie session status not ENABLED → WARN."""
        c = MagicMock()
        c.get_macie_session.return_value = {"status": "PAUSED"}
        mock_client.return_value = c
        result = app.check_macie_on_training_data_buckets()
        _assert_structure(result)
        assert result["status"] == "WARN"

    @patch("finserv_app.boto3.client")
    def test_warn_macie_client_error(self, mock_client):
        """Lines 2590-2591: ClientError on get_macie_session → macie_enabled=False → WARN."""
        c = MagicMock()
        c.get_macie_session.side_effect = _client_error("AccessDeniedException")
        mock_client.return_value = c
        result = app.check_macie_on_training_data_buckets()
        _assert_structure(result)
        assert result["status"] == "WARN"

    @patch("finserv_app.boto3.client")
    def test_pass_macie_enabled(self, mock_client):
        """Line 2615: Macie enabled → Passed."""
        c = MagicMock()
        c.get_macie_session.return_value = {"status": "ENABLED"}
        mock_client.return_value = c
        result = app.check_macie_on_training_data_buckets()
        _assert_structure(result)
        assert any(r["Status"] == "Passed" for r in result["csv_data"])


# =========================================================================
# FS-45 — lines 2665-2666: PII filters warn path
# =========================================================================


class TestFS45PiiFiltersWarn:
    def test_warn_guardrails_without_pii_filters(self):
        """Lines 2665-2666: guardrails exist but no PII filters → WARN."""
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "guard1"}],
                detail_by_id={
                    "g1": {"sensitiveInformationPolicy": {"piiEntities": []}}
                },
            )
        )
        result = app.check_guardrail_pii_filters(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"


# =========================================================================
# FS-46 — lines 2734-2778: data classification tagging paths
# =========================================================================


class TestFS46DataClassificationPaths:
    @patch("finserv_app.boto3.client")
    def test_warn_buckets_without_classification_tags(self, mock_client):
        """Lines 2734-2746: AI/ML buckets without classification tags → WARN."""
        inv = make_resource_inventory(buckets=[{"Name": "aiml-training-data"}])
        c = MagicMock()
        c.get_bucket_tagging.return_value = {
            "TagSet": [{"Key": "Environment", "Value": "prod"}]
        }
        mock_client.return_value = c

        result = app.check_data_classification_tagging(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"

    @patch("finserv_app.boto3.client")
    def test_warn_tagging_client_error_treated_as_unclassified(self, mock_client):
        """Line 2741-2742: ClientError on get_bucket_tagging → bucket added as unclassified."""
        inv = make_resource_inventory(buckets=[{"Name": "aiml-training-data"}])
        c = MagicMock()
        c.get_bucket_tagging.side_effect = _client_error("NoSuchTagSet")
        mock_client.return_value = c

        result = app.check_data_classification_tagging(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"

    @patch("finserv_app.boto3.client")
    def test_tagging_access_error_surfaces_as_could_not_assess(self, mock_client):
        """AccessDenied on get_bucket_tagging re-raises → ERROR (could-not-assess),
        NOT a false 'unclassified' finding."""
        inv = make_resource_inventory(buckets=[{"Name": "aiml-training-data"}])
        c = MagicMock()
        c.get_bucket_tagging.side_effect = _client_error("AccessDenied")
        mock_client.return_value = c

        result = app.check_data_classification_tagging(inv)
        _assert_structure(result)
        assert result["status"] == "ERROR"

    @patch("finserv_app.boto3.client")
    def test_pass_all_buckets_classified(self, mock_client):
        """Line 2765: all AI/ML buckets have classification tags → Passed."""
        inv = make_resource_inventory(buckets=[{"Name": "aiml-training-data"}])
        c = MagicMock()
        c.get_bucket_tagging.return_value = {
            "TagSet": [{"Key": "data-classification", "Value": "Confidential"}]
        }
        mock_client.return_value = c

        result = app.check_data_classification_tagging(inv)
        _assert_structure(result)
        assert any(r["Status"] == "Passed" for r in result["csv_data"])

    @patch("finserv_app.boto3.client")
    def test_multi_page_buckets_completeness(self, mock_client):
        """Pagination completeness: buckets from multiple pages are all assessed.

        The inventory (already fully paginated by the collector) contains buckets
        from 2+ simulated pages. This test verifies the check inspects all of them.
        """
        # Simulate 2 "pages" of buckets — all AI/ML-named so they're all filtered in
        page1 = [{"Name": "train-data-page1-001"}, {"Name": "bedrock-page1-002"}]
        page2 = [{"Name": "knowledge-page2-001"}, {"Name": "sagemaker-page2-002"}]
        all_buckets = page1 + page2

        inv = make_resource_inventory(buckets=all_buckets)
        c = MagicMock()
        c.get_bucket_tagging.return_value = {
            "TagSet": [{"Key": "data-classification", "Value": "Internal"}]
        }
        mock_client.return_value = c

        result = app.check_data_classification_tagging(inv)
        _assert_structure(result)
        # All 4 buckets classified → Passed
        assert any(r["Status"] == "Passed" for r in result["csv_data"])
        # Verify all 4 were assessed (tagging call per AI/ML bucket)
        assert c.get_bucket_tagging.call_count == 4

    @patch("finserv_app.boto3.client")
    def test_single_page_unchanged_vs_baseline(self, mock_client):
        """Single-page case: result is identical to pre-migration behavior (baseline).

        With ≤1 page of buckets, the inventory holds all buckets and the check
        outcome is the same as before migration.
        """
        inv = make_resource_inventory(buckets=[{"Name": "aiml-training-data"}])
        c = MagicMock()
        c.get_bucket_tagging.return_value = {
            "TagSet": [{"Key": "Environment", "Value": "prod"}]
        }
        mock_client.return_value = c

        result = app.check_data_classification_tagging(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"
        assert any(
            r["Finding"] == "AI/ML Buckets Without Data Classification Tags"
            for r in result["csv_data"]
        )


# =========================================================================
# FS-47 — lines 2812-2857: grounding threshold warn/pass paths
# =========================================================================


class TestFS47GroundingThresholdPaths:
    def test_warn_low_grounding_threshold(self):
        """Lines 2812-2826: guardrail with grounding threshold < 0.7 → WARN."""
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "guard1"}],
                detail_by_id={
                    "g1": {
                        "contextualGroundingPolicy": {
                            "filters": [{"type": "GROUNDING", "threshold": 0.5}]
                        }
                    }
                },
            )
        )
        result = app.check_guardrail_grounding_threshold(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"

    def test_pass_adequate_grounding_threshold(self):
        """Line 2844: guardrail with grounding threshold >= 0.7 → Passed."""
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "guard1"}],
                detail_by_id={
                    "g1": {
                        "contextualGroundingPolicy": {
                            "filters": [{"type": "GROUNDING", "threshold": 0.8}]
                        }
                    }
                },
            )
        )
        result = app.check_guardrail_grounding_threshold(inv)
        _assert_structure(result)
        assert any(r["Status"] == "Passed" for r in result["csv_data"])

    def test_fail_no_grounding_filter_at_all(self):
        """Guardrails exist but NONE has a GROUNDING filter (only RELEVANCE) →
        Failed, not a false Pass. Regression guard for the FS-47 false-pass fix."""
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "guard1"}],
                detail_by_id={
                    "g1": {
                        "contextualGroundingPolicy": {
                            "filters": [{"type": "RELEVANCE", "threshold": 0.9}]
                        }
                    }
                },
            )
        )
        result = app.check_guardrail_grounding_threshold(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"
        assert any(r["Status"] == "Failed" for r in result["csv_data"])
        assert not any(r["Status"] == "Passed" for r in result["csv_data"])


# =========================================================================
# FS-48 — line 2898: RAG KB pass path (active KBs)
# =========================================================================


class TestFS48RagKbPass:
    def test_pass_active_kbs_found(self):
        """Line 2898: active KBs found → Passed."""
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[
                    {"knowledgeBaseId": "kb1", "name": "rag-kb", "status": "ACTIVE"}
                ],
                data_sources_by_kb={},
                data_source_detail={},
            )
        )
        result = app.check_rag_knowledge_base_configured(inv)
        _assert_structure(result)
        assert any(r["Status"] == "Passed" for r in result["csv_data"])


# =========================================================================
# FS-50 — lines 2957-2985: ARC relevance grounding paths
# =========================================================================


class TestFS50ArcRelevancePaths:
    def test_warn_no_relevance_filters(self):
        """Lines 2957-2963: guardrails exist but no RELEVANCE filter → WARN."""
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "guard1"}],
                detail_by_id={
                    "g1": {
                        "contextualGroundingPolicy": {
                            "filters": [{"type": "GROUNDING", "threshold": 0.8}]
                        }
                    }
                },
            )
        )
        result = app.check_guardrail_relevance_grounding(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"

    def test_pass_relevance_filter_found(self):
        """Guardrail with RELEVANCE filter → Passed."""
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "guard1"}],
                detail_by_id={
                    "g1": {
                        "contextualGroundingPolicy": {
                            "filters": [{"type": "RELEVANCE", "threshold": 0.7}]
                        }
                    }
                },
            )
        )
        result = app.check_guardrail_relevance_grounding(inv)
        _assert_structure(result)
        assert any(r["Status"] == "Passed" for r in result["csv_data"])


# =========================================================================
# FS-51 — lines 3037-3038: prompt injection warn path
# =========================================================================


class TestFS51PromptInjectionWarn:
    def test_warn_no_prompt_attack_filter(self):
        """Lines 3037-3038: guardrails exist but no PROMPT_ATTACK filter → WARN."""
        inv = make_resource_inventory(
            guardrails=app.GuardrailInventory(
                summaries=[{"id": "g1", "name": "guard1"}],
                detail_by_id={
                    "g1": {
                        "contentPolicy": {
                            "filters": [{"type": "HATE", "inputStrength": "HIGH"}]
                        }
                    }
                },
            )
        )
        result = app.check_prompt_injection_input_validation(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"


# =========================================================================
# FS-52 — lines 3105-3146: SDK version currency paths
# =========================================================================


class TestFS52SdkVersionPaths:
    def test_warn_deprecated_runtime(self):
        """Lines 3105-3113: Bedrock Lambda on deprecated runtime → WARN."""
        inv = make_resource_inventory(
            lambda_functions=[
                {"FunctionName": "bedrock-invoke-fn", "Runtime": "python3.8"}
            ]
        )
        result = app.check_bedrock_sdk_version_currency(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"

    def test_pass_current_runtime(self):
        """Line 3133: Bedrock Lambda on current runtime → Passed."""
        inv = make_resource_inventory(
            lambda_functions=[
                {"FunctionName": "bedrock-invoke-fn", "Runtime": "python3.12"}
            ]
        )
        result = app.check_bedrock_sdk_version_currency(inv)
        _assert_structure(result)
        assert any(r["Status"] == "Passed" for r in result["csv_data"])


# =========================================================================
# FS-53 — lines 3192-3196: WAF injection rules warn path
# =========================================================================


class TestFS53WafInjectionWarn:
    def test_warn_acls_without_injection_rules(self):
        """Lines 3192-3196: WAF ACLs exist but no injection rule groups → WARN."""
        acl_detail = {
            "Rules": [
                {
                    "Name": "rate-limit",
                    "Statement": {"RateBasedStatement": {"Limit": 1000}},
                }
            ]
        }
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(
                summaries=[{"Name": "acl1", "Id": "id1"}],
                detail_by_id={"id1": acl_detail},
            )
        )
        result = app.check_waf_sql_injection_rules(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"


# =========================================================================
# FS-65 — lines 3770, 3781-3782: S3 event notification edge cases
# =========================================================================


class TestFS65S3EventNotificationEdgeCases:
    def test_skip_datasource_with_no_bucket(self):
        """Line 3770: data source with no bucket ARN → continue (no bucket added)."""
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[{"knowledgeBaseId": "kb1"}],
                data_sources_by_kb={"kb1": [{"dataSourceId": "ds1"}]},
                data_source_detail={
                    ("kb1", "ds1"): {
                        "dataSource": {
                            "dataSourceConfiguration": {
                                "s3Configuration": {}  # no bucketArn
                            }
                        }
                    }
                },
            )
        )
        result = app.check_kb_datasource_s3_event_notifications(inv)
        _assert_structure(result)
        # No buckets to check → PASS
        assert result["status"] == "PASS"

    @patch("finserv_app.boto3.client")
    def test_s3_notification_access_error_surfaces_as_could_not_assess(
        self, mock_client
    ):
        """An AccessDenied on get_bucket_notification_configuration must re-raise →
        ERROR envelope (could-not-assess), NOT a false 'missing notifications' finding."""
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[{"knowledgeBaseId": "kb1"}],
                data_sources_by_kb={"kb1": [{"dataSourceId": "ds1"}]},
                data_source_detail={
                    ("kb1", "ds1"): {
                        "dataSource": {
                            "dataSourceConfiguration": {
                                "s3Configuration": {
                                    "bucketArn": "arn:aws:s3:::kb-bucket"
                                }
                            }
                        }
                    }
                },
            )
        )

        def side_effect(service, **kwargs):
            if service == "s3":
                c = MagicMock()
                c.get_bucket_notification_configuration.side_effect = _client_error(
                    "AccessDenied"
                )
                return c
            return MagicMock()

        mock_client.side_effect = side_effect
        result = app.check_kb_datasource_s3_event_notifications(inv)
        _assert_structure(result)
        assert result["status"] == "ERROR"

    @patch("finserv_app.boto3.client")
    def test_deleted_bucket_reported_separately(self, mock_client):
        """A NoSuchBucket on get_bucket_notification_configuration → distinct
        'deleted bucket' finding (High), not conflated with 'missing
        notifications' or labeled '(error)'. Regression guard for the FS-65
        NoSuchBucket refinement."""
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[{"knowledgeBaseId": "kb1", "name": "kb-one"}],
                data_sources_by_kb={"kb1": [{"dataSourceId": "ds1", "name": "ds-one"}]},
                data_source_detail={
                    ("kb1", "ds1"): {
                        "dataSource": {
                            "dataSourceConfiguration": {
                                "s3Configuration": {
                                    "bucketArn": "arn:aws:s3:::deleted-kb-bucket"
                                }
                            }
                        }
                    }
                },
            )
        )

        def side_effect(service, **kwargs):
            if service == "s3":
                c = MagicMock()
                c.get_bucket_notification_configuration.side_effect = _client_error(
                    "NoSuchBucket"
                )
                return c
            return MagicMock()

        mock_client.side_effect = side_effect
        result = app.check_kb_datasource_s3_event_notifications(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"
        deleted = [
            r
            for r in result["csv_data"]
            if r["Finding"] == "KB Data Source References a Deleted S3 Bucket"
        ]
        assert deleted, "expected a distinct deleted-bucket finding"
        assert deleted[0]["Severity"] == "High"
        assert "deleted-kb-bucket" in deleted[0]["Finding_Details"]
        assert not any(
            "(error)" in r.get("Finding_Details", "") for r in result["csv_data"]
        )
        assert not any(
            r["Finding"] == "KB Data Source Buckets Missing S3 Event Notifications"
            for r in result["csv_data"]
        )


class TestFS66AgentcoreIdentityReraise:
    @patch("finserv_app.boto3.client")
    def test_non_access_denied_reraises(self, mock_client):
        """Line 3849: non-AccessDenied ClientError → re-raised → ERROR."""
        c = MagicMock()
        c.list_agent_runtimes.side_effect = _client_error("ServiceUnavailableException")
        mock_client.return_value = c
        result = app.check_agentcore_end_user_identity_propagation()
        _assert_structure(result)
        assert result["status"] == "ERROR"


# =========================================================================
# FS-68 — lines 4031, 4049, 4053, 4056-4057: body size limit warn paths
# =========================================================================


class TestFS68BodySizeLimitWarnPaths:
    def test_warn_rest_api_without_validators(self):
        """Lines 4031, 4049, 4056-4057: REST API without validators → WARN."""
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(summaries=[], detail_by_id={})
        )
        with patch("finserv_app.boto3.client") as mock_client:

            def side_effect(service, **kwargs):
                if service == "apigateway":
                    c = MagicMock()
                    c.get_rest_apis.return_value = {
                        "items": [{"id": "api1", "name": "genai-api"}]
                    }
                    c.get_request_validators.return_value = {
                        "items": []
                    }  # no validators
                    return c
                return MagicMock()

            mock_client.side_effect = side_effect
            result = app.check_api_gateway_request_body_size_limits(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"

    def test_warn_waf_acls_without_size_rules(self):
        """Lines 4053, 4056-4057: WAF ACLs exist but no size constraint rules → WARN."""
        acl_detail = {
            "Rules": [
                {
                    "Name": "rate-limit",
                    "Statement": {"RateBasedStatement": {}},
                }
            ]
        }
        inv = make_resource_inventory(
            web_acls=app.WebAclInventory(
                summaries=[{"Name": "acl1", "Id": "id1"}],
                detail_by_id={"id1": acl_detail},
            )
        )
        with patch("finserv_app.boto3.client") as mock_client:

            def side_effect(service, **kwargs):
                if service == "apigateway":
                    c = MagicMock()
                    c.get_rest_apis.return_value = {"items": []}
                    return c
                return MagicMock()

            mock_client.side_effect = side_effect
            result = app.check_api_gateway_request_body_size_limits(inv)
        _assert_structure(result)
        assert result["status"] == "WARN"


# =========================================================================
# FS-34 — lines 2056-2057: legacy models warn path
# =========================================================================


class TestFS34FmVersionWarn:
    @patch("finserv_app.boto3.client")
    def test_warn_legacy_models_available(self, mock_client):
        """Legacy foundation models available in region → WARN wrapper with an N/A
        finding (availability is not usage, so it is surfaced for review, not failed)."""
        c = MagicMock()
        c.list_foundation_models.return_value = {
            "modelSummaries": [
                {"modelId": "old-model-v1", "modelLifecycle": {"status": "LEGACY"}}
            ]
        }
        c.list_custom_models.return_value = {"modelSummaries": []}
        mock_client.return_value = c
        result = app.check_fm_version_currency()
        _assert_structure(result)
        assert result["status"] == "WARN"
        assert any(r["Status"] == "N/A" for r in result["csv_data"])
        assert any(
            "availability" in r["Finding_Details"].lower() for r in result["csv_data"]
        )
