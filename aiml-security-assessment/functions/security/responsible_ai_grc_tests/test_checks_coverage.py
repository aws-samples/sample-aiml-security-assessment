"""
Additional tests targeting the uncovered branches in responsible_ai_grc_assessments/app.py.
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
        """get_agent raises ClientError → the agent is unread, so no Passed."""
        c = MagicMock()
        c.list_agents.return_value = {
            "agentSummaries": [{"agentId": "a1", "agentName": "EncryptedAgent"}]
        }
        c.get_agent.side_effect = _client_error("AccessDeniedException")
        mock_client.return_value = c
        result = app.check_bedrock_agent_action_boundaries(
            {"role_permissions": {}, "user_permissions": {}}
        )
        assert "check_name" in result
        assert result["status"] == "N/A"
        row = result["csv_data"][0]
        assert row["Status"] == "N/A"
        assert row["Finding"] == "Agent Action Boundary Check Incomplete"
        assert (
            "agent 'EncryptedAgent' (GetAgent failed: AccessDeniedException)"
            in row["Finding_Details"]
        )

    @patch("finserv_app.boto3.client")
    def test_agent_no_role_arn_skipped(self, mock_client):
        """Line 537: agent with no agentResourceRoleArn → continue."""
        c = MagicMock()
        c.list_agents.return_value = {
            "agentSummaries": [{"agentId": "a1", "agentName": "NoRoleAgent"}]
        }
        c.get_agent.return_value = {"agent": {"agentResourceRoleArn": ""}}
        mock_client.return_value = c
        result = app.check_bedrock_agent_action_boundaries(
            {"role_permissions": {}, "user_permissions": {}}
        )
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
        result = app.check_agentcore_runtime_inbound_authorizer()
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
                                "Action": [
                                    "bedrock:InvokeModel",
                                    "bedrock:InvokeModelWithResponseStream",
                                    "bedrock:CreateModelInvocationJob",
                                ],
                                "NotResource": [
                                    "arn:aws:bedrock:*::foundation-model/"
                                    "anthropic.claude-v2",
                                    "arn:aws:bedrock:*:123456789012:"
                                    "inference-profile/approved-*",
                                ],
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
        """Lines 1167-1168: repos exist but scan-on-push disabled → WARN.

        Inspector must be explicitly resolved (not left as an unconfigured
        mock) — an unconfigured MagicMock iterates as empty by default, which
        is indistinguishable from the account being absent from a real
        BatchGetAccountStatus response and would make this test pass for the
        wrong reason: the account-missing-from-response defect, not the
        base scanOnPush=false/WARN path it is meant to cover.
        """
        mock_client.side_effect = self._clients(
            repos_without_scanning=True, inspector_state="DISABLED"
        )
        result = app.check_ecr_image_scanning()
        _assert_structure(result)
        assert result["status"] == "WARN"

    @staticmethod
    def _clients(
        repos_without_scanning=True,
        inspector_error=None,
        inspector_state=None,
        inspector_response=None,
    ):
        ecr = MagicMock()
        ecr.describe_repositories.return_value = {
            "repositories": [
                {
                    "repositoryName": "ml-model-repo",
                    "imageScanningConfiguration": {
                        "scanOnPush": not repos_without_scanning
                    },
                }
            ]
        }

        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "123456789012"}

        inspector = MagicMock()
        if inspector_error is not None:
            inspector.batch_get_account_status.side_effect = inspector_error
        elif inspector_response is not None:
            # Full control over the response shape, for the cases where the
            # call succeeds (HTTP 200, no exception) but does not actually
            # report a usable status for the queried account.
            inspector.batch_get_account_status.return_value = inspector_response
        else:
            inspector.batch_get_account_status.return_value = {
                "accounts": [
                    {
                        "accountId": "123456789012",
                        "resourceState": {"ecr": {"status": inspector_state}},
                    }
                ],
                "failedAccounts": [],
            }

        def factory(service, **kwargs):
            return {"ecr": ecr, "sts": sts, "inspector2": inspector}.get(
                service, MagicMock()
            )

        return factory

    @patch("finserv_app.boto3.client")
    def test_inspector_lookup_denied_is_could_not_assess_not_failed(self, mock_client):
        """BatchGetAccountStatus denied while a repo has no scan-on-push → the
        check must not default an unknown Inspector state to "not enabled".
        Whether Inspector covers the repository is unknown, so this must be
        COULD NOT ASSESS rather than a Failed finding."""
        mock_client.side_effect = self._clients(
            repos_without_scanning=True,
            inspector_error=_client_error("AccessDeniedException"),
        )
        result = app.check_ecr_image_scanning()
        _assert_structure(result)
        assert any(
            r["Finding"].startswith(app.COULD_NOT_ASSESS_PREFIX)
            for r in result["csv_data"]
        )
        assert not any(r["Status"] == "Failed" for r in result["csv_data"])

    @patch("finserv_app.boto3.client")
    def test_inspector_lookup_denied_but_all_repos_scanned_is_still_passed(
        self, mock_client
    ):
        """An Inspector lookup failure is irrelevant when every repository
        already has scan-on-push enabled — nothing is unknown in that case."""
        mock_client.side_effect = self._clients(
            repos_without_scanning=False,
            inspector_error=_client_error("AccessDeniedException"),
        )
        result = app.check_ecr_image_scanning()
        _assert_structure(result)
        assert any(
            r["Finding"] == "ECR Image Scanning Enabled" and r["Status"] == "Passed"
            for r in result["csv_data"]
        )
        assert not any(
            r["Finding"].startswith(app.COULD_NOT_ASSESS_PREFIX)
            for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_inspector_confirmed_disabled_is_still_failed(self, mock_client):
        """Inspector genuinely DISABLED (not unknown) with an unscanned repo →
        the original Failed path must still work."""
        mock_client.side_effect = self._clients(
            repos_without_scanning=True, inspector_state="DISABLED"
        )
        result = app.check_ecr_image_scanning()
        _assert_structure(result)
        assert result["status"] == "WARN"
        assert any(
            r["Finding"] == "ECR Repositories Without Image Scanning"
            and r["Status"] == "Failed"
            for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_inspector_failed_accounts_entry_is_could_not_assess_not_failed(
        self, mock_client
    ):
        """BatchGetAccountStatus can return HTTP 200 with the queried account
        reported in failedAccounts instead of accounts — no exception is
        raised. Verified live: an account ID Inspector cannot resolve comes
        back exactly this way. A repo with no scan-on-push must still be
        COULD NOT ASSESS, not a false Failed, in this no-exception case."""
        mock_client.side_effect = self._clients(
            repos_without_scanning=True,
            inspector_response={
                "accounts": [],
                "failedAccounts": [
                    {
                        "accountId": "123456789012",
                        "errorCode": "ACCESS_DENIED",
                        "errorMessage": "Invoking account does not have access "
                        "to this account",
                    }
                ],
            },
        )
        result = app.check_ecr_image_scanning()
        _assert_structure(result)
        assert any(
            r["Finding"].startswith(app.COULD_NOT_ASSESS_PREFIX)
            for r in result["csv_data"]
        )
        assert not any(r["Status"] == "Failed" for r in result["csv_data"])

    @patch("finserv_app.boto3.client")
    def test_inspector_account_missing_from_response_is_could_not_assess_not_failed(
        self, mock_client
    ):
        """BatchGetAccountStatus succeeds but the queried account appears in
        neither accounts nor failedAccounts. Must still be treated as
        unknown, not silently fall through to "not enabled"."""
        mock_client.side_effect = self._clients(
            repos_without_scanning=True,
            inspector_response={"accounts": [], "failedAccounts": []},
        )
        result = app.check_ecr_image_scanning()
        _assert_structure(result)
        assert any(
            r["Finding"].startswith(app.COULD_NOT_ASSESS_PREFIX)
            for r in result["csv_data"]
        )
        assert not any(r["Status"] == "Failed" for r in result["csv_data"])


# =========================================================================
# FS-20 — lines 1238-1266: feature store warn/pass paths
# =========================================================================


class TestFS20FeatureStoreWarnPass:
    """FS-20 keys off OfflineStoreConfig from DescribeFeatureGroup.

    OfflineStoreStatus is NOT usable: verified against a live account, it is
    absent from both ListFeatureGroups summaries and DescribeFeatureGroup, so a
    check reading it flagged every feature group regardless of configuration.
    """

    @staticmethod
    def _sagemaker(groups, detail):
        c = MagicMock()
        c.list_feature_groups.return_value = {"FeatureGroupSummaries": groups}

        def describe(FeatureGroupName):  # noqa: N803 - matches the boto3 kwarg
            value = detail[FeatureGroupName]
            if isinstance(value, Exception):
                raise value
            return value

        c.describe_feature_group.side_effect = describe
        return c

    @patch("finserv_app.boto3.client")
    def test_warn_groups_without_offline_store(self, mock_client):
        """No OfflineStoreConfig on the describe response → WARN."""
        mock_client.return_value = self._sagemaker(
            [{"FeatureGroupName": "customer-features"}],
            {"customer-features": {"FeatureGroupName": "customer-features"}},
        )
        result = app.check_feature_store_rollback_capability()
        _assert_structure(result)
        assert result["status"] == "WARN"
        assert any(
            r["Finding"] == "Feature Groups Without Offline Store"
            for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_pass_all_groups_have_offline_store(self, mock_client):
        """OfflineStoreConfig present → Passed."""
        mock_client.return_value = self._sagemaker(
            [{"FeatureGroupName": "customer-features"}],
            {
                "customer-features": {
                    "OfflineStoreConfig": {
                        "S3StorageConfig": {
                            "S3Uri": "s3://fs-offline/customer-features"
                        }
                    }
                }
            },
        )
        result = app.check_feature_store_rollback_capability()
        _assert_structure(result)
        assert any(
            r["Finding"] == "Feature Groups With Offline Store Configured"
            and r["Status"] == "Passed"
            for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_describe_denied_is_could_not_assess_not_a_failure(self, mock_client):
        """DescribeFeatureGroup denied → COULD NOT ASSESS, never a Failed row."""
        mock_client.return_value = self._sagemaker(
            [{"FeatureGroupName": "customer-features"}],
            {"customer-features": _client_error("AccessDeniedException")},
        )
        result = app.check_feature_store_rollback_capability()
        _assert_structure(result)
        assert any(
            r["Finding"].startswith(app.COULD_NOT_ASSESS_PREFIX)
            for r in result["csv_data"]
        )
        assert not any(r["Status"] == "Failed" for r in result["csv_data"])


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
    def test_invalid_bedrock_agent_namespace_not_treated_as_kb_access(self):
        """bedrock-agent is a boto3 client name, not an IAM action namespace."""
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
        assert result["status"] == "PASS"

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
    """FS-25 keys off ListCollections.kmsKeyArn, not encryption-policy documents.

    ListSecurityPolicies summaries carry no ``policy`` member, so the previous
    ``json.loads(p.get("policy", "{}"))`` always produced ``{}`` and the
    "AWSOwnedKey not in {}" test was always true — every account was reported as
    using a customer-managed key and the Failed branch was unreachable. Verified
    live: kmsKeyArn is the literal string "auto" for an AWS-owned key.
    """

    @staticmethod
    def _oss(collections=None, error=None):
        c = MagicMock()
        if error is not None:
            c.list_collections.side_effect = error
        else:
            c.list_collections.return_value = {"collectionSummaries": collections}
        return c

    @patch("finserv_app.boto3.client")
    def test_pass_collection_with_cmk(self, mock_client):
        """kmsKeyArn is a real key ARN → Passed."""
        mock_client.return_value = self._oss(
            [
                {
                    "name": "kb-collection",
                    "kmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/abc",
                }
            ]
        )
        result = app.check_opensearch_serverless_encryption()
        _assert_structure(result)
        assert any(
            r["Finding"]
            == "OpenSearch Serverless Collections Using Customer-Managed Keys"
            and r["Status"] == "Passed"
            for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_na_no_collections(self, mock_client):
        """No collections → N/A. Orphaned encryption policies protect no data,
        so flagging them would itself be a false positive."""
        mock_client.return_value = self._oss([])
        result = app.check_opensearch_serverless_encryption()
        _assert_structure(result)
        assert any(
            r["Finding"] == "No OpenSearch Serverless Collections Found"
            and r["Status"] == "N/A"
            for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_fail_collection_with_aws_owned_key(self, mock_client):
        """kmsKeyArn == "auto" means an AWS-owned key → WARN/Failed, not a Pass."""
        mock_client.return_value = self._oss(
            [{"name": "aws-owned-collection", "kmsKeyArn": "auto"}]
        )
        result = app.check_opensearch_serverless_encryption()
        _assert_structure(result)
        assert result["status"] == "WARN"
        assert any(
            r["Finding"]
            == "OpenSearch Serverless Collections Using AWS-Owned Encryption Keys"
            and r["Status"] == "Failed"
            for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_missing_kms_key_arn_is_could_not_assess(self, mock_client):
        """A collection with no kmsKeyArn is undetermined, not silently passed."""
        mock_client.return_value = self._oss([{"name": "mystery-collection"}])
        result = app.check_opensearch_serverless_encryption()
        _assert_structure(result)
        assert any(
            r["Finding"].startswith(app.COULD_NOT_ASSESS_PREFIX)
            for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_list_collections_denied_is_could_not_assess(self, mock_client):
        """aoss:ListCollections denied → COULD NOT ASSESS, not a Failed row."""
        mock_client.return_value = self._oss(
            error=_client_error("AccessDeniedException")
        )
        result = app.check_opensearch_serverless_encryption()
        _assert_structure(result)
        assert any(
            r["Finding"].startswith(app.COULD_NOT_ASSESS_PREFIX)
            for r in result["csv_data"]
        )
        assert not any(r["Status"] == "Failed" for r in result["csv_data"])


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
    """FS-31 reads ingestion-job history, not the data source's own updatedAt.

    A data source's updatedAt is when its CONFIGURATION last changed. Verified
    live: a source last configured 2025-11-21 had in fact completed an ingestion
    on 2025-11-26, so the config timestamp overstated staleness by five days; a
    source edited yesterday that had never synced would have looked current.
    """

    @staticmethod
    def _inventory():
        return make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[{"knowledgeBaseId": "kb1", "name": "my-kb"}],
                data_sources_by_kb={
                    "kb1": [{"dataSourceId": "ds1", "name": "s3-source"}]
                },
                data_source_detail={},
            )
        )

    @staticmethod
    def _agent(jobs=None, error=None):
        c = MagicMock()
        if error is not None:
            c.list_ingestion_jobs.side_effect = error
        else:
            c.list_ingestion_jobs.return_value = {"ingestionJobSummaries": jobs}
        return c

    @patch("finserv_app.boto3.client")
    def test_warn_stale_data_sources(self, mock_client):
        """Most recent COMPLETE ingestion older than the threshold → WARN."""
        stale = datetime.now(timezone.utc) - timedelta(days=10)
        mock_client.return_value = self._agent(
            [{"status": "COMPLETE", "updatedAt": stale}]
        )
        result = app.check_knowledge_base_data_source_sync(self._inventory())
        _assert_structure(result)
        assert result["status"] == "WARN"
        assert any(
            r["Finding"] == "Knowledge Base Data Sources Past Review Threshold"
            for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_pass_recently_synced(self, mock_client):
        """A COMPLETE ingestion inside the threshold → Passed."""
        fresh = datetime.now(timezone.utc) - timedelta(days=1)
        mock_client.return_value = self._agent(
            [{"status": "COMPLETE", "updatedAt": fresh}]
        )
        result = app.check_knowledge_base_data_source_sync(self._inventory())
        _assert_structure(result)
        assert any(
            r["Finding"] == "Knowledge Base Data Sources Recently Synced"
            and r["Status"] == "Passed"
            for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_latest_complete_job_wins_over_newer_failed_job(self, mock_client):
        """Staleness is measured from the most recent COMPLETE job; a newer
        FAILED job must not be read as a successful sync."""
        mock_client.return_value = self._agent(
            [
                {
                    "status": "COMPLETE",
                    "updatedAt": datetime.now(timezone.utc) - timedelta(days=1),
                },
                {
                    "status": "FAILED",
                    "updatedAt": datetime.now(timezone.utc),
                },
            ]
        )
        result = app.check_knowledge_base_data_source_sync(self._inventory())
        _assert_structure(result)
        assert any(
            r["Finding"] == "Knowledge Base Data Sources Recently Synced"
            for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_never_synced_is_a_distinct_failure(self, mock_client):
        """Jobs exist but none COMPLETE → "never synced", and NO Passed row may
        be emitted alongside it."""
        mock_client.return_value = self._agent(
            [{"status": "FAILED", "updatedAt": datetime.now(timezone.utc)}]
        )
        result = app.check_knowledge_base_data_source_sync(self._inventory())
        _assert_structure(result)
        assert result["status"] == "WARN"
        assert any(
            r["Finding"] == "Knowledge Base Data Sources Never Successfully Synced"
            for r in result["csv_data"]
        )
        assert not any(r["Status"] == "Passed" for r in result["csv_data"])

    @patch("finserv_app.boto3.client")
    def test_list_ingestion_jobs_denied_is_could_not_assess(self, mock_client):
        """bedrock:ListIngestionJobs denied → COULD NOT ASSESS and no Passed row."""
        mock_client.return_value = self._agent(
            error=_client_error("AccessDeniedException")
        )
        result = app.check_knowledge_base_data_source_sync(self._inventory())
        _assert_structure(result)
        assert any(
            r["Finding"].startswith(app.COULD_NOT_ASSESS_PREFIX)
            for r in result["csv_data"]
        )
        assert not any(r["Status"] == "Passed" for r in result["csv_data"])

    @patch("finserv_app.boto3.client")
    def test_no_data_sources_is_na_not_a_vacuous_pass(self, mock_client):
        """A KB with no data source has no ingestion to age, so the row is N/A
        rather than "recently synced"."""
        mock_client.return_value = self._agent([])
        inv = make_resource_inventory(
            knowledge_bases=app.KbInventory(
                summaries=[{"knowledgeBaseId": "kb1", "name": "my-kb"}],
                data_sources_by_kb={"kb1": []},
                data_source_detail={},
            )
        )
        result = app.check_knowledge_base_data_source_sync(inv)
        _assert_structure(result)
        assert any(
            r["Finding"] == "No Knowledge Base Data Sources Found"
            and r["Status"] == "N/A"
            for r in result["csv_data"]
        )
        assert not any(r["Status"] == "Passed" for r in result["csv_data"])


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
    """FS-42 paginates ListModelCards on ModelCardSummaries and reads
    ModelCardStatus.

    The response key is ModelCardSummaries, not ModelCardSummaryList. Reading
    the wrong key meant the check reported "No SageMaker Model Cards Found" on
    every account, including accounts that had cards.
    """

    @staticmethod
    def _sagemaker(cards):
        c = MagicMock()
        c.list_model_cards.return_value = {"ModelCardSummaries": cards}
        return c

    @patch("finserv_app.boto3.client")
    def test_pass_approved_model_cards(self, mock_client):
        """An Approved card → Passed."""
        mock_client.return_value = self._sagemaker(
            [{"ModelCardName": "fraud-model-card", "ModelCardStatus": "Approved"}]
        )
        result = app.check_ai_service_cards_documentation()
        _assert_structure(result)
        assert any(
            r["Finding"] == "SageMaker Model Cards Approved" and r["Status"] == "Passed"
            for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_fail_unapproved_model_cards(self, mock_client):
        """A Draft card has not completed its documented review → Failed."""
        mock_client.return_value = self._sagemaker(
            [{"ModelCardName": "fraud-model-card", "ModelCardStatus": "Draft"}]
        )
        result = app.check_ai_service_cards_documentation()
        _assert_structure(result)
        assert result["status"] == "WARN"
        assert any(
            r["Finding"] == "SageMaker Model Cards Not Approved"
            and r["Status"] == "Failed"
            for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_absent_cards_are_na_not_a_failure(self, mock_client):
        """A Bedrock-only estate legitimately has no SageMaker model cards, so
        absence is Informational/N/A rather than Failed/Medium."""
        mock_client.return_value = self._sagemaker([])
        result = app.check_ai_service_cards_documentation()
        _assert_structure(result)
        row = next(
            r
            for r in result["csv_data"]
            if r["Finding"] == "No SageMaker Model Cards Found"
        )
        assert row["Status"] == "N/A"
        # Severity may be a SeverityEnum or a plain string depending on caller.
        assert str(row["Severity"]).upper().endswith("INFORMATIONAL")

    @patch("finserv_app.boto3.client")
    def test_reads_model_card_summaries_not_summary_list(self, mock_client):
        """Guard against a regression to the old, wrong response key."""
        c = MagicMock()
        c.list_model_cards.return_value = {
            "ModelCardSummaries": [
                {"ModelCardName": "real-card", "ModelCardStatus": "Approved"}
            ],
            "ModelCardSummaryList": [],
        }
        mock_client.return_value = c
        result = app.check_ai_service_cards_documentation()
        assert not any(
            r["Finding"] == "No SageMaker Model Cards Found" for r in result["csv_data"]
        )


# =========================================================================
# FS-43 — lines 2536-2541: CloudWatch PII masking paths
# =========================================================================


class TestFS43CloudwatchPiiPaths:
    """FS-43 branches on where Bedrock actually delivers invocation logs.

    Verified live: an account logging to S3 only (no cloudWatchConfig) was still
    reported as a High failure about plaintext PII in CloudWatch, where no
    Bedrock logs existed at all. A log-group-scoped data protection policy is
    also invisible to DescribeAccountPolicies, which produced the opposite error.
    """

    @staticmethod
    def _clients(
        logging_config,
        account_policies=None,
        group_policy=None,
        describe_error=None,
        group_error=None,
        logging_error=None,
    ):
        bedrock = MagicMock()
        if logging_error is not None:
            bedrock.get_model_invocation_logging_configuration.side_effect = (
                logging_error
            )
        else:
            bedrock.get_model_invocation_logging_configuration.return_value = (
                {"loggingConfig": logging_config} if logging_config is not None else {}
            )

        logs = MagicMock()
        if describe_error is not None:
            logs.describe_account_policies.side_effect = describe_error
        else:
            logs.describe_account_policies.return_value = {
                "accountPolicies": account_policies or []
            }
        # GetDataProtectionPolicy does NOT raise for a log group without a
        # policy; it returns a response with no policyDocument member. Only
        # ResponseMetadata comes back, so truthiness of the response is useless.
        if group_error is not None:
            logs.get_data_protection_policy.side_effect = group_error
        else:
            logs.get_data_protection_policy.return_value = (
                {"policyDocument": group_policy, "ResponseMetadata": {}}
                if group_policy
                else {"ResponseMetadata": {}}
            )

        def factory(service, **kwargs):
            return {"bedrock": bedrock, "logs": logs}.get(service, MagicMock())

        return factory

    _CW = {"cloudWatchConfig": {"logGroupName": "/aws/bedrock/invocations"}}

    @patch("finserv_app.boto3.client")
    def test_warn_no_data_protection_policies(self, mock_client):
        """CloudWatch delivery with neither account nor log-group policy → WARN."""
        mock_client.side_effect = self._clients(self._CW)
        result = app.check_cloudwatch_log_pii_masking()
        _assert_structure(result)
        assert result["status"] == "WARN"
        assert any(
            r["Finding"] == "No CloudWatch Logs Data Protection Policies"
            for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_describe_policies_denied_with_no_group_policy_is_could_not_assess(
        self, mock_client
    ):
        """DescribeAccountPolicies denied and no log-group policy found → the
        account-scoped side is UNKNOWN, not confirmed empty, so this must be
        COULD NOT ASSESS rather than a Failed finding. A denial is a permissions
        gap, not evidence that no policy exists."""
        mock_client.side_effect = self._clients(
            self._CW, describe_error=_client_error("AccessDeniedException")
        )
        result = app.check_cloudwatch_log_pii_masking()
        _assert_structure(result)
        assert any(
            r["Finding"].startswith(app.COULD_NOT_ASSESS_PREFIX)
            for r in result["csv_data"]
        )
        assert not any(r["Status"] == "Failed" for r in result["csv_data"])

    @patch("finserv_app.boto3.client")
    def test_group_policy_lookup_denied_with_no_account_policy_is_could_not_assess(
        self, mock_client
    ):
        """GetDataProtectionPolicy denied and no account-scoped policy found →
        the log-group side is UNKNOWN, so this must be COULD NOT ASSESS."""
        mock_client.side_effect = self._clients(
            self._CW, group_error=_client_error("AccessDeniedException")
        )
        result = app.check_cloudwatch_log_pii_masking()
        _assert_structure(result)
        assert any(
            r["Finding"].startswith(app.COULD_NOT_ASSESS_PREFIX)
            for r in result["csv_data"]
        )
        assert not any(r["Status"] == "Failed" for r in result["csv_data"])

    @patch("finserv_app.boto3.client")
    def test_both_policy_lookups_denied_is_could_not_assess(self, mock_client):
        """Both calls denied → COULD NOT ASSESS, never Failed."""
        mock_client.side_effect = self._clients(
            self._CW,
            describe_error=_client_error("AccessDeniedException"),
            group_error=_client_error("ThrottlingException"),
        )
        result = app.check_cloudwatch_log_pii_masking()
        _assert_structure(result)
        assert any(
            r["Finding"].startswith(app.COULD_NOT_ASSESS_PREFIX)
            for r in result["csv_data"]
        )
        assert not any(r["Status"] == "Failed" for r in result["csv_data"])

    @patch("finserv_app.boto3.client")
    def test_describe_policies_denied_but_group_policy_found_is_still_passed(
        self, mock_client
    ):
        """A denial on the account-scoped lookup must not block a legitimate
        Passed verdict when the log-group-scoped policy IS found."""
        mock_client.side_effect = self._clients(
            self._CW,
            describe_error=_client_error("AccessDeniedException"),
            group_policy='{"Name":"dp"}',
        )
        result = app.check_cloudwatch_log_pii_masking()
        _assert_structure(result)
        assert any(
            r["Finding"] == "CloudWatch Logs Data Protection Policies Present"
            and r["Status"] == "Passed"
            for r in result["csv_data"]
        )
        assert not any(
            r["Finding"].startswith(app.COULD_NOT_ASSESS_PREFIX)
            for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_pass_account_scoped_policy(self, mock_client):
        """An account-scoped policy satisfies the control."""
        mock_client.side_effect = self._clients(
            self._CW, account_policies=[{"policyName": "acct-dp"}]
        )
        result = app.check_cloudwatch_log_pii_masking()
        _assert_structure(result)
        assert any(
            r["Finding"] == "CloudWatch Logs Data Protection Policies Present"
            and r["Status"] == "Passed"
            for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_pass_log_group_scoped_policy_only(self, mock_client):
        """A policy attached directly to the log group also satisfies the
        control, even though DescribeAccountPolicies cannot see it."""
        mock_client.side_effect = self._clients(
            self._CW, account_policies=[], group_policy='{"Name":"dp"}'
        )
        result = app.check_cloudwatch_log_pii_masking()
        _assert_structure(result)
        assert any(
            r["Finding"] == "CloudWatch Logs Data Protection Policies Present"
            and r["Status"] == "Passed"
            for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_s3_only_delivery_is_not_applicable(self, mock_client):
        """S3-only delivery → N/A. CloudWatch data protection cannot apply to a
        delivery path that never reaches CloudWatch Logs."""
        mock_client.side_effect = self._clients(
            {"s3Config": {"bucketName": "bedrock-logs-bucket"}}
        )
        result = app.check_cloudwatch_log_pii_masking()
        _assert_structure(result)
        assert any(
            r["Finding"] == "Bedrock Invocation Logs Not Delivered to CloudWatch Logs"
            and r["Status"] == "N/A"
            for r in result["csv_data"]
        )
        assert not any(r["Status"] == "Failed" for r in result["csv_data"])

    @patch("finserv_app.boto3.client")
    def test_logging_disabled_is_not_applicable(self, mock_client):
        """Invocation logging off → nothing to mask → N/A, not a failure."""
        mock_client.side_effect = self._clients(None)
        result = app.check_cloudwatch_log_pii_masking()
        _assert_structure(result)
        assert any(
            r["Finding"] == "Bedrock Invocation Logging Not Enabled"
            and r["Status"] == "N/A"
            for r in result["csv_data"]
        )
        assert not any(r["Status"] == "Failed" for r in result["csv_data"])

    @patch("finserv_app.boto3.client")
    def test_logging_config_unreadable_is_could_not_assess(self, mock_client):
        """Without the logging configuration the applicable destination is
        unknown, so the check must not guess."""
        mock_client.side_effect = self._clients(
            None, logging_error=_client_error("AccessDeniedException")
        )
        result = app.check_cloudwatch_log_pii_masking()
        _assert_structure(result)
        assert any(
            r["Finding"].startswith(app.COULD_NOT_ASSESS_PREFIX)
            for r in result["csv_data"]
        )
        assert not any(r["Status"] == "Failed" for r in result["csv_data"])


# =========================================================================
# FS-44 — lines 2589-2628: Macie paths
# =========================================================================


class TestFS44MaciePaths:
    """FS-44 requires automated discovery, not merely an enabled session.

    Verified live: a session with status ENABLED and automated discovery DISABLED
    was reported as "Macie is enabled and scanning S3 buckets" while Macie was
    scanning nothing. An AccessDenied on GetMacieSession is also ambiguous — for
    an account that never onboarded Macie the message says so, and that is a real
    finding; any other denial is a permissions gap, not a security finding.
    """

    @staticmethod
    def _macie(
        session_status=None,
        discovery_status=None,
        session_error=None,
        discovery_error=None,
    ):
        c = MagicMock()
        if session_error is not None:
            c.get_macie_session.side_effect = session_error
        else:
            c.get_macie_session.return_value = {"status": session_status}
        if discovery_error is not None:
            c.get_automated_discovery_configuration.side_effect = discovery_error
        else:
            c.get_automated_discovery_configuration.return_value = {
                "status": discovery_status
            }
        return c

    @patch("finserv_app.boto3.client")
    def test_warn_macie_not_enabled(self, mock_client):
        """Session status not ENABLED → WARN."""
        mock_client.return_value = self._macie(session_status="PAUSED")
        result = app.check_macie_on_training_data_buckets()
        _assert_structure(result)
        assert result["status"] == "WARN"
        assert any(
            r["Finding"] == "Amazon Macie Not Enabled" for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_not_onboarded_denial_is_reported_as_not_enabled(self, mock_client):
        """AccessDenied whose message says Macie is not enabled is a real
        finding, not a permissions gap."""
        mock_client.return_value = self._macie(
            session_error=_client_error(
                "AccessDeniedException", "Macie is not enabled for this account"
            )
        )
        result = app.check_macie_on_training_data_buckets()
        _assert_structure(result)
        assert result["status"] == "WARN"
        assert any(
            r["Finding"] == "Amazon Macie Not Enabled" for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_generic_denial_is_could_not_assess(self, mock_client):
        """A denial that does not say Macie is disabled is a permissions gap and
        must not be reported as a security failure."""
        mock_client.return_value = self._macie(
            session_error=_client_error("AccessDeniedException", "Access Denied")
        )
        result = app.check_macie_on_training_data_buckets()
        _assert_structure(result)
        assert any(
            r["Finding"].startswith(app.COULD_NOT_ASSESS_PREFIX)
            for r in result["csv_data"]
        )
        assert not any(r["Status"] == "Failed" for r in result["csv_data"])

    @patch("finserv_app.boto3.client")
    def test_pass_macie_enabled_with_automated_discovery(self, mock_client):
        """Session ENABLED and automated discovery ENABLED → Passed."""
        mock_client.return_value = self._macie(
            session_status="ENABLED", discovery_status="ENABLED"
        )
        result = app.check_macie_on_training_data_buckets()
        _assert_structure(result)
        assert any(
            r["Finding"] == "Amazon Macie Automated Discovery Enabled"
            and r["Status"] == "Passed"
            for r in result["csv_data"]
        )

    @patch("finserv_app.boto3.client")
    def test_fail_enabled_session_without_automated_discovery(self, mock_client):
        """Session ENABLED but discovery DISABLED scans nothing → Failed, and no
        Passed row may claim otherwise."""
        mock_client.return_value = self._macie(
            session_status="ENABLED", discovery_status="DISABLED"
        )
        result = app.check_macie_on_training_data_buckets()
        _assert_structure(result)
        assert result["status"] == "WARN"
        assert any(
            r["Finding"] == "Amazon Macie Enabled but Automated Discovery Disabled"
            and r["Status"] == "Failed"
            for r in result["csv_data"]
        )
        assert not any(r["Status"] == "Passed" for r in result["csv_data"])

    @patch("finserv_app.boto3.client")
    def test_discovery_lookup_denied_is_could_not_assess(self, mock_client):
        """macie2:GetAutomatedDiscoveryConfiguration denied → COULD NOT ASSESS."""
        mock_client.return_value = self._macie(
            session_status="ENABLED",
            discovery_error=_client_error("AccessDeniedException"),
        )
        result = app.check_macie_on_training_data_buckets()
        _assert_structure(result)
        assert any(
            r["Finding"].startswith(app.COULD_NOT_ASSESS_PREFIX)
            for r in result["csv_data"]
        )


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
