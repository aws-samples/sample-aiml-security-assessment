"""
Tests for SageMaker security assessment checks (SM-01 through SM-25).

Each check is tested for:
- No resources found -> N/A status
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

from tests.test_helpers import extract_csv_data, assert_finding_schema

# Load sagemaker app module directly to avoid name collisions
_sm_dir = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "aiml-security-assessment/functions/security/sagemaker_assessments",
    )
)
if _sm_dir not in sys.path:
    sys.path.insert(0, _sm_dir)

if "sagemaker_app" in sys.modules:
    sagemaker_app = sys.modules["sagemaker_app"]
else:
    # agentcore_assessments, bedrock_assessments, and sagemaker_assessments
    # each define their own same-named "schema"/"severity_disposition"
    # modules. If another module's test already ran and cached
    # sys.modules["severity_disposition"] (or ["schema"]) with its own
    # version, sagemaker_app.py's plain `from severity_disposition import
    # ...` / `from schema import ...` would silently bind to that other
    # module instead of its own. Evict any stale cache entries so the import
    # below resolves against _sm_dir (already at the front of sys.path).
    sys.modules.pop("severity_disposition", None)
    sys.modules.pop("schema", None)
    _spec = importlib.util.spec_from_file_location(
        "sagemaker_app", os.path.join(_sm_dir, "app.py")
    )
    sagemaker_app = importlib.util.module_from_spec(_spec)
    sys.modules["sagemaker_app"] = sagemaker_app
    _spec.loader.exec_module(sagemaker_app)


# ===================================================================
# SM-01: check_sagemaker_internet_access
# ===================================================================
class TestSM01InternetAccess:
    """SM-01: Check SageMaker direct internet access (notebooks only)."""

    @patch("sagemaker_app.boto3.client")
    def test_sm01_no_resources_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_internet_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        nb_paginator = MagicMock()
        mock_sm.get_paginator.return_value = nb_paginator
        nb_paginator.paginate.return_value = [{"NotebookInstances": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "SM-01"

    @patch("sagemaker_app.boto3.client")
    def test_sm01_notebook_with_internet_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_internet_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        nb_paginator = MagicMock()
        mock_sm.get_paginator.return_value = nb_paginator
        nb_paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": "test-nb"}]}
        ]
        mock_sm.describe_notebook_instance.return_value = {
            "DirectInternetAccess": "Enabled",
            "SubnetId": "subnet-123",
            "VpcId": "vpc-123",
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"

    @patch("sagemaker_app.boto3.client")
    def test_sm01_all_vpc_only_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_internet_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        nb_paginator = MagicMock()
        mock_sm.get_paginator.return_value = nb_paginator
        nb_paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": "test-nb"}]}
        ]
        mock_sm.describe_notebook_instance.return_value = {
            "DirectInternetAccess": "Disabled",
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm01_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_internet_access
        mock_client.side_effect = Exception("SageMaker error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("sagemaker_app.boto3.client")
    def test_sm01_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_internet_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        nb_paginator = MagicMock()
        mock_sm.get_paginator.return_value = nb_paginator
        nb_paginator.paginate.return_value = [{"NotebookInstances": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-27: check_sagemaker_domain_network_access (repo-specific)
# (split out of the former SM-01, which incorrectly labeled domain findings
# under the SageMaker.1 control — that control's scope is NotebookInstance
# only.)
# ===================================================================
class TestSM27DomainNetworkAccess:
    """SM-27: Check SageMaker domain VPC-only network access (repo-specific)."""

    @patch("sagemaker_app.boto3.client")
    def test_sm27_no_domains_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_domain_network_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        domain_paginator = MagicMock()
        mock_sm.get_paginator.return_value = domain_paginator
        domain_paginator.paginate.return_value = [{"Domains": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-27"
        assert findings[0]["Status"] == "N/A"

    @patch("sagemaker_app.boto3.client")
    def test_sm27_domain_not_vpc_only_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_domain_network_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        domain_paginator = MagicMock()
        mock_sm.get_paginator.return_value = domain_paginator
        domain_paginator.paginate.return_value = [{"Domains": [{"DomainId": "d-123"}]}]
        mock_sm.describe_domain.return_value = {
            "DomainName": "test-domain",
            "AppNetworkAccessType": "PublicInternetOnly",
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Check_ID"] == "SM-27"

    @patch("sagemaker_app.boto3.client")
    def test_sm27_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_domain_network_access
        mock_client.side_effect = Exception("SageMaker error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")


# ===================================================================
# SM-02: check_sagemaker_iam_permissions
# ===================================================================
class TestSM02IAMPermissions:
    """SM-02: Check SageMaker IAM permissions and SSO."""

    def test_sm02_empty_cache_returns_findings(self, empty_permission_cache):
        check = sagemaker_app.check_sagemaker_iam_permissions
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-02"

    def test_sm02_full_access_returns_failed(
        self, permission_cache_sagemaker_full_access
    ):
        check = sagemaker_app.check_sagemaker_iam_permissions
        result = check(permission_cache_sagemaker_full_access)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        # Should flag full access as an issue
        has_failed = any(f["Status"] == "Failed" for f in findings)
        assert has_failed

    def test_sm02_schema_valid(self, empty_permission_cache):
        check = sagemaker_app.check_sagemaker_iam_permissions
        result = check(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    def test_sm02_iam_check_does_not_query_domains(
        self, permission_cache_sagemaker_full_access
    ):
        # The IAM-global SM-02 check must NOT call regional SageMaker domain APIs;
        # domain/SSO inspection lives in check_sagemaker_sso_configuration so it is
        # not duplicated per region. Only IAM findings should be produced here.
        check = sagemaker_app.check_sagemaker_iam_permissions
        result = check(permission_cache_sagemaker_full_access, region="Global")
        findings = extract_csv_data(result)
        # No SSO finding should be emitted from the IAM-global check
        assert all("SSO" not in f["Finding"] for f in findings)


# ===================================================================
# SM-02b: check_sagemaker_sso_configuration (regional)
# ===================================================================
class TestSM02SSOConfiguration:
    """SM-02: Regional SageMaker domain SSO configuration check."""

    @patch("sagemaker_app.boto3.client")
    def test_sso_no_domains_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_sso_configuration
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Domains": []}]
        mock_sm.get_paginator.return_value = mock_paginator
        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-02"
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sso_non_sso_domain_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_sso_configuration
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Domains": [{"DomainId": "d-123"}]}]
        mock_sm.get_paginator.return_value = mock_paginator
        mock_sm.describe_domain.return_value = {
            "DomainName": "test-domain",
            "AuthMode": "IAM",
        }
        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert "SSO" in findings[0]["Finding"]

    @patch("sagemaker_app.boto3.client")
    def test_sso_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_sso_configuration
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Domains": []}]
        mock_sm.get_paginator.return_value = mock_paginator
        result = check(region="us-east-1")
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-03: check_sagemaker_notebook_storage_encryption
# (was check_sagemaker_data_protection; split per gap-analysis PR-0 so the
# SM-03 label maps only to SageMaker.21 notebook storage encryption. Domain
# and training-job encryption moved to check_sagemaker_domain_and_training_job_encryption
# under SM-26 — see TestSM26DomainAndTrainingJobEncryption below.)
# ===================================================================
class TestSM03NotebookStorageEncryption:
    """SM-03: Check SageMaker notebook storage encryption (SageMaker.21)."""

    @patch("sagemaker_app.boto3.client")
    def test_sm03_no_resources_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_storage_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"NotebookInstances": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-03"
        assert findings[0]["Status"] == "N/A"

    @patch("sagemaker_app.boto3.client")
    def test_sm03_notebook_without_kms_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_storage_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": "test-nb"}]}
        ]
        mock_sm.describe_notebook_instance.return_value = {}
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"

    @patch("sagemaker_app.boto3.client")
    def test_sm03_notebook_with_customer_kms_returns_passed(self, mock_client):
        """Presence-as-proxy: any configured KMS key id/ARN passes, including
        an AWS-managed key id/ARN that a substring test would miss (the SM-03
        false-PASS defect this rewrite fixes is the substring test itself,
        not this presence check)."""
        check = sagemaker_app.check_sagemaker_notebook_storage_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": "test-nb"}]}
        ]
        mock_sm.describe_notebook_instance.return_value = {
            "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/abcd-1234"
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm03_no_longer_uses_substring_kms_test(self, mock_client):
        """Regression test (gap-analysis PR-0 / SM-03 defect): the rewritten
        check must not gate on a substring match against the KMS key id/ARN
        (the old bug: 'aws/sagemaker' in kms_key_id). That substring test
        missed AWS-managed keys referenced by key id or ARN and could produce
        a false PASS on an encryption control; detection is presence-as-proxy
        only, so the executable body must not contain an 'in kms_key_id'-style
        substring comparison."""
        import inspect

        source = inspect.getsource(
            sagemaker_app.check_sagemaker_notebook_storage_encryption
        )
        assert "in kms_key_id" not in source

    @patch("sagemaker_app.boto3.client")
    def test_sm03_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_storage_encryption
        mock_client.side_effect = Exception("Data protection error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("sagemaker_app.boto3.client")
    def test_sm03_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_storage_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"NotebookInstances": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-26: check_sagemaker_domain_and_training_job_encryption
# (repo-specific hardening check; split out of the former SM-03)
# ===================================================================
class TestSM26DomainAndTrainingJobEncryption:
    """SM-26: Check SageMaker domain/training-job encryption (repo-specific)."""

    @patch("sagemaker_app.boto3.client")
    def test_sm26_no_resources_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_domain_and_training_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        domain_paginator = MagicMock()
        training_paginator = MagicMock()
        mock_sm.get_paginator.side_effect = lambda x: (
            domain_paginator if x == "list_domains" else training_paginator
        )
        domain_paginator.paginate.return_value = [{"Domains": []}]
        training_paginator.paginate.return_value = [{"TrainingJobSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-26"
        assert findings[0]["Status"] == "N/A"

    @patch("sagemaker_app.boto3.client")
    def test_sm26_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_domain_and_training_job_encryption
        mock_client.side_effect = Exception("Data protection error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("sagemaker_app.boto3.client")
    def test_sm26_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_domain_and_training_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        domain_paginator = MagicMock()
        training_paginator = MagicMock()
        mock_sm.get_paginator.side_effect = lambda x: (
            domain_paginator if x == "list_domains" else training_paginator
        )
        domain_paginator.paginate.return_value = [{"Domains": []}]
        training_paginator.paginate.return_value = [{"TrainingJobSummaries": []}]
        result = check(region="us-east-1")
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-04: check_guardduty_enabled
# ===================================================================
class TestSM04GuardDuty:
    """SM-04: Check GuardDuty is enabled."""

    @patch("sagemaker_app.boto3.client")
    def test_sm04_guardduty_enabled_returns_passed(self, mock_client):
        check = sagemaker_app.check_guardduty_enabled
        mock_gd = MagicMock()
        mock_client.return_value = mock_gd
        mock_gd.list_detectors.return_value = {"DetectorIds": ["d-123"]}
        mock_gd.get_detector.return_value = {"Status": "ENABLED"}
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "SM-04"

    @patch("sagemaker_app.boto3.client")
    def test_sm04_guardduty_disabled_returns_failed(self, mock_client):
        check = sagemaker_app.check_guardduty_enabled
        mock_gd = MagicMock()
        mock_client.return_value = mock_gd
        mock_gd.list_detectors.return_value = {"DetectorIds": []}
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm04_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_guardduty_enabled
        mock_client.side_effect = Exception("GuardDuty error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("sagemaker_app.boto3.client")
    def test_sm04_schema_valid(self, mock_client):
        check = sagemaker_app.check_guardduty_enabled
        mock_gd = MagicMock()
        mock_client.return_value = mock_gd
        mock_gd.list_detectors.return_value = {"DetectorIds": []}
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-05: check_sagemaker_mlops_utilization
# ===================================================================
class TestSM05MLOps:
    """SM-05: Check SageMaker MLOps features utilization."""

    @patch("sagemaker_app.boto3.client")
    def test_sm05_empty_cache_returns_findings(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_sagemaker_mlops_utilization
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_model_packages.return_value = {"ModelPackageSummaryList": []}
        mock_sm.list_feature_groups.return_value = {"FeatureGroupSummaries": []}
        mock_sm.list_pipelines.return_value = {"PipelineSummaries": []}
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-05"

    @patch("sagemaker_app.boto3.client")
    def test_sm05_exception_returns_error_result(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_sagemaker_mlops_utilization
        mock_client.side_effect = Exception("MLOps error")
        result = check(empty_permission_cache)
        # SM-05 returns empty csv_data on outer exception but sets status=ERROR
        assert result.get("status") == "ERROR" or result.get("csv_data") is not None

    @patch("sagemaker_app.boto3.client")
    def test_sm05_schema_valid(self, mock_client, empty_permission_cache):
        check = sagemaker_app.check_sagemaker_mlops_utilization
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_model_packages.return_value = {"ModelPackageSummaryList": []}
        mock_sm.list_feature_groups.return_value = {"FeatureGroupSummaries": []}
        mock_sm.list_pipelines.return_value = {"PipelineSummaries": []}
        result = check(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-06: check_sagemaker_clarify_usage
# ===================================================================
class TestSM06Clarify:
    """SM-06: Check SageMaker Clarify usage."""

    @patch("sagemaker_app.boto3.client")
    def test_sm06_empty_cache_returns_findings(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_sagemaker_clarify_usage
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_processing_jobs.return_value = {"ProcessingJobSummaries": []}
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-06"

    @patch("sagemaker_app.boto3.client")
    def test_sm06_exception_returns_error_result(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_sagemaker_clarify_usage
        mock_client.side_effect = Exception("Clarify error")
        result = check(empty_permission_cache)
        assert result.get("status") == "ERROR" or result.get("csv_data") is not None

    @patch("sagemaker_app.boto3.client")
    def test_sm06_schema_valid(self, mock_client, empty_permission_cache):
        check = sagemaker_app.check_sagemaker_clarify_usage
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_processing_jobs.return_value = {"ProcessingJobSummaries": []}
        result = check(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-07: check_sagemaker_model_monitor_usage
# ===================================================================
class TestSM07ModelMonitor:
    """SM-07: Check SageMaker Model Monitor usage."""

    @patch("sagemaker_app.boto3.client")
    def test_sm07_empty_cache_returns_findings(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_sagemaker_model_monitor_usage
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_monitoring_schedules.return_value = {
            "MonitoringScheduleSummaries": []
        }
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-07"

    @patch("sagemaker_app.boto3.client")
    def test_sm07_exception_returns_error_result(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_sagemaker_model_monitor_usage
        mock_client.side_effect = Exception("Monitor error")
        result = check(empty_permission_cache)
        assert result.get("status") == "ERROR" or result.get("csv_data") is not None

    @patch("sagemaker_app.boto3.client")
    def test_sm07_schema_valid(self, mock_client, empty_permission_cache):
        check = sagemaker_app.check_sagemaker_model_monitor_usage
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_monitoring_schedules.return_value = {
            "MonitoringScheduleSummaries": []
        }
        result = check(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-08: check_model_registry_usage
# ===================================================================
class TestSM08ModelRegistry:
    """SM-08: Check Model Registry usage."""

    @patch("sagemaker_app.boto3.client")
    def test_sm08_empty_cache_returns_findings(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_model_registry_usage
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_model_package_groups.return_value = {
            "ModelPackageGroupSummaryList": []
        }
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-08"

    @patch("sagemaker_app.boto3.client")
    def test_sm08_exception_returns_error_result(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_model_registry_usage
        mock_client.side_effect = Exception("Registry error")
        result = check(empty_permission_cache)
        assert result.get("status") == "ERROR" or result.get("csv_data") is not None

    @patch("sagemaker_app.boto3.client")
    def test_sm08_schema_valid(self, mock_client, empty_permission_cache):
        check = sagemaker_app.check_model_registry_usage
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_model_package_groups.return_value = {
            "ModelPackageGroupSummaryList": []
        }
        result = check(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-09: check_sagemaker_notebook_root_access
# ===================================================================
class TestSM09NotebookRootAccess:
    """SM-09: Check notebook root access."""

    @patch("sagemaker_app.boto3.client")
    def test_sm09_no_notebooks_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_root_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"NotebookInstances": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-09"

    @patch("sagemaker_app.boto3.client")
    def test_sm09_root_enabled_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_root_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": "nb-1"}]}
        ]
        mock_sm.describe_notebook_instance.return_value = {
            "RootAccess": "Enabled",
            "NotebookInstanceName": "nb-1",
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm09_root_disabled_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_root_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": "nb-1"}]}
        ]
        mock_sm.describe_notebook_instance.return_value = {
            "RootAccess": "Disabled",
            "NotebookInstanceName": "nb-1",
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm09_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_root_access
        mock_client.side_effect = Exception("Root access error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("sagemaker_app.boto3.client")
    def test_sm09_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_root_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"NotebookInstances": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-10: check_sagemaker_notebook_vpc_deployment
# ===================================================================
class TestSM10NotebookVPC:
    """SM-10: Check notebook VPC deployment."""

    @patch("sagemaker_app.boto3.client")
    def test_sm10_no_notebooks_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_vpc_deployment
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"NotebookInstances": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-10"

    @patch("sagemaker_app.boto3.client")
    def test_sm10_no_vpc_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_vpc_deployment
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": "nb-1"}]}
        ]
        mock_sm.describe_notebook_instance.return_value = {
            "NotebookInstanceName": "nb-1",
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm10_with_vpc_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_vpc_deployment
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": "nb-1"}]}
        ]
        mock_sm.describe_notebook_instance.return_value = {
            "NotebookInstanceName": "nb-1",
            "SubnetId": "subnet-123",
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm10_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_vpc_deployment
        mock_client.side_effect = Exception("VPC error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("sagemaker_app.boto3.client")
    def test_sm10_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_vpc_deployment
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"NotebookInstances": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-11: check_sagemaker_model_network_isolation
# ===================================================================
class TestSM11ModelNetworkIsolation:
    """SM-11: Check model network isolation."""

    @patch("sagemaker_app.boto3.client")
    def test_sm11_no_models_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_network_isolation
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"Models": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-11"

    @patch("sagemaker_app.boto3.client")
    def test_sm11_isolation_disabled_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_network_isolation
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"Models": [{"ModelName": "model-1"}]}]
        mock_sm.describe_model.return_value = {
            "ModelName": "model-1",
            "EnableNetworkIsolation": False,
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm11_isolation_enabled_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_network_isolation
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"Models": [{"ModelName": "model-1"}]}]
        mock_sm.describe_model.return_value = {
            "ModelName": "model-1",
            "EnableNetworkIsolation": True,
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm11_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_network_isolation
        mock_client.side_effect = Exception("Network isolation error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")


# ===================================================================
# SM-12: check_sagemaker_endpoint_instance_count (SageMaker.4)
# ===================================================================
class TestSM12EndpointInstanceCount:
    """SM-12: Check endpoint CONFIG instance count for availability
    (SageMaker.4 evaluates ProductionVariants[*].InitialInstanceCount on the
    EndpointConfig resource, not the live endpoint's CurrentInstanceCount)."""

    @patch("sagemaker_app.boto3.client")
    def test_sm12_no_configs_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_endpoint_instance_count
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"EndpointConfigs": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-12"
        assert findings[0]["Status"] == "N/A"

    @patch("sagemaker_app.boto3.client")
    def test_sm12_single_instance_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_endpoint_instance_count
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"EndpointConfigs": [{"EndpointConfigName": "cfg-1"}]}
        ]
        mock_sm.describe_endpoint_config.return_value = {
            "ProductionVariants": [{"InitialInstanceCount": 1, "VariantName": "v1"}]
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        mock_sm.describe_endpoint_config.assert_called_once_with(
            EndpointConfigName="cfg-1"
        )

    @patch("sagemaker_app.boto3.client")
    def test_sm12_multi_instance_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_endpoint_instance_count
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"EndpointConfigs": [{"EndpointConfigName": "cfg-1"}]}
        ]
        mock_sm.describe_endpoint_config.return_value = {
            "ProductionVariants": [{"InitialInstanceCount": 3, "VariantName": "v1"}]
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm12_serverless_variant_is_skipped(self, mock_client):
        """Regression guard: serverless variants carry no
        InitialInstanceCount (they expose ServerlessConfig instead). They
        must be skipped, not treated as 0 instances, which previously
        false-failed every serverless config. Security Hub SageMaker.4
        applies only to instance-based variants."""
        check = sagemaker_app.check_sagemaker_endpoint_instance_count
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"EndpointConfigs": [{"EndpointConfigName": "cfg-sls"}]}
        ]
        mock_sm.describe_endpoint_config.return_value = {
            "ProductionVariants": [
                {
                    "VariantName": "v1",
                    "ServerlessConfig": {"MemorySizeInMB": 2048},
                }
            ]
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) == 1
        assert findings[0]["Status"] == "N/A"

    @patch("sagemaker_app.boto3.client")
    def test_sm12_mixed_serverless_and_single_instance(self, mock_client):
        """Serverless variants are skipped while instance-based variants are
        still evaluated."""
        check = sagemaker_app.check_sagemaker_endpoint_instance_count
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"EndpointConfigs": [{"EndpointConfigName": "cfg-mix"}]}
        ]
        mock_sm.describe_endpoint_config.return_value = {
            "ProductionVariants": [
                {
                    "VariantName": "sls",
                    "ServerlessConfig": {"MemorySizeInMB": 2048},
                },
                {"VariantName": "inst", "InitialInstanceCount": 1},
            ]
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) == 1
        assert findings[0]["Status"] == "Failed"
        assert "inst" in findings[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_sm12_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_endpoint_instance_count
        mock_client.side_effect = Exception("SageMaker error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("sagemaker_app.boto3.client")
    def test_sm12_endpoint_config_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_endpoint_instance_count
        mock_client.side_effect = Exception("Endpoint error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")


# ===================================================================
# SM-13: check_sagemaker_monitoring_network_isolation
# ===================================================================
class TestSM13MonitoringNetworkIsolation:
    """SM-13: Check monitoring schedule network isolation."""

    @patch("sagemaker_app.boto3.client")
    def test_sm13_no_schedules_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_monitoring_network_isolation
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"MonitoringScheduleSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-13"

    @patch("sagemaker_app.boto3.client")
    def test_sm13_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_monitoring_network_isolation
        mock_client.side_effect = Exception("Monitoring error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("sagemaker_app.boto3.client")
    def test_sm13_inline_definition_with_isolation_passes(self, mock_client):
        """Inline MonitoringJobDefinition (unchanged behavior)."""
        check = sagemaker_app.check_sagemaker_monitoring_network_isolation
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {
                "MonitoringScheduleSummaries": [
                    {"MonitoringScheduleName": "sched-inline"}
                ]
            }
        ]
        mock_sm.describe_monitoring_schedule.return_value = {
            "MonitoringScheduleConfig": {
                "MonitoringJobDefinition": {
                    "NetworkConfig": {"EnableNetworkIsolation": True}
                }
            }
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm13_named_definition_resolves_isolation_enabled(self, mock_client):
        """Regression test (gap-analysis PR-0): a named monitoring job
        definition (MonitoringJobDefinitionName + MonitoringType) must be
        resolved via the matching DescribeXJobDefinition API rather than
        defaulting isolation to disabled because the inline field is absent."""
        check = sagemaker_app.check_sagemaker_monitoring_network_isolation
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"MonitoringScheduleSummaries": [{"MonitoringScheduleName": "sched-named"}]}
        ]
        mock_sm.describe_monitoring_schedule.return_value = {
            "MonitoringScheduleConfig": {
                "MonitoringJobDefinitionName": "my-data-quality-job-def",
                "MonitoringType": "DataQuality",
            }
        }
        mock_sm.describe_data_quality_job_definition.return_value = {
            "NetworkConfig": {"EnableNetworkIsolation": True}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        mock_sm.describe_data_quality_job_definition.assert_called_once_with(
            JobDefinitionName="my-data-quality-job-def"
        )

    @patch("sagemaker_app.boto3.client")
    def test_sm13_named_definition_resolves_isolation_disabled(self, mock_client):
        """Named definition that genuinely lacks isolation still fails."""
        check = sagemaker_app.check_sagemaker_monitoring_network_isolation
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {
                "MonitoringScheduleSummaries": [
                    {"MonitoringScheduleName": "sched-named-fail"}
                ]
            }
        ]
        mock_sm.describe_monitoring_schedule.return_value = {
            "MonitoringScheduleConfig": {
                "MonitoringJobDefinitionName": "my-model-quality-job-def",
                "MonitoringType": "ModelQuality",
            }
        }
        mock_sm.describe_model_quality_job_definition.return_value = {
            "NetworkConfig": {"EnableNetworkIsolation": False}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"


# ===================================================================
# SM-14: check_sagemaker_model_container_repository
# ===================================================================
class TestSM14ContainerRepository:
    """SM-14: Check model container repository access."""

    @patch("sagemaker_app.boto3.client")
    def test_sm14_no_models_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_container_repository
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"Models": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-14"

    @staticmethod
    def _mock_models(mock_client, describe_return):
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"Models": [{"ModelName": "m-1"}]}]
        mock_sm.describe_model.return_value = describe_return
        return mock_sm

    @patch("sagemaker_app.boto3.client")
    def test_sm14_primary_container_vpc_mode_passes(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_container_repository
        self._mock_models(
            mock_client,
            {
                "PrimaryContainer": {
                    "Image": "img",
                    "ImageConfig": {"RepositoryAccessMode": "Vpc"},
                }
            },
        )
        findings = extract_csv_data(check())
        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm14_primary_container_platform_mode_fails(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_container_repository
        self._mock_models(
            mock_client,
            {"PrimaryContainer": {"Image": "img"}},  # no ImageConfig -> Platform
        )
        findings = extract_csv_data(check())
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm14_multicontainer_all_vpc_passes(self, mock_client):
        """Regression guard for the phantom-primary-container bug: an
        inference-pipeline model (Containers[], no PrimaryContainer) whose
        containers all use Vpc mode must PASS. Previously the absent
        PrimaryContainer defaulted to Platform and false-failed every
        multi-container model (Security Hub SageMaker.19 scope)."""
        check = sagemaker_app.check_sagemaker_model_container_repository
        self._mock_models(
            mock_client,
            {
                "Containers": [
                    {
                        "ContainerHostname": "c1",
                        "ImageConfig": {"RepositoryAccessMode": "Vpc"},
                    },
                    {
                        "ContainerHostname": "c2",
                        "ImageConfig": {"RepositoryAccessMode": "Vpc"},
                    },
                ]
            },
        )
        findings = extract_csv_data(check())
        assert len(findings) == 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm14_multicontainer_platform_container_fails(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_container_repository
        self._mock_models(
            mock_client,
            {
                "Containers": [
                    {
                        "ContainerHostname": "c1",
                        "ImageConfig": {"RepositoryAccessMode": "Vpc"},
                    },
                    {"ContainerHostname": "c2"},  # no ImageConfig -> Platform
                ]
            },
        )
        findings = extract_csv_data(check())
        assert findings[0]["Status"] == "Failed"
        assert "c2" in findings[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_sm14_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_container_repository
        mock_client.side_effect = Exception("Container error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")


# ===================================================================
# SM-15: check_sagemaker_feature_store_encryption
# ===================================================================
class TestSM15FeatureStoreEncryption:
    """SM-15: Check Feature Store encryption."""

    @patch("sagemaker_app.boto3.client")
    def test_sm15_no_feature_groups_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_feature_store_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"FeatureGroupSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-15"

    @patch("sagemaker_app.boto3.client")
    def test_sm15_no_encryption_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_feature_store_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"FeatureGroupSummaries": [{"FeatureGroupName": "fg-1"}]}
        ]
        mock_sm.describe_feature_group.return_value = {
            "FeatureGroupName": "fg-1",
            "OfflineStoreConfig": {"S3StorageConfig": {"S3Uri": "s3://bucket"}},
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm15_with_kms_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_feature_store_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"FeatureGroupSummaries": [{"FeatureGroupName": "fg-1"}]}
        ]
        mock_sm.describe_feature_group.return_value = {
            "FeatureGroupName": "fg-1",
            "OfflineStoreConfig": {
                "S3StorageConfig": {
                    "S3Uri": "s3://bucket",
                    "KmsKeyId": "arn:aws:kms:us-east-1:123:key/abc",
                }
            },
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm15_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_feature_store_encryption
        mock_client.side_effect = Exception("Feature store error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")


# ===================================================================
# SM-16: check_sagemaker_data_quality_encryption
# ===================================================================
class TestSM16DataQualityEncryption:
    """SM-16: Check data quality job encryption."""

    @patch("sagemaker_app.boto3.client")
    def test_sm16_no_jobs_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_data_quality_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"JobDefinitionSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-16"

    @patch("sagemaker_app.boto3.client")
    def test_sm16_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_data_quality_encryption
        mock_client.side_effect = Exception("Data quality error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("sagemaker_app.boto3.client")
    def test_sm16_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_data_quality_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"JobDefinitionSummaries": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-17: check_sagemaker_processing_job_encryption
# ===================================================================
class TestSM17ProcessingJobEncryption:
    """SM-17: Check processing job volume encryption."""

    @patch("sagemaker_app.boto3.client")
    def test_sm17_no_jobs_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_processing_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"ProcessingJobSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-17"

    @patch("sagemaker_app.boto3.client")
    def test_sm17_no_encryption_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_processing_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"ProcessingJobSummaries": [{"ProcessingJobName": "pj-1"}]}
        ]
        mock_sm.describe_processing_job.return_value = {
            "ProcessingJobName": "pj-1",
            "ProcessingResources": {
                "ClusterConfig": {"InstanceCount": 1, "InstanceType": "ml.m5.large"}
            },
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm17_with_encryption_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_processing_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"ProcessingJobSummaries": [{"ProcessingJobName": "pj-1"}]}
        ]
        mock_sm.describe_processing_job.return_value = {
            "ProcessingJobName": "pj-1",
            "ProcessingResources": {
                "ClusterConfig": {
                    "InstanceCount": 1,
                    "InstanceType": "ml.m5.large",
                    "VolumeKmsKeyId": "arn:aws:kms:us-east-1:123:key/abc",
                }
            },
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm17_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_processing_job_encryption
        mock_client.side_effect = Exception("Processing error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")


# ===================================================================
# SM-18: check_sagemaker_transform_job_encryption
# ===================================================================
class TestSM18TransformJobEncryption:
    """SM-18: Check transform job volume encryption."""

    @patch("sagemaker_app.boto3.client")
    def test_sm18_no_jobs_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_transform_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"TransformJobSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-18"

    @patch("sagemaker_app.boto3.client")
    def test_sm18_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_transform_job_encryption
        mock_client.side_effect = Exception("Transform error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("sagemaker_app.boto3.client")
    def test_sm18_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_transform_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"TransformJobSummaries": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-19: check_sagemaker_hyperparameter_tuning_encryption
# ===================================================================
class TestSM19HPTuningEncryption:
    """SM-19: Check hyperparameter tuning job encryption."""

    @patch("sagemaker_app.boto3.client")
    def test_sm19_no_jobs_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_hyperparameter_tuning_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"HyperParameterTuningJobSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-19"

    @patch("sagemaker_app.boto3.client")
    def test_sm19_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_hyperparameter_tuning_encryption
        mock_client.side_effect = Exception("HP tuning error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("sagemaker_app.boto3.client")
    def test_sm19_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_hyperparameter_tuning_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"HyperParameterTuningJobSummaries": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-20: check_sagemaker_compilation_job_encryption
# ===================================================================
class TestSM20CompilationJobEncryption:
    """SM-20: Check compilation job encryption."""

    @patch("sagemaker_app.boto3.client")
    def test_sm20_no_jobs_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_compilation_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"CompilationJobSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-20"

    @patch("sagemaker_app.boto3.client")
    def test_sm20_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_compilation_job_encryption
        mock_client.side_effect = Exception("Compilation error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("sagemaker_app.boto3.client")
    def test_sm20_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_compilation_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"CompilationJobSummaries": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-21: check_sagemaker_automl_network_isolation
# ===================================================================
class TestSM21AutoMLNetworkIsolation:
    """SM-21: Check AutoML network isolation."""

    @patch("sagemaker_app.boto3.client")
    def test_sm21_no_jobs_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_automl_network_isolation
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_auto_ml_jobs.return_value = {"AutoMLJobSummaries": []}
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-21"

    @patch("sagemaker_app.boto3.client")
    def test_sm21_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_automl_network_isolation
        mock_client.side_effect = Exception("AutoML error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("sagemaker_app.boto3.client")
    def test_sm21_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_automl_network_isolation
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_auto_ml_jobs.return_value = {"AutoMLJobSummaries": []}
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-22: check_model_approval_workflow
# ===================================================================
class TestSM22ModelApproval:
    """SM-22: Check model approval workflow."""

    @patch("sagemaker_app.boto3.client")
    def test_sm22_no_model_packages_returns_na(self, mock_client):
        check = sagemaker_app.check_model_approval_workflow
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_model_package_groups.return_value = {
            "ModelPackageGroupSummaryList": []
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-22"

    @patch("sagemaker_app.boto3.client")
    def test_sm22_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_model_approval_workflow
        mock_client.side_effect = Exception("Approval error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("sagemaker_app.boto3.client")
    def test_sm22_schema_valid(self, mock_client):
        check = sagemaker_app.check_model_approval_workflow
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_model_package_groups.return_value = {
            "ModelPackageGroupSummaryList": []
        }
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-23: check_model_drift_detection
# ===================================================================
class TestSM23DriftDetection:
    """SM-23: Check model drift detection."""

    @patch("sagemaker_app.boto3.client")
    def test_sm23_no_schedules_returns_na(self, mock_client):
        check = sagemaker_app.check_model_drift_detection
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_monitoring_schedules.return_value = {
            "MonitoringScheduleSummaries": []
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-23"

    @patch("sagemaker_app.boto3.client")
    def test_sm23_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_model_drift_detection
        mock_client.side_effect = Exception("Drift error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("sagemaker_app.boto3.client")
    def test_sm23_schema_valid(self, mock_client):
        check = sagemaker_app.check_model_drift_detection
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_monitoring_schedules.return_value = {
            "MonitoringScheduleSummaries": []
        }
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-24: check_ab_testing_shadow_deployment
# ===================================================================
class TestSM24ABTesting:
    """SM-24: Check A/B testing and shadow deployment."""

    @patch("sagemaker_app.boto3.client")
    def test_sm24_no_endpoints_returns_na(self, mock_client):
        check = sagemaker_app.check_ab_testing_shadow_deployment
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"Endpoints": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-24"

    @patch("sagemaker_app.boto3.client")
    def test_sm24_single_variant_returns_failed(self, mock_client):
        check = sagemaker_app.check_ab_testing_shadow_deployment
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"Endpoints": [{"EndpointName": "ep-1", "EndpointConfigName": "ec-1"}]}
        ]
        mock_sm.describe_endpoint.return_value = {
            "EndpointName": "ep-1",
            "ProductionVariants": [{"VariantName": "v1"}],
        }
        mock_sm.describe_endpoint_config.return_value = {
            "ProductionVariants": [{"VariantName": "v1"}],
            "ShadowProductionVariants": [],
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        # Single variant without shadow should be flagged

    @patch("sagemaker_app.boto3.client")
    def test_sm24_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_ab_testing_shadow_deployment
        mock_client.side_effect = Exception("AB testing error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("sagemaker_app.boto3.client")
    def test_sm24_schema_valid(self, mock_client):
        check = sagemaker_app.check_ab_testing_shadow_deployment
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"Endpoints": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-25: check_ml_lineage_tracking
# ===================================================================
class TestSM25LineageTracking:
    """SM-25: Check ML lineage tracking."""

    @patch("sagemaker_app.boto3.client")
    def test_sm25_no_experiments_returns_na(self, mock_client):
        check = sagemaker_app.check_ml_lineage_tracking
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_experiments.return_value = {"ExperimentSummaries": []}
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"ModelPackageGroupSummaryList": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-25"
        assert findings[0]["Status"] == "N/A"

    @patch("sagemaker_app.boto3.client")
    def test_sm25_experiments_with_trials_returns_passed(self, mock_client):
        check = sagemaker_app.check_ml_lineage_tracking
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_experiments.return_value = {
            "ExperimentSummaries": [{"ExperimentName": "exp-1"}]
        }
        mock_sm.list_trials.return_value = {
            "TrialSummaries": [{"TrialName": "trial-1"}]
        }
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"ModelPackageGroupSummaryList": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm25_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_ml_lineage_tracking
        mock_client.side_effect = Exception("Lineage error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")

    @patch("sagemaker_app.boto3.client")
    def test_sm25_schema_valid(self, mock_client):
        check = sagemaker_app.check_ml_lineage_tracking
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_experiments.return_value = {"ExperimentSummaries": []}
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"ModelPackageGroupSummaryList": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# lambda_handler: multi-region gating and availability probe
# ===================================================================
def _make_client_error(code, message="error"):
    return ClientError({"Error": {"Code": code, "Message": message}}, "operation")


def _sagemaker_event(region="us-east-1", region_index=0):
    return {
        "Region": region,
        "RegionIndex": region_index,
        "Execution": {"Name": "test-execution-1"},
        "StateMachine": {"Name": "test-sm"},
    }


class TestSageMakerHandlerMultiRegion:
    """lambda_handler primary-region gating (SM-02) + availability probe (SM-00)."""

    def _run_handler_unavailable(self, mock_client, event):
        """Drive the handler down the 'SageMaker unavailable' early-return path.
        The availability probe raises EndpointConnectionError so no regional
        checks run; only global IAM checks (if primary) plus SM-00 are emitted."""
        captured = {}

        def fake_csv(findings):
            captured["findings"] = findings
            return "csv"

        test_client = MagicMock()
        test_client.list_notebook_instances.side_effect = EndpointConnectionError(
            endpoint_url="https://sagemaker.invalid"
        )
        mock_client.return_value = test_client

        with (
            patch.object(
                sagemaker_app,
                "get_permissions_cache",
                return_value={"role_permissions": {}, "user_permissions": {}},
            ),
            patch.object(sagemaker_app, "generate_csv_report", side_effect=fake_csv),
            patch.object(sagemaker_app, "write_to_s3", return_value="s3://b/r.csv"),
        ):
            resp = sagemaker_app.lambda_handler(event, None)

        return resp, captured.get("findings", [])

    @patch("sagemaker_app.boto3.client")
    def test_primary_region_emits_global_iam_check_tagged_global(self, mock_client):
        # On the primary region, the IAM-global SM-02 check must be emitted and
        # tagged "Global", even when SageMaker is unavailable in the region.
        resp, findings = self._run_handler_unavailable(
            mock_client, _sagemaker_event(region="ap-south-2", region_index=0)
        )
        assert resp["statusCode"] == 200

        rows = [r for f in findings for r in f.get("csv_data", [])]
        sm02 = [r for r in rows if r["Check_ID"] == "SM-02"]
        assert sm02, "SM-02 IAM-global finding should be present on primary region"
        for r in sm02:
            assert r["Region"] == "Global"
        # The availability finding is tagged with the scanned region.
        sm00 = [r for r in rows if r["Check_ID"] == "SM-00"]
        assert sm00 and sm00[0]["Region"] == "ap-south-2"

    @patch("sagemaker_app.boto3.client")
    def test_non_primary_region_skips_global_iam_check(self, mock_client):
        # On a non-primary region the IAM-global SM-02 check must NOT run.
        resp, findings = self._run_handler_unavailable(
            mock_client, _sagemaker_event(region="eu-west-1", region_index=2)
        )
        assert resp["statusCode"] == 200

        rows = [r for f in findings for r in f.get("csv_data", [])]
        check_ids = {r["Check_ID"] for r in rows}
        assert "SM-02" not in check_ids
        assert check_ids == {"SM-00"}

    @patch("sagemaker_app.boto3.client")
    def test_optin_region_error_treated_as_unavailable(self, mock_client):
        # A region-not-enabled error code is treated like an endpoint failure:
        # emit a single SM-00 N/A finding (no regional checks).
        captured = {}

        def fake_csv(findings):
            captured["findings"] = findings
            return "csv"

        test_client = MagicMock()
        test_client.list_notebook_instances.side_effect = _make_client_error(
            "OptInRequired"
        )
        mock_client.return_value = test_client

        with (
            patch.object(
                sagemaker_app,
                "get_permissions_cache",
                return_value={"role_permissions": {}, "user_permissions": {}},
            ),
            patch.object(sagemaker_app, "generate_csv_report", side_effect=fake_csv),
            patch.object(sagemaker_app, "write_to_s3", return_value="s3://b/r.csv"),
        ):
            resp = sagemaker_app.lambda_handler(
                _sagemaker_event(region="ap-east-1", region_index=1), None
            )

        assert resp["statusCode"] == 200
        rows = [r for f in captured["findings"] for r in f.get("csv_data", [])]
        sm00 = [r for r in rows if r["Check_ID"] == "SM-00"]
        assert sm00 and sm00[0]["Status"] == "N/A"
        assert "ap-east-1" in sm00[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_access_denied_probe_proceeds_with_checks(self, mock_client):
        # AccessDenied is NOT in REGION_UNAVAILABLE_ERROR_CODES: the service is
        # reachable, so the handler must proceed and run regional checks rather
        # than short-circuiting with SM-00.
        captured = {}

        def fake_csv(findings):
            captured["findings"] = findings
            return "csv"

        test_client = MagicMock()
        test_client.list_notebook_instances.side_effect = _make_client_error(
            "AccessDeniedException"
        )
        mock_client.return_value = test_client

        with (
            patch.object(
                sagemaker_app,
                "get_permissions_cache",
                return_value={"role_permissions": {}, "user_permissions": {}},
            ),
            patch.object(sagemaker_app, "generate_csv_report", side_effect=fake_csv),
            patch.object(sagemaker_app, "write_to_s3", return_value="s3://b/r.csv"),
        ):
            resp = sagemaker_app.lambda_handler(
                _sagemaker_event(region="us-east-1", region_index=0), None
            )

        assert resp["statusCode"] == 200
        rows = [r for f in captured["findings"] for r in f.get("csv_data", [])]
        check_ids = {r["Check_ID"] for r in rows}
        # Reachable => no SM-00, and many regional checks ran.
        assert "SM-00" not in check_ids
        assert len(check_ids) > 3


# ===================================================================
# SM-28: check_sagemaker_notebook_platform (SageMaker.8)
# ===================================================================
class TestSM28NotebookPlatform:
    """SM-28: Check SageMaker notebook platform identifier."""

    @patch("sagemaker_app.boto3.client")
    def test_sm28_no_notebooks_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_platform
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"NotebookInstances": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-28"
        assert findings[0]["Status"] == "N/A"

    @patch("sagemaker_app.boto3.client")
    def test_sm28_unsupported_platform_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_platform
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": "nb-1"}]}
        ]
        mock_sm.describe_notebook_instance.return_value = {
            "PlatformIdentifier": "notebook-al1-v1"
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"

    @patch("sagemaker_app.boto3.client")
    def test_sm28_supported_platform_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_platform
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": "nb-1"}]}
        ]
        mock_sm.describe_notebook_instance.return_value = {
            "PlatformIdentifier": "notebook-al2-v3"
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm28_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_platform
        mock_client.side_effect = Exception("SageMaker error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Severity"] == "Low"
        assert findings[0]["Finding"].startswith("COULD NOT ASSESS")


# ===================================================================
# Job-definition-based controls (SageMaker.10/.11/.12/.13/.15/.20/.25)
# ===================================================================
def _mock_job_definition_client(mock_client, list_key, job_name, describe_method):
    mock_sm = MagicMock()
    mock_client.return_value = mock_sm
    paginator = MagicMock()
    mock_sm.get_paginator.return_value = paginator
    paginator.paginate.return_value = [
        {"JobDefinitionSummaries": [{"MonitoringJobDefinitionName": job_name}]}
    ]
    return mock_sm


class TestSM29ExplainabilityTrafficEncryption:
    """SM-29: Model explainability job traffic encryption (SageMaker.10)."""

    @patch("sagemaker_app.boto3.client")
    def test_sm29_no_jobs_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_explainability_traffic_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"JobDefinitionSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-29"
        assert findings[0]["Status"] == "N/A"

    @patch("sagemaker_app.boto3.client")
    def test_sm29_encryption_disabled_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_explainability_traffic_encryption
        mock_sm = _mock_job_definition_client(
            mock_client, "JobDefinitionSummaries", "job-1", None
        )
        mock_sm.describe_model_explainability_job_definition.return_value = {
            "NetworkConfig": {"EnableInterContainerTrafficEncryption": False}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"

    @patch("sagemaker_app.boto3.client")
    def test_sm29_encryption_enabled_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_explainability_traffic_encryption
        mock_sm = _mock_job_definition_client(
            mock_client, "JobDefinitionSummaries", "job-1", None
        )
        mock_sm.describe_model_explainability_job_definition.return_value = {
            "NetworkConfig": {"EnableInterContainerTrafficEncryption": True}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"


class TestSM30DataQualityNetworkIsolation:
    """SM-30: Data quality job network isolation (SageMaker.11)."""

    @patch("sagemaker_app.boto3.client")
    def test_sm30_isolation_disabled_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_data_quality_network_isolation
        mock_sm = _mock_job_definition_client(
            mock_client, "JobDefinitionSummaries", "job-1", None
        )
        mock_sm.describe_data_quality_job_definition.return_value = {
            "NetworkConfig": {"EnableNetworkIsolation": False}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-30"
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"

    @patch("sagemaker_app.boto3.client")
    def test_sm30_isolation_enabled_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_data_quality_network_isolation
        mock_sm = _mock_job_definition_client(
            mock_client, "JobDefinitionSummaries", "job-1", None
        )
        mock_sm.describe_data_quality_job_definition.return_value = {
            "NetworkConfig": {"EnableNetworkIsolation": True}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm30_no_jobs_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_data_quality_network_isolation
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"JobDefinitionSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"


class TestSM31ModelBiasNetworkIsolation:
    """SM-31: Model bias job network isolation (SageMaker.12)."""

    @patch("sagemaker_app.boto3.client")
    def test_sm31_isolation_disabled_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_bias_network_isolation
        mock_sm = _mock_job_definition_client(
            mock_client, "JobDefinitionSummaries", "job-1", None
        )
        mock_sm.describe_model_bias_job_definition.return_value = {
            "NetworkConfig": {"EnableNetworkIsolation": False}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-31"
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm31_isolation_enabled_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_bias_network_isolation
        mock_sm = _mock_job_definition_client(
            mock_client, "JobDefinitionSummaries", "job-1", None
        )
        mock_sm.describe_model_bias_job_definition.return_value = {
            "NetworkConfig": {"EnableNetworkIsolation": True}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"


class TestSM32ModelQualityTrafficEncryption:
    """SM-32: Model quality job traffic encryption (SageMaker.13)."""

    @patch("sagemaker_app.boto3.client")
    def test_sm32_encryption_disabled_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_quality_traffic_encryption
        mock_sm = _mock_job_definition_client(
            mock_client, "JobDefinitionSummaries", "job-1", None
        )
        mock_sm.describe_model_quality_job_definition.return_value = {
            "NetworkConfig": {"EnableInterContainerTrafficEncryption": False}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-32"
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm32_encryption_enabled_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_quality_traffic_encryption
        mock_sm = _mock_job_definition_client(
            mock_client, "JobDefinitionSummaries", "job-1", None
        )
        mock_sm.describe_model_quality_job_definition.return_value = {
            "NetworkConfig": {"EnableInterContainerTrafficEncryption": True}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"


class TestSM33ModelBiasTrafficEncryption:
    """SM-33: Model bias job traffic encryption (SageMaker.15) — only fails
    when instance count >= 2."""

    @patch("sagemaker_app.boto3.client")
    def test_sm33_multi_instance_no_encryption_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_bias_traffic_encryption
        mock_sm = _mock_job_definition_client(
            mock_client, "JobDefinitionSummaries", "job-1", None
        )
        mock_sm.describe_model_bias_job_definition.return_value = {
            "NetworkConfig": {"EnableInterContainerTrafficEncryption": False},
            "JobResources": {"ClusterConfig": {"InstanceCount": 2}},
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-33"
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm33_single_instance_no_encryption_returns_passed(self, mock_client):
        """Single-instance jobs have no inter-container traffic to encrypt,
        so the control does not fail even without encryption enabled."""
        check = sagemaker_app.check_sagemaker_model_bias_traffic_encryption
        mock_sm = _mock_job_definition_client(
            mock_client, "JobDefinitionSummaries", "job-1", None
        )
        mock_sm.describe_model_bias_job_definition.return_value = {
            "NetworkConfig": {"EnableInterContainerTrafficEncryption": False},
            "JobResources": {"ClusterConfig": {"InstanceCount": 1}},
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm33_multi_instance_with_encryption_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_bias_traffic_encryption
        mock_sm = _mock_job_definition_client(
            mock_client, "JobDefinitionSummaries", "job-1", None
        )
        mock_sm.describe_model_bias_job_definition.return_value = {
            "NetworkConfig": {"EnableInterContainerTrafficEncryption": True},
            "JobResources": {"ClusterConfig": {"InstanceCount": 3}},
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"


class TestSM34OnlineFeatureStoreEncryption:
    """SM-34: Online feature store encryption (SageMaker.18) — any KMS key
    satisfies the control."""

    @patch("sagemaker_app.boto3.client")
    def test_sm34_no_kms_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_online_feature_store_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"FeatureGroupSummaries": [{"FeatureGroupName": "fg-1"}]}
        ]
        mock_sm.describe_feature_group.return_value = {
            "OnlineStoreConfig": {
                "EnableOnlineStore": True,
                "StorageType": "Standard",
                "SecurityConfig": {},
            }
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-34"
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"

    @patch("sagemaker_app.boto3.client")
    def test_sm34_any_kms_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_online_feature_store_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"FeatureGroupSummaries": [{"FeatureGroupName": "fg-1"}]}
        ]
        mock_sm.describe_feature_group.return_value = {
            "OnlineStoreConfig": {
                "EnableOnlineStore": True,
                "StorageType": "Standard",
                "SecurityConfig": {"KmsKeyId": "alias/aws/sagemaker"},
            }
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm34_in_memory_storage_skipped(self, mock_client):
        """InMemory storage does not support this configuration and is out
        of scope for the control."""
        check = sagemaker_app.check_sagemaker_online_feature_store_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"FeatureGroupSummaries": [{"FeatureGroupName": "fg-1"}]}
        ]
        mock_sm.describe_feature_group.return_value = {
            "OnlineStoreConfig": {
                "EnableOnlineStore": True,
                "StorageType": "InMemory",
            }
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"

    @patch("sagemaker_app.boto3.client")
    def test_sm34_online_store_disabled_skipped(self, mock_client):
        check = sagemaker_app.check_sagemaker_online_feature_store_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"FeatureGroupSummaries": [{"FeatureGroupName": "fg-1"}]}
        ]
        mock_sm.describe_feature_group.return_value = {
            "OnlineStoreConfig": {"EnableOnlineStore": False}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"


class TestSM35ExplainabilityNetworkIsolation:
    """SM-35: Model explainability job network isolation (SageMaker.20,
    High severity register decision)."""

    @patch("sagemaker_app.boto3.client")
    def test_sm35_isolation_disabled_returns_failed_high(self, mock_client):
        check = sagemaker_app.check_sagemaker_explainability_network_isolation
        mock_sm = _mock_job_definition_client(
            mock_client, "JobDefinitionSummaries", "job-1", None
        )
        mock_sm.describe_model_explainability_job_definition.return_value = {
            "NetworkConfig": {"EnableNetworkIsolation": False}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-35"
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"

    @patch("sagemaker_app.boto3.client")
    def test_sm35_isolation_enabled_returns_passed_high(self, mock_client):
        check = sagemaker_app.check_sagemaker_explainability_network_isolation
        mock_sm = _mock_job_definition_client(
            mock_client, "JobDefinitionSummaries", "job-1", None
        )
        mock_sm.describe_model_explainability_job_definition.return_value = {
            "NetworkConfig": {"EnableNetworkIsolation": True}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Severity"] == "High"


class TestSM39ModelQualityNetworkIsolation:
    """SM-39: Model quality job network isolation (SageMaker.25, High
    severity register decision)."""

    @patch("sagemaker_app.boto3.client")
    def test_sm39_isolation_disabled_returns_failed_high(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_quality_network_isolation
        mock_sm = _mock_job_definition_client(
            mock_client, "JobDefinitionSummaries", "job-1", None
        )
        mock_sm.describe_model_quality_job_definition.return_value = {
            "NetworkConfig": {"EnableNetworkIsolation": False}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-39"
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"

    @patch("sagemaker_app.boto3.client")
    def test_sm39_isolation_enabled_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_quality_network_isolation
        mock_sm = _mock_job_definition_client(
            mock_client, "JobDefinitionSummaries", "job-1", None
        )
        mock_sm.describe_model_quality_job_definition.return_value = {
            "NetworkConfig": {"EnableNetworkIsolation": True}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"


class TestSM36MonitoringTrafficEncryption:
    """SM-36: Monitoring schedule traffic encryption (SageMaker.22), with
    named-definition resolution (same fix pattern as SM-13)."""

    @patch("sagemaker_app.boto3.client")
    def test_sm36_no_schedules_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_monitoring_traffic_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"MonitoringScheduleSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-36"
        assert findings[0]["Status"] == "N/A"

    @patch("sagemaker_app.boto3.client")
    def test_sm36_inline_definition_encrypted_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_monitoring_traffic_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"MonitoringScheduleSummaries": [{"MonitoringScheduleName": "sched-1"}]}
        ]
        mock_sm.describe_monitoring_schedule.return_value = {
            "MonitoringScheduleConfig": {
                "MonitoringJobDefinition": {
                    "NetworkConfig": {"EnableInterContainerTrafficEncryption": True}
                }
            }
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm36_named_definition_resolves_encryption(self, mock_client):
        """Regression test: named monitoring job definitions must be resolved
        via the matching DescribeXJobDefinition API (shared helper with
        SM-13), not defaulted to disabled."""
        check = sagemaker_app.check_sagemaker_monitoring_traffic_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"MonitoringScheduleSummaries": [{"MonitoringScheduleName": "sched-named"}]}
        ]
        mock_sm.describe_monitoring_schedule.return_value = {
            "MonitoringScheduleConfig": {
                "MonitoringJobDefinitionName": "my-model-quality-job-def",
                "MonitoringType": "ModelQuality",
            }
        }
        mock_sm.describe_model_quality_job_definition.return_value = {
            "NetworkConfig": {"EnableInterContainerTrafficEncryption": True}
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        mock_sm.describe_model_quality_job_definition.assert_called_once_with(
            JobDefinitionName="my-model-quality-job-def"
        )

    @patch("sagemaker_app.boto3.client")
    def test_sm36_encryption_disabled_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_monitoring_traffic_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"MonitoringScheduleSummaries": [{"MonitoringScheduleName": "sched-fail"}]}
        ]
        mock_sm.describe_monitoring_schedule.return_value = {
            "MonitoringScheduleConfig": {
                "MonitoringJobDefinition": {
                    "NetworkConfig": {"EnableInterContainerTrafficEncryption": False}
                }
            }
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "Medium"


class TestSM37And38InferenceExperimentEncryption:
    """SM-37 (SageMaker.23, instance storage) and SM-38 (SageMaker.24, data
    storage) inference experiment encryption checks."""

    @patch("sagemaker_app.boto3.client")
    def test_no_experiments_returns_na_both(self, mock_client):
        check = sagemaker_app.check_sagemaker_inference_experiment_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"InferenceExperiments": []}]
        result = check()
        findings = extract_csv_data(result)
        check_ids = {f["Check_ID"] for f in findings}
        assert check_ids == {"SM-37", "SM-38"}
        for f in findings:
            assert f["Status"] == "N/A"

    @patch("sagemaker_app.boto3.client")
    def test_instance_storage_without_kms_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_inference_experiment_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"InferenceExperiments": [{"Name": "exp-1"}]}
        ]
        mock_sm.describe_inference_experiment.return_value = {}
        result = check()
        findings = extract_csv_data(result)
        sm37 = [f for f in findings if f["Check_ID"] == "SM-37"]
        sm38 = [f for f in findings if f["Check_ID"] == "SM-38"]
        assert sm37 and sm37[0]["Status"] == "Failed"
        # No DataStorageConfig means data capture is not enabled; SM-38 is N/A.
        assert sm38 and sm38[0]["Status"] == "N/A"

    @patch("sagemaker_app.boto3.client")
    def test_instance_storage_with_kms_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_inference_experiment_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"InferenceExperiments": [{"Name": "exp-1"}]}
        ]
        mock_sm.describe_inference_experiment.return_value = {
            "KmsKey": "arn:aws:kms:us-east-1:123456789012:key/abcd"
        }
        result = check()
        findings = extract_csv_data(result)
        sm37 = [f for f in findings if f["Check_ID"] == "SM-37"]
        assert sm37 and sm37[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_data_capture_without_kms_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_inference_experiment_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"InferenceExperiments": [{"Name": "exp-1"}]}
        ]
        mock_sm.describe_inference_experiment.return_value = {
            "KmsKey": "arn:aws:kms:us-east-1:123456789012:key/abcd",
            "DataStorageConfig": {"Destination": "s3://bucket/prefix"},
        }
        result = check()
        findings = extract_csv_data(result)
        sm38 = [f for f in findings if f["Check_ID"] == "SM-38"]
        assert sm38 and sm38[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_data_capture_with_kms_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_inference_experiment_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"InferenceExperiments": [{"Name": "exp-1"}]}
        ]
        mock_sm.describe_inference_experiment.return_value = {
            "KmsKey": "arn:aws:kms:us-east-1:123456789012:key/abcd",
            "DataStorageConfig": {
                "Destination": "s3://bucket/prefix",
                "KmsKey": "arn:aws:kms:us-east-1:123456789012:key/data-key",
            },
        }
        result = check()
        findings = extract_csv_data(result)
        sm38 = [f for f in findings if f["Check_ID"] == "SM-38"]
        assert sm38 and sm38[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_exception_returns_error_findings_both(self, mock_client):
        check = sagemaker_app.check_sagemaker_inference_experiment_encryption
        mock_client.side_effect = Exception("SageMaker error")
        result = check()
        findings = extract_csv_data(result)
        check_ids = {f["Check_ID"] for f in findings}
        assert check_ids == {"SM-37", "SM-38"}
        for f in findings:
            assert f["Status"] == "N/A"
            assert f["Severity"] == "Low"
            assert f["Finding"].startswith("COULD NOT ASSESS")
