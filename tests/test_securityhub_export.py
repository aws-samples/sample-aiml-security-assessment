"""ASFF contract, batching, and report-handler tests without AWS calls."""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.stub import Stubber

DIRECTORY = (
    Path(__file__).resolve().parents[1]
    / "aiml-security-assessment/functions/security/generate_consolidated_report"
)
sys.path.insert(0, str(DIRECTORY))
export_spec = importlib.util.spec_from_file_location(
    "securityhub_export", DIRECTORY / "securityhub_export.py"
)
exporter = importlib.util.module_from_spec(export_spec)
sys.modules["securityhub_export"] = exporter
export_spec.loader.exec_module(exporter)

spec = importlib.util.spec_from_file_location(
    "securityhub_report_app", DIRECTORY / "app.py"
)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)
EXECUTION = {
    "Name": "test-execution",
    "Id": "arn:aws:states:us-east-1:123456789012:execution:assessment:test-execution",
    "StartTime": "2026-01-01T00:00:00Z",
}


def row(**overrides):
    return {
        "Check_ID": "BR-01",
        "Finding": "Check IAM permissions",
        "Finding_Details": "An overly permissive role was found",
        "Resolution": "Reduce permissions",
        "Severity": "High",
        "Status": "Failed",
        "Region": "us-west-2",
        **overrides,
    }


def build(rows, **kwargs):
    return exporter.build_findings(
        {"bedrock": {"report": rows}},
        "123456789012",
        "us-east-1",
        "aws",
        EXECUTION,
        {},
        False,
        **kwargs,
    )


@pytest.mark.parametrize("label", exporter.SEVERITIES)
def test_severity_and_asff_shape(label):
    findings = build([row(Severity=label.title())])
    finding = findings[0]
    assert finding["FindingProviderFields"]["Severity"] == {"Label": label}
    assert finding["Compliance"] == {"Status": "FAILED"}
    assert (
        finding["ProductArn"]
        == "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default"
    )
    assert finding["GeneratorId"] == "aiml-security-assessment/BR-01"
    assert finding["Resources"] == [
        {
            "Type": "AwsAccount",
            "Id": "123456789012",
            "Partition": "aws",
            "Region": "us-west-2",
        }
    ]
    client = boto3.client("securityhub", region_name="us-east-1")
    with Stubber(client) as stubber:
        stubber.add_response(
            "batch_import_findings",
            {"FailedCount": 0, "SuccessCount": 1, "FailedFindings": []},
            {"Findings": findings},
        )
        client.batch_import_findings(Findings=findings)


@pytest.mark.parametrize(
    "status,compliance", [("Passed", "PASSED"), ("N/A", "NOT_AVAILABLE")]
)
def test_non_failures_are_informational_not_remediation_claims(status, compliance):
    finding = build([row(Status=status)])[0]
    assert finding["Compliance"]["Status"] == compliance
    assert finding["FindingProviderFields"]["Severity"]["Label"] == "INFORMATIONAL"
    assert "RecordState" not in finding
    assert "Workflow" not in finding


def test_check_summary_keeps_regions_separate_and_deduplicates_global_rows():
    findings = build(
        [
            row(),
            row(Finding_Details="Other role", Severity="Critical"),
            row(Region="Global"),
            row(Region="Global"),
        ]
    )
    assert len(findings) == 2
    regional = next(
        f for f in findings if f["ProductFields"]["AssessedRegion"] == "us-west-2"
    )
    assert regional["ProductFields"]["FailedObservationCount"] == "2"
    assert regional["FindingProviderFields"]["Severity"]["Label"] == "CRITICAL"
    global_finding = next(
        f for f in findings if f["ProductFields"]["AssessedRegion"] == "Global"
    )
    assert global_finding["ProductFields"]["ObservationCount"] == "1"
    assert global_finding["Resources"][0]["Region"] == "us-east-1"


def test_ids_are_retry_stable_but_new_assessments_are_distinct_snapshots():
    finding = build([row()])[0]
    assert finding == build([row(), row()])[0]
    execution = {**EXECUTION, "Id": EXECUTION["Id"] + "-next"}
    other = exporter.build_findings(
        {"bedrock": {"report": [row()]}},
        "123456789012",
        "us-east-1",
        "aws",
        execution,
        {},
        False,
    )[0]
    assert finding["Id"] != other["Id"]
    assert finding["UpdatedAt"] == EXECUTION["StartTime"]


def test_reordered_observations_keep_identical_snapshot():
    first, second = (
        row(),
        row(Finding="Another finding", Finding_Details="Another role"),
    )
    assert build([first, second]) == build([second, first])


def test_reused_execution_name_does_not_collide_with_old_snapshot():
    execution = {**EXECUTION, "StartTime": "2026-06-01T00:00:00Z"}
    other = exporter.build_findings(
        {"bedrock": {"report": [row()]}},
        "123456789012",
        "us-east-1",
        "aws",
        execution,
        {},
        False,
    )[0]
    assert build([row()])[0]["Id"] != other["Id"]


def test_mixed_inconclusive_and_passed_does_not_claim_compliance():
    finding = build([row(Status="Passed"), row(Status="N/A")])[0]
    assert finding["Compliance"]["Status"] == "NOT_AVAILABLE"


def test_missing_region_and_resolution_and_metadata_are_tolerated():
    finding = build([row(Region="", Resolution="")])[0]
    assert finding["Resources"][0]["Region"] == "us-east-1"
    assert "Remediation" not in finding
    assert (
        exporter.build_findings(
            {"account_id": "123456789012", "metadata": {"name": "test"}},
            "123456789012",
            "us-east-1",
            "aws",
            EXECUTION,
            {},
            False,
        )
        == []
    )


def test_unselected_services_and_hidden_grc_are_not_exported():
    results = {
        "bedrock": {"report": [row()]},
        "responsible-ai-grc": {"report": [row(Check_ID="FS-01")]},
    }
    assert (
        exporter.build_findings(
            results,
            "123456789012",
            "us-east-1",
            "aws",
            EXECUTION,
            {"bedrock": False},
            False,
        )
        == []
    )


def test_field_lengths_are_bounded():
    finding = build(
        [row(Finding="x" * 500, Finding_Details="x" * 3000, Resolution="x" * 1000)]
    )[0]
    assert len(finding["Title"]) == 256
    assert len(finding["Description"]) == 1024
    assert len(finding["Remediation"]["Recommendation"]["Text"]) == 512


@pytest.mark.parametrize(
    "override", [{"Status": "ERROR"}, {"Check_ID": ""}, {"Severity": "Bogus"}]
)
def test_invalid_observations_do_not_silently_export(override):
    with pytest.raises(ValueError):
        build([row(**override)])


def test_batches_of_at_most_100_and_uses_requested_region(monkeypatch):
    client = MagicMock()
    client.batch_import_findings.side_effect = [
        {"FailedCount": 0, "SuccessCount": count} for count in [100, 100, 1]
    ]
    factory = MagicMock(return_value=client)
    monkeypatch.setattr(exporter.boto3, "client", factory)
    assert exporter.export_findings([{}] * 201, "us-west-2") == 201
    assert [
        len(call.kwargs["Findings"])
        for call in client.batch_import_findings.call_args_list
    ] == [100, 100, 1]
    assert factory.call_args.kwargs["region_name"] == "us-west-2"


def test_empty_export_does_not_create_client(monkeypatch):
    factory = MagicMock()
    monkeypatch.setattr(exporter.boto3, "client", factory)
    assert exporter.export_findings([], "us-east-1") == 0
    factory.assert_not_called()


@pytest.mark.parametrize(
    "response",
    [
        {"FailedCount": 1, "SuccessCount": 0},
        {"FailedFindings": [{"ErrorCode": "InvalidAccess"}]},
        {"FailedCount": 0, "SuccessCount": 0},
    ],
)
def test_partial_failure_is_visible(monkeypatch, response):
    client = MagicMock()
    client.batch_import_findings.return_value = response
    monkeypatch.setattr(exporter.boto3, "client", lambda *args, **kwargs: client)
    with pytest.raises(RuntimeError, match="Security Hub export"):
        exporter.export_findings([{}], "us-east-1")


@pytest.mark.parametrize("enabled", [False, True])
def test_report_handler_gate_and_order(monkeypatch, enabled):
    monkeypatch.setenv("ENABLE_SECURITY_HUB_EXPORT", str(enabled).lower())
    client = MagicMock()
    client.get_caller_identity.return_value = {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:role/test",
    }
    monkeypatch.setattr(app.boto3, "client", lambda *args, **kwargs: client)
    monkeypatch.setattr(
        app, "get_assessment_results", lambda *args: {"bedrock": {"report": [row()]}}
    )
    monkeypatch.setattr(app, "validate_assessment_artifacts", lambda *args: None)
    monkeypatch.setattr(
        app, "generate_html_report", lambda *args, **kwargs: "<html></html>"
    )
    events = []
    monkeypatch.setattr(
        app, "write_html_to_s3", lambda *args: events.append("report") or "report.html"
    )
    monkeypatch.setattr(app, "export_findings", lambda *args: events.append("export"))
    assert (
        app.lambda_handler({"Execution": EXECUTION, "OriginalInput": {}}, None)[
            "statusCode"
        ]
        == 200
    )
    assert events == (["report", "export"] if enabled else ["report"])


def test_export_errors_propagate_after_report_is_saved(monkeypatch):
    monkeypatch.setenv("ENABLE_SECURITY_HUB_EXPORT", "true")
    client = MagicMock()
    client.get_caller_identity.return_value = {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:role/test",
    }
    monkeypatch.setattr(app.boto3, "client", lambda *args, **kwargs: client)
    monkeypatch.setattr(app, "get_assessment_results", lambda *args: {})
    monkeypatch.setattr(app, "validate_assessment_artifacts", lambda *args: None)
    monkeypatch.setattr(
        app, "generate_html_report", lambda *args, **kwargs: "<html></html>"
    )
    write = MagicMock(return_value="report.html")
    monkeypatch.setattr(app, "write_html_to_s3", write)
    monkeypatch.setattr(
        app,
        "export_findings",
        MagicMock(side_effect=RuntimeError("Security Hub export failed")),
    )
    with pytest.raises(RuntimeError, match="Security Hub export"):
        app.lambda_handler({"Execution": EXECUTION}, None)
    write.assert_called_once()
