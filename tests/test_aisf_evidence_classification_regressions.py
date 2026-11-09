"""Keep inspected configuration findings distinct from collection failures."""

import ast
import importlib.util

import pytest

from tests.test_aisf_catalog_alignment import (
    ACCOUNT,
    EXECUTION,
    ROOT,
    aisf_results,
    observation,
    register,
)
from tests.test_aisf_comprehensive_mapping import (
    assert_downloaded_check,
    downloaded_exports,
    report_pair,
)

SECURITY = ROOT / "aiml-security-assessment/functions/security"
REGION = "us-east-1"


def producer_finding(package, function, check_id, status, finding_name, values):
    """Evaluate the producer's finding expression with synthetic collected data."""
    path = SECURITY / package / "app.py"
    tree = ast.parse(path.read_text())
    source_function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == function
    )
    calls = []
    for node in ast.walk(source_function):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "create_finding"
        ):
            continue
        kwargs = {keyword.arg: keyword.value for keyword in node.keywords}
        if (
            isinstance(kwargs["check_id"], ast.Constant)
            and kwargs["check_id"].value == check_id
            and isinstance(kwargs["status"], ast.Constant)
            and kwargs["status"].value == status
            and isinstance(kwargs["finding_name"], (ast.Name, ast.Constant))
            and (
                kwargs["finding_name"].id
                if isinstance(kwargs["finding_name"], ast.Name)
                else kwargs["finding_name"].value
            )
            == finding_name
        ):
            calls.append(node)
    assert len(calls) == 1, (package, function, check_id, finding_name)
    spec = importlib.util.spec_from_file_location(
        f"aisf_regression_{package}_schema", SECURITY / package / "schema.py"
    )
    schema = importlib.util.module_from_spec(spec)
    with pytest.MonkeyPatch.context() as patch:
        patch.syspath_prepend(str(path.parent))
        spec.loader.exec_module(schema)
    row = eval(
        compile(ast.Expression(calls[0]), str(path), "eval"),
        {"create_finding": schema.create_finding, "region": REGION, **values},
    )
    return {
        **{key: getattr(value, "value", value) for key, value in row.items()},
        "Region": REGION,
        "Account_ID": ACCOUNT,
        "Execution_ID": EXECUTION,
    }


@pytest.fixture(scope="module")
def inspected_source_rows():
    return [
        producer_finding(
            "bedrock_assessments",
            "_bedrock_data_event_findings",
            "BR-06",
            "Failed",
            "INFERENCE_FORENSIC_RECORD_FINDING",
            {
                "INFERENCE_FORENSIC_RECORD_FINDING": "Bedrock Inference Forensic Record",
                "record": {
                    "gaps": [
                        "model invocation logging is off, so no prompt or response is recorded"
                    ],
                    "unread": [],
                },
            },
        ),
        producer_finding(
            "sagemaker_assessments",
            "_propagation_and_plaintext_findings",
            "SM-40",
            "Passed",
            "SECRET_PROPAGATION_FINDING",
            {
                "SECRET_PROPAGATION_FINDING": "Rotated Secret Propagation",
                "SECRET_PROPAGATION_REFERENCE": "https://docs.aws.amazon.com/lambda/latest/dg/",
                "extension_users": 0,
                "functions": [],
                "microvm_versions": [{"version": "1"}],
                "resume_budgets": [],
            },
        ),
        producer_finding(
            "responsible_ai_grc_assessments",
            "check_cloudwatch_log_pii_masking",
            "FS-43",
            "N/A",
            "Bedrock Invocation Logging Not Enabled",
            {
                "COMPLIANCE_MAP": {"FS-43": ""},
                "reference": "https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html",
            },
        ),
    ]


def project(rows):
    return aisf_results.build_aisf_check_results(
        register(
            rows,
            regions=[REGION],
            enable_grc=True,
            enable_owasp=True,
            enable_aisf=True,
        )
    )


@pytest.fixture(scope="module")
def schema_read_failure():
    path = SECURITY / "agentcore_assessments/app.py"
    tree = ast.parse(path.read_text())
    helper = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_s3_schema_unread"
    )
    disabled = next(
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name)
            and target.id == "ARTIFACT_OBJECT_READS_DISABLED"
            for target in node.targets
        )
    )
    namespace = {}
    exec(
        compile(
            ast.Module(body=[helper, disabled], type_ignores=[]), str(path), "exec"
        ),
        namespace,
    )
    return namespace["_s3_schema_unread"], namespace["ARTIFACT_OBJECT_READS_DISABLED"]


@pytest.mark.parametrize("status", ["N/A", "Failed"])
@pytest.mark.parametrize(
    ("check_id", "label", "reason"),
    [
        (
            "AC-34",
            "schema at targetConfiguration.mcp.lambda.toolSchema.s3",
            None,
        ),
        (
            "AC-35",
            "OpenAPI schema",
            "the object is 2097153 bytes, more than the 2097152 byte bound",
        ),
        ("AC-35", "tool schema", "it is not a JSON list of tool definitions"),
    ],
)
def test_unread_gateway_schema_remains_an_evidence_gap(
    schema_read_failure, check_id, label, reason, status
):
    unread, reads_disabled = schema_read_failure
    details = "A gateway target could not be fully judged: " + unread(
        label, ValueError(reads_disabled if reason is None else reason)
    )
    if status == "Failed":
        details = "An inline credential was observed in another target. " + details
    row = observation(
        check_id,
        status,
        Finding="AgentCore Gateway Target Inspection Incomplete",
        Finding_Details=details,
    )
    result = project([row])
    (check,) = result["checks"]
    assert check["status"] == status
    assert check["finding_details"] == details
    assert check["evidence_kind"] == "unavailable"
    assert check["result_kind"] == "unavailable"
    assert result["summary"]["source_results"] == 0
    assert result["summary"]["unavailable_results"] == 1
    assert result["summary"]["statuses"] == {status: 1}
    gaps = [gap for gap in result["gaps"] if gap["kind"] == "unavailable-observation"]
    assert len(gaps) == 1
    assert gaps[0]["source_check_id"] == check_id


@pytest.mark.parametrize(
    ("check_id", "status", "kind", "source_phrase"),
    [
        ("BR-06", "Failed", "failed predicate", "is incomplete:"),
        ("SM-40", "Passed", "passed predicate", "resumeTimeoutInSeconds"),
        ("FS-43", "N/A", "inconclusive", "unavailable for audit"),
    ],
)
def test_successful_inspection_is_not_an_evidence_gap(
    inspected_source_rows, check_id, status, kind, source_phrase
):
    original = next(row for row in inspected_source_rows if row["Check_ID"] == check_id)
    assert source_phrase in original["Finding_Details"]
    result = project([original])
    (check,) = result["checks"]
    assert check["evidence_kind"] == kind
    assert check["result_kind"] == "source-result"
    assert check["status"] == status
    assert check["finding_details"] == original["Finding_Details"]
    assert check["action_required"] == original["Resolution"]
    assert result["summary"]["source_results"] == 1
    assert result["summary"]["unavailable_results"] == 0
    assert result["summary"]["statuses"] == {status: 1}
    assert not any(gap["kind"] == "unavailable-observation" for gap in result["gaps"])
    assert not result["artifact_issues"]
    assert not result["rejected_observations"]


@pytest.mark.parametrize("partial_read", [False, True])
def test_incomplete_configuration_title_does_not_hide_real_deficiency(partial_read):
    details = (
        "Evaluation config synthetic-config attaches 1 evaluator and has no "
        "tool-choice evaluator; no CloudWatch alarm has actions on the scores."
    )
    if partial_read:
        details += " CloudWatch alarms could not be read (AccessDenied)."
    row = observation(
        "AC-40",
        "Failed",
        Finding="AgentCore Evaluation Safety Coverage Incomplete",
        Finding_Details=details,
        Resource_ID="synthetic-config",
    )
    result = project([row])
    (check,) = result["checks"]
    assert check["status"] == "Failed"
    assert check["finding_details"] == details
    assert check["evidence_kind"] == (
        "unavailable" if partial_read else "failed predicate"
    )
    assert check["result_kind"] == ("unavailable" if partial_read else "source-result")
    assert result["summary"]["unavailable_results"] == int(partial_read)
    assert len(
        [gap for gap in result["gaps"] if gap["kind"] == "unavailable-observation"]
    ) == int(partial_read)


@pytest.mark.parametrize(
    ("check_id", "status", "details"),
    [
        (
            "BR-20",
            "Failed",
            "AccessDenied after an observed failure; prior findings retained.",
        ),
        (
            "BR-20",
            "Passed",
            "A resource passed; discovery timed out before the next resource.",
        ),
        ("BR-20", "N/A", "Could not assess this check: AccessDeniedException."),
        ("BR-20", "N/A", "Unsupported region."),
        ("BR-20", "N/A", "Discovery unavailable."),
        ("BR-20", "N/A", "Pagination failed after page 2; prior findings retained."),
        ("BR-20", "N/A", "Discovery safety cap reached."),
        ("BR-20", "N/A", "Timeout during discovery."),
        ("BR-20", "N/A", "Runtime role is not in the IAM permissions cache."),
        (
            "AR-02",
            "N/A",
            "Assessment could not initialize the IAM client needed to query "
            "service-last-accessed data.",
        ),
        (
            "AR-02",
            "N/A",
            "Assessment could not determine the account ID needed to query IAM "
            "service-last-accessed data: RuntimeError.",
        ),
        (
            "AR-02",
            "N/A",
            "IAM could not generate service-last-accessed details for role "
            "'synthetic-role'.",
        ),
        (
            "AR-02",
            "N/A",
            "IAM service-last-accessed details for role 'synthetic-role' did not "
            "complete before the assessment deadline.",
        ),
        (
            "AR-02",
            "N/A",
            "Could not inspect service-last-accessed data for role "
            "'synthetic-role': RuntimeError.",
        ),
        (
            "AR-10",
            "N/A",
            "Assessment could not initialize the EventBridge client needed to "
            "read event rules.",
        ),
        (
            "AC-25",
            "N/A",
            "The IAM permission cache was not available, so the execution roles "
            "of 1 gateway(s) were not read.",
        ),
        (
            "SM-33",
            "N/A",
            "The VPC endpoints of the 1 VPC-attached training job(s) were not "
            "read (ec2:DescribeSubnets, ec2:DescribeVpcEndpoints, "
            "ec2:DescribeRouteTables: RuntimeError).",
        ),
        (
            "AC-45",
            "N/A",
            "Principals in the IAM permission cache can open a shell in the 1 "
            "runtime(s) in this region, and whether an alarm counts shell "
            "connections in this region was not read: RuntimeError.",
        ),
        (
            "AC-45",
            "N/A",
            "No IAM permissions found in cache, so who can open a command shell "
            "in an agent runtime session was not read.",
        ),
    ],
)
def test_collection_gaps_remain_open_and_keep_native_status(check_id, status, details):
    row = observation(check_id, status, Finding_Details=details)
    result = project([row])
    (check,) = result["checks"]
    assert check["status"] == status
    assert check["finding_details"] == details
    assert check["action_required"] == row["Resolution"]
    assert check["evidence_kind"] == "unavailable"
    assert check["result_kind"] == "unavailable"
    assert result["summary"]["source_results"] == 0
    assert result["summary"]["unavailable_results"] == 1
    assert result["summary"]["statuses"] == {status: 1}
    gaps = [gap for gap in result["gaps"] if gap["kind"] == "unavailable-observation"]
    assert len(gaps) == 1
    assert gaps[0]["source_check_id"] == check_id


@pytest.mark.parametrize("include_native", [False, True])
def test_agentic_alias_preserves_inspected_native_evidence(
    inspected_source_rows, include_native
):
    native = inspected_source_rows[0]
    alias = {
        **native,
        "Check_ID": "AG-08",
        "Finding": "Agentic AI Inference Traceability",
        "Finding_Details": f"Source check BR-06: {native['Finding_Details']}",
    }
    result = project(([native] if include_native else []) + [alias])
    (check,) = result["checks"]
    assert check["source_check_id"] == "BR-06"
    assert check["status"] == native["Status"]
    assert check["evidence_kind"] == "failed predicate"
    assert check["result_kind"] == "source-result"
    assert result["summary"]["source_results"] == 1
    assert result["summary"]["unavailable_results"] == 0
    assert not any(gap["kind"] == "unavailable-observation" for gap in result["gaps"])
    assert (
        any(gap["kind"] == "alias-only" for gap in result["gaps"]) is not include_native
    )


def test_both_report_modes_export_correct_native_results(
    tmp_path, inspected_source_rows
):
    originals = {row["Check_ID"]: row for row in inspected_source_rows}
    for account_count, html in enumerate(
        report_pair(tmp_path, inspected_source_rows, aisf=True), start=1
    ):
        exported = downloaded_exports(html)
        result = exported["json"]
        assert result["summary"]["check_results"] == 3 * account_count
        assert result["summary"]["source_results"] == 3 * account_count
        assert result["summary"]["unavailable_results"] == 0
        assert result["summary"]["statuses"] == {
            "Failed": account_count,
            "Passed": account_count,
            "N/A": account_count,
        }
        assert not any(
            gap["kind"] == "unavailable-observation" for gap in result["gaps"]
        )
        for check in result["checks"]:
            original = originals[check["source_check_id"]]
            assert check["status"] == original["Status"]
            assert check["finding_details"] == original["Finding_Details"]
            assert check["action_required"] == original["Resolution"]
            assert check["result_kind"] == "source-result"
            assert_downloaded_check(exported, check)
