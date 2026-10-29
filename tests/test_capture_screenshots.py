import importlib.util
import hashlib
from pathlib import Path
from unittest.mock import Mock

import pytest


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "sample-reports"
    / "scripts"
    / "capture_screenshots.py"
)
SPEC = importlib.util.spec_from_file_location("capture_screenshots", SCRIPT_PATH)
capture_screenshots = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture_screenshots)


def test_capture_all_screenshots_raises_when_clip_guard_fails(monkeypatch):
    clip_error = RuntimeError("Sidebar navigation remains clipped: Agentic AI")
    monkeypatch.setattr(
        capture_screenshots,
        "capture_screenshot",
        Mock(side_effect=clip_error),
    )

    with pytest.raises(RuntimeError, match="Failed to capture 1 screenshot"):
        capture_screenshots.capture_all_screenshots(
            Mock(),
            [
                {
                    "name": "agentcore-navigation",
                    "file": "report.html",
                    "description": "AgentCore navigation",
                    "actions": [],
                }
            ],
        )


def test_capture_all_screenshots_returns_successful_paths(monkeypatch, tmp_path):
    screenshot_path = tmp_path / "report.png"
    monkeypatch.setattr(
        capture_screenshots,
        "capture_screenshot",
        Mock(return_value=screenshot_path),
    )

    captured = capture_screenshots.capture_all_screenshots(
        Mock(),
        [
            {
                "name": "report",
                "file": "report.html",
                "description": "Report",
                "actions": [],
            }
        ],
    )

    assert captured == [screenshot_path]


def _report(details: str) -> str:
    row = (
        '<tr data-service="bedrock"><td><code>111122223333</code></td>'
        "<td><code>us-east-1</code></td><td><code>BR-34</code></td>"
        '<td><div class="col-domain">GuardDuty detector</div>'
        f"<div><strong>Details</strong><p>{details}</p></div>"
        "<div><strong>Resolution</strong><p>No action required</p></div>"
        '<span class="severity informational">Informational</span>'
        '<span class="status passed">Passed</span></td></tr>'
    )
    return (
        "<!DOCTYPE html>\n<html><style>.a{color:#1a2b3c}</style><body>"
        f'<table id="findingsTable"><tbody>{row}</tbody></table></body></html>\n'
    )


def test_anonymize_resource_ids_replaces_ids_consistently_and_once(tmp_path):
    detector = "1a2b3c4d5e6f70819a2b3c4d5e6f7081"
    first = tmp_path / "first.html"
    second = tmp_path / "second.html"
    first.write_text(
        _report(f"Detector {detector} in vpc-0a1b2c3d4e5f60718 (sg-1a2b3c4d)."),
        encoding="utf-8",
    )
    second.write_text(
        _report(f"Detector {detector}; finding .../detector/{detector}/finding."),
        encoding="utf-8",
    )

    replaced = capture_screenshots.anonymize_resource_ids([first, second])

    texts = [path.read_text(encoding="utf-8") for path in (first, second)]
    placeholder = "0" * 29 + "a1"
    assert replaced == {"32-digit hex ID": 3, "AWS resource ID": 2}
    assert all(detector not in text for text in texts)
    assert all(placeholder in text for text in texts)  # same value, same placeholder
    assert "vpc-000000000000000a1" in texts[0] and "sg-000000a2" in texts[0]
    assert all(".a{color:#1a2b3c}" in text for text in texts)  # page CSS kept
    assert all(capture_screenshots.ANONYMIZED_MARKER in text for text in texts)

    assert capture_screenshots.anonymize_resource_ids([first, second]) == {}
    assert [path.read_text(encoding="utf-8") for path in (first, second)] == texts


def test_a_report_anonymized_later_never_reuses_a_placeholder(tmp_path):
    first = tmp_path / "first.html"
    first.write_text(_report("In vpc-0a1b2c3d4e5f60718."), encoding="utf-8")
    capture_screenshots.anonymize_resource_ids([first])
    assert "vpc-000000000000000a1" in first.read_text(encoding="utf-8")

    # Regenerated from the anonymized report: it keeps that placeholder, and
    # a new value is numbered after it.
    later = tmp_path / "later.html"
    later.write_text(
        _report("In vpc-000000000000000a1 and vpc-0f1e2d3c4b5a69788."),
        encoding="utf-8",
    )
    replaced = capture_screenshots.anonymize_resource_ids([first, later])

    text = later.read_text(encoding="utf-8")
    assert replaced == {"AWS resource ID": 1}
    assert "vpc-000000000000000a1 and vpc-000000000000000a2" in text
    assert "vpc-0f1e2d3c4b5a69788" not in text


def test_resource_names_are_cleaned_in_previously_marked_reports(tmp_path):
    role = "ExampleProvisioningRole-DO-NOT-DELETE"
    trail = "ExampleProvisioningTrail-DO-NOT-DELETE"
    session = "ExampleOperator-Console"
    first = tmp_path / "first.html"
    second = tmp_path / "second.html"
    details = (
        f"role '{role}'; arn:aws:iam::111122223333:role/{role}; "
        f"arn:aws:cloudtrail:us-east-1:111122223333:trail/{trail}; "
        f"arn:aws:sts::111122223333:assumed-role/Admin/{session}; "
        "ssoins-0123456789abcdef; AWSReservedSSO_ExampleAccess_0123456789abcdef"
    )
    for path in (first, second):
        path.write_text(
            _report(details).replace(
                "<!DOCTYPE html>\n",
                f"<!DOCTYPE html>\n{capture_screenshots.ANONYMIZED_MARKER}\n",
            ),
            encoding="utf-8",
        )

    assert capture_screenshots.anonymize_resource_names([first, second])
    contents = [path.read_text(encoding="utf-8") for path in (first, second)]
    assert contents[0] == contents[1]
    assert all(name not in contents[0] for name in (role, trail, session))
    assert "ssoins-0123456789abcdef" not in contents[0]
    assert "AWSReservedSSO_ExampleAccess" not in contents[0]
    assert "111122223333" in contents[0]
    assert ".a{color:#1a2b3c}" in contents[0]
    assert capture_screenshots.ANONYMIZED_MARKER in contents[0]
    assert capture_screenshots.ANONYMIZED_NAMES_MARKER in contents[0]
    assert capture_screenshots.anonymize_resource_names([first, second]) == {}
    assert [path.read_text(encoding="utf-8") for path in (first, second)] == contents


def test_source_specific_names_outside_finding_rows_are_cleaned(tmp_path, monkeypatch):
    kinds = capture_screenshots._load_generated_value_kinds()
    monkeypatch.setattr(
        kinds,
        "SOURCE_NAME_FINGERPRINTS",
        {(7, hashlib.sha256(b"example").hexdigest())},
    )
    monkeypatch.setattr(
        capture_screenshots, "_load_generated_value_kinds", lambda: kinds
    )
    report = tmp_path / "report.html"
    report.write_text(
        _report("No named resources in this row.").replace(
            "</body>", "<aside>ExampleWorkload-log-group</aside></body>"
        ),
        encoding="utf-8",
    )

    assert capture_screenshots.anonymize_resource_names([report]) == {
        "source account name": 1
    }
    cleaned = report.read_text(encoding="utf-8")
    assert "ExampleWorkload-log-group" not in cleaned
    assert "<aside>" in cleaned
    assert capture_screenshots.anonymize_resource_names([report]) == {}


def test_a_failed_check_changes_no_file(tmp_path, monkeypatch):
    first = tmp_path / "first.html"
    second = tmp_path / "second.html"
    first.write_text(_report("In vpc-0a1b2c3d4e5f60718."), encoding="utf-8")
    second.write_text(_report("In sg-1a2b3c4d."), encoding="utf-8")
    before = [path.read_text(encoding="utf-8") for path in (first, second)]
    original = capture_screenshots._synthetic_value

    def leaky(kinds, value, kind, index, taken):
        # The second file's value survives its own replacement.
        made_up = original(kinds, value, kind, index, taken)
        return f"{made_up} {value}" if value == "1a2b3c4d" else made_up

    monkeypatch.setattr(capture_screenshots, "_synthetic_value", leaky)
    with pytest.raises(SystemExit):
        capture_screenshots.anonymize_resource_ids([first, second])
    assert [path.read_text(encoding="utf-8") for path in (first, second)] == before


def test_a_one_word_name_is_replaced_only_where_it_was_found(tmp_path):
    report = tmp_path / "report.html"
    report.write_text(
        _report(
            "Role 'ExampleRole' (policy 'root': denies s3:*); trusts "
            "arn:aws:iam::111122223333:root. Only SCPs attached to the root apply. "
            '<a href="https://docs.aws.amazon.com/sagemaker/latest/dg/'
            'nbi-root-access.html">root access</a>'
        ).replace("<style>", "<style>:root{--x:1}"),
        encoding="utf-8",
    )

    assert capture_screenshots.anonymize_resource_names([report]) == {
        "quoted resource name": 2
    }
    cleaned = report.read_text(encoding="utf-8")
    assert "'root'" not in cleaned and "ExampleRole" not in cleaned
    assert "<style>:root{--x:1}" in cleaned
    assert "arn:aws:iam::111122223333:root." in cleaned
    assert "attached to the root apply" in cleaned
    assert "nbi-root-access.html" in cleaned


def test_nothing_in_page_styles_or_scripts_is_replaced(tmp_path):
    report = tmp_path / "report.html"
    report.write_text(
        _report("Role 'ExampleRole-1'.").replace(
            "</body>", "<script>const ok = 'ExampleRole-1';</script></body>"
        ),
        encoding="utf-8",
    )
    before = report.read_text(encoding="utf-8")

    # A value in the page's code isn't rewritten there, and the leak check
    # stops the run rather than leave it in place.
    with pytest.raises(SystemExit):
        capture_screenshots.anonymize_resource_names([report])
    assert report.read_text(encoding="utf-8") == before


def test_unquoted_secret_and_lambda_names_are_cleaned(tmp_path):
    report = tmp_path / "report.html"
    report.write_text(
        _report(
            "Allowed for user build-cli and role web-log-ec2-role; event data "
            "store Org-Data-DS records events. Secret 'team/app/master-key' has "
            "no rotation. Invokes arn:aws:lambda:us-east-1:111122223333:function:"
            "ExampleTracker. The function re-fetches the user ARN; role "
            "AWSServiceRoleForBatch is AWS managed."
        ),
        encoding="utf-8",
    )

    assert capture_screenshots.anonymize_resource_names([report]) == {
        "Lambda function name": 1,
        "quoted secret name": 1,
        "unquoted resource name": 3,
    }
    cleaned = report.read_text(encoding="utf-8")
    for name in ("build-cli", "web-log-ec2-role", "Org-Data-DS", "team/app"):
        assert name not in cleaned
    assert "function:ExampleTracker" not in cleaned
    assert "The function re-fetches the user ARN" in cleaned
    assert "role AWSServiceRoleForBatch" in cleaned


def test_changes_page_links_to_the_sample_report_and_drops_the_csv(tmp_path):
    page = tmp_path / "security_assessment_changes.html"
    page.write_text(
        "<p><strong>Related files</strong></p>\n"
        '<p><a href="security_assessment_single_account_20260901_101112.html">'
        "security_assessment_single_account_20260901_101112.html</a></p>\n"
        '<p><a href="security_assessment_changes_20260901_101130.csv">'
        "security_assessment_changes_20260901_101130.csv</a></p>\n",
        encoding="utf-8",
    )

    capture_screenshots.point_changes_links_at_samples(page)

    assert page.read_text(encoding="utf-8") == (
        "<p><strong>Related files</strong></p>\n"
        '<p><a href="security_assessment_single_account.html">'
        "security_assessment_single_account.html</a></p>\n"
    )
