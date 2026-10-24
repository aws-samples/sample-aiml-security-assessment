import importlib.util
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
