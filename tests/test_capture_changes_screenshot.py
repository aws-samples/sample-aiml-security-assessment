"""capture_changes_screenshot.py: the changes sample's screenshot script.

No browser is started; the checks that run before it are tested directly.
"""

import importlib.util
from pathlib import Path
from unittest.mock import Mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "sample-reports" / "scripts" / "capture_changes_screenshot.py"
SPEC = importlib.util.spec_from_file_location("capture_changes_screenshot", SCRIPT_PATH)
script = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(script)


@pytest.fixture
def no_browser(monkeypatch):
    """Fail the test if the script gets as far as setting up a browser."""
    monkeypatch.setattr(
        script, "ensure_repo_venv", Mock(side_effect=AssertionError("venv"))
    )
    monkeypatch.setattr(
        script.shared,
        "bootstrap_screenshot_environment",
        Mock(side_effect=AssertionError("bootstrap")),
    )


def test_it_captures_only_its_own_screenshot():
    assert [config["file"] for config in script.SCREENSHOTS] == [
        "security_assessment_changes.html"
    ]
    existing = {config["name"] for config in script.shared.SCREENSHOTS}
    assert not existing & {config["name"] for config in script.SCREENSHOTS}


def test_unexpected_account_ids():
    text = (
        "123456789012 111122223333 987654321098 123456789012 2026092706151 987654321098"
    )
    assert script.unexpected_account_ids(text) == ["987654321098"]
    assert script.unexpected_account_ids("no ids here") == []


def test_the_committed_sample_uses_only_placeholder_account_ids():
    page = REPO_ROOT / "sample-reports" / "security_assessment_changes.html"
    assert script.unexpected_account_ids(page.read_text(encoding="utf-8")) == []


def test_unsupported_arguments_are_rejected(no_browser, capsys):
    assert script.main(["--all"]) == 2
    assert "Unsupported argument(s): --all" in capsys.readouterr().out


def test_a_missing_page_stops_before_the_browser(no_browser, monkeypatch, tmp_path):
    monkeypatch.setattr(script.shared, "SAMPLE_REPORTS_DIR", tmp_path)
    assert script.main([]) == 1


def test_a_real_looking_account_id_stops_before_the_browser(
    no_browser, monkeypatch, tmp_path, capsys
):
    (tmp_path / "security_assessment_changes.html").write_text(
        "<html>987654321098</html>", encoding="utf-8"
    )
    monkeypatch.setattr(script.shared, "SAMPLE_REPORTS_DIR", tmp_path)
    assert script.main([]) == 1
    assert "987654321098" in capsys.readouterr().out
