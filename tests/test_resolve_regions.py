"""Tests for target-region resolution."""

import importlib.util
from pathlib import Path
import sys

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[1]
_APP_PATH = (
    _REPO_ROOT
    / "aiml-security-assessment"
    / "functions"
    / "security"
    / "resolve_regions"
    / "app.py"
)
_SPEC = importlib.util.spec_from_file_location("resolve_regions_app", _APP_PATH)
resolve_regions_app = importlib.util.module_from_spec(_SPEC)
sys.modules["resolve_regions_app"] = resolve_regions_app
_SPEC.loader.exec_module(resolve_regions_app)


@pytest.mark.parametrize("target_regions", ["all", "ALL", " All "])
def test_all_is_rejected_at_runtime(monkeypatch, target_regions):
    monkeypatch.setenv("TARGET_REGIONS", target_regions)

    with pytest.raises(ValueError, match="no longer accepts 'all'"):
        resolve_regions_app.resolve_regions()


def test_explicit_regions_are_returned(monkeypatch):
    monkeypatch.setenv("TARGET_REGIONS", "us-east-1, us-west-2")

    assert resolve_regions_app.resolve_regions() == ["us-east-1", "us-west-2"]
