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


def test_unset_target_regions_uses_aws_region(monkeypatch):
    monkeypatch.delenv("TARGET_REGIONS", raising=False)
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")

    assert resolve_regions_app.resolve_regions() == ["us-west-2"]


def test_empty_target_regions_falls_back_to_aws_default_region(monkeypatch):
    monkeypatch.setenv("TARGET_REGIONS", "")
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")

    assert resolve_regions_app.resolve_regions() == ["eu-west-1"]


def test_empty_target_regions_defaults_to_us_east_1(monkeypatch):
    monkeypatch.setenv("TARGET_REGIONS", " ")
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)

    assert resolve_regions_app.resolve_regions() == ["us-east-1"]


@pytest.mark.parametrize("target_regions", ["all", "ALL", " All "])
def test_all_is_rejected_at_runtime(monkeypatch, target_regions):
    monkeypatch.setenv("TARGET_REGIONS", target_regions)

    with pytest.raises(ValueError, match="no longer accepts 'all'"):
        resolve_regions_app.resolve_regions()


def test_explicit_regions_are_returned(monkeypatch):
    monkeypatch.setenv("TARGET_REGIONS", "us-east-1, us-west-2")

    assert resolve_regions_app.resolve_regions() == ["us-east-1", "us-west-2"]
