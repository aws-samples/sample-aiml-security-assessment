import importlib.util
import os
import sys


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORT_APP_DIR = os.path.join(
    REPO_ROOT,
    "aiml-security-assessment",
    "functions",
    "security",
    "generate_consolidated_report",
)

if REPORT_APP_DIR not in sys.path:
    sys.path.insert(0, REPORT_APP_DIR)


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


single_report_app = _load_module(
    "single_report_app",
    os.path.join(REPORT_APP_DIR, "app.py"),
)
multi_report_app = _load_module(
    "multi_report_app",
    os.path.join(REPO_ROOT, "consolidate_html_reports.py"),
)


def test_single_account_report_filename_does_not_include_execution_id():
    key = single_report_app.build_single_account_report_key("20260614_120000")
    assert key == "security_assessment_single_account_20260614_120000.html"
    assert "exec" not in key


def test_multi_account_report_filename_uses_consistent_prefix():
    key = multi_report_app.build_multi_account_report_key("20260614_120000")
    assert (
        key
        == "consolidated-reports/security_assessment_multi_account_20260614_120000.html"
    )
