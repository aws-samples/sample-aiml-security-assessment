"""
Drift-guard for the SageMaker severity register
(docs/AI_SECURITY_BEST_PRACTICES_GAP_ANALYSIS.md "Severity Model").

Mirrors tests/test_bedrock_severity_register.py: the FinServ severity
methodology is adopted here for the SageMaker (SM-*) checks, seeding control
severity from the AWS Security Hub published severity documented directly
in many check docstrings ("Aligns with AWS Security Hub control
SageMaker.N (severity X)"), or the more defensible/most common severity
across a check's own Pass/Fail call sites for repo-only checks.

Asserts that:
  1. The disposition->severity rules match the methodology (NOT_APPLICABLE ->
     Informational, COULD_NOT_ASSESS -> Low).
  2. SEVERITY_REGISTER uses only the four allowed ASFF labels.
  3. Source-scan guard: every static ``finding_name="..."`` literal in app.py
     exists in SEVERITY_REGISTER, and every register key corresponds to a
     finding name in the source (bidirectional; no unregistered names, no
     orphaned register entries). This is the primary drift-guard — it covers
     every Pass/Fail/N-A code path without needing to execute them.
  4. ``could_not_assess_row`` always returns Severity=Low, Status=N/A, with
     the finding name prefixed "COULD NOT ASSESS: ".
"""

import ast
import inspect
import os
import sys
import importlib.util

sys.path.insert(0, "aiml-security-assessment/functions/security/sagemaker_assessments")

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
    # below (and the one further down in this file) resolves against
    # _sm_dir (already at the front of sys.path).
    sys.modules.pop("severity_disposition", None)
    sys.modules.pop("schema", None)
    _spec = importlib.util.spec_from_file_location(
        "sagemaker_app", os.path.join(_sm_dir, "app.py")
    )
    sagemaker_app = importlib.util.module_from_spec(_spec)
    sys.modules["sagemaker_app"] = sagemaker_app
    _spec.loader.exec_module(sagemaker_app)

from severity_disposition import (  # noqa: E402
    SEVERITY_REGISTER,
    _DISPOSITION_SEVERITY,
    COULD_NOT_ASSESS_PREFIX,
    could_not_assess_row,
)

ALLOWED = {"High", "Medium", "Low", "Informational"}


# ---------------------------------------------------------------------------
# 1. Disposition -> severity rules
# ---------------------------------------------------------------------------
def test_disposition_severity_rules():
    assert _DISPOSITION_SEVERITY["NOT_APPLICABLE"] == "Informational"
    assert _DISPOSITION_SEVERITY["COULD_NOT_ASSESS"] == "Low"


# ---------------------------------------------------------------------------
# 2. Register uses only allowed labels
# ---------------------------------------------------------------------------
def test_register_labels_are_allowed():
    assert SEVERITY_REGISTER, "register must not be empty"
    bad = {v for v in SEVERITY_REGISTER.values() if v not in ALLOWED}
    assert not bad, f"register has disallowed labels: {bad}"


# ---------------------------------------------------------------------------
# 3. could_not_assess_row returns the COULD_NOT_ASSESS disposition
# ---------------------------------------------------------------------------
def test_could_not_assess_row_is_low_na():
    row = could_not_assess_row(
        sagemaker_app.create_finding,
        "SM-01",
        "Some Check",
        "boom",
        "https://example.com",
        region="us-east-1",
    )
    assert row["Severity"] == "Low"
    assert row["Status"] == "N/A"
    assert row["Finding"].startswith(COULD_NOT_ASSESS_PREFIX)
    assert row["Region"] == "us-east-1"


def test_could_not_assess_row_region_defaults_empty():
    row = could_not_assess_row(
        sagemaker_app.create_finding,
        "SM-01",
        "Some Check",
        "boom",
        "https://example.com",
    )
    assert row["Region"] == ""


# ---------------------------------------------------------------------------
# 4. Source-scan guard: static finding names <-> register keys (bidirectional)
# ---------------------------------------------------------------------------
def _static_finding_names_from_source():
    """Collect every static ``finding_name="..."`` literal passed to a
    create_finding call in app.py. Dynamic names (f-strings, including the
    COULD NOT ASSESS row template built inside severity_disposition.py) are
    excluded — they are validated by test_could_not_assess_row_is_low_na
    above instead."""
    tree = ast.parse(inspect.getsource(sagemaker_app))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            if func_name != "create_finding":
                continue
            for kw in node.keywords:
                if (
                    kw.arg == "finding_name"
                    and isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, str)
                ):
                    names.add(kw.value.value)
    return names


def test_every_static_finding_name_is_registered():
    """Any finding name the code can emit must have a register entry; a
    rename in code without a register update is a drift and must fail."""
    names = _static_finding_names_from_source()
    missing = sorted(n for n in names if n not in SEVERITY_REGISTER)
    assert not missing, f"finding names missing from SEVERITY_REGISTER: {missing}"


def test_register_has_no_orphaned_entries():
    """Every register key must correspond to a finding name in the source; an
    orphaned entry means a finding was renamed or removed without updating
    the register (the register would silently stop guarding it)."""
    names = _static_finding_names_from_source()
    orphans = sorted(k for k in SEVERITY_REGISTER if k not in names)
    assert not orphans, (
        f"SEVERITY_REGISTER entries with no matching finding_name: {orphans}"
    )
