"""
Drift-guard for the AgentCore severity register
(docs/AI_SECURITY_BEST_PRACTICES_GAP_ANALYSIS.md "Severity Model").

Mirrors finserv_tests/test_severity_register.py: the FinServ severity
methodology is adopted here for the AgentCore (AC-*) and Agentic AI Gateway
(AG-24..27) checks, seeding control severity from the AWS Security Hub
published severity for the control each check implements (or a documented
repo-specific decision for checks with no Security Hub equivalent).

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

sys.path.insert(0, "aiml-security-assessment/functions/security/agentcore_assessments")

_ac_dir = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "aiml-security-assessment/functions/security/agentcore_assessments",
    )
)
if _ac_dir not in sys.path:
    sys.path.insert(0, _ac_dir)

if "agentcore_app" in sys.modules:
    agentcore_app = sys.modules["agentcore_app"]
else:
    # agentcore_assessments, bedrock_assessments, and sagemaker_assessments
    # each define their own same-named "schema"/"severity_disposition"
    # modules. If another module's test already ran and cached
    # sys.modules["severity_disposition"] (or ["schema"]) with its own
    # version, agentcore_app.py's plain `from severity_disposition import
    # ...` / `from schema import ...` would silently bind to that other
    # module instead of its own. Evict any stale cache entries so the import
    # below (and the one further down in this file) resolves against
    # _ac_dir (already at the front of sys.path).
    sys.modules.pop("severity_disposition", None)
    sys.modules.pop("schema", None)
    _spec = importlib.util.spec_from_file_location(
        "agentcore_app", os.path.join(_ac_dir, "app.py")
    )
    agentcore_app = importlib.util.module_from_spec(_spec)
    sys.modules["agentcore_app"] = agentcore_app
    _spec.loader.exec_module(agentcore_app)

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
        agentcore_app.create_finding,
        "AC-01",
        "Some Check",
        "boom",
        "https://example.com",
        agentcore_app.SeverityEnum,
        agentcore_app.StatusEnum,
    )
    assert row["Severity"] == "Low"
    assert row["Status"] == "N/A"
    assert row["Finding"].startswith(COULD_NOT_ASSESS_PREFIX)


# ---------------------------------------------------------------------------
# 4. Source-scan guard: static finding names <-> register keys (bidirectional)
# ---------------------------------------------------------------------------
def _static_finding_names_from_source():
    """Collect every static ``finding_name="..."`` literal passed to a
    create_finding call in app.py. Dynamic names (f-strings, including the
    COULD NOT ASSESS row template) are excluded — they are validated by
    test_could_not_assess_row_is_low_na above instead."""
    tree = ast.parse(inspect.getsource(agentcore_app))
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
