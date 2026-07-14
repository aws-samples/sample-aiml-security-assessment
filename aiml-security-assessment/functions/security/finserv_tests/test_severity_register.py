"""
Drift-guard for the FinServ severity methodology
(REQ-6 / SECURITY_CHECKS_FINSERV_SEVERITY_REGISTER.md).

Asserts that:
  1. The Likelihood x Impact matrix helper matches the documented table (methodology §3.3).
  2. The disposition->severity rules match methodology §3.4.
  3. SEVERITY_REGISTER uses only the four allowed labels (no Critical this round).
  4. Source-scan guard: every static ``finding_name="..."`` literal in app.py exists in
     SEVERITY_REGISTER, and every register key corresponds to a finding name in the source
     (no unregistered names, no orphaned register entries). This is the primary drift-guard:
     it covers Pass/Fail/N-A rows on every code path without needing to execute them.
  5. Runtime spot-check: rows that checks emit with all boto3 calls mocked to raise
     (advisory/static-path rows) carry exactly the register severity, and every emitted
     non-dynamic name is registered.

Scope note: the runtime collection in (5) only exercises paths reachable with AWS down
(mostly advisory rows) — it is a spot-check, not full coverage. Full Pass/Fail-path severity
coverage comes from the source-scan guard in (4) plus the per-scenario assertions in
test_checks.py. The only intentionally dynamic finding name is the
``COULD NOT ASSESS: <check name>`` row, validated separately.
"""

import ast
import inspect

from unittest.mock import MagicMock, patch

from .support import finserv_app as app

ALLOWED = {"High", "Medium", "Low", "Informational"}


# ---------------------------------------------------------------------------
# 1. Matrix helper matches the documented 3x3 table
# ---------------------------------------------------------------------------
def test_label_from_matrix_matches_methodology_table():
    expected = {
        (3, 1): "Medium",
        (3, 2): "High",
        (3, 3): "High",
        (2, 1): "Low",
        (2, 2): "Medium",
        (2, 3): "High",
        (1, 1): "Low",
        (1, 2): "Low",
        (1, 3): "Medium",
    }
    for (i, ell), label in expected.items():
        assert app._label_from_matrix(i, ell) == label, f"matrix[{i},{ell}]"


# ---------------------------------------------------------------------------
# 2. Disposition -> severity rules (methodology §3.4)
# ---------------------------------------------------------------------------
def test_disposition_severity_rules():
    assert app._DISPOSITION_SEVERITY["NOT_APPLICABLE"] == "Informational"
    assert app._DISPOSITION_SEVERITY["ADVISORY"] == "Informational"
    assert app._DISPOSITION_SEVERITY["COULD_NOT_ASSESS"] == "Low"


# ---------------------------------------------------------------------------
# 3. Register uses only allowed labels (no Critical)
# ---------------------------------------------------------------------------
def test_register_labels_are_allowed_no_critical():
    assert app.SEVERITY_REGISTER, "register must not be empty"
    bad = {v for v in app.SEVERITY_REGISTER.values() if v not in ALLOWED}
    assert not bad, f"register has disallowed labels: {bad}"


# ---------------------------------------------------------------------------
# 4. Could-not-assess synthesized row is Low / N/A (COULD_NOT_ASSESS disposition)
# ---------------------------------------------------------------------------
def test_could_not_assess_row_is_low():
    row = app._could_not_assess_row("FS-01", "Some Check", "boom")
    assert row["Severity"] == "Low"
    assert row["Status"] == "N/A"
    assert row["Finding"].startswith(app.COULD_NOT_ASSESS_PREFIX)


# ---------------------------------------------------------------------------
# 5. Source-scan guard: static finding names <-> register keys (bidirectional)
# ---------------------------------------------------------------------------
def _static_finding_names_from_source():
    """Collect every static ``finding_name="..."`` literal passed to a call in
    app.py. Dynamic names (f-strings such as the COULD NOT ASSESS row) are
    excluded and validated separately."""
    tree = ast.parse(inspect.getsource(app))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if (
                    kw.arg == "finding_name"
                    and isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, str)
                ):
                    names.add(kw.value.value)
    return names


# Static finding names that intentionally live outside the severity register:
# synthesized/regional-scope rows whose severity is fixed by their disposition,
# not by a control score. Keep this list short and justified.
_REGISTER_EXEMPT_NAMES = {
    # FS-00 regional-scope row: fixed Informational/N-A by construction.
    "FinServ Regional Scope Not Applicable",
}


def test_every_static_finding_name_is_registered():
    """Any finding name the code can emit must have a register entry; a rename
    in code without a register update is a drift and must fail the build."""
    names = _static_finding_names_from_source() - _REGISTER_EXEMPT_NAMES
    missing = sorted(n for n in names if n not in app.SEVERITY_REGISTER)
    assert not missing, f"finding names missing from SEVERITY_REGISTER: {missing}"


def test_register_has_no_orphaned_entries():
    """Every register key must correspond to a finding name in the source; an
    orphaned entry means a finding was renamed or removed without updating the
    register (the register would silently stop guarding it)."""
    names = _static_finding_names_from_source()
    orphans = sorted(k for k in app.SEVERITY_REGISTER if k not in names)
    assert not orphans, (
        f"SEVERITY_REGISTER entries with no matching finding_name: {orphans}"
    )


# ---------------------------------------------------------------------------
# 6. Runtime spot-check: emitted rows match the register (advisory/static paths)
# ---------------------------------------------------------------------------
def _collect_emitted_rows():
    """Run every registered check with all boto3 calls raising, collecting CSV rows.

    A check whose body raises returns _error_findings (no rows) — that is fine; we only
    assert on the rows that ARE emitted. Advisory checks (no boto3) emit their row directly.
    """
    rows = []
    cache = {"role_permissions": {}, "user_permissions": {}}

    def boom_client(*_a, **_k):
        m = MagicMock()
        # Any attribute access returns a callable that raises, so checks that call
        # boto3 fall into their except/_error_findings path deterministically.
        m.side_effect = Exception("no aws in unit test")

        def _raise(*_aa, **_kk):
            raise Exception("no aws in unit test")

        m.__getattr__ = lambda _name: _raise
        return m

    with patch.object(app.boto3, "client", side_effect=boom_client):
        for check_id, fn in app.build_finserv_checks(cache):
            try:
                result = fn()
            except Exception:
                continue
            for row in result.get("csv_data", []):
                rows.append((row["Finding"], str(row["Severity"]), str(row["Status"])))
    return rows


def test_emitted_severity_matches_register():
    """Advisory/static-path checks emit rows even with boto3 down; assert they
    match the register. Unlike the earlier version of this test, an emitted
    name that is MISSING from the register is a failure, not a skip — only the
    intentionally dynamic COULD NOT ASSESS row and the register-exempt rows
    are excluded."""
    rows = _collect_emitted_rows()
    mismatches = []
    unregistered = []
    for finding, severity, _status in rows:
        if finding.startswith(app.COULD_NOT_ASSESS_PREFIX):
            continue
        if finding in _REGISTER_EXEMPT_NAMES:
            continue
        sev = severity.split(".")[-1].title() if "." in severity else severity
        if finding not in app.SEVERITY_REGISTER:
            unregistered.append(finding)
        elif app.SEVERITY_REGISTER[finding] != sev:
            mismatches.append((finding, sev, app.SEVERITY_REGISTER[finding]))
    assert not unregistered, f"emitted findings missing from register: {unregistered}"
    assert not mismatches, f"severity drift: {mismatches}"


def test_advisory_rows_are_informational_na():
    """All ADVISORY-prefixed findings must be Informational / N/A."""
    rows = _collect_emitted_rows()
    for finding, severity, status in rows:
        if finding.startswith("ADVISORY: "):
            sev = severity.split(".")[-1].title() if "." in severity else severity
            st = status.split(".")[-1] if "." in status else status
            assert sev == "Informational", f"{finding} severity={sev}"
            assert st in ("NA", "N/A"), f"{finding} status={st}"
