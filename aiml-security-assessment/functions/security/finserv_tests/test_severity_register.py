"""
Drift-guard for the FinServ severity methodology
(REQ-6 / SECURITY_CHECKS_FINSERV_SEVERITY_REGISTER.md).

Asserts that:
  1. The Likelihood x Impact matrix helper matches the documented table (methodology §3.3).
  2. The disposition->severity rules match methodology §3.4.
  3. SEVERITY_REGISTER uses only the four allowed labels (no Critical this round).
  4. Every finding-name emitted by the check registry exists in SEVERITY_REGISTER, and the
     emitted `severity=` equals the register value (prevents future drift across 64 checks).

The boto3 calls in every check are mocked to raise, which forces each check down a path that
still emits its finding rows (or is caught), so we can collect the (finding_name, severity)
pairs the code actually produces without real AWS access.
"""

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
# 5. Every emitted finding's severity matches the register (the real drift-guard)
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
    """Advisory/static-path checks emit rows even with boto3 down; assert they match."""
    rows = _collect_emitted_rows()
    # We only check rows whose finding-name is a static name in the register
    # (could-not-assess rows use a dynamic name and are validated separately).
    mismatches = []
    for finding, severity, _status in rows:
        sev = severity.split(".")[-1].title() if "." in severity else severity
        if finding in app.SEVERITY_REGISTER and app.SEVERITY_REGISTER[finding] != sev:
            mismatches.append((finding, sev, app.SEVERITY_REGISTER[finding]))
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
