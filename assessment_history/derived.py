"""Legacy partial AISF aliases derived from compared native check findings.

The main AISF view presents native AI check results. The changes report keeps
three legacy aliases from ``derive_aisf_findings`` in aisf_mappings.py, loaded by
file path, for comparison compatibility. Global evidence retains its own key.
Successful source checks provide partial evidence and cannot pass a whole AISF
control. Both runs use today's mapping, so mapping changes are not findings
changes.
"""

from __future__ import annotations

import functools
import importlib.util
from collections.abc import Iterable
from pathlib import Path

from .models import (
    CORE_MODULES,
    DERIVED_MODULE,
    Finding,
    normalize_status,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
AISF_MAPPINGS_PATH = (
    REPO_ROOT
    / "aiml-security-assessment"
    / "functions"
    / "security"
    / "generate_consolidated_report"
    / "aisf_mappings.py"
)
# A name of its own, so it never clashes with the consolidators' plain
# `import aisf_mappings`.
AISF_MODULE_NAME = "assessment_history_aisf_mappings"
AISF_AREA = "aisf"


class DerivationError(Exception):
    """The AISF rows can't be derived; the message says why."""


def load_aisf_mappings(path: Path = AISF_MAPPINGS_PATH):
    """Load aisf_mappings.py by file path.

    Any error the module raises while loading (a missing file, a syntax error,
    an import or name error) is a DerivationError, so it becomes a note in the
    changes report rather than a failed comparison.
    """
    spec = importlib.util.spec_from_file_location(AISF_MODULE_NAME, path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        raise DerivationError(
            f"can't load {path}: {type(error).__name__}: {error}"
        ) from None
    return module


@functools.lru_cache(maxsize=1)
def aisf_mappings():
    """aisf_mappings.py, loaded once per process."""
    return load_aisf_mappings()


def omitted_aisf_control_ids(compared_services: frozenset[str]) -> list[str]:
    """Controls with no source service selected in both compared runs."""
    try:
        selected = {service: service in compared_services for service in CORE_MODULES}
        return sorted(
            check_id
            for check_id, _services in aisf_mappings().omitted_aisf_controls(selected)
        )
    except DerivationError:
        raise
    except Exception as error:
        raise DerivationError(
            f"can't list omitted controls: {type(error).__name__}: {error}"
        ) from None


def derive_aisf(
    findings: Iterable[Finding],
    account_id: str,
    compared_services: frozenset[str],
    mappings=None,
    notes: list[str] | None = None,
) -> list[Finding]:
    """The AISF rows for one run's compared findings.

    ``compared_services`` are the core services compared in both runs; a
    legacy alias whose sources all belong to another service gets no row.

    Global and regional evidence retain separate keys, so an unrelated scope
    cannot change an alias or satisfy a missing predicate. Successful partial
    evidence remains N/A for the whole control.

    A mapping error or a derived row that can't be read as a Finding is named
    in ``notes``; the other rows are kept.
    """
    try:
        module = aisf_mappings() if mappings is None else mappings
        selected = {service: service in compared_services for service in CORE_MODULES}
        mapping_errors = []
        rows = module.derive_aisf_findings(
            [
                {
                    "Check_ID": finding.check_id,
                    "Account_ID": finding.account_id,
                    "Region": finding.region,
                    "Status": finding.status,
                }
                for finding in findings
            ],
            selected,
            separate_global=True,
            diagnostics=mapping_errors,
        )
    except DerivationError:
        raise
    except Exception as error:
        raise DerivationError(f"{type(error).__name__}: {error}") from None
    if mapping_errors and notes is not None:
        check_ids = sorted({check_id for check_id, _region, _error in mapping_errors})
        notes.append(
            f"AWS AI Security Framework rows not compared for "
            f"{len(mapping_errors)} mapping error(s) ({', '.join(check_ids)}): "
            f"{mapping_errors[0][2]}"
        )
    derived, skipped = [], []
    for row in rows:
        try:
            derived.append(_finding(row, account_id))
        except (KeyError, TypeError, AttributeError, ValueError) as error:
            # InvalidFindingError is a ValueError: a new status or area.
            skipped.append((row, error))
    if skipped and notes is not None:
        check_ids = sorted({str(_get(row, "Check_ID")) for row, _ in skipped})
        row, error = skipped[0]
        notes.append(
            f"AWS AI Security Framework rows not compared for {len(skipped)} "
            f"derived row(s) ({', '.join(check_ids)}): "
            f"{type(error).__name__}: {error}"
        )
    return derived


def _get(row, key: str):
    """A key of a derived row, or None for a row that isn't a mapping."""
    return row.get(key) if isinstance(row, dict) else None


def _finding(row: dict, account_id: str) -> Finding:
    return Finding(
        account_id=account_id,
        module=DERIVED_MODULE,
        area=AISF_AREA,
        region=row["Region"],
        check_id=row["Check_ID"],
        finding=row["Finding"],
        details=row["Finding_Details"],
        severity=row["Severity"],
        status=normalize_status(row["Status"]),
        resolution=row["Resolution"],
        reference=row["Reference"],
    )
