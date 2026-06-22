"""Stable imports and shared helpers for FinServ tests."""

from __future__ import annotations

import importlib.util
import os
import sys


_THIS_DIR = os.path.dirname(__file__)
_FINSERV_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", "finserv_assessments"))
_APP_PATH = os.path.join(_FINSERV_DIR, "app.py")
_SCHEMA_PATH = os.path.join(_FINSERV_DIR, "schema.py")


def _load_module(module_name: str, path: str, add_path: str | None = None):
    saved_sys_path = list(sys.path)
    saved_schema = sys.modules.get("schema")

    try:
        if add_path and add_path not in sys.path:
            sys.path.insert(0, add_path)

        spec = importlib.util.spec_from_file_location(module_name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path[:] = saved_sys_path
        if saved_schema is None:
            sys.modules.pop("schema", None)
        else:
            sys.modules["schema"] = saved_schema


finserv_schema = _load_module("finserv_schema", _SCHEMA_PATH)
finserv_app = _load_module("finserv_app", _APP_PATH, add_path=_FINSERV_DIR)


def make_resource_inventory(**overrides) -> finserv_app.ResourceInventory:
    """Build a fully-available ResourceInventory with sensible empty defaults."""
    defaults: dict = dict(
        lambda_functions=[],
        guardrails=finserv_app.GuardrailInventory(summaries=[], detail_by_id={}),
        knowledge_bases=finserv_app.KbInventory(
            summaries=[], data_sources_by_kb={}, data_source_detail={}
        ),
        buckets=[],
        web_acls=finserv_app.WebAclInventory(summaries=[], detail_by_id={}),
    )
    defaults.update(overrides)
    return finserv_app.ResourceInventory(**defaults)
