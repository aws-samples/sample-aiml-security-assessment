"""Catalog imports retain assessment metadata without copying unused annotations."""

import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "aisf_catalog_import", ROOT / "tools/update_aisf_catalog.py"
)
importer = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(importer)


# This expectation is independent of the importer's allowlist.
EXPECTED_FIELDS = {
    "section",
    "text_sha256",
    "kind",
    "machine_checkable",
    "workload_agnostic",
}


def test_import_projects_annotations_and_keeps_raw_source_provenance(
    tmp_path, monkeypatch
):
    source = tmp_path / "source"
    (source / "build").mkdir(parents=True)
    (source / "crosswalk").mkdir()
    controls_bytes = (importer.REPORT / "aisf_catalog/controls.json").read_bytes()
    (source / "crosswalk/controls.json").write_bytes(controls_bytes)
    (source / "build/export_controls.py").write_text(
        "import pathlib, sys\n"
        "sys.stdout.buffer.write((pathlib.Path(__file__).resolve().parents[1] / "
        '"crosswalk/controls.json").read_bytes())\n'
    )
    baseline = json.loads(
        (importer.REPORT / "aisf_catalog/classification.json").read_bytes()
    )["controls"]
    ledger = {
        "_meta": {"unused_annotation": "source-only top-level annotation"},
        "controls": {
            control_id: {
                **record,
                "unused_annotation": {"label": "source-only control annotation"},
            }
            for control_id, record in reversed(list(baseline.items()))
        },
    }
    raw = json.dumps(ledger).encode()
    (source / "crosswalk/classification-ledger.json").write_bytes(raw)
    report = tmp_path / "report"
    report.mkdir()
    monkeypatch.setattr(importer, "REPORT", report)
    load_catalog = importer.load_catalog
    monkeypatch.setattr(
        importer, "load_catalog", lambda: load_catalog(report / "aisf_catalog")
    )

    importer.import_catalog(source, importer.PINNED_REVISION, check=False)
    catalog = load_catalog(report / "aisf_catalog")
    projected_bytes = (report / "aisf_catalog/classification.json").read_bytes()
    assert (report / "aisf_catalog/controls.json").read_bytes() == controls_bytes
    assert catalog["classifications"] == baseline
    assert len(catalog["classifications"]) == 218
    assert all(set(record) == EXPECTED_FIELDS for record in baseline.values())
    assert b"source-only" not in projected_bytes
    manifest = catalog["manifest"]
    assert manifest["classification_projection"]["schema_version"] == 1
    assert set(manifest["classification_projection"]["fields"]) == EXPECTED_FIELDS
    assert (
        manifest["classification_projection"]["source"]
        == "crosswalk/classification-ledger.json"
    )
    assert manifest["inputs"]["crosswalk/classification-ledger.json"] == (
        hashlib.sha256(raw).hexdigest()
    )
    assert manifest["outputs"]["classification.json"] == (
        hashlib.sha256(projected_bytes).hexdigest()
    )
    importer.import_catalog(source, importer.PINNED_REVISION, check=True)

    # Input ordering and unrelated metadata may change without changing the bundle.
    ledger["_meta"]["unused_annotation"] = "updated source-only annotation"
    (source / "crosswalk/classification-ledger.json").write_text(
        json.dumps(ledger, sort_keys=True)
    )
    importer.import_catalog(source, importer.PINNED_REVISION, check=False)
    assert (report / "aisf_catalog/classification.json").read_bytes() == projected_bytes
    assert (
        load_catalog(report / "aisf_catalog")["manifest"]["inputs"]
        != (manifest["inputs"])
    )
    importer.import_catalog(source, importer.PINNED_REVISION, check=True)
