"""Verified, runtime-local canonical AISF catalog."""

import hashlib
import json
from pathlib import Path

PINNED_REVISION = "5df3295024713ac3ce88130c549bbc4fb2cebd53"
PINNED_EXPORT_SHA256 = (
    "f2d44380f1859c204d13caf093b6e73a0aa2bea55e6f9cd6862971db12e362be"
)
CATALOG_DIRECTORY = Path(__file__).with_name("aisf_catalog")


def load_catalog(directory: Path = CATALOG_DIRECTORY) -> dict:
    """Fail closed on a missing, stale, corrupt, or mismatched catalog bundle."""
    manifest = json.loads((directory / "manifest.json").read_text())
    if manifest["source_revision"] != PINNED_REVISION:
        raise ValueError("Stale AISF source revision")
    if manifest["schema_version"] != 1 or manifest["control_count"] != 218:
        raise ValueError("Unsupported AISF catalog schema or inventory")
    documents = {}
    for name in ("controls.json", "classification.json"):
        content = (directory / name).read_bytes()
        if hashlib.sha256(content).hexdigest() != manifest["outputs"][name]:
            raise ValueError(f"Stale AISF content: {name}")
        documents[name] = json.loads(content)
    if manifest["outputs"]["controls.json"] != PINNED_EXPORT_SHA256:
        raise ValueError("AISF export does not match the pinned revision")
    records = documents["controls.json"]["controls"]
    ids = [record["id"] for record in records]
    if len(ids) != 218 or len(set(ids)) != 218 or ids != manifest["ids"]:
        raise ValueError("AISF control ID mismatch")
    classifications = documents["classification.json"]["controls"]
    if set(classifications) != set(ids):
        raise ValueError("AISF classification ID mismatch")
    return {
        "manifest": manifest,
        "controls": records,
        "classifications": classifications,
    }
