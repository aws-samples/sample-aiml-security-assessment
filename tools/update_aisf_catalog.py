"""Import the canonical export; never interpret the control YAML here."""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = (
    ROOT / "aiml-security-assessment/functions/security/generate_consolidated_report"
)
sys.path.insert(0, str(REPORT))

from aisf_catalog import PINNED_REVISION, load_catalog  # noqa: E402
from aisf_results import load_mapping  # noqa: E402

CLASSIFICATION_FIELDS = (
    "section",
    "text_sha256",
    "kind",
    "machine_checkable",
    "workload_agnostic",
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encode(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()


def check_mapping() -> None:
    """Bind the reviewed predicates to the actual producer source and catalog."""
    entries, _ = load_mapping()
    ledger = json.loads((REPORT / "aisf_catalog/mapping.json").read_text())
    for name, expected in ledger["source_file_sha256"].items():
        if digest((ROOT / name).read_bytes()) != expected:
            raise ValueError(f"Stale AISF predicate review: {name}")
    for record in load_catalog()["controls"]:
        actual = digest(
            json.dumps(
                record, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            ).encode()
        )
        if actual != entries[record["id"]]["canonical_record_sha256"]:
            raise ValueError(f"Stale AISF requirement review: {record['id']}")


def import_catalog(source: Path, revision: str, check: bool) -> None:
    if revision != PINNED_REVISION:
        raise ValueError("Revision differs from the reviewed AISF pin")
    data = subprocess.check_output(
        [sys.executable, "-B", str(source / "build/export_controls.py"), "--stdout"],
        cwd=source,
    )
    if data != (source / "crosswalk/controls.json").read_bytes():
        raise ValueError(
            "Canonical export is stale; update it in its owning repository"
        )
    exported = json.loads(data)
    records = exported["controls"]
    ids = [record["id"] for record in records]
    if len(ids) != 218 or len(set(ids)) != 218:
        raise ValueError("Reviewed catalog requires exactly 218 unique controls")
    inputs = sorted(
        {
            *source.glob("controls/**/*.yaml"),
            *source.glob("build/*.py"),
            source / "crosswalk/classification-ledger.json",
        }
    )
    ledger = json.loads((source / "crosswalk/classification-ledger.json").read_bytes())
    classifications = encode(
        {
            "schema_version": 1,
            "controls": {
                control_id: {field: record[field] for field in CLASSIFICATION_FIELDS}
                for control_id, record in sorted(ledger["controls"].items())
            },
        }
    )
    files = {"controls.json": data, "classification.json": classifications}
    manifest = {
        "schema_version": 1,
        "source_revision": revision,
        "exporter": "build/export_controls.py",
        "exporter_sha256": digest((source / "build/export_controls.py").read_bytes()),
        "export_schema": "canonical normalize_item / controls.json",
        "classification_projection": {
            "schema_version": 1,
            "source": "crosswalk/classification-ledger.json",
            "fields": list(CLASSIFICATION_FIELDS),
        },
        "update_command": (
            ".venv/bin/python tools/update_aisf_catalog.py "
            "--source /path/to/pinned/canonical --revision " + revision
        ),
        "inputs": {
            str(path.relative_to(source)): digest(path.read_bytes()) for path in inputs
        },
        "outputs": {name: digest(content) for name, content in files.items()},
        "control_count": len(ids),
        "ids": ids,
    }
    files["manifest.json"] = encode(manifest)
    directory = REPORT / "aisf_catalog"
    for name, content in files.items():
        path = directory / name
        if check:
            if path.read_bytes() != content:
                raise ValueError(f"Stale AISF bundle: {name}")
        else:
            directory.mkdir(exist_ok=True)
            path.write_bytes(content)
    load_catalog()
    print("AISF catalog: 218 controls; canonical export and provenance verified")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--revision", default=PINNED_REVISION)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.source:
        import_catalog(args.source.resolve(), args.revision, args.check)
    elif args.check:
        load_catalog()
        print("AISF catalog: 218 controls; pinned bundle digests verified")
    else:
        parser.error("--source is required for an import")
    check_mapping()
    print("AISF mapping: 218 requirements and producer source digests verified")


if __name__ == "__main__":
    main()
