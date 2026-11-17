"""Regenerate synthetic AISF reports through both production consolidators."""

import argparse
import hashlib
import io
import json
import os
import re
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
REPORT = (
    ROOT / "aiml-security-assessment/functions/security/generate_consolidated_report"
)
FIXTURES = ROOT / "sample-reports/fixtures/aisf"
SAMPLES = ROOT / "sample-reports"
sys.path[:0] = [str(REPORT), str(ROOT)]

import app as single  # noqa: E402
from aisf_catalog import load_catalog  # noqa: E402
from aisf_results import source_check, value  # noqa: E402
from consolidate_html_reports import (  # noqa: E402
    load_multi_account_results,
    render_multi_account_report,
)


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def encoded(value: object) -> bytes:
    return (
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode()


class FixtureS3:
    """Use the production S3 discovery/parser path without any network access."""

    def __init__(self, directory: Path) -> None:
        self.files = {path.name: path.read_bytes() for path in directory.glob("*.csv")}

    def get_paginator(self, name: str) -> "FixtureS3":
        assert name == "list_objects_v2"
        return self

    def paginate(self, *, Bucket: str, Prefix: str) -> list[dict]:
        assert Bucket == "synthetic-fixture-bucket"
        return [
            {
                "Contents": [
                    {"Key": key, "Size": len(self.files[key])}
                    for key in sorted(self.files)
                    if key.startswith(Prefix)
                ]
            }
        ]

    def get_object(self, *, Bucket: str, Key: str) -> dict:
        assert Bucket == "synthetic-fixture-bucket"
        return {"Body": io.BytesIO(self.files[Key])}


def single_report(scope: dict) -> str:
    account = scope["accounts"][0]
    fake = FixtureS3(FIXTURES / "accounts" / account["account_id"])
    with (
        patch.object(single.boto3, "client", return_value=fake),
        patch.dict(
            os.environ,
            {
                "AIML_ASSESSMENT_BUCKET_NAME": "synthetic-fixture-bucket",
                "AISF_REPORT_TIMESTAMP": scope["timestamp"],
            },
        ),
    ):
        result = single.get_assessment_results(
            account["execution_id"],
            account["account_id"],
            expected_regions=account["regions"],
        )
        original = {
            "ResolvedRegions": {"regions": account["regions"]},
            "ServiceSelection": scope["service_selection"],
            "enableResponsibleAIGRC": scope["enable_grc"],
            "enableOWASP": scope["enable_owasp"],
            "enableAISF": scope["enable_aisf"],
        }
        try:
            single.validate_assessment_artifacts(
                result, account["execution_id"], original
            )
        except ValueError:
            # This fixture intentionally lacks the selected AgentCore west CSV.
            if not result["artifact_issues"]:
                raise
        return single.generate_html_report(
            result,
            show_finserv=scope["enable_grc"],
            service_selection=scope["service_selection"],
            enable_aisf=scope["enable_aisf"],
        )


def products() -> dict[Path, bytes]:
    scope = json.loads((FIXTURES / "scope.json").read_text())
    single_html = single_report(scope)
    multi_result = load_multi_account_results(
        FIXTURES / "accounts",
        scope_manifest=scope,
        service_selection=scope["service_selection"],
        show_finserv=scope["enable_grc"],
        enable_owasp=scope["enable_owasp"],
        enable_aisf=scope["enable_aisf"],
        timestamp=scope["timestamp"],
    )
    html_by_mode = {
        "single_account": single_html,
        "multi_account": render_multi_account_report(multi_result),
    }
    outputs = {}
    summaries = {}
    for mode, html in html_by_mode.items():
        html = re.sub(r"(?m)^[ \t]+$", "", html)
        register = json.loads(
            re.search(
                r'<script[^>]*id="aisf-data"[^>]*>(.*?)</script>', html, re.S
            ).group(1)
        )
        assert register["schema_version"] == 2
        assert register["view"] == "automated-check-results"
        assert "controls" not in register
        assert register["scope"]["enable_aisf"] is True
        assert all(register["scope"]["source_selection"].values())
        observations = [check["observation"] for check in register["checks"]]
        failed_sources = {
            source_check(row)
            for row in observations
            if value(row, "Status") == "Failed"
        }
        assert {
            "BR-21",
            "SM-18",
            "AC-20",
            "AR-03",
            "AG-25",
            "FS-51",
            "OW-11",
        } <= failed_sources
        assert any(
            source_check(row) == "FS-57" and value(row, "Status") == "N/A"
            for row in observations
        )
        assert any(
            source_check(row) == "FS-51" and row.get("source_presentations")
            for row in observations
        )
        assert any(
            check["source_check_id"] == "AG-26"
            and not check["aisf_links"]
            and check["unmapped_reason"]
            for check in register["checks"]
        )
        assert any(
            check["source_check_id"] == "FS-57"
            and check["status"] == "N/A"
            and check["result_kind"] == "source-advisory"
            for check in register["checks"]
        )
        assert not any(
            gap["kind"] == "source-absent" and gap["owner"] == "responsible-ai-grc"
            for gap in register["gaps"]
        )
        outputs[SAMPLES / f"aisf_{mode}.html"] = html.encode()
        outputs[SAMPLES / f"aisf_{mode}.json"] = encoded(register)
        summaries[mode] = register["summary"]
    sources = sorted(
        {
            *FIXTURES.rglob("*"),
            *REPORT.glob("*.py"),
            *REPORT.glob("aisf_catalog/*.json"),
            ROOT / "consolidate_html_reports.py",
            Path(__file__).resolve(),
        }
    )
    provenance = {
        "schema_version": 1,
        "generated_at": scope["timestamp"],
        "source_revision": load_catalog()["manifest"]["source_revision"],
        "synthetic": True,
        "regenerate": ".venv/bin/python tools/generate_aisf_samples.py",
        "check": ".venv/bin/python tools/generate_aisf_samples.py --check",
        "inputs": {
            str(path.relative_to(ROOT)): digest(path.read_bytes())
            for path in sources
            if path.is_file()
        },
        "outputs": {
            str(path.relative_to(ROOT)): digest(data) for path, data in outputs.items()
        },
        "summaries": summaries,
        "primary_samples": {
            "files": {
                name: digest((SAMPLES / name).read_bytes())
                for name in (
                    "security_assessment_single_account.html",
                    "security_assessment_multi_account.html",
                    "security_assessment_changes.html",
                )
            },
            "meaning": "The primary single-account, multi-account, and changes pages contain anonymized assessment results. They are maintained together with the documented anonymization workflow; this generator records their hashes without rewriting them.",
        },
    }
    outputs[SAMPLES / "aisf-provenance.json"] = encoded(provenance)
    return outputs


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for path, data in products().items():
        if args.check:
            if not path.exists() or path.read_bytes() != data:
                raise SystemExit(f"Stale AISF sample: {path.relative_to(ROOT)}")
        else:
            path.write_bytes(data)
    print(
        "Both AISF samples: native check outcomes and collection gaps; provenance verified."
    )


if __name__ == "__main__":
    main()
