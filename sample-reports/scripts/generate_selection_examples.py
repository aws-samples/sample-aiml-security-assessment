"""Generate synthetic selection examples without calling AWS.

Run from the repository root with .venv/bin/python.
"""

from collections import Counter
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
SECURITY = ROOT / "aiml-security-assessment/functions/security"
sys.path.insert(0, str(SECURITY / "generate_consolidated_report"))
import report_template  # noqa: E402

sys.path.insert(0, str(SECURITY / "owasp_assessments"))
spec = importlib.util.spec_from_file_location(
    "selection_example_owasp", SECURITY / "owasp_assessments/app.py"
)
owasp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owasp)


def generate_examples():
    for name, mode, bedrock in (
        ("selection-bedrock", "single", True),
        ("selection-governance-only", "multi", False),
    ):
        selection = dict.fromkeys(report_template.CORE_SERVICE_LABELS, False)
        selection["bedrock"] = bedrock
        source = {
            "Check_ID": "FS-51",
            "Finding": "Synthetic GRC guardrail review",
            "Finding_Details": "Synthetic example: review the guardrail prompt-attack policy.",
            "Resolution": "Review the guardrail prompt-attack configuration.",
            "Reference": "https://docs.aws.amazon.com/bedrock/",
            "Severity": "Medium",
            "Status": "Failed",
            "Region": "us-east-1",
            "_service": "responsible-ai-grc",
            "account_id": "111122223333",
        }
        findings = [source]
        if bedrock:
            findings.append(
                {
                    **source,
                    "Check_ID": "BR-34",
                    "_service": "bedrock",
                    "Finding": "Synthetic prompt attack filter",
                    "Finding_Details": "Synthetic example: prompt attack filter configured.",
                    "Status": "Passed",
                    "Resolution": "No action required.",
                }
            )
            findings.append(
                {
                    **source,
                    "Check_ID": "AG-30",
                    "_service": "agentic",
                    "Finding": "Synthetic Bedrock-derived Agentic AI finding",
                    "Finding_Details": "Synthetic example: contextual lens evidence.",
                    "Status": "N/A",
                    "Severity": "Informational",
                }
            )
        for row in owasp.build_owasp_mapping_findings(
            [source], "us-east-1"
        ) + owasp.build_selection_coverage_findings(selection, "us-east-1"):
            normalized = {
                key: getattr(value, "value", value) for key, value in row.items()
            }
            findings.append(
                {**normalized, "_service": "owasp", "account_id": "111122223333"}
            )
        services = {
            service: []
            for service in (*selection, "agentic", "responsible-ai-grc", "owasp")
        }
        for row in findings:
            services[row["_service"]].append(row)
        stats = {}
        for service, rows in services.items():
            counts = Counter(row["Status"] for row in rows)
            stats[service] = {
                "passed": counts["Passed"],
                "failed": counts["Failed"],
                "na": counts["N/A"],
            }
        html = report_template.generate_html_report(
            findings,
            services,
            stats,
            mode=mode,
            account_id="111122223333",
            account_ids=["111122223333"],
            regions=["us-east-1"],
            timestamp="Synthetic selection example",
            service_selection=selection,
        )
        html = "\n".join(line.rstrip() for line in html.splitlines()) + "\n"
        (ROOT / "sample-reports" / f"{name}.html").write_text(html)


if __name__ == "__main__":
    generate_examples()
