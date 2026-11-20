#!/usr/bin/env python3
"""Generate the Responsible AI GRC provenance record.

Reconciles the three provenance artifacts that already exist in this repository
rather than inventing a fourth:

  1. ``docs/SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md`` — per-check
     ``[Guide §N.N.N]`` tags, with ``, extension`` marking a control that is
     consistent with the guide's risk description but not verbatim in it.
  2. ``responsible_ai_grc_assessments/app.py`` docstrings — the
     ``COMPLIANCE_PLACEHOLDER`` list, which is the in-code regulatory
     provenance.
  3. ``responsible_ai_grc_assessments/app.py`` ``COMPLIANCE_MAP`` — the values
     actually shipped in the ``Compliance_Frameworks`` CSV column.

Output: ``aiml-security-assessment/functions/security/responsible_ai_grc_assessments/provenance.json``

This file is generated AND checked in. ``test_provenance.py`` regenerates it and
fails on any diff, so the record cannot drift from the code and docs.

Deliberate design decision: fields that require human authorship are emitted as
null and listed in ``review_required`` rather than being filled with generated
prose. This record exists to eliminate unfounded claims; fabricating 64
rationales or PDF page numbers would reintroduce exactly that problem. Nulls are
honest and machine-checkable; invented text is neither.

Usage:
    python generate_provenance.py            # write the file
    python generate_provenance.py --check    # exit 1 if the file is stale
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
APP_PATH = os.path.join(
    REPO_ROOT,
    "aiml-security-assessment",
    "functions",
    "security",
    "responsible_ai_grc_assessments",
    "app.py",
)
DOC_PATH = os.path.join(REPO_ROOT, "docs", "SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md")
OUT_PATH = os.path.join(
    REPO_ROOT,
    "aiml-security-assessment",
    "functions",
    "security",
    "responsible_ai_grc_assessments",
    "provenance.json",
)

# The normative source for the FS-* controls. Referred to in documentation as
# "the AWS GRC User Guide" so the shorthand never collides with the capability
# name "Responsible AI GRC".
PRIMARY_SOURCE = {
    "source_id": "aws-grc-user-guide",
    "source_title": (
        "AWS User Guide to Governance, Risk, and Compliance for Responsible AI Adoption"
    ),
    "source_shorthand": "the AWS GRC User Guide",
    "source_version_or_date": "updated 2026-05-13",
    "source_url": (
        "https://d1.awsstatic.com/onedam/marketing-channels/website/aws/en_US/"
        "whitepapers/compliance/"
        "AWS-User-Guide-Governance-Risk-Compliance-for-Responsible-AI-Adoption-"
        "Financial-Services.pdf"
    ),
}

SECONDARY_SOURCE = {
    "source_id": "aws-finserv-genai-risk-guide",
    "source_title": "Generative AI risks and mitigations for financial services",
    "source_version_or_date": "(c) 2026",
    "source_url": (
        "https://d1.awsstatic.com/onedam/marketing-channels/website/public/"
        "global-FinServ-ComplianceGuide-GenAIRisks-public.pdf"
    ),
}

# Fields that require human authorship per control. Emitted as null with the key
# recorded in review_required so CI can report coverage without inventing text.
#
# source_page is deliberately NOT in this list. The repository's provenance
# granularity is the guide SECTION (§1.2.9), which is present and machine
# checkable. Page numbers exist only in the source PDF and would have to be
# hand-transcribed; gating CI on them would make the gate permanently red
# without improving traceability. Section granularity is the contract.
HUMAN_AUTHORED_FIELDS = ("derivation_rationale",)


def _load_app_source() -> str:
    with open(APP_PATH) as handle:
        return handle.read()


def _compliance_map(tree: ast.Module) -> dict:
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.AnnAssign)
            and getattr(node.target, "id", "") == "COMPLIANCE_MAP"
        ):
            return {
                ast.literal_eval(k): ast.literal_eval(v)
                for k, v in zip(node.value.keys, node.value.values)
            }
    raise SystemExit("COMPLIANCE_MAP not found in app.py")


def _docstring_provenance(tree: ast.Module) -> dict:
    """Map check id -> {frameworks, unsupported_assertions, function}.

    Frameworks are attributed only to the check id in the LEADING "FS-NN —"
    position of a docstring. A cross-reference elsewhere in the text (for example
    "as with FS-08") must not transfer frameworks to another control.
    """
    out: dict = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        doc = ast.get_docstring(node) or ""
        placeholder = re.search(r"COMPLIANCE_PLACEHOLDER:\s*\[([^\]]*)\]", doc)
        leading = re.search(r"^\s*(FS-\d{2})\s*[—\-]", doc, re.M)
        if not (placeholder and leading):
            continue
        check_id = leading.group(1)
        entry = out.setdefault(
            check_id,
            {"frameworks": [], "unsupported_assertions": [], "functions": []},
        )
        for token in placeholder.group(1).split(","):
            token = token.strip()
            if token and token not in entry["frameworks"]:
                entry["frameworks"].append(token)
        entry["functions"].append(node.name)
        entry["unsupported_assertions"].extend(_not_asserted(doc))
    return out


def _not_asserted(doc: str) -> list:
    """Extract the bullet list under a 'NOT asserted' heading in a docstring.

    Only the six corrected controls carry these. They are real authored content,
    so they are used rather than nulled.
    """
    match = re.search(
        r"(?:Deliberately NOT asserted|Not proven)[^:]*:\s*\n(.*?)(?:\n\s*\n|\Z)",
        doc,
        re.S,
    )
    if not match:
        return []
    items = []
    for raw in match.group(1).split("\n"):
        line = raw.strip()
        if line.startswith("- "):
            items.append(re.sub(r"\s+", " ", line[2:]).rstrip(","))
        elif items and line and not line.startswith("-"):
            items[-1] = f"{items[-1]} {line}".strip().rstrip(",")
    return items


def _doc_guide_refs() -> dict:
    """Map check id -> {section, derivation_type, excerpt} from the docs table."""
    with open(DOC_PATH) as handle:
        text = handle.read()

    refs: dict = {}
    current = None
    for line in text.split("\n"):
        heading = re.match(r"^####\s+(FS-\d{2})\s*[—\-]\s*(.*)$", line)
        if heading:
            current = heading.group(1)
            refs.setdefault(
                current,
                {
                    "title": heading.group(2).strip(),
                    "source_section": None,
                    "derivation_type": None,
                    "source_excerpt_summary": None,
                    "inspected_aws_evidence": None,
                },
            )
            continue
        if not current:
            continue
        if line.startswith("| Guide ref |"):
            # The tag takes three shapes in the docs, all handled here:
            #   [Guide §1.2.9]
            #   [Guide §1.2.9, extension]
            #   [Guide §1.2.9, §1.2.1, §1.2.2]        (multi-section)
            #   [Guide §1.2.6 — Practical guidance]    (qualified)
            bracket = re.search(r"\[Guide\s+([^\]]*)\]", line)
            if bracket:
                inner = bracket.group(1)
                sections = re.findall(r"§\s*([0-9]+(?:\.[0-9]+)*)", inner)
                if sections:
                    refs[current]["source_section"] = ", ".join(
                        f"§{s}" for s in sections
                    )
                refs[current]["derivation_type"] = (
                    "project-extension"
                    if re.search(r"\bextension\b", inner, re.I)
                    else "direct-derived"
                )
            body = line.split("|")[2] if line.count("|") >= 3 else ""
            excerpt = re.sub(r"\[Guide\s+[^\]]*\]\s*—?\s*", "", body)
            excerpt = re.sub(r"\s+", " ", excerpt).strip()
            refs[current]["source_excerpt_summary"] = excerpt[:400] or None
        elif line.startswith("| Detection |"):
            body = line.split("|")[2] if line.count("|") >= 3 else ""
            refs[current]["inspected_aws_evidence"] = (
                re.sub(r"\s+", " ", body).strip()[:600] or None
            )
    return refs


def build_record() -> dict:
    source = _load_app_source()
    tree = ast.parse(source)
    compliance_map = _compliance_map(tree)
    code_prov = _docstring_provenance(tree)
    doc_refs = _doc_guide_refs()

    controls = []
    for check_id in sorted(compliance_map):
        code = code_prov.get(check_id, {})
        doc = doc_refs.get(check_id, {})
        shipped = [t.strip() for t in compliance_map[check_id].split("|") if t.strip()]
        review_required = [field for field in HUMAN_AUTHORED_FIELDS]
        for field in ("source_section", "derivation_type", "inspected_aws_evidence"):
            if not doc.get(field):
                review_required.append(field)
        if not code.get("unsupported_assertions"):
            review_required.append("unsupported_assertions")

        controls.append(
            {
                "check_id": check_id,
                "title": doc.get("title"),
                "source_id": PRIMARY_SOURCE["source_id"],
                "source_title": PRIMARY_SOURCE["source_title"],
                "source_version_or_date": PRIMARY_SOURCE["source_version_or_date"],
                "source_url": PRIMARY_SOURCE["source_url"],
                "source_section": doc.get("source_section"),
                "source_page": None,
                "derivation_type": doc.get("derivation_type"),
                "source_excerpt_summary": doc.get("source_excerpt_summary"),
                "derivation_rationale": None,
                "inspected_aws_evidence": doc.get("inspected_aws_evidence"),
                "unsupported_assertions": code.get("unsupported_assertions") or [],
                "manual_review_requirements": code.get("unsupported_assertions") or [],
                "implementing_functions": code.get("functions", []),
                "regulatory_mapping_source": code.get("frameworks", []),
                "regulatory_mapping_shipped": shipped,
                "regulatory_mapping_status": "preliminary",
                "review_required": sorted(set(review_required)),
                "last_verified_date": "2026-08-07",
            }
        )

    # FS-00 is emitted at runtime but is not a control and is absent from both
    # the registry and COMPLIANCE_MAP. Recorded explicitly so registry-based
    # audits cannot miss it.
    controls.insert(
        0,
        {
            "check_id": "FS-00",
            "title": "Regional Scope Not Applicable",
            "source_id": None,
            "source_title": None,
            "source_version_or_date": None,
            "source_url": None,
            "source_section": None,
            "source_page": None,
            "derivation_type": "project-extension",
            "source_excerpt_summary": None,
            "derivation_rationale": (
                "Not a control. Emitted by _no_regional_genai_resources_row() as a "
                "visible N/A row when a target region has no GenAI resource "
                "footprint, so the report distinguishes 'not applicable here' from "
                "'not assessed'."
            ),
            "inspected_aws_evidence": (
                "Absence of regional Bedrock, AgentCore, and SageMaker resources."
            ),
            "unsupported_assertions": [],
            "manual_review_requirements": [],
            "implementing_functions": ["_no_regional_genai_resources_row"],
            "regulatory_mapping_source": [],
            "regulatory_mapping_shipped": [],
            "regulatory_mapping_status": "not-applicable",
            "not_a_control": True,
            "review_required": [],
            "last_verified_date": "2026-08-07",
        },
    )

    return {
        "schema_version": "1.0",
        "capability": "Responsible AI GRC",
        "capability_scope_qualifier": (
            "Cross-industry technical controls for AI governance, risk, and compliance"
        ),
        "generated_by": "generate_provenance.py",
        "generated_note": (
            "Generated and checked in. Regenerate with `python "
            "generate_provenance.py`; CI fails if this file is stale. Null fields "
            "require human authorship and are listed per control in "
            "review_required rather than filled with generated prose."
        ),
        "not_the_responsible_ai_lens": (
            "Responsible AI GRC is not the AWS Well-Architected Responsible AI "
            "Lens. The Lens (November 2025) is a separate architectural review "
            "framework with eight focus areas. These checks do not implement, "
            "validate, or measure conformance to it."
        ),
        "sources": [PRIMARY_SOURCE, SECONDARY_SOURCE],
        "control_count": len([c for c in controls if not c.get("not_a_control")]),
        "controls": controls,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if the checked-in file differs from a fresh generation",
    )
    args = parser.parse_args()

    record = build_record()
    rendered = json.dumps(record, indent=2, ensure_ascii=False) + "\n"

    if args.check:
        if not os.path.exists(OUT_PATH):
            print(f"MISSING: {OUT_PATH}", file=sys.stderr)
            return 1
        with open(OUT_PATH) as handle:
            existing = handle.read()
        if existing != rendered:
            print(
                "STALE: provenance.json differs from a fresh generation.\n"
                "Run: python generate_provenance.py",
                file=sys.stderr,
            )
            return 1
        print("provenance.json is current.")
        return 0

    with open(OUT_PATH, "w") as handle:
        handle.write(rendered)

    controls = record["controls"]
    total = len(controls)
    print(f"Wrote {OUT_PATH}")
    print(f"  controls: {record['control_count']} (plus FS-00, not a control)")
    print("  derived field coverage:")
    for field in (
        "source_section",
        "derivation_type",
        "source_excerpt_summary",
        "inspected_aws_evidence",
        "regulatory_mapping_source",
        "regulatory_mapping_shipped",
    ):
        present = sum(1 for c in controls if c.get(field))
        print(f"    {field:28s} {present}/{total}")
    extensions = [
        c["check_id"] for c in controls if c["derivation_type"] == "project-extension"
    ]
    print(f"  project-extension controls: {len(extensions)} {extensions}")
    authored = sum(1 for c in controls if c["unsupported_assertions"])
    print(f"  controls with authored unsupported_assertions: {authored}/{total}")
    pending = sorted({field for c in controls for field in c["review_required"]})
    print(f"  fields awaiting human authorship: {pending}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
