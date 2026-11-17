"""Verify the frozen source review against collectors, catalogs and canonical IDs."""

import ast
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECURITY = ROOT / "aiml-security-assessment/functions/security"
CATALOG = SECURITY / "generate_consolidated_report/aisf_catalog"
PACKAGES = {
    "BR": "bedrock",
    "SM": "sagemaker",
    "AC": "agentcore",
    "AR": "agent_registry",
    "FS": "responsible_ai_grc",
    "OW": "owasp",
}
EXPECTED_FAMILIES = {
    "BR": 57,
    "SM": 42,
    "AC": 53,
    "AR": 10,
    "FS": 64,
    "OW": 2,
    "AG": 5,
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def assignment(tree: ast.Module, name: str) -> dict:
    for node in tree.body:
        targets = (
            node.targets
            if isinstance(node, ast.Assign)
            else [node.target]
            if isinstance(node, ast.AnnAssign)
            else []
        )
        if any(
            isinstance(target, ast.Name) and target.id == name for target in targets
        ):
            return ast.literal_eval(node.value)
    raise ValueError(f"Missing producer assignment: {name}")


def literal_ids(tree: ast.Module, family: str) -> set[str]:
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and re.fullmatch(rf"{family}-\d{{2}}", node.value)
        and not node.value.endswith("-00")
    }


def verify() -> dict:
    mapping = json.loads((CATALOG / "mapping.json").read_text())
    inventory = json.loads((CATALOG / "check_inventory.json").read_text())
    canonical = json.loads((CATALOG / "controls.json").read_text())
    classifications = json.loads((CATALOG / "classification.json").read_text())[
        "controls"
    ]
    manifest = json.loads((CATALOG / "manifest.json").read_text())
    require(
        inventory["source_revision"]
        == mapping["source_revision"]
        == manifest["source_revision"],
        "Catalog/review revision mismatch",
    )
    trees = {}
    tree_paths = {}
    hashes = {}
    native = {}
    for family, package in PACKAGES.items():
        path = SECURITY / f"{package}_assessments/app.py"
        relative = str(path.relative_to(ROOT))
        trees[family] = tree_paths[relative] = ast.parse(path.read_text())
        hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        native[family] = literal_ids(trees[family], family)
    require(
        hashes == inventory["source_file_sha256"] == mapping["source_file_sha256"],
        "Source files changed since predicate review",
    )
    aliases = {}
    for family, name in (
        ("BR", "AGENTIC_BEDROCK_CHECK_MAPPINGS"),
        ("AC", "AGENTIC_AGENTCORE_CHECK_MAPPINGS"),
        ("AR", "AGENTIC_AGENT_REGISTRY_CHECK_MAPPINGS"),
    ):
        for source, projection in assignment(trees[family], name).items():
            require(projection["check_id"] not in aliases, "Duplicate AG alias")
            aliases[projection["check_id"]] = source
    native["AG"] = (
        set.union(*(literal_ids(trees[family], "AG") for family in ("BR", "AC", "AR")))
        - aliases.keys()
    )
    categories = defaultdict(list)
    category_edges = defaultdict(list)
    owasp = assignment(trees["OW"], "OWASP_CHECK_MAPPINGS")
    for source, projections in owasp.items():
        for projection in projections:
            alias = projection["check_id"]
            categories[alias].append(source)
            category_edges[alias].append(
                (source, tuple(projection.get("source_finding_prefixes", [])))
            )
    native["OW"] -= categories.keys()
    require(
        {family: len(ids) for family, ids in native.items()} == EXPECTED_FAMILIES,
        "Native source family inventory changed; review additions/removals",
    )
    require(aliases == mapping["source_aliases"], "AG alias relation changed")
    require(
        {alias: sorted(sources) for alias, sources in categories.items()}
        == mapping["category_aliases"],
        "OWASP category relation changed",
    )
    native_ids = set.union(*native.values())
    expected_ids = native_ids | aliases.keys() | categories.keys()
    checks = {record["check_id"]: record for record in inventory["checks"]}
    require(
        len(checks) == len(inventory["checks"]) == 277, "Duplicate/missing review IDs"
    )
    require(set(checks) == expected_ids, "Source/presentation review ID mismatch")
    catalog_text = "\n".join(
        (ROOT / "docs" / name).read_text()
        for name in (
            "SECURITY_CHECKS.md",
            "SECURITY_CHECKS_RESPONSIBLE_AI_GRC.md",
            "SECURITY_CHECKS_OWASP.md",
        )
    )
    documented = set(re.findall(r"\b(?:BR|SM|AC|AR|AG|FS|OW)-\d{2}\b", catalog_text))
    require(
        expected_ids <= documented, "A reviewed ID is absent from the check catalogs"
    )
    canonical_ids = {control["id"] for control in canonical["controls"]}
    controls = {control["control_id"]: control for control in mapping["controls"]}
    require(
        len(controls) == len(mapping["controls"]) == 218
        and set(controls) == canonical_ids,
        "Canonical control review ID mismatch",
    )
    edges = defaultdict(set)
    edge_details = {}
    for control_id, control in controls.items():
        sources = control["source_checks"]
        require(
            control["coverage"] == ("partial" if sources else "absent"),
            f"Unsupported whole-control proof: {control_id}",
        )
        require(
            len({source["check_id"] for source in sources}) == len(sources),
            "Duplicate edge",
        )
        for source in sources:
            check_id = source["check_id"]
            require(check_id in native_ids, f"Alias/unknown native source: {check_id}")
            require(
                source["failure_proves_violation"] is False,
                "Unreviewed violation claim",
            )
            require(bool(source["canonical_relation"]), f"Missing relation: {check_id}")
            require(bool(source["limitations"]), f"Missing proof gap: {check_id}")
            edges[check_id].add(control_id)
            edge_details[(check_id, control_id)] = source
    for check_id, record in checks.items():
        require(
            record["family"] == check_id.split("-")[0], f"Family mismatch: {check_id}"
        )
        require(bool(record["predicate"]), f"Missing source predicate: {check_id}")
        require(bool(record["code_witnesses"]), f"Missing code witness: {check_id}")
        for witness in record["code_witnesses"]:
            tree = tree_paths.get(witness["path"])
            require(tree is not None, f"Unreviewed witness path: {check_id}")
            found = False
            for node in ast.walk(tree):
                names = (
                    [node.name]
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    else [
                        target.id
                        for target in (
                            node.targets
                            if isinstance(node, ast.Assign)
                            else [node.target]
                            if isinstance(node, ast.AnnAssign)
                            else []
                        )
                        if isinstance(target, ast.Name)
                    ]
                )
                if (
                    witness["function"] in names
                    and node.lineno == witness["line"]
                    and node.end_lineno == witness["end_line"]
                ):
                    found = True
                    break
            require(found, f"Stale code witness: {check_id} {witness['function']}")
        if check_id in native_ids:
            require(
                record["kind"] == "native", f"Native classified as alias: {check_id}"
            )
            actual = {link["control_id"] for link in record["canonical_links"]}
            require(
                actual == edges.get(check_id, set()),
                f"Inventory/edge mismatch: {check_id}",
            )
            for link in record["canonical_links"]:
                source = edge_details[(check_id, link["control_id"])]
                require(
                    link["coverage"] == "partial"
                    and link.get("observation_filters", {})
                    == source.get("observation_filters", {})
                    and all(
                        link.get(field) == source.get(field)
                        for field in (
                            "canonical_relation",
                            "limitations",
                            "failure_proves_violation",
                        )
                    ),
                    f"Inventory/edge proof mismatch: {check_id} {link['control_id']}",
                )
            require(
                record["disposition"] == ("partial" if actual else "excluded"),
                f"Wrong review disposition: {check_id}",
            )
            require(
                actual or bool(record["exclusion_reason"]),
                f"Unreviewed exclusion: {check_id}",
            )
        else:
            require(
                record["kind"] == "alias", f"Projection classified native: {check_id}"
            )
            expected_sources = (
                [aliases[check_id]]
                if check_id in aliases
                else sorted(categories[check_id])
            )
            require(
                record["source_check_ids"] == expected_sources,
                f"Alias source: {check_id}",
            )
            if check_id in categories:
                actual = sorted(
                    (edge["source_check_id"], tuple(edge["source_finding_prefixes"]))
                    for edge in record["source_edges"]
                )
                require(
                    actual == sorted(category_edges[check_id]),
                    f"Alias filters: {check_id}",
                )
    counts = inventory["counts"]
    require(counts == mapping["counts"], "Review count copies differ")
    mapped_controls = sum(
        bool(control["source_checks"]) for control in controls.values()
    )
    expected_counts = {
        "canonical_controls": 218,
        "mapped_controls": mapped_controls,
        "unmapped_controls": 218 - mapped_controls,
        "source_checks": len(edges),
        "source_edges": sum(map(len, edges.values())),
        "complete": 0,
        "partial": mapped_controls,
        "absent": 218 - mapped_controls,
        "native_checks_reviewed": 233,
        "native_checks_excluded": 233 - len(edges),
        "presentation_aliases": len(aliases) + len(categories),
        "presentation_ids": 277,
        "agentic_aliases": len(aliases),
        "owasp_categories": len(categories),
        "owasp_category_sources": len(owasp),
        "owasp_category_edges": sum(map(len, owasp.values())),
        "machine_controls_without_mapped_evidence": sorted(
            control_id
            for control_id, control in controls.items()
            if not control["source_checks"]
            and classifications[control_id]["machine_checkable"]
        ),
        "non_machine_control_with_partial_evidence": sorted(
            control_id
            for control_id, control in controls.items()
            if control["source_checks"]
            and not classifications[control_id]["machine_checkable"]
        ),
    }
    require(
        all(counts[key] == value for key, value in expected_counts.items()),
        "Declared review counts differ from source inventory",
    )
    family_counts = {
        family: {
            "native": len(ids),
            "mapped": len(ids & edges.keys()),
            "excluded": len(ids - edges.keys()),
            "canonical_edges": sum(len(edges.get(check_id, set())) for check_id in ids),
            "aliases": sum(
                record["family"] == family and record["kind"] == "alias"
                for record in checks.values()
            ),
        }
        for family, ids in native.items()
    }
    require(
        inventory["family_counts"] == family_counts,
        "Source family review counts differ",
    )
    require(
        Counter(
            record["collector_status"]
            for record in checks.values()
            if record["kind"] == "native"
        )
        == {"active": 232, "inactive": 1}
        and checks["BR-14"]["collector_status"] == "inactive",
        "Inactive BR-14 evidence was lost",
    )
    return expected_counts


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2, sort_keys=True))
