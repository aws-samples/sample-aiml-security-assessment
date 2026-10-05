#!/usr/bin/env python3
"""Generate the IAM action access-level tables the IAM-09 legs read.

For each IAM namespace an assessment reads, the table lists, per resource type,
the actions that read it and the actions that write it, as the AWS service
authorization reference publishes them. An action is a write when its
annotations mark it IsWrite or IsPermissionManagement and not IsTaggingOnly,
and a read when none of the three is set. Tagging actions are left out. Only resource types
with at least one read and one write are kept, because a single grant can merge
the two only there. Each type also carries its ARN formats with every
${Variable} replaced by "*", so a consumer can tell which types a
resource-scoped statement reaches.

Source: https://servicereference.us-east-1.amazonaws.com/v1/<service>/<service>.json

Output, one file per package:
  aiml-security-assessment/functions/security/<package>/iam_access_levels.json

Usage:
    python generate_iam_access_levels.py          # fetch and write the files
    python generate_iam_access_levels.py --check  # exit 1 if a file is stale
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
SECURITY = os.path.join(REPO_ROOT, "aiml-security-assessment", "functions", "security")
SOURCE = "https://servicereference.us-east-1.amazonaws.com/v1/{0}/{0}.json"

REGISTRY_RESOURCE_TYPES = {"registry", "registry-record"}

# package -> [(namespace, resource-type filter)]. None keeps every type.
PACKAGES = {
    "bedrock_assessments": [
        ("bedrock", None),
        ("s3", None),
        ("dynamodb", None),
        ("s3vectors", None),
    ],
    "sagemaker_assessments": [("sagemaker", None)],
    # AR-01 reads the registry resource types under both namespaces.
    "agentcore_assessments": [("bedrock-agentcore", "exclude-registry")],
    "agent_registry_assessments": [
        ("agent-registry", None),
        ("bedrock-agentcore", "registry-only"),
    ],
}


def _fetch(service: str) -> dict:
    with urllib.request.urlopen(SOURCE.format(service), timeout=30) as response:  # nosec B310
        return json.load(response)


def _table(reference: dict, scope: str | None) -> dict:
    arns = {
        resource["Name"]: sorted(
            re.sub(r"\$\{[^}]*\}", "*", arn) for arn in resource.get("ARNFormats", [])
        )
        for resource in reference.get("Resources", [])
    }
    types: dict = {}
    for action in reference.get("Actions", []):
        props = action.get("Annotations", {}).get("Properties", {})
        tagging = bool(props.get("IsTaggingOnly"))
        write = bool(props.get("IsWrite") or props.get("IsPermissionManagement"))
        read = not (write or tagging)
        write = write and not tagging
        for resource in action.get("Resources") or []:
            name = resource["Name"]
            if scope == "exclude-registry" and name in REGISTRY_RESOURCE_TYPES:
                continue
            if scope == "registry-only" and name not in REGISTRY_RESOURCE_TYPES:
                continue
            entry = types.setdefault(name, {"read": set(), "write": set()})
            if read:
                entry["read"].add(action["Name"])
            if write:
                entry["write"].add(action["Name"])
    return {
        name: {
            "arns": arns.get(name) or ["*"],
            "read": sorted(entry["read"]),
            "write": sorted(entry["write"]),
        }
        for name, entry in sorted(types.items())
        if entry["read"] and entry["write"]
    }


def build() -> dict:
    references: dict = {}
    out = {}
    for package, namespaces in PACKAGES.items():
        services = {}
        for namespace, scope in namespaces:
            if namespace not in references:
                references[namespace] = _fetch(namespace)
            services[namespace] = _table(references[namespace], scope)
        out[package] = {
            "source": SOURCE.format("<service>"),
            "versions": {ns: references[ns].get("Version") for ns, _ in namespaces},
            "services": services,
        }
    return out


def _render(table: dict) -> str:
    return json.dumps(table, indent=1, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    stale = []
    for package, table in build().items():
        path = os.path.join(SECURITY, package, "iam_access_levels.json")
        rendered = _render(table)
        if args.check:
            with open(path, encoding="utf-8") as handle:
                if handle.read() != rendered:
                    stale.append(path)
        else:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(rendered)
    for path in stale:
        print(f"stale: {path}", file=sys.stderr)
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
