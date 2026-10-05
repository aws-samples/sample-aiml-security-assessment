#!/usr/bin/env python3
"""Generate the ARN sub-resource table the resource-scope legs read.

A Resource wildcard stays inside one named resource only when the ARN names
that resource in full and the wildcard sits in a documented sub-resource of
it, such as table/orders/index/* or function:tool:*. The AWS service
authorization reference publishes every resource type's ARN format. Where a
format puts a character right after its first ${Variable} (table/${TableName}
/index/${IndexName}, log-group:${LogGroupName}:log-stream:${LogStreamName}),
that variable is a parent name ending at that character, and the rest of the
ARN is a sub-resource. A format whose first variable runs to the end
(role/${RoleNameWithPath}, secret:${SecretId}, parameter/${...}) has no
sub-resource, so its name may hold "/" and any wildcard in it widens.

Only "/", ":" and "+" count as a sub-resource separator. A "-" after the first
variable (framework:${FrameworkName}-${FrameworkId}) joins a name to a
generated suffix of the same resource, so a wildcard there is a partial name.

The table maps each ARN service segment to the literal text before the first
variable and the separators seen after it, for every format that has one.

Source: https://servicereference.us-east-1.amazonaws.com/v1/service-list.json
and each service's JSON it lists.

Output, one identical file per package:
  aiml-security-assessment/functions/security/<package>/arn_sub_resources.json

Usage:
    python generate_arn_sub_resources.py          # fetch and write the files
    python generate_arn_sub_resources.py --check  # exit 1 if a file is stale
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
SERVICE_LIST = "https://servicereference.us-east-1.amazonaws.com/v1/service-list.json"
PACKAGES = ("bedrock_assessments", "agentcore_assessments")
SEPARATORS = "/:+"
VARIABLE = re.compile(r"\$\{[^}]*\}")


def _fetch(url: str) -> object:
    with urllib.request.urlopen(url, timeout=30) as response:  # nosec B310
        return json.load(response)


def build() -> dict:
    services: dict = {}
    for entry in _fetch(SERVICE_LIST):
        reference = _fetch(entry["url"])
        for resource in reference.get("Resources", []):
            for arn in resource.get("ARNFormats", []):
                parts = arn.split(":", 5)
                if len(parts) < 6 or "$" in parts[2]:
                    continue
                first = VARIABLE.search(parts[5])
                if not first:
                    continue
                after = parts[5][first.end() : first.end() + 1]
                if after and after in SEPARATORS:
                    prefixes = services.setdefault(parts[2].lower(), {})
                    prefix = parts[5][: first.start()]
                    prefixes[prefix] = "".join(
                        sorted(set(prefixes.get(prefix, "")) | {after})
                    )
    return {"source": SERVICE_LIST, "services": services}


def _render(table: dict) -> str:
    return json.dumps(table, indent=1, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = _render(build())
    stale = []
    for package in PACKAGES:
        path = os.path.join(SECURITY, package, "arn_sub_resources.json")
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
