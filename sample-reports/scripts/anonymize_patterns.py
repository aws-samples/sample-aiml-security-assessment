"""Patterns that find values from a real account in the sample reports.

capture_screenshots.py uses them to replace account-specific values (resource
IDs, the random parts of resource names, and names chosen in the source
account) with synthetic placeholders before the samples are committed.
tests/test_sample_reports.py uses them to check that none is left.
"""

from __future__ import annotations

import hashlib
import html
import re
import string
from dataclasses import dataclass

# Rows the report derives itself from other rows; parse_report leaves them out.
REPORT_DERIVED_PREFIXES = ("AISF",)

# --- reading a sample report ----------------------------------------------------

_TABLE_BODY = re.compile(
    r'<table id="findingsTable"[^>]*>.*?<tbody>(.*?)</tbody>', re.S
)
_ROW = re.compile(r"<tr ([^>]*)>(.*?)</tr>", re.S)
_ATTRIBUTE = re.compile(r'data-(\w+)="([^"]*)"')
_CODE_CELL = re.compile(r"<td><code>(.*?)</code></td>", re.S)
_FINDING = re.compile(r'<div class="col-domain">(.*?)</div>', re.S)
# A part's label: "Details", or on a changes page "Details (previous run)",
# "Details (current run)" and "Note".
_PART = re.compile(r"<div><strong>([^<]+)</strong><p>(.*?)</p></div>", re.S)
_DETAIL_PARTS = ("Details", "Details (previous run)", "Details (current run)", "Note")
_LINK = re.compile(r'<a href="([^"]*)"')
_SEVERITY = re.compile(r'<span class="severity [^"]*">(.*?)</span>', re.S)
_STATUS = re.compile(r'<span class="status [^"]*">(.*?)</span>', re.S)


@dataclass(frozen=True)
class SampleRow:
    """One row of a sample report's findings table.

    ``area`` is the report's own assessment area for the row (data-service).
    """

    area: str
    account_id: str
    region: str
    check_id: str
    finding: str
    details: str
    resolution: str
    reference: str
    severity: str
    status: str


def _text(value: str) -> str:
    return html.unescape(value)


def parse_report(text: str) -> list[SampleRow]:
    """Read the findings table of a sample page.

    Reads a main report written by report_template.py and a changes page
    written by assessment_history/render_changes.py, which share the table
    layout. A changes row's previous-run and current-run details, and its
    note, are joined into ``details``. Rows the report derives itself
    (REPORT_DERIVED_PREFIXES) are left out.
    """
    body = _TABLE_BODY.search(text)
    if body is None:
        raise ValueError("no findings table in the report")
    rows = []
    for attributes, cells in _ROW.findall(body.group(1)):
        account_id, region, check_id = _CODE_CELL.findall(cells)[:3]
        if _text(check_id).split("-", 1)[0].upper() in REPORT_DERIVED_PREFIXES:
            continue
        parts = dict(_PART.findall(cells))
        link = _LINK.search(parts.get("Reference", ""))
        rows.append(
            SampleRow(
                area=_text(dict(_ATTRIBUTE.findall(attributes))["service"]),
                account_id=_text(account_id),
                region=_text(region),
                check_id=_text(check_id),
                finding=_text(_FINDING.search(cells).group(1)),
                details="\n".join(
                    _text(parts[label]) for label in _DETAIL_PARTS if label in parts
                ),
                resolution=_text(parts["Resolution"]),
                reference=_text(link.group(1)) if link else "",
                severity=_text(_SEVERITY.search(cells).group(1)),
                status=_text(_STATUS.search(cells).group(1)),
            )
        )
    return rows


# --- values from the source account -------------------------------------------------

# Values in the sample reports that AWS or CloudFormation generated (resource
# IDs and the random parts of resource names) or that were chosen in the
# source account (resource names). capture_screenshots.py replaces them with
# made-up values of the same shape. In each pattern, group "v" is the value.
GENERATED_VALUE_KINDS = (
    (
        "UUID",
        r"(?<![0-9a-f])(?P<v>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
        r"[0-9a-f]{1,12})(?![0-9a-f])",
    ),
    (
        "AWS resource ID",
        r"\b(?:vpc|subnet|sgr|sg|eni|eigw|igw|rtbassoc|rtb|vpce|nat|acl|i|ami"
        r"|vol|snap|lt|tgw-attach|tgw-rtb|tgw|pcx|eipalloc|eipassoc|dopt|pl|vgw"
        r"|cgw|vpn|fsap|fs)-(?P<v>[0-9a-f]{17}|[0-9a-f]{8})\b",
    ),
    # GuardDuty detector and finding IDs, and the hash in a StackSets
    # execution role name ("stacksets-exec-<32 hex>").
    ("32-digit hex ID", r"(?<![0-9A-Za-z])(?P<v>[0-9a-f]{32})(?![0-9A-Za-z])"),
    # Container image layer digests ("sha256:<64 hex>").
    ("image digest", r"(?<=sha256:)(?P<v>[0-9a-f]{64})(?![0-9A-Za-z])"),
    # An account ID that lost its leading zero in a stack name
    # ("aiml-security-<11 digits>-..."), and the part of it left when
    # CloudFormation shortens the stack name in a role name.
    (
        "account ID without its leading zero",
        r"(?<=[a-z]-)(?P<v>\d{11})(?=-[A-Za-z])",
    ),
    (
        "shortened account ID in a stack name",
        r"(?<=-security-)(?P<v>\d{5})(?=-[A-Z])",
    ),
    # IAM Identity Center instance and permission set IDs, and the hash in an
    # AWSReservedSSO_ role name.
    ("16-digit hex ID", r"(?<![0-9A-Za-z])(?P<v>[0-9a-f]{16})(?![0-9A-Za-z])"),
    # IAM unique IDs and service-specific credential IDs; the prefix is kept.
    (
        "IAM unique ID",
        r"\b(?:AKIA|ASIA|AROA|AIDA|ANPA|AGPA|ACCA|ANVA|AIPA|APKA|ABIA)"
        r"(?P<v>[A-Z0-9]{12,20})\b",
    ),
    # The ID at the end of an ARN: a Bedrock agent, prompt, knowledge base or
    # policy, an OpenSearch Serverless collection, an inference profile.
    (
        "ID at the end of an ARN",
        r"(?<=/)(?P<v>(?=[A-Za-z0-9]*[0-9])(?=[A-Za-z0-9]*[A-Za-z])"
        r"[A-Za-z0-9]{10,20})(?![A-Za-z0-9./_-])",
    ),
    # AgentCore runtime and memory IDs ("<name>-<10 characters>").
    (
        "AgentCore ID after a name",
        r"(?<=[A-Za-z0-9_]-)(?P<v>(?=[A-Za-z0-9]*[0-9])(?=[A-Za-z0-9]*[A-Z])"
        r"(?=[A-Za-z0-9]*[a-z])[A-Za-z0-9]{10})(?![A-Za-z0-9])",
    ),
    # AWS Agent Registry IDs ("registry-<16 characters>", or in parentheses).
    (
        "Agent Registry ID",
        r"(?<=[(/-])(?P<v>(?=[A-Za-z0-9]*[0-9])(?=[A-Za-z0-9]*[A-Z])"
        r"(?=[A-Za-z0-9]*[a-z])[A-Za-z0-9]{16})(?![A-Za-z0-9])",
    ),
    (
        "API Gateway ID in parentheses",
        r"(?<=\()(?P<v>(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])[a-z0-9]{10})(?=\))",
    ),
    ("guardrail ID", r"(?<=ID: )(?P<v>[a-z0-9]{12})(?![A-Za-z0-9])"),
    (
        "Cognito app client ID",
        r"(?<![A-Za-z0-9])(?P<v>(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])[a-z0-9]{26})"
        r"(?![A-Za-z0-9])",
    ),
    # The random directory names uv gives its cache in a container image.
    ("uv cache directory", r"(?<=archive-v0/)(?P<v>[A-Za-z0-9_-]{8,40})(?=/)"),
    # Names the console generates: a knowledge base's vector store, an Amazon Q
    # investigation group role, a SageMaker Studio space, a Bedrock API key user.
    (
        "console-generated name suffix",
        r"(?:bedrock-knowledge-base|InvestigationGroup|quickstart-default)-"
        r"(?P<v>(?=[a-z0-9]*[0-9])[a-z0-9]{6})(?![a-z0-9])",
    ),
    # AgentCore gateway IDs ("<name>gateway-<10>", "<name>-gw-<10>").
    (
        "AgentCore gateway ID",
        r"(?:gateway|-gw)-(?P<v>[a-z0-9]{10})(?![A-Za-z0-9-])",
    ),
    # The random part of a CloudTrail bucket name the console creates.
    (
        "CloudTrail bucket suffix",
        r"(?<=cloudtrail-awslogs-\d{12}-)(?P<v>[a-z0-9]{8})(?=-)",
    ),
    ("API key user suffix", r"(?<=BedrockAPIKey-)(?P<v>[a-z0-9]{4})(?![a-z0-9])"),
    ("Organizations ID", r"\bo-(?P<v>[a-z0-9]{10,32})\b"),
    (
        "Organizations root ID",
        r"\br-(?P<v>(?=[a-z0-9]*[0-9])[a-z0-9]{4,32})\b",
    ),
    (
        "Cognito user pool ID",
        r"\b[a-z]{2}(?:-[a-z]+)+-\d_(?P<v>[A-Za-z0-9]{9})(?![A-Za-z0-9])",
    ),
    ("Bedrock ID", r"(?<=ID: )(?P<v>[A-Z0-9]{10})(?![A-Za-z0-9])"),
    ("Bedrock ID in parentheses", r"(?<=\()(?P<v>[A-Z0-9]{10})(?=\))"),
    (
        "Bedrock ID in a role name",
        r"(?<=[a-z]_)(?P<v>[A-Z0-9]{10,11})(?![A-Za-z0-9])",
    ),
    (
        "CloudFormation name suffix",
        r"(?<=[-_])(?P<v>(?=[A-Za-z0-9]*[0-9])(?=[A-Za-z0-9]*[A-Za-z])"
        r"[A-Za-z0-9]{12,13})(?![A-Za-z0-9])",
    ),
    # The same suffixes, and AgentCore memory IDs, when they hold no digit:
    # letters only, switching case at least three times.
    (
        "generated suffix without a digit",
        r"(?<=-)(?P<v>(?=(?:[A-Za-z]*?[a-z]+[A-Z]+){3})[A-Za-z]{10,13})"
        r"(?![A-Za-z0-9])",
    ),
    ("CloudFormation logical ID hash", r"(?<=[a-z])(?P<v>[0-9A-F]{8})(?=-)"),
    (
        "CloudFormation stack name part",
        r"(?<=[A-Z0-9]-)(?P<v>(?=[A-Z0-9]*[A-Z])[A-Z0-9]{8,10})(?=-)",
    ),
    (
        "generated lowercase suffix",
        r"(?<=-)(?P<v>(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])[a-z0-9]{8,11})"
        r"(?![A-Za-z0-9])",
    ),
    ("SageMaker domain ID", r"\bd-(?P<v>[a-z0-9]{12})\b"),
    (
        "generated bucket suffix",
        r"(?<=bucket-)(?P<v>(?=[a-z0-9]*[a-z])[a-z0-9]{12})(?![a-z0-9])",
    ),
    (
        "console role suffix",
        r"(?<=-role-)(?P<v>(?=[a-z0-9]*[a-z])[a-z0-9]{8})(?![a-z0-9])",
    ),
    (
        "conformance pack suffix",
        r"(?<=conformance-pack-)(?P<v>[a-z0-9]{6,12})(?![a-z0-9])",
    ),
    ("quick-start suffix", r"(?<=quick-start-)(?P<v>[a-z0-9]{4,8})(?![a-z0-9])"),
    (
        # Not a 12-digit account ID, as in "sagemaker-us-east-2-<account ID>":
        # account IDs are placeholders already, and the comparison keys on them.
        "suffix after a Region",
        # Nor the date in a model ID, as in "claude-sonnet-4-5-20250929-v1:0".
        r"(?<=-[0-9]-)(?!\d{12}(?![a-z0-9]))(?!20\d{6}-v\d)"
        r"(?P<v>(?=[a-z0-9]*[0-9])[a-z0-9]{4,12})(?![a-z0-9])",
    ),
    (
        "quoted resource name",
        r"(?i:\b(?:role|policy|trail|bucket|runtime|function|lambda|log group)"
        r"(?: name)?\s*[:=]?\s*['\"])(?P<v>[A-Za-z0-9][A-Za-z0-9_.@+=-]{2,127})['\"]",
    ),
    # Secrets Manager names may hold "/" ("team/app/key").
    (
        "quoted secret name",
        r"(?i:\bsecret\s*['\"])(?P<v>[A-Za-z0-9][A-Za-z0-9_./@+=-]{2,511})['\"]",
    ),
    # A name after its resource type, unquoted ("user build-cli", "event data
    # store Org-Data-DS"). Only a name with a "-", "_" or digit counts, so prose
    # ("user ARN", "function URLs") and AWS-created names are left alone.
    (
        "unquoted resource name",
        r"(?i:\b(?:function|user|group|cluster|event data store|role)\s+)"
        r"(?!AWS|Amazon|aws-|awseb-|eks-|arn:)"
        r"(?P<v>(?=[A-Za-z0-9_.@+=-]*[-_0-9])[A-Za-z0-9][A-Za-z0-9_.@+=-]*"
        r"[A-Za-z0-9])(?![A-Za-z0-9_.@+=:/-])",
    ),
    (
        "Lambda function name",
        r"\barn:(?:aws|aws-us-gov|aws-cn):lambda:[a-z0-9-]+:\d{12}:function:"
        r"(?P<v>[A-Za-z0-9_-]+)",
    ),
    (
        "IAM resource path",
        r"\barn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:"
        r"(?:role|policy|user)/(?P<v>[A-Za-z0-9_./+=,@-]*[A-Za-z0-9_+=,@-])",
    ),
    (
        "STS session name",
        r"\barn:(?:aws|aws-us-gov|aws-cn):sts::\d{12}:assumed-role/"
        r"[A-Za-z0-9_+=,.@-]+/(?P<v>[A-Za-z0-9_+=,.@-]*[A-Za-z0-9_+=,@-])",
    ),
    (
        "CloudTrail trail name",
        r"\barn:(?:aws|aws-us-gov|aws-cn):cloudtrail:[a-z0-9-]+:\d{12}:"
        r"trail/(?P<v>[A-Za-z0-9_.-]*[A-Za-z0-9_-])",
    ),
    (
        "S3 bucket name",
        r"\barn:(?:aws|aws-us-gov|aws-cn):s3:::(?P<v>"
        r"[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9])(?=/|[^A-Za-z0-9.-]|$)",
    ),
    ("Identity Center instance", r"\b(?P<v>ssoins-[0-9a-f]{16})(?![A-Za-z0-9])"),
    (
        "Identity Center role",
        r"\b(?P<v>AWSReservedSSO_[A-Za-z0-9_+=,.@-]+)\b",
    ),
)
NAME_KINDS = frozenset(
    {
        "quoted resource name",
        "quoted secret name",
        "unquoted resource name",
        "Lambda function name",
        "IAM resource path",
        "STS session name",
        "CloudTrail trail name",
        "S3 bucket name",
        "Identity Center instance",
        "Identity Center role",
        "source account name",
    }
)
# SHA-256 fingerprints of source-specific name stems. Keep the raw names out
# of this script and the published samples. A stem can begin after "-" or "_".
SOURCE_NAME_FINGERPRINTS = frozenset(
    {
        (8, "8758607d0bcaa8a6efc8f92aa63bf367a6f088001d8fd2f16d1583c356a1a23f"),
        (7, "54fb7f6e0735b34f6de7b9372d6da6c33b22050ae073d581e22e92b3c52cbd21"),
        (18, "0f00093800aaa65d92bb61f02ef6f4afc619ca66ce92073e54796c7ad34ca277"),
        (21, "3329bb23a9f9c3657602052184ec70ad9e918366b443b2f35ea388a0ee073263"),
        (13, "a123d5283b414537f6dde7f049d967a2a6cdee7c41f1609f07bb2e3f2aff6513"),
        (8, "999e2a35ced09b5ae03b18b54defe3fc6d808a5ce165bbf1666b3c84e049c9c3"),
        # Internal program, tool and project names, and personal projects.
        (4, "a1e0ea35dd02b75532066a4b85d4bdce4813c58ccf8e18bc7d45717403718086"),
        (4, "1997ee72332fe290da2ff18b36bcfe0a733d772424d6354629f57569cabd561a"),
        (5, "23247d21ffe16933d9897bc547b69e722fd20e703d0eaed666d099305e60defe"),
        (7, "d693c42022985c00752ed52eea900b418db1c36c0591f40e980d009a483d3414"),
        (10, "77bc7ae458d3f51ce0b1d1ec42ba0baead148559628c1ee45c887a2220f9d2e6"),
        (8, "f2f6c8f8e740ce0954cc2f80702c9725639c6ee41bb6c75a930619b837f9ec9f"),
        (8, "c182db28dc3e5f090b951513ba90e4001739822317fd0580b315566b85d48b9a"),
        (13, "34337d9546ff97f97dd89696eb948f628757811c5755bd14a6dd62fbfcd5578a"),
        (8, "d63f4a0cdaab52726d1ce895e4ac8c3507049e617b0a97d0a0af508bdad34a8d"),
        (11, "28e174396028f226b3bead259d19749205378d9204ce12fd9b1918ab6032a15d"),
        (10, "b5cf43ae07a7364e0c0ca9e838f01f278fc6a71c207a6f8c3de8d908608b2db1"),
    }
)
_NAME_TOKEN = re.compile(r"(?<![A-Za-z0-9_.@+=-])[A-Za-z0-9][A-Za-z0-9_.@+=-]+")


def source_account_names(text: str) -> list[tuple[int, int, str]]:
    """Find source-specific names, including ones outside finding rows."""
    found = []
    for match in _NAME_TOKEN.finditer(text):
        value = match.group()
        starts = (0, *(i + 1 for i, char in enumerate(value) if char in "-_"))
        if any(
            len(value) - start >= width
            and hashlib.sha256(
                value[start : start + width].lower().encode()
            ).hexdigest()
            == fingerprint
            for start in starts
            for width, fingerprint in SOURCE_NAME_FINGERPRINTS
        ):
            found.append((*match.span(), "source account name"))
    return found


# Matches of the patterns above that are fixed names, not generated: the CDK
# bootstrap's default qualifier, a service name, part of a stack name, a
# template's logical resource ID, status words an API returns, and a word of a
# finding's text.
NOT_GENERATED = frozenset(
    {
        "hnb659fds",
        "s3express",
        "PATTERN1STACK",
        "EmptyS3Bucket",
        "SUCCESSFUL",
        "SUPPRESSED",
        "COMPLIANCE",
        "MISCONDUCT",
        "ESSENTIALS",
        "SATv2Stack",
        "re-fetches",
    }
)
# SHA-256 of personal names in the sample reports (in a bucket name, a role
# session name and an IAM user name), kept as hashes so this file doesn't
# repeat them. A word that matches is replaced like a generated value.
PERSONAL_NAME = "personal name"
PERSONAL_NAME_SHA256 = frozenset(
    {
        "56f254089632214490cb5cd0c1760b0b730451077468c758343947063ba285a3",
        "8044948181460cf23c5fd5ad6a432c2fbd8ce1e06cbd4ea1955d37685c81ce6b",
        "fcc094d1a916658e04e55a83182a7591ffedb824ac4542c409b2edb57284a750",
    }
)
_GENERATED = tuple(
    (kind, re.compile(pattern)) for kind, pattern in GENERATED_VALUE_KINDS
)
_WORD = re.compile(r"[A-Za-z]+")
_HEX = re.compile(r"[0-9a-f]+|[0-9A-F]+")


def generated_values(text: str) -> list[tuple[int, int, str]]:
    """(start, end, kind) of each generated value in text, left to right.

    Where two matches overlap, the one that starts first (then the longer one)
    is kept.
    """
    found = [
        (*match.span("v"), kind)
        for kind, pattern in _GENERATED
        for match in pattern.finditer(text)
        if match.group("v") not in NOT_GENERATED
    ]
    found += [
        (*match.span(), PERSONAL_NAME)
        for match in _WORD.finditer(text)
        if hashlib.sha256(match.group().lower().encode()).hexdigest()
        in PERSONAL_NAME_SHA256
    ]
    found += source_account_names(text)
    kept: list[tuple[int, int, str]] = []
    end = 0
    for start, stop, kind in sorted(
        found, key=lambda item: (item[0], item[0] - item[1])
    ):
        if start >= end:
            kept.append((start, stop, kind))
            end = stop
    return kept


def _made_up_character(character: str, byte: int, hex_only: bool) -> str:
    if character.isdigit():
        pool = string.digits
    elif character.islower():
        pool = "abcdef" if hex_only else string.ascii_lowercase
    elif character.isupper():
        pool = "ABCDEF" if hex_only else string.ascii_uppercase
    else:
        return character
    return pool[byte % len(pool)]
