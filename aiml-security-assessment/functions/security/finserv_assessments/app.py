"""
AWS FinServ GenAI Risk Assessment Lambda
=========================================
Implements 65 security checks (64 standalone + 1 shared FS-27 entry for the new
Automated Reasoning Policies check) derived from the AWS guide:
"Financial Services risk management of the use of Generative AI"
https://d1.awsstatic.com/onedam/marketing-channels/website/public/global-FinServ-ComplianceGuide-GenAIRisks-public.pdf

Check ID namespace: FS-01 through FS-69
  FS-01 to FS-63 — original 63 checks across 15 risk categories
                   (FS-17, FS-18, FS-19 merged into upstream SM-07, SM-23, SM-22)
  FS-64 to FS-69 — 6 material gap checks covering mitigations explicitly
                   called out in the Guide but absent from FS-01..63 and
                   the existing BR/SM/AC checks in the AIML Security Assessment.
                   (FS-64 merged into upstream BR-04)

5 checks (FS-17, FS-18, FS-19, FS-23, FS-64) are contributed as upstream extensions
rather than standalone entries — see extension notes in the SECURITY_CHECKS_FINSERV
Part 1 and Part 3 markdown files.

FS-27 is split into two check functions sharing the same check_id:
  1. check_guardrail_contextual_grounding() — verifies contextualGroundingPolicy
     on guardrails (threshold-based, per-inference filtering).
  2. check_automated_reasoning_policies() — verifies Bedrock Automated Reasoning
     policies (formal verification, GA August 2025, limited regions).
Both use FS-27 in the CSV and both appear in the build_finserv_checks() registry.

These checks complement the existing BR/SM/AC checks in the AIML Security Assessment.

COMPLIANCE_PLACEHOLDER: Each check maps to FinServ regulatory frameworks via the
COMPLIANCE_MAP dict below. These mappings now travel with every finding row in the
CSV report (the Compliance_Frameworks column) — see COMPLIANCE_MAP and create_finding.
Frameworks referenced: FFIEC CAT, SR 11-7, NYDFS 500.06, PCI-DSS 12.3.2, SOC 2 CC6,
ISO 27001 A.12, DORA Art.6, MAS TRM 9.

Contribution workflow:
  - Upstream repo: aws-samples/sample-aiml-security-assessment (OSPO-managed, so forks
    are auto-approved by Amazon Code Defender).
  - This Lambda is delivered via a personal fork + feature branch + PR. See
    GIT_WORKFLOW.md for the full 9-step process (fork, branch, ASH scan, commit, push,
    PR, GitHub Actions verification, reviewer assignment, optional Git Defender
    exception ticket).

Pre-commit quality gates (run every edit):
  1. ruff check + ruff format --check on this directory.
  2. sam local invoke FinServSecurityAssessmentFunction against a test event.
  3. cfn-lint / sam validate on the updated SAM templates.
  4. ash --source-dir <repo> --fail-on-findings --config-overrides
     'global_settings.severity_threshold=MEDIUM' — resolve every Critical and High
     finding before opening the PR.
  5. git defender scan on the staged diff.
"""

import boto3
import csv
import functools
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from io import StringIO
from typing import Any, Dict, List, Optional

from botocore.config import Config
from botocore.exceptions import ClientError, ParamValidationError

from schema import create_finding

# ---------------------------------------------------------------------------
# Boto3 config with adaptive retries
# ---------------------------------------------------------------------------
boto3_config = Config(retries=dict(max_attempts=10, mode="adaptive"))

logger = logging.getLogger()
logger.setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def get_permissions_cache(execution_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve IAM permissions cache from S3 (same pattern as other assessments)."""
    try:
        s3_client = boto3.client("s3", config=boto3_config)
        s3_key = f"permissions_cache_{execution_id}.json"
        s3_bucket = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
        response = s3_client.get_object(Bucket=s3_bucket, Key=s3_key)
        return json.loads(response["Body"].read().decode("utf-8"))
    except ClientError as e:
        logger.warning(f"Could not load permissions cache: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error loading permissions cache: {e}", exc_info=True)
        return None


def _empty_findings(check_name: str) -> Dict[str, Any]:
    return {"check_name": check_name, "status": "PASS", "details": "", "csv_data": []}


def _bucket_name_from_arn(bucket_arn: str) -> str:
    """Extract the bucket name from an S3 bucket ARN (arn:aws:s3:::name).

    Returns "" when the value is empty or is not a well-formed S3 bucket ARN, so
    a malformed/unexpected value is skipped rather than mistakenly used as a
    bucket name (which would then fail the subsequent S3 API call)."""
    if not bucket_arn or ":::" not in bucket_arn:
        return ""
    return bucket_arn.split(":::", 1)[1]


def _paginate(
    client,
    operation_name: str,
    result_key: str,
    *,
    token: "tuple[str, str] | None" = None,
    **kwargs,
) -> List[Dict[str, Any]]:
    """Collect all items across pages for a paginated list/describe operation by
    calling the operation directly and following its continuation token.

    Calling the bound method directly (rather than via get_paginator) keeps this
    uniform across services and unit-test mocks. The AWS APIs this Lambda uses
    employ three continuation-token conventions, all handled here:
      - NextToken / NextToken            (organizations, sagemaker, config, events, ...)
      - nextToken / nextToken            (bedrock, bedrock-agent, ecr, ...)
      - Marker / NextMarker              (lambda)
      - position / position              (apigateway)

    A single-page response (no continuation token) yields exactly one call, so
    this is a safe drop-in for previously non-paginated reads and for mocks that
    stub the operation with a single return value.

    Args:
        token: Optional explicit ``(output_field, input_param)`` pair that
            bypasses the convention table entirely.  When set, ``token[0]`` is
            read from each response to find the continuation value and
            ``token[1]`` is the request kwarg used to send it on the next call.
            Use this for operations whose token convention is not in the table,
            or where the output and input names differ from every entry already
            there (e.g. WAFv2 ``NextMarker``/``NextMarker`` vs Lambda's
            ``NextMarker``/``Marker``).  When ``None`` (the default) the
            existing convention table is used unchanged — all current callers
            pass no ``token`` argument and are therefore byte-for-byte identical
            to before this parameter was added.
    """
    # (output token field in response, input token kwarg on request)
    token_conventions = [
        ("NextToken", "NextToken"),
        ("nextToken", "nextToken"),
        ("NextMarker", "Marker"),
        ("position", "position"),
    ]
    method = getattr(client, operation_name)
    items: List[Dict[str, Any]] = []
    call_kwargs = dict(kwargs)
    seen_tokens = set()
    while True:
        resp = method(**call_kwargs)
        items.extend(resp.get(result_key, []) or [])
        next_token = None
        input_field = None
        if token is not None:
            # Explicit override: bypass the convention table.
            out_field, in_field = token
            if resp.get(out_field):
                next_token = resp[out_field]
                input_field = in_field
        else:
            for out_field, in_field in token_conventions:
                if resp.get(out_field):
                    next_token = resp[out_field]
                    input_field = in_field
                    break
        # Stop when there is no token, or if a token repeats (guards against a
        # mock that returns the same token every call → infinite loop).
        if not next_token or next_token in seen_tokens:
            break
        seen_tokens.add(next_token)
        call_kwargs[input_field] = next_token
    return items


def _error_findings(check_name: str, err: Exception) -> Dict[str, Any]:
    return {
        "check_name": check_name,
        "status": "ERROR",
        "details": str(err),
        "csv_data": [],
    }


# Error codes that mean "we were not allowed to read this resource" rather than
# "the control is absent." Treating an access error as a compliance failure
# produces a false non-compliant finding caused purely by a missing permission
# (the credibility problem a compliance tool must avoid).
_ACCESS_ERROR_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "AuthorizationError",
        "Forbidden",
    }
)


def _is_access_error(err: "ClientError") -> bool:
    """True if a ClientError is a permission/authorization error (not a real
    'control absent' signal). Used so a missing IAM permission surfaces as a
    could-not-assess condition instead of a false non-compliant finding."""
    try:
        return err.response.get("Error", {}).get("Code", "") in _ACCESS_ERROR_CODES
    except AttributeError:
        return False


# Error codes meaning the S3 bucket a data source points to no longer exists.
# This is a distinct, actionable condition (a dangling KB data-source reference
# to a deleted bucket) — NOT "versioning/notifications absent." Surfacing it
# separately avoids a misleading "bucket without versioning" label when the real
# problem is the bucket was deleted out from under the Knowledge Base.
_MISSING_BUCKET_ERROR_CODES = frozenset({"NoSuchBucket", "404", "NotFound"})


def _is_missing_bucket_error(err: "ClientError") -> bool:
    """True if a ClientError indicates the S3 bucket does not exist (deleted /
    dangling data-source reference) rather than a missing control or a missing
    permission."""
    try:
        return (
            err.response.get("Error", {}).get("Code", "") in _MISSING_BUCKET_ERROR_CODES
        )
    except AttributeError:
        return False


# Findings whose name starts with this prefix were emitted because the check
# could not run (e.g., missing IAM permission). They are visible in the report
# (Status="N/A") so a failed/permission-denied check does not silently vanish.
COULD_NOT_ASSESS_PREFIX = "COULD NOT ASSESS: "

# ---------------------------------------------------------------------------
# ResourceInventory data model and helpers (REQ-3, REQ-4.1, REQ-6.4)
# ---------------------------------------------------------------------------


class _Unavailable:
    """Sentinel marking an inventory field whose collection failed. Carries the
    originating exception so dependent checks can reproduce the exact
    COULD_NOT_ASSESS output that the check would have produced had it made the
    call itself (design DD-3)."""

    __slots__ = ("error",)

    def __init__(self, error: Exception):
        self.error = error


@dataclass(frozen=True)
class GuardrailInventory:
    """Per-invocation guardrail enumeration. ``frozen=True`` prevents field
    reassignment; the contained list/dict are read-only *by convention*."""

    summaries: list  # raw list_guardrails 'guardrails' entries
    detail_by_id: dict  # id -> get_guardrail(DRAFT) response (or _Unavailable)


@dataclass(frozen=True)
class KbInventory:
    """Per-invocation Knowledge Base enumeration."""

    summaries: list  # knowledgeBaseSummaries
    data_sources_by_kb: (
        dict  # knowledgeBaseId -> list of dataSourceSummaries (or _Unavailable)
    )
    data_source_detail: dict  # (knowledgeBaseId, dataSourceId) -> get_data_source resp (or _Unavailable)


@dataclass(frozen=True)
class WebAclInventory:
    """Per-invocation WAFv2 REGIONAL Web ACL enumeration."""

    summaries: list  # WebACLs list
    detail_by_id: dict  # Id -> get_web_acl response (or _Unavailable)


@dataclass(frozen=True)
class ResourceInventory:
    """Per-invocation, read-only inventory of shared AWS resources.

    Each field is EITHER the collected data structure OR an ``_Unavailable``
    sentinel (carrying the original exception). Checks MUST NOT mutate the
    lists/dicts stored here; the equivalence tests catch any such mutation.

    This is constructed once in ``lambda_handler`` and injected like
    ``permission_cache`` (design DD-1, INV-6)."""

    lambda_functions: "list | _Unavailable"
    guardrails: "GuardrailInventory | _Unavailable"
    knowledge_bases: "KbInventory | _Unavailable"
    buckets: "list | _Unavailable"
    web_acls: "WebAclInventory | _Unavailable"


def inv_available(field) -> bool:
    """Return True when *field* holds real data; False when it is an
    ``_Unavailable`` sentinel."""
    return not isinstance(field, _Unavailable)


def require(inventory: "ResourceInventory | None", field_name: str):
    """Return ``inventory.<field_name>`` when available; raise the stored
    exception when the field is ``_Unavailable``; raise ``RuntimeError`` when
    ``inventory`` is ``None`` (the test-only default from design DD-2b).

    The caller's existing outer ``try/except`` turns the raised exception into
    ``_error_findings`` → ``COULD_NOT_ASSESS``, matching today's behavior."""
    if inventory is None:
        raise RuntimeError("resource inventory not provided")
    value = getattr(inventory, field_name)
    if isinstance(value, _Unavailable):
        raise value.error
    return value


# ---------------------------------------------------------------------------
# COMPLIANCE_MAP — per-check regulatory framework mappings
#
# Each value is a pipe-separated string of FinServ framework identifiers that
# travel with every finding row in the CSV report (Compliance_Frameworks column).
# This mirrors the ASFF Compliance.RelatedRequirements pattern used by AWS
# Security Hub: compliance metadata is embedded in the finding itself, not kept
# in a separate sidecar document.
#
# Disclaimer: mappings are PRELIMINARY and ILLUSTRATIVE. They have not been
# reviewed by AWS Security Assurance Services, external auditors, or the
# regulators named. Each firm should have its own MRM, Legal, and Compliance
# teams validate these mappings against their specific interpretation of each
# framework before relying on them as audit evidence.
# ---------------------------------------------------------------------------
COMPLIANCE_MAP: Dict[str, str] = {
    # Category 1: Unbounded Consumption
    "FS-01": "FFIEC CAT | DORA Art.6",
    "FS-02": "FFIEC CAT | DORA Art.6 | PCI-DSS 12.3.2",
    "FS-03": "FFIEC CAT | SR 11-7",
    "FS-04": "FFIEC CAT | SR 11-7",
    "FS-05": "FFIEC CAT | DORA Art.6",
    "FS-06": "FFIEC CAT | SR 11-7",
    # Category 2: Excessive Agency
    "FS-07": "SR 11-7 | FFIEC CAT",
    "FS-08": "SR 11-7 | MAS TRM 9.1",
    "FS-09": "FFIEC CAT | SR 11-7",
    "FS-10": "SR 11-7 | FFIEC CAT | MAS TRM 9.2",
    "FS-11": "FFIEC CAT | DORA Art.6",
    # Category 3: Supply Chain Vulnerabilities
    "FS-12": "SR 11-7 | FFIEC CAT | ISO 27001 A.15.2",
    "FS-13": "SR 11-7 | ISO 27001 A.12.5 | FFIEC CAT",
    "FS-14": "SR 11-7 | FFIEC CAT | ISO 27001 A.15.1",
    "FS-15": "SR 11-7 | FFIEC CAT | MAS TRM 9.3",
    "FS-16": "ISO 27001 A.12.6 | FFIEC CAT | DORA Art.6",
    # Category 4: Training Data & Model Poisoning
    "FS-20": "SR 11-7 | FFIEC CAT",
    "FS-21": "SR 11-7 | ISO 27001 A.12.3 | FFIEC CAT",
    # Category 5: Vector & Embedding Weaknesses
    "FS-22": "NYDFS 500 | FFIEC CAT | PCI-DSS 12.3.2",
    "FS-24": "NYDFS 500 | FFIEC CAT | PCI-DSS 12.3.2",
    "FS-25": "NYDFS 500 | PCI-DSS 3.5 | FFIEC CAT",
    "FS-26": "NYDFS 500 | FFIEC CAT | PCI-DSS 1.3",
    # Category 6: Non-Compliant Output
    "FS-27": "SR 11-7 | FFIEC CAT | MAS TRM 9.2",
    "FS-28": "SR 11-7 | FFIEC CAT | NYDFS 500 | MAS TRM 9.2",
    "FS-29": "SR 11-7 | FFIEC CAT | NYDFS 500 | MAS TRM 9.2",
    "FS-30": "SR 11-7 | FFIEC CAT | NYDFS 500",
    # Category 7: Misinformation
    "FS-31": "SR 11-7 | FFIEC CAT",
    "FS-32": "SR 11-7 | FFIEC CAT | MAS TRM 9.2",
    "FS-33": "SR 11-7 | FFIEC CAT | ISO 27001 A.12",
    "FS-34": "SR 11-7 | FFIEC CAT",
    # Category 8: Abusive or Harmful Output
    "FS-35": "SR 11-7 | FFIEC CAT",
    "FS-36": "SR 11-7 | FFIEC CAT",
    "FS-37": "SR 11-7 | FFIEC CAT | MAS TRM 9.2",
    "FS-38": "SR 11-7 | FFIEC CAT",
    # Category 9: Biased Output
    "FS-39": "SR 11-7 | FFIEC CAT | ECOA/Fair Housing",
    "FS-40": "SR 11-7 | FFIEC CAT | ECOA/Fair Housing",
    "FS-41": "SR 11-7 | FFIEC CAT",
    "FS-42": "SR 11-7 | FFIEC CAT",
    # Category 10: Sensitive Information Disclosure
    "FS-43": "NYDFS 500 | FFIEC CAT | PCI-DSS",
    "FS-44": "NYDFS 500 | FFIEC CAT | PCI-DSS",
    "FS-45": "NYDFS 500 | FFIEC CAT | PCI-DSS",
    "FS-46": "NYDFS 500 | FFIEC CAT | ISO 27001 A.12 | PCI-DSS",
    # Category 11: Hallucination
    "FS-47": "SR 11-7 | FFIEC CAT",
    "FS-48": "SR 11-7 | FFIEC CAT",
    "FS-49": "SR 11-7 | FFIEC CAT | MAS TRM 9.2",
    "FS-50": "SR 11-7 | FFIEC CAT",
    # Category 12: Prompt Injection
    "FS-51": "NYDFS 500 | FFIEC CAT | OWASP LLM Top 10",
    "FS-52": "NYDFS 500 | FFIEC CAT | ISO 27001 A.12 | OWASP LLM Top 10",
    "FS-53": "NYDFS 500 | PCI-DSS | FFIEC CAT | OWASP LLM Top 10",
    "FS-54": "NYDFS 500 | FFIEC CAT | OWASP LLM Top 10",
    # Category 13: Improper Output Handling
    "FS-55": "FFIEC CAT | OWASP LLM Top 10",
    "FS-56": "NYDFS 500 | PCI-DSS | OWASP LLM Top 10",
    "FS-57": "NYDFS 500.06 | FFIEC CAT | OWASP LLM Top 10",
    "FS-58": "FFIEC CAT | OWASP LLM Top 10",
    # Category 14: Off-Topic & Inappropriate Output
    "FS-59": "SR 11-7 | FFIEC CAT",
    "FS-60": "SR 11-7 | FFIEC CAT",
    # Category 15: Out-of-Date Training Data
    "FS-61": "SR 11-7 | FFIEC CAT",
    "FS-62": "SR 11-7 | FFIEC CAT | MAS TRM 9.2",
    "FS-63": "SR 11-7 | FFIEC CAT | ISO 27001 A.12",
    # Material Gap Checks
    "FS-65": "FFIEC CAT | DORA Art.6 | ISO 27001 A.12",
    "FS-66": "NYDFS 500 | SR 11-7 | MAS TRM 9 | PCI-DSS",
    "FS-67": "SR 11-7 | FFIEC CAT | MAS TRM 9 | PCI-DSS",
    "FS-68": "DORA Art.6 | FFIEC CAT | PCI-DSS | OWASP LLM Top 10",
    "FS-69": "NYDFS 500 | FFIEC CAT | OWASP LLM Top 10",
}


# ---------------------------------------------------------------------------
# SEVERITY METHODOLOGY (see docs/severity-methodology.md + severity-register.md)
#
# Severity = property of the CONTROL (the risk it mitigates), assigned once via a
# Likelihood (L) x Impact (I) matrix mapped to the AWS Security Hub ASFF label set,
# then applied to every Passed/Failed row of that control. The N/A family follows a
# fixed disposition rule so "nothing to assess" rows are consistent.
#
#   Matrix (I x L -> label), 1=Low 2=Medium 3=High:
#       I=3: L1->Medium  L2->High    L3->High
#       I=2: L1->Low     L2->Medium  L3->High
#       I=1: L1->Low     L2->Low     L3->Medium
#   (Critical is intentionally NOT used in this round — see methodology §6.)
#
#   Disposition -> severity:
#       PASS / FAIL          -> control severity (from the matrix)
#       NOT_APPLICABLE       -> Informational  (ASFF: "no issue was found")
#       ADVISORY             -> Informational  (no API can verify it)
#       COULD_NOT_ASSESS     -> Low            (unknown state; re-run after fixing access)
#       SOFT_WARNING         -> control severity (intentional non-failing assessed state)
# ---------------------------------------------------------------------------

_SEVERITY_MATRIX = {
    (3, 1): "Medium",
    (3, 2): "High",
    (3, 3): "High",
    (2, 1): "Low",
    (2, 2): "Medium",
    (2, 3): "High",
    (1, 1): "Low",
    (1, 2): "Low",
    (1, 3): "Medium",
}


def _label_from_matrix(impact: int, likelihood: int) -> str:
    """Map an (Impact, Likelihood) pair (each 1-3) to an ASFF severity label."""
    return _SEVERITY_MATRIX[(impact, likelihood)]


# Disposition tiers whose severity is fixed by the disposition, not by I x L.
_DISPOSITION_SEVERITY = {
    "NOT_APPLICABLE": "Informational",
    "ADVISORY": "Informational",
    "COULD_NOT_ASSESS": "Low",
}


# Authoritative per-finding severity register (keyed by finding-name).
# Source of truth derived from docs/severity-register.md. The test suite
# (test_severity_register.py) asserts every emitted severity matches this map.
# Entries: finding_name -> (severity, disposition). I/L rationale lives in the doc.
SEVERITY_REGISTER: Dict[str, str] = {
    # --- FS-01 (Shield = Low; WAF = Medium) ---
    "AWS Shield Advanced Not Enabled": "Low",
    "AWS Shield Advanced Enabled": "Low",
    "No Regional WAF Web ACLs Found": "Medium",
    "Regional WAF Web ACLs Present": "Medium",
    # --- FS-02 (rate limiting = Medium) ---
    "No API Gateway Usage Plans Found": "Informational",
    "API Gateway Usage Plans Missing Throttle": "Medium",
    "API Gateway Rate Limiting Configured": "Medium",
    # --- FS-03 (token quotas = Medium) ---
    "No Bedrock Token Quotas Returned": "Medium",
    "Bedrock Default Quotas Unavailable — Customization Undetermined": "Medium",
    "Bedrock Token Quotas Customized": "Medium",
    "Bedrock Token Quotas At Default": "Medium",
    # --- FS-04 ---
    "No Cost Anomaly Detection Monitors": "Medium",
    "Cost Anomaly Monitors Do Not Cover Bedrock/SageMaker": "Medium",
    "Cost Anomaly Detection Configured": "Medium",
    # --- FS-05 ---
    "No Bedrock CloudWatch Alarms Found": "Medium",
    "Bedrock CloudWatch Alarms Present": "Medium",
    # --- FS-06 ---
    "No AI/ML Service Budgets Configured": "Medium",
    "AI/ML Service Budgets Configured": "Medium",
    # --- FS-07 (agent action boundaries = High) ---
    "Agent Action Boundary Check": "Informational",
    "Bedrock Agent Overly Broad Action Permissions": "High",
    "Agent Action Boundaries Look Appropriate": "High",
    # --- FS-08 (AgentCore policy engine = High) ---
    "AgentCore Policy Engine — Access Check": "Low",
    "No AgentCore Runtimes Found": "Informational",
    "AgentCore Runtimes Missing Policy Engine": "High",
    "AgentCore Policy Engine Configured": "High",
    # --- FS-09 ---
    "Agent Lambda Functions Without Concurrency Limits": "Medium",
    "Agent Lambda Concurrency Limits Present": "Medium",
    # --- FS-10 (human-in-the-loop = High) ---
    "Human-in-the-Loop Check — No Agent Workflows Found": "Informational",
    "Human Approval Steps Found in Agent Workflows": "High",
    "Agent Workflows Missing Human Approval Steps": "High",
    # --- FS-11 ---
    "No Agent Rate Alarms Found": "Medium",
    "Agent Rate Alarms Present": "Medium",
    # --- FS-12 (SCPs = High) ---
    "SCP Model Access Check — Not in Organization": "Informational",
    "No Bedrock-Scoped SCPs Found": "High",
    "Bedrock SCPs Found": "High",
    # --- FS-13 ---
    "Models Missing Provenance Tags": "Medium",
    "Model Provenance Tags Present": "Medium",
    # --- FS-14 ---
    "No Model Governance Config Rules Found": "Medium",
    "Model Governance Config Rules Present": "Medium",
    # --- FS-15 (eval jobs exist = Medium; absence is a real FAIL) ---
    "No Bedrock Evaluation Jobs Found": "Medium",
    "Bedrock Evaluation Jobs Present": "Medium",
    # --- FS-16 (ECR scanning = High) ---
    "No ECR Repositories Found": "Informational",
    "ECR Repositories Without Image Scanning": "High",
    "ECR Image Scanning Enabled": "High",
    # --- FS-20 ---
    "No SageMaker Feature Groups Found": "Informational",
    "Feature Groups Without Offline Store": "Medium",
    "Feature Store Offline Store Active": "Medium",
    # --- FS-21 (training-data integrity = High) ---
    "No Training Data Buckets Identified": "Informational",
    "Training Data Buckets Without Versioning": "High",
    "Training Data Buckets Have Versioning": "High",
    # --- FS-22 (KB IAM least privilege = High) ---
    "Overly Permissive Knowledge Base IAM Roles": "High",
    "Knowledge Base IAM Permissions Look Appropriate": "High",
    # --- FS-24 (advisory) ---
    "No Knowledge Bases Found": "Informational",
    "ADVISORY: Knowledge Base Metadata Filtering — Manual Review Required": "Informational",
    # --- FS-25 (KB encryption = High) ---
    "No OpenSearch Serverless Encryption Policies": "Informational",
    "OpenSearch Serverless Encryption Not Using Customer-Managed Keys": "High",
    "OpenSearch Serverless Encryption Policies Present": "High",
    # --- FS-26 (VPC isolation = High) ---
    "No OpenSearch Serverless Network Policies": "High",
    "OpenSearch Serverless Collections Not VPC-Restricted": "High",
    "OpenSearch Serverless VPC Access Configured": "High",
    # --- FS-27 (contextual grounding = High; ARC = Medium) ---
    "No Guardrails — Contextual Grounding Not Applicable": "Informational",
    "No Guardrails With Contextual Grounding": "High",
    "Contextual Grounding Enabled on Guardrails": "High",
    "Automated Reasoning Policies — Access Check": "Low",
    "No Automated Reasoning Policies Found": "Medium",
    "Automated Reasoning Policies Found": "Medium",
    # --- FS-28 (denied topics = High) ---
    "No Guardrails — Denied Topics Not Applicable": "Informational",
    "No Guardrails With Denied Financial Topics": "High",
    "Denied Topics Configured on CLASSIC Tier": "High",
    "Guardrails With Topic Policies Found": "High",
    # --- FS-29 (advisory) ---
    "ADVISORY: Compliance Disclaimer — Manual Review Required": "Informational",
    # --- FS-30 (advisory — cannot inspect dataset content) ---
    "ADVISORY: Compliance Dataset Coverage — Manual Review Required": "Informational",
    # --- FS-31 ---
    "Knowledge Base Data Sources Past Review Threshold": "Medium",
    "Knowledge Base Data Sources Recently Synced": "Medium",
    # --- FS-32 (advisory) ---
    "ADVISORY: Source Attribution — Manual Review Required": "Informational",
    # --- FS-33 (distinct risks: deleted bucket High, versioning Medium) ---
    "KB Data Source References a Deleted S3 Bucket": "High",
    "KB Data Source Buckets Without Versioning": "Medium",
    "KB Data Source Buckets Have Versioning": "Medium",
    # --- FS-34 ---
    "Legacy Foundation Models Available in Region": "Informational",
    "Foundation Models Are Current": "Medium",
    # --- FS-35 (advisory) ---
    "ADVISORY: Harmful-Content Test Coverage — Manual Review Required": "Informational",
    # --- FS-36 (content filters = High) ---
    "No Guardrails — Content Filters Not Applicable": "Informational",
    "No Guardrails With Content Filters": "High",
    "Guardrail Content Filters on CLASSIC Tier": "High",
    "Guardrail Content Filters Configured (STANDARD Tier)": "High",
    # --- FS-37 (advisory) ---
    "ADVISORY: User Feedback Mechanism — Manual Review Required": "Informational",
    # --- FS-38 (word filters = Medium) ---
    "No Guardrails — Word Filters Not Applicable": "Informational",
    "No Guardrails With Word Filters": "Medium",
    "Guardrail Word Filters Configured": "Medium",
    # --- FS-39 (bias = High) ---
    "No SageMaker Clarify Bias Monitoring": "High",
    "SageMaker Clarify Bias Monitoring Active": "High",
    # --- FS-40 (advisory) ---
    "ADVISORY: Bias Dataset Coverage — Manual Review Required": "Informational",
    # --- FS-41 (explainability = High) ---
    "No SageMaker Clarify Explainability Monitoring": "High",
    "SageMaker Clarify Explainability Active": "High",
    # --- FS-42 ---
    "No SageMaker Model Cards Found": "Medium",
    "SageMaker Model Cards Present": "Medium",
    # --- FS-43 (log data protection = High) ---
    "No CloudWatch Logs Data Protection Policies": "High",
    "CloudWatch Logs Data Protection Policies Present": "High",
    # --- FS-44 (Macie = High) ---
    "Amazon Macie Not Enabled": "High",
    "Amazon Macie Enabled": "High",
    # --- FS-45 (PII filters = High) ---
    "No Guardrails — PII Filters Not Applicable": "Informational",
    "No Guardrails With PII Filters": "High",
    "Guardrail PII Filters Configured": "High",
    # --- FS-46 (classification = Medium) ---
    "No AI/ML Data Buckets Identified": "Informational",
    "AI/ML Buckets Without Data Classification Tags": "Medium",
    "AI/ML Buckets Have Classification Tags": "Medium",
    # --- FS-47 (grounding threshold = High) ---
    "No Guardrails — Grounding Threshold Not Applicable": "Informational",
    "Guardrails With Low Grounding Thresholds": "High",
    "No Guardrails With a Grounding Filter": "High",
    "Guardrail Grounding Thresholds Appropriate": "High",
    # --- FS-48 ---
    "No Active Knowledge Bases for RAG": "Medium",
    "Active Knowledge Bases for RAG Present": "Medium",
    # --- FS-49 (advisory) ---
    "ADVISORY: Hallucination Disclaimer — Manual Review Required": "Informational",
    # --- FS-50 (relevance grounding = Medium) ---
    "No Guardrails With Relevance Grounding Filters": "Medium",
    "Relevance Grounding Filters Present": "Medium",
    # --- FS-51 (prompt attack = High) ---
    "No Guardrails — Prompt Attack Filters Not Applicable": "Informational",
    "No Guardrails With Prompt Attack Filters": "High",
    "Prompt Attack Filters on CLASSIC Tier": "High",
    "Prompt Attack Filters Configured (STANDARD Tier)": "High",
    # --- FS-52 ---
    "No Bedrock-Related Lambda Functions Found": "Informational",
    "Bedrock Lambda Functions on Deprecated Runtimes": "Medium",
    "Bedrock Lambda Functions on Current Runtimes": "Medium",
    # --- FS-53 (injection rules = High) ---
    "No WAF Web ACLs — Injection Rules Not Applicable": "Informational",
    "WAF ACLs Missing Injection Protection Rules": "High",
    "WAF Injection Protection Rules Present": "High",
    # --- FS-54 (advisory) ---
    "ADVISORY: Penetration Testing — Manual Review Required": "Informational",
    # --- FS-55 ---
    "No Output Validation Functions Found": "Medium",
    "Output Validation Functions Present": "Medium",
    # --- FS-56 (XSS = Medium; now has a FAIL path) ---
    "No WAF ACLs — XSS Prevention Not Applicable": "Informational",
    "WAF ACLs Missing Common Rule Set (XSS)": "Medium",
    "XSS Prevention Common Rule Set Present": "Medium",
    # --- FS-57 (advisory) ---
    "ADVISORY: Output Encoding — Manual Review Required": "Informational",
    # --- FS-58 (advisory) ---
    "ADVISORY: Output Schema Validation — Manual Review Required": "Informational",
    # --- FS-59 (topic allowlist = Medium) ---
    "No Guardrails — Topic Allowlist Not Applicable": "Informational",
    "No Guardrails With Topic Restrictions": "Medium",
    "Topic Restrictions Configured on CLASSIC Tier": "Medium",
    "Guardrail Topic Restrictions Configured": "Medium",
    # --- FS-60 (advisory) ---
    "ADVISORY: Contextual Grounding for Off-Topic Prevention": "Informational",
    # --- FS-61 ---
    "No Automated KB Sync Schedules Detected": "Medium",
    "Automated KB Sync Schedules Present": "Medium",
    # --- FS-62 (advisory) ---
    "ADVISORY: Data Currency Disclaimer — Manual Review Required": "Informational",
    # --- FS-63 ---
    "Legacy Models Without Lifecycle Management": "Medium",
    "Foundation Model Lifecycle Management": "Medium",
    # --- FS-65 (distinct risks) ---
    "KB Data Source Buckets Missing S3 Event Notifications": "Medium",
    "KB Data Source S3 Event Notifications Configured": "Medium",
    # --- FS-66 (identity propagation = High) ---
    "AgentCore Identity Propagation — Access Check": "Low",
    "AgentCore Runtimes Missing End-User Identity Propagation": "High",
    "AgentCore End-User Identity Propagation Configured": "High",
    # --- FS-67 (transaction thresholds = High) ---
    "No Agent Action-Group Lambda Functions Found": "Informational",
    "Agent Action-Group Lambdas May Lack Transaction Thresholds": "High",
    "Agent Action-Group Lambdas Have Threshold Configuration": "High",
    # --- FS-68 (body-size = Medium; now has N/A branch) ---
    "API Gateway Request Body Size Limits Not Enforced": "Medium",
    "API Gateway Request Body Size Limits — Not Applicable": "Informational",
    "API Gateway Request Body Size Limits Configured": "Medium",
    # --- FS-69 ---
    "No Prompt Input Validation Function Found": "Medium",
    "Prompt Input Validation Functions Present": "Medium",
}


def _could_not_assess_row(check_id: str, check_name: str, err: Any) -> Dict[str, Any]:
    """
    Synthesize one visible finding row for a check that errored out and produced
    no rows. Uses Status="N/A", Severity="Low" (the COULD_NOT_ASSESS disposition —
    see severity-methodology.md §3.4) so the gap surfaces in the report as an
    unknown/assessment-gap without inflating the Failed count or implying a
    confirmed control failure.
    """
    return create_finding(
        check_id=check_id,
        finding_name=f"{COULD_NOT_ASSESS_PREFIX}{check_name}",
        finding_details=(
            f"This check could not be completed (error: {err}). The most common cause "
            "is a missing IAM permission for the assessment role; it may also indicate "
            "an unsupported region or an outdated botocore. This control was NOT assessed "
            "— verify the role's permissions and re-run, and assess this control manually "
            "until resolved."
        ),
        resolution=(
            "1. Confirm the assessment role grants the actions this check requires "
            "(see the documented IAM permission set in the README).\n"
            "2. Confirm the service/feature is supported in the assessed region.\n"
            "3. Ensure botocore meets the version floor in requirements.txt.\n"
            "4. Re-run the assessment; assess this control manually until it succeeds."
        ),
        reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html",
        severity="Low",
        status="N/A",
        compliance_frameworks=COMPLIANCE_MAP.get(check_id, ""),
    )


# ===========================================================================
# CATEGORY 1: UNBOUNDED CONSUMPTION (FS-01 to FS-06)
# Risk: GenAI workloads can be exploited to exhaust compute/cost budgets
# COMPLIANCE_PLACEHOLDER: [FFIEC CAT, DORA Art.6, SR 11-7 Appendix A]
# ===========================================================================


def check_waf_shield_on_bedrock_endpoints(inventory) -> Dict[str, Any]:
    """
    FS-01 — Verify AWS WAF is associated with API Gateway or ALB endpoints
    that front Bedrock/GenAI workloads, and that AWS Shield Advanced is enabled.
    COMPLIANCE_PLACEHOLDER: [FFIEC CAT Cyber Risk Management, DORA Art.6 ICT Risk]
    """
    findings = _empty_findings("WAF and Shield Protection Check")
    try:
        shield = boto3.client("shield", config=boto3_config)

        # Check Shield Advanced subscription
        shield_enabled = False
        try:
            shield.describe_subscription()
            shield_enabled = True
        except shield.exceptions.ResourceNotFoundException:
            pass
        except ClientError:
            pass

        # Check WAF Web ACLs exist (regional, covering API GW / ALB)
        # require() raises if inventory is None or the field is _Unavailable,
        # which propagates to the outer except and yields COULD_NOT_ASSESS.
        acls = require(inventory, "web_acls").summaries

        if not shield_enabled:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-01",
                    finding_name="AWS Shield Advanced Not Enabled",
                    finding_details=(
                        "AWS Shield Advanced is not subscribed. GenAI API endpoints are "
                        "vulnerable to volumetric DDoS attacks that can exhaust token quotas "
                        "and inflate costs."
                    ),
                    resolution=(
                        "1. Subscribe to AWS Shield Advanced for DDoS protection.\n"
                        "2. After subscribing, explicitly add resource protections in the "
                        "Shield Advanced console for each Bedrock-facing resource "
                        "(API Gateway stages, ALBs, CloudFront distributions, Route 53 hosted zones). "
                        "Shield Advanced subscription alone does NOT automatically protect resources — "
                        "each resource must be individually added to receive protection.\n"
                        "3. Enable Shield Response Team (SRT) access and configure proactive engagement.\n"
                        "4. Alternatively, use AWS Firewall Manager with a Shield Advanced policy "
                        "to automate resource protection based on tags or resource types."
                    ),
                    reference="https://docs.aws.amazon.com/waf/latest/developerguide/shield-chapter.html",
                    severity="Low",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-01"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-01",
                    finding_name="AWS Shield Advanced Enabled",
                    finding_details="AWS Shield Advanced subscription is active.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/waf/latest/developerguide/shield-chapter.html",
                    severity="Low",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-01"],
                )
            )

        if not acls:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-01",
                    finding_name="No Regional WAF Web ACLs Found",
                    finding_details=(
                        "No AWS WAF regional Web ACLs found. Without WAF, GenAI endpoints "
                        "lack rate-based rules to block abusive callers."
                    ),
                    resolution=(
                        "1. Create a WAF Web ACL with rate-based rules (e.g., 1000 req/5 min per IP).\n"
                        "2. Associate the ACL with API Gateway stages or ALBs fronting Bedrock.\n"
                        "3. Add AWS Managed Rules for known bad inputs."
                    ),
                    reference="https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-01"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-01",
                    finding_name="Regional WAF Web ACLs Present",
                    finding_details=f"Found {len(acls)} regional WAF Web ACL(s).",
                    resolution="Verify ACLs are associated with Bedrock-facing endpoints.",
                    reference="https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-01"],
                )
            )
    except Exception as e:
        return _error_findings("WAF and Shield Protection Check", e)
    return findings


def check_api_gateway_rate_limiting() -> Dict[str, Any]:
    """
    FS-02 — Verify API Gateway usage plans enforce throttling on GenAI endpoints.
    COMPLIANCE_PLACEHOLDER: [FFIEC CAT, DORA Art.6, PCI-DSS 12.3.2]
    """
    findings = _empty_findings("API Gateway Rate Limiting Check")
    try:
        apigw = boto3.client("apigateway", config=boto3_config)
        plans = _paginate(apigw, "get_usage_plans", "items")

        plans_without_throttle = [
            p["name"]
            for p in plans
            if not p.get("throttle") or p["throttle"].get("rateLimit", 0) == 0
        ]

        if not plans:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-02",
                    finding_name="No API Gateway Usage Plans Found",
                    finding_details="No usage plans configured. GenAI API endpoints may have no rate limits.",
                    resolution=(
                        "Create API Gateway usage plans with throttle settings "
                        "(rateLimit and burstLimit) for all Bedrock-facing APIs."
                    ),
                    reference="https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-02"],
                )
            )
        elif plans_without_throttle:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-02",
                    finding_name="API Gateway Usage Plans Missing Throttle",
                    finding_details=(
                        f"Usage plans without throttling: {', '.join(plans_without_throttle)}. "
                        "Unbounded API calls can exhaust Bedrock token quotas and inflate costs."
                    ),
                    resolution=(
                        "Set rateLimit and burstLimit on all usage plans associated with "
                        "GenAI API stages. Consider per-consumer API keys with individual quotas."
                    ),
                    reference="https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-02"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-02",
                    finding_name="API Gateway Rate Limiting Configured",
                    finding_details=f"All {len(plans)} usage plan(s) have throttle settings.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-02"],
                )
            )
    except Exception as e:
        return _error_findings("API Gateway Rate Limiting Check", e)
    return findings


def check_bedrock_token_quotas() -> Dict[str, Any]:
    """
    FS-03 — Check whether Bedrock service quotas for tokens-per-minute (TPM)
    have been reviewed and raised above AWS defaults.

    Token-based quotas are the primary signal. RPM (requests-per-minute) quotas
    are model-specific on the bedrock-runtime endpoint: some models (e.g., Claude
    Opus 4.7/4.8) are governed solely by TPM with no RPM quota; others have both.
    Because RPM applicability varies by model, only TPM quotas drive this verdict
    and an absent RPM quota must never trigger a failure.

    Note: The bedrock-mantle endpoint (OpenAI-compatible, GA May 2026) exposes
    separate input-tokens-per-minute and output-tokens-per-minute quotas also
    under ServiceCode "bedrock". This check focuses on bedrock-runtime on-demand
    TPM quotas; bedrock-mantle quotas are not explicitly separated here.

    Verdict logic (value-based, not adjustability-based):
      - at least one applied token-quota Value > its AWS default  → customized → PASS/Passed
      - all applied token-quota Values == their defaults          → at default → WARN/N-A (soft)
      - no applied token quotas returned                          → WARN/Failed + explanation
      - AWS default quotas could not be retrieved                 → WARN/Failed + "undetermined"
    COMPLIANCE_PLACEHOLDER: [FFIEC CAT, SR 11-7]
    """
    findings = _empty_findings("Bedrock Token Quota Review")
    try:
        sq = boto3.client("service-quotas", config=boto3_config)

        # Applied quotas (paginated). TPM quotas are the primary signal; RPM quotas
        # are model-specific and their absence must not trigger a failure verdict.
        applied = []
        for page in sq.get_paginator("list_service_quotas").paginate(
            ServiceCode="bedrock"
        ):
            applied.extend(page.get("Quotas", []))
        token_quotas = [q for q in applied if "token" in q.get("QuotaName", "").lower()]

        # Empty-applied-list branch: no token quotas found at all.
        if not token_quotas:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-03",
                    finding_name="No Bedrock Token Quotas Returned",
                    finding_details=(
                        "No Bedrock token-based service quotas were returned. This may indicate "
                        "a permissions issue (servicequotas:ListServiceQuotas), an unsupported "
                        "region, or that no Bedrock-specific quotas exist for this account. "
                        "Verify manually in the Service Quotas console."
                    ),
                    resolution=(
                        "1. Confirm the assessment role has servicequotas:ListServiceQuotas.\n"
                        "2. Verify Bedrock is available in the assessed region.\n"
                        "3. Review Bedrock token quotas in the Service Quotas console."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/quotas.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-03"],
                )
            )
            return findings

        # AWS default quotas for comparison (paginated).
        default_values = {}
        for page in sq.get_paginator("list_aws_default_service_quotas").paginate(
            ServiceCode="bedrock"
        ):
            for q in page.get("Quotas", []):
                if q.get("QuotaCode") is not None:
                    default_values[q["QuotaCode"]] = q.get("Value")

        # Default-lookup-fail branch: cannot compare without defaults. Do NOT
        # silently compare a value against itself (which would always Fail).
        if not default_values:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-03",
                    finding_name="Bedrock Default Quotas Unavailable — Customization Undetermined",
                    finding_details=(
                        "AWS default service quotas for Bedrock could not be retrieved "
                        "(list_aws_default_service_quotas returned nothing), so whether the "
                        "applied quotas have been customized cannot be determined. This is "
                        "commonly a permissions issue (servicequotas:ListAWSDefaultServiceQuotas) "
                        "or an unsupported region."
                    ),
                    resolution=(
                        "1. Confirm the assessment role has servicequotas:ListAWSDefaultServiceQuotas.\n"
                        "2. Re-run the assessment once defaults are retrievable.\n"
                        "3. Until then, verify Bedrock token quotas manually in the Service Quotas console."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/quotas.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-03"],
                )
            )
            return findings

        # Value-based comparison. An applied Value == default Value is the
        # expected, non-customized state (ListServiceQuotas may return only
        # default values for some quotas) — this is NOT an error. At-default is
        # reported as a soft warning (WARN/N-A), not a failure, since it is a
        # legitimate verified posture.
        any_customized = any(
            q.get("QuotaCode") in default_values
            and default_values[q["QuotaCode"]] is not None
            and q.get("Value", 0) > default_values[q["QuotaCode"]]
            for q in token_quotas
        )

        if any_customized:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-03",
                    finding_name="Bedrock Token Quotas Customized",
                    finding_details=(
                        f"Found {len(token_quotas)} Bedrock token-based quota(s); at least one "
                        "applied value exceeds the AWS default, indicating quotas have been "
                        "reviewed and raised."
                    ),
                    resolution="No action required. Periodically re-review quotas against expected peak load.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/quotas.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-03"],
                )
            )
        else:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-03",
                    finding_name="Bedrock Token Quotas At Default",
                    finding_details=(
                        f"All {len(token_quotas)} Bedrock token-based quota(s) are at their AWS "
                        "default values — no quota increase has been applied. Running at default "
                        "is a legitimate posture, but it should be a reviewed decision aligned "
                        "with expected peak load rather than an oversight."
                    ),
                    resolution=(
                        "1. Review current Bedrock TPM/TPD quotas in the Service Quotas console.\n"
                        "2. Request increases aligned with expected peak load, or document a "
                        "deliberate decision to remain at default after review.\n"
                        "3. Implement client-side token counting and pre-flight quota checks.\n"
                        "4. Use Bedrock cross-region inference profiles to distribute load."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/quotas.html",
                    severity="Medium",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-03"],
                )
            )
    except Exception as e:
        return _error_findings("Bedrock Token Quota Review", e)
    return findings


def check_cost_anomaly_detection() -> Dict[str, Any]:
    """
    FS-04 — Verify AWS Cost Anomaly Detection monitors are configured for
    Bedrock and SageMaker services.
    COMPLIANCE_PLACEHOLDER: [FFIEC CAT, SR 11-7 Appendix A]
    """
    findings = _empty_findings("Cost Anomaly Detection Check")
    try:
        ce = boto3.client("ce", config=boto3_config)
        # get_anomaly_monitors is paginated (NextPageToken). Read every page so a
        # Bedrock-covering monitor beyond the first page is not missed (which would
        # otherwise produce a false "no coverage" finding).
        monitors = []
        next_token = None
        while True:
            kwargs = {"NextPageToken": next_token} if next_token else {}
            resp = ce.get_anomaly_monitors(**kwargs)
            monitors.extend(resp.get("AnomalyMonitors", []))
            next_token = resp.get("NextPageToken")
            if not next_token:
                break

        # A monitor provides Bedrock/SageMaker service-level coverage if its
        # spec mentions bedrock (rarely populated for DIMENSIONAL+SERVICE
        # monitors, kept for completeness) OR it is a DIMENSIONAL monitor scoped
        # to the SERVICE dimension. DIMENSIONAL+SERVICE is the operative signal;
        # a DIMENSIONAL monitor on LINKED_ACCOUNT/TAG/COST_CATEGORY does NOT
        # provide service-level Bedrock coverage and must not count.
        bedrock_monitors = [
            m
            for m in monitors
            if "bedrock" in json.dumps(m.get("MonitorSpecification", {})).lower()
            or (
                m.get("MonitorType") == "DIMENSIONAL"
                and m.get("MonitorDimension") == "SERVICE"
            )
        ]

        if not monitors:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-04",
                    finding_name="No Cost Anomaly Detection Monitors",
                    finding_details=(
                        "No AWS Cost Anomaly Detection monitors found. Unexpected spikes in "
                        "Bedrock/SageMaker usage (e.g., from prompt injection loops) will go undetected."
                    ),
                    resolution=(
                        "1. Create a Cost Anomaly Detection monitor scoped to AWS/Bedrock and AWS/SageMaker.\n"
                        "2. Configure alert subscriptions (SNS/email) for anomalies above threshold.\n"
                        "3. Set daily spend budgets with AWS Budgets as a secondary control."
                    ),
                    reference="https://docs.aws.amazon.com/cost-management/latest/userguide/getting-started-ad.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-04"],
                )
            )
        elif not bedrock_monitors:
            # Monitors exist, but none provide Bedrock/SageMaker service-level
            # coverage. This is the previously-masked false positive: the old
            # code passed whenever ANY monitor existed.
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-04",
                    finding_name="Cost Anomaly Monitors Do Not Cover Bedrock/SageMaker",
                    finding_details=(
                        f"Found {len(monitors)} anomaly monitor(s), but none provide service-level "
                        "coverage for Bedrock/SageMaker (no DIMENSIONAL monitor scoped to the SERVICE "
                        "dimension, and no monitor specification referencing Bedrock). A generic or "
                        "linked-account monitor does not detect GenAI cost anomalies."
                    ),
                    resolution=(
                        "1. Create a DIMENSIONAL Cost Anomaly Detection monitor scoped to the SERVICE "
                        "dimension so AWS/Bedrock and AWS/SageMaker are covered.\n"
                        "2. Configure alert subscriptions (SNS/email) for anomalies above threshold.\n"
                        "3. Set daily spend budgets with AWS Budgets as a secondary control."
                    ),
                    reference="https://docs.aws.amazon.com/cost-management/latest/userguide/getting-started-ad.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-04"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-04",
                    finding_name="Cost Anomaly Detection Configured",
                    finding_details=f"Found {len(monitors)} anomaly monitor(s); {len(bedrock_monitors)} provide Bedrock/SageMaker service-level coverage.",
                    resolution="Verify monitors cover Bedrock and SageMaker service dimensions.",
                    reference="https://docs.aws.amazon.com/cost-management/latest/userguide/getting-started-ad.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-04"],
                )
            )
    except Exception as e:
        return _error_findings("Cost Anomaly Detection Check", e)
    return findings


def check_cloudwatch_token_alarms() -> Dict[str, Any]:
    """
    FS-05 — Check for CloudWatch alarms on Bedrock InvocationThrottles and
    TokensProcessed metrics to detect runaway consumption.
    COMPLIANCE_PLACEHOLDER: [FFIEC CAT, DORA Art.6]
    """
    findings = _empty_findings("CloudWatch Token Usage Alarms Check")
    try:
        cw = boto3.client("cloudwatch", config=boto3_config)
        paginator = cw.get_paginator("describe_alarms")
        all_alarms = []
        for page in paginator.paginate(AlarmTypes=["MetricAlarm"]):
            all_alarms.extend(page.get("MetricAlarms", []))

        bedrock_alarms = [
            a
            for a in all_alarms
            if a.get("Namespace", "").startswith("AWS/Bedrock")
            or "bedrock" in a.get("AlarmName", "").lower()
        ]

        throttle_alarms = [
            a
            for a in bedrock_alarms
            if "throttl" in a.get("MetricName", "").lower()
            or "throttl" in a.get("AlarmName", "").lower()
        ]

        if not bedrock_alarms:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-05",
                    finding_name="No Bedrock CloudWatch Alarms Found",
                    finding_details=(
                        "No CloudWatch alarms found for Bedrock metrics. "
                        "Token exhaustion and throttling events will not trigger operational alerts."
                    ),
                    resolution=(
                        "Create CloudWatch alarms for:\n"
                        "- AWS/Bedrock InvocationThrottles (threshold > 0)\n"
                        "- AWS/Bedrock TokensProcessed (threshold based on quota)\n"
                        "- Custom application-level token counters via EMF"
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-cw.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-05"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-05",
                    finding_name="Bedrock CloudWatch Alarms Present",
                    finding_details=(
                        f"Found {len(bedrock_alarms)} Bedrock-related alarm(s), "
                        f"{len(throttle_alarms)} covering throttling."
                    ),
                    resolution="Ensure alarms have SNS actions and are in OK state.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-cw.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-05"],
                )
            )
    except Exception as e:
        return _error_findings("CloudWatch Token Usage Alarms Check", e)
    return findings


def check_aws_budgets_for_aiml() -> Dict[str, Any]:
    """
    FS-06 — Verify AWS Budgets are configured with alerts for AI/ML service spend.
    COMPLIANCE_PLACEHOLDER: [FFIEC CAT, SR 11-7]
    """
    findings = _empty_findings("AWS Budgets AI/ML Spend Check")
    try:
        budgets_client = boto3.client("budgets", config=boto3_config)
        sts = boto3.client("sts", config=boto3_config)
        account_id = sts.get_caller_identity()["Account"]

        def _paginate_budgets(show_filter_expression: bool):
            kwargs = {"AccountId": account_id}
            if show_filter_expression:
                kwargs["ShowFilterExpression"] = True
            pages = []
            for page in budgets_client.get_paginator("describe_budgets").paginate(
                **kwargs
            ):
                pages.extend(page.get("Budgets", []))
            return pages

        # FilterExpression is opt-in: DescribeBudgets only returns it when
        # ShowFilterExpression=True. Modern budgets use the structured
        # FilterExpression instead of the deprecated flat CostFilters map.
        # On an old botocore that does not accept ShowFilterExpression, the call
        # raises ParamValidationError (NOT a ClientError) — degrade gracefully
        # to a CostFilters-only check rather than letting the check vanish.
        try:
            all_budgets = _paginate_budgets(show_filter_expression=True)
        except ParamValidationError:
            logger.warning(
                "describe_budgets does not accept ShowFilterExpression on this "
                "botocore; falling back to CostFilters-only budget detection. "
                "Upgrade botocore to check new-style FilterExpression budgets."
            )
            all_budgets = _paginate_budgets(show_filter_expression=False)

        aiml_budgets = [
            b
            for b in all_budgets
            if any(
                svc in json.dumps(b.get("CostFilters", {})).lower()
                or svc in json.dumps(b.get("FilterExpression", {})).lower()
                for svc in ["bedrock", "sagemaker"]
            )
        ]

        if not aiml_budgets:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-06",
                    finding_name="No AI/ML Service Budgets Configured",
                    finding_details=(
                        "No AWS Budgets found scoped to Bedrock or SageMaker. "
                        "Unbounded GenAI spend can go undetected until the monthly bill."
                    ),
                    resolution=(
                        "1. Create cost budgets for AWS Bedrock and SageMaker with 80%/100% alert thresholds.\n"
                        "2. Add SNS notifications to on-call channels.\n"
                        "3. Consider budget actions to apply IAM deny policies when thresholds are breached."
                    ),
                    reference="https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-06"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-06",
                    finding_name="AI/ML Service Budgets Configured",
                    finding_details=f"Found {len(aiml_budgets)} budget(s) covering AI/ML services.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-06"],
                )
            )
    except Exception as e:
        return _error_findings("AWS Budgets AI/ML Spend Check", e)
    return findings


# ===========================================================================
# CATEGORY 2: EXCESSIVE AGENCY (FS-07 to FS-11)
# Risk: Agents take unintended real-world actions beyond their intended scope
# COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, DORA Art.6, MAS TRM 9]
# ===========================================================================


def check_bedrock_agent_action_boundaries(permission_cache) -> Dict[str, Any]:
    """
    FS-07 — Verify Bedrock agent execution roles have narrow action boundaries
    (no wildcard actions on sensitive services like s3:*, iam:*, ec2:*).
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT Cyber Risk Management]
    """
    findings = _empty_findings("Agent Action Boundary Check")
    try:
        bedrock_agent = boto3.client("bedrock-agent", config=boto3_config)
        agents = bedrock_agent.list_agents().get("agentSummaries", [])

        if not agents:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-07",
                    finding_name="Agent Action Boundary Check",
                    finding_details="No Bedrock agents found.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-permissions.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-07"],
                )
            )
            return findings

        SENSITIVE_WILDCARDS = ["iam:*", "s3:*", "ec2:*", "lambda:*", "*"]
        agents_with_issues = []

        for agent_summary in agents:
            agent_id = agent_summary["agentId"]
            agent_name = agent_summary["agentName"]
            try:
                detail = bedrock_agent.get_agent(agentId=agent_id)
            except ClientError as e:
                logger.warning(f"Could not describe agent {agent_name}: {e}")
                continue
            role_arn = detail.get("agent", {}).get("agentResourceRoleArn", "")
            if not role_arn:
                continue
            role_name = role_arn.split("/")[-1]
            role_perms = (
                (permission_cache or {}).get("role_permissions", {}).get(role_name, {})
            )
            for policy in role_perms.get("attached_policies", []) + role_perms.get(
                "inline_policies", []
            ):
                doc = policy.get("document", {})
                if isinstance(doc, str):
                    doc = json.loads(doc)
                for stmt in doc.get("Statement", []):
                    if stmt.get("Effect") != "Allow":
                        continue
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    for action in actions:
                        if action in SENSITIVE_WILDCARDS:
                            agents_with_issues.append(
                                f"Agent '{agent_name}' role '{role_name}' allows '{action}'"
                            )

        if agents_with_issues:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-07",
                    finding_name="Bedrock Agent Overly Broad Action Permissions",
                    finding_details=(
                        "The following agents have execution roles with wildcard or overly broad actions:\n"
                        + "\n".join(f"- {i}" for i in agents_with_issues[:10])
                    ),
                    resolution=(
                        "1. Replace wildcard actions with specific actions the agent needs.\n"
                        "2. Apply permission boundaries to agent execution roles.\n"
                        "3. Use resource-level conditions to restrict to specific ARNs.\n"
                        "4. Implement human-in-the-loop approval for high-impact actions."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-permissions.html",
                    severity="High",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-07"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-07",
                    finding_name="Agent Action Boundaries Look Appropriate",
                    finding_details=f"Reviewed {len(agents)} agent(s); no wildcard sensitive actions found.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-permissions.html",
                    severity="High",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-07"],
                )
            )
    except Exception as e:
        return _error_findings("Agent Action Boundary Check", e)
    return findings


def check_agentcore_policy_engine() -> Dict[str, Any]:
    """
    FS-08 — Check whether Bedrock AgentCore Policy Engine is configured to
    enforce action-level authorization for agent tool calls.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, MAS TRM 9.1]
    """
    findings = _empty_findings("AgentCore Policy Engine Check")
    try:
        # AgentCore policy engine is checked via bedrock-agentcore control plane
        agentcore = boto3.client("bedrock-agentcore-control", config=boto3_config)
        try:
            # List policy stores (policy engine resources)
            response = agentcore.list_agent_runtimes()
            runtimes = response.get("agentRuntimes", [])
        except ClientError as e:
            if "AccessDenied" in str(e) or "UnrecognizedClientException" in str(e):
                findings["csv_data"].append(
                    create_finding(
                        check_id="FS-08",
                        finding_name="AgentCore Policy Engine — Access Check",
                        finding_details="Unable to enumerate AgentCore runtimes (access denied or service unavailable in region).",
                        resolution="Ensure assessment role has bedrock-agentcore:ListAgentRuntimes permission.",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security-authorization.html",
                        severity="Low",
                        status="N/A",
                        compliance_frameworks=COMPLIANCE_MAP["FS-08"],
                    )
                )
                return findings
            raise

        if not runtimes:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-08",
                    finding_name="No AgentCore Runtimes Found",
                    finding_details="No AgentCore runtimes found; policy engine check not applicable.",
                    resolution="If using AgentCore, configure the Policy Engine to authorize tool calls.",
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security-authorization.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-08"],
                )
            )
        else:
            # Check each runtime for policy engine association
            runtimes_without_policy = [
                r["agentRuntimeName"]
                for r in runtimes
                if not r.get("authorizerConfiguration")
            ]
            if runtimes_without_policy:
                findings["status"] = "WARN"
                findings["csv_data"].append(
                    create_finding(
                        check_id="FS-08",
                        finding_name="AgentCore Runtimes Missing Policy Engine",
                        finding_details=(
                            f"Runtimes without authorizer configuration: {', '.join(runtimes_without_policy)}. "
                            "Without a policy engine, agents can invoke any registered tool without authorization checks."
                        ),
                        resolution=(
                            "Configure an authorizer (Lambda or Cedar policy store) on each AgentCore runtime "
                            "to enforce fine-grained tool-call authorization."
                        ),
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security-authorization.html",
                        severity="High",
                        status="Failed",
                        compliance_frameworks=COMPLIANCE_MAP["FS-08"],
                    )
                )
            else:
                findings["csv_data"].append(
                    create_finding(
                        check_id="FS-08",
                        finding_name="AgentCore Policy Engine Configured",
                        finding_details=f"All {len(runtimes)} runtime(s) have authorizer configurations.",
                        resolution="No action required.",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security-authorization.html",
                        severity="High",
                        status="Passed",
                        compliance_frameworks=COMPLIANCE_MAP["FS-08"],
                    )
                )
    except Exception as e:
        return _error_findings("AgentCore Policy Engine Check", e)
    return findings


def check_agent_transaction_limits(inventory) -> Dict[str, Any]:
    """
    FS-09 — Check for application-level transaction/action limits on agents
    via Lambda concurrency limits or Step Functions execution limits.
    COMPLIANCE_PLACEHOLDER: [FFIEC CAT, SR 11-7]
    """
    findings = _empty_findings("Agent Transaction Limits Check")
    try:
        functions = require(inventory, "lambda_functions")

        # Look for agent-related Lambda functions without reserved concurrency
        agent_lambdas = [
            f
            for f in functions
            if any(
                kw in f["FunctionName"].lower() for kw in ["agent", "bedrock", "aiml"]
            )
        ]

        lambda_client = boto3.client("lambda", config=boto3_config)
        lambdas_without_concurrency = []
        for fn in agent_lambdas:
            try:
                config = lambda_client.get_function_concurrency(
                    FunctionName=fn["FunctionName"]
                )
                if not config.get("ReservedConcurrentExecutions"):
                    lambdas_without_concurrency.append(fn["FunctionName"])
            except ClientError:
                lambdas_without_concurrency.append(fn["FunctionName"])

        if lambdas_without_concurrency:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-09",
                    finding_name="Agent Lambda Functions Without Concurrency Limits",
                    finding_details=(
                        f"Agent-related Lambda functions without reserved concurrency: "
                        f"{', '.join(lambdas_without_concurrency[:10])}. "
                        "Unlimited concurrency allows runaway agent loops to exhaust account limits."
                    ),
                    resolution=(
                        "1. Set reserved concurrency on agent Lambda functions.\n"
                        "2. Implement maximum iteration counts in agent orchestration logic.\n"
                        "3. Use Step Functions with MaxConcurrency and timeout states.\n"
                        "4. Add circuit-breaker patterns to agent tool invocations."
                    ),
                    reference="https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-09"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-09",
                    finding_name="Agent Lambda Concurrency Limits Present",
                    finding_details=f"Reviewed {len(agent_lambdas)} agent Lambda(s); concurrency limits appear configured.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html",
                    severity="Medium",
                    status="Passed" if agent_lambdas else "N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-09"],
                )
            )
    except Exception as e:
        return _error_findings("Agent Transaction Limits Check", e)
    return findings


def check_human_in_the_loop_for_high_risk_actions() -> Dict[str, Any]:
    """
    FS-10 — Check for Step Functions or SNS-based human approval steps in
    agent workflows that perform high-risk financial actions.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, MAS TRM 9.2]
    """
    findings = _empty_findings("Human-in-the-Loop Approval Check")
    try:
        sfn = boto3.client("stepfunctions", config=boto3_config)
        machines = sfn.list_state_machines().get("stateMachines", [])

        agent_machines = [
            m
            for m in machines
            if any(
                kw in m["name"].lower()
                for kw in ["agent", "approval", "human", "review"]
            )
        ]

        machines_with_wait = []
        for machine in agent_machines:
            defn = sfn.describe_state_machine(
                stateMachineArn=machine["stateMachineArn"]
            ).get("definition", "{}")
            if '"waitForTaskToken"' in defn or '"TaskToken"' in defn:
                machines_with_wait.append(machine["name"])

        if not agent_machines:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-10",
                    finding_name="Human-in-the-Loop Check — No Agent Workflows Found",
                    finding_details=(
                        "No Step Functions state machines with agent/approval naming found. "
                        "Verify that high-risk agent actions (e.g., fund transfers, account changes) "
                        "have human approval gates."
                    ),
                    resolution=(
                        "Implement Step Functions .waitForTaskToken patterns for high-risk agent actions. "
                        "Route approval requests to human reviewers via SNS/SES/Slack."
                    ),
                    reference="https://docs.aws.amazon.com/step-functions/latest/dg/connect-to-resource.html#connect-wait-token",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-10"],
                )
            )
        elif machines_with_wait:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-10",
                    finding_name="Human Approval Steps Found in Agent Workflows",
                    finding_details=f"State machines with waitForTaskToken (human approval): {', '.join(machines_with_wait)}.",
                    resolution="No action required. Verify approval routing reaches the correct reviewers.",
                    reference="https://docs.aws.amazon.com/step-functions/latest/dg/connect-to-resource.html#connect-wait-token",
                    severity="High",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-10"],
                )
            )
        else:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-10",
                    finding_name="Agent Workflows Missing Human Approval Steps",
                    finding_details=(
                        f"Found {len(agent_machines)} agent-related state machine(s) but none use "
                        "waitForTaskToken for human approval. High-risk financial actions may execute autonomously."
                    ),
                    resolution=(
                        "Add .waitForTaskToken states before irreversible financial actions. "
                        "Define risk tiers and require human approval for Tier 1 actions."
                    ),
                    reference="https://docs.aws.amazon.com/step-functions/latest/dg/connect-to-resource.html#connect-wait-token",
                    severity="High",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-10"],
                )
            )
    except Exception as e:
        return _error_findings("Human-in-the-Loop Approval Check", e)
    return findings


def check_agent_rate_alarms() -> Dict[str, Any]:
    """
    FS-11 — Check for CloudWatch alarms on agent invocation rates to detect
    runaway or looping agent behavior.
    COMPLIANCE_PLACEHOLDER: [FFIEC CAT, DORA Art.6]
    """
    findings = _empty_findings("Agent Rate Alarms Check")
    try:
        cw = boto3.client("cloudwatch", config=boto3_config)
        paginator = cw.get_paginator("describe_alarms")
        all_alarms = []
        for page in paginator.paginate(AlarmTypes=["MetricAlarm"]):
            all_alarms.extend(page.get("MetricAlarms", []))

        agent_alarms = [
            a
            for a in all_alarms
            if "agent" in a.get("AlarmName", "").lower()
            or "agent" in a.get("Namespace", "").lower()
        ]

        if not agent_alarms:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-11",
                    finding_name="No Agent Rate Alarms Found",
                    finding_details=(
                        "No CloudWatch alarms found for agent invocation rates. "
                        "Looping or runaway agents will not trigger operational alerts."
                    ),
                    resolution=(
                        "Create CloudWatch alarms on:\n"
                        "- Bedrock agent invocation counts (threshold based on expected max)\n"
                        "- Lambda invocation errors for agent functions\n"
                        "- Step Functions execution failures and timeouts"
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-cw.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-11"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-11",
                    finding_name="Agent Rate Alarms Present",
                    finding_details=f"Found {len(agent_alarms)} agent-related CloudWatch alarm(s).",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-cw.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-11"],
                )
            )
    except Exception as e:
        return _error_findings("Agent Rate Alarms Check", e)
    return findings


# ===========================================================================
# CATEGORY 3: SUPPLY CHAIN VULNERABILITIES (FS-12 to FS-16)
# Risk: Third-party models, datasets, or plugins introduce malicious code/data
# COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, DORA Art.6, ISO 27001 A.15]
# ===========================================================================


def check_scp_model_access_restrictions() -> Dict[str, Any]:
    """
    FS-12 — Verify SCPs restrict Bedrock model access to an approved model list,
    preventing use of unapproved third-party models.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, ISO 27001 A.15.2]
    """
    findings = _empty_findings("SCP Model Access Restriction Check")
    try:
        orgs = boto3.client("organizations", config=boto3_config)
        try:
            policies = _paginate(
                orgs, "list_policies", "Policies", Filter="SERVICE_CONTROL_POLICY"
            )
        except ClientError as e:
            if "AccessDenied" in str(e) or "AWSOrganizationsNotInUseException" in str(
                e
            ):
                findings["csv_data"].append(
                    create_finding(
                        check_id="FS-12",
                        finding_name="SCP Model Access Check — Not in Organization",
                        finding_details="Account is not part of an AWS Organization or lacks SCP read access.",
                        resolution="If using AWS Organizations, ensure SCPs restrict Bedrock model access to approved models.",
                        reference="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html",
                        severity="Informational",
                        status="N/A",
                        compliance_frameworks=COMPLIANCE_MAP["FS-12"],
                    )
                )
                return findings
            raise

        bedrock_scps = []
        for policy in policies:
            doc_response = orgs.describe_policy(PolicyId=policy["Id"])
            doc = json.loads(doc_response["Policy"]["Content"])
            if "bedrock" in json.dumps(doc).lower():
                bedrock_scps.append(policy["Name"])

        if not bedrock_scps:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-12",
                    finding_name="No Bedrock-Scoped SCPs Found",
                    finding_details=(
                        "No Service Control Policies reference Bedrock. "
                        "Without SCPs, any account in the organization can access any Bedrock model, "
                        "including unapproved third-party models."
                    ),
                    resolution=(
                        "1. Create an SCP that denies bedrock:InvokeModel for model IDs not on the approved list.\n"
                        "2. Use bedrock:ModelId condition key to allowlist approved models.\n"
                        "3. Maintain a model inventory and update the SCP when models are approved/retired."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples.html",
                    severity="High",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-12"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-12",
                    finding_name="Bedrock SCPs Found",
                    finding_details=f"SCPs referencing Bedrock: {', '.join(bedrock_scps)}.",
                    resolution="Verify SCPs use bedrock:ModelId conditions to allowlist approved models.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security_iam_id-based-policy-examples.html",
                    severity="High",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-12"],
                )
            )
    except Exception as e:
        return _error_findings("SCP Model Access Restriction Check", e)
    return findings


def check_model_inventory_tagging() -> Dict[str, Any]:
    """
    FS-13 — Check that custom Bedrock models and SageMaker models are tagged
    with provenance metadata (source, version, approval-date).
    COMPLIANCE_PLACEHOLDER: [SR 11-7, ISO 27001 A.12.5, FFIEC CAT]
    """
    findings = _empty_findings("Model Inventory Tagging Check")
    try:
        bedrock = boto3.client("bedrock", config=boto3_config)
        sm = boto3.client("sagemaker", config=boto3_config)
        REQUIRED_TAGS = {"source", "version", "approval-date"}

        untagged_models = []

        # Check Bedrock custom models
        for model in _paginate(bedrock, "list_custom_models", "modelSummaries"):
            tags_response = bedrock.list_tags_for_resource(
                resourceARN=model["modelArn"]
            )
            tag_keys = {t["key"].lower() for t in tags_response.get("tags", [])}
            missing = REQUIRED_TAGS - tag_keys
            if missing:
                untagged_models.append(
                    f"Bedrock model '{model['modelName']}' missing tags: {missing}"
                )

        # Check SageMaker registered models
        for model in _paginate(sm, "list_models", "Models"):
            tags_response = sm.list_tags(ResourceArn=model["ModelArn"])
            tag_keys = {t["Key"].lower() for t in tags_response.get("Tags", [])}
            missing = REQUIRED_TAGS - tag_keys
            if missing:
                untagged_models.append(
                    f"SageMaker model '{model['ModelName']}' missing tags: {missing}"
                )

        if untagged_models:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-13",
                    finding_name="Models Missing Provenance Tags",
                    finding_details=(
                        f"{len(untagged_models)} model(s) missing required provenance tags:\n"
                        + "\n".join(f"- {m}" for m in untagged_models[:10])
                    ),
                    resolution=(
                        "Tag all models with: source (e.g., 'aws-marketplace', 'internal'), "
                        "version, and approval-date. "
                        "Enforce tagging via SCP or AWS Config rule."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/tagging.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-13"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-13",
                    finding_name="Model Provenance Tags Present",
                    finding_details="All reviewed models have required provenance tags.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/tagging.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-13"],
                )
            )
    except Exception as e:
        return _error_findings("Model Inventory Tagging Check", e)
    return findings


def check_model_onboarding_governance() -> Dict[str, Any]:
    """
    FS-14 — Check for AWS Config rules or Service Catalog constraints that
    enforce model onboarding governance (approved sources only).
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, ISO 27001 A.15.1]
    """
    findings = _empty_findings("Model Onboarding Governance Check")
    try:
        config = boto3.client("config", config=boto3_config)
        rules = _paginate(config, "describe_config_rules", "ConfigRules")

        bedrock_rules = [
            r
            for r in rules
            if "bedrock" in r.get("ConfigRuleName", "").lower()
            or "model" in r.get("ConfigRuleName", "").lower()
        ]

        if not bedrock_rules:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-14",
                    finding_name="No Model Governance Config Rules Found",
                    finding_details=(
                        "No AWS Config rules found for Bedrock model governance. "
                        "Unapproved models may be deployed without detection."
                    ),
                    resolution=(
                        "1. Create custom AWS Config rules to detect use of non-approved Bedrock models.\n"
                        "2. Use AWS Service Catalog to publish approved model configurations.\n"
                        "3. Implement a model risk management (MRM) process per SR 11-7."
                    ),
                    reference="https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-14"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-14",
                    finding_name="Model Governance Config Rules Present",
                    finding_details=f"Found {len(bedrock_rules)} model-related Config rule(s).",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-14"],
                )
            )
    except Exception as e:
        return _error_findings("Model Onboarding Governance Check", e)
    return findings


def check_bedrock_model_evaluation_adversarial() -> Dict[str, Any]:
    """
    FS-15 — Check whether Bedrock Model Evaluation jobs include adversarial
    test datasets (robustness/red-team evaluations).
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, MAS TRM 9.3]
    """
    findings = _empty_findings("Adversarial Model Evaluation Check")
    try:
        bedrock = boto3.client("bedrock", config=boto3_config)
        evals = _paginate(bedrock, "list_evaluation_jobs", "jobSummaries")

        if not evals:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-15",
                    finding_name="No Bedrock Evaluation Jobs Found",
                    finding_details=(
                        "No Bedrock Model Evaluation jobs found. Models have not been evaluated "
                        "for adversarial robustness. FinServ model-risk management (SR 11-7) "
                        "expects documented model validation/evaluation."
                    ),
                    resolution=(
                        "1. Run Bedrock Model Evaluation with adversarial/red-team datasets.\n"
                        "2. Use FMEval library for automated robustness testing.\n"
                        "3. Schedule periodic re-evaluation after model updates."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-evaluation.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-15"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-15",
                    finding_name="Bedrock Evaluation Jobs Present",
                    finding_details=f"Found {len(evals)} evaluation job(s). Verify adversarial datasets are included.",
                    resolution="Ensure evaluation datasets include adversarial/red-team test cases.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-evaluation.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-15"],
                )
            )
    except Exception as e:
        return _error_findings("Adversarial Model Evaluation Check", e)
    return findings


def check_ecr_image_scanning() -> Dict[str, Any]:
    """
    FS-16 — Verify ECR repositories used for custom model containers have
    image scanning enabled (supply chain vulnerability detection).
    COMPLIANCE_PLACEHOLDER: [ISO 27001 A.12.6, FFIEC CAT, DORA Art.6]
    """
    findings = _empty_findings("ECR Image Scanning Check")
    try:
        ecr = boto3.client("ecr", config=boto3_config)
        repos = _paginate(ecr, "describe_repositories", "repositories")

        if not repos:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-16",
                    finding_name="No ECR Repositories Found",
                    finding_details="No ECR repositories found.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-16"],
                )
            )
            return findings

        repos_without_scanning = [
            r["repositoryName"]
            for r in repos
            if not r.get("imageScanningConfiguration", {}).get("scanOnPush", False)
        ]

        if repos_without_scanning:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-16",
                    finding_name="ECR Repositories Without Image Scanning",
                    finding_details=(
                        f"{len(repos_without_scanning)} ECR repo(s) without scan-on-push: "
                        f"{', '.join(repos_without_scanning[:10])}."
                    ),
                    resolution=(
                        "Enable scan-on-push for all ECR repositories containing model containers. "
                        "Consider enabling Enhanced Scanning (Inspector) for CVE detection."
                    ),
                    reference="https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html",
                    severity="High",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-16"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-16",
                    finding_name="ECR Image Scanning Enabled",
                    finding_details=f"All {len(repos)} ECR repo(s) have scan-on-push enabled.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html",
                    severity="High",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-16"],
                )
            )
    except Exception as e:
        return _error_findings("ECR Image Scanning Check", e)
    return findings


# ===========================================================================
# CATEGORY 4: TRAINING DATA & MODEL POISONING (FS-17 to FS-21)
# Risk: Malicious data corrupts model behavior during training or fine-tuning
# COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, MAS TRM 9.3, ISO 27001 A.12]
#
# NOTE: FS-17 (Model Monitor Data Quality → SM-07), FS-18 (Model Drift Detection → SM-23),
# and FS-19 (Model Registry Approval → SM-22) are merged into upstream checks.
# See extension notes in SECURITY_CHECKS_FINSERV_PART1_INFRA_CONTROLS.md.
# ===========================================================================


def check_feature_store_rollback_capability() -> Dict[str, Any]:
    """
    FS-20 — Check SageMaker Feature Store for versioning/offline store
    configuration that enables rollback of poisoned feature data.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT]
    """
    findings = _empty_findings("Feature Store Rollback Check")
    try:
        sm = boto3.client("sagemaker", config=boto3_config)
        groups = _paginate(sm, "list_feature_groups", "FeatureGroupSummaries")

        if not groups:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-20",
                    finding_name="No SageMaker Feature Groups Found",
                    finding_details="No SageMaker Feature Store groups found.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/feature-store.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-20"],
                )
            )
            return findings

        groups_without_offline = [
            g["FeatureGroupName"]
            for g in groups
            if g.get("OfflineStoreStatus", {}).get("Status") != "Active"
        ]

        if groups_without_offline:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-20",
                    finding_name="Feature Groups Without Offline Store",
                    finding_details=(
                        f"{len(groups_without_offline)} feature group(s) lack an active offline store: "
                        f"{', '.join(groups_without_offline[:10])}. "
                        "Without offline store, historical feature data cannot be used for rollback."
                    ),
                    resolution=(
                        "1. Enable offline store (S3-backed) for all production feature groups.\n"
                        "2. Enable S3 versioning on the offline store bucket.\n"
                        "3. Document rollback procedures for poisoned feature data."
                    ),
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/feature-store-offline.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-20"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-20",
                    finding_name="Feature Store Offline Store Active",
                    finding_details=f"All {len(groups)} feature group(s) have active offline stores.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/feature-store-offline.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-20"],
                )
            )
    except Exception as e:
        return _error_findings("Feature Store Rollback Check", e)
    return findings


def check_training_data_s3_versioning(inventory) -> Dict[str, Any]:
    """
    FS-21 — Verify S3 buckets used for training data have versioning enabled
    to support rollback of poisoned datasets.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, ISO 27001 A.12.3, FFIEC CAT]
    """
    findings = _empty_findings("Training Data S3 Versioning Check")
    try:
        buckets = require(inventory, "buckets")
        s3 = boto3.client("s3", config=boto3_config)

        training_buckets = [
            b
            for b in buckets
            if any(
                kw in b["Name"].lower()
                for kw in ["train", "dataset", "model", "sagemaker", "bedrock"]
            )
        ]

        if not training_buckets:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-21",
                    finding_name="No Training Data Buckets Identified",
                    finding_details="No S3 buckets with training/model naming found.",
                    resolution="Tag training data buckets and enable versioning.",
                    reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-21"],
                )
            )
            return findings

        unversioned = []
        for bucket in training_buckets:
            try:
                versioning = s3.get_bucket_versioning(Bucket=bucket["Name"])
            except ClientError as e:
                # An access error means we could not read versioning; re-raise so
                # it surfaces as could-not-assess rather than a false finding, and
                # so one inaccessible bucket does not abort the whole check.
                if _is_access_error(e):
                    raise
                logger.warning(
                    f"Could not check versioning for bucket {bucket['Name']}: {e}"
                )
                unversioned.append(f"{bucket['Name']} (error)")
                continue
            if versioning.get("Status") != "Enabled":
                unversioned.append(bucket["Name"])

        if unversioned:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-21",
                    finding_name="Training Data Buckets Without Versioning",
                    finding_details=(
                        f"{len(unversioned)} training data bucket(s) without versioning: "
                        f"{', '.join(unversioned[:10])}."
                    ),
                    resolution=(
                        "Enable S3 versioning on all training data buckets. "
                        "Consider enabling MFA Delete for additional protection against poisoning."
                    ),
                    reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
                    severity="High",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-21"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-21",
                    finding_name="Training Data Buckets Have Versioning",
                    finding_details=f"All {len(training_buckets)} training bucket(s) have versioning enabled.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
                    severity="High",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-21"],
                )
            )
    except Exception as e:
        return _error_findings("Training Data S3 Versioning Check", e)
    return findings


# ===========================================================================
# CATEGORY 5: VECTOR & EMBEDDING WEAKNESSES (FS-22 to FS-26)
# Risk: Knowledge base / RAG vector stores are improperly secured
# COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, NYDFS 500.06, PCI-DSS 12.3.2]
# ===========================================================================


def _is_overbroad_kb_action(action: Any) -> bool:
    """True if an IAM action grants overly broad Bedrock/Knowledge Base access:
    the full wildcard, a service-wide bedrock(-agent) wildcard, or ANY partial
    wildcard within those namespaces (e.g., 'bedrock-agent:Get*', 'bedrock:Invoke*').
    Round-3 fixed the crash; this widens detection beyond the three exact wildcards."""
    if not isinstance(action, str):
        return False
    a = action.lower()
    if a in ("*", "bedrock:*", "bedrock-agent:*"):
        return True
    if a.endswith("*") and (a.startswith("bedrock:") or a.startswith("bedrock-agent:")):
        return True
    return False


def check_knowledge_base_iam_least_privilege(permission_cache) -> Dict[str, Any]:
    """
    FS-22 — Verify IAM roles accessing Bedrock Knowledge Bases follow
    least privilege (no wildcard bedrock-agent:* permissions).
    COMPLIANCE_PLACEHOLDER: [NYDFS 500.06, FFIEC CAT, PCI-DSS 12.3.2]
    """
    findings = _empty_findings("Knowledge Base IAM Least Privilege Check")
    try:
        issues = []
        for role_name, perms in (
            (permission_cache or {}).get("role_permissions", {}).items()
        ):
            if not isinstance(perms, dict):
                continue
            for policy in (perms.get("attached_policies", []) or []) + (
                perms.get("inline_policies", []) or []
            ):
                if not isinstance(policy, dict):
                    continue
                doc = policy.get("document", {})
                if isinstance(doc, str):
                    try:
                        doc = json.loads(doc)
                    except (ValueError, TypeError):
                        continue
                if not isinstance(doc, dict):
                    continue
                # IAM allows Statement to be a single object (dict) or a list.
                # Normalize to a list so iterating never yields statement *keys*
                # (the cause of the 'str' object has no attribute 'get' crash).
                statements = doc.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]
                for stmt in statements:
                    if not isinstance(stmt, dict):
                        continue
                    if stmt.get("Effect") != "Allow":
                        continue
                    # NotAction Allow ("allow everything except …") is inherently
                    # broad and the antithesis of least privilege — flag it.
                    if "NotAction" in stmt:
                        issues.append(
                            f"Role '{role_name}' uses a NotAction Allow (overly broad — "
                            "grants all actions except those listed)"
                        )
                    resources = stmt.get("Resource", [])
                    if isinstance(resources, str):
                        resources = [resources]
                    unscoped_resource = "*" in resources
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    for action in actions:
                        if _is_overbroad_kb_action(action):
                            issues.append(f"Role '{role_name}' allows '{action}'")
                        elif (
                            unscoped_resource
                            and isinstance(action, str)
                            and (
                                action.lower().startswith("bedrock:")
                                or action.lower().startswith("bedrock-agent:")
                            )
                        ):
                            issues.append(
                                f"Role '{role_name}' allows '{action}' on Resource '*' "
                                "(no ARN scoping to specific Knowledge Bases)"
                            )

        if issues:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-22",
                    finding_name="Overly Permissive Knowledge Base IAM Roles",
                    finding_details=(
                        f"{len(issues)} role(s) with wildcard KB permissions:\n"
                        + "\n".join(f"- {i}" for i in issues[:10])
                    ),
                    resolution=(
                        "Replace wildcard bedrock-agent:* with specific actions: "
                        "bedrock:Retrieve, bedrock:RetrieveAndGenerate. "
                        "Scope resources to specific Knowledge Base ARNs."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam-awsmanpol.html",
                    severity="High",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-22"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-22",
                    finding_name="Knowledge Base IAM Permissions Look Appropriate",
                    finding_details="No wildcard KB permissions found in reviewed roles.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam-awsmanpol.html",
                    severity="High",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-22"],
                )
            )
    except Exception as e:
        return _error_findings("Knowledge Base IAM Least Privilege Check", e)
    return findings


def check_knowledge_base_metadata_filtering(inventory) -> Dict[str, Any]:
    """
    FS-24 — Check that Bedrock Knowledge Bases have metadata fields configured
    to support tenant-level filtering (multi-tenancy isolation).
    COMPLIANCE_PLACEHOLDER: [NYDFS 500.06, FFIEC CAT, PCI-DSS 12.3.2]
    """
    findings = _empty_findings("Knowledge Base Metadata Filtering Check")
    try:
        kbs = require(inventory, "knowledge_bases").summaries

        if not kbs:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-24",
                    finding_name="No Knowledge Bases Found",
                    finding_details="No Bedrock Knowledge Bases found.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/kb-test-config.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-24"],
                )
            )
            return findings

        # Advisory check — metadata filtering is a design pattern, not directly inspectable
        findings["csv_data"].append(
            create_finding(
                check_id="FS-24",
                finding_name="ADVISORY: Knowledge Base Metadata Filtering — Manual Review Required",
                finding_details=(
                    f"Found {len(kbs)} Knowledge Base(s). Tenant-isolation metadata filtering is a "
                    "design pattern that cannot be verified via API — manual review required. "
                    "Verify that metadata attributes (e.g., tenantId, classification) are indexed "
                    "and that Retrieve calls include RetrievalFilter conditions for tenant isolation."
                ),
                resolution=(
                    "1. Add metadata fields (tenantId, dataClassification) to KB data sources.\n"
                    "2. Pass RetrievalFilter in all Retrieve/RetrieveAndGenerate calls.\n"
                    "3. Validate filters in integration tests to prevent cross-tenant data leakage."
                ),
                reference="https://docs.aws.amazon.com/bedrock/latest/userguide/kb-test-config.html",
                severity="Informational",
                status="N/A",
                compliance_frameworks=COMPLIANCE_MAP["FS-24"],
            )
        )
    except Exception as e:
        return _error_findings("Knowledge Base Metadata Filtering Check", e)
    return findings


def check_opensearch_serverless_encryption() -> Dict[str, Any]:
    """
    FS-25 — Verify OpenSearch Serverless collections (used as KB vector stores)
    have encryption policies with customer-managed KMS keys.
    COMPLIANCE_PLACEHOLDER: [NYDFS 500.06, PCI-DSS 3.5, FFIEC CAT]
    """
    findings = _empty_findings("OpenSearch Serverless Encryption Check")
    try:
        oss = boto3.client("opensearchserverless", config=boto3_config)
        policies = oss.list_security_policies(type="encryption").get(
            "securityPolicySummaries", []
        )

        if not policies:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-25",
                    finding_name="No OpenSearch Serverless Encryption Policies",
                    finding_details=(
                        "No OpenSearch Serverless encryption policies found, which indicates "
                        "no OpenSearch Serverless vector-store collections exist in this region. "
                        "If Bedrock Knowledge Bases use a different vector store (e.g., Aurora, "
                        "Pinecone), verify its encryption separately."
                    ),
                    resolution=(
                        "If using OpenSearch Serverless as a Bedrock KB vector store, create an "
                        "encryption security policy specifying a customer-managed KMS key."
                    ),
                    reference="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-encryption.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-25"],
                )
            )
        else:
            # Check for CMK usage. A policy that does not reference AWSOwnedKey is
            # treated as customer-managed (CMK).
            cmk_policies = []
            for policy in policies:
                doc = json.loads(policy.get("policy", "{}"))
                if "AWSOwnedKey" not in json.dumps(doc):
                    cmk_policies.append(policy["name"])

            if not cmk_policies:
                # Encryption policies exist but all use AWS-owned keys — the
                # control (customer-managed encryption) the check verifies is
                # absent, so this is a real finding, not a pass.
                findings["status"] = "WARN"
                findings["csv_data"].append(
                    create_finding(
                        check_id="FS-25",
                        finding_name="OpenSearch Serverless Encryption Not Using Customer-Managed Keys",
                        finding_details=(
                            f"Found {len(policies)} encryption policy(ies), but none use a "
                            "customer-managed KMS key (CMK) — all rely on AWS-owned keys. "
                            "FinServ data-protection controls typically require CMKs for "
                            "key lifecycle control and auditability."
                        ),
                        resolution=(
                            "Update OpenSearch Serverless encryption policies to specify a "
                            "customer-managed KMS key (KmsARN) instead of AWS-owned keys."
                        ),
                        reference="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-encryption.html",
                        severity="High",
                        status="Failed",
                        compliance_frameworks=COMPLIANCE_MAP["FS-25"],
                    )
                )
            else:
                findings["csv_data"].append(
                    create_finding(
                        check_id="FS-25",
                        finding_name="OpenSearch Serverless Encryption Policies Present",
                        finding_details=(
                            f"Found {len(policies)} encryption policy(ies); "
                            f"{len(cmk_policies)} use a customer-managed KMS key."
                        ),
                        resolution="Verify all vector store collections use customer-managed KMS keys.",
                        reference="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-encryption.html",
                        severity="High",
                        status="Passed",
                        compliance_frameworks=COMPLIANCE_MAP["FS-25"],
                    )
                )
    except Exception as e:
        return _error_findings("OpenSearch Serverless Encryption Check", e)
    return findings


def check_knowledge_base_vpc_access() -> Dict[str, Any]:
    """
    FS-26 — Verify OpenSearch Serverless collections have VPC access policies
    restricting access to private network endpoints.
    COMPLIANCE_PLACEHOLDER: [NYDFS 500.06, FFIEC CAT, PCI-DSS 1.3]
    """
    findings = _empty_findings("Knowledge Base VPC Access Check")
    try:
        oss = boto3.client("opensearchserverless", config=boto3_config)
        network_policies = oss.list_security_policies(type="network").get(
            "securityPolicySummaries", []
        )

        if not network_policies:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-26",
                    finding_name="No OpenSearch Serverless Network Policies",
                    finding_details=(
                        "No OpenSearch Serverless network policies found. "
                        "Vector store collections may be publicly accessible."
                    ),
                    resolution=(
                        "Create network security policies for OpenSearch Serverless collections "
                        "restricting access to VPC endpoints only."
                    ),
                    reference="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-network.html",
                    severity="High",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-26"],
                )
            )
        else:
            vpc_policies = []
            for policy in network_policies:
                doc = json.loads(policy.get("policy", "{}"))
                if "vpc" in json.dumps(doc).lower():
                    vpc_policies.append(policy["name"])

            if not vpc_policies:
                findings["status"] = "WARN"
                findings["csv_data"].append(
                    create_finding(
                        check_id="FS-26",
                        finding_name="OpenSearch Serverless Collections Not VPC-Restricted",
                        finding_details=(
                            f"Found {len(network_policies)} network policy(ies) but none restrict to VPC. "
                            "Vector stores may be accessible from the public internet."
                        ),
                        resolution=(
                            "Update network policies to allow access only from VPC endpoints. "
                            "Create an OpenSearch Serverless VPC endpoint in your VPC."
                        ),
                        reference="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-network.html",
                        severity="High",
                        status="Failed",
                        compliance_frameworks=COMPLIANCE_MAP["FS-26"],
                    )
                )
            else:
                findings["csv_data"].append(
                    create_finding(
                        check_id="FS-26",
                        finding_name="OpenSearch Serverless VPC Access Configured",
                        finding_details=f"{len(vpc_policies)} network policy(ies) restrict to VPC.",
                        resolution="No action required.",
                        reference="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-network.html",
                        severity="High",
                        status="Passed",
                        compliance_frameworks=COMPLIANCE_MAP["FS-26"],
                    )
                )
    except Exception as e:
        return _error_findings("Knowledge Base VPC Access Check", e)
    return findings


# ===========================================================================
# CATEGORY 6: NON-COMPLIANT OUTPUT (FS-27 to FS-30)
# Risk: GenAI outputs violate regulatory requirements (e.g., fair lending, disclosures)
# COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, NYDFS 500, MAS TRM 9.2]
# ===========================================================================


def check_guardrail_contextual_grounding(inventory) -> Dict[str, Any]:
    """
    FS-27 — Check whether Bedrock Guardrails have contextual grounding checks
    configured to validate that outputs are grounded in the provided context and
    are relevant to the user query.

    NOTE: This check verifies *contextual grounding* (guardrails-grounding) — a
    separate, independent feature from Automated Reasoning checks (ARC). True ARC
    is assessed in check_automated_reasoning_policies() below. Both controls are
    recommended for FinServ workloads; they complement each other:
      - Contextual grounding: thresholded relevance/grounding filter applied per
        inference call (no policy authoring required).
      - Automated Reasoning: policy-based formal verification of factual claims
        against a customer-authored business-rules document (GA August 2025;
        limited to US/EU regions; requires bedrock:ListAutomatedReasoningPolicies).

    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, MAS TRM 9.2]
    """
    findings = _empty_findings("Guardrail Contextual Grounding Check")
    try:
        guardrail_inv = require(inventory, "guardrails")
        guardrails = guardrail_inv.summaries

        if not guardrails:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-27",
                    finding_name="No Guardrails — Contextual Grounding Not Applicable",
                    finding_details="No Bedrock Guardrails configured. Configure guardrails first (see BR-05).",
                    resolution=(
                        "Configure Bedrock Guardrails with contextual grounding checks "
                        "(grounding threshold ≥0.7 and relevance threshold ≥0.7 for FinServ use cases)."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-grounding.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-27"],
                )
            )
            return findings

        guardrails_with_grounding = []
        for g in guardrails:
            detail = guardrail_inv.detail_by_id[g["id"]]
            if isinstance(detail, _Unavailable):
                raise detail.error
            if detail.get("contextualGroundingPolicy"):
                guardrails_with_grounding.append(g["name"])

        if not guardrails_with_grounding:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-27",
                    finding_name="No Guardrails With Contextual Grounding",
                    finding_details=(
                        f"Found {len(guardrails)} guardrail(s) but none have contextual grounding "
                        "filters enabled. Without grounding checks, outputs that are not supported "
                        "by the source context (hallucinations, regulatory violations) will not be "
                        "filtered at inference time."
                    ),
                    resolution=(
                        "Enable contextual grounding checks on Bedrock Guardrails:\n"
                        "- Set grounding threshold ≥0.7 (filters responses not supported by source context)\n"
                        "- Set relevance threshold ≥0.7 (filters off-topic responses)\n"
                        "Also consider enabling Automated Reasoning checks (bedrock:ListAutomatedReasoningPolicies) "
                        "for policy-based formal verification of factual claims — see FS-27 ARC check."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-grounding.html",
                    severity="High",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-27"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-27",
                    finding_name="Contextual Grounding Enabled on Guardrails",
                    finding_details=f"Guardrails with contextual grounding: {', '.join(guardrails_with_grounding)}.",
                    resolution=(
                        "No action required for contextual grounding. "
                        "Also consider enabling Automated Reasoning checks for formal policy verification."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-grounding.html",
                    severity="High",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-27"],
                )
            )
    except Exception as e:
        return _error_findings("Guardrail Contextual Grounding Check", e)
    return findings


def check_automated_reasoning_policies() -> Dict[str, Any]:
    """
    FS-27b — Check whether Bedrock Automated Reasoning policies have been
    created to provide formal, policy-based verification of GenAI factual claims.

    Automated Reasoning checks (ARC) — GA August 2025 — use formal verification
    to detect hallucinations and ensure outputs comply with authored business rules
    (e.g., loan eligibility criteria, regulatory thresholds). Unlike contextual
    grounding (a threshold applied per call), ARC requires authoring an Automated
    Reasoning Policy document containing the rules to verify against.

    Regions supported (verify against current AWS docs at run time —
    https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-automated-reasoning-checks.html):
    AWS GovCloud (US), us-east-1, us-east-2, us-west-2, eu-central-1, eu-west-1,
    eu-west-3. The list expands over time; treat a region miss as "verify
    availability", not a hard limitation.

    IAM action required: bedrock:ListAutomatedReasoningPolicies

    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, MAS TRM 9.2]
    """
    findings = _empty_findings("Automated Reasoning Policies Check")
    try:
        bedrock = boto3.client("bedrock", config=boto3_config)

        try:
            policies = _paginate(
                bedrock,
                "list_automated_reasoning_policies",
                "automatedReasoningPolicySummaries",
            )
        except ClientError as e:
            if _is_access_error(e):
                findings["csv_data"].append(
                    create_finding(
                        check_id="FS-27",
                        finding_name="Automated Reasoning Policies — Access Check",
                        finding_details=(
                            "Access denied or service unavailable when listing Automated Reasoning "
                            "policies. The IAM action name (bedrock:ListAutomatedReasoningPolicies) "
                            "is correct, so the most likely causes are, in order: (1) the assessment "
                            "MEMBER ROLE in this account was deployed before this action was added "
                            "and has not been re-deployed; (2) an AWS Organizations SCP or permission "
                            "boundary denies this newer Bedrock action; (3) the region does not "
                            "support ARC. ARC is available in AWS GovCloud (US) and a growing set "
                            "of commercial regions (e.g., us-east-1, us-east-2, us-west-2, "
                            "eu-central-1, eu-west-1, eu-west-3) — verify the current list in the "
                            "AWS documentation."
                        ),
                        resolution=(
                            "1. RE-DEPLOY the member-role CloudFormation stack so the role picks up "
                            "bedrock:ListAutomatedReasoningPolicies (templates may be current while "
                            "the *deployed* role is stale). See deployment/1-aiml-security-member-roles.yaml "
                            "and aiml-security-single-account.yaml.\n"
                            "2. Check for an Organizations SCP / permission boundary denying the action.\n"
                            "3. Confirm the assessed region supports Automated Reasoning checks.\n"
                            "4. Re-run the assessment after re-deploying."
                        ),
                        reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html",
                        severity="Low",
                        status="N/A",
                        compliance_frameworks=COMPLIANCE_MAP["FS-27"],
                    )
                )
                return findings
            raise

        if not policies:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-27",
                    finding_name="No Automated Reasoning Policies Found",
                    finding_details=(
                        "No Bedrock Automated Reasoning policies have been created. "
                        "ARC (GA August 2025) uses formal verification to guarantee that GenAI "
                        "outputs comply with authored business rules — e.g., loan criteria, "
                        "regulatory thresholds, policy constraints. Without ARC policies, "
                        "factual accuracy of outputs is not formally verified, only heuristically "
                        "filtered by contextual grounding thresholds."
                    ),
                    resolution=(
                        "1. In the Amazon Bedrock console → Guardrails → Automated Reasoning, "
                        "create a policy document encoding your FinServ business rules "
                        "(e.g., eligibility criteria, rate limits, regulatory thresholds).\n"
                        "2. Associate the ARC policy with your guardrail "
                        "(automatedReasoningPolicy.policies field in CreateGuardrail/UpdateGuardrail).\n"
                        "3. Set confidenceThreshold on the policy to control strictness.\n"
                        "4. ARC requires cross-Region inference — ensure your guardrail has a "
                        "guardrailProfileArn configured (crossRegionDetails in GetGuardrail response).\n"
                        "5. Reference: AWS Announcement — Automated Reasoning checks GA (August 2025)."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/automated-reasoning.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-27"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-27",
                    finding_name="Automated Reasoning Policies Found",
                    finding_details=(
                        f"Found {len(policies)} Automated Reasoning policy(ies): "
                        f"{', '.join(p['name'] for p in policies[:5])}. "
                        "Verify policies are associated with active guardrails via the "
                        "automatedReasoningPolicy field in GetGuardrail."
                    ),
                    resolution=(
                        "Confirm each ARC policy is referenced in a guardrail's "
                        "automatedReasoningPolicy.policies list and that the "
                        "guardrail is applied to your Bedrock inference calls."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/automated-reasoning.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-27"],
                )
            )
    except Exception as e:
        return _error_findings("Automated Reasoning Policies Check", e)
    return findings


def check_guardrail_denied_topics_financial(inventory) -> Dict[str, Any]:
    """
    FS-28 — Verify Bedrock Guardrails have denied topics configured for
    regulated financial advice categories (investment advice, credit decisions).
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, NYDFS 500, MAS TRM 9.2]
    """
    findings = _empty_findings("Financial Denied Topics Check")
    try:
        guardrail_inv = require(inventory, "guardrails")
        guardrails = guardrail_inv.summaries

        if not guardrails:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-28",
                    finding_name="No Guardrails — Denied Topics Not Applicable",
                    finding_details="No Bedrock Guardrails configured.",
                    resolution="Configure guardrails with denied topics for regulated financial content.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-28"],
                )
            )
            return findings

        guardrails_with_topics = []
        topics_classic_tier = []
        for g in guardrails:
            detail = guardrail_inv.detail_by_id[g["id"]]
            if isinstance(detail, _Unavailable):
                raise detail.error
            topic_policy = detail.get("topicPolicy", {})
            if topic_policy.get("topics"):
                guardrails_with_topics.append(g["name"])
                # Denied topics also support tiers (GA June 2025). STANDARD tier
                # adds broader language support and improved detection but requires
                # cross-region inference. topicPolicy.tier.tierName in GetGuardrail.
                tier = topic_policy.get("tier", {}).get("tierName", "CLASSIC")
                if tier == "CLASSIC":
                    topics_classic_tier.append(g["name"])

        if not guardrails_with_topics:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-28",
                    finding_name="No Guardrails With Denied Financial Topics",
                    finding_details=(
                        "No guardrails have topic policies configured. "
                        "GenAI may provide regulated financial advice without controls."
                    ),
                    resolution=(
                        "Add denied topics to guardrails for:\n"
                        "- Specific investment advice (securities recommendations)\n"
                        "- Credit/lending decisions\n"
                        "- Insurance underwriting advice\n"
                        "- Tax advice beyond general information\n"
                        "When authoring denied-topic policies, use existing compliance materials "
                        "as the source: employee policies, training materials, procedure documents, "
                        "and incident reports (as recommended in PDF \u00a71.2.1 Practical guidance). "
                        "Consider the STANDARD tier (GA June 2025) for broader language support; "
                        "it requires cross-region inference on the guardrail."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.html",
                    severity="High",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-28"],
                )
            )
        elif topics_classic_tier:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-28",
                    finding_name="Denied Topics Configured on CLASSIC Tier",
                    finding_details=(
                        f"Guardrails with topic policies: {', '.join(guardrails_with_topics)}. "
                        f"The following use the CLASSIC tier: {', '.join(topics_classic_tier)}. "
                        "CLASSIC tier supports English, French, and Spanish only. The STANDARD tier "
                        "(GA June 2025) provides broader language support and improved detection for "
                        "denied topics."
                    ),
                    resolution=(
                        "Verify topics cover regulated financial advice categories. For multilingual "
                        "FinServ deployments, consider upgrading denied topics to the STANDARD tier "
                        "(set topicsTierConfig.tierName=STANDARD via UpdateGuardrail; requires a "
                        "cross-region inference profile on the guardrail). When authoring denied-topic "
                        "policies, use existing compliance materials as the source: employee policies, "
                        "training materials, procedure documents, and incident reports "
                        "(PDF \u00a71.2.1 Practical guidance)."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.html",
                    severity="High",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-28"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-28",
                    finding_name="Guardrails With Topic Policies Found",
                    finding_details=f"Guardrails with topic policies: {', '.join(guardrails_with_topics)}.",
                    resolution=(
                        "Verify topics cover regulated financial advice categories. "
                        "When authoring or updating denied-topic policies, use existing compliance "
                        "materials as the source: employee policies, training materials, procedure "
                        "documents, and incident reports (as recommended in PDF \u00a71.2.1 Practical guidance)."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.html",
                    severity="High",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-28"],
                )
            )
    except Exception as e:
        return _error_findings("Financial Denied Topics Check", e)
    return findings


def check_compliance_disclaimer_in_outputs() -> Dict[str, Any]:
    """
    FS-29 — Advisory check: verify application-level disclaimers are added to
    GenAI outputs for regulated financial content (not directly checkable via API).
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, NYDFS 500, MAS TRM 9.2]
    """
    findings = _empty_findings("Compliance Disclaimer Check")
    # This is an advisory/manual check — no AWS API can verify application-level disclaimers
    findings["csv_data"].append(
        create_finding(
            check_id="FS-29",
            finding_name="ADVISORY: Compliance Disclaimer — Manual Review Required",
            finding_details=(
                "Application-level compliance disclaimers cannot be verified via AWS APIs. "
                "Manual review required to confirm GenAI outputs include required regulatory disclosures."
            ),
            resolution=(
                "1. Implement post-processing to append required disclaimers to GenAI outputs.\n"
                "2. Use Bedrock Guardrails word filters to block outputs that omit required disclosures.\n"
                "3. Document disclaimer requirements in the AI use case register.\n"
                "4. Test disclaimer presence in QA/UAT before production deployment."
            ),
            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.html",
            severity="Informational",
            status="N/A",
            compliance_frameworks=COMPLIANCE_MAP["FS-29"],
        )
    )
    return findings


def check_bedrock_evaluation_compliance_datasets() -> Dict[str, Any]:
    """
    FS-30 — Advisory: Bedrock Model Evaluation jobs should use compliance-specific
    datasets (e.g., fair lending, UDAP, ECOA test cases).

    The Bedrock evaluation-job APIs do not expose dataset *content*, so whether a
    job actually includes compliance test cases cannot be verified programmatically.
    This is therefore an advisory (manual-review) check. The existence of evaluation
    jobs at all is the verifiable control and is assessed by FS-15.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, NYDFS 500]
    """
    findings = _empty_findings("Compliance Evaluation Datasets Check")
    try:
        findings["csv_data"].append(
            create_finding(
                check_id="FS-30",
                finding_name="ADVISORY: Compliance Dataset Coverage — Manual Review Required",
                finding_details=(
                    "Bedrock model-evaluation dataset content cannot be inspected via API. "
                    "Manually verify your model-evaluation jobs include compliance-specific "
                    "datasets (fair lending/ECOA, Fair Housing Act, UDAP/UDAAP, AML/KYC edge cases). "
                    "Whether any evaluation jobs exist at all is assessed by FS-15."
                ),
                resolution=(
                    "Run Bedrock Model Evaluation with compliance-specific datasets:\n"
                    "- Fair lending test cases (ECOA, Fair Housing Act)\n"
                    "- UDAP/UDAAP unfair/deceptive practice scenarios\n"
                    "- AML/KYC edge cases"
                ),
                reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-evaluation.html",
                severity="Informational",
                status="N/A",
                compliance_frameworks=COMPLIANCE_MAP["FS-30"],
            )
        )
    except Exception as e:
        return _error_findings("Compliance Evaluation Datasets Check", e)
    return findings


# ===========================================================================
# CATEGORY 7: MISINFORMATION (FS-31 to FS-34)
# Risk: GenAI outputs contain false or misleading financial information
# COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, MAS TRM 9.2, NYDFS 500]
# ===========================================================================


def check_knowledge_base_data_source_sync(inventory) -> Dict[str, Any]:
    """
    FS-31 — Verify Bedrock Knowledge Base data sources have recent sync jobs
    to ensure information currency.

    Staleness threshold: AWS does not prescribe a maximum data age for Knowledge
    Bases — the appropriate cadence is workload-specific (intraday for market
    data, weekly/monthly for slow-changing regulatory guidance). This check uses
    a default of 7 days purely as a review prompt; treat a finding as "confirm
    your data-currency requirement is met," not as an AWS-mandated failure.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT]
    """
    # Default review threshold (days). Not an AWS requirement — a configurable
    # heuristic. Firms with stricter or looser currency needs should adjust this.
    STALE_AFTER_DAYS = 7
    findings = _empty_findings("Knowledge Base Data Source Sync Check")
    try:
        kb_inv = require(inventory, "knowledge_bases")
        kbs = kb_inv.summaries

        if not kbs:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-31",
                    finding_name="No Knowledge Bases Found",
                    finding_details="No Bedrock Knowledge Bases found.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base-ingest.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-31"],
                )
            )
            return findings

        stale_kbs = []
        now = datetime.now(timezone.utc)
        for kb in kbs:
            kb_id = kb["knowledgeBaseId"]
            sources = kb_inv.data_sources_by_kb.get(kb_id, [])
            if isinstance(sources, _Unavailable):
                raise sources.error
            for source in sources:
                last_updated = source.get("updatedAt")
                if last_updated:
                    age_days = (now - last_updated).days
                    if age_days > STALE_AFTER_DAYS:
                        stale_kbs.append(
                            f"KB '{kb['name']}' source '{source['name']}' last synced {age_days} days ago"
                        )

        if stale_kbs:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-31",
                    finding_name="Knowledge Base Data Sources Past Review Threshold",
                    finding_details=(
                        f"{len(stale_kbs)} data source(s) not synced in >{STALE_AFTER_DAYS} days "
                        f"(a configurable review threshold, NOT an AWS-mandated limit):\n"
                        + "\n".join(f"- {s}" for s in stale_kbs[:10])
                        + "\nConfirm this age is acceptable for each data source's currency "
                        "requirement — slow-changing reference data may legitimately sync infrequently."
                    ),
                    resolution=(
                        "1. Define the maximum acceptable data age per use case (e.g., intraday for "
                        "market data, daily for product terms, weekly/monthly for regulatory guidance) "
                        "and adjust the review threshold to match.\n"
                        "2. Configure automated sync (EventBridge Scheduler → StartIngestionJob) at "
                        "that cadence — see FS-61.\n"
                        "3. Set CloudWatch alarms on sync job failures."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base-ingest.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-31"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-31",
                    finding_name="Knowledge Base Data Sources Recently Synced",
                    finding_details=(
                        f"All reviewed KB data sources synced within {STALE_AFTER_DAYS} days "
                        "(the default review threshold)."
                    ),
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base-ingest.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-31"],
                )
            )
    except Exception as e:
        return _error_findings("Knowledge Base Data Source Sync Check", e)
    return findings


def check_source_attribution_in_guardrails() -> Dict[str, Any]:
    """
    FS-32 — Advisory check: verify application implements source attribution
    (citations) in GenAI responses to enable fact-checking.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, MAS TRM 9.2]
    """
    findings = _empty_findings("Source Attribution Check")
    findings["csv_data"].append(
        create_finding(
            check_id="FS-32",
            finding_name="ADVISORY: Source Attribution — Manual Review Required",
            finding_details=(
                "Source attribution in GenAI responses cannot be verified via AWS APIs. "
                "Manual review required to confirm responses include citations."
            ),
            resolution=(
                "1. Use Bedrock RetrieveAndGenerate with citations enabled.\n"
                "2. Include source document references in response post-processing.\n"
                "3. Test citation accuracy in QA before production deployment.\n"
                "4. Consider Bedrock Guardrails grounding checks to validate response accuracy."
            ),
            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/kb-test-config.html",
            severity="Informational",
            status="N/A",
            compliance_frameworks=COMPLIANCE_MAP["FS-32"],
        )
    )
    return findings


def check_knowledge_base_integrity_monitoring(inventory) -> Dict[str, Any]:
    """
    FS-33 — Check for S3 object integrity monitoring (checksums, versioning)
    on Knowledge Base data source buckets.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, ISO 27001 A.12.3, FFIEC CAT]
    """
    findings = _empty_findings("Knowledge Base Integrity Monitoring Check")
    try:
        kb_inv = require(inventory, "knowledge_bases")
        kbs = kb_inv.summaries
        s3 = boto3.client("s3", config=boto3_config)

        if not kbs:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-33",
                    finding_name="No Knowledge Bases Found",
                    finding_details="No Bedrock Knowledge Bases found.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-33"],
                )
            )
            return findings

        buckets_without_versioning = []
        missing_buckets = []
        for kb in kbs:
            kb_id = kb["knowledgeBaseId"]
            sources = kb_inv.data_sources_by_kb.get(kb_id, [])
            if isinstance(sources, _Unavailable):
                raise sources.error
            for source in sources:
                ds_id = source["dataSourceId"]
                source_detail = kb_inv.data_source_detail.get((kb_id, ds_id))
                if isinstance(source_detail, _Unavailable):
                    raise source_detail.error
                if source_detail is None:
                    continue
                s3_config = (
                    source_detail.get("dataSource", {})
                    .get("dataSourceConfiguration", {})
                    .get("s3Configuration", {})
                )
                bucket = _bucket_name_from_arn(s3_config.get("bucketArn", ""))
                if bucket:
                    try:
                        versioning = s3.get_bucket_versioning(Bucket=bucket)
                        if versioning.get("Status") != "Enabled":
                            buckets_without_versioning.append(bucket)
                    except ClientError as e:
                        # An access error means we could not read versioning; do
                        # not mislabel the bucket as non-versioned. Re-raise so it
                        # surfaces as could-not-assess instead of a false finding.
                        if _is_access_error(e):
                            raise
                        # The data source points to a bucket that no longer exists
                        # (deleted out from under the KB). This is a distinct,
                        # actionable integrity problem — report it separately, not
                        # as "missing versioning."
                        if _is_missing_bucket_error(e):
                            logger.warning(
                                f"KB '{kb['name']}' data source '{source['name']}' "
                                f"references a deleted bucket: {bucket}"
                            )
                            missing_buckets.append(
                                f"{bucket} (KB '{kb['name']}', source '{source['name']}')"
                            )
                            continue
                        logger.warning(
                            f"Could not check versioning for bucket {bucket}: {e}"
                        )
                        buckets_without_versioning.append(f"{bucket} (error)")

        # A dangling data-source reference to a deleted bucket is a real integrity
        # finding in its own right — emit it as a separate row so it is not
        # conflated with "versioning not enabled."
        if missing_buckets:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-33",
                    finding_name="KB Data Source References a Deleted S3 Bucket",
                    finding_details=(
                        "One or more Knowledge Base data sources point to S3 buckets that no "
                        "longer exist (NoSuchBucket). Retrieval will silently return no results "
                        "for these sources, and the integrity of the KB's grounding data cannot "
                        "be verified:\n"
                        + "\n".join(f"- {b}" for b in missing_buckets[:10])
                    ),
                    resolution=(
                        "1. Investigate why the data-source bucket was deleted (accidental "
                        "deletion, environment teardown, or a stale KB configuration).\n"
                        "2. Recreate/restore the bucket with versioning enabled, or remove the "
                        "orphaned data source from the Knowledge Base.\n"
                        "3. Re-run a KB ingestion job after restoring the data source.\n"
                        "4. Enable S3 versioning and MFA Delete on KB data-source buckets to "
                        "reduce the risk of unrecoverable deletion."
                    ),
                    reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html",
                    severity="High",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-33"],
                )
            )

        if buckets_without_versioning:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-33",
                    finding_name="KB Data Source Buckets Without Versioning",
                    finding_details=(
                        f"KB data source S3 buckets without versioning: "
                        f"{', '.join(buckets_without_versioning[:10])}."
                    ),
                    resolution=(
                        "Enable S3 versioning on all KB data source buckets. "
                        "Enable S3 Object Integrity (checksum) for tamper detection."
                    ),
                    reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-33"],
                )
            )
        elif not missing_buckets:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-33",
                    finding_name="KB Data Source Buckets Have Versioning",
                    finding_details="All reviewed KB data source buckets have versioning enabled.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-33"],
                )
            )
    except Exception as e:
        return _error_findings("Knowledge Base Integrity Monitoring Check", e)
    return findings


def check_fm_version_currency() -> Dict[str, Any]:
    """
    FS-34 — Advisory check: verify foundation model versions in use are current
    and not deprecated (outdated models may have stale training data).
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT]
    """
    findings = _empty_findings("Foundation Model Version Currency Check")
    try:
        bedrock = boto3.client("bedrock", config=boto3_config)
        # Do not filter by output modality: legacy/deprecated models exist across
        # TEXT, EMBEDDING, and IMAGE modalities. Embedding models are widely used
        # in FinServ RAG pipelines and a legacy embedding model produces stale
        # embeddings — missing it would be a false-pass. Fetch all modalities and
        # let the LEGACY lifecycle filter identify any deprecated model in use.
        models = bedrock.list_foundation_models().get("modelSummaries", [])

        deprecated = [
            m["modelId"]
            for m in models
            if m.get("modelLifecycle", {}).get("status") == "LEGACY"
        ]

        if deprecated:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-34",
                    finding_name="Legacy Foundation Models Available in Region",
                    finding_details=(
                        f"Legacy/deprecated foundation models are available in this account/region: "
                        f"{', '.join(deprecated[:10])}. This API reports model *availability*, not "
                        "actual usage — it cannot determine which models your applications invoke. "
                        "Legacy models have older training-data cutoffs and may produce outdated "
                        "information if used. Review whether any are in active use."
                    ),
                    resolution=(
                        "1. Identify which (if any) of these legacy models your applications invoke "
                        "(e.g., via CloudTrail InvokeModel events or application config).\n"
                        "2. Migrate active usage to current model versions.\n"
                        "3. Document training-data cutoff dates for all models in use.\n"
                        "4. Add data-currency disclaimers to outputs from models with old cutoffs."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-lifecycle.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-34"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-34",
                    finding_name="Foundation Models Are Current",
                    finding_details="No legacy/deprecated foundation models detected.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-lifecycle.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-34"],
                )
            )
    except Exception as e:
        return _error_findings("Foundation Model Version Currency Check", e)
    return findings


# ===========================================================================
# CATEGORY 8: ABUSIVE OR HARMFUL OUTPUT (FS-35 to FS-38)
# CATEGORY 9: BIASED OUTPUT (FS-39 to FS-42)
# COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, MAS TRM 9.2, NYDFS 500]
# ===========================================================================


def check_fmeval_harmful_content() -> Dict[str, Any]:
    """
    FS-35 — Check for FMEval or Bedrock Evaluation jobs testing for harmful
    content (toxicity, hate speech, violence).
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, MAS TRM 9.2]
    """
    findings = _empty_findings("FMEval Harmful Content Check")
    try:
        findings["csv_data"].append(
            create_finding(
                check_id="FS-35",
                finding_name="ADVISORY: Harmful-Content Test Coverage — Manual Review Required",
                finding_details=(
                    "Bedrock model-evaluation dataset content cannot be inspected via API. "
                    "Manually verify your model-evaluation/FMEval jobs include harmful-content "
                    "datasets (toxicity, hate speech, violence/self-harm). Whether any evaluation "
                    "jobs exist at all is assessed by FS-15."
                ),
                resolution=(
                    "Run Bedrock Model Evaluation or FMEval with harmful content datasets:\n"
                    "- Toxicity detection\n"
                    "- Hate speech classification\n"
                    "- Violence/self-harm content"
                ),
                reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-evaluation.html",
                severity="Informational",
                status="N/A",
                compliance_frameworks=COMPLIANCE_MAP["FS-35"],
            )
        )
    except Exception as e:
        return _error_findings("FMEval Harmful Content Check", e)
    return findings


def check_guardrail_content_filters(inventory) -> Dict[str, Any]:
    """
    FS-36 — Verify Bedrock Guardrails have content filters configured for
    hate speech, violence, and sexual content at appropriate thresholds.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, MAS TRM 9.2]
    """
    findings = _empty_findings("Guardrail Content Filters Check")
    try:
        guardrail_inv = require(inventory, "guardrails")
        guardrails = guardrail_inv.summaries

        if not guardrails:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-36",
                    finding_name="No Guardrails — Content Filters Not Applicable",
                    finding_details="No Bedrock Guardrails configured.",
                    resolution="Configure guardrails with content filters.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-filters.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-36"],
                )
            )
            return findings

        guardrails_with_filters = []
        guardrails_classic_tier = []
        for g in guardrails:
            detail = guardrail_inv.detail_by_id[g["id"]]
            if isinstance(detail, _Unavailable):
                raise detail.error
            content_policy = detail.get("contentPolicy", {})
            if content_policy.get("filters"):
                guardrails_with_filters.append(g["name"])
                # Check tier: STANDARD offers better accuracy, multilingual support,
                # and improved prompt-attack detection (GA June 2025). FinServ
                # workloads benefit from STANDARD for its contextual understanding and
                # typo-tolerant detection. STANDARD requires cross-region inference.
                # The tier is nested at contentPolicy.tier.tierName in GetGuardrail response.
                tier = content_policy.get("tier", {}).get("tierName", "CLASSIC")
                if tier == "CLASSIC":
                    guardrails_classic_tier.append(g["name"])

        if not guardrails_with_filters:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-36",
                    finding_name="No Guardrails With Content Filters",
                    finding_details=(
                        f"Found {len(guardrails)} guardrail(s) but none have content filters. "
                        "Harmful content (hate, violence, sexual) may pass through unfiltered."
                    ),
                    resolution=(
                        "1. Add content filters to guardrails for: HATE, INSULTS, SEXUAL, VIOLENCE.\n"
                        "2. Set filter strength to HIGH for financial services use cases.\n"
                        "3. Consider the STANDARD tier (GA June 2025) for improved accuracy, "
                        "typographical error detection, and 60+ language support. STANDARD tier "
                        "requires cross-region inference to be enabled on the guardrail."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-filters.html",
                    severity="High",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-36"],
                )
            )
        elif guardrails_classic_tier:
            # Content filters exist but using CLASSIC tier — emit advisory finding
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-36",
                    finding_name="Guardrail Content Filters on CLASSIC Tier",
                    finding_details=(
                        f"Guardrails with content filters: {', '.join(guardrails_with_filters)}. "
                        f"The following use the CLASSIC tier: {', '.join(guardrails_classic_tier)}. "
                        "CLASSIC tier supports English, French, and Spanish only. The STANDARD tier "
                        "(GA June 2025) provides improved contextual understanding, typographical error "
                        "detection, 60+ language support, and better prompt-attack classification "
                        "(distinguishes jailbreaks from prompt injection)."
                    ),
                    resolution=(
                        "Consider upgrading to STANDARD tier content filters for FinServ workloads "
                        "that handle multiple languages or require higher detection accuracy. "
                        "STANDARD tier requires cross-region inference "
                        "(crossRegionDetails.guardrailProfileArn on the guardrail). "
                        "To upgrade: update the guardrail's contentPolicy.filtersConfig.contentFiltersTierConfig "
                        "with tierName=STANDARD and configure a guardrail cross-region profile."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-filters.html",
                    severity="High",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-36"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-36",
                    finding_name="Guardrail Content Filters Configured (STANDARD Tier)",
                    finding_details=(
                        f"All {len(guardrails_with_filters)} guardrail(s) with content filters "
                        "use the STANDARD tier, providing improved accuracy and multilingual support."
                    ),
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-filters.html",
                    severity="High",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-36"],
                )
            )
    except Exception as e:
        return _error_findings("Guardrail Content Filters Check", e)
    return findings


def check_user_feedback_mechanism() -> Dict[str, Any]:
    """
    FS-37 — Advisory check: verify application has a user feedback/reporting
    mechanism for harmful GenAI outputs.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, MAS TRM 9.2]
    """
    findings = _empty_findings("User Feedback Mechanism Check")
    findings["csv_data"].append(
        create_finding(
            check_id="FS-37",
            finding_name="ADVISORY: User Feedback Mechanism — Manual Review Required",
            finding_details=(
                "User feedback mechanisms for harmful outputs cannot be verified via AWS APIs. "
                "Manual review required."
            ),
            resolution=(
                "1. Implement thumbs-up/down or flag-for-review UI in GenAI applications.\n"
                "2. Route flagged outputs to human reviewers via SQS/SNS.\n"
                "3. Log feedback to DynamoDB/S3 for model improvement.\n"
                "4. Define SLAs for reviewing flagged content."
            ),
            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html",
            severity="Informational",
            status="N/A",
            compliance_frameworks=COMPLIANCE_MAP["FS-37"],
        )
    )
    return findings


def check_guardrail_word_filters(inventory) -> Dict[str, Any]:
    """
    FS-38 — Verify Bedrock Guardrails have word/phrase filters (allowlists/denylists)
    configured for financial services context.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT]
    """
    findings = _empty_findings("Guardrail Word Filters Check")
    try:
        guardrail_inv = require(inventory, "guardrails")
        guardrails = guardrail_inv.summaries

        if not guardrails:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-38",
                    finding_name="No Guardrails — Word Filters Not Applicable",
                    finding_details="No Bedrock Guardrails configured.",
                    resolution="Configure guardrails with word filters.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-38"],
                )
            )
            return findings

        guardrails_with_words = []
        for g in guardrails:
            detail = guardrail_inv.detail_by_id[g["id"]]
            if isinstance(detail, _Unavailable):
                raise detail.error
            if detail.get("wordPolicy", {}).get("words") or detail.get(
                "wordPolicy", {}
            ).get("managedWordLists"):
                guardrails_with_words.append(g["name"])

        if not guardrails_with_words:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-38",
                    finding_name="No Guardrails With Word Filters",
                    finding_details=(
                        f"Found {len(guardrails)} guardrail(s) but none have word/phrase filters. "
                        "Profanity and prohibited financial terms may appear in outputs."
                    ),
                    resolution=(
                        "Add word filters to guardrails:\n"
                        "- Enable AWS managed profanity list\n"
                        "- Add custom denylist for prohibited financial terms\n"
                        "- Add allowlist for required regulatory language"
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-38"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-38",
                    finding_name="Guardrail Word Filters Configured",
                    finding_details=f"Guardrails with word filters: {', '.join(guardrails_with_words)}.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-38"],
                )
            )
    except Exception as e:
        return _error_findings("Guardrail Word Filters Check", e)
    return findings


def check_sagemaker_clarify_bias() -> Dict[str, Any]:
    """
    FS-39 — Verify SageMaker Clarify bias detection jobs are configured for
    production models making financial decisions.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, ECOA, Fair Housing Act]
    """
    findings = _empty_findings("SageMaker Clarify Bias Check")
    try:
        sm = boto3.client("sagemaker", config=boto3_config)
        schedules = _paginate(
            sm, "list_monitoring_schedules", "MonitoringScheduleSummaries"
        )

        bias_schedules = [
            s for s in schedules if s.get("MonitoringType") == "ModelBias"
        ]

        if not bias_schedules:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-39",
                    finding_name="No SageMaker Clarify Bias Monitoring",
                    finding_details=(
                        "No SageMaker Clarify model bias monitoring schedules found. "
                        "Models making financial decisions (credit, insurance) may exhibit "
                        "discriminatory bias without detection."
                    ),
                    resolution=(
                        "1. Configure SageMaker Clarify bias detection for all models making "
                        "credit, insurance, or employment decisions.\n"
                        "2. Define protected attributes (age, gender, race proxies).\n"
                        "3. Set bias metric thresholds and alert on violations.\n"
                        "4. Document bias testing results for regulatory examination."
                    ),
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-model-monitor-bias-drift.html",
                    severity="High",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-39"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-39",
                    finding_name="SageMaker Clarify Bias Monitoring Active",
                    finding_details=f"Found {len(bias_schedules)} model bias monitoring schedule(s).",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-model-monitor-bias-drift.html",
                    severity="High",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-39"],
                )
            )
    except Exception as e:
        return _error_findings("SageMaker Clarify Bias Check", e)
    return findings


def check_bedrock_evaluation_bias_datasets() -> Dict[str, Any]:
    """
    FS-40 — Check whether Bedrock Model Evaluation includes bias-specific
    test datasets for GenAI models used in financial decisions.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, ECOA]
    """
    findings = _empty_findings("Bedrock Bias Evaluation Datasets Check")
    try:
        findings["csv_data"].append(
            create_finding(
                check_id="FS-40",
                finding_name="ADVISORY: Bias Dataset Coverage — Manual Review Required",
                finding_details=(
                    "Bedrock model-evaluation dataset content cannot be inspected via API. "
                    "Manually verify your model-evaluation jobs include bias/fairness datasets "
                    "(demographic parity, equal-opportunity, counterfactual fairness) for any "
                    "GenAI models used in financial decisions (ECOA/Fair Housing). Whether any "
                    "evaluation jobs exist at all is assessed by FS-15."
                ),
                resolution=(
                    "Run Bedrock Model Evaluation with bias test datasets:\n"
                    "- Demographic parity test cases\n"
                    "- Equal opportunity scenarios\n"
                    "- Counterfactual fairness tests"
                ),
                reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-evaluation.html",
                severity="Informational",
                status="N/A",
                compliance_frameworks=COMPLIANCE_MAP["FS-40"],
            )
        )
    except Exception as e:
        return _error_findings("Bedrock Bias Evaluation Datasets Check", e)
    return findings


def check_sagemaker_clarify_explainability() -> Dict[str, Any]:
    """
    FS-41 — Verify SageMaker Clarify explainability jobs are configured to
    provide model decision explanations for adverse action notices.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, ECOA Adverse Action]
    """
    findings = _empty_findings("SageMaker Clarify Explainability Check")
    try:
        sm = boto3.client("sagemaker", config=boto3_config)
        schedules = _paginate(
            sm, "list_monitoring_schedules", "MonitoringScheduleSummaries"
        )

        explainability_schedules = [
            s for s in schedules if s.get("MonitoringType") == "ModelExplainability"
        ]

        if not explainability_schedules:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-41",
                    finding_name="No SageMaker Clarify Explainability Monitoring",
                    finding_details=(
                        "No SageMaker Clarify explainability monitoring found. "
                        "Models making adverse financial decisions may not provide "
                        "required explanations (ECOA adverse action notices)."
                    ),
                    resolution=(
                        "1. Configure SageMaker Clarify explainability for credit/lending models.\n"
                        "2. Generate SHAP values for feature importance.\n"
                        "3. Map top features to human-readable adverse action reason codes.\n"
                        "4. Store explanations for regulatory examination."
                    ),
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-model-explainability.html",
                    severity="High",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-41"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-41",
                    finding_name="SageMaker Clarify Explainability Active",
                    finding_details=f"Found {len(explainability_schedules)} explainability monitoring schedule(s).",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-model-explainability.html",
                    severity="High",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-41"],
                )
            )
    except Exception as e:
        return _error_findings("SageMaker Clarify Explainability Check", e)
    return findings


def check_ai_service_cards_documentation() -> Dict[str, Any]:
    """
    FS-42 — Advisory check: verify AI Service Cards / Model Cards are
    documented for all production GenAI models.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, MAS TRM 9.3]
    """
    findings = _empty_findings("AI Service Cards Documentation Check")
    try:
        sm = boto3.client("sagemaker", config=boto3_config)
        model_cards = _paginate(sm, "list_model_cards", "ModelCardSummaryList")

        if not model_cards:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-42",
                    finding_name="No SageMaker Model Cards Found",
                    finding_details=(
                        "No SageMaker Model Cards found. "
                        "Production AI models lack documented intended use, limitations, and bias evaluations."
                    ),
                    resolution=(
                        "1. Create SageMaker Model Cards for all production models.\n"
                        "2. Document: intended use, out-of-scope uses, training data, bias evaluations.\n"
                        "3. Include regulatory compliance attestations.\n"
                        "4. Review and update cards at each model version release."
                    ),
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-cards.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-42"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-42",
                    finding_name="SageMaker Model Cards Present",
                    finding_details=f"Found {len(model_cards)} model card(s).",
                    resolution="Verify cards are current and include bias/fairness evaluations.",
                    reference="https://docs.aws.amazon.com/sagemaker/latest/dg/model-cards.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-42"],
                )
            )
    except Exception as e:
        return _error_findings("AI Service Cards Documentation Check", e)
    return findings


# ===========================================================================
# CATEGORY 10: SENSITIVE INFORMATION DISCLOSURE (FS-43 to FS-46)
# COMPLIANCE_PLACEHOLDER: [NYDFS 500.06, FFIEC CAT, PCI-DSS 3.4, GDPR Art.25]
# ===========================================================================


def check_cloudwatch_log_pii_masking() -> Dict[str, Any]:
    """
    FS-43 — Check for CloudWatch Logs data protection policies that mask PII
    in Bedrock invocation logs.
    COMPLIANCE_PLACEHOLDER: [NYDFS 500.06, GDPR Art.25, PCI-DSS 3.4]
    """
    findings = _empty_findings("CloudWatch Log PII Masking Check")
    try:
        logs = boto3.client("logs", config=boto3_config)
        # List data protection policies
        try:
            policies = logs.describe_account_policies(
                policyType="DATA_PROTECTION_POLICY"
            ).get("accountPolicies", [])
        except ClientError:
            policies = []

        if not policies:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-43",
                    finding_name="No CloudWatch Logs Data Protection Policies",
                    finding_details=(
                        "No CloudWatch Logs data protection policies found. "
                        "PII (SSN, account numbers, credit card numbers) in Bedrock invocation logs "
                        "may be stored in plaintext."
                    ),
                    resolution=(
                        "1. Create CloudWatch Logs data protection policies to mask PII.\n"
                        "2. Enable masking for: SSN, credit card numbers, bank account numbers, email.\n"
                        "3. Apply policies to Bedrock invocation log groups.\n"
                        "4. Test masking with synthetic PII before production deployment."
                    ),
                    reference="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/mask-sensitive-log-data.html",
                    severity="High",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-43"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-43",
                    finding_name="CloudWatch Logs Data Protection Policies Present",
                    finding_details=f"Found {len(policies)} data protection policy(ies).",
                    resolution="Verify policies cover Bedrock invocation log groups.",
                    reference="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/mask-sensitive-log-data.html",
                    severity="High",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-43"],
                )
            )
    except Exception as e:
        return _error_findings("CloudWatch Log PII Masking Check", e)
    return findings


def check_macie_on_training_data_buckets() -> Dict[str, Any]:
    """
    FS-44 — Verify Amazon Macie is enabled and scanning S3 buckets that
    contain training data or KB data sources for PII.
    COMPLIANCE_PLACEHOLDER: [NYDFS 500.06, GDPR Art.25, PCI-DSS 3.4, FFIEC CAT]
    """
    findings = _empty_findings("Amazon Macie PII Scanning Check")
    try:
        macie = boto3.client("macie2", config=boto3_config)
        try:
            status = macie.get_macie_session()
            macie_enabled = status.get("status") == "ENABLED"
        except ClientError:
            macie_enabled = False

        if not macie_enabled:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-44",
                    finding_name="Amazon Macie Not Enabled",
                    finding_details=(
                        "Amazon Macie is not enabled. S3 buckets containing training data "
                        "and KB data sources are not being scanned for PII/sensitive data."
                    ),
                    resolution=(
                        "1. Enable Amazon Macie in all regions where AI/ML data is stored.\n"
                        "2. Create Macie classification jobs for training data and KB buckets.\n"
                        "3. Configure Macie findings to route to Security Hub and SNS.\n"
                        "4. Remediate PII findings before using data for model training."
                    ),
                    reference="https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html",
                    severity="High",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-44"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-44",
                    finding_name="Amazon Macie Enabled",
                    finding_details="Amazon Macie is enabled and scanning S3 buckets.",
                    resolution="Verify Macie jobs cover training data and KB data source buckets.",
                    reference="https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html",
                    severity="High",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-44"],
                )
            )
    except Exception as e:
        return _error_findings("Amazon Macie PII Scanning Check", e)
    return findings


def check_guardrail_pii_filters(inventory) -> Dict[str, Any]:
    """
    FS-45 — Verify Bedrock Guardrails have sensitive information (PII) filters
    configured to block PII in prompts and responses.
    COMPLIANCE_PLACEHOLDER: [NYDFS 500.06, GDPR Art.25, PCI-DSS 3.4]
    """
    findings = _empty_findings("Guardrail PII Filters Check")
    try:
        guardrail_inv = require(inventory, "guardrails")
        guardrails = guardrail_inv.summaries

        if not guardrails:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-45",
                    finding_name="No Guardrails — PII Filters Not Applicable",
                    finding_details="No Bedrock Guardrails configured.",
                    resolution="Configure guardrails with PII/sensitive information filters.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-sensitive-filters.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-45"],
                )
            )
            return findings

        guardrails_with_pii = []
        for g in guardrails:
            detail = guardrail_inv.detail_by_id[g["id"]]
            if isinstance(detail, _Unavailable):
                raise detail.error
            if detail.get("sensitiveInformationPolicy", {}).get("piiEntities"):
                guardrails_with_pii.append(g["name"])

        if not guardrails_with_pii:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-45",
                    finding_name="No Guardrails With PII Filters",
                    finding_details=(
                        f"Found {len(guardrails)} guardrail(s) but none have PII entity filters. "
                        "SSN, credit card numbers, and account numbers may appear in GenAI outputs."
                    ),
                    resolution=(
                        "Add PII entity filters to guardrails for:\n"
                        "- US_SOCIAL_SECURITY_NUMBER\n"
                        "- CREDIT_DEBIT_CARD_NUMBER\n"
                        "- BANK_ACCOUNT_NUMBER\n"
                        "- EMAIL, PHONE, NAME (as appropriate)\n"
                        "Set action to ANONYMIZE or BLOCK."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-sensitive-filters.html",
                    severity="High",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-45"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-45",
                    finding_name="Guardrail PII Filters Configured",
                    finding_details=f"Guardrails with PII filters: {', '.join(guardrails_with_pii)}.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-sensitive-filters.html",
                    severity="High",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-45"],
                )
            )
    except Exception as e:
        return _error_findings("Guardrail PII Filters Check", e)
    return findings


def check_data_classification_tagging(inventory) -> Dict[str, Any]:
    """
    FS-46 — Check that S3 buckets containing AI/ML data are tagged with
    data classification labels (e.g., Confidential, PII, Public).
    COMPLIANCE_PLACEHOLDER: [NYDFS 500.06, FFIEC CAT, ISO 27001 A.8.2]
    """
    findings = _empty_findings("Data Classification Tagging Check")
    try:
        buckets = require(inventory, "buckets")
        s3 = boto3.client("s3", config=boto3_config)

        aiml_buckets = [
            b
            for b in buckets
            if any(
                kw in b["Name"].lower()
                for kw in ["train", "model", "bedrock", "sagemaker", "kb", "knowledge"]
            )
        ]

        if not aiml_buckets:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-46",
                    finding_name="No AI/ML Data Buckets Identified",
                    finding_details="No S3 buckets with AI/ML naming found.",
                    resolution="Tag AI/ML data buckets with data-classification labels.",
                    reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-tagging.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-46"],
                )
            )
            return findings

        unclassified = []
        for bucket in aiml_buckets:
            try:
                tags = s3.get_bucket_tagging(Bucket=bucket["Name"]).get("TagSet", [])
                tag_keys = {t["Key"].lower() for t in tags}
                if (
                    "data-classification" not in tag_keys
                    and "classification" not in tag_keys
                ):
                    unclassified.append(bucket["Name"])
            except ClientError as e:
                # A genuine "no tags" response (NoSuchTagSet) means the bucket is
                # unclassified — a real finding. An access error means we could
                # not read the tags; re-raise so it surfaces as could-not-assess
                # rather than a false "unclassified" finding.
                if _is_access_error(e):
                    raise
                unclassified.append(bucket["Name"])

        if unclassified:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-46",
                    finding_name="AI/ML Buckets Without Data Classification Tags",
                    finding_details=(
                        f"{len(unclassified)} AI/ML bucket(s) without data-classification tags: "
                        f"{', '.join(unclassified[:10])}."
                    ),
                    resolution=(
                        "Tag all AI/ML data buckets with 'data-classification' key. "
                        "Values: Public, Internal, Confidential, Restricted. "
                        "Enforce via SCP or AWS Config rule."
                    ),
                    reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-tagging.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-46"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-46",
                    finding_name="AI/ML Buckets Have Classification Tags",
                    finding_details=f"All {len(aiml_buckets)} AI/ML bucket(s) have classification tags.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-tagging.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-46"],
                )
            )
    except Exception as e:
        return _error_findings("Data Classification Tagging Check", e)
    return findings


# ===========================================================================
# CATEGORY 11: HALLUCINATION (FS-47 to FS-50)
# CATEGORY 12: PROMPT INJECTION (FS-51 to FS-54)
# COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, MAS TRM 9.2, NYDFS 500]
# ===========================================================================


def check_guardrail_grounding_threshold(inventory) -> Dict[str, Any]:
    """
    FS-47 — Verify Bedrock Guardrails contextual grounding thresholds are
    set appropriately high for financial services use cases.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, MAS TRM 9.2]
    """
    findings = _empty_findings("Guardrail Grounding Threshold Check")
    try:
        guardrail_inv = require(inventory, "guardrails")
        guardrails = guardrail_inv.summaries

        if not guardrails:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-47",
                    finding_name="No Guardrails — Grounding Threshold Not Applicable",
                    finding_details="No Bedrock Guardrails configured.",
                    resolution="Configure guardrails with contextual grounding checks.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-grounding.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-47"],
                )
            )
            return findings

        low_threshold_guardrails = []
        guardrails_with_grounding = []
        for g in guardrails:
            detail = guardrail_inv.detail_by_id[g["id"]]
            if isinstance(detail, _Unavailable):
                raise detail.error
            grounding = detail.get("contextualGroundingPolicy", {})
            has_grounding_filter = False
            for filter_item in grounding.get("filters", []):
                if filter_item.get("type") == "GROUNDING":
                    has_grounding_filter = True
                    if filter_item.get("threshold", 1.0) < 0.7:
                        low_threshold_guardrails.append(
                            f"{g['name']} (threshold={filter_item['threshold']})"
                        )
            if has_grounding_filter:
                guardrails_with_grounding.append(g["name"])

        if low_threshold_guardrails:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-47",
                    finding_name="Guardrails With Low Grounding Thresholds",
                    finding_details=(
                        f"Guardrails with grounding threshold <0.7: {', '.join(low_threshold_guardrails)}. "
                        "Low thresholds allow hallucinated responses to pass through."
                    ),
                    resolution=(
                        "Set grounding threshold to 0.7 or higher for financial services use cases "
                        "(valid range is 0 to 0.99; 1.0 is invalid and blocks all content). "
                        "Test threshold impact on response quality before increasing. Note: contextual "
                        "grounding supports summarization, paraphrasing, and Q&A — not conversational "
                        "chatbot use cases; for chatbots use denied topics (FS-28/FS-59) instead."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-contextual-grounding-check.html",
                    severity="High",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-47"],
                )
            )
        elif not guardrails_with_grounding:
            # Guardrails exist but NONE has a GROUNDING filter at all. This is a
            # genuine gap (not a pass): without a grounding filter, ungrounded /
            # hallucinated responses are not detected. Previously this fell through
            # to the "Passed" branch because low_threshold_guardrails was empty.
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-47",
                    finding_name="No Guardrails With a Grounding Filter",
                    finding_details=(
                        f"Found {len(guardrails)} guardrail(s) but none have a GROUNDING contextual "
                        "grounding filter configured. Ungrounded or hallucinated responses are not "
                        "detected for summarization/paraphrasing/Q&A use cases."
                    ),
                    resolution=(
                        "Add a GROUNDING contextual grounding filter (threshold ≥0.7; valid range "
                        "0 to 0.99) to each guardrail used for summarization, paraphrasing, or Q&A. "
                        "Note: contextual grounding is not supported for conversational chatbot use "
                        "cases — use denied topics (FS-28/FS-59) for those."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-contextual-grounding-check.html",
                    severity="High",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-47"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-47",
                    finding_name="Guardrail Grounding Thresholds Appropriate",
                    finding_details=(
                        f"All {len(guardrails_with_grounding)} guardrail(s) with a GROUNDING filter "
                        "have thresholds ≥0.7."
                    ),
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-contextual-grounding-check.html",
                    severity="High",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-47"],
                )
            )
    except Exception as e:
        return _error_findings("Guardrail Grounding Threshold Check", e)
    return findings


def check_rag_knowledge_base_configured(inventory) -> Dict[str, Any]:
    """
    FS-48 — Verify RAG (Retrieval Augmented Generation) is used via Bedrock
    Knowledge Bases to ground responses in authoritative data.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT]
    """
    findings = _empty_findings("RAG Knowledge Base Configuration Check")
    try:
        kbs = require(inventory, "knowledge_bases").summaries

        active_kbs = [k for k in kbs if k.get("status") == "ACTIVE"]

        if not active_kbs:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-48",
                    finding_name="No Active Knowledge Bases for RAG",
                    finding_details=(
                        "No active Bedrock Knowledge Bases found. "
                        "GenAI responses are not grounded in authoritative data sources, "
                        "increasing hallucination risk."
                    ),
                    resolution=(
                        "1. Create Bedrock Knowledge Bases with authoritative financial data.\n"
                        "2. Use RetrieveAndGenerate API to ground responses.\n"
                        "3. Configure data sources with current regulatory and product information."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-48"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-48",
                    finding_name="Active Knowledge Bases for RAG Present",
                    finding_details=f"Found {len(active_kbs)} active Knowledge Base(s) for RAG grounding.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-48"],
                )
            )
    except Exception as e:
        return _error_findings("RAG Knowledge Base Configuration Check", e)
    return findings


def check_hallucination_disclaimer_advisory() -> Dict[str, Any]:
    """
    FS-49 — Advisory check: verify application adds hallucination disclaimers
    to GenAI outputs in financial contexts.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, MAS TRM 9.2]
    """
    findings = _empty_findings("Hallucination Disclaimer Advisory")
    findings["csv_data"].append(
        create_finding(
            check_id="FS-49",
            finding_name="ADVISORY: Hallucination Disclaimer — Manual Review Required",
            finding_details=(
                "Application-level hallucination disclaimers cannot be verified via AWS APIs. "
                "Manual review required."
            ),
            resolution=(
                "1. Add disclaimers to GenAI outputs: 'AI-generated content may contain errors. "
                "Verify with authoritative sources before acting.'\n"
                "2. Implement post-processing to append disclaimers.\n"
                "3. Test disclaimer presence in QA before production."
            ),
            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html",
            severity="Informational",
            status="N/A",
            compliance_frameworks=COMPLIANCE_MAP["FS-49"],
        )
    )
    return findings


def check_guardrail_relevance_grounding(inventory) -> Dict[str, Any]:
    """
    FS-50 — Check for Bedrock Guardrails contextual grounding RELEVANCE filters
    configured to detect and block responses that are not grounded in the context
    retrieved by the RAG pipeline (hallucination prevention).

    NOTE: This check verifies the *RELEVANCE* filter within contextual grounding
    (a different feature from GROUNDING-type filters). RELEVANCE filters block
    responses that are off-topic relative to the user query. GROUNDING filters
    block responses not supported by the source context. Both are important for
    FinServ hallucination mitigation. For formal policy-based verification of
    factual claims, see check_automated_reasoning_policies() (FS-27b).

    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT]
    """
    findings = _empty_findings("Guardrail Relevance Grounding Check")
    try:
        guardrail_inv = require(inventory, "guardrails")
        guardrails = guardrail_inv.summaries

        guardrails_with_relevance = []
        for g in guardrails:
            detail = guardrail_inv.detail_by_id[g["id"]]
            if isinstance(detail, _Unavailable):
                raise detail.error
            grounding = detail.get("contextualGroundingPolicy", {})
            for f in grounding.get("filters", []):
                if f.get("type") == "RELEVANCE":
                    guardrails_with_relevance.append(g["name"])

        if not guardrails_with_relevance:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-50",
                    finding_name="No Guardrails With Relevance Grounding Filters",
                    finding_details=(
                        "No guardrails have RELEVANCE contextual grounding filters. "
                        "Without relevance filters, responses that are off-topic or unrelated "
                        "to the user query will not be blocked, increasing hallucination risk "
                        "in RAG-based FinServ applications."
                    ),
                    resolution=(
                        "Enable the RELEVANCE contextual grounding filter in Bedrock Guardrails "
                        "with a threshold of ≥0.7 to block responses that are not relevant to "
                        "the user query. Also enable the GROUNDING filter (≥0.7) to block "
                        "responses not supported by the retrieved source context."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-grounding.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-50"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-50",
                    finding_name="Relevance Grounding Filters Present",
                    finding_details=(
                        f"Guardrails with RELEVANCE grounding filters: "
                        f"{', '.join(guardrails_with_relevance)}."
                    ),
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-grounding.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-50"],
                )
            )
    except Exception as e:
        return _error_findings("Guardrail Relevance Grounding Check", e)
    return findings


def check_prompt_injection_input_validation(inventory) -> Dict[str, Any]:
    """
    FS-51 — Check for Bedrock Guardrails prompt attack filters to detect
    and block prompt injection attempts.
    COMPLIANCE_PLACEHOLDER: [NYDFS 500.06, FFIEC CAT, OWASP LLM01]
    """
    findings = _empty_findings("Prompt Injection Input Validation Check")
    try:
        guardrail_inv = require(inventory, "guardrails")
        guardrails = guardrail_inv.summaries

        if not guardrails:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-51",
                    finding_name="No Guardrails — Prompt Attack Filters Not Applicable",
                    finding_details="No Bedrock Guardrails configured.",
                    resolution="Configure guardrails with prompt attack filters.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-51"],
                )
            )
            return findings

        guardrails_with_prompt_attack = []
        guardrails_classic_tier_pa = []
        for g in guardrails:
            detail = guardrail_inv.detail_by_id[g["id"]]
            if isinstance(detail, _Unavailable):
                raise detail.error
            content_policy = detail.get("contentPolicy", {})
            for f in content_policy.get("filters", []):
                if f.get("type") == "PROMPT_ATTACK":
                    guardrails_with_prompt_attack.append(g["name"])
                    # STANDARD tier (GA June 2025) improves PROMPT_ATTACK detection
                    # by distinguishing jailbreaks from prompt injection attacks.
                    tier = content_policy.get("tier", {}).get("tierName", "CLASSIC")
                    if tier == "CLASSIC":
                        guardrails_classic_tier_pa.append(g["name"])
                    break

        if not guardrails_with_prompt_attack:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-51",
                    finding_name="No Guardrails With Prompt Attack Filters",
                    finding_details=(
                        f"Found {len(guardrails)} guardrail(s) but none have PROMPT_ATTACK filters. "
                        "Prompt injection attacks may bypass system prompts and access controls."
                    ),
                    resolution=(
                        "1. Enable PROMPT_ATTACK content filter in Bedrock Guardrails.\n"
                        "2. Set input filter strength to HIGH.\n"
                        "3. Use input tags (<amazon-bedrock-guardrails-guardContent_xyz>) to "
                        "differentiate user inputs from developer-provided prompts — required for "
                        "PROMPT_ATTACK filters to work correctly with InvokeModel/InvokeModelWithResponseStream.\n"
                        "4. Consider STANDARD tier (GA June 2025) for better jailbreak vs. injection "
                        "classification and broader language support.\n"
                        "5. Implement application-level input sanitization as defense-in-depth."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-prompt-attack.html",
                    severity="High",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-51"],
                )
            )
        elif guardrails_classic_tier_pa:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-51",
                    finding_name="Prompt Attack Filters on CLASSIC Tier",
                    finding_details=(
                        f"Guardrails with PROMPT_ATTACK filters: {', '.join(guardrails_with_prompt_attack)}. "
                        f"Using CLASSIC tier: {', '.join(guardrails_classic_tier_pa)}. "
                        "STANDARD tier (GA June 2025) better distinguishes jailbreaks from "
                        "prompt injection and provides broader language support."
                    ),
                    resolution=(
                        "Consider upgrading to STANDARD tier for improved PROMPT_ATTACK detection. "
                        "Ensure input tags are used to scope user content for PROMPT_ATTACK evaluation. "
                        "STANDARD tier requires cross-region inference on the guardrail."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-prompt-attack.html",
                    severity="High",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-51"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-51",
                    finding_name="Prompt Attack Filters Configured (STANDARD Tier)",
                    finding_details=(
                        f"Guardrails with PROMPT_ATTACK filters (STANDARD tier): "
                        f"{', '.join(guardrails_with_prompt_attack)}."
                    ),
                    resolution=(
                        "Ensure input tags are used to scope user content when calling "
                        "InvokeModel/InvokeModelWithResponseStream — required for PROMPT_ATTACK "
                        "filters to evaluate user input separately from system prompts."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-prompt-attack.html",
                    severity="High",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-51"],
                )
            )
    except Exception as e:
        return _error_findings("Prompt Injection Input Validation Check", e)
    return findings


def check_bedrock_sdk_version_currency(inventory) -> Dict[str, Any]:
    """
    FS-52 — Advisory check: verify Bedrock SDK versions in Lambda functions
    are current (outdated SDKs may lack prompt injection mitigations).
    COMPLIANCE_PLACEHOLDER: [NYDFS 500.06, FFIEC CAT, ISO 27001 A.12.6]
    """
    findings = _empty_findings("Bedrock SDK Version Currency Check")
    try:
        functions = require(inventory, "lambda_functions")

        bedrock_functions = [
            f
            for f in functions
            if any(
                kw in f["FunctionName"].lower()
                for kw in ["bedrock", "agent", "aiml", "genai"]
            )
        ]

        if not bedrock_functions:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-52",
                    finding_name="No Bedrock-Related Lambda Functions Found",
                    finding_details="No Lambda functions with Bedrock-related naming found.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/lambda/latest/dg/runtimes-update.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-52"],
                )
            )
            return findings

        # Check for deprecated runtimes using the definitive allowlist of currently-
        # supported Lambda managed runtimes (sourced from
        # https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html,
        # retrieved June 2026). Any runtime NOT in this set is considered deprecated
        # or end-of-support. This allowlist approach is more reliable than maintaining
        # a denylist (which silently misses newly-deprecated runtimes).
        #
        # Supported as of June 2026 (ordered newest-first per language):
        SUPPORTED_RUNTIMES = {
            # Python
            "python3.14",
            "python3.13",
            "python3.12",
            "python3.11",
            "python3.10",
            # Node.js
            "nodejs24.x",
            "nodejs22.x",
            # Java
            "java25",
            "java21",
            "java17",
            "java11",
            "java8.al2",
            # .NET
            "dotnet10",
            "dotnet9",
            "dotnet8",
            # Ruby
            "ruby4.0",
            "ruby3.4",
            "ruby3.3",
            # OS-only / custom runtimes
            "provided.al2023",
            "provided.al2",
        }
        outdated_functions = [
            f["FunctionName"]
            for f in bedrock_functions
            if f.get("Runtime", "") and f["Runtime"] not in SUPPORTED_RUNTIMES
        ]

        if outdated_functions:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-52",
                    finding_name="Bedrock Lambda Functions on Deprecated Runtimes",
                    finding_details=(
                        f"Functions on deprecated runtimes: {', '.join(outdated_functions[:10])}. "
                        "Deprecated runtimes may use outdated boto3/SDK versions lacking security patches."
                    ),
                    resolution=(
                        "1. Upgrade Lambda functions to a supported runtime — Python 3.12+, "
                        "Node.js 22.x or 24.x, Java 21+, or .NET 8+.\n"
                        "2. Update boto3 to the latest version in Lambda layers (pin the version "
                        "in requirements.txt and redeploy).\n"
                        "3. Enable Lambda runtime management controls for automatic minor-version "
                        "updates (runtimeManagementConfig.updateRuntimeOn = 'Auto').\n"
                        "4. Refer to https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html "
                        "for the authoritative list of supported and deprecated runtimes."
                    ),
                    reference="https://docs.aws.amazon.com/lambda/latest/dg/runtimes-update.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-52"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-52",
                    finding_name="Bedrock Lambda Functions on Current Runtimes",
                    finding_details=f"All {len(bedrock_functions)} Bedrock Lambda function(s) use current runtimes.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/lambda/latest/dg/runtimes-update.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-52"],
                )
            )
    except Exception as e:
        return _error_findings("Bedrock SDK Version Currency Check", e)
    return findings


def check_waf_sql_injection_rules(inventory) -> Dict[str, Any]:
    """
    FS-53 — Verify WAF Web ACLs include SQL injection and XSS managed rules
    to protect GenAI API endpoints from injection attacks.
    COMPLIANCE_PLACEHOLDER: [NYDFS 500.06, FFIEC CAT, PCI-DSS 6.4.1, OWASP LLM01]
    """
    findings = _empty_findings("WAF Injection Protection Rules Check")
    try:
        # require() raises if inventory is None or web_acls is _Unavailable,
        # propagating to the outer except which yields COULD_NOT_ASSESS.
        web_acl_inv = require(inventory, "web_acls")
        acls = web_acl_inv.summaries

        if not acls:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-53",
                    finding_name="No WAF Web ACLs — Injection Rules Not Applicable",
                    finding_details="No regional WAF Web ACLs found.",
                    resolution="Create WAF Web ACLs with injection protection rules (see FS-01).",
                    reference="https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-53"],
                )
            )
            return findings

        INJECTION_RULE_GROUPS = {
            "AWSManagedRulesSQLiRuleSet",
            "AWSManagedRulesCommonRuleSet",
            "AWSManagedRulesKnownBadInputsRuleSet",
        }

        acls_without_injection_rules = []
        for acl_summary in acls:
            # detail_by_id holds get_web_acl(...)['WebACL'] or _Unavailable.
            # Accessing an _Unavailable entry re-raises its stored error, which
            # propagates to the outer except and yields COULD_NOT_ASSESS —
            # matching today's behaviour (no per-item try/except in this check).
            detail = web_acl_inv.detail_by_id[acl_summary["Id"]]
            if isinstance(detail, _Unavailable):
                raise detail.error
            acl = detail
            rule_names = {
                r.get("Statement", {})
                .get("ManagedRuleGroupStatement", {})
                .get("Name", "")
                for r in acl.get("Rules", [])
            }
            if not rule_names.intersection(INJECTION_RULE_GROUPS):
                acls_without_injection_rules.append(acl_summary["Name"])

        if acls_without_injection_rules:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-53",
                    finding_name="WAF ACLs Missing Injection Protection Rules",
                    finding_details=(
                        f"WAF ACLs without SQL injection/XSS rules: "
                        f"{', '.join(acls_without_injection_rules[:10])}."
                    ),
                    resolution=(
                        "Add AWS Managed Rule Groups to WAF ACLs:\n"
                        "- AWSManagedRulesSQLiRuleSet (SQL injection)\n"
                        "- AWSManagedRulesCommonRuleSet (XSS, LFI, RFI)\n"
                        "- AWSManagedRulesKnownBadInputsRuleSet (prompt injection patterns)"
                    ),
                    reference="https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html",
                    severity="High",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-53"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-53",
                    finding_name="WAF Injection Protection Rules Present",
                    finding_details=f"All {len(acls)} WAF ACL(s) have injection protection rules.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html",
                    severity="High",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-53"],
                )
            )
    except Exception as e:
        return _error_findings("WAF Injection Protection Rules Check", e)
    return findings


def check_penetration_testing_evidence() -> Dict[str, Any]:
    """
    FS-54 — Advisory check: verify penetration testing has been conducted
    on GenAI applications (prompt injection, jailbreak testing).
    COMPLIANCE_PLACEHOLDER: [NYDFS 500.06, FFIEC CAT, PCI-DSS 11.4, DORA Art.26]
    """
    findings = _empty_findings("Penetration Testing Evidence Check")
    findings["csv_data"].append(
        create_finding(
            check_id="FS-54",
            finding_name="ADVISORY: Penetration Testing — Manual Review Required",
            finding_details=(
                "Penetration testing evidence cannot be verified via AWS APIs. "
                "Manual review required to confirm GenAI applications have been tested."
            ),
            resolution=(
                "1. Conduct penetration testing of GenAI applications at least annually and "
                "before major releases.\n"
                "2. Include AI-specific test cases: prompt injection, jailbreak, indirect "
                "(cross-domain) injection, system-prompt leakage, and data-extraction attempts.\n"
                "3. Consider AWS Security Agent for on-demand, AI-driven penetration testing "
                "(GA March 2026; available in US East N. Virginia, US West Oregon, Europe Ireland, "
                "Europe Frankfurt, Asia Pacific Sydney, Asia Pacific Tokyo, with cross-account "
                "shared-VPC testing via AWS RAM). Open-source tools such as Garak or PyRIT and "
                "manual red-teaming are complementary options. Verify current regional availability "
                "on the AWS Security Agent page before relying on it.\n"
                "4. Document findings and remediation for regulatory examination, and tag tested "
                "resources with a last-pentest-date for audit trail.\n"
                "5. For DORA compliance, include GenAI in TLPT (Threat-Led Penetration Testing) scope."
            ),
            reference="https://aws.amazon.com/security/penetration-testing/",
            severity="Informational",
            status="N/A",
            compliance_frameworks=COMPLIANCE_MAP["FS-54"],
        )
    )
    return findings


# ===========================================================================
# CATEGORY 13: IMPROPER OUTPUT HANDLING (FS-55 to FS-58)
# CATEGORY 14: OFF-TOPIC & INAPPROPRIATE OUTPUT (FS-59 to FS-60)
# CATEGORY 15: OUT-OF-DATE TRAINING DATA (FS-61 to FS-63)
# COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, NYDFS 500, OWASP LLM02]
# ===========================================================================


def check_output_validation_lambda(inventory) -> Dict[str, Any]:
    """
    FS-55 — Check for Lambda functions implementing output validation/sanitization
    in GenAI application pipelines.
    COMPLIANCE_PLACEHOLDER: [NYDFS 500.06, FFIEC CAT, OWASP LLM02]
    """
    findings = _empty_findings("Output Validation Lambda Check")
    try:
        functions = require(inventory, "lambda_functions")

        validation_functions = [
            f
            for f in functions
            if any(
                kw in f["FunctionName"].lower()
                for kw in ["validate", "sanitize", "filter", "output"]
            )
        ]

        if not validation_functions:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-55",
                    finding_name="No Output Validation Functions Found",
                    finding_details=(
                        "No Lambda functions with output validation/sanitization naming found. "
                        "GenAI outputs may be passed directly to downstream systems without validation."
                    ),
                    resolution=(
                        "1. Implement output validation Lambda functions in GenAI pipelines.\n"
                        "2. Validate output schema, length, and content before downstream use.\n"
                        "3. Sanitize outputs before rendering in web UIs (XSS prevention).\n"
                        "4. Encode outputs appropriately for the target context (HTML, SQL, JSON)."
                    ),
                    reference="https://genai.owasp.org/llm-top-10/",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-55"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-55",
                    finding_name="Output Validation Functions Present",
                    finding_details=f"Found {len(validation_functions)} output validation/sanitization function(s).",
                    resolution="No action required.",
                    reference="https://genai.owasp.org/llm-top-10/",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-55"],
                )
            )
    except Exception as e:
        return _error_findings("Output Validation Lambda Check", e)
    return findings


def check_xss_prevention_waf(inventory) -> Dict[str, Any]:
    """
    FS-56 — Verify WAF rules include XSS prevention for GenAI web application outputs.
    COMPLIANCE_PLACEHOLDER: [NYDFS 500.06, FFIEC CAT, PCI-DSS 6.4.1, OWASP LLM02]
    """
    findings = _empty_findings("XSS Prevention WAF Check")
    try:
        # require() raises if inventory is None or web_acls is _Unavailable.
        web_acl_inv = require(inventory, "web_acls")
        acls = web_acl_inv.summaries

        if not acls:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-56",
                    finding_name="No WAF ACLs — XSS Prevention Not Applicable",
                    finding_details="No regional WAF Web ACLs found.",
                    resolution="Create WAF ACLs with XSS prevention rules.",
                    reference="https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-56"],
                )
            )
            return findings

        # XSS protections live in the AWS managed Common Rule Set. Inspect each ACL's
        # managed-rule-group statements (mirrors FS-53) to actually verify coverage
        # rather than emitting an unconditional "review required" pass.
        acls_without_xss = []
        for acl_summary in acls:
            # detail_by_id holds get_web_acl(...)['WebACL'] or _Unavailable.
            # An _Unavailable entry re-raises its error → outer except → COULD_NOT_ASSESS.
            detail = web_acl_inv.detail_by_id[acl_summary["Id"]]
            if isinstance(detail, _Unavailable):
                raise detail.error
            acl = detail
            rule_groups = {
                r.get("Statement", {})
                .get("ManagedRuleGroupStatement", {})
                .get("Name", "")
                for r in acl.get("Rules", [])
            }
            if "AWSManagedRulesCommonRuleSet" not in rule_groups:
                acls_without_xss.append(acl_summary["Name"])

        if acls_without_xss:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-56",
                    finding_name="WAF ACLs Missing Common Rule Set (XSS)",
                    finding_details=(
                        "The following WAF ACL(s) do not include AWSManagedRulesCommonRuleSet, "
                        "which provides cross-site-scripting (XSS) protections for GenAI web "
                        "application outputs:\n"
                        + "\n".join(f"- {a}" for a in acls_without_xss[:10])
                    ),
                    resolution=(
                        "1. Add AWSManagedRulesCommonRuleSet to each WAF ACL protecting GenAI "
                        "web applications (it includes the CrossSiteScripting rules).\n"
                        "2. Additionally, implement Content Security Policy (CSP) response headers."
                    ),
                    reference="https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-56"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-56",
                    finding_name="XSS Prevention Common Rule Set Present",
                    finding_details=(
                        f"All {len(acls)} WAF ACL(s) include AWSManagedRulesCommonRuleSet "
                        "(XSS protections)."
                    ),
                    resolution=(
                        "No action required. Consider also implementing Content Security Policy "
                        "(CSP) response headers as defense in depth."
                    ),
                    reference="https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-56"],
                )
            )
    except Exception as e:
        return _error_findings("XSS Prevention WAF Check", e)
    return findings


def check_output_encoding_advisory() -> Dict[str, Any]:
    """
    FS-57 — Advisory check: verify application encodes GenAI outputs
    appropriately for the rendering context.
    COMPLIANCE_PLACEHOLDER: [NYDFS 500.06, FFIEC CAT, OWASP LLM02]
    """
    findings = _empty_findings("Output Encoding Advisory")
    findings["csv_data"].append(
        create_finding(
            check_id="FS-57",
            finding_name="ADVISORY: Output Encoding — Manual Review Required",
            finding_details=(
                "Output encoding practices cannot be verified via AWS APIs. "
                "Manual code review required."
            ),
            resolution=(
                "1. HTML-encode GenAI outputs before rendering in web UIs.\n"
                "2. Use parameterized queries when GenAI output is used in database operations.\n"
                "3. JSON-encode outputs before embedding in JavaScript contexts.\n"
                "4. Validate output length and format before passing to downstream APIs."
            ),
            reference="https://genai.owasp.org/llm-top-10/",
            severity="Informational",
            status="N/A",
            compliance_frameworks=COMPLIANCE_MAP["FS-57"],
        )
    )
    return findings


def check_output_schema_validation(inventory) -> Dict[str, Any]:
    """
    FS-58 — Check for structured output validation using Bedrock response
    schemas or application-level JSON schema validation.
    COMPLIANCE_PLACEHOLDER: [NYDFS 500.06, FFIEC CAT, OWASP LLM02]
    """
    findings = _empty_findings("Output Schema Validation Check")
    try:
        # Check for EventBridge Pipes or Lambda destinations that could validate outputs
        functions = require(inventory, "lambda_functions")

        schema_functions = [
            f
            for f in functions
            if any(
                kw in f["FunctionName"].lower()
                for kw in ["schema", "validate", "parse", "format"]
            )
        ]

        findings["csv_data"].append(
            create_finding(
                check_id="FS-58",
                finding_name="ADVISORY: Output Schema Validation — Manual Review Required",
                finding_details=(
                    f"Found {len(schema_functions)} Lambda function(s) whose names suggest "
                    "schema/validation handling. Structured-output / JSON-schema validation of "
                    "GenAI responses is an application-layer control that cannot be verified "
                    "automatically — manual review required."
                ),
                resolution=(
                    "1. Use Bedrock structured output (response schemas) where supported.\n"
                    "2. Implement JSON schema validation on Lambda output processors.\n"
                    "3. Reject malformed outputs and return safe error responses.\n"
                    "4. Log schema validation failures to CloudWatch for monitoring."
                ),
                reference="https://docs.aws.amazon.com/bedrock/latest/userguide/inference-parameters.html",
                severity="Informational",
                status="N/A",
                compliance_frameworks=COMPLIANCE_MAP["FS-58"],
            )
        )
    except Exception as e:
        return _error_findings("Output Schema Validation Check", e)
    return findings


def check_guardrail_topic_allowlist(inventory) -> Dict[str, Any]:
    """
    FS-59 — Verify Bedrock Guardrails topic policies restrict GenAI to
    on-topic financial services responses only.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, MAS TRM 9.2]
    """
    findings = _empty_findings("Guardrail Topic Allowlist Check")
    try:
        guardrail_inv = require(inventory, "guardrails")
        guardrails = guardrail_inv.summaries

        if not guardrails:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-59",
                    finding_name="No Guardrails — Topic Allowlist Not Applicable",
                    finding_details="No Bedrock Guardrails configured.",
                    resolution="Configure guardrails with topic policies to restrict off-topic responses.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-59"],
                )
            )
            return findings

        guardrails_with_topics = []
        topics_classic_tier = []
        for g in guardrails:
            detail = guardrail_inv.detail_by_id[g["id"]]
            if isinstance(detail, _Unavailable):
                raise detail.error
            topic_policy = detail.get("topicPolicy", {})
            if topic_policy.get("topics"):
                guardrails_with_topics.append(g["name"])
                tier = topic_policy.get("tier", {}).get("tierName", "CLASSIC")
                if tier == "CLASSIC":
                    topics_classic_tier.append(g["name"])

        if not guardrails_with_topics:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-59",
                    finding_name="No Guardrails With Topic Restrictions",
                    finding_details=(
                        f"Found {len(guardrails)} guardrail(s) but none have topic policies. "
                        "GenAI may respond to off-topic requests (e.g., medical advice, legal advice)."
                    ),
                    resolution=(
                        "Add denied topics to guardrails for off-topic categories:\n"
                        "- Medical/health advice\n"
                        "- Legal advice\n"
                        "- Political opinions\n"
                        "- Non-financial product recommendations\n"
                        "Consider the STANDARD tier (GA June 2025) for broader language support; "
                        "it requires cross-region inference on the guardrail."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-59"],
                )
            )
        elif topics_classic_tier:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-59",
                    finding_name="Topic Restrictions Configured on CLASSIC Tier",
                    finding_details=(
                        f"Guardrails with topic policies: {', '.join(guardrails_with_topics)}. "
                        f"The following use the CLASSIC tier: {', '.join(topics_classic_tier)}. "
                        "CLASSIC tier supports English, French, and Spanish only; the STANDARD tier "
                        "(GA June 2025) adds broader language support for off-topic detection."
                    ),
                    resolution=(
                        "For multilingual FinServ deployments, consider upgrading denied topics to "
                        "the STANDARD tier (topicsTierConfig.tierName=STANDARD via UpdateGuardrail; "
                        "requires a cross-region inference profile)."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-59"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-59",
                    finding_name="Guardrail Topic Restrictions Configured",
                    finding_details=f"Guardrails with topic policies: {', '.join(guardrails_with_topics)}.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-59"],
                )
            )
    except Exception as e:
        return _error_findings("Guardrail Topic Allowlist Check", e)
    return findings


def check_contextual_grounding_for_offtopic() -> Dict[str, Any]:
    """
    FS-60 — Verify contextual grounding is used to keep GenAI responses
    within the scope of the provided context/system prompt.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT]
    """
    # This overlaps with FS-47/FS-48 but focuses on off-topic prevention
    findings = _empty_findings("Contextual Grounding for Off-Topic Prevention")
    findings["csv_data"].append(
        create_finding(
            check_id="FS-60",
            finding_name="ADVISORY: Contextual Grounding for Off-Topic Prevention",
            finding_details=(
                "Contextual grounding for off-topic prevention is covered by guardrail "
                "grounding checks (FS-47) and RAG configuration (FS-48). "
                "Additionally verify system prompts explicitly scope the assistant's role."
            ),
            resolution=(
                "1. Include explicit scope instructions in system prompts.\n"
                "2. Use Bedrock Guardrails relevance grounding filter.\n"
                "3. Test with off-topic prompts in QA to verify rejection behavior."
            ),
            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-grounding.html",
            severity="Informational",
            status="N/A",
            compliance_frameworks=COMPLIANCE_MAP["FS-60"],
        )
    )
    return findings


def check_knowledge_base_sync_schedule(inventory) -> Dict[str, Any]:
    """
    FS-61 — Verify Bedrock Knowledge Base data sources have automated sync
    schedules to keep training/retrieval data current.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT]
    """
    # Reuses logic from FS-31 but focuses on scheduled automation
    findings = _empty_findings("Knowledge Base Sync Schedule Check")
    try:
        kbs = require(inventory, "knowledge_bases").summaries
        events = boto3.client("events", config=boto3_config)
        scheduler = boto3.client("scheduler", config=boto3_config)

        if not kbs:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-61",
                    finding_name="No Knowledge Bases Found",
                    finding_details="No Bedrock Knowledge Bases found.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base-ingest.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-61"],
                )
            )
            return findings

        # Check for EventBridge rules (legacy) that trigger KB sync.
        rules = _paginate(events, "list_rules", "Rules")
        kb_sync_rules = [
            r
            for r in rules
            if "bedrock" in r.get("Name", "").lower()
            or "knowledge" in r.get("Name", "").lower()
        ]

        # Check for EventBridge Scheduler schedules (the AWS-recommended approach;
        # classic EventBridge scheduled rules are a legacy feature). The
        # ListSchedules name-prefix filter is server-side, so do a broad list and
        # match on name/target heuristics here. ListSchedules is paginated via
        # NextToken. Treat an access error as a soft signal (do not fail the whole
        # check) since Scheduler may not be in use.
        kb_sync_schedules = []
        scheduler_access_error = None
        try:
            schedules = _paginate(scheduler, "list_schedules", "Schedules")
            kb_sync_schedules = [
                s
                for s in schedules
                if "bedrock" in s.get("Name", "").lower()
                or "knowledge" in s.get("Name", "").lower()
                or "kb-sync" in s.get("Name", "").lower()
                or "ingestion" in s.get("Name", "").lower()
                or "bedrock" in s.get("Target", {}).get("Arn", "").lower()
            ]
        except ClientError as e:
            if not _is_access_error(e):
                raise
            # Remember the access error. If we ALSO find no EventBridge-rule
            # automation, we cannot conclude the control is absent (a Scheduler
            # schedule we were not allowed to read might exist) — so we surface
            # COULD_NOT_ASSESS rather than a false Failed. If a rule IS found, the
            # positive evidence stands and the access gap is immaterial.
            scheduler_access_error = e
            logger.warning(
                "Could not list EventBridge Scheduler schedules (access denied); "
                "grant scheduler:ListSchedules for full FS-61 coverage."
            )

        total_sync_automation = len(kb_sync_rules) + len(kb_sync_schedules)

        # No positive evidence AND we were blocked from reading Scheduler →
        # unknown state, not a confirmed failure. Re-raise so the handler emits a
        # COULD NOT ASSESS row (Status="N/A", Severity="Low").
        if total_sync_automation == 0 and scheduler_access_error is not None:
            raise scheduler_access_error

        if total_sync_automation == 0:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-61",
                    finding_name="No Automated KB Sync Schedules Detected",
                    finding_details=(
                        f"Found {len(kbs)} Knowledge Base(s) but no EventBridge Scheduler "
                        "schedules or EventBridge rules with 'bedrock'/'knowledge' naming were "
                        "found. Note: this check uses a name/target heuristic — sync automation "
                        "with other naming conventions, AWS Step Functions-based orchestration, "
                        "or native Bedrock API-triggered syncs (StartIngestionJob called directly) "
                        "will not be detected. Verify sync automation manually if applicable."
                    ),
                    resolution=(
                        "1. Use EventBridge Scheduler (the AWS-recommended approach) to create a "
                        "recurring schedule (e.g., rate(1 day) or a cron expression) that triggers a "
                        "Lambda function calling the Bedrock StartIngestionJob API for each data source. "
                        "Classic EventBridge scheduled rules also work but are a legacy feature.\n"
                        "2. As of December 2024, Bedrock Knowledge Bases supports custom connectors "
                        "and streaming data ingestion — use direct document ingestion "
                        "(KnowledgeBaseDocuments API) for real-time updates without a full S3 sync.\n"
                        "3. Set sync frequency based on data currency requirements "
                        "(e.g., hourly for market data, daily for regulatory guidance).\n"
                        "4. Configure CloudWatch alarms or SNS notifications on "
                        "IngestionJob FAILED status for sync failure alerting."
                    ),
                    reference="https://docs.aws.amazon.com/scheduler/latest/UserGuide/what-is-scheduler.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-61"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-61",
                    finding_name="Automated KB Sync Schedules Present",
                    finding_details=(
                        f"Found {len(kb_sync_schedules)} EventBridge Scheduler schedule(s) and "
                        f"{len(kb_sync_rules)} EventBridge rule(s) with KB-sync naming. "
                        "Verify each targets the Bedrock StartIngestionJob API for your KB data sources."
                    ),
                    resolution="Verify the schedule frequency matches your data-currency requirements.",
                    reference="https://docs.aws.amazon.com/scheduler/latest/UserGuide/what-is-scheduler.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-61"],
                )
            )
    except Exception as e:
        return _error_findings("Knowledge Base Sync Schedule Check", e)
    return findings


def check_data_currency_disclaimer_advisory() -> Dict[str, Any]:
    """
    FS-62 — Advisory check: verify application adds data currency disclaimers
    to GenAI outputs (e.g., 'Information current as of [date]').
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, MAS TRM 9.2]
    """
    findings = _empty_findings("Data Currency Disclaimer Advisory")
    findings["csv_data"].append(
        create_finding(
            check_id="FS-62",
            finding_name="ADVISORY: Data Currency Disclaimer — Manual Review Required",
            finding_details=(
                "Data currency disclaimers cannot be verified via AWS APIs. "
                "Manual review required."
            ),
            resolution=(
                "1. Add data currency disclaimers to GenAI outputs: "
                "'Information based on data current as of [KB last sync date].'\n"
                "2. Expose KB last sync timestamp in application responses.\n"
                "3. Alert users when KB data is older than defined threshold."
            ),
            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base-ingest.html",
            severity="Informational",
            status="N/A",
            compliance_frameworks=COMPLIANCE_MAP["FS-62"],
        )
    )
    return findings


def check_foundation_model_lifecycle_policy() -> Dict[str, Any]:
    """
    FS-63 — Check for a documented process to update foundation models when
    new versions with more recent training data are released.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, FFIEC CAT, ISO 27001 A.12.5]
    """
    findings = _empty_findings("Foundation Model Lifecycle Policy Check")
    try:
        bedrock = boto3.client("bedrock", config=boto3_config)
        # Do not filter by output modality: legacy/deprecated models exist across
        # TEXT, EMBEDDING, and IMAGE modalities. Embedding models are widely used
        # in FinServ RAG pipelines; a legacy embedding model silently serves stale
        # vector representations. Fetch all modalities to surface any deprecated model.
        models = bedrock.list_foundation_models().get("modelSummaries", [])

        legacy_models = [
            m["modelId"]
            for m in models
            if m.get("modelLifecycle", {}).get("status") == "LEGACY"
        ]

        # Check for Config rules or SSM documents related to model lifecycle
        config_client = boto3.client("config", config=boto3_config)
        rules = _paginate(config_client, "describe_config_rules", "ConfigRules")
        lifecycle_rules = [
            r
            for r in rules
            if "lifecycle" in r.get("ConfigRuleName", "").lower()
            or "model" in r.get("ConfigRuleName", "").lower()
        ]

        if legacy_models and not lifecycle_rules:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-63",
                    finding_name="Legacy Models Without Lifecycle Management",
                    finding_details=(
                        f"Legacy foundation models available: {', '.join(legacy_models[:5])}. "
                        "No Config rules found for model lifecycle management."
                    ),
                    resolution=(
                        "1. Create a model lifecycle management process.\n"
                        "2. Subscribe to AWS Bedrock model deprecation notifications.\n"
                        "3. Test and migrate to new model versions before deprecation dates.\n"
                        "4. Document training data cutoff dates in model inventory."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-lifecycle.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-63"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-63",
                    finding_name="Foundation Model Lifecycle Management",
                    finding_details=(
                        f"No legacy models detected. "
                        f"{len(lifecycle_rules)} lifecycle-related Config rule(s) found."
                    ),
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/model-lifecycle.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-63"],
                )
            )
    except Exception as e:
        return _error_findings("Foundation Model Lifecycle Policy Check", e)
    return findings


# ===========================================================================
# MATERIAL GAP CHECKS (FS-65 to FS-69)
# Mitigations explicitly in the AWS FinServ Guide not covered by FS-01..63
# or the existing BR/SM/AC checks.
# NOTE: FS-64 (Guardrail Trace Logging) is merged into upstream BR-04.
# See extension note in SECURITY_CHECKS_FINSERV_PART3_APP_LAYER_AND_GAPS.md.
# ===========================================================================


def check_kb_datasource_s3_event_notifications(inventory) -> Dict[str, Any]:
    """
    FS-65 — Check that S3 event notifications (EventBridge or SNS/SQS) are
    configured on Knowledge Base data-source buckets to detect unauthorized
    document changes in real time.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, ISO 27001 A.12, FFIEC CAT]
    """
    findings = _empty_findings("KB Data Source S3 Event Notifications Check")
    try:
        kb_inv = require(inventory, "knowledge_bases")
        kbs = kb_inv.summaries
        s3_client = boto3.client("s3", config=boto3_config)

        if not kbs:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-65",
                    finding_name="No Knowledge Bases Found",
                    finding_details="No Bedrock Knowledge Bases found; S3 event notification check not applicable.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/NotificationHowTo.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-65"],
                )
            )
            return findings

        buckets_without_notifications = []
        missing_buckets = []
        for kb in kbs:
            kb_id = kb["knowledgeBaseId"]
            data_sources = kb_inv.data_sources_by_kb.get(kb_id, [])
            if isinstance(data_sources, _Unavailable):
                raise data_sources.error
            for ds in data_sources:
                ds_id = ds["dataSourceId"]
                ds_detail = kb_inv.data_source_detail.get((kb_id, ds_id))
                if isinstance(ds_detail, _Unavailable):
                    raise ds_detail.error
                if ds_detail is None:
                    continue
                s3_config = (
                    ds_detail.get("dataSource", {})
                    .get("dataSourceConfiguration", {})
                    .get("s3Configuration", {})
                )
                bucket = _bucket_name_from_arn(s3_config.get("bucketArn", ""))
                if not bucket:
                    continue
                try:
                    notif = s3_client.get_bucket_notification_configuration(
                        Bucket=bucket
                    )
                    has_notif = any(
                        [
                            notif.get("TopicConfigurations"),
                            notif.get("QueueConfigurations"),
                            notif.get("LambdaFunctionConfigurations"),
                            notif.get("EventBridgeConfiguration"),
                        ]
                    )
                    if not has_notif:
                        buckets_without_notifications.append(bucket)
                except ClientError as e:
                    # An access error means we could not read the notification
                    # config; re-raise so it surfaces as could-not-assess rather
                    # than a false "missing notifications" finding.
                    if _is_access_error(e):
                        raise
                    # The data source points to a deleted bucket — a distinct
                    # integrity problem, not "notifications missing."
                    if _is_missing_bucket_error(e):
                        logger.warning(
                            f"KB '{kb.get('name', kb_id)}' data source "
                            f"'{ds.get('name', ds['dataSourceId'])}' references a "
                            f"deleted bucket: {bucket}"
                        )
                        missing_buckets.append(
                            f"{bucket} (KB '{kb.get('name', kb_id)}', "
                            f"source '{ds.get('name', ds['dataSourceId'])}')"
                        )
                        continue
                    buckets_without_notifications.append(f"{bucket} (error)")

        # A dangling data-source reference to a deleted bucket is a real integrity
        # finding — emit it separately so it is not conflated with "no notifications."
        if missing_buckets:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-65",
                    finding_name="KB Data Source References a Deleted S3 Bucket",
                    finding_details=(
                        "One or more Knowledge Base data sources point to S3 buckets that no "
                        "longer exist (NoSuchBucket). Document-change monitoring cannot be "
                        "assessed and KB grounding data is missing for these sources:\n"
                        + "\n".join(f"- {b}" for b in missing_buckets[:10])
                    ),
                    resolution=(
                        "1. Investigate why the data-source bucket was deleted (accidental "
                        "deletion, environment teardown, or stale KB configuration).\n"
                        "2. Recreate/restore the bucket (with event notifications and versioning "
                        "enabled), or remove the orphaned data source from the Knowledge Base.\n"
                        "3. Re-run a KB ingestion job after restoring the data source."
                    ),
                    reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/EventBridge.html",
                    severity="High",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-65"],
                )
            )

        if buckets_without_notifications:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-65",
                    finding_name="KB Data Source Buckets Missing S3 Event Notifications",
                    finding_details=(
                        "The following KB data-source S3 buckets have no event notifications configured. "
                        "Unauthorized document modifications will not be detected in real time:\n"
                        + "\n".join(
                            f"- {b}" for b in buckets_without_notifications[:10]
                        )
                    ),
                    resolution=(
                        "1. Enable Amazon EventBridge notifications on each KB data-source S3 bucket.\n"
                        "2. Create an EventBridge rule to route s3:ObjectCreated, s3:ObjectRemoved, "
                        "and s3:ObjectModified events to an SNS topic or Lambda for alerting.\n"
                        "3. Integrate alerts into your security incident response workflow."
                    ),
                    reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/EventBridge.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-65"],
                )
            )
        elif not missing_buckets:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-65",
                    finding_name="KB Data Source S3 Event Notifications Configured",
                    finding_details="All KB data-source S3 buckets have event notifications configured.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/AmazonS3/latest/userguide/EventBridge.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-65"],
                )
            )
    except Exception as e:
        return _error_findings("KB Data Source S3 Event Notifications Check", e)
    return findings


def check_agentcore_end_user_identity_propagation() -> Dict[str, Any]:
    """
    FS-66 — Verify AgentCore runtimes are configured to propagate end-user
    identities to downstream tool services so tool calls are authorized by
    the originating user, not solely by the agent execution role.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, NYDFS 500.06, MAS TRM 9.1]
    """
    findings = _empty_findings("AgentCore End-User Identity Propagation Check")
    try:
        agentcore = boto3.client("bedrock-agentcore-control", config=boto3_config)
        try:
            runtimes = agentcore.list_agent_runtimes().get("agentRuntimes", [])
        except ClientError as e:
            if "AccessDenied" in str(e) or "UnrecognizedClientException" in str(e):
                findings["csv_data"].append(
                    create_finding(
                        check_id="FS-66",
                        finding_name="AgentCore Identity Propagation — Access Check",
                        finding_details="Unable to enumerate AgentCore runtimes (access denied or service unavailable in region).",
                        resolution="Ensure assessment role has bedrock-agentcore:ListAgentRuntimes permission.",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security-authorization.html",
                        severity="Low",
                        status="N/A",
                        compliance_frameworks=COMPLIANCE_MAP["FS-66"],
                    )
                )
                return findings
            raise

        if not runtimes:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-66",
                    finding_name="No AgentCore Runtimes Found",
                    finding_details="No AgentCore runtimes found; identity propagation check not applicable.",
                    resolution=(
                        "If using AgentCore, configure token propagation so end-user identities "
                        "are forwarded to tool services."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security-authorization.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-66"],
                )
            )
            return findings

        runtimes_without_identity = [
            r["agentRuntimeName"]
            for r in runtimes
            if not r.get("authorizerConfiguration", {}).get("customJWTAuthorizer")
            and not r.get("authorizerConfiguration", {}).get("iamAuthorizer")
        ]

        if runtimes_without_identity:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-66",
                    finding_name="AgentCore Runtimes Missing End-User Identity Propagation",
                    finding_details=(
                        "The following runtimes have no JWT or IAM authorizer configured for "
                        "end-user identity propagation. Tool calls are authorized only by the "
                        "agent execution role, not the originating user:\n"
                        + "\n".join(f"- {r}" for r in runtimes_without_identity[:10])
                    ),
                    resolution=(
                        "1. Configure a custom JWT authorizer or IAM authorizer on each AgentCore runtime.\n"
                        "2. Propagate the end-user's identity token to downstream tool services.\n"
                        "3. Ensure tool services validate the propagated identity before executing actions.\n"
                        "4. Do not expose propagated identity tokens to unauthorized third parties."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security-authorization.html",
                    severity="High",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-66"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-66",
                    finding_name="AgentCore End-User Identity Propagation Configured",
                    finding_details=f"All {len(runtimes)} runtime(s) have authorizer configurations supporting identity propagation.",
                    resolution="No action required.",
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security-authorization.html",
                    severity="High",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-66"],
                )
            )
    except Exception as e:
        return _error_findings("AgentCore End-User Identity Propagation Check", e)
    return findings


def check_agent_financial_transaction_thresholds(inventory) -> Dict[str, Any]:
    """
    FS-67 — Check AgentCore Policy Engine or action-group Lambda functions
    enforce maximum transaction-value limits to prevent runaway or unauthorized
    high-value financial transactions initiated by agents.
    COMPLIANCE_PLACEHOLDER: [SR 11-7, MAS TRM 9.1, FFIEC CAT, PCI-DSS]
    """
    findings = _empty_findings("Agent Financial Transaction Value Thresholds Check")
    try:
        functions = require(inventory, "lambda_functions")

        # Look for agent action-group Lambda functions
        action_group_lambdas = [
            f
            for f in functions
            if any(
                kw in f["FunctionName"].lower()
                for kw in [
                    "agent",
                    "action",
                    "tool",
                    "bedrock",
                    "finserv",
                    "transaction",
                ]
            )
        ]

        if not action_group_lambdas:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-67",
                    finding_name="No Agent Action-Group Lambda Functions Found",
                    finding_details=(
                        "No Lambda functions matching agent action-group naming patterns found. "
                        "If agents perform financial transactions, verify transaction-value limits "
                        "are enforced in the action-group implementation."
                    ),
                    resolution=(
                        "1. Implement transaction-value threshold checks in all agent action-group "
                        "Lambda functions that initiate financial operations.\n"
                        "2. Use AgentCore Policy Engine to enforce maximum transaction amounts as "
                        "a policy constraint on tool calls.\n"
                        "3. Reject or escalate to human review any transaction exceeding defined limits."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-engine.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-67"],
                )
            )
        else:
            # Advisory: check for environment variables indicating threshold configuration
            lambdas_without_threshold_config = [
                f["FunctionName"]
                for f in action_group_lambdas
                if not any(
                    "threshold" in k.lower()
                    or "limit" in k.lower()
                    or "max" in k.lower()
                    for k in f.get("Environment", {}).get("Variables", {}).keys()
                )
            ]

            if lambdas_without_threshold_config:
                findings["status"] = "WARN"
                findings["csv_data"].append(
                    create_finding(
                        check_id="FS-67",
                        finding_name="Agent Action-Group Lambdas May Lack Transaction Thresholds",
                        finding_details=(
                            "The following agent action-group Lambda functions have no environment "
                            "variables whose names suggest transaction-value threshold configuration "
                            "(this is a best-effort heuristic — a threshold enforced in code or in an "
                            "AgentCore Policy Engine rule would not be detected here, so treat this as "
                            "a prompt for manual verification rather than a definitive gap). "
                            "Without explicit limits, agents could initiate unbounded financial transactions:\n"
                            + "\n".join(
                                f"- {n}" for n in lambdas_without_threshold_config[:10]
                            )
                        ),
                        resolution=(
                            "1. Add transaction-value threshold environment variables (e.g., MAX_TRANSACTION_AMOUNT) "
                            "to each agent action-group Lambda.\n"
                            "2. Implement threshold enforcement logic in the Lambda handler.\n"
                            "3. Configure AgentCore Policy Engine rules to cap financial transaction amounts.\n"
                            "4. Route transactions exceeding thresholds to a human-in-the-loop approval step."
                        ),
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-engine.html",
                        severity="High",
                        status="Failed",
                        compliance_frameworks=COMPLIANCE_MAP["FS-67"],
                    )
                )
            else:
                findings["csv_data"].append(
                    create_finding(
                        check_id="FS-67",
                        finding_name="Agent Action-Group Lambdas Have Threshold Configuration",
                        finding_details=(
                            f"Found {len(action_group_lambdas)} agent action-group Lambda(s) with "
                            "threshold/limit environment variables present."
                        ),
                        resolution="Verify threshold values are appropriate for your financial risk tolerance.",
                        reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-engine.html",
                        severity="High",
                        status="Passed",
                        compliance_frameworks=COMPLIANCE_MAP["FS-67"],
                    )
                )
    except Exception as e:
        return _error_findings("Agent Financial Transaction Value Thresholds Check", e)
    return findings


# Default body-inspection window AWS WAF applies before oversize handling kicks
# in. For CloudFront/API Gateway/Cognito/App Runner/Verified Access the default
# is 16 KB (raisable to 64 KB via the web ACL AssociationConfig); for ALB/AppSync
# it is a fixed 8 KB. A GT/GE SizeConstraint above this window can only ever fire
# if the rule's OversizeHandling is MATCH. See:
# https://docs.aws.amazon.com/waf/latest/developerguide/waf-oversize-request-components.html
_WAF_DEFAULT_BODY_INSPECTION_LIMIT = 16384

# JSON-Schema keywords that actually bound request-body SIZE. A request validator
# only enforces a size cap when its model schema carries one of these — merely
# enabling validateRequestBody does NOT cap payload size (it validates the schema
# / required params only; the REST hard limit is a fixed, non-configurable 10 MB).
_SCHEMA_SIZE_KEYWORDS = ('"maxLength"', '"maxItems"', '"maxProperties"')


def _waf_statement_has_firing_body_size_constraint(
    stmt: Any, inspection_limit: int = _WAF_DEFAULT_BODY_INSPECTION_LIMIT
) -> bool:
    """True if a WAF rule Statement contains a SizeConstraintStatement on the
    request Body/JsonBody that can actually fire.

    Recurses into And/Or/Not combinators. A GT/GE size threshold above the body
    inspection window cannot fire unless OversizeHandling is MATCH, so such a rule
    is NOT credited as a working body-size control (the documented WAF limitation).
    """
    if not isinstance(stmt, dict):
        return False
    sc = stmt.get("SizeConstraintStatement")
    if isinstance(sc, dict):
        ftm = sc.get("FieldToMatch", {}) or {}
        body = ftm.get("Body")
        json_body = ftm.get("JsonBody")
        target = body if isinstance(body, dict) else json_body
        if isinstance(target, dict):
            comparison = sc.get("ComparisonOperator", "")
            size = sc.get("Size", 0) or 0
            oversize = target.get("OversizeHandling")
            # A "block if body > N" rule with N beyond the inspection window only
            # fires when oversize content is treated as a match.
            if (
                comparison in ("GT", "GE")
                and size > inspection_limit
                and oversize != "MATCH"
            ):
                return False
            return True
    for combinator in ("AndStatement", "OrStatement"):
        sub = stmt.get(combinator)
        if isinstance(sub, dict):
            for inner in sub.get("Statements", []) or []:
                if _waf_statement_has_firing_body_size_constraint(
                    inner, inspection_limit
                ):
                    return True
    not_stmt = stmt.get("NotStatement")
    if isinstance(not_stmt, dict):
        if _waf_statement_has_firing_body_size_constraint(
            not_stmt.get("Statement"), inspection_limit
        ):
            return True
    return False


def _api_has_body_size_validator(apigw, api_id: str) -> bool:
    """True only if a REST API has a request validator that validates the body
    AND at least one model whose schema bounds body size (maxLength/maxItems/
    maxProperties). Validator presence alone is NOT sufficient — it does not cap
    payload size (the bug FS-68 previously had)."""
    validators = apigw.get_request_validators(restApiId=api_id).get("items", [])
    if not any(v.get("validateRequestBody") for v in validators):
        return False
    for model in _paginate(apigw, "get_models", "items", restApiId=api_id):
        schema = model.get("schema", "") or ""
        if any(tok in schema for tok in _SCHEMA_SIZE_KEYWORDS):
            return True
    return False


def check_api_gateway_request_body_size_limits(inventory) -> Dict[str, Any]:
    """
    FS-68 — Verify API Gateway REST APIs fronting GenAI endpoints actually enforce
    a maximum input-payload size (to blunt token-exhaustion via oversized prompts).

    Important correctness note: an API Gateway request validator does NOT cap body
    size — it validates required params + a JSON-Schema model, and the REST payload
    limit is a fixed, non-configurable 10 MB. A real size cap requires either (a) a
    validator model with a maxLength/maxItems/maxProperties bound, or (b) a WAF
    SizeConstraintStatement on the request Body that can actually fire within WAF's
    body-inspection window (default 16 KB for API Gateway). This check credits only
    those evidenced controls — validator presence alone is not a pass.
    COMPLIANCE_PLACEHOLDER: [FFIEC CAT, DORA Art.6, PCI-DSS, OWASP LLM10]
    """
    findings = _empty_findings("API Gateway Request Body Size Limits Check")
    try:
        apigw = boto3.client("apigateway", config=boto3_config)

        rest_apis = _paginate(apigw, "get_rest_apis", "items")
        # require() raises if inventory is None or web_acls is _Unavailable.
        web_acl_inv = require(inventory, "web_acls")
        acls = web_acl_inv.summaries

        # Nothing-to-assess branch: no REST APIs AND no WAF ACLs means there is no
        # input-payload surface to evaluate in this region.
        if not rest_apis and not acls:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-68",
                    finding_name="API Gateway Request Body Size Limits — Not Applicable",
                    finding_details=(
                        "No API Gateway REST APIs and no regional WAF Web ACLs were found in this "
                        "region. There is no input-payload surface to assess for body-size limits."
                    ),
                    resolution=(
                        "If GenAI endpoints are fronted by API Gateway or WAF in another region, "
                        "run the assessment there. Otherwise no action is required."
                    ),
                    reference="https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-size-constraint.html",
                    severity="Informational",
                    status="N/A",
                    compliance_frameworks=COMPLIANCE_MAP["FS-68"],
                )
            )
            return findings

        # Evidence 1: REST APIs whose validator model actually bounds body size.
        apis_with_size_control = []
        for api in rest_apis:
            if _api_has_body_size_validator(apigw, api["id"]):
                apis_with_size_control.append(api.get("name", api["id"]))

        # Evidence 2: regional WAF ACLs with a body SizeConstraint that can fire.
        # detail_by_id holds get_web_acl(...)['WebACL'] or _Unavailable.
        # An _Unavailable entry re-raises its error → outer except → COULD_NOT_ASSESS.
        acls_with_size_rules = 0
        for acl in acls:
            detail = web_acl_inv.detail_by_id[acl["Id"]]
            if isinstance(detail, _Unavailable):
                raise detail.error
            rules = detail.get("Rules", [])
            if any(
                _waf_statement_has_firing_body_size_constraint(r.get("Statement", {}))
                for r in rules
            ):
                acls_with_size_rules += 1

        has_size_control = bool(apis_with_size_control) or acls_with_size_rules > 0

        if has_size_control:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-68",
                    finding_name="API Gateway Request Body Size Limits Configured",
                    finding_details=(
                        f"Found {len(rest_apis)} REST API(s) "
                        f"({len(apis_with_size_control)} with a body-size-bounding validator model) "
                        f"and {acls_with_size_rules} WAF ACL(s) with a firing body-size constraint. "
                        "Verify the WAF ACL(s) are associated with the GenAI-facing API stages, "
                        "since this check does not confirm resource association."
                    ),
                    resolution="No action required (verify WAF/API association as noted).",
                    reference="https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-size-constraint.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-68"],
                )
            )
        else:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-68",
                    finding_name="API Gateway Request Body Size Limits Not Enforced",
                    finding_details=(
                        f"Found {len(rest_apis)} REST API(s) and {len(acls)} regional WAF Web "
                        "ACL(s), but none enforce a maximum request-body size. Note: an API "
                        "Gateway request validator does NOT cap body size (it validates the schema "
                        "and required params; the REST limit is a fixed 10 MB), and a WAF body "
                        "SizeConstraint only inspects the first ~16 KB of the body by default. "
                        "Oversized prompts can exhaust Bedrock token quotas and inflate costs."
                    ),
                    resolution=(
                        "1. Add a maxLength (or maxItems/maxProperties) bound to the request-body "
                        "JSON-Schema model used by your request validator, so oversized prompts are "
                        "rejected with a 400.\n"
                        "2. Add a WAF SizeConstraintStatement on the request Body sized within WAF's "
                        "body-inspection window (default 16 KB; raise via the web ACL "
                        "AssociationConfig, or set OversizeHandling=MATCH to block bodies beyond the "
                        "window), and associate the ACL with the API stage.\n"
                        "3. Set the max_tokens parameter in Bedrock API calls to cap output length.\n"
                        "4. Implement client-side token counting before submitting requests."
                    ),
                    reference="https://docs.aws.amazon.com/waf/latest/developerguide/waf-oversize-request-components.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-68"],
                )
            )
    except Exception as e:
        return _error_findings("API Gateway Request Body Size Limits Check", e)
    return findings


def check_prompt_input_validation_function(inventory) -> Dict[str, Any]:
    """
    FS-69 — Check for a Lambda function or API Gateway request validator that
    sanitizes user prompt input (strips special characters, enforces expected
    format, rejects oversized inputs) before forwarding to Bedrock.
    COMPLIANCE_PLACEHOLDER: [OWASP LLM01, FFIEC CAT, NYDFS 500.06]
    """
    findings = _empty_findings("Prompt Input Validation Function Check")
    try:
        functions = require(inventory, "lambda_functions")

        # Look for Lambda functions with input validation / sanitization naming patterns
        VALIDATION_KEYWORDS = [
            "sanitiz",
            "validat",
            "input",
            "preprocess",
            "pre-process",
            "filter",
            "clean",
            "prompt-guard",
            "promptguard",
        ]
        validation_lambdas = [
            f["FunctionName"]
            for f in functions
            if any(kw in f["FunctionName"].lower() for kw in VALIDATION_KEYWORDS)
        ]

        if not validation_lambdas:
            findings["status"] = "WARN"
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-69",
                    finding_name="No Prompt Input Validation Function Found",
                    finding_details=(
                        "No Lambda functions matching input validation or sanitization naming "
                        "patterns were found. Without explicit prompt input validation, malicious "
                        "inputs (special characters, oversized payloads, injection sequences) may "
                        "reach Bedrock unfiltered, bypassing WAF-level controls."
                    ),
                    resolution=(
                        "1. Implement a Lambda authorizer or pre-processing function that:\n"
                        "   - Strips or escapes special characters from user input.\n"
                        "   - Validates input against an expected format (e.g., regex allowlist).\n"
                        "   - Rejects inputs exceeding maximum token/character limits.\n"
                        "   - Logs rejected inputs for security monitoring.\n"
                        "2. Use parameterized prompt templates instead of string concatenation.\n"
                        "3. Apply Bedrock Guardrails PROMPT_ATTACK filter as a complementary control.\n"
                        "4. Reference: AWS Prompt Injection Security guidance."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-injection.html",
                    severity="Medium",
                    status="Failed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-69"],
                )
            )
        else:
            findings["csv_data"].append(
                create_finding(
                    check_id="FS-69",
                    finding_name="Prompt Input Validation Functions Present",
                    finding_details=(
                        f"Found {len(validation_lambdas)} Lambda function(s) with input "
                        f"validation/sanitization naming patterns: "
                        f"{', '.join(validation_lambdas[:5])}."
                    ),
                    resolution=(
                        "Review these functions to confirm they cover: special-character stripping, "
                        "format validation, size limits, and injection-sequence detection."
                    ),
                    reference="https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-injection.html",
                    severity="Medium",
                    status="Passed",
                    compliance_frameworks=COMPLIANCE_MAP["FS-69"],
                )
            )
    except Exception as e:
        return _error_findings("Prompt Input Validation Function Check", e)
    return findings


# ===========================================================================
# REPORT GENERATION & LAMBDA HANDLER
# ===========================================================================


def generate_csv_report(findings: List[Dict[str, Any]]) -> str:
    """Generate CSV report from all security check findings."""
    csv_buffer = StringIO()
    fieldnames = [
        "Check_ID",
        "Finding",
        "Finding_Details",
        "Resolution",
        "Reference",
        "Severity",
        "Status",
        "Compliance_Frameworks",
    ]
    writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)
    writer.writeheader()
    for finding in findings:
        for row in finding.get("csv_data", []):
            writer.writerow(row)
    return csv_buffer.getvalue()


def write_to_s3(execution_id: str, csv_content: str, bucket_name: str) -> str:
    """Write CSV report to S3 bucket."""
    s3_client = boto3.client("s3", config=boto3_config)
    file_name = f"finserv_security_report_{execution_id}.csv"
    s3_client.put_object(
        Bucket=bucket_name, Key=file_name, Body=csv_content, ContentType="text/csv"
    )
    return f"https://{bucket_name}.s3.amazonaws.com/{file_name}"


# ---------------------------------------------------------------------------
# Inventory collector (REQ-1, REQ-2, REQ-3, REQ-4, REQ-7)
# ---------------------------------------------------------------------------


def _safe_collect_lambda_functions():
    """Collect all Lambda functions via list_functions (fully paginated).
    Returns a list on success, or _Unavailable(exc) on any failure."""
    try:
        client = boto3.client("lambda", config=boto3_config)
        return _paginate(client, "list_functions", "Functions")
    except Exception as e:
        logger.warning(
            "inventory:lambda_functions collection failed: %s", type(e).__name__
        )
        return _Unavailable(e)


def _safe_collect_guardrails():
    """Collect Bedrock guardrail summaries and per-guardrail DRAFT detail.
    A single-guardrail detail failure is recorded as _Unavailable for that id
    only — it does NOT abort the whole guardrail inventory."""
    try:
        client = boto3.client("bedrock", config=boto3_config)
        summaries = _paginate(client, "list_guardrails", "guardrails")
        detail_by_id: dict = {}
        for g in summaries:
            gid = g["id"]
            try:
                detail_by_id[gid] = client.get_guardrail(
                    guardrailIdentifier=gid, guardrailVersion="DRAFT"
                )
            except Exception as e:
                logger.warning(
                    "inventory:guardrails detail for %s failed: %s",
                    gid,
                    type(e).__name__,
                )
                detail_by_id[gid] = _Unavailable(e)
        return GuardrailInventory(summaries=summaries, detail_by_id=detail_by_id)
    except Exception as e:
        logger.warning("inventory:guardrails collection failed: %s", type(e).__name__)
        return _Unavailable(e)


def _safe_collect_knowledge_bases():
    """Collect Bedrock Knowledge Base summaries, per-KB data-source summaries,
    and per-data-source detail.  Per-KB and per-data-source failures are
    recorded as _Unavailable without aborting the rest of the collection."""
    try:
        client = boto3.client("bedrock-agent", config=boto3_config)
        summaries = _paginate(client, "list_knowledge_bases", "knowledgeBaseSummaries")
        data_sources_by_kb: dict = {}
        data_source_detail: dict = {}
        for kb in summaries:
            kb_id = kb["knowledgeBaseId"]
            try:
                ds_summaries = _paginate(
                    client,
                    "list_data_sources",
                    "dataSourceSummaries",
                    knowledgeBaseId=kb_id,
                )
                data_sources_by_kb[kb_id] = ds_summaries
                for ds in ds_summaries:
                    ds_id = ds["dataSourceId"]
                    try:
                        data_source_detail[(kb_id, ds_id)] = client.get_data_source(
                            knowledgeBaseId=kb_id, dataSourceId=ds_id
                        )
                    except Exception as e:
                        logger.warning(
                            "inventory:knowledge_bases data_source detail (%s, %s) failed: %s",
                            kb_id,
                            ds_id,
                            type(e).__name__,
                        )
                        data_source_detail[(kb_id, ds_id)] = _Unavailable(e)
            except Exception as e:
                logger.warning(
                    "inventory:knowledge_bases data_sources for KB %s failed: %s",
                    kb_id,
                    type(e).__name__,
                )
                data_sources_by_kb[kb_id] = _Unavailable(e)
        return KbInventory(
            summaries=summaries,
            data_sources_by_kb=data_sources_by_kb,
            data_source_detail=data_source_detail,
        )
    except Exception as e:
        logger.warning(
            "inventory:knowledge_bases collection failed: %s", type(e).__name__
        )
        return _Unavailable(e)


def _safe_collect_buckets():
    """Collect the full account S3 bucket list with explicit ContinuationToken
    pagination.  MaxBuckets=1000 ensures pagination is always engaged so accounts
    above the 10,000-bucket quota (where unpaginated requests are rejected) succeed."""
    try:
        client = boto3.client("s3", config=boto3_config)
        return _paginate(
            client,
            "list_buckets",
            "Buckets",
            token=("ContinuationToken", "ContinuationToken"),
            MaxBuckets=1000,
        )
    except Exception as e:
        logger.warning("inventory:buckets collection failed: %s", type(e).__name__)
        return _Unavailable(e)


def _safe_collect_web_acls():
    """Collect WAFv2 REGIONAL Web ACL summaries and per-ACL detail.  Uses
    explicit NextMarker/NextMarker pagination (WAFv2 input ≠ Lambda Marker).
    Per-ACL detail failures are recorded as _Unavailable for that id only."""
    try:
        client = boto3.client("wafv2", config=boto3_config)
        summaries = _paginate(
            client,
            "list_web_acls",
            "WebACLs",
            token=("NextMarker", "NextMarker"),
            Scope="REGIONAL",
        )
        detail_by_id: dict = {}
        for acl in summaries:
            acl_id = acl["Id"]
            try:
                # Store the WebACL dict directly (response["WebACL"]), not the
                # full envelope, so consuming checks can do detail.get("Rules")
                # without an extra ["WebACL"] indirection (matches design §3).
                resp = client.get_web_acl(Name=acl["Name"], Scope="REGIONAL", Id=acl_id)
                detail_by_id[acl_id] = resp["WebACL"]
            except Exception as e:
                logger.warning(
                    "inventory:web_acls detail for %s failed: %s",
                    acl_id,
                    type(e).__name__,
                )
                detail_by_id[acl_id] = _Unavailable(e)
        return WebAclInventory(summaries=summaries, detail_by_id=detail_by_id)
    except Exception as e:
        logger.warning("inventory:web_acls collection failed: %s", type(e).__name__)
        return _Unavailable(e)


def collect_resource_inventory() -> ResourceInventory:
    """Collect each shared inventory at most once per invocation.

    Each inventory is isolated: a failure yields an ``_Unavailable`` sentinel
    for that field without aborting the others (REQ-4, INV-5).  All five
    inventories are always collected because the current registry always
    consumes all five (design DD-7).

    All clients use ``boto3.client(service, config=boto3_config)`` — no
    ``region_name`` or ``endpoint_url`` — so the Lambda's default-Region
    resolution is preserved (REQ-7, INV-4)."""
    return ResourceInventory(
        lambda_functions=_safe_collect_lambda_functions(),
        guardrails=_safe_collect_guardrails(),
        knowledge_bases=_safe_collect_knowledge_bases(),
        buckets=_safe_collect_buckets(),
        web_acls=_safe_collect_web_acls(),
    )


def build_finserv_checks(permission_cache, inventory=None):
    """
    Single source of truth: ordered (check_id, zero-arg callable) registry of
    all FinServ checks, in execution order (FS-01 → FS-69, skipping the ids
    merged into upstream: FS-17/18/19/23/64). The two permission-cache checks
    are bound with functools.partial so every entry is uniformly zero-arg.

    Driving the handler from this registry lets us attach the correct Check_ID
    to a synthesized "could not assess" row when a check errors out, instead of
    silently dropping the check from the report.

    ``inventory`` is optional (defaults to ``None``) so that existing one-arg
    call sites — e.g. tests/test_severity_register.py — continue to work
    without modification (DD-2b).  ``lambda_handler`` always passes a real
    ``ResourceInventory``; consuming checks will be bound to it in Wave 3.
    FS-21 and FS-46 (S3-inventory consumers) are bound to ``inventory`` here.
    Guardrail consumers (FS-27a, 28, 36, 38, 45, 47, 50, 51, 59) are now
    bound to ``inventory`` as well (Task 7).
    """
    return [
        # --- Category 1: Unbounded Consumption ---
        ("FS-01", functools.partial(check_waf_shield_on_bedrock_endpoints, inventory)),
        ("FS-02", check_api_gateway_rate_limiting),
        ("FS-03", check_bedrock_token_quotas),
        ("FS-04", check_cost_anomaly_detection),
        ("FS-05", check_cloudwatch_token_alarms),
        ("FS-06", check_aws_budgets_for_aiml),
        # --- Category 2: Excessive Agency ---
        (
            "FS-07",
            functools.partial(check_bedrock_agent_action_boundaries, permission_cache),
        ),
        ("FS-08", check_agentcore_policy_engine),
        ("FS-09", functools.partial(check_agent_transaction_limits, inventory)),
        ("FS-10", check_human_in_the_loop_for_high_risk_actions),
        ("FS-11", check_agent_rate_alarms),
        # --- Category 3: Supply Chain Vulnerabilities ---
        ("FS-12", check_scp_model_access_restrictions),
        ("FS-13", check_model_inventory_tagging),
        ("FS-14", check_model_onboarding_governance),
        ("FS-15", check_bedrock_model_evaluation_adversarial),
        ("FS-16", check_ecr_image_scanning),
        # --- Category 4: Training Data & Model Poisoning ---
        ("FS-20", check_feature_store_rollback_capability),
        ("FS-21", functools.partial(check_training_data_s3_versioning, inventory)),
        # --- Category 5: Vector & Embedding Weaknesses ---
        (
            "FS-22",
            functools.partial(
                check_knowledge_base_iam_least_privilege, permission_cache
            ),
        ),
        (
            "FS-24",
            functools.partial(check_knowledge_base_metadata_filtering, inventory),
        ),
        ("FS-25", check_opensearch_serverless_encryption),
        ("FS-26", check_knowledge_base_vpc_access),
        # --- Category 6: Non-Compliant Output ---
        # FS-27 is split into two checks: contextual grounding (threshold-based) and
        # Automated Reasoning policies (formal-verification, GA August 2025). Both
        # use the FS-27 check_id so they appear together in the CSV report.
        ("FS-27", functools.partial(check_guardrail_contextual_grounding, inventory)),
        ("FS-27", check_automated_reasoning_policies),
        (
            "FS-28",
            functools.partial(check_guardrail_denied_topics_financial, inventory),
        ),
        ("FS-29", check_compliance_disclaimer_in_outputs),
        ("FS-30", check_bedrock_evaluation_compliance_datasets),
        # --- Category 7: Misinformation ---
        ("FS-31", functools.partial(check_knowledge_base_data_source_sync, inventory)),
        ("FS-32", check_source_attribution_in_guardrails),
        (
            "FS-33",
            functools.partial(check_knowledge_base_integrity_monitoring, inventory),
        ),
        ("FS-34", check_fm_version_currency),
        # --- Category 8: Abusive or Harmful Output ---
        ("FS-35", check_fmeval_harmful_content),
        ("FS-36", functools.partial(check_guardrail_content_filters, inventory)),
        ("FS-37", check_user_feedback_mechanism),
        ("FS-38", functools.partial(check_guardrail_word_filters, inventory)),
        # --- Category 9: Biased Output ---
        ("FS-39", check_sagemaker_clarify_bias),
        ("FS-40", check_bedrock_evaluation_bias_datasets),
        ("FS-41", check_sagemaker_clarify_explainability),
        ("FS-42", check_ai_service_cards_documentation),
        # --- Category 10: Sensitive Information Disclosure ---
        ("FS-43", check_cloudwatch_log_pii_masking),
        ("FS-44", check_macie_on_training_data_buckets),
        ("FS-45", functools.partial(check_guardrail_pii_filters, inventory)),
        ("FS-46", functools.partial(check_data_classification_tagging, inventory)),
        # --- Category 11: Hallucination ---
        ("FS-47", functools.partial(check_guardrail_grounding_threshold, inventory)),
        ("FS-48", functools.partial(check_rag_knowledge_base_configured, inventory)),
        ("FS-49", check_hallucination_disclaimer_advisory),
        ("FS-50", functools.partial(check_guardrail_relevance_grounding, inventory)),
        # --- Category 12: Prompt Injection ---
        (
            "FS-51",
            functools.partial(check_prompt_injection_input_validation, inventory),
        ),
        ("FS-52", functools.partial(check_bedrock_sdk_version_currency, inventory)),
        ("FS-53", functools.partial(check_waf_sql_injection_rules, inventory)),
        ("FS-54", check_penetration_testing_evidence),
        # --- Category 13: Improper Output Handling ---
        ("FS-55", functools.partial(check_output_validation_lambda, inventory)),
        ("FS-56", functools.partial(check_xss_prevention_waf, inventory)),
        ("FS-57", check_output_encoding_advisory),
        ("FS-58", functools.partial(check_output_schema_validation, inventory)),
        # --- Category 14: Off-Topic & Inappropriate Output ---
        ("FS-59", functools.partial(check_guardrail_topic_allowlist, inventory)),
        ("FS-60", check_contextual_grounding_for_offtopic),
        # --- Category 15: Out-of-Date Training Data ---
        ("FS-61", functools.partial(check_knowledge_base_sync_schedule, inventory)),
        ("FS-62", check_data_currency_disclaimer_advisory),
        ("FS-63", check_foundation_model_lifecycle_policy),
        # --- Material Gap Checks (FS-65 to FS-69) ---
        (
            "FS-65",
            functools.partial(check_kb_datasource_s3_event_notifications, inventory),
        ),
        ("FS-66", check_agentcore_end_user_identity_propagation),
        (
            "FS-67",
            functools.partial(check_agent_financial_transaction_thresholds, inventory),
        ),
        (
            "FS-68",
            functools.partial(check_api_gateway_request_body_size_limits, inventory),
        ),
        ("FS-69", functools.partial(check_prompt_input_validation_function, inventory)),
    ]


def lambda_handler(event, context):
    """Main Lambda handler — runs all FinServ security checks.

    The registry in build_finserv_checks() contains 65 entries (64 standalone
    FS checks plus the new FS-27 Automated Reasoning Policies check). Two
    entries share the FS-27 check_id (contextual grounding + ARC policies),
    both contributing rows to the report under the same check namespace.
    """
    logger.info("Starting FinServ GenAI security assessment")
    all_findings = []

    execution_id = event.get("Execution", {}).get("Name", "local-test")
    permission_cache = get_permissions_cache(execution_id) or {
        "role_permissions": {},
        "user_permissions": {},
    }
    inventory = collect_resource_inventory()  # NEW: once per invocation

    # Run every check from the registry. If a check produces no rows for ANY
    # reason (an ERROR envelope, or an unexpected empty non-error result),
    # synthesize a visible "could not assess" row (keyed by its Check_ID) so the
    # gap surfaces in the report instead of the check silently vanishing. The
    # guard intentionally keys off empty csv_data (not just status=="ERROR") so
    # the no-silent-drop invariant holds structurally, not by data coincidence.
    for check_id, check_fn in build_finserv_checks(permission_cache, inventory):
        result = check_fn()
        if not result.get("csv_data"):
            details = result.get("details", "") or (
                f"check returned status={result.get('status', 'UNKNOWN')!r} "
                "with no findings"
            )
            result.setdefault("csv_data", []).append(
                _could_not_assess_row(
                    check_id,
                    result.get("check_name", check_id),
                    details,
                )
            )
        all_findings.append(result)

    # Generate and upload report
    csv_content = generate_csv_report(all_findings)
    bucket_name = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
    if not bucket_name:
        raise ValueError("AIML_ASSESSMENT_BUCKET_NAME environment variable is not set")

    s3_url = write_to_s3(execution_id, csv_content, bucket_name)

    return {
        "statusCode": 200,
        "body": {
            "message": "FinServ security assessment completed",
            "findings": all_findings,
            "report_url": s3_url,
        },
    }
