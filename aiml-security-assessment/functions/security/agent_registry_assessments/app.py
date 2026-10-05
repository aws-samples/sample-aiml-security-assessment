"""AWS Agent Registry security assessment Lambda function."""

import boto3
import csv
import json
import logging
import os
import re
import time
from datetime import date, datetime, timezone
from fnmatch import fnmatchcase
from io import StringIO
from typing import Any, Dict, Iterable, List, Optional

from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError

from schema import SeverityEnum, StatusEnum, create_finding

logger = logging.getLogger()
logger.setLevel(logging.INFO)

boto3_config = Config(retries=dict(max_attempts=10, mode="adaptive"))
s3_client = boto3.client("s3", config=boto3_config)
iam_client = None
agent_registry_control_client = None
events_client = None
start_time = None

BUCKET_NAME = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
GLOBAL_REGION_LABEL = "Global"
REGISTRY_PAGE_SIZE = 100
RECORD_INVENTORY_LIMIT = 1000
REGISTRY_IAM_NAMESPACE = "agent-registry"
# Both namespaces grant the Registry actions. Support for the public-preview
# `bedrock-agentcore` spelling ends on REGISTRY_PREVIEW_EVENT_SOURCE_END, so until
# then a question about who holds a Registry authority has to read the policy in
# both namespaces or a preview-era grant answers it as absent.
REGISTRY_IAM_NAMESPACES = (REGISTRY_IAM_NAMESPACE, "bedrock-agentcore")
REGISTRY_PUBLISH_ACTIONS = (
    "CreateRegistryRecord",
    "UpdateRegistryRecord",
    "SubmitRegistryRecordForApproval",
)
REGISTRY_APPROVAL_ACTION = "UpdateRegistryRecordStatus"
# Every Registry action in each namespace, from the service authorization
# reference (agent-registry and bedrock-agentcore, version v1.4).
REGISTRY_ACTIONS = tuple(
    f"{REGISTRY_IAM_NAMESPACE}:{name}"
    for name in (
        "CreateRegistry",
        "CreateRegistryRecord",
        "DeleteRegistry",
        "DeleteRegistryRecord",
        "DeleteResourcePolicy",
        "GetDiscoverableRegistryRecord",
        "GetRegistry",
        "GetRegistryRecord",
        "GetResourcePolicy",
        "InvokeRegistryMcp",
        "ListDiscoverableRegistryRecords",
        "ListRegistries",
        "ListRegistryRecords",
        "ListTagsForResource",
        "PutResourcePolicy",
        "SearchDiscoverableRegistryRecords",
        "SubmitRegistryRecordForApproval",
        "TagResource",
        "UntagResource",
        "UpdateRegistry",
        "UpdateRegistryRecord",
        "UpdateRegistryRecordStatus",
    )
) + tuple(
    f"bedrock-agentcore:{name}"
    for name in (
        "CreateRegistry",
        "CreateRegistryRecord",
        "DeleteRegistry",
        "DeleteRegistryRecord",
        "GetRegistry",
        "GetRegistryRecord",
        "InvokeRegistryMcp",
        "ListRegistries",
        "ListRegistryRecords",
        "SearchRegistryRecords",
        "SubmitRegistryRecordForApproval",
        "UpdateRegistry",
        "UpdateRegistryRecord",
        "UpdateRegistryRecordStatus",
    )
)
# Per resource type, the actions that read it and the actions that write it,
# generated from the service authorization reference by
# generate_iam_access_levels.py.
with open(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "iam_access_levels.json"),
    encoding="utf-8",
) as _levels:
    ACCESS_LEVELS: Dict[str, Dict[str, Dict[str, List[str]]]] = json.load(_levels)[
        "services"
    ]
UNRECORDED_PRINCIPAL_ERRORS_NOTE = (
    "The IAM permissions cache predates schema version 2 and did not record "
    "per-principal read errors, so a principal whose policies could not be read "
    "looks the same as one with no policies."
)
SCP_NOT_EVALUATED_NOTE = (
    "Service control policies were not evaluated per principal. They only remove "
    "permissions, so an SCP can make this finding a false Failed but cannot hide "
    "a grant it reports."
)
# Registry lifecycle events are delivered to the default event bus in the
# resource's own account, so a rule on a custom bus never receives them.
REGISTRY_EVENT_BUS_NAME = "default"
# The review pipelines a Registry lifecycle event can be routed to: a Lambda
# function, an SNS topic, an SQS queue or a Step Functions state machine, named
# by the service segment of the target ARN.
REVIEW_PIPELINE_SERVICES = {
    "lambda": "Lambda function",
    "sns": "SNS topic",
    "sqs": "SQS queue",
    "states": "Step Functions state machine",
}
REVIEW_PIPELINE_LABEL = (
    "a Lambda function, SNS topic, SQS queue or Step Functions state machine"
)
REGISTRY_EVENT_SOURCE = "aws.agent-registry"
# The public-preview event source and IAM namespace. Both stop working on the
# date below, so a rule that matches only this source routes nothing after it
# and a `bedrock-agentcore` grant no longer reaches a Registry action.
REGISTRY_PREVIEW_EVENT_SOURCE = "aws.bedrock-agentcore"
REGISTRY_PREVIEW_EVENT_SOURCE_END = date(2026, 10, 30)
REGISTRY_PREVIEW_EVENT_SOURCE_END_LABEL = "30 October 2026"
# The record transitions that carry an approval decision. AR-03 and AR-09 assert
# how the approval workflow is configured and who may decide; routing these three
# is what makes the decisions observable.
REGISTRY_APPROVAL_DETAIL_TYPES = (
    "Registry Record State changed to Pending Approval",
    "Registry Record State changed to Approved",
    "Registry Record State changed to Rejected",
)
# Every detail type the GA source publishes. A rule with no detail-type filter
# matches all of them.
REGISTRY_LIFECYCLE_DETAIL_TYPES = REGISTRY_APPROVAL_DETAIL_TYPES + (
    "Registry Record State changed to Draft",
    "Registry Record State changed to Deprecated",
    "Registry Creating",
    "Registry Ready",
    "Registry Create Failed",
    "Registry Updating",
    "Registry Update Failed",
    "Registry Deleting",
    "Registry Delete Failed",
)
REGION_UNAVAILABLE_ERROR_CODES = {
    "AuthFailure",
    "InvalidClientTokenId",
    "OptInRequired",
    "UnrecognizedClientException",
}
ACCESS_DENIED_ERROR_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
}

AGENTIC_AI_LENS_URL = (
    "https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/"
    "agentic-ai-lens.html"
)
IAM_FULL_ACCESS_REFERENCE_URL = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html"
)
IAM_LAST_ACCESSED_REFERENCE_URL = "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed.html"
APPROVAL_REFERENCE_URL = (
    "https://docs.aws.amazon.com/agent-registry-control/latest/APIReference/"
    "API_ApprovalConfiguration.html"
)
APPROVAL_SEPARATION_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/"
    "registry-concepts.html#registry-concept-personas"
)
AUTHORIZATION_REFERENCE_URL = (
    "https://docs.aws.amazon.com/agent-registry-control/latest/APIReference/"
    "API_CustomJWTAuthorizerConfiguration.html"
)
ENCRYPTION_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/"
    "registry-data-encryption.html"
)
AUTO_DETECTION_REFERENCE_URL = (
    "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/"
    "registry-organizations.html"
)
RECORD_LIFECYCLE_REFERENCE_URL = (
    "https://docs.aws.amazon.com/agent-registry-control/latest/APIReference/"
    "API_SubmitRegistryRecordForApproval.html"
)
PROVENANCE_REFERENCE_URL = (
    "https://docs.aws.amazon.com/agent-registry-control/latest/APIReference/"
    "API_Provenance.html"
)
EVENT_ROUTING_REFERENCE_URL = (
    "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rules.html"
)


def _caller_identity_partition(caller_identity: Dict[str, Any]) -> str:
    """Return the STS ARN partition, defaulting safely for incomplete identities."""
    arn = caller_identity.get("Arn")
    if not isinstance(arn, str):
        return "aws"
    parts = arn.split(":", 2)
    if len(parts) < 3 or parts[0] != "arn" or not parts[1]:
        return "aws"
    return parts[1]


AGENTIC_AGENT_REGISTRY_CHECK_MAPPINGS = {
    "AR-03": {
        "check_id": "AG-33",
        "finding": "Agentic AI Registry Publication Approval Governance",
        "lens_domain": "Agent Identity & Access",
        "context": "Registry approval workflows control which agents, tools, and skills become discoverable to consumers.",
        "resolution": "Require manual review for registry publication where organizational policy does not permit automatic approval.",
    },
    "AR-04": {
        "check_id": "AG-34",
        "finding": "Agentic AI Registry Discovery Authorization",
        "lens_domain": "Agent Identity & Access",
        "context": "Registry discovery authorization requires review against intended callers and effective access boundaries.",
        "resolution": "Review effective IAM access or compare custom JWT audiences, clients, scopes, and claims with approved registry consumers.",
    },
    "AR-05": {
        "check_id": "AG-35",
        "finding": "Agentic AI Registry Metadata Encryption",
        "lens_domain": "Memory & Data Privacy",
        "context": "Registry records can contain agent, tool, endpoint, and ownership metadata that benefits from customer-controlled encryption.",
        "resolution": "Create the registry with a customer-managed KMS key when organizational policy requires customer-controlled encryption.",
    },
    "AR-06": {
        "check_id": "AG-36",
        "finding": "Agentic AI Organization Discovery Coverage",
        "lens_domain": "Auditability & Continuous Assurance",
        "context": "Organization-wide auto-detection provides visibility into unmanaged agent resources.",
        "resolution": "Enable organization-scoped registry auto-detection where centralized discovery is required.",
    },
    "AR-07": {
        "check_id": "AG-37",
        "finding": "Agentic AI Registry Record Lifecycle Governance",
        "lens_domain": "Agent Identity & Access",
        "context": "Registry lifecycle states provide operational visibility but do not independently prove a security control.",
        "resolution": "Review failed or unknown record lifecycle states operationally.",
    },
    "AR-08": {
        "check_id": "AG-38",
        "finding": "Agentic AI Registry Record Provenance",
        "lens_domain": "Auditability & Continuous Assurance",
        "context": "Consumers need attributable record origin and source lineage to understand which account and resource produced an entry.",
        "resolution": "Ensure records retain creator attribution and auto-detected records retain source provenance.",
    },
}


def check_timeout() -> bool:
    """Leave time to write a partial report before the Lambda hard timeout."""
    return start_time is None or time.time() - start_time < 540


def _error_code(error: Exception) -> str:
    if isinstance(error, ClientError):
        return error.response.get("Error", {}).get("Code", "")
    return ""


def _is_unavailable(error: Exception) -> bool:
    return (
        isinstance(error, EndpointConnectionError)
        or _error_code(error) in REGION_UNAVAILABLE_ERROR_CODES
    )


def _is_access_denied(error: Exception) -> bool:
    return _error_code(error) in ACCESS_DENIED_ERROR_CODES


def _error_detail(error: Exception) -> str:
    code = _error_code(error)
    if code:
        return f"{code} ({error.response.get('Error', {}).get('Message', '')})"
    return str(error) or type(error).__name__


def _error_resolution(error: Exception, action: str) -> str:
    if _is_access_denied(error):
        return f"Grant {action} and retry the assessment."
    return "Resolve the service error and retry the assessment."


def _na(
    check_id: str,
    finding: str,
    details: str,
    reference: str,
    resolution: str = "No action required",
) -> Dict[str, Any]:
    return create_finding(
        check_id=check_id,
        finding_name=finding,
        finding_details=details,
        resolution=resolution,
        reference=reference,
        severity=SeverityEnum.INFORMATIONAL,
        status=StatusEnum.NA,
    )


def _get_permissions_cache(execution_id: str) -> Dict[str, Any]:
    try:
        response = s3_client.get_object(
            Bucket=BUCKET_NAME, Key=f"permissions_cache_{execution_id}.json"
        )
        return json.loads(response["Body"].read().decode("utf-8"))
    except ClientError as error:
        if _error_code(error) == "NoSuchKey":
            return {"role_permissions": {}, "user_permissions": {}}
        raise


def _policy_document(policy: Dict[str, Any]) -> Dict[str, Any]:
    document = policy.get("document", {})
    if isinstance(document, str):
        document = json.loads(document)
    return document if isinstance(document, dict) else {}


def _policy_statements(policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return policy statements regardless of IAM's one-or-many JSON shape."""
    statements = _policy_document(policy).get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return [statement for statement in statements if isinstance(statement, dict)]


def _as_list(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value.lower()]
    return [str(item).lower() for item in value] if isinstance(value, list) else []


def _identity_policies(permissions: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Attached, inline and, for a user, group policies of one cached identity."""
    return [
        *(permissions.get("attached_policies") or []),
        *(permissions.get("inline_policies") or []),
        *(permissions.get("group_policies") or []),
    ]


def _statement_matches(statement: Dict[str, Any], action: str) -> bool:
    """Whether one statement's Action or NotAction names a concrete action."""
    if "Action" in statement:
        return any(
            fnmatchcase(action.lower(), pattern)
            for pattern in _as_list(statement.get("Action"))
        )
    return "NotAction" in statement and not any(
        fnmatchcase(action.lower(), pattern)
        for pattern in _as_list(statement.get("NotAction"))
    )


def _granted_actions(permissions: Dict[str, Any], actions: Iterable[str]) -> set:
    """Return the concrete ``actions`` one identity is granted.

    An action counts when an identity-policy Allow names it, no account-wide
    Deny removes it, and the permissions boundary, when there is one, allows it
    too: the effective grant is the intersection of the two. A conditioned or
    resource-scoped boundary Allow still counts as allowing, so an uncertain
    case keeps the grant and can only over-report.
    """
    statements = [
        statement
        for policy in _identity_policies(permissions)
        for statement in _policy_statements(policy)
    ]
    boundary = permissions.get("permissions_boundary")
    boundary_statements = (
        None if boundary is None else _policy_statements({"document": boundary})
    )
    granted = set()
    for action in actions:
        if not any(
            s.get("Effect") == "Allow" and _statement_matches(s, action)
            for s in statements
        ):
            continue
        if any(
            s.get("Effect") == "Deny" and _statement_denies_registry_action(s, action)
            for s in statements
        ):
            continue
        if boundary_statements is not None and (
            any(
                s.get("Effect") == "Deny"
                and _statement_denies_registry_action(s, action)
                for s in boundary_statements
            )
            or not any(
                s.get("Effect") == "Allow" and _statement_matches(s, action)
                for s in boundary_statements
            )
        ):
            continue
        granted.add(action)
    return granted


def _boundary_unread(permission_cache: Dict[str, Any]) -> set:
    """Return (type, name) for each principal whose permissions boundary the
    cache failed to read. The cache stores a null boundary both when none is
    set and when the read failed, so only the error entry tells them apart,
    and such a principal is left unassessed: a boundary could remove the grant.
    """
    return {
        (str(error.get("type", "")).lower(), error["name"])
        for error in permission_cache.get("principal_errors") or []
        if isinstance(error, dict)
        and error.get("name")
        and error.get("stage") == "permissions_boundary"
    }


def _has_wildcard(value: str) -> bool:
    return "*" in value or "?" in value


def _resource_unbounded(statement: Dict[str, Any]) -> bool:
    """Whether an Allow's resource scope is left open: every resource, a
    Resource ARN with a wildcard before the end of its registry id, or a
    NotResource.

    A registry id is service-generated, twelve to sixteen letters and digits,
    so a wildcard in it cannot select registries by name, and one in the
    Region or account segment reaches every registry there. A wildcard after a
    concrete partition, service, Region, account and registry id, such as
    `registry/<id>/record/*`, stays inside that one registry.
    """
    if "NotResource" in statement:
        return True
    for resource in _as_list(statement.get("Resource", [])):
        if not _has_wildcard(resource):
            continue
        parts = resource.split(":", 5)
        if len(parts) != 6 or any(_has_wildcard(part) for part in parts[:5]):
            return True
        resource_type, _, rest = parts[5].partition("/")
        registry_id, separator, _ = rest.partition("/")
        if (
            resource_type != "registry"
            or not registry_id
            or not separator
            or _has_wildcard(registry_id)
        ):
            return True
    return False


def _has_registry_access(permissions: Dict[str, Any], wildcard_only: bool) -> bool:
    if not _granted_actions(
        permissions,
        [a for a in REGISTRY_ACTIONS if a.startswith(f"{REGISTRY_IAM_NAMESPACE}:")],
    ):
        return False
    for policy in _identity_policies(permissions):
        for statement in _policy_statements(policy):
            if statement.get("Effect") != "Allow":
                continue
            actions = _as_list(statement.get("Action", []))
            if wildcard_only and not _resource_unbounded(statement):
                continue
            for action in actions:
                service, _, pattern = action.partition(":")
                if service == REGISTRY_IAM_NAMESPACE and (
                    not wildcard_only or "*" in pattern or "?" in pattern
                ):
                    return True
            not_actions = _as_list(statement.get("NotAction", []))
            if any(
                pattern.partition(":")[0] == REGISTRY_IAM_NAMESPACE
                or fnmatchcase(REGISTRY_IAM_NAMESPACE, pattern.partition(":")[0])
                for pattern in not_actions
            ) and not any(
                pattern in {"*", f"{REGISTRY_IAM_NAMESPACE}:*"}
                for pattern in not_actions
            ):
                return True
    return False


def _principal_read_errors(
    permission_cache: Dict[str, Any],
) -> Optional[List[str]]:
    """Label each principal whose cache read failed, or None for a cache that
    predates ``principal_errors``."""
    errors = permission_cache.get("principal_errors")
    if not isinstance(errors, list):
        return None
    failed: Dict[str, List[str]] = {}
    for error in errors:
        if isinstance(error, dict) and error.get("name"):
            label = f"{error.get('type', 'principal')} '{error['name']}'"
            failed.setdefault(label, []).append(str(error.get("stage", "unknown")))
    return [
        f"{label} ({', '.join(stages)})" for label, stages in sorted(failed.items())
    ]


def _unread_principals_detail(unread: List[str]) -> str:
    shown = ", ".join(unread[:10])
    if len(unread) > 10:
        shown += f" and {len(unread) - 10} more"
    return (
        f"{len(unread)} principal(s) could not be fully read into the IAM "
        f"permissions cache, so their grants are unknown: {shown}."
    )


def _cache_completeness_findings(
    check_id: str,
    finding: str,
    reference: str,
    permission_cache: Dict[str, Any],
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Hold back a Passed row while the cache names an unread principal.

    Each Passed row becomes N/A naming the principals, and a check that found
    something still reports it beside one incomplete row. A cache without
    ``principal_errors`` keeps its verdict and says the errors were not recorded.
    """
    unread = _principal_read_errors(permission_cache)
    if unread is None:
        for row in findings:
            if row["Status"] == StatusEnum.PASSED.value:
                row["Finding_Details"] += " " + UNRECORDED_PRINCIPAL_ERRORS_NOTE
        return findings
    if not unread:
        return findings
    detail = _unread_principals_detail(unread)
    resolution = (
        "Grant the IAM Permission Caching task read access to the listed "
        "principals, then re-run the assessment."
    )
    kept = [row for row in findings if row["Status"] != StatusEnum.PASSED.value]
    passed = [row for row in findings if row["Status"] == StatusEnum.PASSED.value]
    if passed:
        return kept + [
            _na(
                check_id,
                f"{finding} Incomplete",
                f"{row['Finding_Details']} {detail}",
                reference,
                resolution,
            )
            for row in passed
        ]
    return kept + [
        _na(check_id, f"{finding} Incomplete", detail, reference, resolution)
    ]


def _all_access_level_actions() -> List[str]:
    return sorted(
        {
            f"{namespace}:{action}"
            for namespace, types in ACCESS_LEVELS.items()
            for levels in types.values()
            for action in levels["read"] + levels["write"]
        }
    )


def _merged_read_write_grants(permissions: Dict[str, Any]) -> List[str]:
    """Describe each wildcard or NotAction Allow that grants both a read and a
    write action on one Registry resource type.

    An explicit action list separates read from write however long it is; a
    pattern or a NotAction cannot, because it grants whatever it matches. Only
    actions the identity is granted after Denies and its permissions boundary
    count. A condition or resource scope on the Allow applies to the read and
    the write alike, so it does not separate them and is not read.
    """
    effective = {
        action.lower()
        for action in _granted_actions(permissions, _all_access_level_actions())
    }
    grants = []
    for policy in _identity_policies(permissions):
        for statement in _policy_statements(policy):
            if statement.get("Effect") != "Allow":
                continue
            if "Action" in statement:
                triggers = [
                    (f"Action '{pattern}'", {"Action": pattern})
                    for pattern in _as_list(statement.get("Action"))
                    if "*" in pattern or "?" in pattern
                ]
            elif "NotAction" in statement:
                triggers = [
                    (
                        f"NotAction {_as_list(statement.get('NotAction'))}",
                        {"NotAction": statement.get("NotAction")},
                    )
                ]
            else:
                triggers = []
            for label, trigger in triggers:
                for namespace, types in ACCESS_LEVELS.items():
                    merged = []
                    for resource_type, levels in types.items():
                        reads = [
                            f"{namespace}:{a}"
                            for a in levels["read"]
                            if f"{namespace}:{a}".lower() in effective
                            and _statement_matches(trigger, f"{namespace}:{a}")
                        ]
                        writes = [
                            f"{namespace}:{a}"
                            for a in levels["write"]
                            if f"{namespace}:{a}".lower() in effective
                            and _statement_matches(trigger, f"{namespace}:{a}")
                        ]
                        if reads and writes:
                            merged.append((resource_type, reads, writes))
                    if not merged:
                        continue
                    resource_type, reads, writes = max(
                        merged,
                        key=lambda item: any(
                            w.split(":", 1)[1].startswith("Delete") for w in item[2]
                        ),
                    )
                    write = next(
                        (w for w in writes if w.split(":", 1)[1].startswith("Delete")),
                        writes[0],
                    )
                    grants.append(
                        f"{label} grants read and write on {len(merged)} "
                        f"{namespace} resource type(s), for example {reads[0]} and "
                        f"{write} on {resource_type}"
                    )
    return grants


MERGED_READ_WRITE_FINDING = "AWS Agent Registry Read and Write in One Grant"


def _merged_read_write_findings(
    identities: List[tuple],
) -> List[Dict[str, Any]]:
    """AIR-FND-IAM-09 leg of AR-01: a grant that cannot tell read from write."""
    flagged = []
    for kind, name, permissions in identities:
        grants = _merged_read_write_grants(permissions)
        if grants:
            flagged.append((kind, name, grants))
    rows = [
        create_finding(
            "AR-01",
            MERGED_READ_WRITE_FINDING,
            f"{kind.capitalize()} '{name}': {'; '.join(grants[:5])}. An explicit "
            "action list is the only form that grants the read without the write; "
            "a condition or resource scope applies to both alike. "
            + SCP_NOT_EVALUATED_NOTE,
            "Replace the wildcard or NotAction grant with the specific AWS Agent "
            "Registry read actions the identity needs, and grant record writes, "
            "status changes and deletes separately to the principals that make them.",
            IAM_FULL_ACCESS_REFERENCE_URL,
            SeverityEnum.HIGH,
            StatusEnum.FAILED,
        )
        for kind, name, grants in flagged[:20]
    ]
    if len(flagged) > 20:
        rows.append(
            create_finding(
                "AR-01",
                MERGED_READ_WRITE_FINDING,
                f"{len(flagged)} principals hold an AWS Agent Registry grant that "
                "merges read and write (the first 20 are reported individually).",
                "Replace each wildcard or NotAction grant with explicit actions.",
                IAM_FULL_ACCESS_REFERENCE_URL,
                SeverityEnum.HIGH,
                StatusEnum.FAILED,
            )
        )
    return rows


def check_agent_registry_full_access(
    permission_cache: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """AR-01: find full-access, wildcard and read-write-merging Registry grants,
    on every cached role and user."""
    finding = "AWS Agent Registry IAM Full Access Check"
    roles = permission_cache.get("role_permissions", {})
    users = permission_cache.get("user_permissions", {})
    if not roles and not users:
        return _cache_completeness_findings(
            "AR-01",
            finding,
            IAM_FULL_ACCESS_REFERENCE_URL,
            permission_cache,
            [
                _na(
                    "AR-01",
                    finding,
                    "No IAM role or user permissions found in cache.",
                    IAM_FULL_ACCESS_REFERENCE_URL,
                )
            ],
        )
    boundary_unread = _boundary_unread(permission_cache)
    identities = [
        (kind, name, perms)
        for kind, entries in (("role", roles), ("user", users))
        for name, perms in entries.items()
        if (kind, name) not in boundary_unread
        or perms.get("permissions_boundary") is not None
    ]
    full_access, wildcard = [], []
    for kind, name, permissions in identities:
        label = name if kind == "role" else f"user {name}"
        if any(
            "AgentRegistryFullAccess" in policy.get("name", "")
            for policy in [
                *(permissions.get("attached_policies") or []),
                *(permissions.get("group_policies") or []),
            ]
        ) and _granted_actions(permissions, REGISTRY_ACTIONS):
            full_access.append(label)
        if _has_registry_access(permissions, wildcard_only=True):
            wildcard.append(label)
    findings = []
    if full_access:
        findings.append(
            create_finding(
                "AR-01",
                "AWS Agent Registry IAM Full Access Policy",
                "The following principals have AWS Agent Registry full-access policies: "
                + ", ".join(sorted(full_access))
                + ". "
                + SCP_NOT_EVALUATED_NOTE,
                "Replace full-access policies with least-privilege AWS Agent Registry actions and scoped resources.",
                IAM_FULL_ACCESS_REFERENCE_URL,
                SeverityEnum.HIGH,
                StatusEnum.FAILED,
            )
        )
    if wildcard:
        findings.append(
            create_finding(
                "AR-01",
                "AWS Agent Registry IAM Wildcard Permissions",
                "The following principals have wildcard or allow-except AWS Agent Registry permissions on every resource, on a resource ARN with a wildcard that reaches beyond one named registry, or on a NotResource: "
                + ", ".join(sorted(wildcard))
                + ". "
                + SCP_NOT_EVALUATED_NOTE,
                "Replace wildcard permissions with required AWS Agent Registry actions and scoped resources.",
                IAM_FULL_ACCESS_REFERENCE_URL,
                SeverityEnum.HIGH,
                StatusEnum.FAILED,
            )
        )
    findings.extend(_merged_read_write_findings(identities))
    return _cache_completeness_findings(
        "AR-01",
        finding,
        IAM_FULL_ACCESS_REFERENCE_URL,
        permission_cache,
        findings
        or [
            create_finding(
                "AR-01",
                finding,
                f"None of the {len(identities)} cached roles and users has an "
                "AWS Agent Registry full-access policy, a wildcard or allow-except "
                "Registry grant on every resource, on a resource ARN with a "
                "wildcard that reaches beyond one named registry or on a "
                "NotResource, or a grant that "
                "merges Registry read and write actions on one resource type.",
                "No action required",
                IAM_FULL_ACCESS_REFERENCE_URL,
                SeverityEnum.HIGH,
                StatusEnum.PASSED,
            )
        ],
    )


def check_agent_registry_stale_access(
    permission_cache: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """AR-02: identify Registry-authorized principals without recent usage."""
    finding = "AWS Agent Registry Stale Access Check"
    roles = permission_cache.get("role_permissions", {})
    users = permission_cache.get("user_permissions", {})
    if not roles and not users:
        return [
            _na(
                "AR-02",
                finding,
                "No IAM permissions found in cache.",
                IAM_LAST_ACCESSED_REFERENCE_URL,
            )
        ]
    if iam_client is None:
        return [
            _na(
                "AR-02",
                f"{finding} Incomplete",
                "Assessment could not initialize the IAM client needed to query service-last-accessed data.",
                IAM_LAST_ACCESSED_REFERENCE_URL,
                "Resolve the IAM client initialization error and re-run the assessment.",
            )
        ]

    try:
        caller_identity = boto3.client("sts", config=boto3_config).get_caller_identity()
        account_id = caller_identity["Account"]
        partition = _caller_identity_partition(caller_identity)
    except Exception as error:
        return [
            _na(
                "AR-02",
                f"{finding} Incomplete",
                f"Assessment could not determine the account ID needed to query IAM service-last-accessed data: {_error_detail(error)}.",
                IAM_LAST_ACCESSED_REFERENCE_URL,
                (
                    "Verify that the assessment credentials are present and valid, "
                    "the regional STS endpoint is reachable, and GetCallerIdentity "
                    "returns an Account value. This operation does not require an IAM "
                    "Allow permission."
                ),
            )
        ]

    principals = []
    boundary_unread = _boundary_unread(permission_cache)
    for principal_type, entries, arn_prefix in (
        ("role", roles, "role"),
        ("user", users, "user"),
    ):
        for name, permissions in entries.items():
            if (principal_type, name) in boundary_unread and (
                permissions.get("permissions_boundary") is None
            ):
                continue
            if _has_registry_access(permissions, wildcard_only=False):
                principals.append(
                    {
                        "type": principal_type,
                        "name": name,
                        "arn": (
                            f"arn:{partition}:iam::{account_id}:{arn_prefix}/{name}"
                        ),
                    }
                )
    if not principals:
        return [
            _na(
                "AR-02",
                finding,
                "No IAM principals with AWS Agent Registry permissions found.",
                IAM_LAST_ACCESSED_REFERENCE_URL,
            )
        ]

    findings: List[Dict[str, Any]] = []
    stale_principals = []
    never_accessed_principals = []
    for principal_index, principal in enumerate(principals):
        if not check_timeout():
            findings.append(
                _na(
                    "AR-02",
                    f"{finding} Incomplete",
                    f"Stopped before assessing {len(principals) - principal_index} IAM principal(s) because the Lambda timeout was approaching.",
                    IAM_LAST_ACCESSED_REFERENCE_URL,
                    "Re-run the assessment to evaluate the remaining principals.",
                )
            )
            break

        try:
            job_id = iam_client.generate_service_last_accessed_details(
                Arn=principal["arn"]
            )["JobId"]
            deadline = time.monotonic() + 30
            while True:
                response = iam_client.get_service_last_accessed_details(JobId=job_id)
                job_status = response.get("JobStatus", "IN_PROGRESS")
                if job_status == "COMPLETED":
                    services = response.get("ServicesLastAccessed", [])
                    registry_services = [
                        service
                        for service in services
                        if REGISTRY_IAM_NAMESPACE
                        in (
                            f"{service.get('ServiceName', '')} "
                            f"{service.get('ServiceNamespace', '')}"
                        ).lower()
                    ]
                    last_authenticated = [
                        service.get("LastAuthenticated")
                        for service in registry_services
                        if service.get("LastAuthenticated")
                    ]
                    if not last_authenticated:
                        never_accessed_principals.append(principal)
                        break

                    access_dates = []
                    for value in last_authenticated:
                        if isinstance(value, datetime):
                            access_date = value
                        else:
                            access_date = datetime.fromisoformat(
                                str(value).replace("Z", "+00:00")
                            )
                        if access_date.tzinfo is None:
                            access_date = access_date.replace(tzinfo=timezone.utc)
                        access_dates.append(access_date)
                    days_since_access = (
                        datetime.now(timezone.utc) - max(access_dates)
                    ).days
                    if days_since_access > 60:
                        stale_principals.append(
                            {**principal, "days": days_since_access}
                        )
                    break
                if job_status == "FAILED":
                    findings.append(
                        _na(
                            "AR-02",
                            f"{finding} Incomplete",
                            f"IAM could not generate service-last-accessed details for {principal['type']} '{principal['name']}'.",
                            IAM_LAST_ACCESSED_REFERENCE_URL,
                            "Re-run the assessment or review IAM service-last-accessed details manually.",
                        )
                    )
                    break
                if not check_timeout() or time.monotonic() >= deadline:
                    findings.append(
                        _na(
                            "AR-02",
                            f"{finding} Incomplete",
                            f"IAM service-last-accessed details for {principal['type']} '{principal['name']}' did not complete before the assessment deadline.",
                            IAM_LAST_ACCESSED_REFERENCE_URL,
                            "Re-run the assessment or review IAM service-last-accessed details manually.",
                        )
                    )
                    break
                time.sleep(2)  # nosemgrep: bounded IAM asynchronous poll
        except Exception as error:
            findings.append(
                _na(
                    "AR-02",
                    f"{finding} Incomplete",
                    f"Could not inspect service-last-accessed data for {principal['type']} '{principal['name']}': {_error_detail(error)}.",
                    IAM_LAST_ACCESSED_REFERENCE_URL,
                    _error_resolution(
                        error,
                        "iam:GenerateServiceLastAccessedDetails and iam:GetServiceLastAccessedDetails",
                    ),
                )
            )

    if stale_principals:
        details = ", ".join(
            f"{item['type']} '{item['name']}' ({item['days']} days)"
            for item in stale_principals
        )
        findings.append(
            create_finding(
                "AR-02",
                "AWS Agent Registry Stale Access",
                "The following principals have not accessed AWS Agent Registry in 60+ days: "
                + details,
                "Review and remove unused AWS Agent Registry permissions following least privilege.",
                IAM_LAST_ACCESSED_REFERENCE_URL,
                SeverityEnum.MEDIUM,
                StatusEnum.FAILED,
            )
        )
    if never_accessed_principals:
        details = ", ".join(
            f"{item['type']} '{item['name']}'" for item in never_accessed_principals
        )
        findings.append(
            _na(
                "AR-02",
                "AWS Agent Registry Unused Permissions",
                "The following principals have AWS Agent Registry permissions but no service-last-accessed evidence: "
                + details,
                IAM_LAST_ACCESSED_REFERENCE_URL,
                "Review and remove unused AWS Agent Registry permissions following least privilege.",
            )
        )
    return _cache_completeness_findings(
        "AR-02",
        finding,
        IAM_LAST_ACCESSED_REFERENCE_URL,
        permission_cache,
        findings
        or [
            create_finding(
                "AR-02",
                finding,
                f"All {len(principals)} principals with AWS Agent Registry permissions accessed the service within the last 60 days.",
                "No action required",
                IAM_LAST_ACCESSED_REFERENCE_URL,
                SeverityEnum.LOW,
                StatusEnum.PASSED,
            )
        ],
    )


def _preview_support_ended() -> bool:
    """Whether the public-preview source and namespace have stopped working."""
    return datetime.now(timezone.utc).date() >= REGISTRY_PREVIEW_EVENT_SOURCE_END


def _qualified_registry_actions(local_name: str) -> tuple[str, ...]:
    """The namespace spellings of one Registry action that IAM still honours:
    both until the preview namespace is retired, then `agent-registry` alone."""
    namespaces = (
        (REGISTRY_IAM_NAMESPACE,)
        if _preview_support_ended()
        else REGISTRY_IAM_NAMESPACES
    )
    return tuple(f"{namespace}:{local_name}" for namespace in namespaces)


def _statement_denies_registry_action(statement: Dict[str, Any], action: str) -> bool:
    """Whether one Deny statement removes a Registry action account-wide.

    Read with the full action grammar, including NotAction, because a
    service-agnostic Deny does remove the action. A Deny scoped to one registry,
    or carrying a condition, is not an account-wide Deny and does not excuse the
    principal.
    """
    if statement.get("Condition"):
        return False
    if "*" not in _as_list(statement.get("Resource", [])):
        return False
    patterns = _as_list(statement.get("Action", []))
    if patterns:
        return any(fnmatchcase(action.lower(), pattern) for pattern in patterns)
    excluded = _as_list(statement.get("NotAction", []))
    return bool(excluded) and not any(
        fnmatchcase(action.lower(), pattern) for pattern in excluded
    )


def _registry_authority_actions(permissions: Dict[str, Any]) -> tuple[set, set]:
    """Return the Registry authority actions one principal is allowed, and those
    of them an account-wide Deny or the permissions boundary removes.

    Every Allow counts, a service-agnostic `*` or `*:*` and a NotAction among
    them, because each one grants the action.
    """
    watched = _qualified_registry_actions(REGISTRY_APPROVAL_ACTION) + tuple(
        action
        for local_name in REGISTRY_PUBLISH_ACTIONS
        for action in _qualified_registry_actions(local_name)
    )
    allowed = {
        action
        for action in watched
        for policy in _identity_policies(permissions)
        for statement in _policy_statements(policy)
        if statement.get("Effect") == "Allow" and _statement_matches(statement, action)
    }
    return allowed, allowed - _granted_actions(permissions, watched)


def _globs_intersect(first: str, second: str) -> bool:
    """Whether some string matches both IAM resource patterns, where `*` is any
    run of characters, `?` is one character, and both cross ARN segments."""
    seen = set()
    stack = [(0, 0)]
    while stack:
        i, j = stack.pop()
        if (i, j) in seen:
            continue
        seen.add((i, j))
        if i == len(first) and j == len(second):
            return True
        if i < len(first) and first[i] == "*":
            stack.append((i + 1, j))
            if j < len(second):
                stack.append((i, j + 1))
        if j < len(second) and second[j] == "*":
            stack.append((i, j + 1))
            if i < len(first):
                stack.append((i + 1, j))
        if (
            i < len(first)
            and j < len(second)
            and "*" not in (first[i], second[j])
            and (first[i] == second[j] or "?" in (first[i], second[j]))
        ):
            stack.append((i + 1, j + 1))
    return False


def _allow_scopes(
    permissions: Dict[str, Any], action: str
) -> List[tuple[List[str], bool]]:
    """The resource patterns and whether a Condition applies, for each Allow
    that grants ``action``.

    A NotResource Allow, or one naming no Resource, is read as every resource.
    The service segment of a Registry ARN is read in one namespace, because the
    preview spelling names the same registries.
    """
    scopes = []
    for policy in _identity_policies(permissions):
        for statement in _policy_statements(policy):
            if statement.get("Effect") != "Allow" or not _statement_matches(
                statement, action
            ):
                continue
            resources = (
                ["*"]
                if "NotResource" in statement
                else _as_list(statement.get("Resource")) or ["*"]
            )
            normalized = []
            for resource in resources:
                parts = resource.split(":", 5)
                if len(parts) == 6 and parts[2] in REGISTRY_IAM_NAMESPACES:
                    parts[2] = REGISTRY_IAM_NAMESPACE
                normalized.append(":".join(parts))
            scopes.append((normalized, bool(statement.get("Condition"))))
    return scopes


def _registry_approval_collisions(
    permissions_by_name: Dict[str, Any], principal_kind: str
) -> List[str]:
    """Return each principal that can publish a record and approve it as well.

    A publish Allow and an approval Allow collide only when their resource
    scopes overlap, so a curator of one registry who publishes to another is
    not reported. A wildcard overlaps every resource it can match. Conditions
    are not evaluated; a collision resting on a conditioned Allow says so.
    """
    approval_actions = set(_qualified_registry_actions(REGISTRY_APPROVAL_ACTION))
    labels = []
    for principal_name, permissions in permissions_by_name.items():
        allowed, denied = _registry_authority_actions(permissions)
        effective = allowed - denied
        approve_scopes = [
            scope
            for action in sorted(effective & approval_actions)
            for scope in _allow_scopes(permissions, action)
        ]
        publishes = []
        conditioned = False
        for action in sorted(effective - approval_actions):
            pairs = [
                (publish, approve)
                for publish in _allow_scopes(permissions, action)
                for approve in approve_scopes
                if any(_globs_intersect(p, a) for p in publish[0] for a in approve[0])
            ]
            if pairs:
                publishes.append(action)
                conditioned = conditioned or any(p[1] or a[1] for p, a in pairs)
        if publishes:
            labels.append(
                f"{principal_kind} '{principal_name}' ({', '.join(publishes)})"
                + (
                    " under an IAM condition this check does not evaluate"
                    if conditioned
                    else ""
                )
            )
    return sorted(labels)


def check_agent_registry_approval_separation(
    permission_cache: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """AR-09: find principals that can approve the records they publish.

    A record becomes discoverable only once UpdateRegistryRecordStatus sets it to
    APPROVED, so a principal holding that action beside a record write is the
    publisher and the curator of the same entry, and the review the registry's
    approval workflow exists to impose never happens.
    """
    finding = "AWS Agent Registry Approval Authority Separation"
    roles = permission_cache.get("role_permissions", {})
    users = permission_cache.get("user_permissions", {})
    if not roles and not users:
        return [
            _na(
                "AR-09",
                finding,
                "No IAM permissions found in cache.",
                APPROVAL_SEPARATION_REFERENCE_URL,
            )
        ]
    boundary_unread = _boundary_unread(permission_cache)
    collisions = [
        label
        for kind, entries in (("role", roles), ("user", users))
        for label in _registry_approval_collisions(
            {
                name: perms
                for name, perms in entries.items()
                if (kind, name) not in boundary_unread
                or perms.get("permissions_boundary") is not None
            },
            kind,
        )
    ]
    if collisions:
        findings = [
            create_finding(
                "AR-09",
                finding,
                SCP_NOT_EVALUATED_NOTE
                + " The following principals can both publish an AWS Agent Registry record and approve it, on resource scopes that overlap: "
                + ", ".join(collisions),
                f"Split the publisher and curator personas: leave {REGISTRY_IAM_NAMESPACE}:{REGISTRY_APPROVAL_ACTION} to the curator and remove it from principals that create, update, or submit records.",
                APPROVAL_SEPARATION_REFERENCE_URL,
                SeverityEnum.HIGH,
                StatusEnum.FAILED,
            )
        ]
    else:
        findings = [
            create_finding(
                "AR-09",
                finding,
                f"None of the {len(roles) + len(users)} cached IAM identities hold AWS Agent Registry record-publication and record-approval permissions on resource scopes that overlap.",
                "No action required",
                APPROVAL_SEPARATION_REFERENCE_URL,
                SeverityEnum.HIGH,
                StatusEnum.PASSED,
            )
        ]
    return _cache_completeness_findings(
        "AR-09", finding, APPROVAL_SEPARATION_REFERENCE_URL, permission_cache, findings
    )


def get_agent_registry_inventory(
    initialization_error: Optional[Exception] = None,
) -> Dict[str, Any]:
    """List registries once and isolate individual GetRegistry failures."""
    inventory = {
        "items": [],
        "errors": [],
        "list_error": initialization_error,
        "unavailable": False,
        "timed_out": False,
    }
    if agent_registry_control_client is None:
        inventory["unavailable"] = initialization_error is None
        return inventory
    try:
        paginator = agent_registry_control_client.get_paginator("list_registries")
        for page in paginator.paginate(
            PaginationConfig={"PageSize": REGISTRY_PAGE_SIZE}
        ):
            if not check_timeout():
                inventory["timed_out"] = True
                return inventory
            for summary in page.get("registries", []):
                registry_id = summary.get("registryId") or summary.get("registryArn")
                if not registry_id:
                    inventory["errors"].append(
                        (summary, ValueError("Missing registry ID"))
                    )
                    continue
                try:
                    detail = agent_registry_control_client.get_registry(
                        registryId=registry_id
                    )
                    inventory["items"].append({"summary": summary, "detail": detail})
                except Exception as error:
                    inventory["errors"].append((summary, error))
    except Exception as error:
        inventory["list_error"] = error
        inventory["unavailable"] = _is_unavailable(error)
    return inventory


def get_agent_registry_record_inventory(
    registry_inventory: Dict[str, Any],
) -> Dict[str, Any]:
    """List Registry records for every accessible registry, up to the safety cap."""
    inventory = {
        "items": [],
        "errors": [],
        "list_errors": [],
        "registry_inventory": registry_inventory,
        "timed_out": False,
        "truncated": False,
    }
    if registry_inventory.get("timed_out"):
        inventory["timed_out"] = True
        return inventory
    for registry in registry_inventory.get("items", []):
        detail, summary = registry["detail"], registry["summary"]
        registry_id = detail.get("registryId") or summary.get("registryId")
        try:
            paginator = agent_registry_control_client.get_paginator(
                "list_registry_records"
            )
            for page in paginator.paginate(registryId=registry_id):
                if not check_timeout():
                    inventory["timed_out"] = True
                    return inventory
                for record in page.get("registryRecords", []):
                    if len(inventory["items"]) >= RECORD_INVENTORY_LIMIT:
                        inventory["truncated"] = True
                        return inventory
                    inventory["items"].append(
                        {"registry": registry, "summary": record, "detail": record}
                    )
        except Exception as error:
            inventory["list_errors"].append((registry, error))
    return inventory


def _registry_context(item: Dict[str, Any]) -> tuple[str, str, str]:
    detail, summary = item["detail"], item["summary"]
    return (
        detail.get("registryId") or summary.get("registryId") or "unknown",
        detail.get("name") or summary.get("name") or "unknown",
        detail.get("status") or summary.get("status") or "unknown",
    )


def _inventory_start(
    inventory: Dict[str, Any], check_id: str, finding: str, reference: str
) -> Optional[List[Dict[str, Any]]]:
    if inventory.get("unavailable"):
        return [
            _na(
                check_id,
                finding,
                "AWS Agent Registry is not available in this region.",
                reference,
                "No action required unless AWS Agent Registry is expected.",
            )
        ]
    if inventory.get("list_error"):
        error = inventory["list_error"]
        return [
            _na(
                check_id,
                f"{finding} Incomplete",
                f"Assessment could not enumerate AWS Agent Registry registries: {_error_detail(error)}.",
                reference,
                _error_resolution(error, "agent-registry:ListRegistries"),
            )
        ]
    if inventory.get("timed_out"):
        return [
            _na(
                check_id,
                f"{finding} Incomplete",
                "Assessment stopped before the Registry inventory was complete because the Lambda timeout was approaching.",
                reference,
                "Re-run the assessment to complete the Registry inventory.",
            )
        ]
    if not inventory.get("items") and not inventory.get("errors"):
        return [
            _na(check_id, finding, "No AWS Agent Registry registries found.", reference)
        ]
    return None


def _registry_errors(
    inventory: Dict[str, Any], check_id: str, finding: str, reference: str
) -> List[Dict[str, Any]]:
    return [
        _na(
            check_id,
            f"{finding} Incomplete",
            f"Registry '{summary.get('name', summary.get('registryId', 'unknown'))}' could not be read: {_error_detail(error)}.",
            reference,
            _error_resolution(error, "agent-registry:GetRegistry"),
        )
        for summary, error in inventory.get("errors", [])
    ]


def check_agent_registry_approval_governance(
    inventory: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """AR-03: fail a Registry that approves submitted records automatically.

    GetRegistry documents that submitted records require manual review when
    ``autoApprovalRules`` is omitted or empty, so a registry that returns no
    ``approvalConfiguration`` at all reviews manually as well.
    """
    inventory = inventory or get_agent_registry_inventory()
    finding = "AWS Agent Registry Publication Approval Governance"
    early = _inventory_start(inventory, "AR-03", finding, APPROVAL_REFERENCE_URL)
    if early:
        return early
    findings = _registry_errors(inventory, "AR-03", finding, APPROVAL_REFERENCE_URL)
    for item in inventory["items"]:
        registry_id, name, status = _registry_context(item)
        if status != "READY":
            findings.append(
                _na(
                    "AR-03",
                    finding,
                    f"Registry '{name}' ({registry_id}) is {status}; approval governance could not be assessed.",
                    APPROVAL_REFERENCE_URL,
                    "Retry after the registry reaches READY state.",
                )
            )
            continue
        rules = (item["detail"].get("approvalConfiguration") or {}).get(
            "autoApprovalRules"
        )
        if rules:
            findings.append(
                create_finding(
                    "AR-03",
                    finding,
                    f"Registry '{name}' ({registry_id}) automatically approves submitted records (autoApprovalRules: {', '.join(map(str, rules))}).",
                    "Remove auto-approval rules so submitted records require manual review.",
                    APPROVAL_REFERENCE_URL,
                    SeverityEnum.MEDIUM,
                    StatusEnum.FAILED,
                )
            )
        else:
            findings.append(
                create_finding(
                    "AR-03",
                    finding,
                    f"Registry '{name}' ({registry_id}) requires manual review for submitted records: it returns no auto-approval rules.",
                    "No action required",
                    APPROVAL_REFERENCE_URL,
                    SeverityEnum.MEDIUM,
                    StatusEnum.PASSED,
                )
            )
    return findings


def check_agent_registry_discovery_authorization(
    inventory: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """AR-04: assess discovery authorization configuration."""
    inventory = inventory or get_agent_registry_inventory()
    finding = "AWS Agent Registry Discovery Authorization"
    early = _inventory_start(inventory, "AR-04", finding, AUTHORIZATION_REFERENCE_URL)
    if early:
        return early
    findings = _registry_errors(
        inventory, "AR-04", finding, AUTHORIZATION_REFERENCE_URL
    )
    for item in inventory["items"]:
        registry_id, name, status = _registry_context(item)
        if status != "READY":
            findings.append(
                _na(
                    "AR-04",
                    finding,
                    f"Registry '{name}' ({registry_id}) is {status}; discovery authorization could not be assessed.",
                    AUTHORIZATION_REFERENCE_URL,
                    "Retry after the registry reaches READY state.",
                )
            )
            continue
        if "discoveryConfiguration" not in item["detail"]:
            findings.append(
                _na(
                    "AR-04",
                    finding,
                    f"Registry '{name}' ({registry_id}) did not return optional discovery authorization metadata.",
                    AUTHORIZATION_REFERENCE_URL,
                    "No action required. Retry after the service returns discovery authorization metadata.",
                )
            )
            continue
        discovery = item["detail"].get("discoveryConfiguration")
        if not isinstance(discovery, dict) or "authorizerType" not in discovery:
            findings.append(
                _na(
                    "AR-04",
                    finding,
                    f"Registry '{name}' ({registry_id}) did not return a discovery authorizer type.",
                    AUTHORIZATION_REFERENCE_URL,
                    "No action required. Retry after the service returns discovery authorization metadata.",
                )
            )
            continue
        auth_type = discovery.get("authorizerType")
        if auth_type == "CUSTOM_JWT":
            jwt = (discovery.get("authorizerConfiguration") or {}).get(
                "customJWTAuthorizer"
            ) or {}
            constrained = bool(jwt.get("discoveryUrl")) and any(
                jwt.get(key)
                for key in (
                    "allowedAudience",
                    "allowedClients",
                    "allowedScopes",
                    "customClaims",
                )
            )
            if not constrained:
                findings.append(
                    create_finding(
                        "AR-04",
                        finding,
                        f"Registry '{name}' ({registry_id}) uses a custom JWT authorizer without both issuer discovery and a caller constraint.",
                        "Configure an OpenID Connect discovery URL and at least one allowed audience, client, scope, or custom claim.",
                        AUTHORIZATION_REFERENCE_URL,
                        SeverityEnum.HIGH,
                        StatusEnum.FAILED,
                    )
                )
                continue
        if auth_type == "AWS_IAM":
            details = (
                f"Registry '{name}' ({registry_id}) uses AWS IAM authorization; "
                "effective principals require policy review."
            )
        elif auth_type == "CUSTOM_JWT":
            details = (
                f"Registry '{name}' ({registry_id}) uses a constrained custom JWT "
                "authorizer; approved caller values require review."
            )
        else:
            details = (
                f"Registry '{name}' ({registry_id}) returned unsupported discovery "
                f"authorizer type '{auth_type}'; authorization could not be assessed."
            )
        findings.append(
            _na(
                "AR-04",
                finding,
                details,
                AUTHORIZATION_REFERENCE_URL,
                "Review effective IAM access or approved JWT caller constraints.",
            )
        )
    return findings


def check_agent_registry_cmk_encryption(
    inventory: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """AR-05: report or require customer-managed Registry encryption."""
    inventory = inventory or get_agent_registry_inventory()
    finding = "AWS Agent Registry Customer-Managed KMS Encryption"
    early = _inventory_start(inventory, "AR-05", finding, ENCRYPTION_REFERENCE_URL)
    if early:
        return early
    required = os.environ.get("REQUIRE_AGENT_REGISTRY_CMK", "").lower() in {
        "true",
        "1",
        "yes",
    }
    findings = _registry_errors(inventory, "AR-05", finding, ENCRYPTION_REFERENCE_URL)
    for item in inventory["items"]:
        registry_id, name, status = _registry_context(item)
        if status != "READY":
            findings.append(
                _na(
                    "AR-05",
                    finding,
                    f"Registry '{name}' ({registry_id}) is {status}; encryption could not be assessed.",
                    ENCRYPTION_REFERENCE_URL,
                    "Retry after the registry reaches READY state.",
                )
            )
            continue
        if (item["detail"].get("encryptionConfiguration") or {}).get("kmsKeyArn"):
            findings.append(
                create_finding(
                    "AR-05",
                    finding,
                    f"Registry '{name}' ({registry_id}) uses a customer-managed KMS key for encryption at rest.",
                    "No action required",
                    ENCRYPTION_REFERENCE_URL,
                    SeverityEnum.MEDIUM,
                    StatusEnum.PASSED,
                )
            )
        else:
            findings.append(
                create_finding(
                    "AR-05",
                    finding,
                    f"Registry '{name}' ({registry_id}) uses the default AWS owned key for encryption at rest.",
                    "Create a replacement registry with a customer-managed KMS key and migrate records."
                    if required
                    else "No action required under the current baseline. Set REQUIRE_AGENT_REGISTRY_CMK=true to require a customer-managed KMS key.",
                    ENCRYPTION_REFERENCE_URL,
                    SeverityEnum.MEDIUM if required else SeverityEnum.INFORMATIONAL,
                    StatusEnum.FAILED if required else StatusEnum.NA,
                )
            )
    return findings


def check_agent_registry_auto_detection(
    inventory: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """AR-06: report Registry organization auto-detection health."""
    inventory = inventory or get_agent_registry_inventory()
    finding = "AWS Agent Registry Organization Auto-Detection"
    early = _inventory_start(inventory, "AR-06", finding, AUTO_DETECTION_REFERENCE_URL)
    if early:
        return early
    findings = _registry_errors(
        inventory, "AR-06", finding, AUTO_DETECTION_REFERENCE_URL
    )
    for item in inventory["items"]:
        registry_id, name, status = _registry_context(item)
        if status != "READY":
            findings.append(
                _na(
                    "AR-06",
                    finding,
                    f"Registry '{name}' ({registry_id}) is {status}; auto-detection could not be assessed.",
                    AUTO_DETECTION_REFERENCE_URL,
                    "Retry after the registry reaches READY state.",
                )
            )
            continue
        auto_detection = item["detail"].get("autoDetection")
        if not isinstance(auto_detection, dict):
            findings.append(
                _na(
                    "AR-06",
                    finding,
                    f"Registry '{name}' ({registry_id}) did not return optional auto-detection metadata.",
                    AUTO_DETECTION_REFERENCE_URL,
                    "No action required. Retry after the service returns auto-detection metadata.",
                )
            )
            continue
        config = auto_detection.get("configuration")
        auto_status = auto_detection.get("status")
        if (
            not isinstance(config, dict)
            or any(key not in config for key in ("enabled", "scope"))
            or auto_status is None
        ):
            findings.append(
                _na(
                    "AR-06",
                    finding,
                    f"Registry '{name}' ({registry_id}) returned incomplete auto-detection metadata.",
                    AUTO_DETECTION_REFERENCE_URL,
                    "No action required. Retry after the service returns auto-detection metadata.",
                )
            )
        elif (
            config.get("enabled")
            and config.get("scope") == "ORGANIZATION"
            and auto_status == "ACTIVE"
        ):
            findings.append(
                create_finding(
                    "AR-06",
                    finding,
                    f"Registry '{name}' ({registry_id}) has active organization-scoped auto-detection.",
                    "No action required",
                    AUTO_DETECTION_REFERENCE_URL,
                    SeverityEnum.MEDIUM,
                    StatusEnum.PASSED,
                )
            )
        else:
            findings.append(
                _na(
                    "AR-06",
                    finding,
                    f"Registry '{name}' ({registry_id}) has auto-detection configured as enabled={config.get('enabled')}, scope={config.get('scope')}, status={auto_status}.",
                    AUTO_DETECTION_REFERENCE_URL,
                    "Enable organization-scoped auto-detection when centralized discovery is required.",
                )
            )
    return findings


def _record_start(
    record_inventory: Dict[str, Any], check_id: str, finding: str, reference: str
) -> Optional[List[Dict[str, Any]]]:
    parent = record_inventory["registry_inventory"]
    early = _inventory_start(parent, check_id, finding, reference)
    if early:
        return early
    if not record_inventory["items"] and not record_inventory["list_errors"]:
        return [
            _na(check_id, finding, "No AWS Agent Registry records found.", reference)
        ]
    return None


def _record_inventory_notices(
    record_inventory: Dict[str, Any], check_id: str, finding: str, reference: str
) -> List[Dict[str, Any]]:
    """Return partial-inventory notices without discarding collected records."""
    notices = []
    if record_inventory.get("timed_out"):
        notices.append(
            _na(
                check_id,
                f"{finding} Incomplete",
                "Registry record inventory was incomplete because the Lambda timeout was approaching.",
                reference,
                "Re-run the assessment to complete the Registry record inventory.",
            )
        )
    if record_inventory.get("truncated"):
        notices.append(
            _na(
                check_id,
                f"{finding} Incomplete",
                f"Registry record inventory reached the {RECORD_INVENTORY_LIMIT}-record safety limit; collected records were assessed but additional records may exist.",
                reference,
                "Re-run the assessment with a higher inventory limit or a narrower scope to assess remaining records.",
            )
        )
    return notices


def _record_list_error_findings(
    record_inventory: Dict[str, Any], check_id: str, finding: str, reference: str
) -> List[Dict[str, Any]]:
    return [
        _na(
            check_id,
            f"{finding} Incomplete",
            f"Could not list records for registry '{registry['summary'].get('name', 'unknown')}': {_error_detail(error)}.",
            reference,
            _error_resolution(error, "agent-registry:ListRegistryRecords"),
        )
        for registry, error in record_inventory["list_errors"]
    ]


def check_agent_registry_record_lifecycle(
    record_inventory: Optional[Dict[str, Any]] = None,
    registry_inventory: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """AR-07: emit advisory observations for Registry record lifecycle states."""
    registry_inventory = registry_inventory or get_agent_registry_inventory()
    record_inventory = record_inventory or get_agent_registry_record_inventory(
        registry_inventory
    )
    finding = "AWS Agent Registry Record Lifecycle Governance"
    early = _record_start(
        record_inventory, "AR-07", finding, RECORD_LIFECYCLE_REFERENCE_URL
    )
    if early:
        return early
    findings = _record_inventory_notices(
        record_inventory, "AR-07", finding, RECORD_LIFECYCLE_REFERENCE_URL
    ) + _record_list_error_findings(
        record_inventory, "AR-07", finding, RECORD_LIFECYCLE_REFERENCE_URL
    )
    for item in record_inventory["items"]:
        record = item["detail"]
        findings.append(
            _na(
                "AR-07",
                finding,
                f"Registry record '{record.get('displayName') or record.get('name') or record.get('recordId', 'unknown')}' is in lifecycle state {record.get('status', 'unknown')}.",
                RECORD_LIFECYCLE_REFERENCE_URL,
                "Review failed or unknown lifecycle states operationally.",
            )
        )
    return findings


PROVENANCE_RESOURCE_PREFIXES = {
    "AWS::BedrockAgentCore::Runtime": "runtime/",
    "AWS::BedrockAgentCore::Gateway": "gateway/",
}


def _source_id_matches_provenance_type(
    source_id: Any, source_type: Any
) -> Optional[bool]:
    """Validate the AgentCore ARN carried in a ProvenanceSummary sourceId."""
    if source_type is None:
        return None

    expected_prefix = PROVENANCE_RESOURCE_PREFIXES.get(source_type)
    if expected_prefix is None or not isinstance(source_id, str):
        return False

    arn_parts = source_id.split(":", 5)
    if len(arn_parts) != 6:
        return False

    arn_label, partition, service, region, account_id, resource = arn_parts
    if (
        arn_label != "arn"
        or not re.fullmatch(r"aws(?:-[a-z0-9-]+)*", partition)
        or service != "bedrock-agentcore"
        or not re.fullmatch(r"[a-z0-9-]+", region)
        or not re.fullmatch(r"[0-9]{12}", account_id)
        or not resource.startswith(expected_prefix)
    ):
        return False

    resource_id = resource[len(expected_prefix) :]
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]*", resource_id))


def _valid_provenance(provenance: Any) -> Optional[bool]:
    """Return valid, invalid, or indeterminate auto-detected provenance."""
    if not isinstance(provenance, list) or not provenance:
        return None

    missing_source_type = False
    invalid_provenance = False
    for item in provenance:
        if not isinstance(item, dict) or item.get("relation") != "DETECTED_FROM":
            continue
        source_matches = _source_id_matches_provenance_type(
            item.get("sourceId"), item.get("sourceType")
        )
        if source_matches is True:
            return True
        if source_matches is None:
            missing_source_type = True
        else:
            invalid_provenance = True

    if invalid_provenance:
        return False
    return None if missing_source_type else False


def check_agent_registry_record_provenance(
    record_inventory: Optional[Dict[str, Any]] = None,
    registry_inventory: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """AR-08: assess manual creator attribution and auto-detected provenance."""
    registry_inventory = registry_inventory or get_agent_registry_inventory()
    record_inventory = record_inventory or get_agent_registry_record_inventory(
        registry_inventory
    )
    finding = "AWS Agent Registry Record Provenance"
    early = _record_start(record_inventory, "AR-08", finding, PROVENANCE_REFERENCE_URL)
    if early:
        return early
    findings = _record_inventory_notices(
        record_inventory, "AR-08", finding, PROVENANCE_REFERENCE_URL
    ) + _record_list_error_findings(
        record_inventory, "AR-08", finding, PROVENANCE_REFERENCE_URL
    )
    for item in record_inventory["items"]:
        record = item["detail"]
        name = (
            record.get("displayName")
            or record.get("name")
            or record.get("recordId", "unknown")
        )
        auto_detected = record.get("createdByAutoDetection")
        if auto_detected is None:
            findings.append(
                _na(
                    "AR-08",
                    finding,
                    f"Registry record '{name}' did not return optional origin-mode metadata.",
                    PROVENANCE_REFERENCE_URL,
                    "No action required. Retry after the service returns origin-mode metadata.",
                )
            )
        elif auto_detected is True:
            valid = _valid_provenance(record.get("provenanceSummaryList"))
            if valid is None:
                findings.append(
                    _na(
                        "AR-08",
                        finding,
                        f"Auto-detected registry record '{name}' did not return optional provenance metadata.",
                        PROVENANCE_REFERENCE_URL,
                        "No action required. Retry after the service returns provenance metadata.",
                    )
                )
            else:
                findings.append(
                    create_finding(
                        "AR-08",
                        finding,
                        f"Auto-detected registry record '{name}' {'has' if valid else 'does not have'} valid DETECTED_FROM provenance for an AgentCore runtime or gateway.",
                        "No action required"
                        if valid
                        else "Refresh or recreate the auto-detected record so source lineage is preserved.",
                        PROVENANCE_REFERENCE_URL,
                        SeverityEnum.MEDIUM,
                        StatusEnum.PASSED if valid else StatusEnum.FAILED,
                    )
                )
        elif auto_detected is False and re.fullmatch(
            r"[0-9]{12}", str(record.get("createdBy") or "")
        ):
            findings.append(
                create_finding(
                    "AR-08",
                    finding,
                    f"Manually created registry record '{name}' retains creator account attribution.",
                    "No action required",
                    PROVENANCE_REFERENCE_URL,
                    SeverityEnum.MEDIUM,
                    StatusEnum.PASSED,
                )
            )
        elif auto_detected is False and not record.get("createdBy"):
            findings.append(
                _na(
                    "AR-08",
                    finding,
                    f"Manually created registry record '{name}' did not return optional creator account attribution.",
                    PROVENANCE_REFERENCE_URL,
                    "No action required. Retry after the service returns creator metadata.",
                )
            )
        else:
            findings.append(
                create_finding(
                    "AR-08",
                    finding,
                    f"Registry record '{name}' does not include valid creator or auto-detection provenance metadata.",
                    "Refresh or recreate the record through an attributable source.",
                    PROVENANCE_REFERENCE_URL,
                    SeverityEnum.MEDIUM,
                    StatusEnum.FAILED,
                )
            )
    return findings


def _wildcard_matches(pattern: str, value: str) -> bool:
    """EventBridge `wildcard`: `*` matches any run of characters, `\\*` is a
    literal asterisk, and the comparison is case-sensitive.

    Segments are matched left to right with str.find, so a pattern with many
    asterisks costs one pass over the value and cannot backtrack.
    """
    segments = [""]
    index = 0
    while index < len(pattern):
        if pattern[index] == "\\" and index + 1 < len(pattern):
            segments[-1] += pattern[index + 1]
            index += 2
            continue
        if pattern[index] == "*":
            segments.append("")
        else:
            segments[-1] += pattern[index]
        index += 1
    if len(segments) == 1:
        return value == segments[0]
    head, middle, tail = segments[0], segments[1:-1], segments[-1]
    if len(value) < len(head) + len(tail) or not value.startswith(head):
        return False
    position, end = len(head), len(value) - len(tail)
    for segment in middle:
        found = value.find(segment, position, end)
        if found < 0:
            return False
        position = found + len(segment)
    return value.endswith(tail)


def _matcher_matches(matcher: Any, value: str) -> Optional[bool]:
    """Whether one element of an event pattern's value list matches a string.

    None means the element has a shape this check does not evaluate, so its
    reach is undecided, neither a match nor a miss.
    """
    if isinstance(matcher, str):
        return matcher == value
    if not isinstance(matcher, dict):
        # A number, boolean or null matches only a value of its own type.
        return False
    if len(matcher) != 1:
        return None
    operator, operand = next(iter(matcher.items()))
    if operator in ("prefix", "suffix"):
        compare = str.startswith if operator == "prefix" else str.endswith
        if isinstance(operand, str):
            return compare(value, operand)
        if (
            isinstance(operand, dict)
            and list(operand) == ["equals-ignore-case"]
            and isinstance(operand["equals-ignore-case"], str)
        ):
            return compare(value.lower(), operand["equals-ignore-case"].lower())
        return None
    if operator == "equals-ignore-case":
        return value.lower() == operand.lower() if isinstance(operand, str) else None
    if operator == "wildcard":
        return _wildcard_matches(operand, value) if isinstance(operand, str) else None
    if operator == "exists":
        return operand if isinstance(operand, bool) else None
    if operator in ("numeric", "cidr"):
        # Neither matches a string value.
        return False
    if operator != "anything-but":
        return None
    if isinstance(operand, dict):
        if len(operand) != 1:
            return None
        inner, inner_operand = next(iter(operand.items()))
        if inner not in ("prefix", "suffix", "equals-ignore-case", "wildcard"):
            return None
        items = inner_operand if isinstance(inner_operand, list) else [inner_operand]
        results = [_matcher_matches({inner: item}, value) for item in items]
    else:
        items = operand if isinstance(operand, list) else [operand]
        if any(isinstance(item, (dict, list)) for item in items):
            return None
        results = [item == value for item in items]
    if not results or None in results:
        return None
    return not any(results)


def _event_pattern_reach(
    pattern: Dict[str, Any], key: str, candidates: Iterable[str]
) -> Optional[tuple]:
    """Which candidate values one top-level event pattern field matches.

    None means the field is absent, which in EventBridge matches every value.
    Otherwise returns (matched, undecided): the candidates a literal or a content
    matcher in the field's list matches, and those no element matches but an
    element this check does not evaluate might. An empty list leaves every
    candidate undecided.
    """
    if key not in pattern:
        return None
    value = pattern[key]
    elements = value if isinstance(value, list) else [value]
    matched, undecided = set(), set()
    for candidate in candidates:
        results = [_matcher_matches(element, candidate) for element in elements]
        if True in results:
            matched.add(candidate)
        elif None in results or not results:
            undecided.add(candidate)
    return matched, undecided


def _classify_event_pattern(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Read one rule's event pattern for Registry source and detail-type reach.

    `kind` is `other` when the rule cannot receive Registry events, `registry`
    when it matches the GA source, `preview` when it matches only the
    discontinued public-preview source, and `unreadable` when the pattern is not
    a JSON object, has a top-level `$or` branch this check cannot decide, or
    carries a matcher this check does not evaluate on the source or the detail
    type. Prefix, suffix, wildcard, equals-ignore-case and anything-but matchers
    are evaluated against the known source and detail type values.
    """
    raw_pattern = rule.get("EventPattern")
    if not raw_pattern:
        return {"kind": "other"}
    try:
        pattern = json.loads(raw_pattern)
    except (TypeError, ValueError):
        return {"kind": "unreadable", "reason": "its event pattern is not valid JSON"}
    if not isinstance(pattern, dict):
        return {
            "kind": "unreadable",
            "reason": "its event pattern is not a JSON object",
        }
    return _classify_pattern(pattern, rule)


def _classify_or_pattern(
    pattern: Dict[str, Any], rule: Dict[str, Any]
) -> Dict[str, Any]:
    """Classify a top-level `$or` as each branch merged with the sibling keys.

    The rule is `other` when no branch can receive Registry events and
    `unreadable` when any branch cannot be decided. Otherwise it takes the
    detail types and narrowing fields of every branch of its kind, so one
    narrowed branch keeps the whole rule from being credited.
    """
    branches = pattern["$or"]
    siblings = {key: value for key, value in pattern.items() if key != "$or"}
    if not isinstance(branches, list) or not branches:
        return {
            "kind": "unreadable",
            "reason": "its $or is not a list of alternatives",
        }
    results = []
    for branch in branches:
        if not isinstance(branch, dict) or set(branch) & set(siblings):
            return {
                "kind": "unreadable",
                "reason": "an $or alternative is not an object or repeats a field outside the $or",
            }
        results.append(_classify_pattern({**siblings, **branch}, rule))
    for result in results:
        if result["kind"] == "unreadable":
            return result
    kind = next(
        (k for k in ("registry", "preview") if any(r["kind"] == k for r in results)),
        "other",
    )
    if kind == "other":
        return {"kind": "other"}
    same_kind = [result for result in results if result["kind"] == kind]
    return {
        "kind": kind,
        "detail_types": set().union(*(r["detail_types"] for r in same_kind)),
        "narrowed_by": sorted(set().union(*(r["narrowed_by"] for r in same_kind))),
    }


def _classify_pattern(pattern: Dict[str, Any], rule: Dict[str, Any]) -> Dict[str, Any]:
    if "$or" in pattern:
        return _classify_or_pattern(pattern, rule)
    sources = _event_pattern_reach(
        pattern, "source", (REGISTRY_EVENT_SOURCE, REGISTRY_PREVIEW_EVENT_SOURCE)
    )
    matched_sources, undecided_sources = sources or (set(), set())
    matches_ga = sources is None or REGISTRY_EVENT_SOURCE in matched_sources
    matches_preview = REGISTRY_PREVIEW_EVENT_SOURCE in matched_sources
    # The preview source only decides the kind when the GA source is not matched.
    if REGISTRY_EVENT_SOURCE in undecided_sources or (
        not matches_ga and undecided_sources
    ):
        return {
            "kind": "unreadable",
            "reason": "a content filter decides which event sources it matches",
        }
    if not matches_ga and not matches_preview:
        return {"kind": "other"}
    reach = _event_pattern_reach(
        pattern, "detail-type", REGISTRY_LIFECYCLE_DETAIL_TYPES
    )
    # Only the approval transitions enter the verdict, so an undecided match on
    # another lifecycle type is left out of the set without blocking it.
    if reach is not None and reach[1] & set(REGISTRY_APPROVAL_DETAIL_TYPES):
        return {
            "kind": "unreadable",
            "reason": "a content filter decides which detail types it matches",
        }
    detail_types = None if reach is None else reach[0]
    # A pattern with no source filter matches the GA source, but one whose
    # detail-type filter reaches no Registry type still receives no Registry event.
    if reach is not None and not reach[0] and not reach[1]:
        return {"kind": "other"}
    if (
        not matches_ga
        and detail_types is not None
        and not set(detail_types) & set(REGISTRY_APPROVAL_DETAIL_TYPES)
    ):
        return {"kind": "other"}
    return {
        "kind": "registry" if matches_ga else "preview",
        "detail_types": set(REGISTRY_LIFECYCLE_DETAIL_TYPES)
        if detail_types is None
        else set(detail_types),
        "narrowed_by": sorted(
            field
            for field in pattern
            if field not in ("source", "detail-type")
            and not _matches_own_scope(pattern, field, rule)
        ),
    }


def _matches_own_scope(
    pattern: Dict[str, Any], field: str, rule: Dict[str, Any]
) -> bool:
    """Whether an `account` or `region` filter matches the rule's own account or
    Region, which every Registry event this check judges carries.

    Any other field, and an own value that no element decidedly matches, narrows.
    """
    rule_parts = str(rule.get("Arn", "")).split(":", 5)
    if len(rule_parts) != 6:
        return False
    own = {"region": rule_parts[3], "account": rule_parts[4]}.get(field)
    if not own:
        return False
    matched, _ = _event_pattern_reach(pattern, field, (own,))
    return own in matched


def _event_bus_target(
    rule: Dict[str, Any], target_arn: str
) -> Optional[Dict[str, Any]]:
    """Read a target ARN as an event bus, or None when it is any other target.

    `local` is True when the bus is in the rule's own partition, account and
    Region, which is the only case where this function's credentials can list
    the rules that receive the forwarded events.
    """
    parts = target_arn.split(":", 5)
    if len(parts) != 6 or parts[2] != "events" or not parts[5].startswith("event-bus/"):
        return None
    rule_parts = str(rule.get("Arn", "")).split(":", 5)
    return {
        "arn": target_arn,
        "name": parts[5][len("event-bus/") :],
        "local": len(rule_parts) == 6 and rule_parts[1:5] == parts[1:5],
    }


def _is_review_pipeline(target_arn: str) -> bool:
    parts = target_arn.split(":", 5)
    return len(parts) == 6 and parts[2] in REVIEW_PIPELINE_SERVICES


def _rule_targets(
    rule: Dict[str, Any], bus_name: str
) -> tuple[Optional[int], List[Dict[str, Any]], List[str], Optional[Exception]]:
    """Count one rule's targets and read which of them are event buses and
    which are review pipelines.

    Isolates a per-rule failure from the sweep.
    """
    rule_name = rule.get("Name")
    if not rule_name:
        return None, [], [], ValueError("Missing rule name")
    try:
        paginator = events_client.get_paginator("list_targets_by_rule")
        targets = 0
        buses = []
        pipelines = []
        for page in paginator.paginate(Rule=rule_name, EventBusName=bus_name):
            for target in page.get("Targets", []):
                targets += 1
                arn = target.get("Arn", "")
                bus = _event_bus_target(rule, arn)
                if bus is not None:
                    buses.append(bus)
                elif _is_review_pipeline(arn):
                    pipelines.append(arn)
        return targets, buses, pipelines, None
    except Exception as error:
        return None, [], [], error


def _registry_rule_entries(bus_name: str, inventory: Dict[str, Any]) -> tuple:
    """List one bus's rules and read the targets of those matching Registry events.

    Returns the entries and the number of rules examined, or sets `timed_out` on
    the inventory and returns what was read. A listing failure propagates.
    """
    entries = []
    examined = 0
    paginator = events_client.get_paginator("list_rules")
    for page in paginator.paginate(EventBusName=bus_name):
        if not check_timeout():
            inventory["timed_out"] = True
            return entries, examined
        for rule in page.get("Rules", []):
            examined += 1
            classification = _classify_event_pattern(rule)
            if classification["kind"] == "other":
                continue
            entry = {
                "rule": rule,
                "classification": classification,
                "targets": None,
                "bus_targets": [],
                "pipeline_targets": [],
                "target_error": None,
            }
            if classification["kind"] != "unreadable":
                (
                    entry["targets"],
                    entry["bus_targets"],
                    entry["pipeline_targets"],
                    entry["target_error"],
                ) = _rule_targets(rule, bus_name)
            entries.append(entry)
    return entries, examined


def _could_credit(entry: Dict[str, Any]) -> bool:
    """Whether a rule whose targets could not be read would be credited if they
    reached a review pipeline: an enabled GA-source rule with no narrowing."""
    return (
        entry["classification"]["kind"] == "registry"
        and not entry["classification"]["narrowed_by"]
        and entry["rule"].get("State") != "DISABLED"
    )


def _forwards_only(entry: Dict[str, Any]) -> bool:
    """Whether an enabled, unfiltered GA-source rule reaches a review pipeline,
    if at all, only through the event buses it targets."""
    return (
        entry["classification"]["kind"] == "registry"
        and not entry["classification"]["narrowed_by"]
        and entry["rule"].get("State") != "DISABLED"
        and bool(entry["bus_targets"])
        and not entry.get("pipeline_targets")
    )


def get_registry_event_rule_inventory() -> Dict[str, Any]:
    """List the default bus once and count the targets of the Registry rules.

    Targets are listed only for the rules whose pattern can receive Registry
    events, so an account with hundreds of unrelated rules costs one ListRules
    sweep rather than a ListTargetsByRule call per rule. A matching rule whose
    only targets are event buses in this account and Region is followed one hop:
    that bus's rules are read the same way. One hop is enough because a
    forwarded event keeps its source and detail type, and stopping there means a
    bus-to-bus cycle cannot loop the sweep.
    """
    inventory = {
        "items": [],
        "rules_examined": 0,
        "forwarded_buses": {},
        "list_error": None,
        "client_missing": events_client is None,
        "unavailable": False,
        "timed_out": False,
    }
    if events_client is None:
        return inventory
    try:
        inventory["items"], inventory["rules_examined"] = _registry_rule_entries(
            REGISTRY_EVENT_BUS_NAME, inventory
        )
    except Exception as error:
        inventory["list_error"] = error
        inventory["unavailable"] = _is_unavailable(error)
        return inventory
    for entry in inventory["items"]:
        if not _forwards_only(entry):
            continue
        for bus in entry["bus_targets"]:
            if inventory["timed_out"]:
                return inventory
            if not bus["local"] or bus["name"] in inventory["forwarded_buses"]:
                continue
            forwarded = {"items": [], "list_error": None}
            try:
                forwarded["items"], _ = _registry_rule_entries(bus["name"], inventory)
            except Exception as error:
                forwarded["list_error"] = error
            inventory["forwarded_buses"][bus["name"]] = forwarded
    return inventory


def _event_rule_inventory_start(
    rule_inventory: Dict[str, Any], finding: str
) -> Optional[List[Dict[str, Any]]]:
    if rule_inventory.get("client_missing"):
        return [
            _na(
                "AR-10",
                f"{finding} Incomplete",
                "Assessment could not initialize the EventBridge client needed to read event rules.",
                EVENT_ROUTING_REFERENCE_URL,
                "Resolve the EventBridge client initialization error and re-run the assessment.",
            )
        ]
    if rule_inventory.get("unavailable"):
        return [
            _na(
                "AR-10",
                finding,
                "Amazon EventBridge is not available in this region, so Registry lifecycle event routing could not be assessed.",
                EVENT_ROUTING_REFERENCE_URL,
                "No action required unless Amazon EventBridge is expected in this region.",
            )
        ]
    if rule_inventory.get("list_error"):
        error = rule_inventory["list_error"]
        return [
            _na(
                "AR-10",
                f"{finding} Incomplete",
                f"Assessment could not enumerate EventBridge rules on the {REGISTRY_EVENT_BUS_NAME} event bus: {_error_detail(error)}.",
                EVENT_ROUTING_REFERENCE_URL,
                _error_resolution(error, "events:ListRules"),
            )
        ]
    return None


def _registry_scope_label(inventory: Dict[str, Any]) -> str:
    """Name the registries whose lifecycle events the routing verdict covers."""
    names = sorted(_registry_context(item)[1] for item in inventory.get("items", []))
    if not names:
        return "the registries in this account and region"
    listed = ", ".join(f"'{name}'" for name in names[:3])
    if len(names) > 3:
        listed += f" and {len(names) - 3} more"
    return f"registry {listed}" if len(names) == 1 else f"registries {listed}"


def _forwarded_routing(
    entry: Dict[str, Any], rule_inventory: Dict[str, Any], scope: str, finding: str
) -> Dict[str, Any]:
    """Judge a default-bus rule whose only targets are event buses.

    AWS services deliver their events to the default bus, so a rule on another
    bus sees Registry events only through a forwarding rule like this one. A bus
    in this account and Region was read one hop deep by the inventory; a bus in
    another account or Region cannot be read, so the detail types forwarded there
    are returned as `unseen` rather than as covered or missing. So are those
    forwarded to a local bus whose rules, or a rule's pattern or targets, could
    not be read.
    """
    result = {"findings": [], "labels": [], "covered": set(), "unseen": set()}
    name = entry["rule"].get("Name", "unknown")
    detail_types = entry["classification"]["detail_types"]
    for bus in entry["bus_targets"]:
        if not bus["local"]:
            result["unseen"].update(detail_types)
            result["findings"].append(
                _na(
                    "AR-10",
                    finding,
                    f"EventBridge rule '{name}' forwards the lifecycle events of {scope} to event bus '{bus['arn']}' in another account or Region, whose rules this assessment cannot read, so whether they reach a target there is not assessed.",
                    EVENT_ROUTING_REFERENCE_URL,
                    f"In the account and Region that own that event bus, confirm an enabled rule matches source '{REGISTRY_EVENT_SOURCE}' and the approval detail types and has a target other than an event bus.",
                )
            )
            continue
        forwarded = rule_inventory["forwarded_buses"].get(
            bus["name"], {"items": [], "list_error": None}
        )
        if forwarded["list_error"] is not None:
            result["unseen"].update(detail_types)
            result["findings"].append(
                _na(
                    "AR-10",
                    f"{finding} Incomplete",
                    f"EventBridge rule '{name}' forwards Registry lifecycle events to event bus '{bus['name']}', but that bus's rules could not be listed: {_error_detail(forwarded['list_error'])}.",
                    EVENT_ROUTING_REFERENCE_URL,
                    _error_resolution(forwarded["list_error"], "events:ListRules"),
                )
            )
            continue
        credited = False
        undecided = []
        unread = set()
        target_error = None
        for hop in forwarded["items"]:
            hop_name = hop["rule"].get("Name", "unknown")
            classification = hop["classification"]
            if classification["kind"] == "unreadable":
                undecided.append(hop_name)
                unread.update(detail_types)
                continue
            if hop["target_error"] is not None:
                target_error = target_error or hop["target_error"]
                undecided.append(hop_name)
                if _could_credit(hop):
                    unread.update(detail_types & classification["detail_types"])
                continue
            # Bus targets on this bus are not followed: the sweep stops at one hop.
            delivering = len(hop.get("pipeline_targets", []))
            if (
                classification["kind"] != "registry"
                or hop["rule"].get("State") == "DISABLED"
                or delivering == 0
            ):
                continue
            if classification["narrowed_by"]:
                undecided.append(hop_name)
                continue
            credited = True
            result["labels"].append(
                f"'{name}' via event bus '{bus['name']}' rule '{hop_name}' ({delivering} target(s))"
            )
            result["covered"].update(detail_types & classification["detail_types"])
        if credited:
            continue
        if undecided:
            result["unseen"].update(unread)
            result["findings"].append(
                _na(
                    "AR-10",
                    f"{finding} Incomplete" if target_error else finding,
                    "EventBridge rule '{}' forwards Registry lifecycle events to event bus '{}', where rule(s) {} match them but could not be assessed, because a pattern or target list could not be read or the pattern also filters on a field beyond source and detail-type.".format(
                        name,
                        bus["name"],
                        ", ".join(f"'{hop_name}'" for hop_name in undecided),
                    ),
                    EVENT_ROUTING_REFERENCE_URL,
                    _error_resolution(target_error, "events:ListTargetsByRule")
                    if target_error
                    else f"Review those rules on event bus '{bus['name']}' manually against source '{REGISTRY_EVENT_SOURCE}' and the approval detail types.",
                )
            )
            continue
        if rule_inventory.get("timed_out"):
            # The sweep may have stopped before this bus's delivering rule.
            continue
        result["findings"].append(
            create_finding(
                "AR-10",
                finding,
                f"EventBridge rule '{name}' forwards the lifecycle events of {scope} only to event bus '{bus['name']}', where no enabled rule matching source '{REGISTRY_EVENT_SOURCE}' has a target that is {REVIEW_PIPELINE_LABEL}, so no forwarded state change reaches a review pipeline.",
                f"Add an enabled rule on event bus '{bus['name']}' matching source '{REGISTRY_EVENT_SOURCE}' with {REVIEW_PIPELINE_LABEL} as a target, or give rule '{name}' such a target directly.",
                EVENT_ROUTING_REFERENCE_URL,
                SeverityEnum.MEDIUM,
                StatusEnum.FAILED,
            )
        )
    return result


def check_agent_registry_lifecycle_event_routing(
    inventory: Optional[Dict[str, Any]] = None,
    rule_inventory: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """AR-10: assert Registry lifecycle state changes reach an EventBridge target.

    AR-03 and AR-09 assert how the approval workflow is configured and who may
    decide an approval. Neither asks whether the decision is observed anywhere: a
    state change that reaches no target is an approval nobody reviewed. The rules
    read are those on the default event bus, which is where these events land.
    """
    inventory = inventory or get_agent_registry_inventory()
    finding = "AWS Agent Registry Lifecycle Event Routing"
    early = _inventory_start(inventory, "AR-10", finding, EVENT_ROUTING_REFERENCE_URL)
    if early:
        return early
    if rule_inventory is None:
        rule_inventory = get_registry_event_rule_inventory()
    early = _event_rule_inventory_start(rule_inventory, finding)
    if early:
        return early

    scope = _registry_scope_label(inventory)
    findings: List[Dict[str, Any]] = []
    if rule_inventory.get("timed_out"):
        # The rules already read are still judged; only the overall verdict,
        # which needs every rule, is withheld.
        findings.append(
            _na(
                "AR-10",
                f"{finding} Incomplete",
                f"Assessment stopped before reading every rule on the {REGISTRY_EVENT_BUS_NAME} event bus and the event buses it forwards Registry events to, because the Lambda timeout was approaching. The rules read before then are reported below.",
                EVENT_ROUTING_REFERENCE_URL,
                "Re-run the assessment to complete the event rule inventory.",
            )
        )
    routing_labels: List[str] = []
    covered: set = set()
    unseen: set = set()
    narrowed_rules = 0
    for entry in rule_inventory["items"]:
        rule = entry["rule"]
        name = rule.get("Name", "unknown")
        classification = entry["classification"]
        if classification["kind"] == "unreadable":
            # The rule may route any approval transition, so none is missing.
            unseen.update(REGISTRY_APPROVAL_DETAIL_TYPES)
            findings.append(
                _na(
                    "AR-10",
                    finding,
                    f"EventBridge rule '{name}' could not be assessed because {classification['reason']}.",
                    EVENT_ROUTING_REFERENCE_URL,
                    f"Review the rule's event pattern manually against source '{REGISTRY_EVENT_SOURCE}' and the Registry lifecycle detail types.",
                )
            )
            continue
        if entry["target_error"] is not None:
            if _could_credit(entry):
                unseen.update(classification["detail_types"])
            findings.append(
                _na(
                    "AR-10",
                    f"{finding} Incomplete",
                    f"EventBridge rule '{name}' matches Registry lifecycle events but its targets could not be read: {_error_detail(entry['target_error'])}.",
                    EVENT_ROUTING_REFERENCE_URL,
                    _error_resolution(
                        entry["target_error"], "events:ListTargetsByRule"
                    ),
                )
            )
            continue
        if classification["kind"] == "preview":
            if _preview_support_ended():
                details = f"EventBridge rule '{name}' matches only the discontinued public-preview event source '{REGISTRY_PREVIEW_EVENT_SOURCE}', which stopped publishing on {REGISTRY_PREVIEW_EVENT_SOURCE_END_LABEL}, so it no longer routes lifecycle events for {scope}."
                resolution = f"Change the rule's event pattern to match source '{REGISTRY_EVENT_SOURCE}'."
            else:
                details = f"EventBridge rule '{name}' matches only the discontinued public-preview event source '{REGISTRY_PREVIEW_EVENT_SOURCE}', which stops publishing on {REGISTRY_PREVIEW_EVENT_SOURCE_END_LABEL}, so it will stop routing lifecycle events for {scope}."
                resolution = f"Change the rule's event pattern to match source '{REGISTRY_EVENT_SOURCE}' before {REGISTRY_PREVIEW_EVENT_SOURCE_END_LABEL}."
            findings.append(
                create_finding(
                    "AR-10",
                    finding,
                    details,
                    resolution,
                    EVENT_ROUTING_REFERENCE_URL,
                    SeverityEnum.MEDIUM,
                    StatusEnum.FAILED,
                )
            )
            continue
        targets = entry["targets"] or 0
        if rule.get("State") == "DISABLED":
            findings.append(
                create_finding(
                    "AR-10",
                    finding,
                    f"EventBridge rule '{name}' matches the lifecycle events of {scope} but is DISABLED, so no state change reaches its {targets} target(s).",
                    "Enable the rule so Registry lifecycle state changes reach its targets.",
                    EVENT_ROUTING_REFERENCE_URL,
                    SeverityEnum.MEDIUM,
                    StatusEnum.FAILED,
                )
            )
            continue
        if targets == 0:
            findings.append(
                create_finding(
                    "AR-10",
                    finding,
                    f"EventBridge rule '{name}' matches the lifecycle events of {scope} but has no targets, so every matched state change is discarded.",
                    f"Add {REVIEW_PIPELINE_LABEL} as a target of the rule.",
                    EVENT_ROUTING_REFERENCE_URL,
                    SeverityEnum.MEDIUM,
                    StatusEnum.FAILED,
                )
            )
            continue
        if classification["narrowed_by"]:
            narrowed_rules += 1
            findings.append(
                _na(
                    "AR-10",
                    finding,
                    "EventBridge rule '{}' routes Registry lifecycle events to {} target(s), but its pattern also filters on {}, so only the events that match that filter reach a target and the rule is not credited as covering every approval transition of {}.".format(
                        name,
                        targets,
                        ", ".join(
                            f"'{field}'" for field in classification["narrowed_by"]
                        ),
                        scope,
                    ),
                    EVENT_ROUTING_REFERENCE_URL,
                    "Confirm the filter passes every approval event you need reviewed, or add a rule matching the approval detail types that filters on no field beyond source and detail-type.",
                )
            )
            continue
        if _forwards_only(entry):
            forwarded = _forwarded_routing(entry, rule_inventory, scope, finding)
            findings.extend(forwarded["findings"])
            routing_labels.extend(forwarded["labels"])
            covered.update(forwarded["covered"])
            unseen.update(forwarded["unseen"])
            continue
        pipelines = len(entry.get("pipeline_targets", []))
        if not pipelines:
            findings.append(
                create_finding(
                    "AR-10",
                    finding,
                    f"EventBridge rule '{name}' routes the lifecycle events of {scope} to {targets} target(s), none of which is {REVIEW_PIPELINE_LABEL}, so no state change reaches a review pipeline.",
                    f"Add {REVIEW_PIPELINE_LABEL} as a target of the rule, keeping any existing log or stream target as the record.",
                    EVENT_ROUTING_REFERENCE_URL,
                    SeverityEnum.MEDIUM,
                    StatusEnum.FAILED,
                )
            )
            continue
        routing_labels.append(f"'{name}' ({pipelines} target(s))")
        covered.update(classification["detail_types"])

    if rule_inventory.get("timed_out"):
        return findings
    # A transition forwarded to a bus this check cannot read is neither covered
    # nor missing; the forwarding rule's N/A row carries it.
    missing = [
        detail_type
        for detail_type in REGISTRY_APPROVAL_DETAIL_TYPES
        if detail_type not in covered and detail_type not in unseen
    ]
    if not missing and not covered.issuperset(REGISTRY_APPROVAL_DETAIL_TYPES):
        return findings
    if not routing_labels and not unseen:
        matching = len(
            [
                entry
                for entry in rule_inventory["items"]
                if entry["classification"]["kind"] != "unreadable"
            ]
        )
        details = (
            f"None of the {rule_inventory['rules_examined']} rule(s) on the {REGISTRY_EVENT_BUS_NAME} event bus matches source '{REGISTRY_EVENT_SOURCE}', so no lifecycle state change of {scope} is routed anywhere."
            if not matching
            else f"The {matching} rule(s) on the {REGISTRY_EVENT_BUS_NAME} event bus that match Registry lifecycle events route none of them to a target, so no lifecycle state change of {scope} is observed."
        )
        if narrowed_rules:
            details += f" {narrowed_rules} of them filter on a field beyond source and detail-type and are reported separately, because they route only the events that match the filter."
        findings.append(
            create_finding(
                "AR-10",
                finding,
                details,
                f"Create an enabled rule on the {REGISTRY_EVENT_BUS_NAME} event bus matching source '{REGISTRY_EVENT_SOURCE}' and detail types {', '.join(REGISTRY_APPROVAL_DETAIL_TYPES)}, with {REVIEW_PIPELINE_LABEL} as a target.",
                EVENT_ROUTING_REFERENCE_URL,
                SeverityEnum.MEDIUM,
                StatusEnum.FAILED,
            )
        )
    elif missing:
        routed = (
            f"EventBridge rule(s) {', '.join(routing_labels)} route Registry lifecycle events for {scope}, but"
            if routing_labels
            else f"For {scope},"
        )
        findings.append(
            create_finding(
                "AR-10",
                finding,
                f"{routed} no rule matches detail type(s) {', '.join(missing)}, so those approval transitions reach no target.",
                f"Add the missing detail type(s) to an existing rule's event pattern, or create a rule matching them on the {REGISTRY_EVENT_BUS_NAME} event bus.",
                EVENT_ROUTING_REFERENCE_URL,
                SeverityEnum.MEDIUM,
                StatusEnum.FAILED,
            )
        )
    else:
        findings.append(
            create_finding(
                "AR-10",
                finding,
                f"EventBridge rule(s) {', '.join(routing_labels)} on the {REGISTRY_EVENT_BUS_NAME} event bus route every approval transition of {scope} ({', '.join(REGISTRY_APPROVAL_DETAIL_TYPES)}) to at least one target.",
                "No action required",
                EVENT_ROUTING_REFERENCE_URL,
                SeverityEnum.MEDIUM,
                StatusEnum.PASSED,
            )
        )
    return findings


def build_agentic_agent_registry_findings(
    findings: Iterable[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Derive stable AG-33..AG-38 findings from AR source controls."""
    derived = []
    for source in findings:
        mapping = AGENTIC_AGENT_REGISTRY_CHECK_MAPPINGS.get(source.get("Check_ID"))
        if not mapping:
            continue
        status = source.get("Status", StatusEnum.NA)
        derived.append(
            create_finding(
                mapping["check_id"],
                mapping["finding"],
                f"Agentic AI security domain: {mapping['lens_domain']}. {mapping['context']} Source check {source['Check_ID']}: {source.get('Finding_Details', '')}",
                mapping["resolution"],
                AGENTIC_AI_LENS_URL,
                SeverityEnum.INFORMATIONAL
                if status == StatusEnum.NA
                else source.get("Severity", SeverityEnum.INFORMATIONAL),
                status,
                source.get("Region", ""),
            )
        )
    return derived


def generate_csv_report(findings: List[Dict[str, Any]]) -> str:
    output = StringIO()
    fields = [
        "Check_ID",
        "Finding",
        "Finding_Details",
        "Resolution",
        "Reference",
        "Severity",
        "Status",
        "Region",
        "Compliance_Frameworks",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerows(findings)
    return output.getvalue()


def write_to_s3(execution_id: str, csv_content: str, region: str) -> str:
    key = f"agent_registry_security_report_{execution_id}_{region}.csv"
    s3_client.put_object(
        Bucket=BUCKET_NAME, Key=key, Body=csv_content.encode(), ContentType="text/csv"
    )
    return f"s3://{BUCKET_NAME}/{key}"


def _execution_name(event: Dict[str, Any]) -> str:
    """Extract the Step Functions execution name used by all report artifacts."""
    execution = event.get("Execution", {})
    if isinstance(execution, dict):
        return execution.get("Name", "unknown")
    return str(execution) if execution else "unknown"


def _run_check_safely(
    check_id: str,
    finding: str,
    reference: str,
    check: Any,
    *args: Any,
) -> List[Dict[str, Any]]:
    """Convert a single check failure into a visible incomplete finding."""
    try:
        return check(*args)
    except Exception as error:
        logger.exception("%s failed", check_id)
        return [
            _na(
                check_id,
                f"{finding} Incomplete",
                f"Assessment could not complete this check: {_error_detail(error)}.",
                reference,
                "Resolve the reported error and re-run the assessment.",
            )
        ]


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Run the standalone AWS Agent Registry assessment for one target region."""
    global agent_registry_control_client, events_client, iam_client, start_time
    start_time = time.time()
    execution_id = _execution_name(event)
    region = event.get("Region") or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    is_primary_region = event.get("RegionIndex", 0) == 0
    findings: List[Dict[str, Any]] = []
    try:
        initialization_error = None
        try:
            iam_client = boto3.client("iam", config=boto3_config)
        except Exception:
            logger.exception("Unable to initialize IAM client")
            iam_client = None
        try:
            agent_registry_control_client = boto3.client(
                "agent-registry-control", config=boto3_config, region_name=region
            )
        except Exception as error:
            initialization_error = error
        try:
            events_client = boto3.client(
                "events", config=boto3_config, region_name=region
            )
        except Exception:
            logger.exception("Unable to initialize EventBridge client")
            events_client = None

        if is_primary_region:
            try:
                cache = _get_permissions_cache(execution_id)
            except Exception as error:
                logger.exception("Unable to read IAM permission cache")
                cache_findings = [
                    _na(
                        check_id,
                        f"{finding} Incomplete",
                        f"Assessment could not read the IAM permission cache: {_error_detail(error)}.",
                        reference,
                        "Resolve the S3 permission-cache error and re-run the assessment.",
                    )
                    for check_id, finding, reference in (
                        (
                            "AR-01",
                            "AWS Agent Registry IAM Full Access Check",
                            IAM_FULL_ACCESS_REFERENCE_URL,
                        ),
                        (
                            "AR-02",
                            "AWS Agent Registry Stale Access Check",
                            IAM_LAST_ACCESSED_REFERENCE_URL,
                        ),
                        (
                            "AR-09",
                            "AWS Agent Registry Approval Authority Separation",
                            APPROVAL_SEPARATION_REFERENCE_URL,
                        ),
                    )
                ]
            else:
                cache_findings = (
                    _run_check_safely(
                        "AR-01",
                        "AWS Agent Registry IAM Full Access Check",
                        IAM_FULL_ACCESS_REFERENCE_URL,
                        check_agent_registry_full_access,
                        cache,
                    )
                    + _run_check_safely(
                        "AR-02",
                        "AWS Agent Registry Stale Access Check",
                        IAM_LAST_ACCESSED_REFERENCE_URL,
                        check_agent_registry_stale_access,
                        cache,
                    )
                    + _run_check_safely(
                        "AR-09",
                        "AWS Agent Registry Approval Authority Separation",
                        APPROVAL_SEPARATION_REFERENCE_URL,
                        check_agent_registry_approval_separation,
                        cache,
                    )
                )
            for finding in cache_findings:
                finding["Region"] = GLOBAL_REGION_LABEL
                findings.append(finding)
        try:
            inventory = get_agent_registry_inventory(initialization_error)
        except Exception as error:
            logger.exception("Unable to build AWS Agent Registry inventory")
            inventory = {
                "items": [],
                "errors": [],
                "list_error": error,
                "unavailable": False,
                "timed_out": False,
            }
        if inventory.get("unavailable"):
            findings.append(
                _na(
                    "AR-00",
                    "AWS Agent Registry Service Availability",
                    f"AWS Agent Registry is not available in region {region}. No Registry checks were performed.",
                    APPROVAL_REFERENCE_URL,
                    "No action required unless AWS Agent Registry is expected in this region.",
                )
            )
        for check in (
            (
                "AR-03",
                "AWS Agent Registry Publication Approval Governance",
                APPROVAL_REFERENCE_URL,
                check_agent_registry_approval_governance,
            ),
            (
                "AR-04",
                "AWS Agent Registry Discovery Authorization",
                AUTHORIZATION_REFERENCE_URL,
                check_agent_registry_discovery_authorization,
            ),
            (
                "AR-05",
                "AWS Agent Registry Customer-Managed KMS Encryption",
                ENCRYPTION_REFERENCE_URL,
                check_agent_registry_cmk_encryption,
            ),
            (
                "AR-06",
                "AWS Agent Registry Organization Auto-Detection",
                AUTO_DETECTION_REFERENCE_URL,
                check_agent_registry_auto_detection,
            ),
            (
                "AR-10",
                "AWS Agent Registry Lifecycle Event Routing",
                EVENT_ROUTING_REFERENCE_URL,
                check_agent_registry_lifecycle_event_routing,
            ),
        ):
            findings.extend(_run_check_safely(*check, inventory))
        if (
            not inventory.get("unavailable")
            and not inventory.get("list_error")
            and not inventory.get("timed_out")
        ):
            try:
                records = get_agent_registry_record_inventory(inventory)
            except Exception as error:
                logger.exception("Unable to build AWS Agent Registry record inventory")
                records = {
                    "registry_inventory": inventory,
                    "items": [],
                    "list_errors": [
                        (
                            item,
                            error,
                        )
                        for item in inventory.get("items", [])
                    ],
                    "timed_out": False,
                    "truncated": False,
                }
        else:
            records = {
                "registry_inventory": inventory,
                "items": [],
                "list_errors": [],
                "timed_out": False,
                "truncated": False,
            }
        findings.extend(
            _run_check_safely(
                "AR-07",
                "AWS Agent Registry Record Lifecycle Governance",
                RECORD_LIFECYCLE_REFERENCE_URL,
                check_agent_registry_record_lifecycle,
                records,
                inventory,
            )
        )
        findings.extend(
            _run_check_safely(
                "AR-08",
                "AWS Agent Registry Record Provenance",
                PROVENANCE_REFERENCE_URL,
                check_agent_registry_record_provenance,
                records,
                inventory,
            )
        )
        for finding in findings:
            if not finding.get("Region"):
                finding["Region"] = region
        findings.extend(build_agentic_agent_registry_findings(findings))
        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "s3_url": write_to_s3(
                        execution_id, generate_csv_report(findings), region
                    )
                }
            ),
        }
    except Exception:
        logger.exception("AWS Agent Registry assessment failed")
        raise
