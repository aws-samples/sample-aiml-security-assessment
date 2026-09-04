"""AWS Agent Registry security assessment Lambda function."""

import boto3
import csv
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
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
start_time = None

BUCKET_NAME = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
GLOBAL_REGION_LABEL = "Global"
REGISTRY_PAGE_SIZE = 100
RECORD_INVENTORY_LIMIT = 1000
REGISTRY_IAM_NAMESPACE = "agent-registry"
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


def _has_registry_access(permissions: Dict[str, Any], wildcard_only: bool) -> bool:
    for policy in [
        *permissions.get("attached_policies", []),
        *permissions.get("inline_policies", []),
    ]:
        for statement in _policy_statements(policy):
            if statement.get("Effect") != "Allow":
                continue
            actions = _as_list(statement.get("Action", []))
            resources = _as_list(statement.get("Resource", []))
            if wildcard_only and "*" not in resources:
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


def check_agent_registry_full_access(
    permission_cache: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """AR-01: find explicit full-access and wildcard Registry grants."""
    roles = permission_cache.get("role_permissions", {})
    if not roles:
        return [
            _na(
                "AR-01",
                "AWS Agent Registry IAM Full Access Check",
                "No IAM role permissions found in cache.",
                IAM_FULL_ACCESS_REFERENCE_URL,
            )
        ]
    full_access, wildcard = [], []
    for role_name, permissions in roles.items():
        attached = permissions.get("attached_policies", [])
        if any(
            "AgentRegistryFullAccess" in policy.get("name", "") for policy in attached
        ):
            full_access.append(role_name)
        if _has_registry_access(permissions, wildcard_only=True):
            wildcard.append(role_name)
    findings = []
    if full_access:
        findings.append(
            create_finding(
                "AR-01",
                "AWS Agent Registry IAM Full Access Policy",
                "The following roles have AWS Agent Registry full-access policies: "
                + ", ".join(sorted(full_access)),
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
                "The following roles have wildcard or allow-except AWS Agent Registry permissions on all resources: "
                + ", ".join(sorted(wildcard)),
                "Replace wildcard permissions with required AWS Agent Registry actions and scoped resources.",
                IAM_FULL_ACCESS_REFERENCE_URL,
                SeverityEnum.HIGH,
                StatusEnum.FAILED,
            )
        )
    return findings or [
        create_finding(
            "AR-01",
            "AWS Agent Registry IAM Full Access Check",
            "No roles with overly permissive AWS Agent Registry access found.",
            "No action required",
            IAM_FULL_ACCESS_REFERENCE_URL,
            SeverityEnum.HIGH,
            StatusEnum.PASSED,
        )
    ]


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
        partition = caller_identity.get("Arn", "arn:aws:sts::").split(":", 2)[1]
    except Exception as error:
        return [
            _na(
                "AR-02",
                f"{finding} Incomplete",
                f"Assessment could not determine the account ID needed to query IAM service-last-accessed data: {_error_detail(error)}.",
                IAM_LAST_ACCESSED_REFERENCE_URL,
                _error_resolution(error, "sts:GetCallerIdentity"),
            )
        ]

    principals = []
    for principal_type, entries, arn_prefix in (
        ("role", roles, "role"),
        ("user", users, "user"),
    ):
        for name, permissions in entries.items():
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
    return findings or [
        create_finding(
            "AR-02",
            finding,
            f"All {len(principals)} principals with AWS Agent Registry permissions accessed the service within the last 60 days.",
            "No action required",
            IAM_LAST_ACCESSED_REFERENCE_URL,
            SeverityEnum.LOW,
            StatusEnum.PASSED,
        )
    ]


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
    """AR-03: report or require manual Registry record approval."""
    inventory = inventory or get_agent_registry_inventory()
    finding = "AWS Agent Registry Publication Approval Governance"
    early = _inventory_start(inventory, "AR-03", finding, APPROVAL_REFERENCE_URL)
    if early:
        return early
    required = os.environ.get("REQUIRE_AGENT_REGISTRY_MANUAL_APPROVAL", "").lower() in {
        "true",
        "1",
        "yes",
    }
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
        detail = item["detail"]
        if "approvalConfiguration" not in detail:
            findings.append(
                _na(
                    "AR-03",
                    finding,
                    f"Registry '{name}' ({registry_id}) did not return optional approval configuration.",
                    APPROVAL_REFERENCE_URL,
                    "No action required. Retry after the service returns approval configuration metadata.",
                )
            )
        elif (detail.get("approvalConfiguration") or {}).get("autoApprovalRules"):
            findings.append(
                create_finding(
                    "AR-03",
                    finding,
                    f"Registry '{name}' ({registry_id}) automatically approves submitted records.",
                    "Remove auto-approval rules so submitted records require manual review."
                    if required
                    else "No action required under the current baseline. Set REQUIRE_AGENT_REGISTRY_MANUAL_APPROVAL=true to require manual review.",
                    APPROVAL_REFERENCE_URL,
                    SeverityEnum.MEDIUM if required else SeverityEnum.INFORMATIONAL,
                    StatusEnum.FAILED if required else StatusEnum.NA,
                )
            )
        else:
            findings.append(
                create_finding(
                    "AR-03",
                    finding,
                    f"Registry '{name}' ({registry_id}) requires manual review for submitted records.",
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
    global agent_registry_control_client, iam_client, start_time
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
                    )
                ]
            else:
                cache_findings = _run_check_safely(
                    "AR-01",
                    "AWS Agent Registry IAM Full Access Check",
                    IAM_FULL_ACCESS_REFERENCE_URL,
                    check_agent_registry_full_access,
                    cache,
                ) + _run_check_safely(
                    "AR-02",
                    "AWS Agent Registry Stale Access Check",
                    IAM_LAST_ACCESSED_REFERENCE_URL,
                    check_agent_registry_stale_access,
                    cache,
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
