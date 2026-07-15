"""
Severity Model and Disposition helpers for Amazon Bedrock AgentCore checks.

Extracted from the FinServ severity methodology
(docs/SECURITY_CHECKS_FINSERV_SEVERITY_METHODOLOGY.md +
docs/SECURITY_CHECKS_FINSERV_SEVERITY_REGISTER.md) per the gap-analysis
"Severity Model" section, which calls for adopting the same
Likelihood x Impact matrix, disposition rules, and COULD_NOT_ASSESS pattern
tool-wide rather than leaving each general-check module to invent its own
per-finding severities and error-handling ad hoc.

For AgentCore's general checks (mirroring real AWS Security Hub controls),
the control-severity input to the register is the Security Hub published
severity for the control the check implements — not a freshly computed
I x L score. The matrix/disposition mechanics below exist so the module
follows the same governance shape as FinServ (one severity per control,
drift-guarded register, COULD_NOT_ASSESS for unknown state), documented in
docs/SECURITY_CHECKS_FINSERV_SEVERITY_METHODOLOGY.md.

Disposition -> severity:
    PASS / FAIL          -> control severity (register lookup)
    NOT_APPLICABLE        -> Informational  ("no issue was found": resource
                             type genuinely absent)
    COULD_NOT_ASSESS       -> Low  (unknown state: access denied, unsupported
                             region, or an SDK field is missing; re-run after
                             fixing access — never a false Failed and never a
                             silent "no resources" N/A)
"""

from typing import Any, Dict

# Disposition tiers whose severity is fixed by the disposition, not by a
# control score (methodology section 3.4).
_DISPOSITION_SEVERITY = {
    "NOT_APPLICABLE": "Informational",
    "COULD_NOT_ASSESS": "Low",
}

# Prefix applied to the finding name for every COULD_NOT_ASSESS row so it is
# visually distinct in the report and excluded from the severity register's
# static finding-name scan (its name is a template, not a fixed literal).
COULD_NOT_ASSESS_PREFIX = "COULD NOT ASSESS: "


def could_not_assess_row(
    create_finding_fn,
    check_id: str,
    check_name: str,
    err: Any,
    reference: str,
    severity_enum,
    status_enum,
) -> Dict[str, Any]:
    """
    Build one visible finding row for a check (or check phase) that could not
    be completed, per the COULD_NOT_ASSESS disposition: Status=N/A,
    Severity=Low, name prefixed "COULD NOT ASSESS: ". This is the shared
    helper checks should call instead of hand-rolling a
    severity=HIGH/status=FAILED fallback or silently swallowing the error into
    a "no resources found" N/A — both misreport an unknown state as a
    confirmed one.

    Args:
        create_finding_fn: the module's create_finding function.
        check_id: repo-local Check_ID (e.g. "AC-01").
        check_name: human-readable check name (NOT pre-prefixed).
        err: the exception or error string/code that caused the gap.
        reference: documentation URL for this check.
        severity_enum: the module's SeverityEnum class (for .LOW).
        status_enum: the module's StatusEnum class (for .NA).
    """
    return create_finding_fn(
        check_id=check_id,
        finding_name=f"{COULD_NOT_ASSESS_PREFIX}{check_name}",
        finding_details=(
            f"This check could not be completed (error: {err}). The most common "
            "cause is a missing IAM permission for the assessment role; it may "
            "also indicate an unsupported region or an outdated botocore. This "
            "control was NOT assessed — verify the role's permissions and "
            "re-run, and assess this control manually until resolved."
        ),
        resolution=(
            "1. Confirm the assessment role grants the actions this check "
            "requires (see the documented IAM permission set in the README).\n"
            "2. Confirm the service/feature is supported in the assessed region.\n"
            "3. Ensure botocore meets the version floor in requirements.txt.\n"
            "4. Re-run the assessment; assess this control manually until it "
            "succeeds."
        ),
        reference=reference,
        severity=severity_enum.LOW,
        status=status_enum.NA,
    )


# ---------------------------------------------------------------------------
# SEVERITY_REGISTER (drift-guarded by tests/test_agentcore_severity_register.py)
#
# Authoritative per-finding severity, keyed by finding-name, for every
# AgentCore (AC-*) and Agentic AI Gateway (AG-24..27) check. The control
# severity is seeded from the Security Hub published severity for the
# control the check implements (see docs/AI_SECURITY_BEST_PRACTICES_GAP_ANALYSIS.md
# "Severity Model"); repo-specific checks with no Security Hub equivalent use
# the same one-severity-per-control invariant. The `Informational` label is
# reserved for the NOT_APPLICABLE disposition (genuinely no resources to
# assess), never for a control's Pass/Fail severity — see
# _DISPOSITION_SEVERITY above for how Informational/Low are assigned to
# non-Pass/Fail rows.
# ---------------------------------------------------------------------------
SEVERITY_REGISTER: dict = {
    # --- AC-00 (synthesized availability/error rows) ---
    "AgentCore Service Availability": "Informational",
    # --- AC-01 (BedrockAgentCore.1, High) ---
    "AgentCore VPC Configuration Check": "High",
    "AgentCore Runtime VPC Configuration": "High",
    # --- AC-02 (repo-only IAM hardening, High) ---
    "AgentCore IAM Full Access Check": "High",
    "AgentCore IAM Full Access Policy": "High",
    "AgentCore IAM Wildcard Permissions": "High",
    # --- AC-03 (repo-only stale-access hardening; Stale=Medium, Unused=Informational-by-design) ---
    "AgentCore Stale Access Check": "Low",
    "AgentCore Stale Access": "Medium",
    "AgentCore Unused Permissions": "Informational",
    # --- AC-04 (repo-only observability hardening, Medium). GetAgentRuntime
    # has no loggingConfig/tracingConfig fields, so this check can only
    # verify the AgentCore-managed application log group's existence
    # (informational — absence just means the runtime hasn't been invoked
    # yet, not a misconfiguration; there is no API-exposed toggle for either
    # CloudWatch Logs or X-Ray tracing on a Runtime to fail against). ---
    "AgentCore Observability Check": "Medium",
    "ADVISORY: AgentCore Runtime Log Group Not Yet Created": "Informational",
    # --- AC-05 (repo-only ECR encryption hardening; missing=High, AWS-managed=Low) ---
    "AgentCore ECR Repository Encryption": "High",
    "AgentCore ECR Repository AWS-Managed Keys": "Low",
    "AgentCore Encryption Check": "High",
    # --- AC-06 (BedrockAgentCore.6, Medium) ---
    "AgentCore Browser Session Recording Disabled": "Medium",
    # --- AC-07 (BedrockAgentCore.3, Medium) ---
    "AgentCore Memory Configuration Check": "Medium",
    "AgentCore Memory Encryption": "Medium",
    # --- AC-08 (repo-only VPC endpoint hardening; missing=High, unhealthy=Medium) ---
    "AgentCore VPC Endpoints Check": "High",
    "AgentCore VPC Endpoints Missing": "High",
    "AgentCore VPC Endpoints Unhealthy": "Medium",
    # --- AC-09 (repo-only service-linked-role hardening, Medium) ---
    "AgentCore Service-Linked Role Check": "Medium",
    "AgentCore Service-Linked Role Misconfigured": "Medium",
    "AgentCore Service-Linked Role Missing": "Medium",
    # --- AC-10 (repo-only resource-based-policy hardening; missing=High) ---
    "AgentCore Resource-Based Policies Check": "Medium",
    "AgentCore Resource-Based Policies Missing": "High",
    # --- AC-11 (repo-only policy-engine encryption hardening; missing=High) ---
    "AgentCore Policy Engine Encryption Check": "Medium",
    "AgentCore Policy Engine Encryption Missing": "High",
    # --- AC-12 (BedrockAgentCore.4, Medium) ---
    "AgentCore Gateway Encryption Check": "Medium",
    "AgentCore Gateway Encryption Missing": "Medium",
    # --- AC-13 (repo-only gateway configuration hardening, Medium) ---
    "AgentCore Gateway Configuration Check": "Medium",
    # --- AC-14 (BedrockAgentCore.5, High) ---
    "AgentCore Browser Public Network Mode": "High",
    # --- AC-15 (BedrockAgentCore.7, High) ---
    "AgentCore Code Interpreter Insecure Network Mode": "High",
    # --- AG-24 (Agentic AI Gateway inbound authorization, High) ---
    "Agentic AI Gateway Security Controls": "Informational",
    "Agentic AI Gateway Inbound Authorization": "High",
    "Agentic AI Gateway Authenticate-Only Authorization": "High",
    "Agentic AI Gateway Inbound Authorization Disabled": "High",
    # --- AG-25 (Agentic AI Gateway tool policy enforcement, High) ---
    "Agentic AI Gateway Tool Policy Enforcement": "High",
    "Agentic AI Gateway Tool Policy Enforcement Missing": "High",
    "Agentic AI Gateway Tool Policy Not Enforced": "High",
    # --- AG-26 (Agentic AI Gateway error-detail exposure, Medium) ---
    "Agentic AI Gateway Error Detail Exposure": "Medium",
    "Agentic AI Gateway Debug Error Detail Enabled": "Medium",
    # --- AG-27 (Agentic AI Gateway WAF protection, Low) ---
    "Agentic AI Gateway WAF Protection": "Low",
    "Agentic AI Gateway WAF Protection Missing": "Low",
}
