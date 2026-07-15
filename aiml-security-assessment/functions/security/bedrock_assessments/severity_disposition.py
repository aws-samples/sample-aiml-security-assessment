"""
Severity Model and Disposition helpers for Amazon Bedrock checks.

Extracted from the FinServ severity methodology
(docs/SECURITY_CHECKS_FINSERV_SEVERITY_METHODOLOGY.md +
docs/SECURITY_CHECKS_FINSERV_SEVERITY_REGISTER.md) per the gap-analysis
"Severity Model" section, which calls for adopting the same
Likelihood x Impact matrix, disposition rules, and COULD_NOT_ASSESS pattern
tool-wide rather than leaving each general-check module to invent its own
per-finding severities and error-handling ad hoc. This module mirrors
agentcore_assessments/severity_disposition.py, adapted for Bedrock's plain
string severity/status literals (bedrock_assessments/schema.py's
create_finding takes ``severity: str`` / ``status: str`` rather than the
SeverityEnum/StatusEnum attribute style AgentCore uses).

For Bedrock's general checks (mirroring real AWS Security Hub controls where
one exists, plus repo-only hardening checks), the control-severity input to
the register is the Security Hub published severity for the control the
check implements, or the documented repo-only decision for checks with no
Security Hub equivalent. The matrix/disposition mechanics below exist so the
module follows the same governance shape as FinServ (one severity per
control, drift-guarded register, COULD_NOT_ASSESS for unknown state),
documented in docs/SECURITY_CHECKS_FINSERV_SEVERITY_METHODOLOGY.md.

Disposition -> severity:
    PASS / FAIL          -> control severity (register lookup)
    NOT_APPLICABLE        -> Informational  ("no issue was found": resource
                             type genuinely absent)
    COULD_NOT_ASSESS       -> Low  (unknown state: access denied, unsupported
                             region, or an SDK field is missing; re-run after
                             fixing access — never a false Failed and never a
                             silent "no resources" N/A)
"""

from typing import Any, Dict, Optional

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
    region: Optional[str] = "",
) -> Dict[str, Any]:
    """
    Build one visible finding row for a check (or check phase) that could not
    be completed, per the COULD_NOT_ASSESS disposition: Status=N/A,
    Severity=Low, name prefixed "COULD NOT ASSESS: ". This is the shared
    helper checks should call instead of hand-rolling a
    severity="High"/status="Failed" fallback or silently swallowing the error
    into a "no resources found" N/A — both misreport an unknown state as a
    confirmed one.

    Args:
        create_finding_fn: the module's create_finding function.
        check_id: repo-local Check_ID (e.g. "BR-01").
        check_name: human-readable check name (NOT pre-prefixed).
        err: the exception or error string/code that caused the gap.
        reference: documentation URL for this check.
        region: AWS region label to attach to the finding, forwarded to
            create_finding_fn's ``region`` kwarg (Bedrock's create_finding
            always accepts/threads a region, unlike AgentCore's).
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
        severity="Low",
        status="N/A",
        region=region or "",
    )


# ---------------------------------------------------------------------------
# SEVERITY_REGISTER (drift-guarded by tests/test_bedrock_severity_register.py)
#
# Authoritative per-finding severity, keyed by finding-name, for every
# Bedrock (BR-*) check and the Agentic AI Gateway rows Bedrock contributes
# (AG-01..14). The control severity is seeded from the Security Hub
# published severity for the control the check implements where one exists
# (see docs/AI_SECURITY_BEST_PRACTICES_GAP_ANALYSIS.md "Severity Model");
# repo-specific checks with no Security Hub equivalent use the same
# one-severity-per-control invariant, seeded from the more common/most
# defensible severity across the check's own Pass/Fail call sites. The
# `Informational` label is reserved for the NOT_APPLICABLE disposition
# (genuinely no resources to assess), never for a control's Pass/Fail
# severity — see _DISPOSITION_SEVERITY above for how Informational/Low are
# assigned to non-Pass/Fail rows.
# ---------------------------------------------------------------------------
SEVERITY_REGISTER: dict = {
    # --- BR-00 (synthesized availability row) ---
    "Bedrock Service Availability": "Informational",
    # --- BR-01 (AmazonBedrockFullAccess role check, repo-only IAM hardening, High) ---
    "AmazonBedrockFullAccess role check": "High",
    # --- BR-02 (repo-only private-connectivity hardening) ---
    "Amazon Bedrock private connectivity": "High",
    "Amazon Bedrock private connectivity check": "Informational",
    "Amazon Bedrock private connectivity not used": "Medium",
    # --- BR-03 (repo-only marketplace subscription hardening; drift fix:
    #     Passed used Medium while Failed used High — normalized to High,
    #     matching the overly-permissive-access risk on the Failed path) ---
    "Marketplace Subscription Access Check": "High",
    # --- BR-04 (repo-only model invocation logging hardening, Medium) ---
    "Bedrock Model Invocation Logging Check": "Medium",
    # --- BR-05 (repo-only guardrails-configured hardening; drift fix: Passed
    #     used High while Failed used Medium — normalized to Medium, matching
    #     the Failed (no guardrails configured) severity) ---
    "Bedrock Guardrails Check": "Medium",
    # --- BR-06 (repo-only CloudTrail-for-Bedrock hardening; drift fix: Passed
    #     used Medium while Failed used High — normalized to High, matching
    #     the audit-trail-missing risk) ---
    "Bedrock CloudTrail Logging Check": "High",
    # --- BR-07 (repo-only Prompt Management usage hardening, Low) ---
    "Bedrock Prompt Management Check": "Low",
    "Bedrock Prompt Variants Check": "Low",
    # --- BR-08 (repo-only agent-role least-privilege hardening; drift fix:
    #     Passed used Medium while Failed used High — normalized to High,
    #     matching the least-privilege violation risk) ---
    "Bedrock Agent IAM Roles Check": "High",
    # --- BR-09 (repo-only Knowledge Base encryption review; the Review row is
    #     a genuine finding requiring manual verification at the storage
    #     layer, not a "no resources" disposition, so it carries the control
    #     severity rather than Informational) ---
    "Bedrock Knowledge Base Encryption Check": "High",
    "Bedrock Knowledge Base Encryption Review": "High",
    # --- BR-10 (repo-only guardrail-IAM-enforcement hardening; the "Check"
    #     finding_name only ever carries the Passed row (Medium); the Failed
    #     case is reported under the separate "...Missing" finding_name) ---
    "Bedrock Guardrail IAM Enforcement Check": "Medium",
    "Bedrock Guardrail IAM Enforcement Missing": "High",
    # --- BR-11 (repo-only custom-model-encryption review; the Review row is a
    #     genuine finding requiring manual verification, not "no resources",
    #     so it carries a real severity rather than Informational) ---
    "Bedrock Custom Model Encryption Check": "High",
    "Bedrock Custom Model Encryption Review": "Medium",
    # --- BR-12 (repo-only invocation-log-encryption hardening) ---
    "Bedrock Invocation Log Encryption Check": "Medium",
    "Bedrock Invocation Log Encryption": "Medium",
    "Bedrock Invocation Log Encryption Missing": "Informational",
    # --- BR-13 (repo-only Flows-guardrails hardening; drift fix: Passed used
    #     Medium while Failed used High — normalized to High, matching the
    #     missing-guardrail-on-node risk) ---
    "Bedrock Flows Guardrails Check": "Medium",
    "Bedrock Flow Missing Guardrails": "High",
    # --- BR-14 (stale Bedrock access; DISABLED call site, kept for schema
    #     completeness, Medium) ---
    "Stale Bedrock Access Check": "Medium",
    # --- BR-15 (repo-only org-level guardrail enforcement; drift fix: Passed
    #     used Medium while Failed used High — normalized to High, matching
    #     the missing-org-enforcement risk) ---
    "Cross-Account Guardrails Enforcement Check": "High",
    # --- BR-16 (repo-only guardrail-tier hardening; drift fix: Passed used
    #     Low while Failed used Medium — normalized to Medium, matching the
    #     weaker-tier risk) ---
    "Guardrail Tier Validation Check": "Medium",
    # --- BR-17 (repo-only custom-model CMK hardening; drift fix: Passed used
    #     Medium while Failed used High — normalized to High, matching the
    #     customer-managed-key-control risk) ---
    "Custom Model Customer-Managed KMS Encryption Check": "High",
    # --- BR-18 (repo-only model-evaluation hardening, Medium) ---
    "Model Evaluation Implementation Check": "Medium",
    # --- BR-19 (repo-only prompt-flow-validation hardening; drift fix: Passed
    #     used Low while Failed used Medium — normalized to Medium) ---
    "Prompt Flow Validation Check": "Medium",
    # --- BR-20 (repo-only KB customer-managed KMS hardening; drift fix:
    #     Passed used Medium while Failed used High — normalized to High,
    #     matching the customer-managed-key-control risk) ---
    "Knowledge Base Customer-Managed KMS Encryption Check": "High",
    "Knowledge Base Customer-Managed KMS Encryption Review": "Informational",
    # --- BR-21 (repo-only action-group least-privilege hardening; drift fix:
    #     Passed used Medium while Failed used High — normalized to High,
    #     matching the least-privilege violation risk) ---
    "Agent Action Group IAM Least Privilege Check": "High",
    # --- BR-22 (repo-only throttling-quota hardening; drift fix: Passed used
    #     Low while Failed used Medium — normalized to Medium) ---
    "Model Invocation Throttling Limits Check": "Medium",
    # --- BR-23 (repo-only content-filter-coverage hardening; drift fix: Passed
    #     used Low while Failed used High — normalized to High, matching the
    #     missing-content-filter risk) ---
    "Guardrail Content Filter Coverage Check": "High",
    # --- BR-24 (repo-only Automated Reasoning hardening; drift fix: Passed
    #     used Low while Failed used Medium — normalized to Medium) ---
    "Automated Reasoning Policy Implementation Check": "Medium",
    # --- BR-25 (repo-only RAG-evaluation hardening, Low) ---
    "RAG Evaluation Jobs Check": "Low",
    # --- BR-26 (repo-only sensitive-information-filter hardening; drift fix:
    #     Passed used Low while Failed used High — normalized to High,
    #     matching the missing-PII-filter risk) ---
    "Guardrail Sensitive Information Filter Check": "High",
    # --- BR-27 (repo-only contextual-grounding hardening; drift fix: Passed
    #     used Low while Failed used Medium — normalized to Medium) ---
    "Guardrail Contextual Grounding Check": "Medium",
    # --- BR-28 (repo-only agent-guardrail-association hardening; drift fix:
    #     Passed used Low while Failed used High — normalized to High,
    #     matching the missing-guardrail risk) ---
    "Agent Guardrail Association Check": "High",
    # --- BR-29 (repo-only idle-session-TTL hardening, Low) ---
    "Agent Idle Session TTL Check": "Low",
    # --- BR-30 (repo-only imported-model CMK hardening; drift fix: Passed
    #     used Medium while Failed used High — normalized to High, matching
    #     the customer-managed-key-control risk) ---
    "Imported Model Customer-Managed KMS Encryption Check": "High",
    # --- BR-31 (repo-only batch-inference-output CMK hardening; drift fix:
    #     Passed used Low while Failed used Medium — normalized to Medium) ---
    "Batch Inference Output Encryption Check": "Medium",
    # --- BR-32 (repo-only CloudWatch-alarm hardening; drift fix: Passed used
    #     Low while Failed used Medium — normalized to Medium, matching the
    #     missing-alarm risk) ---
    "Bedrock CloudWatch Alarm Check": "Medium",
    # --- BR-33 (Bedrock.1 data source CMK, Medium) ---
    "Bedrock Data Source Encryption Check": "Medium",
    "Bedrock Data Source Encryption Missing": "Medium",
}
