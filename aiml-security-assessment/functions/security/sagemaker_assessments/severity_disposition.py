"""
Severity Model and Disposition helpers for Amazon SageMaker checks.

Extracted from the FinServ severity methodology
(docs/SECURITY_CHECKS_FINSERV_SEVERITY_METHODOLOGY.md +
docs/SECURITY_CHECKS_FINSERV_SEVERITY_REGISTER.md) per the gap-analysis
"Severity Model" section, which calls for adopting the same
Likelihood x Impact matrix, disposition rules, and COULD_NOT_ASSESS pattern
tool-wide rather than leaving each general-check module to invent its own
per-finding severities and error-handling ad hoc. This module mirrors
bedrock_assessments/severity_disposition.py, adapted for SageMaker's plain
string severity/status literals (sagemaker_assessments/schema.py's
create_finding takes ``severity: str`` / ``status: str`` rather than the
SeverityEnum/StatusEnum attribute style AgentCore uses).

For SageMaker's general checks (mirroring real AWS Security Hub controls
where one exists, plus repo-only hardening checks), the control-severity
input to the register is the Security Hub published severity for the
control the check implements, or the documented repo-only decision for
checks with no Security Hub equivalent. Many SageMaker check docstrings
already state "Aligns with AWS Security Hub control SageMaker.N (severity
X)" — that phrase is the authoritative severity source and is used verbatim
wherever present. The matrix/disposition mechanics below exist so the module
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
        check_id: repo-local Check_ID (e.g. "SM-01").
        check_name: human-readable check name (NOT pre-prefixed).
        err: the exception or error string/code that caused the gap.
        reference: documentation URL for this check.
        region: AWS region label to attach to the finding, forwarded to
            create_finding_fn's ``region`` kwarg (SageMaker's create_finding
            always accepts/threads a region).
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
# SEVERITY_REGISTER (drift-guarded by tests/test_sagemaker_severity_register.py)
#
# Authoritative per-finding severity, keyed by finding-name, for every
# SageMaker (SM-*) check. The control severity is seeded from the Security
# Hub published severity for the control the check implements where one
# exists (see docs/AI_SECURITY_BEST_PRACTICES_GAP_ANALYSIS.md "Severity
# Model") — many SageMaker check docstrings document this directly via the
# phrase "Aligns with AWS Security Hub control SageMaker.N (severity X)".
# Repo-specific checks with no Security Hub equivalent use the same
# one-severity-per-control invariant, seeded from the more common/most
# defensible severity across the check's own Pass/Fail call sites. The
# `Informational` label is reserved for the NOT_APPLICABLE disposition
# (genuinely no resources to assess), never for a control's Pass/Fail
# severity — see _DISPOSITION_SEVERITY above for how Informational/Low are
# assigned to non-Pass/Fail rows.
#
# No drift was found while building this register: the finding-names that
# previously appeared with more than one severity across call sites were, in
# every case, the outer "Error during check" exception-handler fallback row
# (severity="High", status="Failed") sharing a finding_name with the
# check's real Passed/Failed rows. That fallback pattern is being replaced
# tool-wide by could_not_assess_row (PR-0's "Permission Handling" fix, see
# Step 3 of the rollout), so those rows are excluded from this register by
# design — they no longer share the control's finding_name once converted
# (COULD_NOT_ASSESS rows use the "COULD NOT ASSESS: <check name>" prefix
# instead). The previously-fixed drift examples called out in the gap
# analysis (SM-11, SM-13, SM-15, SM-03) were already normalized to a single
# real severity in this codebase ahead of this change.
# ---------------------------------------------------------------------------
SEVERITY_REGISTER: dict = {
    # --- SM-00 (synthesized availability row) ---
    "SageMaker Service Availability": "Informational",
    # --- SM-01 (SageMaker.1, High; notebooks only) ---
    "Direct Internet Access Enabled": "High",
    "SageMaker Internet Access Check": "High",
    # --- SM-27 (repo-only domain network access hardening, High) ---
    "Non-VPC Only Network Access": "High",
    "SageMaker Domain Network Access Check": "High",
    # --- SM-04 (repo-only GuardDuty hardening; enabled=Medium, not enabled=High) ---
    "GuardDuty Enabled": "Medium",
    "GuardDuty Not Enabled": "High",
    # --- SM-02 (repo-only IAM hardening: full-access=High, stale access=Medium) ---
    "SageMaker Full Access Policy Used": "High",
    "SageMaker IAM Permissions Check": "High",
    "Stale SageMaker Access": "Medium",
    # --- SM-02 regional (repo-only SSO/domain hardening, Medium) ---
    "SSO Not Properly Configured": "Medium",
    "SageMaker SSO Configuration Check": "Medium",
    # --- SM-03 (SageMaker.21, Medium; notebook storage KMS) ---
    "SageMaker Notebook Storage Encryption Check": "Medium",
    "SageMaker Notebook Storage Encryption Missing": "Medium",
    # --- SM-26 (repo-only domain/training-job encryption hardening, Medium) ---
    "Domain and Training Job Data Protection Check": "Medium",
    "Missing Encryption Configuration": "Medium",
    "Missing VPC Encryption": "Medium",
    # --- SM-05 (repo-only MLOps utilization hardening, Low) ---
    "SageMaker MLOps Features Check": "Low",
    # --- SM-06 (repo-only Clarify usage hardening, Low) ---
    "SageMaker Clarify Usage Check": "Low",
    # --- SM-07 (repo-only Model Monitor usage hardening, Medium) ---
    "SageMaker Model Monitor Usage Check": "Medium",
    # --- SM-09 (SageMaker.3, High; notebook root access) ---
    "SageMaker Notebook Root Access Check": "High",
    "SageMaker Notebook Root Access Enabled": "High",
    # --- SM-10 (SageMaker.2, High; notebook VPC deployment) ---
    "SageMaker Notebook Not in VPC": "High",
    "SageMaker Notebook VPC Deployment Check": "High",
    # --- SM-11 (SageMaker.5, Medium; model network isolation) ---
    "SageMaker Model Network Isolation Check": "Medium",
    "SageMaker Model Network Isolation Disabled": "Medium",
    "SageMaker Model Network Isolation Summary": "Medium",
    # --- SM-12 (SageMaker.4, Medium; endpoint config instance count) ---
    "SageMaker Endpoint Config Single Instance": "Medium",
    "SageMaker Endpoint Instance Count Check": "Medium",
    # --- SM-13 (SageMaker.14, Medium; monitoring network isolation) ---
    "SageMaker Monitoring Network Isolation Check": "Medium",
    "SageMaker Monitoring Network Isolation Disabled": "Medium",
    # --- SM-14 (SageMaker.16/.19, Medium; model container repository access) ---
    "SageMaker Model Platform Repository Access": "Medium",
    "SageMaker Model Repository Access Check": "Medium",
    "SageMaker Model Repository Access Summary": "Medium",
    # --- SM-15 (SageMaker.17, Medium; feature store offline KMS, any KMS) ---
    "SageMaker Feature Store Encryption Check": "Medium",
    "SageMaker Feature Store Offline Encryption Missing": "Medium",
    # --- SM-16 (SageMaker.9, Medium; data quality traffic encryption) ---
    "SageMaker Data Quality Job Encryption Check": "Medium",
    "SageMaker Data Quality Job Encryption Disabled": "Medium",
    # --- SM-17 (repo-only processing job volume encryption hardening, Medium) ---
    "SageMaker Processing Job Encryption Check": "Medium",
    "SageMaker Processing Job Encryption Summary": "Medium",
    "SageMaker Processing Job Volume Encryption Missing": "Medium",
    # --- SM-18 (repo-only transform job volume encryption hardening, Medium) ---
    "SageMaker Transform Job Encryption Check": "Medium",
    "SageMaker Transform Job Encryption Summary": "Medium",
    "SageMaker Transform Job Volume Encryption Missing": "Medium",
    # --- SM-19 (repo-only hyperparameter tuning job encryption hardening, Medium) ---
    "SageMaker Hyperparameter Tuning Job Encryption Check": "Medium",
    "SageMaker Hyperparameter Tuning Job Encryption Missing": "Medium",
    "SageMaker Hyperparameter Tuning Job Encryption Summary": "Medium",
    # --- SM-20 (repo-only compilation job encryption hardening, Medium) ---
    "SageMaker Compilation Job Encryption Check": "Medium",
    "SageMaker Compilation Job Encryption Missing": "Medium",
    "SageMaker Compilation Job Encryption Summary": "Medium",
    # --- SM-21 (repo-only AutoML network isolation hardening, Medium) ---
    "SageMaker AutoML Job Network Isolation Check": "Medium",
    "SageMaker AutoML Job Network Isolation Disabled": "Medium",
    "SageMaker AutoML Job Network Isolation Summary": "Medium",
    # --- SM-29 (SageMaker.10, Medium; explainability traffic encryption) ---
    "SageMaker Explainability Job Traffic Encryption Check": "Medium",
    "SageMaker Explainability Job Traffic Encryption Disabled": "Medium",
    # --- SM-30 (SageMaker.11, Medium; data quality network isolation) ---
    "SageMaker Data Quality Job Network Isolation Check": "Medium",
    "SageMaker Data Quality Job Network Isolation Disabled": "Medium",
    # --- SM-31 (SageMaker.12, Medium; model bias network isolation) ---
    "SageMaker Model Bias Job Network Isolation Check": "Medium",
    "SageMaker Model Bias Job Network Isolation Disabled": "Medium",
    # --- SM-32 (SageMaker.13, Medium; model quality traffic encryption) ---
    "SageMaker Model Quality Job Traffic Encryption Check": "Medium",
    "SageMaker Model Quality Job Traffic Encryption Disabled": "Medium",
    # --- SM-33 (SageMaker.15, Medium; model bias traffic encryption,
    #     multi-instance only) ---
    "SageMaker Model Bias Job Traffic Encryption Check": "Medium",
    "SageMaker Model Bias Job Traffic Encryption Disabled": "Medium",
    # --- SM-35 (SageMaker.20, High; explainability network isolation —
    #     register decision: High seeded from Security Hub even though
    #     sibling isolation controls are Medium, per gap-analysis guidance) ---
    "SageMaker Explainability Job Network Isolation Check": "High",
    "SageMaker Explainability Job Network Isolation Disabled": "High",
    # --- SM-39 (SageMaker.25, High; model quality network isolation —
    #     same register decision as SM-35) ---
    "SageMaker Model Quality Job Network Isolation Check": "High",
    "SageMaker Model Quality Job Network Isolation Disabled": "High",
    # --- SM-36 (SageMaker.22, Medium; monitoring traffic encryption) ---
    "SageMaker Monitoring Traffic Encryption Check": "Medium",
    "SageMaker Monitoring Traffic Encryption Disabled": "Medium",
    # --- SM-28 (SageMaker.8, Medium; notebook platform identifier) ---
    "SageMaker Notebook Platform Check": "Medium",
    "SageMaker Notebook Unsupported Platform": "Medium",
    # --- SM-34 (SageMaker.18, Medium; online feature store KMS, any KMS) ---
    "SageMaker Online Feature Store Encryption Check": "Medium",
    "SageMaker Online Feature Store Encryption Missing": "Medium",
    # --- SM-37/SM-38 (SageMaker.23/.24, Medium; inference experiment
    #     instance/data storage KMS, customer-managed) ---
    "SageMaker Inference Experiment Data Storage Encryption Check": "Medium",
    "SageMaker Inference Experiment Data Storage Encryption Missing": "Medium",
    "SageMaker Inference Experiment Instance Storage Encryption Check": "Medium",
    "SageMaker Inference Experiment Instance Storage Encryption Missing": "Medium",
    # --- SM-22 (repo-only model approval workflow hardening, Medium) ---
    "Model Approval Workflow Check": "Medium",
    # --- SM-23 (repo-only model drift detection hardening, Medium) ---
    "Model Drift Detection Check": "Medium",
    "Model Drift Detection Not Configured": "Medium",
    "Model Drift Detection Summary": "Medium",
    # --- SM-24 (repo-only A/B testing / shadow deployment hardening, Low) ---
    "A/B Testing Pattern Detected": "Low",
    "A/B Testing and Shadow Deployment Check": "Low",
    "Safe Deployment Patterns Check": "Low",
    "Shadow Deployment Pattern Detected": "Low",
    "Single Variant Endpoints": "Informational",
    # --- SM-25 (repo-only ML lineage tracking hardening; Active=Low,
    #     No Active Trials=Low, Not Used=Informational (genuine N/A)) ---
    "ML Lineage Tracking - Experiments Active": "Low",
    "ML Lineage Tracking - Experiments Not Used": "Informational",
    "ML Lineage Tracking - No Active Trials": "Low",
    # --- SM-08 (repo-only Model Registry usage hardening, Medium) ---
    "Model Registry Usage Check": "Medium",
}
