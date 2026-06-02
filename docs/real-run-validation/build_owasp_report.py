#!/usr/bin/env python3
"""
Build the real OWASP-overlay AI/ML Security & Compliance HTML report.

Applies the feedback Agasthi gave on OWASP_DEMO_REPORT.html:
  1. Trim left sidebar to a single Compliance entry (no separate
     "Compliance Frameworks" group, no demo-only nav items).
  2. Combine the two right-side tables ("OWASP Top 10 LLM 2025"
     and "New OWASP Checks - All 18 Extensions") into one unified
     table so each LLM category lists the OW-XX checks under it.
  3. Drop the demo-only sections: Live AWS Validation Evidence,
     Testing Summary, What's Being Pushed to GitHub, Next Step.
  4. Drop the yellow "Review demo" banner.
  5. Use real data from account 676206921018 - the 52 service-level
     findings from CSV plus a live OWASP overlay computed from the
     account state.

Source data:
  - /tmp/bedrock_report.csv     (14 BR-XX checks)
  - /tmp/sagemaker_report.csv   (25 SM-XX checks)
  - /tmp/agentcore_report.csv   (13 AC-XX checks)
  - Live AWS API state captured below for the OW-XX overlay
"""

import csv
import datetime
import html
import os

ACCOUNT_ID = "676206921018"
REGION = "us-east-1"
GENERATED_AT = "April 18, 2026 23:30 UTC"

# -----------------------------------------------------------------------------
# 1. Service-level findings (loaded from CSVs from the actual run)
# -----------------------------------------------------------------------------

def load_findings(csv_path, service):
    rows = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append({
                "check_id": r["Check_ID"],
                "service": service,
                "name": r["Finding"],
                "details": r["Finding_Details"],
                "resolution": r["Resolution"],
                "reference": (r["Reference"] or "").strip().split()[0] if r["Reference"] else "",
                "severity": r["Severity"],
                "status": r["Status"],
                "compliance": owasp_mapping_for(r["Check_ID"]),
            })
    return rows


def owasp_mapping_for(check_id):
    """Map service-level check IDs onto OWASP LLM Top 10 categories."""
    table = {
        # Bedrock
        "BR-01": ("LLM06", "full"),         # IAM least privilege -> Excessive Agency
        "BR-02": ("LLM02", "partial"),      # VPC endpoints -> data egress
        "BR-03": ("LLM03", "partial"),      # Marketplace access -> Supply Chain
        "BR-04": ("LLM02", "full"),         # Invocation logging -> Sensitive Info Disclosure
        "BR-05": ("LLM01", "full"),         # Guardrails -> Prompt Injection
        "BR-06": ("LLM02", "full"),         # CloudTrail -> Sensitive Info Disclosure
        "BR-07": ("LLM07", "partial"),      # Prompt Mgmt -> System Prompt Leakage
        "BR-08": ("LLM06", "full"),         # Agent IAM -> Excessive Agency
        "BR-09": ("LLM02", "full"),         # KB encryption -> Sensitive Info Disclosure
        "BR-10": ("LLM06", "full"),         # Guardrail enforcement -> Excessive Agency
        "BR-11": ("LLM02", "partial"),      # Custom model encryption
        "BR-12": ("LLM02", "full"),         # Invocation log encryption
        "BR-13": ("LLM01", "full"),         # Flows guardrails -> Prompt Injection
        "BR-14": ("LLM06", "partial"),      # Stale access -> Excessive Agency
        # SageMaker
        "SM-01": ("LLM02", "partial"),      # VPC -> data exposure
        "SM-02": ("LLM06", "full"),         # IAM -> Excessive Agency
        "SM-03": ("LLM02", "full"),         # Encryption
        "SM-04": ("LLM04", "partial"),      # GuardDuty -> Data/Model poisoning detection
        "SM-05": ("LLM04", "partial"),      # MLOps -> poisoning safeguards
        "SM-06": ("LLM09", "partial"),      # Clarify -> Misinformation/bias
        "SM-07": ("LLM09", "full"),         # Model Monitor -> Misinformation drift
        "SM-08": ("LLM04", "partial"),      # Model Registry -> approval workflow
        "SM-09": ("LLM06", "partial"),      # Notebook root access
        "SM-10": ("LLM02", "partial"),      # Notebook VPC
        "SM-11": ("LLM02", "partial"),      # Model network isolation
        "SM-12": ("", ""),                  # availability — not OWASP LLM mapped
        "SM-13": ("LLM02", "partial"),      # Monitoring isolation
        "SM-14": ("LLM03", "partial"),      # Model container repo -> Supply Chain
        "SM-15": ("LLM02", "partial"),      # Feature store encryption
        "SM-16": ("LLM02", "partial"),      # Data quality job encryption
        "SM-17": ("LLM02", "partial"),      # Processing job encryption
        "SM-18": ("LLM02", "partial"),      # Transform job encryption
        "SM-19": ("LLM02", "partial"),      # HPO job encryption
        "SM-20": ("LLM02", "partial"),      # Compilation job encryption
        "SM-21": ("LLM02", "partial"),      # AutoML network isolation
        "SM-22": ("LLM04", "partial"),      # Model approval -> poisoning prevention
        "SM-23": ("LLM09", "partial"),      # Drift detection -> Misinformation
        "SM-24": ("LLM04", "partial"),      # A/B testing -> safe rollout
        "SM-25": ("LLM04", "partial"),      # Lineage tracking
        # AgentCore
        "AC-01": ("LLM02", "partial"),      # Runtime VPC
        "AC-02": ("LLM06", "full"),         # IAM full access -> Excessive Agency
        "AC-03": ("LLM06", "partial"),      # Stale access
        "AC-04": ("LLM02", "partial"),      # Observability -> auditability
        "AC-05": ("LLM03", "full"),         # ECR encryption -> Supply Chain
        "AC-06": ("LLM02", "partial"),      # Browser tool storage
        "AC-07": ("LLM02", "full"),         # Memory encryption
        "AC-08": ("LLM02", "partial"),      # VPC endpoints
        "AC-09": ("LLM02", "partial"),      # Service-linked role
        "AC-10": ("LLM06", "full"),         # Resource-based policies
        "AC-11": ("LLM02", "partial"),      # Policy engine encryption
        "AC-12": ("LLM02", "partial"),      # Gateway encryption
        "AC-13": ("LLM02", "partial"),      # Gateway config
    }
    cat, kind = table.get(check_id, ("", ""))
    return {"category": cat, "coverage": kind}


# -----------------------------------------------------------------------------
# 2. OWASP Top 10 LLM 2025 reference data + live OW-XX overlay
# -----------------------------------------------------------------------------

OWASP_LLM_TOP10 = [
    {
        "id": "LLM01",
        "name": "Prompt Injection",
        "doc": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
        "service_checks": ["BR-05", "BR-13"],
        "ow_checks": ["OW-01", "OW-02"],
    },
    {
        "id": "LLM02",
        "name": "Sensitive Information Disclosure",
        "doc": "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/",
        "service_checks": ["BR-04", "BR-06", "BR-09", "BR-12", "SM-03", "AC-07"],
        "ow_checks": ["OW-03", "OW-04", "OW-17"],
    },
    {
        "id": "LLM03",
        "name": "Supply Chain",
        "doc": "https://genai.owasp.org/llmrisk/llm032025-supply-chain/",
        "service_checks": ["BR-03", "AC-05", "SM-14"],
        "ow_checks": ["OW-05", "OW-06", "OW-16"],
    },
    {
        "id": "LLM04",
        "name": "Data and Model Poisoning",
        "doc": "https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/",
        "service_checks": ["SM-05", "SM-07", "SM-22"],
        "ow_checks": ["OW-07"],
    },
    {
        "id": "LLM05",
        "name": "Improper Output Handling",
        "doc": "https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/",
        "service_checks": [],
        "ow_checks": ["OW-08"],
    },
    {
        "id": "LLM06",
        "name": "Excessive Agency",
        "doc": "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
        "service_checks": ["BR-01", "BR-08", "BR-10", "AC-02", "AC-10"],
        "ow_checks": ["OW-09", "OW-10", "OW-18"],
    },
    {
        "id": "LLM07",
        "name": "System Prompt Leakage",
        "doc": "https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/",
        "service_checks": ["BR-07"],
        "ow_checks": ["OW-11"],
    },
    {
        "id": "LLM08",
        "name": "Vector and Embedding Weaknesses",
        "doc": "https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/",
        "service_checks": ["BR-09"],
        "ow_checks": ["OW-12", "OW-13"],
    },
    {
        "id": "LLM09",
        "name": "Misinformation",
        "doc": "https://genai.owasp.org/llmrisk/llm092025-misinformation/",
        "service_checks": ["SM-07", "SM-23"],
        "ow_checks": ["OW-14"],
    },
    {
        "id": "LLM10",
        "name": "Unbounded Consumption",
        "doc": "https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/",
        "service_checks": [],
        "ow_checks": ["OW-15"],
    },
]

OW_CHECKS = {
    "OW-01": {"name": "Guardrail Prompt-Attack Filter Strength",     "severity": "High",   "module": "bedrock inline",      "doc": "https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-content-filters.html"},
    "OW-02": {"name": "Knowledge Base Source Trust",                  "severity": "Medium", "module": "owasp_assessments",   "doc": "https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base-security.html"},
    "OW-03": {"name": "Guardrail PII Redaction",                      "severity": "Medium", "module": "bedrock inline",      "doc": "https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-sensitive-filters.html"},
    "OW-04": {"name": "Invocation Log Retention & Access",            "severity": "Medium", "module": "owasp_assessments",   "doc": "https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html"},
    "OW-05": {"name": "Imported / Custom Model Provenance",           "severity": "Medium", "module": "owasp_assessments",   "doc": "https://docs.aws.amazon.com/bedrock/latest/userguide/custom-models.html"},
    "OW-06": {"name": "SageMaker JumpStart & Marketplace Inventory",  "severity": "Low",    "module": "owasp_assessments",   "doc": "https://docs.aws.amazon.com/sagemaker/latest/dg/jumpstart.html"},
    "OW-07": {"name": "Knowledge Base Ingestion Role Scope",          "severity": "High",   "module": "owasp_assessments",   "doc": "https://docs.aws.amazon.com/bedrock/latest/userguide/kb-permissions.html"},
    "OW-08": {"name": "Guardrail Output Filter",                      "severity": "Medium", "module": "bedrock inline",      "doc": "https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-word-filters.html"},
    "OW-09": {"name": "Agent Action-Group Wildcard Scope",            "severity": "High",   "module": "owasp_assessments",   "doc": "https://docs.aws.amazon.com/bedrock/latest/userguide/agents-permissions.html"},
    "OW-10": {"name": "Human-in-the-Loop & Confirmation Flow",        "severity": "Info",   "module": "owasp_assessments",   "doc": "https://docs.aws.amazon.com/bedrock/latest/userguide/agents-action-groups.html"},
    "OW-11": {"name": "System Prompt Protection",                     "severity": "Medium", "module": "bedrock inline",      "doc": "https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-management.html"},
    "OW-12": {"name": "Vector Store Network Isolation",               "severity": "High",   "module": "owasp_assessments",   "doc": "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-network.html"},
    "OW-13": {"name": "Multi-Tenant Knowledge Base Isolation",        "severity": "Medium", "module": "owasp_assessments",   "doc": "https://docs.aws.amazon.com/bedrock/latest/userguide/kb-multi-tenant.html"},
    "OW-14": {"name": "Contextual Grounding Guardrail",               "severity": "Medium", "module": "bedrock inline",      "doc": "https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-contextual-grounding-check.html"},
    "OW-15": {"name": "Invocation Rate, Token & Cost Controls",       "severity": "Medium", "module": "bedrock + owasp_assessments", "doc": "https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-cw.html"},
    "OW-16": {"name": "Container Image Scanning",                     "severity": "Medium", "module": "agentcore inline",    "doc": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html"},
    "OW-17": {"name": "Knowledge Base Retrieval Access Policy",       "severity": "High",   "module": "owasp_assessments",   "doc": "https://docs.aws.amazon.com/bedrock/latest/userguide/kb-permissions.html"},
    "OW-18": {"name": "Multi-Agent Sub-Agent Inventory",              "severity": "Medium", "module": "owasp_assessments",   "doc": "https://docs.aws.amazon.com/bedrock/latest/userguide/agents-multi-agent.html"},
}

# -----------------------------------------------------------------------------
# Live OWASP overlay results — captured from the actual account state
# -----------------------------------------------------------------------------

# Account state (from live API calls):
#   Bedrock guardrails: 0
#   Bedrock custom models: 0
#   Bedrock model-invocation-logging: not configured
#   Bedrock agents: 0
#   Bedrock flows: 0
#   Bedrock managed prompts: 1 ("test")
#   Bedrock knowledge bases: 0
#   AgentCore runtimes: 2 (example_runtime, RetailRadar_Agent)
#   AgentCore memories: 2
#   ECR repo bedrock-agentcore-retailradar_agent: scanOnPush=false
#   AgentCore log groups: 3, retentionInDays=null on all
#   CloudWatch alarms scoped to Bedrock: 0
#   AWS Budgets scoped to Bedrock: 0
#   SageMaker Studio domains: 3 (Unified Studio dev domains)

OW_FINDINGS = [
    {
        "check_id": "OW-01", "name": "Guardrail Prompt-Attack Filter — N/A",
        "details": "No Bedrock Guardrails are configured in the account, so the PROMPT_ATTACK content-filter strength cannot be evaluated. Service-level check BR-05 already flags this as a Medium-severity gap.",
        "resolution": "Create a Bedrock Guardrail and configure a content filter with type=PROMPT_ATTACK and inputStrength=HIGH, outputStrength=HIGH.",
        "severity": "N/A", "status": "N/A",
    },
    {
        "check_id": "OW-02", "name": "Knowledge Base Source Trust — N/A",
        "details": "No Bedrock Knowledge Bases were found in the account, so KB source-bucket trust cannot be evaluated.",
        "resolution": "When you create a Knowledge Base, ensure the data source S3 bucket is owned by an account/OU you control and that bedrock-agent does not pull from third-party buckets without an explicit allowlist.",
        "severity": "N/A", "status": "N/A",
    },
    {
        "check_id": "OW-03", "name": "Guardrail PII Redaction — N/A",
        "details": "No Bedrock Guardrails are configured so sensitiveInformationPolicy.piiEntities cannot be evaluated.",
        "resolution": "Add a sensitiveInformationPolicy.piiEntities list to your Guardrail covering CREDIT_DEBIT_CARD_NUMBER, EMAIL, PHONE, SSN at minimum (BLOCK or ANONYMIZE depending on use case).",
        "severity": "N/A", "status": "N/A",
    },
    {
        "check_id": "OW-04", "name": "Invocation Log Retention & Access — Failed",
        "details": "Bedrock model-invocation-logging is not enabled at the account level (BR-04 also flags this). Even on the AgentCore runtime log groups (/aws/bedrock-agentcore/runtimes/*), retention is set to null (never expire), which fails the 30-day minimum / log-rotation policy.",
        "resolution": "1) Enable Bedrock model-invocation-logging via PutModelInvocationLoggingConfiguration to a CloudWatch log group or S3 bucket. 2) Set CloudWatch retention >= 30 days using logs:PutRetentionPolicy on /aws/bedrock-agentcore/runtimes/*. 3) Apply a resource policy restricting kms:Decrypt on the log group's CMK to break-glass principals only.",
        "severity": "Medium", "status": "Failed",
    },
    {
        "check_id": "OW-05", "name": "Imported / Custom Model Provenance — N/A",
        "details": "No imported or fine-tuned custom models are present in the account (BR-11 also reports this). The provenance check has nothing to evaluate.",
        "resolution": "When importing or fine-tuning a model, record the source artifact's SHA256, training data lineage, and signing key in the model's tags or in SageMaker Model Cards.",
        "severity": "N/A", "status": "N/A",
    },
    {
        "check_id": "OW-06", "name": "SageMaker JumpStart & Marketplace Inventory — N/A",
        "details": "No SageMaker models found in the account, so no JumpStart or Marketplace deployments to inventory.",
        "resolution": "When deploying JumpStart or Marketplace models, tag them (e.g. owasp:llm03=marketplace) so the supply-chain inventory check can flag them for review.",
        "severity": "N/A", "status": "N/A",
    },
    {
        "check_id": "OW-07", "name": "KB Ingestion Role Scope — N/A",
        "details": "No Knowledge Bases are configured. The check that walks the ingestion role's IAM policy for s3:* / *:* on * has no targets.",
        "resolution": "When creating a Knowledge Base, scope the ingestion role's S3 actions to s3:GetObject + s3:ListBucket on the specific source-data bucket ARN, not s3:* on *.",
        "severity": "N/A", "status": "N/A",
    },
    {
        "check_id": "OW-08", "name": "Guardrail Output Filter — N/A",
        "details": "No Bedrock Guardrails are configured. The output-side wordPolicy / contentPolicy filter cannot be evaluated.",
        "resolution": "Configure wordPolicy.words (denied words) and contentPolicy filters with outputStrength=HIGH on your Bedrock Guardrail. This is a compensating control — primary output handling belongs at the application layer.",
        "severity": "N/A", "status": "N/A",
    },
    {
        "check_id": "OW-09", "name": "Agent Action-Group Wildcard Scope — N/A",
        "details": "No Bedrock Agents found in the account, so action-group Lambda execution roles cannot be scanned for wildcard permissions. AC-02 / AC-10 already cover the AgentCore-side IAM.",
        "resolution": "When you add an agent action group, ensure the Lambda execution role has Action and Resource scoped to the specific bucket / table ARNs the action needs. Do not grant Action: \"s3:*\" on Resource: \"*\".",
        "severity": "N/A", "status": "N/A",
    },
    {
        "check_id": "OW-10", "name": "Human-in-the-Loop & Confirmation Flow — N/A",
        "details": "No Bedrock Agents found in the account. HITL / requireConfirmation cannot be inventoried.",
        "resolution": "For sensitive action groups (writes, payments), set requireConfirmation=ENABLED on the agent action so the user has to approve before the action executes.",
        "severity": "N/A", "status": "N/A",
    },
    {
        "check_id": "OW-11", "name": "System Prompt Protection — Passed (informational)",
        "details": "1 Bedrock managed prompt found (\"test\", id A5OQ5CPS6R). Using Bedrock Prompt Management means the system prompt is stored as a managed resource with versioning rather than embedded in client code. No active or draft variants in production yet.",
        "resolution": "Continue managing system prompts via Bedrock Prompt Management. Ensure IAM read access to bedrock:GetPrompt is restricted to the agents that need it, not granted broadly.",
        "severity": "Info", "status": "Passed",
    },
    {
        "check_id": "OW-12", "name": "Vector Store Network Isolation — N/A",
        "details": "No Bedrock Knowledge Bases are configured, so vector-store (OpenSearch Serverless) network isolation cannot be evaluated.",
        "resolution": "When you provision an OpenSearch Serverless collection for a Knowledge Base, attach a network policy that disables public access and a VPC endpoint policy restricting access to your VPC.",
        "severity": "N/A", "status": "N/A",
    },
    {
        "check_id": "OW-13", "name": "Multi-Tenant Knowledge Base Isolation — N/A",
        "details": "No Knowledge Bases configured.",
        "resolution": "If you build a multi-tenant KB, ensure metadata filtering is enforced server-side (in the Retrieve / RetrieveAndGenerate API call) and not relied on at the client layer.",
        "severity": "N/A", "status": "N/A",
    },
    {
        "check_id": "OW-14", "name": "Contextual Grounding Guardrail — N/A",
        "details": "No Bedrock Guardrails configured, so contextualGroundingPolicy cannot be evaluated.",
        "resolution": "Add a contextualGroundingPolicy with filters of type=GROUNDING and type=RELEVANCE to your Guardrail. Set both thresholds to 0.7+ for retrieval-augmented use cases.",
        "severity": "N/A", "status": "N/A",
    },
    {
        "check_id": "OW-15", "name": "Invocation Rate, Token & Cost Controls — Failed",
        "details": "No CloudWatch alarms are configured against the AWS/Bedrock namespace and no AWS Budget is scoped to Amazon Bedrock service. With AgentCore runtimes deployed, this leaves cost/rate runaway undetected.",
        "resolution": "1) Create a CloudWatch alarm on AWS/Bedrock metric InvocationCount per modelId with a sensible threshold. 2) Create an AWS Budget filtered to Service=\"Amazon Bedrock\" with email/SNS notification at 80% / 100%. 3) For input-side throttling, configure wordPolicy.words on the Guardrail to block oversized prompts.",
        "severity": "Medium", "status": "Failed",
    },
    {
        "check_id": "OW-16", "name": "Container Image Scanning — Failed",
        "details": "ECR repository \"bedrock-agentcore-retailradar_agent\" has scanOnPush=false. AgentCore runtime images can be deployed without vulnerability scanning, which is an LLM03 (Supply Chain) gap.",
        "resolution": "Run aws ecr put-image-scanning-configuration --repository-name bedrock-agentcore-retailradar_agent --image-scanning-configuration scanOnPush=true. For all AgentCore image repos, also enable Enhanced Scanning at the registry level via Inspector.",
        "severity": "Medium", "status": "Failed",
    },
    {
        "check_id": "OW-17", "name": "KB Retrieval Access Policy — N/A",
        "details": "No Knowledge Bases configured.",
        "resolution": "When you create a Knowledge Base, attach a resource-based policy restricting bedrock-agent:Retrieve and bedrock-agent:RetrieveAndGenerate to the specific IAM roles that should query it. Do not rely on identity-based bedrock-agent:* allowing all callers.",
        "severity": "N/A", "status": "N/A",
    },
    {
        "check_id": "OW-18", "name": "Multi-Agent Sub-Agent Inventory — N/A",
        "details": "No Bedrock Agents (and therefore no multi-agent collaborators) found in the account.",
        "resolution": "When you enable multi-agent collaboration, inventory the sub-agents and ensure each sub-agent's IAM role is scoped to only the actions and KBs it needs.",
        "severity": "N/A", "status": "N/A",
    },
]


def status_for_owasp_category(cat_id, service_findings, ow_findings):
    """Compute compliance for an LLM category from the underlying checks."""
    relevant_service = [f for f in service_findings if f["compliance"]["category"] == cat_id]
    relevant_ow = [f for f in ow_findings if any(
        c["id"] == cat_id for c in OWASP_LLM_TOP10
        if f["check_id"] in c["ow_checks"]
    )]
    all_relevant = relevant_service + relevant_ow

    failed = sum(1 for f in all_relevant if f["status"].lower() == "failed")
    passed = sum(1 for f in all_relevant if f["status"].lower() == "passed")

    if failed > 0:
        return "Non-Compliant", failed, passed, len(all_relevant)
    if passed > 0:
        return "Compliant", failed, passed, len(all_relevant)
    return "N/A", failed, passed, len(all_relevant)


# -----------------------------------------------------------------------------
# 3. HTML rendering helpers
# -----------------------------------------------------------------------------

DOCS_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>'


def severity_class(sev):
    s = (sev or "").strip().lower()
    if s == "high":
        return "severity high"
    if s == "medium":
        return "severity medium"
    if s == "low":
        return "severity low"
    return "severity na"


def status_class(status):
    s = (status or "").strip().lower()
    if s == "failed":
        return "status failed"
    if s == "passed":
        return "status passed"
    if s == "compliant":
        return "status compliant"
    if s == "non-compliant":
        return "status non-compliant"
    if s == "partial":
        return "status partial"
    return "status na"


def docs_link(url, title="View AWS Documentation"):
    if not url:
        return ""
    return f'<a href="{html.escape(url)}" target="_blank" rel="noopener" class="reference-btn" title="{html.escape(title)}">{DOCS_ICON}</a>'


def render_compliance_row(cat):
    status, failed, passed, total = status_for_owasp_category(
        cat["id"], SERVICE_FINDINGS, OW_FINDINGS
    )
    service_str = ", ".join(cat["service_checks"]) or "—"
    ow_str = ", ".join(cat["ow_checks"]) or "—"

    rows = []
    rows.append(
        f'<tr class="cat-row" data-llm="{cat["id"]}">'
        f'<td><code>{cat["id"]}</code></td>'
        f'<td class="col-domain">{html.escape(cat["name"])}</td>'
        f'<td class="finding-details">'
        f'  <div><strong style="color:var(--text);">Service-level checks:</strong> {service_str}</div>'
        f'  <div style="margin-top:4px;"><strong style="color:var(--text);">OWASP-specific checks:</strong> {ow_str}</div>'
        f'</td>'
        f'<td><span class="{status_class(status)}">{status}</span></td>'
        f'<td class="finding-details">{failed} failed · {passed} passed · {total} mapped</td>'
        f'<td class="reference-cell">{docs_link(cat["doc"], "OWASP " + cat["id"] + " " + cat["name"])}</td>'
        f'</tr>'
    )

    # Nested OW-XX sub-rows
    for ow_id in cat["ow_checks"]:
        ow = OW_CHECKS[ow_id]
        ow_finding = next((f for f in OW_FINDINGS if f["check_id"] == ow_id), None)
        if ow_finding:
            sub_status = ow_finding["status"]
            sub_sev = ow_finding["severity"]
        else:
            sub_status = "N/A"
            sub_sev = ow["severity"]
        rows.append(
            f'<tr class="sub-row" data-parent="{cat["id"]}">'
            f'<td style="padding-left:36px;"><code>{ow_id}</code></td>'
            f'<td class="finding-details" colspan="2">'
            f'  <div class="col-domain">{html.escape(ow["name"])}</div>'
            f'  <div style="margin-top:2px; color: var(--text-3);">Module: {html.escape(ow["module"])}</div>'
            f'</td>'
            f'<td><span class="{status_class(sub_status)}">{html.escape(sub_status)}</span> '
            f'<span class="{severity_class(sub_sev)}" style="margin-left:6px;">{html.escape(sub_sev)}</span></td>'
            f'<td class="finding-details"></td>'
            f'<td class="reference-cell">{docs_link(ow["doc"], ow["name"])}</td>'
            f'</tr>'
        )
    return "\n".join(rows)


def render_findings_row(f):
    badge = f'<span class="framework-badge owasp">{f["compliance"]["category"]}</span>' if f["compliance"]["category"] else "<span class=\"finding-details\">—</span>"
    coverage = f["compliance"]["coverage"] or ""
    return (
        f'<tr>'
        f'<td><code>{html.escape(f["check_id"])}</code></td>'
        f'<td>'
        f'  <div class="col-domain">{html.escape(f["name"])}</div>'
        f'  <div class="finding-details" style="margin-top:4px;">{html.escape(f["details"])}</div>'
        f'</td>'
        f'<td class="resolution-text">{html.escape(f["resolution"])}</td>'
        f'<td>{badge} <span class="finding-details">{html.escape(coverage)}</span></td>'
        f'<td><span class="{severity_class(f["severity"])}">{html.escape(f["severity"])}</span></td>'
        f'<td><span class="{status_class(f["status"])}">{html.escape(f["status"])}</span></td>'
        f'<td class="reference-cell">{docs_link(f["reference"])}</td>'
        f'</tr>'
    )


# -----------------------------------------------------------------------------
# 4. Compute summary metrics
# -----------------------------------------------------------------------------

SERVICE_FINDINGS = (
    load_findings("/tmp/bedrock_report.csv", "Bedrock")
    + load_findings("/tmp/sagemaker_report.csv", "SageMaker")
    + load_findings("/tmp/agentcore_report.csv", "AgentCore")
)

ALL_FINDINGS = SERVICE_FINDINGS + [
    {
        "check_id": f["check_id"],
        "service": "OWASP",
        "name": f["name"],
        "details": f["details"],
        "resolution": f["resolution"],
        "reference": OW_CHECKS[f["check_id"]]["doc"],
        "severity": f["severity"],
        "status": f["status"],
        "compliance": {
            "category": next((c["id"] for c in OWASP_LLM_TOP10 if f["check_id"] in c["ow_checks"]), ""),
            "coverage": "full" if f["status"] in ("Failed", "Passed") else "n/a",
        },
    }
    for f in OW_FINDINGS
]

total_checks = len(ALL_FINDINGS)
high_failed = sum(1 for f in ALL_FINDINGS if f["severity"].lower() == "high" and f["status"].lower() == "failed")
medium_failed = sum(1 for f in ALL_FINDINGS if f["severity"].lower() == "medium" and f["status"].lower() == "failed")
low_failed = sum(1 for f in ALL_FINDINGS if f["severity"].lower() == "low" and f["status"].lower() == "failed")
passed = sum(1 for f in ALL_FINDINGS if f["status"].lower() == "passed")
failed = sum(1 for f in ALL_FINDINGS if f["status"].lower() == "failed")
na = sum(1 for f in ALL_FINDINGS if f["status"].lower() == "n/a")

# Compliance dashboard percentage
compliant_categories = sum(
    1 for c in OWASP_LLM_TOP10
    if status_for_owasp_category(c["id"], SERVICE_FINDINGS, OW_FINDINGS)[0] == "Compliant"
)
non_compliant_categories = sum(
    1 for c in OWASP_LLM_TOP10
    if status_for_owasp_category(c["id"], SERVICE_FINDINGS, OW_FINDINGS)[0] == "Non-Compliant"
)
na_categories = sum(
    1 for c in OWASP_LLM_TOP10
    if status_for_owasp_category(c["id"], SERVICE_FINDINGS, OW_FINDINGS)[0] == "N/A"
)
compliance_pct = int(round(100 * compliant_categories / max(1, len(OWASP_LLM_TOP10))))

# Top 5 priority recommendations - the most severe failed findings
priority = sorted(
    [f for f in ALL_FINDINGS if f["status"].lower() == "failed"],
    key=lambda f: {"high": 0, "medium": 1, "low": 2}.get(f["severity"].lower(), 3)
)[:5]

# -----------------------------------------------------------------------------
# 5. Render HTML
# -----------------------------------------------------------------------------

priority_html = "".join(
    f'<div class="alert-item {"critical" if f["severity"].lower() == "high" else "warning"}">'
    f'<div class="alert-count">{f["check_id"]}</div>'
    f'<div class="alert-info">'
    f'<div class="alert-domain">{html.escape(f["name"])}</div>'
    f'<div class="alert-category">{html.escape(f["service"])} · {html.escape(f["severity"])}'
    + (f' · OWASP {f["compliance"]["category"]}' if f["compliance"]["category"] else "")
    + '</div>'
    f'</div></div>'
    for f in priority
)

owasp_combined_rows = "\n".join(render_compliance_row(c) for c in OWASP_LLM_TOP10)

findings_rows = "\n".join(render_findings_row(f) for f in ALL_FINDINGS)

# Build sidebar (trimmed per Agasthi's feedback)

HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI/ML Security &amp; Compliance · OWASP LLM Top 10 · Account {ACCOUNT_ID}</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&amp;family=JetBrains+Mono:wght@400;500&amp;display=swap" rel="stylesheet">
<style>
:root {{
    --bg: #f8fafc; --surface: #fff; --surface-2: #f1f5f9; --border: #cbd5e1;
    --text: #0f172a; --text-2: #64748b; --text-3: #94a3b8;
    --accent: #6366f1; --accent-soft: #eef2ff;
    --success: #10b981; --success-soft: #ecfdf5;
    --warning: #f59e0b; --warning-soft: #fffbeb;
    --danger: #ef4444; --danger-soft: #fef2f2;
    --purple: #8b5cf6; --purple-soft: #f5f3ff;
}}
[data-theme="dark"] {{
    --bg: #0f172a; --surface: #1e293b; --surface-2: #334155; --border: #64748b;
    --text: #f1f5f9; --text-2: #94a3b8; --text-3: #64748b;
    --accent: #818cf8; --accent-soft: rgba(129,140,248,.15);
    --success: #4ade80; --success-soft: rgba(74,222,128,.15);
    --warning: #fbbf24; --warning-soft: rgba(251,191,36,.15);
    --danger: #f87171; --danger-soft: rgba(248,113,113,.15);
    --purple: #a78bfa; --purple-soft: rgba(167,139,250,.15);
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: 'DM Sans', system-ui, sans-serif; font-size: 14px; line-height: 1.6; color: var(--text); background: var(--bg); -webkit-font-smoothing: antialiased; }}
.layout {{ display: grid; grid-template-columns: 280px 1fr; min-height: 100vh; }}
.sidebar {{ background: var(--surface); border-right: 1px solid var(--border); padding: 24px 0; position: sticky; top: 0; height: 100vh; overflow-y: auto; display: flex; flex-direction: column; }}
.sidebar-header {{ padding: 0 20px 24px; border-bottom: 1px solid var(--border); margin-bottom: 16px; }}
.sidebar-header h1 {{ font-size: 18px; font-weight: 700; color: var(--text); margin-bottom: 4px; }}
.sidebar-header p {{ font-size: 12px; color: var(--text-3); }}
.theme-toggle {{ display: flex; align-items: center; gap: 8px; margin: 16px 20px; padding: 10px 14px; background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 500; color: var(--text); }}
.theme-toggle:hover {{ border-color: var(--accent); background: var(--accent-soft); }}
.theme-toggle svg {{ width: 18px; height: 18px; }}
.theme-toggle .sun-icon {{ display: none; }}
[data-theme="dark"] .theme-toggle .sun-icon {{ display: block; }}
[data-theme="dark"] .theme-toggle .moon-icon {{ display: none; }}
.nav-section {{ padding: 0 16px; margin-bottom: 20px; }}
.nav-section h3 {{ font-size: 11px; font-weight: 600; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.5px; padding: 0 8px; margin-bottom: 8px; }}
.nav-item {{ display: flex; align-items: center; gap: 10px; padding: 10px 12px; border-radius: 8px; color: var(--text-2); font-size: 13px; font-weight: 500; cursor: pointer; transition: all 0.15s; text-decoration: none; }}
.nav-item:hover {{ background: var(--surface-2); color: var(--text); }}
.nav-item.active {{ background: var(--accent-soft); color: var(--accent); }}
.nav-item svg {{ width: 18px; height: 18px; opacity: 0.7; flex-shrink: 0; }}
.nav-item .count {{ margin-left: auto; font-size: 12px; font-weight: 600; background: var(--surface-2); padding: 2px 8px; border-radius: 10px; }}
.nav-item.active .count {{ background: var(--accent); color: #fff; }}
.sidebar-footer {{ margin-top: auto; padding: 16px 20px; border-top: 1px solid var(--border); font-size: 12px; color: var(--text-3); }}
.main {{ padding: 32px 40px; max-width: 1400px; }}
.page-header {{ margin-bottom: 32px; }}
.page-header h2 {{ font-size: 24px; font-weight: 700; margin-bottom: 8px; }}
.page-header-meta {{ display: flex; gap: 24px; font-size: 13px; color: var(--text-2); flex-wrap: wrap; }}
.page-header-meta span {{ display: flex; align-items: center; gap: 6px; }}
.metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 32px; }}
.metric {{ background: var(--surface); border: 2px solid var(--border); border-radius: 12px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
.metric-label {{ font-size: 13px; color: var(--text-2); margin-bottom: 8px; }}
.metric-value {{ font-size: 28px; font-weight: 700; }}
.metric-sub {{ font-size: 12px; color: var(--text-3); margin-top: 4px; }}
.metric.danger .metric-value {{ color: var(--danger); }}
.metric.warning .metric-value {{ color: var(--warning); }}
.metric.highlight {{ background: linear-gradient(135deg, var(--success-soft) 0%, rgba(16,185,129,.2) 100%); border-color: var(--success); }}
.metric.highlight .metric-value {{ color: var(--success); }}
.metric.purple {{ border-color: var(--purple); }}
.metric.purple .metric-value {{ color: var(--purple); }}
.metric.accent {{ border-color: var(--accent); }}
.metric.accent .metric-value {{ color: var(--accent); }}
.card {{ background: var(--surface); border: 2px solid var(--border); border-radius: 12px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
.card-header {{ padding: 16px 20px; border-bottom: 2px solid var(--border); background: var(--surface-2); }}
.card-header h3 {{ font-size: 15px; font-weight: 600; }}
.card-body {{ padding: 20px; }}
.table-wrap {{ overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th {{ text-align: left; padding: 14px 16px; font-weight: 700; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text); background: var(--surface-2); border-bottom: 3px solid var(--accent); white-space: nowrap; }}
td {{ padding: 14px 16px; border-bottom: 1px solid var(--border); vertical-align: top; line-height: 1.5; word-wrap: break-word; }}
tr:last-child td {{ border-bottom: none; }}
tr:hover td {{ background: var(--surface-2); }}
tr.sub-row td {{ background: var(--surface-2); font-size: 12px; }}
tr.sub-row:hover td {{ background: var(--border); }}
.col-domain {{ font-weight: 600; color: var(--text); }}
.status {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; font-family: 'JetBrains Mono', monospace; }}
.status.compliant, .status.passed {{ background: var(--success-soft); color: var(--success); }}
.status.non-compliant, .status.failed {{ background: var(--danger-soft); color: var(--danger); }}
.status.partial {{ background: var(--warning-soft); color: var(--warning); }}
.status.na {{ background: var(--surface-2); color: var(--text-3); }}
.severity {{ display: inline-flex; align-items: center; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }}
.severity.high {{ background: var(--danger-soft); color: var(--danger); }}
.severity.medium {{ background: var(--warning-soft); color: var(--warning); }}
.severity.low {{ background: var(--accent-soft); color: var(--accent); }}
.severity.na {{ background: var(--surface-2); color: var(--text-3); }}
.framework-badge {{ display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; margin-right: 4px; }}
.framework-badge.owasp {{ background: var(--danger-soft); color: var(--danger); }}
.section {{ scroll-margin-top: 20px; margin-bottom: 40px; }}
.section-title {{ font-size: 18px; font-weight: 700; margin-bottom: 20px; padding-bottom: 12px; border-bottom: 3px solid var(--accent); display: flex; align-items: center; gap: 12px; }}
.section-title .count-pill {{ font-size: 11px; background: var(--surface-2); color: var(--text-2); padding: 3px 10px; border-radius: 99px; font-weight: 500; }}
code {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; background: var(--surface-2); padding: 2px 6px; border-radius: 4px; white-space: nowrap; }}
.reference-cell {{ text-align: center; }}
.reference-btn {{ display: inline-flex; align-items: center; justify-content: center; width: 28px; height: 28px; background: var(--accent-soft); color: var(--accent); text-decoration: none; border-radius: 6px; border: 1px solid var(--border); transition: all 0.15s; }}
.reference-btn:hover {{ background: var(--accent); color: white; border-color: var(--accent); }}
.reference-btn svg {{ width: 14px; height: 14px; }}
.finding-details, .resolution-text {{ color: var(--text-2); font-size: 12px; line-height: 1.6; }}
.compliance-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }}
.compliance-card {{ background: var(--surface); border: 2px solid var(--border); border-radius: 12px; padding: 20px; }}
.compliance-card h4 {{ font-size: 14px; font-weight: 600; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }}
.compliance-card .rate {{ font-size: 32px; font-weight: 700; }}
.compliance-card .rate.high {{ color: var(--success); }}
.compliance-card .rate.medium {{ color: var(--warning); }}
.compliance-card .rate.low {{ color: var(--danger); }}
.compliance-card .rate.planned {{ color: var(--text-3); font-size: 20px; font-weight: 600; }}
.compliance-card .breakdown {{ margin-top: 12px; font-size: 12px; color: var(--text-2); line-height: 1.6; }}
.compliance-card.planned {{ background: var(--surface-2); }}
.gauge-bar {{ height: 8px; background: var(--surface-2); border-radius: 4px; overflow: hidden; margin-top: 8px; }}
.gauge-fill {{ height: 100%; border-radius: 4px; transition: width 0.3s ease; }}
.gauge-fill.warning {{ background: var(--warning); }}
.gauge-fill.danger {{ background: var(--danger); }}
.gauge-fill.success {{ background: var(--success); }}
.alerts {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; }}
.alert-item {{ display: flex; align-items: center; gap: 12px; padding: 12px 16px; border-radius: 8px; background: var(--surface-2); }}
.alert-item.critical {{ background: var(--danger-soft); border-left: 3px solid var(--danger); }}
.alert-item.warning {{ background: var(--warning-soft); border-left: 3px solid var(--warning); }}
.alert-count {{ font-size: 14px; font-weight: 700; min-width: 56px; text-align: center; font-family: 'JetBrains Mono', monospace; }}
.alert-item.critical .alert-count {{ color: var(--danger); }}
.alert-item.warning .alert-count {{ color: var(--warning); }}
.alert-info {{ flex: 1; min-width: 0; }}
.alert-domain {{ font-weight: 600; font-size: 13px; }}
.alert-category {{ font-size: 11px; color: var(--text-2); margin-top: 2px; }}
@media (max-width: 1024px) {{ .layout {{ grid-template-columns: 1fr; }} .sidebar {{ display: none; }} .metrics {{ grid-template-columns: repeat(2, 1fr); }} }}
@media (max-width: 640px) {{ .metrics {{ grid-template-columns: 1fr; }} .main {{ padding: 20px; }} }}
</style>
</head>
<body>
<div class="layout">

<aside class="sidebar">
    <div class="sidebar-header">
        <h1>AI/ML Security &amp; Compliance</h1>
        <p>Assessment Report</p>
    </div>
    <button class="theme-toggle" id="themeToggle" aria-label="Toggle dark mode">
        <svg class="moon-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M6 .278a.768.768 0 0 1 .08.858 7.208 7.208 0 0 0-.878 3.46c0 4.021 3.278 7.277 7.318 7.277.527 0 1.04-.055 1.533-.16a.787.787 0 0 1 .81.316.733.733 0 0 1-.031.893A8.349 8.349 0 0 1 8.344 16C3.734 16 0 12.286 0 7.71 0 4.266 2.114 1.312 5.124.06A.752.752 0 0 1 6 .278z"/></svg>
        <svg class="sun-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M8 11a3 3 0 1 1 0-6 3 3 0 0 1 0 6zm0 1a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM8 0a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-1 0v-2A.5.5 0 0 1 8 0zm0 13a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-1 0v-2A.5.5 0 0 1 8 13zm8-5a.5.5 0 0 1-.5.5h-2a.5.5 0 0 1 0-1h2a.5.5 0 0 1 .5.5zM3 8a.5.5 0 0 1-.5.5h-2a.5.5 0 0 1 0-1h2A.5.5 0 0 1 3 8zm10.657-5.657a.5.5 0 0 1 0 .707l-1.414 1.415a.5.5 0 1 1-.707-.708l1.414-1.414a.5.5 0 0 1 .707 0zm-9.193 9.193a.5.5 0 0 1 0 .707L3.05 13.657a.5.5 0 0 1-.707-.707l1.414-1.414a.5.5 0 0 1 .707 0zm9.193 2.121a.5.5 0 0 1-.707 0l-1.414-1.414a.5.5 0 0 1 .707-.707l1.414 1.414a.5.5 0 0 1 0 .707zM4.464 4.465a.5.5 0 0 1-.707 0L2.343 3.05a.5.5 0 1 1 .707-.707l1.414 1.414a.5.5 0 0 1 0 .708z"/></svg>
        <span class="theme-label">Dark Mode</span>
    </button>

    <nav class="nav-section">
        <h3>Navigation</h3>
        <a href="#overview" class="nav-item active">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>
            Overview
        </a>
        <a href="#compliance" class="nav-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>
            Compliance
            <span class="count">{len(OWASP_LLM_TOP10)}</span>
        </a>
        <a href="#findings" class="nav-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
            Security Findings
            <span class="count">{total_checks}</span>
        </a>
        <a href="#methodology" class="nav-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            Methodology
        </a>
    </nav>

    <nav class="nav-section">
        <h3>By Service</h3>
        <a href="#findings" class="nav-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l9 4.5v9L12 21 3 16.5v-9L12 3z"/></svg>
            Bedrock
            <span class="count">14</span>
        </a>
        <a href="#findings" class="nav-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"/></svg>
            SageMaker
            <span class="count">25</span>
        </a>
        <a href="#findings" class="nav-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 1v6m0 10v6m11-11h-6m-10 0H1"/></svg>
            AgentCore
            <span class="count">13</span>
        </a>
        <a href="#findings" class="nav-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            OWASP (OW-XX)
            <span class="count">18</span>
        </a>
    </nav>

    <div class="sidebar-footer">
        <p>Generated: {GENERATED_AT}</p>
        <p>Account: {ACCOUNT_ID}</p>
        <p>Region: {REGION}</p>
    </div>
</aside>

<main class="main">

    <section id="overview" class="section">
        <div class="page-header">
            <h2>Security &amp; Compliance Assessment Overview</h2>
            <div class="page-header-meta">
                <span><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/></svg>{GENERATED_AT}</span>
                <span><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>Account {ACCOUNT_ID} · {REGION}</span>
                <span><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 11l3 3L22 4"/></svg>{len(OWASP_LLM_TOP10)} OWASP LLM categories evaluated</span>
            </div>
        </div>

        <div class="metrics">
            <div class="metric">
                <div class="metric-label">Total Checks</div>
                <div class="metric-value">{total_checks}</div>
                <div class="metric-sub">{len(SERVICE_FINDINGS)} service-level + {len(OW_FINDINGS)} OWASP</div>
            </div>
            <div class="metric danger">
                <div class="metric-label">Failed</div>
                <div class="metric-value">{failed}</div>
                <div class="metric-sub">{high_failed} High · {medium_failed} Medium · {low_failed} Low</div>
            </div>
            <div class="metric highlight">
                <div class="metric-label">Passed</div>
                <div class="metric-value">{passed}</div>
                <div class="metric-sub">Resources checked &amp; compliant</div>
            </div>
            <div class="metric">
                <div class="metric-label">Not Applicable</div>
                <div class="metric-value">{na}</div>
                <div class="metric-sub">No resources to assess</div>
            </div>
            <div class="metric purple">
                <div class="metric-label">OWASP Compliance</div>
                <div class="metric-value">{compliance_pct}%</div>
                <div class="metric-sub">{compliant_categories} compliant · {non_compliant_categories} non-compliant · {na_categories} N/A</div>
            </div>
        </div>

        <div class="card">
            <div class="card-header"><h3>Priority Recommendations</h3></div>
            <div class="card-body">
                <div class="alerts">
                    {priority_html}
                </div>
            </div>
        </div>
    </section>

    <section id="compliance" class="section">
        <div class="section-title">
            Compliance Dashboard
            <span class="count-pill">OWASP LLM Top 10 (2025) · 1 active framework, 3 planned</span>
        </div>
        <div class="card">
            <div class="card-body">
                <div class="compliance-grid">
                    <div class="compliance-card">
                        <h4><span class="framework-badge owasp">OWASP</span> OWASP Top 10 for LLM</h4>
                        <div class="rate {'medium' if compliance_pct < 70 else 'high' if compliance_pct >= 80 else 'low'}">{compliance_pct}%</div>
                        <div class="gauge-bar"><div class="gauge-fill {'warning' if compliance_pct < 70 else 'success'}" style="width: {compliance_pct}%;"></div></div>
                        <div class="breakdown">
                            <strong>{compliant_categories}</strong> of {len(OWASP_LLM_TOP10)} categories compliant<br>
                            <span style="color: var(--success);">{compliant_categories} Compliant</span> ·
                            <span style="color: var(--danger);">{non_compliant_categories} Non-Compliant</span> ·
                            <span style="color: var(--text-3);">{na_categories} N/A</span>
                        </div>
                    </div>
                    <div class="compliance-card planned">
                        <h4>NIST AI RMF 1.0</h4>
                        <div class="rate planned">Planned</div>
                        <div class="breakdown">Schema placeholder ready. Mapping work scheduled for follow-up release. Findings will surface a NIST-AI-RMF entry in <code>Compliance_Mappings</code> once enabled.</div>
                    </div>
                    <div class="compliance-card planned">
                        <h4>MITRE ATLAS</h4>
                        <div class="rate planned">Planned</div>
                        <div class="breakdown">Schema placeholder ready. Mapping work scheduled for follow-up release.</div>
                    </div>
                    <div class="compliance-card planned">
                        <h4>HIPAA AI/ML</h4>
                        <div class="rate planned">Planned</div>
                        <div class="breakdown">Schema placeholder ready. Mapping work scheduled for follow-up release.</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- COMBINED OWASP TABLE - merges "Top 10 LLM 2025" + "New OWASP Checks 18 Extensions" per Agasthi's feedback -->
        <div class="card">
            <div class="card-header"><h3>OWASP Top 10 for LLM Applications 2025 — Coverage by Category &amp; Check</h3></div>
            <div class="card-body" style="padding: 0;">
                <div class="table-wrap">
                    <table>
                        <thead>
                        <tr>
                            <th style="width: 8%;">ID</th>
                            <th style="width: 22%;">Vulnerability / Check</th>
                            <th style="width: 30%;">AWS Controls Evaluated</th>
                            <th style="width: 16%;">Status</th>
                            <th style="width: 18%;">Coverage</th>
                            <th style="width: 6%;">Docs</th>
                        </tr>
                        </thead>
                        <tbody>
                        {owasp_combined_rows}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </section>

    <section id="findings" class="section">
        <div class="section-title">
            Security Findings
            <span class="count-pill">{total_checks} checks · {failed} failed · {passed} passed · {na} N/A</span>
        </div>
        <div class="card">
            <div class="card-header"><h3>All findings with remediation guidance &amp; AWS documentation links</h3></div>
            <div class="card-body" style="padding: 0;">
                <div class="table-wrap">
                    <table>
                        <thead>
                        <tr>
                            <th style="width: 7%;">Check</th>
                            <th style="width: 22%;">Finding</th>
                            <th style="width: 26%;">Resolution / Remediation</th>
                            <th style="width: 12%;">Compliance</th>
                            <th style="width: 9%;">Severity</th>
                            <th style="width: 9%;">Status</th>
                            <th style="width: 8%;">Docs</th>
                        </tr>
                        </thead>
                        <tbody>
                        {findings_rows}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </section>

    <section id="methodology" class="section">
        <div class="section-title">Assessment Methodology</div>

        <div class="card">
            <div class="card-header"><h3>How findings are produced</h3></div>
            <div class="card-body">
                <p class="finding-details" style="margin-bottom: 12px;">
                    The framework runs three sets of automated control-plane checks against the account, then layers an OWASP LLM Top 10 (2025) compliance overlay on top of every finding:
                </p>
                <ul style="color: var(--text-2); font-size: 12.5px; line-height: 1.8; padding-left: 22px;">
                    <li><strong style="color: var(--text);">Service-level checks ({len(SERVICE_FINDINGS)}):</strong> 14 Bedrock (BR-XX), 25 SageMaker (SM-XX), 13 AgentCore (AC-XX). Sourced from the {GENERATED_AT} run against account {ACCOUNT_ID}.</li>
                    <li><strong style="color: var(--text);">OWASP-specific checks ({len(OW_FINDINGS)}):</strong> 18 application-aware checks (OW-01 through OW-18) that target gaps the AWS-control-plane checks alone cannot detect — guardrail filter strength, KB ingestion role scope, action-group wildcards, image scanning on push, etc.</li>
                    <li><strong style="color: var(--text);">Compliance overlay:</strong> every finding carries a <code>Compliance_Mappings</code> field (e.g. <code>LLM02 / partial</code>) so the same finding can be filtered by service, by severity, or by OWASP category.</li>
                </ul>
            </div>
        </div>

        <div class="card">
            <div class="card-header"><h3>Severity &amp; Compliance Legend</h3></div>
            <div class="card-body" style="padding: 0;">
                <table style="min-width: 100%;">
                    <thead>
                    <tr>
                        <th style="width: 12%;">Severity</th>
                        <th style="width: 32%;">Security Meaning</th>
                        <th style="width: 12%;">Compliance</th>
                        <th style="width: 32%;">Compliance Meaning</th>
                        <th style="width: 12%;">Remediation Window</th>
                    </tr>
                    </thead>
                    <tbody>
                    <tr>
                        <td style="text-align:center;"><span class="severity high">High</span></td>
                        <td class="finding-details">Direct security risk — IAM / access-control gaps, guardrail bypasses, unencrypted PII paths</td>
                        <td style="text-align:center;"><span class="status non-compliant">Non-Compliant</span></td>
                        <td class="finding-details">At least one mapped check failed in this category</td>
                        <td class="resolution-text"><strong>7 days</strong></td>
                    </tr>
                    <tr>
                        <td style="text-align:center;"><span class="severity medium">Medium</span></td>
                        <td class="finding-details">Defense-in-depth gap — encryption, logging, monitoring</td>
                        <td style="text-align:center;"><span class="status partial">Partial</span></td>
                        <td class="finding-details">Passed but AWS control plane cannot fully assess (app-layer dimensions remain)</td>
                        <td class="resolution-text"><strong>30 days</strong></td>
                    </tr>
                    <tr>
                        <td style="text-align:center;"><span class="severity low">Low</span></td>
                        <td class="finding-details">Best-practice deviation</td>
                        <td style="text-align:center;"><span class="status compliant">Compliant</span></td>
                        <td class="finding-details">All mapped checks passed</td>
                        <td class="resolution-text"><strong>90 days</strong></td>
                    </tr>
                    <tr>
                        <td style="text-align:center;"><span class="severity na">Informational</span></td>
                        <td class="finding-details">Advisory — no action required, or no resources to assess</td>
                        <td style="text-align:center;"><span class="status na">N/A</span></td>
                        <td class="finding-details">No mapped findings or no resources in scope</td>
                        <td class="resolution-text">—</td>
                    </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="card">
            <div class="card-header"><h3>Important Caveats</h3></div>
            <div class="card-body">
                <ul style="color: var(--text-2); font-size: 12.5px; line-height: 1.8; padding-left: 22px;">
                    <li><strong style="color: var(--text);">Severity reflects general AWS security best practice.</strong> Your organization's compliance requirements or risk tolerance may push individual findings up or down.</li>
                    <li><strong style="color: var(--text);">Coverage type matters.</strong> "Full" coverage means the AWS control-plane signal alone is sufficient. "Partial-app-layer" means the check infers a property and the application owner should validate at the application tier (e.g. system-prompt protection, KB metadata filtering).</li>
                    <li><strong style="color: var(--text);">N/A is not a pass.</strong> When no resources of a type exist (no Knowledge Bases, no Bedrock Agents, no Guardrails), the dependent OWASP checks come back N/A. They will run on the next assessment after those resources are created.</li>
                </ul>
            </div>
        </div>
    </section>

</main>
</div>

<script>
// Theme toggle
const t = document.getElementById('themeToggle'), root = document.documentElement;
const lab = t.querySelector('.theme-label');
const cur = localStorage.getItem('aiml-report-theme');
if (cur === 'dark') {{ root.setAttribute('data-theme', 'dark'); lab.textContent = 'Light Mode'; }}
t.addEventListener('click', () => {{
    if (root.getAttribute('data-theme') === 'dark') {{
        root.removeAttribute('data-theme');
        localStorage.setItem('aiml-report-theme', 'light');
        lab.textContent = 'Dark Mode';
    }} else {{
        root.setAttribute('data-theme', 'dark');
        localStorage.setItem('aiml-report-theme', 'dark');
        lab.textContent = 'Light Mode';
    }}
}});

// Active nav tracking
const navItems = document.querySelectorAll('.sidebar .nav-item');
const sections = document.querySelectorAll('.section');
navItems.forEach(item => item.addEventListener('click', e => {{
    const href = item.getAttribute('href');
    if (href && href.startsWith('#')) {{
        const tgt = document.querySelector(href);
        if (tgt) {{
            e.preventDefault();
            tgt.scrollIntoView({{behavior: 'smooth'}});
            navItems.forEach(n => n.classList.remove('active'));
            navItems.forEach(n => {{ if (n.getAttribute('href') === href) n.classList.add('active'); }});
        }}
    }}
}}));
window.addEventListener('scroll', () => {{
    let cur = '';
    sections.forEach(s => {{ if (window.pageYOffset >= s.offsetTop - 100) cur = s.getAttribute('id'); }});
    if (cur) navItems.forEach(n => {{
        n.classList.remove('active');
        if (n.getAttribute('href') === '#' + cur) n.classList.add('active');
    }});
}});
</script>
</body>
</html>
"""

OUT = "/Users/biswasrp/resco-aiml-assessment/security_assessment_owasp_676206921018.html"
with open(OUT, "w") as f:
    f.write(HTML)

print(f"Wrote: {OUT}")
print(f"Size: {os.path.getsize(OUT) // 1024} KB")
print()
print(f"Total checks: {total_checks}")
print(f"  Service-level: {len(SERVICE_FINDINGS)} (BR={sum(1 for f in SERVICE_FINDINGS if f['check_id'].startswith('BR'))}, SM={sum(1 for f in SERVICE_FINDINGS if f['check_id'].startswith('SM'))}, AC={sum(1 for f in SERVICE_FINDINGS if f['check_id'].startswith('AC'))})")
print(f"  OWASP overlay: {len(OW_FINDINGS)}")
print(f"Failed: {failed} (High={high_failed} Medium={medium_failed} Low={low_failed})")
print(f"Passed: {passed}")
print(f"N/A: {na}")
print(f"OWASP categories: {compliance_pct}% compliant ({compliant_categories}/{len(OWASP_LLM_TOP10)})")
