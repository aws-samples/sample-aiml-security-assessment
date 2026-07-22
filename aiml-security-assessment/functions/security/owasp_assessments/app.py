"""OWASP Top 10 for LLM assessment Lambda.

This Lambda runs after the per-service Lambdas (Bedrock, SageMaker, AgentCore,
FinServ) have written their region CSVs. It:

1. Reads those CSVs from S3.
2. Applies OWASP_CHECK_MAPPINGS to emit OW-01..OW-10 rows derived from
   existing BR/SM/AC/FS findings.
3. Runs two net-new checks for LLM07 (System Prompt Leakage):
   - OW-11: flag Lambda functions whose env vars look like embedded system prompts
   - OW-12: verify a Bedrock guardrail denies system-prompt-disclosure topics
4. Writes owasp_security_report_<execution_id>_<region>.csv to the assessment bucket.

Gated at the Step Functions layer via the `OWASP Enabled?` Choice state.
"""

import boto3
import csv
import logging
import os
from io import StringIO
from typing import Any, Dict, List, Optional

from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError

from schema import create_finding

boto3_config = Config(retries=dict(max_attempts=10, mode="adaptive"))

logger = logging.getLogger()
logger.setLevel(logging.ERROR)


OWASP_LLM_TOP10_URL = "https://genai.owasp.org/llm-top-10/"
OWASP_LLM_REFERENCE_URLS = {
    "OW-01": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    "OW-02": (
        "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/"
    ),
    "OW-03": "https://genai.owasp.org/llmrisk/llm032025-supply-chain/",
    "OW-04": "https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/",
    "OW-05": ("https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/"),
    "OW-06": "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
    "OW-07": "https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/",
    "OW-08": (
        "https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/"
    ),
    "OW-09": "https://genai.owasp.org/llmrisk/llm092025-misinformation/",
    "OW-10": "https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/",
    # Native LLM07 checks.
    "OW-11": "https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/",
    "OW-12": "https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/",
}


def get_owasp_reference_url(check_id: str) -> str:
    """Return the OWASP category page that matches an emitted OW-XX check."""
    return OWASP_LLM_REFERENCE_URLS.get(check_id, OWASP_LLM_TOP10_URL)


# Heuristic tuning for OW-11 (system prompt embedded in Lambda env var).
# Uses multi-word prompt-shaped phrases (not single common words) and requires
# >= 2 distinct phrase matches to keep false positives low against ordinary
# configuration blobs (policy JSON, log format strings, runbook text) that
# happen to contain isolated words like "system" or "instruction".
SYSTEM_PROMPT_HEURISTIC_MIN_CHARS = 200
SYSTEM_PROMPT_HEURISTIC_PHRASES = (
    "you are a",
    "you are an",
    "your role",
    "your task",
    "you must",
    "you should",
    "helpful assistant",
    "as an assistant",
    "system prompt",
    "system instruction",
    "never reveal",
    "do not reveal",
    "internal instruction",
    "respond politely",
)
SYSTEM_PROMPT_HEURISTIC_MIN_PHRASE_MATCHES = 2

# Heuristic tuning for OW-12 (system-prompt-disclosure denied topic).
SYSTEM_PROMPT_DENY_TOKENS = (
    "system prompt",
    "instruction disclosure",
    "prompt leakage",
    "reveal instructions",
    "internal prompt",
)

# Error codes returned when a region is not enabled / not accessible.
REGION_UNAVAILABLE_ERROR_CODES = {
    "UnrecognizedClientException",
    "InvalidClientTokenId",
    "AuthFailure",
    "OptInRequired",
}

ACCESS_DENIED_ERROR_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
}


# ---------------------------------------------------------------------------
# OWASP_CHECK_MAPPINGS
#
# For each source Check_ID (BR-*/SM-*/AC-*/FS-*), a list of OW-## rows to
# emit. Values are LISTS (not scalars like the AG-* mapping) because one
# source check may contribute to multiple OWASP categories. Each item in
# the list becomes one OW row per source finding row.
#
# Disclaimer: mappings are PRELIMINARY and ILLUSTRATIVE. Each firm should
# validate them against its own interpretation of the OWASP LLM Top 10
# 2025 controls before relying on them as evidence.
# ---------------------------------------------------------------------------
OWASP_CHECK_MAPPINGS: Dict[str, List[Dict[str, str]]] = {
    # LLM01 Prompt Injection
    "BR-23": [
        {
            "check_id": "OW-01",
            "owasp_category": "LLM01:2025 Prompt Injection",
            "finding": "OWASP LLM01: Guardrail Content Filter Coverage",
            "resolution": "Enable Bedrock guardrail content filters (HATE, VIOLENCE, SEXUAL, INSULTS, MISCONDUCT) at MEDIUM strength or higher, and set the PROMPT_ATTACK filter at STANDARD tier.",
        }
    ],
    "BR-27": [
        {
            "check_id": "OW-01",
            "owasp_category": "LLM01:2025 Prompt Injection",
            "finding": "OWASP LLM01: Contextual Grounding Guardrail",
            "resolution": "Enable Bedrock guardrail contextual grounding checks to reduce the surface for indirect prompt injection through retrieved context.",
        },
        {
            "check_id": "OW-04",
            "owasp_category": "LLM04:2025 Data and Model Poisoning",
            "finding": "OWASP LLM04: Contextual Grounding on Retrieved Data",
            "resolution": "Enable contextual grounding guardrail filters so retrieved context that diverges from ground truth is filtered before reaching the model.",
        },
        {
            "check_id": "OW-09",
            "owasp_category": "LLM09:2025 Misinformation",
            "finding": "OWASP LLM09: Contextual Grounding for Faithfulness",
            "resolution": "Set the contextual grounding filter threshold to at least 0.70 to reduce hallucinated responses.",
        },
    ],
    "BR-04": [
        {
            "check_id": "OW-01",
            "owasp_category": "LLM01:2025 Prompt Injection",
            "finding": "OWASP LLM01: Model Invocation Logging",
            "resolution": "Enable Bedrock model invocation logging to S3 and/or CloudWatch Logs so injection attempts and their surrounding context are captured for detection and post-incident analysis.",
        },
        {
            "check_id": "OW-07",
            "owasp_category": "LLM07:2025 System Prompt Leakage",
            "finding": "OWASP LLM07: Model Invocation Logging",
            "resolution": "Enable Bedrock model invocation logging so prompt-extraction attempts against the system prompt are auditable after the fact.",
        },
    ],
    "FS-51": [
        {
            "check_id": "OW-01",
            "owasp_category": "LLM01:2025 Prompt Injection",
            "finding": "OWASP LLM01: PROMPT_ATTACK Filter at Standard Tier",
            "resolution": "Set guardrail PROMPT_ATTACK filter to Standard tier with inputStrength=HIGH.",
        }
    ],
    "FS-52": [
        {
            "check_id": "OW-01",
            "owasp_category": "LLM01:2025 Prompt Injection",
            "finding": "OWASP LLM01: Bedrock-Calling Lambda Runtimes",
            "resolution": "Ensure Lambda functions that invoke Bedrock use a supported (non-deprecated) runtime to receive security patches.",
        }
    ],
    "FS-53": [
        {
            "check_id": "OW-01",
            "owasp_category": "LLM01:2025 Prompt Injection",
            "finding": "OWASP LLM01: WAF SQLi & KnownBadInputs Coverage",
            "resolution": "Add AWS Managed Rule Groups AWSManagedRulesSQLiRuleSet and AWSManagedRulesKnownBadInputsRuleSet to the WAF Web ACL guarding GenAI ingress.",
        }
    ],
    "FS-54": [
        {
            "check_id": "OW-01",
            "owasp_category": "LLM01:2025 Prompt Injection",
            "finding": "OWASP LLM01: Adversarial Testing Evidence",
            "resolution": "Track adversarial / red-team penetration test evidence for the GenAI application via resource tags or an equivalent audit trail.",
        }
    ],
    "FS-69": [
        {
            "check_id": "OW-01",
            "owasp_category": "LLM01:2025 Prompt Injection",
            "finding": "OWASP LLM01: Prompt-Input Validation Lambda",
            "resolution": "Deploy a prompt-input validation Lambda in front of Bedrock invocations to sanitise untrusted input before it reaches the model.",
        }
    ],
    # LLM02 Sensitive Information Disclosure
    "BR-26": [
        {
            "check_id": "OW-02",
            "owasp_category": "LLM02:2025 Sensitive Information Disclosure",
            "finding": "OWASP LLM02: Guardrail PII / Regex Filters",
            "resolution": "Configure guardrail sensitiveInformationPolicy with PII entities and regex patterns; set outputAction=ANONYMIZE or BLOCK.",
        }
    ],
    "FS-43": [
        {
            "check_id": "OW-02",
            "owasp_category": "LLM02:2025 Sensitive Information Disclosure",
            "finding": "OWASP LLM02: CloudWatch Log Data Protection Policies",
            "resolution": "Apply a CloudWatch Logs data protection policy to log groups that receive Bedrock invocation logs.",
        }
    ],
    "FS-44": [
        {
            "check_id": "OW-02",
            "owasp_category": "LLM02:2025 Sensitive Information Disclosure",
            "finding": "OWASP LLM02: Macie Sensitive-Data Discovery",
            "resolution": "Enable Amazon Macie with automated discovery on S3 buckets that hold training or knowledge-base data.",
        }
    ],
    "FS-45": [
        {
            "check_id": "OW-02",
            "owasp_category": "LLM02:2025 Sensitive Information Disclosure",
            "finding": "OWASP LLM02: Guardrail PII Entities Coverage",
            "resolution": "Add the required PII entity types to the guardrail sensitiveInformationPolicy so PII in prompts/responses is filtered.",
        }
    ],
    "FS-46": [
        {
            "check_id": "OW-02",
            "owasp_category": "LLM02:2025 Sensitive Information Disclosure",
            "finding": "OWASP LLM02: S3 Data-Classification Tagging",
            "resolution": "Tag training and knowledge-base S3 buckets with a data-classification tag so downstream automations enforce controls consistent with the sensitivity level.",
        }
    ],
    "SM-03": [
        {
            "check_id": "OW-02",
            "owasp_category": "LLM02:2025 Sensitive Information Disclosure",
            "finding": "OWASP LLM02: SageMaker Data Encryption",
            "resolution": "Configure SageMaker notebooks, domains, and training jobs to use customer-managed KMS keys and encryption in transit for sensitive training and inference data.",
        }
    ],
    "SM-15": [
        {
            "check_id": "OW-02",
            "owasp_category": "LLM02:2025 Sensitive Information Disclosure",
            "finding": "OWASP LLM02: SageMaker Feature Store Encryption",
            "resolution": "Encrypt SageMaker Feature Store offline stores with customer-managed KMS keys so sensitive feature data is protected at rest.",
        }
    ],
    # LLM03 Supply Chain
    "BR-30": [
        {
            "check_id": "OW-03",
            "owasp_category": "LLM03:2025 Supply Chain",
            "finding": "OWASP LLM03: Imported-Model KMS Provenance",
            "resolution": "Encrypt imported Bedrock models with a customer-managed KMS key to preserve provenance and access control across model artefacts.",
        }
    ],
    "FS-12": [
        {
            "check_id": "OW-03",
            "owasp_category": "LLM03:2025 Supply Chain",
            "finding": "OWASP LLM03: SCP-Enforced Model Allowlist",
            "resolution": "Attach an Organizations SCP that denies bedrock:InvokeModel* except for allowlisted bedrock:ModelId values.",
        }
    ],
    "FS-13": [
        {
            "check_id": "OW-03",
            "owasp_category": "LLM03:2025 Supply Chain",
            "finding": "OWASP LLM03: Custom-Model Provenance Tags",
            "resolution": "Tag every Bedrock custom model with model-source, model-version, approval-date, and risk-tier so provenance is auditable.",
        }
    ],
    "FS-14": [
        {
            "check_id": "OW-03",
            "owasp_category": "LLM03:2025 Supply Chain",
            "finding": "OWASP LLM03: Config Rules for Model Onboarding",
            "resolution": "Deploy AWS Config rules that enforce required tags and configuration on AWS::Bedrock::* resources at creation time.",
        }
    ],
    "FS-15": [
        {
            "check_id": "OW-03",
            "owasp_category": "LLM03:2025 Supply Chain",
            "finding": "OWASP LLM03: Adversarial Evaluation Coverage",
            "resolution": "Run Bedrock evaluation jobs that include adversarial and safety datasets before promoting a model to production.",
        }
    ],
    "FS-16": [
        {
            "check_id": "OW-03",
            "owasp_category": "LLM03:2025 Supply Chain",
            "finding": "OWASP LLM03: ECR Image Scanning",
            "resolution": "Enable Amazon Inspector enhanced scanning or scan-on-push on ECR repositories that hold model / agent container images.",
        }
    ],
    "BR-33": [
        {
            "check_id": "OW-03",
            "owasp_category": "LLM03:2025 Supply Chain",
            "finding": "OWASP LLM03: Inspector Lambda Code Scanning",
            "resolution": "Enable Amazon Inspector Lambda standard scanning and Lambda code scanning so vulnerable dependencies and hardcoded secrets in Bedrock-calling Lambda functions are detected as part of the GenAI supply chain.",
        }
    ],
    "SM-01": [
        {
            "check_id": "OW-03",
            "owasp_category": "LLM03:2025 Supply Chain",
            "finding": "OWASP LLM03: SageMaker Internet Exposure",
            "resolution": "Disable direct internet access on SageMaker notebooks and configure domains for VPC-only access to reduce supply-chain exposure from unmanaged network paths.",
        }
    ],
    "SM-10": [
        {
            "check_id": "OW-03",
            "owasp_category": "LLM03:2025 Supply Chain",
            "finding": "OWASP LLM03: SageMaker Notebook VPC Deployment",
            "resolution": "Deploy SageMaker notebook instances inside a VPC so package, data, and model artifact access can be controlled through private network paths.",
        }
    ],
    "SM-11": [
        {
            "check_id": "OW-03",
            "owasp_category": "LLM03:2025 Supply Chain",
            "finding": "OWASP LLM03: SageMaker Model Network Isolation",
            "resolution": "Enable network isolation on SageMaker models so inference containers cannot make unmanaged outbound calls that alter dependencies or exfiltrate model artifacts.",
        },
        {
            "check_id": "OW-10",
            "owasp_category": "LLM10:2025 Unbounded Consumption",
            "finding": "OWASP LLM10: SageMaker Model Outbound Network Control",
            "resolution": "Enable SageMaker model network isolation to prevent deployed model containers from making uncontrolled outbound calls that can amplify consumption or abuse downstream services.",
        },
    ],
    "SM-14": [
        {
            "check_id": "OW-03",
            "owasp_category": "LLM03:2025 Supply Chain",
            "finding": "OWASP LLM03: SageMaker Container Repository Access",
            "resolution": "Configure SageMaker models to pull container images from private ECR repositories through VPC repository access instead of platform or public registry paths.",
        }
    ],
    "SM-21": [
        {
            "check_id": "OW-03",
            "owasp_category": "LLM03:2025 Supply Chain",
            "finding": "OWASP LLM03: SageMaker AutoML Network Isolation",
            "resolution": "Enable network isolation on AutoML jobs so generated training containers cannot fetch unapproved dependencies or send data over unmanaged network paths.",
        }
    ],
    "SM-25": [
        {
            "check_id": "OW-03",
            "owasp_category": "LLM03:2025 Supply Chain",
            "finding": "OWASP LLM03: SageMaker ML Lineage Tracking",
            "resolution": "Use SageMaker Experiments and lineage associations to track training runs, parameters, artifacts, and model package provenance across the ML supply chain.",
        },
        {
            "check_id": "OW-04",
            "owasp_category": "LLM04:2025 Data and Model Poisoning",
            "finding": "OWASP LLM04: SageMaker ML Lineage Tracking",
            "resolution": "Track SageMaker training lineage from source data through model artifacts so poisoned data or model versions can be traced and remediated.",
        },
    ],
    # LLM04 Data and Model Poisoning
    "BR-25": [
        {
            "check_id": "OW-04",
            "owasp_category": "LLM04:2025 Data and Model Poisoning",
            "finding": "OWASP LLM04: RAG Evaluation Coverage",
            "resolution": "Run Bedrock RAG evaluation jobs against knowledge bases regularly to detect degraded retrieval or poisoned context.",
        },
        {
            "check_id": "OW-09",
            "owasp_category": "LLM09:2025 Misinformation",
            "finding": "OWASP LLM09: RAG Evaluation for Faithfulness",
            "resolution": "Include faithfulness and correctness metrics in RAG evaluation jobs to catch misinformation before deploying knowledge-base updates.",
        },
    ],
    "FS-20": [
        {
            "check_id": "OW-04",
            "owasp_category": "LLM04:2025 Data and Model Poisoning",
            "finding": "OWASP LLM04: Feature Store Offline Recovery",
            "resolution": "Enable OfflineStoreConfig on SageMaker Feature Groups so features have a durable, point-in-time record for rollback after a poisoning event.",
        }
    ],
    "FS-21": [
        {
            "check_id": "OW-04",
            "owasp_category": "LLM04:2025 Data and Model Poisoning",
            "finding": "OWASP LLM04: Training-Data Versioning",
            "resolution": "Enable S3 versioning on training-data buckets so poisoned data can be reverted.",
        }
    ],
    "FS-42": [
        {
            "check_id": "OW-04",
            "owasp_category": "LLM04:2025 Data and Model Poisoning",
            "finding": "OWASP LLM04: SageMaker Model Card Documentation",
            "resolution": "Create SageMaker Model Cards for production models that document intended use, training data provenance, and bias/fairness evaluations so poisoned or drifted models are detectable against a documented baseline.",
        },
        {
            "check_id": "OW-09",
            "owasp_category": "LLM09:2025 Misinformation",
            "finding": "OWASP LLM09: SageMaker Model Card Documentation",
            "resolution": "Document each production model's intended use, known limitations, and evaluation results in a SageMaker Model Card so misinformation risks tied to model behaviour are traceable to a reviewed system card.",
        },
    ],
    "SM-07": [
        {
            "check_id": "OW-04",
            "owasp_category": "LLM04:2025 Data and Model Poisoning",
            "finding": "OWASP LLM04: SageMaker Model Monitor Coverage",
            "resolution": "Configure active SageMaker Model Monitor schedules so data-quality and model-quality regressions caused by poisoned inputs or drift are detected.",
        },
        {
            "check_id": "OW-09",
            "owasp_category": "LLM09:2025 Misinformation",
            "finding": "OWASP LLM09: SageMaker Model Monitor Coverage",
            "resolution": "Configure SageMaker Model Monitor schedules for production models so quality regressions that can produce incorrect outputs are detected.",
        },
    ],
    "SM-22": [
        {
            "check_id": "OW-04",
            "owasp_category": "LLM04:2025 Data and Model Poisoning",
            "finding": "OWASP LLM04: SageMaker Model Approval Workflow",
            "resolution": "Require SageMaker Model Registry approval workflows before production deployment so poisoned or unreviewed model versions are not promoted automatically.",
        },
        {
            "check_id": "OW-09",
            "owasp_category": "LLM09:2025 Misinformation",
            "finding": "OWASP LLM09: SageMaker Model Approval Workflow",
            "resolution": "Use SageMaker Model Registry approval workflows to ensure model behavior, intended use, and validation evidence are reviewed before production release.",
        },
    ],
    "SM-23": [
        {
            "check_id": "OW-04",
            "owasp_category": "LLM04:2025 Data and Model Poisoning",
            "finding": "OWASP LLM04: SageMaker Model Drift Detection",
            "resolution": "Enable SageMaker Model Monitor drift detection for production endpoints so poisoning, data drift, and model-quality degradation are identified.",
        },
        {
            "check_id": "OW-09",
            "owasp_category": "LLM09:2025 Misinformation",
            "finding": "OWASP LLM09: SageMaker Model Drift Detection",
            "resolution": "Configure data-quality and model-quality monitoring for SageMaker endpoints so degraded model behavior that can produce misinformation is detected.",
        },
    ],
    # LLM05 Improper Output Handling
    "FS-55": [
        {
            "check_id": "OW-05",
            "owasp_category": "LLM05:2025 Improper Output Handling",
            "finding": "OWASP LLM05: Output-Validation Lambda",
            "resolution": "Deploy an output-validation / sanitisation Lambda between the model response and any downstream consumer to filter injection payloads in generated output.",
        }
    ],
    "FS-56": [
        {
            "check_id": "OW-05",
            "owasp_category": "LLM05:2025 Improper Output Handling",
            "finding": "OWASP LLM05: WAF XSS Protection",
            "resolution": "Ensure the WAF Web ACL guarding GenAI ingress includes AWSManagedRulesCommonRuleSet (XSS) or an equivalent XssMatchStatement.",
        }
    ],
    "FS-57": [
        {
            "check_id": "OW-05",
            "owasp_category": "LLM05:2025 Improper Output Handling",
            "finding": "OWASP LLM05: Output Encoding Libraries",
            "resolution": "Ensure Lambdas that render model output use a well-known output-encoding library appropriate to the downstream sink (HTML, SQL, shell, etc.).",
        }
    ],
    "FS-58": [
        {
            "check_id": "OW-05",
            "owasp_category": "LLM05:2025 Improper Output Handling",
            "finding": "OWASP LLM05: Step Functions Output Schema Validation",
            "resolution": "Add explicit schema-validation states in Step Functions workflows that consume model output.",
        }
    ],
    # LLM06 Excessive Agency
    "BR-21": [
        {
            "check_id": "OW-06",
            "owasp_category": "LLM06:2025 Excessive Agency",
            "finding": "OWASP LLM06: Agent Action-Group Least Privilege",
            "resolution": "Restrict agent action-group Lambda roles to only the specific actions and resources needed for each tool.",
        }
    ],
    "BR-28": [
        {
            "check_id": "OW-06",
            "owasp_category": "LLM06:2025 Excessive Agency",
            "finding": "OWASP LLM06: Bedrock Agent Guardrail Association",
            "resolution": "Attach an approved Bedrock guardrail to every Bedrock agent so autonomous actions are filtered consistently.",
        }
    ],
    "BR-29": [
        {
            "check_id": "OW-06",
            "owasp_category": "LLM06:2025 Excessive Agency",
            "finding": "OWASP LLM06: Agent Idle Session TTL",
            "resolution": "Set idleSessionTTLInSeconds to a conservative value (e.g., <= 3600) so long-lived agent sessions cannot be reused.",
        }
    ],
    "AC-02": [
        {
            "check_id": "OW-06",
            "owasp_category": "LLM06:2025 Excessive Agency",
            "finding": "OWASP LLM06: AgentCore IAM Least Privilege",
            "resolution": "Remove AmazonBedrockAgentCoreFullAccess (or equivalents) from identities that only need read/execute permissions.",
        }
    ],
    "AC-10": [
        {
            "check_id": "OW-06",
            "owasp_category": "LLM06:2025 Excessive Agency",
            "finding": "OWASP LLM06: AgentCore Resource-Based Policies",
            "resolution": "Attach resource-based policies to AgentCore runtimes and gateways so caller identities are constrained.",
        }
    ],
    "FS-07": [
        {
            "check_id": "OW-06",
            "owasp_category": "LLM06:2025 Excessive Agency",
            "finding": "OWASP LLM06: Agent Execution Role Least Privilege",
            "resolution": "Remove wildcard sensitive actions from Bedrock Agent execution roles.",
        }
    ],
    "FS-08": [
        {
            "check_id": "OW-06",
            "owasp_category": "LLM06:2025 Excessive Agency",
            "finding": "OWASP LLM06: AgentCore Gateway Policy Engine",
            "resolution": "Set AgentCore Gateway policyEngineConfiguration.mode to ENFORCE and require identity propagation on Runtimes.",
        }
    ],
    "FS-09": [
        {
            "check_id": "OW-06",
            "owasp_category": "LLM06:2025 Excessive Agency",
            "finding": "OWASP LLM06: Agent Tool Concurrency Limits",
            "resolution": "Set reserved concurrency on agent action-group Lambdas so a runaway agent cannot exhaust downstream capacity.",
        }
    ],
    "FS-10": [
        {
            "check_id": "OW-06",
            "owasp_category": "LLM06:2025 Excessive Agency",
            "finding": "OWASP LLM06: Human-in-the-Loop Callback States",
            "resolution": "Insert Step Functions .waitForTaskToken callback states before any high-risk agent-triggered action.",
        }
    ],
    "FS-67": [
        {
            "check_id": "OW-06",
            "owasp_category": "LLM06:2025 Excessive Agency",
            "finding": "OWASP LLM06: Agent Transaction Thresholds",
            "resolution": "Encode agent transaction thresholds in Cedar policies or Lambda configuration so per-action limits are enforced.",
        }
    ],
    # LLM07 System Prompt Leakage (partial mapping — main coverage from OW-11/OW-12)
    "BR-16": [
        {
            "check_id": "OW-07",
            "owasp_category": "LLM07:2025 System Prompt Leakage",
            "finding": "OWASP LLM07: Guardrail Standard Tier for Prompt Leakage",
            "resolution": "Set guardrail contentPolicy.tier.tierName to STANDARD; Standard tier additionally detects prompt-leakage attacks.",
        }
    ],
    "BR-07": [
        {
            "check_id": "OW-07",
            "owasp_category": "LLM07:2025 System Prompt Leakage",
            "finding": "OWASP LLM07: Bedrock Prompt Management Adoption",
            "resolution": "Manage system prompts through Amazon Bedrock Prompt Management rather than inline code or Lambda env vars so prompts are versioned, IAM-scoped, and auditable — reducing the blast radius of a prompt-leakage incident.",
        }
    ],
    # LLM08 Vector and Embedding Weaknesses
    "BR-20": [
        {
            "check_id": "OW-08",
            "owasp_category": "LLM08:2025 Vector and Embedding Weaknesses",
            "finding": "OWASP LLM08: Managed Knowledge-Base CMK Encryption",
            "resolution": "Configure the Bedrock Managed Knowledge Base to use a customer-managed KMS key for storage encryption.",
        }
    ],
    "FS-22": [
        {
            "check_id": "OW-08",
            "owasp_category": "LLM08:2025 Vector and Embedding Weaknesses",
            "finding": "OWASP LLM08: KB IAM Scope",
            "resolution": "Scope Knowledge Base IAM roles to specific KB ARNs; remove wildcard bedrock:* on KB actions.",
        }
    ],
    "FS-24": [
        {
            "check_id": "OW-08",
            "owasp_category": "LLM08:2025 Vector and Embedding Weaknesses",
            "finding": "OWASP LLM08: KB Metadata Filtering",
            "resolution": "Define Knowledge Base metadata fields so tenant / document-level filtering can be applied at retrieval time.",
        }
    ],
    "FS-25": [
        {
            "check_id": "OW-08",
            "owasp_category": "LLM08:2025 Vector and Embedding Weaknesses",
            "finding": "OWASP LLM08: OpenSearch Serverless Encryption",
            "resolution": "Use a customer-managed KMS key on the OpenSearch Serverless encryption policy for the vector collection.",
        }
    ],
    "FS-26": [
        {
            "check_id": "OW-08",
            "owasp_category": "LLM08:2025 Vector and Embedding Weaknesses",
            "finding": "OWASP LLM08: OpenSearch Serverless Network Policy",
            "resolution": "Set AllowFromPublic=false on the OpenSearch Serverless network policy and restrict access to bedrock.amazonaws.com or a specific VPC endpoint.",
        }
    ],
    # LLM09 Misinformation
    "BR-18": [
        {
            "check_id": "OW-09",
            "owasp_category": "LLM09:2025 Misinformation",
            "finding": "OWASP LLM09: Model Evaluation Jobs",
            "resolution": "Run Bedrock model evaluation jobs that include correctness and safety datasets.",
        }
    ],
    "FS-31": [
        {
            "check_id": "OW-09",
            "owasp_category": "LLM09:2025 Misinformation",
            "finding": "OWASP LLM09: Knowledge-Base Ingestion Freshness",
            "resolution": "Sync Knowledge Base data sources on a schedule (weekly at most); stale KB content increases hallucination risk.",
        }
    ],
    "FS-32": [
        {
            "check_id": "OW-09",
            "owasp_category": "LLM09:2025 Misinformation",
            "finding": "OWASP LLM09: Source Attribution",
            "resolution": "Return citations in RetrieveAndGenerate responses so end users can verify grounding.",
        }
    ],
    "FS-33": [
        {
            "check_id": "OW-09",
            "owasp_category": "LLM09:2025 Misinformation",
            "finding": "OWASP LLM09: KB S3 Data-Source Integrity",
            "resolution": "Enable S3 versioning + notifications on Knowledge Base data-source buckets so ingest failures are visible.",
        }
    ],
    "FS-47": [
        {
            "check_id": "OW-09",
            "owasp_category": "LLM09:2025 Misinformation",
            "finding": "OWASP LLM09: Grounding Filter Threshold",
            "resolution": "Set the contextual grounding filter threshold to at least 0.70 on guardrails used for RAG workflows.",
        }
    ],
    "FS-48": [
        {
            "check_id": "OW-09",
            "owasp_category": "LLM09:2025 Misinformation",
            "finding": "OWASP LLM09: Active Knowledge Base Present",
            "resolution": "Deploy at least one ACTIVE Knowledge Base when Bedrock models are used, so grounded retrieval is available.",
        }
    ],
    "SM-06": [
        {
            "check_id": "OW-09",
            "owasp_category": "LLM09:2025 Misinformation",
            "finding": "OWASP LLM09: SageMaker Clarify Evaluation",
            "resolution": "Use SageMaker Clarify to evaluate bias and explainability for models whose generated outputs can influence user decisions.",
        }
    ],
    # LLM10 Unbounded Consumption
    "BR-22": [
        {
            "check_id": "OW-10",
            "owasp_category": "LLM10:2025 Unbounded Consumption",
            "finding": "OWASP LLM10: Service Quota Throttling Limits",
            "resolution": "Customise Bedrock TPM / RPM service quotas above the account default to establish an explicit consumption ceiling.",
        }
    ],
    "BR-32": [
        {
            "check_id": "OW-10",
            "owasp_category": "LLM10:2025 Unbounded Consumption",
            "finding": "OWASP LLM10: CloudWatch Consumption Alarms",
            "resolution": "Create CloudWatch alarms on Bedrock InvocationThrottles, InputTokenCount, OutputTokenCount, and EstimatedTPMQuotaUsage.",
        }
    ],
    "FS-01": [
        {
            "check_id": "OW-10",
            "owasp_category": "LLM10:2025 Unbounded Consumption",
            "finding": "OWASP LLM10: WAF Rate-Based & Shield Protection",
            "resolution": "Add a WAF RateBasedStatement plus a SizeConstraintStatement on the GenAI ingress and subscribe to AWS Shield Advanced.",
        }
    ],
    "FS-02": [
        {
            "check_id": "OW-10",
            "owasp_category": "LLM10:2025 Unbounded Consumption",
            "finding": "OWASP LLM10: API Gateway Usage Plans",
            "resolution": "Attach API Gateway Usage Plans with non-zero rateLimit / burstLimit to any REST APIs that proxy Bedrock.",
        }
    ],
    "FS-03": [
        {
            "check_id": "OW-10",
            "owasp_category": "LLM10:2025 Unbounded Consumption",
            "finding": "OWASP LLM10: Bedrock TPM/RPM Quotas Customised",
            "resolution": "Customise Bedrock service quotas above the account default so consumption is explicitly bounded.",
        }
    ],
    "FS-04": [
        {
            "check_id": "OW-10",
            "owasp_category": "LLM10:2025 Unbounded Consumption",
            "finding": "OWASP LLM10: Cost Anomaly Detection",
            "resolution": "Configure AWS Cost Anomaly Detection monitors that include Bedrock and SageMaker.",
        }
    ],
    "FS-05": [
        {
            "check_id": "OW-10",
            "owasp_category": "LLM10:2025 Unbounded Consumption",
            "finding": "OWASP LLM10: Token / Throttle Alarms",
            "resolution": "Create CloudWatch alarms on the Bedrock namespace for InvocationThrottles and token counters.",
        }
    ],
    "FS-06": [
        {
            "check_id": "OW-10",
            "owasp_category": "LLM10:2025 Unbounded Consumption",
            "finding": "OWASP LLM10: AWS Budgets with Bedrock Filters",
            "resolution": "Configure AWS Budgets with FilterExpression / CostFilters targeting Bedrock or SageMaker spend, with an alerting SNS action.",
        }
    ],
    "FS-68": [
        {
            "check_id": "OW-10",
            "owasp_category": "LLM10:2025 Unbounded Consumption",
            "finding": "OWASP LLM10: API Gateway Request Body Size Limits",
            "resolution": "Configure API Gateway request validation or an equivalent ingress control so GenAI endpoints reject oversized request bodies before they can drive excessive model consumption.",
        }
    ],
}


def is_region_unsupported(error: Exception) -> bool:
    """Detect a 'this API/feature is not available in this region' error."""
    text = str(error)
    return "UnknownOperation" in text or "Unknown operation" in text


def _list_all_items(
    client,
    operation_name: str,
    result_key: str,
    *,
    max_results_param: str = "maxResults",
    token_param: str = "nextToken",
    token_response_keys: tuple = ("nextToken", "NextToken"),
    max_results: int = 100,
    **kwargs,
) -> List[Dict[str, Any]]:
    """Collect all items from list APIs that expose explicit next-token fields."""
    items: List[Dict[str, Any]] = []
    next_token: Optional[str] = None
    operation = getattr(client, operation_name)

    while True:
        request = dict(kwargs)
        request[max_results_param] = max_results
        if next_token:
            request[token_param] = next_token
        response = operation(**request)
        if not isinstance(response, dict):
            raise TypeError(
                f"{operation_name} returned unexpected response type: "
                f"{type(response).__name__}"
            )
        items.extend(response.get(result_key, []))
        next_token = None
        for token_key in token_response_keys:
            candidate = response.get(token_key)
            if isinstance(candidate, str) and candidate:
                next_token = candidate
                break
        if not next_token:
            break

    return items


# ---------------------------------------------------------------------------
# CSV I/O — read the per-service region CSVs written by earlier Lambdas.
#
# Per-region-scoped services (Bedrock, SageMaker, AgentCore) write one CSV per
# region as `<prefix>_<execution_id>_<region>.csv`. FinServ is different: it
# runs once (RegionIndex==0), emits per-region Region values in its rows, and
# writes a single un-suffixed `finserv_security_report_<execution_id>.csv`.
# So the OWASP Lambda must key on RegionIndex too — mappings that read
# per-region CSVs run in every region, but FS→OW mappings run only from
# RegionIndex==0's invocation to avoid duplicate emission across regions and
# to match FinServ's actual filename.
# ---------------------------------------------------------------------------
PER_REGION_SERVICE_CSV_PREFIXES = (
    "bedrock_security_report",
    "sagemaker_security_report",
    "agentcore_security_report",
)
FINSERV_SERVICE_CSV_PREFIX = "finserv_security_report"


def _read_service_csvs_for_region(
    bucket_name: str,
    execution_id: str,
    region: str,
    include_finserv: bool = False,
    return_missing: bool = False,
) -> List[Dict[str, str]] | tuple[List[Dict[str, str]], List[str]]:
    """Read every per-service CSV that this OWASP invocation should consume.

    Always reads bedrock/sagemaker/agentcore's per-region CSVs. When
    `include_finserv` is True (RegionIndex==0), also reads FinServ's single
    execution-scoped CSV (`finserv_security_report_<execution_id>.csv`). Rows
    from FinServ already carry per-region Region values, so downstream
    mapping preserves them without further modification.

    Missing objects are returned to the caller when `return_missing` is True
    so OWASP can emit explicit coverage rows instead of silently dropping all
    derived OW-01..OW-10 rows for that source.
    """
    s3_client = boto3.client("s3", config=boto3_config)
    rows: List[Dict[str, str]] = []

    keys: List[str] = [
        f"{prefix}_{execution_id}_{region}.csv"
        for prefix in PER_REGION_SERVICE_CSV_PREFIXES
    ]
    if include_finserv:
        keys.append(f"{FINSERV_SERVICE_CSV_PREFIX}_{execution_id}.csv")

    missing_keys: List[str] = []
    for key in keys:
        try:
            response = s3_client.get_object(Bucket=bucket_name, Key=key)
            body = response["Body"].read().decode("utf-8")
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("NoSuchKey", "404"):
                logger.warning(f"OWASP: source CSV not found: {key}")
                missing_keys.append(key)
                continue
            raise
        reader = csv.DictReader(StringIO(body))
        for row in reader:
            rows.append(dict(row))
    if return_missing:
        return rows, missing_keys
    return rows


def build_missing_source_findings(
    missing_keys: List[str], region: str
) -> List[Dict[str, Any]]:
    """Emit visible coverage rows when an upstream assessment CSV is missing."""
    findings: List[Dict[str, Any]] = []
    for key in missing_keys:
        findings.append(
            create_finding(
                check_id="OW-00",
                finding_name="OWASP Source Assessment Coverage",
                finding_details=(
                    f"Required source assessment CSV was not found for OWASP mapping: "
                    f"{key}. OWASP mapping-derived rows that depend on this source "
                    "could not be generated for this invocation."
                ),
                resolution=(
                    "Review the upstream assessment Lambda and Step Functions execution "
                    "for this source, then rerun the assessment. This row is informational "
                    "and indicates incomplete OWASP coverage rather than a control failure."
                ),
                reference=OWASP_LLM_TOP10_URL,
                severity="Informational",
                status="N/A",
                region=region,
            )
        )
    return findings


def build_owasp_mapping_findings(
    source_rows: List[Dict[str, str]], region: str
) -> List[Dict[str, Any]]:
    """Emit OW-## rows for every source row that has an OWASP_CHECK_MAPPINGS entry.

    Per-row work is isolated with try/except so a single malformed source row
    (out-of-enum Severity/Status, or any future schema drift) drops just that
    row and its mappings — not the whole region's OWASP assessment. Per
    CLAUDE.md/AGENTS.md: per-resource detail calls inside a list loop must be
    individually try/excepted.
    """
    owasp_rows: List[Dict[str, Any]] = []
    for row in source_rows:
        try:
            source_check_id = (row.get("Check_ID") or "").strip()
            mappings = OWASP_CHECK_MAPPINGS.get(source_check_id)
            if not mappings:
                continue
            source_details = row.get("Finding_Details", "") or ""
            source_status = (row.get("Status") or "N/A").strip() or "N/A"
            source_severity = (
                row.get("Severity") or "Informational"
            ).strip() or "Informational"
            # Tooling / N/A rows should not inflate severity in the OW view.
            if source_status == "N/A":
                source_severity = "Informational"
            row_region = row.get("Region") or region

            for m in mappings:
                try:
                    owasp_rows.append(
                        create_finding(
                            check_id=m["check_id"],
                            finding_name=m["finding"],
                            finding_details=(
                                f"OWASP category: {m['owasp_category']}. "
                                f"Source check {source_check_id}: {source_details}"
                            ),
                            resolution=m["resolution"],
                            reference=get_owasp_reference_url(m["check_id"]),
                            severity=source_severity,
                            status=source_status,
                            region=row_region,
                        )
                    )
                except Exception as e:
                    logger.warning(
                        f"OWASP: skipping mapping {m.get('check_id')} for source "
                        f"{source_check_id} due to validation error: {e}"
                    )
                    continue
        except Exception as e:
            logger.warning(
                f"OWASP: skipping source row {row.get('Check_ID')!r} due to "
                f"unexpected error: {e}"
            )
            continue
    return owasp_rows


# ---------------------------------------------------------------------------
# OW-11 — System Prompt Embedded in Lambda Env Var
# ---------------------------------------------------------------------------
def _looks_like_system_prompt(value: str) -> bool:
    """Multi-phrase heuristic: >= MIN_CHARS long AND matches >= 2 distinct
    prompt-shaped phrases. Prevents ordinary config/policy blobs that contain
    an isolated word like "system" from triggering the check.
    """
    if not isinstance(value, str) or len(value) < SYSTEM_PROMPT_HEURISTIC_MIN_CHARS:
        return False
    lower = value.lower()
    matches = sum(1 for phrase in SYSTEM_PROMPT_HEURISTIC_PHRASES if phrase in lower)
    return matches >= SYSTEM_PROMPT_HEURISTIC_MIN_PHRASE_MATCHES


def check_system_prompt_in_lambda_env(region: str) -> List[Dict[str, Any]]:
    """OW-11 — flag Lambda functions with env vars that look like embedded system prompts."""
    ow11_reference = get_owasp_reference_url("OW-11")
    try:
        lambda_client = boto3.client("lambda", config=boto3_config, region_name=region)
    except Exception as e:
        logger.error(f"OW-11: failed to create lambda client: {e}")
        return [
            create_finding(
                check_id="OW-11",
                finding_name="OWASP LLM07: System Prompt Embedded in Lambda Env Var",
                finding_details=f"Could not initialise Lambda client in {region}: {e}",
                resolution="No action required. Retry after resolving the underlying error.",
                reference=ow11_reference,
                severity="Informational",
                status="N/A",
                region=region,
            )
        ]

    try:
        functions = _list_all_items(
            lambda_client,
            "list_functions",
            "Functions",
            max_results_param="MaxItems",
            token_param="Marker",
            token_response_keys=("NextMarker",),
            max_results=50,
        )
    except (ClientError, EndpointConnectionError) as e:
        code = ""
        if isinstance(e, ClientError):
            code = e.response.get("Error", {}).get("Code", "")
        if code in REGION_UNAVAILABLE_ERROR_CODES or isinstance(
            e, EndpointConnectionError
        ):
            return [
                create_finding(
                    check_id="OW-11",
                    finding_name="OWASP LLM07: System Prompt Embedded in Lambda Env Var",
                    finding_details=f"Lambda service not available in {region}. No check performed.",
                    resolution="No action required. Lambda is not deployed in this region.",
                    reference=ow11_reference,
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        if code in ACCESS_DENIED_ERROR_CODES:
            return [
                create_finding(
                    check_id="OW-11",
                    finding_name="OWASP LLM07: System Prompt Embedded in Lambda Env Var",
                    finding_details=(
                        "Access denied when listing Lambda functions; the OWASP Lambda "
                        "role is missing lambda:ListFunctions in this region."
                    ),
                    resolution="Grant lambda:ListFunctions to the OWASPSecurityAssessmentFunction role.",
                    reference=ow11_reference,
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        logger.error(f"OW-11: unexpected error listing Lambdas: {e}")
        return [
            create_finding(
                check_id="OW-11",
                finding_name="OWASP LLM07: System Prompt Embedded in Lambda Env Var",
                finding_details=f"Error listing Lambda functions in {region}: {e}",
                resolution="Investigate the error and retry.",
                reference=ow11_reference,
                severity="Informational",
                status="N/A",
                region=region,
            )
        ]

    if not functions:
        return [
            create_finding(
                check_id="OW-11",
                finding_name="OWASP LLM07: System Prompt Embedded in Lambda Env Var",
                finding_details=f"No Lambda functions found in {region}; nothing to inspect.",
                resolution="No action required.",
                reference=ow11_reference,
                severity="Informational",
                status="N/A",
                region=region,
            )
        ]

    offending: List[str] = []
    for fn in functions:
        # list_functions returns full configuration; env vars live in
        # Environment.Variables when present.
        env = ((fn.get("Environment") or {}).get("Variables")) or {}
        for name, value in env.items():
            if _looks_like_system_prompt(value):
                offending.append(f"{fn.get('FunctionName', '<unknown>')}::{name}")
                break

    if offending:
        sample = ", ".join(offending[:5])
        more = "" if len(offending) <= 5 else f" (and {len(offending) - 5} more)"
        return [
            create_finding(
                check_id="OW-11",
                finding_name="OWASP LLM07: System Prompt Embedded in Lambda Env Var",
                finding_details=(
                    f"{len(offending)} Lambda function(s) in {region} have environment "
                    f"variables that heuristically look like embedded system prompts "
                    f"(>= {SYSTEM_PROMPT_HEURISTIC_MIN_CHARS} chars, contain prompt-shaped "
                    f"tokens). Sample: {sample}{more}. Embedded prompts are hard to version, "
                    "audit, and rotate, and can leak if the function configuration is dumped."
                ),
                resolution=(
                    "Move each system prompt into Amazon Bedrock Prompt Management "
                    "(bedrock-agent:CreatePrompt) and inject a Prompt ARN into the Lambda "
                    "env var instead of the raw text. This gives the prompt versioning, "
                    "IAM-scoped access, and centralised audit."
                ),
                reference=ow11_reference,
                severity="Medium",
                status="Failed",
                region=region,
            )
        ]
    return [
        create_finding(
            check_id="OW-11",
            finding_name="OWASP LLM07: System Prompt Embedded in Lambda Env Var",
            finding_details=(
                f"No Lambda function env vars in {region} match the embedded-system-prompt heuristic "
                f"(>= {SYSTEM_PROMPT_HEURISTIC_MIN_CHARS} chars containing prompt-shaped tokens)."
            ),
            resolution="No action required.",
            reference=ow11_reference,
            # Control-inherent severity: OW-11 severity is Medium regardless
            # of Pass/Fail outcome, matching FinServ's severity methodology.
            severity="Medium",
            status="Passed",
            region=region,
        )
    ]


# ---------------------------------------------------------------------------
# OW-12 — System-Prompt-Disclosure Denied Topic
# ---------------------------------------------------------------------------
def check_system_prompt_disclosure_denied_topic(region: str) -> List[Dict[str, Any]]:
    """OW-12 — verify at least one Bedrock guardrail denies system-prompt-disclosure topics."""
    ow12_reference = get_owasp_reference_url("OW-12")
    try:
        bedrock_client = boto3.client(
            "bedrock", config=boto3_config, region_name=region
        )
    except Exception as e:
        logger.error(f"OW-12: failed to create bedrock client: {e}")
        return [
            create_finding(
                check_id="OW-12",
                finding_name="OWASP LLM07: System-Prompt-Disclosure Denied Topic",
                finding_details=f"Could not initialise Bedrock client in {region}: {e}",
                resolution="No action required. Retry after resolving the underlying error.",
                reference=ow12_reference,
                severity="Informational",
                status="N/A",
                region=region,
            )
        ]

    try:
        guardrails = _list_all_items(bedrock_client, "list_guardrails", "guardrails")
    except (ClientError, EndpointConnectionError) as e:
        code = ""
        if isinstance(e, ClientError):
            code = e.response.get("Error", {}).get("Code", "")
        if (
            code in REGION_UNAVAILABLE_ERROR_CODES
            or isinstance(e, EndpointConnectionError)
            or is_region_unsupported(e)
        ):
            return [
                create_finding(
                    check_id="OW-12",
                    finding_name="OWASP LLM07: System-Prompt-Disclosure Denied Topic",
                    finding_details=f"Bedrock service not available in {region}. No check performed.",
                    resolution="No action required. Bedrock is not deployed in this region.",
                    reference=ow12_reference,
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        if code in ACCESS_DENIED_ERROR_CODES:
            return [
                create_finding(
                    check_id="OW-12",
                    finding_name="OWASP LLM07: System-Prompt-Disclosure Denied Topic",
                    finding_details=(
                        "Access denied when listing Bedrock guardrails; the OWASP Lambda "
                        "role is missing bedrock:ListGuardrails."
                    ),
                    resolution="Grant bedrock:ListGuardrails and bedrock:GetGuardrail to the OWASPSecurityAssessmentFunction role.",
                    reference=ow12_reference,
                    severity="Informational",
                    status="N/A",
                    region=region,
                )
            ]
        logger.error(f"OW-12: unexpected error listing guardrails: {e}")
        return [
            create_finding(
                check_id="OW-12",
                finding_name="OWASP LLM07: System-Prompt-Disclosure Denied Topic",
                finding_details=f"Error listing Bedrock guardrails in {region}: {e}",
                resolution="Investigate the error and retry.",
                reference=ow12_reference,
                severity="Informational",
                status="N/A",
                region=region,
            )
        ]

    if not guardrails:
        return [
            create_finding(
                check_id="OW-12",
                finding_name="OWASP LLM07: System-Prompt-Disclosure Denied Topic",
                finding_details=f"No Bedrock guardrails configured in {region}; nothing to inspect.",
                resolution="No action required.",
                reference=ow12_reference,
                severity="Informational",
                status="N/A",
                region=region,
            )
        ]

    matched = False
    readable_count = 0
    unreadable: List[str] = []
    for g in guardrails:
        # Isolate per-guardrail work: a missing "id" (schema drift) or any other
        # unexpected error must degrade this one guardrail to "unreadable", not
        # abort the whole region's OW-12 check. Mirrors build_owasp_mapping_findings.
        try:
            guardrail_id = g.get("id")
            if not guardrail_id:
                unreadable.append("<missing id> (malformed guardrail summary)")
                continue

            # Read the version list_guardrails advertised (typically the latest
            # published version, or DRAFT for unpublished guardrails). Falling
            # back to DRAFT alone would miss cases where a published version has
            # the DENY topic but DRAFT diverged. Individual read failures should
            # not abort the whole check.
            candidate_versions: List[str] = []
            advertised_version = g.get("version")
            if advertised_version:
                candidate_versions.append(str(advertised_version))
            if "DRAFT" not in candidate_versions:
                candidate_versions.append("DRAFT")

            detail = None
            last_error_code = ""
            for version in candidate_versions:
                try:
                    detail = bedrock_client.get_guardrail(
                        guardrailIdentifier=guardrail_id, guardrailVersion=version
                    )
                    break
                except ClientError as e:
                    last_error_code = e.response.get("Error", {}).get("Code", "")
                    logger.info(
                        f"OW-12: get_guardrail failed for {guardrail_id} version={version}: "
                        f"{last_error_code}"
                    )
                    continue
            if detail is None:
                unreadable.append(
                    f"{guardrail_id} ({last_error_code or 'unknown error'})"
                )
                continue
            readable_count += 1

            topic_policy = detail.get("topicPolicy") or {}
            for topic in topic_policy.get("topics", []) or []:
                if str(topic.get("type", "")).upper() != "DENY":
                    continue
                haystack = (
                    str(topic.get("name", "")) + " " + str(topic.get("definition", ""))
                ).lower()
                if any(needle in haystack for needle in SYSTEM_PROMPT_DENY_TOKENS):
                    matched = True
                    break
            if matched:
                break
        except Exception as e:
            logger.warning(
                f"OW-12: skipping guardrail {g.get('id', '<unknown>')} due to "
                f"unexpected error: {e}"
            )
            unreadable.append(f"{g.get('id', '<unknown>')} (unexpected error)")
            continue

    if matched:
        return [
            create_finding(
                check_id="OW-12",
                finding_name="OWASP LLM07: System-Prompt-Disclosure Denied Topic",
                finding_details=(
                    f"At least one Bedrock guardrail in {region} denies a system-prompt-"
                    "disclosure topic; extraction attempts by adversarial prompts should "
                    "be filtered."
                ),
                resolution="No action required.",
                reference=ow12_reference,
                # Control-inherent severity: OW-12 severity is Medium regardless
                # of Pass/Fail outcome, matching FinServ's severity methodology.
                severity="Medium",
                status="Passed",
                region=region,
            )
        ]
    # At least one guardrail was readable and none carried a system-prompt-
    # disclosure DENY topic: that is a genuine gap (Failed), regardless of any
    # guardrails we could not read. Evaluating this before the `unreadable`
    # short-circuit stops an AccessDenied on one guardrail from masking a real
    # failure on another. Only when *nothing* was readable do we fall through
    # to N/A (indeterminate != absent).
    if readable_count > 0:
        failed_detail = (
            f"No readable Bedrock guardrail in {region} has a DENY topic covering "
            "system-prompt disclosure. Attackers can craft prompts that ask the agent "
            "to reveal its system prompt or instructions."
        )
        if unreadable:
            failed_detail += (
                f" Note: {len(unreadable)} of {len(guardrails)} guardrail(s) could not "
                f"be inspected ({', '.join(unreadable[:5])}); this gap is reported from "
                f"the {readable_count} readable guardrail(s) only."
            )
        return [
            create_finding(
                check_id="OW-12",
                finding_name="OWASP LLM07: System-Prompt-Disclosure Denied Topic",
                finding_details=failed_detail,
                resolution=(
                    "Add a DENY topic to at least one guardrail. Suggested topic name: "
                    "'SystemPromptDisclosure'. Suggested definition: 'Requests to reveal, "
                    "describe, or summarise the system prompt, instructions, or internal role "
                    "definition given to the assistant.'"
                ),
                reference=ow12_reference,
                severity="Medium",
                status="Failed",
                region=region,
            )
        ]
    if unreadable:
        return [
            create_finding(
                check_id="OW-12",
                finding_name="OWASP LLM07: System-Prompt-Disclosure Denied Topic",
                finding_details=(
                    f"Could not inspect {len(unreadable)} of {len(guardrails)} Bedrock "
                    f"guardrail(s) in {region} for system-prompt-disclosure DENY topics. "
                    f"Readable guardrails inspected: {readable_count}. Sample unreadable "
                    f"guardrails: {', '.join(unreadable[:5])}."
                ),
                resolution=(
                    "Grant bedrock:GetGuardrail for the listed guardrails or resolve the "
                    "read errors, then rerun the assessment. Do not treat this as proof "
                    "that a DENY topic is absent."
                ),
                reference=ow12_reference,
                severity="Informational",
                status="N/A",
                region=region,
            )
        ]
    # Unreachable in practice: an empty guardrail list is handled earlier, so if
    # we get here at least one guardrail was readable or unreadable. Kept as a
    # defensive N/A fallback so a future edit that breaks the readable/unreadable
    # invariant cannot emit an absence-claiming Failed with no readable evidence
    # (indeterminate != absent).
    return [
        create_finding(
            check_id="OW-12",
            finding_name="OWASP LLM07: System-Prompt-Disclosure Denied Topic",
            finding_details=(
                f"Could not determine system-prompt-disclosure DENY topic coverage in "
                f"{region}; no guardrail was conclusively inspected. Do not treat this as "
                "proof that a DENY topic is absent."
            ),
            resolution=(
                "Rerun the assessment after confirming bedrock:ListGuardrails and "
                "bedrock:GetGuardrail are granted to the OWASPSecurityAssessmentFunction "
                "role."
            ),
            reference=ow12_reference,
            severity="Informational",
            status="N/A",
            region=region,
        )
    ]


# ---------------------------------------------------------------------------
# CSV writer + S3 upload — mirrors the per-service Lambda pattern.
# ---------------------------------------------------------------------------
def generate_csv_report(rows: List[Dict[str, Any]]) -> str:
    csv_buffer = StringIO()
    fieldnames = [
        "Check_ID",
        "Finding",
        "Finding_Details",
        "Resolution",
        "Reference",
        "Severity",
        "Status",
        "Region",
    ]
    writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({k: row.get(k, "") for k in fieldnames})
    return csv_buffer.getvalue()


def write_to_s3(
    execution_id: str, csv_content: str, bucket_name: str, region: str = ""
) -> str:
    s3_client = boto3.client("s3", config=boto3_config)
    if region:
        file_name = f"owasp_security_report_{execution_id}_{region}.csv"
    else:
        file_name = f"owasp_security_report_{execution_id}.csv"
    s3_client.put_object(
        Bucket=bucket_name, Key=file_name, Body=csv_content, ContentType="text/csv"
    )
    s3_url = f"https://{bucket_name}.s3.amazonaws.com/{file_name}"
    logger.info(f"Successfully wrote OWASP report to S3: {s3_url}")
    return s3_url


def lambda_handler(event, context):
    """Main entry point for the OWASP assessment Lambda.

    Expects the Step Functions payload used by the FinServ Lambda:
      { Execution: {Name: ...}, StateMachine: ..., Region: ..., RegionIndex: 0 }

    Runs in every region (unlike FinServ which is gated to RegionIndex==0
    inside the state machine), because BR/SM/AC per-region CSV mappings and
    OW-11/OW-12 native checks are region-scoped. Only the FS→OW mappings
    read from FinServ's single un-suffixed CSV, and those are gated to
    RegionIndex==0 here to avoid duplicate emission across regions.
    """
    logger.info("Starting OWASP Top 10 for LLM assessment")
    try:
        region = event.get("Region", os.environ.get("AWS_REGION", "us-east-1"))
        execution_id = event["Execution"]["Name"]
        region_index = event.get("RegionIndex", 0)
        include_finserv = region_index == 0
        bucket_name = os.environ.get("AIML_ASSESSMENT_BUCKET_NAME")
        if not bucket_name:
            raise ValueError(
                "AIML_ASSESSMENT_BUCKET_NAME environment variable is not set"
            )

        logger.info(
            f"OWASP assessment for region={region} RegionIndex={region_index} "
            f"include_finserv={include_finserv}"
        )

        # 1) Read per-service CSVs the service Lambdas just wrote.
        source_rows, missing_source_keys = _read_service_csvs_for_region(
            bucket_name=bucket_name,
            execution_id=execution_id,
            region=region,
            include_finserv=include_finserv,
            return_missing=True,
        )
        logger.info(f"OWASP: read {len(source_rows)} source rows for {region}")

        # 2) Apply mappings to emit OW-01..OW-10.
        mapping_rows = build_owasp_mapping_findings(source_rows, region=region)
        missing_source_rows = build_missing_source_findings(
            missing_source_keys, region=region
        )

        # 3) Run OW-11 and OW-12 net-new checks.
        ow11_rows = check_system_prompt_in_lambda_env(region=region)
        ow12_rows = check_system_prompt_disclosure_denied_topic(region=region)

        all_rows = mapping_rows + missing_source_rows + ow11_rows + ow12_rows
        logger.info(
            f"OWASP: emitting {len(all_rows)} rows "
            f"({len(mapping_rows)} mapping + {len(missing_source_rows)} missing-source + "
            f"{len(ow11_rows)} OW-11 + {len(ow12_rows)} OW-12)"
        )

        csv_content = generate_csv_report(all_rows)
        s3_url = write_to_s3(
            execution_id=execution_id,
            csv_content=csv_content,
            bucket_name=bucket_name,
            region=region,
        )

        return {
            "statusCode": 200,
            "body": {
                "message": "OWASP assessment completed",
                "row_count": len(all_rows),
                "report_url": s3_url,
            },
        }
    except Exception as e:
        logger.error(f"Error in OWASP lambda_handler: {e}", exc_info=True)
        raise
