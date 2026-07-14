# FinServ Severity Register (authoritative)

This register is the **single source of truth** for the severity of every FinServ finding. It is
derived by applying [`SECURITY_CHECKS_FINSERV_SEVERITY_METHODOLOGY.md`](./SECURITY_CHECKS_FINSERV_SEVERITY_METHODOLOGY.md) (Likelihood × Impact →
ASFF label; §3.4 disposition rules; §3.5 family bands) to the **164 `create_finding` rows / 65
check IDs** extracted from `finserv_assessments/app.py`.

This register is implemented as `SEVERITY_REGISTER` in `app.py` (keyed by finding-name). The
`test_severity_register.py` drift-guard enforces it bidirectionally: every static
`finding_name` literal in the source must have a register entry, every register entry must
correspond to a finding name in the source (no orphans), and emitted rows must carry the
register severity. Because the register is keyed by the human-readable finding name, renaming
a finding in code without updating the register (or vice versa) fails the test suite.

> **Cross-module severity note (documented decision):** FinServ scores customer-managed-key
> encryption absence as **High** for knowledge-base vector stores (FS-25, family band
> "sensitive-data exposure": embeddings of regulated data). The general
> Bedrock/AgentCore/SageMaker checks that mirror Security Hub CMK controls (Bedrock.1,
> BedrockAgentCore.3/.4, SageMaker.21/.23/.24) carry the AWS-published severity **Medium**.
> Both can appear in one report: the FinServ rating reflects the regulated-data context the
> FS checks are scoped to, not a scoring inconsistency.

## How to read it

- **Disposition:** FAIL / PASS / NA-NotApplicable / NA-CouldNotAssess / NA-Advisory / NA-SoftWarning.
- **I, L:** Impact and Likelihood (1–3) for the *control* (blank for advisory/NA rows whose
  severity comes from the disposition rule, not I×L).
- **Sev (new):** the register-assigned severity. **Δ** marks a change from the current code.
- One severity per control across its PASS/FAIL rows (Round-2 invariant).

## Validation outcome (what this register fixes)

The audit of the live code found four defect classes, all resolved here:

1. **Inconsistent NOT_APPLICABLE severity** — "nothing to assess" rows were tagged High (7),
   Medium (10), and Informational (14). → **All NOT_APPLICABLE → Informational** (ASFF "no issue
   found"); the resource-existence signal stays with that resource's own check.
2. **Split COULD_NOT_ASSESS severity** — inline access-checks were Low while `_could_not_assess_row`
   was Medium. → **Unified to Low.**
3. **Pass/Fail severity mismatch for one control** — e.g., FS-66 Failed=High but Passed=Low;
   FS-27 grounding Failed=High but Passed=Medium. → **One control severity applied to both.**
4. **Severity used to encode tier quality** — FS-28/36/51/59 tagged "CLASSIC tier" passes Low and
   "STANDARD tier" High. → **Tier nuance moves to finding details/status; severity = control risk
   (constant).** (Plus a flagged follow-up: should CLASSIC-tier be a `Failed`?)

Plus the Round-3 decisions: FS-01 Shield→Low, WAF→Medium; the cost/rate-limiting family unified to
Medium (FS-02 was High); no `Critical` (capped at High).

---

## Register

### Category 1 — Unbounded Consumption (cost / rate-limiting family → Medium; Shield → Low)

| Check | Finding name | Disposition | I | L | Sev (new) | Δ from current |
|---|---|---|---|---|---|---|
| FS-01 | AWS Shield Advanced Not Enabled | FAIL | 1 | 2 | **Low** | Δ High→Low |
| FS-01 | AWS Shield Advanced Enabled | PASS | 1 | 2 | **Low** | Δ High→Low |
| FS-01 | No Regional WAF Web ACLs Found | FAIL | 2 | 2 | **Medium** | Δ High→Medium |
| FS-01 | Regional WAF Web ACLs Present | PASS | 2 | 2 | **Medium** | Δ High→Medium |
| FS-02 | No API Gateway Usage Plans Found | NA-NotApplicable | – | – | **Informational** | Δ Medium→Info |
| FS-02 | API Gateway Usage Plans Missing Throttle | FAIL | 2 | 2 | **Medium** | Δ High→Medium |
| FS-02 | API Gateway Rate Limiting Configured | PASS | 2 | 2 | **Medium** | Δ High→Medium |
| FS-03 | No Bedrock Token Quotas Returned | FAIL | 2 | 2 | **Medium** | keep |
| FS-03 | Bedrock Default Quotas Unavailable — Customization Undetermined | FAIL | 2 | 2 | **Medium** | keep |
| FS-03 | Bedrock Token Quotas Customized | PASS | 2 | 2 | **Medium** | keep |
| FS-03 | Bedrock Token Quotas At Default | NA-SoftWarning | 2 | 2 | **Medium** | keep (documented exception) |
| FS-04 | No Cost Anomaly Detection Monitors | FAIL | 2 | 2 | **Medium** | keep |
| FS-04 | Cost Anomaly Monitors Do Not Cover Bedrock/SageMaker | FAIL | 2 | 2 | **Medium** | keep |
| FS-04 | Cost Anomaly Detection Configured | PASS | 2 | 2 | **Medium** | keep |
| FS-05 | No Bedrock CloudWatch Alarms Found | FAIL | 2 | 2 | **Medium** | keep |
| FS-05 | Bedrock CloudWatch Alarms Present | PASS | 2 | 2 | **Medium** | keep |
| FS-06 | No AI/ML Service Budgets Configured | FAIL | 2 | 2 | **Medium** | keep |
| FS-06 | AI/ML Service Budgets Configured | PASS | 2 | 2 | **Medium** | keep |

### Category 2 — Excessive Agency (access/agency family → High; cost → Medium)

| Check | Finding name | Disposition | I | L | Sev (new) | Δ from current |
|---|---|---|---|---|---|---|
| FS-07 | Agent Action Boundary Check | NA-NotApplicable | – | – | **Informational** | keep |
| FS-07 | Bedrock Agent Overly Broad Action Permissions | FAIL | 3 | 2 | **High** | keep |
| FS-07 | Agent Action Boundaries Look Appropriate | PASS | 3 | 2 | **High** | keep |
| FS-08 | AgentCore Policy Engine — Access Check | NA-CouldNotAssess | – | – | **Low** | keep |
| FS-08 | No AgentCore Runtimes Found | NA-NotApplicable | – | – | **Informational** | keep |
| FS-08 | AgentCore Runtimes Missing Policy Engine | FAIL | 3 | 2 | **High** | keep |
| FS-08 | AgentCore Policy Engine Configured | PASS | 3 | 2 | **High** | keep |
| FS-09 | Agent Lambda Functions Without Concurrency Limits | FAIL | 2 | 2 | **Medium** | keep |
| FS-09 | Agent Lambda Concurrency Limits Present | PASS (computed) | 2 | 2 | **Medium** | keep |
| FS-10 | Human-in-the-Loop Check — No Agent Workflows Found | NA-NotApplicable | – | – | **Informational** | Δ Medium→Info |
| FS-10 | Human Approval Steps Found in Agent Workflows | PASS | 3 | 2 | **High** | keep |
| FS-10 | Agent Workflows Missing Human Approval Steps | FAIL | 3 | 2 | **High** | keep |
| FS-11 | No Agent Rate Alarms Found | FAIL | 2 | 2 | **Medium** | keep |
| FS-11 | Agent Rate Alarms Present | PASS | 2 | 2 | **Medium** | keep |

### Category 3 — Supply Chain (governance → Medium; SCP/scanning → High)

| Check | Finding name | Disposition | I | L | Sev (new) | Δ from current |
|---|---|---|---|---|---|---|
| FS-12 | SCP Model Access Check — Not in Organization | NA-NotApplicable | – | – | **Informational** | Δ Low→Info |
| FS-12 | No Bedrock-Scoped SCPs Found | FAIL | 3 | 2 | **High** | keep |
| FS-12 | Bedrock SCPs Found | PASS | 3 | 2 | **High** | keep |
| FS-13 | Models Missing Provenance Tags | FAIL | 2 | 2 | **Medium** | keep |
| FS-13 | Model Provenance Tags Present | PASS | 2 | 2 | **Medium** | keep |
| FS-14 | No Model Governance Config Rules Found | FAIL | 2 | 2 | **Medium** | keep |
| FS-14 | Model Governance Config Rules Present | PASS | 2 | 2 | **Medium** | keep |
| FS-15 | No Bedrock Evaluation Jobs Found | FAIL | 2 | 2 | **Medium** | Δ N/A→FAIL, Info→Medium (REQ-10a) |
| FS-15 | Bedrock Evaluation Jobs Present | PASS | 2 | 2 | **Medium** | keep |
| FS-16 | No ECR Repositories Found | NA-NotApplicable | – | – | **Informational** | keep |
| FS-16 | ECR Repositories Without Image Scanning | FAIL | 3 | 2 | **High** | keep |
| FS-16 | ECR Image Scanning Enabled | PASS | 3 | 2 | **High** | keep |

† **Resolved in REQ-10a:** FS-15 now treats "no eval jobs" as **Failed** (real control); FS-30/35/40
are converted to **advisory** (they cannot inspect dataset content). See the REQ-10 section below.

### Category 4 — Training Data & Model Poisoning (data integrity → High; governance → Medium)

| Check | Finding name | Disposition | I | L | Sev (new) | Δ from current |
|---|---|---|---|---|---|---|
| FS-20 | No SageMaker Feature Groups Found | NA-NotApplicable | – | – | **Informational** | keep |
| FS-20 | Feature Groups Without Offline Store | FAIL | 2 | 2 | **Medium** | keep |
| FS-20 | Feature Store Offline Store Active | PASS | 2 | 2 | **Medium** | keep |
| FS-21 | No Training Data Buckets Identified | NA-NotApplicable | – | – | **Informational** | keep |
| FS-21 | Training Data Buckets Without Versioning | FAIL | 3 | 2 | **High** | keep (data-integrity/poisoning recovery) |
| FS-21 | Training Data Buckets Have Versioning | PASS | 3 | 2 | **High** | keep |

### Category 5 — Vector & Embedding Weaknesses (access/encryption → High; governance → Medium)

| Check | Finding name | Disposition | I | L | Sev (new) | Δ from current |
|---|---|---|---|---|---|---|
| FS-22 | Overly Permissive Knowledge Base IAM Roles | FAIL | 3 | 2 | **High** | keep |
| FS-22 | Knowledge Base IAM Permissions Look Appropriate | PASS | 3 | 2 | **High** | keep |
| FS-24 | No Knowledge Bases Found | NA-NotApplicable | – | – | **Informational** | keep |
| FS-24 | Knowledge Base Metadata Filtering — Manual Review Required | NA-Advisory | – | – | **Informational** | Δ Medium/Passed→Info/N/A; add `ADVISORY:` prefix |
| FS-25 | No OpenSearch Serverless Encryption Policies | NA-NotApplicable | – | – | **Informational** | keep |
| FS-25 | OpenSearch Serverless Encryption Not Using Customer-Managed Keys | FAIL | 3 | 2 | **High** | keep |
| FS-25 | OpenSearch Serverless Encryption Policies Present | PASS | 3 | 2 | **High** | keep |
| FS-26 | No OpenSearch Serverless Network Policies | FAIL | 3 | 2 | **High** | keep |
| FS-26 | OpenSearch Serverless Collections Not VPC-Restricted | FAIL | 3 | 2 | **High** | keep |
| FS-26 | OpenSearch Serverless VPC Access Configured | PASS | 3 | 2 | **High** | keep |

### Category 6 — Non-Compliant Output (grounding → High; ARC → Medium)

| Check | Finding name | Disposition | I | L | Sev (new) | Δ from current |
|---|---|---|---|---|---|---|
| FS-27 | No Guardrails — Contextual Grounding Not Applicable | NA-NotApplicable | – | – | **Informational** | Δ Medium→Info |
| FS-27 | No Guardrails With Contextual Grounding | FAIL | 3 | 2 | **High** | keep |
| FS-27 | Contextual Grounding Enabled on Guardrails | PASS | 3 | 2 | **High** | Δ Medium→High (match FAIL) |
| FS-27 | Automated Reasoning Policies — Access Check | NA-CouldNotAssess | – | – | **Low** | keep |
| FS-27 | No Automated Reasoning Policies Found | FAIL | 2 | 2 | **Medium** | keep |
| FS-27 | Automated Reasoning Policies Found | PASS | 2 | 2 | **Medium** | keep |
| FS-28 | No Guardrails — Denied Topics Not Applicable | NA-NotApplicable | – | – | **Informational** | Δ Medium→Info |
| FS-28 | No Guardrails With Denied Financial Topics | FAIL | 3 | 2 | **High** | keep |
| FS-28 | Denied Topics Configured on CLASSIC Tier | PASS | 3 | 2 | **High** | Δ Low→High; tier note → details ‡ |
| FS-28 | Guardrails With Topic Policies Found | PASS | 3 | 2 | **High** | Δ Medium→High |
| FS-29 | ADVISORY: Compliance Disclaimer — Manual Review Required | NA-Advisory | – | – | **Informational** | keep |
| FS-30 | ADVISORY: Compliance Dataset Coverage — Manual Review Required | NA-Advisory | – | – | **Informational** | Δ to advisory (REQ-10a): can't verify dataset content; replaces N/A+PASS |
| FS-31 | No Knowledge Bases Found | NA-NotApplicable | – | – | **Informational** | keep |
| FS-31 | Knowledge Base Data Sources Past Review Threshold | FAIL | 2 | 2 | **Medium** | keep |
| FS-31 | Knowledge Base Data Sources Recently Synced | PASS | 2 | 2 | **Medium** | keep |
| FS-32 | ADVISORY: Source Attribution — Manual Review Required | NA-Advisory | – | – | **Informational** | keep |
| FS-33 | No Knowledge Bases Found | NA-NotApplicable | – | – | **Informational** | keep |
| FS-33 | KB Data Source References a Deleted S3 Bucket | FAIL | 3 | 2 | **High** | keep (distinct risk: dangling/integrity) |
| FS-33 | KB Data Source Buckets Without Versioning | FAIL | 2 | 2 | **Medium** | keep (distinct risk) |
| FS-33 | KB Data Source Buckets Have Versioning | PASS | 2 | 2 | **Medium** | keep |
| FS-34 | Legacy Foundation Models Available in Region | NA-NotApplicable | – | – | **Informational** | Δ Medium→Info (availability ≠ usage) |
| FS-34 | Foundation Models Are Current | PASS | 2 | 2 | **Medium** | keep |

‡ **Resolved in REQ-10b:** CLASSIC-tier guardrails are kept as **Passed** (they provide real
protection; CLASSIC is not deprecated/EOL — a hard FAIL would falsely fail adequate English-only
deployments). Severity = the control's inherent risk (constant); the STANDARD-upgrade
recommendation lives in the finding details.

### Category 7 — Misinformation (eval governance → Medium)

| Check | Finding name | Disposition | I | L | Sev (new) | Δ from current |
|---|---|---|---|---|---|---|
| FS-35 | ADVISORY: Harmful-Content Test Coverage — Manual Review Required | NA-Advisory | – | – | **Informational** | Δ to advisory (REQ-10a): can't verify dataset content; replaces N/A+PASS |

### Category 8 — Abusive/Harmful Output (content safety → High; word filters → Medium)

| Check | Finding name | Disposition | I | L | Sev (new) | Δ from current |
|---|---|---|---|---|---|---|
| FS-36 | No Guardrails — Content Filters Not Applicable | NA-NotApplicable | – | – | **Informational** | Δ High→Info |
| FS-36 | No Guardrails With Content Filters | FAIL | 3 | 2 | **High** | keep |
| FS-36 | Guardrail Content Filters on CLASSIC Tier | PASS | 3 | 2 | **High** | Δ Low→High; tier note → details ‡ |
| FS-36 | Guardrail Content Filters Configured (STANDARD Tier) | PASS | 3 | 2 | **High** | keep |
| FS-37 | ADVISORY: User Feedback Mechanism — Manual Review Required | NA-Advisory | – | – | **Informational** | keep |
| FS-38 | No Guardrails — Word Filters Not Applicable | NA-NotApplicable | – | – | **Informational** | Δ Medium→Info |
| FS-38 | No Guardrails With Word Filters | FAIL | 2 | 2 | **Medium** | keep |
| FS-38 | Guardrail Word Filters Configured | PASS | 2 | 2 | **Medium** | keep |

### Category 9 — Biased Output (fair-lending/ECOA → High)

| Check | Finding name | Disposition | I | L | Sev (new) | Δ from current |
|---|---|---|---|---|---|---|
| FS-39 | No SageMaker Clarify Bias Monitoring | FAIL | 3 | 2 | **High** | keep |
| FS-39 | SageMaker Clarify Bias Monitoring Active | PASS | 3 | 2 | **High** | keep |
| FS-40 | ADVISORY: Bias Dataset Coverage — Manual Review Required | NA-Advisory | – | – | **Informational** | Δ to advisory (REQ-10a): can't verify dataset content; replaces N/A+PASS |
| FS-41 | No SageMaker Clarify Explainability Monitoring | FAIL | 3 | 2 | **High** | keep |
| FS-41 | SageMaker Clarify Explainability Active | PASS | 3 | 2 | **High** | keep |
| FS-42 | No SageMaker Model Cards Found | FAIL | 2 | 2 | **Medium** | keep |
| FS-42 | SageMaker Model Cards Present | PASS | 2 | 2 | **Medium** | keep |

### Category 10 — Sensitive Information Disclosure (data exposure → High; classification → Medium)

| Check | Finding name | Disposition | I | L | Sev (new) | Δ from current |
|---|---|---|---|---|---|---|
| FS-43 | No CloudWatch Logs Data Protection Policies | FAIL | 3 | 2 | **High** | keep |
| FS-43 | CloudWatch Logs Data Protection Policies Present | PASS | 3 | 2 | **High** | keep |
| FS-44 | Amazon Macie Not Enabled | FAIL | 3 | 2 | **High** | keep |
| FS-44 | Amazon Macie Enabled | PASS | 3 | 2 | **High** | keep |
| FS-45 | No Guardrails — PII Filters Not Applicable | NA-NotApplicable | – | – | **Informational** | Δ High→Info |
| FS-45 | No Guardrails With PII Filters | FAIL | 3 | 2 | **High** | keep |
| FS-45 | Guardrail PII Filters Configured | PASS | 3 | 2 | **High** | keep |
| FS-46 | No AI/ML Data Buckets Identified | NA-NotApplicable | – | – | **Informational** | keep |
| FS-46 | AI/ML Buckets Without Data Classification Tags | FAIL | 2 | 2 | **Medium** | keep |
| FS-46 | AI/ML Buckets Have Classification Tags | PASS | 2 | 2 | **Medium** | keep |

### Category 11 — Hallucination (grounding → High; relevance → Medium; advisory → Info)

| Check | Finding name | Disposition | I | L | Sev (new) | Δ from current |
|---|---|---|---|---|---|---|
| FS-47 | No Guardrails — Grounding Threshold Not Applicable | NA-NotApplicable | – | – | **Informational** | Δ High→Info |
| FS-47 | Guardrails With Low Grounding Thresholds | FAIL | 3 | 2 | **High** | keep |
| FS-47 | No Guardrails With a Grounding Filter | FAIL | 3 | 2 | **High** | keep |
| FS-47 | Guardrail Grounding Thresholds Appropriate | PASS | 3 | 2 | **High** | keep |
| FS-48 | No Active Knowledge Bases for RAG | FAIL | 2 | 2 | **Medium** | keep |
| FS-48 | Active Knowledge Bases for RAG Present | PASS | 2 | 2 | **Medium** | keep |
| FS-49 | ADVISORY: Hallucination Disclaimer — Manual Review Required | NA-Advisory | – | – | **Informational** | keep |
| FS-50 | No Guardrails With Relevance Grounding Filters | FAIL | 2 | 2 | **Medium** | keep |
| FS-50 | Relevance Grounding Filters Present | PASS | 2 | 2 | **Medium** | keep |

### Category 12 — Prompt Injection (prompt-attack → High; advisory → Info)

| Check | Finding name | Disposition | I | L | Sev (new) | Δ from current |
|---|---|---|---|---|---|---|
| FS-51 | No Guardrails — Prompt Attack Filters Not Applicable | NA-NotApplicable | – | – | **Informational** | Δ High→Info |
| FS-51 | No Guardrails With Prompt Attack Filters | FAIL | 3 | 2 | **High** | keep |
| FS-51 | Prompt Attack Filters on CLASSIC Tier | PASS | 3 | 2 | **High** | Δ Low→High; tier note → details ‡ |
| FS-51 | Prompt Attack Filters Configured (STANDARD Tier) | PASS | 3 | 2 | **High** | keep |
| FS-52 | No Bedrock-Related Lambda Functions Found | NA-NotApplicable | – | – | **Informational** | keep |
| FS-52 | Bedrock Lambda Functions on Deprecated Runtimes | FAIL | 2 | 2 | **Medium** | keep |
| FS-52 | Bedrock Lambda Functions on Current Runtimes | PASS | 2 | 2 | **Medium** | keep |
| FS-54 | ADVISORY: Penetration Testing — Manual Review Required | NA-Advisory | – | – | **Informational** | keep |

### Category 13 — Improper Output Handling (injection/XSS via WAF → see notes; advisory → Info)

| Check | Finding name | Disposition | I | L | Sev (new) | Δ from current |
|---|---|---|---|---|---|---|
| FS-53 | No WAF Web ACLs — Injection Rules Not Applicable | NA-NotApplicable | – | – | **Informational** | Δ High→Info |
| FS-53 | WAF ACLs Missing Injection Protection Rules | FAIL | 3 | 2 | **High** | keep |
| FS-53 | WAF Injection Protection Rules Present | PASS | 3 | 2 | **High** | keep |
| FS-55 | No Output Validation Functions Found | FAIL | 2 | 2 | **Medium** | keep |
| FS-55 | Output Validation Functions Present | PASS | 2 | 2 | **Medium** | keep |
| FS-56 | No WAF ACLs — XSS Prevention Not Applicable | NA-NotApplicable | – | – | **Informational** | Δ High→Info |
| FS-56 | WAF ACLs Missing Common Rule Set (XSS) | FAIL | 2 | 2 | **Medium** | new FAIL path (REQ-10c) |
| FS-56 | XSS Prevention Common Rule Set Present | PASS | 2 | 2 | **Medium** | Δ replaces "Review" false-Passed (REQ-10c) |
| FS-57 | ADVISORY: Output Encoding — Manual Review Required | NA-Advisory | – | – | **Informational** | keep |
| FS-58 | ADVISORY: Output Schema Validation — Manual Review Required | NA-Advisory | – | – | **Informational** | Δ Medium/Passed→Info/N/A (REQ-2 retag) |

### Category 14 — Off-Topic & Inappropriate Output (topic allowlist → Medium; advisory → Info)

| Check | Finding name | Disposition | I | L | Sev (new) | Δ from current |
|---|---|---|---|---|---|---|
| FS-59 | No Guardrails — Topic Allowlist Not Applicable | NA-NotApplicable | – | – | **Informational** | Δ Medium→Info |
| FS-59 | No Guardrails With Topic Restrictions | FAIL | 2 | 2 | **Medium** | keep |
| FS-59 | Topic Restrictions Configured on CLASSIC Tier | PASS | 2 | 2 | **Medium** | Δ Low→Medium; tier note → details ‡ |
| FS-59 | Guardrail Topic Restrictions Configured | PASS | 2 | 2 | **Medium** | keep |
| FS-60 | ADVISORY: Contextual Grounding for Off-Topic Prevention | NA-Advisory | – | – | **Informational** | keep |

### Category 15 — Out-of-Date Training Data (governance → Medium; advisory → Info)

| Check | Finding name | Disposition | I | L | Sev (new) | Δ from current |
|---|---|---|---|---|---|---|
| FS-61 | No Knowledge Bases Found | NA-NotApplicable | – | – | **Informational** | keep |
| FS-61 | No Automated KB Sync Schedules Detected | FAIL | 2 | 2 | **Medium** | keep |
| FS-61 | Automated KB Sync Schedules Present | PASS | 2 | 2 | **Medium** | keep |
| FS-62 | ADVISORY: Data Currency Disclaimer — Manual Review Required | NA-Advisory | – | – | **Informational** | keep |
| FS-63 | Legacy Models Without Lifecycle Management | FAIL | 2 | 2 | **Medium** | keep |
| FS-63 | Foundation Model Lifecycle Management | PASS | 2 | 2 | **Medium** | keep |

### Material Gap Checks (FS-65 to FS-69)

| Check | Finding name | Disposition | I | L | Sev (new) | Δ from current |
|---|---|---|---|---|---|---|
| FS-65 | No Knowledge Bases Found | NA-NotApplicable | – | – | **Informational** | keep |
| FS-65 | KB Data Source References a Deleted S3 Bucket | FAIL | 3 | 2 | **High** | keep (distinct risk) |
| FS-65 | KB Data Source Buckets Missing S3 Event Notifications | FAIL | 2 | 2 | **Medium** | keep (distinct risk) |
| FS-65 | KB Data Source S3 Event Notifications Configured | PASS | 2 | 2 | **Medium** | keep |
| FS-66 | AgentCore Identity Propagation — Access Check | NA-CouldNotAssess | – | – | **Low** | keep |
| FS-66 | No AgentCore Runtimes Found | NA-NotApplicable | – | – | **Informational** | keep |
| FS-66 | AgentCore Runtimes Missing End-User Identity Propagation | FAIL | 3 | 2 | **High** | keep |
| FS-66 | AgentCore End-User Identity Propagation Configured | PASS | 3 | 2 | **High** | Δ Low→High (match FAIL) |
| FS-67 | No Agent Action-Group Lambda Functions Found | NA-NotApplicable | – | – | **Informational** | Δ High→Info |
| FS-67 | Agent Action-Group Lambdas May Lack Transaction Thresholds | FAIL | 3 | 2 | **High** | keep |
| FS-67 | Agent Action-Group Lambdas Have Threshold Configuration | PASS | 3 | 2 | **High** | keep |
| FS-68 | API Gateway Request Body Size Limits Not Enforced | FAIL | 2 | 2 | **Medium** | keep |
| FS-68 | API Gateway Request Body Size Limits — Not Applicable | NA-NotApplicable | – | – | **Informational** | new branch (REQ-4) |
| FS-68 | API Gateway Request Body Size Limits Configured | PASS | 2 | 2 | **Medium** | keep |
| FS-69 | No Prompt Input Validation Function Found | FAIL | 2 | 2 | **Medium** | keep |
| FS-69 | Prompt Input Validation Functions Present | PASS | 2 | 2 | **Medium** | keep |

### Cross-cutting synthesized row

| Source | Finding name | Disposition | Sev (new) | Δ from current |
|---|---|---|---|---|
| `_could_not_assess_row()` | `COULD NOT ASSESS: <check name>` (any check that errors with no rows) | NA-CouldNotAssess | **Low** | Δ Medium→Low (unify with inline access-checks) |

---

## Change summary

| Change class | Count (approx) | Net effect |
|---|---|---|
| NOT_APPLICABLE N/A → Informational | ~21 rows (7 High, 10 Medium, ~4 Low/other) | removes misleading High/Medium **N/A** rows; no pass-rate impact (N/A excluded) |
| COULD_NOT_ASSESS → Low (unify) | 4 inline + generic row | consistent "unknown" signaling |
| FS-01 Shield High→Low | 2 rows | fixes reviewer Finding 6 |
| FS-01 WAF High→Medium | 2 rows | cost/rate-limiting family consistency |
| FS-02 High→Medium | 2 rows (PASS/FAIL) | cost/rate-limiting family consistency |
| Pass/Fail mismatch fixed (FS-27 grounding, FS-66) | ~3 rows | one severity per control |
| Tier-quality severity removed (FS-28/36/51/59) | 4 PASS rows | severity = control risk; tier nuance → details |
| FS-58 retag (REQ-2) | 1 row | advisory Informational |
| FS-24 advisory retag | 1 row | advisory Informational |
| **REQ-10a** FS-15 absence N/A→Failed | 1 row | now counted in pass rate (real model-validation gap) |
| **REQ-10a** FS-30/35/40 → advisory | 6 rows → 3 advisory | removes false Passed; honest manual-review |
| **REQ-10c** FS-56 gains FAIL path | +1 FAIL row | removes false "review" Passed |
| **REQ-10b** FS-28/36/51/59 CLASSIC kept Passed | 4 rows | severity normalized only (no FAIL) |

**Expected report impact:** High-severity **counted** findings drop modestly (Shield, WAF, FS-02
move out of High; several misleading High **N/A** rows become Informational). Pass-rate changes
only from the Passed-row severity moves (FS-01 Shield/WAF, FS-02), since N/A and Informational are
excluded from the rate. Capture before/after in the PR (task T1b.8).

## Check-logic fixes pulled into this round (REQ-10)

The three previously-flagged check-logic items are now **in scope** and resolved as follows (see
REQ-10 in requirements/design):

1. **REQ-10a — Eval-job checks (FS-15/30/35/40).** FS-15 verifies a real, programmatically
   checkable control (model-evaluation jobs exist) → "no eval jobs" becomes **FAIL/Medium**
   (was N/A). FS-30/35/40 cannot inspect eval-job *dataset content* (they only re-checked job
   existence, redundant with FS-15, and emitted a false **Passed**) → converted to **ADVISORY**
   (Informational, `ADVISORY:` prefix, "manually verify {compliance|harmful-content|bias}
   datasets") — the same honest treatment as FS-58.
2. **REQ-10b — CLASSIC-tier guardrails (FS-28/36/51/59).** **Investigated and intentionally NOT
   converted to FAIL.** Reading the code: CLASSIC tier provides real protection (EN/FR/ES);
   STANDARD adds multilingual + better prompt-attack classification but CLASSIC is **not**
   deprecated/EOL. A hard FAIL would falsely fail adequate (e.g., English-only US) deployments.
   Resolution: keep **PASS** at the control's severity (the §3.4 fix already removed the
   severity-by-tier abuse), and strengthen the STANDARD-upgrade guidance in the finding details.
3. **REQ-10c — FS-56 XSS.** Add a real **FAIL** path mirroring FS-53: inspect each WAF ACL for
   `AWSManagedRulesCommonRuleSet` (contains the XSS rules). Present → PASS; ACLs exist but missing
   it → FAIL/Medium; no ACLs → N/A → Informational. Removes the false "review required" PASS.

**Pass-rate impact of REQ-10:** FS-15-absent now counts as a Failed (was excluded N/A); FS-30/35/40
lose three false Passes (now advisory/excluded); FS-56 can now Fail. Net effect lowers pass rate
slightly but accurately. Capture in T1b.8.
