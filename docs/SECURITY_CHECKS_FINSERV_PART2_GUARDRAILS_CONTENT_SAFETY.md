# FinServ GenAI Risk Checks — Part 2: Guardrails & Content Safety (FS-27 to FS-46)

This is **Part 2 of 3** of the FinServ GenAI security checks derived from the
[AWS guide for Financial Services risk management of the use of Generative AI (March 2026)](https://d1.awsstatic.com/onedam/marketing-channels/website/public/global-FinServ-ComplianceGuide-GenAIRisks-public.pdf)
(referred to throughout as "the FinServ Guide").

This part covers **20 checks** across 5 PDF risk categories:

- **Non-Compliant Output** (FS-27 to FS-30) — §1.2.1
- **Misinformation** (FS-31 to FS-34) — §1.2.3 (FS-34 sources from §1.2.12 — see note)
- **Abusive or Harmful Output** (FS-35 to FS-38) — §1.2.4
- **Biased Output** (FS-39 to FS-42) — §1.2.5
- **Sensitive Information Disclosure** (FS-43 to FS-46) — §1.2.6

**Companion files:**

- `SECURITY_CHECKS_FINSERV_PART1_INFRA_CONTROLS.md` — FS-01 to FS-26 (Unbounded, Excessive Agency, Supply Chain, Training Poisoning, Vector Weaknesses)
- `SECURITY_CHECKS_FINSERV_PART3_APP_LAYER_AND_GAPS.md` — FS-47 to FS-69 (Hallucination, Prompt Injection, Output Handling, Off-Topic, Stale Data, Material Gaps)
- `SECURITY_CHECKS_FINSERV_COMMON.md` — shared intro, severity rubric, validation note, upstream-overlap table

Each check includes how it is **detected** (the AWS API calls or configuration inspected)
and how a failure is **remediated** (the specific AWS actions to take).

See `SECURITY_CHECKS_FINSERV_COMMON.md` for:

- PDF traceability conventions (`[PDF §x.y.z]` vs `[PDF §x.y.z, extension]`)
- Severity rubric (High / Medium / Low / Informational) — see SECURITY_CHECKS_FINSERV_SEVERITY_METHODOLOGY.md
- Validation note and AWS service authorization references
- Relationship to upstream SM/BR/AC checks and consolidation recommendations

---

## FinServ GenAI Risk Checks — Part 2 content

### Non-Compliant Output (FS-27 to FS-30)

> **PDF source:** §1.2.1 Non-compliant output. PDF-listed mitigations:
> (a) prompt engineering to guide the model and prevent unwanted responses;
> (b) content filters and denied topics in Bedrock Guardrails;
> (c) RAG with Bedrock Knowledge Bases;
> (d) Automated Reasoning checks in Bedrock Guardrails;
> (e) human-in-the-loop validation for internal AI systems;
> (f) audit logs of AI-generated outputs and guardrails applied for regulatory reporting.

#### FS-27 — Automated Reasoning Checks

| Field | Detail |
|-------|--------|
| Severity | High (contextual grounding) / Medium (Automated Reasoning) |
| PDF ref | [PDF §1.2.1, §1.2.7] — "Automated Reasoning checks in Amazon Bedrock Guardrails uses automated reasoning to verify that natural language content complies with your defined policies. This mathematical verification helps ensure that your content strictly follows your guardrails." |
| Description | Verifies Bedrock Guardrails have Automated Reasoning checks or contextual grounding enabled. |
| Detection | Calls `bedrock:ListGuardrails` and `bedrock:GetGuardrail` for each. Inspects the response fields `contextualGroundingPolicy` and `automatedReasoningPolicy`. Flags guardrails with neither enabled. |
| Remediation | 1. Enable contextual grounding filters (type `GROUNDING`) with a threshold ≥ 0.7 — these filters CAN block content that fails grounding checks. Note: valid threshold values are 0 to 0.99; a threshold of 1.0 is invalid and will block all content. **Important use-case limitation:** Contextual grounding checks support summarization, paraphrasing, and question answering use cases only — **Conversational QA / Chatbot use cases are not supported**. If your FinServ application is a conversational chatbot, contextual grounding cannot be used for hallucination detection; use Automated Reasoning checks or human-in-the-loop validation instead. 2. If available in your region, additionally enable Automated Reasoning checks by creating an Automated Reasoning policy and attaching it to the guardrail. **Cross-Region inference is REQUIRED for AR:** Guardrails that use Automated Reasoning checks require a cross-Region inference profile — set `crossRegionConfig.guardrailProfileIdentifier` to a profile matching your Region (for example, `us.guardrail.v1:0` for US Regions or `eu.guardrail.v1:0` for EU Regions). Omitting this parameter returns `ValidationException`. As of April 2026, AR is generally available in US East (N. Virginia), US East (Ohio), US West (Oregon), EU (Frankfurt), EU (Ireland), and EU (Paris) — verify current regional availability on the [AR documentation page](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-automated-reasoning-checks.html) before audit reliance, as AWS regularly expands coverage. Attach the **versioned** policy ARN (for example, `...:1`) — the unversioned ARN returns an error. You can attach a maximum of 2 AR policies per guardrail. Important: Automated Reasoning operates in **detect mode only** — it returns findings and feedback but does NOT block content. AR finding types (per the user guide) are: `VALID` (response is consistent with policy), `INVALID` (response contradicts policy rules), `SATISFIABLE` (response could be true or false depending on unstated conditions), `IMPOSSIBLE` (premises are contradictory), `TRANSLATION_AMBIGUOUS` (natural language could not be reliably translated to formal logic), `TOO_COMPLEX` (policy complexity exceeded processing limits), and `NO_TRANSLATIONS` (some or all input was not translated into logic due to irrelevance or lack of matching policy variables). Note: in the `AutomatedReasoningCheckFinding` runtime response, these appear as a **union** with lowercase camelCase keys (`valid`, `invalid`, `satisfiable`, `impossible`, `translationAmbiguous`, `tooComplex`, `noTranslations`) — exactly one key is present per finding. Per AWS docs, AR also **does not protect against prompt injection attacks**, **cannot detect off-topic responses**, **does not support streaming APIs**, and **supports English (US) only** — use content filters, topic policies, and other guardrail components alongside AR. **Critical limitation for cross-account enforcement:** AR policies are NOT supported with Bedrock Guardrails cross-account safeguards (org-level or account-level enforcement) — including an AR policy in a guardrail used for enforcement will cause runtime failures. If you rely on AR, configure it at the application or account level separately. Your application must inspect the AR findings via the `ApplyGuardrail` (or `Converse` / `InvokeModel` / `InvokeAgent` / `RetrieveAndGenerate`) API response and decide whether to serve the response, rewrite it using AR feedback, ask the user for clarification, or fall back to a default behavior. 3. For `INVALID` responses, implement an iterative rewriting loop that feeds AR feedback (contradicting rules) back to the LLM to self-correct. 4. Build an audit trail of all AR validation iterations — log `supportingRules` and `claimsTrueScenario` for `VALID` findings as mathematically verifiable compliance evidence. |
| Reference | [Automated Reasoning in Bedrock Guardrails](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-automated-reasoning-checks.html), [AR Checks Concepts (Validation Results Reference)](https://docs.aws.amazon.com/bedrock/latest/userguide/automated-reasoning-checks-concepts.html), [Integrate AR Checks in Your Application](https://docs.aws.amazon.com/bedrock/latest/userguide/integrate-automated-reasoning-checks.html), [Deploy Automated Reasoning Policy](https://docs.aws.amazon.com/bedrock/latest/userguide/deploy-automated-reasoning-policy.html) |

#### FS-28 — Financial Denied Topics

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.1] — "Configure content filters and guardrails to restrict model responses to approved topics" with reference "Amazon Bedrock User Guide – Guardrails – Denied topics". |
| Description | Checks guardrails have denied topics for regulated financial advice. |
| Detection | Calls `bedrock:GetGuardrail` and inspects `topicPolicy.topics` for entries with `type=DENY`. Flags guardrails with no denied topics or with no topics related to financial advice, investment recommendations, or tax guidance. |
| Remediation | 1. Add denied topics to the guardrail following the AWS best-practice golden rules: (a) **Be crisp and precise** — e.g., "Investment advice is inquiries, guidance, or recommendations about the management or allocation of funds or assets with the goal of generating returns or achieving specific financial objectives" rather than vague "Investment advice". (b) **Define, don't instruct** — write "All content associated with specific investment recommendations" not "Block all investment advice". (c) **Stay positive** — never define topics negatively (e.g., avoid "All content except general financial education"). (d) **Focus on themes, not words** — denied topics capture subjects contextually; use word filters for specific names or entities. (e) **Provide sample phrases** — add up to 5 representative inputs per topic (each up to 100 characters). 2. **Quantity and character limits:** A guardrail can contain a maximum of **30 denied topics**. In Classic tier, topic definitions are limited to 200 characters; in Standard tier, up to 1,000 characters — use Standard tier for complex financial topic definitions. 3. Recommended denied topics for FinServ: "specific investment recommendations", "tax advice", "specific financial product recommendations", "guaranteed returns or performance claims". 4. For multi-account enforcement, use Bedrock cross-account safeguards to apply denied topics from a management-account guardrail across all member accounts automatically. When configuring account-level or org-level enforcement, set **both** `selectiveContentGuarding.messages` AND `selectiveContentGuarding.system` to `COMPREHENSIVE` to ensure guardrails evaluate all user messages AND system prompts regardless of input tags — use `SELECTIVE` only when you trust callers to correctly tag content. Setting only `messages` to COMPREHENSIVE leaves system prompts potentially unguarded. 5. Enforce guardrails via IAM policy conditions (`bedrock:GuardrailIdentifier`) to prevent any Bedrock inference call without a guardrail attached. 6. Test with prompts that attempt to elicit regulated financial advice. |
| Reference | [Bedrock Guardrails Denied Topics](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-denied-topics.html), [Safeguard Tiers for Guardrails](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-tiers.html), [Cross-Account Safeguards with Enforcements](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-enforcements.html), [Guardrails Best Practices](https://aws.amazon.com/blogs/machine-learning/build-safe-generative-ai-applications-like-a-pro-best-practices-with-amazon-bedrock-guardrails/) |

#### FS-29 — Compliance Disclaimer

| Field | Detail |
|-------|--------|
| Severity | Informational |
| PDF ref | [PDF §1.2.1, extension] — disclaimers are not verbatim in §1.2.1 but the PDF references "Implement response disclaimers in customer-facing applications" under §1.2.7 Hallucination, which is conceptually the same control applied here for non-compliant financial-advice output. |
| Description | Advisory: verifies application adds required regulatory disclaimers to AI-generated outputs. |
| Detection | Advisory check — cannot be fully automated. Inspects application Lambda function environment variables or configuration for disclaimer-related settings (e.g., `DISCLAIMER_ENABLED`, `COMPLIANCE_FOOTER`). |
| Remediation | 1. Add a standard regulatory disclaimer to all customer-facing AI-generated responses (e.g., "This information is generated by AI and does not constitute financial advice. Please consult a qualified financial advisor."). 2. Make the disclaimer text configurable via environment variable or parameter store. 3. Ensure disclaimers are not removable by prompt manipulation. |
| Reference | [AWS Well-Architected GenAI Lens — Guardrails](https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/gensec02-bp01.html) |

#### FS-30 — Compliance Evaluation Datasets

| Field | Detail |
|-------|--------|
| Severity | Informational |
| PDF ref | [PDF §1.2.1, extension] — the PDF §1.2.12 practical guidance mentions "Amazon Bedrock Evaluations can help to evaluate models against specific types of attacks"; this check extends that concept to compliance-specific evaluation for FS-regulated outputs. |
| Description | Checks Bedrock evaluation jobs use compliance-specific test datasets. |
| Detection | Calls `bedrock:ListEvaluationJobs` to enumerate existing jobs, then calls `bedrock:GetEvaluationJob` for each to inspect the full `evaluationConfig` including dataset configuration. Flags if no evaluation jobs exist or if none reference compliance/regulatory test data. Note: `ListEvaluationJobs` returns only job summaries — dataset configuration details require `GetEvaluationJob`. |
| Remediation | 1. Create a compliance-specific evaluation dataset containing: prompts requesting regulated financial advice, prompts testing disclaimer presence, prompts testing denied-topic enforcement. 2. Run Bedrock evaluation jobs with this dataset before each production deployment. 3. Set pass/fail thresholds and gate deployments on results. |
| Reference | [Bedrock Model Evaluation](https://docs.aws.amazon.com/bedrock/latest/userguide/evaluation.html) |

### Misinformation (FS-31 to FS-33)

> **PDF source:** §1.2.3 Misinformation through inadvertent or malicious action. PDF-listed mitigations:
> (a) prompt engineering;
> (b) verify knowledge base data sources are up-to-date, accurate, reliable, and complete;
> (c) human-in-the-loop validation for internal AI systems;
> (d) source attribution in RAG responses for end users to verify provenance;
> (e) integrity monitoring on knowledge base data sources — e.g., S3 event notifications to
> track document changes.

#### FS-31 — Knowledge Base Data Source Sync

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.3, §1.2.10] — "Verify that your knowledge base data sources are up-to-date, accurate, reliable, and complete"; "Sync your data with your Amazon Bedrock knowledge base". |
| Description | Verifies KB data sources have been synced within 7 days. |
| Detection | Calls `ListDataSources` then `ListIngestionJobs` for each data source (via the `bedrock-agent` boto3 client; IAM actions are `bedrock:ListDataSources` and `bedrock:ListIngestionJobs`). Checks the most recent successful ingestion job's `updatedAt` timestamp. Flags data sources not synced within 7 days. |
| Remediation | 1. Create an EventBridge scheduled rule to trigger KB data source sync at least weekly. 2. Use `StartIngestionJob` (IAM action `bedrock:StartIngestionJob`) as the rule target. 3. Add CloudWatch alarms for failed ingestion jobs. 4. For rapidly changing data, increase sync frequency. |
| Reference | [Bedrock KB Data Source Sync](https://docs.aws.amazon.com/bedrock/latest/userguide/kb-data-source-sync-ingest.html) |

#### FS-32 — Source Attribution

| Field | Detail |
|-------|--------|
| Severity | Informational |
| PDF ref | [PDF §1.2.3, §1.2.10] — "Use source attribution in RAG-based response for end users to verify provenance of information" (§1.2.3); "Use source attribution in RAG-based response for end users to verify currency of information" (§1.2.10). |
| Description | Advisory: verifies application implements source citations in RAG responses. |
| Detection | Advisory check — inspects application code or configuration for use of the `citations` field in `RetrieveAndGenerate` API responses. Checks Lambda environment variables for attribution-related settings. |
| Remediation | 1. Use the `RetrieveAndGenerate` API (IAM action `bedrock:RetrieveAndGenerate`) which returns `citations` with source document references. Each citation contains `retrievedReferences` — an array where each reference has a `content` object (the cited text), a `location` object (data source type and URI — for S3 sources, `location.type=S3` and `location.s3Location.uri` contains the S3 URI), and optional `metadata` (a string-to-JSON map with any custom metadata attributes stored on the chunk, which can hold document title and other fields). Note: there is no fixed `title` field in the API — if you need to display document titles to end users, store them as a metadata attribute during KB ingestion and retrieve them via `retrievedReferences[].metadata`. 2. Display source citations to end users alongside AI-generated responses. 3. Include the data source location (URI or other location identifier depending on source type: S3, Web, Confluence, SharePoint, Salesforce, Kendra, SQL, or Custom) and the cited text excerpt (from `content`). 4. If document titles are required, ensure they are populated in KB metadata and propagated to your UI. 5. Allow users to click through to the original source document where possible. |
| Reference | [Bedrock RetrieveAndGenerate API](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_RetrieveAndGenerate.html) |

#### FS-33 — Knowledge Base Integrity Monitoring

| Field | Detail |
|-------|--------|
| Severity | High (deleted bucket) / Medium (versioning) |
| PDF ref | [PDF §1.2.3] — "Use integrity monitoring on knowledge base data sources to detect unauthorized modifications. Track changes to documents used in knowledge bases." References "For example on S3 data sources use Amazon S3 event notification to track changes to documents." |
| Description | Checks KB data source S3 buckets have versioning enabled and S3 event notifications (EventBridge or SNS) configured to detect unauthorized document modifications in real time. |
| Detection | Identifies KB data-source S3 buckets via `GetDataSource` (via the `bedrock-agent` boto3 client; IAM action `bedrock:GetDataSource`). Calls `s3:GetBucketVersioning` to verify `Status=Enabled`. Calls `s3:GetBucketNotificationConfiguration` and checks for `EventBridgeConfiguration`, `TopicConfigurations`, `QueueConfigurations`, or `LambdaFunctionConfigurations`. Flags buckets missing either control. |
| Remediation | 1. Enable versioning: `aws s3api put-bucket-versioning --bucket <name> --versioning-configuration Status=Enabled`. 2. Enable EventBridge notifications on the bucket: `aws s3api put-bucket-notification-configuration --bucket <name> --notification-configuration '{"EventBridgeConfiguration":{}}'`. Once enabled, S3 automatically sends **all** bucket events to EventBridge — you do not select specific event types at the bucket level. 3. Create an EventBridge rule that matches S3 events for this bucket — use the `detail-type` field values `Object Created` and `Object Deleted` (these are the EventBridge event type names; note: `s3:ObjectCreated:*` and `s3:ObjectRemoved:*` are the legacy SNS/SQS/Lambda notification event type names and are NOT used in EventBridge rules). Route matched events to an SNS topic or Lambda function for alerting. 4. Integrate alerts into your security incident response workflow. |
| Reference | [S3 EventBridge Integration](https://docs.aws.amazon.com/AmazonS3/latest/userguide/EventBridge.html) |

> **Note:** FS-34 (Third-Party Risk Management for FM Providers) is kept adjacent to Misinformation
> in this file for continuity with the prior draft numbering, but its PDF source is §1.2.12
> Supply Chain Vulnerabilities. Treat FS-34 as a Supply Chain check for compliance-framework
> mapping purposes.

#### FS-34 — Third-Party Risk Management (TPRM) for Foundation Model Providers

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.12] — *"Update existing third-party risk management processes to continuously monitor model providers and third-party dependencies, including tracking vendor security advisories, model deprecation notices, and change to terms and conditions."* (Note: moved from the Misinformation section in the prior draft; the PDF places TPRM under Supply Chain.) |
| Description | Verifies a documented third-party risk management (TPRM) process exists to monitor FM providers for security advisories, model deprecation notices, and T&C changes; also flags legacy FMs currently in use. |
| Detection | Calls `bedrock:ListFoundationModels`, then `bedrock:GetFoundationModel` for each in-use model; inspects `modelLifecycle.status` and flags models with status `LEGACY`. Note: the `FoundationModelLifecycle.status` API field has only **two** valid values — `ACTIVE` and `LEGACY`. There is no `EOL` status value in the API; models that have passed their EOL date are removed from the service entirely and API calls referencing them will fail. The user-facing lifecycle page describes three conceptual states (Active, Legacy, EOL) but the API only exposes two. Advisory component checks for evidence of a TPRM process — e.g., an AWS Config rule or a tag on Bedrock resources indicating periodic review (`tprm-last-reviewed=<ISO-date>`). |
| Remediation | 1. Establish a documented TPRM process: at least quarterly review of each in-use FM provider's security advisories, model lifecycle announcements, and T&C changes. 2. Assign an owner for the TPRM process and record review evidence in your MRM system. 3. Subscribe to AWS Bedrock model lifecycle notifications. 4. Migrate workloads from `LEGACY` models to active versions before their published EOL date — note that for models with EOL dates after February 1, 2026, there is a "public extended access" period where Legacy models remain usable but at higher pricing set by the model provider. 5. For third-party models procured via AWS Marketplace or consumed directly, evaluate the provider's own testing procedures — AWS AI Service Cards provide this transparency for Amazon-trained models. |
| Reference | [Bedrock Model Lifecycle](https://docs.aws.amazon.com/bedrock/latest/userguide/model-lifecycle.html), [Access Amazon Bedrock foundation models](https://docs.aws.amazon.com/bedrock/latest/userguide/model-access.html) |

### Abusive or Harmful Output (FS-35 to FS-38)

> **PDF source:** §1.2.4 Model output is abusive or harmful. PDF-listed mitigations:
> (a) AWS AI Service Cards to understand how Amazon addresses toxicity per model;
> (b) Amazon Bedrock Guardrails to detect and filter harmful content;
> (c) FMEval to evaluate for inappropriate content (sexual, profanity, hate, aggression,
> insults, flirtation, identity attacks, threats);
> (d) user reporting mechanism so end users can flag abusive outputs, reviewed within a
> defined process;
> (e) Practical guidance: create allowlists for approved business terminology to reduce
> false positives on brand, product, industry, and technical vocabulary.

#### FS-35 — FMEval Harmful Content

| Field | Detail |
|-------|--------|
| Severity | Informational |
| PDF ref | [PDF §1.2.4] — "Foundation Model Evaluations (FMEval) evaluates your model to detect inappropriate content, including sexual references, profanity, hate speech, aggression, insults, flirtation, identity-based attacks, and threats." |
| Description | Checks Bedrock evaluation jobs test for harmful/toxic content. |
| Detection | Calls `bedrock:ListEvaluationJobs` to enumerate existing jobs, then calls `bedrock:GetEvaluationJob` for each to inspect the full `evaluationConfig`. The correct metric name depends on the evaluation job type: (a) For **automated model evaluation jobs** (pre-computed metrics), the toxicity metric is `"Builtin.Toxicity"` — the only valid harmful-content metric for this job type. (b) For **judge-based model evaluation jobs** (LLM-as-judge), the harmful content metrics are `"Builtin.Harmfulness"` and `"Builtin.Stereotyping"`. (c) For **knowledge base (RAG) evaluation jobs**, `"Builtin.Harmfulness"` and `"Builtin.Stereotyping"` are also valid. Flags if no evaluation jobs exist or none include a harmful-content metric (`Builtin.Toxicity` for automated, `Builtin.Harmfulness` for judge-based/RAG). Note: `ListEvaluationJobs` returns only job summaries — dataset configuration details require `GetEvaluationJob`. |
| Remediation | 1. For **automated model evaluation** (fastest, no judge model required): create a Bedrock evaluation job with `"Builtin.Toxicity"` in the `metricNames` array. Valid task types are `Summarization`, `Classification`, `QuestionAndAnswer`, `Generation`, and `Custom`. 2. For **judge-based model evaluation** (more nuanced, requires a judge model): create a Bedrock evaluation job with `"Builtin.Harmfulness"` and/or `"Builtin.Stereotyping"` in the `metricNames` array — these metrics are only valid for judge-based and RAG evaluation jobs, not automated model evaluation jobs. 3. Include test prompts designed to elicit harmful content. 4. Set pass/fail thresholds based on the scores returned. 5. Run evaluations before production deployment and after model updates. 6. For more granular toxicity scoring (the 7-category UnitaryAI Detoxify-unbiased scores: `toxicity`, `severe_toxicity`, `obscene`, `threat`, `insult`, `sexual_explicit`, `identity_attack` — or the Toxigen-roberta binary classifier), use SageMaker FMEval via SageMaker Studio or the `fmeval` Python library as a complementary evaluation path. |
| Reference | [Bedrock Model Evaluation Metrics](https://docs.aws.amazon.com/bedrock/latest/userguide/model-evaluation-metrics.html), [SageMaker FMEval Toxicity](https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-toxicity-evaluation.html) |

#### FS-36 — Guardrail Content Filters

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.4] — "Use Amazon Bedrock's guardrails to detect and filter harmful content." |
| Description | Verifies guardrails have content filters for hate, violence, sexual, and other harmful content. |
| Detection | Calls `bedrock:GetGuardrail` and inspects `contentPolicy.filters`. Flags guardrails missing filters for HATE, VIOLENCE, SEXUAL, INSULTS, or MISCONDUCT categories. Also checks that `inputStrength` and `outputStrength` are at least `MEDIUM`. |
| Remediation | 1. Update the guardrail to include content filters for all harmful categories: HATE, VIOLENCE, SEXUAL, INSULTS, MISCONDUCT. 2. Select the **Standard tier** (not Classic) for content filters — it offers better accuracy, broader language support (extensive multilingual support vs. English/French/Spanish only in Classic), prompt leakage detection, and extends protection to harmful content within code elements. Standard tier requires cross-Region inference to be enabled on the guardrail (configurable at creation or by modifying an existing guardrail). 3. Start with **HIGH** filter strength for customer-facing applications; evaluate false-positive rates on representative sample traffic and lower to MEDIUM only if necessary. 4. Apply filters to both INPUT and OUTPUT. 5. Before enabling blocking in production, use **detect mode** (`action=NONE`) to test guardrail behavior on live traffic — review trace output to validate decisions, then switch to `action=BLOCK` once confident. 6. Enforce guardrails organization-wide via IAM policy-based enforcement: add an IAM condition key (`bedrock:GuardrailIdentifier`) to deny any `InvokeModel`/`Converse` call that does not include a guardrail. For account-level or org-level enforcement configurations, set **both** `selectiveContentGuarding.messages` AND `selectiveContentGuarding.system` to `COMPREHENSIVE` to ensure guardrails evaluate all user messages AND system prompts regardless of input tags (use `SELECTIVE` only when you trust callers to correctly tag content). Setting only `messages` to COMPREHENSIVE leaves system prompts potentially unguarded. |
| Reference | [Bedrock Guardrails Content Filters](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-content-filters.html), [Safeguard Tiers for Guardrails](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-tiers.html), [Cross-Account Safeguards with Enforcements](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-enforcements.html), [Guardrails Best Practices](https://aws.amazon.com/blogs/machine-learning/build-safe-generative-ai-applications-like-a-pro-best-practices-with-amazon-bedrock-guardrails/), [IAM Guardrail Enforcement](https://aws.amazon.com/blogs/machine-learning/amazon-bedrock-guardrails-announces-iam-policy-based-enforcement-to-deliver-safe-ai-interactions/) |

#### FS-37 — User Feedback Mechanism

| Field | Detail |
|-------|--------|
| Severity | Informational |
| PDF ref | [PDF §1.2.4] — "Implement a user reporting mechanism that allows end users to flag abusive or harmful outputs. Reported incidents [are] reviewed within a defined process to refine content filters." |
| Description | Advisory: verifies application has a user reporting mechanism for harmful outputs. |
| Detection | Advisory check — inspects application configuration for feedback-related settings (e.g., `FEEDBACK_ENABLED`, `REPORT_ABUSE_ENDPOINT`). Checks for Lambda functions with "feedback" or "report" in the name. |
| Remediation | 1. Implement a "Report this response" button in the application UI. 2. Route reported responses to an SQS queue or DynamoDB table for review. 3. Define an SLA for reviewing reported content (e.g., 24 hours). 4. Use reported incidents to refine guardrail content filters and word lists. 5. Log all reports with Bedrock invocation logging correlation IDs. |
| Reference | [Bedrock Model Invocation Logging](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html) |

#### FS-38 — Guardrail Word Filters and Business Term Allowlists

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.4 — Practical guidance] — "Create allowlists for business terms that include approved terminology for: brand names, product names, industry terms, and technical vocabulary. Also test filter settings to verify that your content filters allow necessary business communications and generate accurate alerts. Monitor and adjust regularly your filtering system to reduce false positives." |
| Description | Checks guardrails have word/phrase block filters configured and that approved business terminology allowlists are defined to prevent false positives on legitimate financial services vocabulary. |
| Detection | Calls `bedrock:GetGuardrail` and inspects `wordPolicy`. Flags guardrails with no custom `words` array (blocked phrases). Also checks `managedWordLists` for the AWS-managed `PROFANITY` list. Note: a guardrail with only the profanity filter and no custom FinServ-specific blocked terms should still be flagged as incomplete for financial services use cases. |
| Remediation | 1. Add blocked words/phrases to the guardrail word filter (profanity, slurs, competitor names if applicable). Each custom word/phrase entry has a maximum length of **100 characters** per the API (`GuardrailWordConfig.text`); the console UI additionally limits entries to **up to three words** per phrase. You can add up to **10,000 items** to the custom word filter. 2. Enable the AWS-managed profanity filter (`managedWordListsConfig` with `type=PROFANITY`) as a baseline. 3. Create an allowlist of approved business terminology: brand names, product names, industry terms, technical vocabulary — document this separately as the guardrail word filter only blocks, it does not allowlist. Test filter settings to verify legitimate business communications are not blocked. 4. Monitor and adjust regularly to reduce false positives. |
| Reference | [Bedrock Guardrails Word Filters](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-word-filters.html) |

### Biased Output (FS-39 to FS-42)

> **PDF source:** §1.2.5 Model output is biased. PDF-listed mitigations:
> (a) AWS AI Service Cards to understand how providers address fairness/bias per model;
> (b) prompt engineering;
> (c) Amazon Bedrock Guardrails;
> (d) Bedrock Evaluations to measure bias;
> (e) Amazon SageMaker Clarify for bias detection, transparency, and prediction explanation
> on fine-tuned and self-trained models;
> (f) develop and maintain a bias testing dataset with representative cases across
> demographic groups, geographic regions, and sensitive attributes — run periodically and
> after each model update.

#### FS-39 — SageMaker Clarify Bias

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.5] — "Use Amazon SageMaker Clarify to detect bias, increase transparency, and explain predictions for your fine-tuned and self-trained AI models." |
| Description | Verifies Clarify model bias monitoring is configured for financial decision models. |
| Detection | Calls `sagemaker:ListMonitoringSchedules` with the `MonitoringTypeEquals=ModelBias` filter parameter (the `MonitoringType` field on the `MonitoringScheduleSummary` response has one of four values: `DataQuality`, `ModelQuality`, `ModelBias`, `ModelExplainability`). Flags if no bias monitoring schedules exist. Cross-references with endpoints tagged `use-case=financial-decision` or similar. Clarify bias monitoring publishes metrics to the `aws/sagemaker/Endpoints/bias-metrics` namespace for real-time endpoints (and `aws/sagemaker/ModelMonitoring/bias-metrics` for batch transform jobs) with `Endpoint`, `MonitoringSchedule`, `BiasStage`, `Label`, `LabelValue`, `Facet`, and `FacetValue` dimensions. |
| Remediation | 1. Create a SageMaker Clarify bias monitoring schedule for each financial decision model endpoint. 2. Specify facets (protected attributes: age, gender, race, geography) and bias metrics (DPL, DI, DPPL). 3. Provide a baseline bias report from training data. 4. Configure CloudWatch alarms on bias metric violations on the `aws/sagemaker/Endpoints/bias-metrics` namespace. Note: `publish_cloudwatch_metrics` is enabled by default — do NOT set it to `Disabled` in the model bias job definition's `Environment` map, as that would stop metrics from being published to CloudWatch. |
| Reference | [SageMaker Clarify Bias Detection](https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-detect-post-training-bias.html) |

#### FS-40 — Bedrock Bias Evaluation Datasets and Cadence

| Field | Detail |
|-------|--------|
| Severity | Informational |
| PDF ref | [PDF §1.2.5] — "Develop and maintain a bias testing dataset that includes representative test cases across demographic groups, geographic regions, and other sensitive attributes relevant to your use case. Run these test cases periodically and after model updates." |
| Description | Checks evaluation jobs include demographic fairness test cases across protected groups and verifies evaluations are run on a defined periodic schedule and after each model update. |
| Detection | Calls `bedrock:ListEvaluationJobs` to enumerate existing jobs, then calls `bedrock:GetEvaluationJob` for each to inspect the full `evaluationConfig` including dataset configuration for demographic diversity test cases. Checks the `creationTime` of the most recent evaluation job and flags if it is older than 90 days or if no evaluation was run after the most recent model deployment. Note: `ListEvaluationJobs` returns only job summaries — dataset configuration details require `GetEvaluationJob`. |
| Remediation | 1. Create a bias evaluation dataset with representative test cases across demographic groups, geographic regions, and other sensitive attributes. 2. Schedule evaluation jobs to run at least quarterly via EventBridge. 3. Trigger an evaluation job automatically after each model update in your CI/CD pipeline. 4. Store results for audit and trend analysis. |
| Reference | [Bedrock Model Evaluation](https://docs.aws.amazon.com/bedrock/latest/userguide/evaluation.html) |

#### FS-41 — SageMaker Clarify Explainability

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.5, extension] — PDF §1.2.5 recommends "Amazon SageMaker Clarify to detect bias, increase transparency, and explain predictions". ECOA/Fair Housing adverse-action-notice use case is an FS-specific extension of Clarify explainability not named verbatim in the PDF. |
| Description | Verifies Clarify explainability monitoring for adverse action notices (commonly cited under ECOA for credit decisions; this is an FS industry-practice extension, not a PDF-prescribed control). |
| Detection | Calls `sagemaker:ListMonitoringSchedules` with the `MonitoringTypeEquals=ModelExplainability` filter parameter. Flags if no explainability monitoring schedules exist for financial decision model endpoints. Clarify explainability monitoring publishes metrics to the `aws/sagemaker/Endpoints/explainability-metrics` namespace for real-time endpoints (and `aws/sagemaker/ModelMonitoring/explainability-metrics` for batch transform jobs) with `Endpoint`, `MonitoringSchedule`, `ExplainabilityMethod` (value: `KernelShap`), `Label`, and `ValueType` (values: `GlobalShapValues` or `ExpectedValue`) dimensions. |
| Remediation | 1. Create a SageMaker Clarify explainability monitoring schedule using SHAP analysis. 2. Configure feature attribution baselines. 3. Use explainability outputs to generate adverse action notices (top contributing factors for negative decisions) where your firm's use case and regulatory interpretation require them. 4. Retain explainability reports for regulatory audit. |
| Reference | [SageMaker Clarify Explainability](https://docs.aws.amazon.com/sagemaker/latest/dg/clarify-model-explainability.html) |

#### FS-42 — AI Service Cards

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.4, §1.2.5, §1.2.14] — "Amazon provides AI Service Cards for models that are pre-trained for AWS services like Amazon Bedrock and Amazon Q. These cards help you understand how Amazon addresses toxicity in each model." Referenced in three separate PDF risk sections. |
| Description | Checks SageMaker Model Cards document intended use and bias evaluations. |
| Detection | Calls `sagemaker:ListModelCards`. For each card, calls `sagemaker:DescribeModelCard` and inspects the content JSON for `intended_uses`, `business_details`, and `evaluation_details` sections. Flags cards missing these sections. |
| Remediation | 1. Create a SageMaker Model Card for each production model. 2. Document: intended use cases, out-of-scope uses, training data description, bias evaluation results, performance metrics. 3. Review and update cards after each model retrain. 4. For Bedrock foundation models, reference the AWS AI Service Cards published by Amazon. |
| Reference | [SageMaker Model Cards](https://docs.aws.amazon.com/sagemaker/latest/dg/model-cards.html), [AWS AI Service Cards](https://aws.amazon.com/ai/responsible-ai/resources/) |

### Sensitive Information Disclosure (FS-43 to FS-46)

> **PDF source:** §1.2.6 Sensitive information disclosure. PDF-listed mitigations:
> (a) Bedrock Guardrails sensitive information filters for PII, PHI;
> (b) data classification scanning and access controls on AI data sources;
> (c) strict IAM access controls for Bedrock API;
> (d) mask sensitive information in CloudWatch Logs and custom application logging;
> (e) protect training and fine-tuning data via data protection best practices;
> (f) monitor PII in training/fine-tuning/RAG data with Amazon Macie;
> (g) remove, mask, or tokenize PII before use in training, fine-tuning, or RAG;
> (h) Practical guidance: least privilege for agent identities; user-authorized communications
> to tool services; propagate end-user identities so tool services can validate them without
> revealing them to unauthorized third parties.

#### FS-43 — CloudWatch Log PII Masking

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.6] — "If you implement model invocation logging for the LLM or custom logging logic in your application, make sure to mask sensitive information in your log data." References "Amazon CloudWatch – Help protect sensitive log data with masking". |
| Description | Checks CloudWatch Logs data protection policies mask PII in Bedrock invocation logs. |
| Detection | Identifies CloudWatch log groups used by Bedrock invocation logging (from `bedrock:GetModelInvocationLoggingConfiguration`). Calls `logs:GetDataProtectionPolicy` for each log group. Flags log groups with no data protection policy or policies missing PII identifiers. Note: model invocation logging only captures calls made through the `bedrock-runtime` endpoint (`Converse`, `ConverseStream`, `InvokeModel`, `InvokeModelWithResponseStream`); calls through other endpoints such as the Responses API (`bedrock-mantle` endpoint) are not captured. |
| Remediation | 1. Create a CloudWatch Logs data protection policy on each Bedrock log group. 2. Include managed data identifiers using their exact ARN-based IDs — country-code suffixes are **required** in the ARN for most identifiers (the data-types table uses the short name such as `Ssn`, but the ARN must include the country code): `Ssn-US` (US Social Security Number; `Ssn-ES` for Spain — there is no bare `Ssn` ARN), `CreditCardNumber` (no suffix), `CreditCardSecurityCode` (no suffix), `EmailAddress` (no suffix), `Address` (no suffix), `PhoneNumber-US`, `BankAccountNumber-US`, `DriversLicense-US`, `PassportNumber-US`, `IndividualTaxIdentificationNumber-US`. 3. Add a `Deidentify` operation statement (no hyphen — this is the exact JSON key required in the policy document, even though AWS prose documentation uses "De-identify") to mask sensitive data, and a separate `Audit` statement to emit findings to CloudWatch. The `Deidentify` operation must contain an empty `"MaskConfig": {}` object. 4. **Retroactive masking scope:** A **log group-level** data protection policy only masks data ingested **after** the policy is applied — historical log events are not retroactively masked. However, an **account-level** data protection policy applies to both existing log groups and log groups created in the future. For maximum coverage, consider creating an account-level policy in addition to log group-level policies. Apply policies at log group creation time or as early as possible. 5. Test by sending a log entry containing sample PII and verifying it is masked in subsequent reads. |
| Reference | [CloudWatch Logs Data Protection](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/mask-sensitive-log-data.html), [PII Data Identifier ARNs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/protect-sensitive-log-data-types-pii.html), [Financial Data Identifier ARNs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/protect-sensitive-log-data-types-financial.html) |

#### FS-44 — Amazon Macie PII Scanning and Pre-Processing

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.6] — "Monitor personally identifiable information (PII) in your data when you train models, fine-tune them, or use retrieval-augmented generation (RAG)" and "Remove, mask, or tokenize personally identifiable information (PII) or sensitive data before you use it for training, fine-tuning, or retrieval-augmented generation (RAG)." |
| Description | Verifies Macie is enabled and scanning AI/ML data buckets, and checks that a PII pre-processing step (tokenization, masking, or removal) exists in training and RAG ingestion pipelines before data reaches the model. |
| Detection | Calls `macie2:GetMacieSession` to verify Macie is enabled. Calls `macie2:GetAutomatedDiscoveryConfiguration` to check whether automated sensitive data discovery is enabled (preferred over manual classification jobs — automated discovery evaluates S3 buckets daily without explicit job creation). Also calls `macie2:ListClassificationJobs` to check for any additional targeted jobs covering S3 buckets tagged for AI/ML use. Additionally inspects SageMaker Processing jobs or Glue jobs for PII-related naming patterns indicating a pre-processing pipeline. |
| Remediation | 1. Enable Amazon Macie in the account. 2. **Preferred:** Enable Macie **Automated Sensitive Data Discovery** (via `macie2:UpdateAutomatedDiscoveryConfiguration` set to `ENABLED`) — this continuously evaluates ALL S3 buckets in the account or organization daily, selects representative objects, and produces sensitive-data findings without requiring manual job creation. 3. For higher-priority AI/ML buckets where you need full-depth scans, supplement with targeted classification jobs (`macie2:CreateClassificationJob`) scheduled at least weekly. 4. Implement a PII pre-processing step in your data pipeline (SageMaker Processing job, Glue job, or Lambda) that tokenizes, masks, or removes PII before data is used for training or RAG ingestion. 5. Use Amazon Comprehend `DetectPiiEntities` or Macie findings to identify PII locations and feed them into the pre-processing step. 6. Route Macie findings to EventBridge and then to your SIEM or ticketing system for timely investigation. |
| Reference | [Amazon Macie](https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html), [Macie Automated Sensitive Data Discovery](https://docs.aws.amazon.com/macie/latest/user/discovery-asdd.html), [Amazon Comprehend PII Detection](https://docs.aws.amazon.com/comprehend/latest/dg/pii.html) |

#### FS-45 — Guardrail PII Filters

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.6] — "Use Amazon Bedrock Guardrails to detect and filter structured sensitive information in model inputs and outputs, such as personally identifiable information (PII), protected health information (PHI)." |
| Description | Checks guardrails have PII entity filters for SSN, credit card, and account numbers. |
| Detection | Calls `bedrock:GetGuardrail` and inspects `sensitiveInformationPolicy.piiEntities`. Flags guardrails missing filters for critical PII types: `US_SOCIAL_SECURITY_NUMBER`, `CREDIT_DEBIT_CARD_NUMBER`, `CREDIT_DEBIT_CARD_CVV`, `CREDIT_DEBIT_CARD_EXPIRY`, `US_BANK_ACCOUNT_NUMBER`, `US_BANK_ROUTING_NUMBER`, `PIN`, `SWIFT_CODE`, `INTERNATIONAL_BANK_ACCOUNT_NUMBER`, `US_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER`, `EMAIL`, `PHONE`. |
| Remediation | 1. Update the guardrail to add PII entity filters for all relevant types. 2. Configure separate input and output actions using the `inputAction` and `outputAction` fields: set `outputAction=ANONYMIZE` (replace with placeholder such as `{US_SOCIAL_SECURITY_NUMBER}`) so PII in model responses is masked before reaching the user; set `inputAction=BLOCK` for PII types that should never be submitted (e.g., SSN, credit card numbers). 3. Use `inputEnabled` and `outputEnabled` to selectively enable evaluation per direction — disable evaluation on a direction you don't need to reduce cost and latency. 4. **PHI coverage nuance:** The Bedrock Guardrails sensitive information filter has only limited built-in PHI entities — specifically `CA_HEALTH_NUMBER` (Canada) and `UK_NATIONAL_HEALTH_SERVICE_NUMBER` (UK). For US HIPAA PHI (for example, Medical Record Numbers, Health Plan Beneficiary Numbers, Medicare Beneficiary Identifiers), there is no built-in entity type — use `regexesConfig` (custom regex patterns) on the guardrail to detect these patterns, complemented by downstream CloudWatch Logs data protection policies (see FS-43) which have PHI identifiers under the HIPAA category. 5. **Critical limitation — tool_use outputs:** The sensitive information filter does NOT detect PII when models respond with `tool_use` (function call) output parameters via supported APIs. For FinServ agentic applications where models invoke tools and return structured function-call responses, implement application-layer PII scanning on tool outputs before they are processed or displayed. 6. **Critical limitation — invocation logs:** Guardrail PII masking applies only to content sent to and returned from the inference model. It does NOT apply to model invocation logs — the `input` field in CloudWatch Logs always contains the original, unmasked request regardless of guardrail intervention. Use CloudWatch Logs data protection policies (see FS-43) to mask PII in logs separately. Similarly, the `match` field in guardrail trace output contains the original PII value, not the masked output. 7. Test with sample inputs containing each PII type and verify both input blocking and output anonymization work as expected. |
| Reference | [Bedrock Guardrails Sensitive Information Filters](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-sensitive-filters.html) |

#### FS-46 — Data Classification Tagging

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.6] — "Implement data classification scanning and access controls on the data sources connected to your AI system to prevent disclosure of company-confidential or proprietary information." |
| Description | Verifies AI/ML S3 buckets are tagged with data classification labels. |
| Detection | Lists S3 buckets and filters for AI/ML-related names or tags. Calls `s3:GetBucketTagging` for each and checks for a `data-classification` tag with values like `public`, `internal`, `confidential`, `restricted`. Flags buckets missing the tag. |
| Remediation | 1. Define a data classification taxonomy (e.g., Public, Internal, Confidential, Restricted). 2. Tag all AI/ML S3 buckets with `data-classification=<level>`. 3. **Detective enforcement:** Create an AWS Config managed rule (`required-tags`, checks up to six tag keys at a time) to identify buckets missing the tag and trigger remediation via a custom SSM automation document (note: the AWS-managed `AWS-SetRequiredTags` automation document does NOT work as a remediation with this rule — you must author a custom Systems Manager automation document). 4. **Preventive enforcement:** Use AWS Organizations **Tag Policies** to require the `data-classification` tag key with allowed values (Public, Internal, Confidential, Restricted) across accounts — Tag Policies are preventive and complement the detective Config rule. 5. Use tag-based IAM policies (via condition keys `aws:ResourceTag/data-classification`) to restrict S3 access based on classification level. 6. Pair with Macie classification jobs (see FS-44) so that buckets automatically classified as containing sensitive data are flagged if their `data-classification` tag is missing or inconsistent with the Macie findings. |
| Reference | [AWS Tagging Best Practices](https://docs.aws.amazon.com/tag-editor/latest/userguide/tagging.html), [AWS Config required-tags Rule](https://docs.aws.amazon.com/config/latest/developerguide/required-tags.html), [AWS Organizations Tag Policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_tag-policies.html) |

