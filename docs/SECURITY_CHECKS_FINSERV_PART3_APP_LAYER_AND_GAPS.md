# FinServ GenAI Risk Checks — Part 3: Application-Layer Controls & Material Gaps (FS-47 to FS-69)

This is **Part 3 of 3** of the FinServ GenAI security checks derived from the
[AWS guide for Financial Services risk management of the use of Generative AI (March 2026)](https://d1.awsstatic.com/onedam/marketing-channels/website/public/global-FinServ-ComplianceGuide-GenAIRisks-public.pdf)
(referred to throughout as "the FinServ Guide").

This part covers **22 standalone checks** across 6 PDF risk categories (FS-64 is merged into upstream BR-04 — see extension note in the Material Gaps section):

- **Hallucination** (FS-47 to FS-50) — §1.2.7
- **Prompt Injection** (FS-51 to FS-54) — §1.2.8
- **Improper Output Handling** (FS-55 to FS-58) — §1.2.13
- **Off-Topic & Inappropriate Output** (FS-59 to FS-60) — §1.2.2
- **Out-of-Date Training Data** (FS-61 to FS-63) — §1.2.10
- **Additional Controls — Material Gaps** (FS-64 to FS-69) — cross-cutting checks addressing PDF-listed mitigations not covered elsewhere; *FS-64 merged into upstream*

**Companion files:**

- `SECURITY_CHECKS_FINSERV_PART1_INFRA_CONTROLS.md` — FS-01 to FS-26 (Unbounded, Excessive Agency, Supply Chain, Training Poisoning, Vector Weaknesses)
- `SECURITY_CHECKS_FINSERV_PART2_GUARDRAILS_CONTENT_SAFETY.md` — FS-27 to FS-46 (Non-Compliant, Misinformation, Abusive, Biased, Sensitive Info)
- `SECURITY_CHECKS_FINSERV_COMMON.md` — shared intro, severity rubric, validation note, upstream-overlap table

Each check includes how it is **detected** (the AWS API calls or configuration inspected)
and how a failure is **remediated** (the specific AWS actions to take).

See `SECURITY_CHECKS_FINSERV_COMMON.md` for:

- PDF traceability conventions (`[PDF §x.y.z]` vs `[PDF §x.y.z, extension]`)
- Severity rubric (High / Medium / Low / Informational) — see SECURITY_CHECKS_FINSERV_SEVERITY_METHODOLOGY.md
- Validation note and AWS service authorization references
- Relationship to upstream SM/BR/AC checks and consolidation recommendations

---

## FinServ GenAI Risk Checks — Part 3 content

### Hallucination (FS-47 to FS-50)

> **PDF source:** §1.2.7 Hallucination. PDF-listed mitigations:
> (a) prompt engineering;
> (b) RAG with Bedrock Knowledge Bases;
> (c) detect hallucinations in RAG and agent-based systems;
> (d) HITL validation for internal AI systems;
> (e) Automated Reasoning checks in Bedrock Guardrails;
> (f) Bedrock Guardrails contextual grounding checks with reference source and query;
> (g) response disclaimers in customer-facing applications informing users that AI responses
> should be verified for critical decisions.

#### FS-47 — Guardrail Grounding Threshold

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.7] — "You can use Amazon Bedrock Guardrails to detect and filter hallucinations in model responses by performing contextual grounding checks when you provide a reference source and query." |
| Description | Verifies guardrail grounding thresholds are set appropriately for financial use cases (this assessment recommends ≥ 0.7; AWS does not prescribe a specific minimum, but the valid range is 0 to 0.99). Note: contextual grounding checks are not supported for conversational chatbot use cases — only for summarization, paraphrasing, and Q&A. |
| Detection | Calls `bedrock:GetGuardrail` and inspects `contextualGroundingPolicy.filters` for the `GROUNDING` filter type. Checks that the `threshold` value is ≥ 0.7. Flags guardrails with lower thresholds or no grounding filter. |
| Remediation | 1. Update the guardrail to set the grounding filter threshold to at least 0.7 (this assessment recommends 0.8 for financial services to reduce hallucination risk — note: AWS does not prescribe a specific minimum, but the valid range is **0 to 0.99**; a value of 1.0 is explicitly invalid and will block all content per AWS documentation). 2. Enable the grounding filter for both the `GROUNDING` and `RELEVANCE` types. 3. Test with prompts that should and should not be grounded in the reference source — tune the threshold based on your false-positive/false-negative tolerance. 4. Monitor grounding filter invocation rates via CloudWatch using the `AWS/Bedrock/Guardrails` namespace. **Important limitation:** Contextual grounding checks support only summarization, paraphrasing, and question-answering use cases — **Conversational QA / Chatbot use cases are explicitly not supported** per AWS documentation. For FinServ chatbot deployments, use denied topics and content filters (FS-28, FS-36, FS-59) as the primary hallucination-mitigation controls instead. |
| Reference | [Bedrock Guardrails Contextual Grounding](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-contextual-grounding-check.html) |

#### FS-48 — RAG Knowledge Base

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.1, §1.2.7, §1.2.10] — "Use Retrieval-Augmented Generation (RAG) to enhance your model responses with information from trusted knowledge bases." Referenced in three separate PDF risk sections. |
| Description | Checks active Knowledge Bases are configured for RAG grounding. |
| Detection | Calls `ListKnowledgeBases` (via the `bedrock-agent` boto3 client; IAM action `bedrock:ListKnowledgeBases`) and checks that at least one KB exists with `status=ACTIVE`. Flags accounts with no active KBs when Bedrock models are in use (indicating responses are ungrounded). |
| Remediation | 1. Create a Bedrock Knowledge Base with your authoritative data sources. 2. Configure the KB with an appropriate embedding model and vector store. 3. Use `RetrieveAndGenerate` API instead of direct `InvokeModel` for customer-facing use cases. 4. Sync data sources on a regular schedule. |
| Reference | [Bedrock Knowledge Bases](https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base.html) |

#### FS-49 — Hallucination Disclaimer

| Field | Detail |
|-------|--------|
| Severity | Informational |
| PDF ref | [PDF §1.2.7] — "Implement response disclaimers in customer-facing applications, to inform end users that AI-generated responses should be verified for critical decisions." References "AWS Well-Architected Framework Generative AI Lens - Implement guardrails to mitigate harmful or incorrect model responses". |
| Description | Advisory: verifies application adds hallucination disclaimers to AI-generated outputs. |
| Detection | Advisory check — inspects application Lambda environment variables for disclaimer-related settings. Checks for post-processing Lambda functions that append disclaimers. |
| Remediation | 1. Add a standard disclaimer to all AI-generated responses: "This response is generated by AI and may contain inaccuracies. Please verify critical information independently." 2. Make the disclaimer configurable and non-removable by prompt manipulation. 3. For financial decisions, add: "This does not constitute financial advice." |
| Reference | [AWS Well-Architected GenAI Lens](https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/gensec02-bp01.html) |

#### FS-50 — Relevance Grounding Filters

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.2, §1.2.7] — "Use Amazon Bedrock Guardrails to detect and filter hallucinations in model responses by performing contextual grounding checks." Contextual grounding covers both `GROUNDING` and `RELEVANCE` filter sub-types. |
| Description | Checks guardrails have relevance grounding filters to prevent off-topic responses. |
| Detection | Calls `bedrock:GetGuardrail` and inspects `contextualGroundingPolicy.filters` for the `RELEVANCE` filter type. Flags guardrails with no relevance filter configured. |
| Remediation | 1. Update the guardrail to enable the `RELEVANCE` contextual grounding filter. 2. Set the threshold to at least 0.7 (valid range is **0 to 0.99**; a value of 1.0 is explicitly invalid per AWS documentation). 3. This ensures responses are relevant to the user's query and the provided reference source, filtering out off-topic hallucinations. **Important limitation:** Contextual grounding checks (both `GROUNDING` and `RELEVANCE`) support only summarization, paraphrasing, and question-answering use cases — **Conversational QA / Chatbot use cases are explicitly not supported** per AWS documentation. For FinServ chatbot deployments, use denied topics (FS-59) as the primary off-topic control. |
| Reference | [Bedrock Guardrails Contextual Grounding](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-contextual-grounding-check.html) |

### Prompt Injection (FS-51 to FS-54)

> **PDF source:** §1.2.8 Prompt injection. PDF-listed mitigations:
> (a) prompt engineering best practices to avoid prompt injection;
> (b) input validation — sanitize user input, remove special characters or use escape sequences,
> match expected format;
> (c) secure coding practices — parameterized queries, avoid string concatenation, minimal
> privileges;
> (d) security testing — regular testing for prompt injection and vulnerabilities, pentest,
> static code analysis, DAST;
> (e) stay updated — keep Bedrock SDK, libraries, and dependencies current;
> (f) Bedrock Guardrails to detect and block user inputs attempting to override system
> instructions through prompt attacks.

#### FS-51 — Prompt Attack Filters

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.8] — "Use Amazon Bedrock Guardrails to detect and block user inputs that attempt to override system instructions through prompt attacks." |
| Description | Verifies guardrails have PROMPT_ATTACK content filters enabled and are configured correctly for the Standard tier. |
| Detection | Calls `bedrock:GetGuardrail` and inspects `contentPolicy.filters` for a filter with `type=PROMPT_ATTACK`. Flags guardrails where this filter is absent, has `inputStrength` set to `NONE` or `LOW` (note: PROMPT_ATTACK only applies to inputs — there is no `outputStrength` for this filter type), or where `contentPolicy.tier.tierName=CLASSIC` (the PROMPT_ATTACK filter in Classic tier detects jailbreaks and prompt injection; in Standard tier it additionally detects **prompt leakage** — attempts to extract system prompts or developer instructions). |
| Remediation | 1. Ensure the guardrail is configured with the **Standard** content filters tier — prompt leakage detection (extracting system prompts/developer instructions) is available only in Standard tier; jailbreak and prompt injection detection are available in both tiers. Standard tier requires cross-Region inference to be enabled on the guardrail. You can configure Standard tier on a **new or existing guardrail**: for an existing guardrail, modify it via `UpdateGuardrail` (set `tierConfig.tierName=STANDARD` in `contentPolicyConfig` and add a `crossRegionConfig.guardrailProfileIdentifier`), or use the console by editing the guardrail and selecting Standard tier with cross-Region inference. 2. Add a `PROMPT_ATTACK` content filter with `inputStrength=HIGH`. 3. **Wrap user input in guardrail input tags when using `InvokeModel` or `InvokeModelResponseStream`** — for these APIs, PROMPT_ATTACK only evaluates content enclosed in input tags (e.g., `<amazon-bedrock-guardrails-guardContent_xyz>user text</amazon-bedrock-guardrails-guardContent_xyz>` — the reserved prefix is `amazon-bedrock-guardrails-guardContent` and the suffix should be a unique random string per request to prevent an attacker from closing the tag and appending malicious content). Untagged content is not evaluated for PROMPT_ATTACK when using these APIs. **Note:** When using the `Converse` API, use the `guardContent` field (`GuardrailConverseContentBlock`) in user messages to scope PROMPT_ATTACK evaluation to specific content — this is the Converse API equivalent of input tags. Without `guardContent`, the guardrail evaluates ALL message content (the entire messages array). Using `guardContent` in user messages ensures only user-provided content is evaluated for prompt attacks, while system prompts and conversation history are excluded. If no `guardContent` blocks are present in messages, the guardrail evaluates everything in the messages array. 4. Test with known prompt injection patterns (role-play attacks, instruction override, delimiter injection). 5. Monitor filter invocation rates via CloudWatch guardrail metrics (`InvocationsIntervened` in the `AWS/Bedrock/Guardrails` namespace, filtered by `GuardrailPolicyType=ContentPolicy`) for trending attack patterns. |
| Reference | [Bedrock Guardrails Prompt Attack](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-prompt-attack.html), [Safeguard tiers for guardrails](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-tiers.html), [Securing Amazon Bedrock Agents against indirect prompt injections](https://aws.amazon.com/blogs/machine-learning/securing-amazon-bedrock-agents-a-guide-to-safeguarding-against-indirect-prompt-injections/) |

#### FS-52 — Bedrock SDK Version Currency

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.8] — "Stay Updated – Keep your Amazon Bedrock SDK, libraries, and dependencies current to receive the latest security patches and updates." |
| Description | Checks Bedrock Lambda functions use current (non-deprecated) runtimes and SDK versions. |
| Detection | Calls `lambda:ListFunctions` and filters for functions with Bedrock-related names or environment variables referencing Bedrock. Checks each function's `Runtime` against the list of deprecated Lambda runtimes. |
| Remediation | 1. Update Lambda functions to use a currently supported runtime — as of April 2026, recommended runtimes are `python3.13` or `python3.14` for Python (both deprecation date June 30, 2029; `python3.12` remains supported through Oct 31, 2028), and `nodejs22.x` or `nodejs24.x` for Node.js (`nodejs20.x` reaches deprecation on April 30, 2026 and should not be used for new deployments). 2. Update the Bedrock SDK (boto3/botocore) to the latest version in your requirements.txt or package.json. 3. Test after upgrading to verify no breaking changes. 4. Subscribe to AWS Lambda runtime deprecation notifications via EventBridge or SNS (Lambda also surfaces runtime deprecation notices via AWS Health Dashboard and Trusted Advisor). |
| Reference | [Lambda Runtime Deprecation Policy](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html) |

#### FS-53 — WAF Injection Protection Rules

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.8, extension] — WAF SQLi and known-bad-inputs rule groups are not named in the PDF, but implement the PDF mitigation "Secure Coding Practices – use parameterized queries, avoid string concatenation for input, grant minimal access privileges" at the network edge for web-facing GenAI endpoints. |
| Description | Verifies WAF ACLs include SQL injection (`AWSManagedRulesSQLiRuleSet`) and known-bad-inputs (`AWSManagedRulesKnownBadInputsRuleSet`) managed rule groups for GenAI endpoints. |
| Detection | Calls `wafv2:ListWebACLs(Scope=REGIONAL)` and for each calls `wafv2:GetWebACL`. Inspects the rules list for `AWSManagedRulesSQLiRuleSet` and `AWSManagedRulesKnownBadInputsRuleSet`. Flags ACLs missing either rule group. |
| Remediation | 1. Add `AWSManagedRulesSQLiRuleSet` to your WAF Web ACL (contains SQLi detection rules for body, URI path, cookie, and query-string components). 2. Add `AWSManagedRulesKnownBadInputsRuleSet` for known Remote Command Execution (RCE) and vulnerability-discovery patterns (e.g., Log4j, Spring Core deserialization, path traversal) — note this rule group does NOT cover XSS; XSS is in `AWSManagedRulesCommonRuleSet` (see FS-56). 3. Set both rule groups to COUNT mode initially, review logs for false positives, then switch to BLOCK. 4. Create custom rules for GenAI-specific injection patterns if needed. |
| Reference | [AWS WAF Managed Rules](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html) |

#### FS-54 — Penetration Testing Evidence

| Field | Detail |
|-------|--------|
| Severity | Informational |
| PDF ref | [PDF §1.2.8] — "Security Testing – Test your applications regularly for prompt injection and other security vulnerabilities. Use penetration testing, static code analysis, and dynamic application security testing (DAST)." |
| Description | Advisory: verifies GenAI applications have been penetration tested for prompt injection and other AI-specific vulnerabilities. |
| Detection | Advisory check — inspects resource tags for `last-pentest-date` or checks for a documented penetration testing schedule. Cannot be fully automated. |
| Remediation | 1. Conduct penetration testing of your GenAI application at least annually and before major releases. 2. Include AI-specific test cases: prompt injection, jailbreak attempts, data extraction, system prompt leakage. 3. Use tools like Garak, PyRIT, manual red-teaming, or the **AWS Security Agent**. As of the March 2026 GA announcement, Security Agent runs from 6 AWS regions (N. Virginia, Oregon, Ireland, Frankfurt, Sydney, Tokyo) but can test targets across AWS, Azure, GCP, and on-premises environments. For multi-account FinServ deployments, Security Agent supports penetration testing on VPC resources **shared across AWS accounts in the same AWS Organization** via AWS Resource Access Manager (RAM) — enable this by launching Security Agent from a central security account and sharing VPC resources from sub-accounts via RAM. **Verify current region coverage on the [AWS Security Agent page](https://aws.amazon.com/security-agent/) before citing**, as AWS has been expanding regional availability and feature set rapidly. 4. Document findings and track remediation. 5. Tag resources with `last-pentest-date` for audit trail. |
| Reference | [AWS Penetration Testing Policy](https://aws.amazon.com/security/penetration-testing/), [AWS Security Agent GA](https://aws.amazon.com/about-aws/whats-new/2026/03/aws-security-agent-ondemand-penetration/) |

### Improper Output Handling (FS-55 to FS-58)

> **PDF source:** §1.2.13 Improper output handling. PDF-listed mitigations:
> (a) implement output validation rules against expected response format (e.g., JSON schema,
> SQL schema);
> (b) apply context-specific output sanitization — HTML encoding for web apps, SQL
> parameterization for database queries, command escaping for system integrations;
> (c) Practical guidance: treat model output as untrusted user input; use Bedrock Agents
> action-group Lambda to implement output encoding so output text is non-executable by
> JavaScript or Markdown.

#### FS-55 — Output Validation Lambda

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.13] — "Implement output validation rules specific to the expected response format. For example, if the AI system is expected to return structured data (JSON, SQL), validate the output against the expected schema before processing." |
| Description | Checks for Lambda functions implementing output validation/sanitization before AI responses reach downstream consumers. |
| Detection | Calls `lambda:ListFunctions` and searches for functions with naming patterns indicating output validation (e.g., "output-valid", "sanitiz", "post-process", "response-filter"). Flags if no such functions exist. |
| Remediation | 1. Implement a post-processing Lambda that validates AI model output before it reaches the end user or downstream system. 2. Validate output against expected schema (JSON schema validation for structured responses). 3. Strip or escape any executable content (HTML tags, JavaScript, SQL fragments). 4. Log rejected outputs for security monitoring. |
| Reference | [AWS Well-Architected Security Pillar — Application Security](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/application-security.html), [Bedrock Prompt Injection Security](https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-injection.html), [Well-Architected FSI Lens — FSISEC14 Monitor AI system outputs for security issues](https://docs.aws.amazon.com/wellarchitected/latest/financial-services-industry-lens/fsisec14.html) |

#### FS-56 — XSS Prevention WAF

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.13, extension] — WAF XSS rule groups are not named in the PDF, but implement the PDF mitigation "Apply context-specific output sanitization ... apply HTML encoding for web applications" at the network edge. |
| Description | Verifies WAF ACLs include XSS prevention rules to protect against AI-generated outputs containing malicious scripts. |
| Detection | Calls `wafv2:GetWebACL` for each regional ACL and inspects rules for `AWSManagedRulesCommonRuleSet` (which includes the four `CrossSiteScripting_*` rules covering request body, query arguments, cookies, and URI path) or custom rules using `XssMatchStatement` on request components. Flags ACLs missing XSS protection. |
| Remediation | 1. Add `AWSManagedRulesCommonRuleSet` to your WAF Web ACL (includes `CrossSiteScripting_COOKIE`, `CrossSiteScripting_QUERYARGUMENTS`, `CrossSiteScripting_BODY`, and `CrossSiteScripting_URIPATH` rules — all four inspect **inbound request** components). 2. `XssMatchStatement` and the CRS XSS rules inspect **request** components only (body, query string, URI path, cookies, headers). WAF does NOT inspect arbitrary response bodies for XSS — response inspection (`ResponseInspection`) is available only in `AWSManagedRulesATPRuleSet`/`AWSManagedRulesACFPRuleSet` for CloudFront-protected ACLs and only scans for configured success/failure strings. 3. To protect against XSS in **AI-generated output**, enforce output encoding at the application layer (see FS-57) — rendering raw model output in a browser without encoding is the root cause that WAF cannot mitigate after the fact. 4. Apply output encoding in your application layer as defense-in-depth. |
| Reference | [AWS WAF XSS Protection](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html) |

#### FS-57 — Output Encoding

| Field | Detail |
|-------|--------|
| Severity | Informational |
| PDF ref | [PDF §1.2.13] — "Apply context-specific output sanitization based on the downstream consumer. For example, apply HTML encoding for web applications, SQL parameterization for database queries, and command escaping for system integrations." Practical guidance: "Use Amazon Bedrock Agents to securely integrate with AWS native and third-party services and implement output encoding in the action group Lambda function under an Amazon Bedrock Agent. Encoding all output text presented to end-users makes it automatically non-executable by JavaScript or Markdown." |
| Description | Advisory: verifies application encodes GenAI outputs appropriately for the rendering context (HTML, JSON, SQL). |
| Detection | Advisory check — inspects application Lambda functions for encoding libraries or patterns (e.g., `html.escape`, `json.dumps`, `markupsafe`). Checks environment variables for encoding-related configuration. |
| Remediation | 1. Treat all model output as untrusted user input. 2. Apply context-specific encoding: HTML encoding for web display, SQL parameterization for database queries, command escaping for system integrations. 3. Use Bedrock Agents action-group Lambda functions to implement output encoding — encoding all output text makes it non-executable by JavaScript or Markdown renderers. 4. Never render raw model output in a web page without encoding. |
| Reference | [OWASP Output Encoding](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) |

#### FS-58 — Output Schema Validation

| Field | Detail |
|-------|--------|
| Severity | Informational |
| PDF ref | [PDF §1.2.13] — "Implement output validation rules specific to the expected response format. For example, if the AI system is expected to return structured data (JSON, SQL), validate the output against the expected schema before processing." |
| Description | Checks for structured output validation in GenAI pipelines (JSON schema, XML schema, or custom validators). |
| Detection | Inspects Step Functions state machine definitions for states that perform schema validation (e.g., `Choice` states with JSON path conditions, Lambda states with "schema" or "validate" in the name). Does not rely on API Gateway response models as a validation signal because those are used for SDK generation, not runtime validation. |
| Remediation | 1. Define a JSON schema for expected AI output format. 2. Add a validation step in your pipeline (Lambda function or Step Functions Choice state) that rejects non-conforming outputs **before** returning the response to clients — this is the runtime enforcement point. 3. Note: API Gateway *response models* in REST APIs are used for SDK generation (user-defined data types) and documentation — they do NOT perform runtime validation of response payloads. API Gateway *request validators* only validate inbound requests against request models. To validate AI output at runtime, implement the check in Lambda/Step Functions before the response reaches API Gateway. 4. Return a safe fallback response when validation fails. 5. Log rejected outputs (without leaking sensitive content) for security monitoring. |
| Reference | [API Gateway Request and Response Validation](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-request-validation.html) |

### Off-Topic & Inappropriate Output (FS-59 to FS-60)

> **PDF source:** §1.2.2 Off-topic and inappropriate output. PDF-listed mitigations:
> (a) prompt engineering with an allowlist of approved topics aligned with business purpose;
> (b) content filters and denied topics in Bedrock Guardrails;
> (c) Bedrock Guardrails contextual grounding check with reference source and query;
> (d) HITL validation for internal AI systems.

#### FS-59 — Guardrail Topic Allowlist

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.2] — "Configure content filters and guardrails to restrict model responses to approved topics." The check name uses "allowlist" loosely — implementation uses denied-topic lists to block out-of-scope content. |
| Description | Verifies guardrails restrict GenAI to on-topic financial services responses via denied topics. |
| Detection | Calls `bedrock:GetGuardrail` and inspects `topicPolicy.topics`. Checks that denied topics exist to block off-topic conversations (e.g., politics, entertainment, medical advice). Flags guardrails with no topic restrictions. |
| Remediation | 1. Define denied topics that are outside your business scope (e.g., "medical advice", "legal advice", "political opinions", "entertainment recommendations"). 2. Add these as denied topics in the guardrail with clear descriptions and sample phrases. 3. Test with off-topic prompts to verify they are blocked. 4. Use the system prompt to positively scope the assistant's role. |
| Reference | [Bedrock Guardrails Topic Policies](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-denied-topics.html) |

#### FS-60 — Contextual Grounding for Off-Topic

| Field | Detail |
|-------|--------|
| Severity | Informational |
| PDF ref | [PDF §1.2.2] — "Use prompt engineering techniques to guide the model toward appropriate topics and prevent unwanted responses. Include an allowlist of approved topics aligned with the business purpose." Use of Bedrock Prompt Management for system prompt versioning is an implementation choice. |
| Description | Advisory: verifies system prompts explicitly scope the assistant's role to prevent off-topic responses. |
| Detection | Advisory check — inspects Bedrock Prompt Management templates (via `ListPrompts` on the `bedrock-agent` boto3 client; IAM action `bedrock:ListPrompts`) for system prompt content that defines the assistant's role, scope, and boundaries. Flags if no prompt templates exist. |
| Remediation | 1. Define a clear system prompt that states: the assistant's role, allowed topics, prohibited topics, and response format. 2. Use Bedrock Prompt Management to version and manage system prompts. 3. Include explicit instructions like "You are a financial services assistant. Only answer questions related to [specific topics]. Decline all other requests politely." 4. Test with boundary-case prompts. |
| Reference | [Bedrock Prompt Management](https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-management.html) |

### Out-of-Date Training Data (FS-61 to FS-63)

> **PDF source:** §1.2.10 Out-of-date training data. PDF-listed mitigations:
> (a) RAG with Bedrock Knowledge Bases;
> (b) keep knowledge bases up to date (sync data sources);
> (c) HITL validation for internal AI systems;
> (d) data currency disclaimers in AI system responses; source attribution via
> RetrieveAndGenerate API for users to verify currency.

#### FS-61 — Knowledge Base Sync Schedule

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.10] — "Keep your knowledge bases up to date." Automated scheduling via EventBridge operationalises this mitigation. |
| Description | Checks EventBridge Scheduler or EventBridge rules automate KB data source sync on a regular schedule. |
| Detection | Calls `events:ListRules` and searches for rules with targets that invoke `StartIngestionJob` (IAM action `bedrock:StartIngestionJob`) or Lambda functions that trigger KB sync. Also checks AWS Scheduler (`scheduler:ListSchedules`) for schedules targeting KB sync. Flags if no scheduled sync mechanism exists. |
| Remediation | 1. Use **EventBridge Scheduler** (the current recommended approach — EventBridge scheduled rules are a legacy feature) to create a recurring schedule that triggers KB data source sync: create a schedule with a rate expression (e.g., `rate(1 day)`) or cron expression (e.g., `cron(0 2 * * ? *)`) targeting a Lambda function. 2. The Lambda function calls `StartIngestionJob` (IAM action `bedrock:StartIngestionJob`) for each data source. 3. Add error handling and CloudWatch alarms for failed syncs. |
| Reference | [EventBridge Scheduler](https://docs.aws.amazon.com/scheduler/latest/UserGuide/what-is-scheduler.html), [EventBridge Scheduled Rules (legacy)](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-rule-schedule.html) |

#### FS-62 — Data Currency Disclaimer

| Field | Detail |
|-------|--------|
| Severity | Informational |
| PDF ref | [PDF §1.2.10] — "Include data currency disclaimers in AI system responses where appropriate. Use source attribution in RAG-based response for end users to verify currency of information." |
| Description | Advisory: verifies application adds data currency disclaimers to AI-generated outputs. |
| Detection | Advisory check — inspects application configuration for data-currency disclaimer settings. Checks system prompts for instructions to include data freshness information. |
| Remediation | 1. Add a data currency disclaimer to responses: "This information is based on data available as of [date]. It may not reflect the most recent changes." 2. Use the `RetrieveAndGenerate` API's source attribution to display document dates. 3. Configure the system prompt to instruct the model to caveat time-sensitive information. |
| Reference | [Bedrock RetrieveAndGenerate API](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_RetrieveAndGenerate.html) |

#### FS-63 — Foundation Model Lifecycle Policy

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.10, extension] — FM currency is conceptually related to "out-of-date training data" but the specific Bedrock lifecycle-status check is not named in the PDF. The PDF's "1.1.6 Monitor and improve" general guidance says "Update your foundation models when new versions become available" — this FS check operationalises that guidance. See also FS-34 (TPRM) which the PDF places under §1.2.12. |
| Description | Checks for a model lifecycle management process and Config rules to ensure models are updated when new versions are available. |
| Detection | Calls `config:DescribeConfigRules` and searches for rules targeting Bedrock resources. Calls `bedrock:GetFoundationModel` for each model in use and inspects `modelLifecycle.status`. Flags models with status `LEGACY` (note: the Bedrock API exposes only two lifecycle status values — `ACTIVE` and `LEGACY`; models past their `endOfLifeTime` are removed from the service entirely and return a ResourceNotFound error, so any model still reachable via the API that is not `ACTIVE` will be `LEGACY`). |
| Remediation | 1. Create an AWS Config custom rule that flags Bedrock models with `modelLifecycle.status=LEGACY`. 2. Establish a model lifecycle policy: evaluate new model versions within 30 days of release, test in staging, migrate production within 90 days (and before the `endOfLifeTime` published in the Bedrock model lifecycle page). 3. Subscribe to AWS Bedrock model lifecycle notifications. 4. Document the policy and assign an owner. 5. **Budget planning for FinServ:** For models with EOL dates after February 1, 2026, after a minimum of 3 months in Legacy state a model enters a **public extended access period** during which the model provider may set higher pricing. The `publicExtendedAccessTime` timestamp in the `FoundationModelLifecycle` response indicates when this phase begins. Include this phase in contract-and-budget review so FinServ cost governance teams are aware of potential price changes before migrating off Legacy models. |
| Reference | [Bedrock Model Lifecycle](https://docs.aws.amazon.com/bedrock/latest/userguide/model-lifecycle.html) |

### Additional Controls — Material Gaps (FS-64 to FS-69)

These checks address mitigations explicitly called out in the AWS FinServ Guide that were
not covered by the original checks in the upstream AIML Security Assessment (BR/SM/AC).
FS-64 is merged into upstream BR-04 (see extension note below); FS-65 to FS-69 ship as
standalone checks.

#### FS-64 — Guardrail Trace Logging → *Merged into upstream BR-04*

> **Upstream extension note (do not ship as a standalone check):** The detection and remediation
> content from FS-64 should be added as a refinement of the existing **BR-04 (Model Invocation
> Logging)** check in the upstream repo.
>
> **What to add to BR-04:**
> - After verifying that `bedrock:GetModelInvocationLoggingConfiguration` shows logging is
>   enabled, additionally verify the log output captures **guardrail trace data**: when
>   guardrails are applied during inference, the invocation log contains a `guardrailTrace`
>   object with `action` (values: `INTERVENED` or `NONE`), `inputAssessments`, and
>   `outputAssessments` arrays detailing which policies were evaluated and their results.
> - **Important logging coverage gap:** Model invocation logging only captures calls made through the `bedrock-runtime` endpoint (`Converse`, `ConverseStream`, `InvokeModel`, `InvokeModelWithResponseStream`). Calls made through the `bedrock-mantle` endpoint (e.g., the Responses API) are **not currently captured** by invocation logging. If your application uses the Responses API, implement application-level logging as a compensating control.
> - Add a remediation note on **retention requirements**: NYDFS 23 NYCRR 500.06 explicitly
>   requires cybersecurity records for ≥ 5 years; SR 11-7 does not prescribe a specific period
>   but requires documentation be maintained for the duration of model use plus a reasonable
>   period thereafter (commonly met with 5–7 year retention per firm policy). Consult your
>   compliance and records-management team for exact requirements.
> - Suggest creating CloudWatch Metrics filters to track guardrail intervention rates (filter
>   on `guardrailTrace.action = INTERVENED`) and applying CloudWatch Logs data protection
>   policies to mask PII in traces.
> - PDF traceability: [PDF §1.2.1] — "Maintain audit logs of AI-generated outputs and the
>   guardrails applied to support regulatory reporting and post-incident analysis." Also
>   §1.2.9 — "Implement audit logging of all actions taken by AI agents."
>
> **Reference:** [Bedrock Model Invocation Logging](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html)

#### FS-65 — KB Data Source S3 Event Notifications

| Field | Detail |
|-------|--------|
| Severity | High (deleted bucket) / Medium (notifications) |
| PDF ref | [PDF §1.2.3] — "Use integrity monitoring on knowledge base data sources to detect unauthorized modifications... For example on S3 data sources use Amazon S3 event notification to track changes to documents." **Note:** This check overlaps with FS-33; FS-33 verifies notifications are *enabled* on the bucket, while FS-65 verifies that notifications are *routed to an alerting destination* (SNS/Lambda/EventBridge rule with a target). In the final PR to aws-samples these two checks may be consolidated into a single check at the reviewer's discretion. |
| Description | Checks that S3 event notifications on KB data-source buckets are routed to an alerting destination (EventBridge rule with SNS/Lambda target, or direct SNS/SQS/Lambda notification) — not just enabled with no consumer. |
| Detection | Identifies KB data-source S3 buckets via `ListDataSources` and `GetDataSource` (via the `bedrock-agent` boto3 client; IAM actions `bedrock:ListDataSources` and `bedrock:GetDataSource`). For each bucket, calls `s3:GetBucketNotificationConfiguration` and checks for the presence of `EventBridgeConfiguration`, `TopicConfigurations`, `QueueConfigurations`, or `LambdaFunctionConfigurations`. Flags buckets with no notifications configured. |
| Remediation | 1. Enable EventBridge notifications on each KB data-source bucket: `aws s3api put-bucket-notification-configuration --bucket <name> --notification-configuration '{"EventBridgeConfiguration":{}}'`. 2. Create an EventBridge rule matching S3 event detail types `"Object Created"` and `"Object Deleted"` for the bucket (note: when S3 sends events to **EventBridge**, the event detail types are `Object Created`/`Object Deleted`; the `s3:ObjectCreated:*` and `s3:ObjectRemoved:*` wildcard names are used only for **direct** SNS/SQS/Lambda notification configurations, not for EventBridge rule patterns). 3. Route events to an SNS topic or Lambda function for alerting. 4. Integrate alerts into your security incident response workflow. |
| Reference | [S3 EventBridge Integration](https://docs.aws.amazon.com/AmazonS3/latest/userguide/EventBridge.html) |

#### FS-66 — AgentCore End-User Identity Propagation

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.6 — Practical guidance] — "1. Implement least privilege for identities associated with agents and tool services. 2. Where supported by the tool service ensure that communications to tool services or agents are authorized by the end user. 3. Customers building their own tool services should consider propagating end-user identities separately; ensuring these identities can be validated and are not revealed to unauthorized third parties." |
| Description | Verifies AgentCore runtimes are configured to propagate end-user identities to downstream tool services, ensuring tool calls are authorized by the originating user and not solely by the agent execution role. |
| Detection | Calls `ListAgentRuntimes` (via the `bedrock-agentcore-control` boto3 client; IAM action `bedrock-agentcore:ListAgentRuntimes`) and inspects each runtime's `authorizerConfiguration.customJWTAuthorizer` for a `discoveryUrl` and allowed audiences/clients/scopes. Flags runtimes with no JWT authorizer (meaning inbound calls carry no verifiable end-user identity), and advises configuring outbound OAuth for downstream tool services. |
| Remediation | 1. Configure a custom JWT inbound authorizer on each AgentCore runtime: specify `discoveryUrl`, `allowedAudience`, `allowedClients`, and optional required custom claims. 2. Propagate the end-user's identity via the `X-Amzn-Bedrock-AgentCore-Runtime-User-Id` header and JWT token in the `Authorization` header when calling downstream tool services. **Important:** Invoking `InvokeAgentRuntime` with the `X-Amzn-Bedrock-AgentCore-Runtime-User-Id` header requires the distinct IAM action `bedrock-agentcore:InvokeAgentRuntimeForUser` in addition to `bedrock-agentcore:InvokeAgentRuntime`. Only trusted principals should hold this permission — scope it to specific runtime resources with IAM resource conditions, never via wildcard. For runtimes that do not need user-id delegation, explicitly **deny** `bedrock-agentcore:InvokeAgentRuntimeForUser` to prevent the header from being accepted. Additionally, derive the user-id from the authenticated principal's context (IAM caller identity or JWT claims) rather than from arbitrary client-supplied values to prevent user impersonation, and log the relationship between the authenticated IAM principal (via CloudTrail's SigV4 context) and the `user-id` value passed. 3. Configure outbound OAuth 2.0 for agents accessing third-party resources on behalf of the user. 4. Ensure tool services validate the propagated JWT before executing actions. 5. Implement agent identity segregation: assign distinct identities to each sub-agent in multi-agent workflows so actions are separately attributable. 6. Apply a maker-checker pattern for critical financial actions — require a second agent or human to verify before execution. 7. Do not log or expose propagated identity tokens to unauthorized third parties. |
| Reference | [Configure Inbound JWT Authorizer](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/inbound-jwt-authorizer.html), [Inbound and Outbound Auth](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-oauth.html) |

#### FS-67 — Agent Financial Transaction Value Thresholds

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.9] — "Enforce transaction value thresholds and action boundaries on agent tool calls (for example to cap financial transaction amounts)." |
| Description | Checks AgentCore Policy Engine (attached to Gateways) or action-group Lambda functions enforce maximum transaction-value limits (e.g., cap on financial amounts an agent can initiate) to prevent runaway or unauthorized high-value transactions. |
| Detection | (a) Calls `ListGateways` (via the `bedrock-agentcore-control` boto3 client; IAM action `bedrock-agentcore:ListGateways`) and for each inspects attached Policy Engine Cedar policies for transaction-value constraints (policies referencing amount, limit, or threshold context attributes). (b) Calls `lambda:ListFunctions` and filters for agent action-group Lambda functions. Inspects each function's environment variables for threshold-related keys (e.g., `MAX_TRANSACTION_AMOUNT`, `TRANSACTION_LIMIT`). Flags gateways and functions with no threshold configuration. |
| Remediation | 1. Add transaction-value threshold environment variables to each agent action-group Lambda (e.g., `MAX_TRANSACTION_AMOUNT=10000`). 2. Implement threshold enforcement logic in the Lambda handler that rejects or escalates transactions exceeding the limit. 3. Author Cedar policies in the AgentCore Policy Engine that evaluate tool-call context attributes (amount, currency, tool) and deny calls exceeding defined limits. 4. Route transactions exceeding thresholds to a human-in-the-loop approval step via Step Functions callback pattern. |
| Reference | [Policy in AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html), [AgentCore Example Policies](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/example-policies.html) |

#### FS-68 — API Gateway Request Body Size Limits

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.11] — "To protect your API endpoints, set maximum length limits for input requests when you use large language models (LLMs) directly or through Amazon Bedrock." |
| Description | Verifies API Gateway REST/HTTP APIs fronting GenAI endpoints have WAF `SizeConstraintStatement` rules enforcing a maximum request body size, optionally paired with an API Gateway request-body JSON schema that bounds individual field lengths — to prevent token-exhaustion attacks via oversized prompts. |
| Detection | Calls `apigateway:GetRestApis` and for each calls `apigateway:GetRequestValidators` to check for validators (validators enforce parameter-existence and request-body JSON schema conformance — not total body size). Calls `wafv2:GetWebACL` for associated ACLs and inspects rules for `SizeConstraintStatement` targeting the request body. Flags APIs with no WAF `SizeConstraintStatement` on body, since that is the only AWS-native mechanism that enforces a custom maximum body size in front of API Gateway. |
| Remediation | 1. **Primary control — WAF `SizeConstraintStatement`:** Add a WAF `SizeConstraintStatement` rule on your regional Web ACL that blocks requests whose body size exceeds your maximum allowed prompt length (e.g., 32 KB). Verify that the Web ACL's `AssociationConfig.RequestBody.DefaultSizeInspectionLimit` is set high enough (16 KB default; can be increased to 32/48/64 KB) so WAF can actually inspect bodies at the size you are enforcing against — if the inspection limit is lower than the `SizeConstraintStatement` threshold, oversized requests fall through to oversize handling instead of the rule. This is the only AWS-native way to enforce a custom maximum body size before requests reach API Gateway. 2. **Secondary control — API Gateway request validation:** Add an API Gateway request validator with a request-body model (JSON schema). Request validators do **not** enforce total body size, but a JSON schema can constrain individual string fields with `maxLength` and arrays with `maxItems`, which indirectly bounds payload content. Note API Gateway REST APIs also enforce a service-level hard limit of 10 MB per request (6 MB when integrated with Lambda) that you cannot lower. 3. Set the `max_tokens` parameter in Bedrock API calls to cap output length. 4. Implement client-side token counting before submitting requests. |
| Reference | [WAF Size Constraint](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-size-constraint-match.html), [WAF Body Inspection Size Limit](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-setting-body-inspection-limit.html), [API Gateway Request Validation](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-request-validation.html) |

#### FS-69 — Prompt Input Validation Function

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.8] — "Input Validation – Before you send user input to Amazon Bedrock or the tokenizer, validate and sanitize it by removing special characters or using escape sequences. Make sure the input matches your expected format." |
| Description | Checks for a Lambda function or API Gateway request validator that sanitizes user prompt input (strips special characters, enforces expected format, rejects oversized inputs) before forwarding to Bedrock, complementing WAF-level controls. |
| Detection | Calls `lambda:ListFunctions` and searches for functions with input-validation naming patterns (e.g., "sanitiz", "validat", "input-filter", "prompt-guard", "preprocess"). Flags if no such functions exist. |
| Remediation | 1. Implement a Lambda authorizer or pre-processing function that: strips or escapes special characters from user input; validates input against an expected format (e.g., regex allowlist); rejects inputs exceeding maximum token/character limits; logs rejected inputs for security monitoring. 2. Use parameterized prompt templates (Bedrock Prompt Management) instead of string concatenation. 3. Apply Bedrock Guardrails PROMPT_ATTACK filter as a complementary control. 4. Integrate the validation function as an API Gateway Lambda authorizer or Step Functions pre-processing step. 5. Implement schema validation for all tool interactions — validate both inputs to and outputs from tools against defined JSON schemas per AWS Prescriptive Guidance for tool integration security. 6. Enforce TLS for all remote tool communications. |
| Reference | [Bedrock Prompt Injection Security](https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-injection.html), [Security Best Practices for Tool Integration](https://docs.aws.amazon.com/prescriptive-guidance/latest/agentic-ai-frameworks/security-best-practices-for-tool-integration.html) |

---

*See `SECURITY_CHECKS_FINSERV_COMMON.md` for the Compliance Framework Mapping table that applies to all 69 FS checks.*
