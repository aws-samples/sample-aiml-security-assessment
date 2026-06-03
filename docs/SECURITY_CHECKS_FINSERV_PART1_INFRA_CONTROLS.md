# FinServ GenAI Risk Checks — Part 1: Infrastructure & Resource Controls (FS-01 to FS-26)

This is **Part 1 of 3** of the FinServ GenAI security checks derived from the
[AWS guide for Financial Services risk management of the use of Generative AI (March 2026)](https://d1.awsstatic.com/onedam/marketing-channels/website/public/global-FinServ-ComplianceGuide-GenAIRisks-public.pdf)
(referred to throughout as "the FinServ Guide").

This part covers **22 standalone checks** across 5 PDF risk categories (FS-17, FS-18, FS-19, and FS-23 are merged into upstream checks — see extension notes in each section):

- **Unbounded Consumption** (FS-01 to FS-06) — §1.2.11
- **Excessive Agency** (FS-07 to FS-11) — §1.2.9
- **Supply Chain Vulnerabilities** (FS-12 to FS-16) — §1.2.12
- **Training Data & Model Poisoning** (FS-17 to FS-21) — §1.2.14 — *FS-17, FS-18, FS-19 merged into upstream*
- **Vector & Embedding Weaknesses** (FS-22 to FS-26) — §1.2.15 — *FS-23 merged into upstream*

**Companion files:**

- `SECURITY_CHECKS_FINSERV_PART2_GUARDRAILS_CONTENT_SAFETY.md` — FS-27 to FS-46 (Non-Compliant, Misinformation, Abusive, Biased, Sensitive Info)
- `SECURITY_CHECKS_FINSERV_PART3_APP_LAYER_AND_GAPS.md` — FS-47 to FS-69 (Hallucination, Prompt Injection, Output Handling, Off-Topic, Stale Data, Material Gaps)
- `SECURITY_CHECKS_FINSERV_COMMON.md` — shared intro, severity rubric, validation note, upstream-overlap table

Each check includes how it is **detected** (the AWS API calls or configuration inspected)
and how a failure is **remediated** (the specific AWS actions to take).

See `SECURITY_CHECKS_FINSERV_COMMON.md` for:

- PDF traceability conventions (`[PDF §x.y.z]` vs `[PDF §x.y.z, extension]`)
- Severity rubric (High / Medium / Low / Advisory)
- Validation note and AWS service authorization references
- Relationship to upstream SM/BR/AC checks and consolidation recommendations

---

## FinServ GenAI Risk Checks — Part 1 content

### Unbounded Consumption (FS-01 to FS-06)

> **PDF source:** §1.2.11 Unbounded consumption. PDF-listed mitigations: (a) AWS WAF and Shield
> Advanced for LLM APIs; (b) maximum input length limits; (c) rate limits/quotas on APIs
> accessing LLMs; (d) cost-and-usage tracking for generative AI. Practical guidance in the PDF
> also calls out `max_tokens` optimisation and CloudWatch metrics for token usage.

#### FS-01 — WAF and Shield Protection

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.11] — "Protect your LLM APIs and Amazon Bedrock-hosted LLMs by using AWS WAF and AWS Shield Advanced." Also covers: "To protect your API endpoints, set maximum length limits for input requests when you use large language models (LLMs) directly or through Amazon Bedrock." |
| Description | Verifies AWS WAF Web ACLs and Shield Advanced protect GenAI API endpoints, and verifies the Web ACL enforces both rate-based limits and body-size (input-length) constraints. |
| Detection | Calls `shield:DescribeSubscription` to check Shield Advanced is active. Calls `wafv2:ListWebACLs(Scope=REGIONAL)` in each region where GenAI API endpoints run to verify at least one regional Web ACL exists (covers API Gateway, ALB, AppSync). **Additionally** calls `wafv2:ListWebACLs(Scope=CLOUDFRONT)` in `us-east-1` to detect Web ACLs protecting CloudFront distributions fronting GenAI workloads — CLOUDFRONT-scope Web ACLs must be created and queried in `us-east-1` per the [WAF resources documentation](https://docs.aws.amazon.com/waf/latest/developerguide/how-aws-waf-works-resources.html). For each Web ACL found, calls `wafv2:GetWebACL` and inspects the `Rules` array for: (a) at least one `RateBasedStatement` (rate limiting) and (b) at least one `SizeConstraintStatement` with `FieldToMatch=Body` or `FieldToMatch=JsonBody` (input-size limit — this implements PDF §1.2.11 mitigation "set maximum length limits for input requests when you use large language models (LLMs) directly or through Amazon Bedrock"). Flags accounts with no Web ACL in either scope, a Web ACL with no rate-based rule, a Web ACL with no body size-constraint rule, or where Shield Advanced is inactive. |
| Remediation | 1. Subscribe to AWS Shield Advanced via the Shield console. 2. Create a WAF Web ACL with both (a) a rate-based rule (e.g., 1 000 req / 5 min per IP) and (b) a `SizeConstraintStatement` that blocks requests where `FieldToMatch=Body` (or `JsonBody` for JSON APIs) exceeds your LLM's expected maximum input size — for example, `ComparisonOperator=GT, Size=100000` (100 KB) — use `Scope=REGIONAL` for API Gateway/ALB/AppSync resources, or `Scope=CLOUDFRONT` (created in `us-east-1`) for CloudFront distributions fronting Bedrock. The body size-constraint rule directly implements the PDF §1.2.11 mitigation "set maximum length limits for input requests when you use large language models (LLMs) directly or through Amazon Bedrock" and prevents large-prompt token-exhaustion attacks before they reach Bedrock. 3. Associate the ACL with the fronting resource (API Gateway stage, ALB, or CloudFront distribution). 4. Add AWS Managed Rules (e.g., `AWSManagedRulesCommonRuleSet`, which includes additional size checks). 5. For CloudFront-fronted workloads, register the distribution with Shield Advanced via `shield:CreateProtection` to unlock automatic application-layer DDoS mitigation. 6. For API Gateway REST APIs, also note the service's own payload-size quota: the default is 10 MB per request (see [API Gateway quotas](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-execution-service-limits-table.html)); use a request validator or Lambda authorizer for sub-10 MB limits where WAF size constraints are unsuitable. |
| Reference | [Shield Advanced](https://docs.aws.amazon.com/waf/latest/developerguide/shield-chapter.html), [WAF](https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html), [WAF Size Constraint Rule](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-size-constraint-match.html), [API Gateway Quotas](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-execution-service-limits-table.html) |

#### FS-02 — API Gateway Rate Limiting

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.11] — "protect your API endpoints by implementing rate limits and quotas for APIs that access large language models (LLMs)". |
| Description | Checks API Gateway usage plans enforce throttling on GenAI endpoints. |
| Detection | Calls `apigateway:GetUsagePlans` and inspects each plan's `throttle.rateLimit` and `throttle.burstLimit`. Flags plans where either is zero or absent. |
| Remediation | 1. Create or update usage plans with `rateLimit` and `burstLimit` values appropriate for your traffic. 2. Associate plans with API stages serving Bedrock. 3. Issue per-consumer API keys with individual quotas. |
| Reference | [API Gateway Throttling](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html) |

#### FS-03 — Bedrock Token Quota Review

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.11, extension] — PDF practical guidance notes "Bedrock has default quota on model inference based on token usage" and recommends optimising `max_tokens`. Quota review as an operational control is an extension aligned with this guidance. |
| Description | Verifies Bedrock TPM/RPM quotas have been reviewed and set appropriately. |
| Detection | Calls `service-quotas:ListServiceQuotas(ServiceCode=bedrock)` for applied quotas and `ListAWSDefaultServiceQuotas` for defaults, then compares each adjustable quota's `Value` against the default `Value`. Flags accounts where every quota equals the service default (indicating no quota review or increase has been requested). |
| Remediation | 1. Review current quotas in the Service Quotas console. 2. Request increases aligned with expected peak load via `service-quotas:RequestServiceQuotaIncrease`. 3. Implement client-side token counting and pre-flight quota checks. 4. Use Bedrock cross-region inference profiles to distribute load — note that cross-region inference routes requests across destination regions automatically with no additional cost, but requires the invoked model to be available in the destination regions defined in the inference profile. |
| Reference | [Bedrock Quotas](https://docs.aws.amazon.com/bedrock/latest/userguide/quotas.html) |

#### FS-04 — Cost Anomaly Detection

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.11] — "Track, allocate, and manage your costs and usage for generative AI." |
| Description | Checks AWS Cost Anomaly Detection monitors cover Bedrock/SageMaker. |
| Detection | Calls `ce:GetAnomalyMonitors` and inspects each monitor. AWS Cost Anomaly Detection supports exactly two `MonitorType` values per the [AnomalyMonitor API](https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_AnomalyMonitor.html): `DIMENSIONAL` (AWS-managed, where `MonitorDimension` is one of `SERVICE`, `LINKED_ACCOUNT`, `TAG`, or `COST_CATEGORY`) and `CUSTOM` (customer-managed, scoped via `MonitorSpecification` to specific values). For `DIMENSIONAL` monitors, checks `MonitorDimension=SERVICE` (the AWS-managed "AWS services" monitor that automatically covers all services including Bedrock and SageMaker — the recommended default). For `CUSTOM` monitors, inspects `MonitorSpecification` for references to Bedrock or SageMaker. Flags accounts with no monitors, or with only narrowly-scoped monitors that would not detect Bedrock cost anomalies (e.g., `DIMENSIONAL` with `MonitorDimension=LINKED_ACCOUNT` only). |
| Remediation | 1. Create an AWS-managed `DIMENSIONAL` monitor with `MonitorDimension=SERVICE` for comprehensive coverage across all AWS services (the recommended default — in the console this appears as "AWS services" under "Managed by AWS"). For narrower scope, add a `CUSTOM` monitor using `MonitorSpecification` with a `Dimensions` expression scoped to specific service values (e.g., `{"Dimensions": {"Key": "SERVICE", "Values": ["Amazon Bedrock", "Amazon SageMaker"]}}`) — note that for `CUSTOM` monitors you use `MonitorSpecification`, not `MonitorDimension`. 2. Configure alert subscriptions (SNS/email) for anomalies above threshold. 3. Set daily spend budgets with AWS Budgets as a secondary control. 4. Enable Bedrock IAM principal cost allocation: tag IAM users/roles with team or cost-center attributes, activate them as cost allocation tags in the Billing and Cost Management console, and include caller identity data in CUR 2.0 exports for per-user/per-team Bedrock spend attribution. |
| Reference | [Cost Anomaly Detection](https://docs.aws.amazon.com/cost-management/latest/userguide/getting-started-ad.html), [Bedrock IAM Cost Allocation](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/iam-principal-cost-allocation.html) |

#### FS-05 — CloudWatch Token Usage Alarms

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.11] — PDF practical guidance cites CloudWatch metrics for token usage; alarms operationalise that guidance. |
| Description | Verifies CloudWatch alarms exist for Bedrock throttling and token metrics. |
| Detection | Paginates `cloudwatch:DescribeAlarms(AlarmTypes=MetricAlarm)` and filters for alarms in the `AWS/Bedrock` namespace or with "bedrock" in the alarm name. Separately counts throttle-specific alarms. |
| Remediation | 1. Create alarms for `AWS/Bedrock InvocationThrottles` (threshold > 0). 2. Create alarms for `AWS/Bedrock EstimatedTPMQuotaUsage` to track approach to token quota limits, and separately on `InputTokenCount` + `OutputTokenCount` (sum via CloudWatch metric math) for absolute token consumption. Note: `TokensProcessed` is not a valid Bedrock metric — the correct runtime metrics are `InputTokenCount`, `OutputTokenCount`, `InvocationThrottles`, `EstimatedTPMQuotaUsage`, `Invocations`, `InvocationLatency`, `TimeToFirstToken`. 3. Publish custom application-level token counters via Embedded Metric Format (EMF) if you need per-tenant or per-feature attribution. 4. Attach SNS actions to all alarms. |
| Reference | [Bedrock CloudWatch Metrics](https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring.html) |

#### FS-06 — AWS Budgets AI/ML Spend

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.11] — "Track, allocate, and manage your costs and usage for generative AI." |
| Description | Checks AWS Budgets are configured with alerts for AI/ML service spend. |
| Detection | Calls `budgets:DescribeBudgets` and inspects each budget's `FilterExpression` (the current field) and `CostFilters` (deprecated but may still be populated on older budgets) for references to "bedrock" or "sagemaker". Note: `CostFilters` is marked deprecated in the AWS Budgets API — new budgets use `FilterExpression` with an `Expression` object; the detection should check both fields to cover both old and new budgets. |
| Remediation | 1. Create cost budgets for Bedrock and SageMaker with 80 %/100 % alert thresholds. 2. Add SNS notifications to on-call channels. 3. Consider budget actions to apply IAM deny policies when thresholds are breached. 4. Enable Bedrock IAM principal cost allocation to attribute inference costs to specific IAM users/roles via Cost Explorer and CUR 2.0 — tag IAM principals with team or cost-center attributes and activate them as cost allocation tags. |
| Reference | [AWS Budgets](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html), [Bedrock IAM Cost Allocation](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/iam-principal-cost-allocation.html) |

### Excessive Agency (FS-07 to FS-11)

> **PDF source:** §1.2.9 Excessive agency. PDF-listed mitigations: (a) Amazon Bedrock AgentCore
> for managing complex tasks; (b) least-privilege permissions on plugins; (c) human-in-the-loop
> output validation; (d) explicit action boundaries in agent configuration (AgentCore Policy);
> (e) audit logging of agent actions with reasoning chain (AgentCore Observability);
> (f) transaction-value thresholds on agent tool calls; (g) monitoring agent call rates with
> alarms (AgentCore Evaluations). Mitigation (e) is covered by the expanded FS-08 check, which
> now verifies both AgentCore Policy Engine and AgentCore Observability are configured.

#### FS-07 — Agent Action Boundaries

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.9] — "grant only the minimum permissions required"; "Define and enforce explicit action boundaries in the agent configuration". |
| Description | Verifies Bedrock agent execution roles have no wildcard sensitive actions (iam:\*, s3:\*, ec2:\*, lambda:\*, \*). |
| Detection | Calls `ListAgents` and `GetAgent` (via the `bedrock-agent` boto3 client; IAM actions are `bedrock:ListAgents` and `bedrock:GetAgent`) to retrieve each agent's `agentResourceRoleArn`. Resolves the role name and inspects attached and inline policy documents from the permissions cache for wildcard Allow statements. |
| Remediation | 1. Replace wildcard actions with the specific actions the agent needs. 2. Apply IAM permission boundaries to agent execution roles. 3. Use resource-level conditions to restrict to specific ARNs. 4. Implement human-in-the-loop approval for high-impact actions. 5. For agents deployed in a VPC, use **AWS Network Firewall** with domain-based filtering to control which external domains agents can reach — this provides a network-layer boundary that limits agent tool access to approved endpoints regardless of IAM permissions. |
| Reference | [Bedrock Agent Permissions](https://docs.aws.amazon.com/bedrock/latest/userguide/agents-permissions.html), [Control Agent Domain Access](https://aws.amazon.com/blogs/machine-learning/control-which-domains-your-ai-agents-can-access/) |

#### FS-08 — AgentCore Policy Engine and Observability

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.9] — "Use Amazon Bedrock AgentCore to manage complex tasks and connect securely"; "Define and enforce explicit action boundaries"; **"Implement audit logging of all actions taken by AI agents, including the reasoning chain that led to each action."** (The audit-logging mitigation's PDF reference is "Observe your agent applications on Amazon Bedrock AgentCore Observability.") |
| Description | Checks AgentCore Gateways have a Policy Engine attached to authorize agent-to-tool interactions, verifies AgentCore Runtimes have an inbound authorizer configured, and verifies AgentCore Observability is enabled so agent reasoning chains and tool calls are auditable. |
| Detection | (a) Calls `ListGateways` and `GetGateway` (via the `bedrock-agentcore-control` boto3 client; IAM actions are `bedrock-agentcore:ListGateways` and `bedrock-agentcore:GetGateway`); inspects `policyEngineConfiguration.arn` and `policyEngineConfiguration.mode` (must be `ENFORCE` for production). (b) Calls `ListAgentRuntimes` (IAM action `bedrock-agentcore:ListAgentRuntimes`) and inspects each runtime's `authorizerConfiguration.customJWTAuthorizer` for inbound auth. (c) Verifies **AgentCore Observability** is enabled by (i) checking that CloudWatch Transaction Search is on via `xray:GetTraceSegmentDestination` (destination should be `CloudWatchLogs`) and that the X-Ray → CloudWatch Logs resource policy is in place via `logs:GetResourcePolicy`, and (ii) calling `logs:DescribeDeliveries` / `logs:DescribeDeliverySources` for AgentCore resource sources (runtime, memory, gateway, built-in tools, identity) — flags runtimes/gateways with no log delivery configured. For memory resources, additionally checks that tracing was enabled at memory creation time. Flags gateways without a Policy Engine in `ENFORCE` mode, runtimes without an authorizer, or accounts where Transaction Search is not enabled or no delivery exists for AgentCore resources. |
| Remediation | 1. Configure a Policy Engine: create via `CreatePolicyEngine` (IAM action `bedrock-agentcore:CreatePolicyEngine`), then author Cedar policies using one of three methods: (a) write Cedar directly for fine-grained control via `CreatePolicy` (IAM action `bedrock-agentcore:CreatePolicy`), (b) use the form-based console UI, or (c) generate Cedar from natural language descriptions (natural-language-to-Cedar is a documented capability in the GA announcement; verify the exact IAM action name against the current [AgentCore Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonbedrockagentcore.html) before writing IAM policies for it). Policy in AgentCore went GA on March 3, 2026 in thirteen AWS regions (US East N. Virginia, US East Ohio, US West Oregon, Asia Pacific Mumbai/Seoul/Singapore/Sydney/Tokyo, Europe Frankfurt/Ireland/London/Paris/Stockholm) — verify current regional availability on the [launch announcement](https://aws.amazon.com/about-aws/whats-new/2026/03/policy-amazon-bedrock-agentcore-generally-available/) before audit reliance. 2. Attach the Policy Engine to each Gateway by specifying the Policy Engine ARN in the `policyEngineConfiguration` field during `CreateGateway`, or attach later via `UpdateGateway`. 3. Start in `LOG_ONLY` mode — the policy engine evaluates actions and logs whether they would be allowed or denied without enforcing the decision — then switch to `ENFORCE` mode once confident. 4. Configure a JWT inbound authorizer on each Runtime with discovery URL, allowed audiences, and allowed clients. 5. **Enable AgentCore Observability** so agent reasoning chains are captured (directly addresses the PDF §1.2.9 audit-logging mitigation): (a) one-time enable CloudWatch Transaction Search — console path **CloudWatch → Application Signals (APM) → Transaction search → Enable Transaction Search**, or CLI: `aws xray update-trace-segment-destination --destination CloudWatchLogs` plus a `logs:PutResourcePolicy` granting `xray.amazonaws.com` permission to `logs:PutLogEvents` on `aws/spans:*` and `/aws/application-signals/data:*`; (b) configure log delivery for AgentCore runtime, memory, gateway, built-in tools, and identity resources via `logs:PutDeliverySource` + `logs:PutDeliveryDestination` + `logs:CreateDelivery` (CloudWatch Logs / S3 / Firehose destinations supported; note the write APIs use `Put*` for source and destination but `Create*` for the delivery pairing); (c) enable tracing at memory creation. For traditional Bedrock Agents (non-AgentCore), set `enableTrace=true` on `InvokeAgent` calls to receive the reasoning-chain trace in the response. |
| Reference | [Policy in AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html), [Inbound JWT Authorizer](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/inbound-jwt-authorizer.html), [AgentCore Observability Configuration](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability-configure.html), [Bedrock Agent Trace View](https://docs.aws.amazon.com/bedrock/latest/userguide/trace-view.html) |

#### FS-09 — Agent Transaction Limits

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.9, extension] — Lambda reserved concurrency is not named in the PDF, but it directly implements the PDF mitigation "Monitor agent call rates and alarm upon exceeding defined thresholds" by capping execution parallelism. |
| Description | Verifies agent Lambda functions have reserved concurrency limits to cap execution parallelism. |
| Detection | Calls `lambda:ListFunctions` and filters for functions with agent-related naming patterns. For each, calls `lambda:GetFunctionConcurrency` and flags functions with no reserved concurrency set. |
| Remediation | 1. Set reserved concurrency on each agent action-group Lambda (e.g., 10–50 depending on expected load). 2. Add CloudWatch alarms for `Throttles` metric on these functions. 3. Consider Step Functions execution limits as an additional control. |
| Reference | [Lambda Reserved Concurrency](https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html) |

#### FS-10 — Human-in-the-Loop Approval

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.9, §1.2.1, §1.2.2, §1.2.3, §1.2.7, §1.2.10] — "For internal AI systems, validate outputs with human review before business use (human-in-the-loop)." HITL is referenced in six separate PDF risk sections. |
| Description | Checks Step Functions workflows have human approval steps for high-risk agent actions. |
| Detection | Calls `stepfunctions:ListStateMachines` and filters for agent/GenAI-related names. Retrieves each definition via `stepfunctions:DescribeStateMachine` and parses the ASL JSON for task states with `.waitForTaskToken` or callback patterns indicating human approval gates. |
| Remediation | 1. Add a callback-pattern task state in your Step Functions workflow before any high-risk action (financial transactions, data modifications, external communications). 2. Route the approval token to a human reviewer via SNS/SQS/Slack. 3. Set a `HeartbeatSeconds` timeout so stale approvals expire. 4. Enable **user confirmation on Bedrock Agent action groups** for inline approval — when configured, the agent returns a confirmation prompt in the `returnControl.invocationInputs` field of the `InvokeAgent` response (alongside `invocationType` and a unique `invocationId`); the client displays the prompt, collects confirm/deny, and returns the user's decision via `sessionState.returnControlInvocationResults` (with `confirmationState` on each `apiResult`/`functionResult`) in the next `InvokeAgent` request (there is no standalone `GetUserConfirmation` API). |
| Reference | [Step Functions Callback Pattern](https://docs.aws.amazon.com/step-functions/latest/dg/connect-to-resource.html#connect-wait-token), [Bedrock Agent User Confirmation](https://docs.aws.amazon.com/bedrock/latest/userguide/agents-userconfirmation.html) |

#### FS-11 — Agent Rate Alarms

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.9] — "Monitor agent call rates and alarm upon exceeding defined thresholds." |
| Description | Verifies CloudWatch alarms exist for agent invocation rates. |
| Detection | Paginates `cloudwatch:DescribeAlarms` and filters for alarms referencing "agent" in the alarm name or targeting `AWS/Bedrock/Agents` agent-related metrics (such as `InvocationCount` or `InvocationThrottles` with the `Operation, AgentAliasArn, ModelId` dimension combination). |
| Remediation | 1. Create CloudWatch alarms on the `AWS/Bedrock/Agents` namespace for `InvocationCount` and `InvocationThrottles`. Per AWS docs, the available dimensions are: `Operation` alone; `Operation, ModelId`; or `Operation, AgentAliasArn, ModelId` — use the `Operation, AgentAliasArn, ModelId` combination to scope alarms to a specific agent alias. 2. Set thresholds based on expected peak agent call rates, established via CloudWatch metric math on historical `InvocationCount` data. 3. Attach SNS actions for on-call notification. 4. Use **AgentCore Evaluations** (GA March 2026, available in 9 AWS regions — verify current regional availability on the [GA announcement](https://aws.amazon.com/about-aws/whats-new/2026/03/agentcore-evaluations-generally-available/)) to monitor agent *quality* alongside rate-based alarms: online evaluation continuously scores production traffic against 13 built-in evaluators (response quality, safety, task completion, tool usage), and on-demand evaluation supports regression testing. |
| Reference | [Bedrock Agents CloudWatch Metrics](https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-agents-cw-metrics.html), [AgentCore Evaluation Types](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/evaluations-types.html) |

### Supply Chain Vulnerabilities (FS-12 to FS-16)

> **PDF source:** §1.2.12 Supply chain vulnerabilities. PDF-listed mitigations:
> (a) control access to serverless and marketplace models (IAM policies, SCPs);
> (b) model onboarding process — EULA review, procurement, security/compliance review,
> MRM assessment, documentation, stakeholder approvals;
> (c) update TPRM to continuously monitor model providers — vendor security advisories,
> deprecation notices, T&C changes;
> (d) maintain a model inventory recording provenance, version, license terms, and risk
> assessment status;
> (e) use Bedrock Evaluations against attack test cases (practical guidance);
> (f) allow-list approved models via SCP (practical guidance).

#### FS-12 — SCP Model Access Restrictions

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.12 — Practical guidance] — "Implement an allow-list of models using a Service Control Policy (SCP) for your AWS organization." |
| Description | Checks SCPs restrict Bedrock model access to approved models only. |
| Detection | Calls `organizations:ListPolicies(Filter=SERVICE_CONTROL_POLICY)` and inspects each SCP document for Deny statements on `bedrock:InvokeModel*` with `StringNotEquals` conditions on `bedrock:ModelId`. Flags if no SCP restricts model access. |
| Remediation | 1. Create an SCP that denies `bedrock:InvokeModel*` except for an explicit allowlist of approved model ARNs. 2. Attach the SCP to the OU containing GenAI workload accounts. 3. For multi-account guardrail enforcement, use the Bedrock cross-account safeguards feature (GA April 3, 2026, available in all AWS commercial and GovCloud regions where Bedrock Guardrails is supported): enable the Amazon Bedrock policy type in AWS Organizations, create a guardrail in the management account, create a versioned guardrail, optionally attach a resource-based policy granting `bedrock:ApplyGuardrail` to member accounts for cross-account access, then create and attach an AWS Organizations Bedrock policy referencing the guardrail ARN and version to the target OUs or accounts. This automatically enforces content filters, denied topics, word filters, sensitive information filters, and contextual grounding checks across all member accounts for every model invocation — no application code changes required. **Important limitation:** Automated Reasoning checks are **not supported** with cross-account safeguards — omit Automated Reasoning policies from any guardrail used for org-level enforcement. If you rely on AR (see FS-27), you must configure AR guardrails separately at the application or account level. 4. Test with both allowed and denied model IDs. |
| Reference | [Managing Access in AWS Organizations](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html), [Bedrock Cross-Account Guardrails](https://aws.amazon.com/blogs/aws/amazon-bedrock-guardrails-supports-cross-account-safeguards-with-centralized-control-and-management/) |

#### FS-13 — Model Inventory Tagging

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.12] — "Maintain a model inventory that records the provenance, version, license terms, and risk assessment status of all models in use across the organization." |
| Description | Verifies models are tagged with provenance metadata (source, version, approval-date). |
| Detection | Calls `bedrock:ListFoundationModels` and `bedrock:ListCustomModels`. For custom models, calls `bedrock:ListTagsForResource` and checks for required tag keys: `model-source`, `model-version`, `approval-date`, `risk-tier`. |
| Remediation | 1. Define a mandatory tagging policy for all AI/ML models. 2. Tag each custom model with provenance metadata. 3. Create an AWS Config rule (`required-tags`) to enforce the tagging policy. 4. For foundation models, maintain an external inventory spreadsheet or CMDB entry. |
| Reference | [Bedrock Tagging](https://docs.aws.amazon.com/bedrock/latest/userguide/tagging.html) |

#### FS-14 — Model Onboarding Governance

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.12] — "To onboard a model, follow these steps: Review EULA, Complete procurement, Follow security and compliance procedures, Assess MRM requirements, Document findings, Get necessary approvals from stakeholders." |
| Description | Checks AWS Config rules enforce model onboarding governance (EULA review, MRM assessment, stakeholder approval). |
| Detection | Calls `config:DescribeConfigRules` and searches for rules targeting `AWS::Bedrock::*` resources or custom rules with "model" or "onboarding" in the name. |
| Remediation | 1. Create a custom AWS Config rule that checks new Bedrock custom models have required tags (approval-date, risk-tier, eula-reviewed). 2. Document the model onboarding process: EULA review → procurement → security/compliance review → MRM assessment → stakeholder sign-off. 3. Store approval artifacts in a versioned S3 bucket. |
| Reference | [AWS Config Custom Rules](https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_develop-rules.html) |

#### FS-15 — Adversarial Model Evaluation

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.12 — Practical guidance] — "Amazon Bedrock Evaluations can help to evaluate models against specific types of attacks by automating your test cases, scoring, reporting and to enable comparison of different models." |
| Description | Verifies Bedrock evaluation jobs include adversarial test datasets. |
| Detection | Calls `bedrock:ListEvaluationJobs` and inspects each job's configuration for evaluation datasets. Flags if no evaluation jobs exist or if none reference adversarial/red-team test data. |
| Remediation | 1. Create a Bedrock model evaluation job with adversarial prompt datasets (prompt injection attempts, jailbreak sequences, harmful content probes). 2. Include both automated metrics and human evaluation. 3. Run evaluations before production deployment and after model updates. 4. Store results for audit. |
| Reference | [Bedrock Model Evaluation](https://docs.aws.amazon.com/bedrock/latest/userguide/evaluation.html) |

#### FS-16 — ECR Image Scanning

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.12, extension] — ECR image scanning is not named in the PDF, but directly mitigates the PDF's listed risk "Third-party package vulnerabilities" in LLM supply chains. Included for completeness of the supply-chain risk category. |
| Description | Checks ECR repositories have scan-on-push enabled for supply chain security of model containers. |
| Detection | Calls `ecr:DescribeRepositories` and for each repository checks `imageScanningConfiguration.scanOnPush`. Also checks whether Amazon Inspector ECR scanning is enabled via `inspector2:BatchGetAccountStatus`. Flags repositories relying solely on basic scanning or with no scanning configured. |
| Remediation | 1. Enable **enhanced scanning** via Amazon Inspector (the current best practice) — Inspector provides continuous vulnerability monitoring, re-scanning images automatically when new CVEs are published, and covers both OS and programming language package vulnerabilities. This requires two steps: (a) enable Inspector ECR scanning at the account level — `aws inspector2 enable --account-ids <account-id> --resource-types ECR`; (b) set the ECR registry scanning configuration to enhanced mode — `aws ecr put-registry-scanning-configuration --scan-type ENHANCED --rules '[{"scanFrequency":"CONTINUOUS_SCAN","repositoryFilters":[{"filter":"*","filterType":"WILDCARD"}]}]'`. **Important limitations:** (i) When enhanced scanning is first enabled, Amazon Inspector only discovers images pushed within the **last 14 days** — older images receive `SCAN_ELIGIBILITY_EXPIRED` status and must be re-pushed to be scanned. (ii) After the initial scan, scan duration is controlled by the ECR re-scan duration setting in the Amazon Inspector console (defaults to `LIFETIME`); if you shorten this duration, images whose last scan exceeds the new window also move to `SCAN_ELIGIBILITY_EXPIRED`. (iii) Enhanced scanning incurs Amazon Inspector charges (no additional ECR cost). (iv) Repositories not matching a scan filter will have `Off` scan frequency and won't be scanned. 2. If enhanced scanning is not available in your region, enable basic scan-on-push as a fallback: `aws ecr put-image-scanning-configuration --repository-name <name> --image-scanning-configuration scanOnPush=true`. 3. Create EventBridge rules to alert on CRITICAL/HIGH findings from Inspector. 4. Integrate findings into your vulnerability management workflow. |
| Reference | [ECR Enhanced Scanning](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning-enhanced.html), [Amazon Inspector ECR Scanning](https://docs.aws.amazon.com/inspector/latest/user/scanning-ecr.html) |

### Training Data & Model Poisoning (FS-17 to FS-21)

> **PDF source:** §1.2.14 Training data and model poisoning. PDF-listed mitigations:
> (a) protect training datasets via data protection best practices;
> (b) use trusted data sources with audit controls tracking changes (who/when);
> (c) monitor training data for pattern/distribution changes (data drift);
> (d) compare retrained model performance against baseline before production;
> (e) rollback plan using versioned training data and models (Feature Store);
> (f) monitor low-entropy classification with thresholds and alerts;
> (g) AI Service Cards for evaluating third-party model testing procedures.

#### FS-17 — Model Monitor Data Quality → *Merged into upstream SM-07*

> **Upstream extension note (do not ship as a standalone check):** The detection and remediation
> content from FS-17 should be added as a refinement of the existing **SM-07 (Model Monitor)**
> check in the upstream `aws-samples/sample-aiml-security-assessment` repo.
>
> **What to add to SM-07:**
>
> - Filter `ListMonitoringSchedules` results for `MonitoringType=DataQuality` (not just any schedule). Note the format difference: `ListMonitoringSchedules`/`MonitoringScheduleSummary` returns `MonitoringType` in PascalCase (`DataQuality`, `ModelQuality`, `ModelBias`, `ModelExplainability`); `DescribeMonitoringSchedule` returns the same type in SCREAMING_SNAKE_CASE (`DATA_QUALITY`, `MODEL_QUALITY`, `MODEL_BIAS`, `MODEL_EXPLAINABILITY`) — the detection should normalise both forms.
> - Require `emit_metrics` to be enabled on the monitoring schedule.
> - Verify CloudWatch alarms exist on the `feature_baseline_drift_<feature_name>` metrics published
>   to namespace `/aws/sagemaker/Endpoints/data-metric` (real-time endpoints, dimensions
>   `EndpointName` + `ScheduleName`) or `/aws/sagemaker/ModelMonitoring/data-metric` (batch
>   transform, dimension `MonitoringSchedule`).
> - PDF traceability: [PDF §1.2.14] — "Monitor your training data for pattern and distribution
>   changes to detect data drift"; "Amazon SageMaker Model Monitor – Data quality."
>
> **Reference:** [SageMaker Model Monitor Data Quality](https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-data-quality.html)

#### FS-18 — Model Drift Detection → *Merged into upstream SM-23*

> **Upstream extension note (do not ship as a standalone check):** The detection and remediation
> content from FS-18 should be added as a refinement of the existing **SM-23 (Model Drift
> Detection)** check in the upstream repo.
>
> **What to add to SM-23:**
> - Filter `ListMonitoringSchedules` results for `MonitoringType=ModelQuality`.
> - Add a new remediation step for **low-entropy classification monitoring** (PDF §1.2.14
>   mitigation): publish custom CloudWatch metrics tracking prediction confidence distributions,
>   set threshold boundaries for unexpected low-confidence/high-confidence clusters, and alert
>   when the retrained model produces unexpected classification patterns — this can indicate
>   training data poisoning before accuracy metrics degrade.
> - PDF traceability: [PDF §1.2.14] — "Before deploying to production, compare your retrained
>   model's performance against previous iterations using historical test data as a baseline."
>
> **Reference:** [SageMaker Model Monitor Model Quality](https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor-model-quality.html)

#### FS-19 — Model Registry Approval → *Merged into upstream SM-22*

> **Upstream extension note (do not ship as a standalone check):** The detection and remediation
> content from FS-19 should be added as a refinement of the existing **SM-22 (Model Approval
> Workflow)** check in the upstream repo.
>
> **What to add to SM-22:**
> - Explicitly check that `ModelApprovalStatus=PendingManualApproval` is the default for new
>   model package versions (not `Approved`).
> - Flag any model package group where the latest version has `ModelApprovalStatus=Approved`
>   without evidence of a manual approval step (i.e., auto-approved at creation time).
> - PDF traceability: [PDF §1.2.14] — cites "Amazon SageMaker AI – Model Registration and
>   Deployment with Model Registry" as a reference for staged deployment with rollback.
>
> **Reference:** [SageMaker Model Registry](https://docs.aws.amazon.com/sagemaker/latest/dg/model-registry.html)

#### FS-20 — Feature Store Rollback

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.14] — "Create a rollback plan by using versioned training data and models. This ensures that you can revert to a stable, working model if failures occur." References "Amazon SageMaker AI Feature Store". |
| Description | Checks SageMaker Feature Store has offline store for rollback capability. |
| Detection | Calls `sagemaker:ListFeatureGroups` to enumerate all groups, then `sagemaker:DescribeFeatureGroup` for each to inspect `OfflineStoreConfig`. Flags feature groups where `OfflineStoreConfig` is absent (online-only groups with no offline store for rollback). |
| Remediation | 1. Enable the offline store on each feature group: specify an S3 URI and data catalog in `OfflineStoreConfig`. 2. The offline store provides a versioned, immutable history of feature values for point-in-time rollback. 3. Test rollback by querying the offline store with a historical timestamp. |
| Reference | [SageMaker Feature Store](https://docs.aws.amazon.com/sagemaker/latest/dg/feature-store.html) |

#### FS-21 — Training Data S3 Versioning and Audit Trail

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.14] — "Use trusted data sources for your training data. Implement audit controls that let you track and review changes, including who made them and when they occurred." |
| Description | Verifies S3 buckets used for training data have versioning enabled so poisoned datasets can be rolled back. Recommends CloudTrail data-event logging as remediation to record who modified training data and when. |
| Detection | Identifies training-data S3 buckets by naming convention (`train`/`dataset`/`model`/`sagemaker`/`bedrock`). Calls `s3:GetBucketVersioning` to verify `Status=Enabled`. (CloudTrail data-event logging is recommended in remediation but is not asserted by this check — verifying it is covered by the upstream BR-06 CloudTrail control and the FS-23 extension.) |
| Remediation | 1. Enable versioning: `aws s3api put-bucket-versioning --bucket <name> --versioning-configuration Status=Enabled`. 2. Enable CloudTrail S3 data events for the training-data buckets to capture PutObject/DeleteObject with caller identity. 3. Enable MFA Delete for critical training datasets. 4. Apply S3 Object Lock for immutable baselines. |
| Reference | [S3 Versioning](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html), [CloudTrail Data Events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html) |

### Vector & Embedding Weaknesses (FS-22 to FS-26)

> **PDF source:** §1.2.15 Vector and embedding weaknesses. PDF-listed mitigations:
> (a) apply least privilege to vector and embedding database access;
> (b) validate knowledge base data sources;
> (c) add data only from trusted sources to knowledge bases;
> (d) monitor and log all activities in knowledge base control plane (CloudTrail);
> (e) enable encryption at rest and in transit for vector and embedding databases;
> (f) implement document/record-level access controls via KB metadata filtering for
> multi-tenancy.

#### FS-22 — Knowledge Base IAM Least Privilege

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.15] — "Apply the principle of least privilege to control access to your vector and embedding database. Only grant users and services the minimum permissions they need to perform their tasks." |
| Description | Checks IAM roles accessing Knowledge Bases have no wildcard `bedrock:*` permissions covering KB actions. |
| Detection | Inspects the permissions cache for all IAM roles. Flags any role with an Allow statement granting `bedrock:*` without resource-level restrictions, or broad `bedrock:` actions covering KB operations without a specific knowledge-base ARN. Note: Bedrock agent and KB operations use the single IAM service prefix `bedrock:` (not `bedrock-agent:`) — the `bedrock-agent` token refers to the boto3 SDK client name, not the IAM action prefix. |
| Remediation | 1. Replace wildcard `bedrock:*` with specific KB actions: `bedrock:Retrieve`, `bedrock:RetrieveAndGenerate`, `bedrock:GetKnowledgeBase` (these are the actual IAM action names — verify via the AWS Service Authorization Reference for Amazon Bedrock). 2. Scope the resource ARN to specific Knowledge Base IDs (e.g., `arn:aws:bedrock:<region>:<account>:knowledge-base/<kb-id>`). 3. Apply IAM permission boundaries to limit blast radius. |
| Reference | [Bedrock Knowledge Base Permissions](https://docs.aws.amazon.com/bedrock/latest/userguide/kb-permissions.html) |

#### FS-23 — Knowledge Base CloudTrail Logging → *Merged into upstream BR-06*

> **Upstream extension note (do not ship as a standalone check):** The detection and remediation
> content from FS-23 should be added as a refinement of the existing **BR-06 (CloudTrail
> Logging)** check in the upstream repo.
>
> **What to add to BR-06:**
> - After verifying that a CloudTrail trail is active and logging Bedrock management events,
>   additionally check for an **advanced event selector** with
>   `resources.type = AWS::Bedrock::KnowledgeBase` to capture `Retrieve` and
>   `RetrieveAndGenerate` data events (these are NOT logged by default — they require an
>   explicit advanced event selector).
> - Note: `InvokeAgent` / `InvokeInlineAgent` are also data events requiring
>   `resources.type = AWS::Bedrock::AgentAlias` or `AWS::Bedrock::InlineAgent` respectively.
>   Data events incur additional CloudTrail charges and can produce high volumes under load.
> - PDF traceability: [PDF §1.2.15] — "Monitor and log all activities in knowledge base
>   control plane" with reference "Monitor Amazon Bedrock API calls using CloudTrail."
>
> **Reference:** [CloudTrail Bedrock Logging](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html)

#### FS-24 — Knowledge Base Metadata Filtering

| Field | Detail |
|-------|--------|
| Severity | Medium |
| PDF ref | [PDF §1.2.15] — "Implement access controls at the document or record level within knowledge bases where different users or applications should only have access to specific subsets of data. Use Amazon Bedrock Knowledge Bases metadata filtering to enforce data segmentation." |
| Description | Advisory: verifies KB metadata fields support tenant-level filtering for multi-tenancy. |
| Detection | Calls `ListKnowledgeBases` and `GetKnowledgeBase` (via the `bedrock-agent` boto3 client; IAM actions are `bedrock:ListKnowledgeBases` and `bedrock:GetKnowledgeBase`). Inspects the storage configuration for metadata field definitions. Flags KBs with no metadata fields defined (no tenant isolation possible). |
| Remediation | 1. Define metadata fields on your KB data sources (e.g., `tenant_id`, `department`, `classification`). 2. Populate metadata during document ingestion. 3. Use the `filter` parameter in Retrieve/RetrieveAndGenerate API calls to enforce tenant-scoped queries. 4. Test that cross-tenant data leakage is prevented. |
| Reference | [Bedrock KB Metadata Filtering](https://docs.aws.amazon.com/bedrock/latest/userguide/kb-test-config.html) |

#### FS-25 — OpenSearch Serverless Encryption

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.15] — "Enable encryption at rest and in transit for vector and embedding databases." |
| Description | Checks OpenSearch Serverless collections used by KBs have CMK encryption policies. |
| Detection | Calls `opensearchserverless:ListCollections` (IAM action `aoss:ListCollections`) and for each calls `opensearchserverless:ListSecurityPolicies(type=encryption)` (IAM action `aoss:ListSecurityPolicies`). Inspects each encryption policy's document for `AWSOwnedKey=true` or missing `KmsARN`. Note: the encryption **policy JSON document** uses PascalCase field names — `AWSOwnedKey` and `KmsARN` — while the direct API `EncryptionConfig` struct uses camelCase (`aWSOwnedKey`, `kmsKeyArn`); detection should inspect the policy document form returned by `GetSecurityPolicy`/`ListSecurityPolicies`. Flags collections using AWS-owned keys instead of customer-managed KMS keys. Note: the boto3 client name is `opensearchserverless`, but IAM actions use the service prefix `aoss:` (not `opensearchserverless:`). Note also: encryption in transit is automatic (TLS 1.2, AES-256) for all OpenSearch Serverless traffic and is not configurable — this check focuses on encryption at rest. |
| Remediation | 1. Create an encryption security policy specifying a customer-managed KMS key: set `AWSOwnedKey=false` and provide `KmsARN` with the ARN of your KMS key. 2. Apply the policy to the collection by matching the collection name or prefix pattern in the policy `Rules`. 3. Ensure the KMS key policy grants the OpenSearch Serverless service principal `kms:Decrypt` and `kms:GenerateDataKey`. Note: if you provide a KMS key directly in the `CreateCollection` request, it takes precedence over any matching security policies. |
| Reference | [OpenSearch Serverless Encryption](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-encryption.html) |

#### FS-26 — Knowledge Base VPC Access

| Field | Detail |
|-------|--------|
| Severity | High |
| PDF ref | [PDF §1.2.15, extension] — network isolation is not verbatim in the PDF but directly implements "Apply the principle of least privilege to control access to your vector and embedding database" at the network layer. |
| Description | Verifies OpenSearch Serverless collections have VPC-only network policies (no public access). |
| Detection | Calls `opensearchserverless:ListSecurityPolicies(type=network)` (IAM action `aoss:ListSecurityPolicies` — the service prefix for OpenSearch Serverless is `aoss`, not `opensearchserverless`) and inspects each policy rule for `AllowFromPublic=true`. Flags collections accessible from the public internet. Note: a policy with `AllowFromPublic=false` may still grant private access to Bedrock via `SourceServices: ["bedrock.amazonaws.com"]` or to specific VPC endpoints via `SourceVPCEs` — these are the recommended private-access patterns and are not flagged. |
| Remediation | 1. Create a network security policy that restricts access to specific VPC endpoints only via `SourceVPCEs`, or grants private AWS service access (e.g., Bedrock) via `SourceServices: ["bedrock.amazonaws.com"]`. Per AWS docs, private access to AWS services applies only to the collection's OpenSearch endpoint, not to the OpenSearch Dashboards endpoint. 2. Create an OpenSearch Serverless VPC endpoint in your VPC if VPC-private access is required. 3. Remove any policy rules with `AllowFromPublic=true`. 4. Test connectivity from within the VPC. |
| Reference | [OpenSearch Serverless Network Access](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-network.html) |

