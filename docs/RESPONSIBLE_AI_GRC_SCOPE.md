# Responsible AI GRC — scope, sources, and compatibility

**Cross-industry technical controls for AI governance, risk, and compliance**

This document is the single reference for what Responsible AI GRC is, what it is not, which AWS
publications it derives from, which legacy identifiers it preserves, and how to move from the legacy
`EnableFinServAssessment` parameter. The report footer and `README.md` link here by name.

Direct-service selection does not restrict GRC coverage or its IAM permissions.
GRC can assess Bedrock, SageMaker, and AgentCore even when their direct
assessments are deselected, and also runs as an OWASP dependency. Disable both
optional assessments to run only the selected direct assessments. GRC findings
remain in their own governance area and do not contribute to direct-service
scores.

## Contents

1. [Scope statement](#scope-statement)
2. [Relationship to the AWS Well-Architected Responsible AI Lens](#relationship-to-the-aws-well-architected-responsible-ai-lens)
   - [Why this notice exists](#why-this-notice-exists)
3. [Why the capability was renamed](#why-the-capability-was-renamed)
4. [Source catalog](#source-catalog)
5. [What the checks do and do not establish](#what-the-checks-do-and-do-not-establish)
6. [Check counts](#check-counts)
7. [Terminology](#terminology)
8. [Compatibility policy](#compatibility-policy)
9. [Migrating from EnableFinServAssessment](#migrating-from-enablefinservassessment)
   - [Which parameter to use](#which-parameter-to-use)
   - [How the two parameters are resolved](#how-the-two-parameters-are-resolved)
   - [Resolving a conflict](#resolving-a-conflict)
   - [Direct Step Functions execution input](#direct-step-functions-execution-input)
   - [The CSV object name has no alias](#the-csv-object-name-has-no-alias)
   - [Verifying the effective value](#verifying-the-effective-value)

## Scope statement

> **Responsible AI GRC** comprises 64 automated checks that evaluate selected AWS configuration
> evidence against project-authored technical controls informed by the AWS User Guide to Governance,
> Risk, and Compliance for Responsible AI Adoption and by AWS financial-services generative-AI risk
> guidance. The controls originated as financial-services controls and were found applicable across
> multiple industries. They do not establish regulatory compliance, certify a system as responsible
> AI, or provide complete Responsible AI or GRC coverage. Regulatory framework mappings are
> preliminary. Manual legal, policy, model-risk, fairness, and use-case review remains required.

## Relationship to the AWS Well-Architected Responsible AI Lens

> **Responsible AI GRC is not the
> [AWS Well-Architected Responsible AI Lens](https://docs.aws.amazon.com/wellarchitected/latest/responsible-ai-lens/responsible-ai-lens.html).**
> These are 64 automated configuration checks informed by the AWS User Guide to Governance, Risk, and
> Compliance for Responsible AI Adoption. The AWS Well-Architected Responsible AI Lens (November
> 2025) is a separate architectural review framework with eight focus areas. This assessment does not
> implement, validate, or measure conformance to that Lens, and passing these checks does not
> indicate Lens alignment.

### Why this notice exists

A capability named "Responsible AI GRC" that does not reference the Responsible AI Lens invites the
question of why. The answer:

- The 64 checks derive from the **AWS GRC User Guide**, a governance, risk, and compliance
  publication. They were authored against its 15 risk categories, not against the Lens's eight focus
  areas.
- The Lens is **not a source** for any check in this repository. It appears only in disambiguation
  statements such as this one. See [Source catalog](#source-catalog).
- Lens mapping is **out of scope**. It would require a separate control-by-control derivation
  against a different framework, and presenting an unmapped capability as Lens-aligned would be an
  unfounded claim.

The former name "FinServ" bore no resemblance to "Responsible AI Lens". "Responsible AI GRC" shares
two words with it and occupies the same conceptual space, so the rename **increases** the risk of
conflation. The notice therefore travels with the name: it appears in the generated report, in
`README.md`, and here.

Any occurrence of "Responsible AI Lens" in this repository must sit inside a disambiguation or
non-implementation statement. A bare reference implying alignment is a defect.

## Why the capability was renamed

The 64 `FS-*` checks were authored against the AWS GRC User Guide and were originally scoped to
financial services. On review the controls proved to have substantial overlap with, and applicability
to, **multiple industries** — encryption at rest, PII detection, guardrail configuration, agent
action boundaries, and logging are not financial-services-specific concerns.

The rename is corroborated externally. The
[2026-05-13 updated guide announcement](https://aws.amazon.com/blogs/security/introducing-the-updated-aws-user-guide-to-governance-risk-and-compliance-for-responsible-ai-adoption/)
**dropped "within Financial Services Industries" from its own title**, and the customer-facing report
links that updated version.

Financial-services provenance is therefore recorded as **origin and traceability**, not as scope.
Individual controls that are genuinely financial-services-specific — for example ECOA adverse-action
or Fair Housing concerns — remain labeled as such at the control level.

## Source catalog

Attribution differs by check bucket and must not be blended.

| Bucket | Primary source |
|---|---|
| **Responsible AI GRC** (64 `FS-*` checks) | AWS User Guide to GRC for Responsible AI Adoption, plus the AWS financial-services generative-AI risk guide |
| Bedrock, SageMaker, AgentCore core checks | AWS Well-Architected **Generative AI Lens** security best practices (`gensec*`) |
| Agentic AI Security checks | AWS Well-Architected **Agentic AI Lens** |
| OWASP checks | OWASP Top 10 for LLM |
| — | AWS Well-Architected **Responsible AI Lens** is **not** a source for any bucket |

Full source detail:

| Source | Date | Role |
|---|---|---|
| [AWS User Guide to GRC for Responsible AI Adoption](https://d1.awsstatic.com/whitepapers/compliance/AWS-User-Guide-Governance-Risk-Compliance-for-Responsible-AI-Adoption-Financial-Services.pdf) | updated 2026 | **Primary normative source.** 15 risk categories, §1.2.1–§1.2.15. Referred to as *the AWS GRC User Guide*. |
| [Generative AI risks and mitigations for financial services](https://d1.awsstatic.com/onedam/marketing-channels/website/public/global-FinServ-ComplianceGuide-GenAIRisks-public.pdf) | © 2026 | Financial-services risk categories and directly derived controls. |
| [Original announcement blog](https://aws.amazon.com/blogs/security/introducing-the-aws-user-guide-to-governance-risk-and-compliance-for-responsible-ai-adoption-within-financial-services-industries/) | 2025-05-14 | Historical context only. Title scoped to Financial Services Industries. Not normative. |
| [Updated announcement blog](https://aws.amazon.com/blogs/security/introducing-the-updated-aws-user-guide-to-governance-risk-and-compliance-for-responsible-ai-adoption/) | 2026-05-13 | Publication context. Title drops "Financial Services Industries". Not normative. |
| [Well-Architected Generative AI Lens](https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/generative-ai-lens.html) | — | Security basis for the core Bedrock, SageMaker, and AgentCore checks (`gensec*` best practices). |
| [Well-Architected Agentic AI Lens](https://docs.aws.amazon.com/wellarchitected/latest/agentic-ai-lens/agentic-ai-lens.html) | — | Basis for the Agentic AI Security checks. |
| [Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html) | — | Core-framework pillar, **distinct** from the GenAI Lens `gensec*` best practices. |
| [Well-Architected Financial Services Industry Lens](https://docs.aws.amazon.com/wellarchitected/latest/financial-services-industry-lens/fsisec14.html) | — | Cited by one control (`FSISEC14`). Retained as a control-level citation only. |
| [Well-Architected Responsible AI Lens](https://docs.aws.amazon.com/wellarchitected/latest/responsible-ai-lens/responsible-ai-lens.html) | Nov 2025 | **Not a source for any check.** See the disambiguation above. |

Two conflations to avoid:

- The **Generative AI Lens security best practices** (`gensec*` pages) and the **Security Pillar** are
  two different publications. There is no document called the "Generative AI Lens Security Pillar".
- **The AWS GRC User Guide** (the source) and **Responsible AI GRC** (this capability) are different
  things. The phrase "the Responsible AI GRC guide" must not be used for either — it is ambiguous
  between our output and AWS's document.

## What the checks do and do not establish

The controls inspect **selected AWS configuration evidence**. Specifically:

- Regulatory framework mappings are **preliminary** unless separately reviewed and validated. Each
  mapping's basis is recorded in
  [`provenance.json`](../aiml-security-assessment/functions/security/responsible_ai_grc_assessments/provenance.json).
- A passed check proves neither legal nor regulatory compliance.
- A passed check does not certify a system as responsible AI.
- Several policy, fairness, data, and application-level controls require **manual review** and are
  reported as advisory rather than pass or fail.
- Some checks are **configuration hints** derived from resource naming or environment-variable names.
  They prompt verification; they do not demonstrate enforcement.

Controls that inspect less than their subject matter suggests state so in their finding text and in
their `unsupported_assertions` provenance field.

## Check counts

Five different numbers are all correct under different definitions. They are reconciled here so no
document has to guess:

| Count | Meaning |
|---|---|
| **69** | `FS-*` numbers allocated in the documentation (`FS-01`–`FS-69`) |
| **64** | standalone checks that ship and run — the number in the scope statement |
| **65** | entries in the `build_finserv_checks()` registry: 64 unique IDs, with `FS-27` appearing twice (contextual grounding and automated reasoning policies) |
| **5** | numbers merged into Bedrock/SageMaker checks and documented as extension notes: `FS-17`, `FS-18`, `FS-19`, `FS-23`, `FS-64` |
| **+1** | `FS-00`, emitted at runtime but **not a control** — a visible N/A row for regions with no GenAI footprint |

`69 = 64 standalone + 5 merged`. `FS-00` is additional to all of these.

## Terminology

| Use | Do not use |
|---|---|
| Responsible AI GRC | FinServ, Financial Services GenAI Risk, Financial Services Risk (as capability names) |
| Cross-industry technical controls for AI governance, risk, and compliance | Financial Services-informed technical controls |
| the AWS GRC User Guide | the Responsible AI GRC guide |
| Responsible AI governance, risk, and compliance (expansion on first use) | — |

Prohibited claims:

```text
the Responsible AI GRC guide          (reserved for the source; must not name the capability)
Responsible AI GRC certification
Responsible AI GRC compliance
Complete Responsible AI / GRC assessment
Responsible AI Lens implementation / alignment / coverage
All Responsible AI controls
```

<a id="why-the-identifiers-are-not-renamed-yet"></a>

## Compatibility policy

The rename splits machine-facing and persisted identifiers into two buckets. Data-contract identifiers
that archived reports, the OWASP mappings, the report consolidation tooling, and customer automation
read are **permanently preserved** unchanged. Identifiers that were purely FinServ *branding* — S3
object names, DOM selectors and CSS classes, deployment/execution inputs, the Lambda logical and
physical names, Step Functions state names, directory and doc filenames, and the IAM `Sid` — are
**renamed** to Responsible AI GRC with no dual-write and no additive alias. The sole exception is the
`EnableFinServAssessment` / `ENABLE_FINSERV` deployment toggle, retained as a legacy alias; see
[Migrating from EnableFinServAssessment](#migrating-from-enablefinservassessment).

Permanently preserved:

| Identifier | Kind |
|---|---|
| `FS-00`, `FS-01`–`FS-69` | check IDs |
| `^[A-Z]{2,3}-\d{2}$` | check ID schema |
| 9-column CSV schema; `Failed`/`Passed`/`N/A`; `High`/`Medium`/`Low`/`Informational` | CSV contract |
| `COULD NOT ASSESS: `, `ADVISORY: ` | reserved finding-name prefixes |
| `show_finserv` | report visibility flag (internal identifier; not customer-visible) |

Renamed from the original FinServ branding to Responsible AI GRC (no dual-write, no additive
alias — the old name is fully retired everywhere it was previously frozen):

| Was | Now |
|---|---|
| `finserv_security_report_{execution_id}.csv` (S3 object name) | `responsible_ai_grc_security_report_{execution_id}.csv` |
| `finserv` service slug, `#finserv` anchor, `data-service` / `data-filter-service` / `data-scope-service` values | `responsible-ai-grc` |
| `industry-nav`, `industry-item`, `industry-chip`, `scope-industry`, `scope-industry-label` CSS classes | `governance-nav`, `governance-item`, `governance-chip`, `scope-governance`, `scope-governance-label` |
| `EnableFinServAssessment`, `ENABLE_FINSERV`, `enableFinServ` (primary deployment/execution inputs) | `EnableResponsibleAIGRCAssessment`, `ENABLE_RESPONSIBLE_AI_GRC`, `enableResponsibleAIGRC` (primary); `EnableFinServAssessment`/`ENABLE_FINSERV` retained as a legacy alias, see [Migrating from EnableFinServAssessment](#migrating-from-enablefinservassessment) |
| `FinServSecurityAssessmentFunction`, `aiml-security-${AWS::StackName}-FinServAssessment` | `ResponsibleAIGRCAssessmentFunction`, `aiml-security-${AWS::StackName}-RAIGRCAssessment` |
| `FinServ Enabled?`, `FinServ Security Assessment`, `FinServ Assessment Incomplete`, `FinServ Assessment Skipped` (Step Functions state names) | `Responsible AI GRC Enabled?`, `Responsible AI GRC Security Assessment`, `Responsible AI GRC Assessment Incomplete`, `Responsible AI GRC Assessment Skipped` |
| `$.finservError` (Step Functions result path) | `$.responsibleAIGRCError` |
| `finserv_assessments/`, `finserv_tests/` directories | `responsible_ai_grc_assessments/`, `responsible_ai_grc_tests/` |
| `docs/SECURITY_CHECKS_FINSERV*.md` filenames | `docs/SECURITY_CHECKS_RESPONSIBLE_AI_GRC*.md` |
| `FinServGenAIRiskAssessmentPermissions` IAM `Sid` | No single equivalent. The statement was renamed `ResponsibleAIGRCAssessmentPermissions` and later split into per-purpose statements (for example `ResponsibleAIGRCReportWrite`); no FinServ-named `Sid` remains |

The physical Lambda name uses the abbreviated suffix `RAIGRCAssessment` because the 64-character
Lambda `FunctionName` limit leaves a 23-character suffix budget in multi-account member mode (the
worst-case fixed portion is 41 characters). The unabbreviated `ResponsibleAIGRCAssessment` would
render to 67 characters.

Archived reports and CSVs generated before this rename retain their original filenames and DOM
selectors — this table describes what the tool produces going forward, not a retroactive rewrite
of historical artifacts.

One declared, intentional change: `Compliance_Frameworks` CSV **values** were corrected to match
in-code provenance. Fourteen checks gained a sourced mapping and eight had an unfounded assertion
removed. Archived reports keep their original values; comparisons across the change boundary should
expect this column to differ.

## Migrating from EnableFinServAssessment

`EnableResponsibleAIGRCAssessment` is the primary parameter for the Responsible AI GRC checks.
`EnableFinServAssessment`, the original name, is retained as a legacy alias so existing stacks and
automation keep working. Both control the same 64 checks, and the parameter you choose has no effect
on check behavior or report content.

You do not need to migrate immediately. There is no removal timeline for `EnableFinServAssessment`;
it is a permanent compatibility contract.

### Which parameter to use

| Your situation | What to do | What happens |
|---|---|---|
| You have never set either parameter | Nothing | Checks stay off (the primary defaults to `"false"` and the alias to `"__UNSET__"`), unless `EnableOWASPAssessment` is `"true"`, which runs them as hidden OWASP evidence |
| You already have `EnableFinServAssessment=true` and want to keep it | Nothing | Checks stay on, unchanged |
| You are deploying fresh, or want to move to the current name | Set `EnableResponsibleAIGRCAssessment` to `"true"` or `"false"`, and leave `EnableFinServAssessment` at `"__UNSET__"` | The primary parameter controls the checks |
| You set both, and they agree | Nothing | Works normally |
| You set `EnableResponsibleAIGRCAssessment="true"` and `EnableFinServAssessment` to `"false"` | **Pick one value** — see [Resolving a conflict](#resolving-a-conflict) | CodeBuild fails before any checks run |

Updating a stack to a template version that includes the rename, without changing any parameter
values, does not change whether the checks run.

### How the two parameters are resolved

`EnableFinServAssessment` defaults to the sentinel `"__UNSET__"`, meaning "deliberately not set".
`EnableResponsibleAIGRCAssessment` defaults to `"false"`. CloudFormation always materializes the
primary value, so a `"false"` primary cannot be distinguished from "left at the default"; it is
treated as "not yet chosen". `buildspec.yml` lowercases both values before comparing them, but
the `__UNSET__` sentinel must match exactly. It resolves the two values as follows:

| `EnableFinServAssessment` (alias) | `EnableResponsibleAIGRCAssessment` (primary) | Effective value |
|---|---|---|
| `__UNSET__` | any | the primary value |
| `true` or `false` | `false` | the alias value |
| `true` | `true` | `true` |
| `false` | `true` | **build fails** with an error naming both parameters |

The rule is one-directional: the build fails only when the primary is `"true"` and the alias
disagrees. Setting the primary to `"false"` while the alias is `"true"` resolves to `true`.

The resolution happens inside the CodeBuild job, not at the CloudFormation layer, so
`describe-stacks` shows each parameter exactly as you set it rather than the resolved value.

### Resolving a conflict

A silently resolved conflict would either run checks you thought were disabled or skip checks you
thought were enabled, so CodeBuild exits with an error instead. Fix it by setting both parameters to
the same value, or by setting `EnableFinServAssessment` back to `"__UNSET__"` so the primary
parameter applies.

### Direct Step Functions execution input

The alias applies only to the CloudFormation parameter `EnableFinServAssessment` and the CodeBuild
environment variable `ENABLE_FINSERV` it becomes. `buildspec.yml` passes the resolved value to Step
Functions as `"enableResponsibleAIGRC"` in the `StartExecution` input; there is no `"enableFinServ"`
key in that input. If you run assessments through the provided CodeBuild templates
(`deployment/aiml-security-single-account.yaml`, `deployment/2-aiml-security-codebuild.yaml`), this
is handled for you.

If you call `StartExecution` directly with the legacy input `{"enableFinServ": "true"}`, the
execution fails with `LegacyEnableFinServInputRejected` when it processes the first region, before
any Responsible AI GRC check runs and without producing a report, rather than silently skipping the
checks. Use `"enableResponsibleAIGRC": "true"` (or `"enableOWASP": "true"`) instead. See
[Troubleshooting §6b](TROUBLESHOOTING.md#6b-execution-fails-with-legacyenablefinservinputrejected).

### The CSV object name has no alias

The assessment Lambda writes a single object named
`responsible_ai_grc_security_report_{execution_id}.csv`. The original name,
`finserv_security_report_{execution_id}.csv`, is retired — not aliased and not dual-written.

If you have automation that reads the CSV from S3 by its exact key — for example, polling for
`finserv_security_report_*.csv` or hardcoding that prefix in an ETL job — update it to
`responsible_ai_grc_security_report_*.csv`. It will find nothing for runs on a template version that
includes the rename.

Two things are unaffected:

- **The HTML report.** `consolidate_html_reports.py` discovers CSVs with the generic
  `**/*_security_report_*.csv` glob, so it finds the new name automatically.
- **Archived CSVs.** Objects already written under the old name are not rewritten or deleted.

The other renamed identifiers — CSS classes, DOM slug, Step Functions state names, the CloudFormation
logical ID, and the physical Lambda name — are listed in the [Compatibility policy](#compatibility-policy).
None of them has an alias either.

### Verifying the effective value

The CodeBuild build log prints the resolved value in the `build` phase, regardless of which
parameter you set:

```text
Responsible AI GRC assessment enabled is true
```

A line printed earlier in the same phase shows which precedence path was taken:

```text
ENABLE_FINSERV not set; using ENABLE_RESPONSIBLE_AI_GRC (false)
```

or

```text
ENABLE_FINSERV set to true; overriding the effective Responsible AI GRC toggle
```
