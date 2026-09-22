# Responsible AI GRC — scope, sources, and compatibility

**Cross-industry technical controls for AI governance, risk, and compliance**

This document is the single reference for what Responsible AI GRC is, what it is not, which AWS
publications it derives from, and which legacy identifiers it preserves. The report footer and
`README.md` link here by name.

Direct-service selection does not restrict GRC coverage or its IAM permissions.
GRC can assess Bedrock, SageMaker, and AgentCore even when their direct
assessments are deselected, and also runs as an OWASP dependency. Disable both
optional assessments to run only the selected direct assessments. GRC findings
remain in their own governance area and do not contribute to direct-service
scores.

## Contents

1. [Scope statement](#scope-statement)
2. [Relationship to the AWS Well-Architected Responsible AI Lens](#relationship-to-the-aws-well-architected-responsible-ai-lens)
3. [Why the capability was renamed](#why-the-capability-was-renamed)
4. [Source catalog](#source-catalog)
5. [What the checks do and do not establish](#what-the-checks-do-and-do-not-establish)
6. [Check counts](#check-counts)
7. [Terminology](#terminology)
8. [Compatibility policy](#compatibility-policy)

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

A reviewer will reasonably ask why a capability named "Responsible AI GRC" does not reference the
Responsible AI Lens. The answer is written down here rather than left to be asked:

- The 64 checks derive from the **AWS GRC User Guide**, a governance, risk, and compliance
  publication. They were authored against its 15 risk categories, not against the Lens's eight focus
  areas.
- The Lens is referenced **zero times** anywhere in this repository, and is deliberately not a source
  for any check. See [Source catalog](#source-catalog).
- Lens mapping is **out of scope** for this release. It would require a separate control-by-control
  derivation against a different framework, and presenting an unmapped capability as Lens-aligned
  would be exactly the kind of unfounded claim this document exists to prevent.

This disambiguation is a required deliverable of the rebrand rather than a courtesy. The former name
"FinServ" bore no resemblance to "Responsible AI Lens". "Responsible AI GRC" shares two words with it
and occupies the same conceptual space, so the rename **increases** the risk of conflation. The
notice therefore travels with the name: it appears in the generated report, in `README.md`, and here.

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
already links that updated, de-scoped version.

Financial-services provenance is therefore recorded as **origin and traceability**, not as scope.
Individual controls that are genuinely financial-services-specific — for example ECOA adverse-action
or Fair Housing concerns — remain labelled as such at the control level.

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

Three different numbers are all correct under different definitions. They are reconciled here so no
document has to guess:

| Count | Meaning |
|---|---|
| **69** | `FS-*` numbers allocated in the documentation (`FS-01`–`FS-69`) |
| **64** | standalone checks that ship and run — the number in the scope statement |
| **65** | entries in the `build_finserv_checks()` registry: 64 unique IDs, with `FS-27` appearing twice (contextual grounding and automated reasoning policies) |
| **5** | numbers merged into upstream Bedrock/SageMaker checks and documented as extension notes: `FS-17`, `FS-18`, `FS-19`, `FS-23`, `FS-64` |
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

## Compatibility policy

The rename splits machine-facing and persisted identifiers into two buckets. Data-contract identifiers
that archived reports, the OWASP mappings, the report consolidation tooling, and customer automation
read are **permanently preserved** unchanged. Identifiers that were purely FinServ *branding* — S3
object names, DOM selectors and CSS classes, deployment/execution inputs, the Lambda logical and
physical names, Step Functions state names, directory and doc filenames, and the IAM `Sid` — are
**renamed** to Responsible AI GRC with no dual-write and no additive alias (the sole exception is the
`EnableFinServAssessment` / `ENABLE_FINSERV` deployment toggle, retained as a legacy alias; see the
Renamed table below).

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
| `EnableFinServAssessment`, `ENABLE_FINSERV`, `enableFinServ` (primary deployment/execution inputs) | `EnableResponsibleAIGRCAssessment`, `ENABLE_RESPONSIBLE_AI_GRC`, `enableResponsibleAIGRC` (primary); `EnableFinServAssessment`/`ENABLE_FINSERV` retained as a legacy alias, see `docs/RESPONSIBLE_AI_GRC_ALIAS_MIGRATION.md` |
| `FinServSecurityAssessmentFunction`, `aiml-security-${AWS::StackName}-FinServAssessment` | `ResponsibleAIGRCAssessmentFunction`, `aiml-security-${AWS::StackName}-RAIGRCAssessment` |
| `FinServ Enabled?`, `FinServ Security Assessment`, `FinServ Assessment Incomplete`, `FinServ Assessment Skipped` (Step Functions state names) | `Responsible AI GRC Enabled?`, `Responsible AI GRC Security Assessment`, `Responsible AI GRC Assessment Incomplete`, `Responsible AI GRC Assessment Skipped` |
| `$.finservError` (Step Functions result path) | `$.responsibleAIGRCError` |
| `finserv_assessments/`, `finserv_tests/` directories | `responsible_ai_grc_assessments/`, `responsible_ai_grc_tests/` |
| `docs/SECURITY_CHECKS_FINSERV*.md` filenames | `docs/SECURITY_CHECKS_RESPONSIBLE_AI_GRC*.md` |
| `FinServGenAIRiskAssessmentPermissions` IAM `Sid` | `ResponsibleAIGRCAssessmentPermissions` |

Archived reports and CSVs generated before this rename retain their original filenames and DOM
selectors — this table describes what the tool produces going forward, not a retroactive rewrite
of historical artifacts.

One declared, intentional change: `Compliance_Frameworks` CSV **values** were corrected to match
in-code provenance. Fourteen checks gained a sourced mapping and eight had an unfounded assertion
removed. Archived reports keep their original values; comparisons across the change boundary should
expect this column to differ.

### Why the identifiers are not renamed yet

Renaming `AWS::Lambda::Function.FunctionName` or a CloudFormation logical ID forces resource
replacement, changing ARNs, permissions, log groups, concurrency, and rollback behavior. Renaming the
documentation files breaks public, search-indexed GitHub Pages URLs. Renaming the CSV prefix or the
`FS-*` IDs breaks the 42 OWASP mappings, the severity register, and historical comparison.

Those changes are reserved for a major release with a deprecation period, a migration guide, and an
archived-report converter.

A recorded constraint for that release: `aiml-security-${AWS::StackName}-ResponsibleAIGRCAssessment`
renders to 67 characters in multi-account member mode, exceeding the 64-character Lambda
`FunctionName` limit. The worst-case fixed portion is 41 characters, leaving a 23-character suffix
budget. Any future physical rename must use a suffix such as `RAIGRCAssessment` (16). Both
`ResponsibleAIGRCAssessment` and `ResponsibleAIGovAssessment` are infeasible.
