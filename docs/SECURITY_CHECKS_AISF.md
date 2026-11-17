# AWS AI Security Framework (AISF) Assessment

Selecting AISF runs the existing AI workload collectors together. Both report
modes show their actual check results, affected resources, remediation, and
reviewed AISF mappings. Checks without a reviewed mapping remain visible as
additional AI security observations. The assessment does not create a manual
review of all 218 canonical controls.

The catalog is pinned to canonical repository revision
`5df3295024713ac3ce88130c549bbc4fb2cebd53`. Its existing
`build/export_controls.py` supplies the stable exported representation.
The vendored bundle preserves each question, guidance, applicability, evidence,
risk, source reference, and implementation step. The obsolete 253-control
crosswalk is historical and is not the inventory oracle.

## Selecting AISF

Set the `EnableAISFAssessment` CloudFormation parameter to `true`. It defaults
to `false` in both top-level deployment templates and both direct SAM templates.
When enabled, it selects all four direct service collectors (Bedrock, SageMaker,
AgentCore, and Agent Registry) plus Responsible AI GRC and OWASP, overriding
individual assessment switches. Customers do not need to select OWASP or GRC
separately to obtain their mapped AISF evidence. GRC runs in the first selected
Region once per account; OWASP runs in each selected Region.

CodeBuild resolves the preset before deployment, execution, artifact copying,
and history. Direct SAM deployments bake the same setting into the state
machine, so an execution with `{}` input uses the preset without extra flags.
Execution input cannot override the deployed AISF or direct-service selection.
With the preset disabled, the existing individual service and optional-standard
selection behavior is preserved.

Selecting AISF runs existing collectors; it does not add a producer, IAM grant,
or whole-control adjudicator. Source results assess their stated predicates.
Optional AgentCore artifact object reads remain controlled by their separate
switch and are not enabled by AISF. Unavailable reads, interrupted collectors,
and original source advice remain visible without creating additional tasks
from unobserved canonical requirements.

## Reference inventory

These counts describe the catalog and mapping review. They are not the
customer report's assessment denominator; displayed results come from the
actual run.

| Measure | Count | Meaning |
| --- | ---: | --- |
| Canonical controls | 218 | 62 baseline and 156 AI controls across 24 sections |
| Machine-classified controls | 104 | Canonical classification, not proof of automated coverage |
| Non-machine controls | 114 | Whole requirements need process or application evidence outside this automated assessment |
| Controls with a reviewed source mapping | 126 | 102 machine and 24 non-machine controls |
| Controls without a mapped collector | 92 | 2 machine and 90 non-machine controls |
| Reviewed mapping edges | 303 | Partial relationships from 208 existing native checks |
| Partial mappings | 126 | Some evidence is reusable; full requirements remain unproven |
| Justified whole-control pass adjudicators | 0 | No current source combination establishes the complete requirement |
| Native source checks reviewed | 233 | 208 mapped and 25 excluded with specific reasons |
| Derived presentation IDs reviewed | 44 | 34 AG aliases and 10 OW categories; not extra native checks |
| Scanner check catalog | 277 | 233 native IDs plus 44 derived presentations; AISF adds no producer checks |

The earlier 64 whole-control labels were re-reviewed and downgraded to partial
evidence. The other 39 mapped controls remain partial. A matching tag, a check
count, a machine classification, or a source `Passed` result does not prove a
canonical control. The report's finding counts come from accepted observations
in the current run.

The producer `Compliance_Frameworks` column retains its existing tags for
compatibility. Bare AISF tags and legacy `(N of M checks)` qualifiers are
historical mapping metadata, not trusted completeness or pass claims.
The reviewed ledger takes precedence over these labels.

## Comprehensive source review

Every current source predicate and derived presentation is accounted for in
`aisf_catalog/check_inventory.json`. The inventory is independent of the old
AISF tags: collector ASTs, native call sites, AG projections, OW category
mappings, and the check catalogs establish the expected IDs. There are 162
BR/SM/AC/AR native IDs, 64 FS IDs, five native AG IDs, and two native OW IDs.
`BR-14` remains a catalog/native ID, but its invocation is disabled; its mapping
does not make that missing observation available.

| Family | Native IDs | Previous mapped / edges | Current mapped / edges | Excluded |
| --- | ---: | ---: | ---: | ---: |
| BR | 57 | 33 / 53 | 50 / 74 | 7 |
| SM | 42 | 26 / 40 | 41 / 63 | 1 |
| AC | 53 | 46 / 81 | 52 / 90 | 1 |
| AR | 10 | 4 / 4 | 9 / 11 | 1 |
| AG | 5 | 4 / 8 | 4 / 8 | 1 |
| FS | 64 | 0 / 0 | 50 / 55 | 14 |
| OW | 2 | 0 / 0 | 2 / 2 | 0 |
| Total | 233 | 113 / 186 | 208 / 303 | 25 |

All 186 previous edges remain as partial evidence; 117 reviewed relationships
are added. The mapped-control count grows from 103 to 126, while controls with
no source mapping fall from 115 to 92. None of these counts means a whole
control passed. OW's ten categories project 84 source IDs through 95 category
edges; these presentations contribute their underlying observations, not
category-wide AISF mappings.

Examples include FS-51 prompt-attack configuration for `AIR-BDR-GRD-02`, FS-45
PII configuration for `AIR-BDR-GRD-03`, and FS-47/50 grounding/relevance settings
for `AIR-BDR-GRD-09`. BR-24 and both FS-27 branches contribute contextual
grounding or formal-policy-validation evidence to GRD-09. Policy existence
does not establish correct rules, domain applicability, guardrail association,
invocation, or response validation. FS-57/58 retain manual review requests for
output encoding and schema validation; actual runtime/tool association and
application behavior still need proof. Native OW-11/12 retain their heuristic
limitations. Topic/profanity configuration in OW-12 is not proof of a dedicated
prompt-attack filter.

The following native checks have no defensible relationship to the pinned
canonical requirements based on their current predicates. Their observations
remain in the AISF view and exports with no reviewed AISF mapping, as well as
in their original report sections. A mapping exclusion does not establish that
an AI check is irrelevant or that its result is clean. Full source locations,
counterevidence, and limitations are in the check inventory.

| Excluded ID | Why the present predicate cannot support an AISF mapping |
| --- | --- |
| AC-05 | ECR name heuristic does not identify a deployed runtime; no matching repository-at-rest requirement |
| AG-26 | Gateway DEBUG mode does not establish application redaction before telemetry export |
| AR-05 | Registry CMK advisory has no matching canonical key requirement |
| BR-19 | PrepareFlow validation does not establish peer review, security testing, approval, or controlled deployment |
| BR-22 | Quota increase requests do not establish per-caller limits or bounded consumption |
| BR-29 | Bedrock idle TTL is not AgentCore runtime lifecycle control or enforced tool/cost bounds |
| BR-30 | Imported model-weight encryption does not establish training, fine-tuning, or grounding-data protection |
| BR-31 | Batch-output encryption does not establish the canonical data-path or disposal requirements |
| BR-38 | Bedrock reasoning-policy keys are not AgentCore Policy engine keys |
| BR-40 | Marketplace endpoint keys do not establish SageMaker transport or training-data requirements |
| SM-12 | Endpoint instance count is an availability setting, not an enforced request or consumption limit |
| FS-03 | Quota increase requests do not establish security bounds |
| FS-14 | Config rule names do not establish rule behavior or SageMaker drift detection |
| FS-25 | A generic AOSS key observation lacks actual Bedrock knowledge-base association |
| FS-26 | A generic AOSS VPC text match lacks public-access semantics and knowledge-base association |
| FS-29 | Compliance disclaimer supplies no observed control predicate |
| FS-30 | Bedrock bias-dataset review does not establish the SageMaker-specific requirement |
| FS-34 | An available LEGACY foundation model is not evidence of a deployed model |
| FS-37 | General user feedback has no matching canonical predicate |
| FS-40 | Bedrock bias review does not establish the SageMaker-specific requirement |
| FS-49 | Hallucination disclaimer supplies no observed control predicate |
| FS-55 | Lambda function names do not establish input-validation behavior |
| FS-62 | Data-currency disclaimer supplies no observed control predicate |
| FS-63 | Config/lifecycle names and model catalog entries do not establish deployed-model governance |
| FS-69 | Prompt input-validation names do not establish validation behavior |

## Report and export contract

The AISF section under **By Compliance Standard** uses the same summary and
findings table as the other frameworks. **View failed findings** and **View all
rows** open the shared table with AISF selected. Use its search, severity, and
status filters, plus account and Region filters where available. Open **Details
and remediation** for source ownership, resource scope, mappings, and evidence.

With no accepted observations, AISF shows an empty or incomplete result as
appropriate; it does not populate 218 canonical rows. Each result preserves:

- Native check identity and original `Passed`, `Failed`, or `N/A` status.
- Finding details, severity, resource identifiers, source remediation, and
  validated reference links.
- Account, Region, execution, producer owner, and discovery/permission errors.
- Reviewed AISF relationships for the actual observed predicate, or an explicit
  indication that no reviewed mapping exists.
- Equivalent AG/OW presentations attached to their underlying observation.

Collector, artifact, and input gaps appear separately under **Coverage gaps and
incomplete inputs** when present.
The canonical catalog remains internal reference data. Its unobserved manual
and unmapped requirements create no customer findings, proof obligations, or
assessment denominator. Actual source-emitted advisory rows retain their
original `N/A` outcome and limitations, are labelled as advisory findings,
and are excluded from automated-result counts.

**Export all AISF JSON** and **Export all AISF CSV** include all retained check
results and coverage gaps, independent of the current display filter. Each
result represents an observation in its actual
scope; multiple resources or conflicting outcomes remain separate observations.
Neither finding counts nor unique check counts claim whole-control compliance.
JSON `scope.enable_aisf` records the preset setting; `scope.source_selection`
records each effective collector selection. The enabled-preset notice requires
all six collectors to be selected. Standalone report inputs with the preset
marker but a partial source selection retain that scope and show an incomplete
scope notice, without assuming that the missing collectors ran.
HTML escapes untrusted text and permits only validated HTTPS source links.
CSV text is protected against spreadsheet formula execution.

## Status semantics

| Result | Meaning |
| --- | --- |
| Passed | The source check's stated predicate passed for the observed resource and scope |
| Failed | The source check's stated predicate failed; its original remediation remains actionable |
| N/A | The source reports no applicable resource, unavailable/inconclusive evidence, or advice requiring application review |

The AISF view preserves these source outcomes. An attached mapping does not
extend a source pass or failure into whole-control AISF compliance. All current
reviewed mappings are partial relationships. Filter for failed results to find
actionable source findings even when another collector is unavailable.
Search matches native check IDs, alias presentations, mapping IDs, finding
details, resources, and remediation. N/A advice and unavailable reads must remain
distinguishable from a successful empty discovery.
`Passed` is never inferred from tags, no-resource discovery, manual/advisory
evidence, unavailable evidence, or a deselected service.

An empty discovery with an explicit successful producer receipt is different
from a denied or interrupted discovery. Neither proves the complete control.
When a collector retains rows before a pagination failure, those rows remain
useful evidence and the missing population remains a gap.

## Scope and input completeness

Regional observations apply only within the same account, execution, Region,
and selected producer. Global evidence has its own explicit scope; it is not
copied into every Region. Only equivalent observations in equivalent scope
are deduplicated. Conflicting pass/fail rows are retained deterministically.
An ambiguous observation without an execution identity is not shared between
multiple executions.

The reviewed evidence includes direct BR/SM/AC/AR checks, native Agentic AI
checks, Responsible AI GRC checks, and native OWASP checks. FS evidence uses the
existing **GRC or OWASP** selection contract. Native OW evidence requires OWASP.
An AG or OW category presentation is traced to its actual source check and
owner. An equivalent alias does not add a second observation; conflicting
observations remain visible. A category row without a specific source identity
cannot stand in for every check in that category.

The AISF preset selects these existing sources together. With the preset off,
the report follows the individual selection flags and does not activate an
omitted source. Both report paths retain FS evidence needed by OWASP, including
when the separate GRC presentation is hidden. Evidence absent because its owner
was not selected remains an explicit scope gap; enabling a report view alone
does not prove that a collector ran.

Partially selected presets expose their actual selected and deselected collectors.
Cross-account, cross-execution, cross-Region, unknown/retired source, and
cross-owner rows are isolated as input issues rather than credited as evidence.

Both consolidators distinguish missing, zero-byte, header-only, malformed,
unreadable, and wrong-schema selected CSVs. A malformed tail does not discard
earlier valid rows. Missing second Regions and explicitly failed assessments
remain visible. A successful report upload does not turn these inputs into a
complete assessment: diagnostic reports preserve useful findings while the run
reports incomplete status.

The state machine preserves compact service completion receipts for each
selected Region, including failures and explicit skips. Single-account report
validation requires these receipts. Multi-account CodeBuild supplies an explicit
account/execution/Region/status manifest through `ASSESSMENT_SCOPE_MANIFEST`.
Without a manifest, the local legacy directory helper reports unknown scope;
directory contents cannot prove that selected accounts or Regions are complete.

## Limits of automated coverage

Some canonical controls require process or application evidence that these
collectors cannot evaluate. They remain in the reference catalog without
becoming customer assessment rows. A whole control's non-machine classification
does not discard legitimate configuration findings mapped to part of it.
Likewise, a machine classification cannot invent a collector or a missing result.
Mappings preserve these limits while check results retain their narrow claims.

## Stable legacy source-summary IDs

Customer results use native check IDs and attach canonical mapping references.
The view does not allocate new `AISF-XX` producer IDs.

| Stable source summary | Canonical control | Source checks |
| --- | --- | --- |
| `AISF-05` | `AIR-BDR-KB-03` | `BR-20` |
| `AISF-07` | `AIR-SGM-EP-08` | `SM-18`, `SM-42` |
| `AISF-08` | `AIR-SGM-TRN-05` | `SM-09`, `SM-01`, `SM-03` |

These summaries preserve source failures, but otherwise report `N/A` with the
partial-proof limitation. `AISF-00` remains an informational completeness marker.
Retired `AISF-01`, `AISF-02`, `AISF-03`, `AISF-04`, and `AISF-06` are never reused.
Their former controls remain under canonical IDs in the reference catalog.

The canonical risk is retained verbatim. Legacy row severities use the scanner's
four-band scale, which collapses critical to High; the retained disclosure
identifies that collapse. The historical critical controls are `AIR-ACR-GW-01`,
`AIR-ACR-RT-09`, and `AIR-BDR-GRD-01`.

AISF is derived by shared `aisf_results.py` at report time. It adds no Lambda,
CSV prefix, assessment branch, IAM grant, or producer count. Its canonical
controls and legacy summaries are excluded from the direct-check pass rate and
Open Action Items to avoid counting source findings twice.

## Catalog, mapping, and sample updates

The report package contains `aisf_catalog/controls.json`, `classification.json`,
`mapping.json`, `check_inventory.json`, and `manifest.json`. The manifest pins the revision, schema,
exporter, relevant source inputs, and generated output hashes. `controls.json`
is the exact canonical export. `classification.json` retains only each control’s
section, text hash, kind, machine-checkability, and workload-agnostic flag. The
manifest records that projection schema and field list alongside the raw source
classification checksum and the projected output checksum. The mapping
ledger also pins the canonical record and producer source digests.
The check inventory accounts for every native predicate and derived presentation,
including untagged checks. It records source locations, aliases, reviewed AISF
relationships, limitations, and a specific exclusion when no defensible
relationship exists. A count is not a reason to add a mapping.

From the repository root, check the vendored bundle and reviewed mapping:

```bash
.venv/bin/python tools/update_aisf_catalog.py --check
.venv/bin/python tools/check_aisf_inventory.py
```

The bundled data is a frozen export identified by its source revision and the
manifest input/output hashes. Runtime checks, tests, inventory validation, and
AISF sample regeneration use this vendored data and do not require the authoring
project. Re-import additionally requires an approved canonical authoring checkout
containing `build/export_controls.py`; that checkout and exporter are not
distributed in this repository. With that checkout available, re-import the
approved revision:

```bash
.venv/bin/python tools/update_aisf_catalog.py \
  --source /path/to/aws-ai-security-framework-assessment \
  --revision 5df3295024713ac3ce88130c549bbc4fb2cebd53
```

Append `--check` to verify that checkout without writing it or the target bundle.
The importer invokes the canonical exporter; it does not interpret YAML through
a second schema. Classification imports use the recorded field allowlist, so
unused source annotations are not copied into the assessment bundle. A new
canonical revision requires explicit pin updates, an
independent mapping review, and refreshed frozen acceptance evidence. Never
repair a mismatch by deriving expected IDs from the implementation ledger.

Regenerate and check both deterministic examples:

```bash
.venv/bin/python tools/generate_aisf_samples.py
.venv/bin/python tools/generate_aisf_samples.py --check
```

See [sample provenance and fixtures](../sample-reports/README.md#current-aisf-examples).
The frozen acceptance inventory is `tests/fixtures/aisf/canonical-ids.txt`.
Acceptance tests exercise both consolidators, all 64 service/standard selections,
artifact failures, scope isolation, unsafe links, and false whole-control passes.

## Interpretation

This assessment reports AI workload check results. Selecting AISF includes the
existing AI collectors and their reviewed mappings; it does not certify every
canonical requirement. Process and application evidence beyond the implemented
checks is outside this assessment's scope.
