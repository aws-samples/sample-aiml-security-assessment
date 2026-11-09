# Sample Reports

This directory contains sample AI/ML security assessment reports and documentation screenshots for the README.

## Contents

### Current AISF examples

These deterministic examples use the actual single-account and multi-account
consolidators. Both HTML reports and their exports show actual AI check results
and their reviewed AISF mappings. The complete canonical catalog is reference
data; unobserved controls do not create report entries or manual-review tasks.

- [Single-account HTML](aisf_single_account.html) and [JSON](aisf_single_account.json).
- [Multi-account HTML](aisf_multi_account.html) and [JSON](aisf_multi_account.json).
- [Input/output provenance](aisf-provenance.json).
- [Synthetic scope and fixed clock](fixtures/aisf/scope.json) and
  [source CSV fixtures](fixtures/aisf/accounts/).

The fixtures use only fake accounts `111122223333` and `444455556666`,
`us-east-1`, `us-west-2`, and explicit Global evidence. All four direct services,
GRC, and OWASP are selected. Failed BR, SM, AC, AR, native AG, FS, and native OW
checks appear under their reviewed AISF relationships in both reports and exports.
`OW-01` projects `FS-51`; it appears as a presentation of that source evidence.
Original `FS-57/58` advice retains its `N/A` status and source limitations.
`AG-26` appears as an additional AI check with no reviewed AISF mapping.

The first account deliberately lacks its selected AgentCore west artifact.
The second account has an interrupted SageMaker west CSV and failed assessment
status. Fixtures also retain conflicting pass/fail observations, denial,
unsupported scope, no-resource discovery, and Global deduplication. These are
intentionally incomplete assessments. Collected findings retain their actual
`Passed`, `Failed`, or `N/A` results while missing inputs remain visible.
They demonstrate report behavior, not live AWS validation.

Open **By Compliance Standard → AWS AI Security Framework**. Filter for failed
results to find the original checks and their actions, or search a native check
ID such as `FS-51`. Open a result to inspect its evidence, scope, and mappings.
JSON and CSV downloads retain all included check results regardless of display
filters. A source check passing does not claim whole-control AISF compliance.

From the repository root, regenerate or check both modes without AWS access:

```bash
.venv/bin/python tools/generate_aisf_samples.py
.venv/bin/python tools/generate_aisf_samples.py --check
```

The fixed timestamp is `2026-11-06T12:00:00+00:00`. Provenance records canonical
revision `5df3295024713ac3ce88130c549bbc4fb2cebd53`, catalog/mapping,
fixture, generator, and output SHA-256 hashes. A byte mismatch fails `--check`.
See the [catalog update flow and report contract](../docs/SECURITY_CHECKS_AISF.md).

The AISF generator records the primary anonymized reports' hashes without
rewriting them. Update those reports together with the workflow below.

### Sample HTML Reports

Interactive HTML reports demonstrating the assessment output:

- **[security_assessment_single_account.html](security_assessment_single_account.html)** - Example report for a single anonymized AWS account showing 1,539 finding rows across Bedrock, SageMaker AI, AgentCore, AWS Agent Registry, Agentic AI Security, Responsible AI GRC, OWASP Top 10 for LLM, and the derived AWS AI Security Framework view
- **[security_assessment_multi_account.html](security_assessment_multi_account.html)** - Example consolidated report for 3 anonymized AWS accounts showing 5,114 finding rows
- **[security_assessment_changes.html](security_assessment_changes.html)** - Example "Changes since last assessment" report for the single-account sample's account, comparing its run with the run before it (see [Changes Since Last Assessment](../docs/ASSESSMENT_HISTORY.md))
- **[selection-bedrock.html](selection-bedrock.html)** - Synthetic Bedrock-only selection with GRC and OWASP enabled.
- **[selection-governance-only.html](selection-governance-only.html)** - Synthetic all-direct-services-disabled selection showing independent GRC findings and OWASP coverage notices.

Regenerate these two selection examples without AWS access:

```bash
.venv/bin/python sample-reports/scripts/generate_selection_examples.py
```

They use fictional findings and a placeholder account ID, and are UI examples rather than live assessment evidence.

The main HTML examples and the changes page come from real runs, anonymized
together by `scripts/capture_screenshots.py --anonymize-only`: account IDs,
resource identifiers, and resource names, including IAM, CloudTrail, bucket,
session, secret, and Identity Center names, are synthetic placeholders, and a
resource has the same placeholder on every page. Their findings are
representative examples, not a current assessment of any account. Bedrock
`N/A` rows have `Informational` severity in both main reports.

**Features:**
- Executive dashboard with severity breakdown
- Priority recommendations
- Filterable findings table
- Light/dark mode toggle
- Direct links to AWS documentation
- Agentic AI Security lens view with its own section, sidebar entry, and filter option

**How to view:** Download the HTML file and open it in your web browser.

### Documentation Screenshots

Screenshots used in the main README to showcase report features:

| File | Description |
|------|-------------|
| `dashboard-overview-light.png` | Executive dashboard in light mode |
| `dashboard-overview-dark.png` | Executive dashboard in dark mode |
| `findings-table.png` | Interactive findings table with filters |
| `multi-account-summary.png` | Multi-account consolidated view |
| `changes-overview.png` | Changes since last assessment (captured by `scripts/capture_changes_screenshot.py`) |

### Developer Tools

#### scripts/

Automated screenshot capture and optimization tool:

- **[capture_screenshots.py](scripts/capture_screenshots.py)** - Python script to generate screenshots from HTML reports
- **[anonymize_patterns.py](scripts/anonymize_patterns.py)** - Patterns `capture_screenshots.py` uses to replace source-account values in the samples
- **[README.md](scripts/README.md)** - Script documentation and usage instructions

#### dev-requirements.txt

Python dependencies for screenshot generation:
- `playwright` - Headless browser automation
- `pillow` - Image processing and optimization

## Regenerating Screenshots

If you modify the report template or want to update screenshots:

```bash
# From repository root
./sample-reports/scripts/capture_screenshots.py
```

The script re-launches itself with the repository-root `.venv`, installs the
dependencies from `sample-reports/dev-requirements.txt` when missing, and keeps
the Playwright Chromium browser under `.venv/playwright-browsers`. The
repository `.venv` must already exist and use Python 3.12.

Screenshot height is calculated from the report sidebar at runtime, ensuring
that every service, lens, governance framework, and compliance-standard
navigation item is included.

To prepare and verify the environment without changing reports or screenshots:

```bash
./sample-reports/scripts/capture_screenshots.py --check-dependencies
```

See [Developer Guide](../docs/DEVELOPER_GUIDE.md#documentation-and-screenshots) for detailed instructions.

## For Developers

When updating the report template (`aiml-security-assessment/functions/security/generate_consolidated_report/report_template.py`):

1. Run an assessment with your changes and download its single-account,
   multi-account, and changes reports
2. Replace and anonymize the three sample pages, then recapture the
   screenshots, as described in
   [Updating the Changes Sample](../docs/DEVELOPER_GUIDE.md#updating-the-changes-sample)
3. Commit the HTML reports and screenshots together

## Notes

- The main reports and the changes page are anonymized results from real runs; the selection examples use fictional findings
- Actual assessment results will vary based on your AWS environment
- Reports are single HTML files with inline CSS and JavaScript; the only external resource is the Google Fonts stylesheet, and the report falls back to system fonts offline
- Screenshots are automatically optimized to keep file sizes small
