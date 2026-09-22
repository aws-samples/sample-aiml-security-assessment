# Sample Reports

This directory contains sample AI/ML security assessment reports and documentation screenshots for the README.

## Contents

### Sample HTML Reports

Interactive HTML reports demonstrating the assessment output:

- **[security_assessment_single_account.html](security_assessment_single_account.html)** - Example report for a single AWS account showing 7 findings across Bedrock, SageMaker, and AgentCore
- **[security_assessment_multi_account.html](security_assessment_multi_account.html)** - Example consolidated report for 3 AWS accounts showing 73 findings
- **[security_assessment_multi_account_agentic_prototype.html](security_assessment_multi_account_agentic_prototype.html)** - Prototype based on the existing multi-account report with an Agentic AI security overlay added to the same UI
- **[agentic-ai-lens-prototype.html](agentic-ai-lens-prototype.html)** - Prototype report showing how security-scoped Agentic AI check and control-domain metadata could be added to the HTML experience

- **[selection-bedrock.html](selection-bedrock.html)** - Synthetic Bedrock-only selection with GRC and OWASP enabled; [screenshot](selection-bedrock.jpg).
- **[selection-governance-only.html](selection-governance-only.html)** - Synthetic all-direct-services-disabled selection showing independent GRC findings and OWASP coverage notices; [screenshot](selection-governance-only.jpg).

Regenerate these two selection examples without AWS access:

```bash
.venv/bin/python sample-reports/scripts/generate_selection_examples.py
```

They use fictional findings and a placeholder account ID, and are UI examples rather than live assessment evidence.

**Features:**
- Executive dashboard with severity breakdown
- Priority recommendations
- Filterable findings table
- Light/dark mode toggle
- Direct links to AWS documentation
- Agentic AI security prototype view with security control summaries, question mapping, and lens-aware filters

**How to view:** Download the HTML file and open it in your web browser.

### Documentation Screenshots

Screenshots used in the main README to showcase report features:

| File | Description |
|------|-------------|
| `dashboard-overview-light.png` | Executive dashboard in light mode |
| `dashboard-overview-dark.png` | Executive dashboard in dark mode |
| `findings-table.png` | Interactive findings table with filters |
| `multi-account-summary.png` | Multi-account consolidated view |

### Developer Tools

#### scripts/

Automated screenshot capture and optimization tool:

- **[capture_screenshots.py](scripts/capture_screenshots.py)** - Python script to generate screenshots from HTML reports
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

1. Regenerate sample reports with your changes
2. Run the screenshot script to update documentation images
3. Commit both HTML reports and screenshots together

## Notes

- These are example reports with realistic but fictional findings
- Actual assessment results will vary based on your AWS environment
- Reports are fully self-contained HTML files (no external dependencies)
- Screenshots are automatically optimized to keep file sizes small
