# Sample Reports

This directory contains sample AI/ML security assessment reports and documentation screenshots for the README.

## Contents

### Sample HTML Reports

Interactive HTML reports demonstrating the assessment output:

- **[security_assessment_single_account.html](security_assessment_single_account.html)** - Example report for a single AWS account showing 7 findings across Bedrock, SageMaker, and AgentCore
- **[security_assessment_multi_account.html](security_assessment_multi_account.html)** - Example consolidated report for 3 AWS accounts showing 73 findings
- **[security_assessment_multi_account_agentic_prototype.html](security_assessment_multi_account_agentic_prototype.html)** - Prototype based on the existing multi-account report with an Agentic AI security overlay added to the same UI
- **[agentic-ai-lens-prototype.html](agentic-ai-lens-prototype.html)** - Prototype report showing how security-scoped Agentic AI check and control-domain metadata could be added to the HTML experience

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

**Total size:** ~585 KB (optimized for web)

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
source .venv/bin/activate
pip install -r sample-reports/dev-requirements.txt
playwright install chromium
python sample-reports/scripts/capture_screenshots.py
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
