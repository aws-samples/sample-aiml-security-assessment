# Scripts

This directory contains utility scripts for development and documentation.

## Changes Sample Builder

`build_changes_sample.py` builds `sample-reports/security_assessment_changes.html`
and `.csv`, and the golden test data for the changes-since-last-assessment report
(`tests/fixtures/assessment_history/golden/`) from the two sample reports. It
needs only the standard library and the repository's `assessment_history`
package.

```bash
# Write the sample and the golden data
.venv/bin/python sample-reports/scripts/build_changes_sample.py

# Verify only; exits 1 if anything is out of date
.venv/bin/python sample-reports/scripts/build_changes_sample.py --check
```

## Changes Screenshot

`capture_changes_screenshot.py` captures `sample-reports/changes-overview.png`
from the sample changes page. It reuses `capture_screenshots.py`'s browser
setup and image optimization but captures only this page, and it doesn't
rewrite any report: it stops if the page holds a 12-digit number that isn't
one of the placeholder account IDs.

```bash
./sample-reports/scripts/capture_changes_screenshot.py
```

Rerun it after regenerating a sample report, and review the diff.

## Screenshot Capture Tool

`capture_screenshots.py` - Automated screenshot capture and optimization for documentation.

### Purpose

Captures screenshots from the HTML sample reports for use in the README and documentation. The script:
- Opens HTML reports in a headless browser
- Captures multiple views (dashboard, tables, light/dark modes)
- Automatically optimizes images for web
- Targets 200-300KB per screenshot

### Installation

The repository-root Python 3.12 `.venv` must already exist. The screenshot
script installs its optional Python packages and Chromium browser automatically
when they are missing.

```bash
# Prepare and verify dependencies without capturing screenshots
./sample-reports/scripts/capture_screenshots.py --check-dependencies
```

Python packages are installed from `sample-reports/dev-requirements.txt` into
the root `.venv`. Chromium is installed under
`.venv/playwright-browsers`.

### Usage

```bash
# Run the script
./sample-reports/scripts/capture_screenshots.py
```

The script will:
1. Launch Chromium in headless mode
2. Load each HTML report from `sample-reports/`
3. Expand the viewport to include the complete left navigation
4. Capture screenshots based on configuration
5. Optimize and compress images
6. Save to `sample-reports/` folder

### Configuration

Edit `sample-reports/scripts/capture_screenshots.py` to customize:

```python
# Viewport size
VIEWPORT_WIDTH = 1440
VIEWPORT_HEIGHT = 900

# Image quality
JPEG_QUALITY = 85
PNG_OPTIMIZE = True

# Screenshots to capture
SCREENSHOTS = [
    {
        "name": "dashboard-overview-light",
        "file": "security_assessment_single_account.html",
        "description": "Executive Dashboard (Light Mode)",
        "actions": [
            {"type": "wait", "selector": ".metrics", "timeout": 2000},
            {"type": "scroll", "position": 0},
        ],
        "clip": {"x": 0, "y": 0, "width": 1440, "height": 800},
    },
    # Add more screenshots...
]
```

### Output

Screenshots are saved with these naming conventions:
- `dashboard-overview-light.png/jpg` - Dashboard in light mode
- `dashboard-overview-dark.png/jpg` - Dashboard in dark mode
- `findings-table.png/jpg` - Findings table view
- `multi-account-summary.png/jpg` - Multi-account report

All images are automatically optimized to keep file sizes under 300KB while maintaining visual quality.

### Adding New Screenshots

1. Add a new entry to the `SCREENSHOTS` list in `sample-reports/scripts/capture_screenshots.py`
2. Define actions (wait, click, scroll) to prepare the view
3. Specify clip area or use full viewport
4. Run the script
5. Update README.md to reference the new screenshot

### Troubleshooting

**Error: playwright not installed**

The script normally installs Playwright automatically. Verify the environment:

```bash
./sample-reports/scripts/capture_screenshots.py --check-dependencies
```

If `.venv` does not exist, create it first:

```bash
python3.12 -m venv .venv
```

**Error: Sample reports not found**
- Ensure you're running from the repository root
- Check that `sample-reports/` directory exists
- Verify HTML files are present

**Screenshots too large**
- Adjust `JPEG_QUALITY` (lower = smaller file)
- Reduce viewport size
- Use clip regions to capture specific areas

### Dependencies

- `playwright` - Browser automation
- `pillow` - Image optimization

See `sample-reports/dev-requirements.txt` for version details.
