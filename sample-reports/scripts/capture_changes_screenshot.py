#!/usr/bin/env python3
"""
Screenshot of the "Changes since last assessment" sample page.

Captures sample-reports/changes-overview.png from
sample-reports/security_assessment_changes.html (built by
build_changes_sample.py). It reuses capture_screenshots.py's environment
setup, capture, and image optimization, but is a separate script so it never
touches the other sample reports or screenshots:

    - It doesn't rewrite any report. The changes sample is built from the
      already-anonymized single-account sample, so instead of replacing
      account IDs it stops if the page holds any 12-digit number that isn't a
      documented placeholder.
    - It captures only its own screenshot.

Usage, from the repository root:
    ./sample-reports/scripts/capture_changes_screenshot.py
    ./sample-reports/scripts/capture_changes_screenshot.py --check-dependencies
"""

import importlib.util
import os
import re
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
SHARED_SCRIPT = SCRIPTS_DIR / "capture_screenshots.py"


def _load_shared():
    """Load capture_screenshots.py by path; importing it has no side effects."""
    spec = importlib.util.spec_from_file_location(
        "capture_screenshots_shared", SHARED_SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


shared = _load_shared()

CHANGES_PAGE = "security_assessment_changes.html"
SCREENSHOTS = [
    {
        "name": "changes-overview",
        "file": CHANGES_PAGE,
        "description": "Changes Since Last Assessment (Light Mode)",
        "actions": [
            {"type": "wait", "selector": ".metrics", "timeout": 2000},
            {"type": "scroll", "position": 0},
        ],
        "clip": {"x": 0, "y": 0, "width": shared.VIEWPORT_WIDTH, "height": 900},
    },
]
_ACCOUNT_ID = re.compile(r"\b\d{12}\b")


def unexpected_account_ids(page_text: str) -> list[str]:
    """12-digit numbers in the page that aren't documented placeholder IDs."""
    placeholders = set(shared.ANONYMIZED_ACCOUNT_IDS)
    found = dict.fromkeys(_ACCOUNT_ID.findall(page_text))
    return [number for number in found if number not in placeholders]


def ensure_repo_venv() -> None:
    """Re-launch this script (not capture_screenshots.py) with the root .venv.

    capture_screenshots.ensure_repo_venv re-launches its own file, so this
    script checks first and re-launches itself.
    """
    venv_python = shared._repo_venv_python()
    if not venv_python.is_file():
        print(f"ERROR: Repository virtual environment not found: {venv_python}")
        print("Create it with Python 3.12 before running this tool:")
        print("  python3.12 -m venv .venv")
        sys.exit(1)
    if Path(sys.prefix).resolve() != (shared.REPO_ROOT / ".venv").resolve():
        print(f"Re-launching with repository Python: {venv_python}", flush=True)
        os.execv(
            str(venv_python),
            [str(venv_python), str(Path(__file__).resolve()), *sys.argv[1:]],
        )


def main(argv=None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    unexpected = [
        argument for argument in arguments if argument != "--check-dependencies"
    ]
    if unexpected:
        print(f"ERROR: Unsupported argument(s): {' '.join(unexpected)}")
        print("Supported option: --check-dependencies")
        return 2
    check_dependencies_only = "--check-dependencies" in arguments

    page_path = shared.SAMPLE_REPORTS_DIR / CHANGES_PAGE
    if not check_dependencies_only:
        if not page_path.is_file():
            print(f"ERROR: {page_path} not found.")
            print(
                "Build it first: .venv/bin/python sample-reports/scripts/build_changes_sample.py"
            )
            return 1
        unexpected_ids = unexpected_account_ids(page_path.read_text(encoding="utf-8"))
        if unexpected_ids:
            print(
                "ERROR: The changes sample holds account IDs that aren't documented "
                f"placeholders: {', '.join(unexpected_ids)}. Rebuild it from the "
                "anonymized single-account sample."
            )
            return 1

    ensure_repo_venv()
    shared.bootstrap_screenshot_environment()
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            if check_dependencies_only:
                print("Screenshot environment is ready.")
                return 0
            captured = shared.capture_all_screenshots(browser, SCREENSHOTS)
        finally:
            browser.close()
    for path in captured:
        print(f"  - {path.name} ({path.stat().st_size / 1024:.1f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
