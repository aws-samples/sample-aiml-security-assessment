#!/usr/bin/env python3
"""
Screenshot Capture Script for AI/ML Security Assessment Reports

This script captures and optimizes screenshots from the sample HTML reports.
Screenshots are saved in the sample-reports/ folder.

Requirements:
    - playwright
    - pillow (PIL)

Installation:
    source .venv/bin/activate
    pip install playwright pillow
    playwright install chromium

Usage:
    python sample-reports/scripts/capture_screenshots.py
"""

import sys
from pathlib import Path
from playwright.sync_api import sync_playwright
from PIL import Image
import time

# Configuration
REPO_ROOT = Path(__file__).parent.parent.parent
SAMPLE_REPORTS_DIR = REPO_ROOT / "sample-reports"
VIEWPORT_WIDTH = 1440
VIEWPORT_HEIGHT = 900
JPEG_QUALITY = 85  # Balance between quality and file size
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
        "clip": {"x": 0, "y": 0, "width": VIEWPORT_WIDTH, "height": 800},
    },
    {
        "name": "dashboard-overview-dark",
        "file": "security_assessment_single_account.html",
        "description": "Executive Dashboard (Dark Mode)",
        "actions": [
            {"type": "wait", "selector": ".metrics", "timeout": 2000},
            {"type": "click", "selector": ".theme-toggle"},
            {"type": "wait_time", "ms": 500},
            {"type": "scroll", "position": 0},
        ],
        "clip": {"x": 0, "y": 0, "width": VIEWPORT_WIDTH, "height": 800},
    },
    {
        "name": "findings-table",
        "file": "security_assessment_single_account.html",
        "description": "Detailed Findings Table with Filters",
        "actions": [
            {"type": "wait", "selector": "table", "timeout": 2000},
            {"type": "scroll", "position": 800},
            {"type": "wait_time", "ms": 300},
        ],
        "clip": {"x": 0, "y": 0, "width": VIEWPORT_WIDTH, "height": 900},
    },
    {
        "name": "multi-account-summary",
        "file": "security_assessment_multi_account.html",
        "description": "Multi-Account Consolidated View",
        "actions": [
            {"type": "wait", "selector": ".metrics", "timeout": 2000},
            {"type": "scroll", "position": 0},
        ],
        "clip": {"x": 0, "y": 0, "width": VIEWPORT_WIDTH, "height": 800},
    },
]


def optimize_png(image_path: Path, max_size_kb: int = 300) -> None:
    """
    Optimize PNG image to reduce file size while maintaining quality.

    Args:
        image_path: Path to the PNG file
        max_size_kb: Maximum target file size in KB
    """
    img = Image.open(image_path)

    # Convert RGBA to RGB if needed (reduces size)
    if img.mode == "RGBA":
        background = Image.new("RGB", img.size, (255, 255, 255))
        background.paste(img, mask=img.split()[3])  # Use alpha channel as mask
        img = background

    # Save with optimization
    img.save(image_path, "PNG", optimize=True)

    # Check file size
    file_size_kb = image_path.stat().st_size / 1024

    # If still too large, reduce quality by converting to JPEG
    if file_size_kb > max_size_kb:
        jpeg_path = image_path.with_suffix(".jpg")
        img.save(jpeg_path, "JPEG", quality=JPEG_QUALITY, optimize=True)
        image_path.unlink()  # Remove PNG
        print(
            f"  Converted to JPEG: {jpeg_path.name} ({jpeg_path.stat().st_size / 1024:.1f} KB)"
        )
        return jpeg_path

    print(f"  Optimized PNG: {image_path.name} ({file_size_kb:.1f} KB)")
    return image_path


def capture_screenshot(browser, screenshot_config: dict) -> Path:
    """
    Capture a screenshot based on the configuration.

    Args:
        browser: Playwright browser instance
        screenshot_config: Screenshot configuration dictionary

    Returns:
        Path to the captured screenshot
    """
    html_file = SAMPLE_REPORTS_DIR / screenshot_config["file"]

    if not html_file.exists():
        print(f"  WARNING: {html_file} not found, skipping...")
        return None

    print(f"\n Capturing: {screenshot_config['description']}")
    print(f"  Source: {screenshot_config['file']}")

    # Create a new page
    page = browser.new_page(
        viewport={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT}
    )

    # Navigate to the HTML file
    page.goto(f"file://{html_file.absolute()}")

    # Execute actions
    for action in screenshot_config["actions"]:
        if action["type"] == "wait":
            page.wait_for_selector(
                action["selector"], timeout=action.get("timeout", 5000)
            )
        elif action["type"] == "click":
            page.click(action["selector"])
        elif action["type"] == "scroll":
            page.evaluate(f"window.scrollTo(0, {action['position']})")
        elif action["type"] == "wait_time":
            time.sleep(action["ms"] / 1000)

    # Capture screenshot
    output_path = SAMPLE_REPORTS_DIR / f"{screenshot_config['name']}.png"

    if "clip" in screenshot_config:
        page.screenshot(path=output_path, clip=screenshot_config["clip"])
    else:
        page.screenshot(path=output_path, full_page=False)

    page.close()

    print(f"  OK Captured: {output_path.name}")

    # Optimize the screenshot
    optimized_path = optimize_png(output_path)

    return optimized_path


def main():
    """Main function to capture all screenshots."""
    print("=" * 70)
    print("AI/ML Security Assessment - Screenshot Capture Tool")
    print("=" * 70)

    # Check if sample reports exist
    if not SAMPLE_REPORTS_DIR.exists():
        print(f"\nERROR: Sample reports directory not found: {SAMPLE_REPORTS_DIR}")
        sys.exit(1)

    print(f"\n Sample reports directory: {SAMPLE_REPORTS_DIR}")
    print(f" Viewport size: {VIEWPORT_WIDTH}x{VIEWPORT_HEIGHT}")
    print(f" Target: {len(SCREENSHOTS)} screenshots")

    try:
        with sync_playwright() as p:
            # Launch browser
            print("\n Launching Chromium browser...")
            browser = p.chromium.launch(headless=True)

            captured_files = []

            # Capture each screenshot
            for screenshot_config in SCREENSHOTS:
                try:
                    output_path = capture_screenshot(browser, screenshot_config)
                    if output_path:
                        captured_files.append(output_path)
                except Exception as e:
                    print(f"  ERROR: Failed to capture screenshot: {e}")
                    continue

            browser.close()

            # Summary
            print("\n" + "=" * 70)
            print(f"SUCCESS: Successfully captured {len(captured_files)} screenshots")
            print("=" * 70)

            print("\n Generated screenshots:")
            total_size = 0
            for file_path in captured_files:
                size_kb = file_path.stat().st_size / 1024
                total_size += size_kb
                print(f"  - {file_path.name} ({size_kb:.1f} KB)")

            print(f"\n Total size: {total_size:.1f} KB ({total_size / 1024:.2f} MB)")

            print("\n Next steps:")
            print("  1. Review the screenshots in the sample-reports/ folder")
            print("  2. Update README.md to reference these screenshots")
            print("  3. Commit the screenshots to the repository")

    except ImportError as e:
        print("\nERROR: Required library not installed")
        print(f"   {e}")
        print("\nPlease install required dependencies:")
        print("   source .venv/bin/activate")
        print("   pip install playwright pillow")
        print("   playwright install chromium")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
