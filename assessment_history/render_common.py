"""Page parts borrowed from the main report, for the assessment history pages.

The main report's template (``report_template.py``) is loaded by file path
under its own module name, and its CSS, fonts link, dark-mode button, page
footer, escaping helpers, area names, and icons are reused. The changes page
then looks and behaves like the main report, including the reader's
light/dark choice. ``report_template.py`` itself is not changed; guard tests
fail if something used here moves.
"""

from __future__ import annotations

import functools
import importlib.util
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .models import CORE_AREAS

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATH = (
    REPO_ROOT
    / "aiml-security-assessment"
    / "functions"
    / "security"
    / "generate_consolidated_report"
    / "report_template.py"
)
# A name of its own, so it never clashes with consolidate_html_reports.py's
# plain `import report_template`.
TEMPLATE_MODULE_NAME = "assessment_history_report_template"

# The one style the main report doesn't have: a grey label for findings that
# went away (same colors as `.severity.na`), plus layout for the page's own
# small parts.
EXTRA_CSS = """
.status.muted { background: var(--surface-2); color: var(--text-3); }
.change-sub { margin-top: 4px; font-size: 11px; color: var(--text-3); font-family: 'JetBrains Mono', monospace; }
.tile-note { margin: -16px 0 24px; }
.area-table { min-width: 720px; }
.area-table th, .area-table td { text-align: right; }
.area-table th:first-child, .area-table td:first-child { text-align: left; }
.area-table tr.group td { font-size: 11px; font-weight: 600; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.5px; background: var(--surface-2); }
.area-table tr.total td { font-weight: 700; }
.note-list { margin: 0; padding-left: 18px; }
.note-list li { margin: 4px 0; }
"""


class RenderError(ValueError):
    """The main report's template can't be used; the message says why."""


@dataclass(frozen=True)
class PageParts:
    """What the changes page borrows from the main report."""

    css: str
    fonts_link: str
    theme_button: str
    page_footer: str
    area_labels: dict[str, str]
    area_icons: dict[str, str]
    # (heading, nav-section CSS class, areas), in the main report's order
    nav_groups: tuple[tuple[str, str, tuple[str, ...]], ...]
    escape_text: Callable[[object], str]
    escape_attr: Callable[[object], str]
    safe_https_url: Callable[[object], str | None]


def _load_module(path: Path):
    spec = importlib.util.spec_from_file_location(TEMPLATE_MODULE_NAME, path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except (OSError, SyntaxError) as error:
        raise RenderError(f"can't load {path}: {error}") from None
    return module


def _find(pattern: str, text: str, what: str) -> str:
    match = re.search(pattern, text, re.S)
    if match is None:
        raise RenderError(f"report_template.py no longer has {what}")
    return match.group(1)


def load_parts(path: Path = TEMPLATE_PATH) -> PageParts:
    """Read the parts the changes page reuses from the main report's template."""
    module = _load_module(path)
    try:
        page = module.get_html_template()
        standards = {
            standard["slug"]: standard for standard in module.COMPLIANCE_STANDARDS
        }
        owasp = standards["owasp"]
        area_labels = {
            # The main report's Assessment Area filter names.
            "bedrock": "Bedrock",
            "sagemaker": "SageMaker",
            "agentcore": "AgentCore",
            "agent-registry": "AWS Agent Registry",
            "agentic": "Agentic AI Security",
            "responsible-ai-grc": module.RESPONSIBLE_AI_GRC_LABEL,
            "owasp": owasp["name"],
        }
        borrowed_icons = {
            "agent-registry": module.AGENT_REGISTRY_ICON,
            "agentic": module.AGENTIC_ICON,
            "responsible-ai-grc": module.RESPONSIBLE_AI_GRC_ICON,
            "owasp": owasp["icon"],
        }
        grc_heading = module.RESPONSIBLE_AI_GRC_NAV_HEADING
        helpers = (module._escape_text, module._escape_attr, module._safe_https_url)
    except (AttributeError, KeyError, TypeError) as error:
        raise RenderError(
            f"report_template.py no longer provides what the changes page uses: {error!r}"
        ) from None

    # The template is a str.format() string, so literal braces are doubled.
    css = _find(r"<style>(.*?)</style>", page, "the report styles")
    css = css.replace("{{", "{").replace("}}", "}")
    # The Bedrock, SageMaker, and AgentCore icons are written inline in the
    # template's sidebar rather than kept as constants.
    service_icons = {
        area: _find(
            rf'<a href="#{area}" class="nav-item">\s*(<span class="service-icon">.*?</svg></span>)',
            page,
            f"the {area} icon",
        )
        for area in ("bedrock", "sagemaker", "agentcore")
    }
    return PageParts(
        css=css + EXTRA_CSS,
        fonts_link=_find(
            r'(<link href="https://fonts\.googleapis\.com[^>]*>)',
            page,
            "the fonts link",
        ),
        theme_button=_find(
            r'(<button class="theme-toggle".*?</button>)', page, "the dark-mode button"
        ),
        page_footer=_find(
            r'(<footer class="page-footer">.*?</footer>)', page, "the page footer"
        ),
        area_labels=area_labels,
        area_icons={**service_icons, **borrowed_icons},
        nav_groups=(
            ("By Service", "", CORE_AREAS),
            ("By Lens", "lens-nav", ("agentic",)),
            (grc_heading, "governance-nav", ("responsible-ai-grc",)),
            ("By Compliance Standard", "compliance-nav", ("owasp",)),
        ),
        escape_text=helpers[0],
        escape_attr=helpers[1],
        safe_https_url=helpers[2],
    )


@functools.lru_cache(maxsize=1)
def page_parts() -> PageParts:
    """The borrowed parts, read once per process."""
    return load_parts()
