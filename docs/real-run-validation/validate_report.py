#!/usr/bin/env python3
"""
Validate the regenerated report against every concrete piece of feedback
Agasthi gave in the Slack thread.

Slack thread captured points:
  Agasthi 4:59 PM:
    "OWASP_DEMO_REPORT.html has a bunch of additional info which seems to be
     more intended for a review? e.g. What's Being Pushed to GitHub, Next Step,
     Testing Summary. I'm guessing these will not be there during the actual
     output?"
    Pranjit 5:00 PM: "Correct"

  Agasthi 5:00 PM:
    "the left navigation has a bunch of additional options as compared to
     the current demo - you might want to trim those down and keep only the
     [...] for now"
     [Attached image was a screenshot of the existing single-account sample
     report's sidebar - which has only two nav groups: Navigation + By Service.]

  Agasthi 5:00 PM:
    "can you generate an actual report and share? not the demo versions"

Earlier in the thread (1:30-1:56 PM):
  - "anyway you can combine into just the compliance place holder"
  - "I see multiple tables OWASP Top 10 for LLM Applications 2025, New OWASP
     Checks - All 18 Extensions ... are you planning to combine them into a
     single table?"
"""

import re
import sys
from collections import OrderedDict

REPORT = "/Users/biswasrp/resco-aiml-assessment/security_assessment_owasp_676206921018.html"
EXISTING_DEMO_BASELINE = "/Users/biswasrp/resco-aiml-assessment/assessment_report.html"

with open(REPORT) as f:
    html = f.read()

with open(EXISTING_DEMO_BASELINE) as f:
    baseline = f.read()


checks = OrderedDict()


def add(label, ok, detail=""):
    checks[label] = (ok, detail)


# -------------------------------------------------------------------------
# 1. Demo-only sections must be removed
# -------------------------------------------------------------------------
demo_sections = [
    ("What's Being Pushed to GitHub", r"What['\u2019]s Being Pushed"),
    ("Next Step section",              r"<h3>\s*Next Step\s*</h3>"),
    ("Testing Summary section",        r"<h2>\s*Testing Summary|>\s*Testing Summary\s*<"),
    ("Live AWS Validation Evidence",   r"Live AWS Validation Evidence|Live AWS Evidence"),
    ("Yellow review-demo banner",      r"demo-banner|Review demo"),
    ("'Demo for Review' in title",     r"Demo for Review"),
    ("Phase 2a/2b/3 commit references",r"Phase 2a|Phase 2b|Phase 1a|Phase 1b"),
    ("feature branch reference",       r"feature/owasp-llm|prancst2004"),
    ("seeded fixture references",      r"seeded run|empty account baseline|fixture|kiro-owasp"),
    ("Commits-on-branch table",        r"Commits on the Feature Branch"),
    ("Review-only PR body refs",       r"PR_BODY\.md|Live fix"),
]
for label, pattern in demo_sections:
    found = bool(re.search(pattern, html, re.IGNORECASE))
    add(f"REMOVED: {label}", not found,
        "absent" if not found else f"FOUND in report (regex: {pattern})")


# -------------------------------------------------------------------------
# 2. Sidebar must match the existing single-account report (only
#    "Navigation" + "By Service" groups, no separate "Compliance Frameworks")
# -------------------------------------------------------------------------
nav_groups_in_baseline = re.findall(r"<nav class=\"nav-section\">.*?<h3>([^<]+)</h3>",
                                    baseline, re.DOTALL)
nav_groups_in_report   = re.findall(r"<nav class=\"nav-section\">.*?<h3>([^<]+)</h3>",
                                    html, re.DOTALL)

add("Sidebar group count matches existing demo (2)",
    len(nav_groups_in_report) == 2,
    f"baseline groups={nav_groups_in_baseline} report groups={nav_groups_in_report}")

add("Sidebar groups are exactly Navigation + By Service",
    [g.strip() for g in nav_groups_in_report] == ["Navigation", "By Service"],
    f"got {nav_groups_in_report}")

add("No standalone 'Compliance Frameworks' nav group",
    "Compliance Frameworks" not in html,
    "absent")

# Demo-only sidebar entries shouldn't be there
sidebar_demo_links = ["#live-evidence", "#testing", "#whats-pushed"]
for link in sidebar_demo_links:
    add(f"Sidebar link {link} removed",
        link not in html,
        "absent")


# -------------------------------------------------------------------------
# 3. Right-side tables must be combined (the 1:30 / 1:45 PM thread)
# -------------------------------------------------------------------------
add("Combined OWASP table title present",
    "OWASP Top 10 for LLM Applications 2025 — Coverage by Category &amp; Check" in html
    or "OWASP Top 10 for LLM Applications 2025 - Coverage by Category" in html,
    "title present")

add("Old standalone 'New OWASP Checks - All 18 Extensions' table absent",
    "New OWASP Checks &mdash; All 18 Extensions" not in html
    and "New OWASP Checks — All 18 Extensions" not in html
    and "New OWASP Checks -- All 18 Extensions" not in html,
    "title absent")

# Both LLM01..LLM10 categories AND OW-01..OW-18 must appear in the same
# table (we render 10 cat rows + 18 sub rows in a single <table>)
cat_row_count = len(re.findall(r'class="cat-row"\s+data-llm="LLM\d{2}"', html))
sub_row_count = len(re.findall(r'class="sub-row"\s+data-parent="LLM\d{2}"', html))
add("Combined table has 10 LLM category rows", cat_row_count == 10,
    f"count={cat_row_count}")
add("Combined table has 18 OW-XX sub-rows nested under categories",
    sub_row_count == 18, f"count={sub_row_count}")


# -------------------------------------------------------------------------
# 4. "Generate an actual report, not a demo version"
# -------------------------------------------------------------------------
add("Real account ID 676206921018 in report", "676206921018" in html, "present")
add("Real region us-east-1 in report",        "us-east-1" in html,    "present")

# Account state was: 0 guardrails, 0 KBs, 0 agents, 0 custom models,
# 2 AgentCore runtimes, 1 ECR repo with scanOnPush=false. Validate that
# the OWASP overlay reflects this real state, not the demo's seeded state.
overlay_real = [
    ("OW-04 reflects logging-disabled state", r"OW-04.*Failed", html, re.DOTALL),
    ("OW-15 reflects no Bedrock budget/alarm", r"OW-15.*Failed", html, re.DOTALL),
    ("OW-16 reflects ECR scanOnPush=false",   r"OW-16.*Failed", html, re.DOTALL),
    ("OW-11 reflects 1 managed prompt found", r"OW-11.*Passed", html, re.DOTALL),
]
for label, pat, body, flags in overlay_real:
    add(label, bool(re.search(pat, body, flags)), "matched")

# Demo-only seeded-resource names should not leak in
seeded_resources = [
    "qxjfofitorgf",                                       # demo guardrail id
    "kiro-owasp-test",                                    # demo log group
    "kiro-owasp-bedrock-budget",                          # demo budget
    "BedrockInvocationSpike",                             # demo alarm
    "OrderBot",                                           # demo agent
    "PlaceOrderRole",                                     # demo IAM role
    "SupportKB",                                          # demo KB
    "prod-guardrail",                                     # demo guardrail
]
for r in seeded_resources:
    add(f"Demo-only seeded resource '{r}' absent", r not in html, "absent")


# -------------------------------------------------------------------------
# 5. Per-check AWS doc links present (matches the existing assessment's
#    pattern of 1 reference link per finding)
# -------------------------------------------------------------------------
aws_doc_links = set(re.findall(r'href="(https://docs\.aws\.amazon\.com[^"]+)"', html))
owasp_doc_links = set(re.findall(r'href="(https://genai\.owasp\.org[^"]+)"', html))

add("AWS docs links per check (>= 50 unique)",
    len(aws_doc_links) >= 50, f"unique={len(aws_doc_links)}")
add("All 10 OWASP LLM category doc links present",
    len(owasp_doc_links) == 10, f"unique={len(owasp_doc_links)}")


# -------------------------------------------------------------------------
# 6. HTML hygiene (no broken structure, no leftover review banners)
# -------------------------------------------------------------------------
# Tags balanced check
from html.parser import HTMLParser


class BalanceChecker(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.errors = []

    def handle_starttag(self, tag, attrs):
        if tag not in ("br", "img", "meta", "link", "input", "hr"):
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack:
            self.errors.append(f"unexpected close </{tag}>")
            return
        if self.stack[-1] != tag:
            if tag in self.stack:
                while self.stack and self.stack[-1] != tag:
                    self.errors.append(f"unclosed <{self.stack.pop()}>")
                if self.stack:
                    self.stack.pop()
            else:
                self.errors.append(f"close </{tag}> with top <{self.stack[-1]}>")
        else:
            self.stack.pop()


bc = BalanceChecker()
bc.feed(html)
add("HTML tags balanced (no unclosed/mismatched)",
    not bc.errors and not bc.stack,
    f"errors={len(bc.errors)} stack-remaining={len(bc.stack)}")


# -------------------------------------------------------------------------
# 7. Footer / generated-at must reflect this run (real, not demo)
# -------------------------------------------------------------------------
add("Footer shows real run date 2026-04-18", "April 18, 2026" in html, "present")
add("Footer shows real account 676206921018",
    "Account: 676206921018" in html, "present")
add("No 'Prepared: May 12, 2026' demo footer",
    "Prepared: May 12, 2026" not in html, "absent")
add("No GitHub feature-branch link in footer",
    "Feature Branch on GitHub" not in html, "absent")


# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
total = len(checks)
ok = sum(1 for v, _ in checks.values() if v)

print()
print("=" * 78)
print(f"Validation against Agasthi's feedback")
print(f"Report: {REPORT}")
print("=" * 78)
print()

last_section = None
for label, (passed, detail) in checks.items():
    icon = "PASS" if passed else "FAIL"
    print(f"  [{icon}] {label}")
    if not passed:
        print(f"         -> {detail}")

print()
print("=" * 78)
print(f"TOTAL: {ok}/{total} checks passed")
print("=" * 78)

sys.exit(0 if ok == total else 1)
