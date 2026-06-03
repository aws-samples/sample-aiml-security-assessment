#!/usr/bin/env python3
"""
Regression: prove the OWASP report reuses the official resco template with ZERO
formatting changes to existing sections — OWASP is purely additive.

Compares my generated report against the official sample report:
  sample-reports/security_assessment_single_account.html
"""

import re
import sys

OFFICIAL = "/Users/biswasrp/resco-aiml-assessment/sample-resco-aiml-assessment/sample-reports/security_assessment_single_account.html"
MINE = "/Users/biswasrp/resco-aiml-assessment/security_assessment_owasp_676206921018.html"

official = open(OFFICIAL).read()
mine = open(MINE).read()

results = []


def check(label, ok, detail=""):
    results.append((label, bool(ok), detail))


def css_of(h):
    return h[h.index("<style>") + 7:h.index("</style>")].strip()


def js_of(h):
    s = h.rindex("<script>") + len("<script>")
    e = h.rindex("</script>")
    return h[s:e]


# 1. CSS byte-identical
check("CSS block is byte-identical to official", css_of(official) == css_of(mine),
      "differs" if css_of(official) != css_of(mine) else "")

# 2. Official JS embedded verbatim (mine = official JS + 1 trailing OWASP filter line)
ojs = js_of(official).rstrip().rstrip("%").rstrip()
mjs = js_of(mine)
check("Official JS embedded verbatim (prefix match)",
      ojs in mjs, "official JS not found verbatim in mine")

# 3. Only-addition to JS is the single OWASP createServiceFilter call
extra = mjs.replace(ojs, "")
extra_calls = re.findall(r"createServiceFilter\([^;]*\);", extra)
check("Only JS addition is 1 OWASP createServiceFilter call",
      len(extra_calls) == 1 and "owaspTable" in extra_calls[0],
      f"extra calls={extra_calls}")

# 4. Head/title identical, no injected web fonts
check("Title matches official", "<title>AI/ML Security Assessment Report</title>" in mine)
check("No injected Google Fonts link (official has none)",
      ("fonts.googleapis.com" in mine) == ("fonts.googleapis.com" in official))

# 5. Main filter-bar markup identical (IDs: searchInput/serviceFilter/etc.)
for fid in ["searchInput", "serviceFilter", "severityFilter", "statusFilter", "resetFilters"]:
    check(f"main filter uses official id #{fid}", f'id="{fid}"' in mine)
check("main Service filter is service-native (no OWASP option)",
      re.search(r'id="serviceFilter">(.*?)</select>', mine, re.DOTALL) is not None
      and "owasp" not in re.search(r'id="serviceFilter">(.*?)</select>', mine, re.DOTALL).group(1).lower())

# 6. Main findings table header identical to official
def main_thead(h):
    m = re.search(r'<table id="findingsTable"><thead>(.*?)</thead>', h, re.DOTALL)
    return m.group(1) if m else None
check("main findingsTable header identical to official",
      main_thead(official) == main_thead(mine),
      "header differs")

# 7. Per-service sections present with official id scheme
for svc in ["bedrock", "sagemaker", "agentcore"]:
    check(f"service section #{svc} present (official scheme)",
          f'<section id="{svc}" class="section">' in mine
          and f'id="{svc}Table"' in mine
          and f'id="{svc}SearchInput"' in mine)

# 8. Service section table header matches official's service table header
def svc_thead(h, sid):
    m = re.search(rf'<table id="{sid}Table"><thead>(.*?)</thead>', h, re.DOTALL)
    return m.group(1) if m else None
check("bedrock service table header matches official",
      svc_thead(official, "bedrock") == svc_thead(mine, "bedrock"),
      "service header differs")

# 9. Overview metric labels identical set
def metric_labels(h):
    seg = h[h.index('<section id="overview"'):h.index('<section id="findings"')]
    return re.findall(r'<div class="metric-label">([^<]+)</div>', seg)
check("Overview metric labels identical to official",
      metric_labels(official) == metric_labels(mine),
      f"official={metric_labels(official)} mine={metric_labels(mine)}")

# 10. table-wrap scroll + sticky still present (Agasthi's scrollbar point)
check("table-wrap max-height:900px + overflow-y:auto present", "max-height: 900px" in mine)
check("sticky table headers present",
      re.search(r"th\s*\{[^}]*position:\s*sticky", mine) is not None)

# 11. ADDITIVE: exactly one new section (#compliance), nav has Compliance item,
#     By Service unchanged (3 services, no OWASP)
order = re.findall(r'<section id="([a-z\-]+)" class="section">', mine)
official_order = re.findall(r'<section id="([a-z\-]+)" class="section">', official)
added = [s for s in order if s not in official_order]
check("exactly ONE new section added (#compliance)",
      added == ["compliance"], f"added={added}")
check("all official sections still present in order",
      [s for s in order if s != "compliance"] == official_order,
      f"mine(minus compliance)={[s for s in order if s!='compliance']} official={official_order}")

bysvc = re.search(r'<h3>\s*By Service\s*</h3>(.*?)</nav>', mine, re.DOTALL).group(1)
check("By Service nav unchanged: 3 services, no OWASP",
      bysvc.count('class="nav-item"') == 3 and "OWASP" not in bysvc)

# 12. OWASP section is self-contained and reuses official component classes only
comp = mine[mine.index('<section id="compliance"'):mine.index('<section id="risk"')]
for cls in ['class="section-title"', 'class="filter-bar"', 'class="table-wrap"',
            'class="metric', 'class="status', 'class="reference-btn"']:
    check(f"OWASP section reuses official component {cls}", cls in comp)

# 13. OWASP doc links + per-check doc links present
aws_docs = len(set(re.findall(r'href="(https://docs\.aws\.amazon\.com[^"]+)"', mine)))
owasp_docs = len(set(re.findall(r'href="(https://genai\.owasp\.org[^"]+)"', mine)))
check(">= 40 unique AWS doc links", aws_docs >= 40, f"unique={aws_docs}")
check("all 10 OWASP category doc links", owasp_docs == 10, f"unique={owasp_docs}")

# 14. Account/region correctness
check("real account 676206921018", mine.count(ACCOUNT := "676206921018") > 10)

# 15. HTML balance (svg-stripped)
from html.parser import HTMLParser
class Bal(HTMLParser):
    VOID = {"br","img","meta","link","input","hr","rect","line","circle","path",
            "polyline","polygon","ellipse","use","stop","area","col","source"}
    def __init__(self):
        super().__init__(); self.st=[]; self.err=[]
    def handle_starttag(self,t,a):
        if t not in self.VOID: self.st.append(t)
    def handle_endtag(self,t):
        if t in self.VOID: return
        if not self.st: self.err.append(f"extra </{t}>"); return
        if self.st[-1]==t: self.st.pop()
        elif t in self.st:
            while self.st and self.st[-1]!=t: self.err.append(f"unclosed <{self.st.pop()}>")
            if self.st: self.st.pop()
        else: self.err.append(f"</{t}> vs <{self.st[-1]}>")
b = Bal(); b.feed(re.sub(r"<svg.*?</svg>","",mine,flags=re.DOTALL))
check("HTML tags balanced (svg-stripped)", not b.err and not b.st,
      f"err={b.err[:4]} stack={b.st[-4:]}")

# ---------------------------------------------------------------------------
ok = sum(1 for _, p, _ in results if p)
total = len(results)
print()
print("=" * 80)
print("REGRESSION: OWASP report vs official resco template")
print("=" * 80)
for label, passed, detail in results:
    print(f"  [{'PASS' if passed else 'FAIL'}] {label}")
    if not passed and detail:
        print(f"         -> {detail}")
print("=" * 80)
print(f"TOTAL: {ok}/{total} passed")
print("=" * 80)
sys.exit(0 if ok == total else 1)
