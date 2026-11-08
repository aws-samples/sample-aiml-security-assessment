"""AISF ships as a *derived* compliance standard, and these tests hold that shape.

A derived standard is registered in `report_template.COMPLIANCE_STANDARDS` so it
renders and routes like any other, but no Lambda runs it and no CSV of its own
reaches S3. Its rows are computed at consolidation time from verdicts that
checks already shipping produced.

Two failure modes are specific to that arrangement and are what most of this
file exists to catch:

1. A derived slug must never become an S3 prefix. The report Lambda's
   `s3:ListBucket` grant restricts `s3:prefix` to the producing artifacts, so
   listing `aisf_security_report_*` returns AccessDenied, which the caller
   re-raises, which fails report generation for every category. The regression
   test asserts against the prefixes actually requested from the paginator and
   against the condition in template.yaml, so it reddens if the `derived` check
   in `app.py` is dropped.
2. A mapping whose source checks are partly absent must be reported, not
   dropped. A dropped row reads as "not relevant here" when what happened is
   that coverage was incomplete.
"""

import ast
import csv
import fnmatch
import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORT_APP_DIR = os.path.join(
    REPO_ROOT,
    "aiml-security-assessment",
    "functions",
    "security",
    "generate_consolidated_report",
)
if REPORT_APP_DIR not in sys.path:
    sys.path.insert(0, REPORT_APP_DIR)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import aisf_mappings  # noqa: E402
import aisf_results  # noqa: E402
import consolidate_html_reports as multi_account  # noqa: E402
import report_template  # noqa: E402

SAM_TEMPLATE = os.path.join(REPO_ROOT, "aiml-security-assessment", "template.yaml")

# Check_ID prefixes that live checks already emit. A compliance standard's
# prefix has to stay clear of these or its rows would be routed by the
# per-service branches before the registry is consulted.
LIVE_CHECK_PREFIXES = {"AC", "AG", "AR", "BR", "FS", "SM"}

# The published id shape. Four letters, where every producing prefix has two:
# see test_the_report_layer_does_not_validate_check_id for why that is legal.
AISF_ID_PATTERN = r"^AISF-\d{2}$"

REQUIRED_REGISTRY_KEYS = {
    "slug",
    "name",
    "prefix",
    "icon",
    "icon_small",
    "reference_url",
    "section_title",
    "scope_text",
}

DERIVED_ROW_KEYS = {
    "Check_ID",
    "Finding",
    "Finding_Details",
    "Resolution",
    "Reference",
    "Severity",
    "Status",
    "Region",
    "Account_ID",
    "_service",
}


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# app.py is loaded under a unique name: several assessment modules are also
# called `app`, and a plain import would collide inside one pytest session.
single_account = _load_module(
    "aisf_single_report_app", os.path.join(REPORT_APP_DIR, "app.py")
)

# The four severity bands a finding may carry, read from the shipped schema
# instead of transcribed. The GRC drift-guard
# (responsible_ai_grc_tests/test_severity_register.py) asserts the same property
# over SEVERITY_REGISTER, which the derived map is invisible to, so the derived
# rows need their own assertion. Reading the enum means a `Critical` added
# upstream fails here instead of being silently permitted by a copied literal.
#
# The schema imports its AISF tag map as a flat module, the way the Lambda does:
# at runtime the function root is on sys.path, so `from aisf_compliance_bedrock
# import ...` resolves. Put that one directory on sys.path for the load and take
# it off again. Leaving a producer directory on the path for the rest of the
# session would shadow `app` and `schema` for any test that loads a different
# producer afterwards, and those names are shared by all six producers.
_BEDROCK_DIR = os.path.join(
    REPO_ROOT,
    "aiml-security-assessment",
    "functions",
    "security",
    "bedrock_assessments",
)
sys.path.insert(0, _BEDROCK_DIR)
try:
    severity_schema = _load_module(
        "aisf_severity_schema", os.path.join(_BEDROCK_DIR, "schema.py")
    )
finally:
    sys.path.remove(_BEDROCK_DIR)
ALLOWED_SEVERITIES = {band.value for band in severity_schema.SeverityEnum}

METHODOLOGY_DOC = os.path.join(
    REPO_ROOT, "docs", "SECURITY_CHECKS_RESPONSIBLE_AI_GRC_SEVERITY_METHODOLOGY.md"
)


def _entry(slug):
    return next(s for s in report_template.COMPLIANCE_STANDARDS if s["slug"] == slug)


def _source_row(check_id, status="Passed", region="us-east-1", account="111122223333"):
    """A CSV-cased source row, as the report Lambda collects them."""
    return {
        "Check_ID": check_id,
        "Finding": f"{check_id} incumbent",
        "Finding_Details": "details",
        "Resolution": "Do the thing",
        "Reference": "https://docs.aws.amazon.com/",
        "Severity": "High",
        "Status": status,
        "Region": region,
        "Account_ID": account,
    }


def _derived_by_id(rows):
    return {r["Check_ID"]: r for r in rows}


def _register_from_html(html):
    match = re.search(r'<script[^>]+id="aisf-data"[^>]*>(.*?)</script>', html, re.S)
    assert match, "Every report must render the accepted AISF source check results."
    return json.loads(match.group(1))


def _checks_from_html(html):
    results = _register_from_html(html)
    assert results["view"] == "automated-check-results"
    assert "controls" not in results
    assert "whole_control_passes" not in results["summary"]
    return results["checks"]


def _all_mappings_derived(status):
    """Every mapping's emitted row, with all source checks present at `status`.

    Assertions about severity and about what a row discloses are made here, on
    the derivation's output, and not on `AISF_DERIVED_MAP`: the map being right
    is not the shipped claim, the row is.
    """
    every_source = sorted(
        {cid for m in aisf_mappings.AISF_DERIVED_MAP for cid in m["sources"]}
    )
    return aisf_mappings.derive_aisf_findings(
        [_source_row(cid, status) for cid in every_source]
    )


class TestRegistryEntry(unittest.TestCase):
    def test_entry_carries_the_eight_required_keys_plus_its_optional_keys(self):
        entry = _entry("aisf")
        self.assertEqual(
            set(entry),
            REQUIRED_REGISTRY_KEYS | {"derived", "scope_text_for"},
            msg=sorted(entry),
        )
        self.assertIs(entry["derived"], True)
        self.assertEqual(
            entry["scope_text_for"](**aisf_mappings.aisf_scope()), entry["scope_text"]
        )
        self.assertEqual(entry["prefix"], "AISF-")
        self.assertEqual(entry["name"], "AWS AI Security Framework")
        self.assertEqual(entry["section_title"], "AWS AI Security Framework Findings")

    def test_prefix_does_not_collide_with_a_live_check_prefix(self):
        prefix = _entry("aisf")["prefix"].rstrip("-").upper()
        self.assertEqual(prefix, "AISF")
        self.assertNotIn(prefix, LIVE_CHECK_PREFIXES)
        # AC-06 and AG-24 are AISF sources and both start with "A": the routing
        # branches compare the full prefix, not the first letter.
        for live in sorted(LIVE_CHECK_PREFIXES):
            self.assertNotEqual(prefix, live)

    def test_every_registered_prefix_and_slug_is_unique(self):
        prefixes = [s["prefix"].upper() for s in report_template.COMPLIANCE_STANDARDS]
        slugs = [s["slug"] for s in report_template.COMPLIANCE_STANDARDS]
        self.assertEqual(len(prefixes), len(set(prefixes)))
        self.assertEqual(len(slugs), len(set(slugs)))

    def test_owasp_is_not_marked_derived(self):
        """OWASP produces a CSV. Flagging it derived would stop it being read."""
        self.assertFalse(_entry("owasp").get("derived", False))

    def test_scope_text_describes_native_results_without_a_canonical_denominator(self):
        scope = _entry("aisf")["scope_text"]
        self.assertNotIn("218", scope)
        self.assertNotIn("All 218 canonical AISF controls", scope)
        self.assertIn("check", scope.lower())
        self.assertIn("source", scope.lower())
        self.assertNotIn("canonical controls", scope.lower())

    def test_ids_are_unique_and_the_coverage_id_is_not_allocated(self):
        ids = [m["check_id"] for m in aisf_mappings.AISF_DERIVED_MAP]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertNotIn(aisf_mappings.AISF_COVERAGE_CHECK_ID, ids)
        for check_id in ids:
            self.assertRegex(check_id, AISF_ID_PATTERN)

    def test_every_id_including_the_coverage_marker_has_the_aisf_shape(self):
        """The published id shape, and the pre-release spelling it replaced.

        The ids were renamed before the first push, so the two-letter spelling
        has never been published. The negative assertion holds the rename: it
        reddens if any id reverts to it.
        """
        ids = [m["check_id"] for m in aisf_mappings.AISF_DERIVED_MAP]
        ids.append(aisf_mappings.AISF_COVERAGE_CHECK_ID)
        self.assertEqual(len(ids), 4)
        for check_id in ids:
            self.assertRegex(check_id, AISF_ID_PATTERN)
            self.assertTrue(check_id.startswith(_entry("aisf")["prefix"]), check_id)
        self.assertNotRegex("AI-05", AISF_ID_PATTERN)

    def test_the_report_layer_does_not_validate_check_id(self):
        """Why a 4-letter prefix is safe here.

        Every assessment Lambda validates `Check_ID` against
        `^[A-Z]{2,3}-\\d{2}$`, which `AISF-01` does not satisfy. Derived rows
        never reach one: they are built in the report layer, whose `Finding`
        model has no `Check_ID` field at all. If that changes, the regex has to
        be widened in the same change.
        """
        report_schema = _load_module(
            "aisf_report_schema", os.path.join(REPORT_APP_DIR, "schema.py")
        )
        self.assertNotIn("Check_ID", report_schema.Finding.model_fields)
        with self.assertRaises(ValueError):
            severity_schema.create_finding(
                check_id=aisf_mappings.AISF_DERIVED_MAP[0]["check_id"],
                finding_name="Test",
                finding_details="Details",
                resolution="Fix",
                reference="https://docs.aws.amazon.com/test",
                severity="Low",
                status="Passed",
            )


class TestRetiredIds(unittest.TestCase):
    """Five ids left the map when their incumbents proved to assert part of it.

    Each incumbent asserts only part of its control, so restating its Passed under
    the AISF id would publish a pass the assessment never earned. The ids stay
    allocated: an archived report that carries one must keep meaning that control.
    """

    RETIRED = {
        "AISF-01": ("AIR-ACR-GW-01", ["AG-24"]),
        "AISF-02": ("AIR-ACR-RT-09", ["AC-06"]),
        "AISF-03": ("AIR-BDR-GRD-01", ["BR-10"]),
        "AISF-04": ("AIR-BDR-GRD-03", ["BR-26"]),
        "AISF-06": ("AIR-BDR-MDL-10", ["BR-37"]),
    }
    REMAINING = {
        "AISF-05": ("AIR-BDR-KB-03", ["BR-20"]),
        "AISF-07": ("AIR-SGM-EP-08", ["SM-18", "SM-42"]),
        "AISF-08": ("AIR-SGM-TRN-05", ["SM-09", "SM-01", "SM-03"]),
    }

    def test_the_retired_ids_are_recorded_with_their_controls(self):
        self.assertEqual(
            {
                cid: entry["control"]
                for cid, entry in aisf_mappings.RETIRED_AISF_IDS.items()
            },
            {cid: control for cid, (control, _) in self.RETIRED.items()},
        )
        for cid, entry in aisf_mappings.RETIRED_AISF_IDS.items():
            self.assertEqual(
                entry["reason"],
                "the incumbent asserts only part of the control",
                msg=cid,
            )

    def test_no_retired_id_or_control_is_in_the_map(self):
        ids = {m["check_id"] for m in aisf_mappings.AISF_DERIVED_MAP}
        controls = {m["control"] for m in aisf_mappings.AISF_DERIVED_MAP}
        for cid, entry in aisf_mappings.RETIRED_AISF_IDS.items():
            self.assertNotIn(cid, ids)
            self.assertNotIn(entry["control"], controls, msg=cid)
        self.assertNotIn(
            aisf_mappings.AISF_COVERAGE_CHECK_ID, aisf_mappings.RETIRED_AISF_IDS
        )

    def test_no_row_is_derived_from_a_retired_ids_sources(self):
        """Every former source present at every status, and no AISF row at all."""
        for status in ("Passed", "Failed", "N/A"):
            rows = aisf_mappings.derive_aisf_findings(
                [
                    _source_row(source, status)
                    for _, sources in self.RETIRED.values()
                    for source in sources
                ]
            )
            self.assertEqual(rows, [], msg=status)

    def test_a_retired_id_is_not_derived_beside_the_remaining_ones(self):
        every_source = [
            source
            for _, sources in (*self.RETIRED.values(), *self.REMAINING.values())
            for source in sources
        ]
        emitted = {
            r["Check_ID"]
            for r in aisf_mappings.derive_aisf_findings(
                [_source_row(source) for source in every_source]
            )
        }
        self.assertEqual(emitted, set(self.REMAINING))
        self.assertFalse(emitted & set(aisf_mappings.RETIRED_AISF_IDS))

    def test_the_next_free_id_skips_the_retired_ones(self):
        """Allocation reads both tables, so a retired number is never handed out."""
        taken = {m["check_id"] for m in aisf_mappings.AISF_DERIVED_MAP} | set(
            aisf_mappings.RETIRED_AISF_IDS
        )
        highest = max(int(cid.split("-")[1]) for cid in taken)
        self.assertEqual(f"AISF-{highest + 1:02d}", "AISF-09")
        self.assertFalse(
            {m["check_id"] for m in aisf_mappings.AISF_DERIVED_MAP}
            & set(aisf_mappings.RETIRED_AISF_IDS)
        )

    def test_the_remaining_three_keep_their_shape(self):
        self.assertEqual(
            {
                m["check_id"]: (m["control"], m["sources"])
                for m in aisf_mappings.AISF_DERIVED_MAP
            },
            self.REMAINING,
        )


class TestSectionRendering(unittest.TestCase):
    """Mirrors tests/test_report_template_owasp.py for the derived standard."""

    def _kwargs(self):
        slugs = [
            "bedrock",
            "sagemaker",
            "agentcore",
            "agent-registry",
            "agentic",
            "responsible-ai-grc",
        ] + [s["slug"] for s in report_template.COMPLIANCE_STANDARDS]
        return {
            "all_findings": [],
            "service_findings": {slug: [] for slug in slugs},
            "service_stats": {
                slug: {"passed": 0, "failed": 0, "na": 0} for slug in slugs
            },
            "mode": "single",
            "account_id": "111122223333",
            "timestamp": "January 1, 2026 00:00:00 UTC",
            "regions": ["us-east-1"],
        }

    def test_no_source_rows_renders_gaps_without_manufacturing_canonical_tasks(self):
        html = report_template.generate_html_report(**self._kwargs())
        self.assertIn('id="aisf"', html)
        self.assertIn("AWS AI Security Framework", html)
        self.assertEqual(_checks_from_html(html), [])
        self.assertTrue(_register_from_html(html)["gaps"])
        self.assertNotIn("218 canonical", html)
        self.assertNotIn("Manual assessment required", html)

    def test_legacy_derived_rows_do_not_manufacture_native_check_results(self):
        kwargs = self._kwargs()
        rows = aisf_mappings.derive_aisf_findings([_source_row("BR-20", "Failed")])
        aisf_rows = [r for r in rows if r["_service"] == "aisf"]
        self.assertTrue(aisf_rows)
        kwargs["all_findings"] = aisf_rows
        kwargs["service_findings"]["aisf"] = aisf_rows
        kwargs["service_stats"]["aisf"] = {
            "passed": 0,
            "failed": len(aisf_rows),
            "na": 0,
        }
        html = report_template.generate_html_report(**kwargs)
        self.assertIn('class="nav-section compliance-nav"', html)
        self.assertIn('value="aisf"', html)
        self.assertIn('id="aisf"', html)
        for element in ("searchInput", "statusFilter", "aisf-json", "aisf-csv"):
            self.assertIn(f'id="{element}"', html)
        self.assertEqual(_checks_from_html(html), [])

    def test_derived_rows_do_not_inflate_open_action_items(self):
        """AISF rows are contextual, like OWASP: they restate other verdicts."""
        kwargs = self._kwargs()
        direct = _source_row("BR-20", "Failed")
        direct["_service"] = "bedrock"
        derived = [
            r
            for r in aisf_mappings.derive_aisf_findings(
                [_source_row("BR-20", "Failed")]
            )
            if r["Check_ID"] == "AISF-05"
        ]
        self.assertEqual(len(derived), 1)
        kwargs["all_findings"] = [direct, *derived]
        kwargs["service_findings"]["bedrock"] = [direct]
        kwargs["service_findings"]["aisf"] = derived
        kwargs["service_stats"]["bedrock"] = {"passed": 0, "failed": 1, "na": 0}
        kwargs["service_stats"]["aisf"] = {"passed": 0, "failed": 1, "na": 0}

        html = report_template.generate_html_report(**kwargs)

        self.assertIn(
            '<div class="metric danger"><div class="metric-label">Open Action Items</div>'
            '<div class="metric-value">1</div>',
            html,
        )


class TestDerivedRowShape(unittest.TestCase):
    def test_rows_carry_exactly_the_keys_the_report_layer_reads(self):
        rows = aisf_mappings.derive_aisf_findings(
            [_source_row("BR-20"), _source_row("SM-09")]
        )
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(set(row), DERIVED_ROW_KEYS, msg=row["Check_ID"])
            self.assertEqual(row["_service"], "aisf")

    def test_details_name_the_aisf_control_and_every_source_check(self):
        rows = _derived_by_id(
            aisf_mappings.derive_aisf_findings(
                [
                    _source_row("SM-09"),
                    _source_row("SM-01"),
                    _source_row("SM-03"),
                ]
            )
        )
        details = rows["AISF-08"]["Finding_Details"]
        self.assertIn("AIR-SGM-TRN-05", details)
        for source in ("SM-09", "SM-01", "SM-03"):
            self.assertIn(source, details)

    def test_finding_name_identifies_the_control_not_the_incumbent(self):
        rows = _derived_by_id(
            aisf_mappings.derive_aisf_findings([_source_row("BR-20")])
        )
        self.assertIn("AIR-BDR-KB-03", rows["AISF-05"]["Finding"])
        self.assertNotIn("incumbent", rows["AISF-05"]["Finding"])

    def test_severity_comes_from_the_control_not_the_source_row(self):
        """BR-20's own severity is irrelevant: AISF-05 carries AISF's risk band."""
        expected = next(
            m["severity"]
            for m in aisf_mappings.AISF_DERIVED_MAP
            if m["check_id"] == "AISF-05"
        )
        rows = _derived_by_id(
            aisf_mappings.derive_aisf_findings(
                [_source_row("BR-20", "Failed") | {"Severity": "Low"}]
            )
        )
        self.assertEqual(rows["AISF-05"]["Severity"], expected)

    def test_no_emitted_severity_is_outside_the_schema_enum(self):
        """Asserted on emitted rows, so a bug in the collapse is caught at output."""
        self.assertNotIn("Critical", ALLOWED_SEVERITIES)
        seen = set()
        for status in ("Passed", "Failed", "N/A"):
            rows = _all_mappings_derived(status)
            self.assertEqual(len(rows), len(aisf_mappings.AISF_DERIVED_MAP), msg=status)
            for row in rows:
                self.assertIn(
                    row["Severity"],
                    ALLOWED_SEVERITIES,
                    msg=f"{row['Check_ID']} at {status}",
                )
                seen.add(row["Severity"])
        # Three distinct bands come out of these inputs, so a derivation that
        # emitted one constant value could not have produced this set.
        self.assertGreaterEqual(len(seen), 3, msg=sorted(seen))

    def test_baked_severity_is_the_collapse_of_the_declared_risk(self):
        for mapping in aisf_mappings.AISF_DERIVED_MAP:
            self.assertIn(
                mapping["risk"],
                aisf_mappings.AISF_RISK_TO_SEVERITY,
                msg=mapping["check_id"],
            )
            self.assertEqual(
                mapping["severity"],
                aisf_mappings.AISF_RISK_TO_SEVERITY[mapping["risk"]],
                msg=mapping["check_id"],
            )

    def test_a_malformed_source_row_drops_only_itself(self):
        rows = aisf_mappings.derive_aisf_findings(
            [None, _source_row("BR-20", "Failed"), 42]
        )
        self.assertIn("AISF-05", _derived_by_id(rows))


class TestSeverityCollapseDisclosure(unittest.TestCase):
    """A risk band renamed by the collapse is disclosed in every row it produces.

    Methodology section 6 keeps four severity levels and accepts, as the cost of
    that, "a genuinely critical Responsible AI GRC risk is reported as High". The
    person reading a finding reads the finding and not the methodology, so the
    row states the pre-collapse band. These tests hold that on emitted rows: a
    disclosure that lives only in the constant has not reached anyone.
    """

    # Pinned deliberately. The three critical controls (AISF-01, -03, -04) were
    # retired, so no shipped mapping is in a renamed band. A control added in one
    # also changes the sentence in docs/SECURITY_CHECKS_AISF.md that says so, so
    # the addition should fail here until that sentence is updated.
    CRITICAL_IDS = set()

    # The disclosure path is still shipped code, so it is exercised through a
    # critical mapping built here and added beside the real ones for each test.
    # Its source id is one no producer emits, so it cannot join a real leg.
    SYNTHETIC = {
        "check_id": "AISF-98",
        "control": "AIR-TEST-CRIT-01",
        "sources": ["ZZ-98"],
        "finding": "AISF AIR-TEST-CRIT-01: Synthetic Critical Control",
        "risk": "critical",
        "severity": "High",
        "resolution": "Synthetic resolution.",
        "reference": "https://docs.aws.amazon.com/",
    }

    def setUp(self):
        patcher = patch.object(
            aisf_mappings,
            "AISF_DERIVED_MAP",
            [*aisf_mappings.AISF_DERIVED_MAP, self.SYNTHETIC],
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _critical(self):
        return [m for m in aisf_mappings.AISF_DERIVED_MAP if m["risk"] == "critical"]

    def test_no_shipped_control_is_in_a_renamed_band(self):
        with patch.object(
            aisf_mappings,
            "AISF_DERIVED_MAP",
            [m for m in aisf_mappings.AISF_DERIVED_MAP if m is not self.SYNTHETIC],
        ):
            self.assertEqual(
                {m["check_id"] for m in self._critical()}, self.CRITICAL_IDS
            )

    def test_every_critical_row_names_its_pre_collapse_risk(self):
        note = aisf_mappings.SEVERITY_COLLAPSE_NOTE["critical"]
        self.assertEqual(self._critical(), [self.SYNTHETIC])
        for status, expected_severity in (
            ("Passed", "Informational"),
            ("Failed", "High"),
            ("N/A", "Informational"),
        ):
            rows = _derived_by_id(_all_mappings_derived(status))
            for mapping in self._critical():
                row = rows[mapping["check_id"]]
                label = f"{mapping['check_id']} at {status}"
                self.assertEqual(row["Severity"], expected_severity, msg=label)
                self.assertIn(note, row["Finding_Details"], msg=label)
                self.assertIn("critical", row["Finding_Details"], msg=label)

    def test_a_critical_mapping_bakes_the_collapse_of_its_risk(self):
        # test_baked_severity_is_the_collapse_of_the_declared_risk reads shipped
        # mappings only, and none is critical since the retirement, so the
        # critical row of the collapse table is held here instead.
        self.assertEqual(self._critical(), [self.SYNTHETIC])
        collapsed = aisf_mappings.AISF_RISK_TO_SEVERITY["critical"]
        self.assertIn(collapsed, ALLOWED_SEVERITIES)
        for mapping in self._critical():
            self.assertEqual(mapping["severity"], collapsed, msg=mapping["check_id"])

    def test_an_na_row_says_which_severity_it_is_carrying(self):
        """Otherwise "reported as High" reads as a claim about an Informational row."""
        rows = _derived_by_id(_all_mappings_derived("N/A"))
        self.assertTrue(self._critical())
        for mapping in self._critical():
            details = rows[mapping["check_id"]]["Finding_Details"]
            self.assertIn("carries Informational", details, msg=mapping["check_id"])

    def test_a_band_that_survives_the_collapse_carries_no_disclosure(self):
        """Negative control: the note is attached by band, not to every row."""
        rows = _derived_by_id(_all_mappings_derived("Passed"))
        uncollapsed = [
            m
            for m in aisf_mappings.AISF_DERIVED_MAP
            if m["risk"] not in aisf_mappings.SEVERITY_COLLAPSE_NOTE
        ]
        self.assertTrue(uncollapsed, "no uncollapsed mapping left to discriminate on")
        for mapping in uncollapsed:
            self.assertNotIn(
                "AISF risk:",
                rows[mapping["check_id"]]["Finding_Details"],
                msg=mapping["check_id"],
            )

    def test_every_band_the_collapse_renames_has_a_note(self):
        renamed = {
            risk
            for risk, severity in aisf_mappings.AISF_RISK_TO_SEVERITY.items()
            if severity.lower() != risk
        }
        self.assertEqual(renamed, {"critical"})
        self.assertTrue(
            renamed.issubset(set(aisf_mappings.SEVERITY_COLLAPSE_NOTE)),
            msg=sorted(renamed),
        )

    def test_the_note_cites_a_methodology_section_that_exists(self):
        note = aisf_mappings.SEVERITY_COLLAPSE_NOTE["critical"]
        self.assertIn(
            "SECURITY_CHECKS_RESPONSIBLE_AI_GRC_SEVERITY_METHODOLOGY.md", note
        )
        self.assertIn("section 6", note)
        with open(METHODOLOGY_DOC) as handle:
            methodology = handle.read()
        self.assertRegex(methodology, r"(?m)^#+\s*6\.\s")
        self.assertIn("keep four levels", methodology)


class TestBatchGuardrailLeg(unittest.TestCase):
    """AISF-07 needs SM-42 beside SM-18.

    SM-18 reads the transform jobs that exist. SM-42 reads the preventive
    guardrail on CreateModel and CreateTransformJob, which the control's
    resolution asks for across both actions. A job-only verdict published
    Passed for an account whose guardrail was absent.
    """

    def _ai07(self, statuses):
        rows = aisf_mappings.derive_aisf_findings(
            [_source_row(cid, status) for cid, status in statuses.items()]
        )
        return _derived_by_id(rows)["AISF-07"]

    def test_a_failed_guardrail_fails_the_control(self):
        row = self._ai07({"SM-18": "Passed", "SM-42": "Failed"})
        self.assertEqual(row["Status"], "Failed")

    def test_jobs_alone_do_not_publish_a_pass(self):
        row = self._ai07({"SM-18": "Passed"})
        self.assertEqual(row["Status"], "N/A")
        self.assertIn("SM-42", row["Finding_Details"])

    def test_both_legs_passed_is_passed(self):
        row = self._ai07({"SM-18": "Passed", "SM-42": "Passed"})
        self.assertEqual(row["Status"], "N/A")


class TestMultiLegAggregation(unittest.TestCase):
    """AISF-08, the three-leg mapping: SM-09, SM-01 and SM-03."""

    LEGS = ("SM-09", "SM-01", "SM-03")

    def _ai08(self, statuses):
        rows = aisf_mappings.derive_aisf_findings(
            [_source_row(cid, status) for cid, status in statuses.items()]
        )
        return _derived_by_id(rows).get("AISF-08")

    def test_every_leg_passed_is_passed(self):
        row = self._ai08({cid: "Passed" for cid in self.LEGS})
        self.assertEqual(row["Status"], "N/A")

    def test_any_leg_failed_is_failed(self):
        for failing in self.LEGS:
            statuses = {cid: "Passed" for cid in self.LEGS}
            statuses[failing] = "Failed"
            row = self._ai08(statuses)
            self.assertEqual(row["Status"], "Failed", msg=failing)

    def test_a_non_verdict_leg_is_not_a_pass(self):
        statuses = {cid: "Passed" for cid in self.LEGS}
        statuses["SM-01"] = "N/A"
        row = self._ai08(statuses)
        self.assertEqual(row["Status"], "N/A")

    def test_a_missing_leg_is_reported_not_dropped(self):
        row = self._ai08({"SM-09": "Passed", "SM-03": "Passed"})
        self.assertIsNotNone(row, "AISF-08 was dropped instead of reported as N/A")
        self.assertEqual(row["Status"], "N/A")
        self.assertIn("SM-01", row["Finding_Details"])
        self.assertIn("SM-09", row["Finding_Details"])

    def test_a_missing_leg_does_not_publish_a_pass(self):
        row = self._ai08({"SM-09": "Passed"})
        self.assertNotEqual(row["Status"], "Passed")


class TestFailedSourceBeatsMissingSource(unittest.TestCase):
    """A present leg that failed decides the control even when another is absent."""

    def test_a_global_failure_with_missing_regional_legs_is_failed(self):
        """A Global failure stays visible without borrowing regional evidence."""
        rows = aisf_mappings.derive_aisf_findings(
            [
                _source_row("SM-09", "Failed", region="Global"),
                _source_row("BR-20", "Passed", region="us-west-2"),
            ]
        )
        row = next(
            r for r in rows if r["Check_ID"] == "AISF-08" and r["Region"] == "Global"
        )
        self.assertEqual(row["Status"], "Failed")
        self.assertEqual(row["Severity"], "Medium")
        self.assertIn("SM-01, SM-03", row["Finding_Details"])
        self.assertIn("SM-09 (Failed)", row["Finding_Details"])

    def test_a_regional_failure_with_a_missing_leg_is_failed(self):
        rows = aisf_mappings.derive_aisf_findings(
            [_source_row("SM-09", "Failed"), _source_row("SM-03", "Passed")]
        )
        row = _derived_by_id(rows)["AISF-08"]
        self.assertEqual(row["Status"], "Failed")
        self.assertIn("SM-01", row["Finding_Details"])

    def test_no_failure_with_a_missing_leg_stays_na(self):
        rows = aisf_mappings.derive_aisf_findings(
            [_source_row("SM-09", "Passed"), _source_row("SM-03", "N/A")]
        )
        row = _derived_by_id(rows)["AISF-08"]
        self.assertEqual(row["Status"], "N/A")
        self.assertEqual(row["Severity"], "Informational")


class TestDeselectedServices(unittest.TestCase):
    """A deselected service is "Not selected", never an AISF-00 coverage gap."""

    def test_sagemaker_off_reports_no_coverage_gap_for_aisf_07_and_08(self):
        rows = aisf_mappings.derive_aisf_findings(
            [_source_row("BR-20", "Passed")], {"sagemaker": False}
        )
        by_id = _derived_by_id(rows)
        self.assertEqual(set(by_id), {"AISF-05"})
        self.assertEqual(by_id["AISF-05"]["Status"], "N/A")

    def test_bedrock_off_reports_no_coverage_gap_for_aisf_05(self):
        rows = aisf_mappings.derive_aisf_findings(
            [
                _source_row(cid, "Passed")
                for cid in ("SM-18", "SM-42", "SM-09", "SM-01", "SM-03")
            ],
            {"bedrock": False},
        )
        self.assertEqual(set(_derived_by_id(rows)), {"AISF-07", "AISF-08"})

    def test_a_selected_service_missing_its_sources_keeps_aisf_00(self):
        rows = aisf_mappings.derive_aisf_findings(
            [_source_row("BR-20", "Passed")],
            {"bedrock": True, "sagemaker": True},
        )
        coverage = _derived_by_id(rows)[aisf_mappings.AISF_COVERAGE_CHECK_ID]
        self.assertIn("AISF-07", coverage["Finding_Details"])
        self.assertIn("AISF-08", coverage["Finding_Details"])
        self.assertNotIn("AISF-05", coverage["Finding_Details"])

    def test_the_coverage_row_links_no_unrelated_document(self):
        rows = aisf_mappings.derive_aisf_findings([_source_row("BR-20", "Passed")])
        coverage = _derived_by_id(rows)[aisf_mappings.AISF_COVERAGE_CHECK_ID]
        self.assertEqual(coverage["Reference"], "")
        self.assertNotEqual(
            _entry("aisf")["reference_url"], report_template.GENAI_LENS_URL
        )


_SECURITY_DIR = os.path.join(
    REPO_ROOT, "aiml-security-assessment", "functions", "security"
)

# Every module-level dict literal that allocates AG- ids, and the service whose
# Lambda emits those rows. Read with ast so no producer module is imported.
AGENTIC_ID_SOURCES = (
    ("bedrock_assessments", "AGENTIC_BEDROCK_CHECK_MAPPINGS", "bedrock"),
    ("agentcore_assessments", "AGENTIC_AGENTCORE_CHECK_MAPPINGS", "agentcore"),
    ("agentcore_assessments", "NATIVE_AGENTIC_AGENTCORE_CHECK_NAMES", "agentcore"),
    (
        "agent_registry_assessments",
        "AGENTIC_AGENT_REGISTRY_CHECK_MAPPINGS",
        "agent-registry",
    ),
)


def _emitted_agentic_ids():
    """AG- id -> the set of services whose Lambda can emit it."""
    emitters = {}
    for package, name, service in AGENTIC_ID_SOURCES:
        with open(
            os.path.join(_SECURITY_DIR, package, "app.py"), encoding="utf-8"
        ) as f:
            tree = ast.parse(f.read())
        node = next(
            n.value
            for n in tree.body
            if isinstance(n, ast.Assign)
            and any(getattr(t, "id", None) == name for t in n.targets)
        )
        literal = ast.literal_eval(node)
        ids = (
            {v["check_id"] for v in literal.values()}
            if all(isinstance(v, dict) for v in literal.values())
            else set(literal)
        )
        for check_id in ids:
            emitters.setdefault(check_id, set()).add(service)
    return emitters


def _agentic_literals(package):
    """Every `AG-NN` string constant in a producer package's non-test modules.

    Wider than `_emitted_agentic_ids()`: it also sees an id a producer names
    outside the three mapping dictionaries.
    """
    ids = set()
    package_dir = os.path.join(_SECURITY_DIR, package)
    for name in sorted(os.listdir(package_dir)):
        if not name.endswith(".py") or name.startswith("test"):
            continue
        with open(os.path.join(package_dir, name), encoding="utf-8") as f:
            tree = ast.parse(f.read())
        ids.update(
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and re.fullmatch(r"AG-\d{2}", node.value)
        )
    return ids


class TestAgenticSourceAttribution(unittest.TestCase):
    """AG- rows come from three Lambdas, so the AG prefix names no one service."""

    BEDROCK_AG_CONTROL = {
        "check_id": "AISF-99",
        "control": "AIR-TEST-01",
        "sources": ["AG-07"],
        "finding": "AISF AIR-TEST-01: synthetic control on a Bedrock-derived AG row",
        "risk": "high",
        "severity": "High",
        "resolution": "Synthetic.",
        "reference": "",
    }

    def _derive(self, rows, selection):
        with patch.object(
            aisf_mappings,
            "AISF_DERIVED_MAP",
            aisf_mappings.AISF_DERIVED_MAP + [self.BEDROCK_AG_CONTROL],
        ):
            return _derived_by_id(aisf_mappings.derive_aisf_findings(rows, selection))

    def test_every_emitted_ag_id_is_attributed_to_its_emitting_service(self):
        emitted = _emitted_agentic_ids()
        self.assertTrue(emitted)
        for check_id, services in emitted.items():
            self.assertEqual(len(services), 1, f"{check_id} has two emitters")
        self.assertEqual(
            aisf_mappings.AGENTIC_SOURCE_SERVICE,
            {cid: next(iter(s)) for cid, s in emitted.items()},
        )

    def test_every_ag_id_a_producer_names_is_attributed_to_that_producer(self):
        """An AG-40 added to any producer fails here before it reaches a report."""
        for package, service in (
            ("bedrock_assessments", "bedrock"),
            ("agentcore_assessments", "agentcore"),
            ("agent_registry_assessments", "agent-registry"),
        ):
            ids = _agentic_literals(package)
            self.assertTrue(ids, package)
            for check_id in sorted(ids):
                self.assertEqual(
                    aisf_mappings.AGENTIC_SOURCE_SERVICE.get(check_id),
                    service,
                    f"{package} names {check_id}",
                )

    def test_an_unattributed_ag_id_is_logged_and_never_counted_as_deselected(self):
        """An unknown source keeps its control in the report, under a warning.

        Treating it as deselected would drop the control with no row and no
        AISF-00 mention, which is the silent outcome the selection rule exists
        to prevent.
        """
        with self.assertLogs(aisf_mappings.logger, "WARNING") as logs:
            self.assertEqual(
                aisf_mappings.source_service("AG-40"),
                aisf_mappings.UNATTRIBUTED_SERVICE,
            )
        self.assertIn("AG-40", logs.output[0])
        self.assertNotIn(
            aisf_mappings.UNATTRIBUTED_SERVICE, report_template.CORE_SERVICE_LABELS
        )

        control = {**self.BEDROCK_AG_CONTROL, "sources": ["AG-40"]}
        nothing_selected = {s: False for s in report_template.CORE_SERVICE_LABELS}
        with (
            patch.object(aisf_mappings, "AISF_DERIVED_MAP", [control]),
            self.assertLogs(aisf_mappings.logger, "WARNING"),
        ):
            self.assertEqual(aisf_mappings.omitted_aisf_controls(nothing_selected), [])
            rows = _derived_by_id(
                aisf_mappings.derive_aisf_findings(
                    [_source_row("AG-40", "Failed")], nothing_selected
                )
            )
        self.assertEqual(rows["AISF-99"]["Status"], "Failed")

    def test_every_mapped_source_resolves_to_a_service(self):
        for mapping in aisf_mappings.AISF_DERIVED_MAP:
            for source in mapping["sources"]:
                self.assertIn(
                    aisf_mappings.source_service(source),
                    report_template.CORE_SERVICE_LABELS,
                    source,
                )

    def test_a_bedrock_derived_ag_source_is_kept_when_only_agentcore_is_off(self):
        rows = self._derive(
            [_source_row("AG-07", "Failed")], {"bedrock": True, "agentcore": False}
        )
        self.assertEqual(rows["AISF-99"]["Status"], "Failed")

    def test_a_bedrock_derived_ag_source_is_dropped_when_bedrock_is_off(self):
        rows = self._derive(
            [_source_row(cid) for cid in ("SM-18", "SM-42", "SM-09", "SM-01", "SM-03")],
            {"bedrock": False, "agentcore": True},
        )
        self.assertNotIn("AISF-99", rows)
        self.assertNotIn(aisf_mappings.AISF_COVERAGE_CHECK_ID, rows)


class TestScopeTextNamesOmittedControls(unittest.TestCase):
    """Deselected legacy aliases never remove canonical inventory or scope."""

    def _html(self, selection):
        kwargs = TestSectionRendering._kwargs(self)
        rows = aisf_mappings.derive_aisf_findings(
            [_source_row("BR-20", "Failed")], selection
        )
        kwargs["all_findings"] = rows
        kwargs["service_findings"]["aisf"] = rows
        kwargs["service_stats"]["aisf"] = {"passed": 0, "failed": len(rows), "na": 0}
        kwargs["service_selection"] = selection
        kwargs["compliance_scope"] = {"aisf": aisf_mappings.aisf_scope(selection)}
        return report_template.generate_html_report(**kwargs)

    def test_omitted_controls_name_their_deselected_service(self):
        self.assertEqual(aisf_mappings.omitted_aisf_controls({}), [])
        self.assertEqual(
            aisf_mappings.omitted_aisf_controls({"sagemaker": False}),
            [("AISF-07", ["sagemaker"]), ("AISF-08", ["sagemaker"])],
        )

    def test_sagemaker_off_preserves_scope_without_manual_control_rows(self):
        html = self._html({"sagemaker": False})
        self.assertFalse(
            _register_from_html(html)["scope"]["source_selection"]["sagemaker"]
        )
        self.assertEqual(_checks_from_html(html), [])

    def test_all_services_selected_omits_nothing(self):
        html = self._html({})
        self.assertNotIn("are omitted because", html)
        self.assertNotIn("is omitted because", html)
        self.assertIn(_entry("aisf")["scope_text"], html)

    def test_bedrock_off_preserves_scope_without_manual_control_rows(self):
        html = report_template.generate_html_report(
            **{
                **self._kwargs_with_rows(),
                "service_selection": {"bedrock": False},
                "compliance_scope": {
                    "aisf": aisf_mappings.aisf_scope({"bedrock": False})
                },
            }
        )
        self.assertFalse(
            _register_from_html(html)["scope"]["source_selection"]["bedrock"]
        )
        self.assertEqual(_checks_from_html(html), [])

    def _kwargs_with_rows(self):
        kwargs = TestSectionRendering._kwargs(self)
        rows = aisf_mappings.derive_aisf_findings(
            [_source_row(cid) for cid in ("SM-18", "SM-42", "SM-09", "SM-01", "SM-03")],
            {"bedrock": False},
        )
        kwargs["all_findings"] = rows
        kwargs["service_findings"]["aisf"] = rows
        kwargs["service_stats"]["aisf"] = {"passed": len(rows), "failed": 0, "na": 0}
        return kwargs

    def test_single_account_report_preserves_selected_native_results_only(self):
        html = single_account.generate_html_report(
            {
                "account_id": "111122223333",
                "bedrock": {
                    "bedrock_security_report_exec_us-east-1": [
                        _source_row("BR-20", "Passed")
                    ]
                },
            },
            service_selection={"sagemaker": "false"},
        )
        checks = _checks_from_html(html)
        self.assertEqual(
            [(c["source_check_id"], c["status"]) for c in checks], [("BR-20", "Passed")]
        )
        self.assertFalse(
            _register_from_html(html)["scope"]["source_selection"]["sagemaker"]
        )


FOURTH_DERIVED_CONTROL = {
    "check_id": "AISF-98",
    "control": "AIR-TEST-02",
    "sources": ["AC-01"],
    "finding": "AISF AIR-TEST-02: synthetic fourth derived control",
    "risk": "high",
    "severity": "High",
    "resolution": "Synthetic.",
    "reference": "",
}


def _with_fourth_derived_control():
    return patch.object(
        aisf_mappings,
        "AISF_DERIVED_MAP",
        [*aisf_mappings.AISF_DERIVED_MAP, FOURTH_DERIVED_CONTROL],
    )


def _aisf_tag_sets():
    """(covered, partial) AISF control ids, read from the producers' tag maps."""
    covered, partial = set(), set()
    for package in sorted(os.listdir(_SECURITY_DIR)):
        package_dir = os.path.join(_SECURITY_DIR, package)
        if not os.path.isdir(package_dir):
            continue
        for name in sorted(os.listdir(package_dir)):
            if not fnmatch.fnmatch(name, "aisf_compliance_*.py"):
                continue
            with open(os.path.join(package_dir, name), encoding="utf-8") as f:
                tree = ast.parse(f.read())
            node = next(
                n.value
                for n in tree.body
                if isinstance(n, ast.Assign)
                and any(
                    getattr(t, "id", None) == "AISF_COMPLIANCE_MAP" for t in n.targets
                )
            )
            for tags in ast.literal_eval(node).values():
                for tag in tags.split("|"):
                    control, qualifier = re.fullmatch(
                        r"AISF (\S+)(?: \((.+)\))?", tag.strip()
                    ).groups()
                    (partial if qualifier == "partial" else covered).add(control)
    return covered, partial


def _read(*parts):
    with open(os.path.join(REPO_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


class TestScopeTextCountsComeFromTheData(unittest.TestCase):
    """Canonical inventory is independent of legacy aliases and producer tags."""

    def _html(self, selection):
        rows = aisf_mappings.derive_aisf_findings(
            [_source_row(cid) for cid in ("BR-20", "AC-01")], selection
        )
        kwargs = TestSectionRendering._kwargs(self)
        kwargs["all_findings"] = rows
        kwargs["service_findings"]["aisf"] = rows
        kwargs["service_stats"]["aisf"] = {"passed": len(rows), "failed": 0, "na": 0}
        kwargs["service_selection"] = selection
        kwargs["compliance_scope"] = {"aisf": aisf_mappings.aisf_scope(selection)}
        return report_template.generate_html_report(**kwargs)

    def test_an_unknown_legacy_alias_cannot_manufacture_native_check_results(self):
        with _with_fourth_derived_control():
            html = self._html({})
        self.assertEqual(_checks_from_html(html), [])
        self.assertNotIn("AIR-TEST-02", json.dumps(_register_from_html(html)))

    def test_unknown_legacy_alias_cannot_change_actual_source_selection(self):
        with _with_fourth_derived_control():
            html = self._html({"sagemaker": False})
        self.assertEqual(_checks_from_html(html), [])
        self.assertFalse(
            _register_from_html(html)["scope"]["source_selection"]["sagemaker"]
        )

    def test_single_account_keeps_native_result_with_an_unknown_legacy_alias(self):
        with _with_fourth_derived_control():
            html = single_account.generate_html_report(
                {
                    "account_id": "111122223333",
                    "bedrock": {
                        "bedrock_security_report_exec_us-east-1": [
                            _source_row("BR-20", "Passed")
                        ]
                    },
                },
                service_selection={"sagemaker": "false"},
            )
        checks = _checks_from_html(html)
        self.assertEqual(
            [(c["source_check_id"], c["status"]) for c in checks], [("BR-20", "Passed")]
        )
        self.assertNotIn(
            "AIR-TEST-02",
            {cid for check in checks for cid in check["aisf_control_ids"]},
        )

    def test_tagged_controls_are_reviewed_as_partial_in_the_mapping_ledger(self):
        covered, partial = _aisf_tag_sets()
        ledger, _ = aisf_results.load_mapping()
        mapped = {key for key, mapping in ledger.items() if mapping["source_checks"]}
        self.assertTrue((covered | partial).issubset(mapped))
        self.assertEqual({ledger[key]["coverage"] for key in mapped}, {"partial"})
        self.assertEqual(len(ledger), 218)
        self.assertFalse(ledger["AIR-ACR-MEM-07"]["source_checks"])
        self.assertFalse(ledger["AIR-FND-GOV-12"]["source_checks"])

    def test_the_aisf_catalog_document_states_the_same_figures(self):
        doc = re.sub(r"\s+", " ", _read("docs", "SECURITY_CHECKS_AISF.md"))
        self.assertIn("218", doc)
        self.assertIn("5df3295024713ac3ce88130c549bbc4fb2cebd53", doc)
        self.assertIn("Machine-classified controls | 104", doc)
        self.assertIn("Non-machine controls | 114", doc)
        self.assertIn("Native source checks reviewed | 233", doc)
        self.assertIn("Derived presentation IDs reviewed | 44", doc)
        self.assertNotIn("assert the whole control", doc)

    def test_the_changelog_states_the_same_figures(self):
        """Only the Unreleased entry is held to today's figures.

        Released entries are never rewritten, so once this one ships a later
        catalog change must not fail against it.
        """
        unreleased = _read("CHANGELOG.md").split("\n## Unreleased", 1)[1]
        unreleased = re.split(r"\n## \d", unreleased, maxsplit=1)[0]
        changelog = re.sub(r"\s+", " ", unreleased)
        self.assertIn("218", changelog)
        self.assertNotIn("64 are asserted in full", changelog)

    def test_the_framework_check_total_matches_the_check_catalog(self):
        total = int(
            re.search(
                r"reference for all (\d+) security checks",
                _read("docs", "SECURITY_CHECKS.md"),
            ).group(1)
        )
        reference = re.sub(r"\s+", " ", _read("docs", "SECURITY_CHECKS_AISF.md"))
        self.assertIn(str(total), reference)
        self.assertNotIn(str(total), _entry("aisf")["scope_text"])


class TestSeveralFindingsPerSourceCheck(unittest.TestCase):
    """One incumbent check emits one finding per resource, so a leg holds many.

    Measured against a real account: 16 findings for `AG-24` and 11 across the
    `SM-09`/`SM-01`/`SM-03` leg in a single account and region. Every case here
    puts the `Failed` row FIRST, because a fixture in `Passed`-then-`Failed`
    order cannot tell the aggregation from a collapse that keeps the last row.
    """

    def _aisf05(self, statuses):
        rows = aisf_mappings.derive_aisf_findings(
            [_source_row("BR-20", status) for status in statuses]
        )
        return _derived_by_id(rows)["AISF-05"]

    def test_a_failed_finding_before_a_passed_one_is_failed(self):
        self.assertEqual(self._aisf05(["Failed", "Passed"])["Status"], "Failed")

    def test_a_failed_finding_after_a_passed_one_is_also_failed(self):
        """Order-independent, so neither direction of collapse can pass."""
        self.assertEqual(self._aisf05(["Passed", "Failed"])["Status"], "Failed")

    def test_a_trailing_summary_pass_after_failures_and_an_na_is_failed(self):
        """A long `Failed` run, an unassessable row, then a trailing `Passed`.

        The shape that defeats a consumer keeping one status per check id: the
        aggregate has to read the whole run and not the last row. An `N/A`
        between them must not end the run either. What shape a given account
        actually produces is not claimed here: it has already changed once.
        """
        row = self._aisf05(["Failed"] * 9 + ["N/A", "Passed"])
        self.assertEqual(row["Status"], "Failed")
        self.assertEqual(row["Severity"], "High")

    def test_every_source_passed_still_leaves_required_proof_missing(self):
        self.assertEqual(self._aisf05(["Passed"] * 3)["Status"], "N/A")

    def test_one_leg_of_a_multi_leg_control_carries_several_findings(self):
        rows = aisf_mappings.derive_aisf_findings(
            [
                _source_row("SM-09", "Failed"),
                _source_row("SM-09", "Passed"),
                _source_row("SM-01", "Passed"),
                _source_row("SM-03", "Passed"),
            ]
        )
        self.assertEqual(_derived_by_id(rows)["AISF-08"]["Status"], "Failed")

    def test_the_details_count_the_findings_behind_the_verdict(self):
        details = self._aisf05(["Failed", "Passed", "Failed"])["Finding_Details"]
        self.assertIn("BR-20 (3 findings: 2 Failed, 1 Passed)", details)
        # A list held per check id reaches this field as a repr if it is
        # formatted straight into the sentence, which ships to the reader.
        self.assertNotIn("[", details)

    def test_a_single_finding_still_reads_as_one_verdict(self):
        details = self._aisf05(["Failed"])["Finding_Details"]
        self.assertIn("BR-20 (Failed)", details)
        self.assertNotIn("1 findings", details)

    def test_the_breakdown_does_not_depend_on_the_row_order(self):
        first = self._aisf05(["Failed", "N/A", "Passed"])["Finding_Details"]
        second = self._aisf05(["Passed", "Failed", "N/A"])["Finding_Details"]
        self.assertEqual(first, second)
        self.assertIn("BR-20 (3 findings: 1 Failed, 1 Passed, 1 N/A)", first)


class TestNotApplicableSeverity(unittest.TestCase):
    def test_no_na_row_carries_a_scored_severity(self):
        # One AISF-relevant source present, so every other mapping is absent
        # and the coverage row plus a partial AISF-08 are produced.
        rows = aisf_mappings.derive_aisf_findings([_source_row("SM-09", "Passed")])
        na_rows = [r for r in rows if r["Status"] == "N/A"]
        self.assertTrue(na_rows)
        for row in na_rows:
            self.assertEqual(row["Severity"], "Informational", msg=row["Check_ID"])

    def test_the_coverage_row_is_emitted_only_when_a_mapping_is_absent(self):
        every_source = sorted(
            {cid for m in aisf_mappings.AISF_DERIVED_MAP for cid in m["sources"]}
        )
        full = aisf_mappings.derive_aisf_findings(
            [_source_row(cid, "Passed") for cid in every_source]
        )
        self.assertNotIn(aisf_mappings.AISF_COVERAGE_CHECK_ID, _derived_by_id(full))

        partial = aisf_mappings.derive_aisf_findings([_source_row("BR-20", "Passed")])
        coverage = _derived_by_id(partial)[aisf_mappings.AISF_COVERAGE_CHECK_ID]
        self.assertEqual(coverage["Status"], "N/A")
        self.assertEqual(coverage["Severity"], "Informational")
        self.assertIn("AISF-08", coverage["Finding_Details"])

    def test_no_rows_at_all_when_no_source_check_is_aisf_relevant(self):
        rows = aisf_mappings.derive_aisf_findings(
            [_source_row("BR-01"), _source_row("AR-08")]
        )
        self.assertEqual(rows, [])

    def test_each_join_key_is_derived_independently(self):
        rows = aisf_mappings.derive_aisf_findings(
            [
                _source_row("BR-20", "Passed", region="us-east-1"),
                _source_row("BR-20", "Failed", region="eu-west-1"),
            ]
        )
        by_region = {r["Region"]: r for r in rows if r["Check_ID"] == "AISF-05"}
        self.assertEqual(by_region["us-east-1"]["Status"], "N/A")
        self.assertEqual(by_region["eu-west-1"]["Status"], "Failed")

    def test_accounts_do_not_share_a_join_key(self):
        rows = aisf_mappings.derive_aisf_findings(
            [
                _source_row("BR-20", "Passed", account="111122223333"),
                _source_row("BR-20", "Failed", account="444455556666"),
            ]
        )
        by_account = {r["Account_ID"]: r for r in rows if r["Check_ID"] == "AISF-05"}
        self.assertEqual(by_account["111122223333"]["Status"], "N/A")
        self.assertEqual(by_account["444455556666"]["Status"], "Failed")


class TestGlobalSourceRows(unittest.TestCase):
    """Global evidence has its own scope and cannot complete regional proof."""

    def _by_key(self, rows, check_id):
        return {
            (r["Account_ID"], r["Region"]): r for r in rows if r["Check_ID"] == check_id
        }

    def test_a_global_failure_remains_visible_in_its_own_scope(self):
        rows = aisf_mappings.derive_aisf_findings(
            [
                _source_row("BR-20", "Failed", region="Global"),
                _source_row("BR-20", "Passed", region="us-east-1"),
            ]
        )
        by_key = self._by_key(rows, "AISF-05")
        self.assertEqual(by_key[("111122223333", "Global")]["Status"], "Failed")
        row = by_key[("111122223333", "us-east-1")]
        self.assertEqual(row["Status"], "N/A")
        self.assertIn("BR-20 (Passed)", row["Finding_Details"])
        self.assertNotIn("2 findings", row["Finding_Details"])

    def test_global_evidence_is_not_copied_into_regions(self):
        rows = aisf_mappings.derive_aisf_findings(
            [
                _source_row("BR-20", "Passed", region="us-east-1"),
                _source_row("BR-20", "Failed", region="Global"),
                _source_row("BR-20", "Passed", region="eu-west-1"),
            ]
        )
        by_key = self._by_key(rows, "AISF-05")
        self.assertEqual(by_key[("111122223333", "Global")]["Status"], "Failed")
        self.assertEqual(by_key[("111122223333", "us-east-1")]["Status"], "N/A")
        self.assertEqual(by_key[("111122223333", "eu-west-1")]["Status"], "N/A")

    def test_a_global_pass_leaves_a_regional_failure_failed(self):
        rows = aisf_mappings.derive_aisf_findings(
            [
                _source_row("BR-20", "Passed", region="Global"),
                _source_row("BR-20", "Failed", region="us-east-1"),
                _source_row("BR-20", "Passed", region="eu-west-1"),
            ]
        )
        by_key = self._by_key(rows, "AISF-05")
        self.assertEqual(by_key[("111122223333", "us-east-1")]["Status"], "Failed")
        self.assertEqual(by_key[("111122223333", "eu-west-1")]["Status"], "N/A")
        self.assertEqual(by_key[("111122223333", "Global")]["Status"], "N/A")

    def test_global_and_regional_multi_leg_evidence_stay_separate(self):
        rows = aisf_mappings.derive_aisf_findings(
            [
                _source_row("SM-09", "Failed", region="Global"),
                _source_row("SM-09", "Passed"),
                _source_row("SM-01", "Passed"),
                _source_row("SM-03", "Passed"),
            ]
        )
        by_key = self._by_key(rows, "AISF-08")
        self.assertEqual(by_key[("111122223333", "Global")]["Status"], "Failed")
        self.assertEqual(by_key[("111122223333", "us-east-1")]["Status"], "N/A")

    def test_global_key_is_preserved_beside_an_incomplete_regional_one(self):
        rows = aisf_mappings.derive_aisf_findings(
            [
                _source_row("SM-09", "Failed", region="Global"),
                _source_row("SM-01", "Passed"),
                _source_row("SM-03", "Passed"),
            ]
        )
        self.assertIn("Global", {r["Region"] for r in rows})
        row = self._by_key(rows, "AISF-08")[("111122223333", "us-east-1")]
        self.assertEqual(row["Status"], "N/A")
        self.assertIn("SM-09", row["Finding_Details"])

    def test_separate_global_keeps_the_global_key_beside_regional_ones(self):
        """A control with only Global sources keeps its own comparison key."""
        rows = aisf_mappings.derive_aisf_findings(
            [
                _source_row("BR-20", "Failed", region="Global"),
                _source_row("SM-18", "Passed"),
                _source_row("SM-42", "Passed"),
            ],
            separate_global=True,
        )
        keys = {(r["Region"], r["Check_ID"]): r for r in rows}
        self.assertEqual(keys[("Global", "AISF-05")]["Status"], "Failed")
        self.assertEqual(keys[("us-east-1", "AISF-07")]["Status"], "N/A")
        # Global sources keep their own scope. No Global AISF-00 calls
        # a regional-only AISF-07 mapping unassessed.
        self.assertNotIn(("us-east-1", "AISF-05"), keys)
        self.assertNotIn(("Global", "AISF-00"), keys)
        self.assertIn("AISF-08", keys[("us-east-1", "AISF-00")]["Finding_Details"])
        self.assertIn("AISF-05", keys[("us-east-1", "AISF-00")]["Finding_Details"])

    def test_separate_global_keeps_regional_and_global_verdicts_independent(self):
        rows = aisf_mappings.derive_aisf_findings(
            [
                _source_row("BR-20", "Failed", region="Global"),
                _source_row("BR-20", "Passed"),
            ],
            separate_global=True,
        )
        by_key = self._by_key(rows, "AISF-05")
        self.assertEqual(by_key[("111122223333", "us-east-1")]["Status"], "N/A")
        self.assertEqual(by_key[("111122223333", "Global")]["Status"], "Failed")

    def test_separate_global_only_global_rows_match_the_default(self):
        source = [_source_row("BR-20", "Failed", region="Global")]
        self.assertEqual(
            aisf_mappings.derive_aisf_findings(source, separate_global=True),
            aisf_mappings.derive_aisf_findings(source),
        )

    def test_an_account_with_only_global_rows_keeps_its_global_key(self):
        rows = aisf_mappings.derive_aisf_findings(
            [_source_row("BR-20", "Failed", region="Global")]
        )
        row = self._by_key(rows, "AISF-05")[("111122223333", "Global")]
        self.assertEqual(row["Status"], "Failed")
        self.assertNotIn("reported under Global", row["Finding_Details"])

    def test_a_global_row_does_not_cross_accounts(self):
        rows = aisf_mappings.derive_aisf_findings(
            [
                _source_row("BR-20", "Failed", region="Global", account="111122223333"),
                _source_row("BR-20", "Passed", account="111122223333"),
                _source_row("BR-20", "Passed", account="444455556666"),
            ]
        )
        by_key = self._by_key(rows, "AISF-05")
        self.assertEqual(by_key[("111122223333", "Global")]["Status"], "Failed")
        self.assertEqual(by_key[("111122223333", "us-east-1")]["Status"], "N/A")
        self.assertEqual(by_key[("444455556666", "us-east-1")]["Status"], "N/A")
        self.assertNotIn(
            "reported under Global",
            by_key[("444455556666", "us-east-1")]["Finding_Details"],
        )


def _listbucket_prefix_patterns():
    """The s3:prefix StringLike list on the report function's ListBucket grant."""

    class Loader(yaml.SafeLoader):
        pass

    def multi(loader, suffix, node):
        if isinstance(node, yaml.ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        return loader.construct_mapping(node)

    Loader.add_multi_constructor("!", multi)
    with open(SAM_TEMPLATE, encoding="utf-8") as handle:
        template = yaml.load(handle, Loader=Loader)
    policies = template["Resources"]["GenerateConsolidatedReportFunction"][
        "Properties"
    ]["Policies"]
    for policy in policies:
        for statement in policy.get("Statement", []):
            if statement.get("Sid") == "AssessmentReportInventory":
                return list(statement["Condition"]["StringLike"]["s3:prefix"])
    raise AssertionError("AssessmentReportInventory statement not found")


class TestDerivedStandardAddsNoS3Prefix(unittest.TestCase):
    """The regression test for the AccessDenied that fails the whole report."""

    def _requested_prefixes(self):
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Contents": []}]
        client = MagicMock()
        client.get_paginator.return_value = paginator
        with (
            patch.object(single_account, "boto3") as mock_boto3,
            patch.dict(
                os.environ, {"AIML_ASSESSMENT_BUCKET_NAME": "test-assessment-bucket"}
            ),
        ):
            mock_boto3.client.return_value = client
            single_account.get_assessment_results("exec-1", "111122223333")
        return [call.kwargs["Prefix"] for call in paginator.paginate.call_args_list]

    def test_no_prefix_is_requested_for_the_derived_standard(self):
        prefixes = self._requested_prefixes()
        self.assertTrue(prefixes)
        for prefix in prefixes:
            self.assertFalse(
                prefix.startswith("aisf_security_report_"),
                msg=f"derived standard reached S3 prefix construction: {prefix}",
            )

    def test_every_requested_prefix_is_permitted_by_the_iam_condition(self):
        patterns = _listbucket_prefix_patterns()
        for prefix in self._requested_prefixes():
            self.assertTrue(
                any(fnmatch.fnmatch(prefix, pattern) for pattern in patterns),
                msg=(
                    f"{prefix} matches no s3:prefix pattern in template.yaml; "
                    "the list_objects_v2 call would return AccessDenied and "
                    "fail report generation for every category"
                ),
            )

    def test_producing_standards_still_get_their_prefix(self):
        """The exclusion is scoped to derived entries, not to the registry."""
        prefixes = self._requested_prefixes()
        self.assertIn("owasp_security_report_exec-1", prefixes)


class TestSingleAccountRouting(unittest.TestCase):
    def _render(self, assessment_results):
        captured = {}

        def fake_render(**kwargs):
            captured.update(kwargs)
            return "<html>ok</html>"

        with patch.object(
            single_account, "generate_report_from_template", side_effect=fake_render
        ):
            single_account.generate_html_report(assessment_results)
        return captured

    def test_derived_rows_are_added_to_the_aisf_buckets(self):
        captured = self._render(
            {
                "account_id": "111122223333",
                "bedrock": {
                    "bedrock_security_report_exec_us-east-1": [
                        _source_row("BR-20", "Passed"),
                    ]
                },
                "sagemaker": {
                    "sagemaker_security_report_exec_us-east-1": [
                        _source_row("SM-18", "Failed"),
                        _source_row("SM-42", "Passed"),
                    ]
                },
            }
        )
        derived = _derived_by_id(captured["service_findings"]["aisf"])
        self.assertEqual(derived["AISF-07"]["Status"], "Failed")
        self.assertEqual(derived["AISF-05"]["Status"], "N/A")
        self.assertEqual(captured["service_stats"]["aisf"]["failed"], 1)
        self.assertEqual(captured["service_stats"]["aisf"]["passed"], 0)
        # And the source rows keep their own service.
        self.assertEqual(
            {f["Check_ID"] for f in captured["service_findings"]["bedrock"]},
            {"BR-20"},
        )
        self.assertEqual(
            {f["Check_ID"] for f in captured["service_findings"]["sagemaker"]},
            {"SM-18", "SM-42"},
        )

    def test_a_deselected_sagemaker_gets_no_aisf_00_row(self):
        captured = {}

        def fake_render(**kwargs):
            captured.update(kwargs)
            return "<html>ok</html>"

        with patch.object(
            single_account, "generate_report_from_template", side_effect=fake_render
        ):
            single_account.generate_html_report(
                {
                    "account_id": "111122223333",
                    "bedrock": {
                        "bedrock_security_report_exec_us-east-1": [
                            _source_row("BR-20", "Passed"),
                        ]
                    },
                },
                service_selection={"sagemaker": "false"},
            )
        self.assertEqual(
            {f["Check_ID"] for f in captured["service_findings"]["aisf"]},
            {"AISF-05"},
        )

    def test_retired_aisf_csv_row_is_isolated_with_a_diagnostic(self):
        """A stale or foreign artifact must not file AISF-* under bedrock."""
        captured = self._render(
            {
                "account_id": "111122223333",
                "bedrock": {
                    "bedrock_security_report_exec_us-east-1": [_source_row("AISF-01")]
                },
            }
        )
        self.assertEqual(captured["service_findings"]["aisf"], [])
        self.assertEqual(captured["service_findings"]["bedrock"], [])
        self.assertTrue(captured["aisf_register"]["artifact_issues"])

    def test_derived_rows_are_deduped_on_the_same_key_as_csv_rows(self):
        captured = self._render(
            {
                "account_id": "111122223333",
                "bedrock": {
                    "bedrock_security_report_exec_us-east-1": [
                        _source_row("BR-20", "Failed")
                    ],
                    # The same CSV listed twice, as an overlapping sync would.
                    "bedrock_security_report_exec_us-east-1_copy": [
                        _source_row("BR-20", "Failed")
                    ],
                },
            }
        )
        ai_05 = [
            f
            for f in captured["service_findings"]["aisf"]
            if f["Check_ID"] == "AISF-05"
        ]
        self.assertEqual(len(ai_05), 1)


class TestMultiAccountConsolidator(unittest.TestCase):
    """The root consolidator builds lowercase-keyed rows; derivation must read them."""

    ACCT = "111122223333"

    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="aisf-consolidate-test-")
        os.makedirs(os.path.join(self.base, self.ACCT), exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def _write(self, filename, rows):
        path = os.path.join(self.base, self.ACCT, filename)
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    def _consolidate(self):
        captured = {}

        def fake_render(**kwargs):
            captured.update(kwargs)
            return "<html>ok</html>"

        with (
            patch.object(multi_account, "boto3") as mock_boto3,
            patch.object(
                multi_account, "generate_html_report", side_effect=fake_render
            ),
            patch.dict(
                os.environ,
                {"BUCKET_REPORT": "test-bucket", "ACCOUNT_FILES_DIR": self.base},
            ),
        ):
            mock_boto3.client.return_value = MagicMock()
            multi_account.consolidate_html_reports()
        return captured

    def test_lowercase_keyed_rows_derive_correctly(self):
        row = _source_row("BR-20", "Failed")
        row.pop("Account_ID")
        self._write("bedrock_security_report_exec_us-east-1.csv", [row])

        captured = self._consolidate()

        derived = _derived_by_id(captured["service_findings"]["aisf"])
        self.assertEqual(derived["AISF-05"]["Status"], "Failed")
        self.assertEqual(derived["AISF-05"]["Account_ID"], self.ACCT)
        self.assertEqual(derived["AISF-05"]["Region"], "us-east-1")
        self.assertEqual(captured["service_stats"]["aisf"]["failed"], 1)

    def test_multi_leg_aggregation_survives_the_lowercase_path(self):
        rows = []
        for check_id in ("SM-09", "SM-01", "SM-03"):
            row = _source_row(check_id, "Passed")
            row.pop("Account_ID")
            rows.append(row)
        self._write("sagemaker_security_report_exec_us-east-1.csv", rows)

        captured = self._consolidate()

        derived = _derived_by_id(captured["service_findings"]["aisf"])
        self.assertEqual(derived["AISF-08"]["Status"], "N/A")

    def test_a_deselected_bedrock_gets_no_aisf_00_row(self):
        rows = []
        for check_id in ("SM-18", "SM-42", "SM-09", "SM-01", "SM-03"):
            row = _source_row(check_id, "Passed")
            row.pop("Account_ID")
            rows.append(row)
        self._write("sagemaker_security_report_exec_us-east-1.csv", rows)

        with patch.dict(os.environ, {"ENABLE_BEDROCK": "false"}):
            captured = self._consolidate()

        self.assertEqual(
            {f["Check_ID"] for f in captured["service_findings"]["aisf"]},
            {"AISF-07", "AISF-08"},
        )

    def test_deselected_sagemaker_is_not_replaced_by_manual_control_tasks(self):
        row = _source_row("BR-20", "Passed")
        row.pop("Account_ID")
        self._write("bedrock_security_report_exec_us-east-1.csv", [row])
        with patch.dict(os.environ, {"ENABLE_SAGEMAKER": "false"}):
            captured = self._consolidate()
        html = report_template.generate_html_report(**captured)
        self.assertFalse(
            _register_from_html(html)["scope"]["source_selection"]["sagemaker"]
        )
        self.assertEqual(
            [(c["source_check_id"], c["status"]) for c in _checks_from_html(html)],
            [("BR-20", "Passed")],
        )

    def test_unknown_legacy_alias_does_not_change_consolidated_native_results(self):
        row = _source_row("BR-20", "Passed")
        row.pop("Account_ID")
        self._write("bedrock_security_report_exec_us-east-1.csv", [row])
        with _with_fourth_derived_control():
            captured = self._consolidate()
            html = report_template.generate_html_report(**captured)
        checks = _checks_from_html(html)
        self.assertEqual(
            [(c["source_check_id"], c["status"]) for c in checks], [("BR-20", "Passed")]
        )
        self.assertNotIn(
            "AIR-TEST-02",
            {cid for check in checks for cid in check["aisf_control_ids"]},
        )

    def test_retired_aisf_csv_row_is_isolated_with_a_diagnostic(self):
        row = _source_row("AISF-01")
        row.pop("Account_ID")
        self._write("bedrock_security_report_exec_us-east-1.csv", [row])

        captured = self._consolidate()

        self.assertEqual(captured["service_findings"]["aisf"], [])
        self.assertEqual(captured["service_findings"]["bedrock"], [])
        self.assertTrue(captured["aisf_register"]["artifact_issues"])


if __name__ == "__main__":
    unittest.main()
