"""The `Compliance_Frameworks` column that tags producer rows with AISF controls.

The column adds no new verdict. It annotates rows the four producer modules
already emit with the AISF control each check contributes to, so
a reader of `bedrock_security_report_*.csv` can trace a row back to the
framework. The tests here hold three properties that a silent drift would break.

1. **The qualifier cannot be dropped.** An unqualified tag asserts that the check
   alone covers the whole control. Writing one on a check that covers only part
   of it publishes a mapping the assessment never earned, the same overclaim the
   derived `AISF-` rows refuse. A tag may reference a partly-covered control only
   because the qualifier says so, so the qualifier is what makes the mechanism
   sound.

2. **The maps must not cross-contaminate.** All six producers name their modules
   `schema.py` and `app.py`, and `app.py` reaches its schema with
   `from schema import create_finding`, resolved through `sys.modules` under that
   bare name. Loading two producers into one interpreter gives the second one the
   first one's schema. That was harmless while the three schema.py files were
   byte-identical; each now imports a different AISF map, so a collision empties
   the tag for every module but the first, with no import error to notice. The
   map modules are named per-producer for that reason and
   `test_two_producers_in_one_interpreter_keep_their_own_maps` is the regression.

3. **The column and the header move together.** Every producer writes its CSV
   with `csv.DictWriter` at the default `extrasaction="raise"`, so a finding that
   grows a key the fieldnames lack raises `ValueError` on the first row. That
   coupling fails closed, which is why it is worth a test: the failure is a
   crashed assessment, not a missing column.
"""

import csv
import glob
import importlib.util
import os
import re
import sys
from io import StringIO

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODULES = os.path.join(REPO_ROOT, "aiml-security-assessment", "functions", "security")


def _producers_from_shipped_maps():
    """The producer directories that ship an AISF map.

    Derived, not hand-listed, so a new producer cannot be left out of the list
    with nothing to notice.

    Empty raises. `pytest.mark.parametrize` over an empty sequence collects zero
    cases and reports a warning, not a failure, so an empty derivation would turn
    every parametrized test in this module into a no-op that reads as green.
    """
    found = sorted(
        os.path.basename(os.path.dirname(path))
        for path in glob.glob(os.path.join(MODULES, "*", "aisf_compliance_*.py"))
    )
    if not found:
        raise RuntimeError(
            f"no aisf_compliance_*.py under {MODULES}: the derivation found no "
            "producer at all, which would make every test in this module vacuous "
            "instead of red"
        )
    return tuple(found)


PRODUCERS = _producers_from_shipped_maps()

# The 8 columns every producer CSV carried before this change, in order.
LEGACY_COLUMNS = [
    "Check_ID",
    "Finding",
    "Finding_Details",
    "Resolution",
    "Reference",
    "Severity",
    "Status",
    "Region",
]
EXPECTED_COLUMNS = LEGACY_COLUMNS + ["Compliance_Frameworks"]


def _load(module_dir, filename, alias, extra_modules=None):
    """Load one file from one producer directory under a unique module name.

    `extra_modules` is seeded into sys.modules for the duration of the load and
    removed afterwards, which is how `app.py` is given its *own* `schema` rather
    than whichever producer was imported first.
    """
    directory = os.path.join(MODULES, module_dir)
    path = os.path.join(directory, filename)
    spec = importlib.util.spec_from_file_location(alias, path)
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, directory)
    saved = {}
    for name, value in (extra_modules or {}).items():
        saved[name] = sys.modules.get(name)
        sys.modules[name] = value
    sys.modules[alias] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(directory)
        for name, previous in saved.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
    return module


def _schema(module_dir):
    return _load(module_dir, "schema.py", f"aisf_col_schema_{module_dir}")


def _app(module_dir, schema_module):
    return _load(
        module_dir,
        "app.py",
        f"aisf_col_app_{module_dir}",
        extra_modules={"schema": schema_module},
    )


@pytest.fixture(scope="module")
def schemas():
    return {d: _schema(d) for d in PRODUCERS}


def _finding(schema_module, check_id, **kwargs):
    return schema_module.create_finding(
        check_id=check_id,
        finding_name="Name",
        finding_details="Details",
        resolution="Resolve",
        reference="https://docs.aws.amazon.com/test",
        severity=schema_module.SeverityEnum.MEDIUM,
        status=schema_module.StatusEnum.PASSED,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# The tag reaches the finding
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("module_dir", PRODUCERS)
def test_every_mapped_check_id_gets_exactly_its_tag(schemas, module_dir):
    schema_module = schemas[module_dir]
    mapping = sys.modules[
        f"aisf_compliance_{module_dir.removesuffix('_assessments')}"
    ].AISF_COMPLIANCE_MAP
    assert mapping, f"{module_dir} has an empty map"
    for check_id, tag in mapping.items():
        finding = _finding(schema_module, check_id)
        assert finding["Compliance_Frameworks"] == tag, check_id


@pytest.mark.parametrize("module_dir", PRODUCERS)
def test_an_unmapped_check_id_gets_no_tag(schemas, module_dir):
    # ZZ-99 is a well-formed id that no producer emits, so the lookup must miss.
    assert _finding(schemas[module_dir], "ZZ-99")["Compliance_Frameworks"] == ""


@pytest.mark.parametrize("module_dir", PRODUCERS)
def test_a_caller_can_suppress_the_tag_with_an_empty_string(schemas, module_dir):
    """None means "look it up", "" means "deliberately untagged".

    They have to stay distinguishable: defaulting the parameter to "" instead of
    None would make an explicit suppression indistinguishable from the default
    and silently re-tag the row.
    """
    schema_module = schemas[module_dir]
    mapping = sys.modules[
        f"aisf_compliance_{module_dir.removesuffix('_assessments')}"
    ].AISF_COMPLIANCE_MAP
    check_id = sorted(mapping)[0]
    assert (
        _finding(schema_module, check_id)["Compliance_Frameworks"] == mapping[check_id]
    )
    assert (
        _finding(schema_module, check_id, compliance_frameworks="")[
            "Compliance_Frameworks"
        ]
        == ""
    )
    assert (
        _finding(schema_module, check_id, compliance_frameworks="AISF OTHER")[
            "Compliance_Frameworks"
        ]
        == "AISF OTHER"
    )


def test_two_producers_in_one_interpreter_keep_their_own_maps(schemas):
    """The regression for the shared-module-name collision.

    Before the map modules were named per producer, both of these resolved to
    whichever directory reached sys.path last, and the other one returned "".
    """
    bedrock = schemas["bedrock_assessments"]
    sagemaker = schemas["sagemaker_assessments"]
    assert (
        _finding(bedrock, "BR-10")["Compliance_Frameworks"]
        == "AISF AIR-BDR-GRD-01 (partial)"
    )
    assert (
        _finding(sagemaker, "SM-18")["Compliance_Frameworks"]
        == "AISF AIR-SGM-EP-08 (1 of 2 checks)"
    )
    # And neither answers for the other's ids.
    assert _finding(bedrock, "SM-18")["Compliance_Frameworks"] == ""
    assert _finding(sagemaker, "BR-10")["Compliance_Frameworks"] == ""


# ---------------------------------------------------------------------------
# The tag reaches the CSV
# ---------------------------------------------------------------------------
def _csv_rows(module_dir, schema_module, findings):
    app = _app(module_dir, schema_module)
    if module_dir in ("bedrock_assessments", "sagemaker_assessments"):
        payload = [{"csv_data": findings}]
    else:
        payload = findings
    return app.generate_csv_report(payload)


@pytest.mark.parametrize("module_dir", PRODUCERS)
def test_csv_header_is_the_nine_column_contract(schemas, module_dir):
    schema_module = schemas[module_dir]
    mapping = sys.modules[
        f"aisf_compliance_{module_dir.removesuffix('_assessments')}"
    ].AISF_COMPLIANCE_MAP
    text = _csv_rows(
        module_dir, schema_module, [_finding(schema_module, sorted(mapping)[0])]
    )
    header = next(csv.reader(StringIO(text)))
    assert header == EXPECTED_COLUMNS


@pytest.mark.parametrize("module_dir", PRODUCERS)
def test_the_tag_survives_the_csv_round_trip(schemas, module_dir):
    schema_module = schemas[module_dir]
    mapping = sys.modules[
        f"aisf_compliance_{module_dir.removesuffix('_assessments')}"
    ].AISF_COMPLIANCE_MAP
    check_id = sorted(mapping)[0]
    text = _csv_rows(module_dir, schema_module, [_finding(schema_module, check_id)])
    row = next(csv.DictReader(StringIO(text)))
    assert row["Compliance_Frameworks"] == mapping[check_id]


@pytest.mark.parametrize("module_dir", PRODUCERS)
def test_writing_a_finding_does_not_raise_on_an_unknown_column(schemas, module_dir):
    """DictWriter defaults to extrasaction="raise".

    So the schema field and the fieldnames list have to move together. This is
    the assertion that catches one landing without the other.
    """
    schema_module = schemas[module_dir]
    text = _csv_rows(module_dir, schema_module, [_finding(schema_module, "ZZ-99")])
    assert "Compliance_Frameworks" in text.splitlines()[0]


def test_agentcore_empty_and_populated_reports_have_the_same_header(schemas):
    """agentcore builds its header twice, once for the no-findings case.

    Updating one list and not the other gives an empty report 8 columns and a
    populated one 9, which a consumer joining the two sees as a missing column
    rather than as a bug.
    """
    schema_module = schemas["agentcore_assessments"]
    app = _app("agentcore_assessments", schema_module)
    empty_header = next(csv.reader(StringIO(app.generate_csv_report([]))))
    populated_header = next(
        csv.reader(
            StringIO(app.generate_csv_report([_finding(schema_module, "AC-06")]))
        )
    )
    assert empty_header == populated_header == EXPECTED_COLUMNS


@pytest.mark.parametrize("module_dir", PRODUCERS)
def test_the_new_column_is_appended_not_inserted(schemas, module_dir):
    """The 8 legacy columns keep their order and position.

    consolidate_html_reports.py and the report Lambda both read these CSVs with
    DictReader, so a reordering would not break them, but an archived report
    diffed against a fresh one would show every column as changed.
    """
    schema_module = schemas[module_dir]
    text = _csv_rows(module_dir, schema_module, [_finding(schema_module, "ZZ-99")])
    header = next(csv.reader(StringIO(text)))
    assert header[:8] == LEGACY_COLUMNS
    assert header[8] == "Compliance_Frameworks"


# ---------------------------------------------------------------------------
# Every map is wired into its producer
# ---------------------------------------------------------------------------
def _all_maps():
    out = {}
    for module_dir in PRODUCERS:
        suffix = module_dir.removesuffix("_assessments")
        path = os.path.join(MODULES, module_dir, f"aisf_compliance_{suffix}.py")
        out[module_dir] = _load(
            module_dir, f"aisf_compliance_{suffix}.py", f"aisf_col_map_{suffix}"
        ).AISF_COMPLIANCE_MAP
        assert os.path.exists(path)
    return out


def test_the_producer_set_is_derived_and_not_empty():
    """The derived producer set, measured against a second reading of it.

    PRODUCERS is derived from which directories hold an `aisf_compliance_*.py`.
    This reads which `schema.py` imports one, which is a different file and a
    different mechanism, so a module that ships a map nothing imports, or imports
    a map it does not ship, appears in one reading and not the other. It also
    catches PRODUCERS being turned back into a hand-written literal. Both counts
    are in the message, because a comparison of two empty sets holds.
    """
    wired = []
    for path in sorted(glob.glob(os.path.join(MODULES, "*", "schema.py"))):
        with open(path) as handle:
            source = handle.read()
        if re.search(
            r"^\s*from aisf_compliance_\w+ import aisf_frameworks", source, re.M
        ):
            wired.append(os.path.basename(os.path.dirname(path)))
    assert PRODUCERS, "the derived producer set is empty; every test here is vacuous"
    assert set(PRODUCERS) == set(wired), (
        f"{len(PRODUCERS)} producer(s) ship a map {sorted(PRODUCERS)}; "
        f"{len(wired)} wire one into schema.py {wired}"
    )


@pytest.mark.parametrize("module_dir", PRODUCERS)
def test_no_producer_builds_a_finding_outside_create_finding(module_dir):
    """The lookup lives in create_finding, so a row that skips it ships no tag.

    And it ships one silently: `csv.DictWriter` raises on a key the fieldnames
    lack, never on a key a row is missing, so a finding assembled as a literal
    dict writes an empty `Compliance_Frameworks` cell and every other test here
    still passes. This is the backward detector for that: no assertion over the
    maps can find a row that was never routed through the lookup.

    The count is not pinned, because it moves with every new check. The property
    is that it is the only construction path.
    """
    with open(os.path.join(MODULES, module_dir, "app.py")) as handle:
        source = handle.read()
    calls = len(re.findall(r"\bcreate_finding\(", source))
    assert calls > 0, f"{module_dir} builds no findings at all"
    literals = re.findall(r'["\']Check_ID["\']\s*:', source)
    assert not literals, (
        f"{module_dir} assembles {len(literals)} finding dict(s) directly beside "
        f"{calls} create_finding call(s); a direct dict skips the AISF tag lookup"
    )
