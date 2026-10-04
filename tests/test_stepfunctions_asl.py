"""Structural regression tests for the Step Functions state machine
``assessments.asl.json``.

These are purely JSON-level structural checks.  They do **not** require AWS
credentials, do not start Step Functions executions, and do not import any
assessment Lambda code.  The goal is to catch accidental drift in:

* the HIPAA enablement Choice gates (OriginalInput.enableHIPAA / ServiceSelection);
* the HIPAA disabled path (the Choice state has an explicit ``Default`` edge);
* ``ResultPath`` on the HIPAA Lambda Task (must be ``null`` or absent so the
  upstream state is preserved, not overwritten by the Lambda output);
* and the absence of hard-coded ``hipaa_security_report_*`` artifact requirements
  in ``Generate Consolidated Report`` that would make the pipeline fail when the
  HIPAA branch is skipped.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ASL_RELATIVE = Path(
    "aiml-security-assessment",
    "statemachine",
    "assessments.asl.json",
)

HIPAA_ENABLED_CHOICE = "HIPAA Enabled?"
HIPAA_TASK = "HIPAA Security Assessment"
HIPAA_SKIPPED = "HIPAA Assessment Skipped"
HIPAA_INCOMPLETE = "HIPAA Assessment Incomplete"
GENERATE_REPORT = "Generate Consolidated Report"


@pytest.fixture(scope="module")
def asl_doc():
    repo_root = Path(__file__).resolve().parent.parent
    asl_path = repo_root / ASL_RELATIVE
    assert asl_path.is_file(), f"ASL JSON missing at {asl_path}"
    raw = asl_path.read_text(encoding="utf-8")
    # The ASL is a CloudFormation template fragment.  Lines such as
    #   "MaxConcurrency": ${MaxRegionConcurrency},
    #   "FunctionName": "${HIPAASecurityAssessmentFunction}",
    # contain unquoted / partly-quoted CloudFormation `${…}` substitution tokens
    # which are **not** valid JSON.  Replace every token (and any surrounding
    # quotes for the already-quoted cases) with a single quoted JSON-safe
    # placeholder so structural tests can still walk the resulting state-machine
    # graph correctly.
    substituted_quoted = re.sub(r'"?\$\{[^}]+\}"?', '"__CFN_PLACEHOLDER__"', raw)
    with pytest.raises(Exception):  # pragma: no cover - pure sanity fallback
        json.loads(raw)
    return json.loads(substituted_quoted)


def _map_state(asl, state_name):
    """Walk every nested object in the ASL looking for a state dict whose keys
    include ``state_name``.  Recurses through ``States`` at every level (the
    HIPAA branch lives inside a Map state's ``Iterator.States`` block)."""

    def _walk(node):
        if not isinstance(node, dict):
            return None
        states = node.get("States")
        if isinstance(states, dict) and state_name in states:
            return states[state_name]
        for child in node.values():
            found = _walk(child) if isinstance(child, (dict, list)) else None
            if isinstance(child, list):
                for item in child:
                    found = found or _walk(item)
            if found is not None:
                return found
        return None

    result = _walk(asl)
    assert result is not None, f"State '{state_name}' not found in ASL document"
    return result


class TestHIPAAStructuralChoiceGates:
    """HIPAA `Choice` state structure: original 2-branch OR gate + default skip."""

    def test_hipaa_enabled_is_a_choice_state(self, asl_doc):
        state = _map_state(asl_doc, HIPAA_ENABLED_CHOICE)
        assert state["Type"] == "Choice"

    def test_choice_has_two_branches_joined_by_or(self, asl_doc):
        """Exactly one top-level `Or` entry wraps two `And` entries.  Each
        And guards (IsPresent + StringEquals "true")."""
        state = _map_state(asl_doc, HIPAA_ENABLED_CHOICE)
        choices = state.get("Choices", [])
        assert len(choices) == 1, (
            "expected a single Choice rule wrapping an Or(2); got "
            f"{len(choices)} choices"
        )
        top = choices[0]
        assert "Or" in top, "Choice rule must be disjunctive (Or)"
        branches = top["Or"]
        assert len(branches) == 2, f"expected 2 Or branches, got {len(branches)}"
        for branch in branches:
            assert "And" in branch, "each Or leaf must be a conjunctive And"
            assert len(branch["And"]) == 2, "each And must be IsPresent + StringEquals"
            clauses = branch["And"]
            assert any(clause.get("IsPresent") is True for clause in clauses)
            assert any(clause.get("StringEquals") == "true" for clause in clauses)
        assert top["Next"] == HIPAA_TASK

    def test_originalinput_enablehipaa_path_reaches_hipaa_task(self, asl_doc):
        state = _map_state(asl_doc, HIPAA_ENABLED_CHOICE)
        branches = state["Choices"][0]["Or"]
        original_input_branch = branches[0]["And"]
        vars_seen = {clause.get("Variable") for clause in original_input_branch}
        assert vars_seen == {"$.OriginalInput.enableHIPAA"}, (
            "expected first Or branch to key off $.OriginalInput.enableHIPAA; "
            f"got {vars_seen}"
        )

    def test_serviceselection_hipaa_path_reaches_hipaa_task(self, asl_doc):
        state = _map_state(asl_doc, HIPAA_ENABLED_CHOICE)
        branches = state["Choices"][0]["Or"]
        ss_branch = branches[1]["And"]
        vars_seen = {clause.get("Variable") for clause in ss_branch}
        # The Variable path uses bracket syntax for the `hipaa` key — a regex
        # match tolerates bracket vs dot for the dict-indexing step.
        assert all(
            re.match(
                r"^\$\.OriginalInput\.ServiceSelection(\['hipaa'\]|\.hipaa)$",
                v,
            )
            for v in vars_seen
        ), f"Unexpected ServiceSelection variable path(s): {vars_seen}"

    def test_disabled_path_defaults_to_skipped_state(self, asl_doc):
        state = _map_state(asl_doc, HIPAA_ENABLED_CHOICE)
        assert state.get("Default") == HIPAA_SKIPPED, (
            "Choice MUST have an explicit Default fall-through so a disabled "
            "HIPAA assessment does not raise 'No choice matched' at runtime"
        )
        skipped = _map_state(asl_doc, HIPAA_SKIPPED)
        assert skipped["Type"] == "Pass"
        # The Skipped Pass must end execution cleanly — either `End: true` or
        # a `Next` that continues the pipeline. Either is acceptable; we do
        # not mandate which so long as it does not raise.
        assert skipped.get("End") is True or "Next" in skipped


class TestHIPAATaskPreservesState:
    """The HIPAA Lambda Task MUST NOT overwrite the execution input that the
    downstream Consolidated Report step reads from.  This is enforced by
    setting ResultPath to the JSON literal ``null`` (or omitting ResultPath
    entirely — but the explicit form is preferred for auditability)."""

    def test_hipaa_task_is_lambda_invoke(self, asl_doc):
        task = _map_state(asl_doc, HIPAA_TASK)
        assert task["Type"] == "Task"
        assert task["Resource"] == "arn:aws:states:::lambda:invoke"

    def test_hipaa_task_payload_routes_stepfunctions_context(self, asl_doc):
        task = _map_state(asl_doc, HIPAA_TASK)
        params = task.get("Parameters", {})
        payload = params.get("Payload", {})
        for required in ("Execution.$", "StateMachine.$", "Region.$", "RegionIndex.$"):
            assert required in payload, f"Lambda Payload missing key: {required}"
        # Each `.$` suffix must reference a root-$ path so the Step Functions
        # interpreter substitutes execution-scoped values (not literals).
        assert payload["Execution.$"] == "$.Execution"
        assert payload["StateMachine.$"] == "$.StateMachine"
        assert payload["Region.$"] == "$.Region"
        assert payload["RegionIndex.$"] == "$.RegionIndex"

    def test_hipaa_task_resultpath_null_preserves_input(self, asl_doc):
        task = _map_state(asl_doc, HIPAA_TASK)
        assert "ResultPath" in task, (
            "ResultPath explicitly required for HIPAA task auditability; "
            "set to JSON null to discard Lambda output and preserve input."
        )
        # JSON literal `null` deserializes to Python None.
        assert task["ResultPath"] is None, (
            f"ResultPath must be JSON null (preserve upstream state); "
            f"got {task['ResultPath']!r} which would overwrite $. with the "
            "Lambda return value, wiping Execution/StateMachine/Region data "
            "needed by the downstream report generator."
        )

    def test_hipaa_task_has_catch_for_all_errors(self, asl_doc):
        task = _map_state(asl_doc, HIPAA_TASK)
        catches = task.get("Catch", [])
        assert len(catches) >= 1, "HIPAA Lambda Task must have at least one Catch"
        any_all = any("States.ALL" in c.get("ErrorEquals", []) for c in catches)
        assert any_all, "at least one Catch must cover States.ALL to avoid silent drops"
        default_catch = next(c for c in catches if "States.ALL" in c["ErrorEquals"])
        assert default_catch.get("Next") == HIPAA_INCOMPLETE


class TestGenerateReportDoesNotHardcodeHIPAAArtifact:
    """When the HIPAA path is skipped, no step in the Map Iterator can
    *require* a ``hipaa_security_report_*`` S3 artifact — otherwise the
    report generator crashes on a skipped assessment even though 'HIPAA
    Assessment Skipped' returned a well-formed Pass result.

    We verify at the structural level: the Generate Consolidated Report
    Parameters block must not contain any literal ``hipaa_security_report``
    substring, and the whole ASL document must not embed it as a static
    string. (The Lambda code discovers artifacts via S3 list-objects prefix
    scanning, which is the correct dynamic pattern.)
    """

    def test_generate_report_parameters_have_no_hipaa_prefix_literal(self, asl_doc):
        report = _map_state(asl_doc, GENERATE_REPORT)
        params = report.get("Parameters", {})
        serialized = json.dumps(params)
        assert "hipaa_security_report" not in serialized, (
            "Generate Consolidated Report Parameters must not hard-code a "
            "hipaa_security_report_* artifact path — use S3 prefix discovery "
            "inside the Lambda so skipped HIPAA runs do not break the pipeline."
        )

    def test_asl_document_has_no_hipaa_artifact_prefix_literal(self, asl_doc):
        serialized = json.dumps(asl_doc)
        assert "hipaa_security_report" not in serialized
