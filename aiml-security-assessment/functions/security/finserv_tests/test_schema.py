"""
Tests for finserv_assessments/schema.py

Covers:
  - Valid finding creation for all severity/status combinations
  - Check_ID pattern validation (FS-NN, BR-NN, AC-NN, SM-NN)
  - Reference URL validation (must start with https://)
  - Required field presence and min_length constraints
  - Pydantic model_dump output structure
"""

import pytest
from schema import Finding, SeverityEnum, StatusEnum, create_finding
from app import COMPLIANCE_MAP, build_finserv_checks


# =========================================================================
# Enum completeness
# =========================================================================


class TestEnums:
    def test_severity_values(self):
        assert set(SeverityEnum) == {
            SeverityEnum.HIGH,
            SeverityEnum.MEDIUM,
            SeverityEnum.LOW,
            SeverityEnum.INFORMATIONAL,
        }

    def test_status_values(self):
        assert set(StatusEnum) == {
            StatusEnum.FAILED,
            StatusEnum.PASSED,
            StatusEnum.NA,
        }

    def test_severity_string_values(self):
        assert SeverityEnum.HIGH.value == "High"
        assert SeverityEnum.MEDIUM.value == "Medium"
        assert SeverityEnum.LOW.value == "Low"
        assert SeverityEnum.INFORMATIONAL.value == "Informational"

    def test_status_string_values(self):
        assert StatusEnum.FAILED.value == "Failed"
        assert StatusEnum.PASSED.value == "Passed"
        assert StatusEnum.NA.value == "N/A"


# =========================================================================
# create_finding — happy paths
# =========================================================================


class TestCreateFindingValid:
    """Every severity × status combination should produce a valid dict."""

    @pytest.mark.parametrize("severity", list(SeverityEnum))
    @pytest.mark.parametrize("status", list(StatusEnum))
    def test_all_severity_status_combos(self, severity, status):
        result = create_finding(
            check_id="FS-01",
            finding_name="Test Finding",
            finding_details="Some details here",
            resolution="Fix it",
            reference="https://docs.aws.amazon.com/example",
            severity=severity.value,
            status=status.value,
        )
        assert isinstance(result, dict)
        assert result["Check_ID"] == "FS-01"
        assert result["Severity"] == severity.value
        assert result["Status"] == status.value

    def test_output_has_all_csv_fields(self):
        result = create_finding(
            check_id="FS-42",
            finding_name="Name",
            finding_details="Details",
            resolution="Resolution",
            reference="https://example.com",
            severity="High",
            status="Failed",
        )
        expected_keys = {
            "Check_ID",
            "Finding",
            "Finding_Details",
            "Resolution",
            "Reference",
            "Severity",
            "Status",
            "Compliance_Frameworks",
        }
        assert set(result.keys()) == expected_keys

    @pytest.mark.parametrize(
        "check_id",
        ["FS-01", "FS-69", "BR-14", "SM-07", "AC-05"],
    )
    def test_valid_check_id_patterns(self, check_id):
        result = create_finding(
            check_id=check_id,
            finding_name="Test",
            finding_details="Details",
            resolution="",
            reference="https://example.com",
            severity="Low",
            status="Passed",
        )
        assert result["Check_ID"] == check_id

    def test_empty_resolution_allowed(self):
        """Resolution has min_length=0, so empty string is valid."""
        result = create_finding(
            check_id="FS-01",
            finding_name="Test",
            finding_details="Details",
            resolution="",
            reference="https://example.com",
            severity="Informational",
            status="Passed",
        )
        assert result["Resolution"] == ""


# =========================================================================
# create_finding — validation errors
# =========================================================================


class TestCreateFindingInvalid:
    def test_invalid_check_id_pattern(self):
        with pytest.raises(Exception):
            create_finding(
                check_id="INVALID",
                finding_name="Test",
                finding_details="Details",
                resolution="Fix",
                reference="https://example.com",
                severity="High",
                status="Failed",
            )

    def test_check_id_lowercase_rejected(self):
        with pytest.raises(Exception):
            create_finding(
                check_id="fs-01",
                finding_name="Test",
                finding_details="Details",
                resolution="Fix",
                reference="https://example.com",
                severity="High",
                status="Failed",
            )

    def test_check_id_missing_dash(self):
        with pytest.raises(Exception):
            create_finding(
                check_id="FS01",
                finding_name="Test",
                finding_details="Details",
                resolution="Fix",
                reference="https://example.com",
                severity="High",
                status="Failed",
            )

    def test_reference_not_https(self):
        with pytest.raises(Exception):
            create_finding(
                check_id="FS-01",
                finding_name="Test",
                finding_details="Details",
                resolution="Fix",
                reference="http://example.com",
                severity="High",
                status="Failed",
            )

    def test_empty_finding_name_rejected(self):
        with pytest.raises(Exception):
            create_finding(
                check_id="FS-01",
                finding_name="",
                finding_details="Details",
                resolution="Fix",
                reference="https://example.com",
                severity="High",
                status="Failed",
            )

    def test_empty_finding_details_rejected(self):
        with pytest.raises(Exception):
            create_finding(
                check_id="FS-01",
                finding_name="Test",
                finding_details="",
                resolution="Fix",
                reference="https://example.com",
                severity="High",
                status="Failed",
            )

    def test_invalid_severity(self):
        with pytest.raises(Exception):
            create_finding(
                check_id="FS-01",
                finding_name="Test",
                finding_details="Details",
                resolution="Fix",
                reference="https://example.com",
                severity="Critical",
                status="Failed",
            )

    def test_invalid_status(self):
        with pytest.raises(Exception):
            create_finding(
                check_id="FS-01",
                finding_name="Test",
                finding_details="Details",
                resolution="Fix",
                reference="https://example.com",
                severity="High",
                status="Open",
            )


# =========================================================================
# Finding model direct instantiation
# =========================================================================


class TestFindingModel:
    def test_model_dump_returns_dict(self):
        f = Finding(
            Check_ID="FS-01",
            Finding="Test",
            Finding_Details="Details",
            Resolution="Fix",
            Reference="https://example.com",
            Severity=SeverityEnum.HIGH,
            Status=StatusEnum.FAILED,
        )
        d = f.model_dump()
        assert isinstance(d, dict)
        assert d["Check_ID"] == "FS-01"

    def test_check_id_three_letter_prefix(self):
        """Three-letter prefixes like ACM-01 should be valid."""
        f = Finding(
            Check_ID="ACM-01",
            Finding="Test",
            Finding_Details="Details",
            Resolution="Fix",
            Reference="https://example.com",
            Severity=SeverityEnum.LOW,
            Status=StatusEnum.PASSED,
        )
        assert f.Check_ID == "ACM-01"


# =========================================================================
# D3 fix — Compliance_Frameworks field in schema and COMPLIANCE_MAP coverage
# =========================================================================


class TestComplianceFrameworksField:
    def test_compliance_frameworks_defaults_to_empty_string(self):
        """compliance_frameworks is optional and defaults to empty string."""
        result = create_finding(
            check_id="FS-01",
            finding_name="Test",
            finding_details="Details",
            resolution="Fix",
            reference="https://example.com",
            severity="High",
            status="Failed",
        )
        assert "Compliance_Frameworks" in result
        assert result["Compliance_Frameworks"] == ""

    def test_compliance_frameworks_round_trips(self):
        """A populated compliance_frameworks value is preserved verbatim."""
        fw = "FFIEC CAT | SR 11-7 | NYDFS 500"
        result = create_finding(
            check_id="FS-01",
            finding_name="Test",
            finding_details="Details",
            resolution="Fix",
            reference="https://example.com",
            severity="High",
            status="Failed",
            compliance_frameworks=fw,
        )
        assert result["Compliance_Frameworks"] == fw

    def test_compliance_map_covers_all_registry_checks(self):
        """Every check in build_finserv_checks must have an entry in COMPLIANCE_MAP."""
        registry = build_finserv_checks({})
        registry_ids = {check_id for check_id, _ in registry}
        missing = registry_ids - set(COMPLIANCE_MAP.keys())
        assert not missing, (
            f"These FS IDs are in the registry but missing from COMPLIANCE_MAP: {sorted(missing)}"
        )

    def test_compliance_map_all_values_non_empty(self):
        """Every COMPLIANCE_MAP entry must have at least one framework."""
        empty = [k for k, v in COMPLIANCE_MAP.items() if not v.strip()]
        assert not empty, f"Empty compliance_frameworks values: {empty}"

    def test_compliance_map_values_pipe_separated(self):
        """All multi-framework values use ' | ' as separator (consistent with ASFF style)."""
        for check_id, value in COMPLIANCE_MAP.items():
            if "|" in value:
                # Each segment should be non-empty after strip
                parts = [p.strip() for p in value.split("|")]
                empty_parts = [p for p in parts if not p]
                assert not empty_parts, f"{check_id}: empty segment in '{value}'"

    def test_compliance_frameworks_present_in_finding_model_dump(self):
        """Finding.model_dump() includes Compliance_Frameworks — critical for CSV writer."""
        f = Finding(
            Check_ID="FS-29",
            Finding="ADVISORY: Test",
            Finding_Details="Details",
            Resolution="Fix",
            Reference="https://example.com",
            Severity=SeverityEnum.INFORMATIONAL,
            Status=StatusEnum.NA,
            Compliance_Frameworks="SR 11-7 | FFIEC CAT | NYDFS 500 | MAS TRM 9.2",
        )
        d = f.model_dump()
        assert "Compliance_Frameworks" in d
        assert (
            d["Compliance_Frameworks"]
            == "SR 11-7 | FFIEC CAT | NYDFS 500 | MAS TRM 9.2"
        )
