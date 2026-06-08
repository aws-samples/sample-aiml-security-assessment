"""
Tests for the create_finding() schema validation across all three services.

Validates that the Pydantic-based Finding model enforces:
- Required fields and types
- Check_ID pattern (XX-NN)
- Reference URL format (https://)
- Severity and Status enum values
"""

import sys
import pytest

# Add each service directory so we can import their schema modules
sys.path.insert(0, "aiml-security-assessment/functions/security/bedrock_assessments")
sys.path.insert(0, "aiml-security-assessment/functions/security/sagemaker_assessments")
sys.path.insert(0, "aiml-security-assessment/functions/security/agentcore_assessments")

from schema import create_finding


# ---------------------------------------------------------------------------
# Valid finding creation
# ---------------------------------------------------------------------------
class TestCreateFindingValid:
    """Tests that valid inputs produce correct output."""

    def test_valid_finding_returns_dict(self):
        result = create_finding(
            check_id="BR-01",
            finding_name="Test Finding",
            finding_details="Details here",
            resolution="Fix it",
            reference="https://docs.aws.amazon.com/test",
            severity="High",
            status="Failed",
        )
        assert isinstance(result, dict)

    def test_valid_finding_has_all_keys(self):
        result = create_finding(
            check_id="SM-01",
            finding_name="Test",
            finding_details="Details",
            resolution="Resolve",
            reference="https://docs.aws.amazon.com/test",
            severity="Medium",
            status="Passed",
        )
        expected_keys = {
            "Check_ID",
            "Finding",
            "Finding_Details",
            "Resolution",
            "Reference",
            "Severity",
            "Status",
        }
        assert set(result.keys()) == expected_keys

    def test_valid_finding_preserves_values(self):
        result = create_finding(
            check_id="AC-05",
            finding_name="Encryption Check",
            finding_details="All encrypted",
            resolution="No action required",
            reference="https://docs.aws.amazon.com/bedrock/latest/userguide/security.html",
            severity="Informational",
            status="Passed",
        )
        assert result["Check_ID"] == "AC-05"
        assert result["Finding"] == "Encryption Check"
        assert result["Status"] == "Passed"
        assert result["Severity"] == "Informational"

    def test_na_status_is_valid(self):
        result = create_finding(
            check_id="BR-09",
            finding_name="KB Check",
            finding_details="No KBs found",
            resolution="No action",
            reference="https://docs.aws.amazon.com/test",
            severity="Informational",
            status="N/A",
        )
        assert result["Status"] == "N/A"

    def test_all_severity_levels(self):
        for severity in ("High", "Medium", "Low", "Informational"):
            result = create_finding(
                check_id="BR-01",
                finding_name="Test",
                finding_details="Details",
                resolution="Fix",
                reference="https://docs.aws.amazon.com/test",
                severity=severity,
                status="Failed",
            )
            assert result["Severity"] == severity

    def test_empty_resolution_is_valid(self):
        result = create_finding(
            check_id="BR-01",
            finding_name="Test",
            finding_details="Details",
            resolution="",
            reference="https://docs.aws.amazon.com/test",
            severity="Low",
            status="Passed",
        )
        assert result["Resolution"] == ""

    def test_three_letter_check_id_prefix(self):
        """AC- prefix has 2 letters, but the regex allows 2-3 uppercase letters."""
        result = create_finding(
            check_id="ACX-01",
            finding_name="Test",
            finding_details="Details",
            resolution="Fix",
            reference="https://docs.aws.amazon.com/test",
            severity="Low",
            status="Passed",
        )
        assert result["Check_ID"] == "ACX-01"


# ---------------------------------------------------------------------------
# Invalid inputs — should raise ValidationError
# ---------------------------------------------------------------------------
class TestCreateFindingInvalid:
    """Tests that invalid inputs raise pydantic ValidationError."""

    def test_invalid_check_id_format(self):
        with pytest.raises(Exception):
            create_finding(
                check_id="INVALID",
                finding_name="Test",
                finding_details="Details",
                resolution="Fix",
                reference="https://docs.aws.amazon.com/test",
                severity="High",
                status="Failed",
            )

    def test_empty_check_id(self):
        with pytest.raises(Exception):
            create_finding(
                check_id="",
                finding_name="Test",
                finding_details="Details",
                resolution="Fix",
                reference="https://docs.aws.amazon.com/test",
                severity="High",
                status="Failed",
            )

    def test_invalid_severity(self):
        with pytest.raises(Exception):
            create_finding(
                check_id="BR-01",
                finding_name="Test",
                finding_details="Details",
                resolution="Fix",
                reference="https://docs.aws.amazon.com/test",
                severity="Critical",
                status="Failed",
            )

    def test_invalid_status(self):
        with pytest.raises(Exception):
            create_finding(
                check_id="BR-01",
                finding_name="Test",
                finding_details="Details",
                resolution="Fix",
                reference="https://docs.aws.amazon.com/test",
                severity="High",
                status="Warning",
            )

    def test_http_reference_rejected(self):
        with pytest.raises(Exception):
            create_finding(
                check_id="BR-01",
                finding_name="Test",
                finding_details="Details",
                resolution="Fix",
                reference="http://docs.aws.amazon.com/test",
                severity="High",
                status="Failed",
            )

    def test_empty_finding_name(self):
        with pytest.raises(Exception):
            create_finding(
                check_id="BR-01",
                finding_name="",
                finding_details="Details",
                resolution="Fix",
                reference="https://docs.aws.amazon.com/test",
                severity="High",
                status="Failed",
            )

    def test_empty_finding_details(self):
        with pytest.raises(Exception):
            create_finding(
                check_id="BR-01",
                finding_name="Test",
                finding_details="",
                resolution="Fix",
                reference="https://docs.aws.amazon.com/test",
                severity="High",
                status="Failed",
            )

    def test_lowercase_check_id_prefix(self):
        with pytest.raises(Exception):
            create_finding(
                check_id="br-01",
                finding_name="Test",
                finding_details="Details",
                resolution="Fix",
                reference="https://docs.aws.amazon.com/test",
                severity="High",
                status="Failed",
            )
