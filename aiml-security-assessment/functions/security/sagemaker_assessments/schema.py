from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, field_validator
import re

from aisf_compliance_sagemaker import aisf_frameworks


class SeverityEnum(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class StatusEnum(str, Enum):
    FAILED = "Failed"
    PASSED = "Passed"
    NA = "N/A"


class Finding(BaseModel):
    """Represents a security finding with required fields and validations"""

    Check_ID: str = Field(
        ...,
        min_length=1,
        description="Unique check identifier (e.g., SM-01, BR-01, AC-01)",
    )
    Finding: str = Field(..., min_length=1, description="The name/title of the finding")
    Finding_Details: str = Field(
        ..., min_length=1, description="Detailed description of the finding"
    )
    Resolution: str = Field(
        ..., min_length=0, description="Steps to resolve the finding"
    )
    Reference: str = Field(..., description="Documentation reference URL")
    Severity: SeverityEnum = Field(..., description="Severity level of the finding")
    Status: StatusEnum = Field(..., description="Current status of the finding")
    Region: str = Field(
        default="", description="AWS region where the finding was identified"
    )
    Compliance_Frameworks: str = Field(
        default="",
        description=(
            "Pipe-separated AISF control ids this check contributes to (e.g. "
            "'AISF AIR-SGM-EP-08'). A '(partial)' qualifier means the check "
            "asserts less than the control requires; '(1 of N checks)' means the "
            "control is asserted by this check together with N-1 others. A tag is "
            "a traceability reference to the AI Security Framework, not a "
            "statement that the control passed: the Status column carries the "
            "verdict."
        ),
    )

    @field_validator("Check_ID")
    @classmethod
    def validate_check_id(cls, v):
        """Validate that Check_ID follows the pattern XX-NN (e.g., SM-01, BR-14, AC-05)"""
        pattern = r"^[A-Z]{2,3}-\d{2}$"
        if not re.match(pattern, v):
            raise ValueError(
                "Check_ID must follow pattern XX-NN (e.g., SM-01, BR-14, AC-05)"
            )
        return v

    @field_validator("Reference")
    @classmethod
    def validate_reference_url(cls, v):
        """Validate that reference URL starts with https://"""
        if not str(v).startswith("https://"):
            raise ValueError("Reference URL must start with https://")
        return v

    @field_validator("Severity")
    @classmethod
    def validate_severity(cls, v):
        """Validate that severity is one of the allowed values"""
        if v not in SeverityEnum.__members__.values():
            raise ValueError("Severity must be one of the allowed values")
        return v

    @field_validator("Status")
    @classmethod
    def validate_status(cls, v):
        """Validate that status is one of the allowed values"""
        if v not in StatusEnum.__members__.values():
            raise ValueError("Status must be one of the allowed values")
        return v


def create_finding(
    check_id: str,
    finding_name: str,
    finding_details: str,
    resolution: str,
    reference: str,
    severity: SeverityEnum,
    status: StatusEnum,
    region: str = "",
    compliance_frameworks: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a validated finding object

    Args:
        check_id: Unique check identifier (e.g., SM-01, BR-01, AC-01)
        finding_name: Name of the finding
        finding_details: Detailed description
        resolution: Steps to resolve
        reference: Documentation URL
        severity: Severity level
        status: Current status
        region: AWS region where the finding was identified
        compliance_frameworks: AISF control tags. Left as None, the tags are
            looked up from the check id, so the several hundred existing call
            sites need no edit. Pass "" to emit an untagged row deliberately;
            None and "" have to be distinguishable for that reason.

    Returns:
        Dict[str, Any]: Validated finding as dictionary

    Raises:
        ValidationError: If any field fails validation
    """
    finding = Finding(
        Check_ID=check_id,
        Finding=finding_name,
        Finding_Details=finding_details,
        Resolution=resolution,
        Reference=reference,
        Severity=severity,
        Status=status,
        Region=region,
        Compliance_Frameworks=(
            aisf_frameworks(check_id)
            if compliance_frameworks is None
            else compliance_frameworks
        ),
    )
    return dict(finding.model_dump())  # Convert to regular dictionary
