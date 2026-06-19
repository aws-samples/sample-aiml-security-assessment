"""
Schema module for FinServ security findings.
Mirrors the schema used in bedrock_assessments/schema.py.
"""

from enum import Enum
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator
import re


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
    """Represents a security finding with required fields and validations."""

    Check_ID: str = Field(
        ...,
        min_length=1,
        description="Unique check identifier (e.g., FS-01)",
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
    Region: str = Field(default="", description="AWS region where the finding was identified")
    Compliance_Frameworks: str = Field(
        default="",
        description=(
            "Pipe-separated list of FinServ regulatory frameworks this control maps to "
            "(e.g., 'FFIEC CAT | SR 11-7 | NYDFS 500'). Preliminary; validate with your "
            "MRM/Legal/Compliance teams before using as audit evidence."
        ),
    )

    @field_validator("Check_ID")
    @classmethod
    def validate_check_id(cls, v):
        # Allow FS-NN pattern for FinServ checks
        pattern = r"^[A-Z]{2,3}-\d{2}$"
        if not re.match(pattern, v):
            raise ValueError(
                "Check_ID must follow pattern XX-NN (e.g., FS-01, BR-14, AC-05)"
            )
        return v

    @field_validator("Reference")
    @classmethod
    def validate_reference_url(cls, v):
        if not str(v).startswith("https://"):
            raise ValueError("Reference URL must start with https://")
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
    compliance_frameworks: Optional[str] = "",
) -> Dict[str, Any]:
    """Create a validated finding dict.

    Args:
        compliance_frameworks: Pipe-separated FinServ regulatory framework identifiers
            (e.g., "FFIEC CAT | SR 11-7 | NYDFS 500"). Populated from COMPLIANCE_MAP
            in app.py. Preliminary mappings — validate with MRM/Legal/Compliance before
            using as audit evidence.
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
        Compliance_Frameworks=compliance_frameworks or "",
    )
    return dict(finding.model_dump())
