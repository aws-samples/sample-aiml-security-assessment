from enum import Enum
import re
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator

from aisf_compliance_agent_registry import aisf_frameworks


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
    """Represents a security finding with the shared report CSV schema."""

    Check_ID: str = Field(..., min_length=1)
    Finding: str = Field(..., min_length=1)
    Finding_Details: str = Field(..., min_length=1)
    Resolution: str = Field(..., min_length=0)
    Reference: str
    Severity: SeverityEnum
    Status: StatusEnum
    Region: str = ""
    Compliance_Frameworks: str = Field(
        default="",
        description=(
            "Pipe-separated AISF control ids this check contributes to (e.g. "
            "'AISF AIR-ACR-REG-02 (partial)'). '(partial)' means the check asserts "
            "less than the control requires; '(1 of N checks)' means the control is "
            "asserted by this check together with N-1 others. A tag is a "
            "traceability reference, not a statement that the control passed."
        ),
    )

    @field_validator("Check_ID")
    @classmethod
    def validate_check_id(cls, value: str) -> str:
        if not re.match(r"^[A-Z]{2,3}-\d{2}$", value):
            raise ValueError("Check_ID must follow pattern XX-NN (e.g., AR-01)")
        return value

    @field_validator("Reference")
    @classmethod
    def validate_reference_url(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("Reference URL must start with https://")
        return value


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
    """Create a validated finding in the shared CSV schema.

    compliance_frameworks left as None looks the AISF tags up from the check id,
    so existing call sites need no edit. Pass "" to emit an untagged row
    deliberately; None and "" have to stay distinguishable for that.
    """
    return dict(
        Finding(
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
        ).model_dump()
    )
