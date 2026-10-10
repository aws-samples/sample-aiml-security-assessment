"""AISF control tags for agent_registry_assessments findings.

Each value names the AISF controls one check contributes to. A "(partial)"
qualifier marks a check that asserts only part of its control, and
docs/SECURITY_CHECKS_AISF.md describes the vocabulary.

The filename carries the module name because the test suite loads several
producers into one interpreter with each module directory on sys.path. A shared
`aisf_compliance.py` would be cached under that bare name and the first loader
would win, silently returning "" for every other module's check ids.

Qualifier vocabulary:
    AISF <control>                  this check alone asserts the whole control
    AISF <control> (1 of N checks)  the control is fully asserted, by this check
                                    together with N-1 others
    AISF <control> (partial)        this check asserts less than the control
                                    requires; the tightening is still outstanding

A tag is a traceability reference, not a statement that the control passed. The
row's own Status column carries the verdict.
"""

AISF_COMPLIANCE_MAP = {
    "AR-01": "AISF AIR-FND-IAM-09 (1 of 4 checks)",
    "AR-03": "AISF AIR-ACR-REG-02 (1 of 3 checks)",
    "AR-09": "AISF AIR-ACR-REG-02 (1 of 3 checks)",
    "AR-10": "AISF AIR-ACR-REG-02 (1 of 3 checks)",
}


def aisf_frameworks(check_id: str) -> str:
    """The AISF tag for a check id, or "" when no control is mapped to it."""
    return AISF_COMPLIANCE_MAP.get(check_id, "")
