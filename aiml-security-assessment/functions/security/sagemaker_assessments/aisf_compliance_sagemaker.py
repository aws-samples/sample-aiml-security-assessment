"""AISF control tags for sagemaker_assessments findings.

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
    "SM-01": "AISF AIR-SGM-TRN-05 (1 of 3 checks)",
    "SM-02": "AISF AIR-FND-IAM-01 (1 of 2 checks) | AISF AIR-FND-IAM-09 (1 of 4 checks) | AISF AIR-SGM-EP-02",
    "SM-03": "AISF AIR-FND-DAT-01 (1 of 4 checks) | AISF AIR-SGM-TRN-02 (1 of 2 checks) | AISF AIR-SGM-TRN-05 (1 of 3 checks)",
    "SM-04": "AISF AIR-FND-DET-02 (1 of 3 checks) | AISF AIR-FND-NET-07 (1 of 2 checks) | AISF AIR-SLF-RT-04 (1 of 2 checks)",
    "SM-09": "AISF AIR-SGM-TRN-05 (1 of 3 checks)",
    "SM-10": "AISF AIR-FND-NET-01 (1 of 6 checks)",
    "SM-11": "AISF AIR-FND-NET-01 (1 of 6 checks) | AISF AIR-SGM-EP-01 | AISF AIR-SGM-EP-03 (partial)",
    "SM-14": "AISF AIR-SGM-EP-03 (partial)",
    "SM-18": "AISF AIR-SGM-EP-08 (1 of 2 checks)",
    "SM-22": "AISF AIR-SGM-GOV-01",
    "SM-23": "AISF AIR-SGM-EP-06 (partial)",
    "SM-26": "AISF AIR-FND-DET-02 (1 of 3 checks) | AISF AIR-FND-DET-04 (partial)",
    "SM-28": "AISF AIR-FND-NET-01 (1 of 6 checks)",
    "SM-31": "AISF AIR-SGM-EP-06 (partial)",
    "SM-32": "AISF AIR-SGM-GOV-10",
    "SM-33": "AISF AIR-FND-NET-01 (1 of 6 checks) | AISF AIR-SGM-TRN-01 (1 of 2 checks)",
    "SM-34": "AISF AIR-SGM-TRN-01 (1 of 2 checks) | AISF AIR-SGM-TRN-02 (1 of 2 checks) | AISF AIR-SGM-TRN-08",
    "SM-35": "AISF AIR-FND-ACC-09",
    "SM-36": "AISF AIR-FND-DET-02 (1 of 3 checks)",
    "SM-37": "AISF AIR-FND-NET-07 (1 of 2 checks)",
    "SM-38": "AISF AIR-SLF-RT-04 (1 of 2 checks)",
    "SM-39": "AISF AIR-FND-NET-03 (partial) | AISF AIR-SLF-RT-02 (1 of 2 checks) | AISF AIR-SLF-RT-05 (partial)",
    "SM-40": "AISF AIR-SLF-RT-06 (partial)",
    "SM-41": "AISF AIR-PHY-EDG-01",
    "SM-42": "AISF AIR-SGM-EP-08 (1 of 2 checks)",
    "SM-43": "AISF AIR-SLF-CMP-08 (partial)",
}


def aisf_frameworks(check_id: str) -> str:
    """The AISF tag for a check id, or "" when no control is mapped to it."""
    return AISF_COMPLIANCE_MAP.get(check_id, "")
