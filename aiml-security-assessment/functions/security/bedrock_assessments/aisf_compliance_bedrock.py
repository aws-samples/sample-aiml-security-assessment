"""AISF control tags for bedrock_assessments findings.

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
    "BR-01": "AISF AIR-FND-IAM-09 (1 of 4 checks)",
    "BR-02": "AISF AIR-FND-NET-02 (partial)",
    "BR-04": "AISF AIR-BDR-MDL-02 (1 of 2 checks) | AISF AIR-FND-DAT-08 | AISF AIR-FND-DET-01 (1 of 3 checks)",
    "BR-06": "AISF AIR-BDR-KB-06 (partial) | AISF AIR-BDR-MDL-07 | AISF AIR-FND-DET-01 (1 of 3 checks)",
    "BR-07": "AISF AIR-BDR-MDL-08 (partial)",
    "BR-10": "AISF AIR-BDR-GRD-01 (partial)",
    "BR-11": "AISF AIR-FND-DAT-01 (1 of 4 checks)",
    "BR-12": "AISF AIR-BDR-MDL-02 (1 of 2 checks) | AISF AIR-FND-DET-01 (1 of 3 checks) | AISF AIR-FND-DET-09 (1 of 2 checks)",
    "BR-17": "AISF AIR-FND-DAT-01 (1 of 4 checks)",
    "BR-20": "AISF AIR-BDR-KB-03 | AISF AIR-FND-DAT-01 (1 of 4 checks)",
    "BR-26": "AISF AIR-BDR-GRD-03 (partial) | AISF AIR-BDR-KB-08 (partial)",
    "BR-27": "AISF AIR-BDR-GRD-09 (partial)",
    "BR-32": "AISF AIR-BDR-GRD-04 (partial)",
    "BR-33": "AISF AIR-SLF-CMP-01 (partial)",
    "BR-34": "AISF AIR-BDR-GRD-02 (partial) | AISF AIR-BDR-KB-05 (partial) | AISF AIR-FND-DET-04 (partial)",
    "BR-37": "AISF AIR-BDR-MDL-10 (partial)",
    "BR-39": "AISF AIR-FND-NET-01 (1 of 6 checks)",
    "BR-41": "AISF AIR-BDR-GRD-10 | AISF AIR-FND-DET-04 (partial)",
    "BR-42": "AISF AIR-BDR-MDL-01 | AISF AIR-BDR-MDL-03 (1 of 2 checks) | AISF AIR-BDR-MDL-04 (1 of 3 checks) | AISF AIR-FND-IAM-01 (1 of 2 checks)",
    "BR-43": "AISF AIR-BDR-MDL-03 (1 of 2 checks) | AISF AIR-BDR-MDL-04 (1 of 3 checks) | AISF AIR-FND-ACC-02 | AISF AIR-FND-DAT-04",
    "BR-44": "AISF AIR-BDR-MDL-04 (1 of 3 checks)",
    "BR-45": "AISF AIR-BDR-MDL-09 | AISF AIR-FND-IAM-03 (1 of 2 checks)",
    "BR-46": "AISF AIR-BDR-KB-01 (partial) | AISF AIR-FND-DAT-03 (partial)",
    "BR-47": "AISF AIR-FND-DAT-02",
    "BR-48": "AISF AIR-FND-DAT-09",
    "BR-49": "AISF AIR-FND-DET-04 (partial)",
    "BR-50": "AISF AIR-FND-IAM-03 (1 of 2 checks)",
    "BR-51": "AISF AIR-FND-IAM-02 (partial)",
    "BR-52": "AISF AIR-FND-DAT-05 (partial)",
    "BR-53": "AISF AIR-FND-GOV-02",
    "BR-54": "AISF AIR-SLF-RT-08",
    "BR-55": "AISF AIR-FND-DAT-10 (partial)",
    "BR-57": "AISF AIR-FND-IAM-05 (1 of 5 checks) | AISF AIR-SLF-AGT-05 (partial)",
}


def aisf_frameworks(check_id: str) -> str:
    """The AISF tag for a check id, or "" when no control is mapped to it."""
    return AISF_COMPLIANCE_MAP.get(check_id, "")
