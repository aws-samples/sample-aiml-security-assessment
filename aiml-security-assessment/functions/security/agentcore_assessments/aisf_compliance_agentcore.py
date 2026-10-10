"""AISF control tags for agentcore_assessments findings.

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
    "AC-01": "AISF AIR-ACR-RT-08 (1 of 2 checks) | AISF AIR-ACR-RT-13 (partial) | AISF AIR-FND-NET-01 (1 of 6 checks) | AISF AIR-FND-NET-03 (partial) | AISF AIR-FND-NET-06 (1 of 5 checks) | AISF AIR-SLF-RT-02 (1 of 2 checks)",
    "AC-02": "AISF AIR-ACR-EVAL-01 | AISF AIR-ACR-PAY-01 | AISF AIR-ACR-RT-03 (1 of 3 checks) | AISF AIR-FND-IAM-05 (1 of 5 checks) | AISF AIR-FND-IAM-09 (1 of 4 checks)",
    "AC-06": "AISF AIR-ACR-RT-09 (partial)",
    "AC-07": "AISF AIR-ACR-MEM-01 (partial)",
    "AC-08": "AISF AIR-ACR-GW-04 (1 of 2 checks) | AISF AIR-ACR-RT-13 (partial) | AISF AIR-FND-NET-02 (partial)",
    "AC-10": "AISF AIR-ACR-GW-03 (partial) | AISF AIR-ACR-RT-13 (partial)",
    "AC-11": "AISF AIR-ACR-POL-04 (partial)",
    "AC-12": "AISF AIR-ACR-GW-10 (1 of 5 checks)",
    "AC-14": "AISF AIR-ACR-ID-05 (1 of 2 checks)",
    "AC-15": "AISF AIR-FND-NET-06 (1 of 5 checks)",
    "AC-17": "AISF AIR-ACR-EVAL-05 (1 of 2 checks) | AISF AIR-ACR-EVAL-06 (1 of 2 checks)",
    "AC-18": "AISF AIR-ACR-GW-10 (1 of 5 checks) | AISF AIR-ACR-MEM-12 (partial) | AISF AIR-ACR-OBS-02",
    "AC-19": "AISF AIR-ACR-GW-10 (1 of 5 checks) | AISF AIR-ACR-MEM-12 (partial) | AISF AIR-ACR-OBS-03 | AISF AIR-ACR-POL-01 (1 of 3 checks)",
    "AC-20": "AISF AIR-ACR-EVAL-07 (partial) | AISF AIR-ACR-GW-10 (1 of 5 checks) | AISF AIR-ACR-OBS-04 (1 of 2 checks)",
    "AC-21": "AISF AIR-ACR-OBS-04 (1 of 2 checks)",
    "AC-22": "AISF AIR-ACR-OBS-06 (partial)",
    "AC-23": "AISF AIR-ACR-MEM-01 (partial)",
    "AC-24": "AISF AIR-ACR-GW-05 (1 of 2 checks)",
    "AC-25": "AISF AIR-ACR-GW-08",
    "AC-26": "AISF AIR-ACR-EVAL-07 (partial) | AISF AIR-ACR-GW-10 (1 of 5 checks) | AISF AIR-FND-DET-09 (1 of 2 checks)",
    "AC-27": "AISF AIR-ACR-GW-03 (partial) | AISF AIR-ACR-GW-04 (1 of 2 checks) | AISF AIR-ACR-RT-13 (partial)",
    "AC-28": "AISF AIR-ACR-GW-02",
    "AC-29": "AISF AIR-ACR-ID-04",
    "AC-30": "AISF AIR-ACR-ID-08 (1 of 2 checks) | AISF AIR-ACR-ID-11 (partial)",
    "AC-31": "AISF AIR-ACR-ID-08 (1 of 2 checks) | AISF AIR-ACR-ID-11 (partial)",
    "AC-32": "AISF AIR-ACR-ID-11 (partial)",
    "AC-33": "AISF AIR-ACR-ID-10",
    "AC-34": "AISF AIR-ACR-ID-05 (1 of 2 checks)",
    "AC-35": "AISF AIR-ACR-POL-01 (1 of 3 checks) | AISF AIR-FND-NET-06 (1 of 5 checks)",
    "AC-36": "AISF AIR-ACR-POL-04 (partial)",
    "AC-37": "AISF AIR-ACR-POL-06",
    "AC-38": "AISF AIR-ACR-POL-07 (1 of 2 checks)",
    "AC-39": "AISF AIR-ACR-EVAL-05 (1 of 2 checks)",
    "AC-40": "AISF AIR-ACR-EVAL-06 (1 of 2 checks)",
    "AC-41": "AISF AIR-ACR-EVAL-07 (partial)",
    "AC-42": "AISF AIR-ACR-EVAL-02",
    "AC-43": "AISF AIR-ACR-EVAL-03 (1 of 2 checks) | AISF AIR-FND-IAM-05 (1 of 5 checks)",
    "AC-44": "AISF AIR-ACR-EVAL-03 (1 of 2 checks) | AISF AIR-ACR-EVAL-04",
    "AC-45": "AISF AIR-ACR-RT-03 (1 of 3 checks) | AISF AIR-FND-IAM-05 (1 of 5 checks)",
    "AC-46": "AISF AIR-ACR-RT-04 (partial)",
    "AC-47": "AISF AIR-ACR-RT-13 (partial)",
    "AC-48": "AISF AIR-ACR-RT-03 (1 of 3 checks) | AISF AIR-ACR-RT-13 (partial) | AISF AIR-FND-IAM-05 (1 of 5 checks)",
    "AC-49": "AISF AIR-ACR-RT-08 (1 of 2 checks) | AISF AIR-FND-NET-03 (partial) | AISF AIR-FND-NET-04 (partial) | AISF AIR-FND-NET-06 (1 of 5 checks)",
    "AC-50": "AISF AIR-SLF-CMP-01 (partial)",
    "AC-51": "AISF AIR-FND-NET-08 (partial)",
    "AC-53": "AISF AIR-FND-DET-10 (partial)",
    "AG-24": "AISF AIR-ACR-GW-01 (partial)",
    "AG-25": "AISF AIR-ACR-POL-01 (1 of 3 checks) | AISF AIR-ACR-POL-07 (1 of 2 checks) | AISF AIR-FND-NET-06 (1 of 5 checks)",
    "AG-27": "AISF AIR-ACR-GW-05 (1 of 2 checks) | AISF AIR-FND-NET-04 (partial)",
    "AG-39": "AISF AIR-FND-NET-04 (partial) | AISF AIR-FND-NET-08 (partial)",
}


def aisf_frameworks(check_id: str) -> str:
    """The AISF tag for a check id, or "" when no control is mapped to it."""
    return AISF_COMPLIANCE_MAP.get(check_id, "")
