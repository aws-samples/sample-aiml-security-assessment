# Independent AISF acceptance oracle

`canonical-ids.txt` freezes the 218 current IDs in canonical export order from
`aws-ai-security-framework-assessment` revision
`5df3295024713ac3ce88130c549bbc4fb2cebd53`.

The reviewed comparison supplied before implementation has SHA-256
`2232e2c832fd04997ded505dd082a1e466f53d0df1c1639a57211db37f724aa2`.
Its complete `controls[*].canonical` records, serialized as UTF-8 JSON with
`sort_keys=True`, `separators=(",", ":")`, and `ensure_ascii=False`, have SHA-256
`0853047d6c919fb8a6506ca0fdbd3996e516d322417386dde29a42ea020274af`.
The canonical exporter output bytes have SHA-256
`f2d44380f1859c204d13caf093b6e73a0aa2bea55e6f9cd6862971db12e362be`.

Tests compare every rendered canonical record against that content digest.
The expected IDs and content digest do not come from runtime mappings, the
vendored bundle, generated reports, or a report template.

The semantic witness cases in `tests/test_aisf_catalog_alignment.py` separately
state gaps identified in the pinned requirements and implemented source checks:
memory retention, human review quality, pre-export telemetry redaction, sandbox
network restrictions, token minting, knowledge-base encryption/access, batch
transform isolation/KMS, and notebook access. Source checks passing does not
close these control-level proof gaps.

Updating this oracle requires a separately reviewed canonical revision/export
and an exact ID/content diff. Running the application catalog updater must not
rewrite this fixture.
