# Example account folder (hand-written)

One account's folder in the central results bucket, written by hand for
tests/test_assessment_history_discover.py. `saved_times.json` gives each
file's S3 save time, because git doesn't keep file times.

| Run (execution ID ends) | Saved (UTC) | What it is |
|---|---|---|
| ...0801 | 2026-08-01 | Old incomplete run (Bedrock only). Never examined |
| ...0903 | 2026-09-03 23:37 | Previous run: us-east-1, Responsible AI GRC |
| ...0915 | 2026-09-15 | Incomplete run: its run record lists all four services as selected, but it has no AgentCore or Agent Registry CSV. Skipped |
| ...0927 | 2026-09-27 06:15 | Current run: us-east-1 and us-west-2, GRC and OWASP |
| ...0928 | 2026-09-27 07:00 | Saved after the current run. Ignored |

Also: the main HTML report, an earlier changes CSV, an unknown findings file
(`nist_...`), a file in a subfolder, and one CSV that starts with the mark
Excel adds. The expected results are worked out by hand in the test.
