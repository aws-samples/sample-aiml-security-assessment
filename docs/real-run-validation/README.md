# Real-Run Validation — OWASP LLM Top 10 Overlay

This folder captures the first end-to-end run of the OWASP LLM Top 10 overlay
against a real AWS account, plus the validation harness used to confirm
the rendered report matches the feedback Agasthi gave on the demo report.

## Run context

| Field | Value |
|---|---|
| AWS account | 676206921018 |
| Region | us-east-1 |
| Run date | April 18, 2026 23:30 UTC |
| Source CSVs | from CodeBuild run `def8674f-6606-451e-b6d5-73c2844ab4e2` |
| Service-level findings | 66 (BR=13, SM=34, AC=19) |
| OWASP overlay findings | 18 (OW-01 through OW-18) |
| Total findings rendered | 84 |
| OWASP categories compliant | 2 / 10 (20%) |

## Files

| File | Purpose |
|---|---|
| `security_assessment_owasp_676206921018.html` | The rendered report shared with Agasthi. 139 KB, self-contained, no external assets. |
| `build_owasp_report.py` | Generator that loads the per-service CSVs, applies the OWASP overlay, and emits the HTML. The OWASP-overlay state was captured directly from live AWS API calls against account 676206921018 (no fixture data). |
| `validate_report.py` | 42-check validation harness. Asserts every concrete change Agasthi requested in the May 12 / April Slack thread is reflected in the rendered output. Exits non-zero if any assertion fails. |

## Validation summary

`validate_report.py` runs 42 assertions covering:

- **11 demo-only artifacts removed** — "What's Being Pushed", "Next Step",
  "Testing Summary", "Live AWS Validation Evidence", review banner,
  Phase 2a/2b/3 commit refs, feature-branch refs, seeded-fixture refs,
  commits-on-branch table, PR-body refs.
- **6 sidebar checks** — group count is 2 (matches existing single-account
  report), groups are exactly `Navigation` + `By Service`, no third
  `Compliance Frameworks` group, and no demo-only links (#live-evidence,
  #testing, #whats-pushed).
- **4 combined-table checks** — single combined table titled
  "OWASP Top 10 for LLM Applications 2025 — Coverage by Category & Check"
  with 10 LLM-category parent rows and 18 OW-XX nested sub-rows. The
  prior standalone "New OWASP Checks — All 18 Extensions" table is gone.
- **14 real-data checks** — real account ID and region present, real
  state reflected in OW-04 / OW-15 / OW-16 / OW-11 findings, and 8
  demo-only seeded resources (`qxjfofitorgf`, `kiro-owasp-test`,
  `OrderBot`, `prod-guardrail`, `SupportKB`, `BedrockInvocationSpike`,
  `kiro-owasp-bedrock-budget`, `PlaceOrderRole`) all absent.
- **2 docs-link checks** — 59 unique AWS doc links, all 10 OWASP
  category doc links present.
- **1 HTML hygiene check** — every tag balanced, no unclosed/mismatched
  tags via Python's `html.parser`.
- **4 footer checks** — real run date and account ID in the footer,
  no `Prepared: May 12, 2026` demo footer, no GitHub feature-branch link.

Last run: 42 / 42 PASS.

## Reproducing

```bash
# 1. Pull the three CSVs from your CodeBuild run's S3 bucket
aws s3 cp s3://<assessment-bucket>/<account>/bedrock_security_report_<exec>.csv   /tmp/bedrock_report.csv
aws s3 cp s3://<assessment-bucket>/<account>/sagemaker_security_report_<exec>.csv /tmp/sagemaker_report.csv
aws s3 cp s3://<assessment-bucket>/<account>/agentcore_security_report_<exec>.csv /tmp/agentcore_report.csv

# 2. Generate the report
python3 build_owasp_report.py

# 3. Validate
python3 validate_report.py
```

The OWASP overlay results inside `build_owasp_report.py` are currently
hard-coded from the April 18 live run. Once the OWASP Lambda from the
`feature/owasp-llm-phase1a-schema-and-tagging` branch is wired into the
deployed assessment stack, the overlay results will come from the
`owasp_security_report_*.csv` produced by that Lambda instead, matching
the same load-CSV pattern used for the three service Lambdas.
