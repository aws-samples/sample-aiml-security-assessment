# Follow-up items (deferred from PR #23 Round 3)

> GitHub Issues are disabled on the fork `mehtadman87/sample-aiml-security-assessment`, so
> deferred work is tracked here in-repo (task T1b.7). Promote to an upstream issue/PR when ready.

## FU-1 — Evaluate adopting a tool-wide `CRITICAL` severity tier

**Status:** Deferred (intentionally out of scope for Round 3).

**Background.** The FinServ severity methodology
([`docs/SECURITY_CHECKS_FINSERV_SEVERITY_METHODOLOGY.md`](./SECURITY_CHECKS_FINSERV_SEVERITY_METHODOLOGY.md))
defines a Likelihood × Impact matrix mapped to the AWS Security Hub ASFF label set, which includes a
**CRITICAL** band (the Impact=High × Likelihood=High cell). Round 3 **capped that cell at High** and
did **not** introduce `Critical`, to keep the FinServ checks consistent with the upstream
Bedrock/SageMaker/AgentCore checks (which have no Critical tier). The drift-guard
(`tests/test_severity_register.py`) asserts no `Critical` is currently emitted.

**Why it is a separate item.** Adopting `Critical` is a **tool-wide** change. Doing it for FinServ
alone would make FinServ inconsistent with the other three services. A tool-wide rollout touches:
- the shared `SeverityEnum` (each package's `schema.py`);
- all four assessment Lambdas (re-score the I=High × L=High controls);
- the report template severity filters/colors (`generate_consolidated_report/report_template.py`
  and `consolidate_html_reports.py`);
- every service's unit tests plus the FinServ drift-guard.

**Decision needed.**
1. Do we want a `CRITICAL` tier across the whole assessment?
2. If yes, which controls qualify (e.g., full guardrail bypass enabling a regulatory breach;
   unauthorized high-value autonomous financial action)?

**References:** methodology §2 (label scale) and §6 (the deferred decision); ASFF severity —
https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_Severity.html

---

## FU-2 — Report UI design for FinServ / OWASP (REQ-8)

Broader report UI re-design (top-page FinServ summary box placement, OWASP grouping, Risk
Distribution treatment) is deferred to a separate PR per the reviewer's suggestion. Round 3 delivers
FinServ as a functionally first-class service (REQ-1, Wave 2); the UI-design discussion is tracked
here for a follow-up PR.

---
---
---

## FU-3 — Shared-inventory refactor for the FinServ assessment Lambda (REQ-13 C3)

**Status:** Deferred from Round 3.1 (Wave 5.5 task T5h.9). Classified **Should-Fix** (performance /
scalability optimization), not a correctness blocker. Tracked here for a focused follow-up PR.

### Background

The FinServ Lambda (`finserv_assessments/app.py`) runs all 64 checks **sequentially in a single
invocation** via `build_finserv_checks()`. There is no cross-check caching, so several checks
independently re-enumerate the **same** account-wide inventories, and many then issue an N+1
per-resource call on top. The Round-3.1 pre-release audit (the per-check AWS API inventory)
identified the following duplicate full-account sweeps within one run:

| Inventory (API) | Times enumerated | Checks performing the enumeration | Per-resource N+1 follow-up |
| --- | --- | --- | --- |
| `lambda:ListFunctions` | ~6× | FS-09, FS-52, FS-55, FS-58, FS-67, FS-69 | FS-09 `GetFunctionConcurrency` per function |
| `bedrock:ListGuardrails` | ~9× | FS-27a, FS-28, FS-36, FS-38, FS-45, FS-47, FS-50, FS-51, FS-59 | `GetGuardrail` per guardrail in each check |
| `bedrock:ListKnowledgeBases` | ~6× | FS-24, FS-31, FS-33, FS-48, FS-61, FS-65 | FS-31/33/65 `ListDataSources`/`GetDataSource` per KB |
| `s3:ListBuckets` (full account) | ~3–4× | FS-21, FS-46 (full sweep); FS-33, FS-65 (KB data-source buckets) | `GetBucketVersioning`/`GetBucketTagging`/`GetBucketNotification` per bucket |
| `wafv2:ListWebACLs` | 4× | FS-01, FS-53, FS-56, FS-68 | `GetWebACL` per ACL in each check |

In small/empty accounts this is harmless (it is why the Wave-5 test account ran in ~3 minutes). In
**large enterprise accounts** — thousands of Lambda functions, hundreds of S3 buckets, many
guardrails/KBs/ACLs — the repeated full sweeps plus N+1 calls multiply API volume, drive adaptive
retries/throttling (`Config(retries=adaptive)`), and inflate wall-clock time. This is the most
likely driver of a slow run, and previously of a `States.Timeout`.

### Why it was deferred (and why that is safe)

1. **It is a large, regression-prone refactor.** It touches ~20 check functions and the way they
   obtain AWS data, plus every corresponding mocked unit test (the per-check tests patch
   `app.boto3.client`). Bundling that into a correctness-focused PR that "must be 100% sure"
   (the reviewer's bar) trades correctness risk for a performance gain.
2. **The blast-radius risk it is associated with (audit C2) is already mitigated in Round 3.1.**
   A `Catch [States.ALL] → "FinServ Assessment Incomplete"` was added to the FinServ task in
   `statemachine/assessments.asl.json`, and the FinServ Lambda `Timeout` was raised 600 → 900 s.
   So even if the FinServ Lambda is slow or times out in a very large account, the consolidated
   report is still generated with the other services' findings and a visible incomplete marker —
   the failure no longer sinks the whole assessment.
3. **It is purely an optimization** (Should-Fix). The disposition logic and severities are unchanged
   by this work; nothing about the *correctness* of any finding depends on it.

### Who is affected

Customers running the FinServ assessment (`EnableFinServAssessment=true`) against accounts with large
resource estates — primarily large enterprises. Symptoms: long FinServ Lambda duration, CloudWatch
throttling/retry noise, and (pre-mitigation) the risk of a 900 s timeout. Small accounts are
unaffected.

### Proposed design

Collect each shared inventory **once** at the start of `lambda_handler`, into a read-only context
object, and pass it to the checks that need it — mirroring the existing `permission_cache` pattern
(which is already injected via `functools.partial` in `build_finserv_checks()`).

1. **Add a `ResourceInventory` collected once per invocation**, e.g.:

   ```python
   @dataclass
   class ResourceInventory:
       lambda_functions: list          # lambda:ListFunctions (+ concurrency map)
       guardrails: list                # bedrock:ListGuardrails + GetGuardrail detail, keyed by id
       knowledge_bases: list           # bedrock:ListKnowledgeBases (+ data sources per KB)
       buckets: list                   # s3:ListBuckets
       web_acls: list                  # wafv2:ListWebACLs + GetWebACL detail (REGIONAL)
   ```

   Each field is populated by one paginated enumeration (reuse `_paginate`). Per-resource detail
   (e.g., `GetGuardrail`, `GetWebACL`) is fetched once and stored alongside, eliminating the N+1
   repetition across checks.

2. **Inject it like `permission_cache`.** In `build_finserv_checks(permission_cache, inventory)`,
   bind the inventory to the relevant checks with `functools.partial`, so every registry entry
   stays uniformly zero-arg and the handler loop is unchanged.

3. **Make collection resilient.** A failure (e.g., `AccessDenied`) collecting one inventory must not
   abort the others or the whole run. Per-inventory collection should be wrapped so a failed
   inventory yields an explicit "unavailable" sentinel; checks that depend on an unavailable
   inventory then emit `COULD_NOT_ASSESS` (consistent with `_is_access_error` handling today) rather
   than a false `Failed`/`Passed`. Preserve the existing per-check `try/except` safety net.

4. **Keep region/pagination semantics identical.** Same default-region clients, same `_paginate`
   token handling; this is a call-site consolidation, not a behavior change.

### Test strategy

- Update the affected per-check unit tests to pass a constructed `ResourceInventory` (or a partial)
  instead of patching `boto3.client` for the enumeration calls. Checks that still make non-inventory
  calls keep their existing mocks.
- Add tests for the collector itself: one enumeration per inventory; pagination; and the
  per-inventory failure path producing the "unavailable" sentinel (→ `COULD_NOT_ASSESS` downstream).
- **Behavior-preserving guarantee:** every existing disposition test (Passed/Failed/N/A per check)
  and the severity drift-guard (`tests/test_severity_register.py`) must remain green with **no**
  disposition or severity changes. That equivalence is the acceptance bar.
- Optionally add a counter/assertion (in a unit harness) proving each inventory API is called at
  most once per handler invocation.

### Acceptance criteria

- Each shared inventory (`ListFunctions`, `ListGuardrails`+`GetGuardrail`, `ListKnowledgeBases`,
  `ListBuckets`, `ListWebACLs`+`GetWebACL`) is enumerated **at most once** per FinServ run.
- No change to any finding's status or severity (all existing tests + the drift-guard pass
  unchanged).
- A per-inventory collection failure degrades only the dependent checks (to `COULD_NOT_ASSESS`), not
  the whole run.
- Workspace `finserv_assessments/` stays byte-identical to the fork copy after sync.

### Risk / considerations

- **Test isolation** if any memoization is module-level: prefer an explicit per-invocation object
  passed as an argument over a module-global cache, to avoid state leaking across unit tests.
- **Partial-inventory correctness:** ensure a check that needs two inventories handles one being
  unavailable independently.
- **Memory:** holding full inventories (e.g., all guardrail details) in memory is bounded and far
  smaller than the permission cache already loaded; no concern at 1024 MB.

### Effort estimate

Roughly 1–2 focused days: ~0.5 day for the collector + injection, ~0.5–1 day updating the ~20
affected checks and their tests, ~0.5 day validation (full suite + a large-account timing check).

### References

- Round-3.1 requirement: **REQ-13 (audit finding C3)** and design section "REQ-13 — Enterprise-scale
  resilience & scope (audit C)" in `.kiro/specs/pr-review-round3-fixes/design.md`.
- Deferred task: **T5h.9** in `.kiro/specs/pr-review-round3-fixes/tasks.md`.
- Related mitigation already shipped in Round 3.1: **T5h.8** (ASL `Catch` on the FinServ task +
  Lambda `Timeout` 600 → 900 s) addressing audit finding C2.
- Existing pattern to mirror: the `permission_cache` injection in `get_permissions_cache()` /
  `build_finserv_checks()` in `finserv_assessments/app.py`.

## FU-4 — Migrate upstream schemas from Pydantic V1 `@validator` to V2 `@field_validator`

**Priority:** Low (tech-debt) — not a blocker.

The upstream `schema.py` files for the Bedrock, SageMaker, AgentCore, consolidated-report,
and IAM-permission-caching Lambdas still use the deprecated Pydantic V1 `@validator` decorator,
which emits `PydanticDeprecatedSince20` warnings and will break when Pydantic V3 removes V1-style
validators. The FinServ `schema.py` already uses the V2 `@field_validator` form.

**Why deferred:** this PR is scoped to `feature/finserv-risk-checks`. The affected files are
upstream/shared components; migrating them here would exceed the PR's scope and risk merge
conflicts with upstream. Best handled as a dedicated upstream change.

**Scope:** swap `@validator("X")` → `@field_validator("X")` + `@classmethod`, adjust signatures,
and re-run each module's tests.

### References

- Identified in the pre-Wave-6 verification pass (`.kiro/specs/pr-review-round3-fixes/tasks.md`).
