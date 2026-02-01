# SMBench Prompts (v1.2.1)
This file defines the end-to-end prompts used with Cursor to implement, review, fix, and verify SMBench v1.2.1, plus three critical prompts for correctness under concurrency and production operability.

## How to Use
- Run prompts in order during each phase.
- Always provide Cursor the repo context (open workspace root).
- Prefer an "agent" run for implementation/fixing, and "chat/review" run for audits.

---

# Prompt 1 — Implementation (End-to-End Build)
**Goal:** Implement SMBench v1.2.1 Phase 0 + Phase 1 skeleton in a way that is testable and aligned with the locked IR and invariants.

**Prompt**
You are implementing SMBench Architecture v1.2.1 (Implementation-Ready).

Hard constraints:
- Enforce per-client strict ordering: at most ONE in-flight operation per client.
- Scheduler heap uses (deadline_us: u64, client_idx: u32), not Instant/String.
- Completion wiring exists and is required: CompletionEvent channel from executors to scheduler.
- Core execution is protocol-agnostic: Operation.extensions may be null and must still work.
- No async Drop for handles; use explicit cleanup patterns.
- Impacket backend uses newline-delimited JSON; max message size 4MB; large writes use WriteFromBlob.

Deliverables (minimum):
1) Rust workspace + module layout:
   - src/ir
   - src/scheduler
   - src/backend
   - src/protocol
   - src/observability
2) IR structs exactly matching v1 schema (locked for Phase 1–3).
3) Scheduler implementation that:
   - groups ops by client
   - maintains per-client queue + in_flight_op tracking
   - uses heap of ScheduledEvent(deadline_us, client_idx)
   - interleaves dispatch + completion handling
4) Executor worker pool that:
   - receives WorkItem
   - executes via selected backend
   - emits CompletionEvent with latency + status
5) Backend trait definitions + at least one stub backend that compiles:
   - OSMountBackend can exist but must be marked DEV ONLY and blocked from "production" mode
   - Impacket backend scaffolding OK (worker protocol types included)

Tests (Phase 0 scaffold):
- timing_precision test using p50/p95/p99 methodology over 1000 timers
- scheduler invariant test: proves no two ops from same client overlap (use instrumentation)

Rules:
- Make the code compile and tests runnable.
- Prefer clarity and correctness over premature optimization.
- Add structured tracing spans with client_idx + op_id correlation.
- Do not introduce schema changes or new IR fields.

Output:
- A commit-style summary of what you changed
- Files created/modified
- How to run tests locally
- Any TODOs that block Phase 0 validation

---

# Prompt 2 — Review (Architecture-to-Code Audit)
**Goal:** Review the implementation against SMBench v1.2.1 and find concrete gaps, risks, and violations.

**Prompt**
Review this repository implementation against SMBench Architecture v1.2.1.

Tasks:
1) Identify any violations of the execution invariants:
   - per-client strict ordering
   - completion op_id correctness
   - timing drift handling (bounded and measured)
   - protocol-agnostic core
2) Identify scheduler correctness issues:
   - heap ordering correctness (min-heap behavior)
   - eligible-client handling
   - completion wiring correctness
   - semaphore permit leaks
3) Identify backend contract mismatches:
   - improper layering (scheduler/executor interpreting extensions)
   - Impacket framing issues
   - OS mount backend not marked dev-only or not blocked
4) Identify production risks:
   - deadlocks or hangs
   - memory growth (handle tables, blocked waiters, queues)
   - log/metrics insufficiency for debugging

Deliverable:
- A prioritized findings list:
  - P0 (must fix now)
  - P1 (fix soon)
  - P2 (nice to have)
- For each finding:
  - exact file and symbol location
  - what breaks
  - recommended fix approach

---

# Prompt 3 — Fix Review Findings (Surgical Remediation)
**Goal:** Apply the review fixes without rewriting architecture.

**Prompt**
Fix the review findings in priority order.

Rules:
- Do not rewrite the architecture.
- Do not change IR schema (locked).
- Keep per-client ordering invariant strict.
- Preserve scheduler heap structure (u64 deadline, u32 client_idx).
- Ensure completion channel is the single source of truth for clearing in-flight ops.
- Add tests for every P0 fix (at least one per fix if feasible).

Deliverable:
- List of changes by finding ID
- New/updated tests
- How to verify locally

---

# Prompt 4 — Verify Fixes (Proof, Not Hope)
**Goal:** Prove the fixes actually work and didn’t regress invariants or performance.

**Prompt**
Verify the fixed implementation.

Tasks:
1) Run and summarize all tests. Add missing tests if coverage is weak.
2) Add a "scheduler invariant verification" test that:
   - creates multi-client IR
   - introduces artificial executor delays
   - proves no two ops per client overlap
3) Add a "completion correctness" test that:
   - forces out-of-order completion attempts
   - ensures scheduler rejects or panics in debug mode
4) Timing drift evaluation:
   - run timing_precision (p50/p95/p99)
   - report values and compare to thresholds

Deliverable:
- Test output summary
- Any remaining gaps
- Recommendation: GO / NO-GO for Phase 0 validation

---

# Prompt 5 — Invariant Violation Hunter (Extra)
**Goal:** Make invariant violations impossible to miss.

**Prompt**
Analyze SMBench for invariant violation risks at runtime.

Focus invariants:
- per-client ordering (no 2 in-flight ops per client)
- completion matching (completion op_id must equal in-flight op_id)
- oplock blocking (no I/O while BreakPending)
- semaphore correctness (no permit leaks)

Tasks:
- Identify every code path where an invariant could be violated.
- Propose runtime assertions and debug counters.
- Add a "panic-on-violation" debug mode and a "log-and-continue" production mode.
- Provide example logs proving a violation occurred.

Deliverable:
- Instrumentation plan + code changes
- A checklist of invariants + how each is enforced + how it is observed

---

# Prompt 6 — Race Condition & Deadlock Audit (Extra)
**Goal:** Identify all “hang forever” scenarios and close them.

**Prompt**
Perform a race-condition and deadlock audit of SMBench.

Analyze:
- scheduler ↔ executor ↔ completion channel
- oplock waiters + ACK paths
- worker crash/restart logic (Impacket)
- shutdown behavior

Tasks:
- Enumerate all blocking waits.
- For each: what unblocks it, and what if that never happens?
- Identify starvation/circular waits.
- Recommend watchdogs/timeouts where appropriate (minimal and targeted).

Deliverable:
- Table of deadlock risks + mitigation + code pointer for each

---

# Prompt 7 — Failure Debugging UX Review (Extra)
**Goal:** Ensure 3am debugging is possible.

**Prompt**
Review SMBench’s failure debugging UX.

Evaluate:
- structured logs (correlation IDs: run_id, client_idx, op_id, handle_ref)
- metrics (latency, queue depths, inflight counts, error codes)
- state dumps (scheduler/clients/handles)
- replay reproducibility

Tasks:
- Define minimum telemetry needed to debug:
  - a hang
  - error spike
  - wrong file contents
- Add a `--debug-dump-on-error` mode:
  - dumps scheduler state
  - dumps per-client queue heads
  - dumps handle table sizes
- Propose a short debugging playbook.

Deliverable:
- Specific logging/metrics additions
- Debug dump design + implementation steps
- A one-page “how to debug failures” section
