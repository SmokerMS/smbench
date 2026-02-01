# Invariant Instrumentation Plan (Prompt 5)

## Invariants
- Per-client ordering: max one in-flight op per client.
- Completion matching: completion op_id must equal in-flight op_id.
- Oplock blocking: no I/O while BreakPending.
- Semaphore correctness: permits returned only via completion.

## Enforcement Points
- Scheduler dispatch rejects in-flight re-entry.
- Scheduler completion rejects op_id mismatches.
- Backend waits on oplock BreakPending before read/write.

## Runtime Modes
- Panic mode (debug): invariant violations panic immediately.
- Log-and-continue (production): violations are logged and counted; state is not mutated.

## Observability
- `SchedulerMetrics` counters: dispatches, completions, invariant_violations.
- Optional scheduler state dumps on invariant violation and in-flight timeout.

## Relevant Code
- Scheduler invariants: `src/scheduler/mod.rs`.
- Oplock blocking: `src/backend/mod.rs`.
