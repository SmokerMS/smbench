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

## Checklist (Prompt 5)
- Per-client ordering: enforced in `dispatch_event` before marking in-flight.
- Completion matching: enforced in `handle_completion` and surfaced via invariant mode.
- Oplock blocking: `wait_if_blocked_by_handle` with timeout and ACK in `handle_oplock_break`.
- Semaphore correctness: permits held in `WorkItem` and released on completion send.

## Example Logs
```
{"level":"ERROR","msg":"Invariant violation","error":"Completion mismatch: expected Some(\"op_1\"), got wrong_op"}
{"level":"ERROR","msg":"Scheduler state dump","reason":"invariant_violation","heap_len":3,"pending_total":12,"inflight_total":1}
{"level":"WARN","msg":"In-flight operation exceeded timeout","client_idx":2,"op_id":"op_42","elapsed_ms":45000}
```
