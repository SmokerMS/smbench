# Race Condition & Deadlock Audit (Prompt 6)

## Blocking Waits
- Scheduler waits on `completion_rx.recv()` when no eligible deadlines.
  - Mitigation: periodic watchdog logs in-flight timeouts and optional state dump.
- Oplock waiters block I/O during BreakPending.
  - Mitigation: timeout on oplock wait with error to avoid infinite wait.
- Worker connection creation (backend connect) can stall.
  - Mitigation: errors are surfaced via completion events.

## Starvation Risks
- In-flight op never completes (backend stuck) -> scheduler stalls for that client.
  - Mitigation: watchdog logs timeouts; operator can inspect state dump.

## Mitigation Checklist (Prompt 6)
- Watchdog interval set and logs in-flight timeouts.
- Oplock wait uses bounded timeout to prevent infinite wait.
- Completion channel close triggers error path.
- Connection creation errors routed via CompletionEvent.

## Optional Hardening (Future)
- Add a per-op timeout that emits a failed CompletionEvent.
- Add bounded retries for transient network errors.

## Code Pointers
- Scheduler loop and watchdog: `src/scheduler/mod.rs`.
- Oplock wait timeout: `src/backend/mod.rs`.
