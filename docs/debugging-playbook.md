# Failure Debugging Playbook (Prompt 7)

## Minimum Telemetry
- Logs include: `client_idx`, `op_id`, completion status, latency.
- Scheduler counters: dispatches, completions, invariant_violations.
- State dump fields: heap size, pending total, in-flight count.

## Debug Dump Mode
- Enabled via scheduler config `debug_dump_on_error`.
- Triggered on invariant violation and in-flight timeout warnings.

## How to Debug
1. Check logs for invariant violations.
2. If state dumps are present, inspect pending vs in-flight counts.
3. If in-flight timeouts occur, inspect backend connectivity and oplock waits.
4. Re-run with `InvariantMode::Panic` for repro.

## Example State Dump
```
reason=invariant_violation heap_len=2 pending_total=7 inflight_total=1 dispatch_count=12 completion_count=11 invariant_violations=1
```

## Code Pointers
- State dump: `Scheduler::log_state_dump` in `src/scheduler/mod.rs`.
- Invariant mode: `InvariantMode` in `src/scheduler/mod.rs`.
