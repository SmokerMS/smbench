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

## Code Pointers
- State dump: `Scheduler::log_state_dump` in `src/scheduler/mod.rs`.
- Invariant mode: `InvariantMode` in `src/scheduler/mod.rs`.
