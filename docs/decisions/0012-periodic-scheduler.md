# 12. Periodic work runs under one scheduler

Date: 2026-10-23

## Status

Accepted. Introduces the `Task`/`Scheduler` seam; WVR-160's inactivity sweep is
the first job written against it.

## Context

The relay grew a handful of independent `tokio::spawn(interval-loop)` blocks:
usage metering (1 s tick, 60 s flush), the abuse bucket sweep (10 min), the
ALTCHA proof sweep, the account token/session/key-log sweep, the inactivity
sweep, and certificate renewal (12 h). Each re-implemented the same shape —
build an interval, `select!` on a shutdown token, log its own failures — so the
relay's periodic work was discoverable only by grepping for `tokio::spawn`, and
every new job copied the boilerplate. Connections separately grew their own
timers (the 5 s visitor byte report, the 15 s SSE heartbeat) that had to
interleave with I/O in a `select!`.

## Decision

### A `Task` is the unit of periodic work

A task is `name()`, `next_tick(now) -> Duration`, `async run(now)`, and an
optional `async shutdown(now)`. `now` is Unix seconds, matching the
store/sweep signatures the tasks already take. Errors are the task's own
concern: it logs them, so a failing job never stops the scheduler.

### One `Scheduler` type, two driving modes

- `run(shutdown)` owns the loop for a process-wide scheduler: it sleeps until
  the earliest deadline and exits on a `CancellationToken`, then calls
  `shutdown()` on each task. Metering uses `shutdown` to flush before the store
  closes.
- `next_deadline()` + `run_due()` never sleep, so a connection drives its own
  timers from a `select!` arm without the scheduler taking the I/O loop from it.

Tasks run **sequentially and are never re-entered**: a task's next deadline is
computed only after its `run` returns, so a slow job delays the others rather
than overlapping itself. The sweeps are bounded batches, so this is acceptable.

### First tick

`Scheduler::new` runs every task once immediately, matching
`tokio::time::interval`. `Scheduler::staggered` delays the first run one full
period, matching `interval_at(now + period, period)`; the SSE heartbeat uses it
so the first frame is not tagged with a heartbeat.

### Where the tasks live

The global instance is assembled once in `server::run` and awaited in the drain.
Metering and certificate renewal keep their tasks next to what they drive
(`metering::MeteringTask`, `cert::CertRenewalTask`); the store-backed sweeps live
in `housekeeping`.

## Consequences

- The relay's periodic work is described in one place — the task list in
  `server::run` — and adding a job is one `Task` impl.
- A slow job delays the others in the same scheduler; the metering accrual is
  elapsed-time based, so a delayed tick loses no open time.
- Connection-local and process-wide timers share the seam, so both are written
  and tested the same way.

## Out of scope

Replacing the mux or `weaver-tokio` event loop — the mux is sans-IO (forbidden
from reading clocks) and the driver is the event loop, which must not sleep to
run a timer — plus per-task priorities, running tasks concurrently within a
scheduler, and moving the `wall_clock` seam.
