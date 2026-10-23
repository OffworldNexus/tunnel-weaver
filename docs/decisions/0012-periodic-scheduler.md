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

A blind interval is also the wrong shape for a job whose cadence depends on
state: the inactivity sweep wants to wake when the next account actually falls
due, not to poll every hour.

## Decision

### A `Task` says *when*, not *how often*

A task is `name()`, `async next_tick(now) -> i64`, `async run(now)`, and an
optional `async shutdown(now)`. `now` and the returned deadline are **absolute
Unix seconds** — the relay's clock everywhere — so a task compares directly
against a stored timestamp; no task here needs sub-second resolution.

`next_tick` is asked once before the first run and again after every run, and it
is `async` on purpose: the answer may be based on state the task just read. The
inactivity sweep, for example, returns
`min(now + poll_ceiling, the instant the next account falls due)` instead of
polling on a fixed interval. Returning a value at or before `now` means "due
now".

### One `Scheduler` type, two driving modes

- `run(shutdown)` owns the loop for the process-wide scheduler: it sleeps until
  the earliest deadline and exits on a `CancellationToken`, then calls
  `shutdown()` on each task. Metering uses `shutdown` to flush before the store
  closes.
- `next_deadline()` + `run_due()` never sleep, so a connection drives its own
  timers from a `select!` arm without the scheduler taking the I/O loop from it.

Due tasks in one pass run **concurrently** (`join_all`), so a slow sweep does not
hold up the metering tick beside it; they run on the runtime's worker pool. A
task is never re-entered: its next deadline is computed only after its `run`
returns, and the next pass does not start until every due task of this one has
finished.

### Where the tasks live

The global instance is assembled once in `server::run` and awaited in the drain.
Metering and certificate renewal keep their tasks next to what they drive
(`metering::MeteringTask`, `cert::CertRenewalTask`); the store-backed sweeps live
in `housekeeping`.

## Consequences

- The relay's periodic work is described in one place — the task list in
  `server::run` — and adding a job is one `Task` impl.
- A job's cadence can follow its data instead of a fixed interval, because
  `next_tick` is absolute and may consult the store.
- Independent jobs no longer serialize: they run concurrently across the pool.
  They must stay independent (they are: `&self`, `Arc`-shared).
- Connection-local and process-wide timers share the seam, so both are written
  and tested the same way.

## Out of scope

Replacing the mux or `weaver-tokio` event loop — the mux is sans-IO (forbidden
from reading clocks) and the driver is the event loop, which must not sleep to
run a timer — plus per-task priorities and moving the `wall_clock` seam.
