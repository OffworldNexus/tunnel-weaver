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

A blind interval is also the wrong shape for most of this work. The inactivity
sweep has nothing to do until the second an account falls due; certificate
renewal nothing until a certificate enters its renewal window; the garbage
sweeps reclaim rows that are already inert and can wait for a quiet hour.
Polling every hour (or every minute) only rereads the same data, and per-job
interval knobs are tuning nobody needs.

## Decision

### A `Task` picks its own instants

A task is `name()`, `async next_tick(last_tick, now) -> i64`, `async run(tick)`,
and an optional `async shutdown(now)`. All times are absolute Unix seconds.

- `next_tick` returns the exact second the task next has work. `last_tick` is
  the scheduled time of the run that just finished, or `None` when the process
  has just started, so a job catches up at boot and then follows its data. It
  is `async` because the answer usually lives in the store: the inactivity
  sweep returns the earliest warning or deletion instant after `last_tick`;
  certificate renewal the opening of the first renewal window (or a failed
  order's backoff retry); metering the next flush boundary; the garbage sweeps
  the next UTC midnight. There are no per-task interval fields or knobs.
- `run(tick)` receives the **scheduled** instant, not a clock reading. Every
  cutoff, SQL predicate and timestamp the run writes derives from that one
  value, so a tick is internally consistent and a late wake-up does not change
  what it means. A task never reads the clock inside `run`.

A task that falls behind (it slept through several of its instants) is asked
again with the real `now` and decides itself whether to replay or skip; every
task here skips, since one run settles everything due.

### One `Scheduler` type, two driving modes

- `run(shutdown)` owns the loop for the process-wide scheduler: it sleeps until
  the earliest deadline and exits on a `CancellationToken`, then calls
  `shutdown()` on each task. Metering uses `shutdown` to flush before the store
  closes.
- `next_wait()` + `run_due()` never sleep, so a connection drives its own
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
- A job wakes when its data says so, not on a fixed interval: the relay is
  idle between events, and there are no interval knobs to tune.
- A job that runs early or late by its own choice must never spin: a
  `next_tick` that could return a past instant for work it cannot do (a failed
  send, an overdue renewal already in flight) bounds it with a retry delay.
- Independent jobs no longer serialize: they run concurrently across the pool.
  They must stay independent (they are: `&self`, `Arc`-shared).
- Connection-local and process-wide timers share the seam, so both are written
  and tested the same way.

## Out of scope

Replacing the mux or `weaver-tokio` event loop — the mux is sans-IO (forbidden
from reading clocks) and the driver is the event loop, which must not sleep to
run a timer — plus per-task priorities and moving the `wall_clock` seam.
