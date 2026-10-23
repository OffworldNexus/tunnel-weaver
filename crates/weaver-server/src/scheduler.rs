//! A tiny cooperative scheduler for the relay's periodic jobs.
//!
//! Every periodic background job — the usage flush, the abuse/ALTCHA/account
//! sweeps, certificate renewal, the inactivity sweep, and each connection's own
//! timers — is a [`Task`]: a [`next_tick`](Task::next_tick) that says when it
//! next wants to run and a [`run`](Task::run) that does the work. A
//! [`Scheduler`] holds a set of tasks, wakes at the earliest deadline and runs
//! whatever is due. That replaces the handful of ad-hoc
//! `tokio::spawn(interval-loop)` blocks so the relay's periodic work is
//! described in one place.
//!
//! Two ways to drive it:
//!
//! * [`Scheduler::run`] owns the loop for a process-wide scheduler: it sleeps
//!   until the next deadline and exits on a [`CancellationToken`], then calls
//!   [`Task::shutdown`] once per task — metering uses that to flush before the
//!   store closes.
//! * [`Scheduler::next_deadline`] + [`Scheduler::run_due`] never sleep, so a
//!   connection's own event loop drives its timers from a `select!` arm without
//!   the scheduler stealing the loop from the I/O.
//!
//! Tasks run sequentially and are never re-entered: a task's next deadline is
//! computed only after its `run` returns, so a slow job delays the others rather
//! than overlapping itself.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// One unit of periodic work.
#[async_trait::async_trait]
pub trait Task: Send + Sync {
    /// Stable name, for logs.
    fn name(&self) -> &'static str;

    /// How long after `now` (Unix seconds) this task next wants to run.
    fn next_tick(&self, now: i64) -> Duration;

    /// Runs one tick. Errors are the task's own concern: it logs them.
    async fn run(&self, now: i64);

    /// One last call when the scheduler stops, for a task that must flush.
    ///
    /// Default is a no-op; only the metering task overrides it.
    async fn shutdown(&self, _now: i64) {}
}

/// One task and when it is next due.
struct Entry {
    task: Arc<dyn Task>,
    next: Instant,
}

/// A set of [`Task`]s driven by one loop.
pub struct Scheduler {
    entries: Vec<Entry>,
    /// Wall clock, injectable so tests are deterministic.
    now: fn() -> i64,
}

impl Scheduler {
    /// Builds a scheduler whose tasks all run once immediately, matching
    /// `tokio::time::interval`'s first-tick behaviour.
    pub fn new(tasks: Vec<Arc<dyn Task>>) -> Self {
        Self::with_clock(tasks, crate::wall_clock::unix_secs)
    }

    /// Like [`new`](Self::new), but every task's first run is one full
    /// `next_tick` away, matching `interval_at(now + period, period)`.
    pub fn staggered(tasks: Vec<Arc<dyn Task>>) -> Self {
        let mut scheduler = Self::new(tasks);
        let now = (scheduler.now)();
        for entry in &mut scheduler.entries {
            entry.next = Instant::now() + entry.task.next_tick(now);
        }
        scheduler
    }

    /// Builds a scheduler with an explicit wall clock (tests).
    pub fn with_clock(tasks: Vec<Arc<dyn Task>>, now: fn() -> i64) -> Self {
        let at = Instant::now();
        Self {
            entries: tasks
                .into_iter()
                .map(|task| Entry { task, next: at })
                .collect(),
            now,
        }
    }

    /// Adds a task, due immediately.
    pub fn add(&mut self, task: Arc<dyn Task>) {
        self.entries.push(Entry {
            task,
            next: Instant::now(),
        });
    }

    /// When the earliest task is next due, or `None` when there are no tasks.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.entries.iter().map(|entry| entry.next).min()
    }

    /// The tasks' names, in order, for the startup log line.
    pub fn names(&self) -> Vec<&'static str> {
        self.entries.iter().map(|entry| entry.task.name()).collect()
    }

    /// Runs every due task once, sequentially. Never sleeps.
    pub async fn run_due(&mut self) {
        let at = Instant::now();
        let now = (self.now)();
        for entry in &mut self.entries {
            if entry.next <= at {
                entry.task.run(now).await;
                entry.next = Instant::now() + entry.task.next_tick(now);
            }
        }
    }

    /// Drives the tasks until `shutdown` is cancelled, then shuts them down.
    ///
    /// This owns the loop: it sleeps until the earliest deadline and calls
    /// [`run_due`](Self::run_due). Await the task that runs this before closing
    /// the store, so a task's `shutdown` flush completes.
    pub async fn run(mut self, shutdown: CancellationToken) {
        while let Some(deadline) = self.next_deadline() {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep_until(deadline) => self.run_due().await,
            }
        }
        let now = (self.now)();
        for entry in &self.entries {
            entry.task.shutdown(now).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

    use super::*;

    /// A task that counts its runs and reports a fixed period.
    struct Counter {
        ticks: AtomicU64,
        shutdowns: AtomicU64,
        last_now: AtomicI64,
        period: Duration,
    }

    impl Counter {
        fn new(period_secs: u64) -> Arc<Self> {
            Arc::new(Self {
                ticks: AtomicU64::new(0),
                shutdowns: AtomicU64::new(0),
                last_now: AtomicI64::new(-1),
                period: Duration::from_secs(period_secs),
            })
        }

        fn ticks(&self) -> u64 {
            self.ticks.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl Task for Counter {
        fn name(&self) -> &'static str {
            "counter"
        }
        fn next_tick(&self, _now: i64) -> Duration {
            self.period
        }
        async fn run(&self, now: i64) {
            self.ticks.fetch_add(1, Ordering::SeqCst);
            self.last_now.store(now, Ordering::SeqCst);
        }
        async fn shutdown(&self, _now: i64) {
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn as_task(task: Arc<Counter>) -> Arc<dyn Task> {
        task
    }

    #[tokio::test]
    async fn runs_immediately_then_not_before_the_period() {
        let task = Counter::new(3600);
        let mut scheduler = Scheduler::with_clock(vec![as_task(task.clone())], || 0);

        scheduler.run_due().await;
        assert_eq!(task.ticks(), 1, "the first tick is immediate");

        // The next deadline moved a full period into the future, so an
        // immediate second pass runs nothing.
        assert!(scheduler.next_deadline().unwrap() > Instant::now());
        scheduler.run_due().await;
        assert_eq!(task.ticks(), 1);
    }

    #[tokio::test]
    async fn staggered_waits_a_full_period_before_the_first_run() {
        let task = Counter::new(3600);
        let mut scheduler = Scheduler::staggered(vec![as_task(task.clone())]);

        scheduler.run_due().await;
        assert_eq!(task.ticks(), 0, "staggered tasks do not fire immediately");
        assert!(scheduler.next_deadline().unwrap() > Instant::now());
    }

    #[tokio::test]
    async fn every_due_task_runs_in_one_pass() {
        let first = Counter::new(60);
        let second = Counter::new(60);
        let mut scheduler =
            Scheduler::with_clock(vec![as_task(first.clone()), as_task(second.clone())], || 0);

        assert!(
            scheduler.next_deadline().unwrap() <= Instant::now(),
            "both tasks are due immediately"
        );
        scheduler.run_due().await;
        assert_eq!(first.ticks(), 1);
        assert_eq!(second.ticks(), 1);
    }

    #[tokio::test]
    async fn run_passes_the_injected_clock_to_tasks() {
        let task = Counter::new(60);
        let mut scheduler = Scheduler::with_clock(vec![as_task(task.clone())], || 1234);
        scheduler.run_due().await;
        assert_eq!(task.last_now.load(Ordering::SeqCst), 1234);
    }

    #[tokio::test]
    async fn run_loop_fires_then_shuts_down_on_cancel() {
        let task = Counter::new(3600);
        let scheduler = Scheduler::with_clock(vec![as_task(task.clone())], || 0);
        let token = CancellationToken::new();

        let handle = tokio::spawn(scheduler.run(token.clone()));
        // The first tick is immediate; let the spawned loop reach it.
        for _ in 0..1000 {
            if task.ticks() >= 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(task.ticks() >= 1, "the loop fired its immediate first tick");

        token.cancel();
        handle.await.unwrap();
        assert_eq!(task.shutdowns.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_empty_scheduler_returns_immediately() {
        let scheduler = Scheduler::new(Vec::new());
        assert_eq!(scheduler.next_deadline(), None);
        scheduler.run(CancellationToken::new()).await;
    }
}
