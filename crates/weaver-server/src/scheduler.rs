//! A tiny cooperative scheduler for the relay's periodic jobs.
//!
//! Every periodic background job — the usage flush, the abuse/ALTCHA/account
//! sweeps, certificate renewal, the inactivity sweep, and each connection's own
//! timers — is a [`Task`]: a [`next_tick`](Task::next_tick) that says **when**
//! (an absolute Unix second) it next wants to run, and a [`run`](Task::run) that
//! does the work. A [`Scheduler`] holds a set of tasks, sleeps until the earliest
//! deadline and runs whatever is due.
//!
//! `next_tick` is absolute, not a duration, and is asked again after every run:
//! a task can base its next wake-up on state it just read, e.g. the inactivity
//! sweep returning `min(now + 1h, the instant the next account falls due)`
//! instead of polling on a blind interval. It is `async` for exactly that
//! reason — the state often lives in the store.
//!
//! Two ways to drive a scheduler:
//!
//! * [`Scheduler::run`] owns the loop for the process-wide scheduler: it sleeps
//!   until the next deadline and exits on a [`CancellationToken`], then calls
//!   [`Task::shutdown`] once per task — metering uses that to flush before the
//!   store closes.
//! * [`Scheduler::next_deadline`] + [`Scheduler::run_due`] never sleep, so a
//!   connection's own event loop drives its timers from a `select!` arm without
//!   the scheduler stealing the loop from the I/O.
//!
//! Deadlines are whole Unix seconds (the relay's clock everywhere): no task here
//! needs sub-second resolution, and it lets a task compare against a stored
//! timestamp directly.
//!
//! Due tasks in one pass run **concurrently** (`join_all`), so a slow sweep does
//! not hold up the metering tick beside it; they run on the runtime's worker
//! pool. A task is still never re-entered: its next deadline is only computed
//! once its `run` has returned, and the next pass does not start until every due
//! task of this one has finished.

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

/// One unit of periodic work.
#[async_trait::async_trait]
pub trait Task: Send + Sync {
    /// Stable name, for logs.
    fn name(&self) -> &'static str;

    /// The absolute Unix second at which this task wants to run next.
    ///
    /// Asked once before the first run and again after every run, so the answer
    /// may be based on state the task just read. Returning a value at or before
    /// `now` means "due now".
    async fn next_tick(&self, now: i64) -> i64;

    /// Runs one tick. Errors are the task's own concern: it logs them.
    async fn run(&self, now: i64);

    /// One last call when the scheduler stops, for a task that must flush.
    ///
    /// Default is a no-op; only the metering task overrides it.
    async fn shutdown(&self, _now: i64) {}
}

/// One task and the Unix second it is next due.
struct Entry {
    task: Arc<dyn Task>,
    next_run: i64,
}

/// A set of [`Task`]s driven by one loop.
pub struct Scheduler {
    entries: Vec<Entry>,
    /// Wall clock, injectable so tests are deterministic.
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl Scheduler {
    /// Builds a scheduler from its tasks, asking each one when it first wants
    /// to run.
    pub async fn new(tasks: Vec<Arc<dyn Task>>) -> Self {
        Self::with_clock(tasks, Arc::new(crate::wall_clock::unix_secs)).await
    }

    /// Builds a scheduler with an explicit wall clock (tests).
    pub async fn with_clock(
        tasks: Vec<Arc<dyn Task>>,
        now: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Self {
        let at = now();
        let mut entries = Vec::with_capacity(tasks.len());
        for task in tasks {
            let next_run = task.next_tick(at).await;
            entries.push(Entry { task, next_run });
        }
        Self { entries, now }
    }

    /// Adds a task, asking it when it first wants to run.
    pub async fn add(&mut self, task: Arc<dyn Task>) {
        let at = (self.now)();
        let next_run = task.next_tick(at).await;
        self.entries.push(Entry { task, next_run });
    }

    /// The Unix second the earliest task is next due, or `None` when there are
    /// no tasks.
    pub fn next_deadline(&self) -> Option<i64> {
        self.entries.iter().map(|entry| entry.next_run).min()
    }

    /// The tasks' names, in order, for the startup log line.
    pub fn names(&self) -> Vec<&'static str> {
        self.entries.iter().map(|entry| entry.task.name()).collect()
    }

    /// Runs every due task once, concurrently. Never sleeps.
    pub async fn run_due(&mut self) {
        let now = (self.now)();
        let due: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.next_run <= now)
            .map(|(index, _)| index)
            .collect();
        if due.is_empty() {
            return;
        }

        let tasks: Vec<Arc<dyn Task>> = due
            .iter()
            .map(|&index| Arc::clone(&self.entries[index].task))
            .collect();
        futures_util::future::join_all(tasks.iter().map(|task| task.run(now))).await;

        // Reschedule from the post-run clock, so a task that overran its period
        // is asked from the time it actually finished rather than piling up.
        let after = (self.now)();
        for &index in &due {
            self.entries[index].next_run = self.entries[index].task.next_tick(after).await;
        }
    }

    /// Drives the tasks until `shutdown` is cancelled, then shuts them down.
    ///
    /// This owns the loop: it sleeps until the earliest deadline and calls
    /// [`run_due`](Self::run_due). Await the task that runs this before closing
    /// the store, so a task's `shutdown` flush completes.
    pub async fn run(mut self, shutdown: CancellationToken) {
        while let Some(deadline) = self.next_deadline() {
            let now = (self.now)();
            let wait = Duration::from_secs(deadline.saturating_sub(now).max(0) as u64);
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep(wait) => self.run_due().await,
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
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    /// A clock the test can move by hand.
    #[derive(Clone)]
    struct TestClock(Arc<Mutex<i64>>);

    impl TestClock {
        fn new(at: i64) -> Self {
            Self(Arc::new(Mutex::new(at)))
        }
        fn set(&self, at: i64) {
            *self.0.lock().unwrap() = at;
        }
        fn as_fn(&self) -> Arc<dyn Fn() -> i64 + Send + Sync> {
            let cell = Arc::clone(&self.0);
            Arc::new(move || *cell.lock().unwrap())
        }
    }

    /// A task that records every `now` it runs at and reports a fixed period.
    struct Counter {
        runs: Mutex<Vec<i64>>,
        shutdowns: AtomicU64,
        period: i64,
    }

    impl Counter {
        fn new(period: i64) -> Arc<Self> {
            Arc::new(Self {
                runs: Mutex::new(Vec::new()),
                shutdowns: AtomicU64::new(0),
                period,
            })
        }
        fn runs(&self) -> Vec<i64> {
            self.runs.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl Task for Counter {
        fn name(&self) -> &'static str {
            "counter"
        }
        async fn next_tick(&self, now: i64) -> i64 {
            now + self.period
        }
        async fn run(&self, now: i64) {
            self.runs.lock().unwrap().push(now);
        }
        async fn shutdown(&self, _now: i64) {
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Two tasks that each wait for the other to start: they only both finish if
    /// the scheduler runs them concurrently.
    struct WaitsForPeer {
        me: Arc<AtomicU64>,
        peer: Arc<AtomicU64>,
        saw_peer: Arc<AtomicU64>,
    }

    #[async_trait::async_trait]
    impl Task for WaitsForPeer {
        fn name(&self) -> &'static str {
            "waits-for-peer"
        }
        async fn next_tick(&self, now: i64) -> i64 {
            now
        }
        async fn run(&self, _now: i64) {
            self.me.store(1, Ordering::SeqCst);
            for _ in 0..100_000 {
                if self.peer.load(Ordering::SeqCst) == 1 {
                    self.saw_peer.store(1, Ordering::SeqCst);
                    return;
                }
                tokio::task::yield_now().await;
            }
        }
    }

    fn as_task<T: Task + 'static>(task: Arc<T>) -> Arc<dyn Task> {
        task
    }

    #[tokio::test]
    async fn the_first_run_is_at_the_tasks_next_tick() {
        let clock = TestClock::new(1000);
        let task = Counter::new(60);
        let mut scheduler = Scheduler::with_clock(vec![as_task(task.clone())], clock.as_fn()).await;

        // The first deadline is what the task asked for, not "now".
        assert_eq!(scheduler.next_deadline(), Some(1060));
        scheduler.run_due().await;
        assert!(task.runs().is_empty(), "not due before its date");

        clock.set(1060);
        scheduler.run_due().await;
        assert_eq!(task.runs(), vec![1060]);
        // The next deadline is derived from the state after the run.
        assert_eq!(scheduler.next_deadline(), Some(1120));
    }

    #[tokio::test]
    async fn every_due_task_runs_in_one_pass() {
        let clock = TestClock::new(0);
        let first = Counter::new(60);
        let second = Counter::new(60);
        let mut scheduler = Scheduler::with_clock(
            vec![as_task(first.clone()), as_task(second.clone())],
            clock.as_fn(),
        )
        .await;

        clock.set(60);
        scheduler.run_due().await;
        assert_eq!(first.runs(), vec![60]);
        assert_eq!(second.runs(), vec![60]);
    }

    #[tokio::test]
    async fn due_tasks_run_concurrently() {
        let clock = TestClock::new(0);
        let a_started = Arc::new(AtomicU64::new(0));
        let b_started = Arc::new(AtomicU64::new(0));
        let a = Arc::new(WaitsForPeer {
            me: Arc::clone(&a_started),
            peer: Arc::clone(&b_started),
            saw_peer: Arc::new(AtomicU64::new(0)),
        });
        let b = Arc::new(WaitsForPeer {
            me: Arc::clone(&b_started),
            peer: Arc::clone(&a_started),
            saw_peer: Arc::new(AtomicU64::new(0)),
        });
        let mut scheduler =
            Scheduler::with_clock(vec![as_task(a.clone()), as_task(b.clone())], clock.as_fn())
                .await;

        scheduler.run_due().await;
        assert_eq!(a.saw_peer.load(Ordering::SeqCst), 1);
        assert_eq!(b.saw_peer.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn run_waits_to_its_deadline_and_shuts_down_on_cancel() {
        let clock = TestClock::new(0);
        let task = Counter::new(3600);
        let scheduler = Scheduler::with_clock(vec![as_task(task.clone())], clock.as_fn()).await;
        let token = CancellationToken::new();

        let handle = tokio::spawn(scheduler.run(token.clone()));
        // The only deadline is an hour out, so nothing runs before we cancel.
        tokio::task::yield_now().await;
        assert!(task.runs().is_empty());

        token.cancel();
        handle.await.unwrap();
        assert!(task.runs().is_empty());
        assert_eq!(task.shutdowns.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_empty_scheduler_returns_immediately() {
        let scheduler = Scheduler::new(Vec::new()).await;
        assert_eq!(scheduler.next_deadline(), None);
        scheduler.run(CancellationToken::new()).await;
    }
}
