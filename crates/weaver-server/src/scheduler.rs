//! A tiny cooperative scheduler for the relay's periodic jobs.
//!
//! Every background job — the usage meter, the store sweeps, certificate
//! renewal, the inactivity sweep, and each connection's own timers — is a
//! [`Task`]. A task is not "something that runs every N seconds": it is
//! something that **picks the instant it next has work to do**. The inactivity
//! sweep wakes exactly when the next account falls due, certificate renewal
//! exactly when the first certificate enters its renewal window, the garbage
//! sweeps at UTC midnight. A fixed period is just the degenerate case (the SSE
//! heartbeat).
//!
//! The contract:
//!
//! * [`Task::next_tick`]`(last_tick, now)` returns the absolute Unix second of
//!   the next run. `last_tick` is the scheduled time of the run that just
//!   finished, or `None` when the process has just started, so a task can catch
//!   up at boot and then follow its data. It is `async` because the answer often
//!   lives in the store.
//! * [`Task::run`]`(tick)` receives the **scheduled** time of the tick — the
//!   instant `next_tick` asked for — never a fresh clock reading. Everything the
//!   run does (cutoffs, SQL predicates, timestamps it writes) is computed from
//!   that one value, so a tick is internally consistent and a late wake-up does
//!   not shift its semantics.
//!
//! Two ways to drive a scheduler:
//!
//! * [`Scheduler::run`] owns the loop for the process-wide scheduler: it sleeps
//!   until the earliest deadline, exits on a [`CancellationToken`], then calls
//!   [`Task::shutdown`] once per task — metering flushes there.
//! * [`Scheduler::next_wait`] + [`Scheduler::run_due`] never sleep, so a
//!   connection's own event loop drives its timers from a `select!` arm.
//!
//! Due tasks in one pass run concurrently (`join_all`) on the runtime's worker
//! pool. A task is never re-entered: its next deadline is asked only once its
//! `run` has returned.

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

/// Seconds in a UTC day.
pub const DAY: i64 = 86_400;

/// The first UTC midnight strictly after `now` (Unix seconds).
pub fn next_midnight(now: i64) -> i64 {
    (now.div_euclid(DAY) + 1) * DAY
}

/// One unit of scheduled work.
#[async_trait::async_trait]
pub trait Task: Send + Sync {
    /// Stable name, for logs.
    fn name(&self) -> &'static str;

    /// The absolute Unix second at which this task next has work to do.
    ///
    /// `last_tick` is the scheduled time of the run that just finished, `None`
    /// before the first run (the process just started). `now` is the clock.
    /// A value at or before `now` means "due now".
    async fn next_tick(&self, last_tick: Option<i64>, now: i64) -> i64;

    /// Runs the tick scheduled for `tick` (Unix seconds). Base every cutoff and
    /// timestamp on `tick`; do not read the clock. Errors are logged here.
    async fn run(&self, tick: i64);

    /// One last call when the scheduler stops, at `now`, for a task that must
    /// flush. Default is a no-op; only metering overrides it.
    async fn shutdown(&self, _now: i64) {}
}

/// One task and when it is next due.
struct Entry {
    task: Arc<dyn Task>,
    next_run: i64,
}

/// A wall clock in Unix milliseconds, injectable so tests are deterministic.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// A set of [`Task`]s driven by one loop.
pub struct Scheduler {
    entries: Vec<Entry>,
    clock_ms: Clock,
}

impl Scheduler {
    /// Builds a scheduler on the wall clock, asking each task for its first
    /// tick.
    pub async fn new(tasks: Vec<Arc<dyn Task>>) -> Self {
        Self::with_clock(tasks, Arc::new(crate::wall_clock::unix_ms)).await
    }

    /// Builds a scheduler on an explicit millisecond clock (tests).
    pub async fn with_clock(tasks: Vec<Arc<dyn Task>>, clock_ms: Clock) -> Self {
        let now = clock_ms().div_euclid(1000);
        let mut entries = Vec::with_capacity(tasks.len());
        for task in tasks {
            let next_run = task.next_tick(None, now).await;
            entries.push(Entry { task, next_run });
        }
        Self { entries, clock_ms }
    }

    fn now(&self) -> i64 {
        (self.clock_ms)().div_euclid(1000)
    }

    /// The Unix second the earliest task is next due, `None` with no tasks.
    pub fn next_deadline(&self) -> Option<i64> {
        self.entries.iter().map(|entry| entry.next_run).min()
    }

    /// How long until the earliest deadline, `None` with no tasks.
    pub fn next_wait(&self) -> Option<Duration> {
        let deadline_ms = self.next_deadline()?.saturating_mul(1000);
        let wait_ms = deadline_ms.saturating_sub((self.clock_ms)()).max(0);
        Some(Duration::from_millis(wait_ms as u64))
    }

    /// The tasks' names, in order, for the startup log line.
    pub fn names(&self) -> Vec<&'static str> {
        self.entries.iter().map(|entry| entry.task.name()).collect()
    }

    /// Runs every due task once, concurrently, each at its own scheduled tick.
    /// Never sleeps.
    pub async fn run_due(&mut self) {
        let now = self.now();
        let due: Vec<(usize, i64)> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.next_run <= now)
            .map(|(index, entry)| (index, entry.next_run))
            .collect();
        if due.is_empty() {
            return;
        }

        let runs: Vec<(Arc<dyn Task>, i64)> = due
            .iter()
            .map(|&(index, tick)| (Arc::clone(&self.entries[index].task), tick))
            .collect();
        futures_util::future::join_all(runs.iter().map(|(task, tick)| task.run(*tick))).await;

        let now = self.now();
        for (index, tick) in due {
            self.entries[index].next_run =
                self.entries[index].task.next_tick(Some(tick), now).await;
        }
    }

    /// Drives the tasks until `shutdown` is cancelled, then shuts them down.
    ///
    /// Await the task that runs this before closing the store, so a task's
    /// `shutdown` flush completes.
    pub async fn run(mut self, shutdown: CancellationToken) {
        while let Some(wait) = self.next_wait() {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep(wait) => self.run_due().await,
            }
        }
        let now = self.now();
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

    /// A clock the test moves by hand, in seconds.
    #[derive(Clone)]
    struct TestClock(Arc<Mutex<i64>>);

    impl TestClock {
        fn new(at: i64) -> Self {
            Self(Arc::new(Mutex::new(at)))
        }
        fn set(&self, at: i64) {
            *self.0.lock().unwrap() = at;
        }
        fn as_clock(&self) -> Clock {
            let cell = Arc::clone(&self.0);
            Arc::new(move || *cell.lock().unwrap() * 1000)
        }
    }

    /// Records every `(last_tick, now)` it is asked and every tick it runs; its
    /// schedule is a fixed list of instants, the way a data-driven task picks
    /// "when the next thing falls due".
    struct Agenda {
        at: Vec<i64>,
        asked: Mutex<Vec<(Option<i64>, i64)>>,
        runs: Mutex<Vec<i64>>,
        shutdowns: AtomicU64,
    }

    impl Agenda {
        fn new(at: Vec<i64>) -> Arc<Self> {
            Arc::new(Self {
                at,
                asked: Mutex::new(Vec::new()),
                runs: Mutex::new(Vec::new()),
                shutdowns: AtomicU64::new(0),
            })
        }
        fn runs(&self) -> Vec<i64> {
            self.runs.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl Task for Agenda {
        fn name(&self) -> &'static str {
            "agenda"
        }
        async fn next_tick(&self, last_tick: Option<i64>, now: i64) -> i64 {
            self.asked.lock().unwrap().push((last_tick, now));
            let after = last_tick.unwrap_or(i64::MIN);
            self.at
                .iter()
                .copied()
                .find(|&at| at > after)
                .unwrap_or(i64::MAX)
        }
        async fn run(&self, tick: i64) {
            self.runs.lock().unwrap().push(tick);
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
        saw_peer: AtomicU64,
    }

    #[async_trait::async_trait]
    impl Task for WaitsForPeer {
        fn name(&self) -> &'static str {
            "waits-for-peer"
        }
        async fn next_tick(&self, last_tick: Option<i64>, now: i64) -> i64 {
            if last_tick.is_none() { now } else { i64::MAX }
        }
        async fn run(&self, _tick: i64) {
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

    #[test]
    fn next_midnight_is_strictly_after() {
        assert_eq!(next_midnight(0), DAY);
        assert_eq!(next_midnight(DAY - 1), DAY);
        assert_eq!(next_midnight(DAY), 2 * DAY);
    }

    #[tokio::test]
    async fn the_first_ask_says_the_process_just_started() {
        let clock = TestClock::new(1000);
        let task = Agenda::new(vec![1500]);
        let scheduler = Scheduler::with_clock(vec![as_task(task.clone())], clock.as_clock()).await;
        assert_eq!(*task.asked.lock().unwrap(), vec![(None, 1000)]);
        assert_eq!(scheduler.next_deadline(), Some(1500));
    }

    #[tokio::test]
    async fn run_gets_the_scheduled_tick_not_the_clock() {
        let clock = TestClock::new(1000);
        let task = Agenda::new(vec![1500, 4000]);
        let mut scheduler =
            Scheduler::with_clock(vec![as_task(task.clone())], clock.as_clock()).await;

        scheduler.run_due().await;
        assert!(task.runs().is_empty(), "not due before its instant");

        // The scheduler wakes late; the run still sees the instant it asked for.
        clock.set(1507);
        scheduler.run_due().await;
        assert_eq!(task.runs(), vec![1500]);
        // And the task is told which tick just ran, plus the real clock.
        assert_eq!(task.asked.lock().unwrap().last(), Some(&(Some(1500), 1507)));
        assert_eq!(scheduler.next_deadline(), Some(4000));
    }

    #[tokio::test]
    async fn due_tasks_run_concurrently() {
        let clock = TestClock::new(0);
        let a_started = Arc::new(AtomicU64::new(0));
        let b_started = Arc::new(AtomicU64::new(0));
        let a = Arc::new(WaitsForPeer {
            me: Arc::clone(&a_started),
            peer: Arc::clone(&b_started),
            saw_peer: AtomicU64::new(0),
        });
        let b = Arc::new(WaitsForPeer {
            me: Arc::clone(&b_started),
            peer: Arc::clone(&a_started),
            saw_peer: AtomicU64::new(0),
        });
        let mut scheduler = Scheduler::with_clock(
            vec![as_task(a.clone()), as_task(b.clone())],
            clock.as_clock(),
        )
        .await;

        scheduler.run_due().await;
        assert_eq!(a.saw_peer.load(Ordering::SeqCst), 1);
        assert_eq!(b.saw_peer.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn run_waits_for_its_deadline_and_shuts_down_on_cancel() {
        let clock = TestClock::new(0);
        let task = Agenda::new(vec![3600]);
        let scheduler = Scheduler::with_clock(vec![as_task(task.clone())], clock.as_clock()).await;
        let token = CancellationToken::new();

        let handle = tokio::spawn(scheduler.run(token.clone()));
        tokio::task::yield_now().await;
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
