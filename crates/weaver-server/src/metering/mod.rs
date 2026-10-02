//! Per-service usage metering.
//!
//! [`MeteringManager`] owns the whole metering concern, so no other module
//! touches usage rows directly:
//!
//! * the **first layer**, an in-memory `(service_id, minute)` aggregation of
//!   traffic counters and registered open time;
//! * the **flush job**, a 1 s ticker that accrues open time and periodically
//!   writes *closed* minutes to the [`Store`], with a final flush of the
//!   partial current minute on shutdown;
//! * the **persistence surface**, the only caller of the store's usage
//!   upsert/query (so the store's inversion of `unused_ms` never leaks).
//!
//! Callers report observations through the clock-free methods: the relay calls
//! [`record_request`](MeteringManager::record_request) when it opens a visitor
//! stream, [`register_stream`](MeteringManager::register_stream) to map that
//! stream to its service, and [`unregister_stream`](MeteringManager::unregister_stream)
//! when it closes. Byte counts arrive by push: the manager publishes itself as
//! the mux's [`StreamBytesSink`] via [`MeteringManager::sink`], so every DATA
//! payload the mux moves calls [`stream_bytes`](MeteringManager::stream_bytes)
//! at the moment it flows. The manager stamps all observations with its own
//! clock; deterministic tests drive the private `*_at(now_ms)` variants.
//!
//! Timing rules (OFF-76):
//! * A minute key is `unix_ms / 60_000`, tagged at observation time, so a late
//!   or missed tick never moves data between buckets.
//! * Byte reports are per-flow deltas tagged when they flow, so a long-lived
//!   stream lands each byte in the minute it actually moved.
//! * Open time is accrue-on-tick: the ticker adds the *actual* wall-clock
//!   elapsed for each registered service, splitting at minute boundaries and
//!   clamping each bucket's `open_ms` to `0..=60_000`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::warn;
use weaver_mux::{StreamBytesSink, StreamId};

use crate::store::Store;
use crate::store::StoreError;
use crate::store::usage::UsageRow;

pub use crate::store::usage::UsageTotal;

/// Length of a metering minute, in milliseconds.
const MINUTE_MS: i64 = 60_000;

/// How often the manager accrues open time and checks for a flush.
const TICK: Duration = Duration::from_secs(1);

/// Counters accumulated for one `(service_id, minute)` bucket.
#[derive(Debug, Clone, Copy, Default)]
struct Bucket {
    bytes_in: u64,
    bytes_out: u64,
    requests: u64,
    /// Milliseconds the service was registered during this minute, `0..=60000`.
    open_ms: u32,
}

/// Open-time bookkeeping for a currently-registered service.
#[derive(Debug, Clone, Copy)]
struct Open {
    /// Unix ms up to which open time has already been accrued.
    accounted_ms: i64,
}

#[derive(Default)]
struct Inner {
    buckets: HashMap<(i32, i64), Bucket>,
    registered: HashMap<i32, Open>,
    /// Which service each currently-open stream belongs to, so byte reports
    /// from the mux (which only knows the stream id) can be attributed.
    streams: HashMap<StreamId, i32>,
}

/// Owns traffic metering and its periodic persistence.
///
/// Cheap to share behind an `Arc`: every observation method takes `&self`.
pub struct MeteringManager {
    store: Store,
    flush_interval: Duration,
    inner: Mutex<Inner>,
}

impl MeteringManager {
    /// Creates a manager that flushes every `flush_interval`.
    pub fn new(store: Store, flush_interval: Duration) -> Self {
        Self {
            store,
            flush_interval,
            inner: Mutex::new(Inner::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A panicking holder cannot leave the counters in a torn state (every
        // update is a single field write under the lock), so recover rather
        // than propagate the poison and take the whole server down.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Records one visitor request (a `Head::Http` stream opened by the relay).
    pub fn record_request(&self, service_id: i32) {
        self.record_request_at(service_id, unix_ms());
    }

    /// Registers an open stream's owning service so the mux's byte reports for
    /// that stream can be attributed. Called by the relay when it opens the
    /// stream, before any bytes flow.
    pub fn register_stream(&self, stream_id: StreamId, service_id: i32) {
        self.lock().streams.insert(stream_id, service_id);
    }

    /// Forgets a stream once it is closed (or the connection ends).
    pub fn unregister_stream(&self, stream_id: StreamId) {
        self.lock().streams.remove(&stream_id);
    }

    /// Reports DATA payload bytes the mux observed flowing on a stream.
    ///
    /// This is the mux's push callback: called the moment bytes flow, so a
    /// long-lived stream is attributed to the minute each byte actually moved.
    pub fn stream_bytes(&self, stream_id: StreamId, bytes_in: u64, bytes_out: u64) {
        self.stream_bytes_at(stream_id, unix_ms(), bytes_in, bytes_out);
    }

    /// Publishes this manager as the mux's byte sink.
    pub fn sink(self: &Arc<Self>) -> Arc<dyn StreamBytesSink> {
        Arc::new(ManagerSink {
            manager: Arc::clone(self),
        })
    }

    /// Marks a service as registered; open time starts accruing from now.
    pub fn register_service(&self, service_id: i32) {
        self.register_service_at(service_id, unix_ms());
    }

    /// Marks a service as no longer registered, accruing its final open slice.
    pub fn unregister_service(&self, service_id: i32) {
        self.unregister_service_at(service_id, unix_ms());
    }

    /// Aggregated per-service usage over `[since_secs, until_secs)`, optionally
    /// filtered by person and/or service name.
    ///
    /// The window arrives as absolute Unix seconds and is converted to minute
    /// numbers here. An unknown person or service name matches nothing and
    /// yields an empty result, not an error.
    pub async fn query(
        &self,
        person: Option<&str>,
        service: Option<&str>,
        since_secs: i64,
        until_secs: i64,
    ) -> Result<Vec<UsageTotal>, StoreError> {
        self.store
            .query_usage(
                person,
                service,
                since_secs.div_euclid(60),
                until_secs.div_euclid(60),
            )
            .await
    }

    /// Flushes every in-memory bucket, including the partial current minute.
    ///
    /// The periodic flush only writes closed minutes; this is the on-demand
    /// variant used at shutdown and by tests.
    pub async fn flush(&self) -> Result<(), StoreError> {
        self.flush_at(true, unix_ms()).await
    }

    /// Spawns the flush job, returning its handle.
    ///
    /// The job ticks once a second, flushing on the configured cadence, and on
    /// `shutdown` performs a final flush that includes the partial current
    /// minute. Await the returned handle before closing the store.
    pub fn start(self: &Arc<Self>, shutdown: CancellationToken) -> JoinHandle<()> {
        let manager = Arc::clone(self);
        tokio::spawn(async move { manager.run(shutdown).await })
    }

    // ------------------------------------------------------------------
    // Internals (explicitly timed, so tests are deterministic)
    // ------------------------------------------------------------------

    fn record_request_at(&self, service_id: i32, now_ms: i64) {
        let mut inner = self.lock();
        let bucket = inner
            .buckets
            .entry((service_id, minute_of(now_ms)))
            .or_default();
        bucket.requests = bucket.requests.saturating_add(1);
    }

    fn stream_bytes_at(&self, stream_id: StreamId, now_ms: i64, bytes_in: u64, bytes_out: u64) {
        let mut inner = self.lock();
        let Some(&service_id) = inner.streams.get(&stream_id) else {
            return;
        };
        let bucket = inner
            .buckets
            .entry((service_id, minute_of(now_ms)))
            .or_default();
        bucket.bytes_in = bucket.bytes_in.saturating_add(bytes_in);
        bucket.bytes_out = bucket.bytes_out.saturating_add(bytes_out);
    }

    fn register_service_at(&self, service_id: i32, now_ms: i64) {
        let mut inner = self.lock();
        // Idempotent: a service already registered keeps its running clock so
        // a redundant register cannot erase the elapsed time since the last
        // tick.
        inner.registered.entry(service_id).or_insert(Open {
            accounted_ms: now_ms,
        });
    }

    fn unregister_service_at(&self, service_id: i32, now_ms: i64) {
        let mut inner = self.lock();
        accrue(&mut inner, service_id, now_ms);
        inner.registered.remove(&service_id);
    }

    fn tick_at(&self, now_ms: i64) {
        let mut inner = self.lock();
        let ids: Vec<i32> = inner.registered.keys().copied().collect();
        for id in ids {
            accrue(&mut inner, id, now_ms);
        }
    }

    async fn flush_at(&self, include_current: bool, now_ms: i64) -> Result<(), StoreError> {
        let now_minute = minute_of(now_ms);
        let drained: Vec<((i32, i64), Bucket)> = {
            let mut inner = self.lock();
            let keys: Vec<(i32, i64)> = inner
                .buckets
                .keys()
                .copied()
                .filter(|(_, m)| include_current || *m < now_minute)
                .collect();
            keys.into_iter()
                .filter_map(|key| inner.buckets.remove(&key).map(|b| (key, b)))
                .collect()
        };
        if drained.is_empty() {
            return Ok(());
        }
        let rows: Vec<UsageRow> = drained
            .iter()
            .map(|((service_id, minute), b)| UsageRow {
                service_id: *service_id,
                minute: *minute,
                bytes_in: b.bytes_in as i64,
                bytes_out: b.bytes_out as i64,
                requests: b.requests as i64,
                open_ms: b.open_ms as i64,
            })
            .collect();
        if let Err(e) = self.store.upsert_usage_batch(&rows).await {
            // The transaction rolled back; put the buckets back so a later
            // flush retries them instead of losing the data.
            let mut inner = self.lock();
            for (key, bucket) in drained {
                let b = inner.buckets.entry(key).or_default();
                b.bytes_in = b.bytes_in.saturating_add(bucket.bytes_in);
                b.bytes_out = b.bytes_out.saturating_add(bucket.bytes_out);
                b.requests = b.requests.saturating_add(bucket.requests);
                b.open_ms = (b.open_ms as i64 + bucket.open_ms as i64).clamp(0, MINUTE_MS) as u32;
            }
            return Err(e);
        }
        Ok(())
    }

    async fn run(self: Arc<Self>, shutdown: CancellationToken) {
        let mut ticker = tokio::time::interval(TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last = Instant::now();
        let mut since_flush = Duration::ZERO;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = ticker.tick() => {
                    let now = Instant::now();
                    since_flush += now.saturating_duration_since(last);
                    last = now;
                    let now_ms = unix_ms();
                    self.tick_at(now_ms);
                    if since_flush >= self.flush_interval {
                        since_flush = Duration::ZERO;
                        if let Err(e) = self.flush_at(false, now_ms).await {
                            warn!(error = %e, "Usage flush failed");
                        }
                    }
                }
            }
        }
        let now_ms = unix_ms();
        self.tick_at(now_ms);
        if let Err(e) = self.flush_at(true, now_ms).await {
            warn!(error = %e, "Final usage flush failed");
        }
    }
}

/// The mux's byte sink: forwards each DATA payload's size to the manager.
///
/// weaver-mux stays ignorant of metering; it only knows this trait. The
/// manager resolves the stream to its service and does all aggregation.
struct ManagerSink {
    manager: Arc<MeteringManager>,
}

impl StreamBytesSink for ManagerSink {
    fn bytes(&self, id: StreamId, bytes_in: u64, bytes_out: u64) {
        self.manager.stream_bytes(id, bytes_in, bytes_out);
    }
}

/// The minute number (since the Unix epoch) containing `now_ms`.
fn minute_of(now_ms: i64) -> i64 {
    now_ms.div_euclid(MINUTE_MS)
}

/// Adds `[accounted_ms, now_ms)` to `service_id`'s buckets, splitting at minute
/// boundaries and clamping each bucket's `open_ms` to one minute.
fn accrue(inner: &mut Inner, service_id: i32, now_ms: i64) {
    let Some(open) = inner.registered.get(&service_id).copied() else {
        return;
    };
    let mut cursor = open.accounted_ms;
    while cursor < now_ms {
        let minute = minute_of(cursor);
        let minute_end = (minute + 1) * MINUTE_MS;
        let seg_end = minute_end.min(now_ms);
        let seg = seg_end - cursor;
        if seg <= 0 {
            break;
        }
        let bucket = inner.buckets.entry((service_id, minute)).or_default();
        bucket.open_ms = (bucket.open_ms as i64 + seg).clamp(0, MINUTE_MS) as u32;
        cursor = seg_end;
    }
    if let Some(open) = inner.registered.get_mut(&service_id) {
        open.accounted_ms = now_ms;
    }
}

/// Wall-clock Unix milliseconds.
fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn manager() -> (MeteringManager, i32) {
        let store = Store::connect("sqlite::memory:").await.expect("store");
        let alice = store.create_person("alice").await.expect("person");
        let laptop = store
            .create_machine(alice.id, "laptop")
            .await
            .expect("machine");
        let svc = store
            .get_or_create_service(laptop.id, "web")
            .await
            .expect("service");
        (MeteringManager::new(store, Duration::from_secs(60)), svc.id)
    }

    /// Queries a minute window by its numeric bounds.
    async fn window(
        manager: &MeteringManager,
        from_minute: i64,
        until_minute: i64,
    ) -> Vec<UsageTotal> {
        manager
            .query(None, None, from_minute * 60, until_minute * 60)
            .await
            .expect("query")
    }

    #[tokio::test]
    async fn full_minute_open_time_reads_back_as_60000() {
        let (meter, svc) = manager().await;
        let start = 100 * MINUTE_MS;
        let end = 101 * MINUTE_MS;
        meter.register_service_at(svc, start);
        meter.unregister_service_at(svc, end);
        meter.flush_at(true, end).await.expect("flush");

        let totals = window(&meter, 0, 1_000).await;
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[0].covered_minutes, 1);
        assert_eq!(totals[0].open_ms, 60_000);
    }

    #[tokio::test]
    async fn early_close_leaves_unused_time() {
        let (meter, svc) = manager().await;
        let start = 100 * MINUTE_MS;
        meter.register_service_at(svc, start);
        meter.unregister_service_at(svc, start + 30_000);
        meter.flush_at(true, start + 30_000).await.expect("flush");

        let totals = window(&meter, 0, 1_000).await;
        assert_eq!(totals[0].open_ms, 30_000);
    }

    #[tokio::test]
    async fn open_time_splits_at_the_minute_boundary() {
        let (meter, svc) = manager().await;
        let start = 99 * MINUTE_MS + 50_000;
        meter.register_service_at(svc, start);
        meter.tick_at(start + 15_000);
        meter.unregister_service_at(svc, start + 15_000);
        meter.flush_at(true, start + 15_000).await.expect("flush");

        let m99 = window(&meter, 99, 100).await;
        assert_eq!(m99[0].open_ms, 10_000);
        let m100 = window(&meter, 100, 101).await;
        assert_eq!(m100[0].open_ms, 5_000);
    }

    #[tokio::test]
    async fn open_ms_never_exceeds_one_minute_under_repeated_ticks() {
        let (meter, svc) = manager().await;
        let start = 100 * MINUTE_MS;
        meter.register_service_at(svc, start);
        for i in 1..=5 {
            meter.tick_at(start + i * 10_000);
        }
        meter.unregister_service_at(svc, start + 50_000);
        meter.flush_at(true, start + 50_000).await.expect("flush");

        let totals = window(&meter, 100, 101).await;
        assert!(totals[0].open_ms <= 60_000);
        assert_eq!(totals[0].open_ms, 50_000);
    }

    #[tokio::test]
    async fn bytes_and_requests_land_in_the_observation_minute() {
        let (meter, svc) = manager().await;
        let stream = 7u32;
        meter.register_stream(stream, svc);
        meter.record_request_at(svc, 100 * MINUTE_MS + 1_000);
        meter.record_request_at(svc, 100 * MINUTE_MS + 2_000);
        meter.stream_bytes_at(stream, 100 * MINUTE_MS + 1_500, 10, 20);
        meter.stream_bytes_at(stream, 101 * MINUTE_MS + 1_500, 5, 7);
        meter.flush_at(true, 102 * MINUTE_MS).await.expect("flush");

        let m100 = window(&meter, 100, 101).await;
        assert_eq!(m100[0].requests, 2);
        assert_eq!(m100[0].bytes_in, 10);
        assert_eq!(m100[0].bytes_out, 20);
        let m101 = window(&meter, 101, 102).await;
        assert_eq!(m101[0].requests, 0);
        assert_eq!(m101[0].bytes_in, 5);
        assert_eq!(m101[0].bytes_out, 7);
    }

    #[tokio::test]
    async fn byte_reports_for_unknown_streams_are_ignored() {
        let (meter, svc) = manager().await;
        // A stream nobody registered belongs to no service; the report is
        // dropped rather than misattributed.
        meter.stream_bytes_at(999, 100 * MINUTE_MS, 10, 20);
        meter.unregister_stream(999);
        meter.flush_at(true, 101 * MINUTE_MS).await.expect("flush");
        assert!(window(&meter, 100, 101).await.is_empty());

        // Once forgotten, a stream's later reports are dropped too.
        meter.register_stream(1, svc);
        meter.unregister_stream(1);
        meter.stream_bytes_at(1, 101 * MINUTE_MS, 1, 1);
        meter.flush_at(true, 102 * MINUTE_MS).await.expect("flush");
        assert!(window(&meter, 101, 102).await.is_empty());
    }

    #[tokio::test]
    async fn flush_without_include_current_skips_the_open_minute() {
        let (meter, svc) = manager().await;
        let now = 100 * MINUTE_MS + 30_000;
        meter.record_request_at(svc, 99 * MINUTE_MS + 1_000);
        meter.record_request_at(svc, now);
        meter.flush_at(false, now).await.expect("flush");

        // Only minute 99 was persisted; the in-flight minute is carried.
        let m99 = window(&meter, 99, 100).await;
        assert_eq!(m99[0].requests, 1);
        assert!(window(&meter, 100, 101).await.is_empty());
    }

    #[tokio::test]
    async fn requests_are_counted_on_open_and_never_decremented() {
        let (meter, svc) = manager().await;
        meter.record_request_at(svc, 100 * MINUTE_MS + 1_000);
        meter.register_stream(1, svc);
        // The stream closes; the request it opened must still be counted.
        meter.unregister_stream(1);
        meter.flush_at(true, 101 * MINUTE_MS).await.expect("flush");

        let totals = window(&meter, 100, 101).await;
        assert_eq!(totals[0].requests, 1);
    }

    #[tokio::test]
    async fn shutdown_flushes_the_partial_current_minute() {
        let (meter, svc) = manager().await;
        let meter = Arc::new(meter);
        let minute = minute_of(unix_ms());
        meter.register_service(svc);
        meter.register_stream(1, svc);
        meter.record_request(svc);
        meter.stream_bytes(1, 11, 22);

        let token = CancellationToken::new();
        let task = meter.start(token.clone());
        tokio::time::sleep(Duration::from_millis(50)).await;
        token.cancel();
        let _ = task.await;

        // The pre-shutdown ticker never flushed (interval is 60 s); only the
        // final flush on shutdown wrote the still-open minute.
        let totals = window(&meter, minute - 1, minute + 2).await;
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[0].requests, 1);
        assert_eq!(totals[0].bytes_in, 11);
        assert_eq!(totals[0].bytes_out, 22);
        assert!(totals[0].open_ms > 0);
    }

    #[tokio::test]
    async fn public_flush_writes_everything_including_the_current_minute() {
        let (meter, svc) = manager().await;
        meter.record_request(svc);
        meter.flush().await.expect("flush");
        // The manager clock is the only source of the minute; read it back.
        let now_minute = minute_of(unix_ms());
        let totals = window(&meter, now_minute, now_minute + 1).await;
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[0].requests, 1);
    }
}
