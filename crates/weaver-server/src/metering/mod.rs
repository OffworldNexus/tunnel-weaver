//! Per-service usage metering.
//!
//! [`MeteringManager`] owns the whole metering concern, so no other module
//! touches usage rows directly:
//!
//! * the **first layer**, an in-memory `(service_id, minute)` aggregation of
//!   traffic counters and registered open time;
//! * the **flush job**, a 1 s ticker that accrues open time and periodically
//!   writes *complete* minutes to the [`Store`] as in-place slot arrays (one
//!   [`SlotWrite`] per service and metric, covering consecutive minutes); the
//!   in-flight minute is never written, so a persisted slot is always a full
//!   nominal minute. On shutdown the in-flight minute is simply dropped;
//! * the **persistence surface**, the only caller of the store's slot writes
//!   and of its usage query.
//!
//! [`query`](MeteringManager::query) blends the persisted arrays with the
//! unflushed in-memory buckets, so the current minute is still visible to
//! callers even though it is never written.
//!
//! Callers report observations through the clock-free methods: the relay calls
//! [`record_request`](MeteringManager::record_request) when it opens a visitor
//! stream and [`register_stream`](MeteringManager::register_stream) to map that
//! stream to its service (used by the tunnel leg). Two legs are metered:
//!
//! * the **visitor leg** —
//!   [`visitor_service_bytes`](MeteringManager::visitor_service_bytes), called
//!   by the HTTPS edge from a socket-level counter, so it measures every byte
//!   on the visitor connection (request/response heads, bodies and framing);
//! * the **tunnel leg** — [`tunnel_bytes`](MeteringManager::tunnel_bytes),
//!   published to the mux as its [`StreamBytesSink`] via
//!   [`MeteringManager::sink`], so every compressed DATA payload the mux moves
//!   reports its wire bytes at the moment it flows, keyed by stream.
//!
//! The manager stamps all observations with its own clock; deterministic tests
//! drive the private `*_at(now_ms)` variants.
//!
//! Timing rules:
//! * A minute key is `unix_ms / 60_000`, tagged at observation time, so a late
//!   or missed tick never moves data between buckets.
//! * Byte reports are per-flow deltas tagged when they flow, so a long-lived
//!   stream lands each byte in the minute it actually moved.
//! * Open time is accrue-on-tick: the ticker adds the *actual* wall-clock
//!   elapsed for each registered service, splitting at minute boundaries and
//!   clamping each bucket's `open_ms` to `0..=60_000`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
#[cfg(test)]
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::warn;
use weaver_mux::{StreamBytesSink, StreamId};

use crate::live::{Change, Entity, LiveHub, Viewer};
use crate::metrics::MetricsStore;
use crate::store::Store;
use crate::store::StoreError;
use crate::store::usage_live::{SlotWrite, Slots};

pub use crate::store::usage::UsageTotal;

/// Length of a metering minute, in milliseconds.
const MINUTE_MS: i64 = 60_000;

/// Minutes in a metering day. A slot run never crosses one, because a day is a
/// separate row of the array.
const MINUTES_PER_DAY: i64 = 24 * 60;

/// How often the manager accrues open time and checks for a flush.
const TICK: Duration = Duration::from_secs(1);

/// Counters accumulated for one `(service_id, minute)` bucket.
#[derive(Debug, Clone, Copy, Default)]
struct Bucket {
    /// Visitor leg: browser -> relay body bytes.
    bytes_in: u64,
    /// Visitor leg: relay -> browser body bytes.
    bytes_out: u64,
    /// Tunnel leg: client -> relay compressed bytes (from the mux).
    tunnel_in: u64,
    /// Tunnel leg: relay -> client compressed bytes (from the mux).
    tunnel_out: u64,
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

/// Aggregated unflushed in-memory counters for one service.
#[derive(Debug, Clone, Copy, Default)]
struct LiveAgg {
    bytes_in: i64,
    bytes_out: i64,
    tunnel_in: i64,
    tunnel_out: i64,
    requests: i64,
    open_ms: i64,
    covered_minutes: i64,
}

#[derive(Default)]
struct Inner {
    buckets: HashMap<(i32, i64), Bucket>,
    registered: HashMap<i32, Open>,
    /// Which service each currently-open stream belongs to, so byte reports
    /// from the mux (which only knows the stream id) can be attributed.
    streams: HashMap<StreamId, i32>,
}

/// Where the manager reads its wall clock.
///
/// Production reads the system clock. Tests pin a value they move themselves:
/// on the real clock a minute boundary can fall between two statements of a
/// test that is asserting about minutes, so the minute the test recorded in is
/// no longer the current one by the time it flushes or reads back.
enum Clock {
    /// The system clock.
    System,
    /// A value the caller controls, advanced by the caller rather than by time.
    #[cfg(test)]
    Fixed(Arc<AtomicI64>),
}

impl Clock {
    /// Unix milliseconds.
    fn now_ms(&self) -> i64 {
        match self {
            Clock::System => crate::wall_clock::unix_ms(),
            #[cfg(test)]
            Clock::Fixed(value) => value.load(Ordering::Relaxed),
        }
    }
}

/// How long the day rollup is kept. The default is one year.
const DEFAULT_RETENTION: Duration = Duration::from_secs(31_536_000);

/// Owns traffic metering and its periodic persistence.
///
/// Cheap to share behind an `Arc`: every observation method takes `&self`.
pub struct MeteringManager {
    store: Store,
    flush_interval: Duration,
    /// How long `usage_daily` rows are kept, swept from the flush tick.
    retention: Duration,
    /// The wall clock. Injected so a test can hold the minute still.
    clock: Clock,
    /// The console's change bus, when the process has one: each flush announces
    /// the metered statistics to the person whose traffic landed, so their open
    /// views re-read. `None` in tests, where nothing is watching.
    live: Option<LiveHub>,
    inner: Mutex<Inner>,
}

impl MeteringManager {
    /// Creates a manager that flushes every `flush_interval`, keeping a year of
    /// folded days.
    pub fn new(store: Store, flush_interval: Duration) -> Self {
        Self::with_retention(store, flush_interval, DEFAULT_RETENTION)
    }

    /// Creates a manager that flushes every `flush_interval` and keeps folded
    /// days for `retention`.
    pub fn with_retention(store: Store, flush_interval: Duration, retention: Duration) -> Self {
        Self::with_clock(store, flush_interval, Clock::System, retention)
    }

    /// Attaches the console's change bus, so a flush wakes the traffic views.
    /// A builder, used once at startup.
    pub fn with_live(mut self, live: LiveHub) -> Self {
        self.live = Some(live);
        self
    }

    /// Creates a manager reading time from `clock`.
    fn with_clock(
        store: Store,
        flush_interval: Duration,
        clock: Clock,
        retention: Duration,
    ) -> Self {
        Self {
            store,
            flush_interval,
            retention,
            clock,
            live: None,
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
        self.record_request_at(service_id, self.clock.now_ms());
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

    /// Reports visitor-leg socket bytes for a service: `bytes_in` read from the
    /// browser, `bytes_out` written to it.
    ///
    /// Called by the HTTPS edge from its socket-level counter, so heads, body
    /// and HTTP framing are all included and long-lived connections are
    /// sampled as their bytes flow.
    pub fn visitor_service_bytes(&self, service_id: i32, bytes_in: u64, bytes_out: u64) {
        self.visitor_service_bytes_at(service_id, self.clock.now_ms(), bytes_in, bytes_out);
    }

    /// Reports tunnel-leg compressed wire bytes the mux moved on a stream.
    ///
    /// This is the mux's push callback: called the moment bytes flow, so a
    /// long-lived stream is attributed to the minute each byte actually moved.
    /// `bytes_in` is `client -> relay`, `bytes_out` is `relay -> client`.
    pub fn tunnel_bytes(&self, stream_id: StreamId, bytes_in: u64, bytes_out: u64) {
        self.tunnel_bytes_at(stream_id, self.clock.now_ms(), bytes_in, bytes_out);
    }

    /// Publishes this manager as the mux's byte sink.
    pub fn sink(self: &Arc<Self>) -> Arc<dyn StreamBytesSink> {
        Arc::new(ManagerSink {
            manager: Arc::clone(self),
        })
    }

    /// Marks a service as registered; open time starts accruing from now.
    pub fn register_service(&self, service_id: i32) {
        self.register_service_at(service_id, self.clock.now_ms());
    }

    /// Marks a service as no longer registered, accruing its final open slice.
    pub fn unregister_service(&self, service_id: i32) {
        self.unregister_service_at(service_id, self.clock.now_ms());
    }

    /// Aggregated per-service usage over `[since_secs, until_secs)`, optionally
    /// filtered by person and/or service name.
    ///
    /// The window arrives as absolute Unix seconds and is converted to minute
    /// numbers here. The result is the **sum of persisted rows and the
    /// unflushed in-memory buckets**, so the current minute and any not-yet-
    /// flushed data show up immediately rather than only after a flush. Open
    /// time is first accrued to now so a currently-registered service's live
    /// row is current. An unknown person or service name matches nothing and
    /// yields an empty result, not an error.
    pub async fn query(
        &self,
        person: Option<&str>,
        service: Option<&str>,
        since_secs: i64,
        until_secs: i64,
    ) -> Result<Vec<UsageTotal>, StoreError> {
        let since_min = since_secs.div_euclid(60);
        // Include every minute bucket that overlaps `[since, until)`. The
        // bucket containing `until - 1` is the last one that does, so a window
        // ending "now" still covers the in-flight minute (whose key equals
        // `minute_of(now)`); a window ending exactly on a boundary does not.
        let until_min = if until_secs > since_secs {
            (until_secs - 1).div_euclid(60) + 1
        } else {
            since_min
        };
        // Bring open time up to the present before snapshotting the live data.
        self.tick_at(self.clock.now_ms());

        let persisted = self
            .store
            .query_usage(person, service, since_min, until_min)
            .await?;
        let live = self.live_totals(since_min, until_min);
        if live.is_empty() {
            return Ok(persisted);
        }

        let ids: Vec<i32> = live.keys().copied().collect();
        let identities = self.store.service_identities(&ids).await?;
        let mut by_id: HashMap<i32, UsageTotal> =
            persisted.into_iter().map(|t| (t.service_id, t)).collect();
        for ident in identities {
            let Some(agg) = live.get(&ident.service_id) else {
                continue;
            };
            // Apply the same filters the SQL query applied to persisted rows.
            if let Some(person) = person
                && !ident.person.eq_ignore_ascii_case(person)
            {
                continue;
            }
            if let Some(service) = service
                && !ident.service.eq_ignore_ascii_case(service)
            {
                continue;
            }
            let entry = by_id.entry(ident.service_id).or_insert_with(|| UsageTotal {
                service_id: ident.service_id,
                service: ident.service.clone(),
                machine: ident.machine.clone(),
                person: ident.person.clone(),
                bytes_in: 0,
                bytes_out: 0,
                tunnel_in: 0,
                tunnel_out: 0,
                requests: 0,
                covered_minutes: 0,
                open_ms: 0,
            });
            entry.bytes_in += agg.bytes_in;
            entry.bytes_out += agg.bytes_out;
            entry.tunnel_in += agg.tunnel_in;
            entry.tunnel_out += agg.tunnel_out;
            entry.requests += agg.requests;
            entry.covered_minutes += agg.covered_minutes;
            entry.open_ms += agg.open_ms;
        }

        let mut totals: Vec<UsageTotal> = by_id.into_values().collect();
        totals.sort_by(|a, b| {
            (&a.person, &a.machine, &a.service).cmp(&(&b.person, &b.machine, &b.service))
        });
        Ok(totals)
    }

    /// Snapshots the unflushed in-memory buckets in `[since_min, until_min)`,
    /// aggregated per service.
    fn live_totals(&self, since_min: i64, until_min: i64) -> HashMap<i32, LiveAgg> {
        let inner = self.lock();
        let mut out: HashMap<i32, LiveAgg> = HashMap::new();
        for (&(service_id, minute), b) in &inner.buckets {
            if minute < since_min || minute >= until_min {
                continue;
            }
            let agg = out.entry(service_id).or_default();
            agg.bytes_in += b.bytes_in as i64;
            agg.bytes_out += b.bytes_out as i64;
            agg.tunnel_in += b.tunnel_in as i64;
            agg.tunnel_out += b.tunnel_out as i64;
            agg.requests += b.requests as i64;
            agg.open_ms += b.open_ms as i64;
            agg.covered_minutes += 1;
        }
        out
    }

    /// Flushes every **complete** in-memory bucket to the store, as in-place
    /// slot writes.
    ///
    /// The in-flight minute is deliberately never written: a persisted slot is
    /// always a full nominal minute, so the live day's arrays stay "mostly
    /// zeroes". The current minute remains visible to [`query`](Self::query)
    /// from memory.
    ///
    /// This is minutes only — it never folds or sweeps. Those are the metering
    /// ticker's job ([`maintain`](Self::maintain), called from [`run`](Self::run)):
    /// a caller that just wants the live arrays current (every unit test, the
    /// shutdown path in a test) must not pay for a day of zstd compression.
    pub async fn flush(&self) -> Result<(), StoreError> {
        self.flush_at(self.clock.now_ms()).await
    }

    /// Folds finished days into the wide rollup and sweeps rows past retention.
    ///
    /// This is the flush's second half, run **only from the ticker loop**
    /// ([`run`](Self::run)) right after the minute flush, so the day that just
    /// ended is folded with its last minute already written. It is deliberately
    /// not called from [`flush`](Self::flush) or
    /// [`flush_at`](Self::flush_at): compression and the retention sweep belong
    /// to the daemon's cadence, not to a test's explicit flush. A failure is
    /// logged and retried on the next tick, because neither the relay's traffic
    /// nor its console should go down over a metrics hiccup.
    async fn maintain(&self) {
        let metrics = MetricsStore::new(self.store.clone());
        match metrics.fold_finished_days().await {
            Ok(0) => {}
            Ok(days) => tracing::debug!(days, "folded finished usage days"),
            Err(e) => warn!(error = %e, "Usage day fold failed"),
        }
        let retention = self.retention.as_secs().min(i64::MAX as u64) as i64;
        if let Err(e) = metrics.sweep(retention).await {
            warn!(error = %e, "Usage rollup sweep failed");
        }
    }

    /// Spawns the flush job, returning its handle.
    ///
    /// The job ticks once a second, accruing open time and flushing on the
    /// configured cadence. On `shutdown` it ticks once more and flushes; the
    /// in-flight minute is still never written, because only complete minutes
    /// are. Await the returned handle before closing the store.
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

    fn visitor_service_bytes_at(
        &self,
        service_id: i32,
        now_ms: i64,
        bytes_in: u64,
        bytes_out: u64,
    ) {
        let mut inner = self.lock();
        let bucket = inner
            .buckets
            .entry((service_id, minute_of(now_ms)))
            .or_default();
        bucket.bytes_in = bucket.bytes_in.saturating_add(bytes_in);
        bucket.bytes_out = bucket.bytes_out.saturating_add(bytes_out);
    }

    fn tunnel_bytes_at(&self, stream_id: StreamId, now_ms: i64, bytes_in: u64, bytes_out: u64) {
        let mut inner = self.lock();
        let Some(&service_id) = inner.streams.get(&stream_id) else {
            return;
        };
        let bucket = inner
            .buckets
            .entry((service_id, minute_of(now_ms)))
            .or_default();
        bucket.tunnel_in = bucket.tunnel_in.saturating_add(bytes_in);
        bucket.tunnel_out = bucket.tunnel_out.saturating_add(bytes_out);
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

    async fn flush_at(&self, now_ms: i64) -> Result<(), StoreError> {
        let now_minute = minute_of(now_ms);
        let drained: Vec<((i32, i64), Bucket)> = {
            let mut inner = self.lock();
            let keys: Vec<(i32, i64)> = inner
                .buckets
                .keys()
                .copied()
                .filter(|(_, m)| *m < now_minute)
                .collect();
            keys.into_iter()
                .filter_map(|key| inner.buckets.remove(&key).map(|b| (key, b)))
                .collect()
        };
        if drained.is_empty() {
            return Ok(());
        }
        let writes = slot_writes(&drained);
        if let Err(e) = self.store.write_day_slots(&writes).await {
            // The transaction rolled back; put the buckets back so a later
            // flush retries them instead of losing the data.
            let mut inner = self.lock();
            for (key, bucket) in drained {
                let b = inner.buckets.entry(key).or_default();
                b.bytes_in = b.bytes_in.saturating_add(bucket.bytes_in);
                b.bytes_out = b.bytes_out.saturating_add(bucket.bytes_out);
                b.tunnel_in = b.tunnel_in.saturating_add(bucket.tunnel_in);
                b.tunnel_out = b.tunnel_out.saturating_add(bucket.tunnel_out);
                b.requests = b.requests.saturating_add(bucket.requests);
                b.open_ms = (b.open_ms as i64 + bucket.open_ms as i64).clamp(0, MINUTE_MS) as u32;
            }
            return Err(e);
        }
        self.announce_flushed(&drained).await;
        Ok(())
    }

    /// Announces the metered statistics to each person whose traffic just
    /// flushed — one change per person per flush, never one per service.
    ///
    /// Best-effort: a console's freshness must never fail a flush, so a lookup
    /// failure is logged and swallowed.
    async fn announce_flushed(&self, drained: &[((i32, i64), Bucket)]) {
        let Some(live) = &self.live else {
            return;
        };
        let ids: Vec<i32> = drained
            .iter()
            .map(|((service_id, _), _)| *service_id)
            .collect();
        let identities = match self.store.service_identities(&ids).await {
            Ok(identities) => identities,
            Err(e) => {
                warn!(error = %e, "could not resolve flushed services for the console");
                return;
            }
        };
        let mut people: BTreeSet<i32> = BTreeSet::new();
        for identity in identities {
            people.insert(identity.person_id);
        }
        for person in people {
            live.publish(Change::visible_to(Viewer::Person(person)).entity(Entity::Statistics));
        }
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
                    let now_ms = self.clock.now_ms();
                    self.tick_at(now_ms);
                    if since_flush >= self.flush_interval {
                        since_flush = Duration::ZERO;
                        if let Err(e) = self.flush_at(now_ms).await {
                            warn!(error = %e, "Usage flush failed");
                        }
                        self.maintain().await;
                    }
                }
            }
        }
        let now_ms = self.clock.now_ms();
        self.tick_at(now_ms);
        if let Err(e) = self.flush_at(now_ms).await {
            warn!(error = %e, "Final usage flush failed");
        }
        self.maintain().await;
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
        self.manager.tunnel_bytes(id, bytes_in, bytes_out);
    }
}

/// The minute number (since the Unix epoch) containing `now_ms`.
fn minute_of(now_ms: i64) -> i64 {
    now_ms.div_euclid(MINUTE_MS)
}

/// Turns drained buckets into absolute in-place slot writes.
///
/// One write per (service, metric) and per **run of consecutive minutes inside
/// one day**. A slot write covers a contiguous range of slots, so a gap would
/// overwrite slots this flush knows nothing about; splitting at a gap (and at
/// midnight, so a run never crosses a day) confines every write to minutes just
/// drained. In steady state a flush drains the one minute since the last tick,
/// so this is one single-slot write per metric per service.
fn slot_writes(drained: &[((i32, i64), Bucket)]) -> Vec<SlotWrite> {
    let mut by_service: BTreeMap<i32, Vec<i64>> = BTreeMap::new();
    let mut buckets: HashMap<(i32, i64), Bucket> = HashMap::with_capacity(drained.len());
    for (key, bucket) in drained {
        by_service.entry(key.0).or_default().push(key.1);
        buckets.insert(*key, *bucket);
    }

    let mut writes = Vec::new();
    for (service_id, mut minutes) in by_service {
        minutes.sort_unstable();
        minutes.dedup();
        let mut start = 0;
        while start < minutes.len() {
            let day = minutes[start].div_euclid(MINUTES_PER_DAY);
            let mut end = start + 1;
            while end < minutes.len()
                && minutes[end] == minutes[end - 1] + 1
                && minutes[end].div_euclid(MINUTES_PER_DAY) == day
            {
                end += 1;
            }
            let run = &minutes[start..end];
            let first_slot = (run[0] - day * MINUTES_PER_DAY) as u16;
            for slots in Slots::ALL {
                let values = run
                    .iter()
                    .map(|minute| slot_value(&buckets[&(service_id, *minute)], slots))
                    .collect();
                writes.push(SlotWrite {
                    service_id,
                    day,
                    slots,
                    first_slot,
                    values,
                });
            }
            start = end;
        }
    }
    writes
}

/// One metric of one bucket as a slot stores it.
///
/// `open_ms` stores open time directly — the old `60_000 - open_ms` inversion
/// existed only to make a full minute the zero value of a per-minute table, and
/// there is no such table any more.
fn slot_value(bucket: &Bucket, slot: Slots) -> i64 {
    match slot {
        Slots::BytesIn => bucket.bytes_in as i64,
        Slots::BytesOut => bucket.bytes_out as i64,
        Slots::TunnelIn => bucket.tunnel_in as i64,
        Slots::TunnelOut => bucket.tunnel_out as i64,
        Slots::Requests => bucket.requests as i64,
        Slots::OpenMs => bucket.open_ms as i64,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn manager() -> (MeteringManager, i32) {
        let (meter, svc, _store) = manager_with_store().await;
        (meter, svc)
    }

    /// Like [`manager`], but also hands back a clone of the backing store so a
    /// test can inspect persisted rows without the live in-memory blend.
    async fn manager_with_store() -> (MeteringManager, i32, Store) {
        manager_with(Clock::System).await
    }

    /// Like [`manager_with_store`], but reading time from `clock`, so a minute
    /// boundary cannot move underneath a test that reasons about minutes.
    async fn manager_with(clock: Clock) -> (MeteringManager, i32, Store) {
        let store = Store::connect("sqlite::memory:").await.expect("store");
        let alice = store.create_test_person("alice").await.expect("person");
        let laptop = store
            .create_machine(alice.id, "laptop", &weaver_mux::KeyId::Ed25519([1; 32]))
            .await
            .expect("machine");
        let svc = store
            .get_or_create_service(laptop.id, "web")
            .await
            .expect("service");
        (
            MeteringManager::with_clock(
                store.clone(),
                Duration::from_secs(60),
                clock,
                // Long enough that day 0 (1970) survives the sweep, so a test
                // can fold and inspect it.
                Duration::from_secs(200 * 365 * 86_400),
            ),
            svc.id,
            store,
        )
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

    /// The console reads the day rollup, so the ticker's second half folds
    /// finished days into one wide row per service and deletes the minutes it
    /// folded. That second half is not [`MeteringManager::flush`]: the fold runs
    /// from the ticker loop, so an explicit flush never compresses.
    #[tokio::test]
    async fn the_tick_folds_finished_days_into_the_wide_rollup() {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

        let (meter, svc, store) = manager_with_store().await;
        let base = 100 * MINUTE_MS;

        // Minute 100 has bytes and is half open; minute 101 has a request.
        meter.register_service_at(svc, base);
        meter.visitor_service_bytes_at(svc, base + 1_000, 11, 22);
        meter.unregister_service_at(svc, base + 30_000);
        meter.record_request_at(svc, base + MINUTE_MS + 1_000);
        meter.flush_at(base + 2 * MINUTE_MS).await.expect("flush");
        let before = store
            .query_usage(None, None, 100, 102)
            .await
            .expect("minutes before the fold");
        assert_eq!(before.len(), 1, "one row per service");
        assert_eq!(
            before[0].covered_minutes, 2,
            "both minutes are still stored"
        );

        // The ticker's second half folds the finished day, then deletes its
        // minutes — all in one transaction per day.
        crate::metrics::MetricsStore::new(store.clone())
            .fold_finished_days()
            .await
            .expect("fold");
        assert!(
            store
                .query_usage(None, None, 100, 102)
                .await
                .unwrap()
                .is_empty(),
            "a folded day's minutes are deleted"
        );

        let row = crate::store::entity::usage_daily::Entity::find()
            .filter(crate::store::entity::usage_daily::Column::ServiceId.eq(svc))
            .filter(crate::store::entity::usage_daily::Column::Day.eq(0))
            .one(store.db())
            .await
            .unwrap()
            .expect("one wide row for the service-day");
        assert_eq!(row.bytes_in, 11, "the day total");
        assert_eq!(row.bytes_out, 22);
        assert_eq!(row.requests, 1);
        assert_eq!(row.open_ms, 30_000, "half-open minute 100");

        let minutes = crate::metrics::decode_blob(&row.bytes_in_minutes).unwrap();
        assert_eq!(minutes.len(), 1440, "1440 little-endian i64 per day");
        assert_eq!(minutes[100], 11, "minute 100's bytes_in");
        let hours = crate::metrics::decode_blob(&row.bytes_in_hours).unwrap();
        assert_eq!(hours.len(), 24, "24 hourly values per day");
        assert_eq!(hours[1], 11, "minute 100 folds into hour 1");
        let open = crate::metrics::decode_blob(&row.open_ms_minutes).unwrap();
        assert_eq!(open[100], 30_000, "minute 100's open time");
    }

    #[tokio::test]
    async fn full_minute_open_time_reads_back_as_60000() {
        let (meter, svc) = manager().await;
        let start = 100 * MINUTE_MS;
        let end = 101 * MINUTE_MS;
        meter.register_service_at(svc, start);
        meter.unregister_service_at(svc, end);
        meter.flush_at(end).await.expect("flush");

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
        meter.flush_at(101 * MINUTE_MS).await.expect("flush");

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
        meter.flush_at(101 * MINUTE_MS).await.expect("flush");

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
        meter.flush_at(101 * MINUTE_MS).await.expect("flush");

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
        meter.visitor_service_bytes_at(svc, 100 * MINUTE_MS + 1_500, 10, 20);
        meter.tunnel_bytes_at(stream, 100 * MINUTE_MS + 1_500, 3, 4);
        meter.visitor_service_bytes_at(svc, 101 * MINUTE_MS + 1_500, 5, 7);
        meter.tunnel_bytes_at(stream, 101 * MINUTE_MS + 1_500, 1, 2);
        meter.flush_at(102 * MINUTE_MS).await.expect("flush");

        let m100 = window(&meter, 100, 101).await;
        assert_eq!(m100[0].requests, 2);
        assert_eq!(m100[0].bytes_in, 10);
        assert_eq!(m100[0].bytes_out, 20);
        assert_eq!(m100[0].tunnel_in, 3);
        assert_eq!(m100[0].tunnel_out, 4);
        let m101 = window(&meter, 101, 102).await;
        assert_eq!(m101[0].requests, 0);
        assert_eq!(m101[0].bytes_in, 5);
        assert_eq!(m101[0].bytes_out, 7);
        assert_eq!(m101[0].tunnel_in, 1);
        assert_eq!(m101[0].tunnel_out, 2);
    }

    #[tokio::test]
    async fn byte_reports_for_unknown_streams_are_ignored() {
        let (meter, svc) = manager().await;
        // A stream nobody registered belongs to no service; the report is
        // dropped rather than misattributed.
        meter.tunnel_bytes_at(999, 100 * MINUTE_MS, 10, 20);
        meter.unregister_stream(999);
        meter.flush_at(101 * MINUTE_MS).await.expect("flush");
        assert!(window(&meter, 100, 101).await.is_empty());

        // Once forgotten, a stream's later reports are dropped too.
        meter.register_stream(1, svc);
        meter.unregister_stream(1);
        meter.tunnel_bytes_at(1, 101 * MINUTE_MS, 1, 1);
        meter.flush_at(102 * MINUTE_MS).await.expect("flush");
        assert!(window(&meter, 101, 102).await.is_empty());
    }

    #[tokio::test]
    async fn flush_persists_only_complete_minutes() {
        let (meter, svc, store) = manager_with_store().await;
        let now = 100 * MINUTE_MS + 30_000;
        meter.record_request_at(svc, 99 * MINUTE_MS + 1_000);
        meter.record_request_at(svc, now);
        meter.flush_at(now).await.expect("flush");

        // Only the complete minute 99 was persisted; the in-flight minute was
        // carried in memory.
        let persisted = store
            .query_usage(None, None, 0, 1_000)
            .await
            .expect("query");
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].covered_minutes, 1);
        assert_eq!(persisted[0].requests, 1);

        // The live query still surfaces the carried in-flight minute.
        let m99 = window(&meter, 99, 100).await;
        assert_eq!(m99[0].requests, 1);
        let m100 = window(&meter, 100, 101).await;
        assert_eq!(m100[0].requests, 1);
    }

    #[tokio::test]
    async fn query_window_includes_the_minute_containing_until() {
        let (meter, svc) = manager().await;
        meter.record_request_at(svc, 100 * MINUTE_MS + 1_000);

        // `until` lands 30 s into minute 100: that bucket overlaps the window
        // and must be included (this is what makes the in-flight minute show
        // when the window ends at "now").
        let inside = meter
            .query(None, None, 100 * 60, 100 * 60 + 30)
            .await
            .expect("query");
        assert_eq!(inside.len(), 1, "window ending mid-minute includes it");
        assert_eq!(inside[0].requests, 1);

        // `until` exactly on the minute-100 start is half-open and excludes it.
        let boundary = meter
            .query(None, None, 99 * 60, 100 * 60)
            .await
            .expect("query");
        assert!(
            boundary.is_empty(),
            "bucket starting at `until` is excluded"
        );
    }

    #[tokio::test]
    async fn query_blends_persisted_and_live_buckets() {
        let (meter, svc, _store) = manager_with_store().await;
        // Minute 99 is flushed to the store; minute 100 stays in memory.
        meter.record_request_at(svc, 99 * MINUTE_MS + 1_000);
        meter.flush_at(100 * MINUTE_MS).await.expect("flush");
        meter.record_request_at(svc, 100 * MINUTE_MS + 1_000);

        let blended = window(&meter, 99, 101).await;
        assert_eq!(blended.len(), 1);
        assert_eq!(blended[0].requests, 2, "persisted + live");
        assert_eq!(blended[0].covered_minutes, 2);

        // The window still excludes the live minute when it is out of range.
        let only_99 = window(&meter, 99, 100).await;
        assert_eq!(only_99[0].requests, 1);
    }

    #[tokio::test]
    async fn requests_are_counted_on_open_and_never_decremented() {
        let (meter, svc) = manager().await;
        meter.record_request_at(svc, 100 * MINUTE_MS + 1_000);
        meter.register_stream(1, svc);
        // The stream closes; the request it opened must still be counted.
        meter.unregister_stream(1);
        meter.flush_at(101 * MINUTE_MS).await.expect("flush");

        let totals = window(&meter, 100, 101).await;
        assert_eq!(totals[0].requests, 1);
    }

    #[tokio::test]
    async fn shutdown_does_not_persist_the_incomplete_minute() {
        // Pinned: on the wall clock the observed minute can complete between
        // recording and cancelling, and the job would then rightly persist it.
        // The subject here is an *incomplete* minute, so it must not be allowed
        // to end on its own.
        let base = 100 * MINUTE_MS + 1_000;
        let clock = Arc::new(AtomicI64::new(base));
        let (meter, svc, store) = manager_with(Clock::Fixed(Arc::clone(&clock))).await;
        let meter = Arc::new(meter);
        let minute = minute_of(base);
        meter.register_service(svc);
        meter.register_stream(1, svc);
        meter.record_request(svc);
        meter.visitor_service_bytes(svc, 11, 22);
        meter.tunnel_bytes(1, 33, 44);

        let token = CancellationToken::new();
        let task = meter.start(token.clone());
        // 50 ms of open time, produced by moving the pinned clock rather than by
        // waiting for the wall clock to move.
        clock.store(base + 50, Ordering::Relaxed);
        token.cancel();
        let _ = task.await;

        // The in-flight minute was not written: only complete minutes land.
        let persisted = store
            .query_usage(None, None, minute - 1, minute + 2)
            .await
            .expect("query");
        assert!(
            persisted.is_empty(),
            "the incomplete minute must not be persisted"
        );

        // It is still visible live until the minute completes.
        let totals = window(&meter, minute - 1, minute + 2).await;
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[0].requests, 1);
        assert_eq!(totals[0].bytes_in, 11);
        assert_eq!(totals[0].bytes_out, 22);
        assert_eq!(totals[0].tunnel_in, 33);
        assert_eq!(totals[0].tunnel_out, 44);
        assert_eq!(totals[0].open_ms, 50);
    }

    #[tokio::test]
    async fn public_flush_persists_only_complete_minutes() {
        // Pinned for the same reason as the shutdown test: the "current" minute
        // must not be able to complete while the test runs.
        let base = 100 * MINUTE_MS + 1_000;
        let (meter, svc, store) = manager_with(Clock::Fixed(Arc::new(AtomicI64::new(base)))).await;
        // A request in the current (incomplete) minute is not persisted...
        meter.record_request(svc);
        meter.flush().await.expect("flush");
        let now_minute = minute_of(base);
        assert!(
            store
                .query_usage(None, None, now_minute, now_minute + 1)
                .await
                .expect("query")
                .is_empty(),
            "the current minute must not be persisted"
        );

        // ...but is still visible live.
        let totals = window(&meter, now_minute, now_minute + 1).await;
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[0].requests, 1);
    }
}
