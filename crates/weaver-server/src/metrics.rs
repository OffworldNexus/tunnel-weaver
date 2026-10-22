//! Usage metrics: the read side of the metered data, plus the day fold.
//!
//! [`MetricsStore`] sits over the [`Store`] and is the only thing that reads
//! the two usage tables together:
//!
//! * `usage_daily` — the wide day-grain rollup a finished day is folded into:
//!   one row per `(service_id, day)` with the six metrics as day totals plus
//!   zstd-compressed hourly and per-minute arrays;
//! * `usage_live` — the days that are not finished yet (in steady state just
//!   today) as six pre-allocated, uncompressed, fixed-offset `i64` arrays per
//!   `(service_id, day)`, written in place. See
//!   [`crate::store::usage_live`].
//!
//! **No caller may learn which side a value came from.** For a window that
//! spans yesterday and today, `totals`, `last_open_minutes` and `query` return
//! one answer assembled from both representations: a day still in `usage_live`
//! is summed from its arrays, a folded day from the rollup row. Nothing reads a
//! per-minute table, because there is none: the old `usage` table is gone.
//!
//! A query names services and metrics and a `[from, to)` window, but **not** a
//! bucket width: the engine picks the finest of minute/hour/day whose slot count
//! over the window is at most [`MAX_SLOTS`], so a day is per-minute and a month
//! is per-day. It tells the client the choice in the `granularity` field.
//!
//! Reads are shaped to avoid the two costs a naive query would pay:
//!
//! * a whole day at day granularity reads the plain total columns, never a
//!   blob;
//! * a finer or partly-covered day reads only that day's arrays — a folded
//!   day's zstd frame is a few hundred bytes, and the live day is one 11,520
//!   byte cell per metric — and slices them in Rust.
//!
//! There are no SQL custom functions available (the sqlx driver cannot register
//! them), which is why the fold stores the *arrays* and why the live day is
//! summed from its slot arrays in Rust rather than by SQL `SUM` over minutes.

use std::collections::{BTreeMap, HashMap, HashSet};

use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, JoinType, QueryFilter,
    QuerySelect, RelationTrait, Set, Statement, TransactionTrait,
};
use serde_json::{Value, json};

use crate::store::entity::{machine, person, service, usage_daily};
use crate::store::usage_live::{MINUTES_PER_DAY as SLOT_MINUTES, Slots};
use crate::store::{Store, StoreError};
use crate::wall_clock::unix_secs;

/// The widest series the engine will emit before coarsening the slot width.
pub const MAX_SLOTS: usize = 500;

/// Seconds per slot of each granularity.
const SECS_PER_MINUTE: i64 = 60;
const SECS_PER_HOUR: i64 = 3_600;
const SECS_PER_DAY: i64 = 86_400;

/// Array lengths the rollup stores: 60 minutes to an hour, 24 hours to a day.
const MINUTES_PER_HOUR: usize = 60;
const HOURS_PER_DAY: usize = 24;
const MINUTES_PER_DAY: usize = 24 * MINUTES_PER_HOUR;

/// The live day's arrays must be exactly as long as the rollup's: the fold
/// copies one into the other, and a mismatch would silently lose minutes.
const _: () = assert!(MINUTES_PER_DAY == SLOT_MINUTES);

/// zstd level for the rollup arrays. They are small and read often, so a low
/// level trades a few bytes for a cheap decode; the point is density, not ratio.
const BLOB_LEVEL: i32 = 3;

/// The six metered quantities. The list order is the column order in both the
/// wide row and the series the store emits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Metric {
    /// Visitor leg: bytes the relay received from the browser.
    BytesIn,
    /// Visitor leg: bytes the relay sent to the browser.
    BytesOut,
    /// Tunnel leg: compressed bytes the relay received from the client.
    TunnelIn,
    /// Tunnel leg: compressed bytes the relay sent to the client.
    TunnelOut,
    /// Requests the relay opened on the visitor leg.
    Requests,
    /// Milliseconds a service was registered.
    OpenMs,
}

impl Metric {
    /// Every metric, in column order.
    pub const ALL: [Metric; 6] = [
        Metric::BytesIn,
        Metric::BytesOut,
        Metric::TunnelIn,
        Metric::TunnelOut,
        Metric::Requests,
        Metric::OpenMs,
    ];

    /// The wire name of the metric, used in the JSON series and the API's
    /// `metrics=` parameter.
    pub fn as_str(self) -> &'static str {
        match self {
            Metric::BytesIn => "bytes_in",
            Metric::BytesOut => "bytes_out",
            Metric::TunnelIn => "tunnel_in",
            Metric::TunnelOut => "tunnel_out",
            Metric::Requests => "requests",
            Metric::OpenMs => "open_ms",
        }
    }

    /// Parses a wire name; `None` for anything unknown (the API turns that into
    /// a 400 rather than guessing).
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.as_str() == name)
    }

    /// This metric's position in [`Metric::ALL`], which is also its position in
    /// the fold's arrays and the totals read.
    fn index(self) -> usize {
        match self {
            Metric::BytesIn => 0,
            Metric::BytesOut => 1,
            Metric::TunnelIn => 2,
            Metric::TunnelOut => 3,
            Metric::Requests => 4,
            Metric::OpenMs => 5,
        }
    }
}

/// How a series is reduced over each slot. Only `sum` exists today; the enum
/// keeps the wire contract explicit and gives the API something to validate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Function {
    /// Add every value that falls in the slot.
    Sum,
}

impl Function {
    /// The wire name of the function.
    pub fn as_str(self) -> &'static str {
        match self {
            Function::Sum => "sum",
        }
    }

    /// Parses a wire name; `None` for anything unknown.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "sum" => Some(Function::Sum),
            _ => None,
        }
    }
}

/// A metrics request. It has no bucket field: the engine chooses the scale from
/// the window and reports it back in the response.
#[derive(Clone, Debug)]
pub struct MetricsQuery {
    /// Service ids to report, in the order their series should appear.
    pub services: Vec<i32>,
    /// Person names whose services should be added to `services` (the console's
    /// person filter). Names are matched case-insensitively.
    pub people: Vec<String>,
    /// Metrics to report, in the order their series should appear.
    pub metrics: Vec<Metric>,
    /// Window start, Unix seconds, inclusive.
    pub from: i64,
    /// Window end, Unix seconds, exclusive.
    pub to: i64,
    /// How each slot is reduced.
    pub function: Function,
}

/// The finest slot width that keeps the series under [`MAX_SLOTS`], or the
/// coarsest available when even a day is too fine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Granularity {
    Minute,
    Hour,
    Day,
}

impl Granularity {
    /// Seconds per slot.
    fn secs(self) -> i64 {
        match self {
            Granularity::Minute => SECS_PER_MINUTE,
            Granularity::Hour => SECS_PER_HOUR,
            Granularity::Day => SECS_PER_DAY,
        }
    }

    /// The finest width whose slot count over `[from, to)` is at most
    /// [`MAX_SLOTS`]. A window longer than ~1.4 years falls through to days
    /// rather than refusing: the console's ranges are far shorter, and a day is
    /// the coarsest scale the rollup can answer.
    fn choose(from: i64, to: i64) -> Self {
        let span = std::cmp::max(to - from, 1);
        for granularity in [Granularity::Minute, Granularity::Hour, Granularity::Day] {
            if ((span + granularity.secs() - 1) / granularity.secs()) as usize <= MAX_SLOTS {
                return granularity;
            }
        }
        Granularity::Day
    }
}

/// The first slot index overlapping `[from, to)` and how many slots follow it.
/// Empty (zero slots) for a non-positive window.
fn slot_range(from: i64, to: i64, granularity: Granularity) -> (i64, usize) {
    if to <= from {
        return (from.div_euclid(granularity.secs()), 0);
    }
    let first = from.div_euclid(granularity.secs());
    let last = (to - 1).div_euclid(granularity.secs());
    (first, (last - first + 1) as usize)
}

/// Reads and folds the metered data. Cheap to clone: it only holds a [`Store`].
#[derive(Clone)]
pub struct MetricsStore {
    store: Store,
}

impl MetricsStore {
    /// Builds a metrics store over `store`.
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    /// The backing store, for callers that also need its typed queries.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Answers `q` as the JSON string the browser consumes.
    ///
    /// The JSON is built directly (no intermediate Rust model) because it is
    /// only ever serialised on its way out. Shape:
    /// `{function, granularity, from, to, series:[{service_id, metric, total,
    /// slots:[[slot, value], …]}]}`; `series` is the cartesian product of the
    /// requested services and metrics, and `granularity` is the slot width the
    /// engine chose.
    #[allow(clippy::too_many_lines)] // one straight-line assembly of the series
    pub async fn query(&self, q: &MetricsQuery) -> Result<String, StoreError> {
        let services = self.resolve_services(q).await?;
        let granularity = Granularity::choose(q.from, q.to);
        let (first_slot, n_slots) = slot_range(q.from, q.to, granularity);

        let mut values: HashMap<(i32, Metric), Vec<i64>> = HashMap::new();
        if !services.is_empty() && !q.metrics.is_empty() && n_slots > 0 {
            for &service in &services {
                for &metric in &q.metrics {
                    values.insert((service, metric), vec![0; n_slots]);
                }
            }
            let mut folded: HashSet<(i32, i64)> = HashSet::new();
            self.fill_folded(
                &services,
                &q.metrics,
                granularity,
                q.from,
                q.to,
                first_slot,
                n_slots,
                &mut values,
                &mut folded,
            )
            .await?;
            self.fill_live(
                &services,
                &q.metrics,
                granularity,
                q.from,
                q.to,
                first_slot,
                n_slots,
                &folded,
                &mut values,
            )
            .await?;
        }

        let mut series: Vec<Value> = Vec::with_capacity(services.len() * q.metrics.len());
        for &service in &services {
            for &metric in &q.metrics {
                let (total, slots) = match values.get(&(service, metric)) {
                    Some(values) => (
                        values.iter().sum::<i64>(),
                        values
                            .iter()
                            .enumerate()
                            .map(|(i, value)| json!([first_slot + i as i64, value]))
                            .collect::<Vec<Value>>(),
                    ),
                    None => (0, Vec::new()),
                };
                series.push(json!({
                    "service_id": service,
                    "metric": metric.as_str(),
                    "total": total,
                    "slots": slots,
                }));
            }
        }
        let response = json!({
            "function": q.function.as_str(),
            "granularity": granularity.secs(),
            "from": q.from,
            "to": q.to,
            "series": series,
        });
        Ok(response.to_string())
    }

    /// Per-`(service, metric)` totals over `[from, to)`.
    ///
    /// A window is assembled from both representations, and the caller cannot
    /// tell which: a folded day is a few `SUM`s over the rollup's plain total
    /// columns (no blob is read), and a day still in `usage_live` is summed from
    /// its slot arrays. No dedup is needed between the two sources: the fold
    /// writes the rollup row and deletes the live row in the same transaction,
    /// so a day is in exactly one of them.
    pub async fn totals(
        &self,
        services: &[i32],
        metrics: &[Metric],
        from: i64,
        to: i64,
    ) -> Result<HashMap<(i32, Metric), i64>, StoreError> {
        let mut totals: HashMap<(i32, Metric), i64> = HashMap::new();
        if services.is_empty() || metrics.is_empty() || to <= from {
            return Ok(totals);
        }
        for &service in services {
            for &metric in metrics {
                totals.insert((service, metric), 0);
            }
        }
        let db = self.store.db();
        let backend = db.get_database_backend();
        let id_list = service_id_list(services);
        let first_day = from.div_euclid(SECS_PER_DAY);
        let last_day = (to - 1).div_euclid(SECS_PER_DAY);

        // Folded days: the rollup's plain total columns.
        for &metric in metrics {
            let sql = format!(
                "SELECT service_id, SUM({metric}) FROM usage_daily \
                 WHERE service_id IN ({id_list}) AND day BETWEEN {first_day} AND {last_day} \
                 GROUP BY service_id",
                metric = metric.as_str()
            );
            for row in db
                .query_all_raw(Statement::from_string(backend, sql))
                .await?
            {
                let service_id: i32 = row.try_get_by_index(0)?;
                let sum: i64 = row.try_get_by_index(1)?;
                if let Some(total) = totals.get_mut(&(service_id, metric)) {
                    *total += sum;
                }
            }
        }

        // Days still live: summed from the slot arrays, clipped to the window's
        // minutes so a partly-covered live day is exact.
        let first_minute = from.div_euclid(SECS_PER_MINUTE);
        let last_minute = (to - 1).div_euclid(SECS_PER_MINUTE);
        let mut by_day: BTreeMap<i64, Vec<i32>> = BTreeMap::new();
        for (service_id, day) in self.store.live_days(services).await? {
            if (first_day..=last_day).contains(&day) {
                by_day.entry(day).or_default().push(service_id);
            }
        }
        let slots = slots_of(metrics);
        for (day, day_services) in by_day {
            let arrays = self
                .store
                .read_day_slots_of(&day_services, day, &slots)
                .await?;
            let base = day * MINUTES_PER_DAY as i64;
            for ((service_id, slot), values) in arrays {
                let metric = metric_of(slot);
                let Some(total) = totals.get_mut(&(service_id, metric)) else {
                    continue;
                };
                for (index, value) in values.iter().enumerate() {
                    let minute = base + index as i64;
                    if minute >= first_minute && minute <= last_minute {
                        *total += value;
                    }
                }
            }
        }
        Ok(totals)
    }

    /// The minute each service was last up, as a minute number since the epoch.
    ///
    /// Presence comes from `open_ms`, folded like every other metric, so the
    /// latest folded day with any open time has its `open_ms_minutes` blob
    /// decoded and its last non-zero index taken. A day still live is
    /// `rposition`ed over its uncompressed `open_ms_slots` array instead, and
    /// the two are combined by `max` — the answer does not depend on which
    /// representation a day happens to be in. Services with no open time at all
    /// are absent from the map.
    pub async fn last_open_minutes(
        &self,
        services: &[i32],
    ) -> Result<HashMap<i32, i64>, StoreError> {
        let mut last: HashMap<i32, i64> = HashMap::new();
        if services.is_empty() {
            return Ok(last);
        }
        let db = self.store.db();
        let backend = db.get_database_backend();
        let id_list = service_id_list(services);

        // Only each service's latest folded day ever matters, so let SQL pick
        // that single row per service. Fetching every day of the window instead
        // moves a month of per-minute blobs per service into Rust (thousands of
        // frames, megabytes) only to discard all but the newest.
        let sql = format!(
            "SELECT d.service_id, d.day, d.open_ms_minutes FROM usage_daily d \
             JOIN (SELECT service_id, MAX(day) AS day FROM usage_daily \
                   WHERE service_id IN ({id_list}) AND open_ms > 0 \
                   GROUP BY service_id) latest \
               ON latest.service_id = d.service_id AND latest.day = d.day"
        );
        for row in db
            .query_all_raw(Statement::from_string(backend, sql))
            .await?
        {
            let service_id: i32 = row.try_get_by_index(0)?;
            let day: i64 = row.try_get_by_index(1)?;
            let blob: Vec<u8> = row.try_get_by_index(2)?;
            // A rollup blob that does not decode is corruption, not "no open
            // time": propagating it beats silently reporting a machine as never
            // seen, and the machine list fails rather than lying.
            let minutes = decode_blob(&blob)?;
            if let Some(index) = minutes.iter().rposition(|value| *value > 0) {
                last.insert(service_id, day * MINUTES_PER_DAY as i64 + index as i64);
            }
        }

        // Every day still live, not just today: a lagging fold must not hide a
        // later day behind an older folded one.
        let mut by_day: BTreeMap<i64, Vec<i32>> = BTreeMap::new();
        for (service_id, day) in self.store.live_days(services).await? {
            by_day.entry(day).or_default().push(service_id);
        }
        for (day, day_services) in by_day {
            let arrays = self
                .store
                .read_day_slots_of(&day_services, day, &[Slots::OpenMs])
                .await?;
            for ((service_id, _), values) in arrays {
                if let Some(index) = values.iter().rposition(|value| *value > 0) {
                    let minute = day * MINUTES_PER_DAY as i64 + index as i64;
                    last.entry(service_id)
                        .and_modify(|seen| *seen = std::cmp::max(*seen, minute))
                        .or_insert(minute);
                }
            }
        }
        Ok(last)
    }

    /// Folds every finished UTC day that still has live rows into the wide
    /// rollup, returning how many days were folded.
    ///
    /// Each day is handled in **one transaction**: its six slot arrays are read
    /// once, pivoted per service into the six per-minute arrays, with the hour
    /// arrays and totals derived from them, compressed and written, and only
    /// then is the day's `usage_live` row deleted — so a finished day's slots
    /// are either all still live or already compressed, never half-folded.
    ///
    /// The write is **absolute**: it is the whole day, so folding the same day
    /// again (by then it has no live rows) cannot double count. Re-running is
    /// idempotent.
    pub async fn fold_finished_days(&self) -> Result<usize, StoreError> {
        // Only days that are complete: a live row for the day in progress must
        // not be folded away from under the console's live read.
        let today = unix_secs().div_euclid(SECS_PER_DAY);
        let days = crate::store::usage_live::days_with_live_rows(self.store.db(), today).await?;
        let mut folded = 0;
        for day in days {
            self.fold_day(day).await?;
            folded += 1;
        }
        Ok(folded)
    }

    /// Deletes rollup rows older than `retention_secs`, returning the number
    /// removed. The rollup is the only history the console reads, so it is the
    /// one table with a retention.
    pub async fn sweep(&self, retention_secs: i64) -> Result<u64, StoreError> {
        let cutoff_day = (unix_secs() - retention_secs).div_euclid(SECS_PER_DAY);
        Ok(usage_daily::Entity::delete_many()
            .filter(usage_daily::Column::Day.lt(cutoff_day))
            .exec(self.store.db())
            .await?
            .rows_affected)
    }

    /// Folds one complete day's live arrays into a rollup row per service, then
    /// deletes those live rows — atomically.
    async fn fold_day(&self, day: i64) -> Result<(), StoreError> {
        let txn = self.store.db().begin().await?;
        let arrays = crate::store::usage_live::live_day_slots(&txn, day, &Slots::ALL).await?;

        let mut by_service: HashMap<i32, [Vec<i64>; 6]> = HashMap::new();
        for ((service_id, slot), values) in arrays {
            let minutes = by_service.entry(service_id).or_insert_with(empty_day);
            let target = &mut minutes[slot.index()];
            // A cell is always a whole 1,440 slots; copy at most that many so a
            // corrupt short one cannot shift the rest.
            let length = values.len().min(MINUTES_PER_DAY);
            target[..length].copy_from_slice(&values[..length]);
        }
        // A service can be deleted between the live-day read above and this
        // write: deleting an account removes its services. Skip the ones already
        // gone rather than tripping the `usage_daily` foreign key — an in-flight
        // bucket for a deleted service must not resurrect a row.
        let present: HashSet<i32> = service::Entity::find()
            .select_only()
            .column(service::Column::Id)
            .filter(service::Column::Id.is_in(by_service.keys().copied()))
            .into_tuple::<i32>()
            .all(&txn)
            .await?
            .into_iter()
            .collect();
        by_service.retain(|service_id, _| present.contains(service_id));

        for (service_id, minutes) in by_service {
            self.write_day(&txn, service_id, day, minutes).await?;
        }

        crate::store::usage_live::delete_live_day(&txn, day).await?;
        txn.commit().await?;
        Ok(())
    }

    /// Writes one service-day rollup row inside `txn`, absolutely.
    ///
    /// It is the whole day: nothing is merged with a previous row, which is
    /// what makes a repeated fold idempotent rather than double counting.
    #[allow(clippy::too_many_lines)] // one wide row is genuinely 18 columns
    async fn write_day(
        &self,
        txn: &DatabaseTransaction,
        service_id: i32,
        day: i64,
        minutes: [Vec<i64>; 6],
    ) -> Result<(), StoreError> {
        let mut totals = [0_i64; 6];
        let mut hours: [Vec<i64>; 6] = std::array::from_fn(|_| vec![0; HOURS_PER_DAY]);
        for (metric, per_minute) in Metric::ALL.into_iter().zip(minutes.iter()) {
            for (hour, chunk) in per_minute
                .as_chunks::<MINUTES_PER_HOUR>()
                .0
                .iter()
                .enumerate()
            {
                let sum: i64 = chunk.iter().sum();
                hours[metric.index()][hour] = sum;
                totals[metric.index()] += sum;
            }
        }
        let hour_blobs: [Vec<u8>; 6] = std::array::from_fn(|i| encode_blob(&hours[i]));
        let minute_blobs: [Vec<u8>; 6] = std::array::from_fn(|i| encode_blob(&minutes[i]));

        let [
            bytes_in,
            bytes_out,
            tunnel_in,
            tunnel_out,
            requests,
            open_ms,
        ] = totals;
        let [
            bytes_in_hours,
            bytes_out_hours,
            tunnel_in_hours,
            tunnel_out_hours,
            requests_hours,
            open_ms_hours,
        ] = hour_blobs;
        let [
            bytes_in_minutes,
            bytes_out_minutes,
            tunnel_in_minutes,
            tunnel_out_minutes,
            requests_minutes,
            open_ms_minutes,
        ] = minute_blobs;
        let model = usage_daily::ActiveModel {
            service_id: Set(service_id),
            day: Set(day),
            bytes_in: Set(bytes_in),
            bytes_in_hours: Set(bytes_in_hours),
            bytes_in_minutes: Set(bytes_in_minutes),
            bytes_out: Set(bytes_out),
            bytes_out_hours: Set(bytes_out_hours),
            bytes_out_minutes: Set(bytes_out_minutes),
            tunnel_in: Set(tunnel_in),
            tunnel_in_hours: Set(tunnel_in_hours),
            tunnel_in_minutes: Set(tunnel_in_minutes),
            tunnel_out: Set(tunnel_out),
            tunnel_out_hours: Set(tunnel_out_hours),
            tunnel_out_minutes: Set(tunnel_out_minutes),
            requests: Set(requests),
            requests_hours: Set(requests_hours),
            requests_minutes: Set(requests_minutes),
            open_ms: Set(open_ms),
            open_ms_hours: Set(open_ms_hours),
            open_ms_minutes: Set(open_ms_minutes),
        };

        let mut conflict =
            OnConflict::columns([usage_daily::Column::ServiceId, usage_daily::Column::Day]);
        let updates = [
            usage_daily::Column::BytesIn,
            usage_daily::Column::BytesInHours,
            usage_daily::Column::BytesInMinutes,
            usage_daily::Column::BytesOut,
            usage_daily::Column::BytesOutHours,
            usage_daily::Column::BytesOutMinutes,
            usage_daily::Column::TunnelIn,
            usage_daily::Column::TunnelInHours,
            usage_daily::Column::TunnelInMinutes,
            usage_daily::Column::TunnelOut,
            usage_daily::Column::TunnelOutHours,
            usage_daily::Column::TunnelOutMinutes,
            usage_daily::Column::Requests,
            usage_daily::Column::RequestsHours,
            usage_daily::Column::RequestsMinutes,
            usage_daily::Column::OpenMs,
            usage_daily::Column::OpenMsHours,
            usage_daily::Column::OpenMsMinutes,
        ];
        conflict.update_columns(updates);
        usage_daily::Entity::insert(model)
            .on_conflict(conflict)
            .exec_without_returning(txn)
            .await?;
        Ok(())
    }

    /// Fills each series from the folded rollup: day totals where the slot is a
    /// day, otherwise the day's zstd array sliced in Rust. Days that produced a
    /// row are recorded in `folded` so the live read does not count them twice.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn fill_folded(
        &self,
        services: &[i32],
        metrics: &[Metric],
        granularity: Granularity,
        from: i64,
        to: i64,
        first_slot: i64,
        n_slots: usize,
        values: &mut HashMap<(i32, Metric), Vec<i64>>,
        folded: &mut HashSet<(i32, i64)>,
    ) -> Result<(), StoreError> {
        let db = self.store.db();
        let backend = db.get_database_backend();
        let mut columns = vec!["service_id".to_string(), "day".to_string()];
        for &metric in metrics {
            columns.push(match granularity {
                Granularity::Day => metric.as_str().to_string(),
                Granularity::Hour => format!("{}_hours", metric.as_str()),
                Granularity::Minute => format!("{}_minutes", metric.as_str()),
            });
        }
        let first_day = from.div_euclid(SECS_PER_DAY);
        let last_day = (to - 1).div_euclid(SECS_PER_DAY);
        let sql = format!(
            "SELECT {columns} FROM usage_daily \
             WHERE service_id IN ({ids}) AND day BETWEEN {first_day} AND {last_day}",
            columns = columns.join(", "),
            ids = service_id_list(services),
        );
        for row in db
            .query_all_raw(Statement::from_string(backend, sql))
            .await?
        {
            let service_id: i32 = row.try_get_by_index(0)?;
            let day: i64 = row.try_get_by_index(1)?;
            folded.insert((service_id, day));
            for (i, &metric) in metrics.iter().enumerate() {
                let Some(buffer) = values.get_mut(&(service_id, metric)) else {
                    continue;
                };
                match granularity {
                    Granularity::Day => {
                        let value: i64 = row.try_get_by_index(2 + i)?;
                        add_slot(buffer, day, first_slot, n_slots, value);
                    }
                    Granularity::Hour => {
                        let blob: Vec<u8> = row.try_get_by_index(2 + i)?;
                        let hours = decode_blob(&blob)?;
                        for (hour, value) in hours.iter().enumerate().take(HOURS_PER_DAY) {
                            add_slot(
                                buffer,
                                day * HOURS_PER_DAY as i64 + hour as i64,
                                first_slot,
                                n_slots,
                                *value,
                            );
                        }
                    }
                    Granularity::Minute => {
                        let blob: Vec<u8> = row.try_get_by_index(2 + i)?;
                        let minutes = decode_blob(&blob)?;
                        for (minute, value) in minutes.iter().enumerate().take(MINUTES_PER_DAY) {
                            add_slot(
                                buffer,
                                day * MINUTES_PER_DAY as i64 + minute as i64,
                                first_slot,
                                n_slots,
                                *value,
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Fills each series from the live days — today, or any day not yet folded.
    /// Service-days already covered by a folded row are skipped.
    #[allow(clippy::too_many_arguments)]
    async fn fill_live(
        &self,
        services: &[i32],
        metrics: &[Metric],
        granularity: Granularity,
        from: i64,
        to: i64,
        first_slot: i64,
        n_slots: usize,
        folded: &HashSet<(i32, i64)>,
        values: &mut HashMap<(i32, Metric), Vec<i64>>,
    ) -> Result<(), StoreError> {
        let first_minute = from.div_euclid(SECS_PER_MINUTE);
        let last_minute = (to - 1).div_euclid(SECS_PER_MINUTE);
        let first_day = first_minute.div_euclid(MINUTES_PER_DAY as i64);
        let last_day = last_minute.div_euclid(MINUTES_PER_DAY as i64);
        let mut by_day: BTreeMap<i64, Vec<i32>> = BTreeMap::new();
        for (service_id, day) in self.store.live_days(services).await? {
            if (first_day..=last_day).contains(&day) && !folded.contains(&(service_id, day)) {
                by_day.entry(day).or_default().push(service_id);
            }
        }
        // The slot width in minutes: a minute falls in the slot its absolute
        // second is divided by the width.
        let minutes_per_slot = granularity.secs() / SECS_PER_MINUTE;
        for (day, day_services) in by_day {
            let arrays = self
                .store
                .read_day_slots_of(&day_services, day, &slots_of(metrics))
                .await?;
            let base = day * MINUTES_PER_DAY as i64;
            for ((service_id, slot), values_in_day) in arrays {
                let metric = metric_of(slot);
                let Some(buffer) = values.get_mut(&(service_id, metric)) else {
                    continue;
                };
                for (index, value) in values_in_day.iter().enumerate() {
                    let minute = base + index as i64;
                    if minute < first_minute || minute > last_minute {
                        continue;
                    }
                    add_slot(
                        buffer,
                        minute.div_euclid(minutes_per_slot),
                        first_slot,
                        n_slots,
                        *value,
                    );
                }
            }
        }
        Ok(())
    }

    /// The services a query covers: the explicit ids plus every service of the
    /// named people, de-duplicated in first-seen order.
    async fn resolve_services(&self, q: &MetricsQuery) -> Result<Vec<i32>, StoreError> {
        let mut services: Vec<i32> = Vec::new();
        let mut seen: HashSet<i32> = HashSet::new();
        for &service in &q.services {
            if seen.insert(service) {
                services.push(service);
            }
        }
        if !q.people.is_empty() {
            let names: Vec<String> = q.people.iter().map(|p| p.to_ascii_lowercase()).collect();
            let rows = service::Entity::find()
                .select_only()
                .column(service::Column::Id)
                .join(JoinType::InnerJoin, service::Relation::Machine.def())
                .join(JoinType::InnerJoin, machine::Relation::Person.def())
                .filter(person::Column::Name.is_in(names))
                .into_tuple::<i32>()
                .all(self.store.db())
                .await?;
            for service in rows {
                if seen.insert(service) {
                    services.push(service);
                }
            }
        }
        Ok(services)
    }
}

/// The six per-minute arrays of one service-day, indexed by [`Metric::index`].
type DaySlots = [Vec<i64>; 6];

/// A zeroed day of per-minute arrays.
fn empty_day() -> DaySlots {
    std::array::from_fn(|_| vec![0; MINUTES_PER_DAY])
}

/// The slot column a metric lives in.
///
/// [`Metric::ALL`] and [`Slots::ALL`] are in the same order, so the bridge is
/// just the shared index; the metrics module keeps its own enum because it is
/// the wire-facing one and the storage keeps its own because it must not depend
/// on the wire.
fn slots_of_metric(metric: Metric) -> Slots {
    Slots::ALL[metric.index()]
}

/// The metric a slot column holds.
fn metric_of(slot: Slots) -> Metric {
    Metric::ALL[slot.index()]
}

/// The distinct slot columns a metric list needs, in request order.
fn slots_of(metrics: &[Metric]) -> Vec<Slots> {
    let mut slots: Vec<Slots> = Vec::with_capacity(metrics.len());
    for &metric in metrics {
        let slot = slots_of_metric(metric);
        if !slots.contains(&slot) {
            slots.push(slot);
        }
    }
    slots
}

/// Adds `value` to `buffer` at the slot's offset, ignoring slots outside the
/// window.
fn add_slot(buffer: &mut [i64], slot: i64, first_slot: i64, n_slots: usize, value: i64) {
    if let Ok(offset) = usize::try_from(slot - first_slot)
        && offset < n_slots
    {
        buffer[offset] += value;
    }
}

/// Renders service ids as a SQL `IN` list. Ids are integers from the store, so
/// they carry no injection risk and need no binding.
fn service_id_list(services: &[i32]) -> String {
    services
        .iter()
        .map(|service| service.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Compresses an `i64` array into the rollup's blob format: a zstd frame over
/// little-endian `i64`s.
///
/// Infallible for an in-memory array (compression has nothing to fail on); the
/// decode side is fallible because the bytes come back from the database.
pub fn encode_blob(values: &[i64]) -> Vec<u8> {
    let mut raw = Vec::with_capacity(values.len() * 8);
    for value in values {
        raw.extend_from_slice(&value.to_le_bytes());
    }
    zstd::bulk::compress(&raw, BLOB_LEVEL).expect("compressing an in-memory buffer cannot fail")
}

/// Expands a rollup blob (see [`encode_blob`]) back into its `i64` array.
pub fn decode_blob(blob: &[u8]) -> Result<Vec<i64>, StoreError> {
    let raw = zstd::stream::decode_all(blob)?;
    if raw.len() % 8 != 0 {
        return Err(StoreError::InvalidUsage(format!(
            "rollup blob of {} bytes is not a whole number of i64",
            raw.len()
        )));
    }
    let (chunks, remainder) = raw.as_chunks::<8>();
    debug_assert!(remainder.is_empty(), "checked above");
    Ok(chunks
        .iter()
        .map(|chunk| i64::from_le_bytes(*chunk))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::usage_live::SlotWrite;

    /// Builds a store with one person, one machine and one service, returning
    /// the store and the service id.
    async fn fixture() -> (Store, i32) {
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
        (store, svc.id)
    }

    /// Writes one minute of one service as slots: `bytes_in` and `bytes_out`
    /// both equal `bytes_in`, `requests` is one and `open_ms` is as given — the
    /// shape the old per-minute `usage` row (and its `unused_ms` inversion) had,
    /// so the tests below read the same.
    async fn minute(
        store: &Store,
        service_id: i32,
        minute_number: i64,
        bytes_in: i64,
        open_ms: i64,
    ) {
        let day = minute_number.div_euclid(MINUTES_PER_DAY as i64);
        let first_slot = (minute_number - day * MINUTES_PER_DAY as i64) as u16;
        let write = |slots, values| SlotWrite {
            service_id,
            day,
            slots,
            first_slot,
            values,
        };
        store
            .write_day_slots(&[
                write(Slots::BytesIn, vec![bytes_in]),
                write(Slots::BytesOut, vec![bytes_in]),
                write(Slots::Requests, vec![1]),
                write(Slots::OpenMs, vec![open_ms]),
            ])
            .await
            .expect("write slots");
    }

    #[test]
    fn granularity_follows_the_window() {
        // A minute window fits minutes.
        assert_eq!(Granularity::choose(0, 60), Granularity::Minute);
        // 60 minutes is 60 slots; 501 minutes needs hours.
        assert_eq!(Granularity::choose(0, 500 * 60), Granularity::Minute);
        assert_eq!(Granularity::choose(0, 501 * 60), Granularity::Hour);
        // A day is 24 hourly slots; 21 days is 504 hourly slots, so days.
        assert_eq!(Granularity::choose(0, 86_400), Granularity::Hour);
        assert_eq!(Granularity::choose(0, 20 * 86_400), Granularity::Hour);
        assert_eq!(Granularity::choose(0, 21 * 86_400), Granularity::Day);
    }

    #[test]
    fn blobs_round_trip() {
        let values: Vec<i64> = (0..MINUTES_PER_DAY as i64).map(|i| i * 7 - 3).collect();
        let blob = encode_blob(&values);
        assert!(
            blob.len() < values.len() * 8,
            "a linear array compresses below its raw size"
        );
        assert_eq!(decode_blob(&blob).unwrap(), values);
    }

    #[tokio::test]
    async fn a_whole_day_reads_the_total_not_the_blob() {
        let (store, service) = fixture().await;
        let metrics = MetricsStore::new(store);
        // One row with a day total and blobs that disagree with it, to prove the
        // whole-day read uses the column.
        let mut per_minute = vec![0_i64; MINUTES_PER_DAY];
        per_minute[0] = 999;
        let hours = encode_blob(&[0_i64; HOURS_PER_DAY]);
        let minutes = encode_blob(&per_minute);
        metrics
            .store()
            .db()
            .execute_unprepared(&format!(
                "INSERT INTO usage_daily (service_id, day, bytes_in, bytes_in_hours, bytes_in_minutes, \
                    bytes_out, bytes_out_hours, bytes_out_minutes, tunnel_in, tunnel_in_hours, tunnel_in_minutes, \
                    tunnel_out, tunnel_out_hours, tunnel_out_minutes, requests, requests_hours, requests_minutes, \
                    open_ms, open_ms_hours, open_ms_minutes) VALUES \
                 ({service}, 100, 500, X'{hours}', X'{minutes}', 0, X'{hours}', X'{minutes}', \
                  0, X'{hours}', X'{minutes}', 0, X'{hours}', X'{minutes}', 0, X'{hours}', X'{minutes}', \
                  0, X'{hours}', X'{minutes}')",
                hours = hex(&hours),
                minutes = hex(&minutes),
            ))
            .await
            .unwrap();

        let q = MetricsQuery {
            services: vec![service],
            people: Vec::new(),
            metrics: vec![Metric::BytesIn],
            from: 100 * 86_400,
            to: 121 * 86_400,
            function: Function::Sum,
        };
        let json: Value = serde_json::from_str(&metrics.query(&q).await.unwrap()).unwrap();
        assert_eq!(json["granularity"], 86_400, "three weeks is day-wide");
        assert_eq!(json["series"][0]["total"], 500);
        assert_eq!(
            json["series"][0]["slots"][0],
            json!([100, 500]),
            "the day total comes from the column, not the (999-byte) blob"
        );
        assert_eq!(json["series"][0]["slots"].as_array().unwrap().len(), 21);
    }

    #[tokio::test]
    async fn a_partial_day_is_sliced_from_the_blob() {
        let (store, service) = fixture().await;
        let metrics = MetricsStore::new(store);
        let mut per_minute = vec![0_i64; MINUTES_PER_DAY];
        for value in per_minute.iter_mut().take(120) {
            *value = 10;
        }
        let hours = encode_blob(&[1200_i64; HOURS_PER_DAY]);
        let minutes = encode_blob(&per_minute);
        let zeros = encode_blob(&[0_i64; HOURS_PER_DAY]);
        metrics
            .store()
            .db()
            .execute_unprepared(&format!(
                "INSERT INTO usage_daily (service_id, day, bytes_in, bytes_in_hours, bytes_in_minutes, \
                    bytes_out, bytes_out_hours, bytes_out_minutes, tunnel_in, tunnel_in_hours, tunnel_in_minutes, \
                    tunnel_out, tunnel_out_hours, tunnel_out_minutes, requests, requests_hours, requests_minutes, \
                    open_ms, open_ms_hours, open_ms_minutes) VALUES \
                 ({service}, 100, 1200, X'{hours}', X'{minutes}', 0, X'{zeros}', X'{zeros}', \
                  0, X'{zeros}', X'{zeros}', 0, X'{zeros}', X'{zeros}', 0, X'{zeros}', X'{zeros}', \
                  0, X'{zeros}', X'{zeros}')",
                hours = hex(&hours),
                minutes = hex(&minutes),
                zeros = hex(&zeros),
            ))
            .await
            .unwrap();

        // The first 30 minutes of day 100, a 30-minute window: minute grain.
        let from = 100 * 86_400;
        let q = MetricsQuery {
            services: vec![service],
            people: Vec::new(),
            metrics: vec![Metric::BytesIn],
            from,
            to: from + 30 * 60,
            function: Function::Sum,
        };
        let json: Value = serde_json::from_str(&metrics.query(&q).await.unwrap()).unwrap();
        assert_eq!(json["granularity"], 60);
        assert_eq!(json["series"][0]["total"], 300, "30 minutes of 10 bytes");
        // The hour array, sliced for the whole hour, would be 1200 — proving the
        // partial read went to the minute blob.
        assert_eq!(json["series"][0]["slots"].as_array().unwrap().len(), 30);

        // The whole-day total still comes from the column.
        let totals = metrics
            .totals(&[service], &[Metric::BytesIn], from, from + 86_400)
            .await
            .unwrap();
        assert_eq!(totals[&(service, Metric::BytesIn)], 1200);
    }

    /// A window that spans a folded day and the live day is answered as a
    /// single series: the caller cannot tell which side a value came from.
    #[tokio::test]
    async fn a_window_spanning_a_folded_day_and_the_live_day_is_uniform() {
        let (store, service) = fixture().await;
        let metrics = MetricsStore::new(store);
        // Folded day 100: 100 bytes in its first hour, minute and all.
        let mut hours = vec![0_i64; HOURS_PER_DAY];
        hours[0] = 100;
        let mut minutes = vec![0_i64; MINUTES_PER_DAY];
        minutes[0] = 100;
        let hours = encode_blob(&hours);
        let minutes = encode_blob(&minutes);
        let zeros = encode_blob(&[0_i64; HOURS_PER_DAY]);
        metrics
            .store()
            .db()
            .execute_unprepared(&format!(
                "INSERT INTO usage_daily (service_id, day, bytes_in, bytes_in_hours, bytes_in_minutes, \
                    bytes_out, bytes_out_hours, bytes_out_minutes, tunnel_in, tunnel_in_hours, tunnel_in_minutes, \
                    tunnel_out, tunnel_out_hours, tunnel_out_minutes, requests, requests_hours, requests_minutes, \
                    open_ms, open_ms_hours, open_ms_minutes) VALUES \
                 ({service}, 100, 100, X'{hours}', X'{minutes}', 0, X'{zeros}', X'{zeros}', \
                  0, X'{zeros}', X'{zeros}', 0, X'{zeros}', X'{zeros}', 0, X'{zeros}', X'{zeros}', \
                  0, X'{zeros}', X'{zeros}')",
                hours = hex(&hours),
                minutes = hex(&minutes),
                zeros = hex(&zeros),
            ))
            .await
            .unwrap();
        // Live day 101: 7 bytes at its first minute.
        minute(&metrics.store.clone(), service, 101 * 1440, 7, 0).await;

        let from = 100 * 86_400;
        let to = 102 * 86_400;
        let q = MetricsQuery {
            services: vec![service],
            people: Vec::new(),
            metrics: vec![Metric::BytesIn],
            from,
            to,
            function: Function::Sum,
        };
        let json: Value = serde_json::from_str(&metrics.query(&q).await.unwrap()).unwrap();
        assert_eq!(json["granularity"], 3_600, "two days is hour-wide");
        assert_eq!(json["series"][0]["total"], 107, "folded 100 + live 7");
        assert_eq!(json["series"][0]["slots"][0], json!([2400, 100]));
        assert_eq!(
            json["series"][0]["slots"][24],
            json!([2424, 7]),
            "day 101's first hour, from the live array"
        );

        // `totals` answers the same window with the same sum.
        let totals = metrics
            .totals(&[service], &[Metric::BytesIn], from, to)
            .await
            .unwrap();
        assert_eq!(totals[&(service, Metric::BytesIn)], 107);
    }

    #[tokio::test]
    async fn the_live_day_is_read_from_the_arrays() {
        let (store, service) = fixture().await;
        let metrics = MetricsStore::new(store);
        let from = 100 * 86_400;
        // Two live minutes in day 100, as slots.
        minute(&metrics.store.clone(), service, 100 * 1440, 5, 60_000).await;
        minute(&metrics.store.clone(), service, 100 * 1440 + 1, 7, 30_000).await;

        let q = MetricsQuery {
            services: vec![service],
            people: Vec::new(),
            metrics: vec![Metric::BytesIn, Metric::OpenMs],
            from,
            to: from + 10 * 60,
            function: Function::Sum,
        };
        let json: Value = serde_json::from_str(&metrics.query(&q).await.unwrap()).unwrap();
        let series = json["series"].as_array().unwrap();
        assert_eq!(series[0]["metric"], "bytes_in");
        assert_eq!(series[0]["total"], 12);
        assert_eq!(series[1]["metric"], "open_ms");
        assert_eq!(series[1]["total"], 90_000);

        let totals = metrics
            .totals(
                &[service],
                &[Metric::Requests, Metric::OpenMs],
                from,
                from + 86_400,
            )
            .await
            .unwrap();
        assert_eq!(totals[&(service, Metric::Requests)], 2);
        assert_eq!(totals[&(service, Metric::OpenMs)], 90_000);
    }

    #[tokio::test]
    async fn last_open_minutes_span_a_folded_day_and_the_live_day() {
        let (store, service) = fixture().await;
        let metrics = MetricsStore::new(store);
        // A folded day whose last open minute is index 5.
        let mut open_minutes = vec![0_i64; MINUTES_PER_DAY];
        open_minutes[5] = 60_000;
        let zeros = encode_blob(&[0_i64; HOURS_PER_DAY]);
        let minutes = encode_blob(&open_minutes);
        metrics
            .store()
            .db()
            .execute_unprepared(&format!(
                "INSERT INTO usage_daily (service_id, day, bytes_in, bytes_in_hours, bytes_in_minutes, \
                    bytes_out, bytes_out_hours, bytes_out_minutes, tunnel_in, tunnel_in_hours, tunnel_in_minutes, \
                    tunnel_out, tunnel_out_hours, tunnel_out_minutes, requests, requests_hours, requests_minutes, \
                    open_ms, open_ms_hours, open_ms_minutes) VALUES \
                 ({service}, 100, 0, X'{zeros}', X'{zeros}', 0, X'{zeros}', X'{zeros}', \
                  0, X'{zeros}', X'{zeros}', 0, X'{zeros}', X'{zeros}', 0, X'{zeros}', X'{zeros}', \
                  60000, X'{zeros}', X'{minutes}')",
                zeros = hex(&zeros),
                minutes = hex(&minutes),
            ))
            .await
            .unwrap();

        let seen = metrics.last_open_minutes(&[service]).await.unwrap();
        assert_eq!(seen[&service], 100 * 1440 + 5);

        // A later live minute wins: the read spans every day still in
        // `usage_live`, not only today.
        let today_minute = unix_secs().div_euclid(60);
        minute(&metrics.store.clone(), service, today_minute, 0, 60_000).await;
        let seen = metrics.last_open_minutes(&[service]).await.unwrap();
        assert_eq!(seen[&service], today_minute);
    }

    /// Lowercase hex, for building a SQL blob literal.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Folds a real backlog of live days and reports what it cost.
    ///
    /// Small and instant by default (one day for two services), so it runs with
    /// the rest of the suite. Scale it into a genuine backfill with
    /// `WVR_BACKFILL_DAYS` and `WVR_BACKFILL_SERVICES`:
    ///
    /// ```text
    /// WVR_BACKFILL_DAYS=30 WVR_BACKFILL_SERVICES=131 \
    ///   cargo test -p weaver-server --lib fold_backfill -- --nocapture
    /// ```
    ///
    /// The seeded days end yesterday, so every one of them is foldable; the day
    /// in progress is deliberately left unseeded.
    #[tokio::test]
    async fn fold_backfill_scales_with_the_env() {
        use std::time::Instant;

        let scale = |name: &str, default: i64| {
            match std::env::var(name) {
                // A typo in the knob fails the test rather than quietly running
                // the default size.
                Ok(raw) => raw
                    .parse()
                    .unwrap_or_else(|_| panic!("{name} must be an integer, got {raw:?}")),
                Err(_) => default,
            }
        };
        let days = scale("WVR_BACKFILL_DAYS", 1);
        let services = scale("WVR_BACKFILL_SERVICES", 2);
        let minutes = days * MINUTES_PER_DAY as i64;

        let store = Store::connect("sqlite::memory:").await.expect("store");
        let alice = store.create_test_person("alice").await.expect("person");
        let laptop = store
            .create_machine(alice.id, "laptop", &weaver_mux::KeyId::Ed25519([1; 32]))
            .await
            .expect("machine");
        for i in 0..services {
            store
                .get_or_create_service(laptop.id, &format!("svc{i}"))
                .await
                .expect("service");
        }

        let mut service_ids = Vec::new();
        for i in 0..services {
            service_ids.push(
                store
                    .get_or_create_service(laptop.id, &format!("svc{i}"))
                    .await
                    .expect("service")
                    .id,
            );
        }

        // One day of slots per (service, day), written in place: every service
        // gets every minute, with `bytes_in` climbing by one per minute so the
        // folded total is known ahead of time. Even minutes are fully open, odd
        // minutes never are.
        let per_day = MINUTES_PER_DAY as i64;
        let last_minute = unix_secs().div_euclid(SECS_PER_MINUTE).div_euclid(per_day) * per_day - 1;
        let first_minute = last_minute - minutes + 1;
        let first_day = first_minute.div_euclid(per_day);
        let seeded_at = Instant::now();
        for day in first_day..first_day + days {
            let mut writes = Vec::new();
            for &service_id in &service_ids {
                let offset = (day - first_day) * per_day;
                let per_minute = 0..per_day;
                let bytes_in = per_minute
                    .clone()
                    .map(|index| 100 + offset + index)
                    .collect();
                let bytes_out = per_minute
                    .clone()
                    .map(|index| 200 + offset + index)
                    .collect();
                let requests = vec![1_i64; MINUTES_PER_DAY];
                let open_ms = per_minute
                    .map(|index| if (offset + index) % 2 == 0 { 60_000 } else { 0 })
                    .collect();
                for (slots, values) in [
                    (Slots::BytesIn, bytes_in),
                    (Slots::BytesOut, bytes_out),
                    (Slots::Requests, requests),
                    (Slots::OpenMs, open_ms),
                ] {
                    writes.push(SlotWrite {
                        service_id,
                        day,
                        slots,
                        first_slot: 0,
                        values,
                    });
                }
            }
            store.write_day_slots(&writes).await.expect("seed slots");
        }
        let seeded = seeded_at.elapsed();

        let metrics = MetricsStore::new(store);
        let folded_at = Instant::now();
        let folded = metrics.fold_finished_days().await.expect("fold");
        let folded_in = folded_at.elapsed();

        let rows = minutes * services;
        let rollup = usage_daily::Entity::find()
            .all(metrics.store().db())
            .await
            .unwrap();
        let blob_pair = rollup.first().map_or(0, |row| {
            row.bytes_in_minutes.len() + row.bytes_in_hours.len()
        });
        eprintln!(
            "backfill: {days} day(s) x {services} service(s) = {rows} minute slot(s); seeded in {seeded:?}, \
             folded {folded} day(s) in {folded_in:?} ({:.0} minute slots/s); rollup {} row(s), {blob_pair} B \
             of bytes_in blobs per row",
            rows as f64 / folded_in.as_secs_f64(),
            rollup.len()
        );

        assert_eq!(folded as i64, days);
        assert_eq!(rollup.len() as i64, days * services);
        // A rollup row covers exactly one day, and the climb restarts at zero at
        // the start of the window, so a row's total depends on how far into the
        // window its day sits.
        let climb = per_day * (per_day - 1) / 2;
        for row in &rollup {
            assert_eq!(
                row.bytes_in,
                per_day * 100 + per_day * (row.day - first_day) * per_day + climb
            );
            assert_eq!(
                row.open_ms,
                per_day / 2 * 60_000,
                "only the even minutes are open"
            );
            assert_eq!(
                decode_blob(&row.bytes_in_minutes).unwrap().len(),
                MINUTES_PER_DAY
            );
            assert_eq!(
                decode_blob(&row.bytes_in_hours).unwrap().len(),
                HOURS_PER_DAY
            );
        }
        // Every seeded slot was folded away into the rollup; nothing is left
        // live for a finished day.
        let backend = metrics.store().db().get_database_backend();
        let left: i64 = metrics
            .store()
            .db()
            .query_one_raw(Statement::from_string(
                backend,
                "SELECT COUNT(*) FROM usage_live".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index(0)
            .unwrap();
        assert_eq!(left, 0);
    }
}
