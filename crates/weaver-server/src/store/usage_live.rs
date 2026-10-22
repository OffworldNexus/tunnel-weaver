//! `usage_live` storage: the current day's slots, written in place.
//!
//! This is the only module that knows how a live day is represented, and the
//! only module with `unsafe`. The public surface is three typed methods on
//! [`Store`]:
//!
//! * [`Store::ensure_day_slots`] pre-allocates the `(service, day)` rows with
//!   `zeroblob(11520)` so a later in-place write always has a row to write to;
//! * [`Store::write_day_slots`] applies a batch of [`SlotWrite`]s, all in one
//!   transaction;
//! * [`Store::read_day_slots`] / [`Store::read_day_slots_of`] decode the arrays
//!   back into `i64`s.
//!
//! ## Why the SQLite path uses the C blob API
//!
//! A live day is six 11,520-byte cells per service. A flush rewrites a handful
//! of consecutive 8-byte slots per metric, so the natural write is
//! `sqlite3_blob_open` + `sqlite3_blob_write` + `sqlite3_blob_close` — it edits
//! the pages in place instead of rewriting the whole cell or touching 1,440
//! rows. To use it we need the raw `sqlite3 *`, which is reached through
//! sqlx's own handle API (see [`Store::write_day_slots`]).
//!
//! ## Hard rules for the blob handle
//!
//! 1. A [`LockedSqliteHandle`](sqlx::sqlite::LockedSqliteHandle) is valid only
//!    until another statement runs on that connection, so the FFI happens in
//!    one tight non-`async` block per write and **no statement is issued while
//!    a handle is open**. All `SELECT rowid`s and the `INSERT OR IGNORE`s run
//!    before the first handle is opened.
//! 2. The handle must not be held across an `await`: the lock is released the
//!    moment the block ends, and the next write re-acquires it.
//! 3. `column` comes from [`Slots::column`] — a fixed allow-list — never from
//!    concatenating anything a caller supplied.
//!
//! Only SQLite gets in-place writes; the non-SQLite path (which cannot be
//! compiled in today) rewrites the array with an SQL concatenation.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;

use sea_orm::sea_query::{OnConflict, Value};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, QueryFilter, QueryOrder, QuerySelect,
    Set, Statement, TransactionTrait,
};
use sqlx::Connection as _;

use super::entity::{service, usage_live};
use super::{Store, StoreError};

/// Minutes in one day, and therefore slots in one `*_slots` cell.
pub const MINUTES_PER_DAY: usize = 1_440;

/// Bytes of one `*_slots` cell: 1,440 little-endian `i64`, uncompressed.
pub const SLOT_BYTES: usize = MINUTES_PER_DAY * 8;

/// The six metered quantities, so a caller names a metric without writing SQL.
///
/// The variant order matches `crate::metrics::Metric::ALL`, which is also the
/// order the fold emits, but this enum exists on its own so the storage layer
/// needs no dependency on the metrics module.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Slots {
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

impl Slots {
    /// Every slot column, in a stable order.
    pub const ALL: [Slots; 6] = [
        Slots::BytesIn,
        Slots::BytesOut,
        Slots::TunnelIn,
        Slots::TunnelOut,
        Slots::Requests,
        Slots::OpenMs,
    ];

    /// The `usage_live` column this names.
    ///
    /// This is the **only** place a column name is chosen, so SQL and FFI can
    /// address an allow-listed column and nothing else.
    pub fn column(self) -> &'static str {
        match self {
            Slots::BytesIn => "bytes_in_slots",
            Slots::BytesOut => "bytes_out_slots",
            Slots::TunnelIn => "tunnel_in_slots",
            Slots::TunnelOut => "tunnel_out_slots",
            Slots::Requests => "requests_slots",
            Slots::OpenMs => "open_ms_slots",
        }
    }

    /// This slot's position in [`Slots::ALL`], i.e. the metric's index.
    pub(crate) fn index(self) -> usize {
        match self {
            Slots::BytesIn => 0,
            Slots::BytesOut => 1,
            Slots::TunnelIn => 2,
            Slots::TunnelOut => 3,
            Slots::Requests => 4,
            Slots::OpenMs => 5,
        }
    }
}

/// One in-place write of consecutive slots of one metric's day array.
///
/// `values[0]` lands at slot `first_slot` and the rest follow it. A write is
/// **absolute**: it replaces what the slots held. The flush only ever writes
/// minutes it has complete knowledge of (a drained bucket), so nothing else has
/// written those slots since.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotWrite {
    pub service_id: i32,
    pub day: i64,
    pub slots: Slots,
    pub first_slot: u16,
    pub values: Vec<i64>,
}

impl SlotWrite {
    /// Rejects a range that would run off the end of the day's array, and
    /// `open_ms` outside `0..=60_000`.
    ///
    /// The upper bound on `open_ms` is the one the old stored inversion
    /// enforced: storage refuses an impossible open time rather than clamping
    /// it silently.
    fn validate(&self) -> Result<(), StoreError> {
        let end = self.first_slot as usize + self.values.len();
        if self.values.is_empty() || end > MINUTES_PER_DAY {
            return Err(StoreError::InvalidUsage(format!(
                "slot write covers {}..{end} of a {MINUTES_PER_DAY}-slot day",
                self.first_slot
            )));
        }
        if self.slots == Slots::OpenMs
            && let Some(bad) = self.values.iter().find(|v| !(0..=60_000).contains(*v))
        {
            return Err(StoreError::InvalidUsage(format!(
                "open_ms {bad} is outside 0..=60000"
            )));
        }
        Ok(())
    }
}

impl Store {
    /// Creates the `usage_live` row of every `(service, day)` pair that needs
    /// one, with its six cells pre-allocated to 11,520 zero bytes.
    ///
    /// Idempotent: a row that already exists is left untouched (its slots keep
    /// whatever they hold), so this is safe to call before every write and safe
    /// to call twice. Pairs whose service has been deleted meanwhile are
    /// dropped rather than failing the whole batch on the foreign key — the
    /// service is gone, so there is nothing left to meter.
    pub async fn ensure_day_slots(&self, rows: &[(i32, i64)]) -> Result<(), StoreError> {
        if rows.is_empty() {
            return Ok(());
        }
        let pairs = self.writable_pairs(rows.iter().copied()).await?;
        if pairs.is_empty() {
            return Ok(());
        }
        let txn = self.db.begin().await?;
        match self.backend() {
            DbBackend::Sqlite => {
                for &(service_id, day) in &pairs {
                    txn.execute_raw(Statement::from_sql_and_values(
                        DbBackend::Sqlite,
                        INSERT_IGNORE_SQL,
                        [Value::from(service_id), Value::from(day)],
                    ))
                    .await?;
                }
            }
            _ => ensure_rows_portable(&txn, &pairs).await?,
        }
        txn.commit().await?;
        Ok(())
    }

    /// Writes a batch of consecutive slots in one transaction: every row is
    /// ensured first, then the slots are written in place.
    ///
    /// **SQLite** acquires exactly one pooled connection for the whole batch
    /// and reaches its raw `sqlite3 *` through sqlx's
    /// `SqliteConnection::lock_handle()`, so `sqlite3_blob_open` /
    /// `sqlite3_blob_write` / `sqlite3_blob_close` edit the cells in place.
    /// A blob handle is only valid until another statement runs on the
    /// connection, so every `INSERT OR IGNORE` and every `SELECT rowid` runs
    /// *before* the first handle is opened, and each handle is opened, written
    /// and closed inside one tight block with no `await`. See the module docs.
    ///
    /// Other backends rewrite each array with
    /// `substr(col, 1, ?) || X'<values>' || substr(col, ? + n + 1)`; they are
    /// honest but not in-place, and are not compiled in today.
    pub async fn write_day_slots(&self, writes: &[SlotWrite]) -> Result<(), StoreError> {
        if writes.is_empty() {
            return Ok(());
        }
        let mut writes: Vec<&SlotWrite> = writes.iter().collect();
        for write in &writes {
            write.validate()?;
        }
        let pairs = self
            .writable_pairs(writes.iter().map(|w| (w.service_id, w.day)))
            .await?;
        writes.retain(|w| pairs.binary_search(&(w.service_id, w.day)).is_ok());
        if writes.is_empty() {
            return Ok(());
        }

        if self.backend() != DbBackend::Sqlite {
            return self.write_day_slots_sql(&writes, &pairs).await;
        }

        let pool = self.db.get_sqlite_connection_pool();
        let mut conn = pool.acquire().await.map_err(sqlx_error)?;
        let mut txn = conn.begin().await.map_err(sqlx_error)?;

        // 1. Every row must exist before any blob handle is opened.
        for &(service_id, day) in &pairs {
            sqlx::query(INSERT_IGNORE_SQL)
                .bind(service_id)
                .bind(day)
                .execute(&mut *txn)
                .await
                .map_err(sqlx_error)?;
        }

        // 2. Resolve every rowid up front: a `SELECT` after a handle is open
        //    would invalidate it.
        let mut rowids: HashMap<(i32, i64), i64> = HashMap::with_capacity(pairs.len());
        for &pair in &pairs {
            let rowid: i64 =
                sqlx::query_scalar("SELECT rowid FROM usage_live WHERE service_id = ? AND day = ?")
                    .bind(pair.0)
                    .bind(pair.1)
                    .fetch_one(&mut *txn)
                    .await
                    .map_err(sqlx_error)?;
            rowids.insert(pair, rowid);
        }

        // 3. In-place writes. Each handle lives only inside its own block, and
        //    no statement runs while one is open.
        for write in &writes {
            let rowid = rowids[&(write.service_id, write.day)];
            let column = write.slots.column();
            let bytes = encode_slots(&write.values);
            let offset = i64::from(write.first_slot) * 8;
            let mut handle = txn.lock_handle().await.map_err(sqlx_error)?;
            let db_handle = handle.as_raw_handle();
            // SAFETY: the handle is held exclusively for this block, so no
            // other statement can run on the connection; `column` is an
            // allow-listed identifier and the byte range is inside the
            // 11,520-byte cell because `validate` checked it.
            unsafe { blob_write_at(db_handle.as_ptr(), column, rowid, &bytes, offset)? };
        }

        txn.commit().await.map_err(sqlx_error)?;
        Ok(())
    }

    /// The non-SQLite write path: rewrite each array with SQL concatenation.
    ///
    /// Not in-place and not implemented for any backend compiled today; it
    /// exists so a future `sqlx-postgres` build has an honest, correct answer
    /// instead of a panic.
    async fn write_day_slots_sql(
        &self,
        writes: &[&SlotWrite],
        pairs: &[(i32, i64)],
    ) -> Result<(), StoreError> {
        let backend = self.backend();
        let txn = self.db.begin().await?;
        ensure_rows_portable(&txn, pairs).await?;
        for write in writes {
            let column = write.slots.column();
            let hex = hex::encode(encode_slots(&write.values));
            let offset = i64::from(write.first_slot) * 8;
            let length = (write.values.len() as i64) * 8;
            let sql = format!(
                "UPDATE usage_live SET {column} = substr({column}, 1, ?) || X'{hex}' \
                 || substr({column}, ? + {length} + 1) \
                 WHERE service_id = ? AND day = ?"
            );
            txn.execute_raw(Statement::from_sql_and_values(
                backend,
                sql,
                [
                    Value::from(offset),
                    Value::from(offset),
                    Value::from(write.service_id),
                    Value::from(write.day),
                ],
            ))
            .await?;
        }
        txn.commit().await?;
        Ok(())
    }

    /// Decodes every metric's array for the given services and day.
    ///
    /// Only rows that exist are returned; a missing service/day is simply
    /// absent, which callers read as all-zeroes.
    pub async fn read_day_slots(
        &self,
        services: &[i32],
        day: i64,
    ) -> Result<HashMap<(i32, Slots), Vec<i64>>, StoreError> {
        self.read_day_slots_of(services, day, &Slots::ALL).await
    }

    /// Decodes a caller-chosen subset of the six arrays for `services` and
    /// `day`, so a reader that needs one metric does not pay for six.
    pub async fn read_day_slots_of(
        &self,
        services: &[i32],
        day: i64,
        slots: &[Slots],
    ) -> Result<HashMap<(i32, Slots), Vec<i64>>, StoreError> {
        if services.is_empty() || slots.is_empty() {
            return Ok(HashMap::new());
        }
        decode_slot_rows(&self.db, Some(services), day, slots).await
    }

    /// The span the window's data actually covers: its first and last minute
    /// carrying any metered traffic, as minute numbers.
    ///
    /// A rate needs a duration, and the duration is a fact about the traffic —
    /// not about the window somebody asked for. A relay that came up two minutes
    /// ago has two minutes of data; dividing that by a thirty-day window invents
    /// a figure out of nothing, which is worse than showing none. The live day is
    /// measured to the minute; a day already folded is measured from its first
    /// minute, so the error there is at most a day, on a span already counted in
    /// days. `None` when nothing in the window carried traffic.
    pub async fn covered_span(
        &self,
        services: &[i32],
        from: i64,
        to: i64,
    ) -> Result<Option<(i64, i64)>, StoreError> {
        if services.is_empty() {
            return Ok(None);
        }
        let per_day = MINUTES_PER_DAY as i64;
        let mut minutes: Vec<i64> = Vec::new();

        // Folded days, at day resolution.
        let placeholders = vec!["?"; services.len()].join(", ");
        let mut values: Vec<Value> = vec![
            Value::from(from.div_euclid(per_day * 60)),
            Value::from(to.div_euclid(per_day * 60)),
        ];
        values.extend(services.iter().map(|service| Value::from(*service)));
        let sql = format!(
            "SELECT MIN(day), MAX(day) FROM usage_daily WHERE day BETWEEN ? AND ? \
             AND service_id IN ({placeholders}) \
             AND (bytes_in + bytes_out + tunnel_in + tunnel_out + requests) > 0"
        );
        let backend = self.db.get_database_backend();
        if let Some(row) = self
            .db
            .query_one_raw(Statement::from_sql_and_values(backend, sql, values))
            .await?
        {
            let earliest: Option<i64> = row.try_get_by_index(0)?;
            let latest: Option<i64> = row.try_get_by_index(1)?;
            if let (Some(earliest), Some(latest)) = (earliest, latest) {
                minutes.push(earliest * per_day);
                minutes.push((latest + 1) * per_day - 1);
            }
        }

        // The live day, to the minute: this is the end that matters when the
        // relay has only just come up.
        let mut days: Vec<i64> = self
            .live_days(services)
            .await?
            .into_iter()
            .map(|(_, day)| day)
            .filter(|day| day * per_day * 60 <= to && (day + 1) * per_day * 60 > from)
            .collect();
        days.sort_unstable();
        days.dedup();
        for day in days {
            for values in self
                .read_day_slots_of(services, day, &[Slots::BytesIn])
                .await?
                .into_values()
            {
                if let Some(index) = values.iter().position(|value| *value > 0) {
                    minutes.push(day * per_day + index as i64);
                }
                if let Some(index) = values.iter().rposition(|value| *value > 0) {
                    minutes.push(day * per_day + index as i64);
                }
            }
        }

        Ok(minutes
            .iter()
            .min()
            .copied()
            .zip(minutes.iter().max().copied()))
    }

    /// Every `(service_id, day)` that currently has a live row, for `services`,
    /// in `(service, day)` order.
    ///
    /// In steady state this is one row per service (today); a lagging fold can
    /// leave a few finished days here, which the uniform readers count as live.
    pub async fn live_days(&self, services: &[i32]) -> Result<Vec<(i32, i64)>, StoreError> {
        if services.is_empty() {
            return Ok(Vec::new());
        }
        Ok(usage_live::Entity::find()
            .select_only()
            .column(usage_live::Column::ServiceId)
            .column(usage_live::Column::Day)
            .filter(usage_live::Column::ServiceId.is_in(services.iter().copied()))
            .order_by_asc(usage_live::Column::ServiceId)
            .order_by_asc(usage_live::Column::Day)
            .into_tuple::<(i32, i64)>()
            .all(&self.db)
            .await?)
    }

    /// The de-duplicated, sorted `(service, day)` pairs whose service still
    /// exists, so a write to a revoked machine is dropped, not an error.
    async fn writable_pairs(
        &self,
        pairs: impl Iterator<Item = (i32, i64)>,
    ) -> Result<Vec<(i32, i64)>, StoreError> {
        let mut wanted: Vec<(i32, i64)> = pairs.collect();
        wanted.sort_unstable();
        wanted.dedup();
        if wanted.is_empty() {
            return Ok(wanted);
        }
        let ids: Vec<i32> = {
            let mut ids: Vec<i32> = wanted.iter().map(|(service, _)| *service).collect();
            ids.dedup();
            ids
        };
        let existing: HashSet<i32> = service::Entity::find()
            .select_only()
            .column(service::Column::Id)
            .filter(service::Column::Id.is_in(ids))
            .into_tuple::<i32>()
            .all(&self.db)
            .await?
            .into_iter()
            .collect();
        wanted.retain(|(service, _)| existing.contains(service));
        Ok(wanted)
    }
}

/// Every day strictly before `before_day` that still has live rows.
///
/// Drives the fold; one day means one transaction.
pub(crate) async fn days_with_live_rows(
    db: &impl ConnectionTrait,
    before_day: i64,
) -> Result<Vec<i64>, StoreError> {
    Ok(usage_live::Entity::find()
        .select_only()
        .column(usage_live::Column::Day)
        .filter(usage_live::Column::Day.lt(before_day))
        .group_by(usage_live::Column::Day)
        .order_by_asc(usage_live::Column::Day)
        .into_tuple::<i64>()
        .all(db)
        .await?)
}

/// Decodes every service's requested arrays for one day, inside `db`'s
/// transaction, so a fold reads the day it is about to compress and delete as
/// one atomic unit.
pub(crate) async fn live_day_slots(
    db: &impl ConnectionTrait,
    day: i64,
    slots: &[Slots],
) -> Result<HashMap<(i32, Slots), Vec<i64>>, StoreError> {
    decode_slot_rows(db, None, day, slots).await
}

/// Deletes every live row of one day, returning how many were removed.
pub(crate) async fn delete_live_day(
    db: &impl ConnectionTrait,
    day: i64,
) -> Result<u64, StoreError> {
    Ok(usage_live::Entity::delete_many()
        .filter(usage_live::Column::Day.eq(day))
        .exec(db)
        .await?
        .rows_affected)
}

/// The `INSERT OR IGNORE` that pre-allocates one live row.
///
/// `zeroblob(11_520)` is the point: it creates the six cells at their final
/// size without shipping 69 KB of zeroes from Rust for every service, and it
/// makes a later in-place blob write impossible to miss. The statement is a
/// literal — no identifier or value is interpolated, so it is auditable by eye
/// and acceptable to sqlx's SQL-safety check; `SLOT_BYTES` is tied to the
/// embedded `11_520` by the assertion below.
const INSERT_IGNORE_SQL: &str = "INSERT OR IGNORE INTO usage_live \
     (service_id, day, bytes_in_slots, bytes_out_slots, tunnel_in_slots, \
      tunnel_out_slots, requests_slots, open_ms_slots) \
     VALUES (?, ?, zeroblob(11520), zeroblob(11520), zeroblob(11520), \
             zeroblob(11520), zeroblob(11520), zeroblob(11520))";

const _: () = assert!(SLOT_BYTES == 11_520);

/// The portable `INSERT OR IGNORE`: a bound zero array, conflict-do-nothing.
///
/// Only reached by [`Store::write_day_slots_sql`], i.e. never on SQLite.
async fn ensure_rows_portable(
    db: &impl ConnectionTrait,
    pairs: &[(i32, i64)],
) -> Result<(), StoreError> {
    let zeros = vec![0_u8; SLOT_BYTES];
    for &(service_id, day) in pairs {
        usage_live::Entity::insert(usage_live::ActiveModel {
            service_id: Set(service_id),
            day: Set(day),
            bytes_in_slots: Set(zeros.clone()),
            bytes_out_slots: Set(zeros.clone()),
            tunnel_in_slots: Set(zeros.clone()),
            tunnel_out_slots: Set(zeros.clone()),
            requests_slots: Set(zeros.clone()),
            open_ms_slots: Set(zeros.clone()),
        })
        .on_conflict(
            OnConflict::columns([usage_live::Column::ServiceId, usage_live::Column::Day])
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(db)
        .await?;
    }
    Ok(())
}

/// Reads the requested arrays for `services` (or every service when `None`)
/// and `day`, decoding each cell into little-endian `i64`s.
async fn decode_slot_rows(
    db: &impl ConnectionTrait,
    services: Option<&[i32]>,
    day: i64,
    slots: &[Slots],
) -> Result<HashMap<(i32, Slots), Vec<i64>>, StoreError> {
    if slots.is_empty() || services.is_some_and(|services| services.is_empty()) {
        return Ok(HashMap::new());
    }
    let columns: Vec<&str> = slots.iter().map(|slot| slot.column()).collect();
    let mut sql = format!(
        "SELECT service_id, {} FROM usage_live WHERE day = ?",
        columns.join(", ")
    );
    let mut values = vec![Value::from(day)];
    if let Some(services) = services {
        let placeholders = vec!["?"; services.len()].join(", ");
        sql.push_str(&format!(" AND service_id IN ({placeholders})"));
        values.extend(services.iter().map(|service| Value::from(*service)));
    }
    let backend = db.get_database_backend();
    let mut decoded: HashMap<(i32, Slots), Vec<i64>> = HashMap::new();
    for row in db
        .query_all_raw(Statement::from_sql_and_values(backend, sql, values))
        .await?
    {
        let service_id: i32 = row.try_get_by_index(0)?;
        for (index, &slot) in slots.iter().enumerate() {
            let bytes: Vec<u8> = row.try_get_by_index(index + 1)?;
            decoded.insert((service_id, slot), decode_slots(&bytes)?);
        }
    }
    Ok(decoded)
}

/// Packs an `i64` array into the little-endian bytes a live cell holds.
fn encode_slots(values: &[i64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(values.len() * 8);
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

/// Unpacks a live cell back into its `i64` array.
///
/// The cell is always the **whole** day: the row is pre-allocated with all 1,440
/// slots, and a minute that was never written is a zero *inside* that
/// allocation, never a missing tail. A cell of any other length is therefore
/// corruption — a truncated cell, a text value, a row edited outside the API —
/// and it is refused rather than decoded. A cell that cannot be decoded must
/// never be quietly read as a day of zeroes.
fn decode_slots(bytes: &[u8]) -> Result<Vec<i64>, StoreError> {
    if bytes.len() != SLOT_BYTES {
        return Err(StoreError::InvalidUsage(format!(
            "usage_live cell of {} bytes is not the {SLOT_BYTES}-byte day array",
            bytes.len()
        )));
    }
    let (chunks, remainder) = bytes.as_chunks::<8>();
    debug_assert!(remainder.is_empty(), "checked above");
    Ok(chunks
        .iter()
        .map(|chunk| i64::from_le_bytes(*chunk))
        .collect())
}

/// Maps an sqlx failure onto the store's error type.
fn sqlx_error(error: sqlx::Error) -> StoreError {
    StoreError::Db(sea_orm::DbErr::Exec(sea_orm::RuntimeErr::SqlxError(
        std::sync::Arc::new(error),
    )))
}

/// Writes `bytes` at byte `offset` of one cell, in place, through the SQLite C
/// blob API.
///
/// The caller must hold the connection's [`LockedSqliteHandle`] for the whole
/// call and must not run another statement until it returns (see the module
/// docs). `column` must be one of [`Slots::column`]'s names.
///
/// # Safety
///
/// `db` must be a live `sqlite3 *` belonging to the connection whose handle the
/// caller holds, and `rowid` must address a row of `usage_live` whose cell is
/// at least `offset + bytes.len()` bytes long.
unsafe fn blob_write_at(
    db: *mut libsqlite3_sys::sqlite3,
    column: &str,
    rowid: i64,
    bytes: &[u8],
    offset: i64,
) -> Result<(), StoreError> {
    use libsqlite3_sys::{SQLITE_OK, sqlite3_blob_close, sqlite3_blob_open, sqlite3_blob_write};

    if bytes.is_empty() {
        return Ok(());
    }
    let database = c"main";
    let table = c"usage_live";
    let name = CString::new(column).expect("allow-listed column names hold no NUL");
    let mut blob: *mut libsqlite3_sys::sqlite3_blob = std::ptr::null_mut();
    // SAFETY: `db` is live for the caller's lock; the C strings outlive the
    // call; `blob` is written only on success.
    let rc = unsafe {
        sqlite3_blob_open(
            db,
            database.as_ptr(),
            table.as_ptr(),
            name.as_ptr(),
            rowid,
            1,
            &mut blob,
        )
    };
    if rc != SQLITE_OK {
        return Err(sqlite_error_message(db, "sqlite3_blob_open", rc));
    }
    let written = bytes.len() as std::os::raw::c_int;
    let start = offset as std::os::raw::c_int;
    // SAFETY: the handle is open on a cell of at least `offset + len` bytes
    // (validated by the caller) and stays open until `blob` is released below.
    let rc = unsafe { sqlite3_blob_write(blob, bytes.as_ptr().cast(), written, start) };
    // Always close: a failed write must not leak the handle.
    let closed = unsafe { sqlite3_blob_close(blob) };
    if rc != SQLITE_OK {
        return Err(sqlite_error_message(db, "sqlite3_blob_write", rc));
    }
    if closed != SQLITE_OK {
        return Err(sqlite_error_message(db, "sqlite3_blob_close", closed));
    }
    Ok(())
}

/// Builds a `StoreError` from SQLite's connection-local error message.
fn sqlite_error_message(
    db: *mut libsqlite3_sys::sqlite3,
    operation: &str,
    rc: std::os::raw::c_int,
) -> StoreError {
    // SAFETY: `db` is live (the caller holds the locked handle). `errmsg`
    // returns a NUL-terminated string owned by the connection, valid until the
    // next call on it, which nothing can make in between.
    let message = unsafe {
        let pointer = libsqlite3_sys::sqlite3_errmsg(db);
        if pointer.is_null() {
            String::new()
        } else {
            std::ffi::CStr::from_ptr(pointer)
                .to_string_lossy()
                .into_owned()
        }
    };
    StoreError::Db(sea_orm::DbErr::Exec(sea_orm::RuntimeErr::Internal(
        format!("{operation} failed (sqlite rc {rc}): {message}"),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store with one person, one machine and one service.
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

    /// Writes one metric's slots at `first_slot` of `day`.
    async fn write(
        store: &Store,
        service: i32,
        day: i64,
        slots: Slots,
        first: u16,
        values: &[i64],
    ) {
        store
            .write_day_slots(&[SlotWrite {
                service_id: service,
                day,
                slots,
                first_slot: first,
                values: values.to_vec(),
            }])
            .await
            .expect("write slots");
    }

    /// Reads back one metric's decoded array.
    async fn read(store: &Store, service: i32, day: i64, slots: Slots) -> Vec<i64> {
        store
            .read_day_slots_of(&[service], day, &[slots])
            .await
            .expect("read slots")
            .remove(&(service, slots))
            .expect("a written day has an array")
    }

    /// A cell that is not the whole day array is corruption: the read must fail
    /// rather than decode the wreckage into a day of zeroes.
    #[tokio::test]
    async fn a_cell_that_is_not_the_whole_day_is_refused() {
        let (store, service) = fixture().await;
        let (day, first) = (1, 0_u16);
        write(&store, service, day, Slots::BytesIn, first, &[7]).await;
        // Damage it the way a foreign writer would: an empty text value where
        // the 11,520-byte day array belongs.
        store
            .db()
            .execute_unprepared(&format!(
                "UPDATE usage_live SET bytes_in_slots = '' \
                 WHERE service_id = {service} AND day = {day}"
            ))
            .await
            .expect("damage the cell");

        let error = store
            .read_day_slots_of(&[service], day, &[Slots::BytesIn])
            .await
            .expect_err("a cell that is not a whole day must not read as zeroes");
        assert!(
            error.to_string().contains("day array"),
            "the error must name what it expected: {error}"
        );
    }

    /// A cell is exactly 11,520 bytes, so `read_day_slots` can hand the caller a
    /// whole 1,440-slot day even after a single-slot write.
    #[tokio::test]
    async fn a_write_pre_allocates_the_whole_day() {
        let (store, service) = fixture().await;
        write(&store, service, 7, Slots::BytesIn, 3, &[42]).await;

        let values = read(&store, service, 7, Slots::BytesIn).await;
        assert_eq!(values.len(), MINUTES_PER_DAY, "the cell is the whole day");
        assert_eq!(values[3], 42);
        assert_eq!(values[2], 0);
        assert_eq!(values[4], 0);
        // The other five metrics of the same row were pre-allocated too.
        for slot in Slots::ALL {
            assert_eq!(read(&store, service, 7, slot).await.len(), MINUTES_PER_DAY);
        }
    }

    /// Out-of-order and overlapping writes land at the slots they name, and a
    /// repeated write replaces the slot rather than accumulating.
    #[tokio::test]
    async fn later_writes_land_at_the_right_offsets() {
        let (store, service) = fixture().await;
        // Written out of order, at offsets that do not touch each other.
        write(&store, service, 7, Slots::Requests, 5, &[5]).await;
        write(&store, service, 7, Slots::Requests, 1, &[1]).await;
        write(&store, service, 7, Slots::Requests, 3, &[3, 4]).await;
        // An overlapping run replaces its range.
        write(&store, service, 7, Slots::Requests, 4, &[40, 50]).await;

        let values = read(&store, service, 7, Slots::Requests).await;
        assert_eq!(&values[0..7], &[0, 1, 0, 3, 40, 50, 0]);
    }

    /// `ensure_day_slots` twice creates nothing new and keeps what is stored.
    #[tokio::test]
    async fn ensure_day_slots_is_idempotent() {
        let (store, service) = fixture().await;
        store
            .ensure_day_slots(&[(service, 7), (service, 8)])
            .await
            .expect("first");
        write(&store, service, 7, Slots::BytesIn, 0, &[9]).await;
        store
            .ensure_day_slots(&[(service, 7), (service, 8)])
            .await
            .expect("second");
        assert_eq!(read(&store, service, 7, Slots::BytesIn).await[0], 9);
        assert_eq!(
            store.live_days(&[service]).await.unwrap(),
            vec![(service, 7), (service, 8)]
        );
    }

    /// A write whose day has no row creates only that row: it cannot reach into
    /// another day's array.
    #[tokio::test]
    async fn a_write_creates_only_its_own_row() {
        let (store, service) = fixture().await;
        write(&store, service, 7, Slots::BytesIn, 0, &[11]).await;
        // Day 8 has no row at all: the write must create it, not touch day 7.
        write(&store, service, 8, Slots::BytesIn, 0, &[22]).await;

        assert_eq!(read(&store, service, 7, Slots::BytesIn).await[0], 11);
        assert_eq!(read(&store, service, 8, Slots::BytesIn).await[0], 22);
        assert_eq!(
            store.live_days(&[service]).await.unwrap(),
            vec![(service, 7), (service, 8)]
        );
    }

    /// One batch across several services, days and metrics all lands.
    #[tokio::test]
    async fn a_batch_lands_across_services_days_and_metrics() {
        let (store, first) = fixture().await;
        let alice = store.get_person_by_name("alice").await.unwrap().unwrap();
        let laptop = store.list_machines(alice.id).await.unwrap()[0].clone();
        let second = store
            .get_or_create_service(laptop.id, "api")
            .await
            .unwrap()
            .id;

        store
            .write_day_slots(&[
                SlotWrite {
                    service_id: first,
                    day: 3,
                    slots: Slots::BytesIn,
                    first_slot: 10,
                    values: vec![1, 2, 3],
                },
                SlotWrite {
                    service_id: first,
                    day: 4,
                    slots: Slots::OpenMs,
                    first_slot: 0,
                    values: vec![60_000],
                },
                SlotWrite {
                    service_id: second,
                    day: 3,
                    slots: Slots::TunnelOut,
                    first_slot: 1_439,
                    values: vec![7],
                },
            ])
            .await
            .expect("batch");

        assert_eq!(
            &read(&store, first, 3, Slots::BytesIn).await[10..13],
            &[1, 2, 3]
        );
        assert_eq!(read(&store, first, 4, Slots::OpenMs).await[0], 60_000);
        assert_eq!(read(&store, second, 3, Slots::TunnelOut).await[1_439], 7);
    }

    /// A write for a service that no longer exists is dropped, not an error,
    /// so one revoked machine cannot sink a flush.
    #[tokio::test]
    async fn a_revoked_services_write_is_dropped() {
        let (store, kept) = fixture().await;
        let alice = store.get_person_by_name("alice").await.unwrap().unwrap();
        let key = weaver_mux::KeyId::Ed25519([2; 32]);
        let gone_machine = store
            .create_machine(alice.id, "desktop", &key)
            .await
            .unwrap();
        let gone = store
            .get_or_create_service(gone_machine.id, "web")
            .await
            .unwrap()
            .id;
        store.revoke_machine(&key).await.unwrap();

        store
            .write_day_slots(&[
                SlotWrite {
                    service_id: kept,
                    day: 1,
                    slots: Slots::Requests,
                    first_slot: 0,
                    values: vec![3],
                },
                SlotWrite {
                    service_id: gone,
                    day: 1,
                    slots: Slots::Requests,
                    first_slot: 0,
                    values: vec![9],
                },
            ])
            .await
            .expect("the live service still lands");
        assert_eq!(read(&store, kept, 1, Slots::Requests).await[0], 3);
        // The dropped write must leave no row at all: assert the absence rather
        // than reading a defaulted array and calling it empty.
        assert!(
            store
                .read_day_slots_of(&[gone], 1, &[Slots::Requests])
                .await
                .expect("the read itself succeeds")
                .is_empty(),
            "a dropped write must not leave a row behind"
        );
    }

    /// An impossible open time is refused, and nothing is written.
    #[tokio::test]
    async fn open_ms_out_of_range_is_rejected() {
        let (store, service) = fixture().await;
        let error = store
            .write_day_slots(&[SlotWrite {
                service_id: service,
                day: 1,
                slots: Slots::OpenMs,
                first_slot: 0,
                values: vec![60_001],
            }])
            .await;
        assert!(
            matches!(error, Err(StoreError::InvalidUsage(_))),
            "{error:?}"
        );
        assert!(store.live_days(&[service]).await.unwrap().is_empty());
    }

    /// A run that would spill past the end of the day is refused.
    #[tokio::test]
    async fn a_run_off_the_end_of_the_day_is_rejected() {
        let (store, service) = fixture().await;
        let error = store
            .write_day_slots(&[SlotWrite {
                service_id: service,
                day: 1,
                slots: Slots::BytesIn,
                first_slot: 1_439,
                values: vec![1, 2],
            }])
            .await;
        assert!(
            matches!(error, Err(StoreError::InvalidUsage(_))),
            "{error:?}"
        );
    }

    /// The cell's byte layout is little-endian, uncompressed, exactly 11,520
    /// bytes — the contract the in-place writes rely on.
    #[tokio::test]
    async fn the_stored_cell_is_11520_le_bytes() {
        let (store, service) = fixture().await;
        write(
            &store,
            service,
            1,
            Slots::BytesIn,
            2,
            &[0x0102_0304_0506_0708],
        )
        .await;
        let backend = store.db().get_database_backend();
        let cell: Vec<u8> = store
            .db()
            .query_one_raw(Statement::from_string(
                backend,
                "SELECT bytes_in_slots FROM usage_live WHERE day = 1".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index(0)
            .unwrap();
        assert_eq!(cell.len(), SLOT_BYTES);
        assert_eq!(&cell[16..24], &0x0102_0304_0506_0708_i64.to_le_bytes());
        assert!(cell[..16].iter().all(|byte| *byte == 0));
    }
}
