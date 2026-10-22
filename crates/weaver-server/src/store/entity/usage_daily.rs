//! `usage_daily`: the wide day-grain rollup the console reads.
//!
//! One row per `(service_id, day)`, not per metric: the day's six totals are
//! plain columns, and each metric also carries the day's 24 hourly values and
//! its 1440 per-minute values as zstd frames over little-endian `i64` arrays.
//! The wide shape keeps storage dense — a service's whole day is one row — so a
//! month of history is a few hundred rows, and a whole-day read never touches a
//! blob. Only a window finer than a day, or one covering a day partly, slices
//! the arrays.
//!
//! The flush owns this table: it folds a finished day's live slot arrays into
//! one row per service, then deletes those live rows, in a single transaction
//! per day. Day numbers share the slot table's epoch (`minute / 1440`), as do
//! the arrays' indices (`open_ms_minutes[0]` is that day's minute 0).

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "usage_daily")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub service_id: i32,
    /// Unix days: the day's first minute divided by 1440.
    #[sea_orm(primary_key, auto_increment = false)]
    pub day: i64,
    /// Visitor leg: browser -> relay body bytes, summed over the day.
    pub bytes_in: i64,
    /// The day's 24 hourly `bytes_in` values, zstd over 24 little-endian `i64`.
    pub bytes_in_hours: Vec<u8>,
    /// The day's 1440 per-minute `bytes_in` values, zstd over `i64`.
    pub bytes_in_minutes: Vec<u8>,
    /// Visitor leg: relay -> browser body bytes, summed over the day.
    pub bytes_out: i64,
    pub bytes_out_hours: Vec<u8>,
    pub bytes_out_minutes: Vec<u8>,
    /// Tunnel leg: client -> relay compressed bytes, summed over the day.
    pub tunnel_in: i64,
    pub tunnel_in_hours: Vec<u8>,
    pub tunnel_in_minutes: Vec<u8>,
    /// Tunnel leg: relay -> client compressed bytes, summed over the day.
    pub tunnel_out: i64,
    pub tunnel_out_hours: Vec<u8>,
    pub tunnel_out_minutes: Vec<u8>,
    pub requests: i64,
    pub requests_hours: Vec<u8>,
    pub requests_minutes: Vec<u8>,
    /// Milliseconds the service was registered during the day.
    pub open_ms: i64,
    pub open_ms_hours: Vec<u8>,
    /// The day's per-minute open time; the last non-zero index is last-seen.
    pub open_ms_minutes: Vec<u8>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::service::Entity",
        from = "Column::ServiceId",
        to = "super::service::Column::Id",
        on_delete = "Cascade"
    )]
    Service,
}

impl Related<super::service::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Service.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
