//! `usage_live`: the current day's metered slots, written in place.
//!
//! One row per `(service_id, day)`. Each of the six metrics is a fixed
//! 11,520-byte cell holding 1,440 little-endian `i64` slots, one per minute of
//! that day (`slot n` is minute `day * 1440 + n`), uncompressed: the flush
//! rewrites a handful of consecutive slots through the SQLite C blob API, so
//! the cell must have a stable size and a stable address. The cells are
//! pre-allocated with `zeroblob`, never grown.
//!
//! There are deliberately no derived columns: the reader holds the array and
//! sums it or `rposition`s it. A day is finished by folding its six arrays into
//! the wide `usage_daily` row and deleting the `usage_live` row in the same
//! transaction, so a finished day is either all still live or already
//! compressed — never half of each.
//!
//! The table is a plain rowid table on purpose: the incremental-blob API
//! addresses a row by `rowid`, which a `WITHOUT ROWID` table does not have.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "usage_live")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub service_id: i32,
    /// Unix days: the day's first minute divided by 1440.
    #[sea_orm(primary_key, auto_increment = false)]
    pub day: i64,
    /// Visitor leg: browser -> relay body bytes, 1440 little-endian `i64`.
    pub bytes_in_slots: Vec<u8>,
    /// Visitor leg: relay -> browser body bytes.
    pub bytes_out_slots: Vec<u8>,
    /// Tunnel leg: client -> relay compressed bytes.
    pub tunnel_in_slots: Vec<u8>,
    /// Tunnel leg: relay -> client compressed bytes.
    pub tunnel_out_slots: Vec<u8>,
    pub requests_slots: Vec<u8>,
    /// Milliseconds the service was registered in each minute, `0..=60_000`.
    pub open_ms_slots: Vec<u8>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::service::Entity",
        from = "Column::ServiceId",
        to = "super::service::Column::Id",
        on_delete = "Cascade",
        on_update = "Cascade"
    )]
    Service,
}

impl Related<super::service::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Service.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
