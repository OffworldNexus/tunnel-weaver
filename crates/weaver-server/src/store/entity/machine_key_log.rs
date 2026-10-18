//! `machine_key_log` table: the audit trail of which key a machine held, when.
//!
//! One row per key a machine has held: opened when the key is attached
//! (`retired_at` null), closed when it is replaced or the machine is revoked.
//! It deliberately has no foreign keys, so it outlives the machine and person it
//! describes. It is write-only from the relay's point of view: nothing that
//! authenticates a key ever reads it — `machine.key_id` is the only source of
//! truth for who a key is.

use sea_orm::entity::prelude::*;

/// `retired_reason` when a machine moved onto a new key.
pub const REASON_REPLACED: &str = "replaced";
/// `retired_reason` when the machine itself was revoked.
pub const REASON_REVOKED: &str = "revoked";

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "machine_key_log")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub key_id: String,
    pub machine_id: i32,
    pub person_id: i32,
    pub added_at: i64,
    pub retired_at: Option<i64>,
    /// [`REASON_REPLACED`] or [`REASON_REVOKED`]; null while the key is current.
    pub retired_reason: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
