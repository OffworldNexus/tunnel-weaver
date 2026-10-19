//! `device` table: the machine's one device key, in a single row.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "device")]
pub struct Model {
    /// Always [`ROW`].
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: i32,
    /// The fingerprint of the current device key, remembered so the next
    /// command resumes it instead of creating another.
    pub key_id: String,
}

/// The id of the only row.
pub const ROW: i32 = 1;

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
