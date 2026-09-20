//! Singleton `config` table holding the server configuration as one JSON blob.
//!
//! A single row (`id = 1`, enforced by a check constraint in the migration)
//! keeps configuration atomic: it is always written and read as a whole.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "config")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: i32,
    pub config_json: String,
    pub updated_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// The only valid primary key value for the singleton row.
pub const SINGLETON_ID: i32 = 1;
