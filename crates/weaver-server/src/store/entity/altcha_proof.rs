//! `altcha_proof` table: single-use proof markers (WVR-136).
//!
//! One row per consumed proof, unique on `(public_key, nonce)`. Consumption is
//! an `INSERT … ON CONFLICT DO NOTHING`: the first insert wins, a replay hits
//! the conflict. Rows live until `expires_at_ms` and are then swept.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "altcha_proof")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub public_key: String,
    pub nonce: String,
    pub consumed_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
