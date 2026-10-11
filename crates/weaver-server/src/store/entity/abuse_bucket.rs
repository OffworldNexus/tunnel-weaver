//! `abuse_bucket` table: persisted GCRA rate-limit state.
//!
//! One row per `(scope, key_kind, key_id)`. `scope` is the policy id, so two
//! policies never share a bucket even when they key on the same value;
//! `key_kind`/`key_id` identify the caller's [`weaver_abuse::Key`]. `tat_ms` is
//! the GCRA theoretical-arrival time in Unix milliseconds (the whole limiter
//! state), and `updated_at_ms` records the last charge so an idle sweep can
//! bound the table. The column set is deliberately tiny: GCRA needs one
//! timestamp, not a token count.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "abuse_bucket")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub scope: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub key_kind: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub key_id: i64,
    pub tat_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
