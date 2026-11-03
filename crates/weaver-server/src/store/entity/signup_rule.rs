//! `signup_rule` table: one numbered rule of the signup policy (WVR-98).
//!
//! Rules are evaluated in ascending `number` order and the first match wins, so
//! `number` is the primary key and doubles as the evaluation position the
//! operator edits and deletes by. `kind` is `email` (the whole address) or
//! `domain` (the part after `@`, matched exactly — no subdomains); `value` is
//! already normalised to the store's lookup-key form.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "signup_rule")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub number: i32,
    /// `allow` or `deny`.
    pub decision: String,
    /// `email` or `domain`.
    pub kind: String,
    /// The normalised address or domain this rule matches.
    pub value: String,
}

/// No relations: a rule references nothing and outlives every account.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
