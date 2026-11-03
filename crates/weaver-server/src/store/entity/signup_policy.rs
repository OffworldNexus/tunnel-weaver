//! `signup_policy` table: the relay-wide default decision on account creation
//! (WVR-98).
//!
//! A singleton (`id = 1`). **No row** means the operator never configured a
//! policy, which is today's behaviour: allow, with no rules. Storing the default
//! explicitly is what makes "deny by default with no rules" representable.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "signup_policy")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: i32,
    /// `allow` or `deny`, applied when no rule matches.
    pub default_decision: String,
}

/// No relations: the policy stands alone.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// The only valid primary key value for the singleton row.
pub const SINGLETON_ID: i32 = 1;
