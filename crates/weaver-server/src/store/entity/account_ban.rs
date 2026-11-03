//! `account_ban` table: one row per ban an operator placed on an account.
//!
//! `unbanned_at` is the instant the ban was lifted, `None` while it holds — so
//! the open ban is the row with no `unbanned_at`, and lifting a ban closes the
//! row instead of deleting it. `reason` is the operator's free text, never
//! shown to the person (they see one fixed suspension sentence).

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "account_ban")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub account_id: i32,
    /// Unix seconds the ban was applied.
    pub banned_at: i64,
    /// The operator's reason; never empty, never sent to the account holder.
    pub reason: String,
    /// Unix seconds the ban was lifted; `None` while the ban holds.
    pub unbanned_at: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::account::Entity",
        from = "Column::AccountId",
        to = "super::account::Column::Id"
    )]
    Account,
}

impl Related<super::account::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Account.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
