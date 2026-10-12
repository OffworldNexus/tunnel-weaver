//! `email_identity` table: the account/address association (WVR-36).
//!
//! The unique `lookup_key` is the database-level guarantee that an address
//! belongs to exactly one account, even when activations race. `email` keeps the
//! address as entered for display; no provider-specific dot/plus rewriting is
//! applied.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "email_identity")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub account_id: i32,
    pub email: String,
    #[sea_orm(unique)]
    pub lookup_key: String,
    pub created_at: i64,
    pub verified_at: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::account::Entity",
        from = "Column::AccountId",
        to = "super::account::Column::Id",
        on_delete = "Cascade"
    )]
    Account,
    #[sea_orm(has_many = "super::email_verification::Entity")]
    EmailVerifications,
}

impl Related<super::account::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Account.def()
    }
}

impl Related<super::email_verification::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::EmailVerifications.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
