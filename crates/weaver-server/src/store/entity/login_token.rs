//! `login_token` table: single-use sign-in links for the inactivity warning.
//!
//! Mirrors `password_reset_token`: only the SHA-256 digest of the raw token is
//! stored, so a leaked database cannot be replayed, and `consumed_at` /
//! `revoked_at` retire a link without deleting its row. The warning email
//! contains one of these; opening it and posting the raw token starts a browser
//! session, which is what resets the account's inactivity clock (WVR-160).

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "login_token")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub account_id: i32,
    /// SHA-256 digest (hex) of the raw token; the raw value is never stored.
    #[sea_orm(unique)]
    pub token_digest: String,
    pub issued_at: i64,
    /// When the emailed link stops working.
    pub expires_at: i64,
    /// Set the once-only instant the link was spent.
    pub consumed_at: Option<i64>,
    /// Set when a newer link supersedes this one.
    pub revoked_at: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::account::Entity",
        from = "Column::AccountId",
        to = "super::account::Column::Id",
        on_delete = "Cascade",
        on_update = "Cascade"
    )]
    Account,
}

impl Related<super::account::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Account.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
