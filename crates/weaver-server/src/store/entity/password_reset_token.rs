//! `password_reset_token` table: single-use, expiring password-reset tokens
//! (WVR-41).
//!
//! Only the digest is stored; the raw secret lives solely in the emailed link
//! (carried in the URL fragment so it never reaches HTTP access logs).
//! Consumption and revocation are timestamps so the row survives as provenance
//! rather than being deleted.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "password_reset_token")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub account_id: i32,
    #[sea_orm(unique)]
    pub token_digest: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub consumed_at: Option<i64>,
    pub revoked_at: Option<i64>,
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
}

impl Related<super::account::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Account.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
