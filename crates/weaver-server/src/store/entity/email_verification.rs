//! `email_verification` table: append-only ownership history (WVR-36).
//!
//! The initial verification is a real row referencing the token that proved it,
//! not a boolean on the account.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "email_verification")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub account_id: i32,
    pub email_identity_id: i32,
    pub token_id: i32,
    pub verified_at: i64,
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
    #[sea_orm(
        belongs_to = "super::email_identity::Entity",
        from = "Column::EmailIdentityId",
        to = "super::email_identity::Column::Id",
        on_delete = "Cascade"
    )]
    EmailIdentity,
    #[sea_orm(
        belongs_to = "super::verification_token::Entity",
        from = "Column::TokenId",
        to = "super::verification_token::Column::Id",
        on_delete = "Restrict"
    )]
    VerificationToken,
}

impl Related<super::account::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Account.def()
    }
}

impl Related<super::email_identity::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::EmailIdentity.def()
    }
}

impl Related<super::verification_token::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VerificationToken.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
