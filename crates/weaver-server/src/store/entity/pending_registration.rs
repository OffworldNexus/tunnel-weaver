//! `pending_registration` table: in-flight signups.
//!
//! A pending registration owns the proposed name/email until ownership is
//! proven. It is never an account and cannot take over an existing address
//! association; `completed_at` marks the run that became (or matched) an
//! account.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "pending_registration")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub flow_id: String,
    pub name: String,
    pub email: String,
    pub lookup_key: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub completed_at: Option<i64>,
    /// The consumed email-verification token that proved ownership of this
    /// registration's address, recorded when ownership is confirmed so the
    /// later completion step can link the verification history to it.
    pub proved_by_token_id: Option<i32>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::verification_token::Entity")]
    VerificationTokens,
}

impl Related<super::verification_token::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VerificationTokens.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
