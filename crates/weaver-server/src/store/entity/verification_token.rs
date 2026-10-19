//! `verification_token` table: single-use proof-of-ownership tokens.
//!
//! Only the digest is stored; the raw secret lives solely in the emailed link.
//! Consumption and revocation are timestamps so the row (and the verification
//! history that references it) survives rather than being deleted.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "verification_token")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub pending_registration_id: i32,
    pub email_lookup_key: String,
    #[sea_orm(unique)]
    pub token_digest: String,
    pub purpose: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub consumed_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::pending_registration::Entity",
        from = "Column::PendingRegistrationId",
        to = "super::pending_registration::Column::Id",
        on_delete = "Cascade"
    )]
    PendingRegistration,
    #[sea_orm(has_many = "super::email_verification::Entity")]
    EmailVerifications,
}

impl Related<super::pending_registration::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PendingRegistration.def()
    }
}

impl Related<super::email_verification::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::EmailVerifications.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
