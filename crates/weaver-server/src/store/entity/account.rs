//! `account` table: stable email-account identities.
//!
//! Distinct from `person`, which is the ASCII tunnel-namespace owner. An account
//! carries a non-unique, Unicode display name (multiple accounts may share one,
//! accents preserved) and is resolved through its `email_identity`, never by
//! name.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "account")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub name: String,
    pub state: String,
    pub created_at: i64,
    pub activated_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::email_identity::Entity")]
    EmailIdentities,
    #[sea_orm(has_many = "super::password_credential::Entity")]
    PasswordCredentials,
    #[sea_orm(has_many = "super::browser_session::Entity")]
    BrowserSessions,
}

impl Related<super::email_identity::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::EmailIdentities.def()
    }
}

impl Related<super::password_credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PasswordCredentials.def()
    }
}

impl Related<super::browser_session::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::BrowserSessions.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
