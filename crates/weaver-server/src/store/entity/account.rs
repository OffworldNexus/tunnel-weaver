//! `account` table: stable email-account identities.
//!
//! Distinct from `person`, which is the ASCII tunnel-namespace owner. An account
//! carries a non-unique, Unicode display name (multiple accounts may share one,
//! accents preserved) and is resolved through its `email_identity`, never by
//! name.
//!
//! `last_login_at` and `inactivity_warning_at` exist for the inactivity sweep
//! (WVR-160): the first is the clock the sweep reads (falling back to
//! `activated_at` for an account that never signed in), the second records that
//! the "will be deleted" warning was sent for the current inactive cycle so it
//! is not repeated every tick.

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
    /// Unix seconds of the last successful sign-in; `None` until the first one.
    pub last_login_at: Option<i64>,
    /// Unix seconds the inactivity warning was last sent; `None` if never.
    pub inactivity_warning_at: Option<i64>,
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
