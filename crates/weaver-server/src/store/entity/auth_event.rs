//! `auth_event` table: the authentication trail (WVR-167).
//!
//! Rows are simultaneously the audit trail and the raw material the session's
//! [`AuthLevel`](crate::account::auth::AuthLevel) is derived from: the latest
//! occurrence of each proof kind on a session, while it is still alive, is what
//! the level is computed from. Nothing level-related is stored on the session.
//!
//! There is deliberately **no foreign key on `session_id`**: the nightly session
//! sweep deletes expired sessions, and the trail must outlive them (the same
//! choice `machine_key_log` makes). `account_id` *does* cascade, because this
//! repo hard-deletes accounts and the deletion guarantee is that nothing of the
//! account survives. Both columns are nullable for the one real absence: a
//! failed password check that matched no account at all.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "auth_event")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// The account, when the event concerns one (`None`: a failed login that
    /// matched no address).
    pub account_id: Option<i32>,
    /// The `browser_session` row the event belongs to, when one existed.
    pub session_id: Option<i32>,
    /// One of the `auth_event` kinds (see `account::auth::EventKind`).
    pub kind: String,
    pub occurred_at: i64,
    /// Peer address, or an empty string when unknown.
    pub ip_address: String,
    /// Truncated `User-Agent`, or an empty string when unknown.
    pub user_agent: String,
    /// The identifier a failed login was attempted against; empty otherwise.
    pub attempted: String,
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
