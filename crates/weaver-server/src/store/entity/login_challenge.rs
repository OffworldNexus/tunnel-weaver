//! `login_challenge` table: the pending emailed code for a sign-in or an
//! address verification (WVR-167, WVR-169).
//!
//! One row per *flow* — a browser session for a sign-in, a pending registration
//! for an address verification — replaced whenever a code is issued or re-sent,
//! so only the newest code is ever accepted. The two flow columns are nullable
//! and mutually exclusive, and each carries a unique index, so a row keyed one
//! way never conflicts with a row keyed the other. Only the code's digest is
//! stored, never the code itself; the row carries its purpose, TTL, attempt
//! count and cap, and the last send time (for the re-send cooldown). Consuming
//! it is a timestamp, so an exhausted row survives as provenance.
//!
//! Cascading from both `browser_session` and `pending_registration` is
//! deliberate: a challenge is meaningless without the flow it belongs to, and
//! that flow's row disappears on logout, expiry, or an abandoned signup.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "login_challenge")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// `sign_in` (the second factor of a sign-in) or `verify_address` (settle
    /// an account's address). It selects the email and whether accepting the
    /// code marks the address verified.
    pub purpose: String,
    /// The browser session a sign-in challenge belongs to; `NULL` for an
    /// address-verification challenge. Exactly one of this and
    /// `pending_registration_id` is set.
    pub session_id: Option<i32>,
    /// The pending registration an address-verification challenge belongs to;
    /// `NULL` for a sign-in challenge.
    pub pending_registration_id: Option<i32>,
    /// SHA-256 digest (base64) of the issued code; the raw code is never stored.
    pub code_hash: String,
    pub created_at: i64,
    /// When the current code stops being accepted.
    pub expires_at: i64,
    /// Wrong entries so far against the current code.
    pub attempts: i32,
    /// How many wrong entries are tolerated before a fresh code is required.
    pub max_attempts: i32,
    /// When a code was last sent, for the re-send cooldown.
    pub last_sent_at: i64,
    /// When the challenge was satisfied, if it was.
    pub consumed_at: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::browser_session::Entity",
        from = "Column::SessionId",
        to = "super::browser_session::Column::Id",
        on_delete = "Cascade"
    )]
    Session,
    #[sea_orm(
        belongs_to = "super::pending_registration::Entity",
        from = "Column::PendingRegistrationId",
        to = "super::pending_registration::Column::Id",
        on_delete = "Cascade"
    )]
    PendingRegistration,
}

impl Related<super::browser_session::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Session.def()
    }
}

impl Related<super::pending_registration::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PendingRegistration.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
