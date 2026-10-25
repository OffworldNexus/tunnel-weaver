//! `login_challenge` table: the pending second-factor code for a sign-in
//! (WVR-167).
//!
//! One row per browser session (unique `session_id`), replaced whenever a code
//! is issued or re-sent — so only the newest code is ever accepted. Only the
//! code's digest is stored, never the code itself; the row carries its TTL,
//! attempt count and cap, and the last send time (for the re-send cooldown).
//! Consuming it is a timestamp, so an exhausted row survives as provenance.
//!
//! Cascading from `browser_session` is deliberate: a challenge is meaningless
//! without its session, and the session row disappears on logout or expiry.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "login_challenge")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// The browser session this challenge belongs to; one challenge at a time.
    #[sea_orm(unique)]
    pub session_id: i32,
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
}

impl Related<super::browser_session::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Session.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
