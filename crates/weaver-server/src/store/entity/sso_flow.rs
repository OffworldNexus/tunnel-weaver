//! `sso_flow` table: the pending half of an external-identity sign-in (WVR-169).
//!
//! Nothing ties the `begin` redirect to the `callback` request except a
//! single-use `handle` that travels as OAuth's `state`. That handle is therefore
//! both the anti-CSRF binding and the home of the PKCE verifier and the nonce
//! across the two stateless requests — there is no session yet, so there is
//! nothing else to carry them.
//!
//! It is deliberately a table and not memory: a restart between begin and callback
//! must fail the flow cleanly rather than let an unknown `state` look legitimate.
//! `kind` separates a `signin` (whose callback mints a session) from a `stepup`
//! (whose callback records a presence proof on an existing one); `account_id` and
//! `session_id` are informational for the latter. There is no foreign key on
//! either: a sign-in flow precedes its session, and its account may not exist yet.
//!
//! Consuming the row is a timestamp, so a redeemed row survives as provenance
//! until the account sweep drops it once it is old.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sso_flow")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// The single-use `state` value; the row is found by it and never by id.
    #[sea_orm(unique)]
    pub handle: String,
    /// `signin` or `stepup`.
    pub kind: String,
    /// The provider the flow is against, e.g. `microsoft`.
    pub provider: String,
    /// The OIDC nonce the ID token must echo.
    pub nonce: String,
    /// The PKCE `code_verifier` the code exchange must present.
    pub code_verifier: String,
    /// A same-origin path to land on after a step-up; empty means `/app`.
    pub return_path: String,
    /// The account a step-up belongs to; `None` for a sign-in.
    pub account_id: Option<i32>,
    /// The session a step-up strengthens; `None` for a sign-in.
    pub session_id: Option<i32>,
    pub created_at: i64,
    /// When the flow stops being acceptable.
    pub expires_at: i64,
    /// When the flow was redeemed, if it was.
    pub consumed_at: Option<i64>,
}

/// No relations: a flow references an account and a session that may not exist
/// yet (and that it must not outlive into a hard delete), so it carries their ids
/// as plain columns instead of foreign keys.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
