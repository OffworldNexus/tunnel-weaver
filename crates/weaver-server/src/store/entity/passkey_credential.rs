//! `passkey_credential` table: the passkeys registered to an account (WVR-163).
//!
//! A passkey is both a way in and a second factor in one credential, so unlike
//! `password_credential` this table is not append-only: removing a passkey is a
//! real, immediate revocation (there is no history to keep, and keeping a
//! removed credential around would keep a way in alive). `credential` holds the
//! serialised `webauthn-rs` `Passkey` — the public key and the metadata the
//! assertion ceremony verifies against.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "passkey_credential")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub account_id: i32,
    /// The credential id, as the wire spells it (base64url). Unique across the
    /// table: it is what an anonymous assertion is resolved by.
    pub credential_id: String,
    /// The serialised `webauthn-rs` `Passkey` (public key, counter and the
    /// properties the authenticator reported). Opaque here on purpose: the
    /// library owns its shape, and it is the counter inside it — not a column —
    /// that the next assertion's clone detection compares against.
    pub credential: String,
    /// The account's WebAuthn user handle, which a discoverable assertion
    /// returns and discovery cross-checks against.
    pub user_unique_id: String,
    /// The transports the authenticator announced, comma-joined (may be empty).
    pub transports: String,
    /// What the person called it; empty means they did not name it.
    pub name: String,
    pub created_at: i64,
    /// When the passkey was last used to sign in. Absent until then — a real
    /// absence, like `browser_session.invalidated_at`.
    pub last_used_at: Option<i64>,
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
