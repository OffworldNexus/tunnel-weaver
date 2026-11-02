//! `external_identity` table: an account's link to an identity held elsewhere
//! (WVR-169).
//!
//! The unique key is the provider's own `(provider, tenant_id, subject)`. It is
//! never an address: `oid`+`tid` are the only values Entra promises will not
//! change or be reused, so they are what a returning sign-in is recognised by.
//! The stored `email` is for display and for the one-time decision to link to an
//! existing account with a verified address — the address itself is keyed in
//! `email_identity`, not here.
//!
//! `refresh_token` is the sealed grant (`nonce ‖ ciphertext` in hex, empty when
//! none) that the housekeeping refresh rotates. Only `account::sso::Microsoft` can
//! open it; the store treats it as opaque, exactly as it treats a TOTP secret.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "external_identity")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub account_id: i32,
    /// The provider this identity belongs to, e.g. `microsoft`.
    pub provider: String,
    /// The provider's tenant identifier (`tid`), part of the durable key.
    pub tenant_id: String,
    /// The provider's subject identifier (`oid`), part of the durable key.
    pub subject: String,
    /// The provider's display name for the person; empty when it gave none.
    pub display_name: String,
    /// The address the provider reported, for display and the linking decision.
    pub email: String,
    /// When the provider asserted the address was verified, if it did.
    pub email_verified_at: Option<i64>,
    /// When the identity was first linked to the account.
    pub linked_at: i64,
    /// The sealed refresh grant, `nonce ‖ ciphertext` in hex; empty means none.
    pub refresh_token: String,
    /// When the sealed grant was last written; `None` until the first one.
    pub refresh_token_updated_at: Option<i64>,
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
