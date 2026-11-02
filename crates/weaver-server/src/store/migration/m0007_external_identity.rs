//! `external_identity`, `sso_flow`, and `auth_event.detail` (WVR-169).
//!
//! The first sign-in through an external identity provider needs three things the
//! schema did not keep:
//!
//! * `external_identity` — the durable link between an account and the identity it
//!   holds elsewhere. The unique key is the provider's own `(provider, tenant_id,
//!   subject)`, never an address: `oid`+`tid` (or their equivalent) are the only
//!   values Entra promises will not change or be reused, so they are what a
//!   returning sign-in is recognised by. The provider's email is stored for
//!   display and for the one-time "link to an existing account with this verified
//!   address" decision, not as a key. `refresh_token` is the sealed grant the
//!   housekeeping refresh rotates (`nonce ‖ ciphertext` in hex, empty means none);
//!   the store never sees the plaintext, exactly as `totp_credential.secret` is
//!   kept. `account_id` cascades: this repo hard-deletes accounts and guarantees
//!   nothing of them — least of all a token that can act as them — survives.
//! * `sso_flow` — the pending half of an authorization-code flow. Nothing ties the
//!   `begin` redirect to the `callback` request except a single-use `handle` that
//!   travels as OAuth's `state`, so the row is the anti-CSRF binding *and* the
//!   PKCE verifier's home across the two stateless requests. It is deliberately a
//!   table and not memory: a restart between begin and callback must fail the flow
//!   cleanly rather than make an unknown `state` look legitimate. `kind` separates
//!   a `signin` (which mints a session) from a `stepup` (which does not), and
//!   `account_id`/`session_id` are informational for the latter. There is no
//!   foreign key on either: a sign-in flow precedes its session, and the account
//!   may not exist yet. An unredeemed row is dropped by the account sweep once it
//!   is old.
//! * `auth_event.detail` — a bounded string for whatever an event needs beyond its
//!   kind and its `attempted` identifier: why an external sign-in was refused.
//!   It is empty for every other event.

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Only the columns referenced as foreign keys of the existing tables.
#[derive(DeriveIden)]
enum Account {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum AuthEvent {
    Table,
    Detail,
}

#[derive(DeriveIden)]
enum ExternalIdentity {
    Table,
    Id,
    AccountId,
    Provider,
    TenantId,
    Subject,
    DisplayName,
    Email,
    EmailVerifiedAt,
    LinkedAt,
    RefreshToken,
    RefreshTokenUpdatedAt,
}

#[derive(DeriveIden)]
enum SsoFlow {
    Table,
    Id,
    Handle,
    Kind,
    Provider,
    Nonce,
    CodeVerifier,
    ReturnPath,
    AccountId,
    SessionId,
    CreatedAt,
    ExpiresAt,
    ConsumedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ExternalIdentity::Table)
                    .col(pk_auto(ExternalIdentity::Id))
                    .col(integer(ExternalIdentity::AccountId))
                    .col(text(ExternalIdentity::Provider))
                    .col(text(ExternalIdentity::TenantId))
                    .col(text(ExternalIdentity::Subject))
                    .col(text(ExternalIdentity::DisplayName).default(""))
                    .col(text(ExternalIdentity::Email).default(""))
                    .col(big_integer_null(ExternalIdentity::EmailVerifiedAt))
                    .col(big_integer(ExternalIdentity::LinkedAt))
                    .col(text(ExternalIdentity::RefreshToken).default(""))
                    .col(big_integer_null(ExternalIdentity::RefreshTokenUpdatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_external_identity_account_id")
                            .from(ExternalIdentity::Table, ExternalIdentity::AccountId)
                            .to(Account::Table, Account::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // The provider's own key: what a returning sign-in is recognised by, and
        // the database-level guarantee that an identity belongs to one account
        // even when two callbacks race.
        manager
            .create_index(
                Index::create()
                    .name("ux_external_identity_key")
                    .table(ExternalIdentity::Table)
                    .col(ExternalIdentity::Provider)
                    .col(ExternalIdentity::TenantId)
                    .col(ExternalIdentity::Subject)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // Listing an account's linked identities.
        manager
            .create_index(
                Index::create()
                    .name("idx_external_identity_account_id")
                    .table(ExternalIdentity::Table)
                    .col(ExternalIdentity::AccountId)
                    .col(ExternalIdentity::LinkedAt)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(SsoFlow::Table)
                    .col(pk_auto(SsoFlow::Id))
                    .col(text(SsoFlow::Handle).unique_key())
                    .col(text(SsoFlow::Kind))
                    .col(text(SsoFlow::Provider))
                    .col(text(SsoFlow::Nonce))
                    .col(text(SsoFlow::CodeVerifier))
                    .col(text(SsoFlow::ReturnPath).default(""))
                    .col(integer_null(SsoFlow::AccountId))
                    .col(integer_null(SsoFlow::SessionId))
                    .col(big_integer(SsoFlow::CreatedAt))
                    .col(big_integer(SsoFlow::ExpiresAt))
                    .col(big_integer_null(SsoFlow::ConsumedAt))
                    .to_owned(),
            )
            .await?;

        // The sweep's query: rows whose TTL has passed.
        manager
            .create_index(
                Index::create()
                    .name("idx_sso_flow_expires_at")
                    .table(SsoFlow::Table)
                    .col(SsoFlow::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        // SQLite rejects more than one ALTER option per statement, so the one
        // column goes alone.
        manager
            .alter_table(
                Table::alter()
                    .table(AuthEvent::Table)
                    .add_column(text(AuthEvent::Detail).default(""))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(AuthEvent::Table)
                    .drop_column(AuthEvent::Detail)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(SsoFlow::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(ExternalIdentity::Table).to_owned())
            .await?;
        Ok(())
    }
}
