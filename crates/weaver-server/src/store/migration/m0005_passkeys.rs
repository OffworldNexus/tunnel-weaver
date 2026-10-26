//! `passkey_credential` (WVR-163).
//!
//! One row per registered passkey. The row is what makes a passkey a *way in*,
//! so it is the security-critical table of the feature:
//!
//! * `credential_id` is unique across the whole table, not merely per account:
//!   it is what an assertion is looked up by on the anonymous sign-in path, so
//!   a credential that somehow appeared twice would be a way to make one
//!   account's key sign another account in. The store rejects a duplicate.
//! * `credential` is the serialised `webauthn-rs` `Passkey` — the public key and
//!   the metadata the ceremony needs to verify a later assertion. It is opaque
//!   to the store.
//! * `user_unique_id` is the account's stable WebAuthn user handle, stored per
//!   credential because a *discoverable* assertion returns it and nothing else:
//!   it is how discovery cross-checks that the credential it resolved really is
//!   this account's. It is the same value on every credential of an account
//!   (derived, never random).
//! * `transports` is the hint the browser reported about the authenticator (a
//!   key on a port versus this very device), comma-joined. It is not a security
//!   property; it is what lets the console label an unnamed passkey.
//! * `name` is never null: an empty string means "the person did not name it",
//!   and the console derives a label from `transports` and the added date.
//! * `last_used_at` is genuinely absent until the credential is first used, so
//!   it is nullable for the same reason `browser_session.invalidated_at` is.
//!
//! `account_id` cascades: this repo hard-deletes accounts and guarantees that
//! nothing of them — least of all a way back in — survives.

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
enum PasskeyCredential {
    Table,
    Id,
    AccountId,
    CredentialId,
    Credential,
    UserUniqueId,
    Transports,
    Name,
    CreatedAt,
    LastUsedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(PasskeyCredential::Table)
                    .col(pk_auto(PasskeyCredential::Id))
                    .col(integer(PasskeyCredential::AccountId))
                    .col(text(PasskeyCredential::CredentialId).unique_key())
                    .col(text(PasskeyCredential::Credential))
                    .col(text(PasskeyCredential::UserUniqueId))
                    .col(text(PasskeyCredential::Transports).default(""))
                    .col(text(PasskeyCredential::Name).default(""))
                    .col(big_integer(PasskeyCredential::CreatedAt))
                    .col(big_integer_null(PasskeyCredential::LastUsedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_passkey_credential_account_id")
                            .from(PasskeyCredential::Table, PasskeyCredential::AccountId)
                            .to(Account::Table, Account::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Listing the account's passkeys, and counting them for the situation
        // the level derivation and the `me` stream both read.
        manager
            .create_index(
                Index::create()
                    .name("idx_passkey_credential_account_id")
                    .table(PasskeyCredential::Table)
                    .col(PasskeyCredential::AccountId)
                    .col(PasskeyCredential::CreatedAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(PasskeyCredential::Table).to_owned())
            .await?;
        Ok(())
    }
}
