//! Password-reset tokens (WVR-41).
//!
//! A dedicated table rather than a re-use of `verification_token`: that table's
//! rows are keyed by a *pending registration* (the pre-account signup state), so
//! its `pending_registration_id` is NOT NULL and carries a foreign key. A reset
//! token belongs to an already-activated *account* instead, so sharing the table
//! would mean reopening the signup table (relaxing the column, rebuilding the
//! SQLite table) for a concept it was never shaped for. Keeping reset tokens
//! separate leaves the signup path untouched and gives the reset flow its own
//! lifecycle.
//!
//! Only the digest is stored; the raw secret lives solely in the emailed link.
//! Consumption and revocation are timestamps so the row survives as provenance
//! rather than being deleted, mirroring `verification_token`.

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Account {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum PasswordResetToken {
    Table,
    Id,
    AccountId,
    TokenDigest,
    IssuedAt,
    ExpiresAt,
    ConsumedAt,
    RevokedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(PasswordResetToken::Table)
                    .col(pk_auto(PasswordResetToken::Id))
                    .col(integer(PasswordResetToken::AccountId))
                    .col(text(PasswordResetToken::TokenDigest).unique_key())
                    .col(big_integer(PasswordResetToken::IssuedAt))
                    .col(big_integer(PasswordResetToken::ExpiresAt))
                    .col(big_integer_null(PasswordResetToken::ConsumedAt))
                    .col(big_integer_null(PasswordResetToken::RevokedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_password_reset_token_account_id")
                            .from(PasswordResetToken::Table, PasswordResetToken::AccountId)
                            .to(Account::Table, Account::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_password_reset_token_account_id")
                    .table(PasswordResetToken::Table)
                    .col(PasswordResetToken::AccountId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_password_reset_token_expires_at")
                    .table(PasswordResetToken::Table)
                    .col(PasswordResetToken::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(PasswordResetToken::Table).to_owned())
            .await?;
        Ok(())
    }
}
