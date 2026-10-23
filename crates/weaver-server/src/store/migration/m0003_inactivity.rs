//! `account.last_login_at` / `account.inactivity_warning_at`, and the
//! `login_token` table that backs the inactivity warning's sign-in link
//! (WVR-160).
//!
//! An account that nobody uses for a year is deleted automatically. Deciding
//! "nobody used it" needs two facts the schema did not keep:
//!
//! * `last_login_at` — the latest successful sign-in, in Unix seconds. Written
//!   on every login (and on the warning link's sign-in). It is nullable because
//!   an account that was activated but never signed in has no sign-in yet; the
//!   sweep falls back to `activated_at` for those so a fresh account is never
//!   mistaken for an abandoned one.
//! * `inactivity_warning_at` — when the "your account will be deleted" email was
//!   last sent. Recorded so the warning is sent once per inactive cycle instead
//!   of on every sweep tick; a later sign-in or metered minute moves the clock
//!   past it, so the next cycle can warn again.
//!
//! `login_token` mirrors `password_reset_token`: a single-use, digest-only
//! token for the warning link. Opening it signs the owner in, which is what
//! resets the inactivity clock. The raw token never touches storage.

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Only the columns added to the m0001-owned `account` table.
#[derive(DeriveIden)]
enum Account {
    Table,
    Id,
    LastLoginAt,
    InactivityWarningAt,
}

#[derive(DeriveIden)]
enum LoginToken {
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
        // Both columns are nullable: absent means "never", not "zero". SQLite
        // rejects more than one ALTER option per statement, so they go one at a
        // time.
        manager
            .alter_table(
                Table::alter()
                    .table(Account::Table)
                    .add_column(big_integer(Account::LastLoginAt).null())
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Account::Table)
                    .add_column(big_integer(Account::InactivityWarningAt).null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(LoginToken::Table)
                    .col(pk_auto(LoginToken::Id))
                    .col(integer(LoginToken::AccountId).not_null())
                    .col(text(LoginToken::TokenDigest).not_null().unique_key())
                    .col(big_integer(LoginToken::IssuedAt).not_null())
                    .col(big_integer(LoginToken::ExpiresAt).not_null())
                    .col(big_integer(LoginToken::ConsumedAt).null())
                    .col(big_integer(LoginToken::RevokedAt).null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_login_token_account_id")
                            .from(LoginToken::Table, LoginToken::AccountId)
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
                    .name("idx_login_token_account_id")
                    .table(LoginToken::Table)
                    .col(LoginToken::AccountId)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(LoginToken::Table).to_owned())
            .await?;
        // SQLite gained `DROP COLUMN` in 3.35; the bundled SQLite is newer. A
        // rollback is a full rebuild, so dropping the columns is enough. One
        // option per statement, as in `up`.
        manager
            .alter_table(
                Table::alter()
                    .table(Account::Table)
                    .drop_column(Account::InactivityWarningAt)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Account::Table)
                    .drop_column(Account::LastLoginAt)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
