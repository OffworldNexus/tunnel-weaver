//! `account.last_login_at` and `account.inactivity_warning_at` (WVR-160).
//!
//! An account that nobody uses for a year is deleted automatically. Deciding
//! "nobody used it" needs two facts the schema did not keep:
//!
//! * `last_login_at` — the latest successful sign-in, in Unix seconds. Written
//!   on every login. It is nullable because an account that was activated but
//!   never signed in has no sign-in yet; the sweep falls back to `activated_at`
//!   for those so a fresh account is never mistaken for an abandoned one.
//! * `inactivity_warning_at` — when the "your account will be deleted" email was
//!   last sent. Recorded so the warning is sent once per inactive cycle instead
//!   of on every sweep tick; a later sign-in or metered minute moves the clock
//!   past it, so the next cycle can warn again.

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Only the columns added to the m0001-owned `account` table.
#[derive(DeriveIden)]
enum Account {
    Table,
    LastLoginAt,
    InactivityWarningAt,
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
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
