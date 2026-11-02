//! `browser_session` remembers which identity provider opened it (WVR-175).
//!
//! A step-up at a provider must return to the *same* provider: its callback
//! checks the re-authenticated identity against the one the account linked
//! there, so re-running the flow at another provider the account also holds
//! would fail with an identity mismatch. The console needs the provider id to
//! build that redirect, and only the session knows which one signed in — the
//! account may hold several linked identities.
//!
//! An empty string means "no provider": every password and passkey session, and
//! every SSO session opened before this migration.

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum BrowserSession {
    Table,
    Provider,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SQLite rejects more than one ALTER option per statement, so the one
        // column goes alone. The default backfills every existing row.
        manager
            .alter_table(
                Table::alter()
                    .table(BrowserSession::Table)
                    .add_column(text(BrowserSession::Provider).default(""))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(BrowserSession::Table)
                    .drop_column(BrowserSession::Provider)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
