//! `auth_event` and `login_challenge` (WVR-167).
//!
//! Making the second factor mandatory and email-based needs two new tables and
//! no change to any existing one:
//!
//! * `auth_event` — the authentication trail, and the source the session's auth
//!   level is *derived* from (the latest occurrence of each proof kind still
//!   alive on a session). It has no foreign key on `session_id` on purpose: the
//!   nightly session sweep deletes expired sessions and the trail must outlive
//!   them, exactly as `machine_key_log` outlives the machine it describes. The
//!   `account_id` link *does* cascade, because this repo hard-deletes accounts
//!   and guarantees nothing of them survives.
//! * `login_challenge` — the pending emailed code for a sign-in: one row per
//!   browser session, replaced on every issue/re-send so only the newest code is
//!   accepted. It cascades from the session, which is meaningless to keep once
//!   the session is gone.

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
enum BrowserSession {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum AuthEvent {
    Table,
    Id,
    AccountId,
    SessionId,
    Kind,
    OccurredAt,
    IpAddress,
    UserAgent,
    Attempted,
}

#[derive(DeriveIden)]
enum LoginChallenge {
    Table,
    Id,
    SessionId,
    CodeHash,
    CreatedAt,
    ExpiresAt,
    Attempts,
    MaxAttempts,
    LastSentAt,
    ConsumedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AuthEvent::Table)
                    .col(pk_auto(AuthEvent::Id))
                    .col(integer_null(AuthEvent::AccountId))
                    .col(integer_null(AuthEvent::SessionId))
                    .col(text(AuthEvent::Kind))
                    .col(big_integer(AuthEvent::OccurredAt))
                    .col(text(AuthEvent::IpAddress).default(""))
                    .col(text(AuthEvent::UserAgent).default(""))
                    .col(text(AuthEvent::Attempted).default(""))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_auth_event_account_id")
                            .from(AuthEvent::Table, AuthEvent::AccountId)
                            .to(Account::Table, Account::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // The level derivation's query: latest occurrence per kind on a session.
        manager
            .create_index(
                Index::create()
                    .name("idx_auth_event_session_kind")
                    .table(AuthEvent::Table)
                    .col(AuthEvent::SessionId)
                    .col(AuthEvent::Kind)
                    .col(AuthEvent::OccurredAt)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_auth_event_account_id")
                    .table(AuthEvent::Table)
                    .col(AuthEvent::AccountId)
                    .col(AuthEvent::OccurredAt)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(LoginChallenge::Table)
                    .col(pk_auto(LoginChallenge::Id))
                    .col(integer(LoginChallenge::SessionId).unique_key())
                    .col(text(LoginChallenge::CodeHash))
                    .col(big_integer(LoginChallenge::CreatedAt))
                    .col(big_integer(LoginChallenge::ExpiresAt))
                    .col(integer(LoginChallenge::Attempts))
                    .col(integer(LoginChallenge::MaxAttempts))
                    .col(big_integer(LoginChallenge::LastSentAt))
                    .col(big_integer_null(LoginChallenge::ConsumedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_login_challenge_session_id")
                            .from(LoginChallenge::Table, LoginChallenge::SessionId)
                            .to(BrowserSession::Table, BrowserSession::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_login_challenge_expires_at")
                    .table(LoginChallenge::Table)
                    .col(LoginChallenge::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(LoginChallenge::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(AuthEvent::Table).to_owned())
            .await?;
        Ok(())
    }
}
