//! `login_challenge` learns the address-verification purpose (WVR-169).
//!
//! One emailed-code mechanism now serves two purposes: the second factor of a
//! sign-in (WVR-167) and proving ownership of a signup's address. A signup has
//! no browser session yet, so the challenge can no longer be keyed by
//! `session_id` alone:
//!
//! * `purpose` — which acceptance means: `sign_in` lifts a session to `Strong`,
//!   `verify_address` settles the account's address. Two distinct emails are
//!   chosen from it.
//! * `session_id` — now nullable: a sign-in challenge still cascades from its
//!   session, an address challenge does not have one.
//! * `pending_registration_id` — the address challenge's flow: it cascades from
//!   the pending signup it belongs to, so abandoning a signup drops its code.
//!
//! The uniqueness moves to each flow in turn: a unique index on `session_id`
//! and one on `pending_registration_id`. Both columns are nullable, and SQL
//! treats `NULL`s as distinct, so a row keyed one way never conflicts with a row
//! keyed the other.
//!
//! SQLite cannot drop a column's `NOT NULL` in place, so the table is rebuilt.
//! That discards any *pending* codes at migration time; a challenge lives for
//! five minutes and a fresh one is one click away, so losing them is the
//! honest cost of the change rather than pretending a session-less row can be
//! written into the old shape.

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Only the columns referenced as foreign keys of the existing tables.
#[derive(DeriveIden)]
enum BrowserSession {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum PendingRegistration {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum LoginChallenge {
    Table,
    Id,
    Purpose,
    SessionId,
    PendingRegistrationId,
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
    /// The rebuild runs on one connection: SQLite otherwise spreads a
    /// migration's statements across the pool, and a table dropped and recreated
    /// under the same name — with an index the old and new shape share — must be
    /// seen consistently by each statement that touches it. One connection also
    /// makes the rebuild atomic.
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(LoginChallenge::Table).to_owned())
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(LoginChallenge::Table)
                    .col(pk_auto(LoginChallenge::Id))
                    .col(text(LoginChallenge::Purpose))
                    .col(integer_null(LoginChallenge::SessionId))
                    .col(integer_null(LoginChallenge::PendingRegistrationId))
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
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_login_challenge_pending_registration_id")
                            .from(LoginChallenge::Table, LoginChallenge::PendingRegistrationId)
                            .to(PendingRegistration::Table, PendingRegistration::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // One challenge per sign-in session.
        manager
            .create_index(
                Index::create()
                    .name("ux_login_challenge_session_id")
                    .table(LoginChallenge::Table)
                    .col(LoginChallenge::SessionId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // One challenge per pending signup.
        manager
            .create_index(
                Index::create()
                    .name("ux_login_challenge_pending_registration_id")
                    .table(LoginChallenge::Table)
                    .col(LoginChallenge::PendingRegistrationId)
                    .unique()
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
        // Restore the m0004 shape: one challenge per browser session, no
        // purpose. The pending rows were already discarded by `up`.
        manager
            .drop_table(Table::drop().table(LoginChallenge::Table).to_owned())
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
}
