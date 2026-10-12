//! Email account lifecycle (WVR-36).
//!
//! Adds the account plane's persistent records: `account` (the stable identity
//! key, distinct from the tunnel-namespace `person`), `pending_registration`
//! (an unverified signup that has not yet become an account),
//! `email_identity` (the one-account-per-address association, enforced by a
//! unique lookup key), `verification_token` (single-use proof-of-ownership
//! tokens, stored as a digest), `email_verification` (append-only ownership
//! history), `password_credential` (append-only Argon2 history with a current
//! marker) and `browser_session` (server-side sessions keyed by a token hash).
//!
//! Timestamps are Unix seconds stored as `i64`, matching the rest of the store.
//! The schema is written against the backend-agnostic builder so the same DDL
//! is valid for SQLite today and PostgreSQL later. The unique indexes are the
//! concurrency-safe enforcement points: `email_identity.lookup_key` guarantees
//! one account per address even under racing activations, and
//! `verification_token.token_digest` / `browser_session.token_hash` make token
//! and session lookup deterministic.

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Account {
    Table,
    Id,
    Name,
    State,
    CreatedAt,
    ActivatedAt,
}

#[derive(DeriveIden)]
enum PendingRegistration {
    Table,
    Id,
    FlowId,
    Name,
    Email,
    LookupKey,
    CreatedAt,
    ExpiresAt,
    CompletedAt,
    ProvedByTokenId,
}

#[derive(DeriveIden)]
enum EmailIdentity {
    Table,
    Id,
    AccountId,
    Email,
    LookupKey,
    CreatedAt,
    VerifiedAt,
}

#[derive(DeriveIden)]
enum VerificationToken {
    Table,
    Id,
    PendingRegistrationId,
    EmailLookupKey,
    TokenDigest,
    Purpose,
    IssuedAt,
    ExpiresAt,
    ConsumedAt,
    RevokedAt,
}

#[derive(DeriveIden)]
enum EmailVerification {
    Table,
    Id,
    AccountId,
    EmailIdentityId,
    TokenId,
    VerifiedAt,
}

#[derive(DeriveIden)]
enum PasswordCredential {
    Table,
    Id,
    AccountId,
    EncodedHash,
    CreatedAt,
    RetiredAt,
}

#[derive(DeriveIden)]
enum BrowserSession {
    Table,
    Id,
    AccountId,
    TokenHash,
    CreatedAt,
    ExpiresAt,
    InvalidatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // The account record. `name` is deliberately NOT unique and preserves
        // Unicode exactly as entered (e.g. "Rémy"); identity is resolved through
        // `email_identity`, never the display name.
        manager
            .create_table(
                Table::create()
                    .table(Account::Table)
                    .col(pk_auto(Account::Id))
                    .col(text(Account::Name))
                    .col(text(Account::State).default("active"))
                    .col(big_integer(Account::CreatedAt))
                    .col(big_integer(Account::ActivatedAt))
                    .to_owned(),
            )
            .await?;

        // An in-flight signup. It owns the proposed name/email until ownership
        // is proven; it is never an account and cannot take over an existing
        // address association. `expires_at` bounds how long the email link lives.
        manager
            .create_table(
                Table::create()
                    .table(PendingRegistration::Table)
                    .col(pk_auto(PendingRegistration::Id))
                    .col(text(PendingRegistration::FlowId).unique_key())
                    .col(text(PendingRegistration::Name))
                    .col(text(PendingRegistration::Email))
                    .col(text(PendingRegistration::LookupKey))
                    .col(big_integer(PendingRegistration::CreatedAt))
                    .col(big_integer(PendingRegistration::ExpiresAt))
                    .col(big_integer_null(PendingRegistration::CompletedAt))
                    .col(integer_null(PendingRegistration::ProvedByTokenId))
                    .to_owned(),
            )
            .await?;

        // The account/address association. The unique `lookup_key` (a trimmed,
        // lowercased address) is the database-level guarantee that an address
        // belongs to exactly one account, even when two activations race. The
        // original `email` is kept for display; no dot/plus rewriting is applied.
        manager
            .create_table(
                Table::create()
                    .table(EmailIdentity::Table)
                    .col(pk_auto(EmailIdentity::Id))
                    .col(integer(EmailIdentity::AccountId))
                    .col(text(EmailIdentity::Email))
                    .col(text(EmailIdentity::LookupKey).unique_key())
                    .col(big_integer(EmailIdentity::CreatedAt))
                    .col(big_integer_null(EmailIdentity::VerifiedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_email_identity_account_id")
                            .from(EmailIdentity::Table, EmailIdentity::AccountId)
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
                    .name("idx_email_identity_account_id")
                    .table(EmailIdentity::Table)
                    .col(EmailIdentity::AccountId)
                    .to_owned(),
            )
            .await?;

        // A single-use proof-of-ownership token. Only the digest is stored; the
        // raw secret lives only in the emailed link. Consumption and revocation
        // are timestamps so the row (and the history that references it) survive.
        manager
            .create_table(
                Table::create()
                    .table(VerificationToken::Table)
                    .col(pk_auto(VerificationToken::Id))
                    .col(integer(VerificationToken::PendingRegistrationId))
                    .col(text(VerificationToken::EmailLookupKey))
                    .col(text(VerificationToken::TokenDigest).unique_key())
                    .col(text(VerificationToken::Purpose).default("email-verification"))
                    .col(big_integer(VerificationToken::IssuedAt))
                    .col(big_integer(VerificationToken::ExpiresAt))
                    .col(big_integer_null(VerificationToken::ConsumedAt))
                    .col(big_integer_null(VerificationToken::RevokedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_verification_token_pending_registration_id")
                            .from(
                                VerificationToken::Table,
                                VerificationToken::PendingRegistrationId,
                            )
                            .to(PendingRegistration::Table, PendingRegistration::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_verification_token_pending_registration_id")
                    .table(VerificationToken::Table)
                    .col(VerificationToken::PendingRegistrationId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_verification_token_expires_at")
                    .table(VerificationToken::Table)
                    .col(VerificationToken::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        // Append-only ownership history. The initial verification is a real row
        // referencing the token that proved it, not a boolean on the account.
        manager
            .create_table(
                Table::create()
                    .table(EmailVerification::Table)
                    .col(pk_auto(EmailVerification::Id))
                    .col(integer(EmailVerification::AccountId))
                    .col(integer(EmailVerification::EmailIdentityId))
                    .col(integer(EmailVerification::TokenId))
                    .col(big_integer(EmailVerification::VerifiedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_email_verification_account_id")
                            .from(EmailVerification::Table, EmailVerification::AccountId)
                            .to(Account::Table, Account::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_email_verification_email_identity_id")
                            .from(EmailVerification::Table, EmailVerification::EmailIdentityId)
                            .to(EmailIdentity::Table, EmailIdentity::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_email_verification_token_id")
                            .from(EmailVerification::Table, EmailVerification::TokenId)
                            .to(VerificationToken::Table, VerificationToken::Id)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_email_verification_account_id")
                    .table(EmailVerification::Table)
                    .col(EmailVerification::AccountId)
                    .to_owned(),
            )
            .await?;

        // Append-only password history. The PHC-encoded Argon2 hash embeds its
        // own parameters and salt. Exactly one row per account is current
        // (`retired_at` null); a change supersedes the old row.
        manager
            .create_table(
                Table::create()
                    .table(PasswordCredential::Table)
                    .col(pk_auto(PasswordCredential::Id))
                    .col(integer(PasswordCredential::AccountId))
                    .col(text(PasswordCredential::EncodedHash))
                    .col(big_integer(PasswordCredential::CreatedAt))
                    .col(big_integer_null(PasswordCredential::RetiredAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_password_credential_account_id")
                            .from(PasswordCredential::Table, PasswordCredential::AccountId)
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
                    .name("idx_password_credential_account_id")
                    .table(PasswordCredential::Table)
                    .col(PasswordCredential::AccountId)
                    .to_owned(),
            )
            .await?;

        // Server-side sessions. The opaque cookie secret is stored only as a
        // digest; `invalidated_at` retires a session without deleting the row.
        manager
            .create_table(
                Table::create()
                    .table(BrowserSession::Table)
                    .col(pk_auto(BrowserSession::Id))
                    .col(integer(BrowserSession::AccountId))
                    .col(text(BrowserSession::TokenHash).unique_key())
                    .col(big_integer(BrowserSession::CreatedAt))
                    .col(big_integer(BrowserSession::ExpiresAt))
                    .col(big_integer_null(BrowserSession::InvalidatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_browser_session_account_id")
                            .from(BrowserSession::Table, BrowserSession::AccountId)
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
                    .name("idx_browser_session_account_id")
                    .table(BrowserSession::Table)
                    .col(BrowserSession::AccountId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_browser_session_expires_at")
                    .table(BrowserSession::Table)
                    .col(BrowserSession::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop in reverse dependency order.
        manager
            .drop_table(Table::drop().table(BrowserSession::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(PasswordCredential::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(EmailVerification::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(VerificationToken::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(EmailIdentity::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(PendingRegistration::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Account::Table).to_owned())
            .await?;
        Ok(())
    }
}
