//! The whole schema, created in dependency order: relay configuration, the
//! account plane, people and their machines, services and hostnames,
//! certificates and ACME challenges, usage metering, abuse buckets and ALTCHA.
//!
//! Written against the backend-agnostic schema builder, so the same DDL is valid
//! for SQLite today and PostgreSQL later. The unique indexes are the
//! concurrency-safe enforcement points: one account per email address
//! (`email_identity.lookup_key`), one person per account (`person.account_id`),
//! one machine per key (`machine.key_id`), deterministic token and session
//! lookups (`verification_token.token_digest`, `password_reset_token.token_digest`,
//! `browser_session.token_hash`) and single-use proofs
//! (`altcha_proof(public_key, nonce)`).

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// Variants mirror column names verbatim; the clippy lint about repeating the
// enum name is a false positive here.
#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum Config {
    Table,
    Id,
    ConfigJson,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum AcmeAccount {
    Table,
    Directory,
    Email,
    CredentialsJson,
    CreatedAt,
}

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

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum Person {
    Table,
    Id,
    Name,
    CreatedAt,
    AccountId,
}

#[derive(DeriveIden)]
enum Machine {
    Table,
    Id,
    PersonId,
    Name,
    CreatedAt,
    KeyId,
}

#[derive(DeriveIden)]
enum MachineKeyLog {
    Table,
    Id,
    KeyId,
    MachineId,
    PersonId,
    AddedAt,
    RetiredAt,
    RetiredReason,
}

#[derive(DeriveIden)]
enum Service {
    Table,
    Id,
    MachineId,
    Name,
    CreatedAt,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum Certificates {
    Table,
    Id,
    Name,
    CertPem,
    KeyPem,
    NotBefore,
    NotAfter,
    Directory,
    ObtainedAt,
    Validation,
}

#[derive(DeriveIden)]
enum Domains {
    Table,
    Id,
    Name,
    LastActiveAt,
    ServiceId,
}

#[derive(DeriveIden)]
enum CertEvents {
    Table,
    Id,
    Name,
    At,
    Kind,
    Detail,
}

#[derive(DeriveIden)]
enum Usage {
    Table,
    ServiceId,
    Minute,
    BytesIn,
    BytesOut,
    TunnelIn,
    TunnelOut,
    Requests,
    UnusedMs,
}

#[derive(DeriveIden)]
enum Challenge {
    Table,
    Id,
    Name,
    Value,
    Certificate,
    CreatedAt,
    Kind,
}

#[derive(DeriveIden)]
enum AbuseBucket {
    Table,
    Scope,
    KeyKind,
    KeyId,
    TatMs,
    UpdatedAtMs,
}

#[derive(DeriveIden)]
enum AltchaClient {
    Table,
    Id,
    PublicKey,
    Secret,
    Algorithm,
    Cost,
    KeyLength,
    KeyPrefix,
    TtlSecs,
    ServiceId,
    CreatedAt,
    RotatedAt,
    RevokedAt,
}

#[derive(DeriveIden)]
enum AltchaProof {
    Table,
    Id,
    PublicKey,
    Nonce,
    ConsumedAtMs,
    ExpiresAtMs,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ----- relay configuration and ACME accounts -----

        // `config` is a singleton: the CHECK keeps callers from ever creating a
        // second row by accident, so reads can assume `id = 1`.
        manager
            .create_table(
                Table::create()
                    .table(Config::Table)
                    .col(
                        integer(Config::Id)
                            .primary_key()
                            .check(Expr::col(Config::Id).eq(1)),
                    )
                    .col(text(Config::ConfigJson))
                    .col(big_integer(Config::UpdatedAt))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(AcmeAccount::Table)
                    .col(text(AcmeAccount::Directory).primary_key())
                    .col(text(AcmeAccount::Email))
                    .col(text(AcmeAccount::CredentialsJson))
                    .col(big_integer(AcmeAccount::CreatedAt))
                    .to_owned(),
            )
            .await?;

        // ----- the account plane -----

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

        // ----- password-reset tokens -----

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

        // ----- people, machines and their keys -----

        // The tunnel-namespace owner. An account has exactly one person and a
        // person exactly one account: `account_id` is unique and cascades, so
        // deleting an account takes its person and everything beneath it.
        manager
            .create_table(
                Table::create()
                    .table(Person::Table)
                    .col(pk_auto(Person::Id))
                    .col(text(Person::Name).unique_key())
                    .col(big_integer(Person::CreatedAt))
                    .col(integer(Person::AccountId).unique_key())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_person_account_id")
                            .from(Person::Table, Person::AccountId)
                            .to(Account::Table, Account::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // A person's machine. It holds exactly one key, and the key alone
        // identifies it, so `key_id` is unique.
        manager
            .create_table(
                Table::create()
                    .table(Machine::Table)
                    .col(pk_auto(Machine::Id))
                    .col(integer(Machine::PersonId))
                    .col(text(Machine::Name))
                    .col(big_integer(Machine::CreatedAt))
                    .col(text(Machine::KeyId).unique_key())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_machine_person_id")
                            .from(Machine::Table, Machine::PersonId)
                            .to(Person::Table, Person::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_machine_person_id_name")
                    .table(Machine::Table)
                    .col(Machine::PersonId)
                    .col(Machine::Name)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // Which key a machine held, when. Deliberately no foreign keys: the log
        // outlives the machine and person it describes. Retired rows are swept
        // after the configured retention, hence the index on `retired_at`.
        manager
            .create_table(
                Table::create()
                    .table(MachineKeyLog::Table)
                    .col(pk_auto(MachineKeyLog::Id))
                    .col(text(MachineKeyLog::KeyId))
                    .col(integer(MachineKeyLog::MachineId))
                    .col(integer(MachineKeyLog::PersonId))
                    .col(big_integer(MachineKeyLog::AddedAt))
                    .col(big_integer_null(MachineKeyLog::RetiredAt))
                    .col(text(MachineKeyLog::RetiredReason))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_machine_key_log_retired_at")
                    .table(MachineKeyLog::Table)
                    .col(MachineKeyLog::RetiredAt)
                    .to_owned(),
            )
            .await?;

        // Services a machine declares.
        manager
            .create_table(
                Table::create()
                    .table(Service::Table)
                    .col(pk_auto(Service::Id))
                    .col(integer(Service::MachineId))
                    .col(text(Service::Name))
                    .col(big_integer(Service::CreatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_service_machine_id")
                            .from(Service::Table, Service::MachineId)
                            .to(Machine::Table, Machine::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_service_machine_id_name")
                    .table(Service::Table)
                    .col(Service::MachineId)
                    .col(Service::Name)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // ----- certificates, hostnames, usage and ACME challenges -----

        // `certificates`: global rows keyed by their own name. There are
        // two long-lived rows (the `[<root>, *.<root>]`
        // wildcard held under the zone apex and the single-name admin
        // certificate) but the table does not hard-code that cardinality.
        manager
            .create_table(
                Table::create()
                    .table(Certificates::Table)
                    .col(pk_auto(Certificates::Id))
                    .col(text(Certificates::Name))
                    .col(text(Certificates::CertPem))
                    .col(text(Certificates::KeyPem))
                    .col(big_integer(Certificates::NotBefore))
                    .col(big_integer(Certificates::NotAfter))
                    .col(text(Certificates::Directory))
                    .col(big_integer(Certificates::ObtainedAt))
                    .col(text(Certificates::Validation).default("dns-01"))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_certificates_name")
                    .table(Certificates::Table)
                    .col(Certificates::Name)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // `domains`: materialized flat service hostnames. `service_id`
        // is nullable so a domain survives the service being removed
        // (`ON DELETE SET NULL`).
        manager
            .create_table(
                Table::create()
                    .table(Domains::Table)
                    .col(pk_auto(Domains::Id))
                    .col(text(Domains::Name).unique_key())
                    .col(big_integer_null(Domains::LastActiveAt))
                    .col(integer_null(Domains::ServiceId))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_domains_service_id")
                            .from(Domains::Table, Domains::ServiceId)
                            .to(Service::Table, Service::Id)
                            .on_delete(ForeignKeyAction::SetNull)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_domains_service_id")
                    .table(Domains::Table)
                    .col(Domains::ServiceId)
                    .to_owned(),
            )
            .await?;

        // Certificate lifecycle events.
        manager
            .create_table(
                Table::create()
                    .table(CertEvents::Table)
                    .col(big_pk_auto(CertEvents::Id))
                    .col(text(CertEvents::Name))
                    .col(big_integer(CertEvents::At))
                    .col(text(CertEvents::Kind))
                    .col(text(CertEvents::Detail))
                    .to_owned(),
            )
            .await?;

        // The hot query is "latest events for one hostname"; index it.
        manager
            .create_index(
                Index::create()
                    .name("idx_cert_events_name_at")
                    .table(CertEvents::Table)
                    .col(CertEvents::Name)
                    .col(CertEvents::At)
                    .to_owned(),
            )
            .await?;

        // `usage`: per-service, per-minute metering buckets. The
        // composite primary key makes the flush upsert idempotent and the extra
        // index on `minute` serves cross-service range scans.
        manager
            .create_table(
                Table::create()
                    .table(Usage::Table)
                    .col(integer(Usage::ServiceId).not_null())
                    .col(big_integer(Usage::Minute).not_null())
                    .col(big_integer(Usage::BytesIn).not_null())
                    .col(big_integer(Usage::BytesOut).not_null())
                    .col(big_integer(Usage::TunnelIn).not_null())
                    .col(big_integer(Usage::TunnelOut).not_null())
                    .col(big_integer(Usage::Requests).not_null())
                    .col(integer(Usage::UnusedMs).not_null())
                    .primary_key(Index::create().col(Usage::ServiceId).col(Usage::Minute))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_usage_service_id")
                            .from(Usage::Table, Usage::ServiceId)
                            .to(Service::Table, Service::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_usage_minute")
                    .table(Usage::Table)
                    .col(Usage::Minute)
                    .to_owned(),
            )
            .await?;

        // `challenge`: persistent, multi-value DNS-01 / HTTP-01 registry.
        // The apex and wildcard authorisations share the challenge name, so the
        // composite unique index is what makes a name a set of values.
        manager
            .create_table(
                Table::create()
                    .table(Challenge::Table)
                    .col(big_pk_auto(Challenge::Id))
                    .col(text(Challenge::Name))
                    .col(text(Challenge::Value))
                    .col(text(Challenge::Certificate))
                    .col(big_integer(Challenge::CreatedAt))
                    .col(text(Challenge::Kind).default("dns-01"))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_challenge_name_value")
                    .table(Challenge::Table)
                    .col(Challenge::Name)
                    .col(Challenge::Value)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // ----- abuse buckets -----

        manager
            .create_table(
                Table::create()
                    .table(AbuseBucket::Table)
                    .col(text(AbuseBucket::Scope))
                    .col(integer(AbuseBucket::KeyKind))
                    .col(big_integer(AbuseBucket::KeyId))
                    .col(big_integer(AbuseBucket::TatMs))
                    .col(big_integer(AbuseBucket::UpdatedAtMs))
                    .primary_key(
                        Index::create()
                            .col(AbuseBucket::Scope)
                            .col(AbuseBucket::KeyKind)
                            .col(AbuseBucket::KeyId),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_abuse_bucket_updated_at")
                    .table(AbuseBucket::Table)
                    .col(AbuseBucket::UpdatedAtMs)
                    .to_owned(),
            )
            .await?;

        // ----- ALTCHA clients and spent proofs -----

        // API clients. `service_id` is null for the internal (admin) client and
        // set for a service client; `ON DELETE SET NULL` keeps the client row if
        // the service disappears. Uniqueness of the internal client is enforced
        // in the create transaction, not a partial index, so the DDL stays
        // portable across SQLite and PostgreSQL.
        manager
            .create_table(
                Table::create()
                    .table(AltchaClient::Table)
                    .col(pk_auto(AltchaClient::Id))
                    .col(text(AltchaClient::PublicKey).unique_key())
                    .col(text(AltchaClient::Secret))
                    .col(text(AltchaClient::Algorithm).default("PBKDF2/SHA-256"))
                    .col(integer(AltchaClient::Cost))
                    .col(integer(AltchaClient::KeyLength).default(32))
                    .col(text(AltchaClient::KeyPrefix).default("00"))
                    .col(big_integer(AltchaClient::TtlSecs))
                    .col(integer_null(AltchaClient::ServiceId))
                    .col(big_integer(AltchaClient::CreatedAt))
                    .col(big_integer(AltchaClient::RotatedAt))
                    .col(big_integer_null(AltchaClient::RevokedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_altcha_client_service_id")
                            .from(AltchaClient::Table, AltchaClient::ServiceId)
                            .to(Service::Table, Service::Id)
                            .on_delete(ForeignKeyAction::SetNull)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_altcha_client_service_id")
                    .table(AltchaClient::Table)
                    .col(AltchaClient::ServiceId)
                    .to_owned(),
            )
            .await?;

        // Spent-proof markers. One row per consumed proof, unique on
        // `(public_key, nonce)`; a replayed payload hits the conflict and is
        // refused. Rows are swept once past `expires_at_ms`.
        manager
            .create_table(
                Table::create()
                    .table(AltchaProof::Table)
                    .col(pk_auto(AltchaProof::Id))
                    .col(text(AltchaProof::PublicKey))
                    .col(text(AltchaProof::Nonce))
                    .col(big_integer(AltchaProof::ConsumedAtMs))
                    .col(big_integer(AltchaProof::ExpiresAtMs))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_altcha_proof_public_key_nonce")
                    .table(AltchaProof::Table)
                    .col(AltchaProof::PublicKey)
                    .col(AltchaProof::Nonce)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_altcha_proof_expires_at_ms")
                    .table(AltchaProof::Table)
                    .col(AltchaProof::ExpiresAtMs)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Reverse dependency order.
        manager
            .drop_table(Table::drop().table(AltchaProof::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(AltchaClient::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(AbuseBucket::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Challenge::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Usage::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(CertEvents::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Domains::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Certificates::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Service::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(MachineKeyLog::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Machine::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Person::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(PasswordResetToken::Table).to_owned())
            .await?;
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
        manager
            .drop_table(Table::drop().table(AcmeAccount::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Config::Table).to_owned())
            .await?;
        Ok(())
    }
}
