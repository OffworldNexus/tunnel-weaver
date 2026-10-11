//! ALTCHA proof-of-work API clients and spent proofs (WVR-136).
//!
//! Adds two tables: `altcha_client` (the API clients a service or the internal
//! admin client signs challenges with) and `altcha_proof` (the single-use
//! markers that make a proof consumable exactly once until it expires). Both are
//! written against the backend-agnostic schema builder; the unique composite
//! index on `altcha_proof` is what makes consumption atomic, and the index on
//! `expires_at_ms` backs the expiry sweep.

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

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
enum Service {
    Table,
    Id,
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
        manager
            .drop_table(Table::drop().table(AltchaProof::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(AltchaClient::Table).to_owned())
            .await
    }
}
