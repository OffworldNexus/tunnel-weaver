//! Abuse buckets: persisted GCRA rate-limit state (WVR-135).
//!
//! Adds the single composite-keyed `abuse_bucket` table (see
//! [`crate::store::entity::abuse_bucket`]). Written against the backend-agnostic
//! schema builder and forward-only, like the rest of the store; the extra index
//! on `updated_at_ms` backs the idle sweep.

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum AbuseBucket {
    Table,
    Scope,
    KeyKind,
    KeyId,
    TatMs,
    UpdatedAtMs,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(AbuseBucket::Table).to_owned())
            .await
    }
}
