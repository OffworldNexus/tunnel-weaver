//! Metering schema: the `usage` table, one row per (service, minute) in
//! which the service was active.
//!
//! Keyed and indexed by `(service_id, minute)`; the composite primary key
//! makes the flush upsert idempotent, and the extra index on `minute` serves
//! cross-service range scans (the usage query's `[since, until)` filter).

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Service {
    Table,
    Id,
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

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Usage::Table).to_owned())
            .await
    }
}
