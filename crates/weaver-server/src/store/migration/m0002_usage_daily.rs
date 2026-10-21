//! `usage_daily` and `usage_live`: the day-grain rollup the console reads and
//! the current day's pre-allocated slot arrays it is built from.
//!
//! `usage_daily` — one row per `(service_id, day)` — **not** per metric. The
//! wide shape exists to keep storage dense: a service's whole day is a single
//! row, and each of the six metrics carries its day total plus two
//! zstd-compressed arrays (24 hourly values and 1440 per-minute values,
//! little-endian `i64`). The totals are plain columns so a whole-day read never
//! touches a blob; the arrays are read only when a window is finer than a day or
//! covers a day only partly.
//!
//! `usage_live` holds the days that are **not finished** (in steady state just
//! today) as six pre-allocated 11,520-byte cells per `(service_id, day)`: 1440
//! little-endian `i64` slots, one per minute, uncompressed and written **in
//! place** through the SQLite C blob API. The table is deliberately a plain
//! rowid table, *not* `WITHOUT ROWID`: the incremental-blob API addresses a row
//! by its `rowid`, which a `WITHOUT ROWID` table does not have, so
//! `sqlite3_blob_open` would refuse it. Pre-allocating the cells with
//! `zeroblob(11520)` means an in-place write can never miss a row and never has
//! to grow a blob.
//!
//! This migration also drops the old per-minute `usage` table (created by
//! m0001): the live day is now one write-in-place array per `(service, metric)`
//! instead of 1440 heap rows per service, which is what made the machines list
//! pay ~142 ms for a 65-machine store. `usage_live` is a table of its own, when
//! a live row is folded into `usage_daily` it is deleted in the same
//! transaction, so no minute is ever counted twice.

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// The six metered quantities, each with a total, an hourly array and a
/// per-minute array.
#[derive(DeriveIden)]
enum UsageDaily {
    Table,
    ServiceId,
    Day,
    BytesIn,
    BytesInHours,
    BytesInMinutes,
    BytesOut,
    BytesOutHours,
    BytesOutMinutes,
    TunnelIn,
    TunnelInHours,
    TunnelInMinutes,
    TunnelOut,
    TunnelOutHours,
    TunnelOutMinutes,
    Requests,
    RequestsHours,
    RequestsMinutes,
    OpenMs,
    OpenMsHours,
    OpenMsMinutes,
}

/// The live day: six fixed-offset `i64` arrays, one slot per minute.
#[derive(DeriveIden)]
enum UsageLive {
    Table,
    ServiceId,
    Day,
    BytesInSlots,
    BytesOutSlots,
    TunnelInSlots,
    TunnelOutSlots,
    RequestsSlots,
    OpenMsSlots,
}

/// The pre-`usage_daily` per-minute table, owned by m0001 and dropped here.
///
/// The idents are still needed so `down` can put the table back before m0001's
/// own `down` reaches it; rolling m0002 back is part of a full rebuild, not a
/// data-preserving path.
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

/// Only the `service` side of the foreign key; the table is owned by m0001.
#[derive(DeriveIden)]
enum Service {
    Table,
    Id,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(UsageDaily::Table)
                    .col(integer(UsageDaily::ServiceId).not_null())
                    .col(big_integer(UsageDaily::Day).not_null())
                    .col(big_integer(UsageDaily::BytesIn).not_null())
                    .col(blob(UsageDaily::BytesInHours).not_null())
                    .col(blob(UsageDaily::BytesInMinutes).not_null())
                    .col(big_integer(UsageDaily::BytesOut).not_null())
                    .col(blob(UsageDaily::BytesOutHours).not_null())
                    .col(blob(UsageDaily::BytesOutMinutes).not_null())
                    .col(big_integer(UsageDaily::TunnelIn).not_null())
                    .col(blob(UsageDaily::TunnelInHours).not_null())
                    .col(blob(UsageDaily::TunnelInMinutes).not_null())
                    .col(big_integer(UsageDaily::TunnelOut).not_null())
                    .col(blob(UsageDaily::TunnelOutHours).not_null())
                    .col(blob(UsageDaily::TunnelOutMinutes).not_null())
                    .col(big_integer(UsageDaily::Requests).not_null())
                    .col(blob(UsageDaily::RequestsHours).not_null())
                    .col(blob(UsageDaily::RequestsMinutes).not_null())
                    .col(big_integer(UsageDaily::OpenMs).not_null())
                    .col(blob(UsageDaily::OpenMsHours).not_null())
                    .col(blob(UsageDaily::OpenMsMinutes).not_null())
                    .primary_key(
                        Index::create()
                            .col(UsageDaily::ServiceId)
                            .col(UsageDaily::Day),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_usage_daily_service_id")
                            .from(UsageDaily::Table, UsageDaily::ServiceId)
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
                    .name("idx_usage_daily_day")
                    .table(UsageDaily::Table)
                    .col(UsageDaily::Day)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(UsageLive::Table)
                    .col(integer(UsageLive::ServiceId).not_null())
                    .col(big_integer(UsageLive::Day).not_null())
                    .col(blob(UsageLive::BytesInSlots).not_null())
                    .col(blob(UsageLive::BytesOutSlots).not_null())
                    .col(blob(UsageLive::TunnelInSlots).not_null())
                    .col(blob(UsageLive::TunnelOutSlots).not_null())
                    .col(blob(UsageLive::RequestsSlots).not_null())
                    .col(blob(UsageLive::OpenMsSlots).not_null())
                    .primary_key(
                        Index::create()
                            .col(UsageLive::ServiceId)
                            .col(UsageLive::Day),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_usage_live_service_id")
                            .from(UsageLive::Table, UsageLive::ServiceId)
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
                    .name("idx_usage_live_day")
                    .table(UsageLive::Table)
                    .col(UsageLive::Day)
                    .to_owned(),
            )
            .await?;

        // The old per-minute table is gone: the live day is an array now.
        manager
            .drop_table(Table::drop().table(Usage::Table).to_owned())
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UsageLive::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(UsageDaily::Table).to_owned())
            .await?;
        // Put the pre-m0002 `usage` table back so m0001's `down` still finds a
        // table to drop (its `DROP TABLE` is not `IF EXISTS`). Losing whatever
        // the live arrays held is inherent: rolling a migration back is a
        // rebuild, not a data-preserving operation.
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
}
