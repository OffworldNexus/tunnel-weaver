//! The client schema: the device key, and the relays it is paired with.

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Device {
    Table,
    Id,
    KeyId,
}

#[derive(DeriveIden)]
enum Relay {
    Table,
    Id,
    AdminHost,
    MachineId,
    KeyId,
    IsDefault,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Device::Table)
                    .col(integer(Device::Id).primary_key())
                    .col(text(Device::KeyId))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Relay::Table)
                    .col(pk_auto(Relay::Id))
                    .col(text(Relay::AdminHost).unique_key())
                    .col(integer(Relay::MachineId))
                    .col(text(Relay::KeyId))
                    .col(boolean(Relay::IsDefault))
                    .to_owned(),
            )
            .await?;

        // At most one default: a partial unique index over the rows that are.
        manager
            .create_index(
                Index::create()
                    .name("idx_relay_single_default")
                    .table(Relay::Table)
                    .col(Relay::IsDefault)
                    .unique()
                    .and_where(Expr::col(Relay::IsDefault).eq(true))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Relay::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Device::Table).to_owned())
            .await?;
        Ok(())
    }
}
