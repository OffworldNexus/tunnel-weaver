//! `account_ban`: the ban history of an account (WVR-178).
//!
//! One row per ban. `unbanned_at` is genuinely absent while the ban holds and
//! carries the instant the operator lifted it otherwise, so the current ban is
//! exactly the row with `unbanned_at IS NULL`. Lifting a ban closes that row and
//! the history stays; banning again appends a new one.
//!
//! `account.state` remains the authority for "may this account act at all"
//! (`active`/`banned`) — every sign-in and admission path reads it, and nothing
//! rebuilds it from this table. This table exists for the operator: what was
//! banned, when, and why. The partial unique index keeps the two from drifting
//! into "two open bans", which would make "the current ban" ambiguous.
//!
//! `account_id` cascades: deleting an account deletes its history, matching the
//! hard-delete guarantee the rest of the schema already makes.

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Only the columns referenced as foreign keys of the existing table.
#[derive(DeriveIden)]
enum Account {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum AccountBan {
    Table,
    Id,
    AccountId,
    BannedAt,
    Reason,
    UnbannedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(AccountBan::Table)
                    .col(pk_auto(AccountBan::Id))
                    .col(integer(AccountBan::AccountId))
                    .col(big_integer(AccountBan::BannedAt))
                    .col(text(AccountBan::Reason))
                    .col(big_integer_null(AccountBan::UnbannedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_account_ban_account_id")
                            .from(AccountBan::Table, AccountBan::AccountId)
                            .to(Account::Table, Account::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // At most one open ban per account: "the current ban" is a single row
        // the store can update in place, and a second `ban` is a caller error
        // rather than a duplicated history.
        manager
            .create_index(
                Index::create()
                    .name("ux_account_ban_open")
                    .table(AccountBan::Table)
                    .col(AccountBan::AccountId)
                    .unique()
                    .and_where(Expr::col(AccountBan::UnbannedAt).is_null())
                    .to_owned(),
            )
            .await?;

        // The list's "most recent ban per account" read, and the cascade's
        // lookup by parent row.
        manager
            .create_index(
                Index::create()
                    .name("idx_account_ban_account_id")
                    .table(AccountBan::Table)
                    .col(AccountBan::AccountId)
                    .col(AccountBan::BannedAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_account_ban_account_id")
                    .table(AccountBan::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("ux_account_ban_open")
                    .table(AccountBan::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(AccountBan::Table).to_owned())
            .await?;
        Ok(())
    }
}
