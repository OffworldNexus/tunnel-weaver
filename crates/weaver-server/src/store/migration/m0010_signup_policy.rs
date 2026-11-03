//! `signup_policy` and `signup_rule`: who may create an account (WVR-98).
//!
//! One relay-wide policy, Apache-ipfw style: a default decision plus numbered
//! rules evaluated in ascending order, first match wins. The policy is read from
//! the store on every attempt rather than from the cached config, so a `signup`
//! CLI write applies to the next signup with no daemon restart.
//!
//! `signup_policy` is a singleton (`id = 1`); **no row** means "not configured",
//! which is exactly today's behaviour — default allow, no rules. `signup_rule`
//! holds one rule per number: `decision` is `allow`/`deny`, `kind` is
//! `email`/`domain`, and `value` is already normalised (trimmed, lowercased).

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum SignupPolicy {
    Table,
    Id,
    DefaultDecision,
}

#[derive(DeriveIden)]
enum SignupRule {
    Table,
    Number,
    Decision,
    Kind,
    Value,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // The CHECK mirrors `config`: a second row cannot be created by accident,
        // so reads can assume `id = 1`.
        manager
            .create_table(
                Table::create()
                    .table(SignupPolicy::Table)
                    .col(
                        integer(SignupPolicy::Id)
                            .primary_key()
                            .check(Expr::col(SignupPolicy::Id).eq(1)),
                    )
                    .col(text(SignupPolicy::DefaultDecision))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(SignupRule::Table)
                    .col(integer(SignupRule::Number).primary_key())
                    .col(text(SignupRule::Decision))
                    .col(text(SignupRule::Kind))
                    .col(text(SignupRule::Value))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(SignupRule::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(SignupPolicy::Table).to_owned())
            .await?;
        Ok(())
    }
}
