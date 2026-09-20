//! Initial schema: singleton config, ACME accounts, certificates, cert events.

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
    Kid,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Certificates {
    Table,
    Name,
    CertPem,
    KeyPem,
    NotBefore,
    NotAfter,
    Issuer,
    Directory,
    ObtainedAt,
    LastActiveAt,
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

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
                    .col(text_null(AcmeAccount::Kid))
                    .col(big_integer(AcmeAccount::CreatedAt))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Certificates::Table)
                    .col(text(Certificates::Name).primary_key())
                    .col(text(Certificates::CertPem))
                    .col(text(Certificates::KeyPem))
                    .col(big_integer(Certificates::NotBefore))
                    .col(big_integer(Certificates::NotAfter))
                    .col(text_null(Certificates::Issuer))
                    .col(text(Certificates::Directory))
                    .col(big_integer(Certificates::ObtainedAt))
                    .col(big_integer_null(Certificates::LastActiveAt))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(CertEvents::Table)
                    .col(big_pk_auto(CertEvents::Id))
                    .col(text(CertEvents::Name))
                    .col(big_integer(CertEvents::At))
                    .col(text(CertEvents::Kind))
                    .col(text_null(CertEvents::Detail))
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
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(CertEvents::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Certificates::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(AcmeAccount::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Config::Table).to_owned())
            .await
    }
}
