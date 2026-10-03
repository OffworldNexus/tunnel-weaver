//! Flat-hostname data model: the certificate relationship is inverted and a
//! persistent ACME challenge registry replaces the in-memory one.
//!
//! Three changes, all OFF-190:
//!
//! 1. `certificates` stops being one row per domain and becomes one global row
//!    keyed by its own name (the zone apex `<root>`, holding the single
//!    `[<root>, *.<root>]` wildcard certificate). The old per-domain model is
//!    discarded outright — OFF-190 drops backward compatibility — and the
//!    operator's next `setup` issues the wildcard. (A data-preserving rebuild
//!    is impossible anyway: per-domain rows do not map onto one global row.)
//! 2. `domains` gains a nullable `certificate_id` FK so a request can resolve
//!    `Host -> domains.name -> service -> live tunnel` in one join.
//! 3. `challenge` holds multi-value TXT rrsets for DNS-01. The apex and the
//!    wildcard authorisations share `_acme-challenge.<root>`, so the same name
//!    must carry two values at once (RFC 8555); the composite unique index is
//!    what makes that a set rather than a single slot.

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

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
    Issuer,
    Directory,
    ObtainedAt,
}

#[derive(DeriveIden)]
enum Challenge {
    Table,
    Id,
    Name,
    Value,
    CreatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. Rebuild `certificates` in its global, name-keyed shape.
        //
        // The old model treated the certificate table as disposable per-domain
        // state and OFF-190 explicitly drops backward compatibility, so this is
        // a straight replace rather than a data-preserving rebuild: the next
        // `setup`/startup re-orders the single wildcard.
        manager
            .drop_table(Table::drop().table(Certificates::Table).to_owned())
            .await?;

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
                    .col(text_null(Certificates::Issuer))
                    .col(text(Certificates::Directory))
                    .col(big_integer(Certificates::ObtainedAt))
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

        // 2. `domains` points at the (global) certificate that covers it.
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE domains ADD COLUMN certificate_id INTEGER \
                 REFERENCES certificates(id) ON DELETE SET NULL",
            )
            .await?;

        // 3. Persistent, multi-value DNS-01 challenge registry.
        manager
            .create_table(
                Table::create()
                    .table(Challenge::Table)
                    .col(big_pk_auto(Challenge::Id))
                    .col(text(Challenge::Name))
                    .col(text(Challenge::Value))
                    .col(big_integer(Challenge::CreatedAt))
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

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Challenge::Table).to_owned())
            .await?;
        // The forward model has no faithful inverse (per-domain certs are gone
        // and the wildcard is not re-derivable), so only the additive table is
        // dropped. `down` is never invoked by the server.
        Ok(())
    }
}
