//! Initial schema: singleton config, ACME accounts, person, machine, machine_key,
//! service, certificates, domains, cert events, per-service usage buckets, and
//! the persistent ACME challenge registry.
//!
//! There has been no release, so this one migration describes the whole current
//! schema and supersedes the former incremental `m0002`–`m0004`.

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

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum Person {
    Table,
    Id,
    Name,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Machine {
    Table,
    Id,
    PersonId,
    Name,
    CreatedAt,
}

#[derive(DeriveIden)]
enum MachineKey {
    Table,
    Id,
    MachineId,
    KeyId,
    CreatedAt,
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
    Issuer,
    Directory,
    ObtainedAt,
    Validation,
    Wildcard,
}

#[derive(DeriveIden)]
enum Domains {
    Table,
    Id,
    Name,
    LastActiveAt,
    ServiceId,
    CertificateId,
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
    CreatedAt,
    Kind,
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

        // 1. person table
        manager
            .create_table(
                Table::create()
                    .table(Person::Table)
                    .col(pk_auto(Person::Id))
                    .col(text(Person::Name).unique_key())
                    .col(big_integer(Person::CreatedAt))
                    .to_owned(),
            )
            .await?;

        // 2. machine table
        manager
            .create_table(
                Table::create()
                    .table(Machine::Table)
                    .col(pk_auto(Machine::Id))
                    .col(integer(Machine::PersonId))
                    .col(text(Machine::Name))
                    .col(big_integer(Machine::CreatedAt))
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

        // 3. machine_key table
        manager
            .create_table(
                Table::create()
                    .table(MachineKey::Table)
                    .col(pk_auto(MachineKey::Id))
                    .col(integer(MachineKey::MachineId))
                    .col(text(MachineKey::KeyId).unique_key())
                    .col(big_integer(MachineKey::CreatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_machine_key_machine_id")
                            .from(MachineKey::Table, MachineKey::MachineId)
                            .to(Machine::Table, Machine::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // 4. service table
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

        // 5. certificates table: global rows keyed by their own name. There are
        // two long-lived rows in the OFF-198 model (the `[<root>, *.<root>]`
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
                    .col(text_null(Certificates::Issuer))
                    .col(text(Certificates::Directory))
                    .col(big_integer(Certificates::ObtainedAt))
                    .col(text(Certificates::Validation).default("dns-01"))
                    // Whether the certificate carries a wildcard SAN. Stored
                    // explicitly rather than re-derived from the name so
                    // `cert status` can label a row accurately even after the
                    // zone model changes.
                    .col(boolean(Certificates::Wildcard).default(false))
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

        // 6. domains table: materialized flat service hostnames. `service_id`
        // and `certificate_id` are nullable so a domain survives either side
        // being removed (`ON DELETE SET NULL`).
        manager
            .create_table(
                Table::create()
                    .table(Domains::Table)
                    .col(pk_auto(Domains::Id))
                    .col(text(Domains::Name).unique_key())
                    .col(big_integer_null(Domains::LastActiveAt))
                    .col(integer_null(Domains::ServiceId))
                    .col(integer_null(Domains::CertificateId))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_domains_service_id")
                            .from(Domains::Table, Domains::ServiceId)
                            .to(Service::Table, Service::Id)
                            .on_delete(ForeignKeyAction::SetNull)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_domains_certificate_id")
                            .from(Domains::Table, Domains::CertificateId)
                            .to(Certificates::Table, Certificates::Id)
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

        // 7. cert_events table
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
            .await?;

        // 8. usage table: per-service, per-minute metering buckets. The
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

        // 9. challenge table: persistent, multi-value DNS-01 / HTTP-01 registry.
        // The apex and wildcard authorisations share the challenge name, so the
        // composite unique index is what makes a name a set of values.
        manager
            .create_table(
                Table::create()
                    .table(Challenge::Table)
                    .col(big_pk_auto(Challenge::Id))
                    .col(text(Challenge::Name))
                    .col(text(Challenge::Value))
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

        // 10. seed default PoC person ("poc"), machine ("laptop"), and dev key.
        // Foreign keys are resolved by name (person/machine names are unique)
        // so the seed never depends on auto-increment values.
        manager
            .exec_stmt(
                Query::insert()
                    .into_table(Person::Table)
                    .columns([Person::Name, Person::CreatedAt])
                    .values_panic(["poc".into(), 0i64.into()])
                    .to_owned(),
            )
            .await?;

        let select_poc_person = Query::select()
            .column(Person::Id)
            .from(Person::Table)
            .and_where(Expr::col(Person::Name).eq("poc"))
            .to_owned();
        let select_laptop_machine = Query::select()
            .column(Machine::Id)
            .expr(Expr::val(
                "ed25519:9b017abe250e5b63f6817a84ec9c7b7598b11fc80056ece29e06b8aa4b517906",
            ))
            .expr(Expr::val(0i64))
            .from(Machine::Table)
            .and_where(Expr::col(Machine::Name).eq("laptop"))
            .and_where(Expr::col(Machine::PersonId).in_subquery(select_poc_person))
            .to_owned();

        let mut insert_machine = Query::insert();
        insert_machine
            .into_table(Machine::Table)
            .columns([Machine::PersonId, Machine::Name, Machine::CreatedAt])
            .select_from(
                Query::select()
                    .column(Person::Id)
                    .expr(Expr::val("laptop"))
                    .expr(Expr::val(0i64))
                    .from(Person::Table)
                    .and_where(Expr::col(Person::Name).eq("poc"))
                    .to_owned(),
            )
            .map_err(|e| DbErr::Custom(e.to_string()))?;
        manager.exec_stmt(insert_machine.to_owned()).await?;

        let mut insert_key = Query::insert();
        insert_key
            .into_table(MachineKey::Table)
            .columns([
                MachineKey::MachineId,
                MachineKey::KeyId,
                MachineKey::CreatedAt,
            ])
            .select_from(select_laptop_machine)
            .map_err(|e| DbErr::Custom(e.to_string()))?;
        manager.exec_stmt(insert_key.to_owned()).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
            .drop_table(Table::drop().table(MachineKey::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Machine::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Person::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(AcmeAccount::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Config::Table).to_owned())
            .await
    }
}
