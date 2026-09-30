//! Initial schema: singleton config, ACME accounts, person, machine, machine_key,
//! service, domains, certificates, cert events.

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

#[derive(DeriveIden)]
enum Domains {
    Table,
    Id,
    Name,
    LastActiveAt,
    ServiceId,
}

#[derive(DeriveIden)]
enum Certificates {
    Table,
    Id,
    DomainId,
    CertPem,
    KeyPem,
    NotBefore,
    NotAfter,
    Issuer,
    Directory,
    ObtainedAt,
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

        // 5. domains table
        manager
            .create_table(
                Table::create()
                    .table(Domains::Table)
                    .col(pk_auto(Domains::Id))
                    .col(text(Domains::Name).unique_key())
                    .col(big_integer_null(Domains::LastActiveAt))
                    .col(integer_null(Domains::ServiceId))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_domains_service_id")
                            .from(Domains::Table, Domains::ServiceId)
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
                    .name("idx_domains_service_id")
                    .table(Domains::Table)
                    .col(Domains::ServiceId)
                    .to_owned(),
            )
            .await?;

        // 6. certificates table
        manager
            .create_table(
                Table::create()
                    .table(Certificates::Table)
                    .col(pk_auto(Certificates::Id))
                    .col(integer(Certificates::DomainId))
                    .col(text(Certificates::CertPem))
                    .col(text(Certificates::KeyPem))
                    .col(big_integer(Certificates::NotBefore))
                    .col(big_integer(Certificates::NotAfter))
                    .col(text_null(Certificates::Issuer))
                    .col(text(Certificates::Directory))
                    .col(big_integer(Certificates::ObtainedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_certificates_domain_id")
                            .from(Certificates::Table, Certificates::DomainId)
                            .to(Domains::Table, Domains::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_certificates_domain_id")
                    .table(Certificates::Table)
                    .col(Certificates::DomainId)
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

        // 8. seed default PoC person ("poc"), machine ("laptop"), and dev key.
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
            .drop_table(Table::drop().table(CertEvents::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Certificates::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Domains::Table).to_owned())
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
