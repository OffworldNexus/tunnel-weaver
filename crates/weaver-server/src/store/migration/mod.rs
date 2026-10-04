//! Schema migrations, tracked by `sea-orm-migration` in its own
//! `seaql_migrations` table.
//!
//! Migrations are written against the backend-agnostic schema builder so the
//! same code produces valid DDL for SQLite today and PostgreSQL later.
//! Migrations are forward-only in practice: `down` is implemented for
//! completeness but never invoked by the server.

use sea_orm_migration::prelude::*;

mod m0001_init;

/// The ordered list of every migration known to this binary.
///
/// There has been no release, so the schema is described by this single initial
/// migration; the former incremental `m0002`–`m0004` have been folded into it.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(m0001_init::Migration)]
    }
}
