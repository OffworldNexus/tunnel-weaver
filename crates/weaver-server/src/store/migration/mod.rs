//! Schema migrations, tracked by `sea-orm-migration` in its own
//! `seaql_migrations` table.
//!
//! Migrations are written against the backend-agnostic schema builder so the
//! same code produces valid DDL for SQLite today and PostgreSQL later.

use sea_orm_migration::prelude::*;

mod m0001_init;
mod m0002_usage_daily;
mod m0003_inactivity;
mod m0004_auth_levels;
mod m0005_passkeys;

/// The ordered list of every migration known to this binary.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m0001_init::Migration),
            Box::new(m0002_usage_daily::Migration),
            Box::new(m0003_inactivity::Migration),
            Box::new(m0004_auth_levels::Migration),
            Box::new(m0005_passkeys::Migration),
        ]
    }
}
