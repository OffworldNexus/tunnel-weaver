//! Client migrations, tracked by `sea-orm-migration` in its own
//! `seaql_migrations` table — the same mechanism the relay's store uses.

use sea_orm_migration::prelude::*;

mod m0001_init;

/// The ordered list of every migration known to this binary.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(m0001_init::Migration)]
    }
}
