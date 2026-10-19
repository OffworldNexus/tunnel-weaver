//! The client's own state, in SQLite.
//!
//! A `weave` machine keeps its device-key fingerprint and one row per relay it
//! is paired with: the admin host it dials, the machine id the relay assigned,
//! and the fingerprint authorised there, plus which relay is the default.
//!
//! The file lives in the OS data directory, or in `WEAVE_DATA_DIR` when set so
//! tests never touch real state.

pub mod entity;
pub mod migration;

use std::path::Path;

use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection,
    EntityTrait, QueryFilter, QueryOrder, Set, TransactionTrait,
};
use sea_orm_migration::MigratorTrait;

pub use entity::relay::Model as Relay;
pub use error::StoreError;

use entity::{device, relay};

use crate::host::normalize_admin_host;

mod error;

/// The client store.
#[derive(Debug)]
pub struct Store {
    db: DatabaseConnection,
}

impl Store {
    /// Opens `weave.db` in `WEAVE_DATA_DIR`, else the platform's data directory.
    pub async fn open_default() -> Result<Self, StoreError> {
        let dir = match std::env::var_os("WEAVE_DATA_DIR").filter(|d| !d.is_empty()) {
            Some(dir) => dir.into(),
            None => directories::ProjectDirs::from("dev", "offworld", "weave")
                .ok_or(StoreError::NoDataDir)?
                .data_dir()
                .to_path_buf(),
        };
        Self::open(dir.join("weave.db")).await
    }

    /// Opens (creating if needed) the SQLite database at `path`.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut opts = ConnectOptions::new(format!("sqlite://{}?mode=rwc", path.display()));
        opts.sqlx_logging(false);
        // `weave start` runs for hours while other commands read and write.
        opts.map_sqlx_sqlite_opts(|o| {
            o.journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                .busy_timeout(std::time::Duration::from_secs(5))
        });
        let db = Database::connect(opts).await?;
        migration::Migrator::up(&db, None).await?;
        Ok(Self { db })
    }

    // ----- device key -------------------------------------------------------

    /// The current device key's fingerprint; empty when none was ever opened.
    pub async fn device_key(&self) -> Result<String, StoreError> {
        Ok(device::Entity::find_by_id(device::ROW)
            .one(&self.db)
            .await?
            .map(|row| row.key_id)
            .unwrap_or_default())
    }

    /// Remembers `key_id` as the current device key.
    pub async fn set_device_key(&self, key_id: &str) -> Result<(), StoreError> {
        device::Entity::insert(device::ActiveModel {
            id: Set(device::ROW),
            key_id: Set(key_id.to_string()),
        })
        .on_conflict(
            OnConflict::column(device::Column::Id)
                .update_column(device::Column::KeyId)
                .to_owned(),
        )
        .exec(&self.db)
        .await?;
        Ok(())
    }

    // ----- relays -----------------------------------------------------------

    /// Records a successful pairing with `admin_host`.
    ///
    /// Upserts the relay's row with the machine id and key the relay approved.
    /// The relay becomes the default when there is none yet; a re-pair keeps
    /// whatever default status it had.
    pub async fn record_pairing(
        &self,
        admin_host: &str,
        machine_id: i32,
        key_id: &str,
    ) -> Result<Relay, StoreError> {
        let admin_host = normalize_admin_host(admin_host)?;
        let txn = self.db.begin().await?;
        let saved = match find_host(&txn, &admin_host).await? {
            Some(existing) => {
                let mut active: relay::ActiveModel = existing.into();
                active.machine_id = Set(machine_id);
                active.key_id = Set(key_id.to_string());
                active.update(&txn).await?
            }
            None => {
                let has_default = find_default(&txn).await?.is_some();
                relay::ActiveModel {
                    admin_host: Set(admin_host),
                    machine_id: Set(machine_id),
                    key_id: Set(key_id.to_string()),
                    is_default: Set(!has_default),
                    ..Default::default()
                }
                .insert(&txn)
                .await?
            }
        };
        txn.commit().await?;
        Ok(saved)
    }

    /// The relay paired at `admin_host`, if any.
    pub async fn relay(&self, admin_host: &str) -> Result<Option<Relay>, StoreError> {
        find_host(&self.db, &normalize_admin_host(admin_host)?).await
    }

    /// The relay used when a command is given none.
    pub async fn default_relay(&self) -> Result<Option<Relay>, StoreError> {
        find_default(&self.db).await
    }

    /// Every paired relay: the default first, then in pairing order.
    pub async fn relays(&self) -> Result<Vec<Relay>, StoreError> {
        Ok(relay::Entity::find()
            .order_by_desc(relay::Column::IsDefault)
            .order_by_asc(relay::Column::Id)
            .all(&self.db)
            .await?)
    }

    /// Makes `admin_host` the default relay. `None` when it is not paired.
    pub async fn set_default(&self, admin_host: &str) -> Result<Option<Relay>, StoreError> {
        let admin_host = normalize_admin_host(admin_host)?;
        let txn = self.db.begin().await?;
        let Some(target) = find_host(&txn, &admin_host).await? else {
            return Ok(None);
        };
        // Clear first: the partial unique index allows one default at a time,
        // statement by statement.
        relay::Entity::update_many()
            .col_expr(relay::Column::IsDefault, Expr::value(false))
            .filter(relay::Column::IsDefault.eq(true))
            .exec(&txn)
            .await?;
        let mut active: relay::ActiveModel = target.into();
        active.is_default = Set(true);
        let saved = active.update(&txn).await?;
        txn.commit().await?;
        Ok(Some(saved))
    }

    /// Forgets `admin_host`. When it was the default, the oldest remaining
    /// relay takes over and is returned.
    pub async fn forget(&self, admin_host: &str) -> Result<Option<Relay>, StoreError> {
        let admin_host = normalize_admin_host(admin_host)?;
        let txn = self.db.begin().await?;
        let Some(removed) = find_host(&txn, &admin_host).await? else {
            return Ok(None);
        };
        relay::Entity::delete_by_id(removed.id).exec(&txn).await?;
        let mut new_default = None;
        if removed.is_default
            && let Some(next) = relay::Entity::find()
                .order_by_asc(relay::Column::Id)
                .one(&txn)
                .await?
        {
            let mut active: relay::ActiveModel = next.into();
            active.is_default = Set(true);
            new_default = Some(active.update(&txn).await?);
        }
        txn.commit().await?;
        Ok(new_default)
    }
}

async fn find_host<C: ConnectionTrait>(
    db: &C,
    admin_host: &str,
) -> Result<Option<Relay>, StoreError> {
    Ok(relay::Entity::find()
        .filter(relay::Column::AdminHost.eq(admin_host))
        .one(db)
        .await?)
}

async fn find_default<C: ConnectionTrait>(db: &C) -> Result<Option<Relay>, StoreError> {
    Ok(relay::Entity::find()
        .filter(relay::Column::IsDefault.eq(true))
        .one(db)
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("weave.db")).await.unwrap();
        (dir, store)
    }

    fn hosts(relays: &[Relay]) -> Vec<(&str, bool)> {
        relays
            .iter()
            .map(|r| (r.admin_host.as_str(), r.is_default))
            .collect()
    }

    #[tokio::test]
    async fn first_pairing_becomes_the_default_and_later_ones_do_not() {
        let (_dir, store) = store().await;
        assert!(store.default_relay().await.unwrap().is_none());

        let a = store
            .record_pairing("a.example", 1, "p256:aa")
            .await
            .unwrap();
        assert!(a.is_default);
        let b = store
            .record_pairing("b.example", 2, "p256:aa")
            .await
            .unwrap();
        assert!(!b.is_default);

        assert_eq!(
            store.default_relay().await.unwrap().unwrap().admin_host,
            "a.example"
        );
        assert_eq!(
            hosts(&store.relays().await.unwrap()),
            [("a.example", true), ("b.example", false)]
        );
    }

    #[tokio::test]
    async fn repairing_updates_in_place_and_keeps_default_status() {
        let (_dir, store) = store().await;
        store
            .record_pairing("a.example", 1, "p256:aa")
            .await
            .unwrap();
        store
            .record_pairing("b.example", 2, "p256:aa")
            .await
            .unwrap();

        let b = store
            .record_pairing("B.Example.", 9, "p256:bb")
            .await
            .unwrap();
        assert_eq!(b.admin_host, "b.example");
        assert_eq!((b.machine_id, b.key_id.as_str()), (9, "p256:bb"));
        assert!(!b.is_default);
        assert_eq!(store.relays().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn set_default_moves_the_single_default() {
        let (_dir, store) = store().await;
        store
            .record_pairing("a.example", 1, "p256:aa")
            .await
            .unwrap();
        store
            .record_pairing("b.example", 2, "p256:aa")
            .await
            .unwrap();
        store
            .record_pairing("c.example", 3, "p256:aa")
            .await
            .unwrap();

        let c = store.set_default("C.EXAMPLE").await.unwrap().unwrap();
        assert!(c.is_default);
        assert_eq!(
            hosts(&store.relays().await.unwrap()),
            [
                ("c.example", true),
                ("a.example", false),
                ("b.example", false)
            ]
        );
        // Idempotent.
        store.set_default("c.example").await.unwrap().unwrap();
        assert!(store.set_default("nope.example").await.unwrap().is_none());
        assert_eq!(
            store.default_relay().await.unwrap().unwrap().admin_host,
            "c.example"
        );
    }

    #[tokio::test]
    async fn forgetting_the_default_promotes_the_oldest_remaining() {
        let (_dir, store) = store().await;
        for (host, machine) in [("a.example", 1), ("b.example", 2), ("c.example", 3)] {
            store
                .record_pairing(host, machine, "p256:aa")
                .await
                .unwrap();
        }
        store.set_default("b.example").await.unwrap();

        let promoted = store.forget("b.example").await.unwrap();
        assert_eq!(promoted.unwrap().admin_host, "a.example");
        assert_eq!(
            hosts(&store.relays().await.unwrap()),
            [("a.example", true), ("c.example", false)]
        );

        // Forgetting a non-default leaves the default alone.
        assert!(store.forget("c.example").await.unwrap().is_none());
        assert_eq!(
            store.default_relay().await.unwrap().unwrap().admin_host,
            "a.example"
        );

        assert!(store.forget("a.example").await.unwrap().is_none());
        assert!(store.default_relay().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn the_device_key_is_one_row() {
        let (_dir, store) = store().await;
        assert_eq!(store.device_key().await.unwrap(), "");
        store.set_device_key("p256:aa").await.unwrap();
        store.set_device_key("p256:bb").await.unwrap();
        assert_eq!(store.device_key().await.unwrap(), "p256:bb");
    }

    #[tokio::test]
    async fn the_index_refuses_a_second_default() {
        let (_dir, store) = store().await;
        store
            .record_pairing("a.example", 1, "p256:aa")
            .await
            .unwrap();
        let second = relay::ActiveModel {
            admin_host: Set("b.example".into()),
            machine_id: Set(2),
            key_id: Set("p256:aa".into()),
            is_default: Set(true),
            ..Default::default()
        }
        .insert(&store.db)
        .await;
        assert!(second.is_err(), "two defaults were accepted");
    }

    #[tokio::test]
    async fn lookups_normalise_the_host() {
        let (_dir, store) = store().await;
        store
            .record_pairing("Weaver1.Offworld.Nexus.:443", 7, "p256:aa")
            .await
            .unwrap();
        let found = store
            .relay("weaver1.offworld.nexus")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.admin_host, "weaver1.offworld.nexus");
        assert!(
            store
                .relay("WEAVER1.offworld.nexus")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .relay("weaver1.offworld.nexus:8443")
                .await
                .unwrap()
                .is_none()
        );
    }
}
