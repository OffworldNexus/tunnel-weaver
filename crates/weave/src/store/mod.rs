//! The client's own state, in SQLite.
//!
//! A `weave` machine keeps one row per relay it is paired with: the admin host
//! it dials, the machine id the relay assigned, and the device-key fingerprint
//! authorised there — plus which relay is the default. It is deliberately
//! ignorant of everything the relay owns (names, hostnames, the tunnel root),
//! because the relay is the authority for those and reports them when asked.
//!
//! Where the file lives is a platform question, not a Unix one: the OS data
//! directory on every platform (`directories`), overridable with
//! `WEAVE_DATA_DIR` so tests and embedding never touch real state.

pub mod entity;
pub mod migration;

use std::path::{Path, PathBuf};

use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection,
    EntityTrait, QueryFilter, QueryOrder, Set, TransactionTrait,
};
use sea_orm_migration::MigratorTrait;

pub use entity::relay::Model as Relay;
pub use error::StoreError;

use entity::relay;

use crate::host::normalize_admin_host;

mod error;

/// How many pooled connections the client keeps. It is a single-user process;
/// two is enough for a concurrent read while a write is in flight.
const MAX_CONNECTIONS: u32 = 2;

/// How long SQLite waits for a competing writer before giving up.
const SQLITE_BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The directory holding the client's database.
///
/// `WEAVE_DATA_DIR` wins when set (tests, embedding); otherwise the platform's
/// per-user data directory.
pub fn data_dir() -> Result<PathBuf, StoreError> {
    if let Some(dir) = std::env::var_os("WEAVE_DATA_DIR")
        && !dir.is_empty()
    {
        return Ok(PathBuf::from(dir));
    }
    directories::ProjectDirs::from("dev", "offworld", "weave")
        .map(|dirs| dirs.data_dir().to_path_buf())
        .ok_or(StoreError::NoDataDir)
}

/// The default database path: `<data dir>/weave.db`.
pub fn default_path() -> Result<PathBuf, StoreError> {
    Ok(data_dir()?.join("weave.db"))
}

/// The client store.
pub struct Store {
    url: String,
    /// Filesystem location when the backend is a file-based SQLite database.
    path: Option<PathBuf>,
    db: DatabaseConnection,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Opens the database in the platform's data directory.
    pub async fn open_default() -> Result<Self, StoreError> {
        Self::open(default_path()?).await
    }

    /// Opens (creating if needed) the SQLite database file at `path`.
    ///
    /// Creates parent directories with mode 0700 and forces the file to 0600 on
    /// Unix: the store records which machine this is on each relay, and which
    /// key is authorised there.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();

        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = std::fs::DirBuilder::new();
                builder.recursive(true);
                builder.mode(0o700);
                builder.create(parent)?;
            }
            #[cfg(not(unix))]
            {
                std::fs::create_dir_all(parent)?;
            }
        }

        let path_str = path
            .to_str()
            .ok_or_else(|| StoreError::InvalidPath("database path is not valid UTF-8".into()))?;
        let url = format!("sqlite://{path_str}?mode=rwc");

        let store = Self::connect(&url).await?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(&path)?;
            let mut perms = metadata.permissions();
            if perms.mode() & 0o777 != 0o600 {
                perms.set_mode(0o600);
                std::fs::set_permissions(&path, perms)?;
            }
        }

        Ok(Self {
            path: Some(path),
            ..store
        })
    }

    /// Connects to a database URL and runs pending migrations.
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        let mut opts = ConnectOptions::new(url);
        opts.max_connections(MAX_CONNECTIONS).sqlx_logging(false);

        // Pragmas are per pooled connection, so they belong to the sqlx options
        // rather than a one-off statement after connect.
        opts.map_sqlx_sqlite_opts(|o| {
            use sqlx::sqlite::{SqliteJournalMode, SqliteSynchronous};
            o.journal_mode(SqliteJournalMode::Wal)
                .synchronous(SqliteSynchronous::Normal)
                .foreign_keys(true)
                .busy_timeout(SQLITE_BUSY_TIMEOUT)
                .pragma("wal_autocheckpoint", "1000")
                .pragma("temp_store", "MEMORY")
        });

        let db = Database::connect(opts).await?;
        migration::Migrator::up(&db, None).await?;

        Ok(Self {
            url: url.to_string(),
            path: None,
            db,
        })
    }

    /// The database file, when the backend is file-based SQLite.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// The connection URL the store was opened with.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The underlying connection (tests, seeding).
    pub fn db(&self) -> &DatabaseConnection {
        &self.db
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
        let admin_host = normalize(admin_host)?;
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
        let Ok(admin_host) = normalize(admin_host) else {
            return Ok(None);
        };
        find_host(&self.db, &admin_host).await
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
        let Ok(admin_host) = normalize(admin_host) else {
            return Ok(None);
        };
        let txn = self.db.begin().await?;
        let Some(target) = find_host(&txn, &admin_host).await? else {
            return Ok(None);
        };
        // Clear first: the partial unique index allows one default at a time,
        // statement by statement.
        clear_default(&txn).await?;
        let mut active: relay::ActiveModel = target.into();
        active.is_default = Set(true);
        let saved = active.update(&txn).await?;
        txn.commit().await?;
        Ok(Some(saved))
    }

    /// Forgets `admin_host`. When it was the default, the oldest remaining
    /// relay takes over. `None` when it was not paired.
    pub async fn forget(&self, admin_host: &str) -> Result<Option<Forgotten>, StoreError> {
        let Ok(admin_host) = normalize(admin_host) else {
            return Ok(None);
        };
        let txn = self.db.begin().await?;
        let Some(removed) = find_host(&txn, &admin_host).await? else {
            return Ok(None);
        };
        relay::Entity::delete_by_id(removed.id).exec(&txn).await?;
        let new_default = if removed.is_default {
            match relay::Entity::find()
                .order_by_asc(relay::Column::Id)
                .one(&txn)
                .await?
            {
                Some(next) => {
                    let mut active: relay::ActiveModel = next.into();
                    active.is_default = Set(true);
                    Some(active.update(&txn).await?)
                }
                None => None,
            }
        } else {
            None
        };
        txn.commit().await?;
        Ok(Some(Forgotten {
            relay: removed,
            new_default,
        }))
    }

    /// Every distinct key fingerprint recorded, the default relay's first.
    ///
    /// All relays share the one device key in the key agent, so any of these
    /// may be the one it still holds.
    pub async fn key_ids(&self) -> Result<Vec<String>, StoreError> {
        let mut out: Vec<String> = Vec::new();
        for relay in self.relays().await? {
            if !out.contains(&relay.key_id) {
                out.push(relay.key_id);
            }
        }
        Ok(out)
    }
}

/// What [`Store::forget`] removed, and who became the default instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forgotten {
    /// The row that was deleted.
    pub relay: Relay,
    /// The relay promoted to default, when the forgotten one was the default
    /// and another remains.
    pub new_default: Option<Relay>,
}

fn normalize(admin_host: &str) -> Result<String, StoreError> {
    normalize_admin_host(admin_host).map_err(|e| StoreError::InvalidHost(e.to_string()))
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

async fn clear_default<C: ConnectionTrait>(db: &C) -> Result<(), StoreError> {
    relay::Entity::update_many()
        .col_expr(relay::Column::IsDefault, Expr::value(false))
        .filter(relay::Column::IsDefault.eq(true))
        .exec(db)
        .await?;
    Ok(())
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
        store.set_default("b.example").await.unwrap();

        let gone = store.forget("b.example").await.unwrap().unwrap();
        assert_eq!(gone.relay.admin_host, "b.example");
        assert_eq!(gone.new_default.unwrap().admin_host, "a.example");
        assert_eq!(
            hosts(&store.relays().await.unwrap()),
            [("a.example", true), ("c.example", false)]
        );

        // Forgetting a non-default leaves the default alone.
        let gone = store.forget("c.example").await.unwrap().unwrap();
        assert!(gone.new_default.is_none());
        assert_eq!(
            store.default_relay().await.unwrap().unwrap().admin_host,
            "a.example"
        );

        let gone = store.forget("a.example").await.unwrap().unwrap();
        assert!(gone.new_default.is_none());
        assert!(store.default_relay().await.unwrap().is_none());
        assert!(store.forget("a.example").await.unwrap().is_none());
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
        .insert(store.db())
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

    #[tokio::test]
    async fn key_ids_are_distinct_default_first() {
        let (_dir, store) = store().await;
        store
            .record_pairing("a.example", 1, "p256:aa")
            .await
            .unwrap();
        store
            .record_pairing("b.example", 2, "p256:bb")
            .await
            .unwrap();
        store
            .record_pairing("c.example", 3, "p256:aa")
            .await
            .unwrap();
        store.set_default("b.example").await.unwrap();
        assert_eq!(store.key_ids().await.unwrap(), ["p256:bb", "p256:aa"]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn database_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/weave.db");
        let _store = Store::open(&path).await.unwrap();
        let file = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let parent = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!((file, parent), (0o600, 0o700));
    }
}
