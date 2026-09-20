//! Persistent state store built on SeaORM.
//!
//! The store is backend-agnostic by construction: every query goes through
//! SeaORM entities or the `sea-query` builder, and the connection is opened
//! from a URL. Today only SQLite is compiled in; enabling PostgreSQL is a
//! matter of adding the `sqlx-postgres` feature and passing a `postgres://`
//! URL to [`Store::connect`]. The handful of SQLite-only niceties (pragmas,
//! file permissions, `VACUUM INTO` backups) are gated on the detected backend.

pub mod entity;
pub mod error;
pub mod migration;

use std::path::{Path, PathBuf};
use std::time::Duration;

use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection,
    DbBackend, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set, Statement,
};
use sea_orm_migration::MigratorTrait;

pub use error::StoreError;
pub use migration::Migrator;

use crate::config::{Config, ConfigError};
use entity::{acme_account, cert_event, certificate, config};

/// Upper bound on pooled connections. SQLite serializes writers anyway; a
/// small pool lets concurrent readers proceed without contention.
const MAX_CONNECTIONS: u32 = 5;

/// How long a connection waits on a locked SQLite database before failing.
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Handle to the state database. Cheap to clone; all clones share one pool.
#[derive(Clone)]
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

/// Current Unix time in seconds, used for `updated_at`/`created_at` stamps.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl Store {
    /// Opens (creating if needed) the SQLite database file at `path`.
    ///
    /// Creates parent directories with mode 0700 and forces the file to 0600
    /// on Unix, since the store holds private keys. Runs pending migrations.
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

    /// Connects to any database URL SeaORM understands and runs pending migrations.
    ///
    /// This is the backend-agnostic entry point; [`Store::open`] is a thin
    /// SQLite-file convenience over it.
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        let mut opts = ConnectOptions::new(url);
        opts.max_connections(MAX_CONNECTIONS).sqlx_logging(false);

        // Pragmas must be applied per pooled connection, hence at the sqlx
        // options level rather than as a one-off statement after connect.
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
        Migrator::up(&db, None).await?;

        Ok(Self {
            url: url.to_string(),
            path: None,
            db,
        })
    }

    /// Returns the path to the database file, if the backend is file-based SQLite.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Returns the connection URL the store was opened with.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Returns the underlying connection for ad-hoc queries (tests, seeding).
    pub fn db(&self) -> &DatabaseConnection {
        &self.db
    }

    fn backend(&self) -> DbBackend {
        self.db.get_database_backend()
    }

    /// Writes `config_json` into the singleton config row, creating or replacing it.
    async fn write_config_json(&self, json_str: String) -> Result<(), StoreError> {
        let model = config::ActiveModel {
            id: Set(config::SINGLETON_ID),
            config_json: Set(json_str),
            updated_at: Set(now_unix()),
        };
        config::Entity::insert(model)
            .on_conflict(
                OnConflict::column(config::Column::Id)
                    .update_columns([config::Column::ConfigJson, config::Column::UpdatedAt])
                    .to_owned(),
            )
            .exec_without_returning(&self.db)
            .await?;
        Ok(())
    }

    /// Reads the raw configuration JSON, if any has been saved.
    pub async fn load_config_json(&self) -> Result<Option<String>, StoreError> {
        let row = config::Entity::find_by_id(config::SINGLETON_ID)
            .one(&self.db)
            .await?;
        Ok(row.map(|r| r.config_json))
    }

    /// Saves the full configuration struct as JSON into the database.
    pub async fn save_config(&self, config: &Config) -> Result<(), StoreError> {
        let json_str = serde_json::to_string(config)
            .map_err(|e| ConfigError::DeserializationFailed(e.to_string()))?;
        self.write_config_json(json_str).await
    }

    /// Updates or inserts an individual configuration field into the JSON configuration object.
    pub async fn set_config(&self, key: &str, value: &str) -> Result<(), StoreError> {
        let mut obj: serde_json::Map<String, serde_json::Value> = self
            .load_config_json()
            .await?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        let json_val =
            serde_json::from_str(value).unwrap_or(serde_json::Value::String(value.to_string()));
        obj.insert(key.to_string(), json_val);

        let json_str = serde_json::to_string(&obj)
            .map_err(|e| ConfigError::DeserializationFailed(e.to_string()))?;
        self.write_config_json(json_str).await
    }

    /// Loads and validates the configuration from the database.
    pub async fn load_config(&self) -> Result<Config, ConfigError> {
        Config::load(self).await
    }

    /// Performs an online backup of the database to `dest`.
    ///
    /// Implemented via `VACUUM INTO`, which only exists on SQLite; other
    /// backends return [`StoreError::UnsupportedBackend`].
    pub async fn backup(&self, dest: impl AsRef<Path>) -> Result<(), StoreError> {
        let backend = self.backend();
        if backend != DbBackend::Sqlite {
            return Err(StoreError::UnsupportedBackend("backup", backend));
        }
        let dest_str = dest
            .as_ref()
            .to_str()
            .ok_or_else(|| StoreError::InvalidPath("destination path is not valid UTF-8".into()))?;
        self.db
            .execute_raw(Statement::from_sql_and_values(
                backend,
                "VACUUM INTO ?",
                [dest_str.into()],
            ))
            .await?;
        Ok(())
    }

    /// Closes the pool, first letting SQLite refresh its planner statistics.
    pub async fn close(self) -> Result<(), StoreError> {
        if self.backend() == DbBackend::Sqlite {
            self.db.execute_unprepared("PRAGMA optimize;").await?;
        }
        self.db.close().await?;
        Ok(())
    }

    /// Returns the number of schema migrations applied to the database.
    pub async fn schema_version(&self) -> Result<u32, StoreError> {
        let applied = Migrator::get_applied_migrations(&self.db).await?;
        Ok(applied.len() as u32)
    }

    // ----- certificates -----

    /// Fetches the metadata record for a certificate by hostname.
    pub async fn get_certificate(&self, name: &str) -> Result<Option<CertRecord>, StoreError> {
        let row = certificate::Entity::find_by_id(name.to_ascii_lowercase())
            .one(&self.db)
            .await?;
        Ok(row.map(CertRecord::from))
    }

    /// Lists all certificate records (without key material) ordered by name.
    pub async fn list_certificates(&self) -> Result<Vec<CertRecord>, StoreError> {
        let rows = self.list_certificates_full().await?;
        Ok(rows.into_iter().map(CertRecord::from).collect())
    }

    /// Lists all certificates including PEM material, ordered by name.
    ///
    /// Used at startup to repopulate the in-memory TLS resolver.
    pub async fn list_certificates_full(&self) -> Result<Vec<certificate::Model>, StoreError> {
        Ok(certificate::Entity::find()
            .order_by_asc(certificate::Column::Name)
            .all(&self.db)
            .await?)
    }

    /// Inserts or replaces a certificate row keyed by hostname.
    pub async fn upsert_certificate(&self, cert: certificate::Model) -> Result<(), StoreError> {
        let active: certificate::ActiveModel = cert.into();
        certificate::Entity::insert(active)
            .on_conflict(
                OnConflict::column(certificate::Column::Name)
                    .update_columns([
                        certificate::Column::CertPem,
                        certificate::Column::KeyPem,
                        certificate::Column::NotBefore,
                        certificate::Column::NotAfter,
                        certificate::Column::Issuer,
                        certificate::Column::Directory,
                        certificate::Column::ObtainedAt,
                        certificate::Column::LastActiveAt,
                    ])
                    .to_owned(),
            )
            .exec_without_returning(&self.db)
            .await?;
        Ok(())
    }

    /// Sets or clears `last_active_at` for a hostname's certificate.
    pub async fn set_cert_active(
        &self,
        name: &str,
        active_at: Option<i64>,
    ) -> Result<(), StoreError> {
        certificate::Entity::update_many()
            .col_expr(certificate::Column::LastActiveAt, Expr::value(active_at))
            .filter(certificate::Column::Name.eq(name.to_ascii_lowercase()))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    // ----- certificate events -----

    /// Appends a certificate lifecycle event.
    pub async fn record_cert_event(
        &self,
        name: &str,
        at: i64,
        kind: &str,
        detail: Option<&str>,
    ) -> Result<(), StoreError> {
        cert_event::ActiveModel {
            name: Set(name.to_string()),
            at: Set(at),
            kind: Set(kind.to_string()),
            detail: Set(detail.map(str::to_string)),
            ..Default::default()
        }
        .insert(&self.db)
        .await?;
        Ok(())
    }

    /// Fetches the most recent `limit` lifecycle events for a given hostname.
    pub async fn get_cert_events(
        &self,
        name: &str,
        limit: usize,
    ) -> Result<Vec<CertEventRecord>, StoreError> {
        let rows = cert_event::Entity::find()
            .filter(cert_event::Column::Name.eq(name.to_ascii_lowercase()))
            .order_by_desc(cert_event::Column::At)
            .order_by_desc(cert_event::Column::Id)
            .limit(limit as u64)
            .all(&self.db)
            .await?;
        Ok(rows.into_iter().map(CertEventRecord::from).collect())
    }

    /// Fetches the single most recent lifecycle event for a given hostname.
    pub async fn get_latest_cert_event(
        &self,
        name: &str,
    ) -> Result<Option<CertEventRecord>, StoreError> {
        let events = self.get_cert_events(name, 1).await?;
        Ok(events.into_iter().next())
    }

    // ----- ACME accounts -----

    /// Fetches the stored ACME account for a directory URL.
    pub async fn get_acme_account(
        &self,
        directory: &str,
    ) -> Result<Option<acme_account::Model>, StoreError> {
        Ok(acme_account::Entity::find_by_id(directory.to_string())
            .one(&self.db)
            .await?)
    }

    /// Inserts or replaces the ACME account registered against `directory`.
    pub async fn upsert_acme_account(
        &self,
        directory: &str,
        email: &str,
        credentials_json: &str,
        kid: Option<&str>,
        created_at: i64,
    ) -> Result<(), StoreError> {
        let model = acme_account::ActiveModel {
            directory: Set(directory.to_string()),
            email: Set(email.to_string()),
            credentials_json: Set(credentials_json.to_string()),
            kid: Set(kid.map(str::to_string)),
            created_at: Set(created_at),
        };
        acme_account::Entity::insert(model)
            .on_conflict(
                OnConflict::column(acme_account::Column::Directory)
                    .update_columns([
                        acme_account::Column::Email,
                        acme_account::Column::CredentialsJson,
                        acme_account::Column::Kid,
                        acme_account::Column::CreatedAt,
                    ])
                    .to_owned(),
            )
            .exec_without_returning(&self.db)
            .await?;
        Ok(())
    }
}

/// Certificate database record metadata (no key material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertRecord {
    pub name: String,
    pub not_before: i64,
    pub not_after: i64,
    pub issuer: Option<String>,
    pub directory: String,
    pub obtained_at: i64,
    pub last_active_at: Option<i64>,
}

impl From<certificate::Model> for CertRecord {
    fn from(m: certificate::Model) -> Self {
        Self {
            name: m.name,
            not_before: m.not_before,
            not_after: m.not_after,
            issuer: m.issuer,
            directory: m.directory,
            obtained_at: m.obtained_at,
            last_active_at: m.last_active_at,
        }
    }
}

/// Certificate event database record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertEventRecord {
    pub id: i64,
    pub name: String,
    pub at: i64,
    pub kind: String,
    pub detail: Option<String>,
}

impl From<cert_event::Model> for CertEventRecord {
    fn from(m: cert_event::Model) -> Self {
        Self {
            id: m.id,
            name: m.name,
            at: m.at,
            kind: m.kind,
            detail: m.detail,
        }
    }
}
