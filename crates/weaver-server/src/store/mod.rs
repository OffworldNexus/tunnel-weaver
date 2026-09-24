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

use sea_orm::sea_query::{Alias, Expr, OnConflict, Query};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection,
    DbBackend, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Set, Statement,
};
use sea_orm_migration::MigratorTrait;

pub use error::StoreError;
pub use migration::Migrator;

use crate::config::{Config, ConfigError};
use entity::{acme_account, cert_event, certificate, config, domain};

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

    // ----- certificates and domains -----

    /// Fetches an existing domain by lowercase name, or creates a new one with optional `last_active_at`.
    pub async fn get_or_create_domain(
        &self,
        name: &str,
        active_at: Option<i64>,
    ) -> Result<domain::Model, StoreError> {
        let lower = name.to_ascii_lowercase();
        if let Some(existing) = domain::Entity::find()
            .filter(domain::Column::Name.eq(&lower))
            .one(&self.db)
            .await?
        {
            if active_at.is_some() && existing.last_active_at != active_at {
                let mut active: domain::ActiveModel = existing.into();
                active.last_active_at = Set(active_at);
                let updated = active.update(&self.db).await?;
                return Ok(updated);
            }
            return Ok(existing);
        }

        let new_domain = domain::ActiveModel {
            name: Set(lower.clone()),
            last_active_at: Set(active_at),
            ..Default::default()
        };
        match new_domain.insert(&self.db).await {
            Ok(model) => Ok(model),
            Err(e) => {
                if let Some(existing) = domain::Entity::find()
                    .filter(domain::Column::Name.eq(&lower))
                    .one(&self.db)
                    .await?
                {
                    Ok(existing)
                } else {
                    Err(e.into())
                }
            }
        }
    }

    /// Fetches a domain by lowercase name.
    pub async fn get_domain(&self, name: &str) -> Result<Option<domain::Model>, StoreError> {
        let lower = name.to_ascii_lowercase();
        Ok(domain::Entity::find()
            .filter(domain::Column::Name.eq(&lower))
            .one(&self.db)
            .await?)
    }

    /// Fetches a domain by either integer ID or hostname.
    pub async fn get_domain_by_id_or_name(
        &self,
        identifier: &str,
    ) -> Result<Option<domain::Model>, StoreError> {
        if let Ok(id) = identifier.parse::<i32>()
            && let Some(d) = domain::Entity::find_by_id(id).one(&self.db).await?
        {
            return Ok(Some(d));
        }
        self.get_domain(identifier).await
    }

    /// Saves a newly issued certificate, ensuring the parent domain exists.
    pub async fn save_certificate(
        &self,
        domain_name: &str,
        cert: NewCertificate,
    ) -> Result<certificate::Model, StoreError> {
        let domain = self
            .get_or_create_domain(domain_name, cert.active_at)
            .await?;
        let active = certificate::ActiveModel {
            domain_id: Set(domain.id),
            cert_pem: Set(cert.cert_pem),
            key_pem: Set(cert.key_pem),
            not_before: Set(cert.not_before),
            not_after: Set(cert.not_after),
            issuer: Set(cert.issuer),
            directory: Set(cert.directory),
            obtained_at: Set(cert.obtained_at),
            ..Default::default()
        };
        let model = active.insert(&self.db).await?;
        Ok(model)
    }

    /// Base query joining certificates with their parent domain.
    fn certs_with_domains() -> sea_orm::SelectTwo<certificate::Entity, domain::Entity> {
        certificate::Entity::find().find_also_related(domain::Entity)
    }

    /// Query for the best certificate per domain, filtered directly in SQL.
    fn best_certs_with_domains() -> sea_orm::SelectTwo<certificate::Entity, domain::Entity> {
        let best_ids = Query::select()
            .column(Alias::new("id"))
            .from_subquery(
                Query::select()
                    .column(certificate::Column::Id)
                    .expr_as(
                        Expr::cust(
                            "ROW_NUMBER() OVER (PARTITION BY domain_id ORDER BY not_after DESC, id DESC)",
                        ),
                        Alias::new("rn"),
                    )
                    .from(certificate::Entity)
                    .to_owned(),
                Alias::new("ranked"),
            )
            .and_where(Expr::cust("ranked.rn = 1"))
            .to_owned();

        Self::certs_with_domains().filter(certificate::Column::Id.in_subquery(best_ids))
    }

    /// Fetches a specific certificate record by its certificate PK ID via a single join query.
    pub async fn get_certificate_by_id(
        &self,
        cert_id: i32,
    ) -> Result<Option<CertRecord>, StoreError> {
        let row = Self::certs_with_domains()
            .filter(certificate::Column::Id.eq(cert_id))
            .one(&self.db)
            .await?;

        Ok(row.map(|(cert, domain)| to_cert_record(cert, domain)))
    }

    /// Fetches the best certificate metadata for a domain by hostname via a single join query.
    pub async fn get_certificate(
        &self,
        domain_name: &str,
    ) -> Result<Option<CertRecord>, StoreError> {
        let lower = domain_name.to_ascii_lowercase();
        let row = Self::best_certs_with_domains()
            .filter(domain::Column::Name.eq(lower))
            .one(&self.db)
            .await?;

        Ok(row.map(|(cert, domain)| to_cert_record(cert, domain)))
    }

    /// Fetches a certificate by integer certificate ID or by domain name (best cert).
    pub async fn get_certificate_by_id_or_name(
        &self,
        identifier: &str,
    ) -> Result<Option<CertRecord>, StoreError> {
        if let Ok(id) = identifier.parse::<i32>() {
            self.get_certificate_by_id(id).await
        } else {
            self.get_certificate(identifier).await
        }
    }

    /// Counts the total number of certificates stored for a domain by ID or hostname directly in SQL.
    pub async fn count_certificates_for_domain(
        &self,
        identifier: &str,
    ) -> Result<usize, StoreError> {
        let Some(domain) = self.get_domain_by_id_or_name(identifier).await? else {
            return Ok(0);
        };
        let count = certificate::Entity::find()
            .filter(certificate::Column::DomainId.eq(domain.id))
            .count(&self.db)
            .await?;
        Ok(count as usize)
    }

    /// Fetches all certificates for a domain by ID or hostname directly via SQL.
    pub async fn get_certificates_for_domain(
        &self,
        identifier: &str,
    ) -> Result<Vec<CertRecord>, StoreError> {
        let Some(domain) = self.get_domain_by_id_or_name(identifier).await? else {
            return Ok(Vec::new());
        };
        let rows = Self::certs_with_domains()
            .filter(certificate::Column::DomainId.eq(domain.id))
            .order_by_desc(certificate::Column::NotAfter)
            .order_by_desc(certificate::Column::Id)
            .all(&self.db)
            .await?;
        Ok(rows
            .into_iter()
            .map(|(cert, domain)| to_cert_record(cert, domain))
            .collect())
    }

    /// Lists certificate records: either only the best certificate per domain or all certificates.
    pub async fn list_certificates(&self, only_best: bool) -> Result<Vec<CertRecord>, StoreError> {
        let rows = if only_best {
            Self::best_certs_with_domains().all(&self.db).await?
        } else {
            Self::certs_with_domains().all(&self.db).await?
        };

        let mut results: Vec<CertRecord> = rows
            .into_iter()
            .map(|(cert, domain)| to_cert_record(cert, domain))
            .collect();
        results.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| b.not_after.cmp(&a.not_after))
        });
        Ok(results)
    }

    /// Lists the best certificate per domain including PEM material, directly queried via SQL.
    pub async fn list_best_certificates_full(&self) -> Result<Vec<FullCertRecord>, StoreError> {
        let rows = Self::best_certs_with_domains().all(&self.db).await?;
        let mut results: Vec<FullCertRecord> = rows
            .into_iter()
            .map(|(cert, domain)| to_full_cert_record(cert, domain))
            .collect();
        results.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| b.not_after.cmp(&a.not_after))
        });
        Ok(results)
    }

    /// Lists all certificates including PEM material across all domains.
    pub async fn list_certificates_full(&self) -> Result<Vec<FullCertRecord>, StoreError> {
        self.list_best_certificates_full().await
    }

    /// Sets or clears `last_active_at` for a domain.
    pub async fn set_domain_active(
        &self,
        name: &str,
        active_at: Option<i64>,
    ) -> Result<(), StoreError> {
        let lower = name.to_ascii_lowercase();
        domain::Entity::update_many()
            .col_expr(domain::Column::LastActiveAt, Expr::value(active_at))
            .filter(domain::Column::Name.eq(lower))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    /// Legacy alias for `set_domain_active`.
    pub async fn set_cert_active(
        &self,
        name: &str,
        active_at: Option<i64>,
    ) -> Result<(), StoreError> {
        self.set_domain_active(name, active_at).await
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

/// Input data for saving a newly issued certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCertificate {
    pub cert_pem: String,
    pub key_pem: String,
    pub not_before: i64,
    pub not_after: i64,
    pub issuer: Option<String>,
    pub directory: String,
    pub obtained_at: i64,
    pub active_at: Option<i64>,
}

/// Maps a certificate model and its joined domain model into a `CertRecord`.
fn to_cert_record(cert: certificate::Model, domain: Option<domain::Model>) -> CertRecord {
    let (name, last_active_at) = match domain {
        Some(d) => (d.name, d.last_active_at),
        None => (String::new(), None),
    };
    CertRecord {
        id: cert.id,
        domain_id: cert.domain_id,
        name,
        not_before: cert.not_before,
        not_after: cert.not_after,
        issuer: cert.issuer,
        directory: cert.directory,
        obtained_at: cert.obtained_at,
        last_active_at,
    }
}

fn to_full_cert_record(cert: certificate::Model, domain: Option<domain::Model>) -> FullCertRecord {
    let (name, last_active_at) = match domain {
        Some(d) => (d.name, d.last_active_at),
        None => (String::new(), None),
    };
    FullCertRecord {
        id: cert.id,
        domain_id: cert.domain_id,
        name,
        cert_pem: cert.cert_pem,
        key_pem: cert.key_pem,
        not_before: cert.not_before,
        not_after: cert.not_after,
        issuer: cert.issuer,
        directory: cert.directory,
        obtained_at: cert.obtained_at,
        last_active_at,
    }
}

/// Certificate database record metadata joined with domain metadata (no key material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertRecord {
    pub id: i32,
    pub domain_id: i32,
    pub name: String,
    pub not_before: i64,
    pub not_after: i64,
    pub issuer: Option<String>,
    pub directory: String,
    pub obtained_at: i64,
    pub last_active_at: Option<i64>,
}

/// Full certificate record with PEM material, used for startup cache hydration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullCertRecord {
    pub id: i32,
    pub domain_id: i32,
    pub name: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub not_before: i64,
    pub not_after: i64,
    pub issuer: Option<String>,
    pub directory: String,
    pub obtained_at: i64,
    pub last_active_at: Option<i64>,
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
