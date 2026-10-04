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
pub mod names;
pub mod usage;

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
use entity::{
    acme_account, cert_event, certificate, challenge, config, domain, machine, machine_key, person,
    service,
};
use weaver_mux::KeyId;

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
            updated_at: Set(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64),
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

    /// Inserts or replaces the certificate stored under `name`.
    ///
    /// A certificate is global and keyed by its own name (the tunnel apex or
    /// the admin domain); a renewal swaps the material in place rather than
    /// appending a row, so at most one row per name exists.
    pub async fn save_certificate(
        &self,
        name: &str,
        cert: NewCertificate,
    ) -> Result<certificate::Model, StoreError> {
        let lower = name.to_ascii_lowercase();
        let active = certificate::ActiveModel {
            name: Set(lower.clone()),
            cert_pem: Set(cert.cert_pem),
            key_pem: Set(cert.key_pem),
            not_before: Set(cert.not_before),
            not_after: Set(cert.not_after),
            issuer: Set(cert.issuer),
            directory: Set(cert.directory),
            obtained_at: Set(cert.obtained_at),
            validation: Set(cert.validation),
            wildcard: Set(cert.wildcard),
            ..Default::default()
        };
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
                        certificate::Column::Validation,
                        certificate::Column::Wildcard,
                    ])
                    .to_owned(),
            )
            .exec_without_returning(&self.db)
            .await?;

        certificate::Entity::find()
            .filter(certificate::Column::Name.eq(lower))
            .one(&self.db)
            .await?
            .ok_or_else(|| {
                sea_orm::DbErr::RecordNotFound("certificate row missing after upsert".into()).into()
            })
    }

    /// Fetches a certificate record by its certificate PK ID.
    pub async fn get_certificate_by_id(
        &self,
        cert_id: i32,
    ) -> Result<Option<CertRecord>, StoreError> {
        let row = certificate::Entity::find_by_id(cert_id)
            .one(&self.db)
            .await?;
        Ok(row.map(to_cert_record))
    }

    /// Fetches the certificate stored under `name` (the root domain in the
    /// wildcard model).
    pub async fn get_certificate(
        &self,
        domain_name: &str,
    ) -> Result<Option<CertRecord>, StoreError> {
        let lower = domain_name.to_ascii_lowercase();
        let row = certificate::Entity::find()
            .filter(certificate::Column::Name.eq(lower))
            .one(&self.db)
            .await?;
        Ok(row.map(to_cert_record))
    }

    /// Fetches a certificate by integer certificate ID or by name.
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

    /// Lists certificate records in name order.
    ///
    /// There is exactly one row per name, so there is nothing to rank or filter.
    pub async fn list_certificates(&self) -> Result<Vec<CertRecord>, StoreError> {
        let mut results: Vec<CertRecord> = certificate::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(to_cert_record)
            .collect();
        results.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| b.not_after.cmp(&a.not_after))
        });
        Ok(results)
    }

    /// Lists every certificate including PEM material, in name order.
    pub async fn list_certificates_full(&self) -> Result<Vec<FullCertRecord>, StoreError> {
        let mut results: Vec<FullCertRecord> = certificate::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(to_full_cert_record)
            .collect();
        results.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| b.not_after.cmp(&a.not_after))
        });
        Ok(results)
    }

    /// Points a materialized domain at the certificate that covers it.
    ///
    /// In the wildcard model every domain points at the single apex
    /// certificate, which is what keeps the routing join to one hop.
    pub async fn set_domain_certificate(
        &self,
        domain_name: &str,
        certificate_id: i32,
    ) -> Result<(), StoreError> {
        let lower = domain_name.to_ascii_lowercase();
        domain::Entity::update_many()
            .col_expr(
                domain::Column::CertificateId,
                Expr::value(Some(certificate_id)),
            )
            .filter(domain::Column::Name.eq(lower))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    // ----- ACME challenge registry (DNS-01 TXT + HTTP-01 tokens) -----

    /// Publishes one DNS-01 TXT value for `name`, ignoring duplicates.
    ///
    /// A DNS-01 challenge name maps to a *set* of values: the apex and the
    /// wildcard authorisations of a single order share
    /// `_acme-challenge.<root>` and must both be answerable at once.
    pub async fn publish_challenge(
        &self,
        name: &str,
        value: &str,
        at: i64,
    ) -> Result<(), StoreError> {
        let lower = name.to_ascii_lowercase();
        let active = challenge::ActiveModel {
            name: Set(lower),
            value: Set(value.to_string()),
            created_at: Set(at),
            kind: Set("dns-01".to_string()),
            ..Default::default()
        };
        challenge::Entity::insert(active)
            .on_conflict(
                OnConflict::columns([challenge::Column::Name, challenge::Column::Value])
                    .do_nothing()
                    .to_owned(),
            )
            .exec_without_returning(&self.db)
            .await?;
        Ok(())
    }

    /// Removes one DNS-01 TXT value for `name`.
    pub async fn remove_challenge(&self, name: &str, value: &str) -> Result<(), StoreError> {
        let lower = name.to_ascii_lowercase();
        challenge::Entity::delete_many()
            .filter(challenge::Column::Name.eq(lower))
            .filter(challenge::Column::Value.eq(value))
            .filter(challenge::Column::Kind.eq("dns-01"))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    /// Removes every DNS-01 TXT value for `name`.
    pub async fn clear_challenges(&self, name: &str) -> Result<(), StoreError> {
        let lower = name.to_ascii_lowercase();
        challenge::Entity::delete_many()
            .filter(challenge::Column::Name.eq(lower))
            .filter(challenge::Column::Kind.eq("dns-01"))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    /// Returns the current DNS-01 TXT values for `name`, oldest first.
    ///
    /// HTTP-01 token rows are never returned, whatever they are named, so the
    /// authoritative responder cannot leak a key authorization as TXT.
    pub async fn get_challenges(&self, name: &str) -> Result<Vec<String>, StoreError> {
        let lower = name.to_ascii_lowercase();
        let rows = challenge::Entity::find()
            .filter(challenge::Column::Name.eq(lower))
            .filter(challenge::Column::Kind.eq("dns-01"))
            .order_by_asc(challenge::Column::Id)
            .all(&self.db)
            .await?;
        Ok(rows.into_iter().map(|r| r.value).collect())
    }

    /// Publishes the HTTP-01 key authorization for an ACME token.
    ///
    /// The token is a case-sensitive path segment, so unlike DNS names it is
    /// stored verbatim. Any previous row for the same token is removed first so
    /// a re-published challenge never serves a stale key authorization.
    pub async fn publish_http01(
        &self,
        token: &str,
        key_auth: &str,
        at: i64,
    ) -> Result<(), StoreError> {
        challenge::Entity::delete_many()
            .filter(challenge::Column::Name.eq(token))
            .filter(challenge::Column::Kind.eq("http-01"))
            .exec(&self.db)
            .await?;
        let active = challenge::ActiveModel {
            name: Set(token.to_string()),
            value: Set(key_auth.to_string()),
            created_at: Set(at),
            kind: Set("http-01".to_string()),
            ..Default::default()
        };
        active.insert(&self.db).await?;
        Ok(())
    }

    /// Returns the HTTP-01 key authorization for `token`, if one is published.
    pub async fn get_http01(&self, token: &str) -> Result<Option<String>, StoreError> {
        let row = challenge::Entity::find()
            .filter(challenge::Column::Name.eq(token))
            .filter(challenge::Column::Kind.eq("http-01"))
            .order_by_desc(challenge::Column::Id)
            .one(&self.db)
            .await?;
        Ok(row.map(|r| r.value))
    }

    /// Removes the HTTP-01 key authorization for `token`.
    pub async fn remove_http01(&self, token: &str) -> Result<(), StoreError> {
        challenge::Entity::delete_many()
            .filter(challenge::Column::Name.eq(token))
            .filter(challenge::Column::Kind.eq("http-01"))
            .exec(&self.db)
            .await?;
        Ok(())
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

    // ----- auth: person, machine, machine_key, service -----

    /// Explicitly creates a new person. Returns an error if the name already exists.
    pub async fn create_person(&self, name: &str) -> Result<person::Model, StoreError> {
        let lower = name.to_ascii_lowercase();
        if !names::is_valid_person_or_machine(&lower) {
            return Err(StoreError::InvalidName(format!(
                "person '{name}' must match ^[a-z0-9]{{1,15}}$"
            )));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let new_person = person::ActiveModel {
            name: Set(lower),
            created_at: Set(now),
            ..Default::default()
        };
        Ok(new_person.insert(&self.db).await?)
    }

    /// Fetches a person by lowercase name.
    pub async fn get_person_by_name(
        &self,
        name: &str,
    ) -> Result<Option<person::Model>, StoreError> {
        let lower = name.to_ascii_lowercase();
        Ok(person::Entity::find()
            .filter(person::Column::Name.eq(&lower))
            .one(&self.db)
            .await?)
    }

    /// Explicitly creates a new machine under a person. Returns an error if the machine name already exists for that person.
    pub async fn create_machine(
        &self,
        person_id: i32,
        name: &str,
    ) -> Result<machine::Model, StoreError> {
        let lower = name.to_ascii_lowercase();
        if !names::is_valid_person_or_machine(&lower) {
            return Err(StoreError::InvalidName(format!(
                "machine '{name}' must match ^[a-z0-9]{{1,15}}$"
            )));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let new_machine = machine::ActiveModel {
            person_id: Set(person_id),
            name: Set(lower),
            created_at: Set(now),
            ..Default::default()
        };
        Ok(new_machine.insert(&self.db).await?)
    }

    /// Fetches a machine by person ID and lowercase name.
    pub async fn get_machine_by_name(
        &self,
        person_id: i32,
        name: &str,
    ) -> Result<Option<machine::Model>, StoreError> {
        let lower = name.to_ascii_lowercase();
        Ok(machine::Entity::find()
            .filter(machine::Column::PersonId.eq(person_id))
            .filter(machine::Column::Name.eq(&lower))
            .one(&self.db)
            .await?)
    }

    /// Associates an authorized public key identifier with a machine.
    ///
    /// Keys are only ever enrolled explicitly — there is no implicit
    /// creation at authentication time, so a duplicate `key_id` is an error.
    pub async fn add_machine_key(
        &self,
        machine_id: i32,
        key_id: &KeyId,
    ) -> Result<machine_key::Model, StoreError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let new_key = machine_key::ActiveModel {
            machine_id: Set(machine_id),
            key_id: Set(format_key_id(key_id)),
            created_at: Set(now),
            ..Default::default()
        };
        Ok(new_key.insert(&self.db).await?)
    }

    /// Resolves an incoming `KeyId` to its registered `(person, machine, machine_key)` tuple.
    pub async fn resolve_key(
        &self,
        key_id: &KeyId,
    ) -> Result<Option<(person::Model, machine::Model, machine_key::Model)>, StoreError> {
        let key_str = format_key_id(key_id);
        let Some((mkey, Some(mach))) = machine_key::Entity::find()
            .filter(machine_key::Column::KeyId.eq(&key_str))
            .find_also_related(machine::Entity)
            .one(&self.db)
            .await?
        else {
            return Ok(None);
        };

        let Some(pers) = person::Entity::find_by_id(mach.person_id)
            .one(&self.db)
            .await?
        else {
            return Ok(None);
        };

        Ok(Some((pers, mach, mkey)))
    }

    /// Fetches an existing service by machine ID and lowercase name, or creates a new one.
    pub async fn get_or_create_service(
        &self,
        machine_id: i32,
        name: &str,
    ) -> Result<service::Model, StoreError> {
        let lower = name.to_ascii_lowercase();
        if !names::is_valid_service(&lower) {
            return Err(StoreError::InvalidName(format!(
                "service '{name}' must match ^[a-z0-9]+(?:-[a-z0-9]+)*$ and be 1-31 chars"
            )));
        }
        if let Some(existing) = service::Entity::find()
            .filter(service::Column::MachineId.eq(machine_id))
            .filter(service::Column::Name.eq(&lower))
            .one(&self.db)
            .await?
        {
            return Ok(existing);
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let new_service = service::ActiveModel {
            machine_id: Set(machine_id),
            name: Set(lower.clone()),
            created_at: Set(now),
            ..Default::default()
        };
        match new_service.insert(&self.db).await {
            Ok(model) => Ok(model),
            Err(e) => {
                if let Some(existing) = service::Entity::find()
                    .filter(service::Column::MachineId.eq(machine_id))
                    .filter(service::Column::Name.eq(&lower))
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

    /// Sets or updates the service linked to a domain.
    pub async fn set_domain_service(
        &self,
        domain_name: &str,
        service_id: i32,
    ) -> Result<domain::Model, StoreError> {
        let lower = domain_name.to_ascii_lowercase();
        let domain_model = self.get_or_create_domain(&lower, None).await?;
        if domain_model.service_id == Some(service_id) {
            return Ok(domain_model);
        }
        let mut active: domain::ActiveModel = domain_model.into();
        active.service_id = Set(Some(service_id));
        let updated = active.update(&self.db).await?;
        Ok(updated)
    }

    /// Persists a service declared by the machine that owns `key_id` and links
    /// it to `hostname`.
    ///
    /// This never enrols identities: the person and machine behind `key_id`
    /// must already exist (they are resolved from `machine_key`), otherwise
    /// [`StoreError::KeyNotEnrolled`] is returned. Declaring the same service
    /// twice is idempotent — the existing `service` row is reused.
    pub async fn register_declared_service(
        &self,
        key_id: &KeyId,
        hostname: &str,
        service: &str,
    ) -> Result<service::Model, StoreError> {
        let Some((_, machine, _)) = self.resolve_key(key_id).await? else {
            return Err(StoreError::KeyNotEnrolled);
        };
        let svc = self.get_or_create_service(machine.id, service).await?;
        self.set_domain_service(hostname, svc.id).await?;
        Ok(svc)
    }

    /// Recomputes every materialized `domains.name` from the current
    /// `(person, machine, service)` names.
    ///
    /// The flat hostname is derived, so renaming a person or machine must
    /// rewrite the affected rows; this is that sweep. It is intentionally
    /// root-parameterized because the `Store` does not itself know the zone
    /// apex. There is no public rename API yet (a follow-up ticket owns the
    /// control/API surface); this exists so the invariant is enforced and
    /// tested from day one.
    pub async fn recompute_domain_names(&self, root: &str) -> Result<(), StoreError> {
        let services = service::Entity::find()
            .find_also_related(machine::Entity)
            .all(&self.db)
            .await?;

        for (svc, machine) in services {
            let Some(machine) = machine else {
                continue;
            };
            let Some(person) = person::Entity::find_by_id(machine.person_id)
                .one(&self.db)
                .await?
            else {
                continue;
            };
            let new_name = names::flat_hostname(&person.name, &machine.name, &svc.name, root);

            if let Some(domain) = domain::Entity::find()
                .filter(domain::Column::ServiceId.eq(svc.id))
                .one(&self.db)
                .await?
                && domain.name != new_name
            {
                let mut active: domain::ActiveModel = domain.into();
                active.name = Set(new_name);
                active.update(&self.db).await?;
            }
        }
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
    /// ACME validation mechanism that produced this certificate
    /// (`dns-01`/`http-01`).
    pub validation: String,
    /// Whether the certificate carries a wildcard SAN (`*.<root>`).
    pub wildcard: bool,
}

/// Maps a certificate model into a `CertRecord`.
fn to_cert_record(cert: certificate::Model) -> CertRecord {
    CertRecord {
        id: cert.id,
        name: cert.name,
        not_before: cert.not_before,
        not_after: cert.not_after,
        issuer: cert.issuer,
        directory: cert.directory,
        obtained_at: cert.obtained_at,
        validation: cert.validation,
        wildcard: cert.wildcard,
    }
}

fn to_full_cert_record(cert: certificate::Model) -> FullCertRecord {
    FullCertRecord {
        id: cert.id,
        name: cert.name,
        cert_pem: cert.cert_pem,
        key_pem: cert.key_pem,
        not_before: cert.not_before,
        not_after: cert.not_after,
        issuer: cert.issuer,
        directory: cert.directory,
        obtained_at: cert.obtained_at,
        validation: cert.validation,
        wildcard: cert.wildcard,
    }
}

/// Certificate database record metadata (no key material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertRecord {
    pub id: i32,
    pub name: String,
    pub not_before: i64,
    pub not_after: i64,
    pub issuer: Option<String>,
    pub directory: String,
    pub obtained_at: i64,
    /// ACME validation mechanism that produced this row (`dns-01`/`http-01`).
    pub validation: String,
    /// Whether the certificate carries a wildcard SAN (`*.<root>`).
    pub wildcard: bool,
}

/// Full certificate record with PEM material, used for startup cache hydration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullCertRecord {
    pub id: i32,
    pub name: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub not_before: i64,
    pub not_after: i64,
    pub issuer: Option<String>,
    pub directory: String,
    pub obtained_at: i64,
    /// ACME validation mechanism that produced this row (`dns-01`/`http-01`).
    pub validation: String,
    /// Whether the certificate carries a wildcard SAN (`*.<root>`).
    pub wildcard: bool,
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

/// Formats a `KeyId` into canonical prefixed text representation.
fn format_key_id(key_id: &KeyId) -> String {
    use std::fmt::Write;
    match key_id {
        KeyId::Ed25519(bytes) => {
            let mut hex = String::with_capacity(64);
            for b in bytes {
                let _ = write!(&mut hex, "{b:02x}");
            }
            format!("ed25519:{hex}")
        }
        KeyId::P256(bytes) => {
            let mut hex = String::with_capacity(66);
            for b in bytes {
                let _ = write!(&mut hex, "{b:02x}");
            }
            format!("p256:{hex}")
        }
    }
}

/// Parses a stored `machine_key.key_id` back into a [`KeyId`].
///
/// This is the inverse of [`format_key_id`]; it lets callers (the identity
/// resolver) serve the *stored* key material rather than trusting the key the
/// peer claimed. Returns `None` for a malformed or unsupported value.
pub fn parse_key_id(value: &str) -> Option<KeyId> {
    let (scheme, hex) = value.split_once(':')?;
    let decode = |hex: &str, len: usize| -> Option<Vec<u8>> {
        if hex.len() != len * 2 {
            return None;
        }
        (0..len)
            .map(|i| u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok())
            .collect()
    };
    match scheme {
        "ed25519" => {
            let bytes: [u8; 32] = decode(hex, 32)?.try_into().ok()?;
            Some(KeyId::Ed25519(bytes))
        }
        "p256" => {
            let bytes: [u8; 33] = decode(hex, 33)?.try_into().ok()?;
            Some(KeyId::P256(bytes))
        }
        _ => None,
    }
}
