//! Persistent state store built on SeaORM.
//!
//! The store is backend-agnostic by construction: every query goes through
//! SeaORM entities or the `sea-query` builder, and the connection is opened
//! from a URL. Today only SQLite is compiled in; enabling PostgreSQL is a
//! matter of adding the `sqlx-postgres` feature and passing a `postgres://`
//! URL to [`Store::connect`]. The handful of SQLite-only niceties (pragmas,
//! file permissions, `VACUUM INTO` backups, and the in-place `usage_live` slot
//! writes) are gated on the detected backend.

pub mod abuse;
pub mod account;
pub mod altcha;
pub mod entity;
pub mod error;
pub mod migration;
pub mod names;
pub mod usage;
pub mod usage_live;

use std::path::{Path, PathBuf};
use std::time::Duration;

use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection,
    DbBackend, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Select, Set, Statement,
    TransactionTrait,
};
use sea_orm_migration::MigratorTrait;

pub use error::StoreError;
pub use migration::Migrator;

use crate::config::{Config, ConfigError};
use crate::wall_clock::unix_secs;
use entity::{
    acme_account, cert_event, certificate, challenge, config, domain, machine, machine_key_log,
    person, service,
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
            updated_at: Set(unix_secs()),
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
            directory: Set(cert.directory),
            obtained_at: Set(cert.obtained_at),
            validation: Set(cert.validation),
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
                        certificate::Column::Directory,
                        certificate::Column::ObtainedAt,
                        certificate::Column::Validation,
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

    /// Lists certificate records in name order.
    pub async fn list_certificates(&self) -> Result<Vec<CertRecord>, StoreError> {
        Ok(certificate::Entity::find()
            .order_by_asc(certificate::Column::Name)
            .all(&self.db)
            .await?
            .into_iter()
            .map(to_cert_record)
            .collect())
    }

    /// Lists every certificate including PEM material, in name order.
    pub async fn list_certificates_full(&self) -> Result<Vec<FullCertRecord>, StoreError> {
        Ok(certificate::Entity::find()
            .order_by_asc(certificate::Column::Name)
            .all(&self.db)
            .await?
            .into_iter()
            .map(to_full_cert_record)
            .collect())
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
        certificate: &str,
        at: i64,
    ) -> Result<(), StoreError> {
        let lower = name.to_ascii_lowercase();
        let active = challenge::ActiveModel {
            name: Set(lower),
            value: Set(value.to_string()),
            certificate: Set(certificate.to_string()),
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
        certificate: &str,
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
            certificate: Set(certificate.to_string()),
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

    // ----- auth: person, machine, key log, service -----

    /// Creates the person of an account.
    ///
    /// An account has exactly one person: a second one for the same account, or
    /// a name already in use, is refused by the unique indexes and surfaces as
    /// [`StoreError::Db`].
    pub async fn create_person(
        &self,
        account_id: i32,
        name: &str,
    ) -> Result<person::Model, StoreError> {
        let lower = name.to_ascii_lowercase();
        if !names::is_valid_person_or_machine(&lower) {
            return Err(StoreError::InvalidName(format!(
                "person '{name}' must match ^[a-z0-9]{{1,15}}$"
            )));
        }
        let new_person = person::ActiveModel {
            name: Set(lower),
            account_id: Set(account_id),
            created_at: Set(unix_secs()),
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

    /// Fetches the person of an account, if it has one yet.
    pub async fn person_by_account(
        &self,
        account_id: i32,
    ) -> Result<Option<person::Model>, StoreError> {
        Ok(person::Entity::find()
            .filter(person::Column::AccountId.eq(account_id))
            .one(&self.db)
            .await?)
    }

    /// The person name to propose for an account called `account_name`: its
    /// slug, or the first numbered variant no person has yet.
    pub async fn propose_person_name(&self, account_name: &str) -> Result<String, StoreError> {
        first_free_name(
            &self.db,
            person::Entity::find(),
            person::Column::Name,
            &names::slugify_person(account_name),
        )
        .await
    }

    /// The machine name to propose for `hostname` under a person: its slug, or
    /// the first numbered variant none of the person's machines has yet.
    pub async fn propose_machine_name(
        &self,
        person_id: i32,
        hostname: &str,
    ) -> Result<String, StoreError> {
        first_free_name(
            &self.db,
            machine::Entity::find().filter(machine::Column::PersonId.eq(person_id)),
            machine::Column::Name,
            &names::slugify_machine(hostname),
        )
        .await
    }

    /// Creates a machine under a person, holding `key_id`, and opens its key
    /// log row.
    ///
    /// A name already used by the person, or a key already held by any machine,
    /// is refused by the unique indexes and surfaces as [`StoreError::Db`].
    pub async fn create_machine(
        &self,
        person_id: i32,
        name: &str,
        key_id: &KeyId,
    ) -> Result<machine::Model, StoreError> {
        let lower = name.to_ascii_lowercase();
        if !names::is_valid_person_or_machine(&lower) {
            return Err(StoreError::InvalidName(format!(
                "machine '{name}' must match ^[a-z0-9]{{1,15}}$"
            )));
        }
        let now = unix_secs();
        let key = key_id.to_string();
        let txn = self.db.begin().await?;
        let created = machine::ActiveModel {
            person_id: Set(person_id),
            name: Set(lower),
            created_at: Set(now),
            key_id: Set(key.clone()),
            ..Default::default()
        }
        .insert(&txn)
        .await?;
        open_key_log(&txn, &created, now).await?;
        txn.commit().await?;
        Ok(created)
    }

    /// Fetches a machine by its id.
    pub async fn machine_by_id(&self, id: i32) -> Result<Option<machine::Model>, StoreError> {
        Ok(machine::Entity::find_by_id(id).one(&self.db).await?)
    }

    /// Resolves a key to the machine holding it and that machine's person.
    ///
    /// This is the identity path: it reads `machine.key_id` and nothing else.
    pub async fn machine_by_key(
        &self,
        key_id: &KeyId,
    ) -> Result<Option<(person::Model, machine::Model)>, StoreError> {
        let Some((mach, Some(pers))) = machine::Entity::find()
            .filter(machine::Column::KeyId.eq(key_id.to_string()))
            .find_also_related(person::Entity)
            .one(&self.db)
            .await?
        else {
            return Ok(None);
        };
        Ok(Some((pers, mach)))
    }

    /// Moves a machine onto a new key: the old key stops working at once.
    ///
    /// In one transaction: `machine.key_id` is overwritten, the old key's log
    /// row is closed as replaced, and a row is opened for the new one. The
    /// machine keeps its id, name, services and hostnames. A key already held
    /// by another machine is refused by the unique index ([`StoreError::Db`]);
    /// an unknown machine is [`StoreError::Conflict`].
    pub async fn replace_machine_key(
        &self,
        machine_id: i32,
        new_key: &KeyId,
    ) -> Result<machine::Model, StoreError> {
        let now = unix_secs();
        let txn = self.db.begin().await?;
        let Some(current) = machine::Entity::find_by_id(machine_id).one(&txn).await? else {
            txn.rollback().await?;
            return Err(StoreError::Conflict(format!(
                "no machine with id {machine_id}"
            )));
        };
        close_key_log(
            &txn,
            current.id,
            &current.key_id,
            machine_key_log::REASON_REPLACED,
            now,
        )
        .await?;
        let mut active: machine::ActiveModel = current.into();
        active.key_id = Set(new_key.to_string());
        let updated = active.update(&txn).await?;
        open_key_log(&txn, &updated, now).await?;
        txn.commit().await?;
        Ok(updated)
    }

    /// Revokes the machine holding `key_id`: deletes it — cascading to its
    /// services, so its hostnames stop being owned — and closes its key log row
    /// as revoked, atomically.
    ///
    /// The name is freed, so a later pairing may propose it again. Returns the
    /// revoked machine, or `None` when the key was not held by any machine
    /// (already revoked: the goal state).
    pub async fn revoke_machine(
        &self,
        key_id: &KeyId,
    ) -> Result<Option<machine::Model>, StoreError> {
        let now = unix_secs();
        let txn = self.db.begin().await?;
        let Some(found) = machine::Entity::find()
            .filter(machine::Column::KeyId.eq(key_id.to_string()))
            .one(&txn)
            .await?
        else {
            txn.rollback().await?;
            return Ok(None);
        };
        machine::Entity::delete_by_id(found.id).exec(&txn).await?;
        close_key_log(
            &txn,
            found.id,
            &found.key_id,
            machine_key_log::REASON_REVOKED,
            now,
        )
        .await?;
        txn.commit().await?;
        Ok(Some(found))
    }

    /// Deletes key log rows retired before `cutoff` (Unix seconds). Rows of
    /// current keys are never deleted, however old.
    pub async fn sweep_machine_key_log(&self, cutoff: i64) -> Result<u64, StoreError> {
        let result = machine_key_log::Entity::delete_many()
            .filter(machine_key_log::Column::RetiredAt.is_not_null())
            .filter(machine_key_log::Column::RetiredAt.lt(cutoff))
            .exec(&self.db)
            .await?;
        Ok(result.rows_affected)
    }

    // ----- machines: listing, presence and rename -----

    /// Lists a person's machines, ordered by name.
    ///
    /// The order is only the stable base: the machine view re-orders by reverse
    /// last use, which it can only do once presence (a metrics read) is in hand.
    pub async fn list_machines(&self, person_id: i32) -> Result<Vec<machine::Model>, StoreError> {
        Ok(machine::Entity::find()
            .filter(machine::Column::PersonId.eq(person_id))
            .order_by_asc(machine::Column::Name)
            .all(&self.db)
            .await?)
    }

    /// The given machines' services, each with the hostnames currently linked
    /// to it, ordered by service name for a stable view.
    ///
    /// Hostnames are read from the materialized `domains` rows rather than
    /// re-derived, so what the list and detail show is exactly what routes. One
    /// query for a whole list, so the caller never runs an N+1.
    pub async fn services_with_hostnames(
        &self,
        machine_ids: &[i32],
    ) -> Result<Vec<(service::Model, Vec<String>)>, StoreError> {
        if machine_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = service::Entity::find()
            .filter(service::Column::MachineId.is_in(machine_ids.iter().copied()))
            .order_by_asc(service::Column::Name)
            .find_with_related(domain::Entity)
            .all(&self.db)
            .await?;
        Ok(rows
            .into_iter()
            .map(|(svc, domains)| {
                let mut hosts: Vec<String> = domains.into_iter().map(|d| d.name).collect();
                hosts.sort();
                (svc, hosts)
            })
            .collect())
    }

    // Presence ("last seen") is a metrics concern now: it is derived from the
    // live day's `open_ms_slots` array (and, for folded days, the rollup's
    // per-minute blob), which only
    // [`crate::metrics::MetricsStore::last_open_minutes`] can decode. The account
    // router resolves a person's service ids here and asks the metrics store.

    /// Renames a machine and re-derives every hostname it serves, atomically.
    ///
    /// The person and machine labels hold no dash, so a hostname
    /// `<person>-<machine>-<service>.<root>` splits at its first two dashes;
    /// each of the machine's `domains` rows is moved from the old prefix to the
    /// new one (leaving the service and root untouched, so the tunnel root is
    /// never needed here). The old row is deleted and the new hostname linked
    /// to the service, so the old name stops being served the moment this
    /// commits. A re-created name that already has an unowned `domains` row
    /// (left by a revoked machine) is reused rather than colliding with the
    /// unique index.
    ///
    /// The live registry is remapped separately by the caller
    /// ([`TunnelRegistry::rename_machine`](crate::tunnel::registry::TunnelRegistry::rename_machine)),
    /// DB first, so the two never disagree about what is served.
    #[allow(clippy::too_many_lines)] // one transaction, deliberately linear
    pub async fn rename_machine(
        &self,
        machine_id: i32,
        new_name: &str,
    ) -> Result<machine::Model, StoreError> {
        let new_lower = new_name.to_ascii_lowercase();
        if !names::is_valid_person_or_machine(&new_lower) {
            return Err(StoreError::InvalidName(format!(
                "machine '{new_name}' must match ^[a-z0-9]{{1,15}}$"
            )));
        }
        let txn = self.db.begin().await?;
        let Some(current) = machine::Entity::find_by_id(machine_id).one(&txn).await? else {
            txn.rollback().await?;
            return Err(StoreError::Conflict(format!(
                "no machine with id {machine_id}"
            )));
        };
        if current.name == new_lower {
            // A rename to the current name is a no-op, not an error.
            txn.commit().await?;
            return Ok(current);
        }
        let Some(pers) = person::Entity::find_by_id(current.person_id)
            .one(&txn)
            .await?
        else {
            txn.rollback().await?;
            return Err(StoreError::Conflict(format!(
                "machine {machine_id} has no person {}",
                current.person_id
            )));
        };

        let old_prefix = format!("{}-{}-", pers.name, current.name);
        let services = service::Entity::find()
            .filter(service::Column::MachineId.eq(machine_id))
            .all(&txn)
            .await?;
        for svc in &services {
            let domains = domain::Entity::find()
                .filter(domain::Column::ServiceId.eq(svc.id))
                .all(&txn)
                .await?;
            for old in domains {
                let Some(rest) = old.name.strip_prefix(&old_prefix) else {
                    continue;
                };
                let new_host = format!("{}-{}-{}", pers.name, new_lower, rest);
                if new_host == old.name {
                    continue;
                }
                // Reuse a row already carrying the new name (an unowned row
                // from an earlier revoke), else create one; then drop the old
                // row so its hostname stops resolving.
                let last_active_at = old.last_active_at;
                if let Some(existing) = domain::Entity::find()
                    .filter(domain::Column::Name.eq(&new_host))
                    .one(&txn)
                    .await?
                {
                    let mut active: domain::ActiveModel = existing.into();
                    active.service_id = Set(Some(svc.id));
                    active.last_active_at = Set(last_active_at);
                    active.update(&txn).await?;
                } else {
                    domain::ActiveModel {
                        name: Set(new_host),
                        last_active_at: Set(last_active_at),
                        service_id: Set(Some(svc.id)),
                        ..Default::default()
                    }
                    .insert(&txn)
                    .await?;
                }
                domain::Entity::delete_by_id(old.id).exec(&txn).await?;
            }
        }

        let mut active: machine::ActiveModel = current.into();
        active.name = Set(new_lower);
        let updated = active.update(&txn).await?;
        txn.commit().await?;
        Ok(updated)
    }

    /// Creates an active account with no email identity and no password, so
    /// nobody can ever sign in to it. Test-only: real accounts come from the
    /// signup flow.
    #[cfg(any(test, feature = "test-util"))]
    pub async fn create_account_without_login(
        &self,
        name: &str,
    ) -> Result<entity::account::Model, StoreError> {
        let now = unix_secs();
        Ok(entity::account::ActiveModel {
            name: Set(name.to_string()),
            state: Set("active".to_string()),
            created_at: Set(now),
            activated_at: Set(now),
            ..Default::default()
        }
        .insert(&self.db)
        .await?)
    }

    /// Creates an account named `name` with its person of the same name, for
    /// tests that need an identity without the signup flow.
    #[cfg(any(test, feature = "test-util"))]
    pub async fn create_test_person(&self, name: &str) -> Result<person::Model, StoreError> {
        let account = self.create_account_without_login(name).await?;
        self.create_person(account.id, name).await
    }

    /// Fetches an existing service by machine ID and name, or creates a new one.
    pub async fn get_or_create_service(
        &self,
        machine_id: i32,
        name: &str,
    ) -> Result<service::Model, StoreError> {
        if !weaver_proto::is_valid_service_name(name) {
            return Err(StoreError::InvalidName(format!(
                "service '{name}' must match ^[a-z0-9]+(-[a-z0-9]+)*$ and be 1-{} chars",
                weaver_proto::SERVICE_NAME_MAX
            )));
        }
        if let Some(existing) = service::Entity::find()
            .filter(service::Column::MachineId.eq(machine_id))
            .filter(service::Column::Name.eq(name))
            .one(&self.db)
            .await?
        {
            return Ok(existing);
        }

        let new_service = service::ActiveModel {
            machine_id: Set(machine_id),
            name: Set(name.to_string()),
            created_at: Set(unix_secs()),
            ..Default::default()
        };
        match new_service.insert(&self.db).await {
            Ok(model) => Ok(model),
            Err(e) => {
                if let Some(existing) = service::Entity::find()
                    .filter(service::Column::MachineId.eq(machine_id))
                    .filter(service::Column::Name.eq(name))
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
        let name = domain_name.to_ascii_lowercase();
        let domain_model = self.get_or_create_domain(&name, None).await?;
        if domain_model.service_id == Some(service_id) {
            return Ok(domain_model);
        }
        let mut active: domain::ActiveModel = domain_model.into();
        active.service_id = Set(Some(service_id));
        let updated = active.update(&self.db).await?;
        Ok(updated)
    }

    /// Persists a service declared by machine `machine_id` and links it to
    /// `hostname`. Declaring the same service twice is idempotent — the
    /// existing `service` row is reused.
    pub async fn register_declared_service(
        &self,
        machine_id: i32,
        hostname: &str,
        service: &str,
    ) -> Result<service::Model, StoreError> {
        let svc = self.get_or_create_service(machine_id, service).await?;
        self.set_domain_service(hostname, svc.id).await?;
        Ok(svc)
    }

    // ----- certificate events -----

    /// Appends a certificate lifecycle event.
    pub async fn record_cert_event(
        &self,
        name: &str,
        at: i64,
        kind: &str,
        detail: &str,
    ) -> Result<(), StoreError> {
        cert_event::ActiveModel {
            name: Set(name.to_string()),
            at: Set(at),
            kind: Set(kind.to_string()),
            detail: Set(detail.to_string()),
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
        created_at: i64,
    ) -> Result<(), StoreError> {
        let model = acme_account::ActiveModel {
            directory: Set(directory.to_string()),
            email: Set(email.to_string()),
            credentials_json: Set(credentials_json.to_string()),
            created_at: Set(created_at),
        };
        acme_account::Entity::insert(model)
            .on_conflict(
                OnConflict::column(acme_account::Column::Directory)
                    .update_columns([
                        acme_account::Column::Email,
                        acme_account::Column::CredentialsJson,
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
    pub directory: String,
    pub obtained_at: i64,
    /// ACME validation mechanism that produced this certificate
    /// (`dns-01`/`http-01`).
    pub validation: String,
}

/// Maps a certificate model into a `CertRecord`.
fn to_cert_record(cert: certificate::Model) -> CertRecord {
    CertRecord {
        id: cert.id,
        name: cert.name,
        not_before: cert.not_before,
        not_after: cert.not_after,
        directory: cert.directory,
        obtained_at: cert.obtained_at,
        validation: cert.validation,
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
        directory: cert.directory,
        obtained_at: cert.obtained_at,
        validation: cert.validation,
    }
}

/// Certificate database record metadata (no key material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertRecord {
    pub id: i32,
    pub name: String,
    pub not_before: i64,
    pub not_after: i64,
    pub directory: String,
    pub obtained_at: i64,
    /// ACME validation mechanism that produced this row (`dns-01`/`http-01`).
    pub validation: String,
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
    pub directory: String,
    pub obtained_at: i64,
    /// ACME validation mechanism that produced this row (`dns-01`/`http-01`).
    pub validation: String,
}

/// Certificate event database record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertEventRecord {
    pub id: i64,
    pub name: String,
    pub at: i64,
    pub kind: String,
    /// Empty when the event carries no detail.
    pub detail: String,
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

/// How many numbered candidates one uniqueness probe asks about.
const NAME_PROBE_BATCH: usize = 16;

/// The first of [`names::candidates`]`(base)` that no row of `scope` has in
/// `column`, asking the database about one batch of candidates at a time:
/// `SELECT <column> FROM … WHERE <scope> AND <column> IN (<batch>)`.
async fn first_free_name<E: EntityTrait>(
    db: &DatabaseConnection,
    scope: Select<E>,
    column: E::Column,
    base: &str,
) -> Result<String, StoreError> {
    let mut candidates = names::candidates(base);
    loop {
        let batch: Vec<String> = candidates.by_ref().take(NAME_PROBE_BATCH).collect();
        let taken: Vec<String> = scope
            .clone()
            .select_only()
            .column(column)
            .filter(column.is_in(batch.iter().cloned()))
            .into_tuple()
            .all(db)
            .await?;
        if let Some(free) = batch.into_iter().find(|name| !taken.contains(name)) {
            return Ok(free);
        }
    }
}

/// Opens the key log row for the key `machine` now holds.
async fn open_key_log(
    db: &impl ConnectionTrait,
    machine: &machine::Model,
    now: i64,
) -> Result<(), StoreError> {
    machine_key_log::ActiveModel {
        key_id: Set(machine.key_id.clone()),
        machine_id: Set(machine.id),
        person_id: Set(machine.person_id),
        added_at: Set(now),
        retired_at: Set(None),
        retired_reason: Set(String::new()),
        ..Default::default()
    }
    .insert(db)
    .await?;
    Ok(())
}

/// Closes the open key log row of `key_id` on `machine_id`.
async fn close_key_log(
    db: &impl ConnectionTrait,
    machine_id: i32,
    key_id: &str,
    reason: &str,
    now: i64,
) -> Result<(), StoreError> {
    machine_key_log::Entity::update_many()
        .col_expr(machine_key_log::Column::RetiredAt, Expr::value(Some(now)))
        .col_expr(
            machine_key_log::Column::RetiredReason,
            Expr::value(reason.to_string()),
        )
        .filter(machine_key_log::Column::MachineId.eq(machine_id))
        .filter(machine_key_log::Column::KeyId.eq(key_id))
        .filter(machine_key_log::Column::RetiredAt.is_null())
        .exec(db)
        .await?;
    Ok(())
}
