pub mod error;
pub mod migration;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OpenFlags, OptionalExtension};

pub use error::StoreError;
pub use migration::Migration;

use crate::config::{Config, ConfigError};

const MAX_READER_POOL_SIZE: usize = 4;

/// SQLite connection pragma configuration.
fn apply_pragmas(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;
         PRAGMA wal_autocheckpoint = 1000;
         PRAGMA temp_store = MEMORY;",
    )?;
    Ok(())
}

/// Pragmas suitable for read-only connections.
fn apply_read_pragmas(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;
         PRAGMA temp_store = MEMORY;",
    )?;
    Ok(())
}

/// SQLite state store managing database access, embedded migrations, and configuration.
#[derive(Clone)]
pub struct Store {
    path: PathBuf,
    writer: Arc<Mutex<Connection>>,
    readers: Arc<Mutex<Vec<Connection>>>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Opens the SQLite database at `path`, creating parent directories (mode 0700)
    /// and file (mode 0600 on Linux), applying required pragmas, and running pending migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();

        // 1. Create parent directory if missing with mode 0700 on Unix
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

        let file_existed = path.exists();

        // 2. Open writer connection
        let mut conn = Connection::open(&path)?;

        // 3. Ensure 0600 permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if !file_existed || path.exists() {
                let metadata = std::fs::metadata(&path)?;
                let mut perms = metadata.permissions();
                if perms.mode() & 0o777 != 0o600 {
                    perms.set_mode(0o600);
                    std::fs::set_permissions(&path, perms)?;
                }
            }
        }

        // 4. Set pragmas
        apply_pragmas(&conn)?;

        // 5. Run forward-only migrations
        migration::run_migrations(&mut conn)?;

        Ok(Self {
            path,
            writer: Arc::new(Mutex::new(conn)),
            readers: Arc::new(Mutex::new(Vec::with_capacity(MAX_READER_POOL_SIZE))),
        })
    }

    /// Returns the path to the database file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Borrows a connection from the read pool or opens a new read-only connection.
    fn acquire_reader(&self) -> Result<Connection, StoreError> {
        let mut pool = self.readers.lock().map_err(|_| StoreError::LockPoisoned)?;
        if let Some(conn) = pool.pop() {
            return Ok(conn);
        }
        drop(pool);

        let conn = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        apply_read_pragmas(&conn)?;
        Ok(conn)
    }

    /// Returns a connection to the read pool if space is available.
    fn release_reader(&self, conn: Connection) {
        if let Ok(mut pool) = self.readers.lock()
            && pool.len() < MAX_READER_POOL_SIZE
        {
            pool.push(conn);
        }
    }

    /// Executes a read closure using a pooled or read-only connection.
    pub fn read<F, R>(&self, f: F) -> Result<R, StoreError>
    where
        F: FnOnce(&Connection) -> Result<R, StoreError>,
    {
        let conn = self.acquire_reader()?;
        let result = f(&conn);
        self.release_reader(conn);
        result
    }

    /// Executes a write closure using the mutex-guarded writer connection.
    pub fn write<F, R>(&self, f: F) -> Result<R, StoreError>
    where
        F: FnOnce(&mut Connection) -> Result<R, StoreError>,
    {
        let mut guard = self.writer.lock().map_err(|_| StoreError::LockPoisoned)?;
        f(&mut guard)
    }

    /// Saves the full configuration struct as JSON into the database.
    pub fn save_config(&self, config: &Config) -> Result<(), StoreError> {
        let json_str = serde_json::to_string(config)
            .map_err(|e| ConfigError::DeserializationFailed(e.to_string()))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        self.write(|conn| {
            conn.execute(
                "INSERT INTO config (id, config_json, updated_at) VALUES (1, ?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET config_json = excluded.config_json, updated_at = excluded.updated_at",
                rusqlite::params![json_str, now],
            )?;
            Ok(())
        })
    }

    /// Updates or inserts an individual configuration field into the JSON configuration object.
    pub fn set_config(&self, key: &str, value: &str) -> Result<(), StoreError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let key = key.to_string();
        let value = value.to_string();

        self.write(|conn| {
            let mut obj: serde_json::Map<String, serde_json::Value> = conn
                .query_row(
                    "SELECT config_json FROM config WHERE id = 1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();

            let json_val = serde_json::from_str(&value)
                .unwrap_or(serde_json::Value::String(value));
            obj.insert(key, json_val);

            let json_str = serde_json::to_string(&obj)
                .map_err(|e| ConfigError::DeserializationFailed(e.to_string()))?;

            conn.execute(
                "INSERT INTO config (id, config_json, updated_at) VALUES (1, ?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET config_json = excluded.config_json, updated_at = excluded.updated_at",
                rusqlite::params![json_str, now],
            )?;
            Ok(())
        })
    }

    /// Loads and validates the configuration from the database.
    pub fn load_config(&self) -> Result<Config, ConfigError> {
        Config::load(self)
    }

    /// Performs an online backup of the database to `dest` using `VACUUM INTO`.
    pub fn backup(&self, dest: impl AsRef<Path>) -> Result<(), StoreError> {
        let dest_path = dest.as_ref();
        let dest_str = dest_path
            .to_str()
            .ok_or_else(|| StoreError::InvalidPath("destination path is not valid UTF-8".into()))?;

        self.write(|conn| {
            // VACUUM INTO supports expression / bind parameter in SQLite 3.27+
            conn.execute("VACUUM INTO ?1", rusqlite::params![dest_str])?;
            Ok(())
        })
    }

    /// Explicitly closes the store, optimizing database layout via `PRAGMA optimize`.
    pub fn close(self) -> Result<(), StoreError> {
        let guard = self.writer.lock().map_err(|_| StoreError::LockPoisoned)?;
        guard.execute_batch("PRAGMA optimize;")?;
        Ok(())
    }

    /// Returns the maximum applied database schema migration version.
    pub fn schema_version(&self) -> Result<u32, StoreError> {
        self.read(|conn| {
            let ver: u32 = conn.query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                [],
                |row| row.get(0),
            )?;
            Ok(ver)
        })
    }

    /// Fetches the metadata record for a certificate by hostname.
    pub fn get_certificate(&self, name: &str) -> Result<Option<CertRecord>, StoreError> {
        let lower = name.to_ascii_lowercase();
        self.read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT name, not_before, not_after, issuer, directory, obtained_at, last_active_at FROM certificates WHERE name = ?1",
            )?;
            let res = stmt
                .query_row(rusqlite::params![lower], |row| {
                    Ok(CertRecord {
                        name: row.get(0)?,
                        not_before: row.get(1)?,
                        not_after: row.get(2)?,
                        issuer: row.get(3)?,
                        directory: row.get(4)?,
                        obtained_at: row.get(5)?,
                        last_active_at: row.get(6)?,
                    })
                })
                .optional()?;
            Ok(res)
        })
    }

    /// Lists all certificate records in the store ordered alphabetically by name.
    pub fn list_certificates(&self) -> Result<Vec<CertRecord>, StoreError> {
        self.read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT name, not_before, not_after, issuer, directory, obtained_at, last_active_at FROM certificates ORDER BY name ASC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(CertRecord {
                    name: row.get(0)?,
                    not_before: row.get(1)?,
                    not_after: row.get(2)?,
                    issuer: row.get(3)?,
                    directory: row.get(4)?,
                    obtained_at: row.get(5)?,
                    last_active_at: row.get(6)?,
                })
            })?;
            let mut list = Vec::new();
            for r in rows {
                list.push(r?);
            }
            Ok(list)
        })
    }

    /// Fetches the most recent `limit` lifecycle events for a given hostname.
    pub fn get_cert_events(
        &self,
        name: &str,
        limit: usize,
    ) -> Result<Vec<CertEventRecord>, StoreError> {
        let lower = name.to_ascii_lowercase();
        let limit_i64 = limit as i64;
        self.read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, name, at, kind, detail FROM cert_events WHERE name = ?1 ORDER BY at DESC, id DESC LIMIT ?2",
            )?;
            let rows = stmt.query_map(rusqlite::params![lower, limit_i64], |row| {
                Ok(CertEventRecord {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    at: row.get(2)?,
                    kind: row.get(3)?,
                    detail: row.get(4)?,
                })
            })?;
            let mut list = Vec::new();
            for r in rows {
                list.push(r?);
            }
            Ok(list)
        })
    }

    /// Fetches the single most recent lifecycle event for a given hostname.
    pub fn get_latest_cert_event(&self, name: &str) -> Result<Option<CertEventRecord>, StoreError> {
        let events = self.get_cert_events(name, 1)?;
        Ok(events.into_iter().next())
    }
}

/// Certificate database record metadata.
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

/// Certificate event database record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertEventRecord {
    pub id: i64,
    pub name: String,
    pub at: i64,
    pub kind: String,
    pub detail: Option<String>,
}

impl Drop for Store {
    fn drop(&mut self) {
        if Arc::strong_count(&self.writer) == 1
            && let Ok(guard) = self.writer.lock()
        {
            let _ = guard.execute_batch("PRAGMA optimize;");
        }
    }
}
