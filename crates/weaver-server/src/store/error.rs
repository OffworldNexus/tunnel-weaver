use thiserror::Error;

use crate::config::ConfigError;

/// Errors arising from Store operations.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Filesystem or I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Underlying SQLite engine failure.
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// Database schema version is newer than the highest migration known to the running binary.
    #[error(
        "Database schema version {db_version} is newer than binary schema version {binary_version}"
    )]
    NewerSchema {
        db_version: u32,
        binary_version: u32,
    },

    /// Recorded checksum of an applied migration does not match the binary's migration content.
    #[error("Migration {version} checksum mismatch: expected {expected}, found {actual}")]
    ChecksumMismatch {
        version: u32,
        expected: String,
        actual: String,
    },

    /// Migrations in the binary are not contiguously numbered.
    #[error("Invalid migration sequence: {0}")]
    InvalidMigrationSequence(String),

    /// Configuration parsing or validation failure.
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    /// Tokio blocking task join error.
    #[error("Async task join error: {0}")]
    Join(#[from] tokio::task::JoinError),

    /// Path contains invalid characters or UTF-8.
    #[error("Invalid path: {0}")]
    InvalidPath(String),

    /// Internal synchronization error (mutex poisoned).
    #[error("Store writer mutex poisoned")]
    LockPoisoned,
}
