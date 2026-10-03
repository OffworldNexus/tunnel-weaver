use thiserror::Error;

use crate::config::ConfigError;

/// Errors arising from Store operations.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Filesystem or I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Underlying database engine or ORM failure.
    #[error("Database error: {0}")]
    Db(#[from] sea_orm::DbErr),

    /// Configuration parsing or validation failure.
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    /// Path contains invalid characters or UTF-8.
    #[error("Invalid path: {0}")]
    InvalidPath(String),

    /// A key was presented that is not enrolled against any machine.
    #[error("Key is not enrolled against any machine")]
    KeyNotEnrolled,

    /// An entity name failed the flat-hostname naming rules, or collided with
    /// a zone label the responder owns.
    #[error("Invalid name: {0}")]
    InvalidName(String),

    /// A metering value fell outside its valid range (e.g. `open_ms > 60000`).
    #[error("Invalid usage value: {0}")]
    InvalidUsage(String),

    /// The operation is only implemented for some SQL backends (e.g. file backup).
    #[error("Operation '{0}' is not supported on the {1:?} backend")]
    UnsupportedBackend(&'static str, sea_orm::DbBackend),
}
