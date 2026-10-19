//! Failures from the client store.

/// Something went wrong reading or writing the client's own state.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Filesystem failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Database engine or ORM failure.
    #[error("database error: {0}")]
    Db(#[from] sea_orm::DbErr),
    /// No per-user data directory could be determined for this platform.
    #[error("cannot locate a data directory for this platform")]
    NoDataDir,
    /// An admin host that cannot be normalised.
    #[error(transparent)]
    InvalidHost(#[from] crate::host::HostError),
}
