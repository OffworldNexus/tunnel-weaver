//! SeaORM entity definitions for the persistent state store.
//!
//! Each module mirrors one table. Timestamps are Unix seconds stored as `i64`
//! so the schema is portable across SQL backends without relying on
//! backend-specific date/time types.

pub mod acme_account;
pub mod cert_event;
pub mod certificate;
pub mod config;
pub mod domain;
pub mod machine;
pub mod machine_key;
pub mod person;
pub mod service;
