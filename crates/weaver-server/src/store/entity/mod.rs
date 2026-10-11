//! SeaORM entity definitions for the persistent state store.
//!
//! Each module mirrors one table. Timestamps are Unix seconds stored as `i64`
//! so the schema is portable across SQL backends without relying on
//! backend-specific date/time types.

pub mod abuse_bucket;
pub mod acme_account;
pub mod altcha_client;
pub mod altcha_proof;
pub mod cert_event;
pub mod certificate;
pub mod challenge;
pub mod config;
pub mod domain;
pub mod machine;
pub mod machine_key;
pub mod person;
pub mod service;
pub mod usage;
