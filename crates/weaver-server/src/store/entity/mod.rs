//! SeaORM entity definitions for the persistent state store.
//!
//! Each module mirrors one table. Timestamps are Unix seconds stored as `i64`
//! so the schema is portable across SQL backends without relying on
//! backend-specific date/time types.

pub mod abuse_bucket;
pub mod account;
pub mod acme_account;
pub mod altcha_client;
pub mod altcha_proof;
pub mod auth_event;
pub mod browser_session;
pub mod cert_event;
pub mod certificate;
pub mod challenge;
pub mod config;
pub mod domain;
pub mod email_identity;
pub mod email_verification;
pub mod login_challenge;
pub mod machine;
pub mod machine_key_log;
pub mod password_credential;
pub mod password_reset_token;
pub mod pending_registration;
pub mod person;
pub mod service;
pub mod usage_daily;
pub mod usage_live;
pub mod verification_token;
