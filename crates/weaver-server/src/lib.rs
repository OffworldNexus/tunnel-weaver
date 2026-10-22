pub mod abuse;
pub mod account;
pub mod altcha;
pub mod cert;
pub mod config;
pub mod control;
pub mod dns;
pub mod edge;
pub mod email;
pub mod metering;
pub mod metrics;
pub mod notify;
pub mod server;
pub mod setup;
pub mod store;
pub mod tunnel;
pub mod wall_clock;

pub use config::{Config, ConfigError};
pub use store::{Migrator, Store, StoreError};

/// Cryptographically random lowercase-hex string of `bytes * 2` characters.
pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut buf);
    hex::encode(buf)
}
