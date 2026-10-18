//! Tunnel Weaver client library.

pub mod connect;
pub mod host;
#[cfg(feature = "dev-signer")]
pub mod identity;
pub mod log;
pub mod pair;
pub mod pool;
pub mod proxy;
pub mod relays;
pub mod rewrite;
pub mod start;
pub mod status;
pub mod store;
pub mod target;
pub mod tpm;
pub mod ui;
pub mod unpair;

pub use connect::{connect_tls, parse_server_address, set_tcp_nodelay, set_tcp_notsent_lowat};
#[cfg(feature = "dev-signer")]
pub use identity::Ed25519Signer;
pub use pair::{PairOptions, run_pair};
pub use start::{SignerSpec, StartOptions, run_start, run_start_with_token, run_start_with_tokens};
pub use target::{ServiceSpec, Target, TargetScheme, parse_specs};
pub use tpm::DeviceKey;
pub use unpair::{revoke_with_signer, run_unpair};
