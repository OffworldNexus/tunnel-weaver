//! Tunnel Weaver client library.
//!
//! A [`Client`] runs the `weave` commands. It is assembled from a [`Store`],
//! a [`KeyAgent`] holding the device key ([`Tpmd`] in production) and a
//! [`Reporter`] that presents progress; the library itself never prints.

mod client;
mod error;
pub mod host;
pub mod key;
pub mod pair;
mod pool;
mod proxy;
pub mod report;
mod rewrite;
pub mod start;
pub mod store;
pub mod target;
pub mod tpm;
pub mod unpair;

pub use client::Client;
pub use error::Error;
pub use key::{KeyAgent, KeyError, OpenedKey, Provision, SecurityLevel};
pub use pair::{PairRequest, Paired, pairing_url};
pub use report::{Phase, Reporter, RequestEvent, Silent};
pub use start::StartOptions;
pub use store::Store;
pub use target::{ServiceSpec, Target, TargetScheme, parse_specs};
pub use tpm::Tpmd;
pub use unpair::Unpaired;
