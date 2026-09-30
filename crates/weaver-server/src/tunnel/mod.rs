//! Tunnel connection management and proxying.

pub mod connection;
pub mod identity;
pub mod proxy;
pub mod registry;

pub use connection::spawn_tunnel_connection;
pub use identity::{Identity, IdentityResolver, StoreIdentityResolver, derive_hostname};
pub use proxy::{ProxyError, forward_visitor_request};
pub use registry::{TunnelRegistry, TunnelRoute};
