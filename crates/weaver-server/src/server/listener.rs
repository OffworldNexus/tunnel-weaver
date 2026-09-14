//! Socket acquisition for HTTP and HTTPS edges.
//!
//! Supports systemd socket activation via `LISTEN_FDS` with strict port-to-role
//! matching, falling back to dual-stack self-bind with SO_REUSEADDR.

use std::env;
use std::net::SocketAddr;
use std::os::unix::io::FromRawFd;

use thiserror::Error;
use tokio::net::TcpListener;
use tracing::{debug, info};

use crate::Config;

/// Errors occurring during listener binding or socket activation.
#[derive(Debug, Error)]
pub enum ListenerError {
    /// Failure during systemd socket activation.
    #[error("Socket activation error: {0}")]
    Activation(String),

    /// Failure to bind a listening socket to a specific address.
    #[error("Failed to bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

/// Sockets acquired for the HTTP and HTTPS edge servers.
pub struct EdgeListeners {
    /// Listener for HTTP cleartext traffic (port 80).
    pub http: TcpListener,
    /// Listener for HTTPS TLS traffic (port 443).
    pub https: TcpListener,
}

/// Binds or acquires listeners for HTTP and HTTPS based on environment or configuration.
///
/// If `LISTEN_FDS` is set, sockets are acquired from file descriptors 3 and 4,
/// requiring exactly two sockets matching the configured HTTP and HTTPS ports.
/// Otherwise, dual-stack sockets are bound directly to `config.listen_http` and `config.listen_https`.
pub fn acquire_listeners(config: &Config) -> Result<EdgeListeners, ListenerError> {
    if let Ok(fds_str) = env::var("LISTEN_FDS") {
        if let Ok(pid_str) = env::var("LISTEN_PID")
            && let Ok(pid) = pid_str.parse::<u32>()
            && pid != std::process::id()
        {
            debug!(
                "LISTEN_PID {} does not match current PID {}, ignoring LISTEN_FDS",
                pid,
                std::process::id()
            );
            return bind_listeners(config);
        }

        let num_fds = fds_str.parse::<usize>().map_err(|e| {
            ListenerError::Activation(format!("Invalid LISTEN_FDS '{fds_str}': {e}"))
        })?;

        if num_fds != 2 {
            return Err(ListenerError::Activation(format!(
                "Expected exactly 2 sockets in LISTEN_FDS matching HTTP and HTTPS, got {num_fds}"
            )));
        }

        let mut http_listener = None;
        let mut https_listener = None;

        for fd in 3..5 {
            let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
            let addr = std_listener.local_addr().map_err(|e| {
                ListenerError::Activation(format!("Failed to get local_addr for fd {fd}: {e}"))
            })?;

            let port = addr.port();
            if port == config.listen_http.port() && http_listener.is_none() {
                std_listener.set_nonblocking(true).map_err(|e| {
                    ListenerError::Activation(format!("Failed to set nonblocking on fd {fd}: {e}"))
                })?;
                let tokio_listener = TcpListener::from_std(std_listener).map_err(|e| {
                    ListenerError::Activation(format!("Failed to convert fd {fd} to tokio: {e}"))
                })?;
                http_listener = Some(tokio_listener);
            } else if port == config.listen_https.port() && https_listener.is_none() {
                std_listener.set_nonblocking(true).map_err(|e| {
                    ListenerError::Activation(format!("Failed to set nonblocking on fd {fd}: {e}"))
                })?;
                let tokio_listener = TcpListener::from_std(std_listener).map_err(|e| {
                    ListenerError::Activation(format!("Failed to convert fd {fd} to tokio: {e}"))
                })?;
                https_listener = Some(tokio_listener);
            } else {
                return Err(ListenerError::Activation(format!(
                    "Inherited socket fd {fd} bound to port {port} matches neither HTTP port {} nor HTTPS port {}",
                    config.listen_http.port(),
                    config.listen_https.port()
                )));
            }
        }

        let (Some(http), Some(https)) = (http_listener, https_listener) else {
            return Err(ListenerError::Activation(
                "LISTEN_FDS sockets did not contain both HTTP and HTTPS listeners".to_string(),
            ));
        };

        info!("Acquired HTTP and HTTPS listeners via systemd socket activation");
        return Ok(EdgeListeners { http, https });
    }

    bind_listeners(config)
}

/// Binds dual-stack listeners directly to the configured addresses.
fn bind_listeners(config: &Config) -> Result<EdgeListeners, ListenerError> {
    let http = bind_single_listener(config.listen_http)?;
    let https = bind_single_listener(config.listen_https)?;
    Ok(EdgeListeners { http, https })
}

/// Binds a single dual-stack TCP listener with SO_REUSEADDR enabled.
fn bind_single_listener(addr: SocketAddr) -> Result<TcpListener, ListenerError> {
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };

    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
        .map_err(|e| ListenerError::Bind { addr, source: e })?;

    let _ = socket.set_reuse_address(true);

    if addr.is_ipv6() {
        // Allow dual-stack IPv4-mapped IPv6 connections
        let _ = socket.set_only_v6(false);
    }

    socket
        .bind(&addr.into())
        .map_err(|e| ListenerError::Bind { addr, source: e })?;

    socket
        .listen(1024)
        .map_err(|e| ListenerError::Bind { addr, source: e })?;

    socket
        .set_nonblocking(true)
        .map_err(|e| ListenerError::Bind { addr, source: e })?;

    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener).map_err(|e| ListenerError::Bind { addr, source: e })
}
