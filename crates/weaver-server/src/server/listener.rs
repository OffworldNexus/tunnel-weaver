//! Socket acquisition for the HTTP, HTTPS, and DNS edges.
//!
//! Supports systemd socket activation via `LISTEN_FDS`, matching inherited
//! sockets to roles by port and socket type, and falling back to dual-stack
//! self-bind with SO_REUSEADDR. DNS is only ever bound to an explicit relay
//! address, never a wildcard, so it cannot collide with the `systemd-resolved`
//! stub on `127.0.0.53:53`.

use std::env;
use std::net::SocketAddr;
use std::os::unix::io::FromRawFd;

use thiserror::Error;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, info, warn};

use crate::Config;

/// The port the authoritative DNS responder is reachable on.
pub const DNS_PORT: u16 = 53;

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

/// Sockets acquired for the edge servers.
pub struct EdgeListeners {
    /// Listener for HTTP cleartext traffic (port 80).
    pub http: TcpListener,
    /// Listener for HTTPS TLS traffic (port 443).
    pub https: TcpListener,
    /// Datagram sockets for authoritative DNS (port 53), one per relay address.
    pub dns_udp: Vec<UdpSocket>,
    /// Stream sockets for authoritative DNS over TCP (port 53), one per relay address.
    pub dns_tcp: Vec<TcpListener>,
}

/// Binds or acquires listeners based on environment or configuration.
///
/// With `LISTEN_FDS` set, sockets are inherited from fd 3 onward. HTTP and
/// HTTPS are matched by port; the two DNS sockets share port 53 and are
/// disambiguated by socket type (datagram vs stream). Without activation, the
/// edges self-bind and DNS is best-effort on the configured relay addresses.
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

        if num_fds < 2 {
            return Err(ListenerError::Activation(format!(
                "Expected at least 2 inherited sockets (HTTP, HTTPS), got {num_fds}"
            )));
        }

        let mut http_listener = None;
        let mut https_listener = None;
        let mut dns_udp = Vec::new();
        let mut dns_tcp = Vec::new();

        for fd in 3..3 + num_fds as i32 {
            // Peek the socket type before committing the fd to a Tokio type.
            let sock = unsafe { socket2::Socket::from_raw_fd(fd) };
            let is_dgram = sock.r#type().map_err(|e| {
                ListenerError::Activation(format!("Failed to get socket type for fd {fd}: {e}"))
            })? == socket2::Type::DGRAM;
            let addr = sock.local_addr().map_err(|e| {
                ListenerError::Activation(format!("Failed to get local_addr for fd {fd}: {e}"))
            })?;
            let port = addr.as_socket().map(|s| s.port()).unwrap_or(0);

            if is_dgram {
                if port != DNS_PORT {
                    return Err(ListenerError::Activation(format!(
                        "Inherited datagram fd {fd} bound to port {port} is not the DNS port {DNS_PORT}"
                    )));
                }
                let std_socket: std::net::UdpSocket = sock.into();
                std_socket.set_nonblocking(true).map_err(|e| {
                    ListenerError::Activation(format!("Failed to set nonblocking on fd {fd}: {e}"))
                })?;
                dns_udp.push(UdpSocket::from_std(std_socket).map_err(|e| {
                    ListenerError::Activation(format!(
                        "Failed to convert fd {fd} to tokio UDP: {e}"
                    ))
                })?);
                continue;
            }

            let std_listener: std::net::TcpListener = sock.into();
            if port == config.listen_http.port() && http_listener.is_none() {
                std_listener.set_nonblocking(true).map_err(|e| {
                    ListenerError::Activation(format!("Failed to set nonblocking on fd {fd}: {e}"))
                })?;
                http_listener = Some(TcpListener::from_std(std_listener).map_err(|e| {
                    ListenerError::Activation(format!("Failed to convert fd {fd} to tokio: {e}"))
                })?);
            } else if port == config.listen_https.port() && https_listener.is_none() {
                std_listener.set_nonblocking(true).map_err(|e| {
                    ListenerError::Activation(format!("Failed to set nonblocking on fd {fd}: {e}"))
                })?;
                https_listener = Some(TcpListener::from_std(std_listener).map_err(|e| {
                    ListenerError::Activation(format!("Failed to convert fd {fd} to tokio: {e}"))
                })?);
            } else if port == DNS_PORT {
                std_listener.set_nonblocking(true).map_err(|e| {
                    ListenerError::Activation(format!("Failed to set nonblocking on fd {fd}: {e}"))
                })?;
                dns_tcp.push(TcpListener::from_std(std_listener).map_err(|e| {
                    ListenerError::Activation(format!("Failed to convert fd {fd} to tokio: {e}"))
                })?);
            } else {
                return Err(ListenerError::Activation(format!(
                    "Inherited stream fd {fd} bound to port {port} matches neither HTTP {}, HTTPS {}, nor DNS {DNS_PORT}",
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

        info!(
            dns_udp = dns_udp.len(),
            dns_tcp = dns_tcp.len(),
            "Acquired edge listeners via systemd socket activation"
        );
        return Ok(EdgeListeners {
            http,
            https,
            dns_udp,
            dns_tcp,
        });
    }

    bind_listeners(config)
}

/// Binds dual-stack listeners directly to the configured addresses.
fn bind_listeners(config: &Config) -> Result<EdgeListeners, ListenerError> {
    let http = bind_single_listener(config.listen_http)?;
    let https = bind_single_listener(config.listen_https)?;

    // DNS is best-effort without socket activation: binding 53 needs privileges
    // or a privileged port mapping. The systemd path is the supported one.
    let mut dns_udp = Vec::new();
    let mut dns_tcp = Vec::new();
    for ip in &config.relay_ips {
        let addr = SocketAddr::new(*ip, DNS_PORT);
        match bind_udp(addr) {
            Ok(socket) => dns_udp.push(socket),
            Err(err) => {
                warn!(%addr, error = %err, "Could not self-bind DNS UDP (expected without privileges)")
            }
        }
        match bind_single_listener(addr) {
            Ok(listener) => dns_tcp.push(listener),
            Err(err) => {
                warn!(%addr, error = %err, "Could not self-bind DNS TCP (expected without privileges)")
            }
        }
    }

    Ok(EdgeListeners {
        http,
        https,
        dns_udp,
        dns_tcp,
    })
}

/// Binds a UDP socket to `addr` with SO_REUSEADDR, nonblocking.
fn bind_udp(addr: SocketAddr) -> Result<UdpSocket, std::io::Error> {
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    let _ = socket.set_reuse_address(true);
    if addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
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
