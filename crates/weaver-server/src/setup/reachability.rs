//! Throwaway listener and self-reachability verification probes.
//!
//! Binds temporary listeners on target ports (80, 443, and 53), connects back
//! via resolved public IP addresses, and validates a random challenge token
//! to ensure incoming public traffic lands on this machine.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::broadcast;
use tracing::{debug, warn};

use super::dns::generate_random_hex;
use super::planner::PortReachability;

/// Scans `/proc/net/tcp{,6}` and `/proc/net/udp{,6}` for socket inodes bound
/// to the given port.
///
/// TCP listening sockets are in state `0A` (LISTEN); an unconnected UDP socket
/// is in state `07`. Scanning both catches the `systemd-resolved` stub, which
/// holds `127.0.0.53:53` over UDP as well as TCP.
#[cfg(target_os = "linux")]
fn find_listening_inodes(port: u16) -> HashSet<u64> {
    let mut inodes = HashSet::new();
    let port_hex = format!("{port:04X}");

    // (proc path, socket state) pairs. `0A` = TCP_LISTEN, `07` = UDP
    // unconnected/socket.
    let sources = [
        ("/proc/net/tcp", "0A"),
        ("/proc/net/tcp6", "0A"),
        ("/proc/net/udp", "07"),
        ("/proc/net/udp6", "07"),
    ];

    for (path, expected_state) in sources {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 10 {
                    let local_addr = fields[1];
                    let state = fields[3];
                    let inode_str = fields[9];

                    if state == expected_state
                        && local_addr.ends_with(&format!(":{port_hex}"))
                        && let Ok(inode) = inode_str.parse::<u64>()
                    {
                        inodes.insert(inode);
                    }
                }
            }
        }
    }
    inodes
}

/// Identifies the process ID and command name listening on the specified port.
#[cfg(target_os = "linux")]
pub fn find_occupying_process(port: u16) -> Option<(u32, String)> {
    let target_inodes = find_listening_inodes(port);
    if target_inodes.is_empty() {
        return None;
    }

    let proc_dir = std::fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        let file_name = entry.file_name();
        let name_str = file_name.to_str()?;
        let Ok(pid) = name_str.parse::<u32>() else {
            continue;
        };

        let fd_dir = Path::new("/proc").join(name_str).join("fd");
        if let Ok(entries) = std::fs::read_dir(fd_dir) {
            for fd_entry in entries.flatten() {
                if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                    let link_str = link.to_string_lossy();
                    if let Some(rest) = link_str.strip_prefix("socket:[")
                        && let Some(inode_str) = rest.strip_suffix(']')
                        && let Ok(inode) = inode_str.parse::<u64>()
                        && target_inodes.contains(&inode)
                    {
                        let comm_path = Path::new("/proc").join(name_str).join("comm");
                        let comm = std::fs::read_to_string(comm_path)
                            .map(|s| s.trim().to_string())
                            .unwrap_or_else(|_| "unknown".to_string());
                        return Some((pid, comm));
                    }
                }
            }
        }
    }
    None
}

/// Stub for non-Linux platforms where `/proc` is not available.
#[cfg(not(target_os = "linux"))]
pub fn find_occupying_process(_port: u16) -> Option<(u32, String)> {
    None
}

/// Creates a dual-stack or IPv4 listener on the specified port.
fn bind_port_listener(port: u16) -> Result<TcpListener, String> {
    use socket2::{Domain, Protocol, Socket, Type};

    // Attempt dual-stack IPv6 listener first
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))
        .map_err(|e| format!("failed to create socket: {e}"))?;

    let _ = socket.set_only_v6(false);
    let _ = socket.set_reuse_address(true);
    let _ = socket.set_nonblocking(true);

    let v6_addr: SocketAddr = format!("[::]:{port}").parse().unwrap();
    if socket.bind(&v6_addr.into()).is_ok() && socket.listen(128).is_ok() {
        let std_listener: std::net::TcpListener = socket.into();
        return TcpListener::from_std(std_listener)
            .map_err(|e| format!("failed to register tokio listener: {e}"));
    }

    // Fallback to IPv4 listener
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .map_err(|e| format!("failed to create IPv4 socket: {e}"))?;
    let _ = socket.set_reuse_address(true);
    let _ = socket.set_nonblocking(true);

    let v4_addr: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();
    if let Err(e) = socket.bind(&v4_addr.into()) {
        if let Some((pid, comm)) = find_occupying_process(port) {
            return Err(format!("port {port} is occupied by PID {pid} ('{comm}')"));
        }
        return Err(format!("port {port} cannot be bound: {e}"));
    }

    socket
        .listen(128)
        .map_err(|e| format!("failed to listen on port {port}: {e}"))?;

    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
        .map_err(|e| format!("failed to register tokio listener: {e}"))
}

/// Binds a TCP listener on an explicit address (no wildcard), used for port 53
/// so the probe mirrors production and does not collide with the resolved stub.
fn bind_explicit_listener(ip: IpAddr, port: u16) -> Result<TcpListener, String> {
    use socket2::{Domain, Protocol, Socket, Type};

    let addr = SocketAddr::new(ip, port);
    let domain = if ip.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .map_err(|e| format!("failed to create socket: {e}"))?;
    let _ = socket.set_reuse_address(true);
    let _ = socket.set_nonblocking(true);
    if ip.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    socket
        .bind(&addr.into())
        .map_err(|e| format!("cannot bind {addr}: {e}"))?;
    socket
        .listen(128)
        .map_err(|e| format!("failed to listen on {addr}: {e}"))?;
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
        .map_err(|e| format!("failed to register tokio listener: {e}"))
}

/// Runs an ephemeral challenge-response responder on the given listener.
async fn run_challenge_responder(
    listener: TcpListener,
    challenge: Arc<String>,
    mut shutdown: broadcast::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = shutdown.recv() => break,
            accept_res = listener.accept() => {
                let Ok((mut stream, _peer)) = accept_res else {
                    continue;
                };
                let challenge_token = Arc::clone(&challenge);
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = stream.read(&mut buf).await
                        && n > 0
                    {
                        let msg = String::from_utf8_lossy(&buf[..n]);
                        if msg.contains(challenge_token.as_str()) {
                            let response = format!("WEAVER-CONFIRM {}\r\n", challenge_token);
                            let _ = stream.write_all(response.as_bytes()).await;
                            let _ = stream.flush().await;
                        }
                    }
                });
            }
        }
    }
}

/// Tests whether outbound connections to the target IP on the given port route back to our challenge listener.
async fn probe_ip_port(ip: IpAddr, port: u16, challenge: &str) -> Result<(), String> {
    let target = SocketAddr::new(ip, port);
    let connect_fut = TcpStream::connect(target);

    let mut stream = match tokio::time::timeout(Duration::from_secs(5), connect_fut).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(format!("connection refused/failed to {target}: {e}")),
        Err(_) => return Err(format!("connection timed out to {target}")),
    };

    let probe_payload = format!("WEAVER-PROBE {challenge}\r\n");
    if let Err(e) = stream.write_all(probe_payload.as_bytes()).await {
        return Err(format!("failed to send challenge probe to {target}: {e}"));
    }
    let _ = stream.flush().await;

    let mut response_buf = [0u8; 512];
    let read_fut = stream.read(&mut response_buf);
    let n = match tokio::time::timeout(Duration::from_secs(5), read_fut).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            return Err(format!(
                "failed to read challenge response from {target}: {e}"
            ));
        }
        Err(_) => {
            return Err(format!(
                "timed out waiting for challenge response from {target}"
            ));
        }
    };

    let response = String::from_utf8_lossy(&response_buf[..n]);
    let expected = format!("WEAVER-CONFIRM {challenge}");
    if response.contains(&expected) {
        Ok(())
    } else {
        Err(format!(
            "response from {target} did not contain valid self-challenge confirmation"
        ))
    }
}

/// Tests whether a UDP datagram sent to `ip`:`port` lands back on a throwaway
/// socket bound to that explicit public address, proving the relay's DNS
/// datagram port is open. The socket binds the relay address directly (never a
/// wildcard), mirroring production and avoiding the `systemd-resolved` stub on
/// `127.0.0.53`.
async fn probe_udp_ip_port(ip: IpAddr, port: u16, challenge: &str) -> Result<(), String> {
    let bind = SocketAddr::new(ip, port);
    let responder = match UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(e) => {
            if let Some((pid, comm)) = find_occupying_process(port) {
                return Err(format!(
                    "could not bind UDP {bind} (occupied by PID {pid} '{comm}'): {e}"
                ));
            }
            return Err(format!("could not bind UDP {bind}: {e}"));
        }
    };

    let prober_bind = if ip.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let prober = UdpSocket::bind(prober_bind)
        .await
        .map_err(|e| format!("could not bind UDP probe socket: {e}"))?;
    prober
        .connect(bind)
        .await
        .map_err(|e| format!("could not connect UDP probe socket to {bind}: {e}"))?;

    let probe_payload = format!("WEAVER-PROBE-UDP {challenge}");
    prober
        .send(probe_payload.as_bytes())
        .await
        .map_err(|e| format!("failed to send UDP challenge to {bind}: {e}"))?;

    // The responder receives the datagram (routed back via the public address)
    // and answers the source.
    let mut buf = [0u8; 512];
    let recv = tokio::time::timeout(Duration::from_secs(5), responder.recv_from(&mut buf));
    let (n, peer) = match recv.await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(format!("UDP challenge receive on {bind} failed: {e}")),
        Err(_) => return Err(format!("timed out waiting for UDP challenge on {bind}")),
    };
    if !String::from_utf8_lossy(&buf[..n]).contains(challenge) {
        return Err(format!("unexpected UDP payload received on {bind}"));
    }

    let confirm = format!("WEAVER-CONFIRM-UDP {challenge}");
    responder
        .send_to(confirm.as_bytes(), peer)
        .await
        .map_err(|e| format!("failed to send UDP confirmation from {bind}: {e}"))?;

    let mut reply = [0u8; 512];
    let read = tokio::time::timeout(Duration::from_secs(5), prober.recv(&mut reply));
    let rn = match read.await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(format!("failed to read UDP confirmation: {e}")),
        Err(_) => {
            return Err(format!(
                "timed out waiting for UDP confirmation from {bind}"
            ));
        }
    };
    if !String::from_utf8_lossy(&reply[..rn]).contains(&confirm) {
        return Err(format!("UDP confirmation received on {bind} did not match"));
    }
    Ok(())
}

/// Performs the complete self-reachability check for ports 80, 443, and 53
/// across all resolved public IPs.
///
/// Port 53 is exercised over both TCP and UDP because the authoritative DNS
/// responder serves both; either failing marks the port unreachable.
pub async fn verify_reachability(
    public_ips: &[IpAddr],
) -> (PortReachability, PortReachability, PortReachability) {
    if public_ips.is_empty() {
        return (
            PortReachability::Failed("no public IPs provided".into()),
            PortReachability::Failed("no public IPs provided".into()),
            PortReachability::Failed("no public IPs provided".into()),
        );
    }

    let token = generate_random_hex(16);
    let challenge = Arc::new(format!("weaver-reachability-{token}"));
    let udp_challenge = format!("weaver-reachability-udp-{token}");

    // 1. Bind each TCP listener independently so a failure on one port does not
    //    hide the state of the others.
    let listener_80 = match bind_port_listener(80) {
        Ok(l) => Some(l),
        Err(e) => {
            warn!(error = %e, "Failed to bind port 80 for reachability probe");
            None
        }
    };
    let listener_443 = match bind_port_listener(443) {
        Ok(l) => Some(l),
        Err(e) => {
            warn!(error = %e, "Failed to bind port 443 for reachability probe");
            None
        }
    };
    let listener_53 = {
        // Port 53 must be bound on the explicit relay addresses, never a
        // wildcard: `[::]:53`/`0.0.0.0:53` collides with the systemd-resolved
        // stub on `127.0.0.53:53`, the exact failure OFF-190 avoids. We
        // therefore bind one listener per public IP.
        let mut listeners = Vec::new();
        for &ip in public_ips {
            match bind_explicit_listener(ip, 53) {
                Ok(l) => listeners.push(l),
                Err(e) => {
                    warn!(%ip, error = %e, "Failed to bind TCP port 53 for reachability probe");
                }
            }
        }
        listeners
    };

    let (shutdown_tx, _) = broadcast::channel(1);

    let responder_80_task = listener_80.map(|l| {
        tokio::spawn(run_challenge_responder(
            l,
            Arc::clone(&challenge),
            shutdown_tx.subscribe(),
        ))
    });
    let responder_443_task = listener_443.map(|l| {
        tokio::spawn(run_challenge_responder(
            l,
            Arc::clone(&challenge),
            shutdown_tx.subscribe(),
        ))
    });
    let responder_53_tasks: Vec<_> = listener_53
        .into_iter()
        .map(|l| {
            tokio::spawn(run_challenge_responder(
                l,
                Arc::clone(&challenge),
                shutdown_tx.subscribe(),
            ))
        })
        .collect();

    // Allow responders to start listening
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 2. Test each port for every resolved IP.
    let port_80_result = if responder_80_task.is_some() {
        probe_tcp_all(public_ips, 80, &challenge).await
    } else {
        PortReachability::Failed("failed to bind port 80".into())
    };

    let port_443_result = if responder_443_task.is_some() {
        probe_tcp_all(public_ips, 443, &challenge).await
    } else {
        PortReachability::Failed("failed to bind port 443".into())
    };

    let mut port_53_result = if responder_53_tasks.is_empty() {
        PortReachability::Failed("failed to bind TCP port 53 on the relay addresses".into())
    } else {
        probe_tcp_all(public_ips, 53, &challenge).await
    };

    // 3. UDP 53: every public IP must accept a datagram on the DNS port.
    if matches!(port_53_result, PortReachability::ReachedSelf) {
        for &ip in public_ips {
            if let Err(e) = probe_udp_ip_port(ip, 53, &udp_challenge).await {
                warn!(ip = %ip, error = %e, "Port 53 UDP reachability verification failed");
                port_53_result = PortReachability::Failed(format!("UDP: {e}"));
                break;
            }
            debug!(ip = %ip, "Port 53 UDP self-reachability verified");
        }
    }

    // Stop responders and wait for tasks to finish
    let _ = shutdown_tx.send(());
    if let Some(task) = responder_80_task {
        let _ = task.await;
    }
    if let Some(task) = responder_443_task {
        let _ = task.await;
    }
    for task in responder_53_tasks {
        let _ = task.await;
    }

    (port_80_result, port_443_result, port_53_result)
}

/// Probes one TCP port across every public IP with the challenge handshake.
async fn probe_tcp_all(public_ips: &[IpAddr], port: u16, challenge: &str) -> PortReachability {
    for &ip in public_ips {
        if let Err(e) = probe_ip_port(ip, port, challenge).await {
            warn!(ip = %ip, port, error = %e, "TCP self-reachability verification failed");
            return PortReachability::Failed(e);
        }
        debug!(ip = %ip, port, "TCP self-reachability verified");
    }
    PortReachability::ReachedSelf
}
