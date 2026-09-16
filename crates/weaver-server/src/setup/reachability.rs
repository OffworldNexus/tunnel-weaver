//! Throwaway listener and self-reachability verification probes.
//!
//! Binds temporary listeners on target ports (80 and 443), connects back
//! via resolved public IP addresses, and validates a random challenge token
//! to ensure incoming public traffic lands on this machine.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tracing::{debug, warn};

use super::dns::generate_random_hex;
use super::planner::PortReachability;

/// Scans `/proc/net/tcp` and `/proc/net/tcp6` for socket inodes listening on the given port.
#[cfg(target_os = "linux")]
fn find_listening_inodes(port: u16) -> HashSet<u64> {
    let mut inodes = HashSet::new();
    let port_hex = format!("{port:04X}");

    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 10 {
                    let local_addr = fields[1];
                    let state = fields[3];
                    let inode_str = fields[9];

                    // State 0A is TCP_LISTEN
                    if state == "0A"
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

/// Performs the complete self-reachability check for port 80 and port 443 across all resolved public IPs.
pub async fn verify_reachability(public_ips: &[IpAddr]) -> (PortReachability, PortReachability) {
    if public_ips.is_empty() {
        return (
            PortReachability::Failed("no public IPs provided".into()),
            PortReachability::Failed("no public IPs provided".into()),
        );
    }

    let token = generate_random_hex(16);
    let challenge = Arc::new(format!("weaver-reachability-{token}"));

    // 1. Setup port 80 listener
    let listener_80 = match bind_port_listener(80) {
        Ok(l) => l,
        Err(e) => {
            return (
                PortReachability::Failed(format!("failed to bind port 80: {e}")),
                PortReachability::Failed("skipped due to port 80 bind failure".into()),
            );
        }
    };

    // 2. Setup port 443 listener
    let listener_443 = match bind_port_listener(443) {
        Ok(l) => l,
        Err(e) => {
            return (
                PortReachability::Failed("skipped due to port 443 bind failure".into()),
                PortReachability::Failed(format!("failed to bind port 443: {e}")),
            );
        }
    };

    let (shutdown_tx, _) = broadcast::channel(1);

    let responder_80_task = tokio::spawn(run_challenge_responder(
        listener_80,
        Arc::clone(&challenge),
        shutdown_tx.subscribe(),
    ));

    let responder_443_task = tokio::spawn(run_challenge_responder(
        listener_443,
        Arc::clone(&challenge),
        shutdown_tx.subscribe(),
    ));

    // Allow responders to start listening
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Test port 80 for every resolved IP
    let mut port_80_result = PortReachability::ReachedSelf;
    for &ip in public_ips {
        if let Err(e) = probe_ip_port(ip, 80, &challenge).await {
            warn!(ip = %ip, error = %e, "Port 80 reachability verification failed");
            port_80_result = PortReachability::Failed(e);
            break;
        }
        debug!(ip = %ip, "Port 80 self-reachability verified");
    }

    // Test port 443 for every resolved IP
    let mut port_443_result = PortReachability::ReachedSelf;
    for &ip in public_ips {
        if let Err(e) = probe_ip_port(ip, 443, &challenge).await {
            warn!(ip = %ip, error = %e, "Port 443 reachability verification failed");
            port_443_result = PortReachability::Failed(e);
            break;
        }
        debug!(ip = %ip, "Port 443 self-reachability verified");
    }

    // Stop responders and wait for tasks to finish
    let _ = shutdown_tx.send(());
    let _ = responder_80_task.await;
    let _ = responder_443_task.await;

    (port_80_result, port_443_result)
}
