//! Systemd notification integration via UNIX domain datagram sockets.
//!
//! Communicates daemon readiness and stopping states to systemd using the protocol
//! specified in sd_notify(3) over the socket defined in `NOTIFY_SOCKET`.

use std::env;
use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::Path;

/// Sends a raw notification message to the systemd supervisor if `NOTIFY_SOCKET` is set.
///
/// Returns `Ok(true)` if a notification was successfully transmitted, or `Ok(false)`
/// if `NOTIFY_SOCKET` was absent (no-op).
pub fn notify(state: &str) -> io::Result<bool> {
    let socket_path = match env::var_os("NOTIFY_SOCKET") {
        Some(val) if !val.is_empty() => val,
        _ => return Ok(false),
    };

    let sock = UnixDatagram::unbound()?;

    #[cfg(target_os = "linux")]
    {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::ffi::OsStrExt;

        let bytes = socket_path.as_bytes();
        if let Some(abstract_name) = bytes.strip_prefix(b"@") {
            let addr = std::os::unix::net::SocketAddr::from_abstract_name(abstract_name)?;
            sock.connect_addr(&addr)?;
            sock.send(state.as_bytes())?;
            return Ok(true);
        }
    }

    sock.send_to(state.as_bytes(), Path::new(&socket_path))?;
    Ok(true)
}

/// Notifies systemd that listeners are active and the daemon is ready to receive connections.
pub fn notify_ready() -> io::Result<bool> {
    notify("READY=1\nSTATUS=listening; certificate: pending\n")
}

/// Notifies systemd that the daemon is initiating graceful shutdown.
pub fn notify_stopping() -> io::Result<bool> {
    notify("STOPPING=1\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_notify_noop_when_unset() {
        // Ensure NOTIFY_SOCKET is unset in this thread/env
        unsafe {
            env::remove_var("NOTIFY_SOCKET");
        }
        let res = notify_ready().expect("notify should succeed as no-op");
        assert!(!res);
    }

    #[test]
    fn test_notify_delivers_to_socket() {
        let dir = tempdir().unwrap();
        let sock_path = dir.path().join("notify.sock");
        let listener = UnixDatagram::bind(&sock_path).unwrap();

        unsafe {
            env::set_var("NOTIFY_SOCKET", &sock_path);
        }

        let res = notify_ready().expect("notify should succeed");
        assert!(res);

        let mut buf = [0u8; 512];
        let (len, _) = listener.recv_from(&mut buf).unwrap();
        let msg = std::str::from_utf8(&buf[..len]).unwrap();
        assert!(msg.contains("READY=1"));
        assert!(msg.contains("STATUS=listening; certificate: pending"));

        let res = notify_stopping().expect("notify stopping should succeed");
        assert!(res);
        let (len, _) = listener.recv_from(&mut buf).unwrap();
        let msg = std::str::from_utf8(&buf[..len]).unwrap();
        assert!(msg.contains("STOPPING=1"));

        unsafe {
            env::remove_var("NOTIFY_SOCKET");
        }
    }
}
