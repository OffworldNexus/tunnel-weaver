//! Relay admin-host normalisation.
//!
//! The admin host is both what the client dials and the mux server name the
//! handshake transcript binds, and the relay compares that name against its own
//! lowercased host byte for byte. So every host is normalised once — before it
//! is stored and before it is dialled — and the normalised value is the one
//! used for TCP, SNI, `Host` and the transcript alike.

use crate::connect::parse_server_address;

/// Why an admin host was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("'{input}' is not a relay address: {reason}")]
pub struct HostError {
    input: String,
    reason: String,
}

impl HostError {
    fn new(input: &str, reason: impl Into<String>) -> Self {
        Self {
            input: input.to_string(),
            reason: reason.into(),
        }
    }
}

/// Normalises a relay admin host to `host` or `host:port`.
///
/// Lowercases the host, strips a trailing dot, and drops the port when it is
/// the default 443. A pasted `https://host/` is accepted for convenience; any
/// other scheme, path, credentials or whitespace is refused.
pub fn normalize_admin_host(raw: &str) -> Result<String, HostError> {
    let trimmed = raw.trim();
    let bare = trimmed.strip_prefix("https://").unwrap_or(trimmed);
    let bare = bare.strip_suffix('/').unwrap_or(bare);
    if bare.is_empty() {
        return Err(HostError::new(raw, "it is empty"));
    }
    if bare.contains("://") {
        return Err(HostError::new(raw, "only https:// relays are supported"));
    }
    if bare
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, '/' | '@' | '?' | '#'))
    {
        return Err(HostError::new(
            raw,
            "give just the host, e.g. relay.example.com",
        ));
    }

    let (host, port) = parse_server_address(bare).map_err(|e| HostError::new(raw, e))?;
    let host = host.to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host);
    if host.is_empty() || host.ends_with('.') || host.starts_with('.') || host.contains("..") {
        return Err(HostError::new(raw, "the host name is malformed"));
    }
    if port == 0 {
        return Err(HostError::new(raw, "port 0 is not a port"));
    }

    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    Ok(if port == 443 {
        host
    } else {
        format!("{host}:{port}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercases_strips_dot_and_default_port() {
        for raw in [
            "weaver1.offworld.nexus",
            "Weaver1.Offworld.Nexus",
            "WEAVER1.OFFWORLD.NEXUS.",
            "weaver1.offworld.nexus:443",
            " Weaver1.offworld.nexus.:443 ",
            "https://Weaver1.Offworld.Nexus/",
        ] {
            assert_eq!(
                normalize_admin_host(raw).unwrap(),
                "weaver1.offworld.nexus",
                "{raw}"
            );
        }
    }

    #[test]
    fn keeps_a_non_default_port() {
        assert_eq!(
            normalize_admin_host("Relay.Example:8443").unwrap(),
            "relay.example:8443"
        );
        assert_eq!(
            normalize_admin_host("127.0.0.1:38223").unwrap(),
            "127.0.0.1:38223"
        );
        assert_eq!(normalize_admin_host("[::1]:4433").unwrap(), "[::1]:4433");
        assert_eq!(normalize_admin_host("[::1]").unwrap(), "[::1]");
    }

    #[test]
    fn is_idempotent() {
        for raw in ["A.b:8443", "x.Y.", "[::1]:9", "localhost"] {
            let once = normalize_admin_host(raw).unwrap();
            assert_eq!(normalize_admin_host(&once).unwrap(), once);
        }
    }

    #[test]
    fn refuses_junk() {
        for raw in [
            "",
            "  ",
            "http://relay.example",
            "relay.example/pair",
            "user@relay.example",
            "relay.example:http",
            "relay.example:0",
            ".",
            "a..b",
        ] {
            assert!(normalize_admin_host(raw).is_err(), "{raw:?} was accepted");
        }
    }
}
