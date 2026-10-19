//! Relay admin hosts.
//!
//! The admin host is both what the client dials and the server name the mux
//! handshake binds, and the relay compares that name against its own lowercased
//! host byte for byte. So every host is normalised once, and the normalised
//! form is what is stored, dialled, sent as SNI and `Host`, and signed.

use std::fmt;

/// Why an admin host was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("'{input}' is not a relay address: {reason}")]
pub struct HostError {
    input: String,
    reason: &'static str,
}

/// A normalised relay admin host: a lowercase DNS name or IPv4 address, and a
/// port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminHost {
    /// The host name, without the port.
    pub host: String,
    /// The port, 443 unless given.
    pub port: u16,
}

impl AdminHost {
    /// Parses `host` or `host:port`, lowercasing the host and stripping a
    /// trailing dot. A pasted `https://host/` is accepted too.
    pub fn parse(raw: &str) -> Result<Self, HostError> {
        let error = |reason| HostError {
            input: raw.to_string(),
            reason,
        };
        let trimmed = raw.trim();
        let bare = trimmed.strip_prefix("https://").unwrap_or(trimmed);
        let bare = bare.strip_suffix('/').unwrap_or(bare);
        if bare.contains("://") {
            return Err(error("only https:// relays are supported"));
        }
        if bare.contains('/') {
            return Err(error("give just the host, e.g. relay.example.com"));
        }
        let (host, port) = match bare.rsplit_once(':') {
            Some((host, port)) => (
                host,
                port.parse()
                    .map_err(|_| error("the port is not a number"))?,
            ),
            None => (bare, 443),
        };
        let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        if host.is_empty() {
            return Err(error("it has no host name"));
        }
        Ok(Self { host, port })
    }
}

impl fmt::Display for AdminHost {
    /// `host`, or `host:port` when the port is not 443.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.port == 443 {
            f.write_str(&self.host)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// The canonical spelling of a relay admin host.
pub fn normalize_admin_host(raw: &str) -> Result<String, HostError> {
    AdminHost::parse(raw).map(|host| host.to_string())
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
        let parsed = AdminHost::parse("127.0.0.1:38223").unwrap();
        assert_eq!((parsed.host.as_str(), parsed.port), ("127.0.0.1", 38223));
        assert_eq!(parsed.to_string(), "127.0.0.1:38223");
    }

    #[test]
    fn refuses_junk() {
        for raw in [
            "",
            "http://relay.example",
            "relay.example/pair",
            "relay.example:http",
        ] {
            assert!(AdminHost::parse(raw).is_err(), "{raw:?} was accepted");
        }
    }
}
