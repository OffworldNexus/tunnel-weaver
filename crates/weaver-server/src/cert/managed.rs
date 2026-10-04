//! The declarative catalog of certificates the relay manages.
//!
//! There is no "zone" type: a certificate *is* its covered identifiers. The
//! relay keeps a small, fixed set of certificates issued and renewed — the
//! single-name admin certificate (HTTP-01) and the tunnel wildcard
//! `[<tunnel>, *.<tunnel>]` (DNS-01) — and every hostname is mapped to the
//! managed certificate whose identifiers cover it. The mapping lives here so
//! the DNS responder, the TLS resolver, the certificate job and the control
//! surface cannot disagree about what is covered.

use instant_acme::ChallengeType;

use crate::config::Config;
use crate::store::names::normalize_domain;

/// The ACME DCV mechanism behind a managed certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validation {
    /// DNS-01: publish a `_acme-challenge` TXT record from our own zone.
    Dns01,
    /// HTTP-01: answer a token under `/.well-known/acme-challenge/`.
    Http01,
}

impl Validation {
    /// The persisted label (`certificates.validation`).
    pub fn label(self) -> &'static str {
        match self {
            Validation::Dns01 => "dns-01",
            Validation::Http01 => "http-01",
        }
    }

    /// The `instant_acme` challenge type this mechanism answers.
    pub fn challenge_type(self) -> ChallengeType {
        match self {
            Validation::Dns01 => ChallengeType::Dns01,
            Validation::Http01 => ChallengeType::Http01,
        }
    }

    /// Parses a persisted validation label, defaulting to DNS-01.
    pub fn from_label(label: &str) -> Validation {
        match label {
            "http-01" => Validation::Http01,
            _ => Validation::Dns01,
        }
    }
}

/// One certificate the relay keeps issued and renewed.
///
/// `name` is the certificate store key; `identifiers` are the DNS names and
/// patterns the certificate covers, exactly as they are sent in the ACME order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedCert {
    /// Certificate store key (the tunnel apex, or the admin hostname).
    pub name: String,
    /// Covered DNS identifiers: exact names, and `*.` patterns matching exactly
    /// one label.
    pub identifiers: Vec<String>,
    /// The ACME DCV mechanism used to issue it.
    pub validation: Validation,
}

impl ManagedCert {
    /// True when any identifier carries a wildcard SAN.
    pub fn wildcard(&self) -> bool {
        self.identifiers.iter().any(|id| id.starts_with("*."))
    }

    /// True when this certificate covers `host`.
    pub fn covers(&self, host: &str) -> bool {
        self.identifiers
            .iter()
            .any(|id| identifier_covers(id, host))
    }
}

/// True when the DNS `pattern` covers `host`.
///
/// An exact pattern matches the same name. A `*.` pattern matches exactly one
/// label beneath its base: `*.example.com` covers `a.example.com` but not
/// `example.com` or `a.b.example.com`. Comparison ignores case and a trailing
/// dot.
pub fn identifier_covers(pattern: &str, host: &str) -> bool {
    let pattern = normalize_domain(pattern);
    let host = normalize_domain(host);
    match pattern.strip_prefix("*.") {
        Some(base) if !base.is_empty() => match host.strip_suffix(base) {
            Some(prefix) => match prefix.strip_suffix('.') {
                Some(label) => !label.is_empty() && !label.contains('.'),
                None => false,
            },
            None => false,
        },
        Some(_) => false,
        None => host == pattern,
    }
}

/// The relay's managed certificates, built from configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedCerts {
    certs: Vec<ManagedCert>,
}

impl ManagedCerts {
    /// Builds the tunnel wildcard and the admin certificate from configuration.
    pub fn from_config(config: &Config) -> Self {
        let tunnel = normalize_domain(&config.tunnel_domain);
        let admin = normalize_domain(&config.admin_domain);
        Self {
            certs: vec![
                ManagedCert {
                    name: admin.clone(),
                    identifiers: vec![admin.clone()],
                    validation: Validation::Http01,
                },
                ManagedCert {
                    name: tunnel.clone(),
                    identifiers: vec![tunnel.clone(), format!("*.{tunnel}")],
                    validation: Validation::Dns01,
                },
            ],
        }
    }

    /// A single tunnel wildcard for `tunnel`, without an admin split.
    ///
    /// Used by tests and by callers that only model the tunnel zone.
    pub fn for_tunnel(tunnel: impl AsRef<str>) -> Self {
        let tunnel = normalize_domain(tunnel.as_ref());
        Self {
            certs: vec![ManagedCert {
                name: tunnel.clone(),
                identifiers: vec![tunnel.clone(), format!("*.{tunnel}")],
                validation: Validation::Dns01,
            }],
        }
    }

    /// Every managed certificate, in a stable order (admin first).
    pub fn all(&self) -> &[ManagedCert] {
        &self.certs
    }

    /// The tunnel wildcard certificate, if the catalog has one.
    pub fn wildcard(&self) -> Option<&ManagedCert> {
        self.certs.iter().find(|c| c.wildcard())
    }

    /// The tunnel zone apex (the wildcard certificate's name), if any.
    pub fn tunnel_domain(&self) -> Option<&str> {
        self.wildcard().map(|c| c.name.as_str())
    }

    /// The managed certificate stored under `name`, if any.
    pub fn by_name(&self, name: &str) -> Option<&ManagedCert> {
        let name = normalize_domain(name);
        self.certs.iter().find(|c| c.name == name)
    }

    /// The managed certificate covering `host`, if any.
    pub fn cert_for(&self, host: &str) -> Option<&ManagedCert> {
        self.certs.iter().find(|c| c.covers(host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_pattern_matches_only_itself() {
        assert!(identifier_covers("example.com", "example.com"));
        assert!(identifier_covers("Example.COM.", "example.com"));
        assert!(!identifier_covers("example.com", "www.example.com"));
        assert!(!identifier_covers("example.com", "other.net"));
    }

    #[test]
    fn wildcard_matches_exactly_one_label() {
        assert!(identifier_covers("*.example.com", "a.example.com"));
        assert!(identifier_covers("*.example.com", "A.Example.COM."));
        assert!(!identifier_covers("*.example.com", "example.com"));
        assert!(!identifier_covers("*.example.com", "a.b.example.com"));
        assert!(!identifier_covers("*.example.com", "notexample.com"));
    }

    #[test]
    fn catalog_splits_admin_and_tunnel() {
        let tunnel = ManagedCerts::for_tunnel("example.com");
        assert_eq!(tunnel.all().len(), 1);
        assert_eq!(
            tunnel
                .cert_for("poc-laptop-web.example.com")
                .map(|c| &c.name),
            Some(&"example.com".to_string())
        );
        assert!(tunnel.cert_for("relay.example.net").is_none());
        assert!(tunnel.cert_for("a.b.example.com").is_none());
    }
}
