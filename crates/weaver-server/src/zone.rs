//! The relay's DNS zone model: the delegated tunnel root and the admin host.
//!
//! OFF-190/OFF-198 give the relay two names with one rule each, and both rules
//! used to be re-implemented wherever they were needed (authoritative DNS,
//! the certificate resolver, the certificate manager, the HTTPS edge). This
//! module owns them so they cannot drift:
//!
//! * the **tunnel zone** is `<root>` itself plus exactly one label beneath it
//!   (`*.<root>` covers one label, so `a.b.<root>` is out of zone), and
//! * each hostname maps to the one managed certificate that covers it — the
//!   tunnel wildcard for anything in the tunnel zone, or the single-name admin
//!   certificate for the admin hostname (which lives *outside* the delegation).
//!
//! All comparison is case-insensitive with any trailing dot ignored.

/// A managed certificate, keyed by the domain name it is stored under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertKind {
    /// The tunnel wildcard `[<root>, *.<root>]`, issued with DNS-01.
    Root,
    /// The relay's own single-name admin certificate, issued with HTTP-01.
    Admin,
}

impl CertKind {
    /// Both managed certificates, tunnel wildcard first. Stable order for the
    /// renewal loop and the control surface.
    pub const ALL: [CertKind; 2] = [CertKind::Root, CertKind::Admin];
}

/// Lowercases a domain and strips any trailing dot, for comparison.
pub fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// The two names that define the relay's serving area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    root: String,
    admin: String,
}

impl Zone {
    /// Builds a zone from the tunnel root and the admin hostname, normalized.
    pub fn new(root: impl AsRef<str>, admin: impl AsRef<str>) -> Self {
        Self {
            root: normalize_domain(root.as_ref()),
            admin: normalize_domain(admin.as_ref()),
        }
    }

    /// The delegated tunnel zone apex, lowercased, no trailing dot.
    pub fn root(&self) -> &str {
        &self.root
    }

    /// The relay's own admin hostname, lowercased, no trailing dot.
    pub fn admin(&self) -> &str {
        &self.admin
    }

    /// The certificate-store key (the domain name) for a managed certificate.
    pub fn cert_name(&self, kind: CertKind) -> &str {
        match kind {
            CertKind::Root => &self.root,
            CertKind::Admin => &self.admin,
        }
    }

    /// Which managed certificate a certificate-store key refers to.
    ///
    /// The two names never overlap (`Config::load` rejects an admin nested
    /// under the tunnel zone), so an exact match on the admin name is enough;
    /// everything else is the tunnel wildcard.
    pub fn kind_of(&self, cert_name: &str) -> CertKind {
        if normalize_domain(cert_name) == self.admin {
            CertKind::Admin
        } else {
            CertKind::Root
        }
    }

    /// True if `host` is the tunnel apex or exactly one label beneath it.
    ///
    /// The admin hostname is deliberately *not* in the tunnel zone: it lives
    /// outside the delegation and is served by its own certificate.
    pub fn in_tunnel_zone(&self, host: &str) -> bool {
        let host = normalize_domain(host);
        if host == self.root {
            return true;
        }
        match host.strip_suffix(&format!(".{}", self.root)) {
            Some(label) => !label.is_empty() && !label.contains('.'),
            None => false,
        }
    }

    /// The managed certificate that covers `host`, if any.
    ///
    /// The tunnel zone is checked first: the admin hostname is never inside it
    /// (an admin nested under the tunnel zone is rejected at config load), and
    /// for a degenerate configuration where the two names are equal the tunnel
    /// wildcard is the right answer.
    pub fn covering_cert(&self, host: &str) -> Option<CertKind> {
        let host = normalize_domain(host);
        if self.in_tunnel_zone(&host) {
            return Some(CertKind::Root);
        }
        if host == self.admin {
            return Some(CertKind::Admin);
        }
        None
    }

    /// The certificate-store key covering `host`, if any.
    pub fn cert_name_for(&self, host: &str) -> Option<String> {
        self.covering_cert(host)
            .map(|kind| self.cert_name(kind).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone() -> Zone {
        Zone::new("Example.COM.", "relay.example.net")
    }

    #[test]
    fn normalizes_both_names() {
        let z = zone();
        assert_eq!(z.root(), "example.com");
        assert_eq!(z.admin(), "relay.example.net");
    }

    #[test]
    fn tunnel_zone_is_apex_plus_one_label() {
        let z = zone();
        assert!(z.in_tunnel_zone("example.com"));
        assert!(z.in_tunnel_zone("Example.COM."));
        assert!(z.in_tunnel_zone("poc-laptop-web.example.com"));
        assert!(!z.in_tunnel_zone("a.b.example.com"));
        assert!(!z.in_tunnel_zone("other.net"));
        // The admin host is outside the tunnel zone even though the relay owns
        // its certificate.
        assert!(!z.in_tunnel_zone("relay.example.net"));
    }

    #[test]
    fn covering_cert_splits_tunnel_and_admin() {
        let z = zone();
        assert_eq!(z.covering_cert("example.com"), Some(CertKind::Root));
        assert_eq!(
            z.covering_cert("poc-laptop-web.example.com"),
            Some(CertKind::Root)
        );
        assert_eq!(z.covering_cert("relay.example.net"), Some(CertKind::Admin));
        assert_eq!(z.covering_cert("a.b.example.com"), None);
        assert_eq!(z.covering_cert("other.net"), None);
    }

    #[test]
    fn cert_names_and_kinds_round_trip() {
        let z = zone();
        assert_eq!(z.cert_name(CertKind::Root), "example.com");
        assert_eq!(z.cert_name(CertKind::Admin), "relay.example.net");
        assert_eq!(z.kind_of("example.com"), CertKind::Root);
        assert_eq!(z.kind_of("RELAY.example.NET."), CertKind::Admin);
        assert_eq!(
            z.cert_name_for("relay.example.net").as_deref(),
            Some("relay.example.net")
        );
    }
}
