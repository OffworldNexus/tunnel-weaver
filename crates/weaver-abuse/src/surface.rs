//! The surfaces the relay serves, and which control-plane routes they exempt.
//!
//! A request's *surface* is the transport it arrived on ([`Scheme`]) plus the
//! host role it targeted ([`Host`]). The same host role has different reachable
//! routes per transport — readiness and the mux WebSocket are TLS-only, ACME
//! HTTP-01 is cleartext-only — so the exemption policy is keyed on both. Passes
//! (see [`crate::pass`]) consult the surface to decide what to protect.
//!
//! Everything here is pure and synchronous: no clock, RNG, IO or database.

use http::Method;

/// The transport a request arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Cleartext port 80: ACME HTTP-01 plus a 308 redirect to HTTPS.
    Http,
    /// TLS port 443: the relay's real web surface.
    Https,
}

impl Scheme {
    /// Short stable token for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// Which of the relay's host roles a request targeted.
///
/// On TLS the role comes from certificate coverage (HTTP-01 ⇒ admin, DNS-01 ⇒
/// tunnel zone) and, within the zone, whether the host is the apex or a
/// subdomain. On cleartext the edge redirects before coverage is resolved, so
/// every port-80 request shares the single [`Host::Cleartext`] role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    /// The relay's own admin host: welcome/health/404, never tunnel traffic.
    Admin,
    /// The tunnel apex (`<root>`): welcome/health/404 plus the mux WebSocket.
    TunnelRoot,
    /// A tunnelled subdomain (`<person>-<machine>-<service>.<root>`).
    Tunneled,
    /// Any host on the cleartext redirect surface.
    Cleartext,
}

impl Host {
    /// Short stable token for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::TunnelRoot => "tunnel-root",
            Self::Tunneled => "tunneled",
            Self::Cleartext => "cleartext",
        }
    }
}

/// Where a request arrived: a host role on a transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Surface {
    /// The transport (cleartext or TLS).
    pub scheme: Scheme,
    /// The host role on that transport.
    pub host: Host,
}

impl Surface {
    /// A request on the TLS edge for the given host role.
    pub fn https(host: Host) -> Self {
        Self {
            scheme: Scheme::Https,
            host,
        }
    }

    /// A request on the cleartext redirect edge.
    pub fn cleartext() -> Self {
        Self {
            scheme: Scheme::Http,
            host: Host::Cleartext,
        }
    }
}

/// Control-plane routes each surface must keep reachable.
///
/// These are matched on method *and* path so that an exempt path reached with a
/// forbidden method (e.g. `TRACE /healthz`) is still inspected. The set is
/// intentionally tiny and derived from routes the edge actually serves: the
/// point is that no rule or budget can lock the relay out of its own health,
/// ACME or mux endpoints — not that any host is bypassed wholesale.
pub(crate) fn is_exempt(surface: Surface, method: &Method, path: &str) -> bool {
    if method != Method::GET {
        return false;
    }
    // ACME HTTP-01 is a public convention wherever the challenge is served;
    // the challenge itself is answered on the cleartext edge, but the tunnel
    // and admin hosts may both legitimately see this path over TLS.
    if path.starts_with("/.well-known/acme-challenge/") {
        return true;
    }
    match surface.scheme {
        // Cleartext only serves ACME (handled above) and a redirect.
        Scheme::Http => false,
        Scheme::Https => match surface.host {
            // Readiness is served on the admin host; the apex additionally
            // hosts the mux WebSocket endpoint, which the admin host never
            // serves.
            Host::Admin => path == "/healthz",
            Host::TunnelRoot => path == "/healthz" || path == "/_weaver/connect",
            Host::Tunneled | Host::Cleartext => false,
        },
    }
}

/// Longest request path written to a block log line.
///
/// Scanner URLs are attacker-controlled and unbounded; capping keeps a hostile
/// request from turning one log line into a flood. 128 bytes is far longer than
/// any real path prefix, so legitimate probes are still fully legible.
const MAX_LOGGED_PATH: usize = 128;

/// Render a request path for logging without leaking or flooding.
///
/// The query string (and any fragment) is dropped — it can carry credentials or
/// tokens that must never reach a log — and the remaining path is capped at
/// [`MAX_LOGGED_PATH`] bytes on a char boundary with a truncation marker.
pub fn bounded_path(path: &str) -> String {
    let path = path.split(['?', '#']).next().unwrap_or("");
    if path.len() <= MAX_LOGGED_PATH {
        return path.to_string();
    }
    let mut end = MAX_LOGGED_PATH;
    while end > 0 && !path.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &path[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn https(host: Host) -> Surface {
        Surface::https(host)
    }

    #[test]
    fn exempts_control_plane_routes_only_for_their_surface_and_method() {
        assert!(is_exempt(https(Host::Admin), &Method::GET, "/healthz"));
        assert!(is_exempt(https(Host::TunnelRoot), &Method::GET, "/healthz"));
        assert!(!is_exempt(https(Host::Tunneled), &Method::GET, "/healthz"));
        assert!(is_exempt(
            https(Host::TunnelRoot),
            &Method::GET,
            "/_weaver/connect"
        ));
        assert!(!is_exempt(
            https(Host::Admin),
            &Method::GET,
            "/_weaver/connect"
        ));
        assert!(is_exempt(
            https(Host::Admin),
            &Method::GET,
            "/.well-known/acme-challenge/token"
        ));
        assert!(is_exempt(
            Surface::cleartext(),
            &Method::GET,
            "/.well-known/acme-challenge/token"
        ));
        // Cleartext serves no readiness or mux route.
        assert!(!is_exempt(Surface::cleartext(), &Method::GET, "/healthz"));
        assert!(!is_exempt(
            Surface::cleartext(),
            &Method::GET,
            "/_weaver/connect"
        ));
        // The exemption is method-scoped: an exempt path with a forbidden
        // method is still inspected.
        assert!(!is_exempt(https(Host::Admin), &Method::TRACE, "/healthz"));
        assert!(!is_exempt(
            https(Host::TunnelRoot),
            &Method::TRACE,
            "/_weaver/connect"
        ));
    }

    #[test]
    fn logged_path_drops_query_and_caps_length() {
        // The query string is never logged, even if a caller passes one.
        assert_eq!(bounded_path("/.env?token=secret"), "/.env");
        assert_eq!(bounded_path("/.env"), "/.env");
        assert_eq!(bounded_path("/a#frag"), "/a");

        let long = format!("/{}", "a".repeat(300));
        let capped = bounded_path(&long);
        assert!(capped.ends_with('…'));
        assert_eq!(capped.chars().filter(|c| *c == '…').count(), 1);
        assert!(capped.len() <= MAX_LOGGED_PATH + '…'.len_utf8());
    }

    #[test]
    fn logged_path_cap_respects_char_boundaries() {
        // A multi-byte character straddling the cap must not be split (which
        // would panic on slicing).
        let path = format!("/{}€", "a".repeat(MAX_LOGGED_PATH - 2));
        let capped = bounded_path(&path);
        assert!(capped.ends_with('…'));
    }
}
