//! Target grammar for `weave start`, and the service→target mapping.
//!
//! A target names the local HTTP origin a service proxies to. The grammar is
//! deliberately tiny: `[host:]port`, `http://host[:port]` or
//! `https://host[:port]`. A target carries no path — one service maps to one
//! origin 1:1 and the visitor path and query are forwarded verbatim, so a
//! target with a non-empty path (e.g. `http://host/app`) is a usage error.
//! A bare trailing slash (`http://host/`) is normalized away.

use std::fmt;

use weaver_proto::is_valid_dns_label;

/// Whether the origin is spoken to over plaintext or TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetScheme {
    /// Plaintext HTTP/1.1 (never h2c).
    Http,
    /// HTTPS, with h1 or h2 selected by ALPN.
    Https,
}

impl TargetScheme {
    /// Lowercase scheme token as it appears in a URL.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    /// Default port when the target omits one.
    fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

/// A parsed local origin a service proxies to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    /// Plaintext or TLS.
    pub scheme: TargetScheme,
    /// Host the client connects to (DNS name or IP literal).
    pub host: String,
    /// Port on `host`.
    pub port: u16,
}

impl Target {
    /// Parse one target token per the grammar.
    ///
    /// `https://` targets are verified against the OS trust store unless the
    /// service is listed in `--insecure-target`.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err("target cannot be empty".to_string());
        }

        if let Some(rest) = raw
            .strip_prefix("http://")
            .map(|r| (TargetScheme::Http, r))
            .or_else(|| {
                raw.strip_prefix("https://")
                    .map(|r| (TargetScheme::Https, r))
            })
        {
            let (scheme, rest) = rest;
            return Self::parse_authority(scheme, rest);
        }

        // No scheme: either a bare port, or `host:port`. Both mean http.
        if raw.contains("://") {
            return Err(format!("unsupported target scheme in '{raw}'"));
        }
        // Reject anything with a path/query/fragment even without a scheme.
        if raw.contains('/') || raw.contains('?') || raw.contains('#') {
            return Err(format!(
                "target '{raw}' must not carry a path; use host:port or a scheme"
            ));
        }
        if let Ok(port) = raw.parse::<u16>() {
            if port == 0 {
                return Err("target port cannot be 0".to_string());
            }
            return Ok(Self {
                scheme: TargetScheme::Http,
                host: "localhost".to_string(),
                port,
            });
        }
        let Some((host, port_str)) = raw.rsplit_once(':') else {
            return Err(format!(
                "target '{raw}' is ambiguous; use a scheme (http://{raw}) or a port"
            ));
        };
        if host.is_empty() {
            return Err("target host cannot be empty".to_string());
        }
        let port = port_str
            .parse::<u16>()
            .map_err(|e| format!("invalid port in target '{raw}': {e}"))?;
        if port == 0 {
            return Err("target port cannot be 0".to_string());
        }
        Ok(Self {
            scheme: TargetScheme::Http,
            host: host.to_string(),
            port,
        })
    }

    fn parse_authority(scheme: TargetScheme, rest: &str) -> Result<Self, String> {
        // Split path/query/fragment off: only an empty path or a bare "/" is
        // allowed, everything else is a usage error.
        let (authority, suffix) = match rest.find(['/', '?', '#']) {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, ""),
        };
        if !suffix.is_empty() && suffix != "/" {
            return Err(format!(
                "target '{s}://{rest}' must not carry a path; one service maps to one origin",
                s = scheme.as_str()
            ));
        }
        if authority.is_empty() {
            return Err("target host cannot be empty".to_string());
        }
        if authority.starts_with('[') {
            // IPv6 literal: [::1] or [::1]:8080
            let close = authority
                .find(']')
                .ok_or_else(|| format!("unterminated IPv6 literal in '{authority}'"))?;
            let host = &authority[1..close];
            let after = &authority[close + 1..];
            let port = if let Some(p) = after.strip_prefix(':') {
                p.parse::<u16>()
                    .map_err(|e| format!("invalid port in '{authority}': {e}"))?
            } else if after.is_empty() {
                scheme.default_port()
            } else {
                return Err(format!("invalid target authority '{authority}'"));
            };
            return Ok(Self {
                scheme,
                host: host.to_string(),
                port,
            });
        }
        match authority.rsplit_once(':') {
            Some((host, port_str)) if !host.is_empty() => {
                let port = port_str
                    .parse::<u16>()
                    .map_err(|e| format!("invalid port in '{authority}': {e}"))?;
                Ok(Self {
                    scheme,
                    host: host.to_string(),
                    port,
                })
            }
            _ => Ok(Self {
                scheme,
                host: authority.to_string(),
                port: scheme.default_port(),
            }),
        }
    }

    /// The `scheme://host:port` origin string used in logs and rewriting.
    pub fn origin(&self) -> String {
        format!("{}://{}:{}", self.scheme.as_str(), self.host, self.port)
    }

    /// The `host[:port]` value written into the `Host` header for the origin.
    pub fn authority(&self) -> String {
        let default = self.scheme.default_port();
        if self.port == default {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.origin())
    }
}

/// One `<service>=<target>` mapping from the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSpec {
    /// DNS-label service name as registered with the relay.
    pub service: String,
    /// The local origin it proxies to.
    pub target: Target,
}

/// Parse the positional `<service>=<target>` arguments, rejecting invalid
/// service labels, invalid targets and duplicate service names.
pub fn parse_specs(raw: &[String]) -> Result<Vec<ServiceSpec>, String> {
    if raw.is_empty() {
        return Err("at least one <service>=<target> mapping is required".to_string());
    }
    let mut specs: Vec<ServiceSpec> = Vec::with_capacity(raw.len());
    for item in raw {
        let Some((service, target)) = item.split_once('=') else {
            return Err(format!(
                "invalid mapping '{item}'; expected <service>=<target>"
            ));
        };
        let service = service.trim();
        if !is_valid_dns_label(service) {
            return Err(format!(
                "invalid service name '{service}': must be a single DNS label (a-z, 0-9, '-', ≤63 chars)"
            ));
        }
        if specs.iter().any(|s| s.service == service) {
            return Err(format!("duplicate service '{service}'"));
        }
        let target = Target::parse(target)?;
        specs.push(ServiceSpec {
            service: service.to_string(),
            target,
        });
    }
    Ok(specs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> Target {
        Target::parse(s).unwrap()
    }

    #[test]
    fn bare_port_means_localhost_http() {
        assert_eq!(
            t("8080"),
            Target {
                scheme: TargetScheme::Http,
                host: "localhost".into(),
                port: 8080
            }
        );
    }

    #[test]
    fn host_port_means_http() {
        assert_eq!(t("example.com:9000").host, "example.com");
        assert_eq!(t("example.com:9000").port, 9000);
        assert_eq!(t("example.com:9000").scheme, TargetScheme::Http);
    }

    #[test]
    fn scheme_defaults_ports() {
        assert_eq!(t("http://example.com").port, 80);
        assert_eq!(t("https://example.com").port, 443);
        assert_eq!(t("https://example.com:8443").port, 8443);
    }

    #[test]
    fn bare_trailing_slash_is_normalized() {
        assert_eq!(t("http://example.com/").port, 80);
        assert_eq!(t("http://example.com/").host, "example.com");
    }

    #[test]
    fn path_component_is_rejected() {
        assert!(Target::parse("http://example.com/app").is_err());
        assert!(Target::parse("http://example.com/app?x=1").is_err());
        assert!(Target::parse("example.com:80/x").is_err());
    }

    #[test]
    fn ipv6_literals() {
        let v6 = t("http://[::1]:8080");
        assert_eq!(v6.host, "::1");
        assert_eq!(v6.port, 8080);
        assert_eq!(t("http://[::1]").port, 80);
    }

    #[test]
    fn bare_hostname_is_ambiguous() {
        assert!(Target::parse("example.com").is_err());
    }

    #[test]
    fn authority_omits_default_port() {
        assert_eq!(t("http://example.com").authority(), "example.com");
        assert_eq!(t("http://example.com:80").authority(), "example.com");
        assert_eq!(t("http://example.com:8080").authority(), "example.com:8080");
    }

    #[test]
    fn specs_parse_and_reject_duplicates() {
        let specs = parse_specs(&["web=8080".into(), "api=http://localhost:9000".into()]).unwrap();
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].service, "web");
        assert_eq!(specs[1].target.port, 9000);

        assert!(parse_specs(&["web=8080".into(), "web=9090".into()]).is_err());
        assert!(parse_specs(&["with.dot=8080".into()]).is_err());
        assert!(parse_specs(&["noequals".into()]).is_err());
        assert!(parse_specs(&[]).is_err());
    }
}
