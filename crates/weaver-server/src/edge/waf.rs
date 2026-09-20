//! Minimal, always-on request firewall for tunnelled hostnames.
//!
//! Every hostname the relay issues a certificate for is published to
//! Certificate Transparency logs and probed by mass scanners within seconds
//! (`/.env`, `/.git/HEAD`, path traversal, framework-specific leaks). Those
//! probes never belong to a legitimate application, so the edge refuses them
//! itself with a branded `403` and the origin never sees them.
//!
//! The rules are deliberately narrow: they match only patterns that no sane
//! web application serves publicly. Anything a real app might legitimately
//! expose (an `/api`, a `/login`, a `/.well-known/…` directory) is left
//! alone. This is not a substitute for visitor authentication (M4), nor for
//! keeping service names out of CT in the first place (per-machine wildcard
//! certs over DNS-01 once the relay serves its own zone — ADR 0007); it just
//! takes the free hits away from the bots until those land.

use http::Method;

/// Why a request was refused. Carried into the log line so an operator can
/// see what the bots are after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Hidden file or directory (`/.env`, `/.git/…`, `/.ssh/…`), except the
    /// `/.well-known/` namespace which is a legitimate public convention.
    Dotfile,
    /// Encoded or literal `..` segment: path traversal.
    Traversal,
    /// Editor/backup leftovers (`~`, `.bak`, `.old`, `.orig`, `.swp`).
    Leftover,
    /// Dumps, archives and key material by extension (`.sql`, `.sqlite`,
    /// `.pem`, `.key`, `.p12`, …).
    SecretMaterial,
    /// Well-known admin/debug endpoints that are never public on a dev
    /// tunnel (`/phpmyadmin`, `/actuator/env`, `/telescope`, `/_debugbar`…).
    DebugEndpoint,
    /// Control characters or a null byte in the path.
    Malformed,
    /// `TRACE` (cross-site tracing) is never proxied.
    Trace,
}

impl Verdict {
    /// Short stable token for logs and the `x-weaver-blocked` header.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dotfile => "dotfile",
            Self::Traversal => "traversal",
            Self::Leftover => "leftover",
            Self::SecretMaterial => "secret-material",
            Self::DebugEndpoint => "debug-endpoint",
            Self::Malformed => "malformed",
            Self::Trace => "trace",
        }
    }
}

/// Inspect a visitor request; `None` means "forward it".
pub fn inspect(method: &Method, raw_path: &str) -> Option<Verdict> {
    if method == Method::TRACE {
        return Some(Verdict::Trace);
    }
    let path = raw_path.split(['?', '#']).next().unwrap_or("");
    let decoded = percent_decode_lossy(path);
    // Decode twice: scanners double-encode (`%252e%252e`) to slip past
    // single-pass filters.
    let decoded = percent_decode_lossy(&decoded);
    let lower = decoded.to_ascii_lowercase();

    if lower.bytes().any(|b| b == 0 || b < 0x20 || b == 0x7f) {
        return Some(Verdict::Malformed);
    }

    let segments: Vec<&str> = lower.split(['/', '\\']).filter(|s| !s.is_empty()).collect();

    if segments.contains(&"..") {
        return Some(Verdict::Traversal);
    }

    for (i, seg) in segments.iter().enumerate() {
        if seg.starts_with('.') && seg.len() > 1 {
            // `/.well-known/…` is a public convention (ACME, security.txt,
            // webfinger, app links); keep it, but only at the root.
            if i == 0 && *seg == ".well-known" {
                continue;
            }
            return Some(Verdict::Dotfile);
        }
    }

    if let Some(last) = segments.last() {
        if last.ends_with('~') || LEFTOVER_SUFFIXES.iter().any(|s| last.ends_with(s)) {
            return Some(Verdict::Leftover);
        }
        if SECRET_SUFFIXES.iter().any(|s| last.ends_with(s)) {
            return Some(Verdict::SecretMaterial);
        }
    }

    if let Some(first) = segments.first()
        && DEBUG_ROOTS.contains(first)
    {
        return Some(Verdict::DebugEndpoint);
    }
    if segments.len() >= 2 && DEBUG_PAIRS.contains(&(segments[0], segments[1])) {
        return Some(Verdict::DebugEndpoint);
    }

    None
}

/// Extensions of editor swap files and backups. A dev server never serves
/// these on purpose.
const LEFTOVER_SUFFIXES: &[&str] = &[
    ".bak", ".backup", ".old", ".orig", ".save", ".swp", ".swo", ".tmp", ".dist",
];

/// Extensions that only ever hold dumps or key material.
const SECRET_SUFFIXES: &[&str] = &[
    ".sql",
    ".sql.gz",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".jks",
    ".keystore",
    ".ppk",
    ".htpasswd",
    ".htaccess",
    "id_rsa",
    "id_ed25519",
];

/// First path segments that are never a legitimate public route on a tunnel
/// but are on every scanner's list.
const DEBUG_ROOTS: &[&str] = &[
    // Spring Boot 1.x exposed the environment dump at `/env` (2.x moved it
    // under `/actuator/env`, covered by DEBUG_PAIRS); scanners try both.
    "env",
    "phpmyadmin",
    "pma",
    "myadmin",
    "adminer",
    "adminer.php",
    "phpinfo.php",
    "info.php",
    "telescope",
    "_debugbar",
    "_profiler",
    "server-status",
    "server-info",
    "trace.axd",
    "elmah.axd",
    "___proxy_subdomain_whm",
    "___proxy_subdomain_cpanel",
    "cgi-bin",
    "wp-config.php",
    "config.php",
    "configuration.php",
    "web.config",
    "docker-compose.yml",
    "docker-compose.yaml",
    "dockerfile",
    "composer.lock",
    "package-lock.json",
    "yarn.lock",
    "credentials",
    "credentials.json",
    "secrets.json",
    "config.json",
    "config.yml",
    "config.yaml",
];

/// Two-segment prefixes for framework debug/leak endpoints.
const DEBUG_PAIRS: &[(&str, &str)] = &[
    ("actuator", "env"),
    ("actuator", "heapdump"),
    ("actuator", "configprops"),
    ("@vite", "env"),
    ("ecp", "current"),
    ("v2", "_catalog"),
    ("_ignition", "execute-solution"),
    ("debug", "default"),
    ("solr", "admin"),
];

/// Percent-decode, keeping any malformed escape verbatim. Lossy on the
/// UTF-8 side since we only compare against ASCII rule tables.
fn percent_decode_lossy(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex(bytes[i + 1]);
            let lo = hex(bytes[i + 2]);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(p: &str) -> Option<Verdict> {
        inspect(&Method::GET, p)
    }

    #[test]
    fn blocks_the_scanner_playbook() {
        for p in [
            "/.env",
            "/.env.backup",
            "/.env.production",
            "/config/.env",
            "/api/.env",
            "/.git/HEAD",
            "/.git/config",
            "/.DS_Store",
            "/.vscode/sftp.json",
            "/.ssh/id_rsa",
        ] {
            assert_eq!(get(p), Some(Verdict::Dotfile), "{p}");
        }
        for p in [
            "/../.env",
            "/%2e%2e%2f%2eenv",
            "/a/%252e%252e/b",
            "/x/..%2f..%2fetc/passwd",
        ] {
            assert!(
                matches!(get(p), Some(Verdict::Traversal) | Some(Verdict::Dotfile)),
                "{p}: {:?}",
                get(p)
            );
        }
        for p in [
            "/index.php~",
            "/config.php.bak",
            "/app.old",
            "/settings.py.swp",
        ] {
            assert_eq!(get(p), Some(Verdict::Leftover), "{p}");
        }
        for p in [
            "/dump.sql",
            "/backup.sql.gz",
            "/db.sqlite3",
            "/server.key",
            "/cert.pem",
        ] {
            assert_eq!(get(p), Some(Verdict::SecretMaterial), "{p}");
        }
        for p in [
            "/phpmyadmin/",
            "/info.php",
            "/telescope/requests",
            "/actuator/env",
            "/env",
            "/env/",
            "/@vite/env",
            "/v2/_catalog",
            "/server-status",
            "/trace.axd",
            "/___proxy_subdomain_whm/login",
            "/ecp/Current/exporttool/x.application",
            "/config.json",
        ] {
            assert_eq!(get(p), Some(Verdict::DebugEndpoint), "{p}");
        }
        assert_eq!(get("/a%00b"), Some(Verdict::Malformed));
        assert_eq!(inspect(&Method::TRACE, "/"), Some(Verdict::Trace));
    }

    #[test]
    fn leaves_legitimate_apps_alone() {
        for p in [
            "/",
            "/index.html",
            "/api/users?id=1",
            "/login",
            "/about",
            "/graphql",
            "/static/app.js",
            "/assets/logo.svg",
            "/.well-known/security.txt",
            "/.well-known/acme-challenge/token",
            "/docs/config.md",
            "/downloads/report.pdf",
            "/v2/items",
            "/environment",
            "/api/env",
            "/api/config",
            "/blog/my.post.with.dots",
            "/files/photo.jpeg",
        ] {
            assert_eq!(get(p), None, "{p}");
        }
        // `.well-known` only at the root; nested it is a hidden dir.
        assert_eq!(get("/x/.well-known/y"), Some(Verdict::Dotfile));
        // Query strings are ignored.
        assert_eq!(get("/search?q=.env"), None);
        assert_eq!(inspect(&Method::POST, "/api/graphql"), None);
        assert_eq!(inspect(&Method::OPTIONS, "/"), None);
    }
}
