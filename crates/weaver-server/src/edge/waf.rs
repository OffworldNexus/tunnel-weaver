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
    /// Known-sensitive hidden file or directory targeted by scanners
    /// (`/.env`, `/.git/…`, `/.ssh/…`), except the `/.well-known/` namespace
    /// which is a legitimate public convention. Frontend tooling dot-dirs are
    /// not matched.
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

    // Percent-decode only when needed, and run a second pass only when the
    // first actually produced a fresh escape (double-encoded scans like
    // `%252e%252e`). Paths without `%` — the vast majority — borrow the input
    // and allocate nothing. Decoding twice unconditionally, as before, was one
    // of the two per-request allocations on this hot path.
    let decoded_owned;
    let decoded: &str = if path.as_bytes().contains(&b'%') {
        let once = percent_decode_lossy(path);
        decoded_owned = if once.as_bytes().contains(&b'%') {
            percent_decode_lossy(&once)
        } else {
            once
        };
        &decoded_owned
    } else {
        path
    };

    // One byte pass settles both the control-character rejection and whether
    // case folding is needed (scanner probes are lowercase, so it usually
    // isn't). Folding case is unaffected by these bytes.
    let mut has_upper = false;
    for b in decoded.bytes() {
        if b == 0 || b < 0x20 || b == 0x7f {
            return Some(Verdict::Malformed);
        }
        has_upper |= b.is_ascii_uppercase();
    }

    // Fold ASCII case only if the path actually has uppercase; this is the
    // second allocation the old code always paid.
    let lower_owned;
    let lower: &str = if has_upper {
        lower_owned = decoded.to_ascii_lowercase();
        &lower_owned
    } else {
        decoded
    };

    // One pass settles everything: traversal, dotfiles, and the first/last
    // segments. Traversal outranks every path-shape rule, so it returns the
    // instant a `..` segment is seen; a risky dotfile is only *remembered*
    // because a later `..` must still win. This replaces the previous two
    // split passes (an existential traversal scan plus the classification
    // scan) with a single traversal.
    let mut first = "";
    let mut second = "";
    let mut last = "";
    let mut dotfile = false;
    for (idx, seg) in lower
        .split(['/', '\\'])
        .filter(|s| !s.is_empty())
        .enumerate()
    {
        if idx == 0 {
            first = seg;
        } else if idx == 1 {
            second = seg;
        }
        last = seg;

        if seg == ".." {
            return Some(Verdict::Traversal);
        }

        // Only the hidden files and directories scanners actually fish for are
        // refused. A blanket "any segment starting with `.`" rule is wrong:
        // modern frontend dev servers legitimately serve assets from
        // dot-directories (`.svelte-kit`, `.pnpm`, `.vite`, `.next`, `.nuxt`),
        // so an allowlist of tooling would rot with every new framework. A
        // curated risk list keeps those reachable while still starving the
        // bots. `/.well-known/…` is a public convention at the root only.
        if !dotfile
            && seg.starts_with('.')
            && !(idx == 0 && seg == ".well-known")
            && is_risky_dotfile(seg)
        {
            dotfile = true;
        }
    }

    if dotfile {
        return Some(Verdict::Dotfile);
    }

    // Classify the final segment by its extension instead of scanning the
    // whole suffix table: one `match` dispatches on the bytes, where the two
    // `iter().any(ends_with)` scans ran ~23 comparisons per request. A name
    // with no dot can only be a backup (`~`) or an SSH private key.
    if !last.is_empty() {
        if last.ends_with('~') {
            return Some(Verdict::Leftover);
        }
        if last.ends_with("id_rsa") || last.ends_with("id_ed25519") {
            return Some(Verdict::SecretMaterial);
        }
        if let Some(dot) = last.rfind('.') {
            match &last[dot + 1..] {
                // Editor swap files and backups.
                "bak" | "backup" | "old" | "orig" | "save" | "swp" | "swo" | "tmp" | "dist" => {
                    return Some(Verdict::Leftover);
                }
                // Dumps and key material.
                "sql" | "sqlite" | "sqlite3" | "db" | "pem" | "key" | "p12" | "pfx" | "jks"
                | "keystore" | "ppk" | "htpasswd" | "htaccess" => {
                    return Some(Verdict::SecretMaterial);
                }
                // `.sql.gz` is the only compressed dump we care about.
                "gz" if last.ends_with(".sql.gz") => return Some(Verdict::SecretMaterial),
                _ => {}
            }
        }
    }

    // Debug roots are exact first segments; a `match` lets the compiler build a
    // dispatch tree instead of a long linear scan.
    if !first.is_empty()
        && matches!(
            first,
            // Spring Boot 1.x exposed the environment dump at `/env` (2.x moved
            // it under `/actuator/env`, covered by DEBUG_PAIRS); scanners try
            // both.
            "env"
                | "phpmyadmin"
                | "pma"
                | "myadmin"
                | "adminer"
                | "adminer.php"
                | "phpinfo.php"
                | "info.php"
                | "telescope"
                | "_debugbar"
                | "_profiler"
                | "server-status"
                | "server-info"
                | "trace.axd"
                | "elmah.axd"
                | "___proxy_subdomain_whm"
                | "___proxy_subdomain_cpanel"
                | "cgi-bin"
                | "wp-config.php"
                | "config.php"
                | "configuration.php"
                | "web.config"
                | "docker-compose.yml"
                | "docker-compose.yaml"
                | "dockerfile"
                | "composer.lock"
                | "package-lock.json"
                | "yarn.lock"
                | "credentials"
                | "credentials.json"
                | "secrets.json"
                | "config.json"
                | "config.yml"
                | "config.yaml"
        )
    {
        return Some(Verdict::DebugEndpoint);
    }
    // Every DEBUG_PAIRS key is one of these roots, so gate the pair scan on the
    // first segment and skip it for ordinary traffic.
    if !second.is_empty()
        && matches!(
            first,
            "actuator" | "@vite" | "ecp" | "v2" | "_ignition" | "debug" | "solr"
        )
        && DEBUG_PAIRS.contains(&(first, second))
    {
        return Some(Verdict::DebugEndpoint);
    }

    None
}

/// Does this path segment name a hidden file or directory that is a known
/// scanner target? `segment` is the lowercased, percent-decoded path piece and
/// is already known to start with `.`.
///
/// Exact names cover the usual credential and metadata droppings; prefix
/// families cover files whose every suffix variant matters (`.env.local`,
/// `.git/config`, `.gitignore`, …). A `match` lets the compiler dispatch on
/// length before comparing bytes.
fn is_risky_dotfile(segment: &str) -> bool {
    if DOTFILE_RISK_PREFIXES.iter().any(|p| segment.starts_with(p)) {
        return true;
    }
    matches!(
        segment,
        ".ds_store"
            | ".aws"
            | ".bash_history"
            | ".config"
            | ".docker"
            | ".dockercfg"
            | ".gnupg"
            | ".hg"
            | ".htaccess"
            | ".htpasswd"
            | ".idea"
            | ".mysql_history"
            | ".netrc"
            | ".npmrc"
            | ".psql_history"
            | ".pypirc"
            | ".python_history"
            | ".ssh"
            | ".svn"
            | ".terraform"
            | ".vscode"
            | ".wgetrc"
            | ".yarnrc"
            | ".zsh_history"
    )
}

/// Dot-prefixed families where every variant is a scanner target: `.env`
/// (`.env.local`, `.env.production`, `.env.backup`) and `.git`
/// (`.git/config`, `.gitignore`, `.git-credentials`).
const DOTFILE_RISK_PREFIXES: &[&str] = &[".env", ".git"];

/// Two-segment prefixes for framework debug/leak endpoints. Every first
/// element must also appear in the `matches!` gate in `inspect`.
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

    /// OFF-96: the dotfile rule matches a curated risk list, not every
    /// dot-segment, so it must still catch risky names at any depth.
    #[test]
    fn blocks_risky_dotfiles_at_any_depth() {
        for p in [
            "/.gitignore",
            "/.git-credentials",
            "/config/.env.local",
            "/api/.env.production",
            "/.aws/credentials",
            "/.config/gcloud/credentials.db",
            "/.npmrc",
            "/.netrc",
            "/.bash_history",
            "/.terraform/terraform.tfstate",
            "/deep/nested/.git/config",
        ] {
            assert_eq!(get(p), Some(Verdict::Dotfile), "{p}");
        }
    }

    /// OFF-96: framework tooling dot-dirs are not risk names and must pass.
    #[test]
    fn permits_frontend_dev_server_assets() {
        for p in [
            "/@fs/home/remy/dev/app/.svelte-kit/generated/client/app.js",
            "/node_modules/.pnpm/@sveltejs+kit@1.0.0/node_modules/@sveltejs/kit/src/runtime/client/entry.js",
            "/.vite/deps/chunk-abc.js",
            "/.next/static/chunks/main.js",
            "/.nuxt/dist/client/app.js",
        ] {
            assert_eq!(get(p), None, "{p}");
        }
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
            // Frontend dev-server assets live in dot-directories and must
            // reach the origin (OFF-96).
            "/@fs/home/remy/dev/app/.svelte-kit/generated/client/app.js",
            "/node_modules/.pnpm/@sveltejs+kit@1.0.0/node_modules/@sveltejs/kit/src/runtime/client/entry.js",
            "/.vite/deps/chunk-abc.js",
            "/.next/static/chunks/main.js",
            "/.nuxt/dist/client/app.js",
        ] {
            assert_eq!(get(p), None, "{p}");
        }
        // `.well-known` is a public convention and, since the blanket
        // dot-segment rule is gone, passes at any depth.
        assert_eq!(get("/x/.well-known/y"), None);
        // Query strings are ignored.
        assert_eq!(get("/search?q=.env"), None);
        assert_eq!(inspect(&Method::POST, "/api/graphql"), None);
        assert_eq!(inspect(&Method::OPTIONS, "/"), None);
    }
}
