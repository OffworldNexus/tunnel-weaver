//! Micro-benchmark for the edge WAF `inspect` hot path (OFF-96).
//!
//! Run with:
//!
//! ```text
//! cargo bench -p weaver-server --bench waf
//! ```
//!
//! Set `WAF_BENCH_DUMP=1` to print the generated corpus for inspection.
//!
//! The corpus is generated deterministically and **every** URL is asserted to
//! produce the verdict its category promises before it is timed. That keeps the
//! numbers honest: 1000 probes a mass scanner sends and the edge must refuse,
//! and 1000 requests real apps and frontend dev servers send and must pass.
//! `inspect` is called on the whole 2000-URL corpus, so a regression anywhere
//! in the pipeline (decode, lowercase, segment split, rule matching) shows up.

use std::hint::black_box;
use std::time::{Duration, Instant};

use http::Method;
use weaver_server::edge::waf::{Verdict, inspect};

/// URLs of each kind in the corpus.
const BLOCKED: usize = 1000;
const ALLOWED: usize = 1000;
/// Full-corpus passes per measurement; we keep the fastest (least noisy) one.
const ROUNDS: usize = 300;

/// SplitMix64: tiny, deterministic, dependency-free.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }
}

// ---------------------------------------------------------------------------
// Blocked corpus: probes that must be refused.
// ---------------------------------------------------------------------------

/// Benign prefixes prepended to position-independent probe templates, so the
/// corpus includes scanners hitting real sub-routes rather than only `/`.
const PREFIXES: &[&str] = &[
    "",
    "/api",
    "/api/v2",
    "/v1",
    "/static",
    "/assets",
    "/app",
    "/user/42",
    "/shop/checkout",
    "/deep/nested/path",
    "/a/b/c/d/e",
    "/wp-content/plugins",
];

/// Query strings blind scanners bolt on; `inspect` strips them, but real
/// traffic carries them, so the corpus should too.
const QUERIES: &[&str] = &[
    "",
    "?id=1",
    "?id=1&sort=desc",
    "?debug=true",
    "?redirect=%2Flogin",
    "#top",
];

const DOTFILES: &[&str] = &[
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.backup",
    "/.git/config",
    "/.git/HEAD",
    "/.gitignore",
    "/.git-credentials",
    "/.ssh/id_rsa",
    "/.aws/credentials",
    "/.npmrc",
    "/.netrc",
    "/.vscode/sftp.json",
    "/.idea/workspace.xml",
    "/.DS_Store",
    "/.config/gcloud/credentials.db",
    "/.terraform/terraform.tfstate",
    "/.bash_history",
    "/.zsh_history",
    "/.docker/config.json",
];

const TRAVERSALS: &[&str] = &[
    "/../etc/passwd",
    "/%2e%2e/etc/passwd",
    "/%252e%252e/etc/passwd",
    "/..%2f..%2fetc%2fpasswd",
    "/a/../../etc/passwd",
    "/..\\windows\\system32\\config",
    "/%2e%2e%5c%2e%2e%5cetc",
    "/static/..%252f..%252fsecret",
];

const LEFTOVERS: &[&str] = &[
    "/index.php~",
    "/config.php.bak",
    "/settings.py.swp",
    "/app.old",
    "/main.js.orig",
    "/dump.tmp",
    "/style.css.save",
    "/backup.bak",
    "/data.dist",
    "/notes.backup",
    "/api.php.swo",
    "/x.js.tmp",
];

/// Non-dot secret names; dot-prefixed ones (`.htpasswd`) are exercised under
/// `DOTFILES` because the dotfile rule fires first.
const SECRETS: &[&str] = &[
    "/dump.sql",
    "/backup.sql.gz",
    "/db.sqlite3",
    "/server.key",
    "/cert.pem",
    "/private.p12",
    "/keystore.jks",
    "/app.ppk",
    "/id_rsa",
    "/id_ed25519",
    "/prod.db",
    "/prod.pfx",
];

/// Debug/leak endpoints only match at the root, so no prefix is prepended.
const DEBUG: &[&str] = &[
    "/phpmyadmin/index.php",
    "/info.php",
    "/telescope/requests",
    "/actuator/env",
    "/actuator/heapdump",
    "/env",
    "/@vite/env",
    "/v2/_catalog",
    "/server-status",
    "/trace.axd",
    "/_ignition/execute-solution",
    "/debug/default/view",
    "/solr/admin",
    "/ecp/current/exporttool",
    "/config.json",
    "/credentials.json",
    "/package-lock.json",
    "/docker-compose.yml",
    "/___proxy_subdomain_whm/login",
    "/wp-config.php",
];

const MALFORMED: &[&str] = &[
    "/a%00b",
    "/x/%00",
    "/foo%0d%0a",
    "/bar%7f",
    "/%01",
    "/baz%09qux",
    "/%1fpath",
    "/c%00d%00e",
];

/// Benign paths used to exercise the `TRACE` early-out.
const SAFE_PATHS: &[&str] = &[
    "/",
    "/index.html",
    "/api/users",
    "/login",
    "/static/app.js",
    "/.well-known/security.txt",
    "/node_modules/.vite/deps/react.js",
];

fn build_blocked() -> Vec<(Method, String)> {
    let mut rng = Rng::new(0xB10C_1002);
    let mut out = Vec::with_capacity(BLOCKED);
    while out.len() < BLOCKED {
        let cat = out.len() % 7;
        // Debug endpoints and trace only need the path shape; prefixes would
        // move them out of root position and change the verdict.
        let prefix = if cat == 4 { "" } else { *rng.pick(PREFIXES) };
        let query = *rng.pick(QUERIES);

        let (method, path, expect) = match cat {
            0 => (
                Method::GET,
                format!("{prefix}{}", rng.pick(DOTFILES)),
                Verdict::Dotfile,
            ),
            1 => (
                Method::GET,
                format!("{prefix}{}", rng.pick(TRAVERSALS)),
                Verdict::Traversal,
            ),
            2 => (
                Method::GET,
                format!("{prefix}{}", rng.pick(LEFTOVERS)),
                Verdict::Leftover,
            ),
            3 => (
                Method::GET,
                format!("{prefix}{}", rng.pick(SECRETS)),
                Verdict::SecretMaterial,
            ),
            4 => (
                Method::GET,
                format!("{prefix}{}", rng.pick(DEBUG)),
                Verdict::DebugEndpoint,
            ),
            5 => (
                Method::GET,
                format!("{prefix}{}", rng.pick(MALFORMED)),
                Verdict::Malformed,
            ),
            _ => (
                Method::TRACE,
                format!("{prefix}{}", rng.pick(SAFE_PATHS)),
                Verdict::Trace,
            ),
        };

        let url = format!("{path}{query}");
        let got = inspect(&method, &url);
        assert_eq!(
            got,
            Some(expect),
            "blocked corpus generated an unexpected verdict for {method} {url}: {got:?}"
        );
        out.push((method, url));
    }
    out
}

// ---------------------------------------------------------------------------
// Allowed corpus: ordinary app and dev-server traffic that must pass.
// ---------------------------------------------------------------------------

/// Path words that never collide with a rule (no `config`, `web`, `env`, …).
const WORDS: &[&str] = &[
    "users",
    "orders",
    "products",
    "login",
    "about",
    "contact",
    "dashboard",
    "settings",
    "profile",
    "search",
    "cart",
    "checkout",
    "invoices",
    "reports",
    "docs",
    "blog",
    "assets",
    "static",
    "media",
    "images",
    "css",
    "font",
    "api",
    "v1",
    "graphql",
    "health",
    "status",
    "metrics",
    "data",
    "items",
    "files",
    "downloads",
    "gallery",
    "team",
    "pricing",
    "terms",
    "privacy",
    "help",
    "support",
    "account",
    "auth",
    "session",
    "events",
    "projects",
    "tasks",
    "articles",
    "comments",
    "tags",
    "categories",
    "feed",
];

/// Extensions that are always safe to serve.
const EXTS: &[&str] = &[
    "js", "css", "html", "svg", "png", "jpg", "jpeg", "webp", "avif", "ico", "woff2", "pdf",
    "json", "xml", "txt", "md", "map",
];

/// Frontend dev-server asset paths from OFF-96.
const DEV_ASSETS: &[&str] = &[
    "/@fs/home/dev/app/.svelte-kit/generated/client/app.js",
    "/node_modules/.pnpm/@sveltejs+kit@1/node_modules/@sveltejs/kit/src/runtime/client/entry.js",
    "/.vite/deps/chunk-abc123.js",
    "/.next/static/chunks/main-app.js",
    "/.nuxt/dist/client/app.js",
    "/node_modules/.vite/deps/react.js",
    "/@fs/home/dev/app/.svelte-kit/generated/client/nodes/2.js",
];

const WELL_KNOWN: &[&str] = &[
    "/.well-known/security.txt",
    "/.well-known/acme-challenge/token123",
    "/.well-known/webfinger",
    "/.well-known/apple-app-site-association",
    "/u/.well-known/nested",
];

/// A single lowercase segment, occasionally a dotted filename (`my.post.name`).
fn safe_segment(rng: &mut Rng) -> String {
    let w = rng.pick(WORDS);
    if rng.below(5) == 0 {
        format!("{w}.{}", rng.pick(WORDS))
    } else {
        (*w).to_string()
    }
}

fn build_allowed() -> Vec<(Method, String)> {
    let mut rng = Rng::new(0xA110_ED02);
    let mut out = Vec::with_capacity(ALLOWED);
    while out.len() < ALLOWED {
        let query = *rng.pick(QUERIES);
        let path = match out.len() % 6 {
            0 => {
                let depth = 1 + rng.below(4);
                let mut p = String::new();
                for _ in 0..depth {
                    p.push('/');
                    p.push_str(&safe_segment(&mut rng));
                }
                p
            }
            1 => format!(
                "/{}/{}.{}",
                rng.pick(WORDS),
                rng.pick(WORDS),
                rng.pick(EXTS)
            ),
            2 => format!(
                "/api/{}/{}/{}",
                rng.pick(WORDS),
                rng.pick(WORDS),
                rng.pick(WORDS)
            ),
            3 => (*rng.pick(DEV_ASSETS)).to_string(),
            4 => (*rng.pick(WELL_KNOWN)).to_string(),
            _ => format!(
                "/{}/{}.{}.{}",
                rng.pick(WORDS),
                rng.pick(WORDS),
                rng.pick(WORDS),
                rng.pick(EXTS)
            ),
        };

        let url = format!("{path}{query}");
        assert_eq!(
            inspect(&Method::GET, &url),
            None,
            "allowed corpus generated a blocked URL: {url}"
        );
        out.push((Method::GET, url));
    }
    out
}

// ---------------------------------------------------------------------------
// Measurement.
// ---------------------------------------------------------------------------

/// Best-of-`rounds` wall time for one pass over `corpus`. `black_box` keeps the
/// optimiser from hoisting the whole loop away.
fn time_corpus(corpus: &[(Method, String)], rounds: usize) -> Duration {
    for _ in 0..5 {
        for (m, u) in corpus {
            black_box(inspect(black_box(m), black_box(u)));
        }
    }
    let mut best = Duration::MAX;
    for _ in 0..rounds {
        let start = Instant::now();
        for (m, u) in corpus {
            black_box(inspect(black_box(m), black_box(u)));
        }
        best = best.min(start.elapsed());
    }
    best
}

fn report(label: &str, elapsed: Duration, n: usize) {
    let ns = elapsed.as_secs_f64() * 1e9 / n as f64;
    println!(
        "{label:>9}: {ns:>8.1} ns/url   ({:>9.1} µs / {n} urls)",
        elapsed.as_secs_f64() * 1e6
    );
}

fn main() {
    let blocked = build_blocked();
    let allowed = build_allowed();
    assert_eq!(blocked.len(), BLOCKED);
    assert_eq!(allowed.len(), ALLOWED);

    if std::env::var_os("WAF_BENCH_DUMP").is_some() {
        println!("# blocked ({}):", blocked.len());
        for (m, u) in &blocked {
            println!("{m} {u}");
        }
        println!("# allowed ({}):", allowed.len());
        for (m, u) in &allowed {
            println!("{m} {u}");
        }
    }

    let mut combined = Vec::with_capacity(BLOCKED + ALLOWED);
    combined.extend(blocked.iter().cloned());
    combined.extend(allowed.iter().cloned());

    println!(
        "waf::inspect — {} urls/corpus, best of {ROUNDS} rounds",
        combined.len()
    );
    report("blocked", time_corpus(&blocked, ROUNDS), blocked.len());
    report("allowed", time_corpus(&allowed, ROUNDS), allowed.len());
    report("combined", time_corpus(&combined, ROUNDS), combined.len());
}
