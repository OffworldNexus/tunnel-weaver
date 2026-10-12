//! Static embedded web assets and HTTP security headers, shared by the
//! `weaver-server` edge and the `weave` client.
//!
//! Both binaries serve branded HTML error pages: the relay edge renders the
//! root welcome page and the "no such tunnel" 404, while the client renders
//! the 502 it returns when a registered service's local origin is
//! unreachable. Keeping the assets in one crate keeps that branding
//! byte-identical and gives both sides a single place to reason about the
//! security headers. All documents are embedded at compile time, so there is
//! no runtime filesystem dependency.

use askama::Template;

// Private compile-time templates keep layout/includes internal and autoescape
// every dynamic value. Rendering never reads files or fetches external assets.
#[derive(Template)]
#[template(path = "welcome.html")]
struct Welcome;

#[derive(Template)]
#[template(path = "no_tunnel.html")]
struct NoTunnel;

#[derive(Template)]
#[template(path = "bad_gateway.html")]
struct BadGateway<'a> {
    target: &'a str,
}

#[derive(Template)]
#[template(path = "forbidden.html")]
struct Forbidden<'a> {
    reason: &'a str,
}

#[derive(Template)]
#[template(path = "throttled.html")]
struct Throttled {
    retry_after: u64,
}

#[derive(Template)]
#[template(path = "unavailable.html")]
struct Unavailable;

#[derive(Template)]
#[template(path = "abuse_check.html")]
struct AbuseCheck<'a> {
    challenge_url: &'a str,
    flow: &'a str,
    /// The widget `display` mode: `standard`, `bar`, or `floating`.
    display: &'a str,
    /// The currently selected mode, for the toggle's active state.
    mode: &'a str,
    /// Content version prefix for the vendored asset URLs.
    asset_version: &'a str,
    /// A well-formed but unverifiable payload, to demo a failing check.
    failure_payload: &'a str,
}

#[derive(Template)]
#[template(path = "abuse_check_result.html")]
struct AbuseCheckResult<'a> {
    verified: bool,
    summary: &'a str,
}

/// Render the informational relay welcome page (not a live health check).
pub fn render_welcome() -> String {
    render(Welcome)
}

/// Render the shared page for an absent or offline tunnel.
pub fn render_no_tunnel() -> String {
    render(NoTunnel)
}

/// Render the branded 502 page for `target`, HTML-escaping the target so a
/// hostile target string cannot inject markup.
pub fn render_bad_gateway(target: &str) -> String {
    render(BadGateway { target })
}

/// Render the branded 403 page naming the firewall rule that fired.
pub fn render_forbidden(reason: &str) -> String {
    render(Forbidden { reason })
}

/// Render the branded 429 page telling the caller when to retry.
pub fn render_throttled(retry_after_secs: u64) -> String {
    render(Throttled {
        retry_after: retry_after_secs,
    })
}

/// Render the branded 503 page for a temporarily unavailable limiter.
pub fn render_unavailable() -> String {
    render(Unavailable)
}

/// The dynamic values for the ALTCHA diagnostic page.
pub struct AbuseCheckPage<'a> {
    /// The absolute challenge URL the widget fetches, including the client key
    /// and the signed purpose/flow.
    pub challenge_url: &'a str,
    /// The per-render flow id, echoed back on submit.
    pub flow: &'a str,
    /// The widget `display` mode to render (`standard`, `bar`, `floating`).
    pub display: &'a str,
    /// The selected mode, for the toggle's active state.
    pub mode: &'a str,
    /// A well-formed but unverifiable payload, to demo a failing check.
    pub failure_payload: &'a str,
}

/// Render the ALTCHA diagnostic page served on the admin host.
pub fn render_abuse_check(page: AbuseCheckPage<'_>) -> String {
    render(AbuseCheck {
        challenge_url: page.challenge_url,
        flow: page.flow,
        display: page.display,
        mode: page.mode,
        asset_version: altcha_asset_version(),
        failure_payload: page.failure_payload,
    })
}

/// Render the outcome of a diagnostic proof-of-work submission.
pub fn render_abuse_check_result(verified: bool, summary: &str) -> String {
    render(AbuseCheckResult { verified, summary })
}

/// A content version for the vendored ALTCHA assets.
///
/// WhiteNoise-style manifest versioning: the page links
/// `/abuse/check/assets/altcha/<version>/<file>`, so a change to *any* vendored
/// file changes the version and busts every cache. Computed once per process
/// over the embedded bytes; no build script needed.
pub fn altcha_asset_version() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION.get_or_init(|| {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for name in [
            "altcha.js",
            "altcha.css",
            "demo-bootstrap.js",
            "workers/pbkdf2.js",
        ] {
            if let Some((bytes, _)) = altcha_asset(name) {
                for &byte in bytes {
                    hash ^= u64::from(byte);
                    hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
                }
            }
        }
        format!("{hash:016x}")
    })
}

/// The vendored ALTCHA widget assets, keyed by their path under
/// `assets/altcha/`. Returns the bytes and the content type to serve them with.
///
/// Pinned to the upstream `altcha` widget v3.3.0 `dist/external` bundle (see
/// `static/altcha/PROVENANCE.md`); the external build is deliberate so the demo
/// works under a strict CSP without `blob:` or inline styles.
pub fn altcha_asset(path: &str) -> Option<(&'static [u8], &'static str)> {
    Some(match path {
        "altcha.js" => (
            include_bytes!("../static/altcha/altcha.js"),
            "text/javascript; charset=utf-8",
        ),
        "altcha.css" => (
            include_bytes!("../static/altcha/altcha.css"),
            "text/css; charset=utf-8",
        ),
        "demo-bootstrap.js" => (
            include_bytes!("../static/altcha/demo-bootstrap.js"),
            "text/javascript; charset=utf-8",
        ),
        "workers/pbkdf2.js" => (
            include_bytes!("../static/altcha/workers/pbkdf2.js"),
            "text/javascript; charset=utf-8",
        ),
        _ => return None,
    })
}

/// String-only templates have no fallible filters or custom Display values;
/// writing their literals and borrowed strings into a String cannot fail.
fn render(template: impl Template) -> String {
    template
        .render()
        .expect("embedded string-only HTML template")
}

/// Inject standard security headers and content-type into HTML responses.
///
/// Applies strict Content-Security-Policy, anti-clickjacking, MIME type
/// sniffing protections, referrer policy, and conditionally
/// Strict-Transport-Security (HSTS) when serving with a valid non-placeholder
/// certificate.
pub fn apply_security_headers<B>(response: &mut http::Response<B>, include_hsts: bool) {
    let headers = response.headers_mut();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        http::header::CONTENT_SECURITY_POLICY,
        http::HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        ),
    );
    headers.insert(
        http::header::X_CONTENT_TYPE_OPTIONS,
        http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        http::header::X_FRAME_OPTIONS,
        http::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        http::header::REFERRER_POLICY,
        http::HeaderValue::from_static("no-referrer"),
    );
    if include_hsts {
        headers.insert(
            http::header::STRICT_TRANSPORT_SECURITY,
            http::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
}

/// Security headers for non-HTML responses (JSON, static assets).
///
/// Sets the anti-sniffing / anti-framing / referrer headers and optional HSTS,
/// but deliberately not `Content-Type` or a CSP — the caller owns those.
pub fn apply_common_security_headers<B>(response: &mut http::Response<B>, include_hsts: bool) {
    let headers = response.headers_mut();
    headers.insert(
        http::header::X_CONTENT_TYPE_OPTIONS,
        http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        http::header::X_FRAME_OPTIONS,
        http::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        http::header::REFERRER_POLICY,
        http::HeaderValue::from_static("no-referrer"),
    );
    if include_hsts {
        headers.insert(
            http::header::STRICT_TRANSPORT_SECURITY,
            http::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
}

/// Security headers for the ALTCHA diagnostic page.
///
/// This is the one deliberately relaxed policy in the relay: the page loads the
/// self-hosted widget (`script-src 'self'`), its stylesheet and the inline
/// branding (`style-src 'self' 'unsafe-inline'`), a same-origin worker
/// (`worker-src 'self'`), and fetches exactly one cross-origin resource — the
/// challenge from the ALTCHA API at `connect_origin`. Everything else stays
/// locked to `'none'`, and the form may only post back to the admin host.
pub fn apply_demo_security_headers<B>(
    response: &mut http::Response<B>,
    connect_origin: &str,
    include_hsts: bool,
) {
    let csp = format!(
        "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; font-src 'self'; worker-src 'self'; \
         connect-src {connect_origin}; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    );
    let headers = response.headers_mut();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    if let Ok(value) = http::HeaderValue::from_str(&csp) {
        headers.insert(http::header::CONTENT_SECURITY_POLICY, value);
    }
    headers.insert(
        http::header::X_CONTENT_TYPE_OPTIONS,
        http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        http::header::X_FRAME_OPTIONS,
        http::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        http::header::REFERRER_POLICY,
        http::HeaderValue::from_static("no-referrer"),
    );
    if include_hsts {
        headers.insert(
            http::header::STRICT_TRANSPORT_SECURITY,
            http::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
}

// The embedded account SPA (WVR-36), generated by `build.rs`.
//
// The map is empty (and `spa_index` returns a placeholder shell) unless the
// `account-spa` feature is on and a build directory exists, so a plain
// `cargo build` still compiles. `weave` depends on this crate with default
// features off, so the client never carries SPA bytes.
include!(concat!(env!("OUT_DIR"), "/spa_assets.rs"));

/// The embedded SPA's content version, used to build immutable asset URLs.
pub fn spa_asset_version() -> &'static str {
    SPA_ASSET_VERSION
}

/// Whether a real SPA is embedded (false when only the placeholder shell is).
pub fn spa_is_embedded() -> bool {
    SPA_ASSET_VERSION != "placeholder"
}

/// An embedded SPA asset by its path relative to the build root (for example
/// `_app/immutable/entry/start.js`). Returns the bytes and content type.
pub fn spa_asset(path: &str) -> Option<(&'static [u8], &'static str)> {
    SPA_ASSETS
        .iter()
        .find(|(name, _, _)| *name == path)
        .map(|(_, bytes, content_type)| (*bytes, *content_type))
}

/// The SPA shell, served for every history-route deep link.
pub fn spa_index() -> &'static [u8] {
    SPA_INDEX
}

/// Security headers for the account SPA shell.
///
/// The app is same-origin with its API, so `connect-src 'self'` suffices and no
/// cross-origin exception is needed. Scripts/styles/workers are limited to the
/// host; `style-src` allows inline styles because Svelte injects them.
pub fn apply_spa_security_headers<B>(response: &mut http::Response<B>, include_hsts: bool) {
    let headers = response.headers_mut();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        http::header::CONTENT_SECURITY_POLICY,
        http::HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
             img-src 'self' data:; font-src 'self'; worker-src 'self'; connect-src 'self'; \
             form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    headers.insert(
        http::header::X_CONTENT_TYPE_OPTIONS,
        http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        http::header::X_FRAME_OPTIONS,
        http::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        http::header::REFERRER_POLICY,
        http::HeaderValue::from_static("no-referrer"),
    );
    if include_hsts {
        headers.insert(
            http::header::STRICT_TRANSPORT_SECURITY,
            http::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assets_embedded_and_non_empty() {
        // `contains` on a non-empty needle implies the asset is non-empty.
        for (html, status) in [
            (render_welcome(), "Operational"),
            (render_no_tunnel(), "404 Not Found"),
            (render_bad_gateway("localhost"), "502 Bad Gateway"),
            (render_forbidden("dotfile"), "403 Forbidden"),
            (render_throttled(30), "429 Too Many Requests"),
            (render_unavailable(), "503 Service Unavailable"),
        ] {
            assert!(html.contains(status));
            assert!(html.contains("<style>"));
            assert!(html.contains("<svg"));
            assert!(!html.contains("{%"));
            for external in ["<script", "<link", "<img", "src=", "@import", "url("] {
                assert!(!html.contains(external), "external asset: {external}");
            }
        }
    }

    #[test]
    fn bad_gateway_names_target_and_leaves_no_placeholder() {
        let html = render_bad_gateway("http://localhost:8080");
        assert!(html.contains("http://localhost:8080"));
        assert!(!html.contains("{{ target }}"));
    }

    #[test]
    fn forbidden_names_reason() {
        let html = render_forbidden("dotfile");
        assert!(html.contains("403 Forbidden"));
        assert!(html.contains("<code>dotfile</code>"));
        assert!(!html.contains("{{ reason }}"));
    }

    #[test]
    fn dynamic_text_cannot_inject_markup_or_templates() {
        // Exercise both entry points: a rule/target is data, never HTML or a
        // second template, including literal entity and template syntax.
        for render in [render_bad_gateway, render_forbidden] {
            let html = render(
                "</code><script>alert('x')</script><img src=x onerror=alert(1)> & \" {{TARGET}} café",
            );
            assert!(!html.contains("<script>"));
            assert!(!html.contains("<img"));
            assert!(!html.contains("</code><script"));
            assert!(html.contains("&lt;") || html.contains("&#60;"));
            assert!(html.contains("&amp;") || html.contains("&#38;"));
            assert!(html.contains("{{TARGET}} café"));
            assert!(render("").contains("<code></code>"));
            let long = "é".repeat(4096);
            assert!(render(&long).contains(&long));
        }
    }

    #[test]
    fn apply_security_headers_sets_all_but_hsts_by_default() {
        let mut resp = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(())
            .unwrap();
        apply_security_headers(&mut resp, false);

        assert_eq!(
            resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            resp.headers()
                .get(http::header::CONTENT_SECURITY_POLICY)
                .unwrap(),
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        );
        assert_eq!(
            resp.headers()
                .get(http::header::X_CONTENT_TYPE_OPTIONS)
                .unwrap(),
            "nosniff"
        );
        assert_eq!(
            resp.headers().get(http::header::X_FRAME_OPTIONS).unwrap(),
            "DENY"
        );
        assert_eq!(
            resp.headers().get(http::header::REFERRER_POLICY).unwrap(),
            "no-referrer"
        );
        assert!(
            resp.headers()
                .get(http::header::STRICT_TRANSPORT_SECURITY)
                .is_none()
        );

        let mut resp_hsts = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(())
            .unwrap();
        apply_security_headers(&mut resp_hsts, true);
        assert_eq!(
            resp_hsts
                .headers()
                .get(http::header::STRICT_TRANSPORT_SECURITY)
                .unwrap(),
            "max-age=31536000; includeSubDomains"
        );
    }
}
