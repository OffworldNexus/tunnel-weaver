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
