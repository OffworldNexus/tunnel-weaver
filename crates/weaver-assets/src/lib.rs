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

/// Embedded HTML content for the root domain welcome page.
pub const WELCOME_HTML: &str = include_str!("welcome.html");

/// Embedded HTML content for the branded subdomain 404 page ("no such tunnel").
pub const NO_TUNNEL_HTML: &str = include_str!("no_tunnel.html");

/// Embedded HTML template for the branded 502 page. It names the unreachable
/// target: call [`render_bad_gateway`] rather than serving this directly, so
/// the target is HTML-escaped.
pub const BAD_GATEWAY_HTML_TEMPLATE: &str = include_str!("bad_gateway.html");

/// Embedded HTML template for the branded 403 page the edge firewall serves
/// for scanner probes. Call [`render_forbidden`].
pub const FORBIDDEN_HTML_TEMPLATE: &str = include_str!("forbidden.html");

/// Placeholder substituted by [`render_bad_gateway`].
const TARGET_PLACEHOLDER: &str = "{{TARGET}}";
/// Placeholder substituted by [`render_forbidden`].
const REASON_PLACEHOLDER: &str = "{{REASON}}";

/// Render the branded 502 page for `target`, HTML-escaping the target so a
/// hostile target string cannot inject markup.
pub fn render_bad_gateway(target: &str) -> String {
    BAD_GATEWAY_HTML_TEMPLATE.replace(TARGET_PLACEHOLDER, &escape_html(target))
}

/// Render the branded 403 page naming the firewall rule that fired.
pub fn render_forbidden(reason: &str) -> String {
    FORBIDDEN_HTML_TEMPLATE.replace(REASON_PLACEHOLDER, &escape_html(reason))
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

/// Minimal HTML text escaping for values interpolated into an attribute-free
/// context. Escapes the five characters that can break out of text or an
/// attribute, which is enough for the target shown inside `<code>`.
fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assets_embedded_and_non_empty() {
        // `contains` on a non-empty needle implies the asset is non-empty.
        assert!(WELCOME_HTML.contains("Tunnel Weaver"));
        assert!(NO_TUNNEL_HTML.contains("No Such Tunnel"));
        assert!(BAD_GATEWAY_HTML_TEMPLATE.contains("502 Bad Gateway"));
    }

    #[test]
    fn bad_gateway_names_target_and_leaves_no_placeholder() {
        let html = render_bad_gateway("http://localhost:8080");
        assert!(html.contains("http://localhost:8080"));
        assert!(!html.contains(TARGET_PLACEHOLDER));
    }

    #[test]
    fn forbidden_names_reason() {
        let html = render_forbidden("dotfile");
        assert!(html.contains("403 Forbidden"));
        assert!(html.contains("<code>dotfile</code>"));
        assert!(!html.contains(REASON_PLACEHOLDER));
    }

    #[test]
    fn bad_gateway_escapes_target() {
        let html = render_bad_gateway("<script>alert('x')</script>");
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("&#39;"));
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
