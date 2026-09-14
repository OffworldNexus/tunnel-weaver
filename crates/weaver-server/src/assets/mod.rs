//! Static embedded web assets and HTTP security headers.
//!
//! Provides compile-time embedded HTML documents for the root welcome page and
//! branded subdomain 404 pages, ensuring zero runtime filesystem dependencies.

/// Embedded HTML content for the root domain welcome page.
pub const WELCOME_HTML: &str = include_str!("welcome.html");

/// Embedded HTML content for the branded subdomain 404 page ("no such tunnel").
pub const NO_TUNNEL_HTML: &str = include_str!("no_tunnel.html");

/// Injects standard security headers and content-type into HTML responses.
///
/// Applies strict Content-Security-Policy, anti-clickjacking, MIME type sniffing
/// protections, and referrer policy according to the specification.
pub fn apply_security_headers<B>(response: &mut http::Response<B>) {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assets_embedded_and_non_empty() {
        assert!(!WELCOME_HTML.is_empty());
        assert!(WELCOME_HTML.contains("Tunnel Weaver"));
        assert!(!NO_TUNNEL_HTML.is_empty());
        assert!(NO_TUNNEL_HTML.contains("No Such Tunnel"));
    }

    #[test]
    fn test_apply_security_headers() {
        let mut resp = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(())
            .unwrap();
        apply_security_headers(&mut resp);

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
    }
}
