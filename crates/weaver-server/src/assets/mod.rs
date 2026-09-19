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
/// protections, referrer policy, and conditionally Strict-Transport-Security (HSTS)
/// when serving with a valid non-placeholder certificate.
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
    fn test_assets_embedded_and_non_empty() {
        // `contains` on a non-empty needle implies the asset is non-empty.
        assert!(WELCOME_HTML.contains("Tunnel Weaver"));
        assert!(NO_TUNNEL_HTML.contains("No Such Tunnel"));
    }

    #[test]
    fn test_apply_security_headers() {
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
