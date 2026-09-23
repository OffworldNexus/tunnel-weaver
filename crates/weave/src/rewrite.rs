//! Header-only URL and cookie rewriting for proxied responses.
//!
//! A service's origin is private (`http://localhost:8080`) but the visitor
//! sees the public origin (`https://web.laptop.poc.example.com`). Any
//! redirect or cookie the origin hands out that points back at itself must
//! be rewritten to the public name or the visitor will be sent to an address
//! it cannot reach. This module deliberately rewrites *headers only*: HTML
//! and other body content are never touched.
//!
//! Disabled per service by `--no-rewrite`.

use weaver_proto::HttpResponseHead;

use crate::target::Target;

/// Headers whose values are absolute URLs and are rewritten when they point
/// at the origin.
const URL_HEADERS: &[&str] = &["location", "content-location", "refresh"];

/// Rewrite `Location`, `Content-Location` and `Refresh` values that point at
/// the origin to the public origin, and strip the `Domain` attribute of
/// cookies scoped to the origin host.
///
/// Relative values and values pointing at a different host are left alone.
pub fn rewrite_response_headers(head: &mut HttpResponseHead, target: &Target, public_origin: &str) {
    for (name, value) in head.headers.iter_mut() {
        if name.eq_ignore_ascii_case("set-cookie") {
            if let Ok(s) = std::str::from_utf8(value) {
                *value = rewrite_set_cookie(s, &target.host).into_bytes();
            }
            continue;
        }
        if !URL_HEADERS.iter().any(|h| name.eq_ignore_ascii_case(h)) {
            continue;
        }
        let Ok(s) = std::str::from_utf8(value) else {
            continue;
        };
        let rewritten = if name.eq_ignore_ascii_case("refresh") {
            rewrite_refresh(s, target, public_origin)
        } else {
            rewrite_url(s, target, public_origin).unwrap_or_else(|| s.to_string())
        };
        *value = rewritten.into_bytes();
    }
}

/// Candidate origin prefixes a self-referential URL may use: with the
/// explicit port, and (for a default port) with it omitted.
fn origin_prefixes(target: &Target) -> Vec<String> {
    let mut out = vec![target.origin()];
    let default = match target.scheme {
        crate::target::TargetScheme::Http => 80,
        crate::target::TargetScheme::Https => 443,
    };
    if target.port == default {
        out.push(format!("{}://{}", target.scheme.as_str(), target.host));
    }
    out
}

/// Rewrite an absolute URL whose origin is one of the target's candidate
/// origins. Returns `None` for relative or foreign URLs.
fn rewrite_url(value: &str, target: &Target, public_origin: &str) -> Option<String> {
    let trimmed = value.trim();
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        // Relative reference (or a scheme we do not rewrite): leave it.
        return None;
    }
    let prefixes = origin_prefixes(target);
    let mut best: Option<&String> = None;
    for prefix in prefixes.iter() {
        // Match origin exactly or followed by a path/query/fragment boundary,
        // so `http://localhost:8080` never matches `http://localhost:8080x`.
        if let Some(rest) = trimmed.strip_prefix(prefix.as_str())
            && (rest.is_empty()
                || rest.starts_with('/')
                || rest.starts_with('?')
                || rest.starts_with('#'))
            && best.is_none_or(|b| b.len() < prefix.len())
        {
            best = Some(prefix);
        }
    }
    let prefix = best?;
    Some(format!("{public_origin}{}", &trimmed[prefix.len()..]))
}

/// `Refresh: 5; url=/foo` / `0;url=http://origin/foo`. Only the URL part is
/// rewritten; the delay and formatting are preserved verbatim.
fn rewrite_refresh(value: &str, target: &Target, public_origin: &str) -> String {
    let Some(eq) = value.find('=') else {
        return value.to_string();
    };
    let (before, url_part) = value.split_at(eq + 1);
    match rewrite_url(url_part.trim(), target, public_origin) {
        Some(rewritten) => format!("{before}{rewritten}"),
        None => value.to_string(),
    }
}

/// Drop a `Domain=` attribute that scopes the cookie to the origin host (a
/// host-only cookie on the public name is what the visitor needs) and add
/// `Secure` when absent, since the public origin is always HTTPS.
fn rewrite_set_cookie(value: &str, target_host: &str) -> String {
    let mut kept: Vec<&str> = Vec::new();
    let mut has_secure = false;
    let mut dropped_domain = false;
    for (i, attr) in value.split(';').enumerate() {
        let attr = attr.trim();
        if i > 0 {
            if let Some((name, val)) = attr.split_once('=') {
                if name.trim().eq_ignore_ascii_case("domain") {
                    let val = val.trim().trim_start_matches('.').to_ascii_lowercase();
                    if val == target_host.to_ascii_lowercase() {
                        dropped_domain = true;
                        continue;
                    }
                }
                if name.trim().eq_ignore_ascii_case("secure") {
                    has_secure = true;
                }
            } else if attr.eq_ignore_ascii_case("secure") {
                has_secure = true;
            }
        }
        if !attr.is_empty() {
            kept.push(attr);
        }
    }
    let mut out = kept.join("; ");
    if dropped_domain && !has_secure {
        out.push_str("; Secure");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::{Target, TargetScheme};

    fn target() -> Target {
        Target {
            scheme: TargetScheme::Http,
            host: "localhost".into(),
            port: 8080,
        }
    }

    fn head(headers: &[(&str, &str)]) -> HttpResponseHead {
        HttpResponseHead {
            status: 200,
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.as_bytes().to_vec()))
                .collect(),
        }
    }

    fn value<'a>(h: &'a HttpResponseHead, name: &str) -> &'a str {
        std::str::from_utf8(h.header(name).unwrap()).unwrap()
    }

    const PUBLIC: &str = "https://web.laptop.poc.example.com";

    #[test]
    fn absolute_location_to_target_is_rewritten() {
        let mut h = head(&[("location", "http://localhost:8080/next?x=1")]);
        rewrite_response_headers(&mut h, &target(), PUBLIC);
        assert_eq!(
            value(&h, "location"),
            "https://web.laptop.poc.example.com/next?x=1"
        );
    }

    #[test]
    fn relative_location_untouched() {
        let mut h = head(&[("location", "/next")]);
        rewrite_response_headers(&mut h, &target(), PUBLIC);
        assert_eq!(value(&h, "location"), "/next");
    }

    #[test]
    fn foreign_location_untouched() {
        let mut h = head(&[("location", "https://other.example/x")]);
        rewrite_response_headers(&mut h, &target(), PUBLIC);
        assert_eq!(value(&h, "location"), "https://other.example/x");
    }

    #[test]
    fn prefix_is_boundary_checked() {
        let mut h = head(&[("location", "http://localhost:80800/x")]);
        rewrite_response_headers(&mut h, &target(), PUBLIC);
        assert_eq!(value(&h, "location"), "http://localhost:80800/x");
    }

    #[test]
    fn default_port_origin_without_port_matches() {
        let t = Target {
            scheme: TargetScheme::Http,
            host: "api.internal".into(),
            port: 80,
        };
        let mut h = head(&[("location", "http://api.internal/x")]);
        rewrite_response_headers(&mut h, &t, PUBLIC);
        assert_eq!(
            value(&h, "location"),
            "https://web.laptop.poc.example.com/x"
        );
    }

    #[test]
    fn content_location_and_refresh_rewritten() {
        let mut h = head(&[
            ("content-location", "http://localhost:8080/a"),
            ("refresh", "5; url=http://localhost:8080/b"),
        ]);
        rewrite_response_headers(&mut h, &target(), PUBLIC);
        assert_eq!(
            value(&h, "content-location"),
            "https://web.laptop.poc.example.com/a"
        );
        assert_eq!(
            value(&h, "refresh"),
            "5; url=https://web.laptop.poc.example.com/b"
        );
    }

    #[test]
    fn set_cookie_domain_dropped_and_secure_added() {
        let mut h = head(&[("set-cookie", "sid=abc; Domain=localhost; Path=/; HttpOnly")]);
        rewrite_response_headers(&mut h, &target(), PUBLIC);
        assert_eq!(value(&h, "set-cookie"), "sid=abc; Path=/; HttpOnly; Secure");
    }

    #[test]
    fn set_cookie_domain_with_leading_dot_and_existing_secure() {
        let mut h = head(&[("set-cookie", "sid=abc; Domain=.localhost; Secure")]);
        rewrite_response_headers(&mut h, &target(), PUBLIC);
        assert_eq!(value(&h, "set-cookie"), "sid=abc; Secure");
    }

    #[test]
    fn set_cookie_foreign_domain_untouched() {
        let mut h = head(&[("set-cookie", "sid=abc; Domain=other.example")]);
        rewrite_response_headers(&mut h, &target(), PUBLIC);
        assert_eq!(value(&h, "set-cookie"), "sid=abc; Domain=other.example");
    }
}
