//! Request-target host extraction with RFC 9112 §3.2 / RFC 9113 §8.3.1
//! validation.
//!
//! The edge routes on the host name alone, so it is also where every
//! host-related MUST of the HTTP specs is enforced: a missing, repeated or
//! malformed `Host` is a **400**, never routed on a best-effort guess.
//! `421 Misdirected Request` is reserved for a well-formed host the edge
//! does not serve (SNI mismatch, unknown domain, IP literal).

use http::{Request, Version};

/// Why a request has no usable host (RFC 9112 §3.2, RFC 9113 §8.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostError {
    /// No `Host` header and no authority in the request-target.
    Missing,
    /// More than one `Host` header line.
    Duplicate,
    /// A `Host` value that is not `uri-host [ ":" port ]`.
    Invalid,
    /// HTTP/2: a `host` header that names a different authority than
    /// `:authority`.
    Mismatch,
}

/// The validated host of a request, without the port.
///
/// The authority of an absolute-form request-target (h1) or the
/// `:authority` pseudo-header (h2) takes precedence over `Host`
/// (RFC 9112 §3.2.2). Exactly one `Host` line is allowed; on h2 it must
/// agree with `:authority`.
pub fn request_host<B>(req: &Request<B>) -> Result<String, HostError> {
    let host_lines: Vec<&[u8]> = req
        .headers()
        .get_all(http::header::HOST)
        .iter()
        .map(|v| v.as_bytes())
        .collect();
    if host_lines.len() > 1 {
        return Err(HostError::Duplicate);
    }
    let header_host = host_lines
        .first()
        .map(|raw| parse_host_value(raw).ok_or(HostError::Invalid))
        .transpose()?;

    let target_host = match req.uri().authority() {
        Some(authority) => {
            Some(parse_host_value(authority.as_str().as_bytes()).ok_or(HostError::Invalid)?)
        }
        None => None,
    };

    match (target_host, header_host) {
        (Some(target), Some(header)) => {
            if req.version() == Version::HTTP_2 && !target.eq_ignore_ascii_case(&header) {
                return Err(HostError::Mismatch);
            }
            Ok(target)
        }
        (Some(target), None) => Ok(target),
        (None, Some(header)) => Ok(header),
        (None, None) => Err(HostError::Missing),
    }
}

/// Parses `uri-host [ ":" port ]` and returns the host part, or `None` if
/// the value is not one the edge can route on.
///
/// Accepted: a DNS name (`[A-Za-z0-9._-]+`, non-empty), an IPv4 literal
/// (same character set), or a bracketed IPv6 literal, each optionally
/// followed by a decimal port. Anything else — empty, whitespace, `@`
/// (userinfo), `,` (a joined list), `/` (a path), percent-encoding,
/// control bytes — is rejected. This is stricter than the URI `reg-name`
/// grammar on purpose: nothing but names and literals ever reach a virtual
/// host, and the excluded shapes are the request-smuggling ones.
pub fn parse_host_value(raw: &[u8]) -> Option<String> {
    let (host, port): (&[u8], Option<&[u8]>) = if let Some(rest) = raw.strip_prefix(b"[") {
        let close = rest.iter().position(|&b| b == b']')?;
        let literal = &rest[..close];
        if literal.is_empty()
            || !literal
                .iter()
                .all(|b| b.is_ascii_hexdigit() || *b == b':' || *b == b'.')
        {
            return None;
        }
        let port = match &rest[close + 1..] {
            [] => None,
            [b':', p @ ..] => Some(p),
            _ => return None,
        };
        (&raw[..close + 2], port)
    } else {
        match raw.iter().position(|&b| b == b':') {
            Some(i) => (&raw[..i], Some(&raw[i + 1..])),
            None => (raw, None),
        }
    };

    if host.is_empty() || host.len() > 255 {
        return None;
    }
    if !host.starts_with(b"[")
        && !host
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return None;
    }
    if let Some(port) = port
        && (port.is_empty() || port.len() > 5 || !port.iter().all(u8::is_ascii_digit))
    {
        return None;
    }
    // ASCII-only by construction; safe to convert losslessly.
    Some(String::from_utf8_lossy(host).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h1(host_lines: &[&str]) -> Request<()> {
        let mut b = Request::builder().uri("/").version(Version::HTTP_11);
        for h in host_lines {
            b = b.header("host", *h);
        }
        b.body(()).unwrap()
    }

    #[test]
    fn well_formed_hosts() {
        assert_eq!(
            parse_host_value(b"example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            parse_host_value(b"example.com:8443").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            parse_host_value(b"a-b_c.Example.COM").as_deref(),
            Some("a-b_c.Example.COM")
        );
        assert_eq!(
            parse_host_value(b"127.0.0.1:80").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(parse_host_value(b"[::1]").as_deref(), Some("[::1]"));
        assert_eq!(
            parse_host_value(b"[2001:db8::1]:443").as_deref(),
            Some("[2001:db8::1]")
        );
    }

    #[test]
    fn malformed_hosts() {
        for bad in [
            &b""[..],
            b" ",
            b"example.com, other.example.com",
            b"example.com,other",
            b"user@example.com",
            b"example.com/path",
            b"example.com:",
            b"example.com:abc",
            b"example.com:123456",
            b"exa mple.com",
            b"example.com\t",
            b"%65xample.com",
            b"[::1",
            b"[::1]x",
            b"[]",
            b"[zz]",
            b"\x00",
        ] {
            assert_eq!(
                parse_host_value(bad),
                None,
                "{:?} should be rejected",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn h1_single_host_is_accepted() {
        assert_eq!(
            request_host(&h1(&["example.com:443"])).unwrap(),
            "example.com"
        );
    }

    #[test]
    fn h1_missing_host_is_missing() {
        assert_eq!(request_host(&h1(&[])), Err(HostError::Missing));
    }

    #[test]
    fn h1_duplicate_host_is_rejected_even_when_identical() {
        assert_eq!(
            request_host(&h1(&["example.com", "example.com"])),
            Err(HostError::Duplicate)
        );
        assert_eq!(
            request_host(&h1(&["example.com", "other.example.com"])),
            Err(HostError::Duplicate)
        );
    }

    #[test]
    fn h1_invalid_host_is_rejected() {
        assert_eq!(request_host(&h1(&[""])), Err(HostError::Invalid));
        assert_eq!(
            request_host(&h1(&["a.com, b.com"])),
            Err(HostError::Invalid)
        );
        assert_eq!(request_host(&h1(&["user@a.com"])), Err(HostError::Invalid));
    }

    #[test]
    fn h1_absolute_form_authority_wins_over_host() {
        let req = Request::builder()
            .uri("http://target.example.com/x")
            .version(Version::HTTP_11)
            .header("host", "other.example.com")
            .body(())
            .unwrap();
        assert_eq!(request_host(&req).unwrap(), "target.example.com");
    }

    #[test]
    fn h2_authority_without_host_is_accepted() {
        let req = Request::builder()
            .uri("https://example.com/")
            .version(Version::HTTP_2)
            .body(())
            .unwrap();
        assert_eq!(request_host(&req).unwrap(), "example.com");
    }

    #[test]
    fn h2_host_agreeing_with_authority_is_accepted() {
        let req = Request::builder()
            .uri("https://example.com/")
            .version(Version::HTTP_2)
            .header("host", "EXAMPLE.com:443")
            .body(())
            .unwrap();
        assert_eq!(request_host(&req).unwrap(), "example.com");
    }

    #[test]
    fn h2_host_disagreeing_with_authority_is_rejected() {
        let req = Request::builder()
            .uri("https://example.com/")
            .version(Version::HTTP_2)
            .header("host", "other.example.com")
            .body(())
            .unwrap();
        assert_eq!(request_host(&req), Err(HostError::Mismatch));
    }
}
