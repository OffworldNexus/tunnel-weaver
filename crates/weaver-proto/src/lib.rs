//! Core protocol constants and wire definitions for Tunnel Weaver.
//!
//! This crate defines shared protocol versioning and schema types used across
//! the `weave` client and `weaver-server` relay.

use serde::{Deserialize, Serialize};

pub mod control;
pub mod framing;
pub mod http;
pub mod poc;

pub use control::{ControlHead, ControlReply, RefusalCode};
pub use framing::{CodecError, decode_length_prefixed, encode_length_prefixed};
pub use http::{HttpHead, HttpResponseHead};

/// The current wire protocol version supported by this build.
pub const PROTOCOL_VERSION: u16 = 1;

/// Application stream head carried in `weaver_mux::wire::Head::opaque`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Head {
    /// Control stream registration.
    Control(ControlHead),
    /// Proxied HTTP request.
    Http(HttpHead),
}

impl Head {
    /// Encodes this `Head` into a `weaver_mux::wire::Head` suitable for `Connection::open`.
    pub fn to_mux_head(&self) -> Result<weaver_mux::wire::Head, CodecError> {
        let hints = match self {
            Self::Control(_) => weaver_mux::Hints {
                content_type: Some("application/octet-stream".to_string()),
                content_length: None,
                upgrade: false,
                content_encoding: None,
            },
            Self::Http(h) => h.hints.clone(),
        };
        let opaque = postcard::to_allocvec(self)?;
        Ok(weaver_mux::wire::Head { hints, opaque })
    }

    /// Decodes a `Head` from a `weaver_mux::wire::Head::opaque` byte slice.
    pub fn from_mux_head(head: &weaver_mux::wire::Head) -> Result<Self, CodecError> {
        Ok(postcard::from_bytes(&head.opaque)?)
    }
}

/// Enforces service name validation as a single DNS label of at most 63 characters.
///
/// Per RFC 1035 / RFC 1123, a valid DNS label:
/// - Has length between 1 and 63 characters (inclusive)
/// - Contains only ASCII alphanumeric characters and hyphens
/// - Cannot start or end with a hyphen
pub fn is_valid_dns_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 63 {
        return false;
    }
    if label.starts_with('-') || label.ends_with('-') {
        return false;
    }
    label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_is_one() {
        assert_eq!(PROTOCOL_VERSION, 1);
    }

    #[test]
    fn test_dns_label_validation() {
        assert!(is_valid_dns_label("web"));
        assert!(is_valid_dns_label("api-1"));
        assert!(is_valid_dns_label("a"));
        assert!(!is_valid_dns_label(""));
        assert!(!is_valid_dns_label("-leading"));
        assert!(!is_valid_dns_label("trailing-"));
        assert!(!is_valid_dns_label("with.dot"));
        assert!(!is_valid_dns_label("with_underscore"));
        assert!(!is_valid_dns_label(&"a".repeat(64)));
        assert!(is_valid_dns_label(&"a".repeat(63)));
    }

    #[test]
    fn test_head_mux_roundtrip() {
        let control = Head::Control(ControlHead::Register {
            service: "web".to_string(),
        });
        let mux_head = control.to_mux_head().unwrap();
        let decoded = Head::from_mux_head(&mux_head).unwrap();
        assert_eq!(control, decoded);

        let http = Head::Http(HttpHead {
            method: "GET".to_string(),
            scheme: "https".to_string(),
            authority: "web.laptop.poc.example.com".to_string(),
            path: "/hello?x=1".to_string(),
            headers: vec![("user-agent".to_string(), b"curl/8.0".to_vec())],
            hints: weaver_mux::Hints::default(),
        });
        let mux_head_http = http.to_mux_head().unwrap();
        let decoded_http = Head::from_mux_head(&mux_head_http).unwrap();
        assert_eq!(http, decoded_http);
    }

    #[test]
    fn test_length_prefixed_framing() {
        let reply = ControlReply::Registered {
            hostname: "web.laptop.poc.example.com".to_string(),
        };
        let encoded = encode_length_prefixed(&reply).unwrap();
        assert!(encoded.len() > 4);

        let decoded: (ControlReply, usize) = decode_length_prefixed(&encoded).unwrap().unwrap();
        assert_eq!(decoded.0, reply);
        assert_eq!(decoded.1, encoded.len());

        let resp = HttpResponseHead {
            status: 302,
            headers: vec![("location".to_string(), b"https://example.com".to_vec())],
        };
        let encoded_resp = encode_length_prefixed(&resp).unwrap();
        let decoded_resp: (HttpResponseHead, usize) =
            decode_length_prefixed(&encoded_resp).unwrap().unwrap();
        assert_eq!(decoded_resp.0, resp);
    }
}
