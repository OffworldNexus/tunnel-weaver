//! Application protocol schema for Tunnel Weaver.
//!
//! This crate defines *what* travels on the mux streams shared by the
//! `weave` client and the `weaver-server` relay, and *how the mux should
//! treat it* ([`policy`]). It knows nothing about sockets, tokio, identities
//! or hostnames.
//!
//! # Conventions
//!
//! * Every stream's first message is a postcard-encoded [`Head`].
//! * Control streams: client sends `Head::Control`, relay answers with one
//!   [`ControlReply`]; the stream then stays open for the registration's
//!   lifetime.
//! * Visitor streams: relay sends `Head::Http` then body chunks; client
//!   answers with [`HttpResponseHead`] then body chunks. Body chunks are
//!   raw bytes, one mux message per chunk.
//! * Message boundaries are the mux's job; nothing here adds a length.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod control;
pub mod http;
pub mod policy;

pub use control::{ControlHead, ControlReply, RefusalCode};
pub use http::{HttpHead, HttpResponseHead};

/// Lowest application protocol version this build accepts.
pub const MIN_PROTOCOL_VERSION: u16 = 2;
/// Application protocol version this build speaks. Carried in
/// [`ControlHead::Register`] and negotiated independently of the mux.
pub const PROTOCOL_VERSION: u16 = 2;

/// Relay-side check of a client's advertised application version.
pub fn accept_protocol_version(client: u16) -> Result<(), RefusalCode> {
    if (MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&client) {
        Ok(())
    } else {
        Err(RefusalCode::UnsupportedVersion {
            min: MIN_PROTOCOL_VERSION,
            max: PROTOCOL_VERSION,
        })
    }
}

/// Postcard (de)serialization failure of a schema message.
#[derive(Debug, Error)]
#[error("codec error: {0}")]
pub struct CodecError(#[from] pub postcard::Error);

/// First message on every stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Head {
    /// Control stream registration.
    Control(ControlHead),
    /// Proxied HTTP request.
    Http(HttpHead),
}

/// Encode any schema message for `Connection::send`.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    Ok(postcard::to_allocvec(value)?)
}

/// Decode a schema message received from `Connection::recv_msg`.
pub fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    Ok(postcard::from_bytes(bytes)?)
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
    fn version_negotiation() {
        assert_eq!(accept_protocol_version(PROTOCOL_VERSION), Ok(()));
        assert_eq!(
            accept_protocol_version(1),
            Err(RefusalCode::UnsupportedVersion {
                min: MIN_PROTOCOL_VERSION,
                max: PROTOCOL_VERSION
            })
        );
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
    fn heads_round_trip() {
        let control = Head::Control(ControlHead::Register {
            proto_version: PROTOCOL_VERSION,
            service: "web".to_string(),
        });
        let decoded: Head = decode(&encode(&control).unwrap()).unwrap();
        assert_eq!(control, decoded);

        let http = Head::Http(HttpHead {
            method: "GET".to_string(),
            scheme: "https".to_string(),
            authority: "web.laptop.poc.example.com".to_string(),
            path: "/hello?x=1".to_string(),
            headers: vec![("user-agent".to_string(), b"curl/8.0".to_vec())],
        });
        let decoded: Head = decode(&encode(&http).unwrap()).unwrap();
        assert_eq!(http, decoded);

        let reply = ControlReply::Registered {
            hostname: "web.laptop.poc.example.com".to_string(),
        };
        let decoded: ControlReply = decode(&encode(&reply).unwrap()).unwrap();
        assert_eq!(reply, decoded);

        let resp = HttpResponseHead {
            status: 302,
            headers: vec![("location".to_string(), b"https://example.com".to_vec())],
        };
        let decoded: HttpResponseHead = decode(&encode(&resp).unwrap()).unwrap();
        assert_eq!(resp, decoded);
    }
}
