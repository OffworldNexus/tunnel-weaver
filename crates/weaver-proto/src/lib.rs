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
//! * Visitor streams: relay sends `Head::Http` then [`BodyFrame`]s; client
//!   answers with [`HttpResponseHead`] then [`BodyFrame`]s. All messages
//!   after the first are decoded from stream state, never from a tag:
//!   the relay's first message is always a [`Head`], the client's first is
//!   always an [`HttpResponseHead`], and everything after is a
//!   [`BodyFrame`].
//! * Interim 1xx responses are carried as repeated [`HttpResponseHead`]s,
//!   each followed by another head; the first non-1xx head is final.
//! * After a final `101` (or a `200` answering an RFC 8441 extended
//!   `CONNECT`), both directions switch to raw [`BodyFrame::Chunk`]s and a
//!   FIN from either side closes the byte pipe.
//! * Message boundaries are the mux's job; nothing here adds a length.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod control;
pub mod http;
pub mod policy;
pub mod reset;

pub use control::{CertStatus, ControlHead, ControlReply, RefusalCode, is_valid_dns_label};
pub use http::{HttpHead, HttpResponseHead};
pub use reset::ResetCode;

/// Lowest application protocol version this build accepts.
pub const MIN_PROTOCOL_VERSION: u16 = 1;
/// Application protocol version this build speaks. Carried in
/// [`ControlHead::Register`] and negotiated independently of the mux.
pub const PROTOCOL_VERSION: u16 = 1;

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

/// A body message after the head on a visitor stream, in either direction.
///
/// The head tells each side whether the following [`BodyFrame`]s are request
/// or response body; the sequence is scanned positionally (see the crate
/// conventions). A `Chunk` carries bytes as they arrive, never a boundary
/// the sender chose to impose; `Trailers` is the optional final message
/// before FIN and carries the HTTP trailer fields, if any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BodyFrame {
    /// One body chunk, forwarded verbatim.
    Chunk(Vec<u8>),
    /// Trailer fields sent once, immediately before FIN.
    Trailers(Vec<(String, Vec<u8>)>),
}

impl BodyFrame {
    /// True when this frame is body data rather than trailers.
    pub fn is_chunk(&self) -> bool {
        matches!(self, Self::Chunk(_))
    }

    /// Trailer list if this is a [`BodyFrame::Trailers`].
    pub fn trailers(&self) -> Option<&[(String, Vec<u8>)]> {
        match self {
            Self::Chunk(_) => None,
            Self::Trailers(fields) => Some(fields),
        }
    }
}

/// Encode any schema message for `Connection::send`.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    Ok(postcard::to_allocvec(value)?)
}

/// Decode a schema message received from `Connection::recv_msg`.
pub fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    Ok(postcard::from_bytes(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_negotiation() {
        assert_eq!(accept_protocol_version(PROTOCOL_VERSION), Ok(()));
        assert_eq!(
            accept_protocol_version(0),
            Err(RefusalCode::UnsupportedVersion {
                min: MIN_PROTOCOL_VERSION,
                max: PROTOCOL_VERSION
            })
        );
    }

    #[test]
    fn heads_round_trip() {
        let control = Head::Control(ControlHead::register("web").unwrap());
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

        let cert = ControlReply::CertState {
            state: CertStatus::Ordering,
        };
        let decoded: ControlReply = decode(&encode(&cert).unwrap()).unwrap();
        assert_eq!(cert, decoded);
        assert!(!CertStatus::Ordering.is_serving());
        assert!(CertStatus::Renewing.is_serving());

        let resp = HttpResponseHead {
            status: 302,
            headers: vec![("location".to_string(), b"https://example.com".to_vec())],
        };
        let decoded: HttpResponseHead = decode(&encode(&resp).unwrap()).unwrap();
        assert_eq!(resp, decoded);
    }

    #[test]
    fn body_frames_round_trip() {
        let chunk = BodyFrame::Chunk(b"hello".to_vec());
        let decoded: BodyFrame = decode(&encode(&chunk).unwrap()).unwrap();
        assert_eq!(chunk, decoded);
        assert!(decoded.is_chunk());
        assert!(decoded.trailers().is_none());

        let trailers = BodyFrame::Trailers(vec![
            ("x-checksum".to_string(), b"abc".to_vec()),
            ("x-trailer".to_string(), b"2".to_vec()),
        ]);
        let decoded: BodyFrame = decode(&encode(&trailers).unwrap()).unwrap();
        assert_eq!(trailers, decoded);
        assert!(!decoded.is_chunk());
        assert_eq!(decoded.trailers().unwrap().len(), 2);
    }

    #[test]
    fn reset_code_round_trip() {
        for code in [
            ResetCode::OriginUnreachable,
            ResetCode::OriginClosed,
            ResetCode::Cancelled,
        ] {
            assert_eq!(ResetCode::from_u32(code.as_u32()), Some(code));
        }
        assert_eq!(ResetCode::OriginUnreachable.as_u32(), 1);
        assert_eq!(ResetCode::from_u32(0), None);
        assert_eq!(ResetCode::from_u32(99), None);
    }
}
