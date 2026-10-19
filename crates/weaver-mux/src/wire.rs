//! Structured frame payloads and their postcard encoding.
//!
//! This module is public so that tests and fuzz targets can hand-craft
//! frames (e.g. a HELLO advertising a future version). Applications never
//! need it: the [`crate::Connection`] API hides frames entirely. Types that
//! are part of the application-facing API ([`KeyId`], [`Signature`],
//! [`Params`]) are re-exported at the crate root; everything else is only
//! reachable through this module.
//!
//! # Evolution rules
//!
//! Postcard is positional, so **field order is the schema**. Appending a
//! field to a struct or a variant to an enum never bumps the protocol
//! version: a decoder for the older layout simply ignores trailing bytes
//! (see [`decode_payload`]). Reordering, removing, or changing the meaning
//! of a field requires a new version.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::error::{CloseReason, ProtocolError, RejectCode};
use crate::frame::FrameType;

/// Lowest protocol version this crate accepts.
pub(crate) const MIN_VERSION: u16 = 1;
/// Highest protocol version this crate speaks.
pub(crate) const MAX_VERSION: u16 = 1;

/// Domain-separation prefix of the handshake transcript.
pub(crate) const TRANSCRIPT_PREFIX: &[u8] = b"weaver-mux-v1";

/// DATA payload flag: the remaining bytes are a zstd frame.
pub const DATA_FLAG_COMPRESSED: u8 = 0x01;
/// DATA payload flag: this frame is not the last fragment of its message;
/// the receiver keeps reassembling until a frame without the flag.
pub const DATA_FLAG_MORE: u8 = 0x02;
/// Every DATA flag bit this version understands; anything else is a
/// decode error.
pub(crate) const DATA_FLAGS_KNOWN: u8 = DATA_FLAG_COMPRESSED | DATA_FLAG_MORE;

/// The single identity concept the mux knows about: the public key that
/// signed the handshake. The variant is the algorithm; the bytes are the raw
/// (for P-256: SEC1 compressed) public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyId {
    /// Ed25519 public key.
    Ed25519([u8; 32]),
    /// ECDSA P-256 public key, SEC1 compressed encoding.
    P256(#[serde(with = "BigArray")] [u8; 33]),
}

/// The one text form of a key, `p256:<hex>` or `ed25519:<hex>` (lowercase
/// hex of the public key bytes): what the relay stores and shows, and what
/// the client remembers.
impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (algorithm, bytes): (&str, &[u8]) = match self {
            Self::P256(bytes) => ("p256", bytes),
            Self::Ed25519(bytes) => ("ed25519", bytes),
        };
        f.write_str(algorithm)?;
        f.write_str(":")?;
        bytes.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// Text that is not a [`KeyId`]'s [`Display`](std::fmt::Display) form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not a key: expected p256:<66 hex> or ed25519:<64 hex>")]
pub struct ParseKeyIdError;

impl std::str::FromStr for KeyId {
    type Err = ParseKeyIdError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        fn nibble(c: u8) -> Result<u8, ParseKeyIdError> {
            match c {
                b'0'..=b'9' => Ok(c - b'0'),
                b'a'..=b'f' => Ok(c - b'a' + 10),
                _ => Err(ParseKeyIdError),
            }
        }
        let (algorithm, hex) = text.split_once(':').ok_or(ParseKeyIdError)?;
        let hex = hex.as_bytes();
        if hex.len() % 2 != 0 {
            return Err(ParseKeyIdError);
        }
        let (pairs, _) = hex.as_chunks::<2>();
        let bytes = pairs
            .iter()
            .map(|&[hi, lo]| Ok(nibble(hi)? << 4 | nibble(lo)?))
            .collect::<Result<Vec<u8>, _>>()?;
        match algorithm {
            "p256" => Ok(Self::P256(bytes.try_into().map_err(|_| ParseKeyIdError)?)),
            "ed25519" => Ok(Self::Ed25519(
                bytes.try_into().map_err(|_| ParseKeyIdError)?,
            )),
            _ => Err(ParseKeyIdError),
        }
    }
}

/// A handshake signature. The variant must match the [`KeyId`] variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Signature {
    /// Ed25519 signature (R ‖ S).
    Ed25519(#[serde(with = "BigArray")] [u8; 64]),
    /// ECDSA P-256 signature, fixed-width r ‖ s.
    P256(#[serde(with = "BigArray")] [u8; 64]),
}

/// CHALLENGE: first frame on the wire, server → client on stream 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    /// Server nonce, mixed into the signed transcript to defeat replay.
    pub nonce_s: [u8; 32],
}

/// HELLO: client → server on stream 0. `version` is deliberately the first
/// field so a server can always read it regardless of what follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Highest protocol version the client speaks.
    pub version: u16,
    /// Key that signed this handshake.
    pub key_id: KeyId,
    /// Client nonce, binds the signature to this connection attempt.
    pub nonce_c: [u8; 32],
    /// Signature over the transcript (see [`crate::auth::transcript`]).
    pub sig: Signature,
}

/// Connection parameters chosen by the server and announced in WELCOME.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Largest DATA payload (post-compression) per frame, in bytes.
    pub max_frame: u32,
    /// Initial per-stream, per-direction credit, in bytes.
    pub initial_window: u32,
    /// Whether the server allows zstd on DATA frames. It may refuse,
    /// never force: compression happens only when both sides allow it.
    pub compression_allowed: bool,
    /// Largest application message either side may send on a stream, in
    /// bytes. Bounds the receiver's reassembly buffer.
    pub max_message: u32,
}

/// WELCOME: server → client, completes the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Welcome {
    /// Negotiated protocol version.
    pub version: u16,
    /// Connection parameters in force from now on.
    pub params: Params,
}

/// REJECT: server → client, then the connection closes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reject {
    /// Why the handshake was refused.
    pub code: RejectCode,
    /// Human-readable detail.
    pub message: String,
}

/// GOAWAY payload: the closing side's [`CloseReason`].
pub type Goaway = CloseReason;

/// RST payload: abort both directions of a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rst {
    /// Application-defined abort code.
    pub code: u32,
}

/// WINDOW_UPDATE payload: grant the peer more send credit on a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowUpdate {
    /// Additional wire bytes the peer may send.
    pub credit: u32,
}

/// PING / PONG payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ping {
    /// Echoed verbatim in the PONG so the sender can match it.
    pub opaque: u64,
}

/// Encode a structured payload with postcard.
pub fn encode_payload<T: Serialize>(value: &T) -> Vec<u8> {
    // Every payload type in this module is a plain data struct: serializing
    // it cannot fail, so an error here is a programming bug.
    postcard::to_allocvec(value).expect("payload serialization is infallible")
}

/// Decode a structured payload. Trailing bytes are tolerated so a decoder
/// for an older layout accepts payloads with appended fields.
pub fn decode_payload<T: DeserializeOwned>(
    frame_type: FrameType,
    bytes: &[u8],
) -> Result<T, ProtocolError> {
    postcard::take_from_bytes::<T>(bytes)
        .map(|(value, _rest)| value)
        .map_err(|_| ProtocolError::Decode(frame_type))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(v: &T) {
        let bytes = encode_payload(v);
        let back: T = decode_payload(FrameType::Data, &bytes).unwrap();
        assert_eq!(&back, v);
    }

    #[test]
    fn payloads_round_trip() {
        round_trip(&Challenge { nonce_s: [7; 32] });
        round_trip(&Hello {
            version: 1,
            key_id: KeyId::P256([9; 33]),
            nonce_c: [3; 32],
            sig: Signature::P256([4; 64]),
        });
        round_trip(&Hello {
            version: 1,
            key_id: KeyId::Ed25519([1; 32]),
            nonce_c: [3; 32],
            sig: Signature::Ed25519([4; 64]),
        });
        round_trip(&Welcome {
            version: 1,
            params: Params {
                max_frame: 16 * 1024,
                initial_window: 512 * 1024,
                compression_allowed: true,
                max_message: 1 << 20,
            },
        });
        round_trip(&Reject {
            code: RejectCode::UnsupportedVersion { min: 1, max: 1 },
            message: "nope".into(),
        });
        round_trip(&crate::Class::Bulk);
        round_trip(&Rst { code: 5 });
        round_trip(&WindowUpdate { credit: 1000 });
        round_trip(&Ping { opaque: u64::MAX });
        round_trip(&crate::error::CloseReason {
            code: crate::error::CloseCode::KeyRevoked,
            message: "bye".into(),
        });
    }

    #[test]
    fn key_text_round_trips() {
        let mut p256 = [0u8; 33];
        p256[0] = 0x02;
        p256[32] = 0xab;
        for key in [KeyId::P256(p256), KeyId::Ed25519([0x42; 32])] {
            let text = key.to_string();
            assert_eq!(text.parse::<KeyId>(), Ok(key), "{text}");
        }
        let text = KeyId::P256(p256).to_string();
        assert!(text.starts_with("p256:02") && text.ends_with("ab"));
        assert_eq!(text.len(), "p256:".len() + 66);
        for bad in [
            "p256:zz",
            "rsa:00",
            "p256",
            "p256:02",
            &text.to_uppercase(),
            &format!("{text}0"),
            &format!("ed25519:{}", "é".repeat(32)),
        ] {
            assert_eq!(bad.parse::<KeyId>(), Err(ParseKeyIdError), "{bad}");
        }
    }

    #[test]
    fn version_is_first_hello_field() {
        let bytes = encode_payload(&Hello {
            version: 0x1234,
            key_id: KeyId::Ed25519([0; 32]),
            nonce_c: [0; 32],
            sig: Signature::Ed25519([0; 64]),
        });
        // postcard varint of 0x1234 = [0xb4, 0x24]
        assert_eq!(&bytes[..2], &[0xb4, 0x24]);
    }

    #[test]
    fn appended_fields_are_ignored_by_old_decoder() {
        #[derive(Serialize)]
        struct PingV2 {
            opaque: u64,
            extra: u32,
        }
        let bytes = encode_payload(&PingV2 {
            opaque: 42,
            extra: 99,
        });
        let old: Ping = decode_payload(FrameType::Ping, &bytes).unwrap();
        assert_eq!(old.opaque, 42);
    }

    #[test]
    fn garbage_is_a_decode_error() {
        let err = decode_payload::<Hello>(FrameType::Hello, &[0xff; 3]).unwrap_err();
        assert_eq!(err, ProtocolError::Decode(FrameType::Hello));
    }
}
