//! Error and close/reject code types shared across the crate.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Protocol violations detected while receiving frames.
///
/// Any of these closes the connection: the local side queues a
/// `GOAWAY { ProtocolError }` and stops accepting streams. Variants are
/// intentionally coarse — the peer only ever sees the close code, the
/// details are for local diagnostics.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// The input buffer was smaller than the mandatory 5-byte header.
    #[error("truncated frame input: expected at least 5 header bytes, found {0}")]
    Truncated(usize),

    /// The frame type discriminant on the wire is not recognized.
    #[error("unknown frame type discriminant: 0x{0:02x}")]
    UnknownFrameType(u8),

    /// A structured payload failed to decode.
    #[error("malformed {0:?} payload")]
    Decode(crate::frame::FrameType),

    /// A frame arrived that is not permitted in the current connection or
    /// stream state (e.g. OPEN before WELCOME, DATA on a closed stream).
    #[error("frame not allowed in current state: {0}")]
    StateViolation(&'static str),

    /// A stream id violated the parity or monotonicity rules.
    #[error("invalid stream id {0}")]
    BadStreamId(u32),

    /// The peer sent more DATA bytes than the credit it had been granted.
    #[error("flow control violation on stream {0}")]
    FlowControl(u32),

    /// A compressed DATA frame did not decompress, or exceeded the
    /// per-frame output cap.
    #[error("decompression failed on stream {0}")]
    Decompress(u32),

    /// The negotiated parameters were outside the allowed ranges.
    #[error("invalid negotiated parameter: {0}")]
    BadParams(&'static str),

    /// The connection is already closed; the frame was ignored.
    #[error("connection closed")]
    Closed,
}

/// Errors returned by the per-stream API (`open`, `write`, `read`, ...).
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum StreamError {
    /// The connection has not finished authenticating yet.
    #[error("connection not authenticated")]
    NotAuthenticated,
    /// The connection is closed (locally or by the peer).
    #[error("connection closed")]
    Closed,
    /// No such stream exists (never opened, or already fully closed).
    #[error("unknown stream")]
    UnknownStream,
    /// The stream's local send direction is already finished.
    #[error("stream send side is closed")]
    SendClosed,
    /// Nothing to read yet; wait for `Event::Readable`.
    #[error("no data available")]
    WouldBlock,
    /// `set_class` was asked to put a stream in the control class.
    #[error("streams cannot be placed in the control class")]
    InvalidClass,
    /// Every stream id of this side's parity has been used.
    #[error("stream ids exhausted")]
    Exhausted,
}

/// Failure reported by a [`crate::auth::Signer`] implementation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("signing failed: {0}")]
pub struct SignError(pub String);

/// Reason a connection is being closed, carried on the wire in GOAWAY.
///
/// The code tells the peer *what to do next*; policy (revocation,
/// eviction) lives outside the mux.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CloseCode {
    /// The key must never be used again. Do not reconnect.
    KeyRevoked,
    /// Keep the key, but do not automatically reconnect.
    Rejected,
    /// Another connection with the same key took over. Do not reconnect.
    Superseded,
    /// The peer is going away. Reconnect with backoff.
    Shutdown,
    /// The peer violated the protocol.
    ProtocolError,
    /// The connection went idle past the deadline (local decision).
    Timeout,
}

/// Payload of GOAWAY and the `reason` of [`crate::Event::Closed`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoAway {
    /// Why the connection is closing.
    pub code: CloseCode,
    /// Optional human-readable detail.
    pub message: Option<String>,
}

impl GoAway {
    /// Convenience constructor for a code without message.
    pub fn new(code: CloseCode) -> Self {
        Self {
            code,
            message: None,
        }
    }
}

/// Why the server refused a handshake (payload of REJECT).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectCode {
    /// The `KeyId` is not known to the server's `Verifier`.
    UnknownKey,
    /// The client's maximum version is below the server's minimum.
    UnsupportedVersion {
        /// Lowest version the server accepts.
        min: u16,
        /// Highest version the server speaks.
        max: u16,
    },
    /// The HELLO signature did not verify against the key.
    BadSignature,
}
