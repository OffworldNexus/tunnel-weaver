//! Framing utilities for sending structured messages across stream data channels.

use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

/// Maximum payload length for length-prefixed control and response heads (64 KiB).
pub const MAX_FRAME_PAYLOAD_LEN: usize = 64 * 1024;

/// Errors that can occur during length-prefixed framing and codec operations.
#[derive(Debug, Error)]
pub enum CodecError {
    /// Postcard serialization or deserialization error.
    #[error("postcard codec error: {0}")]
    Postcard(#[from] postcard::Error),
    /// Encoded payload exceeds the protocol cap.
    #[error("payload length {len} exceeds cap of {max}")]
    TooLong {
        /// Actual length of the serialized payload.
        len: usize,
        /// Maximum allowed payload length.
        max: usize,
    },
}

/// Encodes `value` into a 4-byte big-endian length prefix followed by postcard bytes.
pub fn encode_length_prefixed<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    let payload = postcard::to_allocvec(value)?;
    if payload.len() > MAX_FRAME_PAYLOAD_LEN {
        return Err(CodecError::TooLong {
            len: payload.len(),
            max: MAX_FRAME_PAYLOAD_LEN,
        });
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Decodes a length-prefixed value from `buf` if a complete frame has arrived.
///
/// Returns `Ok(Some((value, bytes_consumed)))` on success, `Ok(None)` if more bytes
/// are required to complete the frame, or `Err(CodecError)` on serialization/length errors.
pub fn decode_length_prefixed<T: DeserializeOwned>(
    buf: &[u8],
) -> Result<Option<(T, usize)>, CodecError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_FRAME_PAYLOAD_LEN {
        return Err(CodecError::TooLong {
            len,
            max: MAX_FRAME_PAYLOAD_LEN,
        });
    }
    if buf.len() < 4 + len {
        return Ok(None);
    }
    let payload = &buf[4..4 + len];
    let val: T = postcard::from_bytes(payload)?;
    Ok(Some((val, 4 + len)))
}
