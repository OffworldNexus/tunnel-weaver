//! Wire frame header codec.
//!
//! Every message on the underlying pipe is exactly one frame laid out as
//! `[stream_id: u32 BE][type: u8][payload...]`. The pipe is assumed to be
//! message-delimited, so no length prefix lives here.

use crate::error::ProtocolError;

/// Identifies the type of frame transmitted over the multiplexer wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameType {
    /// Challenge frame sent by server on connection start.
    Challenge = 0x01,
    /// Hello frame sent by client containing authentication and nonce.
    Hello = 0x02,
    /// Welcome frame sent by server with negotiated parameters.
    Welcome = 0x03,
    /// Reject frame sent by server before closing.
    Reject = 0x04,
    /// Open frame establishing a logical stream.
    Open = 0x05,
    /// Data frame carrying stream payload bytes.
    Data = 0x06,
    /// Fin frame signaling half-close of the sender's stream direction.
    Fin = 0x07,
    /// Reset frame abruptly terminating a stream.
    Rst = 0x08,
    /// Window update frame granting additional stream credit.
    WindowUpdate = 0x09,
    /// Ping frame for keepalive and latency measurement.
    Ping = 0x0a,
    /// Pong response frame answering a ping.
    Pong = 0x0b,
    /// Goaway frame signaling connection teardown.
    Goaway = 0x0c,
}

impl TryFrom<u8> for FrameType {
    type Error = ProtocolError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0x01 => Ok(Self::Challenge),
            0x02 => Ok(Self::Hello),
            0x03 => Ok(Self::Welcome),
            0x04 => Ok(Self::Reject),
            0x05 => Ok(Self::Open),
            0x06 => Ok(Self::Data),
            0x07 => Ok(Self::Fin),
            0x08 => Ok(Self::Rst),
            0x09 => Ok(Self::WindowUpdate),
            0x0a => Ok(Self::Ping),
            0x0b => Ok(Self::Pong),
            0x0c => Ok(Self::Goaway),
            other => Err(ProtocolError::UnknownFrameType(other)),
        }
    }
}

/// A parsed multiplexer frame containing a stream ID, frame type, and payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Logical stream identifier (0 for control frames, odd for client, even for server).
    pub stream_id: u32,
    /// Frame type discriminant.
    pub frame_type: FrameType,
    /// Frame payload bytes.
    pub payload: Vec<u8>,
}

impl Frame {
    /// The size in bytes of the fixed frame header (`u32` stream_id + `u8` frame_type).
    pub const HEADER_LEN: usize = 5;

    /// Parse a frame from its wire representation.
    ///
    /// # Wire Layout
    /// - Bytes 0..4: Big-endian `u32` stream ID.
    /// - Byte 4: `u8` frame type discriminant.
    /// - Bytes 5..: Remaining payload bytes.
    pub fn parse(input: &[u8]) -> Result<Self, ProtocolError> {
        if input.len() < Self::HEADER_LEN {
            return Err(ProtocolError::Truncated(input.len()));
        }

        let stream_id = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
        let frame_type = FrameType::try_from(input[4])?;
        let payload = input[Self::HEADER_LEN..].to_vec();

        Ok(Self {
            stream_id,
            frame_type,
            payload,
        })
    }

    /// Encode the frame into its wire representation.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::HEADER_LEN + self.payload.len());
        self.encode_into(&mut buf);
        buf
    }

    /// Append the wire representation of this frame to `buf`.
    ///
    /// Used by the transmit path so the caller-provided buffer is reused
    /// instead of allocating a fresh `Vec` per frame.
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.stream_id.to_be_bytes());
        buf.push(self.frame_type as u8);
        buf.extend_from_slice(&self.payload);
    }

    /// Total number of bytes this frame occupies on the wire.
    pub fn wire_len(&self) -> usize {
        Self::HEADER_LEN + self.payload.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_frame_round_trip() {
        let original = Frame {
            stream_id: 42,
            frame_type: FrameType::Data,
            payload: b"hello world".to_vec(),
        };

        let encoded = original.encode();
        assert_eq!(encoded.len(), 5 + 11);
        assert_eq!(&encoded[0..4], &42u32.to_be_bytes());
        assert_eq!(encoded[4], FrameType::Data as u8);
        assert_eq!(&encoded[5..], b"hello world");

        let parsed = Frame::parse(&encoded).expect("frame parsing should succeed");
        assert_eq!(parsed, original);
    }

    #[test]
    fn parse_truncated_input() {
        let short_inputs: [&[u8]; 5] = [&[], &[0], &[0, 0], &[0, 0, 0], &[0, 0, 0, 1]];
        for input in short_inputs {
            match Frame::parse(input) {
                Err(ProtocolError::Truncated(len)) => assert_eq!(len, input.len()),
                other => panic!(
                    "expected Truncated error for len {}, got {:?}",
                    input.len(),
                    other
                ),
            }
        }
    }

    #[test]
    fn parse_unknown_frame_type() {
        let input = [0x00, 0x00, 0x00, 0x01, 0xff, 0x01, 0x02];
        match Frame::parse(&input) {
            Err(ProtocolError::UnknownFrameType(0xff)) => {}
            other => panic!("expected UnknownFrameType(0xff), got {:?}", other),
        }
    }

    #[test]
    fn parse_all_valid_frame_types() {
        let types = [
            (0x01, FrameType::Challenge),
            (0x02, FrameType::Hello),
            (0x03, FrameType::Welcome),
            (0x04, FrameType::Reject),
            (0x05, FrameType::Open),
            (0x06, FrameType::Data),
            (0x07, FrameType::Fin),
            (0x08, FrameType::Rst),
            (0x09, FrameType::WindowUpdate),
            (0x0a, FrameType::Ping),
            (0x0b, FrameType::Pong),
            (0x0c, FrameType::Goaway),
        ];

        for (byte, expected_type) in types {
            let mut wire = vec![0, 0, 0, 10, byte];
            wire.extend_from_slice(b"payload");
            let frame = Frame::parse(&wire).unwrap();
            assert_eq!(frame.stream_id, 10);
            assert_eq!(frame.frame_type, expected_type);
            assert_eq!(frame.payload, b"payload");
        }
    }
}
