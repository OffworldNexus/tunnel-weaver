//! Events surfaced to the application via [`crate::Connection::poll_event`].

use crate::error::{GoAway, RejectCode};
use crate::stream::StreamId;
use crate::wire::{Head, KeyId};

/// Something the application should react to. Events are queued in order
/// and drained with `poll_event`; none is ever dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The handshake completed. Streams may now be opened.
    Authenticated {
        /// The key that signed the handshake (on the client: our own).
        key_id: KeyId,
        /// Negotiated protocol version.
        version: u16,
    },
    /// Client only: the server refused the handshake. Followed by `Closed`.
    Rejected {
        /// Why.
        code: RejectCode,
        /// Server-provided detail.
        message: String,
    },
    /// The peer opened a stream.
    StreamOpened {
        /// Id chosen by the peer.
        id: StreamId,
        /// The peer's OPEN payload.
        head: Head,
    },
    /// Bytes are available to `read` on the stream. Edge-triggered: fired
    /// when the inbox transitions from empty to non-empty.
    Readable(StreamId),
    /// Credit became available after `write` returned fewer bytes than
    /// requested. Edge-triggered.
    Writable(StreamId),
    /// The peer half-closed its direction; `read` returns `Ok(0)` once the
    /// inbox drains.
    Finished(StreamId),
    /// The stream was aborted (by the peer, or locally because the
    /// connection closed).
    Reset {
        /// Which stream.
        id: StreamId,
        /// Application-defined abort code.
        code: u32,
    },
    /// The connection is closed. Terminal; nothing follows.
    Closed {
        /// Why. Local closes carry the code we sent; remote closes the code
        /// we received.
        reason: GoAway,
    },
}
