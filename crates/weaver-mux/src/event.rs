//! Events surfaced to the application via [`crate::Connection::poll_event`].

use crate::error::{GoAway, RejectCode};
use crate::stream::StreamId;
use crate::wire::{KeyId, StreamPolicy};

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
    /// The peer opened a stream. No application bytes travel in OPEN; by
    /// convention the layer above sends its own head as the first message.
    StreamOpened {
        /// Id chosen by the peer.
        id: StreamId,
        /// The scheduling policy the peer asked for.
        policy: StreamPolicy,
    },
    /// At least one complete message is available via `recv_msg`.
    /// Edge-triggered: fired when the inbox transitions from empty to
    /// non-empty.
    Readable(StreamId),
    /// Credit became available after `send` returned `WouldBlock`.
    /// Edge-triggered.
    Writable(StreamId),
    /// The peer half-closed its direction and every message it sent has
    /// been consumed with `recv_msg`. Nothing more will arrive on this
    /// stream; the local side may still send.
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
