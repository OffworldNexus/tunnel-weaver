//! Sans-IO authenticated, fair-queued stream multiplexer for Tunnel Weaver.
//!
//! `weaver-mux` turns one reliable, ordered, message-delimited pipe (a
//! WebSocket today) into many bidirectional *message* streams with
//! per-stream flow control, weighted fair scheduling, opportunistic zstd
//! compression, and an SSH-style challenge/response handshake. It does
//! **no I/O**: bytes and events go in and out of a [`Connection`], and
//! every notion of time is the `now: Instant` the caller passes in.
//!
//! # Policy, not content
//!
//! The mux knows nothing about what travels on a stream. The layer above
//! tells it *what to do*: a scheduling [`Class`] at [`Connection::open`]
//! (changeable later with [`Connection::set_class`]), and a [`Compress`]
//! stance on every [`Connection::send`]. Under [`Compress::Auto`] the mux
//! may still decline (size floor, entropy probe, `Realtime` class); under
//! [`Compress::Never`] it never compresses — that is how the layer above
//! keeps secrets and already-encoded bodies out of the compressor. The one
//! decision the mux takes alone: an `Interactive` stream that has sent more
//! than `Config::bulk_threshold` bytes becomes `Bulk`.
//!
//! # Messages, not bytes
//!
//! The transport delimits messages, so the mux does too: one
//! [`Connection::send`] is one message, delivered whole by one
//! [`Connection::recv_msg`]. Messages larger than `max_frame` are split
//! into `MORE`-flagged fragments and reassembled by the receiver, bounded
//! by the negotiated `max_message`.
//!
//! # What the crate does not do
//!
//! * open sockets, spawn threads, arm timers, or read a clock;
//! * encrypt (TLS is the transport's job) or run congestion control;
//! * hold keys — the client passes a [`Signer`], the server a [`Verifier`];
//! * know about people, machines, hostnames, or tunnels. The only identity
//!   it understands is the [`KeyId`] that signed the handshake.
//!
//! # Driving a connection
//!
//! ```text
//! let mut conn = Connection::new(Config::client(signer, "example.com", rng), now);
//! loop {
//!     // 1. bytes in
//!     while let Some(msg) = transport.try_recv() { conn.recv(now, &msg)?; }
//!     // 2. deadlines
//!     conn.handle_timeout(now);
//!     // 3. bytes out — one frame per call, only after the previous one flushed
//!     while transport.is_flushed() && conn.poll_transmit(now, &mut buf) {
//!         transport.send(&buf);
//!     }
//!     // 4. events
//!     while let Some(ev) = conn.poll_event() { handle(ev); }
//!     //    on Event::Readable(id): loop conn.recv_msg(id) until WouldBlock
//!     // 5. sleep until conn.next_timeout() or the transport is readable
//! }
//! ```
//!
//! # Adapter rules
//!
//! The scheduler can only be fair if it decides *what goes next* as late as
//! possible. Two rules keep the decision late:
//!
//! 1. **Call [`Connection::poll_transmit`] only after the previous frame has
//!    been flushed to the sink.** Never pre-buffer frames in the adapter: a
//!    queue of already-scheduled frames is exactly the head-of-line
//!    blocking the scheduler exists to avoid.
//! 2. **Set `TCP_NOTSENT_LOWAT` (about 32 KiB) on Linux and macOS** so the
//!    kernel signals writability only when its own send queue is nearly
//!    empty; otherwise megabytes of bulk data sit in the socket buffer
//!    ahead of an urgent frame. Windows has no equivalent — keep the
//!    adapter's own buffering minimal there.
//!
//! # Structure
//!
//! * [`Connection`]: the state machine and the whole application API;
//! * [`Config`] / [`Role`]: what the adapter supplies;
//! * [`auth`]: the [`Signer`] / [`Verifier`] traits the adapter implements;
//! * [`wire`] / [`Frame`]: payload and frame codecs, public for tests and
//!   fuzz targets only.
#![forbid(clippy::disallowed_methods)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
mod compress;
mod config;
mod connection;
mod error;
mod event;
mod flow;
mod frame;
mod handshake;
mod sched;
mod stream;
mod timers;
pub mod wire;

#[cfg(feature = "test-util")]
pub mod testing;

pub use auth::{PublicKey, Signer, Verifier};
pub use compress::Compress;
pub use config::{
    Config, DEFAULT_BULK_THRESHOLD, MAX_WINDOW, MIN_MESSAGE, MIN_WINDOW, Role, ServerParams,
    Weights,
};
pub use connection::Connection;
pub use error::{CloseCode, CloseReason, ProtocolError, RejectCode, SignError, StreamError};
pub use event::Event;
pub use frame::{Frame, FrameType};
pub use sched::Class;
pub use stream::{RST_CODE_CONNECTION_CLOSED, StreamId};
pub use wire::{KeyId, Params, Signature};
