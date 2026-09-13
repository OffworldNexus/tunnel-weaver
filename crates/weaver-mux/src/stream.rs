//! Per-stream bookkeeping: lifecycle state, buffered frames, windows.
//!
//! A stream is bidirectional with independent half-close per direction.
//! Instead of an explicit four-state enum, each direction carries its own
//! "still open" flag; the classic `Open → HalfClosed → Closed` states fall
//! out of the two flags, and the "which half" question is answered
//! directly by whichever flag is `false`.

use std::collections::VecDeque;

use crate::flow::{RecvWindow, SendWindow};
use crate::sched::Class;
use crate::wire::Hints;

/// Stream identifier. `0` is reserved for connection-level frames; the
/// opener chooses the id (client odd, server even).
pub type StreamId = u32;

/// RST code used when a stream is aborted because the whole connection is
/// closing (GOAWAY), as opposed to an application-level `reset`.
pub const RST_CODE_CONNECTION_CLOSED: u32 = 0;

/// Bytes received on a stream but not yet consumed by the application.
#[derive(Debug)]
pub(crate) struct Chunk {
    /// Decompressed payload bytes.
    pub data: Vec<u8>,
    /// How much of `data` the application already read.
    pub offset: usize,
    /// Credit this chunk occupied on the wire (post-compression payload
    /// bytes), released to the peer once the chunk is fully consumed.
    pub wire_len: u32,
}

/// Whether the sender compresses DATA on this stream. Decided once, on the
/// first write, and never revisited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Compress {
    Undecided,
    On,
    Off,
}

#[derive(Debug)]
pub(crate) struct Stream {
    /// Hints from the OPEN head; drive classification and compression.
    pub hints: Hints,
    /// Current scheduling class.
    pub class: Class,
    /// `set_class` was called: automatic rules leave this stream alone.
    pub class_pinned: bool,
    /// We may still send DATA/FIN (no local FIN or RST yet).
    pub local_open: bool,
    /// The peer may still send DATA/FIN (no remote FIN or RST yet).
    pub remote_open: bool,
    /// Our OPEN frame has left the control queue. DATA must not be
    /// scheduled before it, otherwise the peer sees DATA for an unknown
    /// stream.
    pub open_sent: bool,
    /// `finish()` was called; FIN is queued as soon as the outbox drains.
    pub fin_requested: bool,
    /// FIN has been handed to the control queue.
    pub fin_queued: bool,
    /// The application read `Ok(0)` after the remote FIN (or the stream was
    /// reset) — the entry can be dropped once the local side is done too.
    pub eof_delivered: bool,
    /// DATA payloads (flag byte + body), already compressed, waiting for
    /// the scheduler. Every entry already fits inside `send` credit.
    pub outbox: VecDeque<Vec<u8>>,
    /// Sum of `outbox` payload lengths.
    pub outbox_bytes: u32,
    /// Registered as backlogged in the scheduler.
    pub sched_active: bool,
    pub inbox: VecDeque<Chunk>,
    pub send: SendWindow,
    pub recv: RecvWindow,
    /// Cumulative application bytes accepted by `write`.
    pub written_total: u64,
    pub compress: Compress,
    /// `write` returned short; emit `Writable` when credit returns.
    pub wants_writable: bool,
}

impl Stream {
    pub fn new(hints: Hints, class: Class, window: u32, open_sent: bool) -> Self {
        Self {
            hints,
            class,
            class_pinned: false,
            local_open: true,
            remote_open: true,
            open_sent,
            fin_requested: false,
            fin_queued: false,
            eof_delivered: false,
            outbox: VecDeque::new(),
            outbox_bytes: 0,
            sched_active: false,
            inbox: VecDeque::new(),
            send: SendWindow::new(window),
            recv: RecvWindow::new(window),
            written_total: 0,
            compress: Compress::Undecided,
            wants_writable: false,
        }
    }

    /// Wire bytes of the next DATA frame to send, if any.
    pub fn head_len(&self) -> Option<u32> {
        self.outbox
            .front()
            .map(|p| (crate::frame::Frame::HEADER_LEN + p.len()) as u32)
    }

    /// Credit not yet claimed by frames sitting in the outbox.
    pub fn free_credit(&self) -> u32 {
        self.send.credit().saturating_sub(self.outbox_bytes)
    }

    /// True once both directions are done and nothing is left to deliver;
    /// the connection then forgets the stream.
    pub fn is_finished(&self) -> bool {
        !self.local_open
            && !self.remote_open
            && self.outbox.is_empty()
            && self.inbox.is_empty()
            && self.eof_delivered
            && (!self.fin_requested || self.fin_queued)
    }

    /// Bytes still readable by the application.
    pub fn readable_bytes(&self) -> usize {
        self.inbox.iter().map(|c| c.data.len() - c.offset).sum()
    }
}
