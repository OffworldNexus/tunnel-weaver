//! Per-stream bookkeeping: lifecycle state, buffered frames, windows.
//!
//! A stream is bidirectional with independent half-close per direction.
//! Instead of an explicit four-state enum, each direction carries its own
//! "still open" flag; the classic `Open → HalfClosed → Closed` states fall
//! out of the two flags, and the "which half" question is answered
//! directly by whichever flag is `false`.
//!
//! Streams carry *messages*: the transport is message-delimited, so the
//! mux preserves application message boundaries. A message larger than
//! `max_frame` is split into fragments flagged `MORE` and reassembled here.

use std::collections::VecDeque;

use crate::flow::{RecvWindow, SendWindow};
use crate::sched::Class;
use crate::wire::StreamPolicy;

/// Stream identifier. `0` is reserved for connection-level frames; the
/// opener chooses the id (client odd, server even).
pub type StreamId = u32;

/// RST code used when a stream is aborted because the whole connection is
/// closing (GOAWAY), as opposed to an application-level `reset`.
pub const RST_CODE_CONNECTION_CLOSED: u32 = 0;

#[derive(Debug)]
pub(crate) struct Stream {
    /// Current scheduling class.
    pub class: Class,
    /// Demote `Interactive` to `Bulk` past this many written bytes.
    pub demote_after: Option<u64>,
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
    /// `Event::Finished` was emitted: remote FIN seen and inbox drained.
    pub finished_delivered: bool,
    /// DATA payloads (flag byte + body), already compressed, waiting for
    /// the scheduler. Every entry already fits inside `send` credit.
    pub outbox: VecDeque<Vec<u8>>,
    /// Sum of `outbox` payload lengths.
    pub outbox_bytes: u32,
    /// Registered as backlogged in the scheduler.
    pub sched_active: bool,
    /// Complete messages waiting for `recv_msg`, with the wire credit each
    /// one occupied.
    pub inbox: VecDeque<(Vec<u8>, u32)>,
    /// Fragments of the message currently being reassembled.
    pub partial: Vec<u8>,
    /// Wire credit consumed by `partial` so far.
    pub partial_wire: u32,
    pub send: SendWindow,
    pub recv: RecvWindow,
    /// Cumulative application bytes accepted by `send`.
    pub written_total: u64,
    /// `send` returned `WouldBlock`; emit `Writable` when credit returns.
    pub wants_writable: bool,
}

impl Stream {
    pub fn new(policy: StreamPolicy, window: u32, open_sent: bool) -> Self {
        Self {
            class: policy.class,
            demote_after: policy.demote_after,
            local_open: true,
            remote_open: true,
            open_sent,
            fin_requested: false,
            fin_queued: false,
            finished_delivered: false,
            outbox: VecDeque::new(),
            outbox_bytes: 0,
            sched_active: false,
            inbox: VecDeque::new(),
            partial: Vec::new(),
            partial_wire: 0,
            send: SendWindow::new(window),
            recv: RecvWindow::new(window),
            written_total: 0,
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

    /// The remote side is done and everything it sent has been consumed.
    pub fn remote_drained(&self) -> bool {
        !self.remote_open && self.inbox.is_empty()
    }

    /// True once both directions are done and nothing is left to deliver;
    /// the connection then forgets the stream.
    pub fn is_finished(&self) -> bool {
        !self.local_open
            && self.remote_drained()
            && self.outbox.is_empty()
            && self.finished_delivered
            && (!self.fin_requested || self.fin_queued)
    }

    /// Complete messages waiting for `recv_msg`.
    pub fn pending_messages(&self) -> usize {
        self.inbox.len()
    }
}
