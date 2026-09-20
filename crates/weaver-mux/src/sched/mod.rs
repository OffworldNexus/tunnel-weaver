//! Two-level QFQ scheduling tree: classes at the top, streams inside each
//! data class, and a FIFO of control frames as the control class's backlog.

mod qfq;

use std::collections::VecDeque;

use qfq::Qfq;
use serde::{Deserialize, Serialize};

use crate::config::Weights;
use crate::frame::Frame;
use crate::stream::StreamId;

/// Scheduling class of a stream (or of the control queue).
///
/// Carried on the wire as the OPEN payload, so the variant order is part
/// of the protocol: append, never reorder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Class {
    /// Connection-level frames plus OPEN/FIN/RST/WINDOW_UPDATE. Not a
    /// valid stream class.
    Control,
    /// Latency-sensitive traffic. The mux never compresses on this class.
    Realtime,
    /// Request/response traffic: the default. Demoted to `Bulk` once
    /// `Config::bulk_threshold` bytes have been sent on the stream.
    Interactive,
    /// Throughput traffic.
    Bulk,
}

impl Class {
    fn idx(self) -> usize {
        match self {
            Class::Control => unreachable!("control has no inner scheduler"),
            Class::Realtime => 0,
            Class::Interactive => 1,
            Class::Bulk => 2,
        }
    }
}

/// What `poll_transmit` should emit next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pick {
    /// Pop the front of the control queue.
    Control,
    /// Pop the front of this stream's outbox.
    Stream(StreamId),
}

/// The scheduling tree.
#[derive(Debug)]
pub struct SchedTree {
    top: Qfq<Class>,
    inner: [Qfq<StreamId>; 3],
    control: VecDeque<Frame>,
    max_frame: u32,
}

impl SchedTree {
    /// Build the tree. `max_frame` is every flow's `lmax` — including the
    /// control flow, whose OPEN frames carry application heads of
    /// unbounded size, so a smaller constant would only be a guess.
    pub fn new(weights: Weights, max_frame: u32) -> Self {
        let lmax = max_frame + crate::frame::Frame::HEADER_LEN as u32;
        let mut top = Qfq::new();
        top.add_flow(Class::Control, weights.control, lmax);
        top.add_flow(Class::Realtime, weights.realtime, lmax);
        top.add_flow(Class::Interactive, weights.interactive, lmax);
        top.add_flow(Class::Bulk, weights.bulk, lmax);
        Self {
            top,
            inner: [Qfq::new(), Qfq::new(), Qfq::new()],
            control: VecDeque::new(),
            max_frame: lmax,
        }
    }

    /// Queue a control frame; it becomes the control flow's backlog.
    pub fn push_control(&mut self, frame: Frame) {
        let len = frame.wire_len() as u32;
        self.control.push_back(frame);
        self.top.activate(Class::Control, len);
    }

    /// Drop every queued control frame (connection closing).
    pub fn clear_control(&mut self) {
        self.control.clear();
        self.top.deactivate(Class::Control);
    }

    /// Register a stream in its class with weight 1 (equal shares inside a
    /// class).
    pub fn add_stream(&mut self, id: StreamId, class: Class) {
        self.inner[class.idx()].add_flow(id, 1, self.max_frame);
    }

    /// Forget a stream.
    pub fn remove_stream(&mut self, id: StreamId, class: Class) {
        let inner = &mut self.inner[class.idx()];
        inner.remove_flow(id);
        if !inner.has_backlog() {
            self.top.deactivate(class);
        }
    }

    /// The stream has a frame of `head_len` wire bytes ready and the credit
    /// to send it.
    pub fn activate_stream(&mut self, id: StreamId, class: Class, head_len: u32) {
        let inner = &mut self.inner[class.idx()];
        let was_idle = !inner.has_backlog();
        inner.activate(id, head_len);
        if was_idle {
            let len = inner.next_head_len().unwrap_or(head_len);
            self.top.activate(class, len);
        }
    }

    /// Move a stream between classes. It re-enters the new class at that
    /// class's current virtual time (fresh flow, `S = V`).
    pub fn reclass(&mut self, id: StreamId, from: Class, to: Class, head_len: Option<u32>) {
        if from == to {
            return;
        }
        self.remove_stream(id, from);
        self.add_stream(id, to);
        if let Some(len) = head_len {
            self.activate_stream(id, to, len);
        }
    }

    /// Choose what to send next. Does not consume anything: the caller
    /// pops the frame and then reports it via [`SchedTree::served`].
    pub fn pick(&mut self) -> Option<Pick> {
        let class = self.top.peek()?;
        match class {
            Class::Control => Some(Pick::Control),
            data => self.inner[data.idx()].peek().map(Pick::Stream),
        }
    }

    /// Pop the front control frame (after a `Pick::Control`).
    pub fn pop_control(&mut self) -> Option<Frame> {
        self.control.pop_front()
    }

    /// Account for `len` wire bytes just sent. `next_len` is the stream's
    /// following frame (if it stays backlogged); ignored for control, whose
    /// queue is inspected directly.
    pub fn served(&mut self, pick: Pick, class: Class, len: u32, next_len: Option<u32>) {
        match pick {
            Pick::Control => {
                let next = self.control.front().map(|f| f.wire_len() as u32);
                self.top.served(Class::Control, len, next);
            }
            Pick::Stream(id) => {
                let inner = &mut self.inner[class.idx()];
                inner.served(id, len, next_len);
                let next = inner.next_head_len();
                self.top.served(class, len, next);
            }
        }
    }
}
