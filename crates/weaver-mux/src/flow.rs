//! Per-stream, per-direction credit-based flow control.
//!
//! Credit is measured in DATA payload bytes as they appear on the wire
//! (flag byte + possibly compressed body), so a compressible stream gets
//! more application bytes per unit of credit — the window bounds buffering
//! in the transport, not application throughput.

/// Send side: how many wire bytes we may still put on the wire before the
/// peer has to grant more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendWindow {
    credit: u32,
}

impl SendWindow {
    /// Start with the negotiated initial window.
    pub fn new(initial: u32) -> Self {
        Self { credit: initial }
    }

    /// Credit currently available.
    pub fn credit(&self) -> u32 {
        self.credit
    }

    /// Peer granted more credit (WINDOW_UPDATE). Saturating so a hostile
    /// peer cannot overflow us into a panic.
    pub fn grant(&mut self, extra: u32) {
        self.credit = self.credit.saturating_add(extra);
    }

    /// A DATA frame of `wire_len` payload bytes left. Caller guarantees the
    /// frame fit; the debug assertion documents the invariant.
    pub fn consume(&mut self, wire_len: u32) {
        debug_assert!(wire_len <= self.credit, "DATA emitted beyond credit");
        self.credit = self.credit.saturating_sub(wire_len);
    }
}

/// Receive side: tracks what the peer may still send and when to top it up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvWindow {
    window: u32,
    /// Bytes the peer may still send before we grant more.
    remaining: u32,
    /// Bytes the application consumed since the last WINDOW_UPDATE.
    consumed_since_update: u32,
}

impl RecvWindow {
    /// Start with the negotiated initial window.
    pub fn new(window: u32) -> Self {
        Self {
            window,
            remaining: window,
            consumed_since_update: 0,
        }
    }

    /// A DATA frame with `wire_len` payload bytes arrived. Returns `false`
    /// when the peer exceeded its credit, which is a protocol violation.
    pub fn on_data(&mut self, wire_len: u32) -> bool {
        if wire_len > self.remaining {
            return false;
        }
        self.remaining -= wire_len;
        true
    }

    /// The application consumed a chunk that occupied `wire_len` bytes of
    /// credit. Returns the credit to announce in a WINDOW_UPDATE once at
    /// least half the window has been consumed since the last one — the
    /// cadence that keeps the peer's pipe full without an update per frame.
    pub fn on_consumed(&mut self, wire_len: u32) -> Option<u32> {
        self.consumed_since_update = self.consumed_since_update.saturating_add(wire_len);
        if self.consumed_since_update >= self.window / 2 {
            let credit = self.consumed_since_update;
            self.consumed_since_update = 0;
            self.remaining = self.remaining.saturating_add(credit);
            Some(credit)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recv_window_enforces_credit_and_half_window_cadence() {
        let mut w = RecvWindow::new(1000);
        assert!(w.on_data(600));
        assert!(!w.on_data(500), "peer overran its credit");
        assert!(w.on_data(400));
        // Consuming 499 bytes is under half the window: no update yet.
        assert_eq!(w.on_consumed(499), None);
        // One more byte crosses the threshold: announce everything consumed.
        assert_eq!(w.on_consumed(1), Some(500));
        assert!(w.on_data(500));
        assert_eq!(w.on_consumed(400), None);
        assert_eq!(w.on_consumed(200), Some(600));
    }

    #[test]
    fn send_window_saturates() {
        let mut s = SendWindow::new(u32::MAX - 1);
        s.grant(10);
        assert_eq!(s.credit(), u32::MAX);
        s.consume(5);
        assert_eq!(s.credit(), u32::MAX - 5);
    }
}
