//! The real-time change bus behind the console's SSE streams (WVR-25).
//!
//! A console stream is scoped to exactly one person: every account read is
//! resolved from the signed-in session to that person, so any change that can
//! affect a stream can be attributed to a person. The bus is therefore a
//! broadcast of person ids and nothing more — a presence transition, a
//! membership write or a metered minute wakes only the streams of the person it
//! concerns.
//!
//! The payload is deliberately absent. A stream recomputes its whole resource
//! from the store on every wake, so an event only has to say *whose* view might
//! have changed — never *what* changed, and never by how much. That keeps the
//! bus cheap (a handful of `i32`s at human event rates) and keeps the resource's
//! own handler the single source of truth for the shape it sends.

use tokio::sync::broadcast;

/// How many person ids may be queued for a subscriber that has fallen behind.
/// A lagged subscriber is told so and recomputes everything, so the buffer only
/// needs to absorb a burst: `Lagged` is a correctness-safe outcome, not data
/// loss.
const CAPACITY: usize = 256;

/// The per-person change fan-out shared by the tunnel registry, the account
/// plane and (implicitly) any other writer of a person's view.
#[derive(Clone)]
pub struct LiveHub {
    tx: broadcast::Sender<i32>,
}

impl LiveHub {
    /// Creates an empty hub. A hub with no subscriber is the normal state on a
    /// relay whose console is closed: sends are dropped and nothing runs.
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(CAPACITY);
        Self { tx }
    }

    /// Announces that `person_id`'s console views may have changed.
    ///
    /// Always safe to call: with no live subscriber the send is discarded, and
    /// a slow subscriber that has overflowed the buffer is woken with `Lagged`
    /// and recomputes its whole resource anyway.
    pub fn notify(&self, person_id: i32) {
        let _ = self.tx.send(person_id);
    }

    /// Subscribes a stream to every person's changes; a stream filters for its
    /// own person id, so the bus needs no per-person subscription bookkeeping.
    pub fn subscribe(&self) -> broadcast::Receiver<i32> {
        self.tx.subscribe()
    }
}

impl Default for LiveHub {
    fn default() -> Self {
        Self::new()
    }
}
