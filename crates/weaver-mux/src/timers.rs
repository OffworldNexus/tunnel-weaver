//! Deadline bookkeeping. Every value here derives from `now` instants the
//! caller passed in; the crate never reads a clock.

use std::time::{Duration, Instant};

/// Which deadline fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expired {
    /// Handshake did not complete in time.
    Handshake,
    /// Nothing heard from the peer for `idle_timeout`.
    Idle,
    /// Time to send a keepalive PING.
    Ping,
    /// Time to ask the `Verifier` whether the key is still valid.
    Reverify,
}

#[derive(Debug)]
pub struct Timers {
    /// Last `now` seen; enforces monotonicity.
    pub last_now: Instant,
    /// Last frame received from the peer.
    pub last_recv: Instant,
    /// Last frame we put on the wire.
    pub last_send: Instant,
    /// Armed until the handshake completes.
    pub handshake_deadline: Option<Instant>,
    /// Set once authenticated; enables ping/idle/reverify.
    pub authenticated: bool,
    /// `(opaque, sent_at)` of the PING awaiting its PONG.
    pub ping_outstanding: Option<(u64, Instant)>,
    /// Next `still_valid` poll (server with `reverify_interval` only).
    pub reverify_due: Option<Instant>,
    pub ping_interval: Duration,
    pub idle_timeout: Duration,
    pub reverify_interval: Option<Duration>,
}

impl Timers {
    pub fn new(
        now: Instant,
        handshake_timeout: Duration,
        ping_interval: Duration,
        idle_timeout: Duration,
        reverify_interval: Option<Duration>,
    ) -> Self {
        Self {
            last_now: now,
            last_recv: now,
            last_send: now,
            handshake_deadline: Some(now + handshake_timeout),
            authenticated: false,
            ping_outstanding: None,
            reverify_due: None,
            ping_interval,
            idle_timeout,
            reverify_interval,
        }
    }

    /// Clamp `now` so time never runs backwards inside the connection. A
    /// regression is a caller bug — loud in debug, harmless in release.
    pub fn observe(&mut self, now: Instant) -> Instant {
        debug_assert!(now >= self.last_now, "`now` went backwards");
        let now = now.max(self.last_now);
        self.last_now = now;
        now
    }

    /// Handshake finished: switch from the handshake deadline to the
    /// steady-state keepalive/idle deadlines.
    pub fn on_authenticated(&mut self, now: Instant) {
        self.authenticated = true;
        self.handshake_deadline = None;
        self.last_recv = now;
        self.last_send = now;
        self.reverify_due = self.reverify_interval.map(|i| now + i);
    }

    /// Any frame from the peer counts as liveness.
    pub fn on_recv(&mut self, now: Instant) {
        self.last_recv = now;
    }

    pub fn on_send(&mut self, now: Instant) {
        self.last_send = now;
    }

    fn last_activity(&self) -> Instant {
        self.last_recv.max(self.last_send)
    }

    fn ping_due(&self) -> Option<Instant> {
        if self.authenticated && self.ping_outstanding.is_none() {
            Some(self.last_activity() + self.ping_interval)
        } else {
            None
        }
    }

    fn idle_deadline(&self) -> Option<Instant> {
        self.authenticated
            .then(|| self.last_recv + self.idle_timeout)
    }

    /// Earliest armed deadline, for the adapter's timer.
    pub fn next_timeout(&self) -> Option<Instant> {
        [
            self.handshake_deadline,
            self.ping_due(),
            self.idle_deadline(),
            self.reverify_due,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// The first deadline that has passed at `now`, in severity order:
    /// closes before keepalives. Callers loop until `None`, updating state
    /// between calls so a fired deadline is not reported twice.
    pub fn expired(&self, now: Instant) -> Option<Expired> {
        if self.handshake_deadline.is_some_and(|d| now >= d) {
            return Some(Expired::Handshake);
        }
        if self.idle_deadline().is_some_and(|d| now >= d) {
            return Some(Expired::Idle);
        }
        if self.reverify_due.is_some_and(|d| now >= d) {
            return Some(Expired::Reverify);
        }
        if self.ping_due().is_some_and(|d| now >= d) {
            return Some(Expired::Ping);
        }
        None
    }

    /// Disarm everything (connection closed).
    pub fn clear(&mut self) {
        self.handshake_deadline = None;
        self.authenticated = false;
        self.ping_outstanding = None;
        self.reverify_due = None;
    }
}
