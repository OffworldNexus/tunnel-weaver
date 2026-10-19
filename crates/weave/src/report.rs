//! What the client tells its user, as events.
//!
//! The library never prints: every step worth showing is a [`Reporter`]
//! method, and the CLI decides how it looks. Every method defaults to doing
//! nothing, so an implementation only overrides what it shows.

use std::time::{Duration, SystemTime};

use weaver_proto::CertStatus;

use crate::key::SecurityLevel;
use crate::target::ServiceSpec;

/// Receives the client's progress events.
pub trait Reporter: Send + Sync {
    /// The device key is being opened.
    fn opening_key(&self) {}
    /// The key agent's store is locked; waiting for the user to unlock it.
    fn waiting_for_key_store(&self) {}
    /// Pairing opened the device key. `replaced`: the remembered key was gone,
    /// so this one is new.
    fn device_key(&self, _fingerprint: &str, _level: SecurityLevel, _replaced: bool) {}
    /// The key must be created below the requested floor: may it? Asked only
    /// when the caller did not consent up front.
    fn allow_below_floor(&self, _required: SecurityLevel, _available: SecurityLevel) -> bool {
        false
    }

    /// Dialling a relay.
    fn connecting(&self, _host: &str) {}
    /// The pairing channel to a relay is open.
    fn connected(&self, _host: &str) {}

    /// Pairing will move this existing machine onto the device key.
    fn moving_machine(&self, _machine_id: i32) {}
    /// Solving the relay's proof of work.
    fn solving_proof_of_work(&self) {}
    /// The proof of work is solved.
    fn proof_of_work_solved(&self, _took: Duration) {}
    /// Waiting for someone to approve the pairing at `url`.
    fn awaiting_approval(&self, _url: &str) {}

    /// Asking the relay to revoke this machine.
    fn revoking(&self, _host: &str) {}
    /// The relay does not accept this machine's key, so there was nothing to
    /// revoke: the pairing is forgotten anyway.
    fn pairing_not_effective(&self, _host: &str, _reason: &str) {}

    /// The tunnel is authenticated and `services` are being registered.
    fn tunnel_up(&self, _host: &str, _services: &[ServiceSpec]) {}
    /// A service is reachable at `url`.
    fn registered(&self, _service: &str, _url: &str) {}
    /// The relay refused to register a service.
    fn refused(&self, _service: &str, _detail: &str) {}
    /// A service's certificate changed state.
    fn certificate(&self, _service: &str, _state: CertStatus) {}
    /// A visitor request was proxied (or a long-lived one opened or closed).
    fn request(&self, _request: &RequestEvent<'_>) {}
}

/// Reports nothing.
pub struct Silent;

impl Reporter for Silent {}

/// Which moment of a request a [`RequestEvent`] describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// A normal request completed.
    Done,
    /// A long-lived stream (WebSocket, SSE) opened; size and duration are not
    /// known yet.
    Opened,
    /// A long-lived stream closed; totals are final.
    Closed,
}

/// One proxied visitor request.
#[derive(Debug, Clone)]
pub struct RequestEvent<'a> {
    /// When the request head arrived.
    pub at: SystemTime,
    /// The service it was for.
    pub service: &'a str,
    /// The visitor's address, as the relay stamped it; empty when unknown.
    pub visitor: &'a str,
    /// The visitor-side protocol: `h1`, `h2`, `h3` or `ws`.
    pub proto: &'static str,
    /// HTTP method.
    pub method: &'a str,
    /// Path and query.
    pub path: &'a str,
    /// Response status, once known.
    pub status: Option<u16>,
    /// Response body bytes forwarded so far.
    pub bytes: u64,
    /// Time since the request head arrived.
    pub elapsed: Duration,
    /// Which moment this is.
    pub phase: Phase,
    /// The request headers.
    pub request_headers: &'a [(String, Vec<u8>)],
    /// The response headers, once known.
    pub response_headers: &'a [(String, Vec<u8>)],
}
