//! Connection configuration.

use std::time::Duration;

use rand_core::Rng;

use crate::auth::{Signer, Verifier};
use crate::wire::Compression;

/// Which end of the connection this is. The only asymmetry in the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Dials, receives CHALLENGE, sends HELLO.
    Client,
    /// Accepts, sends CHALLENGE, answers with WELCOME or REJECT.
    Server,
}

/// QFQ weights of the four scheduling classes.
///
/// Only the ratios matter. Defaults give interactive traffic roughly a
/// 90/10 edge over bulk while keeping bulk work-conserving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Weights {
    /// Handshake, GOAWAY, PING/PONG, WINDOW_UPDATE, OPEN/FIN/RST.
    pub control: u32,
    /// Upgrades and server-sent events.
    pub realtime: u32,
    /// Request/response traffic.
    pub interactive: u32,
    /// Large bodies, by hint or after `bulk_threshold` bytes.
    pub bulk: u32,
}

impl Default for Weights {
    fn default() -> Self {
        Self {
            control: 1000,
            realtime: 300,
            interactive: 300,
            bulk: 40,
        }
    }
}

/// Smallest `initial_window` a server may announce.
pub const MIN_WINDOW: u32 = 64 * 1024;
/// Largest `initial_window` a server may announce.
pub const MAX_WINDOW: u32 = 4 * 1024 * 1024;
/// Smallest `max_message` a server may announce.
pub const MIN_MESSAGE: u32 = 16 * 1024;

/// Everything a [`crate::Connection`] needs to know, supplied by the
/// adapter. Keys are never held here: only a boxed [`Signer`] or
/// [`Verifier`], depending on the role.
pub struct Config {
    /// Client or server.
    pub role: Role,
    /// Sole source of randomness (handshake nonces).
    pub rng: Box<dyn Rng + Send>,
    /// Client-side key access. `None` on the server.
    pub signer: Option<Box<dyn Signer + Send>>,
    /// Server-side key lookup. `None` on the client.
    pub verifier: Option<Box<dyn Verifier + Send>>,
    /// The hostname the client dialed; both sides must pass the exact same
    /// string, it is part of the signed transcript.
    pub server_name: String,
    /// Largest DATA payload per frame. Server value is announced in
    /// WELCOME; client value is ignored.
    pub max_frame: u32,
    /// Initial per-stream credit. Server value is announced in WELCOME.
    pub initial_window: u32,
    /// Largest application message on a stream. Server value is announced
    /// in WELCOME and bounds both sides' reassembly buffers.
    pub max_message: u32,
    /// Scheduler class weights.
    pub weights: Weights,
    /// Local zstd level; not negotiated.
    pub zstd_level: i32,
    /// Local compression stance. The server's value is announced in
    /// WELCOME and may only ever turn compression *off* for the client.
    pub compression: Compression,
    /// Deadline for the whole CHALLENGE/HELLO/WELCOME exchange.
    pub handshake_timeout: Duration,
    /// Send a PING after this much silence on the connection.
    pub ping_interval: Duration,
    /// Close the connection after this much silence from the peer.
    pub idle_timeout: Duration,
    /// Server only: poll `Verifier::still_valid` this often.
    pub reverify_interval: Option<Duration>,
    /// TLS exporter value mixed into the transcript when both sides set it.
    pub channel_binding: Option<[u8; 32]>,
}

impl Config {
    fn base(role: Role, server_name: impl Into<String>, rng: Box<dyn Rng + Send>) -> Self {
        Self {
            role,
            rng,
            signer: None,
            verifier: None,
            server_name: server_name.into(),
            max_frame: 16 * 1024,
            initial_window: 512 * 1024,
            max_message: 1024 * 1024,
            weights: Weights::default(),
            zstd_level: 3,
            compression: Compression::BodyOnly,
            handshake_timeout: Duration::from_secs(10),
            ping_interval: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(60),
            reverify_interval: None,
            channel_binding: None,
        }
    }

    /// Client configuration with all defaults. `rng` is only used for the
    /// handshake nonce.
    pub fn client(
        signer: Box<dyn Signer + Send>,
        server_name: impl Into<String>,
        rng: Box<dyn Rng + Send>,
    ) -> Self {
        let mut cfg = Self::base(Role::Client, server_name, rng);
        cfg.signer = Some(signer);
        cfg
    }

    /// Server configuration with all defaults.
    pub fn server(
        verifier: Box<dyn Verifier + Send>,
        server_name: impl Into<String>,
        rng: Box<dyn Rng + Send>,
    ) -> Self {
        let mut cfg = Self::base(Role::Server, server_name, rng);
        cfg.verifier = Some(verifier);
        cfg
    }

    /// Clamp the locally configured values into the ranges the protocol
    /// allows so a server never announces parameters the client must reject.
    pub(crate) fn normalize(&mut self) {
        self.initial_window = self.initial_window.clamp(MIN_WINDOW, MAX_WINDOW);
        self.max_frame = self.max_frame.max(2);
        self.max_message = self.max_message.max(MIN_MESSAGE);
        self.weights.control = self.weights.control.max(1);
        self.weights.realtime = self.weights.realtime.max(1);
        self.weights.interactive = self.weights.interactive.max(1);
        self.weights.bulk = self.weights.bulk.max(1);
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("role", &self.role)
            .field("server_name", &self.server_name)
            .field("max_frame", &self.max_frame)
            .field("initial_window", &self.initial_window)
            .field("max_message", &self.max_message)
            .field("weights", &self.weights)
            .field("zstd_level", &self.zstd_level)
            .field("compression", &self.compression)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("ping_interval", &self.ping_interval)
            .field("idle_timeout", &self.idle_timeout)
            .field("reverify_interval", &self.reverify_interval)
            .field("channel_binding", &self.channel_binding.is_some())
            .finish_non_exhaustive()
    }
}
