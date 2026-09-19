//! Connection configuration.

use std::time::Duration;

use rand_core::Rng;

use crate::auth::{Signer, Verifier};

/// Which end of the connection this is, with the data only that end
/// needs. The only asymmetry in the API: a client signs, a server verifies
/// and announces the connection parameters.
pub enum Role {
    /// Dials, receives CHALLENGE, sends HELLO.
    Client {
        /// Signs the handshake transcript.
        signer: Box<dyn Signer + Send>,
    },
    /// Accepts, sends CHALLENGE, answers with WELCOME or REJECT.
    Server {
        /// Looks up and re-validates the client's key.
        verifier: Box<dyn Verifier + Send>,
        /// Parameters announced in WELCOME and in force for both sides.
        params: ServerParams,
        /// Poll `Verifier::still_valid` this often; `None` never re-checks.
        reverify_interval: Option<Duration>,
    },
}

impl Role {
    pub(crate) fn is_server(&self) -> bool {
        matches!(self, Role::Server { .. })
    }
}

impl std::fmt::Debug for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Client { .. } => f.write_str("Client"),
            Role::Server {
                params,
                reverify_interval,
                ..
            } => f
                .debug_struct("Server")
                .field("params", params)
                .field("reverify_interval", reverify_interval)
                .finish(),
        }
    }
}

/// What a server announces in WELCOME. Clamped into the protocol's legal
/// ranges at [`crate::Connection::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerParams {
    /// Largest DATA payload per frame, in bytes.
    pub max_frame: u32,
    /// Initial per-stream, per-direction credit, in bytes.
    pub initial_window: u32,
    /// Largest application message on a stream; bounds both sides'
    /// reassembly buffers.
    pub max_message: u32,
    /// Whether zstd may be used on this connection at all. A server can
    /// refuse compression, never force it.
    pub compression_allowed: bool,
}

impl Default for ServerParams {
    fn default() -> Self {
        Self {
            max_frame: 16 * 1024,
            initial_window: 512 * 1024,
            max_message: 1024 * 1024,
            compression_allowed: true,
        }
    }
}

/// QFQ weights of the four scheduling classes.
///
/// Only the ratios matter. Defaults give interactive traffic roughly a
/// 90/10 edge over bulk while keeping bulk work-conserving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Weights {
    /// Handshake, GOAWAY, PING/PONG, WINDOW_UPDATE, OPEN/FIN/RST.
    pub control: u32,
    /// Latency-sensitive streams; never compressed.
    pub realtime: u32,
    /// Default class; demoted to bulk after `Config::bulk_threshold` bytes.
    pub interactive: u32,
    /// Throughput streams.
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
/// adapter. Keys are never held here: only the boxed [`Signer`] or
/// [`Verifier`] inside [`Role`].
pub struct Config {
    /// Client or server, with that side's key access.
    pub role: Role,
    /// Sole source of randomness (handshake nonces).
    pub rng: Box<dyn Rng + Send>,
    /// The hostname the client dialed; both sides must pass the exact same
    /// string, it is part of the signed transcript.
    pub server_name: String,
    /// Scheduler class weights.
    pub weights: Weights,
    /// An `Interactive` stream becomes `Bulk` once this many bytes have
    /// been sent on it. `None` disables demotion.
    pub bulk_threshold: Option<u64>,
    /// Local zstd level; not negotiated.
    pub zstd_level: i32,
    /// Local compression stance. Compression happens only when both this
    /// and the server's `compression_allowed` are true.
    pub compression_allowed: bool,
    /// Deadline for the whole CHALLENGE/HELLO/WELCOME exchange.
    pub handshake_timeout: Duration,
    /// Send a PING after this much silence on the connection.
    pub ping_interval: Duration,
    /// Close the connection after this much silence from the peer.
    pub idle_timeout: Duration,
    /// TLS exporter value mixed into the transcript when both sides set it.
    pub channel_binding: Option<[u8; 32]>,
}

/// Default `bulk_threshold`.
pub const DEFAULT_BULK_THRESHOLD: u64 = 256 * 1024;

impl Config {
    fn base(role: Role, server_name: impl Into<String>, rng: Box<dyn Rng + Send>) -> Self {
        Self {
            role,
            rng,
            server_name: server_name.into(),
            weights: Weights::default(),
            bulk_threshold: Some(DEFAULT_BULK_THRESHOLD),
            zstd_level: 3,
            compression_allowed: true,
            handshake_timeout: Duration::from_secs(10),
            ping_interval: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(60),
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
        Self::base(Role::Client { signer }, server_name, rng)
    }

    /// Server configuration with all defaults.
    pub fn server(
        verifier: Box<dyn Verifier + Send>,
        server_name: impl Into<String>,
        rng: Box<dyn Rng + Send>,
    ) -> Self {
        Self::base(
            Role::Server {
                verifier,
                params: ServerParams::default(),
                reverify_interval: None,
            },
            server_name,
            rng,
        )
    }

    /// Server-announced parameters, mutable. `None` on a client.
    pub fn server_params_mut(&mut self) -> Option<&mut ServerParams> {
        match &mut self.role {
            Role::Server { params, .. } => Some(params),
            Role::Client { .. } => None,
        }
    }

    /// Clamp the locally configured values into the ranges the protocol
    /// allows so a server never announces parameters the client must reject.
    pub(crate) fn normalize(&mut self) {
        if let Some(p) = self.server_params_mut() {
            p.initial_window = p.initial_window.clamp(MIN_WINDOW, MAX_WINDOW);
            p.max_frame = p.max_frame.max(2);
            p.max_message = p.max_message.max(MIN_MESSAGE);
        }
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
            .field("weights", &self.weights)
            .field("bulk_threshold", &self.bulk_threshold)
            .field("zstd_level", &self.zstd_level)
            .field("compression_allowed", &self.compression_allowed)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("ping_interval", &self.ping_interval)
            .field("idle_timeout", &self.idle_timeout)
            .field("channel_binding", &self.channel_binding.is_some())
            .finish_non_exhaustive()
    }
}
