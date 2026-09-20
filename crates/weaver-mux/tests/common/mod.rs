//! In-memory test harness: two `Connection`s wired back to back, a fake
//! clock, and helpers that pump frames until both sides go quiet.
#![allow(dead_code)]

use std::time::Duration;

use weaver_mux::testing::{Ed25519TestSigner, FakeClock, MapVerifier, SeededRng};
use weaver_mux::{Compress, Config, Connection, Event, Frame, FrameType, Signer as _};

pub const SERVER_NAME: &str = "mux.example.test";

pub fn client_config(seed: u64) -> Config {
    let signer = Ed25519TestSigner::from_seed(seed);
    Config::client(
        Box::new(signer),
        SERVER_NAME,
        Box::new(SeededRng::new(1000 + seed)),
    )
}

pub fn server_config(client_seed: u64) -> Config {
    let signer = Ed25519TestSigner::from_seed(client_seed);
    let verifier = MapVerifier::with_key(signer.key_id(), signer.public_key());
    Config::server(
        Box::new(verifier),
        SERVER_NAME,
        Box::new(SeededRng::new(2000 + client_seed)),
    )
}

pub struct Pair {
    pub clock: FakeClock,
    pub client: Connection,
    pub server: Connection,
    /// Every frame that crossed the wire, in order, for assertions.
    pub log: Vec<(Side, Frame)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

impl Pair {
    pub fn new(client_cfg: Config, server_cfg: Config) -> Self {
        // The one wall-clock read in the whole test suite: it only anchors
        // the fake clock, every later instant is derived from it. The crate
        // itself forbids `Instant::now` via clippy.toml; tests are a
        // separate crate and opt in explicitly here.
        #[allow(clippy::disallowed_methods)]
        let clock = FakeClock::at(std::time::Instant::now());
        let now = clock.now();
        Self {
            clock,
            client: Connection::new(client_cfg, now),
            server: Connection::new(server_cfg, now),
            log: Vec::new(),
        }
    }

    /// Default pair with matching keys.
    pub fn default_pair() -> Self {
        Self::new(client_config(1), server_config(1))
    }

    /// A pair that has completed the handshake.
    pub fn authenticated() -> Self {
        let mut p = Self::default_pair();
        p.pump();
        assert!(
            matches!(p.client_event(), Some(Event::Authenticated { .. })),
            "client must authenticate"
        );
        assert!(
            matches!(p.server_event(), Some(Event::Authenticated { .. })),
            "server must authenticate"
        );
        p
    }

    pub fn side(&mut self, side: Side) -> &mut Connection {
        match side {
            Side::Client => &mut self.client,
            Side::Server => &mut self.server,
        }
    }

    /// Move one frame from `from` to its peer. Returns the frame if there
    /// was one.
    pub fn step(&mut self, from: Side) -> Option<Frame> {
        let now = self.clock.now();
        let mut buf = Vec::new();
        if !self.side(from).poll_transmit(now, &mut buf) {
            return None;
        }
        let frame = Frame::parse(&buf).expect("we only emit well-formed frames");
        let to = match from {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        };
        // A closed peer rejects everything; that is expected after GOAWAY.
        let _ = self.side(to).recv(now, &buf);
        self.log.push((from, frame.clone()));
        Some(frame)
    }

    /// Alternate sides until neither has anything to send.
    pub fn pump(&mut self) {
        loop {
            let a = self.step(Side::Server).is_some();
            let b = self.step(Side::Client).is_some();
            if !a && !b {
                break;
            }
        }
    }

    pub fn advance(&mut self, by: Duration) {
        let now = self.clock.advance(by);
        self.client.handle_timeout(now);
        self.server.handle_timeout(now);
    }

    pub fn client_event(&mut self) -> Option<Event> {
        self.client.poll_event()
    }

    pub fn server_event(&mut self) -> Option<Event> {
        self.server.poll_event()
    }

    pub fn drain_events(&mut self, side: Side) -> Vec<Event> {
        let conn = self.side(side);
        let mut out = Vec::new();
        while let Some(e) = conn.poll_event() {
            out.push(e);
        }
        out
    }

    pub fn frames_of(&self, from: Side, ty: FrameType) -> Vec<&Frame> {
        self.log
            .iter()
            .filter(|(s, f)| *s == from && f.frame_type == ty)
            .map(|(_, f)| f)
            .collect()
    }
}

/// Take every complete message currently available on a stream.
pub fn recv_all(conn: &mut Connection, id: u32) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Ok(m) = conn.recv_msg(id) {
        out.push(m);
    }
    out
}

/// Concatenation of every message currently available on a stream.
pub fn read_all(conn: &mut Connection, id: u32) -> Vec<u8> {
    recv_all(conn, id).concat()
}

/// `send` with `Compress::Auto`; panics on anything but success.
pub fn send(conn: &mut Connection, id: u32, msg: &[u8]) {
    conn.send(id, msg, Compress::Auto).expect("send");
}

/// Set a server's announced parameters.
pub fn server_params(cfg: &mut Config, f: impl FnOnce(&mut weaver_mux::ServerParams)) {
    f(cfg.server_params_mut().expect("server config"));
}

/// Wire bytes of a hand-built frame.
pub fn encode(frame: &Frame) -> Vec<u8> {
    let mut buf = Vec::new();
    frame.encode_into(&mut buf);
    buf
}
