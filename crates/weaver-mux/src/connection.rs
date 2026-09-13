//! The [`Connection`] state machine: the crate's entire public surface.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::auth;
use crate::compress::{self, ZstdCtx};
use crate::config::{Config, MAX_WINDOW, MIN_WINDOW, Role};
use crate::error::{CloseCode, GoAway, ProtocolError, RejectCode, StreamError};
use crate::event::Event;
use crate::frame::{Frame, FrameType};
use crate::handshake::{self, HandshakeState};
use crate::sched::{Class, Pick, SchedTree, classify};
use crate::stream::{Chunk, Compress, RST_CODE_CONNECTION_CLOSED, Stream, StreamId};
use crate::timers::{Expired, Timers};
use crate::wire::{
    self, Challenge, Compression, DATA_FLAG_COMPRESSED, Head, Hello, KeyId, MAX_VERSION, Params,
    Ping, Reject, Rst, Welcome, WindowUpdate,
};

/// Multiplier of `max_frame` bounding the decompressed size of one DATA
/// frame, so a hostile peer cannot turn a tiny frame into gigabytes.
const DECOMPRESS_CAP_FACTOR: usize = 8;

/// One multiplexed connection. Fully symmetric except for [`Role`].
///
/// All methods take `&mut self` and never block. Time is only ever the
/// `now` passed in; randomness only ever comes from `Config::rng`.
pub struct Connection {
    role: Role,
    cfg: Config,
    hs: HandshakeState,
    nonce_s: Option<[u8; 32]>,
    key_id: Option<KeyId>,
    version: Option<u16>,
    params: Option<Params>,
    compression_enabled: bool,
    streams: HashMap<StreamId, Stream>,
    next_stream_id: u32,
    last_peer_stream_id: u32,
    sched: SchedTree,
    /// Handshake frames go out before anything else and before the
    /// scheduler exists in its final shape (the client learns `max_frame`
    /// from WELCOME).
    handshake_out: VecDeque<Frame>,
    /// GOAWAY is emitted from here, ahead of the scheduler, so it is
    /// literally the next frame after `close()`.
    pending_goaway: Option<Frame>,
    closed: Option<GoAway>,
    timers: Timers,
    events: VecDeque<Event>,
    rtt: Option<Duration>,
    ping_counter: u64,
    zstd: ZstdCtx,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("role", &self.role)
            .field("hs", &self.hs)
            .field("version", &self.version)
            .field("streams", &self.streams.len())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl Connection {
    /// Create a connection. `now` anchors the handshake deadline; the
    /// server queues its CHALLENGE immediately, so call `poll_transmit`
    /// right after.
    pub fn new(mut cfg: Config, now: Instant) -> Self {
        cfg.normalize();
        let timers = Timers::new(
            now,
            cfg.handshake_timeout,
            cfg.ping_interval,
            cfg.idle_timeout,
            match cfg.role {
                Role::Server => cfg.reverify_interval,
                Role::Client => None,
            },
        );
        let sched = SchedTree::new(cfg.weights, cfg.max_frame);
        let zstd = ZstdCtx::new(cfg.zstd_level);
        let (hs, next_stream_id) = match cfg.role {
            Role::Client => (HandshakeState::AwaitChallenge, 1),
            Role::Server => (HandshakeState::ChallengeSent, 2),
        };
        let mut conn = Self {
            role: cfg.role,
            cfg,
            hs,
            nonce_s: None,
            key_id: None,
            version: None,
            params: None,
            compression_enabled: false,
            streams: HashMap::new(),
            next_stream_id,
            last_peer_stream_id: 0,
            sched,
            handshake_out: VecDeque::new(),
            pending_goaway: None,
            closed: None,
            timers,
            events: VecDeque::new(),
            rtt: None,
            ping_counter: 0,
            zstd,
        };
        if conn.role == Role::Server {
            let mut nonce_s = [0u8; 32];
            conn.cfg.rng.fill_bytes(&mut nonce_s);
            conn.nonce_s = Some(nonce_s);
            conn.handshake_out.push_back(Frame {
                stream_id: 0,
                frame_type: FrameType::Challenge,
                payload: wire::encode_payload(&Challenge { nonce_s }),
            });
        }
        conn
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    /// Negotiated protocol version; `None` before WELCOME.
    pub fn version(&self) -> Option<u16> {
        self.version
    }

    /// Most recent PING → PONG round trip, measured with the caller's `now`.
    pub fn rtt(&self) -> Option<Duration> {
        self.rtt
    }

    /// True once `close()` was called or the peer closed.
    pub fn is_closed(&self) -> bool {
        self.closed.is_some()
    }

    /// Parameters in force after WELCOME.
    pub fn params(&self) -> Option<Params> {
        self.params
    }

    /// Current scheduling class of a stream, if it exists.
    pub fn class_of(&self, id: StreamId) -> Option<Class> {
        self.streams.get(&id).map(|s| s.class)
    }

    /// Next event for the application, in order.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Earliest instant at which [`Connection::handle_timeout`] has work.
    pub fn next_timeout(&self) -> Option<Instant> {
        if self.closed.is_some() {
            return None;
        }
        self.timers.next_timeout()
    }

    // ------------------------------------------------------------------
    // Time
    // ------------------------------------------------------------------

    /// Fire every deadline that has passed. Idempotent: a deadline fires
    /// once, and a closed connection has no deadlines.
    pub fn handle_timeout(&mut self, now: Instant) {
        let now = self.timers.observe(now);
        while self.closed.is_none() {
            match self.timers.expired(now) {
                None => break,
                Some(Expired::Handshake) | Some(Expired::Idle) => {
                    self.close_internal(GoAway::new(CloseCode::Timeout), true);
                }
                Some(Expired::Reverify) => {
                    let still_valid = match (&mut self.cfg.verifier, &self.key_id) {
                        (Some(v), Some(k)) => v.still_valid(k),
                        _ => true,
                    };
                    if let Some(interval) = self.timers.reverify_interval {
                        self.timers.reverify_due = Some(now + interval);
                    }
                    if !still_valid {
                        self.close_internal(GoAway::new(CloseCode::KeyRevoked), true);
                    }
                }
                Some(Expired::Ping) => {
                    self.ping_counter += 1;
                    let opaque = self.ping_counter;
                    self.timers.ping_outstanding = Some((opaque, now));
                    self.sched.push_control(Frame {
                        stream_id: 0,
                        frame_type: FrameType::Ping,
                        payload: wire::encode_payload(&Ping { opaque }),
                    });
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Transmit
    // ------------------------------------------------------------------

    /// Fill `buf` with exactly one frame. Returns `false` (and leaves `buf`
    /// empty) when there is nothing to send. Call only after the previous
    /// frame has been flushed to the transport.
    pub fn poll_transmit(&mut self, now: Instant, buf: &mut Vec<u8>) -> bool {
        let now = self.timers.observe(now);
        buf.clear();

        if let Some(frame) = self.pending_goaway.take() {
            frame.encode_into(buf);
            self.timers.on_send(now);
            return true;
        }
        if let Some(frame) = self.handshake_out.pop_front() {
            frame.encode_into(buf);
            self.timers.on_send(now);
            return true;
        }
        let Some(pick) = self.sched.pick() else {
            return false;
        };
        match pick {
            Pick::Control => {
                let Some(frame) = self.sched.pop_control() else {
                    return false;
                };
                let len = frame.wire_len() as u32;
                match frame.frame_type {
                    FrameType::Open => self.on_open_sent(frame.stream_id),
                    FrameType::Ping => {
                        // RTT is measured from the instant the PING actually
                        // leaves, not from when the timer queued it.
                        if let Some(p) = self.timers.ping_outstanding.as_mut() {
                            p.1 = now;
                        }
                    }
                    _ => {}
                }
                self.sched.served(Pick::Control, Class::Control, len, None);
                frame.encode_into(buf);
            }
            Pick::Stream(id) => {
                let Some(stream) = self.streams.get_mut(&id) else {
                    return false;
                };
                let Some(payload) = stream.outbox.pop_front() else {
                    return false;
                };
                let class = stream.class;
                let payload_len = payload.len() as u32;
                stream.outbox_bytes -= payload_len;
                stream.send.consume(payload_len);
                let frame = Frame {
                    stream_id: id,
                    frame_type: FrameType::Data,
                    payload,
                };
                let next_len = stream.head_len();
                if next_len.is_none() {
                    stream.sched_active = false;
                }
                let queue_fin =
                    stream.outbox.is_empty() && stream.fin_requested && !stream.fin_queued;
                self.sched
                    .served(Pick::Stream(id), class, frame.wire_len() as u32, next_len);
                if queue_fin {
                    self.queue_fin(id);
                }
                self.maybe_forget(id);
                frame.encode_into(buf);
            }
        }
        self.timers.on_send(now);
        true
    }

    /// Our OPEN left the wire: DATA for this stream may now be scheduled.
    fn on_open_sent(&mut self, id: StreamId) {
        if let Some(s) = self.streams.get_mut(&id) {
            s.open_sent = true;
            if let Some(len) = s.head_len() {
                s.sched_active = true;
                let class = s.class;
                self.sched.activate_stream(id, class, len);
            }
        }
    }

    fn queue_fin(&mut self, id: StreamId) {
        if let Some(s) = self.streams.get_mut(&id) {
            s.fin_queued = true;
            self.sched.push_control(Frame {
                stream_id: id,
                frame_type: FrameType::Fin,
                payload: Vec::new(),
            });
        }
    }

    /// Drop a stream entry once nothing remains to send or deliver.
    fn maybe_forget(&mut self, id: StreamId) {
        if self.streams.get(&id).is_some_and(Stream::is_finished) {
            self.drop_stream(id);
        }
    }

    fn drop_stream(&mut self, id: StreamId) {
        if let Some(s) = self.streams.remove(&id) {
            self.sched.remove_stream(id, s.class);
        }
    }

    // ------------------------------------------------------------------
    // Receive
    // ------------------------------------------------------------------

    /// Feed one frame (exactly one transport message) from the peer. Any
    /// `Err` means the connection closed itself with `GOAWAY { ProtocolError }`.
    pub fn recv(&mut self, now: Instant, bytes: &[u8]) -> Result<(), ProtocolError> {
        let now = self.timers.observe(now);
        if self.closed.is_some() {
            return Err(ProtocolError::Closed);
        }
        let frame = match Frame::parse(bytes) {
            Ok(f) => f,
            Err(e) => return Err(self.fail(e)),
        };
        self.timers.on_recv(now);
        match self.dispatch(now, frame) {
            Ok(()) => Ok(()),
            Err(e) => Err(self.fail(e)),
        }
    }

    fn fail(&mut self, err: ProtocolError) -> ProtocolError {
        if self.closed.is_none() {
            self.close_internal(
                GoAway {
                    code: CloseCode::ProtocolError,
                    message: Some(err.to_string()),
                },
                true,
            );
        }
        err
    }

    fn dispatch(&mut self, now: Instant, frame: Frame) -> Result<(), ProtocolError> {
        use FrameType as T;
        if frame.stream_id == 0 {
            return match frame.frame_type {
                T::Challenge => self.on_challenge(frame),
                T::Hello => self.on_hello(now, frame),
                T::Welcome => self.on_welcome(now, frame),
                T::Reject => self.on_reject(frame),
                T::Goaway => self.on_goaway(frame),
                T::Ping => self.after_auth().and_then(|_| self.on_ping(frame)),
                T::Pong => self.after_auth().and_then(|_| self.on_pong(now, frame)),
                T::Open | T::Data | T::Fin | T::Rst | T::WindowUpdate => {
                    Err(ProtocolError::BadStreamId(0))
                }
            };
        }
        self.after_auth()?;
        match frame.frame_type {
            T::Open => self.on_stream_open(frame),
            T::Data => self.on_data(frame),
            T::Fin => self.on_fin(frame),
            T::Rst => self.on_rst(frame),
            T::WindowUpdate => self.on_window_update(frame),
            T::Challenge | T::Hello | T::Welcome | T::Reject | T::Ping | T::Pong | T::Goaway => {
                Err(ProtocolError::StateViolation(
                    "connection frame on a non-zero stream",
                ))
            }
        }
    }

    fn after_auth(&self) -> Result<(), ProtocolError> {
        if self.hs == HandshakeState::Done {
            Ok(())
        } else {
            Err(ProtocolError::StateViolation("frame before WELCOME"))
        }
    }

    // --- handshake ------------------------------------------------------

    fn on_challenge(&mut self, frame: Frame) -> Result<(), ProtocolError> {
        if self.role != Role::Client || self.hs != HandshakeState::AwaitChallenge {
            return Err(ProtocolError::StateViolation("unexpected CHALLENGE"));
        }
        let ch: Challenge = wire::decode_payload(FrameType::Challenge, &frame.payload)?;
        let mut nonce_c = [0u8; 32];
        self.cfg.rng.fill_bytes(&mut nonce_c);
        let msg = auth::transcript(
            &ch.nonce_s,
            &nonce_c,
            &self.cfg.server_name,
            self.cfg.channel_binding.as_ref(),
        );
        let signer = self
            .cfg
            .signer
            .as_mut()
            .expect("client config carries a signer");
        let key_id = signer.key_id();
        let sig = match signer.sign(&msg) {
            Ok(sig) => sig,
            Err(e) => {
                // We cannot authenticate; tell the peer we are leaving and
                // surface the reason locally as a rejection-style close.
                self.close_internal(
                    GoAway {
                        code: CloseCode::Rejected,
                        message: Some(e.to_string()),
                    },
                    true,
                );
                return Ok(());
            }
        };
        self.key_id = Some(key_id);
        self.handshake_out.push_back(Frame {
            stream_id: 0,
            frame_type: FrameType::Hello,
            payload: wire::encode_payload(&Hello {
                version: MAX_VERSION,
                key_id,
                nonce_c,
                sig,
            }),
        });
        self.hs = HandshakeState::HelloSent;
        Ok(())
    }

    fn on_hello(&mut self, now: Instant, frame: Frame) -> Result<(), ProtocolError> {
        if self.role != Role::Server || self.hs != HandshakeState::ChallengeSent {
            return Err(ProtocolError::StateViolation("unexpected HELLO"));
        }
        let hello: Hello = wire::decode_payload(FrameType::Hello, &frame.payload)?;
        let version = match handshake::negotiate(hello.version) {
            Ok(v) => v,
            Err(code) => {
                self.reject(code, "unsupported protocol version");
                return Ok(());
            }
        };
        let verifier = self
            .cfg
            .verifier
            .as_mut()
            .expect("server config carries a verifier");
        let Some(pk) = verifier.public_key(&hello.key_id) else {
            self.reject(RejectCode::UnknownKey, "unknown key");
            return Ok(());
        };
        let nonce_s = self.nonce_s.expect("server drew its nonce at construction");
        let msg = auth::transcript(
            &nonce_s,
            &hello.nonce_c,
            &self.cfg.server_name,
            self.cfg.channel_binding.as_ref(),
        );
        if !auth::verify(&hello.key_id, &pk, &msg, &hello.sig) {
            self.reject(RejectCode::BadSignature, "signature verification failed");
            return Ok(());
        }
        let params = Params {
            max_frame: self.cfg.max_frame,
            initial_window: self.cfg.initial_window,
            compression: self.cfg.compression,
        };
        self.handshake_out.push_back(Frame {
            stream_id: 0,
            frame_type: FrameType::Welcome,
            payload: wire::encode_payload(&Welcome { version, params }),
        });
        self.key_id = Some(hello.key_id);
        self.finish_handshake(now, version, params, hello.key_id);
        Ok(())
    }

    fn reject(&mut self, code: RejectCode, message: &str) {
        self.handshake_out.push_back(Frame {
            stream_id: 0,
            frame_type: FrameType::Reject,
            payload: wire::encode_payload(&Reject {
                code,
                message: message.to_owned(),
            }),
        });
        self.close_internal(
            GoAway {
                code: CloseCode::Rejected,
                message: Some(message.to_owned()),
            },
            false,
        );
    }

    fn on_welcome(&mut self, now: Instant, frame: Frame) -> Result<(), ProtocolError> {
        if self.role != Role::Client || self.hs != HandshakeState::HelloSent {
            return Err(ProtocolError::StateViolation("unexpected WELCOME"));
        }
        let w: Welcome = wire::decode_payload(FrameType::Welcome, &frame.payload)?;
        if !handshake::accept_version(MAX_VERSION, w.version) {
            return Err(ProtocolError::BadParams("version"));
        }
        if !(MIN_WINDOW..=MAX_WINDOW).contains(&w.params.initial_window) {
            return Err(ProtocolError::BadParams("initial_window"));
        }
        if w.params.max_frame == 0 {
            return Err(ProtocolError::BadParams("max_frame"));
        }
        // The scheduler's lmax is the negotiated frame size, which the
        // client only learns now. No streams exist yet, so rebuilding is
        // free.
        self.sched = SchedTree::new(self.cfg.weights, w.params.max_frame);
        let key_id = self.key_id.expect("client stored its key id at HELLO");
        self.finish_handshake(now, w.version, w.params, key_id);
        Ok(())
    }

    fn finish_handshake(&mut self, now: Instant, version: u16, params: Params, key_id: KeyId) {
        self.hs = HandshakeState::Done;
        self.version = Some(version);
        self.params = Some(params);
        self.compression_enabled = self.cfg.compression == Compression::BodyOnly
            && params.compression == Compression::BodyOnly;
        self.timers.on_authenticated(now);
        self.events
            .push_back(Event::Authenticated { key_id, version });
    }

    fn on_reject(&mut self, frame: Frame) -> Result<(), ProtocolError> {
        if self.role != Role::Client || self.hs != HandshakeState::HelloSent {
            return Err(ProtocolError::StateViolation("unexpected REJECT"));
        }
        let r: Reject = wire::decode_payload(FrameType::Reject, &frame.payload)?;
        self.events.push_back(Event::Rejected {
            code: r.code,
            message: r.message.clone(),
        });
        // The server closes after REJECT; nothing we send would be read.
        self.close_internal(
            GoAway {
                code: CloseCode::Rejected,
                message: Some(r.message),
            },
            false,
        );
        Ok(())
    }

    // --- connection-level ---------------------------------------------

    fn on_ping(&mut self, frame: Frame) -> Result<(), ProtocolError> {
        let p: Ping = wire::decode_payload(FrameType::Ping, &frame.payload)?;
        self.sched.push_control(Frame {
            stream_id: 0,
            frame_type: FrameType::Pong,
            payload: wire::encode_payload(&p),
        });
        Ok(())
    }

    fn on_pong(&mut self, now: Instant, frame: Frame) -> Result<(), ProtocolError> {
        let p: Ping = wire::decode_payload(FrameType::Pong, &frame.payload)?;
        if let Some((opaque, sent_at)) = self.timers.ping_outstanding
            && opaque == p.opaque
        {
            self.rtt = Some(now.saturating_duration_since(sent_at));
            self.timers.ping_outstanding = None;
        }
        Ok(())
    }

    fn on_goaway(&mut self, frame: Frame) -> Result<(), ProtocolError> {
        let g: GoAway = wire::decode_payload(FrameType::Goaway, &frame.payload)?;
        self.close_internal(g, false);
        Ok(())
    }

    // --- streams --------------------------------------------------------

    fn peer_opens_odd(&self) -> bool {
        self.role == Role::Server
    }

    /// Frames for a stream we no longer track are tolerated when the id is
    /// one that legitimately existed (they raced our RST/FIN); frames for
    /// ids that were never opened are violations.
    fn stream_mut(&mut self, id: StreamId) -> Result<Option<&mut Stream>, ProtocolError> {
        if self.streams.contains_key(&id) {
            return Ok(self.streams.get_mut(&id));
        }
        let is_peer_parity = (id % 2 == 1) == self.peer_opens_odd();
        let known = if is_peer_parity {
            id <= self.last_peer_stream_id
        } else {
            id < self.next_stream_id
        };
        if known {
            Ok(None)
        } else {
            Err(ProtocolError::BadStreamId(id))
        }
    }

    fn on_stream_open(&mut self, frame: Frame) -> Result<(), ProtocolError> {
        let id = frame.stream_id;
        if (id % 2 == 1) != self.peer_opens_odd() || id <= self.last_peer_stream_id {
            return Err(ProtocolError::BadStreamId(id));
        }
        let head: Head = wire::decode_payload(FrameType::Open, &frame.payload)?;
        let window = self.params.expect("authenticated").initial_window;
        let class = classify::at_birth(&head.hints, self.cfg.bulk_threshold);
        // The peer's OPEN is already on the wire, so our DATA may follow at
        // any time: `open_sent` is trivially true.
        let stream = Stream::new(head.hints.clone(), class, window, true);
        self.streams.insert(id, stream);
        self.sched.add_stream(id, class);
        self.last_peer_stream_id = id;
        self.events.push_back(Event::StreamOpened { id, head });
        Ok(())
    }

    fn on_data(&mut self, frame: Frame) -> Result<(), ProtocolError> {
        let id = frame.stream_id;
        let Some(&flags) = frame.payload.first() else {
            return Err(ProtocolError::Decode(FrameType::Data));
        };
        let cap = self.params.expect("authenticated").max_frame as usize * DECOMPRESS_CAP_FACTOR;
        let wire_len = frame.payload.len() as u32;
        let compressed = flags & DATA_FLAG_COMPRESSED != 0;
        let body = &frame.payload[1..];
        let data = if compressed {
            self.zstd
                .decompress(body, cap)
                .map_err(|_| ProtocolError::Decompress(id))?
        } else {
            body.to_vec()
        };
        let Some(stream) = self.stream_mut(id)? else {
            return Ok(());
        };
        if !stream.remote_open {
            return Err(ProtocolError::StateViolation("DATA after FIN"));
        }
        if !stream.recv.on_data(wire_len) {
            return Err(ProtocolError::FlowControl(id));
        }
        if data.is_empty() {
            // Nothing for the application, but the credit was spent.
            if let Some(credit) = stream.recv.on_consumed(wire_len) {
                self.queue_window_update(id, credit);
            }
            return Ok(());
        }
        let was_empty = stream.inbox.is_empty();
        stream.inbox.push_back(Chunk {
            data,
            offset: 0,
            wire_len,
        });
        if was_empty {
            self.events.push_back(Event::Readable(id));
        }
        Ok(())
    }

    fn queue_window_update(&mut self, id: StreamId, credit: u32) {
        self.sched.push_control(Frame {
            stream_id: id,
            frame_type: FrameType::WindowUpdate,
            payload: wire::encode_payload(&WindowUpdate { credit }),
        });
    }

    fn on_fin(&mut self, frame: Frame) -> Result<(), ProtocolError> {
        let id = frame.stream_id;
        let Some(stream) = self.stream_mut(id)? else {
            return Ok(());
        };
        if !stream.remote_open {
            return Err(ProtocolError::StateViolation("duplicate FIN"));
        }
        stream.remote_open = false;
        self.events.push_back(Event::Finished(id));
        Ok(())
    }

    fn on_rst(&mut self, frame: Frame) -> Result<(), ProtocolError> {
        let id = frame.stream_id;
        let rst: Rst = wire::decode_payload(FrameType::Rst, &frame.payload)?;
        if self.stream_mut(id)?.is_none() {
            return Ok(());
        }
        self.drop_stream(id);
        self.events.push_back(Event::Reset { id, code: rst.code });
        Ok(())
    }

    fn on_window_update(&mut self, frame: Frame) -> Result<(), ProtocolError> {
        let id = frame.stream_id;
        let wu: WindowUpdate = wire::decode_payload(FrameType::WindowUpdate, &frame.payload)?;
        let Some(stream) = self.stream_mut(id)? else {
            return Ok(());
        };
        stream.send.grant(wu.credit);
        if stream.wants_writable && stream.free_credit() > 0 {
            stream.wants_writable = false;
            self.events.push_back(Event::Writable(id));
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Stream API
    // ------------------------------------------------------------------

    fn ready(&self) -> Result<(), StreamError> {
        if self.closed.is_some() {
            return Err(StreamError::Closed);
        }
        if self.hs != HandshakeState::Done {
            return Err(StreamError::NotAuthenticated);
        }
        Ok(())
    }

    /// Open a stream toward the peer. Allowed only between WELCOME and close.
    pub fn open(&mut self, head: Head) -> Result<StreamId, StreamError> {
        self.ready()?;
        let id = self.next_stream_id;
        self.next_stream_id = id.checked_add(2).ok_or(StreamError::Exhausted)?;
        let window = self.params.expect("authenticated").initial_window;
        let class = classify::at_birth(&head.hints, self.cfg.bulk_threshold);
        let stream = Stream::new(head.hints.clone(), class, window, false);
        self.streams.insert(id, stream);
        self.sched.add_stream(id, class);
        self.sched.push_control(Frame {
            stream_id: id,
            frame_type: FrameType::Open,
            payload: wire::encode_payload(&head),
        });
        Ok(id)
    }

    /// Queue application bytes. Returns how many were accepted — bounded by
    /// the peer's credit, never blocking. `Ok(0)` means wait for
    /// [`Event::Writable`].
    pub fn write(&mut self, id: StreamId, data: &[u8]) -> Result<usize, StreamError> {
        self.ready()?;
        let max_frame = self.params.expect("authenticated").max_frame as usize;
        let compression_enabled = self.compression_enabled;
        let bulk_threshold = self.cfg.bulk_threshold;
        let stream = self
            .streams
            .get_mut(&id)
            .ok_or(StreamError::UnknownStream)?;
        if !stream.local_open {
            return Err(StreamError::SendClosed);
        }
        if data.is_empty() {
            return Ok(0);
        }
        if stream.compress == Compress::Undecided {
            stream.compress = if compression_enabled
                && compress::should_compress(stream.class, &stream.hints, data)
            {
                Compress::On
            } else {
                Compress::Off
            };
        }
        let compressing = stream.compress == Compress::On;
        let chunk_max = max_frame.saturating_sub(1).max(1);
        let mut offset = 0;
        while offset < data.len() {
            let avail = stream.free_credit() as usize;
            if avail <= 1 {
                break;
            }
            let chunk_len = (data.len() - offset).min(chunk_max).min(avail - 1);
            let chunk = &data[offset..offset + chunk_len];
            let mut payload = Vec::with_capacity(1 + chunk_len);
            payload.push(0);
            let mut done = false;
            if compressing && let Ok(c) = self.zstd.compress(chunk) {
                // Incompressible chunks go out raw so the payload never
                // exceeds the credit we reserved for it.
                if c.len() < chunk_len {
                    payload[0] = DATA_FLAG_COMPRESSED;
                    payload.extend_from_slice(&c);
                    done = true;
                }
            }
            if !done {
                payload.extend_from_slice(chunk);
            }
            stream.outbox_bytes += payload.len() as u32;
            stream.outbox.push_back(payload);
            offset += chunk_len;
        }
        if offset < data.len() {
            stream.wants_writable = true;
        }
        stream.written_total += offset as u64;
        // Demotion to bulk after enough bytes, unless the app pinned the class.
        let old_class = stream.class;
        let new_class = if stream.class_pinned {
            old_class
        } else {
            classify::after_write(old_class, stream.written_total, bulk_threshold)
        };
        let head_len = stream.head_len();
        let open_sent = stream.open_sent;
        let was_active = stream.sched_active;
        if new_class != old_class {
            stream.class = new_class;
            stream.sched_active = open_sent && head_len.is_some();
            self.sched.reclass(
                id,
                old_class,
                new_class,
                if open_sent { head_len } else { None },
            );
        } else if open_sent
            && !was_active
            && let Some(len) = head_len
        {
            stream.sched_active = true;
            self.sched.activate_stream(id, new_class, len);
        }
        Ok(offset)
    }

    /// Half-close our direction. Queued DATA still goes out first.
    pub fn finish(&mut self, id: StreamId) -> Result<(), StreamError> {
        self.ready()?;
        let stream = self
            .streams
            .get_mut(&id)
            .ok_or(StreamError::UnknownStream)?;
        if !stream.local_open {
            return Err(StreamError::SendClosed);
        }
        stream.local_open = false;
        stream.fin_requested = true;
        if stream.outbox.is_empty() {
            self.queue_fin(id);
            self.maybe_forget(id);
        }
        Ok(())
    }

    /// Abort both directions immediately. Unsent DATA is discarded.
    pub fn reset(&mut self, id: StreamId, code: u32) -> Result<(), StreamError> {
        self.ready()?;
        if !self.streams.contains_key(&id) {
            return Err(StreamError::UnknownStream);
        }
        self.drop_stream(id);
        self.sched.push_control(Frame {
            stream_id: id,
            frame_type: FrameType::Rst,
            payload: wire::encode_payload(&Rst { code }),
        });
        Ok(())
    }

    /// Copy received bytes into `buf`. `Ok(0)` only after the peer's FIN
    /// once everything has been read; otherwise `WouldBlock` until
    /// [`Event::Readable`].
    pub fn read(&mut self, id: StreamId, buf: &mut [u8]) -> Result<usize, StreamError> {
        let stream = self
            .streams
            .get_mut(&id)
            .ok_or(StreamError::UnknownStream)?;
        let mut copied = 0;
        let mut updates = Vec::new();
        while copied < buf.len() {
            let Some(chunk) = stream.inbox.front_mut() else {
                break;
            };
            let n = (chunk.data.len() - chunk.offset).min(buf.len() - copied);
            buf[copied..copied + n].copy_from_slice(&chunk.data[chunk.offset..chunk.offset + n]);
            chunk.offset += n;
            copied += n;
            if chunk.offset == chunk.data.len() {
                let wire_len = chunk.wire_len;
                stream.inbox.pop_front();
                if stream.remote_open
                    && let Some(credit) = stream.recv.on_consumed(wire_len)
                {
                    updates.push(credit);
                }
            }
        }
        if copied == 0 && !buf.is_empty() {
            if stream.remote_open {
                return Err(StreamError::WouldBlock);
            }
            stream.eof_delivered = true;
            self.maybe_forget(id);
            return Ok(0);
        }
        for credit in updates {
            self.queue_window_update(id, credit);
        }
        Ok(copied)
    }

    /// Pin a stream to a class. Automatic classification stops for it.
    pub fn set_class(&mut self, id: StreamId, class: Class) -> Result<(), StreamError> {
        if class == Class::Control {
            return Err(StreamError::InvalidClass);
        }
        let stream = self
            .streams
            .get_mut(&id)
            .ok_or(StreamError::UnknownStream)?;
        stream.class_pinned = true;
        let old = stream.class;
        if old != class {
            stream.class = class;
            let head_len = if stream.open_sent {
                stream.head_len()
            } else {
                None
            };
            stream.sched_active = head_len.is_some();
            self.sched.reclass(id, old, class, head_len);
        }
        Ok(())
    }

    /// Bytes waiting to be read on a stream (0 for unknown streams).
    pub fn readable(&self, id: StreamId) -> usize {
        self.streams.get(&id).map_or(0, Stream::readable_bytes)
    }

    // ------------------------------------------------------------------
    // Close
    // ------------------------------------------------------------------

    /// Tear the connection down. GOAWAY is the very next frame out, every
    /// open stream is reset, and `Event::Closed` is emitted locally.
    pub fn close(&mut self, goaway: GoAway) {
        self.close_internal(goaway, true);
    }

    /// `send_goaway` is false when the peer initiated the close (or already
    /// left after REJECT): nothing we send would be read.
    fn close_internal(&mut self, reason: GoAway, send_goaway: bool) {
        if self.closed.is_some() {
            return;
        }
        // Pending control frames (OPEN, WINDOW_UPDATE, ...) are moot now.
        self.sched.clear_control();
        if send_goaway {
            self.pending_goaway = Some(Frame {
                stream_id: 0,
                frame_type: FrameType::Goaway,
                payload: wire::encode_payload(&reason),
            });
        }
        let mut ids: Vec<StreamId> = self.streams.keys().copied().collect();
        ids.sort_unstable();
        for id in ids {
            self.drop_stream(id);
            if send_goaway {
                self.sched.push_control(Frame {
                    stream_id: id,
                    frame_type: FrameType::Rst,
                    payload: wire::encode_payload(&Rst {
                        code: RST_CODE_CONNECTION_CLOSED,
                    }),
                });
            }
            self.events.push_back(Event::Reset {
                id,
                code: RST_CODE_CONNECTION_CLOSED,
            });
        }
        self.timers.clear();
        self.closed = Some(reason.clone());
        self.events.push_back(Event::Closed { reason });
    }
}
