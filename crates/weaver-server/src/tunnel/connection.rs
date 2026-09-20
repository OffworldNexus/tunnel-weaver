//! One client connection: a [`weaver_tokio::Driver`] over the upgraded
//! WebSocket plus the relay's [`StreamHandler`].
//!
//! Stream conventions (see `weaver_proto`): the client opens a control
//! stream whose first message is `Head::Control`; the relay opens one
//! stream per visitor request whose first message is `Head::Http`, followed
//! by raw body chunks, and reads back an `HttpResponseHead` followed by raw
//! body chunks.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Frame;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, info, trace};
use weaver_mux::{
    CloseCode, CloseReason, Compress, Config, Connection, Event, KeyId, StreamError, StreamId,
};
use weaver_proto::control::{ControlHead, ControlReply, RefusalCode};
use weaver_proto::http::{HttpHead, HttpResponseHead};
use weaver_proto::{BodyFrame, Head, ResetCode, policy};
use weaver_tokio::{Driver, Handle, StreamHandler, SystemRng, WsTransport};

use crate::tunnel::identity::ResolverVerifier;
use crate::tunnel::proxy::{BodyFrameItem, BoxBody, ProxyError, ProxyRequest, TunnelResponseBody};
use crate::tunnel::registry::TunnelRegistry;

type RelayHandle = Handle<RelayHandler>;

/// Spawns a background task driving the multiplexer over the upgraded
/// WebSocket stream.
pub fn spawn_tunnel_connection(
    ws_stream: WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>,
    registry: Arc<TunnelRegistry>,
    root_domain: String,
) {
    tokio::spawn(run_tunnel_connection(ws_stream, registry, root_domain));
}

/// How often the mux asks the `IdentityResolver` whether the connected
/// key is still acceptable; a `false` answer closes with `KeyRevoked`.
const REVERIFY_INTERVAL: Duration = Duration::from_secs(60);

async fn run_tunnel_connection(
    ws_stream: WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>,
    registry: Arc<TunnelRegistry>,
    root_domain: String,
) {
    let verifier = Box::new(ResolverVerifier(registry.identities()));
    let mut cfg = Config::server(verifier, root_domain, Box::new(SystemRng));
    if let weaver_mux::Role::Server {
        reverify_interval, ..
    } = &mut cfg.role
    {
        *reverify_interval = Some(REVERIFY_INTERVAL);
    }
    let conn = Connection::new(cfg, Instant::now());

    let (proxy_tx, proxy_rx) = mpsc::channel::<ProxyRequest>(64);
    let handler = RelayHandler {
        registry: Arc::clone(&registry),
        handle: None,
        proxy_tx,
        conn_id: None,
        key: None,
        leases: HashMap::new(),
        inflight: HashMap::new(),
    };
    let driver = Driver::new(conn, WsTransport::new(ws_stream), handler);
    let handle = driver.handle();
    handle.spawn_on({
        let h = handle.clone();
        move |_, handler| handler.handle = Some(h)
    });
    // Visitor requests arrive from hyper tasks; feed them to the driver.
    tokio::spawn(forward_proxy_requests(proxy_rx, handle));

    let (_handler, result) = driver.run().await;
    match result {
        Ok(reason) => info!(?reason, "Tunnel connection closed"),
        Err(err) => debug!(error = %err, "Tunnel connection ended"),
    }
}

/// Turns each `ProxyRequest` into a stream open inside the driver's loop.
async fn forward_proxy_requests(mut rx: mpsc::Receiver<ProxyRequest>, handle: RelayHandle) {
    while let Some(req) = rx.recv().await {
        handle.spawn_on(move |conn, h| h.open_visitor_stream(conn, req));
    }
}

/// How many response frames may queue toward the visitor before the relay
/// stops reading the mux (leaving the sender's window to apply pressure).
const DOWN_HIGH_WATER: usize = 64;
/// Resume reading the mux once the queue drains below this.
const DOWN_LOW_WATER: usize = 16;

/// How many request-body frames may wait for mux credit before the hyper
/// body reader is paused. Bounds relay memory on a large upload against a
/// slow origin: the visitor's own h1/h2 flow control then applies.
const UP_HIGH_WATER: usize = 8;

/// A visitor exchange in progress on one stream.
struct Exchange {
    req: HttpHead,
    response_tx: Option<oneshot::Sender<Result<Response<BoxBody>, ProxyError>>>,
    body_tx: Option<mpsc::Sender<BodyFrameItem>>,
    /// Request body frames accepted from hyper but not yet sent (credit).
    pending_body: VecDeque<BodyFrame>,
    /// Wakes the paused request-body reader once `pending_body` has room.
    body_resume: Option<oneshot::Sender<()>>,
    /// The request body reader has ended; FIN once `pending_body` drains.
    body_done: bool,
    body_compress: Compress,
    /// Visitor asked for an upgrade; the raw I/O to pipe after a `101`.
    on_upgrade: Option<hyper::upgrade::OnUpgrade>,
    /// The upgrade came as an h2 extended CONNECT (answer `200`, not `101`).
    visitor_connect: bool,
    /// The exchange became a raw byte pipe: response frames go to the
    /// visitor socket writer instead of a hyper body.
    piped: bool,
    /// Response frames from the client queued for the visitor.
    pending_down: VecDeque<BodyFrameItem>,
    /// A `body_tx.send` is in flight; only one frame is handed to the
    /// visitor at a time.
    forwarding: bool,
    /// Applied request-body backpressure: stop reading the mux until the
    /// queue drains.
    down_paused: bool,
    /// The client FIN'd its direction (the response is complete); the
    /// exchange is torn down once the queue drains and the in-flight send
    /// finishes.
    client_done: bool,
}

/// A control stream is the lease on a registration: the service stays
/// registered exactly as long as the stream is open. Finishing or
/// resetting it unregisters the service; closing the connection
/// unregisters all of them.
enum Lease {
    /// `register_service` is running off-loop; no hostname yet.
    Pending,
    /// Registered under this hostname.
    Registered(String),
    /// The client closed the stream while registration was still pending;
    /// unregister as soon as the hostname is known.
    Released,
}

pub(crate) struct RelayHandler {
    registry: Arc<TunnelRegistry>,
    handle: Option<RelayHandle>,
    proxy_tx: mpsc::Sender<ProxyRequest>,
    conn_id: Option<u64>,
    key: Option<KeyId>,
    leases: HashMap<StreamId, Lease>,
    inflight: HashMap<StreamId, Exchange>,
}

impl StreamHandler for RelayHandler {
    fn on_event(&mut self, conn: &mut Connection, event: Event) {
        match event {
            Event::Authenticated { key_id, version } => {
                info!(?key_id, version, "Tunnel connection authenticated");
                self.key = Some(key_id);
                let (s_tx, s_rx) = oneshot::channel();
                self.conn_id = Some(self.registry.register_connection(key_id, s_tx));
                let h = self.handle();
                tokio::spawn(async move {
                    if s_rx.await.is_ok() {
                        info!("Tunnel connection superseded, closing");
                        h.close(CloseReason::new(CloseCode::Superseded));
                    }
                });
            }
            Event::StreamOpened { id, .. } => {
                trace!(%id, "Peer opened stream; awaiting head");
            }
            Event::Readable(id) => {
                if self.inflight.contains_key(&id) {
                    self.drain_inbox(conn, id);
                    return;
                }
                while let Ok(msg) = conn.recv_msg(id) {
                    if self.leases.contains_key(&id) {
                        debug!(%id, "Unexpected message on control stream");
                    } else {
                        self.on_first_message(conn, id, &msg);
                    }
                }
            }
            Event::Writable { id, .. } => {
                if let Some(ex) = self.inflight.get_mut(&id) {
                    Self::drain_request_body(ex, conn, id);
                }
            }
            Event::Finished(id) => {
                self.release_lease(conn, id);
                if let Some(ex) = self.inflight.get_mut(&id) {
                    // The response is complete, but frames may still be
                    // queued or in flight. Do not drop `body_tx` yet, or a
                    // hyper body with a `Content-Length` is truncated and the
                    // visitor sees a protocol error; `pump_down` tears the
                    // exchange down once the queue drains.
                    ex.client_done = true;
                }
                let drained = self
                    .inflight
                    .get(&id)
                    .is_some_and(|ex| !ex.forwarding && ex.pending_down.is_empty());
                if drained {
                    self.inflight.remove(&id);
                }
            }
            Event::Reset { id, code } => {
                trace!(%id, code, "Stream reset");
                self.release_lease(conn, id);
                if let Some(mut ex) = self.inflight.remove(&id)
                    && let Some(tx) = ex.response_tx.take()
                {
                    let err = match ResetCode::from_u32(code) {
                        Some(ResetCode::OriginUnreachable) => ProxyError::OriginUnreachable,
                        _ => ProxyError::Reset,
                    };
                    let _ = tx.send(Err(err));
                }
            }
            Event::Closed { reason } => {
                debug!(?reason, "Mux closed");
                if let (Some(k), Some(c)) = (self.key, self.conn_id) {
                    self.registry.unregister_connection(k, c);
                }
            }
            Event::Rejected { .. } => {}
        }
    }
}

impl RelayHandler {
    fn handle(&self) -> RelayHandle {
        self.handle
            .clone()
            .expect("handle installed before the first event can fire")
    }

    /// The client gave up a control stream: drop the registration it
    /// carried. A lease still `Pending` is left in the map so the reply
    /// path sees the stream is gone and unregisters right after
    /// `register_service` completes.
    fn release_lease(&mut self, conn: &mut Connection, id: StreamId) {
        match self.leases.get(&id) {
            Some(Lease::Registered(hostname)) => {
                info!(%id, %hostname, "Control stream closed by client; unregistering");
                if let Some(key) = self.key {
                    self.registry.unregister_service(key, hostname);
                }
                self.leases.remove(&id);
                // Our half was still open: finish it so the stream is freed.
                let _ = conn.finish(id);
            }
            Some(Lease::Pending) => {
                self.leases.insert(id, Lease::Released);
            }
            Some(Lease::Released) | None => {}
        }
    }

    /// First message on a client-opened stream must be a `Head::Control`.
    fn on_first_message(&mut self, conn: &mut Connection, id: StreamId, msg: &[u8]) {
        let Ok(Head::Control(head)) = weaver_proto::decode::<Head>(msg) else {
            debug!(%id, "Unexpected first message from client; resetting");
            let _ = conn.reset(id, ResetCode::Cancelled.as_u32());
            return;
        };
        let ControlHead::Register { service, .. } = &head;
        let service = service.clone();
        let (Some(key), Some(conn_id)) = (self.key, self.conn_id) else {
            let _ = conn.reset(id, ResetCode::Cancelled.as_u32());
            return;
        };
        if let Err(code) = head.validate() {
            Self::reply(conn, id, refused(code, &service));
            return;
        }
        // Registration touches the cert manager (async): run it off the
        // loop and come back through the handle.
        self.leases.insert(id, Lease::Pending);
        let registry = Arc::clone(&self.registry);
        let proxy_tx = self.proxy_tx.clone();
        let handle = self.handle();
        tokio::spawn(async move {
            let res = registry
                .register_service(key, conn_id, &service, proxy_tx)
                .await;
            handle.spawn_on(move |conn, handler| {
                let reply = match res {
                    Ok(hostname) => {
                        match handler.leases.get(&id) {
                            Some(Lease::Released) => {
                                // The client finished the stream while we
                                // were registering: the lease is already gone.
                                handler.leases.remove(&id);
                                handler.registry.unregister_service(key, &hostname);
                                return;
                            }
                            _ => {
                                handler
                                    .leases
                                    .insert(id, Lease::Registered(hostname.clone()));
                                handler.watch_cert(id, hostname.clone());
                            }
                        }
                        ControlReply::Registered { hostname }
                    }
                    Err(code) => {
                        handler.leases.remove(&id);
                        refused(code, &service)
                    }
                };
                Self::reply(conn, id, reply);
            });
        });
    }

    /// Push the hostname's current certificate state on the control stream,
    /// then every transition until the lease is released. The task exits on
    /// its own when the stream is gone (`send` fails) or the broadcast ends.
    fn watch_cert(&self, id: StreamId, hostname: String) {
        let cert_manager = self.registry.cert_manager();
        let handle = self.handle();
        tokio::spawn(async move {
            let mut rx = cert_manager.subscribe_state_changes();
            let mut last = cert_manager.status(&hostname);
            Self::push_cert_state(&handle, id, &last);
            loop {
                match rx.recv().await {
                    Ok((name, state)) if name == hostname => {
                        if state != last {
                            last = state;
                            Self::push_cert_state(&handle, id, &last);
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Missed transitions: resync from the current state.
                        let now = cert_manager.status(&hostname);
                        if now != last {
                            last = now;
                            Self::push_cert_state(&handle, id, &last);
                        }
                    }
                    Err(_) => return,
                }
            }
        });
    }

    fn push_cert_state(handle: &RelayHandle, id: StreamId, state: &crate::cert::state::CertState) {
        let status = match state {
            crate::cert::state::CertState::Pending => weaver_proto::CertStatus::Pending,
            crate::cert::state::CertState::Ordering => weaver_proto::CertStatus::Ordering,
            crate::cert::state::CertState::Issued { .. } => weaver_proto::CertStatus::Issued,
            crate::cert::state::CertState::Renewing { .. } => weaver_proto::CertStatus::Renewing,
            crate::cert::state::CertState::Failed { .. } => weaver_proto::CertStatus::Failed,
        };
        handle.spawn_on(move |conn, handler| {
            // Only while the lease is still held by this stream.
            if matches!(handler.leases.get(&id), Some(Lease::Registered(_)))
                && let Ok(bytes) = weaver_proto::encode(&ControlReply::CertState { state: status })
            {
                let _ = conn.send(id, &bytes, policy::CONTROL_COMPRESS);
            }
        });
    }

    fn reply(conn: &mut Connection, id: StreamId, reply: ControlReply) {
        let refused = matches!(reply, ControlReply::Refused { .. });
        if let Ok(bytes) = weaver_proto::encode(&reply) {
            let _ = conn.send(id, &bytes, policy::CONTROL_COMPRESS);
        }
        if refused {
            let _ = conn.finish(id);
        }
    }

    /// Open a stream for a visitor request: policy from the request, head
    /// as the first message, body chunks streamed in from hyper.
    fn open_visitor_stream(&mut self, conn: &mut Connection, req: ProxyRequest) {
        let head_bytes = match weaver_proto::encode(&Head::Http(req.head.clone())) {
            Ok(b) => b,
            Err(e) => {
                let _ = req.response_tx.send(Err(ProxyError::Codec(e.to_string())));
                return;
            }
        };
        let id = match conn.open(policy::request_class(&req.head)) {
            Ok(id) => id,
            Err(e) => {
                let _ = req.response_tx.send(Err(ProxyError::Mux(e.to_string())));
                return;
            }
        };
        // A fresh stream has a full window (≥ 64 KiB) and the head is
        // bounded by max_message: failure here is an error, not backpressure.
        if let Err(e) = conn.send(id, &head_bytes, policy::HEAD_COMPRESS) {
            let _ = conn.reset(id, ResetCode::Cancelled.as_u32());
            let _ = req.response_tx.send(Err(ProxyError::Mux(e.to_string())));
            return;
        }
        self.inflight.insert(
            id,
            Exchange {
                body_compress: policy::request_body_compress(&req.head),
                req: req.head,
                response_tx: Some(req.response_tx),
                body_tx: None,
                pending_body: VecDeque::new(),
                body_resume: None,
                body_done: false,
                on_upgrade: req.on_upgrade,
                visitor_connect: req.visitor_connect,
                piped: false,
                pending_down: VecDeque::new(),
                forwarding: false,
                down_paused: false,
                client_done: false,
            },
        );
        // Stream the visitor's request body into the loop chunk by chunk.
        // Each frame is handed to the loop with a "room?" oneshot: when the
        // credit-blocked queue is full the reader parks on it until
        // `drain_request_body` frees a slot, so relay memory stays bounded
        // and the visitor's own flow control takes over.
        let h = self.handle();
        let mut body = req.body;
        tokio::spawn(async move {
            while let Some(frame) = body.frame().await {
                match frame {
                    Ok(f) => {
                        let body_frame = if f.is_data() {
                            let data = f.into_data().unwrap_or_default();
                            if data.is_empty() {
                                continue;
                            }
                            BodyFrame::Chunk(data.to_vec())
                        } else if let Ok(trailers) = f.into_trailers() {
                            BodyFrame::Trailers(
                                trailers
                                    .iter()
                                    .map(|(n, v)| (n.as_str().to_string(), v.as_bytes().to_vec()))
                                    .collect(),
                            )
                        } else {
                            continue;
                        };
                        let (room_tx, room_rx) = oneshot::channel::<()>();
                        h.spawn_on(move |conn, handler| {
                            let Some(ex) = handler.inflight.get_mut(&id) else {
                                return;
                            };
                            ex.pending_body.push_back(body_frame);
                            Self::drain_request_body(ex, conn, id);
                            if ex.pending_body.len() < UP_HIGH_WATER {
                                let _ = room_tx.send(());
                            } else {
                                ex.body_resume = Some(room_tx);
                            }
                        });
                        // Err means the exchange is gone: stop reading.
                        if room_rx.await.is_err() {
                            return;
                        }
                    }
                    Err(_) => {
                        h.spawn_on(move |conn, handler| {
                            handler.inflight.remove(&id);
                            let _ = conn.reset(id, ResetCode::Cancelled.as_u32());
                        });
                        return;
                    }
                }
            }
            h.spawn_on(move |conn, handler| {
                if let Some(ex) = handler.inflight.get_mut(&id) {
                    ex.body_done = true;
                    Self::drain_request_body(ex, conn, id);
                }
            });
        });
    }

    fn on_visitor_message(
        handle: &RelayHandle,
        ex: &mut Exchange,
        conn: &mut Connection,
        id: StreamId,
        msg: &[u8],
    ) {
        if ex.response_tx.is_some() {
            // Head messages arrive until the first non-1xx one is final.
            let head: HttpResponseHead = match weaver_proto::decode(msg) {
                Ok(h) => h,
                Err(e) => {
                    debug!(%id, error = %e, "Bad response head from client");
                    if let Some(tx) = ex.response_tx.take() {
                        let _ = tx.send(Err(ProxyError::Codec(e.to_string())));
                    }
                    let _ = conn.reset(id, ResetCode::Cancelled.as_u32());
                    return;
                }
            };
            // `101` is final when the visitor asked for an upgrade; every
            // other 1xx is interim.
            if (100..200).contains(&head.status) && !(head.status == 101 && ex.on_upgrade.is_some())
            {
                // Interim (1xx) response. The relay's high-level server does
                // not expose informational responses, so it is dropped here;
                // the final head still follows.
                trace!(%id, status = head.status, "Interim response from client");
                return;
            }
            let tx = ex
                .response_tx
                .take()
                .expect("checked response_tx.is_some() above");
            if let Some(class) = policy::response_class(&ex.req, &head) {
                let _ = conn.set_class(id, class);
            }
            // An origin `101` to a visitor upgrade: the exchange becomes a
            // raw byte pipe. h1 visitors get the 101 verbatim; an h2
            // extended CONNECT is answered `200` without `Connection`/
            // `Upgrade`, per RFC 8441.
            if head.status == 101 && ex.on_upgrade.is_some() {
                let status = if ex.visitor_connect {
                    StatusCode::OK
                } else {
                    StatusCode::SWITCHING_PROTOCOLS
                };
                let mut builder = Response::builder().status(status);
                for (name, val) in &head.headers {
                    if ex.visitor_connect
                        && (name.eq_ignore_ascii_case("connection")
                            || name.eq_ignore_ascii_case("upgrade")
                            || name.eq_ignore_ascii_case("sec-websocket-accept"))
                    {
                        continue;
                    }
                    if let (Ok(n), Ok(v)) = (
                        HeaderName::from_bytes(name.as_bytes()),
                        HeaderValue::from_bytes(val),
                    ) {
                        builder = builder.header(n, v);
                    }
                }
                let response = builder
                    .body(crate::tunnel::proxy::empty_body())
                    .expect("status and headers were validated");
                let _ = tx.send(Ok(response));
                let _ = conn.set_class(id, weaver_mux::Class::Realtime);
                // Downstream frames now go to the socket writer; `body_tx`
                // is the same channel type, so `pump_down` is unchanged.
                let (pipe_tx, pipe_rx) = mpsc::channel(1);
                ex.body_tx = Some(pipe_tx);
                ex.piped = true;
                let on_upgrade = ex.on_upgrade.take().expect("checked above");
                Self::spawn_upgrade_pipe(handle.clone(), id, on_upgrade, pipe_rx);
                return;
            }
            let mut builder = Response::builder().status(
                StatusCode::from_u16(head.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            );
            for (name, val) in &head.headers {
                if let (Ok(n), Ok(v)) = (
                    HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_bytes(val),
                ) {
                    builder = builder.header(n, v);
                }
            }
            let (body_tx, body_rx) = mpsc::channel(1);
            let response = builder
                .body(TunnelResponseBody::boxed(body_rx))
                .expect("status and headers were validated");
            let _ = tx.send(Ok(response));
            ex.body_tx = Some(body_tx);
        } else if ex.body_tx.is_some() {
            let item: BodyFrameItem = match weaver_proto::decode::<BodyFrame>(msg) {
                Ok(BodyFrame::Chunk(data)) => Ok(Frame::data(Bytes::from(data))),
                Ok(BodyFrame::Trailers(fields)) => {
                    let mut map = http::HeaderMap::new();
                    for (name, value) in fields {
                        if let (Ok(n), Ok(v)) = (
                            HeaderName::from_bytes(name.as_bytes()),
                            HeaderValue::from_bytes(&value),
                        ) {
                            map.append(n, v);
                        }
                    }
                    Ok(Frame::trailers(map))
                }
                Err(e) => Err(e.to_string().into()),
            };
            ex.pending_down.push_back(item);
            if ex.pending_down.len() >= DOWN_HIGH_WATER {
                ex.down_paused = true;
            }
        }
    }

    /// Read every available message on a visitor stream, decoding heads and
    /// body frames, and hand them to the response pump. Stops when the
    /// visitor queue hits its high-water mark, so a slow visitor applies
    /// backpressure through the mux window instead of losing bytes.
    fn drain_inbox(&mut self, conn: &mut Connection, id: StreamId) {
        // Flush anything already queued first.
        self.pump_down(id);
        loop {
            if self
                .inflight
                .get(&id)
                .map(|ex| ex.down_paused)
                .unwrap_or(true)
            {
                return;
            }
            match conn.recv_msg(id) {
                Ok(msg) => {
                    let handle = self.handle();
                    if let Some(ex) = self.inflight.get_mut(&id) {
                        Self::on_visitor_message(&handle, ex, conn, id, &msg);
                    } else {
                        return;
                    }
                    self.pump_down(id);
                }
                Err(_) => return,
            }
        }
    }

    /// Hand at most one queued response frame to the visitor at a time. When
    /// the send completes, the driver resumes pumping, and reading the mux
    /// resumes once the queue falls below the low-water mark.
    fn pump_down(&mut self, id: StreamId) {
        enum Pump {
            Send(mpsc::Sender<BodyFrameItem>, BodyFrameItem),
            Fin,
            Idle,
        }
        let action = {
            let Some(ex) = self.inflight.get_mut(&id) else {
                return;
            };
            if ex.forwarding {
                return;
            }
            match ex.pending_down.pop_front() {
                Some(frame) => match ex.body_tx.clone() {
                    Some(tx) => {
                        ex.forwarding = true;
                        if ex.pending_down.len() <= DOWN_LOW_WATER {
                            ex.down_paused = false;
                        }
                        Pump::Send(tx, frame)
                    }
                    None => Pump::Idle,
                },
                None if ex.client_done => Pump::Fin,
                None => Pump::Idle,
            }
        };
        match action {
            Pump::Send(tx, frame) => {
                let handle = self.handle();
                tokio::spawn(async move {
                    let _ = tx.send(frame).await;
                    handle.spawn_on(move |conn, h| {
                        if let Some(ex) = h.inflight.get_mut(&id) {
                            ex.forwarding = false;
                        }
                        h.drain_inbox(conn, id);
                    });
                });
            }
            Pump::Fin => {
                self.inflight.remove(&id);
            }
            Pump::Idle => {}
        }
    }

    /// After a `101`: pump bytes both ways between the visitor's upgraded
    /// socket and the mux stream. Downstream frames arrive through the same
    /// one-at-a-time channel `pump_down` feeds; upstream bytes are queued as
    /// `BodyFrame::Chunk`s through the existing credit-aware request path.
    /// Either side ending finishes the stream; a socket error resets it.
    fn spawn_upgrade_pipe(
        handle: RelayHandle,
        id: StreamId,
        on_upgrade: hyper::upgrade::OnUpgrade,
        mut down_rx: mpsc::Receiver<BodyFrameItem>,
    ) {
        tokio::spawn(async move {
            let upgraded = match on_upgrade.await {
                Ok(u) => u,
                Err(e) => {
                    debug!(%id, error = %e, "Visitor upgrade failed");
                    handle.spawn_on(move |conn, h| {
                        h.inflight.remove(&id);
                        let _ = conn.reset(id, ResetCode::Cancelled.as_u32());
                    });
                    return;
                }
            };
            let (mut rd, mut wr) = tokio::io::split(TokioIo::new(upgraded));

            // visitor → client
            let up = {
                let handle = handle.clone();
                async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    loop {
                        let n = match rd.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        let chunk = BodyFrame::Chunk(buf[..n].to_vec());
                        let (room_tx, room_rx) = oneshot::channel::<()>();
                        handle.spawn_on(move |conn, h| {
                            let Some(ex) = h.inflight.get_mut(&id) else {
                                return;
                            };
                            ex.pending_body.push_back(chunk);
                            Self::drain_request_body(ex, conn, id);
                            if ex.pending_body.len() < UP_HIGH_WATER {
                                let _ = room_tx.send(());
                            } else {
                                ex.body_resume = Some(room_tx);
                            }
                        });
                        if room_rx.await.is_err() {
                            return;
                        }
                    }
                    // Visitor closed its write side: FIN our half once the
                    // queue drains.
                    handle.spawn_on(move |conn, h| {
                        if let Some(ex) = h.inflight.get_mut(&id) {
                            ex.body_done = true;
                            ex.piped = false;
                            Self::drain_request_body(ex, conn, id);
                        }
                    });
                }
            };

            // client → visitor
            let down = async move {
                while let Some(item) = down_rx.recv().await {
                    let Ok(frame) = item else { break };
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    if wr.write_all(&data).await.is_err() {
                        break;
                    }
                    let _ = wr.flush().await;
                }
                let _ = wr.shutdown().await;
            };

            tokio::join!(up, down);
        });
    }

    fn drain_request_body(ex: &mut Exchange, conn: &mut Connection, id: StreamId) {
        while let Some(frame) = ex.pending_body.front() {
            let bytes = match weaver_proto::encode(frame) {
                Ok(b) => b,
                Err(e) => {
                    debug!(%id, error = %e, "Error encoding request body frame");
                    ex.pending_body.clear();
                    return;
                }
            };
            match conn.send(id, &bytes, ex.body_compress) {
                Ok(()) => {
                    ex.pending_body.pop_front();
                }
                Err(StreamError::WouldBlock) => break,
                Err(e) => {
                    debug!(%id, error = %e, "Error sending request body");
                    ex.pending_body.clear();
                    return;
                }
            }
        }
        // Room freed: let the parked hyper body reader continue.
        if ex.pending_body.len() < UP_HIGH_WATER
            && let Some(resume) = ex.body_resume.take()
        {
            let _ = resume.send(());
        }
        // In a piped exchange the stream stays open until the pipe ends.
        if ex.body_done && ex.pending_body.is_empty() && !ex.piped && ex.on_upgrade.is_none() {
            let _ = conn.finish(id);
        }
    }
}

fn refused(code: RefusalCode, service: &str) -> ControlReply {
    let message = match &code {
        RefusalCode::AlreadyRegistered => format!("Service '{service}' is already registered"),
        RefusalCode::InvalidName => format!("Service '{service}' is not a valid DNS label"),
        RefusalCode::Unauthorized => "Unauthorized client identity".into(),
        RefusalCode::UnsupportedVersion { min, max } => {
            format!("unsupported application protocol version (relay accepts {min}..={max})")
        }
        RefusalCode::Other(s) => s.clone(),
    };
    ControlReply::Refused { code, message }
}
