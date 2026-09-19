//! One client connection: a [`weaver_tokio::Driver`] over the upgraded
//! WebSocket plus the relay's [`StreamHandler`].
//!
//! Stream conventions (see `weaver_proto`): the client opens a control
//! stream whose first message is `Head::Control`; the relay opens one
//! stream per visitor request whose first message is `Head::Http`, followed
//! by raw body chunks, and reads back an `HttpResponseHead` followed by raw
//! body chunks.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Response, StatusCode};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, info, trace};
use weaver_mux::error::{CloseCode, GoAway};
use weaver_mux::{Compress, Config, Connection, Event, KeyId, StreamError, StreamId};
use weaver_proto::control::{ControlHead, ControlReply, RefusalCode};
use weaver_proto::http::{HttpHead, HttpResponseHead};
use weaver_proto::{Head, policy};
use weaver_tokio::{Driver, Handle, StreamHandler, SystemRng, WsTransport};

use crate::tunnel::identity::ResolverVerifier;
use crate::tunnel::proxy::{BoxBody, ProxyError, ProxyRequest, TunnelResponseBody};
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

async fn run_tunnel_connection(
    ws_stream: WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>,
    registry: Arc<TunnelRegistry>,
    root_domain: String,
) {
    let verifier = Box::new(ResolverVerifier(registry.identities()));
    let cfg = Config::server(verifier, root_domain, Box::new(SystemRng));
    let conn = Connection::new(cfg, Instant::now());

    let (proxy_tx, proxy_rx) = mpsc::channel::<ProxyRequest>(64);
    let handler = RelayHandler {
        registry: Arc::clone(&registry),
        handle: None,
        proxy_tx,
        conn_id: None,
        key: None,
        control_streams: HashSet::new(),
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

/// A visitor exchange in progress on one stream.
struct Exchange {
    req: HttpHead,
    response_tx: Option<oneshot::Sender<Result<Response<BoxBody>, ProxyError>>>,
    body_tx: Option<mpsc::Sender<Result<Bytes, Box<dyn std::error::Error + Send + Sync>>>>,
    /// Request body chunks accepted from hyper but not yet sent (credit).
    pending_body: Vec<Bytes>,
    /// The request body reader has ended; FIN once `pending_body` drains.
    body_done: bool,
    body_compress: Compress,
}

pub(crate) struct RelayHandler {
    registry: Arc<TunnelRegistry>,
    handle: Option<RelayHandle>,
    proxy_tx: mpsc::Sender<ProxyRequest>,
    conn_id: Option<u64>,
    key: Option<KeyId>,
    control_streams: HashSet<StreamId>,
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
                        h.close(GoAway::new(CloseCode::Superseded));
                    }
                });
            }
            Event::StreamOpened { id, .. } => {
                trace!(%id, "Peer opened stream; awaiting head");
            }
            Event::Readable(id) => {
                while let Ok(msg) = conn.recv_msg(id) {
                    if let Some(ex) = self.inflight.get_mut(&id) {
                        Self::on_visitor_message(ex, conn, id, &msg);
                    } else if self.control_streams.contains(&id) {
                        debug!(%id, "Unexpected message on control stream");
                    } else {
                        self.on_first_message(conn, id, &msg);
                    }
                }
            }
            Event::Writable(id) => {
                if let Some(ex) = self.inflight.get_mut(&id) {
                    Self::drain_request_body(ex, conn, id);
                }
            }
            Event::Finished(id) => {
                if self.control_streams.remove(&id) {
                    info!(%id, "Control registration stream closed by client");
                }
                if let Some(ex) = self.inflight.remove(&id) {
                    drop(ex.body_tx);
                }
            }
            Event::Reset { id, code } => {
                trace!(%id, code, "Stream reset");
                self.control_streams.remove(&id);
                if let Some(mut ex) = self.inflight.remove(&id)
                    && let Some(tx) = ex.response_tx.take()
                {
                    let _ = tx.send(Err(ProxyError::Reset));
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

    /// First message on a client-opened stream must be a `Head::Control`.
    fn on_first_message(&mut self, conn: &mut Connection, id: StreamId, msg: &[u8]) {
        let Ok(Head::Control(ControlHead::Register {
            proto_version,
            service,
        })) = weaver_proto::decode::<Head>(msg)
        else {
            debug!(%id, "Unexpected first message from client; resetting");
            let _ = conn.reset(id, 0);
            return;
        };
        let (Some(key), Some(conn_id)) = (self.key, self.conn_id) else {
            let _ = conn.reset(id, 0);
            return;
        };
        if let Err(code) = weaver_proto::accept_protocol_version(proto_version) {
            Self::reply(conn, id, refused(code, &service));
            return;
        }
        // Registration touches the cert manager (async): run it off the
        // loop and come back through the handle.
        self.control_streams.insert(id);
        let registry = Arc::clone(&self.registry);
        let proxy_tx = self.proxy_tx.clone();
        let handle = self.handle();
        tokio::spawn(async move {
            let res = registry
                .register_service(key, conn_id, &service, proxy_tx)
                .await;
            handle.spawn_on(move |conn, _| {
                let reply = match res {
                    Ok(hostname) => ControlReply::Registered { hostname },
                    Err(code) => refused(code, &service),
                };
                Self::reply(conn, id, reply);
            });
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
        let id = match conn.open(policy::stream_policy(&req.head)) {
            Ok(id) => id,
            Err(e) => {
                let _ = req.response_tx.send(Err(ProxyError::Mux(e.to_string())));
                return;
            }
        };
        // A fresh stream has a full window (≥ 64 KiB) and the head is
        // bounded by max_message: failure here is an error, not backpressure.
        if let Err(e) = conn.send(id, &head_bytes, policy::HEAD_COMPRESS) {
            let _ = conn.reset(id, 0);
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
                pending_body: Vec::new(),
                body_done: false,
            },
        );
        // Stream the visitor's request body into the loop chunk by chunk.
        let h = self.handle();
        let mut body = req.body;
        tokio::spawn(async move {
            while let Some(frame) = body.frame().await {
                match frame {
                    Ok(f) => {
                        if let Ok(data) = f.into_data()
                            && !data.is_empty()
                        {
                            h.spawn_on(move |conn, handler| {
                                if let Some(ex) = handler.inflight.get_mut(&id) {
                                    ex.pending_body.push(data);
                                    Self::drain_request_body(ex, conn, id);
                                }
                            });
                        }
                    }
                    Err(_) => {
                        h.spawn_on(move |conn, handler| {
                            handler.inflight.remove(&id);
                            let _ = conn.reset(id, 0);
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

    fn on_visitor_message(ex: &mut Exchange, conn: &mut Connection, id: StreamId, msg: &[u8]) {
        if let Some(tx) = ex.response_tx.take() {
            // First message back is the response head.
            let head: HttpResponseHead = match weaver_proto::decode(msg) {
                Ok(h) => h,
                Err(e) => {
                    debug!(%id, error = %e, "Bad response head from client");
                    let _ = tx.send(Err(ProxyError::Codec(e.to_string())));
                    let _ = conn.reset(id, 0);
                    return;
                }
            };
            if let Some(p) = policy::response_policy(&ex.req, &head) {
                let _ = conn.set_policy(id, p);
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
            let (body_tx, body_rx) = mpsc::channel(16);
            let response = builder
                .body(TunnelResponseBody::boxed(body_rx))
                .expect("status and headers were validated");
            let _ = tx.send(Ok(response));
            ex.body_tx = Some(body_tx);
        } else if let Some(body_tx) = &ex.body_tx {
            let _ = body_tx.try_send(Ok(Bytes::copy_from_slice(msg)));
        }
    }

    fn drain_request_body(ex: &mut Exchange, conn: &mut Connection, id: StreamId) {
        while let Some(chunk) = ex.pending_body.first() {
            match conn.send(id, chunk, ex.body_compress) {
                Ok(()) => {
                    ex.pending_body.remove(0);
                }
                Err(StreamError::WouldBlock) => return,
                Err(e) => {
                    debug!(%id, error = %e, "Error sending request body");
                    ex.pending_body.clear();
                    return;
                }
            }
        }
        if ex.body_done {
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
