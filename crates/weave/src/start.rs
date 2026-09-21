//! Implementation of `weave start`: register one or more services on a single
//! mux connection and proxy real HTTP traffic to their local origins.
//!
//! This replaces the fixed-redirect `weave poc` proof of concept. The client
//! connects once, authenticates, opens one control stream per service, and
//! then answers every visitor stream by driving the origin-facing half in
//! [`crate::proxy`]. Registration replies are printed as they arrive; a
//! refusal for one service leaves the others running, and the process exits
//! non-zero once the connection ends if any service failed to register.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use hyper::body::Frame;
use tokio::sync::mpsc::{self, error::TryRecvError};
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use weaver_mux::{CloseCode, CloseReason, Config, Connection, Event, StreamError, StreamId};
use weaver_proto::control::{ControlHead, ControlReply};
use weaver_proto::http::{HttpHead, HttpResponseHead};
use weaver_proto::policy::{self, HEAD_COMPRESS};
use weaver_proto::{BodyFrame, Head, ResetCode, encode};
use weaver_tokio::{Driver, DriverError, Handle, StreamHandler, SystemRng, WsTransport};

use crate::connect::{connect_tls, parse_server_address};
use crate::identity::Ed25519Signer;
use crate::log::{Entry, LogStyle, Phase};
use crate::pool::Pool;
use crate::proxy::{BoxError, ExchangeConfig, OutMsg, run_exchange};
use crate::status::StatusFooter;
use crate::target::{ServiceSpec, Target};

/// Sec-WebSocket-Protocol token both ends must agree on.
pub const WS_SUBPROTOCOL: &str = "weaver-mux-v1";

/// Options for one `weave start` invocation, already parsed from the CLI.
#[derive(Debug, Clone)]
pub struct StartOptions {
    /// One `<service>=<target>` per service to expose.
    pub specs: Vec<ServiceSpec>,
    /// Relay server address (`host` or `host:port`).
    pub server: String,
    /// Extra root CA (PEM) for the relay connection.
    pub insecure_root_ca: Option<PathBuf>,
    /// Services whose target certificate verification is disabled.
    pub insecure_targets: Vec<String>,
    /// Services that keep the public hostname as `Host`.
    pub preserve_host: Vec<String>,
    /// Services with URL/cookie rewriting disabled.
    pub no_rewrite: Vec<String>,
    /// Services that keep visitor-supplied forwarding headers.
    pub append_forwarded: Vec<String>,
    /// Silence the per-request log.
    pub quiet: bool,
    /// Add request and response headers to the per-request log.
    pub verbose: bool,
}

/// How many request-body frames may be queued toward the origin before the
/// mux inbox is left to apply backpressure.
const REQ_BODY_QUEUE: usize = 4;
/// How many response frames may be queued from the origin before the origin
/// task awaits.
const OUT_QUEUE: usize = 4;

/// Executes `weave start`, installing a Ctrl-C handler.
pub async fn run_start(opts: StartOptions) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            cancel_clone.cancel();
        }
    });
    run_start_with_token(opts, cancel).await
}

/// Executes `weave start` with an explicit shutdown token (tests, embedding).
pub async fn run_start_with_token(
    opts: StartOptions,
    shutdown_token: tokio_util::sync::CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run_start_with_tokens(
        opts,
        shutdown_token,
        tokio_util::sync::CancellationToken::new(),
    )
    .await
}

/// Like [`run_start_with_token`], plus a `release_token` that finishes every
/// control stream — dropping the registration leases — while keeping the
/// connection up. Exercises the relay's lease semantics end to end.
pub async fn run_start_with_tokens(
    opts: StartOptions,
    shutdown_token: tokio_util::sync::CancellationToken,
    release_token: tokio_util::sync::CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (host, port) = parse_server_address(&opts.server)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    let tls_stream = connect_tls(&host, port, opts.insecure_root_ca.as_deref()).await?;

    let url = format!("wss://{host}:{port}/_weaver/connect");
    let req = http::Request::builder()
        .method("GET")
        .uri(url)
        .header(http::header::HOST, &host)
        .header(http::header::CONNECTION, "Upgrade")
        .header(http::header::UPGRADE, "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tokio_tungstenite::tungstenite::handshake::client::generate_key(),
        )
        .header("Sec-WebSocket-Protocol", WS_SUBPROTOCOL)
        .body(())?;

    let (ws_stream, _): (WebSocketStream<TlsStream<tokio::net::TcpStream>>, _) =
        tokio_tungstenite::client_async_with_config(req, tls_stream, None).await?;

    let cfg = Config::client(
        Box::new(Ed25519Signer::dev()),
        host.clone(),
        Box::new(SystemRng),
    );
    let conn = Connection::new(cfg, Instant::now());
    let handler = ProxyHandler::new(&opts);
    let driver = Driver::new(conn, WsTransport::new(ws_stream), handler);
    let handle = driver.handle();
    handle.spawn_on({
        let h = handle.clone();
        move |_, handler| handler.handle = Some(h)
    });

    tokio::spawn({
        let handle = handle.clone();
        let release_token = release_token.clone();
        async move {
            release_token.cancelled().await;
            handle.spawn_on(|conn, h| {
                let ids: Vec<StreamId> = h.control.keys().copied().collect();
                for id in ids {
                    h.control.remove(&id);
                    let _ = conn.finish(id);
                }
            });
        }
    });

    tokio::spawn({
        let handle = handle.clone();
        async move {
            shutdown_token.cancelled().await;
            handle.spawn_on(|conn, h| h.shutdown(conn));
        }
    });

    let (mut handler, result) = driver.run().await;
    // Give the terminal back before printing any outcome.
    handler.footer.uninstall();
    if let Some(err) = handler.failure {
        return Err(err.into());
    }
    if !handler.failures.is_empty() {
        return Err(format!(
            "{} of {} service(s) failed to register: {}",
            handler.failures.len(),
            handler.services.len(),
            handler.failures.join("; ")
        )
        .into());
    }
    match result {
        Ok(reason) if handler.shutting_down => {
            debug_assert_eq!(reason.code, CloseCode::Shutdown);
            Ok(())
        }
        Ok(reason) => Err(format!("Connection closed by server: {:?}", reason.code).into()),
        Err(DriverError::TransportClosed) if handler.shutting_down => Ok(()),
        Err(DriverError::TransportClosed) => Err("Connection closed by relay".into()),
        Err(DriverError::Protocol(e)) => Err(format!("Mux protocol error: {e}").into()),
        Err(DriverError::Transport(e)) => Err(format!("WebSocket error: {e}").into()),
    }
}

/// Per-service runtime state, including flags and the assigned hostname.
struct ServiceRuntime {
    target: Target,
    insecure: bool,
    preserve_host: bool,
    no_rewrite: bool,
    append_forwarded: bool,
}

/// A visitor exchange in progress on one stream.
struct Exchange {
    service: String,
    req: HttpHead,
    started: Instant,
    /// Wall-clock arrival, for the log timestamp.
    started_at: std::time::SystemTime,
    status: Option<u16>,
    bytes: u64,
    /// Response frames from the origin task.
    out_rx: mpsc::Receiver<OutMsg>,
    /// Encoded response head waiting for credit.
    out_head: Option<Vec<u8>>,
    /// Encoded body frames waiting for credit.
    pending_bytes: VecDeque<(Vec<u8>, weaver_mux::Compress)>,
    out_done: bool,
    compress: weaver_mux::Compress,
    /// Request body channel toward the origin task.
    req_body_tx: Option<mpsc::Sender<Result<Frame<Bytes>, BoxError>>>,
    req_done: bool,
    req_paused: bool,
    /// Our FIN has gone out; the exchange may outlive it on a pipe.
    fin_sent: bool,
    /// Log line already printed (long-lived streams log at head, then at close).
    logged_at_head: bool,
    long_lived: bool,
    /// Final response head, kept for the `--verbose` header block.
    resp_headers: Vec<(String, Vec<u8>)>,
}

/// The relay's [`StreamHandler`]: registration on the control streams and
/// origin proxying on every visitor stream.
pub struct ProxyHandler {
    services: HashMap<String, ServiceRuntime>,
    hostname_to_service: HashMap<String, String>,
    control: HashMap<StreamId, String>,
    inflight: HashMap<StreamId, Exchange>,
    pool: Pool,
    handle: Option<Handle<ProxyHandler>>,
    style: LogStyle,
    footer: StatusFooter,
    failures: Vec<String>,
    failure: Option<String>,
    shutting_down: bool,
}

impl ProxyHandler {
    /// Build a handler from parsed options.
    pub fn new(opts: &StartOptions) -> Self {
        let flag = |list: &[String]| list.to_vec();
        let insecure = flag(&opts.insecure_targets);
        let preserve = flag(&opts.preserve_host);
        let no_rewrite = flag(&opts.no_rewrite);
        let append = flag(&opts.append_forwarded);
        let services = opts
            .specs
            .iter()
            .map(|spec| {
                (
                    spec.service.clone(),
                    ServiceRuntime {
                        target: spec.target.clone(),
                        insecure: insecure.iter().any(|s| s == &spec.service),
                        preserve_host: preserve.iter().any(|s| s == &spec.service),
                        no_rewrite: no_rewrite.iter().any(|s| s == &spec.service),
                        append_forwarded: append.iter().any(|s| s == &spec.service),
                    },
                )
            })
            .collect();
        let style = LogStyle::detect(opts.quiet, opts.verbose);
        let footer = StatusFooter::new(
            style,
            opts.specs
                .iter()
                .map(|s| (s.service.clone(), s.target.to_string())),
        );
        Self {
            services,
            hostname_to_service: HashMap::new(),
            control: HashMap::new(),
            inflight: HashMap::new(),
            pool: Pool::new(),
            handle: None,
            style,
            footer,
            failures: Vec::new(),
            failure: None,
            shutting_down: false,
        }
    }

    fn handle(&self) -> Handle<ProxyHandler> {
        self.handle
            .clone()
            .expect("handle installed before the first event can fire")
    }

    fn shutdown(&mut self, conn: &mut Connection) {
        for id in self.control.keys() {
            let _ = conn.finish(*id);
        }
        self.shutting_down = true;
        conn.close(CloseReason::new(CloseCode::Shutdown));
    }

    fn fail(&mut self, conn: &mut Connection, msg: String) {
        self.failure = Some(msg);
        conn.close(CloseReason::new(CloseCode::Shutdown));
    }

    /// Open one control stream per service and send its `Register` head.
    fn register_services(&mut self, conn: &mut Connection) {
        let specs: Vec<(String, Target)> = self
            .services
            .iter()
            .map(|(name, rt)| (name.clone(), rt.target.clone()))
            .collect();
        for (service, _target) in specs {
            let head = match ControlHead::register(service.clone()) {
                Ok(h) => h,
                Err(code) => {
                    self.failures
                        .push(format!("{service}: invalid service name ({code:?})"));
                    continue;
                }
            };
            let bytes = match encode(&Head::Control(head)) {
                Ok(b) => b,
                Err(e) => {
                    self.failures.push(format!("{service}: encode failed: {e}"));
                    continue;
                }
            };
            match conn.open(policy::CONTROL_CLASS) {
                Ok(id) => {
                    if let Err(e) = conn.send(id, &bytes, policy::CONTROL_COMPRESS) {
                        self.failures.push(format!("{service}: send failed: {e}"));
                    } else {
                        self.control.insert(id, service);
                    }
                }
                Err(e) => self.failures.push(format!("{service}: open failed: {e}")),
            }
        }
    }

    fn on_control_reply(&mut self, conn: &mut Connection, id: StreamId, msg: &[u8]) {
        let service = self.control.get(&id).cloned().unwrap_or_default();
        match weaver_proto::decode::<ControlReply>(msg) {
            Ok(ControlReply::Registered { hostname }) => {
                let target = self
                    .services
                    .get(&service)
                    .map(|rt| rt.target.clone())
                    .unwrap_or_else(|| {
                        Target::parse("localhost:80").expect("valid fallback target")
                    });
                let url = format!("https://{hostname}/");
                // On a TTY the sticky footer carries this; otherwise print
                // it as a plain line so piped output still records it.
                if self.footer.is_active() {
                    self.footer.registered(&service, url);
                } else {
                    println!(
                        "{}",
                        crate::log::registered_line(
                            &self.style,
                            &service,
                            &url,
                            &target.to_string(),
                        )
                    );
                }
                self.hostname_to_service
                    .insert(hostname.to_ascii_lowercase(), service);
            }
            Ok(ControlReply::Refused { code, message }) => {
                let detail = format!("{message} ({code:?})");
                if self.footer.is_active() {
                    self.footer.refused(&service, detail.clone());
                } else {
                    eprintln!(
                        "{}",
                        crate::log::refused_line(&self.style, &service, &detail)
                    );
                }
                self.failures.push(format!("{service}: {detail}"));
            }
            Ok(ControlReply::CertState { state }) => {
                if self.footer.is_active() {
                    self.footer.cert(&service, state);
                } else {
                    println!("{}", crate::log::cert_line(&self.style, &service, state));
                }
            }
            Err(e) => self.fail(conn, format!("{service}: bad control reply: {e}")),
        }
    }

    /// Resolve the service a visitor stream belongs to from the request
    /// authority.
    ///
    /// A visitor can arrive in the window between the relay registering the
    /// service and the client processing the `Registered` reply, so this must
    /// not depend on the hostname reply. The public hostname is
    /// `<service>.<machine>.<person>.<root>` (see `derive_hostname`), so the
    /// first label is the service name; the exact hostname map is consulted
    /// first for the common case.
    fn resolve_service(&self, authority: &str) -> Option<String> {
        let authority = authority.to_ascii_lowercase();
        if let Some(service) = self.hostname_to_service.get(&authority) {
            return Some(service.clone());
        }
        let host = authority.split(':').next().unwrap_or(&authority);
        let label = host.split('.').next()?;
        if self.services.contains_key(label) {
            return Some(label.to_string());
        }
        None
    }

    /// A new visitor stream: decode its head, resolve the service, spawn the
    /// origin task, and remember the exchange.
    fn start_exchange(&mut self, conn: &mut Connection, id: StreamId, first: &[u8]) {
        let head = match weaver_proto::decode::<Head>(first) {
            Ok(Head::Http(h)) => h,
            _ => {
                let _ = conn.reset(id, ResetCode::Cancelled.as_u32());
                return;
            }
        };
        let Some(service) = self.resolve_service(&head.authority) else {
            let _ = conn.reset(id, ResetCode::Cancelled.as_u32());
            return;
        };
        let Some(rt) = self.services.get(&service) else {
            let _ = conn.reset(id, ResetCode::Cancelled.as_u32());
            return;
        };
        // The public origin is exactly the host the visitor used; the
        // registered hostname is only needed for the startup log line.
        let public_origin = format!("https://{}", head.authority);
        let cfg = ExchangeConfig {
            head: head.clone(),
            target: rt.target.clone(),
            public_origin,
            insecure: rt.insecure,
            preserve_host: rt.preserve_host,
            no_rewrite: rt.no_rewrite,
            append_forwarded: rt.append_forwarded,
        };

        let (req_tx, req_rx) = mpsc::channel(REQ_BODY_QUEUE);
        let (out_tx, out_rx) = mpsc::channel(OUT_QUEUE);
        let handle = self.handle();
        let notify: Arc<dyn Fn() + Send + Sync> = {
            let handle = handle.clone();
            Arc::new(move || {
                let handle = handle.clone();
                handle.spawn_on(move |conn, h| h.pump_out(conn, id));
            })
        };
        let reset: Arc<dyn Fn(u32) + Send + Sync> = {
            let handle = handle.clone();
            Arc::new(move |code| {
                let handle = handle.clone();
                handle.spawn_on(move |conn, h| {
                    if h.inflight.remove(&id).is_some() {
                        let _ = conn.reset(id, code);
                    }
                });
            })
        };
        let pool = self.pool.clone();
        tokio::spawn(run_exchange(
            cfg,
            req_rx,
            pool,
            crate::proxy::Outbox::new(out_tx, notify),
            reset,
        ));

        self.inflight.insert(
            id,
            Exchange {
                service,
                req: head,
                started: Instant::now(),
                started_at: std::time::SystemTime::now(),
                status: None,
                bytes: 0,
                out_rx,
                out_head: None,
                pending_bytes: VecDeque::new(),
                out_done: false,
                compress: weaver_mux::Compress::Auto,
                req_body_tx: Some(req_tx),
                req_done: false,
                req_paused: false,
                fin_sent: false,
                logged_at_head: false,
                resp_headers: Vec::new(),
                long_lived: false,
            },
        );
    }

    /// Drain available messages on a visitor stream, applying request-body
    /// backpressure by pausing when the origin-side queue is full.
    fn drain_stream(&mut self, conn: &mut Connection, id: StreamId) {
        loop {
            if self
                .inflight
                .get(&id)
                .map(|ex| ex.req_paused)
                .unwrap_or(true)
            {
                return;
            }
            match conn.recv_msg(id) {
                Ok(msg) => self.on_visitor_body(conn, id, msg),
                Err(StreamError::WouldBlock) => return,
                Err(_) => return,
            }
        }
    }

    /// Handle one body message from the relay: a [`BodyFrame`] chunk or
    /// trailers. If the origin-side queue is full, the frame is handed to a
    /// task that awaits capacity and then resumes the drain.
    fn on_visitor_body(&mut self, _conn: &mut Connection, id: StreamId, msg: Vec<u8>) {
        let frame: BodyFrame = match weaver_proto::decode(&msg) {
            Ok(f) => f,
            Err(_) => {
                if let Some(ex) = self.inflight.get_mut(&id) {
                    ex.req_done = true;
                    ex.req_body_tx = None;
                }
                return;
            }
        };
        let body_frame = match frame {
            BodyFrame::Chunk(data) => Frame::data(Bytes::from(data)),
            BodyFrame::Trailers(fields) => {
                let mut map = http::HeaderMap::new();
                for (n, v) in fields {
                    if let (Ok(name), Ok(value)) = (
                        HeaderName::from_bytes(n.as_bytes()),
                        HeaderValue::from_bytes(&v),
                    ) {
                        map.append(name, value);
                    }
                }
                Frame::trailers(map)
            }
        };
        let Some(ex) = self.inflight.get_mut(&id) else {
            return;
        };
        let Some(tx) = ex.req_body_tx.clone() else {
            return;
        };
        match tx.try_send(Ok(body_frame)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(frame)) => {
                ex.req_paused = true;
                let handle = self.handle();
                tokio::spawn(async move {
                    let _ = tx.send(frame).await;
                    handle.spawn_on(move |conn, h| {
                        if let Some(ex) = h.inflight.get_mut(&id) {
                            ex.req_paused = false;
                        }
                        h.drain_stream(conn, id);
                    });
                });
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }

    /// Flush the origin's response toward the relay, respecting mux credit,
    /// and FIN the stream once the response is complete.
    fn pump_out(&mut self, conn: &mut Connection, id: StreamId) {
        let style = self.style;
        let Some(ex) = self.inflight.get_mut(&id) else {
            return;
        };
        loop {
            if let Some(bytes) = ex.out_head.take() {
                match conn.send(id, &bytes, HEAD_COMPRESS) {
                    Ok(()) => {}
                    Err(StreamError::WouldBlock) => {
                        ex.out_head = Some(bytes);
                        return;
                    }
                    Err(_) => {
                        self.inflight.remove(&id);
                        return;
                    }
                }
            }
            while let Some((bytes, compress)) = ex.pending_bytes.front() {
                match conn.send(id, bytes, *compress) {
                    Ok(()) => {
                        ex.bytes += bytes.len() as u64;
                        ex.pending_bytes.pop_front();
                    }
                    Err(StreamError::WouldBlock) => return,
                    Err(_) => {
                        self.inflight.remove(&id);
                        return;
                    }
                }
            }
            match ex.out_rx.try_recv() {
                Ok(OutMsg::Head(head)) => {
                    ex.status = Some(head.status);
                    ex.compress = crate::proxy::body_compress(&ex.req, &head);
                    ex.resp_headers = head.headers.clone();
                    ex.long_lived = is_long_lived(&ex.req, &head);
                    if ex.long_lived && !ex.logged_at_head {
                        ex.log_line(&style, Phase::Opened);
                        ex.logged_at_head = true;
                    }
                    match encode(&head) {
                        Ok(bytes) => {
                            ex.out_head = Some(bytes);
                            // Flush now: the head must not wait for the next
                            // wake-up, or a 101/long-poll head sits unsent.
                            continue;
                        }
                        Err(_) => {
                            self.inflight.remove(&id);
                            return;
                        }
                    }
                }
                Ok(OutMsg::Frame(frame)) => match encode(&frame) {
                    Ok(bytes) => ex.pending_bytes.push_back((bytes, ex.compress)),
                    Err(_) => {
                        self.inflight.remove(&id);
                        return;
                    }
                },
                Ok(OutMsg::End) | Err(TryRecvError::Disconnected) => ex.out_done = true,
                Err(TryRecvError::Empty) => return,
            }
            if ex.out_done && ex.pending_bytes.is_empty() && ex.out_head.is_none() {
                if !ex.fin_sent {
                    let _ = conn.finish(id);
                    ex.fin_sent = true;
                    ex.log_line(
                        &style,
                        if ex.long_lived {
                            Phase::Closed
                        } else {
                            Phase::Done
                        },
                    );
                }
                // Our direction is done, but on an upgraded pipe the relay
                // may still be forwarding visitor bytes (its WebSocket Close
                // reply, typically) that must reach the origin: keep the
                // exchange — and its request-body channel — until the relay
                // FINs too. Non-upgrade exchanges have `req_done` already.
                if ex.req_done {
                    self.inflight.remove(&id);
                }
                return;
            }
        }
    }
}

impl Exchange {
    /// Print one request line (and, in verbose mode, the headers). Visitor
    /// IP and protocol come from what the relay stamped on the head.
    fn log_line(&self, style: &LogStyle, phase: Phase) {
        let visitor = self
            .req
            .header("x-forwarded-for")
            .and_then(|v| std::str::from_utf8(v).ok());
        // The relay records the visitor's HTTP version in `Via` (RFC 9110
        // §7.6.3): `2 weaver`, `1.1 weaver`.
        let via = self
            .req
            .header("via")
            .and_then(|v| std::str::from_utf8(v).ok())
            .unwrap_or("");
        let proto = if self.req.header("upgrade").is_some() {
            "ws"
        } else if via.starts_with("2") {
            "h2"
        } else if via.starts_with("3") {
            "h3"
        } else {
            "h1"
        };
        let entry = Entry {
            at: self.started_at,
            service: &self.service,
            visitor,
            proto,
            method: &self.req.method,
            path: &self.req.path,
            status: self.status,
            bytes: self.bytes,
            elapsed: self.started.elapsed(),
            phase,
        };
        if let Some(line) = crate::log::request_line(style, &entry) {
            println!("{line}");
            if style.verbose && phase != Phase::Closed {
                print!(
                    "{}",
                    crate::log::header_block(style, ">", &self.req.headers)
                );
                print!(
                    "{}",
                    crate::log::header_block(style, "<", &self.resp_headers)
                );
            }
        }
    }
}

/// A response is long-lived if it is an event stream or the exchange is a
/// realtime (upgrade/SSE) one; such streams log at head and again at close.
fn is_long_lived(req: &HttpHead, head: &HttpResponseHead) -> bool {
    policy::response_class(req, head) == Some(weaver_mux::Class::Realtime)
        || req.header("upgrade").is_some()
}

impl StreamHandler for ProxyHandler {
    fn on_event(&mut self, conn: &mut Connection, event: Event) {
        match event {
            Event::Authenticated { .. } => self.register_services(conn),
            Event::Rejected { code, message } => {
                self.failure = Some(format!("Connection rejected: {message} ({code:?})"));
            }
            Event::Readable(id) => {
                if self.control.contains_key(&id) {
                    while let Ok(msg) = conn.recv_msg(id) {
                        self.on_control_reply(conn, id, &msg);
                    }
                } else if self.inflight.contains_key(&id) {
                    self.drain_stream(conn, id);
                } else if let Ok(msg) = conn.recv_msg(id) {
                    self.start_exchange(conn, id, &msg);
                    self.drain_stream(conn, id);
                }
            }
            Event::Writable { id, .. } => {
                if self.inflight.contains_key(&id) {
                    self.pump_out(conn, id);
                }
            }
            Event::Finished(id) => {
                let done = if let Some(ex) = self.inflight.get_mut(&id) {
                    ex.req_done = true;
                    // Dropping the sender ends the request body / pipe input.
                    ex.req_body_tx = None;
                    ex.fin_sent
                } else {
                    false
                };
                // Both directions finished (ours went first): tear down.
                if done {
                    self.inflight.remove(&id);
                }
            }
            Event::Reset { id, .. } => {
                self.inflight.remove(&id);
            }
            Event::StreamOpened { .. } | Event::Closed { .. } => {}
        }
    }
}
