//! `weave start`: register services on one mux connection and proxy their
//! visitors to the local origins.
//!
//! The client connects once, opens one control stream per service (the
//! registration lease), and answers every visitor stream by driving the
//! origin-facing half in [`crate::proxy`]. A refusal for one service leaves the
//! others running; the command fails once the connection ends if any did.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use hyper::body::Frame;
use tokio::sync::mpsc::{self, error::TryRecvError};
use tokio_util::sync::CancellationToken;
use weaver_mux::{CloseCode, CloseReason, Connection, Event, StreamError, StreamId};
use weaver_proto::control::{ControlHead, ControlReply};
use weaver_proto::http::{HttpHead, HttpResponseHead};
use weaver_proto::policy::{self, HEAD_COMPRESS};
use weaver_proto::{BodyFrame, Head, ResetCode, encode};
use weaver_tokio::{DriverError, Handle, StreamHandler};

use crate::client::{Client, PairedKey, open_control};
use crate::error::BoxError;
use crate::error::Error;
use crate::host::AdminHost;
use crate::pool::Pool;
use crate::proxy::{OutMsg, Outbox, run_exchange};
use crate::report::{Phase, Reporter, RequestEvent};
use crate::target::ServiceSpec;

/// What to expose, and where.
#[derive(Debug, Clone)]
pub struct StartOptions {
    /// The paired relay to use; the default one when empty.
    pub server: String,
    /// The services to register.
    pub services: Vec<ServiceSpec>,
}

/// How many request-body frames may be queued toward the origin before the
/// mux inbox is left to apply backpressure.
const REQ_BODY_QUEUE: usize = 4;
/// How many response frames may be queued from the origin before the origin
/// task awaits.
const OUT_QUEUE: usize = 4;

impl Client {
    /// Runs the tunnel until `shutdown` is cancelled or the connection ends.
    pub async fn start(
        &self,
        opts: &StartOptions,
        shutdown: CancellationToken,
    ) -> Result<(), Error> {
        self.start_with_release(opts, shutdown, CancellationToken::new())
            .await
    }

    /// Like [`Client::start`], plus `release`: cancelling it finishes every
    /// control stream, dropping the registrations while the connection stays
    /// up.
    pub async fn start_with_release(
        &self,
        opts: &StartOptions,
        shutdown: CancellationToken,
        release: CancellationToken,
    ) -> Result<(), Error> {
        let relay = self.paired_relay(&opts.server).await?;
        let host = AdminHost::parse(&relay.admin_host)?;
        let host_name = relay.admin_host.clone();

        let setup = async {
            let PairedKey::Valid(signer) = self.open_paired_key(&relay).await? else {
                return Err(Error::KeyGone {
                    host: host_name.clone(),
                });
            };
            self.reporter.connecting(&host_name);
            let handler = ProxyHandler::new(
                host_name.clone(),
                opts.services.clone(),
                Arc::clone(&self.reporter),
            );
            self.mux(&host, signer, handler).await
        };
        // The key store may be locked indefinitely: let the user stop waiting.
        let driver = tokio::select! {
            driver = setup => driver?,
            () = shutdown.cancelled() => return Ok(()),
        };

        let handle = driver.handle();
        let run = driver.run();
        tokio::pin!(run);
        let (mut stopping, mut released) = (false, false);
        let (handler, result) = loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                () = shutdown.cancelled(), if !stopping => {
                    stopping = true;
                    handle.spawn_on(|conn, h| h.shutdown(conn));
                }
                () = release.cancelled(), if !released => {
                    released = true;
                    handle.spawn_on(|conn, h| {
                        for (id, _) in h.control.drain() {
                            let _ = conn.finish(id);
                        }
                    });
                }
            }
        };
        handler.outcome(result)
    }
}

/// A visitor exchange in progress on one stream.
struct Exchange {
    service: String,
    req: HttpHead,
    started: Instant,
    started_at: SystemTime,
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
    /// An upgrade or event stream: logged when it opens and when it closes.
    long_lived: bool,
    resp_headers: Vec<(String, Vec<u8>)>,
}

/// Registration on the control streams, origin proxying on every visitor
/// stream.
struct ProxyHandler {
    host: String,
    services: Vec<ServiceSpec>,
    control: HashMap<StreamId, String>,
    inflight: HashMap<StreamId, Exchange>,
    pool: Pool,
    handle: Option<Handle<ProxyHandler>>,
    reporter: Arc<dyn Reporter>,
    /// `service: reason` for each service that did not register.
    failures: Vec<String>,
    /// What ended the connection, when it was not the relay or the user.
    failure: Option<Error>,
    shutting_down: bool,
}

impl ProxyHandler {
    fn new(host: String, services: Vec<ServiceSpec>, reporter: Arc<dyn Reporter>) -> Self {
        Self {
            host,
            services,
            control: HashMap::new(),
            inflight: HashMap::new(),
            pool: Pool::default(),
            handle: None,
            reporter,
            failures: Vec::new(),
            failure: None,
            shutting_down: false,
        }
    }

    /// How the connection's end reads to the user.
    fn outcome(self, result: Result<CloseReason, DriverError>) -> Result<(), Error> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        if !self.failures.is_empty() {
            return Err(Error::Registration {
                total: self.services.len(),
                failures: self.failures,
            });
        }
        let reason = match result {
            Ok(_) | Err(DriverError::TransportClosed) if self.shutting_down => return Ok(()),
            Ok(reason) if reason.code == CloseCode::KeyRevoked => {
                return Err(Error::Revoked { host: self.host });
            }
            Ok(reason) if reason.code == CloseCode::Superseded => {
                "another `weave start` with this machine's key took over".to_string()
            }
            Ok(reason) => format!("the relay closed the connection ({:?})", reason.code),
            Err(DriverError::TransportClosed) => "the connection dropped".to_string(),
            Err(e) => e.to_string(),
        };
        Err(Error::Disconnected {
            host: self.host,
            reason,
        })
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

    fn fail(&mut self, conn: &mut Connection, error: Error) {
        self.failure = Some(error);
        conn.close(CloseReason::new(CloseCode::Shutdown));
    }

    /// Opens one control stream per service and sends its `Register` head.
    fn register_services(&mut self, conn: &mut Connection) {
        for spec in &self.services {
            let opened = ControlHead::register(spec.service.clone())
                .map_err(|code| format!("invalid service name ({code:?})"))
                .and_then(|head| open_control(conn, &head));
            match opened {
                Ok(id) => {
                    self.control.insert(id, spec.service.clone());
                }
                Err(e) => self.failures.push(format!("{}: {e}", spec.service)),
            }
        }
    }

    fn on_control_reply(&mut self, conn: &mut Connection, id: StreamId, msg: &[u8]) {
        let service = self.control.get(&id).cloned().unwrap_or_default();
        match weaver_proto::decode::<ControlReply>(msg) {
            Ok(ControlReply::Registered { hostname }) => {
                self.reporter
                    .registered(&service, &format!("https://{hostname}/"));
            }
            Ok(ControlReply::Refused { code, message }) => {
                let detail = format!("{message} ({code:?})");
                self.reporter.refused(&service, &detail);
                self.failures.push(format!("{service}: {detail}"));
            }
            Ok(ControlReply::CertState { state }) => self.reporter.certificate(&service, state),
            // The answer to a revoke, which a registration stream never sends.
            Ok(ControlReply::Revoked) => self.fail(
                conn,
                Error::Protocol(format!("{service}: `Revoked` on a registration stream")),
            ),
            Err(e) => self.fail(conn, Error::Protocol(format!("{service}: {e}"))),
        }
    }

    /// The service a visitor stream is for, from the request authority.
    ///
    /// Read from the hostname itself, `<person>-<machine>-<service>.<root>`
    /// (person and machine hold no dash), because a visitor can arrive before
    /// the `Registered` reply does.
    fn resolve_service(&self, authority: &str) -> Option<&ServiceSpec> {
        let label = authority.split(['.', ':']).next()?.to_ascii_lowercase();
        let service = label.splitn(3, '-').nth(2)?;
        self.services.iter().find(|s| s.service == service)
    }

    /// A new visitor stream: decode its head, spawn the origin task, and
    /// remember the exchange.
    fn start_exchange(&mut self, conn: &mut Connection, id: StreamId, first: &[u8]) {
        let resolved = match weaver_proto::decode::<Head>(first) {
            Ok(Head::Http(head)) => self
                .resolve_service(&head.authority)
                .cloned()
                .map(|spec| (head, spec)),
            _ => None,
        };
        let Some((head, spec)) = resolved else {
            let _ = conn.reset(id, ResetCode::Cancelled.as_u32());
            return;
        };

        let (req_tx, req_rx) = mpsc::channel(REQ_BODY_QUEUE);
        let (out_tx, out_rx) = mpsc::channel(OUT_QUEUE);
        let handle = self.handle();
        let notify: Arc<dyn Fn() + Send + Sync> = {
            let handle = handle.clone();
            Arc::new(move || handle.spawn_on(move |conn, h| h.pump_out(conn, id)))
        };
        let reset: Arc<dyn Fn(u32) + Send + Sync> = Arc::new(move |code| {
            handle.spawn_on(move |conn, h| {
                if h.inflight.remove(&id).is_some() {
                    let _ = conn.reset(id, code);
                }
            });
        });
        let service = spec.service.clone();
        tokio::spawn(run_exchange(
            head.clone(),
            spec,
            req_rx,
            self.pool.clone(),
            Outbox::new(out_tx, notify),
            reset,
        ));

        self.inflight.insert(
            id,
            Exchange {
                service,
                req: head,
                started: Instant::now(),
                started_at: SystemTime::now(),
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
                long_lived: false,
                resp_headers: Vec::new(),
            },
        );
    }

    /// Drains available messages on a visitor stream, pausing while the
    /// origin-side queue is full.
    fn drain_stream(&mut self, conn: &mut Connection, id: StreamId) {
        while self.inflight.get(&id).is_some_and(|ex| !ex.req_paused) {
            match conn.recv_msg(id) {
                Ok(msg) => self.on_visitor_body(id, msg),
                Err(_) => return,
            }
        }
    }

    /// One body message from the relay: a chunk or trailers. When the
    /// origin-side queue is full, a task awaits capacity and resumes the drain.
    fn on_visitor_body(&mut self, id: StreamId, msg: Vec<u8>) {
        let Some(ex) = self.inflight.get_mut(&id) else {
            return;
        };
        let frame = match weaver_proto::decode::<BodyFrame>(&msg) {
            Ok(BodyFrame::Chunk(data)) => Frame::data(Bytes::from(data)),
            Ok(BodyFrame::Trailers(fields)) => {
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
            Err(_) => {
                ex.req_done = true;
                ex.req_body_tx = None;
                return;
            }
        };
        let Some(tx) = ex.req_body_tx.clone() else {
            return;
        };
        if let Err(mpsc::error::TrySendError::Full(frame)) = tx.try_send(Ok(frame)) {
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
    }

    /// Flushes the origin's response toward the relay within mux credit, and
    /// FINs the stream once the response is complete.
    fn pump_out(&mut self, conn: &mut Connection, id: StreamId) {
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
            let encoded = match ex.out_rx.try_recv() {
                Ok(OutMsg::Head(head)) => {
                    ex.status = Some(head.status);
                    ex.compress = policy::response_body_compress(&ex.req, &head);
                    ex.long_lived = is_long_lived(&ex.req, &head);
                    ex.resp_headers = head.headers.clone();
                    if ex.long_lived {
                        ex.report(self.reporter.as_ref(), Phase::Opened);
                    }
                    // Flushed on the next turn: a 101 or long-poll head must
                    // not wait for another wake-up.
                    encode(&head).map(|bytes| ex.out_head = Some(bytes))
                }
                Ok(OutMsg::Frame(frame)) => {
                    encode(&frame).map(|bytes| ex.pending_bytes.push_back((bytes, ex.compress)))
                }
                Ok(OutMsg::End) | Err(TryRecvError::Disconnected) => {
                    ex.out_done = true;
                    Ok(())
                }
                Err(TryRecvError::Empty) => return,
            };
            if encoded.is_err() {
                self.inflight.remove(&id);
                return;
            }
            if ex.out_done && ex.pending_bytes.is_empty() && ex.out_head.is_none() {
                if !ex.fin_sent {
                    let _ = conn.finish(id);
                    ex.fin_sent = true;
                    let phase = if ex.long_lived {
                        Phase::Closed
                    } else {
                        Phase::Done
                    };
                    ex.report(self.reporter.as_ref(), phase);
                }
                // On an upgraded pipe the relay may still be forwarding
                // visitor bytes (its WebSocket Close reply, typically) that
                // must reach the origin: keep the exchange until the relay
                // FINs too. Other exchanges have `req_done` already.
                if ex.req_done {
                    self.inflight.remove(&id);
                }
                return;
            }
        }
    }
}

impl Exchange {
    fn report(&self, reporter: &dyn Reporter, phase: Phase) {
        let header = |name| {
            self.req
                .header(name)
                .and_then(|v| std::str::from_utf8(v).ok())
        };
        // The relay records the visitor's HTTP version in `Via`: `2 weaver`.
        let via = header("via").unwrap_or("");
        let proto = if header("upgrade").is_some() {
            "ws"
        } else if via.starts_with('2') {
            "h2"
        } else if via.starts_with('3') {
            "h3"
        } else {
            "h1"
        };
        reporter.request(&RequestEvent {
            at: self.started_at,
            service: &self.service,
            visitor: header("x-forwarded-for").unwrap_or(""),
            proto,
            method: &self.req.method,
            path: &self.req.path,
            status: self.status,
            bytes: self.bytes,
            elapsed: self.started.elapsed(),
            phase,
            request_headers: &self.req.headers,
            response_headers: &self.resp_headers,
        });
    }
}

/// An upgrade or a realtime (event stream) response.
fn is_long_lived(req: &HttpHead, head: &HttpResponseHead) -> bool {
    policy::response_class(req, head) == Some(weaver_mux::Class::Realtime)
        || req.header("upgrade").is_some()
}

impl StreamHandler for ProxyHandler {
    fn set_handle(&mut self, handle: Handle<ProxyHandler>) {
        self.handle = Some(handle);
    }

    fn on_event(&mut self, conn: &mut Connection, event: Event) {
        match event {
            Event::Authenticated { .. } => {
                self.reporter.tunnel_up(&self.host, &self.services);
                self.register_services(conn);
            }
            Event::Rejected { code, message } => {
                self.failure = Some(Error::Rejected {
                    host: self.host.clone(),
                    code,
                    message,
                });
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
            Event::Writable { id, .. } => self.pump_out(conn, id),
            Event::Finished(id) => {
                if let Some(ex) = self.inflight.get_mut(&id) {
                    ex.req_done = true;
                    // Dropping the sender ends the request body / pipe input.
                    ex.req_body_tx = None;
                    // Both directions finished (ours went first): tear down.
                    if ex.fin_sent {
                        self.inflight.remove(&id);
                    }
                }
            }
            Event::Reset { id, .. } => {
                self.inflight.remove(&id);
            }
            Event::StreamOpened { .. } | Event::Closed { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Silent;
    use crate::target::Target;

    #[test]
    fn the_service_is_read_from_the_hostname() {
        let handler = ProxyHandler::new(
            "relay.example".into(),
            vec![
                ServiceSpec::new("web", Target::parse("8080").unwrap()),
                ServiceSpec::new("my-api", Target::parse("9090").unwrap()),
            ],
            Arc::new(Silent),
        );
        let service = |authority| {
            handler
                .resolve_service(authority)
                .map(|s| s.service.as_str())
        };
        assert_eq!(service("ann-laptop-web.tunnel.example"), Some("web"));
        assert_eq!(
            service("Ann-Laptop-My-Api.tunnel.example:443"),
            Some("my-api")
        );
        assert_eq!(service("ann-laptop-docs.tunnel.example"), None);
        assert_eq!(service("tunnel.example"), None);
    }
}
