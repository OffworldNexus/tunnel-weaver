//! Implementation of the `weave poc` command: register one service and
//! answer every proxied request with a fixed redirect.

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use weaver_mux::error::{CloseCode, GoAway, RejectCode};
use weaver_mux::{Config, Connection, Event, StreamError, StreamId};
use weaver_proto::control::{ControlHead, ControlReply};
use weaver_proto::http::{HttpHead, HttpResponseHead};
use weaver_proto::{Head, policy};
use weaver_tokio::{Driver, DriverError, StreamHandler, SystemRng, WsTransport};

use crate::connect::{connect_tls, parse_server_address};
use crate::identity::Ed25519Signer;

/// Sec-WebSocket-Protocol token both ends must agree on.
pub const WS_SUBPROTOCOL: &str = "weaver-mux-v1";

/// Executes the `weave poc` client flow.
pub async fn run_poc(
    service: String,
    server: String,
    insecure_root_ca: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            cancel_clone.cancel();
        }
    });
    run_poc_with_token(service, server, insecure_root_ca, cancel).await
}

/// Executes the `weave poc` client flow with an explicit cancellation token.
pub async fn run_poc_with_token(
    service: String,
    server: String,
    insecure_root_ca: Option<&Path>,
    shutdown_token: tokio_util::sync::CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (host, port) = parse_server_address(&server)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    let tls_stream = connect_tls(&host, port, insecure_root_ca).await?;

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
    let handler = PocHandler {
        service,
        control: None,
        inflight: HashMap::new(),
        failure: None,
        shutting_down: false,
    };
    let driver = Driver::new(conn, WsTransport::new(ws_stream), handler);
    let handle = driver.handle();

    // Ctrl-C / test shutdown: FIN the control stream, GOAWAY, and let the
    // driver flush and return.
    tokio::spawn(async move {
        shutdown_token.cancelled().await;
        handle.spawn_on(|conn, h: &mut PocHandler| {
            if let Some(id) = h.control {
                let _ = conn.finish(id);
            }
            h.shutting_down = true;
            conn.close(GoAway::new(CloseCode::Shutdown));
        });
    });

    let (handler, result) = driver.run().await;
    if let Some(err) = handler.failure {
        return Err(err.into());
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

struct PocHandler {
    service: String,
    control: Option<StreamId>,
    inflight: HashMap<StreamId, InflightHttp>,
    /// A fatal application-level condition to report after the driver ends.
    failure: Option<String>,
    shutting_down: bool,
}

struct InflightHttp {
    head: Option<HttpHead>,
    body: Vec<u8>,
}

impl StreamHandler for PocHandler {
    fn on_event(&mut self, conn: &mut Connection, event: Event) {
        match event {
            Event::Authenticated { .. } => {
                let head = Head::Control(ControlHead::Register {
                    proto_version: weaver_proto::PROTOCOL_VERSION,
                    service: self.service.clone(),
                });
                let res = weaver_proto::encode(&head)
                    .map_err(|e| format!("Failed to encode registration head: {e}"))
                    .and_then(|bytes| {
                        let id = conn
                            .open(policy::CONTROL_POLICY)
                            .map_err(|e| format!("Failed to open registration stream: {e}"))?;
                        conn.send(id, &bytes, policy::CONTROL_COMPRESS)
                            .map_err(|e| format!("Failed to send registration: {e}"))?;
                        Ok(id)
                    });
                match res {
                    Ok(id) => self.control = Some(id),
                    Err(msg) => self.fail(conn, msg),
                }
            }
            Event::Rejected { code, message } => {
                self.failure = Some(if matches!(code, RejectCode::UnsupportedVersion { .. }) {
                    format!("Error: Protocol version mismatch: {message}")
                } else {
                    format!("Error: Connection rejected: {message} ({code:?})")
                });
            }
            Event::StreamOpened { id, .. } => {
                self.inflight.insert(
                    id,
                    InflightHttp {
                        head: None,
                        body: Vec::new(),
                    },
                );
            }
            Event::Readable(id) => {
                while let Ok(msg) = conn.recv_msg(id) {
                    if Some(id) == self.control {
                        self.on_control_reply(conn, &msg);
                    } else if let Some(req) = self.inflight.get_mut(&id) {
                        if req.head.is_none() {
                            match weaver_proto::decode::<Head>(&msg) {
                                Ok(Head::Http(h)) => req.head = Some(h),
                                _ => {
                                    self.inflight.remove(&id);
                                    let _ = conn.reset(id, 0);
                                    break;
                                }
                            }
                        } else {
                            req.body.extend_from_slice(&msg);
                        }
                    }
                }
            }
            Event::Finished(id) => {
                if let Some(req) = self.inflight.remove(&id) {
                    if let Some(head) = &req.head {
                        dump_request_http1_wire(head, &req.body);
                        self.respond(conn, id, head);
                    } else {
                        let _ = conn.reset(id, 0);
                    }
                }
            }
            Event::Reset { id, .. } => {
                self.inflight.remove(&id);
            }
            Event::Writable(_) | Event::Closed { .. } => {}
        }
    }
}

impl PocHandler {
    fn fail(&mut self, conn: &mut Connection, msg: String) {
        self.failure = Some(msg);
        conn.close(GoAway::new(CloseCode::Shutdown));
    }

    fn on_control_reply(&mut self, conn: &mut Connection, msg: &[u8]) {
        match weaver_proto::decode::<ControlReply>(msg) {
            Ok(ControlReply::Registered { hostname }) => {
                println!("https://{hostname}/");
            }
            Ok(ControlReply::Refused { code, message }) => {
                self.fail(conn, format!("Registration refused: {message} ({code:?})"));
            }
            Err(e) => self.fail(conn, format!("Bad control reply: {e}")),
        }
    }

    /// Answer every request with a redirect: head first (never
    /// compressed), no body, FIN.
    fn respond(&mut self, conn: &mut Connection, id: StreamId, req: &HttpHead) {
        let resp = HttpResponseHead {
            status: 302,
            headers: vec![
                (
                    "location".to_string(),
                    b"https://www.youtube.com/watch?v=dQw4w9WgXcQ".to_vec(),
                ),
                ("content-length".to_string(), b"0".to_vec()),
            ],
        };
        let _ = policy::response_body_compress(req, &resp); // no body to send
        match weaver_proto::encode(&resp) {
            Ok(bytes) => match conn.send(id, &bytes, policy::HEAD_COMPRESS) {
                Ok(()) | Err(StreamError::UnknownStream) => {}
                Err(e) => eprintln!("failed to send response head: {e}"),
            },
            Err(e) => eprintln!("failed to encode response head: {e}"),
        }
        let _ = conn.finish(id);
    }
}

fn dump_request_http1_wire(head: &HttpHead, body: &[u8]) {
    println!("{} {} HTTP/1.1", head.method, head.path);
    for (name, val) in &head.headers {
        let val_str = String::from_utf8_lossy(val);
        println!("{name}: {val_str}");
    }
    println!();
    println!("[Body: {} bytes]", body.len());
    if !body.is_empty()
        && let Ok(text) = std::str::from_utf8(body)
    {
        let preview = if text.len() > 1024 {
            &text[..1024]
        } else {
            text
        };
        println!("{preview}");
    }
}
