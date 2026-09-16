//! Implementation of the `weave poc` command.

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::Path;
use std::time::Instant;

use bytes::Bytes;
use ed25519_dalek::Signer as DalekSigner;
use futures_util::{SinkExt, StreamExt};
use rand_core::TryRng;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use weaver_mux::error::{CloseCode, GoAway, RejectCode};
use weaver_mux::{Config, Connection, Event, KeyId, SignError, StreamId};
use weaver_proto::control::{ControlHead, ControlReply};
use weaver_proto::framing::{decode_length_prefixed, encode_length_prefixed};
use weaver_proto::http::HttpResponseHead;
use weaver_proto::poc::{POC_KEY_ID, POC_SECRET_KEY};

use crate::connect::{connect_tls, parse_server_address};

struct PocSigner {
    key: ed25519_dalek::SigningKey,
}

impl weaver_mux::auth::Signer for PocSigner {
    fn key_id(&self) -> KeyId {
        POC_KEY_ID
    }

    fn sign(&mut self, msg: &[u8]) -> Result<weaver_mux::wire::Signature, SignError> {
        let sig: ed25519_dalek::Signature = self.key.sign(msg);
        Ok(weaver_mux::wire::Signature::Ed25519(sig.to_bytes()))
    }
}

struct SystemRng;

impl TryRng for SystemRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        let _ = self.try_fill_bytes(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        let _ = self.try_fill_bytes(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        use rand::Rng;
        rand::rng().fill(dst);
        Ok(())
    }
}

struct InflightHttp {
    head: weaver_proto::HttpHead,
    body: Vec<u8>,
}

fn dump_request_http1_wire(head: &weaver_proto::HttpHead, body: &[u8]) {
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
        .header("Sec-WebSocket-Protocol", "weaver-mux-v1")
        .body(())?;

    let (ws_stream, _): (WebSocketStream<TlsStream<tokio::net::TcpStream>>, _) =
        tokio_tungstenite::client_async_with_config(req, tls_stream, None).await?;
    let (mut ws_write, mut ws_read) = ws_stream.split();

    let signer = Box::new(PocSigner {
        key: ed25519_dalek::SigningKey::from_bytes(&POC_SECRET_KEY),
    });
    let rng = Box::new(SystemRng);
    let cfg = Config::client(signer, host.clone(), rng);
    let mut conn = Connection::new(cfg, Instant::now());

    let mut control_stream_id: Option<StreamId> = None;
    let mut control_read_buf = Vec::new();
    let mut inflight_http: HashMap<StreamId, InflightHttp> = HashMap::new();
    let mut transmit_buf = Vec::with_capacity(64 * 1024);

    loop {
        let now = Instant::now();
        let timeout_at = conn
            .next_timeout()
            .unwrap_or_else(|| now + std::time::Duration::from_secs(60));
        let sleep_duration = timeout_at.saturating_duration_since(now);

        tokio::select! {
            _ = shutdown_token.cancelled() => {
                if let Some(id) = control_stream_id {
                    let _ = conn.finish(id);
                }
                conn.close(GoAway::new(CloseCode::Shutdown));
                let now = Instant::now();
                while conn.poll_transmit(now, &mut transmit_buf) {
                    let msg = Message::Binary(Bytes::from(std::mem::take(&mut transmit_buf)));
                    let _ = ws_write.send(msg).await;
                }
                return Ok(());
            }
            _ = tokio::time::sleep(sleep_duration) => {
                conn.handle_timeout(Instant::now());
            }
            ws_msg = ws_read.next() => {
                match ws_msg {
                    Some(Ok(Message::Binary(bytes))) => {
                        let now = Instant::now();
                        if let Err(err) = conn.recv(now, &bytes) {
                            return Err(format!("Mux protocol error: {err}").into());
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        return Err("Connection closed by relay".into());
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        let _ = ws_write.send(Message::Pong(payload)).await;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(err)) => {
                        return Err(format!("WebSocket read error: {err}").into());
                    }
                }
            }
        }

        while let Some(ev) = conn.poll_event() {
            match ev {
                Event::Authenticated { .. } => {
                    let reg_head = weaver_proto::Head::Control(ControlHead::Register {
                        service: service.clone(),
                    });
                    match reg_head.to_mux_head() {
                        Ok(mux_head) => match conn.open(mux_head) {
                            Ok(id) => {
                                control_stream_id = Some(id);
                            }
                            Err(err) => {
                                return Err(
                                    format!("Failed to open registration stream: {err}").into()
                                );
                            }
                        },
                        Err(err) => {
                            return Err(format!("Failed to encode registration head: {err}").into());
                        }
                    }
                }
                Event::Rejected { code, message } => {
                    if matches!(code, RejectCode::UnsupportedVersion { .. }) {
                        return Err(format!("Error: Protocol version mismatch: {message}").into());
                    } else {
                        return Err(
                            format!("Error: Connection rejected: {message} ({code:?})").into()
                        );
                    }
                }
                Event::StreamOpened { id, head } => {
                    if let Ok(weaver_proto::Head::Http(http_head)) =
                        weaver_proto::Head::from_mux_head(&head)
                    {
                        inflight_http.insert(
                            id,
                            InflightHttp {
                                head: http_head,
                                body: Vec::new(),
                            },
                        );
                    } else {
                        let _ = conn.reset(id, 0);
                    }
                }
                Event::Readable(id) => {
                    if Some(id) == control_stream_id {
                        let mut buf = [0u8; 1024];
                        while let Ok(n) = conn.read(id, &mut buf) {
                            if n == 0 {
                                break;
                            }
                            control_read_buf.extend_from_slice(&buf[..n]);
                            if let Ok(Some((reply, _))) =
                                decode_length_prefixed::<ControlReply>(&control_read_buf)
                            {
                                match reply {
                                    ControlReply::Registered { hostname } => {
                                        println!("https://{hostname}/");
                                    }
                                    ControlReply::Refused { code, message } => {
                                        return Err(format!(
                                            "Registration refused: {message} ({code:?})"
                                        )
                                        .into());
                                    }
                                }
                            }
                        }
                    } else if let Some(req) = inflight_http.get_mut(&id) {
                        let mut buf = [0u8; 8192];
                        while let Ok(n) = conn.read(id, &mut buf) {
                            if n == 0 {
                                break;
                            }
                            req.body.extend_from_slice(&buf[..n]);
                        }
                    }
                }
                Event::Finished(id) => {
                    if let Some(req) = inflight_http.remove(&id) {
                        dump_request_http1_wire(&req.head, &req.body);

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
                        if let Ok(encoded) = encode_length_prefixed(&resp) {
                            let _ = conn.write(id, &encoded);
                        }
                        let _ = conn.finish(id);
                    }
                }
                Event::Reset { id, .. } => {
                    inflight_http.remove(&id);
                }
                Event::Closed { reason } => {
                    return Err(format!("Connection closed by server: {:?}", reason.code).into());
                }
                _ => {}
            }
        }

        let now = Instant::now();
        while conn.poll_transmit(now, &mut transmit_buf) {
            let msg = Message::Binary(Bytes::from(std::mem::take(&mut transmit_buf)));
            ws_write.send(msg).await?;
        }

        if conn.is_closed() {
            break;
        }
    }

    Ok(())
}
