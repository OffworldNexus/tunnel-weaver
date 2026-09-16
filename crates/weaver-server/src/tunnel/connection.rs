//! Async task driving a single client multiplexer connection over an upgraded WebSocket.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::{HeaderName, HeaderValue, Response, StatusCode};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, trace};
use weaver_mux::auth::PublicKey;
use weaver_mux::error::{CloseCode, GoAway};
use weaver_mux::{Config, Connection, Event, KeyId, StreamId};
use weaver_proto::control::{ControlHead, ControlReply, RefusalCode};
use weaver_proto::framing::{decode_length_prefixed, encode_length_prefixed};
use weaver_proto::http::HttpResponseHead;
use weaver_proto::poc::{POC_KEY_ID, POC_PUBLIC_KEY};

use crate::tunnel::proxy::{BoxBody, ProxyError, ProxyRequest, TunnelResponseBody};
use crate::tunnel::registry::TunnelRegistry;

/// Verifier authenticating incoming connections against the hard-coded PoC key.
pub struct PocVerifier;

impl weaver_mux::auth::Verifier for PocVerifier {
    fn public_key(&mut self, key_id: &KeyId) -> Option<PublicKey> {
        if key_id == &POC_KEY_ID {
            Some(PublicKey::Ed25519(POC_PUBLIC_KEY))
        } else {
            None
        }
    }
}

enum BodyChunkMsg {
    Data(StreamId, Bytes),
    Fin(StreamId),
    Error(StreamId),
}

struct InflightExchange {
    response_tx: Option<oneshot::Sender<Result<Response<BoxBody>, ProxyError>>>,
    body_tx: Option<mpsc::Sender<Result<Bytes, Box<dyn std::error::Error + Send + Sync>>>>,
    read_buf: Vec<u8>,
    head_parsed: bool,
    pending_request_body: Vec<Bytes>,
}

/// Spawns a background task driving the multiplexer over the upgraded WebSocket stream.
pub fn spawn_tunnel_connection(
    ws_stream: WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>,
    registry: Arc<TunnelRegistry>,
    root_domain: String,
) {
    tokio::spawn(async move {
        if let Err(err) = run_tunnel_connection(ws_stream, registry, root_domain).await {
            debug!(error = %err, "Tunnel connection finished with error");
        }
    });
}

use rand_core::TryRng;
use std::convert::Infallible;

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

async fn run_tunnel_connection(
    ws_stream: WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>,
    registry: Arc<TunnelRegistry>,
    root_domain: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let verifier = Box::new(PocVerifier);
    let rng = Box::new(SystemRng);
    let cfg = Config::server(verifier, root_domain.clone(), rng);
    let mut conn = Connection::new(cfg, Instant::now());

    let (mut ws_write, mut ws_read) = ws_stream.split();
    let (proxy_tx, mut proxy_rx) = mpsc::channel::<ProxyRequest>(64);
    let mut superseded_rx: Option<oneshot::Receiver<()>> = None;
    let (chunk_tx, mut chunk_rx) = mpsc::channel::<BodyChunkMsg>(64);

    let mut conn_id: Option<u64> = None;
    let mut authenticated_key: Option<KeyId> = None;
    let mut active_control_streams: HashSet<StreamId> = HashSet::new();
    let mut inflight: HashMap<StreamId, InflightExchange> = HashMap::new();
    let mut transmit_buf = Vec::with_capacity(64 * 1024);

    // Initial transmit (sends CHALLENGE)
    let now = Instant::now();
    while conn.poll_transmit(now, &mut transmit_buf) {
        let msg = Message::Binary(Bytes::from(std::mem::take(&mut transmit_buf)));
        ws_write.send(msg).await?;
    }

    loop {
        let now = Instant::now();
        let timeout_at = conn
            .next_timeout()
            .unwrap_or_else(|| now + std::time::Duration::from_secs(60));
        let sleep_duration = timeout_at.saturating_duration_since(now);

        tokio::select! {
            _ = async {
                if let Some(ref mut rx) = superseded_rx {
                    let _ = rx.await;
                } else {
                    futures_util::future::pending::<()>().await;
                }
            } => {
                info!(key_id = ?authenticated_key, "Tunnel connection superseded, closing");
                conn.close(GoAway::new(CloseCode::Superseded));
                let now = Instant::now();
                while conn.poll_transmit(now, &mut transmit_buf) {
                    let msg = Message::Binary(Bytes::from(std::mem::take(&mut transmit_buf)));
                    let _ = ws_write.send(msg).await;
                }
                break;
            }
            _ = tokio::time::sleep(sleep_duration) => {
                conn.handle_timeout(Instant::now());
            }
            ws_msg = ws_read.next() => {
                match ws_msg {
                    Some(Ok(Message::Binary(bytes))) => {
                        let now = Instant::now();
                        if let Err(err) = conn.recv(now, &bytes) {
                            debug!(error = %err, "Protocol error on mux recv");
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        info!("WebSocket stream closed by client");
                        break;
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        let _ = ws_write.send(Message::Pong(payload)).await;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(err)) => {
                        debug!(error = %err, "WebSocket read error");
                        break;
                    }
                }
            }
            req_opt = proxy_rx.recv() => {
                if let Some(req) = req_opt {
                    let head = weaver_proto::Head::Http(req.head);
                    match head.to_mux_head() {
                        Ok(mux_head) => {
                            match conn.open(mux_head) {
                                Ok(stream_id) => {
                                    inflight.insert(
                                        stream_id,
                                        InflightExchange {
                                            response_tx: Some(req.response_tx),
                                            body_tx: None,
                                            read_buf: Vec::new(),
                                            head_parsed: false,
                                            pending_request_body: Vec::new(),
                                        },
                                    );

                                    // Stream visitor request body in background task to chunk_tx
                                    let c_tx = chunk_tx.clone();
                                    tokio::spawn(async move {
                                        let mut body = req.body;
                                        while let Some(frame_res) = body.frame().await {
                                            match frame_res {
                                                Ok(frame) => {
                                                    if let Ok(data) = frame.into_data()
                                                        && !data.is_empty()
                                                        && c_tx
                                                            .send(BodyChunkMsg::Data(stream_id, data))
                                                            .await
                                                            .is_err()
                                                    {
                                                        return;
                                                    }
                                                }
                                                Err(_) => {
                                                    let _ = c_tx.send(BodyChunkMsg::Error(stream_id)).await;
                                                    return;
                                                }
                                            }
                                        }
                                        let _ = c_tx.send(BodyChunkMsg::Fin(stream_id)).await;
                                    });
                                }
                                Err(err) => {
                                    debug!(error = %err, "Failed to open mux stream for proxy request");
                                    let _ = req.response_tx.send(Err(ProxyError::Mux(err.to_string())));
                                }
                            }
                        }
                        Err(err) => {
                            let _ = req.response_tx.send(Err(ProxyError::Codec(err.to_string())));
                        }
                    }
                }
            }
            chunk_opt = chunk_rx.recv() => {
                match chunk_opt {
                    Some(BodyChunkMsg::Data(id, data)) => {
                        if let Some(ex) = inflight.get_mut(&id) {
                            match conn.write(id, &data) {
                                Ok(n) if n == data.len() => {}
                                Ok(n) => {
                                    ex.pending_request_body.push(data.slice(n..));
                                }
                                Err(err) => {
                                    debug!(%id, error = %err, "Error writing body data to stream");
                                }
                            }
                        }
                    }
                    Some(BodyChunkMsg::Fin(id)) => {
                        if let Some(ex) = inflight.get_mut(&id)
                            && ex.pending_request_body.is_empty()
                        {
                            let _ = conn.finish(id);
                        }
                    }
                    Some(BodyChunkMsg::Error(id)) => {
                        let _ = conn.reset(id, 0);
                        inflight.remove(&id);
                    }
                    None => {}
                }
            }
        }

        // Process all queued events
        while let Some(ev) = conn.poll_event() {
            match ev {
                Event::Authenticated { key_id, version } => {
                    info!(?key_id, version, "Tunnel connection authenticated");
                    authenticated_key = Some(key_id);
                    let (s_tx, s_rx) = oneshot::channel();
                    superseded_rx = Some(s_rx);
                    conn_id = Some(registry.register_connection(key_id, s_tx));
                }
                Event::StreamOpened { id, head } => {
                    trace!(%id, "Peer opened stream");
                    match weaver_proto::Head::from_mux_head(&head) {
                        Ok(weaver_proto::Head::Control(ControlHead::Register { service })) => {
                            if let (Some(k), Some(c)) = (authenticated_key, conn_id) {
                                let reg_res = registry
                                    .register_service(k, c, &service, proxy_tx.clone())
                                    .await;
                                let reply = match reg_res {
                                    Ok(hostname) => {
                                        active_control_streams.insert(id);
                                        ControlReply::Registered { hostname }
                                    }
                                    Err(code) => {
                                        let msg = match code {
                                            RefusalCode::AlreadyRegistered => {
                                                format!("Service '{service}' is already registered")
                                            }
                                            RefusalCode::InvalidName => {
                                                format!(
                                                    "Service '{service}' is not a valid DNS label"
                                                )
                                            }
                                            RefusalCode::Unauthorized => {
                                                "Unauthorized client identity".to_string()
                                            }
                                            RefusalCode::Other(ref s) => s.clone(),
                                        };
                                        ControlReply::Refused { code, message: msg }
                                    }
                                };

                                if let Ok(encoded) = encode_length_prefixed(&reply) {
                                    let _ = conn.write(id, &encoded);
                                }
                                if matches!(reply, ControlReply::Refused { .. }) {
                                    let _ = conn.finish(id);
                                }
                            }
                        }
                        _ => {
                            // Unexpected stream type from client
                            let _ = conn.reset(id, 0);
                        }
                    }
                }
                Event::Readable(id) => {
                    let mut read_buf = [0u8; 8192];
                    while let Ok(n) = conn.read(id, &mut read_buf) {
                        if n == 0 {
                            break;
                        }
                        if let Some(ex) = inflight.get_mut(&id) {
                            if !ex.head_parsed {
                                ex.read_buf.extend_from_slice(&read_buf[..n]);
                                if let Ok(Some((head, consumed))) =
                                    decode_length_prefixed::<HttpResponseHead>(&ex.read_buf)
                                {
                                    ex.head_parsed = true;
                                    let leftover = ex.read_buf[consumed..].to_vec();
                                    ex.read_buf.clear();

                                    let mut builder = Response::builder().status(
                                        StatusCode::from_u16(head.status)
                                            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                                    );

                                    for (name, val) in head.headers {
                                        if let (Ok(h_name), Ok(h_val)) = (
                                            HeaderName::from_bytes(name.as_bytes()),
                                            HeaderValue::from_bytes(&val),
                                        ) {
                                            builder = builder.header(h_name, h_val);
                                        }
                                    }

                                    let (body_tx, body_rx) = mpsc::channel(16);
                                    let body = TunnelResponseBody::boxed(body_rx);
                                    let response = builder.body(body).unwrap();

                                    if let Some(tx) = ex.response_tx.take() {
                                        let _ = tx.send(Ok(response));
                                    }

                                    ex.body_tx = Some(body_tx.clone());
                                    if !leftover.is_empty() {
                                        let _ = body_tx.try_send(Ok(Bytes::from(leftover)));
                                    }
                                }
                            } else if let Some(ref body_tx) = ex.body_tx {
                                let bytes = Bytes::copy_from_slice(&read_buf[..n]);
                                let _ = body_tx.try_send(Ok(bytes));
                            }
                        }
                    }
                }
                Event::Writable(id) => {
                    if let Some(ex) = inflight.get_mut(&id) {
                        while !ex.pending_request_body.is_empty() {
                            let next_chunk = &ex.pending_request_body[0];
                            match conn.write(id, next_chunk) {
                                Ok(n) if n == next_chunk.len() => {
                                    ex.pending_request_body.remove(0);
                                }
                                Ok(n) => {
                                    let rem = next_chunk.slice(n..);
                                    ex.pending_request_body[0] = rem;
                                    break;
                                }
                                Err(_) => break,
                            }
                        }
                    }
                }
                Event::Finished(id) => {
                    if active_control_streams.remove(&id) {
                        info!(%id, "Control registration stream closed by client");
                    }
                    if let Some(ex) = inflight.remove(&id) {
                        drop(ex.body_tx);
                    }
                }
                Event::Reset { id, code } => {
                    trace!(%id, code, "Stream reset");
                    if active_control_streams.remove(&id) {
                        info!(%id, "Control registration stream reset");
                    }
                    if let Some(mut ex) = inflight.remove(&id)
                        && let Some(tx) = ex.response_tx.take()
                    {
                        let _ = tx.send(Err(ProxyError::Reset));
                    }
                }
                Event::Closed { reason } => {
                    info!(?reason, "Tunnel connection closed");
                    break;
                }
                _ => {}
            }
        }

        // Flush all pending frames to WebSocket sink (strictly unbuffered)
        let now = Instant::now();
        while conn.poll_transmit(now, &mut transmit_buf) {
            let msg = Message::Binary(Bytes::from(std::mem::take(&mut transmit_buf)));
            ws_write.send(msg).await?;
        }

        if conn.is_closed() {
            break;
        }
    }

    if let (Some(k), Some(c)) = (authenticated_key, conn_id) {
        registry.unregister_connection(k, c);
    }

    Ok(())
}
