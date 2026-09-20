//! The origin-facing half of `weave start`: turns one visitor stream into one
//! outbound HTTP request and streams the reply back over the mux.
//!
//! The relay hands us `Head::Http` then [`BodyFrame`]s. We open (or reuse) a
//! connection to the service's target, send the request with a streaming
//! body, and push the origin's response back to the relay as an
//! [`HttpResponseHead`] followed by [`BodyFrame`]s. Nothing is buffered whole:
//! bodies flow chunk by chunk, and the bounded channels plus the mux's own
//! credit provide backpressure in both directions.
//!
//! Header policy lives here: `Host` rewriting (on by default), the
//! `Forwarded` / `X-Forwarded-*` stance, hop-by-hop stripping, and the
//! opt-out URL/cookie rewriting.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::{Method, Request, Uri};
use http_body_util::BodyExt;
use http_body_util::combinators::BoxBody;
use hyper::body::Frame;
use tokio::sync::mpsc;
use weaver_proto::http::{HttpHead, HttpResponseHead};
use weaver_proto::policy;
use weaver_proto::{BodyFrame, ResetCode};

use crate::pool::{OriginConn, Pool};
use crate::rewrite::rewrite_response_headers;
use crate::target::Target;

/// Boxed error used across the proxy boundary.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// Visitor/origin body type: chunks of bytes with an opaque error.
pub type Body = BoxBody<Bytes, BoxError>;

/// Hop-by-hop headers a proxy must not forward (RFC 9110 §7.6.1). The relay
/// strips these too; doing it again here is idempotent and keeps the client
/// correct on its own.
///
/// `Trailer` is deliberately *not* here: it is an end-to-end announcement
/// of which trailer fields follow the body (RFC 9110 §6.6.2), and the
/// trailers themselves are forwarded, so the announcement must be too.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "transfer-encoding",
    "upgrade",
];

/// A message the origin task sends to the mux loop for delivery to the relay.
pub enum OutMsg {
    /// A response head (interim or final).
    Head(HttpResponseHead),
    /// A body frame to forward verbatim.
    Frame(BodyFrame),
    /// The response is complete; FIN the stream.
    End,
}

/// Everything the origin task needs, cloned per exchange.
pub struct ExchangeConfig {
    /// The visitor request head as the relay sent it.
    pub head: HttpHead,
    /// The local origin behind this service.
    pub target: Target,
    /// Public origin the visitor used, e.g. `https://web.laptop.poc.example.com`.
    pub public_origin: String,
    /// Disable certificate verification for this target.
    pub insecure: bool,
    /// Keep the public hostname instead of rewriting `Host` to the target.
    pub preserve_host: bool,
    /// Disable URL/cookie rewriting.
    pub no_rewrite: bool,
    /// Keep visitor-supplied forwarding headers instead of replacing them
    /// with the canonical ones.
    pub append_forwarded: bool,
}

/// A streaming request body fed chunk by chunk from the mux.
pub struct ChannelBody {
    rx: mpsc::Receiver<Result<Frame<Bytes>, BoxError>>,
}

impl ChannelBody {
    /// Wrap the receiving end of the request-body channel.
    pub fn new(rx: mpsc::Receiver<Result<Frame<Bytes>, BoxError>>) -> Self {
        Self { rx }
    }
}

impl hyper::body::Body for ChannelBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.rx.poll_recv(cx)
    }
}

/// The outbound side of an exchange: the channel to the mux loop plus the
/// callback that wakes the loop after each deposit.
pub struct Outbox {
    tx: mpsc::Sender<OutMsg>,
    notify: Arc<dyn Fn() + Send + Sync>,
}

impl Outbox {
    /// Build an outbox from its channel and wake callback.
    pub fn new(tx: mpsc::Sender<OutMsg>, notify: Arc<dyn Fn() + Send + Sync>) -> Self {
        Self { tx, notify }
    }

    async fn send(&self, msg: OutMsg) -> bool {
        let ok = self.tx.send(msg).await.is_ok();
        (self.notify)();
        ok
    }
}

/// Run one exchange: build the request, send it to the origin, and push the
/// response back to the relay through `out`.
///
/// On failure before the response head the task answers a branded 502; on a
/// mid-body failure it asks the relay to reset the stream with a
/// [`ResetCode`].
pub async fn run_exchange(
    cfg: ExchangeConfig,
    body_rx: mpsc::Receiver<Result<Frame<Bytes>, BoxError>>,
    pool: Pool,
    out: Outbox,
    reset: Arc<dyn Fn(u32) + Send + Sync>,
) {
    match run_exchange_inner(&cfg, body_rx, &pool, &out).await {
        Ok(()) => {}
        Err(ExchangeError::BeforeHead) => {
            let html = weaver_assets::render_bad_gateway(&cfg.target.origin());
            let head = bad_gateway_head(html.len());
            let _ = out.send(OutMsg::Head(head)).await;
            let _ = out
                .send(OutMsg::Frame(BodyFrame::Chunk(html.into_bytes())))
                .await;
            let _ = out.send(OutMsg::End).await;
        }
        Err(ExchangeError::MidBody) => {
            reset(ResetCode::OriginClosed.as_u32());
        }
    }
}

enum ExchangeError {
    /// Failure before any response head: map to 502.
    BeforeHead,
    /// Failure after the head: truncate.
    MidBody,
}

async fn run_exchange_inner(
    cfg: &ExchangeConfig,
    mut body_rx: mpsc::Receiver<Result<Frame<Bytes>, BoxError>>,
    pool: &Pool,
    out: &Outbox,
) -> Result<(), ExchangeError> {
    let is_upgrade = cfg.head.header("upgrade").is_some();

    // For an upgrade the mux stream carries the visitor's raw bytes after
    // the 101, and those must go to the origin *socket*, not the hyper
    // request body. Bridge the mux channel into the request body until then;
    // once upgraded, the bridge stops and `body_rx` feeds the pipe directly.
    // Non-upgrade requests hand the receiver straight to hyper.
    let (hyper_body_rx, bridge) = if is_upgrade {
        let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, BoxError>>(1);
        // An upgrade request has no body; keep the sender alive until the
        // 101 arrives so hyper sees an open-but-empty body, then drop it.
        (rx, Some(tx))
    } else {
        let (tx, rx) = mpsc::channel(1);
        drop(tx);
        // Plain requests: swap so hyper owns the real receiver.
        (std::mem::replace(&mut body_rx, rx), None)
    };

    let mut conn = pool
        .acquire(&cfg.target, cfg.insecure)
        .await
        .map_err(|_| ExchangeError::BeforeHead)?;
    let h2 = matches!(conn, OriginConn::Http2(_));

    let request =
        build_request(cfg, hyper_body_rx, is_upgrade, h2).map_err(|_| ExchangeError::BeforeHead)?;

    let response = match &mut conn {
        OriginConn::Http1(send) => send.send_request(request).await,
        OriginConn::Http2(send) => send.send_request(request).await,
    };
    let mut response = match response {
        Ok(resp) => resp,
        Err(_) => return Err(ExchangeError::BeforeHead),
    };

    // Upgrade accepted by the origin: switch to a raw byte pipe.
    if is_upgrade && response.status() == http::StatusCode::SWITCHING_PROTOCOLS {
        drop(bridge);
        let on_upgrade = hyper::upgrade::on(&mut response);
        let (parts, _) = response.into_parts();
        let resp_head = HttpResponseHead {
            status: 101,
            headers: collect_headers(&parts.headers),
        };
        if !out.send(OutMsg::Head(resp_head)).await {
            return Err(ExchangeError::MidBody);
        }
        // hyper hands the raw socket over only once the `SendRequest` is
        // gone; the connection is consumed by the pipe and never pooled.
        drop(conn);
        let upgraded = on_upgrade.await.map_err(|_| ExchangeError::MidBody)?;
        pipe_upgraded(upgraded, body_rx, out).await;
        return Ok(());
    }
    drop(bridge);

    let (parts, mut incoming) = response.into_parts();
    let mut resp_head = HttpResponseHead {
        status: parts.status.as_u16(),
        headers: collect_headers(&parts.headers),
    };
    if !cfg.no_rewrite {
        rewrite_response_headers(&mut resp_head, &cfg.target, &cfg.public_origin);
    }
    if !out.send(OutMsg::Head(resp_head)).await {
        return Err(ExchangeError::MidBody);
    }

    loop {
        match incoming.frame().await {
            Some(Ok(frame)) => {
                if frame.is_data() {
                    let data = frame.into_data().unwrap_or_default();
                    if data.is_empty() {
                        continue;
                    }
                    if !out
                        .send(OutMsg::Frame(BodyFrame::Chunk(data.to_vec())))
                        .await
                    {
                        return Err(ExchangeError::MidBody);
                    }
                } else if let Ok(trailers) = frame.into_trailers() {
                    let fields = trailers
                        .iter()
                        .map(|(n, v)| (n.as_str().to_string(), v.as_bytes().to_vec()))
                        .collect();
                    if !out.send(OutMsg::Frame(BodyFrame::Trailers(fields))).await {
                        return Err(ExchangeError::MidBody);
                    }
                }
            }
            Some(Err(_)) => return Err(ExchangeError::MidBody),
            None => break,
        }
    }
    // The body was read to completion, so the connection is keep-alive
    // clean; return it for reuse. A truncated exchange drops it instead, as
    // does an origin that said `Connection: close` (HTTP/1.0 semantics).
    if origin_keeps_alive(&parts) {
        pool.release(&cfg.target, cfg.insecure, conn).await;
    }
    let _ = out.send(OutMsg::End).await;
    Ok(())
}

/// Whether the origin's response leaves the connection reusable: HTTP/1.1
/// unless it said `Connection: close`; HTTP/1.0 only with an explicit
/// `Connection: keep-alive`; h2 always.
fn origin_keeps_alive(parts: &http::response::Parts) -> bool {
    let tokens: Vec<String> = parts
        .headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .collect();
    match parts.version {
        http::Version::HTTP_10 => tokens.iter().any(|t| t == "keep-alive"),
        http::Version::HTTP_11 => !tokens.iter().any(|t| t == "close"),
        _ => true,
    }
}

/// After a `101`: copy visitor bytes (arriving as `BodyFrame::Chunk`s on the
/// mux) to the origin socket and origin bytes back as chunks, until either
/// side ends. WebSocket framing, subprotocols and permessage-deflate pass
/// through untouched — both hops are opaque byte pipes.
async fn pipe_upgraded(
    upgraded: hyper::upgrade::Upgraded,
    mut from_mux: mpsc::Receiver<Result<Frame<Bytes>, BoxError>>,
    out: &Outbox,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut rd, mut wr) = tokio::io::split(hyper_util::rt::TokioIo::new(upgraded));

    let to_origin = async move {
        while let Some(Ok(frame)) = from_mux.recv().await {
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
    let to_visitor = async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if !out
                        .send(OutMsg::Frame(BodyFrame::Chunk(buf[..n].to_vec())))
                        .await
                    {
                        break;
                    }
                }
            }
        }
        let _ = out.send(OutMsg::End).await;
    };
    tokio::join!(to_origin, to_visitor);
}

/// Build the outbound hyper request: method, absolute URI, policy-cleaned
/// headers, streaming body.
fn build_request(
    cfg: &ExchangeConfig,
    body_rx: mpsc::Receiver<Result<Frame<Bytes>, BoxError>>,
    is_upgrade: bool,
    h2: bool,
) -> Result<Request<Body>, BoxError> {
    let head = &cfg.head;
    let authority = cfg.target.authority();
    // h1 gets an origin-form target (`GET /path`), never absolute-form: a
    // reverse proxy talks to the origin as a plain client, and simple
    // servers treat `GET http://host/path` as a different resource. h2 has
    // no request line; hyper derives `:scheme` / `:authority` from an
    // absolute URI, so build one there.
    let uri: Uri = if h2 {
        format!(
            "{}://{}{}",
            cfg.target.scheme.as_str(),
            authority,
            head.path
        )
        .parse()
        .map_err(|e| format!("invalid request URI: {e}"))?
    } else {
        head.path
            .parse()
            .map_err(|e| format!("invalid request path: {e}"))?
    };
    let method =
        Method::from_bytes(head.method.as_bytes()).map_err(|e| format!("invalid method: {e}"))?;

    let mut builder = Request::builder().method(method).uri(uri);
    {
        let headers = builder.headers_mut().ok_or("request builder rejected")?;
        // Start from the visitor's headers as the relay forwarded them, then
        // apply the origin-facing policy on top.
        for (name, value) in &head.headers {
            if let (Ok(n), Ok(v)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_bytes(value),
            ) {
                headers.append(n, v);
            }
        }
        apply_origin_headers(headers, cfg, is_upgrade)?;
    }
    // An upgrade request carries no body; sending the streaming body would
    // make hyper emit `Transfer-Encoding: chunked`, which origins reject on
    // an upgrade. Use an empty, sized body instead.
    let body = if is_upgrade {
        drop(body_rx);
        http_body_util::Empty::<Bytes>::new()
            .map_err(|never| match never {})
            .boxed()
    } else {
        ChannelBody::new(body_rx).boxed()
    };
    Ok(builder.body(body)?)
}

/// Header policy for the origin-facing request. For an upgrade the
/// `Connection: upgrade` / `Upgrade:` pair is reconstructed after the
/// hop-by-hop strip, since the origin must see the upgrade request.
fn apply_origin_headers(
    headers: &mut http::HeaderMap,
    cfg: &ExchangeConfig,
    is_upgrade: bool,
) -> Result<(), BoxError> {
    // Strip hop-by-hop headers and any header named by a `Connection` token.
    let mut connection_tokens: Vec<String> = Vec::new();
    for value in headers.get_all(http::header::CONNECTION).iter() {
        if let Ok(s) = value.to_str() {
            for token in s.split(',') {
                let t = token.trim().to_ascii_lowercase();
                if !t.is_empty() {
                    connection_tokens.push(t);
                }
            }
        }
    }

    let inbound = collect_forwarding(headers);
    let public_host = cfg.head.authority.clone();
    let upgrade_protocol = if is_upgrade {
        headers.get(http::header::UPGRADE).cloned()
    } else {
        None
    };

    let mut rebuilt: Vec<(HeaderName, HeaderValue)> = Vec::with_capacity(headers.len() + 4);
    for (name, value) in headers.iter() {
        let lname = name.as_str().to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lname.as_str()) || connection_tokens.contains(&lname) {
            continue;
        }
        if lname == "host" {
            continue;
        }
        if !cfg.append_forwarded && is_forwarding_header(&lname) {
            continue;
        }
        rebuilt.push((name.clone(), value.clone()));
    }
    headers.clear();
    for (n, v) in rebuilt {
        headers.append(n, v);
    }
    if let Some(protocol) = upgrade_protocol {
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("upgrade"),
        );
        headers.insert(http::header::UPGRADE, protocol);
    } else {
        // RFC 9110 §10.1.4: `TE: trailers` is how the *next hop* learns it may
        // send trailer fields. The visitor's own `TE` is hop-by-hop and was
        // stripped above; we forward trailers over the mux, so we announce
        // acceptance ourselves — otherwise a well-behaved h1 origin silently
        // drops them.
        headers.insert(http::header::TE, HeaderValue::from_static("trailers"));
    }

    let host_value = if cfg.preserve_host {
        public_host.clone()
    } else {
        cfg.target.authority()
    };
    if let Ok(v) = HeaderValue::from_str(&host_value) {
        headers.insert(http::header::HOST, v);
    }

    if cfg.append_forwarded {
        for (name, values) in inbound.values.iter() {
            for value in values {
                if let (Ok(n), Ok(v)) = (
                    HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_bytes(value),
                ) {
                    headers.append(n, v);
                }
            }
        }
    } else {
        // Set/replace: drop every inbound copy and write the canonical trio,
        // taking the relay's last (trustworthy) value for the visitor IP.
        let for_value = inbound
            .values
            .get("x-forwarded-for")
            .and_then(|v| v.last())
            .cloned();
        match &for_value {
            Some(ip) => insert_bytes(headers, "x-forwarded-for", ip),
            None => insert_bytes(headers, "x-forwarded-for", b"unknown"),
        }
        insert_bytes(headers, "x-forwarded-proto", b"https");
        insert_bytes(headers, "x-forwarded-host", public_host.as_bytes());
        // RFC 7239 `Forwarded`, alongside the X-Forwarded-* trio.
        let forwarded = format!(
            "for=\"{}\";proto=https;host=\"{}\"",
            for_value
                .as_ref()
                .map(|b| String::from_utf8_lossy(b).to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            public_host
        );
        insert_bytes(headers, "forwarded", forwarded.as_bytes());
    }
    Ok(())
}

fn insert_bytes(headers: &mut http::HeaderMap, name: &str, value: &[u8]) {
    if let (Ok(n), Ok(v)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_bytes(value),
    ) {
        headers.insert(n, v);
    }
}

fn is_forwarding_header(lname: &str) -> bool {
    lname == "forwarded" || lname.starts_with("x-forwarded-")
}

/// Snapshot of the inbound forwarding values, in order.
#[derive(Default)]
struct Forwarding {
    values: HashMap<String, Vec<Vec<u8>>>,
}

fn collect_forwarding(headers: &http::HeaderMap) -> Forwarding {
    let mut out = Forwarding::default();
    for name in [
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-host",
        "forwarded",
    ] {
        let values: Vec<Vec<u8>> = headers
            .get_all(name)
            .iter()
            .map(|v| v.as_bytes().to_vec())
            .collect();
        if !values.is_empty() {
            out.values.insert(name.to_string(), values);
        }
    }
    out
}

fn collect_headers(headers: &http::HeaderMap) -> Vec<(String, Vec<u8>)> {
    headers
        .iter()
        .map(|(n, v)| (n.as_str().to_string(), v.as_bytes().to_vec()))
        .collect()
}

/// The branded 502 head used when the origin cannot be reached.
fn bad_gateway_head(len: usize) -> HttpResponseHead {
    HttpResponseHead {
        status: 502,
        headers: vec![
            (
                "content-type".to_string(),
                b"text/html; charset=utf-8".to_vec(),
            ),
            (
                "content-security-policy".to_string(),
                b"default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'".to_vec(),
            ),
            ("x-content-type-options".to_string(), b"nosniff".to_vec()),
            ("content-length".to_string(), len.to_string().into_bytes()),
        ],
    }
}

/// Compression stance for a response body chunk given the request and head.
pub fn body_compress(req: &HttpHead, resp: &HttpResponseHead) -> weaver_mux::Compress {
    policy::response_body_compress(req, resp)
}
