//! Reverse-proxy dispatch for forwarding incoming visitor requests over tunnel streams.

use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::{Frame, Incoming};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use weaver_proto::HttpHead;

use crate::tunnel::registry::TunnelRoute;

/// Visitor-facing response body type (boxed so static error pages and streaming bodies unify).
pub type BoxBody =
    http_body_util::combinators::BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// One item streamed from the tunnel client: a body frame or a failure.
pub type BodyFrameItem =
    Result<hyper::body::Frame<Bytes>, Box<dyn std::error::Error + Send + Sync>>;

/// Helper to wrap full bytes into a BoxBody.
pub fn full_body(bytes: impl Into<Bytes>) -> BoxBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

/// Helper to produce an empty BoxBody.
pub fn empty_body() -> BoxBody {
    full_body(Bytes::new())
}

/// Errors occurring on the proxy path between edge and tunnel.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// The service's local origin refused the connection or never answered
    /// before the response head (mapped to 502).
    #[error("origin unreachable")]
    OriginUnreachable,
    /// Tunnel stream was reset before completing the exchange.
    #[error("tunnel stream reset")]
    Reset,
    /// Tunnel connection dropped or terminated prematurely.
    #[error("tunnel connection terminated")]
    ConnectionClosed,
    /// Error encoding or decoding stream protocol messages.
    #[error("protocol codec error: {0}")]
    Codec(String),
    /// Multiplexer stream or connection error.
    #[error("multiplexer error: {0}")]
    Mux(String),
}

/// Request dispatched from the HTTPS edge to the tunnel connection driver.
pub struct ProxyRequest {
    /// HTTP request metadata and headers forwarded across the stream.
    pub head: HttpHead,
    /// Stream of incoming visitor request body bytes.
    pub body: Incoming,
    /// Return channel for the visitor-facing response once headers arrive from the tunnel.
    pub response_tx: oneshot::Sender<Result<Response<BoxBody>, ProxyError>>,
    /// Present when the visitor asked to upgrade the connection (h1
    /// `Upgrade` or an RFC 8441 extended `CONNECT` on h2). Once the client
    /// answers `101`, this yields the raw visitor I/O to pipe over the
    /// stream.
    pub on_upgrade: Option<hyper::upgrade::OnUpgrade>,
    /// The upgrade arrived as an h2 extended `CONNECT`: the visitor expects a
    /// `200` (not `101`) and no `Connection`/`Upgrade` headers.
    pub visitor_connect: bool,
}

/// Whether a visitor request is an upgrade: an h1 `Upgrade` with a
/// `Connection: upgrade` token, or an h2 extended `CONNECT` (RFC 8441)
/// carrying a `:protocol` pseudo-header.
pub fn upgrade_kind(req: &Request<Incoming>) -> Option<UpgradeKind> {
    if req.method() == http::Method::CONNECT {
        return req
            .extensions()
            .get::<hyper::ext::Protocol>()
            .map(|p| UpgradeKind::ExtendedConnect(p.as_str().to_string()));
    }
    let wants_upgrade = req
        .headers()
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
    let protocol = req
        .headers()
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    match (wants_upgrade, protocol) {
        (true, Some(p)) => Some(UpgradeKind::Http1(p)),
        _ => None,
    }
}

/// How the visitor asked for an upgrade; carries the protocol token.
pub enum UpgradeKind {
    /// HTTP/1.1 `Upgrade: <protocol>`.
    Http1(String),
    /// HTTP/2 extended `CONNECT` with `:protocol = <protocol>`.
    ExtendedConnect(String),
}

/// Hop-by-hop headers a proxy must not forward (RFC 9110 §7.6.1).
pub const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Forwarding headers the edge always writes itself; any visitor-supplied
/// copy is dropped so a client cannot forge its own address or host.
const FORWARDING_HEADERS: &[&str] = &[
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
];

/// Body implementation that streams frames from the tunnel client to the visitor.
///
/// Frames carry both data and trailers, so the origin's trailer fields reach
/// the visitor unchanged.
pub struct TunnelResponseBody {
    rx: mpsc::Receiver<BodyFrameItem>,
}

impl TunnelResponseBody {
    /// Creates a new TunnelResponseBody wrapping an mpsc receiver.
    pub fn new(rx: mpsc::Receiver<BodyFrameItem>) -> Self {
        Self { rx }
    }

    /// Wraps an mpsc receiver into a boxed hyper Body.
    pub fn boxed(rx: mpsc::Receiver<BodyFrameItem>) -> BoxBody {
        Self::new(rx).boxed()
    }
}

impl hyper::body::Body for TunnelResponseBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.rx.poll_recv(cx)
    }
}

/// Prepares and forwards an incoming HTTPS visitor request to the registered tunnel.
pub async fn forward_visitor_request(
    mut req: Request<Incoming>,
    route: &TunnelRoute,
    visitor_ip: IpAddr,
    host: &str,
) -> Result<Response<BoxBody>, StatusCode> {
    // Upgrades: keep a handle on the visitor's raw I/O before consuming the
    // request, and normalize both h1 `Upgrade` and h2 extended CONNECT into
    // the h1-shaped `Upgrade` + `Connection: upgrade` pair the client speaks
    // to its origin. These two headers are deliberately exempt from the
    // hop-by-hop strip below.
    let upgrade = upgrade_kind(&req);
    let on_upgrade = upgrade.as_ref().map(|_| hyper::upgrade::on(&mut req));
    let visitor_connect = matches!(upgrade, Some(UpgradeKind::ExtendedConnect(_)));
    let upgrade_protocol = match &upgrade {
        Some(UpgradeKind::Http1(p)) | Some(UpgradeKind::ExtendedConnect(p)) => Some(p.clone()),
        None => None,
    };

    let (parts, body) = req.into_parts();

    // 1. Identify additional connection-specific hop-by-hop headers from "Connection" header
    let mut extra_hop_by_hop = Vec::new();
    if let Some(conn) = parts.headers.get(http::header::CONNECTION)
        && let Ok(conn_str) = conn.to_str()
    {
        for token in conn_str.split(',') {
            let trimmed = token.trim().to_ascii_lowercase();
            if !trimmed.is_empty() {
                extra_hop_by_hop.push(trimmed);
            }
        }
    }

    // 2. Filter headers: strip hop-by-hop headers per RFC 9110 §7.6.1
    let mut cleaned_headers = Vec::with_capacity(parts.headers.len() + 3);
    for (name, value) in &parts.headers {
        let name_lower = name.as_str().to_ascii_lowercase();
        if HOP_BY_HOP_HEADERS.contains(&name_lower.as_str())
            || extra_hop_by_hop.contains(&name_lower)
            || FORWARDING_HEADERS.contains(&name_lower.as_str())
        {
            continue;
        }
        cleaned_headers.push((name_lower, value.as_bytes().to_vec()));
    }

    // 3. Stamp forwarding metadata: the X-Forwarded-* trio plus RFC 7239
    //    `Forwarded`. Inbound copies were dropped above, so these are the
    //    only ones the origin can trust.
    // The edge listens dual-stack, so IPv4 visitors arrive as
    // IPv4-mapped IPv6 (`::ffff:203.0.113.9`). Report the plain IPv4.
    let visitor = match visitor_ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(|v4| v4.to_string())
            .unwrap_or_else(|| v6.to_string()),
        IpAddr::V4(v4) => v4.to_string(),
    };
    cleaned_headers.push(("x-forwarded-for".to_string(), visitor.clone().into_bytes()));
    cleaned_headers.push(("x-forwarded-proto".to_string(), b"https".to_vec()));
    cleaned_headers.push(("x-forwarded-host".to_string(), host.as_bytes().to_vec()));
    cleaned_headers.push((
        "forwarded".to_string(),
        format!("for=\"{visitor}\";proto=https;host=\"{host}\"").into_bytes(),
    ));
    // RFC 9110 §7.6.3: a proxy records the protocol it received on. This
    // is also how the client learns whether the visitor spoke h1 or h2.
    let received_on = match parts.version {
        http::Version::HTTP_2 => "2",
        http::Version::HTTP_3 => "3",
        http::Version::HTTP_10 => "1.0",
        _ => "1.1",
    };
    cleaned_headers.push((
        "via".to_string(),
        format!("{received_on} weaver").into_bytes(),
    ));

    // Reconstruct the upgrade pair after the strip, and present an extended
    // CONNECT to the client as an ordinary GET upgrade: the origin never
    // sees h2.
    let mut method = parts.method.as_str().to_string();
    if let Some(protocol) = &upgrade_protocol {
        cleaned_headers.push(("connection".to_string(), b"upgrade".to_vec()));
        cleaned_headers.push(("upgrade".to_string(), protocol.as_bytes().to_vec()));
        if visitor_connect {
            method = "GET".to_string();
            // RFC 8441 §5: the h2 handshake has no `Sec-WebSocket-Key`, but
            // an h1 origin requires one. Synthesize it here; the matching
            // `Sec-WebSocket-Accept` is dropped on the way back.
            if protocol.eq_ignore_ascii_case("websocket")
                && !cleaned_headers
                    .iter()
                    .any(|(n, _)| n == "sec-websocket-key")
            {
                let key = tokio_tungstenite::tungstenite::handshake::client::generate_key();
                cleaned_headers.push(("sec-websocket-key".to_string(), key.into_bytes()));
            }
        }
    }

    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(parts.uri.path())
        .to_string();

    let head = HttpHead {
        method,
        scheme: "https".to_string(),
        authority: host.to_string(),
        path,
        headers: cleaned_headers,
    };

    let (response_tx, response_rx) = oneshot::channel();
    let proxy_req = ProxyRequest {
        head,
        body,
        response_tx,
        on_upgrade,
        visitor_connect,
    };

    if route.proxy_tx.send(proxy_req).await.is_err() {
        return Err(StatusCode::BAD_GATEWAY);
    }

    match response_rx.await {
        Ok(Ok(resp)) => Ok(resp),
        _ => Err(StatusCode::BAD_GATEWAY),
    }
}
