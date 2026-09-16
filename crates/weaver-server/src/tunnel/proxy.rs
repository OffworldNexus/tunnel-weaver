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

/// Body implementation that streams raw byte chunks from the tunnel client to the visitor.
pub struct TunnelResponseBody {
    rx: mpsc::Receiver<Result<Bytes, Box<dyn std::error::Error + Send + Sync>>>,
}

impl TunnelResponseBody {
    /// Creates a new TunnelResponseBody wrapping an mpsc receiver.
    pub fn new(
        rx: mpsc::Receiver<Result<Bytes, Box<dyn std::error::Error + Send + Sync>>>,
    ) -> Self {
        Self { rx }
    }

    /// Wraps an mpsc receiver into a boxed hyper Body.
    pub fn boxed(
        rx: mpsc::Receiver<Result<Bytes, Box<dyn std::error::Error + Send + Sync>>>,
    ) -> BoxBody {
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
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Prepares and forwards an incoming HTTPS visitor request to the registered tunnel.
pub async fn forward_visitor_request(
    req: Request<Incoming>,
    route: &TunnelRoute,
    visitor_ip: IpAddr,
    host: &str,
) -> Result<Response<BoxBody>, StatusCode> {
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
        {
            continue;
        }
        cleaned_headers.push((name_lower, value.as_bytes().to_vec()));
    }

    // 3. Append forwarding metadata headers: X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host
    cleaned_headers.push((
        "x-forwarded-for".to_string(),
        visitor_ip.to_string().into_bytes(),
    ));
    cleaned_headers.push(("x-forwarded-proto".to_string(), b"https".to_vec()));
    cleaned_headers.push(("x-forwarded-host".to_string(), host.as_bytes().to_vec()));

    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(parts.uri.path())
        .to_string();

    let head = HttpHead {
        method: parts.method.as_str().to_string(),
        scheme: "https".to_string(),
        authority: host.to_string(),
        path,
        headers: cleaned_headers,
        hints: weaver_mux::Hints::default(),
    };

    let (response_tx, response_rx) = oneshot::channel();
    let proxy_req = ProxyRequest {
        head,
        body,
        response_tx,
    };

    if route.proxy_tx.send(proxy_req).await.is_err() {
        return Err(StatusCode::BAD_GATEWAY);
    }

    match response_rx.await {
        Ok(Ok(resp)) => Ok(resp),
        _ => Err(StatusCode::BAD_GATEWAY),
    }
}
