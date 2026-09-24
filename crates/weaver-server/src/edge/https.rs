//! TLS HTTPS edge server.
//!
//! Terminates TLS connections, validates SNI and Host headers, serves root welcome pages,
//! health checks, WebSocket upgrades for the tunnel client on `GET /_weaver/connect`,
//! proxies incoming visitor requests to registered tunnels, and returns branded 404s.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use http::{Method, Request, Response, StatusCode};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info, trace};

use crate::cert::resolver::CertResolver;
use crate::edge::host::request_host;
use crate::edge::waf;
use crate::tunnel::proxy::{BoxBody, empty_body, forward_visitor_request, full_body};
use crate::tunnel::registry::TunnelRegistry;
use weaver_assets::{apply_security_headers, render_no_tunnel, render_welcome};

/// Shared state for HTTPS request dispatch.
#[derive(Clone)]
pub struct HttpsEdgeConfig {
    /// Configured root domain (e.g. "example.com").
    pub root_domain: String,
    /// Dynamic certificate resolver used to determine if certificate is placeholder.
    pub cert_resolver: Option<Arc<CertResolver>>,
    /// Active tunnel registry for routing subdomain requests and handling connection upgrades.
    pub tunnel_registry: Option<Arc<TunnelRegistry>>,
}

impl std::fmt::Debug for HttpsEdgeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsEdgeConfig")
            .field("root_domain", &self.root_domain)
            .field("has_cert_resolver", &self.cert_resolver.is_some())
            .field("has_tunnel_registry", &self.tunnel_registry.is_some())
            .finish()
    }
}

/// Determines whether a host string is an IPv4 or IPv6 address literal.
pub fn is_ip_literal(host: &str) -> bool {
    let unbracketed = if host.starts_with('[') && host.ends_with(']') {
        &host[1..host.len() - 1]
    } else {
        host
    };
    unbracketed.parse::<IpAddr>().is_ok()
}

pub use weaver_tokio::{set_tcp_nodelay, set_tcp_notsent_lowat};

/// Dispatches an HTTPS request based on SNI and Host header validation.
pub async fn handle_https_request(
    mut req: Request<hyper::body::Incoming>,
    config: Arc<HttpsEdgeConfig>,
    client_sni: Option<String>,
    remote_addr: SocketAddr,
) -> Result<Response<BoxBody>, Infallible> {
    // The relay is a reverse proxy, never a forward proxy: a plain `CONNECT`
    // (tunnelling to an arbitrary authority) is rejected with 405. An RFC
    // 8441 extended CONNECT carries a `:protocol` pseudo-header and is the
    // WebSocket-over-h2 case, handled by the upgrade path.
    if req.method() == Method::CONNECT && req.extensions().get::<hyper::ext::Protocol>().is_none() {
        debug!("Rejecting forward-proxy CONNECT with 405");
        let mut resp = Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(
                http::header::ALLOW,
                "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS",
            )
            .body(full_body(
                "405 Method Not Allowed: CONNECT is not supported\n",
            ))
            .unwrap();
        apply_security_headers(&mut resp, false);
        return Ok(resp);
    }

    // RFC 9112 §3.2 / RFC 9113 §8.3.1: a request with no host, more than
    // one `Host` line, a malformed value, or (h2) a `host` that disagrees
    // with `:authority` is a 400, never routed on a guess. Duplicate `Host`
    // in particular is a request-smuggling shape and the edge must refuse
    // it before anything is forwarded. `Connection: close` because the
    // framing of what follows on that connection can no longer be trusted.
    let host = match request_host(&req) {
        Ok(host) => host,
        Err(reason) => {
            debug!(?reason, "Rejecting request without a usable Host with 400");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(http::header::CONNECTION, "close")
                .body(full_body("400 Bad Request: invalid Host\n"))
                .unwrap());
        }
    };

    // Reject IP literal host with 421 Misdirected Request
    if is_ip_literal(&host) {
        debug!(%host, "Rejecting IP literal host on HTTPS with 421");
        return Ok(Response::builder()
            .status(StatusCode::MISDIRECTED_REQUEST)
            .body(full_body("421 Misdirected Request\n"))
            .unwrap());
    }

    // Require matching SNI and Host headers
    let Some(sni) = client_sni.as_deref() else {
        debug!(%host, "Missing SNI on TLS connection, returning 421");
        return Ok(Response::builder()
            .status(StatusCode::MISDIRECTED_REQUEST)
            .body(full_body("421 Misdirected Request\n"))
            .unwrap());
    };

    if !sni.eq_ignore_ascii_case(&host) {
        debug!(sni, %host, "SNI and Host header mismatch, returning 421");
        return Ok(Response::builder()
            .status(StatusCode::MISDIRECTED_REQUEST)
            .body(full_body("421 Misdirected Request\n"))
            .unwrap());
    }

    let host_lower = host.to_ascii_lowercase();
    let root_lower = config.root_domain.to_ascii_lowercase();

    let include_hsts = config
        .cert_resolver
        .as_ref()
        .is_some_and(|r| !r.is_placeholder(&host));

    if host_lower == root_lower {
        // Handle WebSocket upgrade endpoint GET /_weaver/connect on root domain
        if req.uri().path() == "/_weaver/connect" {
            if req.method() != Method::GET {
                let mut resp = Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(full_body("405 Method Not Allowed\n"))
                    .unwrap();
                apply_security_headers(&mut resp, include_hsts);
                return Ok(resp);
            }

            let ws_proto = req
                .headers()
                .get("sec-websocket-protocol")
                .and_then(|v| v.to_str().ok());
            if ws_proto != Some("weaver-mux-v1") {
                let mut resp = Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(full_body(
                        "400 Bad Request: Sec-WebSocket-Protocol must be weaver-mux-v1\n",
                    ))
                    .unwrap();
                apply_security_headers(&mut resp, include_hsts);
                return Ok(resp);
            }

            let key = match req
                .headers()
                .get("sec-websocket-key")
                .and_then(|v| v.to_str().ok())
            {
                Some(k) => k,
                None => {
                    let mut resp = Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(full_body("400 Bad Request: Missing Sec-WebSocket-Key\n"))
                        .unwrap();
                    apply_security_headers(&mut resp, include_hsts);
                    return Ok(resp);
                }
            };

            let accept =
                tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
            let on_upgrade = hyper::upgrade::on(&mut req);

            if let Some(ref reg) = config.tunnel_registry {
                let reg = Arc::clone(reg);
                let root = config.root_domain.clone();
                tokio::spawn(async move {
                    match on_upgrade.await {
                        Ok(upgraded) => {
                            let io = TokioIo::new(upgraded);
                            let ws_stream = tokio_tungstenite::WebSocketStream::from_raw_socket(
                                io,
                                tokio_tungstenite::tungstenite::protocol::Role::Server,
                                None,
                            )
                            .await;
                            crate::tunnel::spawn_tunnel_connection(ws_stream, reg, root);
                        }
                        Err(err) => {
                            debug!(error = %err, "WebSocket upgrade failed");
                        }
                    }
                });
            }

            let mut resp = Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header(http::header::CONNECTION, "Upgrade")
                .header(http::header::UPGRADE, "websocket")
                .header("Sec-WebSocket-Accept", accept)
                .header("Sec-WebSocket-Protocol", "weaver-mux-v1")
                .body(empty_body())
                .unwrap();
            apply_security_headers(&mut resp, include_hsts);
            return Ok(resp);
        }

        // Standard root domain HTTP endpoints
        match (req.method(), req.uri().path()) {
            (&Method::GET, "/") => {
                let mut resp = Response::builder()
                    .status(StatusCode::OK)
                    .body(full_body(render_welcome()))
                    .unwrap();
                apply_security_headers(&mut resp, include_hsts);
                Ok(resp)
            }
            (&Method::GET, "/healthz") => {
                let mut resp = Response::builder()
                    .status(StatusCode::OK)
                    .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body(full_body("ok\n"))
                    .unwrap();
                apply_security_headers(&mut resp, include_hsts);
                Ok(resp)
            }
            _ => {
                let mut resp = Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(full_body("404 Not Found\n"))
                    .unwrap();
                apply_security_headers(&mut resp, include_hsts);
                Ok(resp)
            }
        }
    } else if host_lower.ends_with(&format!(".{root_lower}"))
        && host_lower.len() > root_lower.len() + 1
    {
        // Always-on edge firewall: scanner probes are refused here so they
        // never open a tunnel stream or reach the origin (see `edge::waf`).
        let raw_path = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or(req.uri().path());
        if let Some(verdict) = waf::inspect(req.method(), raw_path) {
            debug!(
                hostname = %host_lower,
                visitor = %remote_addr.ip(),
                method = %req.method(),
                path = raw_path,
                rule = verdict.as_str(),
                "WAF blocked request"
            );
            let mut resp = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("x-weaver-blocked", verdict.as_str())
                .body(full_body(weaver_assets::render_forbidden(verdict.as_str())))
                .unwrap();
            apply_security_headers(&mut resp, include_hsts);
            return Ok(resp);
        }

        // Check if there is an active tunnel for this subdomain
        if let Some(ref reg) = config.tunnel_registry
            && let Some(route) = reg.lookup(&host_lower)
        {
            let visitor_ip = remote_addr.ip();
            match forward_visitor_request(req, &route, visitor_ip, &host).await {
                Ok(mut resp) => {
                    if include_hsts {
                        resp.headers_mut().insert(
                            http::header::STRICT_TRANSPORT_SECURITY,
                            http::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
                        );
                    }
                    return Ok(resp);
                }
                Err(_) => {
                    debug!(hostname = %host_lower, "Tunnel error 502");
                    let html = weaver_assets::render_bad_gateway(&host_lower);
                    let mut resp = Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(full_body(html))
                        .unwrap();
                    apply_security_headers(&mut resp, include_hsts);
                    return Ok(resp);
                }
            }
        }

        debug!(hostname = %host_lower, "Tunnel not found");
        let mut resp = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(full_body(render_no_tunnel()))
            .unwrap();
        apply_security_headers(&mut resp, include_hsts);
        Ok(resp)
    } else {
        // Unrecognized domain -> 421 Misdirected Request
        debug!(%host, root_domain = %config.root_domain, "Unrecognized domain, returning 421");
        Ok(Response::builder()
            .status(StatusCode::MISDIRECTED_REQUEST)
            .body(full_body("421 Misdirected Request\n"))
            .unwrap())
    }
}

/// Runs the HTTPS TLS edge server on the given listener until the cancellation token is triggered.
pub async fn run_https_server(
    listener: TcpListener,
    tls_config: Arc<ServerConfig>,
    root_domain: String,
    cert_resolver: Option<Arc<CertResolver>>,
    shutdown_token: CancellationToken,
) {
    run_https_server_with_registry(
        listener,
        tls_config,
        root_domain,
        cert_resolver,
        None,
        shutdown_token,
    )
    .await;
}

/// Runs the HTTPS TLS edge server with an optional tunnel registry for proxying.
pub async fn run_https_server_with_registry(
    listener: TcpListener,
    tls_config: Arc<ServerConfig>,
    root_domain: String,
    cert_resolver: Option<Arc<CertResolver>>,
    tunnel_registry: Option<Arc<TunnelRegistry>>,
    shutdown_token: CancellationToken,
) {
    let edge_config = Arc::new(HttpsEdgeConfig {
        root_domain,
        cert_resolver,
        tunnel_registry,
    });
    let acceptor = TlsAcceptor::from(tls_config);
    let mut auto_builder = Builder::new(TokioExecutor::new());
    // Advertise SETTINGS_ENABLE_CONNECT_PROTOCOL so h2 visitors can carry
    // WebSocket as an RFC 8441 extended CONNECT (see ADR 0006).
    auto_builder.http2().enable_connect_protocol();
    let tracker = TaskTracker::new();

    let addr_str = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".into());

    info!(
        addr = %addr_str,
        root_domain = %edge_config.root_domain,
        "HTTPS edge server running"
    );

    loop {
        tokio::select! {
            _ = shutdown_token.cancelled() => {
                info!("HTTPS listener received shutdown signal, stopping accept loop");
                break;
            }
            accept_res = listener.accept() => {
                let (tcp_stream, remote_addr) = match accept_res {
                    Ok(pair) => pair,
                    Err(err) => {
                        trace!(error = %err, "HTTPS accept error");
                        continue;
                    }
                };

                // Disable Nagle and apply TCP_NOTSENT_LOWAT before TLS
                // handshake wrapping. Without NODELAY the response head and
                // its first body chunk go out as separate small writes with
                // the body held until the head is ACKed — a full RTT of added
                // latency on every WAN visitor connection.
                set_tcp_nodelay(&tcp_stream);
                set_tcp_notsent_lowat(&tcp_stream);

                let tls_acceptor = acceptor.clone();
                let config = Arc::clone(&edge_config);
                let auto = auto_builder.clone();
                let conn_token = shutdown_token.clone();

                tracker.spawn(async move {
                    let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                        Ok(s) => s,
                        Err(err) => {
                            trace!(remote = %remote_addr, error = %err, "TLS handshake error");
                            return;
                        }
                    };

                    // Extract negotiated SNI from the TLS connection state
                    let (_, server_conn) = tls_stream.get_ref();
                    let client_sni = server_conn.server_name().map(|s| s.to_string());

                    let io = TokioIo::new(tls_stream);
                    let service = service_fn(move |req| {
                        let cfg = Arc::clone(&config);
                        let sni = client_sni.clone();
                        async move { handle_https_request(req, cfg, sni, remote_addr).await }
                    });

                    let conn = auto.serve_connection_with_upgrades(io, service);
                    tokio::pin!(conn);

                    tokio::select! {
                        res = conn.as_mut() => {
                            if let Err(err) = res {
                                trace!(remote = %remote_addr, error = %err, "HTTPS connection error");
                            }
                        }
                        _ = conn_token.cancelled() => {
                            conn.as_mut().graceful_shutdown();
                            let _ = conn.as_mut().await;
                        }
                    }
                });
            }
        }
    }

    tracker.close();
    tracker.wait().await;
}
