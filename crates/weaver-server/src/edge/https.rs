//! TLS HTTPS edge server.
//!
//! Terminates TLS connections, validates SNI and Host headers, and serves
//! root welcome pages, health checks, branded tunnel 404s, and 421 Misdirected Request responses.

use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace};

use crate::assets::{NO_TUNNEL_HTML, WELCOME_HTML, apply_security_headers};

/// Shared state for HTTPS request dispatch.
#[derive(Clone, Debug)]
pub struct HttpsEdgeConfig {
    /// Configured root domain (e.g. "example.com").
    pub root_domain: String,
}

/// Helper to parse and strip any port component from an authority or Host header value.
pub fn extract_host_without_port(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with('[') {
        // IPv6 address literal: [::1] or [::1]:8443
        if let Some(close_bracket) = trimmed.find(']') {
            return trimmed[..=close_bracket].to_string();
        }
    }
    // Hostname or IPv4: split at ':' if present
    if let Some((host, _port)) = trimmed.split_once(':') {
        host.to_string()
    } else {
        trimmed.to_string()
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

/// Dispatches an HTTPS request based on SNI and Host header validation.
pub async fn handle_https_request(
    req: Request<hyper::body::Incoming>,
    config: Arc<HttpsEdgeConfig>,
    client_sni: Option<String>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let host_header = req
        .headers()
        .get(http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| req.uri().authority().map(|a| a.as_str()))
        .unwrap_or("");

    let host = extract_host_without_port(host_header);

    // Reject empty host or IP literal host with 421 Misdirected Request
    if host.is_empty() || is_ip_literal(&host) {
        debug!(%host, "Rejecting empty or IP literal host on HTTPS with 421");
        return Ok(Response::builder()
            .status(StatusCode::MISDIRECTED_REQUEST)
            .body(Full::new(Bytes::from("421 Misdirected Request\n")))
            .unwrap());
    }

    // Require matching SNI and Host headers
    let Some(sni) = client_sni.as_deref() else {
        debug!(%host, "Missing SNI on TLS connection, returning 421");
        return Ok(Response::builder()
            .status(StatusCode::MISDIRECTED_REQUEST)
            .body(Full::new(Bytes::from("421 Misdirected Request\n")))
            .unwrap());
    };

    if !sni.eq_ignore_ascii_case(&host) {
        debug!(sni, %host, "SNI and Host header mismatch, returning 421");
        return Ok(Response::builder()
            .status(StatusCode::MISDIRECTED_REQUEST)
            .body(Full::new(Bytes::from("421 Misdirected Request\n")))
            .unwrap());
    }

    let host_lower = host.to_ascii_lowercase();
    let root_lower = config.root_domain.to_ascii_lowercase();

    if host_lower == root_lower {
        // Request directed to root domain
        match (req.method(), req.uri().path()) {
            (&Method::GET, "/") => {
                let mut resp = Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::from(WELCOME_HTML)))
                    .unwrap();
                apply_security_headers(&mut resp);
                Ok(resp)
            }
            (&Method::GET, "/healthz") => {
                let resp = Response::builder()
                    .status(StatusCode::OK)
                    .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body(Full::new(Bytes::from("ok\n")))
                    .unwrap();
                Ok(resp)
            }
            _ => {
                let mut resp = Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::from("404 Not Found\n")))
                    .unwrap();
                apply_security_headers(&mut resp);
                Ok(resp)
            }
        }
    } else if host_lower.ends_with(&format!(".{root_lower}"))
        && host_lower.len() > root_lower.len() + 1
    {
        // Subdomain of root domain: return branded "no such tunnel" 404 page
        let mut resp = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from(NO_TUNNEL_HTML)))
            .unwrap();
        apply_security_headers(&mut resp);
        Ok(resp)
    } else {
        // Unrecognized domain -> 421 Misdirected Request
        debug!(%host, root_domain = %config.root_domain, "Unrecognized domain, returning 421");
        Ok(Response::builder()
            .status(StatusCode::MISDIRECTED_REQUEST)
            .body(Full::new(Bytes::from("421 Misdirected Request\n")))
            .unwrap())
    }
}

/// Runs the HTTPS TLS edge server on the given listener until the cancellation token is triggered.
pub async fn run_https_server(
    listener: TcpListener,
    tls_config: Arc<ServerConfig>,
    root_domain: String,
    shutdown_token: CancellationToken,
) {
    let edge_config = Arc::new(HttpsEdgeConfig { root_domain });
    let acceptor = TlsAcceptor::from(tls_config);
    let auto_builder = Builder::new(TokioExecutor::new());

    info!(
        addr = ?listener.local_addr().ok(),
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

                let acceptor = acceptor.clone();
                let config = Arc::clone(&edge_config);
                let auto = auto_builder.clone();
                let conn_token = shutdown_token.clone();

                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(tcp_stream).await {
                        Ok(stream) => stream,
                        Err(err) => {
                            trace!(remote = %remote_addr, error = %err, "TLS handshake failed");
                            return;
                        }
                    };

                    let client_sni = tls_stream
                        .get_ref()
                        .1
                        .server_name()
                        .map(|s| s.to_string());

                    let io = TokioIo::new(tls_stream);
                    let service = service_fn(move |req| {
                        let cfg = Arc::clone(&config);
                        let sni = client_sni.clone();
                        async move { handle_https_request(req, cfg, sni).await }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_host_without_port() {
        assert_eq!(extract_host_without_port("example.com"), "example.com");
        assert_eq!(extract_host_without_port("example.com:443"), "example.com");
        assert_eq!(extract_host_without_port("example.com:8443"), "example.com");
        assert_eq!(extract_host_without_port("[::1]"), "[::1]");
        assert_eq!(extract_host_without_port("[::1]:8443"), "[::1]");
        assert_eq!(extract_host_without_port("127.0.0.1:8080"), "127.0.0.1");
    }

    #[test]
    fn test_is_ip_literal() {
        assert!(is_ip_literal("127.0.0.1"));
        assert!(is_ip_literal("10.0.0.1"));
        assert!(is_ip_literal("[::1]"));
        assert!(is_ip_literal("::1"));
        assert!(!is_ip_literal("example.com"));
        assert!(!is_ip_literal("sub.example.com"));
        assert!(!is_ip_literal("localhost"));
    }
}
