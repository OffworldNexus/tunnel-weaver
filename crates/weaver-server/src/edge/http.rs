//! Cleartext HTTP edge server.
//!
//! Listens on HTTP (port 80) and redirects all cleartext requests to HTTPS
//! via HTTP 308 Permanent Redirect, preserving host, port, and query string,
//! while intercepting `/.well-known/acme-challenge/*` requests to solve ACME
//! HTTP-01 challenges.

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{info, trace};

use crate::cert::challenge::ChallengeRegistry;

/// Shared state for HTTP edge service.
#[derive(Clone, Default)]
pub struct HttpEdgeConfig {
    /// Configured root domain.
    pub root_domain: String,
    /// Port of the HTTPS listener to redirect to.
    pub https_port: u16,
    /// Active challenge registry for solving ACME HTTP-01 challenges.
    pub challenge_registry: Option<Arc<ChallengeRegistry>>,
}

impl std::fmt::Debug for HttpEdgeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpEdgeConfig")
            .field("root_domain", &self.root_domain)
            .field("https_port", &self.https_port)
            .field("has_challenge_registry", &self.challenge_registry.is_some())
            .finish()
    }
}

/// Handles incoming cleartext HTTP requests.
///
/// If the request path targets `/.well-known/acme-challenge/{token}`, queries the challenge
/// registry and returns HTTP 200 with the key authorization bytes if found, or HTTP 404 if
/// unknown. All other requests are redirected to HTTPS via HTTP 308.
pub async fn handle_http_redirect(
    req: Request<hyper::body::Incoming>,
    config: Arc<HttpEdgeConfig>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path();
    if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
        if let Some(registry) = &config.challenge_registry
            && let Some(key_auth) = registry.get_http_01(token)
        {
            trace!(token, "Serving HTTP-01 challenge response");
            let response = Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/octet-stream")
                .body(Full::new(Bytes::from(key_auth)))
                .unwrap();
            return Ok(response);
        }
        trace!(token, "Unknown HTTP-01 challenge token, returning 404");
        let response = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from("404 Not Found\n")))
            .unwrap();
        return Ok(response);
    }

    let host_header = req
        .headers()
        .get(http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| req.uri().authority().map(|a| a.as_str()))
        .unwrap_or("");

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let target_host = format_target_host(host_header, &config.root_domain, config.https_port);
    let location = format!("https://{target_host}{path_and_query}");

    trace!(%location, "Redirecting cleartext HTTP request to HTTPS");

    let response = Response::builder()
        .status(StatusCode::PERMANENT_REDIRECT)
        .header(http::header::LOCATION, location)
        .header(http::header::CONTENT_LENGTH, 0)
        .body(Full::new(Bytes::new()))
        .unwrap();

    Ok(response)
}

/// Helper to extract host without port.
fn extract_host_name(raw: &str) -> &str {
    let trimmed = raw.trim();
    if trimmed.starts_with('[')
        && let Some(close_bracket) = trimmed.find(']')
    {
        return &trimmed[..=close_bracket];
    }
    if let Some((host, _)) = trimmed.split_once(':') {
        host
    } else {
        trimmed
    }
}

/// Computes the target redirect host.
///
/// Rewrites localhost / 127.0.0.1 / `[::1]` loopback addresses to `root_domain`.
/// If the effective host does not specify an explicit port and https_port != 443,
/// appends `:{https_port}`.
pub fn format_target_host(incoming_host: &str, root_domain: &str, https_port: u16) -> String {
    let host_name = extract_host_name(incoming_host);

    let is_loopback = host_name.is_empty()
        || host_name.eq_ignore_ascii_case("localhost")
        || host_name == "127.0.0.1"
        || host_name == "::1"
        || host_name == "[::1]";

    let effective_host = if is_loopback {
        root_domain.to_string()
    } else {
        host_name.to_string()
    };

    // Check if effective_host already specifies an explicit port
    let has_port = if effective_host.starts_with('[') {
        effective_host.contains("]:")
    } else {
        effective_host.contains(':')
    };

    if has_port || https_port == 443 {
        effective_host
    } else {
        format!("{effective_host}:{https_port}")
    }
}

/// Runs the HTTP cleartext edge server on the given listener until the cancellation token is triggered.
pub async fn run_http_server(
    listener: TcpListener,
    root_domain: String,
    https_port: u16,
    challenge_registry: Option<Arc<ChallengeRegistry>>,
    shutdown_token: CancellationToken,
) {
    let edge_config = Arc::new(HttpEdgeConfig {
        root_domain,
        https_port,
        challenge_registry,
    });
    let auto_builder = Builder::new(TokioExecutor::new());
    let tracker = TaskTracker::new();

    let addr_str = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".into());

    info!(
        addr = %addr_str,
        root_domain = %edge_config.root_domain,
        https_port,
        "HTTP cleartext edge server running"
    );

    loop {
        tokio::select! {
            _ = shutdown_token.cancelled() => {
                info!("HTTP listener received shutdown signal, stopping accept loop");
                break;
            }
            accept_res = listener.accept() => {
                let (stream, remote_addr) = match accept_res {
                    Ok(pair) => pair,
                    Err(err) => {
                        trace!(error = %err, "HTTP accept error");
                        continue;
                    }
                };

                let config = Arc::clone(&edge_config);
                let auto = auto_builder.clone();
                let conn_token = shutdown_token.clone();

                tracker.spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |req| {
                        let cfg = Arc::clone(&config);
                        async move { handle_http_redirect(req, cfg).await }
                    });

                    let conn = auto.serve_connection_with_upgrades(io, service);
                    tokio::pin!(conn);

                    tokio::select! {
                        res = conn.as_mut() => {
                            if let Err(err) = res {
                                trace!(remote = %remote_addr, error = %err, "HTTP connection error");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_target_host() {
        assert_eq!(
            format_target_host("example.com", "example.com", 443),
            "example.com"
        );
        assert_eq!(
            format_target_host("example.com", "example.com", 8443),
            "example.com:8443"
        );
        assert_eq!(
            format_target_host("example.com:8080", "example.com", 8443),
            "example.com:8443"
        );
        assert_eq!(
            format_target_host("localhost:8080", "foo.localhost", 8443),
            "foo.localhost:8443"
        );
        assert_eq!(
            format_target_host("127.0.0.1:8080", "foo.localhost", 8443),
            "foo.localhost:8443"
        );
        assert_eq!(
            format_target_host("[::1]:8080", "foo.localhost", 8443),
            "foo.localhost:8443"
        );
        assert_eq!(
            format_target_host("localhost", "foo.localhost:9443", 8443),
            "foo.localhost:9443"
        );
    }
}
