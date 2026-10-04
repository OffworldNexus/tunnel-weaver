//! Cleartext HTTP edge server.
//!
//! Listens on HTTP (port 80). ACME HTTP-01 validation requests under
//! `/.well-known/acme-challenge/` are handed to the registered
//! [`ChallengeResponder`]s — the edge knows only the trait, never how a
//! challenge is stored. Every other cleartext request is redirected to HTTPS
//! via HTTP 308 Permanent Redirect, preserving host, port, and query string.
//! The tunnel wildcard uses DNS-01, so it does not touch this path.

use std::convert::Infallible;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, Response, StatusCode, Version};
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info, trace};

use crate::edge::host::{HostError, request_host};

/// Path prefix ACME HTTP-01 validation requests use.
const ACME_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

/// A source that can recognise and answer an ACME HTTP-01 challenge.
///
/// The HTTP edge depends only on this trait: challenge material lives wherever
/// the business side puts it, and the edge asks each responder in turn.
#[async_trait]
pub trait ChallengeResponder: Send + Sync {
    /// The key authorization to serve for `token`, or `None` if unknown.
    async fn respond(&self, token: &str) -> Option<String>;
}

/// Shared state for HTTP edge service.
#[derive(Clone)]
pub struct HttpEdgeConfig {
    /// Configured tunnel domain (loopback redirects rewrite to it).
    pub tunnel_domain: String,
    /// Port of the HTTPS listener to redirect to.
    pub https_port: u16,
    /// Responders polled for ACME HTTP-01 challenges, in order.
    pub challenge_responders: Vec<Arc<dyn ChallengeResponder>>,
}

impl std::fmt::Debug for HttpEdgeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpEdgeConfig")
            .field("tunnel_domain", &self.tunnel_domain)
            .field("https_port", &self.https_port)
            .field("challenge_responders", &self.challenge_responders.len())
            .finish()
    }
}

/// Handles incoming cleartext HTTP requests: ACME HTTP-01 challenges are served
/// from the store on port 80; everything else is redirected to HTTPS.
pub async fn handle_http_redirect(
    req: Request<hyper::body::Incoming>,
    config: Arc<HttpEdgeConfig>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // ACME HTTP-01 validation is plaintext and must be answered before the
    // redirect: the CA will not follow a 3xx to https for a challenge. The path
    // is fixed by RFC 8555 §8.3; the token is the final segment.
    if let Some(token) = req.uri().path().strip_prefix(ACME_CHALLENGE_PREFIX) {
        return Ok(handle_http01_challenge(token, &config).await);
    }

    // RFC 9112 §3.2: no routing — not even a redirect — on a missing,
    // duplicated or malformed `Host`. HTTP/1.0 without `Host` is the one
    // legitimate hostless shape; it is redirected to the root domain.
    let host = match request_host(&req) {
        Ok(host) => host,
        Err(HostError::Missing) if req.version() == Version::HTTP_10 => String::new(),
        Err(reason) => {
            debug!(
                ?reason,
                "Rejecting cleartext request without a usable Host with 400"
            );
            let response = Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(http::header::CONNECTION, "close")
                .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Full::new(Bytes::from("400 Bad Request: invalid Host\n")))
                .unwrap();
            return Ok(response);
        }
    };

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let target_host = format_target_host(&host, &config.tunnel_domain, config.https_port);
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

/// Answers an ACME HTTP-01 challenge request.
///
/// The token is looked up in the store; a live key authorization is returned as
/// `text/plain` with status 200, anything else is 404. This intentionally does
/// not echo whether the miss was an unknown token or no store — both are the
/// same to a validator.
async fn handle_http01_challenge(token: &str, config: &HttpEdgeConfig) -> Response<Full<Bytes>> {
    let mut key_auth = None;
    if !token.is_empty() {
        for responder in &config.challenge_responders {
            if let Some(value) = responder.respond(token).await {
                key_auth = Some(value);
                break;
            }
        }
    }

    match key_auth {
        Some(value) => {
            trace!(token, "Serving ACME HTTP-01 key authorization");
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "text/plain")
                .body(Full::new(Bytes::from(value)))
                .unwrap()
        }
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from("404 Not Found: unknown challenge\n")))
            .unwrap(),
    }
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
/// Rewrites localhost / 127.0.0.1 / `[::1]` loopback addresses to `tunnel_domain`.
/// If the effective host does not specify an explicit port and https_port != 443,
/// appends `:{https_port}`.
pub fn format_target_host(incoming_host: &str, tunnel_domain: &str, https_port: u16) -> String {
    let host_name = extract_host_name(incoming_host);

    let is_loopback = host_name.is_empty()
        || host_name.eq_ignore_ascii_case("localhost")
        || host_name == "127.0.0.1"
        || host_name == "::1"
        || host_name == "[::1]";

    let effective_host = if is_loopback {
        tunnel_domain.to_string()
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
    tunnel_domain: String,
    https_port: u16,
    challenge_responders: Vec<Arc<dyn ChallengeResponder>>,
    shutdown_token: CancellationToken,
) {
    let edge_config = Arc::new(HttpEdgeConfig {
        tunnel_domain,
        https_port,
        challenge_responders,
    });
    let auto_builder = Builder::new(TokioExecutor::new());
    let tracker = TaskTracker::new();

    let addr_str = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".into());

    info!(
        addr = %addr_str,
        tunnel_domain = %edge_config.tunnel_domain,
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
