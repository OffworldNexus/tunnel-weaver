//! TLS HTTPS edge server.
//!
//! Terminates TLS connections, validates SNI and Host headers, serves root welcome pages,
//! health checks, WebSocket upgrades for the tunnel client on `GET /_weaver/connect`
//! (on the tunnel root and the admin host), the machine pairing channel and API on the
//! admin host, proxies incoming visitor requests to registered tunnels, and returns
//! branded 404s.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::BodyExt;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info, trace, warn};

use crate::abuse::Refusal;
use crate::cert::CertManager;
use crate::cert::managed::{ManagedCerts, Validation};
use crate::cert::resolver::CertResolver;
use crate::edge::counting::{ConnBytes, CountingIo};
use crate::edge::host::request_host;
use crate::tunnel::proxy::{BoxBody, empty_body, forward_visitor_request, full_body};
use crate::tunnel::registry::TunnelRegistry;
use weaver_abuse::{Decision, Host, Pipeline, Surface, ViewId, bounded_path};
use weaver_assets::{apply_security_headers, render_no_tunnel, render_welcome};

/// How often a live visitor connection reports its accumulated socket bytes to
/// metering, so long-lived connections land in the right minute rather than
/// all at close.
const VISITOR_REPORT_INTERVAL: Duration = Duration::from_secs(5);

/// Shared state for HTTPS request dispatch.
#[derive(Clone)]
pub struct HttpsEdgeConfig {
    /// The relay's managed certificates: coverage decides the admin host
    /// (HTTP-01 certificate) from the tunnel zone (DNS-01 wildcard).
    pub managed: Arc<ManagedCerts>,
    /// Dynamic certificate resolver used to determine if certificate is placeholder.
    pub cert_resolver: Option<Arc<CertResolver>>,
    /// Certificate manager, used to record visitor-triggered renewals.
    pub cert_manager: Option<Arc<CertManager>>,
    /// Active tunnel registry for routing subdomain requests and handling connection upgrades.
    pub tunnel_registry: Option<Arc<TunnelRegistry>>,
    /// The usage meter, when the process has one: the account plane reads the
    /// console's traffic figures from it.
    pub metering: Option<Arc<crate::metering::MeteringManager>>,
    /// The safety pipeline run at the request boundary (scanner + budget).
    pub guard: Arc<Pipeline>,
    /// The ALTCHA proof-of-work runtime, when `abuse.altcha` is enabled.
    pub altcha: Option<Arc<crate::altcha::AltchaRuntime>>,
    /// The account plane, served on the admin host only.
    pub account: Option<Arc<crate::account::AccountRuntime>>,
}

impl std::fmt::Debug for HttpsEdgeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsEdgeConfig")
            .field("tunnel_domain", &self.managed.tunnel_domain())
            .field("has_cert_resolver", &self.cert_resolver.is_some())
            .field("has_cert_manager", &self.cert_manager.is_some())
            .field("has_tunnel_registry", &self.tunnel_registry.is_some())
            .field("has_metering", &self.metering.is_some())
            .field("passes", &self.guard.pass_names())
            .field("altcha", &self.altcha.is_some())
            .field("account", &self.account.is_some())
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

/// Build the branded refusal response for a blocked/throttled/unavailable request.
fn refusal_response(refusal: Refusal, include_hsts: bool) -> Response<BoxBody> {
    let mut resp = Response::builder()
        .status(refusal.status())
        .body(full_body(refusal.body()))
        .unwrap();
    refusal.apply(&mut resp);
    apply_security_headers(&mut resp, include_hsts);
    resp
}

/// Collect at most the body of a request whose handler needs it (the ALTCHA
/// verify endpoints). A read error yields empty bytes; the handler then answers
/// a malformed-request error.
async fn collect_body(req: Request<hyper::body::Incoming>) -> Option<Bytes> {
    req.into_body().collect().await.ok().map(|c| c.to_bytes())
}

/// Bridge a hyper request into the account plane's axum router and map the
/// response back, applying the account surface's security headers.
///
/// The router is rebuilt per request (cheap: a small route table) so the raw
/// hyper edge keeps ownership of the boundary and no shared mutable state
/// crosses it. HTML responses get the SPA CSP; everything else gets the shared
/// JSON/asset headers, which do not touch `Content-Type`.
async fn serve_account(
    account: &Arc<crate::account::AccountRuntime>,
    tunnel: Option<Arc<TunnelRegistry>>,
    remote_addr: SocketAddr,
    req: Request<hyper::body::Incoming>,
    include_hsts: bool,
) -> Response<BoxBody> {
    use tower::ServiceExt as _;

    let router = crate::account::router::router(account.clone(), tunnel);
    let (parts, body) = req.into_parts();
    let mut request = Request::from_parts(parts, axum::body::Body::new(body));
    // The raw edge is the only layer that knows the socket address; the account
    // plane records it on its authentication trail (WVR-167).
    request
        .extensions_mut()
        .insert(crate::account::auth::ClientAddr(remote_addr));
    let response = match router.oneshot(request).await {
        Ok(response) => response,
        Err(never) => match never {},
    };
    let (parts, body) = response.into_parts();
    // Account responses are ordinarily small (JSON, HTML, modest assets) and are
    // buffered so the boxed body stays `Send + Sync`, which the edge's unified
    // body type requires. An SSE stream is the exception: it never ends, so it
    // is bridged frame by frame instead.
    let is_stream = parts
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/event-stream"));
    if is_stream {
        let (tx, rx) = tokio::sync::mpsc::channel::<crate::tunnel::proxy::BodyFrameItem>(8);
        tokio::spawn(async move {
            let mut body = body;
            while let Some(frame) = body.frame().await {
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(e) => {
                        let _ = tx.send(Err(Box::new(e))).await;
                        break;
                    }
                };
                if tx.send(Ok(frame)).await.is_err() {
                    break;
                }
            }
        });
        let mut response =
            Response::from_parts(parts, crate::tunnel::proxy::TunnelResponseBody::boxed(rx));
        weaver_assets::apply_common_security_headers(&mut response, include_hsts);
        return response;
    }
    let bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return plain_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "500 Internal Server Error\n",
                include_hsts,
            );
        }
    };
    let mut response = Response::from_parts(parts, full_body(bytes));
    let is_html = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/html"));
    if is_html {
        weaver_assets::apply_spa_security_headers(&mut response, include_hsts);
    } else {
        weaver_assets::apply_common_security_headers(&mut response, include_hsts);
    }
    response
}

pub use weaver_tokio::{set_tcp_nodelay, set_tcp_notsent_lowat};

/// The upgraded socket a WebSocket endpoint serves.
type UpgradedWs = tokio_tungstenite::WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>;

/// A plain-text refusal with the security headers.
fn plain_response(
    status: StatusCode,
    body: impl Into<Bytes>,
    include_hsts: bool,
) -> Response<BoxBody> {
    let mut resp = Response::builder()
        .status(status)
        .body(full_body(body))
        .unwrap();
    apply_security_headers(&mut resp, include_hsts);
    resp
}

/// Answers a `GET` WebSocket upgrade speaking `subprotocol` and hands the
/// upgraded socket, opened with `ws_config`, to `serve`.
fn websocket_upgrade<F, Fut>(
    req: &mut Request<hyper::body::Incoming>,
    subprotocol: &'static str,
    ws_config: Option<tokio_tungstenite::tungstenite::protocol::WebSocketConfig>,
    include_hsts: bool,
    serve: F,
) -> Response<BoxBody>
where
    F: FnOnce(UpgradedWs) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    if req.method() != Method::GET {
        return plain_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "405 Method Not Allowed\n",
            include_hsts,
        );
    }
    let ws_proto = req
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok());
    if ws_proto != Some(subprotocol) {
        return plain_response(
            StatusCode::BAD_REQUEST,
            format!("400 Bad Request: Sec-WebSocket-Protocol must be {subprotocol}\n"),
            include_hsts,
        );
    }
    let Some(key) = req.headers().get("sec-websocket-key") else {
        return plain_response(
            StatusCode::BAD_REQUEST,
            "400 Bad Request: Missing Sec-WebSocket-Key\n",
            include_hsts,
        );
    };
    let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
    let on_upgrade = hyper::upgrade::on(&mut *req);
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
                    TokioIo::new(upgraded),
                    tokio_tungstenite::tungstenite::protocol::Role::Server,
                    ws_config,
                )
                .await;
                serve(ws).await;
            }
            Err(err) => debug!(error = %err, subprotocol, "WebSocket upgrade failed"),
        }
    });

    let mut resp = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(http::header::CONNECTION, "Upgrade")
        .header(http::header::UPGRADE, "websocket")
        .header("Sec-WebSocket-Accept", accept)
        .header("Sec-WebSocket-Protocol", subprotocol)
        .body(empty_body())
        .unwrap();
    apply_security_headers(&mut resp, include_hsts);
    resp
}

/// The budgeted view a request targets.
///
/// Views are named here, at the edge, because this is the single routing
/// boundary every host passes through: no handler can forget to declare what it
/// is. The budgets themselves live in [`crate::abuse`] and the operator's
/// config; only routes with one of their own are named, and everything else on
/// the relay's web surface is [`ViewId::RELAY_WEB`] (budgeted only when the
/// operator arms `abuse`).
fn view_for(surface: Surface, path: &str) -> ViewId {
    let admin = surface.host == Host::Admin;
    match surface.host {
        Host::Tunneled => ViewId::TUNNEL,
        Host::TunnelRoot if path == "/altcha/challenge" => ViewId::ALTCHA_CHALLENGE,
        Host::TunnelRoot if path == "/altcha/verify" => ViewId::ALTCHA_VERIFY,
        _ if admin && path == "/api/account/signup" => ViewId::ACCOUNT_SIGNUP,
        _ if admin && path == "/api/account/login" => ViewId::ACCOUNT_LOGIN,
        // Checking an emailed code guesses digits behind the same password guess
        // that opened the session, so it shares the login budget rather than
        // minting a new one (WVR-167).
        _ if admin && path == "/api/account/login/verify" => ViewId::ACCOUNT_LOGIN,
        // A re-sent code is an email-keyed send like a verification resend.
        _ if admin && path == "/api/account/login/resend" => ViewId::ACCOUNT_RESEND,
        // A password change verifies a guessed credential behind a session, so it
        // is the same guessing surface as a login attempt and shares that budget
        // rather than minting a new one.
        _ if admin && path == "/api/account/password" => ViewId::ACCOUNT_LOGIN,
        // Every passkey endpoint: the anonymous ceremony the sign-in field offers
        // and the button presses, the step-up, and the account's own credential
        // management. A passkey is cryptographic — there is nothing to guess — so
        // these get their own, far looser budget rather than the login's, and one
        // that serves instead of refusing when the budget store hiccups: what it
        // bounds is work, not a secret (WVR-163).
        _ if admin && path.starts_with("/api/account/passkey") => ViewId::ACCOUNT_PASSKEY,
        _ if admin && path == "/api/account/resend" => ViewId::ACCOUNT_RESEND,
        // The pairing channel charges the pairing budget itself, once the proof of
        // work is in: a throttled machine is told so on the channel rather than by
        // a bare 429 on the upgrade.
        _ if admin && path == weaver_proto::pair::PAIR_CHANNEL_PATH => ViewId::RELAY_WEB,
        // The pairing browser API, behind its own fail-closed budget.
        _ if admin && path.starts_with("/api/account/pair/") => ViewId::ACCOUNT_PAIR,
        // The reset request is an unauthenticated, email-keyed, enumeration-safe
        // action: exactly the same situation as a verification resend, so it
        // shares that budget rather than minting a new one.
        _ if admin && path == "/api/account/reset/request" => ViewId::ACCOUNT_RESEND,
        _ => ViewId::RELAY_WEB,
    }
}

/// Dispatches an HTTPS request based on SNI and Host header validation.
///
/// `conn_bytes` is the socket-level counter for this visitor connection; when
/// the request routes to a tunnel, the connection is attributed to that
/// service so its bytes can be metered.
pub async fn handle_https_request(
    mut req: Request<hyper::body::Incoming>,
    config: Arc<HttpsEdgeConfig>,
    client_sni: Option<String>,
    remote_addr: SocketAddr,
    conn_bytes: Arc<ConnBytes>,
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
    let covering = config.managed.cert_for(&host_lower);

    let include_hsts = config
        .cert_resolver
        .as_ref()
        .is_some_and(|r| !r.is_placeholder(&host));

    // The safety pipeline runs at this single routing boundary for every host
    // the relay serves, so no branch can forget it. The surface is derived from
    // the same certificate coverage the branches below use, with the admin
    // certificate checked first: the apex is covered by the tunnel wildcard, so
    // testing `Http01` before the apex name keeps admin and tunnel policy from
    // being conflated. Unknown hosts (no covering cert) fall through to 421.
    let surface = if matches!(covering.map(|c| c.validation), Some(Validation::Http01)) {
        Some(Surface::https(Host::Admin))
    } else if config.managed.tunnel_domain() == Some(host_lower.as_str()) {
        Some(Surface::https(Host::TunnelRoot))
    } else if matches!(covering.map(|c| c.validation), Some(Validation::Dns01)) {
        Some(Surface::https(Host::Tunneled))
    } else {
        None
    };

    if let Some(surface) = surface {
        // The view is what selects the budget, so it is chosen before the guard
        // runs.
        let view = view_for(surface, req.uri().path());
        let ctx = crate::abuse::context(
            surface,
            &req,
            remote_addr,
            view,
            crate::wall_clock::unix_ms(),
        );
        let decision = config.guard.evaluate(&ctx).await;
        match decision {
            Decision::Block { verdict } => debug!(
                hostname = %host_lower,
                visitor = %remote_addr.ip(),
                method = %req.method(),
                scheme = surface.scheme.as_str(),
                surface = surface.host.as_str(),
                path = %bounded_path(req.uri().path()),
                verdict = verdict.as_str(),
                "safety pipeline blocked request"
            ),
            Decision::Throttle {
                policy,
                retry_after_ms,
            } => debug!(
                hostname = %host_lower,
                visitor = %remote_addr.ip(),
                path = %bounded_path(req.uri().path()),
                policy = policy.as_str(),
                retry_after_ms,
                "safety pipeline throttled request"
            ),
            Decision::Degraded { policy } => warn!(
                policy = policy.as_str(),
                "safety pipeline budget store unavailable; serving degraded"
            ),
            // Fail-closed: the request is refused with a 503, so it must say so
            // here — an unexplained 503 on a budgeted route is otherwise
            // invisible in the journal, which is how a passkey sign-in was
            // mistaken for a hang.
            Decision::Unavailable { policy } => warn!(
                hostname = %host_lower,
                visitor = %remote_addr.ip(),
                path = %bounded_path(req.uri().path()),
                policy = policy.as_str(),
                "safety pipeline budget store unavailable; refusing"
            ),
            Decision::Allow => {}
        }
        if let Some(refusal) = Refusal::from_decision(decision) {
            return Ok(refusal_response(refusal, include_hsts));
        }
    }

    // The tunnel WebSocket, on the tunnel root *or* the admin host. A client
    // only ever knows the admin host it paired with, so it dials that; the host
    // it presents becomes the mux handshake name on both sides.
    let on_tunnel_endpoint = matches!(covering.map(|c| c.validation), Some(Validation::Http01))
        || config.managed.tunnel_domain() == Some(host_lower.as_str());
    if on_tunnel_endpoint && req.uri().path() == "/_weaver/connect" {
        let registry = config.tunnel_registry.clone();
        let name = host_lower.clone();
        return Ok(websocket_upgrade(
            &mut req,
            "weaver-mux-v1",
            None,
            include_hsts,
            move |ws| async move {
                if let Some(registry) = registry {
                    crate::tunnel::spawn_tunnel_connection(ws, registry, name);
                }
            },
        ));
    }

    if matches!(covering.map(|c| c.validation), Some(Validation::Http01)) {
        if let Some(mgr) = &config.cert_manager {
            mgr.note_visit(&host_lower);
        }
        // The built-in ALTCHA diagnostic page and its assets.
        if let Some(altcha) = &config.altcha {
            if req.method() == Method::GET && req.uri().path() == "/abuse/check" {
                let query = req.uri().query().map(str::to_owned);
                return Ok(crate::altcha::demo_page(altcha, query.as_deref(), include_hsts).await);
            }
            if req.method() == Method::GET && req.uri().path().starts_with("/abuse/check/assets/") {
                let accept_encoding = req
                    .headers()
                    .get(header::ACCEPT_ENCODING)
                    .and_then(|value| value.to_str().ok());
                return Ok(crate::altcha::demo_asset(
                    req.uri().path(),
                    accept_encoding,
                    include_hsts,
                ));
            }
            if req.method() == Method::POST && req.uri().path() == "/abuse/check/verify" {
                let body = collect_body(req).await.unwrap_or_default();
                return Ok(crate::altcha::demo_verify(altcha, body, include_hsts).await);
            }
        }
        // The plain health endpoint stays Rust-owned.
        if req.method() == Method::GET && req.uri().path() == "/healthz" {
            return Ok(static_host_response(&req, include_hsts));
        }
        // The pairing channel: a WebSocket the machine opens before it has any
        // identity, so it is unauthenticated; it is gated by a proof of work and
        // the pairing budget. Handled on the raw edge because the account
        // router buffers response bodies and would strip the 101.
        if req.uri().path() == weaver_proto::pair::PAIR_CHANNEL_PATH {
            let Some(account) = config.account.clone() else {
                // No account plane on this relay, so there is nothing to pair with.
                return Ok(plain_response(
                    StatusCode::NOT_FOUND,
                    "404 Not Found\n",
                    include_hsts,
                ));
            };
            let peer = crate::account::pairing::Peer {
                guard: Arc::clone(&config.guard),
                addr: remote_addr,
            };
            return Ok(websocket_upgrade(
                &mut req,
                weaver_proto::pair::PAIR_SUBPROTOCOL,
                Some(crate::account::pairing::channel_config()),
                include_hsts,
                move |ws| crate::account::pairing::serve_channel(ws, account, peer),
            ));
        }

        // Everything else on the admin host is the SvelteKit account
        // plane — the landing page at `/`, the auth routes, the account API and
        // the vendored ALTCHA widget.
        if let Some(account) = &config.account {
            return Ok(serve_account(
                account,
                config.tunnel_registry.clone(),
                remote_addr,
                req,
                include_hsts,
            )
            .await);
        }
        return Ok(static_host_response(&req, include_hsts));
    }

    if config.managed.tunnel_domain() == Some(host_lower.as_str()) {
        if let Some(mgr) = &config.cert_manager {
            mgr.note_visit(&host_lower);
        }
        // The ALTCHA API, served as its own service on the apex.
        if let Some(altcha) = &config.altcha {
            if req.method() == Method::GET && req.uri().path() == "/altcha/challenge" {
                let query = req.uri().query().map(str::to_owned);
                return Ok(
                    crate::altcha::api_challenge(altcha, query.as_deref(), include_hsts).await,
                );
            }
            if req.method() == Method::POST && req.uri().path() == "/altcha/verify" {
                let body = collect_body(req).await.unwrap_or_default();
                return Ok(crate::altcha::api_verify(altcha, body, include_hsts).await);
            }
            if req.method() == Method::OPTIONS
                && matches!(req.uri().path(), "/altcha/challenge" | "/altcha/verify")
            {
                return Ok(crate::altcha::api_preflight(altcha, include_hsts));
            }
        }

        // Standard root domain HTTP endpoints
        match (req.method(), req.uri().path()) {
            (&Method::GET, "/") => Ok(plain_response(
                StatusCode::OK,
                render_welcome(),
                include_hsts,
            )),
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
    } else if matches!(covering.map(|c| c.validation), Some(Validation::Dns01)) {
        // Scanner probes were already refused by the surface guard above; what
        // remains here is ordinary tunnel traffic.

        // Check if there is an active tunnel for this subdomain. Resolution is
        // DB-backed: `domains.name -> service -> live proxy channel`.
        if let Some(ref reg) = config.tunnel_registry
            && let Some(route) = reg.resolve(&host_lower).await
        {
            if let Some(mgr) = &config.cert_manager {
                mgr.note_visit(&host_lower);
            }
            // Attribute this visitor connection's socket bytes to the service
            // it serves. First tunnel request wins for the whole connection.
            conn_bytes.set_service(route.service_id);
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
        debug!(%host, tunnel_domain = %config.managed.tunnel_domain().unwrap_or_default(), "Unrecognized domain, returning 421");
        Ok(Response::builder()
            .status(StatusCode::MISDIRECTED_REQUEST)
            .body(full_body("421 Misdirected Request\n"))
            .unwrap())
    }
}

/// Reports a visitor connection's unreported socket bytes to metering.
///
/// No-op until the connection has been attributed to a tunnel service. Called
/// periodically and once more at close, so long-lived connections land their
/// bytes in the minute they actually crossed the wire.
fn report_conn_bytes(bytes: &ConnBytes, config: &HttpsEdgeConfig) {
    let service_id = bytes.service_id();
    if service_id == 0 {
        return;
    }
    let (read, written) = bytes.take_delta();
    if read == 0 && written == 0 {
        return;
    }
    if let Some(reg) = &config.tunnel_registry {
        // `read` is browser -> relay, `written` is relay -> browser.
        reg.metering()
            .visitor_service_bytes(service_id, read, written);
    }
}

/// The per-connection byte-report timer, as a scheduler
/// [`Task`](crate::scheduler::Task).
///
/// A visitor connection owns one of these; its 5 s tick samples the socket
/// counters into metering. The connection's `select!` drives it via
/// [`Scheduler::run_due`](crate::scheduler::Scheduler::run_due), so the timer
/// never owns the I/O loop.
struct VisitorReportTask {
    bytes: Arc<ConnBytes>,
    config: Arc<HttpsEdgeConfig>,
}

#[async_trait::async_trait]
impl crate::scheduler::Task for VisitorReportTask {
    fn name(&self) -> &'static str {
        "visitor-byte-report"
    }
    async fn next_tick(&self, last_tick: Option<i64>, now: i64) -> i64 {
        (last_tick.unwrap_or(now) + VISITOR_REPORT_INTERVAL.as_secs() as i64).max(now)
    }
    async fn run(&self, _tick: i64) {
        report_conn_bytes(&self.bytes, &self.config);
    }
}

/// Welcome/health/404 surface shared by the tunnel apex and the admin host.
fn static_host_response(
    req: &Request<hyper::body::Incoming>,
    include_hsts: bool,
) -> Response<BoxBody> {
    let mut resp = match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => Response::builder()
            .status(StatusCode::OK)
            .body(full_body(render_welcome()))
            .unwrap(),
        (&Method::GET, "/healthz") => Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(full_body("ok\n"))
            .unwrap(),
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(full_body("404 Not Found\n"))
            .unwrap(),
    };
    apply_security_headers(&mut resp, include_hsts);
    resp
}

/// Runs the HTTPS TLS edge server on the given listener until the cancellation token is triggered.
pub async fn run_https_server(
    listener: TcpListener,
    tls_config: Arc<ServerConfig>,
    tunnel_domain: impl AsRef<str>,
    cert_resolver: Option<Arc<CertResolver>>,
    shutdown_token: CancellationToken,
) {
    run_https_server_with_registry(
        listener,
        tls_config,
        tunnel_domain.as_ref(),
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
    tunnel_domain: impl AsRef<str>,
    cert_resolver: Option<Arc<CertResolver>>,
    tunnel_registry: Option<Arc<TunnelRegistry>>,
    shutdown_token: CancellationToken,
) {
    run_https_server_full(
        listener,
        tls_config,
        HttpsEdgeConfig {
            managed: Arc::new(ManagedCerts::for_tunnel(tunnel_domain.as_ref())),
            cert_resolver,
            cert_manager: None,
            tunnel_registry,
            metering: None,
            guard: Arc::new(Pipeline::scanner_only()),
            altcha: None,
            account: None,
        },
        shutdown_token,
    )
    .await;
}

/// Runs the HTTPS TLS edge server with a fully-populated [`HttpsEdgeConfig`].
///
/// The full form is what the daemon uses: it additionally knows the admin
/// domain (served by its own certificate) and the certificate manager
/// (visitor-triggered renewal).
pub async fn run_https_server_full(
    listener: TcpListener,
    tls_config: Arc<ServerConfig>,
    config: HttpsEdgeConfig,
    shutdown_token: CancellationToken,
) {
    let edge_config = Arc::new(config);
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
        tunnel_domain = %edge_config.managed.tunnel_domain().unwrap_or_default(),
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
                let report_config = Arc::clone(&edge_config);
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

                    // Count every byte hyper reads/writes on this visitor
                    // stream; the request handler attributes it to a service
                    // once it resolves a tunnel route.
                    let bytes = Arc::new(ConnBytes::new());
                    let io = TokioIo::new(CountingIo::new(tls_stream, Arc::clone(&bytes)));
                    let service_bytes = Arc::clone(&bytes);
                    let service = service_fn(move |req| {
                        let cfg = Arc::clone(&config);
                        let sni = client_sni.clone();
                        let bytes = Arc::clone(&service_bytes);
                        async move { handle_https_request(req, cfg, sni, remote_addr, bytes).await }
                    });

                    let conn = auto.serve_connection_with_upgrades(io, service);
                    tokio::pin!(conn);

                    // The connection's own scheduler: a single 5 s byte-report
                    // timer, driven here rather than owning a loop of its own.
                    let mut timers = crate::scheduler::Scheduler::new(vec![Arc::new(
                        VisitorReportTask {
                            bytes: Arc::clone(&bytes),
                            config: Arc::clone(&report_config),
                        },
                    ) as Arc<dyn crate::scheduler::Task>])
                    .await;
                    loop {
                        let wait = timers.next_wait().unwrap_or(VISITOR_REPORT_INTERVAL);
                        tokio::select! {
                            res = conn.as_mut() => {
                                if let Err(err) = res {
                                    trace!(remote = %remote_addr, error = %err, "HTTPS connection error");
                                }
                                break;
                            }
                            _ = tokio::time::sleep(wait) => {
                                timers.run_due().await;
                            }
                            _ = conn_token.cancelled() => {
                                conn.as_mut().graceful_shutdown();
                                let _ = conn.as_mut().await;
                                break;
                            }
                        }
                    }
                    // Flush whatever accumulated since the last sample.
                    report_conn_bytes(&bytes, &report_config);
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

    /// Every route with a budget of its own is named by the edge; anything else
    /// on the relay's web surface falls to `relay-web`.
    #[test]
    fn views_name_their_own_budgets() {
        let admin = Surface::https(Host::Admin);
        for (path, view) in [
            ("/api/account/signup", ViewId::ACCOUNT_SIGNUP),
            ("/api/account/login", ViewId::ACCOUNT_LOGIN),
            ("/api/account/login/verify", ViewId::ACCOUNT_LOGIN),
            ("/api/account/password", ViewId::ACCOUNT_LOGIN),
            ("/api/account/login/resend", ViewId::ACCOUNT_RESEND),
            ("/api/account/resend", ViewId::ACCOUNT_RESEND),
            ("/api/account/reset/request", ViewId::ACCOUNT_RESEND),
            ("/api/account/pair/begin", ViewId::ACCOUNT_PAIR),
            ("/app", ViewId::RELAY_WEB),
        ] {
            assert_eq!(view_for(admin, path), view, "{path}");
        }
        // The pairing channel charges its budget itself, once the proof is in.
        assert_eq!(
            view_for(admin, weaver_proto::pair::PAIR_CHANNEL_PATH),
            ViewId::RELAY_WEB
        );
    }

    /// A passkey ceremony must not be charged to the password login's budget:
    /// it is cryptographic, so what it bounds is work rather than a guessing
    /// surface, and the two must never share a bucket (WVR-163).
    #[test]
    fn every_passkey_endpoint_has_its_own_budget() {
        let admin = Surface::https(Host::Admin);
        for path in [
            "/api/account/passkey/begin",
            "/api/account/passkey/finish",
            "/api/account/passkey/step-up/begin",
            "/api/account/passkey/step-up/finish",
            "/api/account/passkeys",
            "/api/account/passkeys/begin",
            "/api/account/passkeys/finish",
            "/api/account/passkeys/7/remove",
        ] {
            assert_eq!(view_for(admin, path), ViewId::ACCOUNT_PASSKEY, "{path}");
        }
    }

    /// The other surfaces keep their views: proxied traffic is unbudgeted, the
    /// apex's ALTCHA API has its own budget, and the admin plane's budgets are
    /// never reached from another host.
    #[test]
    fn other_surfaces_keep_their_views() {
        let apex = Surface::https(Host::TunnelRoot);
        assert_eq!(
            view_for(apex, "/altcha/challenge"),
            ViewId::ALTCHA_CHALLENGE
        );
        assert_eq!(view_for(apex, "/altcha/verify"), ViewId::ALTCHA_VERIFY);
        assert_eq!(view_for(apex, "/api/account/login"), ViewId::RELAY_WEB);
        assert_eq!(
            view_for(Surface::https(Host::Tunneled), "/api/account/login"),
            ViewId::TUNNEL
        );
        assert_eq!(
            view_for(Surface::cleartext(), "/api/account/login"),
            ViewId::RELAY_WEB
        );
    }
}
