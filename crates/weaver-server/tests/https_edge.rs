use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use weaver_server::Config;
use weaver_server::cert::managed::ManagedCerts;
use weaver_server::edge::https::{HttpsEdgeConfig, run_https_server, run_https_server_full};
use weaver_server::edge::tls::create_self_signed_server_config;

#[derive(Debug)]
struct TestInsecureCertVerifier;

impl ServerCertVerifier for TestInsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn create_test_client_config(alpn: Vec<Vec<u8>>) -> Arc<ClientConfig> {
    let provider = rustls::crypto::ring::default_provider();
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TestInsecureCertVerifier))
        .with_no_client_auth();
    config.alpn_protocols = alpn;
    Arc::new(config)
}

async fn spawn_test_https_server(tunnel_domain: &str) -> (std::net::SocketAddr, CancellationToken) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_tls = create_self_signed_server_config(tunnel_domain).unwrap();
    let shutdown_token = CancellationToken::new();

    let token_clone = shutdown_token.clone();
    let root = tunnel_domain.to_string();
    tokio::spawn(async move {
        run_https_server(listener, server_tls, root, None, token_clone).await;
    });

    (addr, shutdown_token)
}

// OFF-70: Security rule — enforce strict HTTPS serving and hardened security headers
// (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) on root domain responses.
#[tokio::test]
async fn test_https_tunnel_domain_endpoints() {
    let tunnel_domain = "weaver.test";
    let (addr, shutdown_token) = spawn_test_https_server(tunnel_domain).await;
    let client_config = create_test_client_config(vec![b"http/1.1".to_vec()]);
    let connector = TlsConnector::from(client_config);

    // 1. GET / on tunnel_domain -> 200 with welcome HTML and security headers
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from(tunnel_domain).unwrap().to_owned();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    tls.write_all(b"GET / HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    tls.read_to_string(&mut resp).await.unwrap();

    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    assert!(resp.contains("content-type: text/html; charset=utf-8"));
    assert!(resp.contains("content-security-policy: default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"));
    assert!(resp.contains("x-content-type-options: nosniff"));
    assert!(resp.contains("x-frame-options: DENY"));
    assert!(resp.contains("referrer-policy: no-referrer"));
    assert!(resp.contains("Tunnel Weaver"));
    assert!(resp.contains("Ready for connections."));
    assert!(resp.contains("<style>"));
    assert!(resp.contains("<svg"));

    // 2. GET /healthz on tunnel_domain -> 200 with "ok"
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from(tunnel_domain).unwrap().to_owned();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    tls.write_all(b"GET /healthz HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    tls.read_to_string(&mut resp).await.unwrap();

    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    assert!(resp.contains("ok"));

    // 3. GET /unmapped on tunnel_domain -> 404
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from(tunnel_domain).unwrap().to_owned();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    tls.write_all(b"GET /unmapped HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    tls.read_to_string(&mut resp).await.unwrap();

    assert!(resp.starts_with("HTTP/1.1 404 Not Found"));
    assert!(resp.contains("content-security-policy:"));

    shutdown_token.cancel();
}

// OFF-70: Failure mode — subdomain requests to unmapped tunnels return a branded 404 page
// rather than leaking internal routing details or serving the root domain.
#[tokio::test]
async fn test_https_subdomain_branded_404() {
    let tunnel_domain = "weaver.test";
    let (addr, shutdown_token) = spawn_test_https_server(tunnel_domain).await;
    let client_config = create_test_client_config(vec![b"http/1.1".to_vec()]);
    let connector = TlsConnector::from(client_config);

    let tcp = TcpStream::connect(addr).await.unwrap();
    let sub = "my-tunnel.weaver.test";
    let server_name = ServerName::try_from(sub).unwrap().to_owned();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    tls.write_all(format!("GET / HTTP/1.1\r\nHost: {sub}\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut resp = String::new();
    tls.read_to_string(&mut resp).await.unwrap();

    assert!(resp.starts_with("HTTP/1.1 404 Not Found"));
    assert!(resp.contains("content-type: text/html; charset=utf-8"));
    assert!(resp.contains("No Such Tunnel"));
    assert!(resp.contains("No tunnel here."));
    assert!(resp.contains("<style>"));
    assert!(resp.contains("<svg"));
    assert!(resp.contains("content-security-policy: default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"));

    shutdown_token.cancel();
}

// OFF-70: Security rule — reject requests with mismatched TLS SNI and Host header,
// unrecognized domains, or IP literals over HTTPS with status 421 Misdirected Request.
#[tokio::test]
async fn test_https_421_misdirected_requests() {
    let tunnel_domain = "weaver.test";
    let (addr, shutdown_token) = spawn_test_https_server(tunnel_domain).await;
    let client_config = create_test_client_config(vec![b"http/1.1".to_vec()]);
    let connector = TlsConnector::from(client_config);

    // Case 1: Unrecognized domain
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("unrecognized.com").unwrap().to_owned();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    tls.write_all(b"GET / HTTP/1.1\r\nHost: unrecognized.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    tls.read_to_string(&mut resp).await.unwrap();

    assert!(resp.starts_with("HTTP/1.1 421 Misdirected Request"));

    // Case 2: Mismatched SNI and Host header
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("weaver.test").unwrap().to_owned();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    tls.write_all(b"GET / HTTP/1.1\r\nHost: other.weaver.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    tls.read_to_string(&mut resp).await.unwrap();

    assert!(resp.starts_with("HTTP/1.1 421 Misdirected Request"));

    // Case 3: IP literal in Host header
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("weaver.test").unwrap().to_owned();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    tls.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    tls.read_to_string(&mut resp).await.unwrap();

    assert!(resp.starts_with("HTTP/1.1 421 Misdirected Request"));

    shutdown_token.cancel();
}

// OFF-86: RFC 9112 §3.2 — a request with no Host, more than one Host line,
// or a malformed Host value MUST get 400, not be routed on a guess (and not
// 421, which is for a well-formed host the edge does not serve).
#[tokio::test]
async fn test_https_400_missing_duplicate_or_invalid_host() {
    let tunnel_domain = "weaver.test";
    let (addr, shutdown_token) = spawn_test_https_server(tunnel_domain).await;
    let client_config = create_test_client_config(vec![b"http/1.1".to_vec()]);
    let connector = TlsConnector::from(client_config);

    let cases: &[(&str, &[u8])] = &[
        ("missing Host", b"GET / HTTP/1.1\r\n\r\n"),
        ("empty Host", b"GET / HTTP/1.1\r\nHost: \r\n\r\n"),
        (
            "duplicate identical Host",
            b"GET / HTTP/1.1\r\nHost: weaver.test\r\nHost: weaver.test\r\n\r\n",
        ),
        (
            "duplicate differing Host",
            b"GET / HTTP/1.1\r\nHost: weaver.test\r\nHost: other.weaver.test\r\n\r\n",
        ),
        (
            "comma-joined Host",
            b"GET / HTTP/1.1\r\nHost: weaver.test, other.example.com\r\n\r\n",
        ),
        (
            "Host with userinfo",
            b"GET / HTTP/1.1\r\nHost: admin@weaver.test\r\n\r\n",
        ),
        (
            "Host with path",
            b"GET / HTTP/1.1\r\nHost: weaver.test/evil\r\n\r\n",
        ),
    ];

    for (label, raw) in cases {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let server_name = ServerName::try_from(tunnel_domain).unwrap().to_owned();
        let mut tls = connector.connect(server_name, tcp).await.unwrap();
        tls.write_all(raw).await.unwrap();
        let mut resp = String::new();
        // No `Connection: close` on the request: the *server* must close.
        tls.read_to_string(&mut resp).await.unwrap();
        assert!(
            resp.starts_with("HTTP/1.1 400 Bad Request"),
            "{label}: expected 400, got {resp:?}"
        );
        assert!(
            resp.to_ascii_lowercase().contains("connection: close"),
            "{label}: 400 must close the connection"
        );
    }

    shutdown_token.cancel();
}

// OFF-86: RFC 9113 §8.3.1 — on h2 a `host` header that disagrees with
// `:authority` is malformed (400); one that agrees is fine.
#[tokio::test]
async fn test_https_h2_host_authority_mismatch_is_400() {
    let tunnel_domain = "weaver.test";
    let (addr, shutdown_token) = spawn_test_https_server(tunnel_domain).await;
    let client_config = create_test_client_config(vec![b"h2".to_vec()]);
    let connector = TlsConnector::from(client_config);

    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from(tunnel_domain).unwrap().to_owned();
    let tls = connector.connect(server_name, tcp).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("https://{tunnel_domain}/healthz"))
        .header(http::header::HOST, "other.weaver.test")
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();
    let res = sender.send_request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("https://{tunnel_domain}/healthz"))
        .header(http::header::HOST, "WEAVER.test:443")
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();
    let res = sender.send_request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    shutdown_token.cancel();
}

#[tokio::test]
async fn test_https_http2_alpn_and_request() {
    let tunnel_domain = "weaver.test";
    let (addr, shutdown_token) = spawn_test_https_server(tunnel_domain).await;

    // Connect negotiating h2
    let client_config = create_test_client_config(vec![b"h2".to_vec()]);
    let connector = TlsConnector::from(client_config);

    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from(tunnel_domain).unwrap().to_owned();
    let tls = connector.connect(server_name, tcp).await.unwrap();

    // Verify ALPN protocol negotiated is h2
    let negotiated = tls.get_ref().1.alpn_protocol();
    assert_eq!(negotiated, Some(b"h2".as_slice()));

    // Execute HTTP/2 request using hyper
    let io = TokioIo::new(tls);
    let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(io)
        .await
        .unwrap();

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("https://{tunnel_domain}/"))
        .header(http::header::HOST, tunnel_domain)
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let res = sender.send_request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&body_bytes);
    assert!(body.contains("Tunnel Weaver"));

    shutdown_token.cancel();
}

/// Sends a raw HTTP/1.1 request over TLS with the given SNI and returns the
/// full response text. The Host header is carried in `raw_request`.
async fn https_request(addr: std::net::SocketAddr, sni: &str, raw_request: &str) -> String {
    let client_config = create_test_client_config(vec![b"http/1.1".to_vec()]);
    let connector = TlsConnector::from(client_config);
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from(sni).unwrap().to_owned();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();
    tls.write_all(raw_request.as_bytes()).await.unwrap();
    let mut resp = String::new();
    tls.read_to_string(&mut resp).await.unwrap();
    resp
}

// WVR-134: The relay's own web endpoints (tunnel apex and admin host) refuse
// the same scanner probes the tunnelled surface already refuses, before any
// handler runs — while readiness and ordinary paths stay reachable.
#[tokio::test]
async fn test_https_apex_refuses_scanner_probes() {
    let tunnel_domain = "weaver.test";
    let (addr, shutdown_token) = spawn_test_https_server(tunnel_domain).await;

    // A scanner playbook probe is refused on the apex with the branded 403,
    // the reason header, and the shared security headers.
    let resp = https_request(
        addr,
        tunnel_domain,
        "GET /.env HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        resp.starts_with("HTTP/1.1 403 Forbidden"),
        "expected 403, got {resp:?}"
    );
    assert!(resp.contains("x-weaver-blocked: dotfile"));
    assert!(resp.contains("content-security-policy:"));

    // TRACE is refused anywhere, including the apex.
    let resp = https_request(
        addr,
        tunnel_domain,
        "TRACE / HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        resp.starts_with("HTTP/1.1 403 Forbidden"),
        "expected 403, got {resp:?}"
    );
    assert!(resp.contains("x-weaver-blocked: trace"));

    // Readiness and the welcome page remain usable.
    let resp = https_request(
        addr,
        tunnel_domain,
        "GET /healthz HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "got {resp:?}");

    let resp = https_request(
        addr,
        tunnel_domain,
        "GET / HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "got {resp:?}");

    // A risky-looking string after the query separator is not a probe: the
    // path is ordinary and must not be blocked (it falls through to the 404).
    let resp = https_request(
        addr,
        tunnel_domain,
        "GET /blog/post.html?q=.env HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        resp.starts_with("HTTP/1.1 404 Not Found"),
        "query string must not trigger the WAF; got {resp:?}"
    );

    // A legitimate `.well-known` path is not a dotfile probe either.
    let resp = https_request(
        addr,
        tunnel_domain,
        "GET /.well-known/security.txt HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        !resp.starts_with("HTTP/1.1 403"),
        "`.well-known` must not be blocked; got {resp:?}"
    );

    shutdown_token.cancel();
}

/// Spawns an HTTPS edge with both an admin host (HTTP-01) and a tunnel zone
/// (DNS-01), as the daemon runs it. `spawn_test_https_server` uses
/// `ManagedCerts::for_tunnel`, which has no admin certificate, so the admin
/// surface is unreachable through it.
async fn spawn_admin_https_server(
    tunnel_domain: &str,
    admin_domain: &str,
) -> (std::net::SocketAddr, CancellationToken) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_tls = create_self_signed_server_config(admin_domain).unwrap();
    let shutdown_token = CancellationToken::new();

    let cfg = Config {
        tunnel_domain: tunnel_domain.to_string(),
        admin_domain: admin_domain.to_string(),
        admin_email: "admin@weaver.test".to_string(),
        acme_provider: "letsencrypt-staging".to_string(),
        listen_http: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        listen_https: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        control_socket: std::env::temp_dir().join(format!(
            "weaver-test-admin-{}-{}.sock",
            std::process::id(),
            addr.port()
        )),
        acme_directory: None,
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: None,
        acme_fallback_providers: Vec::new(),
        usage_flush_interval_secs: 60,
        relay_ips: Vec::new(),
        setup_complete: false,
        email: None,
    };
    let config = HttpsEdgeConfig {
        managed: Arc::new(ManagedCerts::from_config(&cfg)),
        cert_resolver: None,
        cert_manager: None,
        tunnel_registry: None,
    };

    let token_clone = shutdown_token.clone();
    tokio::spawn(async move {
        run_https_server_full(listener, server_tls, config, token_clone).await;
    });

    (addr, shutdown_token)
}

// WVR-134: the admin host's web surface gets the same firewall the tunnel
// surfaces get, with its own policy context (it never serves the mux path).
#[tokio::test]
async fn test_https_admin_refuses_scanner_probes() {
    let admin_domain = "relay-admin.test";
    let (addr, shutdown_token) = spawn_admin_https_server("weaver.test", admin_domain).await;

    let resp = https_request(
        addr,
        admin_domain,
        "GET /.env HTTP/1.1\r\nHost: relay-admin.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        resp.starts_with("HTTP/1.1 403 Forbidden"),
        "expected 403, got {resp:?}"
    );
    assert!(resp.contains("x-weaver-blocked: dotfile"));
    assert!(resp.contains("content-security-policy:"));

    let resp = https_request(
        addr,
        admin_domain,
        "TRACE / HTTP/1.1\r\nHost: relay-admin.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        resp.starts_with("HTTP/1.1 403 Forbidden"),
        "expected 403, got {resp:?}"
    );
    assert!(resp.contains("x-weaver-blocked: trace"));

    // The admin welcome and readiness surfaces remain reachable.
    let resp = https_request(
        addr,
        admin_domain,
        "GET / HTTP/1.1\r\nHost: relay-admin.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "got {resp:?}");

    let resp = https_request(
        addr,
        admin_domain,
        "GET /healthz HTTP/1.1\r\nHost: relay-admin.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "got {resp:?}");

    shutdown_token.cancel();
}
