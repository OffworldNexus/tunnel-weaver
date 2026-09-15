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
use weaver_server::edge::https::run_https_server;
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

async fn spawn_test_https_server(root_domain: &str) -> (std::net::SocketAddr, CancellationToken) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_tls = create_self_signed_server_config(root_domain).unwrap();
    let shutdown_token = CancellationToken::new();

    let token_clone = shutdown_token.clone();
    let root = root_domain.to_string();
    tokio::spawn(async move {
        run_https_server(listener, server_tls, root, None, token_clone).await;
    });

    (addr, shutdown_token)
}

// OFF-70: Security rule — enforce strict HTTPS serving and hardened security headers
// (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) on root domain responses.
#[tokio::test]
async fn test_https_root_domain_endpoints() {
    let root_domain = "weaver.test";
    let (addr, shutdown_token) = spawn_test_https_server(root_domain).await;
    let client_config = create_test_client_config(vec![b"http/1.1".to_vec()]);
    let connector = TlsConnector::from(client_config);

    // 1. GET / on root_domain -> 200 with welcome HTML and security headers
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from(root_domain).unwrap().to_owned();
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

    // 2. GET /healthz on root_domain -> 200 with "ok"
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from(root_domain).unwrap().to_owned();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    tls.write_all(b"GET /healthz HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    tls.read_to_string(&mut resp).await.unwrap();

    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    assert!(resp.contains("ok"));

    // 3. GET /unmapped on root_domain -> 404
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from(root_domain).unwrap().to_owned();
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
    let root_domain = "weaver.test";
    let (addr, shutdown_token) = spawn_test_https_server(root_domain).await;
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
    assert!(resp.contains("content-security-policy: default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"));

    shutdown_token.cancel();
}

// OFF-70: Security rule — reject requests with mismatched TLS SNI and Host header,
// unrecognized domains, or IP literals over HTTPS with status 421 Misdirected Request.
#[tokio::test]
async fn test_https_421_misdirected_requests() {
    let root_domain = "weaver.test";
    let (addr, shutdown_token) = spawn_test_https_server(root_domain).await;
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

#[tokio::test]
async fn test_https_http2_alpn_and_request() {
    let root_domain = "weaver.test";
    let (addr, shutdown_token) = spawn_test_https_server(root_domain).await;

    // Connect negotiating h2
    let client_config = create_test_client_config(vec![b"h2".to_vec()]);
    let connector = TlsConnector::from(client_config);

    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from(root_domain).unwrap().to_owned();
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
        .uri(format!("https://{root_domain}/"))
        .header(http::header::HOST, root_domain)
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let res = sender.send_request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&body_bytes);
    assert!(body.contains("Tunnel Weaver"));

    shutdown_token.cancel();
}
