//! WVR-135: the relay web surface runs the safety pipeline and answers
//! `429 + Retry-After`, while control-plane routes stay reachable.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use weaver_server::cert::managed::ManagedCerts;
use weaver_server::cert::solver::Http01Solver;
use weaver_server::config::{AbuseConfig, BudgetConfig};
use weaver_server::edge::http::{HttpEdgeConfig, run_http_server_full};
use weaver_server::edge::https::{HttpsEdgeConfig, run_https_server_full};
use weaver_server::edge::tls::create_self_signed_server_config;
use weaver_server::{Config, Store, abuse};

/// A per-host budget of exactly one request, refilling over an hour, with a lax
/// network backstop so only the host key is the tight budget in tests.
fn tight_abuse() -> AbuseConfig {
    AbuseConfig {
        enabled: true,
        peer_host: BudgetConfig {
            burst: 1,
            refill_units: 1,
            refill_per_secs: 3600,
        },
        peer_network: BudgetConfig {
            burst: 1000,
            refill_units: 1000,
            refill_per_secs: 1,
        },
        retry_after_cap_secs: 60,
        bucket_ttl_secs: 3600,
        altcha: None,
    }
}

fn sample_config(abuse: Option<AbuseConfig>) -> Config {
    Config {
        tunnel_domain: "weaver.test".into(),
        admin_domain: "relay-admin.test".into(),
        admin_email: "admin@weaver.test".into(),
        acme_provider: "letsencrypt-staging".into(),
        listen_http: SocketAddr::from(([127, 0, 0, 1], 0)),
        listen_https: SocketAddr::from(([127, 0, 0, 1], 0)),
        control_socket: std::env::temp_dir().join("weaver-abuse-test.sock"),
        acme_directory: None,
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: None,
        acme_fallback_providers: Vec::new(),
        usage_flush_interval_secs: 60,
        relay_ips: Vec::new(),
        setup_complete: false,
        email: None,
        abuse,
    }
}

/// A file-backed store: SQLite `:memory:` would open a fresh database per pool
/// connection, so the limiter state would not be shared across requests.
async fn test_store() -> Store {
    let dir = tempfile::tempdir().unwrap().keep();
    Store::open(dir.join("test.db")).await.unwrap()
}

async fn http_request(addr: SocketAddr, raw: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(raw.as_bytes()).await.unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    resp
}

#[tokio::test]
async fn cleartext_surface_is_throttled_but_acme_is_exempt() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let store = test_store().await;
    let cfg = sample_config(Some(tight_abuse()));
    let guard = abuse::build(&cfg, store.clone());
    store
        .publish_http01("tok", "key-auth", None, 0)
        .await
        .unwrap();

    let token = shutdown.clone();
    let server = tokio::spawn(run_http_server_full(
        listener,
        HttpEdgeConfig {
            tunnel_domain: "weaver.test".into(),
            https_port: 443,
            challenge_responders: vec![Arc::new(Http01Solver::new(Arc::new(store.clone())))],
            guard,
        },
        token,
    ));

    let resp = http_request(
        addr,
        "GET / HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 308"), "got {resp:?}");

    let resp = http_request(
        addr,
        "GET /again HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        resp.starts_with("HTTP/1.1 429 Too Many Requests"),
        "got {resp:?}"
    );
    assert!(resp.contains("x-weaver-throttled: relay-web"));
    assert!(resp.contains("retry-after:"));
    assert!(resp.contains("content-security-policy:"));

    // ACME HTTP-01 is answered before the pipeline, so it stays reachable.
    let resp = http_request(
        addr,
        "GET /.well-known/acme-challenge/tok HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200"), "got {resp:?}");
    assert!(resp.ends_with("key-auth"));

    shutdown.cancel();
    server.await.unwrap();
}

#[tokio::test]
async fn cleartext_surface_still_blocks_scanner_probes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let store = test_store().await;
    let cfg = sample_config(Some(tight_abuse()));
    let guard = abuse::build(&cfg, store.clone());

    let token = shutdown.clone();
    let server = tokio::spawn(run_http_server_full(
        listener,
        HttpEdgeConfig {
            tunnel_domain: "weaver.test".into(),
            https_port: 443,
            challenge_responders: Vec::new(),
            guard,
        },
        token,
    ));

    let resp = http_request(
        addr,
        "GET /.env HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 403"), "got {resp:?}");
    assert!(resp.contains("x-weaver-blocked: dotfile"));

    shutdown.cancel();
    server.await.unwrap();
}

#[tokio::test]
async fn disabling_abuse_leaves_the_surface_unchanged() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let store = test_store().await;
    let cfg = sample_config(Some(AbuseConfig {
        enabled: false,
        ..tight_abuse()
    }));
    // A disabled block drops the relay-web budget; the budget pass itself stays
    // because the always-on ALTCHA API is budgeted.
    let guard = abuse::build(&cfg, store.clone());
    assert_eq!(guard.pass_names(), vec!["scanner", "budget"]);

    let token = shutdown.clone();
    let server = tokio::spawn(run_http_server_full(
        listener,
        HttpEdgeConfig {
            tunnel_domain: "weaver.test".into(),
            https_port: 443,
            challenge_responders: Vec::new(),
            guard,
        },
        token,
    ));

    for _ in 0..5 {
        let resp = http_request(
            addr,
            "GET / HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 308"), "got {resp:?}");
    }

    shutdown.cancel();
    server.await.unwrap();
}

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
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

fn client_config() -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TestInsecureCertVerifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

async fn https_request(addr: SocketAddr, sni: &str, raw: &str) -> String {
    let connector = TlsConnector::from(client_config());
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from(sni).unwrap().to_owned();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();
    tls.write_all(raw.as_bytes()).await.unwrap();
    let mut resp = String::new();
    tls.read_to_string(&mut resp).await.unwrap();
    resp
}

#[tokio::test]
async fn https_apex_is_throttled_but_health_is_exempt() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let store = test_store().await;
    let cfg = sample_config(Some(tight_abuse()));
    let guard = abuse::build(&cfg, store.clone());
    let server_tls = create_self_signed_server_config("weaver.test").unwrap();

    let token = shutdown.clone();
    let server = tokio::spawn(run_https_server_full(
        listener,
        server_tls,
        HttpsEdgeConfig {
            managed: Arc::new(ManagedCerts::from_config(&cfg)),
            cert_resolver: None,
            cert_manager: None,
            tunnel_registry: None,
            guard,
            altcha: None,
        },
        token,
    ));

    let resp = https_request(
        addr,
        "weaver.test",
        "GET / HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200"), "got {resp:?}");

    let resp = https_request(
        addr,
        "weaver.test",
        "GET /again HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 429"), "got {resp:?}");
    assert!(resp.contains("x-weaver-throttled: relay-web"));

    // Readiness is exempt, so it is served even with the budget exhausted.
    let resp = https_request(
        addr,
        "weaver.test",
        "GET /healthz HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200"), "got {resp:?}");

    shutdown.cancel();
    server.await.unwrap();
}
