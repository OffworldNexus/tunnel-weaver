//! End-to-end ACME tests against a Pebble ACME server container.
//!
//! Marked with `#[ignore = "e2e"]` so the fast unit/integration test matrix
//! runs in seconds, while the GitHub Actions `e2e-linux` job exercises the full
//! ACME order lifecycle, EAB authentication, and TLS-ALPN-01 verification against Pebble.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use weaver_server::cert::CertManager;
use weaver_server::cert::challenge::ChallengeRegistry;
use weaver_server::cert::clock::SystemClock;
use weaver_server::cert::resolver::CertResolver;
use weaver_server::cert::state::CertState;
use weaver_server::config::Config;
use weaver_server::edge::http::run_http_server;
use weaver_server::edge::https::run_https_server;
use weaver_server::edge::tls::{create_server_config, generate_placeholder_certified_key};
use weaver_server::store::Store;

const PEBBLE_DIR: &str = "https://localhost:14000/dir";
const PEBBLE_ROOT_CA: &str = include_str!("../../../ci/pebble/pebble.minica.pem");

/// Global lock ensuring Pebble E2E tests run sequentially on ports 5001/5002.
static PEBBLE_TEST_LOCK: Mutex<()> = Mutex::const_new(());

/// Checks if Pebble ACME server is running locally on port 14000.
async fn is_pebble_available() -> bool {
    tokio::net::TcpStream::connect("127.0.0.1:14000")
        .await
        .is_ok()
}

fn build_dns_response(buf: &[u8]) -> Option<Vec<u8>> {
    if buf.len() < 12 {
        return None;
    }
    let mut resp = Vec::with_capacity(128);
    resp.extend_from_slice(&buf[..2]); // tx id
    resp.extend_from_slice(b"\x81\x80"); // standard response flags
    resp.extend_from_slice(&buf[4..6]); // question count
    resp.extend_from_slice(b"\x00\x01\x00\x00\x00\x00"); // 1 answer

    let mut idx = 12;
    while idx < buf.len() && buf[idx] != 0 {
        idx += 1 + buf[idx] as usize;
    }
    let qname_end = (idx + 5).min(buf.len());
    resp.extend_from_slice(&buf[12..qname_end]);

    // Answer: name pointer 0xc00c, Type A (1), Class IN (1), TTL 60s, Length 4, 127.0.0.1
    resp.extend_from_slice(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01");
    Some(resp)
}

/// In-test DNS server answering all UDP and TCP queries with `127.0.0.1` for Pebble's `-dnsserver 127.0.0.1:1053`.
async fn spawn_dns_stub(token: CancellationToken) {
    let udp = match UdpSocket::bind("127.0.0.1:1053").await {
        Ok(s) => s,
        Err(_) => return,
    };
    let tcp = match TcpListener::bind("127.0.0.1:1053").await {
        Ok(s) => s,
        Err(_) => return,
    };

    let tok1 = token.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            tokio::select! {
                _ = tok1.cancelled() => break,
                res = udp.recv_from(&mut buf) => {
                    let (len, src) = match res {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    if let Some(resp) = build_dns_response(&buf[..len]) {
                        let _ = udp.send_to(&resp, src).await;
                    }
                }
            }
        }
    });

    let tok2 = token;
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tok2.cancelled() => break,
                res = tcp.accept() => {
                    let (mut stream, _) = match res {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    tokio::spawn(async move {
                        let mut len_buf = [0u8; 2];
                        if stream.read_exact(&mut len_buf).await.is_err() {
                            return;
                        }
                        let msg_len = u16::from_be_bytes(len_buf) as usize;
                        let mut msg_buf = vec![0u8; msg_len];
                        if stream.read_exact(&mut msg_buf).await.is_err() {
                            return;
                        }
                        if let Some(resp) = build_dns_response(&msg_buf) {
                            let resp_len = (resp.len() as u16).to_be_bytes();
                            let _ = stream.write_all(&resp_len).await;
                            let _ = stream.write_all(&resp).await;
                        }
                    });
                }
            }
        }
    });
}

#[derive(Debug)]
struct DangerousNoVerify;
impl rustls::client::danger::ServerCertVerifier for DangerousNoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

/// Fetches the dynamic Root CA from Pebble's management port `https://127.0.0.1:15000/roots/0`,
/// falling back to the bundled `pebble.minica.pem`.
async fn fetch_pebble_issuing_ca() -> Option<String> {
    let provider = rustls::crypto::ring::default_provider();
    let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DangerousNoVerify))
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(client_config));

    if let Ok(tcp) = TcpStream::connect("127.0.0.1:15000").await {
        let server_name = ServerName::try_from("localhost").unwrap().to_owned();
        if let Ok(mut tls) = connector.connect(server_name, tcp).await {
            let req =
                b"GET /roots/0 HTTP/1.1\r\nHost: localhost:15000\r\nConnection: close\r\n\r\n";
            if tls.write_all(req).await.is_ok() {
                let mut resp = String::new();
                if tls.read_to_string(&mut resp).await.is_ok()
                    && let Some(start) = resp.find("-----BEGIN CERTIFICATE-----")
                    && let Some(end) = resp.find("-----END CERTIFICATE-----")
                {
                    return Some(resp[start..end + "-----END CERTIFICATE-----".len()].to_string());
                }
            }
        }
    }
    None
}

async fn create_pebble_trust_client_config() -> Arc<rustls::ClientConfig> {
    use rustls::pki_types::pem::PemObject;
    let mut root_store = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(PEBBLE_ROOT_CA.as_bytes()) {
        root_store.add(cert.unwrap()).unwrap();
    }

    if let Some(issuing_ca) = fetch_pebble_issuing_ca().await {
        for cert in CertificateDer::pem_slice_iter(issuing_ca.as_bytes()) {
            let _ = root_store.add(cert.unwrap());
        }
    }

    let provider = rustls::crypto::ring::default_provider();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

#[tokio::test]
#[ignore = "e2e"]
async fn test_pebble_e2e_issuance_and_lazy_ensure() {
    let _guard = PEBBLE_TEST_LOCK.lock().await;

    if !is_pebble_available().await {
        eprintln!("Skipping Pebble E2E test: Pebble not reachable on 127.0.0.1:14000");
        return;
    }

    let dns_token = CancellationToken::new();
    spawn_dns_stub(dns_token.clone()).await;

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("weaver.db");
    let store = Arc::new(Store::open(&db_path).unwrap());

    // Bind HTTP port 5002 (Pebble's default httpPort) and HTTPS port 5001 (Pebble's tlsPort)
    let http_listener = TcpListener::bind("0.0.0.0:5002").await.unwrap();
    let https_listener = TcpListener::bind("0.0.0.0:5001").await.unwrap();
    let https_port = https_listener.local_addr().unwrap().port();

    let root_domain = "pebble.test";
    let config = Arc::new(Config {
        root_domain: root_domain.into(),
        admin_email: "admin@pebble.test".into(),
        acme_provider: "custom".into(),
        listen_http: "0.0.0.0:5002".parse().unwrap(),
        listen_https: format!("0.0.0.0:{https_port}").parse().unwrap(),
        control_socket: "/tmp/sock".into(),
        acme_directory: Some(PEBBLE_DIR.into()),
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: Some(PEBBLE_ROOT_CA.into()),
        acme_fallback_providers: Vec::new(),
    });

    let placeholder = generate_placeholder_certified_key(root_domain).unwrap();
    let challenge_registry = Arc::new(ChallengeRegistry::new());
    let resolver = Arc::new(CertResolver::new(
        root_domain.into(),
        placeholder,
        Arc::clone(&challenge_registry),
    ));

    let manager = CertManager::new(
        Arc::clone(&config),
        Arc::clone(&store),
        Arc::clone(&resolver),
        Arc::clone(&challenge_registry),
        Arc::new(SystemClock),
        true,
    );

    let shutdown_token = CancellationToken::new();

    // Start HTTP and HTTPS servers
    let reg_clone = Arc::clone(&challenge_registry);
    let s_tok1 = shutdown_token.clone();
    tokio::spawn(async move {
        run_http_server(
            http_listener,
            root_domain.into(),
            https_port,
            Some(reg_clone),
            s_tok1,
        )
        .await;
    });

    let tls_config =
        create_server_config(Arc::clone(&resolver) as Arc<dyn rustls::server::ResolvesServerCert>)
            .unwrap();
    let res_clone = Arc::clone(&resolver);
    let s_tok2 = shutdown_token.clone();
    tokio::spawn(async move {
        run_https_server(
            https_listener,
            tls_config,
            root_domain.into(),
            Some(res_clone),
            s_tok2,
        )
        .await;
    });

    // 1. Initial eager issuance for root domain
    manager.init().unwrap();
    manager.spawn_eager_order_if_pending();

    // Wait up to 30 seconds for root domain cert to become Issued
    let mut issued = false;
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let CertState::Issued { .. } = manager.status(root_domain) {
            issued = true;
            break;
        }
    }
    assert!(
        issued,
        "Root domain certificate should transition to Issued within 30s"
    );

    // 2. Client trusting Pebble root CA connects and gets valid response with HSTS
    let client_config = create_pebble_trust_client_config().await;
    let connector = TlsConnector::from(client_config);

    let tcp = TcpStream::connect(format!("127.0.0.1:{https_port}"))
        .await
        .unwrap();
    let server_name = ServerName::try_from(root_domain).unwrap().to_owned();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();
    tls.write_all(b"GET / HTTP/1.1\r\nHost: pebble.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    tls.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    assert!(resp.contains("strict-transport-security"));

    // 3. Lazy ensure on subdomain
    let sub = "web.laptop.remy.pebble.test";
    assert!(manager.ensure(sub).await.is_ok());
    assert!(matches!(manager.status(sub), CertState::Issued { .. }));

    // 4. Subsequent ensure on same subdomain is an immediate no-op
    assert!(manager.ensure(sub).await.is_ok());

    shutdown_token.cancel();
    dns_token.cancel();
}

#[tokio::test]
#[ignore = "e2e"]
async fn test_pebble_e2e_tls_alpn_01_with_unbound_port_80() {
    let _guard = PEBBLE_TEST_LOCK.lock().await;

    if !is_pebble_available().await {
        eprintln!("Skipping Pebble E2E test: Pebble not reachable on 127.0.0.1:14000");
        return;
    }

    let dns_token = CancellationToken::new();
    spawn_dns_stub(dns_token.clone()).await;

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("weaver.db");
    let store = Arc::new(Store::open(&db_path).unwrap());

    // Port 80 listener is UNBOUND. Port 5001 is bound for HTTPS.
    let https_listener = TcpListener::bind("0.0.0.0:5001").await.unwrap();
    let https_port = https_listener.local_addr().unwrap().port();

    let root_domain = "pebble.test";
    let config = Arc::new(Config {
        root_domain: root_domain.into(),
        admin_email: "admin@pebble.test".into(),
        acme_provider: "custom".into(),
        listen_http: "0.0.0.0:0".parse().unwrap(), // Unbound HTTP
        listen_https: format!("0.0.0.0:{https_port}").parse().unwrap(),
        control_socket: "/tmp/sock".into(),
        acme_directory: Some(PEBBLE_DIR.into()),
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: Some(PEBBLE_ROOT_CA.into()),
        acme_fallback_providers: Vec::new(),
    });

    let placeholder = generate_placeholder_certified_key(root_domain).unwrap();
    let challenge_registry = Arc::new(ChallengeRegistry::new());
    let resolver = Arc::new(CertResolver::new(
        root_domain.into(),
        placeholder,
        Arc::clone(&challenge_registry),
    ));

    // Notice: is_http_enabled is FALSE -> forces TLS-ALPN-01 challenge
    let manager = CertManager::new(
        Arc::clone(&config),
        Arc::clone(&store),
        Arc::clone(&resolver),
        Arc::clone(&challenge_registry),
        Arc::new(SystemClock),
        false,
    );

    let shutdown_token = CancellationToken::new();

    let tls_config =
        create_server_config(Arc::clone(&resolver) as Arc<dyn rustls::server::ResolvesServerCert>)
            .unwrap();
    let res_clone = Arc::clone(&resolver);
    let s_tok = shutdown_token.clone();
    tokio::spawn(async move {
        run_https_server(
            https_listener,
            tls_config,
            root_domain.into(),
            Some(res_clone),
            s_tok,
        )
        .await;
    });

    // Issuance with TLS-ALPN-01 against Pebble
    let sub = "subdomain.pebble.test";
    let res = manager.ensure(sub).await;
    if let Err(e) = &res {
        eprintln!("TLS-ALPN-01 issuance result: {e}");
    }
    assert!(res.is_ok());

    shutdown_token.cancel();
    dns_token.cancel();
}
