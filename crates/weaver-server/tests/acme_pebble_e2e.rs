//! End-to-end ACME tests against a Pebble ACME server container.
//!
//! Marked with `#[ignore = "e2e"]` so the fast unit/integration test matrix
//! runs in seconds, while the GitHub Actions `e2e-linux` job exercises the full
//! ACME order lifecycle, EAB authentication, and TLS-ALPN-01 verification against Pebble.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use weave::{ServiceSpec, StartOptions, Target};

use weaver_server::cert::CertManager;
use weaver_server::cert::clock::SystemClock;
use weaver_server::cert::resolver::CertResolver;
use weaver_server::cert::state::CertState;
use weaver_server::config::Config;
use weaver_server::edge::http::run_http_server;
use weaver_server::edge::https::run_https_server;
use weaver_server::edge::tls::create_server_config;
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

/// Serves the relay's authoritative DNS zone (OFF-190) on the port Pebble is
/// pointed at (`-dnsserver 127.0.0.1:1053`). The responder reads DNS-01 TXT
/// values straight from the shared `Store`, so the challenge the ACME engine
/// publishes is visible to Pebble without a test-only stub.
async fn spawn_dns_responder(
    config: &Config,
    store: Arc<Store>,
    token: CancellationToken,
) -> Option<(tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>)> {
    let responder = Arc::new(weaver_server::dns::DnsResponder::new(config, store));

    let mut udp = None;
    let mut tcp = None;
    for _ in 0..50 {
        if let Ok(u) = UdpSocket::bind("127.0.0.1:1053").await
            && let Ok(t) = TcpListener::bind("127.0.0.1:1053").await
        {
            udp = Some(u);
            tcp = Some(t);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let udp = udp?;
    let tcp = tcp?;

    // Hand the join handles back so a test can await them on teardown. The two
    // Pebble tests both need 127.0.0.1:1053 (Pebble's `-dnsserver` is fixed), so
    // releasing the socket deterministically before the next test binds is
    // required, not just a 200ms sleep.
    let udp_task = tokio::spawn(weaver_server::dns::run_udp(
        udp,
        Arc::clone(&responder),
        token.clone(),
    ));
    let tcp_task = tokio::spawn(weaver_server::dns::run_tcp(tcp, responder, token));
    Some((udp_task, tcp_task))
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

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("weaver.db");
    let store = Arc::new(Store::open(&db_path).await.unwrap());

    // Bind HTTP port 5002 (Pebble's default httpPort) and HTTPS port 5001 (Pebble's tlsPort)
    let http_listener = TcpListener::bind("0.0.0.0:5002").await.unwrap();
    let https_listener = TcpListener::bind("0.0.0.0:5001").await.unwrap();
    let https_port = https_listener.local_addr().unwrap().port();

    let root_domain = "pebble.test";
    let config = Arc::new(Config {
        root_domain: root_domain.into(),
        admin_domain: "relay-admin.test".into(),
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
        usage_flush_interval_secs: 60,
        relay_ips: vec!["127.0.0.1".parse().unwrap()],
        setup_complete: true,
    });

    let dns_token = CancellationToken::new();
    let dns_tasks = spawn_dns_responder(&config, Arc::clone(&store), dns_token.clone())
        .await
        .expect("test DNS responder could not bind 127.0.0.1:1053");

    let resolver = Arc::new(CertResolver::new(root_domain.into()));

    let manager = CertManager::new(
        Arc::clone(&config),
        Arc::clone(&store),
        Arc::clone(&resolver),
        Arc::new(SystemClock),
    );

    let shutdown_token = CancellationToken::new();

    // Start HTTP and HTTPS servers
    let s_tok1 = shutdown_token.clone();
    let http_store = Arc::clone(&store);
    tokio::spawn(async move {
        run_http_server(
            http_listener,
            root_domain.into(),
            https_port,
            http_store,
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
    manager.init().await.unwrap();
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

    // 3. Lazy ensure on a flat service hostname (maps to the wildcard apex)
    let sub = "remy-laptop-web.pebble.test";
    assert!(manager.ensure(sub).await.is_ok());
    assert!(matches!(
        manager.status(root_domain),
        CertState::Issued { .. }
    ));

    // 4. Subsequent ensure on same subdomain is an immediate no-op
    assert!(manager.ensure(sub).await.is_ok());

    shutdown_token.cancel();
    dns_token.cancel();
    // Await the responder tasks so 127.0.0.1:1053 is released before the next
    // Pebble test binds it.
    let (dns_udp, dns_tcp) = dns_tasks;
    let _ = tokio::join!(dns_udp, dns_tcp);
}

#[tokio::test]
#[ignore = "e2e"]
async fn test_pebble_e2e_tunnel_registration_and_proxying() {
    let _guard = PEBBLE_TEST_LOCK.lock().await;

    if !is_pebble_available().await {
        eprintln!("Skipping Pebble E2E test: Pebble not reachable on 127.0.0.1:14000");
        return;
    }

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("weaver.db");
    let store = Arc::new(Store::open(&db_path).await.unwrap());

    let http_listener = TcpListener::bind("0.0.0.0:5002").await.unwrap();
    let https_listener = TcpListener::bind("0.0.0.0:5001").await.unwrap();
    let https_port = https_listener.local_addr().unwrap().port();

    let root_domain = "pebble.test";
    let config = Arc::new(Config {
        root_domain: root_domain.into(),
        admin_domain: "relay-admin.test".into(),
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
        usage_flush_interval_secs: 60,
        relay_ips: vec!["127.0.0.1".parse().unwrap()],
        setup_complete: true,
    });

    let dns_token = CancellationToken::new();
    let dns_tasks = spawn_dns_responder(&config, Arc::clone(&store), dns_token.clone())
        .await
        .expect("test DNS responder could not bind 127.0.0.1:1053");

    let resolver = Arc::new(CertResolver::new(root_domain.into()));

    let manager = CertManager::new(
        Arc::clone(&config),
        Arc::clone(&store),
        Arc::clone(&resolver),
        Arc::new(SystemClock),
    );

    let identity_resolver = Arc::new(weaver_server::tunnel::StoreIdentityResolver::new(
        store.as_ref().clone(),
    ));
    let registry = Arc::new(weaver_server::tunnel::TunnelRegistry::new(
        root_domain.into(),
        Arc::clone(&manager),
        identity_resolver,
        store.as_ref().clone(),
        Arc::new(weaver_server::metering::MeteringManager::new(
            store.as_ref().clone(),
            std::time::Duration::from_secs(60),
        )),
    ));

    let shutdown_token = CancellationToken::new();

    let s_tok1 = shutdown_token.clone();
    let http_store = Arc::clone(&store);
    tokio::spawn(async move {
        run_http_server(
            http_listener,
            root_domain.into(),
            https_port,
            http_store,
            s_tok1,
        )
        .await;
    });

    let tls_config =
        create_server_config(Arc::clone(&resolver) as Arc<dyn rustls::server::ResolvesServerCert>)
            .unwrap();
    let res_clone = Arc::clone(&resolver);
    let reg_server_clone = Arc::clone(&registry);
    let s_tok2 = shutdown_token.clone();
    tokio::spawn(async move {
        weaver_server::edge::https::run_https_server_with_registry(
            https_listener,
            tls_config,
            root_domain.into(),
            Some(res_clone),
            Some(reg_server_clone),
            s_tok2,
        )
        .await;
    });

    // 1. Initial eager issuance for root domain
    manager.init().await.unwrap();
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

    // Write Pebble root CA and dynamic intermediate CA to temp file for weave client
    let mut ca_bundle = PEBBLE_ROOT_CA.to_string();
    if let Some(issuing_ca) = fetch_pebble_issuing_ca().await {
        ca_bundle.push('\n');
        ca_bundle.push_str(&issuing_ca);
    }
    let mut ca_file = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut ca_file, ca_bundle.as_bytes()).unwrap();

    // Start a real in-process origin for `weave start` to proxy to.
    let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin_listener.local_addr().unwrap().port();
    let origin_token = CancellationToken::new();
    let o_tok = origin_token.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = tokio::select! {
                _ = o_tok.cancelled() => break,
                r = origin_listener.accept() => match r {
                    Ok(pair) => pair,
                    Err(_) => continue,
                },
            };
            tokio::spawn(async move {
                let service = service_fn(|_req: Request<hyper::body::Incoming>| async {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("x-origin", "yes")
                            .body(Full::new(Bytes::from_static(b"hello from origin")))
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    // Start weave client
    let client_token = CancellationToken::new();
    let c_tok = client_token.clone();
    let ca_path = ca_file.path().to_path_buf();
    let opts = StartOptions {
        specs: vec![ServiceSpec {
            service: "web".to_string(),
            target: Target::parse(&format!("http://127.0.0.1:{origin_port}")).unwrap(),
        }],
        server: format!("pebble.test:{https_port}"),
        insecure_root_ca: Some(ca_path),
        insecure_targets: Vec::new(),
        preserve_host: Vec::new(),
        no_rewrite: Vec::new(),
        append_forwarded: Vec::new(),
        quiet: true,
        verbose: false,
    };
    let client_task = tokio::spawn(async move { weave::run_start_with_token(opts, c_tok).await });

    // Wait for certificate to be issued and service registered
    let target_hostname = "poc-laptop-web.pebble.test";
    let mut ready = false;
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if registry.resolve(target_hostname).await.is_some()
            && matches!(manager.status(root_domain), CertState::Issued { .. })
        {
            ready = true;
            break;
        }
    }
    assert!(
        ready,
        "Tunnel service should register and obtain ACME cert from Pebble within 30s"
    );

    // Visitor request to tunnel endpoint
    let client_config = create_pebble_trust_client_config().await;
    let connector = TlsConnector::from(client_config);

    let tcp = TcpStream::connect(format!("127.0.0.1:{https_port}"))
        .await
        .unwrap();
    let server_name = ServerName::try_from(target_hostname).unwrap().to_owned();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();
    tls.write_all(
        format!("GET /hello?x=1 HTTP/1.1\r\nHost: {target_hostname}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut resp = String::new();
    tls.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "resp: {resp}");
    assert!(resp.contains("hello from origin"), "resp: {resp}");

    // Terminate client
    client_token.cancel();
    let _ = client_task.await;

    // Verify 404 after unregister
    tokio::time::sleep(Duration::from_millis(300)).await;
    let tcp2 = TcpStream::connect(format!("127.0.0.1:{https_port}"))
        .await
        .unwrap();
    let client_config2 = create_pebble_trust_client_config().await;
    let connector2 = TlsConnector::from(client_config2);
    let server_name2 = ServerName::try_from(target_hostname).unwrap().to_owned();
    let mut tls2 = connector2.connect(server_name2, tcp2).await.unwrap();
    tls2.write_all(
        format!("GET /hello HTTP/1.1\r\nHost: {target_hostname}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut resp2 = String::new();
    tls2.read_to_string(&mut resp2).await.unwrap();
    assert!(resp2.starts_with("HTTP/1.1 404 Not Found"));

    shutdown_token.cancel();
    dns_token.cancel();
    // Await the responder tasks so 127.0.0.1:1053 is released before the next
    // Pebble test binds it.
    let (dns_udp, dns_tcp) = dns_tasks;
    let _ = tokio::join!(dns_udp, dns_tcp);
}
