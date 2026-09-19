use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::Empty;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use tempfile::NamedTempFile;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use weaver_proto::control::RefusalCode;
use weaver_server::cert::resolver::CertResolver;
use weaver_server::cert::{CertManager, ChallengeRegistry, SystemClock};
use weaver_server::config::Config;
use weaver_server::edge::https::run_https_server_with_registry;
use weaver_server::store::Store;
use weaver_server::tunnel::TunnelRegistry;
use weaver_server::tunnel::{Identity, PocResolver, derive_hostname};

#[derive(Debug)]
struct AllowAllVerifier;

impl ServerCertVerifier for AllowAllVerifier {
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

fn create_client_tls_config(alpn: Vec<Vec<u8>>) -> Arc<ClientConfig> {
    let provider = rustls::crypto::ring::default_provider();
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AllowAllVerifier))
        .with_no_client_auth();
    config.alpn_protocols = alpn;
    Arc::new(config)
}

#[allow(dead_code)]
struct TestRelay {
    addr: SocketAddr,
    root_domain: String,
    registry: Arc<TunnelRegistry>,
    cert_manager: Arc<CertManager>,
    shutdown_token: CancellationToken,
    ca_pem_path: std::path::PathBuf,
    _temp_db: NamedTempFile,
    _temp_ca: NamedTempFile,
}

async fn spawn_test_relay(root_domain: &str) -> TestRelay {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let temp_db = NamedTempFile::new().unwrap();
    let store = Arc::new(Store::open(temp_db.path()).unwrap());

    let config = Arc::new(Config {
        root_domain: root_domain.to_string(),
        admin_email: "admin@weaver.test".to_string(),
        acme_provider: "letsencrypt-staging".to_string(),
        listen_http: SocketAddr::from(([127, 0, 0, 1], 0)),
        listen_https: addr,
        control_socket: std::path::PathBuf::from("/tmp/dummy.sock"),
        acme_directory: None,
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: None,
        acme_fallback_providers: Vec::new(),
    });

    let challenge_registry = Arc::new(ChallengeRegistry::new());
    let resolver = Arc::new(CertResolver::new(
        root_domain.to_string(),
        Arc::clone(&challenge_registry),
    ));

    let cert_manager = CertManager::new(
        Arc::clone(&config),
        Arc::clone(&store),
        Arc::clone(&resolver),
        Arc::clone(&challenge_registry),
        Arc::new(SystemClock),
        false,
    );

    // Generate self-signed cert for server
    let (server_tls, cert_pem) = {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec![
            root_domain.to_string(),
            format!("*.{}", root_domain),
            format!("*.laptop.poc.{}", root_domain),
            "127.0.0.1".to_string(),
            "localhost".to_string(),
        ])
        .unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let cert_der: Vec<CertificateDer<'static>> =
            rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let key_der = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();

        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_der, key_der)
            .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        (Arc::new(config), cert_pem)
    };

    let mut temp_ca = NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut temp_ca, cert_pem.as_bytes()).unwrap();
    let ca_pem_path = temp_ca.path().to_path_buf();

    let registry = Arc::new(TunnelRegistry::new(
        root_domain.to_string(),
        Arc::clone(&cert_manager),
        Arc::new(PocResolver),
    ));

    let shutdown_token = CancellationToken::new();
    let s_tok = shutdown_token.clone();
    let root = root_domain.to_string();
    let reg_clone = Arc::clone(&registry);

    tokio::spawn(async move {
        run_https_server_with_registry(listener, server_tls, root, None, Some(reg_clone), s_tok)
            .await;
    });

    TestRelay {
        addr,
        root_domain: root_domain.to_string(),
        registry,
        cert_manager,
        shutdown_token,
        ca_pem_path,
        _temp_db: temp_db,
        _temp_ca: temp_ca,
    }
}

#[tokio::test]
async fn test_tunnel_registration_and_http1_http2_proxying() {
    let root = "localhost";
    let relay = spawn_test_relay(root).await;

    // 1. Start weave poc client in background
    let client_token = CancellationToken::new();
    let c_tok = client_token.clone();
    let server_addr = format!("localhost:{}", relay.addr.port());
    let ca_path = relay.ca_pem_path.clone();

    let client_task = tokio::spawn(async move {
        weave::run_poc_with_token("web".to_string(), server_addr, Some(&ca_path), c_tok).await
    });

    // 2. Wait for registration in registry
    let expected_hostname = derive_hostname("web", &poc_identity(), root);
    let mut registered = false;
    for _ in 0..50 {
        if relay.registry.lookup(&expected_hostname).is_some() {
            registered = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(registered, "Service should register within 5 seconds");

    // Verify cert_manager active status
    assert!(relay.cert_manager.is_active(&expected_hostname));

    // 3. Visitor request over HTTP/1.1
    let client_tls_h1 = create_client_tls_config(vec![b"http/1.1".to_vec()]);
    let connector = TlsConnector::from(client_tls_h1);

    let tcp = TcpStream::connect(relay.addr).await.unwrap();
    let server_name = ServerName::try_from(expected_hostname.clone()).unwrap();
    let tls = connector.connect(server_name, tcp).await.unwrap();
    let io = TokioIo::new(tls);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method(Method::GET)
        .uri("/hello?x=1")
        .header("host", &expected_hostname)
        .header("x-custom-header", "custom-value")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        resp.headers().get("location").unwrap(),
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
    );

    // 4. Visitor request over HTTP/2
    let client_tls_h2 = create_client_tls_config(vec![b"h2".to_vec()]);
    let connector_h2 = TlsConnector::from(client_tls_h2);

    let tcp2 = TcpStream::connect(relay.addr).await.unwrap();
    let server_name2 = ServerName::try_from(expected_hostname.clone()).unwrap();
    let tls2 = connector_h2.connect(server_name2, tcp2).await.unwrap();
    let io2 = TokioIo::new(tls2);

    let (mut sender2, conn2) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io2)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn2.await;
    });

    let req2 = Request::builder()
        .method(Method::GET)
        .uri("/hello?x=1")
        .header("host", &expected_hostname)
        .body(Empty::<Bytes>::new())
        .unwrap();

    let resp2 = sender2.send_request(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::FOUND);
    assert_eq!(
        resp2.headers().get("location").unwrap(),
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
    );

    // 5. Terminate client and verify 404 within 1 second
    client_token.cancel();
    let _ = client_task.await;

    // Wait up to 1 second for route to be removed from registry
    let mut unreg = false;
    for _ in 0..10 {
        if relay.registry.lookup(&expected_hostname).is_none() {
            unreg = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(unreg, "Route should be removed within 1 second");
    assert!(!relay.cert_manager.is_active(&expected_hostname));

    // Send another request and expect 404
    let tcp3 = TcpStream::connect(relay.addr).await.unwrap();
    let client_tls_h1_new = create_client_tls_config(vec![b"http/1.1".to_vec()]);
    let connector3 = TlsConnector::from(client_tls_h1_new);
    let server_name3 = ServerName::try_from(expected_hostname.clone()).unwrap();
    let tls3 = connector3.connect(server_name3, tcp3).await.unwrap();
    let io3 = TokioIo::new(tls3);

    let (mut sender3, conn3) = hyper::client::conn::http1::handshake(io3).await.unwrap();
    tokio::spawn(async move {
        let _ = conn3.await;
    });

    let req3 = Request::builder()
        .method(Method::GET)
        .uri("/hello")
        .header("host", &expected_hostname)
        .body(Empty::<Bytes>::new())
        .unwrap();

    let resp3 = sender3.send_request(req3).await.unwrap();
    assert_eq!(resp3.status(), StatusCode::NOT_FOUND);

    relay.shutdown_token.cancel();
}

#[tokio::test]
async fn test_tunnel_supersession() {
    let root = "localhost";
    let relay = spawn_test_relay(root).await;

    // Start instance 1
    let token1 = CancellationToken::new();
    let c_tok1 = token1.clone();
    let server_addr = format!("localhost:{}", relay.addr.port());
    let ca_path = relay.ca_pem_path.clone();
    let s_addr1 = server_addr.clone();
    let ca_path1 = ca_path.clone();

    let task1 = tokio::spawn(async move {
        weave::run_poc_with_token("web".to_string(), s_addr1, Some(&ca_path1), c_tok1).await
    });

    let expected_hostname = derive_hostname("web", &poc_identity(), root);
    let mut reg1 = false;
    for _ in 0..50 {
        if relay.registry.lookup(&expected_hostname).is_some() {
            reg1 = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(reg1, "Instance 1 should register");

    // Start instance 2 with identical key
    let token2 = CancellationToken::new();
    let c_tok2 = token2.clone();
    let s_addr2 = server_addr.clone();
    let ca_path2 = ca_path.clone();

    let task2 = tokio::spawn(async move {
        weave::run_poc_with_token("web".to_string(), s_addr2, Some(&ca_path2), c_tok2).await
    });

    // Wait for instance 1 to terminate via supersession
    let res1 = task1.await.unwrap();
    assert!(
        res1.is_err(),
        "Instance 1 should terminate when superseded by instance 2"
    );

    // Verify instance 2 is now registered and serving
    let mut reg2 = false;
    for _ in 0..50 {
        if relay.registry.lookup(&expected_hostname).is_some() {
            reg2 = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(reg2, "Instance 2 should be active in registry");

    // Clean up
    token2.cancel();
    let _ = task2.await;
    relay.shutdown_token.cancel();
}

#[tokio::test]
async fn test_duplicate_registration_refusal() {
    let root = "weaver.test";
    let relay = spawn_test_relay(root).await;

    let (proxy_tx, _) = tokio::sync::mpsc::channel(1);
    let (s_tx, _) = tokio::sync::oneshot::channel();
    let conn_id = relay
        .registry
        .register_connection(PocResolver::KEY_ID, s_tx);

    // First registration succeeds
    let res1 = relay
        .registry
        .register_service(PocResolver::KEY_ID, conn_id, "web", proxy_tx.clone())
        .await;
    assert!(res1.is_ok());

    // Duplicate registration for same service returns AlreadyRegistered
    let res2 = relay
        .registry
        .register_service(PocResolver::KEY_ID, conn_id, "web", proxy_tx.clone())
        .await;
    assert_eq!(res2, Err(RefusalCode::AlreadyRegistered));

    // Invalid DNS labels are refused at the schema boundary, before the
    // registry is reached.
    drop(proxy_tx);
    assert_eq!(
        weaver_proto::ControlHead::register("-invalid-"),
        Err(RefusalCode::InvalidName)
    );

    relay.shutdown_token.cancel();
}

fn poc_identity() -> Identity {
    Identity {
        person: "poc".into(),
        machine: "laptop".into(),
    }
}
