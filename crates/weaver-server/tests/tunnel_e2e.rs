use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
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
use weave::{ServiceSpec, StartOptions, Target};
use weaver_proto::control::RefusalCode;
use weaver_server::cert::resolver::CertResolver;
use weaver_server::cert::{CertManager, ChallengeRegistry, SystemClock};
use weaver_server::config::Config;
use weaver_server::edge::https::run_https_server_with_registry;
use weaver_server::store::Store;
use weaver_server::tunnel::TunnelRegistry;
use weaver_server::tunnel::{Identity, PocResolver, derive_hostname};

/// A trivial in-process HTTP/1.1 origin used by the proxy e2e tests. It
/// answers every request with `200`, an `x-origin: yes` marker, a
/// self-referential `location` header (for rewrite assertions) and a body
/// naming the method, path and received body length.
struct TestOrigin {
    addr: SocketAddr,
    token: CancellationToken,
}

impl TestOrigin {
    fn port(&self) -> u16 {
        self.addr.port()
    }
}

async fn spawn_test_origin() -> TestOrigin {
    spawn_test_origin_named("origin").await
}

/// Like [`spawn_test_origin`] but tags every response body with `label`, so
/// tests with two services can tell which origin answered.
async fn spawn_test_origin_named(label: &'static str) -> TestOrigin {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let token = CancellationToken::new();
    let t = token.clone();
    let port = addr.port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = tokio::select! {
                _ = t.cancelled() => break,
                accepted = listener.accept() => match accepted {
                    Ok(pair) => pair,
                    Err(_) => continue,
                },
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |req: Request<Incoming>| async move {
                    let method = req.method().to_string();
                    let path = req
                        .uri()
                        .path_and_query()
                        .map(|pq| pq.as_str().to_string())
                        .unwrap_or_else(|| req.uri().path().to_string());
                    let body = req
                        .into_body()
                        .collect()
                        .await
                        .map(|c| c.to_bytes())
                        .unwrap_or_default();
                    let payload = if path.starts_with("/big") {
                        // 1 MiB, enough to span many mux frames and exercise
                        // the relay's response pump / backpressure path.
                        "x".repeat(1024 * 1024)
                    } else {
                        format!("{label} {method} {path} {} bytes", body.len())
                    };
                    let resp = Response::builder()
                        .status(StatusCode::OK)
                        .header("x-origin", "yes")
                        .header("location", format!("http://127.0.0.1:{port}/next?y=2"))
                        .body(Full::new(Bytes::from(payload)))
                        .unwrap();
                    Ok::<_, Infallible>(resp)
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });
    TestOrigin { addr, token }
}

fn start_options(server: String, ca: &std::path::Path, port: u16) -> StartOptions {
    start_options_multi(server, ca, &[("web", port)])
}

/// Build `StartOptions` for several `<service>=<origin port>` mappings.
fn start_options_multi(
    server: String,
    ca: &std::path::Path,
    services: &[(&str, u16)],
) -> StartOptions {
    StartOptions {
        specs: services
            .iter()
            .map(|(name, port)| ServiceSpec {
                service: (*name).to_string(),
                target: Target::parse(&format!("http://127.0.0.1:{port}")).unwrap(),
            })
            .collect(),
        server,
        insecure_root_ca: Some(ca.to_path_buf()),
        insecure_targets: Vec::new(),
        preserve_host: Vec::new(),
        no_rewrite: Vec::new(),
        append_forwarded: Vec::new(),
        quiet: true,
        verbose: false,
    }
}

/// One HTTP/1.1 visitor request through the edge, returning status and body.
async fn visitor_get_h1(relay: SocketAddr, hostname: &str, path: &str) -> (StatusCode, Bytes) {
    let connector = TlsConnector::from(create_client_tls_config(vec![b"http/1.1".to_vec()]));
    let tcp = TcpStream::connect(relay).await.unwrap();
    let server_name = ServerName::try_from(hostname.to_string()).unwrap();
    let tls = connector.connect(server_name, tcp).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header("host", hostname)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, body)
}

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
    let store = Arc::new(Store::open(temp_db.path()).await.unwrap());

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
    let origin = spawn_test_origin().await;

    // 1. Start a real `weave start` client in the background, pointed at the
    //    in-process origin.
    let client_token = CancellationToken::new();
    let c_tok = client_token.clone();
    let server_addr = format!("localhost:{}", relay.addr.port());
    let ca_path = relay.ca_pem_path.clone();
    let opts = start_options(server_addr, &ca_path, origin.port());

    let client_task = tokio::spawn(async move { weave::run_start_with_token(opts, c_tok).await });

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
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("x-origin").unwrap(), "yes");
    // The origin's self-referential Location was rewritten to the public origin.
    assert_eq!(
        resp.headers().get("location").unwrap(),
        format!("https://{expected_hostname}/next?y=2").as_str()
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"origin GET /hello?x=1 0 bytes");

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
    assert_eq!(resp2.status(), StatusCode::OK);
    assert_eq!(resp2.headers().get("x-origin").unwrap(), "yes");
    assert_eq!(
        resp2.headers().get("location").unwrap(),
        format!("https://{expected_hostname}/next?y=2").as_str()
    );
    let body2 = resp2.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body2[..], b"origin GET /hello?x=1 0 bytes");

    // 4a-2. A 1 MiB response: streams across many frames and exercises the
    //       relay's response pump and backpressure path.
    let req_big = Request::builder()
        .method(Method::GET)
        .uri("/big")
        .header("host", &expected_hostname)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let tcp_big = TcpStream::connect(relay.addr).await.unwrap();
    let tls_big = TlsConnector::from(create_client_tls_config(vec![b"h2".to_vec()]))
        .connect(
            ServerName::try_from(expected_hostname.clone()).unwrap(),
            tcp_big,
        )
        .await
        .unwrap();
    let (mut sender_big, conn_big) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls_big))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = conn_big.await;
    });
    let resp_big = sender_big.send_request(req_big).await.unwrap();
    assert_eq!(resp_big.status(), StatusCode::OK);
    let big_body = resp_big.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(big_body.len(), 1024 * 1024);
    assert!(big_body.iter().all(|b| *b == b'x'));

    // 4b. A large POST body: exercises MORE-flagged fragmentation
    // (> max_frame) and WINDOW_UPDATE (> initial_window / 2 of *wire*
    // bytes consumed). The first half is low-entropy so zstd engages; the
    // second half is incompressible so the wire bytes actually reach the
    // flow-control threshold.
    let mut body = "0123456789abcdef".repeat(20 * 1024).into_bytes(); // 320 KiB
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    body.extend((0..320 * 1024).map(|_| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x as u8
    }));
    let big = Bytes::from(body);
    let req_post = Request::builder()
        .method(Method::POST)
        .uri("/upload")
        .header("host", &expected_hostname)
        .header("content-type", "text/plain")
        .header("content-length", big.len().to_string())
        .body(Full::new(big))
        .unwrap();
    let tcp_post = TcpStream::connect(relay.addr).await.unwrap();
    let tls_post = TlsConnector::from(create_client_tls_config(vec![b"h2".to_vec()]))
        .connect(
            ServerName::try_from(expected_hostname.clone()).unwrap(),
            tcp_post,
        )
        .await
        .unwrap();
    let (mut sender_post, conn_post) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls_post))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = conn_post.await;
    });
    let resp_post = sender_post.send_request(req_post).await.unwrap();
    assert_eq!(resp_post.status(), StatusCode::OK);
    let post_echo = resp_post.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        &post_echo[..],
        format!("origin POST /upload {} bytes", 640 * 1024).as_bytes()
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

/// The control stream is the registration lease: finishing it drops the
/// route and deactivates the cert while the tunnel connection stays up.
#[tokio::test]
async fn test_control_stream_is_the_registration_lease() {
    let root = "localhost";
    let relay = spawn_test_relay(root).await;

    let shutdown = CancellationToken::new();
    let release = CancellationToken::new();
    let (s_tok, r_tok) = (shutdown.clone(), release.clone());
    let server_addr = format!("localhost:{}", relay.addr.port());
    let ca_path = relay.ca_pem_path.clone();
    let opts = start_options(server_addr, &ca_path, 1);
    let client_task =
        tokio::spawn(async move { weave::run_start_with_tokens(opts, s_tok, r_tok).await });

    let hostname = derive_hostname("web", &poc_identity(), root);
    let mut registered = false;
    for _ in 0..50 {
        if relay.registry.lookup(&hostname).is_some() {
            registered = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(registered, "service should register");
    assert!(relay.cert_manager.is_active(&hostname));

    // Drop the lease; the connection stays open.
    release.cancel();
    let mut released = false;
    for _ in 0..20 {
        if relay.registry.lookup(&hostname).is_none() {
            released = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(released, "finishing the control stream must unregister");
    assert!(!relay.cert_manager.is_active(&hostname));
    assert!(
        !client_task.is_finished(),
        "connection must survive the lease release"
    );

    shutdown.cancel();
    client_task.await.unwrap().expect("clean shutdown");
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
        let opts = start_options(s_addr1, &ca_path1, 1);
        weave::run_start_with_token(opts, c_tok1).await
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
        let opts = start_options(s_addr2, &ca_path2, 1);
        weave::run_start_with_token(opts, c_tok2).await
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

/// Two services registered on one connection route to their own origins.
#[tokio::test]
async fn test_two_services_on_one_connection() {
    let root = "localhost";
    let relay = spawn_test_relay(root).await;
    let alpha = spawn_test_origin_named("alpha").await;
    let beta = spawn_test_origin_named("beta").await;

    let token = CancellationToken::new();
    let c_tok = token.clone();
    let server = format!("localhost:{}", relay.addr.port());
    let ca = relay.ca_pem_path.clone();
    let opts = start_options_multi(
        server,
        &ca,
        &[("alpha", alpha.port()), ("beta", beta.port())],
    );
    let task = tokio::spawn(async move { weave::run_start_with_token(opts, c_tok).await });

    let host_a = derive_hostname("alpha", &poc_identity(), root);
    let host_b = derive_hostname("beta", &poc_identity(), root);
    for host in [&host_a, &host_b] {
        let mut ok = false;
        for _ in 0..50 {
            if relay.registry.lookup(host).is_some() {
                ok = true;
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        assert!(ok, "{host} should register");
    }

    let (status_a, body_a) = visitor_get_h1(relay.addr, &host_a, "/a").await;
    let (status_b, body_b) = visitor_get_h1(relay.addr, &host_b, "/b").await;
    let (status_a2, body_a2) = visitor_get_h1(relay.addr, &host_a, "/a2").await;
    assert_eq!(status_a, StatusCode::OK);
    assert_eq!(status_b, StatusCode::OK);
    assert_eq!(status_a2, StatusCode::OK);
    assert_eq!(&body_a[..], b"alpha GET /a 0 bytes");
    assert_eq!(&body_b[..], b"beta GET /b 0 bytes");
    assert_eq!(&body_a2[..], b"alpha GET /a2 0 bytes");

    // The edge firewall refuses scanner probes before they reach the tunnel:
    // the origin would have answered 200 with an echo, so a 403 with the
    // branded page proves the request never crossed the mux.
    for probe in [
        "/.env",
        "/.git/HEAD",
        "/%2e%2e%2f%2eenv",
        "/actuator/env",
        "/db.sqlite3",
    ] {
        let (status, body) = visitor_get_h1(relay.addr, &host_a, probe).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{probe}");
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("Request Blocked"), "{probe}: {text}");
        assert!(!text.contains("alpha GET"), "{probe} reached the origin");
    }
    // …but ordinary dotted paths and .well-known pass through.
    let (status, _) = visitor_get_h1(relay.addr, &host_a, "/.well-known/security.txt").await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = visitor_get_h1(relay.addr, &host_a, "/blog/my.post?q=.env").await;
    assert_eq!(status, StatusCode::OK);

    token.cancel();
    task.await.unwrap().expect("clean shutdown");
    relay.shutdown_token.cancel();
}

/// A WebSocket echo origin (tungstenite server role over plain TCP).
async fn spawn_ws_echo_origin() -> TestOrigin {
    use futures_util::{SinkExt, StreamExt};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let token = CancellationToken::new();
    let t = token.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = tokio::select! {
                _ = t.cancelled() => break,
                accepted = listener.accept() => match accepted {
                    Ok(pair) => pair,
                    Err(_) => continue,
                },
            };
            tokio::spawn(async move {
                let mut ws = match tokio_tungstenite::accept_async(stream).await {
                    Ok(ws) => ws,
                    Err(e) => {
                        eprintln!("ws echo origin: handshake failed: {e:?}");
                        return;
                    }
                };
                while let Some(Ok(msg)) = ws.next().await {
                    if msg.is_text() || msg.is_binary() {
                        if ws.send(msg).await.is_err() {
                            break;
                        }
                    } else if msg.is_close() {
                        break;
                    }
                }
            });
        }
    });
    TestOrigin { addr, token }
}

/// WebSocket rides the tunnel end to end: h1 `Upgrade` and h2 RFC 8441
/// extended CONNECT on the visitor side, plain h1 upgrade to the origin.
#[tokio::test]
async fn test_websocket_upgrade_h1_and_h2_extended_connect() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let root = "localhost";
    let relay = spawn_test_relay(root).await;
    let echo = spawn_ws_echo_origin().await;

    let token = CancellationToken::new();
    let c_tok = token.clone();
    let server = format!("localhost:{}", relay.addr.port());
    let ca = relay.ca_pem_path.clone();
    let opts = start_options_multi(server, &ca, &[("ws", echo.port())]);
    let task = tokio::spawn(async move { weave::run_start_with_token(opts, c_tok).await });

    let host = derive_hostname("ws", &poc_identity(), root);
    let mut ok = false;
    for _ in 0..50 {
        if relay.registry.lookup(&host).is_some() {
            ok = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(ok, "ws service should register");

    // --- h1: classic Upgrade via tungstenite over TLS ---
    {
        let connector = TlsConnector::from(create_client_tls_config(vec![b"http/1.1".to_vec()]));
        let tcp = TcpStream::connect(relay.addr).await.unwrap();
        let tls = connector
            .connect(ServerName::try_from(host.clone()).unwrap(), tcp)
            .await
            .unwrap();
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("wss://{host}/echo"))
            .header("host", &host)
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header(
                "sec-websocket-key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .body(())
            .unwrap();
        let (mut ws, resp) = tokio_tungstenite::client_async(req, tls).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
        ws.send(Message::Text("ping over h1".into())).await.unwrap();
        let echoed = ws.next().await.unwrap().unwrap();
        assert_eq!(echoed.into_text().unwrap().as_str(), "ping over h1");
        let big = vec![0xAB_u8; 200 * 1024];
        ws.send(Message::Binary(big.clone().into())).await.unwrap();
        let echoed = ws.next().await.unwrap().unwrap();
        assert_eq!(echoed.into_data().as_ref(), &big[..]);
        ws.close(None).await.unwrap();
    }

    // --- h2: RFC 8441 extended CONNECT, raw frames over the h2 stream ---
    {
        let connector = TlsConnector::from(create_client_tls_config(vec![b"h2".to_vec()]));
        let tcp = TcpStream::connect(relay.addr).await.unwrap();
        let tls = connector
            .connect(ServerName::try_from(host.clone()).unwrap(), tcp)
            .await
            .unwrap();
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut req = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://{host}/echo"))
            .header("sec-websocket-version", "13")
            .body(Empty::<Bytes>::new())
            .unwrap();
        req.extensions_mut()
            .insert(hyper::ext::Protocol::from_static("websocket"));
        let mut resp = sender.send_request(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "extended CONNECT is answered 200"
        );
        let upgraded = hyper::upgrade::on(&mut resp).await.unwrap();
        // Speak WebSocket framing directly over the upgraded h2 stream.
        let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            TokioIo::new(upgraded),
            tokio_tungstenite::tungstenite::protocol::Role::Client,
            None,
        )
        .await;
        ws.send(Message::Text("ping over h2".into())).await.unwrap();
        let echoed = ws.next().await.unwrap().unwrap();
        assert_eq!(echoed.into_text().unwrap().as_str(), "ping over h2");
        ws.close(None).await.unwrap();
    }

    // A plain CONNECT (no :protocol) is still refused as a forward proxy.
    {
        let connector = TlsConnector::from(create_client_tls_config(vec![b"h2".to_vec()]));
        let tcp = TcpStream::connect(relay.addr).await.unwrap();
        let tls = connector
            .connect(ServerName::try_from(host.clone()).unwrap(), tcp)
            .await
            .unwrap();
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("{host}:443"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    token.cancel();
    task.await.unwrap().expect("clean shutdown");
    relay.shutdown_token.cancel();
}

/// An unreachable origin 502s only its own service.
#[tokio::test]
async fn test_origin_down_502s_only_that_service() {
    let root = "localhost";
    let relay = spawn_test_relay(root).await;
    let down = spawn_test_origin_named("down").await;
    let up = spawn_test_origin_named("up").await;

    let token = CancellationToken::new();
    let c_tok = token.clone();
    let server = format!("localhost:{}", relay.addr.port());
    let ca = relay.ca_pem_path.clone();
    let opts = start_options_multi(server, &ca, &[("down", down.port()), ("up", up.port())]);
    let task = tokio::spawn(async move { weave::run_start_with_token(opts, c_tok).await });

    let host_down = derive_hostname("down", &poc_identity(), root);
    let host_up = derive_hostname("up", &poc_identity(), root);
    for host in [&host_down, &host_up] {
        let mut ok = false;
        for _ in 0..50 {
            if relay.registry.lookup(host).is_some() {
                ok = true;
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        assert!(ok, "{host} should register");
    }

    // Take the "down" origin fully offline before any request reaches it.
    down.token.cancel();
    sleep(Duration::from_millis(100)).await;

    let (status_down, _) = visitor_get_h1(relay.addr, &host_down, "/x").await;
    let (status_up, body_up) = visitor_get_h1(relay.addr, &host_up, "/x").await;
    assert_eq!(status_down, StatusCode::BAD_GATEWAY);
    assert_eq!(status_up, StatusCode::OK);
    assert_eq!(&body_up[..], b"up GET /x 0 bytes");

    token.cancel();
    task.await.unwrap().expect("clean shutdown");
    relay.shutdown_token.cancel();
}

fn poc_identity() -> Identity {
    Identity {
        person: "poc".into(),
        machine: "laptop".into(),
    }
}
