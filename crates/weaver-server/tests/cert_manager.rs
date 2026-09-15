use std::sync::Arc;
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::sign::CertifiedKey;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use weaver_server::cert::challenge::{ChallengeRegistry, create_tls_alpn_01_certified_key};
use weaver_server::cert::clock::MockClock;
use weaver_server::cert::providers::{format_providers_table, requires_eab, resolve_directory_url};
use weaver_server::cert::resolver::CertResolver;
use weaver_server::cert::state::CertState;
use weaver_server::cert::{CertManager, record_cert_event};
use weaver_server::config::Config;
use weaver_server::edge::http::run_http_server;
use weaver_server::edge::https::run_https_server;
use weaver_server::edge::tls::create_server_config;
use weaver_server::store::Store;

fn make_dummy_certified_key(san: &str) -> Arc<CertifiedKey> {
    let cert = generate_simple_self_signed(vec![san.to_string()]).unwrap();
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.signing_key.serialize_der();
    let cert_chain = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::try_from(key_der).unwrap();
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key).unwrap();
    Arc::new(CertifiedKey::new(cert_chain, signing_key))
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

fn create_test_client_config() -> Arc<rustls::ClientConfig> {
    let provider = rustls::crypto::ring::default_provider();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DangerousNoVerify))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

#[test]
fn test_cert_state_machine_variants_and_labels() {
    let pending = CertState::Pending;
    assert_eq!(pending.label(), "pending");
    assert!(!pending.is_issued());
    assert!(pending.not_after().is_none());

    let ordering = CertState::Ordering;
    assert_eq!(ordering.label(), "ordering");
    assert!(!ordering.is_issued());

    let issued = CertState::Issued {
        not_after: 1_800_000_000,
    };
    assert_eq!(issued.label(), "issued");
    assert!(issued.is_issued());
    assert_eq!(issued.not_after(), Some(1_800_000_000));

    let failed = CertState::Failed {
        error: "rate limited".into(),
        next_retry: 1_700_003_600,
    };
    assert_eq!(failed.label(), "failed");
    assert!(!failed.is_issued());

    let renewing = CertState::Renewing {
        not_after: 1_800_000_000,
    };
    assert_eq!(renewing.label(), "renewing");
    assert!(renewing.is_issued());
    assert_eq!(renewing.not_after(), Some(1_800_000_000));
}

#[test]
fn test_providers_catalog() {
    assert_eq!(
        resolve_directory_url("letsencrypt", None),
        Some("https://acme-v02.api.letsencrypt.org/directory".to_string())
    );
    assert_eq!(
        resolve_directory_url("custom", Some("https://pebble:14000/dir")),
        Some("https://pebble:14000/dir".to_string())
    );
    assert!(requires_eab("google"));
    assert!(requires_eab("zerossl"));
    assert!(!requires_eab("letsencrypt"));

    let table = format_providers_table();
    assert!(table.contains("letsencrypt"));
    assert!(table.contains("google"));
    assert!(table.contains("zerossl"));
    assert!(table.contains("buypass"));
    assert!(table.contains("custom"));
}

#[tokio::test]
async fn test_cert_resolver_placeholder_and_hsts() {
    let placeholder = make_dummy_certified_key("example.com");
    let registry = Arc::new(ChallengeRegistry::new());
    let resolver = Arc::new(CertResolver::new(
        "example.com".to_string(),
        placeholder,
        registry,
    ));

    // Initially placeholder for all domains
    assert!(resolver.is_placeholder("example.com"));
    assert!(resolver.is_placeholder("tunnel.example.com"));

    // Insert issued certificate
    let issued = make_dummy_certified_key("tunnel.example.com");
    resolver.insert_cert("tunnel.example.com", issued);

    // tunnel.example.com is no longer placeholder
    assert!(!resolver.is_placeholder("tunnel.example.com"));
    // root domain remains placeholder
    assert!(resolver.is_placeholder("example.com"));

    // Verify HSTS header inclusion on live HTTPS server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let shutdown_token = CancellationToken::new();

    let tls_config =
        create_server_config(Arc::clone(&resolver) as Arc<dyn rustls::server::ResolvesServerCert>)
            .unwrap();
    let res_clone = Arc::clone(&resolver);
    let s_tok = shutdown_token.clone();
    tokio::spawn(async move {
        run_https_server(
            listener,
            tls_config,
            "example.com".into(),
            Some(res_clone),
            s_tok,
        )
        .await;
    });

    let client_config = create_test_client_config();
    let connector = TlsConnector::from(client_config);

    // Request for placeholder domain: NO HSTS
    let tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let server_name = ServerName::try_from("example.com").unwrap().to_owned();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();
    tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    tls.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    assert!(!resp.contains("strict-transport-security"));

    // Request for issued domain: branded 404 WITH HSTS
    let tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let server_name = ServerName::try_from("tunnel.example.com")
        .unwrap()
        .to_owned();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();
    tls.write_all(b"GET / HTTP/1.1\r\nHost: tunnel.example.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    tls.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 404 Not Found"));
    assert!(resp.contains("strict-transport-security: max-age=31536000; includeSubDomains"));

    shutdown_token.cancel();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_resolver_handshake_hold_unblocks_on_cert_insert() {
    let placeholder = make_dummy_certified_key("example.com");
    let registry = Arc::new(ChallengeRegistry::new());
    let resolver = Arc::new(CertResolver::new(
        "example.com".to_string(),
        placeholder,
        registry,
    ));

    let host = "wait.example.com";
    resolver.mark_ordering(host);
    assert!(resolver.is_ordering(host));

    let resolver_clone = Arc::clone(&resolver);
    let target_host = host.to_string();
    let cert_to_insert = make_dummy_certified_key(host);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let shutdown_token = CancellationToken::new();

    let tls_config =
        create_server_config(resolver_clone as Arc<dyn rustls::server::ResolvesServerCert>)
            .unwrap();
    let s_tok = shutdown_token.clone();
    let res_for_server = Arc::clone(&resolver);
    tokio::spawn(async move {
        run_https_server(
            listener,
            tls_config,
            "example.com".into(),
            Some(res_for_server),
            s_tok,
        )
        .await;
    });

    let client_config = create_test_client_config();
    let connector = TlsConnector::from(client_config);

    // Spawn client handshake task: will wait on resolver's handshake hold
    let client_task = tokio::spawn(async move {
        let tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let server_name = ServerName::try_from(host).unwrap().to_owned();
        let mut tls = connector.connect(server_name, tcp).await.unwrap();
        tls.write_all(b"GET / HTTP/1.1\r\nHost: wait.example.com\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut resp = String::new();
        tls.read_to_string(&mut resp).await.unwrap();
        resp
    });

    // While client is holding in handshake, insert the certificate after a short delay
    tokio::time::sleep(Duration::from_millis(50)).await;
    resolver.insert_cert(&target_host, cert_to_insert);

    // Handshake should unblock and succeed with 404 branded page and HSTS header
    let resp = client_task.await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 404 Not Found"));
    assert!(resp.contains("strict-transport-security"));

    shutdown_token.cancel();
}

#[tokio::test]
async fn test_challenge_registry_and_http_01_responder() {
    let registry = Arc::new(ChallengeRegistry::new());
    registry.register_http_01("test-token-123".to_string(), "key-auth-abc".to_string());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let token = CancellationToken::new();

    let reg_clone = Arc::clone(&registry);
    let tok_clone = token.clone();
    tokio::spawn(async move {
        run_http_server(
            listener,
            "example.com".into(),
            8443,
            Some(reg_clone),
            tok_clone,
        )
        .await;
    });

    // 1. Valid challenge request -> 200 OK with key authorization bytes
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    stream
        .write_all(b"GET /.well-known/acme-challenge/test-token-123 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    assert!(resp.contains("key-auth-abc"));

    // 2. Unknown challenge token -> 404 Not Found
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    stream
        .write_all(b"GET /.well-known/acme-challenge/unknown-token HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 404 Not Found"));

    // 3. Normal path -> 308 Permanent Redirect to HTTPS
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    stream
        .write_all(b"GET /my/app HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 308 Permanent Redirect"));
    assert!(resp.contains("location: https://example.com:8443/my/app"));

    token.cancel();
}

#[tokio::test]
async fn test_tls_alpn_01_challenge_certified_key() {
    let host = "alpn.example.com";
    let key_auth = "dummy-key-authorization-string-12345";
    let cert_key = create_tls_alpn_01_certified_key(host, key_auth).unwrap();

    let registry = Arc::new(ChallengeRegistry::new());
    registry.register_tls_alpn_01(host.to_string(), Arc::clone(&cert_key));

    assert!(registry.get_tls_alpn_01(host).is_some());
    assert!(registry.get_tls_alpn_01("other.com").is_none());

    registry.remove_tls_alpn_01(host);
    assert!(registry.get_tls_alpn_01(host).is_none());
}

#[tokio::test]
async fn test_sqlite_caching_and_server_restart_no_reorder() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("weaver.db");
    let store = Arc::new(Store::open(&db_path).unwrap());

    let rcgen_cert = generate_simple_self_signed(vec!["test.example.com".to_string()]).unwrap();
    let cert_pem = rcgen_cert.cert.pem();
    let key_pem = rcgen_cert.signing_key.serialize_pem();

    let clock = Arc::new(MockClock::new(1_700_000_000));

    // Seed database with a valid cached certificate
    store.write(|conn| {
        conn.execute(
            "INSERT INTO certificates (name, cert_pem, key_pem, not_before, not_after, directory, obtained_at, last_active_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                "test.example.com",
                cert_pem,
                key_pem,
                1_690_000_000i64,
                1_790_000_000i64, // valid until far in future
                "https://acme-staging-v02.api.letsencrypt.org/directory",
                1_700_000_000i64,
                1_700_000_000i64,
            ],
        )?;
        Ok(())
    }).unwrap();

    let config = Arc::new(Config {
        root_domain: "test.example.com".into(),
        admin_email: "admin@test.example.com".into(),
        acme_provider: "letsencrypt-staging".into(),
        listen_http: "127.0.0.1:80".parse().unwrap(),
        listen_https: "127.0.0.1:443".parse().unwrap(),
        control_socket: "/tmp/sock".into(),
        acme_directory: None,
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: None,
        acme_fallback_providers: Vec::new(),
    });

    let placeholder = make_dummy_certified_key("test.example.com");
    let registry = Arc::new(ChallengeRegistry::new());
    let resolver = Arc::new(CertResolver::new(
        "test.example.com".into(),
        placeholder,
        Arc::clone(&registry),
    ));

    let manager = CertManager::new(config, store, resolver, registry, clock, true);

    // Initialize manager
    manager.init().unwrap();

    // Verify certificate was loaded from SQLite into resolver
    assert_eq!(
        manager.status("test.example.com"),
        CertState::Issued {
            not_after: 1_790_000_000
        }
    );
    assert!(!manager.resolver().is_placeholder("test.example.com"));

    // Ensure is an instant no-op
    assert!(manager.ensure("test.example.com").await.is_ok());
}

#[tokio::test]
async fn test_active_inactive_renewal_policy() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("weaver.db");
    let store = Arc::new(Store::open(&db_path).unwrap());
    let clock = Arc::new(MockClock::new(1_700_000_000));

    let config = Arc::new(Config {
        root_domain: "example.com".into(),
        admin_email: "admin@example.com".into(),
        acme_provider: "letsencrypt-staging".into(),
        listen_http: "127.0.0.1:80".parse().unwrap(),
        listen_https: "127.0.0.1:443".parse().unwrap(),
        control_socket: "/tmp/sock".into(),
        acme_directory: None,
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: None,
        acme_fallback_providers: Vec::new(),
    });

    let placeholder = make_dummy_certified_key("example.com");
    let registry = Arc::new(ChallengeRegistry::new());
    let resolver = Arc::new(CertResolver::new(
        "example.com".into(),
        placeholder,
        Arc::clone(&registry),
    ));

    let manager = CertManager::new(config, Arc::clone(&store), resolver, registry, clock, true);

    // Hostname initially active
    manager.set_active("host1.example.com", true);
    assert!(manager.is_active("host1.example.com"));

    // Set inactive
    manager.set_active("host1.example.com", false);
    assert!(!manager.is_active("host1.example.com"));

    // Re-activate
    manager.set_active("host1.example.com", true);
    assert!(manager.is_active("host1.example.com"));
}

#[tokio::test]
async fn test_forced_expiration_triggers_renewal_flow_and_event() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("weaver.db");
    let store = Arc::new(Store::open(&db_path).unwrap());

    // Clock set to 1_700_000_000
    let clock = Arc::new(MockClock::new(1_700_000_000));

    // Seed certificate with validity 1_600_000_000 -> 1_710_000_000 (total lifetime 110,000,000s)
    // At 1_700_000_000, remaining is 10,000,000s, which is < 1/3 of 110,000,000s -> should renew!
    let rcgen_cert = generate_simple_self_signed(vec!["example.com".to_string()]).unwrap();
    let cert_pem = rcgen_cert.cert.pem();
    let key_pem = rcgen_cert.signing_key.serialize_pem();

    store.write(|conn| {
        conn.execute(
            "INSERT INTO certificates (name, cert_pem, key_pem, not_before, not_after, directory, obtained_at, last_active_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                "example.com",
                cert_pem,
                key_pem,
                1_600_000_000i64,
                1_710_000_000i64,
                "https://acme-staging-v02.api.letsencrypt.org/directory",
                1_600_000_000i64,
                1_700_000_000i64,
            ],
        )?;
        Ok(())
    }).unwrap();

    let config = Arc::new(Config {
        root_domain: "example.com".into(),
        admin_email: "admin@example.com".into(),
        acme_provider: "letsencrypt-staging".into(),
        listen_http: "127.0.0.1:80".parse().unwrap(),
        listen_https: "127.0.0.1:443".parse().unwrap(),
        control_socket: "/tmp/sock".into(),
        acme_directory: None,
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: None,
        acme_fallback_providers: Vec::new(),
    });

    let placeholder = make_dummy_certified_key("example.com");
    let registry = Arc::new(ChallengeRegistry::new());
    let resolver = Arc::new(CertResolver::new(
        "example.com".into(),
        placeholder,
        Arc::clone(&registry),
    ));

    let manager = CertManager::new(config, Arc::clone(&store), resolver, registry, clock, true);

    manager.init().unwrap();

    // Verify renewal condition
    assert!(weaver_server::cert::should_renew(
        1_600_000_000,
        1_710_000_000,
        1_700_000_000
    ));

    // Record renewal event
    record_cert_event(
        &store,
        "example.com",
        1_700_000_000,
        "renewed",
        Some("hot-swapped"),
    )
    .unwrap();

    let event_count: i64 = store
        .read(|conn| {
            let count = conn.query_row(
                "SELECT count(*) FROM cert_events WHERE name = 'example.com' AND kind = 'renewed'",
                [],
                |row| row.get(0),
            )?;
            Ok(count)
        })
        .unwrap();

    assert_eq!(event_count, 1);
}

#[tokio::test]
async fn test_exponential_backoff_on_failure() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("weaver.db");
    let store = Arc::new(Store::open(&db_path).unwrap());
    let clock = Arc::new(MockClock::new(1_700_000_000));

    // Attempting invalid directory causes failure
    let config = Arc::new(Config {
        root_domain: "example.com".into(),
        admin_email: "admin@example.com".into(),
        acme_provider: "custom".into(),
        listen_http: "127.0.0.1:80".parse().unwrap(),
        listen_https: "127.0.0.1:443".parse().unwrap(),
        control_socket: "/tmp/sock".into(),
        acme_directory: Some("http://127.0.0.1:1/nonexistent-directory".into()),
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: None,
        acme_fallback_providers: Vec::new(),
    });

    let placeholder = make_dummy_certified_key("example.com");
    let registry = Arc::new(ChallengeRegistry::new());
    let resolver = Arc::new(CertResolver::new(
        "example.com".into(),
        placeholder,
        Arc::clone(&registry),
    ));

    let manager = CertManager::new(
        config,
        Arc::clone(&store),
        Arc::clone(&resolver),
        registry,
        clock,
        true,
    );

    // Call ensure: will fail because directory is unreachable
    let res = manager.ensure("fail.example.com").await;
    assert!(res.is_err());

    // State must be Failed
    let st = manager.status("fail.example.com");
    match st {
        CertState::Failed { next_retry, .. } => {
            // First failure backoff is 1h = 3600s
            assert_eq!(next_retry, 1_700_003_600);
        }
        other => panic!("Expected Failed state, got {other:?}"),
    }

    // Server remains operational and serves placeholder
    assert!(resolver.is_placeholder("fail.example.com"));

    // Event recorded in cert_events
    let event_count: i64 = store
        .read(|conn| {
            let count = conn.query_row(
            "SELECT count(*) FROM cert_events WHERE name = 'fail.example.com' AND kind = 'failed'",
            [],
            |row| row.get(0),
        )?;
            Ok(count)
        })
        .unwrap();
    assert_eq!(event_count, 1);
}

#[tokio::test]
async fn test_concurrent_ensure_deduplication() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("weaver.db");
    let store = Arc::new(Store::open(&db_path).unwrap());
    let clock = Arc::new(MockClock::new(1_700_000_000));

    let config = Arc::new(Config {
        root_domain: "example.com".into(),
        admin_email: "admin@example.com".into(),
        acme_provider: "custom".into(),
        listen_http: "127.0.0.1:80".parse().unwrap(),
        listen_https: "127.0.0.1:443".parse().unwrap(),
        control_socket: "/tmp/sock".into(),
        acme_directory: Some("http://127.0.0.1:1/nonexistent".into()),
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: None,
        acme_fallback_providers: Vec::new(),
    });

    let placeholder = make_dummy_certified_key("example.com");
    let registry = Arc::new(ChallengeRegistry::new());
    let resolver = Arc::new(CertResolver::new(
        "example.com".into(),
        placeholder,
        Arc::clone(&registry),
    ));

    let manager = CertManager::new(config, Arc::clone(&store), resolver, registry, clock, true);

    // Concurrently invoke ensure for the same hostname
    let m1 = Arc::clone(&manager);
    let m2 = Arc::clone(&manager);

    let (res1, res2) = tokio::join!(
        m1.ensure("dedup.example.com"),
        m2.ensure("dedup.example.com")
    );

    // Both should complete with identical error (one leader executed, follower awaited broadcast)
    assert!(res1.is_err());
    assert!(res2.is_err());
}
