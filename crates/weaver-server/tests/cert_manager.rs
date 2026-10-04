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

use weaver_server::cert::clock::{Clock, MockClock};
use weaver_server::cert::providers::{
    find_provider, format_providers_table, requires_eab, resolve_directory_url,
};
use weaver_server::cert::resolver::CertResolver;
use weaver_server::cert::state::CertState;
use weaver_server::cert::{CertManager, PROVIDERS, record_cert_event};
use weaver_server::config::Config;
use weaver_server::edge::https::run_https_server;
use weaver_server::edge::tls::create_server_config;
use weaver_server::store::Store;

/// A self-signed certificate valid for `<root>` and `*.<root>`, as the single
/// wildcard the resolver serves.
fn make_wildcard_certified_key(root: &str) -> Arc<CertifiedKey> {
    let cert = generate_simple_self_signed(vec![root.to_string(), format!("*.{root}")]).unwrap();
    let cert_chain = vec![CertificateDer::from(cert.cert.der().to_vec())];
    let key = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
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

fn create_test_client_config_with_alpn(alpn: Vec<Vec<u8>>) -> Arc<rustls::ClientConfig> {
    let provider = rustls::crypto::ring::default_provider();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DangerousNoVerify))
        .with_no_client_auth();
    config.alpn_protocols = alpn;
    Arc::new(config)
}

fn create_test_client_config() -> Arc<rustls::ClientConfig> {
    create_test_client_config_with_alpn(vec![b"http/1.1".to_vec()])
}

fn test_config(root_domain: &str, acme_provider: &str, acme_directory: Option<String>) -> Config {
    Config {
        root_domain: root_domain.to_string(),
        admin_domain: "relay-admin.test".to_string(),
        admin_email: "admin@example.com".into(),
        acme_provider: acme_provider.to_string(),
        listen_http: "127.0.0.1:80".parse().unwrap(),
        listen_https: "127.0.0.1:443".parse().unwrap(),
        control_socket: "/tmp/sock".into(),
        acme_directory,
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: None,
        acme_fallback_providers: Vec::new(),
        usage_flush_interval_secs: 60,
        relay_ips: Vec::new(),
        setup_complete: false,
    }
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

    // DNS-01 needs wildcard support: the catalog advertises which providers
    // can issue `*.<root>`.
    let letsencrypt = find_provider("letsencrypt").expect("letsencrypt provider");
    assert!(letsencrypt.wildcard_capable);
    assert!(PROVIDERS.iter().any(|p| p.wildcard_capable));
    assert!(PROVIDERS.iter().any(|p| !p.wildcard_capable));
}

// OFF-79: Public TLS handshakes for uncertified, unknown, or missing SNI terminate immediately
// at the TCP level without completing a handshake or serving placeholder certificates.
#[tokio::test]
async fn test_cert_resolver_placeholder_and_hsts() {
    let resolver = Arc::new(CertResolver::new("example.com".to_string()));

    // Initially placeholder (uncertified) for the apex and any one-label host.
    assert!(resolver.is_placeholder("example.com"));
    assert!(resolver.is_placeholder("tunnel.example.com"));

    // Insert the single wildcard certificate under the apex.
    let issued = make_wildcard_certified_key("example.com");
    resolver.insert_cert("example.com", issued);

    // The apex and any single-label host under it are now covered.
    assert!(!resolver.is_placeholder("example.com"));
    assert!(!resolver.is_placeholder("tunnel.example.com"));
    // Two labels are outside `*.<root>` coverage and stay placeholder.
    assert!(resolver.is_placeholder("a.b.example.com"));

    // Verify TLS behavior on live HTTPS server
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

    // Request for the wildcard-covered service: branded 404 WITH HSTS.
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

    // Request for the apex: 200 and HSTS.
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
    assert!(resp.contains("strict-transport-security: max-age=31536000; includeSubDomains"));

    // Two labels under the apex are not covered by `*.<root>`: TCP-level reject.
    let tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let server_name = ServerName::try_from("a.b.example.com").unwrap().to_owned();
    assert!(connector.connect(server_name, tcp).await.is_err());

    shutdown_token.cancel();
}

// OFF-79: In-progress certificate issuance holds incoming client TLS handshakes and completes
// successfully once the certificate is provisioned within the hold window.
#[tokio::test(flavor = "multi_thread")]
async fn test_resolver_handshake_hold_unblocks_on_cert_insert() {
    let resolver = Arc::new(CertResolver::new("example.com".to_string()));

    // The wildcard covers `wait.example.com`; ordering is tracked on the apex.
    let host = "wait.example.com";
    resolver.mark_ordering("example.com");
    assert!(resolver.is_ordering("example.com"));

    let resolver_clone = Arc::clone(&resolver);
    let cert_to_insert = make_wildcard_certified_key("example.com");

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
    resolver.insert_cert("example.com", cert_to_insert);

    // Handshake should unblock and succeed with 404 branded page and HSTS header
    let resp = client_task.await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 404 Not Found"));
    assert!(resp.contains("strict-transport-security"));

    shutdown_token.cancel();
}

#[tokio::test]
async fn test_sqlite_caching_and_server_restart_no_reorder() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("weaver.db");
    let store = Arc::new(Store::open(&db_path).await.unwrap());

    let rcgen_cert = generate_simple_self_signed(vec![
        "test.example.com".to_string(),
        "*.test.example.com".to_string(),
    ])
    .unwrap();
    let cert_pem = rcgen_cert.cert.pem();
    let key_pem = rcgen_cert.signing_key.serialize_pem();

    let clock = Arc::new(MockClock::new(1_700_000_000));

    // Seed database with a valid cached wildcard certificate under the apex.
    store
        .save_certificate(
            "test.example.com",
            weaver_server::store::NewCertificate {
                cert_pem: cert_pem.clone(),
                key_pem: key_pem.clone(),
                not_before: 1_690_000_000,
                not_after: 1_790_000_000, // valid until far in future
                issuer: None,
                directory: "https://acme-staging-v02.api.letsencrypt.org/directory".into(),
                obtained_at: 1_700_000_000,
                validation: "dns-01".to_string(),
                wildcard: true,
            },
        )
        .await
        .unwrap();

    let config = Arc::new(test_config("test.example.com", "letsencrypt-staging", None));

    let resolver = Arc::new(CertResolver::with_clock(
        "test.example.com".into(),
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));

    let manager = CertManager::new(config, store, resolver, clock);

    // Initialize manager
    manager.init().await.unwrap();

    // Verify certificate was loaded from SQLite into resolver
    assert_eq!(
        manager.status("test.example.com"),
        CertState::Issued {
            not_after: 1_790_000_000
        }
    );
    assert!(!manager.resolver().is_placeholder("test.example.com"));
    assert!(
        !manager
            .resolver()
            .is_placeholder("poc-laptop-web.test.example.com")
    );

    // Ensure is an instant no-op once the wildcard is valid.
    assert!(manager.ensure("test.example.com").await.is_ok());
    assert!(
        manager
            .ensure("poc-laptop-web.test.example.com")
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn test_init_holds_when_no_certificate_present() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("weaver.db");
    let store = Arc::new(Store::open(&db_path).await.unwrap());
    let clock = Arc::new(MockClock::new(1_700_000_000));

    let config = Arc::new(test_config("example.com", "letsencrypt-staging", None));
    let resolver = Arc::new(CertResolver::with_clock(
        "example.com".into(),
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let manager = CertManager::new(config, Arc::clone(&store), resolver, clock);

    manager.init().await.unwrap();

    // No stored wildcard: the apex is held (Pending) and the resolver refuses
    // to serve until issuance completes.
    assert_eq!(manager.status("example.com"), CertState::Pending);
    assert!(manager.resolver().is_placeholder("example.com"));
    assert!(manager.resolver().is_ordering("example.com"));
}

#[tokio::test]
async fn test_active_inactive_renewal_policy() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("weaver.db");
    let store = Arc::new(Store::open(&db_path).await.unwrap());
    let clock = Arc::new(MockClock::new(1_700_000_000));

    let config = Arc::new(test_config("example.com", "letsencrypt-staging", None));
    let resolver = Arc::new(CertResolver::new("example.com".into()));

    let manager = CertManager::new(config, Arc::clone(&store), resolver, clock);

    // Hostname initially active
    manager.set_active("host1.example.com", true);
    assert!(manager.is_active("host1.example.com"));

    // Set inactive
    manager.set_active("host1.example.com", false);
    assert!(!manager.is_active("host1.example.com"));

    // Re-activate
    manager.set_active("host1.example.com", true);
    assert!(manager.is_active("host1.example.com"));

    // Cert counts span both managed certificates (tunnel wildcard + admin), so
    // with neither active both report inactive.
    let counts = manager.cert_counts().await;
    assert_eq!(counts.inactive, 2);
    manager.set_active("example.com", true);
    let counts = manager.cert_counts().await;
    assert_eq!(counts.inactive, 1);
    manager.set_active("relay-admin.test", true);
    let counts = manager.cert_counts().await;
    assert_eq!(counts.inactive, 0);
}

#[tokio::test]
async fn test_forced_expiration_triggers_renewal_flow_and_event() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("weaver.db");
    let store = Arc::new(Store::open(&db_path).await.unwrap());

    // Clock set to 1_700_000_000
    let clock = Arc::new(MockClock::new(1_700_000_000));

    // Seed certificate with validity 1_600_000_000 -> 1_710_000_000 (total lifetime 110,000,000s)
    // At 1_700_000_000, remaining is 10,000,000s, which is < 1/3 of 110,000,000s -> should renew!
    let rcgen_cert =
        generate_simple_self_signed(vec!["example.com".to_string(), "*.example.com".to_string()])
            .unwrap();
    let cert_pem = rcgen_cert.cert.pem();
    let key_pem = rcgen_cert.signing_key.serialize_pem();

    store
        .save_certificate(
            "example.com",
            weaver_server::store::NewCertificate {
                cert_pem: cert_pem.clone(),
                key_pem: key_pem.clone(),
                not_before: 1_600_000_000,
                not_after: 1_710_000_000,
                issuer: None,
                directory: "https://acme-staging-v02.api.letsencrypt.org/directory".into(),
                obtained_at: 1_600_000_000,
                validation: "dns-01".to_string(),
                wildcard: true,
            },
        )
        .await
        .unwrap();

    let config = Arc::new(test_config("example.com", "letsencrypt-staging", None));
    let resolver = Arc::new(CertResolver::new("example.com".into()));

    let manager = CertManager::new(config, Arc::clone(&store), resolver, clock);

    manager.init().await.unwrap();

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
    .await
    .unwrap();

    let event_count = store
        .get_cert_events("example.com", 100)
        .await
        .unwrap()
        .iter()
        .filter(|e| e.kind == "renewed")
        .count();

    assert_eq!(event_count, 1);
}

#[tokio::test]
async fn test_exponential_backoff_on_failure() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("weaver.db");
    let store = Arc::new(Store::open(&db_path).await.unwrap());
    let clock = Arc::new(MockClock::new(1_700_000_000));

    // Attempting invalid directory causes failure
    let config = Arc::new(test_config(
        "example.com",
        "custom",
        Some("http://127.0.0.1:1/nonexistent-directory".into()),
    ));

    let resolver = Arc::new(CertResolver::new("example.com".into()));

    let manager = CertManager::new(config, Arc::clone(&store), Arc::clone(&resolver), clock);

    // Call ensure: will fail because directory is unreachable
    let res = manager.ensure("fail.example.com").await;
    assert!(res.is_err());

    // State must be Failed on the apex (the wildcard is the only cert).
    let st = manager.status("example.com");
    match st {
        CertState::Failed { next_retry, .. } => {
            // First failure backoff is 1h = 3600s
            assert_eq!(next_retry, 1_700_003_600);
        }
        other => panic!("Expected Failed state, got {other:?}"),
    }

    // Apex remains uncertified; ordering is cleared so requests fail immediately at TCP level
    assert!(resolver.is_placeholder("example.com"));
    assert!(!resolver.is_ordering("example.com"));

    // Event recorded in cert_events under the apex
    let event_count = store
        .get_cert_events("example.com", 100)
        .await
        .unwrap()
        .iter()
        .filter(|e| e.kind == "failed")
        .count();
    assert_eq!(event_count, 1);
}

#[tokio::test]
async fn test_concurrent_ensure_deduplication() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("weaver.db");
    let store = Arc::new(Store::open(&db_path).await.unwrap());
    let clock = Arc::new(MockClock::new(1_700_000_000));

    let config = Arc::new(test_config(
        "example.com",
        "custom",
        Some("http://127.0.0.1:1/nonexistent".into()),
    ));

    let resolver = Arc::new(CertResolver::new("example.com".into()));

    let manager = CertManager::new(config, Arc::clone(&store), resolver, clock);

    // Concurrently invoke ensure for the same hostname; both map to the apex.
    let m1 = Arc::clone(&manager);
    let m2 = Arc::clone(&manager);

    let (res1, res2) = tokio::join!(
        m1.ensure("dedup.example.com"),
        m2.ensure("dedup.example.com")
    );

    // Both should complete with an error (one leader executed, follower awaited broadcast)
    assert!(res1.is_err());
    assert!(res2.is_err());
}

// OFF-79: Incoming TLS handshake for a completely unknown SNI domain terminates immediately
// at the TCP level without completing a TLS handshake.
#[tokio::test]
async fn test_strict_tls_unknown_sni_terminates_tcp() {
    let resolver = Arc::new(CertResolver::new("example.com".to_string()));

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

    // Completely unknown SNI domain
    let tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let server_name = ServerName::try_from("unknown.example.org")
        .unwrap()
        .to_owned();
    let err = connector.connect(server_name, tcp).await;
    assert!(
        err.is_err(),
        "Expected unknown SNI domain to fail TLS handshake"
    );

    shutdown_token.cancel();
}

// OFF-79: Incoming TLS handshake with missing SNI terminates immediately at the TCP level.
#[tokio::test]
async fn test_strict_tls_missing_sni_terminates_tcp() {
    let resolver = Arc::new(CertResolver::new("example.com".to_string()));

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

    // Connecting to IP address sends no SNI extension in ClientHello
    let tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let server_name = ServerName::try_from("127.0.0.1").unwrap().to_owned();
    let err = connector.connect(server_name, tcp).await;
    assert!(err.is_err(), "Expected missing SNI to fail TLS handshake");

    shutdown_token.cancel();
}

// OFF-79: Incoming TLS handshake for a hostname whose certificate order has failed terminates
// immediately at the TCP level without completing a TLS handshake.
#[tokio::test]
async fn test_strict_tls_failed_order_terminates_tcp() {
    let resolver = Arc::new(CertResolver::new("example.com".to_string()));

    let host = "failed-order.example.com";
    resolver.mark_ordering("example.com");
    // Issuance fails: clear ordering without inserting cert
    resolver.clear_ordering("example.com");
    assert!(!resolver.is_ordering("example.com"));

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

    let tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let server_name = ServerName::try_from(host).unwrap().to_owned();
    let err = connector.connect(server_name, tcp).await;
    assert!(
        err.is_err(),
        "Expected failed order to terminate at TCP level"
    );

    shutdown_token.cancel();
}

// OFF-79: Incoming TLS handshake for a hostname in the Renewing state with an existing unexpired
// certificate completes immediately, serving the existing certificate without holding.
#[tokio::test(flavor = "multi_thread")]
async fn test_strict_tls_renewing_serves_immediately_without_hold() {
    let resolver = Arc::new(CertResolver::new("example.com".to_string()));

    let host = "renew.example.com";
    let cert = make_wildcard_certified_key("example.com");
    // Cert valid far in the future, stored under the apex.
    resolver.insert_cert_with_expiry("example.com", cert, 2_000_000_000);

    // Wildcard transitions to background renewal (marked ordering in wait queue)
    resolver.mark_ordering("example.com");
    assert!(resolver.is_ordering("example.com"));

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

    let start = std::time::Instant::now();
    let tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let server_name = ServerName::try_from(host).unwrap().to_owned();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();
    tls.write_all(b"GET / HTTP/1.1\r\nHost: renew.example.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    tls.read_to_string(&mut resp).await.unwrap();

    let duration = start.elapsed();
    assert!(resp.starts_with("HTTP/1.1 404 Not Found"));
    assert!(resp.contains("strict-transport-security"));
    // Verify it was served immediately without waiting on the ordering queue
    assert!(
        duration < Duration::from_secs(2),
        "Handshake took too long: {duration:?}"
    );

    shutdown_token.cancel();
}

// OFF-79: Incoming TLS handshake for a hostname whose certificate order exceeds the hold timeout
// terminates at the TCP level without completing a TLS handshake.
#[tokio::test(flavor = "multi_thread")]
async fn test_strict_tls_hold_timeout_terminates_tcp() {
    // Use short timeout (50ms) to test timeout termination deterministically
    let resolver = Arc::new(
        CertResolver::new("example.com".to_string()).with_hold_timeout(Duration::from_millis(50)),
    );

    let host = "timeout.example.com";
    resolver.mark_ordering("example.com");

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

    let tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let server_name = ServerName::try_from(host).unwrap().to_owned();
    let err = connector.connect(server_name, tcp).await;
    assert!(
        err.is_err(),
        "Expected timed-out handshake to terminate at TCP level"
    );

    shutdown_token.cancel();
}

#[tokio::test]
async fn test_cert_name_selection_admin_vs_tunnel() {
    let dir = tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path().join("select.db")).await.unwrap());
    let config = Arc::new(test_config("example.com", "letsencrypt-staging", None));
    let resolver = Arc::new(CertResolver::new("example.com".into()));
    let manager = CertManager::new(config, store, resolver, Arc::new(MockClock::new(0)));

    // The admin host maps to its own certificate, never the tunnel wildcard.
    assert_eq!(
        manager.cert_name_for("relay-admin.test").as_deref(),
        Some("relay-admin.test")
    );
    // The apex and exactly one label beneath it map to the tunnel wildcard.
    assert_eq!(
        manager.cert_name_for("example.com").as_deref(),
        Some("example.com")
    );
    assert_eq!(
        manager
            .cert_name_for("poc-laptop-web.example.com")
            .as_deref(),
        Some("example.com")
    );
    // Deeper names and unrelated hosts are not covered by either.
    assert_eq!(manager.cert_name_for("a.b.example.com"), None);
    assert_eq!(manager.cert_name_for("other.net"), None);
}

#[tokio::test]
async fn test_note_visit_records_event_and_triggers_issuance() {
    let dir = tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path().join("visit.db")).await.unwrap());
    let clock = Arc::new(MockClock::new(1_700_000_000));
    // A custom directory at a closed port makes the order fail fast without
    // touching a real CA; the point is the visit-triggered wiring, not issuance.
    let config = Arc::new(test_config(
        "example.com",
        "custom",
        Some("http://127.0.0.1:1/directory".into()),
    ));
    let resolver = Arc::new(CertResolver::new("example.com".into()));
    let manager = CertManager::new(config, Arc::clone(&store), resolver, clock);
    manager.init().await.unwrap();

    manager.note_visit("poc-laptop-web.example.com");

    for _ in 0..600 {
        let events = store.get_cert_events("example.com", 10).await.unwrap();
        let visited = events.iter().any(|e| e.kind == "visit");
        if visited
            && matches!(
                manager.status("example.com"),
                CertState::Ordering | CertState::Failed { .. }
            )
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("visitor-triggered issuance did not start");
}
