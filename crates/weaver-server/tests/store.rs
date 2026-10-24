use std::net::SocketAddr;
use std::path::PathBuf;

use sea_orm::{ConnectionTrait, DbBackend, Statement};
use tempfile::TempDir;
use weaver_server::store::account::{
    ActivationOutcome, ActivationRequest, NewAuthEvent, NewPasswordResetToken,
    NewPendingRegistration, NewVerificationToken, ResetRequest,
};
use weaver_server::{Config, ConfigError, Store, StoreError};

/// Runs a scalar query and returns the first column of the first row.
async fn scalar<T>(store: &Store, sql: &str) -> T
where
    T: sea_orm::TryGetable,
{
    let row = store
        .db()
        .query_one_raw(Statement::from_string(DbBackend::Sqlite, sql))
        .await
        .expect("query failed")
        .expect("no row");
    row.try_get_by_index::<T>(0).expect("column decode failed")
}

/// Lowercase hex of a byte slice, for a SQL `X'…'` blob literal.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sample_config() -> Config {
    Config {
        tunnel_domain: "example.com".into(),
        admin_domain: "relay-admin.test".into(),
        admin_email: "admin@example.com".into(),
        acme_provider: "letsencrypt".into(),
        listen_http: "0.0.0.0:80".parse::<SocketAddr>().unwrap(),
        listen_https: "0.0.0.0:443".parse::<SocketAddr>().unwrap(),
        control_socket: PathBuf::from("/run/weaver/weaver.sock"),
        acme_directory: None,
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: None,
        acme_fallback_providers: vec!["letsencrypt-staging".into()],
        usage_flush_interval_secs: 60,
        usage_retention_secs: 31_536_000,
        relay_ips: Vec::new(),
        setup_complete: false,
        email: Some(weaver_server::config::test_email_config()),
        abuse: None,
        account: Default::default(),
    }
}

#[tokio::test]
async fn test_store_open_creates_dirs_and_files_with_correct_permissions() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let nested_dir = temp.path().join("nested").join("sub");
    let db_path = nested_dir.join("weaver.db");

    assert!(!nested_dir.exists());
    assert!(!db_path.exists());

    let store = Store::open(&db_path).await.expect("failed to open store");

    assert!(nested_dir.exists());
    assert!(db_path.exists());
    assert_eq!(store.path(), Some(db_path.as_path()));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir_perms = std::fs::metadata(&nested_dir)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        let file_perms = std::fs::metadata(&db_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(
            dir_perms, 0o700,
            "Parent directory mode should be 0700, got {dir_perms:o}"
        );
        assert_eq!(
            file_perms, 0o600,
            "Database file mode should be 0600, got {file_perms:o}"
        );
    }

    // Verify pragmas are applied to pooled connections
    let journal_mode: String = scalar(&store, "PRAGMA journal_mode;").await;
    assert_eq!(journal_mode.to_lowercase(), "wal");
    let busy_timeout: i64 = scalar(&store, "PRAGMA busy_timeout;").await;
    assert_eq!(busy_timeout, 5000);
    let foreign_keys: i64 = scalar(&store, "PRAGMA foreign_keys;").await;
    assert_eq!(foreign_keys, 1);
    let synchronous: i64 = scalar(&store, "PRAGMA synchronous;").await;
    assert_eq!(synchronous, 1, "1 is NORMAL");
    let temp_store: i64 = scalar(&store, "PRAGMA temp_store;").await;
    assert_eq!(temp_store, 2, "2 is MEMORY");

    store.close().await.expect("close failed");
}

#[tokio::test]
async fn test_store_open_runs_migrations_and_is_idempotent() {
    let temp = TempDir::new().expect("tempdir");
    let db_path = temp.path().join("weaver.db");

    {
        let store = Store::open(&db_path).await.expect("open failed");
        let count: i64 = scalar(
            &store,
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('config', 'acme_account', 'domains', 'certificates', 'cert_events', 'seaql_migrations', 'person', 'machine', 'machine_key_log', 'service', 'usage_daily', 'usage_live', 'challenge', 'abuse_bucket', 'auth_event', 'login_challenge')",
        )
        .await;
        assert_eq!(count, 16);
        assert_eq!(store.schema_version().await.expect("schema_version"), 4);
    }

    // Re-open existing database: should succeed and not re-apply migrations
    {
        let store = Store::open(&db_path).await.expect("re-open failed");
        let migration_count: i64 = scalar(&store, "SELECT count(*) FROM seaql_migrations").await;
        assert_eq!(migration_count, 4);
        assert_eq!(store.schema_version().await.expect("schema_version"), 4);
    }
}

#[tokio::test]
async fn test_store_connect_in_memory_url() {
    let store = Store::connect("sqlite::memory:")
        .await
        .expect("in-memory connect failed");
    assert_eq!(store.path(), None);
    assert_eq!(store.url(), "sqlite::memory:");
    store.save_config(&sample_config()).await.expect("save");
    assert_eq!(store.load_config().await.expect("load"), sample_config());
}

#[tokio::test]
async fn test_store_open_rejects_non_utf8_path_gracefully() {
    // Opening a path whose parent is a regular file cannot succeed; ensure the
    // failure surfaces as an error rather than a panic.
    let temp = TempDir::new().expect("tempdir");
    let blocker = temp.path().join("file");
    std::fs::write(&blocker, b"x").unwrap();
    let db_path = blocker.join("weaver.db");
    match Store::open(&db_path).await {
        Err(StoreError::Io(_)) | Err(StoreError::Db(_)) => {}
        res => panic!("Expected open error, got: {res:?}"),
    }
}

#[tokio::test]
async fn test_config_load_on_unconfigured_db_lists_missing_keys() {
    let temp = TempDir::new().expect("tempdir");
    let db_path = temp.path().join("unconfigured.db");
    let store = Store::open(&db_path).await.expect("open failed");

    match Config::load(&store).await {
        Err(ConfigError::MissingKeys(keys)) => {
            assert!(keys.contains(&"tunnel_domain".to_string()));
            assert!(keys.contains(&"admin_email".to_string()));
            assert!(keys.contains(&"acme_provider".to_string()));
            assert!(keys.contains(&"listen_http".to_string()));
            assert!(keys.contains(&"listen_https".to_string()));
            assert!(keys.contains(&"control_socket".to_string()));
        }
        res => panic!("Expected MissingKeys, got: {res:?}"),
    }
}

#[tokio::test]
async fn test_config_save_and_load_round_trip() {
    let temp = TempDir::new().expect("tempdir");
    let db_path = temp.path().join("config_rt.db");
    let store = Store::open(&db_path).await.expect("open failed");

    let config = sample_config();
    store
        .save_config(&config)
        .await
        .expect("save_config failed");

    let loaded = Config::load(&store).await.expect("load failed");
    assert_eq!(loaded, config);

    // Test store.load_config() shortcut
    let loaded_shortcut = store.load_config().await.expect("shortcut load failed");
    assert_eq!(loaded_shortcut, config);

    // Saving again must replace, not duplicate, the singleton row
    store
        .save_config(&config)
        .await
        .expect("second save failed");
    let rows: i64 = scalar(&store, "SELECT count(*) FROM config").await;
    assert_eq!(rows, 1);
}

#[tokio::test]
async fn test_config_validation_rules() {
    let temp = TempDir::new().expect("tempdir");
    let db_path = temp.path().join("validation.db");
    let store = Store::open(&db_path).await.expect("open failed");

    // Google provider requires EAB kid and hmac
    let invalid_google_config = Config {
        acme_provider: "google".into(),
        acme_fallback_providers: vec![],
        account: Default::default(),
        ..sample_config()
    };

    store
        .save_config(&invalid_google_config)
        .await
        .expect("save succeeded");
    match Config::load(&store).await {
        Err(ConfigError::ValidationFailed(issues)) => {
            assert!(issues.iter().any(|i| i.contains("requires acme_eab_kid")));
            assert!(issues.iter().any(|i| i.contains("requires acme_eab_hmac")));
        }
        res => panic!("Expected ValidationFailed, got: {res:?}"),
    }

    // Custom provider requires acme_directory
    let invalid_custom_config = Config {
        acme_provider: "custom".into(),
        account: Default::default(),
        ..invalid_google_config.clone()
    };
    store
        .save_config(&invalid_custom_config)
        .await
        .expect("save succeeded");
    match Config::load(&store).await {
        Err(ConfigError::ValidationFailed(issues)) => {
            assert!(issues.iter().any(|i| i.contains("requires acme_directory")));
        }
        res => panic!("Expected ValidationFailed, got: {res:?}"),
    }

    // Invalid email validation
    let invalid_email_config = Config {
        acme_provider: "letsencrypt".into(),
        admin_email: "not-an-email".into(),
        account: Default::default(),
        ..invalid_google_config
    };
    store
        .save_config(&invalid_email_config)
        .await
        .expect("save succeeded");
    match Config::load(&store).await {
        Err(ConfigError::ValidationFailed(issues)) => {
            assert!(issues.iter().any(|i| i.contains("not a valid email")));
        }
        res => panic!("Expected ValidationFailed, got: {res:?}"),
    }

    // Foot-gun: an admin domain nested under the delegated tunnel zone
    // would hand the relay's own DNS to the zone the relay is meant to control.
    let nested_admin_config = Config {
        admin_domain: "relay.example.com".into(),
        account: Default::default(),
        ..sample_config()
    };
    store
        .save_config(&nested_admin_config)
        .await
        .expect("save succeeded");
    match Config::load(&store).await {
        Err(ConfigError::ValidationFailed(issues)) => {
            assert!(
                issues.iter().any(|i| i.contains("subdomain")),
                "expected subdomain rejection, got: {issues:?}"
            );
        }
        res => panic!("Expected ValidationFailed, got: {res:?}"),
    }

    // Same name for both is equally unsafe.
    let same_name_config = Config {
        admin_domain: "example.com".into(),
        account: Default::default(),
        ..sample_config()
    };
    store
        .save_config(&same_name_config)
        .await
        .expect("save succeeded");
    match Config::load(&store).await {
        Err(ConfigError::ValidationFailed(issues)) => {
            assert!(issues.iter().any(|i| i.contains("must differ")));
        }
        res => panic!("Expected ValidationFailed, got: {res:?}"),
    }

    // The reverse nesting (tunnel under admin) is safe and must load.
    let tunnel_under_admin = Config {
        tunnel_domain: "tunnels.relay.example.net".into(),
        admin_domain: "relay.example.net".into(),
        acme_provider: "letsencrypt".into(),
        admin_email: "admin@example.com".into(),
        account: Default::default(),
        ..sample_config()
    };
    store
        .save_config(&tunnel_under_admin)
        .await
        .expect("save succeeded");
    assert!(
        Config::load(&store).await.is_ok(),
        "tunnel under admin must be allowed"
    );
}

#[tokio::test]
async fn test_config_validation_abuse_limits() {
    use weaver_server::config::{AbuseConfig, BudgetConfig};

    let temp = TempDir::new().expect("tempdir");
    let store = Store::open(temp.path().join("abuse.db"))
        .await
        .expect("open failed");

    // A coherent armed block loads.
    let ok = Config {
        abuse: Some(AbuseConfig {
            enabled: true,
            peer_host: BudgetConfig {
                burst: 5,
                refill_units: 5,
                refill_per_secs: 60,
            },
            peer_network: BudgetConfig {
                burst: 50,
                refill_units: 50,
                refill_per_secs: 60,
            },
            retry_after_cap_secs: 120,
            bucket_ttl_secs: 3600,
            altcha: None,
        }),
        account: Default::default(),
        ..sample_config()
    };
    store.save_config(&ok).await.expect("save succeeded");
    assert!(Config::load(&store).await.is_ok());

    // A zero burst can never admit anything and is rejected.
    let bad = Config {
        abuse: Some(AbuseConfig {
            peer_host: BudgetConfig {
                burst: 0,
                refill_units: 5,
                refill_per_secs: 60,
            },
            ..ok.abuse.clone().unwrap()
        }),
        account: Default::default(),
        ..ok.clone()
    };
    store.save_config(&bad).await.expect("save succeeded");
    match Config::load(&store).await {
        Err(ConfigError::ValidationFailed(issues)) => {
            assert!(
                issues.iter().any(|i| i.contains("abuse.peer_host.burst")),
                "expected a peer_host.burst issue, got: {issues:?}"
            );
        }
        res => panic!("Expected ValidationFailed, got: {res:?}"),
    }

    // A disabled block is never rejected: its numbers are not in play.
    let disabled = Config {
        abuse: Some(AbuseConfig {
            enabled: false,
            peer_host: BudgetConfig {
                burst: 0,
                refill_units: 0,
                refill_per_secs: 0,
            },
            ..ok.abuse.clone().unwrap()
        }),
        account: Default::default(),
        ..ok.clone()
    };
    store.save_config(&disabled).await.expect("save succeeded");
    assert!(
        Config::load(&store).await.is_ok(),
        "a disabled abuse block must not be validated"
    );
}

#[tokio::test]
async fn test_set_config_mutates_single_key() {
    let temp = TempDir::new().expect("tempdir");
    let db_path = temp.path().join("set_config.db");
    let store = Store::open(&db_path).await.expect("open failed");

    for (k, v) in [
        ("tunnel_domain", "tunnel.nexus.com"),
        ("admin_domain", "\"relay.nexus.com\""),
        ("admin_email", "ops@nexus.com"),
        ("acme_provider", "letsencrypt"),
        ("listen_http", "\"127.0.0.1:8080\""),
        ("listen_https", "\"127.0.0.1:8443\""),
        ("control_socket", "\"/tmp/control.sock\""),
        // Email is required (WVR-167), so the block must be there too.
        (
            "email",
            "{\"provider\":\"resend\",\"from\":\"no-reply@weaver.test\",\"api_key\":\"test-api-key\"}",
        ),
    ] {
        store.set_config(k, v).await.expect("set_config failed");
    }

    let loaded = store.load_config().await.expect("load_config failed");
    assert_eq!(loaded.tunnel_domain, "tunnel.nexus.com");
    assert_eq!(loaded.admin_email, "ops@nexus.com");
    assert_eq!(loaded.acme_provider, "letsencrypt");
    assert_eq!(
        loaded.listen_http,
        "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
    );
}

#[tokio::test]
async fn test_backup_creates_openable_database() {
    let temp = TempDir::new().expect("tempdir");
    let original_db = temp.path().join("original.db");
    let backup_db = temp.path().join("backup.db");

    let store = Store::open(&original_db).await.expect("open failed");
    let config = Config {
        tunnel_domain: "backup.nexus.com".into(),
        account: Default::default(),
        ..sample_config()
    };
    store.save_config(&config).await.expect("save failed");

    // Perform backup
    store.backup(&backup_db).await.expect("backup failed");
    assert!(backup_db.exists());

    // Open backup database directly and verify contents
    let backup_store = Store::open(&backup_db).await.expect("open backup failed");
    let loaded_config = backup_store
        .load_config()
        .await
        .expect("load backup config failed");
    assert_eq!(loaded_config, config);
}

#[tokio::test]
async fn test_auth_persistence_and_identity_resolution() {
    use weaver_mux::KeyId;
    use weaver_mux::auth::PublicKey;
    use weaver_server::tunnel::StoreIdentityResolver;

    let temp = TempDir::new().expect("tempdir");
    let db_path = temp.path().join("auth.db");
    let store = Store::open(&db_path).await.expect("open failed");

    // Identities are never created implicitly: enrol a person, a machine, and
    // a key explicitly, then resolve that custom key.
    let alice = store
        .create_test_person("Alice")
        .await
        .expect("create person");
    assert_eq!(alice.name, "alice");

    let alice_key = KeyId::Ed25519([0x42; 32]);
    let desktop = store
        .create_machine(alice.id, "Workstation", &alice_key)
        .await
        .expect("create machine");
    assert_eq!(desktop.name, "workstation");
    assert_eq!(desktop.person_id, alice.id);
    assert_eq!(desktop.key_id, format!("ed25519:{}", "42".repeat(32)));

    let resolver = StoreIdentityResolver::new(store.clone());
    let id = resolver.identity(&alice_key).await.expect("resolve alice");
    assert_eq!(id.person, "alice");
    assert_eq!(id.machine, "workstation");
    // The resolver serves the *stored* public key material.
    assert_eq!(
        resolver.public_key(&alice_key).await,
        Some(PublicKey::Ed25519([0x42; 32]))
    );

    // An unenrolled key resolves to nothing.
    let unknown_key = KeyId::Ed25519([0xAA; 32]);
    assert!(resolver.identity(&unknown_key).await.is_none());
    assert!(resolver.public_key(&unknown_key).await.is_none());

    // A declared service attaches to the machine and links its flat hostname.
    let svc = store
        .register_declared_service(desktop.id, "alice-workstation-api.example.com", "api")
        .await
        .expect("register service");
    assert_eq!(svc.name, "api");
    assert_eq!(svc.machine_id, desktop.id);

    let domain = store
        .get_domain("alice-workstation-api.example.com")
        .await
        .expect("get domain")
        .expect("domain present");
    assert_eq!(domain.service_id, Some(svc.id));
}

#[tokio::test]
async fn test_certificate_and_event_round_trip() {
    let store = Store::connect("sqlite::memory:").await.expect("connect");
    let cert = weaver_server::store::NewCertificate {
        cert_pem: "CERT".into(),
        key_pem: "KEY".into(),
        not_before: 100,
        not_after: 200,
        directory: "https://acme.test/dir".into(),
        obtained_at: 100,
        validation: "dns-01".to_string(),
    };
    store
        .save_certificate("host.example.com", cert.clone())
        .await
        .expect("save");

    // Lookup is case-insensitive on the caller side
    let rec = store
        .get_certificate("HOST.example.com")
        .await
        .expect("get")
        .expect("present");
    assert_eq!(rec.name, "host.example.com");
    assert_eq!(rec.not_after, 200);
    assert_eq!(rec.validation, "dns-01");

    // Saving under the same name upserts in place: one global row per name.
    store
        .save_certificate(
            "host.example.com",
            weaver_server::store::NewCertificate {
                not_after: 300,
                ..cert
            },
        )
        .await
        .expect("save 2");

    assert_eq!(store.list_certificates().await.expect("list").len(), 1);
    assert_eq!(
        store
            .get_certificate("host.example.com")
            .await
            .unwrap()
            .unwrap()
            .not_after,
        300
    );

    // Lookup by certificate PK ID
    let best_cert = store
        .get_certificate("host.example.com")
        .await
        .unwrap()
        .unwrap();
    let rec_by_id = store
        .get_certificate_by_id(best_cert.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rec_by_id.name, "host.example.com");
    assert_eq!(rec_by_id.not_after, 300);

    // The full record carries PEM material for cache hydration.
    let full = store.list_certificates_full().await.unwrap();
    assert_eq!(full.len(), 1);
    assert_eq!(full[0].cert_pem, "CERT");
    assert_eq!(full[0].key_pem, "KEY");
    assert_eq!(full[0].validation, "dns-01");

    // Events, newest first
    store
        .record_cert_event("host.example.com", 10, "issued", "")
        .await
        .expect("event 1");
    store
        .record_cert_event("host.example.com", 20, "failed", "boom")
        .await
        .expect("event 2");
    let events = store
        .get_cert_events("host.example.com", 10)
        .await
        .expect("events");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].kind, "failed");
    assert_eq!(events[0].detail, "boom");
    let latest = store
        .get_latest_cert_event("host.example.com")
        .await
        .expect("latest")
        .expect("present");
    assert_eq!(latest.at, 20);
}

#[tokio::test]
async fn test_challenge_kinds_are_isolated_and_validation_round_trips() {
    let store = Store::connect("sqlite::memory:").await.expect("connect");

    // DNS-01 TXT rows and HTTP-01 token rows live in the same table but never
    // leak into each other's reads.
    store
        .publish_challenge("_acme-challenge.example.com", "digest-a", "example.com", 1)
        .await
        .unwrap();
    store
        .publish_http01("token-1", "key-auth-1", "admin.example.com", 1)
        .await
        .unwrap();

    assert_eq!(
        store
            .get_challenges("_acme-challenge.example.com")
            .await
            .unwrap(),
        vec!["digest-a".to_string()]
    );
    // The TXT reader must not return a key authorization even if a token row
    // happens to share the queried name.
    assert!(store.get_challenges("token-1").await.unwrap().is_empty());
    assert_eq!(
        store.get_http01("token-1").await.unwrap().as_deref(),
        Some("key-auth-1")
    );

    // HTTP-01 rows are removed by token, DNS-01 by (name, value).
    store.remove_http01("token-1").await.unwrap();
    assert!(store.get_http01("token-1").await.unwrap().is_none());
    store
        .remove_challenge("_acme-challenge.example.com", "digest-a")
        .await
        .unwrap();
    assert!(
        store
            .get_challenges("_acme-challenge.example.com")
            .await
            .unwrap()
            .is_empty()
    );

    // `validation` round-trips both mechanisms.
    for (name, mechanism) in [("example.com", "dns-01"), ("relay.example.net", "http-01")] {
        store
            .save_certificate(
                name,
                weaver_server::store::NewCertificate {
                    cert_pem: format!("CERT-{name}"),
                    key_pem: "KEY".into(),
                    not_before: 1,
                    not_after: 2,
                    directory: "https://acme.test/dir".into(),
                    obtained_at: 1,
                    validation: mechanism.to_string(),
                },
            )
            .await
            .unwrap();
        let rec = store.get_certificate(name).await.unwrap().unwrap();
        assert_eq!(rec.validation, mechanism);
    }
}

#[tokio::test]
async fn test_acme_account_round_trip() {
    let store = Store::connect("sqlite::memory:").await.expect("connect");
    assert!(store.get_acme_account("d").await.unwrap().is_none());
    store
        .upsert_acme_account("d", "a@b.c", "{}", 1)
        .await
        .expect("upsert");
    store
        .upsert_acme_account("d", "a@b.c", "{\"k\":1}", 2)
        .await
        .expect("upsert 2");
    let acct = store.get_acme_account("d").await.unwrap().unwrap();
    assert_eq!(acct.credentials_json, "{\"k\":1}");
    assert_eq!(acct.created_at, 2);
}

#[tokio::test]
async fn test_multiple_certificates_distinct_names() {
    let store = Store::connect("sqlite::memory:").await.expect("connect");

    let cert = |pem: &str, not_after: i64| weaver_server::store::NewCertificate {
        cert_pem: pem.into(),
        key_pem: format!("KEY-{pem}"),
        not_before: 1_000,
        not_after,
        directory: "dir".into(),
        obtained_at: 1_000,
        validation: "dns-01".to_string(),
    };

    store
        .save_certificate("a.example.com", cert("PEM1", 2_000))
        .await
        .unwrap();
    store
        .save_certificate("b.example.com", cert("PEM2", 3_000))
        .await
        .unwrap();
    store
        .save_certificate("c.example.com", cert("PEM3", 1_200))
        .await
        .unwrap();

    // Certificates are global and keyed by name: three distinct rows.
    assert_eq!(store.list_certificates().await.unwrap().len(), 3);
    assert_eq!(store.list_certificates_full().await.unwrap().len(), 3);

    let names: Vec<String> = store
        .list_certificates()
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.name)
        .collect();
    assert_eq!(
        names,
        vec!["a.example.com", "b.example.com", "c.example.com"]
    );

    // Re-saving one name upserts that row and leaves the others untouched.
    store
        .save_certificate("b.example.com", cert("PEM2B", 4_000))
        .await
        .unwrap();
    assert_eq!(store.list_certificates().await.unwrap().len(), 3);
    let b = store
        .get_certificate("b.example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(b.not_after, 4_000);
    let full_b = store
        .list_certificates_full()
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.name == "b.example.com")
        .unwrap();
    assert_eq!(full_b.cert_pem, "PEM2B");
}

#[tokio::test]
async fn test_domain_and_certificate_lifecycles_are_independent() {
    use sea_orm::EntityTrait;
    let store = Store::connect("sqlite::memory:").await.expect("connect");

    let cert = weaver_server::store::NewCertificate {
        cert_pem: "PEM".into(),
        key_pem: "KEY".into(),
        not_before: 1_000,
        not_after: 2_000,
        directory: "dir".into(),
        obtained_at: 1_000,
        validation: "dns-01".to_string(),
    };
    let saved = store
        .save_certificate("cascade.example.com", cert)
        .await
        .unwrap();

    // A materialized domain is independent of the certificate table.
    let domain = store
        .get_or_create_domain("cascade.example.com", None)
        .await
        .unwrap();

    // Certificates are global: deleting a domain must not delete them.
    weaver_server::store::entity::domain::Entity::delete_by_id(domain.id)
        .exec(store.db())
        .await
        .unwrap();
    assert!(
        store
            .get_certificate("cascade.example.com")
            .await
            .unwrap()
            .is_some(),
        "deleting a domain must leave the global certificate alone"
    );

    // Deleting the certificate leaves the domain alone: the covering
    // certificate is resolved at run time, not by a foreign key.
    let recreated = store
        .get_or_create_domain("cascade.example.com", None)
        .await
        .unwrap();
    weaver_server::store::entity::certificate::Entity::delete_by_id(saved.id)
        .exec(store.db())
        .await
        .unwrap();
    let after = store
        .get_domain("cascade.example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.id, recreated.id);
}

#[tokio::test]
async fn test_naming_rules_reject_invalid_names() {
    use weaver_mux::KeyId;

    let store = Store::connect("sqlite::memory:").await.expect("connect");

    for bad in ["", "has-dash", "under_score", "Upper!", &"a".repeat(16)] {
        assert!(
            matches!(
                store.create_person(1, bad).await,
                Err(StoreError::InvalidName(_))
            ),
            "person {bad:?} must be rejected"
        );
    }

    let alice = store.create_test_person("alice").await.unwrap();
    let key = KeyId::Ed25519([0x33; 32]);
    for bad in ["", "has-dash", "under_score", "Upper!", &"a".repeat(16)] {
        assert!(
            matches!(
                store.create_machine(alice.id, bad, &key).await,
                Err(StoreError::InvalidName(_))
            ),
            "machine {bad:?} must be rejected"
        );
    }

    let laptop = store
        .create_machine(alice.id, "laptop", &key)
        .await
        .unwrap();
    // Service names allow dashes between alphanumeric runs but not leading,
    // trailing, doubled, or non-alphanumeric characters.
    for bad in [
        "",
        "-web",
        "web-",
        "a--b",
        "a.b",
        "web/api",
        "My-Web",
        &"a".repeat(32),
    ] {
        assert!(
            matches!(
                store.get_or_create_service(laptop.id, bad).await,
                Err(StoreError::InvalidName(_))
            ),
            "service {bad:?} must be rejected"
        );
    }

    let svc = store
        .get_or_create_service(laptop.id, "my-web")
        .await
        .unwrap();
    assert_eq!(svc.name, "my-web");

    // A declared service is keyed by the flat hostname and validated at the
    // store boundary too (an invalid service never reaches persistence).
    assert!(matches!(
        store
            .register_declared_service(laptop.id, "alice-laptop-x.example.com", "a--b")
            .await,
        Err(StoreError::InvalidName(_))
    ));
}

#[tokio::test]
async fn test_migration_usage_round_trips() {
    use sea_orm_migration::MigratorTrait;

    let temp = TempDir::new().expect("tempdir");
    let db_path = temp.path().join("migrate.db");
    let store = Store::open(&db_path).await.expect("open");

    // Roll the schema back, then re-apply: a full rebuild is what proves
    // `down`/`up` are symmetric.
    weaver_server::Migrator::down(store.db(), None)
        .await
        .expect("down");
    assert_eq!(
        scalar::<i64>(
            &store,
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='usage_live'"
        )
        .await,
        0,
        "down must drop the live-slot table"
    );

    weaver_server::Migrator::up(store.db(), None)
        .await
        .expect("up");
    assert_eq!(
        scalar::<i64>(
            &store,
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='usage_live'"
        )
        .await,
        1,
        "up must recreate the live-slot table"
    );
    // The old per-minute table is gone for good, on a fresh database too.
    assert_eq!(
        scalar::<i64>(
            &store,
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='usage'"
        )
        .await,
        0,
        "the per-minute table must not come back"
    );
}

// ---------------------------------------------------------------------------
// Email attribution is atomic.
//
// These exercise the store boundary directly: a verified signup must land as an
// atomic unit (account + identity + ownership history + one current credential),
// one address must resolve to exactly one account even when two activations
// race, and an account display name must never leak into the tunnel `person`
// namespace.
// ---------------------------------------------------------------------------

/// Stages a verified signup and returns the ids needed to activate it:
/// `(pending_registration_id, proof_token_id, completion_token_id)`.
///
/// The emailed link is followed (the proof token is consumed) and a fresh
/// completion token is minted, mirroring signup → verify → complete.
async fn stage_verified_signup(
    store: &Store,
    name: &str,
    email: &str,
    lookup_key: &str,
    now: i64,
) -> (i32, i32, i32) {
    let pending = store
        .pending_registration_create(NewPendingRegistration {
            flow_id: format!("flow-{name}-{lookup_key}"),
            name: name.to_string(),
            email: email.to_string(),
            lookup_key: lookup_key.to_string(),
            created_at: now,
            expires_at: now + 10_000,
        })
        .await
        .expect("pending registration");

    let proof = store
        .verification_token_issue(
            pending.id,
            NewVerificationToken {
                email_lookup_key: lookup_key.to_string(),
                token_digest: format!("proof-{name}-{lookup_key}"),
                purpose: "email-verification".to_string(),
                issued_at: now,
                expires_at: now + 10_000,
            },
        )
        .await
        .expect("proof token");
    // The user clicked the emailed link; the proof token is spent before the
    // completion window opens.
    assert!(
        store
            .verification_token_consume(proof.id, now)
            .await
            .unwrap(),
        "the proof token must be consumable"
    );

    let completion = store
        .verification_token_issue(
            pending.id,
            NewVerificationToken {
                email_lookup_key: lookup_key.to_string(),
                token_digest: format!("completion-{name}-{lookup_key}"),
                purpose: "registration-completion".to_string(),
                issued_at: now,
                expires_at: now + 10_000,
            },
        )
        .await
        .expect("completion token");

    (pending.id, proof.id, completion.id)
}

/// Activates a staged signup through the store's atomic entry point.
#[allow(clippy::too_many_arguments)]
async fn activate(
    store: &Store,
    pending_registration_id: i32,
    proof_token_id: i32,
    consume_token_id: i32,
    name: &str,
    email: &str,
    lookup_key: &str,
    encoded_hash: &str,
    now: i64,
) -> ActivationOutcome {
    store
        .account_activate(ActivationRequest {
            pending_registration_id,
            consume_token_id,
            proof_token_id,
            name,
            email,
            lookup_key,
            encoded_hash,
            now,
        })
        .await
        .expect("activation should succeed")
}

#[tokio::test]
async fn test_account_activation_links_ownership_and_password_history() {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    use weaver_server::store::entity::{
        email_verification, password_credential, verification_token,
    };

    let temp = TempDir::new().expect("tempdir");
    let store = Store::open(temp.path().join("activate.db"))
        .await
        .expect("open failed");
    let now = 1_000;
    let hash = "$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA";

    let (pending, proof, completion) =
        stage_verified_signup(&store, "Rémy", "remy@example.com", "remy@example.com", now).await;
    let outcome = activate(
        &store,
        pending,
        proof,
        completion,
        "Rémy",
        "remy@example.com",
        "remy@example.com",
        hash,
        now,
    )
    .await;
    let account = match outcome {
        ActivationOutcome::Activated(account) => account,
        other => panic!("expected a fresh activation, got {other:?}"),
    };

    // The address is claimed by this account and marked verified.
    let identity = store
        .email_identity_for_account(account.id)
        .await
        .unwrap()
        .expect("one identity per account");
    assert_eq!(identity.lookup_key, "remy@example.com");
    assert_eq!(identity.verified_at, Some(now));
    let found = store
        .email_identity_find("remy@example.com")
        .await
        .unwrap()
        .expect("address resolves to its account");
    assert_eq!(found.account_id, account.id);

    // The ownership history is a real row referencing the *consumed* proof
    // token, not a boolean on the account.
    let history = email_verification::Entity::find()
        .filter(email_verification::Column::AccountId.eq(account.id))
        .all(store.db())
        .await
        .unwrap();
    assert_eq!(history.len(), 1, "exactly one initial verification row");
    assert_eq!(history[0].email_identity_id, identity.id);
    assert_eq!(history[0].token_id, proof, "history cites the proof token");
    assert_eq!(history[0].verified_at, now);
    let proof_token = verification_token::Entity::find_by_id(proof)
        .one(store.db())
        .await
        .unwrap()
        .expect("proof token survives as audit provenance");
    assert!(
        proof_token.consumed_at.is_some(),
        "the proof token must be spent"
    );

    // Exactly one current credential, referencing the initial hash.
    let credentials = password_credential::Entity::find()
        .filter(password_credential::Column::AccountId.eq(account.id))
        .all(store.db())
        .await
        .unwrap();
    assert_eq!(credentials.len(), 1, "activation writes one credential");
    assert_eq!(credentials[0].encoded_hash, hash);
    assert!(credentials[0].retired_at.is_none(), "it is the current one");
    let current = store
        .password_current_for(account.id)
        .await
        .unwrap()
        .expect("a current credential");
    assert_eq!(current.encoded_hash, hash);

    // The completion token is consumed by the same atomic step.
    let completion_token = verification_token::Entity::find_by_id(completion)
        .one(store.db())
        .await
        .unwrap()
        .expect("completion token row");
    assert!(
        completion_token.consumed_at.is_some(),
        "the completion token must be spent"
    );
}

#[tokio::test]
async fn test_concurrent_activation_of_one_address_has_one_owner() {
    let temp = TempDir::new().expect("tempdir");
    let store = Store::open(temp.path().join("race.db"))
        .await
        .expect("open failed");
    let now = 1_000;
    let lookup = "dupe@example.com";
    let hash_first = "$argon2id$v=19$m=8,t=1,p=1$Zmlyc3Q$aGFzaA";
    let hash_second = "$argon2id$v=19$m=8,t=1,p=1$c2Vjb25k$aGFzaA";

    // Two racing signups for one address: distinct flows and tokens, same key.
    let (p1, proof1, c1) = stage_verified_signup(&store, "First", lookup, lookup, now).await;
    let (p2, proof2, c2) = stage_verified_signup(&store, "Second", lookup, lookup, now).await;

    let (r1, r2) = tokio::join!(
        activate(
            &store, p1, proof1, c1, "First", lookup, lookup, hash_first, now
        ),
        activate(
            &store,
            p2,
            proof2,
            c2,
            "Second",
            lookup,
            lookup,
            hash_second,
            now
        ),
    );

    // Exactly one activation wins; the other confirms the existing account.
    let (winner, existing_id) = match (r1, r2) {
        (ActivationOutcome::Activated(winner), ActivationOutcome::ExistingAccount(existing)) => {
            (winner, existing.id)
        }
        (ActivationOutcome::ExistingAccount(existing), ActivationOutcome::Activated(winner)) => {
            (winner, existing.id)
        }
        other => panic!("expected one Activated and one ExistingAccount, got {other:?}"),
    };
    assert_eq!(
        existing_id, winner.id,
        "the loser hands back the real owner"
    );

    // At the database level there is exactly one account and one identity for
    // the address; the loser's placeholder account was rolled back.
    let accounts: i64 = scalar(&store, "SELECT count(*) FROM account").await;
    assert_eq!(accounts, 1, "one address must yield one account");
    let identities: i64 = scalar(&store, "SELECT count(*) FROM email_identity").await;
    assert_eq!(identities, 1, "one address must yield one identity");

    // The winner's credential is intact and unchanged; the loser wrote none.
    let expected = if winner.name == "First" {
        hash_first
    } else {
        hash_second
    };
    let current = store
        .password_current_for(winner.id)
        .await
        .unwrap()
        .expect("the winner has a credential");
    assert_eq!(current.encoded_hash, expected);
    let credentials: i64 = scalar(&store, "SELECT count(*) FROM password_credential").await;
    assert_eq!(credentials, 1, "the loser must not write a credential");
}

#[tokio::test]
async fn test_same_name_different_emails_and_account_person_separation() {
    use sea_orm::EntityTrait;
    use weaver_server::store::entity::person;

    let temp = TempDir::new().expect("tempdir");
    let store = Store::open(temp.path().join("names.db"))
        .await
        .expect("open failed");
    let now = 1_000;
    let hash = "$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA";

    let (p1, proof1, c1) =
        stage_verified_signup(&store, "Rémy", "a@example.com", "a@example.com", now).await;
    let (p2, proof2, c2) =
        stage_verified_signup(&store, "Rémy", "b@example.com", "b@example.com", now).await;

    let first = match activate(
        &store,
        p1,
        proof1,
        c1,
        "Rémy",
        "a@example.com",
        "a@example.com",
        hash,
        now,
    )
    .await
    {
        ActivationOutcome::Activated(account) => account,
        other => panic!("expected activation for a@example.com, got {other:?}"),
    };
    let second = match activate(
        &store,
        p2,
        proof2,
        c2,
        "Rémy",
        "b@example.com",
        "b@example.com",
        hash,
        now,
    )
    .await
    {
        ActivationOutcome::Activated(account) => account,
        other => panic!("expected activation for b@example.com, got {other:?}"),
    };

    // Two distinct accounts may share one display name, Unicode preserved.
    assert_ne!(first.id, second.id);
    assert_eq!(first.name, "Rémy");
    assert_eq!(second.name, "Rémy");

    // Identity is resolved through the email, never the name.
    assert_eq!(
        store
            .email_identity_find("a@example.com")
            .await
            .unwrap()
            .unwrap()
            .account_id,
        first.id
    );
    assert_eq!(
        store
            .email_identity_find("b@example.com")
            .await
            .unwrap()
            .unwrap()
            .account_id,
        second.id
    );

    // The account plane never touches the tunnel `person` namespace: only
    // pairing creates a person.
    let people = person::Entity::find().all(store.db()).await.unwrap();
    assert!(
        people.is_empty(),
        "accounts must not add person rows: {people:?}"
    );
}

// ----- password reset ---------------------------------------------

/// Activates a fresh account for one address and returns its id, for the reset
/// store tests.
async fn activate_account(store: &Store, email: &str, now: i64) -> i32 {
    let hash = "$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA";
    let (pending, proof, completion) =
        stage_verified_signup(store, "Rémy", email, email, now).await;
    match activate(
        store, pending, proof, completion, "Rémy", email, email, hash, now,
    )
    .await
    {
        ActivationOutcome::Activated(account) => account.id,
        other => panic!("expected activation for {email}, got {other:?}"),
    }
}

#[tokio::test]
async fn test_issue_reset_token_revokes_outstanding() {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    use weaver_server::store::entity::password_reset_token;

    let temp = TempDir::new().expect("tempdir");
    let store = Store::open(temp.path().join("reset-issue.db"))
        .await
        .expect("open failed");
    let now = 1_000;
    let account_id = activate_account(&store, "reset@example.com", now).await;

    let first = store
        .password_reset_token_issue(
            account_id,
            NewPasswordResetToken {
                token_digest: "digest-one".into(),
                issued_at: now,
                expires_at: now + 3_600,
            },
        )
        .await
        .expect("first reset token");
    let second = store
        .password_reset_token_issue(
            account_id,
            NewPasswordResetToken {
                token_digest: "digest-two".into(),
                issued_at: now + 10,
                expires_at: now + 3_610,
            },
        )
        .await
        .expect("second reset token");

    let rows = password_reset_token::Entity::find()
        .filter(password_reset_token::Column::AccountId.eq(account_id))
        .all(store.db())
        .await
        .unwrap();
    assert_eq!(rows.len(), 2, "history is preserved, not overwritten");
    let earlier = rows.iter().find(|r| r.id == first.id).unwrap();
    assert!(
        earlier.revoked_at.is_some(),
        "the earlier token is revoked when a new one is issued"
    );
    let latest = rows.iter().find(|r| r.id == second.id).unwrap();
    assert!(
        latest.revoked_at.is_none() && latest.consumed_at.is_none(),
        "only the latest token is live"
    );
}

#[tokio::test]
async fn test_account_reset_password_supersedes_and_revokes() {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
    use weaver_server::store::entity::{
        browser_session, password_credential, password_reset_token,
    };

    let temp = TempDir::new().expect("tempdir");
    let store = Store::open(temp.path().join("reset-apply.db"))
        .await
        .expect("open failed");
    let now = 1_000;
    let account_id = activate_account(&store, "reset2@example.com", now).await;

    // Two live sessions before the reset (e.g. laptop and phone).
    store
        .session_create(account_id, "session-one", now, now + 100_000)
        .await
        .unwrap();
    store
        .session_create(account_id, "session-two", now, now + 100_000)
        .await
        .unwrap();

    let token = store
        .password_reset_token_issue(
            account_id,
            NewPasswordResetToken {
                token_digest: "digest-apply".into(),
                issued_at: now,
                expires_at: now + 3_600,
            },
        )
        .await
        .expect("reset token");

    let new_hash = "$argon2id$v=19$m=8,t=1,p=1$bmV3$aGFzaA";
    let reset_now = now + 5;
    store
        .account_reset_password(ResetRequest {
            token_id: token.id,
            encoded_hash: new_hash,
            now: reset_now,
        })
        .await
        .expect("reset applies");

    // Append-only history: the old credential is retired, the new one is current.
    let credentials = password_credential::Entity::find()
        .filter(password_credential::Column::AccountId.eq(account_id))
        .order_by_asc(password_credential::Column::Id)
        .all(store.db())
        .await
        .unwrap();
    assert_eq!(credentials.len(), 2, "history is append-only");
    assert_eq!(
        credentials[0].retired_at,
        Some(reset_now),
        "the old credential is retired"
    );
    assert!(
        credentials[1].retired_at.is_none(),
        "the new credential is current"
    );
    assert_eq!(credentials[1].encoded_hash, new_hash);
    let current = store
        .password_current_for(account_id)
        .await
        .unwrap()
        .expect("a current credential");
    assert_eq!(current.encoded_hash, new_hash);

    // A reset signs the user out everywhere: every session is invalidated.
    let sessions = browser_session::Entity::find()
        .filter(browser_session::Column::AccountId.eq(account_id))
        .all(store.db())
        .await
        .unwrap();
    assert_eq!(sessions.len(), 2);
    assert!(
        sessions.iter().all(|s| s.invalidated_at == Some(reset_now)),
        "every session is invalidated by a reset"
    );

    // The token is consumed in the same transaction.
    let stored = password_reset_token::Entity::find_by_id(token.id)
        .one(store.db())
        .await
        .unwrap()
        .expect("token row survives");
    assert_eq!(stored.consumed_at, Some(reset_now));
}

/// An authenticated password change carries the reset's guarantees —
/// append-only credential history and every session ended — without a token.
#[tokio::test]
async fn test_account_change_password_supersedes_and_revokes() {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
    use weaver_server::store::entity::{browser_session, password_credential};

    let temp = TempDir::new().expect("tempdir");
    let store = Store::open(temp.path().join("change-apply.db"))
        .await
        .expect("open failed");
    let now = 1_000;
    let account_id = activate_account(&store, "change1@example.com", now).await;

    // Two live sessions: the device making the change, and another.
    store
        .session_create(account_id, "change-session-one", now, now + 100_000)
        .await
        .unwrap();
    store
        .session_create(account_id, "change-session-two", now, now + 100_000)
        .await
        .unwrap();

    let new_hash = "$argon2id$v=19$m=8,t=1,p=1$Y2hhbmdl$aGFzaA";
    let changed_now = now + 7;
    store
        .account_change_password(account_id, new_hash, changed_now)
        .await
        .expect("change applies");

    // Append-only history: the old credential is retired, the new one is current.
    let credentials = password_credential::Entity::find()
        .filter(password_credential::Column::AccountId.eq(account_id))
        .order_by_asc(password_credential::Column::Id)
        .all(store.db())
        .await
        .unwrap();
    assert_eq!(credentials.len(), 2, "history is append-only");
    assert_eq!(
        credentials[0].retired_at,
        Some(changed_now),
        "the old credential is retired"
    );
    assert!(
        credentials[1].retired_at.is_none(),
        "the new credential is current"
    );
    assert_eq!(credentials[1].encoded_hash, new_hash);
    let current = store
        .password_current_for(account_id)
        .await
        .unwrap()
        .expect("a current credential");
    assert_eq!(current.encoded_hash, new_hash);

    // A change signs the user out everywhere, the acting session included.
    let sessions = browser_session::Entity::find()
        .filter(browser_session::Column::AccountId.eq(account_id))
        .all(store.db())
        .await
        .unwrap();
    assert_eq!(sessions.len(), 2);
    assert!(
        sessions
            .iter()
            .all(|s| s.invalidated_at == Some(changed_now)),
        "every session is invalidated by a password change"
    );
}

/// With no live credential to rotate, a change is refused rather than silently
/// leaving two current credentials. This is the guard that also settles the race
/// between two concurrent changes.
#[tokio::test]
async fn test_account_change_password_refuses_without_a_live_credential() {
    use sea_orm::sea_query::Expr;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    use weaver_server::store::entity::password_credential;

    let temp = TempDir::new().expect("tempdir");
    let store = Store::open(temp.path().join("change-empty.db"))
        .await
        .expect("open failed");
    let now = 1_000;
    let account_id = activate_account(&store, "change2@example.com", now).await;

    // Retire the credential directly, so the account has none to rotate.
    password_credential::Entity::update_many()
        .col_expr(
            password_credential::Column::RetiredAt,
            Expr::value(Some(now)),
        )
        .filter(password_credential::Column::AccountId.eq(account_id))
        .exec(store.db())
        .await
        .unwrap();

    let error = store
        .account_change_password(
            account_id,
            "$argon2id$v=19$m=8,t=1,p=1$bm9uZQ$aGFzaA",
            now + 1,
        )
        .await
        .expect_err("no live credential to rotate");
    assert!(matches!(error, StoreError::Conflict(_)), "{error:?}");
}

#[tokio::test]
async fn test_reset_token_is_single_use() {
    let temp = TempDir::new().expect("tempdir");
    let store = Store::open(temp.path().join("reset-single.db"))
        .await
        .expect("open failed");
    let now = 1_000;
    let account_id = activate_account(&store, "reset3@example.com", now).await;
    let token = store
        .password_reset_token_issue(
            account_id,
            NewPasswordResetToken {
                token_digest: "digest-single".into(),
                issued_at: now,
                expires_at: now + 3_600,
            },
        )
        .await
        .unwrap();
    let hash = "$argon2id$v=19$m=8,t=1,p=1$YQ$aGFzaA";

    store
        .account_reset_password(ResetRequest {
            token_id: token.id,
            encoded_hash: hash,
            now,
        })
        .await
        .expect("the first reset succeeds");
    let replay = store
        .account_reset_password(ResetRequest {
            token_id: token.id,
            encoded_hash: hash,
            now: now + 1,
        })
        .await;
    assert!(
        matches!(replay, Err(StoreError::Conflict(_))),
        "a spent token is refused: {replay:?}"
    );
}

#[tokio::test]
async fn test_reset_token_sweep_removes_only_expired_unconsumed() {
    let temp = TempDir::new().expect("tempdir");
    let store = Store::open(temp.path().join("reset-sweep.db"))
        .await
        .expect("open failed");
    let now = 1_000;
    let account_id = activate_account(&store, "reset4@example.com", now).await;

    // Expired and unconsumed — the only row the sweep should remove.
    store
        .password_reset_token_issue(
            account_id,
            NewPasswordResetToken {
                token_digest: "expired".into(),
                issued_at: now,
                expires_at: now + 10,
            },
        )
        .await
        .unwrap();
    // Still live (and revoked by the later issue, which the sweep ignores).
    store
        .password_reset_token_issue(
            account_id,
            NewPasswordResetToken {
                token_digest: "live".into(),
                issued_at: now,
                expires_at: now + 10_000,
            },
        )
        .await
        .unwrap();
    // Expired but consumed: kept as provenance.
    let consumed = store
        .password_reset_token_issue(
            account_id,
            NewPasswordResetToken {
                token_digest: "consumed".into(),
                issued_at: now,
                expires_at: now + 10,
            },
        )
        .await
        .unwrap();
    assert!(
        store
            .password_reset_token_consume(consumed.id, now)
            .await
            .unwrap()
    );

    let removed = store.password_reset_token_sweep(now + 1_000).await.unwrap();
    assert_eq!(removed, 1, "only the expired unconsumed row is swept");
    assert!(
        store
            .password_reset_token_by_digest("expired")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .password_reset_token_by_digest("live")
            .await
            .unwrap()
            .is_some(),
        "a live token survives the sweep"
    );
    assert!(
        store
            .password_reset_token_by_digest("consumed")
            .await
            .unwrap()
            .is_some(),
        "a consumed row survives as provenance"
    );
}

// ---------------------------------------------------------------------------
// One person per account, one key per machine, and the key log.
// ---------------------------------------------------------------------------

/// Activates a fresh account named `name` through the real signup path.
async fn activated(
    store: &Store,
    name: &str,
    email: &str,
) -> weaver_server::store::entity::account::Model {
    let now = 1_800_000_000;
    let (pending, proof, completion) = stage_verified_signup(store, name, email, email, now).await;
    match activate(
        store,
        pending,
        proof,
        completion,
        name,
        email,
        email,
        "$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA",
        now,
    )
    .await
    {
        ActivationOutcome::Activated(account) => account,
        other => panic!("expected activation, got {other:?}"),
    }
}

/// Every key log row of a machine, oldest first.
async fn key_log(
    store: &Store,
    machine_id: i32,
) -> Vec<weaver_server::store::entity::machine_key_log::Model> {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
    use weaver_server::store::entity::machine_key_log;
    machine_key_log::Entity::find()
        .filter(machine_key_log::Column::MachineId.eq(machine_id))
        .order_by_asc(machine_key_log::Column::Id)
        .all(store.db())
        .await
        .unwrap()
}

#[tokio::test]
async fn test_pairing_names_follow_the_account() {
    use weaver_mux::KeyId;

    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path().join("pairing.db")).await.unwrap();
    let account = activated(&store, "Rémy Sanchez", "remy@example.com").await;

    // The proposal folds accents, lowercases and strips everything else.
    let slug = store.propose_person_name(&account.name).await.unwrap();
    assert_eq!(slug, "remysanchez");
    let person = store.create_person(account.id, &slug).await.unwrap();
    assert_eq!(person.account_id, account.id);
    assert_eq!(
        store.person_by_account(account.id).await.unwrap(),
        Some(person.clone())
    );

    // A taken slug is numbered for the next account with the same name.
    let namesake = activated(&store, "Rémy Sanchez", "other@example.com").await;
    assert_eq!(
        store.propose_person_name(&namesake.name).await.unwrap(),
        "remysanchez2"
    );

    // Machine names come from the hostname, numbered per person; the number
    // eats into the truncated slug so the name stays within 15 characters.
    let hostname = "Rémys-Laptop.local";
    for (byte, expected) in [
        (1, "remyslaptoploca"),
        (2, "remyslaptoploc2"),
        (3, "remyslaptoploc3"),
    ] {
        let name = store
            .propose_machine_name(person.id, hostname)
            .await
            .unwrap();
        assert_eq!(name, expected);
        store
            .create_machine(person.id, &name, &KeyId::Ed25519([byte; 32]))
            .await
            .unwrap();
    }

    // Past the first probe batch, the next batch is asked about.
    for n in 4..=17u8 {
        let name = if n < 10 {
            format!("remyslaptoploc{n}")
        } else {
            format!("remyslaptoplo{n}")
        };
        store
            .create_machine(person.id, &name, &KeyId::Ed25519([n + 10; 32]))
            .await
            .unwrap();
    }
    assert_eq!(
        store
            .propose_machine_name(person.id, hostname)
            .await
            .unwrap(),
        "remyslaptoplo18"
    );

    // Machine names are per person: another person's machines do not count.
    let other = store.create_test_person("other").await.unwrap();
    assert_eq!(
        store
            .propose_machine_name(other.id, hostname)
            .await
            .unwrap(),
        "remyslaptoploca"
    );
}

#[tokio::test]
async fn test_an_account_has_one_person_and_takes_it_along() {
    use sea_orm::EntityTrait;
    use weaver_mux::KeyId;
    use weaver_server::store::entity::{account, machine, person, service};

    let store = Store::connect("sqlite::memory:").await.unwrap();
    let alice = store.create_test_person("alice").await.unwrap();
    assert!(
        matches!(
            store.create_person(alice.account_id, "alice2").await,
            Err(StoreError::Db(_))
        ),
        "a second person for one account must be refused"
    );
    assert!(
        matches!(
            store.create_person(9_999, "ghost").await,
            Err(StoreError::Db(_))
        ),
        "a person needs an existing account"
    );

    let laptop = store
        .create_machine(alice.id, "laptop", &KeyId::Ed25519([7; 32]))
        .await
        .unwrap();
    store.get_or_create_service(laptop.id, "web").await.unwrap();

    account::Entity::delete_by_id(alice.account_id)
        .exec(store.db())
        .await
        .unwrap();
    assert!(
        person::Entity::find()
            .all(store.db())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        machine::Entity::find()
            .all(store.db())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        service::Entity::find()
            .all(store.db())
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn test_delete_account_removes_every_trace_and_is_idempotent() {
    use weaver_mux::KeyId;

    let store = Store::connect("sqlite::memory:").await.unwrap();
    let email = "delete@example.com";
    let account = activated(&store, "Delete Me", email).await;

    // A person, a machine, a service with a materialized hostname, a live usage
    // bucket and a browser session: everything the delete must take along.
    let slug = store.propose_person_name(&account.name).await.unwrap();
    let person = store.create_person(account.id, &slug).await.unwrap();
    let machine = store
        .create_machine(person.id, "laptop", &KeyId::Ed25519([3; 32]))
        .await
        .unwrap();
    let service = store
        .get_or_create_service(machine.id, "web")
        .await
        .unwrap();
    store
        .set_domain_service(&format!("{slug}-laptop-web.weaver.test"), service.id)
        .await
        .unwrap();
    store
        .ensure_day_slots(&[(service.id, 20_000)])
        .await
        .unwrap();
    let now = 1_800_000_000;
    store
        .session_create(account.id, "deadbeef", now, now + 100)
        .await
        .unwrap();

    // The activation left the address's pending registration and its two tokens
    // behind (only `completed_at` was set); the delete must purge those too.
    assert_eq!(
        scalar::<i64>(&store, "SELECT count(*) FROM pending_registration").await,
        1
    );
    assert_eq!(
        scalar::<i64>(&store, "SELECT count(*) FROM verification_token").await,
        2
    );

    store.delete_account(account.id).await.unwrap();

    for table in [
        "account",
        "person",
        "machine",
        "machine_key_log",
        "service",
        "domains",
        "usage_live",
        "usage_daily",
        "browser_session",
        "password_credential",
        "email_identity",
        "email_verification",
        "password_reset_token",
        "pending_registration",
        "verification_token",
    ] {
        assert_eq!(
            scalar::<i64>(&store, &format!("SELECT count(*) FROM {table}")).await,
            0,
            "table {table} still holds a row after account deletion"
        );
    }

    // No reference survives anywhere: the whole database passes an FK audit.
    let broken = store
        .db()
        .query_all_raw(Statement::from_string(
            DbBackend::Sqlite,
            "PRAGMA foreign_key_check",
        ))
        .await
        .unwrap();
    assert!(broken.is_empty(), "foreign_key_check found {broken:?}");

    // The freed person name is reusable, and a repeat delete is the goal state.
    assert_eq!(
        store.propose_person_name(&account.name).await.unwrap(),
        slug
    );
    store.delete_account(account.id).await.unwrap();
}

#[tokio::test]
async fn test_delete_account_without_email_purges_pending_rows_by_name() {
    let store = Store::connect("sqlite::memory:").await.unwrap();
    // `create_test_person` makes an account with no email identity, the SSO
    // shape the display-name fallback exists for.
    let alice = store.create_test_person("alice").await.unwrap();

    let keep = store
        .pending_registration_create(NewPendingRegistration {
            flow_id: "keep".into(),
            name: "Bob".into(),
            email: "bob@example.com".into(),
            lookup_key: "bob@example.com".into(),
            created_at: 1,
            expires_at: 100,
        })
        .await
        .unwrap();
    let mine = store
        .pending_registration_create(NewPendingRegistration {
            // A different casing of the same display name; the match folds.
            name: "Alice".into(),
            flow_id: "mine".into(),
            email: "alice@example.com".into(),
            lookup_key: "alice@example.com".into(),
            created_at: 1,
            expires_at: 100,
        })
        .await
        .unwrap();
    store
        .verification_token_issue(
            mine.id,
            NewVerificationToken {
                email_lookup_key: "alice@example.com".into(),
                token_digest: "token-digest".into(),
                purpose: "email-verification".into(),
                issued_at: 1,
                expires_at: 100,
            },
        )
        .await
        .unwrap();

    store.delete_account(alice.account_id).await.unwrap();

    // Alice's pending row (and its token) are gone; Bob's is untouched.
    let remaining: String = scalar(&store, "SELECT flow_id FROM pending_registration").await;
    assert_eq!(remaining, keep.flow_id);
    assert_eq!(
        scalar::<i64>(&store, "SELECT count(*) FROM verification_token").await,
        0
    );
}

#[tokio::test]
async fn test_a_key_identifies_exactly_one_machine() {
    use weaver_mux::KeyId;

    let store = Store::connect("sqlite::memory:").await.unwrap();
    let alice = store.create_test_person("alice").await.unwrap();
    let bob = store.create_test_person("bob").await.unwrap();
    let key = KeyId::P256([2; 33]);

    let laptop = store
        .create_machine(alice.id, "laptop", &key)
        .await
        .unwrap();
    let (person, machine) = store.machine_by_key(&key).await.unwrap().unwrap();
    assert_eq!((person.id, machine.id), (alice.id, laptop.id));

    // The same key cannot become a second machine, not even another person's.
    assert!(matches!(
        store.create_machine(bob.id, "desktop", &key).await,
        Err(StoreError::Db(_))
    ));
    assert!(matches!(
        store.create_machine(alice.id, "desktop", &key).await,
        Err(StoreError::Db(_))
    ));
    // Nor can another machine be moved onto it.
    let other = store
        .create_machine(bob.id, "desktop", &KeyId::P256([3; 33]))
        .await
        .unwrap();
    assert!(matches!(
        store.replace_machine_key(other.id, &key).await,
        Err(StoreError::Db(_))
    ));
    assert_eq!(
        store.machine_by_id(other.id).await.unwrap().unwrap().key_id,
        other.key_id,
        "a refused replacement changes nothing"
    );
    // Creating the machine opened exactly one log row.
    let log = key_log(&store, laptop.id).await;
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].key_id, laptop.key_id);
    assert_eq!(log[0].person_id, alice.id);
    assert_eq!(log[0].retired_at, None);
}

#[tokio::test]
async fn test_replacing_a_key_moves_the_machine_and_logs_it() {
    use weaver_mux::KeyId;

    let store = Store::connect("sqlite::memory:").await.unwrap();
    let alice = store.create_test_person("alice").await.unwrap();
    let old = KeyId::P256([2; 33]);
    let new = KeyId::P256([3; 33]);
    let laptop = store
        .create_machine(alice.id, "laptop", &old)
        .await
        .unwrap();
    store
        .register_declared_service(laptop.id, "alice-laptop-web.example.com", "web")
        .await
        .unwrap();

    let moved = store.replace_machine_key(laptop.id, &new).await.unwrap();
    assert_eq!((moved.id, moved.name.as_str()), (laptop.id, "laptop"));
    assert!(store.machine_by_key(&old).await.unwrap().is_none());
    assert_eq!(
        store.machine_by_key(&new).await.unwrap().unwrap().1.id,
        laptop.id
    );
    // Services and hostnames stay with the machine.
    let domain = store
        .get_domain("alice-laptop-web.example.com")
        .await
        .unwrap()
        .unwrap();
    assert!(domain.service_id.is_some());

    let log = key_log(&store, laptop.id).await;
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].key_id, laptop.key_id);
    assert!(log[0].retired_at.is_some());
    assert_eq!(log[0].retired_reason, "replaced");
    assert_eq!(log[1].key_id, moved.key_id);
    assert_eq!(log[1].retired_at, None);

    assert!(matches!(
        store
            .replace_machine_key(9_999, &KeyId::P256([4; 33]))
            .await,
        Err(StoreError::Conflict(_))
    ));
}

#[tokio::test]
async fn test_revoking_deletes_the_machine_but_keeps_its_log() {
    use sea_orm::EntityTrait;
    use weaver_mux::KeyId;
    use weaver_server::store::entity::service;

    let store = Store::connect("sqlite::memory:").await.unwrap();
    let alice = store.create_test_person("alice").await.unwrap();
    let key = KeyId::P256([5; 33]);
    let laptop = store
        .create_machine(alice.id, "laptop", &key)
        .await
        .unwrap();
    store
        .register_declared_service(laptop.id, "alice-laptop-web.example.com", "web")
        .await
        .unwrap();

    let revoked = store.revoke_machine(&key).await.unwrap().unwrap();
    assert_eq!(revoked.id, laptop.id);
    assert!(store.machine_by_key(&key).await.unwrap().is_none());
    assert!(store.machine_by_id(laptop.id).await.unwrap().is_none());
    assert!(
        service::Entity::find()
            .all(store.db())
            .await
            .unwrap()
            .is_empty()
    );
    // The name is free again.
    assert_eq!(
        store
            .propose_machine_name(alice.id, "laptop")
            .await
            .unwrap(),
        "laptop"
    );

    let log = key_log(&store, laptop.id).await;
    assert_eq!(log.len(), 1, "the log outlives the machine");
    assert_eq!(log[0].retired_reason, "revoked");
    assert!(log[0].retired_at.is_some());

    // Revoking again is the goal state, not an error.
    assert!(store.revoke_machine(&key).await.unwrap().is_none());
}

#[tokio::test]
async fn test_renaming_a_machine_rederives_its_hostnames() {
    use weaver_mux::KeyId;

    let store = Store::connect("sqlite::memory:").await.unwrap();
    let alice = store.create_test_person("alice").await.unwrap();
    let bob = store.create_test_person("bob").await.unwrap();
    let laptop = store
        .create_machine(alice.id, "laptop", &KeyId::P256([2; 33]))
        .await
        .unwrap();
    store
        .register_declared_service(laptop.id, "alice-laptop-web.example.com", "web")
        .await
        .unwrap();
    store
        .register_declared_service(laptop.id, "alice-laptop-db.example.com", "db")
        .await
        .unwrap();
    let desktop = store
        .create_machine(alice.id, "desktop", &KeyId::P256([3; 33]))
        .await
        .unwrap();
    // Another person's hostname must never be touched by alice's rename.
    let bobs = store
        .create_machine(bob.id, "laptop", &KeyId::P256([4; 33]))
        .await
        .unwrap();
    store
        .register_declared_service(bobs.id, "bob-laptop-web.example.com", "web")
        .await
        .unwrap();

    let renamed = store.rename_machine(laptop.id, "Rig").await.unwrap();
    assert_eq!(renamed.name, "rig", "names are lowercased");

    // Every service moved to the new prefix, old rows are gone.
    let hosts: Vec<String> = store
        .services_with_hostnames(&[laptop.id])
        .await
        .unwrap()
        .into_iter()
        .flat_map(|(_, hosts)| hosts)
        .collect();
    assert_eq!(
        hosts,
        vec!["alice-rig-db.example.com", "alice-rig-web.example.com"]
    );
    assert!(
        store
            .get_domain("alice-laptop-web.example.com")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get_domain("alice-laptop-db.example.com")
            .await
            .unwrap()
            .is_none()
    );
    // Bob's identical-looking name is untouched.
    assert!(
        store
            .get_domain("bob-laptop-web.example.com")
            .await
            .unwrap()
            .is_some()
    );

    // The per-person unique index still holds.
    assert!(matches!(
        store.rename_machine(laptop.id, "desktop").await,
        Err(StoreError::Db(_))
    ));
    // A rename to the current name is a harmless no-op.
    assert_eq!(
        store.rename_machine(laptop.id, "rig").await.unwrap().name,
        "rig"
    );
    // Names are validated before anything is written.
    assert!(matches!(
        store.rename_machine(laptop.id, "Not A Name").await,
        Err(StoreError::InvalidName(_))
    ));
    assert!(matches!(
        store
            .rename_machine(laptop.id, "this-name-is-far-too-long")
            .await,
        Err(StoreError::InvalidName(_))
    ));
    // An unknown machine is a conflict, not a silent success.
    assert!(matches!(
        store.rename_machine(desktop.id + 9_999, "rig").await,
        Err(StoreError::Conflict(_))
    ));
}

#[tokio::test]
async fn test_renaming_adopts_a_leftover_unowned_hostname() {
    use weaver_mux::KeyId;

    let store = Store::connect("sqlite::memory:").await.unwrap();
    let alice = store.create_test_person("alice").await.unwrap();
    // A machine that once served `alice-old-web`, then was revoked: its
    // hostname row survives with its `service_id` cleared.
    let old = store
        .create_machine(alice.id, "old", &KeyId::P256([2; 33]))
        .await
        .unwrap();
    store
        .register_declared_service(old.id, "alice-old-web.example.com", "web")
        .await
        .unwrap();
    store
        .revoke_machine(&old.key_id.parse().unwrap())
        .await
        .unwrap();
    assert!(
        store
            .get_domain("alice-old-web.example.com")
            .await
            .unwrap()
            .unwrap()
            .service_id
            .is_none()
    );

    // A new machine serves `alice-fresh-web`; renaming it to `old` derives a
    // hostname that already exists, so the leftover row must be adopted rather
    // than colliding with the unique index.
    let fresh = store
        .create_machine(alice.id, "fresh", &KeyId::P256([3; 33]))
        .await
        .unwrap();
    store
        .register_declared_service(fresh.id, "alice-fresh-web.example.com", "web")
        .await
        .unwrap();
    let web = store.get_or_create_service(fresh.id, "web").await.unwrap();

    store.rename_machine(fresh.id, "old").await.unwrap();
    assert_eq!(
        store
            .get_domain("alice-old-web.example.com")
            .await
            .unwrap()
            .unwrap()
            .service_id,
        Some(web.id)
    );
    assert!(
        store
            .get_domain("alice-fresh-web.example.com")
            .await
            .unwrap()
            .is_none(),
        "the machine's own old hostname is gone"
    );
}

#[tokio::test]
async fn test_machine_last_seen_comes_from_the_day_rollup() {
    use sea_orm::ConnectionTrait;
    use weaver_mux::KeyId;
    use weaver_server::metrics::{MetricsStore, encode_blob};

    let store = Store::connect("sqlite::memory:").await.unwrap();
    let alice = store.create_test_person("alice").await.unwrap();
    let laptop = store
        .create_machine(alice.id, "laptop", &KeyId::P256([2; 33]))
        .await
        .unwrap();
    let web = store
        .register_declared_service(laptop.id, "alice-laptop-web.example.com", "web")
        .await
        .unwrap();
    let desktop = store
        .create_machine(alice.id, "desktop", &KeyId::P256([3; 33]))
        .await
        .unwrap();
    let desk_web = store
        .register_declared_service(desktop.id, "alice-desktop-web.example.com", "web")
        .await
        .unwrap();
    let metrics = MetricsStore::new(store.clone());

    // Nothing metered yet: never seen.
    assert!(
        metrics
            .last_open_minutes(&[web.id, desk_web.id])
            .await
            .unwrap()
            .is_empty()
    );

    // A folded day carries open time in its per-minute blob; the last non-zero
    // index is the last minute the service was up.
    let mut open = vec![0_i64; 1440];
    open[6] = 60_000;
    let open_blob = encode_blob(&open);
    let zero_blob = encode_blob(&[0_i64; 1440]);
    let z = hex(&zero_blob);
    let blob = hex(&open_blob);
    store
        .db()
        .execute_unprepared(&format!(
            "INSERT INTO usage_daily (service_id, day, bytes_in, bytes_in_hours, bytes_in_minutes, \
                bytes_out, bytes_out_hours, bytes_out_minutes, tunnel_in, tunnel_in_hours, tunnel_in_minutes, \
                tunnel_out, tunnel_out_hours, tunnel_out_minutes, requests, requests_hours, requests_minutes, \
                open_ms, open_ms_hours, open_ms_minutes) VALUES \
             ({}, 100, 0, X'{z}', X'{z}', 0, X'{z}', X'{z}', 0, X'{z}', X'{z}', 0, X'{z}', X'{z}', \
              0, X'{z}', X'{z}', 60000, X'{z}', X'{blob}')",
            web.id
        ))
        .await
        .unwrap();

    let seen = metrics
        .last_open_minutes(&[web.id, desk_web.id])
        .await
        .unwrap();
    assert_eq!(
        seen.get(&web.id),
        Some(&(100 * 1440 + 6)),
        "the folded day's last open minute"
    );
    // A machine with no open time has no presence, even with services.
    assert!(!seen.contains_key(&desk_web.id));

    // A later live day is read from its slot array and wins.
    use weaver_server::store::usage_live::{SlotWrite, Slots};
    let today_minute = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        / 60;
    let day = today_minute.div_euclid(1440);
    store
        .write_day_slots(&[SlotWrite {
            service_id: web.id,
            day,
            slots: Slots::OpenMs,
            first_slot: (today_minute - day * 1440) as u16,
            values: vec![60_000],
        }])
        .await
        .unwrap();
    let seen = metrics.last_open_minutes(&[web.id]).await.unwrap();
    assert_eq!(seen.get(&web.id), Some(&today_minute));
}

/// Upgrading a relay leaves recorded slots and no rollup; the metering tick's
/// fold compresses each finished day into one wide row per service and deletes
/// the live rows it folded.
#[tokio::test]
async fn test_fold_finished_days_compresses_recorded_minutes() {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    use weaver_mux::KeyId;
    use weaver_server::metrics::{MetricsStore, decode_blob};
    use weaver_server::store::entity::usage_daily;
    use weaver_server::store::usage_live::{SlotWrite, Slots};

    let store = Store::connect("sqlite::memory:").await.unwrap();
    let alice = store.create_test_person("alice").await.unwrap();
    let laptop = store
        .create_machine(alice.id, "laptop", &KeyId::P256([2; 33]))
        .await
        .unwrap();
    let web = store
        .register_declared_service(laptop.id, "alice-laptop-web.example.com", "web")
        .await
        .unwrap();

    // Day 0: minute 100 wholly open, minute 101 never open. Day 1: minute 1441
    // half open. Slot arrays store open time directly.
    let slot = |day: i64, first_slot: u16, slots: Slots, values: Vec<i64>| SlotWrite {
        service_id: web.id,
        day,
        slots,
        first_slot,
        values,
    };
    store
        .write_day_slots(&[
            slot(0, 100, Slots::BytesIn, vec![10, 30]),
            slot(0, 100, Slots::BytesOut, vec![20, 40]),
            slot(0, 100, Slots::TunnelIn, vec![1, 3]),
            slot(0, 100, Slots::TunnelOut, vec![2, 4]),
            slot(0, 100, Slots::Requests, vec![1, 2]),
            slot(0, 100, Slots::OpenMs, vec![60_000, 0]),
            slot(1, 1, Slots::BytesIn, vec![5]),
            slot(1, 1, Slots::BytesOut, vec![6]),
            slot(1, 1, Slots::Requests, vec![1]),
            slot(1, 1, Slots::OpenMs, vec![30_000]),
        ])
        .await
        .unwrap();

    let metrics = MetricsStore::new(store.clone());
    assert_eq!(
        metrics.fold_finished_days().await.unwrap(),
        2,
        "one row folded for each finished day"
    );
    assert_eq!(
        scalar::<i64>(&store, "SELECT COUNT(*) FROM usage_live").await,
        0,
        "the folded days' live rows are deleted"
    );

    assert_eq!(
        scalar::<i64>(&store, "SELECT bytes_in FROM usage_daily WHERE day = 0").await,
        40
    );
    assert_eq!(
        scalar::<i64>(&store, "SELECT open_ms FROM usage_daily WHERE day = 0").await,
        60_000,
        "minute 100 fully open plus a never-open minute 101"
    );
    assert_eq!(
        scalar::<i64>(&store, "SELECT requests FROM usage_daily WHERE day = 0").await,
        3
    );

    // The blobs are the day's 1440 little-endian i64 values, zstd-compressed;
    // decoding them recovers the per-minute detail the fold started from.
    let row = usage_daily::Entity::find()
        .filter(usage_daily::Column::ServiceId.eq(web.id))
        .filter(usage_daily::Column::Day.eq(0))
        .one(store.db())
        .await
        .unwrap()
        .expect("one wide row for the service-day");
    let bytes_in = decode_blob(&row.bytes_in_minutes).unwrap();
    assert_eq!(bytes_in.len(), 1440);
    assert_eq!(bytes_in[100], 10);
    assert_eq!(bytes_in[101], 30);
    let hours = decode_blob(&row.bytes_in_hours).unwrap();
    assert_eq!(hours.len(), 24);
    assert_eq!(hours[1], 40, "both minutes are in hour 1");
    let open = decode_blob(&row.open_ms_minutes).unwrap();
    assert_eq!(open[100], 60_000);
    assert_eq!(open[101], 0, "a never-open minute stays zero");

    // Day 1 is a separate row with its own half-open minute.
    assert_eq!(
        scalar::<i64>(&store, "SELECT open_ms FROM usage_daily WHERE day = 1").await,
        30_000
    );
}

/// The rollup is the one table with a retention: `sweep` drops whole rows older
/// than the retention and leaves the rest.
#[tokio::test]
async fn test_sweep_removes_rollup_rows_past_retention() {
    use sea_orm::ConnectionTrait;
    use weaver_mux::KeyId;
    use weaver_server::metrics::MetricsStore;

    let store = Store::connect("sqlite::memory:").await.unwrap();
    let alice = store.create_test_person("alice").await.unwrap();
    let laptop = store
        .create_machine(alice.id, "laptop", &KeyId::P256([2; 33]))
        .await
        .unwrap();
    let web = store
        .register_declared_service(laptop.id, "alice-laptop-web.example.com", "web")
        .await
        .unwrap();

    let now_day = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        / 86_400;
    // An empty blob is a valid non-NULL value, and the sweep never decodes it.
    for day in [now_day - 400, now_day - 2, now_day] {
        store
            .db()
            .execute_unprepared(&format!(
                "INSERT INTO usage_daily (service_id, day, bytes_in, bytes_in_hours, bytes_in_minutes, \
                    bytes_out, bytes_out_hours, bytes_out_minutes, tunnel_in, tunnel_in_hours, tunnel_in_minutes, \
                    tunnel_out, tunnel_out_hours, tunnel_out_minutes, requests, requests_hours, requests_minutes, \
                    open_ms, open_ms_hours, open_ms_minutes) VALUES \
                 ({}, {day}, 0, X'', X'', 0, X'', X'', 0, X'', X'', 0, X'', X'', 0, X'', X'', 0, X'', X'')",
                web.id
            ))
            .await
            .unwrap();
    }

    let metrics = MetricsStore::new(store);
    // A year drops the 400-day-old row but keeps the last two days.
    assert_eq!(metrics.sweep(365 * 86_400).await.unwrap(), 1);
    assert_eq!(
        scalar::<i64>(metrics.store(), "SELECT COUNT(*) FROM usage_daily").await,
        2
    );
    // A zero retention keeps only the current day.
    assert_eq!(metrics.sweep(0).await.unwrap(), 1);
    assert_eq!(
        scalar::<i64>(metrics.store(), "SELECT day FROM usage_daily").await,
        now_day
    );
}

#[tokio::test]
async fn test_key_log_sweep_drops_only_retired_rows_past_the_cutoff() {
    use sea_orm::sea_query::Expr;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    use weaver_mux::KeyId;
    use weaver_server::store::entity::machine_key_log;

    let store = Store::connect("sqlite::memory:").await.unwrap();
    let alice = store.create_test_person("alice").await.unwrap();
    let laptop = store
        .create_machine(alice.id, "laptop", &KeyId::P256([2; 33]))
        .await
        .unwrap();
    store
        .replace_machine_key(laptop.id, &KeyId::P256([3; 33]))
        .await
        .unwrap();
    store
        .replace_machine_key(laptop.id, &KeyId::P256([4; 33]))
        .await
        .unwrap();
    // Backdate everything: the two retired rows to t=100 and t=300, and the
    // current key's row to t=0, so age alone would sweep it.
    let log = key_log(&store, laptop.id).await;
    for (row, retired) in log.iter().zip([Some(100_i64), Some(300), None]) {
        machine_key_log::Entity::update_many()
            .col_expr(machine_key_log::Column::AddedAt, Expr::value(0_i64))
            .col_expr(machine_key_log::Column::RetiredAt, Expr::value(retired))
            .filter(machine_key_log::Column::Id.eq(row.id))
            .exec(store.db())
            .await
            .unwrap();
    }

    assert_eq!(store.sweep_machine_key_log(100).await.unwrap(), 0);
    assert_eq!(store.sweep_machine_key_log(200).await.unwrap(), 1);
    assert_eq!(store.sweep_machine_key_log(i64::MAX).await.unwrap(), 1);
    let left = key_log(&store, laptop.id).await;
    assert_eq!(left.len(), 1, "the current key's row is never swept");
    assert_eq!(left[0].retired_at, None);
    assert_eq!(left[0].key_id, log[2].key_id);

    // The sweep the relay runs uses the configured retention.
    let account = weaver_server::config::AccountConfig::default();
    assert_eq!(account.key_log_cutoff(365 * 86_400 + 5), 5);
}

// ---------------------------------------------------------------------------
// Inactivity sweep inputs (WVR-160).
// ---------------------------------------------------------------------------

const MONTH: i64 = 30 * 86_400;
const YEAR: i64 = 365 * 86_400;

#[tokio::test]
async fn test_inactivity_candidates_use_sign_in_or_activation_and_page_by_id() {
    let store = Store::connect("sqlite::memory:").await.unwrap();
    let t0 = 1_800_000_000;
    let never = activated(&store, "Never Signed In", "never@example.com").await;
    let stale = activated(&store, "Stale", "stale@example.com").await;
    let fresh = activated(&store, "Fresh", "fresh@example.com").await;
    // `stale` signed in five days after activation; `fresh` signed in recently.
    store
        .account_record_login(stale.id, t0 + 5 * 86_400)
        .await
        .unwrap();
    store
        .account_record_login(fresh.id, t0 + YEAR - 86_400)
        .await
        .unwrap();

    let now = t0 + YEAR;
    let candidates = store
        .inactivity_candidates(now, 11 * MONTH, 0, 10)
        .await
        .unwrap();
    let ids: Vec<i32> = candidates.iter().map(|c| c.account_id).collect();
    // `fresh` is inside the warning window and is not even a candidate.
    assert!(
        !ids.contains(&fresh.id),
        "a recently active account is not a candidate"
    );
    // In id order, so the sweep can page through them with a cursor.
    assert_eq!(ids, vec![never.id, stale.id]);
    // An account that never signed in falls back to its activation instant.
    assert_eq!(candidates[0].last_activity, t0);
    assert_eq!(candidates[0].name, "Never Signed In");
    assert_eq!(candidates[0].email, "never@example.com");
    assert!(!candidates[0].has_live_session);
    assert_eq!(candidates[1].last_activity, t0 + 5 * 86_400);

    // A page is bounded, and the cursor resumes after the last id seen.
    let first = store
        .inactivity_candidates(now, 11 * MONTH, 0, 1)
        .await
        .unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].account_id, never.id);
    let second = store
        .inactivity_candidates(now, 11 * MONTH, never.id, 1)
        .await
        .unwrap();
    assert_eq!(second[0].account_id, stale.id);
    assert!(
        store
            .inactivity_candidates(now, 11 * MONTH, stale.id, 1)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn test_inactivity_next_event_is_the_earliest_warning_or_deletion() {
    let store = Store::connect("sqlite::memory:").await.unwrap();
    let (warn_after, delete_after) = (11 * MONTH, YEAR);
    assert_eq!(
        store
            .inactivity_next_event(0, warn_after, delete_after)
            .await
            .unwrap(),
        None,
        "no account, no event"
    );

    let t0 = 1_800_000_000;
    let early = activated(&store, "Early", "early@example.com").await;
    let late = activated(&store, "Late", "late@example.com").await;
    store.account_record_login(early.id, t0).await.unwrap();
    store
        .account_record_login(late.id, t0 + 86_400)
        .await
        .unwrap();

    // The next thing to happen is the early account's warning.
    let next = |after| store.inactivity_next_event(after, warn_after, delete_after);
    assert_eq!(next(t0).await.unwrap(), Some(t0 + warn_after));
    // Once that tick ran, the late account's warning is next.
    assert_eq!(
        next(t0 + warn_after).await.unwrap(),
        Some(t0 + 86_400 + warn_after)
    );

    // A warning sent for this stretch of idleness drops out: the early
    // account's deletion is what remains for it.
    store
        .account_mark_inactivity_warning(early.id, t0 + warn_after)
        .await
        .unwrap();
    store
        .account_mark_inactivity_warning(late.id, t0 + 86_400 + warn_after)
        .await
        .unwrap();
    assert_eq!(next(t0).await.unwrap(), Some(t0 + delete_after));

    // Signing in again starts a new stretch: the old warning no longer counts.
    let back = t0 + YEAR - 10;
    store.account_record_login(early.id, back).await.unwrap();
    assert_eq!(
        next(t0 + delete_after).await.unwrap(),
        Some(t0 + 86_400 + delete_after),
        "the late account's deletion comes before the early one's new warning"
    );
    assert_eq!(
        next(t0 + 86_400 + delete_after).await.unwrap(),
        Some(back + warn_after)
    );
}

#[tokio::test]
async fn test_inactivity_candidates_flag_only_live_sessions() {
    let store = Store::connect("sqlite::memory:").await.unwrap();
    let t0 = 1_800_000_000;
    let now = t0 + YEAR;
    let live = activated(&store, "Live", "live@example.com").await;
    let pending = activated(&store, "Pending", "pending@example.com").await;
    let expired = activated(&store, "Expired", "expired@example.com").await;
    let invalidated = activated(&store, "Invalidated", "invalidated@example.com").await;

    // A live, unexpired session that has passed the second factor...
    let proven = store
        .session_create(live.id, "live-hash", now - 60, now + 3600)
        .await
        .unwrap();
    email_otp_proof(&store, live.id, proven.id, now - 30).await;
    // ...versus a live one that only proved the password: a half-signed-in
    // session is not activity (WVR-167)...
    store
        .session_create(pending.id, "pending-hash", now - 60, now + 3600)
        .await
        .unwrap();
    // ...versus one that is already expired...
    store
        .session_create(expired.id, "expired-hash", now - 7200, now - 3600)
        .await
        .unwrap();
    // ...versus one that was explicitly retired, even though it had proven the
    // second factor.
    let retired = store
        .session_create(invalidated.id, "invalidated-hash", now - 60, now + 3600)
        .await
        .unwrap();
    email_otp_proof(&store, invalidated.id, retired.id, now - 30).await;
    store
        .session_invalidate("invalidated-hash", now)
        .await
        .unwrap();

    let candidates = store
        .inactivity_candidates(now, 11 * MONTH, 0, 10)
        .await
        .unwrap();
    let row = |id: i32| candidates.iter().find(|c| c.account_id == id).unwrap();
    assert!(
        row(live.id).has_live_session,
        "an unexpired session marks the account live"
    );
    assert!(
        !row(pending.id).has_live_session,
        "a session that only proved the password is not activity (WVR-167)"
    );
    assert!(
        !row(expired.id).has_live_session,
        "an expired session does not"
    );
    assert!(
        !row(invalidated.id).has_live_session,
        "an invalidated session does not"
    );
}

/// Records the emailed-code proof against `session_id`, the way a completed
/// sign-in does (WVR-167).
async fn email_otp_proof(store: &Store, account_id: i32, session_id: i32, at: i64) {
    store
        .auth_event_insert(NewAuthEvent {
            account_id: Some(account_id),
            session_id: Some(session_id),
            kind: "email_otp".to_string(),
            occurred_at: at,
            ip_address: String::new(),
            user_agent: String::new(),
            attempted: String::new(),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn test_inactivity_candidates_fold_the_newest_metered_day_into_activity() {
    use weaver_mux::KeyId;
    use weaver_server::store::usage_live::{SlotWrite, Slots};

    let store = Store::connect("sqlite::memory:").await.unwrap();
    let t0 = 1_800_000_000;
    let account = activated(&store, "Metered", "metered@example.com").await;
    let person = store.create_person(account.id, "metered").await.unwrap();
    let laptop = store
        .create_machine(person.id, "laptop", &KeyId::P256([9; 33]))
        .await
        .unwrap();
    let web = store
        .register_declared_service(laptop.id, "metered-laptop-web.example.com", "web")
        .await
        .unwrap();

    // The account last signed in a year ago, but its service was metered
    // yesterday, which is activity in its own right.
    store.account_record_login(account.id, t0).await.unwrap();
    let now = t0 + YEAR;
    let yesterday = (now - 86_400).div_euclid(86_400);
    store
        .write_day_slots(&[SlotWrite {
            service_id: web.id,
            day: yesterday,
            slots: Slots::OpenMs,
            first_slot: 0,
            values: vec![60_000],
        }])
        .await
        .unwrap();

    let candidate = store
        .inactivity_candidates(now, 11 * MONTH, 0, 10)
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.account_id == account.id)
        .expect("a year-old sign-in still shortlists the account");
    // The metered day, not the stale sign-in, is now the activity clock.
    assert_eq!(candidate.last_activity, yesterday * 86_400);
    assert!(now - candidate.last_activity < 11 * MONTH);

    // That same metered day is ancient two years on, so the account is due.
    let later = t0 + 2 * YEAR;
    let candidate = store
        .inactivity_candidates(later, 11 * MONTH, 0, 10)
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.account_id == account.id)
        .unwrap();
    assert!(later - candidate.last_activity >= 11 * MONTH);
}

#[tokio::test]
async fn test_account_login_and_warning_timestamps_round_trip() {
    let store = Store::connect("sqlite::memory:").await.unwrap();
    let account = activated(&store, "Clock", "clock@example.com").await;
    assert_eq!(account.last_login_at, None);
    assert_eq!(account.inactivity_warning_at, None);

    store
        .account_record_login(account.id, 1_800_000_500)
        .await
        .unwrap();
    store
        .account_mark_inactivity_warning(account.id, 1_800_000_600)
        .await
        .unwrap();
    let updated = store.account_by_id(account.id).await.unwrap().unwrap();
    assert_eq!(updated.last_login_at, Some(1_800_000_500));
    assert_eq!(updated.inactivity_warning_at, Some(1_800_000_600));

    // A later sign-in moves the clock without erasing the warning record.
    store
        .account_record_login(account.id, 1_800_001_000)
        .await
        .unwrap();
    let updated = store.account_by_id(account.id).await.unwrap().unwrap();
    assert_eq!(updated.last_login_at, Some(1_800_001_000));
    assert_eq!(updated.inactivity_warning_at, Some(1_800_000_600));
}
