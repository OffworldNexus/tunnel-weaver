use std::net::SocketAddr;
use std::path::PathBuf;

use sea_orm::{ConnectionTrait, DbBackend, Statement};
use tempfile::TempDir;
use weaver_server::store::account::{
    ActivationOutcome, ActivationRequest, NewPasswordResetToken, NewPendingRegistration,
    NewVerificationToken, ResetRequest,
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
        relay_ips: Vec::new(),
        setup_complete: false,
        email: None,
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
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('config', 'acme_account', 'domains', 'certificates', 'cert_events', 'seaql_migrations', 'person', 'machine', 'machine_key', 'service', 'usage', 'challenge', 'abuse_bucket')",
        )
        .await;
        assert_eq!(count, 13);
        assert_eq!(store.schema_version().await.expect("schema_version"), 5);
    }

    // Re-open existing database: should succeed and not re-apply migrations
    {
        let store = Store::open(&db_path).await.expect("re-open failed");
        let migration_count: i64 = scalar(&store, "SELECT count(*) FROM seaql_migrations").await;
        assert_eq!(migration_count, 5);
        assert_eq!(store.schema_version().await.expect("schema_version"), 5);
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

    // OFF-198 foot-gun: an admin domain nested under the delegated tunnel zone
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
    use weaver_server::tunnel::{IdentityResolver, StoreIdentityResolver};

    let temp = TempDir::new().expect("tempdir");
    let db_path = temp.path().join("auth.db");
    let store = Store::open(&db_path).await.expect("open failed");

    // Identities are never created implicitly: enrol a person, a machine, and
    // a key explicitly, then resolve that custom key.
    let alice = store.create_person("Alice").await.expect("create person");
    assert_eq!(alice.name, "alice");

    let desktop = store
        .create_machine(alice.id, "Workstation")
        .await
        .expect("create machine");
    assert_eq!(desktop.name, "workstation");
    assert_eq!(desktop.person_id, alice.id);

    let alice_key = KeyId::Ed25519([0x42; 32]);
    let mkey = store
        .add_machine_key(desktop.id, &alice_key)
        .await
        .expect("add key");
    assert_eq!(mkey.machine_id, desktop.id);

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
        .register_declared_service(&alice_key, "alice-workstation-api.example.com", "API")
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

    // An unenrolled key cannot declare a service.
    assert!(
        store
            .register_declared_service(&unknown_key, "x.example.com", "x")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_certificate_and_event_round_trip() {
    let store = Store::connect("sqlite::memory:").await.expect("connect");
    let cert = weaver_server::store::NewCertificate {
        cert_pem: "CERT".into(),
        key_pem: "KEY".into(),
        not_before: 100,
        not_after: 200,
        issuer: None,
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

    let rec_by_id_str = store
        .get_certificate_by_id_or_name(&best_cert.id.to_string())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rec_by_id_str.id, best_cert.id);

    // The full record carries PEM material for cache hydration.
    let full = store.list_certificates_full().await.unwrap();
    assert_eq!(full.len(), 1);
    assert_eq!(full[0].cert_pem, "CERT");
    assert_eq!(full[0].key_pem, "KEY");
    assert_eq!(full[0].validation, "dns-01");

    // Events, newest first
    store
        .record_cert_event("host.example.com", 10, "issued", None)
        .await
        .expect("event 1");
    store
        .record_cert_event("host.example.com", 20, "failed", Some("boom"))
        .await
        .expect("event 2");
    let events = store
        .get_cert_events("host.example.com", 10)
        .await
        .expect("events");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].kind, "failed");
    assert_eq!(events[0].detail.as_deref(), Some("boom"));
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
        .publish_challenge("_acme-challenge.example.com", "digest-a", None, 1)
        .await
        .unwrap();
    store
        .publish_http01("token-1", "key-auth-1", None, 1)
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
                    issuer: None,
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
        .upsert_acme_account("d", "a@b.c", "{}", Some("kid1"), 1)
        .await
        .expect("upsert");
    store
        .upsert_acme_account("d", "a@b.c", "{\"k\":1}", Some("kid2"), 2)
        .await
        .expect("upsert 2");
    let acct = store.get_acme_account("d").await.unwrap().unwrap();
    assert_eq!(acct.kid.as_deref(), Some("kid2"));
    assert_eq!(acct.credentials_json, "{\"k\":1}");
    assert_eq!(acct.created_at, 2);
}

#[tokio::test]
async fn test_multiple_certificates_distinct_names() {
    let store = Store::connect("sqlite::memory:").await.expect("connect");

    let cert = |pem: &str, issuer: &str, not_after: i64| weaver_server::store::NewCertificate {
        cert_pem: pem.into(),
        key_pem: format!("KEY-{pem}"),
        not_before: 1_000,
        not_after,
        issuer: Some(issuer.into()),
        directory: "dir".into(),
        obtained_at: 1_000,
        validation: "dns-01".to_string(),
    };

    store
        .save_certificate("a.example.com", cert("PEM1", "Issuer 1", 2_000))
        .await
        .unwrap();
    store
        .save_certificate("b.example.com", cert("PEM2", "Issuer 2", 3_000))
        .await
        .unwrap();
    store
        .save_certificate("c.example.com", cert("PEM3", "Issuer 3", 1_200))
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
        .save_certificate("b.example.com", cert("PEM2B", "Issuer 2B", 4_000))
        .await
        .unwrap();
    assert_eq!(store.list_certificates().await.unwrap().len(), 3);
    let b = store
        .get_certificate("b.example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(b.not_after, 4_000);
    assert_eq!(b.issuer.as_deref(), Some("Issuer 2B"));
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
        issuer: None,
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
                store.create_person(bad).await,
                Err(StoreError::InvalidName(_))
            ),
            "person {bad:?} must be rejected"
        );
    }

    let alice = store.create_person("alice").await.unwrap();
    for bad in ["", "has-dash", "under_score", "Upper!", &"a".repeat(16)] {
        assert!(
            matches!(
                store.create_machine(alice.id, bad).await,
                Err(StoreError::InvalidName(_))
            ),
            "machine {bad:?} must be rejected"
        );
    }

    let laptop = store.create_machine(alice.id, "laptop").await.unwrap();
    // Service names allow dashes between alphanumeric runs but not leading,
    // trailing, doubled, or non-alphanumeric characters.
    for bad in [
        "",
        "-web",
        "web-",
        "a--b",
        "a.b",
        "web/api",
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

    // Valid names still work and are lowercased.
    let svc = store
        .get_or_create_service(laptop.id, "My-Web")
        .await
        .unwrap();
    assert_eq!(svc.name, "my-web");

    // A declared service is keyed by the flat hostname and validated at the
    // store boundary too (an invalid service never reaches persistence).
    let key = KeyId::Ed25519([0x33; 32]);
    store.add_machine_key(laptop.id, &key).await.unwrap();
    assert!(matches!(
        store
            .register_declared_service(&key, "alice-laptop-x.example.com", "a--b")
            .await,
        Err(StoreError::InvalidName(_))
    ));
}

#[tokio::test]
async fn test_recompute_domain_names_after_machine_rename() {
    use sea_orm::sea_query::Expr;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    use weaver_mux::KeyId;

    let store = Store::connect("sqlite::memory:").await.expect("connect");
    let alice = store.create_person("alice").await.unwrap();
    let laptop = store.create_machine(alice.id, "laptop").await.unwrap();
    let key = KeyId::Ed25519([0x44; 32]);
    store.add_machine_key(laptop.id, &key).await.unwrap();

    store
        .register_declared_service(&key, "alice-laptop-web.example.com", "web")
        .await
        .unwrap();
    assert!(
        store
            .get_domain("alice-laptop-web.example.com")
            .await
            .unwrap()
            .is_some()
    );

    // Rename the machine directly (there is no public rename API yet) and let
    // the sweep rewrite the derived `domains.name`.
    weaver_server::store::entity::machine::Entity::update_many()
        .col_expr(
            weaver_server::store::entity::machine::Column::Name,
            Expr::value("desktop"),
        )
        .filter(weaver_server::store::entity::machine::Column::Id.eq(laptop.id))
        .exec(store.db())
        .await
        .unwrap();

    store.recompute_domain_names("example.com").await.unwrap();

    assert!(
        store
            .get_domain("alice-desktop-web.example.com")
            .await
            .unwrap()
            .is_some(),
        "the materialized name must follow the renamed machine"
    );
    assert!(
        store
            .get_domain("alice-laptop-web.example.com")
            .await
            .unwrap()
            .is_none(),
        "the stale name must be gone"
    );
}

#[tokio::test]
async fn test_migration_usage_round_trips() {
    use sea_orm_migration::MigratorTrait;

    let temp = TempDir::new().expect("tempdir");
    let db_path = temp.path().join("migrate.db");
    let store = Store::open(&db_path).await.expect("open");

    // Roll every migration back, then re-apply. `m0001` creates the `usage`
    // table along with every other table, so a full rebuild is what proves
    // `down`/`up` are symmetric.
    weaver_server::Migrator::down(store.db(), None)
        .await
        .expect("down");
    let usage_tables: i64 = scalar(
        &store,
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='usage'",
    )
    .await;
    assert_eq!(usage_tables, 0, "down must drop the usage table");

    weaver_server::Migrator::up(store.db(), None)
        .await
        .expect("up");
    let usage_tables: i64 = scalar(
        &store,
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='usage'",
    )
    .await;
    assert_eq!(usage_tables, 1, "up must recreate the usage table");
}

// ---------------------------------------------------------------------------
// WVR-36: email attribution is atomic.
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

    // The account plane never touches the tunnel `person` namespace. The only
    // row present is the migration's default PoC seed ("poc").
    let people = person::Entity::find().all(store.db()).await.unwrap();
    assert!(
        people.iter().all(|p| p.name == "poc"),
        "accounts must not add person rows: {people:?}"
    );
}

// ----- password reset (WVR-41) ---------------------------------------------

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

/// WVR-50: an authenticated password change carries the reset's guarantees —
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
