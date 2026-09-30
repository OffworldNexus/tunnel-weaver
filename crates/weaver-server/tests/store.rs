use std::net::SocketAddr;
use std::path::PathBuf;

use sea_orm::{ConnectionTrait, DbBackend, Statement};
use tempfile::TempDir;
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
        root_domain: "example.com".into(),
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
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('config', 'acme_account', 'domains', 'certificates', 'cert_events', 'seaql_migrations', 'person', 'machine', 'machine_key', 'service')",
        )
        .await;
        assert_eq!(count, 10);
        assert_eq!(store.schema_version().await.expect("schema_version"), 1);
    }

    // Re-open existing database: should succeed and not re-apply migrations
    {
        let store = Store::open(&db_path).await.expect("re-open failed");
        let migration_count: i64 = scalar(&store, "SELECT count(*) FROM seaql_migrations").await;
        assert_eq!(migration_count, 1);
        assert_eq!(store.schema_version().await.expect("schema_version"), 1);
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
            assert!(keys.contains(&"root_domain".to_string()));
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
}

#[tokio::test]
async fn test_set_config_mutates_single_key() {
    let temp = TempDir::new().expect("tempdir");
    let db_path = temp.path().join("set_config.db");
    let store = Store::open(&db_path).await.expect("open failed");

    for (k, v) in [
        ("root_domain", "tunnel.nexus.com"),
        ("admin_email", "ops@nexus.com"),
        ("acme_provider", "letsencrypt"),
        ("listen_http", "\"127.0.0.1:8080\""),
        ("listen_https", "\"127.0.0.1:8443\""),
        ("control_socket", "\"/tmp/control.sock\""),
    ] {
        store.set_config(k, v).await.expect("set_config failed");
    }

    let loaded = store.load_config().await.expect("load_config failed");
    assert_eq!(loaded.root_domain, "tunnel.nexus.com");
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
        root_domain: "backup.nexus.com".into(),
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

    // A declared service attaches to the machine and links its hostname.
    let svc = store
        .register_declared_service(&alice_key, "api.workstation.alice.example.com", "API")
        .await
        .expect("register service");
    assert_eq!(svc.name, "api");
    assert_eq!(svc.machine_id, desktop.id);

    let domain = store
        .get_domain("api.workstation.alice.example.com")
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
        active_at: Some(100),
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
    assert_eq!(rec.last_active_at, Some(100));

    // Saving another certificate inserts a new certificate row linked to the same domain
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

    // only_best = true returns 1 (the best one, not_after = 300)
    assert_eq!(store.list_certificates(true).await.expect("list").len(), 1);
    assert_eq!(
        store
            .get_certificate("host.example.com")
            .await
            .unwrap()
            .unwrap()
            .not_after,
        300
    );

    // only_best = false returns both certificates
    assert_eq!(store.list_certificates(false).await.expect("list").len(), 2);

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

    // Active flag
    store
        .set_cert_active("host.example.com", None)
        .await
        .expect("set inactive");
    assert_eq!(
        store
            .get_certificate("host.example.com")
            .await
            .unwrap()
            .unwrap()
            .last_active_at,
        None
    );

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
async fn test_multiple_certificates_and_best_resolution() {
    let store = Store::connect("sqlite::memory:").await.expect("connect");

    let cert_1 = weaver_server::store::NewCertificate {
        cert_pem: "PEM1".into(),
        key_pem: "KEY1".into(),
        not_before: 1_000,
        not_after: 2_000,
        issuer: Some("Issuer 1".into()),
        directory: "dir1".into(),
        obtained_at: 1_000,
        active_at: Some(1_000),
    };
    let cert_2 = weaver_server::store::NewCertificate {
        cert_pem: "PEM2".into(),
        key_pem: "KEY2".into(),
        not_before: 1_500,
        not_after: 3_000, // Furthest expiration
        issuer: Some("Issuer 2".into()),
        directory: "dir2".into(),
        obtained_at: 1_500,
        active_at: Some(1_500),
    };
    let cert_3 = weaver_server::store::NewCertificate {
        cert_pem: "PEM3".into(),
        key_pem: "KEY3".into(),
        not_before: 500,
        not_after: 1_200,
        issuer: Some("Issuer 3".into()),
        directory: "dir3".into(),
        obtained_at: 500,
        active_at: Some(500),
    };

    store
        .save_certificate("multi.example.com", cert_1)
        .await
        .unwrap();
    store
        .save_certificate("multi.example.com", cert_2)
        .await
        .unwrap();
    store
        .save_certificate("multi.example.com", cert_3)
        .await
        .unwrap();

    // Verify count in SQL
    let count = store
        .count_certificates_for_domain("multi.example.com")
        .await
        .unwrap();
    assert_eq!(count, 3);

    // Verify best certificate resolution chooses cert_2 (furthest not_after = 3000)
    let best = store
        .get_certificate("multi.example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(best.not_after, 3_000);
    assert_eq!(best.issuer.as_deref(), Some("Issuer 2"));

    // Verify list_certificates(true) returns only the single best certificate
    let list_best = store.list_certificates(true).await.unwrap();
    assert_eq!(list_best.len(), 1);
    assert_eq!(list_best[0].not_after, 3_000);

    // Verify list_certificates(false) returns all 3 certificates
    let list_all = store.list_certificates(false).await.unwrap();
    assert_eq!(list_all.len(), 3);

    // Verify list_best_certificates_full returns only 1 full record with PEMs
    let full_best = store.list_best_certificates_full().await.unwrap();
    assert_eq!(full_best.len(), 1);
    assert_eq!(full_best[0].cert_pem, "PEM2");
}

#[tokio::test]
async fn test_cascade_delete_domain() {
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
        active_at: None,
    };
    store
        .save_certificate("cascade.example.com", cert)
        .await
        .unwrap();
    assert_eq!(
        store
            .count_certificates_for_domain("cascade.example.com")
            .await
            .unwrap(),
        1
    );

    let domain = store
        .get_domain("cascade.example.com")
        .await
        .unwrap()
        .unwrap();
    // Delete parent domain directly via entity
    weaver_server::store::entity::domain::Entity::delete_by_id(domain.id)
        .exec(store.db())
        .await
        .unwrap();

    // Associated certificates should be cascaded and deleted
    let certs_count: i64 = scalar(
        &store,
        "SELECT count(*) FROM certificates WHERE domain_id = 999 OR domain_id NOT IN (SELECT id FROM domains)",
    )
    .await;
    assert_eq!(certs_count, 0);
}
