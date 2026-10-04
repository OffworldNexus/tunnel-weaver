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
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('config', 'acme_account', 'domains', 'certificates', 'cert_events', 'seaql_migrations', 'person', 'machine', 'machine_key', 'service', 'usage', 'challenge')",
        )
        .await;
        assert_eq!(count, 12);
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

    // OFF-198 foot-gun: an admin domain nested under the delegated tunnel zone
    // would hand the relay's own DNS to the zone the relay is meant to control.
    let nested_admin_config = Config {
        admin_domain: "relay.example.com".into(),
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
        root_domain: "tunnels.relay.example.net".into(),
        admin_domain: "relay.example.net".into(),
        acme_provider: "letsencrypt".into(),
        admin_email: "admin@example.com".into(),
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
async fn test_set_config_mutates_single_key() {
    let temp = TempDir::new().expect("tempdir");
    let db_path = temp.path().join("set_config.db");
    let store = Store::open(&db_path).await.expect("open failed");

    for (k, v) in [
        ("root_domain", "tunnel.nexus.com"),
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
        wildcard: true,
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
    assert!(rec.wildcard);

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

    // Both `only_best` variants return the single row.
    assert_eq!(store.list_certificates(true).await.expect("list").len(), 1);
    assert_eq!(store.list_certificates(false).await.expect("list").len(), 1);
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
    let full = store.list_best_certificates_full().await.unwrap();
    assert_eq!(full.len(), 1);
    assert_eq!(full[0].cert_pem, "CERT");
    assert_eq!(full[0].key_pem, "KEY");
    assert_eq!(full[0].validation, "dns-01");
    assert!(full[0].wildcard);

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
        .publish_challenge("_acme-challenge.example.com", "digest-a", 1)
        .await
        .unwrap();
    store
        .publish_http01("token-1", "key-auth-1", 1)
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

    // `validation` and `wildcard` round-trip both mechanisms.
    for (name, mechanism, wildcard) in [
        ("example.com", "dns-01", true),
        ("relay.example.net", "http-01", false),
    ] {
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
                    wildcard,
                },
            )
            .await
            .unwrap();
        let rec = store.get_certificate(name).await.unwrap().unwrap();
        assert_eq!(rec.validation, mechanism);
        assert_eq!(rec.wildcard, wildcard);
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
        wildcard: false,
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

    // Certificates are global and keyed by name: three distinct rows, and the
    // `only_best` flag no longer ranks within a domain.
    assert_eq!(store.list_certificates(true).await.unwrap().len(), 3);
    assert_eq!(store.list_certificates(false).await.unwrap().len(), 3);
    assert_eq!(store.list_best_certificates_full().await.unwrap().len(), 3);

    let names: Vec<String> = store
        .list_certificates(false)
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
    assert_eq!(store.list_certificates(false).await.unwrap().len(), 3);
    let b = store
        .get_certificate("b.example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(b.not_after, 4_000);
    assert_eq!(b.issuer.as_deref(), Some("Issuer 2B"));
    let full_b = store
        .list_best_certificates_full()
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.name == "b.example.com")
        .unwrap();
    assert_eq!(full_b.cert_pem, "PEM2B");
}

#[tokio::test]
async fn test_deleting_certificate_clears_domain_reference() {
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
        wildcard: false,
    };
    let saved = store
        .save_certificate("cascade.example.com", cert)
        .await
        .unwrap();

    // A materialized domain points at the covering certificate.
    store
        .get_or_create_domain("cascade.example.com", None)
        .await
        .unwrap();
    store
        .set_domain_certificate("cascade.example.com", saved.id)
        .await
        .unwrap();
    let domain = store
        .get_domain("cascade.example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(domain.certificate_id, Some(saved.id));

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

    // Conversely, deleting the certificate nulls the referencing domain
    // (`ON DELETE SET NULL`) rather than cascading the domain away.
    let recreated = store
        .get_or_create_domain("cascade.example.com", None)
        .await
        .unwrap();
    store
        .set_domain_certificate("cascade.example.com", saved.id)
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
    assert_eq!(after.certificate_id, None);
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

    // Roll the single migration back, then re-apply. `m0001` creates the
    // `usage` table along with every other table, so a full rebuild is what
    // proves `down`/`up` are symmetric.
    weaver_server::Migrator::down(store.db(), Some(1))
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
