use std::net::SocketAddr;
use std::path::PathBuf;

use tempfile::TempDir;
use weaver_server::{Config, ConfigError, Store, StoreError};

#[test]
fn test_store_open_creates_dirs_and_files_with_correct_permissions() {
    let temp = TempDir::new().expect("failed to create temp dir");
    let nested_dir = temp.path().join("nested").join("sub");
    let db_path = nested_dir.join("weaver.db");

    assert!(!nested_dir.exists());
    assert!(!db_path.exists());

    let store = Store::open(&db_path).expect("failed to open store");

    assert!(nested_dir.exists());
    assert!(db_path.exists());

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

    // Verify pragmas
    store
        .read(|conn| {
            let journal_mode: String = conn.query_row("PRAGMA journal_mode;", [], |r| r.get(0))?;
            assert_eq!(journal_mode.to_lowercase(), "wal");

            let busy_timeout: i64 = conn.query_row("PRAGMA busy_timeout;", [], |r| r.get(0))?;
            assert_eq!(busy_timeout, 5000);

            let foreign_keys: i64 = conn.query_row("PRAGMA foreign_keys;", [], |r| r.get(0))?;
            assert_eq!(foreign_keys, 1);

            let synchronous: i64 = conn.query_row("PRAGMA synchronous;", [], |r| r.get(0))?;
            // 1 is NORMAL
            assert_eq!(synchronous, 1);

            let temp_store: i64 = conn.query_row("PRAGMA temp_store;", [], |r| r.get(0))?;
            // 2 is MEMORY
            assert_eq!(temp_store, 2);

            Ok(())
        })
        .expect("pragma query failed");

    // Close and ensure optimize runs
    store.close().expect("close failed");
}

#[test]
fn test_store_open_executes_migration_0001_and_is_idempotent() {
    let temp = TempDir::new().expect("tempdir");
    let db_path = temp.path().join("weaver.db");

    {
        let store = Store::open(&db_path).expect("open failed");
        store
            .read(|conn| {
                // Verify tables created by 0001
                let count: i64 = conn.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('config', 'acme_account', 'certificates', 'cert_events', 'schema_migrations')",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(count, 5);

                let migration_count: i64 =
                    conn.query_row("SELECT count(*) FROM schema_migrations", [], |r| r.get(0))?;
                assert_eq!(migration_count, 1);
                Ok(())
            })
            .expect("read failed");
    }

    // Re-open existing database: should succeed without error and not duplicate migrations
    {
        let store = Store::open(&db_path).expect("re-open failed");
        store
            .read(|conn| {
                let migration_count: i64 =
                    conn.query_row("SELECT count(*) FROM schema_migrations", [], |r| r.get(0))?;
                assert_eq!(migration_count, 1);
                Ok(())
            })
            .expect("read failed");
    }
}

#[test]
fn test_store_refuses_open_on_newer_schema() {
    let temp = TempDir::new().expect("tempdir");
    let db_path = temp.path().join("newer.db");

    {
        let store = Store::open(&db_path).expect("open failed");
        store
            .write(|conn| {
                conn.execute(
                    "INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (999, '999_future', 'fakehash', 12345)",
                    [],
                )?;
                Ok(())
            })
            .expect("write failed");
    }

    // Re-opening should fail with NewerSchema
    match Store::open(&db_path) {
        Err(StoreError::NewerSchema {
            db_version,
            binary_version,
        }) => {
            assert_eq!(db_version, 999);
            assert_eq!(binary_version, 1);
        }
        res => panic!("Expected NewerSchema error, got: {res:?}"),
    }
}

#[test]
fn test_store_refuses_open_on_checksum_mismatch() {
    let temp = TempDir::new().expect("tempdir");
    let db_path = temp.path().join("tampered.db");

    {
        let store = Store::open(&db_path).expect("open failed");
        store
            .write(|conn| {
                conn.execute(
                    "UPDATE schema_migrations SET checksum = 'tampered_checksum' WHERE version = 1",
                    [],
                )?;
                Ok(())
            })
            .expect("write failed");
    }

    // Re-opening should fail with ChecksumMismatch
    match Store::open(&db_path) {
        Err(StoreError::ChecksumMismatch {
            version,
            expected,
            actual,
        }) => {
            assert_eq!(version, 1);
            assert_eq!(actual, "tampered_checksum");
            assert_ne!(expected, "tampered_checksum");
        }
        res => panic!("Expected ChecksumMismatch error, got: {res:?}"),
    }
}

#[test]
fn test_config_load_on_unconfigured_db_lists_missing_keys() {
    let temp = TempDir::new().expect("tempdir");
    let db_path = temp.path().join("unconfigured.db");
    let store = Store::open(&db_path).expect("open failed");

    match Config::load(&store) {
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

#[test]
fn test_config_save_and_load_round_trip() {
    let temp = TempDir::new().expect("tempdir");
    let db_path = temp.path().join("config_rt.db");
    let store = Store::open(&db_path).expect("open failed");

    let config = Config {
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
    };

    store.save_config(&config).expect("save_config failed");

    let loaded = Config::load(&store).expect("load failed");
    assert_eq!(loaded, config);

    // Test store.load_config() shortcut
    let loaded_shortcut = store.load_config().expect("shortcut load failed");
    assert_eq!(loaded_shortcut, config);
}

#[test]
fn test_config_validation_rules() {
    let temp = TempDir::new().expect("tempdir");
    let db_path = temp.path().join("validation.db");
    let store = Store::open(&db_path).expect("open failed");

    // Google provider requires EAB kid and hmac
    let invalid_google_config = Config {
        root_domain: "example.com".into(),
        admin_email: "admin@example.com".into(),
        acme_provider: "google".into(),
        listen_http: "0.0.0.0:80".parse().unwrap(),
        listen_https: "0.0.0.0:443".parse().unwrap(),
        control_socket: PathBuf::from("/run/weaver.sock"),
        acme_directory: None,
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: None,
        acme_fallback_providers: vec![],
    };

    store
        .save_config(&invalid_google_config)
        .expect("save succeeded");
    match Config::load(&store) {
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
        .expect("save succeeded");
    match Config::load(&store) {
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
        .expect("save succeeded");
    match Config::load(&store) {
        Err(ConfigError::ValidationFailed(issues)) => {
            assert!(issues.iter().any(|i| i.contains("not a valid email")));
        }
        res => panic!("Expected ValidationFailed, got: {res:?}"),
    }
}

#[test]
fn test_set_config_mutates_single_key() {
    let temp = TempDir::new().expect("tempdir");
    let db_path = temp.path().join("set_config.db");
    let store = Store::open(&db_path).expect("open failed");

    store
        .set_config("root_domain", "tunnel.nexus.com")
        .expect("set_config failed");
    store
        .set_config("admin_email", "ops@nexus.com")
        .expect("set_config failed");
    store
        .set_config("acme_provider", "letsencrypt")
        .expect("set_config failed");
    store
        .set_config("listen_http", "\"127.0.0.1:8080\"")
        .expect("set_config failed");
    store
        .set_config("listen_https", "\"127.0.0.1:8443\"")
        .expect("set_config failed");
    store
        .set_config("control_socket", "\"/tmp/control.sock\"")
        .expect("set_config failed");

    let loaded = store.load_config().expect("load_config failed");
    assert_eq!(loaded.root_domain, "tunnel.nexus.com");
    assert_eq!(loaded.admin_email, "ops@nexus.com");
    assert_eq!(loaded.acme_provider, "letsencrypt");
    assert_eq!(
        loaded.listen_http,
        "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
    );
}

#[test]
fn test_backup_creates_openable_database() {
    let temp = TempDir::new().expect("tempdir");
    let original_db = temp.path().join("original.db");
    let backup_db = temp.path().join("backup.db");

    let store = Store::open(&original_db).expect("open failed");
    let config = Config {
        root_domain: "backup.nexus.com".into(),
        admin_email: "backup@nexus.com".into(),
        acme_provider: "letsencrypt".into(),
        listen_http: "0.0.0.0:80".parse().unwrap(),
        listen_https: "0.0.0.0:443".parse().unwrap(),
        control_socket: PathBuf::from("/run/weaver.sock"),
        acme_directory: None,
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: None,
        acme_fallback_providers: vec![],
    };
    store.save_config(&config).expect("save failed");

    // Perform backup
    store.backup(&backup_db).expect("backup failed");
    assert!(backup_db.exists());

    // Open backup database directly and verify contents
    let backup_store = Store::open(&backup_db).expect("open backup failed");
    let loaded_config = backup_store
        .load_config()
        .expect("load backup config failed");
    assert_eq!(loaded_config, config);
}
