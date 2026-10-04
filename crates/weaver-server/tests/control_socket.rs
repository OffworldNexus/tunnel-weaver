use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::process::Command;
use std::time::Duration;

use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use weaver_server::{Config, Store};

fn create_valid_test_config(
    http_port: u16,
    https_port: u16,
    control_socket: std::path::PathBuf,
) -> Config {
    Config {
        tunnel_domain: "weaver.test".to_string(),
        admin_domain: "relay-admin.test".to_string(),
        admin_email: "admin@weaver.test".to_string(),
        acme_provider: "letsencrypt-staging".to_string(),
        listen_http: SocketAddr::from(([127, 0, 0, 1], http_port)),
        listen_https: SocketAddr::from(([127, 0, 0, 1], https_port)),
        control_socket,
        acme_directory: None,
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: None,
        acme_fallback_providers: Vec::new(),
        usage_flush_interval_secs: 60,
        relay_ips: Vec::new(),
        setup_complete: false,
    }
}

// 1. Missing control socket exits with code 3 and diagnostic hint
#[test]
fn test_cli_diagnostics_missing_socket() {
    let bin_path = env!("CARGO_BIN_EXE_weaver-server");
    let output = Command::new(bin_path)
        .arg("--socket")
        .arg("/tmp/nonexistent-weaver-socket-12345.sock")
        .arg("status")
        .output()
        .expect("failed to execute weaver-server status");

    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Cannot connect to control socket"));
    assert!(stderr.contains("Hint: systemctl status weaver-server"));
}

// 2. Permission denied connecting to control socket exits with code 1 and diagnostic hint
#[tokio::test]
async fn test_cli_diagnostics_permission_denied() {
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("noperms.sock");
    let _listener = tokio::net::UnixListener::bind(&socket_path).unwrap();

    // Set permission to 0000 (no read/write for anyone)
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o000)).unwrap();

    let bin_path = env!("CARGO_BIN_EXE_weaver-server");
    let output = Command::new(bin_path)
        .arg("--socket")
        .arg(&socket_path)
        .arg("status")
        .output()
        .expect("failed to execute weaver-server status");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Permission denied connecting to control socket"));
    assert!(stderr.contains("Hint: run with sudo or join group 'weaver'"));
}

// 2. Mutual exclusion of --socket and --db
#[test]
fn test_cli_mutual_exclusion_socket_and_db() {
    let bin_path = env!("CARGO_BIN_EXE_weaver-server");
    let output = Command::new(bin_path)
        .arg("--socket")
        .arg("/tmp/some.sock")
        .arg("--db")
        .arg("/tmp/some.db")
        .arg("status")
        .output()
        .expect("failed to execute weaver-server");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be used with")
            || stderr.contains("conflicts with")
            || stderr.contains("--db")
    );
}

// 3. Running 'weaver-server run' without --db refuses to start
#[test]
fn test_cli_run_refuses_without_db() {
    let bin_path = env!("CARGO_BIN_EXE_weaver-server");
    let output = Command::new(bin_path)
        .env_remove("WEAVER_DB")
        .arg("run")
        .output()
        .expect("failed to execute weaver-server run");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Database path is required"));
}

// 4. Invalid hostname without dot and not 'root' exits with code 2
#[test]
fn test_cli_invalid_hostname_exits_2() {
    let bin_path = env!("CARGO_BIN_EXE_weaver-server");
    let output = Command::new(bin_path)
        .arg("--socket")
        .arg("/tmp/some.sock")
        .arg("cert")
        .arg("status")
        .arg("barehostname")
        .output()
        .expect("failed to execute weaver-server cert status");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Invalid hostname 'barehostname'"));
}

// 5. Full daemon integration: permissions, protocol envelope, commands, and shutdown
#[tokio::test]
async fn test_control_socket_daemon_suite() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let control_sock_path = dir.path().join("control.sock");
    let notify_sock_path = dir.path().join("notify.sock");
    let notify_listener = UnixDatagram::bind(&notify_sock_path).unwrap();

    let l1 = TcpListener::bind("127.0.0.1:0").unwrap();
    let l2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let http_port = l1.local_addr().unwrap().port();
    let https_port = l2.local_addr().unwrap().port();
    drop(l1);
    drop(l2);

    let store = Store::open(&db_path).await.unwrap();
    let config = create_valid_test_config(http_port, https_port, control_sock_path.clone());
    store.save_config(&config).await.unwrap();

    // Generate the single wildcard certificate `[weaver.test, *.weaver.test]`.
    let root_rcgen = rcgen::generate_simple_self_signed(vec![
        "weaver.test".to_string(),
        "*.weaver.test".to_string(),
    ])
    .unwrap();
    let root_cert_pem = root_rcgen.cert.pem();
    let root_key_pem = root_rcgen.signing_key.serialize_pem();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let seed_cert =
        |cert_pem: &str, key_pem: &str, days: i64| weaver_server::store::NewCertificate {
            cert_pem: cert_pem.to_string(),
            key_pem: key_pem.to_string(),
            not_before: now - 3600,
            not_after: now + 86400 * days,
            issuer: Some("Test Issuer".to_string()),
            directory: "letsencrypt-staging".to_string(),
            obtained_at: now - 3600,
            validation: "dns-01".to_string(),
        };
    // Seed an older wildcard (30 days left), then upsert the newer one (90
    // days left): one global row keyed by the apex name.
    store
        .save_certificate("weaver.test", seed_cert(&root_cert_pem, &root_key_pem, 30))
        .await
        .unwrap();
    store
        .save_certificate("weaver.test", seed_cert(&root_cert_pem, &root_key_pem, 90))
        .await
        .unwrap();
    // Cert events
    store
        .record_cert_event(
            "weaver.test",
            now - 3600,
            "issued",
            Some("Certificate successfully issued"),
        )
        .await
        .unwrap();

    store.close().await.unwrap();

    let bin_path = env!("CARGO_BIN_EXE_weaver-server");
    let mut child = Command::new(bin_path)
        .arg("--db")
        .arg(&db_path)
        .arg("run")
        .env("NOTIFY_SOCKET", &notify_sock_path)
        .spawn()
        .expect("failed to spawn weaver-server");

    // Wait for READY=1 notification
    let mut buf = [0u8; 512];
    notify_listener
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut saw_ready = false;
    while let Ok(len) = notify_listener.recv(&mut buf) {
        let msg = std::str::from_utf8(&buf[..len]).unwrap();
        if msg.contains("READY=1") {
            saw_ready = true;
            break;
        }
    }
    assert!(saw_ready, "Server failed to send READY notification");

    // --- Check socket file mode 0660 ---
    let meta = std::fs::metadata(&control_sock_path).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o660);

    // --- Test raw socket protocol: malformed JSON and unknown command ---
    {
        let mut stream = UnixStream::connect(&control_sock_path).await.unwrap();
        stream.write_all(b"not json\n").await.unwrap();
        stream.flush().await.unwrap();

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let val: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(val["ok"], false);
        assert!(val["error"].as_str().unwrap().contains("Malformed JSON"));
    }

    {
        let mut stream = UnixStream::connect(&control_sock_path).await.unwrap();
        stream
            .write_all(b"{\"v\": 2, \"cmd\": \"status\"}\n")
            .await
            .unwrap();
        stream.flush().await.unwrap();

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let val: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(val["ok"], false);
        assert!(
            val["error"]
                .as_str()
                .unwrap()
                .contains("Unsupported protocol version")
        );
    }

    {
        let mut stream = UnixStream::connect(&control_sock_path).await.unwrap();
        stream
            .write_all(b"{\"v\": 1, \"cmd\": \"invalid_verb\"}\n")
            .await
            .unwrap();
        stream.flush().await.unwrap();

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let val: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(val["ok"], false);
        assert!(val["error"].as_str().unwrap().contains("Unknown command"));
    }

    // --- Test CLI: status command ---
    {
        let output = Command::new(bin_path)
            .arg("--socket")
            .arg(&control_sock_path)
            .arg("status")
            .arg("--json")
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(0));
        let val: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(val["ok"], true);
        assert_eq!(val["tunnel_domain"], "weaver.test");
        assert_eq!(val["admin_domain"], "relay-admin.test");
        assert_eq!(val["schema_version"], 1);
        // The seeded tunnel wildcard reports issued; the admin certificate has
        // no stored row and is still pending, so it counts as ordering.
        assert_eq!(val["cert_counts"]["issued"], 1);
        assert_eq!(val["cert_counts"]["ordering"], 1);
        assert_eq!(val["cert_counts"]["failed"], 0);
        assert_eq!(val["cert_counts"]["inactive"], 0);
    }

    // --- Test CLI: status human-readable ---
    {
        let output = Command::new(bin_path)
            .arg("--socket")
            .arg(&control_sock_path)
            .arg("status")
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(0));
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Weaver Server Status"));
        assert!(stdout.contains("Root Domain"));
        assert!(stdout.contains("Admin Domain"));
        assert!(stdout.contains("weaver.test"));
        assert!(stdout.contains("relay-admin.test"));
        assert!(stdout.contains("issued"));
        assert!(stdout.contains("inactive"));
    }

    // --- Test CLI: cert status (list view) ---
    {
        let output = Command::new(bin_path)
            .arg("--socket")
            .arg(&control_sock_path)
            .arg("cert")
            .arg("status")
            .arg("--json")
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(0));
        let val: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(val["ok"], true);
        let certs = val["certificates"].as_array().unwrap();
        // Two managed certificates: the tunnel wildcard and the admin host.
        assert_eq!(certs.len(), 2);
        // Root domain is strictly first!
        assert_eq!(certs[0]["name"], "weaver.test");
        assert!(certs[0]["cert_id"].as_i64().is_some());
        assert_eq!(certs[1]["name"], "relay-admin.test");
    }

    // --- Test CLI: cert status --no-only-best (shows all certs and CERT-ID) ---
    {
        let output = Command::new(bin_path)
            .arg("--socket")
            .arg(&control_sock_path)
            .arg("cert")
            .arg("status")
            .arg("--no-only-best")
            .arg("--json")
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(0));
        let val: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(val["ok"], true);
        let certs = val["certificates"].as_array().unwrap();
        // Global certificates have no per-domain ranking: still two rows.
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0]["name"], "weaver.test");
        assert!(certs[0]["cert_id"].as_i64().is_some());
    }

    // --- Test CLI: cert status human-readable table with highlighted root ---
    {
        let output = Command::new(bin_path)
            .arg("--socket")
            .arg(&control_sock_path)
            .arg("cert")
            .arg("status")
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(0));
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("NAME"));
        assert!(!stdout.contains("CERT-ID")); // CERT-ID column omitted by default
        assert!(stdout.contains("weaver.test"));
        assert!(stdout.contains("★")); // Highlighted root!
    }

    // --- Test CLI: cert status --no-only-best table has CERT-ID and ★ on the apex ---
    {
        let output = Command::new(bin_path)
            .arg("--socket")
            .arg(&control_sock_path)
            .arg("cert")
            .arg("status")
            .arg("--no-only-best")
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(0));
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("CERT-ID"));
        assert!(stdout.contains("NAME"));
        // The single global certificate is the highlighted apex row.
        assert!(stdout.contains("★ weaver.test"));
    }

    // --- Test CLI: cert status detail view ---
    {
        let output = Command::new(bin_path)
            .arg("--socket")
            .arg(&control_sock_path)
            .arg("cert")
            .arg("status")
            .arg("root") // alias for root domain!
            .arg("--json")
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(0));
        let val: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(val["ok"], true);
        assert_eq!(val["name"], "weaver.test");
        assert_eq!(val["state"]["status"], "issued");
        assert!(val["cert_id"].as_i64().is_some());
        assert_eq!(val["cert_events"].as_array().unwrap().len(), 1);

        let root_cert_id = val["cert_id"].as_i64().unwrap();

        // Also test detail view by certificate integer PK!
        let output_by_id = Command::new(bin_path)
            .arg("--socket")
            .arg(&control_sock_path)
            .arg("cert")
            .arg("status")
            .arg(root_cert_id.to_string())
            .arg("--json")
            .output()
            .unwrap();

        assert_eq!(output_by_id.status.code(), Some(0));
        let val_by_id: serde_json::Value = serde_json::from_slice(&output_by_id.stdout).unwrap();
        assert_eq!(val_by_id["ok"], true);
        assert_eq!(val_by_id["name"], "weaver.test");
        assert_eq!(val_by_id["cert_id"], root_cert_id);
    }

    // --- Test CLI: cert wait on unknown name exits 1 ---
    {
        let output = Command::new(bin_path)
            .arg("--socket")
            .arg(&control_sock_path)
            .arg("cert")
            .arg("wait")
            .arg("nonexistent.weaver.test")
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(1));
    }

    // --- Test CLI: cert wait on already-issued root domain exits 0 immediately ---
    {
        let output = Command::new(bin_path)
            .arg("--socket")
            .arg(&control_sock_path)
            .arg("cert")
            .arg("wait")
            .arg("root")
            .arg("--json")
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(0));
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"state\":\"issued\""));
    }

    // --- Test CLI: cert renew default (root) ---
    {
        let output = Command::new(bin_path)
            .arg("--socket")
            .arg(&control_sock_path)
            .arg("cert")
            .arg("renew")
            .arg("--json")
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(0));
        let val: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(val["ok"], true);
        assert_eq!(val["renewed"][0], "weaver.test");
    }

    // --- Test CLI: cert renew --all has nothing to skip now ---
    {
        let output = Command::new(bin_path)
            .arg("--socket")
            .arg(&control_sock_path)
            .arg("cert")
            .arg("renew")
            .arg("--all")
            .arg("--json")
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(0));
        let val: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(val["ok"], true);
        let renewed = val["renewed"].as_array().unwrap();
        let skipped = val["skipped_inactive"].as_array().unwrap();
        // Both managed certificates are queued; admin sorts first.
        assert_eq!(
            renewed,
            &vec![
                serde_json::Value::from("relay-admin.test"),
                serde_json::Value::from("weaver.test"),
            ]
        );
        assert!(skipped.is_empty());
    }

    // --- Test CLI: cert renew for an explicit hostname maps to the wildcard ---
    {
        let output = Command::new(bin_path)
            .arg("--socket")
            .arg(&control_sock_path)
            .arg("cert")
            .arg("renew")
            .arg("poc-laptop-web.weaver.test")
            .arg("--json")
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(0));
        let val: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(val["ok"], true);
        assert_eq!(val["renewed"][0], "poc-laptop-web.weaver.test");
    }

    // --- Test CLI: backup command ---
    {
        let backup_dest = dir.path().join("backup.db");
        let output = Command::new(bin_path)
            .arg("--socket")
            .arg(&control_sock_path)
            .arg("backup")
            .arg(&backup_dest)
            .arg("--json")
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(0));
        let val: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(val["ok"], true);
        assert!(backup_dest.exists());
        assert!(val["size"].as_u64().unwrap() > 0);
    }

    // --- Test CLI: shutdown command ---
    {
        let output = Command::new(bin_path)
            .arg("--socket")
            .arg(&control_sock_path)
            .arg("shutdown")
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(0));
    }

    // Server should exit cleanly with status 0
    let status = child.wait().expect("server failed to exit");
    assert!(status.success());

    // Socket file must be cleaned up
    assert!(!control_sock_path.exists());
}

// 6. cert.wait streams transitions, exits with code 4 on Failed, and cert.renew enforces rate limits unless forced
#[tokio::test]
async fn test_cert_wait_streaming_failed_exit_4_and_renew_rate_limit() {
    use std::sync::Arc;
    use std::time::Instant;
    use tokio_util::sync::CancellationToken;
    use weaver_server::cert::{CertManager, CertResolver, CertState, SystemClock};

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let control_sock_path = dir.path().join("control.sock");

    let store = Arc::new(Store::open(&db_path).await.unwrap());
    let config = Arc::new(Config {
        tunnel_domain: "weaver.test".to_string(),
        admin_domain: "relay-admin.test".to_string(),
        admin_email: "admin@weaver.test".to_string(),
        acme_provider: "letsencrypt-staging".to_string(),
        listen_http: "[::]:80".parse().unwrap(),
        listen_https: "[::]:443".parse().unwrap(),
        control_socket: control_sock_path.clone(),
        acme_directory: None,
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: None,
        acme_fallback_providers: Vec::new(),
        usage_flush_interval_secs: 60,
        relay_ips: Vec::new(),
        setup_complete: false,
    });
    store.save_config(&config).await.unwrap();

    let resolver = Arc::new(CertResolver::new(config.tunnel_domain.clone()));

    let cert_manager = CertManager::new(
        Arc::clone(&config),
        Arc::clone(&store),
        Arc::clone(&resolver),
        Arc::new(SystemClock),
    );

    // Track a test hostname in Ordering state
    let test_host = "test-fail.weaver.test";
    cert_manager.set_state(test_host, CertState::Ordering);

    let shutdown_token = CancellationToken::new();
    let listener =
        weaver_server::control::server::bind_control_listener(&control_sock_path).unwrap();

    let srv_token = shutdown_token.clone();
    let srv_sock = control_sock_path.clone();
    let srv_cfg = Arc::clone(&config);
    let srv_store = Arc::clone(&store);
    let srv_mgr = Arc::clone(&cert_manager);
    let srv_metering = Arc::new(weaver_server::metering::MeteringManager::new(
        store.as_ref().clone(),
        Duration::from_secs(60),
    ));
    tokio::spawn(async move {
        let _ = weaver_server::control::server::run_control_server_with_listener(
            listener,
            srv_sock,
            srv_cfg,
            srv_store,
            srv_mgr,
            srv_metering,
            Instant::now(),
            srv_token,
        )
        .await;
    });

    let bin_path = env!("CARGO_BIN_EXE_weaver-server");

    // Spawn a task that simulates failure after a brief delay
    let fail_mgr = Arc::clone(&cert_manager);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        fail_mgr.set_state(
            test_host,
            CertState::Failed {
                error: "ACME Challenge validation failed".to_string(),
                next_retry: now + 3600,
            },
        );
    });

    // Run cert wait via CLI in blocking thread - must stream transition and exit with code 4
    let sock = control_sock_path.clone();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(bin_path)
            .arg("--socket")
            .arg(&sock)
            .arg("cert")
            .arg("wait")
            .arg(test_host)
            .output()
            .expect("failed to execute cert wait")
    })
    .await
    .unwrap();

    assert_eq!(output.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Issuance failed: ACME Challenge validation failed"));

    // Renewal now acts on the apex (the wildcard is the only certificate), so
    // mark the apex failed with a future retry to exercise the rate limit.
    cert_manager.set_state(
        "weaver.test",
        CertState::Failed {
            error: "ACME Challenge validation failed".to_string(),
            next_retry: now + 3600,
        },
    );

    // Now test cert renew without --force -> must fail with rate limit error (exit 1)
    let sock = control_sock_path.clone();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(bin_path)
            .arg("--socket")
            .arg(&sock)
            .arg("cert")
            .arg("renew")
            .arg(test_host)
            .output()
            .expect("failed to execute cert renew")
    })
    .await
    .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Rate limited") || stderr.contains("retry for hostname"));

    // Now test cert renew with --force -> must succeed (exit 0)
    let sock = control_sock_path.clone();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(bin_path)
            .arg("--socket")
            .arg(&sock)
            .arg("cert")
            .arg("renew")
            .arg(test_host)
            .arg("--force")
            .arg("--json")
            .output()
            .expect("failed to execute cert renew --force")
    })
    .await
    .unwrap();

    assert_eq!(output.status.code(), Some(0));
    let val: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(val["ok"], true);
    assert_eq!(val["renewed"][0], test_host);

    shutdown_token.cancel();
}

/// Sends a raw control request and returns the parsed response line.
async fn control_roundtrip(sock: &std::path::Path, req: serde_json::Value) -> serde_json::Value {
    let mut stream = UnixStream::connect(sock).await.unwrap();
    let mut data = serde_json::to_vec(&req).unwrap();
    data.push(b'\n');
    stream.write_all(&data).await.unwrap();
    stream.flush().await.unwrap();
    let (reader, _) = stream.split();
    let mut buf = BufReader::new(reader);
    let mut line = String::new();
    buf.read_line(&mut line).await.unwrap();
    serde_json::from_str(&line).unwrap()
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[tokio::test]
async fn test_usage_control_verb_and_cli() {
    use std::sync::Arc;
    use std::time::Instant;
    use tokio_util::sync::CancellationToken;
    use weaver_server::cert::{CertManager, CertResolver, SystemClock};
    use weaver_server::metering::MeteringManager;

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("usage.db");
    let control_sock_path = dir.path().join("control.sock");

    let store = Arc::new(Store::open(&db_path).await.unwrap());
    let config = Arc::new(create_valid_test_config(0, 0, control_sock_path.clone()));
    store.save_config(&config).await.unwrap();

    let resolver = Arc::new(CertResolver::new(config.tunnel_domain.clone()));
    let cert_manager = CertManager::new(
        Arc::clone(&config),
        Arc::clone(&store),
        resolver,
        Arc::new(SystemClock),
    );

    // Seed one service and drive the manager's own loop so open time accrues.
    let alice = store.create_person("Alice").await.unwrap();
    let laptop = store.create_machine(alice.id, "laptop").await.unwrap();
    let web = store.get_or_create_service(laptop.id, "web").await.unwrap();

    let metering = Arc::new(MeteringManager::new(
        store.as_ref().clone(),
        Duration::from_secs(60),
    ));
    metering.register_service(web.id);
    metering.record_request(web.id);
    metering.record_request(web.id);
    metering.record_request(web.id);
    // Stream byte reports: the relay reports the visitor leg, the mux reports
    // the compressed tunnel leg.
    metering.register_stream(1, web.id);
    metering.visitor_service_bytes(web.id, 1_000, 2_000);
    metering.tunnel_bytes(1, 300, 600);
    metering.unregister_stream(1);
    let meter_task = metering.start(CancellationToken::new());
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    // Stop the open clock, then flush. The current minute is complete-only-
    // persisted, so the row the CLI reads is served live from memory.
    metering.unregister_service(web.id);
    metering.flush().await.expect("flush");

    let shutdown_token = CancellationToken::new();
    let listener =
        weaver_server::control::server::bind_control_listener(&control_sock_path).unwrap();
    let srv_token = shutdown_token.clone();
    let srv_sock = control_sock_path.clone();
    let srv_cfg = Arc::clone(&config);
    let srv_store = Arc::clone(&store);
    let srv_mgr = Arc::clone(&cert_manager);
    let srv_metering = Arc::clone(&metering);
    tokio::spawn(async move {
        let _ = weaver_server::control::server::run_control_server_with_listener(
            listener,
            srv_sock,
            srv_cfg,
            srv_store,
            srv_mgr,
            srv_metering,
            Instant::now(),
            srv_token,
        )
        .await;
    });

    let now = now_secs();
    let from = (now - 3_600).to_string();
    let until = (now + 3_600).to_string();

    let run_usage = |args: Vec<String>| {
        let sock = control_sock_path.clone();
        let bin = env!("CARGO_BIN_EXE_weaver-server");
        tokio::task::spawn_blocking(move || {
            let mut cmd = Command::new(bin);
            cmd.arg("--socket").arg(&sock).arg("usage");
            for a in args {
                cmd.arg(a);
            }
            cmd.output().expect("run usage")
        })
    };

    // JSON round-trip exposes the totals with `open_ms` (never `unused_ms`).
    let output = run_usage(vec![
        "--from".into(),
        from.clone(),
        "--until".into(),
        until.clone(),
        "--json".into(),
    ])
    .await
    .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let val: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(val["ok"], true);
    assert_eq!(val["services"][0]["service"], "web");
    assert_eq!(val["services"][0]["person"], "alice");
    assert_eq!(val["services"][0]["machine"], "laptop");
    assert_eq!(val["services"][0]["bytes_in"], 1_000);
    assert_eq!(val["services"][0]["bytes_out"], 2_000);
    assert_eq!(val["services"][0]["tunnel_in"], 300);
    assert_eq!(val["services"][0]["tunnel_out"], 600);
    assert_eq!(val["services"][0]["requests"], 3);
    assert_eq!(val["services"][0]["covered_minutes"], 1);
    assert!(
        val["services"][0]["open_ms"].as_i64().unwrap() > 0,
        "open time accrued: {}",
        val["services"][0]["open_ms"]
    );

    // Human output prints the service row.
    let output = run_usage(vec![
        "--from".into(),
        from.clone(),
        "--until".into(),
        until.clone(),
    ])
    .await
    .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("web"));

    // Filters: matching names return the row, unknown names return none.
    for (flag, value, expected) in [
        ("--service", "web", 1usize),
        ("--service", "nope", 0),
        ("--person", "alice", 1),
        ("--person", "bob", 0),
    ] {
        let output = run_usage(vec![
            "--from".into(),
            from.clone(),
            "--until".into(),
            until.clone(),
            "--json".into(),
            flag.into(),
            value.into(),
        ])
        .await
        .unwrap();
        assert_eq!(output.status.code(), Some(0));
        let val: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            val["services"].as_array().unwrap().len(),
            expected,
            "{flag} {value}"
        );
    }

    // A bad range is rejected client-side with exit 2.
    let output = run_usage(vec![
        "--from".into(),
        until.clone(),
        "--until".into(),
        from.clone(),
    ])
    .await
    .unwrap();
    assert_eq!(output.status.code(), Some(2));

    // `--since` is accepted as a duration.
    let output = run_usage(vec!["--since".into(), "1d 12h".into(), "--json".into()])
        .await
        .unwrap();
    assert_eq!(output.status.code(), Some(0));

    // The server itself rejects an inverted range sent directly.
    let resp = control_roundtrip(
        &control_sock_path,
        serde_json::json!({"v": 1, "cmd": "usage", "since": 12000, "until": 6000}),
    )
    .await;
    assert_eq!(resp["ok"], false);
    assert!(
        resp["error"]
            .as_str()
            .unwrap()
            .contains("'since' must be before 'until'")
    );

    meter_task.abort();
    shutdown_token.cancel();
}

// 7. status reports both domains; cert.status carries validation + wildcard.
#[tokio::test]
async fn test_status_and_cert_status_report_admin_and_cert_metadata() {
    use std::sync::Arc;
    use std::time::Instant;
    use tokio_util::sync::CancellationToken;
    use weaver_server::cert::{CertManager, CertResolver, SystemClock};

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("meta.db");
    let control_sock_path = dir.path().join("control.sock");

    let store = Arc::new(Store::open(&db_path).await.unwrap());
    let config = Arc::new(create_valid_test_config(0, 0, control_sock_path.clone()));
    store.save_config(&config).await.unwrap();

    let now = now_secs();
    store
        .save_certificate(
            "weaver.test",
            weaver_server::store::NewCertificate {
                cert_pem: "WILDCARD-CERT".into(),
                key_pem: "WILDCARD-KEY".into(),
                not_before: now - 60,
                not_after: now + 86_400,
                issuer: None,
                directory: "letsencrypt-staging".into(),
                obtained_at: now - 60,
                validation: "dns-01".into(),
            },
        )
        .await
        .unwrap();
    store
        .save_certificate(
            "relay-admin.test",
            weaver_server::store::NewCertificate {
                cert_pem: "ADMIN-CERT".into(),
                key_pem: "ADMIN-KEY".into(),
                not_before: now - 60,
                not_after: now + 86_400,
                issuer: None,
                directory: "letsencrypt-staging".into(),
                obtained_at: now - 60,
                validation: "http-01".into(),
            },
        )
        .await
        .unwrap();

    let resolver = Arc::new(CertResolver::new(config.tunnel_domain.clone()));
    let cert_manager = CertManager::new(
        Arc::clone(&config),
        Arc::clone(&store),
        resolver,
        Arc::new(SystemClock),
    );

    let shutdown_token = CancellationToken::new();
    let listener =
        weaver_server::control::server::bind_control_listener(&control_sock_path).unwrap();
    let srv_token = shutdown_token.clone();
    let srv_sock = control_sock_path.clone();
    let srv_cfg = Arc::clone(&config);
    let srv_store = Arc::clone(&store);
    let srv_mgr = Arc::clone(&cert_manager);
    let srv_metering = Arc::new(weaver_server::metering::MeteringManager::new(
        store.as_ref().clone(),
        Duration::from_secs(60),
    ));
    tokio::spawn(async move {
        let _ = weaver_server::control::server::run_control_server_with_listener(
            listener,
            srv_sock,
            srv_cfg,
            srv_store,
            srv_mgr,
            srv_metering,
            Instant::now(),
            srv_token,
        )
        .await;
    });

    // `status` names both managed domains.
    let status = control_roundtrip(
        &control_sock_path,
        serde_json::json!({"v": 1, "cmd": "status"}),
    )
    .await;
    assert_eq!(status["tunnel_domain"], "weaver.test");
    assert_eq!(status["admin_domain"], "relay-admin.test");

    // `cert.status` list carries validation + wildcard for both rows.
    let list = control_roundtrip(
        &control_sock_path,
        serde_json::json!({"v": 1, "cmd": "cert.status"}),
    )
    .await;
    let certs = list["certificates"].as_array().unwrap();
    let root = certs
        .iter()
        .find(|c| c["name"] == "weaver.test")
        .expect("tunnel row");
    assert_eq!(root["validation"], "dns-01");
    let admin = certs
        .iter()
        .find(|c| c["name"] == "relay-admin.test")
        .expect("admin row");
    assert_eq!(admin["validation"], "http-01");

    // Detail view for the admin name reports its mechanism and kind.
    let detail = control_roundtrip(
        &control_sock_path,
        serde_json::json!({"v": 1, "cmd": "cert.status", "name": "relay-admin.test"}),
    )
    .await;
    assert_eq!(detail["ok"], true);
    assert_eq!(detail["validation"], "http-01");

    shutdown_token.cancel();
}

// 8. `doctor` round-trips a full report over the socket and through the CLI.
#[tokio::test]
async fn test_doctor_control_verb_and_cli() {
    use std::sync::Arc;
    use std::time::Instant;
    use tokio_util::sync::CancellationToken;
    use weaver_server::cert::{CertManager, CertResolver, SystemClock};

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("doctor.db");
    let control_sock_path = dir.path().join("control.sock");

    let store = Arc::new(Store::open(&db_path).await.unwrap());
    let config = Arc::new(create_valid_test_config(0, 0, control_sock_path.clone()));
    store.save_config(&config).await.unwrap();

    // Seed the tunnel wildcard so the daemon's certificate-health check has a
    // real record to describe.
    let now = now_secs();
    store
        .save_certificate(
            "weaver.test",
            weaver_server::store::NewCertificate {
                cert_pem: "WILDCARD-CERT".into(),
                key_pem: "WILDCARD-KEY".into(),
                not_before: now - 60,
                not_after: now + 86_400,
                issuer: None,
                directory: "letsencrypt-staging".into(),
                obtained_at: now - 60,
                validation: "dns-01".into(),
            },
        )
        .await
        .unwrap();

    let resolver = Arc::new(CertResolver::new(config.tunnel_domain.clone()));
    let cert_manager = CertManager::new(
        Arc::clone(&config),
        Arc::clone(&store),
        resolver,
        Arc::new(SystemClock),
    );

    let shutdown_token = CancellationToken::new();
    let listener =
        weaver_server::control::server::bind_control_listener(&control_sock_path).unwrap();
    let srv_token = shutdown_token.clone();
    let srv_sock = control_sock_path.clone();
    let srv_cfg = Arc::clone(&config);
    let srv_store = Arc::clone(&store);
    let srv_mgr = Arc::clone(&cert_manager);
    let srv_metering = Arc::new(weaver_server::metering::MeteringManager::new(
        store.as_ref().clone(),
        Duration::from_secs(60),
    ));
    tokio::spawn(async move {
        let _ = weaver_server::control::server::run_control_server_with_listener(
            listener,
            srv_sock,
            srv_cfg,
            srv_store,
            srv_mgr,
            srv_metering,
            Instant::now(),
            srv_token,
        )
        .await;
    });

    // Raw verb: the response is the serialized report, with per-port checks as
    // ordinary checklist items and a certificate check per managed name.
    let report = control_roundtrip(
        &control_sock_path,
        serde_json::json!({"v": 1, "cmd": "doctor"}),
    )
    .await;
    assert_eq!(report["tunnel_domain"], "weaver.test");
    assert_eq!(report["admin_domain"], "relay-admin.test");
    let titles: Vec<&str> = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["title"].as_str().unwrap())
        .collect();
    for expected in [
        "Domain split",
        "Admin addresses",
        "Delegation",
        "Certificate weaver.test",
        "Certificate relay-admin.test",
        "Port 80",
        "Port 443",
        "Port 53",
    ] {
        assert!(titles.contains(&expected), "missing check: {expected}");
    }
    // The seeded wildcard reports its mechanism and kind.
    let root_cert = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["title"] == "Certificate weaver.test")
        .unwrap();
    assert!(root_cert["detail"].as_str().unwrap().contains("dns-01"));
    assert!(root_cert["detail"].as_str().unwrap().contains("wildcard"));
    // No relay IPs are stored, so the port checks fail.
    let port_80 = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["title"] == "Port 80")
        .unwrap();
    assert_eq!(port_80["ok"], false);

    // CLI path: it detects the live relay and prints the report, exiting
    // nonzero because the port checks cannot pass without stored relay IPs.
    // Run the blocking child on a separate thread so the in-process server
    // task keeps making progress on the async runtime.
    let cli_sock = control_sock_path.clone();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_weaver-server"))
            .arg("--socket")
            .arg(&cli_sock)
            .arg("doctor")
            .arg("--json")
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let val: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(val["ok"], false);
    assert_eq!(val["tunnel_domain"], "weaver.test");

    // Human path prints the rendered checklist.
    let cli_sock = control_sock_path.clone();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_weaver-server"))
            .arg("--socket")
            .arg(&cli_sock)
            .arg("doctor")
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Weaver Server Doctor"));
    assert!(stdout.contains("Port 80"));

    shutdown_token.cancel();
}
