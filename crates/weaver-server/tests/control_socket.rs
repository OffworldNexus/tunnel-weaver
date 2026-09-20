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
        root_domain: "weaver.test".to_string(),
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

    // Generate valid self-signed certificates using rcgen
    let root_rcgen = rcgen::generate_simple_self_signed(vec!["weaver.test".to_string()]).unwrap();
    let root_cert_pem = root_rcgen.cert.pem();
    let root_key_pem = root_rcgen.signing_key.serialize_pem();

    let tunnel_rcgen =
        rcgen::generate_simple_self_signed(vec!["tunnel-active.weaver.test".to_string()]).unwrap();
    let tunnel_cert_pem = tunnel_rcgen.cert.pem();
    let tunnel_key_pem = tunnel_rcgen.signing_key.serialize_pem();

    let inactive_rcgen =
        rcgen::generate_simple_self_signed(vec!["tunnel-inactive.weaver.test".to_string()])
            .unwrap();
    let inactive_cert_pem = inactive_rcgen.cert.pem();
    let inactive_key_pem = inactive_rcgen.signing_key.serialize_pem();

    // Seed certificates table with root domain, an active tunnel, and an inactive tunnel
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let seed_cert = |name: &str, cert_pem: &str, key_pem: &str, days: i64, active: bool| {
        weaver_server::store::entity::certificate::Model {
            name: name.to_string(),
            cert_pem: cert_pem.to_string(),
            key_pem: key_pem.to_string(),
            not_before: now - 3600,
            not_after: now + 86400 * days,
            issuer: Some("Test Issuer".to_string()),
            directory: "letsencrypt-staging".to_string(),
            obtained_at: now - 3600,
            last_active_at: active.then_some(now - 3600),
        }
    };
    store
        .upsert_certificate(seed_cert(
            "weaver.test",
            &root_cert_pem,
            &root_key_pem,
            90,
            true,
        ))
        .await
        .unwrap();
    store
        .upsert_certificate(seed_cert(
            "tunnel-active.weaver.test",
            &tunnel_cert_pem,
            &tunnel_key_pem,
            60,
            true,
        ))
        .await
        .unwrap();
    store
        .upsert_certificate(seed_cert(
            "tunnel-inactive.weaver.test",
            &inactive_cert_pem,
            &inactive_key_pem,
            30,
            false,
        ))
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
    store
        .record_cert_event(
            "tunnel-active.weaver.test",
            now - 3600,
            "issued",
            Some("Issued for tunnel"),
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
        assert_eq!(val["root_domain"], "weaver.test");
        assert_eq!(val["schema_version"], 1);
        assert_eq!(val["cert_counts"]["issued"], 2); // root + active
        assert_eq!(val["cert_counts"]["inactive"], 1); // inactive
        assert_eq!(val["cert_counts"]["ordering"], 0);
        assert_eq!(val["cert_counts"]["failed"], 0);
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
        assert!(stdout.contains("weaver.test"));
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
        assert_eq!(certs.len(), 3);
        // Root domain is strictly first!
        assert_eq!(certs[0]["name"], "weaver.test");
        assert_eq!(certs[0]["active"], true);
        // Remaining names sorted alphabetically
        assert_eq!(certs[1]["name"], "tunnel-active.weaver.test");
        assert_eq!(certs[2]["name"], "tunnel-inactive.weaver.test");
        assert_eq!(certs[2]["active"], false);
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
        assert!(stdout.contains("weaver.test"));
        assert!(stdout.contains("★")); // Highlighted root!
        assert!(stdout.contains("tunnel-active.weaver.test"));
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
        assert_eq!(val["cert_events"].as_array().unwrap().len(), 1);
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

    // --- Test CLI: cert renew --all skips inactive ---
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
        assert!(renewed.iter().any(|n| n == "weaver.test"));
        assert!(renewed.iter().any(|n| n == "tunnel-active.weaver.test"));
        assert!(skipped.iter().any(|n| n == "tunnel-inactive.weaver.test"));
    }

    // --- Test CLI: cert renew explicit inactive hostname is permitted ---
    {
        let output = Command::new(bin_path)
            .arg("--socket")
            .arg(&control_sock_path)
            .arg("cert")
            .arg("renew")
            .arg("tunnel-inactive.weaver.test")
            .arg("--json")
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(0));
        let val: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(val["ok"], true);
        assert_eq!(val["renewed"][0], "tunnel-inactive.weaver.test");
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
    use weaver_server::cert::{
        CertManager, CertResolver, CertState, ChallengeRegistry, SystemClock,
    };

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let control_sock_path = dir.path().join("control.sock");

    let store = Arc::new(Store::open(&db_path).await.unwrap());
    let config = Arc::new(Config {
        root_domain: "weaver.test".to_string(),
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
    });
    store.save_config(&config).await.unwrap();

    let challenge_registry = Arc::new(ChallengeRegistry::new());
    let resolver = Arc::new(CertResolver::new(
        config.root_domain.clone(),
        Arc::clone(&challenge_registry),
    ));

    let cert_manager = CertManager::new(
        Arc::clone(&config),
        Arc::clone(&store),
        Arc::clone(&resolver),
        Arc::clone(&challenge_registry),
        Arc::new(SystemClock),
        true,
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
    tokio::spawn(async move {
        let _ = weaver_server::control::server::run_control_server_with_listener(
            listener,
            srv_sock,
            srv_cfg,
            srv_store,
            srv_mgr,
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
