use std::net::{SocketAddr, TcpListener};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::CommandExt;
use std::process::Command;

use tempfile::tempdir;
use weaver_server::{Config, Store};

fn create_valid_test_config(http_port: u16, https_port: u16) -> Config {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let sock = std::env::temp_dir().join(format!(
        "weaver-test-ctrl-{}-{}.sock",
        std::process::id(),
        id
    ));
    Config {
        root_domain: "weaver.test".to_string(),
        admin_email: "admin@weaver.test".to_string(),
        acme_provider: "letsencrypt-staging".to_string(),
        listen_http: SocketAddr::from(([127, 0, 0, 1], http_port)),
        listen_https: SocketAddr::from(([127, 0, 0, 1], https_port)),
        control_socket: sock,
        acme_directory: None,
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: None,
        acme_fallback_providers: Vec::new(),
    }
}

/// Opens the store at `path`, runs `f` against it, and closes it before
/// returning so a subprocess can take over the database file.
fn seed_db<F, Fut>(path: &std::path::Path, f: F)
where
    F: FnOnce(Store) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let store = Store::open(path).await.unwrap();
        f(store.clone()).await;
        store.close().await.unwrap();
    });
}

// OFF-70: Server startup aborts immediately with exit code 78 and lists missing keys when database is unconfigured.
#[test]
fn test_startup_unconfigured_db_exits_78() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("unconfigured.db");

    // Open store to create DB schema, but leave config table empty
    seed_db(&db_path, |_| async {});

    let bin_path = env!("CARGO_BIN_EXE_weaver-server");
    let output = Command::new(bin_path)
        .arg("--db")
        .arg(&db_path)
        .arg("run")
        .output()
        .expect("failed to execute weaver-server run");

    assert_eq!(output.status.code(), Some(78));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Configuration missing required keys"));
    assert!(stderr.contains("root_domain"));
    assert!(stderr.contains("admin_email"));
    assert!(stderr.contains("listen_http"));
    assert!(stderr.contains("listen_https"));
}

// OFF-70: Server startup aborts immediately with exit code 1 when either listen address is already in use.
#[test]
fn test_startup_address_in_use_exits_1() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    // Pre-bind a listener to reserve a port
    let conflicting_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let conflicting_port = conflicting_listener.local_addr().unwrap().port();

    let free_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let free_port = free_listener.local_addr().unwrap().port();
    drop(free_listener);

    let config = create_valid_test_config(conflicting_port, free_port);
    seed_db(&db_path, |store| async move {
        store.save_config(&config).await.unwrap();
    });

    let bin_path = env!("CARGO_BIN_EXE_weaver-server");
    let output = Command::new(bin_path)
        .arg("--db")
        .arg(&db_path)
        .arg("run")
        .output()
        .expect("failed to execute weaver-server run");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(&format!("127.0.0.1:{conflicting_port}")));
}

#[test]
fn test_startup_validation_failure_exits_78() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("invalid.db");

    let mut config = create_valid_test_config(8080, 8443);
    config.admin_email = "not-an-email".to_string();
    // save_config does not validate; validation happens on load at startup
    seed_db(&db_path, |store| async move {
        store.save_config(&config).await.unwrap();
    });

    let bin_path = env!("CARGO_BIN_EXE_weaver-server");
    let output = Command::new(bin_path)
        .arg("--db")
        .arg(&db_path)
        .arg("run")
        .output()
        .expect("failed to execute weaver-server run");

    assert_eq!(output.status.code(), Some(78));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Configuration validation failed"));
    assert!(stderr.contains("not-an-email"));
}

#[test]
fn test_startup_listen_fds_invalid_count_exits_1() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let config = create_valid_test_config(8080, 8443);
    seed_db(&db_path, |store| async move {
        store.save_config(&config).await.unwrap();
    });

    let bin_path = env!("CARGO_BIN_EXE_weaver-server");
    let output = Command::new(bin_path)
        .arg("--db")
        .arg(&db_path)
        .arg("run")
        .env("LISTEN_FDS", "1")
        .output()
        .expect("failed to execute weaver-server run");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Expected exactly 2 sockets in LISTEN_FDS"));
}

#[test]
fn test_startup_listen_fds_and_systemd_notify_and_shutdown() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let notify_sock_path = dir.path().join("notify.sock");
    let notify_listener = UnixDatagram::bind(&notify_sock_path).unwrap();

    let s1 = TcpListener::bind("127.0.0.1:0").unwrap();
    let s2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let http_port = s1.local_addr().unwrap().port();
    let https_port = s2.local_addr().unwrap().port();

    let config = create_valid_test_config(http_port, https_port);
    seed_db(&db_path, |store| async move {
        store.save_config(&config).await.unwrap();
    });

    let fd1 = s1.as_raw_fd();
    let fd2 = s2.as_raw_fd();

    let bin_path = env!("CARGO_BIN_EXE_weaver-server");
    let mut cmd = Command::new(bin_path);
    cmd.arg("--db")
        .arg(&db_path)
        .arg("run")
        .env("LISTEN_FDS", "2")
        .env("NOTIFY_SOCKET", &notify_sock_path);

    unsafe {
        cmd.pre_exec(move || {
            let r1 = libc::dup2(fd1, 3);
            if r1 < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let r2 = libc::dup2(fd2, 4);
            if r2 < 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::fcntl(3, libc::F_SETFD, 0);
            libc::fcntl(4, libc::F_SETFD, 0);
            Ok(())
        });
    }

    let mut child = cmd.spawn().expect("failed to spawn weaver-server");

    // Check systemd notification
    let mut buf = [0u8; 512];
    notify_listener
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let len = notify_listener
        .recv(&mut buf)
        .expect("failed to receive READY notification");
    let msg = std::str::from_utf8(&buf[..len]).unwrap();
    assert!(msg.contains("READY=1"));
    assert!(msg.contains("STATUS=listening; certificate: pending"));

    // OFF-70: Happy path — verify server actively serves traffic using inherited LISTEN_FDS
    // before initiating shutdown.
    {
        use std::io::{Read, Write};
        let mut stream = std::net::TcpStream::connect(format!("127.0.0.1:{http_port}")).unwrap();
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 308"));
        assert!(resp.contains(&format!(
            "location: https://weaver.test:{https_port}/healthz"
        )));
    }

    // Send SIGTERM to initiate graceful shutdown
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }

    // Verify STOPPING=1 notification
    let mut saw_stopping = false;
    while let Ok(len) = notify_listener.recv(&mut buf) {
        let msg = std::str::from_utf8(&buf[..len]).unwrap();
        if msg.contains("STOPPING=1") {
            saw_stopping = true;
            break;
        }
    }
    assert!(saw_stopping);

    // Wait for clean exit
    let status = child.wait().expect("failed to wait for child");
    assert!(status.success());
}
