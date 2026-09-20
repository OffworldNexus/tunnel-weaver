use std::net::{SocketAddr, TcpListener};
use std::os::unix::net::UnixDatagram;
use std::process::Command;
use std::time::Duration;

use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
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

// OFF-70: Failure mode — in-flight requests complete cleanly without truncation
// when SIGTERM triggers shutdown within the 10-second drain window.
#[tokio::test]
async fn test_graceful_shutdown_on_sigterm_with_drain() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let notify_sock_path = dir.path().join("notify.sock");
    let notify_listener = UnixDatagram::bind(&notify_sock_path).unwrap();

    let l1 = TcpListener::bind("127.0.0.1:0").unwrap();
    let l2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let http_port = l1.local_addr().unwrap().port();
    let https_port = l2.local_addr().unwrap().port();
    drop(l1);
    drop(l2);

    let store = Store::open(&db_path).await.unwrap();
    let control_sock_path = dir.path().join("control.sock");
    let config = create_valid_test_config(http_port, https_port, control_sock_path);
    store.save_config(&config).await.unwrap();
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
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut saw_ready = false;
    while let Ok(len) = notify_listener.recv(&mut buf) {
        let msg = std::str::from_utf8(&buf[..len]).unwrap();
        if msg.contains("READY=1") {
            saw_ready = true;
            break;
        }
    }
    assert!(saw_ready);

    // Connect and send an in-flight HTTP request
    let mut stream = TcpStream::connect(format!("127.0.0.1:{http_port}"))
        .await
        .unwrap();

    stream
        .write_all(b"GET /test HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    // Allow the server task to accept and start processing the connection before signalling shutdown
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Send SIGTERM to initiate graceful shutdown
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }

    // Verify STOPPING=1 notification sent
    let mut saw_stopping = false;
    while let Ok(len) = notify_listener.recv(&mut buf) {
        let msg = std::str::from_utf8(&buf[..len]).unwrap();
        if msg.contains("STOPPING=1") {
            saw_stopping = true;
            break;
        }
    }
    assert!(saw_stopping);

    // In-flight request finishes cleanly during shutdown
    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 308"));

    // Child should exit with status 0 within the 10-second cap
    let status = child.wait().unwrap();
    assert!(status.success());
}

#[tokio::test]
async fn test_graceful_shutdown_on_sigint() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let notify_sock_path = dir.path().join("notify.sock");
    let notify_listener = UnixDatagram::bind(&notify_sock_path).unwrap();

    let l1 = TcpListener::bind("127.0.0.1:0").unwrap();
    let l2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let http_port = l1.local_addr().unwrap().port();
    let https_port = l2.local_addr().unwrap().port();
    drop(l1);
    drop(l2);

    let store = Store::open(&db_path).await.unwrap();
    let control_sock_path = dir.path().join("control.sock");
    let config = create_valid_test_config(http_port, https_port, control_sock_path);
    store.save_config(&config).await.unwrap();
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
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut saw_ready = false;
    while let Ok(len) = notify_listener.recv(&mut buf) {
        let msg = std::str::from_utf8(&buf[..len]).unwrap();
        if msg.contains("READY=1") {
            saw_ready = true;
            break;
        }
    }
    assert!(saw_ready);

    // Send SIGINT (Ctrl+C)
    unsafe {
        libc::kill(child.id() as i32, libc::SIGINT);
    }

    // Verify STOPPING=1 notification sent
    let mut saw_stopping = false;
    while let Ok(len) = notify_listener.recv(&mut buf) {
        let msg = std::str::from_utf8(&buf[..len]).unwrap();
        if msg.contains("STOPPING=1") {
            saw_stopping = true;
            break;
        }
    }
    assert!(saw_stopping);

    let status = child.wait().unwrap();
    assert!(status.success());
}
