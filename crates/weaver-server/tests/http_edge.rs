use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use weaver_server::edge::http::run_http_server;

#[tokio::test]
async fn test_http_308_redirect_preserves_host_and_path() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown_token = CancellationToken::new();

    let token_clone = shutdown_token.clone();
    let server_task = tokio::spawn(async move {
        run_http_server(listener, "example.com".to_string(), 8443, token_clone).await;
    });

    // Case 1: Standard host, non-443 HTTPS port -> appends :8443
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"GET /foo/bar?query=param HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();

    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 308"));
    assert!(resp.contains("location: https://example.com:8443/foo/bar?query=param"));

    // Case 2: Host has HTTP port -> rewrites port to HTTPS port :8443
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /api/v1 HTTP/1.1\r\nHost: example.com:8080\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 308"));
    assert!(resp.contains("location: https://example.com:8443/api/v1"));

    // Case 3: Loopback / IP literal host -> rewrites to root_domain:8443
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /status HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 308"));
    assert!(resp.contains("location: https://example.com:8443/status"));

    // Case 4: localhost -> rewrites to root_domain:8443
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost:8080\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 308"));
    assert!(resp.contains("location: https://example.com:8443/"));

    shutdown_token.cancel();
    server_task.await.unwrap();
}

#[tokio::test]
async fn test_http_308_redirect_standard_https_port_443() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown_token = CancellationToken::new();

    let token_clone = shutdown_token.clone();
    let server_task = tokio::spawn(async move {
        run_http_server(listener, "weaver.test".to_string(), 443, token_clone).await;
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 308"));
    assert!(resp.contains("location: https://weaver.test/"));

    shutdown_token.cancel();
    server_task.await.unwrap();
}
