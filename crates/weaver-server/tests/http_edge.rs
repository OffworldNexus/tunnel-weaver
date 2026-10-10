use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use weaver_server::cert::solver::Http01Solver;
use weaver_server::edge::http::run_http_server;
use weaver_server::store::Store;

/// A throwaway store for the redirect tests. The challenge path is not
/// exercised here, so an empty registry is enough.
async fn test_store() -> Arc<Store> {
    let dir = tempfile::tempdir().unwrap().keep();
    Arc::new(Store::open(dir.join("test.db")).await.unwrap())
}

#[tokio::test]
async fn test_http_308_redirect_preserves_host_and_path() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown_token = CancellationToken::new();
    let store = test_store().await;

    let token_clone = shutdown_token.clone();
    let server_task = tokio::spawn(async move {
        run_http_server(
            listener,
            "example.com".to_string(),
            8443,
            vec![Arc::new(Http01Solver::new(store))],
            token_clone,
        )
        .await;
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

    // Case 3: Loopback / IP literal host -> rewrites to tunnel_domain:8443
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /status HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 308"));
    assert!(resp.contains("location: https://example.com:8443/status"));

    // Case 4: localhost -> rewrites to tunnel_domain:8443
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
    let store = test_store().await;

    let token_clone = shutdown_token.clone();
    let server_task = tokio::spawn(async move {
        run_http_server(
            listener,
            "weaver.test".to_string(),
            443,
            vec![Arc::new(Http01Solver::new(store))],
            token_clone,
        )
        .await;
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

// OFF-86: RFC 9112 §3.2 on the cleartext edge too — no redirect is built
// from a missing, duplicated or malformed Host. HTTP/1.0 without Host is
// the one legitimate hostless request and redirects to the root domain.
#[tokio::test]
async fn test_http_400_on_bad_host_but_http10_without_host_redirects() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown_token = CancellationToken::new();
    let store = test_store().await;

    let token_clone = shutdown_token.clone();
    let server_task = tokio::spawn(async move {
        run_http_server(
            listener,
            "weaver.test".to_string(),
            443,
            vec![Arc::new(Http01Solver::new(store))],
            token_clone,
        )
        .await;
    });

    let bad: &[(&str, &[u8])] = &[
        ("missing Host", b"GET / HTTP/1.1\r\n\r\n"),
        (
            "duplicate Host",
            b"GET / HTTP/1.1\r\nHost: weaver.test\r\nHost: weaver.test\r\n\r\n",
        ),
        (
            "comma-joined Host",
            b"GET / HTTP/1.1\r\nHost: weaver.test, evil.example\r\n\r\n",
        ),
    ];
    for (label, raw) in bad {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(raw).await.unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).await.unwrap();
        assert!(
            resp.starts_with("HTTP/1.1 400 Bad Request"),
            "{label}: expected 400, got {resp:?}"
        );
        assert!(!resp.contains("location:"), "{label}: must not redirect");
    }

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(b"GET /x HTTP/1.0\r\n\r\n").await.unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.0 308"), "got {resp:?}");
    assert!(resp.contains("location: https://weaver.test/x"));

    shutdown_token.cancel();
    server_task.await.unwrap();
}

#[tokio::test]
async fn test_http01_challenge_served_on_port_80() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown_token = CancellationToken::new();
    let store = test_store().await;
    store
        .publish_http01("tok-abc", "key-auth-abc", None, 0)
        .await
        .unwrap();

    let store_for_server = Arc::clone(&store);
    let token_clone = shutdown_token.clone();
    let server_task = tokio::spawn(async move {
        run_http_server(
            listener,
            "example.com".to_string(),
            443,
            vec![Arc::new(Http01Solver::new(store_for_server))],
            token_clone,
        )
        .await;
    });

    // A live token returns 200 with the raw key authorization.
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"GET /.well-known/acme-challenge/tok-abc HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 200"), "got {resp:?}");
    assert!(
        resp.ends_with("key-auth-abc"),
        "body missing key auth: {resp:?}"
    );

    // An unknown token is a 404, never a redirect.
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"GET /.well-known/acme-challenge/unknown HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 404"), "got {resp:?}");
    assert!(
        !resp.contains("location:"),
        "challenge miss must not redirect"
    );

    shutdown_token.cancel();
    server_task.await.unwrap();
}

/// Sends a raw cleartext HTTP/1.1 request and returns the full response text.
async fn http_request(addr: std::net::SocketAddr, raw_request: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(raw_request.as_bytes()).await.unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    resp
}

// WVR-134: the cleartext surface refuses the same scanner probes the TLS
// surface does, before the redirect, so port-80 probing is visible in the same
// log stream (scheme=http). ACME HTTP-01 stays exempt; ordinary paths still
// redirect.
#[tokio::test]
async fn test_http_refuses_scanner_probes_and_keeps_acme_and_redirects() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown_token = CancellationToken::new();
    let store = test_store().await;
    store
        .publish_http01("tok-cleartext", "key-auth-cleartext", None, 0)
        .await
        .unwrap();

    let store_for_server = Arc::clone(&store);
    let token_clone = shutdown_token.clone();
    let server_task = tokio::spawn(async move {
        run_http_server(
            listener,
            "weaver.test".to_string(),
            443,
            vec![Arc::new(Http01Solver::new(store_for_server))],
            token_clone,
        )
        .await;
    });

    // A scanner playbook probe is refused on cleartext with the branded 403,
    // the reason header and the shared security headers — and never redirects.
    let resp = http_request(
        addr,
        "GET /.env HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        resp.starts_with("HTTP/1.1 403 Forbidden"),
        "expected 403, got {resp:?}"
    );
    assert!(resp.contains("x-weaver-blocked: dotfile"));
    assert!(resp.contains("content-security-policy:"));
    assert!(
        !resp.contains("location:"),
        "a blocked probe must not redirect"
    );

    // TRACE is refused on cleartext too.
    let resp = http_request(
        addr,
        "TRACE / HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        resp.starts_with("HTTP/1.1 403 Forbidden"),
        "expected 403, got {resp:?}"
    );
    assert!(resp.contains("x-weaver-blocked: trace"));

    // ACME HTTP-01 remains reachable on port 80.
    let resp = http_request(
        addr,
        "GET /.well-known/acme-challenge/tok-cleartext HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200"), "got {resp:?}");
    assert!(resp.ends_with("key-auth-cleartext"));

    // An ordinary path still redirects to HTTPS.
    let resp = http_request(
        addr,
        "GET /foo/bar HTTP/1.1\r\nHost: weaver.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 308"), "got {resp:?}");
    assert!(resp.contains("location: https://weaver.test/foo/bar"));

    shutdown_token.cancel();
    server_task.await.unwrap();
}
