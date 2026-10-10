//! Mock-provider integration tests for OFF-193.
//!
//! A local hyper server records every request and returns a canned response,
//! letting the resend transport, `send-a-joke`, and the `configure` two-step
//! OTP flow be exercised without live credentials.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tempfile::TempDir;
use tokio::net::TcpListener;
use weaver_server::config::EmailConfig;
use weaver_server::email::{Joke, Mailbox, MailerError, mailer_from_config};

/// One recorded request.
#[derive(Debug, Clone)]
struct Recorded {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
}

/// Shared mock state.
struct MockState {
    requests: Mutex<Vec<Recorded>>,
    status: u16,
    body: String,
}

impl MockState {
    fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().unwrap().clone()
    }

    fn header(&self, req: &Recorded, name: &str) -> Option<String> {
        req.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }
}

/// Starts the recording mock and returns its address and state.
async fn start_mock(status: u16, body: &str) -> (SocketAddr, Arc<MockState>) {
    let state = Arc::new(MockState {
        requests: Mutex::new(Vec::new()),
        status,
        body: body.to_string(),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shared = state.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let st = shared.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |req: Request<Incoming>| {
                    let st = st.clone();
                    async move {
                        let (parts, body) = req.into_parts();
                        let bytes = body.collect().await.unwrap().to_bytes();
                        let recorded = Recorded {
                            method: parts.method.to_string(),
                            path: parts.uri.path().to_string(),
                            headers: parts
                                .headers
                                .iter()
                                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                                .collect(),
                            body: String::from_utf8_lossy(&bytes).to_string(),
                        };
                        st.requests.lock().unwrap().push(recorded);
                        let response = Response::builder()
                            .status(st.status)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from(st.body.clone())))
                            .unwrap();
                        Ok::<_, Infallible>(response)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });
    (addr, state)
}

/// Waits until at least `count` requests have been recorded.
async fn wait_for(state: &MockState, count: usize) {
    for _ in 0..200 {
        if state.requests().len() >= count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "timed out waiting for {count} requests, saw {}",
        state.requests().len()
    );
}

fn resend_config(endpoint: &str, api_key: &str) -> EmailConfig {
    EmailConfig {
        provider: "resend".into(),
        from: "relay@example.com".into(),
        from_name: Some("Tunnel Weaver".into()),
        api_key: Some(api_key.into()),
        endpoint: Some(endpoint.into()),
        ..Default::default()
    }
}

fn joke() -> Joke {
    Joke {
        line: "Why did the tunnel cross the road?".into(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mock_provider_records_and_returns_message_id() {
    let (addr, state) = start_mock(200, r#"{"id":"mock-1"}"#).await;
    let endpoint = format!("http://{addr}");
    let cfg = resend_config(&endpoint, "sk_test_secret");
    let mailer = mailer_from_config(Some(&cfg), "https://relay.example.org").unwrap();
    let to = Mailbox::parse("dest@example.org", None).unwrap();

    let email = mailer.compose(to, &joke()).unwrap();
    let receipt = mailer.send(&email).await.unwrap();
    assert_eq!(receipt.message_id.as_deref(), Some("mock-1"));

    wait_for(&state, 1).await;
    let req = state.requests().remove(0);
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/emails");
    assert_eq!(
        state.header(&req, "authorization").as_deref(),
        Some("Bearer sk_test_secret")
    );
    let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
    assert_eq!(body["from"], "Tunnel Weaver <relay@example.com>");
    assert_eq!(body["to"][0], "dest@example.org");
    assert_eq!(body["subject"], "A joke from Tunnel Weaver");
    assert!(
        body["html"]
            .as_str()
            .unwrap()
            .contains("Why did the tunnel cross the road?")
    );
    assert!(
        body["text"]
            .as_str()
            .unwrap()
            .contains("https://relay.example.org")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejection_maps_to_typed_error_without_leaking_the_secret() {
    let (addr, _state) =
        start_mock(422, r#"{"message":"invalid api key","code":"auth_error"}"#).await;
    let endpoint = format!("http://{addr}");
    let secret = "sk_live_leaky_123";
    let cfg = resend_config(&endpoint, secret);
    let mailer = mailer_from_config(Some(&cfg), "https://relay.example.org").unwrap();
    let to = Mailbox::parse("dest@example.org", None).unwrap();
    let email = mailer.compose(to, &joke()).unwrap();

    let err = mailer.send(&email).await.expect_err("should reject");
    match &err {
        MailerError::Rejected {
            status,
            provider_code,
            detail,
        } => {
            assert_eq!(*status, Some(422));
            assert_eq!(provider_code.as_deref(), Some("auth_error"));
            assert!(detail.contains("invalid api key"));
            assert!(!detail.contains(secret), "secret leaked: {detail}");
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
    // The rendered error (what a caller prints) is also scrubbed.
    assert!(!err.to_string().contains(secret), "{}", err);
}

fn run_bin(args: &[&str]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_weaver-server");
    std::process::Command::new(bin)
        .args(args)
        .output()
        .expect("run weaver-server")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_a_joke_binary_uses_the_mock_provider() {
    let (addr, state) = start_mock(200, r#"{"id":"joke-1"}"#).await;
    let temp = TempDir::new().unwrap();
    let db = temp.path().join("weaver.db");
    let endpoint = format!("http://{addr}");

    // Seed a valid config with the mock endpoint.
    let store = weaver_server::Store::open(&db).await.unwrap();
    let config = weaver_server::Config {
        tunnel_domain: "example.com".into(),
        admin_domain: "relay.example.net".into(),
        admin_email: "admin@example.com".into(),
        acme_provider: "letsencrypt".into(),
        listen_http: "0.0.0.0:80".parse().unwrap(),
        listen_https: "0.0.0.0:443".parse().unwrap(),
        control_socket: "/run/weaver/control.sock".into(),
        acme_directory: None,
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: None,
        acme_fallback_providers: vec![],
        usage_flush_interval_secs: 60,
        relay_ips: vec![],
        setup_complete: true,
        email: Some(resend_config(&endpoint, "sk_send_joke")),
    };
    store.save_config(&config).await.unwrap();
    store.close().await.unwrap();

    let db_str = db.to_str().unwrap();
    let out = run_bin(&[
        "send-a-joke",
        "dest@example.org",
        "--db",
        db_str,
        "--email-endpoint",
        &endpoint,
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("sent via Resend"), "{stdout}");
    assert!(stdout.contains("id=joke-1"), "{stdout}");

    wait_for(&state, 1).await;
    let req = state.requests().remove(0);
    assert_eq!(req.path, "/emails");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configure_two_step_otp_then_send() {
    let (addr, state) = start_mock(200, r#"{"id":"otp-1"}"#).await;
    let temp = TempDir::new().unwrap();
    let db = temp.path().join("weaver.db");
    let db_str = db.to_str().unwrap();
    let endpoint = format!("http://{addr}");

    // First run: no OTP, so configure issues one and exits nonzero.
    let first = run_bin(&[
        "configure",
        "--db",
        db_str,
        "--tunnel-domain",
        "example.com",
        "--admin-domain",
        "relay.example.net",
        "--email",
        "admin@example.com",
        "--headless",
        "--email-provider",
        "resend",
        "--email-from",
        "relay@example.com",
        "--email-api-key",
        "sk_otp_secret",
        "--email-endpoint",
        &endpoint,
    ]);
    assert!(!first.status.success(), "first run must require the OTP");
    let first_out = String::from_utf8_lossy(&first.stdout);
    assert!(first_out.contains("OTP was sent"), "{first_out}");

    wait_for(&state, 1).await;
    let otp_request = state.requests().remove(0);
    let body: serde_json::Value = serde_json::from_str(&otp_request.body).unwrap();
    let text = body["text"].as_str().unwrap();
    let code: String = text
        .chars()
        .filter(char::is_ascii_digit)
        .collect::<String>()
        .chars()
        .take(6)
        .collect();
    assert_eq!(code.len(), 6, "no 6-digit OTP in {text}");
    // The OTP is multipart: the base MJML layout carries the same code.
    let html = body["html"].as_str().expect("OTP must carry an HTML body");
    assert!(html.contains(&code), "HTML OTP missing code: {html}");
    assert!(html.contains("<html"));
    let wrong_code = if code == "000000" { "111111" } else { "000000" };

    // Wrong code is refused and preserves the pending challenge.
    let wrong = run_bin(&[
        "configure",
        "--db",
        db_str,
        "--tunnel-domain",
        "example.com",
        "--admin-domain",
        "relay.example.net",
        "--email",
        "admin@example.com",
        "--headless",
        "--email-otp",
        wrong_code,
    ]);
    assert!(!wrong.status.success());

    // Correct code completes and persists the email block.
    let second = run_bin(&[
        "configure",
        "--db",
        db_str,
        "--tunnel-domain",
        "example.com",
        "--admin-domain",
        "relay.example.net",
        "--email",
        "admin@example.com",
        "--headless",
        "--email-otp",
        &code,
    ]);
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    let store = weaver_server::Store::open(&db).await.unwrap();
    let loaded = store.load_config().await.unwrap();
    assert_eq!(
        loaded.email.as_ref().map(|e| e.provider.as_str()),
        Some("resend")
    );
    store.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_a_joke_without_email_exits_nonzero() {
    let temp = TempDir::new().unwrap();
    let db = temp.path().join("weaver.db");
    let store = weaver_server::Store::open(&db).await.unwrap();
    let config = weaver_server::Config {
        tunnel_domain: "example.com".into(),
        admin_domain: "relay.example.net".into(),
        admin_email: "admin@example.com".into(),
        acme_provider: "letsencrypt".into(),
        listen_http: "0.0.0.0:80".parse().unwrap(),
        listen_https: "0.0.0.0:443".parse().unwrap(),
        control_socket: "/run/weaver/control.sock".into(),
        acme_directory: None,
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: None,
        acme_fallback_providers: vec![],
        usage_flush_interval_secs: 60,
        relay_ips: vec![],
        setup_complete: true,
        email: None,
    };
    store.save_config(&config).await.unwrap();
    store.close().await.unwrap();

    let out = run_bin(&[
        "send-a-joke",
        "dest@example.org",
        "--db",
        db.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("email is not configured"));
}
