//! A runnable end-to-end harness for the account lifecycle (WVR-36).
//!
//! This example boots the *real* account stack — the real SQLite `Store`, the
//! real ALTCHA runtime, the real HTTPS edge — against a temporary database and a
//! self-signed certificate, and exposes the captured transactional emails over a
//! small plain-HTTP endpoint. A browser driver (Playwright via Cucumber) can
//! then exercise signup → emailed verification link → password → login against
//! the same code the daemon runs, with no mocking of the account plane itself.
//!
//! Run it with:
//!
//! ```text
//! cargo run -p weaver-server --example e2e_server
//! ```
//!
//! It prints two lines to stdout (and nothing else) for a test runner to pick
//! up, then serves until SIGINT/SIGTERM:
//!
//! ```text
//! E2E_BASE_URL=https://localhost:<https-port>
//! E2E_MAIL_URL=http://127.0.0.1:<mail-port>
//! ```
//!
//! The base URL is `localhost` (not `127.0.0.1`) on purpose: the edge routes on
//! the TLS SNI and `Host` header and refuses IP-literal hosts with `421`, and
//! the account plane's same-origin check compares the browser `Origin` against
//! `https://localhost:<port>`. The certificate carries both `localhost` (DNS)
//! and `127.0.0.1` (IP) SANs. Logs go to stderr; `curl -k` (or Playwright with
//! `ignoreHTTPSErrors`) accepts the self-signed certificate.

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;

use weaver_server::account::AccountRuntime;
use weaver_server::account::password::BreachCheck;
use weaver_server::altcha::AltchaRuntime;
use weaver_server::cert::managed::ManagedCerts;
use weaver_server::config::{AccountConfig, Config};
use weaver_server::edge::https::{HttpsEdgeConfig, run_https_server_full};
use weaver_server::edge::tls::create_self_signed_server_config_for;
use weaver_server::email::{Email, Mailbox, Mailer, MailerError, MailerIdentity, SendReceipt};
use weaver_server::{Store, abuse};

/// A breach checker that never flags anything: the harness must not depend on
/// network access to the Have I Been Pwned range API.
struct NoBreach;

#[async_trait]
impl BreachCheck for NoBreach {
    async fn is_breached(&self, _password: &str) -> Result<bool, String> {
        Ok(false)
    }
}

/// One captured outbound email, shaped for the test runner's JSON.
#[derive(Clone, Serialize)]
struct CapturedMessage {
    subject: String,
    text: String,
    html: String,
}

/// The shared capture buffer: filled by the mailer, drained by the HTTP endpoint.
type Captured = Arc<Mutex<Vec<CapturedMessage>>>;

/// A mailer that records every message instead of sending it.
struct CaptureMailer {
    identity: MailerIdentity,
    sent: Captured,
}

#[async_trait]
impl Mailer for CaptureMailer {
    fn identity(&self) -> &MailerIdentity {
        &self.identity
    }

    async fn send(&self, email: &Email) -> Result<SendReceipt, MailerError> {
        self.sent.lock().unwrap().push(CapturedMessage {
            subject: email.subject.clone(),
            text: email.text.clone(),
            html: email.html.clone(),
        });
        Ok(SendReceipt { message_id: None })
    }
}

/// The account-plane config the harness runs with.
///
/// `base_url` must carry the real HTTPS port: it doubles as the browser
/// `Origin` the account plane checks on every state-changing request. Argon2 is
/// dialled down so a browser-driven signup stays snappy.
fn account_config(base_url: String) -> AccountConfig {
    AccountConfig {
        base_url: Some(base_url),
        argon2_memory_kib: 8,
        argon2_iterations: 1,
        argon2_parallelism: 1,
        ..AccountConfig::default()
    }
}

/// The store config, valid for `localhost`, persisted then reloaded so the
/// harness exercises `Config::load` exactly as the daemon does.
fn sample_config(https_port: u16) -> Config {
    Config {
        tunnel_domain: "weaver.test".into(),
        admin_domain: "localhost".into(),
        admin_email: "admin@weaver.test".into(),
        acme_provider: "letsencrypt-staging".into(),
        // Unused: the harness binds both listeners explicitly. Present because
        // `Config::load` requires them.
        listen_http: SocketAddr::from(([127, 0, 0, 1], 0)),
        listen_https: SocketAddr::from(([127, 0, 0, 1], 0)),
        control_socket: PathBuf::from("e2e-server.sock"),
        acme_directory: None,
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: None,
        acme_fallback_providers: Vec::new(),
        usage_flush_interval_secs: 60,
        relay_ips: Vec::new(),
        setup_complete: false,
        email: None,
        abuse: None,
        account: account_config(format!("https://localhost:{https_port}")),
    }
}

// ----- mail endpoint --------------------------------------------------------

/// `GET /messages` — the captured messages, newest last.
async fn list_messages(State(sent): State<Captured>) -> Json<Vec<CapturedMessage>> {
    let messages = sent.lock().unwrap().clone();
    Json(messages)
}

/// `DELETE /messages` — drop everything captured so far.
async fn clear_messages(State(sent): State<Captured>) -> StatusCode {
    sent.lock().unwrap().clear();
    StatusCode::NO_CONTENT
}

/// `GET /health` — liveness for the test runner.
async fn health() -> &'static str {
    "ok"
}

/// Starts the capture-mail endpoint on `127.0.0.1:0`, returning its address.
async fn serve_mail(sent: Captured) -> SocketAddr {
    let app = Router::new()
        .route("/messages", get(list_messages).delete(clear_messages))
        .route("/health", get(health))
        .with_state(sent);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mail");
    let addr = listener.local_addr().expect("mail addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("mail server");
    });
    addr
}

// ----- lifecycle ------------------------------------------------------------

/// Waits for SIGINT or SIGTERM.
async fn wait_for_shutdown() {
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[tokio::main]
async fn main() {
    // Logs never touch stdout: stdout carries only the two URL lines.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .try_init();

    // A temporary SQLite store, dropped with the process.
    let dir = tempfile::tempdir().expect("temp dir");
    let store = Store::open(dir.path().join("e2e.db"))
        .await
        .expect("open store");

    // Bind the HTTPS listener first so the account base URL can carry its port.
    let https_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind https");
    let https_port = https_listener.local_addr().expect("https addr").port();

    // Persist and reload the config, exactly as the daemon does.
    let config = sample_config(https_port);
    store.save_config(&config).await.expect("save config");
    let config = Config::load(&store).await.expect("load config");

    // The account stack: real ALTCHA runtime, capture mailer, no-op breach check.
    let altcha = AltchaRuntime::from_config(&config, store.clone()).expect("altcha runtime");
    altcha.ensure_demo_client().await.expect("demo client");

    let sent: Captured = Arc::new(Mutex::new(Vec::new()));
    let mailer: Arc<dyn Mailer> = Arc::new(CaptureMailer {
        identity: MailerIdentity::new(
            "capture",
            "Capture",
            Mailbox::new("no-reply@localhost"),
            "https://localhost",
            Vec::new(),
        )
        .expect("mailer identity"),
        sent: Arc::clone(&sent),
    });

    let account = AccountRuntime::with_breach(
        &config.account,
        &config.admin_domain,
        store.clone(),
        Arc::clone(&altcha),
        Some(mailer),
        Arc::new(NoBreach),
    )
    .expect("account runtime");

    // The HTTPS edge, with a self-signed certificate for localhost/127.0.0.1.
    let server_tls = create_self_signed_server_config_for(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])
    .expect("server tls");
    let edge = HttpsEdgeConfig {
        managed: Arc::new(ManagedCerts::from_config(&config)),
        cert_resolver: None,
        cert_manager: None,
        tunnel_registry: None,
        guard: abuse::build(&config, store.clone()),
        altcha: Some(altcha),
        account: Some(account),
    };
    let shutdown = CancellationToken::new();
    tokio::spawn(run_https_server_full(
        https_listener,
        server_tls,
        edge,
        shutdown.clone(),
    ));

    let mail_addr = serve_mail(Arc::clone(&sent)).await;

    // The two lines a test runner reads. Flushed immediately so a reader can
    // poll the pipe rather than guess when the servers are up.
    println!("E2E_BASE_URL=https://localhost:{https_port}");
    println!("E2E_MAIL_URL=http://127.0.0.1:{}", mail_addr.port());
    std::io::stdout().flush().expect("flush stdout");

    wait_for_shutdown().await;
    shutdown.cancel();
}
