//! A runnable end-to-end harness for the account plane and pairing.
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

use std::collections::HashMap;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;
use weaver_mux::KeyId;
use weaver_proto::pair::{ServerMessage, Target};

use weaver_server::account::AccountRuntime;
use weaver_server::account::pairing;
use weaver_server::account::password::BreachCheck;
use weaver_server::altcha::AltchaRuntime;
use weaver_server::cert::managed::ManagedCerts;
use weaver_server::config::{AccountConfig, BudgetConfig, Config};
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
/// dialled down so a browser-driven signup stays snappy, and the per-network
/// abuse budgets are widened for the same reason — a suite is many clients on
/// one address, so the production burst would throttle the run rather than the
/// abuse it is meant to stop.
fn account_config(base_url: String) -> AccountConfig {
    let generous = || BudgetConfig {
        burst: 100_000,
        refill_units: 100_000,
        refill_per_secs: 1,
    };
    AccountConfig {
        base_url: Some(base_url),
        argon2_memory_kib: 8,
        argon2_iterations: 1,
        argon2_parallelism: 1,
        signup: generous(),
        login: generous(),
        resend: generous(),
        pair: generous(),
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

/// Everything the harness's plain-HTTP side needs: the captured mail, the
/// account runtime (to seed a pending pairing) and what each seeded "CLI" was
/// told.
#[derive(Clone)]
struct HarnessState {
    sent: Captured,
    account: Arc<AccountRuntime>,
    https_port: u16,
    outcomes: Outcomes,
}

/// The outcome each seeded pairing's stand-in CLI received, by handle.
type Outcomes = Arc<Mutex<HashMap<String, ServerMessage>>>;

/// `GET /messages` — the captured messages, newest last.
async fn list_messages(State(state): State<HarnessState>) -> Json<Vec<CapturedMessage>> {
    let messages = state.sent.lock().unwrap().clone();
    Json(messages)
}

/// `DELETE /messages` — drop everything captured so far.
async fn clear_messages(State(state): State<HarnessState>) -> StatusCode {
    state.sent.lock().unwrap().clear();
    StatusCode::NO_CONTENT
}

/// Query for [`seed_pairing`]: at most one of `machine` / `machine_id`.
#[derive(Deserialize)]
struct SeedQuery {
    /// The hostname of a new machine (the default target, `laptop`).
    machine: Option<String>,
    /// An existing machine the key is for.
    machine_id: Option<i32>,
    /// Which fabricated key to seed with. A real `weave pair` run mints a fresh
    /// key per machine, so varying this keeps two seeded scenarios from colliding
    /// on the unique `machine.key_id` once the first approves.
    key: Option<u8>,
}

/// The handle and fingerprint of a freshly seeded pending pairing.
#[derive(Serialize)]
struct SeededPairing {
    handle: String,
    fingerprint: String,
}

/// `POST /pair/seed?machine=<hostname>` or `POST /pair/seed?machine_id=<id>`
/// [`&key=<u8>`] — seed a pending pairing.
///
/// The browser half of pairing is exercised without a CLI, a key agent or a
/// proof of work: the scenario seeds a pending pairing, opens the link, and
/// reads what the stand-in CLI was told from `/pair/outcome`.
async fn seed_pairing(
    State(state): State<HarnessState>,
    Query(query): Query<SeedQuery>,
) -> Result<Json<SeededPairing>, (StatusCode, &'static str)> {
    let target = match (query.machine, query.machine_id) {
        (Some(_), Some(_)) => {
            return Err((
                StatusCode::BAD_REQUEST,
                "pass either machine or machine_id, not both",
            ));
        }
        (None, Some(machine_id)) => Target::Existing { machine_id },
        (hostname, None) => Target::New {
            hostname: hostname.unwrap_or_else(|| "laptop".to_string()),
        },
    };
    let key_id = KeyId::P256([query.key.unwrap_or(0x02); 33]);
    let (handle, receiver) = state.account.pairings.register(key_id, target);
    let outcomes = Arc::clone(&state.outcomes);
    let recorded = handle.clone();
    tokio::spawn(async move {
        if let Ok(outcome) = receiver.await {
            outcomes.lock().unwrap().insert(recorded, outcome);
        }
    });
    Ok(Json(SeededPairing {
        handle,
        fingerprint: pairing::fingerprint(&key_id),
    }))
}

/// Query for [`pair_outcome`] and [`pair_link`].
#[derive(Deserialize)]
struct HandleQuery {
    handle: String,
}

/// `GET /pair/outcome?handle=<hex>` — the `ServerMessage` the seeded pairing's
/// CLI received (`Approved` or `Failed`), or `{"state":"pending"}` while none.
async fn pair_outcome(
    State(state): State<HarnessState>,
    Query(query): Query<HandleQuery>,
) -> Json<serde_json::Value> {
    let outcome = state.outcomes.lock().unwrap().get(&query.handle).cloned();
    Json(match outcome {
        Some(message) => serde_json::to_value(message).expect("server message is JSON"),
        None => serde_json::json!({ "state": "pending" }),
    })
}

/// `GET /health` — liveness for the test runner.
async fn health() -> &'static str {
    "ok"
}

/// The URL the CLI prints for a handle.
#[derive(Serialize)]
struct PairLink {
    url: String,
}

/// `GET /pair/link?handle=<hex>` — the link the CLI prints for that handle.
///
/// Built by the product's own [`weave::pair::pairing_url`], so a scenario opens
/// exactly the URL the terminal prints. If the CLI's link format and the
/// `/pair` page's fragment parser ever drift apart, the browser test fails —
/// where a scenario that hand-built the fragment would have passed while the
/// product was broken.
async fn pair_link(
    State(state): State<HarnessState>,
    Query(query): Query<HandleQuery>,
) -> Json<PairLink> {
    let admin_host = format!("localhost:{}", state.https_port);
    Json(PairLink {
        url: weave::pair::pairing_url(&admin_host, &query.handle),
    })
}

/// Starts the capture-mail endpoint on `127.0.0.1:0`, returning its address.
async fn serve_mail(sent: Captured, account: Arc<AccountRuntime>, https_port: u16) -> SocketAddr {
    let app = Router::new()
        .route("/messages", get(list_messages).delete(clear_messages))
        .route("/pair/seed", post(seed_pairing))
        .route("/pair/link", get(pair_link))
        .route("/pair/outcome", get(pair_outcome))
        .route("/health", get(health))
        .with_state(HarnessState {
            sent,
            account,
            https_port,
            outcomes: Arc::default(),
        });
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
        account: Some(Arc::clone(&account)),
    };
    let shutdown = CancellationToken::new();
    tokio::spawn(run_https_server_full(
        https_listener,
        server_tls,
        edge,
        shutdown.clone(),
    ));

    let mail_addr = serve_mail(Arc::clone(&sent), account, https_port).await;

    // The two lines a test runner reads. Flushed immediately so a reader can
    // poll the pipe rather than guess when the servers are up.
    println!("E2E_BASE_URL=https://localhost:{https_port}");
    println!("E2E_MAIL_URL=http://127.0.0.1:{}", mail_addr.port());
    std::io::stdout().flush().expect("flush stdout");

    wait_for_shutdown().await;
    shutdown.cancel();
}
