//! A runnable end-to-end harness for the account plane and pairing.
//!
//! This example boots the *real* account stack — the real SQLite `Store`, the
//! real ALTCHA runtime, the real HTTPS edge — against a temporary database and a
//! self-signed certificate, and exposes the captured transactional emails over a
//! small plain-HTTP endpoint. A browser driver (Playwright via Cucumber) can
//! then exercise signup → emailed verification code → password → login against
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
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use weaver_mux::KeyId;
use weaver_proto::pair::{ServerMessage, Target};

use weaver_server::account::AccountRuntime;
use weaver_server::account::sso::SsoProviders;
use weaver_server::account::sso::testing::{FakeAssertion, FakeProvider};
use weaver_server::altcha::AltchaRuntime;
use weaver_server::cert::managed::ManagedCerts;
use weaver_server::config::{AccountConfig, BudgetConfig, Config};
use weaver_server::edge::https::{HttpsEdgeConfig, run_https_server_full};
use weaver_server::edge::tls::create_self_signed_server_config_for;
use weaver_server::email::{Email, Mailbox, Mailer, MailerError, MailerIdentity, SendReceipt};
use weaver_server::{Store, abuse};

mod support;

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

/// The config the harness runs with.
///
/// `base_url` must carry the real HTTPS port: it doubles as the browser
/// `Origin` the account plane checks on every state-changing request. The
/// per-network abuse budgets are widened — a suite is many clients on one
/// address, so the production burst would throttle the run rather than the
/// abuse it is meant to stop.
fn sample_config(https_port: u16) -> Config {
    let generous = || BudgetConfig {
        burst: 100_000,
        refill_units: 100_000,
        refill_per_secs: 1,
    };
    let account = AccountConfig {
        // A step-up lasts five minutes in production, which no browser test can
        // wait for. Twelve seconds keeps the `certain` window walkable — and
        // leaves seven seconds of it that the console still *holds* `certain`
        // for, after the relay has already reported the fall (its lead is five),
        // which is the whole point of the lead.
        confirm_window_secs: 12,
        signup: generous(),
        login: generous(),
        resend: generous(),
        pair: generous(),
        ..support::account_config(format!("https://localhost:{https_port}"))
    };
    support::config(
        account,
        "e2e-server.sock",
        Some(weaver_server::config::test_email_config()),
    )
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
    /// The identity provider every SSO scenario signs in through; queued per
    /// scenario through `POST /sso/expect`.
    fake: Arc<FakeProvider>,
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
        fingerprint: key_id.to_string(),
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
async fn serve_mail(
    sent: Captured,
    account: Arc<AccountRuntime>,
    https_port: u16,
    fake: Arc<FakeProvider>,
) -> SocketAddr {
    let app = Router::new()
        .route("/messages", get(list_messages).delete(clear_messages))
        .route("/pair/seed", post(seed_pairing))
        .route("/pair/link", get(pair_link))
        .route("/pair/outcome", get(pair_outcome))
        // The fake identity provider's script: a scenario posts the identity it
        // wants the next provider redirect to assert.
        .route("/sso/expect", post(expect_sso))
        .route("/signup-policy", put(set_signup_policy))
        .route("/account-state", put(set_account_state))
        .route("/health", get(health))
        .with_state(HarnessState {
            sent,
            account,
            https_port,
            outcomes: Arc::default(),
            fake,
        });
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mail");
    let addr = listener.local_addr().expect("mail addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("mail server");
    });
    addr
}

/// `POST /sso/expect` — queues what the fake provider asserts on the next
/// redirect. A scenario posts here before it clicks a provider button.
async fn expect_sso(
    State(state): State<HarnessState>,
    Json(assertion): Json<FakeAssertion>,
) -> StatusCode {
    state.fake.expect(assertion);
    StatusCode::NO_CONTENT
}

/// A ban or an unban, as a scenario states it.
#[derive(Deserialize)]
struct AccountStateBody {
    /// Any of the account's addresses.
    email: String,
    /// `banned` or `active`.
    state: String,
    /// Mandatory for `banned`, ignored otherwise.
    #[serde(default)]
    reason: String,
}

/// `PUT /account-state` — ban or unban an account (WVR-178).
///
/// The CLI is a control-socket client and the suite has no socket, so the
/// harness calls the same `Suspension` handle the daemon's control server
/// does. It passes no tunnel registry: the browser scenarios exercise sessions
/// and sign-in, not tunnels.
async fn set_account_state(
    State(state): State<HarnessState>,
    Json(body): Json<AccountStateBody>,
) -> StatusCode {
    let suspension = weaver_server::account::suspension::Suspension::new(
        state.account.store.clone(),
        state.account.live.clone(),
        None,
    );
    let lookup = weaver_server::email::normalize_address(&body.email);
    let now = weaver_server::wall_clock::unix_secs();
    let result = match body.state.as_str() {
        "banned" if !body.reason.trim().is_empty() => {
            suspension.ban(&lookup, body.reason.trim(), now).await
        }
        "active" => suspension.unban(&lookup, now).await,
        _ => return StatusCode::BAD_REQUEST,
    };
    match result {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::CONFLICT,
    }
}

/// A whole signup policy, as a scenario states it.
#[derive(Deserialize)]
struct SignupPolicyBody {
    /// `allow` or `deny`, applied when no rule matches.
    default: String,
    /// Addresses or domains allowed to sign up, in evaluation order.
    allow: Vec<String>,
}

/// `PUT /signup-policy` — replace the relay's signup policy (WVR-98).
///
/// The refusals this feature adds only exist when a policy does, and the suite
/// has no database or CLI handle. So the harness calls the same store method the
/// setup wizard uses, and a scenario states the policy whole rather than
/// replaying CLI verbs.
async fn set_signup_policy(
    State(state): State<HarnessState>,
    Json(body): Json<SignupPolicyBody>,
) -> StatusCode {
    let mut rules = Vec::new();
    for input in &body.allow {
        match weaver_server::store::signup::RuleValue::infer(input) {
            Ok(value) => rules.push((weaver_server::store::signup::Decision::Allow, value)),
            Err(_) => return StatusCode::BAD_REQUEST,
        }
    }
    let Some(default) = weaver_server::store::signup::Decision::parse(&body.default) else {
        return StatusCode::BAD_REQUEST;
    };
    match state
        .account
        .store
        .signup_policy_replace(default, &rules)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

// ----- lifecycle ------------------------------------------------------------

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

    let fake = Arc::new(FakeProvider::new());
    let mut sso =
        SsoProviders::from_config(&config.account, &format!("https://localhost:{https_port}"))
            .expect("sso registry");
    // The fake stands in for every real provider, so the shared pipeline is
    // exercised without a network or an operator's credentials (WVR-175).
    sso.insert(fake.clone());

    let account = AccountRuntime::with_breach_and_sso(
        &config.account,
        &config.admin_domain,
        store.clone(),
        Arc::clone(&altcha),
        Some(mailer),
        weaver_server::live::LiveHub::new(),
        Arc::new(support::NoBreach),
        Some(sso),
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
        // The harness meters for real: the console's traffic figures come from
        // the same store the tests seed usage rows into.
        metering: Some(Arc::new(weaver_server::metering::MeteringManager::new(
            store.clone(),
            std::time::Duration::from_secs(60),
        ))),
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

    let mail_addr = serve_mail(Arc::clone(&sent), account, https_port, fake).await;

    // The two lines a test runner reads. Flushed immediately so a reader can
    // poll the pipe rather than guess when the servers are up.
    println!("E2E_BASE_URL=https://localhost:{https_port}");
    println!("E2E_MAIL_URL=http://127.0.0.1:{}", mail_addr.port());
    std::io::stdout().flush().expect("flush stdout");

    support::wait_for_shutdown().await;
    shutdown.cancel();
}
