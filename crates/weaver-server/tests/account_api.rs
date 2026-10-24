//! End-to-end tests for the account plane.
//!
//! These drive the account axum router directly (no TLS), exercising the same
//! handlers the hyper edge mounts: signup → email verification → password →
//! login → identity → logout, plus the abuse/enumeration and single-use rules.
//! The ALTCHA proof is solved with the engine's test helper, and the mailer is
//! a capture stub so the verification link can be followed.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use base64::Engine as _;
use tower::ServiceExt as _;

use weaver_abuse::altcha::{Challenge, Payload, solve_challenge};
use weaver_server::account::AccountRuntime;
use weaver_server::account::inactivity;
use weaver_server::account::password::BreachCheck;
use weaver_server::account::router::router;
use weaver_server::altcha::AltchaRuntime;
use weaver_server::config::{AccountConfig, Config};
use weaver_server::email::{Email, Mailbox, Mailer, MailerError, MailerIdentity, SendReceipt};
use weaver_server::store::Store;

/// A breach checker that never flags anything (no network in tests).
struct NoBreach;

#[async_trait]
impl BreachCheck for NoBreach {
    async fn is_breached(&self, _password: &str) -> Result<bool, String> {
        Ok(false)
    }
}

/// A mailer that records what it was asked to send.
struct Capture {
    identity: MailerIdentity,
    sent: Arc<Mutex<Vec<Email>>>,
}

#[async_trait]
impl Mailer for Capture {
    fn identity(&self) -> &MailerIdentity {
        &self.identity
    }

    async fn send(&self, email: &Email) -> Result<SendReceipt, MailerError> {
        self.sent.lock().unwrap().push(email.clone());
        Ok(SendReceipt { message_id: None })
    }
}

struct Fixture {
    router: Router,
    account: Arc<AccountRuntime>,
    sent: Arc<Mutex<Vec<Email>>>,
    /// The relay's safety pipeline, built from the same account tuning.
    guard: Arc<weaver_abuse::Pipeline>,
}

async fn setup() -> Fixture {
    setup_with(|_| {}).await
}

/// Builds a fixture with the standard test config, letting `adjust` tweak the
/// account policy (e.g. to disable the resend cooldown in a reset test).
async fn setup_with(adjust: impl FnOnce(&mut AccountConfig)) -> Fixture {
    setup_full(adjust, true).await
}

/// Like [`setup_with`], but with no mailer: the inactivity warning is skipped
/// while deletion still proceeds.
async fn setup_without_mailer(adjust: impl FnOnce(&mut AccountConfig)) -> Fixture {
    setup_full(adjust, false).await
}

async fn setup_full(adjust: impl FnOnce(&mut AccountConfig), with_mailer: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap().keep();
    let store = Store::open(dir.join("account.db")).await.unwrap();

    let config = base_config();
    let altcha = AltchaRuntime::from_config(&config, store.clone()).unwrap();
    altcha.ensure_demo_client().await.unwrap();

    let sent = Arc::new(Mutex::new(Vec::new()));
    let mailer: Option<Arc<dyn Mailer>> = with_mailer.then(|| {
        Arc::new(Capture {
            identity: MailerIdentity::new(
                "stub",
                "Stub",
                Mailbox::new("no-reply@admin.test"),
                "https://admin.test",
                vec![],
            )
            .unwrap(),
            sent: Arc::clone(&sent),
        }) as Arc<dyn Mailer>
    });

    let mut account_config = AccountConfig {
        base_url: Some("https://admin.test".into()),
        cookie_secure: false,
        // Tiny Argon2 so tests stay fast.
        argon2_memory_kib: 8,
        argon2_iterations: 1,
        argon2_parallelism: 1,
        ..Default::default()
    };
    adjust(&mut account_config);
    let guard = weaver_server::abuse::build(
        &Config {
            account: account_config.clone(),
            ..config
        },
        store.clone(),
    );
    let account = AccountRuntime::with_breach(
        &account_config,
        "admin.test",
        store.clone(),
        altcha,
        mailer,
        weaver_server::live::LiveHub::new(),
        Arc::new(NoBreach),
    )
    .unwrap();
    // The console reads its traffic figures from the metrics store over the
    // same store the tests seed usage rows into.
    Fixture {
        router: router(account.clone(), None),
        account,
        sent,
        guard,
    }
}

fn base_config() -> Config {
    Config {
        tunnel_domain: "weaver.test".into(),
        admin_domain: "admin.test".into(),
        admin_email: "admin@weaver.test".into(),
        acme_provider: "letsencrypt-staging".into(),
        listen_http: SocketAddr::from(([127, 0, 0, 1], 0)),
        listen_https: SocketAddr::from(([127, 0, 0, 1], 0)),
        control_socket: std::env::temp_dir().join("weaver-account-test.sock"),
        acme_directory: None,
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: None,
        acme_fallback_providers: Vec::new(),
        usage_flush_interval_secs: 60,
        usage_retention_secs: 31_536_000,
        relay_ips: Vec::new(),
        setup_complete: false,
        email: Some(weaver_server::config::test_email_config()),
        abuse: None,
        account: AccountConfig::default(),
    }
}

/// A solved ALTCHA payload for `purpose`, encoded as the widget would submit it.
async fn solved(account: &AccountRuntime, purpose: &str) -> String {
    let challenge: Challenge = account
        .altcha
        .challenge_for_internal_client(purpose, purpose)
        .await
        .expect("internal client exists");
    let payload = Payload {
        challenge: challenge.clone(),
        solution: solve_challenge(&challenge),
    };
    base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&payload).unwrap())
}

/// A response captured from the router for assertions.
struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: serde_json::Value,
    /// The body's byte length, before any JSON parsing (so binary and
    /// compressed bodies can still be compared by size).
    len: usize,
}

impl Reply {
    /// The value of a `Set-Cookie` by name (without attributes).
    fn cookie(&self, name: &str) -> Option<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find_map(|raw| {
                let (key, rest) = raw.split_once('=')?;
                (key == name).then(|| rest.split(';').next().unwrap_or("").to_string())
            })
    }
}

/// Lowercase hex of a byte slice, for a SQL `X'…'` blob literal.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn call(
    router: &Router,
    method: &str,
    uri: &str,
    headers: &[(&str, String)],
    body: Option<serde_json::Value>,
) -> Reply {
    let mut builder = Request::builder().method(method).uri(uri);
    for (key, value) in headers {
        builder = builder.header(*key, value);
    }
    let body = match &body {
        Some(value) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(value).unwrap())
        }
        None => Body::empty(),
    };
    let response = router
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let is_stream = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/event-stream"));
    let bytes = if is_stream {
        first_event_data(response.into_body()).await
    } else {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
    };
    let parsed = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    Reply {
        status,
        headers,
        body: parsed,
        len: bytes.len(),
    }
}

/// The `data` of the first event on an SSE body (comments skipped), then the
/// stream is dropped — which is how a client leaves.
async fn first_event_data(body: Body) -> bytes::Bytes {
    let (_, data) = Events::new(body).next().await.expect("a first event");
    bytes::Bytes::from(data)
}

/// The wall clock, in Unix seconds.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// An SSE body read event by event.
struct Events {
    body: Body,
    buffer: String,
}

impl Events {
    fn new(body: Body) -> Self {
        Events {
            body,
            buffer: String::new(),
        }
    }

    /// The next event's `(name, data)`, comments skipped; `None` once the
    /// stream has ended.
    async fn next(&mut self) -> Option<(String, String)> {
        use http_body_util::BodyExt;
        loop {
            while let Some(end) = self.buffer.find("\n\n") {
                let event: String = self.buffer.drain(..end + 2).collect();
                let name = event
                    .lines()
                    .find_map(|line| line.strip_prefix("event: "))
                    .unwrap_or("message")
                    .to_string();
                let data: Vec<&str> = event
                    .lines()
                    .filter_map(|line| line.strip_prefix("data: "))
                    .collect();
                if !data.is_empty() {
                    return Some((name, data.join("\n")));
                }
            }
            let frame = tokio::time::timeout(std::time::Duration::from_secs(5), self.body.frame())
                .await
                .expect("the stream sends its next event promptly")?
                .unwrap();
            if let Ok(chunk) = frame.into_data() {
                self.buffer.push_str(std::str::from_utf8(&chunk).unwrap());
            }
        }
    }

    /// The next event, which must be a `state`, parsed.
    async fn state(&mut self) -> serde_json::Value {
        let (name, data) = self.next().await.expect("a state event");
        assert_eq!(name, "state", "{data}");
        serde_json::from_str(&data).unwrap()
    }
}

/// The `GET /api/account/me` stream's first `state` for a session cookie.
async fn me(fixture: &Fixture, session: &str) -> Reply {
    call(
        &fixture.router,
        "GET",
        "/api/account/me",
        &[("cookie", format!("__Host-weaver_session={session}"))],
        None,
    )
    .await
}

/// Extracts the raw verification token from the last captured email.
fn last_token(sent: &Mutex<Vec<Email>>) -> String {
    let emails = sent.lock().unwrap();
    let email = emails.last().expect("an email was sent");
    email
        .text
        .split("token=")
        .nth(1)
        .expect("verification link has a token")
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

/// Runs signup → verify → complete for a fresh address and returns nothing.
async fn register(fixture: &Fixture, name: &str, email: &str, password: &str) {
    let altcha = solved(&fixture.account, "signup").await;
    let reply = call(
        &fixture.router,
        "POST",
        "/api/account/signup",
        &[],
        Some(serde_json::json!({ "name": name, "email": email, "altcha": altcha })),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);

    let token = last_token(&fixture.sent);
    let reply = call(
        &fixture.router,
        "POST",
        "/api/account/verify",
        &[],
        Some(serde_json::json!({ "token": token })),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    assert_eq!(reply.body["outcome"], "set_password");
    let completion = reply.body["completion_token"].as_str().unwrap().to_string();

    let reply = call(
        &fixture.router,
        "POST",
        "/api/account/complete",
        &[],
        Some(serde_json::json!({ "completion_token": completion, "password": password })),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    assert_eq!(reply.body["outcome"], "activated");
}

/// The six-digit code from the newest captured sign-in email.
///
/// The test's stand-in for the person reading their inbox: the plain-text twin
/// carries the code alone on its line.
fn latest_signin_code(sent: &Arc<Mutex<Vec<Email>>>) -> String {
    sent.lock()
        .unwrap()
        .iter()
        .rev()
        .find(|email| email.subject == "Your Tunnel Weaver sign-in code")
        .and_then(|email| {
            email
                .text
                .lines()
                .map(str::trim)
                .find(|line| line.len() == 6 && line.chars().all(|c| c.is_ascii_digit()))
                .map(str::to_string)
        })
        .expect("a sign-in code email was captured")
}

/// The password step of a sign-in: opens a `Basic` session and emails a code.
/// Returns the `(session, csrf)` cookie pair.
async fn login_step(fixture: &Fixture, email: &str, password: &str) -> (String, String) {
    let login = call(
        &fixture.router,
        "POST",
        "/api/account/login",
        &[],
        Some(serde_json::json!({
            "email": email,
            "password": password,
            "altcha": solved(&fixture.account, "login").await,
        })),
    )
    .await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    (
        login
            .cookie("__Host-weaver_session")
            .expect("session cookie set"),
        login.cookie("__Host-weaver_csrf").expect("csrf cookie set"),
    )
}

/// The code step of a sign-in, with the double-submit CSRF pair attached.
async fn verify_code(fixture: &Fixture, session: &str, csrf: &str, code: &str) -> Reply {
    call(
        &fixture.router,
        "POST",
        "/api/account/login/verify",
        &[
            (
                "cookie",
                format!("__Host-weaver_session={session}; __Host-weaver_csrf={csrf}"),
            ),
            ("x-csrf-token", csrf.to_string()),
        ],
        Some(serde_json::json!({ "code": code })),
    )
    .await
}

/// The authoritative end-to-end happy path: signup → emailed link →
/// initial password → login → signed-in identity → logout → login again.
#[tokio::test]
async fn full_lifecycle_signup_verify_login_logout() {
    let fixture = setup().await;
    register(
        &fixture,
        "Rémy",
        "remy@example.com",
        "correct horse battery",
    )
    .await;

    // A verification email and a welcome email were sent.
    assert_eq!(fixture.sent.lock().unwrap().len(), 2);

    // Log in: the password step, then the emailed code (WVR-167).
    let (session, csrf) = login_step(&fixture, "remy@example.com", "correct horse battery").await;
    let verified = verify_code(
        &fixture,
        &session,
        &csrf,
        &latest_signin_code(&fixture.sent),
    )
    .await;
    assert_eq!(verified.status, StatusCode::OK, "{:?}", verified.body);

    // Identity, with the Unicode name preserved, on the session stream.
    let state = me(&fixture, &session).await;
    assert_eq!(state.status, StatusCode::OK);
    assert_eq!(state.body["me"]["name"], "Rémy");
    assert_eq!(state.body["me"]["email"], "remy@example.com");
    // The second factor is done and the password was typed moments ago, so the
    // session is at the top: nothing above it is offered, and the next drop is
    // the password proof ageing out, to `strong`.
    assert_eq!(state.body["level"], "certain");
    assert_eq!(state.body["paths"], serde_json::json!([]));
    assert_eq!(state.body["drop"]["to"], "strong");
    // The Security page's "Password is set" state is driven by this flag.
    assert_eq!(
        state.body["me"]["has_password"], true,
        "a password account reports a live credential"
    );

    // Logout requires the CSRF token.
    let no_csrf = call(
        &fixture.router,
        "POST",
        "/api/account/logout",
        &[("cookie", format!("__Host-weaver_session={session}"))],
        None,
    )
    .await;
    assert_eq!(no_csrf.status, StatusCode::FORBIDDEN);

    let logout = call(
        &fixture.router,
        "POST",
        "/api/account/logout",
        &[
            (
                "cookie",
                format!("__Host-weaver_session={session}; __Host-weaver_csrf={csrf}"),
            ),
            ("x-csrf-token", csrf.clone()),
        ],
        None,
    )
    .await;
    assert_eq!(logout.status, StatusCode::OK);

    // The old cookie no longer authenticates: the stream says `none`, with the
    // way back in.
    let after = me(&fixture, &session).await;
    assert_eq!(after.body["level"], "none");
    assert_eq!(after.body["paths"][0]["to"], "basic");
    assert_eq!(
        after.body["paths"][0]["options"],
        serde_json::json!([[{ "step": "login", "reaches": "basic" }]])
    );
    assert!(after.body.get("me").is_none(), "{:?}", after.body);

    // Logging in again after logout succeeds with the same credentials,
    // and the fresh session authenticates. This proves logout retires the
    // session rather than poisoning the account (login rotates the token).
    let (session2, csrf2) = login_step(&fixture, "remy@example.com", "correct horse battery").await;
    assert_ne!(session2, session, "login must mint a new session token");
    let verified2 = verify_code(
        &fixture,
        &session2,
        &csrf2,
        &latest_signin_code(&fixture.sent),
    )
    .await;
    assert_eq!(verified2.status, StatusCode::OK, "{:?}", verified2.body);

    let me2 = me(&fixture, &session2).await;
    assert_eq!(me2.body["level"], "certain");
    assert_eq!(me2.body["me"]["name"], "Rémy");
    assert_eq!(me2.body["me"]["email"], "remy@example.com");
}

/// The session stream is live: an open one is told the moment the code is
/// accepted and the moment the session ends, and an anonymous one ends after
/// saying so.
#[tokio::test]
async fn the_session_stream_follows_the_level() {
    let fixture = setup().await;
    register(
        &fixture,
        "Rémy",
        "stream@example.com",
        "correct horse battery",
    )
    .await;

    let anonymous = fixture
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/account/me")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::OK);
    let mut events = Events::new(anonymous.into_body());
    assert_eq!(events.state().await["level"], "none");
    assert!(events.next().await.is_none(), "an anonymous stream ends");

    let (session, csrf) = login_step(&fixture, "stream@example.com", "correct horse battery").await;
    let open = fixture
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/account/me")
                .header("cookie", format!("__Host-weaver_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let mut events = Events::new(open.into_body());
    assert_eq!(events.state().await["level"], "basic");

    let accepted = verify_code(
        &fixture,
        &session,
        &csrf,
        &latest_signin_code(&fixture.sent),
    )
    .await;
    assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.body);
    let strong = events.state().await;
    assert_eq!(strong["level"], "certain");
    assert_eq!(strong["me"]["email"], "stream@example.com");

    let logout = call(
        &fixture.router,
        "POST",
        "/api/account/logout",
        &[
            (
                "cookie",
                format!("__Host-weaver_session={session}; __Host-weaver_csrf={csrf}"),
            ),
            ("x-csrf-token", csrf.clone()),
        ],
        None,
    )
    .await;
    assert_eq!(logout.status, StatusCode::OK);
    assert_eq!(events.state().await["level"], "none");
    assert!(events.next().await.is_none(), "a signed-out stream ends");
}

/// Where a step leaves you is worked out from the proofs, not tabulated: the
/// same emailed code lands at `certain` while the password proof is alive and at
/// `strong` once it has aged out, and only then does the way to `certain` grow a
/// second step.
#[tokio::test]
async fn the_ways_up_follow_the_password_proof() {
    use sea_orm::ConnectionTrait as _;

    let fixture = setup().await;
    register(
        &fixture,
        "Rémy",
        "ways-up@example.com",
        "correct horse battery",
    )
    .await;
    let (session, _) = login_step(&fixture, "ways-up@example.com", "correct horse battery").await;

    let fresh = me(&fixture, &session).await;
    assert_eq!(
        fresh.body["paths"][1]["options"],
        serde_json::json!([[{ "step": "verify_email_otp", "reaches": "certain" }]])
    );

    // Ten minutes on: the password proof is past its lifetime.
    fixture
        .account
        .store
        .db()
        .execute_unprepared(
            "UPDATE auth_event SET occurred_at = occurred_at - 600 WHERE kind = 'password'",
        )
        .await
        .unwrap();

    let stale = me(&fixture, &session).await;
    assert_eq!(stale.body["level"], "basic");
    // To `strong`, the code is still the whole way.
    assert_eq!(
        stale.body["paths"][0],
        serde_json::json!({
            "to": "strong",
            "options": [[{ "step": "verify_email_otp", "reaches": "strong" }]],
        })
    );
    // To `certain`, it is not: the password has to be re-typed as well, and the
    // stream says where each step leaves the session.
    assert_eq!(
        stale.body["paths"][1],
        serde_json::json!({
            "to": "certain",
            "options": [[
                { "step": "verify_email_otp", "reaches": "strong" },
                { "step": "confirm_password", "reaches": "certain" },
            ]],
        })
    );
}

/// A drop is announced before it lands, then lands as a `state` of its own.
#[tokio::test]
async fn the_session_stream_announces_a_drop_before_it_lands() {
    let fixture = setup().await;
    register(
        &fixture,
        "Rémy",
        "drop@example.com",
        "correct horse battery",
    )
    .await;
    let (session, _) = sign_in(&fixture, "drop@example.com", "correct horse battery").await;

    use sea_orm::ConnectionTrait as _;

    // Bring the session's end inside the announcement lead.
    let ends_at = unix_now() + 2;
    fixture
        .account
        .store
        .db()
        .execute_unprepared(&format!(
            "UPDATE browser_session SET expires_at = {ends_at} WHERE invalidated_at IS NULL"
        ))
        .await
        .unwrap();

    let open = fixture
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/account/me")
                .header("cookie", format!("__Host-weaver_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let mut events = Events::new(open.into_body());
    let state = events.state().await;
    assert_eq!(state["level"], "certain");
    assert_eq!(
        state["drop"],
        serde_json::json!({ "at": ends_at, "to": "none" })
    );

    let (name, data) = events.next().await.expect("a drop announcement");
    assert_eq!(name, "drop", "{data}");
    let announced: serde_json::Value = serde_json::from_str(&data).unwrap();
    assert_eq!(announced["at"], ends_at);
    assert_eq!(announced["to"], "none");
    assert!(announced["in"].as_i64().unwrap() <= 2);

    assert_eq!(events.state().await["level"], "none");
    assert!(events.next().await.is_none());
}

/// WVR-167: the password alone does not sign anyone in. The session it opens is
/// `basic` — it may read its own level, enter the code, and leave, and nothing
/// else — and the emailed code must be accepted, once, to finish.
#[tokio::test]
async fn login_is_not_complete_until_the_emailed_code() {
    let fixture = setup().await;
    register(
        &fixture,
        "Rémy",
        "twofactor@example.com",
        "correct horse battery",
    )
    .await;

    let (session, csrf) =
        login_step(&fixture, "twofactor@example.com", "correct horse battery").await;
    let cookie = format!("__Host-weaver_session={session}");

    // The session exists but is unfinished, and the stream says how to finish
    // it, and when it ends unless finished.
    let state = me(&fixture, &session).await;
    assert_eq!(state.status, StatusCode::OK);
    assert_eq!(state.body["level"], "basic");
    // The password was typed moments ago, so the emailed code alone lands at
    // `certain`: that is where the stream says the step leaves the session.
    assert_eq!(
        state.body["paths"],
        serde_json::json!([
            {
                "to": "strong",
                "options": [[{ "step": "verify_email_otp", "reaches": "certain" }]],
            },
            {
                "to": "certain",
                "options": [[{ "step": "verify_email_otp", "reaches": "certain" }]],
            },
        ])
    );
    assert_eq!(state.body["drop"]["to"], "none");
    assert!(state.body["drop"]["at"].as_i64().is_some());

    // Every protected endpoint is refused, naming in headers the level that
    // would have been enough and the way there.
    let machines = call(
        &fixture.router,
        "GET",
        "/api/account/machines",
        &[("cookie", cookie.clone())],
        None,
    )
    .await;
    assert_eq!(
        machines.status,
        StatusCode::FORBIDDEN,
        "{:?}",
        machines.body
    );
    assert_eq!(machines.headers["x-weaver-required-level"], "strong");
    assert_eq!(
        machines.headers["x-weaver-upgrade-paths"],
        r#"[[{"step":"verify_email_otp","reaches":"certain"}]]"#
    );

    // So is a write.
    let rename = call(
        &fixture.router,
        "POST",
        "/api/account/machines/1/rename",
        &[
            (
                "cookie",
                format!("__Host-weaver_session={session}; __Host-weaver_csrf={csrf}"),
            ),
            ("x-csrf-token", csrf.clone()),
        ],
        Some(serde_json::json!({ "name": "laptop" })),
    )
    .await;
    assert_eq!(rename.status, StatusCode::FORBIDDEN, "{:?}", rename.body);
    assert_eq!(rename.headers["x-weaver-required-level"], "strong");

    // A wrong code is refused and leaves the session unfinished.
    let code = latest_signin_code(&fixture.sent);
    let wrong = if code == "000000" { "000001" } else { "000000" };
    let refused = verify_code(&fixture, &session, &csrf, wrong).await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        refused.body
    );
    let still_basic = me(&fixture, &session).await;
    assert_eq!(still_basic.body["level"], "basic");

    // The emailed code finishes it, and protected endpoints answer.
    let accepted = verify_code(&fixture, &session, &csrf, &code).await;
    assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.body);
    let state = me(&fixture, &session).await;
    assert_eq!(state.body["level"], "certain");
    let avatar = call(
        &fixture.router,
        "GET",
        "/api/account/avatar",
        &[("cookie", cookie.clone())],
        None,
    )
    .await;
    assert_eq!(avatar.status, StatusCode::OK);

    // The code is single-use: replaying it changes nothing (and is refused).
    let replay = verify_code(&fixture, &session, &csrf, &code).await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST, "{:?}", replay.body);

    // A half-signed-in person can still leave.
    let logout = call(
        &fixture.router,
        "POST",
        "/api/account/logout",
        &[
            (
                "cookie",
                format!("__Host-weaver_session={session}; __Host-weaver_csrf={csrf}"),
            ),
            ("x-csrf-token", csrf.clone()),
        ],
        None,
    )
    .await;
    assert_eq!(logout.status, StatusCode::OK, "{:?}", logout.body);
}

/// WVR-167: asking for another code replaces the pending one, so only the newest
/// code is accepted.
#[tokio::test]
async fn a_resend_replaces_the_previous_sign_in_code() {
    // The cooldown would refuse the immediate re-send; it is a separate policy.
    let fixture = setup_with(|config| config.resend_cooldown_secs = 0).await;
    register(
        &fixture,
        "Rémy",
        "resend-code@example.com",
        "correct horse battery",
    )
    .await;

    let (session, csrf) =
        login_step(&fixture, "resend-code@example.com", "correct horse battery").await;
    let first = latest_signin_code(&fixture.sent);

    let resend = call(
        &fixture.router,
        "POST",
        "/api/account/login/resend",
        &[
            (
                "cookie",
                format!("__Host-weaver_session={session}; __Host-weaver_csrf={csrf}"),
            ),
            ("x-csrf-token", csrf.clone()),
        ],
        None,
    )
    .await;
    assert_eq!(resend.status, StatusCode::OK, "{:?}", resend.body);
    let second = latest_signin_code(&fixture.sent);

    // The replaced code stops working; the fresh one takes.
    let stale = verify_code(&fixture, &session, &csrf, &first).await;
    assert_eq!(stale.status, StatusCode::BAD_REQUEST, "{:?}", stale.body);
    let fresh = verify_code(&fixture, &session, &csrf, &second).await;
    assert_eq!(fresh.status, StatusCode::OK, "{:?}", fresh.body);
}

#[tokio::test]
async fn verification_link_is_single_use() {
    let fixture = setup().await;
    let altcha = solved(&fixture.account, "signup").await;
    call(
        &fixture.router,
        "POST",
        "/api/account/signup",
        &[],
        Some(serde_json::json!({ "name": "A", "email": "a@example.com", "altcha": altcha })),
    )
    .await;
    let token = last_token(&fixture.sent);

    let first = call(
        &fixture.router,
        "POST",
        "/api/account/verify",
        &[],
        Some(serde_json::json!({ "token": token })),
    )
    .await;
    assert_eq!(first.status, StatusCode::OK);

    let second = call(
        &fixture.router,
        "POST",
        "/api/account/verify",
        &[],
        Some(serde_json::json!({ "token": token })),
    )
    .await;
    assert_eq!(second.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn existing_address_is_revealed_only_after_ownership() {
    let fixture = setup().await;
    register(
        &fixture,
        "First",
        "dup@example.com",
        "correct horse battery",
    )
    .await;

    // A second signup for the same address, then verify.
    let altcha = solved(&fixture.account, "signup").await;
    let signup = call(
        &fixture.router,
        "POST",
        "/api/account/signup",
        &[],
        Some(serde_json::json!({ "name": "Second", "email": "dup@example.com", "altcha": altcha })),
    )
    .await;
    // The response does not disclose the existing account.
    assert_eq!(signup.status, StatusCode::OK);
    assert_eq!(signup.body["status"], "check_email");

    let token = last_token(&fixture.sent);
    let verify = call(
        &fixture.router,
        "POST",
        "/api/account/verify",
        &[],
        Some(serde_json::json!({ "token": token })),
    )
    .await;
    assert_eq!(verify.status, StatusCode::OK);
    assert_eq!(verify.body["outcome"], "existing_account");

    // The original password still works — the second signup did not overwrite it.
    let altcha = solved(&fixture.account, "login").await;
    let login = call(
        &fixture.router,
        "POST",
        "/api/account/login",
        &[],
        Some(serde_json::json!({
            "email": "dup@example.com",
            "password": "correct horse battery",
            "altcha": altcha
        })),
    )
    .await;
    assert_eq!(login.status, StatusCode::OK);
}

#[tokio::test]
async fn a_spent_proof_cannot_be_replayed() {
    let fixture = setup().await;
    let altcha = solved(&fixture.account, "signup").await;
    let body = serde_json::json!({ "name": "A", "email": "a@example.com", "altcha": altcha });
    let first = call(
        &fixture.router,
        "POST",
        "/api/account/signup",
        &[],
        Some(body.clone()),
    )
    .await;
    assert_eq!(first.status, StatusCode::OK);
    let replay = call(
        &fixture.router,
        "POST",
        "/api/account/signup",
        &[],
        Some(body),
    )
    .await;
    assert_eq!(replay.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn login_rejects_wrong_credentials_generically() {
    let fixture = setup().await;
    register(&fixture, "A", "a@example.com", "correct horse battery").await;
    let altcha = solved(&fixture.account, "login").await;
    let bad = call(
        &fixture.router,
        "POST",
        "/api/account/login",
        &[],
        Some(serde_json::json!({
            "email": "a@example.com",
            "password": "the-wrong-password",
            "altcha": altcha
        })),
    )
    .await;
    assert_eq!(bad.status, StatusCode::UNAUTHORIZED);
    assert_eq!(bad.body["error"], "invalid email or password");
}

#[tokio::test]
async fn short_passwords_are_refused_at_completion() {
    let fixture = setup().await;
    let altcha = solved(&fixture.account, "signup").await;
    call(
        &fixture.router,
        "POST",
        "/api/account/signup",
        &[],
        Some(serde_json::json!({ "name": "A", "email": "a@example.com", "altcha": altcha })),
    )
    .await;
    let token = last_token(&fixture.sent);
    let verify = call(
        &fixture.router,
        "POST",
        "/api/account/verify",
        &[],
        Some(serde_json::json!({ "token": token })),
    )
    .await;
    let completion = verify.body["completion_token"]
        .as_str()
        .unwrap()
        .to_string();
    let reply = call(
        &fixture.router,
        "POST",
        "/api/account/complete",
        &[],
        Some(serde_json::json!({ "completion_token": completion, "password": "short" })),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn spa_shell_is_served_for_deep_links() {
    let fixture = setup().await;
    let reply = call(&fixture.router, "GET", "/set-password", &[], None).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.headers.get(header::CONTENT_TYPE).unwrap(),
        "text/html; charset=utf-8"
    );

    // Legacy `/account/...` links redirect to the root equivalents.
    let legacy = call(&fixture.router, "GET", "/account/sign-in", &[], None).await;
    assert_eq!(legacy.status, StatusCode::FOUND);
    assert_eq!(legacy.headers.get(header::LOCATION).unwrap(), "/sign-in");
}

// ----- password reset ---------------------------------------------

/// Extracts the raw reset token from the last captured email. The reset link
/// carries the token in the URL *fragment* (`/reset#token=…`), so it never
/// reaches the server or its logs.
fn last_reset_token(sent: &Mutex<Vec<Email>>) -> String {
    let emails = sent.lock().unwrap();
    let email = emails.last().expect("an email was sent");
    email
        .text
        .split("#token=")
        .nth(1)
        .expect("the reset link carries its token in the fragment")
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

/// Requests a reset link for an address (solving the reset PoW).
async fn request_reset(fixture: &Fixture, email: &str) -> Reply {
    let altcha = solved(&fixture.account, "reset").await;
    call(
        &fixture.router,
        "POST",
        "/api/account/reset/request",
        &[],
        Some(serde_json::json!({ "email": email, "altcha": altcha })),
    )
    .await
}

/// Waits (bounded) for the capture mailbox to reach `expected` messages. The
/// reset request sends its email off the response path, so the mail lands after
/// the HTTP reply.
async fn wait_for_mail_count(sent: &Mutex<Vec<Email>>, expected: usize) {
    for _ in 0..300 {
        if sent.lock().unwrap().len() >= expected {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!(
        "expected {expected} captured emails, got {}",
        sent.lock().unwrap().len()
    );
}

/// Waits (bounded) for a captured email with an exact subject, returning it.
///
/// The password-change notification is sent off the response path, and by the
/// time a test looks, a later sign-in code can be the newest message — so the
/// test finds its mail by subject rather than by position.
async fn wait_for_mail_subject(sent: &Mutex<Vec<Email>>, subject: &str) -> Email {
    for _ in 0..300 {
        if let Some(email) = sent
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|email| email.subject == subject)
        {
            return email.clone();
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("no captured email with subject {subject:?}");
}

/// Requests a reset link and waits for the detached email, returning the
/// response and the raw token from the link.
async fn request_reset_and_token(fixture: &Fixture, email: &str) -> (Reply, String) {
    let before = fixture.sent.lock().unwrap().len();
    let reply = request_reset(fixture, email).await;
    wait_for_mail_count(&fixture.sent, before + 1).await;
    let token = last_reset_token(&fixture.sent);
    (reply, token)
}

/// Completes a reset with a raw token and a new password.
async fn complete_reset(fixture: &Fixture, token: &str, password: &str) -> Reply {
    call(
        &fixture.router,
        "POST",
        "/api/account/reset/complete",
        &[],
        Some(serde_json::json!({ "token": token, "password": password })),
    )
    .await
}

/// A reset request for an unknown address must be indistinguishable from one
/// for a real account: same status, same body, and no email.
#[tokio::test]
async fn reset_request_is_indistinguishable_for_known_and_unknown() {
    let fixture = setup().await;
    register(
        &fixture,
        "Rémy",
        "known@example.com",
        "correct horse battery",
    )
    .await;
    let before = fixture.sent.lock().unwrap().len();

    let unknown = request_reset(&fixture, "nobody@example.com").await;
    assert_eq!(unknown.status, StatusCode::OK, "{:?}", unknown.body);
    assert_eq!(unknown.body["status"], "check_email");
    assert_eq!(
        fixture.sent.lock().unwrap().len(),
        before,
        "no email is sent for an unknown address"
    );

    let known = request_reset(&fixture, "known@example.com").await;
    assert_eq!(known.status, StatusCode::OK, "{:?}", known.body);
    assert_eq!(
        known.body, unknown.body,
        "the response must not reveal whether the account exists"
    );
    // The reset email is sent off the response path, so wait for it to land.
    wait_for_mail_count(&fixture.sent, before + 1).await;
    assert_eq!(
        fixture.sent.lock().unwrap().len(),
        before + 1,
        "a reset email is sent for the real account"
    );
}

/// Issuing a new reset token invalidates the previous one: only the latest link
/// works. The cooldown is disabled so two requests can be made back to back.
#[tokio::test]
async fn reset_request_reissues_and_invalidates_previous() {
    let fixture = setup_with(|cfg| cfg.resend_cooldown_secs = 0).await;
    register(
        &fixture,
        "Rémy",
        "reissue@example.com",
        "correct horse battery",
    )
    .await;

    let (_, first) = request_reset_and_token(&fixture, "reissue@example.com").await;
    let (_, second) = request_reset_and_token(&fixture, "reissue@example.com").await;
    assert_ne!(first, second, "a fresh token is minted");

    let dead = complete_reset(&fixture, &first, "a brand new password").await;
    assert_eq!(
        dead.status,
        StatusCode::BAD_REQUEST,
        "the superseded link is refused: {:?}",
        dead.body
    );
    let ok = complete_reset(&fixture, &second, "a brand new password").await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.body);
    assert_eq!(ok.body["outcome"], "reset");
}

/// A reset link works exactly once.
#[tokio::test]
async fn reset_link_is_single_use() {
    let fixture = setup().await;
    register(
        &fixture,
        "Rémy",
        "single@example.com",
        "correct horse battery",
    )
    .await;
    let (requested, token) = request_reset_and_token(&fixture, "single@example.com").await;
    assert_eq!(requested.status, StatusCode::OK, "{:?}", requested.body);

    let first = complete_reset(&fixture, &token, "a brand new password").await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.body);
    let replay = complete_reset(&fixture, &token, "another new password").await;
    assert_eq!(
        replay.status,
        StatusCode::BAD_REQUEST,
        "a spent link is refused: {:?}",
        replay.body
    );
}

/// The non-consuming check resolves the link's email and detects dead links, and
/// does not spend the token.
#[tokio::test]
async fn reset_check_reports_validity_without_consuming() {
    let fixture = setup().await;
    register(
        &fixture,
        "Rémy",
        "check@example.com",
        "correct horse battery",
    )
    .await;
    let (_, token) = request_reset_and_token(&fixture, "check@example.com").await;

    let valid = call(
        &fixture.router,
        "POST",
        "/api/account/reset/check",
        &[],
        Some(serde_json::json!({ "token": token })),
    )
    .await;
    assert_eq!(valid.status, StatusCode::OK, "{:?}", valid.body);
    assert_eq!(valid.body["valid"], true);
    assert_eq!(valid.body["email"], "check@example.com");

    let bogus = call(
        &fixture.router,
        "POST",
        "/api/account/reset/check",
        &[],
        Some(serde_json::json!({ "token": "not-a-real-token" })),
    )
    .await;
    assert_eq!(bogus.status, StatusCode::OK);
    assert_eq!(bogus.body["valid"], false);

    // The check did not consume the token: the reset still completes.
    let done = complete_reset(&fixture, &token, "a brand new password").await;
    assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);

    let after = call(
        &fixture.router,
        "POST",
        "/api/account/reset/check",
        &[],
        Some(serde_json::json!({ "token": token })),
    )
    .await;
    assert_eq!(
        after.body["valid"], false,
        "a consumed link is no longer valid"
    );
}

/// A weak password is refused, and the refusal does not consume the token.
#[tokio::test]
async fn reset_complete_enforces_password_policy() {
    let fixture = setup().await;
    register(
        &fixture,
        "Rémy",
        "policy@example.com",
        "correct horse battery",
    )
    .await;
    let (_, token) = request_reset_and_token(&fixture, "policy@example.com").await;

    let short = complete_reset(&fixture, &token, "short").await;
    assert_eq!(short.status, StatusCode::BAD_REQUEST, "{:?}", short.body);

    let ok = complete_reset(&fixture, &token, "a brand new password").await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.body);
}

/// A completed reset signs the user out everywhere: prior sessions die, the old
/// password stops working, and the new one works.
#[tokio::test]
async fn reset_revokes_every_existing_session() {
    let fixture = setup().await;
    register(
        &fixture,
        "Rémy",
        "revoke@example.com",
        "correct horse battery",
    )
    .await;

    let login = call(
        &fixture.router,
        "POST",
        "/api/account/login",
        &[],
        Some(serde_json::json!({
            "email": "revoke@example.com",
            "password": "correct horse battery",
            "altcha": solved(&fixture.account, "login").await,
        })),
    )
    .await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    let session = login
        .cookie("__Host-weaver_session")
        .expect("session cookie set");

    let (_, token) = request_reset_and_token(&fixture, "revoke@example.com").await;
    let done = complete_reset(&fixture, &token, "a brand new password").await;
    assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);

    // The pre-reset session no longer authenticates.
    let me = call(
        &fixture.router,
        "GET",
        "/api/account/me",
        &[("cookie", format!("__Host-weaver_session={session}"))],
        None,
    )
    .await;
    assert_eq!(
        me.body["level"], "none",
        "a reset signs the user out everywhere"
    );

    // The old password is gone; the new one signs in.
    let old = call(
        &fixture.router,
        "POST",
        "/api/account/login",
        &[],
        Some(serde_json::json!({
            "email": "revoke@example.com",
            "password": "correct horse battery",
            "altcha": solved(&fixture.account, "login").await,
        })),
    )
    .await;
    assert_eq!(old.status, StatusCode::UNAUTHORIZED, "{:?}", old.body);

    let fresh = call(
        &fixture.router,
        "POST",
        "/api/account/login",
        &[],
        Some(serde_json::json!({
            "email": "revoke@example.com",
            "password": "a brand new password",
            "altcha": solved(&fixture.account, "login").await,
        })),
    )
    .await;
    assert_eq!(fresh.status, StatusCode::OK, "{:?}", fresh.body);
}

/// A static asset is served in the pre-compressed variant the client accepts
/// (built at compile time), and the shell negotiates too — so a browser
/// downloads the embedded app and the ALTCHA widget compressed.
#[tokio::test]
async fn static_assets_are_served_pre_compressed() {
    let fixture = setup().await;
    // The widget asset has a stable (unversioned) path, so the test does not
    // depend on this build's content hashes.
    let path = "/assets/altcha/altcha.js";

    let identity = call(&fixture.router, "GET", path, &[], None).await;
    assert_eq!(identity.status, StatusCode::OK);
    assert!(
        identity.headers.get(header::CONTENT_ENCODING).is_none(),
        "no Accept-Encoding means the identity bytes"
    );
    assert_eq!(
        identity.headers.get(header::VARY).unwrap(),
        "accept-encoding",
        "a compressible asset must vary on the encoding"
    );

    let gzip = call(
        &fixture.router,
        "GET",
        path,
        &[("accept-encoding", "gzip, deflate, br".to_string())],
        None,
    )
    .await;
    assert_eq!(gzip.status, StatusCode::OK);
    assert_eq!(gzip.headers.get(header::CONTENT_ENCODING).unwrap(), "gzip");
    assert!(
        gzip.len < identity.len,
        "gzip ({}) should be smaller than identity ({})",
        gzip.len,
        identity.len
    );

    let zstd = call(
        &fixture.router,
        "GET",
        path,
        &[("accept-encoding", "gzip, zstd".to_string())],
        None,
    )
    .await;
    assert_eq!(zstd.status, StatusCode::OK);
    assert_eq!(
        zstd.headers.get(header::CONTENT_ENCODING).unwrap(),
        "zstd",
        "zstd wins when the client offers both"
    );
    assert!(
        zstd.len <= gzip.len,
        "zstd ({}) should be at least as small as gzip ({})",
        zstd.len,
        gzip.len
    );

    // The SPA shell (served for every deep link) negotiates as well, and stays
    // uncached so a deploy is picked up immediately.
    let shell = call(
        &fixture.router,
        "GET",
        "/reset",
        &[("accept-encoding", "zstd".to_string())],
        None,
    )
    .await;
    assert_eq!(shell.status, StatusCode::OK);
    assert_eq!(shell.headers.get(header::CONTENT_ENCODING).unwrap(), "zstd");
    assert_eq!(
        shell.headers.get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
}

/// An expired reset link is refused at serve time (the store also sweeps the
/// row, but the completion route must reject it before it is ever re-issued).
#[tokio::test]
async fn reset_complete_rejects_an_expired_token() {
    use sea_orm::sea_query::Expr;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    use weaver_server::store::entity::password_reset_token;

    let fixture = setup().await;
    register(
        &fixture,
        "Rémy",
        "expired@example.com",
        "correct horse battery",
    )
    .await;
    let (_, token) = request_reset_and_token(&fixture, "expired@example.com").await;

    // Age the link out: the harness has no controllable clock, so expire the row.
    password_reset_token::Entity::update_many()
        .col_expr(password_reset_token::Column::ExpiresAt, Expr::value(0i64))
        .filter(password_reset_token::Column::ConsumedAt.is_null())
        .exec(fixture.account.store.db())
        .await
        .unwrap();

    let refused = complete_reset(&fixture, &token, "a brand new password").await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "an expired link is refused: {:?}",
        refused.body
    );

    // The credential is untouched: the original password still signs in.
    let login = call(
        &fixture.router,
        "POST",
        "/api/account/login",
        &[],
        Some(serde_json::json!({
            "email": "expired@example.com",
            "password": "correct horse battery",
            "altcha": solved(&fixture.account, "login").await,
        })),
    )
    .await;
    assert_eq!(
        login.status,
        StatusCode::OK,
        "a refused expired link must not change the password"
    );
}

/// The reset routes are same-origin only: a cross-site caller is refused before
/// any work happens (no lookup, no token, no email).
#[tokio::test]
async fn reset_routes_refuse_cross_origin_requests() {
    let fixture = setup().await;
    let before = fixture.sent.lock().unwrap().len();

    // A mismatched `Origin` is refused…
    let request = call(
        &fixture.router,
        "POST",
        "/api/account/reset/request",
        &[("origin", "https://evil.example".to_string())],
        Some(serde_json::json!({ "email": "nobody@example.com", "altcha": "irrelevant" })),
    )
    .await;
    assert_eq!(request.status, StatusCode::FORBIDDEN, "{:?}", request.body);

    // …as is a browser-declared cross-site fetch on the completion route.
    let complete = call(
        &fixture.router,
        "POST",
        "/api/account/reset/complete",
        &[("sec-fetch-site", "cross-site".to_string())],
        Some(serde_json::json!({ "token": "whatever", "password": "correct horse battery" })),
    )
    .await;
    assert_eq!(
        complete.status,
        StatusCode::FORBIDDEN,
        "{:?}",
        complete.body
    );

    assert_eq!(
        fixture.sent.lock().unwrap().len(),
        before,
        "a refused request sends nothing"
    );
}

// ----- change password -----------------------------------------------------

/// Signs in completely — password step then emailed code — and returns the
/// `(session, csrf)` cookie pair the change flow needs.
async fn sign_in(fixture: &Fixture, email: &str, password: &str) -> (String, String) {
    let (session, csrf) = login_step(fixture, email, password).await;
    let verified = verify_code(fixture, &session, &csrf, &latest_signin_code(&fixture.sent)).await;
    assert_eq!(verified.status, StatusCode::OK, "{:?}", verified.body);
    (session, csrf)
}

/// Whether a password signs in (a fresh ALTCHA-guarded login attempt).
async fn signs_in(fixture: &Fixture, email: &str, password: &str) -> bool {
    call(
        &fixture.router,
        "POST",
        "/api/account/login",
        &[],
        Some(serde_json::json!({
            "email": email,
            "password": password,
            "altcha": solved(&fixture.account, "login").await,
        })),
    )
    .await
    .status
        == StatusCode::OK
}

/// Posts a change-password request with the double-submit CSRF pair attached.
async fn change_password(
    fixture: &Fixture,
    session: &str,
    csrf: &str,
    current: &str,
    new: &str,
) -> Reply {
    call(
        &fixture.router,
        "POST",
        "/api/account/password",
        &[
            (
                "cookie",
                format!("__Host-weaver_session={session}; __Host-weaver_csrf={csrf}"),
            ),
            ("x-csrf-token", csrf.to_string()),
        ],
        Some(serde_json::json!({ "current_password": current, "new_password": new })),
    )
    .await
}

/// The happy path: the credential is replaced, every session (the acting one
/// included) is gone, the owner is notified, and only the new password works.
#[tokio::test]
async fn change_password_swaps_the_credential_and_signs_out_everywhere() {
    let fixture = setup().await;
    let email = "change@example.com";
    register(&fixture, "Rémy", email, "correct horse battery").await;
    let (session, csrf) = sign_in(&fixture, email, "correct horse battery").await;

    let reply = change_password(
        &fixture,
        &session,
        &csrf,
        "correct horse battery",
        "a much better password",
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    assert_eq!(reply.body["outcome"], "changed");
    assert_eq!(
        reply.cookie("__Host-weaver_session"),
        Some(String::new()),
        "the acting session's cookie is cleared in the reply"
    );

    // The acting session no longer authenticates.
    let me = call(
        &fixture.router,
        "GET",
        "/api/account/me",
        &[("cookie", format!("__Host-weaver_session={session}"))],
        None,
    )
    .await;
    assert_eq!(
        me.body["level"], "none",
        "a change signs the user out everywhere"
    );

    assert!(
        !signs_in(&fixture, email, "correct horse battery").await,
        "the old password stops working"
    );
    assert!(
        signs_in(&fixture, email, "a much better password").await,
        "the new password works"
    );

    // The owner is told, off the response path.
    let notification = wait_for_mail_subject(&fixture.sent, "Your password was changed").await;
    assert!(
        notification.text.contains("was changed on"),
        "the notice carries the event time: {}",
        notification.text
    );
}

/// A wrong current password is refused on the field it belongs to, and nothing
/// is touched: the session survives, the credential is unchanged, no mail.
#[tokio::test]
async fn change_password_refuses_a_wrong_current_password_without_side_effects() {
    let fixture = setup().await;
    let email = "wrong-current@example.com";
    register(&fixture, "Rémy", email, "correct horse battery").await;
    let (session, csrf) = sign_in(&fixture, email, "correct horse battery").await;
    let before = fixture.sent.lock().unwrap().len();

    let reply = change_password(
        &fixture,
        &session,
        &csrf,
        "not my password",
        "a much better password",
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{:?}", reply.body);
    assert_eq!(reply.body["field"], "current_password");
    assert!(reply.body["error"].is_string());

    let me = call(
        &fixture.router,
        "GET",
        "/api/account/me",
        &[("cookie", format!("__Host-weaver_session={session}"))],
        None,
    )
    .await;
    assert_eq!(
        me.body["level"], "certain",
        "a refusal leaves the session alone"
    );
    // The refusal sent nothing. (Checked before the `signs_in` probes below:
    // each password check now emails a sign-in code of its own, WVR-167.)
    assert_eq!(
        fixture.sent.lock().unwrap().len(),
        before,
        "a refusal emails nothing"
    );

    // The credential is unchanged.
    assert!(
        signs_in(&fixture, email, "correct horse battery").await,
        "the credential is unchanged"
    );
    assert!(
        !signs_in(&fixture, email, "a much better password").await,
        "the rejected password was not applied"
    );
}

/// A new password that fails the policy is refused on the new field, and the
/// refusal leaves the credential (and the session) alone so a retry works.
#[tokio::test]
async fn change_password_enforces_the_password_policy() {
    let fixture = setup().await;
    let email = "change-policy@example.com";
    register(&fixture, "Rémy", email, "correct horse battery").await;
    let (session, csrf) = sign_in(&fixture, email, "correct horse battery").await;

    let short = change_password(&fixture, &session, &csrf, "correct horse battery", "short").await;
    assert_eq!(short.status, StatusCode::BAD_REQUEST, "{:?}", short.body);
    assert_eq!(short.body["field"], "new_password");
    assert!(
        signs_in(&fixture, email, "correct horse battery").await,
        "a policy refusal changes nothing"
    );

    let ok = change_password(
        &fixture,
        &session,
        &csrf,
        "correct horse battery",
        "a much better password",
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.body);
}

/// A change ends *every* session: a second device signed in earlier is dead too.
#[tokio::test]
async fn change_password_revokes_a_second_session_too() {
    let fixture = setup().await;
    let email = "change-devices@example.com";
    register(&fixture, "Rémy", email, "correct horse battery").await;
    let (session, csrf) = sign_in(&fixture, email, "correct horse battery").await;
    let (other, _) = sign_in(&fixture, email, "correct horse battery").await;
    assert_ne!(session, other, "two distinct sessions");

    let reply = change_password(
        &fixture,
        &session,
        &csrf,
        "correct horse battery",
        "a much better password",
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);

    for cookie in [&session, &other] {
        let me = call(
            &fixture.router,
            "GET",
            "/api/account/me",
            &[("cookie", format!("__Host-weaver_session={cookie}"))],
            None,
        )
        .await;
        assert_eq!(me.body["level"], "none", "every session is revoked");
    }
}

/// The endpoint is authenticated and CSRF-protected: the level gate refuses a
/// request with no session before the handler runs, and a request that holds a
/// session but fails the same-origin/CSRF guard is refused by the handler.
#[tokio::test]
async fn change_password_requires_a_session_and_a_same_origin_csrf_request() {
    let fixture = setup().await;
    let email = "change-guard@example.com";
    register(&fixture, "Rémy", email, "correct horse battery").await;
    let (session, csrf) = sign_in(&fixture, email, "correct horse battery").await;
    let body = Some(serde_json::json!({
        "current_password": "correct horse battery",
        "new_password": "a much better password",
    }));

    // No cookies at all: the level gate refuses before the handler's guard runs.
    let bare = call(
        &fixture.router,
        "POST",
        "/api/account/password",
        &[],
        body.clone(),
    )
    .await;
    assert_eq!(bare.status, StatusCode::UNAUTHORIZED, "{:?}", bare.body);

    // A browser-declared cross-site fetch → 403.
    let cross_site = call(
        &fixture.router,
        "POST",
        "/api/account/password",
        &[
            ("sec-fetch-site", "cross-site".to_string()),
            (
                "cookie",
                format!("__Host-weaver_session={session}; __Host-weaver_csrf={csrf}"),
            ),
            ("x-csrf-token", csrf.clone()),
        ],
        body.clone(),
    )
    .await;
    assert_eq!(
        cross_site.status,
        StatusCode::FORBIDDEN,
        "{:?}",
        cross_site.body
    );

    // Same-origin but without the CSRF header → 403.
    let no_csrf = call(
        &fixture.router,
        "POST",
        "/api/account/password",
        &[(
            "cookie",
            format!("__Host-weaver_session={session}; __Host-weaver_csrf={csrf}"),
        )],
        body.clone(),
    )
    .await;
    assert_eq!(no_csrf.status, StatusCode::FORBIDDEN, "{:?}", no_csrf.body);

    // A well-formed CSRF pair with no session cookie → 401 (not signed in).
    let signed_out = call(
        &fixture.router,
        "POST",
        "/api/account/password",
        &[
            ("cookie", format!("__Host-weaver_csrf={csrf}")),
            ("x-csrf-token", csrf.clone()),
        ],
        body,
    )
    .await;
    assert_eq!(
        signed_out.status,
        StatusCode::UNAUTHORIZED,
        "{:?}",
        signed_out.body
    );

    // None of the refusals changed the password.
    assert!(signs_in(&fixture, email, "correct horse battery").await);
}

// ----- delete account ------------------------------------------------------

/// Posts a delete-account request with the double-submit CSRF pair attached.
/// The `confirm_password` step-up, with the double-submit CSRF pair attached.
async fn confirm_password(fixture: &Fixture, session: &str, csrf: &str, password: &str) -> Reply {
    call(
        &fixture.router,
        "POST",
        "/api/account/confirm-password",
        &[
            (
                "cookie",
                format!("__Host-weaver_session={session}; __Host-weaver_csrf={csrf}"),
            ),
            ("x-csrf-token", csrf.to_string()),
        ],
        Some(serde_json::json!({ "password": password })),
    )
    .await
}

async fn delete_account(fixture: &Fixture, session: &str, csrf: &str, address: &str) -> Reply {
    call(
        &fixture.router,
        "POST",
        "/api/account/delete",
        &[
            (
                "cookie",
                format!("__Host-weaver_session={session}; __Host-weaver_csrf={csrf}"),
            ),
            ("x-csrf-token", csrf.to_string()),
        ],
        Some(serde_json::json!({ "address": address })),
    )
    .await
}

/// The endpoint is authenticated and CSRF-protected exactly like `logout`: the
/// level gate refuses a request with no session before the handler runs, and a
/// request that holds a session but fails the same-origin/CSRF guard is refused
/// by the handler.
#[tokio::test]
async fn delete_account_requires_a_session_and_a_same_origin_csrf_request() {
    let fixture = setup().await;
    let email = "delete-guard@example.com";
    register(&fixture, "Rémy", email, "correct horse battery").await;
    let (session, csrf) = sign_in(&fixture, email, "correct horse battery").await;
    let body = Some(serde_json::json!({ "address": email }));

    // No cookies at all: the level gate refuses before the handler's guard runs.
    let bare = call(
        &fixture.router,
        "POST",
        "/api/account/delete",
        &[],
        body.clone(),
    )
    .await;
    assert_eq!(bare.status, StatusCode::UNAUTHORIZED, "{:?}", bare.body);

    // A browser-declared cross-site fetch → 403.
    let cross_site = call(
        &fixture.router,
        "POST",
        "/api/account/delete",
        &[
            ("sec-fetch-site", "cross-site".to_string()),
            (
                "cookie",
                format!("__Host-weaver_session={session}; __Host-weaver_csrf={csrf}"),
            ),
            ("x-csrf-token", csrf.clone()),
        ],
        body.clone(),
    )
    .await;
    assert_eq!(
        cross_site.status,
        StatusCode::FORBIDDEN,
        "{:?}",
        cross_site.body
    );

    // Same-origin but without the CSRF header → 403.
    let no_csrf = call(
        &fixture.router,
        "POST",
        "/api/account/delete",
        &[(
            "cookie",
            format!("__Host-weaver_session={session}; __Host-weaver_csrf={csrf}"),
        )],
        body.clone(),
    )
    .await;
    assert_eq!(no_csrf.status, StatusCode::FORBIDDEN, "{:?}", no_csrf.body);

    // A well-formed CSRF pair with no session cookie → 401 (not signed in).
    let signed_out = call(
        &fixture.router,
        "POST",
        "/api/account/delete",
        &[
            ("cookie", format!("__Host-weaver_csrf={csrf}")),
            ("x-csrf-token", csrf.clone()),
        ],
        body,
    )
    .await;
    assert_eq!(
        signed_out.status,
        StatusCode::UNAUTHORIZED,
        "{:?}",
        signed_out.body
    );

    // None of the refusals touched the account.
    let me = call(
        &fixture.router,
        "GET",
        "/api/account/me",
        &[("cookie", format!("__Host-weaver_session={session}"))],
        None,
    )
    .await;
    assert_eq!(
        me.body["level"], "certain",
        "the account survives a refused delete: {:?}",
        me.body
    );
}

/// Deleting needs `Certain`: the password proven moments ago, not merely a
/// second factor passed earlier in the session. The refusal names the level and
/// the step, the step lifts the level, and the retry goes through.
#[tokio::test]
async fn deleting_needs_a_recent_password() {
    use sea_orm::ConnectionTrait as _;

    let fixture = setup().await;
    let email = "step-up@example.com";
    register(&fixture, "Rémy", email, "correct horse battery").await;
    let (session, csrf) = sign_in(&fixture, email, "correct horse battery").await;

    // A sign-in proves the password, so the session starts `Certain` and the
    // gate lets the delete through — this is a fresh credential, not a bypass.
    let state = me(&fixture, &session).await;
    assert_eq!(state.body["level"], "certain");

    // Let the password proof age out; the session is `Strong` again.
    fixture
        .account
        .store
        .db()
        .execute_unprepared(
            "UPDATE auth_event SET occurred_at = occurred_at - 600 \
             WHERE kind IN ('password', 'password_confirmed')",
        )
        .await
        .unwrap();
    let state = me(&fixture, &session).await;
    assert_eq!(state.body["level"], "strong");
    assert_eq!(state.body["drop"]["to"], "none");

    // The delete is refused, naming the level and the way back up.
    let refused = delete_account(&fixture, &session, &csrf, email).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{:?}", refused.body);
    assert_eq!(refused.headers["x-weaver-required-level"], "certain");
    assert_eq!(
        refused.headers["x-weaver-upgrade-paths"],
        r#"[[{"step":"confirm_password","reaches":"certain"}]]"#
    );

    // A wrong password is refused on the field and lifts nothing.
    let wrong = confirm_password(&fixture, &session, &csrf, "not my password").await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST, "{:?}", wrong.body);
    assert_eq!(wrong.body["field"], "password");
    assert_eq!(me(&fixture, &session).await.body["level"], "strong");
    let still_refused = delete_account(&fixture, &session, &csrf, email).await;
    assert_eq!(still_refused.status, StatusCode::FORBIDDEN);

    // The refusal is on the trail as an event of its own.
    let trail = || async {
        fixture
            .account
            .store
            .db()
            .query_all_raw(sea_orm::Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                "SELECT kind FROM auth_event ORDER BY id",
            ))
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.try_get::<String>("", "kind").unwrap())
            .collect::<Vec<String>>()
    };
    let kinds = trail().await;
    assert!(
        kinds.contains(&"password_confirm_failed".to_string()),
        "{kinds:?}"
    );

    // The right password lifts it, and the delete then goes through.
    let confirmed = confirm_password(&fixture, &session, &csrf, "correct horse battery").await;
    assert_eq!(confirmed.status, StatusCode::OK, "{:?}", confirmed.body);
    let state = me(&fixture, &session).await;
    assert_eq!(state.body["level"], "certain");
    // Read before the delete: removing the account takes its trail with it.
    let kinds = trail().await;
    assert!(
        kinds.contains(&"password_confirmed".to_string()),
        "{kinds:?}"
    );

    let deleted = delete_account(&fixture, &session, &csrf, email).await;
    assert_eq!(deleted.status, StatusCode::OK, "{:?}", deleted.body);
}

/// The typed address is the control, not the client-side convenience: a wrong
/// one is refused server-side, and casing/whitespace around the real address
/// still match. A successful delete clears both cookies and ends every session.
#[tokio::test]
async fn delete_account_re_checks_the_address_and_lands_the_owner_signed_out() {
    let fixture = setup().await;
    let email = "delete@example.com";
    register(&fixture, "Rémy", email, "correct horse battery").await;
    let (session, csrf) = sign_in(&fixture, email, "correct horse battery").await;

    // A wrong address is refused even though the request is otherwise valid.
    let wrong = delete_account(&fixture, &session, &csrf, "someone-else@example.com").await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN, "{:?}", wrong.body);

    // An omitted address field is a refusal of the same shape, not a 422.
    let missing = call(
        &fixture.router,
        "POST",
        "/api/account/delete",
        &[
            (
                "cookie",
                format!("__Host-weaver_session={session}; __Host-weaver_csrf={csrf}"),
            ),
            ("x-csrf-token", csrf.clone()),
        ],
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(missing.status, StatusCode::FORBIDDEN, "{:?}", missing.body);

    // Surrounding whitespace and different casing are the same address.
    let reply = delete_account(&fixture, &session, &csrf, "  DELETE@Example.com  ").await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    assert_eq!(
        reply.cookie("__Host-weaver_session"),
        Some(String::new()),
        "the session cookie is cleared"
    );
    assert_eq!(
        reply.cookie("__Host-weaver_csrf"),
        Some(String::new()),
        "the CSRF cookie is cleared too"
    );

    // The session no longer authenticates, and the account is really gone.
    let me = call(
        &fixture.router,
        "GET",
        "/api/account/me",
        &[("cookie", format!("__Host-weaver_session={session}"))],
        None,
    )
    .await;
    assert_eq!(me.body["level"], "none", "a delete ends every session");
    assert!(
        !signs_in(&fixture, email, "correct horse battery").await,
        "the account is gone"
    );

    // A repeat with the same (now dead) session is refused as unauthenticated;
    // the store test covers the idempotency of the underlying delete.
    let again = delete_account(&fixture, &session, &csrf, email).await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED, "{:?}", again.body);
}

// ----- pairing --------------------------------------------------------------
//
// The CLI side is a real WebSocket over an in-memory duplex pipe, served by the
// same `serve_channel` the edge spawns; it solves the relay's proof of work
// with the engine's test solver. The browser side is the account router.

use tokio::io::DuplexStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::Role;
use weaver_mux::KeyId;
use weaver_proto::pair::{
    self, Begin, FailureCode, LookupResponse, Proposed, ServerMessage, Target,
};
use weaver_server::account::pairing;

/// A device key: a real P-256 public key.
fn device_key(seed: u64) -> KeyId {
    use weaver_mux::auth::Signer as _;
    weaver_mux::testing::P256TestSigner::from_seed(seed).key_id()
}

/// The CLI end of a pairing channel.
struct Cli {
    ws: WebSocketStream<DuplexStream>,
}

impl Cli {
    /// Opens a channel against the fixture's relay.
    async fn open(fixture: &Fixture) -> Self {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let account = Arc::clone(&fixture.account);
        let peer = pairing::Peer {
            guard: Arc::clone(&fixture.guard),
            addr: SocketAddr::from(([192, 0, 2, 7], 40_000)),
        };
        tokio::spawn(async move {
            let ws = WebSocketStream::from_raw_socket(
                server,
                Role::Server,
                Some(pairing::channel_config()),
            )
            .await;
            pairing::serve_channel(ws, account, peer).await;
        });
        Self {
            ws: WebSocketStream::from_raw_socket(client, Role::Client, None).await,
        }
    }

    async fn recv(&mut self) -> ServerMessage {
        use futures_util::StreamExt as _;
        loop {
            let message = tokio::time::timeout(std::time::Duration::from_secs(30), self.ws.next())
                .await
                .expect("the relay answers")
                .expect("the channel is open")
                .expect("a WebSocket message");
            if let Message::Text(text) = message {
                return serde_json::from_str(&text).expect("a server message");
            }
        }
    }

    async fn send_text(&mut self, text: String) {
        use futures_util::SinkExt as _;
        self.ws.send(Message::Text(text.into())).await.unwrap();
    }

    async fn challenge(&mut self) -> Challenge {
        match self.recv().await {
            ServerMessage::Challenge { challenge } => challenge,
            other => panic!("the relay must speak first with a challenge, got {other:?}"),
        }
    }

    async fn begin(&mut self, proof: Payload, key_id: KeyId, target: Target) {
        let begin = Begin {
            proof,
            key_id,
            target,
        };
        self.send_text(serde_json::to_string(&begin).unwrap()).await;
    }

    /// Challenge, solve, `Begin`: the relay's next message.
    async fn pair(fixture: &Fixture, key_id: KeyId, target: Target) -> (Self, ServerMessage) {
        let mut cli = Self::open(fixture).await;
        let challenge = cli.challenge().await;
        let proof = solve(challenge).await;
        cli.begin(proof, key_id, target).await;
        let next = cli.recv().await;
        (cli, next)
    }

    /// Like [`Cli::pair`], expecting a handle.
    async fn handle(fixture: &Fixture, key_id: KeyId, target: Target) -> (Self, String) {
        match Self::pair(fixture, key_id, target).await {
            (cli, ServerMessage::Handle { handle }) => (cli, handle),
            (_, other) => panic!("expected a handle, got {other:?}"),
        }
    }
}

async fn solve(challenge: Challenge) -> Payload {
    tokio::task::spawn_blocking(move || Payload {
        solution: solve_challenge(&challenge),
        challenge,
    })
    .await
    .unwrap()
}

/// A signed-in browser.
struct Browser {
    session: String,
    csrf: String,
}

impl Browser {
    async fn new(fixture: &Fixture, name: &str, email: &str) -> Self {
        register(fixture, name, email, "correct horse battery").await;
        let (session, csrf) = sign_in(fixture, email, "correct horse battery").await;
        Self { session, csrf }
    }

    async fn post(&self, fixture: &Fixture, path: &str, body: serde_json::Value) -> Reply {
        call(
            &fixture.router,
            "POST",
            path,
            &[
                (
                    "cookie",
                    format!(
                        "__Host-weaver_session={}; __Host-weaver_csrf={}",
                        self.session, self.csrf
                    ),
                ),
                ("x-csrf-token", self.csrf.clone()),
            ],
            Some(body),
        )
        .await
    }

    async fn get(&self, fixture: &Fixture, path: &str) -> Reply {
        call(
            &fixture.router,
            "GET",
            path,
            &[(
                "cookie",
                format!(
                    "__Host-weaver_session={}; __Host-weaver_csrf={}",
                    self.session, self.csrf
                ),
            )],
            None,
        )
        .await
    }

    async fn lookup(&self, fixture: &Fixture, handle: &str) -> LookupResponse {
        let reply = self
            .post(
                fixture,
                pair::PAIR_LOOKUP_PATH,
                serde_json::json!({ "handle": handle }),
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        serde_json::from_value(reply.body).expect("a lookup response")
    }

    async fn accept(&self, fixture: &Fixture, body: serde_json::Value) -> serde_json::Value {
        let reply = self.post(fixture, pair::PAIR_ACCEPT_PATH, body).await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        reply.body
    }

    async fn reject(&self, fixture: &Fixture, handle: &str) -> serde_json::Value {
        let reply = self
            .post(
                fixture,
                pair::PAIR_REJECT_PATH,
                serde_json::json!({ "handle": handle }),
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        reply.body
    }
}

fn failure(message: ServerMessage) -> FailureCode {
    match message {
        ServerMessage::Failed { code, .. } => code,
        other => panic!("expected a failure, got {other:?}"),
    }
}

/// Pairs a new machine for `browser`'s account and returns its id.
async fn pair_new(fixture: &Fixture, browser: &Browser, key_id: KeyId, person_slug: &str) -> i32 {
    let (mut cli, handle) = Cli::handle(
        fixture,
        key_id,
        Target::New {
            hostname: "laptop".into(),
        },
    )
    .await;
    let reply = browser
        .accept(
            fixture,
            serde_json::json!({ "handle": handle, "person_slug": person_slug }),
        )
        .await;
    assert_eq!(reply, serde_json::json!({ "ok": true, "message": "" }));
    match cli.recv().await {
        ServerMessage::Approved { machine_id, .. } => machine_id,
        other => panic!("expected approval, got {other:?}"),
    }
}

#[tokio::test]
async fn pairing_proves_work_before_anything_else() {
    let fixture = setup().await;
    let browser = Browser::new(&fixture, "Alice", "alice@example.com").await;
    let paired = device_key(1);
    pair_new(&fixture, &browser, paired, "alice").await;

    // A wrong solution for an already-paired key: the proof is what is
    // refused, so the channel says nothing about the key.
    let mut cli = Cli::open(&fixture).await;
    let challenge = cli.challenge().await;
    let mut proof = solve(challenge).await;
    proof.solution.counter = proof.solution.counter.wrapping_add(1);
    cli.begin(proof, paired, Target::Existing { machine_id: 9_999 })
        .await;
    assert_eq!(failure(cli.recv().await), FailureCode::BadProof);

    // A proof solved for another channel's challenge is not this channel's.
    let mut other = Cli::open(&fixture).await;
    let foreign = solve(other.challenge().await).await;
    let mut cli = Cli::open(&fixture).await;
    let _ours = cli.challenge().await;
    cli.begin(
        foreign,
        device_key(2),
        Target::New {
            hostname: "x".into(),
        },
    )
    .await;
    assert_eq!(failure(cli.recv().await), FailureCode::BadProof);

    // With a good proof, the known key is reported as paired.
    let (_cli, next) = Cli::pair(
        &fixture,
        paired,
        Target::New {
            hostname: "x".into(),
        },
    )
    .await;
    assert_eq!(failure(next), FailureCode::AlreadyPaired);

    // Garbage instead of a `Begin`.
    let mut cli = Cli::open(&fixture).await;
    let _ = cli.challenge().await;
    cli.send_text("{\"nope\":1}".into()).await;
    assert_eq!(failure(cli.recv().await), FailureCode::BadRequest);

    assert!(fixture.account.pairings.is_empty());
}

#[tokio::test]
async fn pairing_refuses_malformed_keys_after_the_proof() {
    let fixture = setup().await;
    let (_cli, next) = Cli::pair(
        &fixture,
        KeyId::P256([0x07; 33]),
        Target::New {
            hostname: "laptop".into(),
        },
    )
    .await;
    assert_eq!(failure(next), FailureCode::BadKey);
}

#[tokio::test]
async fn pairing_charges_the_pairing_budget_once_the_proof_is_in() {
    let fixture = setup_with(|account| {
        account.pair = weaver_server::config::BudgetConfig {
            burst: 1,
            refill_units: 1,
            refill_per_secs: 3_600,
        };
    })
    .await;
    let (_first, _) = Cli::handle(
        &fixture,
        device_key(1),
        Target::New {
            hostname: "a".into(),
        },
    )
    .await;
    let (_second, next) = Cli::pair(
        &fixture,
        device_key(2),
        Target::New {
            hostname: "b".into(),
        },
    )
    .await;
    assert_eq!(failure(next), FailureCode::Throttled);
}

#[tokio::test]
async fn pairing_a_new_machine_creates_the_person_and_the_machine() {
    let fixture = setup().await;
    let browser = Browser::new(&fixture, "Rémy Sanchez", "remy@example.com").await;
    let key = device_key(1);
    let (mut cli, handle) = Cli::handle(
        &fixture,
        key,
        Target::New {
            hostname: "Rémys-MacBook-Pro.local".into(),
        },
    )
    .await;

    assert_eq!(
        browser.lookup(&fixture, &handle).await,
        LookupResponse::Waiting {
            fingerprint: key.to_string(),
            account: "Rémy Sanchez".into(),
            person: Proposed {
                name: "remysanchez".into(),
                is_new: true
            },
            machine: Proposed {
                name: "remysmacbookpro".into(),
                is_new: true
            },
        }
    );

    // A new person needs a name; the request keeps waiting until it has one.
    let refused = browser
        .accept(&fixture, serde_json::json!({ "handle": handle }))
        .await;
    assert_eq!(refused["ok"], false);
    assert!(refused["message"].as_str().unwrap().contains("person name"));
    let refused = browser
        .accept(
            &fixture,
            serde_json::json!({ "handle": handle, "person_slug": "Not-Valid" }),
        )
        .await;
    assert_eq!(refused["ok"], false);
    assert!(matches!(
        browser.lookup(&fixture, &handle).await,
        LookupResponse::Waiting { .. }
    ));

    let accepted = browser
        .accept(
            &fixture,
            serde_json::json!({ "handle": handle, "person_slug": "remy", "machine_name": "Mac Book" }),
        )
        .await;
    assert_eq!(accepted, serde_json::json!({ "ok": true, "message": "" }));
    let ServerMessage::Approved {
        machine_id,
        person,
        machine,
    } = cli.recv().await
    else {
        panic!("expected approval");
    };
    assert_eq!((person.as_str(), machine.as_str()), ("remy", "macbook"));

    let store = &fixture.account.store;
    let (owner, paired) = store.machine_by_key(&key).await.unwrap().unwrap();
    assert_eq!((owner.name.as_str(), paired.id), ("remy", machine_id));

    // The handle is spent.
    assert_eq!(
        browser.lookup(&fixture, &handle).await,
        LookupResponse::Gone
    );

    // The second machine reuses the person, which can no longer be renamed here.
    let (mut cli, handle) = Cli::handle(
        &fixture,
        device_key(2),
        Target::New {
            hostname: "macbook".into(),
        },
    )
    .await;
    let LookupResponse::Waiting {
        person, machine, ..
    } = browser.lookup(&fixture, &handle).await
    else {
        panic!("expected a waiting pairing");
    };
    assert_eq!(
        (person, machine),
        (
            Proposed {
                name: "remy".into(),
                is_new: false
            },
            Proposed {
                name: "macbook2".into(),
                is_new: true
            }
        )
    );
    let refused = browser
        .accept(
            &fixture,
            serde_json::json!({ "handle": handle, "person_slug": "other" }),
        )
        .await;
    assert_eq!(refused["ok"], false);
    let accepted = browser
        .accept(&fixture, serde_json::json!({ "handle": handle }))
        .await;
    assert_eq!(accepted, serde_json::json!({ "ok": true, "message": "" }));
    assert!(matches!(
        cli.recv().await,
        ServerMessage::Approved { machine, .. } if machine == "macbook2"
    ));
}

#[tokio::test]
async fn pairing_an_existing_machine_moves_it_onto_the_new_key() {
    let fixture = setup().await;
    let browser = Browser::new(&fixture, "Alice", "alice@example.com").await;
    let old = device_key(1);
    let machine_id = pair_new(&fixture, &browser, old, "alice").await;

    let new = device_key(2);
    let (mut cli, handle) = Cli::handle(&fixture, new, Target::Existing { machine_id }).await;
    let LookupResponse::Waiting {
        person, machine, ..
    } = browser.lookup(&fixture, &handle).await
    else {
        panic!("expected a waiting pairing");
    };
    assert_eq!(
        (person, machine),
        (
            Proposed {
                name: "alice".into(),
                is_new: false
            },
            Proposed {
                name: "laptop".into(),
                is_new: false
            }
        )
    );
    let refused = browser
        .accept(
            &fixture,
            serde_json::json!({ "handle": handle, "machine_name": "renamed" }),
        )
        .await;
    assert_eq!(refused["ok"], false, "an existing machine keeps its name");

    let accepted = browser
        .accept(&fixture, serde_json::json!({ "handle": handle }))
        .await;
    assert_eq!(accepted, serde_json::json!({ "ok": true, "message": "" }));
    assert_eq!(
        cli.recv().await,
        ServerMessage::Approved {
            machine_id,
            person: "alice".into(),
            machine: "laptop".into()
        }
    );
    let store = &fixture.account.store;
    assert!(store.machine_by_key(&old).await.unwrap().is_none());
    assert_eq!(
        store.machine_by_key(&new).await.unwrap().unwrap().1.id,
        machine_id
    );
}

#[tokio::test]
async fn pairing_someone_elses_machine_is_refused() {
    let fixture = setup().await;
    let alice = Browser::new(&fixture, "Alice", "alice@example.com").await;
    let alice_key = device_key(1);
    let machine_id = pair_new(&fixture, &alice, alice_key, "alice").await;
    let mallory = Browser::new(&fixture, "Mallory", "mallory@example.com").await;

    // Mallory's browser is told it is not hers, and cannot accept it anyway.
    let (mut cli, handle) =
        Cli::handle(&fixture, device_key(2), Target::Existing { machine_id }).await;
    assert_eq!(
        mallory.lookup(&fixture, &handle).await,
        LookupResponse::NotYourMachine
    );
    let refused = mallory
        .accept(
            &fixture,
            serde_json::json!({ "handle": handle, "person_slug": "mallory" }),
        )
        .await;
    assert_eq!(refused["ok"], false);
    let refused = mallory
        .accept(&fixture, serde_json::json!({ "handle": handle }))
        .await;
    assert_eq!(refused["ok"], false);
    assert_eq!(failure(cli.recv().await), FailureCode::NotYourMachine);
    assert_eq!(
        fixture
            .account
            .store
            .machine_by_key(&alice_key)
            .await
            .unwrap()
            .unwrap()
            .1
            .id,
        machine_id,
        "alice's machine keeps its key"
    );

    // A machine id that does not exist looks exactly the same.
    let (_cli, handle) = Cli::handle(
        &fixture,
        device_key(3),
        Target::Existing { machine_id: 9_999 },
    )
    .await;
    assert_eq!(
        alice.lookup(&fixture, &handle).await,
        LookupResponse::NotYourMachine
    );
}

#[tokio::test]
async fn pairing_rejected_in_the_browser_tells_the_cli() {
    let fixture = setup().await;
    let browser = Browser::new(&fixture, "Alice", "alice@example.com").await;
    let (mut cli, handle) = Cli::handle(
        &fixture,
        device_key(1),
        Target::New {
            hostname: "laptop".into(),
        },
    )
    .await;
    assert_eq!(
        browser.reject(&fixture, &handle).await,
        serde_json::json!({ "ok": true, "message": "" })
    );
    assert_eq!(failure(cli.recv().await), FailureCode::Rejected);
    assert_eq!(
        browser.lookup(&fixture, &handle).await,
        LookupResponse::Gone
    );
    assert_eq!(browser.reject(&fixture, &handle).await["ok"], false);
    assert!(
        fixture
            .account
            .store
            .machine_by_key(&device_key(1))
            .await
            .unwrap()
            .is_none()
    );
}

// ----- machines -------------------------------------------------------------

/// Signs in a fresh account and seeds it a person with one machine serving one
/// hostname, so the machines endpoints have something to answer with. Returns
/// the signed-in browser, the person id and the machine id.
async fn machines_fixture(fixture: &Fixture) -> (Browser, i32, i32) {
    let browser = Browser::new(fixture, "Rémy", "remy@example.com").await;
    let me = browser.get(fixture, "/api/account/me").await;
    assert_eq!(me.status, StatusCode::OK, "{:?}", me.body);
    let account_id = me.body["me"]["id"].as_i64().expect("account id") as i32;

    let store = &fixture.account.store;
    let person = store
        .create_person(account_id, "remy")
        .await
        .expect("person");
    let machine = store
        .create_machine(person.id, "laptop", &KeyId::P256([7; 33]))
        .await
        .expect("machine");
    store
        .register_declared_service(machine.id, "remy-laptop-web.weaver.test", "web")
        .await
        .expect("service");
    (browser, person.id, machine.id)
}

#[tokio::test]
async fn machines_list_and_detail_describe_the_persons_machines() {
    let fixture = setup().await;
    let (browser, _person, machine_id) = machines_fixture(&fixture).await;

    let list = browser.get(&fixture, "/api/account/machines").await;
    assert_eq!(list.status, StatusCode::OK, "{:?}", list.body);
    let machines = list.body["machines"].as_array().expect("machines array");
    assert_eq!(machines.len(), 1);
    let machine = &machines[0];
    assert_eq!(machine["id"].as_i64().unwrap(), machine_id as i64);
    assert_eq!(machine["name"], "laptop");
    assert_eq!(machine["online"], false, "no registry means offline");
    assert_eq!(machine["last_seen_at"], serde_json::Value::Null);
    assert_eq!(machine["fingerprint"], KeyId::P256([7; 33]).to_string());
    let services = machine["services"].as_array().expect("services");
    assert_eq!(services.len(), 1);
    assert_eq!(services[0]["name"], "web");
    assert_eq!(
        services[0]["hostnames"][0], "remy-laptop-web.weaver.test",
        "the list shows the hostname the relay actually serves"
    );

    let detail = browser
        .get(&fixture, &format!("/api/account/machines/{machine_id}"))
        .await;
    assert_eq!(detail.status, StatusCode::OK, "{:?}", detail.body);
    assert_eq!(detail.body["name"], "laptop");
    assert_eq!(detail.body["fingerprint"], KeyId::P256([7; 33]).to_string());
}

#[tokio::test]
async fn machines_are_private_to_their_person() {
    let fixture = setup().await;
    let (_owner, _person, machine_id) = machines_fixture(&fixture).await;

    let other = Browser::new(&fixture, "Bob", "bob@example.com").await;
    // Another account has no person yet, so it sees an empty list.
    let list = other.get(&fixture, "/api/account/machines").await;
    assert_eq!(list.status, StatusCode::OK, "{:?}", list.body);
    assert!(list.body["machines"].as_array().unwrap().is_empty());

    // Asking for someone else's machine is a 404, not a leak.
    let detail = other
        .get(&fixture, &format!("/api/account/machines/{machine_id}"))
        .await;
    assert_eq!(detail.status, StatusCode::NOT_FOUND, "{:?}", detail.body);
}

#[tokio::test]
async fn machines_require_a_session_and_csrf() {
    let fixture = setup().await;
    let (browser, _person, machine_id) = machines_fixture(&fixture).await;

    let anonymous = call(&fixture.router, "GET", "/api/account/machines", &[], None).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);

    // A state change without the CSRF token is refused.
    let no_csrf = call(
        &fixture.router,
        "POST",
        &format!("/api/account/machines/{machine_id}/rename"),
        &[(
            "cookie",
            format!("__Host-weaver_session={}", browser.session),
        )],
        Some(serde_json::json!({ "name": "rig" })),
    )
    .await;
    assert_eq!(no_csrf.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn renaming_a_machine_is_validated_and_refused_on_collision() {
    let fixture = setup().await;
    let (browser, person, machine_id) = machines_fixture(&fixture).await;
    fixture
        .account
        .store
        .create_machine(person, "desktop", &KeyId::P256([8; 33]))
        .await
        .unwrap();

    // A name this person already uses is a conflict.
    let collision = browser
        .post(
            &fixture,
            &format!("/api/account/machines/{machine_id}/rename"),
            serde_json::json!({ "name": "desktop" }),
        )
        .await;
    assert_eq!(
        collision.status,
        StatusCode::CONFLICT,
        "{:?}",
        collision.body
    );

    // A name that breaks the label rules is a bad request.
    let invalid = browser
        .post(
            &fixture,
            &format!("/api/account/machines/{machine_id}/rename"),
            serde_json::json!({ "name": "Not A Name" }),
        )
        .await;
    assert_eq!(
        invalid.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        invalid.body
    );

    // Neither attempt changed anything.
    let detail = browser
        .get(&fixture, &format!("/api/account/machines/{machine_id}"))
        .await;
    assert_eq!(detail.body["name"], "laptop");
}

#[tokio::test]
async fn renaming_a_machine_moves_its_hostname_at_once() {
    let fixture = setup().await;
    let (browser, _person, machine_id) = machines_fixture(&fixture).await;

    let renamed = browser
        .post(
            &fixture,
            &format!("/api/account/machines/{machine_id}/rename"),
            serde_json::json!({ "name": "Rig" }),
        )
        .await;
    assert_eq!(renamed.status, StatusCode::OK, "{:?}", renamed.body);
    assert_eq!(renamed.body["ok"], true);
    assert_eq!(renamed.body["name"], "rig", "names are lowercased");

    // The machine's hostname is re-derived, and the old one stops serving.
    let detail = browser
        .get(&fixture, &format!("/api/account/machines/{machine_id}"))
        .await;
    assert_eq!(
        detail.body["services"][0]["hostnames"][0],
        "remy-rig-web.weaver.test"
    );
    assert!(
        fixture
            .account
            .store
            .get_domain("remy-laptop-web.weaver.test")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn revoking_a_machine_removes_it_and_frees_its_hostname() {
    let fixture = setup().await;
    let (browser, _person, machine_id) = machines_fixture(&fixture).await;

    let revoked = browser
        .post(
            &fixture,
            &format!("/api/account/machines/{machine_id}/revoke"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(revoked.status, StatusCode::OK, "{:?}", revoked.body);
    assert_eq!(revoked.body["ok"], true);

    let list = browser.get(&fixture, "/api/account/machines").await;
    assert!(list.body["machines"].as_array().unwrap().is_empty());
    // The domain row survives with no service, so the hostname stops resolving.
    assert!(
        fixture
            .account
            .store
            .get_domain("remy-laptop-web.weaver.test")
            .await
            .unwrap()
            .unwrap()
            .service_id
            .is_none()
    );
}

#[tokio::test]
async fn machines_report_their_metered_usage() {
    use sea_orm::ConnectionTrait as _;
    use weaver_server::metrics::encode_blob;

    let fixture = setup().await;
    let (browser, _person, machine_id) = machines_fixture(&fixture).await;
    let store = &fixture.account.store;
    let service = store
        .get_or_create_service(machine_id, "web")
        .await
        .unwrap();
    // One day inside the window, with real bytes and requests. The console reads
    // the wide day rollup, which the flush maintains; the total columns are all
    // the traffic figures need. The detail view also reads `open_ms_minutes`
    // back to report when the machine was last seen, so the presence blobs must
    // be real frames, not the empty stand-ins the totals alone would tolerate:
    // an empty `open_ms_minutes` is corrupt and fails the read. One open minute
    // carrying the day's 60 000 ms keeps the total column and the array in step.
    let day = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 86_400) as i64;
    let mut open_minutes = vec![0_i64; 1440];
    open_minutes[0] = 60_000;
    let open_minutes_blob = hex(&encode_blob(&open_minutes));
    let mut open_hours = vec![0_i64; 24];
    open_hours[0] = 60_000;
    let open_hours_blob = hex(&encode_blob(&open_hours));
    store
        .db()
        .execute_unprepared(&format!(
            "INSERT INTO usage_daily (service_id, day, bytes_in, bytes_in_hours, bytes_in_minutes, \
                bytes_out, bytes_out_hours, bytes_out_minutes, tunnel_in, tunnel_in_hours, tunnel_in_minutes, \
                tunnel_out, tunnel_out_hours, tunnel_out_minutes, requests, requests_hours, requests_minutes, \
                open_ms, open_ms_hours, open_ms_minutes) VALUES \
             ({}, {}, 500, X'', X'', 1000, X'', X'', 20, X'', X'', 30, X'', X'', 7, X'', X'', 60000, X'{open_hours_blob}', X'{open_minutes_blob}')",
            service.id, day
        ))
        .await
        .unwrap();

    let detail = browser
        .get(&fixture, &format!("/api/account/machines/{machine_id}"))
        .await;
    assert_eq!(detail.status, StatusCode::OK, "{:?}", detail.body);
    assert_eq!(detail.body["usage_30d"]["bytes_in"], 500);
    assert_eq!(detail.body["usage_30d"]["bytes_out"], 1000);
    assert_eq!(detail.body["usage_30d"]["requests"], 7);

    // The list carries the same figures.
    let list = browser.get(&fixture, "/api/account/machines").await;
    assert_eq!(list.body["machines"][0]["usage_30d"]["bytes_out"], 1000);
}

#[tokio::test]
async fn metrics_endpoint_returns_a_self_scoped_series() {
    use sea_orm::ConnectionTrait as _;
    use weaver_server::metrics::encode_blob;

    let fixture = setup().await;
    let (browser, _person_id, machine_id) = machines_fixture(&fixture).await;
    let store = &fixture.account.store;
    let mine = store
        .get_or_create_service(machine_id, "web")
        .await
        .unwrap();

    // Another person's machine and service, which must never be returned.
    let other_account = store.create_test_person("mallory").await.unwrap();
    let other_machine = store
        .create_machine(
            other_account.id,
            "desktop",
            &weaver_mux::KeyId::P256([9; 33]),
        )
        .await
        .unwrap();
    let theirs = store
        .get_or_create_service(other_machine.id, "web")
        .await
        .unwrap();

    // A folded day for each service: 500 bytes for mine, 999 for theirs. The
    // hour grain reads the hourly blob, so put the bytes in hour 0 of it.
    let day = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 86_400) as i64;
    for (service_id, bytes) in [(mine.id, 500_i64), (theirs.id, 999_i64)] {
        let mut hours = vec![0_i64; 24];
        hours[0] = bytes;
        let hours_blob = hex(&encode_blob(&hours));
        store
            .db()
            .execute_unprepared(&format!(
                "INSERT INTO usage_daily (service_id, day, bytes_in, bytes_in_hours, bytes_in_minutes, \
                    bytes_out, bytes_out_hours, bytes_out_minutes, tunnel_in, tunnel_in_hours, tunnel_in_minutes, \
                    tunnel_out, tunnel_out_hours, tunnel_out_minutes, requests, requests_hours, requests_minutes, \
                    open_ms, open_ms_hours, open_ms_minutes) VALUES \
                 ({service_id}, {day}, {bytes}, X'{hours_blob}', X'', 0, X'', X'', 0, X'', X'', 0, X'', X'', \
                  0, X'', X'', 0, X'', X'')"
            ))
            .await
            .unwrap();
    }

    // Ask for both services: the other person's is dropped, not returned.
    let from = day * 86_400;
    let to = (day + 1) * 86_400;
    let reply = browser
        .get(
            &fixture,
            &format!(
                "/api/account/metrics?services={},{}&metrics=bytes_in&from={from}&to={to}",
                mine.id, theirs.id
            ),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    assert_eq!(reply.body["function"], "sum");
    assert_eq!(reply.body["granularity"], 3600, "a day window is hour-wide");
    assert_eq!(reply.body["from"], from);
    assert_eq!(reply.body["to"], to);
    let series = reply.body["series"].as_array().expect("series");
    assert_eq!(
        series.len(),
        1,
        "only the signed-in person's service is returned"
    );
    assert_eq!(series[0]["service_id"], mine.id);
    assert_eq!(series[0]["metric"], "bytes_in");
    assert_eq!(
        series[0]["total"], 500,
        "the other person's 999 is never read"
    );
    assert_eq!(
        series[0]["slots"].as_array().unwrap().len(),
        24,
        "the hour slot the bytes fall in"
    );

    // An unknown metric is a 400, not an empty series.
    let bad = browser
        .get(
            &fixture,
            &format!(
                "/api/account/metrics?services={}&metrics=nonsense&from={from}&to={to}",
                mine.id
            ),
        )
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST, "{:?}", bad.body);
    assert!(
        bad.body["error"]
            .as_str()
            .is_some_and(|message| message.contains("nonsense")),
        "the refusal names the bad metric"
    );

    // `from`/`to` also accept `YYYY-MM-DD` (midnight UTC).
    let dated = browser
        .get(
            &fixture,
            &format!(
                "/api/account/metrics?services={}&metrics=bytes_in&from=2020-01-01&to=2020-01-02",
                mine.id
            ),
        )
        .await;
    assert_eq!(dated.status, StatusCode::OK, "{:?}", dated.body);
    assert_eq!(dated.body["from"], 1_577_836_800);
    assert_eq!(dated.body["to"], 1_577_923_200);
    assert_eq!(
        dated.body["series"][0]["total"], 0,
        "nothing was metered in 2020"
    );

    // A date that does not parse is a 400.
    let bad_date = browser
        .get(
            &fixture,
            &format!("/api/account/metrics?services={}&from=not-a-date", mine.id),
        )
        .await;
    assert_eq!(
        bad_date.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        bad_date.body
    );
}

#[tokio::test]
async fn disconnecting_an_offline_machine_is_a_no_op() {
    let fixture = setup().await;
    let (browser, _person, machine_id) = machines_fixture(&fixture).await;

    let reply = browser
        .post(
            &fixture,
            &format!("/api/account/machines/{machine_id}/disconnect"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
    assert_eq!(reply.body["ok"], true);
    assert_eq!(
        reply.body["disconnected"], false,
        "there is no live connection to drop"
    );
}

// ---------------------------------------------------------------------------
// Inactivity sweep (WVR-160).
// ---------------------------------------------------------------------------

/// A fixture tuned to a tiny inactivity timeline: warn at 500 s idle, delete at
/// 1000 s. Real sign-ups activate "now", so a sweep time a little in the future
/// keeps the account past its activation while staying in the same second-scale.
async fn inactivity_fixture() -> Fixture {
    setup_with(|cfg| {
        cfg.inactive_after_secs = 1000;
        cfg.inactivity_warning_before_secs = 500;
    })
    .await
}

/// The account id behind a registered address.
async fn account_id_for(fixture: &Fixture, email: &str) -> i32 {
    fixture
        .account
        .store
        .email_identity_find(email)
        .await
        .unwrap()
        .expect("the address has an account")
        .account_id
}

#[tokio::test]
async fn inactivity_sweep_warns_once_then_deletes() {
    let fixture = inactivity_fixture().await;
    register(
        &fixture,
        "Idle",
        "idle@example.com",
        "correct horse battery",
    )
    .await;
    let account_id = account_id_for(&fixture, "idle@example.com").await;

    // Idle 800 s: inside the warning window, not yet due for deletion, and far
    // enough past activation to be a candidate.
    let now = weaver_server::wall_clock::unix_secs() + 2000;
    fixture
        .account
        .store
        .account_record_login(account_id, now - 800)
        .await
        .unwrap();
    let before = fixture.sent.lock().unwrap().len();

    let report = inactivity::run(&fixture.account, None, now).await.unwrap();
    assert_eq!(report.warned, 1);
    assert_eq!(report.deleted, 0);
    assert_eq!(
        fixture.sent.lock().unwrap().len(),
        before + 1,
        "exactly one warning email"
    );
    let warned = fixture
        .account
        .store
        .account_by_id(account_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(warned.inactivity_warning_at, Some(now));

    // A second tick sends nothing: the warning is recorded.
    let report = inactivity::run(&fixture.account, None, now + 10)
        .await
        .unwrap();
    assert_eq!(report.warned, 0);
    assert_eq!(report.deleted, 0);
    assert_eq!(fixture.sent.lock().unwrap().len(), before + 1);

    // Past the threshold the account is deleted through the shared path.
    let report = inactivity::run(&fixture.account, None, now + 300)
        .await
        .unwrap();
    assert_eq!(report.deleted, 1);
    assert!(
        fixture
            .account
            .store
            .account_by_id(account_id)
            .await
            .unwrap()
            .is_none(),
        "the account is gone"
    );
}

/// The sweep's own schedule: `next_event` names the exact second of the
/// warning (the lead time *before* deletion, not after activity) and then of
/// the deletion, and a run at each of those ticks does exactly that step.
#[tokio::test]
async fn inactivity_sweep_wakes_exactly_at_the_warning_then_the_deletion() {
    let fixture = setup_with(|cfg| {
        cfg.inactive_after_secs = 1000;
        cfg.inactivity_warning_before_secs = 200;
    })
    .await;
    register(
        &fixture,
        "Timed",
        "timed@example.com",
        "correct horse battery",
    )
    .await;
    let account_id = account_id_for(&fixture, "timed@example.com").await;
    let now = weaver_server::wall_clock::unix_secs() + 2000;
    let last_seen = now - 600;
    fixture
        .account
        .store
        .account_record_login(account_id, last_seen)
        .await
        .unwrap();

    // Idle 600 s of a 1000 s life with a 200 s lead: too early to warn.
    let report = inactivity::run(&fixture.account, None, now).await.unwrap();
    assert_eq!(report, inactivity::SweepReport::default());

    let warn_at = inactivity::next_event(&fixture.account, now, now)
        .await
        .unwrap();
    assert_eq!(warn_at, last_seen + 800);
    let report = inactivity::run(&fixture.account, None, warn_at)
        .await
        .unwrap();
    assert_eq!(report.warned, 1);

    let delete_at = inactivity::next_event(&fixture.account, warn_at, warn_at)
        .await
        .unwrap();
    assert_eq!(delete_at, last_seen + 1000);
    let report = inactivity::run(&fixture.account, None, delete_at)
        .await
        .unwrap();
    assert_eq!(report.deleted, 1);
}

#[tokio::test]
async fn inactivity_sweep_signs_in_after_a_warning_and_spares_the_account() {
    let fixture = inactivity_fixture().await;
    register(
        &fixture,
        "Saved",
        "saved@example.com",
        "correct horse battery",
    )
    .await;
    let account_id = account_id_for(&fixture, "saved@example.com").await;

    let now = weaver_server::wall_clock::unix_secs() + 2000;
    fixture
        .account
        .store
        .account_record_login(account_id, now - 800)
        .await
        .unwrap();
    assert_eq!(
        inactivity::run(&fixture.account, None, now)
            .await
            .unwrap()
            .warned,
        1
    );

    // The owner signs in after the warning: the clock moves past it, so the
    // account is neither warned again nor deleted.
    let signed_in = now - 100;
    fixture
        .account
        .store
        .account_record_login(account_id, signed_in)
        .await
        .unwrap();
    let report = inactivity::run(&fixture.account, None, now + 300)
        .await
        .unwrap();
    assert_eq!(report.warned, 0);
    assert_eq!(report.deleted, 0);
    assert!(
        fixture
            .account
            .store
            .account_by_id(account_id)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn inactivity_sweep_skips_an_account_with_a_live_session() {
    let fixture = inactivity_fixture().await;
    register(
        &fixture,
        "Online",
        "online@example.com",
        "correct horse battery",
    )
    .await;
    let account_id = account_id_for(&fixture, "online@example.com").await;
    // Sign in for real: the session outlives the sweep window below.
    sign_in(&fixture, "online@example.com", "correct horse battery").await;

    // Its sign-in is stale on paper, but the live session must win.
    let now = weaver_server::wall_clock::unix_secs() + 2000;
    fixture
        .account
        .store
        .account_record_login(account_id, now - 5000)
        .await
        .unwrap();

    let report = inactivity::run(&fixture.account, None, now).await.unwrap();
    assert_eq!(report.warned, 0, "a live session is never warned");
    assert_eq!(report.deleted, 0, "a live session is never deleted");
    assert!(
        fixture
            .account
            .store
            .account_by_id(account_id)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn inactivity_sweep_deletes_without_a_mailer() {
    let fixture = setup_without_mailer(|cfg| {
        cfg.inactive_after_secs = 1000;
        cfg.inactivity_warning_before_secs = 500;
    })
    .await;
    // No mailer means the signup flow cannot verify an address, so the account
    // is created directly. Deletion needs no email identity.
    let store = fixture.account.store.clone();
    let account = store.create_account_without_login("Nomail").await.unwrap();

    // The warning is skipped, but deletion still happens on schedule.
    let now = weaver_server::wall_clock::unix_secs() + 2000;
    store
        .account_record_login(account.id, now - 800)
        .await
        .unwrap();
    let report = inactivity::run(&fixture.account, None, now).await.unwrap();
    assert_eq!(report.warned, 0);
    assert_eq!(report.deleted, 0);
    assert!(fixture.sent.lock().unwrap().is_empty(), "no email was sent");

    let report = inactivity::run(&fixture.account, None, now + 300)
        .await
        .unwrap();
    assert_eq!(report.deleted, 1);
    assert!(store.account_by_id(account.id).await.unwrap().is_none());
}
