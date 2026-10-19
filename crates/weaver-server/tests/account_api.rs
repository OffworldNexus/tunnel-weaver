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
    let dir = tempfile::tempdir().unwrap().keep();
    let store = Store::open(dir.join("account.db")).await.unwrap();

    let config = base_config();
    let altcha = AltchaRuntime::from_config(&config, store.clone()).unwrap();
    altcha.ensure_demo_client().await.unwrap();

    let sent = Arc::new(Mutex::new(Vec::new()));
    let mailer: Arc<dyn Mailer> = Arc::new(Capture {
        identity: MailerIdentity::new(
            "stub",
            "Stub",
            Mailbox::new("no-reply@admin.test"),
            "https://admin.test",
            vec![],
        )
        .unwrap(),
        sent: Arc::clone(&sent),
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
        store,
        altcha,
        Some(mailer),
        Arc::new(NoBreach),
    )
    .unwrap();
    Fixture {
        router: router(account.clone()),
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
        relay_ips: Vec::new(),
        setup_complete: false,
        email: None,
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
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
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

    // Log in.
    let altcha = solved(&fixture.account, "login").await;
    let login = call(
        &fixture.router,
        "POST",
        "/api/account/login",
        &[],
        Some(serde_json::json!({
            "email": "remy@example.com",
            "password": "correct horse battery",
            "altcha": altcha
        })),
    )
    .await;
    assert_eq!(login.status, StatusCode::OK, "{:?}", login.body);
    let session = login
        .cookie("__Host-weaver_session")
        .expect("session cookie set");
    let csrf = login.cookie("__Host-weaver_csrf").expect("csrf cookie set");

    // Identity, with the Unicode name preserved.
    let me = call(
        &fixture.router,
        "GET",
        "/api/account/me",
        &[("cookie", format!("__Host-weaver_session={session}"))],
        None,
    )
    .await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.body["name"], "Rémy");
    assert_eq!(me.body["email"], "remy@example.com");
    // The Security page's "Password is set" state is driven by this flag.
    assert_eq!(
        me.body["has_password"], true,
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

    // The old cookie no longer authenticates.
    let after = call(
        &fixture.router,
        "GET",
        "/api/account/me",
        &[("cookie", format!("__Host-weaver_session={session}"))],
        None,
    )
    .await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);

    // Logging in again after logout succeeds with the same credentials,
    // and the fresh session authenticates. This proves logout retires the
    // session rather than poisoning the account (login rotates the token).
    let altcha = solved(&fixture.account, "login").await;
    let relogin = call(
        &fixture.router,
        "POST",
        "/api/account/login",
        &[],
        Some(serde_json::json!({
            "email": "remy@example.com",
            "password": "correct horse battery",
            "altcha": altcha
        })),
    )
    .await;
    assert_eq!(relogin.status, StatusCode::OK, "{:?}", relogin.body);
    let session2 = relogin
        .cookie("__Host-weaver_session")
        .expect("fresh session cookie set");
    assert_ne!(session2, session, "login must mint a new session token");

    let me2 = call(
        &fixture.router,
        "GET",
        "/api/account/me",
        &[("cookie", format!("__Host-weaver_session={session2}"))],
        None,
    )
    .await;
    assert_eq!(me2.status, StatusCode::OK);
    assert_eq!(me2.body["name"], "Rémy");
    assert_eq!(me2.body["email"], "remy@example.com");
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
        me.status,
        StatusCode::UNAUTHORIZED,
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

/// Signs in and returns the (session, csrf) cookie pair the change flow needs.
async fn sign_in(fixture: &Fixture, email: &str, password: &str) -> (String, String) {
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
    let before = fixture.sent.lock().unwrap().len();

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
        me.status,
        StatusCode::UNAUTHORIZED,
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
    wait_for_mail_count(&fixture.sent, before + 1).await;
    let sent = fixture.sent.lock().unwrap();
    let notification = sent.last().expect("a notification email");
    assert_eq!(notification.subject, "Your password was changed");
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
        me.status,
        StatusCode::OK,
        "a refusal leaves the session alone"
    );
    assert!(
        signs_in(&fixture, email, "correct horse battery").await,
        "the credential is unchanged"
    );
    assert!(
        !signs_in(&fixture, email, "a much better password").await,
        "the rejected password was not applied"
    );
    assert_eq!(
        fixture.sent.lock().unwrap().len(),
        before,
        "a refusal emails nothing"
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
        assert_eq!(
            me.status,
            StatusCode::UNAUTHORIZED,
            "every session is revoked"
        );
    }
}

/// The endpoint is authenticated and CSRF-protected: like `logout`, the
/// same-origin/CSRF guard runs first, and a well-formed request without a live
/// session is refused as unauthenticated.
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

    // No cookies at all: the CSRF guard refuses before the session is examined,
    // the same order `logout` uses.
    let bare = call(
        &fixture.router,
        "POST",
        "/api/account/password",
        &[],
        body.clone(),
    )
    .await;
    assert_eq!(bare.status, StatusCode::FORBIDDEN, "{:?}", bare.body);

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
