//! End-to-end tests for the account plane (WVR-36).
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

/// The authoritative end-to-end happy path (WVR-36): signup → emailed link →
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

    // WVR-36: logging in again after logout succeeds with the same credentials,
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

// ----- password reset (WVR-41) ---------------------------------------------

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
