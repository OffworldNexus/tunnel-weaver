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

    let account_config = AccountConfig {
        base_url: Some("https://admin.test".into()),
        cookie_secure: false,
        // Tiny Argon2 so tests stay fast.
        argon2_memory_kib: 8,
        argon2_iterations: 1,
        argon2_parallelism: 1,
        ..Default::default()
    };
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
