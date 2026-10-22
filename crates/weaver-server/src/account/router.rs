//! The account plane's axum router.
//!
//! Mounted by the hyper edge for the admin host's `/account` and `/api/account`
//! namespaces only. Every authentication decision lives here or below; the
//! SvelteKit SPA renders and posts to these same-origin endpoints.
//!
//! Ordering rules that matter:
//! * Proof-of-work is verified and consumed *before* any pending-registration
//!   write or email — a spent proof stays spent even if the later step fails.
//! * Every state-changing request is checked against `Origin`/`Sec-Fetch-Site`,
//!   and authenticated ones additionally against a double-submit CSRF token.
//! * Failure responses are generic wherever account existence is at stake, and
//!   login always performs a password verification so its timing does not
//!   reveal whether the address exists.

use std::sync::Arc;

use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use weaver_abuse::AltchaError;

use crate::account::session::{self, CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE};
use crate::account::views::{
    USAGE_WINDOW_SECS, key_of, load_error, owned_machine, person_of, person_services, signed_in,
};
use crate::account::{AccountRuntime, pairing, views};
use crate::email::{Mailbox, PasswordChanged, Reset, Verification, Welcome};
use crate::live::{Change, Entity, Viewer};
use crate::metrics::{Function, Metric, MetricsQuery, MetricsStore};
use crate::store::StoreError;
use crate::store::account::{
    ActivationOutcome, ActivationRequest, NewPasswordResetToken, NewPendingRegistration,
    NewVerificationToken, ResetRequest,
};
use crate::store::entity::pending_registration;
use crate::store::entity::{account, person};
use crate::store::names;
use crate::tunnel::TunnelRegistry;
use crate::wall_clock::unix_secs;
use weaver_mux::CloseCode;
use weaver_proto::pair;

/// Purpose bound into an email-ownership verification token.
const PURPOSE_EMAIL_VERIFICATION: &str = "email-verification";
/// Purpose bound into the short-lived token that authorizes password setup.
const PURPOSE_REGISTRATION_COMPLETION: &str = "registration-completion";
/// ALTCHA purpose for starting a signup.
const ALTCHA_SIGNUP: &str = "signup";
/// ALTCHA purpose for a login attempt.
const ALTCHA_LOGIN: &str = "login";
/// ALTCHA purpose for requesting a password reset.
const ALTCHA_RESET: &str = "reset";

/// Builds the account router with its shared state applied.
///
/// `tunnel` is the live tunnel registry, when the process has one. It is what
/// makes a machine's "online" state, a web-side disconnect and an immediate
/// revoke possible; without it (tests, the e2e harness) machines simply read as
/// offline and the close-based actions are no-ops.
///
/// `metering` was the usage meter; the console's figures now come from
/// [`MetricsStore`] over the same store, so the router no longer needs it.
pub fn router(runtime: Arc<AccountRuntime>, tunnel: Option<Arc<TunnelRegistry>>) -> Router {
    Router::new()
        .route("/api/account/altcha/challenge", get(altcha_challenge))
        .route("/api/account/config", get(config))
        .route("/api/account/signup", post(signup))
        .route("/api/account/resend", post(resend))
        .route("/api/account/verify", post(verify_link))
        .route("/api/account/complete", post(complete))
        .route("/api/account/reset/request", post(reset_request))
        .route("/api/account/reset/check", post(reset_check))
        .route("/api/account/reset/complete", post(reset_complete))
        .route("/api/account/login", post(login))
        .route("/api/account/me", get(me))
        .route("/api/account/avatar", get(avatar))
        .route("/api/account/logout", post(logout))
        .route("/api/account/password", post(change_password))
        .route("/api/account/machines", get(machines_list))
        .route("/api/account/overview", get(overview))
        .route("/api/account/metrics", get(metrics))
        .route("/api/account/machines/{id}", get(machine_detail))
        .route("/api/account/machines/{id}/rename", post(machine_rename))
        .route(
            "/api/account/machines/{id}/disconnect",
            post(machine_disconnect),
        )
        .route("/api/account/machines/{id}/revoke", post(machine_revoke))
        .route(pair::PAIR_LOOKUP_PATH, post(pair_lookup))
        .route(pair::PAIR_ACCEPT_PATH, post(pair_accept))
        .route(pair::PAIR_REJECT_PATH, post(pair_reject))
        .fallback(spa)
        .layer(Extension(tunnel))
        .with_state(runtime)
}

// ----- request bodies -------------------------------------------------------

#[derive(Deserialize)]
struct SignupRequest {
    name: String,
    email: String,
    #[serde(default)]
    altcha: String,
}

#[derive(Deserialize)]
struct ResendRequest {
    flow: String,
}

#[derive(Deserialize)]
struct VerifyRequest {
    token: String,
}

#[derive(Deserialize)]
struct CompleteRequest {
    completion_token: String,
    password: String,
}

#[derive(Deserialize)]
struct ResetRequestBody {
    email: String,
    #[serde(default)]
    altcha: String,
}

#[derive(Deserialize)]
struct ResetCheckRequest {
    token: String,
}

#[derive(Deserialize)]
struct ResetCompleteRequest {
    token: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
    #[serde(default)]
    altcha: String,
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    /// Reauthentication: the account's current password.
    current_password: String,
    new_password: String,
}

#[derive(Deserialize)]
struct ChallengeQuery {
    #[serde(default)]
    purpose: String,
}

// ----- handlers -------------------------------------------------------------

/// `GET /api/account/altcha/challenge?purpose=signup|login|reset` — issue a
/// challenge for the relay's own internal client so the SPA never needs a client
/// key.
async fn altcha_challenge(
    State(rt): State<Arc<AccountRuntime>>,
    Query(params): Query<ChallengeQuery>,
) -> Response {
    if !matches!(
        params.purpose.as_str(),
        ALTCHA_SIGNUP | ALTCHA_LOGIN | ALTCHA_RESET
    ) {
        return err(StatusCode::BAD_REQUEST, "unknown proof-of-work purpose");
    }
    match rt
        .altcha
        .challenge_for_internal_client(&params.purpose, &params.purpose)
        .await
    {
        Some(challenge) => json_ok(serde_json::to_value(&challenge).unwrap_or(Value::Null)),
        None => err(
            StatusCode::SERVICE_UNAVAILABLE,
            "proof-of-work is not available right now",
        ),
    }
}

/// `GET /api/account/config` — client-facing constants the SPA needs.
async fn config(State(rt): State<Arc<AccountRuntime>>) -> Response {
    json_ok(json!({
        "altcha_challenge_url": "/api/account/altcha/challenge",
        "altcha_assets_base": "/assets/altcha/",
        "min_password_length": rt.passwords.min_length(),
        "verification_ttl_secs": rt.config.verification_ttl_secs,
        "resend_cooldown_secs": rt.config.resend_cooldown_secs,
        "support_email": rt.support_email,
        "relay_host": rt.relay_host(),
    }))
}

/// `POST /api/account/signup` — start a registration.
async fn signup(
    State(rt): State<Arc<AccountRuntime>>,
    headers: HeaderMap,
    Json(req): Json<SignupRequest>,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let name = req.name.trim();
    let email = req.email.trim();
    if name.is_empty() || !crate::email::is_valid_address(email) {
        return err(
            StatusCode::BAD_REQUEST,
            "a name and a valid email are required",
        );
    }
    if let Some(response) = consume_altcha(&rt, &req.altcha, ALTCHA_SIGNUP).await {
        return response;
    }

    let now = unix_secs();
    let flow_id = session::new_token();
    let pending = match rt
        .store
        .pending_registration_create(NewPendingRegistration {
            flow_id: flow_id.clone(),
            name: name.to_string(),
            email: email.to_string(),
            lookup_key: normalize_email(email),
            created_at: now,
            // Outlive the link so a verified user can still finish setting a
            // password inside the completion window.
            expires_at: now
                + rt.config.verification_ttl_secs as i64
                + rt.config.completion_ttl_secs as i64,
        })
        .await
    {
        Ok(pending) => pending,
        Err(_) => return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable"),
    };

    // A send failure must not disclose anything, and the pending row survives so
    // the user can resend.
    if let Err(error) = send_verification(&rt, &pending, now).await {
        tracing::warn!(%error, "signup verification email was not sent");
    }

    // Identical body whether or not the address already belongs to an account.
    json_ok(json!({ "status": "check_email", "flow": flow_id }))
}

/// `POST /api/account/resend` — re-issue a verification link, throttled.
async fn resend(
    State(rt): State<Arc<AccountRuntime>>,
    headers: HeaderMap,
    Json(req): Json<ResendRequest>,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let now = unix_secs();
    let Some(pending) = rt
        .store
        .pending_registration_by_flow(&req.flow)
        .await
        .ok()
        .flatten()
        .filter(|p| p.completed_at.is_none() && p.expires_at > now)
    else {
        // Do not disclose whether the flow exists.
        return json_ok(json!({ "status": "check_email" }));
    };

    // Enforce the resend cooldown against the last issued token.
    if let Ok(Some(latest)) = rt
        .store
        .verification_token_latest_for_flow(pending.id)
        .await
        && now - latest.issued_at < rt.config.resend_cooldown_secs as i64
    {
        return json_ok(json!({ "status": "cooldown" }));
    }

    if let Err(error) = send_verification(&rt, &pending, now).await {
        tracing::warn!(%error, "resend verification email was not sent");
    }
    json_ok(json!({ "status": "check_email" }))
}

/// `POST /api/account/verify` — exchange an email link token for the next step.
///
/// Consumes the link (single-use). A new address gets a short-lived completion
/// token for password setup; an address that already belongs to an account is
/// only now revealed, with no credential written and no session created.
async fn verify_link(
    State(rt): State<Arc<AccountRuntime>>,
    headers: HeaderMap,
    Json(req): Json<VerifyRequest>,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let now = unix_secs();
    let digest = session::token_hash(&req.token);
    let Some(token) = rt
        .store
        .verification_token_by_digest(&digest)
        .await
        .ok()
        .flatten()
    else {
        return err(
            StatusCode::BAD_REQUEST,
            "this link is invalid or has already been used",
        );
    };
    if token.purpose != PURPOSE_EMAIL_VERIFICATION
        || token.consumed_at.is_some()
        || token.revoked_at.is_some()
        || token.expires_at <= now
    {
        return err(
            StatusCode::BAD_REQUEST,
            "this link has expired or has already been used",
        );
    }
    let Some(pending) = rt
        .store
        .pending_registration_by_id(token.pending_registration_id)
        .await
        .ok()
        .flatten()
        .filter(|p| p.completed_at.is_none() && p.expires_at > now)
    else {
        return err(
            StatusCode::BAD_REQUEST,
            "this link has expired or has already been used",
        );
    };

    // Single-use: consume the link now, before deciding the next step.
    if !rt
        .store
        .verification_token_consume(token.id, now)
        .await
        .unwrap_or(false)
    {
        return err(
            StatusCode::BAD_REQUEST,
            "this link has expired or has already been used",
        );
    }
    let _ = rt
        .store
        .pending_registration_set_proved_by(pending.id, token.id)
        .await;

    // Existing address: reveal only after ownership is proven.
    if rt
        .store
        .email_identity_find(&token.email_lookup_key)
        .await
        .ok()
        .flatten()
        .is_some()
    {
        let _ = rt
            .store
            .pending_registration_complete(pending.id, now)
            .await;
        return json_ok(json!({ "outcome": "existing_account", "email": pending.email }));
    }

    // New address: issue a short-lived completion token for password setup.
    let raw = session::new_token();
    match rt
        .store
        .verification_token_issue(
            pending.id,
            NewVerificationToken {
                email_lookup_key: token.email_lookup_key.clone(),
                token_digest: session::token_hash(&raw),
                purpose: PURPOSE_REGISTRATION_COMPLETION.to_string(),
                issued_at: now,
                expires_at: now + rt.config.completion_ttl_secs as i64,
            },
        )
        .await
    {
        Ok(_) => json_ok(json!({
            "outcome": "set_password",
            "completion_token": raw,
            "name": pending.name,
            "email": pending.email,
        })),
        Err(_) => err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable"),
    }
}

/// `POST /api/account/complete` — set the initial password and activate.
async fn complete(
    State(rt): State<Arc<AccountRuntime>>,
    headers: HeaderMap,
    Json(req): Json<CompleteRequest>,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let now = unix_secs();
    let digest = session::token_hash(&req.completion_token);
    let Some(token) = rt
        .store
        .verification_token_by_digest(&digest)
        .await
        .ok()
        .flatten()
    else {
        return err(
            StatusCode::BAD_REQUEST,
            "this registration has expired; start again",
        );
    };
    if token.purpose != PURPOSE_REGISTRATION_COMPLETION
        || token.consumed_at.is_some()
        || token.revoked_at.is_some()
        || token.expires_at <= now
    {
        return err(
            StatusCode::BAD_REQUEST,
            "this registration has expired; start again",
        );
    }
    let Some(pending) = rt
        .store
        .pending_registration_by_id(token.pending_registration_id)
        .await
        .ok()
        .flatten()
        .filter(|p| p.completed_at.is_none())
    else {
        return err(
            StatusCode::BAD_REQUEST,
            "this registration has already been completed",
        );
    };
    let Some(proof_token_id) = pending.proved_by_token_id else {
        return err(
            StatusCode::BAD_REQUEST,
            "this registration has expired; start again",
        );
    };

    if let Err(error) = rt.passwords.validate(&req.password).await {
        return password_error_response(&rt, error);
    }
    let Ok(encoded_hash) = rt.passwords.hash(&req.password) else {
        return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    };

    match rt
        .store
        .account_activate(ActivationRequest {
            pending_registration_id: pending.id,
            consume_token_id: token.id,
            proof_token_id,
            name: &pending.name,
            email: &pending.email,
            lookup_key: &pending.lookup_key,
            encoded_hash: &encoded_hash,
            now,
        })
        .await
    {
        Ok(ActivationOutcome::Activated(_)) => {
            let _ = send_welcome(&rt, &pending).await;
            json_ok(json!({ "outcome": "activated" }))
        }
        Ok(ActivationOutcome::ExistingAccount(_)) => {
            json_ok(json!({ "outcome": "existing_account", "email": pending.email }))
        }
        Err(_) => err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable"),
    }
}

/// `POST /api/account/reset/request` — email a reset link, if an account exists.
///
/// The response is **identical** whether or not the address belongs to an
/// account, and the work on the response path is identical too: we always
/// resolve the address, always mint and digest a token, and always spend the
/// same Argon2 verification.
///
/// Everything that only happens for a real account — the cooldown read, the
/// token write, and above all the email-provider round-trip — is pushed onto a
/// detached task. Awaiting the send here would make the response time (hundreds
/// of milliseconds) a dead giveaway of whether the address has an account,
/// defeating the equalizer above. So neither the body nor the timing can be
/// used to probe for accounts.
async fn reset_request(
    State(rt): State<Arc<AccountRuntime>>,
    headers: HeaderMap,
    Json(req): Json<ResetRequestBody>,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let email = req.email.trim();
    if !crate::email::is_valid_address(email) {
        return err(StatusCode::BAD_REQUEST, "a valid email is required");
    }
    if let Some(response) = consume_altcha(&rt, &req.altcha, ALTCHA_RESET).await {
        return response;
    }
    let now = unix_secs();
    let lookup = normalize_email(email);

    // Resolve without disclosing. Both branches below do the same amount of
    // work so an observer cannot learn whether the address exists.
    let identity = rt.store.email_identity_find(&lookup).await.ok().flatten();
    let account = match &identity {
        Some(identity) => rt
            .store
            .account_by_id(identity.account_id)
            .await
            .ok()
            .flatten(),
        None => None,
    };

    // Mint a token and spend the Argon2 verification regardless of the outcome;
    // the results are discarded on the no-account path. The verify mirrors
    // `login`'s dummy-hash technique purely to equalize timing.
    let raw = session::new_token();
    let digest = session::token_hash(&raw);
    let _ = rt.passwords.verify(email, &rt.dummy_hash);

    // The account-only half runs detached, off the response path, so the reply
    // is not delayed by (and does not reveal) a database write or an email
    // send. `issue_and_send_reset` owns its own logging.
    if let (Some(account), Some(identity)) = (account, identity) {
        let rt = Arc::clone(&rt);
        tokio::spawn(async move {
            issue_and_send_reset(&rt, &account, &identity.email, &raw, digest, now).await;
        });
    }

    // Identical body whether or not the address already belongs to an account.
    json_ok(json!({ "status": "check_email" }))
}

/// The account-only half of a reset request, run detached from the response.
///
/// Applies the per-account cooldown, issues the single-use token and sends the
/// link. Nothing here changes the HTTP response, which the caller has already
/// sent: a cooldown or a failure must stay indistinguishable from any other
/// request, so every outcome is only logged.
async fn issue_and_send_reset(
    rt: &AccountRuntime,
    account: &crate::store::entity::account::Model,
    email: &str,
    raw: &str,
    digest: String,
    now: i64,
) {
    if account.state != "active" {
        return;
    }
    let cooling_down = matches!(
        rt.store
            .password_reset_token_latest_for_account(account.id)
            .await
            .ok()
            .flatten(),
        Some(latest) if now - latest.issued_at < rt.config.resend_cooldown_secs as i64
    );
    if cooling_down {
        return;
    }
    match rt
        .store
        .password_reset_token_issue(
            account.id,
            NewPasswordResetToken {
                token_digest: digest,
                issued_at: now,
                expires_at: now + rt.config.reset_ttl_secs as i64,
            },
        )
        .await
    {
        Ok(_) => {
            if let Err(error) = send_reset(rt, &account.name, email, raw).await {
                tracing::warn!(%error, "password reset email was not sent");
            }
        }
        // A persistence failure must not disclose anything either.
        Err(error) => {
            tracing::warn!(%error, "password reset token was not issued");
        }
    }
}

/// `POST /api/account/reset/check` — resolve a reset link without consuming it.
///
/// Lets the "choose a new password" page render the verified address and detect
/// a dead link before the user types anything. Never consumes the token.
async fn reset_check(
    State(rt): State<Arc<AccountRuntime>>,
    headers: HeaderMap,
    Json(req): Json<ResetCheckRequest>,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let now = unix_secs();
    let digest = session::token_hash(&req.token);
    let token = rt
        .store
        .password_reset_token_by_digest(&digest)
        .await
        .ok()
        .flatten()
        .filter(|t| t.consumed_at.is_none() && t.revoked_at.is_none() && t.expires_at > now);
    let Some(token) = token else {
        return json_ok(json!({ "valid": false }));
    };
    match rt
        .store
        .email_identity_for_account(token.account_id)
        .await
        .ok()
        .flatten()
    {
        Some(identity) => json_ok(json!({ "valid": true, "email": identity.email })),
        None => json_ok(json!({ "valid": false })),
    }
}

/// `POST /api/account/reset/complete` — set a new password from a reset link.
///
/// Consumes the token, replaces the credential and invalidates every session in
/// one store transaction. Like `/complete`, it requires no ALTCHA (the token is
/// the proof) and writes no session — the user signs in again afterwards.
async fn reset_complete(
    State(rt): State<Arc<AccountRuntime>>,
    headers: HeaderMap,
    Json(req): Json<ResetCompleteRequest>,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let now = unix_secs();
    let digest = session::token_hash(&req.token);
    let Some(token) = rt
        .store
        .password_reset_token_by_digest(&digest)
        .await
        .ok()
        .flatten()
    else {
        return err(
            StatusCode::BAD_REQUEST,
            "this link is invalid or has already been used",
        );
    };
    if token.consumed_at.is_some() || token.revoked_at.is_some() || token.expires_at <= now {
        return err(
            StatusCode::BAD_REQUEST,
            "this link has expired or has already been used",
        );
    }

    if let Err(error) = rt.passwords.validate(&req.password).await {
        return password_error_response(&rt, error);
    }
    let Ok(encoded_hash) = rt.passwords.hash(&req.password) else {
        return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    };

    match rt
        .store
        .account_reset_password(ResetRequest {
            token_id: token.id,
            encoded_hash: &encoded_hash,
            now,
        })
        .await
    {
        Ok(_) => json_ok(json!({ "outcome": "reset" })),
        Err(StoreError::Conflict(_)) => err(
            StatusCode::BAD_REQUEST,
            "this link has expired or has already been used",
        ),
        Err(_) => err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable"),
    }
}

/// `POST /api/account/login` — verify credentials and start a session.
async fn login(
    State(rt): State<Arc<AccountRuntime>>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    if let Some(response) = consume_altcha(&rt, &req.altcha, ALTCHA_LOGIN).await {
        return response;
    }
    let now = unix_secs();
    let lookup = normalize_email(&req.email);

    // Resolve without disclosing; verify against a dummy hash when absent so the
    // response timing does not reveal whether the address exists.
    let account = match rt.store.email_identity_find(&lookup).await.ok().flatten() {
        Some(identity) => rt
            .store
            .account_by_id(identity.account_id)
            .await
            .ok()
            .flatten(),
        None => None,
    };
    let stored = match &account {
        Some(account) => rt
            .store
            .password_current_for(account.id)
            .await
            .ok()
            .flatten()
            .map(|credential| credential.encoded_hash),
        None => None,
    };
    let hash = stored.as_deref().unwrap_or(&rt.dummy_hash);
    let password_ok = rt.passwords.verify(&req.password, hash);
    let Some(account) = account.filter(|_| password_ok) else {
        return err(StatusCode::UNAUTHORIZED, "invalid email or password");
    };

    let raw = match rt.sessions.create(account.id, now).await {
        Ok(raw) => raw,
        Err(_) => return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable"),
    };
    let csrf = session::new_token();
    let response = json_ok(json!({ "ok": true, "name": account.name }));
    let response = with_cookie(response, rt.sessions.session_cookie(&raw));
    with_cookie(response, rt.sessions.csrf_cookie(&csrf))
}

/// `GET /api/account/me` — the signed-in identity.
async fn me(State(rt): State<Arc<AccountRuntime>>, headers: HeaderMap) -> Response {
    let Some(raw) = session::cookie(&headers, SESSION_COOKIE) else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    match rt.sessions.account(&raw, unix_secs()).await {
        Ok(Some(account)) => {
            let email = rt
                .store
                .email_identity_for_account(account.id)
                .await
                .ok()
                .flatten()
                .map(|identity| identity.email);
            // Drives the Security page's "Password is set" state: a live
            // credential exists for every email/password account today, but the
            // flag keeps the panel honest once passkeys or SSO arrive.
            let has_password = rt
                .store
                .password_current_for(account.id)
                .await
                .ok()
                .flatten()
                .is_some();
            json_ok(
                json!({ "id": account.id, "name": account.name, "email": email, "has_password": has_password }),
            )
        }
        _ => err(StatusCode::UNAUTHORIZED, "not signed in"),
    }
}

/// How large an avatar may be asked to be, and the size used when unprompted.
///
/// The console draws it at 36 px and asks for twice that so it survives a
/// high-density screen; the clamp keeps a hand-written URL from asking for a
/// megabyte of SVG.
const AVATAR_DEFAULT_SIZE: u32 = 96;
const AVATAR_MIN_SIZE: u32 = 16;
const AVATAR_MAX_SIZE: u32 = 512;

/// Query for [`avatar`].
#[derive(Deserialize)]
struct AvatarQuery {
    /// Pixel size to render, clamped to [`AVATAR_MIN_SIZE`]..=[`AVATAR_MAX_SIZE`].
    size: Option<u32>,
}

/// `GET /api/account/avatar` — the signed-in account's bird, as an SVG.
///
/// `bird-id` derives the species and its mid-century silkscreen palette from the
/// address itself, so the same account always gets the same bird and the relay
/// stores nothing to serve it. Every model is drawn inside the inscribed circle,
/// so the console's round frame never clips a beak or a crest.
async fn avatar(
    State(rt): State<Arc<AccountRuntime>>,
    headers: HeaderMap,
    Query(query): Query<AvatarQuery>,
) -> Response {
    let Some(raw) = session::cookie(&headers, SESSION_COOKIE) else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let Ok(Some(account)) = rt.sessions.account(&raw, unix_secs()).await else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let Some(identity) = rt
        .store
        .email_identity_for_account(account.id)
        .await
        .ok()
        .flatten()
    else {
        return err(StatusCode::NOT_FOUND, "this account has no email address");
    };
    let size = query
        .size
        .unwrap_or(AVATAR_DEFAULT_SIZE)
        .clamp(AVATAR_MIN_SIZE, AVATAR_MAX_SIZE);
    let svg = bird_id::Avatar::from_email(&identity.email).svg_circle_sized(size);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "image/svg+xml; charset=utf-8")],
        svg,
    )
        .into_response()
}

/// `POST /api/account/logout` — invalidate the current session (CSRF-protected).
async fn logout(State(rt): State<Arc<AccountRuntime>>, headers: HeaderMap) -> Response {
    if !origin_ok(&headers, &rt.base_url) || !csrf_ok(&headers) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    if let Some(raw) = session::cookie(&headers, SESSION_COOKIE) {
        let _ = rt.sessions.invalidate(&raw, unix_secs()).await;
    }
    with_cookie(
        json_ok(json!({ "ok": true })),
        rt.sessions.clear_session_cookie(),
    )
}

/// A pairing action's answer.
fn action(ok: bool, message: &str) -> Response {
    let response = pair::ActionResponse {
        ok,
        message: message.to_string(),
    };
    json_ok(serde_json::to_value(&response).unwrap_or(Value::Null))
}

const NO_LONGER_WAITING: &str = "This pairing request is no longer waiting.";
const NOT_YOUR_MACHINE: &str = "That machine does not belong to this account.";
const COULD_NOT_PAIR: &str = "Could not pair this machine. Try again.";

// ----- machines -------------------------------------------------------------

/// Body of a rename request.
#[derive(Deserialize)]
struct RenameRequest {
    name: String,
}

/// `GET /api/account/machines` — a page of the signed-in person's machines, or
/// its live stream (see [`views::Machines`]).
async fn machines_list(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(tunnel): Extension<Option<Arc<TunnelRegistry>>>,
    req: Request,
) -> Response {
    views::serve::<views::Machines>(rt, tunnel, req).await
}

/// `GET /api/account/overview` — the account rollup, or its live stream (see
/// [`views::Overview`]).
async fn overview(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(tunnel): Extension<Option<Arc<TunnelRegistry>>>,
    req: Request,
) -> Response {
    views::serve::<views::Overview>(rt, tunnel, req).await
}

/// Query parameters of `GET /api/account/metrics`.
#[derive(Deserialize)]
struct MetricsParams {
    /// Comma-separated service ids; absent means every service of the person.
    services: Option<String>,
    /// Comma-separated person names. Self-scoped: only the signed-in person's
    /// own name is honoured, so this can never widen the query.
    people: Option<String>,
    /// Comma-separated metric names; absent means every metric.
    metrics: Option<String>,
    /// Window start, Unix seconds or `YYYY-MM-DD`; defaults to 30 days ago.
    from: Option<String>,
    /// Window end, Unix seconds or `YYYY-MM-DD`; defaults to now.
    to: Option<String>,
    /// Reduction; absent means `sum`.
    function: Option<String>,
}

/// `GET /api/account/metrics` — the signed-in person's usage series, as the
/// metrics store's JSON verbatim (`Content-Type: application/json`).
///
/// Self-scoped: any requested service id that is not one of the person's is
/// dropped, and only the person's own name survives `people`, so another
/// person's data can never be read. An unknown metric, function or date is a
/// 400 rather than a silent default.
async fn metrics(
    State(rt): State<Arc<AccountRuntime>>,
    Query(params): Query<MetricsParams>,
    headers: HeaderMap,
) -> Response {
    let Some(account) = signed_in(&rt, &headers).await else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let Some(person) = person_of(&rt, account.id).await else {
        return err(StatusCode::BAD_REQUEST, "this account has no person yet");
    };
    let metrics = match parse_metrics(params.metrics.as_deref()) {
        Ok(metrics) => metrics,
        Err(message) => return err(StatusCode::BAD_REQUEST, &message),
    };
    let function = match parse_function(params.function.as_deref()) {
        Ok(function) => function,
        Err(message) => return err(StatusCode::BAD_REQUEST, &message),
    };
    let now = unix_secs();
    let from = match parse_time(params.from.as_deref(), now - USAGE_WINDOW_SECS) {
        Ok(from) => from,
        Err(message) => return err(StatusCode::BAD_REQUEST, &message),
    };
    let to = match parse_time(params.to.as_deref(), now) {
        Ok(to) => to,
        Err(message) => return err(StatusCode::BAD_REQUEST, &message),
    };

    let owned = match person_services(&rt.store, &person).await {
        Ok(services) => services,
        Err(e) => return load_error(e),
    };
    let owned_ids: Vec<i32> = owned.iter().map(|(_, svc)| svc.id).collect();
    let requested = parse_service_ids(params.services.as_deref());
    let services: Vec<i32> = if requested.is_empty() {
        owned_ids.clone()
    } else {
        requested
            .into_iter()
            .filter(|id| owned_ids.contains(id))
            .collect()
    };
    let people: Vec<String> = parse_csv(params.people.as_deref())
        .into_iter()
        .filter(|name| name.eq_ignore_ascii_case(&person.name))
        .collect();

    let query = MetricsQuery {
        services,
        people,
        metrics,
        from,
        to,
        function,
    };
    match MetricsStore::new(rt.store.clone()).query(&query).await {
        Ok(body) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            body,
        )
            .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "failed to read account metrics");
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not read usage metrics",
            )
        }
    }
}

/// Splits a comma-separated parameter into trimmed, non-empty items.
fn parse_csv(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

/// Parses the `metrics` parameter; absent means every metric. An unknown name is
/// an error, so a typo is a 400 rather than a silently empty series.
fn parse_metrics(value: Option<&str>) -> Result<Vec<Metric>, String> {
    let names = parse_csv(value);
    if names.is_empty() {
        return Ok(Metric::ALL.to_vec());
    }
    names
        .iter()
        .map(|name| Metric::parse(name).ok_or_else(|| format!("unknown metric '{name}'")))
        .collect()
}

/// Parses the `function` parameter; absent means `sum`.
fn parse_function(value: Option<&str>) -> Result<Function, String> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        None => Ok(Function::Sum),
        Some(name) => Function::parse(name).ok_or_else(|| format!("unknown function '{name}'")),
    }
}

/// Parses a time parameter as Unix seconds or a `YYYY-MM-DD` date (midnight
/// UTC), falling back to `default`; an unparsable value is an error.
fn parse_time(value: Option<&str>, default: i64) -> Result<i64, String> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(default);
    };
    if let Ok(seconds) = value.parse::<i64>() {
        return Ok(seconds);
    }
    match value.parse::<jiff::civil::Date>() {
        Ok(date) => date
            .at(0, 0, 0, 0)
            .to_zoned(jiff::tz::TimeZone::UTC)
            .map(|zoned| zoned.timestamp().as_second())
            .map_err(|e| format!("invalid date '{value}': {e}")),
        Err(_) => Err(format!("invalid time '{value}'")),
    }
}

/// Parses comma-separated service ids, ignoring entries that are not integers.
fn parse_service_ids(value: Option<&str>) -> Vec<i32> {
    parse_csv(value)
        .iter()
        .filter_map(|id| id.parse::<i32>().ok())
        .collect()
}

/// `GET /api/account/machines/{id}` — one machine, or its live stream (see
/// [`views::MachineDetail`]).
async fn machine_detail(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(tunnel): Extension<Option<Arc<TunnelRegistry>>>,
    req: Request,
) -> Response {
    views::serve::<views::MachineDetail>(rt, tunnel, req).await
}

/// `POST /api/account/machines/{id}/rename` — rename a machine (CSRF-protected).
///
/// The store renames the machine and re-derives its hostnames first; the live
/// registry is remapped second, so what routes follows what is stored. A
/// machine that is offline is simply renamed — its hostnames are already the
/// new ones for whenever it reconnects.
async fn machine_rename(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(tunnel): Extension<Option<Arc<TunnelRegistry>>>,
    Path(machine_id): Path<i32>,
    headers: HeaderMap,
    Json(req): Json<RenameRequest>,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) || !csrf_ok(&headers) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let Some(account) = signed_in(&rt, &headers).await else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let Some(person) = person_of(&rt, account.id).await else {
        return err(StatusCode::NOT_FOUND, "machine not found");
    };
    let machine = match owned_machine(&rt, &person, machine_id).await {
        Ok(Some(machine)) => machine,
        Ok(None) => return err(StatusCode::NOT_FOUND, "machine not found"),
        Err(e) => return load_error(e),
    };
    let renamed = match rt.store.rename_machine(machine.id, req.name.trim()).await {
        Ok(renamed) => renamed,
        Err(StoreError::InvalidName(_)) => {
            return err(
                StatusCode::BAD_REQUEST,
                "a machine name is 1–15 lowercase letters or digits",
            );
        }
        // The per-person unique index refuses a name this person already uses.
        Err(StoreError::Db(_)) => {
            return err(
                StatusCode::CONFLICT,
                "you already have a machine with this name",
            );
        }
        Err(e) => return load_error(e),
    };
    if let (Some(registry), Some(key)) = (tunnel.as_deref(), key_of(&renamed)) {
        registry.rename_machine(&key).await;
    }
    rt.live.publish(
        Change::visible_to(Viewer::Person(person.id))
            .entity(Entity::Machine)
            .id(machine.id),
    );
    json_ok(json!({ "ok": true, "name": renamed.name }))
}

/// `POST /api/account/machines/{id}/disconnect` — drop a live tunnel.
///
/// The key is kept: the relay closes with `Rejected` so the client exits and
/// does not reconnect, and the machine comes back on the next `weave start`.
/// Idempotent — a machine that is already offline answers `disconnected: false`.
async fn machine_disconnect(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(tunnel): Extension<Option<Arc<TunnelRegistry>>>,
    Path(machine_id): Path<i32>,
    headers: HeaderMap,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) || !csrf_ok(&headers) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let Some(account) = signed_in(&rt, &headers).await else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let Some(person) = person_of(&rt, account.id).await else {
        return err(StatusCode::NOT_FOUND, "machine not found");
    };
    let machine = match owned_machine(&rt, &person, machine_id).await {
        Ok(Some(machine)) => machine,
        Ok(None) => return err(StatusCode::NOT_FOUND, "machine not found"),
        Err(e) => return load_error(e),
    };
    let disconnected = match (tunnel.as_deref(), key_of(&machine)) {
        (Some(registry), Some(key)) => registry.close_connection(&key, CloseCode::Rejected),
        _ => false,
    };
    // The connection's driver deregisters it (and announces the machine) a
    // moment later; announce here too so an open console flips the row at once.
    if disconnected {
        rt.live.publish(
            Change::visible_to(Viewer::Person(person.id))
                .entity(Entity::Machine)
                .id(machine.id),
        );
    }
    json_ok(json!({ "ok": true, "disconnected": disconnected }))
}

/// `POST /api/account/machines/{id}/revoke` — revoke a machine (CSRF-protected).
///
/// The live tunnel is closed with `KeyRevoked` first, so it drops at once
/// rather than waiting for the reverify poll; the machine is then deleted in the
/// store, cascading its services, so its hostnames stop resolving. Both sides
/// read the same `machine.key_id` row, so the registry and the store cannot
/// disagree. Revoking an already-gone key is the goal state, not an error.
async fn machine_revoke(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(tunnel): Extension<Option<Arc<TunnelRegistry>>>,
    Path(machine_id): Path<i32>,
    headers: HeaderMap,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) || !csrf_ok(&headers) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let Some(account) = signed_in(&rt, &headers).await else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let Some(person) = person_of(&rt, account.id).await else {
        return err(StatusCode::NOT_FOUND, "machine not found");
    };
    let machine = match owned_machine(&rt, &person, machine_id).await {
        Ok(Some(machine)) => machine,
        Ok(None) => return err(StatusCode::NOT_FOUND, "machine not found"),
        Err(e) => return load_error(e),
    };
    let Some(key) = key_of(&machine) else {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "this machine has no usable key",
        );
    };
    if let Some(registry) = tunnel.as_deref() {
        registry.close_connection(&key, CloseCode::KeyRevoked);
    }
    match rt.store.revoke_machine(&key).await {
        Ok(_) => {
            // A removal changes the set of machines, so every machine view
            // re-reads, not just the one that vanished.
            rt.live
                .publish(Change::visible_to(Viewer::Person(person.id)).entity(Entity::Machine));
            json_ok(json!({ "ok": true }))
        }
        Err(e) => load_error(e),
    }
}

/// `POST /api/account/pair/lookup` — resolve a handle without consuming it.
///
/// The handle arrives in the body, never the query, so it cannot reach a log or
/// a `Referer`. A missing handle is answered with `gone`, which the SPA renders
/// as "this request is no longer waiting" rather than an error.
async fn pair_lookup(
    State(rt): State<Arc<AccountRuntime>>,
    headers: HeaderMap,
    Json(req): Json<pair::HandleRequest>,
) -> Response {
    let Some(account) = signed_in(&rt, &headers).await else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let Some(view) = rt.pairings.view(&req.handle) else {
        return json_ok(serde_json::to_value(pair::LookupResponse::Gone).unwrap_or(Value::Null));
    };
    match lookup(&rt, &account, &view).await {
        Ok(response) => json_ok(serde_json::to_value(&response).unwrap_or(Value::Null)),
        Err(e) => {
            tracing::warn!(error = %e, "pairing lookup failed");
            err(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily unavailable; please try again",
            )
        }
    }
}

async fn lookup(
    rt: &AccountRuntime,
    account: &account::Model,
    view: &pairing::PendingView,
) -> Result<pair::LookupResponse, StoreError> {
    let person = rt.store.person_by_account(account.id).await?;
    let existing = |name: String| pair::Proposed {
        name,
        is_new: false,
    };
    let proposed = |name: String| pair::Proposed { name, is_new: true };
    let (person, machine) = match (&view.target, person) {
        (pair::Target::Existing { machine_id }, Some(person)) => {
            let Some(machine) = owned_machine(rt, &person, *machine_id).await? else {
                return Ok(pair::LookupResponse::NotYourMachine);
            };
            (existing(person.name), existing(machine.name))
        }
        (pair::Target::Existing { .. }, None) => return Ok(pair::LookupResponse::NotYourMachine),
        (pair::Target::New { hostname }, Some(person)) => {
            let machine = rt.store.propose_machine_name(person.id, hostname).await?;
            (existing(person.name), proposed(machine))
        }
        // A person that does not exist yet has no machines to collide with.
        (pair::Target::New { hostname }, None) => (
            proposed(rt.store.propose_person_name(&account.name).await?),
            proposed(names::slugify_machine(hostname)),
        ),
    };
    Ok(pair::LookupResponse::Waiting {
        fingerprint: view.key_id.to_string(),
        account: account.name.clone(),
        person,
        machine,
    })
}

/// What an accepted pairing does, settled before the handle is consumed.
enum Approval {
    /// Move the machine `machine_id` onto the new key, if `person` owns it.
    Rekey {
        person: Option<person::Model>,
        machine_id: i32,
    },
    /// Create a machine named after `requested` for the owner.
    New { owner: Owner, requested: String },
}

/// Who a new machine belongs to.
enum Owner {
    Existing(person::Model),
    /// The account has no person yet: create it under this (free) slug.
    New(String),
}

/// `POST /api/account/pair/accept` — approve the pending pairing.
///
/// The request is validated against the pending pairing first, so a name the
/// person can fix leaves the handle waiting. Only then is the handle consumed
/// — single use even if the writes fail — and the outcome pushed down the CLI's
/// channel.
async fn pair_accept(
    State(rt): State<Arc<AccountRuntime>>,
    headers: HeaderMap,
    Json(req): Json<pair::AcceptRequest>,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) || !csrf_ok(&headers) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let Some(account) = signed_in(&rt, &headers).await else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let Some(view) = rt.pairings.view(&req.handle) else {
        return action(false, NO_LONGER_WAITING);
    };
    let person = match rt.store.person_by_account(account.id).await {
        Ok(person) => person,
        Err(e) => {
            tracing::warn!(error = %e, "pairing: person lookup failed");
            return action(false, COULD_NOT_PAIR);
        }
    };

    // Names the person may not set here are refused while the request is
    // still waiting, so the page can correct itself.
    let approval = match view.target {
        pair::Target::Existing { machine_id } => {
            if !req.person_slug.is_empty() || !req.machine_name.is_empty() {
                return action(
                    false,
                    "A machine that moves onto a new key keeps its names.",
                );
            }
            Approval::Rekey { person, machine_id }
        }
        pair::Target::New { hostname } => {
            let slug = req.person_slug;
            let owner = match person {
                Some(existing) if !slug.is_empty() => {
                    return action(
                        false,
                        &format!(
                            "This account's person name is already '{}' and cannot be changed here.",
                            existing.name
                        ),
                    );
                }
                Some(existing) => Owner::Existing(existing),
                None if slug.is_empty() => return action(false, "Choose a person name."),
                None => match validate_person_slug(&rt, &slug).await {
                    Ok(slug) => Owner::New(slug),
                    Err(message) => return action(false, &message),
                },
            };
            let requested = if req.machine_name.is_empty() {
                hostname
            } else {
                req.machine_name
            };
            Approval::New { owner, requested }
        }
    };

    let Some(taken) = rt.pairings.take(&req.handle) else {
        return action(false, NO_LONGER_WAITING);
    };
    match approve(&rt, &account, approval, &taken.key_id).await {
        Ok(approved) => {
            taken.finish(approved);
            action(true, "")
        }
        Err((code, message)) => {
            taken.fail(code, message);
            action(false, message)
        }
    }
}

/// The person slug a new person may take: valid, and not anyone's yet.
async fn validate_person_slug(rt: &AccountRuntime, slug: &str) -> Result<String, String> {
    let slug = slug.trim().to_ascii_lowercase();
    if !names::is_valid_person_or_machine(&slug) {
        return Err("A person name is 1 to 15 lowercase letters or digits.".into());
    }
    match rt.store.get_person_by_name(&slug).await {
        Ok(None) => Ok(slug),
        Ok(Some(_)) => Err(format!(
            "The person name '{slug}' is taken. Choose another."
        )),
        Err(e) => {
            tracing::warn!(error = %e, "pairing: person name lookup failed");
            Err(COULD_NOT_PAIR.into())
        }
    }
}

/// Applies an accepted pairing, returning what to tell the CLI.
///
/// A key paired meanwhile, a name taken meanwhile: the unique indexes refuse
/// the write, and the pairing fails as unavailable.
async fn approve(
    rt: &AccountRuntime,
    account: &account::Model,
    approval: Approval,
    key_id: &weaver_mux::KeyId,
) -> Result<pair::ServerMessage, (pair::FailureCode, &'static str)> {
    let unavailable = |e: StoreError| {
        tracing::warn!(error = %e, "pairing: could not apply the approval");
        (pair::FailureCode::Unavailable, COULD_NOT_PAIR)
    };
    let not_yours = (pair::FailureCode::NotYourMachine, NOT_YOUR_MACHINE);
    let (person, machine) = match approval {
        Approval::Rekey { person, machine_id } => {
            // Ownership is re-checked now: the lookup's answer may be stale.
            let person = person.ok_or(not_yours)?;
            let machine = owned_machine(rt, &person, machine_id)
                .await
                .map_err(unavailable)?
                .ok_or(not_yours)?;
            let machine = rt
                .store
                .replace_machine_key(machine.id, key_id)
                .await
                .map_err(unavailable)?;
            (person, machine)
        }
        Approval::New { owner, requested } => {
            let person = match owner {
                Owner::Existing(person) => person,
                Owner::New(slug) => rt
                    .store
                    .create_person(account.id, &slug)
                    .await
                    .map_err(unavailable)?,
            };
            let name = rt
                .store
                .propose_machine_name(person.id, &requested)
                .await
                .map_err(unavailable)?;
            let machine = rt
                .store
                .create_machine(person.id, &name, key_id)
                .await
                .map_err(unavailable)?;
            (person, machine)
        }
    };
    // An addition changes the set of machines: every machine view re-reads.
    rt.live
        .publish(Change::visible_to(Viewer::Person(person.id)).entity(Entity::Machine));
    Ok(pair::ServerMessage::Approved {
        machine_id: machine.id,
        person: person.name,
        machine: machine.name,
    })
}

/// `POST /api/account/pair/reject` — refuse the pending pairing.
async fn pair_reject(
    State(rt): State<Arc<AccountRuntime>>,
    headers: HeaderMap,
    Json(req): Json<pair::HandleRequest>,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) || !csrf_ok(&headers) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    if signed_in(&rt, &headers).await.is_none() {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    }
    match rt.pairings.take(&req.handle) {
        Some(taken) => {
            taken.fail(
                pair::FailureCode::Rejected,
                "The pairing request was rejected in the browser.",
            );
            action(true, "")
        }
        None => action(false, NO_LONGER_WAITING),
    }
}

/// `POST /api/account/password` — change the signed-in account's password.
///
/// Reauthentication is the point: the design contract requires it for every
/// sensitive action, so the current password is verified before anything is
/// written, exactly the way `/login` verifies it. The new password then passes
/// the same policy and hashing as a reset, and the store rotates the credential
/// and kills **every** session — including this one — so the change ends with a
/// fresh sign-in, identical to a reset. The notification email is sent detached,
/// after the write has committed.
async fn change_password(
    State(rt): State<Arc<AccountRuntime>>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) || !csrf_ok(&headers) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let Some(raw) = session::cookie(&headers, SESSION_COOKIE) else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let now = unix_secs();
    let Ok(Some(account)) = rt.sessions.account(&raw, now).await else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };

    // Reauthentication. A live credential is guaranteed for accounts that can
    // sign in with a password, so its absence is a server-side inconsistency.
    let stored = rt
        .store
        .password_current_for(account.id)
        .await
        .ok()
        .flatten()
        .map(|credential| credential.encoded_hash);
    let Some(stored) = stored else {
        return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    };
    if !rt.passwords.verify(&req.current_password, &stored) {
        return field_error(
            StatusCode::BAD_REQUEST,
            FIELD_CURRENT_PASSWORD,
            "that is not your current password",
        );
    }

    if let Err(error) = rt.passwords.validate(&req.new_password).await {
        let (status, message) = password_error(error, rt.passwords.min_length());
        return field_error(status, FIELD_NEW_PASSWORD, &message);
    }
    let Ok(encoded_hash) = rt.passwords.hash(&req.new_password) else {
        return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    };

    match rt
        .store
        .account_change_password(account.id, &encoded_hash, now)
        .await
    {
        Ok(_) => {
            // Off the response path, and only after the change committed — a
            // notification must never describe a write that rolled back.
            if let Some(identity) = rt
                .store
                .email_identity_for_account(account.id)
                .await
                .ok()
                .flatten()
            {
                let rt = Arc::clone(&rt);
                let name = account.name.clone();
                let email = identity.email.clone();
                tokio::spawn(async move {
                    if let Err(error) = send_password_changed(&rt, &name, &email, now).await {
                        tracing::warn!(%error, "password-changed email was not sent");
                    }
                });
            }
            // Every session is now dead, this one included: clear the cookie so
            // the browser does not keep presenting a session that no longer
            // exists, and let the SPA send the user to sign in again.
            with_cookie(
                json_ok(json!({ "outcome": "changed" })),
                rt.sessions.clear_session_cookie(),
            )
        }
        // No live credential left to rotate: a concurrent change won the race.
        Err(StoreError::Conflict(_)) => err(
            StatusCode::CONFLICT,
            "this password has already been changed",
        ),
        Err(_) => err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable"),
    }
}

/// Serves the embedded SPA shell and its assets, and the vendored ALTCHA widget.
///
/// The app owns the admin host root, so `/` is the landing page and `_app/…`
/// are its assets. Legacy `/account/…` links redirect to the root equivalent.
async fn spa(State(_rt): State<Arc<AccountRuntime>>, headers: HeaderMap, uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    // Unknown API paths must not fall through to the SPA shell.
    if path.starts_with("api/account") {
        return err(StatusCode::NOT_FOUND, "not found");
    }

    // The app used to live under `/account`; redirect old links to the root.
    if path == "account" || path.starts_with("account/") {
        let rest = path
            .strip_prefix("account")
            .unwrap_or("")
            .trim_start_matches('/');
        let location = if rest.is_empty() {
            "/".to_string()
        } else {
            format!("/{rest}")
        };
        return redirect(&location);
    }

    // The vendored ALTCHA widget. Both a stable path (`assets/altcha/altcha.js`)
    // and the versioned demo path (`assets/altcha/<version>/altcha.js`) resolve
    // to the same embedded bytes. The admin path is unversioned, so it is only
    // revalidated, never cached immutably.
    if let Some(rest) = path.strip_prefix("assets/altcha/") {
        let candidate = weaver_assets::altcha_asset(rest).or_else(|| {
            rest.split_once('/')
                .and_then(|(_, tail)| weaver_assets::altcha_asset(tail))
        });
        if let Some(asset) = candidate {
            return asset_response(&headers, &asset, CACHE_REVALIDATE);
        }
        return err(StatusCode::NOT_FOUND, "not found");
    }

    if let Some(asset) = weaver_assets::spa_asset(path) {
        // Content-hashed assets are immutable; the unhashed ones are not.
        let cache = if path.starts_with("_app/immutable/") {
            CACHE_IMMUTABLE
        } else {
            CACHE_REVALIDATE
        };
        return asset_response(&headers, &asset, cache);
    }

    // History-route deep links and the root return the shell, never stored so a
    // deploy is picked up immediately.
    asset_response(&headers, &weaver_assets::spa_index(), CACHE_NO_STORE)
}

// ----- helpers --------------------------------------------------------------

/// Verifies and consumes an ALTCHA payload for one purpose, mapping engine
/// results onto HTTP responses. `None` means the proof was accepted; `Some` is a
/// ready refusal response.
async fn consume_altcha(rt: &AccountRuntime, encoded: &str, purpose: &str) -> Option<Response> {
    if encoded.is_empty() {
        return Some(err(
            StatusCode::FORBIDDEN,
            "the proof-of-work check is required; please try again",
        ));
    }
    let Some(payload) = crate::altcha::decode_payload(encoded) else {
        return Some(err(
            StatusCode::BAD_REQUEST,
            "the proof-of-work payload is malformed",
        ));
    };
    let Some(client) = payload
        .challenge
        .parameters
        .data
        .as_ref()
        .and_then(|data| data.get("client"))
        .and_then(Value::as_str)
    else {
        return Some(err(
            StatusCode::BAD_REQUEST,
            "the proof-of-work payload is malformed",
        ));
    };
    match rt
        .altcha
        .verify_payload(client, &payload, purpose, purpose)
        .await
    {
        Ok(_) => None,
        Err(AltchaError::Proof(_)) => Some(err(
            StatusCode::FORBIDDEN,
            "the proof-of-work check failed; please try again",
        )),
        Err(AltchaError::Store(_)) => Some(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily unavailable; please try again",
        )),
    }
}

/// Issues a fresh verification token and emails the link. The pending row is the
/// retry mechanism, so a failure here is logged, not fatal.
async fn send_verification(
    rt: &AccountRuntime,
    pending: &pending_registration::Model,
    now: i64,
) -> Result<(), String> {
    let raw = session::new_token();
    rt.store
        .verification_token_issue(
            pending.id,
            NewVerificationToken {
                email_lookup_key: pending.lookup_key.clone(),
                token_digest: session::token_hash(&raw),
                purpose: PURPOSE_EMAIL_VERIFICATION.to_string(),
                issued_at: now,
                expires_at: now + rt.config.verification_ttl_secs as i64,
            },
        )
        .await
        .map_err(|e| e.to_string())?;

    let Some(mailer) = &rt.mailer else {
        return Err("email is not configured".into());
    };
    let to =
        Mailbox::parse(&pending.email, Some(pending.name.clone())).map_err(|e| e.to_string())?;
    let template = Verification {
        verification_url: rt.verification_url(&raw),
        expires_in: human_duration(rt.config.verification_ttl_secs),
    };
    let email = mailer.compose(to, &template).map_err(|e| e.to_string())?;
    mailer.send(&email).await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Sends the welcome email once, best-effort, after activation succeeds.
async fn send_welcome(
    rt: &AccountRuntime,
    pending: &pending_registration::Model,
) -> Result<(), String> {
    let Some(mailer) = &rt.mailer else {
        return Err("email is not configured".into());
    };
    let to =
        Mailbox::parse(&pending.email, Some(pending.name.clone())).map_err(|e| e.to_string())?;
    let template = Welcome {
        account_url: rt.account_url(),
    };
    let email = mailer.compose(to, &template).map_err(|e| e.to_string())?;
    mailer.send(&email).await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Composes and sends the password-reset email for an already-persisted token.
/// `raw` is the plaintext token the recipient opens; it is never logged here.
async fn send_reset(rt: &AccountRuntime, name: &str, email: &str, raw: &str) -> Result<(), String> {
    let Some(mailer) = &rt.mailer else {
        return Err("email is not configured".into());
    };
    let to = Mailbox::parse(email, Some(name.to_string())).map_err(|e| e.to_string())?;
    let template = Reset {
        reset_url: rt.reset_url(raw),
        expires_in: human_duration(rt.config.reset_ttl_secs),
    };
    let email = mailer.compose(to, &template).map_err(|e| e.to_string())?;
    mailer.send(&email).await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Composes and sends the "your password was changed" notification.
///
/// Carries the event time and a link to the ordinary, unauthenticated recovery
/// flow — never a pre-authorised action — so a recipient who does not recognise
/// the change can act on it safely.
async fn send_password_changed(
    rt: &AccountRuntime,
    name: &str,
    email: &str,
    now: i64,
) -> Result<(), String> {
    let Some(mailer) = &rt.mailer else {
        return Err("email is not configured".into());
    };
    let to = Mailbox::parse(email, Some(name.to_string())).map_err(|e| e.to_string())?;
    let template = PasswordChanged {
        event_time: human_timestamp(now),
        recovery_url: rt.password_recovery_url(),
    };
    let email = mailer.compose(to, &template).map_err(|e| e.to_string())?;
    mailer.send(&email).await.map_err(|e| e.to_string())?;
    Ok(())
}

/// The password inputs a refusal can be attributed to, so the SPA can
/// render the message on the offending field instead of form-wide.
const FIELD_CURRENT_PASSWORD: &str = "current_password";
const FIELD_NEW_PASSWORD: &str = "new_password";

/// Maps a password-policy failure onto a status and a safe, user-facing message.
///
/// Split out from the response so a caller that knows which input failed can tag
/// the refusal with a `field`, while the single-password endpoints keep their
/// exact, field-less body.
fn password_error(
    error: crate::account::password::PasswordError,
    min_length: usize,
) -> (StatusCode, String) {
    use crate::account::password::PasswordError;
    match error {
        PasswordError::TooShort { .. } => (
            StatusCode::BAD_REQUEST,
            format!("choose a password of at least {min_length} characters"),
        ),
        PasswordError::Breached => (
            StatusCode::BAD_REQUEST,
            "this password appears in a known breach; choose a different one".to_string(),
        ),
        PasswordError::BreachUnavailable(_) | PasswordError::Hash(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily unavailable; please try again".to_string(),
        ),
    }
}

/// Maps a password-policy failure onto a field-less response.
fn password_error_response(
    rt: &AccountRuntime,
    error: crate::account::password::PasswordError,
) -> Response {
    let (status, message) = password_error(error, rt.passwords.min_length());
    err(status, &message)
}

/// A refusal tagged with the input it belongs to, so the SPA can place the
/// message on that field. Additive to the body: `error` keeps its meaning.
fn field_error(status: StatusCode, field: &str, message: &str) -> Response {
    (status, Json(json!({ "error": message, "field": field }))).into_response()
}

/// A same-origin check for state-changing requests.
///
/// A browser sends `Sec-Fetch-Site`; `same-origin`/`none` are allowed and
/// `cross-site` is refused. When only `Origin` is present it must match the
/// account origin. Absent both, the request is not a browser cross-site attempt
/// (the API is not reachable from a third-party page without one of these).
fn origin_ok(headers: &HeaderMap, base_url: &str) -> bool {
    if let Some(site) = headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
    {
        return matches!(site, "same-origin" | "none");
    }
    if let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        return origin.trim_end_matches('/') == base_url.trim_end_matches('/');
    }
    true
}

/// Double-submit CSRF check: the header must equal the CSRF cookie.
fn csrf_ok(headers: &HeaderMap) -> bool {
    match (
        headers
            .get(CSRF_HEADER)
            .and_then(|value| value.to_str().ok()),
        session::cookie(headers, CSRF_COOKIE),
    ) {
        (Some(header), Some(cookie)) => !header.is_empty() && header == cookie,
        _ => false,
    }
}

/// A 302 redirect to a same-origin path.
fn redirect(location: &str) -> Response {
    let mut response = Response::new(axum::body::Body::empty());
    *response.status_mut() = StatusCode::FOUND;
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

/// A successful JSON response.
pub(crate) fn json_ok(value: Value) -> Response {
    (StatusCode::OK, Json(value)).into_response()
}

/// A JSON error response.
pub(crate) fn err(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

/// Appends a `Set-Cookie` header if it is a valid header value.
fn with_cookie(mut response: Response, cookie: String) -> Response {
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

/// Cache policy for a content-hashed asset: eternal, because the URL changes
/// whenever the bytes do.
const CACHE_IMMUTABLE: &str = "public, max-age=31536000, immutable";
/// Cache policy for a stable URL: revalidate before reuse.
const CACHE_REVALIDATE: &str = "no-cache";
/// Cache policy for the SPA shell: never store it, so a deploy takes effect at
/// once.
const CACHE_NO_STORE: &str = "no-store";

/// A static asset response, serving the best variant the client accepts.
/// `Vary: accept-encoding` is sent whenever the asset has a compressed variant,
/// so shared caches key on the encoding rather than mixing the two.
fn asset_response(
    headers: &HeaderMap,
    asset: &weaver_assets::Asset,
    cache: &'static str,
) -> Response {
    let coding = weaver_assets::negotiate_encoding(
        headers
            .get(header::ACCEPT_ENCODING)
            .and_then(|value| value.to_str().ok()),
        asset,
    );
    let mut response = Response::new(axum::body::Body::from(asset.encoded(coding)));
    let out = response.headers_mut();
    out.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(asset.content_type),
    );
    out.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    if asset.gzip.is_some() || asset.zstd.is_some() {
        out.insert(header::VARY, HeaderValue::from_static("accept-encoding"));
    }
    if let Some(token) = coding.token()
        && let Ok(value) = HeaderValue::from_str(token)
    {
        out.insert(header::CONTENT_ENCODING, value);
    }
    response
}

/// Normalises an address into its lookup/uniqueness key. No dot/plus rewriting.
fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// A short human phrase for a lifetime, used in email copy. Singular forms are
/// used for exactly one unit (`"1 hour"`, not `"1 hours"`).
fn human_duration(secs: u64) -> String {
    if secs >= 3600 && secs.is_multiple_of(3600) {
        let hours = secs / 3600;
        if hours == 1 {
            "1 hour".to_string()
        } else {
            format!("{hours} hours")
        }
    } else if secs >= 60 && secs.is_multiple_of(60) {
        let minutes = secs / 60;
        if minutes == 1 {
            "1 minute".to_string()
        } else {
            format!("{minutes} minutes")
        }
    } else {
        format!("{secs} seconds")
    }
}

/// A human, timezone-qualified instant for security copy (e.g.
/// `2026-10-12 14:01 UTC`). The zone comes from the server, so the exact string
/// is environment-dependent and must not be asserted literally in tests.
fn human_timestamp(secs: i64) -> String {
    let zoned = jiff::Timestamp::from_second(secs)
        .map(|ts| ts.to_zoned(jiff::tz::TimeZone::system()))
        .unwrap_or_else(|_| jiff::Zoned::now());
    format!(
        "{} {}",
        zoned.strftime("%Y-%m-%d %H:%M"),
        zoned.strftime("%Z")
    )
}
