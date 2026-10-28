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
use axum::{Extension, Json, Router, middleware};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use weaver_abuse::AltchaError;

use crate::account::auth::{AuthLevel, AuthManager, EventKind, SessionContext, watch};
use crate::account::passkey;
use crate::account::session::{self, CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE};
use crate::account::views::{
    USAGE_WINDOW_SECS, key_of, load_error, owned_machine, person_of, person_services, signed_in,
};
use crate::account::{AccountRuntime, pairing, second_factor, totp, views};
use crate::email::{Mailbox, PasswordChanged, Reset, SignInCode, Verification, Welcome};
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
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

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
        .route("/api/account/login/verify", post(login_verify))
        .route("/api/account/login/resend", post(login_resend))
        .route("/api/account/login/totp", post(login_totp))
        .route("/api/account/me", get(me))
        .route("/api/account/avatar", get(avatar))
        .route("/api/account/logout", post(logout))
        .route("/api/account/delete", post(delete_account))
        .route("/api/account/password", post(change_password))
        .route("/api/account/confirm-password", post(confirm_password))
        // Passkeys (WVR-163). The singular names the *ceremony* — signing in,
        // and stepping a session up to `Certain` without a password — while the
        // plural names the credentials themselves.
        .route("/api/account/passkey/begin", post(passkey_signin_begin))
        .route("/api/account/passkey/finish", post(passkey_signin_finish))
        .route(
            "/api/account/passkey/step-up/begin",
            post(passkey_stepup_begin),
        )
        .route(
            "/api/account/passkey/step-up/finish",
            post(passkey_stepup_finish),
        )
        .route("/api/account/passkeys/begin", post(passkey_register_begin))
        .route(
            "/api/account/passkeys/finish",
            post(passkey_register_finish),
        )
        .route("/api/account/passkeys/{id}/remove", post(passkey_remove))
        // Authenticator apps (WVR-166). `begin` and `confirm` are `Certain`
        // (the gate's business): an app is a second factor that works without
        // the mailbox, so planting one must take a proof of presence. Removing
        // one is ordinary authenticated work, like removing a passkey.
        .route("/api/account/totp/begin", post(totp_begin))
        .route("/api/account/totp/confirm", post(totp_confirm))
        .route("/api/account/totp/{id}/remove", post(totp_remove))
        // What the Security page shows, in one request (WVR-166): whether a
        // password is set, the passkeys, and the authenticator apps. It is a
        // page's data, refreshed by the page's own actions, rather than three
        // endpoints each arriving when it feels like it.
        .route("/api/account/security", get(security))
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
        // Deny by default: every `/api/account/*` request must hold the level it
        // needs, and the gate is what builds the request's `AuthManager` (WVR-167).
        .layer(middleware::from_fn_with_state(
            runtime.clone(),
            crate::account::auth::gate,
        ))
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

/// Body of a `POST /api/account/totp/begin` (WVR-166).
#[derive(Deserialize)]
struct TotpBeginRequest {
    /// What the person calls this app; empty when they did not name it. It is the
    /// label the authenticator displays beside the issuer, and it is what tells
    /// two enrolled apps apart in the console.
    #[serde(default)]
    name: String,
}

/// Body of a `POST /api/account/totp/confirm` (WVR-166).
#[derive(Deserialize)]
struct TotpConfirmRequest {
    /// The pending enrolment's row id, from `totp/begin`.
    id: i32,
    code: String,
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
        Ok(account) => {
            watch::sessions_changed(&rt.live, account.id);
            json_ok(json!({ "outcome": "reset" }))
        }
        Err(StoreError::Conflict(_)) => err(
            StatusCode::BAD_REQUEST,
            "this link has expired or has already been used",
        ),
        Err(_) => err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable"),
    }
}

/// `POST /api/account/login` — verify the password and start the second factor.
///
/// Success opens a `Basic` session (the password factor is proven) and emails a
/// one-time code — unless the account has a confirmed authenticator app, in
/// which case nothing is issued and nothing is sent (WVR-166): the app is the
/// factor offered, and the emailed code is behind the console's "email me a code
/// instead" (which is `POST /api/account/login/resend`). It does **not** sign
/// anyone in: the session can reach nothing but the climb until one of the two
/// codes is accepted. If the code cannot be sent the session is rolled back,
/// rather than leaving a page that can never be satisfied.
///
/// The sign-in is recorded on the inactivity clock (WVR-160) only once the code
/// is accepted, so an abandoned second step is never mistaken for activity.
async fn login(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(manager): Extension<AuthManager>,
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
    let Some(account) = account.as_ref().filter(|_| password_ok) else {
        let _ = manager
            .login_failed(req.email.trim(), account.as_ref().map(|account| account.id))
            .await;
        return err(StatusCode::UNAUTHORIZED, "invalid email or password");
    };

    // The second factor travels by email, so an account without an address
    // cannot sign in. Only test-only fixtures lack one; treat it as an
    // unreachable state, never a bypass.
    let Some(identity) = rt
        .store
        .email_identity_for_account(account.id)
        .await
        .ok()
        .flatten()
    else {
        tracing::warn!(
            account_id = account.id,
            "sign-in blocked: account has no email address"
        );
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "sign-in is temporarily unavailable",
        );
    };

    let raw = match rt.sessions.create(account.id, now).await {
        Ok(raw) => raw,
        Err(_) => return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable"),
    };
    let Some(session) = rt
        .store
        .session_live(&session::token_hash(&raw), now)
        .await
        .ok()
        .flatten()
    else {
        let _ = rt.sessions.invalidate(&raw, now).await;
        return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    };
    let context = SessionContext {
        session_id: session.id,
        account_id: account.id,
    };

    if manager.password_checked(context).await.is_err() {
        let _ = rt.sessions.invalidate(&raw, now).await;
        return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    }

    // The factor offered is the strongest the account configured, and the one it
    // configured on purpose is the authenticator app: with a confirmed one there
    // is no code to issue and no email to send (WVR-166). Nothing is taken from
    // anyone — the emailed code is one click away, `POST /login/resend` being
    // what the console's "email me a code instead" calls.
    let has_app = rt
        .store
        .totp_confirmed_count_for(account.id)
        .await
        .map(|count| count > 0)
        .unwrap_or(false);
    if !has_app {
        let Ok(code) = second_factor::issue(&rt.store, session.id, now).await else {
            let _ = rt.sessions.invalidate(&raw, now).await;
            return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
        };
        if manager.email_otp_issued(context).await.is_err() {
            let _ = rt.sessions.invalidate(&raw, now).await;
            return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
        }
        if let Err(error) = send_signin_code(&rt, &account.name, &identity.email, &code).await {
            tracing::warn!(account_id = account.id, error = %error, "sign-in code email was not sent");
            let _ = rt.sessions.invalidate(&raw, now).await;
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "we could not send your code; try again",
            );
        }
    }
    let csrf = session::new_token();
    let response = json_ok(json!({ "status": "second_factor" }));
    let response = with_cookie(response, rt.sessions.session_cookie(&raw));
    with_cookie(response, rt.sessions.csrf_cookie(&csrf))
}

/// Body of a `POST /api/account/login/verify`.
#[derive(Deserialize)]
struct LoginVerifyRequest {
    code: String,
}

/// `POST /api/account/login/verify` — accept the emailed code and finish signing
/// in (CSRF-protected).
///
/// One of the two places a session becomes `Strong` — its twin is
/// `/login/totp` (WVR-166) — and, with it, the only places the inactivity clock
/// advances. A refusal is a `400` (never a `401`, which the SPA would read as
/// "session expired") and invites a re-send.
async fn login_verify(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(manager): Extension<AuthManager>,
    headers: HeaderMap,
    Json(req): Json<LoginVerifyRequest>,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) || !csrf_ok(&headers) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let Some(session) = manager.session() else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let now = unix_secs();
    match second_factor::verify(&rt.store, session.session_id, &req.code, now).await {
        Ok(()) => {
            if manager.email_otp_verified(session).await.is_err() {
                return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
            }
            // The sign-in is complete only now: this is what the sweep reads.
            if rt
                .store
                .account_record_login(session.account_id, now)
                .await
                .is_err()
            {
                return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
            }
            tracing::info!(account_id = session.account_id, "Second factor verified");
            json_ok(json!({ "ok": true }))
        }
        Err(error) => {
            let _ = manager.email_otp_failed(session).await;
            tracing::warn!(
                account_id = session.account_id,
                reason = ?error,
                "Second factor refused"
            );
            err(StatusCode::BAD_REQUEST, error.message())
        }
    }
}

/// `POST /api/account/login/totp` — accept a code from an authenticator app and
/// finish signing in (CSRF-protected) (WVR-166).
///
/// The app's twin of `/login/verify`, with the same contract: it is a way out of
/// a `Basic` session, a refusal is a `400` and never a `401`, and taking it is
/// what records the sign-in on the inactivity clock. What differs is what it
/// verifies against — every confirmed app of the account, each with its own
/// one-step drift window and its own replay guard — and that wrong codes are
/// counted: six digits behind a stolen password are guessable in a way a code
/// sitting in a mailbox is not.
async fn login_totp(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(manager): Extension<AuthManager>,
    headers: HeaderMap,
    Json(req): Json<LoginVerifyRequest>,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) || !csrf_ok(&headers) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let Some(session) = manager.session() else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let now = unix_secs();
    // The allowance is counted over this session's own window and from its own
    // rows, so it can only ever stop the session that spent it: a guesser
    // exhausts their session, never the owner's, and the emailed code stays a
    // way through for both.
    let since = now - rt.config.session_ttl_secs as i64;
    let wrong = rt
        .store
        .auth_event_count_since(session.session_id, EventKind::TotpFailed.as_str(), since)
        .await
        .unwrap_or(0);
    match totp::verify(
        &rt.store,
        &rt.config.totp_key,
        session.account_id,
        &req.code,
        wrong,
        now,
    )
    .await
    {
        Ok(()) => {
            if manager.totp_verified(session).await.is_err()
                || rt
                    .store
                    .account_record_login(session.account_id, now)
                    .await
                    .is_err()
            {
                return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
            }
            tracing::info!(
                account_id = session.account_id,
                "Second factor verified with an authenticator app"
            );
            json_ok(json!({ "ok": true }))
        }
        Err(error) => {
            let _ = manager.totp_failed(session).await;
            tracing::warn!(
                account_id = session.account_id,
                reason = ?error,
                "Authenticator code refused"
            );
            authenticator_problem(error, StatusCode::BAD_REQUEST, error.message())
        }
    }
}

/// `POST /api/account/login/resend` — send a fresh code for the same sign-in
/// (CSRF-protected, throttled).
///
/// Re-issuing replaces the challenge, so the previous code stops working and the
/// attempt count and TTL restart.
async fn login_resend(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(manager): Extension<AuthManager>,
    headers: HeaderMap,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) || !csrf_ok(&headers) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let Some(session) = manager.session() else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let now = unix_secs();

    // Enforce the re-send cooldown against the last issued code.
    if let Some(last_sent_at) = second_factor::last_sent_at(&rt.store, session.session_id).await
        && now - last_sent_at < rt.config.resend_cooldown_secs as i64
    {
        return json_ok(json!({ "status": "cooldown" }));
    }

    let Some(identity) = rt
        .store
        .email_identity_for_account(session.account_id)
        .await
        .ok()
        .flatten()
    else {
        return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    };
    let Ok(Some(account)) = rt.store.account_by_id(session.account_id).await else {
        return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    };

    let Ok(code) = second_factor::issue(&rt.store, session.session_id, now).await else {
        return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    };
    let _ = manager.email_otp_issued(session).await;
    if let Err(error) = send_signin_code(&rt, &account.name, &identity.email, &code).await {
        tracing::warn!(account_id = account.id, error = %error, "sign-in code email was not sent");
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "we could not send your code; try again",
        );
    }
    json_ok(json!({ "status": "second_factor" }))
}

/// `GET /api/account/me` — the session's identity and authentication, as an
/// event stream (see [`crate::account::auth::watch`]).
///
/// Reachable by anyone: an anonymous visitor is answered with a `none` state
/// rather than a `401`, which an `EventSource` could not read.
async fn me(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(manager): Extension<AuthManager>,
    headers: HeaderMap,
) -> Response {
    watch::serve(rt, manager, &headers)
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
///
/// Reachable at `Basic` too: a half-signed-in person must still be able to
/// leave. The trail is closed before the session is retired, so a proof given
/// earlier on this session can never be revived.
async fn logout(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(manager): Extension<AuthManager>,
    headers: HeaderMap,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) || !csrf_ok(&headers) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    if let Some(session) = manager.session() {
        let _ = manager.logged_out(session).await;
    }
    if let Some(raw) = session::cookie(&headers, SESSION_COOKIE) {
        let _ = rt.sessions.invalidate(&raw, unix_secs()).await;
    }
    // Announced only once the row is retired, so a stream that reloads on it
    // finds the session gone rather than briefly without its proofs.
    if let Some(session) = manager.session() {
        watch::session_changed(&rt.live, session);
    }
    with_cookie(
        json_ok(json!({ "ok": true })),
        rt.sessions.clear_session_cookie(),
    )
}

/// Body of a `POST /api/account/confirm-password`.
#[derive(Deserialize)]
struct ConfirmPasswordRequest {
    password: String,
}

/// `POST /api/account/confirm-password` — the `confirm_password` step: type the
/// password again to reach `Certain` (CSRF-protected).
///
/// A destructive action asks for `Certain` — the password proven moments ago —
/// so this is how a `strong` session gets back there without signing out and in
/// again. The proof it writes is the same one the sign-in writes, at the instant
/// it is checked, so it renews the window rather than opening a second one; the
/// session's streams announce it at once and the console sees the new level
/// without asking.
///
/// Reachable at `Strong` (the gate's default): a session that has not passed the
/// second factor climbs to `Strong` first, and only then comes here.
///
/// **It is only served where it is expected.** A session that already holds
/// `Certain` — the console having been told so, the lead window included — has
/// nothing to confirm, so it is refused rather than given another Argon2
/// verification and another `auth_event` row. That makes proving a password
/// something a client cannot ask for at will: at most once per step-up window,
/// which is exactly what the window is for.
async fn confirm_password(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(manager): Extension<AuthManager>,
    headers: HeaderMap,
    Json(req): Json<ConfirmPasswordRequest>,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) || !csrf_ok(&headers) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let Some(session) = manager.session() else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let now = unix_secs();
    let Some(raw) = session::cookie(&headers, SESSION_COOKIE) else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let Some((row, _)) = rt.sessions.live(&raw, now).await.ok().flatten() else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    if !manager.step_up_expected(row.expires_at).await {
        return err(StatusCode::CONFLICT, "this sign-in is already confirmed");
    }

    // A live credential is guaranteed for accounts that can sign in with a
    // password, so its absence is a server-side inconsistency rather than a
    // refusal to describe.
    let stored = rt
        .store
        .password_current_for(session.account_id)
        .await
        .ok()
        .flatten()
        .map(|credential| credential.encoded_hash);
    let Some(stored) = stored else {
        return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    };
    if !rt.passwords.verify(&req.password, &stored) {
        let _ = manager.password_confirmation_failed(session).await;
        return field_error(
            StatusCode::BAD_REQUEST,
            FIELD_PASSWORD,
            "that is not your password",
        );
    }

    if manager.password_confirmed(session).await.is_err() {
        return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    }
    tracing::info!(
        account_id = session.account_id,
        "Password confirmed for a step-up"
    );
    json_ok(json!({ "ok": true }))
}

/// Body of a delete-account request.
#[derive(Deserialize)]
struct DeleteAccountRequest {
    /// The string the user typed back; re-checked server-side below. Defaulted
    /// so an omitted field is an empty (never-matching) address — a `403`, not
    /// a deserializer `422` — keeping every refusal one shape.
    #[serde(default)]
    address: String,
}

/// `POST /api/account/delete` — irreversibly delete the signed-in account.
///
/// The gate demands `Certain`, not merely `Strong`: the password must have been
/// proven moments ago, so an unattended console cannot delete the account on a
/// session that has been open for hours. The console answers that refusal with
/// its password step (`POST /api/account/confirm-password`) and submits again —
/// and is refused again if the proof aged out while the confirmation was open.
/// Same-origin and CSRF are checked here as well. The typed address is re-checked **here**
/// against the account's real address, or its display name when it has no email
/// identity: the client-side gate is convenience, this is the control. Both
/// comparisons trim and case-fold, so casing or stray whitespace still matches.
///
/// Every live tunnel is closed with `KeyRevoked` before the rows go, so no
/// machine outruns the delete; the store then removes the account and all it
/// owns in one transaction. The response clears both cookies, and the removed
/// session rows mean a repeat request is answered `401`. The store call is
/// idempotent, so a concurrent double-submit that still holds a valid session
/// succeeds rather than failing on an already-gone account.
async fn delete_account(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(tunnel): Extension<Option<Arc<TunnelRegistry>>>,
    headers: HeaderMap,
    Json(req): Json<DeleteAccountRequest>,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) || !csrf_ok(&headers) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let Some(account) = signed_in(&rt, &headers).await else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    // The address when the account has one, else the display name — the same
    // value the SPA asks the user to type back.
    let expected = rt
        .store
        .email_identity_for_account(account.id)
        .await
        .ok()
        .flatten()
        .map(|identity| identity.email)
        .unwrap_or_else(|| account.name.clone());
    if req.address.trim().to_lowercase() != expected.trim().to_lowercase() {
        return err(StatusCode::FORBIDDEN, "request refused");
    }

    // The one shared deletion path closes every live tunnel first, so none
    // survives the rows to reconnect, then removes the account and all it owns.
    match rt.delete_account(account.id, tunnel.as_deref()).await {
        Ok(()) => with_cookie(
            with_cookie(
                json_ok(json!({ "ok": true })),
                rt.sessions.clear_session_cookie(),
            ),
            rt.sessions.clear_csrf_cookie(),
        ),
        Err(e) => load_error(e),
    }
}

// ----- passkeys (WVR-163) ---------------------------------------------------

/// What a passkey sign-in refused with says, whatever the reason.
///
/// The message is deliberately the password sign-in's, and so is the status: a
/// caller learns that signing in did not happen, and nothing about whether the
/// address exists — the difference between "no such account" and "that account
/// has no passkey" is not theirs to see.
const PASSKEY_SIGNIN_REFUSED: &str = "invalid email or password";

/// Body of a `POST /api/account/passkey/begin`.
#[derive(Deserialize)]
struct PasskeySigninBeginRequest {
    /// The address to sign in as. Empty means "offer me whatever this browser
    /// holds for you" — the discoverable, autofill ceremony.
    #[serde(default)]
    email: String,
}

/// Body of a `POST /api/account/passkey/finish`.
#[derive(Deserialize)]
struct PasskeyAssertionRequest {
    /// The single-use handle `begin` answered with.
    handle: String,
    /// The browser's assertion, as `PublicKeyCredential.toJSON()` spells it.
    credential: PublicKeyCredential,
}

/// Body of a `POST /api/account/passkeys/finish`.
#[derive(Deserialize)]
struct PasskeyRegistrationRequest {
    handle: String,
    /// What to call it; empty means the person did not name it.
    #[serde(default)]
    label: String,
    /// The browser's registration, as `PublicKeyCredential.toJSON()` spells it.
    credential: RegisterPublicKeyCredential,
}

/// The body every `begin` answers with: the handle to finish under, and the
/// options the browser needs.
fn passkey_started<T: Serialize>(started: passkey::Started<T>) -> Response {
    let options = serde_json::to_value(started.options).unwrap_or(Value::Null);
    json_ok(json!({ "handle": started.handle, "options": options }))
}

/// How a ceremony's failure is answered.
///
/// A store that could not be read is a `503`; everything else is the caller's to
/// decide, because "no such ceremony" and "that assertion did not verify" are
/// the same refusal to a person and different answers to a log.
fn passkey_problem(
    error: passkey::PasskeyError,
    refused: StatusCode,
    refused_message: &str,
) -> Response {
    match error {
        passkey::PasskeyError::Unavailable => {
            err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable")
        }
        _ => err(refused, refused_message),
    }
}

/// `POST /api/account/passkey/begin` — start a passkey sign-in (public).
///
/// With an address, the assertion is against that account's own credentials.
/// Without one, the browser is invited to offer a discoverable passkey in the
/// sign-in field's autofill, and the account is resolved from whichever
/// credential comes back.
///
/// Cheap: no password is hashed and no email is sent, so it is bounded by the
/// edge's login budget (and shares that budget with the password sign-in, whose
/// guessing surface this is) rather than by a proof of work.
async fn passkey_signin_begin(
    State(rt): State<Arc<AccountRuntime>>,
    headers: HeaderMap,
    Json(req): Json<PasskeySigninBeginRequest>,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let now = unix_secs();
    let lookup = normalize_email(&req.email);
    if lookup.is_empty() {
        return match passkey::begin_discover(&rt, now) {
            Ok(started) => passkey_started(started),
            Err(error) => passkey_problem(
                error,
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily unavailable",
            ),
        };
    }
    let account = match rt.store.email_identity_find(&lookup).await.ok().flatten() {
        Some(identity) => rt
            .store
            .account_by_id(identity.account_id)
            .await
            .ok()
            .flatten(),
        None => None,
    };
    // An address nothing matches and an account with no passkey are answered
    // identically, message and status, so probing can only learn whether *some*
    // account behind that address holds a passkey — no more than the login
    // budget already allows anyone to ask.
    let Some(account) = account else {
        return err(StatusCode::UNAUTHORIZED, PASSKEY_SIGNIN_REFUSED);
    };
    match passkey::begin_assert(&rt, account.id, now).await {
        Ok(started) => passkey_started(started),
        Err(error) => passkey_problem(error, StatusCode::UNAUTHORIZED, PASSKEY_SIGNIN_REFUSED),
    }
}

/// `POST /api/account/passkey/finish` — accept a passkey assertion and sign in
/// (public).
///
/// The one place a session opens with no password at all, and the one way an
/// anonymous request reaches `Strong` in a single step: the assertion carries
/// user verification, so the new session is `Certain` and falls to `Strong` when
/// the confirmation window ends.
async fn passkey_signin_finish(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(manager): Extension<AuthManager>,
    headers: HeaderMap,
    Json(req): Json<PasskeyAssertionRequest>,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let now = unix_secs();
    let Ok(asserted) = passkey::finish_signin(&rt, &req.handle, &req.credential, now).await else {
        // No session exists yet, so the trail gets the attempt and nothing else.
        let _ = manager.passkey_failed(None, None, "").await;
        return err(StatusCode::UNAUTHORIZED, PASSKEY_SIGNIN_REFUSED);
    };

    // The second factor travels by email, so an account without an address
    // cannot sign in; only test-only fixtures lack one, and it is never a
    // bypass.
    let Some(identity) = rt
        .store
        .email_identity_for_account(asserted.account_id)
        .await
        .ok()
        .flatten()
    else {
        tracing::warn!(
            account_id = asserted.account_id,
            "passkey sign-in blocked: account has no email address"
        );
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "sign-in is temporarily unavailable",
        );
    };
    let _ = identity;

    let raw = match rt.sessions.create(asserted.account_id, now).await {
        Ok(raw) => raw,
        Err(_) => return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable"),
    };
    let Some(session) = rt
        .store
        .session_live(&session::token_hash(&raw), now)
        .await
        .ok()
        .flatten()
    else {
        let _ = rt.sessions.invalidate(&raw, now).await;
        return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    };
    let context = SessionContext {
        session_id: session.id,
        account_id: asserted.account_id,
    };
    if manager
        .passkey_asserted(context, asserted.user_verified)
        .await
        .is_err()
        || rt
            .store
            .account_record_login(asserted.account_id, now)
            .await
            .is_err()
    {
        let _ = rt.sessions.invalidate(&raw, now).await;
        return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    }
    tracing::info!(account_id = asserted.account_id, "Signed in with a passkey");

    let csrf = session::new_token();
    let response = json_ok(json!({ "status": "signed_in" }));
    let response = with_cookie(response, rt.sessions.session_cookie(&raw));
    with_cookie(response, rt.sessions.csrf_cookie(&csrf))
}

/// `GET /api/account/security` — everything the Security page shows (WVR-166).
///
/// One request for one page. What an account signs in with — whether a password
/// is set, its passkeys, its authenticator apps — is one screen of the console,
/// and three endpoints meant three lists arriving in their own time and three
/// ways to refresh them. The page loads this through its data loader and its
/// actions invalidate that load, so there is one source and one refresh.
///
/// Authenticator apps are listed only once they are *confirmed*: an enrolment
/// that was begun and never proved is not a factor, is not shown, and is dropped
/// by the account sweep when it goes stale.
async fn security(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(manager): Extension<AuthManager>,
) -> Response {
    let Some(session) = manager.session() else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let account_id = session.account_id;
    let Ok(passkeys) = rt.store.passkeys_for_account(account_id).await else {
        return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    };
    let Ok(apps) = rt.store.totp_confirmed_for_account(account_id).await else {
        return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    };
    let Ok(credential) = rt.store.password_current_for(account_id).await else {
        return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    };
    let passkeys: Vec<passkey::PasskeyView> = passkeys.iter().map(passkey::view).collect();
    let apps: Vec<totp::AuthenticatorView> = apps.iter().map(totp::view).collect();
    json_ok(json!({
        "has_password": credential.is_some(),
        "passkeys": passkeys,
        "authenticator_apps": apps,
    }))
}

/// `POST /api/account/passkeys/begin` — start registering a passkey.
///
/// Reachable at `Certain` (the gate's business, not this handler's): a passkey
/// outlives every password, so planting one must take a proof of presence.
async fn passkey_register_begin(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(manager): Extension<AuthManager>,
    headers: HeaderMap,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) || !csrf_ok(&headers) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let Some(session) = manager.session() else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let now = unix_secs();
    let Some(account) = rt
        .store
        .account_by_id(session.account_id)
        .await
        .ok()
        .flatten()
    else {
        return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    };
    // Both are what the authenticator stores alongside the credential, so the
    // browser can show a person which account and which passkey they are
    // creating. Neither is a key.
    let email = rt
        .store
        .email_identity_for_account(session.account_id)
        .await
        .ok()
        .flatten()
        .map(|identity| identity.email)
        .unwrap_or_else(|| account.name.clone());
    match passkey::begin_register(&rt, session.account_id, &account.name, &email, now).await {
        Ok(started) => passkey_started(started),
        Err(error) => passkey_problem(error, StatusCode::BAD_REQUEST, error.message()),
    }
}

/// `POST /api/account/passkeys/finish` — store the registered credential.
async fn passkey_register_finish(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(manager): Extension<AuthManager>,
    headers: HeaderMap,
    Json(req): Json<PasskeyRegistrationRequest>,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) || !csrf_ok(&headers) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let Some(session) = manager.session() else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let now = unix_secs();
    match passkey::finish_register(&rt, &req.handle, &req.credential, &req.label, now).await {
        // The ceremony carries the account it was started for; a credential that
        // came back for another account is a refusal, not a filing.
        Ok(row) if row.account_id == session.account_id => {
            // The ways up changed for every session of this account: the
            // assertion is now one of them, and the console learns it from its
            // own stream rather than by asking.
            watch::sessions_changed(&rt.live, session.account_id);
            json_ok(json!({ "passkey": passkey::view(&row) }))
        }
        Ok(_) => {
            tracing::warn!(
                account_id = session.account_id,
                "passkey registration answered for another account"
            );
            err(
                StatusCode::BAD_REQUEST,
                passkey::PasskeyError::Refused.message(),
            )
        }
        Err(error) => passkey_problem(error, StatusCode::BAD_REQUEST, error.message()),
    }
}

/// `POST /api/account/passkeys/{id}/remove` — remove one of the account's own
/// passkeys (CSRF-protected).
///
/// Not a `Certain` action: removing a credential takes a way in away, and the
/// other way in — the password — still works, so it loses nothing an unattended
/// browser could be tricked into losing.
async fn passkey_remove(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(manager): Extension<AuthManager>,
    Path(id): Path<i32>,
    headers: HeaderMap,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) || !csrf_ok(&headers) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let Some(session) = manager.session() else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    match rt.store.passkey_remove(id, session.account_id).await {
        Ok(true) => {
            watch::sessions_changed(&rt.live, session.account_id);
            tracing::info!(
                account_id = session.account_id,
                passkey_id = id,
                "Passkey removed"
            );
            json_ok(json!({ "ok": true }))
        }
        Ok(false) => err(StatusCode::NOT_FOUND, "no such passkey"),
        Err(error) => load_error(error),
    }
}

/// `POST /api/account/totp/begin` — start enrolling an authenticator app
/// (CSRF-protected) (WVR-166).
///
/// Reachable at `Certain` (the gate's business, not this handler's): an app is a
/// second factor that works without the mailbox, so planting one takes a proof
/// of presence — the same rule as planting a passkey. An account may hold as
/// many apps as it likes, so this never replaces one.
///
/// The name is collected *here* rather than at confirmation because it is the
/// label the authenticator app displays: the URI an app is set up from is built
/// once, and cannot be relabelled afterwards.
async fn totp_begin(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(manager): Extension<AuthManager>,
    headers: HeaderMap,
    Json(req): Json<TotpBeginRequest>,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) || !csrf_ok(&headers) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let Some(session) = manager.session() else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let now = unix_secs();
    let Some(account) = rt
        .store
        .account_by_id(session.account_id)
        .await
        .ok()
        .flatten()
    else {
        return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
    };
    // The account's address, which the URI falls back to when the app is not
    // named. The name is the fallback for the test-only accounts with no
    // address — nothing but an opaque handler needs that.
    let address = rt
        .store
        .email_identity_for_account(session.account_id)
        .await
        .ok()
        .flatten()
        .map(|identity| identity.email)
        .unwrap_or_else(|| account.name.clone());
    match totp::begin(
        &rt.store,
        &rt.config.totp_key,
        session.account_id,
        &address,
        &req.name,
        now,
    )
    .await
    {
        // The secret is in the body, so nothing may store the response. No
        // session change is announced: an unconfirmed enrolment is not a way up.
        Ok(begun) => json_no_store(json!({
            "id": begun.id,
            "secret": begun.secret,
            "uri": begun.uri,
        })),
        Err(error) => authenticator_problem(error, StatusCode::BAD_REQUEST, error.message()),
    }
}

/// `POST /api/account/totp/confirm` — confirm a pending app with a code it
/// produced (CSRF-protected) (WVR-166).
///
/// Confirming is what makes the app a factor, so the ways up of every session of
/// the account change here — that is what the announcement is for. Entering a
/// valid code also proves the app's possession on *this* session, which is
/// recorded like any other proof.
async fn totp_confirm(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(manager): Extension<AuthManager>,
    headers: HeaderMap,
    Json(req): Json<TotpConfirmRequest>,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) || !csrf_ok(&headers) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let Some(session) = manager.session() else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let now = unix_secs();
    match totp::confirm(
        &rt.store,
        &rt.config.totp_key,
        session.account_id,
        req.id,
        &req.code,
        now,
    )
    .await
    {
        Ok(row) => {
            let _ = manager.totp_verified(session).await;
            watch::sessions_changed(&rt.live, session.account_id);
            tracing::info!(
                account_id = session.account_id,
                app_id = row.id,
                "Authenticator app enrolled"
            );
            json_ok(json!({ "app": totp::view(&row) }))
        }
        Err(error) => {
            let _ = manager.totp_failed(session).await;
            tracing::warn!(
                account_id = session.account_id,
                app_id = req.id,
                reason = ?error,
                "Authenticator code refused while enrolling"
            );
            authenticator_problem(error, StatusCode::BAD_REQUEST, error.message())
        }
    }
}

/// `POST /api/account/totp/{id}/remove` — remove one of the account's apps
/// (CSRF-protected) (WVR-166).
///
/// Not a `Certain` action, for the same reason removing a passkey is not: the
/// account keeps its other factors and the emailed code still signs it in, so
/// nothing is lost that an unattended browser could be tricked into losing. A
/// pending enrolment is removable here too — that is how it is abandoned.
async fn totp_remove(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(manager): Extension<AuthManager>,
    Path(id): Path<i32>,
    headers: HeaderMap,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) || !csrf_ok(&headers) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let Some(session) = manager.session() else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    match rt.store.totp_remove(id, session.account_id).await {
        Ok(true) => {
            // The ways up changed: `verify_totp` leaves every session of the
            // account the moment its last confirmed app goes.
            watch::sessions_changed(&rt.live, session.account_id);
            tracing::info!(
                account_id = session.account_id,
                app_id = id,
                "Authenticator app removed"
            );
            json_ok(json!({ "ok": true }))
        }
        Ok(false) => err(StatusCode::NOT_FOUND, "no such authenticator app"),
        Err(error) => load_error(error),
    }
}

/// How an authenticator-app refusal is answered.
///
/// A key that cannot seal anything, or a store that could not be read, is a
/// `503`: neither is something the person can act on. Everything else is the
/// caller's to decide, because "no such app" and "that code is not right" are
/// different answers to a log and the same shrug to a person.
fn authenticator_problem(
    error: totp::AuthenticatorError,
    refused: StatusCode,
    refused_message: &str,
) -> Response {
    match error {
        totp::AuthenticatorError::NoKey | totp::AuthenticatorError::Unavailable => {
            err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable")
        }
        _ => err(refused, refused_message),
    }
}

/// `POST /api/account/passkey/step-up/begin` — start an assertion that lifts
/// this session back to `Certain`, or that finishes signing in a `Basic` one
/// (CSRF-protected).
///
/// The passkey twin of `confirm-password`, including its guard: it is only
/// served where a step-up is *expected*, so a client cannot spend challenges at
/// will, and it deliberately does not require `Certain` — it is the way there.
/// From a `Basic` session the same guard holds (a step-up *is* expected), and the
/// ceremony is the way to finish signing in rather than to come back up.
async fn passkey_stepup_begin(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(manager): Extension<AuthManager>,
    headers: HeaderMap,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) || !csrf_ok(&headers) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    if manager.session().is_none() {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    }
    let now = unix_secs();
    let Some(raw) = session::cookie(&headers, SESSION_COOKIE) else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let Some((row, _)) = rt.sessions.live(&raw, now).await.ok().flatten() else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    if !manager.step_up_expected(row.expires_at).await {
        return err(StatusCode::CONFLICT, "this sign-in is already confirmed");
    }
    // Discoverable, not named: the ceremony is the same one an anonymous sign-in
    // uses, and it is the only shape some password managers answer at all — they
    // stay silent when a request names a credential. The account it resolves to
    // is checked below, against this very session.
    match passkey::begin_discover(&rt, now) {
        Ok(started) => passkey_started(started),
        Err(error) => passkey_problem(error, StatusCode::BAD_REQUEST, error.message()),
    }
}

/// `POST /api/account/passkey/step-up/finish` — accept the assertion.
///
/// Two jobs, one ceremony. On a session that has already passed its second
/// factor it is a step-up: the assertion lifts the level back to `Certain` in
/// place. On a `Basic` one it is the *sign-in* — the assertion is a way in, and
/// the console offers it beside the codes — so the inactivity clock is advanced
/// the way the anonymous ceremony advances it.
async fn passkey_stepup_finish(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(manager): Extension<AuthManager>,
    headers: HeaderMap,
    Json(req): Json<PasskeyAssertionRequest>,
) -> Response {
    if !origin_ok(&headers, &rt.base_url) || !csrf_ok(&headers) {
        return err(StatusCode::FORBIDDEN, "request refused");
    }
    let Some(session) = manager.session() else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let now = unix_secs();
    let Some(raw) = session::cookie(&headers, SESSION_COOKIE) else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let Some((row, _)) = rt.sessions.live(&raw, now).await.ok().flatten() else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    if !manager.step_up_expected(row.expires_at).await {
        return err(StatusCode::CONFLICT, "this sign-in is already confirmed");
    }
    match passkey::finish_step_up(&rt, &req.handle, &req.credential, now).await {
        // The assertion has to be this session's own account's, or a ceremony
        // started elsewhere could lift this one.
        Ok(asserted) if asserted.account_id == session.account_id => {
            // An assertion from a session that had *not* passed its second factor
            // is a sign-in, not a step-up: the person proved a credential that is
            // a way in, so the inactivity clock has to hear about it exactly as it
            // does for the anonymous ceremony (WVR-166).
            let signing_in = manager.level().await < AuthLevel::Strong;
            if manager
                .passkey_asserted(session, asserted.user_verified)
                .await
                .is_err()
                || (signing_in
                    && rt
                        .store
                        .account_record_login(session.account_id, now)
                        .await
                        .is_err())
            {
                return err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable");
            }
            if signing_in {
                tracing::info!(account_id = session.account_id, "Signed in with a passkey");
            } else {
                tracing::info!(
                    account_id = session.account_id,
                    "Passkey confirmed for a step-up"
                );
            }
            json_ok(json!({ "ok": true }))
        }
        Ok(_) => {
            let _ = manager
                .passkey_failed(Some(session.account_id), Some(session.session_id), "")
                .await;
            err(
                StatusCode::BAD_REQUEST,
                passkey::PasskeyError::Refused.message(),
            )
        }
        Err(error) => {
            let _ = manager
                .passkey_failed(Some(session.account_id), Some(session.session_id), "")
                .await;
            passkey_problem(error, StatusCode::BAD_REQUEST, error.message())
        }
    }
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
            watch::sessions_changed(&rt.live, account.id);
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

/// Composes and sends the sign-in second-factor code.
///
/// `code` is the plaintext code; it is never logged here. A failure is returned
/// so the caller can fail the sign-in closed rather than leaving a page that can
/// never be satisfied.
async fn send_signin_code(
    rt: &AccountRuntime,
    name: &str,
    email: &str,
    code: &str,
) -> Result<(), String> {
    let Some(mailer) = &rt.mailer else {
        return Err("email is not configured".into());
    };
    let to = Mailbox::parse(email, Some(name.to_string())).map_err(|e| e.to_string())?;
    let template = SignInCode {
        code: code.to_string(),
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
/// The field a refused `confirm_password` step-up names.
const FIELD_PASSWORD: &str = "password";
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

/// [`json_ok`] for a body that must never be cached: a secret travels in it.
fn json_no_store(value: Value) -> Response {
    let mut response = json_ok(value);
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(CACHE_NO_STORE),
    );
    response
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
pub(crate) fn human_timestamp(secs: i64) -> String {
    let zoned = jiff::Timestamp::from_second(secs)
        .map(|ts| ts.to_zoned(jiff::tz::TimeZone::system()))
        .unwrap_or_else(|_| jiff::Zoned::now());
    format!(
        "{} {}",
        zoned.strftime("%Y-%m-%d %H:%M"),
        zoned.strftime("%Z")
    )
}
