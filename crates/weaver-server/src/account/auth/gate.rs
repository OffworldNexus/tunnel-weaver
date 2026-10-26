//! The gate: every request declares the level it needs, the middleware asks the
//! [`AuthManager`] whether the session holds it and, when short, refuses.
//!
//! Rules mirror the reference's gate: **deny by default**, and the views needed
//! to *reach* the second factor are exempted by an exact (method, path) list
//! rather than by a prefix — a prefix would let a future route inherit an
//! exemption by accident.
//!
//! The reference *redirects* to the first step; an API cannot 302, so here the
//! refusal (`401` with no session, `403` with one too weak) carries two headers
//! and the SvelteKit side decides what to do with them:
//!
//! - `x-weaver-required-level`: the level the route needs (`basic`, `strong`);
//! - `x-weaver-upgrade-paths`: a JSON array of options, each an ordered array
//!   of `{"step", "reaches"}` — the step to take and the level it would leave
//!   the session at, preferred first — e.g.
//!   `[[{"step":"verify_email_otp","reaches":"strong"}]]`.
//!
//! Only refusals carry them: the console knows statically which level each of
//! its actions needs, and learns the ways up from the `me` stream.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::account::AccountRuntime;
use crate::account::session::{self, SESSION_COOKIE};
use crate::wall_clock::unix_secs;

use super::{AuthLevel, AuthManager, ClientAddr, SessionContext, WireStep};

/// The longest `User-Agent` recorded on an `auth_event` row.
const USER_AGENT_MAX_LEN: usize = 2000;

/// The refusal header naming the level the route needs.
pub const REQUIRED_LEVEL_HEADER: &str = "x-weaver-required-level";

/// The refusal header listing the options that would reach it (JSON).
pub const UPGRADE_PATHS_HEADER: &str = "x-weaver-upgrade-paths";

/// The deny-by-default level gate over the account API.
///
/// A request with no session to a route that needs one is a `401` (so the SPA's
/// "session expired" handling keeps working); a session that is merely too weak
/// is a `403`. Both name the required level and the ways up in headers.
pub async fn gate(State(rt): State<Arc<AccountRuntime>>, mut req: Request, next: Next) -> Response {
    let now = unix_secs();
    let live = match session::cookie(req.headers(), SESSION_COOKIE) {
        Some(raw) => rt.sessions.live(&raw, now).await.ok().flatten(),
        None => None,
    };
    let session = live.as_ref().map(|(row, account)| SessionContext {
        session_id: row.id,
        account_id: account.id,
    });
    let ip_address = req
        .extensions()
        .get::<ClientAddr>()
        .map(|addr| addr.0.ip().to_string())
        .unwrap_or_default();
    let user_agent: String = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .chars()
        .take(USER_AGENT_MAX_LEN)
        .collect();

    let manager = AuthManager::new(
        rt.store.clone(),
        rt.live.clone(),
        session,
        rt.config.session_ttl_secs as i64,
        rt.config.confirm_window_secs as i64,
        now,
        ip_address,
        user_agent,
    );
    req.extensions_mut().insert(manager.clone());

    let required = required_level(req.method(), req.uri().path());
    if required == AuthLevel::None {
        return next.run(req).await;
    }
    let (status, message) = if session.is_none() {
        (StatusCode::UNAUTHORIZED, "not signed in")
    } else if manager.satisfies(required).await {
        return next.run(req).await;
    } else {
        (StatusCode::FORBIDDEN, "second factor required")
    };
    let options = manager.upgrade_paths(required).await;
    refusal(status, message, required, &options)
}

/// A level refusal: the status and `{error}` body every refusal has, plus the
/// two headers that tell the client what would have been enough and how to
/// get there.
fn refusal(
    status: StatusCode,
    message: &str,
    required: AuthLevel,
    options: &[Vec<WireStep>],
) -> Response {
    let mut response = (status, Json(json!({ "error": message }))).into_response();
    let headers = response.headers_mut();
    headers.insert(
        REQUIRED_LEVEL_HEADER,
        HeaderValue::from_static(required.as_str()),
    );
    let options = serde_json::to_string(options).unwrap_or_else(|_| "[]".to_string());
    if let Ok(value) = HeaderValue::from_str(&options) {
        headers.insert(UPGRADE_PATHS_HEADER, value);
    }
    response
}

/// The level a route requires: `Strong` unless the exact (method, path) is on
/// the public front door, on the list of routes needed to climb, or asks for a
/// step-up.
fn required_level(method: &Method, path: &str) -> AuthLevel {
    if !path.starts_with("/api/account/") {
        return AuthLevel::None;
    }
    if is_public(method, path) {
        return AuthLevel::None;
    }
    if is_basic(method, path) {
        return AuthLevel::Basic;
    }
    if is_certain(method, path) {
        return AuthLevel::Certain;
    }
    AuthLevel::Strong
}

/// The front door: everything reachable before any factor is proven, including
/// the two ways a sign-in starts — the password step (which mints a `Basic`
/// session) and the passkey ceremony (which mints a `Strong` one outright).
fn is_public(method: &Method, path: &str) -> bool {
    match path {
        // `me` answers anyone: an anonymous visitor is told `none` on the stream
        // itself, which an `EventSource` can read and a `401` it could not.
        "/api/account/altcha/challenge" | "/api/account/config" | "/api/account/me" => {
            *method == Method::GET
        }
        "/api/account/signup"
        | "/api/account/resend"
        | "/api/account/verify"
        | "/api/account/complete"
        | "/api/account/reset/request"
        | "/api/account/reset/check"
        | "/api/account/reset/complete"
        | "/api/account/login"
        // The anonymous passkey ceremony (WVR-163): `begin` issues the challenge,
        // `finish` accepts the assertion and opens the session. Named in the
        // singular to keep them visibly apart from the authenticated
        // `/api/account/passkeys` routes below, which manage credentials.
        | "/api/account/passkey/begin"
        | "/api/account/passkey/finish" => *method == Method::POST,
        _ => false,
    }
}

/// The minimum to climb from `Basic` to `Strong`, plus leaving: verify and
/// re-send the code, and sign out.
fn is_basic(method: &Method, path: &str) -> bool {
    match path {
        "/api/account/login/verify" | "/api/account/login/resend" | "/api/account/logout" => {
            *method == Method::POST
        }
        _ => false,
    }
}

/// The routes that ask for `Certain` — the password proven moments ago, not
/// merely a second factor passed at some point in the session's life.
///
/// Only actions that lose something irreversibly belong here: an unattended
/// unlocked browser must not be able to delete the account in one click. The
/// console answers the refusal with the `confirm_password` step, and the same
/// gate refuses again if the proof has aged out by the time it is submitted.
/// Registering a passkey joins them (WVR-163): it plants a credential that
/// signs in on its own, which is at least as lasting as a deletion, and the
/// nominal way to arrive here is a sign-in that already holds `Certain`.
fn is_certain(method: &Method, path: &str) -> bool {
    matches!(
        (method, path),
        (&Method::POST, "/api/account/delete")
            | (&Method::POST, "/api/account/passkeys/begin")
            | (&Method::POST, "/api/account/passkeys/finish")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_routes_need_nothing() {
        assert_eq!(
            required_level(&Method::POST, "/api/account/login"),
            AuthLevel::None
        );
        assert_eq!(
            required_level(&Method::GET, "/api/account/config"),
            AuthLevel::None
        );
        // The session stream tells an anonymous visitor so itself.
        assert_eq!(
            required_level(&Method::GET, "/api/account/me"),
            AuthLevel::None
        );
        // The anonymous passkey ceremony is the other way a sign-in starts.
        assert_eq!(
            required_level(&Method::POST, "/api/account/passkey/begin"),
            AuthLevel::None
        );
        assert_eq!(
            required_level(&Method::POST, "/api/account/passkey/finish"),
            AuthLevel::None
        );
    }

    #[test]
    fn climb_routes_need_basic() {
        assert_eq!(
            required_level(&Method::POST, "/api/account/login/verify"),
            AuthLevel::Basic
        );
    }

    #[test]
    fn only_the_irreversible_actions_ask_for_certain() {
        assert_eq!(
            required_level(&Method::POST, "/api/account/delete"),
            AuthLevel::Certain
        );
        // Reading the route does not, and neither does its neighbour.
        assert_eq!(
            required_level(&Method::GET, "/api/account/delete"),
            AuthLevel::Strong
        );
        assert_eq!(
            required_level(&Method::POST, "/api/account/delete/all"),
            AuthLevel::Strong
        );
        // The step that reaches `Certain` must not itself require it.
        assert_eq!(
            required_level(&Method::POST, "/api/account/confirm-password"),
            AuthLevel::Strong
        );
    }

    #[test]
    fn registering_a_passkey_asks_for_certain_and_managing_it_does_not() {
        // Planting a credential is as lasting as a deletion.
        assert_eq!(
            required_level(&Method::POST, "/api/account/passkeys/begin"),
            AuthLevel::Certain
        );
        assert_eq!(
            required_level(&Method::POST, "/api/account/passkeys/finish"),
            AuthLevel::Certain
        );
        // Listing, removing and asserting are ordinary authenticated work.
        for (method, path) in [
            (Method::GET, "/api/account/passkeys"),
            (Method::POST, "/api/account/passkeys/7/remove"),
            (Method::POST, "/api/account/passkey/step-up/begin"),
            (Method::POST, "/api/account/passkey/step-up/finish"),
        ] {
            assert_eq!(required_level(&method, path), AuthLevel::Strong, "{path}");
        }
    }

    #[test]
    fn everything_else_on_the_api_is_strong() {
        for (method, path) in [
            (Method::GET, "/api/account/machines"),
            (Method::GET, "/api/account/overview"),
            (Method::GET, "/api/account/avatar"),
            (Method::POST, "/api/account/password"),
            (Method::POST, "/api/account/confirm-password"),
            (Method::POST, "/api/account/pair/accept"),
            (Method::POST, "/api/account/some/future/route"),
        ] {
            assert_eq!(required_level(&method, path), AuthLevel::Strong, "{path}");
        }
    }

    #[test]
    fn the_exemption_is_exact_not_a_prefix() {
        // A lookalike of a public path stays Strong.
        assert_eq!(
            required_level(&Method::POST, "/api/account/login/../delete"),
            AuthLevel::Strong
        );
        assert_eq!(
            required_level(&Method::GET, "/api/account/config/leak"),
            AuthLevel::Strong
        );
        // Including a lookalike of the passkey ceremony: `passkeys/…` manages
        // credentials and is emphatically not the public front door.
        assert_eq!(
            required_level(&Method::POST, "/api/account/passkey/beginish"),
            AuthLevel::Strong
        );
        assert_eq!(
            required_level(&Method::POST, "/api/account/passkeys/begin"),
            AuthLevel::Certain
        );
    }

    #[test]
    fn non_api_paths_are_untouched() {
        assert_eq!(required_level(&Method::GET, "/app"), AuthLevel::None);
        assert_eq!(
            required_level(&Method::GET, "/assets/x.js"),
            AuthLevel::None
        );
    }

    #[test]
    fn a_public_route_with_the_wrong_method_stays_strong() {
        assert_eq!(
            required_level(&Method::GET, "/api/account/login"),
            AuthLevel::Strong
        );
        // The ceremony is a POST: a GET of it is nobody's business.
        assert_eq!(
            required_level(&Method::GET, "/api/account/passkey/begin"),
            AuthLevel::Strong
        );
        assert_eq!(
            required_level(&Method::GET, "/api/account/passkey/finish"),
            AuthLevel::Strong
        );
    }
}
