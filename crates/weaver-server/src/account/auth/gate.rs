//! The gate: every request declares the level it needs, the middleware asks the
//! [`AuthManager`] whether the session holds it and, when short, refuses.
//!
//! Rules mirror the reference's gate: **deny by default**, and the views needed
//! to *reach* the second factor are exempted by an exact (method, path) list
//! rather than by a prefix — a prefix would let a future route inherit an
//! exemption by accident.
//!
//! The reference *redirects* to the first step; an API cannot 302, so here the
//! gate returns a `403` naming the required level and the step, and the
//! SvelteKit side performs the navigation.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::account::AccountRuntime;
use crate::account::session::{self, SESSION_COOKIE};
use crate::wall_clock::unix_secs;

use super::{AuthLevel, AuthManager, ClientAddr, SessionContext};

/// The longest `User-Agent` recorded on an `auth_event` row.
const USER_AGENT_MAX_LEN: usize = 2000;

/// The deny-by-default level gate over the account API.
///
/// A request with no session to a route that needs one is a `401` (so the SPA's
/// "session expired" handling keeps working); a session that is merely too weak
/// is a `403` naming the step that would lift it.
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
        session,
        rt.config.session_ttl_secs as i64,
        now,
        ip_address,
        user_agent,
    );
    req.extensions_mut().insert(manager.clone());

    let required = required_level(req.method(), req.uri().path());
    if required == AuthLevel::None {
        return next.run(req).await;
    }
    if session.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "not signed in" })),
        )
            .into_response();
    }
    if manager.satisfies(required).await {
        return next.run(req).await;
    }
    let step = manager
        .best_step(required)
        .await
        .map(|step| step.as_str())
        .unwrap_or("login");
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "second factor required",
            "required": required.as_str(),
            "step": step,
        })),
    )
        .into_response()
}

/// The level a route requires: `Strong` unless the exact (method, path) is on
/// the public front door or the list of routes needed to climb.
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
    AuthLevel::Strong
}

/// The front door: everything reachable before any factor is proven, including
/// the password step of sign-in (which mints a `Basic` session).
fn is_public(method: &Method, path: &str) -> bool {
    match path {
        "/api/account/altcha/challenge" | "/api/account/config" => *method == Method::GET,
        "/api/account/signup"
        | "/api/account/resend"
        | "/api/account/verify"
        | "/api/account/complete"
        | "/api/account/reset/request"
        | "/api/account/reset/check"
        | "/api/account/reset/complete"
        | "/api/account/login" => *method == Method::POST,
        _ => false,
    }
}

/// The minimum to climb from `Basic` to `Strong`, plus leaving: verify and
/// re-send the code, read the level, and sign out.
fn is_basic(method: &Method, path: &str) -> bool {
    match path {
        "/api/account/me" => *method == Method::GET,
        "/api/account/login/verify" | "/api/account/login/resend" | "/api/account/logout" => {
            *method == Method::POST
        }
        _ => false,
    }
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
    }

    #[test]
    fn climb_routes_need_basic() {
        assert_eq!(
            required_level(&Method::GET, "/api/account/me"),
            AuthLevel::Basic
        );
        assert_eq!(
            required_level(&Method::POST, "/api/account/login/verify"),
            AuthLevel::Basic
        );
    }

    #[test]
    fn everything_else_on_the_api_is_strong() {
        for (method, path) in [
            (Method::GET, "/api/account/machines"),
            (Method::GET, "/api/account/overview"),
            (Method::GET, "/api/account/avatar"),
            (Method::POST, "/api/account/password"),
            (Method::POST, "/api/account/delete"),
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
    }
}
