//! External identity providers: signing in with an identity held elsewhere
//! (WVR-169).
//!
//! This slice ships Microsoft (Entra ID) as a *direct* provider: the relay runs
//! the OIDC authorization-code + PKCE flow itself, so it reads Entra's own
//! assertion of how the person authenticated (`amr`) and turns it into a session
//! level.
//!
//! The shape of a sign-in:
//!
//! 1. [`microsoft_begin`] stores a single-use pending flow (the `state`, the
//!    nonce and the PKCE verifier) and redirects to the provider.
//! 2. [`microsoft_callback`] redeems it, exchanges the code, verifies the ID
//!    token, resolves the identity to an account (creating it — an implicit
//!    sign-up — when it is new), opens a session and records the proofs the
//!    provider's assertion justifies. An address the provider did not vouch for
//!    is settled by the emailed code.
//! 3. [`microsoft_step_up`] re-runs the redirect with `prompt=login` on an
//!    existing session; its callback records the presence proof that lifts an
//!    SSO session to `Certain`.
//!
//! The provider is configured by the operator (`weaver-server sso microsoft
//! set`) and read at boot into one [`Microsoft`], which the runtime holds only
//! when the provider is enabled.

pub mod oidc;
mod refresh;

use std::sync::Arc;

use axum::Extension;
use axum::extract::{Query, State};
use axum::response::Response;
use http::StatusCode;
use serde::Deserialize;

use crate::account::AccountRuntime;
use crate::account::auth::{AuthManager, SessionContext};
use crate::account::router::{err, redirect};
use crate::account::second_factor::Purpose;
use crate::account::signin::OpenedSession;
use crate::config::AccountConfig;
use crate::seal::{SealError, SealKey};
use crate::store::account::{NewExternalIdentity, NewSsoFlow};
use crate::store::entity::sso_flow;
use crate::store::{Store, StoreError};
use crate::wall_clock::unix_secs;

use self::oidc::{EntraClient, IdToken, TokenError, VerifyError};

pub use self::refresh::SsoRefreshTask;

/// The provider name used everywhere a row stores it.
const PROVIDER: &str = "microsoft";

/// The associated data binding a sealed value to this provider, so a secret
/// copied into another provider's slot fails to open.
const SEAL_AAD: &[u8] = b"weaver-sso:microsoft";

/// How long a pending flow may sit before it is refused. Ten minutes is far
/// longer than a sign-in takes and short enough that a leaked `state` is stale.
pub const FLOW_TTL_SECS: i64 = 600;

/// The path the provider redirects back to, under the account base URL.
const CALLBACK_PATH: &str = "/api/account/sso/microsoft/callback";

/// Where a finished sign-in lands. `/app` is correct at both levels: the app
/// guard sends a `Basic` session to the verify step, and a `Strong` one onwards.
const LANDING: &str = "/app";

/// Which half of the protocol a pending flow is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowKind {
    /// A sign-in; its callback mints a session.
    SignIn,
    /// A step-up; its callback records presence on an existing session.
    StepUp,
}

impl FlowKind {
    const fn as_str(self) -> &'static str {
        match self {
            FlowKind::SignIn => "signin",
            FlowKind::StepUp => "stepup",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        [FlowKind::SignIn, FlowKind::StepUp]
            .into_iter()
            .find(|kind| kind.as_str() == value)
    }
}

/// Why a provider request did not complete.
enum Failure {
    /// Refused: `reason` goes back to the sign-in page, `detail` to the trail.
    Refused {
        reason: &'static str,
        detail: &'static str,
        account_id: Option<i32>,
    },
    /// The provider or the store could not be reached.
    Unavailable,
}

fn refused(reason: &'static str, detail: &'static str) -> Failure {
    Failure::Refused {
        reason,
        detail,
        account_id: None,
    }
}

impl From<StoreError> for Failure {
    fn from(_: StoreError) -> Self {
        Failure::Unavailable
    }
}

/// The enabled Microsoft provider: its client, and what it seals with.
pub struct Microsoft {
    client: EntraClient,
    sso_key: SealKey,
    redirect_uri: String,
}

impl Microsoft {
    /// The provider the config enables, if any.
    ///
    /// A preset whose sealed client secret cannot be opened (a changed
    /// `sso_key`) is logged and left out, rather than offered half-configured.
    pub fn from_config(
        config: &AccountConfig,
        base_url: &str,
    ) -> Result<Option<Arc<Self>>, String> {
        let Some(preset) = config.microsoft.as_ref().filter(|preset| preset.enabled) else {
            return Ok(None);
        };
        let client_secret = match config.sso_key.open_text(SEAL_AAD, &preset.client_secret) {
            Ok(secret) => secret,
            Err(error) => {
                tracing::warn!(
                    reason = error.message(),
                    "Microsoft sign-in disabled: its client secret cannot be read"
                );
                return Ok(None);
            }
        };
        Ok(Some(Arc::new(Self {
            client: EntraClient::new(&preset.authority, &preset.client_id, &client_secret)?,
            sso_key: config.sso_key.clone(),
            redirect_uri: format!("{}{CALLBACK_PATH}", base_url.trim_end_matches('/')),
        })))
    }

    /// Seals a client secret for the config, as `sso microsoft set` stores it.
    pub fn seal_client_secret(key: &SealKey, secret: &str) -> Result<String, SealError> {
        key.seal(SEAL_AAD, secret.as_bytes())
    }

    fn seal(&self, value: &str) -> Result<String, SealError> {
        self.sso_key.seal(SEAL_AAD, value.as_bytes())
    }

    fn open(&self, sealed: &str) -> Result<String, SealError> {
        self.sso_key.open_text(SEAL_AAD, sealed)
    }

    /// Stores a pending flow and returns the provider URL to send the browser to.
    async fn start(
        &self,
        store: &Store,
        kind: FlowKind,
        session: Option<SessionContext>,
        return_path: &str,
        max_age: Option<i64>,
    ) -> Result<String, Failure> {
        let now = unix_secs();
        let handle = crate::random_hex(32);
        let nonce = crate::random_hex(32);
        let verifier = crate::random_hex(32);
        store
            .sso_flow_create(NewSsoFlow {
                handle: &handle,
                kind: kind.as_str(),
                provider: PROVIDER,
                nonce: &nonce,
                code_verifier: &verifier,
                return_path,
                account_id: session.map(|session| session.account_id),
                session_id: session.map(|session| session.session_id),
                created_at: now,
                expires_at: now + FLOW_TTL_SECS,
            })
            .await?;
        // `login` makes the provider ask the person again rather than silently
        // reuse its own session — the whole point of a step-up.
        let prompt = match kind {
            FlowKind::SignIn => "select_account",
            FlowKind::StepUp => "login",
        };
        self.client
            .authorize_url(
                &self.redirect_uri,
                &handle,
                &nonce,
                &verifier,
                prompt,
                max_age,
            )
            .await
            .map_err(|error| {
                tracing::warn!(%error, "SSO discovery failed");
                Failure::Unavailable
            })
    }

    /// Redeems a callback: the pending flow, the verified ID token, and the
    /// refresh token when the provider issued one.
    async fn redeem(
        &self,
        store: &Store,
        query: &CallbackQuery,
        now: i64,
    ) -> Result<(sso_flow::Model, FlowKind, IdToken, String, Option<String>), Failure> {
        if !query.error.is_empty() {
            return Err(refused("denied", "provider refused"));
        }
        let flow = store
            .sso_flow_take(&query.state, now)
            .await?
            .ok_or(refused("expired", "unknown or expired state"))?;
        let kind = FlowKind::parse(&flow.kind).ok_or(refused("state", "unknown flow kind"))?;
        let with_account = |reason, detail| Failure::Refused {
            reason,
            detail,
            account_id: flow.account_id,
        };
        if query.code.is_empty() {
            return Err(with_account("code", "no code"));
        }
        let tokens = match self
            .client
            .exchange_code(&query.code, &self.redirect_uri, &flow.code_verifier)
            .await
        {
            Ok(tokens) => tokens,
            Err(TokenError::Rejected) => return Err(with_account("rejected", "code refused")),
            Err(TokenError::Unavailable(error)) => {
                tracing::warn!(%error, "SSO token exchange failed");
                return Err(Failure::Unavailable);
            }
        };
        let id_token = tokens
            .id_token
            .ok_or_else(|| with_account("token", "no id token"))?;
        let claims = match self.client.verify(&id_token, &flow.nonce).await {
            Ok(claims) => claims,
            Err(VerifyError::Invalid(detail)) => return Err(with_account("token", detail)),
            Err(VerifyError::Unavailable(error)) => {
                tracing::warn!(%error, "SSO signing keys unavailable");
                return Err(Failure::Unavailable);
            }
        };
        Ok((flow, kind, claims, id_token, tokens.refresh_token))
    }
}

/// Query of the provider's callback. Every field is absent on some answer, and
/// empty means absent.
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    code: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    error: String,
}

/// Query of the step-up start.
#[derive(Debug, Deserialize)]
pub struct StepUpQuery {
    #[serde(default)]
    return_path: String,
}

/// `GET /api/account/sso/microsoft/begin` — start a sign-in (public).
pub async fn microsoft_begin(State(rt): State<Arc<AccountRuntime>>) -> Response {
    let Some(provider) = rt.microsoft.as_deref() else {
        return err(StatusCode::NOT_FOUND, "not configured");
    };
    match provider
        .start(&rt.store, FlowKind::SignIn, None, "", None)
        .await
    {
        Ok(url) => redirect(&url),
        Err(_) => unavailable(),
    }
}

/// `GET /api/account/sso/microsoft/step-up` — re-authenticate at the provider
/// (session; the gate keeps it `Basic`-reachable).
pub async fn microsoft_step_up(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(manager): Extension<AuthManager>,
    Query(query): Query<StepUpQuery>,
) -> Response {
    let Some(session) = manager.session() else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let Some(provider) = rt.microsoft.as_deref() else {
        return err(StatusCode::NOT_FOUND, "not configured");
    };
    // `max_age` is what makes Entra report `auth_time`, which the callback
    // checks to know the re-authentication really just happened.
    let max_age = rt.config.confirm_window_secs as i64;
    match provider
        .start(
            &rt.store,
            FlowKind::StepUp,
            Some(session),
            &sanitize_return_path(&query.return_path),
            Some(max_age),
        )
        .await
    {
        Ok(url) => redirect(&url),
        Err(_) => unavailable(),
    }
}

/// `GET /api/account/sso/microsoft/callback` — finish a sign-in or a step-up
/// (public).
pub async fn microsoft_callback(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(manager): Extension<AuthManager>,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let Some(provider) = rt.microsoft.as_deref() else {
        return signin_error("disabled");
    };
    let now = unix_secs();
    let outcome = match provider.redeem(&rt.store, &query, now).await {
        Ok((flow, FlowKind::StepUp, claims, _, _)) => {
            finish_step_up(&rt, &manager, &flow, &claims, now).await
        }
        Ok((_, FlowKind::SignIn, claims, id_token, refresh_token)) => {
            finish_sign_in(
                &rt,
                provider,
                &manager,
                &claims,
                &id_token,
                refresh_token,
                now,
            )
            .await
        }
        Err(failure) => Err(failure),
    };
    match outcome {
        Ok(response) => response,
        Err(Failure::Refused {
            reason,
            detail,
            account_id,
        }) => {
            let _ = manager.sso_failed(account_id, detail).await;
            signin_error(reason)
        }
        Err(Failure::Unavailable) => unavailable(),
    }
}

/// The sign-in half of the callback: resolve the identity to an account, open a
/// session, record the proofs, and offer the emailed code.
async fn finish_sign_in(
    rt: &AccountRuntime,
    provider: &Microsoft,
    manager: &AuthManager,
    claims: &IdToken,
    id_token: &str,
    refresh_token: Option<String>,
    now: i64,
) -> Result<Response, Failure> {
    // The address is what an account is created from, so a token without one
    // cannot sign anyone in.
    let Some((address, verified)) = claims.address() else {
        tracing::warn!(
            claims = ?oidc::claim_names(id_token),
            "SSO token carried no usable email claim; refusing the sign-in"
        );
        return Err(refused("email", "no email in the token"));
    };
    let sealed_refresh = refresh_token
        .and_then(|token| match provider.seal(&token) {
            Ok(sealed) => Some(sealed),
            Err(error) => {
                tracing::warn!(
                    reason = error.message(),
                    "provider refresh token not stored"
                );
                None
            }
        })
        .unwrap_or_default();

    let resolved = match rt
        .store
        .external_identity_resolve_or_create(NewExternalIdentity {
            provider: PROVIDER,
            tenant_id: &claims.tid,
            subject: &claims.oid,
            name: claims.display_name(),
            email: address,
            lookup_key: &address.to_lowercase(),
            email_verified_at: verified.then_some(now),
            sealed_refresh: &sealed_refresh,
            now,
        })
        .await
    {
        Ok(resolved) => resolved,
        // The address belongs to another account and the provider does not
        // vouch for it: refusing is the takeover-safe answer.
        Err(StoreError::Conflict(_)) => return Err(refused("email", "address already in use")),
        Err(error) => {
            tracing::warn!(%error, "could not resolve an external identity");
            return Err(Failure::Unavailable);
        }
    };
    let account = resolved.account;
    let identity = rt
        .store
        .email_identity_for_account(account.id)
        .await?
        .ok_or(Failure::Unavailable)?;
    // An address nobody has proven yet must be settled by the emailed code
    // before the account counts as strongly signed in, whatever the provider
    // asserted: the code is issued for that purpose, and the provider's MFA is
    // not taken until it is.
    let settle = identity.verified_at.is_none();
    let mfa = claims.asserted_mfa() && !settle;

    let opened = OpenedSession::open(rt, account.id, now)
        .await
        .ok_or(Failure::Unavailable)?;
    if manager.sso_accepted(opened.context).await.is_err()
        || (mfa && manager.sso_mfa_asserted(opened.context).await.is_err())
        || opened.record_login().await.is_err()
    {
        opened.close().await;
        return Err(Failure::Unavailable);
    }
    tracing::info!(
        account_id = account.id,
        created = resolved.created,
        mfa,
        "Signed in with Microsoft"
    );

    if !mfa {
        let purpose = if settle {
            Purpose::VerifyAddress
        } else {
            Purpose::SignIn
        };
        if let Err(error) = opened
            .offer_emailed_code(manager, purpose, &account.name, &identity.email)
            .await
        {
            tracing::warn!(account_id = account.id, %error, "sign-in code email was not sent");
        }
    }
    Ok(opened.finish(redirect(LANDING)))
}

/// The step-up half of the callback: check the identity is the one this account
/// signed in with, and that the provider really just re-authenticated it.
async fn finish_step_up(
    rt: &AccountRuntime,
    manager: &AuthManager,
    flow: &sso_flow::Model,
    claims: &IdToken,
    now: i64,
) -> Result<Response, Failure> {
    let (Some(account_id), Some(session_id)) = (flow.account_id, flow.session_id) else {
        return Err(refused("state", "step-up without a session"));
    };
    let with_account = |reason, detail| Failure::Refused {
        reason,
        detail,
        account_id: Some(account_id),
    };
    let linked = rt
        .store
        .external_identity_for_account(account_id)
        .await?
        .into_iter()
        .any(|identity| {
            identity.provider == PROVIDER
                && identity.tenant_id.eq_ignore_ascii_case(&claims.tid)
                && identity.subject == claims.oid
        });
    if !linked {
        return Err(with_account("identity", "step-up identity mismatch"));
    }
    let fresh = claims
        .auth_time
        .is_some_and(|auth_time| now - auth_time <= rt.config.confirm_window_secs as i64);
    if !fresh {
        return Err(with_account("stale", "step-up not fresh"));
    }
    manager
        .sso_presence(SessionContext {
            session_id,
            account_id,
        })
        .await?;
    Ok(redirect(&sanitize_return_path(&flow.return_path)))
}

/// A same-origin return path, or the default landing. Anything that could leave
/// the origin (a scheme, a host, a protocol-relative `//`) is discarded.
fn sanitize_return_path(candidate: &str) -> String {
    if candidate.starts_with('/') && !candidate.starts_with("//") && !candidate.contains('\\') {
        candidate.to_string()
    } else {
        LANDING.to_string()
    }
}

/// A redirect back to the sign-in page carrying a short reason.
fn signin_error(reason: &str) -> Response {
    redirect(&format!(
        "/sign-in?sso_error={}",
        oidc::percent_encode(reason)
    ))
}

fn unavailable() -> Response {
    err(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_paths_stay_on_the_origin() {
        assert_eq!(sanitize_return_path("/app/settings"), "/app/settings");
        assert_eq!(sanitize_return_path("//evil.example"), LANDING);
        assert_eq!(sanitize_return_path("https://evil.example"), LANDING);
        assert_eq!(sanitize_return_path("/\\evil.example"), LANDING);
        assert_eq!(sanitize_return_path(""), LANDING);
    }
}
