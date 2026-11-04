//! External identity providers: signing in with an identity held elsewhere
//! (WVR-169), through one shared pipeline (WVR-175).
//!
//! A provider adds *facts*, never a flow: its endpoints, how its issuer is
//! spelled, its extra authorize parameters and its claim mapping. The pipeline
//! below is the same for every provider and only ever sees an [`Assertion`]:
//!
//! 1. [`begin`] stores a single-use pending flow (the `state`, the nonce and
//!    the PKCE verifier) and redirects to the provider.
//! 2. [`callback`] redeems it, asks the provider for an [`Assertion`], resolves
//!    the identity to an account (creating it — an implicit sign-up — when it is
//!    new), opens a session and records the proofs the assertion justifies. An
//!    address the provider did not vouch for is settled by the emailed code.
//! 3. [`step_up`] re-runs the redirect with a forced re-authentication on an
//!    existing session; its callback records the presence proof that lifts an
//!    SSO session to `Certain`.
//!
//! Providers are configured by the operator (`weaver-server sso <provider> set`)
//! and built once at boot into [`SsoProviders`]. A preset whose sealed client
//! secret cannot be opened is logged and left out rather than offered
//! half-configured. Nothing in this file branches on a provider's id.

pub mod google;
pub mod microsoft;
pub mod oidc;
mod refresh;
pub mod testing;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Extension;
use axum::extract::{Path, Query, State};
use axum::response::Response;
use http::StatusCode;
use serde::Deserialize;

use crate::account::AccountRuntime;
use crate::account::auth::{AuthManager, SessionContext};
use crate::account::router::{err, redirect};
use crate::account::second_factor::Purpose;
use crate::account::signin::OpenedSession;
use crate::config::{AccountConfig, ProviderKind, ProviderPreset};
use crate::seal::{SealError, SealKey};
use crate::store::StoreError;
use crate::store::account::{NewExternalIdentity, NewSsoFlow};
use crate::store::entity::sso_flow;
use crate::wall_clock::unix_secs;

pub use self::refresh::SsoRefreshTask;

/// How long a pending flow may sit before it is refused. Ten minutes is far
/// longer than a sign-in takes and short enough that a leaked `state` is stale.
pub const FLOW_TTL_SECS: i64 = 600;

/// Where a finished sign-in lands. `/app` is correct at both levels: the app
/// guard sends a `Basic` session to the verify step, and a `Strong` one onwards.
const LANDING: &str = "/app";

/// The provider-neutral result of a completed sign-in: everything the pipeline
/// is allowed to know about what the provider asserted.
#[derive(Debug, Clone)]
pub struct Assertion {
    /// The provider that produced this assertion; the route segment and seal AAD.
    pub provider: &'static str,
    /// The provider's tenant identifier, empty when it has none.
    pub tenant: String,
    /// The provider's durable subject identifier.
    pub subject: String,
    /// The address to create or sign in the account with, and whether the
    /// provider vouched for it.
    pub address: Option<(String, bool)>,
    /// The display name for a new account; empty when the provider gave none.
    pub name: String,
    /// Whether the provider asserted a second factor for *this* sign-in. Anything
    /// in doubt is `false` — that is the whole B3 rule.
    pub mfa: bool,
    /// When the person authenticated at the provider, when it reports it.
    pub auth_time: Option<i64>,
    /// A refresh grant to keep, when the provider issued one.
    pub refresh_grant: Option<String>,
}

/// How a provider is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    /// The relay runs the authorization-code + PKCE flow itself.
    Redirect,
    /// A broker's SDK signs in and hands the relay a token to verify.
    Token,
}

/// Why the provider is being asked, which is also how insistently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prompt {
    /// An ordinary sign-in: let the provider reuse its own session.
    SignIn,
    /// A step-up: make the person authenticate again, within `max_age` seconds.
    StepUp { max_age: i64 },
}

/// Why a provider request did not complete. The split is the same for every
/// provider: a refusal goes back to the sign-in page and the trail, anything
/// else is a temporary outage.
#[derive(Debug)]
pub enum ProviderError {
    /// Refused: `reason` goes back to the sign-in page, `detail` to the trail.
    Refused {
        reason: &'static str,
        detail: &'static str,
    },
    /// The provider could not be reached, or answered nonsense.
    Unavailable,
}

impl ProviderError {
    /// A refusal with its two explanations.
    pub fn refused(reason: &'static str, detail: &'static str) -> Self {
        ProviderError::Refused { reason, detail }
    }
}

/// What a refresh attempt did.
#[derive(Debug)]
pub enum RefreshOutcome {
    /// The provider issued a new refresh grant.
    Rotated(String),
    /// The grant is dead. Fail closed: this never means the account is deleted.
    Rejected,
    /// The provider could not be reached; try again next tick.
    Unavailable(String),
    /// This provider has no refresh story (a broker token, say).
    Unsupported,
}

/// The pending half of a flow, as a provider sees it.
pub struct PendingFlow {
    /// The single-use `state` value the callback carries back.
    pub state: String,
    /// The nonce the ID token must echo.
    pub nonce: String,
    /// The PKCE verifier whose challenge was sent.
    pub code_verifier: String,
    /// Where the provider must send the browser back.
    pub redirect_uri: String,
}

/// One configured provider.
///
/// Every method but `id`/`label`/`entry` is optional in practice: a redirect
/// provider implements `authorize_url` and `redeem`, a broker implements
/// `verify_token`, and a provider with no refresh story takes the default.
#[async_trait::async_trait]
pub trait IdentityProvider: Send + Sync {
    /// The stable id: the route segment, the registry key, and the seal AAD.
    fn id(&self) -> &'static str;

    /// The button text the sign-in page shows.
    fn label(&self) -> &'static str;

    /// How the provider is reached.
    fn entry(&self) -> Entry;

    /// The authorization-request URL for `flow`.
    async fn authorize_url(
        &self,
        flow: &PendingFlow,
        prompt: Prompt,
    ) -> Result<String, ProviderError>;

    /// Redeems the provider's authorization code into an assertion.
    async fn redeem(&self, code: &str, flow: &PendingFlow) -> Result<Assertion, ProviderError>;

    /// Verifies a token a broker's SDK obtained (the `Token` entry).
    async fn verify_token(&self, _token: &str) -> Result<Assertion, ProviderError> {
        Err(ProviderError::Unavailable)
    }

    /// Refreshes a stored grant.
    async fn refresh(&self, _grant: &str) -> RefreshOutcome {
        RefreshOutcome::Unsupported
    }
}

/// The enabled providers, by id, with what seals their secrets.
///
/// Built once from [`AccountConfig`] and injected everywhere a provider is
/// needed: the routes, the refresh task and `/api/account/config`. Only enabled
/// presets with an openable secret are registered.
#[derive(Clone)]
pub struct SsoProviders {
    sso_key: SealKey,
    base_url: String,
    providers: BTreeMap<&'static str, Arc<dyn IdentityProvider>>,
}

impl SsoProviders {
    /// Builds the registry from the configured presets.
    ///
    /// A preset whose sealed secret cannot be opened (a rotated `sso_key`) is
    /// logged and skipped: it is better to not offer a provider than to offer
    /// one that fails every sign-in halfway through.
    pub fn from_config(config: &AccountConfig, base_url: &str) -> Result<Self, String> {
        let mut registry = Self {
            sso_key: config.sso_key.clone(),
            base_url: base_url.trim_end_matches('/').to_string(),
            providers: BTreeMap::new(),
        };
        for preset in config.sso.values().filter(|preset| preset.enabled) {
            let Some(provider) = build(config, preset)? else {
                continue;
            };
            registry.providers.insert(provider.id(), provider);
        }
        Ok(registry)
    }

    /// An empty registry, for tests and harnesses that inject providers.
    pub fn empty(sso_key: SealKey, base_url: &str) -> Self {
        Self {
            sso_key,
            base_url: base_url.trim_end_matches('/').to_string(),
            providers: BTreeMap::new(),
        }
    }

    /// Registers (or replaces) one provider.
    pub fn insert(&mut self, provider: Arc<dyn IdentityProvider>) {
        self.providers.insert(provider.id(), provider);
    }

    /// The provider with this id, when it is enabled.
    pub fn get(&self, id: &str) -> Option<Arc<dyn IdentityProvider>> {
        self.providers.get(id).cloned()
    }

    /// The enabled providers as `(id, label)`, in id order.
    pub fn describe(&self) -> Vec<(&'static str, &'static str)> {
        self.providers
            .values()
            .map(|provider| (provider.id(), provider.label()))
            .collect()
    }

    /// Whether any provider is enabled.
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    /// Where a provider's callback lives, built from the account base URL.
    pub fn redirect_uri(&self, provider: &str) -> String {
        format!("{}/api/account/sso/{provider}/callback", self.base_url)
    }

    /// Seals a provider's client secret for the config, as `sso <provider> set`
    /// stores it. The AAD binds the value to its provider, so a secret copied
    /// into another provider's slot fails to open.
    pub fn seal(key: &SealKey, provider: &str, value: &str) -> Result<String, SealError> {
        key.seal(&seal_aad(provider), value.as_bytes())
    }

    /// Seals a refresh grant; the pipeline's half of the same binding.
    pub fn seal_refresh(&self, provider: &str, value: &str) -> Result<String, SealError> {
        Self::seal(&self.sso_key, provider, value)
    }

    /// Opens a sealed value belonging to `provider`.
    pub fn open(&self, provider: &str, sealed: &str) -> Result<String, SealError> {
        self.sso_key.open_text(&seal_aad(provider), sealed)
    }
}

/// The associated data binding a sealed value to one provider.
fn seal_aad(provider: &str) -> Vec<u8> {
    format!("weaver-sso:{provider}").into_bytes()
}

/// Builds one configured provider.
///
/// This is the only place that knows which presets map to which implementation;
/// past it the pipeline sees the trait alone.
fn build(
    config: &AccountConfig,
    preset: &ProviderPreset,
) -> Result<Option<Arc<dyn IdentityProvider>>, String> {
    let id = preset.kind.id();
    let secret = if preset.kind.client_secret().is_empty() {
        String::new()
    } else {
        match config
            .sso_key
            .open_text(&seal_aad(id), preset.kind.client_secret())
        {
            Ok(secret) => secret,
            Err(error) => {
                tracing::warn!(
                    provider = id,
                    reason = error.message(),
                    "sign-in provider disabled: its client secret cannot be read"
                );
                return Ok(None);
            }
        }
    };
    let provider: Option<Arc<dyn IdentityProvider>> = match &preset.kind {
        ProviderKind::Microsoft {
            authority,
            client_id,
            ..
        } => microsoft::Microsoft::from_preset(authority, client_id, &secret)?
            .map(|provider| provider as Arc<dyn IdentityProvider>),
        ProviderKind::Google { client_id, .. } => google::Google::from_preset(client_id, &secret)?
            .map(|provider| provider as Arc<dyn IdentityProvider>),
    };
    Ok(provider)
}

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

/// Why a pipeline step did not complete.
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

/// Stores a pending flow and returns the provider URL to send the browser to.
async fn start(
    rt: &AccountRuntime,
    provider: &Arc<dyn IdentityProvider>,
    kind: FlowKind,
    session: Option<SessionContext>,
    return_path: &str,
    prompt: Prompt,
) -> Result<String, Failure> {
    let now = unix_secs();
    let state = crate::random_hex(32);
    let nonce = crate::random_hex(32);
    let verifier = crate::random_hex(32);
    store_flow(
        rt,
        provider.id(),
        kind,
        session,
        return_path,
        &state,
        &nonce,
        &verifier,
        now,
    )
    .await?;
    provider
        .authorize_url(
            &PendingFlow {
                state,
                nonce,
                code_verifier: verifier,
                redirect_uri: rt.sso.redirect_uri(provider.id()),
            },
            prompt,
        )
        .await
        .map_err(|error| {
            tracing::warn!(provider = provider.id(), ?error, "SSO authorize failed");
            Failure::Unavailable
        })
}

/// Persists the pending flow. Split out so the diagnostics of a failed write
/// stay in one place.
#[allow(clippy::too_many_arguments)] // The whole flow row is threaded explicitly.
async fn store_flow(
    rt: &AccountRuntime,
    provider: &str,
    kind: FlowKind,
    session: Option<SessionContext>,
    return_path: &str,
    state: &str,
    nonce: &str,
    verifier: &str,
    now: i64,
) -> Result<(), Failure> {
    rt.store
        .sso_flow_create(NewSsoFlow {
            handle: state,
            kind: kind.as_str(),
            provider,
            nonce,
            code_verifier: verifier,
            return_path,
            account_id: session.map(|session| session.account_id),
            session_id: session.map(|session| session.session_id),
            created_at: now,
            expires_at: now + FLOW_TTL_SECS,
        })
        .await?;
    Ok(())
}

/// Redeems a callback: the pending flow, then the provider's assertion.
///
/// The flow is consumed before the provider is called, so a replayed `state`
/// cannot drive a second exchange even if the provider is slow.
async fn redeem(
    rt: &AccountRuntime,
    provider: &Arc<dyn IdentityProvider>,
    query: &CallbackQuery,
    now: i64,
) -> Result<(sso_flow::Model, FlowKind, Assertion), Failure> {
    if !query.error.is_empty() {
        return Err(refused("denied", "provider refused"));
    }
    let flow = rt
        .store
        .sso_flow_take(&query.state, now)
        .await?
        .ok_or(refused("expired", "unknown or expired state"))?;
    let with_account = |reason, detail| Failure::Refused {
        reason,
        detail,
        account_id: flow.account_id,
    };
    if flow.provider != provider.id() {
        return Err(with_account("state", "flow belongs to another provider"));
    }
    let kind = FlowKind::parse(&flow.kind).ok_or(with_account("state", "unknown flow kind"))?;
    if query.code.is_empty() {
        return Err(with_account("code", "no code"));
    }
    let assertion = provider
        .redeem(
            &query.code,
            &PendingFlow {
                state: query.state.clone(),
                nonce: flow.nonce.clone(),
                code_verifier: flow.code_verifier.clone(),
                redirect_uri: rt.sso.redirect_uri(provider.id()),
            },
        )
        .await
        .map_err(|error| match error {
            ProviderError::Refused { reason, detail } => with_account(reason, detail),
            ProviderError::Unavailable => Failure::Unavailable,
        })?;
    Ok((flow, kind, assertion))
}

/// `GET /api/account/sso/{provider}/begin` — start a sign-in (public).
pub async fn begin(State(rt): State<Arc<AccountRuntime>>, Path(id): Path<String>) -> Response {
    let Some(provider) = rt.sso.get(&id) else {
        return err(StatusCode::NOT_FOUND, "not configured");
    };
    if provider.entry() != Entry::Redirect {
        return err(StatusCode::NOT_FOUND, "not configured");
    }
    match start(&rt, &provider, FlowKind::SignIn, None, "", Prompt::SignIn).await {
        Ok(url) => redirect(&url),
        Err(_) => unavailable(),
    }
}

/// `GET /api/account/sso/{provider}/step-up` — re-authenticate at the provider
/// (session; the gate keeps it `Basic`-reachable).
pub async fn step_up(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(manager): Extension<AuthManager>,
    Path(id): Path<String>,
    Query(query): Query<StepUpQuery>,
) -> Response {
    let Some(session) = manager.session() else {
        return err(StatusCode::UNAUTHORIZED, "not signed in");
    };
    let Some(provider) = rt.sso.get(&id) else {
        return err(StatusCode::NOT_FOUND, "not configured");
    };
    if provider.entry() != Entry::Redirect {
        return err(StatusCode::NOT_FOUND, "not configured");
    }
    // The window is what makes the provider report `auth_time`, which the
    // callback checks to know the re-authentication really just happened.
    let max_age = rt.config.confirm_window_secs as i64;
    match start(
        &rt,
        &provider,
        FlowKind::StepUp,
        Some(session),
        &sanitize_return_path(&query.return_path),
        Prompt::StepUp { max_age },
    )
    .await
    {
        Ok(url) => redirect(&url),
        Err(_) => unavailable(),
    }
}

/// `GET /api/account/sso/{provider}/callback` — finish a sign-in or a step-up
/// (public).
pub async fn callback(
    State(rt): State<Arc<AccountRuntime>>,
    Extension(manager): Extension<AuthManager>,
    Path(id): Path<String>,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let Some(provider) = rt.sso.get(&id) else {
        return signin_error("disabled");
    };
    let now = unix_secs();
    let outcome = match redeem(&rt, &provider, &query, now).await {
        Ok((flow, FlowKind::StepUp, assertion)) => {
            finish_step_up(&rt, &manager, &flow, &assertion, now).await
        }
        Ok((_, FlowKind::SignIn, assertion)) => {
            finish_sign_in(&rt, &manager, &assertion, now).await
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
    manager: &AuthManager,
    assertion: &Assertion,
    now: i64,
) -> Result<Response, Failure> {
    // The address is what an account is created from, so an assertion without
    // one cannot sign anyone in.
    let Some((address, verified)) = assertion.address.clone() else {
        return Err(refused("email", "no email in the token"));
    };
    let sealed_refresh = assertion
        .refresh_grant
        .as_deref()
        .and_then(
            |token| match rt.sso.seal_refresh(assertion.provider, token) {
                Ok(sealed) => Some(sealed),
                Err(error) => {
                    tracing::warn!(
                        provider = assertion.provider,
                        reason = error.message(),
                        "provider refresh token not stored"
                    );
                    None
                }
            },
        )
        .unwrap_or_default();

    let resolved = match rt
        .store
        .external_identity_resolve_or_create(NewExternalIdentity {
            provider: assertion.provider,
            tenant_id: &assertion.tenant,
            subject: &assertion.subject,
            name: &assertion.name,
            email: &address,
            lookup_key: &crate::email::normalize_address(&address),
            email_verified_at: verified.then_some(now),
            sealed_refresh: &sealed_refresh,
            now,
        })
        .await
    {
        Ok(resolved) => resolved,
        // The relay's signup policy refused this first sign-in (WVR-98): the
        // person is sent back to the sign-in page with the fixed wording.
        Err(StoreError::SignupRefused { refusal }) => {
            crate::account::log_signup_refusal(&address, refusal);
            return Err(refused("signup_closed", "signup policy denied"));
        }
        // The address belongs to another account and the provider does not
        // vouch for it: refusing is the takeover-safe answer.
        Err(StoreError::Conflict(_)) => return Err(refused("email", "address already in use")),
        Err(error) => {
            tracing::warn!(%error, "could not resolve an external identity");
            return Err(Failure::Unavailable);
        }
    };
    let account = resolved.account;
    // The provider callback succeeded, so the person proved who they are: only
    // now is a suspension disclosed, and never the reason (WVR-178).
    if crate::account::suspension::suspended(&account) {
        return Err(refused("suspended", "account suspended"));
    }
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
    let mfa = assertion.mfa && !settle;

    let opened = OpenedSession::open(rt, account.id, now, assertion.provider)
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
        provider = assertion.provider,
        created = resolved.created,
        mfa,
        "Signed in with an external identity provider"
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
    assertion: &Assertion,
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
            identity.provider == assertion.provider
                && identity.tenant_id.eq_ignore_ascii_case(&assertion.tenant)
                && identity.subject == assertion.subject
        });
    if !linked {
        return Err(with_account("identity", "step-up identity mismatch"));
    }
    let fresh = assertion
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

    #[test]
    fn a_sealed_secret_cannot_move_between_providers() {
        let key = SealKey::generate();
        let sealed = SsoProviders::seal(&key, "google", "s3cret").expect("seal");
        let google = SsoProviders::empty(key.clone(), "https://admin.test");
        assert_eq!(google.open("google", &sealed).expect("open"), "s3cret");
        // The same key, but asked for another provider's slot: the AAD differs.
        assert!(google.open("microsoft", &sealed).is_err());
    }
}
