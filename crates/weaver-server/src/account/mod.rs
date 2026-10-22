//! The account plane: signup, email verification, password, login and
//! logout.
//!
//! Served from the admin host only, behind an axum router mounted inside the
//! raw-hyper edge. The Rust side owns every authentication decision — the
//! SvelteKit SPA only renders and posts to these same-origin endpoints.
//!
//! The plane is always on; [`crate::config::AccountConfig`] only tunes it. The
//! runtime is built once at startup and shared through the edge config.

pub mod pairing;
pub mod password;
pub mod router;
pub mod session;
pub mod stream;

use std::sync::Arc;

use crate::altcha::AltchaRuntime;
use crate::config::AccountConfig;
use crate::email::Mailer;
use crate::live::LiveHub;
use crate::store::Store;
use password::Passwords;
use session::Sessions;

/// Shared state for the account plane, built once and mounted into the edge.
#[derive(Clone)]
pub struct AccountRuntime {
    pub store: Store,
    pub altcha: Arc<AltchaRuntime>,
    pub mailer: Option<Arc<dyn Mailer>>,
    pub passwords: Arc<Passwords>,
    pub sessions: Sessions,
    pub config: AccountConfig,
    /// The in-memory registry of pending pairings. Not persisted: a
    /// pending pairing lives only as long as the CLI's channel.
    pub pairings: pairing::Pairings,
    /// The console's real-time change bus: presence transitions, membership
    /// writes and metered minutes announce the affected person here, and every
    /// open SSE stream of that person recomputes (WVR-25).
    pub live: LiveHub,
    /// Absolute HTTPS base URL of the account plane (e.g. `https://admin.host`).
    pub base_url: String,
    /// A precomputed hash verified against when no account matches, so login
    /// timing does not reveal whether an address exists.
    pub dummy_hash: String,
    /// Public support address for the app footer, if any.
    pub support_email: Option<String>,
}

impl AccountRuntime {
    /// Builds the runtime from validated config, the store and the ALTCHA engine.
    ///
    /// A failure here is fatal at startup: the account plane cannot operate
    /// without a usable password policy.
    pub fn from_config(
        config: &AccountConfig,
        admin_domain: &str,
        store: Store,
        altcha: Arc<AltchaRuntime>,
        mailer: Option<Arc<dyn Mailer>>,
        live: LiveHub,
    ) -> Result<Arc<Self>, String> {
        let breach = password::HibpBreachCheck::new(config.hibp_url.clone())?;
        Self::with_breach(
            config,
            admin_domain,
            store,
            altcha,
            mailer,
            live,
            Arc::new(breach),
        )
    }

    /// Builds the runtime with an injected breach source.
    ///
    /// The daemon uses [`AccountRuntime::from_config`]; tests inject a
    /// deterministic checker instead of reaching the network.
    pub fn with_breach(
        config: &AccountConfig,
        admin_domain: &str,
        store: Store,
        altcha: Arc<AltchaRuntime>,
        mailer: Option<Arc<dyn Mailer>>,
        live: LiveHub,
        breach: Arc<dyn password::BreachCheck>,
    ) -> Result<Arc<Self>, String> {
        let base_url = config
            .base_url
            .clone()
            .filter(|url| !url.is_empty())
            .unwrap_or_else(|| format!("https://{admin_domain}"));
        let passwords = Passwords::new(
            config.min_password_length,
            config.argon2_memory_kib,
            config.argon2_iterations,
            config.argon2_parallelism,
            breach,
        )
        .map_err(|e| e.to_string())?;
        // A real hash of a throwaway string, so an unknown-address login spends
        // the same Argon2 work as a known one.
        let dummy_hash = passwords
            .hash("weaver-login-timing-equalizer")
            .map_err(|e| e.to_string())?;
        let sessions = Sessions::new(
            store.clone(),
            config.session_ttl_secs as i64,
            config.cookie_secure,
        );
        // Prefer an explicit support address; otherwise reuse the mailer's sender
        // so the footer can link somewhere real rather than a dead placeholder.
        let support_email = config.support_email.clone().or_else(|| {
            mailer
                .as_ref()
                .map(|mailer| mailer.identity().from.address.clone())
        });
        Ok(Arc::new(Self {
            store,
            altcha,
            mailer,
            passwords: Arc::new(passwords),
            sessions,
            config: config.clone(),
            pairings: pairing::Pairings::default(),
            live,
            base_url,
            dummy_hash,
            support_email,
        }))
    }

    /// Builds the single-use verification link for a raw token.
    pub fn verification_url(&self, raw_token: &str) -> String {
        format!(
            "{}/verify?token={raw_token}",
            self.base_url.trim_end_matches('/')
        )
    }

    /// Builds the single-use password-reset link for a raw token.
    ///
    /// The token travels in the URL **fragment**, not the query string, so it is
    /// never sent to the server and cannot leak through HTTP access logs (nor a
    /// `Referer` header). The SPA reads it from `location.hash`.
    pub fn reset_url(&self, raw_token: &str) -> String {
        format!(
            "{}/reset#token={raw_token}",
            self.base_url.trim_end_matches('/')
        )
    }

    /// The absolute HTTPS URL of the signed-in account shell.
    pub fn account_url(&self) -> String {
        format!("{}/app", self.base_url.trim_end_matches('/'))
    }

    /// The admin host a client dials to pair, for the `weave pair <host>`
    /// instruction shown in the console.
    ///
    /// Derived from `base_url` (the SPA's own origin) so a custom
    /// `account.base_url` stays correct; the scheme and any path are dropped,
    /// leaving just the host (and port) the CLI needs.
    pub fn relay_host(&self) -> String {
        let after_scheme = self
            .base_url
            .split_once("://")
            .map_or(self.base_url.as_str(), |(_, rest)| rest);
        after_scheme
            .split('/')
            .next()
            .unwrap_or(after_scheme)
            .to_string()
    }

    /// The absolute HTTPS URL of the normal password-recovery page.
    ///
    /// Linked from the "your password was changed" notification so a recipient
    /// who does not recognise the change lands on the ordinary, unauthenticated
    /// recovery flow — never a pre-authorised action.
    pub fn password_recovery_url(&self) -> String {
        format!("{}/forgot-password", self.base_url.trim_end_matches('/'))
    }
}
