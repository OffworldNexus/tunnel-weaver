use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::store::Store;

/// Configuration errors during loading or validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    /// Required configuration keys are missing.
    #[error("Configuration missing required keys: {}", .0.join(", "))]
    MissingKeys(Vec<String>),

    /// Configuration values failed validation constraints.
    #[error("Configuration validation failed: {}", .0.join("; "))]
    ValidationFailed(Vec<String>),

    /// Failed to deserialize configuration JSON.
    #[error("Config deserialization failed: {0}")]
    DeserializationFailed(String),

    /// Store or database error occurred while loading configuration.
    #[error("Store error: {0}")]
    Store(String),
}

/// Server configuration representing operational parameters and ACME provisioning settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Base domain for routed public tunnels (e.g. "example.com").
    ///
    /// This is the *delegated* zone: the parent delegates it in full to the
    /// relay, which then owns every name beneath it.
    pub tunnel_domain: String,
    /// The relay's own stable hostname (e.g. "relay.example.net").
    ///
    /// Kept outside the tunnel delegation so the relay's own DNS, control
    /// endpoint, and admin certificate are never controlled by the delegated
    /// zone. Setup detects `relay_ips` from its A/AAAA records and serves the
    /// authoritative NS/SOA under this name.
    pub admin_domain: String,
    /// Administrator contact email for ACME registration.
    pub admin_email: String,
    /// ACME directory provider (e.g. "letsencrypt", "letsencrypt-staging", "google", "zerossl", "buypass", "custom").
    pub acme_provider: String,
    /// HTTP listen socket address for cleartext traffic and ACME http-01 challenge solving.
    pub listen_http: SocketAddr,
    /// HTTPS listen socket address for TLS termination.
    pub listen_https: SocketAddr,
    /// Filesystem path for the UNIX domain control socket.
    pub control_socket: PathBuf,
    /// Custom ACME directory URL (required when acme_provider is "custom").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme_directory: Option<String>,
    /// External Account Binding Key Identifier (required for Google Trust Services and ZeroSSL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme_eab_kid: Option<String>,
    /// External Account Binding HMAC key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme_eab_hmac: Option<String>,
    /// Optional PEM-encoded custom Root CA certificate for private ACME directories (e.g. Pebble/StepCA).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme_root_ca_pem: Option<String>,
    /// Ordered fallback ACME providers if primary provider fails.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acme_fallback_providers: Vec<String>,
    /// How often the usage meter flushes closed minute buckets, in seconds.
    /// Defaults to 60.
    #[serde(default = "default_usage_flush_interval")]
    pub usage_flush_interval_secs: u64,
    /// How long the day rollup (`usage_daily`) is kept, in seconds. Defaults to
    /// one year.
    ///
    /// The minute table is not swept by age — the metering tick folds a
    /// finished day's minutes into `usage_daily` and deletes them in the same
    /// transaction — so this is the retention of the console's whole history.
    #[serde(default = "default_usage_retention")]
    pub usage_retention_secs: u64,
    /// The relay's own public IPv4/IPv6 addresses.
    ///
    /// Auto-filled at `setup` from the apex `A`/`AAAA` records it resolves,
    /// then operator-editable (required behind NAT). These drive the
    /// reachability probes, the authoritative DNS A/AAAA answers, and the
    /// explicit address the DNS socket unit binds — never a wildcard, which
    /// would collide with the `systemd-resolved` stub on `127.0.0.53:53`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_ips: Vec<std::net::IpAddr>,
    /// Whether `setup` has completed at least once.
    ///
    /// The daemon auto-orders the wildcard at startup, but on a fresh install
    /// the delegation and port-53 checks must pass first. `setup` leaves this
    /// false until those checks succeed and it has triggered the order, so the
    /// first boot does not race an unreachable zone.
    #[serde(default)]
    pub setup_complete: bool,
    /// Transactional-email configuration.
    ///
    /// Required: the sign-in second factor is an emailed code (WVR-167), so a
    /// relay that cannot send mail cannot sign anyone in. [`Config::load`]
    /// rejects an absent block; it is still `Option` at the type level only so a
    /// `configure`-built value can be assembled before the OTP proof decides it.
    /// Credentials live here because the config JSON is stored in the 0600 SQLite
    /// database — the same trust model as the ACME EAB material and certificate
    /// private keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<EmailConfig>,
    /// Optional request-budget configuration for the relay's own web surface.
    ///
    /// Absent means the surface runs without a request budget (the default);
    /// present means the `relay-web` policy is armed and validated by
    /// [`Config::load`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abuse: Option<AbuseConfig>,
    /// Account-plane tuning.
    ///
    /// The account plane is always served — it is the relay's own product
    /// surface — so this block only tunes it. Every field has a built-in
    /// default, so an absent block is exactly [`AccountConfig::default`].
    #[serde(default)]
    pub account: AccountConfig,
}

/// Operator-supplied transactional-email settings.
///
/// Field names are deliberately provider-neutral: the catalog in
/// [`crate::email::providers`] maps them onto each provider's auth scheme and
/// request body. Each provider needs a different subset, so every field but the
/// provider and sender is optional at the type level; [`Config::load`] enforces
/// the per-provider requirements.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EmailConfig {
    /// Catalog provider id (e.g. "resend", "smtp").
    pub provider: String,
    /// Verified sender address; the mailer stamps it as the `From` header.
    pub from: String,
    /// Optional display name for the sender.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_name: Option<String>,
    /// HTTP API key, or the SMTP password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// Mailjet secret half of the Basic credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// SMTP or HTTP Basic username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Mailgun sending domain, carried in the request path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Base-URL override: regional hosts, the EU Mailgun API, or a CI mock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Transactional template id, required by template-only providers (Loops).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
}

/// A syntactically valid email block for tests, fixtures and the harness.
///
/// Email is a hard requirement (WVR-167), so every boot path needs a block that
/// passes validation. Nothing here reaches the network: a transport is only
/// built, never used, and the sender domain is a reserved example.
#[cfg(any(test, feature = "test-util"))]
pub fn test_email_config() -> EmailConfig {
    EmailConfig {
        provider: "resend".to_string(),
        from: "no-reply@weaver.test".to_string(),
        api_key: Some("test-api-key".to_string()),
        ..EmailConfig::default()
    }
}

/// Redacts credentials so `EmailConfig` can sit inside `Config`'s derived
/// `Debug` without printing secrets in logs, error paths, or `status` output.
impl std::fmt::Debug for EmailConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailConfig")
            .field("provider", &self.provider)
            .field("from", &self.from)
            .field("from_name", &self.from_name)
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("endpoint", &self.endpoint)
            .field("template_id", &self.template_id)
            .field("api_key", &self.api_key.as_ref().map(|_| "[redacted]"))
            .field("secret", &self.secret.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// Operator-supplied abuse-protection settings.
///
/// Absent means the relay web surface runs with no request budget; present means
/// the `relay-web` policy is armed. Two budgets run side by side: a restrictive
/// per-host bucket and a laxer per-network backstop, so one abusive host is
/// caught before whole subnets are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbuseConfig {
    /// Whether the budget is enforced. A disabled block still validates.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Budget keyed on the client host (IPv4 `/32`, IPv6 `/64`).
    #[serde(default = "default_peer_host_budget")]
    pub peer_host: BudgetConfig,
    /// Budget keyed on the surrounding network (IPv4 `/24`, IPv6 `/56`).
    #[serde(default = "default_peer_network_budget")]
    pub peer_network: BudgetConfig,
    /// Upper bound on the surfaced `Retry-After`, in seconds.
    #[serde(default = "default_retry_after_cap_secs")]
    pub retry_after_cap_secs: u64,
    /// Idle lifetime of a persisted bucket, in seconds, before the sweep drops it.
    #[serde(default = "default_bucket_ttl_secs")]
    pub bucket_ttl_secs: u64,
    /// Optional ALTCHA proof-of-work tuning.
    ///
    /// The ALTCHA API is always served; this block only tunes its budgets and
    /// client defaults. Absent, the built-in defaults apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub altcha: Option<AltchaConfig>,
}

/// Operator-supplied ALTCHA proof-of-work tuning.
///
/// The ALTCHA API is always served — it is the relay's own service, not an
/// optional feature — so this block only tunes it. Every field has a built-in
/// default, and an absent block is exactly [`AltchaConfig::builtin`].
///
/// Challenge issuance and verification carry independent budgets, so exhausting
/// issuance cannot spend the verification budget or fall through to unbounded
/// work. The remaining fields are the defaults new clients are provisioned with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AltchaConfig {
    /// Budget for challenge issuance.
    #[serde(default = "default_altcha_challenge_budget")]
    pub challenge: BudgetConfig,
    /// Budget for solution verification.
    #[serde(default = "default_altcha_verify_budget")]
    pub verify: BudgetConfig,
    /// Default PBKDF2 iteration count for new clients.
    #[serde(default = "default_altcha_cost")]
    pub default_cost: u32,
    /// Default hex key prefix for new clients.
    #[serde(default = "default_altcha_key_prefix")]
    pub default_key_prefix: String,
    /// Default challenge lifetime, in seconds.
    #[serde(default = "default_altcha_ttl_secs")]
    pub default_ttl_secs: u64,
    /// Upper bound on live spent-proof rows before verification fails closed.
    #[serde(default = "default_altcha_proof_cap")]
    pub proof_cap: u64,
    /// Override for the public base URL of the ALTCHA API.
    ///
    /// Defaults to `https://<tunnel domain>`. Set for non-standard deployments,
    /// or a local endpoint in tests, where the diagnostic's server-side call
    /// should not traverse the public apex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_base_url: Option<String>,
}

impl AltchaConfig {
    /// The built-in tuning, used when no `abuse.altcha` block is configured.
    ///
    /// Kept in one place so the serde defaults and the "no block" path cannot
    /// drift.
    pub(crate) fn builtin() -> Self {
        Self {
            challenge: default_altcha_challenge_budget(),
            verify: default_altcha_verify_budget(),
            default_cost: default_altcha_cost(),
            default_key_prefix: default_altcha_key_prefix(),
            default_ttl_secs: default_altcha_ttl_secs(),
            proof_cap: default_altcha_proof_cap(),
            api_base_url: None,
        }
    }
}

/// Operator-supplied account-plane tuning.
///
/// The account plane is always served, so this block only tunes it. Field
/// defaults encode the agreed policy: a 12-character minimum, Django-compatible
/// Argon2id work parameters, a 24-hour verification link, a 60-second resend
/// cooldown, a 1-hour post-verification completion window, a 1-hour
/// password-reset link, and a 30-day session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountConfig {
    /// Minimum accepted password length.
    #[serde(default = "default_account_min_password_length")]
    pub min_password_length: usize,
    /// Argon2id memory cost, in KiB.
    #[serde(default = "default_account_argon2_memory_kib")]
    pub argon2_memory_kib: u32,
    /// Argon2id iteration count.
    #[serde(default = "default_account_argon2_iterations")]
    pub argon2_iterations: u32,
    /// Argon2id parallelism (lanes).
    #[serde(default = "default_account_argon2_parallelism")]
    pub argon2_parallelism: u32,
    /// Verification-link lifetime, in seconds.
    #[serde(default = "default_account_verification_ttl_secs")]
    pub verification_ttl_secs: u64,
    /// Minimum seconds between verification resends for one registration.
    #[serde(default = "default_account_resend_cooldown_secs")]
    pub resend_cooldown_secs: u64,
    /// How long a verified signup may finish setting a password, in seconds.
    #[serde(default = "default_account_completion_ttl_secs")]
    pub completion_ttl_secs: u64,
    /// Password-reset link lifetime, in seconds.
    #[serde(default = "default_account_reset_ttl_secs")]
    pub reset_ttl_secs: u64,
    /// Browser-session lifetime, in seconds.
    #[serde(default = "default_account_session_ttl_secs")]
    pub session_ttl_secs: u64,
    /// How long a password check keeps a session at `Certain`, in seconds —
    /// the window a `confirm_password` step-up is good for.
    ///
    /// Sensitive actions (deleting the account) need `Certain`, so this is how
    /// long a console that has been left open can still do them without asking
    /// for the password again.
    #[serde(default = "default_account_confirm_window_secs")]
    pub confirm_window_secs: u64,
    /// Whether session cookies carry the `Secure` attribute. Disable only for
    /// local plain-HTTP development, where browsers drop `Secure` cookies.
    #[serde(default = "default_true")]
    pub cookie_secure: bool,
    /// Base URL of the Have I Been Pwned k-anonymity range API.
    #[serde(default = "default_account_hibp_url")]
    pub hibp_url: String,
    /// Per-network budget for starting a signup.
    #[serde(default = "default_account_signup_budget")]
    pub signup: BudgetConfig,
    /// Per-network budget for login attempts.
    #[serde(default = "default_account_login_budget")]
    pub login: BudgetConfig,
    /// Per-network budget for passkey ceremonies.
    ///
    /// A passkey is cryptographic — there is nothing to guess — so this budget
    /// bounds unauthenticated work rather than a guessing surface, and it is far
    /// looser than the login budget it once shared.
    #[serde(default = "default_account_passkey_budget")]
    pub passkey: BudgetConfig,
    /// Per-network budget for verification resends.
    #[serde(default = "default_account_resend_budget")]
    pub resend: BudgetConfig,
    /// Per-network budget for opening a pending pairing and its browser API.
    ///
    /// Opening a pending pairing is unauthenticated, so it is bounded like a
    /// signup even though it costs a socket rather than a row.
    #[serde(default = "default_account_pair_budget")]
    pub pair: BudgetConfig,
    /// How long a retired machine key stays in the key log, in days.
    ///
    /// The log is an audit trail only; the nightly account sweep drops rows
    /// retired longer ago than this. Rows of keys still in use are never
    /// dropped.
    #[serde(default = "default_account_key_log_retention_days")]
    pub key_log_retention_days: u64,
    /// Public support address shown in the app footer as a `mailto:` link.
    ///
    /// Defaults to the configured mailer's `From` address when unset. When
    /// neither exists the footer renders no contact link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_email: Option<String>,
    /// Public base URL of the account plane, used to build email links.
    ///
    /// Defaults to `https://<admin_domain>`. Set for non-standard deployments or
    /// a local endpoint in tests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// Inactivity threshold, in seconds: an account with no activity for longer
    /// than this is deleted by the periodic sweep.
    ///
    /// Activity is the later of the last sign-in, the newest metered minute and
    /// "is live right now" (a live session or tunnel always wins).
    #[serde(default = "default_account_inactive_after_secs")]
    pub inactive_after_secs: u64,
    /// How long before deletion the inactivity warning is sent, in seconds.
    ///
    /// Must be smaller than `inactive_after_secs`; the gap is the window in
    /// which the owner can sign in to save the account.
    #[serde(default = "default_account_inactivity_warning_before_secs")]
    pub inactivity_warning_before_secs: u64,
}

impl Default for AccountConfig {
    fn default() -> Self {
        Self {
            min_password_length: default_account_min_password_length(),
            argon2_memory_kib: default_account_argon2_memory_kib(),
            argon2_iterations: default_account_argon2_iterations(),
            argon2_parallelism: default_account_argon2_parallelism(),
            verification_ttl_secs: default_account_verification_ttl_secs(),
            resend_cooldown_secs: default_account_resend_cooldown_secs(),
            completion_ttl_secs: default_account_completion_ttl_secs(),
            reset_ttl_secs: default_account_reset_ttl_secs(),
            session_ttl_secs: default_account_session_ttl_secs(),
            confirm_window_secs: default_account_confirm_window_secs(),
            cookie_secure: true,
            hibp_url: default_account_hibp_url(),
            signup: default_account_signup_budget(),
            login: default_account_login_budget(),
            passkey: default_account_passkey_budget(),
            resend: default_account_resend_budget(),
            pair: default_account_pair_budget(),
            key_log_retention_days: default_account_key_log_retention_days(),
            support_email: None,
            base_url: None,
            inactive_after_secs: default_account_inactive_after_secs(),
            inactivity_warning_before_secs: default_account_inactivity_warning_before_secs(),
        }
    }
}

impl AccountConfig {
    /// The key log sweep cutoff at `now` (Unix seconds): rows retired before it
    /// are past retention.
    pub fn key_log_cutoff(&self, now: i64) -> i64 {
        let retention = i64::try_from(self.key_log_retention_days)
            .unwrap_or(i64::MAX)
            .saturating_mul(86_400);
        now.saturating_sub(retention)
    }
}

/// Default minimum password length.
fn default_account_min_password_length() -> usize {
    12
}

/// Default Argon2id memory cost (100 MiB), matching Django's default.
fn default_account_argon2_memory_kib() -> u32 {
    102_400
}

/// Default Argon2id iteration count, matching Django's default.
fn default_account_argon2_iterations() -> u32 {
    2
}

/// Default Argon2id parallelism, matching Django's default.
fn default_account_argon2_parallelism() -> u32 {
    8
}

/// Default verification-link lifetime: 24 hours.
fn default_account_verification_ttl_secs() -> u64 {
    86_400
}

/// Default resend cooldown: 60 seconds.
fn default_account_resend_cooldown_secs() -> u64 {
    60
}

/// Default completion window after verification: 1 hour.
fn default_account_completion_ttl_secs() -> u64 {
    3_600
}

/// Default password-reset link lifetime: 1 hour.
fn default_account_reset_ttl_secs() -> u64 {
    3_600
}

/// Default session lifetime: 30 days.
fn default_account_session_ttl_secs() -> u64 {
    2_592_000
}

/// Default step-up window: 5 minutes.
fn default_account_confirm_window_secs() -> u64 {
    300
}

/// Default breach-check endpoint.
fn default_account_hibp_url() -> String {
    "https://api.pwnedpasswords.com/range".to_string()
}

/// Default signup budget: a 10-request burst refilling at 10 per 10 minutes.
fn default_account_signup_budget() -> BudgetConfig {
    BudgetConfig {
        burst: 10,
        refill_units: 10,
        refill_per_secs: 600,
    }
}

/// Default login budget: a 30-request burst refilling at 30 per 10 minutes.
fn default_account_login_budget() -> BudgetConfig {
    BudgetConfig {
        burst: 30,
        refill_units: 30,
        refill_per_secs: 600,
    }
}

/// Default passkey budget: a 300-request burst refilling at 300 per minute.
///
/// One passkey sign-in is a handful of requests — the field's offer, the
/// ceremony, the finish — so a person cannot come near this; only a flood can.
/// That is the point: an assertion cannot be guessed, so what is bounded here is
/// work, not a secret.
fn default_account_passkey_budget() -> BudgetConfig {
    BudgetConfig {
        burst: 300,
        refill_units: 300,
        refill_per_secs: 60,
    }
}

/// Default resend budget: a 20-request burst refilling at 20 per 10 minutes.
fn default_account_resend_budget() -> BudgetConfig {
    BudgetConfig {
        burst: 20,
        refill_units: 20,
        refill_per_secs: 600,
    }
}

/// Default pairing budget: a 20-request burst refilling at 20 per 10 minutes.
///
/// Pairing is a rare, deliberate act; the budget only has to stop a machine
/// from opening pending pairings in a loop.
fn default_account_pair_budget() -> BudgetConfig {
    BudgetConfig {
        burst: 20,
        refill_units: 20,
        refill_per_secs: 600,
    }
}

/// Default key log retention: one year.
fn default_account_key_log_retention_days() -> u64 {
    365
}

/// Default inactivity threshold: twelve months.
fn default_account_inactive_after_secs() -> u64 {
    365 * 86_400
}

/// Default warning lead time: one month before deletion.
fn default_account_inactivity_warning_before_secs() -> u64 {
    30 * 86_400
}

/// One token bucket's burst and refill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetConfig {
    /// Maximum units available at once (the burst).
    pub burst: u32,
    /// Units replenished every `refill_per_secs`.
    pub refill_units: u32,
    /// The refill window, in seconds.
    pub refill_per_secs: u64,
}

/// Returns the enabled-by-default flag for [`AbuseConfig`].
fn default_true() -> bool {
    true
}

/// Default per-host budget: a 30-request burst refilling at 30 per minute.
fn default_peer_host_budget() -> BudgetConfig {
    BudgetConfig {
        burst: 30,
        refill_units: 30,
        refill_per_secs: 60,
    }
}

/// Default per-network backstop: a 150-request burst refilling at 150 per minute.
fn default_peer_network_budget() -> BudgetConfig {
    BudgetConfig {
        burst: 150,
        refill_units: 150,
        refill_per_secs: 60,
    }
}

/// Default `Retry-After` bound, in seconds.
fn default_retry_after_cap_secs() -> u64 {
    600
}

/// Default idle lifetime for a persisted bucket, in seconds.
fn default_bucket_ttl_secs() -> u64 {
    3600
}

/// Default challenge-issuance budget: a 60-request burst refilling per minute.
fn default_altcha_challenge_budget() -> BudgetConfig {
    BudgetConfig {
        burst: 60,
        refill_units: 60,
        refill_per_secs: 60,
    }
}

/// Default verification budget: a 30-request burst refilling per minute.
fn default_altcha_verify_budget() -> BudgetConfig {
    BudgetConfig {
        burst: 30,
        refill_units: 30,
        refill_per_secs: 60,
    }
}

/// Default PBKDF2 iteration count for new ALTCHA clients.
fn default_altcha_cost() -> u32 {
    5_000
}

/// Default hex key prefix for new ALTCHA clients.
fn default_altcha_key_prefix() -> String {
    "00".to_string()
}

/// Default ALTCHA challenge lifetime, in seconds.
fn default_altcha_ttl_secs() -> u64 {
    300
}

/// Default cap on live spent-proof rows.
fn default_altcha_proof_cap() -> u64 {
    100_000
}

/// Rejects an armed [`AbuseConfig`] whose buckets could never admit anything.
///
/// A disabled block is never rejected; its numbers are not in play.
fn validate_abuse_config(abuse: &AbuseConfig) -> Vec<String> {
    let mut issues = Vec::new();
    for (name, budget) in [
        ("peer_host", &abuse.peer_host),
        ("peer_network", &abuse.peer_network),
    ] {
        if budget.burst < 1 {
            issues.push(format!("abuse.{name}.burst must be >= 1"));
        }
        if budget.refill_units < 1 {
            issues.push(format!("abuse.{name}.refill_units must be >= 1"));
        }
        if budget.refill_per_secs < 1 {
            issues.push(format!("abuse.{name}.refill_per_secs must be >= 1"));
        }
    }
    if abuse.retry_after_cap_secs < 1 {
        issues.push("abuse.retry_after_cap_secs must be >= 1".into());
    }
    if abuse.bucket_ttl_secs < 1 {
        issues.push("abuse.bucket_ttl_secs must be >= 1".into());
    }
    if let Some(altcha) = &abuse.altcha {
        for (name, budget) in [
            ("altcha.challenge", &altcha.challenge),
            ("altcha.verify", &altcha.verify),
        ] {
            if budget.burst < 1 {
                issues.push(format!("abuse.{name}.burst must be >= 1"));
            }
            if budget.refill_units < 1 {
                issues.push(format!("abuse.{name}.refill_units must be >= 1"));
            }
            if budget.refill_per_secs < 1 {
                issues.push(format!("abuse.{name}.refill_per_secs must be >= 1"));
            }
        }
        if altcha.default_cost < 1 {
            issues.push("abuse.altcha.default_cost must be >= 1".into());
        }
        if altcha.default_key_prefix.is_empty()
            || !altcha
                .default_key_prefix
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            issues.push("abuse.altcha.default_key_prefix must be a non-empty hex string".into());
        }
        if altcha.default_ttl_secs < 1 {
            issues.push("abuse.altcha.default_ttl_secs must be >= 1".into());
        }
        if altcha.proof_cap < 1 {
            issues.push("abuse.altcha.proof_cap must be >= 1".into());
        }
    }
    issues
}

/// Default usage flush interval, in seconds.
fn default_usage_flush_interval() -> u64 {
    60
}

/// The usage rollup's default retention: one year, the console's whole history.
/// What an existing config predating the key, or a caller with nothing to
/// preserve, should use.
pub fn default_usage_retention() -> u64 {
    31_536_000
}

/// Checks the admin/tunnel domain split and returns a reason when it is unsafe.
///
/// The tunnel domain is delegated in full to this relay, so an admin domain
/// *under* the tunnel zone would put the relay's own DNS — and therefore the
/// admin certificate's HTTP-01 DCV and the authoritative NS records — under the
/// delegated zone's control. The reverse nesting (tunnel under admin) is safe
/// and allowed. Both names are compared case-insensitively with any trailing
/// dot ignored.
///
/// Returns `None` when the pair is acceptable. Callers are expected to have
/// already rejected empty names, but an empty input is reported here too.
pub fn domain_split_issue(admin_domain: &str, tunnel_domain: &str) -> Option<String> {
    let admin = crate::store::names::normalize_domain(admin_domain);
    let root = crate::store::names::normalize_domain(tunnel_domain);
    if admin.is_empty() || root.is_empty() {
        return Some("admin_domain and tunnel_domain must both be non-empty".into());
    }
    if admin == root {
        return Some("admin_domain and tunnel_domain must differ".into());
    }
    if admin.ends_with(&format!(".{root}")) {
        return Some(format!(
            "admin_domain '{admin}' must not be a subdomain of the tunnel domain '{root}'"
        ));
    }
    None
}

/// Rejects account tuning whose work parameters or lifetimes could not admit
/// anything. The account plane is always armed, so this is always checked.
fn validate_account_config(account: &AccountConfig) -> Vec<String> {
    let mut issues = Vec::new();
    if account.min_password_length < 8 {
        issues.push("account.min_password_length must be >= 8".into());
    }
    if account.argon2_memory_kib < 8 {
        issues.push("account.argon2_memory_kib must be >= 8".into());
    }
    if account.argon2_iterations < 1 {
        issues.push("account.argon2_iterations must be >= 1".into());
    }
    if account.argon2_parallelism < 1 {
        issues.push("account.argon2_parallelism must be >= 1".into());
    }
    for (name, value) in [
        ("verification_ttl_secs", account.verification_ttl_secs),
        ("resend_cooldown_secs", account.resend_cooldown_secs),
        ("completion_ttl_secs", account.completion_ttl_secs),
        ("reset_ttl_secs", account.reset_ttl_secs),
        ("session_ttl_secs", account.session_ttl_secs),
        ("confirm_window_secs", account.confirm_window_secs),
        ("key_log_retention_days", account.key_log_retention_days),
        ("inactive_after_secs", account.inactive_after_secs),
        (
            "inactivity_warning_before_secs",
            account.inactivity_warning_before_secs,
        ),
    ] {
        if value < 1 {
            issues.push(format!("account.{name} must be >= 1"));
        }
    }
    if account.inactivity_warning_before_secs >= account.inactive_after_secs {
        issues.push(
            "account.inactivity_warning_before_secs must be smaller than account.inactive_after_secs"
                .into(),
        );
    }
    for (name, budget) in [
        ("signup", &account.signup),
        ("login", &account.login),
        ("resend", &account.resend),
        ("pair", &account.pair),
    ] {
        if budget.burst < 1 {
            issues.push(format!("account.{name}.burst must be >= 1"));
        }
        if budget.refill_units < 1 {
            issues.push(format!("account.{name}.refill_units must be >= 1"));
        }
        if budget.refill_per_secs < 1 {
            issues.push(format!("account.{name}.refill_per_secs must be >= 1"));
        }
    }
    if account.hibp_url.trim().is_empty() {
        issues.push("account.hibp_url must not be empty".into());
    }
    issues
}

impl Config {
    /// Loads and validates configuration from the store.
    pub async fn load(store: &Store) -> Result<Self, ConfigError> {
        let raw_json = store
            .load_config_json()
            .await
            .map_err(|e| ConfigError::Store(e.to_string()))?;

        let Some(json_str) = raw_json else {
            return Err(ConfigError::MissingKeys(vec![
                "tunnel_domain".into(),
                "admin_domain".into(),
                "admin_email".into(),
                "acme_provider".into(),
                "listen_http".into(),
                "listen_https".into(),
                "control_socket".into(),
            ]));
        };

        let val: serde_json::Value = serde_json::from_str(&json_str)
            .map_err(|e| ConfigError::DeserializationFailed(e.to_string()))?;

        let obj = val.as_object().ok_or_else(|| {
            ConfigError::DeserializationFailed("root JSON is not an object".into())
        })?;

        let required_keys = [
            "tunnel_domain",
            "admin_domain",
            "admin_email",
            "acme_provider",
            "listen_http",
            "listen_https",
            "control_socket",
        ];

        let mut missing = Vec::new();
        for key in &required_keys {
            if obj.get(*key).is_none_or(|v| v.is_null()) {
                missing.push(key.to_string());
            }
        }

        if !missing.is_empty() {
            return Err(ConfigError::MissingKeys(missing));
        }

        let config: Config = serde_json::from_value(val)
            .map_err(|e| ConfigError::DeserializationFailed(e.to_string()))?;

        // Semantic validation
        let mut validation_issues = Vec::new();
        if config.tunnel_domain.trim().is_empty() {
            validation_issues.push("tunnel_domain must not be empty".into());
        }
        if config.admin_domain.trim().is_empty() {
            validation_issues.push("admin_domain must not be empty".into());
        }
        // Only compare the pair once both are present; the empty checks above
        // already reported the missing side.
        if !config.tunnel_domain.trim().is_empty()
            && !config.admin_domain.trim().is_empty()
            && let Some(issue) = domain_split_issue(&config.admin_domain, &config.tunnel_domain)
        {
            validation_issues.push(issue);
        }

        let email = config.admin_email.trim();
        if !email.contains('@') || !email.contains('.') {
            validation_issues.push(format!(
                "admin_email '{email}' is not a valid email address"
            ));
        }

        let provider = config.acme_provider.to_lowercase();
        if provider == "google" || provider == "zerossl" {
            if config
                .acme_eab_kid
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                validation_issues.push(format!("acme_provider '{provider}' requires acme_eab_kid"));
            }
            if config
                .acme_eab_hmac
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                validation_issues
                    .push(format!("acme_provider '{provider}' requires acme_eab_hmac"));
            }
        } else if provider == "custom"
            && config
                .acme_directory
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
        {
            validation_issues.push("acme_provider 'custom' requires acme_directory URL".into());
        }

        // Email is a hard requirement (WVR-167): the second factor is an emailed
        // code, so a relay that cannot send mail cannot sign anyone in. An absent
        // block is a validation failure, never a degraded mode with the second
        // factor quietly unavailable.
        match &config.email {
            Some(email) => {
                validation_issues.extend(crate::email::providers::validate_email_config(email));
            }
            None => validation_issues.push(
                "email is required: configure an email provider (the emailed second factor is the sign-in)".into(),
            ),
        }

        // Abuse limits are opt-in; an armed block must be internally coherent.
        if let Some(abuse) = &config.abuse
            && abuse.enabled
        {
            validation_issues.extend(validate_abuse_config(abuse));
        }

        // Account tuning is always armed, so it is always validated.
        validation_issues.extend(validate_account_config(&config.account));

        if !validation_issues.is_empty() {
            return Err(ConfigError::ValidationFailed(validation_issues));
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The passkey budget bounds unauthenticated work, not a secret: an
    /// assertion cannot be guessed, so it must be far looser than the login
    /// budget that password attempts share with a person's own sign-ins
    /// (WVR-163).
    #[test]
    fn the_passkey_budget_is_laxer_than_the_login_budget() {
        let account = AccountConfig::default();
        assert!(account.passkey.burst > account.login.burst);
        let login_per_sec =
            account.login.refill_units as f64 / account.login.refill_per_secs as f64;
        let passkey_per_sec =
            account.passkey.refill_units as f64 / account.passkey.refill_per_secs as f64;
        assert!(
            passkey_per_sec > login_per_sec * 10.0,
            "the passkey budget must be a lot looser, not merely different"
        );
        // An absent key falls back to the same default, so a config written
        // before WVR-163 gets the loose budget rather than the login's.
        let absent: AccountConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(absent.passkey, account.passkey);
    }

    #[test]
    fn key_log_retention_defaults_to_a_year() {
        let account = AccountConfig::default();
        assert_eq!(account.key_log_retention_days, 365);
        assert_eq!(account.key_log_cutoff(400 * 86_400), 35 * 86_400);
        let absent: AccountConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(absent.key_log_retention_days, 365);
    }

    #[test]
    fn key_log_retention_must_be_positive() {
        let account = AccountConfig {
            key_log_retention_days: 0,
            ..AccountConfig::default()
        };
        assert!(
            validate_account_config(&account)
                .iter()
                .any(|issue| issue == "account.key_log_retention_days must be >= 1")
        );
        assert!(validate_account_config(&AccountConfig::default()).is_empty());
    }

    #[test]
    fn huge_retention_does_not_overflow() {
        let account = AccountConfig {
            key_log_retention_days: u64::MAX,
            ..AccountConfig::default()
        };
        assert_eq!(account.key_log_cutoff(1_000), 1_000 - i64::MAX);
    }

    #[test]
    fn inactivity_defaults_are_a_year_and_a_month() {
        let account = AccountConfig::default();
        assert_eq!(account.inactive_after_secs, 365 * 86_400);
        assert_eq!(account.inactivity_warning_before_secs, 30 * 86_400);
        // Absent keys fall back to the same defaults, so an existing config
        // predating WVR-160 still gets the sweep armed.
        let absent: AccountConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(absent.inactive_after_secs, 365 * 86_400);
        assert_eq!(absent.inactivity_warning_before_secs, 30 * 86_400);
    }

    #[test]
    fn warning_must_be_positive_and_precede_deletion() {
        let account = AccountConfig {
            inactive_after_secs: 100,
            inactivity_warning_before_secs: 100,
            ..AccountConfig::default()
        };
        assert!(
            validate_account_config(&account)
                .iter()
                .any(|issue| issue.contains("inactivity_warning_before_secs must be smaller"))
        );

        let zero = AccountConfig {
            inactivity_warning_before_secs: 0,
            ..AccountConfig::default()
        };
        assert!(
            validate_account_config(&zero)
                .iter()
                .any(|issue| issue == "account.inactivity_warning_before_secs must be >= 1")
        );
    }
}
