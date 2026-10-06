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
    /// Defaults to 60; `#[serde(default)]` lets configs stored before
    /// metering existed keep loading.
    #[serde(default = "default_usage_flush_interval")]
    pub usage_flush_interval_secs: u64,
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
    /// Optional transactional-email configuration.
    ///
    /// Absent means email is disabled: the server still boots and every caller
    /// receives [`crate::email::MailerError::NotConfigured`]. Present means the
    /// nested block is validated by [`Config::load`]. Credentials live here
    /// because the config JSON is stored in the 0600 SQLite database — the same
    /// trust model as the ACME EAB material and certificate private keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<EmailConfig>,
}

/// Operator-supplied transactional-email settings.
///
/// Field names are deliberately provider-neutral: the catalog in
/// [`crate::email::providers`] maps them onto each provider's auth scheme and
/// request body. All fields are optional at the type level so a config stored
/// before a field existed still deserialises; [`Config::load`] enforces the
/// per-provider requirements.
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

/// Default usage flush interval, in seconds.
fn default_usage_flush_interval() -> u64 {
    60
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

        // Email is opt-in: an absent block means the server boots with email
        // disabled, while a present block must fully validate.
        if let Some(email) = &config.email {
            validation_issues.extend(crate::email::providers::validate_email_config(email));
        }

        if !validation_issues.is_empty() {
            return Err(ConfigError::ValidationFailed(validation_issues));
        }

        Ok(config)
    }
}
