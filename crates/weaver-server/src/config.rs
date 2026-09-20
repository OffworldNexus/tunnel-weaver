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
    pub root_domain: String,
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
                "root_domain".into(),
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
            "root_domain",
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
        if config.root_domain.trim().is_empty() {
            validation_issues.push("root_domain must not be empty".into());
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

        if !validation_issues.is_empty() {
            return Err(ConfigError::ValidationFailed(validation_issues));
        }

        Ok(config)
    }
}
