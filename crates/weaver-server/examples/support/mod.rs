//! What the example harnesses share: an offline breach check, the config they
//! boot the real account stack with, and their shutdown signal.

use std::net::SocketAddr;
use std::path::PathBuf;

use async_trait::async_trait;
use tokio::signal::unix::{SignalKind, signal};

use weaver_server::account::password::BreachCheck;
use weaver_server::config::{AccountConfig, Config, EmailConfig};

/// A breach checker that never flags anything: a harness must not depend on
/// reaching the Have I Been Pwned range API.
pub struct NoBreach;

#[async_trait]
impl BreachCheck for NoBreach {
    async fn is_breached(&self, _password: &str) -> Result<bool, String> {
        Ok(false)
    }
}

/// The account config of a harness: served at `base_url`, Argon2 dialled down so
/// a browser-driven signup stays snappy, and the sealing keys the daemon would
/// generate at boot supplied here (a harness builds the runtime directly).
pub fn account_config(base_url: String) -> AccountConfig {
    let mut account = AccountConfig {
        base_url: Some(base_url),
        argon2_memory_kib: 8,
        argon2_iterations: 1,
        argon2_parallelism: 1,
        ..AccountConfig::default()
    };
    account.generate_missing_keys();
    account
}

/// The daemon-shaped config around `account`, valid for `localhost`. Nothing a
/// harness does binds the listeners or runs ACME; they are present because
/// `Config` requires them.
pub fn config(account: AccountConfig, control_socket: &str, email: Option<EmailConfig>) -> Config {
    Config {
        tunnel_domain: "weaver.test".into(),
        admin_domain: "localhost".into(),
        admin_email: "admin@weaver.test".into(),
        acme_provider: "letsencrypt-staging".into(),
        listen_http: SocketAddr::from(([127, 0, 0, 1], 0)),
        listen_https: SocketAddr::from(([127, 0, 0, 1], 0)),
        control_socket: PathBuf::from(control_socket),
        acme_directory: None,
        acme_eab_kid: None,
        acme_eab_hmac: None,
        acme_root_ca_pem: None,
        acme_fallback_providers: Vec::new(),
        usage_flush_interval_secs: 60,
        usage_retention_secs: 31_536_000,
        relay_ips: Vec::new(),
        setup_complete: false,
        email,
        abuse: None,
        account,
    }
}

/// Waits for SIGINT or SIGTERM.
pub async fn wait_for_shutdown() {
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}
