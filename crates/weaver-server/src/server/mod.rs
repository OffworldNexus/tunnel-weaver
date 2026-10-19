//! Server daemon lifecycle, configuration validation, and graceful shutdown orchestration.

pub mod listener;

use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::server::ResolvesServerCert;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::cert::managed::ManagedCerts;
use crate::cert::solver::Http01Solver;
use crate::cert::{CertManager, CertResolver, SystemClock};
use crate::config::{Config, ConfigError};
use crate::dns::{
    AcmeChallenges, DnsResponder, DnsResponderConfig, DomainGenerator, TunnelDomains,
};
use crate::edge::http::{ChallengeResponder, HttpEdgeConfig, run_http_server_full};
use crate::edge::tls::{TlsError, create_server_config};
use crate::notify::{notify_ready_with_cert_status, notify_stopping};
use crate::server::listener::{ListenerError, acquire_listeners};
use crate::store::{Store, StoreError};

/// Standard exit code for configuration errors (`EX_CONFIG`).
pub const EX_CONFIG: i32 = 78;

/// Errors that can cause `weaver-server run` to fail during startup or runtime.
#[derive(Debug, Error)]
pub enum ServerError {
    /// Failed to open or initialize SQLite state store.
    #[error("Store error: {0}")]
    Store(#[from] StoreError),

    /// Missing required configuration keys in database.
    #[error("Configuration missing required keys: {}", .0.join(", "))]
    MissingConfig(Vec<String>),

    /// Invalid configuration values.
    #[error("Configuration validation failed: {}", .0.join("; "))]
    ValidationConfig(Vec<String>),

    /// Failed to bind listening socket.
    #[error("Failed to bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        source: std::io::Error,
    },

    /// Systemd socket activation error.
    #[error("Socket activation error: {0}")]
    Activation(String),

    /// TLS certificate or rustls setup error.
    #[error("TLS configuration error: {0}")]
    Tls(#[from] TlsError),
}

/// Logs a warning to stderr if running as effective UID 0 (root) outside a container.
pub fn check_root_warning() {
    let euid = unsafe { libc::geteuid() };
    if euid == 0 && !Path::new("/.dockerenv").exists() && env::var_os("container").is_none() {
        warn!("Running with effective UID 0 (root) outside a container is not recommended");
    }
}

/// Runs the main `weaver-server` daemon.
///
/// Validates root execution environment, opens the state store, validates configuration,
/// acquires listeners, generates self-signed TLS certificates, notifies systemd of readiness,
/// and serves HTTP/HTTPS traffic until a termination signal or cancellation token triggers shutdown.
pub async fn run_server(
    db_path: PathBuf,
    external_shutdown: Option<CancellationToken>,
) -> Result<(), ServerError> {
    // 1. Check root UID warning
    check_root_warning();

    // 2. Open the store (creates directories and applies migrations)
    let store = Store::open(&db_path).await?;

    // 3. Load and validate configuration
    let config = match Config::load(&store).await {
        Ok(cfg) => cfg,
        Err(ConfigError::MissingKeys(keys)) => return Err(ServerError::MissingConfig(keys)),
        Err(ConfigError::ValidationFailed(issues)) => {
            return Err(ServerError::ValidationConfig(issues));
        }
        Err(ConfigError::DeserializationFailed(msg)) => {
            return Err(ServerError::ValidationConfig(vec![msg]));
        }
        Err(ConfigError::Store(msg)) => {
            return Err(ServerError::Store(StoreError::InvalidPath(msg)));
        }
    };

    info!(
        tunnel_domain = %config.tunnel_domain,
        admin_domain = %config.admin_domain,
        http_listen = %config.listen_http,
        https_listen = %config.listen_https,
        "Configuration loaded and validated"
    );

    // 4. Acquire listeners (LISTEN_FDS or dual-stack self-bind)
    let listeners = match acquire_listeners(&config) {
        Ok(l) => l,
        Err(ListenerError::Bind { addr, source }) => {
            return Err(ServerError::Bind { addr, source });
        }
        Err(ListenerError::Activation(msg)) => {
            return Err(ServerError::Activation(msg));
        }
    };

    // 5. Initialize certificate manager and dynamic TLS resolver
    let resolver = Arc::new(CertResolver::with_managed(
        Arc::new(ManagedCerts::from_config(&config)),
        Arc::new(SystemClock),
    ));

    let cert_manager = CertManager::new(
        Arc::new(config.clone()),
        Arc::new(store.clone()),
        Arc::clone(&resolver),
        Arc::new(SystemClock),
    );
    cert_manager
        .init()
        .await
        .map_err(|e| ServerError::Activation(format!("Failed to initialize CertManager: {e}")))?;

    let tls_config = create_server_config(Arc::clone(&resolver) as Arc<dyn ResolvesServerCert>)?;

    // 6. Bind control socket listener before declaring readiness
    let control_socket_path = config.control_socket.clone();
    let control_listener = crate::control::server::bind_control_listener(&control_socket_path)
        .map_err(|e| ServerError::Activation(format!("Failed to bind control socket: {e}")))?;

    // 7. Pre-register termination signal handlers before declaring readiness
    #[cfg(unix)]
    let (mut sigint, mut sigterm) = {
        use tokio::signal::unix::{SignalKind, signal};
        let int = signal(SignalKind::interrupt()).map_err(|e| {
            ServerError::Activation(format!("Failed to register SIGINT handler: {e}"))
        })?;
        let term = signal(SignalKind::terminate()).map_err(|e| {
            ServerError::Activation(format!("Failed to register SIGTERM handler: {e}"))
        })?;
        (int, term)
    };

    // 8. Spawn HTTP, HTTPS, and control server tasks and eager issuance
    let shutdown_token = external_shutdown.unwrap_or_default();

    // Start background renewal loop
    cert_manager.start_renewal_loop(shutdown_token.clone());

    let identity_resolver = Arc::new(crate::tunnel::StoreIdentityResolver::new(store.clone()));
    let metering = Arc::new(crate::metering::MeteringManager::new(
        store.clone(),
        Duration::from_secs(config.usage_flush_interval_secs),
    ));
    let tunnel_registry = Arc::new(crate::tunnel::TunnelRegistry::new(
        config.tunnel_domain.clone(),
        Arc::clone(&cert_manager),
        identity_resolver,
        store.clone(),
        Arc::clone(&metering),
    ));

    // The manager ticks once a second and flushes on the configured cadence;
    // on shutdown it performs a final flush that includes the partial current
    // minute, which the drain below awaits before the store is closed.
    let usage_task = Arc::clone(&metering).start(shutdown_token.clone());

    // The relay-web budget gate (None when abuse is unconfigured) plus
    // a background sweep that drops idle buckets so the table stays bounded.
    let guard = crate::abuse::build(&config, store.clone());
    // The ALTCHA runtime (None when `abuse.altcha` is not enabled).
    let altcha =
        crate::altcha::AltchaRuntime::from_config(&config, store.clone()).map_err(|e| {
            ServerError::Activation(format!("Failed to initialize ALTCHA runtime: {e}"))
        })?;
    altcha.ensure_demo_client().await.map_err(|e| {
        ServerError::Activation(format!("Failed to provision the ALTCHA demo client: {e}"))
    })?;
    let abuse_task = config
        .abuse
        .as_ref()
        .filter(|abuse| abuse.enabled)
        .map(|cfg| {
            let store = store.clone();
            let ttl_ms = (cfg.bucket_ttl_secs as i64).saturating_mul(1000).max(1);
            let token = shutdown_token.clone();
            info!(ttl_secs = cfg.bucket_ttl_secs, "abuse bucket sweep running");
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(600));
                loop {
                    tokio::select! {
                        _ = token.cancelled() => break,
                        _ = ticker.tick() => {
                            let cutoff = crate::wall_clock::unix_ms() - ttl_ms;
                            if let Err(err) = store.abuse_sweep(cutoff).await {
                                warn!(error = %err, "abuse bucket sweep failed");
                            }
                        }
                    }
                }
            })
        });

    // Sweep expired spent-proof markers so the table stays bounded. The
    // ALTCHA API is always served, so this always runs.
    let altcha_sweep = config
        .abuse
        .as_ref()
        .and_then(|abuse| abuse.altcha.clone())
        .unwrap_or_else(crate::config::AltchaConfig::builtin);
    let altcha_task = {
        let store = store.clone();
        let interval = altcha_sweep.sweep_interval_secs.max(1);
        let token = shutdown_token.clone();
        info!(interval_secs = interval, "ALTCHA proof sweep running");
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(interval));
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = ticker.tick() => {
                        let cutoff = crate::wall_clock::unix_ms();
                        if let Err(err) = store.altcha_sweep_proofs(cutoff).await {
                            warn!(error = %err, "ALTCHA proof sweep failed");
                        }
                    }
                }
            }
        })
    };

    // The account plane. It is always served on the admin host. The
    // mailer is optional: when email is not configured, signup still records the
    // pending registration and the user can resend once mail is set up.
    let support_url = format!("https://{}", config.admin_domain);
    let mailer = match crate::email::mailer_from_config(config.email.as_ref(), &support_url) {
        Ok(mailer) => Some(mailer),
        Err(crate::email::MailerError::NotConfigured) => None,
        Err(err) => {
            return Err(ServerError::Activation(format!(
                "Failed to initialize the account mailer: {err}"
            )));
        }
    };
    let account = crate::account::AccountRuntime::from_config(
        &config.account,
        &config.admin_domain,
        store.clone(),
        altcha.clone(),
        mailer,
    )
    .map_err(|e| ServerError::Activation(format!("Failed to initialize the account plane: {e}")))?;
    let account_sweep = {
        let store = store.clone();
        let account_config = config.account.clone();
        let interval = config.account.sweep_interval_secs.max(1);
        let token = shutdown_token.clone();
        info!(
            interval_secs = interval,
            "account token/session/key-log sweep running"
        );
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(interval));
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = ticker.tick() => {
                        let cutoff = crate::wall_clock::unix_ms() / 1000;
                        if let Err(err) = store.verification_token_sweep(cutoff).await {
                            warn!(error = %err, "verification token sweep failed");
                        }
                        if let Err(err) = store.password_reset_token_sweep(cutoff).await {
                            warn!(error = %err, "password reset token sweep failed");
                        }
                        if let Err(err) = store.session_sweep(cutoff).await {
                            warn!(error = %err, "session sweep failed");
                        }
                        let key_log_cutoff = account_config.key_log_cutoff(cutoff);
                        if let Err(err) = store.sweep_machine_key_log(key_log_cutoff).await {
                            warn!(error = %err, "machine key log sweep failed");
                        }
                    }
                }
            }
        })
    };

    let http_token = shutdown_token.clone();
    let challenge_responders: Vec<Arc<dyn ChallengeResponder>> =
        vec![Arc::new(Http01Solver::new(Arc::new(store.clone())))];
    let http_task = tokio::spawn(run_http_server_full(
        listeners.http,
        HttpEdgeConfig {
            tunnel_domain: config.tunnel_domain.clone(),
            https_port: config.listen_https.port(),
            challenge_responders,
            guard: guard.clone(),
        },
        http_token,
    ));

    let https_token = shutdown_token.clone();
    let https_task = tokio::spawn(crate::edge::https::run_https_server_full(
        listeners.https,
        tls_config,
        crate::edge::https::HttpsEdgeConfig {
            managed: Arc::new(ManagedCerts::from_config(&config)),
            cert_resolver: Some(Arc::clone(&resolver)),
            cert_manager: Some(Arc::clone(&cert_manager)),
            tunnel_registry: Some(tunnel_registry),
            guard: guard.clone(),
            altcha: Some(altcha.clone()),
            account: Some(account.clone()),
        },
        https_token,
    ));

    // Authoritative DNS responder: one task per inherited/self-bound socket,
    // over the ACME challenge registry (TXT) and the tunnel domain
    // (A/AAAA/NS/SOA/CAA).
    let generator_config = DnsResponderConfig::from_config(&config);
    let generators: Vec<Arc<dyn DomainGenerator>> = vec![
        Arc::new(AcmeChallenges::new(Arc::new(store.clone()))),
        Arc::new(TunnelDomains::new(&generator_config)),
    ];
    let dns_responder = Arc::new(DnsResponder::new(generators));
    let mut dns_tasks = Vec::new();
    for socket in listeners.dns_udp {
        dns_tasks.push(tokio::spawn(crate::dns::run_udp(
            socket,
            Arc::clone(&dns_responder),
            shutdown_token.clone(),
        )));
    }
    for listener in listeners.dns_tcp {
        dns_tasks.push(tokio::spawn(crate::dns::run_tcp(
            listener,
            Arc::clone(&dns_responder),
            shutdown_token.clone(),
        )));
    }
    if dns_tasks.is_empty() {
        info!("No DNS listeners acquired; authoritative DNS is not served in this process");
    }

    let control_token = shutdown_token.clone();
    let control_start_time = Instant::now();
    let control_config = Arc::new(config.clone());
    let control_store = Arc::new(store.clone());
    let control_cert_mgr = Arc::clone(&cert_manager);
    let control_metering = Arc::clone(&metering);
    let control_task = tokio::spawn(async move {
        if let Err(err) = crate::control::server::run_control_server_with_listener(
            control_listener,
            control_socket_path,
            control_config,
            control_store,
            control_cert_mgr,
            control_metering,
            control_start_time,
            control_token,
        )
        .await
        {
            warn!(error = %err, "Control socket listener ended with error");
        }
    });

    // 9. Notify systemd readiness
    if let Err(err) = notify_ready_with_cert_status(cert_manager.root_cert_status()) {
        warn!(error = %err, "Failed to send systemd READY notification");
    }

    // Spawn eager issuance for root domain after READY notification.
    //
    // On a fresh install `setup_complete` is false until setup has verified the
    // delegation and port 53 and triggered the order itself; the daemon awaits
    // that explicit `cert.order` rather than racing an unreachable zone.
    if config.setup_complete {
        cert_manager.spawn_eager_order_if_pending();
    } else {
        info!(
            "setup_complete is false; skipping startup auto-order (setup will trigger cert.order)"
        );
    }

    // 9. Wait for shutdown signal
    let term_token = shutdown_token.clone();
    #[cfg(unix)]
    tokio::select! {
        _ = sigint.recv() => {
            info!("Received SIGINT (Ctrl+C), initiating graceful shutdown");
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM, initiating graceful shutdown");
        }
        _ = term_token.cancelled() => {
            info!("External shutdown token cancelled, initiating graceful shutdown");
        }
    }
    #[cfg(not(unix))]
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl+C, initiating graceful shutdown");
        }
        _ = term_token.cancelled() => {
            info!("External shutdown token cancelled, initiating graceful shutdown");
        }
    }

    // 10. Graceful shutdown coordination
    if let Err(err) = notify_stopping() {
        warn!(error = %err, "Failed to send systemd STOPPING notification");
    }

    shutdown_token.cancel();

    // Drain connections with 10-second cap
    let drain_timeout = Duration::from_secs(10);
    info!(drain_timeout_secs = 10, "Draining active connections");

    let drain = async {
        let _ = tokio::join!(http_task, https_task, control_task, usage_task);
        if let Some(task) = abuse_task {
            let _ = task.await;
        }
        let _ = altcha_task.await;
        let _ = account_sweep.await;
        let _ = futures_util::future::join_all(dns_tasks).await;
    };

    if tokio::time::timeout(drain_timeout, drain).await.is_err() {
        warn!("Connection drain timed out after 10 seconds; proceeding to close");
    }

    // Close the store
    if let Err(err) = store.close().await {
        error!(error = %err, "Error closing store");
    }

    info!("Server shutdown complete");
    Ok(())
}
