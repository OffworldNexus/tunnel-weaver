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

use crate::cert::{CertManager, CertResolver, ChallengeRegistry, SystemClock};
use crate::config::{Config, ConfigError};
use crate::edge::http::run_http_server;
use crate::edge::https::run_https_server_with_registry;
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
/// Validates root execution environment, opens SQLite database, validates configuration,
/// acquires listeners, generates self-signed TLS certificates, notifies systemd of readiness,
/// and serves HTTP/HTTPS traffic until a termination signal or cancellation token triggers shutdown.
pub async fn run_server(
    db_path: PathBuf,
    external_shutdown: Option<CancellationToken>,
) -> Result<(), ServerError> {
    // 1. Check root UID warning
    check_root_warning();

    // 2. Open SQLite store (creates directories and applies migrations)
    let store = Store::open(&db_path)?;

    // 3. Load and validate configuration
    let config = match Config::load(&store) {
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
        root_domain = %config.root_domain,
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
    let challenge_registry = Arc::new(ChallengeRegistry::new());
    let resolver = Arc::new(CertResolver::new(
        config.root_domain.clone(),
        Arc::clone(&challenge_registry),
    ));

    let cert_manager = CertManager::new(
        Arc::new(config.clone()),
        Arc::new(store.clone()),
        Arc::clone(&resolver),
        Arc::clone(&challenge_registry),
        Arc::new(SystemClock),
        true,
    );
    cert_manager
        .init()
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

    let tunnel_registry = Arc::new(crate::tunnel::TunnelRegistry::new(
        config.root_domain.clone(),
        Arc::clone(&cert_manager),
        Arc::new(crate::tunnel::PocResolver),
    ));

    let http_token = shutdown_token.clone();
    let http_task = tokio::spawn(run_http_server(
        listeners.http,
        config.root_domain.clone(),
        config.listen_https.port(),
        Some(Arc::clone(&challenge_registry)),
        http_token,
    ));

    let https_token = shutdown_token.clone();
    let https_task = tokio::spawn(run_https_server_with_registry(
        listeners.https,
        tls_config,
        config.root_domain.clone(),
        Some(Arc::clone(&resolver)),
        Some(tunnel_registry),
        https_token,
    ));

    let control_token = shutdown_token.clone();
    let control_start_time = Instant::now();
    let control_config = Arc::new(config.clone());
    let control_store = Arc::new(store.clone());
    let control_cert_mgr = Arc::clone(&cert_manager);
    let control_task = tokio::spawn(async move {
        if let Err(err) = crate::control::server::run_control_server_with_listener(
            control_listener,
            control_socket_path,
            control_config,
            control_store,
            control_cert_mgr,
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

    // Spawn eager issuance for root domain after READY notification
    cert_manager.spawn_eager_order_if_pending();

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
        let _ = tokio::join!(http_task, https_task, control_task);
    };

    if tokio::time::timeout(drain_timeout, drain).await.is_err() {
        warn!("Connection drain timed out after 10 seconds; proceeding to close");
    }

    // Close SQLite store
    if let Err(err) = store.close() {
        error!(error = %err, "Error closing SQLite store");
    }

    info!("Server shutdown complete");
    Ok(())
}
