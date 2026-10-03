//! Certificate management daemon, resolvers, and ACME coordination.

pub mod acme;
pub mod clock;
pub mod events;
pub mod providers;
pub mod renewal;
pub mod resolver;
pub mod state;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::{Mutex, Semaphore, broadcast};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

pub use acme::{
    AcmeEngine, AcmeError, IssuedCertificate, RegisteredAcmeAccount, parse_cert_validity,
    register_acme_account,
};
#[cfg(any(test, feature = "test-util"))]
pub use clock::MockClock;
pub use clock::{Clock, SystemClock, format_unix_timestamp};
pub use events::record_cert_event;
pub use providers::{PROVIDERS, find_provider, format_providers_table};
pub use renewal::{compute_backoff, should_renew};
pub use resolver::{CertResolver, parse_certified_key};
pub use state::CertState;

/// How long a service registration waits for the wildcard certificate before
/// giving up. Registering during the wildcard-pending window is a rare edge
/// case (initial setup or a certificate outage), so a bounded hold is enough.
pub const CERT_WAIT_TIMEOUT: Duration = Duration::from_secs(60);

/// Error conditions that can occur during manual or batch certificate renewal.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RenewError {
    /// Requested hostname was not found in the certificate store.
    #[error("Certificate for hostname '{0}' not found in store")]
    NotFound(String),
    /// Renewal request was rejected due to backoff rate limiting.
    #[error("Rate limited: retry for hostname '{name}' allowed after {retry_at}")]
    RateLimited { name: String, retry_at: i64 },
    /// Renewal request was rejected because the global order limit has been reached.
    #[error("Global in-flight ACME order limit reached (4 concurrent orders)")]
    CapacityExceeded,
    /// Store or ACME error.
    #[error("Store error: {0}")]
    Store(String),
}

use crate::config::Config;
use crate::notify::notify_cert_status;
use crate::store::Store;

/// High-level certificate manager daemon for the single wildcard certificate.
///
/// Coordinates:
/// - Eager initial issuance of `[<root>, *.<root>]` at startup
/// - Waiting for that certificate during service registration (`ensure`)
/// - Deduplication of concurrent waiters
/// - Certificate state tracking (`Pending`, `Ordering`, `Issued`, `Failed`, `Renewing`)
/// - Systemd status mirroring for the root domain
/// - Background renewal loop (every 12 hours) with exponential backoff on failure
///
/// Unlike the old per-name model there is exactly one certificate; a renewal
/// swaps it in atomically, and a failure near expiry takes every tunnel down
/// with it. That blast radius is the deliberate cost of keeping service names
/// out of Certificate Transparency, and is what the WARN/ERROR alerts target.
pub struct CertManager {
    config: Arc<Config>,
    store: Arc<Store>,
    clock: Arc<dyn Clock>,
    resolver: Arc<CertResolver>,
    acme_engine: Arc<AcmeEngine>,
    states: RwLock<HashMap<String, CertState>>,
    /// Hostnames with a live or recently-live tunnel. Kept only for the
    /// control surface; it never gates renewal — the wildcard must be valid
    /// unconditionally.
    active_hosts: RwLock<HashSet<String>>,
    failure_counts: RwLock<HashMap<String, u32>>,
    order_semaphore: Arc<Semaphore>,
    in_flight: Mutex<HashMap<String, broadcast::Sender<Result<(), String>>>>,
    state_change_tx: broadcast::Sender<(String, CertState)>,
}

impl CertManager {
    /// Creates a new `CertManager` daemon instance.
    pub fn new(
        config: Arc<Config>,
        store: Arc<Store>,
        resolver: Arc<CertResolver>,
        clock: Arc<dyn Clock>,
    ) -> Arc<Self> {
        let acme_engine = Arc::new(AcmeEngine::new(
            Arc::clone(&config),
            Arc::clone(&store),
            Arc::clone(&clock),
        ));

        let (state_change_tx, _) = broadcast::channel(128);

        Arc::new(Self {
            config,
            store,
            clock,
            resolver,
            acme_engine,
            states: RwLock::new(HashMap::new()),
            active_hosts: RwLock::new(HashSet::new()),
            failure_counts: RwLock::new(HashMap::new()),
            order_semaphore: Arc::new(Semaphore::new(4)),
            in_flight: Mutex::new(HashMap::new()),
            state_change_tx,
        })
    }

    /// The wildcard certificate name (the zone apex), lowercased.
    fn root_name(&self) -> String {
        self.config.root_domain.to_ascii_lowercase()
    }

    /// Initializes the cached wildcard certificate from the store and marks
    /// handshakes as held if none is valid.
    pub async fn init(self: &Arc<Self>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let root = self.root_name();

        let certs = self.store.list_best_certificates_full().await?;
        let now = self.clock.now_unix();
        let mut root_valid = false;

        for cert in certs {
            let lower = cert.name.to_ascii_lowercase();
            if lower != root {
                // Legacy or foreign rows cannot be served: the resolver only
                // maps SNI onto the apex and its wildcard.
                continue;
            }

            if cert.not_after > now {
                match parse_certified_key(&cert.cert_pem, &cert.key_pem) {
                    Ok(certified_key) => {
                        self.resolver.insert_cert_with_expiry(
                            &lower,
                            certified_key,
                            cert.not_after,
                        );
                        self.set_state(
                            &lower,
                            CertState::Issued {
                                not_after: cert.not_after,
                            },
                        );
                        root_valid = true;
                        info!(
                            hostname = %lower,
                            expires_at = %format_unix_timestamp(cert.not_after),
                            "Loaded valid wildcard TLS certificate from database"
                        );
                    }
                    Err(err) => {
                        warn!(name = %lower, error = %err, "Failed to parse cached certificate from database");
                    }
                }
            } else {
                debug!(name = %lower, not_after = cert.not_after, now, "Cached certificate has expired");
            }
        }

        if !root_valid {
            info!(
                root_domain = %root,
                "No valid cached wildcard certificate found; holding incoming handshakes while initiating eager ACME issuance"
            );
            self.set_state(&root, CertState::Pending);
            self.resolver.mark_ordering(&root);
        }

        Ok(())
    }

    /// Spawns background eager issuance for the wildcard if it is `Pending`.
    pub fn spawn_eager_order_if_pending(self: &Arc<Self>) {
        let root = self.root_name();
        let is_pending = {
            let states = self.states.read().unwrap();
            matches!(states.get(&root), Some(CertState::Pending))
        };

        if is_pending {
            let manager = Arc::clone(self);
            tokio::spawn(async move {
                debug!(root_domain = %root, "Spawning eager wildcard ACME order");
                if let Err(err) = manager.ensure(&root).await {
                    warn!(root_domain = %root, error = %err, "Initial wildcard issuance failed");
                }
            });
        }
    }

    /// Waits (bounded) for the wildcard certificate to be valid.
    ///
    /// Any hostname under the root is covered by the same certificate, so this
    /// resolves `name` to the apex and either returns immediately or joins the
    /// in-flight order.
    pub async fn ensure(self: &Arc<Self>, name: &str) -> Result<(), AcmeError> {
        let root = self.root_name();
        // Keep the display-only activity set truthful even though it no longer
        // affects renewal.
        self.set_active(&root, true);
        if !name.eq_ignore_ascii_case(&root) {
            self.set_active(name, true);
        }

        if let Some(CertState::Issued { not_after }) =
            self.states.read().unwrap().get(&root).cloned()
            && not_after > self.clock.now_unix()
        {
            return Ok(());
        }

        let mut rx = {
            let mut in_flight = self.in_flight.lock().await;
            if let Some(tx) = in_flight.get(&root) {
                tx.subscribe()
            } else {
                let (tx, _) = broadcast::channel(1);
                in_flight.insert(root.clone(), tx);
                drop(in_flight);
                return self.execute_issuance(root).await;
            }
        };

        match tokio::time::timeout(CERT_WAIT_TIMEOUT, rx.recv()).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(err))) => Err(AcmeError::Other(err)),
            Ok(Err(_)) => Err(AcmeError::Other("In-flight order channel closed".into())),
            Err(_) => Err(AcmeError::Other(
                "Timed out waiting for the wildcard certificate".into(),
            )),
        }
    }

    /// Internal execution of the single wildcard ACME order.
    async fn execute_issuance(self: &Arc<Self>, root: String) -> Result<(), AcmeError> {
        let is_renewing = matches!(
            self.status(&root),
            CertState::Renewing { not_after } if not_after > self.clock.now_unix()
        );

        if !is_renewing {
            self.set_state(&root, CertState::Ordering);
            self.resolver.mark_ordering(&root);
            let _ = notify_cert_status("ordering");
        } else {
            let _ = notify_cert_status("renewing");
        }

        let _permit = self
            .order_semaphore
            .acquire()
            .await
            .map_err(|e| AcmeError::Other(format!("Semaphore error: {e}")))?;

        info!(root_domain = %root, "Initiating wildcard ACME certificate order");

        let issue_result = self.acme_engine.issue_wildcard(&root).await;

        match issue_result {
            Ok(cert) => {
                let certified_key = parse_certified_key(&cert.cert_pem, &cert.key_pem)
                    .map_err(|e| AcmeError::Other(format!("Failed to parse issued key: {e}")))?;

                // Atomic swap: the resolver replaces the cached key only when
                // the new one is at least as new, so live handshakes keep
                // being served throughout a renewal.
                self.resolver.insert_cert(&root, certified_key);
                self.set_state(
                    &root,
                    CertState::Issued {
                        not_after: cert.not_after,
                    },
                );
                self.failure_counts.write().unwrap().remove(&root);

                info!(
                    root_domain = %root,
                    valid_from = %format_unix_timestamp(cert.not_before),
                    valid_until = %format_unix_timestamp(cert.not_after),
                    "Wildcard certificate issued and active in TLS resolver"
                );
                let _ = notify_cert_status("issued");

                let mut in_flight = self.in_flight.lock().await;
                if let Some(tx) = in_flight.remove(&root) {
                    let _ = tx.send(Ok(()));
                }
                Ok(())
            }
            Err(err) => {
                self.resolver.clear_ordering(&root);

                let count = {
                    let mut counts = self.failure_counts.write().unwrap();
                    let c = counts.entry(root.clone()).or_insert(0);
                    *c += 1;
                    *c
                };

                let retry_after = match &err {
                    AcmeError::RateLimited {
                        retry_after_secs, ..
                    } => *retry_after_secs,
                    _ => None,
                };

                let backoff = compute_backoff(count, retry_after);
                let next_retry = self.clock.now_unix() + backoff.as_secs() as i64;

                self.set_state(
                    &root,
                    CertState::Failed {
                        error: err.to_string(),
                        next_retry,
                    },
                );
                let _ = notify_cert_status("failed");

                error!(
                    root_domain = %root,
                    error = %err,
                    retry_at = %format_unix_timestamp(next_retry),
                    "Wildcard certificate issuance failed; all tunnels will be without a valid certificate until it succeeds"
                );

                let _ = record_cert_event(
                    &self.store,
                    &root,
                    self.clock.now_unix(),
                    "failed",
                    Some(&err.to_string()),
                )
                .await;

                let mut in_flight = self.in_flight.lock().await;
                if let Some(tx) = in_flight.remove(&root) {
                    let _ = tx.send(Err(err.to_string()));
                }

                Err(err)
            }
        }
    }

    /// Sets the display-only active status for a hostname.
    pub fn set_active(&self, name: &str, active: bool) {
        let lower = name.to_ascii_lowercase();
        let now = self.clock.now_unix();

        if active {
            self.active_hosts.write().unwrap().insert(lower.clone());
        } else {
            self.active_hosts.write().unwrap().remove(&lower);
        }

        let store = self.store.clone();
        let active_at = active.then_some(now);
        tokio::spawn(async move {
            if let Err(err) = store.set_cert_active(&lower, active_at).await {
                warn!(hostname = %lower, error = %err, "Failed to persist certificate active flag");
            }
        });
    }

    /// Returns true if `name` is currently marked as active.
    pub fn is_active(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        self.active_hosts.read().unwrap().contains(&lower)
    }

    /// Retrieves the current certificate state for a hostname.
    pub fn status(&self, name: &str) -> CertState {
        let lower = if name.eq_ignore_ascii_case(&self.root_name()) {
            self.root_name()
        } else {
            name.to_ascii_lowercase()
        };
        self.states
            .read()
            .unwrap()
            .get(&lower)
            .cloned()
            .unwrap_or(CertState::Pending)
    }

    /// Sets the certificate state for a hostname and broadcasts the transition.
    pub fn set_state(&self, name: &str, state: CertState) {
        let lower = name.to_ascii_lowercase();
        self.states
            .write()
            .unwrap()
            .insert(lower.clone(), state.clone());
        let _ = self.state_change_tx.send((lower, state));
    }

    /// Subscribes to certificate lifecycle state transitions.
    pub fn subscribe_state_changes(&self) -> broadcast::Receiver<(String, CertState)> {
        self.state_change_tx.subscribe()
    }

    /// Certificate counts for the control surface, over the single wildcard.
    pub async fn cert_counts(&self) -> crate::control::protocol::CertCounts {
        let root = self.root_name();
        let mut counts = crate::control::protocol::CertCounts::default();

        if self.is_active(&root) {
            match self.status(&root) {
                CertState::Issued { .. } | CertState::Renewing { .. } => counts.issued += 1,
                CertState::Ordering | CertState::Pending => counts.ordering += 1,
                CertState::Failed { .. } => counts.failed += 1,
            }
        } else {
            counts.inactive += 1;
        }

        counts
    }

    /// Manually triggers renewal of the wildcard certificate.
    ///
    /// Any hostname is accepted and mapped to the apex; the wildcard covers
    /// them all. Respects the backoff and in-flight cap unless `force`.
    pub async fn renew_hostname(
        self: &Arc<Self>,
        _name: &str,
        force: bool,
    ) -> Result<(), RenewError> {
        let root = self.root_name();

        if !force {
            if let CertState::Failed { next_retry, .. } = self.status(&root) {
                let now = self.clock.now_unix();
                if now < next_retry {
                    return Err(RenewError::RateLimited {
                        name: root,
                        retry_at: next_retry,
                    });
                }
            }

            if self.order_semaphore.available_permits() == 0 {
                return Err(RenewError::CapacityExceeded);
            }
        }

        let not_after = match self.status(&root) {
            CertState::Issued { not_after } | CertState::Renewing { not_after } => not_after,
            _ => 0,
        };

        if not_after > 0 {
            self.set_state(&root, CertState::Renewing { not_after });
        } else {
            self.set_state(&root, CertState::Ordering);
        }

        let mgr = Arc::clone(self);
        let target = root.clone();
        tokio::spawn(async move {
            if let Err(err) = mgr.execute_issuance(target.clone()).await {
                warn!(root_domain = %target, error = %err, "Manual wildcard renewal failed");
            }
        });

        Ok(())
    }

    /// Triggers renewal of the wildcard certificate.
    pub async fn renew_all(
        self: &Arc<Self>,
        force: bool,
    ) -> Result<crate::control::protocol::RenewResponse, RenewError> {
        let root = self.root_name();
        self.renew_hostname(&root, force).await?;
        Ok(crate::control::protocol::RenewResponse {
            ok: true,
            renewed: vec![root],
            status: "queued".to_string(),
            skipped_inactive: Vec::new(),
        })
    }

    /// Returns a snapshot of all tracked certificate states.
    pub fn list_states(&self) -> HashMap<String, CertState> {
        self.states.read().unwrap().clone()
    }

    /// Returns the current state label for the root domain ("pending", "ordering", "issued", etc.).
    pub fn root_cert_status(&self) -> &'static str {
        let root = self.root_name();
        self.status(&root).label()
    }

    /// Renews the wildcard if it is within the renewal window (< 1/3 lifetime).
    ///
    /// There is no active-host gating: an idle relay must still hold a valid
    /// wildcard so a tunnel can be served the moment it registers.
    pub async fn renew_eligible(self: &Arc<Self>) -> Vec<Result<String, String>> {
        let root = self.root_name();
        let now = self.clock.now_unix();

        let cert = match self.store.get_certificate(&root).await {
            Ok(Some(c)) => c,
            Ok(None) => {
                warn!(root_domain = %root, "No stored wildcard certificate to renew");
                return Vec::new();
            }
            Err(e) => {
                error!(error = %e, "Failed to query wildcard certificate for renewal");
                return vec![Err(e.to_string())];
            }
        };

        if !should_renew(cert.not_before, cert.not_after, now) {
            return Vec::new();
        }

        info!(
            root_domain = %root,
            not_before = cert.not_before,
            not_after = cert.not_after,
            now,
            "Renewing wildcard certificate"
        );

        self.set_state(
            &root,
            CertState::Renewing {
                not_after: cert.not_after,
            },
        );
        let _ = notify_cert_status("renewing");

        match self.execute_issuance(root.clone()).await {
            Ok(()) => {
                let _ =
                    record_cert_event(&self.store, &root, self.clock.now_unix(), "renewed", None)
                        .await;
                vec![Ok(root)]
            }
            Err(e) => {
                let remaining = cert.not_after.saturating_sub(now);
                error!(
                    root_domain = %root,
                    error = %e,
                    expires_in_secs = remaining,
                    "Wildcard certificate renewal failed; service will hard-fail at expiry if it does not recover"
                );
                vec![Err(format!("Renewal for {root} failed: {e}"))]
            }
        }
    }

    /// Spawns the background renewal loop task running every 12 hours (+ jitter).
    pub fn start_renewal_loop(self: &Arc<Self>, shutdown_token: CancellationToken) {
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            info!("Certificate renewal background loop started");
            let mut interval = tokio::time::interval(Duration::from_secs(12 * 3600));

            loop {
                tokio::select! {
                    _ = shutdown_token.cancelled() => {
                        info!("Certificate renewal loop received cancellation, shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        debug!("Executing scheduled certificate renewal tick");
                        let _ = manager.renew_eligible().await;
                    }
                }
            }
        });
    }

    /// Returns a reference to the dynamic certificate resolver.
    pub fn resolver(&self) -> Arc<CertResolver> {
        Arc::clone(&self.resolver)
    }
}
