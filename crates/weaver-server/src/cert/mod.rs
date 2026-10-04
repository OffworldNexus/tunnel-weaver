//! Certificate management daemon, resolvers, and ACME coordination.

pub mod acme;
pub mod clock;
pub mod events;
pub mod providers;
pub mod renewal;
pub mod resolver;
pub mod solver;
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
use crate::zone::{CertKind, Zone};

/// High-level certificate manager daemon for the relay's managed certificates.
///
/// Coordinates:
/// - Eager initial issuance of the tunnel wildcard `[<root>, *.<root>]`
///   (DNS-01) and the single-name admin certificate (HTTP-01)
/// - Waiting for the covering certificate during service registration (`ensure`)
/// - Deduplication of concurrent waiters
/// - Certificate state tracking (`Pending`, `Ordering`, `Issued`, `Failed`, `Renewing`)
/// - Systemd status mirroring for the tunnel domain
/// - Background renewal loop (every 12 hours) with exponential backoff on failure
///
/// The tunnel wildcard covers every tunnel hostname, so a wildcard renewal
/// swaps it in atomically and a failure near expiry takes every tunnel down
/// with it. That blast radius is the deliberate cost of keeping service names
/// out of Certificate Transparency, and is what the WARN/ERROR alerts target.
/// The admin certificate is independent: its failure affects only the relay's
/// own endpoint.
pub struct CertManager {
    store: Arc<Store>,
    clock: Arc<dyn Clock>,
    resolver: Arc<CertResolver>,
    acme_engine: Arc<AcmeEngine>,
    /// The relay's serving area: maps a hostname to the one managed
    /// certificate that covers it, and names each certificate's store key.
    zone: Zone,
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

        let zone = Zone::new(&config.root_domain, &config.admin_domain);
        Arc::new(Self {
            store,
            clock,
            resolver,
            acme_engine,
            zone,
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
        self.zone.root().to_string()
    }

    /// The admin certificate name (the relay's own hostname), lowercased.
    fn admin_name(&self) -> String {
        self.zone.admin().to_string()
    }

    /// Resolves a hostname to the certificate name that covers it.
    ///
    /// The admin certificate covers exactly the admin domain; the tunnel
    /// wildcard covers the apex and exactly one label beneath it. Returns
    /// `None` for hostnames no managed certificate covers.
    pub fn cert_name_for(&self, host: &str) -> Option<String> {
        self.zone.cert_name_for(host)
    }

    /// Initializes the cached certificates from the store and marks handshakes
    /// as held for any managed certificate without a valid row.
    pub async fn init(self: &Arc<Self>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let admin = self.admin_name();
        let root = self.root_name();

        let certs = self.store.list_certificates_full().await?;
        let now = self.clock.now_unix();
        let mut valid: HashSet<String> = HashSet::new();

        for cert in certs {
            let lower = cert.name.to_ascii_lowercase();
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
                        valid.insert(lower.clone());
                        info!(
                            hostname = %lower,
                            expires_at = %format_unix_timestamp(cert.not_after),
                            "Loaded valid TLS certificate from database"
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

        for name in [&admin, &root] {
            if !valid.contains(name) {
                info!(
                    hostname = %name,
                    "No valid cached certificate found; holding incoming handshakes while initiating eager ACME issuance"
                );
                self.set_state(name, CertState::Pending);
                self.resolver.mark_ordering(name);
            }
        }

        Ok(())
    }

    /// Spawns background eager issuance for any managed certificate that is
    /// still `Pending` (fresh install, or a cache miss after an outage).
    pub fn spawn_eager_order_if_pending(self: &Arc<Self>) {
        for name in [self.root_name(), self.admin_name()] {
            let is_pending = {
                let states = self.states.read().unwrap();
                matches!(states.get(&name), Some(CertState::Pending))
            };

            if is_pending {
                let manager = Arc::clone(self);
                tokio::spawn(async move {
                    debug!(hostname = %name, "Spawning eager ACME order");
                    if let Err(err) = manager.ensure(&name).await {
                        warn!(hostname = %name, error = %err, "Initial ACME issuance failed");
                    }
                });
            }
        }
    }

    /// Waits (bounded) for the certificate covering `name` to be valid.
    ///
    /// `name` is resolved to its covering certificate — the admin name exactly,
    /// or the tunnel apex for any flat tunnel hostname — and the caller either
    /// returns immediately or joins that certificate's in-flight order.
    pub async fn ensure(self: &Arc<Self>, name: &str) -> Result<(), AcmeError> {
        let Some(cert_name) = self.cert_name_for(name) else {
            return Err(AcmeError::Other(format!(
                "Hostname '{name}' is not covered by a managed certificate"
            )));
        };

        // Keep the display-only activity set truthful even though it no longer
        // affects renewal.
        self.set_active(&cert_name, true);
        if !name.eq_ignore_ascii_case(&cert_name) {
            self.set_active(name, true);
        }

        if let Some(CertState::Issued { not_after }) =
            self.states.read().unwrap().get(&cert_name).cloned()
            && not_after > self.clock.now_unix()
        {
            return Ok(());
        }

        let mut rx = {
            let mut in_flight = self.in_flight.lock().await;
            if let Some(tx) = in_flight.get(&cert_name) {
                tx.subscribe()
            } else {
                let (tx, _) = broadcast::channel(1);
                in_flight.insert(cert_name.clone(), tx);
                drop(in_flight);
                return self.execute_issuance(cert_name).await;
            }
        };

        match tokio::time::timeout(CERT_WAIT_TIMEOUT, rx.recv()).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(err))) => Err(AcmeError::Other(err)),
            Ok(Err(_)) => Err(AcmeError::Other("In-flight order channel closed".into())),
            Err(_) => Err(AcmeError::Other(
                "Timed out waiting for the certificate".into(),
            )),
        }
    }

    /// Records a visitor touch for `host` and kicks issuance when the covering
    /// certificate is missing or inside its renewal window.
    ///
    /// Called from the HTTPS edge on the request path, so it must never block
    /// the visitor: all work runs in a spawned task. Rate limiting reuses the
    /// existing `CertState::Failed` backoff and [`ensure`](Self::ensure)'s
    /// in-flight dedup, so a trickle of visits cannot stampede the CA. The 12 h
    /// loop remains the floor; this only shortens the worst case after an outage
    /// or an early-expiry scare.
    pub fn note_visit(self: &Arc<Self>, host: &str) {
        let Some(cert_name) = self.cert_name_for(host) else {
            return;
        };
        let manager = Arc::clone(self);
        let host = host.to_ascii_lowercase();
        tokio::spawn(async move {
            let now = manager.clock.now_unix();
            let _ = record_cert_event(&manager.store, &cert_name, now, "visit", Some(&host)).await;

            match manager.status(&cert_name) {
                // A live order already covers this host.
                CertState::Ordering | CertState::Renewing { .. } => {}
                // Respect the backoff before retrying a failed order.
                CertState::Failed { next_retry, .. } => {
                    if now >= next_retry
                        && let Err(err) = manager.ensure(&cert_name).await
                    {
                        debug!(hostname = %cert_name, error = %err, "Visitor-triggered issuance did not complete");
                    }
                }
                CertState::Issued { not_after } if not_after <= now => {
                    if let Err(err) = manager.ensure(&cert_name).await {
                        debug!(hostname = %cert_name, error = %err, "Visitor-triggered re-issuance did not complete");
                    }
                }
                CertState::Issued { .. } => {
                    // Valid but possibly inside the renewal window. `ensure`
                    // would return immediately, so drive an actual renewal.
                    if let Ok(Some(cert)) = manager.store.get_certificate(&cert_name).await
                        && should_renew(cert.not_before, cert.not_after, now)
                        && let Err(err) = manager.renew_hostname(&cert_name, false).await
                    {
                        debug!(hostname = %cert_name, error = %err, "Visitor-triggered renewal did not start");
                    }
                }
                CertState::Pending => {
                    if let Err(err) = manager.ensure(&cert_name).await {
                        debug!(hostname = %cert_name, error = %err, "Visitor-triggered issuance did not complete");
                    }
                }
            }
        });
    }

    /// Internal execution of one certificate's ACME order.
    ///
    /// Dispatches on the name: the admin certificate uses HTTP-01, the tunnel
    /// wildcard uses DNS-01.
    async fn execute_issuance(self: &Arc<Self>, cert_name: String) -> Result<(), AcmeError> {
        let is_admin = matches!(self.zone.kind_of(&cert_name), CertKind::Admin);

        let is_renewing = matches!(
            self.status(&cert_name),
            CertState::Renewing { not_after } if not_after > self.clock.now_unix()
        );

        if !is_renewing {
            self.set_state(&cert_name, CertState::Ordering);
            self.resolver.mark_ordering(&cert_name);
            let _ = notify_cert_status("ordering");
        } else {
            let _ = notify_cert_status("renewing");
        }

        let _permit = self
            .order_semaphore
            .acquire()
            .await
            .map_err(|e| AcmeError::Other(format!("Semaphore error: {e}")))?;

        info!(
            hostname = %cert_name,
            mechanism = if is_admin { "http-01" } else { "dns-01" },
            "Initiating ACME certificate order"
        );

        let issue_result = if is_admin {
            self.acme_engine.issue_admin(&cert_name).await
        } else {
            self.acme_engine.issue_wildcard(&cert_name).await
        };

        match issue_result {
            Ok(cert) => {
                let certified_key = parse_certified_key(&cert.cert_pem, &cert.key_pem)
                    .map_err(|e| AcmeError::Other(format!("Failed to parse issued key: {e}")))?;

                // Atomic swap: the resolver replaces the cached key only when
                // the new one is at least as new, so live handshakes keep
                // being served throughout a renewal.
                self.resolver.insert_cert(&cert_name, certified_key);
                self.set_state(
                    &cert_name,
                    CertState::Issued {
                        not_after: cert.not_after,
                    },
                );
                self.failure_counts.write().unwrap().remove(&cert_name);

                info!(
                    hostname = %cert_name,
                    valid_from = %format_unix_timestamp(cert.not_before),
                    valid_until = %format_unix_timestamp(cert.not_after),
                    "Certificate issued and active in TLS resolver"
                );
                let _ = notify_cert_status("issued");

                let mut in_flight = self.in_flight.lock().await;
                if let Some(tx) = in_flight.remove(&cert_name) {
                    let _ = tx.send(Ok(()));
                }
                Ok(())
            }
            Err(err) => {
                self.resolver.clear_ordering(&cert_name);

                let count = {
                    let mut counts = self.failure_counts.write().unwrap();
                    let c = counts.entry(cert_name.clone()).or_insert(0);
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
                    &cert_name,
                    CertState::Failed {
                        error: err.to_string(),
                        next_retry,
                    },
                );
                let _ = notify_cert_status("failed");

                error!(
                    hostname = %cert_name,
                    error = %err,
                    retry_at = %format_unix_timestamp(next_retry),
                    "Certificate issuance failed; affected hostnames will be without a valid certificate until it succeeds"
                );

                let _ = record_cert_event(
                    &self.store,
                    &cert_name,
                    self.clock.now_unix(),
                    "failed",
                    Some(&err.to_string()),
                )
                .await;

                let mut in_flight = self.in_flight.lock().await;
                if let Some(tx) = in_flight.remove(&cert_name) {
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
            if let Err(err) = store.set_domain_active(&lower, active_at).await {
                warn!(hostname = %lower, error = %err, "Failed to persist certificate active flag");
            }
        });
    }

    /// Returns true if `name` is currently marked as active.
    pub fn is_active(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        self.active_hosts.read().unwrap().contains(&lower)
    }

    /// Retrieves the current certificate state for a hostname, resolving it to
    /// the certificate that covers it (so a flat tunnel hostname reports the
    /// state of the tunnel wildcard).
    pub fn status(&self, name: &str) -> CertState {
        let key = self
            .cert_name_for(name)
            .unwrap_or_else(|| name.to_ascii_lowercase());
        self.states
            .read()
            .unwrap()
            .get(&key)
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

    /// Certificate counts for the control surface, over both managed
    /// certificates (tunnel wildcard and admin).
    pub async fn cert_counts(&self) -> crate::control::protocol::CertCounts {
        let mut counts = crate::control::protocol::CertCounts::default();

        for name in [self.root_name(), self.admin_name()] {
            if self.is_active(&name) {
                match self.status(&name) {
                    CertState::Issued { .. } | CertState::Renewing { .. } => counts.issued += 1,
                    CertState::Ordering | CertState::Pending => counts.ordering += 1,
                    CertState::Failed { .. } => counts.failed += 1,
                }
            } else {
                counts.inactive += 1;
            }
        }

        counts
    }

    /// Manually triggers renewal of the certificate covering `name`.
    ///
    /// Any hostname is mapped to its covering certificate (admin exact, tunnel
    /// apex for a flat name). Respects the backoff and in-flight cap unless
    /// `force`.
    pub async fn renew_hostname(
        self: &Arc<Self>,
        name: &str,
        force: bool,
    ) -> Result<(), RenewError> {
        let Some(cert_name) = self.cert_name_for(name) else {
            return Err(RenewError::NotFound(name.to_string()));
        };

        if !force {
            if let CertState::Failed { next_retry, .. } = self.status(&cert_name) {
                let now = self.clock.now_unix();
                if now < next_retry {
                    return Err(RenewError::RateLimited {
                        name: cert_name,
                        retry_at: next_retry,
                    });
                }
            }

            if self.order_semaphore.available_permits() == 0 {
                return Err(RenewError::CapacityExceeded);
            }
        }

        let not_after = match self.status(&cert_name) {
            CertState::Issued { not_after } | CertState::Renewing { not_after } => not_after,
            _ => 0,
        };

        if not_after > 0 {
            self.set_state(&cert_name, CertState::Renewing { not_after });
        } else {
            self.set_state(&cert_name, CertState::Ordering);
        }

        let mgr = Arc::clone(self);
        let target = cert_name.clone();
        tokio::spawn(async move {
            if let Err(err) = mgr.execute_issuance(target.clone()).await {
                warn!(hostname = %target, error = %err, "Manual certificate renewal failed");
            }
        });

        Ok(())
    }

    /// Triggers renewal of both managed certificates.
    pub async fn renew_all(
        self: &Arc<Self>,
        force: bool,
    ) -> Result<crate::control::protocol::RenewResponse, RenewError> {
        let names = [self.admin_name(), self.root_name()];
        for name in &names {
            self.renew_hostname(name, force).await?;
        }
        Ok(crate::control::protocol::RenewResponse {
            ok: true,
            renewed: names.to_vec(),
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

    /// Renews either managed certificate if it is within the renewal window
    /// (< 1/3 lifetime).
    ///
    /// There is no active-host gating: an idle relay must still hold a valid
    /// wildcard (and admin certificate) so a tunnel can be served the moment it
    /// registers.
    pub async fn renew_eligible(self: &Arc<Self>) -> Vec<Result<String, String>> {
        let now = self.clock.now_unix();
        let mut results = Vec::new();

        for cert_name in [self.admin_name(), self.root_name()] {
            let cert = match self.store.get_certificate(&cert_name).await {
                Ok(Some(c)) => c,
                Ok(None) => {
                    warn!(hostname = %cert_name, "No stored certificate to renew");
                    continue;
                }
                Err(e) => {
                    error!(hostname = %cert_name, error = %e, "Failed to query certificate for renewal");
                    results.push(Err(e.to_string()));
                    continue;
                }
            };

            if !should_renew(cert.not_before, cert.not_after, now) {
                continue;
            }

            info!(
                hostname = %cert_name,
                not_before = cert.not_before,
                not_after = cert.not_after,
                now,
                "Renewing certificate"
            );

            self.set_state(
                &cert_name,
                CertState::Renewing {
                    not_after: cert.not_after,
                },
            );
            let _ = notify_cert_status("renewing");

            match self.execute_issuance(cert_name.clone()).await {
                Ok(()) => {
                    let _ = record_cert_event(
                        &self.store,
                        &cert_name,
                        self.clock.now_unix(),
                        "renewed",
                        None,
                    )
                    .await;
                    results.push(Ok(cert_name));
                }
                Err(e) => {
                    let remaining = cert.not_after.saturating_sub(now);
                    error!(
                        hostname = %cert_name,
                        error = %e,
                        expires_in_secs = remaining,
                        "Certificate renewal failed; service will hard-fail at expiry if it does not recover"
                    );
                    results.push(Err(format!("Renewal for {cert_name} failed: {e}")));
                }
            }
        }

        results
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
