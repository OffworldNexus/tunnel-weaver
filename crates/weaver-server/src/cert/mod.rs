//! Certificate management daemon, resolvers, challenge responders, and ACME coordination.

pub mod acme;
pub mod challenge;
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

pub use acme::{AcmeEngine, AcmeError, IssuedCertificate, parse_cert_validity};
pub use challenge::{ChallengeRegistry, create_tls_alpn_01_certified_key};
pub use clock::{Clock, MockClock, SystemClock, format_unix_timestamp};
pub use events::record_cert_event;
pub use renewal::{compute_backoff, should_renew};
pub use resolver::{CertResolver, parse_certified_key};
pub use state::CertState;

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

/// High-level certificate manager daemon.
///
/// Coordinates:
/// - Eager initial issuance for `root_domain`
/// - Lazy per-hostname issuance via `ensure(name)`
/// - Deduplication of concurrent in-flight orders for the same hostname
/// - Global concurrency limit (max 4 concurrent in-flight ACME orders)
/// - Per-name state tracking (`Pending`, `Ordering`, `Issued`, `Failed`, `Renewing`)
/// - Systemd status mirroring for the root domain
/// - Background renewal loop (every 12 hours) with exponential backoff on failure
pub struct CertManager {
    config: Arc<Config>,
    store: Arc<Store>,
    clock: Arc<dyn Clock>,
    resolver: Arc<CertResolver>,
    acme_engine: Arc<AcmeEngine>,
    challenge_registry: Arc<ChallengeRegistry>,
    states: RwLock<HashMap<String, CertState>>,
    active_hosts: RwLock<HashSet<String>>,
    failure_counts: RwLock<HashMap<String, u32>>,
    order_semaphore: Arc<Semaphore>,
    in_flight: Mutex<HashMap<String, broadcast::Sender<Result<(), String>>>>,
    state_change_tx: broadcast::Sender<(String, CertState)>,
    is_http_enabled: bool,
}

impl CertManager {
    /// Creates a new `CertManager` daemon instance.
    pub fn new(
        config: Arc<Config>,
        store: Arc<Store>,
        resolver: Arc<CertResolver>,
        challenge_registry: Arc<ChallengeRegistry>,
        clock: Arc<dyn Clock>,
        is_http_enabled: bool,
    ) -> Arc<Self> {
        let acme_engine = Arc::new(AcmeEngine::new(
            Arc::clone(&config),
            Arc::clone(&store),
            Arc::clone(&clock),
            Arc::clone(&challenge_registry),
        ));

        let (state_change_tx, _) = broadcast::channel(128);

        Arc::new(Self {
            config,
            store,
            clock,
            resolver,
            acme_engine,
            challenge_registry,
            states: RwLock::new(HashMap::new()),
            active_hosts: RwLock::new(HashSet::new()),
            failure_counts: RwLock::new(HashMap::new()),
            order_semaphore: Arc::new(Semaphore::new(4)),
            in_flight: Mutex::new(HashMap::new()),
            state_change_tx,
            is_http_enabled,
        })
    }

    /// Initializes cached certificates from SQLite and triggers eager root domain issuance if needed.
    pub fn init(self: &Arc<Self>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let root_domain = self.config.root_domain.to_ascii_lowercase();

        // 1. Read all cached certificates from the database
        let certs = self.store.read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT name, cert_pem, key_pem, not_before, not_after, last_active_at FROM certificates",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                ))
            })?;
            let mut result = Vec::new();
            for r in rows {
                result.push(r?);
            }
            Ok(result)
        })?;

        let now = self.clock.now_unix();
        let mut root_valid = false;

        for (name, cert_pem, key_pem, _not_before, not_after, last_active_at) in certs {
            let lower = name.to_ascii_lowercase();

            if not_after > now {
                match parse_certified_key(&cert_pem, &key_pem) {
                    Ok(certified_key) => {
                        self.resolver.insert_cert(&lower, certified_key);
                        self.set_state(&lower, CertState::Issued { not_after });

                        if last_active_at.is_some() || lower == root_domain {
                            self.active_hosts.write().unwrap().insert(lower.clone());
                        }

                        if lower == root_domain {
                            root_valid = true;
                        }

                        info!(
                            hostname = %lower,
                            expires_at = %format_unix_timestamp(not_after),
                            "Loaded valid TLS certificate from database"
                        );
                    }
                    Err(err) => {
                        warn!(name = %lower, error = %err, "Failed to parse cached certificate from database");
                    }
                }
            } else {
                debug!(name = %lower, not_after, now, "Cached certificate has expired");
            }
        }

        // 2. If root domain has no valid cached certificate, mark Pending and ordering in resolver
        if !root_valid {
            info!(
                root_domain = %root_domain,
                "No valid cached root certificate found; holding incoming handshakes while initiating eager ACME issuance"
            );

            self.set_state(&root_domain, CertState::Pending);
            self.resolver.mark_ordering(&root_domain);
        }

        Ok(())
    }

    /// Spawns background eager issuance for the root domain if it is in the `Pending` state.
    pub fn spawn_eager_order_if_pending(self: &Arc<Self>) {
        let root_domain = self.config.root_domain.to_ascii_lowercase();
        let is_pending = {
            let states = self.states.read().unwrap();
            matches!(states.get(&root_domain), Some(CertState::Pending))
        };

        if is_pending {
            let manager = Arc::clone(self);
            let root_name = root_domain.clone();
            tokio::spawn(async move {
                debug!(root_domain = %root_name, "Spawning eager root domain ACME order");
                if let Err(err) = manager.ensure(&root_name).await {
                    warn!(root_domain = %root_name, error = %err, "Initial root domain issuance failed");
                }
            });
        }
    }

    /// Lazily issues a certificate for `name` if no valid certificate exists, deduplicating concurrent calls.
    pub async fn ensure(self: &Arc<Self>, name: &str) -> Result<(), AcmeError> {
        let lower = name.to_ascii_lowercase();

        // 1. Mark hostname as active
        self.set_active(&lower, true);

        // 2. Check if valid certificate is already issued
        {
            let states = self.states.read().unwrap();
            if let Some(CertState::Issued { not_after }) = states.get(&lower)
                && *not_after > self.clock.now_unix()
            {
                return Ok(());
            }
        }

        // 3. Deduplicate concurrent issuance requests for the same hostname
        let mut rx = {
            let mut in_flight = self.in_flight.lock().await;
            if let Some(tx) = in_flight.get(&lower) {
                tx.subscribe()
            } else {
                let (tx, _) = broadcast::channel(1);
                in_flight.insert(lower.clone(), tx);
                // We are the leader for this issuance
                drop(in_flight);

                return self.execute_issuance(lower).await;
            }
        };

        // Follower: wait for leader's issuance result
        match rx.recv().await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(AcmeError::Other(err)),
            Err(_) => Err(AcmeError::Other("In-flight order channel closed".into())),
        }
    }

    /// Internal execution of the ACME order under concurrency control.
    async fn execute_issuance(self: &Arc<Self>, lower: String) -> Result<(), AcmeError> {
        let is_root = lower == self.config.root_domain.to_ascii_lowercase();

        let is_renewing = matches!(
            self.status(&lower),
            CertState::Renewing { not_after } if not_after > self.clock.now_unix()
        );

        if !is_renewing {
            // Update state to Ordering and mark resolver to hold in-flight handshakes
            self.set_state(&lower, CertState::Ordering);
            self.resolver.mark_ordering(&lower);
            if is_root {
                let _ = notify_cert_status("ordering");
            }
        } else if is_root {
            // Preserve Renewing state and notify systemd of renewing
            let _ = notify_cert_status("renewing");
        }

        // Acquire global order permit (max 4 concurrent ACME orders)
        let _permit = self
            .order_semaphore
            .acquire()
            .await
            .map_err(|e| AcmeError::Other(format!("Semaphore error: {e}")))?;

        info!(
            hostname = %lower,
            "Initiating ACME certificate order"
        );

        let issue_result = self
            .acme_engine
            .issue_certificate(&lower, self.is_http_enabled)
            .await;

        match issue_result {
            Ok(cert) => {
                let certified_key = parse_certified_key(&cert.cert_pem, &cert.key_pem)
                    .map_err(|e| AcmeError::Other(format!("Failed to parse issued key: {e}")))?;

                self.resolver.insert_cert(&lower, certified_key);
                self.set_state(
                    &lower,
                    CertState::Issued {
                        not_after: cert.not_after,
                    },
                );
                self.failure_counts.write().unwrap().remove(&lower);

                info!(
                    hostname = %lower,
                    valid_from = %format_unix_timestamp(cert.not_before),
                    valid_until = %format_unix_timestamp(cert.not_after),
                    "Certificate issued and active in TLS resolver"
                );

                if is_root {
                    let _ = notify_cert_status("issued");
                }

                // Notify any concurrent callers waiting on this hostname
                let mut in_flight = self.in_flight.lock().await;
                if let Some(tx) = in_flight.remove(&lower) {
                    let _ = tx.send(Ok(()));
                }

                Ok(())
            }
            Err(err) => {
                self.resolver.clear_ordering(&lower);

                // Compute exponential backoff
                let count = {
                    let mut counts = self.failure_counts.write().unwrap();
                    let c = counts.entry(lower.clone()).or_insert(0);
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
                    &lower,
                    CertState::Failed {
                        error: err.to_string(),
                        next_retry,
                    },
                );

                if is_root {
                    let _ = notify_cert_status("failed");
                }

                let _ = record_cert_event(
                    &self.store,
                    &lower,
                    self.clock.now_unix(),
                    "failed",
                    Some(&err.to_string()),
                );

                // Notify in-flight waiters of error
                let mut in_flight = self.in_flight.lock().await;
                if let Some(tx) = in_flight.remove(&lower) {
                    let _ = tx.send(Err(err.to_string()));
                }

                Err(err)
            }
        }
    }

    /// Sets the active status for a hostname.
    ///
    /// Inactive hostnames are skipped by the background renewal loop, allowing their
    /// certificates to expire until re-activated or requested via `ensure`.
    pub fn set_active(&self, name: &str, active: bool) {
        let lower = name.to_ascii_lowercase();
        let now = self.clock.now_unix();

        if active {
            self.active_hosts.write().unwrap().insert(lower.clone());
            let _ = self.store.write(|conn| {
                conn.execute(
                    "UPDATE certificates SET last_active_at = ?1 WHERE name = ?2",
                    rusqlite::params![now, lower],
                )?;
                Ok(())
            });
        } else {
            self.active_hosts.write().unwrap().remove(&lower);
            let _ = self.store.write(|conn| {
                conn.execute(
                    "UPDATE certificates SET last_active_at = NULL WHERE name = ?2",
                    rusqlite::params![lower],
                )?;
                Ok(())
            });
        }
    }

    /// Returns true if `name` is currently marked as active.
    pub fn is_active(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        self.active_hosts.read().unwrap().contains(&lower)
    }

    /// Retrieves the current certificate state for a hostname.
    pub fn status(&self, name: &str) -> CertState {
        let lower = name.to_ascii_lowercase();
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

    /// Computes per-name certificate counts partitioned mutually exclusively:
    /// inactive names count under `inactive`; active names partition into
    /// `issued`, `ordering`, or `failed`.
    pub fn cert_counts(&self) -> crate::control::protocol::CertCounts {
        let root_domain = self.config.root_domain.to_ascii_lowercase();
        let mut all_names = HashSet::new();
        all_names.insert(root_domain);

        if let Ok(certs) = self.store.list_certificates() {
            for c in certs {
                all_names.insert(c.name.to_ascii_lowercase());
            }
        }

        {
            let states = self.states.read().unwrap();
            for name in states.keys() {
                all_names.insert(name.clone());
            }
        }

        let mut counts = crate::control::protocol::CertCounts::default();

        for name in all_names {
            if !self.is_active(&name) {
                counts.inactive += 1;
            } else {
                let state = self.status(&name);
                match state {
                    CertState::Issued { .. } | CertState::Renewing { .. } => counts.issued += 1,
                    CertState::Ordering | CertState::Pending => counts.ordering += 1,
                    CertState::Failed { .. } => counts.failed += 1,
                }
            }
        }

        counts
    }

    /// Manually triggers renewal for a specific hostname (or root domain).
    ///
    /// Respects the rate-limit backoff and global in-flight cap unless `force` is true.
    /// Inactive hostnames are permitted if explicitly named.
    pub async fn renew_hostname(
        self: &Arc<Self>,
        name: &str,
        force: bool,
    ) -> Result<(), RenewError> {
        let root_domain = self.config.root_domain.to_ascii_lowercase();
        let lower = if name == "root" {
            root_domain.clone()
        } else {
            name.to_ascii_lowercase()
        };

        // Check if certificate exists in configuration, memory states, or DB store
        let exists = lower == root_domain
            || self.states.read().unwrap().contains_key(&lower)
            || self
                .store
                .get_certificate(&lower)
                .map_err(|e| RenewError::Store(e.to_string()))?
                .is_some();

        if !exists {
            return Err(RenewError::NotFound(lower));
        }

        if !force {
            // Check rate limits
            let state = self.status(&lower);
            if let CertState::Failed { next_retry, .. } = state {
                let now = self.clock.now_unix();
                if now < next_retry {
                    return Err(RenewError::RateLimited {
                        name: lower,
                        retry_at: next_retry,
                    });
                }
            }

            // Check global in-flight cap (4)
            if self.order_semaphore.available_permits() == 0 {
                return Err(RenewError::CapacityExceeded);
            }
        }

        let not_after = match self.status(&lower) {
            CertState::Issued { not_after } | CertState::Renewing { not_after } => not_after,
            _ => 0,
        };

        if not_after > 0 {
            self.set_state(&lower, CertState::Renewing { not_after });
        } else {
            self.set_state(&lower, CertState::Ordering);
        }

        let mgr = Arc::clone(self);
        let target = lower.clone();
        tokio::spawn(async move {
            if let Err(err) = mgr.execute_issuance(target.clone()).await {
                tracing::warn!(hostname = %target, error = %err, "Manual certificate renewal failed");
            }
        });

        Ok(())
    }

    /// Triggers renewal for the root domain and all active hostnames, skipping inactive ones.
    pub async fn renew_all(
        self: &Arc<Self>,
        force: bool,
    ) -> Result<crate::control::protocol::RenewResponse, RenewError> {
        let root_domain = self.config.root_domain.to_ascii_lowercase();
        let mut candidates = HashSet::new();
        candidates.insert(root_domain.clone());

        if let Ok(certs) = self.store.list_certificates() {
            for c in certs {
                candidates.insert(c.name.to_ascii_lowercase());
            }
        }

        {
            let states = self.states.read().unwrap();
            for name in states.keys() {
                candidates.insert(name.clone());
            }
        }

        let mut to_renew = Vec::new();
        let mut skipped = Vec::new();

        for name in candidates {
            if name == root_domain || self.is_active(&name) {
                to_renew.push(name);
            } else {
                skipped.push(name);
            }
        }

        to_renew.sort();
        skipped.sort();

        // Check guards before launching renewals if not forced
        if !force {
            for name in &to_renew {
                let state = self.status(name);
                if let CertState::Failed { next_retry, .. } = state {
                    let now = self.clock.now_unix();
                    if now < next_retry {
                        return Err(RenewError::RateLimited {
                            name: name.clone(),
                            retry_at: next_retry,
                        });
                    }
                }
            }
            if self.order_semaphore.available_permits() == 0 {
                return Err(RenewError::CapacityExceeded);
            }
        }

        for name in &to_renew {
            let not_after = match self.status(name) {
                CertState::Issued { not_after } | CertState::Renewing { not_after } => not_after,
                _ => 0,
            };
            if not_after > 0 {
                self.set_state(name, CertState::Renewing { not_after });
            } else {
                self.set_state(name, CertState::Ordering);
            }

            let mgr = Arc::clone(self);
            let target = name.clone();
            tokio::spawn(async move {
                if let Err(err) = mgr.execute_issuance(target.clone()).await {
                    tracing::warn!(hostname = %target, error = %err, "Batch certificate renewal failed");
                }
            });
        }

        Ok(crate::control::protocol::RenewResponse {
            ok: true,
            renewed: to_renew,
            status: "queued".to_string(),
            skipped_inactive: skipped,
        })
    }

    /// Returns a snapshot of all tracked hostname certificate states.
    pub fn list_states(&self) -> HashMap<String, CertState> {
        self.states.read().unwrap().clone()
    }

    /// Returns the current state label for the root domain ("pending", "ordering", "issued", etc.).
    pub fn root_cert_status(&self) -> &'static str {
        let root_domain = self.config.root_domain.to_ascii_lowercase();
        self.status(&root_domain).label()
    }

    /// Scans tracked certificates and renews eligible hostnames (< 1/3 lifetime remaining).
    pub async fn renew_eligible(self: &Arc<Self>) -> Vec<Result<String, String>> {
        let root_domain = self.config.root_domain.to_ascii_lowercase();
        let now = self.clock.now_unix();

        // Query certificates from database
        let certs_res = self.store.read(|conn| {
            let mut stmt = conn
                .prepare("SELECT name, not_before, not_after, last_active_at FROM certificates")?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            })?;
            let mut list = Vec::new();
            for r in rows {
                list.push(r?);
            }
            Ok(list)
        });

        let certs = match certs_res {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "Failed to query certificates for renewal");
                return vec![Err(e.to_string())];
            }
        };

        let mut results = Vec::new();

        for (name, not_before, not_after, last_active_at) in certs {
            let lower = name.to_ascii_lowercase();
            let is_root = lower == root_domain;
            let is_active = is_root
                || last_active_at.is_some()
                || self.active_hosts.read().unwrap().contains(&lower);

            // Skip inactive hostnames
            if !is_active {
                debug!(hostname = %lower, "Skipping renewal for inactive hostname");
                continue;
            }

            // Check if within renewal window (< 1/3 lifetime remaining)
            if should_renew(not_before, not_after, now) {
                info!(hostname = %lower, not_before, not_after, now, "Renewing certificate");

                self.set_state(&lower, CertState::Renewing { not_after });
                if is_root {
                    let _ = notify_cert_status("renewing");
                }

                // Force renewal issuance
                match self.execute_issuance(lower.clone()).await {
                    Ok(()) => {
                        let _ = record_cert_event(
                            &self.store,
                            &lower,
                            self.clock.now_unix(),
                            "renewed",
                            None,
                        );
                        results.push(Ok(lower));
                    }
                    Err(e) => {
                        results.push(Err(format!("Renewal for {lower} failed: {e}")));
                    }
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

    /// Returns a reference to the active challenge registry.
    pub fn challenge_registry(&self) -> Arc<ChallengeRegistry> {
        Arc::clone(&self.challenge_registry)
    }
}
