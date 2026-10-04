use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::Duration;

use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::pem::PemObject;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tracing::{debug, trace};

use crate::cert::acme::parse_cert_validity;
use crate::cert::clock::{Clock, SystemClock};
use crate::cert::managed::ManagedCerts;

/// In-memory stored certificate with its parsed expiration timestamp.
#[derive(Clone)]
struct StoredCert {
    key: Arc<CertifiedKey>,
    not_after: i64,
}

/// Synchronous waiter pair for holding in-flight TLS handshakes.
struct HandshakeWaiter {
    lock: Mutex<bool>,
    cvar: Condvar,
}

impl HandshakeWaiter {
    fn new() -> Self {
        Self {
            lock: Mutex::new(false),
            cvar: Condvar::new(),
        }
    }

    fn notify(&self) {
        let mut guard = self.lock.lock().unwrap();
        *guard = true;
        self.cvar.notify_all();
    }

    fn wait_timeout(&self, timeout: Duration) {
        let mut guard = self.lock.lock().unwrap();
        let start = std::time::Instant::now();
        while !*guard {
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                break;
            }
            let remaining = timeout - elapsed;
            let (next_guard, result) = self.cvar.wait_timeout(guard, remaining).unwrap();
            guard = next_guard;
            if result.timed_out() {
                break;
            }
        }
    }
}

pub const DEFAULT_HOLD_TIMEOUT: Duration = Duration::from_secs(30);

/// Dynamic TLS certificate resolver.
///
/// Dispatches incoming TLS connections:
/// - Serves the tunnel wildcard: SNI `<root>` matches the apex, exactly one
///   label under `<root>` matches `*.<root>`
/// - Serves the admin certificate for the exact `admin_domain` SNI
/// - Holds handshakes up to 30s while the covering order is in flight
/// - Rejects unknown hostnames, missing SNI, failed orders, and timed-out orders at the TCP level
/// - Strictly prohibits serving self-signed or placeholder certificates to public HTTPS clients
pub struct CertResolver {
    /// The managed certificates that define which SNI is served by which
    /// certificate. There is no separate zone type: coverage comes from the
    /// catalog itself.
    managed: Arc<ManagedCerts>,
    certs: RwLock<HashMap<String, StoredCert>>,
    ordering_waiters: Mutex<HashMap<String, Arc<HandshakeWaiter>>>,
    clock: Arc<dyn Clock>,
    hold_timeout: Duration,
}

impl std::fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertResolver")
            .field("managed", &self.managed.all().len())
            .field("certs_count", &self.certs.read().unwrap().len())
            .finish()
    }
}

impl CertResolver {
    /// Creates a new `CertResolver` serving a single tunnel wildcard.
    ///
    /// Convenience for tests and tunnel-only callers; production wires the full
    /// catalog with [`CertResolver::with_managed`].
    pub fn new(tunnel_domain: impl AsRef<str>) -> Self {
        Self::with_clock(tunnel_domain, Arc::new(SystemClock))
    }

    /// Creates a new `CertResolver` with an injected clock for deterministic time in tests.
    pub fn with_clock(tunnel_domain: impl AsRef<str>, clock: Arc<dyn Clock>) -> Self {
        Self::with_managed(Arc::new(ManagedCerts::for_tunnel(tunnel_domain)), clock)
    }

    /// Creates a resolver driven by the full managed-certificate catalog.
    pub fn with_managed(managed: Arc<ManagedCerts>, clock: Arc<dyn Clock>) -> Self {
        Self {
            managed,
            certs: RwLock::new(HashMap::new()),
            ordering_waiters: Mutex::new(HashMap::new()),
            clock,
            hold_timeout: DEFAULT_HOLD_TIMEOUT,
        }
    }

    /// Overrides the handshake hold timeout (defaults to 30s).
    pub fn with_hold_timeout(mut self, timeout: Duration) -> Self {
        self.hold_timeout = timeout;
        self
    }

    /// Maps an SNI to the certificate name that serves it.
    ///
    /// The managed catalog decides coverage: the admin certificate covers
    /// exactly the admin hostname; the tunnel certificate covers the apex and
    /// exactly one label beneath it.
    fn cert_name_for(&self, host: &str) -> Option<String> {
        self.managed.cert_for(host).map(|c| c.name.clone())
    }

    /// Checks whether the certificate currently served for `name` is a placeholder certificate.
    /// Under strict TLS doctrine, placeholder certificates are never served, so this returns
    /// `false` if an unexpired certificate exists, or `true` otherwise.
    pub fn is_placeholder(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        let now = self.clock.now_unix();
        let certs = self.certs.read().unwrap();
        match self
            .cert_name_for(&lower)
            .and_then(|n| certs.get(&n).cloned())
        {
            Some(cert) => cert.not_after <= now,
            None => true,
        }
    }

    /// Stores an issued certificate for `name` and unblocks any waiting handshakes.
    /// Automatically extracts `not_after` expiration timestamp from the leaf certificate.
    pub fn insert_cert(&self, name: &str, certified_key: Arc<CertifiedKey>) {
        let not_after = certified_key
            .cert
            .first()
            .and_then(|c| parse_cert_validity(c.as_ref()).ok())
            .map(|(_, na)| na)
            .unwrap_or(i64::MAX);
        self.insert_cert_with_expiry(name, certified_key, not_after);
    }

    /// Stores an issued certificate for `name` with an explicit `not_after` expiration timestamp
    /// and unblocks any waiting handshakes. Updates the in-memory best certificate cache if
    /// the certificate is newer than or equal to any currently cached certificate for `name`.
    pub fn insert_cert_with_expiry(
        &self,
        name: &str,
        certified_key: Arc<CertifiedKey>,
        not_after: i64,
    ) {
        let lower = name.to_ascii_lowercase();
        let mut certs = self.certs.write().unwrap();
        match certs.get_mut(&lower) {
            Some(existing) => {
                if not_after >= existing.not_after {
                    *existing = StoredCert {
                        key: certified_key,
                        not_after,
                    };
                }
            }
            None => {
                certs.insert(
                    lower.clone(),
                    StoredCert {
                        key: certified_key,
                        not_after,
                    },
                );
            }
        }
        drop(certs);

        if let Some(waiter) = self.ordering_waiters.lock().unwrap().remove(&lower) {
            waiter.notify();
        }
    }

    /// Marks a hostname as currently undergoing ordering, preparing a wait queue.
    pub fn mark_ordering(&self, name: &str) {
        let lower = name.to_ascii_lowercase();
        let mut waiters = self.ordering_waiters.lock().unwrap();
        waiters
            .entry(lower)
            .or_insert_with(|| Arc::new(HandshakeWaiter::new()));
    }

    /// Clears the ordering status for `name` on failure, unblocking waiting handshakes.
    pub fn clear_ordering(&self, name: &str) {
        let lower = name.to_ascii_lowercase();
        if let Some(waiter) = self.ordering_waiters.lock().unwrap().remove(&lower) {
            waiter.notify();
        }
    }

    /// Checks if a hostname is currently marked as undergoing ordering.
    pub fn is_ordering(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        self.ordering_waiters.lock().unwrap().contains_key(&lower)
    }

    fn wait_for_ordering(&self, name: &str, timeout: Duration) {
        let waiter = {
            let waiters = self.ordering_waiters.lock().unwrap();
            waiters.get(name).cloned()
        };

        if let Some(waiter) = waiter {
            trace!(
                name,
                "Holding TLS handshake for active ACME issuance (up to 30s)"
            );
            let is_multi_thread = tokio::runtime::Handle::try_current()
                .map(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
                .unwrap_or(false);

            if is_multi_thread {
                tokio::task::block_in_place(|| {
                    waiter.wait_timeout(timeout);
                });
            } else {
                waiter.wait_timeout(timeout);
            }
        }
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        // 1. Normal TLS request: check SNI.
        // Requests without SNI extension are rejected immediately at the TCP level.
        let Some(sni) = client_hello.server_name() else {
            debug!("Rejecting TLS handshake: SNI extension is missing");
            return None;
        };
        let host = sni.to_ascii_lowercase();
        let now = self.clock.now_unix();

        // 2. Map the SNI onto the certificate that covers it: the apex exactly,
        //    or the single-label wildcard. Anything else has no certificate.
        let Some(cert_name) = self.cert_name_for(&host) else {
            debug!(%host, "SNI is outside the wildcard coverage; rejecting TLS handshake");
            return None;
        };

        // 3. Check if a valid, unexpired certificate is already available.
        // If an unexpired certificate exists (including during background renewal),
        // serve it immediately without holding.
        if let Some(cert) = self.certs.read().unwrap().get(&cert_name)
            && cert.not_after > now
        {
            return Some(Arc::clone(&cert.key));
        }

        // 4. If the wildcard is actively undergoing issuance (and has no valid
        // unexpired cert), hold incoming handshake up to hold_timeout.
        if self.is_ordering(&cert_name) {
            self.wait_for_ordering(&cert_name, self.hold_timeout);
            // Check again after wait
            if let Some(cert) = self.certs.read().unwrap().get(&cert_name)
                && cert.not_after > self.clock.now_unix()
            {
                return Some(Arc::clone(&cert.key));
            }
        }

        // 5. Strict TLS doctrine: never serve self-signed or placeholder certificates.
        // Returning None causes rustls to abort the handshake, terminating the connection
        // at the TCP level without exchanging certificates.
        debug!(%host, "No valid certificate available; rejecting TLS handshake at TCP level");
        None
    }
}

/// Helper to parse PEM certificate chain and private key into an `Arc<CertifiedKey>`.
pub fn parse_certified_key(
    cert_pem: &str,
    key_pem: &str,
) -> Result<Arc<CertifiedKey>, Box<dyn std::error::Error + Send + Sync>> {
    let mut cert_chain = Vec::new();
    for item in rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes()) {
        let cert = item?;
        cert_chain.push(cert);
    }
    if cert_chain.is_empty() {
        return Err("No certificates found in cert_pem".into());
    }

    let key_der = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)?;
    Ok(Arc::new(CertifiedKey::new(cert_chain, signing_key)))
}
