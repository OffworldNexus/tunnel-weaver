use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::Duration;

use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::pem::PemObject;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tracing::{debug, trace};

use crate::cert::acme::parse_cert_validity;
use crate::cert::challenge::ChallengeRegistry;
use crate::cert::clock::{Clock, SystemClock};

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
/// - Responds to ALPN `acme-tls/1` TLS-ALPN-01 challenges via `ChallengeRegistry`
/// - Serves valid unexpired issued ACME certificates per SNI
/// - Holds handshakes up to 30s when connecting to a hostname undergoing ACME issuance
/// - Rejects unknown hostnames, missing SNI, failed orders, and timed-out orders at the TCP level
/// - Strictly prohibits serving self-signed or placeholder certificates to public HTTPS clients
pub struct CertResolver {
    root_domain: String,
    challenge_registry: Arc<ChallengeRegistry>,
    certs: RwLock<HashMap<String, StoredCert>>,
    ordering_waiters: Mutex<HashMap<String, Arc<HandshakeWaiter>>>,
    clock: Arc<dyn Clock>,
    hold_timeout: Duration,
}

impl std::fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertResolver")
            .field("root_domain", &self.root_domain)
            .field("certs_count", &self.certs.read().unwrap().len())
            .finish()
    }
}

impl CertResolver {
    /// Creates a new `CertResolver` with the given root domain and challenge registry.
    pub fn new(root_domain: String, challenge_registry: Arc<ChallengeRegistry>) -> Self {
        Self::with_clock(root_domain, challenge_registry, Arc::new(SystemClock))
    }

    /// Creates a new `CertResolver` with an injected clock for deterministic time in tests.
    pub fn with_clock(
        root_domain: String,
        challenge_registry: Arc<ChallengeRegistry>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            root_domain: root_domain.to_ascii_lowercase(),
            challenge_registry,
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

    /// Checks whether the certificate currently served for `name` is a placeholder certificate.
    /// Under strict TLS doctrine, placeholder certificates are never served, so this returns
    /// `false` if an unexpired certificate exists, or `true` otherwise.
    pub fn is_placeholder(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        let now = self.clock.now_unix();
        let certs = self.certs.read().unwrap();
        match certs.get(&lower) {
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
    /// and unblocks any waiting handshakes.
    pub fn insert_cert_with_expiry(
        &self,
        name: &str,
        certified_key: Arc<CertifiedKey>,
        not_after: i64,
    ) {
        let lower = name.to_ascii_lowercase();
        self.certs.write().unwrap().insert(
            lower.clone(),
            StoredCert {
                key: certified_key,
                not_after,
            },
        );

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
        // 1. Check for TLS-ALPN-01 challenge matching ALPN `acme-tls/1`
        let has_acme_alpn = client_hello
            .alpn()
            .into_iter()
            .flatten()
            .any(|proto| proto == b"acme-tls/1");

        if has_acme_alpn {
            if let Some(sni) = client_hello.server_name()
                && let Some(challenge_key) = self.challenge_registry.get_tls_alpn_01(sni)
            {
                debug!(sni, "Serving TLS-ALPN-01 challenge certificate");
                return Some(challenge_key);
            }
            debug!("TLS-ALPN-01 requested but no matching challenge key found");
            return None;
        }

        // 2. Normal TLS request: check SNI.
        // Requests without SNI extension are rejected immediately at the TCP level.
        let Some(sni) = client_hello.server_name() else {
            debug!("Rejecting TLS handshake: SNI extension is missing");
            return None;
        };
        let host = sni.to_ascii_lowercase();
        let now = self.clock.now_unix();

        // 3. Check if a valid, unexpired certificate is already available.
        // If an unexpired certificate exists (including during background renewal),
        // serve it immediately without holding.
        if let Some(cert) = self.certs.read().unwrap().get(&host)
            && cert.not_after > now
        {
            return Some(Arc::clone(&cert.key));
        }

        // 4. If hostname is actively undergoing issuance (and has no valid unexpired cert),
        // hold incoming handshake up to hold_timeout (30 seconds by default).
        if self.is_ordering(&host) {
            self.wait_for_ordering(&host, self.hold_timeout);
            // Check again after wait
            if let Some(cert) = self.certs.read().unwrap().get(&host)
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
