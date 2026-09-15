use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::Duration;

use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::pem::PemObject;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tracing::{debug, trace};

use crate::cert::challenge::ChallengeRegistry;

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
        let guard = self.lock.lock().unwrap();
        if *guard {
            return;
        }
        let _ = self.cvar.wait_timeout(guard, timeout);
    }
}

/// Dynamic TLS certificate resolver.
///
/// Dispatches incoming TLS connections:
/// - Responds to ALPN `acme-tls/1` TLS-ALPN-01 challenges via `ChallengeRegistry`
/// - Serves valid issued ACME certificates per SNI
/// - Holds handshakes up to 30s when connecting to a hostname undergoing ACME issuance
/// - Falls back to an in-memory self-signed placeholder certificate until ACME issuance completes
pub struct CertResolver {
    root_domain: String,
    placeholder_key: Arc<CertifiedKey>,
    challenge_registry: Arc<ChallengeRegistry>,
    certs: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    ordering_waiters: Mutex<HashMap<String, Arc<HandshakeWaiter>>>,
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
    /// Creates a new `CertResolver` with the given placeholder certificate and challenge registry.
    pub fn new(
        root_domain: String,
        placeholder_key: Arc<CertifiedKey>,
        challenge_registry: Arc<ChallengeRegistry>,
    ) -> Self {
        Self {
            root_domain: root_domain.to_ascii_lowercase(),
            placeholder_key,
            challenge_registry,
            certs: RwLock::new(HashMap::new()),
            ordering_waiters: Mutex::new(HashMap::new()),
        }
    }

    /// Checks whether the certificate currently served for `name` is the placeholder certificate.
    pub fn is_placeholder(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        !self.certs.read().unwrap().contains_key(&lower)
    }

    /// Stores an issued certificate for `name` and unblocks any waiting handshakes.
    pub fn insert_cert(&self, name: &str, certified_key: Arc<CertifiedKey>) {
        let lower = name.to_ascii_lowercase();
        self.certs
            .write()
            .unwrap()
            .insert(lower.clone(), certified_key);

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

    /// Returns a reference to the placeholder certificate.
    pub fn placeholder(&self) -> Arc<CertifiedKey> {
        Arc::clone(&self.placeholder_key)
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

        // 2. Normal TLS request: check SNI
        let sni = client_hello.server_name().unwrap_or(&self.root_domain);
        let host = sni.to_ascii_lowercase();

        // Check if certificate is already available
        if let Some(cert) = self.certs.read().unwrap().get(&host) {
            return Some(Arc::clone(cert));
        }

        // If hostname is undergoing issuance, hold handshake up to 30 seconds
        if self.is_ordering(&host) {
            self.wait_for_ordering(&host, Duration::from_secs(30));
            // Check again after wait
            if let Some(cert) = self.certs.read().unwrap().get(&host) {
                return Some(Arc::clone(cert));
            }
        }

        // 3. Fallback to placeholder certificate
        trace!(%host, "Serving self-signed placeholder certificate");
        Some(Arc::clone(&self.placeholder_key))
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
