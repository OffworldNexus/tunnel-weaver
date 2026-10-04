//! Challenge-solver abstraction for ACME authorizations.
//!
//! OFF-198 needs two DCV mechanisms at once: DNS-01 for the delegated tunnel
//! wildcard (we own the zone and serve the TXT rrset ourselves) and HTTP-01 for
//! the relay's own admin hostname (we do *not* own its DNS, but we do own port
//! 80). Rather than teaching [`crate::cert::acme::AcmeEngine`] about DNS and
//! HTTP separately, every mechanism is a [`ChallengeSolver`] behind one
//! interface. The engine only ever deals in `instant_acme::ChallengeType` and
//! [`ChallengeGuard`]s, so it carries no responder-specific code.
//!
//! A solver's [`ChallengeSolver::provision`] writes the response material into
//! the store and returns a guard. The guard withdraws the response when it is
//! dropped, which is exactly when an order settles — including on every early
//! return and on a panic. The authoritative DNS responder and the port-80 edge
//! read the store generatively, so no solver ever touches a socket itself.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use instant_acme::ChallengeType;
use sha2::{Digest, Sha256};
use tracing::debug;

use crate::store::Store;

/// Errors a solver can return while provisioning a challenge response.
#[derive(Debug, thiserror::Error)]
pub enum SolverError {
    /// The challenge registry write failed.
    #[error("failed to publish challenge response: {0}")]
    Store(String),
    /// The engine asked for a mechanism this solver does not implement.
    #[error("solver does not handle the offered challenge type")]
    UnsupportedType,
}

/// Which mechanism a [`ChallengeGuard`] must withdraw from the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuardKind {
    Dns01,
    Http01,
}

/// RAII withdrawal of a published ACME challenge response.
///
/// Holds the store handle plus the exact key/value the solver published. When
/// dropped it removes that response, so an order that succeeds, fails, or panics
/// never leaves a stale TXT or key authorization behind. Removal is spawned on
/// the ambient Tokio runtime because `Drop` cannot await; if there is no
/// runtime (only possible in a non-async test) the row is left for the daemon's
/// next challenge clear rather than blocking.
pub struct ChallengeGuard {
    store: Arc<Store>,
    kind: GuardKind,
    key: String,
    value: String,
}

impl std::fmt::Debug for ChallengeGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChallengeGuard")
            .field("kind", &self.kind)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl Drop for ChallengeGuard {
    fn drop(&mut self) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let store = Arc::clone(&self.store);
        let kind = self.kind;
        let key = std::mem::take(&mut self.key);
        let value = std::mem::take(&mut self.value);
        handle.spawn(async move {
            let result = match kind {
                GuardKind::Dns01 => store.remove_challenge(&key, &value).await,
                GuardKind::Http01 => store.remove_http01(&key).await,
            };
            if let Err(err) = result {
                debug!(key = %key, error = %err, "Failed to withdraw ACME challenge response");
            }
        });
    }
}

/// One ACME DCV mechanism that can publish and later withdraw a response.
#[async_trait]
pub trait ChallengeSolver: Send + Sync {
    /// The `instant_acme` challenge type this solver answers.
    fn challenge_type(&self) -> ChallengeType;

    /// Publishes the response for `identifier`'s authorization.
    ///
    /// `token` is the ACME challenge token (used verbatim by HTTP-01 as the
    /// request path segment; ignored by DNS-01, which derives its owner name
    /// from `identifier`). `key_authorization` is the RFC 8555 §8.1 key
    /// authorization: DNS-01 stores its SHA-256 digest, HTTP-01 stores it
    /// verbatim. The returned guard withdraws the response on drop.
    async fn provision(
        &self,
        identifier: &str,
        token: &str,
        key_authorization: &str,
    ) -> Result<ChallengeGuard, SolverError>;
}

/// DNS-01: publish a `_acme-challenge.<domain>` TXT digest.
///
/// The wildcard authorization's identifier is `*.<root>`; the `*.` prefix is
/// stripped so the apex and wildcard authorizations of one order share the same
/// owner name, which is what lets a single multi-value TXT rrset satisfy both.
pub struct Dns01Solver {
    store: Arc<Store>,
}

impl Dns01Solver {
    /// Creates a DNS-01 solver backed by the challenge registry.
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    /// Owner name for an authorization identifier, with any `*.` removed.
    fn owner_name(identifier: &str) -> String {
        let host = identifier.strip_prefix("*.").unwrap_or(identifier);
        format!("_acme-challenge.{host}")
    }

    /// base64url(SHA-256(key authorization)), the DNS-01 TXT value.
    fn dns_value(key_authorization: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(key_authorization.as_bytes()))
    }
}

#[async_trait]
impl ChallengeSolver for Dns01Solver {
    fn challenge_type(&self) -> ChallengeType {
        ChallengeType::Dns01
    }

    async fn provision(
        &self,
        identifier: &str,
        _token: &str,
        key_authorization: &str,
    ) -> Result<ChallengeGuard, SolverError> {
        let name = Self::owner_name(identifier);
        let value = Self::dns_value(key_authorization);
        let now = now_unix();
        self.store
            .publish_challenge(&name, &value, now)
            .await
            .map_err(|e| SolverError::Store(e.to_string()))?;
        Ok(ChallengeGuard {
            store: Arc::clone(&self.store),
            kind: GuardKind::Dns01,
            key: name,
            value,
        })
    }
}

/// HTTP-01: publish a key authorization under the ACME token as the path.
pub struct Http01Solver {
    store: Arc<Store>,
}

impl Http01Solver {
    /// Creates an HTTP-01 solver backed by the challenge registry.
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl ChallengeSolver for Http01Solver {
    fn challenge_type(&self) -> ChallengeType {
        ChallengeType::Http01
    }

    async fn provision(
        &self,
        _identifier: &str,
        token: &str,
        key_authorization: &str,
    ) -> Result<ChallengeGuard, SolverError> {
        let now = now_unix();
        self.store
            .publish_http01(token, key_authorization, now)
            .await
            .map_err(|e| SolverError::Store(e.to_string()))?;
        Ok(ChallengeGuard {
            store: Arc::clone(&self.store),
            kind: GuardKind::Http01,
            key: token.to_string(),
            value: key_authorization.to_string(),
        })
    }
}

/// A fixed set of solvers keyed by `ChallengeType`.
///
/// `instant_acme::ChallengeType` is not `Hash`, so the registry is a short
/// linear scan; there are only two mechanisms and lookups happen once per
/// authorization.
#[derive(Default)]
pub struct SolverRegistry {
    solvers: Vec<(ChallengeType, Arc<dyn ChallengeSolver>)>,
}

impl std::fmt::Debug for SolverRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SolverRegistry")
            .field("solvers", &self.solvers.len())
            .finish()
    }
}

impl SolverRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a registry with the two first-class mechanisms registered.
    pub fn with_defaults(store: Arc<Store>) -> Self {
        let mut registry = Self::new();
        registry.register(Arc::new(Dns01Solver::new(Arc::clone(&store))));
        registry.register(Arc::new(Http01Solver::new(store)));
        registry
    }

    /// Adds (or replaces) the solver for its challenge type.
    pub fn register(&mut self, solver: Arc<dyn ChallengeSolver>) {
        let ty = solver.challenge_type();
        self.solvers.retain(|(t, _)| t != &ty);
        self.solvers.push((ty, solver));
    }

    /// Returns the solver registered for `challenge_type`, if any.
    pub fn get(&self, challenge_type: &ChallengeType) -> Option<Arc<dyn ChallengeSolver>> {
        self.solvers
            .iter()
            .find(|(t, _)| t == challenge_type)
            .map(|(_, s)| Arc::clone(s))
    }
}

/// Human-readable label for a challenge type, used in logs and the
/// `certificates.validation` column.
pub fn validation_label(challenge_type: &ChallengeType) -> &'static str {
    match challenge_type {
        ChallengeType::Dns01 => "dns-01",
        ChallengeType::Http01 => "http-01",
        _ => "unknown",
    }
}

/// Current Unix time, for challenge row timestamps.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_store() -> Arc<Store> {
        let dir = tempfile::tempdir().unwrap().keep();
        Arc::new(Store::open(dir.join("test.db")).await.unwrap())
    }

    #[tokio::test]
    async fn dns01_solver_publishes_digest_and_guard_withdraws() {
        let store = test_store().await;
        let solver = Dns01Solver::new(Arc::clone(&store));

        let guard = solver
            .provision("*.example.com", "ignored", "key-auth-value")
            .await
            .unwrap();

        let expected = Dns01Solver::dns_value("key-auth-value");
        assert_eq!(
            store
                .get_challenges("_acme-challenge.example.com")
                .await
                .unwrap(),
            vec![expected]
        );

        drop(guard);
        // Withdrawal is spawned; yield until the row is gone.
        for _ in 0..100 {
            if store
                .get_challenges("_acme-challenge.example.com")
                .await
                .unwrap()
                .is_empty()
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("DNS-01 challenge row was not withdrawn");
    }

    #[tokio::test]
    async fn http01_solver_publishes_key_auth_and_guard_withdraws() {
        let store = test_store().await;
        let solver = Http01Solver::new(Arc::clone(&store));

        let guard = solver
            .provision("admin.example.net", "tok-123", "key-auth-value")
            .await
            .unwrap();

        assert_eq!(
            store.get_http01("tok-123").await.unwrap().as_deref(),
            Some("key-auth-value")
        );

        drop(guard);
        for _ in 0..100 {
            if store.get_http01("tok-123").await.unwrap().is_none() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("HTTP-01 challenge row was not withdrawn");
    }

    #[tokio::test]
    async fn registry_lookup_is_type_exact() {
        let store = test_store().await;
        let registry = SolverRegistry::with_defaults(store);

        assert_eq!(
            registry
                .get(&ChallengeType::Dns01)
                .unwrap()
                .challenge_type(),
            ChallengeType::Dns01
        );
        assert_eq!(
            registry
                .get(&ChallengeType::Http01)
                .unwrap()
                .challenge_type(),
            ChallengeType::Http01
        );
        assert!(registry.get(&ChallengeType::TlsAlpn01).is_none());
        assert_eq!(validation_label(&ChallengeType::Dns01), "dns-01");
        assert_eq!(validation_label(&ChallengeType::Http01), "http-01");
    }

    #[test]
    fn dns_owner_name_strips_wildcard() {
        assert_eq!(
            Dns01Solver::owner_name("*.example.com"),
            "_acme-challenge.example.com"
        );
        assert_eq!(
            Dns01Solver::owner_name("example.com"),
            "_acme-challenge.example.com"
        );
    }
}
