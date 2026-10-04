//! Challenge-solver abstraction for ACME authorizations.
//!
//! The relay drives two DCV mechanisms: DNS-01 for the delegated tunnel
//! wildcard (we own the zone and serve the TXT rrset ourselves) and HTTP-01 for
//! the relay's own admin hostname (we do *not* own its DNS, but we do own port
//! 80). The protocol servers answer generatively from the store; a solver only
//! writes the response material there and returns a guard that withdraws it.
//!
//! There is deliberately no registry of solvers: the two mechanisms are a fixed
//! pair, so [`Solvers`] holds one of each and the ACME engine selects by
//! [`Validation`]. The engine itself never names DNS or HTTP.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use sha2::{Digest, Sha256};
use tracing::debug;

use crate::cert::managed::Validation;
use crate::store::Store;

/// Errors a solver can return while provisioning a challenge response.
#[derive(Debug, thiserror::Error)]
pub enum SolverError {
    /// The challenge registry write failed.
    #[error("failed to publish challenge response: {0}")]
    Store(String),
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
    /// Publishes the response for `identifier`'s authorization.
    ///
    /// `token` is the ACME challenge token (used verbatim by HTTP-01 as the
    /// request path segment; ignored by DNS-01, which derives its owner name
    /// from `identifier`). `key_authorization` is the RFC 8555 §8.1 key
    /// authorization: DNS-01 stores its SHA-256 digest, HTTP-01 stores it
    /// verbatim. `certificate` is the managed certificate the challenge is
    /// solved for, recorded for diagnostics. The returned guard withdraws the
    /// response on drop.
    async fn provision(
        &self,
        identifier: &str,
        token: &str,
        key_authorization: &str,
        certificate: &str,
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
    async fn provision(
        &self,
        identifier: &str,
        _token: &str,
        key_authorization: &str,
        certificate: &str,
    ) -> Result<ChallengeGuard, SolverError> {
        let name = Self::owner_name(identifier);
        let value = Self::dns_value(key_authorization);
        let now = now_unix();
        self.store
            .publish_challenge(&name, &value, Some(certificate), now)
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
    async fn provision(
        &self,
        _identifier: &str,
        token: &str,
        key_authorization: &str,
        certificate: &str,
    ) -> Result<ChallengeGuard, SolverError> {
        let now = now_unix();
        self.store
            .publish_http01(token, key_authorization, Some(certificate), now)
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

/// The HTTP-01 solver doubles as the edge's challenge responder: it is the one
/// component that knows how a token maps to key-authorization material.
#[async_trait]
impl crate::edge::http::ChallengeResponder for Http01Solver {
    async fn respond(&self, token: &str) -> Option<String> {
        if token.is_empty() {
            return None;
        }
        self.store.get_http01(token).await.ok().flatten()
    }
}

/// The fixed pair of DCV mechanisms, selected by [`Validation`].
pub struct Solvers {
    dns: Arc<dyn ChallengeSolver>,
    http: Arc<dyn ChallengeSolver>,
}

impl std::fmt::Debug for Solvers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Solvers").finish_non_exhaustive()
    }
}

impl Solvers {
    /// Builds the two store-backed solvers.
    pub fn with_store(store: Arc<Store>) -> Self {
        Self {
            dns: Arc::new(Dns01Solver::new(Arc::clone(&store))),
            http: Arc::new(Http01Solver::new(store)),
        }
    }

    /// The solver for `validation`.
    pub fn get(&self, validation: Validation) -> Arc<dyn ChallengeSolver> {
        match validation {
            Validation::Dns01 => Arc::clone(&self.dns),
            Validation::Http01 => Arc::clone(&self.http),
        }
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
            .provision("*.example.com", "ignored", "key-auth-value", "example.com")
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
            .provision(
                "admin.example.net",
                "tok-123",
                "key-auth-value",
                "admin.example.net",
            )
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
