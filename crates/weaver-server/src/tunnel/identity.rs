//! Who is behind a key. Relay policy, deliberately outside the protocol
//! crates: the mux only knows `KeyId`, the schema knows nothing about
//! identities at all.

use std::sync::Arc;

use weaver_mux::KeyId;
use weaver_mux::auth::{PublicKey, Verifier};

use crate::store::Store;

/// A resolved client identity: the `(person, machine)` pair that owns the
/// key, from which service hostnames are derived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Namespace owner (a person or account).
    pub person: String,
    /// Machine within that namespace.
    pub machine: String,
}

/// Maps keys to identities and public keys. One implementation serves both
/// as the mux [`Verifier`] and as the registry's authorization source, so
/// the two can never disagree about who a key belongs to.
#[async_trait::async_trait]
pub trait IdentityResolver: Send + Sync {
    /// The public key for `key_id`, or `None` if unknown.
    async fn public_key(&self, key_id: &KeyId) -> Option<PublicKey>;

    /// The identity behind `key_id`, or `None` if it may not register
    /// services.
    async fn identity(&self, key_id: &KeyId) -> Option<Identity>;

    /// Whether the key is still acceptable. Polled by the mux at
    /// `Config::reverify_interval`.
    async fn still_valid(&self, _key_id: &KeyId) -> bool {
        true
    }
}

/// Adapter making any `Arc<dyn IdentityResolver>` usable as the mux's
/// `Box<dyn Verifier>`.
pub struct ResolverVerifier(pub Arc<dyn IdentityResolver>);

#[async_trait::async_trait]
impl Verifier for ResolverVerifier {
    async fn public_key(&mut self, key_id: &KeyId) -> Option<PublicKey> {
        self.0.public_key(key_id).await
    }

    async fn still_valid(&mut self, key_id: &KeyId) -> bool {
        self.0.still_valid(key_id).await
    }
}

/// Store-backed identity resolver querying `person`, `machine`, and `machine_key`.
#[derive(Clone)]
pub struct StoreIdentityResolver {
    store: Store,
}

impl StoreIdentityResolver {
    pub fn new(store: Store) -> Self {
        Self { store }
    }
}

#[async_trait::async_trait]
impl IdentityResolver for StoreIdentityResolver {
    async fn public_key(&self, key_id: &KeyId) -> Option<PublicKey> {
        // Serve the key *stored* for this identity, not the bytes the peer
        // claimed: the lookup already matched on the canonical key id, and
        // `weaver_mux::auth::verify` additionally rejects any mismatch.
        let (_, _, machine_key) = self.store.resolve_key(key_id).await.ok()??;
        match crate::store::parse_key_id(&machine_key.key_id)? {
            KeyId::Ed25519(bytes) => Some(PublicKey::Ed25519(bytes)),
            KeyId::P256(bytes) => Some(PublicKey::P256(bytes)),
        }
    }

    async fn identity(&self, key_id: &KeyId) -> Option<Identity> {
        let Ok(Some((pers, mach, _))) = self.store.resolve_key(key_id).await else {
            return None;
        };
        Some(Identity {
            person: pers.name,
            machine: mach.name,
        })
    }

    async fn still_valid(&self, key_id: &KeyId) -> bool {
        self.public_key(key_id).await.is_some()
    }
}

/// Derives the fully-qualified tunnel hostname:
/// `<service>.<machine>.<person>.<root>`, lowercased.
pub fn derive_hostname(service: &str, identity: &Identity, root: &str) -> String {
    format!(
        "{}.{}.{}.{root}",
        service.to_ascii_lowercase(),
        identity.machine.to_ascii_lowercase(),
        identity.person.to_ascii_lowercase()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_derivation() {
        let id = Identity {
            person: "Poc".into(),
            machine: "Laptop".into(),
        };
        assert_eq!(
            derive_hostname("Web", &id, "example.com"),
            "web.laptop.poc.example.com"
        );
    }
}
