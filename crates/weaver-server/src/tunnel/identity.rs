//! Who is behind a key. Relay policy, deliberately outside the protocol
//! crates: the mux only knows `KeyId`, the schema knows nothing about
//! identities at all.

use std::sync::Arc;

use weaver_mux::KeyId;
use weaver_mux::auth::{PublicKey, Verifier};

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
pub trait IdentityResolver: Send + Sync {
    /// The public key for `key_id`, or `None` if unknown.
    fn public_key(&self, key_id: &KeyId) -> Option<PublicKey>;

    /// The identity behind `key_id`, or `None` if it may not register
    /// services.
    fn identity(&self, key_id: &KeyId) -> Option<Identity>;

    /// Whether the key is still acceptable. Polled by the mux at
    /// `Config::reverify_interval`.
    fn still_valid(&self, _key_id: &KeyId) -> bool {
        true
    }
}

/// Adapter making any `Arc<dyn IdentityResolver>` usable as the mux's
/// `Box<dyn Verifier>`.
pub struct ResolverVerifier(pub Arc<dyn IdentityResolver>);

impl Verifier for ResolverVerifier {
    fn public_key(&mut self, key_id: &KeyId) -> Option<PublicKey> {
        self.0.public_key(key_id)
    }

    fn still_valid(&mut self, key_id: &KeyId) -> bool {
        self.0.still_valid(key_id)
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

/// Milestone-1 resolver: exactly one hard-coded Ed25519 key, owned by
/// `poc/laptop`. Replaced by a store-backed resolver once enrolment exists.
#[derive(Debug, Default, Clone, Copy)]
pub struct PocResolver;

impl PocResolver {
    /// Public key bytes of the PoC client (its `weave --dev-key` seed is
    /// `b"weaver-poc-laptop-secret-key-32b"`).
    pub const PUBLIC_KEY: [u8; 32] = [
        0x9b, 0x01, 0x7a, 0xbe, 0x25, 0x0e, 0x5b, 0x63, 0xf6, 0x81, 0x7a, 0x84, 0xec, 0x9c, 0x7b,
        0x75, 0x98, 0xb1, 0x1f, 0xc8, 0x00, 0x56, 0xec, 0xe2, 0x9e, 0x06, 0xb8, 0xaa, 0x4b, 0x51,
        0x79, 0x06,
    ];
    /// The PoC client's `KeyId`.
    pub const KEY_ID: KeyId = KeyId::Ed25519(Self::PUBLIC_KEY);
}

impl IdentityResolver for PocResolver {
    fn public_key(&self, key_id: &KeyId) -> Option<PublicKey> {
        (key_id == &Self::KEY_ID).then_some(PublicKey::Ed25519(Self::PUBLIC_KEY))
    }

    fn identity(&self, key_id: &KeyId) -> Option<Identity> {
        (key_id == &Self::KEY_ID).then(|| Identity {
            person: "poc".into(),
            machine: "laptop".into(),
        })
    }
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

    #[test]
    fn poc_resolver_knows_exactly_one_key() {
        let r = PocResolver;
        assert!(r.public_key(&PocResolver::KEY_ID).is_some());
        assert!(r.identity(&PocResolver::KEY_ID).is_some());
        assert!(r.public_key(&KeyId::Ed25519([0; 32])).is_none());
        assert!(r.identity(&KeyId::Ed25519([0; 32])).is_none());
    }
}
