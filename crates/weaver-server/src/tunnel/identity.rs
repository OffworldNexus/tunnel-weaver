//! Who is behind a key. Relay policy, deliberately outside the protocol
//! crates: the mux only knows `KeyId`, the schema knows nothing about
//! identities at all.

use weaver_mux::KeyId;
use weaver_mux::auth::PublicKey;

use crate::store::Store;

/// A resolved client identity: the `(person, machine)` pair that owns the
/// key, from which service hostnames are derived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The machine's row id.
    pub machine_id: i32,
    /// The owning person's row id.
    ///
    /// Carried alongside the names so a live transition can address the person's
    /// console streams ([`crate::live::LiveHub`]) without a second lookup.
    pub person_id: i32,
    /// Namespace owner (a person or account).
    pub person: String,
    /// Machine within that namespace.
    pub machine: String,
}

/// Store-backed identity resolver: a key is whichever machine holds it in
/// `machine.key_id`, and nothing else is consulted. It serves both the mux
/// handshake and the registry, so the two can never disagree about who a key
/// belongs to.
#[derive(Clone)]
pub struct StoreIdentityResolver {
    store: Store,
}

impl StoreIdentityResolver {
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    /// The public key for `key_id`, or `None` if no machine holds it.
    pub async fn public_key(&self, key_id: &KeyId) -> Option<PublicKey> {
        self.identity(key_id).await?;
        Some(match *key_id {
            KeyId::Ed25519(bytes) => PublicKey::Ed25519(bytes),
            KeyId::P256(bytes) => PublicKey::P256(bytes),
        })
    }

    /// The identity behind `key_id`, or `None` if no machine holds it.
    pub async fn identity(&self, key_id: &KeyId) -> Option<Identity> {
        let (person, machine) = self.store.machine_by_key(key_id).await.ok()??;
        Some(Identity {
            machine_id: machine.id,
            person_id: person.id,
            person: person.name,
            machine: machine.name,
        })
    }
}

impl Identity {
    /// This machine's hostname for `service`:
    /// `<person>-<machine>-<service>.<root>`, lowercased.
    pub fn hostname(&self, service: &str, root: &str) -> String {
        crate::store::names::flat_hostname(&self.person, &self.machine, service, root)
    }
}
