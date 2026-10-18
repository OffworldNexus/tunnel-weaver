//! The hard-coded development device key.
//!
//! Compiled only with the `dev-signer` feature. A real `weave` holds no key at
//! all: pairing provisions a P-256 key inside the **tpmd** local
//! key agent and signs through [`crate::tpm`]. This module exists for tests
//! only — the in-process integration tests and the nightly droplet run, where
//! there is no key agent and no browser to approve a pairing: the relay enrols
//! this key directly (`weaver-server dev-enrol`), [`dev_enrol`] records the
//! matching relay row on the client, and `weave start --dev-signer` signs with
//! it.
//!
//! It is a cargo feature rather than a runtime switch on purpose: a production
//! binary must not even contain the seed.

use ed25519_dalek::Signer as _;
use weaver_mux::auth::Signer;
use weaver_mux::{KeyId, SignError, Signature};

use crate::host::normalize_admin_host;
use crate::store::{Relay, Store};

/// Fixed 32-byte Ed25519 seed of the development client.
pub const DEV_SECRET_KEY: [u8; 32] = *b"weaver-poc-laptop-secret-key-32b";

/// In-memory Ed25519 signer.
pub struct Ed25519Signer {
    key: ed25519_dalek::SigningKey,
}

impl Ed25519Signer {
    /// Signer from a raw seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: ed25519_dalek::SigningKey::from_bytes(seed),
        }
    }

    /// The development key the PoC relay accepts.
    pub fn dev() -> Self {
        Self::from_seed(&DEV_SECRET_KEY)
    }
}

#[async_trait::async_trait]
impl Signer for Ed25519Signer {
    fn key_id(&self) -> KeyId {
        KeyId::Ed25519(self.key.verifying_key().to_bytes())
    }

    async fn sign(&mut self, msg: &[u8]) -> Result<Signature, SignError> {
        let sig: ed25519_dalek::Signature = self.key.sign(msg);
        Ok(Signature::Ed25519(sig.to_bytes()))
    }
}

/// The development key's fingerprint as the client store records it:
/// `ed25519:<hex>`.
pub fn dev_key_id() -> String {
    let KeyId::Ed25519(bytes) = Ed25519Signer::dev().key_id() else {
        unreachable!("the development key is Ed25519");
    };
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("ed25519:{hex}")
}

/// Test-only: records that `admin_host` authorises the development key as
/// `machine_id`, as a completed pairing would. Idempotent; the first relay
/// recorded becomes the default.
pub async fn dev_enrol(
    store: &Store,
    admin_host: &str,
    machine_id: i32,
) -> Result<Relay, Box<dyn std::error::Error + Send + Sync>> {
    let admin_host = normalize_admin_host(admin_host)?;
    Ok(store
        .record_pairing(&admin_host, machine_id, &dev_key_id())
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_key_id_spells_the_dev_key() {
        assert_eq!(
            dev_key_id(),
            "ed25519:9b017abe250e5b63f6817a84ec9c7b7598b11fc80056ece29e06b8aa4b517906"
        );
    }

    #[tokio::test]
    async fn dev_enrol_records_a_normalised_default_row_idempotently() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("weave.db")).await.unwrap();

        let row = dev_enrol(&store, "A1.Example.Nexus.:443", 7).await.unwrap();
        assert_eq!(row.admin_host, "a1.example.nexus");
        assert_eq!(
            (row.machine_id, row.key_id.as_str()),
            (7, dev_key_id().as_str())
        );
        assert!(row.is_default);

        let again = dev_enrol(&store, "a1.example.nexus", 7).await.unwrap();
        assert_eq!(again, row);
        assert_eq!(store.relays().await.unwrap(), [row]);

        assert!(dev_enrol(&store, "http://nope", 1).await.is_err());
    }

    #[test]
    fn dev_key_matches_seeded_relay_key() {
        // Mirrors the `machine_key` row seeded by the relay's initial migration.
        let expected: [u8; 32] = [
            0x9b, 0x01, 0x7a, 0xbe, 0x25, 0x0e, 0x5b, 0x63, 0xf6, 0x81, 0x7a, 0x84, 0xec, 0x9c,
            0x7b, 0x75, 0x98, 0xb1, 0x1f, 0xc8, 0x00, 0x56, 0xec, 0xe2, 0x9e, 0x06, 0xb8, 0xaa,
            0x4b, 0x51, 0x79, 0x06,
        ];
        assert_eq!(Ed25519Signer::dev().key_id(), KeyId::Ed25519(expected));
    }
}
