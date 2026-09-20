//! Client key material.
//!
//! Milestone 1 ships one hard-coded development key so the relay's
//! `PocResolver` recognises the client. Real enrolment replaces this with a
//! key stored in the OS keychain / TPM behind the same [`Signer`] trait.

use ed25519_dalek::Signer as _;
use weaver_mux::auth::Signer;
use weaver_mux::{KeyId, SignError, Signature};

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

impl Signer for Ed25519Signer {
    fn key_id(&self) -> KeyId {
        KeyId::Ed25519(self.key.verifying_key().to_bytes())
    }

    fn sign(&mut self, msg: &[u8]) -> Result<Signature, SignError> {
        let sig: ed25519_dalek::Signature = self.key.sign(msg);
        Ok(Signature::Ed25519(sig.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_key_matches_relay_poc_resolver() {
        // Mirrors `weaver_server::tunnel::PocResolver::PUBLIC_KEY`.
        let expected: [u8; 32] = [
            0x9b, 0x01, 0x7a, 0xbe, 0x25, 0x0e, 0x5b, 0x63, 0xf6, 0x81, 0x7a, 0x84, 0xec, 0x9c,
            0x7b, 0x75, 0x98, 0xb1, 0x1f, 0xc8, 0x00, 0x56, 0xec, 0xe2, 0x9e, 0x06, 0xb8, 0xaa,
            0x4b, 0x51, 0x79, 0x06,
        ];
        assert_eq!(Ed25519Signer::dev().key_id(), KeyId::Ed25519(expected));
    }
}
