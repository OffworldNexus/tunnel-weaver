//! Handshake authentication: transcript construction and signature checks.
//!
//! The mux never holds keys. The client is given a [`Signer`], the server a
//! [`Verifier`]; both are traits defined here and implemented by the
//! adapter. Verification of the signature itself happens inside this module
//! so the security-relevant bytes are assembled in exactly one place.

use ed25519_dalek::VerifyingKey as EdKey;
use p256::ecdsa::signature::Verifier as _;

use crate::error::SignError;
use crate::wire::{KeyId, Signature, TRANSCRIPT_PREFIX};

/// A public key resolved by the server's [`Verifier`]. The variant must
/// match the [`KeyId`] it was looked up with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKey {
    /// Ed25519 public key bytes.
    Ed25519([u8; 32]),
    /// P-256 public key, SEC1 compressed.
    P256([u8; 33]),
}

/// Client-side access to the device key. Implemented by the adapter; may
/// call into a TPM / Secure Enclave, hence the fallible `sign`.
pub trait Signer {
    /// The identity that will be sent in HELLO.
    fn key_id(&self) -> KeyId;
    /// Sign `msg` with the key behind [`Signer::key_id`].
    fn sign(&mut self, msg: &[u8]) -> Result<Signature, SignError>;
}

/// Server-side key lookup. Implemented by the adapter (registry, database,
/// static allow-list, ...).
pub trait Verifier {
    /// The public key for `key_id`, or `None` if the key is unknown — which
    /// the server reports to the client as `REJECT { UnknownKey }`.
    fn public_key(&mut self, key_id: &KeyId) -> Option<PublicKey>;

    /// Lazy revalidation, polled every `Config::reverify_interval`. Returning
    /// `false` closes the connection with `KeyRevoked`. Defaults to always
    /// valid so implementations that do not support revocation need not
    /// override it.
    fn still_valid(&mut self, _key_id: &KeyId) -> bool {
        true
    }
}

/// Build the bytes both sides sign / verify:
/// `"weaver-mux-v1" ‖ nonce_s ‖ nonce_c ‖ server_name [‖ channel_binding]`.
///
/// Everything except `server_name` is fixed-width, so the encoding is
/// unambiguous without length prefixes as long as both sides agree on the
/// presence of the channel binding (they must, per the protocol).
pub fn transcript(
    nonce_s: &[u8; 32],
    nonce_c: &[u8; 32],
    server_name: &str,
    channel_binding: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(TRANSCRIPT_PREFIX.len() + 64 + server_name.len() + 32);
    out.extend_from_slice(TRANSCRIPT_PREFIX);
    out.extend_from_slice(nonce_s);
    out.extend_from_slice(nonce_c);
    out.extend_from_slice(server_name.as_bytes());
    if let Some(cb) = channel_binding {
        out.extend_from_slice(cb);
    }
    out
}

/// Check that `sig` is a valid signature of `msg` under `key`, and that
/// the algorithm variants of `key_id`, `key`, and `sig` all agree.
pub fn verify(key_id: &KeyId, key: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    match (key_id, key, sig) {
        (KeyId::Ed25519(id), PublicKey::Ed25519(pk), Signature::Ed25519(sig)) => {
            if id != pk {
                return false;
            }
            let Ok(vk) = EdKey::from_bytes(pk) else {
                return false;
            };
            let sig = ed25519_dalek::Signature::from_bytes(sig);
            vk.verify_strict(msg, &sig).is_ok()
        }
        (KeyId::P256(id), PublicKey::P256(pk), Signature::P256(sig)) => {
            if id != pk {
                return false;
            }
            let Ok(vk) = p256::ecdsa::VerifyingKey::from_sec1_bytes(pk) else {
                return false;
            };
            let Ok(sig) = p256::ecdsa::Signature::from_slice(sig) else {
                return false;
            };
            vk.verify(msg, &sig).is_ok()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Ed25519TestSigner, P256TestSigner};

    #[test]
    fn transcript_layout() {
        let t = transcript(&[1; 32], &[2; 32], "example.com", None);
        assert_eq!(&t[..13], b"weaver-mux-v1");
        assert_eq!(&t[13..45], &[1; 32]);
        assert_eq!(&t[45..77], &[2; 32]);
        assert_eq!(&t[77..], b"example.com");
        let t2 = transcript(&[1; 32], &[2; 32], "example.com", Some(&[9; 32]));
        assert_eq!(t2.len(), t.len() + 32);
        assert_eq!(&t2[t.len()..], &[9; 32]);
    }

    #[test]
    fn ed25519_round_trip() {
        let mut s = Ed25519TestSigner::from_seed(1);
        let id = s.key_id();
        let pk = s.public_key();
        let sig = s.sign(b"hello").unwrap();
        assert!(verify(&id, &pk, b"hello", &sig));
        assert!(!verify(&id, &pk, b"hellp", &sig));
        // Wrong algorithm pairing is rejected.
        assert!(!verify(&id, &pk, b"hello", &Signature::P256([0; 64])));
    }

    #[test]
    fn p256_round_trip() {
        let mut s = P256TestSigner::from_seed(1);
        let id = s.key_id();
        let pk = s.public_key();
        let sig = s.sign(b"hello").unwrap();
        assert!(verify(&id, &pk, b"hello", &sig));
        assert!(!verify(&id, &pk, b"hellp", &sig));
        let other = P256TestSigner::from_seed(2).public_key();
        assert!(!verify(&id, &other, b"hello", &sig));
    }
}
