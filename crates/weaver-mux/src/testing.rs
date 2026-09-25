//! Deterministic fixtures for tests and fuzz targets (feature `test-util`).
//!
//! Nothing here touches the wall clock or OS randomness: every helper is
//! seeded so a failing test reproduces byte-for-byte.

use std::collections::HashMap;
use std::convert::Infallible;
use std::time::{Duration, Instant};

use p256::ecdsa::signature::Signer as _;
use p256::elliptic_curve::sec1::ToSec1Point as _;
use rand_core::TryRng;

use crate::auth::{PublicKey, Signer, Verifier};
use crate::error::SignError;
use crate::wire::{KeyId, Signature};

/// Tiny xorshift64* generator. Not cryptographic — it only has to be
/// deterministic and cheap.
#[derive(Debug, Clone)]
pub struct SeededRng(u64);

impl SeededRng {
    /// Create a generator from a seed. Zero is remapped so the state never
    /// gets stuck.
    pub fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }
}

impl TryRng for SeededRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok((self.try_next_u64()? >> 32) as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        Ok(x.wrapping_mul(0x2545_F491_4F6C_DD1D))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dst.chunks_mut(8) {
            let bytes = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

/// A clock the test advances by hand.
#[derive(Debug, Clone)]
pub struct FakeClock {
    now: Instant,
}

impl FakeClock {
    /// Start the clock at `anchor`. `Instant` has no constructor other than
    /// the wall clock, which this crate forbids itself from touching, so the
    /// one sanctioned read happens in the test crate that calls this.
    pub fn at(anchor: Instant) -> Self {
        Self { now: anchor }
    }

    /// Current fake time.
    pub fn now(&self) -> Instant {
        self.now
    }

    /// Move the clock forward.
    pub fn advance(&mut self, by: Duration) -> Instant {
        self.now += by;
        self.now
    }

    /// Jump the clock to exactly `to` (must not go backwards).
    pub fn set(&mut self, to: Instant) -> Instant {
        assert!(to >= self.now, "FakeClock cannot go backwards");
        self.now = to;
        self.now
    }
}

/// In-memory Ed25519 signer derived from a seed.
pub struct Ed25519TestSigner {
    key: ed25519_dalek::SigningKey,
}

impl Ed25519TestSigner {
    /// Derive a key pair deterministically from `seed`.
    pub fn from_seed(seed: u64) -> Self {
        let mut rng = SeededRng::new(seed ^ 0x0ED2_5519);
        let mut secret = [0u8; 32];
        rng.try_fill_bytes(&mut secret)
            .unwrap_or_else(|e| match e {});
        Self {
            key: ed25519_dalek::SigningKey::from_bytes(&secret),
        }
    }

    /// The public half, as the server's `Verifier` would return it.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::Ed25519(self.key.verifying_key().to_bytes())
    }
}

impl Signer for Ed25519TestSigner {
    fn key_id(&self) -> KeyId {
        KeyId::Ed25519(self.key.verifying_key().to_bytes())
    }

    fn sign(&mut self, msg: &[u8]) -> Result<Signature, SignError> {
        let sig: ed25519_dalek::Signature = self.key.sign(msg);
        Ok(Signature::Ed25519(sig.to_bytes()))
    }
}

/// In-memory ECDSA P-256 signer derived from a seed. Signing is RFC 6979
/// deterministic, so no RNG is needed at sign time.
pub struct P256TestSigner {
    key: p256::ecdsa::SigningKey,
}

impl P256TestSigner {
    /// Derive a key pair deterministically from `seed`.
    pub fn from_seed(seed: u64) -> Self {
        let mut rng = SeededRng::new(seed ^ 0x2560);
        // Loop until the scalar is in range; virtually always first try.
        loop {
            let mut secret = [0u8; 32];
            rng.try_fill_bytes(&mut secret)
                .unwrap_or_else(|e| match e {});
            if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&secret) {
                return Self { key };
            }
        }
    }

    fn compressed(&self) -> [u8; 33] {
        let point = self.key.verifying_key().as_affine().to_sec1_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// The public half, as the server's `Verifier` would return it.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::P256(self.compressed())
    }
}

impl Signer for P256TestSigner {
    fn key_id(&self) -> KeyId {
        KeyId::P256(self.compressed())
    }

    fn sign(&mut self, msg: &[u8]) -> Result<Signature, SignError> {
        let sig: p256::ecdsa::Signature = self.key.sign(msg);
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig.to_bytes());
        Ok(Signature::P256(out))
    }
}

/// A signer that always fails, for exercising the `SignError` path.
pub struct FailingSigner(pub KeyId);

impl Signer for FailingSigner {
    fn key_id(&self) -> KeyId {
        self.0
    }

    fn sign(&mut self, _msg: &[u8]) -> Result<Signature, SignError> {
        Err(SignError("test signer refuses".into()))
    }
}

/// `Verifier` backed by a map. Keys can be marked invalid to exercise the
/// `still_valid` re-check.
#[derive(Default)]
pub struct MapVerifier {
    keys: HashMap<KeyId, PublicKey>,
    revoked: std::collections::HashSet<KeyId>,
    /// Number of `still_valid` calls, for asserting the reverify cadence.
    pub still_valid_calls: usize,
}

impl MapVerifier {
    /// Empty verifier: every key is unknown.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a key.
    pub fn insert(&mut self, id: KeyId, pk: PublicKey) -> &mut Self {
        self.keys.insert(id, pk);
        self
    }

    /// Convenience: build a verifier that knows exactly this signer's key.
    pub fn with_key(id: KeyId, pk: PublicKey) -> Self {
        let mut v = Self::new();
        v.insert(id, pk);
        v
    }

    /// Make `still_valid` return `false` for this key from now on.
    pub fn revoke(&mut self, id: KeyId) {
        self.revoked.insert(id);
    }
}

#[async_trait::async_trait]
impl Verifier for MapVerifier {
    async fn public_key(&mut self, key_id: &KeyId) -> Option<PublicKey> {
        self.keys.get(key_id).copied()
    }

    async fn still_valid(&mut self, key_id: &KeyId) -> bool {
        self.still_valid_calls += 1;
        !self.revoked.contains(key_id)
    }
}
