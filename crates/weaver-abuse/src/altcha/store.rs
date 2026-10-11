//! The injected proof store: the ALTCHA engine's only IO boundary.
//!
//! The engine never persists anything itself. It asks a [`ProofStore`] to
//! resolve a client (its signing secret and approved work parameters) and to
//! *atomically* consume a proof once. The server implements the trait over its
//! local SQLite store; tests use the in-memory fixture in [`crate::testing`].

use async_trait::async_trait;

use crate::store::StoreError;

/// A registered ALTCHA client, as resolved from its public key at request time.
///
/// A client is either a tunnelled *service* or the relay's *internal* client
/// (which serves the admin domain); the engine does not care which — it only
/// needs the signer's secret and the work parameters the server approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltchaClient {
    /// The public key that identifies the client on challenge requests.
    pub public_key: String,
    /// The HMAC secret that signs (and verifies) this client's challenges.
    pub secret: String,
    /// The approved KDF algorithm (e.g. `"PBKDF2/SHA-256"`).
    pub algorithm: String,
    /// The approved PBKDF2 iteration count.
    pub cost: u32,
    /// The approved derived-key length in bytes.
    pub key_length: usize,
    /// The approved hex key prefix (the solve-difficulty knob).
    pub key_prefix: String,
    /// Challenge lifetime in seconds; `<= 0` means no expiry.
    pub ttl_secs: i64,
}

/// The single-use key for a proof: the client it belongs to and the nonce that
/// makes the challenge unique.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsumeKey<'a> {
    /// The client's public key.
    pub public_key: &'a str,
    /// The challenge nonce.
    pub nonce: &'a str,
    /// Absolute expiry of the spent marker, in Unix milliseconds.
    pub expires_at_ms: i64,
}

/// The result of trying to consume a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumeOutcome {
    /// This call inserted the single-use marker; the proof is now spent.
    Consumed,
    /// A marker already existed; the proof was replayed.
    AlreadySpent,
}

/// An atomic client registry and proof-consumption store.
///
/// `consume` must be atomic: two concurrent submissions of the same proof must
/// yield exactly one [`ConsumeOutcome::Consumed`], and the spent marker must
/// survive a relay restart until `expires_at_ms`.
#[async_trait]
pub trait ProofStore: Send + Sync {
    /// Resolve a live client by public key; `Ok(None)` if unknown or revoked.
    async fn client(&self, public_key: &str) -> Result<Option<AltchaClient>, StoreError>;

    /// Atomically record that `key` has been spent at `now_ms`.
    async fn consume(&self, key: ConsumeKey<'_>, now_ms: i64)
    -> Result<ConsumeOutcome, StoreError>;
}
