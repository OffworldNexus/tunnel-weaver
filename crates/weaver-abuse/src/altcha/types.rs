//! The ALTCHA v3 / `altcha-lib` v2 wire types.
//!
//! Serde names and nesting mirror upstream (`Challenge.parameters`,
//! `expiresAt`, `keyLength`, `keyPrefix`, `derivedKey`, …) so a challenge we
//! produce is byte-compatible with what the official widget expects, and a
//! payload the widget submits deserialises here. Optional `None` fields are
//! omitted from the JSON, matching upstream, which is what makes the canonical
//! (key-sorted) JSON of the parameters stable across both implementations.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The signed parameters of a challenge.
///
/// Serialises in alphabetical key order via the engine's canonical form; the
/// HMAC is taken over that form, so every field here is authenticated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeParameters {
    /// Key-derivation algorithm, e.g. `"PBKDF2/SHA-256"`.
    pub algorithm: String,
    /// Algorithm-specific work cost (PBKDF2 iterations).
    pub cost: u32,
    /// Signed metadata. The engine writes `client`, `purpose` and `flow` here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<BTreeMap<String, serde_json::Value>>,
    /// Unix seconds after which the challenge is spent; `0`/absent means never.
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// Length of the derived key, in bytes.
    #[serde(rename = "keyLength")]
    pub key_length: usize,
    /// Hex prefix the derived key must start with.
    #[serde(rename = "keyPrefix")]
    pub key_prefix: String,
    /// Random per-challenge nonce (hex), the KDF password prefix.
    pub nonce: String,
    /// Random per-challenge salt (hex).
    pub salt: String,
}

/// A challenge issued to a client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    /// The signed parameters.
    pub parameters: ChallengeParameters,
    /// `HMAC-SHA256(secret, canonical_json(parameters))`, hex-encoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// A solved challenge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Solution {
    /// The counter that yields a matching derived key.
    pub counter: u32,
    /// The derived key (hex) the client found.
    #[serde(rename = "derivedKey")]
    pub derived_key: String,
    /// Solve time in milliseconds; informational, not authenticated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<f64>,
}

/// The payload a client submits: the challenge it was given and its solution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Payload {
    /// The challenge, echoed back.
    pub challenge: Challenge,
    /// The submitted solution.
    pub solution: Solution,
}

/// Why a payload was refused.
///
/// The API layer maps each variant to a status/message. Expiry, signature
/// presence and signature validity are checked before any key derivation, so a refusal here never
/// implies the relay did unbounded work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProofError {
    /// The challenge's `expiresAt` is in the past.
    #[error("challenge expired")]
    Expired,
    /// The challenge carried no signature.
    #[error("challenge is unsigned")]
    MissingSignature,
    /// The signature did not match the parameters.
    #[error("challenge signature is invalid")]
    BadSignature,
    /// The challenge names an algorithm this engine does not implement.
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
    /// The signed `data` is missing, or its purpose/flow is not the expected one.
    #[error("proof is not bound to this purpose and flow")]
    WrongContext,
    /// The derived key did not match the signed prefix.
    #[error("solution is invalid")]
    BadSolution,
    /// The proof's single-use marker already exists.
    #[error("proof was already spent")]
    Spent,
    /// No live client matches the public key.
    #[error("unknown or revoked client")]
    UnknownClient,
}
