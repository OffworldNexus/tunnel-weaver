//! Challenge creation and solution verification for `PBKDF2/SHA-256`.
//!
//! See the [module docs](crate::altcha) for the wire shape and the security
//! rationale behind the verification order.

use std::collections::BTreeMap;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::altcha::types::{Challenge, ChallengeParameters, ProofError, Solution};

/// The one key-derivation algorithm this engine produces and accepts.
///
/// Upstream spells it `PBKDF2/SHA-256`; matching is case-insensitive so a peer
/// that spells it differently is still understood, but the engine only ever
/// issues this exact spelling.
pub const SUPPORTED_ALGORITHM: &str = "PBKDF2/SHA-256";

/// True when `algorithm` names the single supported KDF.
fn is_supported(algorithm: &str) -> bool {
    algorithm.eq_ignore_ascii_case(SUPPORTED_ALGORITHM)
}

/// Inputs for [`create_challenge`].
///
/// Entropy and time are supplied by the caller: the engine is sans-IO and never
/// reaches for a random source or a clock.
pub struct CreateRequest<'a> {
    /// Key-derivation algorithm; callers pass [`SUPPORTED_ALGORITHM`].
    pub algorithm: &'a str,
    /// PBKDF2 iteration count (the main work knob).
    pub cost: u32,
    /// Derived key length in bytes (upstream default 32).
    pub key_length: usize,
    /// Hex prefix the derived key must match (longer = more work per solve).
    pub key_prefix: &'a str,
    /// Lifetime in seconds from `now_ms`; `<= 0` means no expiry.
    pub ttl_secs: i64,
    /// The client's HMAC secret; the signature binds every parameter to it.
    pub secret: &'a str,
    /// Signed metadata (`client`, `purpose`, `flow`). Serialised with sorted keys.
    pub data: BTreeMap<String, serde_json::Value>,
    /// Caller-supplied 16-byte nonce.
    pub nonce: [u8; 16],
    /// Caller-supplied 16-byte salt.
    pub salt: [u8; 16],
    /// Caller-supplied Unix time in milliseconds.
    pub now_ms: i64,
}

/// Create a signed challenge.
///
/// Pure and infallible: the caller has already validated the client's
/// parameters, and the signature covers exactly what was passed in.
pub fn create_challenge(req: CreateRequest<'_>) -> Challenge {
    let expires_at = (req.ttl_secs > 0).then(|| req.now_ms / 1000 + req.ttl_secs);
    let parameters = ChallengeParameters {
        algorithm: req.algorithm.to_string(),
        cost: req.cost,
        data: (!req.data.is_empty()).then_some(req.data),
        expires_at,
        key_length: req.key_length,
        key_prefix: req.key_prefix.to_ascii_lowercase(),
        key_signature: None,
        memory_cost: None,
        nonce: hex::encode(req.nonce),
        parallelism: None,
        salt: hex::encode(req.salt),
    };
    let signature = hex::encode(hmac_sha256(
        req.secret.as_bytes(),
        canonical_json(&parameters).as_bytes(),
    ));
    Challenge {
        parameters,
        signature: Some(signature),
    }
}

/// Inputs for [`verify_solution`].
pub struct VerifyRequest<'a> {
    /// The challenge echoed by the client.
    pub challenge: &'a Challenge,
    /// The solution the client submitted.
    pub solution: &'a Solution,
    /// The signer's HMAC secret, resolved from the challenge's `data.client`.
    pub secret: &'a str,
    /// Caller-supplied Unix time in milliseconds.
    pub now_ms: i64,
    /// The purpose the protected action expects (from its signed `data`).
    pub expected_purpose: &'a str,
    /// The flow the protected action expects (from its signed `data`).
    pub expected_flow: &'a str,
}

/// A verified proof, carrying the authenticated context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The challenge nonce, which identifies this proof for single-use consume.
    pub nonce: String,
    /// The signed purpose.
    pub purpose: String,
    /// The signed flow.
    pub flow: String,
}

/// Verify a submitted solution.
///
/// Checks, in order: expiry; signature presence; signature validity over the
/// canonical parameters; a supported algorithm; the signed `purpose`/`flow`;
/// and only then the derived key. The KDF therefore runs at most once, on
/// server-chosen parameters, after the signature has authenticated them.
pub fn verify_solution(req: VerifyRequest<'_>) -> Result<Verified, ProofError> {
    let params = &req.challenge.parameters;

    // 1. Expiry. `0`/absent means never; the challenge is spent as soon as `now`
    // passes `expiresAt` (whole seconds, matching upstream).
    if let Some(expires_at) = params.expires_at.filter(|&t| t != 0)
        && req.now_ms / 1000 > expires_at
    {
        return Err(ProofError::Expired);
    }

    // 2. Signature presence.
    let signature = req
        .challenge
        .signature
        .as_deref()
        .ok_or(ProofError::MissingSignature)?;

    // 3. Signature validity over the canonical parameters.
    let expected = hex::encode(hmac_sha256(
        req.secret.as_bytes(),
        canonical_json(params).as_bytes(),
    ));
    if !constant_time_eq_hex(signature, &expected) {
        return Err(ProofError::BadSignature);
    }

    // 4. Algorithm. The signature has already proved the server chose it, but a
    // client configured for another algorithm must not be verifiable here.
    if !is_supported(&params.algorithm) {
        return Err(ProofError::UnsupportedAlgorithm);
    }

    // 5. Signed purpose/flow binding. `data` is covered by the signature, so
    // this is a trustworthy context check, done before the KDF.
    let data = params.data.as_ref().ok_or(ProofError::WrongContext)?;
    let purpose = data.get("purpose").and_then(|v| v.as_str()).unwrap_or("");
    let flow = data.get("flow").and_then(|v| v.as_str()).unwrap_or("");
    if purpose != req.expected_purpose || flow != req.expected_flow {
        return Err(ProofError::WrongContext);
    }

    // 6. Solution: re-derive once from the submitted counter and require both an
    // exact key match and the signed prefix. Malformed hex is an invalid
    // solution, never an error.
    let nonce = hex::decode(&params.nonce).map_err(|_| ProofError::BadSolution)?;
    let salt = hex::decode(&params.salt).map_err(|_| ProofError::BadSolution)?;
    let password = build_password(&nonce, req.solution.counter);
    let derived = derive_key(params.cost, params.key_length, &salt, &password);
    let derived_hex = hex::encode(&derived);
    if !constant_time_eq_hex(&derived_hex, &req.solution.derived_key)
        || !key_prefix_matches(&params.key_prefix, &derived)
    {
        return Err(ProofError::BadSolution);
    }

    Ok(Verified {
        nonce: params.nonce.clone(),
        purpose: purpose.to_string(),
        flow: flow.to_string(),
    })
}

/// Solve a challenge by brute force: the first counter whose derived key matches
/// the signed prefix.
///
/// Test-only. The production solver is the ALTCHA widget; this exists so the
/// engine's own tests and fixtures can produce a valid solution without a
/// browser. It is not compiled unless the `test-util` feature is on.
#[cfg(feature = "test-util")]
pub fn solve_challenge(challenge: &Challenge) -> Solution {
    let params = &challenge.parameters;
    let nonce = hex::decode(&params.nonce).expect("challenge nonce is hex");
    let salt = hex::decode(&params.salt).expect("challenge salt is hex");
    for counter in 0u32.. {
        let password = build_password(&nonce, counter);
        let derived = derive_key(params.cost, params.key_length, &salt, &password);
        if key_prefix_matches(&params.key_prefix, &derived) {
            return Solution {
                counter,
                derived_key: hex::encode(&derived),
                time: None,
            };
        }
    }
    unreachable!("uint32 counter space is exhausted")
}

/// Derive the key for one counter with PBKDF2-HMAC-SHA-256.
fn derive_key(cost: u32, key_length: usize, salt: &[u8], password: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; key_length];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, cost, &mut out);
    out
}

/// The KDF password: `nonce || counter`, the counter as 4 big-endian bytes.
fn build_password(nonce: &[u8], counter: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(nonce.len() + 4);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&counter.to_be_bytes());
    buf
}

/// Does the derived key satisfy the signed hex prefix?
///
/// Even-length prefixes are compared as bytes; an odd-length prefix is compared
/// as hex text, case-insensitively — matching upstream's two matcher arms.
fn key_prefix_matches(prefix: &str, derived: &[u8]) -> bool {
    if prefix.len().is_multiple_of(2) {
        match hex::decode(prefix) {
            Ok(bytes) => derived.starts_with(&bytes),
            Err(_) => false,
        }
    } else if !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        false
    } else {
        let hex = hex::encode(derived);
        hex.len() >= prefix.len()
            && hex.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
    }
}

/// `HMAC-SHA256(key, data)`.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Constant-time equality for hex strings, compared as bytes.
fn constant_time_eq_hex(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Canonical JSON: object keys sorted recursively, matching upstream's signer.
fn canonical_json<T: serde::Serialize>(value: &T) -> String {
    let value = serde_json::to_value(value).expect("challenge parameters serialise");
    serde_json::to_string(&sort_keys(value)).expect("canonical JSON serialises")
}

/// Recursively sort object keys.
fn sort_keys(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<String, serde_json::Value> =
                map.into_iter().map(|(k, v)| (k, sort_keys(v))).collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(sort_keys).collect())
        }
        other => other,
    }
}
