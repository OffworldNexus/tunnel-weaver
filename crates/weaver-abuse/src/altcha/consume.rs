//! The consumer entry point: verify a presented proof and consume it once.
//!
//! This is the narrow contract a protected application calls. It resolves the
//! client, verifies the signature, expiry, signed context and solution, and
//! atomically consumes the proof — returning a *result*, never deciding a
//! response. Whether a missing or invalid proof should refuse the caller's
//! action, and with which status, is the caller's policy, not the abuse
//! engine's: the relay never blocks a request *because of* proof-of-work.

use crate::altcha::pow::{Verified, VerifyRequest, verify_solution};
use crate::altcha::store::{ConsumeKey, ConsumeOutcome, ProofStore};
use crate::altcha::types::{Payload, ProofError};
use crate::store::StoreError;

/// How long a spent marker lives when a challenge carries no expiry.
///
/// Our challenges always carry a TTL, so this only bounds the pathological case:
/// without it, a no-expiry challenge would create a permanent row.
const NO_EXPIRY_MARKER_MS: i64 = 60 * 60 * 1000;

/// Why a proof was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AltchaError {
    /// The proof itself was refused: unknown or revoked client, unsupported
    /// algorithm, bad signature, expired, wrong context, bad solution, or spent.
    #[error("proof refused: {0}")]
    Proof(ProofError),
    /// The proof store failed. The caller must not authorize the action, and
    /// should surface a temporary-unavailable signal.
    #[error("proof store unavailable: {0}")]
    Store(StoreError),
}

/// A proof presented by a client, plus the context the action expects it bound to.
pub struct ConsumeRequest<'a> {
    /// The client public key named by the payload's signed `data.client`.
    pub client: &'a str,
    /// The decoded `{ challenge, solution }` payload.
    pub payload: &'a Payload,
    /// The purpose the protected action expects (checked against the signed `data`).
    pub purpose: &'a str,
    /// The flow the protected action expects (checked against the signed `data`).
    pub flow: &'a str,
    /// Caller-supplied Unix time in milliseconds.
    pub now_ms: i64,
}

/// Verify a presented proof and consume it exactly once.
///
/// Resolves the client, checks its approved algorithm, verifies the challenge
/// (expiry, signature, signed purpose/flow, then the solution), and records the
/// single-use marker. The KDF runs at most once, on server-approved parameters.
pub async fn verify_and_consume<S: ProofStore>(
    store: &S,
    request: ConsumeRequest<'_>,
) -> Result<Verified, AltchaError> {
    // Resolve the client by the public key named inside the (unverified) payload.
    let client = match store.client(request.client).await {
        Ok(Some(client)) => client,
        Ok(None) => return Err(AltchaError::Proof(ProofError::UnknownClient)),
        Err(err) => return Err(AltchaError::Store(err)),
    };

    // The client's configured algorithm is the only one it may be verified with.
    if !request
        .payload
        .challenge
        .parameters
        .algorithm
        .eq_ignore_ascii_case(&client.algorithm)
    {
        return Err(AltchaError::Proof(ProofError::UnsupportedAlgorithm));
    }

    let verified = verify_solution(VerifyRequest {
        challenge: &request.payload.challenge,
        solution: &request.payload.solution,
        secret: &client.secret,
        now_ms: request.now_ms,
        expected_purpose: request.purpose,
        expected_flow: request.flow,
    })
    .map_err(AltchaError::Proof)?;

    // Consume exactly once; the marker lives until the challenge expires.
    let expires_at_ms = request
        .payload
        .challenge
        .parameters
        .expires_at
        .filter(|&t| t != 0)
        .map(|secs| secs.saturating_mul(1000))
        .unwrap_or_else(|| request.now_ms.saturating_add(NO_EXPIRY_MARKER_MS));
    match store
        .consume(
            ConsumeKey {
                public_key: request.client,
                nonce: &verified.nonce,
                expires_at_ms,
            },
            request.now_ms,
        )
        .await
    {
        Ok(ConsumeOutcome::Consumed) => Ok(verified),
        Ok(ConsumeOutcome::AlreadySpent) => Err(AltchaError::Proof(ProofError::Spent)),
        Err(err) => Err(AltchaError::Store(err)),
    }
}
