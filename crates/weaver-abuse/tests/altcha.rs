//! Engine tests for ALTCHA challenge creation and solution verification.
//!
//! These exercise the pure engine directly — no server, no store — using the
//! test-only brute-force solver. The cross-implementation check against the
//! official `altcha` crate lives in `tests/interop.rs`.

use std::collections::BTreeMap;

use proptest::prelude::*;
use weaver_abuse::Verified;
use weaver_abuse::altcha::{
    Challenge, CreateRequest, ProofError, SUPPORTED_ALGORITHM, VerifyRequest, create_challenge,
    solve_challenge, verify_solution,
};

const SECRET: &str = "unit-test-secret";
const NOW_MS: i64 = 1_700_000_000_000;

fn data(purpose: &str, flow: &str) -> BTreeMap<String, serde_json::Value> {
    BTreeMap::from([
        ("client".to_string(), "client-key".into()),
        ("purpose".to_string(), purpose.into()),
        ("flow".to_string(), flow.into()),
    ])
}

fn challenge(algorithm: &str, ttl_secs: i64) -> Challenge {
    create_challenge(CreateRequest {
        algorithm,
        cost: 10,
        key_length: 32,
        key_prefix: "00",
        ttl_secs,
        secret: SECRET,
        data: data("diagnostic", "flow-1"),
        nonce: [7u8; 16],
        salt: [9u8; 16],
        now_ms: NOW_MS,
    })
}

fn verify(ch: &Challenge, now_ms: i64) -> Result<Verified, ProofError> {
    let solution = solve_challenge(ch);
    verify_solution(VerifyRequest {
        challenge: ch,
        solution: &solution,
        secret: SECRET,
        now_ms,
        expected_purpose: "diagnostic",
        expected_flow: "flow-1",
    })
}

#[test]
fn valid_solution_verifies() {
    let ch = challenge(SUPPORTED_ALGORITHM, 300);
    let verified = verify(&ch, NOW_MS).expect("a freshly solved challenge verifies");
    assert_eq!(verified.purpose, "diagnostic");
    assert_eq!(verified.flow, "flow-1");
    assert_eq!(verified.nonce, ch.parameters.nonce);
    // The nonce identifies the proof for single-use consumption.
    assert!(!verified.nonce.is_empty());
}

#[test]
fn signature_is_deterministic_for_fixed_entropy() {
    // Given the same nonce/salt/params, the canonical JSON and HMAC are stable.
    assert_eq!(
        challenge(SUPPORTED_ALGORITHM, 300).signature,
        challenge(SUPPORTED_ALGORITHM, 300).signature
    );
}

#[test]
fn wrong_secret_is_rejected() {
    let ch = challenge(SUPPORTED_ALGORITHM, 300);
    let solution = solve_challenge(&ch);
    let err = verify_solution(VerifyRequest {
        challenge: &ch,
        solution: &solution,
        secret: "a-different-secret",
        now_ms: NOW_MS,
        expected_purpose: "diagnostic",
        expected_flow: "flow-1",
    })
    .unwrap_err();
    assert_eq!(err, ProofError::BadSignature);
}

#[test]
fn tampered_work_parameters_are_rejected() {
    // Changing the signed cost (a cheaper challenge) breaks the signature, even
    // though the solution is recomputed against the tampered parameters.
    let mut ch = challenge(SUPPORTED_ALGORITHM, 300);
    ch.parameters.cost = 1;
    let solution = solve_challenge(&ch);
    let err = verify_solution(VerifyRequest {
        challenge: &ch,
        solution: &solution,
        secret: SECRET,
        now_ms: NOW_MS,
        expected_purpose: "diagnostic",
        expected_flow: "flow-1",
    })
    .unwrap_err();
    assert_eq!(err, ProofError::BadSignature);
}

#[test]
fn tampered_signed_data_is_rejected() {
    let mut ch = challenge(SUPPORTED_ALGORITHM, 300);
    ch.parameters
        .data
        .as_mut()
        .unwrap()
        .insert("flow".to_string(), "evil".into());
    assert_eq!(verify(&ch, NOW_MS).unwrap_err(), ProofError::BadSignature);
}

#[test]
fn unsigned_challenge_is_rejected() {
    let mut ch = challenge(SUPPORTED_ALGORITHM, 300);
    ch.signature = None;
    assert_eq!(
        verify(&ch, NOW_MS).unwrap_err(),
        ProofError::MissingSignature
    );
}

#[test]
fn expired_challenge_is_rejected() {
    let ch = challenge(SUPPORTED_ALGORITHM, 60);
    let just_inside = NOW_MS + 60_000;
    let just_past = NOW_MS + 61_000;
    assert!(verify(&ch, just_inside).is_ok());
    assert_eq!(verify(&ch, just_past).unwrap_err(), ProofError::Expired);
}

#[test]
fn challenge_without_expiry_is_accepted_much_later() {
    let ch = challenge(SUPPORTED_ALGORITHM, 0);
    assert!(ch.parameters.expires_at.is_none());
    assert!(verify(&ch, NOW_MS + 10_000_000).is_ok());
}

#[test]
fn wrong_flow_is_rejected_before_solving() {
    let ch = challenge(SUPPORTED_ALGORITHM, 300);
    let solution = solve_challenge(&ch);
    let err = verify_solution(VerifyRequest {
        challenge: &ch,
        solution: &solution,
        secret: SECRET,
        now_ms: NOW_MS,
        expected_purpose: "diagnostic",
        expected_flow: "some-other-flow",
    })
    .unwrap_err();
    assert_eq!(err, ProofError::WrongContext);
}

#[test]
fn unsupported_algorithm_is_rejected() {
    // Signed with the right secret and solved, but the algorithm is not one we
    // implement: refused before any solution check.
    let ch = challenge("ARGON2ID", 300);
    assert_eq!(
        verify(&ch, NOW_MS).unwrap_err(),
        ProofError::UnsupportedAlgorithm
    );
}

#[test]
fn bad_solution_is_rejected() {
    let ch = challenge(SUPPORTED_ALGORITHM, 300);
    let mut solution = solve_challenge(&ch);
    solution.derived_key = "00".repeat(32);
    let err = verify_solution(VerifyRequest {
        challenge: &ch,
        solution: &solution,
        secret: SECRET,
        now_ms: NOW_MS,
        expected_purpose: "diagnostic",
        expected_flow: "flow-1",
    })
    .unwrap_err();
    assert_eq!(err, ProofError::BadSolution);
}

proptest! {
    /// Any change to the signed `cost` invalidates the signature, regardless of
    /// the value chosen.
    #[test]
    fn any_tampered_cost_is_rejected(cost in 1u32..=20) {
        let mut ch = challenge(SUPPORTED_ALGORITHM, 300);
        prop_assume!(cost != ch.parameters.cost);
        ch.parameters.cost = cost;
        let solution = solve_challenge(&ch);
        let result = verify_solution(VerifyRequest {
            challenge: &ch,
            solution: &solution,
            secret: SECRET,
            now_ms: NOW_MS,
            expected_purpose: "diagnostic",
            expected_flow: "flow-1",
        });
        prop_assert_eq!(result.unwrap_err(), ProofError::BadSignature);
    }
}
