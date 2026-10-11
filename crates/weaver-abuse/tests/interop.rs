//! Interoperability seal against the official `altcha` crate (test-only).
//!
//! This is the trust anchor for our protocol correctness: the official crate is
//! itself validated against the `altcha-lib` JS reference, so if a challenge we
//! produce is solvable and verifiable *by it*, and a challenge it produces is
//! solvable and verifiable *by us*, and both solvers agree bit-for-bit on the
//! derived key, our wire format, canonical JSON, HMAC and KDF are right.
//!
//! The production engine never depends on this crate; it is a dev-dependency.

use std::collections::BTreeMap;

use altcha::{
    CreateChallengeOptions, SolveChallengeOptions, VerifySolutionOptions, create_challenge,
    solve_challenge, verify_solution,
};
use weaver_abuse::altcha::{
    Challenge, CreateRequest, VerifyRequest, create_challenge as our_create,
    solve_challenge as our_solve, verify_solution as our_verify,
};

const SECRET: &str = "interop-secret";
const COST: u32 = 100;

fn data() -> BTreeMap<String, serde_json::Value> {
    BTreeMap::from([
        ("client".to_string(), "interop-client".into()),
        ("purpose".to_string(), "diagnostic".into()),
        ("flow".to_string(), "interop-flow".into()),
    ])
}

/// A fixed challenge from our engine (no expiry, so neither the official crate's
/// real clock nor ours can make it stale).
fn our_challenge() -> Challenge {
    our_create(CreateRequest {
        algorithm: "PBKDF2/SHA-256",
        cost: COST,
        key_length: 32,
        key_prefix: "00",
        ttl_secs: 0,
        secret: SECRET,
        data: data(),
        nonce: [0x11; 16],
        salt: [0x22; 16],
        now_ms: 0,
    })
}

/// Re-encode between the two crates' identical wire shapes.
fn upstream_challenge(challenge: &Challenge) -> altcha::Challenge {
    serde_json::from_value(serde_json::to_value(challenge).unwrap()).unwrap()
}

fn our_challenge_from(upstream: &altcha::Challenge) -> Challenge {
    serde_json::from_value(serde_json::to_value(upstream).unwrap()).unwrap()
}

fn our_solution_from(upstream: &altcha::Solution) -> weaver_abuse::altcha::Solution {
    serde_json::from_value(serde_json::to_value(upstream).unwrap()).unwrap()
}

fn upstream_solution_from(ours: &weaver_abuse::altcha::Solution) -> altcha::Solution {
    serde_json::from_value(serde_json::to_value(ours).unwrap()).unwrap()
}

fn our_verify_ok(challenge: &Challenge, solution: &weaver_abuse::altcha::Solution) {
    let verified = our_verify(VerifyRequest {
        challenge,
        solution,
        secret: SECRET,
        now_ms: 1_700_000_000_000,
        expected_purpose: "diagnostic",
        expected_flow: "interop-flow",
    })
    .expect("our engine accepts an upstream-produced solution");
    assert_eq!(verified.flow, "interop-flow");
}

#[test]
fn our_challenge_is_solved_and_verified_by_the_official_crate() {
    let challenge = our_challenge();
    let upstream = upstream_challenge(&challenge);

    let solution = solve_challenge(SolveChallengeOptions::new(&upstream))
        .expect("upstream solve_challenge")
        .expect("a solution exists");
    let result = verify_solution(VerifySolutionOptions::new(&upstream, &solution, SECRET))
        .expect("upstream verify_solution");
    assert!(result.verified, "official crate must accept our challenge");

    // Our engine accepts the official solver's solution too.
    our_verify_ok(&challenge, &our_solution_from(&solution));
}

#[test]
fn an_official_challenge_is_solved_and_verified_by_us() {
    let upstream = create_challenge(CreateChallengeOptions {
        algorithm: "PBKDF2/SHA-256".to_string(),
        cost: COST,
        key_prefix: "00".to_string(),
        data: Some(data()),
        hmac_signature_secret: Some(SECRET.to_string()),
        ..Default::default()
    })
    .expect("upstream create_challenge");
    let challenge = our_challenge_from(&upstream);

    // Our brute-force solver finds a counter; our engine verifies it...
    let solution = our_solve(&challenge);
    our_verify_ok(&challenge, &solution);

    // ...and the official crate verifies the very same solution.
    let result = verify_solution(VerifySolutionOptions::new(
        &upstream,
        &upstream_solution_from(&solution),
        SECRET,
    ))
    .expect("upstream verify_solution");
    assert!(result.verified, "official crate must accept our solution");
}

#[test]
fn both_solvers_agree_on_counter_and_derived_key() {
    let challenge = our_challenge();
    let upstream = upstream_challenge(&challenge);

    let ours = our_solve(&challenge);
    let theirs = solve_challenge(SolveChallengeOptions::new(&upstream))
        .expect("upstream solve_challenge")
        .expect("a solution exists");

    // Deterministic iteration from counter 0 must land on the same solution.
    assert_eq!(ours.counter, theirs.counter);
    assert_eq!(ours.derived_key, theirs.derived_key);
}

/// A frozen cross-implementation vector: the fixed challenge `our_challenge()`
/// produces, and the counter and derived key the official crate finds for it.
///
/// Guards against any drift in the canonical JSON, the HMAC, the KDF or the
/// password/counter encoding — a change to any of them breaks this.
#[test]
fn known_answer_vector_matches_the_official_implementation() {
    let challenge: Challenge = serde_json::from_str(
        r#"{"parameters":{"algorithm":"PBKDF2/SHA-256","cost":100,"data":{"client":"interop-client","flow":"interop-flow","purpose":"diagnostic"},"keyLength":32,"keyPrefix":"00","nonce":"11111111111111111111111111111111","salt":"22222222222222222222222222222222"},"signature":"2c458bb0e605cee46b27cbf049142c3afc85a1ae3de689f881615891c42e32e0"}"#,
    )
    .expect("valid golden challenge");

    let solution = our_solve(&challenge);
    assert_eq!(solution.counter, 585);
    assert_eq!(
        solution.derived_key,
        "0041cb86c0febb9fcbe9ebe2e4a39fc8a15705d0d3ed51706eea999bd773d678"
    );
    our_verify_ok(&challenge, &solution);
}
