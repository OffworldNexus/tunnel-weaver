//! ALTCHA v3 proof-of-work: challenge creation, verification and single use.
//!
//! This module implements the *server* half of the official ALTCHA v3 /
//! `altcha-lib` v2 protocol — enough of it for the unmodified
//! `<altcha-widget>` to solve a challenge and for the engine to verify the
//! solution it submits. It targets one algorithm, `PBKDF2/SHA-256`, chosen for
//! being real work per counter while staying small and dependency-light to
//! implement correctly in Rust.
//!
//! Everything here is pure and sans-IO: challenge creation takes caller-supplied
//! entropy (nonce + salt) and time (`now_ms`), verification takes caller-supplied
//! time, and both return plain data. The engine never reads a clock or an RNG,
//! and it never touches a database — persistence is the injected
//! [`ProofStore`].
//!
//! # Ownership
//!
//! The engine owns the *capability*: it issues challenges, verifies solutions
//! and consumes a proof exactly once. It does **not** decide whether a missing
//! or invalid proof should refuse a request — that is the protected
//! application's policy. [`verify_and_consume`] returns a
//! [`Result`], and the caller maps it to its own response.
//!
//! # Wire shape
//!
//! Field names and nesting are pinned to upstream source, not guessed. A
//! challenge is `{ parameters, signature }`, the parameters carry the
//! algorithm, `cost`, `keyLength`, `keyPrefix`, `nonce`, `salt` and optional
//! `expiresAt`/`data`, and the submitted payload is `{ challenge, solution }`
//! with `solution = { counter, derivedKey }`. The signature is
//! `HMAC-SHA256(secret, canonical_json(parameters))` over recursively
//! key-sorted JSON, so it authenticates every parameter — including the work
//! parameters and the signed `data` context.
//!
//! # Why the order of verification matters
//!
//! [`verify_solution`] rejects expiry, a missing signature, a bad signature and
//! a wrong `data` context *before* it derives a key. The expensive KDF only runs
//! once the signature has proved that `algorithm`/`cost`/`keyLength`/`keyPrefix`
//! were chosen by the server, so a caller can never force the relay to burn
//! unbounded CPU on attacker-chosen parameters.

mod consume;
mod pow;
mod store;
mod types;

pub use consume::{AltchaError, ConsumeRequest, verify_and_consume};
#[cfg(feature = "test-util")]
pub use pow::solve_challenge;
pub use pow::{
    CreateRequest, SUPPORTED_ALGORITHM, Verified, VerifyRequest, create_challenge,
    try_solve_challenge, verify_solution,
};
pub use store::{AltchaClient, ConsumeKey, ConsumeOutcome, ProofStore};
pub use types::{
    Challenge, ChallengeParameters, CounterMode, HmacAlgorithm, Payload, ProofError, Solution,
};
