//! Sans-IO safety middleware for the relay's own web surface.
//!
//! The relay is protected by a **pipeline of collaborating passes** over a
//! shared [`RequestContext`]. Each pass sees what earlier passes observed —
//! findings, the request's [`Fingerprint`], the selected view — and either
//! continues or stops the pipeline with a [`Decision`] (`Allow`, `Block`,
//! `Throttle`, …). The server maps that one decision to a response and knows
//! none of the rules.
//!
//! # Pieces
//!
//! * [`rule`] / [`Rule`]: reusable predicates (the scanner firewall catalogue)
//!   that emit [`Finding`]s.
//! * [`Pass`] / [`Pipeline`] and the built-in [`ScannerPass`] and [`BudgetPass`].
//! * [`Gcra`] / [`Quota`] / [`Policy`]: the per-key rate-limit engine, charged
//!   through an injected [`BudgetStore`].
//! * [`Surface`] / [`ViewId`] / [`Route`]: what was requested, and which budget
//!   applies.
//! * [`altcha`]: the proof-of-work engine — challenge creation, solution
//!   verification, and atomic single-use consumption, exposed as a
//!   [`verify_and_consume`] capability the protected application calls.
//!
//! # What the crate does not do
//!
//! * read time or randomness — the caller supplies `now_ms` and entropy;
//! * talk to a database, tokio, or the network — that is [`BudgetStore`] and
//!   [`ProofStore`];
//! * decide HTTP responses — the server maps [`Decision`].
#![forbid(clippy::disallowed_methods)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod altcha;
mod context;
mod gate;
mod gcra;
mod key;
mod pass;
mod passes;
mod policy;
mod rule;
pub mod scanner;
mod store;
mod surface;

#[cfg(feature = "test-util")]
pub mod testing;

#[cfg(feature = "test-util")]
pub use altcha::solve_challenge;
pub use altcha::{
    AltchaClient, AltchaError, Challenge, ConsumeKey, ConsumeOutcome, ConsumeRequest,
    CreateRequest, Payload, ProofError, ProofStore, Verified, VerifyRequest, create_challenge,
    try_solve_challenge, verify_and_consume, verify_solution,
};
pub use context::RequestContext;
pub use gate::{Admission, Gate, GateError};
pub use gcra::{Charge, Gcra, Outcome, Quota, Rate, Snapshot};
pub use key::{Fingerprint, Key, KeyKind, PeerMasks, fingerprint, fingerprint_with};
pub use pass::{Decision, Pass, PassOutcome, Pipeline};
pub use passes::{BudgetPass, ScannerPass};
pub use policy::{
    Budget, CostRule, Policy, PolicyId, PolicySet, Route, RouteTable, StoreErrorPolicy, ViewId,
};
pub use rule::{Finding, Rule, ScannerRule, Severity};
pub use scanner::ScanVerdict;
pub use store::{BudgetStore, StoreError};
pub use surface::{Host, Scheme, Surface, bounded_path, is_exempt};
