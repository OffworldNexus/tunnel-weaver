//! Authentication levels, proofs and the gate (WVR-167).
//!
//! This mirrors the auth-levels-and-proofs design used in `jonator`
//! (`people/auth/{levels,paths,manager,gate}.py`): the session's authentication
//! is a *level* derived from the *proofs* still alive on it, not a flag stored
//! anywhere.
//!
//! - [`level`]: the ordered [`AuthLevel`] enum. `Basic` is "one factor, the
//!   password", `Strong` is "the second factor is alive".
//! - [`proof`]: the [`ProofKind`] set and each kind's lifetime. WVR-167 uses
//!   `password` and `email_otp`; WVR-163 adds the two a passkey assertion
//!   writes; WVR-166 adds `totp`, the authenticator app's code. WVR-164/165 add
//!   kinds, never a redesign.
//! - [`paths`]: the [`AuthPath`] trait — *how* one authenticates, the level it
//!   currently grants and the steps it offers to climb. Three concrete paths
//!   exist: password + second factor (an emailed code, or one from an
//!   authenticator app), and passkeys (WVR-163).
//! - [`manager`]: the per-request [`AuthManager`], sole owner of the audit
//!   trail (the `auth_event` rows that are also the level's source) and the
//!   session plumbing.
//! - [`gate`]: the deny-by-default middleware over `/api/account/*` that
//!   refuses a session below the level a route requires, naming the level and
//!   the upgrade options in response headers.
//! - [`watch`]: the `GET /api/account/me` event stream — the session's level,
//!   the way up to every higher one, and each drop announced before it lands.
//!
//! The rule the whole plane exists to enforce: **a second factor is never
//! optional**. A session that has only proven the password can do exactly one
//! thing besides leaving — climb to `Strong` by entering an emailed code.

pub mod gate;
pub mod level;
pub mod manager;
pub mod paths;
pub mod proof;
pub mod watch;

use std::net::SocketAddr;

pub use gate::gate;
pub use level::AuthLevel;
pub use manager::{AuthManager, SessionContext};
pub use paths::{PATHS, Situation, Step, StepKind, level_of};
pub use proof::ProofKind;

/// The kind of an `auth_event` row.
///
/// The rows are simultaneously the audit trail and the raw material the level
/// is derived from: the `password`, `email_otp`, `totp`, `passkey` and
/// `passkey_user_verification` kinds are proofs (see [`ProofKind`]), the rest
/// are recorded for the record's sake. Adding a kind is a value, not a
/// migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// The password was checked and a session opened (first factor).
    Password,
    /// The password was checked again on a live session to step up to
    /// `Certain` — the `confirm_password` step (WVR-165).
    PasswordConfirmed,
    /// A step-up password check was refused; the session stays where it was.
    PasswordConfirmFailed,
    /// The email factor was engaged — a code was issued or re-sent.
    EmailOtpIssued,
    /// An emailed code was accepted.
    EmailOtp,
    /// An emailed code was refused (wrong, expired or attempt-capped).
    EmailOtpFailed,
    /// A code from an authenticator app was accepted (WVR-166) — the same
    /// second factor as an emailed code, reached through a shared secret.
    Totp,
    /// A code from an authenticator app was refused (wrong, replayed, capped, or
    /// the app's secret could not be read). The session keeps whatever it had.
    TotpFailed,
    /// A passkey assertion was accepted, and the credential it named is the
    /// session's now (WVR-163) — the possession factor.
    Passkey,
    /// A passkey assertion was accepted *with user verification*: the
    /// authenticator checked the person (biometric or PIN) as it signed
    /// (WVR-163). Recorded alongside [`EventKind::Passkey`], never instead of
    /// it, so the trail says whether the assertion really was a full one.
    PasskeyUserVerification,
    /// A passkey assertion was refused (unknown credential, wrong account,
    /// failed verification, or a replay). The session keeps whatever it had.
    PasskeyFailed,
    /// A password check failed, before any session existed.
    LoginFailed,
    /// The session was closed; proofs before it cannot be revived.
    Logout,
}

impl EventKind {
    /// Every kind, for parsing a stored row.
    pub const ALL: [EventKind; 13] = [
        EventKind::Password,
        EventKind::PasswordConfirmed,
        EventKind::PasswordConfirmFailed,
        EventKind::EmailOtpIssued,
        EventKind::EmailOtp,
        EventKind::EmailOtpFailed,
        EventKind::Totp,
        EventKind::TotpFailed,
        EventKind::Passkey,
        EventKind::PasskeyUserVerification,
        EventKind::PasskeyFailed,
        EventKind::LoginFailed,
        EventKind::Logout,
    ];

    /// The stable string stored in `auth_event.kind`.
    pub const fn as_str(self) -> &'static str {
        match self {
            EventKind::Password => "password",
            EventKind::PasswordConfirmed => "password_confirmed",
            EventKind::PasswordConfirmFailed => "password_confirm_failed",
            EventKind::EmailOtpIssued => "email_otp_issued",
            EventKind::EmailOtp => "email_otp",
            EventKind::EmailOtpFailed => "email_otp_failed",
            EventKind::Totp => "totp",
            EventKind::TotpFailed => "totp_failed",
            EventKind::Passkey => "passkey",
            EventKind::PasskeyUserVerification => "passkey_user_verification",
            EventKind::PasskeyFailed => "passkey_failed",
            EventKind::LoginFailed => "login_failed",
            EventKind::Logout => "logout",
        }
    }

    /// Parses a stored `auth_event.kind`.
    pub fn parse(kind: &str) -> Option<Self> {
        EventKind::ALL.into_iter().find(|k| k.as_str() == kind)
    }

    /// The proof this event records — what the level is derived from, or `None`
    /// for an event that only has to be on the record. Several events can feed
    /// the same proof: a sign-in and a step-up both prove the password, and the
    /// later one is what the level reads.
    pub const fn proof(self) -> Option<ProofKind> {
        match self {
            EventKind::Password | EventKind::PasswordConfirmed => Some(ProofKind::Password),
            EventKind::EmailOtp => Some(ProofKind::EmailOtp),
            EventKind::Totp => Some(ProofKind::Totp),
            EventKind::Passkey => Some(ProofKind::Passkey),
            EventKind::PasskeyUserVerification => Some(ProofKind::PasskeyUserVerification),
            EventKind::PasswordConfirmFailed
            | EventKind::EmailOtpIssued
            | EventKind::EmailOtpFailed
            | EventKind::TotpFailed
            | EventKind::PasskeyFailed
            | EventKind::LoginFailed
            | EventKind::Logout => None,
        }
    }
}

/// One step of an upgrade option as the wire spells it.
///
/// `reaches` is where taking the step would leave the session, which the
/// server works out from the proofs it holds now: it is not a property of the
/// step alone. WVR-165 adds no field here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct WireStep {
    /// The stable step name.
    pub step: &'static str,
    /// The level the session would hold once this step is taken.
    pub reaches: &'static str,
}

/// The peer address of the request.
///
/// Inserted into request extensions by the edge so the [`AuthManager`] can
/// record it on every `auth_event` row. It travels as a request extension
/// rather than an extractor because the raw-hyper edge is the only layer that
/// knows the socket address; the axum router never sees a `ConnectInfo`.
#[derive(Debug, Clone, Copy)]
pub struct ClientAddr(pub SocketAddr);
