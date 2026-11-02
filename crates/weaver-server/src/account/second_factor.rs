//! The emailed one-time code, for a sign-in or an address verification
//! (WVR-167, WVR-169).
//!
//! One mechanism serves two purposes. A password check opens a `Basic` session;
//! `sign_in` issues the code that lifts it to `Strong`. A signup has no session
//! yet; `verify_address` issues the code that proves the mailbox and settles the
//! address. The code policy lives in [`crate::email::otp`] and is shared with
//! the setup/configure flow: six digits, hashed at rest, a five-minute lifetime,
//! five attempts, single use.
//!
//! A code is stored per *flow* — a session or a pending registration — so only
//! the newest code is accepted: re-sending replaces it. Only the purpose varies
//! what accepting it does beyond proving the mailbox.

use crate::email::otp::{self, OTP_MAX_ATTEMPTS, OTP_TTL_SECS};
use crate::store::account::NewLoginChallenge;
use crate::store::entity::login_challenge;
use crate::store::{Store, StoreError};

/// Which flow a challenge belongs to: the identity its uniqueness follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// The second factor of a browser session's sign-in.
    Session(i32),
    /// Proving ownership of a pending registration's address.
    PendingRegistration(i32),
}

impl Flow {
    /// The session column, for the one flow that has a session.
    fn session_id(self) -> Option<i32> {
        match self {
            Flow::Session(id) => Some(id),
            Flow::PendingRegistration(_) => None,
        }
    }

    /// The pending-registration column, for the one flow that has one.
    fn pending_registration_id(self) -> Option<i32> {
        match self {
            Flow::PendingRegistration(id) => Some(id),
            Flow::Session(_) => None,
        }
    }
}

/// Why a code was issued, and therefore what accepting it does beyond proving
/// the mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// Prove the mailbox and settle the account's address: accepting the code
    /// marks the address verified.
    VerifyAddress,
    /// The second factor of a sign-in; the address is left as it is.
    SignIn,
}

impl Purpose {
    /// The stable string stored in `login_challenge.purpose`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Purpose::VerifyAddress => "verify_address",
            Purpose::SignIn => "sign_in",
        }
    }

    /// Parses a stored purpose. `None` only for a value this program never
    /// wrote; [`verify`] treats that as no live challenge.
    fn parse(value: &str) -> Option<Self> {
        match value {
            "verify_address" => Some(Purpose::VerifyAddress),
            "sign_in" => Some(Purpose::SignIn),
            _ => None,
        }
    }
}

/// Why a submitted code was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// The digits did not match.
    Wrong,
    /// There is no live challenge, or its lifetime ran out.
    Expired,
    /// The code was already accepted once; a fresh one is required.
    Used,
    /// The attempt cap was reached; a fresh code is required.
    TooManyAttempts,
}

impl VerifyError {
    /// The message shown to the person (English; no locale yet).
    pub const fn message(self) -> &'static str {
        match self {
            VerifyError::Wrong => "That code is not right. Check it and try again.",
            VerifyError::Expired => "That code has expired. Request a new one.",
            VerifyError::Used => "That code has already been used. Request a new one.",
            VerifyError::TooManyAttempts => "Too many tries. Request a new code to continue.",
        }
    }
}

/// The emailed-code challenge of one flow.
///
/// A handle rather than free functions because every operation is about the
/// same `(store, flow)` pair: whoever holds one can issue, check and inspect
/// that flow's code, and nothing else.
pub struct Challenge<'a> {
    store: &'a Store,
    flow: Flow,
}

impl<'a> Challenge<'a> {
    pub fn new(store: &'a Store, flow: Flow) -> Self {
        Self { store, flow }
    }

    /// Issues (or replaces) the flow's code and returns it in the clear.
    ///
    /// The plaintext is returned only so the caller can put it in an email; it
    /// is never stored or logged.
    pub async fn issue(&self, purpose: Purpose, now: i64) -> Result<String, StoreError> {
        let code = otp::generate_code();
        self.store
            .login_challenge_upsert(NewLoginChallenge {
                purpose: purpose.as_str().to_string(),
                session_id: self.flow.session_id(),
                pending_registration_id: self.flow.pending_registration_id(),
                code_hash: otp::hash_code(&code),
                created_at: now,
                expires_at: now + OTP_TTL_SECS,
                max_attempts: OTP_MAX_ATTEMPTS as i32,
                last_sent_at: now,
            })
            .await?;
        Ok(code)
    }

    /// Checks a submitted code, consuming it when it is accepted.
    ///
    /// Consumption is a conditional update, so two simultaneous submissions of
    /// the same correct code cannot both succeed: the second finds it already
    /// consumed. The accepted [`Purpose`] is returned so the caller can act on
    /// it — settling an address or not.
    pub async fn verify(&self, candidate: &str, now: i64) -> Result<Purpose, VerifyError> {
        let Some(challenge) = self.row().await else {
            return Err(VerifyError::Expired);
        };
        let Some(purpose) = Purpose::parse(&challenge.purpose) else {
            // A value this program never wrote cannot be a live challenge.
            return Err(VerifyError::Expired);
        };
        if challenge.consumed_at.is_some() {
            return Err(VerifyError::Used);
        }
        if now > challenge.expires_at {
            return Err(VerifyError::Expired);
        }
        if challenge.attempts >= challenge.max_attempts {
            return Err(VerifyError::TooManyAttempts);
        }
        if otp::hash_code(candidate.trim()) == challenge.code_hash {
            let consumed = self
                .store
                .login_challenge_consume(challenge.id, now)
                .await
                .unwrap_or(false);
            return if consumed {
                Ok(purpose)
            } else {
                // Lost the race to a simultaneous submission of the same code.
                Err(VerifyError::Used)
            };
        }
        let attempts = challenge.attempts + 1;
        let _ = self
            .store
            .login_challenge_record_attempt(challenge.id, attempts)
            .await;
        if attempts >= challenge.max_attempts {
            Err(VerifyError::TooManyAttempts)
        } else {
            Err(VerifyError::Wrong)
        }
    }

    /// The current code as a re-send sees it: why it was issued (so a re-send
    /// preserves the purpose) and when it was last sent (for the cooldown).
    /// `None` when the flow has no code.
    pub async fn pending(&self) -> Option<(Purpose, i64)> {
        let challenge = self.row().await?;
        let purpose = Purpose::parse(&challenge.purpose)?;
        Some((purpose, challenge.last_sent_at))
    }

    /// The flow's row, whichever column keys it.
    async fn row(&self) -> Option<login_challenge::Model> {
        let found = match self.flow {
            Flow::Session(id) => self.store.login_challenge_by_session(id).await,
            Flow::PendingRegistration(id) => {
                self.store.login_challenge_by_pending_registration(id).await
            }
        };
        found.ok().flatten()
    }
}
