//! The emailed second factor for a sign-in (WVR-167).
//!
//! A password check opens a `Basic` session; this module issues the code that
//! lifts it to `Strong` and checks the code the person types back. The policy
//! lives in [`crate::email::otp`] and is shared with the setup/configure flow:
//! six digits, hashed at rest, a five-minute lifetime, five attempts, single
//! use. The code is stored per *session*, so only the newest code is accepted —
//! re-sending replaces it.

use crate::email::otp::{self, OTP_MAX_ATTEMPTS, OTP_TTL_SECS};
use crate::store::account::NewLoginChallenge;
use crate::store::{Store, StoreError};

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

/// Issues (or replaces) the code for a session and returns it in the clear.
///
/// The plaintext is returned only so the caller can put it in an email; it is
/// never stored or logged.
pub async fn issue(store: &Store, session_id: i32, now: i64) -> Result<String, StoreError> {
    let code = otp::generate_code();
    store
        .login_challenge_upsert(NewLoginChallenge {
            session_id,
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
/// Consumption is a conditional update, so two simultaneous submissions of the
/// same correct code cannot both succeed: the second finds it already consumed.
pub async fn verify(
    store: &Store,
    session_id: i32,
    candidate: &str,
    now: i64,
) -> Result<(), VerifyError> {
    let Some(challenge) = store
        .login_challenge_by_session(session_id)
        .await
        .ok()
        .flatten()
    else {
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
        let consumed = store
            .login_challenge_consume(challenge.id, now)
            .await
            .unwrap_or(false);
        return if consumed {
            Ok(())
        } else {
            // Lost the race to a simultaneous submission of the same code.
            Err(VerifyError::Used)
        };
    }
    let attempts = challenge.attempts + 1;
    let _ = store
        .login_challenge_record_attempt(challenge.id, attempts)
        .await;
    if attempts >= challenge.max_attempts {
        Err(VerifyError::TooManyAttempts)
    } else {
        Err(VerifyError::Wrong)
    }
}

/// The pending challenge's issue time, for the re-send cooldown. `None` when the
/// session has no challenge.
pub async fn last_sent_at(store: &Store, session_id: i32) -> Option<i64> {
    store
        .login_challenge_by_session(session_id)
        .await
        .ok()
        .flatten()
        .map(|challenge| challenge.last_sent_at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_codes_are_six_digits() {
        // The generator is shared with setup; this guards the sign-in contract.
        for _ in 0..20 {
            let code = otp::generate_code();
            assert_eq!(code.len(), otp::OTP_DIGITS);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn every_refusal_has_copy() {
        for error in [
            VerifyError::Wrong,
            VerifyError::Expired,
            VerifyError::Used,
            VerifyError::TooManyAttempts,
        ] {
            assert!(!error.message().is_empty());
        }
    }
}
