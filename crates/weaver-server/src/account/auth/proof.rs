//! The facts a session can prove, and how long each stays true.
//!
//! A proof is recorded as an `auth_event` row; the *latest* occurrence of each
//! kind on a session, while it is still within that kind's lifetime, is what
//! feeds the derived [`AuthLevel`](super::AuthLevel). Nothing level-related is
//! cached on the session itself.
//!
//! WVR-167 defines the password and emailed-code kinds; WVR-163 adds the two a
//! passkey assertion writes — the credential's possession, and the
//! user-verification it performed moments ago. WVR-166 adds the authenticator
//! app's code, which is the emailed code's twin: the same thing proven — that
//! the person holds the second factor — reached without the mailbox.
//! WVR-164/165 (backup codes, "turn email OTP off") add kinds here and a
//! `StepKind` to reach them — they never re-architect the level derivation.

/// Something the person demonstrated on this session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProofKind {
    /// The password was checked. Granting `Basic` is the session's existence;
    /// this proof exists so the `Certain` level has a second input — a password
    /// typed moments ago.
    Password,
    /// An emailed one-time code was accepted — the second factor.
    EmailOtp,
    /// A code from an authenticator app was accepted (WVR-166) — the second
    /// factor again, reached through a shared secret instead of the mailbox.
    /// The two are interchangeable inputs to the same level: a session that
    /// entered an app's code right after signing in is `Certain`, exactly as one
    /// that entered an emailed code, and falls to `Strong` on the same clock.
    Totp,
    /// A passkey assertion was accepted (WVR-163): the *possession* half, "this
    /// person holds the credential". It is the same thing the emailed code
    /// proves, so it lives as long as the session too.
    Passkey,
    /// The same assertion performed user verification — Face ID, Touch ID,
    /// Windows Hello, a key's PIN (WVR-163). It is the *presence-of-person*
    /// half, the same thing a password typed moments ago proves, so it lives
    /// only for the confirmation window: a passkey sign-in is `Certain` at
    /// once and falls to `Strong` when this expires.
    PasskeyUserVerification,
}

impl ProofKind {
    /// Every kind the level derivation knows about.
    pub const ALL: [ProofKind; 5] = [
        ProofKind::Password,
        ProofKind::EmailOtp,
        ProofKind::Totp,
        ProofKind::Passkey,
        ProofKind::PasskeyUserVerification,
    ];

    /// The stable string stored in `auth_event.kind`.
    pub const fn as_str(self) -> &'static str {
        match self {
            ProofKind::Password => "password",
            ProofKind::EmailOtp => "email_otp",
            ProofKind::Totp => "totp",
            ProofKind::Passkey => "passkey",
            ProofKind::PasskeyUserVerification => "passkey_user_verification",
        }
    }

    /// How long an occurrence of this kind stays alive, in seconds.
    ///
    /// The short kinds (the password, and a passkey's user verification) only
    /// distinguish `Certain` from `Strong`, and they are the window a step-up is
    /// good for (`account.confirm_window_secs`). The long kinds (the emailed
    /// code, a code from an authenticator app, and a passkey's possession) live
    /// as long as the session they were given on, so a completed second factor
    /// holds for the whole session rather than demanding a mid-session
    /// re-step-up.
    pub const fn max_age_secs(self, session_ttl_secs: i64, confirm_window_secs: i64) -> i64 {
        match self {
            ProofKind::Password | ProofKind::PasskeyUserVerification => confirm_window_secs,
            ProofKind::EmailOtp | ProofKind::Totp | ProofKind::Passkey => session_ttl_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sign_in_proof_names_are_the_stored_ones() {
        // `manager` holds the other half: every proof has an event writing it,
        // under the very same name.
        for kind in ProofKind::ALL {
            assert!(!kind.as_str().is_empty());
        }
    }

    #[test]
    fn otp_lifetime_tracks_the_session() {
        assert_eq!(ProofKind::EmailOtp.max_age_secs(86_400, 300), 86_400);
        assert_eq!(ProofKind::Password.max_age_secs(86_400, 300), 300);
    }

    #[test]
    fn a_passkey_is_strong_for_the_session_and_certain_only_for_the_window() {
        // The possession half holds for the session, the user-verification half
        // for the confirmation window: `Certain` now, `Strong` afterwards.
        assert_eq!(ProofKind::Passkey.max_age_secs(86_400, 300), 86_400);
        assert_eq!(
            ProofKind::PasskeyUserVerification.max_age_secs(86_400, 300),
            300
        );
    }

    #[test]
    fn an_authenticator_code_lives_as_long_as_an_emailed_one() {
        // The whole point of the twin: entering one after signing in is
        // `Certain` and decays to `Strong` on the same clock as the other.
        assert_eq!(ProofKind::Totp.max_age_secs(86_400, 300), 86_400);
        assert_eq!(
            ProofKind::Totp.max_age_secs(86_400, 300),
            ProofKind::EmailOtp.max_age_secs(86_400, 300)
        );
    }
}
