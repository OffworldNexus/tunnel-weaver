//! The facts a session can prove, and how long each stays true.
//!
//! A proof is recorded as an `auth_event` row; the *latest* occurrence of each
//! kind on a session, while it is still within that kind's lifetime, is what
//! feeds the derived [`AuthLevel`](super::AuthLevel). Nothing level-related is
//! cached on the session itself.
//!
//! WVR-167 defines two kinds. WVR-164/165/166 (backup codes, "turn email OTP
//! off", authenticator app) add kinds here and a `StepKind` to reach them —
//! they never re-architect the level derivation.

/// Something the person demonstrated on this session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProofKind {
    /// The password was checked. Granting `Basic` is the session's existence;
    /// this proof exists so the (currently unused) `Certain` level has a second
    /// input — a password typed moments ago.
    Password,
    /// An emailed one-time code was accepted — the second factor.
    EmailOtp,
}

impl ProofKind {
    /// Every kind the level derivation knows about.
    pub const ALL: [ProofKind; 2] = [ProofKind::Password, ProofKind::EmailOtp];

    /// The stable string stored in `auth_event.kind`.
    pub const fn as_str(self) -> &'static str {
        match self {
            ProofKind::Password => "password",
            ProofKind::EmailOtp => "email_otp",
        }
    }

    /// Parses a stored `auth_event.kind`, or `None` when it is not a proof.
    pub fn parse(kind: &str) -> Option<Self> {
        ProofKind::ALL.into_iter().find(|k| k.as_str() == kind)
    }

    /// How long an occurrence of this kind stays alive, in seconds.
    ///
    /// The password proof is short (the reference's five minutes): it only
    /// distinguishes `Certain` from `Strong`. The emailed-code proof lives as
    /// long as the session it was given on, so a completed second factor holds
    /// for the whole session rather than demanding a mid-session re-step-up.
    pub const fn max_age_secs(self, session_ttl_secs: i64) -> i64 {
        match self {
            ProofKind::Password => 300,
            ProofKind::EmailOtp => session_ttl_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_the_stored_name() {
        for kind in ProofKind::ALL {
            assert_eq!(ProofKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(ProofKind::parse("logout"), None);
    }

    #[test]
    fn otp_lifetime_tracks_the_session() {
        assert_eq!(ProofKind::EmailOtp.max_age_secs(86_400), 86_400);
        assert!(ProofKind::Password.max_age_secs(86_400) < 86_400);
    }
}
