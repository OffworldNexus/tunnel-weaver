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
    /// Control of an external identity the provider asserted (WVR-169). The
    /// possession half of an SSO sign-in: on its own it is one factor, so it
    /// grants `Basic` — exactly as the password does — and holds for the session.
    IdentityProvider,
    /// The provider asserted a second factor for the sign-in (WVR-169) — Entra's
    /// `amr` carried `mfa`. It is the same thing an emailed code proves, so it
    /// grants `Strong` and lives as long as the session.
    IdentityProviderMfa,
    /// The provider re-authenticated the person on demand (WVR-169) — a step-up
    /// with `prompt=login`. It is the *presence-of-person* half, the same thing a
    /// password typed moments ago proves, so it lives only for the confirmation
    /// window and is what lets an SSO session reach `Certain`.
    IdentityProviderPresence,
}

impl ProofKind {
    /// Every kind the level derivation knows about.
    pub const ALL: [ProofKind; 8] = [
        ProofKind::Password,
        ProofKind::EmailOtp,
        ProofKind::Totp,
        ProofKind::Passkey,
        ProofKind::PasskeyUserVerification,
        ProofKind::IdentityProvider,
        ProofKind::IdentityProviderMfa,
        ProofKind::IdentityProviderPresence,
    ];

    /// The stable string stored in `auth_event.kind`.
    pub const fn as_str(self) -> &'static str {
        match self {
            ProofKind::Password => "password",
            ProofKind::EmailOtp => "email_otp",
            ProofKind::Totp => "totp",
            ProofKind::Passkey => "passkey",
            ProofKind::PasskeyUserVerification => "passkey_user_verification",
            ProofKind::IdentityProvider => "identity_provider",
            ProofKind::IdentityProviderMfa => "identity_provider_mfa",
            ProofKind::IdentityProviderPresence => "identity_provider_presence",
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
            ProofKind::Password
            | ProofKind::PasskeyUserVerification
            | ProofKind::IdentityProviderPresence => confirm_window_secs,
            ProofKind::EmailOtp
            | ProofKind::Totp
            | ProofKind::Passkey
            | ProofKind::IdentityProvider
            | ProofKind::IdentityProviderMfa => session_ttl_secs,
        }
    }
}
