//! Ways of authenticating: what level a session currently holds, and what a
//! person can do to climb.
//!
//! A [`AuthPath`] is one way in (password then emailed code, a passkey…). It
//! *describes* steps; how a step is presented — a SvelteKit route for the
//! console, a JSON `403` for the API — is the caller's business. The trait is
//! the seam WVR-166 plugs into for the next factor kind.

use std::collections::BTreeMap;

use super::AuthLevel;
use super::proof::ProofKind;

/// What a path gets to look at: who the session belongs to and the latest
/// occurrence of each proof still counting on it.
#[derive(Debug, Clone)]
pub struct Situation {
    /// The account the session belongs to, or `None` when it is anonymous.
    pub account_id: Option<i32>,
    /// Whether the account has at least one registered passkey, which is what
    /// decides whether *asserting with a passkey* can be offered as a way up.
    pub has_passkeys: bool,
    /// The latest occurrence (Unix seconds) of each proof on the session.
    pub proofs: BTreeMap<ProofKind, i64>,
    /// The request's instant, so lifetimes are evaluated consistently.
    pub now: i64,
    /// The configured session lifetime, which the emailed-code proof borrows.
    pub session_ttl_secs: i64,
    /// The configured step-up window: how long a password proof keeps `Certain`.
    pub confirm_window_secs: i64,
}

impl Situation {
    /// How long a proof of `kind` stays alive on this session.
    pub fn max_age(&self, kind: ProofKind) -> i64 {
        kind.max_age_secs(self.session_ttl_secs, self.confirm_window_secs)
    }

    /// Whether `kind` was proven within its lifetime.
    pub fn has_valid(&self, kind: ProofKind) -> bool {
        match self.proofs.get(&kind) {
            Some(&at) => self.now - at < self.max_age(kind),
            None => false,
        }
    }

    /// Whether `kind` was ever proven on this session (alive or not).
    pub fn was_used(&self, kind: ProofKind) -> bool {
        self.proofs.contains_key(&kind)
    }
}

/// What a person can do to climb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepKind {
    /// Start over: the sign-in form.
    Login,
    /// Enter the emailed second-factor code.
    VerifyEmailOtp,
    /// Re-type the password: what `Certain` asks for once the sign-in's own
    /// password proof has aged out (WVR-165).
    ConfirmPassword,
    /// Assert with a registered passkey (WVR-163). In-place: the console runs
    /// the ceremony in the step-up popin, with no page and no emailed code, and
    /// the session lands at `Certain` — the assertion carries user
    /// verification, the same thing re-typing the password proves.
    AssertPasskey,
}

impl StepKind {
    /// The stable wire name, echoed by the gate's refusal.
    pub const fn as_str(self) -> &'static str {
        match self {
            StepKind::Login => "login",
            StepKind::VerifyEmailOtp => "verify_email_otp",
            StepKind::ConfirmPassword => "confirm_password",
            StepKind::AssertPasskey => "assert_passkey",
        }
    }

    /// The proofs this step records, at the instant it is taken.
    ///
    /// A slice rather than one kind because a single passkey assertion proves
    /// two things at once: the credential is held (possession), and the
    /// authenticator verified the person (user verification). They expire
    /// differently, and that difference *is* the `Certain`-then-`Strong`
    /// behaviour of a passkey sign-in.
    pub const fn proves(self) -> &'static [ProofKind] {
        match self {
            // Signing in opens a session and checks the password; the session
            // exists is what `levels_after` adds on top.
            StepKind::Login | StepKind::ConfirmPassword => &[ProofKind::Password],
            StepKind::VerifyEmailOtp => &[ProofKind::EmailOtp],
            StepKind::AssertPasskey => &[ProofKind::Passkey, ProofKind::PasskeyUserVerification],
        }
    }
}

/// One thing the person has to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step(pub StepKind);

/// One way of authenticating.
pub trait AuthPath: Send + Sync {
    /// The proof kinds this path relies on, so its options can be offered first
    /// when the session was opened through it.
    fn proofs(&self) -> &'static [ProofKind];

    /// The level this path grants to the current situation.
    fn current_level(&self, situation: &Situation) -> AuthLevel;

    /// The options (each a sequence of steps) this path offers to reach
    /// `target`; an empty list means it cannot get there.
    fn steps_to(&self, situation: &Situation, target: AuthLevel) -> Vec<Vec<Step>>;
}

/// Password first, then an emailed code.
///
/// `Basic`: the session exists and the password was checked. `Strong`: the
/// emailed-code proof is alive. `Certain`: also a recent password proof. The
/// emailed code always exists for a password account, so there is nothing to
/// enrol — unlike the reference's device flow, the only step is to verify.
pub struct PasswordEmailOtpPath;

impl AuthPath for PasswordEmailOtpPath {
    fn proofs(&self) -> &'static [ProofKind] {
        &[ProofKind::Password, ProofKind::EmailOtp]
    }

    fn current_level(&self, situation: &Situation) -> AuthLevel {
        if situation.account_id.is_none() {
            return AuthLevel::None;
        }
        // A session opened by another path — a passkey sign-in, say — holds
        // neither of this path's proofs, and this path can do nothing for it:
        // there is no password check here to repeat and no code pending to
        // enter. Saying `None` keeps the ways up honest, and leaves the account
        // its nominal recovery route: sign out and sign in again.
        if !situation.was_used(ProofKind::Password) && !situation.was_used(ProofKind::EmailOtp) {
            return AuthLevel::None;
        }
        if !situation.has_valid(ProofKind::EmailOtp) {
            return AuthLevel::Basic;
        }
        if situation.has_valid(ProofKind::Password) {
            return AuthLevel::Certain;
        }
        AuthLevel::Strong
    }

    fn steps_to(&self, situation: &Situation, target: AuthLevel) -> Vec<Vec<Step>> {
        if situation.account_id.is_none() {
            return vec![vec![Step(StepKind::Login)]];
        }
        let current = self.current_level(situation);
        if current == AuthLevel::None {
            return Vec::new();
        }
        let mut steps = Vec::new();
        if current < AuthLevel::Strong && target >= AuthLevel::Strong {
            steps.push(Step(StepKind::VerifyEmailOtp));
        }
        // A password typed moments ago (at sign-in, say) already counts.
        if target >= AuthLevel::Certain && !situation.has_valid(ProofKind::Password) {
            steps.push(Step(StepKind::ConfirmPassword));
        }
        if steps.is_empty() {
            Vec::new()
        } else {
            vec![steps]
        }
    }
}

/// A passkey: one gesture, no password, no emailed code (WVR-163).
///
/// The assertion carries user verification, so taking it lands at `Certain` and
/// decays to `Strong` — the same shape as a password *and* an emailed code, out
/// of a single ceremony. Its `steps_to` is what makes an assertion a step-up for
/// a session that signed in some other way: what an assertion needs is a
/// registered passkey and a session already strong, not a passkey proof in hand.
pub struct PasskeyPath;

impl AuthPath for PasskeyPath {
    fn proofs(&self) -> &'static [ProofKind] {
        &[ProofKind::Passkey, ProofKind::PasskeyUserVerification]
    }

    fn current_level(&self, situation: &Situation) -> AuthLevel {
        if situation.account_id.is_none() || !situation.has_valid(ProofKind::Passkey) {
            return AuthLevel::None;
        }
        // The user-verification half is the `Certain` half, exactly as a password
        // typed moments ago is. It expires on the confirmation window while the
        // possession half holds for the whole session, which is the only
        // difference between `Certain` and `Strong` here.
        if situation.has_valid(ProofKind::Password)
            || situation.has_valid(ProofKind::PasskeyUserVerification)
        {
            return AuthLevel::Certain;
        }
        AuthLevel::Strong
    }

    fn steps_to(&self, situation: &Situation, target: AuthLevel) -> Vec<Vec<Step>> {
        if situation.account_id.is_none() || !situation.has_passkeys {
            return Vec::new();
        }
        // The assertion's endpoint is `Strong`-gated: a `Basic` session's only
        // way up is the emailed code it was just sent, so offering an assertion
        // there would name a step the gate refuses.
        if level_of(situation) < AuthLevel::Strong {
            return Vec::new();
        }
        if self.current_level(situation) < target {
            vec![vec![Step(StepKind::AssertPasskey)]]
        } else {
            Vec::new()
        }
    }
}

/// Every path, in preference order.
pub static PATHS: &[&dyn AuthPath] = &[&PasswordEmailOtpPath, &PasskeyPath];

/// The best level any path grants `situation`.
pub fn level_of(situation: &Situation) -> AuthLevel {
    PATHS
        .iter()
        .map(|path| path.current_level(situation))
        .max()
        .unwrap_or(AuthLevel::None)
}

/// The level the session would hold after each of `steps`, in order.
///
/// Simulated, not tabulated: a step's outcome depends on the proofs already
/// held. Entering the emailed code moments after signing in lands at `Certain`,
/// because the password proof is still alive; the same step ten minutes later
/// lands at `Strong`. That is what tells a client where a climb will actually
/// leave it.
pub fn levels_after(situation: &Situation, steps: &[Step]) -> Vec<AuthLevel> {
    let mut walk = situation.clone();
    let mut levels = Vec::with_capacity(steps.len());
    for step in steps {
        if step.0 == StepKind::Login {
            // A sign-in leaves a session behind; the id is not what any level
            // reads, only that there is one.
            walk.account_id = walk.account_id.or(Some(0));
        }
        for proof in step.0.proves() {
            walk.proofs.insert(*proof, walk.now);
        }
        levels.push(level_of(&walk));
    }
    levels
}

#[cfg(test)]
mod tests {
    use super::*;

    fn situation(account: bool, proofs: &[(ProofKind, i64)], now: i64) -> Situation {
        situation_with(account, false, proofs, now)
    }

    /// The same, with passkeys registered on the account.
    fn situation_with(
        account: bool,
        has_passkeys: bool,
        proofs: &[(ProofKind, i64)],
        now: i64,
    ) -> Situation {
        Situation {
            account_id: account.then_some(1),
            has_passkeys,
            proofs: proofs.iter().copied().collect(),
            now,
            session_ttl_secs: 86_400,
            confirm_window_secs: 300,
        }
    }

    #[test]
    fn no_account_is_none() {
        let s = situation(false, &[], 1_000);
        assert_eq!(PasswordEmailOtpPath.current_level(&s), AuthLevel::None);
    }

    #[test]
    fn password_only_is_basic() {
        let s = situation(true, &[(ProofKind::Password, 1_000)], 1_000);
        assert_eq!(PasswordEmailOtpPath.current_level(&s), AuthLevel::Basic);
    }

    #[test]
    fn live_otp_is_strong() {
        // The password proof has aged out; the OTP proof alone is Strong.
        let s = situation(
            true,
            &[(ProofKind::Password, 1_000), (ProofKind::EmailOtp, 2_000)],
            2_100,
        );
        assert_eq!(PasswordEmailOtpPath.current_level(&s), AuthLevel::Strong);
    }

    #[test]
    fn live_otp_and_recent_password_is_certain() {
        let s = situation(
            true,
            &[(ProofKind::Password, 2_000), (ProofKind::EmailOtp, 2_000)],
            2_100,
        );
        assert_eq!(PasswordEmailOtpPath.current_level(&s), AuthLevel::Certain);
    }

    #[test]
    fn expired_otp_falls_back_to_basic() {
        let s = situation(true, &[(ProofKind::EmailOtp, 1_000)], 1_000 + 86_400 + 1);
        assert_eq!(PasswordEmailOtpPath.current_level(&s), AuthLevel::Basic);
    }

    #[test]
    fn anonymous_offers_login_and_basic_offers_verify() {
        let anon = situation(false, &[], 1_000);
        assert_eq!(
            PasswordEmailOtpPath.steps_to(&anon, AuthLevel::Strong),
            vec![vec![Step(StepKind::Login)]]
        );
        let basic = situation(true, &[(ProofKind::Password, 1_000)], 1_000);
        assert_eq!(
            PasswordEmailOtpPath.steps_to(&basic, AuthLevel::Strong),
            vec![vec![Step(StepKind::VerifyEmailOtp)]]
        );
    }

    #[test]
    fn a_step_reaches_different_levels_depending_on_the_proofs() {
        // Just signed in: the code alone lands at Certain.
        let fresh = situation(true, &[(ProofKind::Password, 1_000)], 1_000);
        assert_eq!(
            levels_after(&fresh, &[Step(StepKind::VerifyEmailOtp)]),
            vec![AuthLevel::Certain]
        );
        // Ten minutes later the password proof is gone: the code lands at
        // Strong, and only re-typing the password reaches Certain.
        let stale = situation(true, &[(ProofKind::Password, 1_000)], 1_700);
        assert_eq!(
            levels_after(
                &stale,
                &[
                    Step(StepKind::VerifyEmailOtp),
                    Step(StepKind::ConfirmPassword),
                ]
            ),
            vec![AuthLevel::Strong, AuthLevel::Certain]
        );
    }

    #[test]
    fn a_climb_from_anonymous_starts_with_a_session() {
        let anon = situation(false, &[], 1_000);
        assert_eq!(
            levels_after(&anon, &[Step(StepKind::Login)]),
            vec![AuthLevel::Basic]
        );
    }

    #[test]
    fn certain_asks_for_the_password_only_once_it_has_aged_out() {
        // Just signed in: the code alone reaches Certain.
        let fresh = situation(true, &[(ProofKind::Password, 1_000)], 1_000);
        assert_eq!(
            PasswordEmailOtpPath.steps_to(&fresh, AuthLevel::Certain),
            vec![vec![Step(StepKind::VerifyEmailOtp)]]
        );
        // Later, Strong needs the password re-typed.
        let strong = situation(
            true,
            &[(ProofKind::Password, 1_000), (ProofKind::EmailOtp, 1_000)],
            2_000,
        );
        assert_eq!(
            PasswordEmailOtpPath.current_level(&strong),
            AuthLevel::Strong
        );
        assert_eq!(
            PasswordEmailOtpPath.steps_to(&strong, AuthLevel::Certain),
            vec![vec![Step(StepKind::ConfirmPassword)]]
        );
    }

    #[test]
    fn a_passkey_sign_in_is_certain_then_strong() {
        // The assertion proves possession and user verification together.
        let fresh = situation(
            true,
            &[
                (ProofKind::Passkey, 1_000),
                (ProofKind::PasskeyUserVerification, 1_000),
            ],
            1_000,
        );
        assert_eq!(PasskeyPath.current_level(&fresh), AuthLevel::Certain);
        assert_eq!(level_of(&fresh), AuthLevel::Certain);

        // Once the user-verification window (300 s here) has passed, what is
        // left is the possession proof, and that holds for the session: Strong.
        let later = situation(
            true,
            &[
                (ProofKind::Passkey, 1_000),
                (ProofKind::PasskeyUserVerification, 1_000),
            ],
            1_301,
        );
        assert_eq!(PasskeyPath.current_level(&later), AuthLevel::Strong);
        assert_eq!(level_of(&later), AuthLevel::Strong);
    }

    #[test]
    fn a_passkey_session_is_left_alone_by_the_password_path() {
        // The session was not opened with a password and no code is pending, so
        // the password path neither grants it a level nor names a step for it.
        let passkey_session = situation(
            true,
            &[
                (ProofKind::Passkey, 1_000),
                (ProofKind::PasskeyUserVerification, 1_000),
            ],
            1_000,
        );
        assert_eq!(
            PasswordEmailOtpPath.current_level(&passkey_session),
            AuthLevel::None
        );
        assert!(
            PasswordEmailOtpPath
                .steps_to(&passkey_session, AuthLevel::Certain)
                .is_empty()
        );
    }

    #[test]
    fn a_strong_session_with_a_passkey_is_offered_the_assertion() {
        // Signed in with the password and the emailed code, ten minutes ago:
        // Strong, `Certain` aged out. Either re-typing the password or
        // asserting with the passkey gets back there.
        let strong = situation_with(
            true,
            true,
            &[(ProofKind::Password, 1_000), (ProofKind::EmailOtp, 1_000)],
            2_000,
        );
        assert_eq!(
            PasskeyPath.steps_to(&strong, AuthLevel::Certain),
            vec![vec![Step(StepKind::AssertPasskey)]]
        );
        assert_eq!(
            levels_after(&strong, &[Step(StepKind::AssertPasskey)]),
            vec![AuthLevel::Certain]
        );
    }

    #[test]
    fn no_registered_passkey_means_no_assertion_step() {
        let strong = situation_with(
            true,
            false,
            &[(ProofKind::Password, 1_000), (ProofKind::EmailOtp, 1_000)],
            2_000,
        );
        assert!(PasskeyPath.steps_to(&strong, AuthLevel::Certain).is_empty());
    }

    #[test]
    fn a_basic_session_is_not_offered_an_assertion() {
        // The password was just checked: the only way up is the emailed code
        // that was just sent, because that is what the gate will serve.
        let basic = situation_with(true, true, &[(ProofKind::Password, 1_000)], 1_000);
        assert_eq!(level_of(&basic), AuthLevel::Basic);
        assert!(PasskeyPath.steps_to(&basic, AuthLevel::Strong).is_empty());
        assert!(PasskeyPath.steps_to(&basic, AuthLevel::Certain).is_empty());
    }

    #[test]
    fn a_lapsed_passkey_session_can_assert_its_way_back_to_certain() {
        // The session signed in with a passkey and its user verification has
        // since lapsed: Strong, with the assertion as its way back to Certain.
        let lapsed = situation_with(
            true,
            true,
            &[
                (ProofKind::Passkey, 1_000),
                (ProofKind::PasskeyUserVerification, 1_000),
            ],
            1_301,
        );
        assert_eq!(level_of(&lapsed), AuthLevel::Strong);
        assert_eq!(
            PasskeyPath.steps_to(&lapsed, AuthLevel::Certain),
            vec![vec![Step(StepKind::AssertPasskey)]]
        );
        assert_eq!(
            levels_after(&lapsed, &[Step(StepKind::AssertPasskey)]),
            vec![AuthLevel::Certain]
        );

        // A session that already holds Certain is offered nothing: an assertion
        // is never a step to take for its own sake.
        let certain = situation_with(
            true,
            true,
            &[
                (ProofKind::Passkey, 1_301),
                (ProofKind::PasskeyUserVerification, 1_301),
            ],
            1_301,
        );
        assert_eq!(level_of(&certain), AuthLevel::Certain);
        assert!(
            PasskeyPath
                .steps_to(&certain, AuthLevel::Certain)
                .is_empty()
        );
        assert!(PasskeyPath.steps_to(&certain, AuthLevel::Strong).is_empty());
    }
}
