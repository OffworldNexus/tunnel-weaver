//! Ways of authenticating: what level a session currently holds, and what a
//! person can do to climb.
//!
//! A [`AuthPath`] is one way in (password then second factor, a passkey…). It
//! *describes* steps; how a step is presented — a SvelteKit route for the
//! console, a JSON `403` for the API — is the caller's business. The trait is
//! what each new factor kind plugs into: WVR-166 adds the authenticator app by
//! adding a path, not by touching the level derivation.

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
    /// Whether the account has at least one *confirmed* authenticator app
    /// (WVR-166), which is what decides whether *entering a code from an
    /// authenticator app* can be offered as a way up. A pending enrolment does
    /// not count: it is not a factor yet.
    pub has_totp: bool,
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
    /// Enter the code an authenticator app produces (WVR-166). The same level as
    /// the emailed code, and offered before it when the account has an app:
    /// both are the second factor, and the app is the one the person set up on
    /// purpose.
    VerifyTotp,
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
            StepKind::VerifyTotp => "verify_totp",
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
            StepKind::VerifyTotp => &[ProofKind::Totp],
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
        // Offered from `Basic` up: an assertion is a way *in* as much as it is a
        // step-up, so someone who has just typed a password and holds a passkey
        // can reach for that instead of the code — which is what the console's
        // "try another way" offers them (WVR-166). The anonymous case never
        // reaches here: it has no account to assert against.
        if self.current_level(situation) < target {
            vec![vec![Step(StepKind::AssertPasskey)]]
        } else {
            Vec::new()
        }
    }
}

/// An authenticator app: the emailed code's twin (WVR-166).
///
/// A code from an app proves exactly what an emailed code proves — this person
/// holds the second factor — so this path is the emailed one with the mailbox
/// swapped for a shared secret, and its `current_level` is that path's body with
/// `EmailOtp` replaced by `Totp`. The two are *not* merged into one path because
/// they are offered differently: the app is the factor shown first when the
/// account has one, and the emailed code is the alternative behind it.
///
/// It is listed first in [`PATHS`], which is what makes an app's code the
/// preferred way up among the equal-length options (see
/// [`upgrade_paths`](super::manager::upgrade_paths)).
pub struct AuthenticatorPath;

impl AuthPath for AuthenticatorPath {
    fn proofs(&self) -> &'static [ProofKind] {
        &[ProofKind::Password, ProofKind::Totp]
    }

    fn current_level(&self, situation: &Situation) -> AuthLevel {
        if situation.account_id.is_none() {
            return AuthLevel::None;
        }
        // A session opened by another path holds neither of this path's proofs,
        // and this path can do nothing for it: there is no password check here
        // to repeat and no code pending to enter. `None` keeps the ways up
        // honest — the same rule the emailed path follows.
        if !situation.was_used(ProofKind::Password) && !situation.was_used(ProofKind::Totp) {
            return AuthLevel::None;
        }
        if !situation.has_valid(ProofKind::Totp) {
            return AuthLevel::Basic;
        }
        if situation.has_valid(ProofKind::Password) {
            return AuthLevel::Certain;
        }
        AuthLevel::Strong
    }

    fn steps_to(&self, situation: &Situation, target: AuthLevel) -> Vec<Vec<Step>> {
        // No session at all: the way in is the sign-in form, which is the
        // emailed path's step to name. This path starts from a signed-in
        // session, and its endpoint is `Basic`-gated like the emailed code's, so
        // it offers nothing before that.
        if situation.account_id.is_none() || !situation.has_totp {
            return Vec::new();
        }
        let current = self.current_level(situation);
        if current == AuthLevel::None {
            return Vec::new();
        }
        let mut steps = Vec::new();
        if current < AuthLevel::Strong && target >= AuthLevel::Strong {
            steps.push(Step(StepKind::VerifyTotp));
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

/// Every path, in preference order.
///
/// Order is what "the strongest configured second factor" means: among the
/// options that reach the same level in the same number of steps, the first path
/// to propose one wins, so an authenticator app is offered before the emailed
/// code (WVR-166) and a passkey's single gesture before either.
pub static PATHS: &[&dyn AuthPath] = &[&AuthenticatorPath, &PasswordEmailOtpPath, &PasskeyPath];

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
        situation_with(account, false, false, proofs, now)
    }

    /// The same, with the given factors configured on the account.
    fn situation_with(
        account: bool,
        has_passkeys: bool,
        has_totp: bool,
        proofs: &[(ProofKind, i64)],
        now: i64,
    ) -> Situation {
        Situation {
            account_id: account.then_some(1),
            has_passkeys,
            has_totp,
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
            false,
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
            false,
            &[(ProofKind::Password, 1_000), (ProofKind::EmailOtp, 1_000)],
            2_000,
        );
        assert!(PasskeyPath.steps_to(&strong, AuthLevel::Certain).is_empty());
    }

    #[test]
    fn a_basic_session_is_offered_the_assertion() {
        // The password was just checked, so the emailed code is one way up — and
        // so is a passkey, which is a way *in* as much as it is a step-up: the
        // console offers it beside the code (WVR-166).
        let basic = situation_with(true, true, false, &[(ProofKind::Password, 1_000)], 1_000);
        assert_eq!(level_of(&basic), AuthLevel::Basic);
        assert_eq!(
            PasskeyPath.steps_to(&basic, AuthLevel::Strong),
            vec![vec![Step(StepKind::AssertPasskey)]]
        );
        assert_eq!(
            levels_after(&basic, &[Step(StepKind::AssertPasskey)]),
            vec![AuthLevel::Certain]
        );
    }

    #[test]
    fn a_lapsed_passkey_session_can_assert_its_way_back_to_certain() {
        // The session signed in with a passkey and its user verification has
        // since lapsed: Strong, with the assertion as its way back to Certain.
        let lapsed = situation_with(
            true,
            true,
            false,
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
            false,
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

    #[test]
    fn an_authenticator_code_is_certain_then_strong() {
        // The emailed code's twin in full: entered seconds after the password it
        // is `Certain`; once the confirmation window has passed, the code alone
        // holds `Strong` for the rest of the session.
        let fresh = situation_with(
            true,
            false,
            true,
            &[(ProofKind::Password, 2_000), (ProofKind::Totp, 2_000)],
            2_100,
        );
        assert_eq!(AuthenticatorPath.current_level(&fresh), AuthLevel::Certain);
        assert_eq!(level_of(&fresh), AuthLevel::Certain);

        let later = situation_with(
            true,
            false,
            true,
            &[(ProofKind::Password, 2_000), (ProofKind::Totp, 2_000)],
            2_301,
        );
        assert_eq!(AuthenticatorPath.current_level(&later), AuthLevel::Strong);
        assert_eq!(level_of(&later), AuthLevel::Strong);
    }

    #[test]
    fn an_authenticator_session_is_the_emailed_paths_business_only_up_to_basic() {
        // Each path knows its own kind: for a session that entered an app's
        // code, the emailed path sees the password proof and stops at `Basic`,
        // while the level (`level_of`, the best any path grants) is `Strong`.
        let s = situation_with(
            true,
            false,
            true,
            &[(ProofKind::Password, 1_000), (ProofKind::Totp, 1_000)],
            1_301,
        );
        assert_eq!(PasswordEmailOtpPath.current_level(&s), AuthLevel::Basic);
        assert_eq!(AuthenticatorPath.current_level(&s), AuthLevel::Strong);
        assert_eq!(level_of(&s), AuthLevel::Strong);
    }

    #[test]
    fn the_app_is_a_way_up_only_when_one_is_confirmed() {
        // A code cannot be entered before something can produce it: with no
        // confirmed app the path names no step, exactly as the passkey path does
        // with no credential. A pending enrolment counts as none — `has_totp` is
        // the *confirmed* count.
        let with_app = situation_with(true, false, true, &[(ProofKind::Password, 1_000)], 1_000);
        assert_eq!(
            AuthenticatorPath.steps_to(&with_app, AuthLevel::Strong),
            vec![vec![Step(StepKind::VerifyTotp)]]
        );

        let without = situation_with(true, false, false, &[(ProofKind::Password, 1_000)], 1_000);
        assert!(
            AuthenticatorPath
                .steps_to(&without, AuthLevel::Strong)
                .is_empty()
        );
        assert!(
            AuthenticatorPath
                .steps_to(&without, AuthLevel::Certain)
                .is_empty()
        );
        // And it never grants a level on its own without a code: the password
        // proof alone is the emailed path's `Basic`, not this path's.
        assert_eq!(AuthenticatorPath.current_level(&without), AuthLevel::Basic);
    }

    #[test]
    fn the_app_is_not_a_way_to_reach_certain_on_its_own() {
        // Signed in with the password and an app's code, ten minutes ago:
        // `Strong`. The way back to `Certain` is the password — the code is
        // already in hand, and entering a fresh one proves nothing newer.
        let strong = situation_with(
            true,
            false,
            true,
            &[(ProofKind::Password, 1_000), (ProofKind::Totp, 1_000)],
            2_000,
        );
        assert_eq!(AuthenticatorPath.current_level(&strong), AuthLevel::Strong);
        assert_eq!(
            AuthenticatorPath.steps_to(&strong, AuthLevel::Certain),
            vec![vec![Step(StepKind::ConfirmPassword)]]
        );
        assert!(
            AuthenticatorPath
                .steps_to(&strong, AuthLevel::Strong)
                .is_empty()
        );
    }

    #[test]
    fn a_signed_out_visitor_is_not_offered_a_code_by_the_app_path() {
        // The way in is the sign-in form, which the emailed path names. This
        // path starts from a signed-in session, so it adds no second copy of it.
        let anon = situation(false, &[], 1_000);
        assert!(
            AuthenticatorPath
                .steps_to(&anon, AuthLevel::Strong)
                .is_empty()
        );
        assert_eq!(
            PasswordEmailOtpPath.steps_to(&anon, AuthLevel::Strong),
            vec![vec![Step(StepKind::Login)]]
        );
    }
}
