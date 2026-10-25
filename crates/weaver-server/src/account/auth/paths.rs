//! Ways of authenticating: what level a session currently holds, and what a
//! person can do to climb.
//!
//! A [`AuthPath`] is one way in (password then emailed code, SSO…). It *describes*
//! steps; how a step is presented — a SvelteKit route for the console, a JSON
//! `403` for the API — is the caller's business. Only one concrete path exists
//! today; the trait is the seam WVR-163/166 plug into.

use std::collections::BTreeMap;

use super::AuthLevel;
use super::proof::ProofKind;

/// What a path gets to look at: who the session belongs to and the latest
/// occurrence of each proof still counting on it.
#[derive(Debug, Clone)]
pub struct Situation {
    /// The account the session belongs to, or `None` when it is anonymous.
    pub account_id: Option<i32>,
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
    /// password proof has aged out. No page performs it yet (WVR-165).
    ConfirmPassword,
}

impl StepKind {
    /// The stable wire name, echoed by the gate's refusal.
    pub const fn as_str(self) -> &'static str {
        match self {
            StepKind::Login => "login",
            StepKind::VerifyEmailOtp => "verify_email_otp",
            StepKind::ConfirmPassword => "confirm_password",
        }
    }

    /// The proof this step records, at the instant it is taken.
    pub const fn proves(self) -> Option<ProofKind> {
        match self {
            // Signing in opens a session and checks the password; the session
            // exists is what `levels_after` adds on top.
            StepKind::Login | StepKind::ConfirmPassword => Some(ProofKind::Password),
            StepKind::VerifyEmailOtp => Some(ProofKind::EmailOtp),
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

/// Every path, in preference order.
pub static PATHS: &[&dyn AuthPath] = &[&PasswordEmailOtpPath];

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
        if let Some(proof) = step.0.proves() {
            walk.proofs.insert(proof, walk.now);
        }
        levels.push(level_of(&walk));
    }
    levels
}

#[cfg(test)]
mod tests {
    use super::*;

    fn situation(account: bool, proofs: &[(ProofKind, i64)], now: i64) -> Situation {
        Situation {
            account_id: account.then_some(1),
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
}
