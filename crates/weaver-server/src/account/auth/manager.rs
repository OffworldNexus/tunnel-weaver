//! The request-scoped authentication manager.
//!
//! Ask it (`level`, `satisfies`, `steps_to`) or tell it (`password_checked`,
//! `email_otp_verified`…). Every "tell" writes an `auth_event` row with the
//! request's forensic context and drops the memoised proofs, so the next "ask"
//! sees it.
//!
//! Facts and verdict are kept apart: what happened is stored as rows; the level
//! is *derived* by the paths from the latest row of each proof kind still alive
//! on this browser session. Nothing level-related is cached in the session — the
//! session only owns the id that ties its rows together.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::live::LiveHub;
use crate::store::account::NewAuthEvent;
use crate::store::{Store, StoreError};

use super::paths::{PATHS, level_of, levels_after};
use super::{AuthLevel, EventKind, ProofKind, Situation, Step, WireStep};

/// The long identifier (an address, an account name) an `auth_event` row may
/// carry; bounded so a crafted field cannot bloat the trail.
const ATTEMPTED_MAX_LEN: usize = 320;

/// The session an [`AuthManager`] works for: its row id (the trail's key) and
/// the account it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionContext {
    /// `browser_session.id` — ties every `auth_event` of this login together.
    pub session_id: i32,
    /// The account the session belongs to.
    pub account_id: i32,
}

/// The per-request authentication manager. Cheap to clone (shared inner state).
#[derive(Clone)]
pub struct AuthManager(Arc<Inner>);

struct Inner {
    store: Store,
    /// Where a recorded proof is announced, so a session's open streams reload
    /// its proofs and re-plan their next expiry.
    live: LiveHub,
    session: Option<SessionContext>,
    session_ttl_secs: i64,
    /// How long a password proof keeps `Certain`, which is what a step-up buys.
    confirm_window_secs: i64,
    now: i64,
    ip_address: String,
    user_agent: String,
    /// The derived proofs, memoised after the first load of the request.
    proofs: Mutex<Option<BTreeMap<ProofKind, i64>>>,
}

impl AuthManager {
    /// Builds the manager for a request. `now` is captured once so every
    /// lifetime in the request is measured against the same instant.
    #[allow(clippy::too_many_arguments)] // The request's context is threaded explicitly; none of it derives from another.
    pub fn new(
        store: Store,
        live: LiveHub,
        session: Option<SessionContext>,
        session_ttl_secs: i64,
        confirm_window_secs: i64,
        now: i64,
        ip_address: String,
        user_agent: String,
    ) -> Self {
        AuthManager(Arc::new(Inner {
            store,
            live,
            session,
            session_ttl_secs,
            confirm_window_secs,
            now,
            ip_address,
            user_agent,
            proofs: Mutex::new(None),
        }))
    }

    /// The session this manager works for, if any.
    pub fn session(&self) -> Option<SessionContext> {
        self.0.session
    }

    /// The account the session belongs to, if any.
    pub fn account_id(&self) -> Option<i32> {
        self.0.session.map(|session| session.account_id)
    }

    // --- ask ---------------------------------------------------------------

    /// The subject and the live proofs on this session — one indexed query,
    /// memoised for the request.
    pub async fn situation(&self) -> Situation {
        Situation {
            account_id: self.account_id(),
            proofs: self.proofs().await,
            now: self.0.now,
            session_ttl_secs: self.0.session_ttl_secs,
            confirm_window_secs: self.0.confirm_window_secs,
        }
    }

    /// The session's level: the best any path grants.
    pub async fn level(&self) -> AuthLevel {
        level_of(&self.situation().await)
    }

    /// The same request's manager re-pointed at `session` and `now`: a long-lived
    /// stream loads the trail of the session it watches with this.
    pub fn at(&self, session: Option<SessionContext>, now: i64) -> AuthManager {
        AuthManager::new(
            self.0.store.clone(),
            self.0.live.clone(),
            session,
            self.0.session_ttl_secs,
            self.0.confirm_window_secs,
            now,
            self.0.ip_address.clone(),
            self.0.user_agent.clone(),
        )
    }

    /// Whether the session is at least `required`.
    pub async fn satisfies(&self, required: AuthLevel) -> bool {
        self.level().await >= required
    }

    /// The ways to reach `target`, each an ordered run of steps, the preferred
    /// first, and each step labelled with the level it would leave the session
    /// at (see [`levels_after`]).
    pub async fn upgrade_paths(&self, target: AuthLevel) -> Vec<Vec<WireStep>> {
        upgrade_paths(&self.situation().await, target)
    }

    // --- tell --------------------------------------------------------------

    /// The password was verified and a session opened (the first factor).
    pub async fn password_checked(&self, session: SessionContext) -> Result<(), StoreError> {
        self.record(
            EventKind::Password,
            Some(session.account_id),
            Some(session.session_id),
            "",
        )
        .await
    }

    /// The password was checked again on this session to step up to `Certain`
    /// — the `confirm_password` step. It proves the same thing the sign-in did,
    /// so it renews that proof's window rather than adding a new kind.
    pub async fn password_confirmed(&self, session: SessionContext) -> Result<(), StoreError> {
        self.record(
            EventKind::PasswordConfirmed,
            Some(session.account_id),
            Some(session.session_id),
            "",
        )
        .await
    }

    /// A step-up password check was refused. The session keeps whatever proofs
    /// it had; this is on the record only.
    pub async fn password_confirmation_failed(
        &self,
        session: SessionContext,
    ) -> Result<(), StoreError> {
        self.record(
            EventKind::PasswordConfirmFailed,
            Some(session.account_id),
            Some(session.session_id),
            "",
        )
        .await
    }

    /// The email factor was engaged: a code was issued or re-sent.
    pub async fn email_otp_issued(&self, session: SessionContext) -> Result<(), StoreError> {
        self.record(
            EventKind::EmailOtpIssued,
            Some(session.account_id),
            Some(session.session_id),
            "",
        )
        .await
    }

    /// An emailed code was accepted.
    pub async fn email_otp_verified(&self, session: SessionContext) -> Result<(), StoreError> {
        self.record(
            EventKind::EmailOtp,
            Some(session.account_id),
            Some(session.session_id),
            "",
        )
        .await
    }

    /// An emailed code was refused.
    pub async fn email_otp_failed(&self, session: SessionContext) -> Result<(), StoreError> {
        self.record(
            EventKind::EmailOtpFailed,
            Some(session.account_id),
            Some(session.session_id),
            "",
        )
        .await
    }

    /// The session was closed; proofs before it cannot be revived.
    pub async fn logged_out(&self, session: SessionContext) -> Result<(), StoreError> {
        self.record(
            EventKind::Logout,
            Some(session.account_id),
            Some(session.session_id),
            "",
        )
        .await
    }

    /// A password check failed, before any session existed.
    ///
    /// `account_id` is the account the address belongs to when one matched, so
    /// a trail can tell "wrong password for a real account" from "no such
    /// address"; `attempted` is the identifier tried.
    pub async fn login_failed(
        &self,
        attempted: &str,
        account_id: Option<i32>,
    ) -> Result<(), StoreError> {
        self.record(EventKind::LoginFailed, account_id, None, attempted)
            .await
    }

    // --- internals ---------------------------------------------------------

    async fn record(
        &self,
        kind: EventKind,
        account_id: Option<i32>,
        session_id: Option<i32>,
        attempted: &str,
    ) -> Result<(), StoreError> {
        self.0
            .store
            .auth_event_insert(NewAuthEvent {
                account_id,
                session_id,
                kind: kind.as_str().to_string(),
                occurred_at: self.0.now,
                ip_address: self.0.ip_address.clone(),
                user_agent: self.0.user_agent.clone(),
                attempted: truncate(attempted),
            })
            .await?;
        // The next "ask" must see the row just written.
        *self.0.proofs.lock().expect("proofs mutex poisoned") = None;
        // A new proof changes the session's proof list: its open streams must
        // reload it and re-plan the next expiry. Other kinds change nothing a
        // level is derived from.
        if kind.proof().is_some()
            && let (Some(account_id), Some(session_id)) = (account_id, session_id)
        {
            super::watch::session_changed(
                &self.0.live,
                SessionContext {
                    session_id,
                    account_id,
                },
            );
        }
        Ok(())
    }

    async fn proofs(&self) -> BTreeMap<ProofKind, i64> {
        if let Some(cached) = self.0.proofs.lock().expect("proofs mutex poisoned").clone() {
            return cached;
        }
        let loaded = self.load_proofs().await.unwrap_or_default();
        *self.0.proofs.lock().expect("proofs mutex poisoned") = Some(loaded.clone());
        loaded
    }

    async fn load_proofs(&self) -> Result<BTreeMap<ProofKind, i64>, StoreError> {
        let Some(session) = self.0.session else {
            return Ok(BTreeMap::new());
        };
        let latest = self
            .0
            .store
            .auth_event_latest_by_kind(session.session_id)
            .await?;
        let mut proofs = BTreeMap::new();
        let mut logged_out_at: Option<i64> = None;
        for (kind, at) in latest {
            match EventKind::parse(&kind) {
                Some(EventKind::Logout) => logged_out_at = Some(at),
                // Several events feed one proof (a sign-in and a step-up both
                // prove the password); `latest_by_kind` already kept the newest
                // row of each, so the newest proof wins.
                Some(event) => {
                    if let Some(proof) = event.proof() {
                        proofs.insert(proof, at);
                    }
                }
                None => {}
            }
        }
        // A logout ends the trail: earlier proofs cannot be revived by a session
        // that somehow kept the same id.
        if let Some(logout) = logged_out_at {
            proofs.retain(|_, at| *at > logout);
        }
        Ok(proofs)
    }
}

/// Every path's options to reach `target`: the path the session was opened
/// with first, then shortest first.
pub fn steps_to(situation: &Situation, target: AuthLevel) -> Vec<Vec<Step>> {
    let mut options = Vec::new();
    for path in PATHS {
        let active = path.proofs().iter().any(|kind| situation.was_used(*kind));
        for option in path.steps_to(situation, target) {
            options.push((!active, option.len(), option));
        }
    }
    options.sort_by_key(|(inactive, length, _)| (*inactive, *length));
    options.into_iter().map(|(_, _, option)| option).collect()
}

/// The ways to reach `target` from `situation`, each an ordered run of steps,
/// the preferred first, and each step labelled with the level taking it would
/// leave the session at.
pub fn upgrade_paths(situation: &Situation, target: AuthLevel) -> Vec<Vec<WireStep>> {
    steps_to(situation, target)
        .into_iter()
        .map(|steps| {
            let reaches = levels_after(situation, &steps);
            steps
                .into_iter()
                .zip(reaches)
                .map(|(step, reaches)| WireStep {
                    step: step.0.as_str(),
                    reaches: reaches.as_str(),
                })
                .collect()
        })
        .collect()
}

/// The instants, in order and after `situation.now`, at which a proof expires
/// before the session itself ends at `session_ends_at`.
fn expiries(situation: &Situation, session_ends_at: i64) -> Vec<i64> {
    let mut instants: Vec<i64> = situation
        .proofs
        .iter()
        .map(|(kind, at)| at + situation.max_age(*kind))
        .filter(|instant| *instant > situation.now && *instant < session_ends_at)
        .collect();
    instants.sort_unstable();
    instants
}

/// The next instant anything derived from `situation` changes: the next proof
/// expiry (the level or the ways up move there), or the session's end.
pub fn next_expiry(situation: &Situation, session_ends_at: i64) -> i64 {
    expiries(situation, session_ends_at)
        .first()
        .copied()
        .unwrap_or(session_ends_at)
}

/// The next instant the level of `situation` falls, and what it falls to.
///
/// Read off the proofs alone: each expires at its occurrence plus its lifetime,
/// so the candidates are those instants, in order, and the first at which the
/// derived level is lower is the drop. With none, the session's own end is the
/// drop, to `None`. `None` when there is no session to drop from.
pub fn next_drop(situation: &Situation, session_ends_at: i64) -> Option<(i64, AuthLevel)> {
    let current = level_of(situation);
    if current == AuthLevel::None {
        return None;
    }
    for instant in expiries(situation, session_ends_at) {
        let later = Situation {
            now: instant,
            ..situation.clone()
        };
        let level = level_of(&later);
        if level < current {
            return Some((instant, level));
        }
    }
    Some((session_ends_at, AuthLevel::None))
}

/// Truncates a recorded identifier to a bounded length.
fn truncate(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() <= ATTEMPTED_MAX_LEN {
        return trimmed.to_string();
    }
    let mut cut = ATTEMPTED_MAX_LEN;
    while cut > 0 && !trimmed.is_char_boundary(cut) {
        cut -= 1;
    }
    trimmed[..cut].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_and_event_names_agree() {
        // The recorded event kind and the proof kind it feeds must be one string.
        assert_eq!(EventKind::Password.as_str(), ProofKind::Password.as_str());
        assert_eq!(EventKind::EmailOtp.as_str(), ProofKind::EmailOtp.as_str());
    }

    #[test]
    fn every_event_kind_round_trips_and_the_proofs_are_reachable() {
        for kind in EventKind::ALL {
            assert_eq!(EventKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(EventKind::parse("not-a-kind"), None);
        // The two ways of proving the password are distinct rows but one proof.
        assert_eq!(EventKind::Password.proof(), Some(ProofKind::Password));
        assert_eq!(
            EventKind::PasswordConfirmed.proof(),
            Some(ProofKind::Password)
        );
        assert_eq!(EventKind::Logout.proof(), None);
        // Every proof the levels read is written by some event.
        for proof in ProofKind::ALL {
            assert!(
                EventKind::ALL
                    .into_iter()
                    .any(|kind| kind.proof() == Some(proof)),
                "{proof:?} has no event recording it"
            );
        }
    }

    fn situation(proofs: &[(ProofKind, i64)], now: i64, ttl: i64) -> Situation {
        Situation {
            account_id: Some(1),
            proofs: proofs.iter().copied().collect(),
            now,
            session_ttl_secs: ttl,
            confirm_window_secs: 300,
        }
    }

    #[test]
    fn a_certain_session_drops_to_strong_when_the_password_ages_out() {
        let s = situation(
            &[(ProofKind::Password, 100), (ProofKind::EmailOtp, 200)],
            250,
            1_000,
        );
        assert_eq!(next_drop(&s, 5_000), Some((400, AuthLevel::Strong)));
        assert_eq!(next_expiry(&s, 5_000), 400);
    }

    #[test]
    fn a_strong_session_drops_to_basic_when_the_code_ages_out() {
        // The password proof is long gone; the code proof ages out before the
        // session row does.
        let s = situation(
            &[(ProofKind::Password, 100), (ProofKind::EmailOtp, 200)],
            500,
            1_000,
        );
        assert_eq!(next_drop(&s, 5_000), Some((1_200, AuthLevel::Basic)));
    }

    #[test]
    fn a_basic_session_changes_at_the_password_expiry_without_dropping() {
        // The ways up change when the password ages out (Certain then needs it
        // re-typed), so that is the next re-check; the level only drops at the
        // session's end.
        let s = situation(&[(ProofKind::Password, 200)], 250, 1_000);
        assert_eq!(next_expiry(&s, 1_200), 500);
        assert_eq!(next_drop(&s, 1_200), Some((1_200, AuthLevel::None)));
    }

    #[test]
    fn no_session_has_no_drop() {
        let mut s = situation(&[], 250, 1_000);
        s.account_id = None;
        assert_eq!(next_drop(&s, 1_200), None);
    }

    #[test]
    fn truncate_is_bounded_and_boundary_safe() {
        assert_eq!(truncate("  hi  "), "hi");
        let long = "é".repeat(500);
        let out = truncate(&long);
        assert!(out.len() <= ATTEMPTED_MAX_LEN);
        assert!(out.chars().all(|c| c == 'é'));
    }
}
