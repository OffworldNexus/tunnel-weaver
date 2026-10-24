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

use crate::store::account::NewAuthEvent;
use crate::store::{Store, StoreError};

use super::{AuthLevel, EventKind, PATHS, ProofKind, Situation, Step, StepKind};

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
    session: Option<SessionContext>,
    session_ttl_secs: i64,
    now: i64,
    ip_address: String,
    user_agent: String,
    /// The derived proofs, memoised after the first load of the request.
    proofs: Mutex<Option<BTreeMap<ProofKind, i64>>>,
}

impl AuthManager {
    /// Builds the manager for a request. `now` is captured once so every
    /// lifetime in the request is measured against the same instant.
    pub fn new(
        store: Store,
        session: Option<SessionContext>,
        session_ttl_secs: i64,
        now: i64,
        ip_address: String,
        user_agent: String,
    ) -> Self {
        AuthManager(Arc::new(Inner {
            store,
            session,
            session_ttl_secs,
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
        }
    }

    /// The session's level: the best any path grants.
    pub async fn level(&self) -> AuthLevel {
        let situation = self.situation().await;
        PATHS
            .iter()
            .map(|path| path.current_level(&situation))
            .max()
            .unwrap_or(AuthLevel::None)
    }

    /// Whether the session is at least `required`.
    pub async fn satisfies(&self, required: AuthLevel) -> bool {
        self.level().await >= required
    }

    /// Every path's options to reach `target`: the path the session was opened
    /// with first, then shortest first.
    pub async fn steps_to(&self, target: AuthLevel) -> Vec<Vec<Step>> {
        let situation = self.situation().await;
        let mut options = Vec::new();
        for path in PATHS {
            let active = path.proofs().iter().any(|kind| situation.was_used(*kind));
            for option in path.steps_to(&situation, target) {
                options.push((!active, option.len(), option));
            }
        }
        options.sort_by_key(|(inactive, length, _)| (*inactive, *length));
        options.into_iter().map(|(_, _, option)| option).collect()
    }

    /// The preferred first step towards `target`, if any path can get there.
    pub async fn best_step(&self, target: AuthLevel) -> Option<StepKind> {
        self.steps_to(target)
            .await
            .into_iter()
            .find_map(|steps| steps.first().map(|step| step.0))
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
            if kind == EventKind::Logout.as_str() {
                logged_out_at = Some(at);
            } else if let Some(proof) = ProofKind::parse(&kind) {
                proofs.insert(proof, at);
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
    fn truncate_is_bounded_and_boundary_safe() {
        assert_eq!(truncate("  hi  "), "hi");
        let long = "é".repeat(500);
        let out = truncate(&long);
        assert!(out.len() <= ATTEMPTED_MAX_LEN);
        assert!(out.chars().all(|c| c == 'é'));
    }
}
