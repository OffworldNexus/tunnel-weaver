//! `GET /api/account/me`: the session's authentication, as an event stream.
//!
//! It is the console's single source of truth for "what may I do". On connect,
//! and every time the level changes, the stream sends a `state` event:
//!
//! ```json
//! { "level": "basic",
//!   "paths": [{ "to": "strong", "options": [["verify_email_otp"]] }],
//!   "me": { "id": 1, "name": "…", "email": "…", "has_password": true },
//!   "drop": { "at": 1761300000, "to": "none" } }
//! ```
//!
//! `paths` names, for every level above the current one, the options (each an
//! ordered list of steps) that would reach it — they depend on how the account
//! authenticates, so the client cannot guess them. `me` and `drop` are present
//! exactly while a session is live; `drop` is the next instant the level falls.
//!
//! The stream holds the session's proofs in memory and derives everything from
//! them. Each proof expires at a known instant, so the next drop is computed,
//! not polled: a timer is set for it, a `drop` event announces it
//! [`DROP_LEAD_SECS`] ahead (with `in`, the seconds left, so the client need not
//! trust its own clock), and when it fires the level is recomputed from the
//! same proofs and the next drop planned. The store is read again only when the
//! proof list itself changes — a proof recorded by the [`AuthManager`], or the
//! session retired — which is announced on the [`LiveHub`] as an
//! [`Entity::Session`] change. The timers are [`Task`]s on a per-stream
//! [`Scheduler`], as for the console's own streams.
//!
//! An anonymous request gets one `state` with `"level": "none"` and the stream
//! ends: the client closes it and opens a new one once a sign-in starts.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

use async_trait::async_trait;
use axum::http::HeaderMap;
use axum::response::Response;
use bytes::Bytes;
use serde_json::{Value, json};
use tokio::sync::{broadcast, mpsc};

use crate::account::AccountRuntime;
use crate::account::session::{self, SESSION_COOKIE};
use crate::account::views::{FRAME_BUFFER, HEARTBEAT, HeartbeatTask, sse_event, sse_response};
use crate::live::{Change, Entity, Interest, LiveHub, Viewer};
use crate::scheduler::{Scheduler, Task};
use crate::store::StoreError;
use crate::wall_clock::unix_secs;

use super::manager::{next_drop, next_expiry, upgrade_paths};
use super::{AuthLevel, AuthManager, ProofKind, SessionContext, Situation, level_of};

/// How long before a level drops the stream announces it — enough for the
/// console to warn, and for a write already in flight to land before it.
pub const DROP_LEAD_SECS: i64 = 30;

/// Announces that one session's proof list changed (a proof recorded, the
/// session retired).
pub fn session_changed(live: &LiveHub, session: SessionContext) {
    live.publish(
        Change::visible_to(Viewer::Account(session.account_id))
            .entity(Entity::Session)
            .id(session.session_id),
    );
}

/// Announces that every session of an account may be gone (a password change
/// or reset retires them all; so does a deletion).
pub fn sessions_changed(live: &LiveHub, account_id: i32) {
    live.publish(Change::visible_to(Viewer::Account(account_id)).entity(Entity::Session));
}

/// Opens the stream for the request's session cookie (or its absence).
pub fn serve(rt: Arc<AccountRuntime>, manager: AuthManager, headers: &HeaderMap) -> Response {
    let raw = session::cookie(headers, SESSION_COOKIE).unwrap_or_default();
    let (tx, rx) = mpsc::channel::<Bytes>(FRAME_BUFFER);
    tokio::spawn(run(rt, manager, raw, tx));
    sse_response(rx)
}

/// What the stream knows about the session it watches: loaded once, and again
/// only when its proof list changes.
struct Watched {
    session: SessionContext,
    /// When the session row itself expires.
    ends_at: i64,
    /// The latest occurrence of each live proof.
    proofs: BTreeMap<ProofKind, i64>,
    /// The two lifetimes the proofs are measured against (see [`Situation`]).
    session_ttl_secs: i64,
    confirm_window_secs: i64,
    me: Value,
}

impl Watched {
    /// The proofs as they stand at `now`.
    fn situation(&self, now: i64) -> Situation {
        Situation {
            account_id: Some(self.session.account_id),
            proofs: self.proofs.clone(),
            now,
            session_ttl_secs: self.session_ttl_secs,
            confirm_window_secs: self.confirm_window_secs,
        }
    }
}

/// Loads the session behind `raw` and its proofs, or `None` when there is no
/// live session.
async fn load(
    rt: &AccountRuntime,
    manager: &AuthManager,
    raw: &str,
    now: i64,
) -> Result<Option<Watched>, StoreError> {
    if raw.is_empty() {
        return Ok(None);
    }
    let Some((row, account)) = rt.sessions.live(raw, now).await? else {
        return Ok(None);
    };
    let session = SessionContext {
        session_id: row.id,
        account_id: account.id,
    };
    let situation = manager.at(Some(session), now).situation().await;
    let email = rt
        .store
        .email_identity_for_account(account.id)
        .await?
        .map(|identity| identity.email)
        .unwrap_or_default();
    // Drives the Security page's "Password is set" state: a live credential
    // exists for every email/password account today, but the flag keeps the
    // panel honest once passkeys or SSO arrive.
    let has_password = rt.store.password_current_for(account.id).await?.is_some();
    Ok(Some(Watched {
        session,
        ends_at: row.expires_at,
        proofs: situation.proofs,
        session_ttl_secs: situation.session_ttl_secs,
        confirm_window_secs: situation.confirm_window_secs,
        me: json!({
            "id": account.id,
            "name": account.name,
            "email": email,
            "has_password": has_password,
        }),
    }))
}

/// The `state` body at `now`, and the drop to plan for (`None`: nothing left
/// to watch, so the stream ends).
fn state(watched: Option<&Watched>, now: i64) -> (Value, Option<Plan>) {
    let watched = watched.filter(|watched| now < watched.ends_at);
    let situation = match watched {
        Some(watched) => watched.situation(now),
        None => Situation {
            account_id: None,
            proofs: BTreeMap::new(),
            now,
            session_ttl_secs: 0,
            confirm_window_secs: 0,
        },
    };
    let level = level_of(&situation);
    let paths: Vec<Value> = AuthLevel::ALL
        .into_iter()
        .filter(|target| *target > level)
        .filter_map(|target| {
            let options = upgrade_paths(&situation, target);
            (!options.is_empty()).then(|| json!({ "to": target.as_str(), "options": options }))
        })
        .collect();
    let Some(watched) = watched else {
        return (json!({ "level": level.as_str(), "paths": paths }), None);
    };
    let (at, to) =
        next_drop(&situation, watched.ends_at).unwrap_or((watched.ends_at, AuthLevel::None));
    let body = json!({
        "level": level.as_str(),
        "paths": paths,
        "me": watched.me,
        "drop": { "at": at, "to": to.as_str() },
    });
    let plan = Plan {
        drop: (at, to),
        recheck_at: next_expiry(&situation, watched.ends_at),
    };
    (body, Some(plan))
}

/// The instants a stream has to wake at, read off its proofs.
struct Plan {
    /// The next drop of the level: announced ahead of time.
    drop: (i64, AuthLevel),
    /// The next proof expiry (or the session's end): the level or the ways up
    /// change there, so the state is recomputed and sent.
    recheck_at: i64,
}

async fn run(rt: Arc<AccountRuntime>, manager: AuthManager, raw: String, tx: mpsc::Sender<Bytes>) {
    let mut changes = rt.live.subscribe();
    let mut watched = match load(&rt, &manager, &raw, unix_secs()).await {
        Ok(watched) => watched,
        // Ending the response lets the browser's `EventSource` retry; telling a
        // signed-in person `none` because a read failed would be a lie.
        Err(error) => {
            tracing::warn!(%error, "the session stream could not load its session");
            return;
        }
    };
    // The drop already announced, so re-planning does not announce it twice.
    let announced = Arc::new(AtomicI64::new(0));

    loop {
        let (body, plan) = state(watched.as_ref(), unix_secs());
        let body = serde_json::to_vec(&body).unwrap_or_default();
        if tx.send(sse_event("state", &body)).await.is_err() {
            return;
        }
        let (Some(current), Some(plan)) = (watched.as_ref(), plan) else {
            return;
        };
        let (at, to) = plan.drop;
        let viewer = Viewer::Account(current.session.account_id);
        let interests = [Interest::these(
            Entity::Session,
            [current.session.session_id],
        )];

        let expired = Arc::new(AtomicBool::new(false));
        let mut tasks: Vec<Arc<dyn Task>> = vec![
            Arc::new(HeartbeatTask { tx: tx.clone() }),
            Arc::new(ExpiryTask {
                at: plan.recheck_at,
                expired: Arc::clone(&expired),
            }),
        ];
        if announced.load(Ordering::Relaxed) != at {
            tasks.push(Arc::new(AnnounceTask {
                at,
                to,
                tx: tx.clone(),
                announced: Arc::clone(&announced),
            }));
        }
        let mut timers = Scheduler::new(tasks).await;

        loop {
            let wait = timers.next_wait().unwrap_or(HEARTBEAT);
            tokio::select! {
                () = tx.closed() => return,
                change = changes.recv() => match change {
                    Ok(change) if change.invalidates(viewer, &interests) => {
                        match load(&rt, &manager, &raw, unix_secs()).await {
                            Ok(reloaded) => watched = reloaded,
                            // Keep planning from the proofs already known; the
                            // next change or drop tries again.
                            Err(error) => {
                                tracing::warn!(%error, "the session stream could not reload its proofs");
                                continue;
                            }
                        }
                        break;
                    }
                    Ok(_) => continue,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        if let Ok(reloaded) = load(&rt, &manager, &raw, unix_secs()).await {
                            watched = reloaded;
                        }
                        break;
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                },
                () = tokio::time::sleep(wait) => {
                    timers.run_due().await;
                    if tx.is_closed() {
                        return;
                    }
                    // A proof expired: recompute from the proofs already held.
                    if expired.load(Ordering::Relaxed) {
                        break;
                    }
                }
            }
        }
    }
}

/// Sends the `drop` announcement [`DROP_LEAD_SECS`] before the drop — or at
/// once, for a drop planned inside the lead.
struct AnnounceTask {
    at: i64,
    to: AuthLevel,
    tx: mpsc::Sender<Bytes>,
    announced: Arc<AtomicI64>,
}

#[async_trait]
impl Task for AnnounceTask {
    fn name(&self) -> &'static str {
        "session-drop-announcement"
    }
    async fn next_tick(&self, last_tick: Option<i64>, now: i64) -> i64 {
        match last_tick {
            None => (self.at - DROP_LEAD_SECS).max(now),
            Some(_) => i64::MAX,
        }
    }
    async fn run(&self, tick: i64) {
        let body = json!({ "at": self.at, "in": self.at - tick, "to": self.to.as_str() });
        let body = serde_json::to_vec(&body).unwrap_or_default();
        if self.tx.send(sse_event("drop", &body)).await.is_ok() {
            self.announced.store(self.at, Ordering::Relaxed);
        }
    }
}

/// Fires at the next proof expiry (or the session's end).
struct ExpiryTask {
    at: i64,
    expired: Arc<AtomicBool>,
}

#[async_trait]
impl Task for ExpiryTask {
    fn name(&self) -> &'static str {
        "session-proof-expiry"
    }
    async fn next_tick(&self, last_tick: Option<i64>, _now: i64) -> i64 {
        match last_tick {
            None => self.at,
            Some(_) => i64::MAX,
        }
    }
    async fn run(&self, _tick: i64) {
        self.expired.store(true, Ordering::Relaxed);
    }
}
