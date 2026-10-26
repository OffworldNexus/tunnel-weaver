//! `GET /api/account/me`: the session's authentication, as an event stream.
//!
//! It is the console's single source of truth for "what may I do". On connect,
//! and every time the level changes, the stream sends a `state` event:
//!
//! ```json
//! { "level": "basic",
//!   "paths": [{ "to": "strong", "options": [[{ "step": "verify_email_otp", "reaches": "strong" }]] }],
//!   "me": { "id": 1, "name": "…", "email": "…", "has_password": true } }
//! ```
//!
//! The console is told a *level*, never a policy: `paths` names, for every level
//! above the one it holds, the options (each an ordered list of steps) that would
//! reach it — they depend on how the account authenticates, so the client cannot
//! guess them — and `me` is the identity. There is no "a fall is coming, to
//! this, at that time": the console holds what it holds, and the relay says
//! [`LEVEL_LEAD_SECS`] early what it will hold next, which is the whole of the
//! UI's business.
//!
//! The stream holds the session's proofs in memory and derives everything from
//! them. Each proof expires at a known instant, so the frame's future is
//! computed, not polled: one timer wakes at the instant the held level or the
//! ways up change, and the store is read again only when the proof list itself
//! changes — a proof recorded by the [`AuthManager`], or the session retired —
//! which is announced on the [`LiveHub`] as an [`Entity::Session`] change. The
//! timers are [`Task`]s on a per-stream [`Scheduler`], as for the console's own
//! streams.
//!
//! An anonymous request gets one `state` with `"level": "none"` and the stream
//! ends: the client closes it and opens a new one once a sign-in starts.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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

use super::manager::{LEVEL_LEAD_SECS, next_drop, next_expiry, upgrade_paths};
use super::{AuthLevel, AuthManager, ProofKind, SessionContext, Situation, level_of};

/// Announces that one session's proof list changed (a proof recorded, the
/// session retired).
pub fn session_changed(live: &LiveHub, session: SessionContext) {
    live.publish(
        Change::visible_to(Viewer::Account(session.account_id))
            .entity(Entity::Session)
            .id(session.session_id),
    );
}

/// Announces that every session of an account must re-read the account's own
/// state: a password change or reset retires them all, a deletion takes them
/// with it, and enrolling or removing a passkey changes which ways up they have
/// (WVR-167, WVR-163).
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
    /// Whether the account holds passkeys: what decides whether the
    /// `assert_passkey` step is part of the ways up it is told about.
    has_passkeys: bool,
    me: Value,
}

impl Watched {
    /// The proofs as they stand at `now`.
    fn situation(&self, now: i64) -> Situation {
        Situation {
            account_id: Some(self.session.account_id),
            has_passkeys: self.has_passkeys,
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
    // exists for every email/password account today, because a password stays
    // the recovery anchor even for an account that signs in with passkeys.
    let has_password = rt.store.password_current_for(account.id).await?.is_some();
    Ok(Some(Watched {
        session,
        ends_at: row.expires_at,
        proofs: situation.proofs,
        session_ttl_secs: situation.session_ttl_secs,
        confirm_window_secs: situation.confirm_window_secs,
        // Read with the proofs (the situation already counted them), so a
        // registration or a removal reaches the stream through the same
        // session change that reloads everything else.
        has_passkeys: situation.has_passkeys,
        me: json!({
            "id": account.id,
            "name": account.name,
            "email": email,
            "has_password": has_password,
        }),
    }))
}

/// The `state` body the console holds at `now`, and when it next changes
/// (`None`: nothing left to watch, so the stream ends).
///
/// The body is computed as of the level the console holds — the session's level,
/// or the one a fall within [`LEVEL_LEAD_SECS`] will leave, so the console hears
/// about a fall before the relay enforces it. Everything else in the frame (the
/// ways up, the identity) is read at that same instant, so the frame is one
/// coherent state rather than a mixture of before and after.
fn state(watched: Option<&Watched>, now: i64) -> (Value, Option<i64>) {
    let watched = watched.filter(|watched| now < watched.ends_at);
    let Some(current) = watched else {
        // Nobody signed in: `none`, and the ways in. There is nothing to watch,
        // so the stream ends here.
        let situation = Situation {
            account_id: None,
            has_passkeys: false,
            proofs: BTreeMap::new(),
            now,
            session_ttl_secs: 0,
            confirm_window_secs: 0,
        };
        return (frame(&situation, None), None);
    };

    let now_situation = current.situation(now);
    let (fall_at, _) =
        next_drop(&now_situation, current.ends_at).unwrap_or((current.ends_at, AuthLevel::None));
    // A fall this close is not news to wait for: the console holds the level it
    // will leave it at.
    let at = if fall_at - now <= LEVEL_LEAD_SECS {
        fall_at
    } else {
        now
    };
    let situation = current.situation(at);
    let body = frame(&situation, Some(current));

    // Wake when the held level changes: the next fall's lead, or the next proof
    // expiry (which moves the ways up), whichever comes first.
    let next = next_drop(&situation, current.ends_at)
        .map(|(at, _)| at - LEVEL_LEAD_SECS)
        .unwrap_or(i64::MAX);
    let wake = next_expiry(&situation, current.ends_at)
        .min(next)
        .max(now + 1);
    (body, Some(wake))
}

/// One `state` frame: the level at `situation`'s instant, the ways up from it,
/// and the identity.
fn frame(situation: &Situation, watched: Option<&Watched>) -> Value {
    let level = level_of(situation);
    let paths: Vec<Value> = AuthLevel::ALL
        .into_iter()
        .filter(|target| *target > level)
        .filter_map(|target| {
            let options = upgrade_paths(situation, target);
            (!options.is_empty()).then(|| json!({ "to": target.as_str(), "options": options }))
        })
        .collect();
    match watched {
        Some(watched) => json!({
            "level": level.as_str(),
            "paths": paths,
            "me": watched.me,
        }),
        None => json!({ "level": level.as_str(), "paths": paths }),
    }
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

    loop {
        let (body, wake) = state(watched.as_ref(), unix_secs());
        let body = serde_json::to_vec(&body).unwrap_or_default();
        if tx.send(sse_event("state", &body)).await.is_err() {
            return;
        }
        let (Some(current), Some(wake)) = (watched.as_ref(), wake) else {
            return;
        };
        let viewer = Viewer::Account(current.session.account_id);
        let interests = [Interest::these(
            Entity::Session,
            [current.session.session_id],
        )];

        // One timer, at the instant the held level or the ways up change; and the
        // keep-alive, which also notices a peer that has gone away.
        let changed = Arc::new(AtomicBool::new(false));
        let timers: Vec<Arc<dyn Task>> = vec![
            Arc::new(HeartbeatTask { tx: tx.clone() }),
            Arc::new(BeliefTask {
                at: wake,
                changed: Arc::clone(&changed),
            }),
        ];
        let mut timers = Scheduler::new(timers).await;

        loop {
            let wait = timers.next_wait().unwrap_or(HEARTBEAT);
            tokio::select! {
                () = tx.closed() => return,
                change = changes.recv() => match change {
                    Ok(change) if change.invalidates(viewer, &interests) => {
                        match load(&rt, &manager, &raw, unix_secs()).await {
                            Ok(reloaded) => watched = reloaded,
                            // Keep planning from the proofs already known; the
                            // next change or expiry tries again.
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
                    // The level the console holds moved: recompute from the
                    // proofs already in hand.
                    if changed.load(Ordering::Relaxed) {
                        break;
                    }
                }
            }
        }
    }
}

/// Fires when the level the console holds changes — the next fall's lead, or the
/// next proof expiry.
struct BeliefTask {
    at: i64,
    changed: Arc<AtomicBool>,
}

#[async_trait]
impl Task for BeliefTask {
    fn name(&self) -> &'static str {
        "session-belief"
    }
    async fn next_tick(&self, last_tick: Option<i64>, _now: i64) -> i64 {
        match last_tick {
            None => self.at,
            Some(_) => i64::MAX,
        }
    }
    async fn run(&self, _tick: i64) {
        self.changed.store(true, Ordering::Relaxed);
    }
}
