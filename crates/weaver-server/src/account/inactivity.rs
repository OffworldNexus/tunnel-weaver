//! The inactivity sweep: warn, then delete, accounts nobody uses.
//!
//! This is WVR-160's trigger. It never invents a second deletion path: it sends
//! one warning email `inactivity_warning_before_secs` ahead of the deadline,
//! then at `inactive_after_secs` of idleness calls
//! [`AccountRuntime::delete_account`](crate::account::AccountRuntime::delete_account)
//! — the very same function the "delete my account" endpoint uses.
//!
//! It is not polled. [`next_event`] reads the store and returns the exact second
//! the next account is due for its warning or its deletion, and the scheduler
//! sleeps until then; [`run`] then settles every account due at that tick.
//!
//! The two "active right now" signals — a live browser session and a live tunnel
//! — are honored whatever the timestamps say, because a tunnel can run for
//! months without a console sign-in. A live session is a column the candidate
//! query reads; a live tunnel only the registry knows, so it is checked here.
//! Both also write activity (a sign-in, a metered minute), which is what moves
//! a skipped account's next event forward.

use tracing::{debug, info, warn};

use crate::account::views::key_of;
use crate::account::{AccountRuntime, router::human_timestamp};
use crate::email::{InactivityWarning, Mailbox};
use crate::store::StoreError;
use crate::store::account::InactivityCandidate;
use crate::store::entity::machine;
use crate::tunnel::TunnelRegistry;

/// Page size when walking the due accounts. Every due account is handled in
/// the tick; the page only bounds how many rows are in memory at once.
pub const SWEEP_PAGE: u64 = 100;

/// When a run left work undone (store error, failed deletion or send), how long
/// before the backlog is retried, in seconds.
pub const RETRY_AFTER_FAILURE: i64 = 3_600;

/// What one tick did, for the log line.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepReport {
    /// Warning emails sent this tick.
    pub warned: u64,
    /// Accounts deleted this tick.
    pub deleted: u64,
    /// Deletions or warnings that failed and must be retried.
    pub failed: u64,
}

/// The configured timeline, in seconds of idleness.
struct Timeline {
    /// Idle age at which the account is deleted.
    delete_after: i64,
    /// Idle age at which the warning goes out.
    warn_after: i64,
}

impl Timeline {
    fn of(rt: &AccountRuntime) -> Self {
        let delete_after = i64::try_from(rt.config.inactive_after_secs).unwrap_or(i64::MAX);
        let lead = i64::try_from(rt.config.inactivity_warning_before_secs).unwrap_or(i64::MAX);
        Self {
            delete_after,
            warn_after: delete_after.saturating_sub(lead),
        }
    }
}

/// The Unix second at which the inactivity sweep next has work, given that
/// everything due up to `last_tick` was settled.
///
/// It is the earliest warning or deletion instant strictly after `last_tick`
/// across all accounts, bounded by `now + warn_after`: an account that does not
/// exist yet (or signs in right now) cannot need a warning before that.
pub async fn next_event(rt: &AccountRuntime, last_tick: i64, now: i64) -> Result<i64, StoreError> {
    let timeline = Timeline::of(rt);
    let earliest = rt
        .store
        .inactivity_next_event(last_tick, timeline.warn_after, timeline.delete_after)
        .await?;
    let fresh = now.saturating_add(timeline.warn_after);
    Ok(earliest.map_or(fresh, |at| at.min(fresh)))
}

/// Runs the tick scheduled for `tick` (Unix seconds): settles every account due
/// at that instant.
///
/// `registry` is the live tunnel registry, when the process has one; without it
/// (tests, the e2e harness) machines simply read as offline and no account is
/// skipped for a tunnel.
pub async fn run(
    rt: &AccountRuntime,
    registry: Option<&TunnelRegistry>,
    tick: i64,
) -> Result<SweepReport, StoreError> {
    let timeline = Timeline::of(rt);
    let mut report = SweepReport::default();
    let mut after_id = 0;
    loop {
        let page = rt
            .store
            .inactivity_candidates(tick, timeline.warn_after, after_id, SWEEP_PAGE)
            .await?;
        let Some(last) = page.last() else {
            break;
        };
        after_id = last.account_id;
        let full = page.len() as u64 == SWEEP_PAGE;

        for candidate in page {
            settle(rt, registry, &candidate, tick, &timeline, &mut report).await;
        }
        if !full {
            break;
        }
    }
    Ok(report)
}

/// Warns or deletes one candidate, as its idleness at `tick` dictates.
async fn settle(
    rt: &AccountRuntime,
    registry: Option<&TunnelRegistry>,
    candidate: &InactivityCandidate,
    tick: i64,
    timeline: &Timeline,
    report: &mut SweepReport,
) {
    // A live session is "active right now"; never sweep it.
    if candidate.has_live_session {
        return;
    }
    let machines = machines_of(rt, candidate.account_id).await;
    if has_live_tunnel(registry, &machines) {
        return;
    }

    let idle = tick.saturating_sub(candidate.last_activity);
    if idle >= timeline.delete_after {
        if delete(rt, registry, candidate).await {
            report.deleted += 1;
        } else {
            report.failed += 1;
        }
    } else if idle >= timeline.warn_after && not_warned_since(candidate) {
        match warn_account(rt, candidate, tick, timeline.delete_after).await {
            Warned::Sent => report.warned += 1,
            Warned::Skipped => {}
            Warned::Failed => report.failed += 1,
        }
    }
}

/// The candidate's machines, or none when it has not paired a person yet.
async fn machines_of(rt: &AccountRuntime, account_id: i32) -> Vec<machine::Model> {
    match rt.store.person_by_account(account_id).await {
        Ok(Some(person)) => rt.store.list_machines(person.id).await.unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Whether any of `machines` holds a live tunnel connection.
fn has_live_tunnel(registry: Option<&TunnelRegistry>, machines: &[machine::Model]) -> bool {
    let Some(registry) = registry else {
        return false;
    };
    machines
        .iter()
        .filter_map(key_of)
        .any(|key| registry.is_connected(&key))
}

/// Whether the account has had no sign-in or metered minute since its last
/// warning, so the warning has to go out for this cycle.
fn not_warned_since(candidate: &InactivityCandidate) -> bool {
    candidate
        .warning_at
        .is_none_or(|warned| warned < candidate.last_activity)
}

/// Deletes the account through the shared deletion path. Returns whether it
/// went through.
///
/// A failure is logged, not fatal: one account must not abandon the rest of the
/// tick.
async fn delete(
    rt: &AccountRuntime,
    registry: Option<&TunnelRegistry>,
    candidate: &InactivityCandidate,
) -> bool {
    match rt.delete_account(candidate.account_id, registry).await {
        Ok(()) => {
            info!(
                account_id = candidate.account_id,
                "Inactive account deleted"
            );
            true
        }
        Err(err) => {
            warn!(
                account_id = candidate.account_id,
                error = %err,
                "Failed to delete an inactive account"
            );
            false
        }
    }
}

/// How a warning attempt ended.
enum Warned {
    /// Sent and recorded.
    Sent,
    /// Deliberately not sent (no mailer, no usable address): not retried.
    Skipped,
    /// Sending failed: retried on a later tick.
    Failed,
}

/// Sends the inactivity warning and records it at `tick`.
///
/// Best-effort by design: with no mailer configured the warning is skipped and
/// the account is still deleted on schedule. The record is written only after a
/// successful send, so a failed send is retried by a later tick.
async fn warn_account(
    rt: &AccountRuntime,
    candidate: &InactivityCandidate,
    tick: i64,
    inactive_after: i64,
) -> Warned {
    let Some(mailer) = &rt.mailer else {
        debug!(
            account_id = candidate.account_id,
            "Inactivity warning skipped: email is not configured"
        );
        return Warned::Skipped;
    };
    if candidate.email.is_empty() {
        return Warned::Skipped;
    }
    let Some(to) = Mailbox::parse(&candidate.email, Some(candidate.name.clone())).ok() else {
        return Warned::Skipped;
    };

    // The account is deleted at `last_activity + inactive_after`; the warning
    // tells the owner that date. The link is the ordinary sign-in page, not a
    // pre-authorised action: signing in there resets the clock.
    let delete_at = candidate.last_activity.saturating_add(inactive_after);
    let template = InactivityWarning {
        signin_url: rt.signin_url(),
        delete_on: human_timestamp(delete_at),
    };
    let email = match mailer.compose(to, &template) {
        Ok(email) => email,
        Err(err) => {
            warn!(account_id = candidate.account_id, error = %err, "Failed to compose the inactivity warning");
            return Warned::Failed;
        }
    };
    if let Err(err) = mailer.send(&email).await {
        warn!(account_id = candidate.account_id, error = %err, "Failed to send the inactivity warning");
        return Warned::Failed;
    }
    if let Err(err) = rt
        .store
        .account_mark_inactivity_warning(candidate.account_id, tick)
        .await
    {
        warn!(account_id = candidate.account_id, error = %err, "Failed to record the inactivity warning");
    }
    debug!(account_id = candidate.account_id, "Inactivity warning sent");
    Warned::Sent
}
