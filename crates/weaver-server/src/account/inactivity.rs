//! The periodic inactivity sweep: warn, then delete, accounts nobody uses.
//!
//! This is WVR-160's trigger. It runs alongside the account token/session sweep
//! and never invents a second deletion path: it sends one warning email at the
//! configured lead time, then at the threshold calls the very same
//! [`Store::delete_account`](crate::store::Store::delete_account) that the
//! "delete my account" button uses.
//!
//! The two "active right now" signals — a live browser session and a live tunnel
//! — are honored whatever the timestamps say, because a tunnel can run for
//! months without a console sign-in. A live session is a column the candidate
//! query reads; a live tunnel only the registry knows, so it is checked here.
//!
//! Every tick is bounded (`SWEEP_BATCH`): a large expiry set is worked through
//! over several ticks rather than stalling the relay.

use tracing::{debug, info, warn};

use crate::account::session;
use crate::account::views::key_of;
use crate::account::{AccountRuntime, router::human_timestamp};
use crate::email::{InactivityWarning, Mailbox};
use crate::store::StoreError;
use crate::store::account::InactivityCandidate;
use crate::store::entity::machine;
use crate::tunnel::TunnelRegistry;
use weaver_mux::CloseCode;

/// How many accounts one tick considers. The bound is what keeps a large expiry
/// set from stalling the relay: the rest are picked up on later ticks.
pub const SWEEP_BATCH: u64 = 100;

/// A floor on the sign-in link's life, so a warning sent late in the window
/// still leaves the owner time to act.
const MIN_LINK_TTL_SECS: i64 = 86_400;

/// What one tick did, for the log line.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepReport {
    /// Warning emails sent this tick.
    pub warned: u64,
    /// Accounts deleted this tick.
    pub deleted: u64,
}

/// Runs one sweep tick at `now` (Unix seconds).
///
/// `registry` is the live tunnel registry, when the process has one; without it
/// (tests, the e2e harness) machines simply read as offline and no account is
/// skipped for a tunnel.
pub async fn run(
    rt: &AccountRuntime,
    registry: Option<&TunnelRegistry>,
    now: i64,
) -> Result<SweepReport, StoreError> {
    let inactive_after = i64::try_from(rt.config.inactive_after_secs).unwrap_or(i64::MAX);
    let warning_before =
        i64::try_from(rt.config.inactivity_warning_before_secs).unwrap_or(i64::MAX);

    // Candidates are accounts already past the warning threshold; the query
    // bounds the batch and orders by the oldest sign-in.
    let candidates = rt
        .store
        .inactivity_candidates(now, warning_before, SWEEP_BATCH)
        .await?;

    let mut report = SweepReport::default();
    for candidate in candidates {
        // A live session is "active right now"; never sweep it.
        if candidate.has_live_session {
            continue;
        }
        let machines = machines_of(rt, candidate.account_id).await;
        if has_live_tunnel(registry, &machines) {
            continue;
        }

        let idle = now.saturating_sub(candidate.last_activity);
        if idle >= inactive_after {
            delete(rt, registry, &candidate, &machines).await;
            report.deleted += 1;
        } else if idle >= warning_before
            && not_warned_since(&candidate)
            && warn_account(rt, &candidate, now, inactive_after).await
        {
            report.warned += 1;
        }
    }
    Ok(report)
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

/// Deletes the account through the shared store operation, closing any live
/// tunnel first so no machine outruns the delete.
async fn delete(
    rt: &AccountRuntime,
    registry: Option<&TunnelRegistry>,
    candidate: &InactivityCandidate,
    machines: &[machine::Model],
) {
    if let Some(registry) = registry {
        for key in machines.iter().filter_map(key_of) {
            registry.close_connection(&key, CloseCode::KeyRevoked);
        }
    }
    match rt.store.delete_account(candidate.account_id).await {
        Ok(()) => {
            info!(
                account_id = candidate.account_id,
                "Inactive account deleted"
            );
        }
        Err(err) => {
            // One account's failure must not abandon the rest of the batch.
            warn!(
                account_id = candidate.account_id,
                error = %err,
                "Failed to delete an inactive account"
            );
        }
    }
}

/// Sends the inactivity warning and records it. Returns whether it went out.
///
/// Best-effort by design: with no mailer configured, or a send failure, the
/// account is still deleted on schedule — the warning is skipped, not queued.
/// The record is written only after a successful send, so a later tick can
/// retry a genuine failure.
async fn warn_account(
    rt: &AccountRuntime,
    candidate: &InactivityCandidate,
    now: i64,
    inactive_after: i64,
) -> bool {
    let Some(mailer) = &rt.mailer else {
        debug!(
            account_id = candidate.account_id,
            "Inactivity warning skipped: email is not configured"
        );
        return false;
    };
    if candidate.email.is_empty() {
        return false;
    }
    let Some(to) = Mailbox::parse(&candidate.email, Some(candidate.name.clone())).ok() else {
        return false;
    };

    let delete_at = candidate.last_activity.saturating_add(inactive_after);
    let expires_at = delete_at.max(now.saturating_add(MIN_LINK_TTL_SECS));

    // A fresh single-use link. Issuing revokes any earlier one, so only the
    // latest email works.
    let raw = session::new_token();
    if let Err(err) = rt
        .store
        .login_token_issue(
            candidate.account_id,
            &session::token_hash(&raw),
            now,
            expires_at,
        )
        .await
    {
        warn!(account_id = candidate.account_id, error = %err, "Failed to mint a sign-in link");
        return false;
    }

    let template = InactivityWarning {
        signin_url: rt.signin_url(&raw),
        delete_on: human_timestamp(delete_at),
    };
    let email = match mailer.compose(to, &template) {
        Ok(email) => email,
        Err(err) => {
            warn!(account_id = candidate.account_id, error = %err, "Failed to compose the inactivity warning");
            return false;
        }
    };
    if let Err(err) = mailer.send(&email).await {
        warn!(account_id = candidate.account_id, error = %err, "Failed to send the inactivity warning");
        return false;
    }
    if let Err(err) = rt
        .store
        .account_mark_inactivity_warning(candidate.account_id, now)
        .await
    {
        warn!(account_id = candidate.account_id, error = %err, "Failed to record the inactivity warning");
    }
    debug!(account_id = candidate.account_id, "Inactivity warning sent");
    true
}
