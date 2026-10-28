//! The relay's housekeeping sweeps, as [`Task`](crate::scheduler::Task)s.
//!
//! The garbage sweeps (abuse buckets, spent ALTCHA proofs, expired account
//! tokens and sessions) only reclaim rows that are already inert — every reader
//! filters on expiry — so they run once at boot to catch up and then at each UTC
//! midnight. The inactivity sweep is different: it acts on people, so it wakes
//! exactly when the next account falls due. Metering and certificate renewal
//! are tasks too, but live next to what they drive ([`crate::metering`],
//! [`crate::cert`]).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tracing::{info, warn};

use crate::account::AccountRuntime;
use crate::account::inactivity;
use crate::config::AccountConfig;
use crate::scheduler::{Task, next_midnight};
use crate::store::Store;
use crate::tunnel::TunnelRegistry;

/// Boot catch-up, then every UTC midnight: the schedule of a pure garbage sweep.
fn at_boot_then_midnight(last_tick: Option<i64>, now: i64) -> i64 {
    match last_tick {
        None => now,
        Some(_) => next_midnight(now),
    }
}

/// Drops abuse rate-limit buckets idle for longer than the configured TTL.
pub struct AbuseSweepTask {
    store: Store,
    ttl_ms: i64,
}

impl AbuseSweepTask {
    /// `ttl_ms` is how long a bucket may sit idle before the sweep drops it.
    pub fn new(store: Store, ttl_ms: i64) -> Self {
        Self { store, ttl_ms }
    }
}

#[async_trait::async_trait]
impl Task for AbuseSweepTask {
    fn name(&self) -> &'static str {
        "abuse-bucket-sweep"
    }
    async fn next_tick(&self, last_tick: Option<i64>, now: i64) -> i64 {
        at_boot_then_midnight(last_tick, now)
    }
    async fn run(&self, tick: i64) {
        let cutoff = tick.saturating_mul(1000).saturating_sub(self.ttl_ms);
        if let Err(err) = self.store.abuse_sweep(cutoff).await {
            warn!(error = %err, "abuse bucket sweep failed");
        }
    }
}

/// Drops expired ALTCHA proof markers so the table stays small.
///
/// Only live markers count against the proof cap, so how long an expired one
/// lingers is a disk question, not a correctness one.
pub struct AltchaSweepTask {
    store: Store,
}

impl AltchaSweepTask {
    pub fn new(store: Store) -> Self {
        Self { store }
    }
}

#[async_trait::async_trait]
impl Task for AltchaSweepTask {
    fn name(&self) -> &'static str {
        "altcha-proof-sweep"
    }
    async fn next_tick(&self, last_tick: Option<i64>, now: i64) -> i64 {
        at_boot_then_midnight(last_tick, now)
    }
    async fn run(&self, tick: i64) {
        if let Err(err) = self
            .store
            .altcha_sweep_proofs(tick.saturating_mul(1000))
            .await
        {
            warn!(error = %err, "ALTCHA proof sweep failed");
        }
    }
}

/// Prunes the account plane's expiry-scoped rows: verification tokens, reset
/// tokens, expired sessions, retired machine key-log rows, and enrolments that
/// were begun and never confirmed.
pub struct AccountSweepTask {
    store: Store,
    config: AccountConfig,
}

/// How long an unconfirmed authenticator-app enrolment may sit before the sweep
/// drops it (WVR-166).
///
/// A pending row lives only as long as the dialog that began it: confirming it
/// takes a code, which takes a minute. Anything still unconfirmed a day later is
/// an abandoned dialog, and a day is far more slack than an enrolment needs —
/// while still being short enough that a sealed secret does not linger.
const PENDING_TOTP_TTL_SECS: i64 = 86_400;

impl AccountSweepTask {
    pub fn new(store: Store, config: AccountConfig) -> Self {
        Self { store, config }
    }
}

#[async_trait::async_trait]
impl Task for AccountSweepTask {
    fn name(&self) -> &'static str {
        "account-sweep"
    }
    async fn next_tick(&self, last_tick: Option<i64>, now: i64) -> i64 {
        at_boot_then_midnight(last_tick, now)
    }
    async fn run(&self, tick: i64) {
        if let Err(err) = self.store.verification_token_sweep(tick).await {
            warn!(error = %err, "verification token sweep failed");
        }
        if let Err(err) = self.store.password_reset_token_sweep(tick).await {
            warn!(error = %err, "password reset token sweep failed");
        }
        if let Err(err) = self.store.session_sweep(tick).await {
            warn!(error = %err, "session sweep failed");
        }
        if let Err(err) = self.store.login_challenge_sweep(tick).await {
            warn!(error = %err, "login challenge sweep failed");
        }
        let key_log_cutoff = self.config.key_log_cutoff(tick);
        if let Err(err) = self.store.sweep_machine_key_log(key_log_cutoff).await {
            warn!(error = %err, "machine key log sweep failed");
        }
        if let Err(err) = self
            .store
            .totp_pending_sweep(tick.saturating_sub(PENDING_TOTP_TTL_SECS))
            .await
        {
            warn!(error = %err, "pending authenticator enrolment sweep failed");
        }
    }
}

/// Warns and then deletes accounts nobody has used (WVR-160).
///
/// Wakes at the exact second the next account is due for its warning or its
/// deletion (see [`inactivity::next_event`]).
pub struct InactivitySweepTask {
    account: Arc<AccountRuntime>,
    registry: Arc<TunnelRegistry>,
    /// Set when the last run left work undone (a store error, a failed
    /// deletion), so the next tick retries it instead of skipping past it.
    failed: AtomicBool,
}

impl InactivitySweepTask {
    pub fn new(account: Arc<AccountRuntime>, registry: Arc<TunnelRegistry>) -> Self {
        Self {
            account,
            registry,
            failed: AtomicBool::new(false),
        }
    }
}

#[async_trait::async_trait]
impl Task for InactivitySweepTask {
    fn name(&self) -> &'static str {
        "inactivity-sweep"
    }
    async fn next_tick(&self, last_tick: Option<i64>, now: i64) -> i64 {
        // At boot, catch up on whatever fell due while the relay was down.
        let Some(last_tick) = last_tick else {
            return now;
        };
        // Events up to `last_tick` were settled by that run — unless part of it
        // failed, in which case the backlog is retried later.
        let retry = self
            .failed
            .swap(false, Ordering::SeqCst)
            .then_some(now + inactivity::RETRY_AFTER_FAILURE);
        match inactivity::next_event(&self.account, last_tick, now).await {
            Ok(at) => retry.map_or(at, |retry| retry.min(at)),
            Err(err) => {
                warn!(error = %err, "inactivity schedule lookup failed");
                now + inactivity::RETRY_AFTER_FAILURE
            }
        }
    }
    async fn run(&self, tick: i64) {
        match inactivity::run(&self.account, Some(&self.registry), tick).await {
            Ok(report) => {
                if report.failed > 0 {
                    self.failed.store(true, Ordering::SeqCst);
                }
                info!(
                    warned = report.warned,
                    deleted = report.deleted,
                    failed = report.failed,
                    "inactivity sweep complete"
                );
            }
            Err(err) => {
                self.failed.store(true, Ordering::SeqCst);
                warn!(error = %err, "inactivity sweep failed");
            }
        }
    }
}
