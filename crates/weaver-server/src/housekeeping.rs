//! The relay's housekeeping sweeps, as [`Task`](crate::scheduler::Task)s.
//!
//! These are the store- and account-bound periodic jobs that used to be four
//! hand-written interval loops in [`crate::server`]. Each one is a plain
//! [`Task`]: a fixed period and a `run` that prunes something. Metering and
//! certificate renewal are also tasks, but live next to what they drive
//! ([`crate::metering`], [`crate::cert`]).

use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};

use crate::account::AccountRuntime;
use crate::account::inactivity;
use crate::config::AccountConfig;
use crate::scheduler::Task;
use crate::store::Store;
use crate::tunnel::TunnelRegistry;
use crate::wall_clock::{unix_ms, unix_secs};

/// How often idle abuse buckets are dropped. Fixed, unlike the bucket TTL it
/// prunes against.
pub const ABUSE_SWEEP_INTERVAL: Duration = Duration::from_secs(600);

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
    async fn next_tick(&self, now: i64) -> i64 {
        now + ABUSE_SWEEP_INTERVAL.as_secs() as i64
    }
    async fn run(&self, _now: i64) {
        let cutoff = unix_ms() - self.ttl_ms;
        if let Err(err) = self.store.abuse_sweep(cutoff).await {
            warn!(error = %err, "abuse bucket sweep failed");
        }
    }
}

/// Drops spent ALTCHA proof markers so the table stays bounded.
pub struct AltchaSweepTask {
    store: Store,
    interval: Duration,
}

impl AltchaSweepTask {
    pub fn new(store: Store, interval: Duration) -> Self {
        Self { store, interval }
    }
}

#[async_trait::async_trait]
impl Task for AltchaSweepTask {
    fn name(&self) -> &'static str {
        "altcha-proof-sweep"
    }
    async fn next_tick(&self, now: i64) -> i64 {
        now + self.interval.as_secs() as i64
    }
    async fn run(&self, _now: i64) {
        let cutoff = unix_ms();
        if let Err(err) = self.store.altcha_sweep_proofs(cutoff).await {
            warn!(error = %err, "ALTCHA proof sweep failed");
        }
    }
}

/// Prunes the account plane's expiry-scoped rows: verification tokens, reset
/// tokens, expired sessions, and retired machine key-log rows.
pub struct AccountSweepTask {
    store: Store,
    config: AccountConfig,
    interval: Duration,
}

impl AccountSweepTask {
    pub fn new(store: Store, config: AccountConfig, interval: Duration) -> Self {
        Self {
            store,
            config,
            interval,
        }
    }
}

#[async_trait::async_trait]
impl Task for AccountSweepTask {
    fn name(&self) -> &'static str {
        "account-sweep"
    }
    async fn next_tick(&self, now: i64) -> i64 {
        now + self.interval.as_secs() as i64
    }
    async fn run(&self, _now: i64) {
        let cutoff = unix_secs();
        if let Err(err) = self.store.verification_token_sweep(cutoff).await {
            warn!(error = %err, "verification token sweep failed");
        }
        if let Err(err) = self.store.password_reset_token_sweep(cutoff).await {
            warn!(error = %err, "password reset token sweep failed");
        }
        if let Err(err) = self.store.session_sweep(cutoff).await {
            warn!(error = %err, "session sweep failed");
        }
        let key_log_cutoff = self.config.key_log_cutoff(cutoff);
        if let Err(err) = self.store.sweep_machine_key_log(key_log_cutoff).await {
            warn!(error = %err, "machine key log sweep failed");
        }
    }
}

/// Warns and then deletes accounts nobody has used (WVR-160).
///
/// Bounded per tick inside [`inactivity::run`]; it reuses the same cadence as
/// the account sweep so the whole account plane is pruned on one clock.
pub struct InactivitySweepTask {
    account: Arc<AccountRuntime>,
    registry: Arc<TunnelRegistry>,
    interval: Duration,
}

impl InactivitySweepTask {
    pub fn new(
        account: Arc<AccountRuntime>,
        registry: Arc<TunnelRegistry>,
        interval: Duration,
    ) -> Self {
        Self {
            account,
            registry,
            interval,
        }
    }
}

#[async_trait::async_trait]
impl Task for InactivitySweepTask {
    fn name(&self) -> &'static str {
        "inactivity-sweep"
    }
    async fn next_tick(&self, now: i64) -> i64 {
        now + self.interval.as_secs() as i64
    }
    async fn run(&self, now: i64) {
        match inactivity::run(&self.account, Some(&self.registry), now).await {
            Ok(report) => info!(
                warned = report.warned,
                deleted = report.deleted,
                "inactivity sweep complete"
            ),
            Err(err) => warn!(error = %err, "inactivity sweep failed"),
        }
    }
}
