//! Account suspension (WVR-178): the operator's ban, as one operation.
//!
//! A ban is stored, not held in memory: [`Suspension::ban`] writes the history
//! row, flips `account.state` and invalidates every live session in one store
//! transaction, then announces the change to what the running daemon holds and
//! the store cannot — the console's SSE streams and the account's live tunnels.
//! Lifting the ban is the same store write with no announcement: sessions stay
//! dead until the person signs in again and a machine comes back on its next
//! `weave start`, exactly as after a web-side disconnect.
//!
//! The refusal sentence is fixed and lives here once. It is shown only *after*
//! authentication succeeded (a correct password, a verified assertion, a
//! provider callback), never before, so a ban does not disclose that an account
//! exists to someone who cannot sign in to it. The reason the operator recorded
//! is never sent to the person.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::Response;

use weaver_mux::CloseCode;

use crate::account::{router, views};
use crate::live::LiveHub;
use crate::store::Store;
use crate::store::StoreError;
use crate::store::account::AccountState;
use crate::store::entity::account;
use crate::tunnel::TunnelRegistry;

/// The one thing a suspended person is told, whoever they are and however they
/// tried to sign in.
pub const SUSPENDED: &str = "This account has been suspended. Contact the relay operator.";

/// Whether `account` may not act at all.
///
/// An unknown `state` value counts as suspended: every gate that matters fails
/// closed, so a value this build does not understand never opens access.
pub fn suspended(account: &account::Model) -> bool {
    AccountState::parse(&account.state) != Some(AccountState::Active)
}

/// The refusal response for an authenticated-but-suspended sign-in.
pub fn refusal() -> Response {
    router::err(StatusCode::FORBIDDEN, SUSPENDED)
}

/// The control surface's handle on suspension: what a ban must write, plus the
/// live state it must drop.
///
/// It is a struct rather than three arguments because banning is one operation
/// with three collaborators, and because the control surface should not have to
/// hold the whole account plane to suspend an account.
#[derive(Clone)]
pub struct Suspension {
    store: Store,
    /// The console's change bus: every open stream of the account re-reads its
    /// session when it is told the session changed.
    live: LiveHub,
    /// The live tunnels; `None` in fixtures that do not serve any.
    tunnel: Option<Arc<TunnelRegistry>>,
}

impl Suspension {
    /// Builds the handle from the daemon's shared state.
    pub fn new(store: Store, live: LiveHub, tunnel: Option<Arc<TunnelRegistry>>) -> Self {
        Self {
            store,
            live,
            tunnel,
        }
    }

    /// Bans the account that owns `lookup_key`, then drops what the store
    /// cannot.
    ///
    /// The store transaction commits first, so the ban is already in force —
    /// `account.state`, the open ban row and the invalidated sessions — before
    /// anything in memory is touched. Announcing afterwards means the reload the
    /// SSE push triggers cannot see a live session and re-open a tab the ban
    /// should have closed.
    pub async fn ban(
        &self,
        lookup_key: &str,
        reason: &str,
        now: i64,
    ) -> Result<account::Model, StoreError> {
        let account = self.store.account_ban(lookup_key, reason, now).await?;
        crate::account::auth::watch::sessions_changed(&self.live, account.id);
        self.drop_tunnels(account.id).await?;
        Ok(account)
    }

    /// Lifts the ban on the account that owns `lookup_key`.
    ///
    /// No runtime announcement: the sessions the ban killed are already dead,
    /// its routes already evicted, and a machine reconnects and re-registers on
    /// its own once its key passes admission again.
    pub async fn unban(&self, lookup_key: &str, now: i64) -> Result<account::Model, StoreError> {
        self.store.account_unban(lookup_key, now).await
    }

    /// Evicts and closes every live tunnel of `account_id`.
    ///
    /// Each machine is closed with `Rejected`, which keeps its key: the client
    /// stops and does not reconnect, but unbanning needs no re-enrolment.
    async fn drop_tunnels(&self, account_id: i32) -> Result<(), StoreError> {
        let Some(registry) = self.tunnel.as_deref() else {
            return Ok(());
        };
        let Some(person) = self.store.person_by_account(account_id).await? else {
            return Ok(());
        };
        let keys: Vec<_> = self
            .store
            .list_machines(person.id)
            .await?
            .iter()
            .filter_map(views::key_of)
            .collect();
        registry.evict_keys(&keys, CloseCode::Rejected);
        Ok(())
    }
}
