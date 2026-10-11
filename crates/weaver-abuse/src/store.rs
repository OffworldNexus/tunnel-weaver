//! The injected budget store: the engine's only IO boundary.
//!
//! The engine never persists anything itself. It hands a [`Key`], a [`Quota`],
//! a cost and an absolute `now_ms` to a [`BudgetStore`] and receives the
//! [`Charge`]s back. The server implements the trait over its local SQLite
//! store; tests use the in-memory fixture in [`crate::testing`].

use async_trait::async_trait;

use crate::gcra::{Charge, Quota};
use crate::key::Key;
use crate::policy::PolicyId;

/// A budget-store failure, kept distinct from a rate-limit denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The backing store could not be reached or the update failed.
    #[error("budget store unavailable")]
    Unavailable,
    /// The store is at its configured capacity and refused the entry.
    #[error("budget store at capacity")]
    Capacity,
}

/// An atomic, per-key budget store.
#[async_trait]
pub trait BudgetStore: Send + Sync {
    /// Atomically charge `cost` units for `key` under `scope`.
    ///
    /// Implementations must read the bucket, apply [`crate::Gcra::check`], and
    /// write it back without another writer interleaving.
    async fn check(
        &self,
        scope: PolicyId,
        key: Key,
        quota: &Quota,
        cost: u32,
        now_ms: i64,
        retry_cap_ms: i64,
    ) -> Result<Charge, StoreError>;

    /// Atomically charge every `(key, quota)` in `budgets` under `scope`.
    ///
    /// The default implementation charges keys one at a time. A store that can
    /// make the whole set atomic — one SQLite transaction, or one lock — should
    /// override it. Either way a partial failure only ever *over*-charges, which
    /// is the fail-safe direction.
    async fn check_all(
        &self,
        scope: PolicyId,
        budgets: &[(Key, Quota)],
        cost: u32,
        now_ms: i64,
        retry_cap_ms: i64,
    ) -> Result<Vec<Charge>, StoreError> {
        let mut decisions = Vec::with_capacity(budgets.len());
        for (key, quota) in budgets {
            decisions.push(
                self.check(scope, *key, quota, cost, now_ms, retry_cap_ms)
                    .await?,
            );
        }
        Ok(decisions)
    }
}
