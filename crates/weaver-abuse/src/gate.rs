//! The admission gate: charge a fingerprint's budgets for a policy.

use crate::gcra::{Outcome, Quota};
use crate::key::{Fingerprint, Key};
use crate::policy::{PolicyId, PolicySet, StoreErrorPolicy};
use crate::store::BudgetStore;

/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateError {
    /// The caller exceeded a budget; retry after `retry_after_ms`.
    Throttled {
        /// The policy that refused.
        policy: PolicyId,
        /// Milliseconds to wait, already bounded by the configured cap.
        retry_after_ms: i64,
    },
    /// The budget store failed; `decision` is the policy's configured stance.
    Store {
        /// The policy whose charge failed.
        policy: PolicyId,
        /// How the caller should treat a store failure for this policy.
        decision: StoreErrorPolicy,
    },
}

/// Charges a fingerprint's budgets against an injected [`BudgetStore`].
pub struct Gate<S> {
    store: S,
    policies: PolicySet,
    retry_cap_ms: i64,
}

impl<S: BudgetStore> Gate<S> {
    /// Build a gate over `store` with `policies` and a `Retry-After` bound.
    pub fn new(store: S, policies: PolicySet, retry_cap_ms: i64) -> Self {
        Self {
            store,
            policies,
            retry_cap_ms,
        }
    }

    /// Charge every budget `policy` selects for `fp`, at `cost` units.
    ///
    /// A request is admitted only if every selected budget admits; the longest
    /// `retry_after_ms` wins. An unknown policy, or one whose budgets match no
    /// key in the fingerprint, admits without charging.
    pub async fn admit(
        &self,
        policy: PolicyId,
        fp: &Fingerprint,
        cost: u32,
        now_ms: i64,
    ) -> Result<(), GateError> {
        let Some(configured) = self.policies.get(policy) else {
            return Ok(());
        };
        let selected: Vec<(Key, Quota)> = configured
            .budgets
            .iter()
            .filter_map(|budget| fp.get(budget.key).map(|key| (key, budget.quota)))
            .collect();
        if selected.is_empty() {
            return Ok(());
        }

        let charges = self
            .store
            .check_all(policy, &selected, cost, now_ms, self.retry_cap_ms)
            .await
            .map_err(|_| GateError::Store {
                policy,
                decision: configured.on_store_error,
            })?;

        let retry_after_ms = charges
            .iter()
            .filter(|charge| charge.outcome == Outcome::Throttled)
            .map(|charge| charge.retry_after_ms)
            .max();
        match retry_after_ms {
            Some(retry_after_ms) => Err(GateError::Throttled {
                policy,
                retry_after_ms,
            }),
            None => Ok(()),
        }
    }
}
