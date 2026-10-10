//! The admission gate: charge a fingerprint's budgets for a policy.

use crate::gcra::Quota;
use crate::key::{Fingerprint, Key};
use crate::policy::{PolicyId, PolicySet, StoreErrorPolicy};
use crate::store::BudgetStore;

/// A granted request, carrying the budget left on the tightest key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admission {
    /// Remaining unit-cost requests on the tightest budget, after charging.
    pub remaining: u32,
}

/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateError {
    /// The caller exceeded a budget; retry after `retry_after_ms`.
    Throttled {
        /// The policy that refused.
        policy: PolicyId,
        /// Milliseconds to wait, already bounded by the configured cap.
        retry_after_ms: i64,
        /// Always 0 for a refusal; present for symmetry with [`Admission`].
        remaining: u32,
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

    /// The underlying store.
    pub fn store(&self) -> &S {
        &self.store
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
    ) -> Result<Admission, GateError> {
        let Some(configured) = self.policies.get(policy) else {
            return Ok(Admission { remaining: 0 });
        };
        let selected: Vec<(Key, Quota)> = configured
            .budgets
            .iter()
            .filter_map(|budget| fp.get(budget.key).map(|key| (key, budget.quota)))
            .collect();
        if selected.is_empty() {
            return Ok(Admission { remaining: 0 });
        }

        let decisions = match self
            .store
            .check_all(policy, &selected, cost, now_ms, self.retry_cap_ms)
            .await
        {
            Ok(decisions) => decisions,
            Err(_) => {
                return Err(GateError::Store {
                    policy,
                    decision: configured.on_store_error,
                });
            }
        };

        let mut retry_after_ms = 0i64;
        let mut remaining = u32::MAX;
        for decision in &decisions {
            if decision.outcome == crate::gcra::Outcome::Throttled {
                retry_after_ms = retry_after_ms.max(decision.retry_after_ms);
            }
            remaining = remaining.min(decision.remaining);
        }

        if retry_after_ms > 0 {
            return Err(GateError::Throttled {
                policy,
                retry_after_ms,
                remaining: 0,
            });
        }
        Ok(Admission {
            remaining: if remaining == u32::MAX { 0 } else { remaining },
        })
    }
}
