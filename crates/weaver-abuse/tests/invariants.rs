//! End-to-end invariants for the engine, exercised through the public API and
//! the in-memory fixture store.

use async_trait::async_trait;
use proptest::prelude::*;
use weaver_abuse::testing::MemoryStore;
use weaver_abuse::{
    Budget, BudgetStore, Charge, Gate, GateError, Gcra, Key, KeyKind, Outcome, Policy, PolicyId,
    PolicySet, Quota, Rate, StoreError, StoreErrorPolicy, fingerprint,
};

const CAP: i64 = 1_000_000; // effectively no retry clamp

fn quota(burst: u32, units: u32, per_ms: i64) -> Quota {
    Quota {
        burst,
        refill: Rate { units, per_ms },
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..Default::default() })]

    /// Waiting exactly the reported delay admits again.
    #[test]
    fn retry_delay_is_sufficient(burst in 1u32..=8, units in 1u32..=5, per_ms in 100i64..=5000) {
        let q = quota(burst, units, per_ms);
        let mut gcra = Gcra::new();
        for _ in 0..burst {
            let _ = gcra.check(&q, 1, 0, CAP);
        }
        let denied = gcra.check(&q, 1, 0, CAP);
        prop_assert_eq!(denied.outcome, Outcome::Throttled);
        let recovered = gcra.check(&q, 1, denied.retry_after_ms, CAP);
        prop_assert_eq!(recovered.outcome, Outcome::Admitted);
    }

    /// Over any window of length `per_ms`, admissions never exceed `burst + units`.
    #[test]
    fn conservation(burst in 1u32..=6, units in 1u32..=4, per_ms in 200i64..=2000) {
        let q = quota(burst, units, per_ms);
        let step = (per_ms / i64::from(units)).max(1);
        let mut gcra = Gcra::new();
        let mut admitted_at = Vec::new();
        let mut now = 0i64;
        for i in 0..40 {
            now += i64::from(i % 3) * step;
            if gcra.check(&q, 1, now, CAP).outcome == Outcome::Admitted {
                admitted_at.push(now);
            }
        }
        let limit = burst + units;
        for &start in &admitted_at {
            let count = admitted_at
                .iter()
                .filter(|&&t| t >= start && t < start + per_ms)
                .count() as u32;
            prop_assert!(count <= limit, "count {count} exceeds {limit}");
        }
    }

}

#[tokio::test]
async fn memory_store_matches_reference_gcra() {
    let q = quota(3, 1, 1000);
    let store = MemoryStore::new(1024, 0);
    let scope = PolicyId::RELAY_WEB;
    let key = Key {
        kind: KeyKind::PeerHost,
        id: 42,
    };
    let mut reference = Gcra::new();
    for step in 0..50 {
        let now = step * 500;
        let got = store.check(scope, key, &q, 1, now, CAP).await.unwrap();
        let want = reference.check(&q, 1, now, CAP);
        assert_eq!(got, want, "step {step}");
    }
}

#[tokio::test]
async fn memory_store_bounds_capacity_and_expires() {
    let q = quota(3, 1, 1000);
    let store = MemoryStore::new(2, 1000);
    let scope = PolicyId::RELAY_WEB;
    let key = |id| Key {
        kind: KeyKind::PeerHost,
        id,
    };

    assert!(store.check(scope, key(1), &q, 1, 0, CAP).await.is_ok());
    assert!(store.check(scope, key(2), &q, 1, 0, CAP).await.is_ok());
    assert!(matches!(
        store.check(scope, key(3), &q, 1, 0, CAP).await,
        Err(StoreError::Capacity)
    ));

    // Past the idle TTL the old entries expire and a new key fits again.
    assert!(store.check(scope, key(3), &q, 1, 2000, CAP).await.is_ok());
}

/// Returns a fixed decision per key, in order.
struct StubStore(Vec<Charge>);

#[async_trait]
impl BudgetStore for StubStore {
    async fn check(
        &self,
        _scope: PolicyId,
        _key: Key,
        _quota: &Quota,
        _cost: u32,
        _now_ms: i64,
        _retry_cap_ms: i64,
    ) -> Result<Charge, StoreError> {
        Ok(self.0[0])
    }

    async fn check_all(
        &self,
        _scope: PolicyId,
        budgets: &[(Key, Quota)],
        _cost: u32,
        _now_ms: i64,
        _retry_cap_ms: i64,
    ) -> Result<Vec<Charge>, StoreError> {
        Ok(self.0.iter().copied().take(budgets.len()).collect())
    }
}

/// Always fails, to exercise the store-error policy.
struct FailingStore;

#[async_trait]
impl BudgetStore for FailingStore {
    async fn check(
        &self,
        _scope: PolicyId,
        _key: Key,
        _quota: &Quota,
        _cost: u32,
        _now_ms: i64,
        _retry_cap_ms: i64,
    ) -> Result<Charge, StoreError> {
        Err(StoreError::Unavailable)
    }
}

fn two_budget_policy(on_store_error: StoreErrorPolicy) -> PolicySet {
    PolicySet::new(vec![Policy {
        id: PolicyId::RELAY_WEB,
        budgets: vec![
            Budget {
                key: KeyKind::PeerHost,
                quota: quota(3, 1, 1000),
            },
            Budget {
                key: KeyKind::PeerNetwork,
                quota: quota(30, 10, 1000),
            },
        ],
        on_store_error,
    }])
}

fn decision(outcome: Outcome, retry_after_ms: i64) -> Charge {
    Charge {
        outcome,
        retry_after_ms,
    }
}

#[tokio::test]
async fn gate_reports_the_longest_retry() {
    let gate = Gate::new(
        StubStore(vec![
            decision(Outcome::Throttled, 100),
            decision(Outcome::Throttled, 300),
        ]),
        two_budget_policy(StoreErrorPolicy::Degraded),
        CAP,
    );
    let fp = fingerprint("10.0.0.1".parse().unwrap());
    let err = gate
        .admit(PolicyId::RELAY_WEB, &fp, 1, 0)
        .await
        .unwrap_err();
    match err {
        GateError::Throttled { retry_after_ms, .. } => assert_eq!(retry_after_ms, 300),
        other => panic!("expected throttled, got {other:?}"),
    }
}

#[tokio::test]
async fn gate_throttles_when_any_budget_refuses() {
    let gate = Gate::new(
        StubStore(vec![
            decision(Outcome::Admitted, 0),
            decision(Outcome::Throttled, 200),
        ]),
        two_budget_policy(StoreErrorPolicy::Degraded),
        CAP,
    );
    let fp = fingerprint("10.0.0.1".parse().unwrap());
    assert_eq!(
        gate.admit(PolicyId::RELAY_WEB, &fp, 1, 0).await,
        Err(GateError::Throttled {
            policy: PolicyId::RELAY_WEB,
            retry_after_ms: 200,
        })
    );
}
#[tokio::test]
async fn gate_surfaces_store_failure_stance() {
    let gate = Gate::new(
        FailingStore,
        two_budget_policy(StoreErrorPolicy::FailClosed),
        CAP,
    );
    let fp = fingerprint("10.0.0.1".parse().unwrap());
    assert_eq!(
        gate.admit(PolicyId::RELAY_WEB, &fp, 1, 0)
            .await
            .unwrap_err(),
        GateError::Store {
            policy: PolicyId::RELAY_WEB,
            decision: StoreErrorPolicy::FailClosed,
        }
    );
}

#[tokio::test]
async fn gate_end_to_end_through_memory_store() {
    let gate = Gate::new(
        MemoryStore::new(64, 0),
        two_budget_policy(StoreErrorPolicy::Degraded),
        CAP,
    );
    let fp = fingerprint("203.0.113.9".parse().unwrap());
    // The peer-host burst (3) is the tighter budget, so the 4th unit is refused.
    for i in 0..3 {
        assert!(
            gate.admit(PolicyId::RELAY_WEB, &fp, 1, 0).await.is_ok(),
            "admission {i}"
        );
    }
    assert!(matches!(
        gate.admit(PolicyId::RELAY_WEB, &fp, 1, 0).await,
        Err(GateError::Throttled { .. })
    ));
    // A different source has its own budget.
    let other = fingerprint("203.0.113.10".parse().unwrap());
    assert!(gate.admit(PolicyId::RELAY_WEB, &other, 1, 0).await.is_ok());
}
