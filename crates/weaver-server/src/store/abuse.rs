//! Persistent rate-limit buckets (WVR-135).
//!
//! The GCRA arithmetic lives in `weaver-abuse`; this module is the store side:
//! it loads each key's theoretical-arrival time, runs the pure
//! [`weaver_abuse::Gcra::check`], and writes it back. Everything for one policy
//! charge happens in a single transaction, so a multi-key policy is atomic and
//! a crash can never leave a half-charged bucket set. This is the only place
//! `abuse_bucket` rows change.

use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait};
use weaver_abuse::{Charge, Gcra, Key, PolicyId, Quota};

use super::entity::abuse_bucket;
use super::{Store, StoreError};

impl Store {
    /// Atomically charge every `(key, quota)` in `budgets` for `scope`.
    ///
    /// Runs in one transaction: each bucket is read, charged with the pure
    /// [`Gcra::check`], and upserted; the decisions are returned once the
    /// transaction commits. `key_id` is stored as its `i64` bit pattern — the
    /// sign is irrelevant, only round-trip equality matters.
    pub(crate) async fn abuse_check_all(
        &self,
        scope: PolicyId,
        budgets: &[(Key, Quota)],
        cost: u32,
        now_ms: i64,
        retry_cap_ms: i64,
    ) -> Result<Vec<Charge>, StoreError> {
        let txn = self.db.begin().await?;
        let mut decisions = Vec::with_capacity(budgets.len());
        for (key, quota) in budgets {
            let key_id = key.id as i64;
            let existing = abuse_bucket::Entity::find()
                .filter(abuse_bucket::Column::Scope.eq(scope.as_str()))
                .filter(abuse_bucket::Column::KeyKind.eq(key.kind.code()))
                .filter(abuse_bucket::Column::KeyId.eq(key_id))
                .one(&txn)
                .await?;

            let mut gcra = match existing {
                Some(model) => Gcra::from_tat_ms(model.tat_ms),
                None => Gcra::new(),
            };
            let decision = gcra.check(quota, cost, now_ms, retry_cap_ms);
            let tat_ms = gcra.tat_ms().unwrap_or(now_ms);

            abuse_bucket::Entity::insert(abuse_bucket::ActiveModel {
                scope: Set(scope.as_str().to_string()),
                key_kind: Set(key.kind.code()),
                key_id: Set(key_id),
                tat_ms: Set(tat_ms),
                updated_at_ms: Set(now_ms),
            })
            .on_conflict(
                OnConflict::columns([
                    abuse_bucket::Column::Scope,
                    abuse_bucket::Column::KeyKind,
                    abuse_bucket::Column::KeyId,
                ])
                .update_columns([
                    abuse_bucket::Column::TatMs,
                    abuse_bucket::Column::UpdatedAtMs,
                ])
                .to_owned(),
            )
            .exec_without_returning(&txn)
            .await?;

            decisions.push(decision);
        }
        txn.commit().await?;
        Ok(decisions)
    }

    /// Delete buckets untouched since `cutoff_ms`; returns the rows removed.
    pub(crate) async fn abuse_sweep(&self, cutoff_ms: i64) -> Result<u64, StoreError> {
        let result = abuse_bucket::Entity::delete_many()
            .filter(abuse_bucket::Column::UpdatedAtMs.lt(cutoff_ms))
            .exec(&self.db)
            .await?;
        Ok(result.rows_affected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use weaver_abuse::{KeyKind, Outcome, Rate};

    fn quota() -> Quota {
        Quota {
            burst: 2,
            refill: Rate {
                units: 1,
                per_ms: 60_000,
            },
        }
    }

    fn keys() -> Vec<(Key, Quota)> {
        vec![
            (
                Key {
                    kind: KeyKind::PeerHost,
                    id: 1,
                },
                quota(),
            ),
            (
                Key {
                    kind: KeyKind::PeerNetwork,
                    id: 2,
                },
                quota(),
            ),
        ]
    }

    #[tokio::test]
    async fn charge_is_atomic_and_survives_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("abuse.db");
        let scope = PolicyId::RELAY_WEB;

        let store = Store::open(&path).await.unwrap();
        // Burst of 2: the first two units admit, the third is refused.
        for _ in 0..2 {
            let decisions = store
                .abuse_check_all(scope, &keys(), 1, 0, 60_000)
                .await
                .unwrap();
            assert!(decisions.iter().all(|d| d.outcome == Outcome::Admitted));
        }
        let third = store
            .abuse_check_all(scope, &keys(), 1, 0, 60_000)
            .await
            .unwrap();
        assert!(third.iter().all(|d| d.outcome == Outcome::Throttled));
        drop(store);

        // A fresh open sees the persisted debt.
        let reopened = Store::open(&path).await.unwrap();
        let again = reopened
            .abuse_check_all(scope, &keys(), 1, 0, 60_000)
            .await
            .unwrap();
        assert!(again.iter().all(|d| d.outcome == Outcome::Throttled));
    }

    #[tokio::test]
    async fn sweep_removes_only_idle_rows() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let scope = PolicyId::RELAY_WEB;
        let old = [(
            Key {
                kind: KeyKind::PeerHost,
                id: 10,
            },
            quota(),
        )];
        let fresh = [(
            Key {
                kind: KeyKind::PeerHost,
                id: 11,
            },
            quota(),
        )];
        store
            .abuse_check_all(scope, &old, 1, 1_000, 60_000)
            .await
            .unwrap();
        store
            .abuse_check_all(scope, &fresh, 1, 100_000, 60_000)
            .await
            .unwrap();

        let removed = store.abuse_sweep(50_000).await.unwrap();
        assert_eq!(removed, 1, "only the idle row is swept");
    }
}
