//! Deterministic fixtures for downstream tests.
//!
//! Gated behind the `test-util` feature so it never ships in the engine's
//! production path. The server's own store is SQLite-backed; this exists to
//! exercise the gate and the server's edge wiring without a database.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;

use crate::gcra::{Charge, Gcra, Quota};
use crate::key::{Key, KeyKind};
use crate::policy::PolicyId;
use crate::store::{BudgetStore, StoreError};

/// A bounded, in-memory [`BudgetStore`] for tests and examples.
///
/// Single-process only, with lazy idle-TTL eviction and a hard entry cap. The
/// whole policy is charged under one lock, so multi-key admission is atomic.
/// State is lost on drop — real deployments use the server's SQLite store.
pub struct MemoryStore {
    inner: Mutex<Inner>,
    cap: usize,
    ttl_ms: i64,
}

struct Inner {
    entries: HashMap<EntryId, Entry>,
}

#[derive(PartialEq, Eq, Hash)]
struct EntryId {
    scope: &'static str,
    kind: KeyKind,
    id: u64,
}

struct Entry {
    gcra: Gcra,
    updated_ms: i64,
}

impl MemoryStore {
    /// Build a store capped at `cap` entries with a `ttl_ms` idle lifetime.
    pub fn new(cap: usize, ttl_ms: i64) -> Self {
        Self {
            inner: Mutex::new(Inner {
                entries: HashMap::new(),
            }),
            cap,
            ttl_ms,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|err| err.into_inner())
    }

    fn evict(inner: &mut Inner, now_ms: i64, ttl_ms: i64) {
        if ttl_ms <= 0 {
            return;
        }
        let cutoff = now_ms.saturating_sub(ttl_ms);
        inner.entries.retain(|_, entry| entry.updated_ms >= cutoff);
    }

    fn id(scope: PolicyId, key: Key) -> EntryId {
        EntryId {
            scope: scope.as_str(),
            kind: key.kind,
            id: key.id,
        }
    }

    fn charge(entry: &mut Entry, quota: &Quota, cost: u32, now_ms: i64, cap_ms: i64) -> Charge {
        entry.updated_ms = now_ms;
        entry.gcra.check(quota, cost, now_ms, cap_ms)
    }
}

#[async_trait]
impl BudgetStore for MemoryStore {
    async fn check(
        &self,
        scope: PolicyId,
        key: Key,
        quota: &Quota,
        cost: u32,
        now_ms: i64,
        retry_cap_ms: i64,
    ) -> Result<Charge, StoreError> {
        let mut inner = self.lock();
        Self::evict(&mut inner, now_ms, self.ttl_ms);
        let id = Self::id(scope, key);
        if !inner.entries.contains_key(&id) && inner.entries.len() >= self.cap {
            return Err(StoreError::Capacity);
        }
        let entry = inner.entries.entry(id).or_insert_with(|| Entry {
            gcra: Gcra::new(),
            updated_ms: now_ms,
        });
        Ok(Self::charge(entry, quota, cost, now_ms, retry_cap_ms))
    }

    async fn check_all(
        &self,
        scope: PolicyId,
        budgets: &[(Key, Quota)],
        cost: u32,
        now_ms: i64,
        retry_cap_ms: i64,
    ) -> Result<Vec<Charge>, StoreError> {
        let mut inner = self.lock();
        Self::evict(&mut inner, now_ms, self.ttl_ms);

        // All-or-nothing capacity check for the new keys in this policy.
        let new_keys = budgets
            .iter()
            .filter(|(key, _)| !inner.entries.contains_key(&Self::id(scope, *key)))
            .count();
        if inner.entries.len() + new_keys > self.cap {
            return Err(StoreError::Capacity);
        }

        let mut decisions = Vec::with_capacity(budgets.len());
        for (key, quota) in budgets {
            let id = Self::id(scope, *key);
            let entry = inner.entries.entry(id).or_insert_with(|| Entry {
                gcra: Gcra::new(),
                updated_ms: now_ms,
            });
            decisions.push(Self::charge(entry, quota, cost, now_ms, retry_cap_ms));
        }
        Ok(decisions)
    }
}
