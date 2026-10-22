//! Usage reads for the metering control verb: the live day's arrays aggregated.
//!
//! The slot *storage* lives in [`super::usage_live`] and the rollup reads live
//! in [`crate::metrics`]; what is here is the one query the metering manager
//! serves — a per-service aggregate over a window, with the display identity
//! (`service`, `machine`, `person`) resolved from the store.
//!
//! The window is read from the **live day's arrays** only. A folded day's
//! minutes are compressed into `usage_daily` and are no longer readable minute
//! by minute — exactly as the old per-minute `usage` rows were deleted as they
//! were folded — so a folded day contributes nothing here. The console's own
//! figures come from [`crate::metrics::MetricsStore::totals`], which does see
//! the rolled-up day.

use std::collections::{BTreeMap, HashMap};

use sea_orm::{
    ColumnTrait, EntityTrait, JoinType, QueryFilter, QueryOrder, QuerySelect, RelationTrait,
};

use super::entity::{machine, person, service};
use super::usage_live::{MINUTES_PER_DAY, Slots};
use super::{Store, StoreError};

impl Store {
    /// Aggregated per-service usage over `[since_min, until_min)`, optionally
    /// filtered by person and/or service name.
    ///
    /// `since_min`/`until_min` are minute numbers. `open_ms` is the sum of the
    /// `open_ms` slots, which store open time directly — there is no stored
    /// inversion to undo any more. An unknown person or service name matches
    /// nothing and yields an empty result, not an error.
    ///
    /// A minute counts as *covered* when any of its six slots is non-zero, i.e.
    /// when a bucket was recorded for it; a service with no covered minute in
    /// the window is left out of the result.
    pub(crate) async fn query_usage(
        &self,
        person: Option<&str>,
        service: Option<&str>,
        since_min: i64,
        until_min: i64,
    ) -> Result<Vec<UsageTotal>, StoreError> {
        if until_min <= since_min {
            return Ok(Vec::new());
        }
        let identities = self.usage_identities(person, service).await?;
        if identities.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<i32> = identities.iter().map(|i| i.service_id).collect();
        let mut totals: HashMap<i32, UsageTotal> = identities
            .into_iter()
            .map(|identity| (identity.service_id, UsageTotal::from_identity(&identity)))
            .collect();

        let first_day = since_min.div_euclid(MINUTES_PER_DAY as i64);
        let last_day = (until_min - 1).div_euclid(MINUTES_PER_DAY as i64);
        let mut by_day: BTreeMap<i64, Vec<i32>> = BTreeMap::new();
        for (service_id, day) in self.live_days(&ids).await? {
            if (first_day..=last_day).contains(&day) {
                by_day.entry(day).or_default().push(service_id);
            }
        }

        for (day, day_services) in by_day {
            let arrays = self
                .read_day_slots_of(&day_services, day, &Slots::ALL)
                .await?;
            let base = day * MINUTES_PER_DAY as i64;
            // Only the window's minutes can be covered; skip the rest.
            let first = (since_min - base).clamp(0, MINUTES_PER_DAY as i64) as usize;
            let last = (until_min - base).clamp(0, MINUTES_PER_DAY as i64) as usize;
            for service_id in day_services {
                let Some(total) = totals.get_mut(&service_id) else {
                    continue;
                };
                for index in first..last {
                    let mut covered = false;
                    for slot in Slots::ALL {
                        let Some(value) = arrays
                            .get(&(service_id, slot))
                            .and_then(|values| values.get(index))
                            .copied()
                        else {
                            continue;
                        };
                        covered |= value != 0;
                        match slot {
                            Slots::BytesIn => total.bytes_in += value,
                            Slots::BytesOut => total.bytes_out += value,
                            Slots::TunnelIn => total.tunnel_in += value,
                            Slots::TunnelOut => total.tunnel_out += value,
                            Slots::Requests => total.requests += value,
                            Slots::OpenMs => total.open_ms += value,
                        }
                    }
                    if covered {
                        total.covered_minutes += 1;
                    }
                }
            }
        }

        let mut totals: Vec<UsageTotal> = totals
            .into_values()
            .filter(|total| total.covered_minutes > 0)
            .collect();
        totals.sort_by(|a, b| {
            (&a.person, &a.machine, &a.service).cmp(&(&b.person, &b.machine, &b.service))
        });
        Ok(totals)
    }

    /// The services matching the meter's optional person/service-name filters,
    /// with their display identity, in `person → machine → service` order.
    ///
    /// An unknown name matches nothing, so the filter is applied to the
    /// identity rather than to usage, and a service with no usage in the window
    /// is simply absent from [`Store::query_usage`]'s result.
    async fn usage_identities(
        &self,
        person: Option<&str>,
        service: Option<&str>,
    ) -> Result<Vec<ServiceIdentity>, StoreError> {
        let mut query = service::Entity::find()
            .select_only()
            .column_as(service::Column::Id, "service_id")
            .column_as(service::Column::Name, "service")
            .column_as(machine::Column::Name, "machine")
            .column_as(person::Column::Name, "person")
            .join(JoinType::InnerJoin, service::Relation::Machine.def())
            .join(JoinType::InnerJoin, machine::Relation::Person.def())
            .order_by_asc(person::Column::Name)
            .order_by_asc(machine::Column::Name)
            .order_by_asc(service::Column::Name);
        if let Some(person) = person {
            query = query.filter(person::Column::Name.eq(person.to_ascii_lowercase()));
        }
        if let Some(service) = service {
            query = query.filter(service::Column::Name.eq(service.to_ascii_lowercase()));
        }
        Ok(query
            .into_model::<ServiceIdentityRow>()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|row| ServiceIdentity {
                service_id: row.service_id,
                service: row.service,
                machine: row.machine,
                person: row.person,
            })
            .collect())
    }

    /// Resolves `(service, machine, person)` names for a set of service ids.
    ///
    /// Used by the metering manager to name services that only exist in the
    /// unflushed in-memory buckets and therefore have no persisted slot array
    /// to read. Unknown ids are simply absent from the result.
    pub(crate) async fn service_identities(
        &self,
        ids: &[i32],
    ) -> Result<Vec<ServiceIdentity>, StoreError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = service::Entity::find()
            .select_only()
            .column_as(service::Column::Id, "service_id")
            .column_as(service::Column::Name, "service")
            .column_as(machine::Column::Name, "machine")
            .column_as(person::Column::Name, "person")
            .join(JoinType::InnerJoin, service::Relation::Machine.def())
            .join(JoinType::InnerJoin, machine::Relation::Person.def())
            .filter(service::Column::Id.is_in(ids.iter().copied()))
            .into_model::<ServiceIdentityRow>()
            .all(&self.db)
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| ServiceIdentity {
                service_id: r.service_id,
                service: r.service,
                machine: r.machine,
                person: r.person,
            })
            .collect())
    }
}

/// One service's display identity, resolved from `service → machine → person`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServiceIdentity {
    pub(crate) service_id: i32,
    pub(crate) service: String,
    pub(crate) machine: String,
    pub(crate) person: String,
}

/// Raw identity row matched to the query's column aliases.
#[derive(Debug, sea_orm::FromQueryResult)]
struct ServiceIdentityRow {
    service_id: i32,
    service: String,
    machine: String,
    person: String,
}

/// Aggregated usage for one service over a queried window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageTotal {
    pub service_id: i32,
    pub service: String,
    pub machine: String,
    pub person: String,
    /// Visitor leg: browser -> relay body bytes.
    pub bytes_in: i64,
    /// Visitor leg: relay -> browser body bytes.
    pub bytes_out: i64,
    /// Tunnel leg: client -> relay compressed bytes.
    pub tunnel_in: i64,
    /// Tunnel leg: relay -> client compressed bytes.
    pub tunnel_out: i64,
    pub requests: i64,
    /// Distinct minutes with a recorded bucket in the window.
    pub covered_minutes: i64,
    /// Milliseconds the service was registered across the window.
    pub open_ms: i64,
}

impl UsageTotal {
    /// A zeroed total carrying an identity, ready to be summed into.
    fn from_identity(identity: &ServiceIdentity) -> Self {
        Self {
            service_id: identity.service_id,
            service: identity.service.clone(),
            machine: identity.machine.clone(),
            person: identity.person.clone(),
            bytes_in: 0,
            bytes_out: 0,
            tunnel_in: 0,
            tunnel_out: 0,
            requests: 0,
            covered_minutes: 0,
            open_ms: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::usage_live::SlotWrite;

    /// Writes one minute's worth of one metric at its slot in `day`.
    async fn slot(store: &Store, service_id: i32, minute: i64, slots: Slots, value: i64) {
        let day = minute.div_euclid(MINUTES_PER_DAY as i64);
        store
            .write_day_slots(&[SlotWrite {
                service_id,
                day,
                slots,
                first_slot: (minute - day * MINUTES_PER_DAY as i64) as u16,
                values: vec![value],
            }])
            .await
            .expect("write slot");
    }

    #[tokio::test]
    async fn query_sums_the_live_arrays_and_inverts_nothing() {
        let store = Store::connect("sqlite::memory:").await.expect("connect");
        let alice = store.create_test_person("Alice").await.expect("person");
        let laptop = store
            .create_machine(alice.id, "Laptop", &weaver_mux::KeyId::Ed25519([1; 32]))
            .await
            .expect("machine");
        let web = store
            .get_or_create_service(laptop.id, "web")
            .await
            .expect("service");

        // Minute 100: half open. Minute 101: fully open.
        for (minute, bytes, open_ms) in [(100, 3, 30_000), (101, 9, 60_000)] {
            slot(&store, web.id, minute, Slots::BytesIn, bytes).await;
            slot(&store, web.id, minute, Slots::BytesOut, bytes * 2).await;
            slot(&store, web.id, minute, Slots::Requests, 1).await;
            slot(&store, web.id, minute, Slots::OpenMs, open_ms).await;
        }

        let totals = store
            .query_usage(None, None, 100, 102)
            .await
            .expect("query");
        assert_eq!(totals.len(), 1);
        let t = &totals[0];
        assert_eq!(t.covered_minutes, 2);
        assert_eq!(t.bytes_in, 12);
        assert_eq!(t.bytes_out, 24);
        assert_eq!(t.requests, 2);
        assert_eq!(t.open_ms, 90_000, "30000 + 60000, no inversion left");
        assert_eq!(t.service, "web");
        assert_eq!(t.machine, "laptop");
        assert_eq!(t.person, "alice");

        // The window is half-open: [100, 101) covers only minute 100.
        let only_100 = store.query_usage(None, None, 100, 101).await.unwrap();
        assert_eq!(only_100[0].covered_minutes, 1);
        assert_eq!(only_100[0].open_ms, 30_000);

        // Filters match case-insensitively; unknown names yield no rows.
        assert_eq!(
            store
                .query_usage(None, Some("WEB"), 100, 102)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store
                .query_usage(Some("alice"), None, 100, 102)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            store
                .query_usage(Some("bob"), None, 100, 102)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .query_usage(None, Some("nope"), 100, 102)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// A service with no recorded minute is absent, and so is a window with no
    /// live row at all.
    #[tokio::test]
    async fn a_window_with_no_slots_yields_nothing() {
        let store = Store::connect("sqlite::memory:").await.expect("connect");
        let alice = store.create_test_person("alice").await.expect("person");
        let laptop = store
            .create_machine(alice.id, "laptop", &weaver_mux::KeyId::Ed25519([1; 32]))
            .await
            .expect("machine");
        store.get_or_create_service(laptop.id, "web").await.unwrap();

        assert!(
            store
                .query_usage(None, None, 0, 1_000)
                .await
                .unwrap()
                .is_empty()
        );
        slot(&store, 1, 100, Slots::Requests, 0).await;
        assert!(
            store
                .query_usage(None, None, 0, 1_000)
                .await
                .unwrap()
                .is_empty(),
            "an all-zero bucket is not a covered minute"
        );
    }
}
