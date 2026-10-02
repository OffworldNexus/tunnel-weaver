//! Persistent usage storage: one row per `(service_id, minute)` bucket.
//!
//! The storage logic for [`Store`] lives here rather than in `store/mod.rs` so
//! that module stays about general store concerns. The business-logic caller
//! is [`crate::metering::MeteringManager`]; nothing else reads or writes usage
//! rows, and the `unused_ms` inversion never leaks past this module.

use sea_orm::sea_query::{Alias, Expr, ExprTrait, OnConflict};
use sea_orm::{
    ColumnTrait, EntityTrait, JoinType, QueryFilter, QueryOrder, QuerySelect, RelationTrait, Set,
    TransactionTrait,
};

use super::entity::{machine, person, service, usage};
use super::{Store, StoreError};

impl Store {
    /// Persists a batch of metered minute buckets in one transaction.
    ///
    /// The bucket key is `(service_id, minute)`. Every counter is
    /// *incremented* on conflict — the manager flushes each bucket once, so
    /// the increment path is a safety net for a partial minute landing on an
    /// already-written one — and the stored `unused_ms` is produced by
    /// [`unused_ms_from_open_ms`], the single place the inversion happens.
    /// `open_ms` outside `0..=60_000` is rejected, never silently clamped.
    pub(crate) async fn upsert_usage_batch(&self, rows: &[UsageRow]) -> Result<(), StoreError> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut models = Vec::with_capacity(rows.len());
        for row in rows {
            models.push(usage::ActiveModel {
                service_id: Set(row.service_id),
                minute: Set(row.minute),
                bytes_in: Set(row.bytes_in),
                bytes_out: Set(row.bytes_out),
                tunnel_in: Set(row.tunnel_in),
                tunnel_out: Set(row.tunnel_out),
                requests: Set(row.requests),
                unused_ms: Set(unused_ms_from_open_ms(row.open_ms)?),
            });
        }
        // SQLite/Postgres expose the proposed row as `excluded`; referencing
        // it explicitly lets us add the incoming counters to the stored ones
        // rather than overwrite them.
        let excluded = |col: usage::Column| Expr::col((Alias::new("excluded"), col));
        let mut conflict = OnConflict::columns([usage::Column::ServiceId, usage::Column::Minute]);
        conflict
            .value(
                usage::Column::BytesIn,
                Expr::col(usage::Column::BytesIn).add(excluded(usage::Column::BytesIn)),
            )
            .value(
                usage::Column::BytesOut,
                Expr::col(usage::Column::BytesOut).add(excluded(usage::Column::BytesOut)),
            )
            .value(
                usage::Column::TunnelIn,
                Expr::col(usage::Column::TunnelIn).add(excluded(usage::Column::TunnelIn)),
            )
            .value(
                usage::Column::TunnelOut,
                Expr::col(usage::Column::TunnelOut).add(excluded(usage::Column::TunnelOut)),
            )
            .value(
                usage::Column::Requests,
                Expr::col(usage::Column::Requests).add(excluded(usage::Column::Requests)),
            )
            .value(
                usage::Column::UnusedMs,
                Expr::col(usage::Column::UnusedMs).add(excluded(usage::Column::UnusedMs)),
            );

        let txn = self.db.begin().await?;
        usage::Entity::insert_many(models)
            .on_conflict(conflict)
            .exec_without_returning(&txn)
            .await?;
        txn.commit().await?;
        Ok(())
    }

    /// Aggregated per-service usage over `[since_min, until_min)`, optionally
    /// filtered by person and/or service name.
    ///
    /// `since_min`/`until_min` are minute numbers. `open_ms` is derived here
    /// and only here (`covered_minutes * 60_000 - SUM(unused_ms)`), so the
    /// stored inversion never leaks past the store. An unknown person or
    /// service name matches nothing and yields an empty result, not an error.
    pub(crate) async fn query_usage(
        &self,
        person: Option<&str>,
        service: Option<&str>,
        since_min: i64,
        until_min: i64,
    ) -> Result<Vec<UsageTotal>, StoreError> {
        let mut query = usage::Entity::find()
            .select_only()
            .column(usage::Column::ServiceId)
            .column_as(service::Column::Name, "service")
            .column_as(machine::Column::Name, "machine")
            .column_as(person::Column::Name, "person")
            .column_as(Expr::col(usage::Column::BytesIn).sum(), "bytes_in")
            .column_as(Expr::col(usage::Column::BytesOut).sum(), "bytes_out")
            .column_as(Expr::col(usage::Column::TunnelIn).sum(), "tunnel_in")
            .column_as(Expr::col(usage::Column::TunnelOut).sum(), "tunnel_out")
            .column_as(Expr::col(usage::Column::Requests).sum(), "requests")
            .column_as(Expr::col(usage::Column::UnusedMs).sum(), "unused_ms")
            .column_as(Expr::col(usage::Column::Minute).count(), "covered_minutes")
            .join(JoinType::InnerJoin, usage::Relation::Service.def())
            .join(JoinType::InnerJoin, service::Relation::Machine.def())
            .join(JoinType::InnerJoin, machine::Relation::Person.def())
            .filter(usage::Column::Minute.gte(since_min))
            .filter(usage::Column::Minute.lt(until_min))
            .group_by(usage::Column::ServiceId)
            .group_by(service::Column::Name)
            .group_by(machine::Column::Name)
            .group_by(person::Column::Name)
            .order_by_asc(person::Column::Name)
            .order_by_asc(machine::Column::Name)
            .order_by_asc(service::Column::Name);
        if let Some(person) = person {
            query = query.filter(person::Column::Name.eq(person.to_ascii_lowercase()));
        }
        if let Some(service) = service {
            query = query.filter(service::Column::Name.eq(service.to_ascii_lowercase()));
        }
        let rows = query.into_model::<UsageAggRow>().all(&self.db).await?;
        Ok(rows
            .into_iter()
            .map(|r| UsageTotal {
                service_id: r.service_id,
                service: r.service,
                machine: r.machine,
                person: r.person,
                bytes_in: r.bytes_in,
                bytes_out: r.bytes_out,
                tunnel_in: r.tunnel_in,
                tunnel_out: r.tunnel_out,
                requests: r.requests,
                covered_minutes: r.covered_minutes,
                open_ms: r.covered_minutes * 60_000 - r.unused_ms,
            })
            .collect())
    }

    /// Resolves `(service, machine, person)` names for a set of service ids.
    ///
    /// Used by the metering manager to name services that only exist in the
    /// unflushed in-memory buckets and therefore have no persisted usage row
    /// to join against. Unknown ids are simply absent from the result.
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

/// One metered minute for one service, ready to be persisted.
///
/// Produced by [`crate::metering::MeteringManager`]; `open_ms` is the
/// milliseconds the service was registered during this nominal minute
/// (`0..=60_000`). Crate-internal: metering is the only writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UsageRow {
    pub(crate) service_id: i32,
    pub(crate) minute: i64,
    pub(crate) bytes_in: i64,
    pub(crate) bytes_out: i64,
    pub(crate) tunnel_in: i64,
    pub(crate) tunnel_out: i64,
    pub(crate) requests: i64,
    pub(crate) open_ms: i64,
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
    /// Distinct minutes with a persisted bucket in the window.
    pub covered_minutes: i64,
    /// Milliseconds the service was registered across the window.
    pub open_ms: i64,
}

/// Raw aggregate row before the `open_ms` inversion, matched to the query's
/// column aliases.
#[derive(Debug, sea_orm::FromQueryResult)]
struct UsageAggRow {
    service_id: i32,
    service: String,
    machine: String,
    person: String,
    bytes_in: i64,
    bytes_out: i64,
    tunnel_in: i64,
    tunnel_out: i64,
    requests: i64,
    unused_ms: i64,
    covered_minutes: i64,
}

/// Inverts `open_ms` into the stored `unused_ms`, rejecting out-of-range input.
///
/// Storage keeps the *unused* milliseconds so the common full-minute bucket is
/// the zero value and an alternate view could be added without a schema
/// change. This is the single place the inversion is applied;
/// [`Store::query_usage`] is the single place it is undone.
fn unused_ms_from_open_ms(open_ms: i64) -> Result<i32, StoreError> {
    if !(0..=60_000).contains(&open_ms) {
        return Err(StoreError::InvalidUsage(format!(
            "open_ms {open_ms} is outside 0..=60000"
        )));
    }
    Ok((60_000 - open_ms) as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn upsert_increments_and_rejects_out_of_range() {
        let store = Store::connect("sqlite::memory:").await.expect("connect");
        let alice = store.create_person("Alice").await.expect("person");
        let laptop = store
            .create_machine(alice.id, "Laptop")
            .await
            .expect("machine");
        let svc = store
            .get_or_create_service(laptop.id, "web")
            .await
            .expect("service");

        let row = UsageRow {
            service_id: svc.id,
            minute: 100,
            bytes_in: 10,
            bytes_out: 20,
            tunnel_in: 1,
            tunnel_out: 2,
            requests: 1,
            open_ms: 60_000,
        };
        store.upsert_usage_batch(&[row]).await.expect("first flush");

        // Flushing the same bucket again accumulates every counter.
        store
            .upsert_usage_batch(&[UsageRow {
                bytes_in: 5,
                bytes_out: 7,
                requests: 2,
                ..row
            }])
            .await
            .expect("second flush");

        let totals = store
            .query_usage(None, None, 0, 1_000)
            .await
            .expect("query");
        assert_eq!(totals.len(), 1);
        let t = &totals[0];
        assert_eq!(t.bytes_in, 15);
        assert_eq!(t.bytes_out, 27);
        assert_eq!(t.tunnel_in, 2);
        assert_eq!(t.tunnel_out, 4);
        assert_eq!(t.requests, 3);
        assert_eq!(t.covered_minutes, 1);
        assert_eq!(t.open_ms, 60_000, "a full minute stays a full minute");
        assert_eq!(t.service, "web");
        assert_eq!(t.machine, "laptop");
        assert_eq!(t.person, "alice");

        // An out-of-range open_ms is rejected and stores nothing at all.
        let err = store
            .upsert_usage_batch(&[UsageRow {
                service_id: svc.id,
                minute: 101,
                open_ms: 60_001,
                ..row
            }])
            .await;
        assert!(
            matches!(err, Err(StoreError::InvalidUsage(_))),
            "got {err:?}"
        );
        assert_eq!(
            store.query_usage(None, None, 0, 1_000).await.unwrap().len(),
            1,
            "the rejected batch must not have written a row"
        );
    }

    #[tokio::test]
    async fn query_filters_and_open_ms_inversion() {
        let store = Store::connect("sqlite::memory:").await.expect("connect");
        let alice = store.create_person("Alice").await.expect("person");
        let laptop = store
            .create_machine(alice.id, "Laptop")
            .await
            .expect("machine");
        let web = store
            .get_or_create_service(laptop.id, "web")
            .await
            .expect("service");

        // Minute 100: half open. Minute 101: fully open.
        store
            .upsert_usage_batch(&[
                UsageRow {
                    service_id: web.id,
                    minute: 100,
                    bytes_in: 1,
                    bytes_out: 2,
                    tunnel_in: 10,
                    tunnel_out: 20,
                    requests: 1,
                    open_ms: 30_000,
                },
                UsageRow {
                    service_id: web.id,
                    minute: 101,
                    bytes_in: 3,
                    bytes_out: 4,
                    tunnel_in: 30,
                    tunnel_out: 40,
                    requests: 2,
                    open_ms: 60_000,
                },
            ])
            .await
            .expect("flush");

        let totals = store
            .query_usage(None, None, 100, 102)
            .await
            .expect("query");
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[0].covered_minutes, 2);
        assert_eq!(totals[0].bytes_in, 4);
        assert_eq!(totals[0].open_ms, 90_000, "30000 + 60000");

        // The window is half-open: [100, 101) covers only minute 100.
        let only_100 = store
            .query_usage(None, None, 100, 101)
            .await
            .expect("query");
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
}
