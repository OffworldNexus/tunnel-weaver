//! `GET /api/account/machines` — a page of the signed-in person's machines,
//! most recently used first.

use std::collections::{BTreeSet, HashMap};

use async_trait::async_trait;
use axum::http::request::Parts;
use axum::response::Response;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::live::{Entity, Interest, Viewer};
use crate::store::entity::{machine, person};
use crate::wall_clock::unix_secs;

use super::{
    ServiceView, View, ViewContext, load_error, machine_view, parse_query, person_of,
    require_account, service_view, usage_index, viewer_of,
};

/// The collection's query: which page, and the two filters the console offers.
#[derive(Deserialize)]
struct MachinesQuery {
    page: Option<u32>,
    per_page: Option<u32>,
    /// A case-insensitive substring of the machine name.
    q: Option<String>,
    /// `all` (the default), `online` or `offline`.
    health: Option<String>,
}

/// The collection's default page size, and its ceiling.
const PER_PAGE: u32 = 60;
const PER_PAGE_MAX: u32 = 200;

/// A page of the person's machines.
pub struct Machines {
    /// `None` for an account that has not paired yet (an empty first page).
    person: Option<person::Model>,
    page: Value,
    /// The machine ids the rendered page mentions. A change to one of them, or
    /// to any machine at all (an addition or a removal), is this view's
    /// business — the list also carries each machine's traffic, so it listens
    /// for statistics too.
    machine_ids: BTreeSet<i32>,
}

#[async_trait]
impl View for Machines {
    async fn load(ctx: &ViewContext<'_>, parts: &Parts) -> Result<Self, Response> {
        let account = require_account(ctx.runtime, &parts.headers).await?;
        let query: MachinesQuery = parse_query(&parts.uri)?;
        let Some(person) = person_of(ctx.runtime, account.id).await else {
            return Ok(Self {
                person: None,
                page: empty_page(),
                machine_ids: BTreeSet::new(),
            });
        };
        let (page, machine_ids) = page_of(ctx, &person, &query).await?;
        Ok(Self {
            person: Some(person),
            page,
            machine_ids,
        })
    }

    fn json(&self) -> Value {
        self.page.clone()
    }

    fn viewer(&self) -> Viewer {
        viewer_of(self.person.as_ref())
    }

    fn interests(&self) -> Vec<Interest> {
        vec![
            Interest::these(Entity::Machine, self.machine_ids.iter().copied()),
            Interest::all(Entity::Statistics),
        ]
    }
}

/// An empty first page, for an account with no person yet.
fn empty_page() -> Value {
    json!({ "machines": [], "page": 1, "per_page": PER_PAGE, "total": 0, "page_count": 1 })
}

/// One page of `person`'s machines, and the ids it lists.
///
/// The person's machines are small in number, so the name and health filters are
/// applied in memory (health is derived from the live registry, which the store
/// cannot filter on), and only the requested page's services and usage are then
/// read — the expensive per-machine lookups never touch the rows being skipped.
///
/// The list reads **most recently used first**, which is also what makes the
/// first machine the right default name for something that belongs to a device
/// (a passkey). Presence decides it: a machine alive right now sorts first, then
/// the metered minutes, and a machine never seen sorts last.
async fn page_of(
    ctx: &ViewContext<'_>,
    person: &person::Model,
    query: &MachinesQuery,
) -> Result<(Value, BTreeSet<i32>), Response> {
    let per_page = query.per_page.unwrap_or(PER_PAGE).clamp(1, PER_PAGE_MAX) as usize;
    let needle = query.q.as_deref().unwrap_or("").trim().to_ascii_lowercase();
    let health = query.health.as_deref().unwrap_or("all");

    // Presence is what orders the list, so the metered minutes are read before
    // anything is filtered or paged.
    let last_seen = last_seen_by_machine(&ctx.runtime.store, person)
        .await
        .map_err(load_error)?;
    let now = unix_secs();
    let used_at = |machine: &machine::Model| -> Option<i64> {
        if super::online(machine, ctx.tunnel) {
            Some(now)
        } else {
            last_seen.get(&machine.id).copied()
        }
    };

    let mut matched: Vec<machine::Model> = ctx
        .runtime
        .store
        .list_machines(person.id)
        .await
        .map_err(load_error)?
        .into_iter()
        .filter(|machine| needle.is_empty() || machine.name.contains(&needle))
        .filter(|machine| match health {
            "online" => super::online(machine, ctx.tunnel),
            "offline" => !super::online(machine, ctx.tunnel),
            _ => true,
        })
        .collect();
    // Reverse last use: the machine in play is the one worth reading first, and
    // one that has never been seen sorts last. The name breaks ties, so two live
    // machines never swap places between refreshes.
    matched.sort_by(|left, right| {
        used_at(right)
            .cmp(&used_at(left))
            .then_with(|| left.name.cmp(&right.name))
    });

    let total = matched.len();
    let page_count = total.div_ceil(per_page).max(1);
    let page = query.page.unwrap_or(1).clamp(1, page_count as u32);
    let start = (page as usize - 1) * per_page;
    let slice: Vec<machine::Model> = matched.into_iter().skip(start).take(per_page).collect();

    let ids: Vec<i32> = slice.iter().map(|machine| machine.id).collect();
    let names: HashMap<i32, String> = slice
        .iter()
        .map(|machine| (machine.id, machine.name.clone()))
        .collect();
    let usage = usage_index(&ctx.runtime.store, person)
        .await
        .map_err(load_error)?;
    let mut services: HashMap<i32, Vec<ServiceView>> = HashMap::new();
    for (svc, hostnames) in ctx
        .runtime
        .store
        .services_with_hostnames(&ids)
        .await
        .map_err(load_error)?
    {
        let machine_id = svc.machine_id;
        let machine_name = names.get(&machine_id).cloned().unwrap_or_default();
        let service_usage = usage.of_service(&machine_name, &svc.name);
        services.entry(machine_id).or_default().push(service_view(
            svc,
            hostnames,
            ctx.tunnel,
            service_usage,
        ));
    }
    let listed: BTreeSet<i32> = slice.iter().map(|machine| machine.id).collect();
    let machines: Vec<Value> = slice
        .into_iter()
        .map(|machine| {
            machine_view(
                &machine,
                super::online(&machine, ctx.tunnel),
                last_seen.get(&machine.id).copied(),
                services.remove(&machine.id).unwrap_or_default(),
                usage.of_machine(&machine.name),
            )
        })
        .collect();

    let page = json!({
        "machines": machines,
        "page": page,
        "per_page": per_page,
        "total": total,
        "page_count": page_count,
    });
    Ok((page, listed))
}

/// Each machine's most recent open minute (Unix seconds), from the metrics
/// store. Machines with no metered minute are absent.
async fn last_seen_by_machine(
    store: &crate::store::Store,
    person: &person::Model,
) -> Result<HashMap<i32, i64>, crate::store::StoreError> {
    let services = super::person_services(store, person).await?;
    let ids: Vec<i32> = services.iter().map(|(_, svc)| svc.id).collect();
    let minutes = crate::metrics::MetricsStore::new(store.clone())
        .last_open_minutes(&ids)
        .await?;
    let mut last_seen: HashMap<i32, i64> = HashMap::new();
    for (machine, svc) in services {
        if let Some(minute) = minutes.get(&svc.id) {
            let seconds = minute * 60;
            last_seen
                .entry(machine.id)
                .and_modify(|seen| *seen = (*seen).max(seconds))
                .or_insert(seconds);
        }
    }
    Ok(last_seen)
}
