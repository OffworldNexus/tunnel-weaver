//! `GET /api/account/overview` — the account-level rollup.

use async_trait::async_trait;
use axum::http::request::Parts;
use axum::response::Response;
use serde_json::{Value, json};

use crate::live::{Entity, Interest, Viewer};
use crate::store::entity::person;

use super::{
    USAGE_WINDOW_SECS, Usage, View, ViewContext, load_error, online, person_of, require_account,
    usage_index, viewer_of,
};
use crate::wall_clock::unix_secs;

/// How many machines and tunnels are live, and the traffic carried.
pub struct Overview {
    person: Option<person::Model>,
    body: Value,
}

#[async_trait]
impl View for Overview {
    async fn load(ctx: &ViewContext<'_>, parts: &Parts) -> Result<Self, Response> {
        let account = require_account(ctx.runtime, &parts.headers).await?;
        let Some(person) = person_of(ctx.runtime, account.id).await else {
            return Ok(Self {
                person: None,
                body: empty(),
            });
        };
        let body = rollup(ctx, &person).await?;
        Ok(Self {
            person: Some(person),
            body,
        })
    }

    fn json(&self) -> Value {
        self.body.clone()
    }

    fn viewer(&self) -> Viewer {
        viewer_of(self.person.as_ref())
    }

    fn interests(&self) -> Vec<Interest> {
        // The rollup is counts and totals: any machine or tunnel anywhere, or a
        // traffic flush, can move it.
        vec![
            Interest::all(Entity::Machine),
            Interest::all(Entity::Tunnel),
            Interest::all(Entity::Statistics),
        ]
    }
}

/// The all-zero rollup for an account with no person yet.
fn empty() -> Value {
    json!({
        "machines": { "online": 0, "total": 0 },
        "tunnels": { "active": 0, "total": 0 },
        "usage_30d": Usage::default().json(),
        "window_days": USAGE_WINDOW_SECS / 86_400,
        "covered_seconds": 0,
    })
}

/// Presence counts and traffic totals for `person`.
async fn rollup(ctx: &ViewContext<'_>, person: &person::Model) -> Result<Value, Response> {
    let store = &ctx.runtime.store;
    let machines = store.list_machines(person.id).await.map_err(load_error)?;
    let ids: Vec<i32> = machines.iter().map(|machine| machine.id).collect();
    let machines_online = machines
        .iter()
        .filter(|machine| online(machine, ctx.tunnel))
        .count();

    let services = store
        .services_with_hostnames(&ids)
        .await
        .map_err(load_error)?;
    let tunnels_total = services.len();
    let tunnels_active = services
        .iter()
        .filter(|(_, hostnames)| {
            ctx.tunnel
                .is_some_and(|t| hostnames.iter().any(|hostname| t.is_active(hostname)))
        })
        .count();

    let usage = usage_index(store, person)
        .await
        .map_err(load_error)?
        .total();

    // The figures above are sums, true of the whole window; a *rate* is not, so
    // the relay reports how much of the window the traffic actually covers.
    let service_ids: Vec<i32> = services.iter().map(|(service, _)| service.id).collect();
    let now = unix_secs();
    let covered_seconds = match store
        .covered_span(&service_ids, now - USAGE_WINDOW_SECS, now)
        .await
        .map_err(load_error)?
    {
        Some((first, last)) => (last - first + 1) * 60,
        None => 0,
    };

    Ok(json!({
        "machines": { "online": machines_online, "total": machines.len() },
        "tunnels": { "active": tunnels_active, "total": tunnels_total },
        "usage_30d": usage.json(),
        "window_days": USAGE_WINDOW_SECS / 86_400,
        "covered_seconds": covered_seconds,
    }))
}
