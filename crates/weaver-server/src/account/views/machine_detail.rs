//! `GET /api/account/machines/{id}` — one machine of the signed-in person.

use std::collections::BTreeSet;

use async_trait::async_trait;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::Response;
use serde_json::Value;

use crate::account::router::err;
use crate::live::{Entity, Interest, Viewer};
use crate::store::entity::person;

use super::{
    View, ViewContext, load_error, machine_last_seen, machine_view, online, owned_machine,
    person_of, require_account, service_view, usage_index, viewer_of,
};

/// One machine: its identity, presence, services and traffic.
pub struct MachineDetail {
    person: person::Model,
    machine_id: i32,
    body: Value,
    /// The service ids the rendered detail lists: a tunnel change to one of them
    /// (or to this machine) is this view's business; its traffic follows
    /// statistics.
    service_ids: BTreeSet<i32>,
}

#[async_trait]
impl View for MachineDetail {
    async fn load(ctx: &ViewContext<'_>, parts: &Parts) -> Result<Self, Response> {
        let account = require_account(ctx.runtime, &parts.headers).await?;
        let machine_id = match parts.uri.path().rsplit('/').next().map(str::parse::<i32>) {
            Some(Ok(id)) if id > 0 => id,
            _ => return Err(not_found()),
        };
        let Some(person) = person_of(ctx.runtime, account.id).await else {
            return Err(not_found());
        };
        let machine = match owned_machine(ctx.runtime, &person, machine_id).await {
            Ok(Some(machine)) => machine,
            Ok(None) => return Err(not_found()),
            Err(e) => return Err(load_error(e)),
        };

        let usage = usage_index(&ctx.runtime.store, &person)
            .await
            .map_err(load_error)?;
        let mut service_ids = BTreeSet::new();
        let services = match ctx
            .runtime
            .store
            .services_with_hostnames(&[machine.id])
            .await
        {
            Ok(services) => services
                .into_iter()
                .map(|(svc, hostnames)| {
                    service_ids.insert(svc.id);
                    let service_usage = usage.of_service(&machine.name, &svc.name);
                    service_view(svc, hostnames, ctx.tunnel, service_usage)
                })
                .collect::<Vec<_>>(),
            Err(e) => return Err(load_error(e)),
        };
        let last_seen_at = machine_last_seen(&ctx.runtime.store, machine.id)
            .await
            .map_err(load_error)?;
        let body = machine_view(
            &machine,
            online(&machine, ctx.tunnel),
            last_seen_at,
            services,
            usage.of_machine(&machine.name),
        );

        Ok(Self {
            person,
            machine_id,
            body,
            service_ids,
        })
    }

    fn json(&self) -> Value {
        self.body.clone()
    }

    fn viewer(&self) -> Viewer {
        viewer_of(Some(&self.person))
    }

    fn interests(&self) -> Vec<Interest> {
        vec![
            Interest::these(Entity::Machine, [self.machine_id]),
            Interest::these(Entity::Tunnel, self.service_ids.iter().copied()),
            Interest::all(Entity::Statistics),
        ]
    }
}

/// A machine that is not this account's: a 404, never an empty page.
fn not_found() -> Response {
    err(StatusCode::NOT_FOUND, "machine not found")
}
