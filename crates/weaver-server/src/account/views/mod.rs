//! Console views: one resource per streamable account route.
//!
//! A [`View`] is a snapshot of a console resource. It is built from an HTTP
//! request — parsing its query, authenticating the caller, reading what it
//! needs — and renders itself to JSON. It also declares its [`Interest`]s: the
//! live changes that would make the snapshot stale.
//!
//! Both halves of the route go through the same trait, so they can never
//! disagree about what a resource *is*:
//!
//! * an ordinary request calls [`View::load`] once and returns
//!   [`View::json`] — the JSON path;
//! * a request asking for `text/event-stream` calls [`serve_stream`], which
//!   re-`load`s the view whenever a change matches its interests and sends each
//!   fresh body as an SSE frame — the streaming path.
//!
//! Authentication is part of construction: [`require_account`] resolves the
//! session cookie for every view, and the per-view person resolution is what
//! distinguishes a signed-in person from a signed-in account that has not
//! paired yet.

// A view's refusal is a ready HTTP response — the same type an axum handler
// returns. Boxing it merely to satisfy a size heuristic would be noise at every
// call site, so the lint is allowed for the whole views module and its children.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{Query, Request};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::Response;
use bytes::Bytes;
use futures_util::stream;
use serde_json::{Value, json};
use tokio::sync::{broadcast, mpsc};
use tokio::time::MissedTickBehavior;
use weaver_mux::KeyId;

use crate::account::AccountRuntime;
use crate::account::router::{err, json_ok};
use crate::account::session::{self, SESSION_COOKIE};
use crate::live::{Change, Interest, Viewer};
use crate::metrics::{Metric, MetricsStore};
use crate::store::entity::{account, machine, person, service};
use crate::store::{Store, StoreError};
use crate::tunnel::registry::TunnelRegistry;
use crate::wall_clock::unix_secs;

mod machine_detail;
mod machines;
mod overview;

pub use machine_detail::MachineDetail;
pub use machines::Machines;
pub use overview::Overview;

/// Keep-alive comment cadence: long enough to be free, short enough to defeat a
/// typical 30–60 s idle timeout in a proxy, and it doubles as the read that
/// notices a peer that has gone away.
const HEARTBEAT: Duration = Duration::from_secs(15);

/// How long a burst of changes is allowed to collect before one re-render.
const COALESCE: Duration = Duration::from_millis(200);

/// Frames buffered between the render loop and the socket.
const FRAME_BUFFER: usize = 8;

/// The frame sent when the session behind a stream is gone.
const EXPIRED_FRAME: &[u8] = b"event: expired\ndata: {}\n\n";

/// The frame sent when the streamed resource no longer exists.
const GONE_FRAME: &[u8] = b"event: gone\ndata: {}\n\n";

/// What a view's constructor is given: the account plane and, when the process
/// has one, the live tunnel registry (the only source of "online").
pub struct ViewContext<'a> {
    pub runtime: &'a Arc<AccountRuntime>,
    pub tunnel: Option<&'a TunnelRegistry>,
}

/// One console resource that can be rendered once or watched live.
#[async_trait]
pub trait View: Send + Sync + Sized + 'static {
    /// Builds a fresh snapshot from a request: authenticate, parse, read.
    /// `Err` is a ready HTTP refusal.
    async fn load(ctx: &ViewContext<'_>, parts: &Parts) -> Result<Self, Response>;

    /// The JSON body a client receives.
    fn json(&self) -> Value;

    /// Whose changes this view can see.
    fn viewer(&self) -> Viewer;

    /// What live changes make the last snapshot stale.
    fn interests(&self) -> Vec<Interest>;
}

/// Serves one streamable route: a single JSON render, or an SSE stream.
pub async fn serve<V: View>(
    runtime: Arc<AccountRuntime>,
    tunnel: Option<Arc<TunnelRegistry>>,
    req: Request,
) -> Response {
    let (parts, _body) = req.into_parts();
    if wants_stream(&parts.headers) {
        return serve_stream::<V>(runtime, tunnel, parts);
    }
    let ctx = ViewContext {
        runtime: &runtime,
        tunnel: tunnel.as_deref(),
    };
    match V::load(&ctx, &parts).await {
        Ok(view) => json_ok(view.json()),
        Err(response) => response,
    }
}

/// Whether the request asks for the resource as a stream rather than once.
fn wants_stream(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|part| {
                part.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("text/event-stream")
            })
        })
}

/// Opens an SSE stream: an initial snapshot, then a fresh one on every change
/// the view's interests match.
///
/// The body is an axum stream of frames produced by a detached task. The edge
/// hands this response's streaming body straight to the socket rather than
/// buffering it.
fn serve_stream<V: View>(
    runtime: Arc<AccountRuntime>,
    tunnel: Option<Arc<TunnelRegistry>>,
    parts: Parts,
) -> Response {
    let (tx, rx) = mpsc::channel::<Bytes>(FRAME_BUFFER);
    tokio::spawn(run::<V>(runtime, tunnel, parts, tx));
    let frames = stream::unfold(rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|chunk| (Ok::<Bytes, std::convert::Infallible>(chunk), rx))
    });
    axum::http::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        // Asked of any fronting proxy that buffers bodies by default; harmless
        // when nothing is in front.
        .header("X-Accel-Buffering", "no")
        .body(Body::from_stream(frames))
        .expect("static SSE headers are valid")
}

/// The stream's loop: render, wait for a change this view cares about, repeat.
async fn run<V: View>(
    runtime: Arc<AccountRuntime>,
    tunnel: Option<Arc<TunnelRegistry>>,
    parts: Parts,
    tx: mpsc::Sender<Bytes>,
) {
    let mut changes = runtime.live.subscribe();
    // An offset, not a plain interval: `interval`'s first tick is immediate, and
    // an immediate heartbeat would only add noise to the first frame.
    let mut heartbeat =
        tokio::time::interval_at(tokio::time::Instant::now() + HEARTBEAT, HEARTBEAT);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut last: Option<Vec<u8>> = None;
    let mut viewer = Viewer::Anyone;
    let mut interests: Vec<Interest> = Vec::new();

    loop {
        let ctx = ViewContext {
            runtime: &runtime,
            tunnel: tunnel.as_deref(),
        };
        match V::load(&ctx, &parts).await {
            Ok(view) => {
                viewer = view.viewer();
                interests = view.interests();
                let body = serde_json::to_vec(&view.json()).unwrap_or_else(|_| b"null".to_vec());
                if last.as_deref() != Some(body.as_slice()) {
                    if tx.send(sse_data(&body)).await.is_err() {
                        return;
                    }
                    last = Some(body);
                }
            }
            // The session is gone: end the stream so the client returns to sign
            // in rather than reconnecting into a redirect loop.
            Err(response) if response.status() == StatusCode::UNAUTHORIZED => {
                let _ = tx.send(Bytes::from_static(EXPIRED_FRAME)).await;
                return;
            }
            // The resource is gone (a machine revoked while its detail was open).
            Err(response) if response.status() == StatusCode::NOT_FOUND => {
                let _ = tx.send(Bytes::from_static(GONE_FRAME)).await;
                return;
            }
            // A transient read failure must not kill a live console; wait for the
            // next change and try again.
            Err(_) => {}
        }

        // Wait for a change this view cares about, or a keep-alive tick.
        loop {
            tokio::select! {
                change = changes.recv() => match change {
                    Ok(change) if change.invalidates(viewer, &interests) => break,
                    Ok(_) => continue,
                    Err(broadcast::error::RecvError::Lagged(_)) => break,
                    Err(broadcast::error::RecvError::Closed) => return,
                },
                _ = heartbeat.tick() => {
                    if tx.send(Bytes::from_static(b": ping\n\n")).await.is_err() {
                        return;
                    }
                }
            }
        }
        coalesce(&mut changes).await;
    }
}

/// Waits out the coalescing window, swallowing every change that arrives in it.
async fn coalesce(changes: &mut broadcast::Receiver<Change>) {
    loop {
        match tokio::time::timeout(COALESCE, changes.recv()).await {
            Ok(Ok(_)) | Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(broadcast::error::RecvError::Closed)) | Err(_) => return,
        }
    }
}

/// Frames a JSON body as one SSE event, splitting multi-line bodies so every
/// line keeps its `data:` prefix.
fn sse_data(body: &[u8]) -> Bytes {
    let text = String::from_utf8_lossy(body);
    let mut frame = String::with_capacity(text.len() + 16);
    for line in text.split('\n') {
        frame.push_str("data: ");
        frame.push_str(line);
        frame.push('\n');
    }
    frame.push('\n');
    Bytes::from(frame)
}

/// The scope a view's streams listen under: the signed-in person, or a sentinel
/// that no published change can reach for an account with no person yet.
fn viewer_of(person: Option<&person::Model>) -> Viewer {
    Viewer::Person(person.map(|person| person.id).unwrap_or(0))
}

// ----- authentication and ownership ----------------------------------------

/// Resolves the signed-in account from the session cookie, or `None`.
pub(crate) async fn signed_in(rt: &AccountRuntime, headers: &HeaderMap) -> Option<account::Model> {
    let raw = session::cookie(headers, SESSION_COOKIE)?;
    rt.sessions.account(&raw, unix_secs()).await.ok().flatten()
}

/// The signed-in account, or a ready `401`.
pub(crate) async fn require_account(
    rt: &AccountRuntime,
    headers: &HeaderMap,
) -> Result<account::Model, Response> {
    signed_in(rt, headers)
        .await
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "not signed in"))
}

/// The account's person, or `None` when it has not paired yet.
pub(crate) async fn person_of(rt: &AccountRuntime, account_id: i32) -> Option<person::Model> {
    rt.store.person_by_account(account_id).await.ok().flatten()
}

/// The machine `machine_id`, if it belongs to `person`.
pub(crate) async fn owned_machine(
    rt: &AccountRuntime,
    person: &person::Model,
    machine_id: i32,
) -> Result<Option<machine::Model>, StoreError> {
    Ok(rt
        .store
        .machine_by_id(machine_id)
        .await?
        .filter(|machine| machine.person_id == person.id))
}

/// A failed read: logged, generic to the client.
pub(crate) fn load_error(e: StoreError) -> Response {
    tracing::warn!(error = %e, "failed to load a console view");
    err(
        StatusCode::INTERNAL_SERVER_ERROR,
        "could not load this view",
    )
}

// ----- shared console reading ----------------------------------------------

/// A slice of usage over the console's reporting window.
#[derive(Clone, Copy, Default)]
pub(crate) struct Usage {
    pub(crate) bytes_in: i64,
    pub(crate) bytes_out: i64,
    pub(crate) requests: i64,
}

impl Usage {
    pub(crate) fn json(self) -> Value {
        json!({ "bytes_in": self.bytes_in, "bytes_out": self.bytes_out, "requests": self.requests })
    }

    fn add(self, other: Usage) -> Usage {
        Usage {
            bytes_in: self.bytes_in + other.bytes_in,
            bytes_out: self.bytes_out + other.bytes_out,
            requests: self.requests + other.requests,
        }
    }
}

/// A service a machine declares, as the console renders it.
pub(crate) struct ServiceView {
    pub(crate) name: String,
    pub(crate) hostnames: Vec<String>,
    pub(crate) active: bool,
    pub(crate) usage: Usage,
}

impl ServiceView {
    fn json(self) -> Value {
        json!({
            "name": self.name,
            "hostnames": self.hostnames,
            "active": self.active,
            "usage_30d": self.usage.json(),
        })
    }
}

/// How far back the console's traffic figures reach.
pub(crate) const USAGE_WINDOW_SECS: i64 = 30 * 24 * 60 * 60;

/// The account's traffic over the reporting window, indexed per machine and per
/// `(machine, service)`.
#[derive(Default)]
pub(crate) struct UsageIndex {
    machines: HashMap<String, Usage>,
    services: HashMap<(String, String), Usage>,
}

impl UsageIndex {
    fn total(&self) -> Usage {
        self.machines
            .values()
            .copied()
            .fold(Usage::default(), Usage::add)
    }

    fn of_machine(&self, machine: &str) -> Usage {
        self.machines.get(machine).copied().unwrap_or_default()
    }

    fn of_service(&self, machine: &str, service: &str) -> Usage {
        self.services
            .get(&(machine.to_string(), service.to_string()))
            .copied()
            .unwrap_or_default()
    }
}

/// The signed-in person's services, each with the name of the machine it runs
/// on, in `machine → service` order.
pub(crate) async fn person_services(
    store: &Store,
    person: &person::Model,
) -> Result<Vec<(machine::Model, service::Model)>, StoreError> {
    let machines = store.list_machines(person.id).await?;
    let mut by_id: HashMap<i32, machine::Model> = HashMap::new();
    for machine in machines {
        by_id.insert(machine.id, machine);
    }
    let ids: Vec<i32> = by_id.keys().copied().collect();
    let mut services = Vec::new();
    for (svc, _) in store.services_with_hostnames(&ids).await? {
        if let Some(machine) = by_id.get(&svc.machine_id) {
            services.push((machine.clone(), svc));
        }
    }
    Ok(services)
}

/// The account's traffic over the reporting window, read from the metrics store.
async fn usage_index(store: &Store, person: &person::Model) -> Result<UsageIndex, StoreError> {
    let until = unix_secs();
    let services = person_services(store, person).await?;
    let ids: Vec<i32> = services.iter().map(|(_, svc)| svc.id).collect();
    let totals = MetricsStore::new(store.clone())
        .totals(
            &ids,
            &[Metric::BytesIn, Metric::BytesOut, Metric::Requests],
            until - USAGE_WINDOW_SECS,
            until,
        )
        .await?;
    let mut index = UsageIndex::default();
    for (machine, svc) in services {
        let usage = Usage {
            bytes_in: totals.get(&(svc.id, Metric::BytesIn)).copied().unwrap_or(0),
            bytes_out: totals
                .get(&(svc.id, Metric::BytesOut))
                .copied()
                .unwrap_or(0),
            requests: totals
                .get(&(svc.id, Metric::Requests))
                .copied()
                .unwrap_or(0),
        };
        let machine_usage = index.machines.entry(machine.name.clone()).or_default();
        *machine_usage = machine_usage.add(usage);
        index.services.insert((machine.name, svc.name), usage);
    }
    Ok(index)
}

/// A machine's key in canonical text form, or `None` if the stored key does not
/// parse. A corrupt row must not turn the whole list into a 500.
pub(crate) fn key_of(machine: &machine::Model) -> Option<KeyId> {
    machine.key_id.parse().ok()
}

/// A machine as the console renders it.
pub(crate) fn machine_view(
    machine: &machine::Model,
    online: bool,
    metered_last_seen: Option<i64>,
    services: Vec<ServiceView>,
    usage: Usage,
) -> Value {
    json!({
        "id": machine.id,
        "name": machine.name,
        "online": online,
        "last_seen_at": last_seen(online, metered_last_seen),
        "paired_at": machine.created_at,
        "fingerprint": machine.key_id,
        "usage_30d": usage.json(),
        "services": services.into_iter().map(ServiceView::json).collect::<Vec<Value>>(),
    })
}

/// When a machine was last seen: "now" if it holds a live connection, else the
/// most recent metered minute (`None` if it was never metered).
pub(crate) fn last_seen(online: bool, metered_last_seen: Option<i64>) -> Option<i64> {
    if online {
        Some(unix_secs())
    } else {
        metered_last_seen
    }
}

/// A service as the view sees it: its liveness comes from the live registry, so
/// a service with no registry (or no route) is simply inactive.
pub(crate) fn service_view(
    svc: service::Model,
    hostnames: Vec<String>,
    tunnel: Option<&TunnelRegistry>,
    usage: Usage,
) -> ServiceView {
    let active = tunnel.is_some_and(|t| hostnames.iter().any(|host| t.is_active(host)));
    ServiceView {
        name: svc.name,
        hostnames,
        active,
        usage,
    }
}

/// Whether a machine holds a live connection, per the registry.
pub(crate) fn online(machine: &machine::Model, tunnel: Option<&TunnelRegistry>) -> bool {
    tunnel.is_some_and(|t| key_of(machine).is_some_and(|key| t.is_connected(&key)))
}

/// One machine's most recent open minute (Unix seconds), or `None` when it has
/// never been metered.
pub(crate) async fn machine_last_seen(
    store: &Store,
    machine_id: i32,
) -> Result<Option<i64>, StoreError> {
    let svc_ids: Vec<i32> = store
        .services_with_hostnames(&[machine_id])
        .await?
        .into_iter()
        .map(|(svc, _)| svc.id)
        .collect();
    let minutes = MetricsStore::new(store.clone())
        .last_open_minutes(&svc_ids)
        .await?;
    Ok(minutes.values().copied().max().map(|minute| minute * 60))
}

/// A query string parsed into `T`, or a `400`.
pub(crate) fn parse_query<T: serde::de::DeserializeOwned>(uri: &Uri) -> Result<T, Response> {
    Query::try_from_uri(uri)
        .map(|Query(value)| value)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "invalid query string"))
}
