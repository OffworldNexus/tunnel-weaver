//! The console's real-time streams (WVR-25).
//!
//! There is no WebSocket and no subscription protocol: **every streamable GET
//! gains an SSE variant**, chosen by `Accept: text/event-stream`. The URL, the
//! query string and the response body are exactly those of the JSON call; the
//! body is simply re-sent as an SSE frame whenever it changes. In one line: get
//! the JSON once, or get it every time it changes.
//!
//! Two consequences shape the code. First, the stream is *presentation-free*:
//! every frame is a full snapshot, so there is no event log, no `Last-Event-ID`
//! replay and nothing to reconcile. Second, the resource is not re-shaped here:
//! each tick re-runs the very same request through the account router, so
//! authentication, self-scoping, query parsing and the payload shape are the
//! JSON route's, never a second implementation of them.
//!
//! The stream is served on the raw hyper edge rather than inside the account
//! router because that router buffers its response body; the endless body is fed
//! through the same mpsc-backed [`TunnelResponseBody`] the tunnel proxy uses.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri, header};
use http_body_util::BodyExt;
use hyper::body::Frame;
use tokio::sync::{broadcast, mpsc};
use tokio::time::MissedTickBehavior;

use weaver_assets::apply_common_security_headers;

use crate::account::AccountRuntime;
use crate::account::session::SESSION_COOKIE;
use crate::tunnel::proxy::{BodyFrameItem, BoxBody, TunnelResponseBody};
use crate::tunnel::registry::TunnelRegistry;
use crate::wall_clock::unix_secs;

/// Keep-alive comment cadence. Long enough to be free, short enough to defeat a
/// typical 30–60 s idle timeout in a proxy or load balancer, and it doubles as
/// the read that notices a peer that has gone away.
const HEARTBEAT: Duration = Duration::from_secs(15);

/// How often a stream re-reads its resource to pick up traffic figures, which
/// move only at minute granularity. Presence and membership changes arrive
/// immediately on the bus; this is the slow floor, and an unchanged body is not
/// re-sent.
const TRAFFIC: Duration = Duration::from_secs(60);

/// How often the session behind the stream is re-checked, so a logout or a
/// password change (which invalidates every session) ends the stream promptly.
const SESSION_CHECK: Duration = Duration::from_secs(30);

/// How long a burst of changes is allowed to collect before one recompute.
/// A machine reconnecting registers its services one message at a time; without
/// this, each would wake a separate recompute.
const COALESCE: Duration = Duration::from_millis(200);

/// Frames buffered between the recompute task and the socket. The writer is a
/// fast memcpy; a client that cannot keep up with a handful of small snapshots
/// is already gone, and the send then fails and ends the stream.
const FRAME_BUFFER: usize = 8;

/// Whether the request asks the account API to be streamed rather than returned
/// once. The route and query are untouched: it is the same resource, selected by
/// `Accept: text/event-stream` instead of the JSON default.
pub fn wants_stream<B>(req: &Request<B>) -> bool {
    req.method() == Method::GET
        && streamable_path(req.uri().path())
        && accepts_event_stream(req.headers())
}

/// The account routes that offer a stream. Kept to the presence- and
/// membership-driven views; the metrics chart is not streamed today.
fn streamable_path(path: &str) -> bool {
    if matches!(path, "/api/account/machines" | "/api/account/overview") {
        return true;
    }
    path.strip_prefix("/api/account/machines/")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether `Accept` lists `text/event-stream`. Parameters (e.g. `;q=0.9`) are
/// ignored: the media type alone decides.
fn accepts_event_stream(headers: &HeaderMap) -> bool {
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

/// Serves one console stream: resolves the signed-in person, then streams the
/// resource until the session dies or the client goes away.
///
/// An unauthenticated request still gets a `200 text/event-stream`, whose only
/// frame is `event: expired`: the client then closes instead of reconnecting
/// into a redirect loop, and no data is exposed either way.
pub async fn serve(
    account: &Arc<AccountRuntime>,
    tunnel: Option<Arc<TunnelRegistry>>,
    req: Request<hyper::body::Incoming>,
    include_hsts: bool,
) -> Response<BoxBody> {
    let (parts, _body) = req.into_parts();
    // The request is a GET, so there is no body to drain; its path, query and
    // `Cookie` header are all the recompute needs.
    let uri = parts.uri;
    let headers = parts.headers;
    let person = streaming_person(account, &headers).await;

    let (tx, rx) = mpsc::channel::<BodyFrameItem>(FRAME_BUFFER);
    tokio::spawn(run_stream(
        Arc::clone(account),
        tunnel,
        uri,
        headers,
        person,
        tx,
    ));

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        // Asked of any fronting proxy that buffers bodies by default; harmless
        // when nothing is in front.
        .header("X-Accel-Buffering", "no")
        .body(TunnelResponseBody::boxed(rx))
        .expect("static SSE headers are valid");
    // The account surface's shared headers, which — unlike the generic
    // `apply_security_headers` — leave `Content-Type` alone: clobbering it to
    // `text/html` would make the browser refuse the stream.
    apply_common_security_headers(&mut response, include_hsts);
    response
}

/// The signed-in person's id, `None` when the session is gone.
///
/// A personless account (one that has not paired yet) streams as person `0`,
/// which matches no bus event: its resource handlers already answer an empty
/// view, so the stream stays honest and simply never wakes on presence.
async fn streaming_person(account: &AccountRuntime, headers: &HeaderMap) -> Option<i32> {
    let raw = crate::account::session::cookie(headers, SESSION_COOKIE)?;
    let row = account
        .sessions
        .account(&raw, unix_secs())
        .await
        .ok()
        .flatten()?;
    let person = account.store.person_by_account(row.id).await.ok().flatten();
    Some(person.map(|person| person.id).unwrap_or(0))
}

/// The stream's body: an initial snapshot, then a fresh one on every change.
async fn run_stream(
    account: Arc<AccountRuntime>,
    tunnel: Option<Arc<TunnelRegistry>>,
    uri: Uri,
    headers: HeaderMap,
    person: Option<i32>,
    tx: mpsc::Sender<BodyFrameItem>,
) {
    let Some(person_id) = person else {
        let _ = send_frame(&tx, EXPIRED_FRAME).await;
        return;
    };

    // Offsets, not plain intervals: `interval`'s first tick is immediate, and an
    // immediate heartbeat would only add noise to the first frame.
    let start = tokio::time::Instant::now();
    let mut heartbeat = tokio::time::interval_at(start + HEARTBEAT, HEARTBEAT);
    let mut traffic = tokio::time::interval_at(start + TRAFFIC, TRAFFIC);
    let mut session = tokio::time::interval_at(start + SESSION_CHECK, SESSION_CHECK);
    for timer in [&mut heartbeat, &mut traffic, &mut session] {
        timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
    }
    let mut events = account.live.subscribe();

    // The first frame is always a full snapshot of the resource.
    let mut last: Option<Bytes> = None;
    if !emit(&account, &tunnel, &uri, &headers, &tx, &mut last).await {
        return;
    }

    loop {
        tokio::select! {
            changed = events.recv() => match changed {
                Ok(id) if id == person_id => {}
                // Another person's change: not this stream's business.
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            },
            _ = heartbeat.tick() => {
                if send_frame(&tx, ": ping\n\n").await.is_err() {
                    break;
                }
                continue;
            }
            _ = session.tick() => {
                if streaming_person(&account, &headers).await.is_none() {
                    let _ = send_frame(&tx, EXPIRED_FRAME).await;
                    break;
                }
                continue;
            }
            // The slow traffic floor; falls through to a recompute.
            _ = traffic.tick() => {}
        }

        // Collapse a burst of changes into a single recompute.
        coalesce(&mut events).await;
        if !emit(&account, &tunnel, &uri, &headers, &tx, &mut last).await {
            break;
        }
    }
}

/// Waits out the coalescing window, swallowing every change that arrives in it.
async fn coalesce(events: &mut broadcast::Receiver<i32>) {
    loop {
        match tokio::time::timeout(COALESCE, events.recv()).await {
            Ok(Ok(_)) | Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(broadcast::error::RecvError::Closed)) | Err(_) => return,
        }
    }
}

/// Recomputes the resource and emits it as a full snapshot if it changed.
///
/// Returns `false` when the stream should end: a dead session, or a client that
/// has gone away (the send fails).
async fn emit(
    account: &Arc<AccountRuntime>,
    tunnel: &Option<Arc<TunnelRegistry>>,
    uri: &Uri,
    headers: &HeaderMap,
    tx: &mpsc::Sender<BodyFrameItem>,
    last: &mut Option<Bytes>,
) -> bool {
    let (status, body) = match recompute(account, tunnel, uri, headers).await {
        Ok(result) => result,
        Err(error) => {
            // A transient read failure must not kill a live console; keep the
            // stream and try again on the next wake.
            tracing::debug!(%error, path = %uri.path(), "console stream recompute failed");
            return true;
        }
    };
    if !status.is_success() {
        // 401 — the session is gone. Anything else (a machine revoked while this
        // stream was open) — the resource is gone. Either way the stream ends
        // rather than sending a body the client would mistake for the resource.
        let frame = if status == StatusCode::UNAUTHORIZED {
            EXPIRED_FRAME
        } else {
            GONE_FRAME
        };
        let _ = send_frame(tx, frame).await;
        return false;
    }
    // Presence events fire for changes this particular resource does not show
    // (a rename that leaves the overview counts alone); never churn the client
    // with an identical snapshot.
    if last.as_deref() == Some(body.as_ref()) {
        return true;
    }
    if send_frame(tx, &sse_data(&body)).await.is_err() {
        return false;
    }
    *last = Some(body);
    true
}

/// Runs the same request through the account router and returns its buffered
/// body. Authentication, self-scoping, query parsing and shape are therefore the
/// JSON route's, and a stream can only ever return what its cookie could `GET`.
async fn recompute(
    account: &Arc<AccountRuntime>,
    tunnel: &Option<Arc<TunnelRegistry>>,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<(StatusCode, Bytes), String> {
    use tower::ServiceExt as _;

    let router = crate::account::router::router(Arc::clone(account), tunnel.clone());
    let mut request = Request::new(axum::body::Body::empty());
    *request.method_mut() = Method::GET;
    *request.uri_mut() = uri.clone();
    *request.headers_mut() = headers.clone();
    let response = match router.oneshot(request).await {
        Ok(response) => response,
        Err(never) => match never {},
    };
    let (parts, body) = response.into_parts();
    let bytes = body
        .collect()
        .await
        .map_err(|error| error.to_string())?
        .to_bytes();
    Ok((parts.status, bytes))
}

/// The frame sent when the stream's session is gone.
const EXPIRED_FRAME: &str = "event: expired\ndata: {}\n\n";

/// The frame sent when the streamed resource no longer exists (a machine
/// revoked while its detail stream was open).
const GONE_FRAME: &str = "event: gone\ndata: {}\n\n";

/// Frames a JSON body as one SSE event.
///
/// Multi-line bodies (a pretty-printed metrics payload) are split so every line
/// keeps its `data:` prefix, which is what lets a client reassemble them.
fn sse_data(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let mut frame = String::with_capacity(text.len() + 16);
    for line in text.split('\n') {
        frame.push_str("data: ");
        frame.push_str(line);
        frame.push('\n');
    }
    frame.push('\n');
    frame
}

/// Pushes one already-framed chunk onto the stream. `Err` means the client is
/// gone and the task should stop.
async fn send_frame(tx: &mpsc::Sender<BodyFrameItem>, text: &str) -> Result<(), ()> {
    tx.send(Ok(Frame::data(Bytes::copy_from_slice(text.as_bytes()))))
        .await
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(accept: &str, path: &str) -> Request<()> {
        Request::builder()
            .method(Method::GET)
            .uri(path)
            .header(header::ACCEPT, accept)
            .body(())
            .unwrap()
    }

    #[test]
    fn only_the_streamable_routes_are_streamed() {
        assert!(wants_stream(&request(
            "text/event-stream",
            "/api/account/machines"
        )));
        assert!(wants_stream(&request(
            "text/event-stream",
            "/api/account/machines?page=1"
        )));
        assert!(wants_stream(&request(
            "text/event-stream",
            "/api/account/machines/12"
        )));
        assert!(wants_stream(&request(
            "text/event-stream",
            "/api/account/overview"
        )));
        // Not streamed: the metrics chart, the SPA, and a non-numeric id.
        assert!(!wants_stream(&request(
            "text/event-stream",
            "/api/account/metrics"
        )));
        assert!(!wants_stream(&request(
            "text/event-stream",
            "/app/machines"
        )));
        assert!(!wants_stream(&request(
            "text/event-stream",
            "/api/account/machines/abc"
        )));
    }

    #[test]
    fn the_media_type_is_matched_with_or_without_parameters() {
        assert!(wants_stream(&request(
            "text/event-stream",
            "/api/account/overview"
        )));
        assert!(wants_stream(&request(
            "text/event-stream;q=0.9, application/json",
            "/api/account/overview"
        )));
        assert!(!wants_stream(&request(
            "application/json",
            "/api/account/overview"
        )));
        assert!(!wants_stream(&request("*/*", "/api/account/overview")));
    }

    #[test]
    fn a_snapshot_is_framed_line_by_line() {
        assert_eq!(sse_data(b"{\"ok\":true}"), "data: {\"ok\":true}\n\n");
        assert_eq!(
            sse_data(b"{\n\"a\":1\n}"),
            "data: {\ndata: \"a\":1\ndata: }\n\n"
        );
    }
}
