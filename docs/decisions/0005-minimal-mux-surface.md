# 5. Minimal mux surface: class not policy, one name per concept

Date: 2026-09-19

## Status

Accepted. Amends ADR 0004 (`StreamPolicy` → `Class`, `GoAway` → `CloseReason`, `Compression` → `compression_allowed`). Wire format is unchanged except that the OPEN payload is now a bare `Class` instead of `StreamPolicy { class, demote_after }`; still `weaver-mux-v1` under the pre-1.0 rule of ADR 0004.

## Context

A second audit of the tree after ADR 0004 found no structural leak — the dependency graph and the "knows / does not know" table hold — but a public surface much larger than its consumers:

- The whole `sched` module (including the generic QFQ), `flow`, and a dozen `SchedTree`/`Qfq` methods were `pub` with zero users outside the crate.
- Every type in `error`, `event`, `frame` was reachable by two paths (`weaver_mux::X` and `weaver_mux::error::X`); callers used both.
- `StreamPolicy { class, demote_after }` let the caller write `realtime().demote_after(n)`, which compiled, round-tripped on the wire, and did nothing. Demotion is one rule the mux applies on its own; it does not belong in a per-stream wire payload.
- `GoAway` was at once the GOAWAY wire payload, the argument of `close()`, and the `reason` in `Event::Closed`. `Compress` (per-message, never serialized) sat in `wire.rs` next to `Compression` (negotiated, serialized).
- `recv_msg` checked only `closed` while every other stream method went through `ready()`; `pending_messages` returned `0` for an unknown stream while `class_of` returned `None`; `recv` on a closed connection returned `ProtocolError::Closed`, which the docstring described as "closed itself with GOAWAY".
- `Config` held `signer: Option`, `verifier: Option` and server-only numeric fields for both roles, with the invariant enforced by `expect()`.

The project rule is: no hidden code. An item is either useful to the PoC and public, or deleted.

## Decision

### Surface

| Was | Now |
|---|---|
| `pub mod sched`, `pub mod flow`, `pub mod error/event/frame/config` | private; every application type re-exported once at the root |
| `SchedTree::{control_pending, deactivate_stream, has_backlog, backlogged_classes}`, `sched::classify` | deleted |
| `Qfq::{contains, is_active, virtual_time}` | `#[cfg(test)]` |
| `Compression::{BodyOnly, Off}` | `bool compression_allowed` |
| `DEFAULT_DEMOTE_AFTER` | deleted |
| `weaver_tokio::{Connection, Event, StreamId}` re-exports | deleted; `Transport` exported instead |

`wire` stays public for tests and fuzz targets only; its application-facing types (`KeyId`, `Signature`, `Params`) are re-exported at the root.

### One name per concept

| Concept | Name |
|---|---|
| Scheduling class of a stream, at `open`, `set_class`, and in `Event::StreamOpened` | `Class` |
| Why a connection closed: argument of `close`, `Event::Closed.reason` | `CloseReason { code: CloseCode, message }` |
| GOAWAY wire payload | `wire::Goaway` (`= CloseReason`) |
| Why a handshake was refused | `RejectCode` |
| Per-message compression stance | `Compress::{Auto, Never}` (in `compress`, not `wire`) |
| Server-announced parameters | `ServerParams` (config) → `Params` (wire) |

### Demotion is a connection setting

`Config::bulk_threshold: Option<u64>` (default 256 KiB). An `Interactive` stream that has sent more than that becomes `Bulk`. No other class is ever changed by the mux. The layer above picks `Class::Bulk` up front when it already knows the body is large (`weaver_proto::policy::request_class`), and `Class::Realtime` for anything that must stay open indefinitely — WebSocket upgrades, event streams — which is by construction never demoted.

### Role carries what the role needs

```rust
enum Role {
    Client { signer: Box<dyn Signer + Send> },
    Server { verifier: Box<dyn Verifier + Send>, params: ServerParams, reverify_interval: Option<Duration> },
}
```

An invalid configuration is unrepresentable; the client no longer carries four numeric fields that are documented as ignored.

### Uniform stream API contracts

- Every stream method (`open`, `send`, `finish`, `reset`, `recv_msg`, `set_class`) fails with `StreamError::Closed` after close and `NotAuthenticated` before WELCOME.
- `class_of` and `pending_messages` both return `Option`.
- `recv` after close is `Ok(())`: frames are ignored. `ProtocolError::Closed` is gone; every `Err` from `recv` now really does mean "the mux closed itself with GOAWAY".
- `Event::Writable { id, credit }` carries the free credit so a handler can decide without a `WouldBlock` round-trip.

### Schema validation at the schema boundary

`ControlHead::register(service)` refuses a non-DNS-label name on the client; `ControlHead::validate()` re-checks name and `proto_version` on the relay. `TunnelRegistry::register_service` no longer validates names.

## Consequences

- Public items in `weaver-mux` drop from ~90 to ~40; every one has a production caller or is a test/fuzz hook under `wire`/`testing`.
- `weaver-proto::policy` exposes `request_class`, `response_class`, `CONTROL_CLASS`, plus the unchanged `*_compress` functions; `BULK_THRESHOLD` there is the *declared-size* cutoff for opening as bulk, distinct from the mux's *sent-bytes* `bulk_threshold`.
- Tests that need a class pinned set `client.bulk_threshold = None` instead of calling `set_policy(id, pinned(..))`.
