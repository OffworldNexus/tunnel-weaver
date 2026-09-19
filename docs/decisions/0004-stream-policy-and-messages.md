# 4. Stream policy, per-message compression, and a message-oriented mux

Date: 2026-09-19

## Status

Accepted. Supersedes the classification, compression and framing points of ADR 0002 and the stream-1 / PoC-key wording of ADR 0003.

The wire format changes here are **breaking but unversioned**: the protocol stays `weaver-mux-v1` (mux `MIN_VERSION = MAX_VERSION = 1`, application `PROTOCOL_VERSION = 1`) until the 1.0 release. Before 1.0 there is no compatibility promise between builds; every deployment ships client and relay together.

## Context

`docs/architecture-layers.md` audited the boundaries between `weaver-mux`, `weaver-proto` and the binaries and found:

- The mux carried an HTTP vocabulary (`Hints`: MIME type, Content-Length, Upgrade, Content-Encoding) and a MIME table, so it knew about the layer above it, while proto sent `Hints::default()` and could not say anything the heuristics did not already cover — in particular "this is a secret, do not compress".
- Compression was decided once per stream, so "uncompressed headers, compressed body" (the BREACH shape) was inexpressible.
- Request heads travelled in unbounded `OPEN` payloads while response heads travelled as length-prefixed `DATA`: two codecs, two size limits, and a length prefix on top of a message-delimited transport.
- `weaver-proto` held relay identity policy and a secret key; `PROTOCOL_VERSION` was printed but never negotiated.
- Both binaries duplicated the tokio event loop, `SystemRng`, and `TCP_NOTSENT_LOWAT`.

## Decision

### Two knobs, two scopes

| Knob | Scope | Why |
|---|---|---|
| `StreamPolicy { class, demote_after }` | stream, at `open` / `set_policy` | The scheduler orders frames per flow; splitting one stream across flows would let a later message overtake an earlier one. |
| `Compress::{Never, Auto}` | message, at `send` | The `COMPRESSED` flag is already per frame; compression does not affect ordering. |

The mux is a pure mechanism: QFQ over the class the caller named, zstd only under `Auto` and only when it pays (size floor, entropy probe, raw fallback, never on `Realtime`). It has no notion of MIME, headers or secrets. `Class::Small` is renamed `Interactive`.

### One message = one `send` = one `recv_msg`

The transport delimits messages, so the mux preserves application message boundaries. Messages over `max_frame` are fragmented with a `MORE` flag and reassembled by the receiver, bounded by `max_message` (negotiated in `WELCOME`, min 16 KiB, default 1 MiB). `read`/`write` are gone. `Event::Finished` fires only once the peer's FIN has arrived *and* every message has been consumed, so a stream is released without an extra read call.

`OPEN` carries only the `StreamPolicy`. The application head is the first message on the stream, so request and response heads use the same path.

### `weaver-proto` is schema plus policy translation

- `policy::stream_policy`, `response_policy`, `request_body_compress`, `response_body_compress` translate HTTP into mux vocabulary. Heads are always `Never`; bodies are `Never` when already encoded, pre-compressed by MIME, realtime, or when the request carries `Authorization`/`Cookie` and the response is `text/html`/`application/json` (BREACH).
- `framing` (length prefix) is deleted; `encode`/`decode` are plain postcard.
- `poc` is gone: identity lives in `weaver_server::tunnel::identity` (`IdentityResolver`, `PocResolver`), key material in `weave::identity`.
- `ControlHead::Register` carries `proto_version`; the relay answers `Refused { UnsupportedVersion }`.

### `weaver-tokio` is the adapter layer

`Driver<T: Transport, H: StreamHandler>` pumps a `Connection` over a `Sink<Bytes> + Stream`, enforcing one frame per `poll_transmit` flushed before the next, answering WebSocket ping/pong, and closing the mux locally when the transport drops. `Handle<H>` lets other tasks run closures on the connection and handler inside the loop. `SystemRng` and `set_tcp_notsent_lowat` live here and are applied on both ends.

## Consequences

- Wire (still `weaver-mux-v1`, see Status): `Params.max_message`, `DATA` flags `COMPRESSED | MORE`, `OPEN` payload is `StreamPolicy`, `ControlHead::Register.proto_version`.
- Dependency graph: `weave`, `weaver-server` → `weaver-tokio`, `weaver-proto` → `weaver-mux`. Acyclic; no crate depends on a layer above it.
- Knowledge per layer:

| Layer | Knows | Does not know |
|---|---|---|
| `weaver-mux` | classes, per-message compression stance, credit, frames, `KeyId` | MIME, HTTP, hostnames, identities, schemas |
| `weaver-proto` | HTTP/control schemas, HTTP → policy rules, proto version | sockets, tokio, who a key is |
| `weaver-tokio` | how to pump a `Connection` over a `Sink+Stream` | schemas, policy rules |
| binaries | identity, routing, certs, CLI | frame layout, scheduler |
