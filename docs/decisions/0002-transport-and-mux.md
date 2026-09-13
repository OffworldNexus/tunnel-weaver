# 2. Transport and multiplexer: WSS on 443, sans-IO QFQ mux

Date: 2026-09-13

## Status

Accepted

## Context

Tunnel Weaver moves many concurrent HTTP-shaped streams (page loads,
long-lived SSE feeds, WebSocket upgrades, multi-gigabyte downloads) between a
client behind an arbitrary network and a server on the public internet. The
transport must survive corporate proxies, hotel Wi-Fi, and deep packet
inspection; the multiplexer on top must keep an interactive request
responsive while a bulk transfer saturates the same pipe.

Two independent choices are recorded here because they were made together
and constrain each other: what carries the bytes (transport) and how streams
share it (`weaver-mux`).

## Decision

### Transport for M1: WebSocket Secure on port 443, and nothing else

The only transport in Milestone 1 is a WebSocket over TLS on 443. It looks
like ordinary HTTPS to every middlebox, rides through HTTP CONNECT proxies,
and reuses the certificate automation the edge already needs for serving
tunnels. WebSocket also delivers exactly the abstraction the mux wants: a
reliable, ordered, **message-delimited** pipe, so the mux needs no length
prefix and no reassembly.

### Why not QUIC first

QUIC would give us streams, flow control, and loss recovery for free. It is
not the M1 transport because:

- UDP is blocked or throttled on a meaningful share of the networks our
  users sit behind; a QUIC-only client simply does not connect there.
- Every QUIC deployment in practice ships a TCP fallback anyway, so QUIC
  first means building two transports before the first tunnel works.
- A single-binary edge on hyper with WSS has no extra operational surface
  (no UDP ports, no separate cert plumbing, no ALPN negotiation to debug).

QUIC is the planned second transport, not a rejected one — see "QUIC
later" below.

### The multiplexer: `weaver-mux`, sans-IO

`weaver-mux` is a pure state machine. It never opens a socket, spawns a
thread, reads a clock, or draws randomness: frames go in and out of a
`Connection`, and the adapter passes `now: Instant` and a boxed RNG. This
is enforced mechanically (`clippy.toml` bans `Instant::now` and
`SystemTime::now`; the crate `forbid`s the lint) and is what makes the
whole scheduler testable with a fake clock and a seeded RNG, back to back
in memory, on every CI platform.

Key design points:

- **Frames.** `[stream_id: u32 BE][type: u8][payload]`, structured payloads
  in postcard with append-only evolution. Stream 0 is the connection;
  client streams are odd, server streams even. One transport message is
  one frame.
- **Authentication: the SSH model.** The server sends a `CHALLENGE`
  nonce; the client answers with a `HELLO` carrying its `KeyId`, its own
  nonce, and a signature over
  `"weaver-mux-v1" ‖ nonce_s ‖ nonce_c ‖ server_name [‖ channel_binding]`.
  The server looks the key up through a `Verifier` trait, verifies
  (Ed25519 or ECDSA P-256 — the latter because TPMs and Secure Enclaves
  speak it), and replies `WELCOME` or `REJECT`. The mux holds no keys and
  knows exactly one identity concept, the `KeyId`; who that key belongs to
  is somebody else's table. Channel binding to the TLS exporter is
  supported but off by default: too many corporate proxies terminate TLS.
- **Streams.** Bidirectional, independent half-close per direction (`FIN`),
  abort with `RST`. This maps onto every HTTP shape without special
  cases: request/response, streaming bodies, SSE that never ends, and
  upgrades.
- **Flow control.** Per-stream, per-direction credit windows measured in
  post-compression wire bytes, default 512 KiB (negotiated, 64 KiB–4 MiB).
  The receiver tops up once it has consumed half a window. There is no
  connection-level window: the transport below already has one.
- **Scheduling: Quick Fair Queueing.** `poll_transmit` emits one frame per
  call and chooses it with QFQ (Checconi, Valente, Rizzo 2013 — the
  algorithm behind Linux `sch_qfq`) over a two-level tree: four classes
  (`control` 1000, `realtime` 300, `small` 300, `bulk` 40 by default), then
  equal-weight streams inside each data class. QFQ gives weighted shares
  with an O(1) per-packet delay bound, which is what keeps a new small
  stream's first frames from waiting behind a bulk backlog. Round-robin
  and deficit round-robin were rejected because their delay bound grows
  with the number of flows; strict priority was rejected because it
  starves bulk. `control` is an ordinary weighted QFQ flow — its huge
  weight and tiny frames make PING/RST effectively immediate, but the
  guarantee is QFQ's delay bound, not "always next". The one exception is
  `GOAWAY`: `close()` places it in a dedicated slot ahead of the scheduler
  so it is literally the next frame out.
- **Classification.** Streams are born `small`; an upgrade or an
  `text/event-stream` content type makes them `realtime`; a declared
  length over 256 KiB, or 256 KiB of cumulative writes, makes them
  `bulk`. The application can pin a class with `set_class`.
- **Compression.** zstd per `DATA` frame, decided once per stream on the
  first write and signalled by a flag bit. Skipped, cheapest test first,
  for realtime streams, already-encoded or precompressed content types
  (`image/*` except SVG, `video/*`, `audio/*`, `font/woff*`, zip/gzip/
  zstd/xz/pdf/wasm/octet-stream), frames under 1 KiB, and first frames
  whose byte entropy is at or above 7.5 bits/byte. The server may refuse
  compression in `WELCOME` but can never force it.

  **BREACH note.** Compressing attacker-influenced data next to a secret
  is the CRIME/BREACH class of side channel. The mux mitigates the
  obvious cases (no compression on heads, none on realtime streams), but
  the layer that knows a response carries a secret must disable
  compression for that stream via `Compression::Off` or `set_class(…,
  Realtime)`. The mux cannot know.
- **Close codes.** `KeyRevoked` (never reconnect), `Rejected` (keep key,
  no auto-reconnect), `Superseded` (another connection took over),
  `Shutdown` (reconnect with backoff), `ProtocolError`, `Timeout`. The mux
  only carries the code; revocation and supersession policy live outside.

### Adapter contract

Two rules make the scheduler's decisions matter:

1. Call `poll_transmit` only after the previous frame has been flushed;
   never pre-buffer frames in the adapter.
2. Set `TCP_NOTSENT_LOWAT` (≈32 KiB) on Linux and macOS so the kernel does
   not queue megabytes of bulk ahead of an urgent frame. Windows has no
   equivalent; keep adapter buffering minimal there.

### QUIC later

QUIC arrives behind the same `Connection` API. A QUIC adapter maps mux
streams onto QUIC streams one to one and lets QUIC's own flow control take
over; the frame layout, handshake, scheduler, and compression policy do
not change. Nothing in the mux assumes TCP or WebSocket beyond "reliable,
ordered, message-delimited".

## Consequences

- `weaver-mux` depends on `serde`/`postcard`, `ed25519-dalek`, `p256`,
  `rand_core`, and `zstd` (C `zstd-sys`; the pure-Rust alternative is
  decode-only at our MSRV). All licences fit `deny.toml` unchanged.
- Every mux test is no-I/O and runs unmodified on Linux, macOS, and
  Windows; scheduler properties run under `proptest` with
  `PROPTEST_CASES=2000` and a fixed seed in CI.
- Two new fuzz targets (`mux_recv`, `mux_handshake`) join `frame_parse` in
  the `fuzz-smoke` job.
- The WSS/TLS/tokio adapter, `TCP_NOTSENT_LOWAT` plumbing, the contents of
  stream heads, key storage, and the registry are deliberately outside
  this crate and belong to later tickets.
