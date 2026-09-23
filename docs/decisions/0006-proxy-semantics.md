# 6. Proxy semantics for `weave start`

Date: 2026-09-20

## Status

Accepted. Amends the visitor-stream schema of ADR 0003/0004: a body message
is now a `weaver_proto::BodyFrame` (`Chunk` or `Trailers`) rather than a raw
byte string, and a mid-body failure is signalled with a typed `ResetCode`.
The application protocol version stays `1`; under the pre-1.0 rule of ADR
0004 the change is breaking and the client and relay must ship together, so
there is no mixed-version rollout.

## Context

ADR 0003 introduced a proof-of-concept protocol where the client answered
every visitor request with a fixed `302` and a raw chunk of bytes was a
whole body message. OFF-75 replaces that with real proxying to a local
origin, which forces decisions the PoC never had to make:

- Bodies must stream without buffering, in both directions, while preserving
  the origin's framing (chunked vs content-length on h1; whatever hyper maps
  on h2), including trailer fields.
- The origin may send interim `1xx` responses before the final head.
- A stream may upgrade to a raw byte pipe (WebSocket), in which case body
  framing stops and bytes flow until FIN.
- A hop-by-hop header policy, a `Host` rewrite default, forwarding headers,
  and header-only URL/cookie rewriting are needed to make a local origin
  reachable behind a public name.
- The relay edge must reject a forward-proxy `CONNECT`, while the
  visitor-facing requirement that every behavior-table row be exercised over
  both h1 and h2 raises the question of WebSocket over h2.

## Decision

### `BodyFrame` and `ResetCode`

A stream's first message remains a `Head` (relay side) or an
`HttpResponseHead` (client side); every message after that is decoded
positionally as a `BodyFrame`. There is no tag byte.

```rust
enum BodyFrame { Chunk(Vec<u8>), Trailers(Vec<(String, Vec<u8>)>) }
```

`Trailers` is sent at most once, immediately before FIN. A mid-body origin
failure is reported with a typed code on the mux reset frame:

```rust
enum ResetCode { OriginUnreachable = 1, OriginClosed = 2, Cancelled = 3 }
```

`OriginUnreachable` (failure before the response head) maps to a `502`
with a branded page; `OriginClosed` (failure after the head) truncates an
h1 response or sends `RST_STREAM` on h2; `Cancelled` drops the exchange
silently. The numeric values are the wire contract.

### Response sequence

- Relay → client: `Head::Http` · request `BodyFrame`s · FIN.
- Client → relay: `HttpResponseHead` · response `BodyFrame`s · FIN.
- Interim `1xx` heads repeat before the final head: every `1xx` head is
  followed by another head, and the first non-`1xx` head is final. The
  client relays the origin's interim heads verbatim; the relay's
  high-level hyper server cannot emit informational responses, so it logs
  and drops interim heads before the final one.
- After a final `101` (h1) or a `200` answering an RFC 8441 extended
  `CONNECT` (h2), both directions switch to raw `BodyFrame::Chunk`s; a FIN
  from either side closes the byte pipe.

### Streaming and backpressure

Bodies are never buffered whole. Each side keeps at most one chunk in
flight per stream and propagates `WouldBlock`/`Writable` credit to the
producer: the relay's request-body reader pauses when the origin-side queue
is full and resumes on a driver command; the client's response pump flushes
pending frames on `Event::Writable`. The mux's own per-stream window is the
outer bound.

### Origin connections

The client talks to origins with hyper's low-level client connection API
(`client::conn::http1` / `http2`), not the pooled high-level client, so
trailers, interim responses and upgrade semantics survive. `http://` targets
are h1 only — never h2c. `https://` targets offer `h2`, then `http/1.1`
via ALPN. A small idle pool per target keeps keep-alive connections.
Connection to a target has a **10 s** timeout that maps to `502`; there is
**no timeout on the origin response** itself, on purpose: SSE and long-poll
origins must not be cut off.

### Header policy

- Hop-by-hop headers per RFC 9110 §7.6.1 are stripped at each hop,
  including any header named by a `Connection` token.
- `Host` is rewritten to the target's authority by default;
  `--preserve-host <service>` keeps the public hostname.
- The relay strips any visitor-supplied `Forwarded` / `X-Forwarded-*` and
  writes the canonical `X-Forwarded-For` / `-Proto` / `-Host` and an RFC
  7239 `Forwarded`. The client, by default, replaces inbound forwarding
  headers with the canonical ones; `--append-forwarded <service>` keeps the
  visitor's copies.
- `Location`, `Content-Location` and `Refresh` values whose origin equals
  the target origin are rewritten to the public origin, preserving path and
  query. Relative values and foreign hosts are left alone.
- `Set-Cookie` whose `Domain=` equals the target host drops the attribute
  (host-only cookie on the public name) and gains `Secure` when absent.
- Body content is never rewritten. `--no-rewrite <service>` disables all of
  the above rewriting for that service.

### `CONNECT` and WebSocket

The relay is a reverse proxy, never a forward proxy: a plain `.CONNECT` is
rejected with `405`. WebSocket is supported on h1 via `Upgrade` and, in
scope per OFF-75, over h2 via an RFC 8441 **extended `CONNECT`** carrying
`:protocol=websocket`. Extended `CONNECT` is distinguished from the
rejected plain `CONNECT` by the presence of the `:protocol` pseudo-header.

On the visitor→origin hop the relay normalizes both shapes into an h1
`GET` + `Connection: upgrade` + `Upgrade: <protocol>`: origins never see
h2. For an extended CONNECT the relay also synthesizes the
`Sec-WebSocket-Key` the h2 handshake lacks (RFC 8441 §5) and drops the
origin's `Sec-WebSocket-Accept` from the `200`. After the origin's `101`
both hops become raw byte pipes: the relay writes queued frames to the
visitor's upgraded socket and queues visitor bytes as `BodyFrame::Chunk`s
through the same credit-aware request path, so a slow peer on either end
applies backpressure through the mux window.

> Known limitation: interim `1xx` responses other than the final `101`
> are relayed by the client but logged and dropped at the relay, because
> the edge's high-level hyper server cannot emit informational responses.

## Consequences

- `weaver-mux` still knows nothing about HTTP: `BodyFrame` and `ResetCode`
  live in `weaver-proto`, and the mux carries them as opaque message bytes
  and an opaque `u32` reset code.
- The shared branded pages (`welcome.html`, `no_tunnel.html`, and the new
  `bad_gateway.html`) move to a leaf `weaver-assets` crate so the client's
  502 and the edge's 403/404/502 render identically.
- `weave start` no longer needs the relay to know the target; the target
  grammar and all origin-facing policy live in the client.
- The 502 page is generated by whichever side detects the failure: the
  client when the origin is unreachable, the edge when the tunnel stream
  resets.
