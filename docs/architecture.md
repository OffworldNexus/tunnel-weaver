# Architecture: the layers and what crosses them

This document is the current map of the workspace's abstraction layers:
which crate owns which concept, every call that crosses a crate boundary,
and the internal call flow of the multiplexer. It is the reference for
checking that a change does not leak a concept into a layer that should
not know it, and that no two APIs cover the same concern.

Decisions behind this shape: ADR 0002 (transport and mux), 0003 (tunnel
protocol), 0004 (stream policy and messages), 0005 (minimal mux surface),
0008 (flat hostnames and the wildcard certificate), 0010 (one key per
machine), 0011 (the client dials the admin host only).

## 1. Layer map

```mermaid
flowchart TB
    subgraph L4["L4 - Binaries: identity, routing, certs, CLI"]
        weave["weave<br/>ProxyHandler, origin pool, pairing, client store (SQLite),<br/>tpmd device key, relay registry, WS+TLS dial"]
        server["weaver-server<br/>RelayHandler, TunnelRegistry, IdentityResolver,<br/>Pairings, edge http/https, cert manager, control socket"]
    end
    subgraph L3["L3 - weaver-tokio: the only event loop"]
        tokio["Driver&lt;T: Transport, H: StreamHandler&gt;<br/>Handle&lt;H&gt; · WsTransport · SystemRng · set_tcp_notsent_lowat"]
    end
    subgraph L2["L2 - weaver-proto: schema + HTTP→policy"]
        proto["Head { Control | Http } · pair · ControlReply · HttpResponseHead<br/>encode / decode (postcard) · policy: request_class, response_class, *_compress"]
    end
    subgraph L1["L1 - weaver-mux: sans-IO multiplexer"]
        mux["Connection · Config/Role · Class · Compress<br/>Event · CloseReason · StreamError<br/>Signer / Verifier traits"]
    end
    weave --> tokio & proto & mux
    server --> tokio & proto & mux
    tokio --> mux
    proto -- "Class, Compress only" --> mux
```

| Layer | Knows | Does not know |
|---|---|---|
| `weaver-mux` | classes, per-message compression stance, credit, frames, `KeyId` | MIME, HTTP, hostnames, identities, schemas, sockets, clocks |
| `weaver-proto` | HTTP/control schemas, HTTP → `Class`/`Compress` rules, proto version | sockets, tokio, who a key is |
| `weaver-tokio` | how to pump a `Connection` over a `Sink + Stream` | schemas, policy rules |
| binaries | identity, pairing and the device key, routing, certs, CLI | frame layout, scheduler |

The graph is acyclic and each crate depends only on layers below it.

## 2. `weaver-mux`

### 2.1 Public surface

Everything an application can name, in one place (`lib.rs`). `wire` is
public only so tests and fuzz targets can hand-craft frames.

```mermaid
classDiagram
    class Connection {
        +new(Config, now) Connection
        +recv(now, bytes) Result~(), ProtocolError~
        +poll_transmit(buf) bool
        +handle_timeout(now)
        +next_timeout() Option~Instant~
        +poll_event() Option~Event~
        +open(Class) Result~StreamId, StreamError~
        +send(id, msg, Compress) Result~(), StreamError~
        +recv_msg(id) Result~Vec~u8~, StreamError~
        +finish(id) Result~(), StreamError~
        +reset(id, code) Result~(), StreamError~
        +set_class(id, Class) Result~(), StreamError~
        +close(CloseReason)
        +is_closed() bool
        +version() / params() / rtt() / class_of() / pending_messages() [test-util]
    }
    class Config {
        role: Role
        rng: Box~dyn Rng~
        server_name: String
        weights: Weights
        bulk_threshold: Option~u64~
        zstd_level: i32
        compression_allowed: bool
        handshake_timeout / ping_interval / idle_timeout
        channel_binding: Option~[u8;32]~
        +client(signer, name, rng)
        +server(verifier, name, rng)
        +server_params_mut() Option~&mut ServerParams~
    }
    class Role {
        <<enum>>
        Client(signer)
        Server(verifier, params: ServerParams, reverify_interval)
    }
    class Class {
        <<enum>>
        Control · Realtime · Interactive · Bulk
    }
    class Compress {
        <<enum>>
        Auto · Never
    }
    class Event {
        <<enum>>
        Authenticated(key_id, version)
        Rejected(code: RejectCode, message)
        StreamOpened(id, class)
        Readable(id)
        Writable(id, credit)
        Finished(id)
        Reset(id, code)
        Closed(reason: CloseReason)
    }
    class CloseReason {
        code: CloseCode
        message: Option~String~
    }
    class Signer {
        <<trait>>
        key_id() KeyId
        sign(msg) Result~Signature, SignError~
    }
    class Verifier {
        <<trait>>
        public_key(&KeyId) Option~PublicKey~
        still_valid(&KeyId) bool
    }
    Connection --> Config
    Config --> Role
    Role --> Signer
    Role --> Verifier
    Connection ..> Event : emits
    Connection ..> Class
    Connection ..> Compress
    Connection ..> CloseReason
```

Vocabulary, one name per concept:

| Concept | Name |
|---|---|
| how a stream is scheduled | `Class` |
| whether one message may be compressed | `Compress` |
| why a connection closed (API, event, GOAWAY payload) | `CloseReason` / `CloseCode` |
| why a handshake was refused (REJECT payload) | `RejectCode` |
| why a stream was aborted | `u32` code in `reset` / `Event::Reset` |
| what the server announces | `ServerParams` (config) → `Params` (wire) |

### 2.2 Module graph

```mermaid
flowchart LR
    Connection["connection::Connection"]
    subgraph pure["pure helpers"]
        frame["frame — 5-byte header codec"]
        wire["wire — postcard payloads"]
        auth["auth — transcript(), verify()"]
        handshake["handshake — negotiate(), accept_version()"]
        compressfn["compress::should_compress — size floor, entropy, Realtime"]
    end
    subgraph owned["owned state"]
        streams["HashMap&lt;StreamId, Stream&gt;<br/>outbox · inbox · partial · windows · flags"]
        flow["flow::SendWindow / RecvWindow"]
        sched["sched::SchedTree = Qfq&lt;Class&gt; + 3×Qfq&lt;StreamId&gt; + control FIFO"]
        timers["timers::Timers — handshake · ping · idle · reverify"]
        zstd["compress::ZstdCtx"]
        events["VecDeque&lt;Event&gt;"]
    end
    Connection --> frame & wire & auth & handshake & compressfn
    Connection --> streams & sched & timers & zstd & events
    streams --> flow
```

Enforced inside the crate: `#![forbid(clippy::disallowed_methods)]` +
`clippy.toml` ban `Instant::now`, `SystemTime::now` and RNG calls. Time
enters only as `now`; randomness only via `Config::rng`. Keys never enter:
the crate sees a `KeyId` and a `Signature`.

### 2.3 What each public call touches

```mermaid
flowchart LR
    subgraph adapter["adapter → Connection"]
        new["new"] ; recv["recv"] ; ht["handle_timeout"] ; pt["poll_transmit"] ; pe["poll_event"] ; nt["next_timeout"]
    end
    subgraph app["application → Connection"]
        open["open"] ; send["send"] ; rm["recv_msg"] ; fin["finish"] ; rst["reset"] ; sc["set_class"] ; cl["close"]
    end
    subgraph inside["internal"]
        F["Frame/wire"] ; S["streams"] ; Q["SchedTree"] ; T["Timers"] ; Z["ZstdCtx"] ; E["events"] ; SV["Signer / Verifier / Rng"]
    end
    new --> T & Q & Z
    new -- "server: nonce, CHALLENGE" --> SV
    recv --> F & T
    recv -- "CHALLENGE: rng, sign()" --> SV
    recv -- "HELLO: public_key(), verify" --> SV
    recv -- "DATA: decompress, reassemble" --> Z & S & E
    recv -- "OPEN/FIN/RST/WU" --> S & Q & E
    ht --> T
    ht -- "Reverify: still_valid()" --> SV
    ht -- "Ping" --> Q
    pt --> Q & S & T
    pe --> E
    nt --> T
    open --> S & Q
    send -- "compress, fragment, demote" --> Z & S & Q
    rm -- "WINDOW_UPDATE, Finished" --> S & Q & E
    fin --> S & Q
    rst --> S & Q
    sc --> S & Q
    cl --> Q & S & T & E
```

Only `new`, `recv` and `handle_timeout` reach the adapter-supplied traits.
Every stream method goes through one `ready()` check: `Closed` after
close, `NotAuthenticated` before WELCOME.

### 2.4 Handshake

```mermaid
sequenceDiagram
    autonumber
    participant CA as client adapter
    participant CC as client Connection
    participant SC as server Connection
    participant SA as server adapter
    participant S as dyn Signer
    participant V as dyn Verifier

    SA->>SC: new(Config::server(..), now)
    Note over SC: rng → nonce_s, handshake_out ← CHALLENGE
    SA->>SC: poll_transmit
    SC-->>CA: CHALLENGE{nonce_s}
    CA->>CC: recv
    Note over CC: rng → nonce_c<br/>msg = transcript(nonce_s, nonce_c, server_name, channel_binding)
    CC->>S: key_id(), sign(msg)
    Note over CC: handshake_out ← HELLO{version, key_id, nonce_c, sig}
    CA->>CC: poll_transmit
    CC-->>SA: HELLO
    SA->>SC: recv
    Note over SC: negotiate(version) → REJECT UnsupportedVersion
    SC->>V: public_key(key_id) → None → REJECT UnknownKey
    Note over SC: verify(sig) false → REJECT BadSignature<br/>WELCOME{version, Params from ServerParams}<br/>hs = Done, timers.on_authenticated
    SC-->>SA: Event::Authenticated
    SA->>SC: poll_transmit
    SC-->>CA: WELCOME
    CA->>CC: recv
    Note over CC: accept_version, range-check Params<br/>rebuild SchedTree with max_frame<br/>compression_enabled = local && server allowed
    CC-->>CA: Event::Authenticated
```

REJECT closes the server side without GOAWAY and yields
`Event::Rejected` then `Event::Closed` on the client.

### 2.5 One message, end to end

```mermaid
sequenceDiagram
    autonumber
    participant App as application
    participant C as Connection (sender)
    participant Q as SchedTree
    participant Ad as adapter
    participant P as Connection (receiver)
    participant PApp as peer application

    App->>C: open(Class::Interactive)
    C->>Q: add_stream · push_control(OPEN{class})
    C-->>App: StreamId
    App->>C: send(id, msg, Compress::Auto)
    Note over C: TooLarge if len > max_message<br/>WouldBlock if credit < len + n_frags<br/>per fragment: should_compress? zstd, raw fallback<br/>flags = COMPRESSED? | MORE?<br/>written_total > bulk_threshold → Bulk
    C->>Q: activate_stream / reclass
    Ad->>C: poll_transmit
    C->>Q: pick() → Control → OPEN
    Ad->>C: poll_transmit
    C->>Q: pick() → Stream(id) → DATA
    Ad-->>P: recv(OPEN) · recv(DATA…)
    Note over P: OPEN: class ≠ Control, parity, monotonic<br/>DATA: flags known, decompress ≤ 8×max_frame,<br/>credit check, partial += data ≤ max_message<br/>no MORE → inbox.push
    P-->>PApp: Event::StreamOpened{id, class} · Event::Readable(id)
    PApp->>P: recv_msg(id) until WouldBlock
    Note over P: recv.on_consumed → WINDOW_UPDATE when ≥ window/2
    App->>C: finish(id)
    C->>Q: push_control(FIN) once outbox drains
    Ad-->>P: recv(FIN)
    Note over P: Finished fires when FIN seen AND inbox empty
    P-->>PApp: Event::Finished(id)
```

Stream release is automatic: once both halves are closed, FIN queued,
outbox empty and `Finished` delivered, the stream is forgotten. No extra
read is required.

### 2.6 Timers

```mermaid
flowchart TD
    nt["next_timeout()"] --> T["min(handshake_deadline, ping_due, idle_deadline, reverify_due)"]
    ht["handle_timeout(now)"] --> obs["timers.observe(now) — never backwards"]
    obs --> loop{"expired?"}
    loop -- Handshake / Idle --> to["close(Timeout) + GOAWAY"]
    loop -- Reverify --> sv["verifier.still_valid(key_id)"]
    sv -- false --> kr["close(KeyRevoked) + GOAWAY"]
    sv -- true --> rearm["reverify_due += interval"] --> loop
    loop -- Ping --> ping["ping_counter += 1<br/>push_control(PING); sent_at fixed at transmit"] --> loop
    loop -- none --> done["return"]
```

## 3. `weaver-proto`

A schema crate plus the single place that translates HTTP into mux
vocabulary. No state, no I/O, no mux driving.

```mermaid
classDiagram
    class Head {
        <<enum>>
        Control(ControlHead)
        Http(HttpHead)
    }
    class ControlHead {
        <<enum>>
        Register(proto_version, service)
        Revoke(proto_version)
        +register(service) Result~Self, RefusalCode~
        +revoke() Self
        +validate() Result~(), RefusalCode~
    }
    class ControlReply {
        <<enum>>
        Registered(hostname)
        Refused(code: RefusalCode, message)
        Revoked
    }
    class HttpHead {
        method, scheme, authority, path
        headers: Vec~(String, Vec~u8~)~
        +header(name) Option~&[u8]~
    }
    class HttpResponseHead {
        status: u16
        headers
        +header(name)
    }
    class BodyFrame {
        <<enum>>
        Chunk(Vec~u8~)
        Trailers(Vec~(String, Vec~u8~)~)
    }
    class ResetCode {
        <<enum>>
        OriginUnreachable = 1
        OriginClosed = 2
        Cancelled = 3
        +as_u32() u32
        +from_u32(u32) Option~Self~
    }
    class codec {
        <<fns>>
        encode(&T) Result~Vec~u8~, CodecError~
        decode(&[u8]) Result~T, CodecError~
        accept_protocol_version(u16)
        is_valid_dns_label(&str)
    }
    class policy {
        <<module>>
        CONTROL_CLASS = Interactive
        CONTROL_COMPRESS = Never
        HEAD_COMPRESS = Never
        BULK_THRESHOLD = 256 KiB (declared size)
        request_class(&HttpHead) Class
        response_class(&HttpHead, &HttpResponseHead) Option~Class~
        request_body_compress(&HttpHead) Compress
        response_body_compress(&HttpHead, &HttpResponseHead) Compress
    }
    Head --> ControlHead
    Head --> HttpHead
    ControlReply --> RefusalCode
    policy ..> HttpHead
    policy ..> HttpResponseHead
    BodyFrame ..> HttpHead : body for the preceding head
    ResetCode ..> BodyFrame : mid-body failure
    class pair {
        <<module — JSON, not postcard>>
        PAIR_CHANNEL_PATH · PAIR_SUBPROTOCOL · PAIR_POW_PURPOSE
        Begin(proof, key_id, target)
        ServerMessage(Challenge|Handle|Approved|Failed)
        Lookup / Accept / Reject bodies
    }
    class mux_Class["weaver_mux::Class"]
    class mux_Compress["weaver_mux::Compress"]
    policy ..> mux_Class
    policy ..> mux_Compress
```

Stream conventions (all in `weaver-proto` docs, enforced by the handlers).
After the head, every message is a `BodyFrame` decoded from stream state —
never from a tag; `Trailers` is the optional final frame before FIN. A
mid-body origin failure travels as a typed `ResetCode` on the mux reset
frame. **The control stream is the registration lease**: a service is
registered exactly as long as the control stream that registered it is
open. The client drops a service by finishing that stream; the relay
unregisters it on `Finished`/`Reset`, and unregisters everything on
`Closed`. There is no `Unregister` message because the stream lifecycle
already expresses it.

The control stream also carries one **one-shot** head, `Revoke`: a client
authenticated by a device key is entitled to withdraw that very key, so
`weave unpair` opens a control stream, sends `Revoke`, and the relay deletes
the machine — its key, services and hostnames — then answers
`ControlReply::Revoked`. A `KeyRevoked` close is an equivalent confirmation;
the relay closes the connection after the reply. Pairing has its own
transport and does not touch the mux control plane: `weaver-proto::pair` is
fairly ordinary JSON (the pairing channel is a plain WebSocket on the admin
host, and the browser API is JSON already), so it is the one schema module
that is *not* postcard.

```mermaid
flowchart LR
    subgraph control["control stream (client-opened, stays open)"]
        c1["msg 1: Head::Control(Register)"] --> c2["msg 2: ControlReply"] --> c3["… open = registered; FIN/RST = unregistered"]
    end
    subgraph visitor["visitor stream (relay-opened)"]
        v1["msg 1: Head::Http(HttpHead) — Never"] --> v2["msg 2..n: BodyFrame::Chunk — request_body_compress"] --> v3["opt: BodyFrame::Trailers"] --> v4["FIN"]
        v5["msg 1 back: HttpResponseHead — Never<br/>(repeats for 1xx; first non-1xx is final)"] --> v6["msg 2..n back: BodyFrame::Chunk — response_body_compress"] --> v7["opt: BodyFrame::Trailers"] --> v8["FIN"]
        v9["after 101 / extended CONNECT: raw BodyFrame::Chunk both ways until FIN"]
    end
```

Policy rules, in the order they apply:

| Decision | Rule |
|---|---|
| `request_class` | `Upgrade` or `Accept: text/event-stream` → `Realtime`; declared `Content-Length` > 256 KiB → `Bulk`; else `Interactive` (mux demotes after `bulk_threshold` sent bytes) |
| `response_class` | request already realtime → keep; response `text/event-stream` → `Realtime`; declared length > 256 KiB → `Bulk` |
| heads | always `Never` (cookies, tokens, CSRF secrets) |
| bodies | `Never` if realtime, `Content-Encoding` set, MIME pre-compressed, or request carries `Authorization`/`Cookie` and the response is `text/html` / `application/json` / `xhtml` (BREACH); else `Auto` |

## 4. `weaver-tokio`

```mermaid
flowchart TD
    start["Driver::new(conn, transport, handler)"] --> flush["flush: while poll_transmit → transport.send(frame)<br/>one frame per send, flushed before the next"]
    flush --> closed{"conn.is_closed()?"}
    closed -- yes --> ret["dispatch_events; return (handler, Ok(reason))"]
    closed -- no --> sel{"select!"}
    sel -- "sleep(next_timeout)" --> ht["conn.handle_timeout(now)"]
    sel -- "transport.next() = Some(Ok(Some(bytes)))" --> rv["conn.recv(now, bytes)<br/>Err → outcome = Protocol(e)"]
    sel -- "Some(Ok(None)) — ws ping/pong" --> noop["nothing"]
    sel -- "Some(Err) / None" --> fin["conn.close(Shutdown); dispatch; return Err"]
    sel -- "cmd_rx: Handle::spawn_on / call / close" --> cmd["cmd(&mut conn, &mut handler)"]
    ht & rv & noop & cmd --> ev["while poll_event: handler.on_event(&mut conn, ev)"]
    ev --> flush
```

Public surface: `Driver`, `Handle<H>` (`spawn_on`, `call`, `close`),
`StreamHandler::on_event`, `DriverError`, `Transport`, `WsTransport`,
`SystemRng`, `set_tcp_notsent_lowat`. It re-exports nothing from
`weaver-mux`; binaries import mux types from `weaver_mux` directly.

## 5. Binaries: the two `StreamHandler`s

### 5.1 Relay (`weaver-server/src/tunnel/connection.rs`)

```mermaid
flowchart LR
    Auth["Authenticated{key_id}"] --> reg["registry.register_connection → conn_id<br/>spawn: superseded → Handle::close(Superseded)"]
    Rd["Readable(id)"] --> loop["loop recv_msg"]
    loop -- "inflight[id]" --> vm["on_visitor_message:<br/>repeated heads (1xx logged/dropped); final → response_class → set_class → hyper Response<br/>then: BodyFrame::Chunk/Trailers → body_tx"]
    loop -- "new stream" --> fm["on_first_message:<br/>decode Head::Control → validate()<br/>Register: spawn registry.register_service → ControlReply<br/>Revoke: registry.revoke_machine(key) → ControlReply::Revoked"]
    Wr["Writable{id}"] --> drain["drain_request_body: retry pending chunks"]
    Fin["Finished(id)"] --> lease["release_lease: control stream → registry.unregister_service<br/>visitor stream → drop body_tx"]
    Rs["Reset{id}"] --> lease
    Rs --> err["response_tx ← Err(Reset)"]
    Cl["Closed"] --> unreg["registry.unregister_connection (all leases)"]
    prx["proxy_rx: ProxyRequest (from edge)"] --> op["open(request_class(head))<br/>send(Head::Http, Never)<br/>spawn body reader → send(encode(BodyFrame), request_body_compress) / finish"]
```

### 5.2 Client (`weave/src/start.rs`)

One `weave start <service>=<target>…` invocation registers every service on
a single connection: one control stream per service, one `Driver`. Each
visitor stream is answered by an origin task (`weave/src/proxy.rs`) that
drives one outbound hyper request through the per-target pool
(`weave/src/pool.rs`).

```mermaid
flowchart LR
    Auth["Authenticated"] --> openc["for each service:<br/>ControlHead::register; open(CONTROL_CLASS); send(Head::Control, Never)"]
    Rej["Rejected{code}"] --> f1["failure = rejected"]
    Rd["Readable(id)"] --> which{"control?"}
    which -- yes --> ctl["decode ControlReply → print 'svc url → target'<br/>Refused → record failure, others keep running"]
    which -- no --> start["resolve service from authority<br/>(flat label, split at first two dashes; no Registered race)<br/>spawn run_exchange; insert Exchange"]
    start --> drain["drain_stream: decode BodyFrame → req_body_tx<br/>pause + resume on full (backpressure)"]
    Wr["Writable{id}"] --> pump["pump_out: flush encoded head/frames on credit"]
    out["run_exchange: pool.acquire → hyper h1/h2 →<br/>send head(s) + BodyFrame::Chunk/Trailers + End"] --> pump
    Fin["Finished(id)"] --> drop["drop req_body_tx (FIN the request body)"]
    Rs["Reset{id}"] --> rm["inflight.remove"]
```

The connection is dialled to the paired relay's **admin host** — the only
address the client knows — at `/_weaver/connect`, and the host it presents is
the mux handshake server name (ADR 0011). The public URL of each service
comes from `ControlReply::Registered { hostname }`; the client prints it and
never derives or caches it. Resolving an incoming visitor stream still falls
back to the flat label (the reply may not have been seen yet), but the relay
is the authority for what that label is.

### 5.3 A visitor request through every layer

```mermaid
sequenceDiagram
    autonumber
    participant Vis as visitor (HTTPS)
    participant Edge as edge::https (hyper)
    participant Reg as TunnelRegistry
    participant RH as RelayHandler
    participant SM as mux (server)
    participant WS as WebSocket/TLS
    participant CM as mux (client)
    participant PH as ProxyHandler
    participant Origin as local origin

    Vis->>Edge: GET https://poc-laptop-web.<root>/
    Edge->>Reg: lookup(host) → proxy_tx
    Edge->>RH: ProxyRequest{HttpHead, body, response_tx}
    RH->>SM: open(policy::request_class(head))
    RH->>SM: send(id, encode(Head::Http), HEAD_COMPRESS)
    RH->>SM: send(id, chunk, request_body_compress) … finish(id)
    SM-->>WS: OPEN{class} · DATA … · FIN
    WS-->>CM: recv ×n
    CM-->>PH: StreamOpened · Readable · Finished
    PH->>CM: recv_msg → Head::Http, BodyFrame
    PH->>Origin: hyper request (pool, h1/h2, Host rewritten)
    Origin-->>PH: HttpResponseHead + body frames (+ trailers)
    PH->>CM: send(id, encode(HttpResponseHead), HEAD_COMPRESS) then BodyFrame… then finish(id)
    CM-->>WS: DATA · FIN
    WS-->>SM: recv
    SM-->>RH: Readable(id)
    RH->>SM: recv_msg → HttpResponseHead, BodyFrame
    RH->>SM: set_class(id, response_class(..)) if any
    RH->>Edge: response_tx ← Response
    Edge-->>Vis: 200 (origin's status)
    SM-->>RH: Finished(id) → drop body_tx
```

## 6. Pairing and the machine identity model

### 6.1 Commands and the client's own state (`crates/weave`)

`weave` is a small stateful agent, not a one-shot tunnel command:

| Command | Effect |
|---|---|
| `weave pair <admin-host> [--machine ID] [--min-key-security L] [--allow-below-floor]` | enrol this machine's device key with a relay, with browser approval |
| `weave start <service>=<target>… [--server HOST]` | register services on a paired relay and proxy to their origins |
| `weave unpair [<admin-host>]` | revoke this machine on the relay, then forget it locally |
| `weave relays` / `weave relays default <admin-host>` | list paired relays / choose the default |

Its durable state is a SeaORM-managed SQLite database
(`crates/weave/src/store/`) in the platform's per-user data directory
(`directories`; overridable with `WEAVE_DATA_DIR`), file `weave.db`. It holds
the fingerprint of the machine's one device key (a single `device` row, so a
later command resumes that key instead of having tpmd mint another) and **one
`relay` row per pairing** — the admin host it dials, the machine id the relay
assigned, and the device-key fingerprint authorised there — plus which relay is
the default (a partial unique index allows at most
one; the first pairing becomes it). It deliberately holds no relay-owned
state: no hostname, no tunnel root, no service address (ADR 0011).

The device key never leaves **tpmd**, the local key agent. `weave` stores only
its `p256:<hex>` fingerprint and signs by asking the agent over async IPC —
which is why the mux's `Signer::sign` is asynchronous even though the mux
itself stays sans-IO. `--min-key-security` (`file`/`keyring`/`sealed`/
`hardware`, default `sealed`) is a floor; provisioning below it needs
`--allow-below-floor` or an interactive yes. `weave start` only ever *resumes*
the key the relay authorised, so a vanished key is an error the user resolves
by pairing again, never a silent new identity.

### 6.2 The pairing flow

Pairing uses two transports, neither of them the mux:

- the **pairing channel** — a plain JSON WebSocket the CLI opens to the admin
  host at `/api/account/pair/channel` (subprotocol `weaver-pair-v1`). The relay
  speaks first with a signed ALTCHA proof-of-work challenge (purpose `pair`);
  the CLI answers with exactly one `Begin { proof, key_id, target }`; the relay
  answers with a `Handle` and then exactly one outcome.
- the **browser API** — `POST /api/account/pair/{lookup,accept,reject}`,
  behind a session (and origin + CSRF for accept/reject).

```mermaid
sequenceDiagram
    autonumber
    participant CLI as weave pair
    participant Edge as edge (admin host)
    participant Pair as Pairings (in-memory)
    participant Store as relay Store
    participant SPA as /pair page (browser)

    CLI->>Edge: WSS GET /api/account/pair/channel (weaver-pair-v1)
    Edge->>Store: ALTCHA challenge (purpose "pair")
    Edge-->>CLI: ServerMessage::Challenge
    Note over CLI: solve proof of work (bounded), open the device key in tpmd
    CLI->>Edge: Begin{proof, key_id, target}
    Edge->>Store: machine_by_key(key_id) → AlreadyPaired / ok
    Edge->>Pair: register(key_id, target)
    Edge-->>CLI: ServerMessage::Handle{handle}
    CLI-->>CLI: print the approval link and wait
    SPA->>Edge: POST /api/account/pair/lookup{handle}
    Edge-->>SPA: Waiting{fingerprint, account, person, machine}
    SPA->>Edge: POST /api/account/pair/accept{handle, person_slug?, machine_name?}
    Edge->>Store: create_machine / replace_machine_key (+ key log)
    Edge-->>CLI: ServerMessage::Approved{machine_id, person, machine}
    CLI->>Store: record_pairing (client store)
```

The **handle** is a capability: 32 random bytes, lowercase hex, single use,
carried only in the link's fragment (never the query) and in JSON bodies — so
it cannot reach an access log or a `Referer`. The pending pairing is
**in-memory only** (`account::pairing::Pairings`): it lives exactly as long as
the CLI's channel, so there is nothing to expire or sweep, and a relay restart
simply ends it. Above it sit the usual abuse controls: the proof of work, the
`account-pair` request budget, a 16 KiB message cap and a 60 s `Begin`
timeout.

`target` selects the machine: `New { hostname }` creates a machine (the relay
proposes a slug from the raw hostname and the person slug from the account
name, and the person may edit a proposed name); `Existing { machine_id }`
moves a machine whose key was lost onto this key — its id, name, services and
hostnames stay, only the key changes. `weave pair` chooses between them from
its own store: a known relay under a different key means the old key is gone.

### 6.3 Identity model and schema

- One account owns exactly **one person** (`person.account_id` unique).
- A machine belongs to one person and holds exactly **one key**
  (`machine.key_id` unique). The key alone identifies the machine — and
  therefore the person, the account, and every hostname derived from them.
  There is no `machine_key` table any more; attaching a key to an existing
  machine **overwrites `key_id` in place**.
- Nothing that authenticates a key reads history: `StoreIdentityResolver`
  resolves `machine.key_id` and nothing else, and the mux `Verifier` and the
  registry's authorization source are the same resolver, so they cannot
  disagree. `machine_key_log` is a **write-only audit trail** (one row per key,
  opened when attached, closed on replace or revoke; deliberately no foreign
  keys, so it outlives the machine). The account sweep drops rows retired
  longer ago than `account.key_log_retention_days` (default 365); rows of
  current keys are never dropped.
- Pairing is the **only** enrolment path; there is no implicit creation at
  authentication time.
- Revocation is bilateral: `weave unpair` authenticates with the very key it
  revokes and the relay deletes the machine — cascading to its services and
  hostnames, and closing its key log row as revoked. The name is freed, so a
  later pairing may propose it again. The client forgets the relay only once
  the relay has replied `Revoked`; there is no one-sided unpair.

The relay's schema is now a **single squashed migration**, `m0001_init`,
which creates the final schema directly (relay config and ACME accounts; the
account plane; `person`/`machine`/`machine_key_log`; services and hostnames;
certificates and challenges; usage; abuse buckets and ALTCHA). There is no
backward compatibility and no incremental history: the live relay's database
was rebuilt rather than migrated.

### 6.4 Tunnel addressing

The mux WebSocket `/_weaver/connect` is served on the **tunnel root and the
admin host**. A client only ever knows the admin host it paired with, so it
dials that; the host it presents (parsed from the request and lowercased)
becomes the mux handshake `server_name` on both ends, binding the transcript to
the name the client actually dialled. The relay reports each registered
service's public hostname in `ControlReply::Registered { hostname }`, so the
client learns its address rather than constructing or caching it.

Admin hosts are normalised once — lowercased, trailing dot stripped, a default
`:443` dropped, a pasted `https://host/` accepted — before being stored and
before being dialled; the normalised value is what TCP, SNI, the `Host` header
and the transcript all use. Because the admin host is the transcript name and
the admin certificate's name, renaming it means re-pairing.

## 7. Boundary checklist

What to verify when touching a boundary. Each row is currently true.

| Boundary | Invariant | Enforced by |
|---|---|---|
| mux ⟂ time / randomness | only `now` parameters and `Config::rng` | clippy `disallowed_methods`, `#![forbid]` |
| mux ⟂ keys | `Signer`/`Verifier` traits; mux sees `KeyId` + `Signature` | `Role` enum carries exactly one of them |
| mux ⟂ content | OPEN carries only `Class`; DATA is opaque bytes + flags | `wire.rs` has no MIME/HTTP types; `compress` is content-agnostic |
| mux ⟂ transport | one `recv` = one message; one `poll_transmit` = one frame; no length prefix | `Driver::flush`; `frame.rs` header has no length |
| proto → mux | uses `Class` and `Compress` only, never `Connection` | `weaver-proto/Cargo.toml` + `policy.rs` imports |
| proto ⟂ identity | `Head`/`HttpHead` carry no keys or hostnames; the `pair` module carries a `KeyId` and a raw hostname on purpose, as the enrolment schema | `identity` lives in `weave` and `weaver-server` |
| tokio ⟂ schema | `Driver` is generic in `H: StreamHandler`; never decodes | `weaver-tokio` does not depend on `weaver-proto` |
| one name per concept | `Class`, `Compress`, `CloseReason`, `RejectCode`, reset `u32` | ADR 0005 table |
| uniform stream API | every stream method → `ready()`; accessors → `Option` | `Connection::ready`, `class_of`, `pending_messages` |
| no hidden code | every `pub` item has a production caller, or is a test/fuzz hook under `wire`/`testing` | ADR 0005 |
| schema validation at the schema | service name and proto version checked by `ControlHead::register` / `validate` on both ends | `control.rs`; registry does not re-validate |
| identity ⟂ key history | authentication reads `machine.key_id` only; `machine_key_log` is write-only | `StoreIdentityResolver`, migration indexes, ADR 0010 |
| client ⟂ relay-assigned addressing | the client store holds only the admin host, machine id and key fingerprint | client store, ADR 0011 |
| pending pairing ⟂ persistence | a pending pairing is in memory only, live exactly as long as the CLI's channel | `account::pairing::Pairings`; no table |
| unauthenticated pairing ⟂ abuse | proof of work (ALTCHA purpose `pair`), the `account-pair` budget, a 16 KiB message cap and a 60 s `Begin` timeout | `account/pairing.rs`, edge routing |
