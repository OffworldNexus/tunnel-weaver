# 3. Tunnel protocol: stream lifetimes, supersession, hostname schema, and PoC deprecation

Date: 2026-09-16

## Status

Accepted

## Context

Milestone 1 introduces the first end-to-end integration between the client (`weave`) and the relay (`weaver-server`) across the sans-IO multiplexer (`weaver-mux`) running over WSS on port 443.

The architecture requires explicit definitions for:
- Stream lifetimes and parity (control stream vs. visitor proxy exchanges).
- Connection supersession when duplicate client identities connect.
- Hostname derivation and namespace hierarchy.
- Hard-coded proof-of-concept identity key deprecation.

## Decision

### 1. Stream Parity and Lifetimes

`weaver-mux` allocates odd stream IDs to client-initiated streams and even stream IDs to server-initiated streams. Stream 0 is reserved for connection-level authentication (`CHALLENGE` / `HELLO` / `WELCOME`) and flow control.

- **Control Stream (Client-Initiated):**
  - Immediately following authentication (`Event::Authenticated`), the client opens a stream with `policy::CONTROL_POLICY` and sends, as its first message, `Head::Control(ControlHead::Register { proto_version, service })`. The mux allocates the id (the first client stream is 1, but the protocol does not depend on it).
  - The relay checks `proto_version` against `weaver_proto::accept_protocol_version`, verifies the service label, resolves the key to an identity through the relay's `IdentityResolver`, derives the public hostname, initiates certificate provisioning via `CertManager::ensure`, and replies on the same stream with one message, `ControlReply::Registered { hostname }` or `ControlReply::Refused { code, message }`. Every control message is sent with `Compress::Never`.
  - On success, **the control stream is held open for the lifetime of the service registration**. Neither side half-closes or resets it while the service is active.
  - If the control stream closes (FIN or RST) or the underlying connection drops, the service registration is immediately removed from the relay's routing table, and `CertManager::set_active(hostname, false)` is invoked to pause certificate renewals.

- **Data Streams (Even Streams, Server-Initiated):**
  - Each incoming visitor HTTP request on a registered hostname opens a fresh, independent even stream (2, 4, 6, ...) initiated by the relay.
  - The stream opens with `policy::stream_policy(&head)` and its first message is `Head::Http(HttpHead)`, carrying RFC 9110 request metadata, stripped hop-by-hop headers, and appended `X-Forwarded-*` headers. Heads are always sent with `Compress::Never`.
  - The visitor request body is streamed as one mux message per chunk with `policy::request_body_compress(&head)`. When the request body finishes, the relay sends `FIN` (half-close).
  - The client drains the request body, dumps request information to stdout, and replies with one `HttpResponseHead` message followed by body chunk messages (`policy::response_body_compress`). The relay may reclassify the stream on the response head via `policy::response_policy`.
  - When the response body completes, the client sends `FIN` (closing the stream).
  - If the tunnel stream errors or resets before response headers are parsed, the relay returns an HTTP 502 Bad Gateway response to the visitor.

### 2. Connection Supersession Policy

Tunnel client authentication uses public-key identities (`KeyId`).

- When a new connection successfully authenticates with a `KeyId` that is already active on the relay:
  - The existing lingering connection is immediately terminated by sending `GOAWAY { code: Superseded }`.
  - All services registered under the superseded connection are removed from the routing registry.
  - The newer connection takes over exclusive control.
- When an active connection attempts to register a service name that is already registered on that machine, the relay refuses the duplicate registration with `ControlReply::Refused { code: AlreadyRegistered }` without evicting the existing service registration.

### 3. Hostname Schema

Tunnel hostnames follow a strict hierarchical derivation:

```
<service>.<machine>.<person>.<root>
```

- `<service>`: Single DNS label validated against RFC 1035 / RFC 1123 rules (1–63 ASCII alphanumeric characters or hyphens; cannot begin or end with a hyphen).
- `<machine>`: Hardware or instance identifier associated with the client key (for PoC: `"laptop"`).
- `<person>`: User or account identity associated with the client key (for PoC: `"poc"`).
- `<root>`: Configured server root domain (e.g. `example.com` or `weaver.test`).

This four-level hierarchy provides unambiguous namespace isolation across different machines and users while allowing multiple distinct services on one machine.

### 4. Proof-of-Concept Key Deprecation Plan

For Milestone 1 PoC (OFF-74):
- The client signs with the development seed in `weave::identity::DEV_SECRET_KEY` (`Ed25519Signer::dev()`).
- The relay resolves keys through `weaver_server::tunnel::IdentityResolver`; the `PocResolver` implementation knows exactly one key and maps it to `("poc", "laptop")`. The same resolver is the mux `Verifier`, so authentication and authorization cannot disagree.
- `weaver-proto` carries no key material and no identity mapping (ADR 0004).

Deprecation path:
- **Milestone 2 (Enrollment & Storage):** Replace the development seed with on-disk key generation (`~/.config/weaver/keys/`) and enrollment tokens (`weave login`).
- **Milestone 3 (Multi-tenant SQLite Auth):** A store-backed `IdentityResolver` replaces `PocResolver`, adding revocation via `still_valid`.

## Consequences

- Stream 1 failure unambiguously signals service teardown, simplifying health monitoring and automated certificate deactivation.
- Supersession prevents stale or zombie connections from retaining tunnel routes when a device sleeps, reconnects, or restarts.
- Strict DNS label validation on service names ensures valid hostnames before requesting certificates or DNS updates.
