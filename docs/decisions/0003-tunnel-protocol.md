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

- **Control Stream (Stream 1, Client-Initiated):**
  - Immediately following authentication (`Event::Authenticated`), the client opens Stream 1 carrying `Head::Control(ControlHead::Register { service })`.
  - The relay verifies the service label, derives the public hostname, initiates certificate provisioning via `CertManager::ensure`, and replies on Stream 1 with `ControlReply::Registered { hostname }` or `ControlReply::Refused { code, message }`.
  - On success, **Stream 1 is held open for the lifetime of the service registration**. Neither side half-closes or resets it while the service is active.
  - If Stream 1 closes (FIN or RST) or the underlying connection drops, the service registration is immediately removed from the relay's routing table, and `CertManager::set_active(hostname, false)` is invoked to pause certificate renewals.

- **Data Streams (Even Streams, Server-Initiated):**
  - Each incoming visitor HTTP request on a registered hostname opens a fresh, independent even stream (2, 4, 6, ...) initiated by the relay.
  - The stream opens with `Head::Http(HttpHead)`, carrying RFC 9110 request metadata, stripped hop-by-hop headers, and appended `X-Forwarded-*` headers.
  - The visitor request body is streamed as `DATA` frames. When the request body finishes, the relay sends `FIN` (half-close).
  - The client drains the request body, dumps request information to stdout, and replies with a length-prefixed `HttpResponseHead` followed by the response body.
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
- Client authentication is pinned to hard-coded Ed25519 constants (`POC_KEY_ID`, `POC_SECRET_KEY`, `POC_PUBLIC_KEY`) in `weaver-proto::poc`.
- Identity resolution is statically mapped (`POC_KEY_ID -> ("poc", "laptop")`).

Deprecation path:
- **Milestone 2 (Enrollment & Storage):** Replace hard-coded PoC keys with on-disk key generation (`~/.config/weaver/keys/`) and enrollment tokens (`weave login`).
- **Milestone 3 (Multi-tenant SQLite Auth):** The relay replaces the static `PocVerifier` with database-backed public key lookups and revocations.
- `weaver-proto::poc` will be feature-gated or removed once dynamic device enrollment is active.

## Consequences

- Stream 1 failure unambiguously signals service teardown, simplifying health monitoring and automated certificate deactivation.
- Supersession prevents stale or zombie connections from retaining tunnel routes when a device sleeps, reconnects, or restarts.
- Strict DNS label validation on service names ensures valid hostnames before requesting certificates or DNS updates.
