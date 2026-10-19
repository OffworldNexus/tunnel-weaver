# 3. Tunnel protocol: stream lifetimes, supersession, hostname schema, and PoC deprecation

Date: 2026-09-16

## Status

Accepted. Amended (see the amendment at the end): the hostname schema is now
flat (ADR 0008), the control plane gained `Revoke`/`Revoked`, and the
proof-of-concept identity described in §4 has been retired.

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

## Amendment: flat hostnames, bilateral revoke, real device keys

Three of the calls above have moved on since this ADR was accepted.

**§3 Hostname schema is flat.** OFF-190/ADR 0008 replaced the four-level
`<service>.<machine>.<person>.<root>` hierarchy with a single flat label,
`<person>-<machine>-<service>.<root>`, because one wildcard certificate covers
exactly one label. Person and machine names cannot contain a dash, so the label
still splits unambiguously. §3 above is superseded; the authoritative
statement is ADR 0008. The relay's identity path still derives the hostname
from the `(person, machine, service)` tuple
(`weaver_server::tunnel::identity::derive_hostname`), so the *source* of the
name is unchanged even though its shape is.

**A second control head, `Revoke`.** The control stream carries one additional
one-shot head, `ControlHead::Revoke { proto_version }`, which deletes the
machine holding the key the connection authenticated with (its key, services
and hostnames), and one reply, `ControlReply::Revoked`. No extra proof is
needed or possible: the mux handshake already proved possession of the device
key, which is exactly the authority to withdraw it. This is what makes
`weave unpair` bilateral. The relay replies `Revoked` and the client closes;
a `KeyRevoked` close is an equivalent confirmation. The existing refusal path
is reused for a revoke that cannot be applied, so there is still exactly one
refusal schema on the control stream.

**§4 Proof-of-concept identity is retired.** The development seed and
`PocResolver` are gone from the production path. A real client holds no key at
all: pairing provisions a P-256 key inside the `tpmd` local key agent, and the
store-backed `StoreIdentityResolver` resolves `machine.key_id` (ADR 0010).
There is no development seed anywhere any more: tests inject a signer through
the client's `KeyAgent` seam, exactly as production injects tpmd. The
"Milestone 2/3" deprecation path in §4 is therefore complete, in a different
shape than predicted: enrolment is browser-approved pairing, not a token verb.
