# 11. Client addressing: dial the admin host, store no relay-assigned address

Date: 2026-10-19

## Status

Accepted. Implements the client-side half of pair-and-approve.

## Context

A relay assigns every service a public hostname
(`<person>-<machine>-<service>.<root>`, ADR 0008) and serves the tunnel
WebSocket at `/_weaver/connect`. Before pairing, that endpoint lived only on the
tunnel root, so a client effectively had to know relay topology. After pairing,
the client knows exactly one thing about a relay: the admin host a person typed
and approved. That name is also the relay's own certificate name and the
`server_name` the mux handshake transcript binds.

The client is now stateful (it remembers which relays it is paired with) and
must decide what to persist. Persisting relay-assigned addresses would make the
relay's naming an API the client depends on, and would break the moment a
hostname changed.

## Decision

### The client stores only what it owns

`weave`'s durable store is one `relay` row per pairing: the **admin host** it
dials, the machine id the relay assigned, and the device-key fingerprint
authorised there — plus which relay is the default. It stores **no**
relay-assigned hostname, no tunnel root, and no service address. The relay is
the authority for those, and reports them when asked.

### Every command dials the admin host

The admin host is the only address the client knows, so it is the only address
the client dials:

- `/_weaver/connect` for the mux (both `weave start` and `weave unpair`);
- `/api/account/pair/channel` for pairing.

`/_weaver/connect` is therefore served on the admin host **as well as** the
tunnel root, so the admin host is a complete client entry point. The host the
client presents becomes the mux handshake `server_name` on both sides, binding
the transcript to the name the client actually dialled.

### The relay reports the hostname; the client never derives it

The relay answers a registration with `ControlReply::Registered { hostname }`.
The client prints the URL from that value and does not construct or cache it.
The one place a client still parses a hostname is resolving an inbound visitor
stream, which must work in the window before the reply arrives; the relay
remains the authority for what the label means.

### Admin hosts are normalised once

A host is lowercased, a trailing dot is stripped, a default `:443` is dropped,
and a pasted `https://host/` is accepted — before it is stored and before it is
dialled. The normalised value is what TCP, SNI, the `Host` header and the
transcript all use. This matters because the relay compares the presented name
against its own host byte for byte, so `Relay.Example` and `relay.example`
must not be two identities.

### The device key stays in the key agent

The client stores only the key's `p256:<hex>` fingerprint. The key itself never
leaves `tpmd`; signing is an async call to the agent (which is why the mux
`Signer::sign` is asynchronous). `--min-key-security`
(`file`/`keyring`/`sealed`/`hardware`, default `sealed`) is a floor enforced by
the agent, and provisioning below it needs explicit consent.

### Where the store lives

The store is a SeaORM-managed SQLite database in the platform's per-user data
directory (`directories`), overridable with `WEAVE_DATA_DIR` for tests and
embedding, mode 0600 on Unix. It holds no secret.

## Consequences

- The client needs DNS for the admin host only, and no relay-assigned hostname
  becomes part of the client's persistent state or its contract.
- Because the admin host is the transcript name and the admin certificate's
  name, renaming it means re-pairing; there is no alias.
- The client can be pointed at a fresh relay without knowing anything about its
  tunnel domain, which is what makes the pairing link the only out-of-band
  value a person needs.
- A relay that changed a service's hostname would still work: the client would
  print the new one on the next `weave start`.

## Out of scope

Aliases or multiple addresses per relay, relay-side guarantees about hostname
stability, client-side caching of assigned hostnames, and any client-side
record of a relay's tunnel domain.
