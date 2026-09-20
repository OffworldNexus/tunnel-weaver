# 7. DNS strategies and wildcard certificates

Date: 2026-09-20

## Status

Proposed. Records a direction decided during OFF-75 testing; not implemented
in M1. The edge WAF (`weaver-server/src/edge/waf.rs`) is the M1 stopgap for
the exposure this ADR eventually closes.

## Context

Every hostname the relay obtains a publicly-trusted certificate for is
published to Certificate Transparency logs within seconds of issuance, and
mass scanners subscribe to those logs. During OFF-75 testing a freshly
registered `a.laptop.poc.<root>` received the standard scanner playbook
(`/.env*`, `/.git/HEAD`, traversal, framework debug endpoints) inside a
minute, with no link ever shared.

Today the relay orders **one certificate per service hostname**
(TLS-ALPN-01, lazily on registration). Consequences:

- Every service *name* is public the moment it is registered.
- Every registration pays an ACME round-trip and counts against Let's
  Encrypt's per-registered-domain rate limits.
- A visitor arriving before issuance completes is held at the TLS layer
  (ADR: strict TLS, OFF-79).

Wildcard certificates (`*.<machine>.<person>.<root>`) fix all three, but a
wildcard requires the **DNS-01** challenge, which requires the relay to be
able to publish TXT records under its own zone. That is a DNS question
before it is a certificate question.

## Decision

Two supported DNS strategies. The **second is the one to push**; the first
is the low-friction fallback for operators who will not delegate.

### Strategy A — static records at the operator's DNS provider

The operator creates, once:

```
<root>            A/AAAA  → relay
*.<root>          A/AAAA  → relay
```

Certificates stay per-hostname (TLS-ALPN-01) because the relay cannot write
TXT records. This is what M1 ships; nothing to change. Service names remain
visible in CT.

### Strategy B — delegate the zone; the relay is its own nameserver

The operator creates a **glue/delegation** at the parent:

```
<root>       NS  ns.<root>
ns.<root>    A/AAAA → relay        (glue)
```

`weaver-server` answers authoritative DNS for `<root>` on UDP/TCP 53
alongside HTTP/HTTPS:

- `A`/`AAAA` for `<root>` and any name under it → the relay's addresses.
- `TXT _acme-challenge.<name>` → served from the in-memory challenge
  registry, so **DNS-01** works for any name, including wildcards.
- `CAA` for `<root>` restricting issuance to the configured ACME CA.
- Everything else → `NXDOMAIN` / `NODATA`, with SOA/NS for the zone.

With DNS-01 available the cert model becomes:

| Name | Certificate | When |
|---|---|---|
| `<root>` | `<root>` + `*.<root>`? no — see below | eager at `setup` |
| `<machine>.<person>.<root>` | `*.<machine>.<person>.<root>` (+ the bare name) | on first registration from that machine, then cached/renewed |

Service hostnames are then **never in CT**: the log shows one wildcard per
machine. Registration no longer touches ACME at all after the first service
on a machine, so the strict-TLS hold path is hit only once per machine
lifetime.

`*.<root>` alone is not enough: a wildcard matches exactly one label, and
service hostnames have three below the root. Per-machine wildcards are the
right granularity (one identity, one cert, revocable together).

### Interaction with the rest of the roadmap

- **WAF (M1, this commit)**: stays on regardless of strategy; it removes
  the free hits but does not hide names.
- **Visitor auth (M4)**: the actual fix for "a hostname exists" being a
  problem. Wildcards make the hostname unguessable-by-CT; auth makes it
  worthless when guessed.
- **Setup (OFF-73)**: `setup` gains a DNS mode question (A: "records
  exist?" verification as today; B: "delegation exists?" verification by
  querying the parent for the NS + glue and by resolving a random probe name
  through public resolvers back to itself). Port 53 joins the reachability
  preflight in mode B.
- **Store**: the challenge registry becomes the DNS TXT source of truth;
  no new persistent state — the zone is derived from config + registry.

## Consequences

- Strategy B makes the relay a single point of DNS failure for `<root>`; it
  already is one for HTTP, so this adds no new failure domain, but
  operators should be told plainly that `<root>` resolves only while the
  relay is up.
- DNS answers must be tiny and stateless (no recursion, no zone transfers,
  rate-limit unknown names) so the server cannot be used as an amplifier.
- Both strategies must keep working: an operator can start with A and move
  to B without re-registering clients, because hostnames do not change.

## Out of scope for this ADR

Choosing a DNS library, DNSSEC, secondary nameservers, and IPv6-only
deployments. Those belong to the implementing ticket.
