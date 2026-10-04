# 8. Flat hostnames and the single wildcard certificate

Date: 2026-10-04

## Status

Accepted. Implements OFF-190, amended by OFF-198 (see the amendment at the end).
Supersedes the per-machine-wildcard direction in
ADR 0007 (which was Proposed, never shipped) and corrects two of its calls:
out-of-zone answers are `REFUSED`, not `NXDOMAIN`, and DNS is a hard setup
precondition rather than an optional strategy.

## Context

The M1 model ordered **one certificate per service hostname**, lazily on
registration, so every service name appeared in Certificate Transparency and
every registration paid an ACME round-trip (ADR 0007). OFF-190 replaces that
with:

- one authoritative DNS responder in-process, and
- one wildcard certificate `[<root>, *.<root>]` ordered eagerly at `setup`, and
- a service hostname that is a **single flat label**,
  `<person>-<machine>-<service>.<root>`.

A wildcard matches exactly one label, so the flat form is a hard invariant:
`a.b.<root>` is not covered. Person and machine names cannot contain a dash, so
the label splits unambiguously at its first two dashes.

## Decision

### Certificate

Exactly two names are ever submitted to a CA, as one DNS-01 order with SAN
`[<root>, *.<root>]`. The apex serves account/registration pages and anything
outside the flat scheme; the wildcard covers every tunnel. Per-service issuance,
TLS-ALPN-01, and HTTP-01 are deleted.

The apex and wildcard authorisations share the challenge name
`_acme-challenge.<root>`, so the registry stores a **multi-value TXT rrset** for
the name (a `challenge` table keyed by `(name, value)`), not one value per name.

The certificate is one global row keyed by `<root>`; `domains.certificate_id`
points every materialized hostname at it, so `Host -> domains.name -> service`
is a single join. Renewal is central (the existing 12 h loop, `< 1/3` lifetime
left) and **atomic-swaps** the resolver entry so a renewal never black-holes
live handshakes. There is no `active_hosts` gating: the wildcard must be valid
even when every tunnel is idle.

### Blast radius

One certificate covers all tunnels, so a renewal that fails near expiry is a
**total outage** — the deliberate cost of keeping service names out of CT. On
unrecoverable expiry the relay **hard-fails** (rustls aborts the handshake)
rather than serving an invalid cert. Alerting is systemd `sd_notify` status plus
`WARN`/`ERROR` logs on issuance/renewal failure; richer paging is a follow-up.

### Authoritative DNS

`hickory-proto` drives a generative responder (no zone files, no second binary)
that reuses the SeaORM store for the challenge registry. It answers
A/AAAA/NS/CAA/SOA and DNS-01 TXT.

- **No recursion, ever.** `RA=0`.
- **Out-of-zone → `REFUSED`.** We are not authoritative for the parent, so
  NXDOMAIN would be wrong. (This corrects ADR 0007.)
- Every in-zone name resolves to the relay's addresses identically; that is the
  anti-enumeration mechanism, so unregistered names are **not** NXDOMAINed.
- TXT is answered only for live challenge names; otherwise `NODATA`.
- ANY is minimised per RFC 8482 (single HINFO); AXFR/IXFR/UPDATE/NOTIFY and
  `CH`/`version.bind` are refused.
- EDNS is minimal (echo OPT, buffer 512, `DO=0`, BADVERS on unknown version);
  no DNSSEC, no DNS Cookies, no rate limiter (deferred).
- TTLs: static records 1 h; ACME TXT 30 s; negative caching 30 s.

Port 53 is delivered exactly like 80/443: a systemd socket unit
(`ListenDatagram=` + `ListenStream=`), socket-activated, so the service keeps an
empty `CapabilityBoundingSet=`. `setup` binds an **explicit relay address**,
never a wildcard, because a wildcard would collide with the `systemd-resolved`
stub on `127.0.0.53:53`. Disabling the stub is out of scope.

### Setup

DNS is a hard precondition; there is no non-DNS mode. `setup`:

1. Verifies reachability on 80, 443, and 53 (TCP challenge-response + UDP token),
   and extends the occupancy preflight to `/proc/net/udp*` (state `07`) so the
   resolved stub is reported before the bind is attempted.
2. Verifies delegation with **explicit public-resolution queries**, not the host
   resolver (which a local stub can mask): parent `NS <root>` must return
   `<root>`; apex `A`/`AAAA` must include the relay; a fresh
   `probe-<hex>.<root>` must resolve to the relay through each public recursive.
3. Resolves the apex, compares it to the relay's own address, and requires
   self-delegation (`NS <root>` -> `<root>`).
4. Installs the units, starts the responder, triggers the wildcard order over
   the control socket only after the checks pass, waits for issuance, and only
   then persists `setup_complete = true`.

`Config` gains `relay_ips` (the machine's public IPs; auto-filled from the apex
at setup and operator-editable for NAT) and `setup_complete`. On a fresh install
the daemon serves DNS but does **not** auto-order until `setup` has signalled
that the checks passed; on every subsequent start it auto-orders as before when
the certificate is missing or expired.

## Consequences

- The relay is a single point of DNS, TLS, and HTTP failure for `<root>`; it
  already was one for HTTP, so this adds no new failure domain, but `<root>`
  resolves only while the relay is up.
- The public UDP/TCP 53 surface adds a small (≈2.5–3.5×) reflection risk and a
  real IP-reputation cost; volumetric protection is upstream, and an operator
  firewall example is expected.
- `~6` CA orders/year/domain replace per-registration issuance, so CA rate
  limits stop being a design constraint.
- Any code path that accepts a multi-label name under `<root>` must be tightened
  or the CT-privacy argument breaks.

## Out of scope

DNSSEC, DNS Cookies, a rate limiter, secondary nameservers, disabling
systemd-resolved, and automated operator paging on renewal failure.

## Amendment: admin domain split (OFF-198)

OFF-190 made the tunnel zone self-delegated (`NS <root> -> <root>`) and gave the
relay one wildcard certificate. That couples the relay's own hostname and DNS to
the delegated zone. OFF-198 splits them:

- `tunnel_domain` is the **tunnel** domain, delegated in full to the relay.
- `admin_domain` is the relay's own stable hostname, *outside* the delegation.
  `A`/`AAAA <admin>` points at the relay and `NS <root>` points at `<admin>`.

`Config::load` rejects an empty admin domain, `admin == root`, and an admin
domain nested under the tunnel domain (`admin` ends with `.<root>`). The reverse
nesting — tunnel under admin — is allowed. This is the foot-gun the split
exists to prevent: an admin domain under the delegated zone would let that zone
control the relay's own DNS and the admin certificate's DCV.

Two certificates are now issued and renewed together (the 12 h loop covers
both):

| Certificate | Names | DCV | Depends on |
|---|---|---|---|
| tunnel | `[<root>, *.<root>]` | DNS-01 | parent `NS <root> -> <admin>` |
| admin | `[<admin>]` | HTTP-01 | inbound port 80 |

The authoritative responder's `NS`/SOA MNAME is `<admin>`, and it serves CAA
(`issue`/`issuewild`) for the tunnel apex only — we do not own the admin zone and
must not publish CAA for it. `CertResolver` maps the exact admin SNI to the
admin certificate and the apex/first-label tunnel SNI to the wildcard, never
cross-matching.

Both mechanisms live behind one `ChallengeSolver` interface
(`cert/solver.rs`): `Dns01Solver` writes the `_acme-challenge.<root>` TXT digest
and `Http01Solver` writes the token/key-authorization row, each returning a
`ChallengeGuard` that withdraws its response on drop. `AcmeEngine` holds a
`SolverRegistry` and picks the solver for the offered `ChallengeType`, so it
carries no DNS- or HTTP-specific code. The `challenge` table gained a `kind`
column (`dns-01`/`http-01`) and `certificates` gained `validation`, so each
responder only ever reads its own rows and renewal can dispatch per row.

`setup` asks for both domains, validates the split first, resolves `relay_ips`
from the admin `A`/`AAAA`, verifies the `NS <root> -> <admin>` delegation, issues
both certificates, probes both HTTPS endpoints, and only then persists
`setup_complete`.

HTTPS-edge visits to a covered host call `CertManager::note_visit`, which records
a lifecycle event and (outside the existing backoff) triggers issuance when the
covering certificate is missing or inside its renewal window. This shortens the
worst case after an outage; the 12 h loop remains the floor.

