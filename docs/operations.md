# Relay operations

Operational notes for a `weaver-server` relay, focused on the OFF-190/OFF-198
DNS split and certificate model. See
[ADR 0008](decisions/0008-flat-hostnames-wildcard-cert.md) for the design.

## What the relay now serves

Two domains are involved:

- the **tunnel domain** `<root>` — delegated in full to the relay, which is
  authoritative for it;
- the **admin domain** `<admin>` — the relay's own stable hostname, kept
  *outside* the tunnel delegation.

The tunnel domain:
- `https://<person>-<machine>-<service>.<root>/` — one flat one-label hostname
  per tunnel, covered by a single `[<root>, *.<root>]` certificate (DNS-01).
- Authoritative DNS for `<root>` on UDP/TCP 53.

The admin domain:
- `https://<admin>/` — the relay's own welcome/health endpoint, covered by a
  single-name certificate (HTTP-01). Because the admin zone is not delegated to
  us, its certificate can only be validated over port 80.

Cleartext HTTP on 80 serves ACME HTTP-01 challenges for the admin certificate
and redirects everything else to HTTPS. `weave start` is unchanged: it publishes
a local port and prints the URL.

## `relay_ips` and NAT

`Config.relay_ips` is the list of public addresses the relay answers with and
binds DNS to. `setup` auto-fills it from the **admin domain's** `A`/`AAAA`
(always resolvable, unlike the delegated apex), so the common case needs no
editing. It is the single source of truth for:

- the A/AAAA answers the authoritative responder gives for every in-zone name,
- the reachability self-probes, and
- the `ListenDatagram=` / `ListenStream=` lines in `weaver-server.socket`.

Behind NAT the address you can *bind* is the private interface address, while
the public address is the port-forward target. Set `relay_ips` to the **public**
addresses; `setup` binds them explicitly and the reachability probe confirms the
port-forward actually loops back. Never bind a wildcard (`0.0.0.0:53` /
`[::]:53`): it collides with the `systemd-resolved` stub on `127.0.0.53:53` and
fails with `EADDRINUSE`.

To change the addresses after install, edit the JSON in the `config` table and
restart, or re-run `setup` after updating DNS.

## Delegation

The tunnel domain is delegated to the relay's own **admin** hostname, which is
not part of the delegated zone. In one visit at your DNS provider, add:

1. `A`/`AAAA <admin> -> <relay addresses>` (the relay's public IPs).
2. `NS <root> -> <admin>.` (one flat label under `<root>` resolves to the relay).

Then run `weaver-server setup --tunnel-domain <root> --admin-domain <admin>`
(interactive `setup` prompts for both). It must reject an admin domain that is
the same as, or a subdomain of, the tunnel domain before doing anything else:
otherwise the tunnel delegation would control the admin DNS and the admin
certificate's HTTP-01 DCV.

`setup` orders **two** certificates and waits for both:

- the tunnel wildcard `[<root>, *.<root>]` via **DNS-01**, which needs the `NS`
  delegation to be live; and
- the admin host `<admin>` via **HTTP-01**, which needs inbound port 80.

`setup_complete` is persisted only after both HTTPS endpoints pass. If the `NS`
record is missing it prints the exact two records to add and exits, leaving the
responder running.

`setup` verifies delegation by querying the parent and the public recursives
(1.1.1.1, 8.8.8.8, 9.9.9.9) directly, bypassing the host resolver so a local
stub cannot mask a broken delegation. Public resolvers cache the `NS` answer, so
a just-added record may take a few minutes to appear; re-run `setup` if it
reports the record missing. A provider that blocks port 53 is a hard failure —
no proxy can hide it.


## Certificate expiry is a total outage

One tunnel certificate covers every tunnel. If renewal fails near expiry, the
relay **hard-fails**: rustls aborts the handshake rather than serving an invalid
cert, so all tunnels and the tunnel apex go down together. This is the deliberate
cost of keeping service names out of Certificate Transparency. The admin
certificate is independent: its failure only affects the relay's own endpoint.

- Alerting is systemd `sd_notify` status plus `WARN`/`ERROR` logs. Watch for
  `Wildcard certificate issuance failed` / `renewal failed` and the reported
  `retry_at`.
- The background renewal loop runs every 12 h and renews when less than a third
  of the lifetime remains. DNS-01 reuse of the local responder means renewal
  does not re-run `setup`.
- On unrecoverable expiry, check `journalctl -u weaver-server` for the ACME
  error, confirm port 53 and delegation still hold, then force a re-order:
  `weaver-server control cert order`.

## Ports

| Port | Purpose | Bound by |
|---|---|---|
| 80 | HTTP redirect | `weaver-server.socket` |
| 443 | HTTPS edge | `weaver-server.socket` |
| 53/udp, 53/tcp | Authoritative DNS | `weaver-server.socket` |

systemd owns the binds; the service runs with an empty `CapabilityBoundingSet=`.
Without socket activation (containers), DNS self-bind on 53 needs
`CAP_NET_BIND_SERVICE` or a privileged port mapping.
