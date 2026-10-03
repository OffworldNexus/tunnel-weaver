# Relay operations

Operational notes for a `weaver-server` relay, focused on the OFF-190 DNS and
wildcard-certificate model. See
[ADR 0008](decisions/0008-flat-hostnames-wildcard-cert.md) for the design.

## What the relay now serves

- `https://<person>-<machine>-<service>.<root>/` — one flat one-label hostname
  per tunnel, covered by a single `[<root>, *.<root>]` certificate.
- Authoritative DNS for `<root>` on UDP/TCP 53.
- Cleartext HTTP on 80 (redirect to HTTPS only).

`weave start` is unchanged: it publishes a local port and prints the URL.

## `relay_ips` and NAT

`Config.relay_ips` is the list of public addresses the relay answers with and
binds DNS to. `setup` auto-fills it from the apex `A`/`AAAA` it resolves, so the
common case needs no editing. It is the single source of truth for:

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

The relay is its own nameserver for `<root>`; delegation is self-referential.

1. Point `<root>` `A`/`AAAA` at the relay.
2. Point the `NS` records of `<root>` at `<root>` itself.

`setup` verifies both by querying the parent and public recursives directly
(1.1.1.1, 8.8.8.8, 9.9.9.9), bypassing the host resolver so a local stub cannot
mask a broken delegation. A provider that blocks port 53 is a hard failure — no
proxy can hide it.

## Certificate expiry is a total outage

One certificate covers every tunnel. If renewal fails near expiry, the relay
**hard-fails**: rustls aborts the handshake rather than serving an invalid cert,
so all tunnels and the apex go down together. This is the deliberate cost of
keeping service names out of Certificate Transparency.

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
