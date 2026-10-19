# 10. Machine identity: one key per machine, the key is the identity

Date: 2026-10-19

## Status

Accepted. Implements the machine-identity half of pair-and-approve.

## Context

The M1 proof of concept resolved a connecting key through a hard-coded map
(`PocResolver` → `("poc", "laptop")`). The store-backed resolver that replaced
it modelled identity as three tables — `person`, `machine`, `machine_key` — with
a person owning many machines and a machine holding many keys, and keys were
enrolled by whatever code path happened to create them. None of that was tied
to an account.

Pair-and-approve introduces the account plane (signup, email verification,
login) and lets a person approve a machine in a browser. That forces explicit
answers to: what does a key identify, how many keys may a machine hold, how is
a key enrolled, and what happens to a machine's identity when its key is
replaced or revoked.

## Decision

### One account, one person

An account owns exactly one person (`person.account_id` is unique), and a
person belongs to exactly one account. Deleting the account cascades to the
person, and with it every machine, service and hostname. The person slug is the
first label of every hostname the account owns, so it is globally unique and
chosen once.

### One key per machine; the key identifies the machine

A machine belongs to one person and holds exactly **one** key: `machine.key_id`
is unique. The key alone resolves to the machine, and therefore to the person,
the account, and every hostname derived from them. There is no `machine_key`
table any more; a key is not a separate entity that can be attached or detached.
Attaching a key to an existing machine **overwrites `key_id` in place**, keeping
the machine's id, name, services and hostnames.

Authentication reads `machine.key_id` and nothing else. The mux `Verifier` and
the registry's authorization source are the same `StoreIdentityResolver`, so
who authenticates and who may register services cannot disagree (ADR 0003's
original intent, now enforced by a single unique index).

### No key history in the live path; a write-only audit log

Nothing that authorises a key reads history. The old keys a machine has held
are recorded in `machine_key_log` — one row opened when a key is attached
(`retired_at` null) and closed when it is replaced or the machine is revoked
(`retired_reason` = `replaced`/`revoked`). Two properties are deliberate:

- it has **no foreign keys**, so it outlives the machine and person it
  describes and a deleted machine does not erase its own audit trail;
- it is **write-only**: it is never consulted to authenticate, and dropping it
  would not change who a key is.

Retired rows are swept by the account sweep once they are older than
`account.key_log_retention_days` (default 365, minimum 1). The row of a
machine's current key is never dropped. The log is an audit trail, not a
rotation mechanism and not a source of truth.

### Pairing is the only enrolment path

A key becomes authorised only when a person approves it in the browser. There
is no implicit creation at authentication time. `weave pair` opens the pairing
channel, and the approval creates a machine (`Target::New`) or moves an existing
one onto a new key (`Target::Existing`, the lost-key case). Before that, the key
is unknown to the relay.

### Revocation is bilateral and key-possession-authorised

`weave unpair` authenticates with the very key it is revoking — the mux
handshake already proved possession, which is exactly the authority to withdraw
it — and sends a `Revoke` control head. The relay deletes the machine, its key,
its services and its hostnames (a cascade), closes the key log row as revoked,
and replies `Revoked`, leaving the close to the client (and closing with
`KeyRevoked` itself only if the client lingers). The client forgets the relay
only after that reply; the periodic key re-check is held off while a revoke is
in flight, so it cannot close the connection between the deletion and the
reply. If the relay instead rejects the handshake because it no longer knows
the key, the pairing was not effective and the client forgets it with a
warning. There is no one-sided unpair, no separate revocation credential, and
no way to revoke a key you do not hold.

## Consequences

- Key rotation is a first-class, name-preserving operation: a machine can be
  moved onto a new key without touching its services or hostnames, and the
  old key stops working at once because `key_id` was overwritten.
- "Which key is this" is a single unique-index lookup, so the identity path is
  one indexed read rather than a join. The cost is that a machine can never
  hold two keys at once: hardware-plus-recovery, or overlapping rotation
  windows, are not expressible.
- The audit log can be truncated without affecting authentication, and its
  lack of foreign keys means it survives the machine it documents.
- A lost key is recovered only by re-pairing the machine onto a new key, or by
  revoking it. There is no recovery of the old key itself.
- Deleting an account cascades person → machines → services → hostnames, which
  is the intended meaning of "close an account".

## Out of scope

Multiple keys per machine (recovery keys, overlapping rotation), key expiry or
scheduled rotation policy, per-key scopes or roles, and a browser-side revoke
of an already-paired machine.
