# Relay operations

Operational notes for a `weaver-server` relay, focused on the OFF-190/OFF-198
DNS split and certificate model, plus machine pairing and the account plane.
See [ADR 0008](decisions/0008-flat-hostnames-wildcard-cert.md) for the DNS
design and [ADR 0010](decisions/0010-machine-identity.md) /
[ADR 0011](decisions/0011-client-addressing.md) for pairing.

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
- `https://<admin>/` — the relay's own welcome/health endpoint and the account
  plane (landing, sign-up, sign-in, pairing), covered by a single-name
  certificate (HTTP-01). Because the admin zone is not delegated to us, its
  certificate can only be validated over port 80.
- `wss://<admin>/_weaver/connect` — the tunnel WebSocket. It is served here as
  well as on the tunnel root, so the admin host is a complete client entry
  point: a paired client dials only the name it knows and learns its public
  hostnames from the relay.
- `wss://<admin>/api/account/pair/channel` — the machine pairing channel (see
  [Machine pairing](#machine-pairing)).

Cleartext HTTP on 80 serves ACME HTTP-01 challenges for the admin certificate
and redirects everything else to HTTPS. `weave start <service>=<target>…`
proxies local origins; it prints the public URL the relay assigned, which it
learns from the control reply rather than deriving itself.

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
- The background renewal job runs at boot, then wakes at the exact second the
  first certificate has less than a third of its lifetime left (or at the
  failed order's `retry_at`), and renews it then. DNS-01 reuse of the local responder means renewal
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

## Signing in with a passkey

An account that holds `Certain` can register a passkey from the console's
security page. The browser creates a **discoverable** credential (the
authenticator stores it, so the sign-in field can offer it with no address
typed) and the relay keeps the public half in `passkey_credential`, named after
the most recently active machine unless the person edits it. A credential id
belongs to one account for good — the table's unique index enforces it — so the
same passkey cannot be enrolled twice or re-homed.

A passkey signs in two ways, both on the sign-in page:

- **The field.** The page starts one discoverable ceremony on load and leaves
  the assertion pending against a field marked `autocomplete="username
  webauthn"`, so the browser offers the passkey inline in autofill. Whether a
  given password manager appears there is that manager's conditional-UI support,
  not the relay's.
- **The button.** "Sign in with a passkey" asks for the picker
  (`mediation: 'optional'`) and signs in with what comes back. It stands the
  field's pending request down first, because a page may have only one
  credential request in flight.

What an operator should expect:

- **An assertion is `Certain` at once and falls to `Strong`** after
  `account.confirm_window_secs` (default 300): the possession half lasts as long
  as the session, the user-verification half only as long as the confirmation
  window. The same gesture also answers a step-up in place of the password,
  which makes the account `Certain` again.
- **Ceremonies are memory only.** Single-use handles, five minutes, swept when
  the next one starts: a restart ends the ones in flight and nothing is left in
  the store.
- **They have their own budget.** `account.passkey` (default: a 300-request
  burst refilling 300 per minute). An assertion cannot be guessed, so this
  bounds unauthenticated work rather than a guessing surface, and unlike the
  credential budgets it **serves** the request when the budget store cannot
  answer, logging loudly, instead of failing closed.
- **The journal says what happened**: `Passkey registered`, `Passkey removed`,
  `Signed in with a passkey`, and `passkey_failed` on the account's auth trail.
  A `503` now names the policy that refused it.

## Machine pairing

A machine is enrolled by a person in a browser, never implicitly. The client
(`weave`) runs:

```
weave pair <admin-host> [--machine ID] [--min-key-security LEVEL] [--allow-below-floor]
```

which opens a WebSocket to the admin host at `/api/account/pair/channel`,
solves an ALTCHA proof-of-work challenge (purpose `pair`), sends the machine's
public key (the private key never leaves `tpmd`) and its target, and prints a
link:

```
https://<admin>/pair#handle=<hex>
```

The handle is a capability and rides in the URL **fragment**, so it never
reaches an access log (`Referer`) or a proxy's query log. A signed-in person
opens the link and approves or rejects on the SPA's `/pair` page. For a new
machine they confirm the machine name — and, when the account has no person
yet, the person slug — both editable proposals; for a lost key they simply
confirm that the machine moves onto the new key. On approval the CLI records
the relay locally and prints the machine it is paired as.

What an operator should expect:

- **Approval is the only enrolment path.** There is no implicit key creation at
  authentication time, and the pairing channel is unauthenticated — it is
  bounded by the proof of work, the `account-pair` request budget (default: a
  20-request burst refilling 20 per 10 minutes), a 16 KiB message cap and a
  60 s `Begin` timeout. Refusals come back as a typed `Failed { code }`.
- **A pending pairing is memory only.** It lives exactly as long as the CLI's
  channel, so a relay restart simply ends it (`LookupResponse::Gone` in the
  browser).
- **A key belongs to one machine.** A key that is already enrolled is refused
  with `AlreadyPaired`; `Existing { machine_id }` re-attaches a machine whose
  key was lost, replacing the old key in place (the machine, its name, its
  services and its hostnames all stay).
- **The client decides the target.** `weave pair` moves a known machine onto a
  new key when its own store's fingerprint no longer matches, and asks for a
  new machine otherwise; `--machine ID` overrides.
- **The device-key floor is the client's.** `--min-key-security`
  (`file`/`keyring`/`sealed`/`hardware`, default `sealed`) is enforced by the
  key agent; a weaker backend needs `--allow-below-floor`. The relay never sees
  the key.
- **Config**: `account.pair` (a `BudgetConfig`) and `abuse.altcha` (the
  challenge tuning). Neither is required; both have built-in defaults.

## Revoking a machine

`weave unpair [<admin-host>]` is **bilateral**. It authenticates with the very
device key it is revoking and sends a `Revoke` control head; the relay deletes
the machine — its key, its services and every hostname derived from them — then
answers `Revoked`. The client forgets the relay only after that reply. If the
relay rejects the handshake because it no longer knows the key, the pairing was
not effective, so the client forgets it with a warning; any other failure
(unreachable relay, dropped connection) leaves the pairing in place. The
machine name is freed, so a later pairing may propose it again. There is no
endpoint that revokes a machine for someone else; the only authority is
possession of the key.

## The key audit log

The relay keeps `machine_key_log`, an audit trail of which key a machine held
and when. A row opens when a key is attached (`retired_at` null) and closes
when it is replaced or the machine is revoked (`retired_reason` is `replaced`
or `revoked`). The table deliberately has **no foreign keys**, so the history
outlives the machine and person it describes. It is **write-only** as far as
authentication goes: nothing that authorises a key reads it; `machine.key_id`
is the only source of truth for who a key is.

Retention is swept by the account sweep (at boot, then every UTC midnight):
rows retired longer ago than `account.key_log_retention_days` (default **365**,
minimum 1) are deleted, while the row of a machine's current key is never
deleted however old it is. Set the retention to `0` and `Config::load` rejects
the config.

## Periodic jobs

Every background job is a `Task` driven by one process-wide `Scheduler` built in
`server::run` (ADR 0012); the startup log line `periodic scheduler running`
lists them by name. A task is not "run every N seconds": its
`next_tick(last_tick, now)` returns the exact Unix second it next has work
(`last_tick` is `None` at boot, so a job can catch up first), and `run(tick)`
does that work as of the scheduled `tick`, never a fresh clock reading. The
drain awaits the scheduler, and its `shutdown` pass performs the metering
task's final flush before the store closes.

| Task | Wakes at | Config |
|---|---|---|
| `usage-metering` | each epoch-aligned multiple of `usage_flush_interval_secs` (by default, the instant a minute closes) | `usage_flush_interval_secs`, `usage_retention_secs` |
| `abuse-bucket-sweep` | boot, then UTC midnight (only when abuse is enabled) | `abuse.bucket_ttl_secs` |
| `altcha-proof-sweep` | boot, then UTC midnight | — |
| `account-sweep` | boot, then UTC midnight | `account.key_log_retention_days` |
| `inactivity-sweep` | boot, then the exact second the next account is due for its warning or deletion | `account.inactive_after_secs`, `account.inactivity_warning_before_secs` |
| `cert-renewal` | boot, then the opening of the first renewal window or a failed order's retry | — |

The garbage sweeps can wait for midnight because what they reclaim is already
inert: every reader filters on expiry, and the ALTCHA proof cap only counts
unexpired markers. The former `account.sweep_interval_secs` and
`abuse.altcha.sweep_interval_secs` keys are gone; an existing config that still
sets them loads and ignores them.

Connections have their own scheduler for connection-local timers
(`visitor-byte-report` every 5 s, `sse-heartbeat` every 15 s), driven from the
connection's own `select!` rather than sleeping.

## Abandoned accounts

An account nobody uses is eventually deleted, so abandoned data does not
accumulate forever. The **inactivity sweep** is not polled: it computes, from
the store, the exact second the next account is due for its warning or its
deletion, sleeps until then, and settles every account due at that tick
(paging through them 100 at a time). It reads each account's last activity:

- the last successful sign-in, `account.last_login_at` (falling back to
  `activated_at` for an account that never signed in);
- the newest day any of its services was metered (`usage_daily`, folded, or the
  live day);
- and two "active right now" signals that always win whatever the timestamps
  say: a live browser session (`browser_session` unexpired and uninvalidated)
  and a live tunnel for any of its machines.

The last two matter because a tunnel can run for months without a console
sign-in, so an account that looks stale on paper may in fact be serving traffic.

Two knobs control the timeline. `account.inactivity_warning_before_secs`
(default **2592000**, one month) is how long before deletion the warning is
sent; `account.inactive_after_secs` (default **31536000**, twelve months) is
when the account is deleted. Both must be positive and the warning must come
first, or `Config::load` rejects the config. With the defaults an account is
warned after eleven months of idleness and deleted at twelve.

At the warning mark the relay sends **one** email to the account's own address,
linking to the ordinary sign-in page; signing in there resets the clock. The
send is recorded in `account.inactivity_warning_at`, so it is not repeated every
tick, and a later sign-in or metered minute moves the clock past it so the next
cycle can warn again. The warning is best-effort: with no mailer configured the
account is still deleted on schedule, with no warning. A send that fails (or a
deletion that fails) is retried an hour later.

At the threshold the account is removed through the very same
`Store::delete_account` operation as the "delete my account" button — no second
cascade path. Its keys are captured, the store rows are removed (invalidating
its sessions and, because the store is the routing authority, its hostnames and
keys), and its live tunnels are then closed with `KeyRevoked`. The sweep logs
the number of warnings sent, accounts deleted and failures per tick.

## Schema

All migrations were squashed into a single `m0001_init` that creates the final
schema directly. `machine_key` no longer exists; a machine holds exactly one
key in `machine.key_id` (unique). There is deliberately **no backward
compatibility and no migration path** from an earlier build: an existing relay
database must be rebuilt, and its machines re-paired. (The live relay was
rebuilt rather than migrated.) Deployment tooling that expected incrementally
applied migrations should treat the relay database as disposable before this
change lands.

Later migrations add on top of that baseline rather than squashing again:
`m0002_usage_daily` introduces the day-grain `usage_daily` rollup and the live
`usage_live` slot arrays, and `m0003_inactivity` adds `account.last_login_at`
and `account.inactivity_warning_at` for the inactivity sweep.

## The nightly

The DigitalOcean nightly drives the real product, not a bypass. `tpmd` is
installed from the pinned revision and run per-user on its `dummy` backend
(whose floor is `file`, so `weave pair` runs with `--min-key-security file`);
the account is created through the real sign-up page and verified by the real
emailed link read back through Resend's Receiving API; the machine is approved
in Chromium on the real `/pair` page; then `weave start` runs with the hostname
read from the relay's own output; and h2spec, Http11Probe and Autobahn run
through the tunnel. It needs `DIGITALOCEAN_TOKEN`, `NIGHTLY_DOMAIN` and the
Resend secrets (`RESEND_API_KEY`, `WEAVER_E2E_EMAIL`, `WEAVER_E2E_FROM`), and
fails fast when they are missing.

## Transactional email

Email is required (WVR-167). Every sign-in sends a one-time code to the
account's address, so the relay refuses to boot without a working `email` block
rather than running with the second factor unavailable.

- List the provider catalog with `weaver-server providers email`. `providers`
  alone still shows the ACME/SSL table.
- `setup` requires email after the ACME step (it is a prerequisite, not a
  choice), shows the chosen provider's guidance, gathers the verified sender and
  credentials (offering ambient env values such as `RESEND_API_KEY` when
  present), then **sends and verifies a numeric OTP** to the admin address.
  Setup cannot complete until the code is accepted.
- `configure` is headless and two-step. The first run with email flags sends the
  OTP and exits non-zero:
  `configure --email-provider resend --email-from relay@example.com --email-api-key-file /root/resend.key …`
  The second run proves it:
  `configure --email-otp 123456 …` (or `WEAVER_EMAIL_OTP`).
- Use `--email-api-key-file` rather than `--email-api-key` so keys stay out of
  shell history. `--email-endpoint` overrides the provider base URL (regional
  hosts, Mailgun EU, or a CI mock).
- Email is **required**, not optional (WVR-167): every sign-in sends a one-time
  code to the account's address, so a relay with no working provider cannot sign
  anyone in. There is no `--no-email`: a `configure` or `setup` that would leave
  the block empty is refused, and a config without one fails validation at load,
  so the daemon will not start in a state where the second factor is unavailable.
- Credentials live in the 0600 SQLite file, like the certificate keys. `status`
  reports the configured provider and sender but never a credential, `doctor`
  prints none either, and provider error output is redacted.
- `weaver-server send-a-joke ADDRESS [--email-endpoint URL]` is a hidden dev/e2e
  verb that sends the joke template through the configured provider; it exits
  non-zero with the redacted provider error on rejection. It predates the
  account email flow and survives only as a provider smoke check; nothing in the
  product or CI depends on it.

No retries, queue, bounce handling, or delivery webhooks exist: a send is
awaited, and an accepted send is a tracing event. A non-2xx provider response
becomes a typed rejection carrying the HTTP status and provider message.

