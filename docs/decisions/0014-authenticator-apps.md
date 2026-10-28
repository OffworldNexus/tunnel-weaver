# 14. An authenticator app is the emailed code's twin

Date: 2026-10-27

## Status

Accepted. Introduces the TOTP factor, the `totp_credential` table, the `totp` /
`totp_failed` event kinds, the `verify_totp` step, and `account.totp_key` — the
first thing this relay encrypts at rest.

## Context

The second factor was emailed, and only emailed. That is a factor a person
*receives*: it needs a working mailbox, a working provider, and a wait, every
time. An authenticator app is the same factor kept in the person's pocket, and it
removes the mailbox from the critical path of signing in.

Two things made this cheap, and one made it expensive.

Cheap: the level machinery was built for exactly this. When the emailed code
arrived (WVR-167) and the passkey after it (WVR-163, ADR 0013), the rule was
written down in `auth/proof.rs` — a new factor *adds* a proof kind and a step and
reaches them, and never re-architects the derivation. An authenticator app is the
first case that takes the rule at its word: it is not a new shape of factor at
all, it is the existing one reached another way.

Expensive: nothing in the relay was encrypted at rest, because nothing needed to
be. Passwords are Argon2id hashes, session tokens and emailed codes are SHA-256
digests, passkeys are public keys. A TOTP secret is the first secret the relay
must be able to *recover* — it has to compute a code from it — so storing it
plaintext would make the database a set of live second factors, and this ticket
had to introduce key management to avoid that.

## Decision

### The twin, not a stronger factor

A code from an app proves what an emailed code proves: that the person holds the
second factor. So it reaches the same level by the same route —
`ProofKind::Totp` joins `EmailOtp` in the same lifetime arm of `max_age_secs`,
and `AuthenticatorPath::current_level` is the emailed path's body with the kind
swapped. A code entered seconds after the password is `Certain`; the same code,
still alive, reads `Strong` once `account.confirm_window_secs` has passed. No new
level, no new comparison, nothing to keep in step.

"Strongest" is therefore *preference*, not strength: `AuthenticatorPath` is first
in `PATHS`, so among the ways up that reach the same level in the same number of
steps, the app's code is offered first and the emailed code sits behind it.

### Many apps, one row each, each with a name

`totp_credential` is one-to-many with the account, shaped like `email_identity`:
no uniqueness on `account_id`, an index for the count and the list, a cascade on
delete. An account may hold as many apps as it likes, each row with its own
secret, so revoking one device does not disturb the others.

One thing `email_identity` has is deliberately absent, and one was added. There is
no `lookup_key`, because its whole job is a global uniqueness invariant ("an
address belongs to one account") and a secret is unique by construction and never
looked up by value. There *is* a `name`, collected **before** the secret is drawn
— the enrolment dialog asks for it first — because the name is the label the
authenticator app itself displays beside the issuer: built into the URI, it
cannot be relabelled afterwards, and with several devices enrolled it is what
tells them apart both in the app and in the console. An app the person did not
name is stored as an empty string and shown as "Authenticator app"; the removal
confirmation then asks for the account's address instead, so the two surfaces
never confirm a generic label that proves nothing.

### A pending enrolment is not a factor, and is not shown

`confirmed_at` is null until a code the app produced has been verified, and the
ways up count only confirmed rows. `confirm` writes that step as used in the same
conditional update, so a code that enrolled an app cannot then sign in with it.

A pending row is invisible everywhere: the console lists confirmed apps only, and
nothing can be verified against an unfinished enrolment. What is left of one —
an abandoned dialog — is deleted by the account sweep once it is a day old
(`totp_pending_sweep`, run from `AccountSweepTask` beside the other expiry
sweeps). Only *unconfirmed* rows are ever swept: a confirmed app's secret is a
live second factor, and deleting it would be revoking something nobody asked to
revoke.

### One endpoint for the page, read through its loader

What an account signs in with — whether a password is set, its passkeys, its
authenticator apps — is one screen of the console, so it is one request:
`GET /api/account/security`. The page reads it through its route loader
(`depends('app:security')`) and every action on it invalidates that load.

This replaced two per-credential list endpoints, and it is the part that is not
about the factor at all. The passkeys list had been read by the component after
mount, so it appeared a beat late and drifted; the apps list, read the same way,
could miss a row the relay had just created (an enrolment refused or abandoned
left a pending row the page had never fetched). A page whose data is one load,
refreshed by invalidation, cannot disagree with the relay — the page shows the
answer rather than a copy of it.

### The secret is recoverable, so it is sealed

`account.totp_key` is a 32-byte key, sealed with AES-256-GCM under `ring` — the
same crate the TLS stack already uses — with the account id as associated data,
so a sealed secret copied into another account's row fails to open rather than
quietly becoming that account's second factor. The stored value is `nonce ‖
ciphertext`, hex. The plaintext secret exists in exactly one place: the response
to the enrolment that created it, which carries `Cache-Control: no-store`.

The key is generated by `setup` and by `configure`, and **repaired at boot** when
it is missing, with a warning. An install upgraded from before this ticket has no
key; refusing to serve, or leaving enrolment permanently unavailable, would make
the feature dead on every existing deployment for no reason. Losing the key is
the real hazard, and it costs the account its apps, not its way in: a secret that
cannot be opened is logged and skipped, and the emailed code still signs in.

That repair is also why `configure` had to change. It used to rebuild the account
block from `Default::default()`, which would have silently made every enrolled
secret unreadable on the first re-run — the one change in this ticket that
touches existing behaviour.

### The window, and the replay guard that makes it safe

A code is accepted for its own 30-second step and for the step either side: 90
seconds of tolerance, enough for a phone whose clock has drifted. What keeps the
extra width from being a second chance is `last_used_step`, per credential,
advanced only forward by a conditional UPDATE — so a code observed by an attacker
is refused even across a restart, and the same code cannot be submitted twice.
The step recorded is the one the code *belongs to*, not the current one, which is
what stops the window being re-entered.

Six digits behind a stolen password are guessable, so a session gets five wrong
codes (`totp::MAX_WRONG_CODES`, counted from its own `totp_failed` rows). The
allowance is per session, never per account: a guesser exhausts their own and
cannot lock the owner out, and the emailed code is a way through for both.

### Sign-in offers the best factor, and every other way is one step away

When a confirmed app exists, `POST /api/account/login` issues nothing and sends
nothing. The code step asks for the first *code* the relay offers — the app's
code — and deliberately never defaults to a passkey: a passkey is a way *in*,
offered on the sign-in page, and someone who has typed a password and landed on
this step is finishing what they started.

Everything else the account can do is behind **"Try another way"**, a page of its
own built from the relay's own `paths` for the session — one row per way up, in
the relay's preference order. Choosing the emailed code is what *sends* it, so the
page the person lands on has a code waiting; a factor the console has never heard
of is still listed (its label is the relay's step name, tidied) and handed to the
same machinery that performs every other way up, so a later factor is usable
before anyone writes copy for it.

This is the difference from a single "email me instead" button: the ways up are
the relay's answer rather than a hand-written list of two, and the console's job
is to describe and perform them. An account with no app behaves exactly as
before — the code step asks for the emailed code, and there is nothing to choose.
The app's code endpoint shares the login budget at the edge: it is the same guess,
one factor over.

## Consequences

- A person can sign in without their mailbox, and the emailed code stays a
  permanent alternative — nothing is taken away by adding an app.
- Database backups now contain secret material that is worth stealing: the key
  lives in the config singleton, so a backup of the database alone is not enough
  to read the apps, and a backup that includes both is.
- Rotating the key has no re-encryption path. Every enrolled app stops working,
  with a log line and a working emailed code; the console shows the app still
  enrolled, because the relay cannot tell a rotated key from a tampered row
  without one.
- The count of confirmed apps joins the per-request situation read, alongside
  passkeys: one indexed count on a hot path, memoised, and a read failure reads
  as "none" rather than refusing anything.
- The console learns all of it from one endpoint (`GET /api/account/security`)
  read through the page's loader, so a page that shows what the account signs in
  with cannot hold a stale copy of it.

## Out of scope

Backup codes (WVR-164) and turning the emailed code off (WVR-165) — both are
later tickets, and this one reserves no column, route or wire shape for either.
Also out: SSO, WebAuthn as a second factor (a passkey is a way *in*), and any
push or hardware-token factor that would need a different protocol.
