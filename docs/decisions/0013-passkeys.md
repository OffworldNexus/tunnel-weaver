# 13. Passkeys sign in, and an assertion is two proofs

Date: 2026-10-26

## Status

Accepted. Introduces the passkey ceremony, the `passkey_credential` table and
the `passkey` / `passkey_user_verification` proof kinds.

## Context

The account plane had exactly two ways in: a password, then an emailed code.
Both are things a person *knows* or *receives*, and both are replayed by anyone
who learns them. The console is where machines are enrolled and where an account
is deleted, so it is worth a credential that cannot be phished or guessed.

A passkey is that credential, and it is also a better sign-in: one gesture, no
password, no code, nothing to type. What it must not become is a third way to
get stuck. The owner of this relay asked for two things and nothing else — the
email field offering the passkey when one exists, and a button that performs the
sign-in — with an explicit fallback: the field may go if the button works.

Two constraints shaped the rest. The model already distinguished *how* a session
was proven (`Basic` → `Strong` → `Certain`) for irreversible actions, and a
passkey should sit inside it rather than beside it. And the relay is its own
identity service: there is no third party to trust and no client secret to leak.

## Decision

### The relay is the relying party

`webauthn_relying_party` builds the RP from the account plane's own config: the
relying party id is the admin domain, the origin is `account.base_url`, with no
attestation requested. A ceremony can therefore only be completed by a page this
relay served, and the trust anchor is the deployment rather than a vendor.

### One credential, one account, discoverable

A `credential_id` belongs to exactly one account for good, enforced by a
table-wide unique index rather than by a check (the check only makes the
ordinary case say the right thing). Registration asks for a **discoverable**
credential: `webauthn-rs` requests `residentKey: discouraged` by default, and a
passkey nobody is offered is a passkey people forget they have. Discoverability
is what lets an address-less ceremony pick a credential, which is what makes the
field's inline offer possible at all.

The user handle is derived, never random — it is stored on the authenticator and
comes back on every discoverable assertion, so it must be the same value every
time — and it is deliberately *not* the account id: it is a UUIDv5 of one, so
what the browser's picker shows reveals nothing actionable.

### An assertion is two proofs, and the levels are untouched

An accepted assertion writes two things:

- `passkey` — the *possession* half. It is what the emailed code proves, so it
  lives as long as the session: one passkey sign-in holds for the whole session
  rather than demanding a mid-session re-step-up.
- `passkey_user_verification` — the *presence-of-person* half, when the
  authenticator verified the person (Face ID, Touch ID, Windows Hello, a key's
  PIN). It is what a password typed moments ago proves, so it lives only for
  `account.confirm_window_secs`.

Together they make a passkey sign-in `Certain` immediately — as if the password
had been typed and the code entered — decaying to `Strong` when the second half
ages out. No new level, no exception in the derivation: the existing proof kinds
gained members and nothing else changed.

### Where the ceremonies sit in the gate

- Signing in (`passkey/begin`, `passkey/finish`) is **public**: it is the front
  door, and it is the only place an anonymous request reaches `Strong` in one
  step.
- The step-up and credential management (`passkeys`, `passkeys/{id}/remove`) ask
  for **`Strong`**, like the rest of the console.
- **Registering** a credential (`passkeys/begin`, `passkeys/finish`) asks for
  `Certain`, beside deletion. Planting a credential that signs in on its own is
  at least as lasting as deleting the account, and an unattended unlocked
  browser must not be able to do it in one click.

### One step-up pattern, for the whole console

`Certain` is asked for the same way everywhere: prove it *first* (a passkey
assertion or the password), then the modal opens, and a lapse mid-modal hands
back rather than stacking a second dialog. Account deletion and passkey
registration share that helper instead of each growing their own prompt.

### Its own budget at the edge, and it does not fail closed

The first cut charged the passkey endpoints to the password login's budget. That
was wrong on both counts, and production found it: a page load plus a couple of
attempts spends an allowance sized for password guessing, and the credential
budgets *fail closed*, so a hiccup in the budget store became an unexplained
`503` on a cryptographic gesture. Passkeys now have their own view and policy
(`account-passkey`, `account.passkey`): far looser, because there is nothing to
guess, and `Degraded` rather than `FailClosed`, because what it bounds is
unauthenticated *work*, not a secret. The fail-closed path also logs now, which
it did not before — that silence is why it took two rounds to find.

## Consequences

- A person with a passkey can sign in with one gesture, from the field's inline
  offer or the button, and can step up with it instead of a password.
- The password and emailed code remain the recovery anchor: a passkey is a way
  in, never the only one. An account that loses its passkey and its password
  still has the reset flow.
- Every ceremony is memory only — single-use handles, five minutes, swept when
  the next one starts — so a relay restart ends the ceremonies in flight and
  nothing has to be cleaned out of the store.
- Whether a passkey appears in the *field's* autofill is the password manager's
  conditional-UI support. The button is the path the relay guarantees, which is
  why the protocol is tested through it.
- A wrong or unknown credential is refused identically to a wrong password: the
  answer says nothing about which addresses hold passkeys.

## Out of scope

Attestation (an enterprise device-trust policy, not a sign-in requirement);
cross-device or synced-credential policy, which belongs to the platform;
passkeys as a *second* factor beside the password; and any third-party identity
provider.
