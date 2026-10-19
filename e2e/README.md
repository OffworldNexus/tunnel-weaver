# Tunnel Weaver end-to-end BDD suite

Real browser tests for the account relay: Gherkin `.feature` files drive
Playwright's Chromium against the **real** server — the real SQLite store, the
real ALTCHA proof-of-work widget, the real HTTPS edge — booted by the
`weaver-server --example e2e_server` harness. Only email is captured in-process
instead of being sent, and the terminal half of pairing is stood in for by the
harness.

## What runs

- `features/landing.feature` — the public front door and its calls to action.
- `features/account.feature` — sign-up through verification, sign-in and
  sign-out, a password change, the password reset round trip, and that neither
  sign-up nor reset discloses whether an address is registered.
- `features/pairing.feature` — approving and rejecting a machine, the
  sign-in and sign-up detours, a lost key keeping its machine, and someone
  else's machine.

## Prerequisites

- Node.js 20+ and pnpm (`corepack enable` supplies the pinned version)
- A Rust toolchain that can build the workspace
- The account SPA built **before** the example, because the server binary
  embeds it at compile time: `pnpm run build:spa`

## Run it

```bash
cd e2e
pnpm install
pnpm exec playwright install chromium  # add --with-deps on a bare Linux image
pnpm test                              # builds the e2e_server example, then runs Cucumber
```

`pnpm run test:ci` runs Cucumber against an already built example.

The harness prints its two origins and serves until killed:

```
E2E_BASE_URL=https://localhost:<https-port>
E2E_MAIL_URL=http://127.0.0.1:<mail-port>
```

The TLS certificate is self-signed, so Playwright ignores HTTPS errors.

## Layout

```
e2e/
├── cucumber.mjs
├── features/
│   ├── *.feature
│   ├── step_definitions/
│   │   ├── common.steps.js    # navigation, headings, links, signing in
│   │   ├── account.steps.js   # sign-up, reset, password change
│   │   └── pairing.steps.js
│   └── support/
│       ├── harness.js         # the server process, mailbox and pairing seed
│       ├── world.js
│       ├── hooks.js
│       ├── flow.js            # journey legs shared by several steps
│       └── assertions.js
└── nightly/provision.mjs      # drives a live relay's pages for the nightly
```

## Debugging

A failing scenario gets a full-page screenshot and its URL attached to the
report. Each scenario has a fresh browser context, a unique email address, and
an empty capture mailbox.
