# Tunnel Weaver end-to-end BDD suite

Real browser tests for the account relay: Gherkin `.feature` files drive
Playwright's Chromium against the **real** server — the real SQLite store, the
real ALTCHA proof-of-work widget, the real HTTPS edge — booted by the
`weaver-server --example e2e_server` harness. Only email is captured in-process
instead of being sent.

## What runs

- `features/landing.feature` — the public front door presents the product and
  offers sign in / create account.
- `features/account.feature` — the full happy path (land → sign up → check
  email → verify → set password → sign in → sign out → sign in again), a generic
  wrong-password refusal, and non-disclosure of an already-registered address
  until its owner follows the verification link.

The harness prints its two origins and serves until killed:

```
E2E_BASE_URL=https://localhost:<https-port>
E2E_MAIL_URL=http://127.0.0.1:<mail-port>
```

The TLS certificate is self-signed, so Playwright runs with
`ignoreHTTPSErrors` and always uses the `https://localhost:<port>` host.

## Prerequisites

- Node.js 20+ and npm
- A Rust toolchain that can build the workspace
- The account SPA built **before** the example, because the SPA is embedded into
  the server binary at compile time (`weaver-assets` `build.rs` reads
  `frontend/build`):

  ```bash
  npm run build:spa        # cd ../frontend && npm ci && npm run build
  ```

## Run it

```bash
cd e2e
npm install
npx playwright install chromium        # add --with-deps on a bare Linux image

# build the harness example, then run the suite
npm test
```

Other scripts:

| Command              | What it does                                              |
| -------------------- | --------------------------------------------------------- |
| `npm test`           | Build the `e2e_server` example, then run Cucumber.        |
| `npm run test:ci`    | Run Cucumber only (assumes the example is already built). |
| `npm run build:spa`  | Build the SvelteKit SPA into `frontend/build`.            |
| `npm run build:example` | `cargo build -p weaver-server --example e2e_server`.   |

The World prefers the prebuilt binary at
`target/debug/examples/e2e_server`; if it is missing, it falls back to
`cargo run -p weaver-server --example e2e_server` (which builds first). Either
way the process is started once per run and terminated on exit.

## Layout

```
e2e/
├── cucumber.mjs                     # Cucumber config (paths, imports, formatter)
├── features/
│   ├── landing.feature
│   ├── account.feature
│   ├── step_definitions/
│   │   ├── common.steps.js          # shared view assertions
│   │   ├── landing.steps.js
│   │   └── account.steps.js
│   └── support/
│       ├── harness.js               # spawn/stop the server + mailbox client
│       ├── world.js                 # custom World (page, origins, mail helpers)
│       ├── hooks.js                 # BeforeAll/Before/After/AfterAll
│       ├── flow.js                  # declarative account-journey helpers
│       └── assertions.js            # loud, auto-waiting assertions
└── README.md
```

## Debugging

On a failing scenario the `After` hook attaches a full-page screenshot, the page
HTML and the current URL to the Cucumber report. Scenarios are isolated: each
gets a fresh browser context (no shared cookies/sessionStorage) and a unique
email, and the capture mailbox is cleared at scenario start.
