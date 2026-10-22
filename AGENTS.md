# Agent Guidelines

## Testing

- Full suite (fast): `cargo test --workspace` (~100s, timeout 240000ms)
- CI-strength property tests: `PROPTEST_CASES=2000 PROPTEST_RNG_SEED=67 cargo test -p weaver-mux` (~70s, timeout 300000ms)
- Ignored e2e suite: `cargo test --workspace -- --ignored` (~9s warm, timeout 60000ms)
- Format check: `cargo fmt --check` (~1s, timeout 30000ms)
- Clippy: `cargo clippy --workspace --all-targets -- -D warnings` (~5s, timeout 120000ms)
- Dependency policy: `cargo deny check` (~2s, timeout 60000ms)
- Always: quiet on success; dump failures only.
- Fuzz crate compiles: `(cd fuzz && cargo check)` (~1s, timeout 60000ms)
- SPA build — a **prerequisite** for any `cargo build`/`test`/`clippy` that
  compiles `weaver-server`, whose binary embeds the app (`weaver-assets/build.rs`
  hard-fails while the `account-spa` feature is on and the output is missing):
  `cd frontend && pnpm run build` (~3s, timeout 180000ms). Must exit 0 and
  externalize the bootstrap (no inline `<script>` in `build/index.html`).
- Browser BDD (Cucumber + Playwright against the real server):
  `cd e2e && pnpm test` (~23s, timeout 300000ms); one-time
  `pnpm exec playwright install chromium`. It rebuilds
  `weaver-server --example e2e_server` first, so stop any running copy of that
  binary (a live one blocks the relink with `ETXTBSY`).
- Type-check the SPA: `pnpm -C frontend run check` (svelte-check, ~10s,
  timeout 120000ms). Must report 0 errors and 0 warnings.
- Lint the SPA: `pnpm -C frontend run lint` (Prettier check + type-aware
  ESLint, ~8s, timeout 120000ms). Must report 0 errors and 0 warnings;
  `pnpm -C frontend run format` applies Prettier and the autofixable rules.
- Conformance (nightly / PR to develop only, needs the DO droplet): h2spec
  and Autobahn run in `.github/workflows/nightly.yml`; allow-lists live in
  `ci/conformance/*-allowlist.txt`, one case per line with a justification.
- Last measured: 2026-10-19, full suite 577 passed/0 failed/4 ignored, e2e 18
  scenarios/193 steps passed (43s), SPA lint and svelte-check clean.
  (Prior: 2026-10-12, 559 passed (100s) after WVR-50; 550 passed (72s).)

## Conventions

- **Fields are mandatory.** Every field — struct, database column, JSON
  payload, TypeScript type — is required and always present unless there is a
  real, stated reason for it to be absent. "It might be useful someday" and "it
  is optional in the form" are not reasons.
- **Strings are never nullable.** An empty string means "no value"; there is no
  `Option<String>`, nullable `TEXT` column, or `string | null`. Code that needs
  to know tests for emptiness.
- **Other types: rarely nullable in TypeScript, honestly optional in Rust.** In
  TS/JS, `| null` and `?:` are an untracked trap: before reaching for them,
  check whether a sensible value already says "none" (`0`, `false`, an empty
  array). In Rust, `Option<T>` (and a nullable column behind it) is fine when
  absence is a real state the compiler should make callers handle — a
  timestamp that has not happened yet, a foreign key that is legitimately
  absent — rather than a "maybe set" convenience. Strings stay non-nullable
  everywhere.

## Crate notes

- `weaver-server` persists state through SeaORM 2 (`src/store/`): entities in
  `store/entity/`, schema-builder migrations in `store/migration/`. Never write
  raw SQL outside `store/`; add a typed `Store` method instead. SQLite-only
  behaviour (pragmas, `VACUUM INTO`, file perms) must be gated on
  `DbBackend::Sqlite` so a future `sqlx-postgres` feature needs no code change.

- `weaver-assets` embeds the built account SPA (`frontend/build`) and the
  vendored ALTCHA widget into the `weaver-server` binary at compile time, and
  pre-compresses the compressible ones into gzip + zstd variants right there
  (nothing is compressed per request; the edge picks a variant from
  `Accept-Encoding` via `negotiate_encoding`). `weave` links the crate with the
  feature off and carries no SPA bytes. The embed is mandatory while
  `account-spa` is on, so build the SPA before compiling `weaver-server` (see
  Testing).

- `vision/` is a stand-alone, fully mocked SvelteKit reference application for
  the signed-in console (`cd vision && pnpm run dev`, type-check with
  `pnpm -C vision run check`). It is not embedded into `weaver-server`; it
  exists as the living UX and visual design specification for the console:
  - Role hierarchy and scoped sidebar drill-down (`super_admin → org_admin → user → machine`,
    where admin accounts own no machines or tunnels of their own).
  - Minitel hardware control language: 4-layer cut-corner `Keycap` action
    buttons, videotex inverse-video `.chips` radio/mode rails, SVG bat-handle
    `Toggle` switches, `@ark-ui/svelte` `Dialog` / `DatePicker` (with
    type-to-confirm deletion and ban-annotation modals), `layerchart`
    per-second speed graphs with 30-day `P50`/`P95` reference lines, and
    `@harshmandan/svaul` request inspection drawer with the Flux-Capacitor
    Y-junction byte diagram.
  - **Whenever new frontend or console features are developed in `frontend/`,
    use `vision/` as the reference example** for information architecture,
    interaction flows, component choices, and visual styling.

- The relay serves authoritative DNS (`src/dns/`, `hickory-proto`) for the
  tunnel domain `<root>` and one flat label beneath it. Hostnames are
  `<person>-<machine>-<service>.<root>` (`store::names`); person/machine are
  `[a-z0-9]{1,15}` with no dash so the label splits at its first two dashes. A
  single `[<root>, *.<root>]` wildcard cert (DNS-01) covers every tunnel and
  keeps service names out of CT. The relay's own `<admin>` domain is kept
  *outside* the tunnel delegation, gets its own `[<admin>]` HTTP-01 certificate,
  and is the zone's `NS`/SOA MNAME target; `Config::load` rejects an admin
  domain nested under the tunnel domain. `challenge.kind` separates DNS TXT rows
  (`dns-01`) from token rows (`http-01`); both DCV mechanisms sit behind the
  `cert::solver::ChallengeSolver` registry. See ADR 0008 and
  `docs/operations.md`.

- `weaver-mux` is sans-IO: never call `Instant::now`/`SystemTime::now` or
  any RNG inside it (clippy.toml + `#![forbid]` enforce this). Tests use
  `weaver_mux::testing` (feature `test-util`) for the fake clock, seeded
  RNG, and in-memory signers/verifier.
- Layering (ADR 0004, 0005): `weaver-mux` knows policy (`Class`,
  `Compress`), never content (no MIME, HTTP, identities). Public surface
  is minimal: an item is either used by the PoC or deleted, never hidden. `weaver-proto`
  is schema + HTTP→policy rules and holds no keys. `weaver-tokio` is the
  only event loop; binaries plug a `StreamHandler` into its `Driver`.
  Streams carry whole messages (`send`/`recv_msg`); never add a length
  prefix above the mux.
