# Agent Guidelines

## Testing

- Full suite (fast): `cargo test --workspace` (~10s warm, ~31s after a dep change, timeout 120000ms)
- CI-strength property tests: `PROPTEST_CASES=2000 PROPTEST_RNG_SEED=67 cargo test -p weaver-mux` (~70s, timeout 300000ms)
- Ignored e2e suite: `cargo test --workspace -- --ignored` (~9s warm, timeout 60000ms)
- Format check: `cargo fmt --check` (~1s, timeout 30000ms)
- Clippy: `cargo clippy --workspace --all-targets -- -D warnings` (~5s, timeout 120000ms)
- Dependency policy: `cargo deny check` (~2s, timeout 60000ms)
- Always: quiet on success; dump failures only.
- Fuzz crate compiles: `(cd fuzz && cargo check)` (~1s, timeout 60000ms)
- Conformance (nightly / PR to develop only, needs the DO droplet): h2spec
  and Autobahn run in `.github/workflows/nightly.yml`; allow-lists live in
  `ci/conformance/*-allowlist.txt`, one case per line with a justification.
- Last measured: 2026-10-04, full suite 353 passed/0 failed (ignored suite 3
  pass/skip; the 3 `#[ignore = "e2e"]` cases only build without Pebble).
  (Prior: 2026-10-02, 330 passed.)

## Crate notes

- `weaver-server` persists state through SeaORM 2 (`src/store/`): entities in
  `store/entity/`, schema-builder migrations in `store/migration/`. Never write
  raw SQL outside `store/`; add a typed `Store` method instead. SQLite-only
  behaviour (pragmas, `VACUUM INTO`, file perms) must be gated on
  `DbBackend::Sqlite` so a future `sqlx-postgres` feature needs no code change.

- The relay serves authoritative DNS (`src/dns/`, `hickory-proto`) for `<root>`
  and one flat label beneath it. Hostnames are `<person>-<machine>-<service>.<root>`
  (`store::names`); person/machine are `[a-z0-9]{1,15}` with no dash so the label
  splits at its first two dashes. A single `[<root>, *.<root>]` wildcard cert
  covers every tunnel and keeps service names out of CT; ACME is DNS-01 only and
  the challenge registry is the multi-value `challenge` table. See ADR 0008 and
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
