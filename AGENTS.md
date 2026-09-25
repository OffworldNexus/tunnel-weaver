# Agent Guidelines

## Testing

- Full suite (fast): `cargo test --workspace` (~10s warm, ~31s after a dep change, timeout 120000ms)
- CI-strength property tests: `PROPTEST_CASES=2000 PROPTEST_RNG_SEED=67 cargo test -p weaver-mux` (~70s, timeout 300000ms)
- Ignored e2e suite: `cargo test --workspace -- --ignored` (~1s warm, timeout 60000ms)
- Format check: `cargo fmt --check` (~1s, timeout 30000ms)
- Clippy: `cargo clippy --workspace --all-targets -- -D warnings` (~5s, timeout 120000ms)
- Dependency policy: `cargo deny check` (~2s, timeout 60000ms)
- Always: quiet on success; dump failures only.
- Fuzz crate compiles: `(cd fuzz && cargo check)` (~1s, timeout 60000ms)
- Conformance (nightly / PR to develop only, needs the DO droplet): h2spec
  and Autobahn run in `.github/workflows/nightly.yml`; allow-lists live in
  `ci/conformance/*-allowlist.txt`, one case per line with a justification.
- Last measured: 2026-09-25, full suite 7.0s (warm), ignored suite 0.7s.

## Crate notes

- `weaver-server` persists state through SeaORM 2 (`src/store/`): entities in
  `store/entity/`, schema-builder migrations in `store/migration/`. Never write
  raw SQL outside `store/`; add a typed `Store` method instead. SQLite-only
  behaviour (pragmas, `VACUUM INTO`, file perms) must be gated on
  `DbBackend::Sqlite` so a future `sqlx-postgres` feature needs no code change.

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
