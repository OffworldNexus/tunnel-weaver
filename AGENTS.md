# Agent Guidelines

## Testing

- Full suite (fast): `cargo test --workspace` (~4s, timeout 60000ms)
- CI-strength property tests: `PROPTEST_CASES=2000 PROPTEST_RNG_SEED=67 cargo test -p weaver-mux` (~60s, timeout 300000ms)
- Ignored e2e suite: `cargo test --workspace -- --ignored` (~1s, timeout 60000ms)
- Format check: `cargo fmt --check` (~1s, timeout 30000ms)
- Clippy: `cargo clippy --workspace --all-targets -- -D warnings` (~5s, timeout 120000ms)
- Dependency policy: `cargo deny check` (~2s, timeout 60000ms)
- Always: quiet on success; dump failures only.
- Last measured: 2026-09-16, full suite 4s.

## Crate notes

- `weaver-mux` is sans-IO: never call `Instant::now`/`SystemTime::now` or
  any RNG inside it (clippy.toml + `#![forbid]` enforce this). Tests use
  `weaver_mux::testing` (feature `test-util`) for the fake clock, seeded
  RNG, and in-memory signers/verifier.
