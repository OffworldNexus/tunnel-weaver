# Agent Guidelines

## Testing

- Full suite (fast): `cargo test --workspace` (~1s, timeout 60000ms)
- Ignored e2e suite: `cargo test --workspace -- --ignored` (~1s, timeout 60000ms)
- Format check: `cargo fmt --check` (~1s, timeout 30000ms)
- Clippy: `cargo clippy --workspace --all-targets -- -D warnings` (~2s, timeout 60000ms)
- Always: quiet on success; dump failures only.
- Last measured: 2026-09-13, full suite 0s.
