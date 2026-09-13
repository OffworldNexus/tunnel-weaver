# Contributing to Tunnel Weaver

Welcome to Tunnel Weaver. To keep the codebase robust, maintainable, and continuously shippable, all contributions must strictly adhere to the following rules.

## Core Engineering Rules

### 1. Nothing ships as a stub
Every command, flag, type, and endpoint that exists does what it says, today. Things a later ticket needs do not exist yet — no `todo!()`, no "arrives in M3" messages, no reserved flags, no empty enum variants, no trait methods with default `unimplemented!()`. Hooks are added by the ticket that first needs them, in the same PR as the first real implementation. The only tolerated "not real yet" is test infrastructure that exercises real code (such as a fuzz target on real frame parsing, or a CI job that runs a real `--version`).

### 2. Every ticket adds its verification to this pipeline
A ticket is done when its jobs are green on all three operating systems it targets (Linux, macOS, Windows). No test exists that CI does not run. No job may pass because it found nothing to run; every CI job must execute at least one test, target, or binary.

### 3. Every architectural decision is an ADR
Every architectural decision must be documented as an Architecture Decision Record (ADR) under `docs/decisions/`, in the same pull request as the implementation. Tickets must explicitly list the ADRs produced.

## Development Workflow

- **Trunk branch**: `develop`. All feature branches branch from and merge into `develop`.
- **Feature branch naming**: Use the Linear feature branch naming convention (e.g. `feature/off-<id>-<description>`).
- **Formatting and Linting**:
  - Code must be formatted with `cargo fmt` (configured via `rustfmt.toml` with `style_edition = "2024"`).
  - Clippy must pass cleanly without warnings: `cargo clippy --workspace --all-targets -- -D warnings`.
  - Dependencies and licenses must satisfy `cargo deny check` according to `deny.toml`.
- **Testing**:
  - Run the full test suite locally: `cargo test --workspace`.
  - On non-Linux platforms, exclude Linux-only components: `cargo test --workspace --exclude weaver-server`.
