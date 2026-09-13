# 1. License: Apache-2.0

Date: 2026-09-13

## Status

Accepted

## Context

Tunnel Weaver is an open-core tunneling and reverse proxying system designed for exposing local services to public domains with automated TLS, end-to-end authentication, and multiplexed streams.

As part of the initial architecture restart for Milestone 1:
- Transport: WebSocket Secure (WSS) on port 443 with stream multiplexing (`weaver-mux`).
- Authentication: Device keys based on an SSH-style key model.
- Edge Stack: Hyper HTTP/1.1 and H2 with `rustls-acme` automated certificates.
- Storage: Single embedded SQLite database.
- Server Platform: Systemd on Linux only.
- Client Platform: Cross-platform (`weave` on Linux, macOS, Windows).

A permissive, industry-standard open source license is required to facilitate broad adoption, clear patent grant terms, and clean integration across client and server environments.

## Decision

We license Tunnel Weaver under the Apache License, Version 2.0 (Apache-2.0).

The repository will remain private during initial development, at which point it will be published under Apache-2.0.

## Consequences

- All workspace crates (`weaver-mux`, `weaver-proto`, `weaver-server`, `weave`) and future additions are governed by Apache-2.0.
- All contributions must be submitted under the Apache-2.0 terms.
- `cargo-deny` enforces Apache-2.0 and compatible licenses across the dependency graph in CI from day one.
