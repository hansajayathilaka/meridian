# CLAUDE.md — tools/ (dev tooling, lints, rigs)

Scoped memory. Inherits [root](../CLAUDE.md). Developer tooling that CI mirrors — keep these and
`.github/workflows/ci.yml` in lockstep.

## Contents
- `xtask/` — the `xtask` dev-tooling crate (workspace member): codegen and conformance-vector
  generation (`cargo run -p xtask -- vectors`).
- **Invariant lints** (also run by `just lint-invariants` / CI):
  - `lint-server-no-core.sh` — `meridian-rendezvous` must not depend on `meridian-core` (ADR 0008).
  - `lint-no-serde-on-blob.sh` — no structured (de)serialization of opaque payloads server-side.
  - `lint-metrics-allowlist.sh` (+ `metrics-allowlist.txt`) — server exports only allowlisted metrics.
- `check-docs.sh` — relative-link / doc checker (run during verification).
- `netns-nat-matrix.sh`, `netns-two-lans.sh`, `testrig` — network-namespace rigs for the NAT/LAN harnesses.

## Rules
- **A lint encodes a security invariant — don't weaken it to pass.** Fix the offending code, not the lint.
- Tooling changes that alter what CI enforces go through the **devops** agent and update CI together.
- `xtask` produces wire-critical fixtures; regenerated vectors must be byte-identical — review any diff.
