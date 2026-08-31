# CLAUDE.md — tools/ (dev tooling, lints, rigs)

Scoped memory. Inherits [root](../CLAUDE.md). Developer tooling that CI mirrors — keep these and
`.github/workflows/ci.yml` in lockstep.

## Contents
- `xtask/` — the `xtask` dev-tooling crate (workspace member): codegen and conformance-vector
  generation (`cargo run -p xtask -- vectors`).
- **Invariant lints** (also run by `just lint-invariants` / CI):
  - `lint-server-no-core.sh` — `meridian-rendezvous` must not depend on `meridian-core` (ADR 0008).
  - `lint-tui-no-cli.sh` — `meridian-tui` must depend on `meridian-core` only, never `meridian-cli`
    (ADR 0020 condition 3).
  - `lint-no-serde-on-blob.sh` — no structured (de)serialization of opaque payloads server-side.
  - `lint-metrics-allowlist.sh` (+ `metrics-allowlist.txt`) — server exports only allowlisted metrics.
- `check-docs.sh` — relative-link / doc checker (run during verification).
- `netns-nat-matrix.sh`, `netns-two-lans.sh`, `testrig` — network-namespace rigs for the NAT/LAN harnesses.
- `netns-netem.sh` — `tc netem` loss/RTT injection for any existing veth pair (e.g. the rigs above),
  parameterized by loss %/RTT with a named `file-transfer` profile (1% loss / 80ms RTT, per feature
  09); file-transfer-agnostic pure test infra (task 10.13), consumed by 10.14/10.15. Directly
  executable or sourceable (`apply_netem_pair`/`clear_netem_pair`). `smoke`/`smoke-all` build their
  own throwaway veth pair and prove injected loss/RTT is actually observed via ping; gracefully skips
  (exit 0) without root or without a kernel built with `CONFIG_NET_SCH_NETEM`.

## Rules
- **A lint encodes a security invariant — don't weaken it to pass.** Fix the offending code, not the lint.
- Tooling changes that alter what CI enforces go through the **devops** agent and update CI together.
- `xtask` produces wire-critical fixtures; regenerated vectors must be byte-identical — review any diff.
