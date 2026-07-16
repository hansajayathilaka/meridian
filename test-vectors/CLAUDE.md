# CLAUDE.md — test-vectors/ (conformance fixtures)

Scoped memory. Inherits [root](../CLAUDE.md). The byte-exact fixtures that keep one Rust core identical
across all five targets (CLI/WASM/desktop/mobile). This is the "test" memory of the repo.

## Contents
- `identity-v1.json` — `mrd1:` identity + QR conformance vectors (gates the T01 wire-critical deps).
- `safety-numbers-v1.json` — safety-number/fingerprint vectors (T08).

## Rules
- **Vectors are canonical, not incidental.** Every wire/format change regenerates them via
  `cargo run -p xtask -- vectors`, and every target must reproduce them **byte-for-byte**.
- **Never edit a vector by hand to make a test pass** — regenerate from the source of truth, and if the
  bytes changed, the wire version must bump and the change is reviewed (**architect** + **security-reviewer**).
- A vector diff in a PR is a wire change — treat it as such, never as noise.
- New wire-critical surfaces (new stream types, new bundle fields) ship with their own vectors.
