# CLAUDE.md — test-vectors/ (conformance fixtures)

Scoped memory. Inherits [root](../CLAUDE.md). The byte-exact fixtures that keep one Rust core identical
across all five targets (CLI/WASM/desktop/mobile). This is the "test" memory of the repo.

## Contents
- `identity-v1.json` — `mrd1:` identity + QR conformance vectors (gates the T01 wire-critical deps).
- `x3dh-v1.json` — X3DH prekey-handshake vectors: DH legs, IKM concatenation, derived root/header
  keys (task 1.6, review finding F1).
- `ratchet-v1.json` — header-encrypted Double Ratchet transcript: chain-key/message-key
  intermediates (byte-pinned where the protocol's own entropy injection allows; see the vector's
  `note` for the determinism boundary), plus a functional header-seal/open round trip.
- `envelope-v1.json` — `MessageEnvelope` deterministic-CBOR wire-encoding vectors.
- `safety-numbers-v1.json` — safety-number/fingerprint vectors (T08).

`apps/crypto/tests/conformance.rs` is the CI gate that re-derives these from the crate's real code
and asserts byte equality — a vector that only "the generator produced" is not sufficient; this test
is what fails on a spec-divergent KDF label or wire-layout drift (see also the
`X3DH_INFO`-label-divergence negative test inside `apps/crypto/src/x3dh.rs`).

## Rules
- **Vectors are canonical, not incidental.** Every wire/format change regenerates them via
  `cargo run -p xtask -- vectors`, and every target must reproduce them **byte-for-byte**.
- **Never edit a vector by hand to make a test pass** — regenerate from the source of truth, and if the
  bytes changed, the wire version must bump and the change is reviewed (**architect** + **security-reviewer**).
- A vector diff in a PR is a wire change — treat it as such, never as noise.
- New wire-critical surfaces (new stream types, new bundle fields) ship with their own vectors.
