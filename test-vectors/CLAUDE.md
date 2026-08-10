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
- `federation-v1.json` — s2s `FedFrame` body wire-encoding vectors (T06 cross-org federation).
- `c2s-v1.json` — c2s `Fetch.hint`/`RouteBody.to_hint`/federation-error-code wire-encoding vectors
  (task 3.14, review finding F20). Deliberately narrower than the full c2s frame set — see the
  vector's own `note` field and `docs/tasks/phase-3/3.14-c2s-hint-conformance-vectors.md` Scope.

`apps/crypto/tests/conformance.rs` re-derives the crypto-derivation vectors (x3dh/ratchet/envelope/
safety-numbers) from the crate's real code and asserts byte equality — a vector that only "the
generator produced" is not sufficient; this test is what fails on a spec-divergent KDF label or
wire-layout drift (see also the `X3DH_INFO`-label-divergence negative test inside
`apps/crypto/src/x3dh.rs`). `apps/proto/tests/conformance.rs` holds `c2s-v1.json` to the same
independent-re-derivation bar. `federation-v1.json` currently has no such consumer — only the
`cargo run -p xtask -- vectors && git diff --exit-code` self-consistency check in CI, which still
exercises the real `FedFrame` encode path but is a weaker proof than an independent re-derivation.
