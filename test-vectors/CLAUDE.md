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
- `federation-v1.json` — s2s `FedFrame` body wire-encoding vectors (T06 cross-org federation),
  extended in task 8.4 with an `err-mailbox-full` case (`fed_error_codes::MAILBOX_FULL`, task 8.3)
  alongside the pre-existing `err` (`NOT_FOUND`) case.
- `c2s-v1.json` — c2s `Fetch.hint`/`RouteBody.to_hint`/federation-error-code wire-encoding vectors
  (task 3.14, review finding F20). Deliberately narrower than the full c2s frame set — see the
  vector's own `note` field and `docs/tasks/phase-3/3.14-c2s-hint-conformance-vectors.md` Scope.
  Extended in task 8.4 with the T07 mailbox wire fields task 8.3 added (`RouteOk.queued`,
  `Deliver.mailbox_id`, `MailboxAck`/`MailboxAckOk`, `error_codes::MAILBOX_FULL`) — the pre-8.3
  vectors stay byte-identical (locked by
  `apps/proto/tests/conformance.rs::pre_8_3_vectors_are_byte_identical_after_8_4_regeneration`).
  Extended in task 9.8 (review finding F8) with `mailbox-ack-empty` (`MailboxAck{ids:[]}`, the
  `0x80` CBOR empty-array shape), alongside the pre-existing non-empty `mailbox-ack` vector.
- `file-transfer-v1.json` — `mrd.file/1` conformance vectors (task 11.7, review finding F7,
  Phase 11 review of Phase 10's new wire surfaces): `FileManifest` CBOR encoding (including the
  zero-chunk/empty-file convention, root = `BLAKE3(0x00)`), the BLAKE3 merkle leaf/internal-node
  construction plus `ChunkFrame` CBOR encoding (a clean power-of-two multi-leaf proof, an
  odd-leaf-count case producing a `ProofStep::Promoted` step, and a short/non-power-of-two final
  chunk), and the resume-bitmap byte layout (all-missing, all-present, and a mixed pattern crossing
  a byte boundary). The first `meridian-streams` vector file — architect-ratified as its own file,
  separate from `session-substrate-v1.json`, by owning crate/domain.
- `session-substrate-v1.json` — session-lifecycle plumbing conformance vectors (task 11.7, review
  finding F7): the per-stream HKDF-export `info` byte layout (`stream_export_info`, task 10.4,
  pinning the `sid = 0`/`sid = u64::MAX` 8-byte big-endian boundary) and
  `SignalContent::IceRestartOffer`/`IceRestartAnswer` CBOR encoding (task 10.22, ADR 0025; one
  canonical vector each plus one with an empty `ice` candidate list). Separate from
  `file-transfer-v1.json` because this is core/envelope session-substrate plumbing, not a
  `meridian-streams` file-transfer shape.

`apps/crypto/tests/conformance.rs` re-derives the crypto-derivation vectors (x3dh/ratchet/envelope/
safety-numbers) from the crate's real code and asserts byte equality — a vector that only "the
generator produced" is not sufficient; this test is what fails on a spec-divergent KDF label or
wire-layout drift (see also the `X3DH_INFO`-label-divergence negative test inside
`apps/crypto/src/x3dh.rs`). `apps/proto/tests/conformance.rs` holds `c2s-v1.json` to the same
independent-re-derivation bar, as does `apps/core/tests/stream_export_info_conformance.rs` for
`session-substrate-v1.json`'s `stream_export_info` section specifically (same
divergent-domain-tag-negative-test pattern as `x3dh.rs`). `federation-v1.json`, `file-transfer-v1.json`,
and the rest of `session-substrate-v1.json` (`SignalContent::IceRestartOffer`/`Answer`) currently have
no such consumer — only the `cargo run -p xtask -- vectors && git diff --exit-code` self-consistency
check in CI, which still exercises the real encode path but is a weaker proof than an independent
re-derivation. This is a deliberate, architect-ratified choice for ordinary public serde/CBOR shapes
already exercised by real round-trip/shape-assertion unit tests in-crate, not an oversight (see
`docs/tasks/phase-11/11.7-file-transfer-conformance-vectors.md`'s Risks/notes).
