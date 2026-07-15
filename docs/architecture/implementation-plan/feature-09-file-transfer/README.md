> **Nav:** [plan index](../README.md) · **Milestone M2** · [canonical spec: T09](../../features/09-file-transfer.md) · [stream-types-v1](../../../api/stream-types-v1.md) · [stream-type-authoring skill](../../../../.claude/skills/stream-type-authoring/SKILL.md)

# Feature 09 — File Transfer Stream (`mrd.file/1`)

**Milestone:** M2 · **Depends on:** Feature 04 + M0 real transport (Phase 3) · **Canonical spec:**
[T09](../../features/09-file-transfer.md).

**Goal (from spec).** Resumable, integrity-verified P2P file transfer implemented **purely as a stream
type against the T04 registry — zero core-session edits allowed**. That constraint is the point: it
validates that "ultimate sharing platform" is an architectural property. **`[ADR]`** = the stream-type
contract (must stay additive-only).

**Exit acceptance (spec §Acceptance).** Byte-perfect delivery under 1% loss / 80 ms RTT; resume never
re-sends >2% delivered data; injected corrupt chunk detected by AEAD/merkle and re-requested (never
written); a third-party engineer implements a toy `mrd.echo/1` from `stream-types-v1.md` in <1 day.

| Task | Scope | Tags | Depends on | Status |
|---|---|---|---|---|
| F09.1 | Manifest on ctrl (name, size, BLAKE3 merkle root, per-file key sealed under ratchet) | [ADR][SEC] | M2 | ☐ |
| F09.2 | 64 KiB chunking + per-chunk AEAD (nonce=index) over reliable-unordered channel | [SEC] | F09.1 | ☐ |
| F09.3 | Backpressure (bufferedAmount watermarks) + incremental subtree merkle verification | — | F09.2 | ☐ |
| F09.4 | Resume via missing-range bitmap after redial/ICE-restart | — | F09.2 | ☐ |
| F09.5 | Accept/reject policy hook + TUI progress/inline image preview + multi-file batches | — | F09.2 | ☐ |
| F09.6 | `stream-types-v1.md` `mrd.file/1` section (third-party-implementable) + `mrd.echo/1` reference check | [ADR] | F09.1 | ☐ |
| F09.7 | Soak: 1 GiB + 10 GiB on netns rig (1% loss / 80 ms) + kill/resume automation; throughput report | [ADR] | F09.4 | ☐ |

- **F09.1 [ADR][SEC]** — manifest + per-file key sealed under the ratchet; **zero core edits** (registry only). Tests: manifest round-trip; key sealing; core-crate diff is empty (CODEOWNERS-style check). DoD 3,4,6.
- **F09.2 [SEC]** — chunk AEAD, nonce=index; corrupt chunk fails AEAD. Tests: byte-perfect reassembly; tampered chunk rejected. DoD 2,4.
- **F09.3** — watermark backpressure; incremental subtree verify. Tests: no unbounded buffering; partial-tree verify. DoD 2.
- **F09.4** — missing-range bitmap resume after redial. Tests: kill mid-transfer → resume re-sends ≤2%. DoD 2.
- **F09.5** — accept/reject hook (auto-accept images <N MB), progress + sixel/kitty preview, batches. Tests: policy hook; batch ordering. DoD 4.
- **F09.6 [ADR]** — the contract doc, written for a third party; the `mrd.echo/1` <1-day reference implementation is the acceptance gate on the doc. Tests: reference impl builds against the doc alone. DoD 3,6,7.
- **F09.7 [ADR]** — the soak that gives ADR-6 (SCTP-over-DTLS) its final numbers; feeds the Phase-4 QUIC decision. Tests: 1/10 GiB soak; throughput report committed. DoD 2.

**Stream-contract note.** This is the first non-built-in stream type; R2 verifies the additive-only
property held (no `apps/core` session edits) and that the doc is genuinely third-party-implementable.
