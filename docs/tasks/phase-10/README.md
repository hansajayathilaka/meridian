<!-- Copy this file to docs/tasks/phase-N/README.md. Created by /pick-next-phase (build) or
     /start-review-phase (review); the todo list is filled by /plan-phase or /plan-review-phase. -->
> **Nav:** [tracker](../README.md) · [roadmap](../../architecture/roadmap.md) · [features](../../architecture/features/)

# Phase 10 — File Transfer Stream

**Kind:** build · **Status:** planning · **Reviews phase(s):** n/a

## Goal
Ship **[T09 — File Transfer Stream](../../architecture/features/09-file-transfer.md)** (`mrd.file/1`):
resumable, integrity-verified P2P file/image transfer implemented purely as a stream type against the
T04 extension registry — **no changes to core session code allowed**. That constraint is the point: this
feature validates that "ultimate sharing platform" is an architectural property, not just a slogan.
Acceptance = a runnable demo transferring a 1 GiB file that survives being killed mid-transfer and
resumes to a verified BLAKE3 match, plus the soak-test throughput report the feature spec calls for.

## Chosen feature(s) / scope
- **T09 — File Transfer Stream** — [spec](../../architecture/features/09-file-transfer.md) · Priority
  **P2** · depends on **T04** (P2P Session Substrate, done since Phase 0 ✔) · indicative effort 2
  eng-weeks.

In scope per the spec: manifest-on-ctrl (name, size, BLAKE3 merkle root, per-file key sealed under the
ratchet), 64 KiB AEAD-per-chunk framing over a reliable-unordered channel, backpressure via
`bufferedAmount` watermarks, resume via a missing-range bitmap after redial, incremental subtree
verification, a recipient accept/reject policy hook (auto-accept images below a configurable size), an
inline TUI surface (sixel/kitty image preview where available, plus a progress UI), and multi-file
batches. Out of scope per the spec: reshare/dedup of identical ciphertext across peers (recorded as a
design follow-up, §7.2) and mailbox'd/offline file delivery (files require a live session by design;
small images may fall back to inline chat payloads ≤ 64 KiB instead).

## Dependency check
T09's only numbered dependency is **T04 — P2P Session Substrate**, done in Phase 0
([phase-0/README.md](../phase-0/README.md)) and exercised continuously since (federation, mailbox,
TUI). No other feature blocks it.

The unblocked set at this point in the tracker is actually **{T09, T10, T14}** — T07/T06 both closed
(Phases 6–9), so T14 (deps T06, T07) and T10 (deps T05, T06) are technically pickable too. T09 is chosen
over both:
- **Priority tier.** The feature specs carry explicit tiers: T09 and T10 are **P2**, T14 is **P3**
  ([09-file-transfer.md](../../architecture/features/09-file-transfer.md#l6),
  [14-selfhosting-ops-kit.md](../../architecture/features/14-selfhosting-ops-kit.md#l6)). T09 and T10
  both outrank T14 on the roadmap's own "priority order" table
  ([roadmap.md](../../architecture/roadmap.md)); between T09 and T10, Track B's own declared sequence
  (`04→05→09→10→16`) places 09 ahead of 10.
- **Critical-path test — the same one Phase 2 used to pick T06 over T08/T09.** Phase 2's README
  ([phase-2/README.md](../phase-2/README.md)) picked Feature 06 over 08/09 because "06 is the sole gate
  on Features 07, 10 and 14... Choosing 08 or 09 instead unblocks nothing new." Applying that test today:
  **T09 is the sole gate on T11** (Browser & Desktop Clients, deps "T04–T09") **and on T16** (Tier-2
  Tunnels, deps "T09"), and transitively on T15 (deps "T09, T11") and, through T11, on T12/T13. Track D
  (`17→11→12→15`) is entirely stalled on T09 right now. **T14 gates nothing** — no feature spec lists it
  as a dependency; it is a leaf in the dependency DAG.
- **T09 was deliberately deferred, never deprioritized.** The only prior mention of T09 in the tracker
  is [phase-2/README.md](../phase-2/README.md), which kept it *out* of Phase 2 purely to avoid doubling
  that phase's review surface alongside T06 — not a statement that it should wait behind T14. The
  master tracker's repeated "T14 is unblocked" notes (Phases 6–9) are momentum from discussing T14 as
  the mailbox's Track-C sibling while envelope-v2/mailbox were the active scope; they never re-examined
  the full unblocked set once T07 actually closed. Phase 8's own README caught and corrected a similar
  drift once already (T14 was *not* bundled with T07 despite earlier tracker prose implying both were
  "clear to pick" — see [phase-8/README.md](../phase-8/README.md)); this is the same kind of correction.
- **Not bundled with T10 or T14.** T09 is (mostly) a pure additive stream type — the extension registry
  (task [4.18](../phase-4/4.18-extension-registry.md)) already names T09 as an anticipated future
  consumer, and the TUI's own extension mechanism (`apps/tui/src/surface.rs`) is ready to register
  against with zero TUI-core edits. T10 (AV calls) and T14 (ops kit) share no code path with it.
  Bundling either in would violate the "one coherent, reviewable unit" principle Phase 2's own README
  used to keep T09 out of a bundle in the first place, for no dependency reason — only "both happen to
  be unblocked," which doesn't justify a bundle on its own (contrast with Phase 4's T08+T17 bundle,
  which was forced by T08 being a hard prerequisite for T17's verification screens). See "Architect
  consult" below, however: planning surfaced real substrate-completion work in `apps/core`/`apps/crypto`/
  `apps/transport` that T09 needs but that isn't file-transfer-specific — those tasks are kept separate
  from and sequenced before the actual `mrd.file/1` `StreamType` implementation, which itself still
  lands with zero diffs to any core crate.

T10 and T14 remain valid, unblocked choices for a **later** build phase — nothing here forecloses either.

## Architect consult: substrate/wire-shape decisions settled before task breakdown

Two architect consults ran during `/plan-phase`, following the Phase 8 precedent of settling wire-shape
questions before the planner breaks a feature into tasks. Full transcripts are in this phase's task
files' own "Risks / notes" sections (10.1, 10.4, 10.9); summarized here for anyone reading the phase
overview alone.

**1. The session substrate never finished driving a second stream type.** `apps/core/src/session.rs`'s
`open_stream`/`handle_ctrl` Open/Accept arms negotiate a stream over `mrd.ctrl/1` but never actually open
a second WebRTC data channel, and `pump`'s demux only recognizes the two hardcoded `CTRL_LABEL`/
`CHAT_LABEL` channels — everything else is force-decoded as a ctrl frame. `docs/api/core-api-contracts.md`
only ever claimed T04 built "the negotiation," not the data-channel/frame-dispatch machinery for a second
type, and `open_stream`'s own doc comment already anticipated "T09 is the first second stream type to
drive it." **Decision:** this is legitimate substrate-completion work, not a stream-type-authoring rule
violation — split into a dedicated substrate task (10.4, `meridian-core`, reviewed to confirm zero
file-transfer-specific logic) landing strictly before the actual `mrd.file/1` `StreamType` impl (10.6,
which must show zero diffs to `apps/core`). Fix shape: **both** sides symmetrically call
`add_data_channel` with a stream-id-derived label (matching the existing `CTRL_LABEL`/`CHAT_LABEL`
pattern), not initiator-only — confirmed against both the real webrtc-rs backend's negotiated-channel
scheme (which requires both sides to call `add_data_channel` for the channel to exist on both ends at
all) and the loopback test transport. `system-design.md`'s "the initiator opens" prose is imprecise;
task 10.12 corrects it via `/doc-sync`, no ADR needed. Planning also surfaced two related substrate
gaps with no prior name: no generic outbound `send_stream_frame`/backpressure primitive exists either
(folded into task 10.4/10.2), and `wire-protocol.md`'s documented `Resume` ctrl frame was never
implemented and can't be without the same core-leakage problem (resolved as in-stream, task 10.9).

**2. Per-stream key derivation needs a new `meridian-crypto` primitive.** `docs/api/stream-types-v1.md`
and the crypto-protocols skill already specify the target mechanism (`HKDF(ratchet_export, info =
"mrd/stream/" ‖ type ‖ sid)`) as accepted design, but `DoubleRatchet` has no export method today.
**Decision:** no new ADR needed — this implements already-accepted design, not a new crypto-architecture
decision — but mandatory `security-reviewer` sign-off is required (task 10.1, `apps/crypto`'s CLAUDE.md:
"the most security-critical crate in the tree"). Shape: a paired `encrypt_and_export`/
`decrypt_and_export` tied to the one message exchanged at stream OPEN, returning `HKDF(mk, info)` —
never `mk` itself — never a general "export current chain state" method (which would break forward
secrecy for the whole session, not just one stream).

## Tasks (todo)
<!-- Filled by /plan-phase. Status marks: [ ] pending [~] in progress [x] done [!] blocked -->
Dependency waves (full task files hold the Definition of Task detail — Goal/Scope/Deliverables/Risks/
Tests/Reviews):

**Wave 1 — independent substrate primitives**
- [x] **10.1** Ratchet HKDF-export for per-stream keys — [file](./10.1-ratchet-hkdf-export.md)
- [x] **10.2** `Transport::buffered_amount` backpressure primitive — [file](./10.2-transport-buffered-amount.md)
- [x] **10.3** Scaffold `meridian-streams` + manifest schema + BLAKE3 merkle build/verify — [file](./10.3-streams-crate-manifest-merkle.md)

**Wave 2 — substrate completion (depends on 10.1, 10.2)**
- [~] **10.4** Generalize the session substrate to drive a second stream type — [file](./10.4-session-substrate-multi-stream.md)

**Wave 3 — file-type crypto/schema pieces (parallel with 10.4; depends on 10.3)**
- [x] **10.5** Per-chunk AEAD (`k_f`, nonce = chunk index) — [file](./10.5-per-chunk-aead.md)

**Wave 4 — the `StreamType` implementation (depends on 10.3, 10.4, 10.5)**
- [ ] **10.6** `mrd.file/1` `StreamType` implementation — [file](./10.6-filestream-type-impl.md)

**Wave 5 — engines (depend on 10.6)**
- [ ] **10.7** Sender engine: chunking, backpressure, progress, multi-file batches — [file](./10.7-sender-engine.md)
- [ ] **10.8** Receiver engine: write-by-offset, incremental verification, corruption handling — [file](./10.8-receiver-engine.md)
- [ ] **10.9** Resume protocol: in-stream missing-range bitmap + redial integration (depends on 10.7, 10.8) — [file](./10.9-resume-protocol.md)

**Wave 6 — client surfaces**
- [ ] **10.10** CLI `meridian send` (depends on 10.7, 10.8, 10.9) — [file](./10.10-cli-send-command.md)
- [ ] **10.11** TUI surface: renderer + transfers pane + palette command (depends on 10.6) — [file](./10.11-tui-surface.md)

**Wave 7 — spec + docs**
- [ ] **10.12** `mrd.file/1` spec section + wire/design doc corrections (depends on 10.4, 10.6, 10.9) — [file](./10.12-spec-doc-sync.md)

**Wave 8 — test infrastructure**
- [x] **10.13** netns rig: loss/RTT injection profiles (independent, can run in Wave 1) — [file](./10.13-netns-loss-rtt-profiles.md)
- [ ] **10.14** Soak test: 1 GiB / 10 GiB transfers + throughput report (depends on 10.10, 10.13) — [file](./10.14-soak-test-throughput.md)
- [ ] **10.15** Kill/resume test automation (depends on 10.9, 10.10, 10.13) — [file](./10.15-kill-resume-automation.md)
- [ ] **10.16** Corrupted-chunk adversarial test (depends on 10.8) — [file](./10.16-corrupted-chunk-adversarial-test.md)

**Wave 9 — phase exit**
- [ ] **10.17** Phase exit: acceptance demo + third-party implementability check + doc sync (depends on all above) — [file](./10.17-phase-exit-demo.md)

## Exit criteria
All tasks `[x]`, tree green (`cargo build --workspace`, `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`), docs synced, and the feature's acceptance demo
(1 GiB / 10 GiB soak transfers on the netns rig with loss/RTT profiles, kill/resume automation) runs
end-to-end per the spec's "Working output" section, plus the reference third-party implementability
check (task 10.17). Then `/start-review-phase`.
