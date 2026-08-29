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
- **Not bundled with T10 or T14.** T09 is a pure additive stream type touching only `apps/core`'s stream
  registry plus a TUI surface — the extension registry (task
  [4.18](../phase-4/4.18-extension-registry.md)) already names T09 as an anticipated future consumer. T10
  (AV calls) and T14 (ops kit) share no code path with it. Bundling either in would violate the "one
  coherent, reviewable unit" principle Phase 2's own README used to keep T09 out of a bundle in the first
  place, for no dependency reason — only "both happen to be unblocked," which doesn't justify a bundle on
  its own (contrast with Phase 4's T08+T17 bundle, which was forced by T08 being a hard prerequisite for
  T17's verification screens).

T10 and T14 remain valid, unblocked choices for a **later** build phase — nothing here forecloses either.

## Tasks (todo)
<!-- Filled by /plan-phase. Status marks: [ ] pending [~] in progress [x] done [!] blocked -->
- [ ] **10.1** <title> — [file](./10.1-<slug>.md)

## Exit criteria
All tasks `[x]`, tree green (`cargo build --workspace`, `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`), docs synced, and the feature's acceptance demo
(1 GiB / 10 GiB soak transfers on the netns rig with loss/RTT profiles, kill/resume automation) runs
end-to-end per the spec's "Working output" section. Then `/start-review-phase`.
