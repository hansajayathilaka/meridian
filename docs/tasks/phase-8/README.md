<!-- Copy this file to docs/tasks/phase-N/README.md. Created by /pick-next-phase (build) or
     /start-review-phase (review); the todo list is filled by /plan-phase or /plan-review-phase. -->
> **Nav:** [tracker](../README.md) · [roadmap](../../architecture/roadmap.md) · [features](../../architecture/features/)

# Phase 8 — Offline Ciphertext Mailbox

**Kind:** build · **Status:** planning · **Reviews phase(s):** n/a (build phase)

## Goal
Ship **[T07 — Offline Ciphertext Mailbox](../../architecture/features/07-offline-mailbox.md)**: deliver
messages to offline recipients via a TTL-bounded, size-capped, ciphertext-only mailbox on the
recipient's home rendezvous — the deliberate, loudly-disclosed exception of [ADR
0007](../../adr/0007-offline-mailbox.md), implemented with its constraints enforced in code, not policy
prose. Acceptance is the feature spec's own demo script: an offline recipient's client is stopped, three
envelopes queue at their home server, `meridian-admin mailbox dump` shows only opaque ciphertext/size/
timestamp (the "honesty demo" for threat A7), all three arrive correctly ordered and ratchet-intact on
reconnect, the mailbox empties on acknowledged delivery, and a `TTL=0` org disables the store entirely
(pure-P2P mode).

## Chosen feature(s) / scope
- **T07 — Offline Ciphertext Mailbox** — [spec](../../architecture/features/07-offline-mailbox.md) ·
  depends on T03 (E2EE Messaging, relayed — done, Phase 0) and T06 (Cross-Org Federation — done, Phase 2),
  plus the standing envelope-v2 dependency gate (done, Phase 6, closed by Phase 7's review) (all done ✔)

**T14 (Self-Hosting Ops Kit) is explicitly NOT in scope for this phase.** Its own roadmap dependency row
is "T06, T07" ([roadmap.md](../../architecture/roadmap.md) line 26) — T06 is done but T07 is exactly the
feature this phase is building, i.e. still pending, not done. The parallel-tracks section lists Track C
sequentially as `02→06→07→14` (roadmap.md line 70), not concurrent. T14's own deliverables substantively
consume T07's output (its demo shows a live "mailbox depth" Grafana panel; its backup/restore runbook is
scoped around mailbox DB contents), so there is no meaningful subset of T14 that doesn't depend on
mailbox internals this phase hasn't built yet. T14 is the next feature to pick once Phase 8 closes and
its review phase clears — not before.

## Dependency check
- **T03 (E2EE Messaging, relayed)** — done, Phase 0 (0.3).
- **T06 (Cross-Org Federation)** — done, Phase 2 (2.1–2.17), reviewed clean in Phase 3.
- **Envelope-v2 standing gate** — the mailbox may only ship once envelope v2 lands, since v1's signed
  ciphertexts sitting in a multi-day server-side mailbox is exactly the exposure v2 removes (roadmap.md's
  gate note). Done in Phase 6 (6.1–6.8), verified at its flag-day exit gate, and Phase 7's review of
  Phase 6 closed with zero blocking findings outstanding (all 6 fix-tasks landed). This is the gate
  [docs/tasks/README.md](../README.md)'s "Live carry-forwards" section already records as RESOLVED.
- **T07/T14 mailbox-PK naming note** — task 7.6 (Phase 7) already resolved a naming collision risk ahead
  of this planning pass: the mailbox's planned PK is a server-assigned `id INTEGER PK` (matching
  `one_time_prekeys.id`'s shape), deliberately independent of `MessageEnvelope::eid` — see
  [data-model.md](../../architecture/data-model.md)'s mailbox table note and
  [phase-7/7.6](../phase-7/7.6-eid-mailbox-naming-collision-note.md). `/plan-phase` should treat this as
  already decided, not re-litigate it.
- No other open dependency blocks this phase. The Phase-1 adversarial frontier and the remaining unowned
  doc-sync/zeroization residuals in [docs/tasks/README.md](../README.md)'s "Live carry-forwards" section
  are deliberately not pulled into this phase's scope — they stay available for a future `/plan-phase` if
  capacity allows.

## Tasks (todo)
<!-- Filled by /plan-phase. Status marks: [ ] pending [~] in progress [x] done [!] blocked -->
- [ ] **8.1** <title> — [file](./8.1-<slug>.md)

## Exit criteria
Phase 8 is done when every task is `[x]`, the tree is green (`cargo build --workspace`, `cargo fmt
--check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo nextest run`), docs are synced,
and the feature spec's acceptance demo runs end-to-end: TTL-bounded/size-capped mailbox delivery on
reconnect, ordered + ratchet-intact decryption of queued envelopes, deletion-on-acknowledged-delivery,
`meridian-admin mailbox dump` showing only opaque ciphertext (the A7 honesty demo), quota-exceeded
surfaced to the sender, `TTL=0` genuinely disabling the store, and it working across federation (Org A
sender → Org B mailbox). Then the next command is `/start-review-phase`.
