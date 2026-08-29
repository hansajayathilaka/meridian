<!-- Created by /start-review-phase. The todo list below is filled by /plan-review-phase. -->
> **Nav:** [tracker](../README.md) · [roadmap](../../architecture/roadmap.md) · [features](../../architecture/features/)

# Phase 9 — Review of Phase 8

**Kind:** review · **Status:** sweep complete, verdict recorded · **Reviews phase(s):** Phase 8 (Offline
Ciphertext Mailbox, tasks 8.1–8.17)

## Goal
Sweep everything built since the Phase-7 review for bugs, gaps, loopholes, and on-the-fly decisions
before T14 becomes pickable. Scope is Phase 8 — T07 Offline Ciphertext Mailbox (ADR 0007): the mailbox
store trait + SQLite migration, wire/proto fields (`RouteOk.queued`, `mailbox_full`,
`Deliver.mailbox_id`, `MailboxAck`/`MailboxAckOk`), route-path enqueue (local + federated), TTL purge,
delivery-on-reconnect + ack handling, `meridian-admin mailbox dump`, the opacity/at-rest audit
extension, X3DH-via-mailbox coverage, cross-federation acceptance, and the three live-demo fix-tasks
(8.15 mailbox-queued client surface, 8.16 `meridian register` prekey-secret persistence, 8.17
mailbox-ack/pending-request race).

## Chosen feature(s) / scope
- **Phase 8 — Offline Ciphertext Mailbox** (all 17 tasks, 8.1–8.13, 8.15–8.17, 8.14) —
  [phase-8/README.md](../phase-8/README.md). Diff range: `f871859` (Phase 7 close) `..` `fa634bc`
  (current `main`/this branch's base). Two merge PRs in this window: #83 (`pick-next-phase`, phase-8
  README only, no code) and #84 (all of 8.1–8.17 + the exit demo + doc sync). No untracked out-of-band
  PRs landed in this window — confirmed via `git log --merges f871859..fa634bc`, which shows only
  those two merges.

## Dependency check
Phase 8 is closed (17/17 tasks `[x]`, exit gate 8.14 passed with a full same-server + cross-federation
demo) per the master tracker. This review phase follows it per the lifecycle (`/start-review-phase`
always follows a closed build phase).

## Review sweep
Delegated in parallel, each an independent full-diff read (phase-wide diff, so single-lens agents
rather than the combined `reviewer` agent):
- **code-reviewer** — correctness, loopholes, gaps, dead ends, missing pieces, simplifications across
  the mailbox store/route-path/delivery/purge/CLI code.
- **security-reviewer** — anonymity-model "must never" list; ciphertext-only mailbox opacity (no
  plaintext/metadata leakage into stored rows, logs, or metrics); key/secret handling in the
  8.16/8.10 X3DH-via-mailbox paths.
- **architect** — ADR 0007 conformance, the settled wire-shape decisions from Phase 8's architect
  consult (`RouteOk.queued`, `Deliver.mailbox_id`, `MailboxAck`/`MailboxAckOk`, `mailbox_full`,
  federated-route framing), dependency-graph/stream-registry contracts, wire/API contract discipline.
- **test-engineer** — coverage gaps across the pyramid + adversarial harnesses for mailbox
  quota/TTL/dedup/redelivery and the two known live carry-forwards (4096-id ack cap, quota TOCTOU race).

Also carried into this sweep: the two **live carry-forwards already on record** from Phase 8's own task
reviews (not new findings, but re-examined for severity/ownership in this pass) —
- `MailboxAck`'s 4096-id cap is reachable, not merely theoretical (8.7's review).
- Mailbox quota check is a TOCTOU race under concurrent routes to the same recipient (8.5's review).

Findings, on-the-fly decisions, and coverage gaps: [review-report.md](./review-report.md). **14
findings — 0 blocking, 9 should-fix, 5 nits.** No on-the-fly decision needs `/adr` ratification — the
one genuine on-the-fly decision Phase 8 produced (the mailbox-drain `Deliver.from` sentinel question)
was already correctly escalated and ratified as ADR 0024 during the phase itself. Verdict: **green to
proceed** — T14 is not blocked; F1 (the mailbox quota TOCTOU race, reassessed by security-reviewer as
a more seriously exploitable storage-exhaustion DoS than the original carry-forward note suggested) is
the phase's top-priority should-fix.

## Tasks (todo)
<!-- Filled by /plan-review-phase. Status marks: [ ] pending [~] in progress [x] done [!] blocked -->
(populated by `/plan-review-phase` from [review-report.md](./review-report.md)'s 9 should-fix + 5 nit
findings)

## Exit criteria
All fix-tasks `[x]`, tree green, docs synced, findings closed per the report's verdict. Then:
`/pick-next-phase` for the next build phase (T14, unblocked once this review clears).
