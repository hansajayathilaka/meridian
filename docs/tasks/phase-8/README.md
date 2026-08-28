<!-- Copy this file to docs/tasks/phase-N/README.md. Created by /pick-next-phase (build) or
     /start-review-phase (review); the todo list is filled by /plan-phase or /plan-review-phase. -->
> **Nav:** [tracker](../README.md) · [roadmap](../../architecture/roadmap.md) · [features](../../architecture/features/)

# Phase 8 — Offline Ciphertext Mailbox

**Kind:** build · **Status:** in progress · **Reviews phase(s):** n/a (build phase)

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

## Architect consult (wire-shape decisions, settled before task breakdown)
Because T07 necessarily changes canonical wire contracts (`docs/api/wire-protocol.md`,
`rendezvous-protocol-v1.md`, `federation-protocol-v1.md`, `apps/proto`), an architect pass ran
before the planner broke the phase into tasks, so no task has to re-derive these mid-implementation:

1. **`RouteOk` gains one additive optional field, `queued: bool`** (omitted when `false` — existing
   `delivered:true` traffic stays byte-identical). Outcomes: delivered-live →
   `RouteOk{delivered:true}`; queued to mailbox → `RouteOk{delivered:false, queued:true}`;
   TTL=0-and-offline → unchanged `Err{not_connected}`; mailbox full → new `Err{mailbox_full}`
   (never a `RouteOk`). See [8.3](./8.3-wire-proto-mailbox-fields.md).
2. **Federated routing needs no `federation-protocol-v1.md` change.** `handle_fed_route` enqueuing
   on an offline recipient and returning `Ok(())` is still "silent success" — `FedRoute` stays
   fire-and-forget, "no `FedRouteOk`" stays a settled decision, not reopened. Consequence: a
   federated sender's `RouteOk` stays optimistic `{delivered:true, queued:false}` even when the
   foreign server actually queued rather than delivered live — a **widening of the already-accepted
   `ROUTE_REPLY_GRACE` false-positive residual** (federation-protocol-v1.md §2), not a new one. The
   feature spec's "queued at org-b" sender-visible message is truthfully achievable only for a
   **same-server** route; `meridian-admin mailbox dump` at the foreign org is the real proof for the
   federated case. See [8.6](./8.6-fed-route-mailbox-enqueue.md), [8.13](./8.13-cross-federation-mailbox-acceptance.md), [8.14](./8.14-phase-exit-mailbox-demo.md).
3. **Delivery-on-reconnect**: queued mail pushes as ordinary `Deliver` frames immediately after
   `AuthOk`, in `arrived_at`/`id` order. `Deliver` gains one additive optional field,
   `mailbox_id: Option<u64>` (present only for a mailbox-drain push). The stale
   `mailbox_ack{envelope_ids[]}` wire-protocol.md placeholder is corrected to `MailboxAck{ids:
   [uint]}` (mailbox row `id`s, **never** the opaque `eid` inside the blob — see the naming
   collision task 7.6 already resolved) plus a new `MailboxAckOk{}` reply. Server deletes only rows
   matching the authenticated connection's own `account_pub`. See [8.3](./8.3-wire-proto-mailbox-fields.md), [8.7](./8.7-mailbox-delivery-reconnect-ack.md).
4. **Quota**: new error code `mailbox_full` in both `error_codes` and `fed_error_codes`. Local:
   synchronous `Err{mailbox_full}` instead of queuing. Federated: `FedErr{mailbox_full}` — a
   legitimate exception to fire-and-forget, since federation-protocol-v1.md §2 already says
   "failure is reported only via `FedErr`"; no new op. See [8.5](./8.5-local-route-mailbox-enqueue.md), [8.6](./8.6-fed-route-mailbox-enqueue.md).
5. **`TTL=0`** is purely `config.mailbox.ttl_days == 0` short-circuiting to the existing
   `not_connected` path — no wire-visible difference, no new type.
6. **`eid` dedup** stays purely client-side (task 6.4's already-shipped mechanism); the mailbox's
   own server-assigned `id` plays no role in dedup, only in ack/deletion — matches task 7.6's
   resolution verbatim.
7. **No new ADR needed.** Every decision above is additive wire-shape detail inside ADR 0007's
   already-accepted mailbox scope — it touches no envelope shape (ADR 0016), no trust boundary
   (ADR 0017), and does not reopen "no `FedRouteOk`." Routed via doc updates + a `meridian-proto`
   version bump + conformance vectors, not an ADR.

## Tasks (todo)
<!-- Filled by /plan-phase. Status marks: [ ] pending [~] in progress [x] done [!] blocked -->

Task breakdown by **planner**, with an **architect** consult run first to settle the wire-shape
questions the mailbox necessarily raises (recorded in each affected task's Scope/Links). Dependency
order: storage seam (8.1–8.2) and wire types (8.3–8.4) are independent of each other and of
everything downstream; route-path integration (8.5–8.6) depends on both; delivery/ack (8.7–8.8)
depends on route-path integration; purge/X3DH/CLI/audit (8.9–8.12) depend only on storage; the
cross-federation acceptance test (8.13) and the phase-exit demo (8.14) come last.

**Wave 1 — independent**
- [x] **8.1** Mailbox store trait + in-memory impl + config surface — [file](./8.1-mailbox-store-trait-config.md)
- [x] **8.3** Wire/proto: `RouteOk.queued`, `mailbox_full`, `Deliver.mailbox_id`, `MailboxAck`/`MailboxAckOk` — [file](./8.3-wire-proto-mailbox-fields.md)

**Wave 2**
- [x] **8.2** SQLite mailbox migration + `SqliteStore` impl (depends on 8.1) — [file](./8.2-sqlite-mailbox-migration.md)
- [x] **8.4** Conformance vectors for the mailbox wire fields (depends on 8.3) — [file](./8.4-mailbox-conformance-vectors.md)

**Wave 3 — route-path integration**
- [x] **8.5** `handle_route` local mailbox enqueue, TTL/quota-aware (depends on 8.1, 8.3) — [file](./8.5-local-route-mailbox-enqueue.md)
- [x] **8.6** `handle_fed_route` mailbox enqueue on offline recipient (depends on 8.1, 8.3, 8.5) — [file](./8.6-fed-route-mailbox-enqueue.md)

**Wave 4 — delivery, ack, and independent storage-only follow-ons**
- [x] **8.7** Delivery-on-reconnect push + `MailboxAck` handling, server side (depends on 8.1, 8.2, 8.3, 8.5) — [file](./8.7-mailbox-delivery-reconnect-ack.md)
- [ ] **8.9** TTL expiry purge job (depends on 8.1, 8.2) — [file](./8.9-mailbox-ttl-purge-job.md)
- [ ] **8.11** `meridian-admin mailbox dump <pubkey>` (depends on 8.1, 8.2) — [file](./8.11-meridian-admin-mailbox-dump.md)
- [ ] **8.12** Opacity/at-rest audit extension for mailbox rows (depends on 8.2) — [file](./8.12-opacity-audit-mailbox-rows.md)

**Wave 5**
- [ ] **8.8** Client-side `MailboxAck` send + redelivery-dedup confirmation (depends on 8.7) — [file](./8.8-client-mailbox-ack-dedup.md)
- [ ] **8.10** X3DH-initial-message-via-mailbox coverage (depends on 8.5, 8.7) — [file](./8.10-x3dh-initial-via-mailbox.md)

**Wave 6 — acceptance + exit**
- [ ] **8.13** Cross-federation acceptance test: Org A → Org B mailbox → reconnect (depends on 8.6, 8.7, 8.9) — [file](./8.13-cross-federation-mailbox-acceptance.md)
- [ ] **8.14** Phase exit: full demo script + doc sync (depends on 8.1–8.13) — [file](./8.14-phase-exit-mailbox-demo.md)

## Exit criteria
Phase 8 is done when every task is `[x]`, the tree is green (`cargo build --workspace`, `cargo fmt
--check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo nextest run`), docs are synced,
and the feature spec's acceptance demo runs end-to-end: TTL-bounded/size-capped mailbox delivery on
reconnect, ordered + ratchet-intact decryption of queued envelopes, deletion-on-acknowledged-delivery,
`meridian-admin mailbox dump` showing only opaque ciphertext (the A7 honesty demo), quota-exceeded
surfaced to the sender, `TTL=0` genuinely disabling the store, and it working across federation (Org A
sender → Org B mailbox). Then the next command is `/start-review-phase`.
