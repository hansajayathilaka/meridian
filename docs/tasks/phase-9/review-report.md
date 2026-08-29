<!-- Written by /start-review-phase to docs/tasks/phase-N/review-report.md.
     /plan-review-phase reads this and turns each actionable finding into a numbered fix-task. -->
> **Nav:** [tracker](../README.md) · [phase](./README.md) · [Definition of Done](../../../CONTRIBUTING.md)

# Phase 9 — Review Report

**Reviews:** Phase 8 — Offline Ciphertext Mailbox (T07, ADR 0007), tasks 8.1–8.17 · **Date:** 2026-08-29 ·
**Reviewers:** code-reviewer, security-reviewer, architect, test-engineer

## Summary
Phase 8 is solid and matches its ADR and pre-task architect consult exactly: the mailbox is genuinely
TTL-bounded, size-capped, ciphertext-only, and deletes on acknowledged delivery. All four reviewers
independently confirmed this holds in the shipped code, not just in task-file prose — the architect
re-derived every wire-shape decision from source, the security-reviewer traced the ADR 0024 drain
sentinel through the ratchet AAD to confirm authentication doesn't weaken, and both `meridian-admin
mailbox dump` and the opacity/at-rest audit extension have real non-vacuity tests proving they'd catch
a plaintext-leak regression. The test suite is green throughout every touched crate (1027 tests, zero
failures, zero clippy/fmt/lint drift). **Zero blocking findings.**

The headline risk is the mailbox quota's check-then-write race (`mailbox_enqueue_with_quota`), already
on record as a carry-forward from tasks 8.5/8.7's own reviews. This pass re-examined it in more depth
than the original carry-forward note and found the exploitable blast radius is materially larger than
"roughly one extra envelope per concurrent racer": the local route path has no per-envelope size cap
(unlike the federated path's 1 MiB `MAX_FRAME_LEN`), no per-account connection-concurrency limit exists,
and account creation is free — so a single malicious account can burst many near-maximal-size `Route`
frames at one offline victim from multiple connections and overrun quota by concurrency × envelope size,
not by one envelope. This is now the phase's top-priority should-fix. Everything else is genuine but
narrower: three new correctness gaps in the mailbox delivery/read paths, and several coverage gaps
mirroring Phase 7's own "conformance vectors need boundary cases" lesson.

## Findings
Severity: **blocking** (must fix before next build) · **should-fix** (fix this review phase) · **nit** (optional).

| # | Severity | Area / file | Finding | Recommended fix | → Fix-task |
|---|----------|-------------|---------|-----------------|-----------|
| F1 | should-fix | `apps/rendezvous/src/store.rs:165-183` (`mailbox_enqueue_with_quota`), `apps/rendezvous/src/ws.rs::handle_route` | **Quota TOCTOU is a practically exploitable storage-exhaustion DoS against a targeted offline recipient**, not a minor race. The check (`mailbox_size_bytes_for_recipient`) and the write (`mailbox_enqueue`) are two unserialized `Store` calls with no lock/transaction spanning them, in both `MemoryStore` and `SqliteStore`. Nothing bounds the attacker's fan-out: `route_per_account_per_min` (600, `config.rs:627`) is a fixed-window rate limit, not a concurrency cap; `Registry::add` places no cap on concurrent connections per account; and — unlike the federated path, which caps `req.envelope` at `MAX_FRAME_LEN` (1 MiB) as explicit defense-in-depth — the **local** `Op::Route` path has no per-envelope size cap of its own, relying on an undocumented WebSocket framework default. A single free-to-create account opening many connections and bursting near-simultaneous, near-maximal envelopes at one offline victim can overrun `quota_mb` by concurrency × envelope size. | Serialize the check-and-enqueue per recipient (per-recipient async lock, or one atomic SQL statement/transaction with post-insert trim), and add the same per-envelope size cap to the local route path that the federated path already has. Add a concurrency-adversarial test that races N concurrent `Route`s at one offline recipient and asserts the overrun bound, re-run with large envelopes to show the current "bounded" assumption fails. | 9.1 |
| F2 | should-fix | `apps/rendezvous/src/ws.rs:220-267` (`MAILBOX_ACK_MAX_IDS`) | An oversized `MailboxAck.ids` batch (&gt;4096) is silently truncated with `MailboxAckOk{}` still returned — fails safe (unacked rows redrain, scoped-delete prevents cross-account harm, no existence oracle) but completely untested, and a full 4096-id batch plus the recipient bind is 4097 bound SQL parameters, which would itself error on a SQLite build compiled with the older `SQLITE_MAX_VARIABLE_NUMBER = 999` default. | Chunk the delete into sub-999-parameter batches rather than relying on the compiled SQLite variable limit; add a test proving an id past the cap survives (isn't deleted) and the client gets no error signal, matching the documented "fails safe" claim. | 9.2 |
| F3 | should-fix | `apps/signaling/src/client.rs:437-457` (`next_deliver`) | The client unconditionally trusts server-supplied `Deliver.mailbox_id` and later flushes it as a real `MailboxAck`, with no way to distinguish a genuine drain-originated id from one attached to an ordinary live delivery. Bounded by `mailbox_delete_by_ids`'s `(recipient_pub, id)` scoping — a buggy/malicious server can at most trick a client into acking (and thus losing redelivery of) one of its **own** genuine queued rows, not another account's — but this trust boundary is unreasoned and undocumented, unlike ADR 0024's explicit treatment of the analogous `Deliver.from` question. | Either document/accept this as a bounded trust boundary (mirroring ADR 0024's reasoning), or add client-side validation tying an acked `mailbox_id` to an actual drain event. Add a test constructing a live (non-drained) `Deliver` carrying a `mailbox_id` to probe the current behavior. | 9.3 |
| F4 | should-fix | `apps/rendezvous/src/ws.rs:90-101` | **Drain/registration race window**: `drain_mailbox` runs, then `state.registry.add(...)` registers the connection as reachable — afterward, not before. A `Route` from a third party landing in that gap finds the recipient not yet registered and falls through to `queue_to_mailbox`, even though the recipient is (in wall-clock terms) already live. That message then sits mailboxed until the recipient's *next* reconnect, silently contradicting the "deliver on reconnect" framing for a message that actually arrived after reconnect completed. | Register the connection before draining (with drain-vs-live-delivery ordering handled via a per-recipient lock/queue instead of connection-registration ordering), or re-run a tiny incremental drain immediately after `registry.add`. | 9.4 |
| F5 | should-fix | `apps/rendezvous/src/store.rs:79-87,118-124`, `store/sqlite.rs:183-196,232-241` | Mailbox reads (`mailbox_list_for_recipient`, `mailbox_size_bytes_for_recipient`) don't filter `expires_at` — only the background purge job enforces TTL. Consequence: a recipient reconnecting after TTL elapses but before the next purge tick still receives the expired envelope on drain, and expired-but-unpurged bytes count toward quota, producing spurious `mailbox_full` errors for senders. | Filter `expires_at &gt; now` in both read paths, or explicitly document/test the bounded staleness window as an accepted residual (matching how other phase-8 residuals are handled). | 9.5 |
| F6 | should-fix | `apps/rendezvous/src/store.rs::mailbox_enqueue_with_quota` (no direct unit test); `apps/rendezvous/tests/*` (only `quota_mb = 0` cases exist) | Quota's exact-at-cap boundary (`current_bytes + blob.len() &gt; quota_bytes`, strictly `&gt;`) is never exercised at any level — only the "obviously over" `quota_mb = 0` case is tested. | Add a unit test directly against `mailbox_enqueue_with_quota`: `current_bytes + blob.len() == quota_bytes` → `Queued`; `== quota_bytes + 1` → `QuotaExceeded`. | 9.6 |
| F7 | should-fix | `apps/rendezvous/src/federation/inbound.rs:294-298` (`handle_fed_route`), `apps/rendezvous/tests/federation_mailbox.rs`/`federation_route.rs` | The federated route path has a `ttl_days == 0` short-circuit mirroring the local path's, but — unlike the local path (`route_to_offline_peer_errors_when_mailbox_disabled`) — no test constructs `ttl_days: 0` for the federated path. "TTL=0 disables the store entirely" is a named feature-spec acceptance criterion; the federation boundary could silently regress with nothing to catch it. | Add a federated-path test mirroring the existing local-path `ttl_days == 0` test. | 9.7 |
| F8 | should-fix | `test-vectors/c2s-v1.json` (`mailbox-ack`), `tools/xtask/src/vectors/c2s.rs` | Conformance vectors lock only the populated `MailboxAck{ids:[1,2,3]}` shape. `MailboxAck{ids:[]}` is a real, reachable wire shape (used whenever `discard_pending_mailbox_ack` empties the accumulator before a flush) that's covered by `meridian-proto`'s own roundtrip test but not byte-locked in the conformance vector file — CLI/WASM/mobile could drift on the empty-array CBOR shape without any conformance test catching it. Direct echo of Phase 7's F7 finding ("conformance vectors cover only one canonical shape"). | Add a `mailbox-ack-empty` case to `tools/xtask/src/vectors/c2s.rs` and lock its `frame_hex`. | 9.8 |
| N1 | nit | `apps/rendezvous/src/config.rs::Config::validate` | No config-level validation for `Mailbox` (unlike `Federation`). `quota_mb = 0` with `ttl_days &gt; 0` silently makes every offline route to that org fail with `mailbox_full`, indistinguishable from "intentionally near-full" until debugged. | Add a `Mailbox::validate` following the `Federation::validate` precedent. | 9.9 |
| N2 | nit | `tools/metrics-allowlist.txt:7-8` | `meridian_mailbox_depth`/`meridian_mailbox_oldest_age_seconds` are pre-allowlisted for T14 but unregistered today — not a violation, but a reminder that when T14 implements them they must stay aggregate/server-wide, never per-recipient (which would materialize the mailbox-size-as-contact-graph signal the design otherwise avoids). | No action needed this phase; carry the constraint into T14's task file when planned. | — (carry-forward, not a fix-task) |
| N3 | nit | `apps/core/tests/eid_dedup.rs` | The Phase 7 `eid`-dedup proptest (`eid_dedup_holds_under_random_interleavings`) only drives the live path (`recv_raw`); the mailbox-drain counterpart has one deterministic duplicate test, no randomized interleavings, and no mixed live/mailbox-arrival-order cases. | Extend the proptest (or add a sibling) covering `recv_raw_mailbox` interleavings, given ADR 0024's sender-check bypass is new attack surface on this path. | 9.10 |
| N4 | nit | `apps/rendezvous/src/mailbox_purge.rs` | Only the pure `run_purge_once` is tested; the scheduled `purge_loop` wrapper (immediate-first-tick, failure-not-fatal claims) has zero coverage. | Add a `#[tokio::test(start_paused = true)]` test using `tokio::time::pause`/`advance`. | 9.10 |
| N5 | nit | `apps/rendezvous/src/store.rs` / `store/sqlite.rs` mailbox tests | Double-ack of an already-deleted same-account row (ack `[id]` twice from the same connection) is untested — likely already a silent no-op per the delete-scoping logic, but unverified. | Add a store-level test confirming the second ack is a silent no-op, not an error. | 9.10 |

## On-the-fly decisions to ratify
None. The architect review confirmed the one genuine on-the-fly architectural decision that emerged
during Phase 8 implementation — the mailbox-drain `Deliver.from` sentinel question forced by task
8.7 — was already correctly escalated and ratified as **ADR 0024** during the phase itself, not left
unratified. Task 8.6's `handle_fed_route` offline-recipient durability fix was pre-cleared by the
phase's own pre-task architect consult and is architecturally sound on independent re-assessment
(purely additive, doesn't reopen the no-`FedRouteOk` framing, doesn't touch ADR 0017's trust boundary);
it needed no separate ADR. No process gap found here — this is the mechanism working as intended.

## Coverage / test gaps
Full crate suite actually executed (not summarized from task files) is green throughout: `meridian-proto`
16/16, `meridian-rendezvous` 205/205 (+3 intentionally `#[ignore]`d), `meridian-core` 117/117,
`meridian-signaling` 1/1, `meridian-cli` 77/77, `meridian-tui` 611/611 (+1 intentionally `#[ignore]`d) —
1027 tests, zero failures, zero clippy/fmt/lint drift (`cargo fmt --check`, `clippy -D warnings` across
every touched crate, `lint-no-serde-on-blob.sh`, `lint-server-no-core.sh`, `lint-metrics-allowlist.sh`
all clean). The specific gaps are captured as F1–F8/N3–N5 above: the two already-known carry-forwards
(quota TOCTOU, `MailboxAck` truncation) remain wholly uncharacterized by any test; three narrower
boundary-case omissions (quota exact-at-cap, federated `ttl_days == 0`, empty-`ids` conformance vector)
mirror the same "boundary cases missed under a fast-moving wire-protocol phase" pattern Phase 7's F7
already predicted recurring; and the mailbox-drain path lacks the randomized-interleaving proptest
treatment Phase 7 gave the live path's `eid` dedup.

## Verdict
**Green to proceed after fix-tasks land — zero blocking findings.** T14 is not blocked on this review;
the mailbox's core invariants (TTL bound, ciphertext-only, ADR 0007/0024 conformance, dependency graph,
wire-contract discipline) all hold in the shipped code, confirmed independently by all four reviewers
against source rather than task-file claims. F1 (the quota TOCTOU's now-clarified DoS exploitability)
is the phase's top-priority should-fix and should land first; F2–F8 are independent narrower
correctness/coverage gaps; N1–N5 are optional. None require new ADRs.
