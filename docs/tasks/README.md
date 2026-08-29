# Meridian — Task Tracker

The single activity list for the project. Drive work with the five commands (see the
[task-tracking skill](../../.claude/skills/task-tracking/SKILL.md)); this file is always the record.

```
Build phase:   /pick-next-phase → /plan-phase → /next-task ×N
Review phase:  /start-review-phase → /plan-review-phase → /next-task ×N (fix-tasks)
```

**Status marks:** `[ ]` pending · `[~]` in progress · `[x]` done · `[!]` blocked.
Numbering is `P.N` (phase.task). These *execution* phases differ from the *design* Phase 0–4 in
[system-design.md §11](../architecture/system-design.md) — don't conflate them.

---

## ▶ NOW / NEXT

- **NOW:** **Phase 4 (T08 + T17) is closed — 52/52 tasks done**, exit gate passed on its seventh attempt
  (4.52). Full lineage: [Phase 4's README](./phase-4/README.md#exit-criteria).
- **NOW:** **Phase 5 (review of Phase 4) closed — 14/14 fix-tasks done** (5.1–5.14; 5.14 was a genuine
  second instance of F3's bug class found by 5.3's own review round, not part of the original
  18-finding report). Every task's named reviewer(s) signed off PASS with zero blocking findings across
  the whole phase — the second consecutive phase-wide sweep this clean, after Phase 4's own seven-attempt
  exit-gate discipline. Each non-blocking should-fix a reviewer raised was either closed in the same
  commit (5.10's two coverage-gap tests, 5.13's `debug_assert`, 5.14's `export_json` fail-closed test) or
  explicitly ratified as a deliberate, documented carry-forward rather than silently dropped (5.10's
  `SIGINT`/`SIGTERM`-bypasses-the-drain residual — [phase-5/README.md](./phase-5/README.md#residual-carried-forward-by-510s-review)).
  No task's fix-shape decision (5.12's keybinding tie-break contract, 5.14's export-time-join-over-
  write-through call) was judged to need an ADR — both internal, single-crate implementation choices,
  not new components/dependencies/wire changes. Tree green (`cargo build --workspace`, `cargo fmt
  --check`, `cargo clippy --workspace --all-targets -- -D warnings` all clean). Full closure summary:
  [phase-5/README.md](./phase-5/README.md#exit-criteria).
- **NOW:** **Phase 6 (Envelope v2) is closed — 8/8 tasks done** (6.1–6.8). The per-message Ed25519
  identity-key signature is gone from `MessageEnvelope`; authentication now rests on the ratchet AEAD +
  X3DH `DH1` under the canonical v2 AAD (ADR 0016 C1–C7), with enforced/monitored SPK rotation,
  commit-on-successful-decrypt, a leading `v: 2` field, the `eid` replay-dedup key, and
  `ratchet-v2.json`/`envelope-v2.json` conformance vectors all shipped. 6.8's exit gate confirmed a
  green full-workspace build/fmt/clippy/test run, a live two-party CLI demo proving only `v: 2`
  envelopes exist on the wire, and a clean grep sweep for any remaining live-path `mrd.env/1` reference.
  Zero blocking findings across every task's review. Full closure summary:
  [6.8's Outcome](./phase-6/6.8-phase-exit-flag-day-demo.md#outcome) and its
  [demo transcript](./phase-6/6.8-demo-transcript.md). This also discharges the standing envelope-v2
  dependency gate — see "Live carry-forwards" below — so **T07 (mailbox) and T14 are now pickable**.
- **NOW:** **Phase 7 (review of Phase 6) opened — sweep complete, verdict recorded.**
  [Report](./phase-7/review-report.md): 9 findings — **1 blocking** (F1: the C5/R5 flag-day hard-reject
  path, `ChatError::UnsupportedEnvelopeVersion`, has zero test proving it actually fires — the
  enforcement code itself was independently confirmed correct by all four reviewers, so this is a
  coverage gap, not a live defect), 6 should-fix (F2: the "clean, diagnosable hard error" claim
  unverified for a genuine v1-shaped blob, which fails earlier at codec decode; F3: a newly-introduced
  un-zeroized OTK-secret discard in `commit_responder_otk`; F4: the pre-existing peeked-SPK/OTK-secret
  zeroization carry-forward, now routinely attacker-triggerable under C2, finally given an owning task;
  F5: stale v1-signature prose in `route_tamper.rs` that 6.7's doc-sync missed inside its own named
  scope; F6: `eid` dedup has no property/fuzz coverage; F7: conformance vectors cover only one canonical
  shape), 2 nits (N1: the `eid`/T07-mailbox naming collision needs an explicit note before T07 planning;
  N2: 12 stale signature-era doc sites outside 6.7's scope, still unowned). Zero on-the-fly decisions
  need `/adr` ratification — the two candidates checked (the `v:2` non-negotiation constraint, C1's
  fail-open mechanism) are both correctly scoped as implementation detail within ADR 0016's own
  accepted-residual framing. **Verdict: blocked until F1 lands, then clear for the next build phase**
  (T07/T14) — F1 is a single new test cell against already-correct code, not a design change, so this
  is not expected to meaningfully delay closure. Full report:
  [phase-7/review-report.md](./phase-7/review-report.md).
- **NOW:** **Phase 7's findings are broken into 6 numbered fix-tasks** (7.1–7.6), planned by the
  **planner** agent. F1 (blocking) + F2 pair into **7.1** (same untested flag-day hard-reject area); F3 +
  F4 pair into **7.2** (same `PrekeyVault`/responder-session secret-handling function family); F5–F7 and
  N1 each get their own task (**7.3**–**7.6**). N2 (the 12-site stale-doc sweep) was **not** converted —
  deferred to a future `/plan-phase` per the report's own verdict, since it spans many files outside a
  tight scope and touches no security-critical prose; it stays an unowned carry-forward below. No fix-task
  has a hard build-order dependency on another; 7.1 is listed first only because it's the blocking item.
  Full breakdown: [phase-7/README.md](./phase-7/README.md#tasks-todo).
- **NOW:** **4/6 Phase 7 fix-tasks done** (7.1–7.4), one `/next-task all` batch, one commit each,
  reviewed and green throughout. **7.1** (F1 blocking + F2) closed the flag-day hard-reject coverage
  gap with two new `chat_manager.rs` cells plus a one-sentence `messaging-envelope-v1.md` precision
  edit. **7.2** (F3 + F4) zeroized the discarded/peeked OTK/SPK secret copies in `chat.rs`'s
  `PrekeyVault`/responder-session code — review surfaced a residual (the copied-out `opk_secret` still
  crosses `Session::respond`/`x3dh::respond`'s pre-existing by-value signature unzeroized, out of
  7.2's declared scope) now recorded as a fresh carry-forward below rather than silently dropped.
  **7.3** (F5) fixed the two stale v1-signature comment sites in `route_tamper.rs` 6.7's doc-sync
  missed. **7.4** (F6) added a `proptest`-based property test for `eid` dedup, non-vacuity verified
  twice independently (implementer + test-engineer), both by neutralizing the real dedup guard and
  confirming a genuine, shrunk failure. Zero blocking or should-fix findings survived across all four
  tasks' review rounds. Tree green throughout (`cargo test`/`fmt`/`clippy` per touched crate).
  Task-picker's batch stopped here by design: **7.5** needs an architect sign-off on a conformance-
  vector byte-size `TODO: confirm` *before* it can start, so it wasn't cleanly unblocked for this run;
  **7.6** wasn't reached either since fix-tasks are worked in priority order. Draft PR opened carrying
  all four commits: [#82](https://github.com/hansajayathilaka/meridian/pull/82).
- **NOW:** **5/6 Phase 7 fix-tasks done** (7.1–7.4, 7.6). **7.6** (N1) resolved the `eid`/mailbox
  naming collision task-picker judged 7.5 couldn't get to first: the mailbox's planned PK is renamed
  `id INTEGER PK` (server-assigned sequential, matching `one_time_prekeys.id`'s existing shape),
  explicitly independent of `MessageEnvelope::eid` — deriving it from the envelope's `eid` would have
  required the server to decode a field out of the opaque blob it never otherwise touches, a real,
  structurally-enforced invariant (confirmed: `apps/rendezvous` doesn't even depend on the
  `meridian-envelope` crate). No ADR needed — resolves ADR 0007's own scope, doesn't invent new
  architecture. Independent architect sign-off verified every claim against source (the opaque-blob
  invariant, the T07 feature-spec dedup claim, the `one_time_prekeys.id` precedent) rather than
  trusting the stated reasoning. `docs/architecture/data-model.md` and this file's own carry-forward
  updated; `bash tools/check-docs.sh` clean.
- **NOW:** **Phase 7 (review of Phase 6) is closed — 6/6 fix-tasks done** (7.1–7.6). **7.5** (F7) closed
  the last one: an architect pre-check (this task's own required first step) decided the boundary-case
  `ct` size — 65536 bytes, matching the codebase's one existing "large payload" constant (`mrd.file/1`'s
  64 KiB chunk size) and the first CBOR length-prefix width boundary under RFC 8949 — and the prekey
  pairing (both new vectors share the already-maximal `prekey-with-opk` preamble). Two vectors
  (`ct-empty`, `ct-large`) added to `test-vectors/envelope-v2.json` via genuine `xtask` regeneration;
  the three existing vectors stay byte-identical. Independent architect review re-derived every claim
  from raw bytes rather than trusting it (confirmed the CBOR length-prefix boundary directly from the
  vector's hex, independently re-ran the regeneration itself). Zero blocking or should-fix findings
  survived any of the six tasks' review rounds across this whole phase. Tree green throughout. Draft PR
  [#82](https://github.com/hansajayathilaka/meridian/pull/82) carries all six commits.
- **NOW:** **Phase 8 (Offline Ciphertext Mailbox) opened — scope is T07 alone, not T07+T14.**
  Task-picker resolved the tracker's own apparent tension: the prior NEXT note said "T07 and T14 are
  clear to pick" because both were unblocked by the *same* envelope-v2 gate, but T14's own roadmap
  dependency row is "T06, T07" ([roadmap.md](../architecture/roadmap.md) line 26) — T07 is exactly the
  feature this phase builds, so it is pending, not done, and doesn't satisfy T14's dependency yet. Track
  C's parallel-tracks entry is sequential (`02→06→07→14`, roadmap.md line 70), and T14's own deliverables
  (mailbox-depth dashboard panel, mailbox-scoped backup runbook) substantively consume T07's output, so
  no meaningful subset of T14 is buildable in parallel. **T14 is deferred to the phase after Phase 8
  closes and its review sweep clears.** Dependency check, scope, and the full T14-deferral rationale:
  [phase-8/README.md](./phase-8/README.md).
- **NOW:** **Phase 8 planned — 14 tasks (8.1–8.14) across 6 dependency waves.** An architect consult
  ran first to settle the wire-shape questions T07 necessarily raises (`RouteOk.queued`,
  `Deliver.mailbox_id`, `MailboxAck`/`MailboxAckOk` correcting the stale `mailbox_ack{envelope_ids[]}`
  placeholder, a new `mailbox_full` error code, and the federated-route framing correction — the
  sender-visible "queued at org-b" message is only truthfully achievable for a same-server route, not
  a federated one, since `FedRoute` stays fire-and-forget with no `FedRouteOk` by settled decision);
  full record in [phase-8/README.md](./phase-8/README.md#architect-consult-wire-shape-decisions-settled-before-task-breakdown).
  No new ADR needed — every decision is additive detail inside ADR 0007's existing scope. The planner
  then broke T07 into: storage seam + wire types (8.1–8.4, independent), route-path integration
  (8.5–8.6), delivery/ack (8.7–8.8), purge/X3DH-coverage/CLI/opacity-audit (8.9–8.12, storage-only
  deps), cross-federation acceptance (8.13), and the phase-exit demo (8.14). 8.6 also closes a
  pre-existing correctness gap found along the way: `handle_fed_route` today silently drops an
  envelope to an offline federated recipient (`Ok(())` regardless of delivery) — T07 makes that
  durable instead of lossy. Full breakdown: [phase-8/README.md](./phase-8/README.md#tasks-todo).
- **NOW:** **Phase 8 (Offline Ciphertext Mailbox) closed — 17/17 tasks done** (8.1–8.13, 8.15–8.17;
  8.14 was the phase-exit demo + doc sync). Three fix-tasks (8.15, 8.16, 8.17) were opened and landed
  mid-phase after 8.14's live demo prep found real gaps — a client-visible copy gap for the
  optimistic-ack framing (8.15), `meridian register` discarding its own published prekey secrets
  (8.16), and mailbox-drained messages silently lost when they arrived before a first-contact request
  was accepted (8.17) — each fixed, reviewed PASS with zero blocking findings, and landed as its own
  commit before the exit demo was re-run clean. Full acceptance demo (same-server + cross-federation,
  with the sender-optimistic-ack framing correction demonstrated live) ran end-to-end; transcript:
  [phase-8/8.14-demo-transcript.md](./phase-8/8.14-demo-transcript.md). Tree green throughout
  (`cargo build --workspace`, `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D
  warnings`, full test suite — 1125 tests across 112 binaries, zero failures). Full closure summary:
  [phase-8/README.md](./phase-8/README.md#exit-criteria).
- **NOW:** **Phase 9 (review of Phase 8) opened — sweep complete, verdict recorded.**
  [Report](./phase-9/review-report.md): 14 findings — **0 blocking**, 9 should-fix (F1–F8, N3–N5 folded
  as fix-tasks 9.1–9.10), 5 nits (N1, N2 not converted — see below). Diff range `f871859` (Phase 7
  close) `..` `fa634bc` (current `main`); confirmed via `git log --merges` that only PR #83
  (`pick-next-phase`, README-only) and PR #84 (all of 8.1–8.17) landed in this window — no untracked
  out-of-band PRs. All four reviewers confirmed the mailbox's core invariants (TTL-bounded,
  ciphertext-only, deletion-on-ack, ADR 0007/0024 conformance, clean dependency graph, wire-contract
  discipline) hold in the shipped code, verified against source rather than task-file claims — full
  crate suite green throughout (1027 tests, zero failures, zero clippy/fmt/lint drift). The headline
  finding: **F1**, the mailbox quota check-then-write race already on record as a carry-forward from
  tasks 8.5/8.7, was re-examined in more depth than the original note and found more seriously
  exploitable than "roughly one extra envelope per concurrent racer" — the local route path has no
  per-envelope size cap (unlike the federated path's 1 MiB `MAX_FRAME_LEN`) and no per-account
  connection-concurrency limit exists, so a single free-to-create account can overrun `quota_mb` by
  concurrency × envelope size via a burst of near-maximal `Route` frames. F2–F8 are narrower,
  independent correctness/coverage gaps (an untested `MailboxAck` truncation path with a latent SQLite
  bound-parameter risk; unverified client trust of server-supplied `Deliver.mailbox_id` for acks,
  bounded by existing per-recipient delete-scoping; a drain/connection-registration race window that
  can delay a message to the recipient's *next* reconnect; stale-row leakage into drain/quota reads
  before the next purge sweep; and three boundary-case test gaps — quota exact-at-cap, federated
  `ttl_days == 0`, and an unlocked empty-`ids` conformance vector shape, the last a direct echo of
  Phase 7's own F7 finding). Zero on-the-fly decisions need `/adr` ratification — the one genuine
  on-the-fly decision Phase 8 produced (the mailbox-drain `Deliver.from` sentinel question) was already
  correctly escalated and ratified as **ADR 0024** during the phase itself, confirmed by independent
  architect re-derivation from source. **Verdict: green to proceed — T14 is not blocked**, F1 is simply
  this review phase's top-priority should-fix. Full report:
  [phase-9/review-report.md](./phase-9/review-report.md).
- **NOW:** **Phase 9's findings are broken into 10 numbered fix-tasks** (9.1–9.10), planned by the
  **planner** agent. F1 (top-priority DoS fix, per the review verdict) → **9.1**; F6 → **9.2** (hard
  dependency on 9.1 — its boundary test targets the exact function 9.1 modifies for locking); F5 → **9.3**
  and F4 → **9.4** (both soft-ordered after 9.1 — same `store.rs`/`ws.rs` mailbox code area, avoids
  rebase churn and lets 9.4 reuse 9.1's new locking primitive); F2 → **9.5** (finishes the
  `ws.rs`-touching tasks in one pass); F3 → **9.6**, F7 → **9.7**, F8 → **9.8**, N1 → **9.9** (each in
  files no other phase-9 task touches, so no ordering constraint); N3+N4+N5 → **9.10**, a single bundled
  nit-sweep task (matching the Phase 3/Phase 5 nit-sweep precedent), soft-ordered last so its new tests
  exercise the final race-fixed/TTL-filtered code paths from 9.1/9.3. N2 (the unregistered-metrics
  reminder) was **not** converted — stays an unowned carry-forward for T14's own future task file, per
  the report's own verdict. Full breakdown: [phase-9/README.md](./phase-9/README.md#tasks-todo).
- **NEXT:** `/next-task` — work Phase 9's fix-tasks, 9.1 first. The Phase-1 adversarial frontier remains
  an unowned carry-forward for a future `/plan-phase` if capacity allows; the six Phase-4-named TUI/T08
  residuals are Phase-4-scoped follow-ups and stay listed below for a future phase.


### Live carry-forwards (not owned by any open task)
- **RESOLVED into Phase 9's review — `MailboxAck`'s 4096-id cap is reachable, not merely theoretical**
  (originally task 8.7's review). Phase 9's sweep re-examined this and confirmed it non-blocking (no
  cross-account harm — `mailbox_delete_by_ids` scopes by `(recipient_pub, id)`, no existence oracle —
  but genuinely untested, plus a latent SQLite bound-parameter risk on older builds compiled with the
  `SQLITE_MAX_VARIABLE_NUMBER = 999` default). Recorded as **F2** in
  [phase-9/review-report.md](./phase-9/review-report.md), pending fix-task **9.2** once
  `/plan-review-phase` runs. No longer flag separately here — track via Phase 9's fix-tasks instead.
- **RESOLVED into Phase 9's review — Mailbox quota check is a TOCTOU race under concurrent routes to
  the same recipient** (originally task 8.5's review). Phase 9's sweep re-examined this in more depth
  and found it a more seriously exploitable storage-exhaustion DoS than "roughly one extra envelope per
  concurrent racer": the local route path has no per-envelope size cap (unlike the federated path's
  1 MiB `MAX_FRAME_LEN`) and no per-account connection-concurrency limit exists, so a single
  free-to-create account can overrun `quota_mb` by concurrency × envelope size via a burst of
  near-maximal `Route` frames from multiple connections. Recorded as **F1** (the review's top-priority
  should-fix) in [phase-9/review-report.md](./phase-9/review-report.md), pending fix-task **9.1**. No
  longer flag separately here — track via Phase 9's fix-tasks instead.

Phase 4 is now closed; its own unowned findings live in
[phase-4/README.md](./phase-4/README.md#exit-criteria)'s "Findings with no task yet" sections, for
`/plan-phase` to pick up in a future build phase. These are the standing exceptions that would otherwise
evaporate:
- **RESOLVED (Phase 6, task 6.8): envelope v2's standing dependency gate is now satisfied.** The gate
  itself — encoded mechanically in [roadmap.md](../architecture/roadmap.md) (T07's deps row + the note
  beneath the table) per [Phase 4's README](./phase-4/README.md#envelope-v2-re-deferred--the-concrete-trigger)
  — required a tracker task/phase named "envelope v2" to exist with status done before T07 (and,
  transitively, T14) could be picked. [Phase 6 — Envelope v2](./phase-6/README.md) (6.1–6.8) is that
  phase, closed with a green full-workspace gate, a live two-party CLI demo, and a grep-confirmed sweep
  showing no live-path `mrd.env/1`/v1 reference remains — see
  [6.8's Outcome](./phase-6/6.8-phase-exit-flag-day-demo.md#outcome) and its
  [demo transcript](./phase-6/6.8-demo-transcript.md). The replay-dedup obligation this bullet used to
  carry forward from Phase 2 (2.13 bounded a replay's harm to one failed decrypt) was discharged in the
  same phase by [task 6.4](./phase-6/6.4-eid-replay-dedup.md)'s `eid` dedup key
  ([ADR 0016](../adr/0016-envelope-deniability.md) C7). **T07 and T14 are now pickable** by a future
  `/pick-next-phase` like any other feature whose numbered dependencies are done.
- **The adversarial frontier carried from Phase 1** — SPK grace-window aging, stale-bundle replay on
  the fetch path, same-OTK-to-many-fetchers, reflection, per-device delivery, skipped-key exhaustion.
  Listed in [phase-3/README.md](./phase-3/README.md#findings-with-no-task-and-why); not a Phase-2
  regression, deliberately not scoped into Phase 3.
- **Definition of Done gate 9 (TUI client surface) is now live** — every user-visible feature ships a
  TUI surface via the [extension contract](../architecture/tui-client.md#8-extension-contract--every-feature-ships-a-tui-surface),
  or its task file states why it has none. It binds from T17 onward; features already built (T01–T06)
  acquire their surfaces as T17 and their own follow-ups land. `/plan-phase` must carry this into
  every future build phase's task set.
- **If `relay_rewrite.rs` ever flakes in CI**, widen its `SIDE_TIMEOUT`, **never** `ANSWER_TIMEOUT` —
  the test burns ~31 s real time with only ~4–5 s slack over the 30 s timeout it is exercising.
- **A human must confirm branch protection on `main` actually requires `ci.yml` to pass before
  merge** (`docs/operations/docker-image.md` §1) — no tool available to an agent session can read
  GitHub's branch-protection/ruleset config. 3.12 landed the pre-merge docker build gate itself but
  left this one sub-item open by design rather than guessing; check GitHub Settings → Branches/
  Rulesets and update that doc's `TODO: confirm` once observed.
- **RESOLVED for its declared scope (Phase 7, task 7.2), residual now carried forward:**
  `PrekeyVault::establish_responder_session_provisional`'s peeked SPK/OTK secrets (flagged by task
  6.3's security-reviewer) are now `Zeroizing`-wrapped in `apps/core/src/chat.rs` at the point of
  receipt (F3/F4, [phase-7/7.2](./phase-7/7.2-zeroize-otk-spk-secret-copies.md)). But 7.2's own
  reviewer found the fix only protects the secret up to the `Session::respond` call boundary: that
  function and `x3dh::respond` (`apps/crypto/src/session.rs`/`apps/crypto/src/x3dh.rs`) take
  `opk_secret: Option<[u8; 32]>` **by value**, unchanged by 7.2 (out of its declared `chat.rs`-only
  scope), so the OTK secret still crosses into and through the crypto layer as a fresh, unzeroized,
  plain-`Option` duplicate before being dropped. Short-lived stack memory, never logged/persisted, so
  still non-blocking — but no open task owns `apps/crypto`'s `Session::respond`/`x3dh::respond`
  signatures to close this end-to-end (e.g. take `Option<&[u8;32]>` matching `spk_secret`'s
  already-by-reference pattern, or wrap internally in `Zeroizing`). Flag for whoever next touches
  that boundary or for a future `/plan-phase`.
- **A devops-owned server-side SPK-staleness metric/alert is still unbuilt** (task 6.2's Decision 2,
  architect-reviewed) — client-side enforcement + local warning (task 6.2) satisfies ADR 0016 C1's
  "monitored" obligation for now, but an operator-side view independent of any single client's own
  honesty about reporting its staleness (e.g. "count of accounts whose `prekeys.rotated_at` is older
  than N × the rotation interval") is real, useful follow-up work against `apps/rendezvous`/
  `tools/metrics-allowlist.txt`/`docs/operations/monitoring.md` — the column already exists
  server-side, nothing about 6.2 forecloses it. No open task owns this; schedule via a future
  `/plan-phase` when devops prioritizes it.
- **RESOLVED (Phase 7, task 7.6): T07's planned `mailbox` table PK is `id INTEGER PK`** — a
  server-assigned sequential row id, same shape as `one_time_prekeys.id`, deliberately independent
  of `MessageEnvelope::eid` (task 6.4's client-side replay-dedup key). The naming collision flagged by
  task 6.4's architect review is resolved, not just re-flagged: the envelope's `eid` lives inside the
  opaque `blob` column, which the server never decodes (route's opaque-blob contract, `OpaqueBlob`, the
  no-serde-on-blob lint) — deriving the mailbox PK from it would have required peeking one field of an
  otherwise-opaque payload, a real invariant violation, not a nuance. Dedup on redelivery stays a
  client-side concern only (T07's own feature spec deliverable 2; task 2.8's "no s2s dedup" already
  stands), so the server never needs to read `eid` at all. No ADR needed — this applies ADR-7's
  existing mailbox scope and the pre-existing opaque-blob invariant consistently, resolving an
  accidental naming collision in a not-yet-implemented table, not new binding architecture. See
  [data-model.md](../architecture/data-model.md)'s mailbox table note.
- **A residual sweep of stale "envelope signature"/"signed envelope" language remains outside task
  6.7's file scope** — `apps/rendezvous/src/config.rs`, `apps/rendezvous/src/ws.rs`,
  `apps/rendezvous/src/lib.rs`/`main.rs`, `apps/cli/tests/relay_rewrite.rs`,
  `apps/core/tests/preamble_mutation.rs`, `apps/core/tests/desync_recovery.rs`,
  `apps/store/src/lib.rs`, `apps/proto/src/msg.rs`/`fed.rs`, `apps/signaling/src/lib.rs`/`client.rs`,
  `apps/cli/src/opacity.rs`. Flagged by 6.7's implementer and spot-checked by its architect review
  (7 of 12 sites confirmed genuinely stale and genuinely out of 6.7's literal scope; deferring them
  was judged correct since none blocks anything else in this phase). No task currently owns this;
  pick up via a future `/plan-phase` doc-sync sweep (not urgent — none is security-critical prose,
  unlike the sites 6.7 already fixed).
> live in each task file's **Outcome** section (and the phase README) — not here. This block carries
> only what is *currently actionable* plus obligations no open task owns.

---

## Phases

### Phase 0 — Foundation · **done** · [details](./phase-0/README.md)
Trust-critical substrate: identity, E2EE messaging, P2P session, NAT traversal. Recorded retroactively.
- [x] **0.1** Identity & Keystore Core (T01) — [file](./phase-0/0.1-identity-keystore.md)
- [x] **0.2** Rendezvous Server MVP (T02) — [file](./phase-0/0.2-rendezvous-mvp.md)
- [x] **0.3** E2EE Messaging, relayed (T03) — [file](./phase-0/0.3-e2ee-messaging.md)
- [x] **0.4** P2P Session Substrate (T04) — [file](./phase-0/0.4-p2p-session-substrate.md)
- [x] **0.5** NAT Traversal & Relay Policy (T05) — [file](./phase-0/0.5-nat-traversal-relay.md)

### Phase 1 — Review of Phase 0 · **done** · [details](./phase-1/README.md)
Review of Phase 0 (Features 1–5). [Report](./phase-1/review-report.md) findings F1–F22 → 21 fix-tasks,
ordered blocking-first per the Verdict (doc/ADR truth → freeze crypto → real gates → close Features 4/5 →
design decisions). Blocking gate for Phase 2: F1, F2, F3, F10, F11.

**Group A — Doc/ADR truth restoration** (blocking)
- [x] **1.1** ADR 0015 — ratchet composition (F2) — [file](./phase-1/1.1-adr-0015-ratchet-composition.md)
- [x] **1.2** Doc-sync: purge stale "ratchet = vodozemac" (F3) — [file](./phase-1/1.2-doc-sync-vodozemac.md)
- [x] **1.3** Reconcile T03/T04/T05 specs + wire-deferral (F9) — [file](./phase-1/1.3-reconcile-transport-crypto-specs.md)
- [x] **1.4** Repair roadmap "Phasing" splice + ADR 0013 tail (F19) — [file](./phase-1/1.4-repair-roadmap-splice.md)

**Group B — Freeze the crypto** (blocking / should-fix)
- [x] **1.5** Zeroization gaps: X3DH master secret + ratchet header keys (F5, F6) — [file](./phase-1/1.5-crypto-zeroization-gaps.md)
- [x] **1.6** Conformance vectors: X3DH / ratchet / envelope / safety numbers + CI (F1) — [file](./phase-1/1.6-conformance-vectors.md)
- [x] **1.7** SecretStore KDF op — drop signature-determinism dependency (F7) — [file](./phase-1/1.7-secretstore-kdf-op.md)

**Group C — Make the gates real** (should-fix)
- [x] **1.8** Real CI gates: deny.toml + cargo-deny + blocking clippy (F4, F18) — [file](./phase-1/1.8-ci-blocking-gates.md)
- [x] **1.9** Metrics-allowlist exhaustiveness test (F14) — [file](./phase-1/1.9-metrics-exhaustiveness.md)
- [x] **1.10** Harden no-serde-on-blob lint (F15) — [file](./phase-1/1.10-no-serde-blob-lint.md)
- [x] **1.11** Re-point opacity-audit harness gate (F8) — [file](./phase-1/1.11-opacity-harness-gate.md)
- [x] **1.12** Rendezvous fail-closed config + feature-gate tamper hook (F16, F17) — [file](./phase-1/1.12-rendezvous-fail-closed.md)

**Group D — Close Features 4/5 honestly** (blocking; honesty cheap, backend weeks)
- [x] **1.13** Feature 4 honesty: transport label + SDP test (F10 honesty) — [file](./phase-1/1.13-feature4-honesty.md)
- [x] **1.14** Feature 5 honesty: coturn user-quota + credential-reuse wording (F11 honesty) — [file](./phase-1/1.14-feature5-honesty.md)
- [x] **1.15** webrtc-rs `Transport` backend (F10 backend) — [file](./phase-1/1.15-webrtc-backend.md)
- [x] **1.16** Observed-candidate relay-only enforcement (F20) — [file](./phase-1/1.16-nat-acceptance-matrix.md)
- [x] **1.22** `meridian` CLI: `--transport webrtc` wiring (F11 wire, prerequisite; split from 1.16) — [file](./phase-1/1.22-webrtc-cli-transport.md)
- [x] **1.23** ~~NAT/relay wire-level acceptance matrix~~ — split before implementation into 1.24-1.27 (see file) — [file](./phase-1/1.23-netns-nat-matrix.md)
- [x] **1.24** Real-signaling `SignalRelay` + `session connect` CLI (F11 wire, prerequisite; split from 1.23; depends on 1.22) — [file](./phase-1/1.24-real-signaling-p2p-cli.md)
- [x] **1.25** netns topology + NAT-flavor emulation + coturn/rendezvous orchestration (F11 wire; split from 1.23; depends on 1.14) — [file](./phase-1/1.25-netns-topology-coturn.md)
- [x] **1.26** Drive real peers across the topology + capture pcaps (F11 wire; split from 1.23; depends on 1.24, 1.25) — 3/4 cells connect for real, 4th documented (see file) — [file](./phase-1/1.26-netns-drive-and-capture.md)
- [x] **1.27** pcap-analysis assertions + CI/harness wiring — closes F11 wire-level (split from 1.23; depends on 1.26) — [file](./phase-1/1.27-pcap-assertions-ci.md)
- [x] **1.29** ICE candidate-pair nomination stall under direct/prefer-relay (F11 wire; carved out of 1.26) — [file](./phase-1/1.29-ice-nomination-relay-fallback.md)
- [x] **1.30** TURN-over-TCP client gap under relay-only + udp-blocked (F11 wire; carved out of 1.26) — [file](./phase-1/1.30-turn-tcp-dependency-gap.md)

**Group E — Design decisions + remaining should-fix / nit**
- [x] **1.17** ADR — deniability vs envelope signature (on-the-fly) — [file](./phase-1/1.17-adr-deniability-envelope-sig.md)
- [x] **1.18** Desync → fresh-X3DH auto-recovery decision (F13, on-the-fly) — [file](./phase-1/1.18-desync-recovery-decision.md)
- [x] **1.19** 5k-connection capacity test (F12) — [file](./phase-1/1.19-capacity-test-5k.md)
- [x] **1.20** Server-hardening bundle (F21) — [file](./phase-1/1.20-server-hardening-bundle.md)
- [x] **1.21** Coverage tooling or drop the % (F22) — [file](./phase-1/1.21-coverage-tooling.md)
- [x] **1.28** Active relay-rewrite adversarial test (on-the-fly, flagged during 1.23's split; not part of F11's closure) — [file](./phase-1/1.28-active-relay-rewrite-test.md)
- [x] **1.31** Prekey-bundle republish/fetch race on reconnect (on-the-fly, found during 1.27's live-rig verification; not part of F11's closure) — [file](./phase-1/1.31-prekey-bundle-republish-race.md)

**Group E follow-ups — surfaced by Group E's own reviews** (not in the original Group E set)
- [x] **1.32** Relay attacks that PASS the envelope signature check (from-spoof / replay / reorder / cross-delivery; from 1.28's security review, fold into [ADR 0016](../adr/0016-envelope-deniability.md)'s test obligations) — [file](./phase-1/1.32-relay-attacks-past-signature.md)
- [x] **1.33** Bound the dialer's wait for an answer in `recv_sdp` (availability/diagnostics; from 1.28) — [file](./phase-1/1.33-bound-answer-wait.md)

### Phase 2 — Cross-Org Federation · **done** · [details](./phase-2/README.md)
Build phase. **[T06 — Cross-Org Federation](../architecture/features/06-cross-org-federation.md)**
alone: s2s mTLS (WebPKI + private-CA), federated prekey fetch + envelope forwarding on the strict
`client → own server → foreign server → client` invariant, DNS-SRV **and** static-map discovery,
`open | allowlist | closed` policy, federation-edge rate limits, the first-contact message-request
gate, and a new `federation-protocol-v1.md` wire contract. Deps `T04 (T05 recommended)` both done;
Phase 2's blocking gate (F1, F2, F3, F10, F11) satisfied by Phase 1 Group D. Acceptance = the §7.1
cross-org walkthrough as a runnable `demo/two-orgs` script under both discovery modes.

**Decide before any byte is shaped**
- [x] **2.1** ADR 0017 — federation trust boundary: peer auth + cross-org `from` attestation — [file](./phase-2/2.1-adr-federation-trust-boundary.md)

**Contracts**
- [x] **2.2** `federation-protocol-v1.md` + s2s wire types + conformance vectors — [file](./phase-2/2.2-federation-protocol-v1.md)
- [x] **2.3** c2s extension for federation (hint fields, error codes, vectors; re-defers the §8 schema `TODO` to T07) — [file](./phase-2/2.3-c2s-federation-extension.md)

**Server spine**
- [x] **2.4** s2s mTLS link: listener + dialer (WebPKI and private-CA) — [file](./phase-2/2.4-s2s-mtls-link.md)
- [x] **2.5** Discovery: DNS SRV `_meridian-fed._tcp` + `federation_map.toml` static mode — [file](./phase-2/2.5-federation-discovery.md)
- [x] **2.6** Federation policy (`open | allowlist | closed`) + edge rate limits — [file](./phase-2/2.6-federation-policy-limits.md)
- [x] **2.7** Federated prekey fetch, both sides (§3.3 steps 2–4) — [file](./phase-2/2.7-federated-prekey-fetch.md)
- [x] **2.8** Federated envelope forwarding + per-request reachability (§3.3 step 5, §3.4) — [file](./phase-2/2.8-federated-route-reachability.md)

**Client**
- [x] **2.9** Client federation error taxonomy: clean `closed` error + stale-hint case — [file](./phase-2/2.9-client-federation-errors.md)
- [x] **2.10** First-contact message-request gate (client-side, §3.5) — [file](./phase-2/2.10-message-request-gate.md)

**Follow-up surfaced by 2.9's review** — architect required a new task rather than folding the fix
into 2.9 or 2.11.
- [x] **2.15** Thread the peer's org hint into live signaling/chat routing (blocks 2.11, 2.12) — [file](./phase-2/2.15-thread-route-hint.md)

**Demo + exit gate**
- [x] **2.11** `demo/two-orgs/`: two full stacks, private CA, both discovery modes — [file](./phase-2/2.11-demo-two-orgs.md)
- [x] **2.12** Cross-org abuse + acceptance suite (the phase exit gate) — [file](./phase-2/2.12-cross-org-abuse-acceptance.md)

**Carried in from Phase 1** (production defect surfaced by 1.32; not part of T06)
- [x] **2.13** A replayed envelope permanently wedges the receiving ratchet (`Ratchet::decrypt` commits `ckr`/`nr` before `aead_open` and never rolls back — unauthenticated permanent session DoS) — [file](./phase-2/2.13-ratchet-replay-dos.md)
- [x] **2.14** Wire the message-request gate into the P2P session substrate (from 2.10's review; `session connect` currently bypasses the gate entirely) — [file](./phase-2/2.14-p2p-message-request-gate.md)
- [x] **2.16** `session_connect_webrtc.rs`'s TURN-grant test hangs in real CI, root cause unconfirmed (surfaced while closing 2.15; `#[ignore]`d rather than guessed at) — [file](./phase-2/2.16-turn-grant-ci-hang.md)
- [x] **2.17** Bound the answerer's wait for an offer (`recv_sdp`, mirror of 1.33; surfaced by 2.12's review) — [file](./phase-2/2.17-bound-offer-wait.md)

### Phase 3 — Review of Phase 2 · **done** · [details](./phase-3/README.md)
Review phase. Sweeps everything built since the Phase-1 review: Phase 2 (2.1–2.17), the Phase-1
follow-ups 1.32/1.33, and the untracked out-of-band PRs #36–#42 (figment/ADR 0018, Docker Hub
publish, Dokploy stack, coturn fixes, CLI `wss://`). [Report](./phase-3/review-report.md): 25 findings
— **3 blocking** (F1 outbound-policy SSRF, F2 serial-accept listener DoS, F3 unbounded outbound s2s
I/O), 17 should-fix, 5 nits. Verdict: **blocked until F1/F2/F3 land**, then green for the next build
phase.

**Wave 1 — blocking gate** (3.2 before 3.3: same `link.rs`, and 3.3 reuses 3.2's `with_deadline`)
- [x] **3.1** Enforce federation policy on the outbound dial path (F1) — [file](./phase-3/3.1-outbound-federation-policy.md)
- [x] **3.2** Un-wedge the inbound s2s listener: concurrent, time-bounded accept (F2+N5) — [file](./phase-3/3.2-inbound-accept-loop-hardening.md)
- [x] **3.3** Bound every outbound s2s I/O exchange (F3) — [file](./phase-3/3.3-outbound-s2s-timeouts.md)

**Wave 2 — test harness** (after the gate, before every other test-adding task)
- [x] **3.4** Extract the shared s2s test harness (PKI + server boot) (F18) — [file](./phase-3/3.4-federation-test-support-harness.md)

**Wave 3 — federation server**
- [x] **3.5** Stop the reachability pre-check double-spending route budgets (F4) — [file](./phase-3/3.5-fed-ratelimit-double-spend.md)
- [x] **3.6** Accept-side peer identity must consider all authenticated SANs (F9) — [file](./phase-3/3.6-multi-san-peer-identity.md)
- [x] **3.7** Reuse TLS config + one link per federated message, SRV failover (F10+N2) — [file](./phase-3/3.7-federation-link-reuse.md)
- [x] **3.8** Count federated deliveries in `envelopes_routed_total` (F8+N4) — [file](./phase-3/3.8-fed-delivery-metrics.md)
- [x] **3.9** Resolve the dead per-partner `policy` field in `federation_map.toml` (F7) — [file](./phase-3/3.9-federation-map-policy-field.md)

**Wave 4 — parallel track** (core client + CI; no federation-server contention)
- [x] **3.10** Bound `pending_requests` against a stranger flood (F5) — [file](./phase-3/3.10-message-request-flood-bound.md)
- [x] **3.11** Thread first-contact state into `decide_open` (ctrl-frame gate) (F11) — [file](./phase-3/3.11-first-contact-ctrl-gate.md)
- [x] **3.12** Build the rendezvous image pre-merge + schedule the `--ignored` runner (F12) — [file](./phase-3/3.12-ci-docker-build-gate.md)
- [x] **3.13** Test the `wss://` crypto-provider install (F13) — [file](./phase-3/3.13-wss-crypto-provider-test.md)
- [x] **3.14** Conformance vectors for the c2s hint extension (F20) — [file](./phase-3/3.14-c2s-hint-conformance-vectors.md)

**Wave 5 — docs, ops, ratification**
- [x] **3.15** Doc-sync the federation wire/deploy facts (F14+F15) — [file](./phase-3/3.15-federation-protocol-doc-sync.md)
- [x] **3.16** Warn on private-CA trust anchors under SRV discovery (F6) — [file](./phase-3/3.16-private-ca-srv-hazard.md)
- [x] **3.17** Give the production stack a federation surface with a C7 guard-rail (F17) — [file](./phase-3/3.17-dokploy-federation-surface.md)
- [x] **3.18** Fix the live coturn `realm` placeholder (F19) — [file](./phase-3/3.18-coturn-realm-placeholder.md)
- [x] **3.19** ADR 0019 — container image distribution + signing (F16 remainder) — [file](./phase-3/3.19-adr-image-distribution-signing.md)

**Wave 6 — last**
- [x] **3.20** Resolve the `ROUTE_REPLY_GRACE` false-positive-success residual (may yield ADR 0020) — [file](./phase-3/3.20-route-reply-grace-residual.md)
- [x] **3.21** Nit sweep (N1, N3) — [file](./phase-3/3.21-phase-3-nit-sweep.md)
- [x] **3.22** s2s framing adversarial suite (**optional — first to cut**) — [file](./phase-3/3.22-s2s-framing-adversarial.md)

**Wave 7 — found during 3.22, not part of the original report**
- [x] **3.23** Bound `serve_link`'s idle read (no idle-read deadline; in WebPKI mode exploitable by
  any public-CA cert-holder, not gated by federation policy) — [file](./phase-3/3.23-serve-link-idle-read-deadline.md)

### Phase 4 — Verification & Trust + Terminal TUI Client · **done** · [details](./phase-4/README.md)
Build phase. **[T08 — Verification & Contact Trust](../architecture/features/08-verification-trust.md)**
+ **[T17 — Terminal TUI Client](../architecture/features/17-terminal-tui-client.md)**, bundled: T08's
core trust module (safety-number compare, TOFU→pinned→verified states, un-softenable key-change
blocking, `meridian-mitm-sim`) is a hard prerequisite for T17's mandatory verification screens — see
the [phase README](./phase-4/README.md#resolving-the-t17t08-overlap) for why they aren't split.
Envelope v2 (T07's blocker) is deliberately **not** in this phase — see
[the re-deferral](./phase-4/README.md#envelope-v2-re-deferred--the-concrete-trigger) — except for a narrow v1-scoped fix
inside 4.9. 38 tasks (28 originally planned + 10 added post-4.28 to close the T17 gap it found —
see [Phase 4's own status note](./phase-4/README.md) for why), [full DAG here](./phase-4/README.md#dependency-order).

**ADR track — blocks all T17 code, not T08**
- [x] **4.1** ADR 0020 — TUI packaging — [file](./phase-4/4.1-adr-tui-packaging.md)
- [x] **4.2** ADR 0021 — client-local store & config formats — [file](./phase-4/4.2-adr-client-store-config-formats.md)

**T08 track — starts immediately**
- [x] **4.3** Trust module + contact store core — [file](./phase-4/4.3-trust-module-contact-store.md)
- [x] **4.4** Key-change handling: block/warn semantics — [file](./phase-4/4.4-key-change-block-warn-gate.md)
- [x] **4.5** Safety-number compare UX primitives + `meridian verify` — [file](./phase-4/4.5-safety-number-verify-cli.md)
- [x] **4.6** Petname assignment + contact management CLI — [file](./phase-4/4.6-petname-contact-management-cli.md)
- [x] **4.7** Message-request UX finalization (from T06) — [file](./phase-4/4.7-message-request-finalization.md)
- [x] **4.8** Org directory-attestation ingest — [file](./phase-4/4.8-directory-attestation-ingest.md)
- [x] **4.9** Desync detection → guarded fresh-X3DH re-handshake (incl. `open_bytes` short-circuit fix) — [file](./phase-4/4.9-desync-guarded-rehandshake.md)
- [x] **4.10** `meridian-mitm-sim` trust-state matrix — [file](./phase-4/4.10-mitm-sim-trust-matrix.md)

**T17 infra — no T08 dependency**
- [x] **4.11** `apps/tui` crate skeleton + terminal guard — [file](./phase-4/4.11-tui-crate-skeleton-terminal-guard.md)
- [x] **4.12** `meridian tui` subcommand + environment gate — [file](./phase-4/4.12-tui-subcommand-env-gate.md)
- [x] **4.13** Extract shared account/home-layout helpers into `meridian-core` — [file](./phase-4/4.13-extract-account-home-layout-core.md)
- [x] **4.14** `meridian-tui::config` — [file](./phase-4/4.14-tui-config.md)
- [x] **4.15** `meridian-tui::store` — [file](./phase-4/4.15-tui-store.md)
- [x] **4.16** Onboarding screen — [file](./phase-4/4.16-onboarding-screen.md)
- [x] **4.17** Unlock screen — [file](./phase-4/4.17-unlock-screen.md)
- [x] **4.18** Extension registry (`meridian-tui::surface`) — [file](./phase-4/4.18-extension-registry.md)

**T17 screens — converge at 4.19**
- [x] **4.19** Contact list + add-contact + contact detail — [file](./phase-4/4.19-contact-list-detail-screens.md)
- [x] **4.20** Chat / conversation screen — [file](./phase-4/4.20-chat-screen.md)
- [x] **4.21** Message-request queue screen — [file](./phase-4/4.21-message-request-queue-screen.md)
- [x] **4.22** Verification screen — [file](./phase-4/4.22-verification-screen.md)
- [x] **4.23** Key-change adversarial test — [file](./phase-4/4.23-key-change-adversarial-test.md)
- [x] **4.24** Settings screen — [file](./phase-4/4.24-settings-screen.md)
- [x] **4.25** Help overlay + command palette + diagnostics — [file](./phase-4/4.25-help-palette-diagnostics.md)
- [x] **4.26** Terminal-constraint degradation — [file](./phase-4/4.26-terminal-constraint-degradation.md)
- [x] **4.27** At-rest audit harness — [file](./phase-4/4.27-at-rest-audit-harness.md)

**Phase exit gate (first attempt — found the T17 gap below)**
- [x] **4.28** Docs sync + phase acceptance-demo wiring — [file](./phase-4/4.28-docs-sync-acceptance-demo.md)

**T17 gap closure — added post-4.28** (real `run_worker` execution, a live inbound-message receive path
found missing during this planning pass, `Preflight`/`Screen::Main` navigation, and a second, planned-to-
succeed exit-gate attempt) — see [Phase 4's own task list](./phase-4/README.md#tasks-todo) for full detail
- [x] **4.29** `Effect::LoadSession` + `LiveSession` assembly — [file](./phase-4/4.29-load-session-live-session.md)
- [x] **4.30** Real `run_worker`: account lifecycle — [file](./phase-4/4.30-run-worker-account-lifecycle.md)
- [x] **4.31** Real `run_worker`: contacts & contact-detail persistence — [file](./phase-4/4.31-run-worker-contacts-persistence.md)
- [x] **4.32** Real `run_worker`: trust & request-queue persistence — [file](./phase-4/4.32-run-worker-trust-request-persistence.md)
- [x] **4.33** Real `run_worker`: outbound chat — [file](./phase-4/4.33-run-worker-outbound-chat.md)
- [x] **4.34** Real `run_worker`: settings & diagnostics — [file](./phase-4/4.34-run-worker-settings-diagnostics.md)
- [x] **4.35** Inbound delivery stream — [file](./phase-4/4.35-inbound-delivery-stream.md)
- [x] **4.36** `Screen::Main` + live navigation — [file](./phase-4/4.36-screen-main-live-navigation.md)
- [x] **4.37** Preflight routing — [file](./phase-4/4.37-preflight-routing.md)
- [x] **4.38** T17 acceptance-demo closure (phase re-exit gate) — [file](./phase-4/4.38-t17-acceptance-demo-closure.md)
- [x] **4.39** Prekey bundle republish + vault persistence on session start (fix for 4.38's Defect A) — [file](./phase-4/4.39-prekey-bundle-republish.md)
- [x] **4.40** Thread the live-session secret store through file-backed contacts/trust/send handlers (fix for 4.38's Defect B) — [file](./phase-4/4.40-file-backed-live-session-store.md)
- [x] **4.41** T17 acceptance-demo closure, third exit-gate attempt — [file](./phase-4/4.41-t17-acceptance-demo-closure-attempt-3.md)

**Third gap-closure wave — added post-4.41** (fix shapes for 4.42 and 4.43 were decided at plan time by
an architect consult recorded in their own files; neither needs a further pre-code consult or a new ADR).
Recommended landing order is **4.43 → 4.42 → 4.44 → 4.45**; numbering keeps 4.42 = Defect C as
pre-announced.
- [x] **4.42** Post-accept path to chat/verify with a message-request sender (Defect C — the blocking defect) — [file](./phase-4/4.42-post-accept-chat-affordance.md)
- [x] **4.43** File-backed prekey republish performance, 188 s → seconds (4.39's recorded, unfixed defect; land first) — [file](./phase-4/4.43-file-backed-republish-performance.md)
- [x] **4.44** Load a chat's persisted transcript when the chat screen opens (predicted "Defect D"; verify first, then fix) — [file](./phase-4/4.44-chat-history-load-on-open.md)
- [x] **4.45** T17 acceptance-demo closure, fourth exit-gate attempt (hard join on 4.42, 4.43, 4.44) — [file](./phase-4/4.45-t17-acceptance-demo-closure-attempt-4.md)
- [x] **4.46** Reconcile `Effect::AddContact` into the live `MainState::trust` (fix for 4.45's fourth defect) — [file](./phase-4/4.46-add-contact-trust-reconciliation.md)
- [x] **4.47** Fix `--export-json` demo-script/spec wording (doc-only) — [file](./phase-4/4.47-export-json-doc-fix.md)
- [x] **4.48** T17 acceptance-demo closure, fifth exit-gate attempt — [file](./phase-4/4.48-t17-acceptance-demo-closure-attempt-5.md)
- [x] **4.49** Persist the accepted sender's intro into `history.jsonl` (fix for 4.48's fifth defect) — [file](./phase-4/4.49-persist-accepted-intro-history.md)
- [x] **4.50** T17 acceptance-demo closure, sixth exit-gate attempt (verdict FAIL — sixth defect found;
  closed by the sixth gap-closure wave, 4.51/4.52) — [file](./phase-4/4.50-t17-acceptance-demo-closure-attempt-6.md)
- [x] **4.51** Root-cause and fix the file-backed responder's blocking-scrypt hazard (fix for 4.50's
  sixth defect) — [file](./phase-4/4.51-file-backed-inbound-blocking-fix.md)
- [x] **4.52** T17 acceptance-demo closure, seventh exit-gate attempt — verdict PASS, Phase 4 exit gate
  closed — [file](./phase-4/4.52-t17-acceptance-demo-closure-attempt-7.md)

### Phase 5 — Review of Phase 4 · **done** · [details](./phase-5/README.md)
Review phase. Sweeps everything built since the Phase-3 review: Phase 4 (T08 + T17, tasks 4.1–4.52) and
the untracked out-of-band PRs #66–#73 that landed alongside/after it. [Report](./phase-5/review-report.md):
18 findings — **0 blocking**, 9 should-fix, 9 nits (F1 combines a duplicate correctness+coverage finding
from two lenses, numbered once). Verdict: **green to proceed**, no blocker for the next build phase
(envelope-v2). 14 fix-tasks landed, all `[x]`: 13 covering all 18 findings (N8 folded into 5.5 rather
than its own task) plus 5.14, a genuine second instance of F3's bug class found by 5.3's own review
round — see [phase-5/README.md](./phase-5/README.md#exit-criteria) for the closure summary.

**Wave 1 — fully parallel**
- [x] **5.1** Persist and always-reconcile Sent→Delivered receipts (F1) — [file](./phase-5/5.1-persist-reconcile-delivery-receipts.md)
- [x] **5.2** Diagnostics-surfaced repair action for `run_accept_request`'s partial-failure window (F2) — [file](./phase-5/5.2-accept-request-repair-action.md)
- [x] **5.4** `spawn_blocking`-wrap `run_mark_verified`/`run_set_petname` (F4) — [file](./phase-5/5.4-spawn-blocking-mark-verified-set-petname.md)
- [x] **5.5** Wire receive-side key-change detection into the TUI inbound loop + `session.rs` (F5 + N8 deferred) — [file](./phase-5/5.5-wire-receive-side-key-change-detection.md)
- [x] **5.7** App-level reconciliation tests for Settings/Diagnostics (F7) — [file](./phase-5/5.7-settings-diagnostics-app-level-tests.md)
- [x] **5.8** App-level end-to-end tests for onboarding/unlock (F8) — [file](./phase-5/5.8-onboarding-unlock-app-level-tests.md)
- [x] **5.9** Scheduled CI workflow for `demo/p2p-wire-proof` (F9) — [file](./phase-5/5.9-schedule-p2p-wire-proof-ci.md)
- [x] **5.10** Drain/flush-on-shutdown hook for `Effect::PersistHistory` (F10) — [file](./phase-5/5.10-persist-history-drain-on-shutdown.md)
- [x] **5.11** Extract shared `observe_into_live_trust` helper (N1) — [file](./phase-5/5.11-extract-observe-into-live-trust-helper.md)
- [x] **5.12** Pin `find_binding`'s keybinding-collision tie-break contract (N7) — [file](./phase-5/5.12-pin-keybinding-collision-tiebreak.md)
- [x] **5.13** Nit sweep: doc/comment/mechanical fixes (N2, N3, N4, N5, N6) — [file](./phase-5/5.13-phase-5-nit-sweep.md)
- [x] **5.14** `run_acknowledge_key_change` has the same `contacts.json` trust-staleness bug as F3 (found by 5.3's own review, depends on 5.3) — [file](./phase-5/5.14-acknowledge-key-change-trust-staleness.md)

**Wave 2 — sequenced (same-function/same-file conflicts)**
- [x] **5.3** Fix `contacts.json` trust staleness + cover `export_json` (F3; depends on 5.4) — [file](./phase-5/5.3-fix-contacts-trust-staleness-export.md)
- [x] **5.6** Federated mitm-sim cell: verified-contact key-change block (F6; depends on 5.5) — [file](./phase-5/5.6-federated-verified-key-change-mitm-cell.md)

### Phase 6 — Envelope v2 · **done** · [details](./phase-6/README.md)
Build phase. **Envelope v2** — [ADR 0016](../adr/0016-envelope-deniability.md) (binding), not a
numbered feature: drops the per-message identity-key signature from `MessageEnvelope`, relying on the
ratchet AEAD + X3DH `DH1` for authentication. Deps: T03 (done), ADR 0016 (accepted). This is the
standing dependency gate named in [roadmap.md](../architecture/roadmap.md) that unblocks T07 (mailbox)
and, transitively, T14. 8 tasks; dependency waves and the `/plan-phase` refinements (planner + architect
consult) that shaped them: [phase-6/README.md](./phase-6/README.md).

**Wave 1 — independent, both unblocked now**
- [x] **6.1** SPK rotation policy: age tracking + rotation-due predicate (C1, 1/3) — [file](./phase-6/6.1-spk-rotation-age-tracking.md)
- [x] **6.3** Envelope v2 core cutover: wire shape + canonical AAD + commit-on-decrypt + desync short-circuit fix (C2, C3, C5, C6, C7 short-circuit) — [file](./phase-6/6.3-envelope-v2-core-cutover.md)

**Wave 2**
- [x] **6.2** SPK rotation enforcement: trigger + monitoring in both client loops (C1, 2–3/3; depends on 6.1) — [file](./phase-6/6.2-spk-rotation-enforcement.md)
- [x] **6.4** `eid` replay-dedup key (C7, 2/2; depends on 6.3) — [file](./phase-6/6.4-eid-replay-dedup.md)
- [x] **6.6** Test re-pointing: v1 detector → v2 AEAD + new C3/R1 adversarial cells (depends on 6.3) — [file](./phase-6/6.6-repoint-adversarial-tests.md)

**Wave 3**
- [x] **6.5** Conformance vectors: `ratchet-v2.json` + `envelope-v2.json` (depends on 6.3, 6.4) — [file](./phase-6/6.5-conformance-vectors-v2.md)
- [x] **6.7** Doc-sync: describe envelope v2 as shipped (C4; depends on 6.3, 6.4) — [file](./phase-6/6.7-doc-sync-envelope-v2.md)

**Wave 4 — exit gate**
- [x] **6.8** Phase exit: flag-day cutover verification + acceptance demo + roadmap unblock (depends on 6.1–6.7) — [file](./phase-6/6.8-phase-exit-flag-day-demo.md)

### Phase 7 — Review of Phase 6 · **done** · [details](./phase-7/README.md)
Review phase. Sweeps everything built since the Phase-5 review: Phase 6 — Envelope v2 (tasks 6.1–6.8).
No untracked out-of-band PRs landed in this window. [Report](./phase-7/review-report.md): 9 findings —
**1 blocking** (F1), 6 should-fix (F2–F7), 2 nits (N1–N2). Zero on-the-fly decisions need `/adr`
ratification. All 6 fix-tasks (7.1–7.6) closed — F1 (blocking), F2–F7 (should-fix), N1 (nit) all
resolved with zero should-fix/blocking findings surviving any review round; N2 deliberately not
converted, deferred to a future `/plan-phase` per the report's own verdict. Tree green throughout.
**T07/T14 are clear to pick.**
- [x] **7.1** Flag-day hard-reject test coverage (F1, F2) — [file](./phase-7/7.1-flag-day-hard-reject-coverage.md)
- [x] **7.2** Zeroize discarded/peeked OTK and SPK secret copies (F3, F4) — [file](./phase-7/7.2-zeroize-otk-spk-secret-copies.md)
- [x] **7.3** Stale v1-signature prose in `route_tamper.rs` (F5) — [file](./phase-7/7.3-route-tamper-stale-signature-prose.md)
- [x] **7.4** Property test for `eid` dedup bound + duplicate detection (F6) — [file](./phase-7/7.4-eid-dedup-property-test.md)
- [x] **7.5** Boundary-case conformance vectors for `envelope-v2.json` (F7) — [file](./phase-7/7.5-envelope-v2-boundary-vectors.md)
- [x] **7.6** Resolve the `eid`/mailbox naming collision before T07 planning (N1) — [file](./phase-7/7.6-eid-mailbox-naming-collision-note.md)

### Phase 8 — Offline Ciphertext Mailbox · **closed — 17/17 done** · [details](./phase-8/README.md)
Build phase. **[T07 — Offline Ciphertext Mailbox](../architecture/features/07-offline-mailbox.md)**
alone: TTL-bounded, size-capped, ciphertext-only mailbox on the recipient's home rendezvous (ADR 0007),
with deletion-on-acknowledged-delivery, per-recipient quota, cross-federation delivery, and the
`meridian-admin mailbox dump` honesty demo. Deps T03 + T06 (both done) plus the envelope-v2 standing gate
(done, Phase 6/7). **T14 is deliberately not bundled in** — see [phase-8/README.md](./phase-8/README.md)
for why. 14 tasks (8.1–8.14) across 6 dependency waves, shaped by an architect consult that settled the
wire-protocol questions T07 raises before any task started; full record and breakdown:
[phase-8/README.md](./phase-8/README.md).

**Wave 1 — independent**
- [x] **8.1** Mailbox store trait + in-memory impl + config surface — [file](./phase-8/8.1-mailbox-store-trait-config.md)
- [x] **8.3** Wire/proto: `RouteOk.queued`, `mailbox_full`, `Deliver.mailbox_id`, `MailboxAck`/`MailboxAckOk` — [file](./phase-8/8.3-wire-proto-mailbox-fields.md)

**Wave 2**
- [x] **8.2** SQLite mailbox migration + `SqliteStore` impl — [file](./phase-8/8.2-sqlite-mailbox-migration.md)
- [x] **8.4** Conformance vectors for the mailbox wire fields — [file](./phase-8/8.4-mailbox-conformance-vectors.md)

**Wave 3 — route-path integration**
- [x] **8.5** `handle_route` local mailbox enqueue, TTL/quota-aware — [file](./phase-8/8.5-local-route-mailbox-enqueue.md)
- [x] **8.6** `handle_fed_route` mailbox enqueue on offline recipient — [file](./phase-8/8.6-fed-route-mailbox-enqueue.md)

**Wave 4 — delivery, ack, and storage-only follow-ons**
- [x] **8.7** Delivery-on-reconnect push + `MailboxAck` handling, server side — [file](./phase-8/8.7-mailbox-delivery-reconnect-ack.md)
- [x] **8.9** TTL expiry purge job — [file](./phase-8/8.9-mailbox-ttl-purge-job.md)
- [x] **8.11** `meridian-admin mailbox dump <pubkey>` — [file](./phase-8/8.11-meridian-admin-mailbox-dump.md)
- [x] **8.12** Opacity/at-rest audit extension for mailbox rows — [file](./phase-8/8.12-opacity-audit-mailbox-rows.md)

**Wave 5**
- [x] **8.8** Client-side `MailboxAck` send + redelivery-dedup confirmation — [file](./phase-8/8.8-client-mailbox-ack-dedup.md)
- [x] **8.10** X3DH-initial-message-via-mailbox coverage — [file](./phase-8/8.10-x3dh-initial-via-mailbox.md)

**Wave 6 — acceptance + exit**
- [x] **8.13** Cross-federation acceptance test: Org A → Org B mailbox → reconnect — [file](./phase-8/8.13-cross-federation-mailbox-acceptance.md)
- [x] **8.15** Client surfaces the mailbox-queued outcome (fix-task found during 8.14's live demo prep) — [file](./phase-8/8.15-client-surfaces-mailbox-queued-outcome.md)
- [x] **8.16** `meridian register` persists its published bundle's prekey secrets (fix-task found during 8.14's live demo) — [file](./phase-8/8.16-cli-register-persists-prekey-secrets.md)
- [x] **8.17** Mailbox-drained messages arriving before a first-contact request is accepted must not be silently lost (fix-task found during 8.14's live demo) — [file](./phase-8/8.17-mailbox-ack-must-not-swallow-pending-request-messages.md)
- [x] **8.14** Phase exit: full demo script + doc sync — [file](./phase-8/8.14-phase-exit-mailbox-demo.md)

### Phase 9 — Review of Phase 8 · **in progress — 10 fix-tasks planned, 0/10 done** · [details](./phase-9/README.md)
Review phase. Sweeps everything built since the Phase-7 review: Phase 8 — Offline Ciphertext Mailbox
(tasks 8.1–8.17). No untracked out-of-band PRs landed in this window (confirmed: only PR #83
`pick-next-phase` and PR #84, all of 8.1–8.17, merged between the two review points).
[Report](./phase-9/review-report.md): 14 findings — **0 blocking**, 9 should-fix (F1–F8 plus N3–N5
folded in as fix-tasks), 5 nits (N1 folds in, N2 stays an unowned carry-forward for T14). Zero
on-the-fly decisions need `/adr` ratification — Phase 8's one genuine on-the-fly decision (the
mailbox-drain `Deliver.from` sentinel) was already ratified as ADR 0024 during the phase itself.
**Verdict: green to proceed — T14 is not blocked.** 10 fix-tasks (9.1–9.10) planned by the **planner**
agent; landing order and dependencies: [phase-9/README.md](./phase-9/README.md#tasks-todo).

- [~] **9.1** Serialize mailbox quota check-and-enqueue; cap local route envelope size (F1) — [file](./phase-9/9.1-mailbox-quota-race-and-local-size-cap.md)
- [ ] **9.2** Quota exact-at-cap boundary test (F6; depends on 9.1) — [file](./phase-9/9.2-mailbox-quota-boundary-test.md)
- [ ] **9.3** Filter `expires_at` on mailbox reads (F5; soft-depends on 9.1) — [file](./phase-9/9.3-mailbox-expires-at-read-filter.md)
- [ ] **9.4** Fix drain/registration race window (F4; soft-depends on 9.1) — [file](./phase-9/9.4-mailbox-drain-registration-race.md)
- [ ] **9.5** Chunk `MailboxAck` delete into sub-999-parameter batches (F2) — [file](./phase-9/9.5-mailbox-ack-chunk-delete.md)
- [ ] **9.6** Document/validate client trust in `Deliver.mailbox_id` (F3) — [file](./phase-9/9.6-mailbox-id-client-trust-boundary.md)
- [ ] **9.7** Federated-path `ttl_days == 0` test (F7) — [file](./phase-9/9.7-federated-ttl-zero-test.md)
- [ ] **9.8** Lock `MailboxAck{ids:[]}` conformance vector (F8) — [file](./phase-9/9.8-mailbox-ack-empty-conformance-vector.md)
- [ ] **9.9** Add `Mailbox::validate` config check (N1) — [file](./phase-9/9.9-mailbox-config-validate.md)
- [ ] **9.10** Nit sweep: mailbox-drain proptest, `purge_loop` coverage, double-ack no-op test (N3, N4, N5; soft-depends on 9.1, 9.3) — [file](./phase-9/9.10-phase-9-nit-sweep.md)

## Legend / how to read
- Each task line links to its own file with **Goal · Scope · Deliverables · Risks · Tests · Reviews · Status**.
- Phase folders (`phase-N/`) hold a `README.md` (phase overview + todo) and one file per task; review
  phases also hold a `review-report.md`.
- Definition of Task and Definition of Done: [CONTRIBUTING.md](../../CONTRIBUTING.md).
