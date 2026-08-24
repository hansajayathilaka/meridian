> **Nav:** [tracker](../README.md) · [phase](./README.md) · [Definition of Done](../../../CONTRIBUTING.md)

# Phase 5 — Review Report

**Reviews:** Phase 4 (T08 — Verification & Contact Trust + T17 — Terminal TUI Client, tasks 4.1–4.52)
plus untracked out-of-band PRs #66–#73 merged in the same window · **Date:** 2026-08-24 · **Reviewers:**
code-reviewer, security-reviewer, architect, test-engineer

## Summary
Phase 4 is the largest single build phase to date (107 commits, 94 files, ~45.5k insertions) and the
first to ship a full interactive client (`meridian tui`) with a persistent local store and a real
trust/verification control. Its own internal discipline was unusually heavy — the T17 acceptance demo
needed seven exit-gate attempts and found six genuine defects along the way, each closed by an
independent live-run-plus-reviewer cycle. That discipline shows: **this sweep found zero blocking
defects.** No ADR drift, no dependency-graph or extension-registry violations, no trust-state-machine
bypass, no sealed-store leak, and no exploitable regression from the six `decrypt_seed()` call sites
task 4.51 moved off the blocking runtime. The two new out-of-band ADRs (0022 → superseded same-window
by 0023) are a clean self-correction with no leftover cruft.

What the sweep did find is a consistent pattern: **six previously-named, already-known residual
findings from Phase 4's own README are all still accurate and still unowned** (F2–F4, F10 below), and
**a brand-new out-of-band feature — the Sent/Delivered message-status indicator (PRs #71/#72) — landed
outside the tracked-task pipeline and reproduces exactly the same class of gap** the tracked work spent
six waves fixing: a live-UI reconciliation path with no App-level test and a real correctness bug (F1).
Nothing here blocks the next build phase (envelope-v2, per Phase 4's own committed trigger), but F1–F9
should land as fix-tasks before that work starts, since several touch the trust/delivery paths
envelope-v2 will also touch.

## Findings
Severity: **blocking** (must fix before next build) · **should-fix** (fix this review phase) · **nit** (optional).

| # | Severity | Area / file | Finding | Recommended fix | → Fix-task |
|---|----------|-------------|---------|-----------------|-----------|
| F1 | should-fix | `apps/tui/src/app.rs:1429-1467`, `screens/chat.rs:786-800`, `worker.rs:1858-1867` | The new Sent/Delivered message-status indicator (out-of-band PRs #71/#72, no task file) only flips a message to "Delivered" when the exact `Screen::Chat` for that peer is the top of the screen stack at the moment the receipt arrives; the transition is never persisted, so it silently reverts to "Sent" on restart, and is unreachable at all if the user has navigated away. Zero App-level test exists for `InboundEvent::Receipt` routing — every test either drives `chat::apply_receipt` directly on a bare `ChatState` or never constructs `InboundEvent::Receipt` at all. | Route the receipt through the live screen stack the same way `apply_accepted_request`/`apply_added_contact` reconcile other inbound events (update regardless of which screen is on top), and persist the transition. Add an `accept_to_chat.rs`-style test dispatching a real `AppEvent::Inbound(InboundEvent::Receipt{..})` and asserting the rendered transcript. | 5.1 |
| F2 | should-fix | `apps/tui/src/worker.rs:1256-1373` | `run_accept_request`'s partial-failure window (already named in Phase 4's README, still unowned by any task): if `trust.bin` saves but `contacts.json`'s save then fails, a retry takes the early return and never repairs the missing row — peer durably trusted but permanently unreachable through any on-screen affordance (ADR 0001 forbids a hint-less manual re-add). Task 4.49 added a second instance of the same class: if `history::append` fails after `trust.bin`/`contacts.json` already succeeded, the intro is permanently lost on retry. The retry-succeeds branch itself is well tested (`run_worker_trust.rs:526`). | Add a diagnostics-surfaced repair action that rebuilds rows missing for an existing `trust.bin` contact, explicitly distinct from the delete-tombstone case (design direction already sketched inline in `worker.rs`'s own comments). | 5.2 |
| F3 | should-fix | `apps/tui/src/worker.rs:1449-1460` (`run_mark_verified`), `apps/tui/src/store/export.rs:84-135` (`export_json`) | `contacts.json`'s `trust` field goes stale after live verification (`run_mark_verified` only writes `trust.bin`) and `export_json` never exports `trust.bin`'s content at all — an exported dump shows `"trust": "pinned"` for a contact the live UI correctly shows as "verified." Already named in Phase 4's README, still unowned. Additionally, `export_json` itself has **zero test coverage at any layer** (`export.rs`'s own test module only covers `chmod` helpers). | Either write-through `run_mark_verified` into `contacts.json`, or have `export_json` join `trust.bin` the same way `screens/main.rs::build_contact_entries` does. Add an integration test that first pins today's (wrong) behavior, flippable once the fix lands. | 5.3 |
| F4 | should-fix | `apps/tui/src/worker.rs:977-999, 1449-1460` | `run_mark_verified`/`run_set_petname` still run synchronous file-backed `decrypt_seed()` scrypt unwraps directly on the single-threaded tokio runtime — the exact class of bug task 4.51 fixed for six other call sites, deliberately split off there (13 `live_store`-routed handlers, disproportionately wider diff). 4.52's live-run data measured the real cost: ~3.7–4.1s UI-thread block, masked from casual observation by the optimistic in-memory flip. Security review confirms this is a latency/availability issue only, not a new timing side-channel (no remote party is positioned to observe it). | Generalize 4.51's `Arc<dyn SecretStore>` + `spawn_blocking` shape to `OnboardingSession::live_store`, or scope a narrower fix for just these two highest-impact handlers first. | 5.4 |
| F5 | should-fix | `apps/core/src/session.rs` (no `TrustStore` references), `apps/tui/src/worker.rs::process_inbound_delivery` (no `observe_key_change` call) | Receive-side key-change detection is wired into **no** inbound path — not the CLI's P2P session substrate (`session.rs` has zero `TrustStore`/`can_send` references), not the TUI's inbound delivery loop. `TrustStore::can_send`'s fail-open for unknown/unobserved contacts means a MITM against an established conversation outside the CLI's `chat` command is currently undetected. Already named as a known gap in Phase 4's README; not a regression, but task 4.46 (`AddContact` reconciliation) now makes every added contact correctly trust-tracked, which is a prerequisite for this gap to actually matter in practice — the remaining surface is now just "no receive-path check exists," not also "contacts aren't tracked at all." | Wire `observe_key_change`/`can_send` into `run_inbound_loop`'s content path and `apps/core/src/session.rs`'s P2P dial path, mirroring `apps/cli/src/chat.rs`'s existing discipline. Extend `meridian-mitm-sim` with a cell substituting a key against an already-established TUI/P2P session, not just the CLI `chat` command path. | 5.5 |
| F6 | should-fix | `harnesses/mitm-sim/` | The T08 trust-state matrix (task 4.10) has no federated (cross-org) cell for an already-**verified** contact's key-change block — the existing federated cell (from task 2.12) only proves fresh-contact (TOFU) rejection. Given A2×2 (colluding org servers) is a named threat-model adversary, this is a real coverage gap. | Add a harness cell combining 2.12's two-server topology with 4.10's verified-contact-key-substitution assertion. | 5.6 |
| F7 | should-fix | `apps/tui/tests/screens_settings.rs`, `screens_help_palette.rs`, `run_worker_settings.rs` | Settings and Diagnostics screens have no App-level test combining a real key event, a real worker dispatch, and reconciliation of the completed effect back into the live screen — only disjoint halves exist (screen-level synthetic events; worker-level dispatch with no screen stack). This is the exact gap class (Defect C / the `AddContact` reconciliation gap) that took six waves to close for other screens. | Extend `accept_to_chat.rs`'s harness style to Settings (real key edit → real `Effect::SaveSetting` → confirm persisted/session-only outcome renders) and Diagnostics (`Ctrl+K` → real `RunDoctor` outcome rendered, including the not-on-`PATH` failure path). | 5.7 |
| F8 | should-fix | `apps/tui/tests/screens_onboarding.rs`, `screens_unlock.rs` | No automated test drives the very first user-facing flow (type a passphrase / step through onboarding → real `Effect::Unlock`/`GenerateAccount` → `App::handle_worker` → land on `Screen::Main`) through real key events end to end — both test files explicitly document "no real worker exists yet" and every downstream test (`accept_to_chat.rs`) bypasses onboarding/unlock via a pre-provisioned account. Mitigated in practice by manual PTY runs across all seven exit-gate attempts, but that's not a regression test. | Add one `accept_to_chat.rs`-style test per flow: typed passphrase → real `Screen::Unlock` → `Screen::Main`; stepped onboarding sub-screens → real account generation/registration/bundle-publish → `Screen::Main`. | 5.8 |
| F9 | should-fix | `demo/p2p-wire-proof/`, `.github/workflows/*.yml` | `demo/p2p-wire-proof/` (out-of-band PR #73) substantiates Meridian's headline "no server sees plaintext, direct P2P" claim but has no CI trigger at all, not even scheduled — its own README says so explicitly. `docs/testing/strategy.md`'s stated model has a scheduled soak/ops bucket this fits; it needs `NET_ADMIN`/`NET_RAW` + Docker so it can't simply fold into `test-harnesses`, but that's an argument for a scheduled workflow, not for staying purely human-run indefinitely — mirrors task 3.12's precedent for the rendezvous Docker build gate. | Add a scheduled (weekly/release) GitHub Actions workflow running the demo, mirroring 3.12's shape. | 5.9 |
| F10 | nit | `apps/tui` (no drain/flush hook in `lib.rs::run()`) | `Effect::PersistHistory`'s async write to `history.jsonl` has no drain-on-shutdown window — a message that just rendered live can fail to survive a restart if the process is killed within ~2s of appearing. Found by 4.51's own test-engineer pass; confirmed still present and still untested (no reproduction test exists anywhere). | Give history-persist effects a drain window or an explicit flush-on-shutdown hook; add a regression test once fixed. | 5.10 |
| N1 | nit | `apps/tui/src/app.rs:2215-2249` vs `2302-2343` | `apply_accepted_request` and `apply_added_contact`'s stack-walk-and-`trust.observe` dispatch logic (~20 lines) is duplicated verbatim — `apply_added_contact`'s own doc comment acknowledges it rather than extracting it. This exact reconciliation logic has been the source of three defects this phase (4.42, 4.45, 4.46); worth collapsing into a shared helper before a fourth caller appears. | Extract `fn observe_into_live_trust(&mut self, main_idx, pubkey, hint, at)`. | 5.11 |
| N2 | nit | `docs/architecture/features/17-terminal-tui-client.md:102,104` | Demo script still reads `^N`/`^V` where the real bindings are plain `n`/`v` (correct in `tui-client.md`'s own reference table). Flagged and left unfixed across three prior sweeps (4.42, 4.48, 4.50). | Doc-only fix, mirroring task 4.47's shape. | 5.12 |
| N3 | nit | `apps/core/src/trust.rs:430-434` | `observe_key_change`'s `ConflictingContact` guard (`if &existing.pubkey != previous_pubkey`) is tautological given the module's own invariant that `contacts[k].pubkey == k` always holds and the early-return above already guarantees `new_pubkey != previous_pubkey` — the inner branch can never be false when reached. Behavior is correct, but the code reads as though a live case exists where it wouldn't be. | Simplify to a flat `contains_key` check with a comment explaining the invariant, or add a `debug_assert`. | 5.13 |
| N4 | nit | `apps/tui/src/screens/diagnostics.rs:89-92,361-383` | `run_doctor_binary` resolves `meridian` via `PATH` rather than an absolute path — already flagged as an accepted risk in the module's own doc comment with a `TODO: confirm`, but only in-comment, not tracked. | Formalize into a tracked task, or confirm-and-close the `TODO: confirm` explicitly. | 5.14 |
| N5 | nit | `docs/adr/README.md:31` | ADR 0022's summary-table row reads as the live decision before the "Superseded by 0023" note appears in the same cell — not a drift bug (0022's own file header is unambiguous), purely a readability ordering nit. | Lead the cell with "Superseded by 0023" or otherwise front-load the supersession note. | 5.15 |
| N6 | nit | `apps/tui/src/surface.rs:232-238` | `PaletteAction::PushScreen` is a first-party escape hatch reaching pre-existing built-in `Screen` variants, distinct from `PushPane` (the actual sanctioned third-party extension mechanism) — not a violation, but worth naming so a future feature doesn't mistake it for the extension path. | Add a doc comment distinguishing `PushScreen` (built-in only) from `PushPane` (the real extension point). | 5.16 |
| N7 | nit | `apps/tui/src/surface.rs:330-338` | `find_binding`'s tie-break on colliding keybindings is unpinned ("current, unexamined behavior"), unlike `register`'s documented last-write-wins rule. Low risk today (only T17's own commands registered), but risk grows as more features register via the extension contract. | Pin the tie-break explicitly (registration-order error, or an explicit collision registry) before a second real feature lands. | 5.17 |
| N8 | nit | `apps/core/tests/trust_store.rs` | No test covers a concurrent-verification race (a key-change arriving from the inbound loop while `mark_verified` is in flight in the same session) — low priority today since the TUI's worker runtime is currently single-threaded, but this exact interleaving-race class was found and fixed once already this phase (task 4.46, `Ctrl-R`/`AddContact`). | Add a low-priority regression test once F5's receive-side wiring lands (the race isn't reachable before then). | 5.18 |

## On-the-fly decisions to ratify
None found needing ratification. The architect lens specifically checked the two fix-shape decisions
made via inline consult rather than a new ADR (task 4.40 — extending in-memory key residency; task
4.42 — synthesizing a `contacts.json` row on accept) and confirmed both judgments hold: 4.40 correctly
extends an already-shipped residency pattern rather than introducing a new exposure class, and 4.42
correctly refused to invent a hint-less `mrd1:` id, deferring to ADR 0001 instead of working around it.
The out-of-band ADR 0022 → 0023 supersession (release-binary distribution: initially shipped the wrong
binary, corrected same-window) was reviewed and found clean — no leftover artifacts from the 0022-era
pipeline, both ADR files read as coherent history.

## Coverage / test gaps
Beyond F1, F3, F7, F8, F9, F10, N8 above (all coverage-shaped findings), the sweep confirmed:
- The **adversarial harness frontier carried from Phase 3** (SPK grace-window aging, stale-bundle
  replay, same-OTK-to-many-fetchers, reflection, per-device delivery, skipped-key exhaustion) is
  accurately still listed as not-yet-covered in `harnesses/mitm-sim/README.md`'s "Not modelled" section
  — verbatim the same six items, not silently dropped or silently (and unrecorded) fixed.
- **Conformance vectors hold**: T08's `meridian verify` UX layer calls only the already-vector-pinned
  `safety_number`/`display_groups` core functions; no new fingerprint code path needs new vectors.
- **The out-of-band CI job-split is a faithful decomposition**: all four harnesses and the
  conformance-vector/cross-org/tamper-hook steps remain in the blocking `build` gate post-split; the
  one regression the split introduced (`test-nat-matrix`'s missing example build) was root-caused and
  fixed in the same commit window (`822c477`), not patched over.
- The Windows double-input fix (`819a3a1`) ships its own targeted regression test and needs nothing
  further.

## Verdict
**Green to proceed.** Zero blocking findings — the next build phase (envelope-v2, per Phase 4's own
committed trigger in `docs/architecture/roadmap.md` and this project's README) is not gated by anything
here. F1–F9 (should-fix) should land as fix-tasks this review phase before that build starts, since
several (F1, F4, F5) touch the same trust/ratchet/inbound-delivery surface envelope-v2 will modify, and
landing them first avoids compounding two waves of changes on the same code. N1–N8 (nits) are optional
and may be picked up opportunistically within the same review phase or deferred.
