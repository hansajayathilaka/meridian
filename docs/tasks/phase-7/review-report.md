<!-- Written by /start-review-phase to docs/tasks/phase-7/review-report.md.
     /plan-review-phase reads this and turns each actionable finding into a numbered fix-task. -->
> **Nav:** [tracker](../README.md) · [phase](./README.md) · [Definition of Done](../../../CONTRIBUTING.md)

# Phase 7 — Review Report

**Reviews:** Phase 6 — Envelope v2, tasks 6.1–6.8 (diff `bf476c5..ab71157`) · **Date:** 2026-08-27 ·
**Reviewers:** code-reviewer, security-reviewer, architect, test-engineer

## Summary
Phase 6 is a materially sound, well-executed cryptographic migration. All four independent lenses
converge on the same verdict: **ADR 0016's binding conditions (C1–C7) are genuinely implemented, not
just self-reported** — commit-on-successful-decrypt (`open_bytes`, `apps/core/src/chat.rs:1652-1783`)
defers OTK consumption and session install past every code path until after a successful AEAD open; the
canonical v2 AAD is built from raw Ed25519 encodings and the *received* preamble bytes, guarded by a real
negative test; `eid` dedup runs pre-crypto with no TOCTOU and bounded growth; SPK rotation enforcement is
real (not aspirational) and tested on both long-running client loops; the re-pointed adversarial suite
(`preamble_mutation.rs`, `eid_dedup.rs`, `commit_on_decrypt_independent.rs`) asserts specific error
variants and byte-identical state on rejection, not vacuous "any error" checks; no test functions were
deleted rather than re-pointed; the dependency graph, wire docs, and roadmap/tracker updates all check
out.

One **blocking** gap surfaced: the flag-day hard-reject path (`ChatError::UnsupportedEnvelopeVersion`,
C5/R5) that the ADR calls out as the mechanism making cutover "a clean, diagnosable hard error" has **zero
test coverage** proving it actually fires — the code is independently confirmed correct by three
reviewers reading the same lines, but nothing currently guards it against regression. Six should-fix items
(three secret-zeroization/handling gaps in the OTK/SPK provisional path, one stale-doc-prose miss inside
6.7's own named scope, and two test-coverage gaps in `eid` dedup and conformance vectors) and two nits.
Nothing here reopens or reshapes ADR 0016 itself, and no on-the-fly decision needs `/adr` ratification.

## Findings
Severity: **blocking** (must fix before next build) · **should-fix** (fix this review phase) · **nit** (optional).

| # | Severity | Area / file | Finding | Recommended fix |
|---|----------|-------------|---------|-----------------|
| F1 | blocking | `apps/core/src/chat.rs:1661-1664` (`ChatError::UnsupportedEnvelopeVersion`); no test in `apps/core/tests/*.rs` or `apps/cli/tests/*.rs` | The C5/R5 hard-reject path — a structurally v2-shaped envelope carrying a wrong `v` value — is never exercised by a test that calls `open_bytes`/`open_inbound` and asserts rejection *before* any crypto/session work. `apps/envelope/tests/roundtrip.rs::envelope_version_is_mandatory_and_never_defaulted` only proves the *codec* preserves an arbitrary `v`; it never reaches `meridian-core`'s enforcement. The 6.8 demo only proves genuine traffic is always `v==2`, never that a wrong-version envelope is rejected on receipt. | Add a `chat_manager.rs` cell: take a genuine opening envelope, set `v` to a non-2 value, assert `open_bytes` returns `ChatError::UnsupportedEnvelopeVersion(1)` with the OTK pool depth and session table untouched, plus a control that the genuine `v:2` envelope still succeeds. |
| F2 | should-fix | `apps/envelope/src/envelope.rs` (`from_blob`) + `apps/core/src/chat.rs:1660-1665` | ADR 0016's "clean, diagnosable hard error" claim (C5/R5) is untested for the *actual* flag-day scenario: a genuine v1-shaped blob (no `v`/`eid`, has `sig`) fails earlier, at codec decode, with a generic `CodecError`/`ChatError::Codec` — it never reaches `UnsupportedEnvelopeVersion` at all. No test or doc asserts what diagnostic an operator actually sees for this real-world case; 6.8's demo transcript only decodes already-v2 blobs. | Add a test asserting the exact error an operator sees when a genuine v1-shaped blob is fed through the v2 path, or soften the ADR/doc claim to scope "clean, diagnosable" to wrong-version-but-v2-shaped envelopes only. Can share a fix-task with F1. |
| F3 | should-fix | `apps/core/src/chat.rs:1847-1850` (`commit_responder_otk`) | `take_otk_secret`'s returned `[u8;32]` OTK secret copy is discarded via `let _ = ...` without zeroizing. New behavior introduced by task 6.3's peek/commit split (under the old eager-consume design this discard-without-use path didn't exist) — a literal violation of crypto-protocols skill rule 6, cheap to fix. Distinct from the pre-existing carry-forward (F4). | Wrap the returned secret in `zeroize::Zeroizing` (or explicitly `.zeroize()`) before dropping it in `commit_responder_otk`. |
| F4 | should-fix | `apps/core/src/chat.rs` `establish_responder_session_provisional` / `PrekeyVault::peek_spk_secret`/`peek_otk_secret` (~542-566, ~1799-1833) | The pre-existing, previously non-blocking carry-forward (`docs/tasks/README.md`'s Live carry-forwards, flagged by 6.3's own security review) — plain `[u8;32]` stack copies of peeked SPK/OTK secrets, not `Zeroizing`-wrapped — is confirmed unchanged but now **routinely attacker-triggerable** under C2: every mutated preamble/ciphertext takes this path, not just legitimate publishes. It has ridden as an unowned README bullet since Phase 6 opened; time to give it an owning task rather than let it evaporate again. | Wrap `spk_secret`/`opk_secret` locals in `zeroize::Zeroizing` inside `establish_responder_session_provisional`. Can land in the same task as F3 (same function family, same fix shape). |
| F5 | should-fix | `apps/rendezvous/src/route_tamper.rs:136,151` | Stale v1-signature prose ("the receiver compares `Deliver.from` against the *signed* `sender_pub`", "valid, correctly signed, but belonging to a *different* session") survives inside the exact file task 6.7's `/plan-phase` refinement #3 named as "actively misleading, not just outdated." The file's module-level doc (lines 1-9) was correctly rewritten; these two body-comment sites were missed. Comment-only — `plan()`'s actual logic only ever compared byte fields, never checked a signature — so no behavior/security impact, but a genuine C4 gap 6.7's own self-report didn't catch. | Reword lines 136 and 151 to AEAD-authenticated-plaintext-field language, matching the fix already applied to this file's module doc and to `apps/cli/tests/relay_attacks.rs`. |
| F6 | should-fix | `apps/core/tests/eid_dedup.rs` | `eid` dedup coverage is entirely example-based (redelivery, unconfirmed-retransmit, bounded-flood-of-distinct-eids) with no property/fuzz test. `meridian-core`/`meridian-crypto`/`meridian-envelope` have no `proptest`/`quickcheck` dependency at all (only `apps/identity` does). No randomized/near-collision coverage or adversarial out-of-order arrival test for the `MAX_SEEN_EIDS` eviction bound. | Add a small `proptest` generating random `eid` sequences with controlled duplicate/near-duplicate rates, asserting `seen_eids_len(&state) <= MAX_SEEN_EIDS` always holds and exact duplicates are always caught regardless of arrival order. |
| F7 | should-fix | `test-vectors/envelope-v2.json` | All three conformance vectors (`no-prekey`, `prekey-no-opk`, `prekey-with-opk`) use the same 8-byte `ct_hex` — no empty-`ct`, maximal-size-preamble, or other boundary-shape vector. CI wiring itself (`cargo run -p xtask -- vectors` + `git diff --exit-code` regenerate-and-diff gate, plus `apps/crypto/tests/conformance.rs`) is solid; only the vector *content* is thin. | Add an empty-`ct` vector and a maximal-length preamble/`ct` vector, regenerated via `cargo run -p xtask -- vectors` (never hand-edited). |
| N1 | nit | `docs/tasks/README.md:101-109`, `docs/architecture/data-model.md` | The `MessageEnvelope::eid` (task 6.4, client-side dedup) vs. T07's planned mailbox `eid BLOB` primary-key naming collision — already flagged by 6.4's own architect review — is still just an unowned README bullet with no explicit resolution recorded, even though Phase 6's ADR is exactly what gates T07. | Have an architect pass record an explicit note (or ADR addendum) cross-referencing both uses now, before T07 planning starts, so `/plan-phase` for T07 doesn't pick a colliding or ambiguous name by accident. |
| N2 | nit | `apps/rendezvous/src/{config,ws,lib,main}.rs`, `apps/cli/tests/relay_rewrite.rs`, `apps/core/tests/{preamble_mutation,desync_recovery}.rs`, `apps/store/src/lib.rs`, `apps/proto/src/{msg,fed}.rs`, `apps/signaling/src/{lib,client}.rs`, `apps/cli/src/opacity.rs` | 12 stale "envelope signature"/"signed envelope" sites outside 6.7's file scope, 7/12 spot-checked as genuinely stale by 6.7's own implementer and architect review, still unowned. None is security-critical prose (per 6.7's assessment), but this is precisely the class of stale comment-driven language this sweep looks for, and it will keep accumulating. | Schedule a doc-sync sweep task in a future `/plan-phase` rather than letting it ride indefinitely as an unowned README bullet. |

## On-the-fly decisions to ratify
None found. The architect pass specifically checked the two candidates that looked most like new binding
architecture — the constraint that `v: 2` must never route through either existing version-negotiation
mechanism (Bundle `v:1`/`v:2`, `Hello.streams[].ver`), and C1's fail-open/rotation-interval mechanism — and
both are correctly framed by [phase-6/README.md](../phase-6/README.md#4-plan-phase-refinements-planner--architect-consult-before-task-files-were-written)
as implementation details within ADR 0016's own accepted-residual scope, decided with architect +
security-reviewer sign-off per this codebase's existing `TODO: confirm` precedent — not new binding
architecture requiring a fresh ADR.

## Coverage / test gaps
- **F1** — the C5/R5 flag-day hard-reject path has no test proving it fires (blocking).
- **F2** — the real-world v1-shaped-blob flag-day scenario's actual diagnostic is unverified (should-fix,
  shares root cause with F1).
- **F6** — `eid` dedup has no property/fuzz coverage, only example-based cells (should-fix).
- **F7** — conformance vectors cover only one canonical shape, no boundary/edge cases (should-fix).
- Everything else the pyramid should cover for this phase checks out clean: KCI (R1) is
  documented-by-test, sign-flipped `sender_pub` (C3) is covered, preamble mutation (R3/C2) is covered on
  both the first-contact and task-4.9-fallback branches with byte-identical-state assertions on
  rejection plus positive controls, and SPK rotation's fail-open decision is tested symmetrically across
  both long-running client loops (no fail-closed variant needed — none was chosen, by design, per task
  6.2's Outcome).

## Verdict
**Blocked until F1 lands, then clear for the next build phase** (T07/T14, now pickable per Phase 6's
roadmap unblock). F1 is cheap — a single new test cell against already-correct code, not a design or
implementation fix — so this is not expected to meaningfully delay `/plan-review-phase`. F2–F7 are
should-fix and land alongside F1 in this review phase's fix-tasks; N1–N2 are optional but recommended
while the context is fresh. Nothing here reopens ADR 0016 or contradicts any prior phase's closure.
