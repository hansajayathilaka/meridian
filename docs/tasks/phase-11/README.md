<!-- Created by /start-review-phase. The todo list below is filled by /plan-review-phase. -->
> **Nav:** [tracker](../README.md) · [roadmap](../../architecture/roadmap.md) · [features](../../architecture/features/)

# Phase 11 — Review of Phase 10

**Kind:** review · **Status:** sweep complete, verdict recorded — blocked until F1 lands ·
**Reviews phase(s):** Phase 10 (File Transfer Stream, tasks 10.1–10.24)

## Goal
Sweep everything built since the Phase-9 review for bugs, gaps, loopholes, and on-the-fly decisions
before the next build phase (T10 or T14) is picked. Scope is Phase 10 — T09 File Transfer Stream:
`mrd.file/1` as a stream-type extension (manifest-on-ctrl, 64 KiB AEAD-chunked, backpressure,
resume-via-bitmap, incremental subtree verification, TUI inline preview/progress fallback), the
session-substrate multi-stream generalization it required, the SCTP max-message-size fix (10.18), and
the full `ice_restart` gap-closure wave (ADR 0025, tasks 10.19–10.24) that reopened and then re-closed
the phase's own exit gate.

## Chosen feature(s) / scope
- **Phase 10 — File Transfer Stream** (all 24 tasks, 10.1–10.24) —
  [phase-10/README.md](../phase-10/README.md). Diff range: `804f204` (Phase 9 close, PR #87 merged) `..`
  `e3836dd` (current `main`/this branch's base). Merge PRs in this window, confirmed via
  `git log --merges 804f204..e3836dd`: #88 (`pick-next-phase`, phase-10 README only, no code), #89–#92
  (all of 10.1–10.24 across four `next-task` batches), and one **untracked out-of-band PR**: #86
  (dependabot bump of `ghcr.io/devcontainers/features/docker-in-docker` 4.0.0 → 4.1.0, a 6-line
  `.devcontainer/devcontainer-lock.json` change only — trivial, no source/wire/security surface, noted
  here for completeness but not a review target). No other untracked PRs landed in this window.

## Dependency check
Phase 10 is closed (24/24 tasks `[x]`, exit gate 10.24 passed on its second attempt — the real
`meridian send` multi-chunk transfer and the network-cut/`ice_restart`/resume kill-resume scenario both
verified live over real WebRTC/netns) per the master tracker. This review phase follows it per the
lifecycle (`/start-review-phase` always follows a closed build phase).

## Review sweep
Delegated in parallel, each an independent full-diff read (phase-wide diff, so single-lens agents
rather than the combined `reviewer` agent):
- **code-reviewer** — correctness, loopholes, gaps, dead ends, missing pieces, simplifications across
  the streams crate (manifest/merkle/chunk/sender/receiver/resume), the session-substrate multi-stream
  generalization, the SCTP fix, and the `ice_restart` signaling rewrite.
- **security-reviewer** — anonymity-model "must never" list; per-chunk AEAD key handling
  (`k_f`/nonce-by-index), the new `DoubleRatchet` HKDF-export primitive, the `ice_restart` layered
  fingerprint check, and any plaintext/metadata leakage into transfer logs/metrics/TUI state.
- **architect** — ADR 0025 (ICE-restart renegotiation) conformance, the stream-type extension contract
  (zero core-crate diffs outside the deliberate 10.4 substrate-completion task), wire/API contract
  discipline for the new `IceRestartOffer`/`Answer` signal types and the resume-bitmap protocol,
  dependency-graph cleanliness.
- **test-engineer** — coverage gaps across the pyramid + adversarial harnesses for corrupted chunks,
  kill/resume, the netns loss/RTT rig, and the soak test; also re-examine the five live carry-forwards
  already on record from Phase 10's own task reviews (below) for severity/ownership.

Also carried into this sweep: the **live carry-forwards already on record** from Phase 10's own task
reviews (not new findings, but re-examined for severity/ownership in this pass) —
- `tools/netns-kill-resume.sh`'s `need_veth_linkstate` pre-flight self-check false-negatives on any
  long-lived-shell PID ≥ 5 digits (found by 10.17).
- `.claude/skills/stream-type-authoring/SKILL.md` step 3 is stale relative to `stream-types-v1.md`'s
  per-frame (not once-at-OPEN) ratchet-export mechanism (found by 10.17's third-party check).
- `Transport::recv()` has no bounded timeout anywhere in its call chain (found by 10.18's review).
- `apps/tui`'s extension registry has no public seam for a feature module to register into a *live*
  session, and `chat.rs`'s transcript renderer never consults the shared registry (found by 10.11).
- `MessageRenderer::render`'s `Vec<Line<'static>>` return type structurally cannot carry a sixel/kitty
  inline-image escape sequence (found by 10.11, verified against `ratatui-core` source).
- `mrd.file/1`'s per-chunk merkle proof has no pinned wire delivery mechanism (found by 10.12's doc-sync).
- Reshare/dedup of identical file ciphertext is design-permitted but unimplemented (feature spec's own
  out-of-scope note).
- The `RESTART_GLARE_WINDOW` mutual-timeout race and the post-restart DTLS/SCTP readiness race (both
  found by the `ice_restart` gap-closure wave, tasks 10.22/10.23 — non-blocking, non-security).

Findings, on-the-fly decisions, and coverage gaps: [review-report.md](./review-report.md). **10
findings — 1 blocking (F1), 9 should-fix (F2–F10), 5 nits (N1–N5).** N1 folds into F2's fix-task (same
data structure); N2–N4 are informational/deferred, not converted; N5 (the `CtrlFrame::Close` cleanup gap,
re-confirmed from task 10.4's own recorded residual but never previously surfaced to the master
tracker) is dormant/unreachable today and promoted straight to a tracker carry-forward rather than a
fix-task. One should-fix (F10 in the report, the stale `netns-kill-resume.sh` PID carry-forward) is a
**correction**, not a new gap: task 10.23 already fixed it — the master tracker's carry-forward list
should drop that item. Zero on-the-fly decisions need `/adr` ratification — the one candidate (task
10.22's mid-phase `ice_restart` signaling fix) was independently re-derived as an implementation-level
bugfix within ADR 0025's existing scope, not a design change. **Verdict: blocked until F1 lands** — a
real, deterministically-reproducible `sid`-collision defect in `P2pSession::open_stream` when both
peers concurrently open the same bidirectional stream type (exactly `mrd.file/1`'s registered shape),
found by code-reviewer and reproducible today on `LoopbackTransport` alone. Mirrors the Phase-7/Phase-10
precedent for a phase-exit-blocking finding recorded rather than downgraded. Full report:
[review-report.md](./review-report.md).

## Tasks (todo)
<!-- Filled by /plan-review-phase. Status marks: [ ] pending [~] in progress [x] done [!] blocked -->
Planned by the **planner** agent from [review-report.md](./review-report.md)'s 1 blocking + 9 should-fix
findings (10 fix-tasks, 11.1–11.10; N1 folds into 11.3's F3 fix; N2–N4 stay informational/deferred per
the report's own disposition, not converted; N5 was already promoted straight to a tracker carry-forward,
not a fix-task). Landing order below follows dependency analysis: 11.1 lands first (the phase's one
blocking finding, F1's `sid`-collision fix, architect-ratified before or as part of its own task); 11.2
and 11.6 are **soft**-ordered after 11.1 (and, for 11.6, after 11.2 too) — all three touch
`apps/core/src/session.rs`'s `open_stream`/`ice_restart` area, so landing in this order avoids rebase
churn even though none is a functional dependency of another. 11.3 (F3+N1, the `apps/streams/file.rs`
buffer restructuring) has **no** dependency and is sequenced after the session.rs cluster only because
it's a separate crate/area. 11.4 **soft**-depends on 11.3 — its new test lands in the same
`run_responder`/`finalize_transfer` functions N1's fix touches. 11.5 (resume boundary tests) has **no**
dependency on anything in this phase. 11.7 (conformance vectors) has **no** hard dependency but is
deliberately sequenced before 11.8: it locks in the four already-shipped, stable wire shapes now, before
11.8's own architect consult decides whether to extend the chunk wire shape further — if it does, that's
a follow-up vector amendment flagged as 11.8's own residual, not a reason to block 11.7 today. 11.8 (F8,
the phase's most architecturally significant should-fix) has **no** hard dependency on any other
fix-task. 11.9 (docs-only devops confirmation, mirroring the existing branch-protection `TODO: confirm`
precedent) and 11.10 (the new CI workflow for the kill-resume rig) are each independent of everything
else and of each other.

- [x] **11.1** Namespace `open_stream`'s `sid`/channel-label derivation to fix concurrent-open collisions (F1, blocking) — [file](./11.1-fix-open-stream-sid-collision.md)
- [x] **11.2** Enforce relay-only on `ice_restart`'s freshly-gathered candidates (F2; soft-depends on 11.1) — [file](./11.2-ice-restart-relay-only-enforcement.md)
- [x] **11.3** Bound/restructure `mrd.file/1`'s `pending_chunks` buffer and its O(n) rescan (F3 + N1) — [file](./11.3-bound-pending-chunks-buffer.md)
- [x] **11.4** Real-CLI-path bit-flip rejection test (F4; soft-depends on 11.3) — [file](./11.4-cli-bitflip-rejection-test.md)
- [x] **11.5** Resume boundary tests: 0 chunks received / all-but-last chunk (F5) — [file](./11.5-resume-boundary-tests.md)
- [x] **11.6** Make `RESTART_GLARE_WINDOW` test-overridable; cover the timeout-fallback branch (F6; soft-depends on 11.1, 11.2) — [file](./11.6-restart-glare-window-timeout-test.md)
- [x] **11.7** Conformance vectors for Phase 10's new wire surfaces (F7) — [file](./11.7-file-transfer-conformance-vectors.md)
- [ ] **11.8** Wire `FileReceiver`'s per-chunk verification into the real send path, or narrow the claim (F8) — [file](./11.8-chunk-proof-delivery-mechanism.md)
- [ ] **11.9** Confirm `soak-file-transfer.yml` ran clean post-10.18 on a real runner (F9, devops-owned, docs-only) — [file](./11.9-soak-workflow-runner-confirmation.md)
- [x] **11.10** Add scheduled/`workflow_dispatch` CI for `netns-kill-resume.sh` (F10) — [file](./11.10-netns-kill-resume-ci-workflow.md)

**N2, N3, N4** were deliberately **not** converted to fix-tasks — matching the review report's own
disposition: N2 (`LoopbackTransport::ice_restart`'s "no-op" doc-comment overclaim) and N4 (no back-to-back
resume-bitmap test) are low-priority, "pick up next time the file is touched / if capacity allows" items
with no live defect behind them; N3 (the dead HKDF-export capability) needs no action at all — the report
itself calls it a byproduct of a clean design, not a gap. **N5** (the `CtrlFrame::Close` cleanup gap) was
**not** converted either — it was already promoted straight to a master-tracker carry-forward bullet by
the report itself, since it's dormant/unreachable today (no code path in this phase ever sends `Close`
for a file transfer); no fix-task would have anything live to test against.

## Exit criteria
All fix-tasks (11.1–11.10) `[x]`. Tree green workspace-wide (`cargo build --workspace`,
`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings` in both default and
`--features webrtc` configs, `tools/check-docs.sh`, `tools/lint-server-no-core.sh`,
`tools/lint-tui-no-cli.sh`). Findings closed per the report's verdict: every task's named reviewer(s)
signing off PASS with zero blocking findings surviving any task's final review round. 11.9 may stay open
longer than the rest since it depends on a human/devops observation an agent session cannot make
directly — matching the existing branch-protection `TODO: confirm` precedent — and should not itself
block the phase's other 9 tasks from closing. Docs synced as part of each task's own commit. Draft PR:
[#93](https://github.com/hansajayathilaka/meridian/pull/93).
