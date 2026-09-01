<!-- Created by /start-review-phase. The todo list below is filled by /plan-review-phase. -->
> **Nav:** [tracker](../README.md) · [roadmap](../../architecture/roadmap.md) · [features](../../architecture/features/)

# Phase 11 — Review of Phase 10

**Kind:** review · **Status:** in progress — sweep running · **Reviews phase(s):** Phase 10 (File
Transfer Stream, tasks 10.1–10.24)

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

Findings, on-the-fly decisions, and coverage gaps: `review-report.md` (sweep in progress — this link
becomes live once that file lands in this same PR).

## Tasks (todo)
<!-- Filled by /plan-review-phase. Status marks: [ ] pending [~] in progress [x] done [!] blocked -->
(pending `/plan-review-phase`)

## Exit criteria
(pending `/plan-review-phase` and the fix-task run)
