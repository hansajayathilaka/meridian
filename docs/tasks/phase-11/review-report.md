<!-- Written by /start-review-phase to docs/tasks/phase-N/review-report.md.
     /plan-review-phase reads this and turns each actionable finding into a numbered fix-task. -->
> **Nav:** [tracker](../README.md) · [phase](./README.md) · [Definition of Done](../../../CONTRIBUTING.md)

# Phase 11 — Review Report

**Reviews:** Phase 10 (File Transfer Stream, tasks 10.1–10.24) · **Date:** 2026-09-01 ·
**Reviewers:** code-reviewer, security-reviewer, architect, test-engineer

## Summary
Phase 10 is fundamentally sound: the merkle/chunk/AEAD core (`apps/streams`), the ADR-0025 `ice_restart`
signaling rewrite, and the SCTP fix all read as correct and are backed by real, passing test suites
(1000+ tests run live across `meridian-streams`, `meridian-core` default + `--features webrtc`,
`meridian-transport` default + `--features webrtc`, `meridian-tui` — zero failures, zero `#[ignore]`s
found in the touched crates). No anonymity-model "must never" violation was found, and ADR 0025's
Decision text was independently confirmed to match what shipped, point-for-point, including the
mid-phase 10.22 bugfix (judged an implementation-level correction within the ADR's existing scope, not
a design change — no `/adr` ratification needed).

The one **blocking** finding is a real, deterministically-reproducible substrate bug: `P2pSession`
assigns stream ids from a purely local, uncoordinated counter, so two peers independently opening the
same bidirectional stream type (exactly what `mrd.file/1` is registered as) at close to the same time
race to the same `sid`, producing two distinct local data channels bound to an identical wire label —
on `LoopbackTransport` (used by nearly all in-repo tests) this silently cross-delivers one transfer's
frames into the other's handler, and on the real WebRTC backend it binds two `RTCDataChannel`s to one
negotiated SCTP stream. This sat undetected because every existing test opens streams sequentially from
one side, and the one real caller (`meridian send`) deliberately restricts itself to a single directed
batch — a restriction that incidentally avoids the bug rather than fixing it.

Nine further should-fix findings cluster into three groups: (a) two narrower correctness/hardening gaps
in shipped code (`ice_restart`'s fresh candidates skip the existing `relay-only` fail-closed check;
`file.rs`'s inbound chunk buffer is unbounded, with a resource-exhaustion shape); (b) coverage gaps
where a doc comment or task's own stated invariant is not actually exercised end-to-end by any test
(the real CLI path's bit-flip rejection, the `RESTART_GLARE_WINDOW` timeout-fallback branch, resume at
0/all-but-last chunks); and (c) two artifact-completeness gaps that matter more once a second client
exists (no conformance vectors for any of this phase's new wire surfaces; `mrd.file/1`'s own incremental
per-chunk verification engine, `FileReceiver`, has no live caller in the real `meridian send` path
today — it's tested in isolation but the shipped CLI bypasses it for a coarser whole-file check). One
should-fix item corrects a **stale carry-forward**: the `netns-kill-resume.sh` PID false-negative the
phase-11 README (following the master tracker) still listed as live was in fact already fixed by task
10.23 — confirmed by direct code reading, not re-litigated.

Zero on-the-fly decisions need `/adr` ratification. **Verdict: blocked until F1 lands** (a real,
reachable substrate defect, not theoretical), then green for the next build phase.

## Findings
Severity: **blocking** (must fix before next build) · **should-fix** (fix this review phase) · **nit** (optional).

| # | Severity | Area / file | Finding | Recommended fix | → Fix-task |
|---|----------|-------------|---------|-----------------|-----------|
| F1 | blocking | `apps/core/src/session.rs` (`open_stream`, `next_sid`, `handle_ctrl`'s `Open`/`Accept` arms, `stream_channel_label`) | Concurrent bidirectional `open_stream` calls for the same stream type (e.g. two peers each sending the other a file at once) race to the same `sid`: both sides independently increment a purely-local counter with no coordination, so `stream_channel_label` (`"{ty}#{sid}"`) collides. On `LoopbackTransport` this silently cross-delivers one transfer's frames into the other's `on_frame` handler (first-match `find` in `LoopbackFabric::send`); on the real WebRTC backend, two distinct `RTCDataChannel`s end up negotiated onto the same SCTP stream id, since `add_data_channel`'s collision guard only rejects *different* labels hashing to the same id, not an identical label reused. Deterministically reproducible today with `LoopbackTransport` alone. | Namespace the `sid` (or the derived label) by which side originated the open — reuse the identity-key lexicographic tie-break already established for the dial/answer role and `ice_restart` glare (e.g. even `sid`s for the smaller-key identity, odd for the larger), or add an explicit originator marker to `stream_channel_label`. This is a pinned wire-shape derivation other stream types will also rely on — needs **architect** sign-off, not just a code fix. | 11.1 |
| F2 | should-fix | `apps/core/src/session.rs` (`restart_offer_and_await_answer`, `answer_restart_offer`) | The original dial/answer handshake calls `enforce_relay_only(policy, &ice)` on freshly-gathered ICE candidates *before* sealing/sending them (fail-closed defense-in-depth against a transport bug leaking a host/srflx candidate under `relay-only` policy — this is F20's own stated reason for existing). The `ice_restart` signaling path (ADR 0025, task 10.22) also gathers and sends fresh candidates on every restart but never calls `enforce_relay_only` on them. Not exploitable today only because the real backend sets `RTCIceTransportPolicy` once at construction and never recreates the `RTCPeerConnection` on restart — but that "assume from construction" is exactly what the original check was written not to trust. | Call `enforce_relay_only(self.policy, &ice)?` immediately after each `candidate_strings(...)` call in both restart functions, mirroring the original handshake's existing call sites exactly (same fail-closed teardown semantics). Add a test exercising `ice_restart` under `IcePolicy::RelayOnly` with a transport stub injecting a non-relay post-restart candidate, asserting `RelayOnlyViolation` and nothing sent. | 11.2 |
| F3 | should-fix | `apps/streams/src/file.rs` (`on_frame`, `TransferState::pending_chunks`) | Inbound chunk frames are buffered into an unbounded `Vec<Vec<u8>>` with no size cap and no dedup — a duplicate/retransmitted chunk (expected on a reliable-unordered channel) is appended again rather than replacing/ignored. `run_responder`'s own completion check rescans this list end-to-end on every pump event. An already-accepted peer that floods tiny chunk frames can grow this unboundedly, bounded only by consumer drain speed. | Bound `pending_chunks` or convert it to an index-keyed map (matching `apps/streams/src/receiver.rs::FileReceiver`'s already-correct approach) before this buffering pattern gets copied by a second stream type. | 11.3 |
| F4 | should-fix | `apps/cli/src/send.rs` (`finalize_transfer`, `run_responder`) | The real production receive path's own module doc asserts "a single bit-flip anywhere still fails this check and the file is never written," but no test actually flips a chunk's ciphertext and drives it through `run_responder`/`finalize_transfer`. The one "never written on failure" CLI test only exercises a wrong *declared manifest root*, never a tampered per-chunk AEAD payload — a different code branch (`open_chunk(...).map_err(...)`) is untested. The underlying AEAD primitive is independently proven elsewhere (`chunk.rs`'s own tests), but the CLI's own claimed property isn't pinned by a regression test at the layer that actually ships. | Add a variant of the existing `send_and_receive_round_trip_over_loopback_is_byte_identical` harness that flips one ciphertext byte in one `tagged_chunk_frame` (reusing `corrupted_chunk_adversarial.rs`'s technique) and asserts `run_responder` returns an authentication error with no file written. | 11.4 |
| F5 | should-fix | `apps/streams/tests/resume_protocol.rs` | Every resume test uses a contiguous prefix/suffix split or a scattered-but-partial miss (8/13, 10/13, {2,5,9} of 13). Resume at **0 chunks received** (full resend) and resume at **all-but-last chunk** (exercising the short final-chunk-size boundary) are both untested end-to-end, though the bitmap-encoding-level unit test for the empty case exists in isolation. | Add both boundary cases as full pipeline tests (through `ResumeRequest`/`send_missing_chunks`, not just the bitmap encoder). | 11.5 |
| F6 | should-fix | `apps/core/src/session.rs` (`ice_restart`, `RESTART_GLARE_WINDOW`) | The larger-key side's "glare window elapses with no incoming offer, so this side falls through to offering itself" branch (~lines 952–968) has zero test coverage anywhere in the tree — every existing `ice_restart` test has both sides call concurrently or pre-seeds a signal, so the timeout-then-fallback path never fires. This is real, reachable production code, not a theoretical branch. | Make `RESTART_GLARE_WINDOW` injectable (a parameter or `#[cfg(test)]` override) so a test can force the timeout deterministically and assert the fallback still completes a working restart, rather than leaving this branch proven only by code review. | 11.6 |
| F7 | should-fix | `test-vectors/` | No conformance vectors exist for any of this phase's new wire surfaces: the `mrd.file/1` manifest CBOR encoding, the BLAKE3 merkle chunk framing, the resume-bitmap wire shape, the per-stream HKDF-export primitive's `info` byte layout, or `SignalContent::IceRestartOffer`/`Answer`. Not yet a live interop bug (no second client exists), but T09 is the sole gate for T11 (browser/desktop), which is exactly when an unpinned encoding turns into a silent divergence. | Regenerate `test-vectors/` to add fixtures for each of the four wire shapes above, following the existing `ratchet-v2.json`/`envelope-v2.json` pattern (byte-fixed, `xtask`-regenerated). | 11.7 |
| F8 | should-fix | `apps/streams/src/receiver.rs` (`FileReceiver`) vs. `apps/cli/src/send.rs` (`finalize_transfer`) | `FileReceiver`'s incremental per-chunk merkle verification — the engine task 10.16's adversarial test actually targets, and the mechanism the feature spec's "incremental subtree verification" deliverable names — has **no live caller** in the real `meridian send` path. The shipped CLI bypasses it entirely for a coarser whole-file-at-the-end check (`finalize_transfer`), because no per-chunk proof ever reaches the wire (the pre-existing, already-documented "no pinned wire delivery mechanism" carry-forward). Net effect: the incremental-verification deliverable is unreachable through the one real production code path today, not just missing a wire format. | Either wire a real proof-delivery mechanism (extending the chunk wire shape, or a bulk-proof-set exchange over `mrd.ctrl/1`, per `receiver.rs`'s own doc) so `FileReceiver` gets a genuine caller, or explicitly narrow the feature's claimed deliverable until it does. Elevated from a doc-only carry-forward to should-fix since the practical consequence (unreachable code path, coarser real verification than advertised) goes beyond documentation. | 11.8 |
| F9 | should-fix | `docs/testing/soak-file-transfer-throughput.md`, `.github/workflows/soak-file-transfer.yml` | The soak doc honestly records what ran (loopback 2 MiB/64 MiB pass) and what didn't (1 GiB incomplete, 10 GiB never attempted, no real netem-affected run — this sandbox lacks `CONFIG_NET_SCH_NETEM`). The scheduled CI soak workflow was documented as "expected red until the SCTP fix lands" — that fix (10.18) has since landed on this branch, so the workflow's real pass/fail state on an actual runner is now the load-bearing signal for the spec's own throughput numbers, and nothing in this sweep could confirm it has actually run clean post-fix. | Confirm (devops-owned) that `soak-file-transfer.yml` has executed successfully on a real runner since 10.18 landed; update the doc's `TODO: confirm` once observed, consistent with the existing precedent for CI-config facts no agent session can verify. | 11.9 |
| F10 | should-fix | `.github/workflows/` (missing), `tools/netns-kill-resume.sh` | No CI workflow runs the kill/resume rig at all, unlike its two sibling rigs (`netns-netem-smoke.yml`, `soak-file-transfer.yml`). Task 10.15's own file explains the omission was deliberate at the time (the then-blocking SCTP defect meant `run`/`probe` would fail every scheduled run) — but that defect was fixed by 10.18, and the scenario was subsequently proven passing live multiple times (10.23: 3/3, 10.24: 2/2 further). Nobody revisited the original call after the blocker cleared. | Add a scheduled/`workflow_dispatch` `netns-kill-resume.yml` mirroring the two sibling workflows now that the rationale for omitting it no longer holds. | 11.10 |
| N1 | nit | `apps/cli/src/send.rs` (`run_responder`) | `distinct_chunk_indices` rescans all of `pending_chunks` from scratch on nearly every pump event — O(n) per event, quadratic overall for a transfer with many chunks/retransmits. Not a correctness bug; worth a follow-up before a large real-file soak run, and naturally resolved if F3's buffer restructuring lands. | Fold into 11.3 (F3) rather than a separate task — same data structure. | (11.3) |
| N2 | nit | `apps/transport/src/loopback.rs` (`ice_restart`), ADR 0025 / task 10.19 wording | `LoopbackTransport::ice_restart` is documented as an "explicit, documented no-op" but actually mutates `ice_generation` and re-gathers `local_candidates` — functionally inert (nothing meaningful to restart over a fake network) but the "no-op" label overclaims next to what the code does. Pre-existing wording, not new drift. | Tighten the doc comment on `LoopbackTransport::ice_restart` itself next time that file is touched — not urgent enough for its own task. | (deferred) |
| N3 | nit | `apps/crypto/src/ratchet.rs` (`encrypt_and_export`/`decrypt_and_export`), `apps/core/src/session.rs` (`send_stream_frame`) | The per-stream HKDF-export primitive (task 10.1) is fully built, tested, and correctly zeroizes its output — but has no live consumer today: the exported key is computed and then immediately discarded (zeroized) rather than used by anything, since `mrd.file/1`'s own `k_f` is independently random, not ratchet-derived. Dead capability, not a defect. | No action needed — informational only, correctly a byproduct of a clean design (no accidental coupling of file-chunk keys to ratchet chain-sync state). | (none) |
| N4 | nit | `apps/streams/src/file.rs` (`FileStream::watch_resume`) | No test sends two resume bitmaps back-to-back (e.g. duplicate/racing resume triggers after a glare-resolved restart) to check the resume-notification channel doesn't drop or misorder a second message. Low priority: no design doc claims exactly-once resume-request semantics. | Optional — pick up only if capacity allows. | (deferred) |
| N5 | nit | `apps/core/src/session.rs` (`handle_ctrl`'s `Close` arm) | Re-confirmed still true from task 10.4's own recorded residual (not previously surfaced to the master tracker's carry-forward list): `CtrlFrame::Close` only removes the `open_streams` entry, leaving `labels`/`channel_of_stream`/`stream_channels` dangling. Currently dormant/unreachable — no code in this phase ever sends `Close` for a file transfer (only the pre-existing capability-mismatch teardown path sends it, unrelated to `mrd.file/1`). | No action needed this phase given it's unreachable today; promote to the master tracker's carry-forward list so it's visible for whoever next drives a stream type that does send `Close` mid-session. | (carry-forward) |

## On-the-fly decisions to ratify
None. The one candidate — task 10.22's mid-phase fix to `ice_restart`'s offer/answer signaling
(replacing the commit-state-inference heuristic with a new, unconditional `Transport::set_remote_offer_and_answer`
method, and removing a redundant self-restart call on the answerer's own side) — was independently
re-derived by the architect lens directly from the current code and ADR 0025's Decision text: the wire
shape, tie-break rule, tolerant-delivery contract, and layered fingerprint check are all unchanged: only
*how* the existing `Transport` trait was being (mis)used internally changed. This is a bugfix within
ADR 0025's existing scope, not a design change, so no `/adr` update or supersession is needed.

## Coverage / test gaps
Summarized from the should-fix table above (F4–F7, F9, F10) plus:
- **Actual test runs, all green**: `meridian-streams` (68 tests), `meridian-core` default + `--features
  webrtc` (all files, including 20/20 `p2p_session.rs` + 4/4 `p2p_session_webrtc.rs` incl. the
  regression test for 10.22's own found-and-fixed bug), `meridian-transport` default (8/8) +
  `--features webrtc` (11 unit + 10 integration, incl. the transport-level regression for the same
  10.22 bug and `multi_chunk_file_transfer_completes_over_real_sctp`), `meridian-tui` (173 unit + ~430
  integration). No `#[ignore]`d tests found in any touched crate; CI (`ci.yml`) runs the identical test
  set.
- **`RESTART_GLARE_WINDOW` mutual-timeout race and the post-restart DTLS/SCTP readiness race** (both
  already-recorded carry-forwards): re-confirmed genuinely untested — the readiness race's one
  reproduction artifact (`apps/cli/examples/netns_ice_restart_probe.rs`) is a standalone example, not a
  `#[test]`, not wired into any CI workflow. Both remain correctly characterized as non-blocking
  reliability gaps, not security-relevant (security-reviewer independently confirmed neither can produce
  a *weaker* session, only "no session," consistent with the threat model's own goal 6).
- **Stale carry-forward correction (not a new gap)**: the phase-11 README's carried-forward
  `tools/netns-kill-resume.sh` PID-length false-negative is **already fixed** — task 10.23 zero-pads the
  PID to 6 digits, confirmed by direct reading of the current script and its own comment trail. The
  master tracker's "Live carry-forwards" section should drop this item rather than continue carrying it
  as live; no fix-task needed.

## Verdict
**Blocked until F1 lands** — the concurrent-`open_stream` `sid` collision is a real, deterministically
reproducible substrate defect (not theoretical), and `mrd.file/1` is registered exactly `Bidir`, the
shape that triggers it. F1 needs architect sign-off on the fix's wire-shape derivation before or as part
of its own task, matching the Phase-7/Phase-10 precedent for a phase-exit-blocking finding found during
review rather than silently downgraded. Once F1 lands (and is re-reviewed clean), this phase is green to
proceed — the should-fix items (F2–F10) are real but none are a live security exploit or correctness
defect blocking the next build phase (T10 or T14) on their own.
