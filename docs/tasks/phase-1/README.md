<!-- Copy this file to docs/tasks/phase-N/README.md. Created by /pick-next-phase (build) or
     /start-review-phase (review); the todo list is filled by /plan-phase or /plan-review-phase. -->
> **Nav:** [tracker](../README.md) · [roadmap](../../architecture/roadmap.md) · [features](../../architecture/features/)

# Phase 1 — Review of Phase 0

**Kind:** review · **Status:** in progress · **Reviews phase(s):** Phase 0 (Features 1–5, T01–T05)

## Goal
Sweep everything built in Phase 0 for bugs, gaps, loopholes, and on-the-fly decisions, then close the
actionable findings. The sweep is done ([review-report.md](./review-report.md), findings F1–F22); this
phase turns those findings into fix-tasks and lands them. Verdict: **blocked until F1, F2, F3, F10, F11
resolved** before Feature 10 (media) or Phase 2 (T06 federation) stacks further work.

## Chosen feature(s) / scope
Fix-tasks derived from [review-report.md](./review-report.md). Ordering follows the Verdict's priority
chain: doc/ADR truth → freeze the crypto → make the gates real → close Features 4/5 honestly →
design decisions + remaining should-fix/nit.

## Dependency check
The Phase 0 build is complete; its review report is written. Fix-tasks are unblocked now. Internal
dependencies between fix-tasks are declared per task (notably 1.2→1.1, 1.15→1.13/1.3, 1.16→1.15/1.14,
1.22→1.15, 1.24→1.22, 1.25→1.14, 1.26→1.24/1.25, 1.27→1.26). 1.23 was split before implementation into
1.24-1.27 (see [1.23](./1.23-netns-nat-matrix.md)'s Status); 1.24 and 1.25 were independent of each other
and proceeded in parallel — both are now done. 1.26 was attempted (needs both); its own harness/tcpdump/pcap
deliverables work, but its "all four cells connect" deliverable surfaced two real connectivity bugs against
the real backend, carved out (not silently folded in or dropped) as **1.29** and **1.30** — both are now
done, and a re-run against both fixes confirms 3/4 cells connect for real, with the 4th failing fast per an
architect-approved amendment to 1.26's deliverable (see [1.26](./1.26-netns-drive-and-capture.md)'s Status).
1.26 is now done; 1.27 is next.

## Tasks (todo)
<!-- Status marks: [ ] pending [~] in progress [x] done [!] blocked -->

**Group A — Doc/ADR truth restoration** (blocking)
- [x] **1.1** ADR 0015 — ratchet composition (F2) — [file](./1.1-adr-0015-ratchet-composition.md)
- [x] **1.2** Doc-sync: purge stale "ratchet = vodozemac" (F3) — [file](./1.2-doc-sync-vodozemac.md)
- [x] **1.3** Reconcile T03/T04/T05 specs with composed ratchet + wire-deferral (F9) — [file](./1.3-reconcile-transport-crypto-specs.md)
- [x] **1.4** Repair roadmap "Phasing" splice + ADR 0013 tail (F19) — [file](./1.4-repair-roadmap-splice.md)

**Group B — Freeze the crypto** (blocking / should-fix)
- [x] **1.5** Zeroization gaps: X3DH master secret + ratchet header keys (F5, F6) — [file](./1.5-crypto-zeroization-gaps.md)
- [x] **1.6** Conformance vectors: X3DH / ratchet / envelope / safety numbers + CI (F1) — [file](./1.6-conformance-vectors.md)
- [x] **1.7** SecretStore KDF op — drop signature-determinism dependency (F7) — [file](./1.7-secretstore-kdf-op.md)

**Group C — Make the gates real** (should-fix)
- [x] **1.8** Real CI gates: deny.toml + cargo-deny + blocking clippy (F4, F18) — [file](./1.8-ci-blocking-gates.md)
- [x] **1.9** Metrics-allowlist exhaustiveness test (F14) — [file](./1.9-metrics-exhaustiveness.md)
- [x] **1.10** Harden no-serde-on-blob lint (F15) — [file](./1.10-no-serde-blob-lint.md)
- [x] **1.11** Re-point opacity-audit harness gate (F8) — [file](./1.11-opacity-harness-gate.md)
- [x] **1.12** Rendezvous fail-closed config + feature-gate tamper hook (F16, F17) — [file](./1.12-rendezvous-fail-closed.md)

**Group D — Close Features 4/5 honestly** (blocking; honesty cheap, backend weeks)
- [x] **1.13** Feature 4 honesty: transport label + SDP test (F10 honesty) — [file](./1.13-feature4-honesty.md)
- [x] **1.14** Feature 5 honesty: coturn user-quota + credential-reuse wording (F11 honesty) — [file](./1.14-feature5-honesty.md)
- [x] **1.15** webrtc-rs `Transport` backend (F10 backend) — [file](./1.15-webrtc-backend.md)
- [x] **1.16** Observed-candidate relay-only enforcement (F20) — [file](./1.16-nat-acceptance-matrix.md)
- [x] **1.22** `meridian` CLI: `--transport webrtc` wiring (F11 wire, prerequisite; split from 1.16) — [file](./1.22-webrtc-cli-transport.md)
- [x] **1.23** ~~NAT/relay wire-level acceptance matrix~~ — split before implementation into 1.24-1.27 (see file) — [file](./1.23-netns-nat-matrix.md)
- [x] **1.24** Real-signaling `SignalRelay` + `session connect` CLI (F11 wire, prerequisite; split from 1.23; depends on 1.22) — [file](./1.24-real-signaling-p2p-cli.md)
- [x] **1.25** netns topology + NAT-flavor emulation + coturn/rendezvous orchestration (F11 wire; split from 1.23; depends on 1.14) — [file](./1.25-netns-topology-coturn.md)
- [x] **1.26** Drive real peers across the topology + capture pcaps (F11 wire; split from 1.23; depends on 1.24, 1.25) — 3/4 cells connect for real, 4th documented (see file) — [file](./1.26-netns-drive-and-capture.md)
- [ ] **1.27** pcap-analysis assertions + CI/harness wiring — closes F11 wire-level (split from 1.23; depends on 1.26) — [file](./1.27-pcap-assertions-ci.md)
- [x] **1.29** ICE candidate-pair nomination stall under direct/prefer-relay (F11 wire; carved out of 1.26; depends on 1.26) — [file](./1.29-ice-nomination-relay-fallback.md)
- [x] **1.30** TURN-over-TCP client gap under relay-only + udp-blocked (F11 wire; carved out of 1.26; depends on 1.26) — [file](./1.30-turn-tcp-dependency-gap.md)

**Group E — Design decisions + remaining should-fix / nit**
- [ ] **1.17** ADR — deniability vs envelope signature (on-the-fly) — [file](./1.17-adr-deniability-envelope-sig.md)
- [ ] **1.18** Desync → fresh-X3DH auto-recovery decision (F13, on-the-fly) — [file](./1.18-desync-recovery-decision.md)
- [ ] **1.19** 5k-connection capacity test (F12) — [file](./1.19-capacity-test-5k.md)
- [ ] **1.20** Server-hardening bundle (F21) — [file](./1.20-server-hardening-bundle.md)
- [ ] **1.21** Coverage tooling or drop the % (F22) — [file](./1.21-coverage-tooling.md)
- [ ] **1.28** Active relay-rewrite adversarial test (on-the-fly, flagged during 1.23's split; not part of F11's closure) — [file](./1.28-active-relay-rewrite-test.md)

## Exit criteria
All fix-tasks `[x]`, tree green (`just build` + `cargo clippy -D warnings` clean), docs synced. Blocking
findings F1, F2, F3, F10, F11 closed — for F10/F11 this means 1.13–1.16, 1.22, and 1.24–1.30 landed
(backend 1.15 and the netns/tcpdump matrix chain 1.24–1.30 are the tasks that may span multiple PRs; 1.23
itself was split before implementation, see its file; 1.29/1.30 were similarly carved out of 1.26 once real
connectivity bugs surfaced against the real backend, per their files' Status sections). Then
`/pick-next-phase` selects Phase 2 (T06 federation).

## Finding → fix-task map
| F | Sev | Task | F | Sev | Task |
|---|-----|------|---|-----|------|
| F1 | blocking | 1.6 | F12 | should-fix | 1.19 |
| F2 | blocking | 1.1 | F13 | should-fix | 1.18 |
| F3 | blocking | 1.2 | F14 | should-fix | 1.9 |
| F4 | should-fix | 1.8 | F15 | should-fix | 1.10 |
| F5 | should-fix | 1.5 | F16 | should-fix | 1.12 |
| F6 | should-fix | 1.5 | F17 | should-fix | 1.12 |
| F7 | should-fix | 1.7 | F18 | should-fix | 1.8 |
| F8 | should-fix | 1.11 | F19 | should-fix | 1.4 |
| F9 | should-fix | 1.3 | F20 | nit | 1.16 |
| F10 | blocking | 1.13 + 1.15 | F21 | nit | 1.20 |
| F11 | blocking | 1.14 + 1.22 + 1.24 + 1.25 + 1.26 + 1.27 + 1.29 + 1.30 | F22 | nit | 1.21 |

On-the-fly decisions: ratchet composition → 1.1 (ADR 0015); deniability vs envelope signature → 1.17
(ADR); desync auto-recovery → 1.18; active relay-rewrite adversarial test (flagged during 1.23's split,
not part of F11's closure) → 1.28; ICE nomination stall + TURN-over-TCP dependency gap (both found while
running 1.26 against the real backend, root-caused by connectivity-debugger, scoped by architect) → 1.29,
1.30. **No action** (already recorded as deferred): threat-model goal 2 key-substitution half → Feature 8.
