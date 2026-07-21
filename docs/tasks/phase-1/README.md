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
1.22→1.15, 1.23→1.22/1.14).

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

**Group D — Close Features 4/5 honestly** (blocking; honesty fixes cheap, backend weeks)
- [x] **1.13** Feature 4 honesty: transport label + SDP test (F10 honesty) — [file](./1.13-feature4-honesty.md)
- [x] **1.14** Feature 5 honesty: coturn user-quota + credential-reuse wording (F11 honesty) — [file](./1.14-feature5-honesty.md)
- [x] **1.15** webrtc-rs `Transport` backend (F10 backend) — [file](./1.15-webrtc-backend.md)
- [x] **1.16** Observed-candidate relay-only enforcement (F20) — [file](./1.16-nat-acceptance-matrix.md)
- [x] **1.22** `meridian` CLI: `--transport webrtc` wiring (F11 wire, prerequisite; split from 1.16) — [file](./1.22-webrtc-cli-transport.md)
- [ ] **1.23** NAT/relay wire-level acceptance matrix (F11 wire; split from 1.16, depends on 1.22) — [file](./1.23-netns-nat-matrix.md)

**Group E — Design decisions + remaining should-fix / nit**
- [ ] **1.17** ADR — deniability vs envelope signature (on-the-fly) — [file](./1.17-adr-deniability-envelope-sig.md)
- [ ] **1.18** Desync → fresh-X3DH auto-recovery decision (F13, on-the-fly) — [file](./1.18-desync-recovery-decision.md)
- [ ] **1.19** 5k-connection capacity test (F12) — [file](./1.19-capacity-test-5k.md)
- [ ] **1.20** Server-hardening bundle (F21) — [file](./1.20-server-hardening-bundle.md)
- [ ] **1.21** Coverage tooling or drop the % (F22) — [file](./1.21-coverage-tooling.md)

## Exit criteria
All fix-tasks `[x]`, tree green (`just build` + `cargo clippy -D warnings` clean), docs synced. Blocking
findings F1, F2, F3, F10, F11 closed — for F10/F11 this means 1.13–1.16 and 1.22–1.23 landed (backend
1.15 and the netns/tcpdump matrix 1.23 are the tasks that may span multiple PRs). Then `/pick-next-phase`
selects Phase 2 (T06 federation).

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
| F11 | blocking | 1.14 + 1.22 + 1.23 | F22 | nit | 1.21 |

On-the-fly decisions: ratchet composition → 1.1 (ADR 0015); deniability vs envelope signature → 1.17
(ADR); desync auto-recovery → 1.18. **No action** (already recorded as deferred): threat-model goal 2
key-substitution half → Feature 8.
