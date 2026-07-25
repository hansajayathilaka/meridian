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

- **NOW:** **Phase 1 Group E's original 7 tasks are all done** (1.17-1.21, 1.28, 1.31), so every
  numbered task from the Phase-1 review report (F1-F22) plus the on-the-fly decisions is now closed.
  Highlights, with the review findings that changed the work:
  **1.17** — ADR 0016 accepted: envelope **v2 drops the per-message identity-key signature** so
  transcripts become deniable; Phase 1 lands doc-honesty edits only, the wire is unchanged.
  security-reviewer returned APPROVE-WITH-CHANGES and corrected a *backwards* KCI residual (an
  SPK-compromise attacker can **forge** a first-contact session but **cannot read** the genuine one,
  so v2 is a strict capability gain for the attacker), established that the signature is load-bearing
  for the prekey preamble (the AEAD fails closed only *after* the OTK is consumed and the session
  inserted → commit-on-successful-decrypt is now normative), required `AD` stay raw Ed25519 (the
  Montgomery map drops the sign bit), and found the envelope has **no version field** to hang a flag
  day on. Binding conditions C1-C7 + residuals R1-R5 are in the ADR. It also surfaced that
  `wire-protocol.md` §3 carried a **second, divergent** envelope definition whose signing input
  omitted `sender_pub` — reconciled. And that `envelope/signal.rs` wrongly credited the DTLS
  fingerprint to the envelope signature (it is bound by the ratchet AEAD's `AD`) — corrected, and the
  reason v2 is a no-op for fingerprint binding.
  **1.18** — architect call: **defer** receiver-side desync auto-recovery to Feature 08 on
  dependency-order grounds (reacting to undecryptable traffic is an attacker-triggerable
  session-reset / skipped-key-destruction / prekey-depletion oracle, and its re-handshake fetches a
  bundle, so it cannot precede block-on-key-change). Adds `ChatError::Desync` for diagnosability
  (no rejection decision changes) and a test asserting the session is **byte-identically** unchanged
  after a rejected undecryptable envelope.
  **1.19** — wrote the `--ignored` 5k capacity test that the code *referenced but did not have*.
  **2,000** concurrent connections demonstrated in 0.82 s; 5k is untestable in this container (hard
  fd limit 4096) and is recorded as **neither demonstrated nor disproven** rather than downgraded.
  **1.20** — `lint-server-no-core.sh` is now a structural `cargo tree` check (proven on a real planted
  dep: adding only `meridian-signaling` surfaced `-identity` and `-store` *transitively*, which the old
  grep could never see); salted per-process `LogId` + a tracing lint landed **ahead of** observability;
  rate-limiter growth bounded by an amortised sweep that provably cannot reset a live budget.
  **1.21** — measuring coverage revealed the criterion was impossible, not merely unmeasured: **Rust on
  stable emits no branch coverage at all**. Tooling added (`just coverage`, non-blocking CI job) and the
  "≥90% branch" figure replaced with measured numbers (`id.rs` 91.58% region; workspace 75.98%).
  **1.31** — prekey-generation retention bounded (one generation + 60 s); 3 of the 4 new tests were
  confirmed to **fail against the old code**, so they genuinely reproduce the bug.
  **1.28** — active relay-rewrite adversarial test; security-reviewer APPROVE-WITH-CHANGES, all 5
  required changes applied. Its most valuable finding was not about 1.28 at all: **task 1.12's
  compile-gate guard had never run in CI**, because resolver-2 unification turns `test-tamper-hook` on
  workspace-wide whenever dev targets build (`apps/cli`'s dev-dep pins it), so every
  `cfg(not(feature))` guard was compiled out under `cargo test --workspace`. Now there is a
  package-scoped default-features CI step, two new inertness tests, and a feature-resolution F17 check
  (an `nm`-symbol check was **rejected** as a fake gate — measured, it passes whether the feature is on
  or off). It also caught that 1.28's own test could pass vacuously; the outcome is now pinned to
  `Rejected(Chat(BadSignature))` on the responder specifically.
- **NEXT:** Two follow-ups **surfaced by Group E's own reviews** are filed and pending — **1.32**
  (relay attacks that *pass* the signature check: forged `Deliver.from`, replay, reorder,
  cross-delivery — to be folded into ADR 0016's existing mitm-sim test obligations, one thread not two)
  and **1.33** (bound the dialer's unbounded `recv_sdp` wait; availability/diagnostics only). Neither
  is blocking: Phase 2's gate (F1, F2, F3, F10, F11) was already fully satisfied by Group D, and both
  are should-fix/nit class. **Decision for the user:** fold 1.32/1.33 into Phase 1 before closing it,
  or defer them and run `/pick-next-phase` to start **Phase 2 (T06 Cross-Org Federation)** now. Phase 1
  cannot be marked fully `[x]` while they are open.
- Phase 1's other exit criteria are met: tree green (`cargo test --workspace` 45 suites / 0 failures,
  `cargo clippy --workspace --all-targets -D warnings` clean), all four invariant lints + their
  selftests pass, docs synced (`tools/check-docs.sh`, 1222 links, none broken).

---

## Phases

### Phase 0 — Foundation · **done** · [details](./phase-0/README.md)
Trust-critical substrate: identity, E2EE messaging, P2P session, NAT traversal. Recorded retroactively.
- [x] **0.1** Identity & Keystore Core (T01) — [file](./phase-0/0.1-identity-keystore.md)
- [x] **0.2** Rendezvous Server MVP (T02) — [file](./phase-0/0.2-rendezvous-mvp.md)
- [x] **0.3** E2EE Messaging, relayed (T03) — [file](./phase-0/0.3-e2ee-messaging.md)
- [x] **0.4** P2P Session Substrate (T04) — [file](./phase-0/0.4-p2p-session-substrate.md)
- [x] **0.5** NAT Traversal & Relay Policy (T05) — [file](./phase-0/0.5-nat-traversal-relay.md)

### Phase 1 — Review of Phase 0 · **in progress** · [details](./phase-1/README.md)
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
- [ ] **1.32** Relay attacks that PASS the envelope signature check (from-spoof / replay / reorder / cross-delivery; from 1.28's security review, fold into [ADR 0016](../adr/0016-envelope-deniability.md)'s test obligations) — [file](./phase-1/1.32-relay-attacks-past-signature.md)
- [ ] **1.33** Bound the dialer's wait for an answer in `recv_sdp` (availability/diagnostics; from 1.28) — [file](./phase-1/1.33-bound-answer-wait.md)

---

## Legend / how to read
- Each task line links to its own file with **Goal · Scope · Deliverables · Risks · Tests · Reviews · Status**.
- Phase folders (`phase-N/`) hold a `README.md` (phase overview + todo) and one file per task; review
  phases also hold a `review-report.md`.
- Definition of Task and Definition of Done: [CONTRIBUTING.md](../../CONTRIBUTING.md).
