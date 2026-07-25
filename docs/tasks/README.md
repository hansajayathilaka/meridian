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

- **NOW:** Phase 1 fix-tasks landing — Group A (1.1-1.4) done. Group B done (1.5-1.7). Group C done (1.8-1.12).
  Group D: honesty fixes done (1.13, 1.14); webrtc-rs `Transport` backend done (1.15 — real ICE/SCTP/DTLS,
  gated tests wired into CI/Justfile; ICE-restart-on-real-network-change and relay-transport
  classification are documented, scoped-out gaps, see the task file); observed-candidate relay-only
  enforcement done (1.16 — F20 closed; the netns/tcpdump wire-level matrix that was 1.16's other
  deliverable turned out to need its own CLI transport wiring first, so it split into **1.22** (CLI
  `--transport webrtc`) and **1.23** (the matrix itself); **1.22** done (`--transport <loopback|webrtc>`
  on `meridian session demo`, gated `webrtc` cargo feature on `meridian-cli`, PR #25). **1.23** was then
  itself split *before* implementation — its "drive two real peers using 1.22's flag" premise assumed
  cross-process signaling that doesn't exist yet (`session demo` runs both peers in one process) — into
  **1.24** (real-signaling `SignalRelay` + `session connect` CLI, depends on 1.22), **1.25** (netns
  topology + NAT-flavor emulation + coturn/rendezvous orchestration, depends on 1.14, parallel to 1.24),
  **1.26** (drive real peers + capture pcaps, depends on 1.24+1.25), and **1.27** (pcap-analysis
  assertions + CI wiring — the task that actually closes F11's wire-level half, depends on 1.26). A fifth
  item flagged during the split (an active relay-rewrite adversarial test against the rendezvous) is
  tracked separately as **1.28**, not part of F11's closure. **1.24** and **1.25** are both done. **1.26**
  was run against the real rig: its own harness (topology-driving, per-cell relay policy, tcpdump
  bracketing, predictable pcap naming, path/transport/role summaries) all work correctly, but its
  "all four cells connect" deliverable surfaced two real connectivity bugs the harness was designed to
  catch — an ICE candidate-pair-nomination stall under `direct`/`prefer-relay` (root-caused: permanently-
  unreachable host/srflx pairs never reach a terminal `Failed` state, so the agent never falls through to
  the relay pair that works fine on its own) and a TURN-over-TCP client gap under `relay-only` +
  `udp-blocked` (root-caused: the pinned `webrtc-ice` 0.17.1 has zero client-side TURN/TCP support at all,
  confirmed by reading its source). Per architect review these were carved out — not silently folded in or
  dropped — as **1.29** (nomination stall) and **1.30** (TURN/TCP gap); both are now done. **1.29** shipped
  a session-level relay-only retry fallback (`apps/core/src/session.rs`, architect-signed-off) after a
  config-level timeout tweak alone proved insufficient. **1.30** confirmed no upstream `webrtc-ice` release
  (checked through 0.17.2) adds TURN/TCP support, so documented `udp-blocked + relay-only` as a proven,
  currently-unsupported dependency limitation and added a bounded timeout so it now fails fast (~20-50s)
  instead of hanging. Re-run against both fixes: `full-cone`/`port-restricted`/`symmetric:symmetric` all
  connect for real (`path=relay`); `udp-blocked` still can't connect but fails fast and cleanly. Per
  architect sign-off, 1.26's "all four cells connect" criterion was explicitly amended (3/4 connect for
  real, 4th is a documented upstream ceiling, not a task failure) — **1.26 is now done**. **1.27**
  (pcap-analysis assertions + CI/harness wiring) is also now done, turning 1.26's captures into strict,
  fail-closed pass/fail checks (path/rung corroboration, zero host/srflx-leak gated on relay-only policy,
  DTLS-ciphertext-only, udp-blocked fails-fast) and wiring `harnesses/nat-matrix/run.sh` to build+run them
  in CI. Personally re-verifying it against the live rig (not just the implementing agent's self-report)
  surfaced and fixed two more real bugs — a prekey-bundle publish/fetch race on reconnect (rig-scoped fix
  landed here; the underlying, out-of-scope race in `session_connect.rs` is tracked separately as
  **1.31**, not part of F11's closure) and a CI-harness build-order gap that silently dropped the
  `webrtc` feature before the rig ran. security-reviewer and connectivity-debugger's required reviews
  each found one more real gap in the assertions themselves (a fail-open on an unreadable pcap; assertion
  (b) gated on the wrong variable), both fixed before merge; a known, honestly-documented residual gap
  (the actually-connecting relay session for the 3 fallback cells isn't yet independently wire-verified
  for zero-leak, only `udp-blocked`'s trivial case is) is recorded in 1.27's task file rather than
  papered over. **Group D (1.13-1.16, 1.22-1.30) is now fully done — F11 (wire-level) is fully closed.**
- **NEXT:** Group D is complete. The blocking gate for Phase 2 (F1, F2, F3, F10, F11) is now fully
  satisfied — `/pick-next-phase` can select Phase 2 (T06 Cross-Org Federation) per the Phase 1 Goal's
  verdict. Phase 1 itself isn't fully `[x]` yet: Group E's should-fix/nit items remain pending — **1.17**
  (deniability ADR), **1.18** (desync recovery decision), **1.19** (5k-connection capacity test), **1.20**
  (server-hardening bundle), **1.21** (coverage tooling), **1.28** (active relay-rewrite adversarial
  test), and the newly-added **1.31** (prekey-bundle republish race, found during 1.27's verification) —
  run **`/next-task`** to continue with Group E, or **`/pick-next-phase`** to start Phase 2 in parallel
  per the Goal's explicit blocking-vs-should-fix distinction.
- After Phase 1 fixes fully land (Group E too): exit criteria are met per
  [phase-1/README.md](./phase-1/README.md)'s Exit criteria section.

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
- [~] **1.17** ADR — deniability vs envelope signature (on-the-fly) — [file](./phase-1/1.17-adr-deniability-envelope-sig.md)
- [~] **1.18** Desync → fresh-X3DH auto-recovery decision (F13, on-the-fly) — [file](./phase-1/1.18-desync-recovery-decision.md)
- [~] **1.19** 5k-connection capacity test (F12) — [file](./phase-1/1.19-capacity-test-5k.md)
- [~] **1.20** Server-hardening bundle (F21) — [file](./phase-1/1.20-server-hardening-bundle.md)
- [~] **1.21** Coverage tooling or drop the % (F22) — [file](./phase-1/1.21-coverage-tooling.md)
- [~] **1.28** Active relay-rewrite adversarial test (on-the-fly, flagged during 1.23's split; not part of F11's closure) — [file](./phase-1/1.28-active-relay-rewrite-test.md)
- [~] **1.31** Prekey-bundle republish/fetch race on reconnect (on-the-fly, found during 1.27's live-rig verification; not part of F11's closure) — [file](./phase-1/1.31-prekey-bundle-republish-race.md)

---

## Legend / how to read
- Each task line links to its own file with **Goal · Scope · Deliverables · Risks · Tests · Reviews · Status**.
- Phase folders (`phase-N/`) hold a `README.md` (phase overview + todo) and one file per task; review
  phases also hold a `review-report.md`.
- Definition of Task and Definition of Done: [CONTRIBUTING.md](../../CONTRIBUTING.md).
