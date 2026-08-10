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

- **NOW:** **Phase 3 Wave 3 is (all but 3.9) done and Wave 4 is fully done.** **3.1**–**3.8** and
  **3.10**–**3.14** all landed ([3.1](./phase-3/3.1-outbound-federation-policy.md),
  [3.2](./phase-3/3.2-inbound-accept-loop-hardening.md), [3.3](./phase-3/3.3-outbound-s2s-timeouts.md),
  [3.4](./phase-3/3.4-federation-test-support-harness.md), [3.5](./phase-3/3.5-fed-ratelimit-double-spend.md),
  [3.6](./phase-3/3.6-multi-san-peer-identity.md), [3.7](./phase-3/3.7-federation-link-reuse.md),
  [3.8](./phase-3/3.8-fed-delivery-metrics.md), [3.10](./phase-3/3.10-message-request-flood-bound.md),
  [3.11](./phase-3/3.11-first-contact-ctrl-gate.md), [3.12](./phase-3/3.12-ci-docker-build-gate.md),
  [3.13](./phase-3/3.13-wss-crypto-provider-test.md), [3.14](./phase-3/3.14-c2s-hint-conformance-vectors.md)).
  3.5 (fed ratelimit double-spend, F4) took three review rounds — see its Outcome. 3.6/3.7/3.8/3.11
  each closed with only trivial/zero findings; 3.13 and 3.14's combined reviews each independently
  reproduced their own mutation-checks (disabling the fix / corrupting a fixture byte) rather than
  taking the implementer's account on trust, both zero blocking findings. Phases 0–2 are **done**.
- **NEXT:** `/next-task` — **3.9** (dead per-partner `policy` field in `federation_map.toml`, F7) is
  the last item in Wave 3 and the only thing before Wave 5, but per its own file needs an **architect
  decision** before implementation (three materially different fixes on the table, no default named —
  see [phase-3/README.md](./phase-3/README.md#adr-obligations)); this is a genuine pre-implementation
  escalation, not a normal review gate.

### Live carry-forwards (not owned by any open task)
Everything else is owned by a Phase-3 task; these are the exceptions that would otherwise evaporate:
- **Envelope v2 must carry the replay-dedup obligation.** Phase 2 ships **zero s2s replay/dedup**,
  deferred entirely to envelope v2's `eid` per [ADR 0016](../adr/0016-envelope-deniability.md) C7
  (2.13 bounds a replay's harm to one failed decrypt). When Feature 08/09 is planned, this must
  appear in the envelope-v2 task's obligations.
- **The adversarial frontier carried from Phase 1** — SPK grace-window aging, stale-bundle replay on
  the fetch path, same-OTK-to-many-fetchers, reflection, per-device delivery, skipped-key exhaustion.
  Listed in [phase-3/README.md](./phase-3/README.md#findings-with-no-task-and-why); not a Phase-2
  regression, deliberately not scoped into Phase 3.
- **If `relay_rewrite.rs` ever flakes in CI**, widen its `SIDE_TIMEOUT`, **never** `ANSWER_TIMEOUT` —
  the test burns ~31 s real time with only ~4–5 s slack over the 30 s timeout it is exercising.
- **A human must confirm branch protection on `main` actually requires `ci.yml` to pass before
  merge** (`docs/operations/docker-image.md` §1) — no tool available to an agent session can read
  GitHub's branch-protection/ruleset config. 3.12 landed the pre-merge docker build gate itself but
  left this one sub-item open by design rather than guessing; check GitHub Settings → Branches/
  Rulesets and update that doc's `TODO: confirm` once observed.

> **Keep this section short.** Per-task outcomes, review sign-offs, and the decisions behind them
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

### Phase 3 — Review of Phase 2 · **in progress** · [details](./phase-3/README.md)
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
- [ ] **3.9** Resolve the dead per-partner `policy` field in `federation_map.toml` (F7) — [file](./phase-3/3.9-federation-map-policy-field.md)

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
- [ ] **3.21** Nit sweep (N1, N3) — [file](./phase-3/3.21-phase-3-nit-sweep.md)
- [ ] **3.22** s2s framing adversarial suite (**optional — first to cut**) — [file](./phase-3/3.22-s2s-framing-adversarial.md)

---

## Legend / how to read
- Each task line links to its own file with **Goal · Scope · Deliverables · Risks · Tests · Reviews · Status**.
- Phase folders (`phase-N/`) hold a `README.md` (phase overview + todo) and one file per task; review
  phases also hold a `review-report.md`.
- Definition of Task and Definition of Done: [CONTRIBUTING.md](../../CONTRIBUTING.md).
