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

- **NOW:** **Phase 4 (T08 + T17) is closed — 52/52 tasks done.** **4.52, the seventh exit-gate attempt,
  genuinely passed**, re-verifying 4.51's fix for the sixth defect (4.50's finding). Held to the same
  two-independent-live-runs-plus-reviewer discipline as every prior attempt, with one deliberate,
  explicitly authorized deviation: both live runs (implementer + `test-engineer`) drove the full T17
  demo — both account types, a ≥10-trial (24 total, both directions) first-contact delivery-reliability
  check, message-request accept, intro-history no-duplicate, safety-number verify, restart-with-no-
  re-handshake, `--export-json` — against a real, owner-operated rendezvous server
  (`wss://rendezvous.hansajayathilaka.com`) instead of a local in-process one. Both runs agreed on every
  Scope point: 4.51's fix holds (nothing near the original 70s–260s range across 24 fresh trials), and
  the one residual finding — `run_mark_verified`'s real backend latency for a file-backed account
  (~3.7–4.1s) — is the same, already-known, already-named `live_store`-routed hazard 4.51 itself split
  off, not a new regression, independently re-confirmed against source by the `reviewer` pass. Full
  lineage of all seven exit-gate attempts in [Phase 4's README](./phase-4/README.md#exit-criteria); full
  evidence in [4.52's own Status section](./phase-4/4.52-t17-acceptance-demo-closure-attempt-7.md).
- **NOW:** **Phase 5 (review of Phase 4) swept.** Four parallel lenses (code-reviewer, security-reviewer,
  architect, test-engineer) reviewed the full diff since the Phase-3 review — Phase 4's T08+T17
  (4.1–4.52) plus 19 untracked out-of-band commits (PRs #66–#73: CI job-split, the release-binary
  pipeline + ADR 0022→0023 self-correction, a Windows TUI input fix, message-status indicators, and the
  `demo/p2p-wire-proof` demo). **Verdict: green, zero blocking findings** — an unusually clean result
  given the diff's size, consistent with Phase 4's own heavy internal review discipline (seven exit-gate
  attempts, six defects caught and fixed before this sweep even started). 9 should-fix + 8 nit findings,
  none newly regressing anything already shipped: six are re-confirmations of residuals Phase 4's own
  README already named and left unowned (partial-failure repair action, stale `^N`/`^V` doc, stale
  `contacts.json.trust`/`export_json` gap, file-backed `run_mark_verified`/`run_set_petname` latency,
  `PersistHistory` drain-window flake); the rest are freshly found, the most notable being that the
  out-of-band Sent/Delivered message-status feature (landed outside the tracked-task pipeline) has an
  unreachable/unpersisted "Delivered" state and zero App-level test — reproducing, on a brand-new
  feature, the exact reconciliation-gap class T17's own six-wave closure spent the whole phase fixing.
  No ADR drift, no unratified on-the-fly decisions, no trust-state-machine bypass, no sealed-store leak.
  Full findings: [phase-5/review-report.md](./phase-5/review-report.md).
- **NOW:** **Phase 5 planned — 13 fix-tasks broken out** from the review report's 18 findings (F1–F10,
  N1–N8). Delegated to the **planner** agent; grounded against current source before finalizing scope.
  All 9 should-fix findings (F1–F9) plus F10 got their own task; N1 (a trust-reconciliation helper
  extraction with real defect history) and N7 (a genuine extension-registry policy decision) each got
  their own task; N2–N6 (doc/comment/mechanical) bundled into one nit sweep (5.13), mirroring Phase 3's
  3.21 precedent; N8 folded into 5.5 as a deferred stretch-goal since it isn't independently reachable
  until 5.5's own fix lands. Two same-function/same-file conflicts required explicit sequencing: **5.4
  before 5.3** (both touch `run_mark_verified`) and **5.5 before 5.6** (both append to
  `harnesses/mitm-sim/run.sh`); everything else runs in parallel. Full breakdown:
  [phase-5/README.md](./phase-5/README.md#tasks-todo).
- **NEXT:** `/next-task` — start landing Phase 5's 13 fix-tasks (Wave 1 first: 5.1, 5.2, 5.4, 5.5, 5.7,
  5.8, 5.9, 5.10, 5.11, 5.12, 5.13; then 5.3 after 5.4, and 5.6 after 5.5).


### Live carry-forwards (not owned by any open task)
Phase 4 is now closed; its own unowned findings live in
[phase-4/README.md](./phase-4/README.md#exit-criteria)'s "Findings with no task yet" sections, for
`/plan-phase` to pick up in a future build phase. These are the standing exceptions that would otherwise
evaporate:
- **Envelope v2 is now a standing, mechanically-checked dependency gate**, not prose. See
  [roadmap.md](../architecture/roadmap.md) (T07's deps row + the note beneath the table) and
  [Phase 4's README](./phase-4/README.md#envelope-v2-re-deferred--the-concrete-trigger). It must still carry the
  replay-dedup obligation from Phase 2 (2.13 bounds a replay's harm to one failed decrypt; full dedup
  via envelope v2's `eid` per [ADR 0016](../adr/0016-envelope-deniability.md) C7) into whatever build
  phase implements it.
- **The adversarial frontier carried from Phase 1** — SPK grace-window aging, stale-bundle replay on
  the fetch path, same-OTK-to-many-fetchers, reflection, per-device delivery, skipped-key exhaustion.
  Listed in [phase-3/README.md](./phase-3/README.md#findings-with-no-task-and-why); not a Phase-2
  regression, deliberately not scoped into Phase 3.
- **Definition of Done gate 9 (TUI client surface) is now live** — every user-visible feature ships a
  TUI surface via the [extension contract](../architecture/tui-client.md#8-extension-contract--every-feature-ships-a-tui-surface),
  or its task file states why it has none. It binds from T17 onward; features already built (T01–T06)
  acquire their surfaces as T17 and their own follow-ups land. `/plan-phase` must carry this into
  every future build phase's task set.
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

### Phase 3 — Review of Phase 2 · **done** · [details](./phase-3/README.md)
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
- [x] **3.9** Resolve the dead per-partner `policy` field in `federation_map.toml` (F7) — [file](./phase-3/3.9-federation-map-policy-field.md)

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
- [x] **3.21** Nit sweep (N1, N3) — [file](./phase-3/3.21-phase-3-nit-sweep.md)
- [x] **3.22** s2s framing adversarial suite (**optional — first to cut**) — [file](./phase-3/3.22-s2s-framing-adversarial.md)

**Wave 7 — found during 3.22, not part of the original report**
- [x] **3.23** Bound `serve_link`'s idle read (no idle-read deadline; in WebPKI mode exploitable by
  any public-CA cert-holder, not gated by federation policy) — [file](./phase-3/3.23-serve-link-idle-read-deadline.md)

### Phase 4 — Verification & Trust + Terminal TUI Client · **done** · [details](./phase-4/README.md)
Build phase. **[T08 — Verification & Contact Trust](../architecture/features/08-verification-trust.md)**
+ **[T17 — Terminal TUI Client](../architecture/features/17-terminal-tui-client.md)**, bundled: T08's
core trust module (safety-number compare, TOFU→pinned→verified states, un-softenable key-change
blocking, `meridian-mitm-sim`) is a hard prerequisite for T17's mandatory verification screens — see
the [phase README](./phase-4/README.md#resolving-the-t17t08-overlap) for why they aren't split.
Envelope v2 (T07's blocker) is deliberately **not** in this phase — see
[the re-deferral](./phase-4/README.md#envelope-v2-re-deferred--the-concrete-trigger) — except for a narrow v1-scoped fix
inside 4.9. 38 tasks (28 originally planned + 10 added post-4.28 to close the T17 gap it found —
see [Phase 4's own status note](./phase-4/README.md) for why), [full DAG here](./phase-4/README.md#dependency-order).

**ADR track — blocks all T17 code, not T08**
- [x] **4.1** ADR 0020 — TUI packaging — [file](./phase-4/4.1-adr-tui-packaging.md)
- [x] **4.2** ADR 0021 — client-local store & config formats — [file](./phase-4/4.2-adr-client-store-config-formats.md)

**T08 track — starts immediately**
- [x] **4.3** Trust module + contact store core — [file](./phase-4/4.3-trust-module-contact-store.md)
- [x] **4.4** Key-change handling: block/warn semantics — [file](./phase-4/4.4-key-change-block-warn-gate.md)
- [x] **4.5** Safety-number compare UX primitives + `meridian verify` — [file](./phase-4/4.5-safety-number-verify-cli.md)
- [x] **4.6** Petname assignment + contact management CLI — [file](./phase-4/4.6-petname-contact-management-cli.md)
- [x] **4.7** Message-request UX finalization (from T06) — [file](./phase-4/4.7-message-request-finalization.md)
- [x] **4.8** Org directory-attestation ingest — [file](./phase-4/4.8-directory-attestation-ingest.md)
- [x] **4.9** Desync detection → guarded fresh-X3DH re-handshake (incl. `open_bytes` short-circuit fix) — [file](./phase-4/4.9-desync-guarded-rehandshake.md)
- [x] **4.10** `meridian-mitm-sim` trust-state matrix — [file](./phase-4/4.10-mitm-sim-trust-matrix.md)

**T17 infra — no T08 dependency**
- [x] **4.11** `apps/tui` crate skeleton + terminal guard — [file](./phase-4/4.11-tui-crate-skeleton-terminal-guard.md)
- [x] **4.12** `meridian tui` subcommand + environment gate — [file](./phase-4/4.12-tui-subcommand-env-gate.md)
- [x] **4.13** Extract shared account/home-layout helpers into `meridian-core` — [file](./phase-4/4.13-extract-account-home-layout-core.md)
- [x] **4.14** `meridian-tui::config` — [file](./phase-4/4.14-tui-config.md)
- [x] **4.15** `meridian-tui::store` — [file](./phase-4/4.15-tui-store.md)
- [x] **4.16** Onboarding screen — [file](./phase-4/4.16-onboarding-screen.md)
- [x] **4.17** Unlock screen — [file](./phase-4/4.17-unlock-screen.md)
- [x] **4.18** Extension registry (`meridian-tui::surface`) — [file](./phase-4/4.18-extension-registry.md)

**T17 screens — converge at 4.19**
- [x] **4.19** Contact list + add-contact + contact detail — [file](./phase-4/4.19-contact-list-detail-screens.md)
- [x] **4.20** Chat / conversation screen — [file](./phase-4/4.20-chat-screen.md)
- [x] **4.21** Message-request queue screen — [file](./phase-4/4.21-message-request-queue-screen.md)
- [x] **4.22** Verification screen — [file](./phase-4/4.22-verification-screen.md)
- [x] **4.23** Key-change adversarial test — [file](./phase-4/4.23-key-change-adversarial-test.md)
- [x] **4.24** Settings screen — [file](./phase-4/4.24-settings-screen.md)
- [x] **4.25** Help overlay + command palette + diagnostics — [file](./phase-4/4.25-help-palette-diagnostics.md)
- [x] **4.26** Terminal-constraint degradation — [file](./phase-4/4.26-terminal-constraint-degradation.md)
- [x] **4.27** At-rest audit harness — [file](./phase-4/4.27-at-rest-audit-harness.md)

**Phase exit gate (first attempt — found the T17 gap below)**
- [x] **4.28** Docs sync + phase acceptance-demo wiring — [file](./phase-4/4.28-docs-sync-acceptance-demo.md)

**T17 gap closure — added post-4.28** (real `run_worker` execution, a live inbound-message receive path
found missing during this planning pass, `Preflight`/`Screen::Main` navigation, and a second, planned-to-
succeed exit-gate attempt) — see [Phase 4's own task list](./phase-4/README.md#tasks-todo) for full detail
- [x] **4.29** `Effect::LoadSession` + `LiveSession` assembly — [file](./phase-4/4.29-load-session-live-session.md)
- [x] **4.30** Real `run_worker`: account lifecycle — [file](./phase-4/4.30-run-worker-account-lifecycle.md)
- [x] **4.31** Real `run_worker`: contacts & contact-detail persistence — [file](./phase-4/4.31-run-worker-contacts-persistence.md)
- [x] **4.32** Real `run_worker`: trust & request-queue persistence — [file](./phase-4/4.32-run-worker-trust-request-persistence.md)
- [x] **4.33** Real `run_worker`: outbound chat — [file](./phase-4/4.33-run-worker-outbound-chat.md)
- [x] **4.34** Real `run_worker`: settings & diagnostics — [file](./phase-4/4.34-run-worker-settings-diagnostics.md)
- [x] **4.35** Inbound delivery stream — [file](./phase-4/4.35-inbound-delivery-stream.md)
- [x] **4.36** `Screen::Main` + live navigation — [file](./phase-4/4.36-screen-main-live-navigation.md)
- [x] **4.37** Preflight routing — [file](./phase-4/4.37-preflight-routing.md)
- [x] **4.38** T17 acceptance-demo closure (phase re-exit gate) — [file](./phase-4/4.38-t17-acceptance-demo-closure.md)
- [x] **4.39** Prekey bundle republish + vault persistence on session start (fix for 4.38's Defect A) — [file](./phase-4/4.39-prekey-bundle-republish.md)
- [x] **4.40** Thread the live-session secret store through file-backed contacts/trust/send handlers (fix for 4.38's Defect B) — [file](./phase-4/4.40-file-backed-live-session-store.md)
- [x] **4.41** T17 acceptance-demo closure, third exit-gate attempt — [file](./phase-4/4.41-t17-acceptance-demo-closure-attempt-3.md)

**Third gap-closure wave — added post-4.41** (fix shapes for 4.42 and 4.43 were decided at plan time by
an architect consult recorded in their own files; neither needs a further pre-code consult or a new ADR).
Recommended landing order is **4.43 → 4.42 → 4.44 → 4.45**; numbering keeps 4.42 = Defect C as
pre-announced.
- [x] **4.42** Post-accept path to chat/verify with a message-request sender (Defect C — the blocking defect) — [file](./phase-4/4.42-post-accept-chat-affordance.md)
- [x] **4.43** File-backed prekey republish performance, 188 s → seconds (4.39's recorded, unfixed defect; land first) — [file](./phase-4/4.43-file-backed-republish-performance.md)
- [x] **4.44** Load a chat's persisted transcript when the chat screen opens (predicted "Defect D"; verify first, then fix) — [file](./phase-4/4.44-chat-history-load-on-open.md)
- [x] **4.45** T17 acceptance-demo closure, fourth exit-gate attempt (hard join on 4.42, 4.43, 4.44) — [file](./phase-4/4.45-t17-acceptance-demo-closure-attempt-4.md)
- [x] **4.46** Reconcile `Effect::AddContact` into the live `MainState::trust` (fix for 4.45's fourth defect) — [file](./phase-4/4.46-add-contact-trust-reconciliation.md)
- [x] **4.47** Fix `--export-json` demo-script/spec wording (doc-only) — [file](./phase-4/4.47-export-json-doc-fix.md)
- [x] **4.48** T17 acceptance-demo closure, fifth exit-gate attempt — [file](./phase-4/4.48-t17-acceptance-demo-closure-attempt-5.md)
- [x] **4.49** Persist the accepted sender's intro into `history.jsonl` (fix for 4.48's fifth defect) — [file](./phase-4/4.49-persist-accepted-intro-history.md)
- [x] **4.50** T17 acceptance-demo closure, sixth exit-gate attempt (verdict FAIL — sixth defect found;
  closed by the sixth gap-closure wave, 4.51/4.52) — [file](./phase-4/4.50-t17-acceptance-demo-closure-attempt-6.md)
- [x] **4.51** Root-cause and fix the file-backed responder's blocking-scrypt hazard (fix for 4.50's
  sixth defect) — [file](./phase-4/4.51-file-backed-inbound-blocking-fix.md)
- [x] **4.52** T17 acceptance-demo closure, seventh exit-gate attempt — verdict PASS, Phase 4 exit gate
  closed — [file](./phase-4/4.52-t17-acceptance-demo-closure-attempt-7.md)

### Phase 5 — Review of Phase 4 · **in progress** · [details](./phase-5/README.md)
Review phase. Sweeps everything built since the Phase-3 review: Phase 4 (T08 + T17, tasks 4.1–4.52) and
the untracked out-of-band PRs #66–#73 that landed alongside/after it. [Report](./phase-5/review-report.md):
18 findings — **0 blocking**, 9 should-fix, 9 nits (F1 combines a duplicate correctness+coverage finding
from two lenses, numbered once). Verdict: **green to proceed**, no blocker for the next build phase
(envelope-v2). 13 fix-tasks cover all 18 findings (N8 folded into 5.5 rather than its own task — see
[phase-5/README.md](./phase-5/README.md#tasks-todo)).

**Wave 1 — fully parallel**
- [x] **5.1** Persist and always-reconcile Sent→Delivered receipts (F1) — [file](./phase-5/5.1-persist-reconcile-delivery-receipts.md)
- [x] **5.2** Diagnostics-surfaced repair action for `run_accept_request`'s partial-failure window (F2) — [file](./phase-5/5.2-accept-request-repair-action.md)
- [x] **5.4** `spawn_blocking`-wrap `run_mark_verified`/`run_set_petname` (F4) — [file](./phase-5/5.4-spawn-blocking-mark-verified-set-petname.md)
- [x] **5.5** Wire receive-side key-change detection into the TUI inbound loop + `session.rs` (F5 + N8 deferred) — [file](./phase-5/5.5-wire-receive-side-key-change-detection.md)
- [x] **5.7** App-level reconciliation tests for Settings/Diagnostics (F7) — [file](./phase-5/5.7-settings-diagnostics-app-level-tests.md)
- [x] **5.8** App-level end-to-end tests for onboarding/unlock (F8) — [file](./phase-5/5.8-onboarding-unlock-app-level-tests.md)
- [x] **5.9** Scheduled CI workflow for `demo/p2p-wire-proof` (F9) — [file](./phase-5/5.9-schedule-p2p-wire-proof-ci.md)
- [~] **5.10** Drain/flush-on-shutdown hook for `Effect::PersistHistory` (F10) — [file](./phase-5/5.10-persist-history-drain-on-shutdown.md)
- [ ] **5.11** Extract shared `observe_into_live_trust` helper (N1) — [file](./phase-5/5.11-extract-observe-into-live-trust-helper.md)
- [ ] **5.12** Pin `find_binding`'s keybinding-collision tie-break contract (N7) — [file](./phase-5/5.12-pin-keybinding-collision-tiebreak.md)
- [ ] **5.13** Nit sweep: doc/comment/mechanical fixes (N2, N3, N4, N5, N6) — [file](./phase-5/5.13-phase-5-nit-sweep.md)
- [ ] **5.14** `run_acknowledge_key_change` has the same `contacts.json` trust-staleness bug as F3 (found by 5.3's own review, depends on 5.3) — [file](./phase-5/5.14-acknowledge-key-change-trust-staleness.md)

**Wave 2 — sequenced (same-function/same-file conflicts)**
- [x] **5.3** Fix `contacts.json` trust staleness + cover `export_json` (F3; depends on 5.4) — [file](./phase-5/5.3-fix-contacts-trust-staleness-export.md)
- [x] **5.6** Federated mitm-sim cell: verified-contact key-change block (F6; depends on 5.5) — [file](./phase-5/5.6-federated-verified-key-change-mitm-cell.md)

## Legend / how to read
- Each task line links to its own file with **Goal · Scope · Deliverables · Risks · Tests · Reviews · Status**.
- Phase folders (`phase-N/`) hold a `README.md` (phase overview + todo) and one file per task; review
  phases also hold a `review-report.md`.
- Definition of Task and Definition of Done: [CONTRIBUTING.md](../../CONTRIBUTING.md).
