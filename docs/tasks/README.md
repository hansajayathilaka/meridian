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
- **ALSO NOW:** **Phase 2 is picked — T06 Cross-Org Federation**, alone
  ([phase README](./phase-2/README.md)). With Features 01-05 done the unblocked set was {06, 08, 09};
  06 wins on the dependency DAG (Track C `02→06→07→14` — it is the sole gate on Features 07, 10 and 14
  and transitively on 11/12/15, and it is P1) and its declared deps `T04 (T05 recommended)` are both
  complete. **08 was rejected as a parallel pick because it *consumes* 06** — its scope pulls in the
  message-request UX "from T06" and cross-org attestation ingest, and 1.18 already deferred desync
  auto-recovery into it, so running the two together would race on one first-contact/trust surface.
  **09 is genuinely parallel** (Track B, additive stream type, registry-only) but was left out on
  sizing: 06 alone is ~3 eng-weeks of new s2s protocol + new wire contract + two-stack demo + abuse
  suite, and bundling 09 would roughly double what Phase 3's review sweep has to cover.
  `/plan-phase` also inherits one delegated **`TODO: confirm`** — `rendezvous-protocol-v1.md` stores a
  prekey bundle as a single CBOR blob and defers "normalized schema + Postgres" to T06/T07; it must be
  resolved or explicitly re-deferred.
- **ALSO NOW:** **Phase 2 is planned — 12 tasks (2.1-2.12)**, [phase README](./phase-2/README.md).
  Two agent findings reshaped the breakdown, and both are worth carrying forward:
  **(1) The forwarding path is not implementable as specified.** `Deliver{from}` is *required* by the
  client (`apps/core/src/chat.rs` hard-rejects `envelope.sender_pub != from` with `SenderMismatch`),
  but `wire-protocol.md` §4's `fed_route{to, envelope}` carries **no** `from`, and server B cannot
  derive one — the envelope is opaque to it, and decoding it would need `meridian-envelope`, which the
  server must never depend on. `wire-protocol.md` §2 supplies a *third* divergent shape,
  `deliver {from_server, blob}`. So the very first task is **2.1 — ADR 0017**, deciding what the
  receiving server may believe: which name the peer cert authenticates (in both WebPKI and private-CA
  modes) and who attests `from` across the boundary. It must also **scope-correct ADR 0016's residual
  R4**, whose "the routing `from` is taken from the authenticated WebSocket session" is true
  single-hop and **false federated**. Nothing that shapes s2s bytes may land before it — retrofitting
  provenance into a published contract is a wire break with vectors already generated.
  **(2) Two live doc contradictions** that would otherwise be settled by whichever task hard-coded an
  answer first: `wire-protocol.md` §2 specifies `fetch_bundle {target, hint}` where the implemented
  `Fetch` has no hint (2.3 reconciles), and `data-model.md` defines `federation_map` as a **DB table**
  while the feature spec calls it a **config file** (2.5 settles).
  Also settled: the delegated `TODO: confirm` on normalized schema + Postgres is **re-deferred to
  T07** with its reason recorded (2.3) — Feature 06 adds no new persisted state, and T07's mailbox is
  the first consumer a normalized schema would have. And `lint-server-no-core.sh` is a crate-**name**
  allowlist, so federation lives *inside* `apps/rendezvous/` with shared types in `apps/proto/`; a
  `meridian-federation` crate would fail the lint without touching core.
- **ALSO NOW:** **1.32 is done** — [PR #32](https://github.com/hansajayathilaka/meridian/pull/32).
  **2.1 is therefore unblocked**, which was the point of running it first. The relay now has its four
  key-material-free attacks as independently-gated server modes (`spoof_from` → `SenderMismatch`,
  `replay` → refused at the ratchet, `reorder` → tolerated without loss/forgery/duplication, `drop` →
  denial stays denial, `cross_deliver` → `UnknownPrekey`), plus ADR 0016's preamble-mutation cells
  client-side. Both required reviews signed off; three findings outlive the task:
  **(1) A production defect, filed as [2.13](./phase-2/2.13-ratchet-replay-dos.md).** One replayed
  envelope **permanently wedges the receiving ratchet**: `Ratchet::decrypt` advances `ckr`/`nr` before
  `aead_open` and never rolls back, so after one duplicate every subsequent genuine message from that
  peer fails. Unauthenticated, key-material-free, permanent, mountable by any relay — and it breaks
  *benign* duplicate delivery too, which T07's mailbox will produce with no attacker at all. Left
  unfixed on purpose (1.32's `Out:` is production code; asserting today's behaviour would entrench
  it) but recorded in the threat-mitigation matrix's A2/A3 rows so it survives Phase 1 being archived.
  It is a **defect, not an accepted residual** — it contradicts threat-model goal 6.
  **(2) The CI gate was half-unexercised, again.** The feature-**ON** tests had no deterministic
  invocation: `-p` with default features compiles them out, mitm-sim's filtered call skips them, and
  they ran only via resolver-2 unification through `apps/cli`'s dev-dep pin. The same accidental
  coupling 1.28 found, load-bearing in the *other* direction — dropping that pin would have silently
  stopped running every runtime-gate test. Now an explicit CI step. Measured proof the two runs are
  disjoint: default-features 13 lib + 20 integration, feature-on 20 + 15.
  **(3) Non-vacuity was re-derived, not asserted.** test-engineer neutered code and observed failure:
  hook inert → 5 of 6 cells fail, each on its own attack-specific assertion; the `SenderMismatch`
  check deleted → exactly one fails; the signature check stubbed → all 4 preamble cells fail with the
  OTK consumed and a poisoned session installed (ADR 0016's C2 exposure, measured); and with the
  error-class pin *also* loosened they **still** fail, on the OTK-depth and no-session assertions — so
  the three anti-DoS properties are independently load-bearing.
  Scope correction recorded rather than papered over: *delay* needs no flag (a delayed-but-in-order
  message is indistinguishable from an honest one); the one observable delay attack is aging past the
  SPK grace window, now named as uncovered in the harness frontier list — along with stale-bundle
  replay on the fetch path, same-OTK-to-many-fetchers, reflection, per-device delivery and
  skipped-key exhaustion.
- **ALSO NOW:** **2.1 is done** — [PR #33](https://github.com/hansajayathilaka/meridian/pull/33). ADR
  0017 resolves the forcing problem (`fed_route` gains a server-asserted `from: bstr[32]`, bounded by
  the client-side `SenderMismatch` check exactly as the single-hop case already is), pins peer-cert
  verification to the hint/discovery domain (never the literal SRV target) in both WebPKI and
  private-CA modes with a fail-closed missing-pin rule, keys federation-edge rate limits to (mTLS peer
  identity, asserted `from`), scope-corrects ADR 0016 R4 to single-hop, and flips ADRs 0001–0008
  `Proposed` → `Accepted`. architect: consistent, no revision. security-reviewer: APPROVE-WITH-CHANGES,
  both changes landed — C4 now fail-closes a missing/malformed `federation_map.toml` pin, and new C7
  requires s2s mTLS to terminate **in-process** (never proxy/VIP), resolving task 2.4's open
  termination-point `TODO: confirm`.
- **ALSO NOW:** **2.2 is done** — `federation-protocol-v1.md` (new doc) + `apps/proto/src/fed.rs`
  (`FedOp`, `FedFrame`, `FedHello`, `FedFetchBundle`, `FedBundle`, `FedRoute{to, from, envelope}`,
  `FedReachability`, `FedReachable`, `FedErr`, `fed_error_codes`) implement ADR 0017's decisions
  verbatim — the C1/C2 canonical `fed_route` shape, C5's mTLS-peer-identity-is-authoritative rule
  (both `FedHello.domain` and `FedFetchBundle.requesting_server` are documented as self-asserted/
  informational only, never a policy input), and C7's in-process-termination framing (length-delimited
  CBOR directly on the mTLS byte stream, no WS/HTTP2). `FedOp`/`FedFrame` are a structurally distinct
  plane from the c2s `Op`/`Frame` — verified by grep, `apps/rendezvous/` has zero references. `id = 0`
  is reserved for a two-way `FedHello` exchange; every other id is chosen by whichever side initiates
  (s2s has no client/server asymmetry to reserve a shared id space around, unlike c2s). `contact_token`
  is recorded reserved-and-unimplemented, no field added. `test-vectors/federation-v1.json` covers all
  7 body types deterministically; `lint-no-serde-on-blob.sh`'s allowlist extended as an explicit,
  reviewed line item. Contracts-only as scoped: zero diff in `apps/rendezvous/`; `wire-protocol.md §2`'s
  stale `deliver{from_server, blob}` duplicate deliberately left for 2.3. All three listed reviewers
  signed off clean — architect: consistent, no revision; security-reviewer: APPROVE, no changes
  required; code-reviewer: approve, two non-blocking nits (redundant test case; b32 fields lack a
  dedicated compact-CBOR-shape unit assertion, covered indirectly by the vectors + CI's byte-identical
  gate).
- **ALSO NOW:** **2.3 is done** — [PR #35](https://github.com/hansajayathilaka/meridian/pull/35). The
  c2s contract gains `Fetch.hint` / `RouteBody.to_hint` (optional, backward-compatible plain domain
  strings — byte-identical on the wire for hint-less clients, test-proven not just claimed) and
  `fed_denied`/`fed_unreachable`/`not_found_at_hint`. `Deliver` is unchanged, per ADR 0017 C2's
  decision that the canonical c2s push stays `Deliver{from, blob}` — only its doc comment now records
  the federated-`from` provenance (ADR 0017 (b)/C2/C6). `wire-protocol.md §2` and
  `rendezvous-protocol-v1.md` are reconciled to the canonical shapes (the stale `deliver{from_server,
  ...}` duplicate is gone), and the delegated `TODO: confirm normalized schema + Postgres` is
  resolved — **re-deferred to T07**, reasoning recorded in both the doc and `sqlite.rs`. Contracts-only
  as scoped: zero diff in `apps/rendezvous/src/ws.rs`, no client error-copy (2.9's job). All three
  reviewers signed off clean: architect — consistent, no revision; security-reviewer — APPROVE, no
  changes required; code-reviewer — APPROVE, no blocking findings (one doc nit fixed inline, one left
  as a non-blocking informational note).
- **ALSO NOW:** **2.4 is done** — s2s mTLS link (`apps/rendezvous/src/federation/{mod,link}.rs`),
  WebPKI + private-CA modes, domain-pinned verification (ADR 0017 C3), in-process TLS termination
  (ADR 0017 C7), fail-closed `config::Federation` defaults, `meridian_federation_link_up` as an
  aggregate gauge with **no** `peer_domain` label (security-reviewer: a per-partner label would
  materialize the cross-org contact graph, forbidden by anonymity-and-retention.md must-never #2).
  Default federation port **8444** (`TODO: confirm`, not IANA-registered). architect: consistent, no
  revision. security-reviewer: APPROVE-WITH-CHANGES — required fail-closed cert-loading regression
  tests (empty/nonexistent/zero-cert paths) added in a follow-up commit; also flagged, non-blocking,
  that the accept side doesn't yet pin inbound peer identity to a specific expected partner — that's
  2.5/2.6 policy territory, not a 2.4 gap. code-reviewer: approve-with-nits — `missing_client_cert_is_rejected`
  didn't isolate the mechanism it claimed to test (a coincidental app-level check would also catch a
  *fully* disabled mandatory-client-auth requirement, in a state that in fact rejects every connection);
  fixed with a doc comment pointing at the happy-path tests as the real proof mTLS is mandatory.
- **ALSO NOW:** **2.5 is done** — federation discovery (`apps/rendezvous/src/federation/discovery.rs`):
  `Discovery` trait, `StaticMap` (`federation_map.toml`, fail-closed `pinned_identity`, case-folded
  domains), `SrvDiscovery` (RFC 2782 ordering, `Target == "."` → no-record). `Federation::validate()`
  now rejects `discovery = "srv"` + a non-empty `ca_bundle_path` — that combination reopened ADR 0017
  (a)'s rejected "Option A" impersonation hole. Resolved the `federation_map` config-file-vs-DB-table
  contradiction (two docs had it, both fixed). test-engineer's most notable finding: the original
  air-gap "zero DNS lookups" test was vacuous (a `TripwireResolver` never actually reachable from
  `StaticMap::resolve`'s code path) — replaced with an `LD_PRELOAD getaddrinfo(3)` syscall-interposition
  test, verified against the exact mutation that broke the old one. security-reviewer flagged that
  `pinned_identity` isn't wired into `link::dial()`'s identity check yet — carried forward as an
  explicit deliverable + required test on **2.7**'s task file, not a 2.5 gap (2.7 doesn't dial yet).
  All four reviewers (architect, test-engineer, code-reviewer, security-reviewer — the last added
  mid-task since this touches ADR 0017 C4's trust pin) signed off after fixes.
- **ALSO NOW:** **1.33 is done — and with it, Phase 1 is fully closed.** Bounded the dialer's
  previously-infinite wait for an answer in `recv_sdp` (`apps/core/src/session.rs`): new
  `SessionError::AnswerTimeout`, existing cleanup path already closed the transport on any `Err`, no
  leak. architect caught that the first implementation (5s) was backwards — trickle ICE isn't
  supported yet, so both sides gather full ICE candidates before sending SDP, and the real backend's
  own gather is bounded at up to 20s (`GATHER_TIMEOUT`); a 5s dialer bound sat *inside* that and
  would have spuriously aborted honest-but-slow handshakes. Raised to 30s. security-reviewer
  APPROVE, no blocking changes — confirmed fail-closed holds (no session is ever partially
  constructed) and the OTK-depletion-amplifier note doesn't get worse (the server-side per-source
  fetch limiter is independent of this client-side wait, and nothing retries on timeout). 1.28's
  `relay_rewrite.rs` tightened to assert the specific new error instead of a `StillWaiting`
  catch-all; its multi-threaded test couldn't use tokio's paused-clock trick the way the new unit
  test could, so it now takes ~31s real time — an accepted tradeoff, not chased further.
  Phase 1's last open item (1.32 closed earlier) is now closed too: every task in the Phase-1 review
  report (F1–F22) plus all on-the-fly decisions is `[x]`. Phase 1 marked **done**.
  **Also fixed mid-batch:** PR #44's CI (`License / advisory gate`) failed on `rustls-pemfile`
  (RUSTSEC-2025-0134, unmaintained, no safe upgrade) — added in task 2.4. Replaced with
  `rustls-pki-types`'s own `PemObject` trait (what `rustls-pemfile` now just wraps), dropping the
  dependency entirely; `apps/rendezvous/src/federation/link.rs` and its test file both updated.
- **ALSO NOW:** **2.10 is done.** First-contact message-request gate, entirely client-side
  (`apps/core/src/chat.rs`'s `open_inbound`): a first envelope from an unrecognized peer key lands
  in `pending_requests` instead of delivering; a second pre-accept envelope is refused, not merged;
  gating happens after signature verification/session establishment so a rejected first contact
  still costs the OTK it consumed (same accepted-behavior class as 1.33). architect confirmed
  client-side-only is *binding* (not just asserted) per anonymity-and-retention.md must-never #2.
  All three reviewers independently found and required tracking the same real gap: the gate is
  structurally inert on the P2P session-signaling path (`session connect` bypasses it — the crypto
  session installs before any chat content flows) — tracked as **2.14** rather than left implicit,
  with `threat-mitigation-matrix.md`'s claim corrected and a regression test pinning today's
  behavior. security-reviewer APPROVE-WITH-CHANGES (both required fixes applied); test-engineer
  PASS, no required fixes (mutation-tested the new suite and the four pre-existing tests' shims).
- **ALSO NOW:** **2.13 is done.** `DoubleRatchet::decrypt`'s receiving-chain advance is now
  failure-atomic: mutations stage on a checkpoint copy and commit only after `aead_open` succeeds, so
  a replayed/tampered envelope degrades exactly one message instead of permanently wedging the
  chain. Regression tests were shown to fail against the pre-fix code first (the task's own required
  process gate), including the compound DH-ratchet-catch-up path. Conformance vectors unchanged.
  security-reviewer APPROVE-WITH-CHANGES caught a real issue the fix's first draft introduced: making
  `DoubleRatchet` derive the public `Clone` trait (to stage the scratch copy) would have let any
  external holder fork a live session and reuse an AEAD key+nonce pair on a later encrypt/decrypt —
  catastrophic, since both are derived solely from the single-use message key. Fixed with a
  crate-private `checkpoint()` method instead. Also corrected a false "replay dedup by eid" claim in
  `threat-mitigation-matrix.md`'s A3 row (unimplemented in v1 per `wire-protocol.md`). test-engineer
  independently reproduced the fail-before/pass-after evidence and confirmed the compound-case test
  is non-vacuous.
- **NEXT:** `/next-task`. Continuing the batch: **2.6** next, then **2.7**, **2.8**, **2.9**,
  **2.11**, **2.12** in dependency order. **2.14** (new, from 2.10's review) queues up after 2.10's
  own dependents since it depends on 2.10.
  **One Phase-1 follow-up is still open** — **1.33** (bound the dialer's unbounded `recv_sdp` wait;
  availability/diagnostics only). It does not block Phase 2's gate (F1, F2, F3, F10, F11 — satisfied
  by Group D) and is nit class, but it sits on code T06 extends: 06's "a `closed`-policy org rejects
  inbound federation with a **clean client-side error**" criterion is precisely the case an unbounded
  wait turns into a hang. **1.33 gates 2.9** only (it touches `apps/core/src/session.rs`, which no
  server task touches), so it runs in parallel. It stays numbered under Phase 1 (it is a Phase-1
  finding); Phase 1 cannot be marked fully `[x]` while it is open, and closing it closes Phase 1.
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

### Phase 2 — Cross-Org Federation · **in progress** · [details](./phase-2/README.md)
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
- [~] **2.6** Federation policy (`open | allowlist | closed`) + edge rate limits — [file](./phase-2/2.6-federation-policy-limits.md)
- [ ] **2.7** Federated prekey fetch, both sides (§3.3 steps 2–4) — [file](./phase-2/2.7-federated-prekey-fetch.md)
- [ ] **2.8** Federated envelope forwarding + per-request reachability (§3.3 step 5, §3.4) — [file](./phase-2/2.8-federated-route-reachability.md)

**Client**
- [ ] **2.9** Client federation error taxonomy: clean `closed` error + stale-hint case — [file](./phase-2/2.9-client-federation-errors.md)
- [x] **2.10** First-contact message-request gate (client-side, §3.5) — [file](./phase-2/2.10-message-request-gate.md)

**Demo + exit gate**
- [ ] **2.11** `demo/two-orgs/`: two full stacks, private CA, both discovery modes — [file](./phase-2/2.11-demo-two-orgs.md)
- [ ] **2.12** Cross-org abuse + acceptance suite (the phase exit gate) — [file](./phase-2/2.12-cross-org-abuse-acceptance.md)

**Carried in from Phase 1** (production defect surfaced by 1.32; not part of T06)
- [x] **2.13** A replayed envelope permanently wedges the receiving ratchet (`Ratchet::decrypt` commits `ckr`/`nr` before `aead_open` and never rolls back — unauthenticated permanent session DoS) — [file](./phase-2/2.13-ratchet-replay-dos.md)
- [ ] **2.14** Wire the message-request gate into the P2P session substrate (from 2.10's review; `session connect` currently bypasses the gate entirely) — [file](./phase-2/2.14-p2p-message-request-gate.md)

---

## Legend / how to read
- Each task line links to its own file with **Goal · Scope · Deliverables · Risks · Tests · Reviews · Status**.
- Phase folders (`phase-N/`) hold a `README.md` (phase overview + todo) and one file per task; review
  phases also hold a `review-report.md`.
- Definition of Task and Definition of Done: [CONTRIBUTING.md](../../CONTRIBUTING.md).
