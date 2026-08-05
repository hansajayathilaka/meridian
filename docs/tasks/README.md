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
- **ALSO NOW:** **2.6 is done.** Pure federation admission/rate-limit decision layer
  (`apps/rendezvous/src/federation/policy.rs`): `FederationPolicy` (closed structurally cannot
  consult allowlist state; allowlist is exact-match), `FederationLimits` reusing task 1.20's
  amortised-sweep `RateLimiter` for per-origin-fetch/per-origin-route/per-origin-account budgets.
  Deliberately unwired from any handler (2.7/2.8) and builds no client-visible copy (2.9).
  architect: consistent — confirmed the pure-decision-layer boundary was planned at `/plan-phase`
  time, not improvised. security-reviewer: APPROVE-WITH-CHANGES — traced all six required checks
  against code; found `lint-no-raw-id-logging.sh`'s pattern didn't actually cover
  `origin_domain`/`origin_account` despite the module doc claiming it did (fixed). code-reviewer:
  request-changes — found and reproduced a real bug: checking the shared per-origin budget before
  the per-account one meant an already-over-budget account's rejected retries could still drain the
  shared pool and starve every other account behind the same origin, exactly the failure mode the
  per-account budget exists to prevent. Reordered account-first; pinning test added.
- **ALSO NOW:** **2.7 is done.** Federated prekey fetch, both directions — the first task to run
  tasks 2.4/2.5's previously-inert s2s listener/dialer in a live server. Server A's
  `outbound::fetch_foreign_bundle` pins to `Endpoint::pinned_identity` (2.5's inherited
  requirement); server B's `inbound::handle_fed_fetch` binds `origin_domain` to the
  mTLS-authenticated `link.peer_domain` and is task 2.6's policy/limits' first real caller. No
  bundle verification server-side either direction (client-side `verify_bundle` stays the sole
  trust anchor, §3.3 step 4) — confirmed by all four reviewers that `meridian-signaling` is never
  imported into the server crate. architect required fixing an incoherent boot-failure split (s2s
  bind failure now fatal, matching this codebase's established fail-loud posture); security-reviewer
  and code-reviewer independently caught the same error-message leak (server A's internal dial
  config was interpolated into client-visible failure text — fixed to use only the client's own
  hint); test-engineer mutation-tested both critical tests (single-websocket routing invariant,
  pinned-identity rejection) and confirmed neither is vacuous.
- **ALSO NOW:** **2.8 is done.** Federated envelope forwarding + per-request reachability — the
  last piece of Feature 06's server spine. Before implementing, resolved three open architect
  decisions in the task file: oversized envelopes reuse `MAX_FRAME_LEN` (no new constant); zero
  s2s replay/dedup, deferred entirely to envelope v2's `eid` per ADR 0016 C7 (task 2.13 already
  bounds a replay's harm to one failed decrypt); `fed_reachability` is s2s-internal only, no new
  client-visible c2s trigger, must collapse to the exact same `not_connected` outcome local routing
  already produces — no existence oracle. Implementer self-caught a real bug mid-build: the
  reachability pre-check's own policy answers were initially masking a `closed`-policy origin as
  merely offline, caught by the task's own test failing. architect: consistent, confirmed §3.4
  per-request-only presence and the ADR 0007 boundary, flagged an incomplete residual-doc gap on
  `ROUTE_REPLY_GRACE` (fixed). security-reviewer: APPROVE-WITH-CHANGES, procedural only.
  test-engineer: PASS, mutation-tested everything including the bug-fix itself, and recovered
  cleanly from a `git checkout --` near-miss mid-review. code-reviewer: approve-with-nits, found
  real duplicated pinning-dial logic between `fetch_foreign_bundle` and the new `dial_foreign`
  helper (fixed — now shared) and converged with the other two reviewers on the same
  `ROUTE_REPLY_GRACE` finding (fixed via honest residual documentation, no number was guessed).
  Non-blocking follow-ups noted, not fixed: federated deliveries aren't counted in
  `envelopes_routed_total`; the third near-duplicate test-harness copy means a `tests/common/mod.rs`
  extraction is now overdue.
- **ALSO NOW:** **2.9 is done.** New `SignalError`/`SessionError` variants `FedDenied`/
  `FedUnreachable`/`NotFoundAtHint`, kept structurally distinct from `BundleVerification`/
  `FingerprintMismatch` (a `classify_federation_error` helper reclassifies wire codes without ever
  leaking server-internal detail); CLI copy + a bounded retry that never retries a policy denial or
  unreachable peer; a real subprocess-driven acceptance test (`apps/cli/tests/federation_errors.rs`)
  with a wall-clock kill-on-hang guard proving both "no hang" and "no security-copy leak" are real,
  falsifiable properties (test-engineer mutation-tested every claim). security-reviewer APPROVE;
  test-engineer PASS; code-reviewer approve-with-nits surfaced a real architectural gap — **no live
  CLI path ever calls `route_with_hint` with an actual hint** (`RendezvousRelay::send` and
  `chat::route_tolerant` hardcode `None`), so cross-org **routing** doesn't work end-to-end yet even
  though cross-org **bundle fetch** does. architect confirmed (binding per `system-design.md` §3.3
  step 2 / §3.4, not a new decision) and required a new task rather than folding the fix into 2.9 or
  2.11: **2.15**, inserted before 2.11 since 2.11's demo and 2.12's abuse suite both need real
  cross-org routing to run at all.
- **ALSO NOW:** **2.15 is done.** `RendezvousRelay` (apps/core/src/signal_relay.rs) and
  `chat.rs`'s `route_tolerant` now thread the peer's real org hint into every routed call, not just
  the bundle fetch — closing the gap 2.9's review found. security-reviewer APPROVE; test-engineer
  PASS (mutation-tested twice, including 8 clean flakiness-check runs of the new WebRTC-handshake
  test). code-reviewer's one contingent finding — the `session_connect.rs`/`RendezvousRelay` half had
  zero regression coverage — closed with a new bidirectional two-org `session connect` test
  (`apps/cli/tests/session_connect_federation.rs`). That verification pass also caught a real
  pre-existing gap (dating to 1.24): `cargo test -p meridian-cli --features webrtc` was never wired
  into `Justfile`/CI, so this task's own new regression tests would have silently never run — fixed
  in both files.
- **ALSO NOW:** **2.11 is done.** `demo/two-orgs/` (base compose + static/srv discovery overrides,
  rendezvous/coturn/edge images, a DNS service for real SRV resolution, `README.md`,
  `run-walkthrough.sh`) verified with real `docker compose up` runs, both discovery modes: cross-org
  chat federates, 2.10's message-request gate fires, delivery succeeds once accepted, real P2P/DTLS
  establishes, and zero plaintext ever appears in either server's logs. Two real bugs found and
  fixed by actually running the stack, not by inspection: `bootstrap-ca.sh`'s leaf keys were `0600`,
  unreadable by the rendezvous container's non-root user after it drops privilege — `chmod 644`
  scoped to the two leaf keys only (CA key untouched); no root `.dockerignore` existed, so every
  image's `COPY . .` was shipping the multi-GB `/target` cache into the build context. Resolved the
  task's own `infra/deploy/two-orgs.compose.yml` `TODO: confirm`: that file was a pre-2.11 scaffold
  stub, not a maintained production reference — `demo/two-orgs/` supersedes it outright.
  security-reviewer APPROVE (two low-severity non-blocking notes: shared-host leaf-key readability,
  TURN secret via CLI arg vs. env var); architect consistent (ADR 0008/0017 C7 topology confirmed
  wired for real, not just claimed in comments); code-reviewer approve-with-nits, one should-fix
  taken seriously and fixed — `run-walkthrough.sh` had declared a bash array literally named `HOME`,
  silently clobbering the real `$HOME` env var for every subsequent `docker compose` call in the
  script (renamed to `HOMES`).
- **ALSO NOW:** **2.12 is done — the Phase 2 exit gate.** Turned Feature 06's acceptance criteria
  into executable, CI-wired gates: `apps/rendezvous/tests/federation_abuse.rs` (route-dimension rate
  limits, allowlist-miss rejection with a positive control, oversized envelopes, the A2×2 cross-org
  malicious-server bundle-substitution test pinned to `SignalError::BundleVerification`, plus the
  F17 structural-inertness counterpart) and `apps/cli/tests/two_orgs_walkthrough.rs` (a CLI-
  subprocess message-request-gate-then-delivery walkthrough, and a continuity test killing **both**
  rendezvous servers post-P2P-establishment with chat still flowing both ways). New federated
  opacity audit (`apps/cli/src/opacity.rs::run_federated_audit`, proven sensitive to a fed-only leak,
  not vacuous) and new cross-org cells in `harnesses/mitm-sim`/`harnesses/opacity-audit`. The one
  in-scope production change: extended the existing `test-tamper-hook` feature (1.28/1.32) so a
  malicious server B can substitute a bundle on the federated fetch path, same F17 discipline.
  security-reviewer APPROVE-WITH-CHANGES, architect consistent, test-engineer PASS (independently
  reproduced both required mutation tests from a clean start), code-reviewer approve-with-nits. All
  four reviewers independently confirmed a real production gap the suite's own mutation testing
  surfaced: `session::answer`'s wait for an offer (`recv_sdp`) is unbounded — the mirror of task
  1.33's dialer-side fix, newly reachable because a federated route can now be rejected server-side
  before any offer arrives. Filed as its own tracked task rather than left in review prose, mirroring
  2.9→2.15 and 2.10→2.14: **2.17**. code-reviewer also flagged (non-blocking, recommended as a
  Phase-3 fix-task) that test-harness PKI/server-bootstrap boilerplate has now been duplicated a
  fifth/sixth time across `apps/rendezvous/tests/` and `apps/cli/tests/` — debt first noted at 2.7/
  2.8 and still unaddressed.
- **ALSO NOW:** **2.14 is done.** `ChatState::open_inbound` is now a thin wrapper over
  `open_inbound_gated(..., force_first_contact)`; `P2pSession` snapshots
  `chat.has_session(&peer_ik)` before the offer/answer handshake (both `dial_established` and
  `answer_with_config`, including the 1.29 relay-fallback retry, which correctly reuses rather than
  recomputes the snapshot) and forces the gate on the first `CHAT_LABEL` frame via `pump`, clearing
  the flag only once the gate actually fires — a garbled first frame can't let a later genuine one
  slip through ungated. `session_connect.rs` prints a loud sender+safety-number notice instead of
  silently delivering, since that command's `ChatState` has no persisted contacts to accept/reject
  against. New pinning test in `apps/core/tests/p2p_session.rs` proves first content is held, a
  second pre-accept envelope is refused, and accept delivers normally; test-engineer independently
  proved non-vacuity by disabling the gate and confirming the test (plus two others) fail with
  plaintext delivered ungated. architect: consistent, no required changes — confirmed the mechanism
  doesn't disturb the handshake structure and the snapshot timing is race-free. security-reviewer:
  APPROVE — gate-after-verification holds, no new server-visible signal; one non-blocking follow-up
  noted (a narrow mailbox/P2P concurrent-accept race that could spuriously over-gate, fail-safe
  direction, worth a future regression test). test-engineer: PASS, all four affected suites green
  including `--features webrtc`. `docs/security/threat-mitigation-matrix.md`'s gate entry updated to
  close 2.10's relay-path-only caveat.
- **ALSO NOW:** **2.17 is done.** New `OFFER_TIMEOUT` (30s, a distinct name from `ANSWER_TIMEOUT` but
  the same value — the two waits bound different sides of the handshake for different reasons, so
  keeping them independently named allows future independent tuning even though the underlying cost,
  one relay hop plus one peer's up-to-~20s full-candidate gather under non-trickle ICE, is the same)
  and `SessionError::OfferTimeout` now bound both of `answer_with_config`'s `recv_sdp` waits (the
  initial offer wait and the 1.29 relay-fallback retry) — a peer whose offer never arrives (e.g. a
  federated route rejected server-side before any offer reaches the answering side, per 2.12's
  review) now fails closed with a diagnosable error instead of hanging forever, mirroring 1.33's
  dialer-side fix. Traced and ruled out the OTK-consumption-amplifier question the task required:
  `take_otk_secret` only fires after an offer's bytes actually arrive and pass verification, so a
  timed-out wait never touches it — a hostile/absent dial can't drain anything of the answerer's own
  by repeatedly triggering `answer()`. architect: consistent, no required changes — verified the
  timeout math against the real `WAIT_TIMEOUT`/`GATHER_TIMEOUT` bounds, not just asserted.
  security-reviewer: APPROVE — confirmed via code trace, no new attack surface, no wire change.
- **ALSO NOW:** **2.16 is done — and with it, Phase 2 is fully closed.** Root cause, found by direct
  repeated reproduction (not guessed at): `webrtc_backend.rs`'s `ICE_DISCONNECTED_TIMEOUT`+
  `ICE_FAILED_TIMEOUT` (2s+4s, from 1.29) were tight enough that a genuinely-reachable host-candidate
  pair could get declared `Failed` whenever other configured ICE servers stalled against a dead TURN
  endpoint, triggering 1.29's own relay-fallback retry (also doomed) and summing two full bounded
  attempts to ~70-90s — past every external bound the test had tried. Widened to 3s+9s (still inside
  `WAIT_TIMEOUT`'s 15s). architect's review of that widening surfaced a real concern (shrinks 1.29's
  real-NAT margin from 9s to 3s headroom) and, investigating it, a repo-wide gap: the netns-nat-matrix
  rig has **never actually run in CI** since task 1.25 (silently skips without root, and is missing
  `coturn` even with it). Fixed — with explicit user sign-off before pushing, since it grants a CI
  step `sudo` — by installing `coturn` and running the rig's final invocation under `sudo`, scoped to
  that one step. Real CI (PR #46, run `30891921311`) then supplied the actual verification no sandbox
  could: the previously-hanging test passed, and the netns rig executed for the first time ever,
  passing all four NAT cells' pcap assertions (3/4 connect via relay with zero address leak,
  udp-blocked fails per 1.30's documented gap) — confirming the timeout widening is safe under real
  multi-hop NAT, not just asserted. Test hardened with an IP-literal TURN endpoint and bounded runtime
  teardown as defense-in-depth. With 2.1-2.17 all `[x]`, every Phase 2 task is closed.
- **NOW: Phase 3 review sweep is written** — [report](./phase-3/review-report.md), 25 findings
  (**3 blocking, 17 should-fix, 5 nits**), [PR #47](https://github.com/hansajayathilaka/meridian/pull/47).
  Verdict: **blocked until the 3 blockers land**, then green to proceed. Phase 2's crypto/opacity core
  is sound — all six anonymity "must never" invariants and ADRs 0016/0017/0018 hold in code — but the
  sweep found what per-task review structurally could not: three availability/admission defects in the
  **2.6/2.7/2.8 seams** of the federation *server* plane.
  **F1 (blocking)** — outbound federation enforces **no policy**: `admit` is called only on the three
  inbound handlers, never in `dial_foreign`, so a `closed`/allowlist server still dials any
  client-named `hint`; in SRV mode that's client-driven SSRF / internal port-probe (2.6 scoped the
  outbound check and 2.7/2.8 wired only inbound). **F2 (blocking)** — one silent TCP connection wedges
  the whole inbound listener: `accept()` runs the mTLS handshake + `FedHello` inline in a serial,
  timeout-free loop. **F3 (blocking)** — no timeouts on any outbound s2s I/O, so a black-holed partner
  hangs a client's whole ws session and leaks the task + TLS link. All three verified against code, all
  have local fixes. Below blocking: a reachability pre-check that halves 2.6's rate budgets to ~30
  msg/min (F4), an unbounded stranger-flood amplifier in the message-request gate (F5), a shared-
  private-CA + SRV+WebPKI pinning-bypass the demo itself models (F6), dead per-partner `policy` map
  field (F7), fed deliveries uncounted in `envelopes_routed_total` (F8), first-SAN-only allowlisting
  (F9), per-message TLS-config/trust-store reloads + double-dial (F10), the 2.14 gate covering chat
  frames but not stream `Open` (F11), no pre-merge docker build (F12), untested wss:// path (F13),
  plus doc-sync/ratification debt: port 8444 + 1 MiB frame ceiling undocumented (F14), C5 fetch-keying
  in comments only (F15), image publish **migrated Docker Hub → ghcr.io** (removes the long-lived
  registry credential; still-unsigned images + the distribution-channel choice want a short ADR — F16),
  Dokploy stack lacks
  a C7 federation guard-rail (F17), 8× duplicated test PKI (F18), a live `<CHANGE_ME>` coturn realm
  (F19), missing c2s hint conformance vectors (F20), 5 nits. `ROUTE_REPLY_GRACE`'s 500 ms false-
  success residual also needs a tracked task + possible `/adr`. On-the-fly decisions ratified in the
  report's table.
- **ALSO NOW: Phase 3 is planned — 22 fix-tasks (3.1-3.22)**, [phase README](./phase-3/README.md).
  All 25 findings are accounted for; nothing was dropped silently. Three planning calls are worth
  carrying forward:
  **(1) F2 and F3 stay separate tasks** even though both are "s2s timeouts" — accept-side vs
  dial-side, unauthenticated remote DoS vs partner-induced local resource leak, different tests,
  independently revertable. They share only the `with_deadline` helper 3.2 introduces, which is why
  3.2 lands first.
  **(2) The test-harness extraction (3.4/F18) is sequenced *after* the blocking gate, not before.**
  It is the single most important ordering call in the plan: the blockers must not wait on an
  11-file refactor, so the phase deliberately accepts three more `make_ca` copies (from 3.1-3.3) for
  one PR window — but 3.4 then lands before every other test-adding task so a 12th copy never
  appears.
  **(3) Four tasks carry `TODO: confirm` markers rather than guessed numbers** — the timeout/cap
  defaults in 3.2 and 3.3, the `pending_requests` cap in 3.10, and whether a non-public trust root is
  even detectable in 3.16. Implementers must not invent these silently.
  Findings deliberately given **no task**, each with its reason recorded in the phase README: the
  "fine as-is" ratification list (with one carry-forward obligation — zero s2s replay dedup must
  appear in the envelope-v2 task's obligations), the `demo/two-orgs` CI smoke, `relay_rewrite.rs`'s
  timing slack (if it flakes, widen `SIDE_TIMEOUT`, **never** `ANSWER_TIMEOUT`), and the Phase-1
  carried adversarial frontier (SPK grace aging, stale-bundle replay, same-OTK-to-many-fetchers,
  reflection, per-device delivery, skipped-key exhaustion) — carried forward, not dropped.
  **ADR obligations:** 3.19 → ADR 0019 (required); 3.20 → ADR 0020 (conditional, only if the RTT
  measurement reopens the no-`FedRouteOk` wire decision); 3.9 and 3.16 need an architect decision but
  no new ADR (3.16 may need an amending note on ADR 0017).
- **NEXT:** `/next-task` — start Wave 1. **3.1, 3.2, 3.3 are the blocking gate** for the next build
  phase and are independently landable; 3.1 first (highest severity: SSRF/admission), then 3.2, then
  3.3.
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

### Phase 3 — Review of Phase 2 · **planning** · [details](./phase-3/README.md)
Review phase. Sweeps everything built since the Phase-1 review: Phase 2 (2.1–2.17), the Phase-1
follow-ups 1.32/1.33, and the untracked out-of-band PRs #36–#42 (figment/ADR 0018, Docker Hub
publish, Dokploy stack, coturn fixes, CLI `wss://`). [Report](./phase-3/review-report.md): 25 findings
— **3 blocking** (F1 outbound-policy SSRF, F2 serial-accept listener DoS, F3 unbounded outbound s2s
I/O), 17 should-fix, 5 nits. Verdict: **blocked until F1/F2/F3 land**, then green for the next build
phase. Fix-tasks (`3.N`) filled by `/plan-review-phase`.
**Wave 1 — blocking gate** (3.2 before 3.3: same `link.rs`, and 3.3 reuses 3.2's `with_deadline`)
- [ ] **3.1** Enforce federation policy on the outbound dial path (F1) — [file](./phase-3/3.1-outbound-federation-policy.md)
- [ ] **3.2** Un-wedge the inbound s2s listener: concurrent, time-bounded accept (F2+N5) — [file](./phase-3/3.2-inbound-accept-loop-hardening.md)
- [ ] **3.3** Bound every outbound s2s I/O exchange (F3) — [file](./phase-3/3.3-outbound-s2s-timeouts.md)

**Wave 2 — test harness** (after the gate, before every other test-adding task)
- [ ] **3.4** Extract the shared s2s test harness (PKI + server boot) (F18) — [file](./phase-3/3.4-federation-test-support-harness.md)

**Wave 3 — federation server**
- [ ] **3.5** Stop the reachability pre-check double-spending route budgets (F4) — [file](./phase-3/3.5-fed-ratelimit-double-spend.md)
- [ ] **3.6** Accept-side peer identity must consider all authenticated SANs (F9) — [file](./phase-3/3.6-multi-san-peer-identity.md)
- [ ] **3.7** Reuse TLS config + one link per federated message, SRV failover (F10+N2) — [file](./phase-3/3.7-federation-link-reuse.md)
- [ ] **3.8** Count federated deliveries in `envelopes_routed_total` (F8+N4) — [file](./phase-3/3.8-fed-delivery-metrics.md)
- [ ] **3.9** Resolve the dead per-partner `policy` field in `federation_map.toml` (F7) — [file](./phase-3/3.9-federation-map-policy-field.md)

**Wave 4 — parallel track** (core client + CI; no federation-server contention)
- [ ] **3.10** Bound `pending_requests` against a stranger flood (F5) — [file](./phase-3/3.10-message-request-flood-bound.md)
- [ ] **3.11** Thread first-contact state into `decide_open` (ctrl-frame gate) (F11) — [file](./phase-3/3.11-first-contact-ctrl-gate.md)
- [ ] **3.12** Build the rendezvous image pre-merge + schedule the `--ignored` runner (F12) — [file](./phase-3/3.12-ci-docker-build-gate.md)
- [ ] **3.13** Test the `wss://` crypto-provider install (F13) — [file](./phase-3/3.13-wss-crypto-provider-test.md)
- [ ] **3.14** Conformance vectors for the c2s hint extension (F20) — [file](./phase-3/3.14-c2s-hint-conformance-vectors.md)

**Wave 5 — docs, ops, ratification**
- [ ] **3.15** Doc-sync the federation wire/deploy facts (F14+F15) — [file](./phase-3/3.15-federation-protocol-doc-sync.md)
- [ ] **3.16** Warn on private-CA trust anchors under SRV discovery (F6) — [file](./phase-3/3.16-private-ca-srv-hazard.md)
- [ ] **3.17** Give the production stack a federation surface with a C7 guard-rail (F17) — [file](./phase-3/3.17-dokploy-federation-surface.md)
- [ ] **3.18** Fix the live coturn `realm` placeholder (F19) — [file](./phase-3/3.18-coturn-realm-placeholder.md)
- [ ] **3.19** ADR 0019 — container image distribution + signing (F16 remainder) — [file](./phase-3/3.19-adr-image-distribution-signing.md)

**Wave 6 — last**
- [ ] **3.20** Resolve the `ROUTE_REPLY_GRACE` false-positive-success residual (may yield ADR 0020) — [file](./phase-3/3.20-route-reply-grace-residual.md)
- [ ] **3.21** Nit sweep (N1, N3) — [file](./phase-3/3.21-phase-3-nit-sweep.md)
- [ ] **3.22** s2s framing adversarial suite (**optional — first to cut**) — [file](./phase-3/3.22-s2s-framing-adversarial.md)

---

## Legend / how to read
- Each task line links to its own file with **Goal · Scope · Deliverables · Risks · Tests · Reviews · Status**.
- Phase folders (`phase-N/`) hold a `README.md` (phase overview + todo) and one file per task; review
  phases also hold a `review-report.md`.
- Definition of Task and Definition of Done: [CONTRIBUTING.md](../../CONTRIBUTING.md).
