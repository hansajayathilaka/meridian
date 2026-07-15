<!-- Source: post-Feature-5 review (library-change security, completed-work, missing tasks, gaps, future
     risks). This plan governs REMEDIATION work; the feature cadence resumes at roadmap.md once Phase 5
     clears. Every task closes one or more review findings by construction — see the traceability map. -->
> **Nav:** [docs index](../INDEX.md) · [roadmap](./roadmap.md) · [system design](./system-design.md) · [ADR index](../adr/README.md) · [Definition of Done](../../CONTRIBUTING.md) · [test strategy](../testing/strategy.md)

# Implementation Plan — Remediation of the Features 1–5 Review

This plan turns the Features 1–5 review into buildable work. It sits **between** the completed critical
path (Features 01–05) and the next roadmap feature (06, Cross-Org Federation): the review found the
*code* sound but the *guardrails, conformance surface, and real transport* incomplete, so the
foundation is hardened here before more features stack on it.

**Relationship to the [roadmap](./roadmap.md).** The roadmap orders *features*; this plan orders the
*remediation* that must land before the roadmap resumes. Feature tasks (06–16) are still started with
[`/new-task <feature>`](../../.claude/commands/new-task.md); remediation tasks in this document are
driven one at a time with [`/next-task`](../../.claude/commands/next-task.md). Phase 5 is the explicit
hand-back point.

**How tasks are sized.** Each task builds exactly **one small, self-contained thing** that can be
planned, built test-first, tested, and reviewed in a single focused pass. That granularity is
deliberate: the review's worst findings (a lint that checks nothing, a "frozen" format with no vectors,
a completed feature running on a simulated transport) all came from work that was too coarse to verify.
Small tasks close that class of gap by construction.

**Every task below carries the same five fields:**
- **Scope** — the one thing it builds (and, implicitly, what it does *not*).
- **Touches** — crates/files/docs, with an **[ADR]** tag when it enters an ADR-bound area (crypto,
  transport, wire protocol, federation) and a **[SEC]** tag when it touches identity, keys, crypto,
  signaling, storage, logging, metrics, or federation. Tagged tasks get **architect** and/or
  **security-reviewer** design sign-off *before* build.
- **Deliverables** — the documented artifacts produced.
- **Tests** — the tests that prove it works (authored test-first).
- **Verification (DoD)** — the [Definition of Done](../../CONTRIBUTING.md) items this task must satisfy,
  by number.
- **Depends on** — upstream task IDs.

---

## Part A — Completed work (baseline, carried forward as done)

These are **done** and are not re-planned or re-opened here. They are the baseline the remediation
builds on. Where the review found a gap *inside* a completed feature, the gap is carried as a
remediation task in Part B (cited in the "closes" column of the traceability map) — the feature itself
still stands.

| # | Feature | Status | Verified by |
|---|---------|--------|-------------|
| 01 | Identity & Keystore Core | **Done** | `meridian-identity` + CLI; `test-vectors/identity-v1.json` consumed byte-for-byte by `apps/identity/tests/conformance.rs`; 10⁶ fuzz + flipped-bit + same-principal + plaintext-never-on-disk all pass |
| 02 | Rendezvous Server MVP | **Done** | `meridian-rendezvous` binary + Dockerfile; challenge/response auth, exact-key bundle fetch, fail-closed tampered-bundle abort (`mitm-sim`); opaque routing verified |
| 03 | E2EE Messaging (relayed) | **Done** | In-house composed Double Ratchet + X3DH in `meridian-crypto`, verified line-by-line against `messaging-envelope-v1.md`; FS/PCS/out-of-order/restart-resume tests pass; opacity audit passes |
| 04 | P2P Session Substrate | **Done (substrate logic)** | `Transport` trait, session state machine, fingerprint binding, ctrl channel, stream registry, ICE-restart — all tested against `LoopbackTransport` |
| 05 | NAT Traversal & Relay Policy | **Done (policy logic)** | Three-position policy, strip-before-gather, ephemeral TURN minting, `meridian doctor` — all tested in-process |

> **Honesty note carried into Part B.** Features 04 and 05 are complete at the *substrate/policy* layer
> but their *wire-level* acceptance (real WebRTC, real coturn, packet captures) was never demonstrated,
> because no production transport backend exists. That divergence is closed by **Phase 3**, and until it
> lands the specs are annotated "wire-level verification deferred" by **T0.5** — the features are not
> silently overclaimed.

---

## Part B — Remaining work (6 phases, 37 tasks)

Phases are dependency-ordered. Within a phase, tasks may run in any order unless a "Depends on" says
otherwise. **Phase 0 and Phase 1 are pure-guardrail** (documentation truth and CI enforcement) and
carry near-zero product-code risk, so they land first and stop the review's findings from regressing
while later phases are built.

### Phase 0 — Truth restoration: doc & ADR integrity (6 tasks)

*No product code changes. Fixes the recorded design so the ADRs, the stack doc, and — most importantly
— the `.claude/` guidance that steers future sessions stop teaching a superseded decision.*

#### T0.1 — Write ADR 0015: ratchet composed in `meridian-crypto` **[ADR][SEC]**
- **Scope.** The standalone superseding ADR the 2026-07 note in ADR 0011 promised but never produced.
- **Touches.** `docs/adr/0015-ratchet-composition.md` (new); references `docs/adr/0011-ratchet-library.md`,
  `docs/adr/0003-e2ee-protocol.md`. **architect** authors/reviews via `/adr`.
- **Deliverables.** ADR in house format: Options A/B/C with fair pro/con, the `ratchet-header-enc` spike
  finding as Context, explicit **"Supersedes the ratchet-mechanism portion of ADR 0011"**, and a restatement
  that the Apache-vs-AGPL license rationale of 0011 stands. Records "protocol glue over audited
  primitives, not an audited protocol implementation" as an accepted con on the Phase-1 external-review gate.
- **Tests.** `tools/check-docs.sh` (links + mermaid) passes; ADR cross-links resolve.
- **Verification (DoD).** 5 (no architectural drift — decision recorded via supersede), 7 (docs synced).
- **Depends on.** —

#### T0.2 — Correct ADR 0011 header and the ADR index
- **Scope.** Make the binding record self-consistent: ADR 0011's status line and the index must point to 0015.
- **Touches.** `docs/adr/0011-ratchet-library.md` (status line ~L6), `docs/adr/README.md` (row L20, notes L25–28).
- **Deliverables.** 0011 status → "Accepted; ratchet mechanism superseded by 0015" with a top-of-file
  pointer; the 2026-07 note kept as history, linked to 0015. Index row + "remaining spike" note corrected
  (the `ratchet-header-enc` spike ran; its outcome is 0015).
- **Tests.** `tools/check-docs.sh` passes; grep shows no "(Accepted)" claim for the pre-supersede decision.
- **Verification (DoD).** 5, 7.
- **Depends on.** T0.1

#### T0.3 — Doc-sync the vodozemac drift (10 locations; `.claude/` first) **[SEC]**
- **Scope.** Every doc that still says "the ratchet is vodozemac" is corrected to "composed in
  `meridian-crypto` per ADR 0015". No code.
- **Touches, in blast-radius order:** `.claude/skills/crypto-protocols/SKILL.md` (L8,13,17 — "Ratchet =
  vodozemac" absolute rule), `.claude/agents/architect.md` (L23–25 — claims 0011 unresolved),
  `CLAUDE.md` (L18), `docs/adr/README.md`, `docs/architecture/stack.md` (L20,132,153,179),
  `docs/glossary.md` (L14), `docs/INDEX.md` (L87–88,106), `docs/handoff-readiness.md` (L71),
  `LICENSE` (L23). **architect** verifies completeness. Run via `/doc-sync`.
- **Deliverables.** Updated docs; the crypto skill states the composition rule and the "never bespoke =
  never hand-roll a *primitive*; well-specified protocol glue over audited primitives is allowed" nuance.
- **Tests.** `grep -rn vodozemac docs .claude CLAUDE.md LICENSE` returns only ADR 0011/0015 history and
  the "vodozemac remains the fallback if it exposes a seedable ratchet" note — nowhere else.
- **Verification (DoD).** 7, 8.
- **Depends on.** T0.1

#### T0.4 — Repair the roadmap phasing corruption and the ADR 0013 splice artifact
- **Scope.** Restore the "Phasing" content that a botched extraction overwrote with spliced ADR text.
- **Touches.** `docs/architecture/roadmap.md` (L30–43, corrupted), `docs/adr/0013-server-web-framework.md`
  (trailing orphan heading L8–9). Correct content survives at `docs/architecture/system-design.md:317–325`.
- **Deliverables.** A real phasing table (Phases 0–4) summarizing/linking system-design §11; the stray
  ADR 0013 heading removed. Adds a note that `check-docs.sh` validates only links+mermaid, so this
  corruption class is CI-invisible — see T0.4's follow-on lint idea in Phase 1.
- **Tests.** `tools/check-docs.sh` passes; roadmap renders with no orphaned ADR fragments.
- **Verification (DoD).** 7.
- **Depends on.** —

#### T0.5 — Annotate F03/F04/F05 specs with the wire-level-deferred status
- **Scope.** Record, in the specs themselves, that F04/F05 acceptance requiring real WebRTC/coturn/captures
  is deferred to Phase 3; align the F03 "no hand-rolled ratchet" wording with ADR 0015.
- **Touches.** `docs/architecture/features/03-…md` (L12 "no hand-rolled ratchet" → "no hand-rolled
  *primitive*; ratchet composed per ADR 0015"), `04-…md`, `05-…md` (acceptance sections),
  `docs/handoff-readiness.md` (F. spikes: mark `ratchet-header-enc` resolved).
- **Deliverables.** Specs carry an explicit "wire-level verification: deferred to implementation-plan
  Phase 3" banner; no acceptance criterion is silently dropped.
- **Tests.** `tools/check-docs.sh` passes.
- **Verification (DoD).** 7, 8.
- **Depends on.** T0.1

#### T0.6 — Open the deniability-vs-envelope-signature decision **[ADR][SEC]**
- **Scope.** Surface, as a decision task, the contradiction the review found *inside the design*: the
  envelope signs every ciphertext with the identity key (`Sign_IK{ratchet_ct}`,
  `messaging-envelope-v1.md:96`), while threat-model goal 4 (`threat-model.md:34`) claims deniability
  because "identity-key signatures are confined to key distribution and signaling." A signed ciphertext
  is third-party-provable authorship.
- **Touches.** `docs/adr/0016-message-authorship-deniability.md` (new, **draft**); references the envelope
  spec and threat model. **architect + security-reviewer** own it.
- **Deliverables.** A draft ADR laying out the two consistent end-states — (a) narrow the deniability
  claim in the threat model, or (b) drop the outer signature in envelope v2 (the ratchet AEAD already
  binds both identity keys) — with the security trade of each. **This task ends in a recorded decision,
  not code.** If option (b) is chosen it schedules a wire-versioned envelope-v2 task; if (a), it amends
  the threat model. **This is the one finding that may need a human call** — the loop escalates it via
  `AskUserQuestion` rather than choosing unilaterally, because it changes a stated security guarantee.
- **Tests.** N/A (decision doc); `check-docs.sh` passes.
- **Verification (DoD).** 4 (security invariants — deniability claim), 5, 8.
- **Depends on.** —

### Phase 1 — Make the CI gates real (enforcement layer, 10 tasks)

*The review's central finding: the code is clean but the gates that keep it clean are hollow. These
land before Phase 2+ so new work can't slip through a decorative check. Each task makes one gate
actually fail on the violation it names.*

#### T1.1 — Metrics-allowlist: assert on rendered output, not macro style **[SEC]**
- **Scope.** Make the metrics gate catch a non-allowlisted metric (e.g. a `{from,to}` contact-graph
  label) that today sails through because `metrics.rs` renders text by hand.
- **Touches.** `tools/lint-metrics-allowlist.sh`, `apps/rendezvous/tests/rendezvous.rs` (L293),
  `tools/metrics-allowlist.txt`. **[SEC]** metrics. security-reviewer signs off.
- **Deliverables.** Lint greps `meridian_[a-z_]+` string literals in `apps/rendezvous/src` against the
  allowlist; the integration test parses **every** family in the `/metrics` body and asserts membership.
- **Tests.** New test: injecting a rogue metric family fails the assertion; the exhaustiveness lint flags
  a planted non-allowlisted literal.
- **Verification (DoD).** 2, 4 (the metrics-allowlist enforcement lint must actually enforce).
- **Depends on.** —

#### T1.2 — no-serde-on-blob: deny envelope-content decoding in the server **[SEC]**
- **Scope.** Make the lint catch the must-never-#1 defect it exists for — type-inferred decode of an
  envelope/content type in the routing path.
- **Touches.** `tools/lint-no-serde-on-blob.sh`; optionally split `meridian-proto` so content types live
  in a module the server crate cannot import. **[SEC]** storage/logging boundary. security-reviewer.
- **Deliverables.** Lint denies `MessageEnvelope|SignalContent|ChatContent|from_blob|\.blob\.0` in
  non-test `apps/rendezvous/src`; catches both turbofish and inference decode.
- **Tests.** A planted `let _: MessageEnvelope = decode(&body.blob.0)` in a fixture fails the lint;
  current server code passes.
- **Verification (DoD).** 4 (no-serde-on-blob lint must pass *and mean it*).
- **Depends on.** —

#### T1.3 — Make clippy blocking
- **Scope.** Remove the `|| true` so clippy is a real gate (it is clean today, so this is free).
- **Touches.** `.github/workflows/ci.yml` (lint job), `Justfile` (`lint`).
- **Deliverables.** `cargo clippy --workspace --all-targets -- -D warnings` blocks CI.
- **Tests.** CI lint job fails on a planted `#[warn]`-triggering line; passes on `main`.
- **Verification (DoD).** 1 (builds & lints clean — enforced, not incidental).
- **Depends on.** —

#### T1.4 — Land `deny.toml` and a real cargo-deny job **[ADR]**
- **Scope.** Enforce the AGPL/license invariant ADR 0011/0015 declare but CI only `echo`es.
- **Touches.** `deny.toml` (new), `.github/workflows/ci.yml` (supply-chain job). **[ADR]** license
  decision. architect confirms the policy matches ADR 0015.
- **Deliverables.** `cargo deny check advisories licenses` blocking AGPL and flagging advisories.
- **Tests.** A planted AGPL dev-dep fails the job; the current graph passes.
- **Verification (DoD).** 5 (ADR consequence enforced).
- **Depends on.** T0.1 (policy references 0015)

#### T1.5 — Re-point the opacity-audit harness at the real test
- **Scope.** The named CI "Adversarial harnesses" gate must run the real audit, not the exit-0 stub.
- **Touches.** `harnesses/opacity-audit/run.sh`, `harnesses/README.md` (stale status table).
- **Deliverables.** `run.sh` invokes `cargo test -q -p meridian-cli opacity_audit_passes` (mirrors
  `mitm-sim`/`nat-matrix`); README table reflects live vs stub accurately.
- **Tests.** Weakening the opacity test now turns the harness red (verified by a scratch edit, reverted).
- **Verification (DoD).** 2 (security tests never weakened — and the gate can now detect weakening).
- **Depends on.** —

#### T1.6 — Harden lint-server-no-core to the resolved graph **[ADR]**
- **Scope.** Enforce the *actual* invariant (server depends only on `meridian-proto`), not a one-file grep.
- **Touches.** `tools/lint-server-no-core.sh`. **[ADR]** dependency topology (ADR 0008). architect.
- **Deliverables.** `cargo tree -p meridian-rendezvous -e normal -i meridian-core` (and `-identity`,
  `-store`, `-crypto`) asserted empty; dev-deps excluded so test-only usage doesn't false-positive.
- **Tests.** A planted normal-dep on `meridian-core` fails; current graph passes.
- **Verification (DoD).** 5 (server-no-core invariant).
- **Depends on.** —

#### T1.7 — Fail closed on config-load error **[SEC]**
- **Scope.** A requested-but-unparseable `--config` must abort, not silently boot open-registration defaults.
- **Touches.** `apps/rendezvous/src/main.rs` (L32–38). **[SEC]** admission/federation posture.
  security-reviewer (threat-model goal 6).
- **Deliverables.** Non-zero exit when `--config` is given and fails to parse; defaults only when no config
  was requested.
- **Tests.** Startup test: bad path / malformed TOML → non-zero exit; valid config boots; no-config uses defaults.
- **Verification (DoD).** 4 (fail closed, never silently weaker).
- **Depends on.** —

#### T1.8 — Feature-gate the bundle-tamper hook out of release **[SEC]**
- **Scope.** Remove the key-substitution code path from production binaries.
- **Touches.** `apps/rendezvous/src/ws.rs` (L230–235), `config.rs` (L28), `apps/proto/src/msg.rs`
  (`Fetch.tamper`). **[SEC]** signaling/key trust. security-reviewer.
- **Deliverables.** `substitute_bundle` + `tamper` honor path behind a `test-hooks` cargo feature excluded
  from `--release`; startup refuses `allow_test_tamper=true` unless `domain=="localhost"`.
- **Tests.** `mitm-sim` still passes with the feature on; a release build has no tamper symbol (compile check).
- **Verification (DoD).** 4.
- **Depends on.** —

#### T1.9 — Evict expired rate-limiter entries
- **Scope.** Bound the rate-limiter map so attacker-controlled IPs can't grow it unboundedly (memory-DoS +
  incidental in-RAM record of every key seen).
- **Touches.** `apps/rendezvous/src/ratelimit.rs` (L35).
- **Deliverables.** Per-`check` eviction of expired windows (or a size cap).
- **Tests.** Unit test: expired entries are dropped; live windows retained; map size bounded under churn.
- **Verification (DoD).** 2, 4.
- **Depends on.** —

#### T1.10 — Add a salted-hash `LogId` and a tracing-identifier lint **[SEC]**
- **Scope.** Put the invariant-#4 guardrail in place *before* observability lands (today it's satisfied only
  because the server logs nothing).
- **Touches.** `apps/rendezvous/src/` (new `LogId` newtype), `tools/lint-log-no-raw-id.sh` (new), CI + Justfile.
  **[SEC]** logging. security-reviewer.
- **Deliverables.** `LogId` (per-deploy salt from config → truncated hash, `Display` via hash only); lint
  denies `account_pub`/`peer_ip`/`auth.` inside `tracing::`/`log::` call sites in `apps/rendezvous`.
- **Tests.** Lint fails on a planted `tracing::info!(?account_pub)`; `LogId` never renders the raw value.
- **Verification (DoD).** 4.
- **Depends on.** —

### Phase 2 — Freeze the crypto: conformance vectors + hygiene (7 tasks)

*The swap is correct but unpinned. These convert "frozen" from a doc claim into a byte-checked CI reality
before the browser/mobile ports (Features 11/12) implement the same spec against nothing. All are **[SEC]**;
wire-frozen vector tasks are **[ADR]** (a vector defines the wire).*

#### T2.1 — X3DH known-answer vectors + CI runner **[ADR][SEC]**
- **Scope.** Freeze the X3DH derivation: fixed inputs → `master`, `root`, `hk_ab`, `hk_ba`, `AD`.
- **Touches.** `tools/xtask/src/vectors.rs`, `test-vectors/x3dh-v1.json` (new), `apps/crypto/tests/`,
  `.github/workflows/ci.yml` (L51 TODO). **[ADR]** wire/KDF labels. architect + security-reviewer.
- **Deliverables.** KAT file generated by `xtask -- vectors`; a consuming test; CI runner replacing the TODO.
- **Tests.** Byte-exact assertion against the committed vectors; a deliberately wrong `info` string fails.
- **Verification (DoD).** 3 (wire/API vector-checked), 4.
- **Depends on.** —

#### T2.2 — Double Ratchet transcript vectors **[ADR][SEC]**
- **Scope.** Freeze a fixed ratchet transcript → ciphertexts + header/chain-key intermediates.
- **Touches.** `test-vectors/ratchet-v1.json` (new), `apps/crypto/tests/`, `xtask`. **[ADR]** header layout,
  `KDF_RK`/`KDF_CK`/`MsgKey` labels. architect + security-reviewer.
- **Deliverables.** KAT covering a DH-ratchet step, a skipped-key case, and header encryption; consuming test.
- **Tests.** Byte-exact; an off-by-one chain-key label fails.
- **Verification (DoD).** 3, 4.
- **Depends on.** T2.1

#### T2.3 — Envelope + prekey-bundle vectors **[ADR][SEC]**
- **Scope.** Freeze `MessageEnvelope` and the `v:1` prekey bundle byte layout.
- **Touches.** `test-vectors/envelope-v1.json`, `test-vectors/prekey-bundle-v1.json` (new),
  `apps/proto/tests/`, `apps/signaling/`, `xtask`. **[ADR]** wire format. architect + security-reviewer.
- **Deliverables.** KATs + consuming tests; `signing_input` construction pinned.
- **Tests.** Byte-exact; a reordered signing-input field fails.
- **Verification (DoD).** 3, 4.
- **Depends on.** —

#### T2.4 — Safety-number vectors + value test **[SEC]**
- **Scope.** Populate the empty `safety-numbers-v1.json` and assert a *value*, not just symmetry.
- **Touches.** `test-vectors/safety-numbers-v1.json`, `apps/crypto/tests/`, `xtask`. **[SEC]** verification UX
  backstop. security-reviewer (resolves the "5200 iterations, version width, chunk endianness" ambiguity).
- **Deliverables.** ≥3 KAT fingerprints; a value-asserting test; the iteration semantics documented unambiguously.
- **Tests.** Byte/value-exact; an off-by-one iteration count fails. (T08 later builds compare-UX on this.)
- **Verification (DoD).** 3, 4.
- **Depends on.** —

#### T2.5 — Zeroize the X3DH master secret and ratchet header keys **[SEC]**
- **Scope.** Close the two hygiene gaps: the concatenated `ikm` master secret and the four header keys.
- **Touches.** `apps/crypto/src/x3dh.rs` (L57–74, 94–102, 132–140), `apps/crypto/src/ratchet.rs`
  (Drop L70–84). **[SEC]** keys. security-reviewer.
- **Deliverables.** `Zeroizing<Vec<u8>>` for `ikm`; `okm` zeroized; `hks/hkr/nhks/nhkr` added to `Drop`.
- **Tests.** A test asserting the header-key fields are covered by `Drop` (or a `#[cfg(test)]` hook); existing
  crypto tests still pass.
- **Verification (DoD).** 4.
- **Depends on.** —

#### T2.6 — Dedicated at-rest key-derivation op on `SecretStore` **[ADR][SEC]**
- **Scope.** Stop deriving the session-store key from a signature (which a randomized/HSM signer would make
  non-deterministic → permanently undecryptable state).
- **Touches.** `apps/store/src/lib.rs` (trait), `apps/crypto/src/at_rest.rs` (L19–24),
  `apps/core/src/chat.rs`, `messaging-envelope-v1.md` (§6 TODO). **[ADR]** SecretStore contract (ties to
  ADR 0005 multi-device). architect + security-reviewer.
- **Deliverables.** A `derive`/`kdf` op on `SecretStore`; at-rest key uses it; the determinism dependency
  removed and the §6 `TODO: confirm` resolved.
- **Tests.** Round-trip persistence across a simulated randomized-signature store; a migration/versioning
  test for existing sealed state.
- **Verification (DoD).** 3 (if the seal format versions), 4, 5.
- **Depends on.** T2.3 (share the vector harness)

#### T2.7 — wasm32 + aarch64 build validation in CI
- **Scope.** Deliver the F03 risk-note requirement: prove the crypto/core compiles to the target matrix
  "this task, not later."
- **Touches.** `.github/workflows/ci.yml` (add wasm32/aarch64 build steps), `apps/web` (real build vs echo
  stubs), feature-gating `meridian-store` native backends for wasm.
- **Deliverables.** CI builds `meridian-crypto`/`meridian-core` to `wasm32` and `aarch64`; the store's
  native (age/keyring) backends are feature-gated off for wasm.
- **Tests.** CI target-build jobs are green and blocking.
- **Verification (DoD).** 1, 3 (byte-identical-across-targets is *possible* once these build).
- **Depends on.** T2.1, T2.2, T2.3 (vectors give the cross-target check something to compare)

### Phase 3 — Real transport backend: close Features 04/05 by construction (8 tasks) **[ADR]**

*Replaces the simulated transport so F04/F05 acceptance is proven on a real wire. Every task here is
ADR-bound (0014 media stack / 0006 terminal transport); the fingerprint and relay-only tasks are also
**[SEC]**. Gated behind the existing empty `webrtc` feature so default CI stays pure-Rust.*

#### T3.1 — webrtc-rs backend skeleton behind the `Transport` trait **[ADR]**
- **Scope.** A real `WebRtcTransport` implementing the trait, feature-gated `webrtc`, data-channel connect
  only (no policy/fingerprint yet).
- **Touches.** `apps/transport/Cargo.toml` (real dep), `apps/transport/src/webrtc.rs` (new). **[ADR]** 0014/0006.
  architect approves the dependency + seam before build; devops on the dep tree.
- **Deliverables.** Feature-gated backend; two in-process peers connect over a real data channel.
- **Tests.** Gated integration test: connect + echo over `webrtc`; default build unchanged.
- **Verification (DoD).** 1, 5 (matches ADR 0014 trait seam).
- **Depends on.** Phase 1 (gates), T0.5

#### T3.2 — Real DTLS fingerprint binding + teardown **[ADR][SEC]**
- **Scope.** Cross-check the negotiated DTLS fingerprint against the identity-signed value on the *real*
  handshake; mismatch tears down.
- **Touches.** `apps/transport/src/webrtc.rs`, `apps/core/src/session.rs` (L900–916). **[ADR][SEC]** §4.6.
  security-reviewer + architect.
- **Deliverables.** Real-backend fingerprint verification wired to the existing fail-closed teardown.
- **Tests.** Forced-mismatch integration test (real DTLS) tears down 100%; extends `mitm-sim`.
- **Verification (DoD).** 2, 4.
- **Depends on.** T3.1

#### T3.3 — Real ICE gathering + relay-only strip-before-gather; observed-candidate `session info` **[ADR][SEC]**
- **Scope.** Gather real host/srflx/relay candidates; `relay-only` strips host/srflx *before* gathering; the
  privacy line is derived from *observed* candidates and aborts if a host/srflx leaks.
- **Touches.** `apps/transport/src/webrtc.rs`, `apps/core/src/session.rs` (L291,296–299 — the hardcoded
  `transport:"webrtc-datachannel"` overclaim and the policy-derived line). **[ADR][SEC]** §5.4.
  security-reviewer + architect.
- **Deliverables.** `session info` reflects the real backend and real candidate classes; dial aborts if a
  host/srflx candidate appears under `RelayOnly`.
- **Tests.** Integration: under `RelayOnly`, `local_candidates()` contains only relay; a forced host candidate
  aborts the dial.
- **Verification (DoD).** 4, 6 (honest availability — no overclaim in user-visible output).
- **Depends on.** T3.1

#### T3.4 — netns two-LAN rig on the real backend (F04 acceptance) **[ADR]**
- **Scope.** Drive `tools/netns-two-lans.sh` with the real `webrtc` build across two NAT'd namespaces.
- **Touches.** `tools/netns-two-lans.sh` (remove the "when the webrtc backend is built" TODO), CI (root-gated job).
  **[ADR]** connectivity-debugger runs point.
- **Deliverables.** Server-down chat continuity demonstrated over a real P2P path across two LANs.
- **Tests.** The rig connects host→srflx and survives a server kill; CI runs it where NET_ADMIN is available,
  skips honestly otherwise.
- **Verification (DoD).** 2.
- **Depends on.** T3.1, T3.3

#### T3.5 — coturn integration: ephemeral creds end-to-end + single-session enforcement **[ADR][SEC]**
- **Scope.** Run real coturn; mint→use→expire a credential; make "single-session/reuse-rejected" true
  (`user-quota`) or reword the claim honestly.
- **Touches.** `infra/coturn/turnserver.conf` (L50 `user-quota`), `apps/rendezvous/src/turn.rs`,
  `docs/api/rendezvous-protocol-v1.md` (L77), `05-…md` (L32). **[SEC]** relay/metadata. devops +
  security-reviewer.
- **Deliverables.** End-to-end TURN allocation against real coturn; `user-quota` bounding allocations per
  credential window; docs reworded to the enforced property.
- **Tests.** Integration: a captured credential's reuse is bounded/rejected as documented; expiry rejects.
- **Verification (DoD).** 4, 7 (docs match enforced behavior — no overclaim).
- **Depends on.** T3.1

#### T3.6 — netns NAT matrix + tcpdump captures in CI (F05 acceptance) **[ADR][SEC]**
- **Scope.** The four NAT cells over the real backend + relay; packet captures prove the wire-level claims.
- **Touches.** `tools/netns-nat-matrix.sh` (L71–78 TODO), CI. **[ADR][SEC]** connectivity-debugger +
  security-reviewer.
- **Deliverables.** All four cells connect (symmetric×symmetric via relay, UDP-blocked via TLS-443); a
  capture on the peer namespace contains **zero** of our host/srflx addresses under `relay-only`; a capture
  on the TURN namespace shows only DTLS ciphertext.
- **Tests.** Capture-asserting tests (root-gated in CI, honest skip otherwise).
- **Verification (DoD).** 2, 4.
- **Depends on.** T3.3, T3.5

#### T3.7 — webrtc-rs SCTP soak test **[ADR]**
- **Scope.** The F04 risk-note soak: SCTP throughput/stability under loss, *before* Feature 09's 1 GiB
  transfers depend on it.
- **Touches.** `harnesses/` (new soak entry) or a `--ignored` long test; connectivity-debugger + test-engineer.
- **Deliverables.** A soak run measuring throughput/stability under injected loss; a recorded baseline.
- **Tests.** `--ignored` soak test with a documented pass threshold; runs in a nightly/opt-in CI lane.
- **Verification (DoD).** 2.
- **Depends on.** T3.1

#### T3.8 — Timed acceptance: ≥30 min continuity, <5 s ICE restart **[ADR]**
- **Scope.** Replace the structural stand-ins with *measured* timing acceptance from the F04 spec.
- **Touches.** `apps/core/tests/p2p_session.rs`, netns rig. **[ADR]** connectivity-debugger.
- **Deliverables.** A measured server-down continuity run and a measured Wi-Fi→other-interface ICE-restart
  recovery under 5 s.
- **Tests.** Timed assertions (opt-in lane for the 30-min run).
- **Verification (DoD).** 2.
- **Depends on.** T3.4

### Phase 4 — Deferred correctness & completed-work gaps (4 tasks)

*Independent correctness items the review found inside completed features. Grouped here because none
blocks the foundation, but each closes a real gap.*

#### T4.1 — Desync → fresh-X3DH auto-recovery **[SEC]**
- **Scope.** Implement the §10 recovery the F03 spec requires: a peer that can't decrypt under `HKr`/`NHKr`
  re-initiates X3DH (fresh prekey message) instead of stranding the session.
- **Touches.** `apps/core/src/chat.rs`, `apps/crypto/src/`. **[SEC]** crypto/session. security-reviewer.
- **Deliverables.** Automatic fresh-X3DH on unrecoverable desync; documented in `messaging-envelope-v1.md` §3.
- **Tests.** Induce desync (drop/replace ratchet state) → session heals within one round-trip; no plaintext
  downgrade path.
- **Verification (DoD).** 2, 4.
- **Depends on.** T2.2

#### T4.2 — Real 5k-connection capacity test (F02)
- **Scope.** Replace the phantom `--ignored capacity` reference with a real `#[ignore]` capacity test.
- **Touches.** `apps/rendezvous/tests/rendezvous.rs` (L338–342).
- **Deliverables.** An `#[ignore]`d test that opens the target connection count and asserts the acceptance
  bound; wired into an opt-in CI lane.
- **Tests.** The capacity test itself; the default suite is unaffected.
- **Verification (DoD).** 2.
- **Depends on.** —

#### T4.3 — Make `malicious_relay_cannot_touch_inner_sdp` a real adversarial test **[SEC]**
- **Scope.** The test's body must perform the relay rewrite (wrong `from`) it promises, not just confirm a
  healthy connect.
- **Touches.** `apps/core/tests/p2p_session.rs` (L248–264), loopback MITM harness. **[SEC]** signaling.
  security-reviewer.
- **Deliverables.** The test injects a routing-metadata rewrite and asserts the inner SDP is untouched and
  the session behaves correctly.
- **Tests.** The rewritten-`from` case fails closed / is rejected as designed.
- **Verification (DoD).** 2.
- **Depends on.** —

#### T4.4 — SPK rotation policy: confirm design, then implement **[ADR][SEC]**
- **Scope.** Resolve the genuinely-absent design detail (SPK rotation/overlap; single-SPK `PrekeyVault`).
- **Touches.** `messaging-envelope-v1.md`, `apps/signaling/src/bundle.rs` (L16 TODO), `apps/core/src/chat.rs`.
  **[ADR][SEC]** key lifecycle. architect + security-reviewer decide the policy first (may amend a spec),
  then a follow-on task implements it.
- **Deliverables.** A documented rotation/overlap policy; implementation honoring it.
- **Tests.** Rotation retains in-flight sessions; expired SPK handling; no reuse gap.
- **Verification (DoD).** 3 (if wire touched), 4, 5, 8.
- **Depends on.** T2.3

### Phase 5 — Phase-1 GA readiness gate & roadmap hand-back (2 tasks)

#### T5.1 — Assemble the external crypto-review package **[SEC]**
- **Scope.** The hand-composed ratchet's only independent scrutiny is the Phase-1 external review
  (`testing/strategy.md §7`); make it actionable.
- **Touches.** `docs/testing/strategy.md` §7, a review-package doc. **[SEC]** security-reviewer assembles.
- **Deliverables.** A package: ADR 0015, the frozen vectors (T2.1–T2.4), the ratchet-glue source map, and
  the threat-model deltas from T0.6. Scheduled as a named GA gate.
- **Tests.** N/A (process); the referenced artifacts all exist and are linked.
- **Verification (DoD).** 4, 8.
- **Depends on.** T2.1, T2.2, T2.3, T2.4, T0.6

#### T5.2 — Foundation-green checkpoint → resume the roadmap
- **Scope.** Confirm every Phase 0–4 gate is green and hand control back to the feature cadence
  (`/new-task 06-cross-org-federation`).
- **Touches.** `docs/architecture/roadmap.md` (mark remediation complete), this plan (status).
- **Deliverables.** A checkpoint note: all lints blocking and meaningful, all vectors frozen and checked,
  real transport proven; Feature 06 unblocked.
- **Tests.** Full `just lint && just test` green; all harnesses live (no stubs for shipped features).
- **Verification (DoD).** 1–8 (whole-repo).
- **Depends on.** All prior phases.

---

## Part C — Traceability: every review finding → the task that closes it

| Review area | Finding | Closed by |
|---|---|---|
| 1 Library change | No X3DH/ratchet/envelope/safety-number vectors | T2.1, T2.2, T2.3, T2.4 |
| 1 | ADR supersede procedure not followed (no ADR 0015) | T0.1, T0.2 |
| 1 | 10 docs still say vodozemac (`.claude/` first) | T0.3 |
| 1 | cargo-deny AGPL gate absent | T1.4 |
| 1 | X3DH master secret + header keys un-zeroized | T2.5 |
| 1 | At-rest key depends on signature determinism | T2.6 |
| 1 | Opacity-audit harness is a stub | T1.5 |
| 1 | T03 spec still says "no hand-rolled ratchet" | T0.5 |
| 2 Completed work | F02 5k-capacity test is phantom | T4.2 |
| 2 | F03 desync→fresh-X3DH not implemented | T4.1 |
| 2 | F04 no webrtc-rs backend; `session info` overclaims | T3.1, T3.3 |
| 2 | F04 weakened `malicious_relay` test | T4.3 |
| 2 | F05 wire-level acceptance simulated; coturn unrun; single-session overclaim | T3.5, T3.6 |
| 3 Missing tasks | Conformance vectors + CI runner | T2.1–T2.4, T2.7 |
| 3 | wasm32 build validation | T2.7 |
| 3 | Roadmap corruption + ADR 0013 splice | T0.4 |
| 4 Gaps | Metrics-allowlist lint vacuous | T1.1 |
| 4 | no-serde-on-blob bypassable | T1.2 |
| 4 | Server fails open on config error | T1.7 |
| 4 | Tamper hook in production binary | T1.8 |
| 4 | Relay-only line from policy not observation | T3.3 |
| 4 | lint-server-no-core grep too narrow | T1.6 |
| 4 | Salted-hash LogId missing before observability | T1.10 |
| 4 | Rate-limiter unbounded growth | T1.9 |
| 4 | Clippy non-blocking | T1.3 |
| 5 Future risks | Deniability vs envelope-signature contradiction | T0.6 |
| 5 | External crypto review load-bearing | T5.1 |
| 5 | Feature 10 stacking on unproven invariants | Phase 3 (all) |
| 5 | Interop debt compounds silently | T2.1–T2.4, T2.7 |
| 5 | Verified-contact key-change (goal 2, deferred to F08) | out of scope — tracked at Feature 08 |

## Part D — ADR-bound / security-sensitive tasks (require pre-build review)

Tasks tagged **[ADR]** get **architect** sign-off before build; **[SEC]** tasks get **security-reviewer**
sign-off. Both-tagged tasks get both.

- **architect + security-reviewer:** T0.1, T0.6, T2.1, T2.2, T2.3, T2.6, T3.2, T3.3, T3.6, T4.4.
- **architect only:** T1.4, T1.6, T3.1, T3.4, T3.5*, T3.7, T3.8. (*T3.5 also SEC.)
- **security-reviewer only:** T0.3, T1.1, T1.2, T1.7, T1.8, T1.10, T2.4, T2.5, T4.1, T4.3, T5.1.

The [`/next-task`](../../.claude/commands/next-task.md) command reads these tags and routes the planning
and final-review steps to the named subagents automatically.
