<!-- Written by /start-review-phase to docs/tasks/phase-1/review-report.md.
     /plan-review-phase reads this and turns each actionable finding into a numbered fix-task. -->
> **Nav:** [tracker](../README.md) · [phase](./README.md) · [Definition of Done](../../../CONTRIBUTING.md)

# Phase 1 — Review Report

**Reviews:** Phase 0 (Features 1–5, T01–T05) · **Date:** 2026-07-16 · **Reviewers:** code-reviewer, security-reviewer, architect, test-engineer

## Summary

The ADR 0011 → in-house ratchet swap is **cryptographically sound but procedurally unsafe as recorded**. The
in-house Double Ratchet and X3DH in `meridian-crypto` were verified line-by-line against the frozen wire spec
and Signal's published construction — DH ordering, KDF labels, header encryption, skipped-key bounds, replay
rejection, verify-before-decrypt, and forward-secrecy/post-compromise-security properties are all correct and
genuinely tested. However, nearly every guardrail the superseding ADR note claims protects this swap does not
actually exist: there are no X3DH/ratchet conformance vectors, the cargo-deny license gate is an echo `TODO`,
the promised standalone superseding ADR was never written, and ten documents — including three that steer
future Claude Code sessions — still say the ratchet is vodozemac.

Features 1–3 are in a sound state. Features 4 and 5 are **not complete as specified**: no webrtc-rs backend
exists anywhere in the workspace (the `webrtc` cargo feature is an empty flag), so all P2P, NAT-traversal, and
relay-only IP-hiding behavior is proven only against an in-process simulated transport, and that divergence
from the specs is recorded nowhere. Separately, the server-side code itself violates none of the "must never"
invariants — but the CI enforcement layer meant to keep it that way is largely decorative (two of three lints
are vacuous or bypassable, one harness gate is a no-op stub, clippy is non-blocking).

**Does this block Phase 2 (T06 Cross-Org Federation)?** Not the crypto substance, but the doc-truth and
guardrail gaps must close first — stale `.claude/` guidance will actively misdirect any session (including
federation work) that touches crypto or transport, and Feature 4/5's simulation-only status means federation
work would stack a new feature on top of unproven wire-level invariants. See Verdict.

## Findings

Severity: **blocking** (must fix before next build) · **should-fix** (fix this review phase) · **nit** (optional).

| # | Severity | Area / file | Finding | Recommended fix | → Fix-task |
|---|----------|-------------|---------|-----------------|-----------|
| F1 | blocking | `docs/adr/0011-ratchet-library.md:78`; `test-vectors/`; `.github/workflows/ci.yml:51` | No conformance vectors exist for X3DH, the ratchet, or the envelope. The ADR's superseding note claims the integration "carries its own test vectors" — false. `test-vectors/` has only identity vectors plus an empty `safety-numbers-v1.json`; the CI conformance step is a `TODO` comment. Existing tests only prove self-consistency; a spec-divergent KDF label would pass today and surface as a silent interop break when Features 11/12 (browser/mobile) implement the same spec. | Generate known-answer vectors (X3DH intermediates, fixed ratchet transcript, safety numbers) via `xtask -- vectors`, commit them, wire a CI runner. | — |
| F2 | blocking | `docs/adr/0011-ratchet-library.md:6,52`; `docs/adr/README.md:20` | ADR supersede procedure not followed. No numbered superseding ADR exists ("0011a" isn't house numbering — next is 0015); ADR 0011's status line still reads plain "Accepted" with the reversal buried at line 52; the ADR index still says "vodozemac + hand-wired X3DH (Accepted)" and lists the decisive spike as still pending. This is exactly the state CONTRIBUTING DoD item 5 forbids. | Write `docs/adr/0015-ratchet-composition.md`; correct 0011's header and the index. | — |
| F3 | blocking | `.claude/skills/crypto-protocols/SKILL.md:13`; `.claude/agents/architect.md:23-25`; `CLAUDE.md:18`; `docs/architecture/stack.md:20,132,153,179`; `docs/glossary.md:14`; `docs/INDEX.md:87-88,106`; `docs/handoff-readiness.md:71`; `LICENSE:23` | Ten documents still teach the old (vodozemac) decision. Worst are the three that steer future sessions: the crypto-protocols skill states "Ratchet = vodozemac" as an absolute rule, the architect agent's instructions claim ADR 0011 is still unresolved, and root `CLAUDE.md:18` says "via vodozemac". | One `/doc-sync` pass over this list, `.claude/` files first. | — |
| F4 | should-fix | `docs/adr/0011-ratchet-library.md`; `.claude/skills/crypto-protocols/SKILL.md`; `docs/architecture/stack.md`; no `deny.toml`; `.github/workflows/ci.yml:62-69` | The cargo-deny AGPL gate claimed by the ADR, the skill, and stack.md does not exist. No `deny.toml` anywhere; the CI supply-chain job is `echo "TODO cargo-deny check"`. The license decision — the entire reason for the library choice — has no enforcement. | Add `deny.toml` with the AGPL/license-incompatibility rules the ADR describes; wire a real `cargo deny check` CI job. | — |
| F5 | should-fix | `apps/crypto/src/x3dh.rs:94-102,132-140` | The concatenated X3DH master secret is assembled into a plain `Vec<u8>` that is dropped without zeroization, negating the per-leg `Zeroizing` wrappers upstream. | Wrap the concatenation buffer in `Zeroizing<Vec<u8>>` (or equivalent) before deriving the root key. | — |
| F6 | should-fix | `apps/crypto/src/ratchet.rs:70-84` | The four header-encryption keys are omitted from `DoubleRatchet`'s `Drop` zeroization. | Add the header-encryption keys to the `Drop` impl's zeroize set. | — |
| F7 | should-fix | `apps/crypto/src/at_rest.rs:19-24`; `apps/store/src/lib.rs:70-83` | The at-rest session-store key silently depends on Ed25519 signature determinism: the store key is derived from a signature over a fixed label, but the `SecretStore` trait guarantees no determinism. A future HSM/enclave store with randomized signatures would make all persisted ratchet state permanently undecryptable. Currently flagged only as a `TODO: confirm` in the docs. | Add a dedicated key-derivation operation on `SecretStore` that doesn't depend on signature determinism; document it as a hard recoverability dependency until fixed. | — |
| F8 | should-fix | `harnesses/opacity-audit/run.sh` | The opacity-audit harness script is still the day-one exit-0 stub, even though its own contract says it "MUST be replaced" when the guarded feature ships. The real audit exists and runs (`apps/cli/src/opacity.rs:121-251`) but only via `cargo test`, so the named CI gate can never fail. | Re-point `harnesses/opacity-audit/run.sh` at the real `cargo test` invocation covering `apps/cli/src/opacity.rs`. | — |
| F9 | should-fix | `docs/architecture/features/03-e2ee-messaging-relayed.md:12` | T03 spec was never reconciled with the ratchet-composition decision: it still requires an "audited lib … no hand-rolled ratchet," and its risk note requiring wasm32/aarch64 validation "this task" was met only by an isolated primitive probe — no wasm target is built anywhere in CI. | Update T03 spec to reflect the composed-ratchet decision (link ADR 0015); either build the wasm32 validation into CI or record the deferral explicitly. | — |
| F10 | blocking | `apps/transport/Cargo.toml:23`; `apps/core/src/session.rs:291`; `apps/core/tests/p2p_session.rs:248-264` | Feature 4 (P2P substrate) is complete only in simulation. The spec requires "Transport trait + first impl (webrtc-rs…)"; the only implementation is `LoopbackTransport`, and `webrtc = []` is an empty feature with no dependency and no gated code. The substrate logic itself (fingerprint binding fail-closed, ctrl channel, stream registry, capability rejection, ICE restart) is real and well-tested against loopback, but: the headline demo ("kill the server, chat continues") runs only in-process; session info hardcodes `transport: "webrtc-datachannel"` — an overclaim in user-visible output; and `malicious_relay_cannot_touch_inner_sdp` promises an active relay-rewrite attack but its body admits it "just confirms a healthy connect". | Implement the webrtc-rs backend behind the existing `Transport` trait; fix the hardcoded transport label; strengthen or rename the weakened SDP test to match what it actually proves. | — |
| F11 | blocking | `apps/transport/src/types.rs:93`; `tools/netns-nat-matrix.sh:71-78`; `infra/coturn/turnserver.conf:50`; `apps/rendezvous/tests/rendezvous.rs:165` | Feature 5 (NAT/relay policy): logic complete, wire-level acceptance not demonstrable (same root cause as F10). Credential minting, the three-level policy, strip-before-gather, and `meridian doctor` are implemented and tested, but all four NAT "cells" connect only inside an in-process enum simulation; coturn is configured but never exercised by anything; the spec's packet-capture criteria are blocked on the missing backend. Also an overclaim: with `use-auth-secret`/`user-quota` commented out, a captured credential admits unlimited allocations until expiry — the existing test only proves grants are distinct, not that reuse is rejected. | Enable coturn `user-quota`; reword the "single-session, reuse rejected" claim to match actual behavior until enforced; run the netns/tcpdump acceptance matrix once F10's backend lands. | — |
| F12 | should-fix | `apps/rendezvous/tests/rendezvous.rs:338-342` | Feature 2's "5k concurrent connections" acceptance criterion is covered only by a 250-connection smoke test whose comment references an `--ignored` capacity test that does not exist. | Write the referenced 5k-connection `--ignored` capacity test, or amend the spec to the demonstrated number. | — |
| F13 | should-fix | `apps/core/src/chat.rs:36-41`; `docs/api/messaging-envelope-v1.md` | Feature 3's spec'd "desync → fresh-X3DH recovery" behavior could not be confirmed. Fail-closed error paths exist and the envelope spec describes recovery as the losing peer re-initiating, but no code automatically re-initiates X3DH after a desync, and nothing tests that flow. | Confirm intended behavior (see "On-the-fly decisions" below); implement and test if auto-recovery is intended, or document manual recovery as the spec'd behavior. | — |
| F14 | should-fix | `apps/rendezvous/src/metrics.rs:4`; `apps/rendezvous/tests/rendezvous.rs:293`; `tools/metrics-allowlist.txt` | Metrics-allowlist lint is vacuous. It parses macro forms, but `metrics.rs` renders Prometheus text by hand — explicitly so the lint has nothing to flag — and the compensating test only asserts allowlisted names are present, never that others are absent. A contact-graph metric would pass CI today. | Assert every metric family in the rendered `/metrics` body is present in `tools/metrics-allowlist.txt` (exhaustiveness, not just presence). | — |
| F15 | should-fix | `tools/lint-no-serde-on-blob.sh:8,12` | `no-serde-on-blob` lint wouldn't catch its target violation. It matches only a literal `payload:` field and turbofish deserialization; the server's actual decode style (type-inferred `frame.decode()`) and a hypothetical envelope decode match neither pattern. | Deny envelope-content type names from being imported into `apps/rendezvous/src`, or move content types into a module the server crate cannot import. | — |
| F16 | should-fix | `apps/rendezvous/src/main.rs:32-38` | Server fails open on config errors. A typo'd `--config` path warns and boots with defaults — invite-only silently becomes open registration — violating threat-model goal 6 ("never silently weaker"). | Exit non-zero when a requested config path is supplied but fails to parse. | — |
| F17 | should-fix | `apps/rendezvous/src/ws.rs:230-235` | The bundle-tamper test hook ships in the production binary behind a runtime TOML flag. | Gate the hook behind a cargo feature excluded from release builds. | — |
| F18 | should-fix | `.github/workflows/ci.yml`; `Justfile` | Clippy runs with `\|\| true` in both CI and the Justfile, making it non-blocking. It happens to be clean today, so flipping it to blocking is free. | Remove `\|\| true`; make `cargo clippy -D warnings` a blocking CI gate. | — |
| F19 | should-fix | `docs/architecture/roadmap.md:30-43`; ADR 0013 (tail) | `roadmap.md`'s "Phasing" section is corrupted with spliced-in ADR text (correct content survives at `docs/architecture/system-design.md:317-325`); a smaller artifact of the same botched extraction sits at the end of ADR 0013. The docs CI job checks only links and mermaid, so this class of corruption is invisible to it. | Restore the "Phasing" section from `system-design.md:317-325`; clean up the ADR 0013 tail artifact. | — |
| F20 | nit | `apps/rendezvous/src/session.rs:296-299` | Relay-only privacy line is derived from policy, not observation. Not a defect today (no real backend exists yet), but flagged so it isn't forgotten. | When a real transport backend lands (F10), classify actual gathered candidates and abort the dial if a host/srflx candidate appears under relay-only. | — |
| F21 | nit | `tools/lint-server-no-core.sh`; `apps/rendezvous/src/ratelimit.rs:35`; server logging | Smaller hardening items: the `lint-server-no-core` grep should become a `cargo tree` check covering identity/store/crypto and transitive routes; add a salted-hash `LogId` helper plus a tracing lint before observability lands (invariant #4 currently holds only because the server logs nothing); evict expired rate-limiter entries (unbounded growth keyed by attacker-controlled IPs). | Bundle as one hardening task; not urgent individually. | — |
| F22 | nit | Feature 1 acceptance criteria | "≥90% branch coverage" claim is unverifiable — no coverage tooling exists in the project. All other Feature 1 acceptance criteria are verified by real tests (10⁶ fuzzed round-trips, flipped-bit rejection, same-principal semantics, plaintext-never-on-disk, live identity conformance vectors). | Add a coverage tool (e.g. `cargo llvm-cov`) if the criterion is to remain measurable, or drop the specific percentage from the spec. | — |

## On-the-fly decisions to ratify

- **Ratchet composition itself.** During Feature 3, a spike found vodozemac 0.10 cannot be seeded from an
  externally computed X3DH root key, cannot use the frozen v:1 prekey bundle, and exposes neither header
  encryption nor raw message keys. The ratchet was composed in `meridian-crypto` from the same audited
  RustCrypto primitives ADR 0011 already allocated to X3DH; the AGPL-avoidance rationale that rejected
  libsignal is unchanged. This decision is sound but was never formally recorded — see F1–F3. **→ needs
  `docs/adr/0015-ratchet-composition.md`.**
- **Deniability vs. envelope signature — needs an explicit decision.** The envelope signs every message
  ciphertext with the identity key (`Sign_IK{ratchet_ct}`, `docs/api/messaging-envelope-v1.md:96`), while
  threat-model goal 4 claims deniability because "identity-key signatures are confined to key distribution and
  signaling" (`docs/security/threat-model.md:34`). A signed ciphertext is third-party-provable authorship —
  this contradicts the deniability claim. Either the threat model's claim needs narrowing, or envelope v2
  should drop the signature (the ratchet AEAD already binds both identity keys). The contradiction is inside
  the design docs themselves, so it needs an ADR, not code. **→ needs an ADR.**
- **Desync → fresh-X3DH auto-recovery — confirm or implement (see F13).** Spec implies automatic re-initiation
  by the losing peer; no such code path exists or is tested. Needs a decision on whether auto-recovery is
  in-scope for Phase 1 or deferred.
- **Scoped, not a defect — for awareness only.** The "verified contact → key substitution fails closed" half
  of threat-model goal 2 is deliberately deferred to Feature 8 (`apps/core/src/session.rs:571-573`); today's
  bundle check protects fetch-by-known-key only. No action needed now, but don't mistake this for an oversight
  later.

## Coverage / test gaps

- **No conformance vectors** for X3DH, the Double Ratchet, the envelope, or safety numbers (F1) — the single
  highest-leverage test gap; blocks meaningful interop verification once Features 11/12 exist.
- **No wasm32 build validation in CI** (F9) — T03's risk note explicitly required this "this task, not later";
  `apps/web` scripts are currently echo stubs.
- **No 5k-connection capacity test** for Feature 2 (F12) — only a 250-connection smoke test exists; the spec's
  own acceptance number is untested.
- **No branch-coverage tooling** anywhere in the project (F22) — the "≥90%" claim in Feature 1's acceptance
  criteria is currently unmeasurable.
- **opacity-audit harness gate is a stub** (F8) — the real test exists but the CI-visible gate cannot fail.
- **Wire-level P2P/NAT acceptance is entirely unproven** (F10, F11) — everything currently passes only against
  `LoopbackTransport` / an in-process NAT-cell simulation; no packet has ever actually traversed a real
  webrtc-rs connection or coturn relay in this codebase.
- **Clippy is not a blocking gate** (F18) — currently clean, so free to flip, but a regression would not be
  caught until manually checked.

## Verdict

**Blocked until F1, F2, F3, F10, F11 resolved** before Feature 10 (media) or Phase 2 (T06 federation) stacks
further work on top of these gaps. Rationale, in priority order:

1. **Doc/ADR truth restoration (hours).** Write ADR 0015, fix 0011's header and the ADR index, run doc-sync
   over the ten stale files — `.claude/` files first, since they actively steer future Claude Code sessions.
   Repair the roadmap splice (F19). Reconcile T03/T04/T05 specs with an explicit "wire-level verification
   deferred pending webrtc backend" note so the divergence is recorded instead of silent.
2. **Freeze the crypto (days).** Generate and commit X3DH/ratchet/envelope/safety-number known-answer vectors
   and wire them into CI (F1); fix the two zeroization gaps (F5, F6); resolve or document the signature-
   determinism dependency of the session store (F7).
3. **Make the gates real (days).** Metrics exhaustiveness test (F14), hardened no-serde-on-blob lint (F15),
   `clippy -D warnings` (F18), `deny.toml` + real cargo-deny job (F4), opacity harness re-pointing (F8),
   fail-closed config (F16), feature-gate the tamper hook (F17).
4. **Close Features 4/5 honestly (weeks).** Implement the webrtc-rs backend behind the existing `Transport`
   trait (F10), run the netns/tcpdump acceptance matrix, enable coturn `user-quota` and reword the
   single-session claim (F11), derive the relay-only UX line from observed candidates (F20) — all before
   Feature 10 (media) stacks on it, per Feature 4's own risk note.
5. **Schedule the design decisions:** the deniability-vs-envelope-signature contradiction (ADR), the desync
   auto-recovery flow (confirm or implement), and the external crypto-review engagement — the Phase-1 external
   crypto review (`docs/testing/strategy.md` §7) is now load-bearing, not a formality, since the ratchet is
   hand-composed rather than an audited protocol implementation. The vectors from step 2 are its precondition.

Everything else (F12, F13, F21, F22) is should-fix/nit and can land within this review phase without blocking
the next build phase's start, provided items 1–4 above land first.
