<!-- Created by /pick-next-phase. The todo list below is filled by /plan-phase. -->
> **Nav:** [tracker](../README.md) · [roadmap](../../architecture/roadmap.md) · [features](../../architecture/features/)

# Phase 4 — Verification & Trust + Terminal TUI Client

**Kind:** build · **Status:** planning · **Reviews phase(s):** n/a (build phase; Phase 5 will review it)

## Goal
Ship **Feature 08 — Verification & Contact Trust** and **Feature 17 — Terminal TUI Client** together,
as one coherent phase: T08 lands the core trust module (safety-number compare UX, TOFU→pinned→verified
contact states, un-softenable key-change blocking, the `meridian-mitm-sim` adversarial harness) that
"lands in core, consumed by every client"; T17 lands the first interactive human-facing client
(`meridian tui`) and is the reference consumer of that trust module — completing the system's core
security promise (a fully malicious rendezvous cannot MITM a verified contact) *and* giving a human a
way to actually use and verify it, in the same phase.

**Acceptance demos** (from the feature specs):
- T08: [`docs/architecture/features/08-verification-trust.md`](../../architecture/features/08-verification-trust.md)
  — `meridian-mitm-sim --attack substitute-key --against verified` aborts 0-leak on all attacks; against
  `tofu`, a loud key-change warning blocks sending; safety numbers are order-independent and
  byte-identical to new conformance vectors.
- T17: [`docs/architecture/features/17-terminal-tui-client.md`](../../architecture/features/17-terminal-tui-client.md)
  — a user with no prior state reaches a delivered, verified message using only on-screen affordances
  in `meridian tui`; restart restores contacts/history/ratchet state with no re-handshake; key change on
  a verified contact hard-blocks the composer; the at-rest audit finds no plaintext in any file the TUI
  writes.

## Chosen feature(s) / scope
- **T08 — Verification & Contact Trust** — [spec](../../architecture/features/08-verification-trust.md)
  · depends on T03 — **done ✔**
- **T17 — Terminal TUI Client** — [spec](../../architecture/features/17-terminal-tui-client.md) ·
  depends on T01–T05 (T06 also done, so cross-org IDs work) — **all done ✔**

**In scope (T08):** safety-number compare UX (computation already lands in core from T03,
`apps/crypto/src/fingerprint.rs`); contact store states `new → pinned (TOFU) → verified`; key-change
handling (verified ⇒ block sends until re-verified; pinned ⇒ prominent warn, org-configurable to
block); petname assignment; message-request UX finalization (from T06); org directory-attestation
ingest; receiver-side desync detection → guarded fresh-X3DH re-handshake (deferred here from T03 by
task 1.18, gated on the key-change handling above per that task's reasoning); the
`meridian-mitm-sim` harness; `docs/security/verification-ux.md` already exists as the canonical
wording doc — T08 is what makes clients actually enforce it.

**In scope (T17):** onboarding (keypair → OS keystore/passphrase file → `mrd1:` ID + QR → rendezvous
registration), unlock, contact list (add by `mrd1:` ID / QR import, petnames, filter), chat (scrollback,
composer, delivery state, restart-persistent history), message-request queue, verification screens
(safety number + QR, mark-verified, block — **consuming T08's trust module, not a shadow
implementation**), sealed local JSON store (`at_rest::seal`), `config.toml` via figment, help
overlay/command palette/diagnostics, and the extension registry every later feature's TUI surface
plugs into (Definition of Done gate 9).

**Out of scope (per both specs):** any new protocol/wire type/crypto in the TUI (a defect in the plan
if needed); group chat, calls/media, file transfer, multi-device, offline delivery UI (T07 not yet
built — outbox stays a *local* retry queue, copy must not imply store-and-forward); contact-token
issuance/enforcement at the federation edge (→ T14); web-of-trust.

## Resolving the T17/T08 overlap
T17's spec lists "Verification" as unconditional in-scope (safety number + QR, mark-verified, block,
"un-softenable key-change handling from `verification-ux.md`") with no fallback language — unlike its
explicit deferral treatment of T07 ("until then the outbox is a local retry queue and the UI must say
so"). That asymmetry is the tell: T17 was written assuming T08's core trust module already exists.
Picking T17 alone would force either stubbing a scope item T17 calls mandatory, or building a shadow
trust-state machine directly in `meridian-tui::store` — which would both violate T17's own "no
protocol logic in the TUI" boundary and create a second, divergent key-change-block implementation for
a security-critical control (exactly the class of defect `security-reviewer` treats as blocking).

**Resolution:** both features land in this phase, with T08's core trust module and `meridian-mitm-sim`
harness sequenced ahead of T17's verification screens (`/plan-phase` must order the task DAG
accordingly). T17's local store then holds trust state only as a UI-facing attribute per contact
(petname/filter/display); all actual state transitions, TOFU pinning, and key-change block enforcement
call into T08's real core module.

## Dependency check
Phase 3 (review of Phase 2) is fully closed — all 23 tasks `[x]`, no open ADR obligations, tree green.
Phases 0–2 done. With 01–06 all done, the roadmap's dependency table makes {07, 08, 17} look pickable,
but:

- **T07 is excluded.** Its deps column (`03, 06`) doesn't capture a real, ADR-level blocker: [ADR
  0016](../../adr/0016-envelope-deniability.md) states *"Schedule \[envelope v2] in the next build
  phase and **gate Feature 07 (mailbox) on it** — shipping the mailbox first is what makes the
  \[mailbox-holds-signed-ciphertext] exposure durable."* Envelope v2 has not been implemented (no
  `mrd.env/2` / `EnvelopeV2` / `envelope_v2` anywhere in `apps/`), and the Phase-3 carry-forward note
  ties its scheduling trigger to "when Feature 08/09 is planned" — which is now. T07 stays deferred
  until envelope v2 lands.
- **T08 and T17 are both genuinely unblocked** (T08 deps on T03 done; T17 deps on T01–T05 done, T06
  also done) and, per the overlap analysis above, belong together rather than in separate phases —
  running T17 without T08 would force a shadow trust implementation; running T08 without T17 leaves
  the core module with no interactive client to prove it end-to-end (the CLI's scriptable surface
  doesn't exercise the UX the security guarantee depends on: unskippable warnings, blocked composers).
- Track A (`01→03→08→13`) and Track D (`17→11→12→15`) both point here next; the roadmap explicitly
  calls Track D "able to run in parallel with any other track," which is consistent with bundling
  17 alongside 08 rather than waiting.

**Envelope-v2 obligation — must not evaporate a second time.** The Phase-3 carry-forward note says
"When Feature 08/09 is planned, this must appear in the envelope-v2 task's obligations." That trigger
has now fired. `/plan-phase` must either (a) schedule the envelope-v2 build task inside this phase —
a natural fit alongside T08, since both touch ratchet/session-establishment internals (T08's
desync→fresh-X3DH re-handshake work and ADR 0016's C2/C7 commit-on-decrypt/desync-short-circuit
obligations overlap), or (b) explicitly re-defer it with a new, concrete trigger recorded here and in
the tracker. Silently dropping it a second time is not an option.

## ADR obligations — must open before any code
Per T17's spec, `/plan-phase` must schedule these first, same shape as Phase 2's 2.1:
1. **ADR 0020 — TUI packaging.** Recorded intent: new `apps/tui` crate (`meridian-tui`), launched by
   `meridian tui` in `meridian-cli` behind a default-on `tui` feature. Alternatives to weigh: standalone
   `meridian-tui` binary, or folding directly into `meridian-cli`.
2. **ADR 0021 — client-local store & config formats.** Recorded intent: sealed JSON via
   `at_rest::seal` under the `SessionStoreKey/v1`-derived key; TOML config; explicit `--export-json`
   rather than a persistent-plaintext opt-out (rejected alternative `store.encrypt = false` must be
   recorded as rejected, with reasoning).

T08 has no "Decisions to ratify" section and no ADR obligations of its own.

## Reading list for `/plan-phase`
- **ADRs (binding):** [0016 envelope deniability](../../adr/0016-envelope-deniability.md) (T07 gate +
  the envelope-v2 obligation above) · [0011](../../adr/0011-ratchet-library.md) /
  [0015](../../adr/0015-ratchet-composition.md) (ratchet composition T08's desync recovery touches) ·
  0020/0021 (to be written this phase).
- **Design / security:** [verification-ux.md](../../security/verification-ux.md) (canonical warning
  wording, already written) · [tui-client.md](../../architecture/tui-client.md) (full T17 design incl.
  ADR 0020/0021 schemas + [extension contract](../../architecture/tui-client.md#8-extension-contract--every-feature-ships-a-tui-surface))
  · [data-model.md §2](../../architecture/data-model.md#2-client-local-store-encrypted-via-secretstore-key)
  (client-local store) · [threat-model.md](../../security/threat-model.md) §1.2 goals 2 & 6 (why
  verification exists) · task [1.18](../phase-1/1.18-desync-recovery-decision.md) (desync→fresh-X3DH
  decision T08 realizes).
- **Skills:** [crypto-protocols](../../../.claude/skills/crypto-protocols/SKILL.md) (fingerprint
  construction is wire-critical, T08 freezes conformance vectors on top of it) ·
  [task-tracking](../../../.claude/skills/task-tracking/SKILL.md) · Definition of Done gate 9 (every
  future user-visible feature ships its TUI surface via T17's extension registry, starting now).

## Tasks (todo)
<!-- Filled by /plan-phase. Status marks: [ ] pending [~] in progress [x] done [!] blocked -->
- [ ] **4.1** <title> — [file](./4.1-<slug>.md)

## Exit criteria
- All Phase 4 tasks `[x]`, tree green (`just build`, `cargo clippy --workspace --all-targets -D
  warnings` clean), docs synced.
- T08's acceptance demo runs: `meridian-mitm-sim` matrix — 0 silent successes against `verified`, 0
  successes against `pinned` without the exact `verification-ux.md` warning shown.
- T17's acceptance demo runs: onboarding → verified chat → restart-persists → key-change blocks, all
  from `meridian tui` alone, at 80×24, with the at-rest audit and panic-restores-terminal test green.
- The envelope-v2 obligation above is either discharged this phase or re-deferred with a concrete,
  recorded trigger — not silently dropped again.
- Then: `/start-review-phase` for Phase 5.
