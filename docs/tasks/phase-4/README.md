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

## Envelope-v2 re-deferred — the concrete trigger
`/plan-phase` (with an **architect** call) resolved the obligation from this README's Dependency-check
section: full envelope-v2 (ADR 0016 C1–C7, new AAD, `v: 2` field, hard flag day, new conformance
vectors) is **not** scheduled in Phase 4. Nothing in ADR 0016 requires it — the ADR gates only Feature
07 (mailbox), and T07 is already excluded from this phase for that exact reason. Bundling all of C1–C7
alongside T08+T17 would repeat, at much larger scale, the "one coherent, reviewable unit" problem Phase
2's README used to keep T09 out of Phase 2 alongside T06.

**What does land in Phase 4:** a narrow, v1-scoped, non-wire-breaking fix inside task
[4.9](./4.9-desync-guarded-rehandshake.md) — `open_bytes`'s stale-session short-circuit, which
architect confirmed would otherwise make T08's own desync-recovery deliverable not actually work (a
legitimate re-initiation from a peer with a *stale* session, not merely *no* session, is currently
swallowed forever). This fix does **not** discharge ADR 0016 C7 — envelope v2 will still rewrite the
same function under the new AAD/commit-on-decrypt rules and must re-verify this behavior then.

**The trigger, made mechanical instead of prose (so it can't evaporate a third time):**
1. [`docs/architecture/roadmap.md`](../../architecture/roadmap.md)'s dependency table now lists T07's
   deps as `03, 06, envelope-v2` — the same table `task-picker` mechanically reads every
   `/pick-next-phase` run, so a future run cannot read T07 as pickable without also seeing the new
   dependency.
2. Envelope-v2 is committed here as the **named next build-phase target**: after Phase 5 (this phase's
   review sweep), the build phase immediately following is envelope-v2's own phase — scope pre-written
   as ADR 0016's C1–C7 + `ratchet-v2.json`/`envelope-v2.json` vectors + the flag-day cutover, sized
   comparably to Phase 2 (T06), so a future `/plan-phase` cannot under-scope it either.
3. `docs/tasks/README.md`'s Live carry-forwards restates this as a rule: T07 (and T14, transitively) are
   not pickable until an envelope-v2 task/phase exists in the tracker with status done.

## Tasks (todo)
<!-- Status marks: [ ] pending [~] in progress [x] done [!] blocked -->

**ADR track — block all T17 code, not T08** (4.1, 4.2 can run together)
- [x] **4.1** ADR 0020 — TUI packaging — [file](./4.1-adr-tui-packaging.md)
- [x] **4.2** ADR 0021 — client-local store & config formats — [file](./4.2-adr-client-store-config-formats.md)

**T08 track — starts immediately, independent of the ADRs** (the phase's longest critical-path chain)
- [x] **4.3** Trust module + contact store core — [file](./4.3-trust-module-contact-store.md)
- [x] **4.4** Key-change handling: block/warn semantics — [file](./4.4-key-change-block-warn-gate.md)
- [x] **4.5** Safety-number compare UX primitives + `meridian verify` — [file](./4.5-safety-number-verify-cli.md)
- [x] **4.6** Petname assignment + contact management CLI — [file](./4.6-petname-contact-management-cli.md)
- [x] **4.7** Message-request UX finalization (from T06) — [file](./4.7-message-request-finalization.md)
- [x] **4.8** Org directory-attestation ingest — [file](./4.8-directory-attestation-ingest.md)
- [x] **4.9** Desync detection → guarded fresh-X3DH re-handshake (1.18 follow-through; includes the
  `open_bytes` short-circuit fix) — [file](./4.9-desync-guarded-rehandshake.md)
- [x] **4.10** `meridian-mitm-sim` trust-state matrix — [file](./4.10-mitm-sim-trust-matrix.md)

**T17 infra — no dependency on T08; starts alongside it once 4.1 lands** (4.13 has zero dependencies —
start it day 1)
- [x] **4.11** `apps/tui` crate skeleton + terminal guard — [file](./4.11-tui-crate-skeleton-terminal-guard.md)
- [x] **4.12** `meridian tui` subcommand + environment gate — [file](./4.12-tui-subcommand-env-gate.md)
- [x] **4.13** Extract shared account/home-layout helpers into `meridian-core` — [file](./4.13-extract-account-home-layout-core.md)
- [x] **4.14** `meridian-tui::config` — [file](./4.14-tui-config.md)
- [x] **4.15** `meridian-tui::store` — [file](./4.15-tui-store.md)
- [x] **4.16** Onboarding screen — [file](./4.16-onboarding-screen.md)
- [x] **4.17** Unlock screen — [file](./4.17-unlock-screen.md)
- [x] **4.18** Extension registry (`meridian-tui::surface`) — [file](./4.18-extension-registry.md)

**T17 screens — the rendezvous point; 4.19 is the first task needing both tracks**
- [x] **4.19** Contact list + add-contact + contact detail — [file](./4.19-contact-list-detail-screens.md)
- [x] **4.20** Chat / conversation screen — [file](./4.20-chat-screen.md)
- [x] **4.21** Message-request queue screen — [file](./4.21-message-request-queue-screen.md)
- [x] **4.22** Verification screen — [file](./4.22-verification-screen.md)
- [x] **4.23** Key-change adversarial test — [file](./4.23-key-change-adversarial-test.md)
- [x] **4.24** Settings screen — [file](./4.24-settings-screen.md)
- [ ] **4.25** Help overlay + command palette + diagnostics — [file](./4.25-help-palette-diagnostics.md)
- [ ] **4.26** Terminal-constraint degradation — [file](./4.26-terminal-constraint-degradation.md)
- [ ] **4.27** At-rest audit harness — [file](./4.27-at-rest-audit-harness.md)

**Phase exit gate**
- [ ] **4.28** Docs sync + phase acceptance-demo wiring — [file](./4.28-docs-sync-acceptance-demo.md)

### Dependency order
```
4.1 ─┬─► 4.11 ─┬─► 4.12
     │         └─► 4.18
4.2 ─┘
4.13 (no deps — start day 1) ──► 4.14, 4.15, 4.17, 4.19

4.3 ─┬─► 4.4 ──► 4.9 ──► 4.10
     ├─► 4.5 ───────────►┤
     ├─► 4.6 ──► 4.7 ────┤
     └─► 4.8 (needs 4.3, 4.6)

4.14 ──► 4.16 ──┐
4.15 ──┬─► 4.17 ┤
       └────────┴─► 4.19 ──► 4.20 ──► 4.21
(4.3,4.6) ──────────┘          │        ▲
(4.4) ──────────────────────────┘        │
(4.7) ─────────────────────────────────┘
(4.4,4.5) ──────────────────────────────────────► 4.22 ──► 4.23
4.14 ──► 4.24
4.18,4.19,4.20 ──► 4.25
4.20 ──► 4.26
4.15,4.16,4.19,4.20,4.22 ──► 4.27
everything ──► 4.28
```
**Parallel tracks.** Track ADR (4.1, 4.2) — no code. Track T08 (4.3→4.10) — the phase's longest
sequential chain, zero dependency on the ADRs or on any T17 task. Track T17-infra (4.13 independent;
4.11/4.12/4.18 need only 4.1) — runs alongside Track T08. Once 4.1+4.2 land, 4.14/4.15/4.16/4.17 proceed
in parallel with T08's later tasks (they touch disjoint files: `apps/tui` vs. `apps/core/src/trust.rs` +
`harnesses/`). **4.19 is the hard merge point** — the first T17 task needing T08's `trust.rs` (4.3) and
petname API (4.6); everything downstream in T17 (4.20–4.27) serializes behind both tracks converging
there. 4.24 and 4.13 are the most freely schedulable — use them to fill slack.

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
