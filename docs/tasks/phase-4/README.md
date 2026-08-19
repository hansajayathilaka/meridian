<!-- Created by /pick-next-phase. The todo list below is filled by /plan-phase. -->
> **Nav:** [tracker](../README.md) · [roadmap](../../architecture/roadmap.md) · [features](../../architecture/features/)

# Phase 4 — Verification & Trust + Terminal TUI Client

**Kind:** build · **Status:** in progress — 45/48 tasks done (4.1–4.45); the fourth exit-gate attempt
(4.45) found a fourth genuine defect and `/plan-phase` has now scoped the fourth gap-closure wave to
close it: **4.46** (`Effect::AddContact` never reconciles into the live `MainState::trust`, plus a
second, closely related interleaving gap traced during this planning pass), **4.47** (a doc-only
`--export-json` demo-script fix, split out since it's unrelated in root cause), and **4.48** (the fifth
exit-gate attempt, hard-joined on both). Neither 4.46 nor 4.47 needs a pre-code consult or a new ADR
(recorded in each task file's own text) — both are mechanical fixes with one obvious,
already-precedented shape. Per the task-tracking skill's own §7 ("a build phase isn't done until its
acceptance demo runs"), the phase is **still not closed**: task 4.28 found T17's acceptance demo did not
run end to end; 4.29–4.37 closed that specific gap, but 4.38 — the second exit-gate attempt — found the
demo *still* doesn't pass, for two reasons. Fix tasks 4.39/4.40 closed both of those, genuinely,
confirmed live — but 4.41, the third exit-gate attempt, found a third defect (Defect C). The third
gap-closure wave, 4.42–4.45, fixed Defect C, the 188 s republish defect, and the predicted history-load
gap — but 4.45, the fourth exit-gate attempt, found the fourth defect above (see
[exit criteria](#exit-criteria) for the full writeup) · **Reviews phase(s):** n/a (build phase; Phase 5
will review it, once it's actually closeable)

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
- [x] **4.25** Help overlay + command palette + diagnostics — [file](./4.25-help-palette-diagnostics.md)
- [x] **4.26** Terminal-constraint degradation — [file](./4.26-terminal-constraint-degradation.md)
- [x] **4.27** At-rest audit harness — [file](./4.27-at-rest-audit-harness.md)

**Phase exit gate (first attempt — found the gap below, honestly, rather than papering over it)**
- [x] **4.28** Docs sync + phase acceptance-demo wiring — [file](./4.28-docs-sync-acceptance-demo.md)

**T17 gap closure — added post-4.28.** Per the task-tracking skill's own §7, a build phase isn't done
until its acceptance demo runs; 4.28 found T17's doesn't. These 10 tasks close it: real `run_worker`
effect execution (split into five independently-testable groups by which store files/screens each
touches — 4.30–4.34), a previously-unscoped third gap found during planning (no live inbound-message
receive path at all — 4.35), the missing `Preflight`/`Screen::Main` live navigation (4.36/4.37), the
shared `LiveSession` plumbing all of the above need (4.29), and a second, now-successful acceptance-demo
closure (4.38) mirroring 4.28's own role. Full planning rationale (including the judgment calls on how
the `run_worker` split was chosen, why `LiveSession` is a dedicated task, and why 4.28 itself was never
reopened) lives in each task file's own text plus the architect consult recorded in
[tui-client.md §4](../../architecture/tui-client.md) once folded in by 4.38.
- [x] **4.29** `Effect::LoadSession` + `LiveSession` assembly — [file](./4.29-load-session-live-session.md)
- [x] **4.30** Real `run_worker`: account lifecycle — [file](./4.30-run-worker-account-lifecycle.md)
- [x] **4.31** Real `run_worker`: contacts & contact-detail persistence — [file](./4.31-run-worker-contacts-persistence.md)
- [x] **4.32** Real `run_worker`: trust & request-queue persistence — [file](./4.32-run-worker-trust-request-persistence.md)
- [x] **4.33** Real `run_worker`: outbound chat — [file](./4.33-run-worker-outbound-chat.md)
- [x] **4.34** Real `run_worker`: settings & diagnostics — [file](./4.34-run-worker-settings-diagnostics.md)
- [x] **4.35** Inbound delivery stream — [file](./4.35-inbound-delivery-stream.md)
- [x] **4.36** `Screen::Main` + live navigation — [file](./4.36-screen-main-live-navigation.md)
- [x] **4.37** Preflight routing — [file](./4.37-preflight-routing.md)
- [x] **4.38** T17 acceptance-demo closure (phase re-exit gate) — [file](./4.38-t17-acceptance-demo-closure.md)
  — **done in the sense 4.28 was done**: its own verification/doc-reconciliation scope is fully
  executed and honestly written up; the demo it verified still does **not** pass (see Exit criteria
  below) — 4.39/4.40/4.41 are needed next, not a reopening of this one.

**Second gap-closure wave (planned by `/plan-phase` against 4.38's own findings)** — fixes both defects
4.38 found live, then a third, hopefully-final exit-gate attempt.
- [x] **4.39** Prekey bundle republish + vault persistence on session start (fix for 4.38's Defect A —
  no first-contact message can ever be decrypted, for any account type) — [file](./4.39-prekey-bundle-republish.md)
- [x] **4.40** Thread the live-session secret store through file-backed contacts/trust/send handlers (fix
  for 4.38's Defect B — file-backed accounts fail closed post-`Screen::Main`) — [file](./4.40-file-backed-live-session-store.md)
- [x] **4.41** T17 acceptance-demo closure, third exit-gate attempt (needs both 4.39 and 4.40) — [file](./4.41-t17-acceptance-demo-closure-attempt-3.md)
  — **done in the sense 4.28/4.38 were done**: its own verification-only scope is fully executed and
  independently confirmed; the demo it verified still does **not** pass (Defect C — see Exit criteria
  below) — the third gap-closure wave below is what's needed next, not a reopening of this one.

**Third gap-closure wave (planned by `/plan-phase` against 4.41's findings)** — fixes Defect C, the
still-open 188 s republish defect 4.39 recorded and 4.41 measured, and one defect predicted from source
at plan time, then a fourth exit-gate attempt. Both fix-shape design questions were **decided at plan
time** by an architect consult (recorded in 4.42's and 4.43's own files) — neither needs a further
pre-code consult, and neither needs a new ADR.
- [x] **4.42** Post-accept path to chat/verify with a message-request sender (fix for 4.41's Defect C —
  the phase's blocking defect) — [file](./4.42-post-accept-chat-affordance.md)
- [x] **4.43** File-backed prekey republish performance, 188 s → seconds (fix for the defect 4.39
  recorded and left open, measured live by 4.41; **land first**) — [file](./4.43-file-backed-republish-performance.md)
- [x] **4.44** Load a chat's persisted transcript when the chat screen opens (predicted "Defect D",
  traced in source at plan time — **verify first, then fix**) — [file](./4.44-chat-history-load-on-open.md)
- [x] **4.45** T17 acceptance-demo closure, fourth exit-gate attempt (hard join on 4.42, 4.43, 4.44) — [file](./4.45-t17-acceptance-demo-closure-attempt-4.md)

**Fourth gap-closure wave (planned by `/plan-phase` against 4.45's findings)** — fixes the fourth
defect (`Effect::AddContact` never reconciling into the live `MainState::trust`, plus a second,
closely related interleaving gap traced during this planning pass), the doc-only `--export-json`
mismatch 4.45 also recorded, then a fifth exit-gate attempt. Neither fix task needs a pre-code
consult or a new ADR — unlike the third wave's 4.40/4.42, neither has a genuine design choice to make
(recorded in each task file's own text).
- [ ] **4.46** Reconcile `Effect::AddContact` into the live `MainState::trust` (fix for 4.45's fourth
  defect — the initiator-verify-in-session gap) — [file](./4.46-add-contact-trust-reconciliation.md)
- [ ] **4.47** Fix `--export-json` demo-script/spec wording (directory layout, not a flat file;
  doc-only, pre-existing since task 4.15) — [file](./4.47-export-json-doc-fix.md)
- [ ] **4.48** T17 acceptance-demo closure, fifth exit-gate attempt (hard join on 4.46, 4.47) —
  [file](./4.48-t17-acceptance-demo-closure-attempt-5.md)

**Findings with no task yet — surfaced by 4.42's own review, owned by no open task:**
- **Shape B** (an `OpenChat`-style transition from `Screen::Requests` straight to Chat) was evaluated and
  deliberately severed from 4.42 — the `RequestsAction` enum it needs ripples through ~30 call sites in
  `screens_requests.rs`. A+C alone were independently re-confirmed (by `reviewer`) to satisfy the
  acceptance criterion, so this is a flow-quality follow-up, not a defect.
- **A repair action for `run_accept_request`'s partial-failure window** (`trust.bin` saves, `contacts.json`
  save then fails ⇒ retry writes no row ⇒ peer durably trusted but permanently unreachable through any
  on-screen affordance, since ADR 0001 also forbids a hint-less manual re-add). `apps/tui/src/worker.rs`
  carries the design direction inline (a diagnostics-surfaced action rebuilding only rows missing for an
  existing `trust.bin` contact, explicitly distinct from the delete-tombstone case) but no task exists yet.

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

-- T17 gap closure (added post-4.28) --
4.13,4.15,4.3 ──► 4.29 ─┬─► 4.35 (inbound stream)
                        └─► 4.36 (Screen::Main + nav) ──► 4.37 (Preflight, also needs 4.29)
4.16,4.17 ──► 4.30 (run_worker: account)         ─┐
4.19      ──► 4.31 (run_worker: contacts)         │  4.30-4.34 independent of each other and of
4.21,4.22,4.4 ──► 4.32 (run_worker: trust/reqs)   │  4.29/4.35/4.36/4.37, but share run_worker's
4.20      ──► 4.33 (run_worker: outbound chat)    │  match statement — must land as sequential
4.24,4.25 ──► 4.34 (run_worker: settings/diag)   ─┘  commits (any order among themselves)
4.29–4.37 (all of them) ──► 4.38 (re-exit gate)

-- Second gap-closure wave (added post-4.38, planned via /plan-phase) --
4.29,4.35,4.37 ──► 4.39 (bundle republish — Defect A fix)
4.29,4.31,4.32,4.33,4.35,4.37 ──► 4.40 (file-backed store cache — Defect B fix;
                                          logically independent of 4.39, land after it
                                          to avoid a simultaneous diff on worker.rs's
                                          session-threading machinery)
4.39,4.40 ──► 4.41 (third exit-gate attempt)

-- Third gap-closure wave (added post-4.41, planned via /plan-phase) --
4.39,4.40 ──► 4.43 (file-backed republish perf — 188s; no open design question,
                      land FIRST: it cuts every later live file-backed verification
                      cycle from ~190s/peer to ~3s/peer, which 4.42/4.44/4.45 all pay)
4.32,4.36,4.37,4.40 ──► 4.42 (Defect C — post-accept chat/verify affordance)
4.42 ──► 4.44 (chat-history load; logically independent, land after 4.42 to avoid a
                 simultaneous diff on ChatState construction + App's screen stack)
4.42,4.43,4.44 ──► 4.45 (fourth exit-gate attempt — hard join, no partial credit)

-- Fourth gap-closure wave (added post-4.45, planned via /plan-phase) --
4.19,4.36,4.42 ──► 4.46 (AddContact trust reconciliation — no open design question)
(no deps, doc-only) ──► 4.47 (export-json doc fix — disjoint files from 4.46, land in either order)
4.46,4.47 ──► 4.48 (fifth exit-gate attempt — hard join, no partial credit)
```
**Landing order (fourth wave).** 4.46 and 4.47 touch disjoint files (`apps/tui/src/app.rs` + its tests
vs. `docs/architecture/features/17-terminal-tui-client.md`), so either may land first — no
simultaneous-diff conflict risk like the third wave's shared `worker.rs` had. 4.48 hard-joins both.

**Numbering vs. landing order (third wave).** Files are numbered 4.42–4.45 (4.42 = Defect C, as already
pre-announced by 4.41's Status, this README, and the master tracker), but the recommended *landing* order
is **4.43 → 4.42 → 4.44 → 4.45**, mirroring the 4.39-before-4.40 precedent: 4.43 has no open design
question and pays for itself immediately in every later live verification cycle.
**Parallel tracks.** Track ADR (4.1, 4.2) — no code. Track T08 (4.3→4.10) — the phase's longest
sequential chain, zero dependency on the ADRs or on any T17 task. Track T17-infra (4.13 independent;
4.11/4.12/4.18 need only 4.1) — runs alongside Track T08. Once 4.1+4.2 land, 4.14/4.15/4.16/4.17 proceed
in parallel with T08's later tasks (they touch disjoint files: `apps/tui` vs. `apps/core/src/trust.rs` +
`harnesses/`). **4.19 is the hard merge point** — the first T17 task needing T08's `trust.rs` (4.3) and
petname API (4.6); everything downstream in T17 (4.20–4.27) serializes behind both tracks converging
there. 4.24 and 4.13 are the most freely schedulable — use them to fill slack.

**T17 gap-closure tracks (4.29–4.38).** Wave 1 — fully parallel, each depends only on already-done
Phase 4 tasks: 4.30, 4.31, 4.32, 4.33, 4.34 (the five `run_worker` groups) plus 4.29 (`LiveSession`).
Wave 2 — each needs only 4.29: 4.35 (inbound stream), 4.36 (`Screen::Main`). Wave 3: 4.37 (Preflight,
needs 4.29 + 4.36). Wave 4: 4.38 (needs everything). Scheduling note: **4.30 is the highest-value single
task to land first** even though it has no hard dependency on anything in this set — it is the exact fix
for the specific hang 4.28 reproduced ("Generating your identity…"), so it turns a completely stuck
onboarding into a runnable (if not yet fully navigable) session soonest.

**Second gap-closure wave (4.39–4.41), planned against 4.38's own findings.** 4.39 and 4.40 fix two
genuinely independent defects (different code paths, no shared blocking dependency, confirmed during
planning) — develop in parallel if convenient, but land sequentially since both touch
`apps/tui/src/worker.rs`'s session-threading machinery (`OnboardingSession` or its successor): 4.39 first,
since it's the more fundamental blocker (blocks first-contact receiving for *every* account type, not just
file-backed) and has no open design question, so it can start immediately; 4.40 second, since it carries
a load-bearing architect + security-reviewer consult before any code lands (extending in-memory key
residency for the full session lifetime is a real security-posture question, not a mechanical
thread-through) and should rebase onto 4.39's landed diff rather than the reverse. 4.41 is a hard join on
both — there's no partial-credit path, since either defect alone independently blocks a different point
in the demo script.

## Exit criteria

**Assessed honestly by task 4.28** (the phase's first exit-gate attempt) — see its own file for the full
diff and [tui-client.md §10](../../architecture/tui-client.md#10-current-implementation-status-as-of-task-428)
for the complete writeup of the one criterion below that did **not** hold at that point. Task 4.38 was
meant to be the **second, planned-to-succeed** exit-gate attempt, once 4.29–4.37 closed the gap 4.28
found — **it wasn't**: 4.38 re-ran the demo live and found it still doesn't pass, for two reasons (one
already flagged by 4.37, one newly discovered by 4.38's own live re-run and its new regression test).
See [tui-client.md §11](../../architecture/tui-client.md#11-current-implementation-status-as-of-task-438--the-phases-second-exit-gate-attempt)
and [4.38's own Status section](./4.38-t17-acceptance-demo-closure.md) for the full writeup. `/plan-phase`
was re-invoked against these two specific findings and broke them into
[4.39](./4.39-prekey-bundle-republish.md) (Defect A fix), [4.40](./4.40-file-backed-live-session-store.md)
(Defect B fix), and [4.41](./4.41-t17-acceptance-demo-closure-attempt-3.md) (a third, hopefully-final
exit-gate attempt) — see the [dependency order](#dependency-order) above for how they relate.

- [x] All 28 originally-planned Phase 4 tasks (4.1–4.28) are `[x]` in the tracker (see
  [dependency order](#dependency-order)). **Not sufficient for phase closure** — see the next item.
- [x] Tree green: `cargo fmt --check` clean; `cargo clippy --workspace --all-targets -- -D warnings`
  clean (re-run fresh by 4.28, not assumed from prior tasks' own gates). Docs synced: `bash
  tools/check-docs.sh` clean (2301 relative links checked, 0 broken); the screen-flow diagram
  re-validated syntactically via `mermaid-cli` (not available as a bare `mmdc` in this environment,
  same as every earlier task's own check — fetched on demand via `npx` for this one-time validation
  pass, and reconciled against the real screen stack while at it).
- [x] **T08's acceptance demo runs, confirmed end to end by 4.28**: `bash harnesses/mitm-sim/run.sh`
  exits 0 — 0 silent successes against `verified`, 0 successes against `pinned` without the exact
  `verification-ux.md` warning shown, across every cell including the T08 trust-state matrix (task
  4.10). The literal `meridian-mitm-sim --attack substitute-key --against <state>` invocation in
  [08-verification-trust.md](../../architecture/features/08-verification-trust.md)'s "Working output"
  is illustrative shorthand for this harness (there is no standalone `meridian-mitm-sim` binary with
  those flags — see task [4.10](./4.10-mitm-sim-trust-matrix.md)'s own Status section, which already
  recorded this); the harness itself is what actually ships and actually runs.
- [ ] **T17's acceptance demo still does NOT run end to end — re-confirmed empirically by 4.41, not
  assumed.** 4.29–4.37 genuinely closed 4.28's own hang. 4.39 and 4.40 genuinely closed the two defects
  4.38 found — **both confirmed live by 4.41's own two-peer PTY runs, for both account types**: Defect A
  (no prekey republish) is closed — a responder genuinely receives and correctly decrypts a real
  first-contact message, byte-for-byte, over the real wire. Defect B (file-backed accounts failing
  closed) is closed — a file-backed account's `AddContact` genuinely succeeds post-`Screen::Main`, no
  fail-closed error. **But 4.41's own live re-run reached new ground no prior attempt reached (a real,
  live, two-peer first-contact exchange driven entirely through the interactive UI) and found a third,
  new, independently-confirmed defect: Defect C.** After a responder accepts a message request
  (`Effect::AcceptRequest`), the sender never appears in the Contacts list and there is no live-UI path
  to open a chat with them, verify them, or reply — for either account type, reproduced identically
  twice. Root cause: `worker.rs::run_accept_request` writes `sessions.bin`/`trust.bin` but never
  `contacts.json`; `screens/main.rs::build_contact_entries` joins off `contacts.json` only (a gap its own
  doc comment already flagged as a `TODO: confirm` during task 4.36); `screens/requests.rs`'s accept
  action has no `OpenChat`-style transition; no command-palette entry reaches a non-contact peer either.
  The underlying ratchet session and trust record are confirmed fully functional (`live_session_e2e.rs`
  proves `SendMessage`/`MarkVerified` both succeed against the accepted sender directly through
  `worker::dispatch`) — this is a live-UI-affordance gap only, not a crypto/session defect. Full writeup:
  [4.41's own Status section](./4.41-t17-acceptance-demo-closure-attempt-3.md). **Not fixed by 4.41
  itself** — its own scope was verification only, per this project's "report, don't patch around it" rule.
  This checkbox stays `[ ]` until the third gap-closure wave closes it: **[4.42](./4.42-post-accept-chat-affordance.md)**
  (Defect C — its fix shape was decided at plan time by an architect consult recorded in that file:
  synthesizing a `contacts.json` row on accept is *mandatory*, because `TrustStore::observe` gives the
  sender `hint == ""` and `to_id_string` rejects an empty hint, making the "re-add manually" workaround
  structurally impossible; plus a required in-memory propagation piece neither of 4.41's candidate shapes
  considered; **landed — Defect C closed**: `worker::run_accept_request` now also upserts and saves the
  sender's sealed `contacts.json` row (`id: ""`, `hint: ""`, `conv_handle: None`) on the same
  `accepted || pin_still_owed` retry guard as the pin, with no hint-less `mrd1:` id form invented
  (ADR 0001 held); `AcceptRequestEffect.outcome` widened to `Option<AddedContact>` and
  `App::apply_accepted_request` replays `trust.observe` (worker-supplied timestamp), the contacts-row
  update and an in-memory `chat.accept_request` into the live `Screen::Main`, so the sender is reachable
  for chat/reply/verify immediately *and* after a restart, and an accepted request no longer re-appears
  on the next `^R`. Proven at the screen level by a new `apps/tui/tests/accept_to_chat.rs` — real key
  events through `App` + the real `worker::dispatch` against a real sealed `$MERIDIAN_HOME` — the layer
  `live_session_e2e.rs` structurally cannot reach and the reason three exit-gate attempts passed while
  this was broken. Shape B (an `OpenChat` transition from the Requests screen itself) was severed as
  the task file permits, and is *not* required for the acceptance criterion. This checkbox still stays
  `[ ]`, since 4.45 is the only task permitted to flip it), **[4.43](./4.43-file-backed-republish-performance.md)** (the 188 s republish defect 4.39
  recorded and 4.41 measured live — settled by 4.40's own consult, since the correct fix *reduces* key
  residency rather than extending it; **landed**: `worker::inbound_handoff` now also builds an
  unwrap-once `MemorySecretStore` for `worker::republish_bundle`, and `run_worker` drops it before
  spawning `run_inbound_loop`, taking a file-backed completed-`Effect::Unlock` → `run_inbound_loop`
  spawn from a locally re-measured **194.5 s to 1.92 s** and a real PTY-driven "Unlocking" →
  `Screen::Main` from **211.5 s to 3.6 s**; `InboundHandoff::store` and the OS-keystore branch are
  unchanged — this checkbox still stays `[ ]`, since 4.45 is the only task permitted to flip it),
  **[4.44](./4.44-chat-history-load-on-open.md)** (a fourth defect
  predicted from source at plan time: `screens/main.rs` builds every chat with a literal `Vec::new()`
  history and nothing in the crate loads per-peer history into a screen, so the demo's restart-restore
  step cannot currently pass — scoped verify-first so it closes cheaply if that trace is wrong;
  **confirmed live, not a false trace, and landed**: a new `Effect::LoadHistory` round trip, dispatched
  from `ContactsAction::OpenChat`, merges disk-loaded history with any live-arrived entries via the
  existing `chat::insert_deduped`; `LiveSession` stays genuinely untouched, so no architect pre-consult
  was triggered; restart-restore and same-session re-open both verified working, with review-round
  coverage added for the `Ctrl-R`-behind-an-open-chat interleaving and the load-failure path — this
  checkbox still stays `[ ]`, since 4.45 is the only task permitted to flip it), and finally
  **[4.45](./4.45-t17-acceptance-demo-closure-attempt-4.md)**, the fourth exit-gate attempt — **run,
  verdict FAIL, a fourth new defect found and independently confirmed twice over** (source read +
  isolated test + two full live two-peer PTY runs, by both the implementer and a genuinely independent
  second run): `Effect::AddContact` has no reconciliation arm in `App::handle_worker` (unlike
  `AcceptRequest`/`RejectRequest`/`LoadHistory`/`LoadSession`, each of which does), so a contact added via
  the plain `n`-add flow never syncs into the live in-memory `TrustStore` — its own initiator cannot mark
  it verified in the same session (`TrustError::UnknownContact`), and `TrustStore::can_send`'s fail-open
  for unknown contacts means the key-change/MITM warn gate is also blind to that peer for the rest of the
  session (real invariant break; not yet actively exploitable today, since receive-side key-change
  detection isn't wired into the TUI's live inbound loop for *any* contact yet — a separate, already-
  tracked task-4.35 gap). **Pre-existing since task 4.19** — this wave's own fixes are what let a live run
  reach the code path for the first time, not something 4.42/4.43/4.44 introduced. Two secondary findings
  also recorded, not silently absorbed: `--export-json` writes a directory (correct, intentional, sealed-
  layout-mirroring) but the feature spec's demo script and this task's own step 7 both wrote the `jq`
  invocation as if it were a flat file (pre-existing since task 4.15, doc-only fix needed); and the
  OS-keystore restart methodology reasoning (kill only the app process, not the surrounding D-Bus/keyring
  session) was independently endorsed from source but only live-confirmed by one of the two runs. Full
  writeup: [4.45's own Status section](./4.45-t17-acceptance-demo-closure-attempt-4.md). **Not fixed by
  4.45 itself**, per its own explicit scope. `/plan-phase` has now scoped that fourth gap-closure wave:
  **[4.46](./4.46-add-contact-trust-reconciliation.md)** (the `Effect::AddContact` reconciliation fix,
  mirroring `App::apply_accepted_request`'s own precedent, plus a second interleaving gap traced during
  planning), **[4.47](./4.47-export-json-doc-fix.md)** (the doc-only `--export-json` demo-script fix,
  split out as its own task since it is unrelated in root cause), and
  **[4.48](./4.48-t17-acceptance-demo-closure-attempt-5.md)** (the fifth exit-gate attempt, hard-joined
  on both). This box stays `[ ]` until 4.48 confirms a genuine pass.
- [x] The envelope-v2 obligation above was re-deferred with a concrete, mechanical trigger (see
  [above](#envelope-v2-re-deferred--the-concrete-trigger)) — not silently dropped.
- Then: **not yet** `/start-review-phase` for Phase 5 — the task-tracking skill's own §7 still applies
  ("a build phase isn't done until its acceptance demo runs"), and it still doesn't. The fourth
  gap-closure wave (4.46–4.48, planned and scoped) must close the gap above first; see
  [docs/tasks/README.md](../README.md)'s carry-forward section.
