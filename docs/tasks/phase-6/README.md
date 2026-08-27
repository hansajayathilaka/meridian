<!-- Created by /pick-next-phase. The todo list below is filled by /plan-phase. -->
> **Nav:** [tracker](../README.md) · [roadmap](../../architecture/roadmap.md) · [features](../../architecture/features/)

# Phase 6 — Envelope v2

**Kind:** build · **Status:** done · **Reviews phase(s):** n/a (this phase itself gets swept by
the next review phase, Phase 7)

## Goal
Implement **envelope v2** — the wire-format change [ADR 0016](../../adr/0016-envelope-deniability.md)
accepted but deliberately deferred out of both Phase 1 (docs-only landing) and Phase 4 (re-deferred with
a mechanical trigger, not silently dropped). Envelope v2 drops the per-message Ed25519 identity-key
signature from `MessageEnvelope`, relying instead on the ratchet AEAD and X3DH's `DH1` for
authentication, and is the standing dependency gate that unblocks **T07 — Offline Ciphertext Mailbox**
(and transitively T14). This is not a numbered feature in [roadmap.md](../../architecture/roadmap.md) —
it is a wire/crypto migration, scoped entirely by ADR 0016's binding conditions.

Working output at sign-off: `apps/envelope`/`apps/core` speak only `v: 2` envelopes; the v1 signature
path is gone; conformance vectors (`ratchet-v2.json`, `envelope-v2.json`) are generated and checked in
`apps/crypto/tests/conformance.rs`; the ADR's re-pointed v1 test cells (KCI, sign-flipped `sender_pub`,
preamble-mutation OTK/session-install assertions) pass against the new AEAD-only detector; and the flag
day is a clean, diagnosable hard error (no v1/v2 interop, no negotiation).

## Chosen feature(s) / scope
- **Envelope v2** — [ADR 0016](../../adr/0016-envelope-deniability.md) (binding) · not a
  `docs/architecture/features/NN-*.md` spec; scope is the ADR's own "Follow-up build task" and
  "Binding conditions" sections, plus the wire docs it amends:
  [messaging-envelope-v1.md](../../api/messaging-envelope-v1.md) (becomes the v2 wire definition) and
  [wire-protocol.md §3](../../api/wire-protocol.md) (reconcile the `v`/`eid` shape).
  Depends on: T03 (E2EE messaging, done), ADR 0016 (accepted). **All done ✔**

Scope is pre-written by the ADR and by [Phase 4's re-deferral](../phase-4/README.md#envelope-v2-re-deferred--the-concrete-trigger),
which sized it "comparably to Phase 2 (T06)" so `/plan-phase` doesn't under-scope it:

1. **C1 — Enforced, monitored SPK rotation.** No code today enforces the "~weekly" signed-prekey
   rotation the design assumes; this is v2's compensating control for R1 (KCI on the opening message)
   and must land *before* v2 ships, with tests — not as an aspiration.
2. **C2 — Commit-on-successful-decrypt.** Responder runs X3DH provisionally, ratchet-decrypts, and only
   *then* consumes the one-time prekey and installs the session (`take_otk_secret` must not run on the
   provisional path; `sessions.insert` deferred). This rewrites `open_bytes` — cross-reference
   [task 1.18](../phase-1/1.18-desync-recovery-decision.md) and [task 4.9](../phase-4/4.9-desync-guarded-rehandshake.md),
   since it's also where **C7**'s desync short-circuit fix belongs.
3. **C3 — Canonical v2 AAD**: `"mrd.env/2" ‖ AD ‖ prekey_preamble ‖ enc_header`, with explicit 1-byte
   presence flags in the preamble encoding, raw Ed25519 encodings (never Montgomery-normalized) in
   `AD`, and the AAD derived from the *received* preamble bytes.
4. **C4 — Doc/comment corrections** completed outside Phase 1's original scope (see ADR
   Consequences), plus superseding `crypto-protocols/SKILL.md` rule 4 ("check the identity signature
   before touching payload") — deliberately *not* touched until now.
5. **C5 — Leading `v: 2` field** on `MessageEnvelope` (today has no version field at all) — a
   sender-declared version, not negotiated, so the flag-day cutover fails as a clean hard error.
6. **C6 — No tautological "AD assertion"** claimed as authentication; keep it as a refactor-regression
   guard only, documented as such.
7. **C7 — Rewrite `open_bytes`'s desync short-circuit** (the `sessions.contains_key` early-return that
   silently swallows a legitimate re-initiated X3DH) as part of the same function C2 already rewrites,
   and add the `eid` replay-dedup key `wire-protocol.md` specifies but the implementation lacks (carries
   forward the Phase-2 replay-dedup obligation — 2.13 only bounded a replay's harm to one failed
   decrypt; full dedup via `eid` is this phase's job).
8. **Vectors + conformance**: `test-vectors/ratchet-v1.json` gains a `ratchet-v2.json` sibling, plus new
   `envelope-v2.json`, regenerated via `cargo run -p xtask -- vectors` (v1 files retained), covered by
   `apps/crypto/tests/conformance.rs`.
9. **Test re-pointing, not deletion**: the v1-pinned cells in `apps/core/tests/preamble_mutation.rs`
   (OTK-depth, byte-identical-state, `ChatError::BadSignature` detector) must be re-pointed at the
   ratchet AEAD as the new detector — they fail at cutover regardless, and only become C2 evidence once
   re-pointed. New cells: sign-flipped `sender_pub` (C3, meaningless under v1, real under v2) and the
   documented KCI cell (R1, an *enumerated* accepted residual, not a silent success). §4.6's
   tampered-fingerprint test (`apps/transport/tests/webrtc_backend.rs`) must stay green across the
   cutover as evidence the signature drop is a no-op for fingerprint binding.
10. **Doc-sync**: `threat-model.md`, `threat-mitigation-matrix.md`, `system-design.md`, and
    `messaging-envelope-v1.md`/`wire-protocol.md` updated to describe v2 as shipped, per ADR 0016's
    "Consequences" section and C4.
11. **Unblock the roadmap gate**: once this phase is `- [x]` end to end, update
    [roadmap.md](../../architecture/roadmap.md)'s T07 deps row and `docs/tasks/README.md`'s
    Live-carry-forwards note that currently blocks T07/T14 from being pickable.

## Dependency check
Everything envelope v2 touches is already built and stable: T03 (E2EE messaging/ratchet, Phase 0),
T06 (federation, Phase 2) which is why R4's federated-deniability scope matters, and T08 (verification &
trust, Phase 4) whose desync-recovery work (4.9) this phase's C2/C7 rewrite must not regress — 4.9 fixed
the short-circuit's most acute symptom under v1's AAD; this phase rewrites the same function under the
new AAD and must re-verify 4.9's behavior, not merely preserve it. ADR 0016 is **Accepted**; only its
*implementation* was deferred, twice, each time with an explicit, recorded trigger rather than left to
evaporate:
- Phase 1 (1.17) landed the doc/ADR-truth half only, by design.
- Phase 4 re-deferred it with the mechanical trigger reproduced above, naming *this* phase — the one
  immediately following Phase 5's review sweep — as where it lands.
- Phase 5's review (closed, 0 blocking) raised nothing that reopens or reshapes this scope.

No other phase or task is unresolved ahead of this one; the phase is unblocked now.

## `/plan-phase` refinements (planner + architect consult, before task files were written)
The 11-item scope list above was written at `/pick-next-phase` time, straight from the ADR text. A
**planner** pass (task breakdown) and an independent **architect** pass (architecture-guard read of the
actual code, not just the ADR) both ran before the task files below were written, and changed the shape
in three ways the scope list above doesn't capture:

1. **C2 and C3 cannot land as separately-mergeable tasks.** The AAD/wire-shape change (C3) is only safe
   *together with* commit-on-successful-decrypt (C2) — landing one without the other reproduces the R3
   vulnerability the ADR calls out. Both, plus C5/C6 and C7's short-circuit half, are one task (6.1's
   sibling **6.3**), not split further, even though that makes 6.3 the largest task in the phase. C7's
   `eid` half is safely separable (6.4) since it isn't part of the AEAD/AAD safety property.
2. **6.3 is reviewed by architect + security-reviewer as two independent named lenses**, not the
   combined `reviewer` agent this workflow otherwise defaults to for a single task. Precedent: this
   exact function (`ChatState::open_bytes`) was hardened by task 1.18, and a security bug in that fix
   was caught only by "architect + security-reviewer, independently" (recorded in
   [messaging-envelope-v1.md](../../api/messaging-envelope-v1.md) around the desync-recovery section).
   6.3 rewrites the same function under new rules and gets the same treatment.
3. **C4's doc-sync scope is wider than the ADR's own list**: `apps/rendezvous/src/route_tamper.rs`,
   `apps/rendezvous/src/auth.rs`, and `apps/core/src/session.rs`'s `ANSWER_TIMEOUT` doc comment all
   contain v1-specific security-reasoning prose ("every byte is either signed or is the signature")
   that goes stale — actively misleading, not just outdated — the moment the signature disappears.
   Folded into **6.7** alongside the ADR's originally-named doc set.

A fourth finding didn't change the task shape but is now an explicit constraint inside **6.3**: the
`v: 2` field must never be routed through either of the codebase's two *existing* version-negotiation
mechanisms (Bundle `v:1`/`v:2`'s soft anti-rollback warning, or `Hello.streams[].ver` capability
exchange) — both are one associative hop away ("we already have versioning") and both are exactly the
kind of negotiation ADR 0016's R5 forbids for message authentication.

No new ADR was needed for any of this — C1's SPK-rotation-enforcement mechanism (interval, fail-open/
fail-closed behavior) is the one genuinely unspecified detail in the ADR, and is handled as a
`TODO: confirm` + documented decision inside 6.1/6.2's own task files with architect + security-reviewer
sign-off, per this codebase's existing precedent for this class of gap (e.g. `DESYNC_RECOVERY_THRESHOLD`),
not as a new binding decision that would contradict or extend an accepted ADR.

## Tasks (todo)
<!-- Status marks: [ ] pending [~] in progress [x] done [!] blocked -->

**Wave 1 — parallel tracks** (rotation enforcement and the core cutover touch disjoint code and can be
developed independently; the AAD/commit-on-decrypt rewrite must not be split further — see 6.3's own
Goal section for why)
- [x] **6.1** SPK rotation policy: age tracking + rotation-due predicate (C1, part 1/3) — [file](./6.1-spk-rotation-age-tracking.md)
- [x] **6.3** Envelope v2 core cutover: wire shape + canonical AAD + commit-on-decrypt + desync short-circuit fix (C2, C3, C5, C6, C7 short-circuit) — [file](./6.3-envelope-v2-core-cutover.md)

**Wave 2**
- [x] **6.2** SPK rotation enforcement: trigger + monitoring in both long-running client loops (C1, parts 2–3/3; depends on 6.1) — [file](./6.2-spk-rotation-enforcement.md)
- [x] **6.4** `eid` replay-dedup key (C7, second half; depends on 6.3) — [file](./6.4-eid-replay-dedup.md)
- [x] **6.6** Test re-pointing: v1 detector → v2 AEAD, plus the new C3/R1 adversarial cells (depends on 6.3) — [file](./6.6-repoint-adversarial-tests.md)

**Wave 3**
- [x] **6.5** Conformance vectors: `ratchet-v2.json` + `envelope-v2.json` (depends on 6.3, 6.4) — [file](./6.5-conformance-vectors-v2.md)
- [x] **6.7** Doc-sync: describe envelope v2 as shipped (C4; depends on 6.3, 6.4) — [file](./6.7-doc-sync-envelope-v2.md)

**Wave 4 — exit gate**
- [x] **6.8** Phase exit: flag-day cutover verification + acceptance demo + roadmap unblock (depends on 6.1–6.7) — [file](./6.8-phase-exit-flag-day-demo.md)

## Exit criteria
All tasks `- [x]`; tree green (`cargo build --workspace`, `cargo fmt --check`,
`cargo clippy --workspace --all-targets -- -D warnings`); `ratchet-v2.json`/`envelope-v2.json`
generated and checked by `apps/crypto/tests/conformance.rs`; the re-pointed v1 test cells (OTK-depth,
byte-identical-state, sign-flipped `sender_pub`, KCI) pass against the AEAD-only detector; docs synced
per C4 (including superseding `crypto-protocols/SKILL.md` rule 4); `roadmap.md`'s T07 deps row and
`docs/tasks/README.md`'s Live-carry-forwards both updated to reflect envelope-v2 as done, unblocking
T07/T14 for a future `/pick-next-phase`. Then: `/start-review-phase` for Phase 7.
