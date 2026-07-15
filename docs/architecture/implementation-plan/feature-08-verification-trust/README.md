> **Nav:** [plan index](../README.md) · **Milestone M1** · [canonical spec: T08](../../features/08-verification-trust.md) · [verification UX](../../../security/verification-ux.md) · [Definition of Done](../../../../CONTRIBUTING.md)

# Feature 08 — Verification & Contact Trust

**Milestone:** M1 (may run in parallel with Feature 06) · **Depends on:** Feature 03 · **Canonical spec:**
[T08](../../features/08-verification-trust.md).

**Goal (from spec).** The human-verifiable trust layer — safety numbers (numeric + QR), TOFU pinning,
verified-contact state, blocking key-change semantics — proven by an adversarial harness that a fully
malicious rendezvous cannot silently MITM a verified contact. **The whole feature is `[SEC]`** (threat-model
goals 2 & 6); this is *why the system survives malicious servers*.

**Exit acceptance (spec §Acceptance).** MITM matrix: 0 attacks succeed silently against `verified`; against
`pinned`, 0 succeed without the exact `verification-ux.md` warning shown; safety numbers order-independent;
fingerprint vectors added to the T01 conformance fixtures (byte-identical for browser/mobile later).

> This feature **consumes M0's T2.4** (safety-number vectors) — freeze them there, finalize UX here.

| Task | Scope | Tags | Depends on | Status |
|---|---|---|---|---|
| F08.1 | Safety-number finalization (numeric + QR) on the T2.4 vectors | [SEC] | M0 T2.4 | ☐ |
| F08.2 | Contact store states `new → pinned (TOFU) → verified` (encrypted at rest) | [SEC] | F08.1 | ☐ |
| F08.3 | QR compare flow (display + scan-file headless) in CLI/TUI | [SEC] | F08.1 | ☐ |
| F08.4 | Key-change semantics: verified ⇒ block; pinned ⇒ loud warn | [SEC] | F08.2 | ☐ |
| F08.5 | Petname assignment + org directory-attestation ingest | [SEC] | F08.2 | ☐ |
| F08.6 | Message-request UX finalization (key + intro before any session) | [SEC] | F08.2 | ☐ |
| F08.7 | `meridian-mitm-sim` trust matrix + `verification-ux.md` canonical wording | [SEC] | F08.4 | ☐ |

### F08.1 — Safety-number finalization
- **Scope.** Numeric 60-digit + QR rendering of the order-independent fingerprint; lands in core, consumed by every client.
- **Touches.** `apps/crypto/src/fingerprint.rs`, `apps/cli`. **[SEC]**. security-reviewer.
- **Deliverables.** Numeric + QR on the frozen T2.4 vectors; order-independence guaranteed.
- **Tests.** Value-exact against `test-vectors/safety-numbers-v1.json`; Alice/Bob compute identical strings.
- **Verification (DoD).** 3, 4.

### F08.2 — Contact store + trust states
- **Scope.** `new → pinned (TOFU) → verified` state machine; store encrypted at rest via the T01 `SecretStore`.
- **Touches.** `apps/core/src/trust/` (new), `apps/store`. **[SEC]** storage. security-reviewer.
- **Deliverables.** Trust-state store; matches the trust-state-machine diagram.
- **Tests.** State transitions; at-rest encryption; wrong-key store fails closed.
- **Verification (DoD).** 4, 7 (diagram sync).

### F08.3 — QR compare flow
- **Scope.** Display + scan-file compare in CLI/TUI (camera scan is a T11 client concern).
- **Touches.** `apps/cli/src/verify.rs` (new). **[SEC]**. security-reviewer.
- **Deliverables.** `meridian verify <id>` display + `--scan-file`.
- **Tests.** Matching numbers → VERIFIED; mismatch → not verified, no state change.
- **Verification (DoD).** 4.

### F08.4 — Key-change semantics
- **Scope.** verified ⇒ **block sends until re-verified**; pinned ⇒ prominent warn (org-configurable to block).
- **Touches.** `apps/core/src/trust/`, `apps/core/src/session.rs` (the T04 deferral at L571–573). **[SEC]**. security-reviewer.
- **Deliverables.** Blocking semantics wired into send path; closes the R0 "verified-contact key-change" gap (threat-model goal 2, second half).
- **Tests.** verified key-change blocks; pinned key-change warns with exact wording; re-verify unblocks.
- **Verification (DoD).** 2, 4.

### F08.5 — Petname + directory attestation
- **Scope.** Petnames (display names never from the wire); ingest signed org HR-name→key attestations as petname *provenance*, **not key authority** (§3.5).
- **Touches.** `apps/core/src/trust/`. **[SEC]**. security-reviewer.
- **Deliverables.** Petname assignment; attestation ingest that never overrides key trust.
- **Tests.** Attestation influences display only; a malicious attestation cannot assert a key.
- **Verification (DoD).** 4.

### F08.6 — Message-request UX finalization
- **Scope.** First contact shows key + intro before any session (finalizes the F06.5 gate on the client).
- **Touches.** `apps/cli`, `apps/core`. **[SEC]**. security-reviewer.
- **Deliverables.** Key + intro surfaced pre-accept; no session before user decision.
- **Tests.** First-contact flow shows key; accept/decline paths correct.
- **Verification (DoD).** 4.

### F08.7 — MITM trust matrix + verification-ux.md
- **Scope.** `meridian-mitm-sim` substitutes bundles/keys at every opportunity against TOFU-only and verified states → pass/fail matrix; finalize `verification-ux.md` (un-softenable warnings).
- **Touches.** `harnesses/mitm-sim` (extend beyond T02/T04 cases), `docs/security/verification-ux.md`. **[SEC]**. security-reviewer + test-engineer.
- **Deliverables.** Trust-state attack matrix; canonical warning wording clients must not soften.
- **Tests.** 0 silent successes vs `verified`; vs `pinned` the exact warning is required; key-rotation drill (legit reinstall) re-verifies via QR.
- **Verification (DoD).** 2, 4.
