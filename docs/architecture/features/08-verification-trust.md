<!-- Source: tasks/T08-verification-trust.md. Feature spec with runnable acceptance demo. -->
> **Nav:** [docs index](../../INDEX.md) · [roadmap](../roadmap.md) · [system design](../system-design.md) · [test strategy](../../testing/strategy.md)

# T08 — Verification & Contact Trust

**Priority:** P1 — this task is why the system survives malicious servers · **Design refs:** §4.4, §3.5, §1.2 goals 2 & 6 · **Depends on:** T03 · **Indicative effort:** 2 eng-weeks

## Goal
Implement the human-verifiable trust layer: safety numbers (numeric + QR), TOFU pinning, verified-contact state, and *blocking* key-change semantics — then prove, with an adversarial harness, that a fully malicious rendezvous cannot complete an undetected MITM against verified contacts.

## Scope
In: safety-number computation (Signal-construction fingerprint over both identity keys — lands in core, consumed by every client); contact store states `new → pinned (TOFU) → verified`; QR compare flow in CLI/TUI (display + scan-file for headless); key-change handling: verified ⇒ **block sends until re-verified**, pinned ⇒ prominent warn (org-configurable to block); petname assignment (§3.1 — display names are never taken from the wire); message-request UX finalization (first contact shows key + intro before any session, from T06); org **directory attestation** ingest (signed HR-name→key mappings treated as petname provenance, not key authority, §3.5).
Out: contact-token issuance/enforcement at federation edge (follow-up in T14 hardening), web-of-trust anything.

## Deliverables
1. Trust module + contact store (encrypted at rest via T01 `SecretStore`).
2. **Adversarial harness `meridian-mitm-sim`:** a rendezvous variant that substitutes bundles/keys at every opportunity, scripted against both TOFU-only and verified contact states — outputs a pass/fail matrix.
3. `verification-ux.md` — canonical wording of every warning (clients must not soften it).

## Working output (demo script)
```
$ meridian verify mrd1:<bob>@org-b.test        # both sides run; QRs / 60-digit numbers match
  contact marked VERIFIED ✔
$ meridian-mitm-sim --attack substitute-key --against verified
  → attack #1..#7: session establishment ABORTED (0 messages leaked)   ← the headline
$ meridian-mitm-sim --attack substitute-key --against tofu
  → LOUD key-change warning presented; send blocked pending user decision
$ # key rotation drill: bob legitimately reinstalls → alice sees change, re-verifies via QR
```

## Acceptance criteria
MITM matrix: 0 attacks succeed silently against `verified`; against `pinned`, 0 succeed without the exact `verification-ux.md` warning being shown; safety numbers are order-independent (Alice and Bob compute identical strings); fingerprint test vectors added to the T01 conformance fixtures (browser/mobile must match byte-for-byte later).

## Risks / notes
The security of goal #2 (§1.2) is exactly as strong as the *unskippability* of these warnings. Resist every future product request to auto-dismiss key-change alerts; this doc is the place that says no.
