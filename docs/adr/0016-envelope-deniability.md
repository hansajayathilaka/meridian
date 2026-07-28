<!-- Resolves the "deniability vs. envelope signature" on-the-fly decision recorded in
     docs/tasks/phase-1/review-report.md; fix-task docs/tasks/phase-1/1.17-adr-deniability-envelope-sig.md. -->
> **Nav:** [ADR index](./README.md) · [ADR 0003 (E2EE protocol)](./0003-e2ee-protocol.md) · [ADR 0007 (offline mailbox)](./0007-offline-mailbox.md) · [messaging envelope v1](../api/messaging-envelope-v1.md) · [threat model](../security/threat-model.md) · [crypto-protocols skill](../../.claude/skills/crypto-protocols/SKILL.md)

# ADR 0016: Deniability vs. the envelope identity-key signature — drop the per-message signature at envelope v2

**Status:** **Accepted** (decision), **implementation deferred** to the envelope-v2 build task (see
[Consequences](#consequences)). **Does not supersede** [ADR 0003](./0003-e2ee-protocol.md) — it
complements it, and it is an enabler for [ADR 0007](./0007-offline-mailbox.md)'s sealed-sender clause.

## Context

Two canonical documents contradict each other, and have since T03:

- [messaging-envelope-v1.md §4](../api/messaging-envelope-v1.md) signs **every** ratchet ciphertext
  with the sender's Ed25519 identity key — `Sign_IK{ratchet_ct}`, with `sender_pub` inside and signed.
  An identity-key signature over message ciphertext is third-party-provable authorship.
- [threat-model.md §1.2 goal 4](../security/threat-model.md) claims Signal-style weak deniability
  *because* "identity-key signatures are confined to key distribution and signaling."

Both cannot be true. The signature is real and implemented
([`apps/envelope/src/envelope.rs`](../../apps/envelope/src/envelope.rs),
produced/verified in [`apps/core/src/chat.rs`](../../apps/core/src/chat.rs)), so goal 4 as written is
false for v1 traffic. This was flagged as an on-the-fly decision during the Phase-1 review and is
resolved here rather than left as a doc-level contradiction.

### What the signature actually does today (established by review, not assumed)

- **It is not what binds the DTLS fingerprint.** `SignalContent` (SDP, ICE, `dtls_fp`) is *ratchet
  plaintext*, sealed via `ChatState::seal_bytes` — the envelope signature covers the **ciphertext**,
  never the SDP or the fingerprint. Fingerprint binding comes from the ratchet AEAD, from
  `AD = IK_A ‖ IK_B` in that AEAD's AAD, and (on first contact) from X3DH's `DH1`. Several code
  comments assert otherwise; **they are already wrong today**, independent of this ADR, and are
  corrected in the same pass.
- **It is load-bearing for the prekey preamble.** The ratchet AAD is `AD ‖ enc_header`, and `AD` is
  only `IK_initiator ‖ IK_responder`. `ek_pub`/`used_spk`/`used_opk` appear in **no** AAD; they are
  bound only *implicitly* (they feed the root derivation, so tampering breaks decryption). But the
  AEAD fails closed **late** — `take_otk_secret` and `sessions.insert` both run *before*
  `session.decrypt()`. So today the signature is the only thing preventing an on-path attacker from
  mutating a genuine envelope's preamble to burn an unrelated one-time prekey and install a poisoned
  responder session that permanently blocks the real sender.
- **It is redundant for authentication of an established session.** Message authenticity comes from
  the ratchet AEAD under a chain key only the two peers hold.
- **It is a cheap pre-filter** — junk is rejected on one Ed25519 verify, before any DH.

## Options

- **A. Narrow the threat-model claim** to match the shipped wire: state that v1 envelopes are
  identity-signed and therefore not deniable, and keep signing.
- **B. Spec envelope v2 to drop the per-message identity-key signature**, relying on the ratchet AEAD
  and the X3DH identity binding for authentication; defer implementation to a build phase.

## Decision

**B — envelope v2 drops the per-message identity-key signature.** Phase 1 lands only the honesty
edits (the wire is unchanged); the wire change itself is a separate, later build task.

### Why B

1. **Goal 4 is not an isolated sentence.** Deniability is asserted in
   [threat-model.md:34](../security/threat-model.md), [system-design.md §4.3](../architecture/system-design.md),
   and system-design's limitation 7. Option A means abandoning a stated security goal in a product
   whose pitch is Signal-grade E2EE.
2. **B is already a prerequisite for a decision on record.** [ADR 0007](./0007-offline-mailbox.md)
   commits to "sender-signature *inside* the encryption where possible via sealed-sender-style
   wrapping", and roadmap Phase 3 commits to sealed-sender envelope wrapping. v1's outer plaintext
   `sender_pub` + `sig` are exactly what that must remove. B is on the critical path of an accepted
   direction, not a new ambition.
3. **The mailbox makes this concrete, and is the strongest argument.** Under v1, [ADR 0007](./0007-offline-mailbox.md)'s
   offline mailbox is a server-side store of **signed** ciphertexts with a multi-day TTL. That means
   an org's own server — A1/A7, the *baseline* adversary per the threat model — holds, for days,
   third-party-verifiable cryptographic proof of who authored what, usable against the user without
   anyone having to trust the operator's word. v2 reduces that to unattributable bytes.
4. **Now is the cheapest moment.** Zero production deployments means v2 can be a flag day. Later it
   requires version negotiation *on message authentication*, which is itself a deniability-downgrade
   oracle. Do it before the mailbox (Feature 07) and before browser/mobile (Features 11/12) multiply
   the implementations that must migrate.
5. **First-contact authentication survives.** `DH1 = DH(IK_A, SPK_B)` is unconditional, so forging a
   first message requires `IK_A`'s or `SPK_B`'s private key. This is X3DH's mutual-authentication
   property and the reason Signal does not sign message ciphertexts.
6. **Threat-model goal 2 (authenticity) and goal 6 (never a weaker session) are unaffected.** Goal 2
   rests on bundle-signature verification under the exact requested key, safety numbers, and Feature
   08 block-on-change. Only the *ordering* of rejection changes.

### Rejected: Option A

A is safer as code — zero new defect surface, no flag day, no KCI change. It is rejected because it
permanently accepts the mailbox exposure in (3) against the threat model's baseline adversary, and
because it forces the design docs to state that Meridian has materially less deniability than the
Signal-family design they cite throughout. The security review's verdict was **approve-with-changes**,
not approve — B is defensible *only* with the binding conditions below.

## Binding conditions on the envelope-v2 implementation

These came out of security review and are **normative**; v2 must not ship without them.

**C1 — Signed-prekey rotation becomes an enforced, monitored control** (see R1). No code today
enforces or monitors the "~weekly" SPK rotation the design assumes. That must become real, with tests,
*before* v2 ships — it is v2's compensating control, not an aspiration.

**C2 — Commit-on-successful-decrypt is normative.** The responder runs X3DH **provisionally**,
ratchet-decrypts, and only then consumes the one-time prekey and installs the session. This requires a
read-only prekey lookup (`take_otk_secret` is destructive and must not be used on the provisional
path) and deferral of `sessions.insert`. Without this rule, v2 is unsafe: see R3.

**C3 — The v2 AAD is specified canonically** as
`aad = "mrd.env/2" ‖ AD ‖ prekey_preamble ‖ enc_header`, where:
- the preamble encoding keeps the **explicit 1-byte presence flags** v1's signing input uses —
  without them `Some(opk)` versus a longer field is splice-ambiguous;
- `AD` is the **raw Ed25519 encodings** of both identity keys, never the Montgomery forms and never
  "normalized". The Ed25519→X25519 birational map drops the sign bit, so `A` and `−A` convert to the
  same Montgomery `u` and yield an identical root; carrying the full Ed25519 encodings in the AAD is
  the *only* thing that makes a sign-flipped `sender_pub` fail closed once the signature is gone;
- the responder derives the AAD from the **received** preamble bytes (attacker-controlled by design),
  so mutation fails the AEAD. An implementation that "helpfully" uses locally-derived values
  reintroduces the gap.

**C4 — The doc/comment corrections are completed**, including the ones outside this task's original
scope (see [Consequences](#consequences)).

**C5 — v2 envelopes carry a leading `v: 2` field.** `MessageEnvelope` has **no version field** today —
its version exists only as the `mrd.env/1` tag inside the signing input, which vanishes with the
signature. This violates [wire-protocol.md](../api/wire-protocol.md)'s "every versioned object carries
a leading `v`". A sender-declared version is **not** a negotiation and creates no downgrade oracle; it
is what makes the flag day a clean, diagnosable hard error rather than an ambiguous AEAD failure.

**C6 — Do not claim a post-decryption "AD assertion" as an authentication step.** It is tautological:
the session's `ad` is built from `sender_pub` and `ad` is already in the AAD, so a successful decrypt
already implies it. Keep it as a refactor-regression guard, and describe it as one. Authentication
comes from `DH1` (first contact) and chain-key secrecy (thereafter).

**C7 — v2 must not entrench the desync short-circuit.** `open_bytes`'s `sessions.contains_key`
short-circuit means a *legitimate* re-initiated X3DH after desync is silently ignored — the new prekey
envelope decrypts against the stale session and fails. v2 rewrites this exact function; cross-reference
[task 1.18](../tasks/phase-1/1.18-desync-recovery-decision.md). v2 is also the cheap moment to add the
`eid` replay-dedup key that `wire-protocol.md` specifies and the implementation lacks.

## Accepted residual risks

> **R1 — Key-compromise impersonation on the opening message.** Dropping the per-message identity
> signature makes first-contact authentication rest entirely on X3DH's `DH1 = DH(IK_A, SPK_B)`. An
> attacker who obtains a responder's **signed-prekey secret** — without their identity key — can
> therefore forge a complete first-contact session from *any* sender to that responder. This attacker
> can **not** read the genuine sender's real first message (that requires `DH2 = DH(EK_A, IK_B)`, i.e.
> the responder's identity key), so this is a strict *gain* in attacker capability relative to envelope
> v1, where the identity signature blocked the forgery. Because SDP offers ride the same envelope as
> chat, the forged session can assert the attacker's own DTLS fingerprint and pass the §4.6
> cross-check, yielding a media/data MITM under the impersonated identity. Safety-number verification
> does **not** detect this: both identity keys are genuine. The signed-prekey secret is also the
> softest key in the hierarchy — the identity key lives behind the `SecretStore` (enclave-capable,
> non-exportable), while the signed-prekey secret is in-process plaintext. Meridian accepts this
> because it is the same property Signal's X3DH has; the compensating controls are enforced
> signed-prekey rotation (target ~weekly, monitored, and bounded further by the 60-second
> superseded-generation grace window) and keystore-grade handling of prekey secrets. Both are
> prerequisites for shipping envelope v2, not aspirations.

> **R2 — Loss of the cheap pre-filter (denial of service, not confidentiality).** Without a signature
> to reject junk before any crypto work, a hostile origin can force a full provisional X3DH —
> including a `SecretStore` DH that on mobile is a secure-enclave operation — per junk prekey envelope,
> and can force up to `MAX_SKIPPED_STORED` (2000) header-decryption trials per junk envelope on an
> existing session. Rate limiting at the routing layer, not the envelope format, is the mitigation. No
> confidentiality or authenticity property is affected.

> **R3 — Prekey-preamble integrity is enforced late, by the AEAD.** The X3DH preamble is bound only
> through the message AAD, so tampering is detected at decryption rather than before it. Envelope v2
> is therefore only safe with **commit-on-successful-decrypt**: the responder runs X3DH provisionally,
> decrypts, and only then consumes the one-time prekey and installs the session. Without this rule,
> mutating the preamble of a *genuine* envelope burns an unrelated one-time prekey and installs a
> poisoned session that permanently blocks the real sender.

> **R4 — Scope of the deniability obtained.** Envelope v2 obtains *offline deniability of authorship*:
> message authentication reduces to symmetric AEAD under keys the recipient also holds, so no
> ciphertext is third-party-verifiable as any particular sender's, and any transcript can be forged by
> the recipient. It does **not** obtain deniability of *participation*: prekey-bundle signatures, the
> domain-bound rendezvous auth signature, and account-signed device records all remain identity-key
> signatures proving a key was live at a given server at a given time. Nor does it defeat *server
> testimony*: the routing `from` is taken from the authenticated WebSocket session, so an operator can
> attest that a blob arrived on a given account's connection — testimony that requires trusting the
> operator, not a transferable cryptographic proof. This is weak, Signal-grade deniability, not OTR- or
> court-grade, and there is no online/interactive deniability.

> **R5 — Hard flag day.** v1 and v2 envelopes do not interoperate and there is no negotiation, by
> design: negotiating *message authentication* would itself be a deniability-downgrade oracle (a
> malicious server claiming "your peer only speaks v1" would force the sender to keep signing). The
> cost is a coordinated cutover with no mixed-version window. To make the cutover diagnosable rather
> than ambiguous, v2 envelopes carry a leading `v: 2` field — a sender-declared version, never a
> negotiated one.

## Consequences

### Landing now (Phase 1, task 1.17) — docs only, wire unchanged
The contradiction is removed by stating v1's real property everywhere it is currently misstated:
[threat-model.md](../security/threat-model.md) goal 4 + §1.3,
[messaging-envelope-v1.md](../api/messaging-envelope-v1.md) versioning note + §4,
[wire-protocol.md §3](../api/wire-protocol.md), [system-design.md](../architecture/system-design.md)
§4.3 + §7.1 + limitation 7, and
[threat-mitigation-matrix.md](../security/threat-mitigation-matrix.md)'s A2 row and first-message
deniability claim. The already-incorrect "fingerprint is identity-bound by the envelope signature"
comments in [`apps/envelope/src/signal.rs`](../../apps/envelope/src/signal.rs) are corrected too, since
they are wrong today regardless of this decision.

`wire-protocol.md §3` deserves separate mention: it carries a **second, divergent** envelope definition
(`v`, `eid`, and a signing input of `v ‖ eid ‖ payload` that omits `sender_pub`) that disagrees with
both `messaging-envelope-v1.md` and the implementation. Its missing `sender_pub` is a key-substitution
weakness in the spec. It is reconciled to the implemented format in this pass.

### Deliberately NOT changed now
[crypto-protocols/SKILL.md](../../.claude/skills/crypto-protocols/SKILL.md) rule 4 ("check the identity
signature on an envelope before touching its payload") stays as-is. Security review recommended
superseding it in this pass; that is **declined for the interim**, because v1 still signs and the rule
is correct and load-bearing for the code that exists today — weakening it now would tell a future
session not to verify a signature the current wire depends on. It is instead recorded as a v2-time
obligation under C4, alongside
[api-contracts/SKILL.md](../../.claude/skills/api-contracts/SKILL.md),
[webrtc-nat-traversal/SKILL.md](../../.claude/skills/webrtc-nat-traversal/SKILL.md), and the
`apps/CLAUDE.md` / `apps/rendezvous/CLAUDE.md` rules.

### Follow-up build task (must be scheduled, or the "interim" becomes permanent)
**"Envelope v2 — drop the per-message identity signature."** Schedule in the next build phase and
**gate Feature 07 (mailbox) on it** — shipping the mailbox first is what makes the exposure in
Decision-rationale (3) durable. Obligations: C1–C7 above, plus wire/vector work — changing the ratchet
AAD changes the *ratchet message* construction, so `test-vectors/ratchet-v1.json` becomes
`ratchet-v2.json` alongside a new `envelope-v2.json`, regenerated via `cargo run -p xtask -- vectors`
(v1 files retained; vectors are canonical and never hand-edited) and covered by
`apps/crypto/tests/conformance.rs`. Coordinate with [task 1.6](../tasks/phase-1/1.6-conformance-vectors.md).

### Test obligations

Task [1.32](../tasks/phase-1/1.32-relay-attacks-past-signature.md) discharged the v1-reachable ones
(folded into a single thread with its own relay-attack cells, as this ADR asked). Status per item:

- **R3 / C2 — DISCHARGED for v1** by `apps/core/tests/preamble_mutation.rs` (in the `mitm-sim`
  harness): a forged prekey envelope claiming `from = Alice`, and *mutated* preamble on a genuine
  envelope (`used_opk`→`None`, `used_opk`→another held OTK, `used_spk`→previous generation). Each
  asserts all four properties — decrypt fails (pinned to `ChatError::BadSignature`, the v1 detector),
  OTK pool depth unchanged (counted, with a positive control proving the counter is sensitive), no
  session installed (in fact the whole `ChatState` is byte-identical), and Alice's genuine envelope
  subsequently succeeds. The relay-mounted half of the forged-`from` case is
  `apps/cli/tests/relay_attacks.rs::forged_deliver_from_is_rejected_as_sender_mismatch`, which drives
  it from a real hostile rendezvous (`ChatError::SenderMismatch`).
  **Still open for the v2 build task:** these cells pin `ChatError::BadSignature` as the detector, so
  they fail at the v2 cutover **regardless** — the detector they name ceases to exist. They are not a
  C2 detector today. Once re-pointed at the ratchet AEAD they *become* one: a v2 without C2
  (commit-on-successful-decrypt) fails their OTK-depth and byte-identical-state assertions, because
  the OTK would be consumed and the session installed before the AEAD failed. Re-point, never delete.
- **C3 — OPEN (v2).** The Ed25519 sign-flipped `sender_pub` case is a v2 property: under v1 the
  signature covers `sender_pub`, so a flip is caught trivially, and the case only becomes meaningful
  once the AAD carries the raw Ed25519 encodings. The **live gap in v1** this item recorded —
  `apps/core/tests/chat_manager.rs` covering wrong-`from` and a ciphertext byte-flip but **not**
  preamble mutation — is now closed by `preamble_mutation.rs` above.
- **R1 — OPEN (v2).** The documented-by-test KCI cell lands with envelope v2. The **conflict is
  resolved**: [testing/strategy.md](../testing/strategy.md) and
  [threat-mitigation-matrix.md](../security/threat-mitigation-matrix.md) now say "0 silent successes
  **outside the enumerated accepted residuals**", so the harness no longer contradicts this ADR. The
  wording is deliberately not weaker: "enumerated" means listed as an accepted residual **in this
  ADR** or in [threat-model.md §1.3](../security/threat-model.md) — not "in any ADR", which is an
  open set a future decision could quietly extend. The exception is **not live under envelope v1**:
  no enumerated residual applies to that matrix today, so the current requirement is 0 silent
  successes, unqualified. Extending the enumerated list requires a new ADR with security-reviewer
  sign-off; the list is not to be extended to make a harness go green.
- **§4.6 unchanged** → `apps/transport/tests/webrtc_backend.rs`'s tampered-fingerprint test must stay
  green across the v2 cutover; that is the evidence that dropping the signature is a no-op for
  fingerprint binding.
