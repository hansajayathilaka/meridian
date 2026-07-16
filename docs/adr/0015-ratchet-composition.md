<!-- Source: formalizes the T03 on-the-fly decision recorded in ADR 0011's superseding note (2026-07);
     see docs/tasks/phase-1/review-report.md findings F1-F3 and "On-the-fly decisions → ratchet composition". -->
> **Nav:** [ADR index](./README.md) · [ADR 0011 (superseded)](./0011-ratchet-library.md) · [ADR 0003 (E2EE protocol)](./0003-e2ee-protocol.md) · [crypto-protocols skill](../../.claude/skills/crypto-protocols/SKILL.md)

# ADR 0015: Ratchet composition — header-encrypted Double Ratchet assembled from RustCrypto primitives

**Status:** **Accepted.** **Supersedes** the "vodozemac for the Double Ratchet" mechanism of
[ADR 0011](./0011-ratchet-library.md) (the license-driven rejection of libsignal in that ADR is
unchanged and still binding).

## Context
[ADR 0011](./0011-ratchet-library.md) chose vodozemac (Apache-2.0, audited by Least Authority) over
libsignal-client (AGPL-3.0) for the Double Ratchet, on the strength of license fit, embeddability, and
clean multi-target (wasm32 + aarch64) builds. It flagged one open item: whether vodozemac's public API
would actually support Meridian's key/bundle model, tracked as the `/spike ratchet-header-enc`
time-boxed spike due before Phase-0 GA.

That spike ran during Feature 3 (T03) implementation, against real code rather than documentation, and
found vodozemac 0.10's public API unusable for our model:

- `Session` construction goes **only** through Olm's own 3DH handshake over Olm-managed Curve25519
  identity + one-time keys (`Account::create_{outbound,inbound}_session`). There is **no** entry point
  to seed the Double Ratchet from an externally-computed X3DH root key.
- vodozemac does not interoperate with the frozen `v:1` prekey bundle (Ed25519 identity key +
  separately-signed X25519 prekeys, conformance-locked in T02) — Olm's bundle shape is different and
  not swappable without breaking that freeze.
- The API exposes **neither** header encryption **nor** raw message-key access, so ADR 0011's own
  mitigation ("layer header encryption around vodozemac's message keys") is not realizable.

Adopting Olm wholesale to work around this would mean moving identity keys out of the `SecretStore` and
breaking the already-frozen bundle format — a much larger change than the ratchet-library choice was
meant to gate. This decision was made and implemented under T03 to avoid blocking Feature 3; it is
recorded here as the properly numbered superseding ADR per [CONTRIBUTING.md](../../CONTRIBUTING.md)'s
Definition of Done (ADRs must match the code) and review finding F2.

## Options
- **A. Adopt vodozemac's Olm handshake wholesale**, replacing the frozen `v:1` X3DH bundle and moving
  identity keys into Olm's account model.
- **B. Assemble the header-encrypted Double Ratchet in `meridian-crypto`** from the same audited
  RustCrypto primitives ADR 0011 already allocates to the X3DH layer (`x25519-dalek`, `ed25519-dalek`,
  `hkdf`, `hmac`, `sha2`, `xchacha20poly1305`), following the published Signal Double-Ratchet spec, and keep vodozemac
  as the intended future dependency if it ever exposes a seedable ratchet + header encryption.
- **C. Switch to libsignal-client**, which supports this key/bundle model directly.

## Decision
**B — compose the ratchet in `meridian-crypto` from audited RustCrypto primitives**, keyed by the
externally-computed X3DH root key and the frozen `v:1` bundle, implementing header encryption per the
Signal Double-Ratchet spec directly (this is, in effect, Option C from ADR 0011 — "assemble from
RustCrypto primitives" — applied specifically to the ratchet, not a reversal of that ADR's
license-driven rejection of libsignal).

### Pros (why B wins for *this* project)
- **Preserves the frozen wire format.** The `v:1` prekey bundle and X3DH layer (already implemented and
  conformance-locked in T02) are untouched; only the ratchet's key-schedule implementation changes.
- **No primitive is hand-rolled.** Every cryptographic operation (X25519 DH, Ed25519, HKDF, HMAC,
  SHA-256, XChaCha20-Poly1305) comes from the same audited RustCrypto crates ADR 0011 already accepted for X3DH;
  only the well-specified Double-Ratchet protocol *glue* connecting them is assembled in-house, exactly
  as ADR 0011 already accepted for X3DH itself. The "never bespoke crypto" rule holds.
- **AGPL-avoidance rationale is untouched.** Option A doesn't require libsignal, and Option C
  (libsignal-client) is rejected for the same reason ADR 0011 rejected it: AGPL-3.0 is incompatible
  with a self-hostable, third-party-redistributed product's licensing goals. Nothing about this decision
  revisits that tradeoff.
- **Multi-target build stays clean.** The primitive set (`ed25519-dalek`, `x25519-dalek`, `hkdf`,
  `hmac`, `sha2`, `xchacha20poly1305`, `subtle`) compiles clean to aarch64 (full crate) and wasm32
  (isolated primitive probe, standard `getrandom` `js`/`wasm_js` backend) — the same toolchain-friendly
  outcome ADR 0011 chose vodozemac for.
- **Reversible.** `meridian-crypto` still exposes the ratchet behind a stable trait; if vodozemac later
  exposes a seedable ratchet with header encryption, this layer can delegate to it without touching
  `meridian-core` consumers.

### Cons (accepted, with mitigations)
- **Higher implementation and review burden than an audited library.** The ratchet is now hand-composed
  protocol glue, not an audited off-the-shelf implementation. *Mitigation:* it carries its own known-
  answer test vectors and FS/PCS/opacity harnesses (T03; see review finding F1 / fix-task 1.6), and is a
  named item on the Phase-1 external crypto-review gate ([testing/strategy.md §7](../testing/strategy.md)) —
  that review is now load-bearing, not a formality.
- **Option A (adopt Olm wholesale) was rejected** because it would force breaking the frozen `v:1`
  bundle and relocating identity keys out of `SecretStore` — a materially larger and riskier change than
  swapping a ratchet implementation, for a library that still wouldn't solve the header-encryption gap
  any more directly than Option B does.
- **Option C (libsignal-client) was rejected** for the same AGPL-3.0 reason ADR 0011 already gave;
  restating it here so the rationale travels with the decision that actually changed.

## Consequences
- `meridian-crypto` implements the Double-Ratchet key schedule and header encryption directly on top of
  RustCrypto primitives; vodozemac is no longer a dependency of the ratchet layer (it was never wired in
  beyond the spike).
- `cargo-deny` continues to block AGPL dependencies; the license constraint from ADR 0011 is unchanged.
- Wire format is unaffected — [messaging-envelope-v1.md](../api/messaging-envelope-v1.md) and the frozen
  `v:1` prekey bundle stand as specified.
- The Phase-1 external crypto-review engagement ([testing/strategy.md §7](../testing/strategy.md)) is
  upgraded from a scheduled formality to a blocking precondition, since the ratchet is now a hand-
  composed protocol implementation rather than a delegation to an independently audited one.
- If vodozemac (or another library) later exposes a seedable ratchet with header encryption compatible
  with the frozen bundle, migrating back behind the same `meridian-crypto` trait remains open — this ADR
  does not foreclose that.
