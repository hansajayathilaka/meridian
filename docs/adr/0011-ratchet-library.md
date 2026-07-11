<!-- Source: REPO-01 §6 ADR-R3, RESOLVED by handoff decision (see docs/handoff-readiness.md D1). -->
> **Nav:** [ADR index](./README.md) · [stack](../architecture/stack.md) · [crypto-protocols skill](../../.claude/skills/crypto-protocols/SKILL.md)

# ADR 0011: Ratchet & key-agreement library — vodozemac + hand-wired X3DH

**Status:** **Accepted** (was Proposed/open; resolved at handoff). **Supersedes** the open state of this ADR.

## Context
Meridian needs X3DH + Double Ratchet (see [ADR 0003](./0003-e2ee-protocol.md)) via an audited
implementation — never bespoke crypto. The core compiles to WASM (browser) and aarch64 (mobile), and
the product is **self-hostable and redistributed by third parties**, so library license and
embeddability matter as much as cryptographic pedigree.

## Options
- **A. libsignal-client** — Signal's own Rust lib; the most battle-tested X3DH+Ratchet on earth.
- **B. vodozemac + hand-wired X3DH (chosen)** — Matrix's audited (Least Authority) Rust ratchet;
  Apache-2.0; built as a reusable library; clean WASM story.
- **C. Assemble from RustCrypto primitives** — maximum control.

## Decision
**B — vodozemac for the Double Ratchet, with a thin X3DH prekey layer in `meridian-crypto`.**

### Pros (why B wins for *this* project)
- **License fit is decisive.** libsignal-client is **AGPL-3.0**; embedding it in a self-hostable
  product that others deploy and modify creates copyleft obligations across the whole distribution.
  vodozemac is **Apache-2.0**, matching the workspace license and removing that friction entirely.
  This aligns with the end goal: a thing organizations can actually run and adapt without legal review.
- **Built for reuse.** vodozemac is a library with a stable, embedding-oriented API; libsignal's API is
  shaped around Signal's own app and store assumptions.
- **Clean multi-target builds.** Audited, pure-Rust, compiles cleanly to wasm32 and aarch64 — the
  exact matrix that bites us later if the ratchet lib fights the toolchain.
- **Audited.** Independent security audit (Least Authority), so the "never bespoke" rule holds.

### Cons (accepted, with mitigations)
- **X3DH is not in vodozemac** → we wire the prekey handshake ourselves around audited primitives
  (`x25519-dalek`, `ed25519-dalek`, `hkdf`, `sha2`). *Mitigation:* X3DH is a well-specified, small
  surface; it lives behind `meridian-crypto`'s API, gets its own test vectors, and is a scheduled
  external-review item before Phase-1 GA ([testing/strategy.md](../testing/strategy.md) §7).
- **Less "brand-name" battle-testing than libsignal.** *Mitigation:* vodozemac secures Matrix E2EE in
  production at large scale; the ratchet itself is the audited part.
- **Header-encryption + PQXDH slot** must be confirmed against vodozemac's API. *Mitigation:* tracked
  as the one remaining spike (`/spike ratchet-header-enc`), time-boxed in Phase 0; if header encryption
  is not exposed, we layer it in `meridian-crypto` around vodozemac's message keys.

## Consequences
- `meridian-crypto` exposes X3DH + ratchet behind a stable trait; the choice is reversible without
  touching `meridian-core` consumers.
- `cargo-deny` enforces the license decision in CI (no AGPL deps enter the graph).
- The PQXDH (`ml-kem`) hybrid slot ([ADR 0003](./0003-e2ee-protocol.md)) is added around this layer,
  not inside vodozemac.
