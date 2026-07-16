<!-- Source: REPO-01 §6 ADR-R3, RESOLVED by handoff decision (see docs/handoff-readiness.md D1). -->
> **Nav:** [ADR index](./README.md) · [stack](../architecture/stack.md) · [crypto-protocols skill](../../.claude/skills/crypto-protocols/SKILL.md)

# ADR 0011: Ratchet & key-agreement library — vodozemac + hand-wired X3DH

**Status:** **Superseded by [0015](./0015-ratchet-composition.md)** for the Double-Ratchet mechanism
(was Proposed/open; resolved at handoff, then partially superseded once the `ratchet-header-enc` spike
ran against real code). The X3DH-layer decision and the AGPL-avoidance rationale below remain binding —
see [0015](./0015-ratchet-composition.md) for what changed and why.

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

<a id="supersede-2026-07"></a>
## Superseding note (2026-07, resolved by T03) — ratchet composed in `meridian-crypto`, not vodozemac

**Status:** the ratchet-library *outcome* below supersedes the "vodozemac for the Double Ratchet"
mechanism of the Decision above. The **rationale that chose vodozemac over libsignal is unchanged**
(Apache-2.0 vs AGPL, pure-Rust multi-target); only the integration mechanism changed once the
`ratchet-header-enc` spike was run against real code.

**Finding (spike outcome).** vodozemac 0.10's public API constructs a `Session` **only** through
Olm's own 3DH handshake over Olm-managed Curve25519 identity + one-time keys
(`Account::create_{outbound,inbound}_session`). It offers **no** way to seed the Double Ratchet from
an externally-computed X3DH `root` key, does **not** interoperate with the frozen `v:1` prekey bundle
(Ed25519 identity + separately-signed X25519 prekeys, conformance-locked in T02), and exposes
**neither** header encryption **nor** raw message-key access. The ADR's own mitigation ("layer header
encryption around vodozemac's message keys") is therefore not realizable through its public API, and
adopting Olm wholesale would require breaking the frozen bundle format and moving identity keys out
of the `SecretStore`.

**Decision.** Compose the header-encrypted Double Ratchet in `meridian-crypto` from the **same
audited RustCrypto primitives this ADR already allocates to the X3DH layer** (`x25519-dalek`,
`hkdf`, `hmac`, `sha2`, `chacha20poly1305`) following the published Signal Double-Ratchet spec. This
is effectively **Option C for the ratchet specifically**, chosen because Option B's ratchet is not
reachable for our key/bundle model — not a reversal of the license-driven rejection of libsignal.

**Guardrails (unchanged intent of "never bespoke").** No primitive is hand-rolled — only the
well-specified protocol glue is assembled, exactly as the ADR already accepted for X3DH. The
integration carries its own test vectors + FS/PCS/opacity harnesses (T03) and is a named item on the
**Phase-1 external crypto-review gate** ([testing/strategy.md §7](../testing/strategy.md)). Wire
details are frozen in [messaging-envelope-v1.md](../api/messaging-envelope-v1.md). `cargo-deny` still
blocks AGPL; vodozemac remains the intended dependency if/when it exposes a seedable ratchet + header
encryption, at which point this layer can delegate to it behind the same `meridian-crypto` API.

**Multi-target check (T03, per the feature-spec risk note).** The ratchet/X3DH primitive set
(`ed25519-dalek`, `x25519-dalek`, `hkdf`, `hmac`, `sha2`, `chacha20poly1305`, `subtle`) compiles
clean to **aarch64** (full crate) and **wasm32** (isolated primitive probe; wasm needs only the
standard `getrandom` `js`/`wasm_js` backend — a T11 browser-integration detail, not a ratchet-library
problem). This is the pure-Rust, toolchain-friendly outcome the ADR chose vodozemac for; the T11 wasm
build of `meridian-core` will additionally feature-gate `meridian-store`'s native backends (age /
keyring), which are the remaining non-wasm pieces — tracked with T11, not here.

*Formalized:* this note recorded the binding decision made at T03 so implementation was not blocked.
It is now formalized as [ADR 0015](./0015-ratchet-composition.md) (house-numbered — "0011a" was never
correct numbering); 0015 is the canonical record going forward, this note stands as historical context.
