# CLAUDE.md — apps/crypto (`meridian-crypto`)

Scoped memory. Inherits [root](../../CLAUDE.md) + [apps/CLAUDE.md](../CLAUDE.md). The most
security-critical crate in the tree.

Read first: [crypto-protocols skill](../../.claude/skills/crypto-protocols/SKILL.md),
[ADR 0011 (ratchet library — X3DH layer)](../../docs/adr/0011-ratchet-library.md),
[ADR 0015 (ratchet composition)](../../docs/adr/0015-ratchet-composition.md),
[messaging-envelope-v1](../../docs/api/messaging-envelope-v1.md).

## Rules
- **Never hand-roll crypto.** X3DH + header-encrypted Double Ratchet are composed here from audited
  RustCrypto primitives only (`x25519-dalek`, `ed25519-dalek`, `hkdf`, `hmac`, `sha2`,
  `chacha20poly1305`) per ADR 0015 — vodozemac's public API cannot be seeded from an externally-computed
  X3DH root key or the frozen `v:1` bundle. OpenMLS for groups later. No bespoke primitives, modes, or
  KDFs — only the well-specified protocol glue connecting audited primitives is assembled in-house.
- **Key hygiene:** zeroize secret material; never log keys, nonces, or plaintext; keys live behind
  `meridian-store`'s `SecretStore`.
- **Forward secrecy & PCS are invariants** — a test asserting them is never weakened to go green.
- Any change to session/message key derivation or the fingerprint construction is **wire-critical**:
  version it and regenerate conformance vectors byte-identical (`test-vectors/`).
- The PQ slot stays a slot until the spike lands ([handoff-readiness §F](../../docs/handoff-readiness.md)).
- Route any change here through the **security-reviewer** agent.
