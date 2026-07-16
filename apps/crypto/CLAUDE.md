# CLAUDE.md — apps/crypto (`meridian-crypto`)

Scoped memory. Inherits [root](../../CLAUDE.md) + [apps/CLAUDE.md](../CLAUDE.md). The most
security-critical crate in the tree.

Read first: [crypto-protocols skill](../../.claude/skills/crypto-protocols/SKILL.md),
[ADR 0011 (ratchet library)](../../docs/adr/0011-ratchet-library.md),
[messaging-envelope-v1](../../docs/api/messaging-envelope-v1.md).

## Rules
- **Never hand-roll crypto.** X3DH + Double Ratchet via **vodozemac**; OpenMLS for groups later. No
  bespoke primitives, modes, or KDFs.
- **Key hygiene:** zeroize secret material; never log keys, nonces, or plaintext; keys live behind
  `meridian-store`'s `SecretStore`.
- **Forward secrecy & PCS are invariants** — a test asserting them is never weakened to go green.
- Any change to session/message key derivation or the fingerprint construction is **wire-critical**:
  version it and regenerate conformance vectors byte-identical (`test-vectors/`).
- The PQ slot stays a slot until the spike lands ([handoff-readiness §F](../../docs/handoff-readiness.md)).
- Route any change here through the **security-reviewer** agent.
