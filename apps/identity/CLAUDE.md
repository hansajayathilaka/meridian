# CLAUDE.md — apps/identity (`meridian-identity`)

Scoped memory. Inherits [root](../../CLAUDE.md) + [apps/CLAUDE.md](../CLAUDE.md).

Read first: [identity-format](../../docs/api/identity-format.md),
[anonymity-model skill](../../.claude/skills/anonymity-model/SKILL.md).

## Rules
- **Wire-critical.** `mrd1:` encoding, the CRC, and QR bytes are canonical in `identity-format.md`.
  Any byte change bumps the version and must re-pass `test-vectors/identity-v1.json` before merge.
- Wire-critical deps (`ed25519-dalek`, `data-encoding`, `crc32c`) are pinned in the root
  `Cargo.toml`; a bump is a reviewed change gated on the conformance vectors.
- **Display names never come from the wire** — petnames are local (§3.1). IDs are pseudonymous, not
  Tor-grade; never overclaim.
- Verify signatures before trusting any parsed field; every byte off the wire is hostile.
- Route changes through **security-reviewer** + **architect** (wire format).
