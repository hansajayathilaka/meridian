# API & Protocol Reference

Canonical wire and library contracts for Meridian. If a diagram or prose description
anywhere in the repo disagrees with these files, **these files win** and the other is fixed.

- [Wire protocol (v1)](./wire-protocol.md) — identity string grammar, CBOR envelope,
  WSS ops, server-to-server federation ops, `mrd.ctrl` frames, stream framing, versioning/PQ slot.
- [Core API contracts](./core-api-contracts.md) — the stable Rust traits (`Transport`,
  `SecretStore`, `StreamType`) and public `meridian-core` surface consumed by every client shim.

Related: [system design](../architecture/system-design.md) ·
[data model](../architecture/data-model.md) ·
[api-contracts skill](../../.claude/skills/api-contracts/SKILL.md)
