# API & Protocol Reference

Canonical wire and library contracts for Meridian. If a diagram or prose description
anywhere in the repo disagrees with these files, **these files win** and the other is fixed.

- [Wire protocol (v1)](./wire-protocol.md) — identity string grammar, CBOR envelope,
  WSS ops, server-to-server federation ops, `mrd.ctrl` frames, stream framing, versioning/PQ slot.
- [Identity format (v1, frozen)](./identity-format.md) — the `mrd1:…@domain` string in full:
  field layout, checksum, canonical hint rules, parse rejections, QR, keystore, and the PQ slot (T01).
- [Rendezvous protocol (v1)](./rendezvous-protocol-v1.md) — the client↔server CBOR framing: the
  `{op,id,body}` frame, challenge–response auth, bundle publish/fetch (with the client's mandatory
  verification), opaque routing, config, and metrics (T02).
- [Core API contracts](./core-api-contracts.md) — the stable Rust traits (`Transport`,
  `SecretStore`, `StreamType`) and public `meridian-core` surface consumed by every client shim.

Related: [system design](../architecture/system-design.md) ·
[data model](../architecture/data-model.md) ·
[api-contracts skill](../../.claude/skills/api-contracts/SKILL.md)
