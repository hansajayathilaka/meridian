# CLAUDE.md — apps/proto (`meridian-proto`)

Scoped memory. Inherits [root](../../CLAUDE.md) + [apps/CLAUDE.md](../CLAUDE.md). The wire-type source
of truth and the **only** crate the server depends on.

Read first: [wire-protocol](../../docs/api/wire-protocol.md),
[api-contracts skill](../../.claude/skills/api-contracts/SKILL.md),
[data-model](../../docs/architecture/data-model.md).

## Rules
- **All wire types live here.** Envelopes, prekey bundles, ctrl/signal frames, stream framing — defined
  once, compiled by both clients and server. Never redefine these shapes elsewhere.
- **A wire change is a `meridian-proto` change:** bump the `v`, prefer capability negotiation over
  breaking changes, and regenerate conformance vectors byte-identical across CLI/WASM/mobile.
- **`OpaqueBlob` stays opaque.** No structured (de)serialization of payload bytes — enforced by
  `tools/lint-no-serde-on-blob.sh`.
- Deterministic CBOR encoding (ciborium) — no map-ordering nondeterminism on the wire.
- Route changes through **architect** (dep graph) + **security-reviewer** (opacity).
