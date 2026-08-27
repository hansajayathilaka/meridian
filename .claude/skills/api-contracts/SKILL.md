---
name: api-contracts
description: Use when implementing or changing anything that crosses the wire (envelopes, prekey bundles, signaling ops, ctrl frames, stream framing) or the public core API (Transport, SecretStore, StreamType, identity/session surfaces). Ensures wire/format changes stay versioned, verified, and consistent between clients and server.
---
# API & Wire Contracts — enforcement skill

**Canonical sources (these win over diagrams and prose):**
- [docs/api/wire-protocol.md](../../../docs/api/wire-protocol.md)
- [docs/api/core-api-contracts.md](../../../docs/api/core-api-contracts.md)
- [docs/architecture/data-model.md](../../../docs/architecture/data-model.md)

## Rules
1. **Server and clients share wire types by compiling the same crate** (`meridian-proto`). Do not
   redefine envelope/bundle/ctrl shapes anywhere else. A wire change is a `meridian-proto` change.
2. **Version every wire change.** Bundles/envelopes carry a `v`; add capability negotiation rather
   than breaking silently. A downgrade below a contact's previously-seen version must warn
   (anti-rollback).
3. **Envelopes stay opaque to servers.** Routing paths treat bodies as bytes — no serde on content.
   Envelope v2 carries no per-message signature
   ([ADR 0016](../../../docs/adr/0016-envelope-deniability.md)): recipients authenticate via the
   ratchet AEAD (fails closed on tamper) plus the `sender_pub`/`v` cross-checks before trusting the
   payload. Prekey bundles and device records remain identity-key-signed and are verified before use —
   that requirement is unaffected.
4. **The public traits are semver-stable from Phase 1:** `Transport`, `SecretStore`, `StreamType`.
   Additive stream types use `register_stream_type` only — no edits to core crates.
5. **DTLS-SRTP fingerprint** travels inside the encrypted envelope and is cross-checked post-handshake.

## Definition of done for a wire/API change
- `meridian-proto` updated; `v` bumped if bytes changed; capability negotiation in place.
- **Conformance vectors regenerated** and byte-identical across CLI / WASM / mobile
  ([test strategy](../../../docs/testing/strategy.md) §1).
- Docs synced via [/doc-sync](../../commands/doc-sync.md); relevant
  [diagram](../../../docs/architecture/diagrams/README.md) updated.
- Reviewed against [ADR 0003](../../../docs/adr/0003-e2ee-protocol.md) and, for identity,
  [ADR 0001](../../../docs/adr/0001-identity-scheme.md).
