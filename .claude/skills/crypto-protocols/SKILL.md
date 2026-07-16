---
name: crypto-protocols
description: Use when writing or reviewing ANY cryptographic code — key generation, X3DH, Double Ratchet, session/message keys, safety numbers, media-key derivation, multi-device keys, or the PQ slot. Encodes the "never hand-roll" rules, the chosen libraries, and key-lifecycle discipline.
---
# Cryptographic Protocols — enforcement skill

**Read first:** [ADR 0003 (E2EE protocol)](../../../docs/adr/0003-e2ee-protocol.md),
[ADR 0011 (X3DH layer)](../../../docs/adr/0011-ratchet-library.md),
[ADR 0015 (ratchet composition)](../../../docs/adr/0015-ratchet-composition.md),
[system design §4](../../../docs/architecture/system-design.md), and the
[wire protocol §7 versioning/PQ slot](../../../docs/api/wire-protocol.md).

## Absolute rules
1. **Never hand-roll a primitive or a protocol.** Ratchet = header-encrypted Double Ratchet **composed
   in `meridian-crypto` from audited RustCrypto primitives** (`x25519-dalek`, `ed25519-dalek`, `hkdf`,
   `hmac`, `sha2`, `chacha20poly1305`) per [ADR 0015](../../../docs/adr/0015-ratchet-composition.md) —
   vodozemac's public API cannot be seeded from an externally-computed X3DH root key or the frozen `v:1`
   bundle. X3DH = the same thin layer in `meridian-crypto` over those primitives. AEAD =
   XChaCha20-Poly1305 (`chacha20poly1305` crate). Hash/merkle = `blake3`. The ratchet is *assembled
   from* audited primitives, not itself an audited off-the-shelf implementation — it carries its own
   conformance vectors and FS/PCS harnesses, and is on the Phase-1 external crypto-review gate as a
   load-bearing item, not a formality. If a task seems to need a new construction, stop and escalate via
   [/spike](../../commands/spike.md) — do not improvise.
2. **No AGPL crypto deps.** `cargo-deny` blocks them (this is why RustCrypto/vodozemac, not libsignal —
   [ADR 0011](../../../docs/adr/0011-ratchet-library.md), [ADR 0015](../../../docs/adr/0015-ratchet-composition.md)).
3. **Message protection is application-layer, inside transport.** Double Ratchet with **header
   encryption** wraps every data-channel payload *in addition to* DTLS — this is what makes content
   security independent of the transport path (design §4.3). Never rely on DTLS alone for content.
4. **Verify before you decrypt/deserialize.** Check the identity signature on an envelope before
   touching its payload. Verify prekey bundles under the *requested* key before use — a mismatch is a
   hard failure, never a downgrade (design §3.3, §4.2).
5. **Media auth is identity-bound.** DTLS-SRTP fingerprints travel inside the encrypted envelope and
   are cross-checked post-handshake; a mismatch tears the session down (design §4.6).
6. **Keys live in the keystore.** Account keys use the OS keystore/secure enclave via the
   `SecretStore` trait; headless uses an age/scrypt-wrapped keyfile. `zeroize` secrets. Never write a
   private key to a log, a DB, or the network.

## Key lifecycle (per [key-hierarchy diagram](../../../docs/architecture/diagrams/key-hierarchy.mermaid))
Account identity key → signs device subkeys + signed prekey + one-time prekeys; derives safety
numbers. Per session: X3DH → root key → ratchet chains (per peer-device). Per stream: HKDF-export
keyed by stream id. Per file: dedicated key sealed under the ratchet.

## Definition of done for crypto changes
- Uses only the approved libraries; `cargo-deny` clean.
- Forward-secrecy and post-compromise properties preserved (see the FS/PCS harness in
  [test strategy §3](../../../docs/testing/strategy.md)).
- Conformance vectors regenerated if IDs/safety numbers/bundle format changed (byte-identical across
  CLI/WASM/mobile).
- Pair with the [security-reviewer](../../agents/security-reviewer.md); crypto is on the Phase-1
  external-review gate.
