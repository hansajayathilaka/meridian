---
name: stream-type-authoring
description: Use when adding or modifying a stream type (chat, file, location, sticker, call, tunnel, fs, or a new one). Encodes the extension contract that keeps "ultimate sharing platform" an architectural property — new stream types add via the registry with ZERO core-crate edits.
---
# Stream-Type Authoring — enforcement skill

**Read first:** [system design §5.3](../../../docs/architecture/system-design.md), the
[stream-plugin diagram](../../../docs/architecture/diagrams/stream-plugin.mermaid), and
[core-api-contracts (StreamType)](../../../docs/api/core-api-contracts.md).

## What a stream type IS (and nothing more)
A stream type is exactly four things:
1. a registered **name + version** (e.g. `mrd.file/1`),
2. a **CBOR message schema**,
3. a **channel config** (reliable/ordered, reliable/unordered, unreliable, or RTP transceiver),
4. a **policy descriptor** (auto-accept / prompt / org hook).

If you are adding anything else to the core to make a feature work, you are doing it wrong.

## The one hard rule
**Register via `register_stream_type(...)` only. Do NOT edit core crates** (identity, crypto, session,
transport, signaling). This is enforced by CODEOWNERS on the core crates and is an acceptance criterion
for features 09/15/16. The "third-party implementability" test applies: someone must be able to build a
new stream type from [the wire protocol §5–§6](../../../docs/api/wire-protocol.md) alone.

## Recipe
1. Define the CBOR body types in `meridian-streams` (or a feature crate), not in `meridian-proto`
   unless the frame is a control frame.
2. Pick the channel config from the four kinds. Media types attach an RTP transceiver instead of a
   data channel.
3. Derive per-stream keys via HKDF-export from the ratchet, `info = "mrd/stream/" ‖ type ‖ sid`
   (see [crypto-protocols skill](../crypto-protocols/SKILL.md)) — one ratchet step at OPEN, fast AEAD
   after.
4. Implement the `StreamType` trait: `name`, `channel_cfg`, `on_open` (return a policy decision),
   `on_frame`.
5. Add a spec section to the wire-protocol doc and a demo to the feature spec; run
   [/doc-sync](../../commands/doc-sync.md).

## Definition of done
- Zero diffs to core crates (CI dependency/CODEOWNERS check green).
- Framing matches [wire protocol §6](../../../docs/api/wire-protocol.md); versioned name.
- Policy descriptor present; sensitive types (tunnels, screenshare) default to prompt/allowlist, never
  auto-accept ([anonymity-model skill](../anonymity-model/SKILL.md)).
