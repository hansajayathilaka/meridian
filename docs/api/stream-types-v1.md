<!-- Source: T04 (feature 04-p2p-session-substrate). The stream-type extension contract. -->
> **Nav:** [docs index](../INDEX.md) · [api reference](./README.md) · [wire protocol](./wire-protocol.md) · [core API contracts](./core-api-contracts.md) · [system design §5.3](../architecture/system-design.md) · [stream-type-authoring skill](../../.claude/skills/stream-type-authoring/SKILL.md)

# Stream Types — v1 (the extension contract)

The versioned contract third parties (and features T09/T10/T15/T16) code against to add a new kind of
sharing to Meridian **without editing any core crate**. This is what makes "ultimate sharing
platform" an *architectural* property rather than a slogan (system-design §5.3): a new feature is a
registry name, a channel config, a direction, and a policy hook — nothing else in the stack changes.

Implemented by [`meridian-core::streams`](../../apps/core/src/streams.rs) (the registry + `StreamType`
trait) and driven by [`meridian-core::session`](../../apps/core/src/session.rs) (the substrate that
runs `mrd.ctrl/1`); the wire frames live in [`meridian-envelope`](../../apps/envelope/src/ctrl.rs).

## The key property

Adding a stream type is **additive**: you implement the [`StreamType`](#the-streamtype-trait) trait
downstream and call `register_stream_type`. You never touch `meridian-proto`, `meridian-core`'s
session or crypto code, or the server. CODEOWNERS on the core crate enforces this (D12); a change
that adds a stream type by editing a core enum is a design violation — supersede via the registry
instead.

`mrd.ctrl/1` (channel 0) is **not** a stream type — it is the control channel itself, always opened
first, and is implicit. Stream types ride channels 1..N.

## Channel 0: capability handshake (`mrd.ctrl/1`)

Once the peer connection is up and the DTLS fingerprint is bound (§4.6), both sides open channel 0
and exchange `Hello`, then negotiate streams. Every ctrl frame is CBOR and is **ratchet-sealed like
any payload** (wrapped in `SignalContent::Ctrl`), so a data-channel observer sees only ciphertext.

```
Hello    = {v, streams: [{name, ver, dir, mandatory}], transports: ["webrtc"], limits}
Open     = {sid, type, params, chan: {reliable, ordered, max_rtx?} | rtp}
Accept   = {sid}
Reject   = {sid, code, reason}          ; code = "unsupported" for an unknown type
Close    = {sid, status}
Keepalive= {t}                          ; liveness + flow-control hints; echoed
```

**Capability rule (test-enforced):** a peer that advertises a `mandatory: true` stream type the other
side does not support causes a **graceful** session rejection at capability exchange (`check_peer`) —
an error and a `Close{status:"capability"}`, never a crash and never a silent downgrade
(wire-protocol §2). An unknown *optional* type is simply unavailable; opening it yields
`Reject{code:"unsupported"}`, never a session error (wire-protocol §5).

## The `StreamType` trait

The exact surface (`core-api-contracts.md` §"Stream registry"):

```rust
pub trait StreamType: Send + Sync {
    fn name(&self) -> &'static str;               // e.g. "mrd.file/1" — includes the version
    fn version(&self) -> u16;
    fn channel_cfg(&self) -> ChannelCfg;          // reliability/ordering, or RTP for media
    fn direction(&self) -> Direction;             // Outbound | Inbound | Bidir
    fn mandatory(&self) -> bool { false }         // must the peer also support it?
    fn on_open(&self, sid: StreamId, params: &[u8], policy: &PolicyCtx) -> OpenDecision {
        OpenDecision::Accept                       // default: auto-accept (chat behavior)
    }
    fn on_frame(&self, sid: StreamId, frame: &[u8]) {}
}

// The ONLY mutation point downstream features use — no core edits:
pub fn register_stream_type(registry: &mut StreamRegistry, ty: Arc<dyn StreamType>);
```

- **`name` / `version`** — the registry key. The version lives in the name suffix (`/1`); a wire
  break is a *new* name, negotiated by capability exchange, never a silent reinterpretation.
- **`channel_cfg`** — how the data channel is configured when the stream opens: `reliable + ordered`
  for chat & control; `reliable + unordered` for file chunks; `unreliable` (`max_retransmits =
  Some(0)`) for live location/game streams; media types return an RTP config and attach a
  transceiver instead of a data channel (ADR 0014).
- **`direction`** — which way the type is offered, advertised in `Hello`.
- **`mandatory`** — advertise as required. `mrd.chat/1` is mandatory (the Tier-1 baseline both peers
  must speak); most third-party types are optional.
- **`on_open`** — the policy hook. Return `Accept` or `Reject{code, reason}` from the peer identity
  and first-contact state in `PolicyCtx`. Chat auto-accepts; screenshare/SSH/org-policy types prompt
  or consult a policy engine here (§5.3). This is where the message-request gate and org policy live.
- **`on_frame`** — per-frame delivery once the stream is open. File/fs types assemble chunks here.

## Stream framing (channels 1..N)

Data-channel payloads are length-prefixed and per-stream AEAD-sealed (wire-protocol §6):

```
frame = uint32-le length ‖ AEAD_stream_key(seq_nonce, cbor_body)
stream_key = HKDF(ratchet_export, info = "mrd/stream/" ‖ type ‖ sid)
```

One ratchet step at `OPEN` derives the per-stream key; frames then use symmetric AEAD with monotonic
nonces (forward secrecy at stream granularity). `TODO: confirm` — T04 re-homes `mrd.chat/1` by
carrying the existing signed `MessageEnvelope` bytes over the chat data channel (the same bytes are
valid over relay or data channel, §4.3), which is transport-equivalent and opaque; the per-stream
`HKDF(ratchet_export…)` key schedule above is the target for the bulk stream types (T09 file
transfer) and requires exposing a ratchet export from `meridian-crypto`, which lands with T09.

## Built-in and roadmap stream types

| Type | Channel config | Notes |
|------|----------------|-------|
| `mrd.ctrl/1` | reliable, ordered | channel 0; not a registered type |
| `mrd.chat/1` | reliable, ordered | Tier-1 baseline (mandatory); auto-accept (T03/T04) |
| `mrd.file/1` | reliable, unordered | manifest on ctrl; 64 KiB chunks; merkle resume (T09) |
| `mrd.call.audio/1`, `.video/1` | RTP transceivers | Opus / VP9-or-AV1; DTLS-SRTP (T10) |
| `mrd.location/1`, sticker types | unreliable, unordered | live-position / ephemeral (T15) |
| `mrd.tunnel.tcp/1`, `mrd.fs/1` | reliable, ordered | Tier-2 tunnels; policy-gated (T16) |

Each is *only* a `StreamType` implementation plus a `register_stream_type` call. If adding one
requires editing a core crate, the extension contract has been broken — fix the contract, not the
core.
