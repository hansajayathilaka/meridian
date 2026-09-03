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

Every stream frame is ratchet-sealed *directly*, one Double Ratchet step per frame call (not once at
`OPEN`, as an earlier draft of this section had it) — the same message-key AEAD construction used for
any other ratchet-sealed payload, so forward secrecy holds at frame granularity by construction, not
via a separately-derived symmetric cipher. `P2pSession::send_stream_frame` (outbound) and the generic
inbound dispatch in `pump` (`apps/core/src/session.rs`) both call
`meridian_crypto::Session::encrypt_and_export`/`decrypt_and_export` per frame; the returned ciphertext
*is* the frame, sent as one transport message over the stream's own data channel — SCTP already frames
messages, so there is no separate length prefix on the wire. (An earlier draft of this section
specified `frame = uint32-le length ‖ AEAD_stream_key(seq_nonce, cbor_body)` with a stream key derived
once at `OPEN`; that shape never shipped and is superseded by the one below.)

Each call also derives a one-way HKDF export of the one message key (`mk`) it just consumed:

```
export = HKDF(mk, info),  info = "mrd/stream/" ‖ type (UTF-8 bytes) ‖ sid (u64, 8 bytes big-endian)
```

`type`/`sid` are the stream's own registry name and id — both peers already know them for any stream
they have open, so `info` needs no negotiation of its own. **No stream type consumes this export
today**: the current implementation computes it on both ends of every frame and immediately zeroizes
it, since no downstream symmetric-key consumer exists yet (a plausible future one: a high-rate media
stream type wanting to avoid a full ratchet step per packet). `mrd.file/1` (below) does **not** use
this export either — it seals its per-chunk data under its own independently-generated key (`k_f`,
itself carried ratchet-sealed as ordinary manifest content) layered *inside* the already
ratchet-sealed frame, never derived from this export.

`mrd.chat/1` is unaffected by any of this: it keeps carrying the existing signed `MessageEnvelope`
bytes over its own data channel (`ChatState::send_chat`/`send_chat_content`), never routed through
`send_stream_frame` or this per-frame export path.

## Built-in and roadmap stream types

| Type | Channel config | Notes |
|------|----------------|-------|
| `mrd.ctrl/1` | reliable, ordered | channel 0; not a registered type |
| `mrd.chat/1` | reliable, ordered | Tier-1 baseline (mandatory); auto-accept (T03/T04) |
| `mrd.file/1` | reliable, unordered | manifest on ctrl; 64 KiB chunks; merkle resume (T09) — [full spec](#mrdfile1--worked-example-t09) |
| `mrd.call.audio/1`, `.video/1` | RTP transceivers | Opus / VP9-or-AV1; DTLS-SRTP (T10) |
| `mrd.location/1`, sticker types | unreliable, unordered | live-position / ephemeral (T15) |
| `mrd.tunnel.tcp/1`, `mrd.fs/1` | reliable, ordered | Tier-2 tunnels; policy-gated (T16) |

Each is *only* a `StreamType` implementation plus a `register_stream_type` call. If adding one
requires editing a core crate, the extension contract has been broken — fix the contract, not the
core.

## `mrd.file/1` — worked example (T09)

The rest of this doc describes the extension contract in the abstract; this section is a full,
concrete example of a real stream type built entirely against it — `mrd.file/1`, resumable
integrity-verified P2P file transfer (`docs/architecture/features/09-file-transfer.md`). It is written
to be implementable from this section alone, without reading `meridian-streams`'s source, and doubles
as the model for the third-party `mrd.echo/1` reference check that feature's acceptance criteria call
for.

Implemented entirely in the downstream `meridian-streams` crate (`apps/streams`), depending only on
`meridian-core`'s public surface — zero diffs to `meridian-core`, `meridian-crypto`, or
`meridian-transport`.

### Registration

| | |
|---|---|
| `name()` | `"mrd.file/1"` |
| `version()` | `1` |
| `channel_cfg()` | `ChannelCfg { reliable: true, ordered: false, max_retransmits: None, .. }` |
| `direction()` | `Bidir` |
| `mandatory()` | `false` (trait default) — a peer without this type simply can't receive files; opening it against one yields `Reject{code:"unsupported"}` at capability exchange, never a session error |

The `label` a `StreamType::channel_cfg()` sets is not what ends up on the wire: the substrate
(`apps/core/src/session.rs`) overwrites it with `"{type}#{sid}"` before opening the actual data
channel, so two opens of the same type in one session never collide on a label. Implementers don't
need to set a meaningful `label` themselves.

### `on_open` policy

Decode `params` as the manifest below (see "Manifest"); a manifest that fails to decode is rejected
outright (`Reject{code:"invalid", reason:"malformed mrd.file/1 manifest"}`) — never partially decoded,
never panics.

Given a decoded manifest and `PolicyCtx`:
1. **First contact always loses**, checked before anything else: if `PolicyCtx::first_contact` is
   `true`, reject unconditionally (`Reject{code:"first-contact", ...}`), regardless of file type or
   size. A stranger can never auto-accept a file transfer.
2. Otherwise, if the sender-supplied `name` has a common image extension (`.jpg`/`.jpeg`/`.png`/`.gif`/
   `.webp`/`.bmp`/`.heic`/`.heif`/`.avif`/`.tiff`/`.tif`, case-insensitive) **and** `size` is at or
   below a configurable auto-accept threshold, accept automatically. This implementation's own default
   threshold is 5 MiB — a local UX knob (`TODO: confirm`, the feature spec names no default), never a
   wire-relevant value; nothing about the threshold is on the wire, only the sender's own `size` field
   is. Extension-sniffing `name` is a UX heuristic only, never a security boundary — a hostile sender
   who names a non-image file `photo.jpg` can reach this branch but the bytes must still pass merkle
   verification before anything is written.
3. Otherwise, consult an application-supplied policy hook (a prompt, an allowlist, whatever the host
   application wants) — accept or reject per its answer.

### Manifest (sent as `Open.params`)

Deterministic CBOR, a 4-field map:

```
FileManifest = {
  name : tstr,           ; sender-supplied display name — never used as a filesystem path without
                          ; sanitization on the receiving side; this is display-only, not trusted input
  size : uint,            ; the file's exact length in bytes
  root : bstr .size 32,   ; BLAKE3 merkle root over the file's chunks (see "Merkle construction"),
                          ; MUST encode as a CBOR byte string (major type 2), never an array of ints
  key  : bstr,            ; the per-file symmetric key k_f, sealed under the sender's ratchet session
                          ; with the recipient (opaque ciphertext to this schema — see below)
}
```

`key`'s plaintext, once ratchet-unsealed by the recipient, is exactly `k_f`: a fresh, independently
CSPRNG-random 32-byte key, generated anew for **every** file (never reused — see "Per-chunk AEAD" for
why reuse is catastrophic). It is sealed via the sender's *existing* ratchet-encrypted content-sealing
path — the same mechanism used for any other structured payload sent over an established session — not
a new crypto mechanism and not derived from the per-frame stream export described above. `k_f` itself
never appears anywhere in cleartext outside the two endpoints' memory.

### Merkle construction (pinned — byte-for-byte, cross-implementation critical)

- **Chunking.** The file is split into consecutive 64 KiB (`65536`-byte) chunks in file order; only the
  final chunk may be shorter (the file's length modulo 65536, or a full 65536-byte chunk if the length
  is an exact multiple). Chunks are never padded.
- **Leaf hash.** `leaf_i = BLAKE3(0x00 ‖ chunk_i)` — a single `0x00` domain-separation byte, then the
  raw chunk bytes, no length prefix. One leaf per chunk, in file order.
- **Internal node hash.** `node = BLAKE3(0x01 ‖ left ‖ right)` — a single `0x01` domain-separation
  byte, then the 32-byte `left` child hash, then the 32-byte `right` child hash (65 input bytes total),
  no length prefix. The `0x00`/`0x01` domain separation between leaves and internal nodes is load-
  bearing: without it, two hash values any legitimate proof holder can learn (their own running hash
  and the proof's final sibling) could be concatenated into a forged 64-byte one-chunk "file" whose
  root collides with a real multi-chunk file's root (the classic Merkle-tree type-confusion bug, the
  same class RFC 6962 §2.1 closes).
- **Tree shape: bottom-up pairwise fold, odd node promoted (never duplicated).** Starting from the leaf
  level, each subsequent level pairs adjacent nodes left-to-right — `(level[0], level[1]), (level[2],
  level[3]), …` — hashing each pair into one parent node in the same relative order. If a level has an
  odd number of nodes, the final unpaired node is carried forward **unchanged** (never re-hashed, never
  paired with a copy of itself) to become a node of the next level. Repeat until exactly one node
  remains: the root. A one-chunk file's root is exactly that chunk's own leaf hash (no internal node is
  ever computed). This is a plain level-by-level fold — **not** RFC 6962 / Certificate Transparency's
  largest-power-of-two-split construction — with the one deliberate exception of odd-node promotion,
  chosen specifically to avoid the classic Merkle "duplicate the last leaf" second-preimage weakness.
- **Empty file.** A zero-byte file is treated as exactly one virtual leaf, `BLAKE3(0x00)` (the leaf hash
  of an empty chunk — note this still applies the `0x00` domain-separation prefix, so it is
  `BLAKE3(0x00)`, not bare `BLAKE3(b"")`). Its root equals that single leaf hash.
- **Proofs.** An inclusion proof for leaf `k` is the sequence of steps from that leaf toward the root,
  one per tree level: at each level, either `Sibling{hash, side}` (combine the running hash with
  `hash` on the given `Left`/`Right` side via the internal-node formula above) or `Promoted` (this
  level's node had no sibling and was carried through unchanged — the running hash passes through
  untouched). A proof also carries `leaf_index` and `leaf_count`.
- **Verification.** Recompute the running hash from the candidate chunk's own bytes
  (`leaf_hash(chunk)`) by folding in each proof step in order, then compare the result to the expected
  root. Verification also cross-checks `leaf_index` against the Left/Right/Promoted pattern of the
  proof's own steps — each step's expected side is exactly `leaf_index`'s bit at that level, read
  least-significant-bit first — **and** rejects if any high-order bits of `leaf_index` remain
  unconsumed after walking every step (i.e. it also rejects `leaf_index >= leaf_count`, and any
  aliasing of `leaf_index` by a multiple of `2^(number of steps)`). Skipping either check lets a party
  relabel a valid proof to falsely claim a different chunk offset in the file.

### Per-chunk AEAD (pinned)

- **Algorithm:** XChaCha20-Poly1305.
- **Key:** `k_f`, the manifest's unsealed 32-byte per-file key, used directly — no further KDF.
- **Nonce (24 bytes):** the chunk index `i` (`u64`) as 8 bytes little-endian, followed by 16 zero
  bytes — `LE64(i) ‖ 0x00×16`. Every chunk of one file therefore gets a distinct, deterministic nonce
  with nothing to carry on the wire beyond `i` itself (already present in the chunk body — see below).
- **AAD:** none. The chunk index is bound implicitly via the nonce: substituting chunk `j`'s ciphertext
  for chunk `i` changes the nonce a correct `open(k_f, i, …)` call derives, so the AEAD tag fails to
  verify unless the ciphertext was genuinely sealed for that exact index.
- **Ciphertext layout:** the raw AEAD output (ciphertext ‖ 16-byte Poly1305 tag), no nonce prepended —
  the nonce is fully determined by `i`, which already rides alongside `data` in the chunk body.
- **Critical invariant:** `k_f` must never be reused across two different files. Nonce uniqueness
  within one file's own chunk stream holds by construction (each file's chunks are indexed `0, 1, 2, …`
  exactly once), but reusing the same `k_f` for a second file would seal chunk `i` of both files under
  the identical `(key, nonce)` pair — a catastrophic AEAD failure (keystream reuse, enabling plaintext
  recovery and forgery). This has no in-band detection; it is a hard contract on whoever generates and
  seals `k_f` (mint a fresh, independently random `k_f` per file, always).

### Wire chunk body and in-stream framing

The chunk body, CBOR: `ChunkFrame = {i: uint, data: bstr}` — `data` MUST encode as a CBOR byte string
(major type 2), never an array of small integers, and is exactly the AEAD output above for chunk `i`.
This rides *inside* the per-frame ratchet seal described in "Stream framing" above — two AEAD layers
in total: the outer, generic per-frame ratchet seal every stream frame gets, and this inner,
`mrd.file/1`-specific per-chunk seal under `k_f`.

Since a resume message (below) can also arrive on this same already-open channel, every in-stream
`mrd.file/1` frame (after the outer ratchet layer is removed) is actually:

```
tag: u8 ‖ body: bytes
```

- `tag = 0x00` — `body` is a `ChunkFrame` CBOR encoding, unchanged from the shape above.
- `tag = 0x01` — `body` is a `ResumeRequest` CBOR encoding (below).
- Any other `tag` byte, or an empty frame (no tag byte at all), is not a valid `mrd.file/1` in-stream
  frame and MUST be dropped silently — never panic on a malformed frame from an already-accepted
  stream.

**Known gap — the chosen mechanism for how a chunk's merkle proof reaches the receiver is decided but
not yet wired into the real send path.** The wire chunk body above is exactly `{i, data}` — no proof
field. The reference receiver implementation's own per-chunk verification step (`FileReceiver::
receive_frame`) requires a `MerkleProof` for `i` as a value the caller must already have on hand, and
nothing in this tree supplies one today — the real `meridian send` CLI path (`apps/cli/src/send.rs`)
does not call `FileReceiver` at all; instead it buffers every chunk (each already individually
AEAD-authenticated via `open_chunk`) and, once the whole file has arrived, does a single whole-file
merkle-root recomputation against the manifest's `root`. A corrupted-but-authenticated chunk therefore
fails the *entire* transfer today, not just that chunk (review finding F8,
[11.8's decision record](../tasks/phase-11/11.8-chunk-proof-delivery-mechanism.md#risks--notes)).

Of the two candidate directions previously on record here, an architect consult (task 11.8) **decided
against both as literally written**: a per-chunk proof extension to `ChunkFrame`'s wire shape would
amend an already conformance-vector-pinned shape and is wire-inefficient (redundant shared internal-node
hashes summed across every chunk); folding a proof set/leaf-hash list into `mrd.ctrl/1` or the
`FileManifest` would either also amend a pinned shape or repeat the exact `CtrlFrame`-core-crate-leakage
mistake task 10.9's own review already rejected once for the resume bitmap (see "Resume, in-stream"
below, and `wire-protocol.md` §5's own correction). The **chosen mechanism** instead reuses the same additive, in-stream frame-tag
multiplexing task 10.9 already shipped for the resume bitmap: a new frame kind (`FRAME_TAG_LEAF_HASHES`)
carrying a flat, paginated list of the file's leaf hashes, sent once per transfer before any chunk
frame, verified once against `manifest.root`, after which each chunk needs only a cheap
`leaf_hash(plaintext) == received_list[i]` comparison — no per-chunk proof machinery, and the existing
resume-bitmap mechanism becomes the actual re-request path once this lands. This is additive (touches
neither `ChunkFrame`'s nor `FileManifest`'s pinned CBOR, no `CtrlFrame`/core-crate change) so it needed
no ADR. **Not yet implemented** — the real wiring (pagination under the SCTP max-message-size ceiling, a
new `MerkleTree::from_leaf_hashes` constructor, and a `FileReceiver::receive_frame` API change to consume
an installed leaf-hash list instead of a per-call proof) is tracked as an unowned carry-forward for a
future build phase, not a small fix; see the master tracker's carry-forward list. A toy `mrd.echo/1`
implementation is unaffected, since it has no merkle layer at all.

### Resume, in-stream (not a `mrd.ctrl/1` frame)

After a session drop and redial (`P2pSession::ice_restart`; ratchets and stream-level state outlive the
transport), the receiver tells the sender which chunks are still missing so the sender resumes rather
than re-sending the whole file. This rides **in-stream**, over `mrd.file/1`'s own already-open data
channel (`tag = 0x01` above) — deliberately **not** a new `mrd.ctrl/1` control-frame variant, since that
would force `CtrlFrame` and `session.rs::handle_ctrl`'s exhaustive match to grow a file-transfer-
specific arm, which is exactly the core-crate leakage the stream-type extension contract exists to
reject. (An earlier revision of `wire-protocol.md` §5 documented a `Resume` ctrl-frame shape; that was
never implemented and, per this settled design, never will be — see that section's own correction.)

`ResumeRequest = {bitmap: bstr}` — `bitmap` MUST encode as a CBOR byte string, and there is no `sid`
field: since this rides in-stream over the specific transfer's own channel, the receiving side already
knows which transfer a frame belongs to from the channel it arrived on.

`bitmap`'s exact encoding: `ceil(leaf_count / 8)` bytes, one bit per chunk index, **LSB-first within
each byte** — bit `(i % 8)` of byte `(i / 8)` is `1` if chunk `i` is still missing (not yet received
*and* verified — both the AEAD-open and merkle-verify checks passed) and `0` if it has already been
received and verified. Any bits at or beyond `leaf_count` in the final byte are `0` and MUST be
ignored by the reader: a bitmap with garbage or truncated trailing bits is read as "nothing further is
missing," never as an instruction to address a chunk index that doesn't exist in this file — a reader
must never derive an index `>= leaf_count` from a bitmap, however malformed.

Sender behavior on receiving a `ResumeRequest`: resend exactly the chunk indices the bitmap marks
missing (reusing the same per-chunk send primitive as the initial transfer), never a parallel send
path, and never anything already marked received.

Receiver behavior: send the current missing-range bitmap once the stream is confirmed live again after
a redial. **No automatic trigger exists for this today** — `ice_restart()` renegotiates ICE only; it
emits no session event and calls into no stream-type hook that could fire this automatically. An
application-level session-lifecycle layer must call the send-bitmap primitive itself, explicitly, right
after its own `ice_restart()` call returns. (Tracked as an open carry-forward — see
[docs/tasks/README.md](../tasks/README.md#live-carry-forwards-not-owned-by-any-open-task).)

### Backpressure (watermarks)

Sending is throttled against the transport's own outbound buffer depth (`buffered_amount` for the
stream's data channel), with hysteresis rather than a single threshold:

- **High watermark: 4 MiB (64 chunks).** Pause sending once the buffered amount exceeds this. Large
  enough to smooth ordinary network/RTT jitter with no per-chunk acknowledgment (this substrate has
  none — buffered amount is the only backpressure signal available), small enough to cap how much
  unacknowledged ciphertext one stalled transfer (or several concurrent ones) can pile up if the peer
  or its network briefly stalls.
- **Low watermark: 1 MiB (16 chunks, a quarter of the high watermark).** Once paused, resume only once
  the backlog has drained to at or below this. Deliberately *not* equal to the high watermark: a
  single-threshold policy would pause and immediately resume every time the buffered amount drifted a
  few bytes either side of one line (queue depth isn't perfectly monotonic under concurrent drains),
  thrashing the send loop. A quarter-of-high low watermark gives a real hysteresis gap while still
  resuming promptly, without waiting for the queue to empty completely (which would idle the link).
- **Poll interval while paused: 5 ms.** Frequent enough to feel instantaneous once capacity frees up,
  without busy-spinning the executor.

These specific byte thresholds are `TODO: confirm` against a real soak-test throughput report (a later
phase task); nothing about them is wire-relevant — a receiver can't observe a sender's watermark
choices at all, so any implementation is free to pick its own without breaking interoperability.

A multi-file batch is sent **sequentially**: file `N+1`'s first chunk is only sent after file `N`'s
last chunk has been handed to the transport (not necessarily peer-acknowledged — this substrate has no
application-level ack). Interleaving multiple files' chunks on one connection is not done — it would
need its own per-file fairness/priority policy this design does not define.

### Follow-up: reshare/dedup (tracked, not built)

The per-file-key design permits reusing identical sealed ciphertext for a second authorized peer
without re-encrypting (`docs/architecture/system-design.md` §7.2) — explicitly out of scope for what
this crate builds today, per the feature spec's own out-of-scope note
(`docs/architecture/features/09-file-transfer.md`). See system-design.md §7.2 for the full status and
the tracked carry-forward.
