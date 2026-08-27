<!-- Source: DOC-01-wire-protocol-v1. Canonical wire-format spec. -->
> **Nav:** [docs index](../INDEX.md) · [api reference](./README.md) · [core API contracts](./core-api-contracts.md) · [data model](../architecture/data-model.md)

# Wire Protocol Specification — v1 (draft)

Normative companion to `p2p-comms-design.md` §3–§5 and diagrams D03/D07/D12. All structures are **CBOR** (RFC 8949, deterministic encoding). Every versioned object carries a leading `v` field; unknown *optional* fields are ignored, unknown *mandatory* capability names are rejected at capability exchange.

## 1. Identity string (frozen in T01)

```
mrd1:<base32-nopad( multicodec(0xED, ed25519-pub) ‖ pubkey[32] ‖ crc32c[4] )>@<hint-domain>
```
Canonical form: lowercase base32, punycode-normalized hint, no trailing dot. Parsers MUST reject: bad checksum, non-canonical case, hint containing `/` or whitespace. Two IDs are the *same principal* iff key parts match, regardless of hint.

The multicodec prefix is `ed25519-pub` (`0xed`) as an unsigned-varint (`0xED 0x01`); the checksum is
CRC32C (Castagnoli) big-endian over `multicodec ‖ pubkey`. Full field layout, canonical hint rules
(ASCII/LDH, homoglyph rejection), and the ordered list of parse rejections are specified in
**[identity-format.md](./identity-format.md)** — the authority for this section.

## 2. Client ↔ Rendezvous (WSS)

Auth handshake: server → `challenge{v, nonce[32], server_time}`; client → `auth{v, account_pub, sig = Ed25519(nonce ‖ server_domain)}`. Domain inclusion prevents cross-server challenge replay. Then CBOR frames, each `{op, id, body}` with `id` echoed in replies. The concrete T02 framing, error codes, config, and metrics are specified in **[rendezvous-protocol-v1.md](./rendezvous-protocol-v1.md)** — the authority for this section.

| op | body | notes |
|---|---|---|
| `publish_bundle` | `{v, spk, spk_sig, otks[], otk_sigs[], device_record}` | all sigs under account key |
| `fetch_bundle` | `{target: pubkey, hint?}` | exact full key only — no prefix ops exist; `hint` is an optional plain domain string, present when `target` may be a foreign account (T06, [2.3](../tasks/phase-2/2.3-c2s-federation-extension.md)) |
| `route` | `{to: pubkey, to_hint?, blob: bstr}` | blob is opaque; server code path has no serde on it (lint-enforced); `to_hint` is `fetch_bundle.hint`'s counterpart for routing (T06); reply is `route_ok` (below) or an `err` (`not_connected`, `mailbox_full` — T07) |
| `route_ok` | `{delivered: bool, queued?: bool}` | reply to `route`; `delivered:true` = pushed to a live connection (`queued` omitted, byte-identical to pre-T07 traffic); `{delivered:false, queued:true}` = accepted into the recipient's offline mailbox instead (T07, [8.3](../tasks/phase-8/8.3-wire-proto-mailbox-fields.md)) — an offline recipient with no mailbox available (`ttl_days == 0`) or over quota is never a `route_ok`, it's an `err` |
| `deliver` | `{from, blob: bstr, mailbox_id?: uint}` | push to client; `from` is the sender key the envelope claims — for a federated route it is the foreign server's assertion relayed verbatim (ADR 0017), not a new field; `mailbox_id` is present only when this push drains a row from the recipient's offline mailbox (T07) — it is the mailbox's own server-assigned row id, **never** the opaque `eid` inside `blob` (data-model.md's mailbox table note, task 7.6) — absent for a live route, so existing traffic is byte-identical |
| `mailbox_ack` | `MailboxAck{ids: [uint]}` → `MailboxAckOk{}` | client → server: acknowledge one or more mailbox-drain `deliver` pushes so the server deletes the corresponding rows, keyed by `ids` echoed from `deliver.mailbox_id` (never `eid`); server deletes only rows owned by the authenticated connection's own account. Supersedes the earlier `{envelope_ids[]}` placeholder, which predated the mailbox's actual server-assigned-`id` PK shape (task 7.6) and collided with `MessageEnvelope::eid`'s name (T07, [8.3](../tasks/phase-8/8.3-wire-proto-mailbox-fields.md)) |
| `turn_cred` | `{}` → `{urls[], username, credential, ttl}` | ephemeral HMAC per session |

**T07 mailbox error code.** `mailbox_full` (c2s `error_codes` and, on the federation side, s2s
`fed_error_codes`) — a `route`/`fed_route` named a recipient who is offline and whose mailbox is
already at its size/count quota; the sender gets a synchronous error instead of the envelope being
silently dropped or accepted past the cap. Distinct from `not_connected`, which means no mailbox is
available at all (`ttl_days == 0`). [8.3](../tasks/phase-8/8.3-wire-proto-mailbox-fields.md) adds
the wire types only — the route-handler behaviour that emits `route_ok{queued}`/`mailbox_full`/
`deliver{mailbox_id}` lands in 8.5–8.7.

## 3. Envelope (the only thing servers ever route)

**As implemented — envelope v2** (canonical: [messaging-envelope-v1.md §4](./messaging-envelope-v1.md),
type in [`apps/envelope`](../../apps/envelope)). [ADR 0016](../adr/0016-envelope-deniability.md) shipped
this cutover: no per-message signature; authentication comes entirely from the ratchet AEAD.

```
MessageEnvelope = {
  v          : u16,          ; mandatory, always 2 — sender-declared, never negotiated; any other
                              ; value (or its absence) is a hard local reject (ADR 0016 C5/R5)
  sender_pub : bstr[32],     ; Ed25519 sender account key (inside). No longer signed over.
  eid        : bstr[16],     ; sender-random 128-bit dedup key, minted fresh per envelope
                              ; (task 6.4, ADR 0016 C7)
  prekey     : Prekey?,      ; present only on opening message(s)
  ct         : bstr,         ; ratchet ciphertext, ENCRYPTED HEADERS — AEAD-authenticated
}
```

The v2 message AEAD's associated data is the canonical C3 formula:
`aad = "mrd.env/2" ‖ AD ‖ prekey_preamble ‖ enc_header`, where `AD = IK_initiator ‖ IK_responder` (the
raw Ed25519 encodings, never normalized to Montgomery form) is baked into the ratchet session's fixed
`ad` field once at construction, and `prekey_preamble` is the presence-flagged encoding of `Prekey`
from the envelope actually received (never a locally recomputed value — see
[messaging-envelope-v1.md §3](./messaging-envelope-v1.md)).

Recipients check `v == 2` (hard reject on any other value, never a downgrade), cross-check
`sender_pub` against the routing `from`, and authenticate+decrypt `ct` via the ratchet AEAD — there is
no separate signature-verify step. `ct` plaintext (post-ratchet) is a `Content` union: `x3dh_init`,
`sdp_offer{sdp, dtls_fp, ice[]}`, `sdp_answer{…}`, `ice_trickle{…}`, `chat{…}`,
`ring{stream_type, params}`, `receipt{…}`.

> **Two former known deviations from §1's rules — now closed:**
> 1. **Leading `v` field.** The now-superseded v1 envelope had none — its version existed only as the
>    `mrd.env/1` domain tag inside a signing input that no longer exists. v2 carries the mandatory
>    `v: 2` field §1 requires.
> 2. **`eid`.** v1 specified but never implemented an envelope-level dedup/replay key. v2 carries one
>    (task 6.4, ADR 0016 C7), minted fresh per `ChatState::seal_bytes` call.
>
> (An earlier revision of this section specified a *different, since-corrected* envelope — see
> [ADR 0016](../adr/0016-envelope-deniability.md)'s Consequences for the record.)

Sealed-sender wrapping (hiding `sender_pub` from the recipient's server) remains a Phase-3 layer on
this format; [ADR 0016](../adr/0016-envelope-deniability.md)'s removal of the outer plaintext signature
was its prerequisite, now shipped. **Deniability:** dropping the per-message signature makes authorship
no longer third-party-provable — weak, Signal-grade, single-hop, authorship-only (ADR 0016 residual
R4); it does not cover participation (bundle/auth/device signatures) or the federated case, which is
one hop further (ADR 0017).

**Invariant (test-enforced):** the same Envelope bytes are valid whether carried over WSS routing, the mailbox, s2s federation, or a data channel — transport-independence per design §4.3.

## 4. Server ↔ Server (federation, mTLS)

After the mTLS handshake (peer identity established per [ADR 0017](../adr/0017-federation-trust-boundary.md)),
each side exchanges `fed_hello{v, domain}` once, then `fed_fetch_bundle{target, requesting_server}`
↔ `fed_bundle{bundle}`, `fed_route{to, from, envelope}` (fire-and-forget on success), and
`fed_reachability{target}` → `fed_reachable{connected: bool}` (per-request only — no presence
subscriptions cross-org). Rate limits keyed by (origin server, origin account) — origin server is
the mTLS peer identity, origin account is the `from` the sending server asserts (ADR 0017 C5).
`fed_route`'s `from: bstr[32]` is routing metadata asserted by the sending server, carried
alongside — never decoded from — the opaque `envelope` (ADR 0017 C1/C2). An optional
`contact_token{issuer_sig, audience, exp}` field on first-contact routes, gated by the target
org's policy, is **documented but not implemented** — reserved for T08/T14. The concrete T06 s2s
framing, ops, and error codes are specified in
**[federation-protocol-v1.md](./federation-protocol-v1.md)** — the authority for this section.

## 5. mrd.ctrl/1 (channel 0)

```
Hello    = {v, streams: [{name, ver, dir, mandatory: bool}], transports: ["webrtc"], limits}
Open     = {sid: uint, type: tstr, params: map, chan: {reliable: bool, ordered: bool,
            max_rtx: ?uint} / "rtp"}
Accept   = {sid} | Reject = {sid, code, reason}
Close    = {sid, status}
Keepalive= {t}                        ; also carries flow-control hints
Resume   = {sid, bitmap: bstr}        ; file/fs range resume
```
Unknown `type` in `Open` ⇒ `Reject{code: unsupported}` — never a session error. All ctrl frames are ratchet-sealed like any payload.

## 6. Stream framing

Data-channel payloads: `uint32-le length ‖ AEAD_stream_key(seq_nonce, cbor_body)`. Stream keys: `HKDF(ratchet_export, info = "mrd/stream/" ‖ type ‖ sid)` — one ratchet step at OPEN, then symmetric AEAD with monotonic nonces (FS at stream granularity, §5.3). `mrd.file/1` chunk body: `{i: uint, data: bstr}`, AEAD key = per-file `k_f`, nonce = `i`.

## 7. Versioning & PQ slot

Bundle `v:1` = classical X3DH. `v:2` reserved: adds `pq_kem_prekey (ML-KEM-768) + sig` → PQXDH-style hybrid KDF. Clients advertise max supported bundle version at registration; senders use the highest the recipient bundle offers — downgrade below a contact's previously-seen version triggers a trust-state warning (anti-rollback).
