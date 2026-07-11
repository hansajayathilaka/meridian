<!-- Source: DOC-01-wire-protocol-v1. Canonical wire-format spec. -->
> **Nav:** [docs index](../INDEX.md) · [api reference](./README.md) · [core API contracts](./core-api-contracts.md) · [data model](../architecture/data-model.md)

# Wire Protocol Specification — v1 (draft)

Normative companion to `p2p-comms-design.md` §3–§5 and diagrams D03/D07/D12. All structures are **CBOR** (RFC 8949, deterministic encoding). Every versioned object carries a leading `v` field; unknown *optional* fields are ignored, unknown *mandatory* capability names are rejected at capability exchange.

## 1. Identity string (frozen in T01)

```
mrd1:<base32-nopad( multicodec(0xED, ed25519-pub) ‖ pubkey[32] ‖ crc32c[4] )>@<hint-domain>
```
Canonical form: lowercase base32, punycode-normalized hint, no trailing dot. Parsers MUST reject: bad checksum, non-canonical case, hint containing `/` or whitespace. Two IDs are the *same principal* iff key parts match, regardless of hint.

## 2. Client ↔ Rendezvous (WSS)

Auth handshake: server → `challenge{v, nonce[32], server_time}`; client → `auth{v, account_pub, sig = Ed25519(nonce ‖ server_domain)}`. Domain inclusion prevents cross-server challenge replay. Then CBOR frames, each `{op, id, body}` with `id` echoed in replies.

| op | body | notes |
|---|---|---|
| `publish_bundle` | `{v, spk, spk_sig, otks[], otk_sigs[], device_record}` | all sigs under account key |
| `fetch_bundle` | `{target: pubkey, hint}` | exact full key only — no prefix ops exist |
| `route` | `{to: pubkey, blob: bstr}` | blob is opaque; server code path has no serde on it (lint-enforced) |
| `deliver` | `{from_server, blob: bstr}` | push to client |
| `mailbox_ack` | `{envelope_ids[]}` | triggers deletion |
| `turn_cred` | `{}` → `{urls[], username, credential, ttl}` | ephemeral HMAC per session |

## 3. Envelope (the only thing servers ever route)

```
Envelope = {
  v: 1,
  eid: bstr[16],            ; random, dedup key
  sender_pub: bstr[32],     ; Ed25519
  payload: bstr,            ; ratchet ciphertext, ENCRYPTED HEADERS
  sig: bstr[64]             ; Ed25519(sender) over (v ‖ eid ‖ payload)
}
```
Recipients verify `sig` before touching `payload`. Sealed-sender wrapping (hiding `sender_pub` from the recipient's server) is a Phase-3 layer on this format — `v` bump reserved. `payload` plaintext (post-ratchet) is a `Content` union: `x3dh_init`, `sdp_offer{sdp, dtls_fp, ice[]}`, `sdp_answer{…}`, `ice_trickle{…}`, `chat{…}`, `ring{stream_type, params}`, `receipt{…}`.

**Invariant (test-enforced):** the same Envelope bytes are valid whether carried over WSS routing, the mailbox, s2s federation, or a data channel — transport-independence per design §4.3.

## 4. Server ↔ Server (federation, mTLS)

`fed_fetch_bundle{target, requesting_server}`, `fed_route{to, envelope}`, `fed_reachability{target}` → `{connected: bool}` (per-request only — no presence subscriptions cross-org). Rate limits keyed by (origin server, origin account). Optional `contact_token{issuer_sig, audience, exp}` field on first-contact routes when the target org's policy requires it.

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
