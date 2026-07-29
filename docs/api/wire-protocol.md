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
| `route` | `{to: pubkey, to_hint?, blob: bstr}` | blob is opaque; server code path has no serde on it (lint-enforced); `to_hint` is `fetch_bundle.hint`'s counterpart for routing (T06) |
| `deliver` | `{from, blob: bstr}` | push to client; `from` is the sender key the envelope claims — for a federated route it is the foreign server's assertion relayed verbatim (ADR 0017), not a new field |
| `mailbox_ack` | `{envelope_ids[]}` | triggers deletion |
| `turn_cred` | `{}` → `{urls[], username, credential, ttl}` | ephemeral HMAC per session |

## 3. Envelope (the only thing servers ever route)

**As implemented** (canonical: [messaging-envelope-v1.md §4](./messaging-envelope-v1.md), type in
[`apps/envelope`](../../apps/envelope)):

```
MessageEnvelope = {
  sender_pub : bstr[32],    ; Ed25519 sender account key (inside, and signed)
  prekey     : Prekey?,     ; present only on opening message(s)
  ct         : bstr,        ; ratchet ciphertext, ENCRYPTED HEADERS
  sig        : bstr[64]     ; Ed25519(sender) over signing_input
}
signing_input = "mrd.env/1" ‖ sender_pub ‖ prekey_flag ‖ [ek_pub ‖ used_spk ‖ opk_flag ‖ used_opk?] ‖ ct
```

Recipients verify `sig` before touching `ct`, and check `sender_pub` against the routing `from`.
`ct` plaintext (post-ratchet) is a `Content` union: `x3dh_init`, `sdp_offer{sdp, dtls_fp, ice[]}`,
`sdp_answer{…}`, `ice_trickle{…}`, `chat{…}`, `ring{stream_type, params}`, `receipt{…}`.

> **Two known deviations from §1's rules, recorded rather than hidden** (both are
> [ADR 0016](../adr/0016-envelope-deniability.md) v2 obligations, not edits to make here):
> 1. **No leading `v` field.** This envelope's version exists only as the `mrd.env/1` domain tag
>    inside `signing_input`, which violates §1's "every versioned object carries a leading `v`".
>    v2 adds `v: 2`.
> 2. **No `eid`.** The dedup/replay key described in §1 is specified but not implemented, so v1 has
>    no envelope-level replay protection. v2 is the cheap moment to add it.
>
> An earlier revision of this section specified a *different* envelope (`v`/`eid`, and a signing
> input of `v ‖ eid ‖ payload` that omitted `sender_pub`). That contradicted both the canonical spec
> and the implementation, and its missing `sender_pub` was a key-substitution weakness in the spec
> itself. It is corrected above.

Sealed-sender wrapping (hiding `sender_pub` from the recipient's server) is a Phase-3 layer on this
format; [ADR 0016](../adr/0016-envelope-deniability.md)'s removal of the outer plaintext signature is
its prerequisite. **Deniability:** v1's identity-key signature makes authorship third-party-provable —
threat-model goal 4 is unmet until v2.

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
