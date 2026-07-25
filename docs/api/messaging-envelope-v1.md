<!-- Source: T03 (feature 03-e2ee-messaging-relayed). The wire-frozen E2EE messaging spec. -->
> **Nav:** [docs index](../INDEX.md) · [api reference](./README.md) · [wire protocol](./wire-protocol.md) · [rendezvous protocol](./rendezvous-protocol-v1.md) · [system design §4](../architecture/system-design.md) · [ADR 0003](../adr/0003-e2ee-protocol.md) · [ADR 0011](../adr/0011-ratchet-library.md)

# Messaging Envelope — v1

The versioned spec for Meridian's end-to-end-encrypted 1:1 messaging (T03): the X3DH handshake, the
header-encrypted Double Ratchet, the signed envelope the server relays, and the `mrd.chat/1`
payload. Implemented by [`meridian-crypto`](../../apps/crypto) (crypto) and
[`meridian-core::chat`](../../apps/core/src/chat.rs) (framing/session manager); the wire types live
in [`meridian-proto`](../../apps/proto).

The **key property** this proves: content security does not depend on the transport path
(system-design §4.3 point 2). The same signed, ratcheted envelope defined here rides the server
relay today (T03), a WebRTC data channel later (T04), and the offline mailbox later still (T07) —
**unchanged**. The server only ever sees an [`OpaqueBlob`](./rendezvous-protocol-v1.md).

> **Versioning.** Domain tags below carry `/v1`. Any change to the KDF labels, DH ordering, header
> layout, or signing input is a wire break requiring a new version and an ADR — not an edit here.
> **v2 is already decided** ([ADR 0016](../adr/0016-envelope-deniability.md)): it drops the
> per-message identity-key signature so that transcripts become deniable, moves the domain tag and
> prekey preamble into the ratchet AAD, and adds the leading `v` field this format currently lacks.
> Implementation is a separate build task; everything below describes v1 as shipped.
> Bundle `v:2` (PQXDH) folds an ML-KEM leg into X3DH per [wire-protocol §7](./wire-protocol.md#7-versioning--pq-slot).

## 1. Cryptographic building blocks

All from audited RustCrypto primitives — nothing hand-rolled ([ADR 0011](../adr/0011-ratchet-library.md);
see §7 for why the ratchet is composed in `meridian-crypto` rather than delegated to vodozemac):

| Purpose | Primitive |
|---|---|
| Identity signatures | Ed25519 (`ed25519-dalek`) |
| DH | X25519 (`x25519-dalek`) |
| KDF | HKDF-SHA256 (`hkdf` + `sha2`) |
| Chain KDF | HMAC-SHA256 (`hmac`) |
| AEAD (messages, headers, at-rest) | XChaCha20-Poly1305 (`chacha20poly1305`) |
| Safety number | iterated SHA-512 |

The account identity key is **Ed25519**. For the X3DH legs that DH against an identity key, the key
is converted to its birationally-equivalent X25519 (Montgomery) form — the private side inside the
[`SecretStore`](./core-api-contracts.md) (`SignOrDh::Dh`, libsodium `sk_to_curve25519`), the public
side via `VerifyingKey::to_montgomery`. The identity private key never leaves the keystore.

## 2. X3DH (session establishment)

Against a fetched, **signature-verified** prekey bundle (`v:1`: `IK` Ed25519, `SPK`/`OPK` X25519 —
see [rendezvous-protocol §bundle](./rendezvous-protocol-v1.md)). Bundle signatures MUST verify under
the exact requested key first; a mismatch is a hard abort, never a downgrade (§4.2, "must never" #5).

```
DH1 = DH(IK_A, SPK_B)
DH2 = DH(EK_A, IK_B)
DH3 = DH(EK_A, SPK_B)
DH4 = DH(EK_A, OPK_B)          # omitted if the bundle carried no one-time prekey
master = 0xFF*32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ DH4
root ‖ hk_ab ‖ hk_ba = HKDF-SHA256(salt = 0*32, ikm = master, info = "Meridian/X3DH/v1")   # 96 bytes
AD = IK_initiator ‖ IK_responder                                                            # 64 bytes
```

`EK_A` is the initiator's ephemeral X25519 key. `root` seeds the ratchet; `hk_ab`/`hk_ba` are the
initial header keys (one per direction); `AD` is bound into every message AEAD. The initiator
transmits the **prekey preamble** (`EK_A`, `used_spk`, `used_opk`) in the envelope until it receives
a reply, so a lost opening message cannot strand the session.

## 3. Double Ratchet with header encryption

Follows Signal's *Double Ratchet with header encryption* (spec §5). Meridian's one explicit choice
is the two X3DH-derived shared header keys, initialised as:

| | `HKs` | `HKr` | `NHKs` | `NHKr` |
|---|---|---|---|---|
| Initiator | `hk_ab` | — | *(derived)* | `hk_ba` |
| Responder | — | — | `hk_ba` | `hk_ab` |

The initiator's initial remote ratchet key is `SPK_B` (the responder's signed prekey). KDFs:

```
KDF_RK(rk, dh)  = HKDF-SHA256(salt = rk, ikm = dh, info = "Meridian/RatchetRoot/HE/v1")  → root' ‖ CK ‖ NHK   (96 B)
KDF_CK(ck)      = ( HMAC-SHA256(ck, 0x02),  HMAC-SHA256(ck, 0x01) )                        → (CK', MK)
message key     = HKDF-SHA256(salt = 0*32, ikm = MK, info = "Meridian/MsgKey/v1")          → key(32) ‖ nonce(24)
```

- **Header** (plaintext, 40 bytes): `ratchet_pub(32) ‖ PN:u32-be ‖ N:u32-be`. Encrypted under the
  current header key with a random 24-byte nonce (`nonce ‖ AEAD_ct`), so counters and ratchet public
  keys are never visible to a relay/store.
- **Message AEAD**: `XChaCha20Poly1305(key, nonce, plaintext, aad = AD ‖ enc_header)`.
- **Skipped keys**: retained keyed by `(header_key, N)`; bounded by `MAX_SKIP = 1000` per chain and
  `MAX_SKIPPED_STORED = 2000` overall (out-of-order / dropped-message delivery).
- **Desync recovery (v1 — no automatic teardown).** An `enc_header` that opens under neither `HKr` nor
  `NHKr` is rejected and the envelope dropped; **the receiving session is left untouched** — an
  undecryptable inbound message never resets, tears down, or re-keys a live session. Recovery is driven
  only by the peer that *knows* it lost state (restored backup, missing/corrupt session store): having
  no session for that peer, it fetches a fresh signature-verified bundle and re-initiates X3DH, which
  the counterpart accepts as an ordinary prekey message (§4 receiver rules). A peer whose own session is
  healthy requires **user/operator action** (deleting the session) to recover. Automatic
  detection-and-renegotiation on the *receiving* side is deliberately deferred: reacting to
  undecryptable traffic would hand an active attacker (threat-model A2) a session-reset,
  skipped-key-destruction, and prekey-depletion oracle, and it must not ship before verified-contact
  block-on-key-change ([Feature 08](../architecture/features/08-verification-trust.md), threat-model
  goal 2) guards the re-handshake's bundle fetch. Decision recorded in task 1.18.

### Ratchet message framing

```
len(enc_header):u16-be ‖ enc_header ‖ ciphertext
```

## 4. The envelope (what the server relays)

`Sign_IK{ ratchet_ct }` with the sender key inside (system-design §7.1 step 6). Deterministic CBOR,
carried verbatim as the routing [`OpaqueBlob`](./rendezvous-protocol-v1.md):

> **Deniability: v1 envelopes are NOT deniable.** This per-message identity-key signature makes
> authorship of every v1 message third-party-provable, so threat-model goal 4 is **unmet for v1**.
> [ADR 0016](../adr/0016-envelope-deniability.md) decides to drop the signature at **envelope v2**
> (the ratchet AEAD plus the X3DH `AD = IK_initiator ‖ IK_responder` binding already authenticate
> both identity keys). v2 is a wire break with binding preconditions — commit-on-successful-decrypt,
> a canonical AAD carrying the prekey preamble, a leading `v: 2`, and enforced signed-prekey
> rotation. Read that ADR before touching this section.
>
> Note also what the signature does **not** cover: `SignalContent` (SDP/ICE/`dtls_fp`) is ratchet
> *plaintext*, so the DTLS-fingerprint binding of §4.6 rests on the ratchet AEAD and X3DH, never on
> this signature. Code comments claiming otherwise are wrong.

```
MessageEnvelope {
  sender_pub : bytes(32),         # sender Ed25519 account key (inside, and signed)
  prekey     : Prekey?,           # present only on opening message(s)
  ct         : bytes,             # the ratchet message from §3
  sig        : bytes(64),         # Ed25519(sender) over signing_input
}
Prekey { ek_pub: bytes(32), used_spk: bytes(32), used_opk: bytes(32)? }

signing_input = "mrd.env/1" ‖ sender_pub ‖ prekey_flag ‖ [ek_pub ‖ used_spk ‖ opk_flag ‖ used_opk?] ‖ ct
```

**Receiver rules (in order):** (1) `sender_pub` MUST equal the routing `from`; (2) verify `sig`
under `sender_pub` **before** any decryption; (3) if no session and a `prekey` is present, run X3DH
as responder using the locally-held prekey secrets for `used_spk`/`used_opk` (one-time prekey
consumed); (4) ratchet-decrypt `ct`. Any failure drops the envelope — never a downgrade.

## 5. `mrd.chat/1` payload

The plaintext sealed by the ratchet (also the offline-mailbox format, T07). Deterministic CBOR:

```
ChatContent =
  | Text    { id: bytes(16), body: text }     # id is a random 128-bit message id
  | Receipt { ack: bytes(16) }                # acknowledges a Text by id
```

Typing/reactions are additive variants (no wire break). Attachments are `mrd.file/1` (T09).

## 6. At-rest session store

Ratchet state + published-prekey secrets are serialized (CBOR) and sealed with XChaCha20-Poly1305
under a key derived from the account key: the client signs `"Meridian/SessionStoreKey/v1"` through
the `SecretStore` (private key stays in the store) and HKDFs the signature into the store key. The
store is never written unsealed (system-design §4.7). *TODO: confirm* a dedicated `SecretStore`
key-derivation op (vs. reusing a deterministic signature) with the multi-device work (T13).

## 7. Safety number (verification backstop)

Order-independent 60-digit fingerprint of the two identity keys (system-design §4.4): per key,
iterated SHA-512 (`version ‖ key ‖ key`, 5200 iterations) → six 5-digit groups; the two per-key
fingerprints are concatenated in sorted key order so both peers derive the same number. T03 lands
the computation; T08 builds the compare/verify UX and freezes conformance vectors on it.

## 8. Note on the ratchet library ([ADR 0011](../adr/0011-ratchet-library.md))

ADR 0011 selected vodozemac for the Double Ratchet with a hand-wired X3DH. vodozemac 0.10's public
API constructs sessions only through Olm's own 3DH over Olm-managed keys — it cannot be seeded from
the externally-computed X3DH `root` this design requires, nor from the frozen `v:1` bundle, and it
exposes neither header encryption nor raw message keys. The ratchet is therefore composed here from
the same audited primitives the ADR already allocates to the X3DH layer (ADR 0011 "Option C" for the
ratchet specifically). This is recorded in the ADR's 2026-07 superseding note and is on the Phase-1
external crypto-review gate ([testing/strategy.md §7](../testing/strategy.md)).
