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

> **Versioning.** The X3DH/ratchet KDF domain tags below (`Meridian/X3DH/v1`,
> `Meridian/RatchetRoot/HE/v1`, `Meridian/MsgKey/v1` — §1–§3) are unchanged by envelope versioning;
> any change to the KDF labels, DH ordering, or header layout is a separate wire break requiring a new
> version and an ADR, not an edit here. **The envelope itself is now v2, shipped**
> ([ADR 0016](../adr/0016-envelope-deniability.md)): it drops the per-message identity-key signature
> (transcripts are deniable — see §4), moves the domain tag (`mrd.env/2`) and the X3DH preamble into
> the ratchet AAD, and carries a mandatory leading `v: 2` field. §4 below describes the shipped v2
> envelope shape. This file keeps its `v1` name for link/history stability — it predates ADR 0016 —
> but is not describing a still-live v1 wire format: v1 and v2 do not interoperate and there is no
> negotiation (ADR 0016 R5, a hard flag day); v1 no longer ships.
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
initial header keys (one per direction); `AD` is bound into every message AEAD via the ratchet's fixed
AAD prefix `"mrd.env/2" ‖ AD`, baked in once at session construction (ADR 0016 C3; see §3). The
initiator transmits the **prekey preamble** (`EK_A`, `used_spk`, `used_opk`) in the envelope until it
receives a reply, so a lost opening message cannot strand the session.

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
- **Message AEAD**: `XChaCha20Poly1305(key, nonce, plaintext, aad = "mrd.env/2" ‖ AD ‖ prekey_preamble ‖ enc_header)`
  (the canonical ADR 0016 C3 formula). The domain tag and `AD` are baked into the ratchet's fixed `ad`
  field once, at session construction; the per-message `prekey_preamble` (present only on the opening
  message(s) — the presence-flagged encoding of `Prekey` from §4) is threaded through per call. The
  decrypt side MUST use the preamble bytes actually received on the wire, never a value it locally
  recomputes, or preamble-mutation detection silently breaks (see `apps/crypto/src/ratchet.rs`'s
  module doc for the negative-test regression this guards).
- **Skipped keys**: retained keyed by `(header_key, N)`; bounded by `MAX_SKIP = 1000` per chain and
  `MAX_SKIPPED_STORED = 2000` overall (out-of-order / dropped-message delivery).
- **Desync recovery (v1).** An `enc_header` that opens under neither `HKr` nor `NHKr` is rejected and
  the envelope dropped; on its own, **the receiving session is left untouched** — an undecryptable
  inbound message never resets, tears down, or re-keys a live session by itself. Two paths recover
  from this, both landed, and both guarded:
  - **The "safe half" (task 1.18, freshness-gated since a 4.9 review fixup).** The peer that *knows*
    it lost state (restored backup, missing/corrupt session store) has no session for the
    counterpart, so it fetches a fresh signature-verified bundle and re-initiates X3DH. The
    counterpart accepts this as an ordinary prekey message (§4 receiver rules) — including, since
    task 4.9, when it still holds a **stale** session for that identity key rather than no session
    at all: `open_bytes` first tries the existing session as usual, and only on an
    `UndecryptableHeader` failure — and only if the envelope actually carries a fresh X3DH prekey
    preamble — attempts a fresh responder establishment from that preamble and re-tries the same
    ciphertext against it. Any failure along the way (e.g. the referenced one-time prekey was
    already consumed) leaves the stale session completely untouched and the envelope still
    classifies as desync, exactly as before.
    - **This case only — no existing session at all — is genuinely unconditional on freshness**,
      because there is no live session yet to roll back: `open_bytes`'s first-contact branch
      accepts a fresh, signature-verified prekey envelope immediately, replay or not.
    - **The stale-session fallback (the case above) is additionally gated on freshness, not just
      signature validity — this is the fix for a real, previously-shipped-in-review vulnerability.**
      A verified signature proves only that the claimed sender produced these bytes *at some point*,
      never that they are fresh. X3DH is deterministic in its public inputs, so a malicious
      relay/rendezvous server that has merely observed one of the sender's own past opening
      envelopes could replay it byte-for-byte once the receiver's ratchet had genuinely advanced
      past it (a couple of ordinary round-trips is enough), reconstructing the byte-identical
      initial session and decrypting the also-replayed ciphertext successfully — deterministically,
      every time, for OTK-free X3DH (`used_opk: None`, legal and common), since the signed prekey is
      never consumed on use. That would have silently rolled a live, forward-secret-advanced session
      back to its own initial state through the ordinary success path, with no gate and no notice —
      exactly the "weaker session" outcome `docs/security/threat-model.md` goal 6 rules out, and the
      same oracle class task 1.18's `attempt_recovery`/threshold/gate machinery exists to prevent,
      reintroduced through this different, ungated code path.
      **The fix (second-round — the first version of this fix was itself exploitable).** The first
      fixup had `ChatState` record only the single most-recently-established `ek_pub` per peer,
      *overwritten* on every new responder establishment. A further review round (architect +
      security-reviewer, independently) found that overwritable-scalar design itself exploitable
      within one ordinary session: an attacker who can force `DESYNC_RECOVERY_THRESHOLD` desyncs
      against the *peer's own* inbound path can drive that peer's guarded recovery to produce a
      second, entirely genuine responder establishment for the same identity — which silently
      displaces the recorded `ek_pub`, so a subsequent replay of the *original* opening envelope (its
      referenced signed prekey generation still unexpired — a signed prekey is never consumed on use,
      and a real client may not republish for the lifetime of a long-running session) no longer
      matched anything and was accepted again, exactly reconstructing that first session and rolling
      the live one back to it.
      **The corrected design:** `ChatState` records **every** `ek_pub` that established a responder
      session with a peer, each tagged with the specific signed-prekey generation it referenced, for
      as long as that generation remains accepted by the local prekey vault (the vault's current
      generation, or the single grace-window-retained previous one — task 1.31). Before the
      stale-session fallback attempts fresh establishment, it checks the incoming envelope's
      `prekey.ek_pub` against **every** still-generation-valid recorded entry for that peer, not just
      the most recent. A match against any of them means this is a replay of material that already
      established a session currently or previously held — the fallback is refused outright, exactly
      as if it did not exist, and the envelope classifies as an ordinary desync. A genuine
      re-initiator always draws a fresh random ephemeral key per X3DH initiation, so this never
      rejects a real re-initiation; a peer with no recorded `ek_pub` at all (never went through
      responder establishment — e.g. the current session was established as an *initiator*) has no
      freshness signal available, so the fallback behaves exactly as before either fixup for that
      case, relying on signature validity alone.
      **Pruning, and why it stays bounded.** An entry is dropped once its referenced generation is no
      longer accepted — pruned in the same call that retires the prekey vault's own superseded
      generation (`PrekeyVault::expire_previous_generation`, via `ChatState`'s own wrapper), so this
      history's growth is bounded by exactly the mechanism that already bounds that generation's own
      retention (at most one superseded generation, for at most `PREV_GENERATION_GRACE_SECS`), not a
      separate, disconnected accumulation. Within a single still-current generation, repeated
      attacker-forced re-establishment cycles can still add one entry each — bounded by the same
      `DESYNC_RECOVERY_THRESHOLD`-gated rate the recovery machinery is already rate-limited by (see
      the "dangerous half" residual below), not literally unbounded, but not capped by count either;
      a hard per-peer cap was judged unnecessary scope given that existing rate limit. Once an entry
      is pruned because its generation genuinely expired, a replay referencing it is not left
      unprotected: it instead fails inside the fallback's own fresh-establishment attempt
      (`UnknownPrekey`, since the vault no longer holds that generation's secret at all), which
      `open_bytes` already treats as an ordinary failed recovery attempt — the envelope still
      classifies as desync, the session still untouched.
      **Residual, stated honestly.** This closes the specific replay-of-verbatim-prekey-material
      attack, for as long as the referenced material's generation stays accepted at all — genuinely
      expired material is independently blocked by the ordinary unknown-prekey failure path, not by
      this freshness check. It does not, and is not intended to, protect against a peer whose *own*
      private key material has been compromised (an attacker who can compute a genuinely new, valid
      X3DH handshake is cryptographically indistinguishable from the real peer — no freshness check
      can or should catch that; that is a key-compromise scenario outside what any receiver-side
      replay check can address). It also does not change the "dangerous half" residual described
      below, which is a separate, already-stated trade-off.
  - **The "dangerous half" (task 4.9, following through on task 1.18's deferred decision).** A peer
    whose *own* session looks healthy but whose inbound decryption keeps failing (an active
    attacker replaying/corrupting traffic — threat-model A2 — or the counterpart having genuinely
    lost its state) MAY now recover automatically, but only under a specific, multi-part guard:
    1. **Repeated, never single.** A per-peer counter tracks *consecutive* desync classifications,
       reset on any successful decrypt from that peer; only once a threshold is crossed
       (`DESYNC_RECOVERY_THRESHOLD` in `apps/core/src/chat.rs`, `TODO: confirm` the exact number —
       currently 5) does recovery become eligible. A single replayed or corrupted envelope is never
       enough on its own to force anything.
    2. **Gated by the block/warn key-change gate ([Feature 08](../architecture/features/08-verification-trust.md),
       task 4.4).** Before fetching anything, the client consults the peer's `SendGate`
       (`TrustStore::can_send`); a peer currently `Warn`/`Blocked` from an unresolved key change is
       refused an automatic re-handshake — surfaced to the user as recovery being *paused* pending
       that existing resolution, never silently skipped or silently proceeded past.
    3. **A key change surfaced mid-recovery is an ordinary key-change event, never a bypass.** If
       the fetch ever reveals the peer's identity key genuinely changed, that is routed through
       `TrustStore::observe_key_change` (block on verified, warn on pinned) exactly like any other
       key-change discovery — never silently accepted "because a recovery flow is already in
       progress". In practice this branch is close to unreachable via the shipped client, since the
       bundle fetch is pinned to the exact expected key (`verify_bundle` aborts on any substitution
       before a bundle is even returned) — but the recovery function's own contract enforces it
       regardless, for any future fetch strategy that could resolve differently.
    4. **The forced session replacement is a separate, explicit surface**
       (`ChatState::replace_session_as_initiator`), never a side effect of the ordinary
       `start_initiator_session` path every other caller already uses (which stays
       idempotent-as-a-no-op when a session exists, for the normal "reopen a chat" case). Only a
       decided recovery attempt ever discards a session; the counter/threshold bookkeeping never
       touches `sessions` or skipped-message keys on its own.
    5. **User-visible notice.** An actual automatic recovery is never silent.
    - **Residual, stated honestly.** This rate-limits, but does not eliminate, the oracle 1.18
      identified: an attacker able to force `DESYNC_RECOVERY_THRESHOLD` desync classifications on
      demand can still trigger one recovery attempt (and, if the gate reads `Ok`, one one-time-prekey
      consumption) per that many forced failures — bounded, not zero.

  A peer whose own session is healthy and whose desync count never crosses the threshold still falls
  back to **user/operator action** (deleting the session) exactly as before this task.

### Ratchet message framing

```
len(enc_header):u16-be ‖ enc_header ‖ ciphertext
```

## 4. The envelope (what the server relays)

Envelope **v2** ([ADR 0016](../adr/0016-envelope-deniability.md)): no per-message signature —
authentication comes entirely from the ratchet AEAD over `ct` (§3), keyed by the X3DH-derived `AD`
baked into the session at construction. Deterministic CBOR, carried verbatim as the routing
[`OpaqueBlob`](./rendezvous-protocol-v1.md):

> **Deniability: v2 envelopes achieve weak, Signal-grade deniability of *authorship*, single-hop
> only** (ADR 0016 residual R4). Message authentication reduces to symmetric AEAD under keys the
> recipient also holds, so no ciphertext is third-party-verifiable as any particular sender's, and any
> transcript can be forged by the recipient. This does **not** cover *participation*: prekey-bundle
> signatures, the domain-bound rendezvous auth signature, and account-signed device records all remain
> identity-key signatures proving a key was live at a given server at a given time — nor does it
> defeat *server testimony* (the routing `from` is taken from the authenticated WebSocket session, so
> an operator can attest a blob arrived on a given account's connection). This is true single-hop; the
> federated case is one hop further and is **not** fully resolved by this ADR alone — see
> [ADR 0017](../adr/0017-federation-trust-boundary.md). There is no online/interactive deniability, and
> this is not OTR-/court-grade. (The now-superseded envelope v1 signed every ratchet ciphertext with
> the sender's identity key and had no deniability property at all.)
>
> Note also what authentication does **not** rest on: `SignalContent` (SDP/ICE/`dtls_fp`) is ratchet
> *plaintext*, so the DTLS-fingerprint binding of §4.6 rests on the ratchet AEAD and X3DH — this was
> already true under v1 and is unaffected by dropping the signature.

```
MessageEnvelope {
  v          : u16,               # mandatory, always 2 — sender-declared, never negotiated; any
                                   # other value (or its absence) is a hard local reject (ADR 0016
                                   # C5/R5), never a downgrade
  sender_pub : bytes(32),         # sender Ed25519 account key (inside). No longer signed over —
                                   # authenticated instead by the ratchet AEAD's AD
                                   # (X3DH IK_initiator ‖ IK_responder), which fails closed on a
                                   # substituted key
  eid        : bytes(16),         # sender-random 128-bit dedup key, minted fresh per
                                   # `ChatState::seal_bytes` call (task 6.4, ADR 0016 C7). Outer
                                   # plaintext, deliberately outside the AAD — a redelivery/duplicate-
                                   # processing convenience, not a security boundary
  prekey     : Prekey?,           # present only on opening message(s); bound into the AAD (§3) via
                                   # the bytes actually received, never a locally recomputed value
  ct         : bytes,             # the ratchet message from §3 — AEAD-authenticated, no separate
                                   # signature
}
Prekey { ek_pub: bytes(32), used_spk: bytes(32), used_opk: bytes(32)? }
```

**Receiver rules (in order):** (1) decode and check `v == 2` exactly — any other value is a hard
reject (`ChatError::UnsupportedEnvelopeVersion`), never a downgrade; (2) `sender_pub` MUST equal the
routing `from` (`ChatError::SenderMismatch`); (3) if no session and a `prekey` is present, run X3DH
**provisionally** as responder against the locally-held prekey secrets for `used_spk`/`used_opk` — the
one-time prekey is consumed, and the session installed, only *after* ratchet-decrypt actually succeeds
(commit-on-successful-decrypt, ADR 0016 C2); (4) ratchet-decrypt `ct` using the preamble bytes actually
received. Any failure drops the envelope — never a downgrade. Rule (1)'s clean, diagnosable
`ChatError::UnsupportedEnvelopeVersion` applies only to a structurally v2-shaped envelope carrying a
wrong `v` — a genuine v1-shaped blob (no `v`/`eid` fields at all) fails earlier still, at CBOR codec
decode (`ChatError::Codec`), a distinguishable but different diagnostic (task 7.1, ADR 0016 "Test
obligations" F2).

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
