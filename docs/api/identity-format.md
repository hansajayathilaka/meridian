<!-- Source: T01 (feature 01-identity-keystore-core). The wire-frozen identity spec. -->
> **Nav:** [docs index](../INDEX.md) · [api reference](./README.md) · [wire protocol](./wire-protocol.md) · [core API contracts](./core-api-contracts.md) · [ADR 0001](../adr/0001-identity-scheme.md)

# Identity Format — v1 (frozen)

The canonical, versioned spec for Meridian's self-certifying identity string. This is the authority
for [wire-protocol.md §1](./wire-protocol.md#1-identity-string-frozen-in-t01); the two must agree.
Implemented by [`meridian-identity`](../../apps/identity); conformance fixtures live in
[`test-vectors/identity-v1.json`](../../test-vectors/identity-v1.json).

> **This format is frozen.** The string ends up on business cards, QR codes, and in verified-contact
> pins. Any change is a user-facing migration and requires a new version (`mrd2:…`) plus an ADR — not
> an edit here. See the [risk note in the feature spec](../architecture/features/01-identity-keystore-core.md#risks--notes).

## 1. The string

```
mrd1:<base32-nopad( multicodec ‖ pubkey[32] ‖ crc32c[4] )>@<hint-domain>

e.g.  mrd1:5uatw2rhxthlnjbnmkr2rubkn4gxgzjscv3r3ysduy5masfbrnm5ukkzjaw3i@chat.example
```

Two deliberately separable parts (system-design §3.1, ADR-0001):

- **The key part is the identity.** Globally unique, unforgeable, server-independent. All
  authentication, verification, and (later) safety numbers derive from the key alone.
- **`@hint-domain` is an advisory routing hint**, not a name. It answers only "which rendezvous
  server currently agrees to route for this key?" A stale hint degrades reachability, never security.

**Same-principal rule:** two IDs are the *same principal* iff their key parts are byte-equal,
regardless of hint.

## 2. The key part (frozen field layout)

| Field | Bytes | Value | Notes |
|---|---|---|---|
| multicodec prefix | 2 | `0xED 0x01` | `ed25519-pub` (code `0xed`) as an unsigned-varint — identical to `did:key`'s `z6Mk…` payload |
| public key | 32 | Ed25519 point | the account identity key |
| checksum | 4 | CRC32C(prefix ‖ pubkey), **big-endian** | Castagnoli polynomial; guards against transcription errors |

The 38-byte buffer is encoded with **RFC 4648 base32, lowercase, no padding** (61 characters). The
alphabet is `abcdefghijklmnopqrstuvwxyz234567`.

Checksum coverage is `multicodec ‖ pubkey` (the 34 bytes preceding it). This means a flipped bit
*anywhere* in the prefix, key, or checksum is caught: prefix corruption fails the multicodec check,
and key or checksum corruption fails the CRC.

## 3. The hint (canonical form)

Canonical hints are **ASCII, lowercase, LDH** (letters / digits / hyphen) DNS names:

- ASCII only. **Non-ASCII is rejected** — this is the homoglyph defense (a Cyrillic-`а` look-alike
  domain fails to parse). Internationalized domains MUST be punycode-encoded (`xn--…`) by the caller
  first. *(TODO: confirm whether a later version performs IDNA normalization on input rather than
  rejecting raw Unicode.)*
- Lowercase only (uppercase is non-canonical → rejected).
- No whitespace, `/`, or `@`.
- Labels are 1–63 chars, do not start or end with `-`, and are separated by single `.`; no leading,
  trailing, or doubled dots. Total length ≤ 253 bytes.

## 4. Parsing rules (a parser MUST reject)

In order, `parse_id` rejects:

| Condition | Error |
|---|---|
| missing `mrd1:` prefix | `MissingScheme` |
| not exactly one `@` separating a non-empty key part and hint | `MalformedStructure` |
| any uppercase in the key part | `NonCanonicalCase` |
| key part not valid base32 | `BadBase32` |
| decoded length ≠ 38 bytes | `BadLength` |
| multicodec prefix ≠ `0xED 0x01` | `UnknownMulticodec` |
| CRC32C mismatch | `ChecksumMismatch` |
| non-canonical hint (see §3) | `BadHint` |

The public key is *not* required to be a valid curve point at parse time (the string is validated;
curve validity is enforced separately when the key is used for verification). This keeps parsing a
pure string operation and matches the conformance vectors.

## 5. QR & display name

A QR code carries **exactly the canonical string** — nothing else is authoritative. A display name
MAY accompany it out-of-band, but it is a *local petname* assigned by the receiver, never trusted
from the wire (system-design §3.5). Decoding a QR yields the string, which is then parsed by §4 — a
QR is a transport, not a trust anchor.

## 6. Keystore (private side)

The account **private** key is an Ed25519 seed held by a [`SecretStore`](./core-api-contracts.md):
either the OS keystore (Keychain / DPAPI / Secret Service — keys never touch disk in plaintext) or,
for headless clients, an **age/scrypt passphrase-wrapped keyfile** (system-design §4.7). Signing
happens *through* the store so an enclave-backed implementation can keep the key non-extractable. The
only sanctioned way the seed leaves the store is a user-initiated, passphrase-encrypted **export**
(the sole recovery softening; system-design §10) — there is no server-side escrow.

## 7. Versioning & the PQ slot

The `mrd1:` scheme tag *is* the version. The classical layout above is v1. A future
**post-quantum** identity would be a new tag (`mrd2:…`) carrying an additional signed KEM component,
negotiated the same way the [prekey bundle reserves `v:2` for PQXDH](./wire-protocol.md#7-versioning--pq-slot)
(system-design §4.2). v1 IDs remain valid; migration is additive, never a silent reinterpretation of
existing strings.

## 8. Conformance

Every client (CLI, WASM, mobile) MUST reproduce [`test-vectors/identity-v1.json`](../../test-vectors/identity-v1.json)
byte-identically ([testing/strategy.md §1](../testing/strategy.md)). Regenerate the fixtures with
`cargo run -p xtask -- vectors`. Bumps to the wire-critical crates (`ed25519-dalek`, `data-encoding`,
`crc32c`) must pass these vectors before merge.
