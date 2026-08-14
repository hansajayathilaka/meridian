<!-- Schema proposal for task 4.8. Revised after the required architect + security-reviewer pass:
     verdict was approved-with-required-changes (1: multi-org storage was internally contradictory;
     2: the signed byte sequence was underspecified; 3: needed a total cross-import suggestions cap,
     not just a per-artifact one; 4: hr_name needed a concrete bound, not just prose). All four
     applied below. -->
> **Nav:** [docs index](../INDEX.md) · [system-design.md §3.5](../architecture/system-design.md) ·
> [feature 08: verification & trust](../architecture/features/08-verification-trust.md) ·
> [verification-ux.md](./verification-ux.md) · precedent [ADR 0017](../adr/0017-federation-trust-boundary.md)

# Org directory attestation — schema & provenance model (task 4.8)

## Why this exists

`system-design.md §3.5`: *"an enterprise MAY run an internal signed directory mapping HR identities
→ account keys, which clients treat as a petname source with provenance, not as a key authority — a
wrong directory entry is detectable by the victim, whose client knows its own key."* No wire/file
schema for this exists anywhere in `docs/` today. This document is that schema proposal — task 4.8's
required deliverable 1, needing **architect sign-off before implementation, not after** (the task
file's own risk note).

**Not a wire protocol.** This artifact never crosses the rendezvous c2s/s2s connection — no
`meridian-proto` type, no server involvement of any kind. An org distributes the signed file to its
members out-of-band (intranet, MDM push, email, USB) exactly the way `federation_map.toml`'s
`pinned_identity` is provisioned today (`docs/tasks/phase-2/2.5-federation-discovery.md`), and a user
runs `meridian directory import <path>` to ingest it locally. This document lives under
`docs/security/` (trust-model territory), not `docs/api/` (which is reserved for things that actually
cross a wire this project controls both ends of).

## The provenance-not-authority boundary (binding)

This is the entire point of the feature, restated precisely so the implementation can be checked
against it:

1. A directory attestation produces, at most, a **suggested display name** for an already-known
   account key — never a petname assignment, never a trust-state transition, never anything that
   `can_send`/`TrustState` reads.
2. It is **stored separately** from [`Contact::petname`](../../apps/core/src/trust.rs) (task 4.6) —
   a distinct field/type, never merged, never silently promoted to `petname` by any code path.
3. Applying a suggestion as the actual petname is **always an explicit user action** (mirrors 4.6's
   own `--petname`/prompt invariant: no auto-apply, ever, from any wire- or attestation-sourced
   string).
4. An attestation for a key the user has **never observed** creates no `Contact` and no side effect
   — ingest only *annotates* existing contacts (or holds unmatched entries for future contacts to
   pick up when the corresponding key is eventually TOFU-pinned by `observe`), it never itself calls
   `TrustStore::observe`.
5. A directory entry never overrides, downgrades, or upgrades `TrustState`. In particular: an org
   attesting a name for a key does **not** verify that key — only `mark_verified`'s existing
   out-of-band safety-number flow (4.5) does that.

## Artifact schema (`v: 1`)

CBOR-encoded (matching the codebase's existing wire-artifact convention — `PrekeyBundle`,
`OpaqueBlob` — even though this specific artifact isn't wire-transmitted; reusing the same encoding
means `apps/proto`'s existing `bytes::{b32,b64}` serde helpers apply unchanged and a future export
tool has one less format to support). File extension `.mrdir` (arbitrary, unimportant — content is
what's verified, not the name).

```rust
/// Format version. A bump changes signed-artifact bytes.
pub const DIRECTORY_VERSION: u16 = 1;
/// Upper bound on entries in one artifact — bounds ingest cost and at-rest storage growth from a
/// single import (mirrors chat.rs's MAX_PENDING_REQUESTS/trust.rs's MAX_HINT_LEN precedent of
/// capping attacker- or bulk-import-controlled collection sizes). A larger enterprise splits
/// across multiple `.mrdir` files/imports rather than needing a bigger single-file cap.
pub const MAX_DIRECTORY_ENTRIES: usize = 10_000;
/// Bound one entry's `hr_name` — hostile-input-facing content (an org's directory, or a
/// compromised org signing key, is the same threat class as `Contact::hint`, not the
/// user-typed-only `Contact::petname` — see trust.rs's MAX_HINT_LEN vs. MAX_PETNAME_LEN
/// distinction). Reuses trust.rs's MAX_HINT_LEN value (253) for the same reasoning; truncated at
/// ingest, at a UTF-8 boundary, never rejected — same style as `bounded_hint`/`bounded_petname`.
pub const MAX_HR_NAME_LEN: usize = 253;
/// Total cap on suggestions held across ALL imports, not just one artifact — MAX_DIRECTORY_ENTRIES
/// alone only bounds a single artifact's contribution; repeated re-imports or several distinct
/// `.mrdir` files pinned to one (or a compromised) org_signing_pub could otherwise grow the
/// suggestions map unboundedly. Mirrors chat.rs's MAX_PENDING_REQUESTS + evict_oldest_pending
/// pattern exactly: oldest `attested_at` evicted first once this cap is hit.
pub const MAX_TOTAL_DIRECTORY_SUGGESTIONS: usize = 50_000;

/// The exact byte sequence [`DirectoryAttestation::sig`] is computed and verified over: every
/// field of [`DirectoryAttestation`] except `sig` itself, as its own concrete type — not "the
/// struct minus a field" as a loose instruction, which would leave two independent
/// implementations (native, WASM, a future mobile-via-UniFFI client) free to diverge on exactly
/// what bytes get signed. CBOR-encode *this* type via `ciborium::into_writer` and sign/verify
/// that byte string, full stop — mirrors how `apps/proto/CLAUDE.md`'s deterministic-CBOR rule is
/// meant to be satisfied: one concrete type, one encoding, no ambiguity.
pub struct DirectoryAttestationSignable {
    pub v: u16,
    pub org_domain: String,
    pub org_signing_pub: [u8; 32],
    pub issued_at: u64,
    pub entries: Vec<DirectoryEntry>,
}

pub struct DirectoryAttestation {
    pub v: u16,                    // DIRECTORY_VERSION
    pub org_domain: String,        // the issuing org's hint domain, e.g. "org-a.test" — display only
    pub org_signing_pub: [u8; 32], // Ed25519 public key this artifact is signed under
    pub issued_at: u64,            // unix seconds, org's clock
    pub entries: Vec<DirectoryEntry>,
    pub sig: [u8; 64],             // Ed25519(org_signing_pub) over the CBOR encoding of the
                                    // DirectoryAttestationSignable built from every field above
                                    // (v, org_domain, org_signing_pub, issued_at, entries) —
                                    // see DirectoryAttestationSignable's own doc
}

pub struct DirectoryEntry {
    pub account_pub: [u8; 32], // the account key this entry names
    pub hr_name: String,       // e.g. "Dana Smith, Finance" — bounded by MAX_HR_NAME_LEN
}
```

**Signing.** Plain Ed25519 over the CBOR encoding of [`DirectoryAttestationSignable`] (defined
above, precisely — see its doc comment for why a named type rather than a "struct minus one field"
instruction) — no new cryptographic construction (per the task's own risk note: "if this task
seems to need a new primitive, that's a planning defect"). Verification reuses
`meridian_identity::{sign, verify}` exactly as-is; `sign`/`verify` are already generic over
arbitrary message bytes, not just identity self-certification, so no crypto crate changes at all.

**Trust anchor: `org_signing_pub` is caller-supplied, never self-asserted.** The artifact carries its
own claimed signing key — that alone proves nothing (anyone can self-sign a claim about anyone).
Ingest therefore takes the expected `org_signing_pub` as an **explicit parameter from the local
operator**, e.g. `meridian directory import <path> --org-key <hex>`, exactly mirroring
`federation_map.toml`'s `pinned_identity` (`docs/tasks/phase-2/2.5-federation-discovery.md`) and
`ADR 0017`'s peer-cert-pinning precedent: a value the org distributes to its members out-of-band
(the same channel that distributes the `.mrdir` file itself), pinned locally, never fetched or
discovered automatically. An artifact whose embedded `org_signing_pub` doesn't match the
caller-supplied pin, or whose `sig` doesn't verify under it, is rejected outright — ingest fails
closed, nothing is stored.

## Storage: `DirectorySuggestion`

A new type in `apps/core/src/trust.rs` (or a sibling module, `apps/core/src/directory.rs` — TBD at
implementation time, doesn't change the schema). **Multi-valued per `account_pub`** — a single key
can carry one suggestion *per distinct attesting org signing key*, never collapsed to one, and
`DirectorySuggestion` carries its own `org_signing_pub` so storage can actually key/match on it
(the identifying field), not on the display-only `org_domain`:

```rust
pub struct DirectorySuggestion {
    pub hr_name: String,           // bounded by MAX_HR_NAME_LEN, truncate-not-reject
    pub org_domain: String,        // display only — never the match key, see above
    pub org_signing_pub: [u8; 32], // the match key: which attesting org this suggestion is from
    pub attested_at: u64,          // the artifact's issued_at, not local ingest time
}
```

`TrustStore` (or its sibling) gains `suggestions: BTreeMap<[u8; 32], Vec<DirectorySuggestion>>`
(keyed by `account_pub`) alongside `contacts`, plus:
- `ingest_directory(artifact, expected_org_signing_pub) -> Result<usize, DirectoryError>` — verifies,
  then upserts one `DirectorySuggestion` per entry into that key's `Vec`: a later `issued_at` from
  the **same** `org_signing_pub` replaces its existing entry in the vec (never appends a duplicate
  from one org); an entry from a **different** `org_signing_pub` for the same `account_pub` is
  pushed alongside, never merged or overwritten — a user may reasonably see suggestions from more
  than one org if they have contacts spanning multiple attesting enterprises (deciding how to
  *display* more than one suggestion for one contact is explicitly a later UI-layer concern, 4.19+,
  not this schema's job). Once the running total across every key's `Vec` reaches
  `MAX_TOTAL_DIRECTORY_SUGGESTIONS`, the oldest `attested_at` entry anywhere in the map is evicted
  before inserting a new one — mirrors `chat.rs`'s `MAX_PENDING_REQUESTS`/`evict_oldest_pending`
  pattern exactly, just applied to this map instead. Returns the count ingested (for CLI/TUI
  feedback), or an error naming why the whole artifact was rejected (bad signature, wrong signing
  key, oversized, malformed).
- `directory_suggestions(account_pub) -> impl Iterator<Item = &DirectorySuggestion>` — read-only,
  yields every suggestion for that key (zero or more) a CLI/TUI layer can display alongside (never
  merged into) a `Contact`'s real `petname`.

`ingest_directory` never calls `observe`/`set_petname`/anything that mutates `Contact`/`TrustState` —
condition 1/2/4 above, enforced structurally the same way 4.6's petname-never-from-wire invariant is:
by there being no code path that could, not merely a convention.

**Unmatched entries are held, not dropped** (resolves the schema's earlier open question,
architect-confirmed): a `DirectoryEntry` for an `account_pub` this store has never `observe`d still
gets a `DirectorySuggestion` recorded, so a later `contact add`/first-contact `observe` for that key
picks up the existing suggestion immediately rather than requiring an org to re-distribute and
re-import the same file after every new hire's first contact. This is safe specifically because
`MAX_DIRECTORY_ENTRIES` (per artifact) and `MAX_TOTAL_DIRECTORY_SUGGESTIONS` (across all imports,
with oldest-first eviction) together bound the cost of holding unmatched entries — a held-forever
design without eviction would not have been acceptable.

## Rejected alternative

**Auto-apply the attested name as `petname` when no local petname is already set.** Rejected outright
— this is precisely the "key authority via displayname" confusion `system-design.md §3.5` exists to
prevent, and would make an org's directory a silent, un-auditable override of what is supposed to be
a strictly local, user-controlled field (4.6). No config flag should ever be added to enable this
without a superseding decision, mirroring ADR 0021's treatment of `store.encrypt = false`.
