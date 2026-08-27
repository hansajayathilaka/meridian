<!-- Source: DOC-02-data-model. -->
> **Nav:** [docs index](../INDEX.md) · [system design](./system-design.md) · [wire protocol](../api/wire-protocol.md) · [privacy & retention](../security/anonymity-and-retention.md)

# Data Model — Rendezvous & Client Stores

Companion to design §2.1/§9.1 and D10/D11. The guiding review question for every column: *"what does an admin with the DB (threat A7) learn?"* — the answer is recorded per table.

## 1. Rendezvous (SQLite default / Postgres flag)

```sql
accounts(          -- A7 learns: which pubkeys registered, when
  account_pub BLOB PRIMARY KEY, created_at, admission TEXT,  -- open|invite|oidc
  max_bundle_v INT)

prekeys(           -- A7 learns: rotation cadence; contents are PUBLIC keys anyway
  account_pub REFERENCES accounts, spk BLOB, spk_sig BLOB, rotated_at)

one_time_prekeys(  -- pool depth is a monitored metric (depletion = attack signal)
  id INTEGER PK, account_pub, otk BLOB, otk_sig BLOB, issued_to_hash BLOB NULL)
  -- issued_to_hash: salted hash of requester, for per-source issuance limits only

device_records(    -- append-only, ACCOUNT-signed; server stores, never edits
  account_pub, version INT, record BLOB /*signed CBOR*/, PRIMARY KEY(account_pub, version))

mailbox(           -- ADR-7. A7 learns: count, sizes, timestamps. Nothing else.
  id INTEGER PK,   -- server-assigned sequential row id (same shape as one_time_prekeys.id).
                   -- Deliberately independent of MessageEnvelope::eid (task 6.4, ADR 0016 C7):
                   -- that eid lives inside the opaque `blob` below, which the server never
                   -- decodes (route's opaque-blob contract; apps/proto's OpaqueBlob; the
                   -- no-serde-on-blob lint). The shared name was coincidental drafting, resolved
                   -- by task 7.6 — this is not the same key, and not derived from it. Dedup on
                   -- redelivery is a client-side concern only (T07 deliverable 2; task 2.8's
                   -- "no s2s dedup" already stands) — the server never needs to read eid at all.
  recipient_pub, blob BLOB /*opaque — no-serde lint*/,
  arrived_at, expires_at, size_bytes)
  -- purge job on expires_at; delete on ack (by id); quota trigger per recipient
  -- TTL=0 config ⇒ inserts disabled entirely (pure-P2P mode)

rate_counters(scope TEXT, key_hash BLOB, window_start, count)  -- salted hashes only
```

**`federation_map` is a config file, not a table (superseded).** An earlier draft of this doc
listed `federation_map(domain PK, endpoint, ca_pin, policy)` as a rendezvous DB table. That was
never built and is **not the design**: [task 2.3](../tasks/phase-2/2.3-c2s-federation-extension.md)
re-deferred "normalized schema + Postgres" to T07 with "Feature 06 adds no new persisted state,"
and [ADR 0002](../adr/0002-federation-mechanism.md)'s air-gap case depends on federation partners
being named in a static **file**, not queryable server state, with no shared/DB-backed lookup at
all. The actual shape — resolved and implemented by
[task 2.5](../tasks/phase-2/2.5-federation-discovery.md) — is `federation_map.toml`, an
operator-edited config file parsed by `meridian_rendezvous::federation::discovery::StaticMap`
(schema documented in that module and in the reference fixture,
[`demo/two-orgs/federation_map.toml`](../../demo/two-orgs/federation_map.toml)): per-partner
`domain`, `endpoint` (`host:port`), and a mandatory `pinned_identity` (SAN/CN, [ADR 0017](../adr/0017-federation-trust-boundary.md)
C4 — not a certificate/key fingerprint, hence not named `ca_pin`). No per-partner `policy` field:
[task 3.9](../tasks/phase-3/3.9-federation-map-policy-field.md) closed the earlier reserved-but-dead
version of that field (parsed, never consulted) by making it a fail-closed config-load error —
federation admission is server-wide only, via `federation.policy` ([task 2.6](../tasks/phase-2/2.6-federation-policy-limits.md), `open | allowlist | closed`), never a per-partner dimension.

Deliberately absent: contact lists, message metadata beyond the mailbox row, display names, sender columns on mailbox rows (sender is inside the sealed envelope). Backup/restore stance (§10): losing this DB costs *reachability* (clients republish bundles on reconnect), never confidentiality or identity.

## 2. Client local store (encrypted via SecretStore key)

```
identity/        account keypair ref (OS keystore handle or wrapped file), device subkeys
sessions/        per (peer_pub, device_id): ratchet state, skipped-message keys (capped),
                 last DTLS fp seen
contacts/        peer_pub → {petname, trust: new|pinned|verified|blocked,
                 pinned_key_history[], device_record_version_seen, policy overrides}
history/         per conversation, envelope-id-deduped; prunable
outbox/          queued envelopes awaiting connectivity (idempotent by eid)
streams/         resumable transfer state: manifest, merkle root, range bitmap
config/          org-pushed defaults (ICE servers, connection policy) + user overrides
```
Whole store sealed with XChaCha20-Poly1305 under a key from `SecretStore`; browser variant = same layout in IndexedDB encrypted blobs. **Two ADR-0021-ratified exceptions to "whole store sealed," scoped to the terminal client only:** `config/`'s terminal realization (`config.toml`) is deliberately plaintext and human-edited, never sealed — a config file with no secret content, meant to be hand-read/edited; and the terminal client adds one file outside this abstract list entirely, `tui/state.json` (pure UI view-state: last-open conversation as an opaque non-identifying handle, pane geometry, scroll offsets — no petname/body/key/contact-identifying content), which is likewise deliberately unsealed. Every other bucket above (`identity/`, `sessions/`, `contacts/`, `history/`, `outbox/`, `streams/`) stays sealed without exception. The terminal client's concrete realization of `contacts/`, `history/`, `outbox/`, and `config/` — file layout, JSON schemas, versioning/migration, and the TOML config — is specified in [tui-client.md §5](./tui-client.md#5-local-store--configuration) (ratified by [ADR 0021](../adr/0021-client-local-store-config-formats.md)). That encoding is client-local: each client realizes this layout in its own format, and a portable/shared on-disk format would need its own contract. Restore-from-backup with stale ratchet state fails closed → automatic fresh X3DH with a user-visible notice (§10).

## 3. Retention defaults

Rendezvous logs: salted-hash identifiers, 7-day retention (org-overridable — documented, not hidden). Mailbox TTL 14 d. Client history: user-controlled, disappearing-messages timer implemented client-side as a stream-type-level feature (both ends enforce; a compromised peer (A4) can obviously retain — stated honestly in UX copy).
