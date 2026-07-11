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
  eid BLOB PK, recipient_pub, blob BLOB /*opaque — no-serde lint*/,
  arrived_at, expires_at, size_bytes)
  -- purge job on expires_at; delete on ack; quota trigger per recipient
  -- TTL=0 config ⇒ inserts disabled entirely (pure-P2P mode)

federation_map(    -- air-gapped static mode; SRV used when absent
  domain TEXT PK, endpoint TEXT, ca_pin BLOB NULL, policy TEXT /*open|allow|closed*/)

rate_counters(scope TEXT, key_hash BLOB, window_start, count)  -- salted hashes only
```

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
Whole store sealed with XChaCha20-Poly1305 under a key from `SecretStore`; browser variant = same layout in IndexedDB encrypted blobs. Restore-from-backup with stale ratchet state fails closed → automatic fresh X3DH with a user-visible notice (§10).

## 3. Retention defaults

Rendezvous logs: salted-hash identifiers, 7-day retention (org-overridable — documented, not hidden). Mailbox TTL 14 d. Client history: user-controlled, disappearing-messages timer implemented client-side as a stream-type-level feature (both ends enforce; a compromised peer (A4) can obviously retain — stated honestly in UX copy).
