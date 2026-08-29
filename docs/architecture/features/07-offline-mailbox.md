<!-- Source: tasks/T07-offline-mailbox.md. Feature spec with runnable acceptance demo. -->
> **Nav:** [docs index](../../INDEX.md) · [roadmap](../roadmap.md) · [system design](../system-design.md) · [test strategy](../../testing/strategy.md)

# T07 — Offline Ciphertext Mailbox

**Priority:** P1 · **Design refs:** ADR-7, §3.3, §10 · **Depends on:** T03, T06 · **Indicative effort:** 1–2 eng-weeks

## Goal
Deliver messages to offline recipients via a TTL-bounded, size-capped, ciphertext-only mailbox on the recipient's home rendezvous — the deliberate, loudly-disclosed exception of ADR-7, implemented with its constraints enforced in code, not policy prose.

## Scope
In: mailbox store keyed by recipient pubkey (envelopes only — the store type is `Vec<u8>`, same no-serde lint as T02); deletion-on-acknowledged-delivery; TTL (org-configurable, default 14 d, **TTL=0 = pure-P2P mode** must genuinely disable the store); per-recipient quota with sender-visible "mailbox full" error; delivery on reconnect with client ack; works across federation (Org A sender → Org B mailbox); X3DH-initial messages via mailbox (the async first-contact case §4.2).
Out: padding/batching mitigations (Phase 3 — record as explicit follow-up), sealed-sender wrapping (Phase 3).

## Deliverables
1. Mailbox module + migrations; config: `mailbox.ttl_days`, `mailbox.quota_mb`.
2. Client offline-queue + dedup on redelivery (idempotent by envelope id).
3. **Inspection demo tooling:** `meridian-admin mailbox dump <pubkey>` prints exactly what an admin (threat A7) can see — sizes, timestamps, opaque blobs — making the residual metadata concrete.

## Working output (demo script)
```
$ meridian chat mrd1:<bob>@org-b.test    # bob's client is stopped
  [mailbox] bob offline — queued at org-b (expires in 14d)
$ meridian-admin --server org-b mailbox dump <bob>
  3 envelopes | 1.2 KiB, 0.9 KiB, 4.1 KiB | ts … | contents: <opaque>   ← the honesty demo
$ meridian chat …                        # start bob
  — all three messages arrive, correctly ordered, ratchet intact —
$ meridian-admin mailbox dump <bob>      # → empty (deleted on delivery)
$ # TTL=0 org: same send → "recipient offline; this org runs pure-P2P delivery"
```

## Acceptance criteria
Expired envelopes are provably purged (test advances clock); redelivered duplicates are dropped client-side; out-of-order mailbox delivery decrypts (skipped-message keys, from T03); quota exceeded surfaces to *sender* with a clean error; opacity audit covers at-rest DB pages (no plaintext, headers encrypted).

## Risks / notes
Do not let convenience features creep in (search, server-side read state, "sync"). The mailbox's entire security argument is its poverty of function.

## Client trust in `Deliver.mailbox_id` (task 9.6, phase-9 review finding F3)
`apps/signaling/src/client.rs`'s `SignalingClient::next_deliver` accumulates **any**
`Deliver.mailbox_id` it receives — from a genuine mailbox drain (this feature) or an ordinary live
delivery the server happened to tag with one — into `pending_mailbox_acks`, later flushed as a real
`MailboxAck` by `ack_pending_mailbox`. The client has no wire-level way to distinguish the two cases:
the protocol carries no drain-batch marker, and `mailbox_id` (unlike `Deliver.from`, ADR 0024) has no
cryptographic backstop of its own to fall back on — it is server-supplied bookkeeping, trusted as-is.

This is a **deliberate, accepted, bounded trust boundary**, reasoned through the same way
[ADR 0024](../../adr/0024-mailbox-drain-from-attestation.md) reasoned through the analogous question
for `Deliver.from`, applied to this distinct, weaker field:

- **Bound:** `Store::mailbox_delete_by_ids` (`apps/rendezvous/src/store.rs`, exercised by
  `ws.rs`'s `MailboxAck` handler) deletes only a row that matches *both* an acked id *and* the
  authenticated connection's own `account_pub`. A buggy or malicious server can therefore at most
  trick a client into acking (and losing) one of its **own** genuine queued rows early — never
  another account's row.
- **No cross-account capability:** the recipient scoping on the delete path is structural (a `WHERE`
  clause on both columns), not a check the client's trust decision could bypass even if the server
  supplied an id belonging to a different account.
- **No confidentiality break either way:** a mailbox row is ciphertext-only regardless of whether it
  is acked early, late, or never — accumulating (or not accumulating) a `mailbox_id` reveals nothing
  about, and changes nothing about, what the row contains.
- **Why not add drain-batch validation instead:** doing so would require a wire-protocol change (a
  drain-start/drain-end marker or similar), a `meridian-proto` change with conformance-vector
  re-vectoring, to close a bound that is already this narrow. Not undertaken; revisit only with a
  fresh forcing function, mirroring ADR 0024's own framing for why it didn't widen `Deliver.from` to
  an `Option` for a functionally-equivalent reason.

Covered by a unit test in `apps/signaling/src/client.rs` (`mailbox_id_on_a_live_looking_deliver_is_still_accumulated`)
that constructs a live-looking `Deliver` (no ADR-0024 sentinel, a real-looking `from`) carrying a
`mailbox_id` and asserts it is still accumulated — proving the documented behavior, not an absence of
one.
