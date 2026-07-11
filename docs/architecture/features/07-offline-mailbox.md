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
