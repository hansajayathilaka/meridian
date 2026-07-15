> **Nav:** [plan index](../README.md) · **Milestone M1** · [canonical spec: T07](../../features/07-offline-mailbox.md) · [ADR 0007 mailbox](../../../adr/0007-offline-mailbox.md) · [anonymity & retention](../../../security/anonymity-and-retention.md)

# Feature 07 — Offline Ciphertext Mailbox

**Milestone:** M1 · **Depends on:** Feature 03, Feature 06 · **Canonical spec:**
[T07](../../features/07-offline-mailbox.md).

**Goal (from spec).** A TTL-bounded, size-capped, **ciphertext-only** mailbox on the recipient's home
rendezvous — ADR 0007's deliberate, loudly-disclosed exception, with its constraints enforced **in code,
not policy prose**. **`[SEC]`** (storage/retention). The "must never #6" rule (no convenience features)
is the review checklist here.

**Exit acceptance (spec §Acceptance).** Expired envelopes provably purged (clock-advance test); redelivered
duplicates dropped client-side; out-of-order mailbox delivery decrypts via skipped keys; quota-exceeded
surfaces to the *sender*; opacity audit covers at-rest DB pages (no plaintext, headers encrypted).

| Task | Scope | Tags | Depends on | Status |
|---|---|---|---|---|
| F07.1 | Mailbox store keyed by recipient pubkey (`Vec<u8>`) + TTL + `TTL=0` truly disables | [SEC] | M1 F06 | ☐ |
| F07.2 | Per-recipient quota + sender-visible "mailbox full" error | [SEC] | F07.1 | ☐ |
| F07.3 | Delivery-on-reconnect + client ack + deletion-on-ack | [SEC] | F07.1 | ☐ |
| F07.4 | Client offline-queue + idempotent dedup by envelope id | [SEC] | F07.3 | ☐ |
| F07.5 | Federated mailbox (Org A → Org B) + X3DH-initial via mailbox | [ADR][SEC] | F07.3, F06 | ☐ |
| F07.6 | `meridian-admin mailbox dump` + at-rest opacity audit | [SEC] | F07.1 | ☐ |

### F07.1 — Mailbox store + TTL
- **Scope.** Store keyed by recipient pubkey, envelopes only (`Vec<u8>` — same no-serde lint as T02); org-configurable TTL (default 14 d); **`TTL=0` genuinely disables the store** (pure-P2P mode).
- **Touches.** `apps/rendezvous/src/mailbox/` (new) + migrations, config `mailbox.ttl_days`. **[SEC]** storage. security-reviewer.
- **Deliverables.** Ciphertext-only store; TTL purge; `TTL=0` returns "recipient offline; pure-P2P" and writes nothing.
- **Tests.** Clock-advance purge; `TTL=0` stores nothing; no-serde-on-blob passes on the mailbox path.
- **Verification (DoD).** 2, 4.

### F07.2 — Quota + sender error
- **Scope.** Per-recipient quota (`mailbox.quota_mb`); overflow surfaces to the **sender** with a clean error.
- **Touches.** `apps/rendezvous/src/mailbox/`, config, `apps/proto` (error). **[SEC]**. security-reviewer.
- **Deliverables.** Quota enforcement; sender-visible "mailbox full".
- **Tests.** Quota exceeded → sender error; recipient store not corrupted.
- **Verification (DoD).** 4.

### F07.3 — Delivery + ack + deletion
- **Scope.** Deliver on recipient reconnect; delete on acknowledged delivery.
- **Touches.** `apps/rendezvous/src/mailbox/`, `apps/core`. **[SEC]**. security-reviewer.
- **Deliverables.** Deliver-then-ack-then-delete; ordered delivery; skipped-message keys handle out-of-order.
- **Tests.** Reconnect delivers all; post-ack dump is empty; out-of-order decrypts.
- **Verification (DoD).** 2, 4.

### F07.4 — Client offline-queue + dedup
- **Scope.** Client-side queue and idempotent dedup by envelope id on redelivery.
- **Touches.** `apps/core/src/chat.rs`, client store. **[SEC]**. security-reviewer.
- **Deliverables.** Idempotent redelivery; duplicates dropped client-side.
- **Tests.** Redelivered duplicate dropped; no double-decrypt.
- **Verification (DoD).** 2.

### F07.5 — Federated mailbox + async X3DH
- **Scope.** Org A sender → Org B mailbox across federation; X3DH-initial (first-contact) messages via mailbox (§4.2 async case).
- **Touches.** `apps/rendezvous/src/{mailbox,federation}/`. **[ADR][SEC]** federation + wire. architect + security-reviewer.
- **Deliverables.** Cross-org queuing; prekey preamble carried through the mailbox so an async first message establishes a session.
- **Tests.** Cross-org offline send → recipient gets it on reconnect; async X3DH establishes correctly.
- **Verification (DoD).** 3, 4.

### F07.6 — Admin inspection + at-rest opacity
- **Scope.** `meridian-admin mailbox dump <pubkey>` prints exactly what an A7 admin sees (sizes, timestamps, opaque blobs) — the honesty demo; extend the opacity audit to at-rest DB pages.
- **Touches.** `apps/rendezvous` (admin CLI), `harnesses/opacity-audit`. **[SEC]**. security-reviewer + test-engineer.
- **Deliverables.** Admin dump tool; opacity audit over DB pages (no plaintext, headers encrypted).
- **Tests.** Dump shows metadata only; at-rest opacity audit passes.
- **Verification (DoD).** 2, 4.
