<!-- Source: DOC-03-threat-mitigation-matrix. -->
> **Nav:** [docs index](../INDEX.md) · [threat model](./threat-model.md) · [test strategy](../testing/strategy.md)

# Threat → Mitigation → Verifying Test Matrix

Companion to design §1. Every adversary maps to concrete mitigations *and* to the task/harness that proves the mitigation holds — so the threat model is continuously tested, not asserted once. See D06 (trust state machine) and D05 (session state machine) for the fail-closed paths.

| # | Adversary | What they attempt | Mitigation (design ref) | Proven by (task / harness) |
|---|-----------|-------------------|-------------------------|----------------------------|
| A1 | Honest-but-curious operator | read content, build contact graph | E2EE all modalities; opaque routing; ratchet inside transport (§4.3) | T03 opacity audit (CI); T14 metrics-endpoint lint (no per-user leakage) |
| A2 | Malicious signaling server | key substitution MITM; drop/forge | addressed-to-key fetch + sig verify (§3.3); fp-in-envelope (§4.6); verified⇒block on change (§4.4); envelope sigs (**v1 only** — removed at v2 per [ADR 0016](../adr/0016-envelope-deniability.md); the row does not depend on them, since bundle-sig verification, the ratchet AEAD's identity binding, and block-on-change carry it) | T02 tampered-bundle test; 1.28 active relay-rewrite of routed blobs (detected at envelope auth, fails closed); 1.32 relay attacks that pass the signature check — forged `Deliver.from`, replay, reorder, drop, cross-delivery — plus X3DH preamble mutation (each rejected with its own diagnosable error, consuming no prekey and installing no session); T08 `meridian-mitm-sim` matrix (0 silent wins **outside the enumerated accepted residuals** — enumerated in [ADR 0016](../adr/0016-envelope-deniability.md) or §1.3 only, not "any ADR"; the exception is **not live under envelope v1**, where the requirement is 0 silent wins unqualified, and extending the list needs a new ADR with security-reviewer sign-off); [task 2.13](../tasks/phase-2/2.13-ratchet-replay-dos.md) fixed the one case that used to survive a replay only at the cost of wedging the session — see A3 |
| A2×2 | Colluding org servers | dual-side MITM across federation | same key-binding end to end; safety numbers out-of-band | task 2.12 `federation_abuse.rs::cross_org_malicious_server_bundle_substitution_is_rejected_by_the_client` (org B's server actively lies about bob's prekey bundle over the FEDERATED `fed_fetch_bundle` path; alice's client, which only ever talks to org A, rejects with `SignalError::BundleVerification` specifically — the `test-tamper-hook`'s federated extension, structurally inert without the cargo feature); `harnesses/mitm-sim` cross-org cell (same test, wired into the harness); T08 verified-contact MITM |
| A3 | Network MITM | inject/replay/downgrade | WSS + mTLS; DTLS-SRTP; AEAD everywhere; replay dedup by `eid` (**specified, not implemented in v1** — [wire-protocol.md](../api/wire-protocol.md) "No `eid`": v1 has no envelope-level replay protection at all; deferred to envelope v2); domain-bound auth challenge; `DoubleRatchet::decrypt` is failure-atomic ([task 2.13](../tasks/phase-2/2.13-ratchet-replay-dos.md)) — a failed `aead_open` discards its state changes (staged on a crate-private checkpoint copy, committed only on success), so a replayed/forged envelope degrades exactly the one message rather than permanently wedging the receiving chain | T02 auth-replay test; T05 TURN ciphertext capture check; 1.32 relay replay cell (a duplicate is never accepted twice, and the session **survives** it — a genuine subsequent message still opens); `apps/crypto/tests/ratchet_replay.rs` (task 2.13: the ratchet is byte-identically unchanged after a failed decrypt, including the compound DH-ratchet + skipped-key catch-up path, and a genuine message opens afterwards) |
| A4 | Compromised peer | learn your IP, other contacts, escalate | relay-only policy hides IP (§5.4); no contact-graph on wire; per-contact tunnel allowlist (T16); grant expiry (T15) | 1.16 observed-candidate enforcement (code-level, fail-closed abort — done); T05/1.27 relay-only packet capture (wire-level — done for the `udp-blocked`+relay-only cell; the `direct`/`prefer-relay` cells' post-fallback relay round is NOT yet independently wire-verified for zero-leak, see 1.27's task file Risks — tracked follow-up); T16 allowlist bypass tests |
| A5 | Metadata observer | who-talks-to-whom, timing, IPs via ICE | org-bounded metadata (ADR-2); relay-only; header encryption; mailbox padding (Phase 3) | documented residual (§1.3); 1.16 observed-candidate enforcement (code-level — done); T05/1.27 IP-leak packet capture (wire-level — done for `udp-blocked`+relay-only; same residual gap as A4 for the 3 fallback-to-relay cells); **open: mixnet (§12 Q1)** |
| A6 | Device compromise / key exfil | past + future messages, impersonation | FS + PCS (Double Ratchet); OS keystore/enclave; per-device revocation (§4.5); blast-radius limits | T03 FS/PCS harness; T13 revocation drill |
| A7 | Enterprise insider (root on infra) | dragnet, ghost devices, spam | content-blind by construction; signed device records (ghost = bad sig); mailbox shows only sizes/timestamps; client dist is separate trust channel (§9.4) | T13 ghost-device harness (forged + key-theft); T07 `mailbox dump` honesty demo |

## Enumeration / spam (cross-cutting, §3.5)
- 256-bit key namespace → nothing to walk; `fetch_bundle` exact-key only (T02).
- Federation rate limits per (origin server, account); allowlist/closed policies (T06).
- First-contact message-request gate (T06/T08; landed 2.10) — **covers the relay/mailbox delivery
  path (`ChatState::open_inbound`) only.** A direct P2P dial (`meridian session connect`) currently
  bypasses it entirely: the crypto session is already installed by the SDP offer/answer exchange
  (`chat.open_bytes`, not `open_inbound`) before any chat content flows, so `is_first_contact` is
  structurally always false on that path. Tracked as [2.14](../tasks/phase-2/2.14-p2p-message-request-gate.md).
  Optional contact tokens + PoW stamp (T14).
- OTK depletion bounded per-source; signed-prekey fallback weakens only first-message deniability, never confidentiality (T02). (Moot for envelope v1, which is not deniable at all — every ciphertext is identity-signed; see [ADR 0016](../adr/0016-envelope-deniability.md).)

## Explicitly accepted residual risk (design §1.3 — restated so nobody "fixes" it silently)
1. Direct-mode peer IPs visible to each other; relay-only trades latency to hide them.
2. Involved orgs' servers see who-signals-whom + timing. Full metadata hiding = Phase-3+ / open question.
3. Mailbox holds TTL-bounded ciphertext (ADR-7) — a real server-side store, disclosed.
4. Live endpoint compromise exposes current plaintext — mitigated in blast radius, not prevented.
5. No PQ until the `v:2` bundle bump — harvest-now-decrypt-later applies to v1 traffic.
6. Browser-served code isn't binary-signed; enterprises prefer desktop or self-audited origin.
7. Group properties weaker than 1:1 until MLS (Phase 3); group metadata weaker thereafter.
8. Air-gapped iOS: no push wake (foreground/polling only).
