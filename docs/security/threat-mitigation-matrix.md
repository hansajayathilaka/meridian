<!-- Source: DOC-03-threat-mitigation-matrix. -->
> **Nav:** [docs index](../INDEX.md) · [threat model](./threat-model.md) · [test strategy](../testing/strategy.md)

# Threat → Mitigation → Verifying Test Matrix

Companion to design §1. Every adversary maps to concrete mitigations *and* to the task/harness that proves the mitigation holds — so the threat model is continuously tested, not asserted once. See D06 (trust state machine) and D05 (session state machine) for the fail-closed paths.

| # | Adversary | What they attempt | Mitigation (design ref) | Proven by (task / harness) |
|---|-----------|-------------------|-------------------------|----------------------------|
| A1 | Honest-but-curious operator | read content, build contact graph | E2EE all modalities; opaque routing; ratchet inside transport (§4.3) | T03 opacity audit (CI); T14 metrics-endpoint lint (no per-user leakage) |
| A2 | Malicious signaling server | key substitution MITM; drop/forge | addressed-to-key fetch + sig verify (§3.3); envelope sigs; fp-in-envelope (§4.6); verified⇒block on change (§4.4) | T02 tampered-bundle test; T08 `meridian-mitm-sim` matrix (0 silent wins) |
| A2×2 | Colluding org servers | dual-side MITM across federation | same key-binding end to end; safety numbers out-of-band | T06 cross-org substitution test; T08 verified-contact MITM |
| A3 | Network MITM | inject/replay/downgrade | WSS + mTLS; DTLS-SRTP; AEAD everywhere; replay dedup by eid; domain-bound auth challenge | T02 auth-replay test; T05 TURN ciphertext capture check |
| A4 | Compromised peer | learn your IP, other contacts, escalate | relay-only policy hides IP (§5.4); no contact-graph on wire; per-contact tunnel allowlist (T16); grant expiry (T15) | 1.16 observed-candidate enforcement (code-level, fail-closed abort — done); T05/1.27 relay-only packet capture (wire-level — pending); T16 allowlist bypass tests |
| A5 | Metadata observer | who-talks-to-whom, timing, IPs via ICE | org-bounded metadata (ADR-2); relay-only; header encryption; mailbox padding (Phase 3) | documented residual (§1.3); 1.16 observed-candidate enforcement (code-level — done); T05/1.27 IP-leak packet capture (wire-level — pending); **open: mixnet (§12 Q1)** |
| A6 | Device compromise / key exfil | past + future messages, impersonation | FS + PCS (Double Ratchet); OS keystore/enclave; per-device revocation (§4.5); blast-radius limits | T03 FS/PCS harness; T13 revocation drill |
| A7 | Enterprise insider (root on infra) | dragnet, ghost devices, spam | content-blind by construction; signed device records (ghost = bad sig); mailbox shows only sizes/timestamps; client dist is separate trust channel (§9.4) | T13 ghost-device harness (forged + key-theft); T07 `mailbox dump` honesty demo |

## Enumeration / spam (cross-cutting, §3.5)
- 256-bit key namespace → nothing to walk; `fetch_bundle` exact-key only (T02).
- Federation rate limits per (origin server, account); allowlist/closed policies (T06).
- First-contact message-request gate (T06/T08); optional contact tokens + PoW stamp (T14).
- OTK depletion bounded per-source; signed-prekey fallback weakens only first-message deniability, never confidentiality (T02).

## Explicitly accepted residual risk (design §1.3 — restated so nobody "fixes" it silently)
1. Direct-mode peer IPs visible to each other; relay-only trades latency to hide them.
2. Involved orgs' servers see who-signals-whom + timing. Full metadata hiding = Phase-3+ / open question.
3. Mailbox holds TTL-bounded ciphertext (ADR-7) — a real server-side store, disclosed.
4. Live endpoint compromise exposes current plaintext — mitigated in blast radius, not prevented.
5. No PQ until the `v:2` bundle bump — harvest-now-decrypt-later applies to v1 traffic.
6. Browser-served code isn't binary-signed; enterprises prefer desktop or self-audited origin.
7. Group properties weaker than 1:1 until MLS (Phase 3); group metadata weaker thereafter.
8. Air-gapped iOS: no push wake (foreground/polling only).
