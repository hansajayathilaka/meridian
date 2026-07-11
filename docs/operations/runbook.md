# Incident, Rollback & Failure-Mode Runbook

<!-- Source: p2p-comms-design.md §10 (failure modes & mitigations); tasks/T14 (upgrade/rollback,
     air-gap install, prekey-drain drill). -->
> **Nav:** [docs index](../INDEX.md) · [operations index](./README.md) · [deployment](./deployment.md) · [monitoring](./monitoring.md) · [/deploy-check command](../../.claude/commands/deploy-check.md)

## Failure modes → mitigations

## 10. Failure modes, mitigations, known limitations

**Failure modes → mitigations.** Home rendezvous down → outbound to other orgs still works via the *sender's* server? No — envelopes to K_B route via B's hint; mitigation: multi-hint IDs (Phase 3) and client retry with jittered backoff; existing live P2P sessions are unaffected (servers are out of the data path). Both peers behind symmetric NAT + no TURN reachable → session fails; mitigation: TURN/TLS-443 last-resort transport, and clear diagnostics (`meridian doctor`) that name the blocked path. Prekey depletion (targeted) → signed-prekey fallback (weakened first-message deniability, not confidentiality) + per-source issuance limits + operator alert. Clock skew breaking prekey/token validity windows → generous windows, server-supplied time hints (authenticated, advisory). Device loss without another linked device → **identity is unrecoverable by design** (no escrow); contacts see a key change and must re-verify — painful, honest, documented; optional user-managed encrypted key backup (age-encrypted file the user stores themselves) is the only softening we offer. Malicious federation partner → bilateral: rate limits, contact-token requirements, allowlist ejection; blast radius is spam/DoS, never content or impersonation. TURN compromise → metadata of relayed flows leaks (IPs, timing, volume); content safe; rotate HMAC secret. Ratchet state desync (restored backup) → sessions fail closed; automatic re-handshake via fresh X3DH with a user-visible notice.

**Known limitations, stated plainly:** (1) metadata per §1.3 — who-talks-to-whom is visible to the involved orgs' servers, and IPs to peers in `direct` mode; (2) offline delivery holds ciphertext server-side (ADR-7) — TTL-bounded, but it exists; (3) no PQ protection until the PQXDH bump lands — harvest-now-decrypt-later applies to v1 traffic; (4) browsers can't pin the app the way binaries can; (5) group properties (Phase ≥2) are weaker than 1:1 until MLS lands, and group *metadata* stays weaker after; (6) air-gapped iOS has no push; (7) deniability is weak-Signal-grade, not OTR-court-grade, and sealed-sender-style sender hiding from the *recipient's own server* is partial in v1.

---


## Rollback & upgrade
Per [feature 14](../architecture/features/14-selfhosting-ops-kit.md): `helm upgrade` and
`ops/rollback.sh` must each leave a working stack (smoke suite green). Both paths are exercised in
CI (compose weekly, air-gap per release).

## Incident response
<!-- TODO: confirm on-call rotation, severity ladder, comms channels, and escalation contacts —
     these are org-specific and not defined in the 38 source documents. Populate per deployment. -->
- Triage: identify blast radius using the [threat→mitigation matrix](../security/threat-mitigation-matrix.md)
  (most failures degrade availability, not confidentiality — confirm which).
- Key-substitution alarm on a verified contact: treat as potential active MITM
  ([threat model](../security/threat-model.md) goal 2); do **not** advise users to bypass the block.
- Postmortem: blameless; record which invariant (if any) was stressed.
