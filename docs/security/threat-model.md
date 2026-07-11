# Threat Model & Security Goals

<!-- Source: p2p-comms-design.md §1 (canonical extract). The full system design links here
     instead of duplicating this section. -->
> **Nav:** [docs index](../INDEX.md) · [system design](../architecture/system-design.md) · [threat→mitigation matrix](./threat-mitigation-matrix.md) · [anonymity & retention](./anonymity-and-retention.md)

This is the single source of truth for what Meridian protects, what it does not, and against whom.
The [security-reviewer](../../.claude/agents/security-reviewer.md) subagent and the
[anonymity-model skill](../../.claude/skills/anonymity-model/SKILL.md) load this file before any review.

## 1. Threat model & security goals

### 1.1 Adversaries considered

**A1. Honest-but-curious signaling/relay operator.** Runs the org's signaling and TURN servers faithfully but logs and inspects everything it can. This is the *baseline* adversary — in an enterprise deployment, IT *is* this adversary by default.

**A2. Malicious signaling server.** Actively drops, delays, reorders, or forges signaling messages; attempts to MITM key agreement by substituting keys; attempts to enumerate the user base; colludes with a malicious counterpart server in a federation.

**A3. Network-level MITM.** On-path attacker between client↔server or peer↔peer (hostile Wi-Fi, compromised router, BGP hijack). Can inject, drop, and replay packets; can attempt TLS downgrade.

**A4. Compromised peer.** The person you are talking to is the adversary (or their device is). Trivially "wins" against content you sent them — the interesting questions are what *else* they learn (your IP, your other contacts, your device list) and whether they can escalate.

**A5. Metadata observer.** Global-ish passive observer correlating who-talks-to-whom, when, how much, and from which IPs — including via ICE candidate exchange, TURN allocation logs, and traffic analysis of encrypted flows.

**A6. Device compromise / key exfiltration.** Malware or physical seizure of an endpoint; extraction of long-term identity keys and ratchet state.

**A7. Enterprise insider.** An admin of the self-hosted stack, with root on the signaling and TURN hosts and the ability to push (unsigned) config — but *not* the ability to push client binaries (client distribution is a separate trust channel; see §9.4).

### 1.2 Security goals (what we protect)

1. **Content confidentiality & integrity, end-to-end**, for every modality — text, files, voice, video, screenshare, location, stickers, and Tier-2 tunneled streams — against A1–A3, A5, A7. No infrastructure component can read or undetectably modify content.
2. **Authenticity of identity.** A peer who verifies a contact's ID (or safety number) gets a cryptographic guarantee they are talking to the holder of that identity key, even if *every* server in the path is malicious (A2). Server-substituted keys are detectable, and with verified contacts, session establishment to a substituted key *fails closed*.
3. **Forward secrecy and post-compromise security** for messaging: compromise of current keys (A6) does not reveal past messages, and the session self-heals after the compromise ends (Double Ratchet properties).
4. **Deniability (weak).** Message authentication uses MACs within ratchet sessions, not signatures, so transcripts are not third-party-provable (standard Signal-style deniability; identity-key signatures are confined to key distribution and signaling).
5. **Anti-enumeration and unsolicited-contact resistance.** Knowing that a server exists must not let A2/A5 enumerate its users; possessing infrastructure access must not let A7 spam or dragnet-introduce users (§3.5).
6. **Availability degradation is honest.** A malicious server (A2) can deny service — we do not claim otherwise — but it cannot silently downgrade security. Every failure is either "no session" or "secure session"; never "weaker session."

### 1.3 Explicitly out of scope / accepted residual risk

- **Endpoint compromise depth (A6):** if a device is rooted while in use, plaintext and current keys are exposed. We mitigate blast radius (per-device keys, FS/PCS, OS keystore/secure-enclave storage, revocation) but do not claim to defeat a live implant.
- **Traffic-analysis-grade metadata (A5):** connection timing, flow volume, and — in direct-P2P mode — peer IP addresses are visible to their respective observers. Relay-only mode hides peer IPs from each other but concentrates metadata at the org's TURN server (visible to A1/A7). We do not attempt Tor/mixnet integration in v1; it is an open question (§12).
- **Compelled key disclosure / rubber-hose;** malicious *client builds* (supply-chain of the app itself) — mitigated by reproducible builds and signed releases, but out of the protocol's scope.
- **Availability under DoS** against self-hosted infra beyond standard rate-limiting/anycast advice.
- **Group-scale (>~50) metadata hiding.** Group membership is visible to members; delivery patterns partially visible to servers.

The one-sentence summary: **servers are trusted for availability only; peers are trusted for content you deliberately send them; nobody is trusted for keys.**

---

