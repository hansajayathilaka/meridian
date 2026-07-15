> **Nav:** [plan index](../README.md) · **Milestone M2** · [canonical spec: T16](../../features/16-tier2-tunnels.md) · [stream-types-v1](../../../api/stream-types-v1.md) · [threat model](../../../security/threat-model.md)

# Feature 16 — Tier-2 Tunnels: SSH-over-P2P & `mrd.fs/1`

**Milestone:** M2 · **Depends on:** Feature 09 · **Canonical spec:**
[T16](../../features/16-tier2-tunnels.md).

**Goal (from spec).** Arbitrary TCP tunneling (`mrd.tunnel.tcp/1`) and a native file-service protocol
(`mrd.fs/1`) on the identical substrate — headlined by SSH-ing into a NAT'd headless box addressed by its
Meridian ID. **`[SEC]`** is dominant here: this is the feature enterprise security teams scrutinize, so
default-deny controls ship **with** the capability, never after.

**Exit acceptance (spec §Acceptance).** Interactive SSH usable (<15 ms echo overhead direct); allowlist
bypass attempts (header games, port 0, IPv6 literals, DNS-resolving-elsewhere) all rejected by tests;
`mrd.fs` write ops fail on read-only exports; tunnels refused from non-granted contacts; whole demo passes
with the rendezvous **stopped** after setup.

| Task | Scope | Tags | Depends on | Status |
|---|---|---|---|---|
| F16.1 | `mrd.tunnel.tcp/1` — TCP↔reliable-ordered channel + connect header | [ADR][SEC] | M2 F09 | ☐ |
| F16.2 | **Mandatory default-empty recipient allowlist** + per-contact grants (verified-only, org-configurable) | [SEC] | F16.1 | ☐ |
| F16.3 | `meridian tunnel` CLI + `ssh` ProxyCommand recipe (unmodified ssh) | — | F16.1 | ☐ |
| F16.4 | `mrd.fs/1` — list/stat/get/put/rename over CBOR, reusing T09 chunk/merkle/resume, read-only default | [ADR][SEC] | F09 | ☐ |
| F16.5 | `tunnel-security.md` (policy model, double-encryption rationale, abuse analysis) + throughput report | [SEC] | F16.2 | ☐ |
| F16.6 | Headline demo scripted in CI on the netns rig (incl. server-stopped reassertion) | [SEC] | F16.2, F16.3 | ☐ |

- **F16.1 [ADR][SEC]** — one TCP conn ↔ one channel; SSH's own crypto retained (double encryption deliberate — the tunnel adds reach, not trust). Registry-only, zero core edits. Tests: tunnel round-trip; core diff empty. DoD 3,6.
- **F16.2 [SEC]** — the security core: `tunnel.allow` is **mandatory and default-empty**; a peer can never open a target the recipient didn't permit; verified-contacts-only option; org kill switch. Tests: **every bypass class** (port 0, IPv6 literal, DNS-resolving-elsewhere, header games) rejected. Review: security-reviewer. DoD 4.
- **F16.3** — client UX + ProxyCommand so plain `ssh` works. Tests: interactive SSH via ProxyCommand. DoD 4.
- **F16.4 [ADR][SEC]** — `mrd.fs/1` verbs, rooted at an explicitly exported dir, **read-only by default**; reuses T09 machinery. Tests: write fails on ro export; resume works. DoD 3,4,6.
- **F16.5 [SEC]** — the doc written *for the enterprise reviewer*: default-deny, explicit grants, verified-only, kill switch; abuse analysis (compromised initiator reaches only the allowlist; servers see nothing). DoD 7.
- **F16.6 [SEC]** — CI demo including the rendezvous-stopped reassertion of the core property. Tests: full demo green on netns; non-granted contact refused. DoD 2.
